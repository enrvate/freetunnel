// cppcheck-suppress-file missingIncludeSystem
#include "app/Backend.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QPointer>
#include <QThread>

#include "core/ConfigImport.h"
#include "core/ConfigStore.h"
#include "core/ConfigToml.h"
#include "core/ControlCommand.h"
#include "core/CredentialStore.h"
#include "core/InstanceControl.h"

Backend::Backend(QObject *parent) : QObject(parent) {
    freetunnel::sweepLegacyPlaintextStorage();
    freetunnel::sweepLegacyInstanceAuthFile();
    m_settings = loadAppSettings();
    reloadConfigs();
    if (!m_settings.last_config_path.isEmpty() && m_paths.contains(m_settings.last_config_path)) {
        m_activePath = m_settings.last_config_path;
    } else if (!m_paths.isEmpty()) {
        m_activePath = m_paths.first();
    }

    wireVpnClientSignals();
    m_client.setSessionLogging(m_settings.logging_enabled);

    m_ticker.setInterval(1000);
    connect(&m_ticker, &QTimer::timeout, this, [this]() { onStatsTick(); });
    m_ticker.start();

    // Re-check the log size hourly. This used to wait for a fully-down tunnel
    // because the core appended to the same file through its own descriptor —
    // it no longer does, so the trim can run during a long session, which is
    // exactly when the file grows.
    m_logTrimTimer.setInterval(60 * 60 * 1000);
    connect(&m_logTrimTimer, &QTimer::timeout, this, [this]() {
        if (m_settings.logging_enabled)
            trimLogFile();
    });
    m_logTrimTimer.start();

    wireHotkeyLifecycle();

    if (m_settings.logging_enabled) {
        trimLogFile();
        loadLogTail();
        appendLog(QStringLiteral("INFO"),
                  tr("FreeTunnel %1 started").arg(appVersion()));
    }

    // Background update check: badge Settings when a newer release exists.
    QTimer::singleShot(1200, this, [this] { checkForUpdates(false); });

    // Connect on startup if requested (deferred so the window shows first).
    if (m_settings.auto_connect_on_start && !m_activePath.isEmpty())
        QTimer::singleShot(600, this, [this] { connectVpn(); });
}

void Backend::wireVpnClientSignals()
{
    connect(&m_client, &VpnHelperClient::stateChanged, this, &Backend::onVpnClientStateChanged);
    connect(&m_client, &VpnHelperClient::tunnelStats, this,
            [this](quint64 up, quint64 down) {
                m_accUp += up;
                m_accDown += down;
            });
    connect(&m_client, &VpnHelperClient::connectionInfo, this,
            [this](const QString &m) {
                // Internal recovery/watchdog chatter ("recovery: reconnecting", …)
                // just duplicates the state line ("Reconnecting…"); keep it for the
                // verbose log only so a normal reconnect isn't three near-identical
                // lines.
                if (!m_settings.verbose_logs && isInternalVpnError(m))
                    return;
                appendLog(QStringLiteral("INFO"), m);
            });
    connect(&m_client, &VpnHelperClient::connectProgress, this,
            [this](const QString &m) { appendLog(QStringLiteral("INFO"), m); });
    connect(&m_client, &VpnHelperClient::coreLogLine, this,
            [this](const QString &line) { appendCoreLog(line); });
    connect(&m_client, &VpnHelperClient::vpnError, this, &Backend::onVpnErrorReceived);
}

void Backend::clearReapplyingIfDone(VpnHelperClient::State st, bool nowConnected)
{
    if (m_reapplying && (nowConnected || st == VpnHelperClient::State::Error))
        m_reapplying = false;
}

void Backend::applyVpnClientState(VpnHelperClient::State st)
{
    const bool nowConnected = st == VpnHelperClient::State::Connected;
    if (nowConnected && !m_connected)
        m_session.restart();
    m_connected = nowConnected;
    clearReapplyingIfDone(st, nowConnected);
    // A config-switch / rule-reapply teardown is the first half of a reconnect,
    // not an "Off" state. Reporting connected=connecting=disconnecting=false for
    // that window made the UI show "Off" while the tunnel was still up, let
    // toggle() start a connect that raced the pending one, and let removeConfig()
    // miss its delete-active guard (leaving m_pendingReconnect to auto-connect a
    // config the user never selected).
    const bool switching = m_reapplying
            && (st == VpnHelperClient::State::Disconnecting
                || st == VpnHelperClient::State::Disconnected);
    m_connecting = st == VpnHelperClient::State::Connecting
                   || st == VpnHelperClient::State::Reconnecting
                   || st == VpnHelperClient::State::WaitingForNetwork
                   || switching;
    m_disconnecting = st == VpnHelperClient::State::Disconnecting && !m_reapplying;
}

void Backend::onVpnClientStateChanged(VpnHelperClient::State st)
{
    applyVpnClientState(st);
    emit stateChanged();
    appendLog(QStringLiteral("INFO"), statusText());
    // A config switch / live rule reapply disconnects first, then reconnects only
    // once the old tunnel is fully down. Defer so we never re-enter the VPN client
    // from inside its own state callback (disconnectVpn can emit this synchronously).
    if (st == VpnHelperClient::State::Disconnected && m_pendingReconnect)
        QTimer::singleShot(0, this, [this]() { firePendingReconnect(); });
}

bool Backend::isInternalVpnError(const QString &m) const
{
    const QString lower = m.toLower();
    return lower.contains(QLatin1String("recovery:"))
           || lower.contains(QLatin1String("fd watchdog:"))
           || lower.contains(QLatin1String("network wait timeout:"));
}

namespace {

QString classifyVpnErrorMessage(const QString &lower)
{
    // Helper lifecycle messages are already written for humans — and phrases
    // like "authorization may have been declined" would false-match the
    // credential branch below and turn an elevation refusal into a bogus
    // "Authentication failed — check the username and password".
    if (lower.contains(QLatin1String("helper")))
        return QString();
    if (lower.contains(QLatin1String("disconnect")) || lower.contains(QLatin1String("core"))) {
        return QCoreApplication::translate(
                "Backend",
                "Connection lost — couldn't reach the server. Check the config or your network.");
    }
    if (lower.contains(QLatin1String("timeout")) || lower.contains(QLatin1String("timed out"))) {
        return QCoreApplication::translate("Backend", "Server isn't responding (timed out).");
    }
    if (lower.contains(QLatin1String("auth")) || lower.contains(QLatin1String("credential"))) {
        return QCoreApplication::translate("Backend",
                                           "Authentication failed — check the username and password.");
    }
    return QString();
}

} // namespace

QString Backend::friendlyVpnError(const QString &m) const
{
    if (m.startsWith(QStringLiteral("Connection failed:"), Qt::CaseInsensitive))
        return m;
    const QString classified = classifyVpnErrorMessage(m.toLower());
    return classified.isEmpty() ? m : classified;
}

void Backend::emitDedupedVpnError(const QString &friendly)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (friendly == m_lastErrorMsg && now - m_lastErrorAt <= 30000)
        return;
    m_lastErrorMsg = friendly;
    m_lastErrorAt = now;
    emit errorOccurred(friendly);
}

void Backend::onVpnErrorReceived(const QString &m)
{
    appendLog(QStringLiteral("ERROR"), m);
    // NOT gated on m_inConnect: a synchronous helper-spawn failure (no
    // pkexec/sudo, token file not writable) emits from inside connectVpn(),
    // and swallowing it left Connect looking like a silent no-op. Duplicate
    // chatter is already handled by m_reapplying + the 30 s dedupe below.
    if (m_reapplying || isInternalVpnError(m))
        return;
    emitDedupedVpnError(friendlyVpnError(m));
}

void Backend::onStatsTick()
{
    m_downRate = static_cast<double>(m_accDown);
    m_upRate = static_cast<double>(m_accUp);
    m_accUp = m_accDown = 0;
    emit tick();
}

QString Backend::statusText() const {
    switch (m_client.state()) {
    case VpnHelperClient::State::Connected: return tr("Connected");
    case VpnHelperClient::State::Connecting: return tr("Connecting…");
    case VpnHelperClient::State::Reconnecting: return tr("Reconnecting…");
    case VpnHelperClient::State::WaitingForNetwork: return tr("Waiting for network…");
    case VpnHelperClient::State::Disconnecting: return tr("Disconnecting…");
    case VpnHelperClient::State::Error: return tr("Error");
    default: return tr("Off");
    }
}

QString Backend::sessionTime() const {
    if (!m_connected)
        return QString();
    qint64 secs = m_session.elapsed() / 1000;
    return QStringLiteral("%1:%2:%3")
            .arg(secs / 3600, 2, 10, QChar('0'))
            .arg((secs % 3600) / 60, 2, 10, QChar('0'))
            .arg(secs % 60, 2, 10, QChar('0'));
}

static QString fmtRate(double bytesPerSec) {
    return QString::number(bytesPerSec / 1.0e6, 'f', 1);
}
QString Backend::downSpeed() const { return fmtRate(m_downRate); }
QString Backend::upSpeed() const { return fmtRate(m_upRate); }

QString Backend::activeConfig() const {
    return m_activePath.isEmpty() ? tr("No config") : nameForPath(m_activePath);
}

QString Backend::nameForPath(const QString &path) const {
    return QFileInfo(path).completeBaseName();
}

void Backend::reloadConfigs() {
    m_paths = loadStoredConfigs();
    m_names.clear();
    for (const QString &p : m_paths)
        m_names << nameForPath(p);
    ++m_pingGeneration; // invalidate in-flight probes: indices are shifting
    m_pings.clear(); // indices shifted — stale pings would mislabel servers
    emit pingsChanged();
    emit configsChanged();
}

void Backend::toggle() {
    // A click while connecting cancels the attempt; while connected it
    // disconnects; otherwise it starts connecting.
    if (m_connected || m_connecting)
        disconnectVpn();
    else
        connectVpn();
}

bool Backend::shouldSkipConnectAttempt() const
{
    return !m_reapplying && (m_connected || m_connecting || m_disconnecting);
}

void Backend::logConnectAttempt()
{
    QFile f(m_activePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    const freetunnel::ConfigToml c = freetunnel::parseConfigToml(QString::fromUtf8(f.readAll()));
    const bool h3 = c.protocol == QLatin1String("http3");
    appendLog(QStringLiteral("INFO"),
              tr("Connecting to %1 [%2] · %3 over %4")
                      .arg(c.hostname.isEmpty() ? nameForPath(m_activePath) : c.hostname,
                           c.addresses,
                           h3 ? QStringLiteral("HTTP/3") : QStringLiteral("HTTP/2"),
                           h3 ? QStringLiteral("UDP/QUIC") : QStringLiteral("TCP")));
}

void Backend::failConnectNoPassword()
{
    m_connecting = false;
    // Nothing further will report Connected or Error for this attempt, so
    // clearReapplyingIfDone() would never run: a reapply that dies here used to
    // latch m_reapplying forever, masking m_disconnecting, swallowing every
    // vpnError toast and killing live rule reapply until some later connect
    // happened to succeed.
    m_reapplying = false;
    emit stateChanged();
    emit errorOccurred(tr("Config has no password — edit it and try again"));
}

void Backend::connectVpn() {
    if (m_activePath.isEmpty()) {
        emit errorOccurred(tr("Select a config first"));
        return;
    }
    // Connect hotkey / deep link: no-op when already up or a session is in flight.
    // reconnectActiveConfig() sets m_reapplying so live rule edits can still rebuild.
    if (shouldSkipConnectAttempt())
        return;
    // Show "Connecting…" immediately — the helper handshake (and any elevation
    // prompt) can take a few seconds before the core reports a real state.
    // A subsequent state change (Connected / Error / Disconnected) overrides it.
    if (!m_connecting) {
        m_connecting = true;
        emit stateChanged();
    }
    logConnectAttempt();
    buildConnectTomlAsync();
}

// Building the connect TOML reads the config's password out of the OS credential
// store. That is a blocking IPC to securityd on macOS, and while the system is
// asking the user whether this build of the app may read the item, it does not
// return — which froze the whole UI, spinner and all, for as long as the dialog
// was up. Do it on a worker thread and resume on ours.
void Backend::buildConnectTomlAsync()
{
    const quint64 generation = ++m_connectGen;
    const QString path = m_activePath;
    const QString level =
            m_settings.verbose_logs ? QStringLiteral("info") : QStringLiteral("warn");
    // NOT parented to this Backend, and that is the fix for an abort rather than a
    // style preference. A QThread that is a child of Backend is deleted by
    // ~QObject, which on a thread still inside the keychain read means
    // QThread's destructor reaching qFatal("Destroyed while thread is still
    // running") and the process dying on SIGABRT. The window is exactly the one
    // this function exists for: the read blocks while macOS asks the user whether
    // this build may open the item, and quitting during that is an ordinary thing
    // to do. Unparented, nothing destroys it underneath itself; it deletes itself
    // on finished() below.
    auto *watcher = new QThread;
    // Guarded because the worker must be free to outlive us. QPointer clears if
    // this Backend goes away first, and a queued invocation whose receiver is
    // gone is discarded by Qt — so the result simply never lands, which is the
    // right outcome for a connect nobody is waiting for any more.
    const QPointer<Backend> self(this);
    // Qt::DirectConnection is what makes this actually asynchronous, and it is not
    // decoration. A QThread OBJECT lives in the thread that created it — here the
    // GUI thread — so an auto connection to one of its own signals is queued back
    // to the GUI thread and the body runs there. This function exists to keep the
    // blocking keychain read off the UI, and without this it did the opposite:
    // spun up a thread, then froze the window on it anyway. Direct delivery runs
    // the body in the emitting thread, which for started() is the worker.
    QObject::connect(
            watcher, &QThread::started, watcher,
            [watcher, self, generation, path, level]() {
                // Read here, carried by value: the worker must touch no member of
                // Backend, or "free to outlive us" is not true.
                QThread *const builtOn = QThread::currentThread();
                const QString toml = freetunnel::buildConnectConfigToml(path, level);
                if (self) {
                    QMetaObject::invokeMethod(
                            self,
                            [self, generation, toml, builtOn]() {
                                if (!self)
                                    return;
#ifdef FT_ENABLE_TEST_HOOKS
                                self->m_lastTomlBuildThread.store(builtOn);
#endif
                                self->onConnectTomlReady(generation, toml);
                            },
                            Qt::QueuedConnection);
                }
                watcher->quit();
            },
            Qt::DirectConnection);
    QObject::connect(watcher, &QThread::finished, watcher, &QObject::deleteLater);
    watcher->start();
}

void Backend::onConnectTomlReady(quint64 generation, const QString &toml)
{
    // Superseded by a disconnect, a config switch or a newer attempt while the
    // credential store had us waiting.
    if (generation != m_connectGen)
        return;
    if (toml.isEmpty()) {
        failConnectNoPassword();
        return;
    }
    m_inConnect = true;
    m_client.loadConfigFromToml(toml);
    applySplitRules(); // push domain-bypass rules to the core before connecting
    m_client.setKillSwitch(m_settings.killswitch_enabled);
    m_client.setLogLevel(m_settings.verbose_logs ? QStringLiteral("info") : QStringLiteral("warn"));
    m_client.setSessionLogging(m_settings.logging_enabled);
    m_client.connectVpn();
    m_inConnect = false;
}

void Backend::disconnectVpn() {
    if (!m_connected && !m_connecting)
        return; // nothing to disconnect or cancel
    ++m_connectGen; // a credential read still in flight must not start a session
    m_reapplying = false;
    m_pendingReconnect = false; // an explicit disconnect cancels a config-switch reconnect
    // Show "Disconnecting…" right away; clear the optimistic "Connecting…".
    m_connecting = false;
    m_disconnecting = true;
    emit stateChanged();
    m_client.disconnectVpn(); // aborts a pending startup, or stops a live tunnel
}

void Backend::prepareQuit() {
    if (m_shutdownPrepared)
        return;
    m_shutdownPrepared = true;
    if (!m_quitting) {
        m_quitting = true;
        emit aboutToShutdown();
    }
    unregisterHotkeys();
    m_ticker.stop();
    m_client.shutdown();
    freetunnel::sweepStaleMaterializedConfigs();
}

bool Backend::applicationClosingDown() const
{
    return m_quitting || QCoreApplication::closingDown();
}

void Backend::quitApplication() {
    if (m_quitting)
        return;
    m_quitting = true;
    emit aboutToShutdown();
    // Let QML hide the tray icon before exit (macOS keeps running while status items exist).
    QMetaObject::invokeMethod(qApp, []() { QCoreApplication::exit(0); }, Qt::QueuedConnection);
}

QString Backend::credentialStorageWarning() const
{
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    if (!freetunnel::CredentialStore::secureStorageAvailable()) {
        return tr("Secure credential storage is unavailable. Install gnome-keyring or "
                  "KWallet (with secret-tool) before saving VPN passwords.");
    }
#endif
    return QString();
}

void Backend::handleControl(const QString &command) {
    using freetunnel::ControlAction;
    const auto cmd = freetunnel::parseControlCommand(command);
    switch (cmd.action) {
    case ControlAction::ImportLink: importDeepLink(cmd.payload); break;
    case ControlAction::Toggle:     toggle(); break;
    case ControlAction::Connect:    connectVpn(); break;
    case ControlAction::Disconnect: disconnectVpn(); break;
    case ControlAction::None:       break; // window raise handled by the caller
    }
}

void Backend::selectConfig(int index) {
    if (index < 0 || index >= m_paths.size())
        return;
    if (m_paths.at(index) == m_activePath) // already active — don't reconnect
        return;
    m_activePath = m_paths.at(index);
    m_settings.last_config_path = m_activePath;
    persistSettings();
    emit configChanged();
    if (m_connected || m_connecting)
        reconnectActiveConfig();
}

void Backend::removeConfig(int index) {
    if (index < 0 || index >= m_paths.size())
        return;
    const QString path = m_paths.at(index);
    // Deleting the config we're actively connected to (or connecting to) must
    // tear the tunnel down. Otherwise the helper keeps an orphaned tunnel to a
    // server that no longer has a config, and the active slot silently shifts to
    // whatever config lands first below — leaving m_connected true, so its
    // "connected" badge would jump onto a config that isn't actually up.
    if (path == m_activePath && (m_connected || m_connecting))
        disconnectVpn();
    freetunnel::CredentialStore::deletePassword(freetunnel::CredentialStore::keyForConfigPath(path));
    // Remove the TOML itself when we own it (imported/created configs live in
    // the app config dir) — a "deleted" server shouldn't stay recoverable on
    // disk with its hostname/username/cert. Files elsewhere are the user's.
    const QString appConfigDir = QFileInfo(
            QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)).absoluteFilePath();
    if (QFileInfo(path).absolutePath() == appConfigDir)
        QFile::remove(path);
    QStringList stored = loadStoredConfigs();
    stored.removeAll(path);
    saveStoredConfigs(stored);
    if (m_settings.config_profiles.remove(path) > 0)
        persistSettings();
    if (m_activePath == path)
        m_activePath.clear();
    reloadConfigs();
    if (m_activePath.isEmpty() && !m_paths.isEmpty())
        m_activePath = m_paths.first();
    emit configChanged();
}
