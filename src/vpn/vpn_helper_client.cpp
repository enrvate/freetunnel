// cppcheck-suppress-file missingIncludeSystem
#include "vpn/vpn_helper_client.h"
#include "vpn/vpn_helper_launch.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileDevice>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTemporaryFile>
#include <QTimer>

#include "core/AppImagePath.h" // runningAppImagePath (Linux elevation target)
#include "core/AppUiUtils.h" // shellEscape / appleScriptEscape (macOS)
#include "vpn/vpn_helper_protocol.h"

namespace {

const QHostAddress kLoopback = QHostAddress(QStringLiteral("127.0.0.1"));

} // namespace

#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>
#endif

#if !defined(Q_OS_MACOS) && !defined(Q_OS_WIN)
// Declared in vpn_helper_launch.h and deliberately NOT in the anonymous namespace
// below: this builds the argv pkexec runs as root, and while it was file-local no
// test could reach it. External linkage here rather than a move to
// vpn_helper_launch.cpp, which would mean adding that source to nine test targets
// that already compile this one.
namespace freetunnel {

QStringList linuxHelperCommand(const QString &exe, const QString &appImage, quint16 port,
                               const QString &tokenPath)
{
    QStringList cmd;
    // `appImage` names the binary the user is about to authorize as root, so it
    // must come from the kernel (freetunnel::runningAppImagePath) and never from
    // $APPIMAGE/$APPDIR. Re-exec is needed at all because the running executable
    // lives inside a user-private FUSE mount that root cannot read; the AppImage
    // file behind it is a normal file that root can.
    if (!appImage.isEmpty()) {
        cmd << QStringLiteral("env") << QStringLiteral("APPIMAGE_EXTRACT_AND_RUN=1") << appImage;
    } else {
        cmd << exe;
    }
    cmd << QStringLiteral("--helper") << QStringLiteral("--port") << QString::number(port)
        << QStringLiteral("--token-file") << tokenPath;
    return cmd;
}

} // namespace freetunnel

namespace {

bool startLinuxElevation(QProcess *proc, const QString &elevator, const QStringList &helperCmd)
{
    QStringList args;
    if (elevator == QLatin1String("sudo"))
        args << QStringLiteral("--");
    args += helperCmd;
    proc->start(elevator, args);
    if (!proc->waitForStarted(5000))
        return false;
    if (elevator == QLatin1String("pkexec") && proc->waitForFinished(1000))
        return false;
    return true;
}

} // namespace
#endif

VpnHelperClient::VpnHelperClient(QObject *parent) : QObject(parent) {}

VpnHelperClient::~VpnHelperClient() {
    shutdown();
}

void VpnHelperClient::shutdown() {
    if (m_sock && m_helloAcked) {
        QJsonObject q;
        q["cmd"] = "quit";
        send(q);
        m_sock->flush();
        m_sock->waitForBytesWritten(300);
    }
    abortStartup();
}

void VpnHelperClient::clearTokenFile() {
    if (m_tokenPath.isEmpty())
        return;
    QFile::remove(m_tokenPath);
    m_tokenPath.clear();
}

static VpnHelperClient::State stateFromString(const QString &s) {
    using S = VpnHelperClient::State;
    if (s == "Connecting") return S::Connecting;
    if (s == "Connected") return S::Connected;
    if (s == "Reconnecting") return S::Reconnecting;
    if (s == "WaitingForNetwork") return S::WaitingForNetwork;
    if (s == "Disconnecting") return S::Disconnecting;
    if (s == "Error") return S::Error;
    return S::Disconnected;
}

bool VpnHelperClient::loadConfigFromToml(const QString &toml) {
    m_configToml = toml;
    return !toml.isEmpty();
}

void VpnHelperClient::setExtraExclusions(const std::vector<std::string> &exclusions) {
    m_exclusions = exclusions;
    if (m_helloAcked) {
        QJsonObject c; c["cmd"] = "setExclusions";
        QJsonArray arr;
        for (const auto &d : m_exclusions) arr.append(QString::fromStdString(d));
        c["domains"] = arr;
        send(c);
    }
}

void VpnHelperClient::setExcludedRoutes(const std::vector<std::string> &routes) {
    m_excludedRoutes = routes;
    if (m_helloAcked) {
        QJsonObject c; c["cmd"] = "setRoutes";
        QJsonArray arr;
        for (const auto &r : m_excludedRoutes) arr.append(QString::fromStdString(r));
        c["excluded"] = arr;
        send(c);
    }
}

void VpnHelperClient::setVpnMode(bool selective) {
    m_selective = selective;
    if (m_helloAcked) {
        QJsonObject c; c["cmd"] = "setMode"; c["selective"] = selective;
        send(c);
    }
}

void VpnHelperClient::setKillSwitch(bool enabled) {
    m_killSwitch = enabled;
    if (m_helloAcked) {
        QJsonObject c; c["cmd"] = "setKillSwitch"; c["enabled"] = enabled;
        send(c);
    }
}

void VpnHelperClient::setLogLevel(const QString &level) {
    m_logLevel = level;
    if (m_helloAcked) {
        QJsonObject c; c["cmd"] = "setLogLevel"; c["level"] = level;
        send(c);
    }
}

void VpnHelperClient::setSessionLogging(bool enabled)
{
    m_loggingEnabled = enabled;
}

void VpnHelperClient::connectVpn() {
    if (!ensureHelper())
        return;
    if (!m_helloAcked) {
        m_connectPending = true;
        return;
    }
    QJsonObject c;
    c["cmd"] = "connect";
    c["loggingEnabled"] = m_loggingEnabled;
    c["configToml"] = m_configToml; // inline only — the helper refuses file paths
    send(c);
}

void VpnHelperClient::disconnectVpn() {
    if (!m_helloAcked) {
        abortStartup();
        // Cancelling during helper startup/elevation: the state is still
        // Disconnected (nothing sets Connecting locally — states arrive from the
        // helper), so a value-guarded setState emitted nothing at all. The GUI
        // clears its "disconnecting" flag only from this signal, so it stuck on
        // "Disconnecting…" forever and every later connect became a silent
        // no-op. Always report the outcome, even when the value is unchanged.
        m_state = State::Disconnected;
        emit stateChanged(m_state);
        return;
    }
    if (!m_sock) return;
    QJsonObject c; c["cmd"] = "disconnect"; send(c);
}

void VpnHelperClient::abortStartup() {
    m_connectPending = false;
    m_starting = false;
    m_helloAcked = false;
    m_peerProven = false;
    m_guiNonce.clear();
    // A partial line left over from the dead connection would otherwise be
    // prepended to the next helper's first message and swallow its challenge.
    m_buf.clear();
    if (m_attempt) { m_attempt->stop(); m_attempt->deleteLater(); m_attempt = nullptr; }
    if (m_sock) { m_sock->abort(); m_sock->deleteLater(); m_sock = nullptr; }
    // On macOS m_proc is osascript, not the helper — the helper was exec'd into
    // the background and survives this kill. Two things bound it: deleting the
    // token file below makes a helper that has not read it yet exit immediately
    // (no token, no start), and one that already read it finds itself
    // unauthenticated and self-quits on its own 60 s deadline. Until then it
    // holds a loopback port with a token nobody will ever present, so it cannot
    // be driven — but it is a live root process, which is why the deadline
    // exists at all.
    if (m_proc) { m_proc->kill(); m_proc->deleteLater(); m_proc = nullptr; }
    clearTokenFile();
}

void VpnHelperClient::resetHelperTransport()
{
    m_buf.clear();
    if (m_sock) {
        m_sock->deleteLater();
        m_sock = nullptr;
    }
    if (m_proc) {
        m_proc->deleteLater();
        m_proc = nullptr;
    }
}

bool VpnHelperClient::configureProductionHelper()
{
    // Full dynamic/ephemeral port range 49152–65535 (16384 ports).
    m_tcpPort = static_cast<quint16>(49152 + QRandomGenerator::system()->bounded(16384));
    // Two 64-bit CSPRNG values, zero-padded to a fixed 32-hex (128-bit) string —
    // QString::number(…, 16) drops leading zero nibbles, which would otherwise
    // make the token length leak a little and vary between runs.
    m_token = QStringLiteral("%1%2")
                      .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'))
                      .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'));
    clearTokenFile();
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(dir);
    QTemporaryFile tf(dir + QStringLiteral("/.fthelper-XXXXXX"));
    tf.setAutoRemove(false);
    if (!tf.open()) {
        fail(tr("Could not create the VPN helper token file"));
        return false;
    }
    tf.write(m_token.toUtf8());
    tf.close();
    QFile::setPermissions(tf.fileName(), QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    m_tokenPath = tf.fileName();

    QString err;
    if (!spawnElevatedHelper(m_tcpPort, m_tokenPath, &err)) {
        fail(err.isEmpty() ? tr("Could not start the VPN helper") : err);
        return false;
    }
    return true;
}

bool VpnHelperClient::configureTestHelper()
{
#ifdef FT_ENABLE_TEST_HOOKS
    m_tcpPort = static_cast<quint16>(qEnvironmentVariableIntValue("FT_TEST_HELPER_PORT"));
    m_token = QString::fromUtf8(qgetenv("FT_TEST_HELPER_TOKEN"));
    if (m_token.isEmpty()) {
        fail(tr("FT_TEST_HELPER_TOKEN is required when FT_TEST_HELPER_PORT is set"));
        return false;
    }
    return true;
#else
    return false;
#endif
}

void VpnHelperClient::wireHelperSocket(bool testHelper)
{
    m_sock = new QTcpSocket(this);
    connect(m_sock, &QTcpSocket::connected, this, &VpnHelperClient::onSocketConnected);
    connect(m_sock, &QTcpSocket::readyRead, this, &VpnHelperClient::onReadyRead);
    connect(m_sock, &QTcpSocket::disconnected, this, [this]() {
        m_helloAcked = false;
        m_peerProven = false;
        m_starting = false;
        if (m_state != State::Disconnected)
            setState(State::Disconnected);
    });
    if (testHelper) {
        m_sock->connectToHost(kLoopback, m_tcpPort);
        return;
    }
    startHelperConnectRetry();
}

void VpnHelperClient::startHelperConnectRetry()
{
    if (m_attempt) {
        m_attempt->stop();
        m_attempt->deleteLater();
    }
    m_attempt = new QTimer(this);
    m_tries = 0;
    connect(m_attempt, &QTimer::timeout, this, [this]() {
        if (!m_sock) {
            if (m_attempt) {
                m_attempt->stop();
                m_attempt->deleteLater();
                m_attempt = nullptr;
            }
            return;
        }
        if (m_sock->state() == QAbstractSocket::ConnectedState) {
            m_attempt->stop();
            m_attempt->deleteLater();
            m_attempt = nullptr;
            return;
        }
        // 240 × 250 ms = 60 s. The elevation dialog blocks the helper from even
        // starting until the user finishes typing the admin password — the old
        // 20 s window expired mid-typing for anyone without Touch ID.
        if (++m_tries > 240) {
            m_attempt->stop();
            m_attempt->deleteLater();
            m_attempt = nullptr;
            const QString detail = m_sock->errorString();
            fail(tr("The VPN helper didn't start — authorization may have been declined, "
                    "or the elevated helper could not be reached.%1")
                         .arg(detail.isEmpty() ? QString()
                                               : QStringLiteral(" (") + detail + QLatin1Char(')')));
            return;
        }
        m_sock->abort();
        m_sock->connectToHost(kLoopback, m_tcpPort);
    });
    m_attempt->start(250);
    m_sock->connectToHost(kLoopback, m_tcpPort);
}

bool VpnHelperClient::ensureHelper() {
    if (m_sock && m_sock->state() == QAbstractSocket::ConnectedState)
        return true;
    if (m_starting)
        return true;
    m_starting = true;
    resetHelperTransport();

#if defined(FT_ENABLE_TEST_HOOKS)
    if (qEnvironmentVariableIsSet("FT_TEST_HELPER_PORT")) {
        if (!configureTestHelper())
            return false;
        wireHelperSocket(true);
        return true;
    }
#endif
    if (!configureProductionHelper())
        return false;
    wireHelperSocket(false);
    return true;
}

#if defined(Q_OS_MACOS)
static bool launchMacElevatedHelper(QProcess **procOut, QObject *parent, const QString &exe,
                                    quint16 port, const QString &tokenPath, QString *err)
{
    const QString inner =
            QStringLiteral("logf=$(mktemp \"${TMPDIR:-/tmp}/freetunnel-helper.XXXXXX\") || logf=/dev/null; "
                           "exec %1 --helper --port %2 --token-file %3 "
                           ">\"$logf\" 2>&1 &")
                    .arg(shellEscape(exe), QString::number(port), shellEscape(tokenPath));
    const QString script = QStringLiteral("do shell script \"%1\" with administrator privileges")
                                   .arg(appleScriptEscape(inner));
    auto *proc = new QProcess(parent);
    proc->start(QStringLiteral("osascript"), {QStringLiteral("-e"), script});
    if (!proc->waitForStarted(5000)) {
        if (err)
            *err = QObject::tr("Could not launch osascript");
        proc->deleteLater();
        return false;
    }
    *procOut = proc;
    return true;
}
#endif

#if defined(Q_OS_WIN)
static bool launchWinElevatedHelper(const QString &exe, quint16 port, const QString &tokenPath,
                                    QString *err)
{
    const QString exeDir = QFileInfo(exe).absolutePath();
    const QString args = QStringLiteral("--helper --port %1 --token-file \"%2\"")
                                 .arg(QString::number(port), tokenPath);
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    const std::wstring wexe = exe.toStdWString();
    const std::wstring wargs = args.toStdWString();
    const std::wstring wdir = exeDir.toStdWString();
    sei.lpFile = wexe.c_str();
    sei.lpParameters = wargs.c_str();
    sei.lpDirectory = wdir.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) {
        if (err)
            *err = QObject::tr("Elevation was cancelled or failed");
        return false;
    }
    return true;
}
#endif

bool VpnHelperClient::spawnElevatedHelper(quint16 port, const QString &tokenPath, QString *err) {
    const QString exe = QCoreApplication::applicationFilePath();

#if defined(Q_OS_MACOS)
    return launchMacElevatedHelper(&m_proc, this, exe, port, tokenPath, err);
#elif defined(Q_OS_WIN)
    return launchWinElevatedHelper(exe, port, tokenPath, err);
#else
    m_proc = new QProcess(this);
    const QStringList helperCmd =
            freetunnel::linuxHelperCommand(exe, freetunnel::runningAppImagePath(), port,
                                           tokenPath);

    if (startLinuxElevation(m_proc, QStringLiteral("pkexec"), helperCmd))
        return true;

    m_proc->deleteLater();
    m_proc = new QProcess(this);

    if (startLinuxElevation(m_proc, QStringLiteral("sudo"), helperCmd))
        return true;

    if (err) {
        *err = tr("Could not start the VPN helper — authorization may have been "
                  "declined, or pkexec/sudo elevation failed.");
    }
    return false;
#endif
}

void VpnHelperClient::onSocketConnected() {
    m_starting = false;
    // Open with a nonce and NO secret. The helper only starts listening once the
    // elevation prompt is answered, so until then anything could be holding this
    // port — it has to prove it knows the token before we send it anything.
    m_guiNonce = QStringLiteral("%1%2")
                         .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'))
                         .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'));
    QJsonObject hello;
    hello["cmd"] = "hello";
    hello["nonce"] = m_guiNonce;
    send(hello);
}

void VpnHelperClient::send(const QJsonObject &obj) {
    if (!m_sock) return;
    m_sock->write(QJsonDocument(obj).toJson(QJsonDocument::Compact) + '\n');
}

void VpnHelperClient::onReadyRead() {
    m_buf += m_sock->readAll();
    // Drain complete lines FIRST, then judge what is left. The cap used to be
    // applied to the whole accumulated buffer, so a single readAll() carrying a
    // burst of perfectly well-formed events (the core emits one per flow) killed
    // the helper — and because the buffer survived the teardown, every later
    // connect failed instantly, after the user had re-entered their password.
    int nl = -1;
    while ((nl = m_buf.indexOf('\n')) >= 0) {
        const QByteArray line = m_buf.left(nl);
        m_buf.remove(0, nl + 1);
        const auto doc = QJsonDocument::fromJson(line);
        if (doc.isObject()) handleEvent(doc.object());
    }
    // Only an unterminated remainder can be over-long: a real line never is.
    if (m_buf.size() > vpn_helper::kMaxIpcLineBytes) {
        m_buf.clear();
        fail(tr("VPN helper sent too much data"));
    }
}

void VpnHelperClient::handleReadyEvent()
{
    m_helloAcked = true;
    clearTokenFile();
    setVpnMode(m_selective);
    setKillSwitch(m_killSwitch);
    setLogLevel(m_logLevel);
    setExtraExclusions(m_exclusions);
    setExcludedRoutes(m_excludedRoutes);
    if (!m_connectPending)
        return;
    m_connectPending = false;
    connectVpn();
}

void VpnHelperClient::handleChallengeEvent(const QJsonObject &ev) {
    // Verify the peer before answering: a wrong proof means we are talking to
    // something that squatted the port, not to our elevated helper. Failing
    // closed here is what keeps the config TOML — and the VPN password in it
    // — from ever reaching it.
    if (m_helloAcked || m_guiNonce.isEmpty())
        return;
    if (!vpn_helper::tokensEqual(
                ev.value("proof").toString(),
                vpn_helper::authProof(m_token, QString::fromLatin1(vpn_helper::kHelperRole),
                                      m_guiNonce))) {
        fail(tr("The process answering on the helper port could not prove it is the "
                "FreeTunnel helper — refusing to send the config."));
        return;
    }
    const QString helperNonce = ev.value("nonce").toString();
    if (helperNonce.isEmpty()) {
        fail(tr("VPN helper sent an invalid challenge"));
        return;
    }
    m_peerProven = true;
    QJsonObject auth;
    auth["cmd"] = "auth";
    auth["proof"] = vpn_helper::authProof(m_token, QString::fromLatin1(vpn_helper::kGuiRole),
                                          helperNonce);
    send(auth);
}

void VpnHelperClient::handleEvent(const QJsonObject &ev) {
    const QString type = ev.value("ev").toString();
    if (type == "challenge") {
        handleChallengeEvent(ev);
        return;
    }
    // Until the peer has proven it holds the token, NOTHING else it says means
    // anything. Verifying the challenge but still acting on an unsolicited
    // "ready" would defeat the whole handshake: a squatter could simply skip the
    // challenge, claim to be ready, and be handed the config TOML — password
    // included — and then report a tunnel that does not exist.
    if (!m_peerProven) {
        fail(tr("The process answering on the helper port did not authenticate — "
                "refusing to continue."));
        return;
    }
    if (type == "ready") {
        handleReadyEvent();
        return;
    }
    if (type == "state") {
        setState(stateFromString(ev.value("state").toString()));
        return;
    }
    if (type == "stats") {
        emit tunnelStats(static_cast<quint64>(ev.value("up").toDouble()),
                         static_cast<quint64>(ev.value("down").toDouble()));
        return;
    }
    if (type == "info") {
        emit connectionInfo(ev.value("msg").toString());
        return;
    }
    if (type == "progress") {
        emit connectProgress(ev.value("msg").toString());
        return;
    }
    if (type == "log") {
        emit coreLogLine(ev.value("msg").toString());
        return;
    }
    if (type == "error") {
        emit vpnError(ev.value("msg").toString());
    }
}

void VpnHelperClient::setState(State s) {
    if (m_state == s) return;
    m_state = s;
    emit stateChanged(m_state);
}

void VpnHelperClient::fail(const QString &msg) {
    abortStartup();
    emit vpnError(msg);
    setState(State::Error);
    setState(State::Disconnected);
}
