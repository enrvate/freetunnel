// cppcheck-suppress-file missingIncludeSystem
#include "qt_trusttunnel_client.h"
#include "qt_trusttunnel_platform.h"
#include "qt_trusttunnel_events.h"
#include "core/AppRules.h"
#include "core/ProcessLookup.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMetaObject>
#include <QRandomGenerator>
#include <QThread>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iterator>
#include <toml++/toml.h>

#ifdef _WIN32
#ifndef IOVEC_DEFINED_QT
#define IOVEC_DEFINED_QT
struct iovec {
    void *iov_base; // cppcheck-suppress unusedStructMember
    size_t iov_len; // cppcheck-suppress unusedStructMember
};
#endif
#endif

#include "vpn/vpn.h"
#include "net/tls.h"

namespace {

// Test-only overrides for the watchdog/join intervals — the real values (10 s /
// 30 s / 15 s) would make the state-machine tests take minutes. Compiled out of
// release builds.
int testHookMs(const char *name, int defaultMs)
{
#ifdef FT_ENABLE_TEST_HOOKS
    bool ok = false;
    const int v = qEnvironmentVariableIntValue(name, &ok);
    if (ok && v > 0)
        return v;
#else
    Q_UNUSED(name);
#endif
    return defaultMs;
}

} // namespace

QtTrustTunnelClient::QtTrustTunnelClient(QObject *parent)
    : QObject(parent) {
    // Parent the member timers so moveToThread() carries them along with this
    // object. The helper server moves the client to a dedicated VPN thread;
    // an unparented member timer stays on the construction thread and Qt then
    // silently refuses every start() from the VPN thread ("Timers cannot be
    // started from another thread") — auto-reconnect, the fd watchdog and the
    // network-wait recovery never fire.
    m_reconnectTimer.setParent(this);
    m_fdWatchdogTimer.setParent(this);
    m_networkWaitTimer.setParent(this);

    m_reconnectTimer.setSingleShot(true);
    connect(&m_reconnectTimer, &QTimer::timeout, this, &QtTrustTunnelClient::startConnectAttempt);

    m_stuckJoinWaitMs = testHookMs("FT_TEST_STUCK_JOIN_MS", 15000);

    // Periodically check open fd count and force clean reconnect if leaking.
    m_fdWatchdogTimer.setInterval(testHookMs("FT_TEST_FD_WATCHDOG_MS", 10000)); // every 10 s
    connect(&m_fdWatchdogTimer, &QTimer::timeout, this, &QtTrustTunnelClient::checkFdHealth);

    // If we stay stuck in WaitingForNetwork for more than 30 s (common after
    // sleep/wake or a brief network blip where the core doesn't self-recover),
    // force a clean teardown and reconnect from the Qt side.
    m_networkWaitTimer.setSingleShot(true);
    m_networkWaitTimer.setInterval(testHookMs("FT_TEST_NETWORK_WAIT_MS", 30000));
    connect(&m_networkWaitTimer, &QTimer::timeout, this, [this]() {
        if (m_state != State::WaitingForNetwork || m_stopRequested || !m_autoReconnect)
            return;
        // Same trade as the fd watchdog: destroying the core client destroys the
        // kill switch with it, and the backoff that follows leaves the machine
        // unprotected for up to 30 s per round — on the network the user just
        // woke up on, which is exactly when they were relying on it. Waiting
        // longer for a core that may be wedged is the safe direction; the state
        // stays WaitingForNetwork, so the UI keeps saying the tunnel is not up.
        if (m_killSwitch) {
            qWarning("[network watchdog] still waiting for network, but the kill switch is on — "
                     "not tearing the client down, since that would drop the traffic block");
            m_networkWaitTimer.start(); // keep checking; do not give up silently
            return;
        }
        teardownClient();
        scheduleReconnect(QStringLiteral("network wait timeout: forcing clean reconnect"));
    });
}

QtTrustTunnelClient::~QtTrustTunnelClient() {
    // Suppress all signal emission during destruction — connected slots may
    // reference this object which is already being torn down.
    m_stopRequested = true;
    // Do this FIRST and outside every other teardown step: an abandoned connect
    // thread resumes inside a native call and then re-checks the guard, and the
    // core callbacks of an abandoned client marshal back through it. Once alive
    // is false neither touches this object again. Released immediately — the
    // join below must never run with the guard mutex held.
    {
        std::lock_guard<std::mutex> lk(m_guard->mutex);
        m_guard->alive = false;
    }
    m_reconnectTimer.stop();
    if (joinOrAbandonConnectThread(m_stuckJoinWaitMs)) {
        delete m_connectThread;
        m_connectThread = nullptr;
    }
    // else: abandoned — the thread (and the core objects it may still touch)
    // intentionally leak; we're going down anyway and a terminate() could
    // deadlock the process on locks the native call holds.
    blockSignals(true);
    teardownClient();
}

void QtTrustTunnelClient::teardownClient() {
    // If teardownClient is called from the object's thread (handleCoreStateChanged,
    // checkFdHealth, disconnectVpn) the connect thread may currently be inside
    // m_client->connect() or set_system_dns(), so resetting m_client while it
    // runs would be a use-after-free. Join it — or, if it is stuck in the
    // native call, abandon it (joinOrAbandonConnectThread hands the core
    // objects over to the stale thread's cleanup, leaving m_client null here).
    //
    // When teardownClient is called FROM the connect thread itself
    // (doConnectAttempt on a reconnect) we must NOT join — that would deadlock.
    if (QThread::currentThread() != m_connectThread)
        joinOrAbandonConnectThread(m_stuckJoinWaitMs);

    // Invalidate the session: any core events still queued (or emitted during
    // the disconnect below) belong to the client being destroyed and must not
    // be attributed to a session started afterwards. The attempt generation goes
    // with it — a worker that finished just before this teardown must not get to
    // install its client afterwards and leave a live tunnel behind a
    // "Disconnected" state.
    ++m_sessionGen;
    ++m_guard->attemptGen;

    if (m_networkMonitor) {
        m_networkMonitor->stop();
        m_networkMonitor.reset();
    }
    if (m_client) {
        m_client->disconnect();
    }
    m_client.reset();
#ifdef Q_OS_WIN
    m_winPhysicalIfIndex.store(0);
#endif
}

void QtTrustTunnelClient::setConfig(ag::TrustTunnelConfig config) {
    std::lock_guard<std::mutex> lk(m_configMutex);
    setConfigLocked(std::move(config));
}

void QtTrustTunnelClient::setConfigLocked(ag::TrustTunnelConfig config) {
    m_config = std::move(config);
    // m_logLevel is set from the config TOML's loglevel in the load functions
    // (driven by the GUI's Verbose-logs toggle: warn by default, info when on).
    m_config->loglevel = m_logLevel;
    ag::Logger::set_log_level(m_logLevel);
    if (std::holds_alternative<ag::TrustTunnelConfig::TunListener>(m_config->listener)) {
        auto &tun = std::get<ag::TrustTunnelConfig::TunListener>(m_config->listener);
        tun.excluded_routes.insert(tun.excluded_routes.end(), m_extraExcludedRoutes.begin(), m_extraExcludedRoutes.end());
    }
    // Append extra exclusions (domain bypass rules)
    // Save original exclusions before we touch them so they can be restored
    // if the user changes bypass rules later.
    m_originalExclusions = m_config->exclusions;
    for (const auto &ex : m_extraExclusions) {
        if (!m_config->exclusions.empty() && m_config->exclusions.back() != ' ') {
            m_config->exclusions.push_back(' ');
        }
        m_config->exclusions.append(ex);
    }
    // Routing policy: general = bypass the exclusions, selective = route only them.
    m_config->mode = m_selectiveMode ? ag::VPN_MODE_SELECTIVE : ag::VPN_MODE_GENERAL;
    m_config->killswitch_enabled = m_killSwitch;
}

void QtTrustTunnelClient::setVpnMode(bool selective) {
    {
        std::lock_guard<std::mutex> lk(m_configMutex);
        m_selectiveMode = selective;
        if (m_config.has_value())
            m_config->mode = selective ? ag::VPN_MODE_SELECTIVE : ag::VPN_MODE_GENERAL;
    }
    // App rules read the mode the same way the routes and domains lists do, so
    // it has to reach their snapshot too — otherwise switching mode would flip
    // every list except this one.
    std::lock_guard<std::mutex> lk(m_appRules->mutex);
    m_appRules->selective = selective;
}

void QtTrustTunnelClient::setAppRules(const QStringList &rules) {
    // Sanitized here rather than trusted from the IPC: this runs in the
    // elevated helper, and a rule that cannot match is better dropped than
    // carried into a routing decision.
    const QStringList clean = freetunnel::sanitizedAppRules(rules);
    std::lock_guard<std::mutex> lk(m_appRules->mutex);
    m_appRules->rules = clean;
}

void QtTrustTunnelClient::setKillSwitch(bool enabled) {
    std::lock_guard<std::mutex> lk(m_configMutex);
    m_killSwitch = enabled;
    if (m_config.has_value())
        m_config->killswitch_enabled = enabled;
}

void QtTrustTunnelClient::setSessionLogging(bool enabled)
{
    // The path is derived here and never supplied by the caller. This object
    // runs inside the ELEVATED helper, and the core creates (and creates the
    // parent directory of) whatever it is told to use — so accepting a path over
    // IPC was a root file-write primitive that had to be fenced in with owner,
    // symlink and canonicality checks. Not offering the choice removes the whole
    // class instead of guarding it: the file below is a transport buffer the
    // helper tails and forwards, and the GUI keeps the durable log.
    {
        std::lock_guard<std::mutex> lk(m_configMutex);
        m_loggingEnabled = enabled;
        m_coreLogPath = enabled ? qt_trusttunnel_default_core_log_path() : QString();
        applyCoreLogPathToConfigLocked();
    }
    if (!enabled)
        stopCoreLogTail();
}

// The core's build_config may not surface the TOML `loglevel`, so read it back
// ourselves and use it as the client log level. The GUI sets it from the
// Verbose-logs toggle (warn by default, info when on); without this the core
// stayed pinned at the default level and the toggle did nothing.
static ag::LogLevel logLevelFromTomlTable(const toml::table &t, ag::LogLevel fallback)
{
    if (const auto lvl = t["loglevel"].value<std::string>())
        return qt_trusttunnel_parse_log_level(QString::fromStdString(*lvl));
    return fallback;
}

bool QtTrustTunnelClient::loadConfigFromToml(const QString &tomlContent) {
    if (tomlContent.isEmpty()) {
        setState(State::Error);
        emit vpnError(QStringLiteral("Empty config"));
        return false;
    }
    toml::parse_result parsed = toml::parse(tomlContent.toStdString());
    if (!parsed) {
        // Copy immediately: description() hands back a view owned by the parse
        // result, and keeping a view alive across statements is a lifetime trap.
        const std::string descr{parsed.error().description()};
        setState(State::Error);
        emit vpnError(QString("Failed parsing config: %1").arg(QString::fromStdString(descr)));
        return false;
    }

    auto config = ag::TrustTunnelConfig::build_config(parsed.table());
    if (!config.has_value()) {
        setState(State::Error);
        emit vpnError(QStringLiteral("Invalid TrustTunnel config structure"));
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(m_configMutex);
        m_lastConfigToml = tomlContent;
        m_logLevel = logLevelFromTomlTable(parsed.table(), m_logLevel);
        setConfigLocked(std::move(*config));
    }
    setState(State::Disconnected);
    return true;
}

void QtTrustTunnelClient::setReconnectBoundsMs(int initialDelayMs, int maxDelayMs) {
    m_reconnectDelayMs = std::max(250, initialDelayMs);
    m_reconnectMaxMs = std::max(m_reconnectDelayMs, maxDelayMs);
}

void QtTrustTunnelClient::setExtraExclusionDomains(const QStringList &domains)
{
    std::vector<std::string> exclusions;
    exclusions.reserve(static_cast<size_t>(domains.size()));
    std::transform(domains.cbegin(), domains.cend(), std::back_inserter(exclusions),
                   [](const QString &d) { return d.toStdString(); });
    setExtraExclusions(exclusions);
}

void QtTrustTunnelClient::setExcludedRouteStrings(const QStringList &routes)
{
    std::vector<std::string> excluded;
    excluded.reserve(static_cast<size_t>(routes.size()));
    std::transform(routes.cbegin(), routes.cend(), std::back_inserter(excluded),
                     [](const QString &r) { return r.toStdString(); });
    setExcludedRoutes(excluded);
}

void QtTrustTunnelClient::disconnectVpn() {
    m_stopRequested = true;
    // beginConnect()'s delayed start compares this: a disconnect that lands
    // inside the teardown delay must cancel the pending connect instead of
    // letting the tunnel come up after the user explicitly stopped it.
    ++m_disconnectGen;
    m_reconnectTimer.stop();
    m_fdWatchdogTimer.stop();
    m_networkWaitTimer.stop();
    stopCoreLogTail();

    // Stop the in-flight attempt. Bounded: an attempt stuck inside a blocking
    // native call is abandoned after m_stuckJoinWaitMs (see
    // joinOrAbandonConnectThread) so the user's disconnect always completes.
    joinOrAbandonConnectThread(m_stuckJoinWaitMs);

    setState(State::Disconnecting);
    teardownClient();

    m_everConnected = false;
    setState(State::Disconnected);
    emit vpnDisconnected();
    // NOTE: m_stopRequested is intentionally left TRUE so that any stale
    // core state-change callbacks still queued (via Qt::QueuedConnection)
    // are silently discarded by handleCoreStateChanged(). The flag is
    // reset in connectVpn() when the user initiates a new session.
}

bool QtTrustTunnelClient::isConnected() const {
    return m_state == State::Connected;
}

QtTrustTunnelClient::State QtTrustTunnelClient::state() const {
    return m_state;
}

void QtTrustTunnelClient::setLogLevel(const QString &level) {
    {
        std::lock_guard<std::mutex> lk(m_configMutex);
        m_logLevel = qt_trusttunnel_parse_log_level(level);
        ag::Logger::set_log_level(m_logLevel);
        if (m_config.has_value()) {
            m_config->loglevel = m_logLevel;
        }
    }
    // The per-connection handler reads this from its own snapshot rather than
    // the config, for the same reason it reads the rules there: it must not
    // depend on this object still existing.
    std::lock_guard<std::mutex> lk(m_appRules->mutex);
    // "info" and not "debug": that is what the Verbose logs switch actually
    // sends (BackendSettings.cpp sends info when on, warn when off). Checking
    // for debug here would have made this dead code.
    const QString l = level.toLower();
    m_appRules->verbose = l == QLatin1String("info") || l == QLatin1String("debug")
            || l == QLatin1String("trace");
}

void QtTrustTunnelClient::setExcludedRoutes(const std::vector<std::string> &excludeRoutes) {
    std::lock_guard<std::mutex> lk(m_configMutex);
    m_extraExcludedRoutes = excludeRoutes;
    if (m_config.has_value() && std::holds_alternative<ag::TrustTunnelConfig::TunListener>(m_config->listener)) {
        auto &tun = std::get<ag::TrustTunnelConfig::TunListener>(m_config->listener);
        tun.excluded_routes.insert(tun.excluded_routes.end(), m_extraExcludedRoutes.begin(), m_extraExcludedRoutes.end());
    }
}

void QtTrustTunnelClient::setExtraExclusions(const std::vector<std::string> &exclusions) {
    std::lock_guard<std::mutex> lk(m_configMutex);
    m_extraExclusions = exclusions;
    if (m_config.has_value()) {
        // Restore original config exclusions first, then append new ones.
        // This prevents duplicate/stale entries from accumulating.
        m_config->exclusions = m_originalExclusions;
        for (const auto &ex : m_extraExclusions) {
            if (!m_config->exclusions.empty() && m_config->exclusions.back() != ' ') {
                m_config->exclusions.push_back(' ');
            }
            m_config->exclusions.append(ex);
        }
    }
}

void QtTrustTunnelClient::postCoreStateChanged(quint64 session, int coreState, int errCode,
                                               const QString &errText)
{
    QMetaObject::invokeMethod(
            this,
            [this, session, coreState, errCode, errText]() {
                if (session != m_sessionGen)
                    return;
                handleCoreStateChanged(static_cast<ag::VpnSessionState>(coreState), errCode,
                                       errText);
            },
            Qt::QueuedConnection);
}

void QtTrustTunnelClient::postTunnelStats(quint64 session, quint64 up, quint64 down)
{
    QMetaObject::invokeMethod(
            this,
            [this, session, up, down]() {
                if (session == m_sessionGen)
                    emit tunnelStats(up, down);
            },
            Qt::QueuedConnection);
}

void QtTrustTunnelClient::postConnectionInfo(quint64 session, const QString &line)
{
    QMetaObject::invokeMethod(
            this,
            [this, session, line]() {
                if (session == m_sessionGen)
                    emit connectionInfo(line);
            },
            Qt::QueuedConnection);
}

namespace {

// One line, in the order someone diagnosing reads it: did it run, as whom, how
// much did it see, and how long did it take.
QString describeScan(const freetunnel::ProcessLookup::ScanReport &r)
{
    return QStringLiteral("app rules: scan %1 — euid %2, pids %3 (%4 refused), sockets %5, "
                          "entries %6, distinct %7, errno %8, %9 ms")
            .arg(r.ok ? QStringLiteral("ok") : QStringLiteral("FAILED"))
            .arg(r.euid)
            .arg(r.pidsScanned)
            .arg(r.pidsSkipped)
            .arg(r.socketsSeen)
            .arg(r.entries)
            .arg(r.distinctPids)
            .arg(r.lastErrno)
            .arg(r.elapsedMs);
}

} // namespace

// Split out of makeCallbacks, which had grown to 145 lines around it. The seam
// is the one the code already had: this is a self-contained lambda with its own
// captures and no reference to anything else being built there.
std::function<void(const ag::VpnConnectRequestSnapshot &, ag::VpnConnectDecision *)>
QtTrustTunnelClient::makeConnectRequestHandler(const GuardPtr &guard, quint64 session) {
    // Per-application split tunnelling. This runs on the wrapper's own loop, one
    // connection at a time, which is what lets it read the system's socket
    // tables without stalling traffic. The rules come from a shared snapshot so
    // the lookup needs no lock on this object; `this` is touched only at the
    // end, to log, and only under the liveness guard.
    auto lookup = std::make_shared<freetunnel::ProcessLookup>();
    auto scanWarned = std::make_shared<bool>(false);
    auto appRules = m_appRules;
    return [this, guard, session, appRules, lookup,
            scanWarned](const ag::VpnConnectRequestSnapshot &req,
                                                 ag::VpnConnectDecision *decision) {
        if (decision == nullptr)
            return;
        QStringList rules;
        bool selective = false;
        bool verbose = false;
        {
            std::lock_guard<std::mutex> lk(appRules->mutex);
            rules = appRules->rules;
            selective = appRules->selective;
            verbose = appRules->verbose;
        }
        // No rules means the feature is off, and off must cost nothing: no
        // table walk, and the same VPN_CA_DEFAULT the wrapper answered before
        // any of this existed.
        if (rules.isEmpty())
            return;

        const freetunnel::LocalFlow flow{req.family, req.proto, req.src_port,
                                         QString::fromStdString(req.src_ip)};
        const freetunnel::AppIdentity app = lookup->resolve(flow);
        switch (freetunnel::appActionFor(app, rules, selective)) {
        case freetunnel::AppAction::ForceBypass:
            decision->action = ag::VPN_CA_FORCE_BYPASS;
            break;
        case freetunnel::AppAction::ForceTunnel:
            decision->action = ag::VPN_CA_FORCE_REDIRECT;
            break;
        case freetunnel::AppAction::Default:
            break;
        }
        // decision->app_name is deliberately NOT set. It looks like a harmless way
        // to get the program into the core's own log, and it is not: the core
        // passes it to the upstream, which puts it in the CONNECT request sent
        // to the VPN endpoint (upstream open_connection -> send_connect_request
        // -> make_http_connect_request). That would tell the operator which
        // application opened every connection — a thing this app exists to avoid
        // telling anyone. The line below puts it in the local log instead, which
        // is where the user was going to look anyway.

        // And say so in the app's own log. Without this the feature is
        // unobservable: a rule that never matched and a rule that matched and
        // was overruled look identical from outside, and the first question
        // anyone asks — "did it even see my program?" — has no answer.
        // Said once per session, in the app's own log, because the helper's
        // stderr goes to a root-owned temp file nobody reporting a problem will
        // ever read. The numbers are the point: distinct is what distinguishes
        // "this process cannot see other processes" (1) from "the table is full
        // and the port simply was not in it" (hundreds), and those need
        // completely different fixes. It replaces a yes/no that could not fire
        // in either case.
        if (!*scanWarned) {
            *scanWarned = true;
            const QString line = describeScan(lookup->lastScan());
            std::lock_guard<std::mutex> lk(guard->mutex);
            if (guard->alive)
                postConnectionInfo(session, line);
        }

        const bool routed = decision->action == ag::VPN_CA_FORCE_BYPASS
                || decision->action == ag::VPN_CA_FORCE_REDIRECT;
        // A connection nobody wrote a rule for is the overwhelming majority, and
        // logging those buries the handful that matter under every program on
        // the machine. Verbose is where that question gets answered.
        if (!routed && !verbose)
            return;
        const QString who = app.name.isEmpty()
                ? QStringLiteral("unknown (port %1)").arg(req.src_port)
                : app.name;
        const QString what = decision->action == ag::VPN_CA_FORCE_BYPASS ? QStringLiteral("bypass")
                : decision->action == ag::VPN_CA_FORCE_REDIRECT          ? QStringLiteral("tunnel")
                                                                         : QStringLiteral("no rule");
        // The lookup above may be slow; the guard is taken only now, and only
        // to reach back into an object that may have been destroyed meanwhile.
        std::lock_guard<std::mutex> lk(guard->mutex);
        if (guard->alive)
            postConnectionInfo(session, QStringLiteral("app %1 → %2").arg(who, what));
    };
}

ag::VpnCallbacks QtTrustTunnelClient::makeCallbacks(const GuardPtr &guard) {
    // Core callbacks are queued to our event loop, so events from a client that
    // has since been torn down (config switch: disconnect + connect a new one)
    // can arrive after the next session already started. A stale DISCONNECTED
    // would then trigger a bogus reconnect of the NEW session. Tag every event
    // with the session generation it belongs to and drop mismatches on arrival.
    //
    // An ABANDONED client outlives this object entirely, so the hop back to it
    // is taken under the guard: while the mutex is held `alive` cannot flip, and
    // once the destructor has cleared it no callback dereferences `this` again.
    // Note the payload is extracted BEFORE the lock — that touches the event,
    // not this object, and must not happen while holding it.
    const quint64 session = ++m_sessionGen;
    ag::VpnCallbacks callbacks;
    callbacks.verify_handler = qt_trusttunnel_verify_server_certificate;
    callbacks.protect_handler = [this, guard](ag::SocketProtectEvent *event) {
        std::lock_guard<std::mutex> lk(guard->mutex);
        if (guard->alive)
            protectOutboundSocket(event);
    };
    callbacks.state_changed_handler = [this, guard, session](ag::VpnStateChangedEvent *event) {
        const StateChangedPayload payload = extractStateChangedPayload(event);
        std::lock_guard<std::mutex> lk(guard->mutex);
        if (guard->alive)
            postCoreStateChanged(session, static_cast<int>(payload.state), payload.errCode,
                                 payload.errText);
    };
    callbacks.tunnel_stats_handler = [this, guard,
                                      session](ag::VpnTunnelConnectionStatsEvent *event) {
        if (!event)
            return;
        const quint64 up = event->upload;
        const quint64 down = event->download;
        std::lock_guard<std::mutex> lk(guard->mutex);
        if (guard->alive)
            postTunnelStats(session, up, down);
    };
    callbacks.connect_request_handler = makeConnectRequestHandler(guard, session);
    callbacks.connection_info_handler = [this, guard, session](ag::VpnConnectionInfoEvent *event) {
        const QString line = qt_trusttunnel_connection_info_line(event);
        std::lock_guard<std::mutex> lk(guard->mutex);
        if (guard->alive)
            postConnectionInfo(session, line);
    };
    return callbacks;
}


void QtTrustTunnelClient::protectOutboundSocket(ag::SocketProtectEvent *event)
{
#ifdef Q_OS_WIN
    pinWindowsPhysicalOutbound(m_winPhysicalIfIndex.load());
#endif
    qt_trusttunnel_protect_outbound_socket(event);
}

void QtTrustTunnelClient::scheduleReconnect(const QString &reason) {
    // Failed connect attempts call this from m_connectThread; the timers live
    // on this object's thread and QTimer::start() from any other thread is a
    // silent no-op — the retry would never fire. Marshal onto our thread.
    if (QThread::currentThread() != thread()) {
        const QString reasonCopy = reason;
        QMetaObject::invokeMethod(
                this, [this, reasonCopy]() { scheduleReconnect(reasonCopy); }, Qt::QueuedConnection);
        return;
    }

    const QString message = reason.isEmpty() ? QStringLiteral("connect() failed") : reason;
    if (m_stopRequested) {
        // The user asked to disconnect while an attempt was in flight — the
        // session is over, don't overwrite Disconnected with a spurious Error.
        return;
    }
    if (!m_autoReconnect) {
        setState(State::Error);
        emit vpnError(message);
        return;
    }

    // If the timer is already running, don't restart it — avoids resetting the
    // countdown and double-incrementing the delay.
    if (m_reconnectTimer.isActive()) {
        return;
    }

    // If the connection was very short-lived (<10s), the issue is likely
    // persistent — increase the backoff faster to avoid a rapid reconnect loop.
    auto now = std::chrono::steady_clock::now();
    const auto lastAttempt = m_lastConnectAttempt.load();
    auto sinceLastAttempt = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastAttempt).count();
    if (lastAttempt != std::chrono::steady_clock::time_point{} && sinceLastAttempt < 10000) {
        m_reconnectDelayMs = std::min(m_reconnectDelayMs * 2, m_reconnectMaxMs);
    }

    // Add jitter (±20%) to avoid thundering-herd reconnects.
    int jitter = static_cast<int>(m_reconnectDelayMs * 0.2);
    int jitteredDelay = m_reconnectDelayMs
            + (jitter > 0 ? QRandomGenerator::global()->bounded(-jitter, jitter + 1) : 0);
    jitteredDelay = std::max(250, jitteredDelay);

    setState(State::Reconnecting);
    emit vpnError(message);
    m_reconnectTimer.start(jitteredDelay);
    m_reconnectDelayMs = std::min(m_reconnectDelayMs * 2, m_reconnectMaxMs);
}

void QtTrustTunnelClient::setState(State s) {
    if (m_state.exchange(s) == s) {
        return;
    }
    emit stateChanged(s);
}

void QtTrustTunnelClient::handleCoreConnected()
{
    m_reconnectDelayMs = 1000;
    m_reconnectTimer.stop();
    m_networkWaitTimer.stop();
    m_everConnected = true;
    m_fdBaseline = countOpenFds();
    setState(State::Connected);
    emit vpnConnected();
}

void QtTrustTunnelClient::handleCoreConnecting()
{
    m_networkWaitTimer.stop();
    setState(m_everConnected ? State::Reconnecting : State::Connecting);
}

void QtTrustTunnelClient::handleCoreRecovery(const QString &reason)
{
    // Core handles in-process recovery; tearing down here races DNS/network restarts
    // and leaves the tunnel stuck in VPN_SS_WAITING_RECOVERY until vpn_stop.
    m_networkWaitTimer.stop();
    m_reconnectTimer.stop();
    setState(m_everConnected ? State::Reconnecting : State::Connecting);
    if (!reason.isEmpty())
        emit connectionInfo(reason);
}

void QtTrustTunnelClient::handleCoreWaitingForNetwork()
{
    setState(State::WaitingForNetwork);
    if (!m_stopRequested && m_autoReconnect)
        m_networkWaitTimer.start();
}

void QtTrustTunnelClient::handleCoreDisconnected(int errCode, const QString &errText)
{
    m_networkWaitTimer.stop();
    if (m_stopRequested)
        return;
    scheduleReconnect(
            buildDisconnectReason(errCode, errText, m_everConnected, m_lastConnectAttempt.load()));
}

void QtTrustTunnelClient::handleCoreStateChanged(ag::VpnSessionState coreState, int errCode,
                                                 const QString &errText) {
    if (m_stopRequested)
        return;

    switch (coreState) {
    case ag::VPN_SS_CONNECTED:
        handleCoreConnected();
        break;
    case ag::VPN_SS_CONNECTING:
        handleCoreConnecting();
        break;
    case ag::VPN_SS_RECOVERING:
        handleCoreRecovery(recoveryReason(QStringLiteral("recovery"), errCode, errText));
        break;
    case ag::VPN_SS_WAITING_RECOVERY:
        handleCoreRecovery(recoveryReason(QStringLiteral("waiting recovery"), errCode, errText));
        break;
    case ag::VPN_SS_WAITING_FOR_NETWORK:
        handleCoreWaitingForNetwork();
        break;
    case ag::VPN_SS_DISCONNECTED:
        handleCoreDisconnected(errCode, errText);
        break;
    default:
        break;
    }
}
// countOpenFds / getFdLimit / checkFdHealth / forceFdReconnect live in
// qt_trusttunnel_fdwatch.cpp.

// applyCoreLogPathToConfig / resetCoreLogFile / startCoreLogTail /
// stopCoreLogTail / pollCoreLogFile live in qt_trusttunnel_corelog.cpp.
