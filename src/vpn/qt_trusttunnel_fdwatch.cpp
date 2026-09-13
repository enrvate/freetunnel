// cppcheck-suppress-file missingIncludeSystem
// fd-leak watchdog for QtTrustTunnelClient: a leaking core session shows up as
// unbounded fd growth; force a clean reconnect before the process hits the
// rlimit and every socket/file operation starts failing.
#include "qt_trusttunnel_client.h"

#include <algorithm>

#ifndef _WIN32
#include <dirent.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

int QtTrustTunnelClient::countOpenFds() {
#if defined(__APPLE__) || defined(__linux__)
    DIR *dir = opendir("/dev/fd");
    if (!dir) {
        // Fallback for Linux: /proc/self/fd
        dir = opendir("/proc/self/fd");
    }
    // Both opendir calls need a descriptor themselves, so they fail with EMFILE
    // exactly when the process is out of them — i.e. when the watchdog matters
    // most. Reporting that as a count of 0 made checkFdHealth() treat it as a
    // healthy baseline and then, once fds recovered, read the recovery as
    // runaway growth and tear down a perfectly good tunnel.
    if (!dir)
        return -1;
    int count = 0;
    while (readdir(dir) != nullptr) {
        ++count;
    }
    closedir(dir);
    count -= 2; // subtract "." and ".."
    return count < 0 ? 0 : count;
#else
    return -1; // not supported on Windows
#endif
}

int QtTrustTunnelClient::getFdLimit() {
#ifndef _WIN32
    struct rlimit rl{};
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        return static_cast<int>(rl.rlim_cur);
    }
#endif
    return -1;
}

void QtTrustTunnelClient::forceFdReconnect(const QString &logReason, const QString &userReason)
{
    qWarning("%s", qPrintable(logReason));
    // The kill switch exists only as a flag on the live core client, so
    // teardownClient() takes the traffic block down along with the tun device,
    // the routes and the DNS override — and scheduleReconnect() then waits, up to
    // 30 s per round and doubling. This watchdog is the sharp case: it fires while
    // the tunnel is Connected and healthy, so a leaking fd counter would cost the
    // user an unprotected window on a working connection. Leaking fds is a
    // resource problem, not a connectivity one; it does not break the tunnel now,
    // and it is not worth trading protection for. Keep the tunnel and keep saying
    // so — loudly, every time the watchdog fires, so the condition is visible in
    // the log rather than silently endured.
    if (m_killSwitch) {
        qWarning("[fd watchdog] kill switch is on — keeping the tunnel up rather than "
                 "reconnecting, which would drop the traffic block for the whole backoff");
        emit vpnError(QObject::tr("The connection is using an unusual number of system "
                                  "resources. The tunnel is being kept up because the kill "
                                  "switch is on — reconnect manually when convenient."));
        return;
    }
    emit vpnError(userReason);
    teardownClient();
    if (!m_stopRequested && m_autoReconnect)
        scheduleReconnect(QStringLiteral("fd watchdog: too many open files, clean reconnect"));
}

void QtTrustTunnelClient::checkFdHealth() {
    if (m_state != State::Connected && m_state != State::Reconnecting)
        return;
    const int openFds = countOpenFds();
    if (openFds < 0)
        return;

    // Judged on the FLOOR, not the current count. This check exists to catch
    // descriptors that are lost and never returned, and comparing the current
    // count to the connect-time baseline could not tell that apart from load —
    // which per-application split tunnelling turned from theory into a daily
    // false alarm. A program routed around the tunnel opens its connections
    // directly from this process, so a browser on the bypass list legitimately
    // holds dozens of sockets here, and the user was told the connection was
    // "using an unusual number of system resources" for working correctly.
    //
    // A leak never gives its descriptors back, so the lowest reading in the
    // window keeps climbing. Load raises the peak and lets it fall again, and
    // one low reading anywhere in the window is enough to say so.
    constexpr int kFdWindow = 6;
    m_fdSamples.append(openFds);
    while (m_fdSamples.size() > kFdWindow)
        m_fdSamples.removeFirst();

    const int fdLimit = getFdLimit();
    // Scaled to the resource rather than a flat 64 — on a machine that allows
    // ten thousand descriptors, sixty-four of them is noise — but capped, because
    // a limit of a million would put the threshold past any leak worth catching.
    // A thousand descriptors that never come back is unambiguous either way.
    const int growthThreshold = std::clamp(fdLimit > 0 ? fdLimit / 4 : 256, 256, 1024);
    const int windowFloor =
            m_fdSamples.size() == kFdWindow ? *std::min_element(m_fdSamples.cbegin(),
                                                                m_fdSamples.cend())
                                            : -1;
    if (m_fdBaseline >= 0 && windowFloor >= 0 && windowFloor - m_fdBaseline >= growthThreshold) {
        forceFdReconnect(
                QStringLiteral("[fd watchdog] Open fds have not fallen below %1 across %2 checks, "
                               "%3 above the baseline of %4 (currently %5)")
                        .arg(windowFloor)
                        .arg(kFdWindow)
                        .arg(windowFloor - m_fdBaseline)
                        .arg(m_fdBaseline)
                        .arg(openFds),
                QStringLiteral("fd watchdog: reconnecting after fd growth"));
        return;
    }

    if (fdLimit < 0)
        return;
    const double usage = static_cast<double>(openFds) / static_cast<double>(fdLimit);
    if (usage > 0.85) {
        forceFdReconnect(
                QStringLiteral("[fd watchdog] Open fds: %1 / %2 (%3%)")
                        .arg(openFds)
                        .arg(fdLimit)
                        .arg(static_cast<int>(usage * 100.0)),
                QStringLiteral("fd watchdog: reconnecting near fd limit"));
    }
}
