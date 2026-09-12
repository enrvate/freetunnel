// cppcheck-suppress-file missingIncludeSystem
#include "qt_trusttunnel_client.h"

// For inet_ntop/ntohs in the address formatter below.
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <QDir>
#include <QHash>
#include <QStandardPaths>

#include <string>

#include "net/network_manager.h"
#include "net/tls.h"
#include "vpn/vpn.h"

#if defined(__linux__)
#include <net/if.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include "net/os_tunnel.h"
#include <windows.h>

bool qt_trusttunnel_is_process_elevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}
#endif

QString qt_trusttunnel_default_core_log_path()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
            + QStringLiteral("/freetunnel.log");
}

static const QHash<int, QString> &vpnErrorCodeNames()
{
    static const QHash<int, QString> names = {
            {ag::VPN_EC_NOERROR, QStringLiteral("OK")},
            {ag::VPN_EC_ERROR, QStringLiteral("ERROR")},
            {ag::VPN_EC_INVALID_SETTINGS, QStringLiteral("INVALID_SETTINGS")},
            {ag::VPN_EC_ADDR_IN_USE, QStringLiteral("ADDR_IN_USE")},
            {ag::VPN_EC_INVALID_STATE, QStringLiteral("INVALID_STATE")},
            {ag::VPN_EC_AUTH_REQUIRED, QStringLiteral("AUTH_REQUIRED")},
            {ag::VPN_EC_LOCATION_UNAVAILABLE, QStringLiteral("LOCATION_UNAVAILABLE")},
            {ag::VPN_EC_CERTIFICATE_VERIFICATION_FAILED, QStringLiteral("CERTIFICATE_VERIFICATION_FAILED")},
            {ag::VPN_EC_EVENT_LOOP_FAILURE, QStringLiteral("EVENT_LOOP_FAILURE")},
            {ag::VPN_EC_INITIAL_CONNECT_FAILED, QStringLiteral("INITIAL_CONNECT_FAILED")},
            {ag::VPN_EC_FATAL_CONNECTIVITY_ERROR, QStringLiteral("FATAL_CONNECTIVITY_ERROR")},
    };
    return names;
}

static QString vpnErrorCodeName(int code)
{
    const auto it = vpnErrorCodeNames().constFind(code);
    return it != vpnErrorCodeNames().constEnd() ? *it : QStringLiteral("ERR_%1").arg(code);
}

QString qt_trusttunnel_format_vpn_error(int code, const QString &text)
{
    const QString trimmed = text.trimmed();
    if (code == ag::VPN_EC_NOERROR && trimmed.isEmpty())
        return QString();
    if (trimmed.isEmpty())
        return vpnErrorCodeName(code);
    if (code == ag::VPN_EC_NOERROR || code == ag::VPN_EC_ERROR)
        return trimmed;
    return QStringLiteral("%1 (%2)").arg(trimmed, vpnErrorCodeName(code));
}

ag::LogLevel qt_trusttunnel_parse_log_level(const QString &level)
{
    const QString l = level.toLower();
    if (l == "error")
        return ag::LOG_LEVEL_ERROR;
    if (l == "warn" || l == "warning")
        return ag::LOG_LEVEL_WARN;
    if (l == "debug")
        return ag::LOG_LEVEL_DEBUG;
    if (l == "trace")
        return ag::LOG_LEVEL_TRACE;
    return ag::LOG_LEVEL_INFO;
}

#if defined(__APPLE__)
static void protectOutboundSocketApple(ag::SocketProtectEvent *event)
{
    const uint32_t idx = ag::vpn_network_manager_get_outbound_interface();
    if (idx == 0)
        return;
    const int level = event->peer->sa_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
    const int opt = event->peer->sa_family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF;
    if (setsockopt(event->fd, level, opt, &idx, sizeof(idx)) != 0)
        event->result = -1;
}
#endif

#if defined(__linux__)
static void protectOutboundSocketLinux(ag::SocketProtectEvent *event)
{
    if (geteuid() != 0) {
        event->result = -1;
        return;
    }
    const uint32_t idx = ag::vpn_network_manager_get_outbound_interface();
    if (idx == 0) {
        event->result = -1;
        return;
    }
    char ifname[IFNAMSIZ]{};
    if (if_indextoname(static_cast<unsigned int>(idx), ifname) == nullptr)
        event->result = -1;
    else {
        const socklen_t optlen =
                static_cast<socklen_t>(std::char_traits<char>::length(ifname) + 1);
        if (setsockopt(event->fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, optlen) != 0)
            event->result = -1;
    }
}
#endif

#ifdef _WIN32
static void protectOutboundSocketWin(ag::SocketProtectEvent *event)
{
    const uint32_t outbound = ag::vpn_network_manager_get_outbound_interface();
    if (!ag::vpn_win_socket_protect(event->fd, event->peer)) {
        qWarning("Windows socket protect failed (outbound ifindex %u)", outbound);
        event->result = -1;
    }
}
#endif

void qt_trusttunnel_protect_outbound_socket(ag::SocketProtectEvent *event)
{
    if (!event)
        return;
    event->result = 0;
#if defined(__APPLE__)
    protectOutboundSocketApple(event);
#elif defined(__linux__)
    protectOutboundSocketLinux(event);
#elif defined(_WIN32)
    protectOutboundSocketWin(event);
#endif
}

void qt_trusttunnel_verify_server_certificate(ag::VpnVerifyCertificateEvent *event)
{
    if (!event)
        return;
    const char *err = ag::tls_verify_cert(event->cert, event->chain, nullptr);
    if (err != nullptr) {
        qWarning("TrustTunnel certificate verification failed: %s", err);
        event->result = -1;
        return;
    }
    event->result = 0;
}

// "203.0.113.7:443", or "[2001:db8::1]:443" — bracketed so the port is readable
// next to a v6 address instead of running into its colons.
QString qt_trusttunnel_format_address(const struct sockaddr *sa)
{
    if (sa == nullptr)
        return {};
    char buf[INET6_ADDRSTRLEN] = {};
    if (sa->sa_family == AF_INET) {
        const auto *in4 = reinterpret_cast<const struct sockaddr_in *>(sa);
        if (inet_ntop(AF_INET, &in4->sin_addr, buf, sizeof(buf)) == nullptr)
            return {};
        return QStringLiteral("%1:%2").arg(QLatin1String(buf)).arg(ntohs(in4->sin_port));
    }
    if (sa->sa_family == AF_INET6) {
        const auto *in6 = reinterpret_cast<const struct sockaddr_in6 *>(sa);
        if (inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf)) == nullptr)
            return {};
        return QStringLiteral("[%1]:%2").arg(QLatin1String(buf)).arg(ntohs(in6->sin6_port));
    }
    return {};
}

QString qt_trusttunnel_connection_info_line(ag::VpnConnectionInfoEvent *event)
{
    if (!event)
        return QStringLiteral("connection info");
    QString action;
    switch (event->action) {
    case ag::VPN_FCA_BYPASS: action = QStringLiteral("bypass"); break;
    case ag::VPN_FCA_TUNNEL: action = QStringLiteral("tunnel"); break;
    case ag::VPN_FCA_REJECT: action = QStringLiteral("reject"); break;
    default: action = QStringLiteral("unknown"); break;
    }
    // A connection made straight to an address has no domain, and printing a
    // dash for it made a whole class of log lines useless — "bypass -" says
    // nothing about what was bypassed. The address is what there is to say.
    QString target = event->domain ? QString::fromUtf8(event->domain) : QString();
    if (target.isEmpty() && event->dst != nullptr)
        target = qt_trusttunnel_format_address(event->dst->c_sockaddr());
    if (target.isEmpty())
        target = QStringLiteral("unknown destination");
    return QStringLiteral("%1 %2").arg(action, target);
}
