// cppcheck-suppress-file missingIncludeSystem
// Minimal mock of the TrustTunnel core API surface used by the Qt wrapper
// (src/vpn/qt_trusttunnel_*). Lets tests compile QtTrustTunnelClient without
// the native core and drive its state machine via mockcore::Controller.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace ag {

enum VpnSessionState {
    VPN_SS_DISCONNECTED,
    VPN_SS_CONNECTING,
    VPN_SS_CONNECTED,
    VPN_SS_RECOVERING,
    VPN_SS_WAITING_RECOVERY,
    VPN_SS_WAITING_FOR_NETWORK,
};

enum VpnErrorCode {
    VPN_EC_NOERROR = 0,
    VPN_EC_ERROR,
    VPN_EC_INVALID_SETTINGS,
    VPN_EC_ADDR_IN_USE,
    VPN_EC_INVALID_STATE,
    VPN_EC_AUTH_REQUIRED,
    VPN_EC_LOCATION_UNAVAILABLE,
    VPN_EC_CERTIFICATE_VERIFICATION_FAILED,
    VPN_EC_EVENT_LOOP_FAILURE,
    VPN_EC_INITIAL_CONNECT_FAILED,
    VPN_EC_FATAL_CONNECTIVITY_ERROR,
};

// What the client may answer to a connect request. Mirrors the core enum; the
// two forced values are what per-app rules use to override the mode.
enum VpnConnectAction {
    VPN_CA_DEFAULT,
    VPN_CA_FORCE_BYPASS,
    VPN_CA_FORCE_REDIRECT,
    VPN_CA_REJECT,
};

enum VpnFilteredConnectionAction {
    VPN_FCA_BYPASS,
    VPN_FCA_TUNNEL,
    VPN_FCA_REJECT,
};

enum LogLevel {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE,
};

enum VpnMode {
    VPN_MODE_GENERAL,
    VPN_MODE_SELECTIVE,
};

struct VpnError {
    int code = VPN_EC_NOERROR;
    const char *text = nullptr;
};

struct VpnStateChangedEvent {
    VpnSessionState state = VPN_SS_DISCONNECTED;
    VpnError error;
    struct {
        VpnError error;
    } waiting_recovery_info;
};

struct MockIoChunk {
    size_t iov_len = 0;
};

struct VpnClientOutputEvent {
    struct {
        size_t chunks_num = 0;
        const MockIoChunk *chunks = nullptr;
    } packet;
};

struct VpnTunnelConnectionStatsEvent {
    uint64_t upload = 0;
    uint64_t download = 0;
};

struct VpnConnectionInfoEvent {
    int action = VPN_FCA_TUNNEL;
    const char *domain = nullptr;
};

struct SocketProtectEvent {
    int fd = -1;
    const sockaddr *peer = nullptr;
    int result = 0;
};

struct VpnVerifyCertificateEvent {
    const char *cert = nullptr;
    const char *chain = nullptr;
    int result = 0;
};

// Mirrors what vendor/trusttunnel/02-connect-request-handler.patch adds to the
// real wrapper. Kept in step by hand, like the rest of this mock: a test that
// builds against a shape the real header no longer has proves nothing.
struct VpnConnectRequestSnapshot {
    uint64_t id = 0;
    int proto = 0;
    int family = 0;
    uint16_t src_port = 0;
    std::string src_ip;
    std::string app_name;
};

struct VpnConnectDecision {
    VpnConnectAction action = VPN_CA_DEFAULT;
    std::string app_name;
    int uid = -1;
};

struct VpnCallbacks {
    std::function<void(SocketProtectEvent *)> protect_handler;
    std::function<void(VpnVerifyCertificateEvent *)> verify_handler;
    std::function<void(VpnStateChangedEvent *)> state_changed_handler;
    std::function<void(VpnClientOutputEvent *)> client_output_handler;
    std::function<void(VpnTunnelConnectionStatsEvent *)> tunnel_stats_handler;
    std::function<void(VpnConnectionInfoEvent *)> connection_info_handler;
    std::function<void(const VpnConnectRequestSnapshot &, VpnConnectDecision *)> connect_request_handler;
};

struct Logger {
    // Recorded so tests can assert that the Verbose-logs toggle actually reaches
    // the core: the wrapper reads `loglevel` back out of the config TOML and
    // pushes it here, and that readback silently regressed once already.
    static LogLevel &last_level()
    {
        static LogLevel level = LOG_LEVEL_INFO;
        return level;
    }
    static void set_log_level(LogLevel l) { last_level() = l; }
};

} // namespace ag
