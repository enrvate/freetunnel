// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "vpn/trusttunnel/client.h"
#include "vpn/vpn.h"

#include <QString>

ag::LogLevel qt_trusttunnel_parse_log_level(const QString &level);
QString qt_trusttunnel_default_core_log_path();
QString qt_trusttunnel_format_vpn_error(int code, const QString &text);
void qt_trusttunnel_protect_outbound_socket(ag::SocketProtectEvent *event);
void qt_trusttunnel_verify_server_certificate(ag::VpnVerifyCertificateEvent *event);
// "203.0.113.7:443" / "[2001:db8::1]:443", empty for anything else.
QString qt_trusttunnel_format_address(const struct sockaddr *sa);
QString qt_trusttunnel_connection_info_line(ag::VpnConnectionInfoEvent *event);

#ifdef _WIN32
bool qt_trusttunnel_is_process_elevated();
#endif
