// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QString>
#include <QStringList>
#include <QMap>

struct AppSettings {
    QString log_path = "";
    bool logging_enabled = true;
    bool verbose_logs = false; // run the VPN core at info level (debug); else warn
    QString theme_mode = "system";
    QString language = "en";
    bool auto_connect_on_start = false;
    bool killswitch_enabled = true;

    // Domain bypass rules: domains matching these patterns skip the VPN tunnel.
    // Supports wildcards: *.example.com, exact: example.com. domain_bypass_rules
    // mirrors the active profile's list (this is what the core consumes).
    bool domain_bypass_enabled = true;
    QStringList domain_bypass_rules;
    // "general" = route everything except the rules (bypass); "selective" =
    // route only the rules through the VPN. Maps to the core's vpn_mode.
    QString vpn_mode = "general";

    // Excluded routes: IP/CIDR subnets that bypass the tunnel at the routing
    // level (the core's excluded_routes), independent of the domain rules above.
    QStringList excluded_routes;
    // Per-application split tunnelling. Read the same way as excluded_routes and
    // the domain rules: in general mode these programs leave the tunnel, in
    // "Through VPN" mode they are the only ones that enter it. Each entry is an
    // absolute path or a bare executable name (see core/AppRules.h).
    QStringList app_rules;

    // Split-tunnel profiles: named sets of domain-bypass rules. active_profile is
    // the profile currently being *edited* on the Split page; its rules mirror
    // into domain_bypass_rules above. profile_order preserves creation order.
    QString active_profile = "Default";
    QMap<QString, QStringList> profiles{{"Default", {}}};
    QStringList profile_order{"Default"};
    // Which split profile each config uses (config path -> profile name). A
    // config not listed (or pointing at a deleted profile) uses "Default".
    QMap<QString, QString> config_profiles;

    // Global system hotkeys (portable key sequences, e.g. "Ctrl+Alt+T").
    // Empty string = unbound. hotkeys_enabled is the master switch.
    bool hotkeys_enabled = true;
    QString hotkey_toggle = "Ctrl+Shift+T";
    QString hotkey_connect = "Ctrl+Shift+E";
    QString hotkey_disconnect = "Ctrl+Shift+D";

    // Last used config
    QString last_config_path = "";
};

AppSettings loadAppSettings();
void saveAppSettings(const AppSettings &cfg);

// Private/special-use IPv4 ranges that should bypass the tunnel by default.
QStringList defaultExcludedRoutes();
// Built-in "Recommended for Russia" domain bypass set.
QStringList recommendedRussiaDomains();
