// cppcheck-suppress-file missingIncludeSystem
#include "AppSettings.h"

#include <QSettings>
#include <QStandardPaths>

#include "core/BypassRules.h"

static QString defaultLogPath() {
    // Keep the log in the per-user app data dir (owner-only). A predictable,
    // world-writable path like /tmp/freetunnel.log lets another local user
    // pre-create a symlink that we'd then append to (and chmod 0600).
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/freetunnel.log";
}

// The pre-1.0.5 default on macOS/Linux. Migrated to defaultLogPath() on load.
static QString legacyTmpLogPath() {
    return QStringLiteral("/tmp/freetunnel.log");
}

QStringList defaultExcludedRoutes() {
    // Private / special-use IPv4 ranges that should never be tunnelled
    // (RFC1918 / CGNAT / link-local / etc.).
    return {
        QStringLiteral("10.0.0.0/8"),       QStringLiteral("100.64.0.0/10"),
        QStringLiteral("169.254.0.0/16"),   QStringLiteral("172.16.0.0/12"),
        QStringLiteral("192.0.0.0/24"),     QStringLiteral("192.168.0.0/16"),
        QStringLiteral("255.255.255.255/32")};
}

QStringList recommendedRussiaDomains() {
    // RU services that TrustTunnel's DOMAIN_FILTER accepts (no TLD-only *.ru / .ru).
    return sanitizedBypassRules({
        QStringLiteral("yandex.ru"), QStringLiteral("*.yandex.ru"), QStringLiteral("ya.ru"),
        QStringLiteral("*.ya.ru"), QStringLiteral("yastatic.net"), QStringLiteral("*.yastatic.net"),
        QStringLiteral("yandex.net"), QStringLiteral("*.yandex.net"),
        QStringLiteral("vk.com"), QStringLiteral("*.vk.com"), QStringLiteral("vk.ru"),
        QStringLiteral("*.vk.ru"), QStringLiteral("vkontakte.ru"), QStringLiteral("*.vkontakte.ru"),
        QStringLiteral("mail.ru"), QStringLiteral("*.mail.ru"), QStringLiteral("list.ru"),
        QStringLiteral("*.list.ru"), QStringLiteral("bk.ru"), QStringLiteral("*.bk.ru"),
        QStringLiteral("inbox.ru"), QStringLiteral("*.inbox.ru"),
        QStringLiteral("ok.ru"), QStringLiteral("*.ok.ru"),
        QStringLiteral("rambler.ru"), QStringLiteral("*.rambler.ru"), QStringLiteral("lenta.ru"),
        QStringLiteral("*.lenta.ru"), QStringLiteral("ria.ru"), QStringLiteral("*.ria.ru"),
        QStringLiteral("tass.ru"), QStringLiteral("*.tass.ru"),
        QStringLiteral("gosuslugi.ru"), QStringLiteral("*.gosuslugi.ru"), QStringLiteral("mos.ru"),
        QStringLiteral("*.mos.ru"), QStringLiteral("api.mos.ru"), QStringLiteral("parking.mos.ru"),
        QStringLiteral("avito.ru"), QStringLiteral("*.avito.ru"), QStringLiteral("cian.ru"),
        QStringLiteral("*.cian.ru"),
        QStringLiteral("ozon.ru"), QStringLiteral("*.ozon.ru"), QStringLiteral("wildberries.ru"),
        QStringLiteral("*.wildberries.ru"),
        QStringLiteral("nalog.gov.ru"), QStringLiteral("*.nalog.gov.ru"), QStringLiteral("*.gov.ru"),
        QStringLiteral("pfr.gov.ru"), QStringLiteral("*.pfr.gov.ru"), QStringLiteral("fss.ru"),
        QStringLiteral("*.fss.ru"), QStringLiteral("rosreestr.gov.ru"), QStringLiteral("*.rosreestr.gov.ru"),
        QStringLiteral("gibdd.ru"), QStringLiteral("*.gibdd.ru"), QStringLiteral("мвд.рф"),
        QStringLiteral("*.мвд.рф"),
        QStringLiteral("cbr.ru"), QStringLiteral("*.cbr.ru"), QStringLiteral("minfin.gov.ru"),
        QStringLiteral("*.minfin.gov.ru"),
        QStringLiteral("government.ru"), QStringLiteral("*.government.ru"), QStringLiteral("kremlin.ru"),
        QStringLiteral("*.kremlin.ru"),
        QStringLiteral("rospotrebnadzor.ru"), QStringLiteral("*.rospotrebnadzor.ru"),
        QStringLiteral("tbank.ru"), QStringLiteral("*.tbank.ru"), QStringLiteral("tinkoff.ru"),
        QStringLiteral("*.tinkoff.ru"), QStringLiteral("tinkoff.com"), QStringLiteral("*.tinkoff.com"),
        QStringLiteral("sberbank.ru"), QStringLiteral("*.sberbank.ru"), QStringLiteral("sber.ru"),
        QStringLiteral("*.sber.ru"),
        QStringLiteral("vtb.ru"), QStringLiteral("*.vtb.ru"),
        QStringLiteral("alfabank.ru"), QStringLiteral("*.alfabank.ru"), QStringLiteral("alfabank.com"),
        QStringLiteral("*.alfabank.com"),
        QStringLiteral("raiffeisen.ru"), QStringLiteral("*.raiffeisen.ru"),
        QStringLiteral("gazprombank.ru"), QStringLiteral("*.gazprombank.ru"),
        QStringLiteral("open.ru"), QStringLiteral("*.open.ru"),
        QStringLiteral("psbank.ru"), QStringLiteral("*.psbank.ru"),
        QStringLiteral("rosselkhozbank.ru"), QStringLiteral("*.rosselkhozbank.ru"),
        QStringLiteral("sovcombank.ru"), QStringLiteral("*.sovcombank.ru")});
}

static QStringList domainsForProfileName(const QSettings &s, const QString &n,
                                         const QStringList &names, const QStringList &legacy)
{
    const QString key = QStringLiteral("bypass/profile/") + n;
    if (s.contains(key))
        return s.value(key).toStringList();
    if (n == QStringLiteral("Default")) {
        if (!legacy.isEmpty() && names == QStringList{QStringLiteral("Default")})
            return legacy;
        return recommendedRussiaDomains();
    }
    return {};
}

static void loadProfileMap(const QSettings &s, AppSettings &out)
{
    const QStringList names = s.value("bypass/profile_names", QStringList{"Default"}).toStringList();
    const QStringList legacy = s.value("bypass/rules", QStringList{}).toStringList();
    out.profiles.clear();
    for (const QString &n : names)
        out.profiles.insert(n, sanitizedBypassRules(domainsForProfileName(s, n, names, legacy)));
    if (out.profiles.isEmpty())
        out.profiles.insert(QStringLiteral("Default"), recommendedRussiaDomains());
    if (!legacy.isEmpty() && out.profiles.value(QStringLiteral("Default")).isEmpty()
            && names == QStringList{QStringLiteral("Default")})
        out.profiles[QStringLiteral("Default")] = sanitizedBypassRules(legacy);
}

static QStringList mergedProfileOrder(const QSettings &s, const QStringList &names,
                                      const AppSettings &out)
{
    QStringList order;
    for (const QString &n : s.value("bypass/profile_order", names).toStringList()) {
        if (out.profiles.contains(n) && !order.contains(n))
            order << n;
    }
    for (const QString &n : names) {
        if (!order.contains(n))
            order << n;
    }
    if (!order.contains(QStringLiteral("Default")))
        order.prepend(QStringLiteral("Default"));
    return order;
}

static void loadConfigProfileAssignments(const QSettings &s, AppSettings &out)
{
    const QVariantMap cp = s.value("bypass/config_profiles").toMap();
    for (auto it = cp.constBegin(); it != cp.constEnd(); ++it)
        out.config_profiles.insert(it.key(), it.value().toString());
}

static void loadProfileOrderAndAssignments(const QSettings &s, AppSettings &out)
{
    out.active_profile = s.value("bypass/active_profile", QStringLiteral("Default")).toString();
    if (!out.profiles.contains(out.active_profile))
        out.active_profile = out.profiles.firstKey();
    out.domain_bypass_rules = out.profiles.value(out.active_profile);

    const QStringList names = out.profiles.keys();
    out.profile_order = mergedProfileOrder(s, names, out);
    loadConfigProfileAssignments(s, out);
}

static void loadBypassProfiles(const QSettings &s, AppSettings &out)
{
    loadProfileMap(s, out);
    loadProfileOrderAndAssignments(s, out);
}

AppSettings loadAppSettings() {
    // Uses QCoreApplication's organization/application name (set to "FreeTunnel"
    // in main()), so tests can redirect the store to an isolated domain.
    QSettings s;
    AppSettings out;
    out.log_path = s.value("logs/path", defaultLogPath()).toString();
    out.logging_enabled = s.value("logs/enabled", true).toBool();
    out.verbose_logs = s.value("logs/verbose", false).toBool();
    // Migrate the old insecure /tmp default to the per-user app data dir.
    if (out.log_path == legacyTmpLogPath())
        out.log_path = defaultLogPath();
    out.theme_mode = s.value("ui/theme_mode", "system").toString();
    out.language = s.value("ui/language", "en").toString();
    out.auto_connect_on_start = s.value("vpn/auto_connect_on_start", false).toBool();
    out.killswitch_enabled = s.value("vpn/killswitch_enabled", true).toBool();
    out.domain_bypass_enabled = s.value("bypass/enabled", true).toBool();
    out.vpn_mode = s.value("bypass/mode", QStringLiteral("general")).toString();
    out.excluded_routes = s.value("routing/excluded_routes", defaultExcludedRoutes()).toStringList();
    out.app_rules = s.value("routing/app_rules").toStringList();
    loadBypassProfiles(s, out);
    out.hotkeys_enabled = s.value("hotkeys/enabled", true).toBool();
    out.hotkey_toggle = s.value("hotkeys/toggle", "Ctrl+Shift+T").toString();
    out.hotkey_connect = s.value("hotkeys/connect", "Ctrl+Shift+E").toString();
    out.hotkey_disconnect = s.value("hotkeys/disconnect", "Ctrl+Shift+D").toString();
    out.last_config_path = s.value("vpn/last_config_path", "").toString();
    if (out.log_path.isEmpty()) {
        out.log_path = defaultLogPath();
    }
    return out;
}

void saveAppSettings(const AppSettings &cfg) {
    QSettings s;
    s.setValue("logs/path", cfg.log_path);
    s.setValue("logs/enabled", cfg.logging_enabled);
    s.setValue("logs/verbose", cfg.verbose_logs);
    s.setValue("ui/theme_mode", cfg.theme_mode);
    s.setValue("ui/language", cfg.language);
    s.setValue("vpn/auto_connect_on_start", cfg.auto_connect_on_start);
    s.setValue("vpn/killswitch_enabled", cfg.killswitch_enabled);
    s.setValue("bypass/enabled", cfg.domain_bypass_enabled);
    s.setValue("bypass/mode", cfg.vpn_mode);
    s.setValue("routing/excluded_routes", cfg.excluded_routes);
    s.setValue("routing/app_rules", cfg.app_rules);
    s.setValue("bypass/rules", cfg.domain_bypass_rules); // active mirror (core)
    s.setValue("bypass/active_profile", cfg.active_profile);
    s.setValue("bypass/profile_names", QStringList(cfg.profiles.keys()));
    s.setValue("bypass/profile_order", cfg.profile_order);
    s.remove("bypass/profile"); // drop stale per-profile entries, then rewrite
    for (auto it = cfg.profiles.constBegin(); it != cfg.profiles.constEnd(); ++it)
        s.setValue("bypass/profile/" + it.key(), it.value());
    QVariantMap cp;
    for (auto it = cfg.config_profiles.constBegin(); it != cfg.config_profiles.constEnd(); ++it)
        cp.insert(it.key(), it.value());
    s.setValue("bypass/config_profiles", cp);
    s.setValue("hotkeys/enabled", cfg.hotkeys_enabled);
    s.setValue("hotkeys/toggle", cfg.hotkey_toggle);
    s.setValue("hotkeys/connect", cfg.hotkey_connect);
    s.setValue("hotkeys/disconnect", cfg.hotkey_disconnect);
    s.setValue("vpn/last_config_path", cfg.last_config_path);
}
