// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include <QCoreApplication>
#include <QSettings>
#include <QTemporaryDir>

#include "core/AppSettings.h"
#include "core/BypassRules.h"

// Round-trip coverage for the settings store, including the global-hotkey
// fields. QSettings is redirected to a temp dir so the test never touches the
// real user scope.
class TestAppSettings : public QObject {
    Q_OBJECT
    QTemporaryDir m_dir;

private slots:
    void initTestCase();
    void defaultsWhenEmpty();
    void roundTrip();
    void profilesPreserveOrder();
    void theInsecureTmpLogPathIsMigratedOnLoad();
    void theDefaultExcludedRoutesCoverThePrivateRanges();
};

void TestAppSettings::initTestCase() {
    // A unique org/app + IniFormat redirected to a temp dir keeps the test
    // fully hermetic and away from the real "FreeTunnel" store on every
    // platform (macOS NativeFormat goes through cfprefsd, which ignores setPath).
    QCoreApplication::setOrganizationName(QStringLiteral("FreeTunnelTest"));
    QCoreApplication::setApplicationName(QStringLiteral("AppSettingsTest"));
    QVERIFY(m_dir.isValid());
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_dir.path());
}

void TestAppSettings::defaultsWhenEmpty() {
    // Fresh, empty scope yields the documented defaults.
    AppSettings s = loadAppSettings();
    QCOMPARE(s.language, QStringLiteral("en"));
    QCOMPARE(s.theme_mode, QStringLiteral("system"));
    QCOMPARE(s.auto_connect_on_start, false);
    QCOMPARE(s.killswitch_enabled, true);
    QCOMPARE(s.domain_bypass_enabled, true);
    QCOMPARE(s.logging_enabled, true);
    QCOMPARE(s.profiles.value(QStringLiteral("Default")), recommendedRussiaDomains());
    QVERIFY(!recommendedRussiaDomains().contains(QStringLiteral("*.ru")));
    QVERIFY(!recommendedRussiaDomains().contains(QStringLiteral(".ru")));
    QCOMPARE(s.hotkeys_enabled, true);
    QCOMPARE(s.hotkey_toggle, QStringLiteral("Ctrl+Shift+T"));
    QCOMPARE(s.hotkey_connect, QStringLiteral("Ctrl+Shift+E"));
    QCOMPARE(s.hotkey_disconnect, QStringLiteral("Ctrl+Shift+D"));
    QVERIFY(s.last_config_path.isEmpty());
}

void TestAppSettings::roundTrip() {
    AppSettings in;
    in.language = QStringLiteral("ru");
    in.theme_mode = QStringLiteral("dark");
    in.auto_connect_on_start = true;
    in.killswitch_enabled = true;
    in.domain_bypass_enabled = true;
    in.domain_bypass_rules = {QStringLiteral("github.com"), QStringLiteral("*.gov.ru")};
    in.excluded_routes = {QStringLiteral("10.0.0.0/8"), QStringLiteral("192.168.1.0/24")};
    in.hotkeys_enabled = false;
    in.hotkey_toggle = QStringLiteral("Ctrl+Alt+T");
    in.hotkey_connect = QStringLiteral("Ctrl+Alt+C");
    in.hotkey_disconnect = QStringLiteral("Ctrl+Alt+D");
    in.last_config_path = QStringLiteral("/tmp/configs/germany.toml");
    saveAppSettings(in);

    AppSettings out = loadAppSettings();
    QCOMPARE(out.language, in.language);
    QCOMPARE(out.theme_mode, in.theme_mode);
    QCOMPARE(out.auto_connect_on_start, true);
    QCOMPARE(out.killswitch_enabled, true);
    QCOMPARE(out.domain_bypass_enabled, true);
    QCOMPARE(out.domain_bypass_rules, in.domain_bypass_rules);
    QCOMPARE(out.excluded_routes, in.excluded_routes);
    QCOMPARE(out.hotkeys_enabled, false);
    QCOMPARE(out.hotkey_toggle, in.hotkey_toggle);
    QCOMPARE(out.hotkey_connect, in.hotkey_connect);
    QCOMPARE(out.hotkey_disconnect, in.hotkey_disconnect);
    QCOMPARE(out.last_config_path, in.last_config_path);
}

void TestAppSettings::profilesPreserveOrder() {
    AppSettings in;
    // Names chosen so alphabetical order would differ from creation order.
    in.profiles = {{"Default", {}}, {"Work", {"intra.corp"}}, {"Alpha", {"a.com"}}};
    in.profile_order = {"Default", "Work", "Alpha"};
    in.active_profile = "Work";
    in.domain_bypass_rules = in.profiles.value("Work");
    saveAppSettings(in);

    AppSettings out = loadAppSettings();
    // Creation order preserved (not sorted to Alpha, Default, Work).
    QCOMPARE(out.profile_order, (QStringList{"Default", "Work", "Alpha"}));
    QCOMPARE(out.active_profile, QStringLiteral("Work"));
    QCOMPARE(out.profiles.value("Work"), (QStringList{"intra.corp"}));
    QCOMPARE(out.domain_bypass_rules, (QStringList{"intra.corp"}));
}

// Before 1.0.5 the log lived at /tmp/freetunnel.log, and the comment beside
// defaultLogPath() says why that had to change: a predictable, world-writable
// path lets another local user pre-create a symlink that the app then appends to
// and chmods 0600. The migration on load is the only thing that moves an upgrading
// user off it, and deleting it broke no test.
void TestAppSettings::theInsecureTmpLogPathIsMigratedOnLoad() {
    {
        QSettings s;
        s.setValue(QStringLiteral("logs/path"), QStringLiteral("/tmp/freetunnel.log"));
        s.sync();
    }
    const AppSettings loaded = loadAppSettings();
    QVERIFY2(loaded.log_path != QStringLiteral("/tmp/freetunnel.log"),
             "a profile written before 1.0.5 must not keep logging to the shared /tmp path");
    QVERIFY2(loaded.log_path.endsWith(QStringLiteral("freetunnel.log")),
             "the migration should move the log, not drop the setting");

    // A path the user chose themselves is theirs, and must survive untouched —
    // the migration is for one specific legacy default, not a general override.
    const QString chosen = m_dir.path() + QStringLiteral("/my-own.log");
    {
        QSettings s;
        s.setValue(QStringLiteral("logs/path"), chosen);
        s.sync();
    }
    QCOMPARE(loadAppSettings().log_path, chosen);
}

// These are the ranges the comment calls "should never be tunnelled". Asserting
// membership rather than the exact list keeps the test about the invariant: a
// range may be added, but losing one silently routes a whole private network
// into the tunnel, and dropping 10/8 from the defaults broke nothing.
void TestAppSettings::theDefaultExcludedRoutesCoverThePrivateRanges() {
    const QStringList routes = defaultExcludedRoutes();
    const QStringList mustHave{
        QStringLiteral("10.0.0.0/8"),      // RFC1918
        QStringLiteral("172.16.0.0/12"),   // RFC1918
        QStringLiteral("192.168.0.0/16"),  // RFC1918
        QStringLiteral("100.64.0.0/10"),   // CGNAT, RFC6598
        QStringLiteral("169.254.0.0/16"),  // link-local
    };
    // Loopback is deliberately NOT in this list and must not be added: 127/8 is
    // routed to the loopback interface by the OS, ahead of any default route a
    // tunnel installs, so it never reaches the tunnel to need excluding. My first
    // draft of this test asserted it was present and failed — the list was right.
    QVERIFY(!routes.contains(QStringLiteral("127.0.0.0/8")));
    for (const QString &range : mustHave) {
        QVERIFY2(routes.contains(range),
                 qPrintable(QStringLiteral("%1 must stay out of the tunnel").arg(range)));
    }
}

QTEST_MAIN(TestAppSettings)
#include "test_appsettings.moc"
