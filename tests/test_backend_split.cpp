// cppcheck-suppress-file missingIncludeSystem
// Split-tunnel behaviour: excluded routes, profiles, and which edits are
// supposed to disturb a live tunnel.
//
// Only addDomain() validation was covered before, so route add/remove/restore,
// the whole profile model, and the "don't churn the tunnel for a no-op" rules
// were free to regress silently — including the setVpnMode fix, which is exactly
// the kind of change that looks right and does nothing.
#include <QtTest>

#include <QSignalSpy>
#include <QStandardPaths>
#include <QDir>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QUrl>

#include "app/Backend.h"
#include "core/AppSettings.h"

class TestBackendSplit : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void init();

    void addExcludedRouteAcceptsValidAndRejectsInvalid();
    void addExcludedRouteAcceptsAPastedList();
    void addExcludedRouteIgnoresDuplicates();
    void removeAndClearExcludedRoutes();
    void restoreDefaultsIsANoOpWhenAlreadyDefault();
    void profileCreateSelectAndRemove();
    void removingAProfileFallsConfigsBackToDefault();
    void defaultProfileCannotBeRemoved();
    void vpnModeIsPersistedAndNormalized();
    void selectiveModeWithNoRulesKeepsTheFullTunnel();
    void selectiveModeIsInactiveWhileSplitIsOff();
    void appRulesAreRulesToo();
    void appRulesAreValidatedDedupedAndPersisted();
    void aDroppedShortcutBecomesARuleForTheProgramItNames();
    void turningSplitTunnellingOffDoesNotInvertTheAppRules();

private:
    QTemporaryDir m_home;
};

void TestBackendSplit::initTestCase()
{
    QVERIFY(m_home.isValid());
    qputenv("XDG_CONFIG_HOME", m_home.path().toUtf8());
    qputenv("XDG_DATA_HOME", m_home.path().toUtf8());
    // Test mode + *Test names: never touch the real configs.json / settings.
    QStandardPaths::setTestModeEnabled(true);
    QCoreApplication::setOrganizationName(QStringLiteral("FreeTunnelTest"));
    QCoreApplication::setApplicationName(QStringLiteral("BackendSplitTest"));
    // The Backend persists through a default-constructed QSettings, so the
    // *default* format is what has to be redirected. Clearing
    // QSettings(IniFormat, ...) by hand did nothing: on Unix NativeFormat writes
    // BackendSplitTest.conf while IniFormat addresses BackendSplitTest.ini, so the
    // store the Backend actually reads survived every "clean" init(). Any case that
    // aborted mid-way then poisoned every later run of the suite — and the writes
    // landed in the real ~/.qttest, not in this temp dir.
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_home.path());
}

void TestBackendSplit::init()
{
    // Each case starts from a clean settings store.
    QSettings(QSettings::IniFormat, QSettings::UserScope, QStringLiteral("FreeTunnelTest"),
              QStringLiteral("BackendSplitTest"))
            .clear();
}

void TestBackendSplit::addExcludedRouteAcceptsValidAndRejectsInvalid()
{
    Backend backend;
    backend.clearExcludedRoutes();
    QSignalSpy errors(&backend, &Backend::errorOccurred);

    QVERIFY(backend.addExcludedRoute(QStringLiteral("10.0.0.0/8")));
    QVERIFY(backend.excludedRoutes().contains(QStringLiteral("10.0.0.0/8")));
    QCOMPARE(errors.count(), 0);

    QVERIFY(!backend.addExcludedRoute(QStringLiteral("not-an-address")));
    QCOMPARE(errors.count(), 1);
    QVERIFY(!backend.excludedRoutes().contains(QStringLiteral("not-an-address")));

    // Out-of-range prefix length must be refused too — an over-broad route here
    // would silently push traffic outside the tunnel.
    QVERIFY(!backend.addExcludedRoute(QStringLiteral("10.0.0.0/33")));
    QVERIFY(!backend.excludedRoutes().contains(QStringLiteral("10.0.0.0/33")));

    QVERIFY(backend.addExcludedRoute(QStringLiteral("2001:db8::/32")));
    QVERIFY(backend.excludedRoutes().contains(QStringLiteral("2001:db8::/32")));
}

void TestBackendSplit::addExcludedRouteAcceptsAPastedList()
{
    Backend backend;
    backend.clearExcludedRoutes();

    QVERIFY(backend.addExcludedRoute(QStringLiteral("10.0.0.0/8, 192.168.0.0/16\n172.16.0.0/12")));
    QCOMPARE(backend.excludedRoutes().size(), 3);
    QVERIFY(backend.excludedRoutes().contains(QStringLiteral("192.168.0.0/16")));

    // A list with one bad entry keeps the good ones and still reports the error.
    QSignalSpy errors(&backend, &Backend::errorOccurred);
    QVERIFY(backend.addExcludedRoute(QStringLiteral("8.8.8.8 nonsense")));
    QCOMPARE(errors.count(), 1);
    QVERIFY(backend.excludedRoutes().contains(QStringLiteral("8.8.8.8")));
    QVERIFY(!backend.excludedRoutes().contains(QStringLiteral("nonsense")));
}

void TestBackendSplit::addExcludedRouteIgnoresDuplicates()
{
    Backend backend;
    backend.clearExcludedRoutes();
    QVERIFY(backend.addExcludedRoute(QStringLiteral("10.0.0.0/8")));
    const int before = backend.excludedRoutes().size();

    QVERIFY(!backend.addExcludedRoute(QStringLiteral("10.0.0.0/8")));
    QCOMPARE(backend.excludedRoutes().size(), before);
    // Duplicates within one pasted list collapse as well.
    QVERIFY(backend.addExcludedRoute(QStringLiteral("7.7.7.0/24 7.7.7.0/24")));
    QCOMPARE(backend.excludedRoutes().count(QStringLiteral("7.7.7.0/24")), 1);
}

void TestBackendSplit::removeAndClearExcludedRoutes()
{
    Backend backend;
    backend.clearExcludedRoutes();
    QVERIFY(backend.addExcludedRoute(QStringLiteral("10.0.0.0/8 192.168.0.0/16")));
    QCOMPARE(backend.excludedRoutes().size(), 2);

    backend.removeExcludedRoute(0);
    QCOMPARE(backend.excludedRoutes().size(), 1);

    // Out-of-range indices must be inert, not crash or clear the list.
    backend.removeExcludedRoute(-1);
    backend.removeExcludedRoute(99);
    QCOMPARE(backend.excludedRoutes().size(), 1);

    backend.clearExcludedRoutes();
    QVERIFY(backend.excludedRoutes().isEmpty());
}

void TestBackendSplit::restoreDefaultsIsANoOpWhenAlreadyDefault()
{
    Backend backend;
    backend.restoreDefaultExcludedRoutes();
    const QStringList defaults = backend.excludedRoutes();
    QVERIFY(!defaults.isEmpty());

    // Restoring again must not emit splitChanged: that signal drives a live
    // re-apply, and reconnecting the tunnel for a no-op is the bug this guards.
    QSignalSpy changed(&backend, &Backend::splitChanged);
    backend.restoreDefaultExcludedRoutes();
    QCOMPARE(changed.count(), 0);
    QCOMPARE(backend.excludedRoutes(), defaults);

    // But a real deviation is restored, and does signal.
    backend.clearExcludedRoutes();
    changed.clear();
    backend.restoreDefaultExcludedRoutes();
    QCOMPARE(backend.excludedRoutes(), defaults);
    QVERIFY(changed.count() > 0);
}

void TestBackendSplit::profileCreateSelectAndRemove()
{
    Backend backend;
    const int baseCount = backend.profiles().size();
    QVERIFY(backend.profiles().contains(QStringLiteral("Default")));

    backend.addProfile(QStringLiteral("Work"));
    QCOMPARE(backend.profiles().size(), baseCount + 1);
    QCOMPARE(backend.activeProfile(), QStringLiteral("Work")); // edit what you just made
    QVERIFY(backend.domains().isEmpty());

    QVERIFY(backend.addDomain(QStringLiteral("example.com")));
    QVERIFY(backend.domains().contains(QStringLiteral("example.com")));

    // Switching profiles swaps the edited rule set, and switching back restores it.
    backend.selectProfile(QStringLiteral("Default"));
    QCOMPARE(backend.activeProfile(), QStringLiteral("Default"));
    QVERIFY(!backend.domains().contains(QStringLiteral("example.com")));
    backend.selectProfile(QStringLiteral("Work"));
    QVERIFY(backend.domains().contains(QStringLiteral("example.com")));

    // Duplicate and empty names are refused.
    backend.addProfile(QStringLiteral("Work"));
    backend.addProfile(QStringLiteral("   "));
    QCOMPARE(backend.profiles().size(), baseCount + 1);

    backend.removeProfile(QStringLiteral("Work"));
    QCOMPARE(backend.profiles().size(), baseCount);
    QCOMPARE(backend.activeProfile(), QStringLiteral("Default"));
}

void TestBackendSplit::removingAProfileFallsConfigsBackToDefault()
{
    Backend backend;
    backend.addProfile(QStringLiteral("Temp"));
    QVERIFY(backend.profiles().contains(QStringLiteral("Temp")));

    QSignalSpy configChanged(&backend, &Backend::configChanged);
    backend.removeProfile(QStringLiteral("Temp"));

    QVERIFY(!backend.profiles().contains(QStringLiteral("Temp")));
    // Configs that pointed at it must be re-pointed, and the UI told, because a
    // config's effective profile just changed.
    QVERIFY(configChanged.count() > 0);
}

void TestBackendSplit::defaultProfileCannotBeRemoved()
{
    Backend backend;
    backend.removeProfile(QStringLiteral("Default"));
    QVERIFY(backend.profiles().contains(QStringLiteral("Default")));
}

void TestBackendSplit::vpnModeIsPersistedAndNormalized()
{
    {
        Backend backend;
        backend.setVpnMode(QStringLiteral("selective"));
        QCOMPARE(backend.vpnMode(), QStringLiteral("selective"));

        // Anything that isn't a known mode must not be persisted verbatim: the
        // value is read back at startup, so garbage would outlive the session.
        backend.setVpnMode(QStringLiteral("nonsense"));
        QCOMPARE(backend.vpnMode(), QStringLiteral("general"));

        backend.setVpnMode(QStringLiteral("general"));
        QCOMPARE(backend.vpnMode(), QStringLiteral("general"));
        backend.setVpnMode(QStringLiteral("selective"));
    }
    // A new Backend reads the persisted value back.
    Backend reopened;
    QCOMPARE(reopened.vpnMode(), QStringLiteral("selective"));
}

void TestBackendSplit::selectiveModeWithNoRulesKeepsTheFullTunnel()
{
    Backend backend;
    backend.setSplitEnabled(true);
    backend.setVpnMode(QStringLiteral("selective"));
    backend.clearDomains();

    // "selective" routes only the listed rules through the tunnel, so an empty list
    // would route nothing and every byte would leave in the clear while the UI still
    // said Connected. The mode stays *chosen* — the user's setting is not silently
    // rewritten — but it must not be what the core is told.
    QCOMPARE(backend.vpnMode(), QStringLiteral("selective"));
    QVERIFY(!backend.selectiveModeActive());
    QVERIFY(backend.selectiveModeWouldLeak());

    // One real rule is enough to make the chosen mode safe, and it must then
    // actually take effect.
    QVERIFY(backend.addDomain(QStringLiteral("example.com")));
    QVERIFY(backend.selectiveModeActive());
    QVERIFY(!backend.selectiveModeWouldLeak());

    // Emptying the list again has to fall back, not leak: this is the "Clear all"
    // path on an already-connected client.
    backend.clearDomains();
    QVERIFY(!backend.selectiveModeActive());
    QVERIFY(backend.selectiveModeWouldLeak());

    // Bypass mode with no rules is a perfectly ordinary full tunnel, not a leak.
    backend.setVpnMode(QStringLiteral("general"));
    QVERIFY(!backend.selectiveModeWouldLeak());
}

// "Through VPN" with applications and no domains is a complete configuration:
// the listed programs go through the tunnel and nothing else does. Before app
// rules existed, an empty domain list meant "nothing would be routed", so the
// tunnel fell back to carrying everything — doing that here would silently
// route the traffic the user had just arranged to keep out.
void TestBackendSplit::appRulesAreRulesToo()
{
    Backend backend;
    backend.setSplitEnabled(true);
    backend.setVpnMode(QStringLiteral("selective"));
    backend.clearDomains();
    QVERIFY(backend.selectiveModeWouldLeak());

    QVERIFY(backend.addAppRule(QStringLiteral("firefox")));
    QVERIFY(backend.selectiveModeActive());
    QVERIFY2(!backend.selectiveModeWouldLeak(),
             "an app rule is a rule: the mode the user chose is now safe to apply");

    // And removing the last one has to fall back again, exactly as clearing the
    // domains does.
    backend.clearAppRules();
    QVERIFY(!backend.selectiveModeActive());
    QVERIFY(backend.selectiveModeWouldLeak());
}

void TestBackendSplit::appRulesAreValidatedDedupedAndPersisted()
{
    {
        Backend backend;
        QVERIFY(backend.appRules().isEmpty());

        // Rejected, and not stored: the user is told rather than shown a rule
        // that could never match anything.
        QVERIFY(!backend.addAppRule(QString()));
        QVERIFY(!backend.addAppRule(QStringLiteral("   ")));
        QVERIFY(!backend.addAppRule(QStringLiteral("relative/path")));
        QVERIFY(backend.appRules().isEmpty());

        QVERIFY(backend.addAppRule(QStringLiteral("  firefox  ")));
        QCOMPARE(backend.appRules(), QStringList{QStringLiteral("firefox")});
        // Re-adding the same program is not an error and not a second entry.
        QVERIFY(!backend.addAppRule(QStringLiteral("firefox")));
        QCOMPARE(backend.appRules().size(), 1);

        // Unlike an address, a rule is never split on whitespace — program paths
        // contain spaces, and splitting one would turn a single valid rule into
        // several invalid ones.
#ifdef Q_OS_WIN
        const QString spaced = QStringLiteral("C:\\Program Files\\Some App\\app.exe");
#else
        const QString spaced = QStringLiteral("/opt/Some App/app");
#endif
        QVERIFY(backend.addAppRule(spaced));
        QCOMPARE(backend.appRules().size(), 2);
        QVERIFY(backend.appRules().last().contains(QLatin1String("Some App")));

        backend.removeAppRule(0);
        QCOMPARE(backend.appRules().size(), 1);
        // Out-of-range removals must not throw the list away.
        backend.removeAppRule(-1);
        backend.removeAppRule(99);
        QCOMPARE(backend.appRules().size(), 1);
    }

    Backend reopened;
    QCOMPARE(reopened.appRules().size(), 1);
    QVERIFY(reopened.appRules().first().contains(QLatin1String("Some App")));
}

// Dropping an icon is the gesture people actually have. What lands on the window
// is a shortcut, not a program, and a rule made from the shortcut's own path
// would be stored, listed back, and never match anything.
void TestBackendSplit::aDroppedShortcutBecomesARuleForTheProgramItNames()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString program = dir.filePath(QStringLiteral("theprogram"));
    QFile bin(program);
    QVERIFY(bin.open(QIODevice::WriteOnly));
    bin.close();

    const QString entry = dir.filePath(QStringLiteral("shortcut.desktop"));
    QFile f(entry);
    QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Text));
    f.write(QStringLiteral("[Desktop Entry]\nType=Application\nExec=\"%1\" %u\n")
                    .arg(program).toUtf8());
    f.close();

    Backend backend;
    QSignalSpy errors(&backend, &Backend::errorOccurred);

    // The URL form, because that is what a drop hands over.
    QVERIFY(backend.addApplicationFromPath(QUrl::fromLocalFile(entry).toString()));
    QCOMPARE(backend.appRules().size(), 1);
    // Canonical, because that is how rules are stored — and on macOS a temporary
    // directory is reached through /var, which is a symlink to /private/var.
    const QString canonical = QFileInfo(program).canonicalFilePath();
    QCOMPARE(backend.appRules().first(),
             QDir::toNativeSeparators(canonical.isEmpty() ? program : canonical));
    QCOMPARE(errors.count(), 0);

    // A folder or a document landing on the window by accident is told apart from
    // a program, and says so rather than storing something unmatchable.
    QVERIFY(!backend.addApplicationFromPath(QUrl::fromLocalFile(dir.path()).toString()));
    QCOMPARE(backend.appRules().size(), 1);
    QCOMPARE(errors.count(), 1);
}

void TestBackendSplit::selectiveModeIsInactiveWhileSplitIsOff()
{
    Backend backend;
    backend.setVpnMode(QStringLiteral("selective"));
    backend.setSplitEnabled(false);
    QVERIFY(backend.addDomain(QStringLiteral("example.com")));
    // The master toggle wins: with split tunneling off the core gets no rules at
    // all, so selective mode must not be requested either.
    QVERIFY(!backend.selectiveModeActive());
    QVERIFY(!backend.selectiveModeWouldLeak());
}

// The nastiest shape this feature can take. In "Through VPN" the list means
// "only these go through"; in bypass mode the same list means "these stay out".
// Switching the whole feature off puts the core in general mode — so a list that
// was still being pushed reversed its meaning, and a user who turned split
// tunnelling off expecting everything to be protected got the one program they
// cared about sent out in the clear, with the interface saying it was off.
void TestBackendSplit::turningSplitTunnellingOffDoesNotInvertTheAppRules()
{
    Backend backend;
    backend.setSplitEnabled(true);
    backend.setVpnMode(QStringLiteral("selective"));
    QVERIFY(backend.addAppRule(QStringLiteral("firefox")));
    QVERIFY(backend.selectiveModeActive());

    backend.setSplitEnabled(false);
    // The rule stays in the settings — the user did not delete it, and it comes
    // back when they switch the feature on again.
    QCOMPARE(backend.appRules().size(), 1);
    // But it must no longer be in force, in either direction.
    QVERIFY(!backend.selectiveModeActive());
    QVERIFY(!backend.selectiveModeWouldLeak());

    backend.setSplitEnabled(true);
    QVERIFY(backend.selectiveModeActive());
}

QTEST_MAIN(TestBackendSplit)
#include "test_backend_split.moc"
