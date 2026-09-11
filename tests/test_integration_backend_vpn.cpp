// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include <QJsonObject>

#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QSettings>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QTemporaryDir>

#include "app/Backend.h"
#include "core/AppSettings.h"
#include "core/ConfigStore.h"
#include "core/ConfigToml.h"
#include "core/CredentialStore.h"
#include "core/DeepLink.h"
#include "helper_ipc_mock_server.h"

class TestIntegrationBackendVpn : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void init();
    void backendConnectsThroughMockHelper();
    void connectPushesTheSecuritySettingsToTheHelper();
    void connectWithNoRulesAsksForTheFullTunnelNotSelective();
    void configSwitchSuppressesCoreDisconnectToast();
    void deletingActiveConfigWhileConnectedTearsDownTunnel();
    void exportRoundTrips();
    void domainRulesAcceptTldWildcardsAndIdn();
};

static AppSettings hermeticSettings(const QString &logPath)
{
    AppSettings settings;
    settings.hotkeys_enabled = false;
    settings.auto_connect_on_start = false;
    settings.killswitch_enabled = false;
    settings.domain_bypass_enabled = false;
    settings.domain_bypass_rules.clear();
    settings.profiles.clear();
    settings.profiles.insert(QStringLiteral("Default"), {});
    settings.profile_order = {QStringLiteral("Default")};
    settings.active_profile = QStringLiteral("Default");
    settings.log_path = logPath;
    settings.excluded_routes = defaultExcludedRoutes();
    return settings;
}

void TestIntegrationBackendVpn::initTestCase()
{
    QSettings().clear();
    saveAppSettings(hermeticSettings(
        QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        + QStringLiteral("/backend-vpn-test.log")));
}

void TestIntegrationBackendVpn::init()
{
    freetunnel::sweepStaleMaterializedConfigs();
    saveStoredConfigs({});
}

void TestIntegrationBackendVpn::backendConnectsThroughMockHelper()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(base);

    QTemporaryFile configFile(QDir(base).filePath(QStringLiteral("backend-vpn-XXXXXX.toml")));
    configFile.setAutoRemove(true);
    QVERIFY(configFile.open());

    freetunnel::ConfigToml cfg;
    cfg.hostname = QStringLiteral("backend.example.com");
    cfg.addresses = QStringLiteral("203.0.113.50:443");
    cfg.username = QStringLiteral("user");
    configFile.write(freetunnel::buildConfigToml(cfg).toUtf8());
    configFile.close();
    const QString configPath = configFile.fileName();

    QVERIFY(freetunnel::CredentialStore::storePassword(configPath, QStringLiteral("secret")));

    saveStoredConfigs({configPath});
    AppSettings settings = loadAppSettings();
    settings.last_config_path = configPath;
    saveAppSettings(settings);

    const QString token = QStringLiteral("backend-integration-token");
    MockHelperServer server(token);
    QVERIFY(server.listen());

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(server.port()));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    Backend backend;
    QSignalSpy stateSpy(&backend, &Backend::stateChanged);

    backend.connectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return backend.connected(); }, 10000));
    QVERIFY(stateSpy.count() > 0);

    // Regression: connect must not write password-bearing .connect-*.toml in the GUI
    // process — config is sent in-memory to the helper over loopback IPC.
    auto connectTemps = [&]() {
        return QDir(base).entryList({QStringLiteral(".connect-*.toml")},
                                    QDir::Files | QDir::Hidden).size();
    };
    QVERIFY(connectTemps() == 0);

    backend.disconnectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return !backend.connected() && !backend.connecting(); }, 5000));
    QVERIFY(connectTemps() == 0);

    backend.prepareQuit();
    QVERIFY(connectTemps() == 0);
    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");

    // The keychain service name is hardcoded and not affected by test mode, so
    // drop the entry we created to avoid leaving it in the real OS credential store.
    freetunnel::CredentialStore::deletePassword(configPath);
}

static bool writeTestConfig(const QString &base, const QString &hostname, QString *outPath);

// The first link of the kill-switch chain: Backend must push the PERSISTED
// settings to the helper on every connect. Deleting that push leaves the tunnel
// coming up perfectly — connected, no error, session timer running — with the
// kill switch simply never armed and split tunnelling never applied, which no
// other test notices because they all assert on connectivity.
void TestIntegrationBackendVpn::connectPushesTheSecuritySettingsToTheHelper()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(base);
    QString configPath;
    QVERIFY(writeTestConfig(base, QStringLiteral("kill.example"), &configPath));
    QVERIFY(freetunnel::CredentialStore::storePassword(configPath, QStringLiteral("secret")));

    saveStoredConfigs({configPath});
    AppSettings settings = loadAppSettings();
    settings.last_config_path = configPath;
    settings.killswitch_enabled = true;
    settings.domain_bypass_enabled = true;
    settings.vpn_mode = QStringLiteral("selective");
    settings.profiles[QStringLiteral("Default")] = {QStringLiteral("example.com")};
    settings.domain_bypass_rules = settings.profiles.value(QStringLiteral("Default"));
    saveAppSettings(settings);

    const QString token = QStringLiteral("backend-settings-token");
    MockHelperServer server(token);
    QVERIFY(server.listen());
    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(server.port()));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    Backend backend;
    backend.connectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return backend.connected(); }, 10000));

    // The VALUE, not merely the command name: a key read under the wrong spelling
    // decodes to false through QJsonValue::toBool() with nothing failing anywhere.
    const QJsonObject killSwitch = server.lastMessageFor(QStringLiteral("setKillSwitch"));
    QVERIFY2(!killSwitch.isEmpty(), "connect never sent setKillSwitch to the helper");
    QVERIFY2(killSwitch.contains(QStringLiteral("enabled")),
             "setKillSwitch carried no 'enabled' key — a renamed key decodes to false silently");
    QCOMPARE(killSwitch.value(QStringLiteral("enabled")).toBool(), true);

    // Selective mode is only requested when the rule list is non-empty; this
    // profile has one, so it must arrive as on.
    const QJsonObject mode = server.lastMessageFor(QStringLiteral("setMode"));
    QVERIFY2(!mode.isEmpty(), "connect never sent setMode to the helper");
    QCOMPARE(mode.value(QStringLiteral("selective")).toBool(), true);

    backend.disconnectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return !backend.connected() && !backend.connecting(); }, 5000));
    backend.prepareQuit();
    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
    freetunnel::CredentialStore::deletePassword(configPath);
}

static bool writeTestConfig(const QString &base, const QString &hostname, QString *outPath)
{
    QTemporaryFile configFile(QDir(base).filePath(hostname + QStringLiteral("-XXXXXX.toml")));
    configFile.setAutoRemove(false);
    if (!configFile.open())
        return false;

    freetunnel::ConfigToml cfg;
    cfg.hostname = hostname;
    cfg.addresses = QStringLiteral("203.0.113.50:443");
    cfg.username = QStringLiteral("user");
    configFile.write(freetunnel::buildConfigToml(cfg).toUtf8());
    configFile.close();
    if (!freetunnel::CredentialStore::storePassword(configFile.fileName(), QStringLiteral("secret")))
        return false;
    *outPath = configFile.fileName();
    return true;
}

// The sibling above proves selective mode is requested when a rule exists. This
// is the other half, and it is the half that leaks: "selective" routes ONLY the
// listed rules through the tunnel, so an empty list routes nothing and every
// byte leaves in the clear while the UI still says Connected.
//
// backend_split already checks selectiveModeActive() and selectiveModeWouldLeak(),
// but those are what the Backend *thinks*. Nothing checked what the core is
// actually told, and the wiring between the two is where this can break: a
// mutation that left both predicates correct and passed domain_bypass_enabled
// straight to setVpnMode() went unnoticed by the whole suite.
void TestIntegrationBackendVpn::connectWithNoRulesAsksForTheFullTunnelNotSelective()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(base);
    QString configPath;
    QVERIFY(writeTestConfig(base, QStringLiteral("norules.example"), &configPath));
    QVERIFY(freetunnel::CredentialStore::storePassword(configPath, QStringLiteral("secret")));

    saveStoredConfigs({configPath});
    AppSettings settings = loadAppSettings();
    settings.last_config_path = configPath;
    settings.domain_bypass_enabled = true;
    settings.vpn_mode = QStringLiteral("selective");
    // The reachable misconfiguration: a fresh install, "Clear all", or a newly
    // added profile all leave the active rule list empty.
    settings.profiles[QStringLiteral("Default")] = {};
    settings.domain_bypass_rules = {};
    saveAppSettings(settings);

    const QString token = QStringLiteral("backend-norules-token");
    MockHelperServer server(token);
    QVERIFY(server.listen());
    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(server.port()));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    Backend backend;
    backend.connectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return backend.connected(); }, 10000));

    const QJsonObject mode = server.lastMessageFor(QStringLiteral("setMode"));
    QVERIFY2(!mode.isEmpty(), "connect never sent setMode to the helper");
    QVERIFY2(!mode.value(QStringLiteral("selective")).toBool(),
             "selective mode with an empty rule list must NOT reach the core - it would "
             "route nothing through the tunnel while the UI says Connected");

    // The user's chosen setting is not silently rewritten; only what the core is
    // told differs.
    QCOMPARE(backend.vpnMode(), QStringLiteral("selective"));

    backend.disconnectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return !backend.connected() && !backend.connecting(); }, 5000));
    backend.prepareQuit();
    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
}

void TestIntegrationBackendVpn::configSwitchSuppressesCoreDisconnectToast()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(base);

    QString configA, configB;
    QVERIFY(writeTestConfig(base, QStringLiteral("server-a"), &configA));
    QVERIFY(writeTestConfig(base, QStringLiteral("server-b"), &configB));
    saveStoredConfigs({configA, configB});
    AppSettings settings = loadAppSettings();
    settings.last_config_path = configA;
    saveAppSettings(settings);

    const QString token = QStringLiteral("backend-switch-token");
    MockHelperServer server(token);
    QVERIFY(server.listen());

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(server.port()));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    Backend backend;
    QSignalSpy errorSpy(&backend, &Backend::errorOccurred);

    backend.connectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return backend.connected(); }, 10000));
    QCOMPARE(backend.activeIndex(), 0);

    backend.selectConfig(1);
    QVERIFY(QTest::qWaitFor([&]() { return backend.connected(); }, 10000));
    QCOMPARE(backend.activeIndex(), 1);

    // A QSignalSpy row is the argument LIST, not the argument. Binding it to a
    // const QVariant& built a temporary QVariant wrapping the whole list, so this
    // loop used to compare against something like "QVariantList(...)" and could
    // never see the message it names — the check passed no matter what was emitted.
    for (const QList<QVariant> &row : errorSpy) {
        QVERIFY(!row.isEmpty());
        const QString text = row.at(0).toString();
        const QString msg = text.toLower();
        QVERIFY2(!msg.contains(QStringLiteral("connection lost")),
                 qPrintable(QStringLiteral("unexpected toast: ") + text));
    }

    backend.prepareQuit();
    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
    freetunnel::CredentialStore::deletePassword(configA);
    freetunnel::CredentialStore::deletePassword(configB);
    QFile::remove(configA);
    QFile::remove(configB);
}

void TestIntegrationBackendVpn::deletingActiveConfigWhileConnectedTearsDownTunnel()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(base);

    QString configA, configB;
    QVERIFY(writeTestConfig(base, QStringLiteral("del-server-a"), &configA));
    QVERIFY(writeTestConfig(base, QStringLiteral("del-server-b"), &configB));
    saveStoredConfigs({configA, configB});
    AppSettings settings = loadAppSettings();
    settings.last_config_path = configA;
    saveAppSettings(settings);

    const QString token = QStringLiteral("backend-delete-token");
    MockHelperServer server(token);
    QVERIFY(server.listen());
    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(server.port()));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    Backend backend;
    backend.connectVpn();
    QVERIFY(QTest::qWaitFor([&]() { return backend.connected(); }, 10000));
    QCOMPARE(backend.activeIndex(), 0);

    // Deleting a NON-active config while connected must leave the tunnel up.
    backend.removeConfig(1);
    QTest::qWait(200);
    QVERIFY(backend.connected());
    QCOMPARE(backend.activeIndex(), 0); // configA still the active, still connected

    // Deleting the ACTIVE config must tear the tunnel down — not silently
    // relabel the "connected" state onto whatever config remains.
    backend.removeConfig(0);
    QVERIFY(QTest::qWaitFor([&]() { return !backend.connected() && !backend.connecting(); }, 5000));
    QVERIFY(!backend.connected());

    backend.prepareQuit();
    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
    freetunnel::CredentialStore::deletePassword(configA);
    freetunnel::CredentialStore::deletePassword(configB);
    QFile::remove(configA);
    QFile::remove(configB);
}

void TestIntegrationBackendVpn::exportRoundTrips()
{
    Backend backend;
    QVariantMap f;
    f[QStringLiteral("name")] = QStringLiteral("Export Test");
    f[QStringLiteral("hostname")] = QStringLiteral("vpn.export.test");
    f[QStringLiteral("addresses")] = QStringLiteral("203.0.113.7:443");
    f[QStringLiteral("username")] = QStringLiteral("exp-user");
    f[QStringLiteral("password")] = QStringLiteral("exp-pass");
    f[QStringLiteral("protocol")] = QStringLiteral("http2");
    QVERIFY(backend.createConfig(f));
    QCOMPARE(backend.configs().size(), 1);

    // Deep link round-trips through the parser with credentials intact.
    const QString link = backend.configDeepLink(0);
    QVERIFY(link.startsWith(QLatin1String("tt://")));
    QString err;
    const auto dl = freetunnel::parseDeepLink(link, &err);
    QVERIFY2(dl.has_value(), qPrintable(err));
    QCOMPARE(dl->hostname, QStringLiteral("vpn.export.test"));
    QVERIFY(dl->addresses.contains(QStringLiteral("203.0.113.7:443")));
    QCOMPARE(dl->username, QStringLiteral("exp-user"));
    QCOMPARE(dl->password, QStringLiteral("exp-pass"));

    // TOML export writes a usable file (password injected from the keychain).
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString out = dir.filePath(QStringLiteral("exported.toml"));
    QVERIFY(backend.exportConfigToml(0, out));
    QFile g(out);
    QVERIFY(g.open(QIODevice::ReadOnly | QIODevice::Text));
    const freetunnel::ConfigToml c = freetunnel::parseConfigToml(QString::fromUtf8(g.readAll()));
    QCOMPARE(c.hostname, QStringLiteral("vpn.export.test"));
    QCOMPARE(c.username, QStringLiteral("exp-user"));
    QCOMPARE(c.password, QStringLiteral("exp-pass"));

    // Clean up the keychain entry + file the config created.
    backend.prepareQuit();
    for (const QString &path : loadStoredConfigs()) {
        freetunnel::CredentialStore::deletePassword(
                freetunnel::CredentialStore::keyForConfigPath(path));
        QFile::remove(path);
    }
}

void TestIntegrationBackendVpn::domainRulesAcceptTldWildcardsAndIdn()
{
    Backend backend;
    // TLD-only wildcards are rejected — TrustTunnel's DOMAIN_FILTER cannot use them.
    QVERIFY(!backend.addDomain(QStringLiteral("*.ru")));
    QVERIFY(!backend.addDomain(QStringLiteral(".su")));
    QVERIFY(!backend.addDomain(QStringLiteral("*.рф")));   // *.рф
    QVERIFY(backend.addDomain(QStringLiteral("мвд.рф"))); // мвд.рф
    QVERIFY(backend.addDomain(QStringLiteral("yandex.ru")));
    QVERIFY(backend.addDomain(QStringLiteral("192.168.0.0/16")));
    // A bare TLD without a wildcard, and malformed labels, stay rejected.
    QVERIFY(!backend.addDomain(QStringLiteral("ru")));
    QVERIFY(!backend.addDomain(QStringLiteral("foo_bar.com")));
    QVERIFY(!backend.addDomain(QStringLiteral("-bad.com")));
}

int main(int argc, char *argv[])
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QStandardPaths::setTestModeEnabled(true);
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QTemporaryDir iniDir;
    if (!iniDir.isValid())
        return 1;
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, iniDir.path());

    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("BackendVpnTest"));
    app.setOrganizationName(QStringLiteral("FreeTunnelTest"));
    TestIntegrationBackendVpn tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_integration_backend_vpn.moc"
