// cppcheck-suppress-file missingIncludeSystem
// The config surface the main window is built on: create, edit, rename, export,
// share as a link, reorder, remove.
//
// This is where the user's VPN password lives, and until now the only coverage
// was the deep-link import path. Everything asserted here is something a bug on
// this branch actually did, or could do unnoticed: write the password into the
// .toml instead of the credential store, leave it world-readable, drop the
// credential when a config is renamed, or destroy an existing config because a
// save failed halfway.
#include <QtTest>

#include <QScopeGuard>

#include <QThread>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryDir>

#include "app/Backend.h"
#include "app/BackendConfigShared.h"
#include "core/ConfigToml.h"
#include "core/CredentialStore.h"
#include "core/DeepLink.h"

class TestBackendConfig : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void init();
    void cleanup();

    void createStoresThePasswordOutsideTheConfigFile();
    void createdConfigIsOwnerOnly();
    void editInPlaceKeepsThePathAndUpdatesTheFields();
    void renamingCarriesThePasswordToTheNewPath();
    void aFailedSaveLeavesTheExistingConfigIntact();
    void exportCarriesThePasswordAndStaysOwnerOnly();
    void deepLinkRoundTripsBackIntoTheSameConfig();
    void moveConfigReordersTheList();
    void removeConfigForgetsThePassword();
    void readAccessorsRejectOutOfRangeIndexes();
    void pingsAreResetForEveryConfig();
    void theConnectConfigIsBuiltOffTheGuiThread();

private:
    // A complete, valid create form; individual cases override what they exercise.
    static QVariantMap form(const QString &name, const QString &password);
    QString pathFor(const Backend &backend, int index) const;
    static void assertOwnerOnly(const QString &path);

    QTemporaryDir m_home;
};

void TestBackendConfig::initTestCase()
{
    QVERIFY(m_home.isValid());
    qputenv("XDG_CONFIG_HOME", m_home.path().toUtf8());
    qputenv("XDG_DATA_HOME", m_home.path().toUtf8());
    // Test mode + *Test names + a credential service unique to this process:
    // nothing here can reach the user's real configs.json or their keychain.
    QStandardPaths::setTestModeEnabled(true);
    QCoreApplication::setOrganizationName(QStringLiteral("FreeTunnelTest"));
    QCoreApplication::setApplicationName(QStringLiteral("BackendConfigTest"));
    // See the same note in test_backend_split: the Backend writes through a
    // default-constructed QSettings, which on Unix is NativeFormat (*.conf), so
    // clearing the IniFormat store (*.ini) in init() never touched it. Redirect the
    // default format into this run's temp dir so the store is genuinely per-run.
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_home.path());
}

void TestBackendConfig::init()
{
    QSettings(QSettings::IniFormat, QSettings::UserScope, QStringLiteral("FreeTunnelTest"),
              QStringLiteral("BackendConfigTest"))
            .clear();
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(dir);
    for (const QFileInfo &fi : QDir(dir).entryInfoList({QStringLiteral("*.toml")}, QDir::Files))
        QFile::remove(fi.absoluteFilePath());
    QFile::remove(QDir(dir).filePath(QStringLiteral("configs.json")));
}

void TestBackendConfig::cleanup()
{
    // Leave no credential entries behind, not even in the per-process service.
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    for (const QFileInfo &fi : QDir(dir).entryInfoList({QStringLiteral("*.toml")}, QDir::Files)) {
        freetunnel::CredentialStore::deletePassword(
                freetunnel::CredentialStore::keyForConfigPath(fi.absoluteFilePath()));
    }
}

QVariantMap TestBackendConfig::form(const QString &name, const QString &password)
{
    QVariantMap f;
    f[QStringLiteral("name")] = name;
    f[QStringLiteral("hostname")] = QStringLiteral("vpn.example.org");
    f[QStringLiteral("addresses")] = QStringLiteral("198.51.100.7:443");
    f[QStringLiteral("username")] = QStringLiteral("alice");
    f[QStringLiteral("password")] = password;
    f[QStringLiteral("protocol")] = QStringLiteral("http2");
    f[QStringLiteral("dns")] = QStringLiteral("1.1.1.1");
    return f;
}

// Owner-only is a POSIX-mode claim. On Windows the code relies on the config
// directory's ACL instead of mode bits, and Qt does not consult NTFS ACLs unless
// permission checking is explicitly enabled — it reports every file as readable
// by everyone — so the check would test Qt's default, not our code.
void TestBackendConfig::assertOwnerOnly(const QString &path)
{
#if defined(Q_OS_UNIX)
    const QFile::Permissions perms = QFile::permissions(path);
    QVERIFY2(!(perms & (QFileDevice::ReadGroup | QFileDevice::ReadOther)),
             qPrintable(QStringLiteral("%1 is readable by other local users").arg(path)));
#else
    QVERIFY(QFileInfo::exists(path));
#endif
}

QString TestBackendConfig::pathFor(const Backend &backend, int index) const
{
    // The list exposes display names; the file is the one that carries the name.
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    const QString name = backend.configs().value(index);
    for (const QFileInfo &fi : QDir(dir).entryInfoList({QStringLiteral("*.toml")}, QDir::Files)) {
        if (fi.completeBaseName() == name)
            return fi.absoluteFilePath();
    }
    return QString();
}

// The whole point of the credential store: the config file that ends up on disk
// must not contain the password, and the password must be retrievable.
void TestBackendConfig::createStoresThePasswordOutsideTheConfigFile()
{
    Backend backend;
    QSignalSpy configs(&backend, &Backend::configsChanged);
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));
    QVERIFY(configs.count() > 0);
    QCOMPARE(backend.configs(), QStringList{QStringLiteral("Alpha")});

    const QString path = pathFor(backend, 0);
    QVERIFY2(!path.isEmpty(), "the created config is not on disk");
    QFile f(path);
    QVERIFY(f.open(QIODevice::ReadOnly));
    const QString onDisk = QString::fromUtf8(f.readAll());
    QVERIFY2(!onDisk.contains(QStringLiteral("hunter2")),
             "the password was written into the config file in cleartext");

    // ...and it round-trips back into the edit form.
    QCOMPARE(backend.configFields(0).value(QStringLiteral("password")).toString(),
             QStringLiteral("hunter2"));
    QCOMPARE(backend.configFields(0).value(QStringLiteral("username")).toString(),
             QStringLiteral("alice"));
}

// A config carries the server, the username and (on the import path, briefly)
// the password. Another local user has no business reading it.
void TestBackendConfig::createdConfigIsOwnerOnly()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));
    assertOwnerOnly(pathFor(backend, 0));
}

void TestBackendConfig::editInPlaceKeepsThePathAndUpdatesTheFields()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));
    const QString before = pathFor(backend, 0);

    QVariantMap edit = form(QStringLiteral("Alpha"), QStringLiteral("newpass"));
    edit[QStringLiteral("username")] = QStringLiteral("bob");
    edit[QStringLiteral("editIndex")] = 0;
    QVERIFY(backend.createConfig(edit));

    QCOMPARE(backend.configs().size(), 1); // an edit must not fork a second entry
    QCOMPARE(pathFor(backend, 0), before); // ...and saves over the original file
    const QVariantMap fields = backend.configFields(0);
    QCOMPARE(fields.value(QStringLiteral("username")).toString(), QStringLiteral("bob"));
    QCOMPARE(fields.value(QStringLiteral("password")).toString(), QStringLiteral("newpass"));
}

// Renaming moves the file, and the credential is keyed BY PATH — so the store
// has to be updated too, or the config silently loses its password and fails to
// connect with nothing on screen to explain why.
void TestBackendConfig::renamingCarriesThePasswordToTheNewPath()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));
    const QString oldPath = pathFor(backend, 0);

    QVariantMap edit = form(QStringLiteral("Renamed"), QStringLiteral("hunter2"));
    edit[QStringLiteral("editIndex")] = 0;
    QVERIFY(backend.createConfig(edit));

    QCOMPARE(backend.configs(), QStringList{QStringLiteral("Renamed")});
    const QString newPath = pathFor(backend, 0);
    QVERIFY(newPath != oldPath);
    QVERIFY2(!QFileInfo::exists(oldPath), "the old config file was left behind");
    QCOMPARE(backend.configFields(0).value(QStringLiteral("password")).toString(),
             QStringLiteral("hunter2"));
    // The stale entry must not linger in the credential store either.
    QVERIFY(freetunnel::CredentialStore::loadPassword(
                    freetunnel::CredentialStore::keyForConfigPath(oldPath))
                    .isEmpty());
}

// saveConfigWithPassword stages the body and only replaces the destination once
// the password is in the store. The old order truncated the file first, so a
// locked keyring destroyed a working config outright. Here the failure is a
// write failure (an undeletable directory in place of the target), but the
// invariant under test is the same one: a failed save leaves the config alone.
void TestBackendConfig::aFailedSaveLeavesTheExistingConfigIntact()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    const QString target = QDir(dir).filePath(QStringLiteral("staged.toml"));
    QVERIFY(freetunnel::backend_config::writeConfigFile(target, QByteArrayLiteral("original\n")));

    // A path that cannot be written: QSaveFile stages next to the target, and the
    // commit over a directory cannot succeed.
    const QString blocked = QDir(dir).filePath(QStringLiteral("blocked.toml"));
    QVERIFY(QDir().mkpath(blocked));
    QString err;
    QVERIFY(!freetunnel::backend_config::saveConfigWithPassword(
            blocked, QByteArrayLiteral("body\n"), QStringLiteral("pw"), &err));
    QCOMPARE(err, QStringLiteral("write"));

    // The untouched config next to it is still exactly what it was.
    QFile f(target);
    QVERIFY(f.open(QIODevice::ReadOnly));
    QCOMPARE(f.readAll(), QByteArrayLiteral("original\n"));
    freetunnel::CredentialStore::deletePassword(
            freetunnel::CredentialStore::keyForConfigPath(blocked));
    QDir().rmdir(blocked);
    QFile::remove(target);
}

// Export is the one path that deliberately writes the password in cleartext, into
// a directory the user picked. It has to land owner-only from the first byte.
void TestBackendConfig::exportCarriesThePasswordAndStaysOwnerOnly()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));

    const QString dest = QDir(m_home.path()).filePath(QStringLiteral("exported.toml"));
    QFile::remove(dest);
    QVERIFY(backend.exportConfigToml(0, dest));

    QFile f(dest);
    QVERIFY(f.open(QIODevice::ReadOnly));
    const freetunnel::ConfigToml c = freetunnel::parseConfigToml(QString::fromUtf8(f.readAll()));
    f.close();
    QCOMPARE(c.username, QStringLiteral("alice"));
    QCOMPARE(c.password, QStringLiteral("hunter2")); // pulled back out of the store
    assertOwnerOnly(dest);
    QFile::remove(dest);
}

// "Copy link" then "paste link" is a supported way to move a server between
// machines, so the link the app produces has to survive its own parser.
void TestBackendConfig::deepLinkRoundTripsBackIntoTheSameConfig()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));

    const QString link = backend.configDeepLink(0);
    QVERIFY(!link.isEmpty());

    QString err;
    const std::optional<freetunnel::DeepLinkConfig> parsed =
            freetunnel::parseDeepLink(link, &err);
    QVERIFY2(parsed.has_value(), qPrintable(err));
    const freetunnel::DeepLinkConfig &dl = *parsed;
    QCOMPARE(dl.hostname, QStringLiteral("vpn.example.org"));
    QCOMPARE(dl.username, QStringLiteral("alice"));
    QCOMPARE(dl.password, QStringLiteral("hunter2"));
    QCOMPARE(dl.addresses, QStringList{QStringLiteral("198.51.100.7:443")});
    QCOMPARE(dl.name, QStringLiteral("Alpha"));
}

void TestBackendConfig::moveConfigReordersTheList()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("a"))));
    QVERIFY(backend.createConfig(form(QStringLiteral("Beta"), QStringLiteral("b"))));
    const QStringList before = backend.configs();
    QCOMPARE(before.size(), 2);

    backend.moveConfig(0, 1);
    QStringList expected = before;
    expected.move(0, 1);
    QCOMPARE(backend.configs(), expected);

    // Out-of-range and no-op moves must leave the order alone rather than throw
    // the list away.
    backend.moveConfig(0, 0);
    backend.moveConfig(-1, 1);
    backend.moveConfig(0, 99);
    QCOMPARE(backend.configs(), expected);
}

// A removed config's password has no owner left. Leaving it in the OS store
// means a credential the user cannot see and cannot delete from the app.
void TestBackendConfig::removeConfigForgetsThePassword()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));
    const QString path = pathFor(backend, 0);
    const QString key = freetunnel::CredentialStore::keyForConfigPath(path);
    QCOMPARE(freetunnel::CredentialStore::loadPassword(key), QStringLiteral("hunter2"));

    backend.removeConfig(0);
    QVERIFY(backend.configs().isEmpty());
    QVERIFY2(!QFileInfo::exists(path), "the config file survived removal");
    QVERIFY2(freetunnel::CredentialStore::loadPassword(key).isEmpty(),
             "the password outlived the config it belonged to");
}

// QML asks for fields by row index, and rows disappear (removal, reload) between
// the click and the call. Every read accessor has to tolerate that.
void TestBackendConfig::readAccessorsRejectOutOfRangeIndexes()
{
    Backend backend;
    QVERIFY(backend.configFields(-1).isEmpty());
    QVERIFY(backend.configFields(0).isEmpty()); // no configs at all yet
    QVERIFY(backend.configDeepLink(-1).isEmpty());
    QVERIFY(backend.configDeepLink(5).isEmpty());
    QVERIFY(!backend.exportConfigToml(3, QDir(m_home.path()).filePath(QStringLiteral("no.toml"))));

    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("a"))));
    QVERIFY(backend.configFields(1).isEmpty()); // one past the end
    QVERIFY(backend.configDeepLink(1).isEmpty());
    // An empty destination is not a path — exporting there must fail, not write
    // the password to some default location.
    QVERIFY(!backend.exportConfigToml(0, QString()));
}

// pingConfigs() restarts the whole column: one placeholder per config, in the
// list's own order, and any probe still in flight from a previous run must not
// write into it afterwards.
void TestBackendConfig::pingsAreResetForEveryConfig()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("a"))));
    QVERIFY(backend.createConfig(form(QStringLiteral("Beta"), QStringLiteral("b"))));

    QSignalSpy pings(&backend, &Backend::pingsChanged);
    backend.pingConfigs();
    QVERIFY(pings.count() > 0);
    QCOMPARE(backend.pings().size(), backend.configs().size());

    // Restart immediately: the second run supersedes the first, and the column is
    // still exactly as long as the list — the stale probes cannot append to it.
    backend.pingConfigs();
    QCOMPARE(backend.pings().size(), backend.configs().size());
    QTest::qWait(600);
    QCOMPARE(backend.pings().size(), backend.configs().size());
}

// buildConnectTomlAsync() exists for one reason: building the connect config means
// reading the password out of the OS keychain, which blocks — on Linux for as long
// as the user takes to answer a keyring prompt. Doing that on the GUI thread
// freezes the window mid-connect.
//
// It was doing exactly that. A QThread OBJECT lives in the thread that created it,
// so connecting to its own started() signal with the default (auto) type queues the
// body back to the GUI thread: the worker starts, emits, and the work happens on
// the UI thread anyway. Nothing observable changes when this regresses — the app
// still connects, it just stops responding while it does — so the thread it ran on
// is recorded and asserted here.
void TestBackendConfig::theConnectConfigIsBuiltOffTheGuiThread()
{
    Backend backend;
    QVERIFY(backend.createConfig(form(QStringLiteral("Alpha"), QStringLiteral("hunter2"))));

    // Point the VPN client at a port nothing answers on. Without this connectVpn()
    // would try to spawn the privileged helper for real — an elevation prompt in
    // the middle of a unit test. The config build under test happens first either
    // way; what follows is expected to fail, and that is fine.
    qputenv("FT_TEST_HELPER_PORT", QByteArrayLiteral("1"));
    qputenv("FT_TEST_HELPER_TOKEN", QByteArrayLiteral("unused"));
    auto restore = qScopeGuard([] {
        qunsetenv("FT_TEST_HELPER_PORT");
        qunsetenv("FT_TEST_HELPER_TOKEN");
    });

    backend.connectVpn();

    // Checked the instant connectVpn() returns, while the worker is certainly
    // still alive, and deterministic because it asks about ownership rather than
    // timing: the build worker must not be a child of Backend.
    //
    // It used to be `new QThread(this)`. ~QObject then deletes it as part of
    // Backend's own destruction, and if the thread is still inside the keychain
    // read QThread's destructor reaches qFatal("Destroyed while thread is still
    // running") and the process aborts. That is how this test failed on macOS:
    // its assertions passed, then SIGABRT during teardown. Linux hid it because
    // the credential read there is microseconds and the worker always won the
    // race. The same window is reachable in the app — quitting while macOS has
    // its authorization dialog up, which is the very situation this worker exists
    // for.
    QVERIFY2(backend.findChildren<QThread *>().isEmpty(),
             "the config-build worker must not be parented to Backend: ~QObject would "
             "delete it mid-read and QThread's destructor calls qFatal");

    // lastTomlBuildThread() is now recorded when the build COMPLETES, not when it
    // starts, so waiting for it here also means this test can no longer outrun the
    // worker it started.
    QTRY_VERIFY_WITH_TIMEOUT(backend.lastTomlBuildThread() != nullptr, 10000);
    QVERIFY2(backend.lastTomlBuildThread() != QThread::currentThread(),
             "the connect config was built on the GUI thread — the keychain read blocks it");

    backend.disconnectVpn();
}

QTEST_MAIN(TestBackendConfig)
#include "test_backend_config.moc"
