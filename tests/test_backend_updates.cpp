// cppcheck-suppress-file missingIncludeSystem
// Backend's update surface: the state machine QML binds to, and the decision
// behind the one clickable icon in the Settings row.
//
// This file existed at 2.3% line coverage while owning the code that ends in
// launching a downloaded installer. Both bugs found here were found by review,
// not by tests: a failed CHECK was reported to the user as "You have the latest
// version", and the retry icon started a DOWNLOAD instead of re-checking,
// because "did the download or the check fail?" was inferred from
// m_latestVersion — which is set by the first successful check and never
// cleared.
#include <QtTest>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryDir>

#include "app/Backend.h"
#include "core/UpdateChecker.h"
#include "mock_http_server.h"

class TestBackendUpdates : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();

    void checkFindsNewerVersion();
    void checkFindsNothingNewer();
    void failedCheckReportsTheFailure();
    void retryAfterFailedCheckChecksAgainInsteadOfDownloading();
    void backgroundCheckDoesNotPaintCheckingState();
    void asecondCheckWhileOneIsRunningIsIgnored();

private:
    // Serve one release payload and wait for the check to settle.
    static void serveRelease(MockHttpServer &http, const QString &tag);
    static bool settled(const Backend &backend);

    QTemporaryDir m_home;
};

void TestBackendUpdates::initTestCase()
{
    QVERIFY(m_home.isValid());
    qputenv("XDG_CONFIG_HOME", m_home.path().toUtf8());
    qputenv("XDG_DATA_HOME", m_home.path().toUtf8());
    QStandardPaths::setTestModeEnabled(true);
    QCoreApplication::setOrganizationName(QStringLiteral("FreeTunnelTest"));
    QCoreApplication::setApplicationName(QStringLiteral("BackendUpdatesTest"));
}

void TestBackendUpdates::serveRelease(MockHttpServer &http, const QString &tag)
{
    const QString base = http.baseUrl();
    QJsonObject release;
    release[QStringLiteral("tag_name")] = tag;
    release[QStringLiteral("html_url")] = base + QStringLiteral("/release");

    // Asset URLs on the mock host: UpdateChecker trusts its own test base, so the
    // release resolves without reaching github.com. The URL/tag validation itself
    // is covered in test_update_checker_e2e.
    QJsonArray assets;
    QJsonObject sums;
    sums[QStringLiteral("name")] = QStringLiteral("SHA256SUMS.txt");
    sums[QStringLiteral("browser_download_url")] = base + QStringLiteral("/checksums");
    assets.append(sums);
    release[QStringLiteral("assets")] = assets;

    MockHttpServer::Route route;
    route.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), route);
}

bool TestBackendUpdates::settled(const Backend &backend)
{
    const QString s = backend.updateState();
    return s == QLatin1String("current") || s == QLatin1String("available")
            || s == QLatin1String("error");
}

void TestBackendUpdates::checkFindsNewerVersion()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());
    serveRelease(http, QStringLiteral("v99.0.0"));

    Backend backend;
    backend.checkForUpdates(true);
    QTRY_VERIFY_WITH_TIMEOUT(settled(backend), 10000);

    QCOMPARE(backend.updateState(), QStringLiteral("available"));
    QCOMPARE(backend.latestVersion(), QStringLiteral("99.0.0"));
    QVERIFY2(backend.updateMessage().contains(QStringLiteral("99.0.0")),
             qPrintable(backend.updateMessage()));
    qunsetenv("FT_GITHUB_API_BASE");
}

// Clicking "Check for updates" twice, or a background timer firing while the
// user has just asked, must not start two checks. Two guards stand between that
// and the network — one keeps a single UpdateChecker, the other refuses to start
// while a check is already in flight — and the sweep found neither was tested.
//
// The observation has to be the request count. Once both checks settle, the
// state, the version and the message all read exactly the same whether one check
// ran or two, so nothing the Backend exposes can tell them apart.
void TestBackendUpdates::asecondCheckWhileOneIsRunningIsIgnored()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());
    serveRelease(http, QStringLiteral("v99.0.0"));

    Backend backend;
    backend.checkForUpdates(true);
    backend.checkForUpdates(true);   // the impatient second click
    QTRY_VERIFY_WITH_TIMEOUT(settled(backend), 10000);

    QCOMPARE(backend.updateState(), QStringLiteral("available"));
    QCOMPARE(http.requestCount(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest")), 1);

    // And only one updater exists to have made it. ensureUpdater() parents each
    // one to the Backend, so a missing guard would leave a pile of them wired to
    // the same signals, every one answering the next check.
    QCOMPARE(backend.findChildren<UpdateChecker *>().size(), 1);

    // A later check is still allowed — the guard is about concurrency, not a
    // one-shot latch.
    backend.checkForUpdates(true);
    QTRY_VERIFY_WITH_TIMEOUT(settled(backend), 10000);
    QCOMPARE(http.requestCount(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest")), 2);
    QCOMPARE(backend.findChildren<UpdateChecker *>().size(), 1);

    qunsetenv("FT_GITHUB_API_BASE");
}

void TestBackendUpdates::checkFindsNothingNewer()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());
    // 0.0.1 can never be newer than whatever this build reports.
    serveRelease(http, QStringLiteral("v0.0.1"));

    Backend backend;
    backend.checkForUpdates(true);
    QTRY_VERIFY_WITH_TIMEOUT(settled(backend), 10000);

    QCOMPARE(backend.updateState(), QStringLiteral("current"));
    qunsetenv("FT_GITHUB_API_BASE");
}

// The regression that mattered most: an offline user was told they were up to
// date, because the checker reports its own failures through the same signal it
// uses for "nothing newer".
void TestBackendUpdates::failedCheckReportsTheFailure()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());
    // No route registered for the releases path -> the request fails.

    Backend backend;
    backend.checkForUpdates(true);
    QTRY_VERIFY_WITH_TIMEOUT(settled(backend), 10000);

    QCOMPARE(backend.updateState(), QStringLiteral("error"));
    QVERIFY2(!backend.updateMessage().contains(QStringLiteral("latest version"),
                                               Qt::CaseInsensitive),
             qPrintable(backend.updateMessage()));
    QVERIFY(!backend.updateMessage().isEmpty());
    qunsetenv("FT_GITHUB_API_BASE");
}

// After a check that FAILED there is nothing resolved to download, so the icon
// must retry the check. This only regressed once a release had already been
// seen, so the test establishes that state first — which is exactly what the
// old m_latestVersion proxy got wrong.
void TestBackendUpdates::retryAfterFailedCheckChecksAgainInsteadOfDownloading()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());
    serveRelease(http, QStringLiteral("v99.0.0"));

    Backend backend;
    backend.checkForUpdates(true);
    QTRY_VERIFY_WITH_TIMEOUT(settled(backend), 10000);
    QCOMPARE(backend.updateState(), QStringLiteral("available")); // a release IS known now

    // Now make the next check fail, the way going offline would.
    MockHttpServer::Route broken;
    broken.status = 500;
    broken.body = QByteArrayLiteral("nope");
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), broken);

    backend.checkForUpdates(true);
    QTRY_VERIFY_WITH_TIMEOUT(settled(backend), 10000);
    QCOMPARE(backend.updateState(), QStringLiteral("error"));

    // The user clicks the icon. It must re-check — and a re-check is observable
    // as the "checking" state, which a download never produces.
    QSignalSpy changed(&backend, &Backend::updateChanged);
    serveRelease(http, QStringLiteral("v99.0.0"));
    backend.openLatestRelease();

    bool sawChecking = backend.updateState() == QLatin1String("checking");
    QTRY_VERIFY_WITH_TIMEOUT(
            [&]() {
                if (backend.updateState() == QLatin1String("checking"))
                    sawChecking = true;
                return sawChecking && settled(backend);
            }(),
            10000);
    QVERIFY2(sawChecking, "the retry did not re-check — it went straight to a download");
    QVERIFY2(backend.updateState() != QLatin1String("downloading")
                     && backend.updateState() != QLatin1String("ready"),
             qPrintable(backend.updateState()));
    qunsetenv("FT_GITHUB_API_BASE");
}

// The automatic check at startup must not paint the Settings row: the user did
// not ask, and a spinner appearing on its own reads as something being wrong.
void TestBackendUpdates::backgroundCheckDoesNotPaintCheckingState()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());
    serveRelease(http, QStringLiteral("v0.0.1")); // nothing newer

    Backend backend;
    backend.checkForUpdates(false);
    QCOMPARE(backend.updateState(), QString()); // not "checking"

    // And a background check that finds nothing must stay silent rather than
    // announcing "you are up to date" nobody asked about.
    QTest::qWait(1500);
    QVERIFY2(backend.updateState().isEmpty() || backend.updateState() == QLatin1String("available"),
             qPrintable(backend.updateState()));
    qunsetenv("FT_GITHUB_API_BASE");
}

QTEST_MAIN(TestBackendUpdates)
#include "test_backend_updates.moc"
