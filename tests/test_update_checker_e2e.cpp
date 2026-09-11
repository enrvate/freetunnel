// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include <QDir>

#include <QStandardPaths>

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryFile>

#include "core/ReleaseVerify.h"
#include "core/UpdateChecker.h"
#include "mock_http_server.h"

// Resolves to the generated stand-in in the build tree, not to
// include/core/ReleaseSigning.h — see the fixture block in tests/CMakeLists.txt.
// It carries the public half of the throwaway key the signing helpers below use,
// which is what makes the "signature accepted" path reachable from a test at
// all. signedReleaseFixtureIsWired() re-derives it and fails loudly if the two
// ever stop matching, so a broken fixture can never look like a passing test.
#include "ReleaseSigning.h"

#if __has_include(<openssl/evp.h>)
#define FT_TEST_HAVE_OPENSSL 1
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

class TestUpdateCheckerE2e : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void checkNowFindsNewerRelease();
    void checkNowNoUpdateWhenCurrent();
    void checkNowNetworkError();
    void checkNowInvalidJson();
    void downloadVerifiesChecksum();
    void downloadRejectsBadChecksum();
    void downloadRejectsMissingChecksums();
    void downloadRejectsMissingSignature();
    void downloadRejectsInvalidSignature();
    void downloadAcceptsGenuinelySignedRelease();
    void downloadRejectsAManifestSignedForAnotherVersion();
    void downloadAcceptsAManifestFromBeforeVersionBinding();
    void downloadRejectsSignatureOverOtherContent();
    void rejectsAssetsFromAnotherRepo();
    void rejectsAssetsWhosePathTagDiffersFromTheRelease();
    void acceptsAssetsPublishedUnderThisReleaseTag();
    void replacesHostileHtmlUrlWithTheCanonicalReleasePage();
    void rejectsImplausibleTag();
};

#ifdef FT_TEST_HAVE_OPENSSL
// Seed of the throwaway Ed25519 key this file signs manifests with. A raw seed
// rather than a stored key file so nothing in the tree resembles a real signing
// key: the public half in the generated ReleaseSigning.h is derived from exactly
// these bytes, and signedReleaseFixtureIsWired() proves it before any test
// leans on a signature.
static const unsigned char kTestSigningSeed[32] = {
    0xf7, 0xe6, 0xd5, 0xc4, 0xb3, 0xa2, 0x91, 0x80, 0x7f, 0x6e, 0x5d,
    0x4c, 0x3b, 0x2a, 0x19, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
    0x01, 0x00, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87};

static EVP_PKEY *testSigningKey()
{
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, kTestSigningSeed,
                                        sizeof kTestSigningSeed);
}

// The SubjectPublicKeyInfo PEM matching kTestSigningSeed, in the exact shape
// ReleaseSigning.h stores it.
static QByteArray testSigningPublicKeyPem()
{
    EVP_PKEY *key = testSigningKey();
    if (!key)
        return {};
    QByteArray pem;
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio && PEM_write_bio_PUBKEY(bio, key) == 1) {
        char *data = nullptr;
        const long size = BIO_get_mem_data(bio, &data);
        if (data && size > 0)
            pem = QByteArray(data, static_cast<qsizetype>(size));
    }
    if (bio)
        BIO_free(bio);
    EVP_PKEY_free(key);
    return pem;
}

// A real detached Ed25519 signature over @p data — the same thing the release
// workflow produces for SHA256SUMS.txt, only with the throwaway key.
static QByteArray signWithTestKey(const QByteArray &data)
{
    EVP_PKEY *key = testSigningKey();
    if (!key)
        return {};
    QByteArray sig;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) == 1) {
        const auto *bytes = reinterpret_cast<const unsigned char *>(data.constData());
        const auto len = static_cast<size_t>(data.size());
        size_t sigLen = 0;
        if (EVP_DigestSign(ctx, nullptr, &sigLen, bytes, len) == 1) {
            sig.resize(static_cast<qsizetype>(sigLen));
            if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char *>(sig.data()), &sigLen, bytes,
                               len)
                != 1)
                sig.clear();
            else
                sig.resize(static_cast<qsizetype>(sigLen));
        }
    }
    if (ctx)
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return sig;
}

// True when the key UpdateChecker was compiled with really is the one
// kTestSigningSeed belongs to. Checked before every test that leans on a
// signature: if the fixture header ever fell off the include path the shipped
// public key would come back, no test signature could match it, and "signature
// rejected" would start looking like correct behaviour everywhere.
static bool signedReleaseFixtureIsWired()
{
    return testSigningPublicKeyPem() == QByteArray(freetunnel::kReleaseSigningPublicKeyPem);
}
#endif


static QString sha256HexOfBytes(const QByteArray &body)
{
    QTemporaryFile tf;
    tf.setAutoRemove(true);
    if (!tf.open())
        return QString();
    tf.write(body);
    tf.close();
    return sha256HexOfFile(tf.fileName());
}


static QString testInstallerAssetName()
{
#if defined(_WIN32)
    return QStringLiteral("freetunnel-test.exe");
#elif defined(__APPLE__)
    return QStringLiteral("freetunnel-test.dmg");
#else
    return QStringLiteral("freetunnel-test.AppImage");
#endif
}

static QJsonObject makeReleaseJson(const QString &tag, const QString &baseUrl,
                                   const QString &installerName)
{
    QJsonObject release;
    release[QStringLiteral("tag_name")] = tag;
    release[QStringLiteral("html_url")] = baseUrl + QStringLiteral("/release");
    release[QStringLiteral("body")] = QStringLiteral("notes");

    QJsonArray assets;
    QJsonObject sumsAsset;
    sumsAsset[QStringLiteral("name")] = QStringLiteral("SHA256SUMS.txt");
    sumsAsset[QStringLiteral("browser_download_url")] = baseUrl + QStringLiteral("/checksums");
    assets.append(sumsAsset);

    QJsonObject installerAsset;
    installerAsset[QStringLiteral("name")] = installerName;
    installerAsset[QStringLiteral("browser_download_url")] = baseUrl + QStringLiteral("/installer");
    assets.append(installerAsset);

    release[QStringLiteral("assets")] = assets;
    return release;
}

// The URL/tag gatekeepers are SKIPPED for hosts matching FT_GITHUB_API_BASE, so
// tests that build every URL from the mock's base never execute them — deleting
// the checks would keep the suite green. These helpers keep the API on the mock
// (so checkNow() still reaches it) while putting REAL github.com URLs in the
// payload, which is what makes the validators run.
static QJsonObject assetJson(const QString &name, const QString &url)
{
    QJsonObject a;
    a[QStringLiteral("name")] = name;
    a[QStringLiteral("browser_download_url")] = url;
    return a;
}

static QJsonObject releaseWithAssetBase(const QString &tag, const QString &assetBase,
                                        const QString &htmlUrl)
{
    QJsonObject release;
    release[QStringLiteral("tag_name")] = tag;
    release[QStringLiteral("html_url")] = htmlUrl;
    QJsonArray assets;
    assets.append(assetJson(QStringLiteral("SHA256SUMS.txt"), assetBase + QStringLiteral("/SHA256SUMS.txt")));
    assets.append(assetJson(testInstallerAssetName(),
                            assetBase + QStringLiteral("/") + testInstallerAssetName()));
    release[QStringLiteral("assets")] = assets;
    return release;
}

// Serve `release` from the mock and run a check against it.
static bool runCheck(MockHttpServer &http, const QJsonObject &release, UpdateChecker &checker,
                     QSignalSpy &available, QSignalSpy &none)
{
    MockHttpServer::Route route;
    route.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), route);
    checker.checkNow();
    return QTest::qWaitFor([&]() { return available.count() > 0 || none.count() > 0; }, 5000);
}

void TestUpdateCheckerE2e::checkNowFindsNewerRelease()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());

    const QJsonObject release =
            makeReleaseJson(QStringLiteral("v2.0.0"), base, QStringLiteral("freetunnel-test.AppImage"));
    MockHttpServer::Route route;
    route.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), route);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);

    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0 || none.count() > 0; }, 5000));
    QCOMPARE(available.count(), 1);
    QCOMPARE(checker.latestRelease().version, QStringLiteral("2.0.0"));
    qunsetenv("FT_GITHUB_API_BASE");
}

void TestUpdateCheckerE2e::checkNowNoUpdateWhenCurrent()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());

    const QJsonObject release =
            makeReleaseJson(QStringLiteral("v1.0.0"), base, QStringLiteral("freetunnel-test.AppImage"));
    MockHttpServer::Route route;
    route.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), route);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return none.count() > 0; }, 5000));
    QCOMPARE(none.count(), 1);
    qunsetenv("FT_GITHUB_API_BASE");
}

void TestUpdateCheckerE2e::downloadVerifiesChecksum()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());
    qputenv("FT_TEST_SKIP_UPDATE_SIG", "1");

    const QByteArray installerBody = QByteArrayLiteral("installer-payload");
    const QString installerName = testInstallerAssetName();
    const QString hex = sha256HexOfBytes(installerBody);
    const QByteArray sums = (hex + QStringLiteral("  ") + installerName + QChar('\n')).toUtf8();

    const QJsonObject release = makeReleaseJson(QStringLiteral("v2.0.0"), base, installerName);
    MockHttpServer::Route releaseRoute;
    releaseRoute.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), releaseRoute);

    MockHttpServer::Route sumsRoute;
    sumsRoute.body = sums;
    sumsRoute.contentType = QByteArrayLiteral("text/plain");
    http.setRoute(QStringLiteral("/checksums"), sumsRoute);

    MockHttpServer::Route installerRoute;
    installerRoute.body = installerBody;
    installerRoute.contentType = QByteArrayLiteral("application/octet-stream");
    http.setRoute(QStringLiteral("/installer"), installerRoute);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy ready(&checker, &UpdateChecker::downloadReady);
    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return ready.count() > 0 || failed.count() > 0; }, 10000));
    QCOMPARE(ready.count(), 1);
    QVERIFY(QFile::exists(ready.at(0).at(0).toString()));

    qunsetenv("FT_GITHUB_API_BASE");
    qunsetenv("FT_TEST_SKIP_UPDATE_SIG");
}

void TestUpdateCheckerE2e::checkNowNetworkError()
{
    qputenv("FT_GITHUB_API_BASE", QByteArrayLiteral("http://127.0.0.1:1"));

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return none.count() > 0; }, 5000));
    QCOMPARE(none.count(), 1);
    QVERIFY(none.at(0).at(0).toString().contains(QStringLiteral("Network error")));

    qunsetenv("FT_GITHUB_API_BASE");
}

void TestUpdateCheckerE2e::checkNowInvalidJson()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());

    MockHttpServer::Route route;
    route.body = QByteArrayLiteral("not-json");
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), route);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return none.count() > 0; }, 5000));
    QCOMPARE(none.at(0).at(0).toString(), QStringLiteral("Invalid response from GitHub API"));

    qunsetenv("FT_GITHUB_API_BASE");
}

void TestUpdateCheckerE2e::downloadRejectsMissingChecksums()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());

    QJsonObject release;
    release[QStringLiteral("tag_name")] = QStringLiteral("v2.0.0");
    release[QStringLiteral("html_url")] = base + QStringLiteral("/release");
    release[QStringLiteral("body")] = QStringLiteral("notes");
    QJsonArray assets;
    QJsonObject installerAsset;
    installerAsset[QStringLiteral("name")] = testInstallerAssetName();
    installerAsset[QStringLiteral("browser_download_url")] = base + QStringLiteral("/installer");
    assets.append(installerAsset);
    release[QStringLiteral("assets")] = assets;

    MockHttpServer::Route releaseRoute;
    releaseRoute.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), releaseRoute);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return failed.count() > 0; }, 5000));
    QVERIFY(failed.at(0).at(0).toString().contains(QStringLiteral("SHA256SUMS.txt")));

    qunsetenv("FT_GITHUB_API_BASE");
}

void TestUpdateCheckerE2e::downloadRejectsMissingSignature()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());

    const QString installerName = testInstallerAssetName();
    const QJsonObject release = makeReleaseJson(QStringLiteral("v2.0.0"), base, installerName);
    MockHttpServer::Route releaseRoute;
    releaseRoute.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), releaseRoute);

    const QByteArray sums = QByteArrayLiteral("abc123  ") + installerName.toUtf8() + "\n";
    MockHttpServer::Route sumsRoute;
    sumsRoute.body = sums;
    sumsRoute.contentType = QByteArrayLiteral("text/plain");
    http.setRoute(QStringLiteral("/checksums"), sumsRoute);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return failed.count() > 0; }, 5000));
    QVERIFY(failed.at(0).at(0).toString().contains(QStringLiteral("not signed")));

    qunsetenv("FT_GITHUB_API_BASE");
}

void TestUpdateCheckerE2e::downloadRejectsInvalidSignature()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());

    const QString installerName = testInstallerAssetName();
    QJsonObject release = makeReleaseJson(QStringLiteral("v2.0.0"), base, installerName);
    QJsonArray assets = release[QStringLiteral("assets")].toArray();
    QJsonObject sigAsset;
    sigAsset[QStringLiteral("name")] = QStringLiteral("SHA256SUMS.txt.sig");
    sigAsset[QStringLiteral("browser_download_url")] = base + QStringLiteral("/signature");
    assets.append(sigAsset);
    release[QStringLiteral("assets")] = assets;

    MockHttpServer::Route releaseRoute;
    releaseRoute.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), releaseRoute);

    const QByteArray sums = QByteArrayLiteral("abc123  ") + installerName.toUtf8() + "\n";
    MockHttpServer::Route sumsRoute;
    sumsRoute.body = sums;
    sumsRoute.contentType = QByteArrayLiteral("text/plain");
    http.setRoute(QStringLiteral("/checksums"), sumsRoute);

    MockHttpServer::Route sigRoute;
    sigRoute.body = QByteArrayLiteral("not-a-valid-signature");
    sigRoute.contentType = QByteArrayLiteral("application/octet-stream");
    http.setRoute(QStringLiteral("/signature"), sigRoute);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return failed.count() > 0; }, 10000));
    QVERIFY(failed.at(0).at(0).toString().contains(QStringLiteral("signature")));

    qunsetenv("FT_GITHUB_API_BASE");
}

#ifdef FT_TEST_HAVE_OPENSSL
// The manifest a real release ships: one line, the installer's true digest.
static QByteArray sumsManifestFor(const QByteArray &installerBody, const QString &assetName)
{
    return (sha256HexOfBytes(installerBody) + QStringLiteral("  ") + assetName + QChar('\n'))
            .toUtf8();
}

// The manifest a release built after version binding produces: the same content,
// with the release it belongs to written into the bytes the signature covers.
static QByteArray versionedSumsManifestFor(const QByteArray &installerBody,
                                           const QString &assetName, const QString &version)
{
    return (QStringLiteral("version=") + version + QChar('\n')).toUtf8()
            + sumsManifestFor(installerBody, assetName);
}

// Publish a complete release the way GitHub does: the installer, the manifest
// covering it, and a detached SHA256SUMS.txt.sig. Every route is well formed, so
// the only thing left to decide the outcome is whether @p signature really
// covers @p sums under the compiled-in key.
static void serveSignedRelease(MockHttpServer &http, const QString &base,
                               const QByteArray &installerBody, const QByteArray &sums,
                               const QByteArray &signature)
{
    QJsonObject release =
            makeReleaseJson(QStringLiteral("v2.0.0"), base, testInstallerAssetName());
    QJsonArray assets = release[QStringLiteral("assets")].toArray();
    assets.append(assetJson(QStringLiteral("SHA256SUMS.txt.sig"),
                            base + QStringLiteral("/signature")));
    release[QStringLiteral("assets")] = assets;

    MockHttpServer::Route releaseRoute;
    releaseRoute.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), releaseRoute);

    MockHttpServer::Route sumsRoute;
    sumsRoute.body = sums;
    sumsRoute.contentType = QByteArrayLiteral("text/plain");
    http.setRoute(QStringLiteral("/checksums"), sumsRoute);

    MockHttpServer::Route sigRoute;
    sigRoute.body = signature;
    sigRoute.contentType = QByteArrayLiteral("application/octet-stream");
    http.setRoute(QStringLiteral("/signature"), sigRoute);

    MockHttpServer::Route installerRoute;
    installerRoute.body = installerBody;
    installerRoute.contentType = QByteArrayLiteral("application/octet-stream");
    http.setRoute(QStringLiteral("/installer"), installerRoute);
}
#endif

// The one test that walks the path every genuine release takes: fetch the
// manifest, fetch the signature, verify it, and only then download and stage the
// installer. Nothing else covers it — the other signature tests all end in
// downloadFailed (they pass whether verification works or is broken shut), and
// the two that do reach downloadReady set FT_TEST_SKIP_UPDATE_SIG, which turns
// signatureVerificationActive() off and skips fetchSignature() entirely.
//
// What that leaves undefended is any mistake in *how* verifyEd25519Signature()
// is called rather than in the primitive: swapping its data and signature
// arguments, hashing the installer instead of the manifest, passing the wrong
// key. Each of those fails closed, so every existing test stays green while
// every real signed release is refused with "Update signature is invalid" and
// the entire user base is stranded on the build it already has, security fixes
// included. Deliberately no FT_TEST_SKIP_UPDATE_SIG here.
void TestUpdateCheckerE2e::downloadAcceptsGenuinelySignedRelease()
{
#ifndef FT_TEST_HAVE_OPENSSL
    QSKIP("Built without OpenSSL headers, so verifyEd25519Signature() rejects everything and "
          "the accept path cannot be exercised at all.");
#else
    QVERIFY2(signedReleaseFixtureIsWired(),
             "generated ReleaseSigning.h does not match kTestSigningSeed");

    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());
    // An earlier test in this binary may have left it set; verification must be
    // ON for this one or it proves nothing.
    qunsetenv("FT_TEST_SKIP_UPDATE_SIG");

    const QByteArray installerBody = QByteArrayLiteral("genuinely-signed-installer-payload");
    const QByteArray sums = sumsManifestFor(installerBody, testInstallerAssetName());
    const QByteArray signature = signWithTestKey(sums);
    QVERIFY(!signature.isEmpty());
    serveSignedRelease(http, base, installerBody, sums, signature);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy ready(&checker, &UpdateChecker::downloadReady);
    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return ready.count() > 0 || failed.count() > 0; }, 10000));
    QVERIFY2(failed.isEmpty(),
             failed.isEmpty() ? "" : qPrintable(failed.at(0).at(0).toString()));
    QCOMPARE(ready.count(), 1);

    // The staged file must be the payload we served, byte for byte: downloadReady
    // is the signal that gets it executed.
    const QString staged = ready.at(0).at(0).toString();
    QVERIFY(QFile::exists(staged));
    QFile f(staged);
    QVERIFY(f.open(QIODevice::ReadOnly));
    QCOMPARE(f.readAll(), installerBody);
    f.close();
    QFile::remove(staged);

    qunsetenv("FT_GITHUB_API_BASE");
#endif
}

// The companion to the test above, and the reason it is not enough on its own:
// this signature is real and made with the right key, it just covers different
// bytes. Verifying the wrong buffer — the installer, a stale manifest, a
// hard-coded string — would still satisfy "a valid signature exists", and only
// binding the check to the manifest actually fetched stops a swapped-in
// SHA256SUMS.txt from being installed under an old release's signature.
void TestUpdateCheckerE2e::downloadRejectsSignatureOverOtherContent()
{
#ifndef FT_TEST_HAVE_OPENSSL
    QSKIP("Built without OpenSSL headers, so no signature can be produced to sign anything with.");
#else
    QVERIFY2(signedReleaseFixtureIsWired(),
             "generated ReleaseSigning.h does not match kTestSigningSeed");

    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());
    qunsetenv("FT_TEST_SKIP_UPDATE_SIG");

    const QByteArray installerBody = QByteArrayLiteral("genuinely-signed-installer-payload");
    const QByteArray sums = sumsManifestFor(installerBody, testInstallerAssetName());
    // Signed with the trusted key, but over the previous release's manifest.
    const QByteArray signature =
            signWithTestKey(sumsManifestFor(QByteArrayLiteral("some-older-release"),
                                            testInstallerAssetName()));
    QVERIFY(!signature.isEmpty());
    QVERIFY(signature != signWithTestKey(sums));
    serveSignedRelease(http, base, installerBody, sums, signature);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy ready(&checker, &UpdateChecker::downloadReady);
    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return ready.count() > 0 || failed.count() > 0; }, 10000));
    QCOMPARE(ready.count(), 0);
    QCOMPARE(failed.count(), 1);
    QVERIFY2(failed.at(0).at(0).toString().contains(QStringLiteral("signature is invalid")),
             qPrintable(failed.at(0).at(0).toString()));

    qunsetenv("FT_GITHUB_API_BASE");
#endif
}

void TestUpdateCheckerE2e::downloadRejectsBadChecksum()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());
    qputenv("FT_TEST_SKIP_UPDATE_SIG", "1");

    const QByteArray installerBody = QByteArrayLiteral("installer-payload");
    const QString installerName = testInstallerAssetName();
    const QByteArray sums = QByteArray("deadbeef  ") + testInstallerAssetName().toUtf8() + "\n";

    const QJsonObject release = makeReleaseJson(QStringLiteral("v2.0.0"), base, installerName);
    MockHttpServer::Route releaseRoute;
    releaseRoute.body = QJsonDocument(release).toJson(QJsonDocument::Compact);
    http.setRoute(QStringLiteral("/repos/dimmmmmmmer/freetunnel/releases/latest"), releaseRoute);

    MockHttpServer::Route sumsRoute;
    sumsRoute.body = sums;
    sumsRoute.contentType = QByteArrayLiteral("text/plain");
    http.setRoute(QStringLiteral("/checksums"), sumsRoute);

    MockHttpServer::Route installerRoute;
    installerRoute.body = installerBody;
    installerRoute.contentType = QByteArrayLiteral("application/octet-stream");
    http.setRoute(QStringLiteral("/installer"), installerRoute);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return failed.count() > 0; }, 10000));
    QCOMPARE(failed.count(), 1);

    // Reporting the mismatch is only half the job: the file that failed the check
    // is an executable installer sitting in a directory the user can open. Leaving
    // it there turns a refused update into one they can still run by hand, and
    // deleting the QFile::remove() that prevents that broke nothing in this suite.
    const QString staged = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
            + QStringLiteral("/updates/") + testInstallerAssetName();
    QVERIFY2(!QFile::exists(staged),
             qPrintable(QStringLiteral("an installer that failed its integrity check must not "
                                       "be left behind at %1")
                                .arg(staged)));

    qunsetenv("FT_GITHUB_API_BASE");
    qunsetenv("FT_TEST_SKIP_UPDATE_SIG");
}

// An asset hosted under someone else's repo must not be picked up, even when the
// tag matches — otherwise a hostile API response points the installer at a file
// the attacker controls.
void TestUpdateCheckerE2e::rejectsAssetsFromAnotherRepo()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    QVERIFY(runCheck(http,
                     releaseWithAssetBase(
                             QStringLiteral("v2.0.0"),
                             QStringLiteral("https://github.com/attacker/freetunnel/releases/download/v2.0.0"),
                             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/tag/v2.0.0")),
                     checker, available, none));

    // The release itself is newer, so it is announced — but nothing downloadable
    // was accepted from it.
    QCOMPARE(available.count(), 1);
    QVERIFY(checker.latestRelease().installerUrl.isEmpty());
    QVERIFY(checker.latestRelease().checksumsUrl.isEmpty());

    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return failed.count() > 0; }, 5000));
    qunsetenv("FT_GITHUB_API_BASE");
}

// The tag in the asset path is what binds the manifest and the installer to the
// advertised release; without it, tag v9.9.9 could serve an older signed build.
void TestUpdateCheckerE2e::rejectsAssetsWhosePathTagDiffersFromTheRelease()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    QVERIFY(runCheck(http,
                     releaseWithAssetBase(
                             QStringLiteral("v9.9.9"),
                             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/download/v1.1.5"),
                             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/tag/v9.9.9")),
                     checker, available, none));

    QCOMPARE(available.count(), 1);
    QVERIFY(checker.latestRelease().installerUrl.isEmpty());
    QVERIFY(checker.latestRelease().checksumsUrl.isEmpty());
    qunsetenv("FT_GITHUB_API_BASE");
}

// The mirror of the two rejections: a genuine release's assets must be accepted,
// so an over-strict validator (which would strand every user) fails here too.
void TestUpdateCheckerE2e::acceptsAssetsPublishedUnderThisReleaseTag()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());

    const QString assetBase =
            QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/download/v2.0.0");
    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    QVERIFY(runCheck(http,
                     releaseWithAssetBase(
                             QStringLiteral("v2.0.0"), assetBase,
                             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/tag/v2.0.0")),
                     checker, available, none));

    QCOMPARE(available.count(), 1);
    QCOMPARE(checker.latestRelease().installerUrl,
             assetBase + QStringLiteral("/") + testInstallerAssetName());
    QCOMPARE(checker.latestRelease().checksumsUrl, assetBase + QStringLiteral("/SHA256SUMS.txt"));
    QCOMPARE(checker.latestRelease().htmlUrl,
             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/tag/v2.0.0"));
    qunsetenv("FT_GITHUB_API_BASE");
}

// html_url is handed to the user's browser and arrives in the same untrusted
// JSON as everything else.
void TestUpdateCheckerE2e::replacesHostileHtmlUrlWithTheCanonicalReleasePage()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    QVERIFY(runCheck(http,
                     releaseWithAssetBase(
                             QStringLiteral("v2.0.0"),
                             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/download/v2.0.0"),
                             QStringLiteral("https://evil.example/phish")),
                     checker, available, none));

    QCOMPARE(available.count(), 1);
    const QString shown = checker.latestRelease().htmlUrl;
    QVERIFY2(!shown.contains(QStringLiteral("evil.example")), qPrintable(shown));
    QVERIFY(shown.startsWith(QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/")));
    qunsetenv("FT_GITHUB_API_BASE");
}

void TestUpdateCheckerE2e::rejectsImplausibleTag()
{
    MockHttpServer http;
    QVERIFY(http.listen());
    qputenv("FT_GITHUB_API_BASE", http.baseUrl().toUtf8());

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    QSignalSpy none(&checker, &UpdateChecker::noUpdateAvailable);
    QVERIFY(runCheck(http,
                     releaseWithAssetBase(
                             QStringLiteral("../../etc/passwd"),
                             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/download/v2.0.0"),
                             QStringLiteral("https://github.com/dimmmmmmmer/freetunnel/releases/latest")),
                     checker, available, none));

    QCOMPARE(available.count(), 0);
    QCOMPARE(none.count(), 1);
    QVERIFY(none.first().at(0).toString().contains(QStringLiteral("Invalid response")));
    qunsetenv("FT_GITHUB_API_BASE");
}

// Replay: a manifest and signature that are entirely genuine, just from another
// release. Everything an attacker who controls the release metadata can present
// verifies — the key is real, the hashes are real, the assets are real — so the
// version inside the signed bytes is the only thing that can catch it.
void TestUpdateCheckerE2e::downloadRejectsAManifestSignedForAnotherVersion()
{
#ifndef FT_TEST_HAVE_OPENSSL
    QSKIP("Built without OpenSSL headers, so no signature can be produced to replay.");
#else
    QVERIFY(signedReleaseFixtureIsWired());

    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());
    qunsetenv("FT_TEST_SKIP_UPDATE_SIG");

    const QByteArray installerBody = QByteArrayLiteral("older-release-payload");
    // Offered as v2.0.0 (see serveSignedRelease), signed as 1.9.0.
    const QByteArray sums =
            versionedSumsManifestFor(installerBody, testInstallerAssetName(),
                                     QStringLiteral("1.9.0"));
    const QByteArray signature = signWithTestKey(sums);
    QVERIFY(!signature.isEmpty());
    serveSignedRelease(http, base, installerBody, sums, signature);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy ready(&checker, &UpdateChecker::downloadReady);
    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return ready.count() > 0 || failed.count() > 0; }, 10000));
    QCOMPARE(ready.count(), 0);
    QCOMPARE(failed.count(), 1);
    // Named versions, so the log says what was wrong rather than "invalid".
    const QString msg = failed.at(0).at(0).toString();
    QVERIFY2(msg.contains(QStringLiteral("1.9.0")) && msg.contains(QStringLiteral("2.0.0")),
             qPrintable(msg));
#endif
}

// Every release published before the version line existed has none, and those
// clients have to keep updating — refusing them would strand exactly the users
// this check exists to protect, on the build they already have.
void TestUpdateCheckerE2e::downloadAcceptsAManifestFromBeforeVersionBinding()
{
#ifndef FT_TEST_HAVE_OPENSSL
    QSKIP("Built without OpenSSL headers, so the accept path cannot be exercised.");
#else
    QVERIFY(signedReleaseFixtureIsWired());

    MockHttpServer http;
    QVERIFY(http.listen());
    const QString base = http.baseUrl();
    qputenv("FT_GITHUB_API_BASE", base.toUtf8());
    qunsetenv("FT_TEST_SKIP_UPDATE_SIG");

    const QByteArray installerBody = QByteArrayLiteral("legacy-unversioned-payload");
    const QByteArray sums = sumsManifestFor(installerBody, testInstallerAssetName());
    const QByteArray signature = signWithTestKey(sums);
    serveSignedRelease(http, base, installerBody, sums, signature);

    UpdateChecker checker(QStringLiteral("dimmmmmmmer/freetunnel"), QStringLiteral("1.0.0"));
    QSignalSpy available(&checker, &UpdateChecker::updateAvailable);
    checker.checkNow();
    QVERIFY(QTest::qWaitFor([&]() { return available.count() > 0; }, 5000));

    QSignalSpy ready(&checker, &UpdateChecker::downloadReady);
    QSignalSpy failed(&checker, &UpdateChecker::downloadFailed);
    checker.downloadLatest();
    QVERIFY(QTest::qWaitFor([&]() { return ready.count() > 0 || failed.count() > 0; }, 10000));
    QVERIFY2(failed.isEmpty(), qPrintable(failed.isEmpty() ? QString()
                                                           : failed.at(0).at(0).toString()));
    QCOMPARE(ready.count(), 1);
#endif
}

// This test downloads an installer and stages it under
// QStandardPaths::CacheLocation, which without a test identity is the REAL user
// cache — so running the suite left executables in ~/.cache and, worse, meant a
// developer's own FreeTunnel cache was the directory under test. Give it a name
// of its own and the test-mode redirect the rest of the suite uses.
void TestUpdateCheckerE2e::initTestCase()
{
    QCoreApplication::setOrganizationName(QStringLiteral("FreeTunnelTest"));
    QCoreApplication::setApplicationName(QStringLiteral("UpdateCheckerE2eTest"));
    QStandardPaths::setTestModeEnabled(true);
}

// And take the staged downloads with us. A test that leaves an executable behind
// on every run is one nobody wants to run locally.
void TestUpdateCheckerE2e::cleanupTestCase()
{
    const QString staging = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
            + QStringLiteral("/updates");
    QDir(staging).removeRecursively();
}

QTEST_MAIN(TestUpdateCheckerE2e)
#include "test_update_checker_e2e.moc"
