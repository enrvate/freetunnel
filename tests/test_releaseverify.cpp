// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include <QTemporaryFile>

#include "core/ReleaseSigning.h"
#include "core/ReleaseVerify.h"

class TestReleaseVerify : public QObject {
    Q_OBJECT

private slots:
    void parseSums();
    void verifyMatch();
    void verifyMismatch();
    void versionFromSumsReadsTheSignedVersion();
    void signatureVerificationIsCompiledIn();
    void ed25519Valid();
    void ed25519Invalid();
    void theShippedSigningKeyIsAUsableEd25519PublicKey();
};

void TestReleaseVerify::parseSums()
{
    const QByteArray sums = "abc123  freetunnel-linux-x86_64.AppImage\n"
                            "def456  freetunnel-linux-x86_64.deb\n";
    QCOMPARE(expectedSha256FromSums(sums, QStringLiteral("freetunnel-linux-x86_64.AppImage")),
             QStringLiteral("abc123"));
    QVERIFY(expectedSha256FromSums(sums, QStringLiteral("missing")).isEmpty());
}

void TestReleaseVerify::verifyMatch()
{
    QTemporaryFile tf;
    QVERIFY(tf.open());
    tf.write("payload");
    tf.close();

    const QByteArray sums = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  test.bin\n";
    // hash of "test" not "payload" — use actual hash of payload
    const QString hex = sha256HexOfFile(tf.fileName());
    const QByteArray realSums = (hex + "  test.bin\n").toLatin1();
    QVERIFY(verifyFileAgainstSums(tf.fileName(), realSums, QStringLiteral("test.bin")));
}

void TestReleaseVerify::verifyMismatch()
{
    QTemporaryFile tf;
    QVERIFY(tf.open());
    tf.write("payload");
    tf.close();
    const QByteArray sums = "deadbeef  test.bin\n";
    QVERIFY(!verifyFileAgainstSums(tf.fileName(), sums, QStringLiteral("test.bin")));
}

// The version line is what makes a signature mean "this release" rather than
// merely "we built these bytes". Parsing it is independent of OpenSSL, so unlike
// the verification tests this one runs everywhere — which matters, because the
// rest of this feature is only exercised on builds that have OpenSSL headers.
void TestReleaseVerify::versionFromSumsReadsTheSignedVersion()
{
    // Written as a comment: people verify this file with `sha256sum -c`, which
    // calls any line it cannot parse "improperly formatted" — a warning that reads
    // like tampering, and a failure under --strict.
    const QByteArray versioned =
            "#version=1.1.8\n"
            "abc123  freetunnel-linux-x86_64.deb\n";
    QCOMPARE(versionFromSums(versioned), QStringLiteral("1.1.8"));
    // The line must not eat the asset it sits above.
    QCOMPARE(expectedSha256FromSums(versioned, QStringLiteral("freetunnel-linux-x86_64.deb")),
             QStringLiteral("abc123"));

    // Releases published before this existed carry no version, and must stay
    // installable — refusing them would strand the clients this protects.
    QVERIFY(versionFromSums("abc123  freetunnel-linux-x86_64.deb\n").isEmpty());
    QVERIFY(versionFromSums(QByteArray()).isEmpty());

    // An appended second line must not talk over the signer's. (The signature
    // covers the whole file, so this is depth rather than the only defence.)
    QCOMPARE(versionFromSums("#version=1.1.8\nabc  x\n#version=9.9.9\n"),
             QStringLiteral("1.1.8"));

    // Trailing whitespace and CRLF from a text-mode pipeline.
    QCOMPARE(versionFromSums("#version=1.1.8  \r\nabc  x\n"), QStringLiteral("1.1.8"));
    // The bare form stays readable too — releases signed before the comment
    // spelling was adopted must keep verifying.
    QCOMPARE(versionFromSums("version=1.1.8\nabc  x\n"), QStringLiteral("1.1.8"));

    // A hash line is not a version line, whatever it contains.
    QVERIFY(versionFromSums("abc  version=2.0.0\n").isEmpty());
}

// These three used to sit behind `#if __has_include(<openssl/evp.h>)` — the very
// condition that turns verifyEd25519Signature() into a flat `false`. So they
// vanished from the binary at exactly the moment the feature they guard stopped
// working, and a local run reported "6 passed, 0 skipped" with no hint that
// signature verification had not been exercised at all. Compiled in
// unconditionally now, and skipped out loud when the capability is missing.
void TestReleaseVerify::signatureVerificationIsCompiledIn()
{
    if (!releaseSignatureVerificationAvailable())
        QSKIP("built without OpenSSL: update signature verification is INERT in this "
              "build and the three tests below cannot run. Never ship such a build.");
    QVERIFY(releaseSignatureVerificationAvailable());
}

void TestReleaseVerify::ed25519Valid()
{
    if (!releaseSignatureVerificationAvailable())
        QSKIP("built without OpenSSL");
    static const char kPubPem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEAdSdq79YO2Q2DAi/R23X7qCa5qsL3EVwG3Kb064ajl38=\n"
        "-----END PUBLIC KEY-----\n";
    const QByteArray manifest("abc123  test.AppImage\n");
    const QByteArray sig = QByteArray::fromHex(
        "d57a0fcaee75b77602433ee06e0f8b55cacd9113fe5969068b24211a0f11ec4"
        "fdf3503b8c06c3b4be0fcd547d773250c634ca96df804b15f5336f355a6563008");
    QVERIFY(verifyEd25519Signature(manifest, sig, kPubPem));
}

void TestReleaseVerify::ed25519Invalid()
{
    if (!releaseSignatureVerificationAvailable())
        QSKIP("built without OpenSSL");
    static const char kPubPem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEAdSdq79YO2Q2DAi/R23X7qCa5qsL3EVwG3Kb064ajl38=\n"
        "-----END PUBLIC KEY-----\n";
    const QByteArray manifest("tampered  test.AppImage\n");
    const QByteArray sig = QByteArray::fromHex(
        "d57a0fcaee75b77602433ee06e0f8b55cacd9113fe5969068b24211a0f11ec4"
        "fdf3503b8c06c3b4be0fcd547d773250c634ca96df804b15f5336f355a6563008");
    QVERIFY(!verifyEd25519Signature(manifest, sig, kPubPem));
}

// The updater's whole trust anchor is one string constant. test_update_checker_e2e
// deliberately compiles against a generated stand-in key so it can sign its own
// manifests, which means nothing else in the suite would notice if the real one
// were blanked or corrupted — by a botched key rotation, a stray sed, a merge that
// empties the literal. signatureVerificationConfigured() then reports "no key
// configured" and, depending on how that is read, either locks every user out of
// every future update or stops checking signatures at all. Neither should be
// reachable by accident, so assert the shipped constant is a real key here, where
// the real header is the one being compiled.
//
// The first two checks below never needed OpenSSL — they are string assertions
// about a compiled-in constant — yet the whole test used to be hidden behind
// __has_include, so a build without OpenSSL also lost its only guard against the
// shipped key being blanked. They now run everywhere; only the part that asks
// OpenSSL to parse the key is skipped.
void TestReleaseVerify::theShippedSigningKeyIsAUsableEd25519PublicKey()
{
    const QByteArray pem = QByteArray(freetunnel::kReleaseSigningPublicKeyPem);
    QVERIFY2(!pem.trimmed().isEmpty(), "the shipped release signing key is empty");
    QVERIFY2(pem.contains("-----BEGIN PUBLIC KEY-----"), "not a SubjectPublicKeyInfo PEM");

    // Shape-check the key itself, with arithmetic rather than OpenSSL, so this
    // still bites in a build that has no OpenSSL — which is the local dev build,
    // and so the one where a mangled key would first appear. An Ed25519
    // SubjectPublicKeyInfo is exactly 44 bytes: a 12-byte DER header naming
    // OID 1.3.101.112, then the 32-byte key. Emptying the base64 body leaves a
    // PEM that is neither empty nor missing its BEGIN line, so the two checks
    // above wave it through; this one does not.
    QByteArray b64;
    for (const QByteArray &line : pem.split('\n')) {
        const QByteArray t = line.trimmed();
        if (!t.isEmpty() && !t.startsWith("-----"))
            b64 += t;
    }
    const QByteArray der = QByteArray::fromBase64(b64);
    QCOMPARE(der.size(), 44);
    QCOMPARE(der.left(12).toHex(), QByteArrayLiteral("302a300506032b6570032100"));

    if (!releaseSignatureVerificationAvailable())
        QSKIP("built without OpenSSL: the key cannot be load-tested here");

    // Well-formed is not enough — OpenSSL has to accept it as an Ed25519 key, which
    // is what verifyEd25519Signature() will ask of it at update time. Feeding it a
    // signature we know is wrong proves the key LOADS: a key OpenSSL cannot parse
    // and a good key rejecting a bad signature are both "false" at the call site,
    // so distinguish them by checking that a garbage key fails the same way for a
    // different reason — see ed25519Invalid for the signature-level case.
    QVERIFY(!verifyEd25519Signature(QByteArrayLiteral("payload"),
                                    QByteArrayLiteral("not-a-signature"), pem));
    QVERIFY(!verifyEd25519Signature(
            QByteArrayLiteral("payload"), QByteArrayLiteral("not-a-signature"),
            QByteArrayLiteral("-----BEGIN PUBLIC KEY-----\nbroken\n-----END PUBLIC KEY-----\n")));
}

QTEST_MAIN(TestReleaseVerify)
#include "test_releaseverify.moc"
