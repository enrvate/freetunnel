// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>
#include <QRandomGenerator>

#include "core/DeepLink.h"

using namespace freetunnel;

class TestDeepLink : public QObject {
    Q_OBJECT

private slots:
    void roundTrip();
    void rejectsBadScheme();
    void rejectsMissingRequired();
    void rejectsFutureVersion();
    void ignoresUnknownTags();
    void decodesHandCrafted();
    void longValuesUseMultiByteVarint();
    void tomlContainsKeyFields();
    void tomlInjectionStripped();
    void malformedPayloadsNeverCrash();
    void structuredTlvFuzzNeverCrash();
    void mutatesValidLinksSafely();
    void rejectsOversizedTlvLength();
    void rejectsATlvLengthPastTheEndOfThePayload();
    void acceptsTrustTunnelQrFragment();
};

void TestDeepLink::roundTrip() {
    DeepLinkConfig in;
    in.hostname = "vpn.example.com";
    in.addresses = {"1.2.3.4:443", "[2001:db8::1]:443"};
    in.customSni = "example.org";
    in.hasIpv6 = false;
    in.username = "premium";
    in.password = "s3cretPass";
    in.skipVerification = true;
    in.upstreamProtocol = UpstreamProtocol::Http3;
    in.antiDpi = true;
    in.clientRandomPrefix = "deadbeef/ffff";
    in.name = "My Server";
    in.dnsUpstreams = {"1.1.1.1", "tls://dns.example.com"};

    const QString uri = encodeDeepLink(in);
    QVERIFY(uri.startsWith("tt://?"));

    QString err;
    auto out = parseDeepLink(uri, &err);
    QVERIFY2(out.has_value(), qPrintable(err));

    QCOMPARE(out->hostname, in.hostname);
    QCOMPARE(out->addresses, in.addresses);
    QCOMPARE(out->customSni, in.customSni);
    QCOMPARE(out->hasIpv6, false);
    QCOMPARE(out->username, in.username);
    QCOMPARE(out->password, in.password);
    QCOMPARE(out->skipVerification, true);
    QVERIFY(out->upstreamProtocol == UpstreamProtocol::Http3);
    QCOMPARE(out->antiDpi, true);
    QCOMPARE(out->clientRandomPrefix, in.clientRandomPrefix);
    QCOMPARE(out->name, in.name);
    QCOMPARE(out->dnsUpstreams, in.dnsUpstreams);
}

void TestDeepLink::rejectsBadScheme() {
    QString err;
    QVERIFY(!parseDeepLink("https://example.com", &err).has_value());
    QVERIFY(!err.isEmpty());
    QVERIFY(!parseDeepLink("tt://?", &err).has_value()); // empty payload
}

void TestDeepLink::rejectsMissingRequired() {
    DeepLinkConfig in;
    in.hostname = "h.example";
    // no addresses / username / password
    const QString uri = encodeDeepLink(in);
    QString err;
    QVERIFY(!parseDeepLink(uri, &err).has_value());
}

void TestDeepLink::rejectsFutureVersion() {
    // Hand-craft a payload that declares version 99 plus all required fields.
    QByteArray p;
    auto tlv = [&](char tag, const QByteArray &v) {
        p.append(tag);
        p.append(static_cast<char>(v.size()));
        p.append(v);
    };
    tlv(0x00, QByteArray(1, 2)); // version = 2 (> kDeepLinkMaxVersion); fits one varint byte
    tlv(0x01, "h");
    tlv(0x02, "1.2.3.4:443");
    tlv(0x05, "u");
    tlv(0x06, "pw");
    const QString uri = "tt://?"
            + QString::fromLatin1(p.toBase64(QByteArray::Base64UrlEncoding
                                             | QByteArray::OmitTrailingEquals));
    QString err;
    QVERIFY(!parseDeepLink(uri, &err).has_value());
    QVERIFY(err.contains("version"));
}

void TestDeepLink::ignoresUnknownTags() {
    QByteArray p;
    auto tlv = [&](char tag, const QByteArray &v) {
        p.append(tag);
        p.append(static_cast<char>(v.size()));
        p.append(v);
    };
    tlv(0x01, "h.example");
    tlv(0x02, "1.2.3.4:443");
    tlv(0x05, "user");
    tlv(0x06, "pass");
    tlv(0x2A, "future-field-payload"); // unknown tag must be skipped
    const QString uri = "tt://?"
            + QString::fromLatin1(p.toBase64(QByteArray::Base64UrlEncoding
                                             | QByteArray::OmitTrailingEquals));
    QString err;
    auto out = parseDeepLink(uri, &err);
    QVERIFY2(out.has_value(), qPrintable(err));
    QCOMPARE(out->hostname, QStringLiteral("h.example"));
    QCOMPARE(out->hasIpv6, true); // default preserved
}

void TestDeepLink::decodesHandCrafted() {
    // Decoder must work independently of our encoder.
    QByteArray p;
    auto tlv = [&](char tag, const QByteArray &v) {
        p.append(tag);
        p.append(static_cast<char>(v.size()));
        p.append(v);
    };
    tlv(0x01, "host.tld");
    tlv(0x02, "10.0.0.1:8443");
    tlv(0x02, "10.0.0.2:8443");
    tlv(0x05, "alice");
    tlv(0x06, "wonderland");
    const QString uri = "tt://?"
            + QString::fromLatin1(p.toBase64(QByteArray::Base64UrlEncoding
                                             | QByteArray::OmitTrailingEquals));
    auto out = parseDeepLink(uri);
    QVERIFY(out.has_value());
    QCOMPARE(out->addresses.size(), 2);
    QCOMPARE(out->addresses.at(1), QStringLiteral("10.0.0.2:8443"));
}

void TestDeepLink::longValuesUseMultiByteVarint() {
    DeepLinkConfig in;
    in.hostname = QString(200, QChar('a')); // > 63 bytes -> 2-byte length varint
    in.addresses = {"1.2.3.4:443"};
    in.username = "u";
    in.password = "p";
    const QString uri = encodeDeepLink(in);
    auto out = parseDeepLink(uri);
    QVERIFY(out.has_value());
    QCOMPARE(out->hostname.size(), 200);
}

void TestDeepLink::tomlContainsKeyFields() {
    DeepLinkConfig in;
    in.hostname = "vpn.example.com";
    in.addresses = {"1.2.3.4:443"};
    in.username = "u";
    in.password = "p";
    in.upstreamProtocol = UpstreamProtocol::Http3;
    const QString toml = deepLinkConfigToToml(in);
    QVERIFY(toml.contains("[endpoint]"));
    QVERIFY(toml.contains("hostname = \"vpn.example.com\""));
    QVERIFY(toml.contains("addresses = [\"1.2.3.4:443\"]"));
    QVERIFY(toml.contains("upstream_protocol = \"http3\""));
}

// A crafted field with control characters must not be able to break out of its
// quoted TOML value and inject extra keys into the generated config.
void TestDeepLink::tomlInjectionStripped() {
    DeepLinkConfig in;
    in.hostname = "h.example";
    in.addresses = {"1.2.3.4:443"};
    in.username = "u\nskip_verification = true\nx = \""; // newline + quote break-out attempt
    in.password = "p";
    const QString toml = deepLinkConfigToToml(in);
    // No injected key can appear at the start of a line...
    QVERIFY(!toml.contains(QStringLiteral("\nskip_verification = true")));
    // ...and the legitimate value is intact.
    QVERIFY(toml.contains(QStringLiteral("skip_verification = false")));
    // The newline is stripped, so the value collapses onto its own (single) line.
    QVERIFY(toml.contains(QStringLiteral("username = \"uskip_verification = true")));
}

void TestDeepLink::malformedPayloadsNeverCrash()
{
    for (int seed = 0; seed < 3000; ++seed) {
        QByteArray p;
        p.resize(seed % 512);
        for (int i = 0; i < p.size(); ++i)
            p[i] = static_cast<char>((seed * 31 + i * 17) & 0xFF);
        const QString uri = QStringLiteral("tt://?")
                + QString::fromLatin1(p.toBase64(QByteArray::Base64UrlEncoding));
        QString err;
        (void)parseDeepLink(uri, &err);
    }
    QVERIFY(true);
}

// Random TLV-shaped byte streams (not necessarily valid base64url payloads).
void TestDeepLink::structuredTlvFuzzNeverCrash()
{
    auto *rng = QRandomGenerator::global();
    for (int i = 0; i < 2000; ++i) {
        QByteArray p;
        p.resize(rng->bounded(1, 384));
        for (int j = 0; j < p.size(); ++j)
            p[j] = static_cast<char>(rng->generate() & 0xFF);
        const QString uri = QStringLiteral("tt://?")
                + QString::fromLatin1(p.toBase64(QByteArray::Base64UrlEncoding
                                                 | QByteArray::OmitTrailingEquals));
        QString err;
        (void)parseDeepLink(uri, &err);
    }
    QVERIFY(true);
}

void TestDeepLink::mutatesValidLinksSafely()
{
    DeepLinkConfig in;
    in.hostname = QStringLiteral("vpn.example.com");
    in.addresses = {QStringLiteral("1.2.3.4:443")};
    in.username = QStringLiteral("user");
    in.password = QStringLiteral("pass");
    const QString valid = encodeDeepLink(in);
    const QString payload = valid.mid(QStringLiteral("tt://?").size());

    auto *rng = QRandomGenerator::global();
    for (int i = 0; i < 500; ++i) {
        QByteArray mutated = payload.toLatin1();
        const int n = rng->bounded(1, 8);
        for (int j = 0; j < n; ++j) {
            const int pos = rng->bounded(mutated.size() + 1);
            if (pos == mutated.size())
                mutated.append(static_cast<char>(rng->generate() & 0xFF));
            else
                mutated[pos] = static_cast<char>(rng->generate() & 0xFF);
        }
        if (rng->bounded(4) == 0 && !mutated.isEmpty())
            mutated.chop(rng->bounded(1, qMin(16, mutated.size())));
        const QString uri = QStringLiteral("tt://?")
                + QString::fromLatin1(mutated);
        QString err;
        (void)parseDeepLink(uri, &err);
    }
    QVERIFY(true);
}

void TestDeepLink::rejectsOversizedTlvLength()
{
    // Tag 0x01 + 8-byte varint length > INT_MAX must fail safely (no overflow crash).
    QByteArray p;
    p.append(static_cast<char>(0x01));
    p.append(static_cast<char>(0xC0));
    for (int i = 0; i < 7; ++i)
        p.append(static_cast<char>(0xFF));
    const QString uri = QStringLiteral("tt://?")
            + QString::fromLatin1(p.toBase64(QByteArray::Base64UrlEncoding
                                             | QByteArray::OmitTrailingEquals));
    QString err;
    QVERIFY(!parseDeepLink(uri, &err).has_value());
    QVERIFY(!err.isEmpty());
}

// rejectsOversizedTlvLength above uses a length above INT_MAX, which the first
// guard in tlvLengthFits() catches. The third guard — a length that is a
// perfectly ordinary int but reaches past the bytes actually present — had no
// test, and deleting it broke nothing. That is the truncated link: a share link
// cut short by a chat client, a copy that missed the tail.
//
// It matters beyond neatness because QByteArray::mid() silently clamps. Without
// the bounds check nothing crashes; the parser simply accepts a short value as
// though it were whole, so a link claiming a 64-byte password and carrying four
// bytes would import as a four-byte password and connect with it.
void TestDeepLink::rejectsATlvLengthPastTheEndOfThePayload()
{
    QByteArray p;
    auto tlv = [&](char tag, const QByteArray &v) {
        p.append(tag);
        p.append(static_cast<char>(v.size()));
        p.append(v);
    };
    tlv(0x01, "host.tld");
    tlv(0x02, "10.0.0.1:8443");
    tlv(0x05, "alice");
    // Declares 32 bytes of password and then stops after four.
    p.append(static_cast<char>(0x06));
    p.append(static_cast<char>(32));
    p.append("word");

    const QString uri = QStringLiteral("tt://?")
            + QString::fromLatin1(p.toBase64(QByteArray::Base64UrlEncoding
                                             | QByteArray::OmitTrailingEquals));
    QString err;
    const auto out = parseDeepLink(uri, &err);
    QVERIFY2(!out.has_value(),
             "a TLV reaching past the end of the payload must be refused, not silently "
             "truncated to whatever bytes happen to be there");
    QVERIFY(!err.isEmpty());
}

void TestDeepLink::acceptsTrustTunnelQrFragment()
{
    DeepLinkConfig in;
    in.hostname = "vpn.example.com";
    in.addresses = {"1.2.3.4:443"};
    in.username = "user";
    in.password = "pass";
    const QString uri = encodeDeepLink(in);
    const QString payload = uri.mid(QStringLiteral("tt://?").size());
    const QString qr = QStringLiteral("https://trusttunnel.org/qr.html#tt=") + payload;
    QString err;
    auto out = parseDeepLink(qr, &err);
    QVERIFY2(out.has_value(), qPrintable(err));
    QCOMPARE(out->hostname, in.hostname);
}

QTEST_MAIN(TestDeepLink)
#include "test_deeplink.moc"
