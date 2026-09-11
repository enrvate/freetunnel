// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include "core/ConfigToml.h"

using namespace freetunnel;

// Round-trip + key-field coverage for config TOML generation/parsing (the
// create/edit path).
class TestConfigToml : public QObject {
    Q_OBJECT

private slots:
    void roundTripKeepsWhatTheEditorDoesNotUnderstand();
    void aCertificateCannotForgeSections();
    void roundTripOfOurOwnOutputIsStable();
    void roundTrip();
    void escapesQuotes();
    void emptyCertificate();
    void defaultsProtocol();
    void boolFlagsAreLineAnchored();
    void securityFlagsDefaultClosed();
    void fieldValuesCannotInjectTomlKeys();
};

void TestConfigToml::roundTrip() {
    ConfigToml in;
    in.hostname = "vpn.example.com";
    in.addresses = "1.2.3.4:443, [2001:db8::1]:443";
    in.username = "premium";
    in.password = "s3cret";
    in.protocol = "http3";
    in.dns = "1.1.1.1, tls://8.8.8.8";
    in.customSni = "example.org";
    in.clientRandom = "deadbeef";
    in.allowIpv6 = false;
    in.skipVerification = true;
    in.antiDpi = true;
    in.certificate = "-----BEGIN-----\nabc\n-----END-----";

    const ConfigToml out = parseConfigToml(buildConfigToml(in));
    QCOMPARE(out.hostname, in.hostname);
    QCOMPARE(out.addresses, in.addresses);
    QCOMPARE(out.username, in.username);
    QCOMPARE(out.password, in.password);
    QCOMPARE(out.protocol, QStringLiteral("http3"));
    QCOMPARE(out.dns, in.dns);
    QCOMPARE(out.customSni, in.customSni);
    QCOMPARE(out.clientRandom, in.clientRandom);
    QCOMPARE(out.allowIpv6, false);
    QCOMPARE(out.skipVerification, true);
    QCOMPARE(out.antiDpi, true);
    QCOMPARE(out.certificate, in.certificate);
}

void TestConfigToml::escapesQuotes() {
    ConfigToml in;
    in.hostname = "h.example";
    in.addresses = "1.2.3.4:443";
    in.username = "u";
    in.password = "p\"a\\ss"; // quote + backslash
    const QString toml = buildConfigToml(in);
    QVERIFY(toml.contains("password = \"p\\\"a\\\\ss\""));
    QCOMPARE(parseConfigToml(toml).password, in.password);
}

void TestConfigToml::emptyCertificate() {
    ConfigToml in;
    in.hostname = "h"; in.addresses = "1.2.3.4:443"; in.username = "u"; in.password = "p";
    const QString toml = buildConfigToml(in);
    QVERIFY(toml.contains("certificate = \"\""));
    QVERIFY(parseConfigToml(toml).certificate.isEmpty());
}

void TestConfigToml::defaultsProtocol() {
    ConfigToml in;
    in.hostname = "h"; in.addresses = "1.2.3.4:443"; in.username = "u"; in.password = "p";
    in.protocol = "http2";
    QVERIFY(buildConfigToml(in).contains("upstream_protocol = \"http2\""));
    // Unknown protocol falls back to http2.
    in.protocol = "weird";
    QVERIFY(buildConfigToml(in).contains("upstream_protocol = \"http2\""));
}

void TestConfigToml::boolFlagsAreLineAnchored() {
    // A `skip_verification = true` substring sitting inside another value (e.g. a
    // pasted certificate body) must NOT flip the real flag — it's only honored
    // when it stands alone at the start of a line.
    const QString toml = QStringLiteral(
            "skip_verification = false\n"
            "has_ipv6 = true\n"
            "anti_dpi = false\n"
            "certificate = \"\"\"\n"
            "note: skip_verification = true anti_dpi = true has_ipv6 = false\n"
            "\"\"\"\n");
    const ConfigToml c = parseConfigToml(toml);
    QCOMPARE(c.skipVerification, false);
    QCOMPARE(c.antiDpi, false);
    QCOMPARE(c.allowIpv6, true);

    // And a genuine line-anchored flag is still read.
    ConfigToml on = parseConfigToml(QStringLiteral("skip_verification = true\n"));
    QCOMPARE(on.skipVerification, true);
}

// The test above always spells the flags out. What it never covers is a config
// that simply omits them, which is the common case: a minimal TOML, or one
// written by an older client. The defaults then decide, and one of them is
// security-significant — skip_verification turns off server certificate
// checking, so it has to default closed rather than open.
//
// Found by mutation: flipping that default to `true` broke nothing in the suite.
void TestConfigToml::securityFlagsDefaultClosed() {
    const ConfigToml c = parseConfigToml(QStringLiteral(
            "hostname = \"vpn.example.com\"\n"
            "username = \"u\"\n"));
    QVERIFY2(!c.skipVerification,
             "a config that does not mention skip_verification must still verify "
             "the server certificate");
    QVERIFY2(!c.antiDpi, "anti_dpi must default off");
    // Not a security flag, but the same class of silent default: IPv6 is allowed
    // unless a config says otherwise, and flipping it would black-hole v6 traffic.
    QVERIFY2(c.allowIpv6, "has_ipv6 must default on");
}

// A config is rewritten far more often than it looks: migrateConfigPassword()
// parses and rebuilds every config on import, so anything this editor has no
// field for used to be dropped the moment a config entered the app — silently,
// with the file still parsing and still connecting, just routing differently.
void TestConfigToml::roundTripKeepsWhatTheEditorDoesNotUnderstand()
{
    const QString original = QStringLiteral(
            "loglevel = \"info\"\n"
            "vpn_mode = \"general\"\n"
            "provider_quirk = 42\n"           // unknown root key
            "dns_upstreams = [\"1.1.1.1\"]\n"
            "\n[endpoint]\n"
            "hostname = \"vpn.example.com\"\n"
            "addresses = [\"1.2.3.4:443\"]\n"
            "username = \"u\"\n"
            "provider_tag = \"gold\"\n"      // unknown endpoint key
            "\n[listener.tun]\n"
            "bound_if = \"en0\"\n"
            "mtu_size = 1280\n"
            "excluded_routes = [\"10.9.0.0/16\"]\n"
            "\n[listener.socks]\n"            // a table this editor never writes
            "port = 1080\n");

    const freetunnel::ConfigToml parsed = freetunnel::parseConfigToml(original);
    QCOMPARE(parsed.hostname, QStringLiteral("vpn.example.com"));

    const QString rebuilt = freetunnel::buildConfigToml(parsed);

    // The user's routing, not our defaults.
    QVERIFY2(rebuilt.contains(QStringLiteral("mtu_size = 1280")), qPrintable(rebuilt));
    QVERIFY2(rebuilt.contains(QStringLiteral("bound_if = \"en0\"")), qPrintable(rebuilt));
    QVERIFY2(rebuilt.contains(QStringLiteral("excluded_routes = [\"10.9.0.0/16\"]")),
             qPrintable(rebuilt));
    QVERIFY2(!rebuilt.contains(QStringLiteral("192.168.0.0/16")),
             "our default routes were written over the config's own");

    // Sections and keys we have no field for.
    QVERIFY2(rebuilt.contains(QStringLiteral("[listener.socks]")), qPrintable(rebuilt));
    QVERIFY2(rebuilt.contains(QStringLiteral("port = 1080")), qPrintable(rebuilt));
    QVERIFY2(rebuilt.contains(QStringLiteral("provider_quirk = 42")), qPrintable(rebuilt));
    QVERIFY2(rebuilt.contains(QStringLiteral("provider_tag = \"gold\"")), qPrintable(rebuilt));

    // Stable: a second trip changes nothing more.
    QCOMPARE(freetunnel::buildConfigToml(freetunnel::parseConfigToml(rebuilt)), rebuilt);
}

// A certificate is the one value that can contain anything, and it is attacker
// influenced on the import path. The splitter must step over it rather than read
// its contents as structure.
void TestConfigToml::aCertificateCannotForgeSections()
{
    freetunnel::ConfigToml c;
    c.hostname = QStringLiteral("h");
    c.certificate = QStringLiteral("-----BEGIN CERTIFICATE-----\n"
                                   "[listener.tun]\n"
                                   "excluded_routes = [\"203.0.113.7/32\"]\n"
                                   "-----END CERTIFICATE-----");
    const QString built = freetunnel::buildConfigToml(c);
    const freetunnel::ConfigToml back = freetunnel::parseConfigToml(built);

    // The forged table stayed inside the certificate: it was not lifted out into
    // tunSection, and it did not become an "extra" section that we would then
    // re-emit as real structure on the next save.
    QVERIFY2(back.tunSection.contains(QStringLiteral("mtu_size")), qPrintable(back.tunSection));
    QVERIFY2(!back.tunSection.contains(QStringLiteral("203.0.113.7")), qPrintable(back.tunSection));
    QVERIFY2(!back.extraSections.contains(QStringLiteral("203.0.113.7")),
             qPrintable(back.extraSections));
    QCOMPARE(back.certificate, c.certificate);
}

// Nothing to preserve is the common case: a config this editor wrote itself must
// come back byte for byte, or every save would grow the file.
void TestConfigToml::roundTripOfOurOwnOutputIsStable()
{
    freetunnel::ConfigToml c;
    c.hostname = QStringLiteral("vpn.example.com");
    c.addresses = QStringLiteral("1.2.3.4:443");
    c.username = QStringLiteral("u");
    const QString once = freetunnel::buildConfigToml(c);
    QCOMPARE(freetunnel::buildConfigToml(freetunnel::parseConfigToml(once)), once);
}

// There are two TOML writers in this codebase with two separate escapers.
// test_deeplink's tomlInjectionStripped covers the import path
// (deepLinkConfigToToml). This is the other one — buildConfigToml, which rewrites
// the user's own config on every edit and on migrateConfigPassword — and nothing
// exercised its escaping at all. Disabling the control-character strip in
// tomlEsc() left the whole suite green.
//
// It matters because of who reads the result: the config produced here is handed
// to the elevated helper as an inline document. A newline surviving a field value
// does not corrupt a file, it adds a key — and skip_verification is one key away.
void TestConfigToml::fieldValuesCannotInjectTomlKeys() {
    ConfigToml c;
    c.hostname = QStringLiteral("h.example");
    c.addresses = QStringLiteral("1.2.3.4:443");
    c.username = QStringLiteral("u\nskip_verification = true\nx = \"");
    c.password = QStringLiteral("p\"\nanti_dpi = true\ny = \"");

    const QString toml = buildConfigToml(c, QStringLiteral("info"));

    QVERIFY2(!toml.contains(QStringLiteral("\nskip_verification = true")),
             "a newline in a field value must not open a new TOML key");
    QVERIFY2(!toml.contains(QStringLiteral("\nanti_dpi = true")),
             "a quote in a field value must not close its string and start a key");

    // The real proof is what the parser makes of it: both security flags must come
    // back at their safe defaults, not at what the injected text asked for.
    const ConfigToml back = parseConfigToml(toml);
    QVERIFY2(!back.skipVerification, "injected skip_verification survived the round trip");
    QVERIFY2(!back.antiDpi, "injected anti_dpi survived the round trip");
    QCOMPARE(back.hostname, c.hostname);
}

QTEST_MAIN(TestConfigToml)
#include "test_configtoml.moc"
