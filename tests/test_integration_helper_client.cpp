// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTcpSocket>

#include <QJsonArray>
#include <QScopeGuard>
#include <QSignalSpy>
#include <QStringList>
#include <QTcpServer>

#include <string>
#include <vector>

#include "helper_ipc_mock_server.h"
#include "vpn/vpn_helper_client.h"
#include "vpn/vpn_helper_launch.h"
#include "vpn/vpn_helper_protocol.h"

namespace {

QStringList jsonStringArray(const QJsonObject &obj, const char *key)
{
    QStringList out;
    for (const QJsonValue &v : obj.value(QLatin1String(key)).toArray())
        out.append(v.toString());
    return out;
}

} // namespace

// GUI-side helper IPC client (no elevated process): mirrors VpnHelperClient handshake.
class TestIntegrationHelperClient : public QObject {
    Q_OBJECT

private slots:
    void clientHandshakeAndConnectFlow();
    void realClientRefusesPeerThatCannotProveTheToken();
    void realClientRefusesPeerThatSkipsTheChallenge();
    void realClientRefusesAChallengeCarryingNoNonce();
    void securitySettingsAreSentAsValuesNotJustCommandNames();
    void theElevatedArgvComesFromItsArgumentsAndNotTheEnvironment();
};

// linuxHelperCommand() builds the argv pkexec is asked to run AS ROOT, and until
// now it was file-local in vpn_helper_client.cpp with no test anywhere — the one
// function in this codebase whose output is executed with full privilege, and the
// only one nothing checked.
//
// docs/security-threats.md describes the bug this shape exists to prevent, and it
// is worth restating because it was real: naming the AppImage from $APPIMAGE and
// validating it against $APPDIR is not validation, since an attacker who can set
// the GUI's environment sets both sides — and $APPDIR only had to be a path
// prefix, so APPDIR=/usr passed for an ordinary /usr/bin/FreeTunnel install and
// $APPIMAGE was then run as root. The answer is that the path arrives as an
// argument, from the kernel via runningAppImagePath(), and this function reads no
// environment at all.
void TestIntegrationHelperClient::theElevatedArgvComesFromItsArgumentsAndNotTheEnvironment()
{
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN)
    QSKIP("linuxHelperCommand() is the Linux elevation path");
#else
    const QString exe = QStringLiteral("/usr/bin/FreeTunnel");
    const QString tokenPath = QStringLiteral("/run/user/1000/ft.token");

    // An AppImage build re-execs the .AppImage file, because the running
    // executable sits in a FUSE mount root cannot read.
    const QStringList viaAppImage = freetunnel::linuxHelperCommand(
            exe, QStringLiteral("/home/u/FreeTunnel.AppImage"), 51820, tokenPath);
    const QStringList expectedAppImage{QStringLiteral("env"),
                                       QStringLiteral("APPIMAGE_EXTRACT_AND_RUN=1"),
                                       QStringLiteral("/home/u/FreeTunnel.AppImage"),
                                       QStringLiteral("--helper"),
                                       QStringLiteral("--port"),
                                       QStringLiteral("51820"),
                                       QStringLiteral("--token-file"),
                                       tokenPath};
    QCOMPARE(viaAppImage, expectedAppImage);

    // An ordinary install re-execs itself and gains no env wrapper.
    const QStringList viaExe = freetunnel::linuxHelperCommand(exe, QString(), 51820, tokenPath);
    const QStringList expectedExe{QStringLiteral("/usr/bin/FreeTunnel"),
                                  QStringLiteral("--helper"),
                                  QStringLiteral("--port"),
                                  QStringLiteral("51820"),
                                  QStringLiteral("--token-file"),
                                  tokenPath};
    QCOMPARE(viaExe, expectedExe);

    // The point of the whole arrangement: a hostile environment changes nothing.
    // Both variables are set to paths an attacker would want root to run, and the
    // argv must be byte-for-byte what it was above.
    const QByteArray oldAppImage = qgetenv("APPIMAGE");
    const QByteArray oldAppDir = qgetenv("APPDIR");
    qputenv("APPIMAGE", "/tmp/evil.AppImage");
    qputenv("APPDIR", "/usr");
    const auto restore = qScopeGuard([&] {
        if (oldAppImage.isEmpty()) qunsetenv("APPIMAGE"); else qputenv("APPIMAGE", oldAppImage);
        if (oldAppDir.isEmpty()) qunsetenv("APPDIR"); else qputenv("APPDIR", oldAppDir);
    });

    QCOMPARE(freetunnel::linuxHelperCommand(exe, QString(), 51820, tokenPath), expectedExe);
    QCOMPARE(freetunnel::linuxHelperCommand(exe, QStringLiteral("/home/u/FreeTunnel.AppImage"),
                                            51820, tokenPath),
             expectedAppImage);
    for (const QStringList &cmd : {viaExe, expectedAppImage}) {
        for (const QString &arg : cmd)
            QVERIFY2(!arg.contains(QStringLiteral("evil")),
                     "the elevated argv must never pick anything up from the environment");
    }
#endif
}

void TestIntegrationHelperClient::clientHandshakeAndConnectFlow()
{
    const QString token = QStringLiteral("client-integration-token");
    MockHelperServer server(token);
    QVERIFY(server.listen());

    QTcpSocket sock;
    sock.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), server.port());
    QVERIFY(sock.waitForConnected(3000));
    server.acceptPending();

    QVERIFY(mockHelperHandshake(server, sock, token));
    QJsonObject hello;
    hello[QStringLiteral("cmd")] = QStringLiteral("noop");
    sock.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(server.waitForClientData(3000));
    QVERIFY(server.authed());

    QJsonObject setMode;
    setMode[QStringLiteral("cmd")] = QStringLiteral("setMode");
    setMode[QStringLiteral("selective")] = false;
    sock.write(QJsonDocument(setMode).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(server.waitForClientData(1000));
    QCOMPARE(server.lastCmd(), QStringLiteral("setMode"));

    QJsonObject connectCmd;
    connectCmd[QStringLiteral("cmd")] = QStringLiteral("connect");
    connectCmd[QStringLiteral("configPath")] = QStringLiteral("/tmp/test.toml");
    sock.write(QJsonDocument(connectCmd).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(server.waitForClientData(3000));
    QCOMPARE(server.lastCmd(), QStringLiteral("connect"));

    QString lastState;
    for (int i = 0; i < 6 && lastState != QLatin1String("Connected"); ++i) {
        if (sock.bytesAvailable() == 0 && !sock.waitForReadyRead(3000))
            break;
        while (sock.canReadLine()) {
            const auto doc = QJsonDocument::fromJson(sock.readLine());
            if (!doc.isObject())
                continue;
            const QJsonObject ev = doc.object();
            if (ev.value(QStringLiteral("ev")).toString() == QLatin1String("state"))
                lastState = ev.value(QStringLiteral("state")).toString();
        }
    }
    QCOMPARE(lastState, QStringLiteral("Connected"));

    QJsonObject disconnectCmd;
    disconnectCmd[QStringLiteral("cmd")] = QStringLiteral("disconnect");
    sock.write(QJsonDocument(disconnectCmd).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(server.waitForClientData(3000));
    QCOMPARE(server.lastCmd(), QStringLiteral("disconnect"));
}

// The helper only starts listening after the elevation prompt is answered, so a
// local process can own that port in the meantime. It must not be able to talk
// the GUI into handing over the config: that payload carries the VPN password,
// and an answer of "Connected" from it would show a protected tunnel where there
// is none. Drive the REAL VpnHelperClient against a peer that cannot produce the
// proof and assert it never sends anything sensitive.
void TestIntegrationHelperClient::realClientRefusesPeerThatCannotProveTheToken()
{
    QTcpServer rogue;
    QVERIFY(rogue.listen(QHostAddress(QStringLiteral("127.0.0.1")), 0));

    QByteArray received;
    QTcpSocket *peer = nullptr;
    connect(&rogue, &QTcpServer::newConnection, this, [&]() {
        peer = rogue.nextPendingConnection();
        connect(peer, &QTcpSocket::readyRead, this, [&]() {
            received += peer->readAll();
            // Answer the hello like a helper would, but with a proof we cannot
            // actually compute — we do not know the token.
            if (received.contains("\"cmd\":\"hello\"")) {
                QJsonObject ch;
                ch[QStringLiteral("ev")] = QStringLiteral("challenge");
                ch[QStringLiteral("proof")] = QString(64, QLatin1Char('0'));
                ch[QStringLiteral("nonce")] = QStringLiteral("rogue-nonce");
                peer->write(QJsonDocument(ch).toJson(QJsonDocument::Compact) + '\n');
                peer->flush();
            }
        });
    });

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(rogue.serverPort()));
    qputenv("FT_TEST_HELPER_TOKEN", "the-real-token");

    VpnHelperClient client;
    QSignalSpy errors(&client, &VpnHelperClient::vpnError);
    client.loadConfigFromToml(QStringLiteral("password = \"super-secret\"\n"));
    client.connectVpn();

    QTRY_VERIFY_WITH_TIMEOUT(!errors.isEmpty(), 5000);
    // Guard against passing for the wrong reason: the negative assertions below
    // are only meaningful if the client actually reached this peer and opened
    // the handshake with it.
    QVERIFY(received.contains("\"cmd\":\"hello\""));
    QVERIFY(!received.contains("super-secret"));
    QVERIFY(!received.contains("\"cmd\":\"auth\""));
    QVERIFY(!received.contains("\"cmd\":\"connect\""));

    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
}

// The sibling above gives a wrong proof. This one gives a RIGHT proof and no
// nonce, which is the more interesting case: the peer has satisfied the only
// check most readers think about, and the client still has to refuse — with no
// server nonce there is nothing for its own proof to answer, so whatever it
// sent back would be a constant a listener could replay.
//
// Found by mutation: deleting the empty-nonce check broke nothing in the suite.
void TestIntegrationHelperClient::realClientRefusesAChallengeCarryingNoNonce()
{
    const QString token = QStringLiteral("no-nonce-challenge-token");

    QTcpServer rogue;
    QVERIFY(rogue.listen(QHostAddress(QStringLiteral("127.0.0.1")), 0));

    QByteArray received;
    QTcpSocket *peer = nullptr;
    connect(&rogue, &QTcpServer::newConnection, this, [&]() {
        peer = rogue.nextPendingConnection();
        connect(peer, &QTcpSocket::readyRead, this, [&]() {
            received += peer->readAll();
            const int nl = received.indexOf('\n');
            if (nl < 0 || !received.contains("\"cmd\":\"hello\""))
                return;
            const QJsonObject hello =
                    QJsonDocument::fromJson(received.left(nl)).object();
            QJsonObject ch;
            ch[QStringLiteral("ev")] = QStringLiteral("challenge");
            // A genuine proof: this peer really does hold the token.
            ch[QStringLiteral("proof")] = vpn_helper::authProof(
                    token, QString::fromLatin1(vpn_helper::kHelperRole),
                    hello.value(QStringLiteral("nonce")).toString());
            ch[QStringLiteral("nonce")] = QString();  // ... but no nonce of its own
            peer->write(QJsonDocument(ch).toJson(QJsonDocument::Compact) + '\n');
            peer->flush();
        });
    });

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(rogue.serverPort()));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    VpnHelperClient client;
    QSignalSpy errors(&client, &VpnHelperClient::vpnError);
    client.loadConfigFromToml(QStringLiteral("password = \"super-secret\"\n"));
    client.connectVpn();

    QTRY_VERIFY_WITH_TIMEOUT(!errors.isEmpty(), 5000);
    // Same guard as the sibling: the negative assertions mean nothing unless the
    // client actually talked to this peer.
    QVERIFY(received.contains("\"cmd\":\"hello\""));
    QVERIFY2(!received.contains("\"cmd\":\"auth\""),
             "the client must not answer a challenge that carries no nonce");
    QVERIFY2(!received.contains("super-secret"),
             "the config, and the VPN password in it, must never reach this peer");
    QVERIFY(!received.contains("\"cmd\":\"connect\""));

    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
}

// Verifying the challenge is not sufficient on its own: the client must also
// refuse to act on ANYTHING from a peer that never proved itself. A rogue that
// simply skipped the challenge and announced {"ev":"ready"} was handed the
// config TOML — password included — and could then report a tunnel that did not
// exist. Everything said before a peer is proven has to be inert.
void TestIntegrationHelperClient::realClientRefusesPeerThatSkipsTheChallenge()
{
    QTcpServer rogue;
    QVERIFY(rogue.listen(QHostAddress(QStringLiteral("127.0.0.1")), 0));

    QByteArray received;
    QTcpSocket *peer = nullptr;
    connect(&rogue, &QTcpServer::newConnection, this, [&]() {
        peer = rogue.nextPendingConnection();
        connect(peer, &QTcpSocket::readyRead, this, [&]() {
            const bool first = received.isEmpty();
            received += peer->readAll();
            if (first) {
                // No challenge, no proof — just claim the handshake is done.
                peer->write(QByteArrayLiteral("{\"ev\":\"ready\"}\n"));
                peer->flush();
            }
        });
    });

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(rogue.serverPort()));
    qputenv("FT_TEST_HELPER_TOKEN", "the-real-token");

    VpnHelperClient client;
    QSignalSpy errors(&client, &VpnHelperClient::vpnError);
    client.loadConfigFromToml(QStringLiteral("password = \"super-secret\"\n"));
    client.connectVpn();

    QTRY_VERIFY_WITH_TIMEOUT(!errors.isEmpty(), 5000);
    // The client did talk to this peer, so the negative assertions mean something.
    QVERIFY(received.contains("\"cmd\":\"hello\""));
    QVERIFY(!received.contains("super-secret"));
    QVERIFY(!received.contains("\"cmd\":\"connect\""));
    QVERIFY(!received.contains("\"cmd\":\"auth\""));

    // A fabricated state from it must not move the client either.
    if (peer) {
        peer->write(QByteArrayLiteral("{\"ev\":\"state\",\"state\":\"Connected\"}\n"));
        peer->flush();
    }
    QTest::qWait(200);
    QVERIFY(client.state() != VpnHelperClient::State::Connected);

    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
}

// The GUI half of the kill-switch chain: whatever Backend asks for has to leave
// this process as a JSON value the elevated helper can read back. Asserting that
// a "setKillSwitch" line was sent proves nothing — the helper reads
// c.value("enabled").toBool(), and QJsonValue::toBool() answers false for a key
// that is absent or misspelled, so a rename on either side silently disarms the
// kill switch in every session while the toggle in the GUI still reads ON.
// Assert the key is PRESENT and carries the value the caller asked for.
void TestIntegrationHelperClient::securitySettingsAreSentAsValuesNotJustCommandNames()
{
    const QString token = QStringLiteral("settings-value-token");
    MockHelperServer server(token);
    QVERIFY(server.listen());

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(server.port()));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    VpnHelperClient client;
    client.setKillSwitch(true);
    client.setVpnMode(true);
    client.setExcludedRoutes(std::vector<std::string>{"10.66.0.0/16"});
    client.setExtraExclusions(std::vector<std::string>{"intranet.example"});
    client.loadConfigFromToml(QStringLiteral("loglevel = \"warn\"\n"
                                             "[endpoint]\n"
                                             "hostname = \"vpn.example\"\n"));
    client.connectVpn();

    // The settings are pushed the moment the handshake completes, before connect.
    QTRY_VERIFY_WITH_TIMEOUT(
            !server.lastMessageFor(QStringLiteral("setKillSwitch")).isEmpty(), 10000);

    const QJsonObject killSwitch = server.lastMessageFor(QStringLiteral("setKillSwitch"));
    QVERIFY2(killSwitch.contains(QStringLiteral("enabled")),
             "setKillSwitch carried no \"enabled\" key — the helper decodes a missing key as "
             "false and turns the kill switch off without anything reporting it");
    QCOMPARE(killSwitch.value(QStringLiteral("enabled")).toBool(), true);

    const QJsonObject mode = server.lastMessageFor(QStringLiteral("setMode"));
    QVERIFY2(mode.contains(QStringLiteral("selective")), "setMode carried no \"selective\" key");
    QCOMPARE(mode.value(QStringLiteral("selective")).toBool(), true);

    QCOMPARE(jsonStringArray(server.lastMessageFor(QStringLiteral("setRoutes")), "excluded"),
             QStringList{QStringLiteral("10.66.0.0/16")});
    QCOMPARE(jsonStringArray(server.lastMessageFor(QStringLiteral("setExclusions")), "domains"),
             QStringList{QStringLiteral("intranet.example")});

    // Turning them back off must travel just as faithfully: a sender that hardcodes
    // true is exactly as broken as one that drops the value, and only this half of
    // the assertion can tell them apart.
    client.setKillSwitch(false);
    client.setVpnMode(false);
    QTRY_VERIFY_WITH_TIMEOUT(
            server.lastMessageFor(QStringLiteral("setKillSwitch"))
                    .value(QStringLiteral("enabled"))
                    .toBool()
                    == false,
            10000);
    QTRY_VERIFY_WITH_TIMEOUT(server.lastMessageFor(QStringLiteral("setMode"))
                                     .value(QStringLiteral("selective"))
                                     .toBool()
                                     == false,
                             10000);
    // Still the right key, not merely a missing one decoding to false.
    QVERIFY(server.lastMessageFor(QStringLiteral("setKillSwitch"))
                    .contains(QStringLiteral("enabled")));

    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
}

QTEST_MAIN(TestIntegrationHelperClient)
#include "test_integration_helper_client.moc"
