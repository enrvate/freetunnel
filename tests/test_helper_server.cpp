// cppcheck-suppress-file missingIncludeSystem
// The REAL helper server (src/vpn/vpn_helper_server.cpp) driven by the REAL GUI
// client (src/vpn/vpn_helper_client.cpp), over a real loopback socket.
//
// This is the privilege boundary: in production the server side runs as root and
// parses whatever the GUI sends. Until now it was in no test target at all — the
// helper-IPC tests drove a hand-written double whose pre-auth policy differed
// from production, so an authentication or parsing regression on the elevated
// side was invisible. Here the helper is a real child process (built against the
// mock core, so no root and no VPN core are needed).
#include <QtTest>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QHostAddress>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QProcess>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>

#include <string>
#include <vector>

#include "vpn/vpn_helper_client.h"
#include "vpn/vpn_helper_protocol.h"

namespace {

// The helper refuses to start without a readable token file, and deletes it on
// read — one file per launch.
QString writeTokenFile(const QDir &dir, const QString &name, const QString &token)
{
    const QString path = dir.filePath(name);
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return QString();
    f.write(token.toUtf8());
    f.close();
    return path;
}

// A port the kernel just handed out, which nothing can promise is still free by
// the time the helper child gets round to binding it — the probe has to let go
// before the child can take it. The gap is small but it is a real one on a busy
// runner, so startHelper() detects the loss and the caller retries on another
// port rather than spending twenty seconds failing to connect to a stranger.
quint16 freePort()
{
    QTcpServer probe;
    probe.listen(QHostAddress(QStringLiteral("127.0.0.1")), 0);
    const quint16 port = probe.serverPort();
    probe.close();
    return port;
}

// The helper's mock core (tests/mock_core) writes the config it was handed to
// FT_TEST_CORE_CONFIG_DUMP as one `key=value` record per line. It has to travel
// through a file because the helper is a separate PROCESS: its core lives on the
// far side of the privilege boundary this test exists to cross, so there is no
// in-memory double the test could interrogate instead.
QMap<QString, QString> readCoreConfigDump(const QString &path)
{
    QMap<QString, QString> out;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return out;
    const QStringList lines = QString::fromUtf8(f.readAll()).split(QLatin1Char('\n'));
    for (const QString &line : lines) {
        const int eq = line.indexOf(QLatin1Char('='));
        if (eq > 0)
            out.insert(line.left(eq), line.mid(eq + 1));
    }
    return out;
}

} // namespace

class TestHelperServer : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void init();
    void cleanup();

    void realClientCompletesHandshakeWithRealServer();
    void serverRejectsPeerWithoutTheToken();
    void serverRejectsAuthWithoutHello();
    void serverSurvivesGarbageAndOversizedInput();
    void serverDropsAPreAuthPeerThatExceedsTheLineCap();
    void serverDropsASecondHelloOnTheSameConnection();
    void serverRefusesPathBasedConnect();
    void newestConnectionCanStillAuthenticateUnderPreAuthPressure();
    void connectIgnoresAnyLogPathTheClientSends();
    void killSwitchAndSplitSettingsReachTheCoreInsideTheHelper();

private:
    bool startHelper(quint16 port, const QString &token);
    bool startHelperOnAFreePort(const QString &token, quint16 *portOut);
    void stopHelper();

    QTemporaryDir m_dir;
    QProcess *m_helper = nullptr;
    // Where the helper's core drops the config it was built with, one file per
    // launch (see readCoreConfigDump above).
    QString m_configDump;
};

void TestHelperServer::initTestCase()
{
    QVERIFY(m_dir.isValid());
    QVERIFY2(QFile::exists(QStringLiteral(FT_TEST_HELPER_BINARY)),
             "helper binary was not built next to this test");
#if defined(Q_OS_WIN)
    // runVpnHelper() refuses to start on Windows unless wintun.dll sits next to
    // the executable — a real production requirement (the core loads it to make
    // the tunnel adapter), but nothing to do with the IPC layer under test here.
    // Drop a placeholder next to the helper so the handshake and the parser get
    // exercised on Windows too; it is a build-directory artifact and is never
    // packaged.
    const QString stub = QFileInfo(QStringLiteral(FT_TEST_HELPER_BINARY)).absolutePath()
            + QStringLiteral("/wintun.dll");
    if (!QFile::exists(stub)) {
        QFile f(stub);
        QVERIFY2(f.open(QIODevice::WriteOnly), "could not place the wintun.dll placeholder");
        f.write("placeholder for tests");
        f.close();
    }
#endif
}

void TestHelperServer::init() {}

void TestHelperServer::cleanup()
{
    stopHelper();
}

bool TestHelperServer::startHelper(quint16 port, const QString &token)
{
    static int seq = 0;
    const QString tokenPath =
            writeTokenFile(QDir(m_dir.path()), QStringLiteral("token-%1").arg(++seq), token);
    if (tokenPath.isEmpty())
        return false;
    m_configDump = QDir(m_dir.path()).filePath(QStringLiteral("core-config-%1").arg(seq));

    m_helper = new QProcess(this);
    m_helper->setProcessChannelMode(QProcess::ForwardedErrorChannel);
    // The CHILD is the one that runs the privilege check, and QProcess snapshots
    // the environment at start() — setting this in the test process afterwards
    // would never reach it.
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("FT_TEST_SKIP_PRIVILEGE_CHECK"), QStringLiteral("1"));
    // Same reasoning: the config the helper's core is built with can only be seen
    // from out here if the child is told where to leave it.
    env.insert(QStringLiteral("FT_TEST_CORE_CONFIG_DUMP"), m_configDump);
    m_helper->setProcessEnvironment(env);
    m_helper->start(QStringLiteral(FT_TEST_HELPER_BINARY),
                    {QStringLiteral("--helper"), QStringLiteral("--port"),
                     QString::number(port), QStringLiteral("--token-file"), tokenPath});
    if (!m_helper->waitForStarted(5000))
        return false;

    // Wait for it to actually bind before anyone tries to connect.
    for (int i = 0; i < 100; ++i) {
        // If the child is gone, waiting the full five seconds proves nothing: it
        // either could not bind — someone took the port between freePort() and
        // now — or it died on startup. Either way the answer is already in.
        if (m_helper->state() == QProcess::NotRunning)
            return false;
        QTcpSocket probe;
        probe.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
        if (probe.waitForConnected(100)) {
            probe.abort();
            return true;
        }
        QTest::qWait(50);
    }
    return false;
}

// Start the helper on a port that is still free when it actually binds. Picking
// one and hoping is what made this suite flaky: the kernel hands out a port, the
// probe closes, and on a loaded machine something else can claim it before the
// child does.
bool TestHelperServer::startHelperOnAFreePort(const QString &token, quint16 *portOut)
{
    for (int attempt = 0; attempt < 5; ++attempt) {
        const quint16 port = freePort();
        if (startHelper(port, token)) {
            *portOut = port;
            return true;
        }
        stopHelper(); // clear the failed child before trying the next port
    }
    return false;
}

void TestHelperServer::stopHelper()
{
    if (!m_helper)
        return;
    // Ask before insisting. The helper exits through its event loop on SIGTERM,
    // which runs the tunnel teardown — and, because it only ever runs as a
    // separate process, is also the only moment gcov writes its counters. While
    // this was a straight kill(), vpn_helper_server.cpp reported 0% coverage
    // despite being one of the better-tested files here, and that zero pointed
    // effort at code which needed none.
    m_helper->terminate();
    if (!m_helper->waitForFinished(3000)) {
        m_helper->kill();
        m_helper->waitForFinished(3000);
    }
    delete m_helper;
    m_helper = nullptr;
}

// End-to-end: the production client and the production server agree on the
// mutual-auth handshake and reach a working session.
void TestHelperServer::realClientCompletesHandshakeWithRealServer()
{
    const QString token = QStringLiteral("0123456789abcdef0123456789abcdef");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(port));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    VpnHelperClient client;
    // The helper sends its "started with/without admin privileges" info line
    // immediately after "ready" — receiving it proves the whole mutual handshake
    // agreed end to end between the two production implementations.
    QSignalSpy info(&client, &VpnHelperClient::connectionInfo);
    QSignalSpy errors(&client, &VpnHelperClient::vpnError);
    QSignalSpy progress(&client, &VpnHelperClient::connectProgress);
    client.loadConfigFromToml(QStringLiteral("loglevel = \"warn\"\n"
                                             "[endpoint]\n"
                                             "hostname = \"vpn.example\"\n"));
    client.connectVpn();

    QTRY_VERIFY_WITH_TIMEOUT(info.count() > 0, 20000);
    QVERIFY(info.first().at(0).toString().contains(QStringLiteral("VPN helper started")));

    // And the config actually reached the core behind it: the wrapper reports its
    // connect progress only after the helper accepted and forwarded the command.
    QTRY_VERIFY_WITH_TIMEOUT(progress.count() > 0, 20000);
    for (const auto &e : errors)
        QVERIFY2(!e.at(0).toString().contains(QStringLiteral("authenticate")),
                 qPrintable(e.at(0).toString()));

    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
}

// A local peer that cannot prove it holds the token must never be promoted, and
// must not learn anything useful. This is the elevated side of the squatting
// scenario the handshake exists for.
void TestHelperServer::serverRejectsPeerWithoutTheToken()
{
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(QStringLiteral("the-real-token"), &port));

    QTcpSocket rogue;
    rogue.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(rogue.waitForConnected(3000));

    QJsonObject hello;
    hello[QStringLiteral("cmd")] = QStringLiteral("hello");
    hello[QStringLiteral("nonce")] = QStringLiteral("rogue-nonce");
    rogue.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    rogue.flush();
    QVERIFY(rogue.waitForReadyRead(3000));

    // The server answers with a challenge — that alone proves nothing to us, and
    // crucially the proof is not something we can forge without the token.
    const QJsonObject challenge = QJsonDocument::fromJson(rogue.readLine()).object();
    QCOMPARE(challenge.value(QStringLiteral("ev")).toString(), QStringLiteral("challenge"));
    QVERIFY(!challenge.value(QStringLiteral("nonce")).toString().isEmpty());

    QJsonObject auth;
    auth[QStringLiteral("cmd")] = QStringLiteral("auth");
    auth[QStringLiteral("proof")] = vpn_helper::authProof(
            QStringLiteral("wrong-token"), QString::fromLatin1(vpn_helper::kGuiRole),
            challenge.value(QStringLiteral("nonce")).toString());
    rogue.write(QJsonDocument(auth).toJson(QJsonDocument::Compact) + '\n');
    rogue.flush();

    // Dropped, and never told "ready".
    QVERIFY(rogue.waitForDisconnected(3000));
    QVERIFY(!rogue.readAll().contains("ready"));
}

void TestHelperServer::serverRejectsAuthWithoutHello()
{
    const QString token = QStringLiteral("token-for-skip-hello");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    QTcpSocket rogue;
    rogue.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(rogue.waitForConnected(3000));

    // Even with the correct token, an auth that skips the challenge exchange must
    // not authenticate: there is no server nonce it could be answering.
    QJsonObject auth;
    auth[QStringLiteral("cmd")] = QStringLiteral("auth");
    auth[QStringLiteral("proof")] = vpn_helper::authProof(
            token, QString::fromLatin1(vpn_helper::kGuiRole), QStringLiteral("made-up-nonce"));
    rogue.write(QJsonDocument(auth).toJson(QJsonDocument::Compact) + '\n');
    rogue.flush();

    QVERIFY(rogue.waitForDisconnected(3000));
    QVERIFY(!rogue.readAll().contains("ready"));
}

// The elevated parser must not die on hostile input — a crash here is a
// denial of service against a root process.
void TestHelperServer::serverSurvivesGarbageAndOversizedInput()
{
    const QString token = QStringLiteral("token-for-garbage");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    {
        QTcpSocket junk;
        junk.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
        QVERIFY(junk.waitForConnected(3000));
        junk.write("not-json\n{]\n42\n");
        junk.write(QByteArray(vpn_helper::kMaxIpcLineBytes + 1024, 'x'));
        junk.write("\n");
        junk.flush();
        junk.waitForDisconnected(3000);
    }

    // Still alive and still able to serve the genuine client afterwards.
    QCOMPARE(m_helper->state(), QProcess::Running);

    QTcpSocket good;
    good.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(good.waitForConnected(3000));
    QJsonObject hello;
    hello[QStringLiteral("cmd")] = QStringLiteral("hello");
    hello[QStringLiteral("nonce")] = QStringLiteral("good-nonce");
    good.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    good.flush();
    QVERIFY(good.waitForReadyRead(3000));
    QCOMPARE(QJsonDocument::fromJson(good.readLine()).object().value(QStringLiteral("ev")).toString(),
             QStringLiteral("challenge"));
}

// The cap on a pre-auth line is a documented security property — see
// docs/security-threats.md, "Pre-authentication connections are capped and
// time-limited so they cannot exhaust the root process". Nothing checked it.
//
// The garbage test above cannot: its first line is unparseable JSON, so the peer
// is already dropped for that reason before a single oversized byte is weighed,
// and its waitForDisconnected() result is never asserted on. Removing the cap
// entirely left that test green.
//
// So send nothing but bulk, and no newline: the helper cannot frame a line, and
// the only thing that can end this connection is the cap.
void TestHelperServer::serverDropsAPreAuthPeerThatExceedsTheLineCap()
{
    const QString token = QStringLiteral("token-for-line-cap");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    QTcpSocket hog;
    hog.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(hog.waitForConnected(3000));

    hog.write(QByteArray(vpn_helper::kMaxIpcLineBytes + 1024, 'x'));
    hog.flush();
    while (hog.bytesToWrite() > 0 && hog.waitForBytesWritten(3000)) { }

    // The wait is deliberately far below the helper's 5 s pre-auth deadline, and
    // that is the whole discriminating power of this test. Every pending socket
    // is dropped when the deadline fires, so a generous wait would go green
    // whether the cap exists or not — which is exactly what happened on the first
    // attempt at this test. The cap drops the peer the moment the bytes land, so
    // if this connection is still open a second later, the cap is gone.
    QElapsedTimer elapsed;
    elapsed.start();
    const bool dropped = hog.waitForDisconnected(1500);
    QVERIFY2(dropped && elapsed.elapsed() < 1500,
             qPrintable(QStringLiteral("a pre-auth peer past the line cap must be dropped "
                                       "immediately, not left to the %1 ms deadline "
                                       "(disconnected=%2 after %3 ms)")
                                .arg(5000)
                                .arg(dropped)
                                .arg(elapsed.elapsed())));

    // And the helper is still there for an honest client.
    QCOMPARE(m_helper->state(), QProcess::Running);
}

// A peer that says hello twice is either confused or probing: the second hello
// would hand it a fresh server nonce for the same socket, letting it discard a
// challenge it did not like and ask for another. The helper drops it instead.
void TestHelperServer::serverDropsASecondHelloOnTheSameConnection()
{
    const QString token = QStringLiteral("token-for-double-hello");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    QTcpSocket peer;
    peer.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(peer.waitForConnected(3000));

    QJsonObject hello;
    hello[QStringLiteral("cmd")] = QStringLiteral("hello");
    hello[QStringLiteral("nonce")] = QStringLiteral("first-nonce");
    peer.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    peer.flush();
    QVERIFY(peer.waitForReadyRead(3000));
    const QJsonObject first = QJsonDocument::fromJson(peer.readLine()).object();
    QCOMPARE(first.value(QStringLiteral("ev")).toString(), QStringLiteral("challenge"));

    hello[QStringLiteral("nonce")] = QStringLiteral("second-nonce");
    peer.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    peer.flush();

    QVERIFY2(peer.waitForDisconnected(5000),
             "a second hello on one connection must drop the peer, not re-challenge it");
    QVERIFY2(!peer.readAll().contains("challenge"),
             "the helper must not issue a second challenge on the same socket");
}

// Hardening the elevated side already relies on: a connect naming a FILE must be
// refused, because the helper would open it as root.
void TestHelperServer::serverRefusesPathBasedConnect()
{
    const QString token = QStringLiteral("token-for-path-connect");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    QTcpSocket sock;
    sock.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(sock.waitForConnected(3000));

    QJsonObject hello;
    hello[QStringLiteral("cmd")] = QStringLiteral("hello");
    hello[QStringLiteral("nonce")] = QStringLiteral("path-nonce");
    sock.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(sock.waitForReadyRead(3000));
    const QJsonObject challenge = QJsonDocument::fromJson(sock.readLine()).object();

    QJsonObject auth;
    auth[QStringLiteral("cmd")] = QStringLiteral("auth");
    auth[QStringLiteral("proof")] =
            vpn_helper::authProof(token, QString::fromLatin1(vpn_helper::kGuiRole),
                                  challenge.value(QStringLiteral("nonce")).toString());
    sock.write(QJsonDocument(auth).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(sock.waitForReadyRead(3000));
    QCOMPARE(QJsonDocument::fromJson(sock.readLine()).object().value(QStringLiteral("ev")).toString(),
             QStringLiteral("ready"));

    // configPath instead of inline configToml.
    QJsonObject connectCmd;
    connectCmd[QStringLiteral("cmd")] = QStringLiteral("connect");
    connectCmd[QStringLiteral("configPath")] = QStringLiteral("/etc/passwd");
    sock.write(QJsonDocument(connectCmd).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();

    QString errMsg;
    for (int i = 0; i < 20 && errMsg.isEmpty(); ++i) {
        if (sock.bytesAvailable() == 0 && !sock.waitForReadyRead(1000))
            break;
        while (sock.canReadLine()) {
            const QJsonObject ev = QJsonDocument::fromJson(sock.readLine()).object();
            if (ev.value(QStringLiteral("ev")).toString() == QLatin1String("error"))
                errMsg = ev.value(QStringLiteral("msg")).toString();
        }
    }
    QVERIFY(!errMsg.isEmpty());
    QVERIFY(errMsg.contains(QStringLiteral("inline"), Qt::CaseInsensitive));
}

// Idle pre-auth connections must not be able to lock the genuine client out:
// the cap evicts the oldest, so the newest arrival can always still authenticate.
void TestHelperServer::newestConnectionCanStillAuthenticateUnderPreAuthPressure()
{
    const QString token = QStringLiteral("token-under-pressure");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    std::vector<QTcpSocket *> squatters;
    for (int i = 0; i < 16; ++i) {
        auto *s = new QTcpSocket(this);
        s->connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
        s->waitForConnected(1000); // idle on purpose: never sends anything
        squatters.push_back(s);
    }

    QTcpSocket good;
    good.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(good.waitForConnected(3000));

    QJsonObject hello;
    hello[QStringLiteral("cmd")] = QStringLiteral("hello");
    hello[QStringLiteral("nonce")] = QStringLiteral("pressure-nonce");
    good.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    good.flush();
    QVERIFY2(good.waitForReadyRead(5000), "genuine client was locked out by idle pre-auth sockets");
    const QJsonObject challenge = QJsonDocument::fromJson(good.readLine()).object();
    QCOMPARE(challenge.value(QStringLiteral("ev")).toString(), QStringLiteral("challenge"));

    QJsonObject auth;
    auth[QStringLiteral("cmd")] = QStringLiteral("auth");
    auth[QStringLiteral("proof")] =
            vpn_helper::authProof(token, QString::fromLatin1(vpn_helper::kGuiRole),
                                  challenge.value(QStringLiteral("nonce")).toString());
    good.write(QJsonDocument(auth).toJson(QJsonDocument::Compact) + '\n');
    good.flush();
    QVERIFY(good.waitForReadyRead(5000));
    QCOMPARE(QJsonDocument::fromJson(good.readLine()).object().value(QStringLiteral("ev")).toString(),
             QStringLiteral("ready"));

    for (auto *s : squatters)
        s->abort();
    qDeleteAll(squatters);
}

// The core log path used to travel over IPC, and the helper creates that file —
// and its parent directory — as root. The field is gone from the protocol now,
// so a client that still sends one must have no effect whatsoever: this is the
// regression guard for the removal, not for a validator.
void TestHelperServer::connectIgnoresAnyLogPathTheClientSends()
{
    const QString token = QStringLiteral("token-for-logpath");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));

    const QString forbidden = QDir(m_dir.path()).filePath(QStringLiteral("planted/evil.log"));
    QVERIFY(!QFile::exists(forbidden));

    QTcpSocket sock;
    sock.connectToHost(QHostAddress(QStringLiteral("127.0.0.1")), port);
    QVERIFY(sock.waitForConnected(3000));

    QJsonObject hello;
    hello[QStringLiteral("cmd")] = QStringLiteral("hello");
    hello[QStringLiteral("nonce")] = QStringLiteral("logpath-nonce");
    sock.write(QJsonDocument(hello).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(sock.waitForReadyRead(3000));
    const QJsonObject challenge = QJsonDocument::fromJson(sock.readLine()).object();

    QJsonObject auth;
    auth[QStringLiteral("cmd")] = QStringLiteral("auth");
    auth[QStringLiteral("proof")] =
            vpn_helper::authProof(token, QString::fromLatin1(vpn_helper::kGuiRole),
                                  challenge.value(QStringLiteral("nonce")).toString());
    sock.write(QJsonDocument(auth).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();
    QVERIFY(sock.waitForReadyRead(3000));
    QCOMPARE(QJsonDocument::fromJson(sock.readLine()).object().value(QStringLiteral("ev")).toString(),
             QStringLiteral("ready"));

    QJsonObject connectCmd;
    connectCmd[QStringLiteral("cmd")] = QStringLiteral("connect");
    connectCmd[QStringLiteral("configToml")] = QStringLiteral("loglevel = \"warn\"\n"
                                                              "[endpoint]\n"
                                                              "hostname = \"vpn.example\"\n");
    connectCmd[QStringLiteral("loggingEnabled")] = true;
    connectCmd[QStringLiteral("logPath")] = forbidden;
    sock.write(QJsonDocument(connectCmd).toJson(QJsonDocument::Compact) + '\n');
    sock.flush();

    // Give the helper time to act on the command before concluding it did not.
    QTest::qWait(1500);
    QVERIFY2(!QFile::exists(forbidden), "helper honoured a client-supplied log path");
    QVERIFY2(!QDir(m_dir.path()).exists(QStringLiteral("planted")),
             "helper created a directory a client named");
}

// The whole kill-switch chain across the privilege boundary, in one go: the real
// GUI client encodes the setting, the real elevated server parses it, and the
// core inside that server is built with it. Every link was untested, and each one
// fails silently — the helper reads c.value("enabled").toBool(), which answers
// false for a key that is absent or spelled differently, so a rename anywhere
// along the way leaves the kill switch off in every session while the GUI toggle
// still reads ON and the entire suite stays green. The routing mode and the split
// routes ride the same path and fail the same quiet way.
void TestHelperServer::killSwitchAndSplitSettingsReachTheCoreInsideTheHelper()
{
    const QString token = QStringLiteral("token-for-core-settings");
    quint16 port = 0;
    QVERIFY(startHelperOnAFreePort(token, &port));
    QVERIFY(!QFile::exists(m_configDump));

    qputenv("FT_TEST_HELPER_PORT", QByteArray::number(port));
    qputenv("FT_TEST_HELPER_TOKEN", token.toUtf8());

    VpnHelperClient client;
    QSignalSpy errors(&client, &VpnHelperClient::vpnError);
    // Set before the handshake, exactly as Backend does at startup: the client
    // holds them and pushes them the moment the helper says it is ready.
    client.setKillSwitch(true);
    client.setVpnMode(true);
    client.setExcludedRoutes(std::vector<std::string>{"10.66.0.0/16"});
    client.setExtraExclusions(std::vector<std::string>{"intranet.example"});
    client.loadConfigFromToml(QStringLiteral("loglevel = \"warn\"\n"
                                             "[endpoint]\n"
                                             "hostname = \"vpn.example\"\n"));
    client.connectVpn();

    // The dump appears only once the helper's core client is CONSTRUCTED, so its
    // existence already proves the connect made it across.
    QTRY_VERIFY_WITH_TIMEOUT(QFile::exists(m_configDump), 20000);
    const QMap<QString, QString> cfg = readCoreConfigDump(m_configDump);

    QCOMPARE(cfg.value(QStringLiteral("killswitch_enabled")), QStringLiteral("1"));
    QCOMPARE(cfg.value(QStringLiteral("mode")), QStringLiteral("selective"));
    QCOMPARE(cfg.value(QStringLiteral("excluded_routes")), QStringLiteral("10.66.0.0/16"));
    QVERIFY2(cfg.value(QStringLiteral("exclusions")).contains(QStringLiteral("intranet.example")),
             qPrintable(cfg.value(QStringLiteral("exclusions"))));

    for (const auto &e : errors)
        QVERIFY2(!e.at(0).toString().contains(QStringLiteral("authenticate")),
                 qPrintable(e.at(0).toString()));

    qunsetenv("FT_TEST_HELPER_PORT");
    qunsetenv("FT_TEST_HELPER_TOKEN");
}

QTEST_MAIN(TestHelperServer)
#include "test_helper_server.moc"
