// cppcheck-suppress-file missingIncludeSystem
// Attributing a connection to the program that opened it is the half of per-app
// split tunnelling that is different on every platform, so the important test
// here is the live one: open a real socket and ask who owns it. It runs on
// Linux, macOS and Windows and must find this very test binary. A platform
// backend that silently answers "don't know" would otherwise look exactly like
// a working one — every rule would simply never match.
#include <QtTest>

#include <QCoreApplication>
#include <QFileInfo>
#include <QTcpServer>
#include <QUdpSocket>

#include "core/ProcessLookup.h"

#ifdef Q_OS_WIN
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#endif

using freetunnel::AppIdentity;
using freetunnel::LocalFlow;
using freetunnel::ProcessLookup;

class TestProcessLookup : public QObject {
    Q_OBJECT

private slots:
    void findsTheProcessBehindARealTcpSocket();
    void findsTheProcessBehindARealUdpSocket();
    void aPortNobodyHasOpenResolvesToNothing();
    void portZeroIsNeverLookedUp();
    void parsesAProcNetTable();
    void parsesAnIpv6ProcNetTable();
    void ignoresTheHeaderAndAnythingMalformed();
    void anUnknownPidHasNoIdentity();
    void theScanReportsWhatItSaw();
};

// The whole chain, on the real operating system: a socket exists, therefore the
// lookup must name this process and the path must be this binary.
void TestProcessLookup::findsTheProcessBehindARealTcpSocket()
{
    QTcpServer server;
    QVERIFY2(server.listen(QHostAddress::LocalHost, 0), qPrintable(server.errorString()));
    const quint16 port = server.serverPort();
    QVERIFY(port != 0);

    ProcessLookup lookup;
    const AppIdentity id = lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, port, QStringLiteral("127.0.0.1")});

    QVERIFY2(!id.executablePath.isEmpty(),
            "the socket is open right now, so the platform backend must attribute it");
    const QString self = QCoreApplication::applicationFilePath();
    QCOMPARE(QFileInfo(id.executablePath).canonicalFilePath(), QFileInfo(self).canonicalFilePath());
    QCOMPARE(id.name, QFileInfo(self).fileName());
}

// UDP goes through a different table on every platform, so it is not covered by
// the TCP case. QUIC — which is what a FreeTunnel HTTP/3 config uses — is UDP.
void TestProcessLookup::findsTheProcessBehindARealUdpSocket()
{
    QUdpSocket socket;
    QVERIFY2(socket.bind(QHostAddress::LocalHost, 0), qPrintable(socket.errorString()));
    const quint16 port = socket.localPort();
    QVERIFY(port != 0);

    ProcessLookup lookup;
    const AppIdentity id = lookup.resolve(LocalFlow{AF_INET, IPPROTO_UDP, port, QStringLiteral("127.0.0.1")});

    QVERIFY2(!id.executablePath.isEmpty(), "a bound UDP socket must be attributable too");
    QCOMPARE(QFileInfo(id.executablePath).canonicalFilePath(),
            QFileInfo(QCoreApplication::applicationFilePath()).canonicalFilePath());
}

// A miss must be a miss. If an unattributable socket came back as some
// arbitrary process, a bypass rule for that process would start pulling
// unrelated traffic out of the tunnel.
void TestProcessLookup::aPortNobodyHasOpenResolvesToNothing()
{
    // Bind and release, so the port is known to have no owner at the moment we
    // ask — rather than picking a number and hoping.
    quint16 port = 0;
    {
        QTcpServer probe;
        QVERIFY(probe.listen(QHostAddress::LocalHost, 0));
        port = probe.serverPort();
    }
    QVERIFY(port != 0);

    ProcessLookup lookup;
    const AppIdentity id = lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, port, QStringLiteral("127.0.0.1")});
    QVERIFY2(id.executablePath.isEmpty() && id.name.isEmpty(),
            "a closed port must not be attributed to anyone");
}

void TestProcessLookup::portZeroIsNeverLookedUp()
{
    ProcessLookup lookup;
    const AppIdentity id = lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, 0, QString()});
    QVERIFY(id.executablePath.isEmpty());
}

// The Linux table parser, exercised on every platform: the format is a kernel
// interface, it does not change under us, and a fixture tests it where the
// tests actually run rather than only on a machine that has a /proc.
void TestProcessLookup::parsesAProcNetTable()
{
    const QString table = QStringLiteral(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41234 1 0000 100 0\n"
            "   1: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 41235 1 0000 20 4 30 10 -1\n");

    const QList<freetunnel::SocketOwner> rows = freetunnel::parseProcNetTable(table, IPPROTO_TCP);
    QCOMPARE(rows.size(), 2);
    QCOMPARE(rows[0].port, quint16(8080)); // 0x1F90
    QCOMPARE(rows[0].inode, quint64(41234));
    QCOMPARE(rows[0].proto, IPPROTO_TCP);
    QCOMPARE(rows[1].port, quint16(50000)); // 0xC350
    QCOMPARE(rows[1].inode, quint64(41235));
}

// tcp6 writes the address as 32 hex digits, so the port is not at a fixed
// offset into the field — it is whatever follows the colon.
void TestProcessLookup::parsesAnIpv6ProcNetTable()
{
    const QString table = QStringLiteral(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22 1 0000 100 0\n");

    const QList<freetunnel::SocketOwner> rows = freetunnel::parseProcNetTable(table, IPPROTO_TCP);
    QCOMPARE(rows.size(), 1);
    QCOMPARE(rows[0].port, quint16(22)); // 0x0016
    QCOMPARE(rows[0].inode, quint64(22));
}

// A parser that accepts the header line would invent a socket on some port and
// attribute it to inode 0, which resolves to nobody — harmless here, but the
// same leniency is what turns a truncated read into a wrong answer.
void TestProcessLookup::ignoresTheHeaderAndAnythingMalformed()
{
    QVERIFY(freetunnel::parseProcNetTable(QString(), IPPROTO_TCP).isEmpty());
    QVERIFY(freetunnel::parseProcNetTable(
                    QStringLiteral("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"),
                    IPPROTO_TCP)
                    .isEmpty());
    // Too few fields, no colon in the local address, and a zero port.
    QVERIFY(freetunnel::parseProcNetTable(QStringLiteral("   0: 0100007F:1F90 00000000:0000\n"), IPPROTO_TCP)
                    .isEmpty());
    QVERIFY(freetunnel::parseProcNetTable(
                    QStringLiteral("   0: nonsense 00000000:0000 0A 0:0 00:0 0 1000 0 41234 1 0000 100 0\n"),
                    IPPROTO_TCP)
                    .isEmpty());
    QVERIFY(freetunnel::parseProcNetTable(
                    QStringLiteral("   0: 0100007F:0000 00000000:0000 0A 0:0 00:0 0 1000 0 41234 1 0000 100 0\n"),
                    IPPROTO_TCP)
                    .isEmpty());
}

void TestProcessLookup::anUnknownPidHasNoIdentity()
{
    QVERIFY(freetunnel::identityForPid(-1).executablePath.isEmpty());
    QVERIFY(freetunnel::identityForPid(0).executablePath.isEmpty());
}

// The report exists because the boolean it replaced could not fire: it asked
// whether the owner table was empty, and it never is — this process always owns
// a socket and can always inspect itself. So "no sockets found" looked exactly
// like success, and asking a person whether that line appeared would have told
// us nothing either way.
void TestProcessLookup::theScanReportsWhatItSaw()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));

    ProcessLookup lookup;
    lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, server.serverPort(), QString()});

    const auto r = lookup.lastScan();
    QVERIFY2(r.ok, "the walk ran");
    QVERIFY2(r.entries > 0, "this machine has open sockets, so the table cannot be empty");
    QVERIFY2(r.distinctPids >= 1, "at least this process owns something");
    // The number the macOS investigation turns on: one means the scan can only
    // see itself, which is a different fault from a port that was never listed.
    QVERIFY2(r.distinctPids > 1,
             qPrintable(QStringLiteral("only %1 process visible — the scan cannot see others")
                                .arg(r.distinctPids)));

    // The counters have to be filled, not merely declared: a report of zeroes
    // reads as "this machine has nothing" and would send the next person
    // looking in the wrong place entirely.
    QVERIFY2(r.pidsScanned > 1, "the walk visited more than one process");
    QVERIFY2(r.socketsSeen > 0, "and saw sockets while doing it");
#ifndef Q_OS_WIN
    QCOMPARE(r.euid, static_cast<int>(::geteuid()));
#endif
}

QTEST_MAIN(TestProcessLookup)
#include "test_processlookup.moc"
