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

namespace {

// The lookup only walks processes a rule names, so every live test here has to
// say that this test binary is one of them — which is also the arrangement the
// application uses, rather than a test-only mode.
QStringList watchSelf()
{
    return {QDir::toNativeSeparators(
            QFileInfo(QCoreApplication::applicationFilePath()).canonicalFilePath())};
}

} // namespace

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
    void aSocketOpenedAfterTheLastWalkIsStillFound();
    void addingAProgramToTheRulesTakesEffectAtOnce();
    void withNoRulesNothingIsWalkedAtAll();
    void connectionsFromUnnamedProgramsDoNotEachBuyAWalk();
    void aBurstFromTheWatchedProgramSharesOneWalk();
    void bothWaysOfReadingTheSocketTablesAgree();
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
    lookup.setWatchList(watchSelf());
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
    lookup.setWatchList(watchSelf());
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
    lookup.setWatchList(watchSelf());
    const AppIdentity id = lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, port, QStringLiteral("127.0.0.1")});
    QVERIFY2(id.executablePath.isEmpty() && id.name.isEmpty(),
            "a closed port must not be attributed to anyone");
}

void TestProcessLookup::portZeroIsNeverLookedUp()
{
    ProcessLookup lookup;
    lookup.setWatchList(watchSelf());
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
    lookup.setWatchList(watchSelf());
    lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, server.serverPort(), QString()});

    const auto r = lookup.lastScan();
    QVERIFY2(r.ok, "the walk ran");
    QVERIFY2(r.entries > 0, "this process has a socket open, so the table cannot be empty");
    QVERIFY2(r.distinctPids >= 1, "at least this process owns something");

    // The counters have to be filled, not merely declared: a report of zeroes
    // reads as "this machine has nothing" and would send the next person
    // looking in the wrong place entirely.
    //
    // Windows is handed a finished socket table by the IP helper API and never
    // walks processes at all, so the two process counters are meaningless there.
    // entries and distinctPids above already cover what it does do.
#ifndef Q_OS_WIN
    QVERIFY2(r.pidsScanned > 1, "the walk looked at more than one process");
    QVERIFY2(r.socketsSeen > 0, "and read descriptors while doing it");
    QCOMPARE(r.euid, static_cast<int>(::geteuid()));
#endif
    // Only Linux decides which processes to open, so only there is there
    // anything to count: the pair "hundreds scanned, none watched" is what
    // distinguishes a walk that cannot see other processes from a rule that
    // names nothing running.
#ifdef Q_OS_LINUX
    QVERIFY2(r.pidsWatched >= 1, "one of them was the program the rule names");
#endif

    // Per walk, not since the beginning. These used to accumulate, which was
    // survivable while the table was rebuilt twice a minute and is not now that
    // a walk can happen on any connection: the line a person is asked to paste
    // would grow without bound and mean nothing.
    //
    // The walks are forced by asking about sockets that did not exist when the
    // last one ran, which is what a connection is. Calling invalidate() would
    // not do: it zeroes the report itself, so the counters would look fresh
    // however the walk behaved.
    const int firstScan = r.pidsScanned;
    QList<QTcpServer *> later;
    for (int i = 0; i < 3; ++i) {
        auto *fresh = new QTcpServer;
        QVERIFY(fresh->listen(QHostAddress::LocalHost, 0));
        later.append(fresh);
        QVERIFY(!lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, fresh->serverPort(), QString()})
                         .executablePath.isEmpty());
    }
    qDeleteAll(later);
    QVERIFY2(lookup.lastScan().pidsScanned < firstScan * 2 + 2,
             qPrintable(QStringLiteral("counters accumulated: %1 then %2")
                                .arg(firstScan)
                                .arg(lookup.lastScan().pidsScanned)));
}

// A page's worth of connections from programs nobody named must not each buy a
// walk of the machine. They are the overwhelming majority of what the handler
// sees, and if every one of them rebuilt the table there would be no budget
// left for the connections a rule is actually about — the intermittent failure
// this all exists to remove, returning as "it depends what else was busy".
//
// What makes them cheap is that the walk records the ports it saw and could not
// attribute, so "not one of yours" is an answer rather than a gap.
void TestProcessLookup::connectionsFromUnnamedProgramsDoNotEachBuyAWalk()
{
    ProcessLookup lookup;
    // Nothing on the list is running, so every socket below belongs to a program
    // the rules do not name — which is what every other program on a real
    // machine looks like from here.
    lookup.setWatchList({QStringLiteral("a-program-that-is-not-running")});

    QList<QTcpServer *> sockets;
    for (int i = 0; i < 40; ++i) {
        auto *s = new QTcpServer;
        QVERIFY(s->listen(QHostAddress::LocalHost, 0));
        sockets.append(s);
    }

    // One question to build a table that has seen all of them.
    lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, sockets.first()->serverPort(), QString()});
    QVERIFY(lookup.lastScan().ok);
    const qint64 before = lookup.walksTaken();

    for (QTcpServer *s : sockets) {
        QVERIFY2(lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, s->serverPort(), QString()})
                         .executablePath.isEmpty(),
                 "no rule names this program, so it must not be attributed");
    }
    const qint64 walks = lookup.walksTaken() - before;
    qDeleteAll(sockets);

    QVERIFY2(walks <= 1,
             qPrintable(QStringLiteral("%1 connections from unnamed programs cost %2 walks")
                                .arg(40)
                                .arg(walks)));
}

// The same property from the other side: connections the rules DO name, made
// before the walk, are answered by that one walk rather than each forcing
// another. This is what makes a page load affordable.
void TestProcessLookup::aBurstFromTheWatchedProgramSharesOneWalk()
{
    ProcessLookup lookup;
    lookup.setWatchList(watchSelf());

    QList<QTcpServer *> sockets;
    for (int i = 0; i < 20; ++i) {
        auto *s = new QTcpServer;
        QVERIFY(s->listen(QHostAddress::LocalHost, 0));
        sockets.append(s);
    }

    lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, sockets.first()->serverPort(), QString()});
    const qint64 before = lookup.walksTaken();
    for (QTcpServer *s : sockets) {
        QVERIFY(!lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, s->serverPort(), QString()})
                         .executablePath.isEmpty());
    }
    const qint64 walks = lookup.walksTaken() - before;
    qDeleteAll(sockets);

    QVERIFY2(walks <= 1,
             qPrintable(QStringLiteral("20 connections already open cost %1 walks").arg(walks)));
}

// The reason the rest of this exists. A table is a snapshot, and a connection is
// by definition made after the last snapshot was taken — so if a miss were
// answered from the snapshot, whether a rule applied would depend on how long
// ago some unrelated connection happened to be. That is what a person saw as
// "it works on some tabs and not others".
//
// The operating system binds the port before the packet that carries it exists,
// so the socket IS there to be found; nothing here has to wait for anything.
void TestProcessLookup::aSocketOpenedAfterTheLastWalkIsStillFound()
{
    ProcessLookup lookup;
    lookup.setWatchList(watchSelf());

    // A first question, purely so that a table exists and is as fresh as it can
    // be — this is the worst case for the old behaviour, not the best.
    QTcpServer first;
    QVERIFY(first.listen(QHostAddress::LocalHost, 0));
    lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, first.serverPort(), QString()});
    QVERIFY(lookup.lastScan().ok);

    // Now a socket that table cannot contain, asked about with no wait at all.
    QTcpServer later;
    QVERIFY(later.listen(QHostAddress::LocalHost, 0));
    const AppIdentity id =
            lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, later.serverPort(), QString()});
    QVERIFY2(!id.executablePath.isEmpty(),
             "a socket opened after the last walk must still be attributed, immediately");
}

// A rule added while the tunnel is up applies to the next connection, not the
// next session. The table only contains the programs it was told to look for,
// so a list that has changed is a table that never asked about the program the
// user has just added — and they would be left watching a rule do nothing.
void TestProcessLookup::addingAProgramToTheRulesTakesEffectAtOnce()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    const LocalFlow flow{AF_INET, IPPROTO_TCP, server.serverPort(), QString()};

    ProcessLookup lookup;
    lookup.setWatchList({QStringLiteral("some-program-that-is-not-running")});
    QVERIFY2(lookup.resolve(flow).executablePath.isEmpty(),
             "a program no rule names must not be attributed to anyone");

    lookup.setWatchList(watchSelf());
    QVERIFY2(!lookup.resolve(flow).executablePath.isEmpty(),
             "and the moment a rule names it, the very next connection sees it");
}

// Off costs nothing. With no rules there is no program to look for, so the walk
// — the expensive part, and the only part that touches the rest of the machine
// — must not happen at all.
void TestProcessLookup::withNoRulesNothingIsWalkedAtAll()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));

    ProcessLookup lookup;
    const AppIdentity id =
            lookup.resolve(LocalFlow{AF_INET, IPPROTO_TCP, server.serverPort(), QString()});
    QVERIFY(id.executablePath.isEmpty());
    QVERIFY2(!lookup.lastScan().ok, "no rules, so nothing was walked");
}

// The kernel is asked for its open sockets in binary, through the same netlink
// interface `ss` uses, and read back as text from /proc/net only where that is
// refused — a kernel built without the inet_diag modules. Both are live code,
// and the text one runs on no machine this is developed or tested on, which is
// exactly how a fallback rots unnoticed until the day it is needed.
//
// So it is run here, against the same question, and the two must agree. They
// were measured to agree row for row — same inodes, protocols and ports — but
// that was measured once, by hand; this is the part that keeps being true.
void TestProcessLookup::bothWaysOfReadingTheSocketTablesAgree()
{
#ifndef Q_OS_LINUX
    QSKIP("only Linux has two ways of reading them");
#else
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    const LocalFlow flow{AF_INET, IPPROTO_TCP, server.serverPort(), QString()};

    ProcessLookup viaNetlink;
    viaNetlink.setWatchList(watchSelf());
    const AppIdentity fromNetlink = viaNetlink.resolve(flow);
    const ProcessLookup::ScanReport netlinkScan = viaNetlink.lastScan();

    // Everything that depends on the environment happens between these two
    // lines, and the assertions come after it is restored: a QVERIFY that fails
    // inside would otherwise leave every later test reading the text tables.
    qputenv("FT_TEST_NO_SOCKET_NETLINK", "1");
    ProcessLookup viaProcNet;
    viaProcNet.setWatchList(watchSelf());
    const AppIdentity fromProcNet = viaProcNet.resolve(flow);
    const ProcessLookup::ScanReport procScan = viaProcNet.lastScan();

    // And the other half of the answer, which decides most connections: ports
    // that are open and belong to nobody named must be recorded by this path
    // too, or every such connection would buy a walk of its own.
    ProcessLookup unnamed;
    unnamed.setWatchList({QStringLiteral("a-program-that-is-not-running")});
    unnamed.resolve(flow);
    const qint64 walksBefore = unnamed.walksTaken();
    for (int i = 0; i < 5; ++i)
        unnamed.resolve(flow);
    const qint64 unnamedWalks = unnamed.walksTaken() - walksBefore;
    qunsetenv("FT_TEST_NO_SOCKET_NETLINK");

    QVERIFY2(netlinkScan.netlink, "this kernel answers sock_diag, so that is what should be used");
    QVERIFY2(!procScan.netlink, "the hook must actually have forced the text tables");
    QVERIFY2(procScan.ok, "and that path must complete");
    QVERIFY2(!fromNetlink.executablePath.isEmpty(), "the socket is open, so it must be attributed");
    QCOMPARE(fromProcNet.executablePath, fromNetlink.executablePath);
    QCOMPARE(fromProcNet.name, fromNetlink.name);
    QVERIFY2(unnamedWalks == 0,
             qPrintable(QStringLiteral("the text path cost %1 walks for ports it had already seen")
                                .arg(unnamedWalks)));
#endif
}

QTEST_MAIN(TestProcessLookup)
#include "test_processlookup.moc"
