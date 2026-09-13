// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "core/AppRules.h"

#include <QHash>
#include <QString>

#include <chrono>
#include <cstdint>

namespace freetunnel {

// One end of a connection as the VPN core describes it: the local socket the
// traffic came from. That is all we need to find the program, because the local
// port is what the operating system indexes its socket tables by.
struct LocalFlow {
    int family = 0;      // AF_INET / AF_INET6
    int proto = 0;       // IPPROTO_TCP / IPPROTO_UDP
    std::uint16_t port = 0; // local port, host byte order
    QString ip;          // local address, presentation form; may be empty
};

// A socket table entry, in the one shape the three platforms agree on.
struct SocketOwner {
    std::uint16_t port = 0;
    int proto = 0;
    qint64 pid = -1;
    std::uint64_t inode = 0; // Linux only; 0 elsewhere
};

// Parse one /proc/net/{tcp,tcp6,udp,udp6} table. Pure, and compiled on every
// platform so the parsing can be tested where the tests actually run rather
// than only on the machine that has a /proc.
//
// `proto` is stamped onto every row because the table itself does not say which
// protocol it is — the file name does.
QList<SocketOwner> parseProcNetTable(const QString &contents, int proto);

// Resolves connections to the program that opened them.
//
// Every platform answers this question by walking a table of all open sockets,
// which is far too expensive to do per connection: a busy machine has thousands
// of them, and the answer is needed while a connection is waiting to be set up.
// So the whole table is built at most once per `ttl` and served from memory in
// between. A connection that arrives just after a program started may therefore
// miss; the caller treats a miss as "no rule applies" rather than guessing.
class ProcessLookup {
public:
    explicit ProcessLookup(std::chrono::milliseconds ttl = std::chrono::milliseconds(1500));

    // The program that owns this flow's local socket, or an empty identity when
    // it cannot be attributed.
    AppIdentity resolve(const LocalFlow &flow);

    // Drop the cached table. For tests, and for reconnects, where every socket
    // the previous session saw is gone.
    void invalidate();

    // What the last scan actually saw.
    //
    // This replaces a boolean that could not fire. It asked whether the owner
    // table was empty, and the table is never empty: the helper always owns its
    // own listening socket, and a process can always inspect itself. So the one
    // state it was written to catch — "this machine reports nothing" — looked
    // identical to success, and a report of "no, that line never appeared"
    // would have meant nothing at all.
    //
    // distinctPids is the number that settles it. One means the scan saw only
    // this process, and the problem is that it cannot see others. Hundreds means
    // the table is fine and the misses are elsewhere — a port that was never in
    // it, or one that arrived after the last walk.
    struct ScanReport {
        bool ok = false;      // the walk ran to completion
        int euid = -1;        // who we were while walking
        int pidsScanned = 0;
        int pidsSkipped = 0;  // processes whose descriptors we were refused
        int socketsSeen = 0;
        int entries = 0;      // (protocol, port) -> pid pairs recorded
        int distinctPids = 0;
        int lastErrno = 0;
        qint64 elapsedMs = 0;
    };
    const ScanReport &lastScan() const { return m_report; }

private:
    void refreshIfStale();

    std::chrono::steady_clock::time_point m_builtAt{};
    bool m_everBuilt = false;
    std::chrono::milliseconds m_ttl;
    // (proto << 16) | port  ->  pid. Ports are unique per protocol on a host,
    // which is what makes this key enough.
    QHash<std::uint32_t, qint64> m_owners;
    QHash<qint64, AppIdentity> m_identities;
    ScanReport m_report;

    // Fills the parts of the report every platform can answer, and stamps the
    // table as ready. Called at the end of each platform's walk.
    // How long the built table is trusted, derived from what building it cost.
    std::chrono::milliseconds currentTtl() const;
    void finishScan(std::chrono::steady_clock::time_point startedAt, bool ok);
};

// The executable behind a process id, or an empty identity when the OS will not
// say — a process that exited between the table walk and this call, or one this
// user may not look at.
AppIdentity identityForPid(qint64 pid);

} // namespace freetunnel
