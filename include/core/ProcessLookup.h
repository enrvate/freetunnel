// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "core/AppRules.h"

#include <QHash>
#include <QString>
#include <QStringList>

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

// The pid recorded for a port the walk saw and could not attribute to any
// watched program. See ProcessLookup::m_owners.
constexpr qint64 kUnattributed = -1;

// Parse one /proc/net/{tcp,tcp6,udp,udp6} table. Pure, and compiled on every
// platform so the parsing can be tested where the tests actually run rather
// than only on the machine that has a /proc.
//
// `proto` is stamped onto every row because the table itself does not say which
// protocol it is — the file name does.
QList<SocketOwner> parseProcNetTable(const QString &contents, int proto);

// Resolves connections to the program that opened them.
//
// The operating system binds a socket's local port before the first packet that
// carries it can exist, and this is asked only because such a packet arrived.
// So the socket is always already in the system's tables when the question is
// put: a lookup that fails to find it has not discovered a race, it has
// discovered that our copy of those tables is older than the question. That is
// the whole design here — a miss is never accepted as an answer while a fresher
// look is affordable, and how fresh the look needs to be is decided by
// comparing timestamps, not by trusting an interval to have been long enough.
//
// Affordable is the other half. Walking every process's descriptors to find one
// socket is far too expensive to repeat per connection, but it is also far more
// than the question needs: the decision is "does this belong to a program the
// user wrote a rule about", and there are usually one or two of those. So only
// those processes are walked — see setWatchList — which is what turns a fresh
// look from something to be rationed into something to be taken every time.
class ProcessLookup {
public:
    explicit ProcessLookup(std::chrono::milliseconds ttl = std::chrono::milliseconds(1500));

    // The programs whose sockets have to be known, in the same spelling
    // appMatchesRules() takes. Every other process on the machine is skipped
    // during the walk: its connections resolve to nothing, which is already
    // what "no rule applies" looks like to the caller.
    //
    // Changing the list throws the table away. It was built to answer a
    // different question, and a program that has just been added to the rules
    // would not be in it.
    void setWatchList(const QStringList &rules);

    // The program that owns this flow's local socket, or an empty identity when
    // it is not one of the watched ones — or, on the rare occasions the system
    // will not say, when it cannot be attributed at all.
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
    // distinctPids is the number that settles a report of "my rule does
    // nothing". One means the walk can see only itself, and the fault is that
    // it cannot look at other processes. Hundreds means it can, and the rule is
    // naming something the system reports under a different path — a different
    // fix entirely.
    struct ScanReport {
        bool ok = false;      // the walk ran to completion
        int euid = -1;        // who we were while walking
        int pidsScanned = 0;
        // Of those, the ones a rule names. Counted only where the walk has to
        // decide which processes to open — on Linux, whose descriptor lists are
        // expensive enough to be worth skipping. macOS and Windows read every
        // process anyway and leave this at zero.
        int pidsWatched = 0;
        // Processes with no executable to name at all: kernel threads, which
        // have none, and processes that exited between the listing and the
        // question. Counted apart from a refusal because they are not one —
        // this machine reports 459 of them out of 767 while running as root,
        // and reading that as "459 refused" sent a real investigation looking
        // for a permissions problem that was not there.
        int pidsWithoutProgram = 0;
        int pidsSkipped = 0;  // processes the system would not describe
        int socketsSeen = 0;  // descriptors examined; 0 on Windows, which hands
                              // over a finished table instead of being walked
        int entries = 0;      // (protocol, port) -> pid pairs recorded
        int distinctPids = 0;
        int lastErrno = 0;
        // Linux only: whether the sockets came from the kernel in binary
        // (NETLINK_SOCK_DIAG) or had to be read back as text from /proc/net.
        // Worth reporting because it is the difference between a walk of about
        // one millisecond and one of nearly three, and a machine whose kernel
        // lacks the inet_diag modules is otherwise indistinguishable from a
        // slow one.
        bool netlink = false;
        // Microseconds, not milliseconds. The walk is expected to land under a
        // millisecond now that it only visits the processes a rule names, and
        // the figure is not only displayed: the rebuild budget below is derived
        // from it, so rounding it to zero would remove the budget entirely.
        qint64 elapsedUs = 0;
    };
    const ScanReport &lastScan() const { return m_report; }

    // How many times the machine has been walked since this object was made.
    //
    // The number that says whether the feature is costing anything: one walk per
    // connection means the table is answering nothing and every connection is
    // paying for a fresh one, which is what happens if the walk stops recording
    // the ports it cannot attribute. Reported alongside the scan, and the thing
    // the tests measure, because the alternative is asserting on wall-clock
    // timings that are different on every machine.
    qint64 walksTaken() const { return m_walks; }

private:
    void refreshIfStale();
    // The platform's own walk. Called with the table already emptied and the
    // report zeroed, and expected to call finishScan() before returning.
    void walk(std::chrono::steady_clock::time_point startedAt);
    // Whether to look again for a flow the table does not have. See the note at
    // the definition: the answer is yes unless the table is already newer than
    // the question, or unless looking again would spend more of this machine
    // than the feature is worth.
    bool shouldLookAgain(std::chrono::steady_clock::time_point asked) const;
    // Hand back the time that has passed since the last question, as credit
    // towards looking again. See the definition.
    void accrueLookCredit(std::chrono::steady_clock::time_point now);

    std::chrono::steady_clock::time_point m_builtAt{};
    bool m_everBuilt = false;
    std::chrono::milliseconds m_ttl;
    QStringList m_watch;
    // Microseconds of walking this object is still entitled to, and when that
    // was last worked out.
    qint64 m_credit = 0;
    qint64 m_walks = 0;
    std::chrono::steady_clock::time_point m_creditAt{};
    // (proto << 16) | port  ->  pid. Ports are unique per protocol on a host,
    // which is what makes this key enough.
    //
    // A value of kUnattributed means the walk SAW this port and established
    // that no watched program owns it. That is not the same as the port being
    // absent, and the difference is what stops the machine from being walked
    // once per connection: absent means the table is older than the socket and
    // must be rebuilt, while present-and-unattributed is a final answer for
    // every connection whose socket already existed when the walk ran. Without
    // it, a page's worth of connections from programs nobody wrote a rule about
    // would each force their own walk, and the walks that matter would be the
    // ones left without budget.
    QHash<std::uint32_t, qint64> m_owners;
    ScanReport m_report;

    // How long a table that DOES contain the flow is trusted without looking
    // again. Only a hit can be answered from an old table — see resolve().
    std::chrono::milliseconds currentTtl() const;
    // Fills the parts of the report every platform can answer, and stamps the
    // table as ready. Called at the end of each platform's walk.
    void finishScan(std::chrono::steady_clock::time_point startedAt, bool ok);
};

// The executable behind a process id, or an empty identity when the OS will not
// say — a process that exited between the table walk and this call, or one this
// user may not look at.
AppIdentity identityForPid(qint64 pid);

} // namespace freetunnel
