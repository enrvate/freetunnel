// cppcheck-suppress-file missingIncludeSystem
#include "core/ProcessLookup.h"

#include <QDir>
#include <QSet>

#include <algorithm>
#include <QtGlobal>

#include <cerrno>
#include <QFileInfo>

#if defined(Q_OS_WIN)
// <windows.h> defines min and max as function-like macros, so every later
// std::max(a, b) in this file becomes std::(a, b): an error reported at the use
// site with no mention of the cause, on the one platform that is not the
// development machine. NOMINMAX is the documented way to decline them, and it
// is set here rather than in the build files because the file is compiled by
// two of those and only one of them would be remembered.
#define NOMINMAX
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
// clang-format on
#elif defined(Q_OS_MACOS)
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace freetunnel {

namespace {

// ntohs is called unqualified on purpose: on Darwin it is a macro
// (__DARWIN_OSSwapInt16), and ::ntohs does not parse there.
constexpr std::uint32_t ownerKey(int proto, std::uint16_t port)
{
    return (static_cast<std::uint32_t>(proto) << 16) | port;
}

// How much of this machine walking the process table may have. A quarter of
// real time, saved up to fifty milliseconds' worth.
//
// The obvious rule — "wait four times what the last walk cost before walking
// again" — is wrong in precisely the case it exists for. Connections arrive in
// bursts: opening one page makes twenty of them in a few milliseconds, each one
// a new socket, each one needing a look that the previous connection's walk was
// too early to have taken. A gap rule refuses nineteen of those twenty. Credit
// earned while the machine was idle, which is nearly all the time, is what lets
// the burst be answered — and a program that opens connections without pause
// still cannot take more than its quarter.
constexpr qint64 kLookDutyDivisor = 4;
// Enough saved up to answer a page's worth of connections back to back, on a
// machine where a walk is slow. Anything larger buys nothing: the connections
// are set up one after another, so the wait a person would notice is the walks
// themselves, not the permission to make them.
constexpr qint64 kLookCreditCapUs = 150000;

} // namespace

// ---------------------------------------------------------------------------
// /proc/net table parsing. Pure, and built on every platform for the tests.
// ---------------------------------------------------------------------------

QList<SocketOwner> parseProcNetTable(const QString &contents, int proto)
{
    QList<SocketOwner> out;
    const QList<QStringView> lines = QStringView(contents).split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QStringView &line : lines) {
        const QList<QStringView> f = line.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        // sl local rem st tx:rx tr:tm retrnsmt uid timeout inode
        //  0     1   2  3    4     5        6   7       8     9
        if (f.size() < 10)
            continue; // the header line, and anything truncated
        const QList<QStringView> local = f[1].split(QLatin1Char(':'), Qt::SkipEmptyParts);
        if (local.size() != 2)
            continue;
        bool ok = false;
        const uint port = local[1].toUInt(&ok, 16);
        if (!ok || port == 0 || port > 0xFFFF)
            continue;
        bool inodeOk = false;
        const qulonglong inode = f[9].toULongLong(&inodeOk);
        if (!inodeOk)
            continue;

        SocketOwner owner;
        owner.port = static_cast<std::uint16_t>(port);
        owner.proto = proto;
        owner.inode = inode;
        out.append(owner);
    }
    return out;
}

// ---------------------------------------------------------------------------
// identityForPid
// ---------------------------------------------------------------------------

AppIdentity identityForPid(qint64 pid)
{
    if (pid <= 0)
        return {};

#if defined(Q_OS_WIN)
    // PROCESS_QUERY_LIMITED_INFORMATION is the weakest right that answers this,
    // and the only one a few protected system processes will grant at all.
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h == nullptr)
        return {};
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD len = static_cast<DWORD>(std::size(buf));
    const BOOL ok = ::QueryFullProcessImageNameW(h, 0, buf, &len);
    ::CloseHandle(h);
    if (!ok || len == 0)
        return {};
    const QString path = QString::fromWCharArray(buf, static_cast<int>(len));
#elif defined(Q_OS_MACOS)
    char buf[PROC_PIDPATHINFO_MAXSIZE] = {};
    const int n = ::proc_pidpath(static_cast<int>(pid), buf, sizeof(buf));
    if (n <= 0)
        return {};
    const QString path = QString::fromUtf8(buf, n);
#else
    // /proc/<pid>/exe is the kernel's own answer, which is why it is used
    // instead of /proc/<pid>/cmdline: a process can rewrite its command line,
    // and a rule that can be spoofed by the program it is meant to constrain is
    // worse than no rule.
    //
    // readlink(2) rather than QFile::symLinkTarget(), which canonicalises what
    // it reads — a stat and a path walk per process, on top of the readlink it
    // does anyway. The kernel has already resolved this link; there is nothing
    // left to canonicalise. Measured on a machine with seven hundred and fifty
    // processes, this is the difference between six milliseconds of walk and
    // under two, and the walk now happens on connections rather than on a timer.
    char buf[PATH_MAX + 1] = {};
    char procPath[64] = {};
    std::snprintf(procPath, sizeof(procPath), "/proc/%lld/exe", static_cast<long long>(pid));
    const ssize_t n = ::readlink(procPath, buf, sizeof(buf) - 1);
    if (n <= 0)
        return {};
    QString path = QString::fromLocal8Bit(buf, static_cast<int>(n));
    // The kernel marks a binary that has been replaced or removed since the
    // process started. The suffix is not part of any path and would stop the
    // rule matching, which is the opposite of what an upgraded application
    // should do to a rule about it.
    if (path.endsWith(QLatin1String(" (deleted)")))
        path.chop(10);
#endif

    if (path.isEmpty())
        return {};
    AppIdentity id;
    id.executablePath = QDir::toNativeSeparators(path);
    const int slash = id.executablePath.lastIndexOf(QDir::separator());
    id.name = slash >= 0 ? id.executablePath.mid(slash + 1) : id.executablePath;
    return id;
}

// ---------------------------------------------------------------------------
// ProcessLookup
// ---------------------------------------------------------------------------

ProcessLookup::ProcessLookup(std::chrono::milliseconds ttl)
    : m_ttl(ttl)
{
}

void ProcessLookup::setWatchList(const QStringList &rules)
{
    // Normalised once here rather than per rule per process per walk, which is
    // what appMatchesRules() would otherwise do — it takes rules in any
    // spelling, and the walk asks it about every process on the machine.
    const QStringList wanted = sanitizedAppRules(rules);
    if (m_watch == wanted)
        return;
    m_watch = wanted;
    // The table answers "which of THESE programs owns which port". A different
    // list is a different question, and the most important case is the one where
    // a program was just added: it was skipped during every previous walk, so
    // every one of its connections would be answered "not yours" from a table
    // that never looked. Comparing the lists is the whole of the bookkeeping —
    // no version counter to forget to bump.
    invalidate();
}

// The one entry point to a walk. Each platform implements walk() and nothing
// else, so the decision of WHEN to look is in a single place instead of being
// repeated, slightly differently, three times.
void ProcessLookup::refreshIfStale()
{
    const auto now = std::chrono::steady_clock::now();
    if (m_everBuilt && now - m_builtAt < currentTtl())
        return;
    m_owners.clear();
    // m_identities is NOT cleared here: each platform's walk decides what of it
    // survives, because only the platforms that enumerate processes have the
    // evidence to decide. See carryIdentitiesForward().
    //
    // Counters are per walk. They used to accumulate, which was invisible while
    // the table was rebuilt twice a minute and would be nonsense now.
    const ScanReport fresh;
    m_report = fresh;
    walk(now);
    m_credit -= m_report.elapsedUs;
}

// How long a table that contains the flow is trusted without asking again.
//
// This bounds one specific error and no other: the port was in the table, and
// the process that owned it has since let it go and another has taken it. That
// needs the operating system to work its way through an ephemeral range of some
// thirty thousand ports, so the bound can be generous. A MISS is never
// answered from here — see resolve() — because a miss has a cause we can act
// on, and this does not.
//
// Derived from what the last walk cost rather than fixed, because the fixed
// number was wrong by two orders of magnitude on a real machine: the walk took
// about 4 ms there and was trusted for 1500.
std::chrono::milliseconds ProcessLookup::currentTtl() const
{
    if (m_report.elapsedUs <= 0)
        return m_ttl;
    const auto derived = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::microseconds(m_report.elapsedUs * 20));
    return std::clamp(derived, std::chrono::milliseconds(100), m_ttl);
}

void ProcessLookup::finishScan(std::chrono::steady_clock::time_point startedAt, bool ok)
{
    const auto done = std::chrono::steady_clock::now();
    m_report.ok = ok;
#ifdef Q_OS_WIN
    m_report.euid = -1; // no such notion here
#else
    m_report.euid = static_cast<int>(::geteuid());
#endif
    m_report.entries = static_cast<int>(m_owners.size());
    QSet<qint64> pids;
    for (const qint64 pid : m_owners)
        pids.insert(pid);
    m_report.distinctPids = static_cast<int>(pids.size());
    m_report.elapsedUs =
            std::chrono::duration_cast<std::chrono::microseconds>(done - startedAt).count();
    // Stamped now rather than with the time taken before the walk: stamping
    // with the earlier value made the table count as one scan-duration old the
    // moment it was published.
    m_builtAt = done;
    m_everBuilt = ok;
}

void ProcessLookup::invalidate()
{
    m_everBuilt = false;
    m_owners.clear();
    // m_identities survives. It says which program a pid is, which no reconnect
    // and no change of rules can alter, and the next walk validates it against
    // the pids that exist then — see carryIdentitiesForward(). Dropping it here
    // would make every rule edit cost a full re-identification of the machine.
    m_report = {};
}

#if defined(Q_OS_WIN)

namespace {

// One pass over a Windows socket table. GetExtended*Table returns the whole
// table in one buffer, which is exactly the shape we want: one syscall per
// refresh rather than one per connection.
template <typename TableT, typename RowGetter>
void collectWindowsTable(QHash<std::uint32_t, qint64> *owners, ULONG af, int proto, bool tcp, RowGetter rows)
{
    ULONG size = 0;
    DWORD rc = tcp ? ::GetExtendedTcpTable(nullptr, &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0)
                   : ::GetExtendedUdpTable(nullptr, &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return;
    QByteArray buf(static_cast<int>(size), Qt::Uninitialized);
    rc = tcp ? ::GetExtendedTcpTable(buf.data(), &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0)
             : ::GetExtendedUdpTable(buf.data(), &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
    if (rc != NO_ERROR)
        return;
    rows(reinterpret_cast<const TableT *>(buf.constData()), owners, proto);
}

} // namespace

void ProcessLookup::walk(std::chrono::steady_clock::time_point now)
{
    // Windows never enumerates processes — the IP helper API hands over a
    // finished table naming the owning pid of every port — so there is no
    // listing to tell a pid that has been present all along from one that has
    // been reissued. Without that evidence the pid -> program map cannot be
    // carried over, and is emptied instead. Refilling it costs two calls per
    // connection, and only for the connections that turn out to be
    // attributable at all.
    m_identities.clear();
    m_pidWatermark = 0;

    collectWindowsTable<MIB_TCPTABLE_OWNER_PID>(&m_owners, AF_INET, IPPROTO_TCP, true,
            [](const MIB_TCPTABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });
    collectWindowsTable<MIB_TCP6TABLE_OWNER_PID>(&m_owners, AF_INET6, IPPROTO_TCP, true,
            [](const MIB_TCP6TABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });
    collectWindowsTable<MIB_UDPTABLE_OWNER_PID>(&m_owners, AF_INET, IPPROTO_UDP, false,
            [](const MIB_UDPTABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });
    collectWindowsTable<MIB_UDP6TABLE_OWNER_PID>(&m_owners, AF_INET6, IPPROTO_UDP, false,
            [](const MIB_UDP6TABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });

    finishScan(now, true);
}

#elif defined(Q_OS_MACOS)

void ProcessLookup::walk(std::chrono::steady_clock::time_point now)
{
    // macOS has no socket table to read; the ports have to be gathered from
    // each process's own file descriptors. Listing those descriptors is the
    // expensive part — a browser holds hundreds, and the call copies out every
    // one of them, sockets and files alike — so it is asked only of the
    // processes a rule actually names. Everything else costs one call to learn
    // its executable and is then left alone.
    int count = ::proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (count <= 0) {
        // Not cached: m_everBuilt stays false so the next connection tries
        // again, instead of every connection for the next TTL inheriting one
        // failed call's emptiness.
        m_report.lastErrno = errno;
        finishScan(now, false);
        return;
    }
    QByteArray pidBuf(count, Qt::Uninitialized);
    count = ::proc_listpids(PROC_ALL_PIDS, 0, pidBuf.data(), pidBuf.size());
    if (count <= 0) {
        m_report.lastErrno = errno;
        finishScan(now, false);
        return;
    }
    const int nPids = count / static_cast<int>(sizeof(pid_t));
    const auto *raw = reinterpret_cast<const pid_t *>(pidBuf.constData());
    QList<qint64> pids;
    pids.reserve(nPids);
    for (int i = 0; i < nPids; ++i) {
        if (raw[i] > 0)
            pids.append(static_cast<qint64>(raw[i]));
    }
    carryIdentitiesForward(pids);

    for (const qint64 pid64 : pids) {
        const pid_t pid = static_cast<pid_t>(pid64);
        ++m_report.pidsScanned;
        const AppIdentity id = identityFor(pid64);
        if (id.executablePath.isEmpty()) {
            // As root this should essentially never fire for a live process, so
            // a large count here is itself the answer to why nothing matches.
            ++m_report.pidsSkipped;
            continue;
        }
        if (!appMatchesRules(id, m_watch))
            continue;
        ++m_report.pidsWatched;
        int bufSize = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bufSize <= 0) {
            ++m_report.pidsSkipped;
            m_report.lastErrno = errno;
            continue;
        }
        QByteArray fdBuf(bufSize, Qt::Uninitialized);
        bufSize = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdBuf.data(), fdBuf.size());
        if (bufSize <= 0)
            continue;
        const int nFds = bufSize / static_cast<int>(sizeof(proc_fdinfo));
        const auto *fds = reinterpret_cast<const proc_fdinfo *>(fdBuf.constData());
        for (int f = 0; f < nFds; ++f) {
            if (fds[f].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;
            ++m_report.socketsSeen;
            // Over-allocated as insurance, and nothing more than that. It was
            // committed as "the macOS cause" on the theory that a kernel newer
            // than the build SDK would refuse an exact-sized buffer with ENOMEM
            // and skip every socket on the machine. The refusal mechanism is
            // real, but the premise is not: sizeof(struct socket_fdinfo) has
            // been 792 bytes at every XNU release from macOS 10.14 to now — the
            // union is sized by un_sockinfo, which has not moved — and the
            // structs sit outside any PRIVATE/KERNEL guard, so the SDK header
            // and the kernel header cannot disagree. The exact-sized version was
            // correct. This is kept because it costs nothing and removes the
            // question, not because it fixed anything.
            alignas(socket_fdinfo) char raw[sizeof(socket_fdinfo) + 1024] = {};
            const int got = ::proc_pidfdinfo(pid, fds[f].proc_fd, PROC_PIDFDSOCKETINFO, raw,
                                             static_cast<int>(sizeof(raw)));
            if (got <= 0)
                continue;
            const socket_fdinfo &si = *reinterpret_cast<const socket_fdinfo *>(raw);
            const int family = si.psi.soi_family;
            if (family != AF_INET && family != AF_INET6)
                continue;
            int proto = 0;
            std::uint16_t port = 0;
            if (si.psi.soi_kind == SOCKINFO_TCP) {
                proto = IPPROTO_TCP;
                port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
            } else if (si.psi.soi_kind == SOCKINFO_IN) {
                proto = IPPROTO_UDP;
                port = ntohs(si.psi.soi_proto.pri_in.insi_lport);
            } else {
                continue;
            }
            if (port == 0)
                continue;
            // Does not overwrite: two processes can legitimately hold the same
            // (protocol, port) — a listener and an accepted connection, or a
            // socket one of them is about to close — and letting whichever pid
            // the scan happened to reach last win makes the answer depend on
            // process enumeration order.
            const std::uint32_t key = ownerKey(proto, port);
            if (!m_owners.contains(key))
                m_owners.insert(key, pid64);
        }
    }

    finishScan(now, true);
}

#else

namespace {

// Every process on the machine, cheaply. readdir(3) rather than
// QDir::entryList(QDir::Dirs), which would stat each of the thousand-odd entries
// in /proc to establish what the name alone already says: an entry that is not a
// number is not a process.
QList<qint64> listProcessIds()
{
    QList<qint64> pids;
    DIR *proc = ::opendir("/proc");
    if (proc == nullptr)
        return pids;
    while (const dirent *entry = ::readdir(proc)) {
        char *end = nullptr;
        const long long parsed = std::strtoll(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || parsed <= 0)
            continue;
        pids.append(static_cast<qint64>(parsed));
    }
    ::closedir(proc);
    return pids;
}

// A whole /proc file in one read, into a buffer the caller reuses.
//
// QFile would do, and did, but a /proc file reports a size of zero, so Qt reads
// it in growing chunks and copies the result; with the four socket tables read
// on most walks, that is a third of the cost of reading them at all. Nothing
// here is Qt's fault — it cannot know the file is generated rather than stored.
QString readWholeFile(const char *path, QByteArray *buffer)
{
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return {};
    qint64 total = 0;
    for (;;) {
        if (total == buffer->size())
            buffer->resize(buffer->size() * 2);
        const ssize_t got = ::read(fd, buffer->data() + total, buffer->size() - total);
        if (got <= 0)
            break;
        total += got;
    }
    ::close(fd);
    return QString::fromLatin1(buffer->constData(), static_cast<int>(total));
}

// The socket inodes one process holds open, by reading its /proc/<pid>/fd
// links. This is what `ss -p` does, and it is the expensive half of a Linux
// lookup — a directory listing plus one readlink per descriptor — which is why
// it is asked only of the processes a rule names.
void collectSocketInodes(qint64 pid, QHash<std::uint64_t, qint64> *out,
                         ProcessLookup::ScanReport *report)
{
    QDir fdDir(QStringLiteral("/proc/%1/fd").arg(pid));
    // Not QDir::Files: these are symlinks pointing at sockets, and QDir
    // classifies a symlink by what it resolves to, so a socket link is not a
    // "file" and the filter would return nothing at all.
    const QStringList fds = fdDir.entryList(QDir::AllEntries | QDir::System | QDir::NoDotAndDotDot);
    for (const QString &fd : fds) {
        // readlink(2) rather than QFile::symLinkTarget(): a socket link reads
        // "socket:[12345]", which is not a path, and Qt helpfully resolves it
        // against the directory into "/proc/<pid>/fd/socket:[12345]". Everything
        // below then fails to match, silently, and every rule stops working —
        // which is exactly what happened the first time this was written.
        const QByteArray linkPath = fdDir.filePath(fd).toLocal8Bit();
        char buf[64] = {};
        const ssize_t n = ::readlink(linkPath.constData(), buf, sizeof(buf) - 1);
        if (n <= 0)
            continue;
        const QByteArray target(buf, static_cast<int>(n));
        if (!target.startsWith("socket:[") || !target.endsWith(']'))
            continue;
        ++report->socketsSeen;
        bool ok = false;
        const qulonglong inode = target.mid(8, target.size() - 9).toULongLong(&ok);
        if (ok && inode != 0)
            out->insert(inode, pid);
    }
}

} // namespace

void ProcessLookup::walk(std::chrono::steady_clock::time_point now)
{
    struct Table {
        const char *path;
        int proto;
    };
    static constexpr Table kTables[] = {
            {"/proc/net/tcp", IPPROTO_TCP},
            {"/proc/net/tcp6", IPPROTO_TCP},
            {"/proc/net/udp", IPPROTO_UDP},
            {"/proc/net/udp6", IPPROTO_UDP},
    };

    const QList<qint64> pids = listProcessIds();
    carryIdentitiesForward(pids);

    QHash<std::uint64_t, qint64> byInode;
    for (const qint64 pid : pids) {
        ++m_report.pidsScanned;
        const AppIdentity id = identityFor(pid);
        if (id.executablePath.isEmpty()) {
            // A process that exited between the listing and this line, or one
            // this user is not allowed to look at. Both are ordinary; a count in
            // the hundreds is not, and says the walk is running unprivileged.
            ++m_report.pidsSkipped;
            continue;
        }
        if (!appMatchesRules(id, m_watch))
            continue;
        ++m_report.pidsWatched;
        collectSocketInodes(pid, &byInode, &m_report);
    }

    // The tables, and only if they can matter: with no watched program running
    // there is nothing to map the inodes onto.
    //
    // This is the expensive part of a Linux walk by a wide margin — the kernel
    // formats every socket on the machine as text — and it is read in full every
    // time, which is a deliberate choice rather than an oversight. Remembering
    // which port an inode had would be sound, since neither changes for the life
    // of a socket; the trap is the inodes the tables DO NOT mention. A socket
    // that exists but is not yet connected appears in no table at all (measured:
    // neither before bind() nor after it, only once it is connected or
    // listening) and is indistinguishable from a unix or netlink socket, which
    // will never appear. Remembering "this one has no port" would therefore
    // catch every connection whose socket was created a few microseconds before
    // a walk happened to look, and misroute it for as long as it lasted — the
    // intermittent failure this whole change exists to remove, reintroduced by
    // the optimisation meant to pay for it.
    if (!byInode.isEmpty()) {
        QByteArray buffer(256 * 1024, Qt::Uninitialized);
        for (const Table &t : kTables) {
            const QList<SocketOwner> sockets = parseProcNetTable(readWholeFile(t.path, &buffer), t.proto);
            for (const SocketOwner &sock : sockets) {
                const auto it = byInode.constFind(sock.inode);
                if (it == byInode.constEnd())
                    continue;
                // First one wins, for the same reason as the macOS walk above.
                const std::uint32_t key = ownerKey(sock.proto, sock.port);
                if (!m_owners.contains(key))
                    m_owners.insert(key, it.value());
            }
        }
    }

    finishScan(now, true);
}

#endif

// Which of the previous walk's answers may be reused.
//
// A pid is not a durable name for a program. The kernel issues pids in order
// and eventually wraps, and after a wrap the same number is a different process
// — so a carried-over entry would name the wrong binary, and here that means
// routing one program's traffic by another program's rule.
//
// Two facts make the carry-over safe without asking the system anything extra.
// A pid that has been present in every listing since it was recorded cannot
// have been reissued, because being reissued requires having gone away first;
// so an entry is dropped the moment its pid is absent. And a wrap announces
// itself: pids climb, so a pid appearing for the FIRST time below the highest
// one ever issued means the counter has come round again, and the whole map is
// dropped. Both are read off the listing the walk had to make anyway — no extra
// call, and nothing here depends on how much time has passed.
void ProcessLookup::carryIdentitiesForward(const QList<qint64> &pids)
{
    qint64 highestNew = 0;
    bool wrapped = false;
    for (const qint64 pid : pids) {
        if (m_identities.contains(pid))
            continue;
        highestNew = std::max(highestNew, pid);
        if (pid < m_pidWatermark)
            wrapped = true;
    }

    if (wrapped) {
        m_identities.clear();
        // Reset to where the counter evidently is now, not to the highest pid
        // alive: long-running processes keep their high numbers from before the
        // wrap, and taking the maximum of those would report a wrap on every
        // walk from here on and disable the map for good.
        m_pidWatermark = highestNew;
        return;
    }

    const QSet<qint64> live(pids.constBegin(), pids.constEnd());
    for (auto it = m_identities.begin(); it != m_identities.end();) {
        if (live.contains(it.key()))
            ++it;
        else
            it = m_identities.erase(it);
    }
    m_pidWatermark = std::max(m_pidWatermark, highestNew);
}

AppIdentity ProcessLookup::identityFor(qint64 pid)
{
    const auto cached = m_identities.constFind(pid);
    if (cached != m_identities.constEnd())
        return cached.value();
    errno = 0;
    const AppIdentity id = identityForPid(pid);
    // Only when the system was actually asked. Reporting whatever errno happened
    // to hold after a cache hit would put a number in the diagnostic line that
    // belongs to some unrelated call, which is worse than no number at all.
    if (id.executablePath.isEmpty())
        m_report.lastErrno = errno;
    m_identities.insert(pid, id);
    return id;
}

void ProcessLookup::accrueLookCredit(std::chrono::steady_clock::time_point now)
{
    if (m_creditAt == std::chrono::steady_clock::time_point{}) {
        // The first connections of a session are the ones a person is watching,
        // so the bucket starts full rather than empty.
        m_credit = kLookCreditCapUs;
        m_creditAt = now;
        return;
    }
    const qint64 elapsedUs =
            std::chrono::duration_cast<std::chrono::microseconds>(now - m_creditAt).count();
    if (elapsedUs > 0)
        m_credit = std::min(kLookCreditCapUs, m_credit + elapsedUs / kLookDutyDivisor);
    m_creditAt = now;
}

// Whether to go and look again for a flow the table does not have.
//
// A miss is not evidence of a race. The operating system had to bind this
// socket's local port before the packet that carries it could exist, and this
// question was only asked because that packet arrived — so the socket is in the
// system's tables right now, and the only thing that can be wrong is our copy of
// them. Hence the middle test: if the table was finished AFTER the question was
// asked, it did look, the socket genuinely is not attributable, and looking a
// third time would find the same nothing. Otherwise the table simply predates
// the question and is worth rebuilding.
//
// That leaves cost as the only reason to decline, which is what the credit is.
bool ProcessLookup::shouldLookAgain(std::chrono::steady_clock::time_point asked) const
{
    if (!m_everBuilt)
        return false; // the walk we just tried did not complete; it will be retried
    if (m_builtAt >= asked)
        return false;
    return m_credit >= std::max<qint64>(m_report.elapsedUs, 0);
}

AppIdentity ProcessLookup::resolve(const LocalFlow &flow)
{
    // No rules means no watched processes, and the walk would have nothing to
    // look for. This is also what makes the feature cost nothing when it is off.
    if (flow.port == 0 || m_watch.isEmpty())
        return {};

    // Stamped first, and used twice below. This is the instant from which the
    // socket is known to exist, so it is what "fresh enough" is measured
    // against — a timestamp comparison rather than an interval anyone had to
    // guess the right length for.
    const auto asked = std::chrono::steady_clock::now();
    accrueLookCredit(asked);
    refreshIfStale();

    const std::uint32_t key = ownerKey(flow.proto, flow.port);
    auto owner = m_owners.constFind(key);
    if (owner == m_owners.constEnd() && shouldLookAgain(asked)) {
        m_everBuilt = false;
        refreshIfStale();
        owner = m_owners.constFind(key);
    }
    if (owner == m_owners.constEnd())
        return {};

    // On Windows this is where the program gets named at all: its tables say
    // which process owns a port but not what that process is, so the answer is
    // looked up for the one pid that turned out to matter rather than for the
    // hundreds that did not. Elsewhere the walk had to ask already, in order to
    // decide whether to open the process, and this reads back what it recorded.
    const qint64 pid = owner.value();
    const AppIdentity id = identityFor(pid);
    // And the filter, once, for everyone. On the platforms that walk processes
    // this can only agree with what the walk already decided; on Windows, which
    // is handed every port on the machine whether we asked or not, this IS the
    // filter — applied to the one flow being asked about rather than to the
    // hundreds of processes that were never the question.
    return appMatchesRules(id, m_watch) ? id : AppIdentity{};
}

} // namespace freetunnel
