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
// The Linux branch. It already names /proc paths, so it is not portable to any
// other Unix, and the kernel headers below do not make it less so.
// clang-format off
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
// clang-format on
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
    const qsizetype slash = id.executablePath.lastIndexOf(QDir::separator());
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
    // Counters are per walk. They used to accumulate, which was invisible while
    // the table was rebuilt twice a minute and would be nonsense now.
    const ScanReport fresh;
    m_report = fresh;
    ++m_walks;
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
    for (const qint64 pid : m_owners) {
        if (pid != kUnattributed)
            pids.insert(pid);
    }
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
    // Windows never enumerates processes: the IP helper API hands over a
    // finished table naming the owning pid of every port on the machine. So
    // every port is attributed here, and which of them a rule names is decided
    // in resolve(), for the one port being asked about rather than for the
    // hundreds that were not.
    collectWindowsTable<MIB_TCPTABLE_OWNER_PID>(&m_owners, AF_INET, IPPROTO_TCP, true,
            [](const MIB_TCPTABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    // A row the system attributes to nobody — a connection in
                    // TIME_WAIT is reported that way — can never name a program,
                    // and recording it would displace a row that can.
                    if (row.dwOwningPid == 0)
                        continue;
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });
    collectWindowsTable<MIB_TCP6TABLE_OWNER_PID>(&m_owners, AF_INET6, IPPROTO_TCP, true,
            [](const MIB_TCP6TABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    // A row the system attributes to nobody — a connection in
                    // TIME_WAIT is reported that way — can never name a program,
                    // and recording it would displace a row that can.
                    if (row.dwOwningPid == 0)
                        continue;
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });
    collectWindowsTable<MIB_UDPTABLE_OWNER_PID>(&m_owners, AF_INET, IPPROTO_UDP, false,
            [](const MIB_UDPTABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    // A row the system attributes to nobody — a connection in
                    // TIME_WAIT is reported that way — can never name a program,
                    // and recording it would displace a row that can.
                    if (row.dwOwningPid == 0)
                        continue;
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });
    collectWindowsTable<MIB_UDP6TABLE_OWNER_PID>(&m_owners, AF_INET6, IPPROTO_UDP, false,
            [](const MIB_UDP6TABLE_OWNER_PID *t, QHash<std::uint32_t, qint64> *owners, int proto) {
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto &row = t->table[i];
                    // A row the system attributes to nobody — a connection in
                    // TIME_WAIT is reported that way — can never name a program,
                    // and recording it would displace a row that can.
                    if (row.dwOwningPid == 0)
                        continue;
                    owners->insert(ownerKey(proto, ntohs(static_cast<u_short>(row.dwLocalPort))),
                            static_cast<qint64>(row.dwOwningPid));
                }
            });

    finishScan(now, true);
}

#elif defined(Q_OS_MACOS)

void ProcessLookup::walk(std::chrono::steady_clock::time_point now)
{
    // macOS has no socket table to read; the ports have to be gathered from each
    // process's own file descriptors, and every process is read rather than only
    // the ones a rule names.
    //
    // That is deliberate, and it is the cheaper of the two here. Reading only
    // the named processes would mean asking every process for its executable
    // first, which on this platform costs about what reading its descriptors
    // costs — and it would leave the walk knowing nothing about the ports it
    // skipped. Those ports are the answer to most connections: a table that can
    // say "this port is open and belongs to nobody you named" settles them
    // outright, while a table that omits them makes each one look like a table
    // too old to trust and buy another walk.
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
    const auto *pids = reinterpret_cast<const pid_t *>(pidBuf.constData());

    for (int i = 0; i < nPids; ++i) {
        const pid_t pid = pids[i];
        if (pid <= 0)
            continue;
        ++m_report.pidsScanned;
        errno = 0;
        int bufSize = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bufSize <= 0) {
            // A process that has gone is not a process that refused. As root the
            // refusals should be none, so a count here is itself the answer to
            // why nothing matches.
            if (errno == ESRCH)
                ++m_report.pidsWithoutProgram;
            else
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
                m_owners.insert(key, static_cast<qint64>(pid));
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

// Which tables hold the sockets we can be asked about, and what protocol each
// one is. Both ways of reading them below work through this list.
struct SocketTable {
    const char *path; // /proc/net/<name>
    int family;       // AF_INET / AF_INET6
    int proto;        // IPPROTO_TCP / IPPROTO_UDP
};
constexpr SocketTable kSocketTables[] = {
        {"/proc/net/tcp", AF_INET, IPPROTO_TCP},
        {"/proc/net/tcp6", AF_INET6, IPPROTO_TCP},
        {"/proc/net/udp", AF_INET, IPPROTO_UDP},
        {"/proc/net/udp6", AF_INET6, IPPROTO_UDP},
};

// One sock_diag dump: every socket of one family and protocol, appended to out.
// Returns 0, or the error the kernel replied with.
int dumpOneFamily(int fd, const SocketTable &table, std::uint32_t seq, QByteArray *buffer,
                  QList<SocketOwner> *out)
{
    struct {
        nlmsghdr header;
        inet_diag_req_v2 request;
    } message = {};
    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    message.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    message.header.nlmsg_seq = seq;
    message.request.sdiag_family = static_cast<std::uint8_t>(table.family);
    message.request.sdiag_protocol = static_cast<std::uint8_t>(table.proto);
    // Every state, including the ones a connection passes through on its way in
    // and out. A socket in SYN_SENT is exactly the case this all exists for: the
    // program has called connect(), which is why we are being asked at all.
    message.request.idiag_states = ~0u;

    sockaddr_nl kernel = {};
    kernel.nl_family = AF_NETLINK;
    if (::sendto(fd, &message, sizeof(message), 0, reinterpret_cast<sockaddr *>(&kernel),
                 sizeof(kernel))
        < 0) {
        return errno;
    }

    for (;;) {
        errno = 0;
        // MSG_TRUNC makes the kernel report how large the datagram really was,
        // not how much of it fitted. Without it a buffer that was too small
        // would lose sockets silently, and a lost socket is a rule that does not
        // apply to one connection — the failure this whole path exists to stop.
        // The buffer is far larger than a netlink dump chunk, so this is a
        // guard, not an expectation.
        const ssize_t got = ::recv(fd, buffer->data(), buffer->size(), MSG_TRUNC);
        if (got <= 0)
            return errno != 0 ? errno : EIO;
        if (got > buffer->size())
            return EMSGSIZE;
        // Walked by hand rather than with NLMSG_OK/NLMSG_NEXT. Those macros
        // compare the kernel's unsigned length against the caller's, which the
        // client build rejects outright (-Wsign-compare -Werror), and the
        // obvious way round it — an unsigned counter — is worse than a warning:
        // NLMSG_ALIGN can round a message up past what is left, and the
        // subtraction would then wrap to an enormous value and walk off the end
        // of the buffer. Both bounds are checked here instead.
        char *cursor = buffer->data();
        ssize_t remaining = got;
        while (remaining >= static_cast<ssize_t>(sizeof(nlmsghdr))) {
            auto *header = reinterpret_cast<nlmsghdr *>(cursor);
            const ssize_t declared = static_cast<ssize_t>(header->nlmsg_len);
            if (declared < static_cast<ssize_t>(sizeof(nlmsghdr)) || declared > remaining)
                break;
            const ssize_t step = static_cast<ssize_t>(NLMSG_ALIGN(header->nlmsg_len));
            cursor += step;
            remaining = step > remaining ? 0 : remaining - step;

            // A dump abandoned earlier would leave its remaining messages in the
            // socket; they are recognised by the sequence number and dropped.
            if (header->nlmsg_seq != seq)
                continue;
            if (header->nlmsg_type == NLMSG_DONE)
                return 0;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const auto *error = static_cast<const nlmsgerr *>(NLMSG_DATA(header));
                // The kernel reports errors as negative errno. A kernel built
                // without the matching diag module answers here rather than
                // failing the send.
                return error->error < 0 ? -error->error : EIO;
            }
            const auto *entry = static_cast<const inet_diag_msg *>(NLMSG_DATA(header));
            SocketOwner owner;
            owner.port = ntohs(entry->id.idiag_sport);
            owner.proto = table.proto;
            owner.inode = entry->idiag_inode;
            if (owner.port != 0)
                out->append(owner);
        }
    }
}

// Every inet socket on the machine, asked of the kernel in binary.
//
// This is the interface `ss` uses, and it exists because the text tables in
// /proc/net make the kernel format every socket on the machine one line at a
// time. Measured here with 325 sockets open: 0.95 ms against 2.6, and the two
// agree row for row — the same inodes, protocols and ports, none missing on
// either side.
//
// They are not quite identical, and the difference runs the safe way: this
// reports a socket from the moment it is bound, while the text tables show it
// only once it is listening or connected. Nothing depends on that — a connect
// request reaches us after connect(), by which point both sources have it — but
// it is why a row-by-row comparison can differ on a machine where something
// binds a port and holds it.
//
// Returns false when the kernel will not answer, which is how one built without
// the inet_diag modules replies. The caller reads the text tables instead. It is
// all four dumps or none: a machine with tcp_diag and no udp_diag would
// otherwise answer half the question, and half an answer here means a rule that
// works for some of a program's connections.
bool socketsViaNetlink(QList<SocketOwner> *out, QByteArray *buffer, int *lastErrno)
{
#ifdef FT_ENABLE_TEST_HOOKS
    // Test-only, compiled out of release builds. Every kernel this is built and
    // tested on has the inet_diag modules, so without a way to refuse them the
    // fallback below would never run outside the machine of whoever is missing
    // them — and a path that only runs where nobody is looking is a path that
    // has already stopped working by the time it is wanted.
    if (qEnvironmentVariableIsSet("FT_TEST_NO_SOCKET_NETLINK")) {
        *lastErrno = ENOSYS;
        return false;
    }
#endif
    // Opened per walk rather than kept: measured at no cost either way, and a
    // descriptor held open for the life of the client is one the descriptor
    // watchdog would have to be told about. A failure here is also the answer
    // for a kernel built without sock_diag at all, and for a sandbox that
    // refuses AF_NETLINK.
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        *lastErrno = errno;
        return false;
    }
    QList<SocketOwner> gathered;
    std::uint32_t seq = 1;
    for (const SocketTable &table : kSocketTables) {
        const int failed = dumpOneFamily(fd, table, seq++, buffer, &gathered);
        if (failed != 0) {
            *lastErrno = failed;
            ::close(fd);
            return false;
        }
    }
    ::close(fd);
    *out = std::move(gathered);
    return true;
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
    const QList<qint64> pids = listProcessIds();
    if (pids.isEmpty()) {
        // /proc is always readable on a running Linux system, so this is the
        // walk having failed rather than the machine having no processes. Said
        // so explicitly: with the tables still recording every port it saw, a
        // silent empty listing would mark the whole machine unattributed and
        // report a healthy scan while no rule could ever match.
        m_report.lastErrno = errno;
        finishScan(now, false);
        return;
    }

    QHash<std::uint64_t, qint64> byInode;
    for (const qint64 pid : pids) {
        ++m_report.pidsScanned;
        errno = 0;
        const AppIdentity id = identityForPid(pid);
        if (id.executablePath.isEmpty()) {
            // Two different things, and telling them apart is the whole value of
            // the count. A kernel thread has no executable and never will —
            // there are hundreds of them on an ordinary desktop — while a
            // refusal means this walk cannot see the machine it is on.
            if (errno == ENOENT || errno == ESRCH)
                ++m_report.pidsWithoutProgram;
            else
                ++m_report.pidsSkipped;
            continue;
        }
        if (!appMatchesRules(id, m_watch))
            continue;
        ++m_report.pidsWatched;
        collectSocketInodes(pid, &byInode, &m_report);
    }

    // Every socket on the machine, whether or not anything watched holds it. The
    // ones nothing holds are the point: they are what lets a connection from
    // some other program be answered outright instead of buying a walk of
    // its own.
    //
    // Gathered in full every time, which is a deliberate choice rather than an
    // oversight. Remembering which port an inode had would be sound, since
    // neither changes for the life of a socket; the trap is the inodes that are
    // NOT mentioned. A socket that has been created and not yet bound appears
    // nowhere — measured against both sources — and is indistinguishable from a
    // unix or netlink socket, which will never appear. Remembering "this one has
    // no port" would therefore catch every connection whose socket was created a
    // few microseconds before a walk happened to look, and misroute it for as
    // long as it lasted — the intermittent failure this whole change exists to
    // remove, reintroduced by the optimisation meant to pay for it.
    QByteArray buffer(256 * 1024, Qt::Uninitialized);
    QList<SocketOwner> sockets;
    m_report.netlink = socketsViaNetlink(&sockets, &buffer, &m_report.lastErrno);
    if (!m_report.netlink) {
        for (const SocketTable &table : kSocketTables)
            sockets.append(parseProcNetTable(readWholeFile(table.path, &buffer), table.proto));
    }

    for (const SocketOwner &sock : sockets) {
        const std::uint32_t key = ownerKey(sock.proto, sock.port);
        const auto owner = byInode.constFind(sock.inode);
        if (owner == byInode.constEnd()) {
            // Seen, and nobody watched holds it. Recorded only if no watched
            // process has claimed this port already: one port can carry two
            // sockets — a listener and a connection accepted on it — and the
            // program that was asked about must win over the one that was not.
            if (!m_owners.contains(key))
                m_owners.insert(key, kUnattributed);
            continue;
        }
        // First one wins among watched owners, for the same reason as the macOS
        // walk above; an unattributed marker is overwritten.
        const auto claimed = m_owners.constFind(key);
        if (claimed == m_owners.constEnd() || claimed.value() == kUnattributed)
            m_owners.insert(key, owner.value());
    }

    finishScan(now, true);
}

#endif

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

    const qint64 pid = owner.value();
    // The walk saw this port and established that nobody named holds it. That is
    // an answer, not a gap, and it is the answer to most connections.
    if (pid == kUnattributed)
        return {};

    // Asked now, not remembered. A pid is only the number of a process, and
    // exec() keeps the number while replacing the program behind it — so a
    // remembered answer would name the wrong program for the whole life of
    // anything started through a wrapper that execs, in either direction: a
    // rule that silently never applies, or one program's traffic routed by
    // another program's rule. It is one system call.
    const AppIdentity id = identityForPid(pid);
    // And the filter, once, for everyone. Where the walk reads every process it
    // is this that decides; where the walk already skipped what no rule names,
    // this can only agree with it.
    return appMatchesRules(id, m_watch) ? id : AppIdentity{};
}

} // namespace freetunnel
