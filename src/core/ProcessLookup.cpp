// cppcheck-suppress-file missingIncludeSystem
#include "core/ProcessLookup.h"

#include <QDir>
#include <QtGlobal>
#include <QFile>
#include <QFileInfo>

#if defined(Q_OS_WIN)
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
    // symLinkTarget is right here, unlike for the fd links above: /proc/<pid>/exe
    // does point at a real absolute path, so there is nothing for Qt to mangle.
    const QString path = QFile::symLinkTarget(QStringLiteral("/proc/%1/exe").arg(pid));
#endif

    if (path.isEmpty())
        return {};
    AppIdentity id;
    id.executablePath = QDir::toNativeSeparators(path);
    id.name = QFileInfo(path).fileName();
    return id;
}

// ---------------------------------------------------------------------------
// ProcessLookup
// ---------------------------------------------------------------------------

ProcessLookup::ProcessLookup(std::chrono::milliseconds ttl)
    : m_ttl(ttl)
{
}

void ProcessLookup::invalidate()
{
    m_everBuilt = false;
    m_owners.clear();
    m_identities.clear();
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

void ProcessLookup::refreshIfStale()
{
    const auto now = std::chrono::steady_clock::now();
    if (m_everBuilt && now - m_builtAt < m_ttl)
        return;
    m_owners.clear();
    m_identities.clear();

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

    m_builtAt = now;
    m_everBuilt = true;
}

#elif defined(Q_OS_MACOS)

void ProcessLookup::refreshIfStale()
{
    const auto now = std::chrono::steady_clock::now();
    if (m_everBuilt && now - m_builtAt < m_ttl)
        return;
    m_owners.clear();
    m_identities.clear();

    // macOS has no socket table to read; the ports have to be gathered from
    // each process's own file descriptors. That is why this is done once per
    // TTL for every process, rather than per connection.
    int count = ::proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (count <= 0) {
        m_builtAt = now;
        m_everBuilt = true;
        return;
    }
    QByteArray pidBuf(count, Qt::Uninitialized);
    count = ::proc_listpids(PROC_ALL_PIDS, 0, pidBuf.data(), pidBuf.size());
    if (count <= 0) {
        m_builtAt = now;
        m_everBuilt = true;
        return;
    }
    const int nPids = count / static_cast<int>(sizeof(pid_t));
    const auto *pids = reinterpret_cast<const pid_t *>(pidBuf.constData());

    for (int i = 0; i < nPids; ++i) {
        const pid_t pid = pids[i];
        if (pid <= 0)
            continue;
        int bufSize = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bufSize <= 0)
            continue; // a process we may not inspect; skipping it costs us one program
        QByteArray fdBuf(bufSize, Qt::Uninitialized);
        bufSize = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdBuf.data(), fdBuf.size());
        if (bufSize <= 0)
            continue;
        const int nFds = bufSize / static_cast<int>(sizeof(proc_fdinfo));
        const auto *fds = reinterpret_cast<const proc_fdinfo *>(fdBuf.constData());
        for (int f = 0; f < nFds; ++f) {
            if (fds[f].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;
            socket_fdinfo si = {};
            // Accepts a short write rather than demanding exactly sizeof(si).
            // The kernel fills as much of the struct as its own ABI knows, and
            // an SDK newer than the kernel makes an equality check reject every
            // socket on the machine — which looks exactly like "no program owns
            // this connection" rather than like a broken scan.
            const int got = ::proc_pidfdinfo(pid, fds[f].proc_fd, PROC_PIDFDSOCKETINFO, &si,
                                             sizeof(si));
            if (got < static_cast<int>(sizeof(si.psi.soi_family) + sizeof(si.psi.soi_kind)))
                continue;
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
            m_owners.insert(ownerKey(proto, port), static_cast<qint64>(pid));
        }
    }

    if (m_owners.isEmpty()) {
        // Said once per session, not per connection: this is the difference
        // between "that program could not be identified" and "no program on
        // this machine can be", and only the second is a bug in here.
        static bool warned = false;
        if (!warned) {
            warned = true;
            qWarning("process lookup found no sockets at all — every connection will read as "
                     "unknown (scanned %d pids)",
                     nPids);
        }
    }
    m_builtAt = now;
    m_everBuilt = true;
}

#else

namespace {

// inode -> pid, by walking /proc/<pid>/fd and reading the socket: links. This
// is what `ss -p` does, and it is the expensive half of a Linux lookup, which
// is why it happens once per refresh and not once per connection.
QHash<std::uint64_t, qint64> socketInodeOwners()
{
    QHash<std::uint64_t, qint64> out;
    QDir proc(QStringLiteral("/proc"));
    const QStringList entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &entry : entries) {
        bool isPid = false;
        const qint64 pid = entry.toLongLong(&isPid);
        if (!isPid || pid <= 0)
            continue;
        QDir fdDir(QStringLiteral("/proc/%1/fd").arg(pid));
        // Not QDir::Files: these are symlinks pointing at sockets, and QDir
        // classifies a symlink by what it resolves to, so a socket link is not
        // a "file" and the filter would return nothing at all.
        const QStringList fds = fdDir.entryList(QDir::AllEntries | QDir::System | QDir::NoDotAndDotDot);
        for (const QString &fd : fds) {
            // readlink(2) rather than QFile::symLinkTarget(): a socket link
            // reads "socket:[12345]", which is not a path, and Qt helpfully
            // resolves it against the directory into
            // "/proc/<pid>/fd/socket:[12345]". Everything below then fails to
            // match, silently, and every rule stops working — which is exactly
            // what happened the first time this was written.
            const QByteArray linkPath = fdDir.filePath(fd).toLocal8Bit();
            char buf[64] = {};
            const ssize_t n = ::readlink(linkPath.constData(), buf, sizeof(buf) - 1);
            if (n <= 0)
                continue;
            const QByteArray target(buf, static_cast<int>(n));
            if (!target.startsWith("socket:[") || !target.endsWith(']'))
                continue;
            bool ok = false;
            const qulonglong inode = target.mid(8, target.size() - 9).toULongLong(&ok);
            if (ok && inode != 0)
                out.insert(inode, pid);
        }
    }
    return out;
}

} // namespace

void ProcessLookup::refreshIfStale()
{
    const auto now = std::chrono::steady_clock::now();
    if (m_everBuilt && now - m_builtAt < m_ttl)
        return;
    m_owners.clear();
    m_identities.clear();

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

    QList<SocketOwner> sockets;
    for (const Table &t : kTables) {
        QFile f(QString::fromLatin1(t.path));
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
            continue;
        sockets.append(parseProcNetTable(QString::fromLatin1(f.readAll()), t.proto));
    }
    if (!sockets.isEmpty()) {
        const QHash<std::uint64_t, qint64> byInode = socketInodeOwners();
        for (const SocketOwner &s : sockets) {
            const auto it = byInode.constFind(s.inode);
            if (it != byInode.constEnd())
                m_owners.insert(ownerKey(s.proto, s.port), it.value());
        }
    }

    m_builtAt = now;
    m_everBuilt = true;
}

#endif

AppIdentity ProcessLookup::resolve(const LocalFlow &flow)
{
    if (flow.port == 0)
        return {};
    refreshIfStale();

    auto owner = m_owners.constFind(ownerKey(flow.proto, flow.port));
    if (owner == m_owners.constEnd()) {
        // A socket opened since the last refresh is the common miss, and it is
        // the one a user is most likely to be watching — a program's very first
        // connection after launch. So a miss buys one rebuild.
        //
        // But only one per kMinRebuild: misses are not rare. Sockets we can
        // never attribute (other users' processes, the kernel's own) would
        // otherwise force a full rescan on every single connection, which on
        // Linux means walking every file descriptor of every process while a
        // connection waits on the answer.
        const auto now = std::chrono::steady_clock::now();
        static constexpr auto kMinRebuild = std::chrono::milliseconds(250);
        if (m_everBuilt && now - m_builtAt >= kMinRebuild) {
            invalidate();
            refreshIfStale();
            owner = m_owners.constFind(ownerKey(flow.proto, flow.port));
        }
        if (owner == m_owners.constEnd())
            return {};
    }

    const qint64 pid = owner.value();
    const auto cached = m_identities.constFind(pid);
    if (cached != m_identities.constEnd())
        return cached.value();
    const AppIdentity id = identityForPid(pid);
    m_identities.insert(pid, id);
    return id;
}

} // namespace freetunnel
