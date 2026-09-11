// cppcheck-suppress-file missingIncludeSystem
#include "vpn/vpn_helper_server.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QHostAddress>
#include <QRandomGenerator>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QStringList>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>

#include "vpn/qt_trusttunnel_client.h"
#include "vpn/vpn_helper_launch.h"
#include "vpn/vpn_helper_protocol.h"

#if defined(Q_OS_WIN)
#include <windows.h>
#else
#include <unistd.h>
#endif

#if defined(Q_OS_WIN)
static bool prepareWindowsHelperRuntime(QString *errOut)
{
    const QString dir = QCoreApplication::applicationDirPath();
    QDir::setCurrent(dir);
    SetDllDirectoryW(reinterpret_cast<LPCWSTR>(dir.utf16()));
    if (!QFile::exists(dir + QStringLiteral("/wintun.dll"))) {
        if (errOut) {
            *errOut = QObject::tr("wintun.dll is missing next to FreeTunnel.exe (%1). "
                                  "Reinstall from the official installer.")
                              .arg(dir);
        }
        return false;
    }
    return true;
}
#endif

namespace {

// Always bind/connect on IPv4 loopback — QHostAddress::LocalHost can prefer
// ::1 on some hosts while the peer listens on 127.0.0.1 only.
const QHostAddress kLoopback = QHostAddress(QStringLiteral("127.0.0.1"));

// Whether this (helper) process is actually running elevated. A failed
// "create listener" from the core almost always means it is not, so we report
// it to the GUI log to make the cause obvious.
bool helperIsElevated() {
#if defined(Q_OS_WIN)
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elev{};
    DWORD len = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &len)
            && elev.TokenIsElevated != 0;
    CloseHandle(token);
    return ok;
#else
    return ::geteuid() == 0;
#endif
}

QString stateName(QtTrustTunnelClient::State s) {
    switch (s) {
    case QtTrustTunnelClient::State::Connecting: return QStringLiteral("Connecting");
    case QtTrustTunnelClient::State::Connected: return QStringLiteral("Connected");
    case QtTrustTunnelClient::State::Reconnecting: return QStringLiteral("Reconnecting");
    case QtTrustTunnelClient::State::WaitingForNetwork: return QStringLiteral("WaitingForNetwork");
    case QtTrustTunnelClient::State::Disconnecting: return QStringLiteral("Disconnecting");
    case QtTrustTunnelClient::State::Error: return QStringLiteral("Error");
    default: return QStringLiteral("Disconnected");
    }
}

// Bridges one GUI connection to the VPN core. Quits the process when the GUI
// disconnects, so the elevated helper never lingers.
class HelperServer : public QObject {
public:
    HelperServer(quint16 port, QString token)
        : m_port(port), m_token(std::move(token)) {
        m_client.moveToThread(&m_vpnThread);
        m_vpnThread.start();
        connect(&m_client, &QtTrustTunnelClient::stateChanged, this,
                [this](QtTrustTunnelClient::State s) {
                    QJsonObject e; e["ev"] = "state"; e["state"] = stateName(s); send(e);
                }, Qt::QueuedConnection);
        connect(&m_client, &QtTrustTunnelClient::tunnelStats, this,
                [this](quint64 up, quint64 down) {
                    QJsonObject e; e["ev"] = "stats";
                    e["up"] = double(up); e["down"] = double(down); send(e);
                }, Qt::QueuedConnection);
        connect(&m_client, &QtTrustTunnelClient::connectionInfo, this,
                [this](const QString &m) { QJsonObject e; e["ev"]="info"; e["msg"]=m; send(e); },
                Qt::QueuedConnection);
        connect(&m_client, &QtTrustTunnelClient::connectProgress, this,
                [this](const QString &m) { QJsonObject e; e["ev"]="progress"; e["msg"]=m; send(e); },
                Qt::QueuedConnection);
        connect(&m_client, &QtTrustTunnelClient::coreLogLine, this,
                [this](const QString &line) {
                    QJsonObject e;
                    e["ev"] = "log";
                    e["msg"] = line;
                    send(e);
                },
                Qt::QueuedConnection);
        connect(&m_client, &QtTrustTunnelClient::vpnError, this,
                [this](const QString &m) { QJsonObject e; e["ev"]="error"; e["msg"]=m; send(e); },
                Qt::QueuedConnection);
    }

    ~HelperServer() override {
        if (m_vpnThread.isRunning()) {
            QMetaObject::invokeMethod(&m_client, "disconnectVpn", Qt::BlockingQueuedConnection);
            m_vpnThread.quit();
            m_vpnThread.wait();
        }
    }

    bool listen() {
        // Loopback TCP works across uid boundaries (GUI user ↔ elevated helper).
        // Authentication is enforced by the one-time token handshake.
        connect(&m_server, &QTcpServer::newConnection, this, &HelperServer::onConnection);
        if (m_server.listen(kLoopback, m_port))
            return true;
        qWarning("HelperServer: listen(127.0.0.1:%u) failed: %s",
                 m_port, qPrintable(m_server.errorString()));
        return false;
    }

    bool authed() const { return m_authed; }

private:
    // Unauthenticated connections never occupy the single client slot: they are
    // tracked as "pending" and only a valid token promotes one to the client
    // (closing the rest). This stops a local process that can reach the loopback
    // port — but lacks the owner-only token — from squatting the slot and
    // blocking the real GUI from ever connecting. Each pending connection is
    // also dropped after a short deadline so it can't linger.
    static constexpr int kAuthDeadlineMs = 5000;
    static constexpr int kMaxPendingConnections = 8;

    static QString randomNonce() {
        return QStringLiteral("%1%2")
                .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'))
                .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'));
    }

    void onConnection() {
        while (QTcpSocket *s = m_server.nextPendingConnection()) {
            if (m_authed) { s->close(); s->deleteLater(); continue; }
            // Pre-auth sockets are unauthenticated by definition and this is a
            // root process: without a ceiling, a local process could open
            // thousands during the (up to 60 s) elevation window and buffer
            // hundreds of MB into it until the OOM killer takes the helper.
            //
            // Evict the OLDEST rather than refusing the newest: refusing would
            // hand a squatter the very thing the pending set exists to prevent —
            // hold the cap open with idle connections and the real GUI can never
            // get in. The genuine client is always the most recent arrival.
            while (m_pendingOrder.size() >= kMaxPendingConnections) {
                QTcpSocket *oldest = m_pendingOrder.first();
                dropPending(oldest);
                m_pendingOrder.removeAll(oldest);
            }
            m_pending.insert(s);
            m_pendingOrder.append(s);
            connect(s, &QTcpSocket::readyRead, this, [this, s]() { onPendingRead(s); });
            connect(s, &QTcpSocket::disconnected, this, [this, s]() { dropPending(s); });
            // Context object = s, so the timer auto-cancels if s is destroyed first.
            QTimer::singleShot(kAuthDeadlineMs, s, [this, s]() { dropPending(s); });
        }
    }

    void dropPending(QTcpSocket *s) {
        m_pendingOrder.removeAll(s);
        if (!m_pending.remove(s))
            return;
        m_pendingBuf.remove(s);
        m_pendingNonce.remove(s);
        s->close();
        s->deleteLater();
    }

    void send(const QJsonObject &e) {
        if (m_authed && m_sock)
            m_sock->write(QJsonDocument(e).toJson(QJsonDocument::Compact) + '\n');
    }

    // Step 1 of the handshake: the GUI opens with a nonce and no secret. We answer
    // with our proof (so it can tell a real helper from whoever squatted the port)
    // plus a nonce of our own for it to answer in turn. Split out of
    // onPendingRead() so that step 1 and step 2 are each readable on their own;
    // every exit here either drops the peer or leaves it pending, never authed.
    void handleHelloLine(QTcpSocket *s, const QJsonObject &c, const QByteArray &rest) {
        const QString guiNonce = c.value("nonce").toString();
        if (guiNonce.isEmpty() || m_pendingNonce.contains(s)) {
            dropPending(s);
            return;
        }
        const QString ourNonce = randomNonce();
        m_pendingNonce.insert(s, ourNonce);
        m_pendingBuf[s] = rest;
        QJsonObject e;
        e["ev"] = "challenge";
        e["proof"] = vpn_helper::authProof(m_token, QString::fromLatin1(vpn_helper::kHelperRole),
                                           guiNonce);
        e["nonce"] = ourNonce;
        s->write(QJsonDocument(e).toJson(QJsonDocument::Compact) + '\n');
        if (!m_pendingBuf[s].isEmpty())
            onPendingRead(s); // the auth line may already be in the same burst
    }

    void onPendingRead(QTcpSocket *s) {
        if (!m_pending.contains(s))
            return;
        QByteArray &buf = m_pendingBuf[s];
        buf += s->readAll();
        if (buf.size() > vpn_helper::kMaxIpcLineBytes) {
            dropPending(s);
            return;
        }
        const int nl = buf.indexOf('\n');
        if (nl < 0)
            return; // wait for a complete line
        const QByteArray line = buf.left(nl);
        const QByteArray rest = buf.mid(nl + 1);
        const auto doc = QJsonDocument::fromJson(line);
        const QJsonObject c = doc.object();
        if (!doc.isObject()) {
            dropPending(s);
            return;
        }
        const QString cmd = c.value("cmd").toString();
        if (cmd == QLatin1String("hello")) {
            handleHelloLine(s, c, rest);
            return;
        }
        // Step 2: the GUI proves it holds the same token. Only then does this
        // socket become the privileged channel.
        const auto it = m_pendingNonce.constFind(s);
        if (cmd != QLatin1String("auth") || it == m_pendingNonce.constEnd()
            || !vpn_helper::tokensEqual(
                    c.value("proof").toString(),
                    vpn_helper::authProof(m_token, QString::fromLatin1(vpn_helper::kGuiRole),
                                          it.value()))) {
            dropPending(s);
            return;
        }
        promoteToAuthed(s, rest);
    }

    void promoteToAuthed(QTcpSocket *s, const QByteArray &rest) {
        m_authed = true;
        m_pending.remove(s);
        m_pendingOrder.removeAll(s);
        m_pendingBuf.remove(s);
        m_pendingNonce.remove(s);
        const auto racing = m_pending;
        for (QTcpSocket *other : racing)
            dropPending(other);

        m_sock = s;
        m_buf = rest;
        disconnect(s, nullptr, this, nullptr);
        connect(m_sock, &QTcpSocket::readyRead, this, &HelperServer::onReadyRead);
        connect(m_sock, &QTcpSocket::disconnected, this, []() { QCoreApplication::quit(); });

        QJsonObject e;
        e["ev"] = "ready";
        m_sock->write(QJsonDocument(e).toJson(QJsonDocument::Compact) + '\n');
        QJsonObject pe;
        pe["ev"] = "info";
        pe["msg"] = helperIsElevated()
                ? QStringLiteral("VPN helper started with admin privileges")
                : QStringLiteral("VPN helper started WITHOUT admin privileges — connecting will fail");
        m_sock->write(QJsonDocument(pe).toJson(QJsonDocument::Compact) + '\n');

        // Process any commands pipelined after the hello line in the same burst.
        if (!m_buf.isEmpty())
            processAuthedBuffer();
    }

    void onReadyRead() {
        m_buf += m_sock->readAll();
        processAuthedBuffer();
    }

    void processAuthedBuffer() {
        // Cap the LINE, not the accumulated buffer: a legitimate pipelined burst
        // (a large exclusion list followed by an inline config TOML) could
        // exceed the cap while every individual message was well within it, and
        // dropping the privileged socket makes the helper quit mid-session.
        int nl = -1;
        while ((nl = m_buf.indexOf('\n')) >= 0) {
            const QByteArray line = m_buf.left(nl);
            m_buf.remove(0, nl + 1);
            const auto doc = QJsonDocument::fromJson(line);
            if (doc.isObject()) handleAuthed(doc.object());
        }
        if (m_buf.size() > vpn_helper::kMaxIpcLineBytes) {
            m_buf.clear();
            m_sock->close();
        }
    }

    // Scalar setting commands that just forward one value to the VPN client.
    // Split out of handleAuthed to keep its branch count under the lint limit.
    bool applyClientSetting(const QString &cmd, const QJsonObject &c) {
        if (cmd == "setMode") {
            QMetaObject::invokeMethod(&m_client, "setVpnMode", Qt::QueuedConnection,
                                      Q_ARG(bool, c.value("selective").toBool()));
            return true;
        }
        if (cmd == "setKillSwitch") {
            QMetaObject::invokeMethod(&m_client, "setKillSwitch", Qt::QueuedConnection,
                                      Q_ARG(bool, c.value("enabled").toBool()));
            return true;
        }
        if (cmd == "setLogLevel") {
            QMetaObject::invokeMethod(&m_client, "setLogLevel", Qt::QueuedConnection,
                                      Q_ARG(QString, c.value("level").toString()));
            return true;
        }
        return false;
    }

    void handleAuthed(const QJsonObject &c) {
        const QString cmd = c.value("cmd").toString();
        if (cmd == "setExclusions")
            return applyExclusions(c);
        if (cmd == "setRoutes")
            return applyRoutes(c);
        if (applyClientSetting(cmd, c))
            return;
        if (cmd == "connect") {
            handleConnect(c);
            return;
        }
        if (cmd == "disconnect") {
            QMetaObject::invokeMethod(&m_client, "disconnectVpn", Qt::QueuedConnection);
            return;
        }
        if (cmd == "quit")
            QCoreApplication::quit();
    }

    void applyExclusions(const QJsonObject &c) {
        QStringList domains;
        for (const QJsonValue &v : c.value(QStringLiteral("domains")).toArray())
            domains.append(v.toString());
        QMetaObject::invokeMethod(&m_client, "setExtraExclusionDomains", Qt::QueuedConnection,
                                  Q_ARG(QStringList, domains));
    }

    void applyRoutes(const QJsonObject &c) {
        QStringList routes;
        for (const QJsonValue &v : c.value(QStringLiteral("excluded")).toArray())
            routes.append(v.toString());
        QMetaObject::invokeMethod(&m_client, "setExcludedRouteStrings", Qt::QueuedConnection,
                                  Q_ARG(QStringList, routes));
    }

    void handleConnect(const QJsonObject &c) {
#if defined(Q_OS_WIN)
        QString wintunErr;
        if (!prepareWindowsHelperRuntime(&wintunErr)) {
            QJsonObject e;
            e["ev"] = "error";
            e["msg"] = wintunErr;
            send(e);
            return;
        }
#endif
        const QString toml = c.value(QStringLiteral("configToml")).toString();
        // Path-based connect would make this elevated process open an arbitrary
        // file named by the (unprivileged) GUI. Nothing legitimate uses it — the
        // GUI always sends the config inline — so refuse it as hardening.
        if (toml.isEmpty()) {
            QJsonObject e;
            e["ev"] = "error";
            e["msg"] = QStringLiteral("connect requires inline configToml");
            send(e);
            return;
        }
        // Only whether to log — never where. The core creates the file and its
        // parent directory as root, so a caller-supplied path was a root
        // file-write primitive; the client derives its own path now, which
        // removes the class rather than fencing it in.
        const bool loggingEnabled = c.value(QStringLiteral("loggingEnabled")).toBool(true);
        QMetaObject::invokeMethod(&m_client, "setSessionLogging", Qt::QueuedConnection,
                                  Q_ARG(bool, loggingEnabled));
        QMetaObject::invokeMethod(&m_client, "beginConnect", Qt::QueuedConnection,
                                  Q_ARG(QString, toml));
    }

    quint16 m_port = 0;
    QString m_token;
    QTcpServer m_server;
    QTcpSocket *m_sock = nullptr;
    QByteArray m_buf;
    QSet<QTcpSocket *> m_pending;
    QList<QTcpSocket *> m_pendingOrder; // arrival order, for oldest-first eviction
    QHash<QTcpSocket *, QByteArray> m_pendingBuf;
    QHash<QTcpSocket *, QString> m_pendingNonce; // our challenge, per pending socket
    bool m_authed = false;
    QThread m_vpnThread;
    QtTrustTunnelClient m_client;
};

} // namespace

int runVpnHelper(int argc, char **argv) {
    QCoreApplication app(argc, argv);
#if defined(Q_OS_WIN)
    QString wintunErr;
    if (!prepareWindowsHelperRuntime(&wintunErr)) {
        qWarning("%s", qPrintable(wintunErr));
        return 4;
    }
#endif
    const freetunnel::HelperLaunchConfig cfg =
            freetunnel::parseHelperLaunchArgs(QCoreApplication::arguments());
    if (!cfg.ok())
        return 2;

    HelperServer server(cfg.port, cfg.token);
    if (!server.listen())
        return 3;

    QTimer::singleShot(60000, &app, [&server]() {
        if (!server.authed())
            QCoreApplication::quit();
    });
    return app.exec();
}
