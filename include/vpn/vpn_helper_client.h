// cppcheck-suppress-file missingIncludeSystem
#pragma once

// GUI-side proxy for the VPN. Spawns the privileged helper (the same binary run
// with --helper, elevated once per session) and drives it over loopback TCP.
// Exposes the same signal/slot surface the Backend expects, so the GUI never
// runs the VPN core (or root) in-process.

#include <QByteArray>
#include <QObject>
#include <QString>
#include <string>
#include <vector>

class QTcpSocket;
class QProcess;
class QTimer;
class QJsonObject;

class VpnHelperClient : public QObject {
    Q_OBJECT
public:
    enum class State {
        Disconnected,
        Connecting,
        Connected,
        Reconnecting,
        WaitingForNetwork,
        Disconnecting,
        Error,
    };
    Q_ENUM(State)

    explicit VpnHelperClient(QObject *parent = nullptr);
    ~VpnHelperClient() override;

    bool loadConfigFromToml(const QString &tomlContent);
    void setExtraExclusions(const std::vector<std::string> &exclusions);
    void setExcludedRoutes(const std::vector<std::string> &routes);
    void setVpnMode(bool selective);
    void setKillSwitch(bool enabled);
    void setLogLevel(const QString &level); // "warn"/"info"/… applied live, no reconnect
    void setSessionLogging(bool enabled);

    void connectVpn();
    void disconnectVpn();
    void shutdown();
    State state() const { return m_state; }

signals:
    void stateChanged(VpnHelperClient::State state);
    void tunnelStats(quint64 upload, quint64 download);
    void connectionInfo(const QString &msg);
    void connectProgress(const QString &step);
    void coreLogLine(const QString &line);
    void vpnError(const QString &msg);

private:
    bool ensureHelper();
    bool spawnElevatedHelper(quint16 port, const QString &tokenPath, QString *err);
    void resetHelperTransport();
    bool configureTestHelper();
    bool configureProductionHelper();
    void wireHelperSocket(bool testHelper);
    void startHelperConnectRetry();
    void abortStartup();
    void clearTokenFile();
    void send(const QJsonObject &obj);
    void onReadyRead();
    void onSocketConnected();
    void handleEvent(const QJsonObject &ev);
    // The first half of the mutual handshake, split out of handleEvent() so that
    // the peer check and the event dispatch can each be read on their own.
    void handleChallengeEvent(const QJsonObject &ev);
    void handleReadyEvent();
    void setState(State s);
    void fail(const QString &msg);

    QProcess *m_proc = nullptr;
    QTcpSocket *m_sock = nullptr;
    quint16 m_tcpPort = 0;
    QString m_token;
    QString m_guiNonce;        // our half of the mutual-auth handshake
    bool m_peerProven = false; // peer answered our challenge with a valid proof
    QString m_tokenPath;
    QString m_configToml;
    std::vector<std::string> m_exclusions;
    std::vector<std::string> m_excludedRoutes;
    bool m_selective = false;
    bool m_killSwitch = false;
    QString m_logLevel = QStringLiteral("warn");
    bool m_loggingEnabled = true;
    State m_state = State::Disconnected;
    bool m_helloAcked = false;
    bool m_connectPending = false;
    bool m_starting = false;
    QTimer *m_attempt = nullptr;
    int m_tries = 0;
    QByteArray m_buf;
};
