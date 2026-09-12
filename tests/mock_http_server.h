// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QTcpServer>
#include <QString>

// Minimal loopback HTTP/1.1 server for UpdateChecker integration tests.
class MockHttpServer : public QObject {
    Q_OBJECT
public:
    struct Route {
        QByteArray body;
        int status = 200;
        QByteArray contentType = QByteArrayLiteral("application/json");
    };

    explicit MockHttpServer(QObject *parent = nullptr);

    bool listen();
    quint16 port() const;
    void setRoute(const QString &path, const Route &route);
    QString baseUrl() const;
    // How many requests this path has served. Used to tell "the guard stopped a
    // second check" from "the second check ran too" — a difference no signal or
    // state property exposes, because both look the same once they settle.
    int requestCount(const QString &path) const { return m_hits.value(path); }

private:
    void onNewConnection();

    QTcpServer m_server;
    QHash<QString, Route> m_routes;
    QHash<QString, int> m_hits;
};
