// cppcheck-suppress-file missingIncludeSystem
#include "mock_http_server.h"

#include <QTcpSocket>

MockHttpServer::MockHttpServer(QObject *parent)
    : QObject(parent)
{
    m_server.setParent(this);
    connect(&m_server, &QTcpServer::newConnection, this, &MockHttpServer::onNewConnection);
}

bool MockHttpServer::listen()
{
    return m_server.listen(QHostAddress(QStringLiteral("127.0.0.1")));
}

quint16 MockHttpServer::port() const
{
    return m_server.serverPort();
}

void MockHttpServer::setRoute(const QString &path, const Route &route)
{
    m_routes.insert(path, route);
}

QString MockHttpServer::baseUrl() const
{
    return QStringLiteral("http://127.0.0.1:%1").arg(m_server.serverPort());
}

void MockHttpServer::onNewConnection()
{
    while (m_server.hasPendingConnections()) {
        QTcpSocket *sock = m_server.nextPendingConnection();
        if (!sock)
            continue;
        connect(sock, &QTcpSocket::readyRead, sock, [this, sock]() {
            const QByteArray req = sock->readAll();
            const int lineEnd = req.indexOf("\r\n");
            const QByteArray line = lineEnd >= 0 ? req.left(lineEnd) : req;
            const QList<QByteArray> parts = line.split(' ');
            if (parts.size() < 2)
                return;
            QString path = QString::fromUtf8(parts.at(1));
            const int query = path.indexOf(QLatin1Char('?'));
            if (query >= 0)
                path = path.left(query);

            ++m_hits[path];
            const Route route = m_routes.value(path);
            const QByteArray body = route.body;
            QByteArray response = QByteArrayLiteral("HTTP/1.1 ");
            response += QByteArray::number(route.status);
            response += route.status == 200 ? QByteArrayLiteral(" OK\r\n")
                                          : QByteArrayLiteral(" Error\r\n");
            response += QByteArrayLiteral("Content-Type: ");
            response += route.contentType;
            response += QByteArrayLiteral("\r\nContent-Length: ");
            response += QByteArray::number(body.size());
            response += QByteArrayLiteral("\r\nConnection: close\r\n\r\n");
            response += body;
            sock->write(response);
            sock->flush();
            sock->disconnectFromHost();
        });
    }
}
