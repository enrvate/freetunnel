// cppcheck-suppress-file missingIncludeSystem
// Core log file handling for QtTrustTunnelClient: choosing the path the VPN core
// writes to, truncating it between sessions, and tailing it so the GUI can show
// core lines live. Split out of qt_trusttunnel_client.cpp, which had grown past
// the point where one file could be read end to end.
//
// The path is chosen here rather than accepted from the GUI on purpose: the core
// runs elevated, so a caller-supplied log path would be a write primitive for
// root. See docs/security-threats.md.
#include "qt_trusttunnel_client.h"
#include "qt_trusttunnel_events.h"
#include "qt_trusttunnel_platform.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMetaObject>
#include <QString>
#include <QTimer>

#include <mutex>

void QtTrustTunnelClient::applyCoreLogPathToConfig()
{
    std::lock_guard<std::mutex> lk(m_configMutex);
    applyCoreLogPathToConfigLocked();
}

void QtTrustTunnelClient::applyCoreLogPathToConfigLocked()
{
    if (!m_loggingEnabled) {
        if (m_config.has_value())
            m_config->log_file_path.clear();
        return;
    }
    if (m_coreLogPath.isEmpty())
        m_coreLogPath = qt_trusttunnel_default_core_log_path();
    if (m_config.has_value())
        m_config->log_file_path = m_coreLogPath.toStdString();
}

void QtTrustTunnelClient::resetCoreLogFile()
{
    QString path;
    {
        std::lock_guard<std::mutex> lk(m_configMutex);
        if (!m_loggingEnabled)
            return;
        path = m_coreLogPath;
    }
    if (path.isEmpty())
        return;
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.close();
    m_coreLogOffset = 0;
}

void QtTrustTunnelClient::startCoreLogTail()
{
    // Called from ensureClientReady on the connect thread: a QTimer created
    // there would be parented across threads (Qt drops the parent) and take the
    // connect thread's affinity, where no event loop ever runs — the poll never
    // fired and no core log line reached the GUI. Marshal onto our own thread.
    if (QThread::currentThread() != thread()) {
        QMetaObject::invokeMethod(this, [this]() { startCoreLogTail(); }, Qt::QueuedConnection);
        return;
    }
    // The hop above is queued, so a disconnect can land between the request and
    // this call — re-arming the poll then would leave it running with no session
    // behind it.
    if (m_stopRequested)
        return;
    QString path;
    {
        std::lock_guard<std::mutex> lk(m_configMutex);
        if (!m_loggingEnabled)
            return;
        applyCoreLogPathToConfigLocked();
        path = m_coreLogPath;
    }
    if (path.isEmpty())
        return;
    QDir().mkpath(QFileInfo(path).absolutePath());

    if (!m_coreLogPoll) {
        m_coreLogPoll = new QTimer(this);
        m_coreLogPoll->setInterval(800);
        connect(m_coreLogPoll, &QTimer::timeout, this, &QtTrustTunnelClient::pollCoreLogFile);
    }
    if (!m_coreLogPoll->isActive())
        m_coreLogPoll->start();
    pollCoreLogFile();
}

void QtTrustTunnelClient::stopCoreLogTail()
{
    if (QThread::currentThread() != thread()) {
        QMetaObject::invokeMethod(this, [this]() { stopCoreLogTail(); }, Qt::QueuedConnection);
        return;
    }
    if (m_coreLogPoll)
        m_coreLogPoll->stop();
    m_coreLogLineBuffer.clear();
}

void QtTrustTunnelClient::pollCoreLogFile()
{
    QString path;
    {
        std::lock_guard<std::mutex> lk(m_configMutex);
        path = m_coreLogPath;
    }
    if (path.isEmpty())
        return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return;
    if (!f.seek(m_coreLogOffset))
        return;
    const QByteArray chunk = f.readAll();
    m_coreLogOffset = f.pos();
    f.close();
    // Not "return when the file did not grow": the per-poll line cap leaves whole
    // lines in the buffer, and they were only ever flushed by the NEXT chunk. A
    // core that logged a burst and then went quiet — which is exactly what happens
    // once a tunnel settles — left its last lines sitting in memory, never shown.
    if (chunk.isEmpty() && m_coreLogLineBuffer.isEmpty())
        return;

    constexpr int kMaxLinesPerPoll = 24;
    drainCoreLogTailBytes(&m_coreLogLineBuffer, chunk, kMaxLinesPerPoll,
            [this](const QString &line) { emit coreLogLine(line); });
}
