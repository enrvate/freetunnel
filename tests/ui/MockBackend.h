// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

#include "app/LogModel.h"

// Lightweight Backend stand-in for headless QML/UI tests (no VPN core).
class MockBackend : public QObject {
    Q_OBJECT
    // Test-only scratch pad. QML closures cannot write into a C++ test directly,
    // and QML objects reject properties they did not declare, so a confirm
    // callback needs somewhere real to record that it ran. Used by
    // aSecondConfirmQueuesInsteadOfReplacingTheLiveOne to tell WHICH callback
    // fired, which is the whole question when two dialogs are queued.
    Q_PROPERTY(QString confirmLog MEMBER m_confirmLog)
    Q_PROPERTY(bool connected READ connected WRITE setConnected NOTIFY stateChanged)
    Q_PROPERTY(bool connecting READ connecting WRITE setConnecting NOTIFY stateChanged)
    Q_PROPERTY(bool disconnecting READ disconnecting WRITE setDisconnecting NOTIFY stateChanged)
    // NOTIFY signals mirror Backend's so bindings re-evaluate the same way here
    // (speeds/session time on tick, names on configsChanged, …).
    Q_PROPERTY(QString sessionTime READ sessionTime NOTIFY tick)
    Q_PROPERTY(QString downSpeed READ downSpeed NOTIFY tick)
    Q_PROPERTY(QString upSpeed READ upSpeed NOTIFY tick)
    Q_PROPERTY(QString activeConfig READ activeConfig NOTIFY configChanged)
    Q_PROPERTY(QStringList configs READ configs NOTIFY configsChanged)
    Q_PROPERTY(int activeIndex READ activeIndex NOTIFY configChanged)
    Q_PROPERTY(QString language READ language WRITE setLanguage NOTIFY languageChanged)
    Q_PROPERTY(QString themeMode READ themeMode WRITE setThemeMode NOTIFY settingsChanged)
    Q_PROPERTY(bool autoConnect READ autoConnect WRITE setAutoConnect NOTIFY settingsChanged)
    Q_PROPERTY(bool killSwitch READ killSwitch WRITE setKillSwitch NOTIFY settingsChanged)
    Q_PROPERTY(QObject *logModel READ logModel CONSTANT)
    Q_PROPERTY(bool splitEnabled READ splitEnabled WRITE setSplitEnabled NOTIFY splitChanged)
    Q_PROPERTY(QString vpnMode READ vpnMode WRITE setVpnMode NOTIFY splitChanged)
    // Mirrors Backend: "selective" with no rules would route nothing through the
    // tunnel, so the Backend keeps the full tunnel and the Split page explains it.
    // Derived here the same way, so the page under test sees the real relationship
    // rather than a constant.
    Q_PROPERTY(bool selectiveModeWouldLeak READ selectiveModeWouldLeak NOTIFY splitChanged)
    Q_PROPERTY(QStringList domains READ domains NOTIFY splitChanged)
    Q_PROPERTY(QStringList excludedRoutes READ excludedRoutes NOTIFY splitChanged)
    Q_PROPERTY(QStringList appRules READ appRules NOTIFY splitChanged)
    Q_PROPERTY(QStringList profiles READ profiles NOTIFY splitChanged)
    Q_PROPERTY(QString activeProfile READ activeProfile NOTIFY splitChanged)
    Q_PROPERTY(bool hotkeysSupported READ hotkeysSupported CONSTANT)
    Q_PROPERTY(bool hotkeysEnabled READ hotkeysEnabled WRITE setHotkeysEnabled NOTIFY hotkeysChanged)
    Q_PROPERTY(QString hotkeyToggle READ hotkeyToggle WRITE setHotkeyToggle NOTIFY hotkeysChanged)
    Q_PROPERTY(QString hotkeyConnect READ hotkeyConnect WRITE setHotkeyConnect NOTIFY hotkeysChanged)
    Q_PROPERTY(QString hotkeyDisconnect READ hotkeyDisconnect WRITE setHotkeyDisconnect NOTIFY hotkeysChanged)
    Q_PROPERTY(QString appVersion READ appVersion CONSTANT)
    Q_PROPERTY(QString coreVersion READ coreVersion CONSTANT)
    Q_PROPERTY(QString updateState READ updateState NOTIFY updateChanged)
    Q_PROPERTY(QString updateMessage READ updateMessage NOTIFY updateChanged)
    Q_PROPERTY(QString latestVersion READ latestVersion NOTIFY updateChanged)
    Q_PROPERTY(QString logPath READ logPath CONSTANT)
    Q_PROPERTY(bool loggingEnabled READ loggingEnabled WRITE setLoggingEnabled NOTIFY settingsChanged)
    Q_PROPERTY(bool verboseLogs READ verboseLogs WRITE setVerboseLogs NOTIFY settingsChanged)
    Q_PROPERTY(bool autoStart READ autoStart WRITE setAutoStart NOTIFY settingsChanged)
    Q_PROPERTY(QVariantList pings READ pings NOTIFY pingsChanged)
    Q_PROPERTY(QString credentialStorageWarning READ credentialStorageWarning NOTIFY
                       credentialStorageChanged)

public:
    explicit MockBackend(QObject *parent = nullptr);

    bool connected() const { return m_connected; }
    void setConnected(bool v);
    bool connecting() const { return m_connecting; }
    void setConnecting(bool v);
    bool disconnecting() const { return m_disconnecting; }
    void setDisconnecting(bool v);
    QString sessionTime() const { return m_sessionTime; }
    QString downSpeed() const { return m_downSpeed; }
    QString upSpeed() const { return m_upSpeed; }
    QString activeConfig() const { return m_activeConfig; }
    QStringList configs() const { return m_configs; }
    int activeIndex() const { return m_activeIndex; }

    QString language() const { return m_language; }
    void setLanguage(const QString &v);
    QString themeMode() const { return m_themeMode; }
    void setThemeMode(const QString &v);
    bool autoConnect() const { return m_autoConnect; }
    void setAutoConnect(bool v);
    bool killSwitch() const { return m_killSwitch; }
    void setKillSwitch(bool v);
    bool loggingEnabled() const { return m_loggingEnabled; }
    void setLoggingEnabled(bool v) {
        if (m_loggingEnabled == v)
            return;
        m_loggingEnabled = v;
        emit settingsChanged();
    }
    bool verboseLogs() const { return m_verboseLogs; }
    void setVerboseLogs(bool v) {
        if (m_verboseLogs == v)
            return;
        m_verboseLogs = v;
        emit settingsChanged();
    }

    QObject *logModel() { return &m_logModel; }
    bool splitEnabled() const { return m_splitEnabled; }
    void setSplitEnabled(bool v);
    QString vpnMode() const { return m_vpnMode; }
    bool selectiveModeWouldLeak() const
    {
        return m_splitEnabled && m_vpnMode == QLatin1String("selective") && m_domains.isEmpty();
    }
    void setVpnMode(const QString &v);
    QStringList domains() const { return m_domains; }
    QStringList excludedRoutes() const { return m_excludedRoutes; }
    QStringList appRules() const { return m_appRules; }
    QStringList profiles() const { return m_profiles; }
    QString activeProfile() const { return m_activeProfile; }

    bool hotkeysSupported() const { return m_hotkeysSupported; }
    bool hotkeysEnabled() const { return m_hotkeysEnabled; }
    void setHotkeysEnabled(bool v);
    QString hotkeyToggle() const { return m_hotkeyToggle; }
    QString hotkeyConnect() const { return m_hotkeyConnect; }
    QString hotkeyDisconnect() const { return m_hotkeyDisconnect; }
    void setHotkeyToggle(const QString &v);
    void setHotkeyConnect(const QString &v);
    void setHotkeyDisconnect(const QString &v);
    // Backend maps a key's physical position to its Latin letter; nothing to map
    // headlessly, so report "not a letter key" like the real one does.
    Q_INVOKABLE QString physicalLetterForScanCode(quint32) const { return QString(); }

    // Empty = the OS keychain works, which is the normal desktop case.
    QString credentialStorageWarning() const { return m_credentialStorageWarning; }

    QString appVersion() const { return QStringLiteral("1.0.0-test"); }
    QString coreVersion() const { return QStringLiteral("test-core"); }
    QString updateState() const { return QString(); }
    QString updateMessage() const { return QString(); }
    QString latestVersion() const { return QString(); }
    QString logPath() const;
    bool autoStart() const { return m_autoStart; }
    void setAutoStart(bool v);
    QVariantList pings() const { return m_pings; }

    int toggleCount() const { return m_toggleCount; }

    Q_INVOKABLE QString readBundledText(const QUrl &url) const;
    Q_INVOKABLE void toggle();
    Q_INVOKABLE void connectVpn() { m_connecting = true; emit stateChanged(); }
    Q_INVOKABLE void disconnectVpn() { m_connected = false; emit stateChanged(); }
    Q_INVOKABLE void selectConfig(int index);
    Q_INVOKABLE void removeConfig(int index);
    Q_INVOKABLE void moveConfig(int from, int to); // manual reorder (drag in the list)
    Q_INVOKABLE bool importDeepLink(const QString &link);
    Q_INVOKABLE bool confirmDeepLinkImport(const QString &link, bool replaceExisting = false);
    Q_INVOKABLE bool importFile(const QString &path);
    Q_INVOKABLE bool createConfig(const QVariantMap &fields);
    Q_INVOKABLE QVariantMap configFields(int index) const;
    Q_INVOKABLE QString configDeepLink(int) const { return QStringLiteral("tt://?mock"); }
    Q_INVOKABLE bool exportConfigToml(int, const QString &) const { return true; }
    Q_INVOKABLE void clearLogs() {}
    Q_INVOKABLE void openLogFolder() {}
    Q_INVOKABLE QString logText() const { return QString(); }
    Q_INVOKABLE void copyToClipboard(const QString &) const {}
    Q_INVOKABLE QString readTextFile(const QString &) const { return QString(); }
    Q_INVOKABLE bool addDomain(const QString &) { return false; }
    Q_INVOKABLE void removeDomain(int) {}
    Q_INVOKABLE void clearDomains() {}
    Q_INVOKABLE bool addExcludedRoute(const QString &) { return false; }
    Q_INVOKABLE void removeExcludedRoute(int) {}
    Q_INVOKABLE void clearExcludedRoutes() {}
    Q_INVOKABLE bool addAppRule(const QString &) { return false; }
    Q_INVOKABLE bool addApplicationFromPath(const QString &) { return false; }
    // Two rows so the picker renders with content, one of them a long path,
    // which is what the left elide in the delegate is for.
    Q_INVOKABLE QVariantList installedApplications() {
        QVariantList out;
        QVariantMap a; a["name"] = QStringLiteral("Firefox"); a["path"] = QStringLiteral("/usr/bin/firefox");
        QVariantMap b; b["name"] = QStringLiteral("Some App");
        b["path"] = QStringLiteral("/usr/lib/some/very/long/path/to/a/program");
        out << a << b;
        return out;
    }
    Q_INVOKABLE void removeAppRule(int) {}
    Q_INVOKABLE void clearAppRules() {}
    Q_INVOKABLE void restoreDefaultExcludedRoutes() {}
    Q_INVOKABLE void addRecommendedRussia() {}
    Q_INVOKABLE void selectProfile(const QString &) {}
    Q_INVOKABLE void addProfile(const QString &) {}
    Q_INVOKABLE void removeProfile(const QString &) {}
    Q_INVOKABLE void checkForUpdates() {}
    Q_INVOKABLE void downloadUpdate() {}
    Q_INVOKABLE void openLatestRelease() {}
    Q_INVOKABLE void openUrl(const QString &) {}
    Q_INVOKABLE void startWindowDrag(QObject *) {}
    Q_INVOKABLE void pingConfigs() {}
    Q_INVOKABLE bool importFromClipboard() { return false; }
    Q_INVOKABLE void prepareQuit()
    {
        m_shutdownPrepared = true;
        emit aboutToShutdown();
    }
    Q_INVOKABLE void quitApplication() { prepareQuit(); }
    // Main.qml's onClosing asks this before treating a close as a real quit.
    Q_INVOKABLE bool applicationClosingDown() const { return m_shutdownPrepared; }

signals:
    void stateChanged();
    void tick();
    void configChanged();
    void configsChanged();
    void settingsChanged();
    void logChanged();
    void splitChanged();
    void hotkeysChanged();
    void updateChanged();
    void pingsChanged();
    void languageChanged(const QString &lang);
    void credentialStorageChanged();
    void errorOccurred(const QString &msg);
    void deepLinkImportConfirmationRequired(const QString &message, const QString &link,
                                            const QString &existingName);
    void configImported(const QString &name); // a config was added via file/clipboard/deep-link
    void aboutToShutdown();

private:
    bool m_connected = false;
    bool m_connecting = false;
    bool m_disconnecting = false;
    QString m_confirmLog;
    QString m_sessionTime = QStringLiteral("0:00:01");
    QString m_downSpeed = QStringLiteral("1.2");
    QString m_upSpeed = QStringLiteral("0.4");
    QString m_activeConfig = QStringLiteral("Test Config");
    QStringList m_configs = {QStringLiteral("Test Config"), QStringLiteral("Backup")};
    int m_activeIndex = 0;
    QString m_language = QStringLiteral("en");
    QString m_themeMode = QStringLiteral("dark");
    bool m_autoConnect = false;
    bool m_killSwitch = false;
    bool m_loggingEnabled = true;
    bool m_verboseLogs = false;
    LogModel m_logModel;
    bool m_splitEnabled = false;
    QString m_vpnMode = QStringLiteral("general");
    QStringList m_domains;
    QStringList m_excludedRoutes = {QStringLiteral("10.0.0.0/8")};
    // One bare name and one long path, so the page is rendered with both
    // shapes a rule can take — the path is what exercises the left elide.
    QStringList m_appRules = {QStringLiteral("firefox"),
                              QStringLiteral("/usr/lib/some/very/long/path/to/a/program")};
    QStringList m_profiles = {QStringLiteral("Default")};
    QString m_activeProfile = QStringLiteral("Default");
    bool m_hotkeysSupported = true;
    bool m_hotkeysEnabled = true;
    QString m_hotkeyToggle = QStringLiteral("Ctrl+Alt+T");
    QString m_hotkeyConnect;
    QString m_hotkeyDisconnect;
    bool m_autoStart = false;
    QVariantList m_pings = {QStringLiteral("42 ms"), QStringLiteral("—")};
    QString m_credentialStorageWarning;
    bool m_shutdownPrepared = false;
    int m_toggleCount = 0;
};
