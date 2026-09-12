// cppcheck-suppress-file missingIncludeSystem
#include "core/InstalledApps.h"

#include "core/AppRules.h"
#include "core/AppShortcut.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStandardPaths>

#include <algorithm>

namespace freetunnel {

namespace {

// Shared with AppShortcut's parser in shape but not in purpose: that one looks
// for the program, this one for what to show. Kept separate rather than
// generalised, because the two want different things from the same file and a
// single "get a key" helper would end up with a mode flag.
QString desktopValue(const QString &contents, const QString &key)
{
    bool inEntry = false;
    const QList<QStringView> lines = QStringView(contents).split(QLatin1Char('\n'));
    for (const QStringView &raw : lines) {
        const QStringView line = raw.trimmed();
        if (line.startsWith(QLatin1Char('['))) {
            inEntry = (line == QLatin1String("[Desktop Entry]"));
            continue;
        }
        if (!inEntry || line.startsWith(QLatin1Char('#')))
            continue;
        const qsizetype eq = line.indexOf(QLatin1Char('='));
        if (eq <= 0)
            continue;
        if (line.left(eq).trimmed() == key)
            return line.mid(eq + 1).trimmed().toString();
    }
    return {};
}

bool isTrue(const QString &v)
{
    return v.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0;
}

#if !defined(Q_OS_WIN) && !defined(Q_OS_MACOS)
void appendLinuxApps(QList<InstalledApp> *out)
{
    const QStringList dirs = QStandardPaths::standardLocations(QStandardPaths::ApplicationsLocation);
    for (const QString &dirPath : dirs) {
        QDir dir(dirPath);
        if (!dir.exists())
            continue;
        const QStringList entries = dir.entryList({QStringLiteral("*.desktop")}, QDir::Files);
        for (const QString &entry : entries) {
            const QString path = dir.filePath(entry);
            QFile f(path);
            if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
                continue;
            const QString contents = QString::fromUtf8(f.readAll());
            if (!desktopEntryIsVisibleApplication(contents))
                continue;
            const QString exe = resolveApplicationTarget(path);
            if (exe.isEmpty())
                continue; // names a program that is not actually installed
            QString name = displayNameFromDesktopEntry(contents);
            if (name.isEmpty())
                name = QFileInfo(exe).fileName();
            out->append(InstalledApp{name, exe});
        }
    }
}
#endif

#ifdef Q_OS_WIN
void appendWindowsApps(QList<InstalledApp> *out)
{
    // The Start Menu is the list a person already has in their head, which is
    // why it is used rather than the uninstall registry: the registry knows
    // about installed packages, not about the things someone clicks.
    const QStringList dirs = QStandardPaths::standardLocations(QStandardPaths::ApplicationsLocation);
    for (const QString &dirPath : dirs) {
        if (!QDir(dirPath).exists())
            continue;
        QDirIterator it(dirPath, {QStringLiteral("*.lnk")}, QDir::Files,
                        QDirIterator::Subdirectories);
        while (it.hasNext()) {
            const QString linkPath = it.next();
            const QString exe = resolveApplicationTarget(linkPath);
            if (exe.isEmpty())
                continue;
            // Shortcuts to documents, help files and web pages live in the same
            // tree. Only a program can be a rule.
            if (QFileInfo(exe).suffix().compare(QLatin1String("exe"), Qt::CaseInsensitive) != 0)
                continue;
            out->append(InstalledApp{QFileInfo(linkPath).completeBaseName(), exe});
        }
    }
}
#endif

#ifdef Q_OS_MACOS
void appendMacApps(QList<InstalledApp> *out)
{
    const QStringList dirs = QStandardPaths::standardLocations(QStandardPaths::ApplicationsLocation);
    for (const QString &dirPath : dirs) {
        QDir dir(dirPath);
        if (!dir.exists())
            continue;
        // One level down as well: /Applications/Utilities is where a good half
        // of the system's own programs live.
        QStringList candidates = dir.entryList({QStringLiteral("*.app")}, QDir::Dirs | QDir::NoDotAndDotDot);
        for (QString &c : candidates)
            c = dir.filePath(c);
        const QStringList subdirs = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
        for (const QString &sub : subdirs) {
            if (sub.endsWith(QLatin1String(".app")))
                continue;
            QDir subDir(dir.filePath(sub));
            const QStringList inner = subDir.entryList({QStringLiteral("*.app")},
                                                       QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QString &c : inner)
                candidates.append(subDir.filePath(c));
        }
        for (const QString &bundle : std::as_const(candidates)) {
            const QString exe = resolveApplicationTarget(bundle);
            if (exe.isEmpty())
                continue;
            out->append(InstalledApp{QFileInfo(bundle).completeBaseName(), exe});
        }
    }
}
#endif

} // namespace

bool desktopEntryIsVisibleApplication(const QString &contents)
{
    if (desktopValue(contents, QStringLiteral("Type")) != QLatin1String("Application"))
        return false;
    if (isTrue(desktopValue(contents, QStringLiteral("NoDisplay"))))
        return false;
    if (isTrue(desktopValue(contents, QStringLiteral("Hidden"))))
        return false;
    return true;
}

QString displayNameFromDesktopEntry(const QString &contents)
{
    return desktopValue(contents, QStringLiteral("Name"));
}

QList<InstalledApp> installedApplications()
{
    QList<InstalledApp> apps;
#if defined(Q_OS_WIN)
    appendWindowsApps(&apps);
#elif defined(Q_OS_MACOS)
    appendMacApps(&apps);
#else
    appendLinuxApps(&apps);
#endif

    const Qt::CaseSensitivity cs = appPathCaseSensitivity();
    std::sort(apps.begin(), apps.end(), [](const InstalledApp &a, const InstalledApp &b) {
        const int byName = a.name.localeAwareCompare(b.name);
        if (byName != 0)
            return byName < 0;
        return a.executablePath < b.executablePath;
    });

    // One program commonly has several entries — a Flatpak beside a distribution
    // package, or a Start Menu shortcut in both the machine-wide and the
    // per-user tree. Keeping the first means keeping the name that sorted first,
    // which is stable between runs.
    QList<InstalledApp> unique;
    QSet<QString> seen;
    unique.reserve(apps.size());
    for (const InstalledApp &app : std::as_const(apps)) {
        const QString key = cs == Qt::CaseInsensitive ? app.executablePath.toLower() : app.executablePath;
        if (seen.contains(key))
            continue;
        seen.insert(key);
        unique.append(app);
    }
    return unique;
}

} // namespace freetunnel
