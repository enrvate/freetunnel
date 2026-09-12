// cppcheck-suppress-file missingIncludeSystem
#include "core/AppShortcut.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QStringList>
#include <QUrl>

#ifdef Q_OS_WIN
// clang-format off
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
// clang-format on
#endif

namespace freetunnel {

namespace {

// Field codes a launcher substitutes at start time (%f, %U, %i…). They are not
// part of the program name, and one left in would make the rule unmatchable.
bool isFieldCode(const QString &token)
{
    return token.size() == 2 && token.startsWith(QLatin1Char('%'));
}

// Split an Exec= line the way a launcher does: quoted runs hold together, so a
// program under "/opt/My App/" survives.
QStringList splitExec(const QString &line)
{
    QStringList out;
    QString current;
    bool inQuotes = false;
    bool escaped = false;
    for (const QChar c : line) {
        if (escaped) {
            current.append(c);
            escaped = false;
            continue;
        }
        if (c == QLatin1Char('\\')) {
            escaped = true;
            continue;
        }
        if (c == QLatin1Char('"')) {
            inQuotes = !inQuotes;
            continue;
        }
        if (!inQuotes && c.isSpace()) {
            if (!current.isEmpty()) {
                out.append(current);
                current.clear();
            }
            continue;
        }
        current.append(c);
    }
    if (!current.isEmpty())
        out.append(current);
    return out;
}

QString valueForKey(const QString &contents, const QString &key)
{
    // Only the [Desktop Entry] group counts. Actions further down the file carry
    // their own Exec= lines for "open a new window" and the like, and picking one
    // of those up would name the right program by luck or the wrong one by
    // accident.
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

QString absoluteExecutable(const QString &program)
{
    if (program.isEmpty())
        return {};
    if (QFileInfo(program).isAbsolute())
        return QFileInfo(program).exists() ? QDir::toNativeSeparators(program) : QString();
    // A bare name in Exec= is resolved against PATH, the same as the launcher
    // would. Falling back to the bare name would store a rule that happens to
    // work — bare names do match — but would lose the precision the user asked
    // for by pointing at a specific shortcut.
    const QString found = QStandardPaths::findExecutable(program);
    return found.isEmpty() ? QString() : QDir::toNativeSeparators(found);
}

#ifdef Q_OS_WIN
QString resolveWindowsShortcut(const QString &lnkPath)
{
    // The GUI thread has COM initialised already; a worker may not. Accept both,
    // and only uninitialise what this call actually initialised.
    const HRESULT init = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool weInitialised = SUCCEEDED(init);

    QString result;
    IShellLinkW *link = nullptr;
    if (SUCCEEDED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                     reinterpret_cast<void **>(&link)))) {
        IPersistFile *file = nullptr;
        if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void **>(&file)))) {
            const QString native = QDir::toNativeSeparators(lnkPath);
            if (SUCCEEDED(file->Load(reinterpret_cast<LPCOLESTR>(native.utf16()), STGM_READ))) {
                wchar_t target[MAX_PATH * 2] = {};
                // No SLGP_UNCPRIORITY / resolve flags: this must not go off and
                // hunt for a moved target over the network while the user waits
                // on a drop.
                if (SUCCEEDED(link->GetPath(target, static_cast<int>(std::size(target)), nullptr,
                                            SLGP_RAWPATH))) {
                    result = QString::fromWCharArray(target);
                }
            }
            file->Release();
        }
        link->Release();
    }

    if (weInitialised && init != S_FALSE)
        ::CoUninitialize();
    if (result.isEmpty() || !QFileInfo(result).exists())
        return {};
    return QDir::toNativeSeparators(result);
}
#endif

// The executable inside a macOS .app bundle. Implemented by looking in
// Contents/MacOS rather than by parsing Info.plist, because the plist may be
// binary and the directory answers the question directly. Built on every
// platform so a dropped bundle copied to another machine still resolves, and so
// the logic is testable where the tests run.
QString executableInsideBundle(const QString &bundlePath)
{
    const QDir macos(bundlePath + QStringLiteral("/Contents/MacOS"));
    if (!macos.exists())
        return {};
    // CFBundleExecutable is conventionally the bundle's own name, so try that
    // first and fall back to whatever single program is in there.
    const QString byName = macos.filePath(QFileInfo(bundlePath).completeBaseName());
    if (QFileInfo(byName).isFile())
        return QDir::toNativeSeparators(byName);
    const QStringList entries = macos.entryList(QDir::Files | QDir::NoDotAndDotDot);
    if (entries.size() == 1)
        return QDir::toNativeSeparators(macos.filePath(entries.first()));
    return {};
}

} // namespace

QString sandboxedProgramFromDesktopEntry(const QString &contents)
{
    const QStringList tokens = splitExec(valueForKey(contents, QStringLiteral("Exec")));
    if (tokens.isEmpty())
        return {};
    const QString runner = QFileInfo(tokens.first()).fileName();

    if (runner == QLatin1String("flatpak")) {
        // The entry usually says outright which program inside the sandbox it
        // starts: "flatpak run --command=anydesk … com.anydesk.Anydesk".
        for (const QString &t : tokens) {
            if (t.startsWith(QLatin1String("--command=")))
                return t.mid(10);
        }
        // Otherwise the application id is the only handle, and its last segment
        // is the convention for the program's own name.
        for (const QString &t : tokens) {
            if (t.startsWith(QLatin1Char('-')) || !t.contains(QLatin1Char('.'))
                    || t.contains(QLatin1Char('/')))
                continue;
            const QString last = t.section(QLatin1Char('.'), -1);
            if (!last.isEmpty())
                return last.toLower();
        }
        return {};
    }

    if (runner == QLatin1String("snap")) {
        // "snap run foo"
        for (int i = 1; i < tokens.size(); ++i) {
            if (tokens[i] == QLatin1String("run"))
                continue;
            if (tokens[i].startsWith(QLatin1Char('-')))
                continue;
            return tokens[i].section(QLatin1Char('.'), -1);
        }
        return {};
    }

    // /snap/bin/foo is a wrapper script, not the program: the process that ends
    // up in the socket table is the one inside /snap/foo/current/.
    if (tokens.first().startsWith(QLatin1String("/snap/bin/")))
        return runner;

    return {};
}

QString executableFromDesktopEntry(const QString &contents)
{
    // TryExec is the launcher's own "is this installed" probe and names the
    // binary with no arguments attached, so it is the cleaner answer when present.
    const QString tryExec = valueForKey(contents, QStringLiteral("TryExec"));
    if (!tryExec.isEmpty()) {
        const QStringList parts = splitExec(tryExec);
        if (!parts.isEmpty())
            return parts.first();
    }

    const QString exec = valueForKey(contents, QStringLiteral("Exec"));
    for (const QString &token : splitExec(exec)) {
        if (isFieldCode(token))
            continue;
        // env VAR=value /usr/bin/program — step over the wrapper and its
        // assignments to reach the program actually being launched.
        if (token == QLatin1String("env"))
            continue;
        if (token.contains(QLatin1Char('=')) && !token.contains(QLatin1Char('/')))
            continue;
        return token;
    }
    return {};
}

QString resolveApplicationTarget(const QString &pathOrUrl)
{
    QString path = pathOrUrl.trimmed();
    if (path.isEmpty())
        return {};
    if (path.startsWith(QLatin1String("file:")))
        path = QUrl(path).toLocalFile();
    if (path.isEmpty())
        return {};

    const QFileInfo info(path);
    const QString suffix = info.suffix().toLower();

    if (suffix == QLatin1String("desktop") && info.isFile()) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
            return {};
        const QString contents = QString::fromUtf8(f.readAll());
        // Checked first: for a sandboxed program the launcher path is a real
        // file and would resolve perfectly well — to the wrong thing.
        const QString sandboxed = sandboxedProgramFromDesktopEntry(contents);
        if (!sandboxed.isEmpty())
            return sandboxed;
        return absoluteExecutable(executableFromDesktopEntry(contents));
    }

    if (suffix == QLatin1String("app") && info.isDir())
        return executableInsideBundle(path);

#ifdef Q_OS_WIN
    if (suffix == QLatin1String("lnk") && info.isFile())
        return resolveWindowsShortcut(path);
#endif

    // Anything else has to already be a program. A directory that is not a
    // bundle, or a document someone dropped by mistake, resolves to nothing
    // rather than becoming a rule that silently never matches.
    if (!info.isFile())
        return {};
    return QDir::toNativeSeparators(info.absoluteFilePath());
}

} // namespace freetunnel
