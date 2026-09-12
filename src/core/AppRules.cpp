// cppcheck-suppress-file missingIncludeSystem
#include "core/AppRules.h"

#include <QDir>
#include <QFileInfo>
#include <QSet>

namespace freetunnel {

Qt::CaseSensitivity appPathCaseSensitivity()
{
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}

namespace {

// Users paste paths out of file managers and terminals, which is where the
// quotes come from.
QString unquote(const QString &s)
{
    QString r = s.trimmed();
    if (r.size() >= 2 && ((r.startsWith(QLatin1Char('"')) && r.endsWith(QLatin1Char('"')))
                          || (r.startsWith(QLatin1Char('\'')) && r.endsWith(QLatin1Char('\''))))) {
        r = r.mid(1, r.size() - 2).trimmed();
    }
    return r;
}

bool looksLikePath(const QString &rule)
{
    return rule.contains(QLatin1Char('/')) || rule.contains(QLatin1Char('\\'));
}

// A file name with nothing a path separator could hide in. Control characters
// are rejected outright: they cannot appear in a name the OS will report back
// to us, so a rule containing one can only ever be a mistake or an attempt to
// make a stored rule print as something other than what it matches.
bool isPlausibleFileName(const QString &name)
{
    if (name.isEmpty() || name.size() > 255)
        return false;
    if (name == QLatin1String(".") || name == QLatin1String(".."))
        return false;
    for (const QChar c : name) {
        if (c.unicode() < 0x20 || c.unicode() == 0x7F)
            return false;
    }
    return true;
}

} // namespace

QString normalizedAppRule(const QString &rule)
{
    const QString r = unquote(rule);
    if (r.isEmpty())
        return {};

    // A trailing separator is the user saying "directory", and a rule names one
    // program, not a folder of them. Reject it here rather than after cleaning
    // the path, because by then "/usr/bin/" has become "/usr/bin" and is
    // indistinguishable from a rule for a program that happens to be called bin.
    if (r.size() > 1 && (r.endsWith(QLatin1Char('/')) || r.endsWith(QLatin1Char('\\'))))
        return {};

    if (!looksLikePath(r))
        return isPlausibleFileName(r) ? r : QString();

    // QDir::cleanPath resolves "." and ".." segments and collapses repeated
    // separators, so two spellings of the same path compare equal. It leaves
    // symlinks alone, which is correct here: we are naming a rule, not opening
    // a file, and resolving links at rule-entry time would bake in whatever the
    // link pointed at that day.
    QString path = QDir::cleanPath(QDir::fromNativeSeparators(r));
    if (path.endsWith(QLatin1Char('/')) && path.size() > 1)
        path.chop(1);

    const QFileInfo info(path);
    if (!info.isAbsolute())
        return {};
    if (!isPlausibleFileName(info.fileName()))
        return {};

    return QDir::toNativeSeparators(path);
}

bool isValidAppRule(const QString &rule)
{
    return !normalizedAppRule(rule).isEmpty();
}

QStringList sanitizedAppRules(const QStringList &rules)
{
    QStringList out;
    QSet<QString> seen;
    for (const QString &rule : rules) {
        const QString norm = normalizedAppRule(rule);
        if (norm.isEmpty())
            continue;
        // Dedupe on the comparison form, store the normalized one. On a
        // case-insensitive platform two spellings of one path are one rule.
        const QString key = appPathCaseSensitivity() == Qt::CaseInsensitive ? norm.toLower() : norm;
        if (seen.contains(key))
            continue;
        seen.insert(key);
        out.append(norm);
    }
    return out;
}

bool appMatchesRules(const AppIdentity &app, const QStringList &rules)
{
    if (app.executablePath.isEmpty() && app.name.isEmpty())
        return false;

    const Qt::CaseSensitivity cs = appPathCaseSensitivity();
    const QString path = app.executablePath.isEmpty()
            ? QString()
            : QDir::toNativeSeparators(QDir::cleanPath(QDir::fromNativeSeparators(app.executablePath)));
    // Prefer the name the OS gave us, but a lookup that only produced a path
    // still has to match bare-name rules, so derive one when it is missing.
    const QString name = !app.name.isEmpty() ? app.name : QFileInfo(path).fileName();

    for (const QString &rule : rules) {
        const QString norm = normalizedAppRule(rule);
        if (norm.isEmpty())
            continue;
        if (looksLikePath(norm)) {
            if (!path.isEmpty() && path.compare(norm, cs) == 0)
                return true;
        } else if (!name.isEmpty() && name.compare(norm, cs) == 0) {
            return true;
        }
    }
    return false;
}

AppAction appActionFor(const AppIdentity &app, const QStringList &rules, bool selectiveMode)
{
    if (rules.isEmpty())
        return AppAction::Default;
    if (!appMatchesRules(app, rules))
        return AppAction::Default;
    return selectiveMode ? AppAction::ForceTunnel : AppAction::ForceBypass;
}

} // namespace freetunnel
