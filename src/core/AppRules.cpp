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

QString appBundleOf(const QString &path)
{
    // Implemented on the string rather than the filesystem so it works for a
    // process path reported by a machine we are not standing on, and so it can
    // be tested where the tests run.
    // Not named `unix`: that is a predefined macro on Linux and the file stops
    // compiling in a way that reads like a parser bug.
    const QString slashed = QDir::fromNativeSeparators(path);
    const qsizetype marker = slashed.indexOf(QLatin1String(".app/Contents/"));
    if (marker < 0)
        return {};
    return QDir::toNativeSeparators(slashed.left(marker + 4)); // keep ".app"
}

namespace {

// One rule against one program. Pulled out of the loop so the loop is a loop:
// the decision below is three separate questions, and they read as three.
bool oneRuleMatches(const QString &norm, const QString &path, const QString &name,
                    Qt::CaseSensitivity cs)
{
    if (norm.isEmpty())
        return false;
    if (!looksLikePath(norm))
        return !name.isEmpty() && name.compare(norm, cs) == 0;
    if (!path.isEmpty() && path.compare(norm, cs) == 0)
        return true;
    // Same application, different binary inside it. Only when BOTH are in a
    // bundle — a bare directory prefix match would make a rule for one program
    // cover every program beside it.
    const QString ruleBundle = appBundleOf(norm);
    return !ruleBundle.isEmpty() && !path.isEmpty()
            && ruleBundle.compare(appBundleOf(path), cs) == 0;
}

} // namespace

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
        if (oneRuleMatches(normalizedAppRule(rule), path, name, cs))
            return true;
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
