// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QString>
#include <QStringList>
#include <Qt>

namespace freetunnel {

// Which process a connection came from. Filled in by the platform lookup in
// ProcessLookup.h; either field may be empty when the OS would not say.
struct AppIdentity {
    QString executablePath; // absolute path of the running binary
    QString name;           // file name only, no directories
};

// What to do with one connection, before domain and route rules get a say.
enum class AppAction {
    Default,     // no app rule applies: fall through to the existing rules
    ForceBypass, // leave the tunnel, unconditionally
    ForceTunnel, // enter the tunnel, unconditionally
};

// Paths are compared case-insensitively on Windows and macOS and
// case-sensitively on Linux, because that is what each filesystem means by "the
// same file". Getting this wrong in the lax direction is not merely untidy: a
// bypass rule that matches a file the user did not mean sends that program's
// traffic outside the tunnel.
Qt::CaseSensitivity appPathCaseSensitivity();

// UI validation. A rule is either an absolute path to an executable or a bare
// executable file name; anything else is rejected rather than stored, so the
// user is never shown a rule that cannot match.
bool isValidAppRule(const QString &rule);

// Storage and comparison form: trimmed, unquoted, separators normalized to the
// platform's. Empty when the rule is not one.
QString normalizedAppRule(const QString &rule);

// Drop what cannot match and dedupe, keeping the first spelling of each rule.
QStringList sanitizedAppRules(const QStringList &rules);

// The .app bundle a path lives inside, or empty when it is not inside one.
// "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT" -> "/Applications/ChatGPT.app"
QString appBundleOf(const QString &path);

// The directory a program has to itself, or empty when it does not have one.
// "/usr/lib/firefox/firefox" -> "/usr/lib/firefox", because the directory is
// named after the program in it; "/usr/bin/firefox" -> empty, because /usr/bin
// belongs to everyone.
//
// This is the same idea as a .app bundle, spelled the way the other platforms
// spell it. A program installed in its own directory keeps its helpers there
// beside it, and the naming test is what keeps it from meaning "everything in
// /usr/bin": a program would have to be called "bin" to widen that.
QString appDirectoryOf(const QString &path);

// Does any rule name this program? A path rule matches the whole path; a bare
// name matches the file name of any path.
//
// On macOS a path rule also matches anything inside the same .app bundle. That
// is not a convenience: a browser-like program does its networking from a
// separate helper process that lives inside its own bundle, so the connections
// a user wants routed never come from the executable they picked. Matching the
// bundle is what makes a rule mean the application rather than one binary.
//
// A rule that names a program in a directory of its own does the same, for the
// same reason. Reported from a Linux desktop: a rule on the Firefox the menu
// entry points at, /usr/lib/firefox/firefox, matched nothing at all, because
// that file is a five-kilobyte stub whose whole job is to exec firefox-bin —
// and exec keeps the pid, so every running process says firefox-bin. The rule
// named a file that is never a running program.
bool appMatchesRules(const AppIdentity &app, const QStringList &rules);

// The decision for one connection. `selectiveMode` is the existing split-tunnel
// mode: false means "everything through the VPN except what is listed", true
// means "only what is listed goes through the VPN". App rules follow that same
// sense, so a user does not have to hold two opposite mental models at once.
//
// An identity that could not be resolved at all matches nothing and returns
// Default. That is deliberate: the alternative is to guess, and guessing wrong
// here either leaks a tunnelled program onto the open network or silently
// tunnels one the user excluded.
AppAction appActionFor(const AppIdentity &app, const QStringList &rules, bool selectiveMode);

} // namespace freetunnel
