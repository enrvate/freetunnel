// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QtGlobal>

#include <QString>
#include <QStringList>

namespace freetunnel {

struct HelperLaunchConfig {
    quint16 port = 0;
    QString token;
    bool ok() const { return port != 0 && !token.isEmpty(); }
};

/// Parse `--helper --port P --token-file F` arguments (reads and deletes token file).
HelperLaunchConfig parseHelperLaunchArgs(const QStringList &args);

/// Read a one-time token from a helper launch file and remove the file.
QString readHelperTokenFile(const QString &path);

// Build the argv that pkexec is asked to run AS ROOT on Linux.
//
// @p appImage must come from the kernel (runningAppImagePath()), never from
// $APPIMAGE or $APPDIR: an attacker who can set the GUI's environment sets both
// sides of any check between them, and this string names the binary the user is
// about to authorize as root. Empty means "not an AppImage build" and the running
// executable is used instead.
//
// Declared here, beside the parser that reads these arguments back, because it
// used to be file-local in vpn_helper_client.cpp and therefore untested — the one
// function in the codebase whose output is executed with full privilege.
QStringList linuxHelperCommand(const QString &exe, const QString &appImage, quint16 port,
                               const QString &tokenPath);

} // namespace freetunnel
