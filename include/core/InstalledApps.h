// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QList>
#include <QString>

namespace freetunnel {

// One program as a person would recognise it, paired with the name a rule can
// actually match.
struct InstalledApp {
    QString name;           // "Firefox Web Browser"
    QString executablePath; // "/usr/lib/firefox/firefox"
};

// Everything the system lists as an installed application: .desktop entries on
// Linux (including Flatpak and Snap, since those register entries like anything
// else), Start Menu shortcuts on Windows, .app bundles on macOS.
//
// Sorted by name and deduplicated by executable, because one program routinely
// has several entries — a Flatpak and a distribution package, or a Start Menu
// shortcut in both the machine-wide and the per-user tree.
//
// Slow enough to be worth doing off the interface thread: on Windows every
// shortcut has to be resolved through the shell to find out what it points at.
QList<InstalledApp> installedApplications();

// Whether an entry should be offered to a person at all. Entries exist that are
// deliberately not shown in menus — MIME handlers, per-session helpers — and
// listing those would bury the programs someone is actually looking for.
bool desktopEntryIsVisibleApplication(const QString &contents);

// The Name= of a .desktop entry. Separated from the file handling so the
// parsing is tested on every platform, not only where .desktop files are native.
QString displayNameFromDesktopEntry(const QString &contents);

} // namespace freetunnel
