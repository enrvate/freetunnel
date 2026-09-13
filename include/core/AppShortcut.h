// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <QString>

namespace freetunnel {

// Turn whatever a person dropped on the window — or picked in a file dialog —
// into the executable it stands for.
//
// Nobody drags a binary out of /usr/bin. They drag the icon they already have:
// a .desktop entry on Linux, a .lnk shortcut on Windows, an .app bundle on
// macOS. Each of those names a program without being one, so each has to be
// followed to the thing that will actually show up in the system's socket table
// — which is the only name a rule can ever match.
//
// Returns the name a rule should use: an absolute path to an existing file,
// or — for a program that runs inside a sandbox — a bare program name. Empty
// when the argument is not a program and does not lead to one. Accepts a plain
// path or a file: URL.
//
// The sandbox case is not a nicety. A Flatpak entry launches
// "/usr/bin/flatpak run … com.anydesk.Anydesk", so following it naively yields
// /usr/bin/flatpak — and a bypass rule for that would take EVERY Flatpak
// program out of the tunnel, not the one that was asked for. The process the
// system actually reports is /app/extra/anydesk, inside the sandbox, so a bare
// name is what matches it.
QString resolveApplicationTarget(const QString &pathOrUrl);

// The Exec/TryExec program named by the contents of a .desktop entry, without
// its arguments or field codes. Separated from the file handling so the parsing
// can be tested on every platform, not only where .desktop files are native.
// Returns an empty string when the entry names nothing usable.
QString executableFromDesktopEntry(const QString &contents);

// The program a .desktop entry launches through a sandbox runner, as a bare
// name, or empty when the entry is not one of those. Exposed for testing, and
// because the list of installed applications needs the same answer.
QString sandboxedProgramFromDesktopEntry(const QString &contents);

// The value of one key in a .desktop entry's [Desktop Entry] group, or empty.
// Shared rather than reimplemented: InstalledApps had a byte-identical copy, and
// two copies of a parser are two places to fix the next quirk in.
QString desktopEntryValue(const QString &contents, const QString &key);

} // namespace freetunnel
