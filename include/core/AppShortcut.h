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
// Returns an absolute path to an existing file, or an empty string when the
// argument is not a program and does not lead to one. Accepts a plain path or a
// file: URL.
QString resolveApplicationTarget(const QString &pathOrUrl);

// The Exec/TryExec program named by the contents of a .desktop entry, without
// its arguments or field codes. Separated from the file handling so the parsing
// can be tested on every platform, not only where .desktop files are native.
// Returns an empty string when the entry names nothing usable.
QString executableFromDesktopEntry(const QString &contents);

} // namespace freetunnel
