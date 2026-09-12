// cppcheck-suppress-file missingIncludeSystem
// Nobody drags a binary out of /usr/bin — they drag the icon they already have,
// which is a shortcut naming a program without being one. Following it wrongly
// is worse than not following it: a rule built from a mis-parsed Exec= line is
// stored, listed back to the user, and never matches anything.
#include <QtTest>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include "core/AppShortcut.h"

class TestAppShortcut : public QObject {
    Q_OBJECT

private slots:
    void readsTheProgramOutOfADesktopEntry();
    void readsTheProgramOutOfADesktopEntry_data();
    void ignoresExecLinesOutsideTheDesktopEntryGroup();
    void aDroppedDesktopFileResolvesToItsProgram();
    void aDroppedProgramResolvesToItself();
    void aMacBundleResolvesToTheProgramInside();
    void thingsThatAreNotProgramsResolveToNothing();
    void acceptsAFileUrlAsWellAsAPath();
    void aSandboxedAppResolvesToItsOwnNameNotTheLauncher();
    void aSandboxedAppResolvesToItsOwnNameNotTheLauncher_data();
    void aBundleDraggedFromFinderCarriesATrailingSlash();
    void aBundleDeclaresItsOwnExecutableName();
};

void TestAppShortcut::readsTheProgramOutOfADesktopEntry_data()
{
    QTest::addColumn<QString>("contents");
    QTest::addColumn<QString>("expected");

    QTest::newRow("plain") << QStringLiteral("[Desktop Entry]\nExec=/usr/bin/firefox\n")
                           << QStringLiteral("/usr/bin/firefox");
    // The field code is substituted by the launcher and is not part of the name.
    QTest::newRow("field code") << QStringLiteral("[Desktop Entry]\nExec=/usr/bin/firefox %u\n")
                                << QStringLiteral("/usr/bin/firefox");
    // Program directories contain spaces; quoting is how a .desktop file says so.
    QTest::newRow("quoted path with spaces")
            << QStringLiteral("[Desktop Entry]\nExec=\"/opt/My App/app\" --new-window\n")
            << QStringLiteral("/opt/My App/app");
    // TryExec names the binary with nothing attached, so it wins when present.
    QTest::newRow("TryExec preferred")
            << QStringLiteral("[Desktop Entry]\nTryExec=/usr/bin/code\nExec=/usr/bin/code --unity-launch %F\n")
            << QStringLiteral("/usr/bin/code");
    // Wrappers: step over `env` and its assignments to the real program.
    QTest::newRow("env wrapper")
            << QStringLiteral("[Desktop Entry]\nExec=env GDK_BACKEND=x11 /usr/bin/signal-desktop %u\n")
            << QStringLiteral("/usr/bin/signal-desktop");
    QTest::newRow("bare name") << QStringLiteral("[Desktop Entry]\nExec=firefox %u\n")
                               << QStringLiteral("firefox");
    QTest::newRow("no exec") << QStringLiteral("[Desktop Entry]\nName=Thing\n") << QString();
    QTest::newRow("empty") << QString() << QString();
}

void TestAppShortcut::readsTheProgramOutOfADesktopEntry()
{
    QFETCH(QString, contents);
    QFETCH(QString, expected);
    QCOMPARE(freetunnel::executableFromDesktopEntry(contents), expected);
}

// Desktop actions ("Open a New Window") carry their own Exec= lines. Reading one
// of those instead of the entry's own would name the right program by luck, or a
// different one by accident.
void TestAppShortcut::ignoresExecLinesOutsideTheDesktopEntryGroup()
{
    const QString contents = QStringLiteral(
            "[Desktop Entry]\n"
            "Exec=/usr/bin/firefox %u\n"
            "\n"
            "[Desktop Action new-private-window]\n"
            "Exec=/usr/bin/firefox-private --private-window\n");
    QCOMPARE(freetunnel::executableFromDesktopEntry(contents), QStringLiteral("/usr/bin/firefox"));
}

void TestAppShortcut::aDroppedDesktopFileResolvesToItsProgram()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    // A real program to point at, so the resolver's existence check has
    // something to find.
    const QString program = dir.filePath(QStringLiteral("someprogram"));
    QFile bin(program);
    QVERIFY(bin.open(QIODevice::WriteOnly));
    bin.write("#!/bin/sh\n");
    bin.close();

    const QString entry = dir.filePath(QStringLiteral("thing.desktop"));
    QFile f(entry);
    QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Text));
    f.write(QStringLiteral("[Desktop Entry]\nType=Application\nExec=\"%1\" %u\n")
                    .arg(program)
                    .toUtf8());
    f.close();

    QCOMPARE(freetunnel::resolveApplicationTarget(entry), QDir::toNativeSeparators(program));
}

void TestAppShortcut::aDroppedProgramResolvesToItself()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString program = dir.filePath(QStringLiteral("plainprogram"));
    QFile bin(program);
    QVERIFY(bin.open(QIODevice::WriteOnly));
    bin.close();

    QCOMPARE(freetunnel::resolveApplicationTarget(program), QDir::toNativeSeparators(program));
}

// Built and tested everywhere, not only on macOS: a person can drop a bundle
// that came from a shared folder, and the logic should be judged where the
// tests actually run.
void TestAppShortcut::aMacBundleResolvesToTheProgramInside()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString bundle = dir.filePath(QStringLiteral("Some App.app"));
    QVERIFY(QDir().mkpath(bundle + QStringLiteral("/Contents/MacOS")));
    const QString inner = bundle + QStringLiteral("/Contents/MacOS/Some App");
    QFile bin(inner);
    QVERIFY(bin.open(QIODevice::WriteOnly));
    bin.close();

    QCOMPARE(freetunnel::resolveApplicationTarget(bundle), QDir::toNativeSeparators(inner));
}

// A document, a folder, a shortcut pointing at something that is gone. Each has
// to produce nothing, so the caller can say "that is not a program" instead of
// storing a rule that can never fire.
void TestAppShortcut::thingsThatAreNotProgramsResolveToNothing()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    QVERIFY(freetunnel::resolveApplicationTarget(QString()).isEmpty());
    QVERIFY(freetunnel::resolveApplicationTarget(QStringLiteral("   ")).isEmpty());
    QVERIFY(freetunnel::resolveApplicationTarget(dir.path()).isEmpty()); // a plain directory
    QVERIFY(freetunnel::resolveApplicationTarget(dir.filePath(QStringLiteral("missing"))).isEmpty());

    // A .desktop entry naming a program that is not installed.
    const QString entry = dir.filePath(QStringLiteral("broken.desktop"));
    QFile f(entry);
    QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Text));
    f.write("[Desktop Entry]\nExec=/nonexistent/nothing %u\n");
    f.close();
    QVERIFY(freetunnel::resolveApplicationTarget(entry).isEmpty());

    // A bundle with nothing inside it.
    const QString emptyBundle = dir.filePath(QStringLiteral("Empty.app"));
    QVERIFY(QDir().mkpath(emptyBundle + QStringLiteral("/Contents/MacOS")));
    QVERIFY(freetunnel::resolveApplicationTarget(emptyBundle).isEmpty());
}

// A drop hands over a file: URL, not a path.
void TestAppShortcut::acceptsAFileUrlAsWellAsAPath()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    // With a space in the name, because that is where URL decoding goes wrong.
    const QString program = dir.filePath(QStringLiteral("my program"));
    QFile bin(program);
    QVERIFY(bin.open(QIODevice::WriteOnly));
    bin.close();

    QCOMPARE(freetunnel::resolveApplicationTarget(QUrl::fromLocalFile(program).toString()),
             QDir::toNativeSeparators(program));
}

void TestAppShortcut::aSandboxedAppResolvesToItsOwnNameNotTheLauncher_data()
{
    QTest::addColumn<QString>("contents");
    QTest::addColumn<QString>("expected");

    // The real AnyDesk entry, which is what exposed this: following it naively
    // gives /usr/bin/flatpak, and a bypass rule for the launcher would take
    // every Flatpak program out of the tunnel instead of this one. The process
    // the system reports is /app/extra/anydesk, so the bare name matches it.
    QTest::newRow("flatpak with --command")
            << QStringLiteral("[Desktop Entry]\nType=Application\n"
                              "Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 "
                              "--command=anydesk --file-forwarding com.anydesk.Anydesk @@u %u @@\n")
            << QStringLiteral("anydesk");
    // Without --command the application id is the only handle there is.
    QTest::newRow("flatpak without --command")
            << QStringLiteral("[Desktop Entry]\nExec=/usr/bin/flatpak run com.spotify.Client\n")
            << QStringLiteral("client");
    QTest::newRow("snap run")
            << QStringLiteral("[Desktop Entry]\nExec=snap run chromium %U\n")
            << QStringLiteral("chromium");
    // /snap/bin/x is a wrapper script; the program lives under /snap/x/current.
    QTest::newRow("snap wrapper path")
            << QStringLiteral("[Desktop Entry]\nExec=/snap/bin/telegram-desktop %u\n")
            << QStringLiteral("telegram-desktop");
    // An ordinary program must NOT be turned into a bare name: naming one copy
    // of it precisely is the whole point of a path rule.
    QTest::newRow("not sandboxed")
            << QStringLiteral("[Desktop Entry]\nExec=/usr/bin/firefox %u\n") << QString();
}

void TestAppShortcut::aSandboxedAppResolvesToItsOwnNameNotTheLauncher()
{
    QFETCH(QString, contents);
    QFETCH(QString, expected);
    QCOMPARE(freetunnel::sandboxedProgramFromDesktopEntry(contents), expected);

    // And the whole-file path agrees, so a dropped icon and the installed-apps
    // list cannot disagree about the same entry.
    if (!expected.isEmpty()) {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString entry = dir.filePath(QStringLiteral("sandboxed.desktop"));
        QFile f(entry);
        QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Text));
        f.write(contents.toUtf8());
        f.close();
        QCOMPARE(freetunnel::resolveApplicationTarget(entry), expected);
    }
}

// Reported from a real macOS desktop: dragging an application out of
// /Applications was answered with "that is not a program". Finder hands over a
// directory with a trailing slash, a .app IS a directory, and with the slash
// left on QFileInfo::suffix() is empty — so the bundle was never recognised as
// one. Every spelling a drop can arrive in has to work.
void TestAppShortcut::aBundleDraggedFromFinderCarriesATrailingSlash()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString bundle = dir.filePath(QStringLiteral("Safari.app"));
    QVERIFY(QDir().mkpath(bundle + QStringLiteral("/Contents/MacOS")));
    const QString inner = bundle + QStringLiteral("/Contents/MacOS/Safari");
    QFile bin(inner);
    QVERIFY(bin.open(QIODevice::WriteOnly));
    bin.close();
    const QString expected = QDir::toNativeSeparators(inner);

    QCOMPARE(freetunnel::resolveApplicationTarget(bundle), expected);
    QCOMPARE(freetunnel::resolveApplicationTarget(bundle + QStringLiteral("/")), expected);
    QCOMPARE(freetunnel::resolveApplicationTarget(QUrl::fromLocalFile(bundle).toString()), expected);
    QCOMPARE(freetunnel::resolveApplicationTarget(QUrl::fromLocalFile(bundle).toString()
                                                  + QStringLiteral("/")),
             expected);
}

// A bundle's executable is not always named after the bundle — Visual Studio
// Code's is Electron. Its own Info.plist is the authority, so ask that before
// guessing from the name.
void TestAppShortcut::aBundleDeclaresItsOwnExecutableName()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString bundle = dir.filePath(QStringLiteral("Some Editor.app"));
    QVERIFY(QDir().mkpath(bundle + QStringLiteral("/Contents/MacOS")));

    // Two programs inside, so neither the name guess nor the single-file
    // fallback can produce the answer — only the plist can.
    for (const QString &name : {QStringLiteral("Electron"), QStringLiteral("helper")}) {
        QFile bin(bundle + QStringLiteral("/Contents/MacOS/") + name);
        QVERIFY(bin.open(QIODevice::WriteOnly));
        bin.close();
    }
    QFile plist(bundle + QStringLiteral("/Contents/Info.plist"));
    QVERIFY(plist.open(QIODevice::WriteOnly | QIODevice::Text));
    plist.write("<?xml version=\"1.0\"?>\n<plist><dict>\n"
                "<key>CFBundleName</key><string>Some Editor</string>\n"
                "<key>CFBundleExecutable</key><string>Electron</string>\n"
                "</dict></plist>\n");
    plist.close();

    QCOMPARE(freetunnel::resolveApplicationTarget(bundle),
             QDir::toNativeSeparators(bundle + QStringLiteral("/Contents/MacOS/Electron")));
}

QTEST_MAIN(TestAppShortcut)
#include "test_appshortcut.moc"
