// cppcheck-suppress-file missingIncludeSystem
// The picker exists so nobody has to know a path. That only works if the list is
// the list a person recognises: the programs they launch, each named once, and
// none of the invisible entries the desktop keeps for its own bookkeeping.
#include <QtTest>

#include "core/InstalledApps.h"

class TestInstalledApps : public QObject {
    Q_OBJECT

private slots:
    void offersOnlyEntriesMeantToBeSeen();
    void offersOnlyEntriesMeantToBeSeen_data();
    void readsTheDisplayName();
    void theScanIsSaneOnThisMachine();
};

void TestInstalledApps::offersOnlyEntriesMeantToBeSeen_data()
{
    QTest::addColumn<QString>("contents");
    QTest::addColumn<bool>("visible");

    QTest::newRow("ordinary application")
            << QStringLiteral("[Desktop Entry]\nType=Application\nName=Thing\nExec=/usr/bin/thing\n") << true;
    // NoDisplay is how a MIME handler or a session helper says "I am not a thing
    // in the menu". Listing those would bury the programs someone is looking for.
    QTest::newRow("NoDisplay")
            << QStringLiteral("[Desktop Entry]\nType=Application\nNoDisplay=true\nName=Helper\n") << false;
    QTest::newRow("NoDisplay capitalised")
            << QStringLiteral("[Desktop Entry]\nType=Application\nNoDisplay=True\nName=Helper\n") << false;
    QTest::newRow("Hidden")
            << QStringLiteral("[Desktop Entry]\nType=Application\nHidden=true\nName=Gone\n") << false;
    // A link or a directory entry is not a program and cannot be a rule.
    QTest::newRow("Type=Link")
            << QStringLiteral("[Desktop Entry]\nType=Link\nName=Somewhere\nURL=https://x\n") << false;
    QTest::newRow("no Type at all") << QStringLiteral("[Desktop Entry]\nName=Mystery\n") << false;
    QTest::newRow("empty") << QString() << false;
}

void TestInstalledApps::offersOnlyEntriesMeantToBeSeen()
{
    QFETCH(QString, contents);
    QFETCH(bool, visible);
    QCOMPARE(freetunnel::desktopEntryIsVisibleApplication(contents), visible);
}

void TestInstalledApps::readsTheDisplayName()
{
    QCOMPARE(freetunnel::displayNameFromDesktopEntry(
                     QStringLiteral("[Desktop Entry]\nType=Application\nName=Firefox Web Browser\n")),
             QStringLiteral("Firefox Web Browser"));
    // A name from a desktop action is not this entry's name.
    QCOMPARE(freetunnel::displayNameFromDesktopEntry(QStringLiteral(
                     "[Desktop Entry]\nName=Firefox\n\n[Desktop Action new-window]\nName=New Window\n")),
             QStringLiteral("Firefox"));
    QVERIFY(freetunnel::displayNameFromDesktopEntry(QStringLiteral("[Desktop Entry]\n")).isEmpty());
}

// Not an assertion about this machine's software, which the test cannot know:
// an assertion about the shape of whatever it finds. A scan that returned rows
// with an empty name, an empty target, or the same program twice would make the
// picker useless in a way no amount of parser testing would catch.
void TestInstalledApps::theScanIsSaneOnThisMachine()
{
    QElapsedTimer timer;
    timer.start();
    const QList<freetunnel::InstalledApp> apps = freetunnel::installedApplications();
    const qint64 elapsed = timer.elapsed();

    QSet<QString> targets;
    for (const freetunnel::InstalledApp &app : apps) {
        QVERIFY2(!app.name.isEmpty(), "a row with no name is a row nobody can pick");
        QVERIFY2(!app.executablePath.isEmpty(), "a row with no target cannot become a rule");
        QVERIFY2(!targets.contains(app.executablePath),
                 qPrintable(QStringLiteral("listed twice: %1").arg(app.executablePath)));
        targets.insert(app.executablePath);
    }

    // The picker opens on this call, so it has to be quick enough not to be felt.
    // Generous, because a CI runner is not a desktop and Windows resolves every
    // Start Menu shortcut through the shell.
    QVERIFY2(elapsed < 10000, qPrintable(QStringLiteral("scan took %1 ms").arg(elapsed)));
}

QTEST_MAIN(TestInstalledApps)
#include "test_installedapps.moc"
