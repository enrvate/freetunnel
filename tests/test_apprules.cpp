// cppcheck-suppress-file missingIncludeSystem
// App rules decide whether one program's traffic leaves the tunnel. The failure
// that matters is not "a rule did not work" — the user notices that — but "a
// rule matched something the user did not name", because the consequence is
// traffic going outside the VPN while the interface says it is protected. So
// most of what is asserted here is about what must NOT match.
#include <QtTest>

#include <QDir>

#include "core/AppRules.h"

using freetunnel::AppAction;
using freetunnel::AppIdentity;

namespace {

// Absolute paths look different on Windows, and normalizedAppRule() rejects a
// relative one, so the fixtures have to be built per platform rather than
// written out as literals.
QString absPath(const QString &tail)
{
#ifdef Q_OS_WIN
    return QStringLiteral("C:\\") + QString(tail).replace(QLatin1Char('/'), QLatin1Char('\\'));
#else
    return QStringLiteral("/") + tail;
#endif
}

AppIdentity appAt(const QString &path)
{
    return AppIdentity{path, QFileInfo(path).fileName()};
}

} // namespace

class TestAppRules : public QObject {
    Q_OBJECT

private slots:
    void aBareNameMatchesTheProgramWhereverItLives();
    void aPathRuleMatchesOnlyThatPath();
    void anUnresolvedProcessMatchesNothing();
    void rejectsWhatCannotBeAnExecutable();
    void rejectsWhatCannotBeAnExecutable_data();
    void spellingsOfOnePathAreOneRule();
    void aRelativePathIsNotARule();
    void modeDecidesWhichWayAMatchGoes();
    void anEmptyRuleListNeverForcesAnything();
    void caseFollowsTheFilesystem();
    void quotesAndSpacesSurviveTheRoundTrip();
    void aRuleMeansTheApplicationNotOneBinaryInsideIt();
};

// The ordinary case: the user types "firefox" and means firefox, wherever the
// distribution decided to put it.
void TestAppRules::aBareNameMatchesTheProgramWhereverItLives()
{
    const QStringList rules{QStringLiteral("firefox")};
    QVERIFY(freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("usr/bin/firefox"))), rules));
    QVERIFY(freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("opt/firefox/firefox"))), rules));
    // ...and means firefox, not something that merely contains the word.
    QVERIFY(!freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("usr/bin/firefox-esr"))), rules));
    QVERIFY(!freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("usr/bin/notfirefox"))), rules));
    QVERIFY(!freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("home/me/firefox/README"))), rules));
}

// A path rule is the precise form: it must not degrade into a name match, or
// naming one copy of a program would quietly cover every other copy.
void TestAppRules::aPathRuleMatchesOnlyThatPath()
{
    const QStringList rules{absPath(QStringLiteral("usr/bin/curl"))};
    QVERIFY(freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("usr/bin/curl"))), rules));
    QVERIFY(!freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("usr/local/bin/curl"))), rules));
    QVERIFY(!freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("home/me/bin/curl"))), rules));
}

// The lookup fails sometimes — a socket that closed before we asked, a process
// we may not read. Whatever happens then, it must not be "matches everything".
void TestAppRules::anUnresolvedProcessMatchesNothing()
{
    const QStringList rules{QStringLiteral("firefox"), absPath(QStringLiteral("usr/bin/curl"))};
    QVERIFY(!freetunnel::appMatchesRules(AppIdentity{}, rules));
    QVERIFY(!freetunnel::appMatchesRules(AppIdentity{QString(), QString()}, rules));
    QCOMPARE(freetunnel::appActionFor(AppIdentity{}, rules, false), AppAction::Default);
    QCOMPARE(freetunnel::appActionFor(AppIdentity{}, rules, true), AppAction::Default);
}

void TestAppRules::rejectsWhatCannotBeAnExecutable_data()
{
    QTest::addColumn<QString>("rule");
    QTest::newRow("empty") << QString();
    QTest::newRow("blank") << QStringLiteral("   ");
    QTest::newRow("dot") << QStringLiteral(".");
    QTest::newRow("dotdot") << QStringLiteral("..");
    QTest::newRow("newline in a name") << QStringLiteral("fire\nfox");
    QTest::newRow("tab in a name") << QStringLiteral("fire\tfox");
    QTest::newRow("null in a name") << QStringLiteral("fire\0fox");
    // A rule is a program, not a directory of them.
    QTest::newRow("bare separator") << QStringLiteral("/");
    QTest::newRow("trailing separator") << absPath(QStringLiteral("usr/bin/"));
}

void TestAppRules::rejectsWhatCannotBeAnExecutable()
{
    QFETCH(QString, rule);
    QVERIFY2(!freetunnel::isValidAppRule(rule), qPrintable(QStringLiteral("accepted: %1").arg(rule)));
    QVERIFY(freetunnel::normalizedAppRule(rule).isEmpty());
    // And nothing the UI rejects may survive into the list the matcher reads.
    QVERIFY(freetunnel::sanitizedAppRules({rule}).isEmpty());
}

// Two spellings of one path are one rule, or the list grows a duplicate every
// time the user pastes from a different place.
void TestAppRules::spellingsOfOnePathAreOneRule()
{
    const QString plain = absPath(QStringLiteral("usr/bin/curl"));
    const QString roundabout = absPath(QStringLiteral("usr/lib/../bin/./curl"));
    QCOMPARE(freetunnel::normalizedAppRule(roundabout), freetunnel::normalizedAppRule(plain));

    const QStringList sanitized = freetunnel::sanitizedAppRules({plain, roundabout, plain});
    QCOMPARE(sanitized.size(), 1);
    QCOMPARE(sanitized.first(), freetunnel::normalizedAppRule(plain));

    // The roundabout spelling still matches the program it names.
    QVERIFY(freetunnel::appMatchesRules(appAt(plain), {roundabout}));
}

// Relative paths cannot be resolved against anything meaningful here — the
// lookup reports absolute paths — so accepting one would store a rule that can
// never match.
void TestAppRules::aRelativePathIsNotARule()
{
    QVERIFY(!freetunnel::isValidAppRule(QStringLiteral("bin/curl")));
    QVERIFY(!freetunnel::isValidAppRule(QStringLiteral("./curl")));
    QVERIFY(!freetunnel::isValidAppRule(QStringLiteral("../curl")));
#ifdef Q_OS_WIN
    QVERIFY(!freetunnel::isValidAppRule(QStringLiteral("bin\\curl.exe")));
#endif
}

// The same list means opposite things in the two split-tunnel modes, exactly as
// the existing route and domain rules do. A user should not have to keep two
// mental models.
void TestAppRules::modeDecidesWhichWayAMatchGoes()
{
    const QStringList rules{QStringLiteral("firefox")};
    const AppIdentity firefox = appAt(absPath(QStringLiteral("usr/bin/firefox")));
    const AppIdentity other = appAt(absPath(QStringLiteral("usr/bin/curl")));

    QCOMPARE(freetunnel::appActionFor(firefox, rules, false), AppAction::ForceBypass);
    QCOMPARE(freetunnel::appActionFor(firefox, rules, true), AppAction::ForceTunnel);
    // An unmatched program is not forced either way; the domain and route rules
    // still get their say.
    QCOMPARE(freetunnel::appActionFor(other, rules, false), AppAction::Default);
    QCOMPARE(freetunnel::appActionFor(other, rules, true), AppAction::Default);
}

// With the feature switched off — no rules — every connection must take exactly
// the path it took before the feature existed.
void TestAppRules::anEmptyRuleListNeverForcesAnything()
{
    const AppIdentity firefox = appAt(absPath(QStringLiteral("usr/bin/firefox")));
    QCOMPARE(freetunnel::appActionFor(firefox, {}, false), AppAction::Default);
    QCOMPARE(freetunnel::appActionFor(firefox, {}, true), AppAction::Default);
    QCOMPARE(freetunnel::appActionFor(firefox, {QString()}, false), AppAction::Default);
}

// Case handling follows the filesystem rather than being uniformly lax: on
// Linux /usr/bin/FOO and /usr/bin/foo are two different programs, and a bypass
// rule matching the wrong one puts traffic outside the tunnel.
void TestAppRules::caseFollowsTheFilesystem()
{
    const QStringList rules{QStringLiteral("firefox")};
    const bool matches = freetunnel::appMatchesRules(appAt(absPath(QStringLiteral("usr/bin/FireFox"))), rules);
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
    QVERIFY2(matches, "Windows and macOS filesystems treat these as one file");
    QCOMPARE(freetunnel::appPathCaseSensitivity(), Qt::CaseInsensitive);
#else
    QVERIFY2(!matches, "on Linux these are two different files");
    QCOMPARE(freetunnel::appPathCaseSensitivity(), Qt::CaseSensitive);
#endif
}

// Paths copied out of a file manager arrive quoted, and program directories
// routinely contain spaces. Both have to survive into a rule that matches.
void TestAppRules::quotesAndSpacesSurviveTheRoundTrip()
{
    const QString path = absPath(QStringLiteral("Program Files/Some App/app"));
    const QString quoted = QLatin1Char('"') + path + QLatin1Char('"');
    QCOMPARE(freetunnel::normalizedAppRule(quoted), freetunnel::normalizedAppRule(path));
    QVERIFY(freetunnel::appMatchesRules(appAt(path), {quoted}));
    QVERIFY(freetunnel::appMatchesRules(appAt(path), {QStringLiteral("  ") + path + QStringLiteral("  ")}));
}

// Reported from a real macOS desktop: an application added to the bypass list
// was tunnelled anyway. A browser-like program does not open its sockets from
// the binary you picked — it does them from a helper process inside its own
// bundle — so the rule never saw the connections that mattered. A rule has to
// mean the application.
void TestAppRules::aRuleMeansTheApplicationNotOneBinaryInsideIt()
{
    const QString picked = QStringLiteral("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT");
    const QStringList rules{picked};

    QCOMPARE(freetunnel::appBundleOf(picked), QStringLiteral("/Applications/ChatGPT.app"));

    // The process the socket actually belongs to.
    const QString helper = QStringLiteral(
            "/Applications/ChatGPT.app/Contents/Frameworks/ChatGPT Helper.app/Contents/MacOS/ChatGPT Helper");
    QVERIFY2(freetunnel::appMatchesRules(AppIdentity{helper, QStringLiteral("ChatGPT Helper")}, rules),
             "a helper inside the same application must be covered by the rule");

    // And the binary itself, still.
    QVERIFY(freetunnel::appMatchesRules(appAt(picked), rules));

    // But NOT a different application, even one installed beside it. If this
    // ever passes, one bypass rule quietly takes every neighbouring program out
    // of the tunnel.
    QVERIFY(!freetunnel::appMatchesRules(
            appAt(QStringLiteral("/Applications/Other.app/Contents/MacOS/Other")), rules));
    // Nor an ordinary program that merely shares a directory.
    QVERIFY(!freetunnel::appMatchesRules(
            appAt(QStringLiteral("/usr/bin/other")), {QStringLiteral("/usr/bin/curl")}));
    QVERIFY(freetunnel::appBundleOf(QStringLiteral("/usr/bin/curl")).isEmpty());
    // A directory that merely ends in .app is not a bundle path either.
    QVERIFY(freetunnel::appBundleOf(QStringLiteral("/tmp/notabundle.app")).isEmpty());
}

QTEST_MAIN(TestAppRules)
#include "test_apprules.moc"
