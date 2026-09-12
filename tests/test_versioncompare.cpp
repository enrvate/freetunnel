// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include "core/VersionCompare.h"

class TestVersionCompare : public QObject {
    Q_OBJECT

private slots:
    void preReleasesOrderByNumberNotByText();
    void newerNumeric();
    void sameVersion();
    void suffixOrdering();
    void releaseBeatsPrerelease();
    void nonSemverFallback();
    void aNumericDowngradeIsRefusedEvenWhenTheSuffixLooksNewer();
};

void TestVersionCompare::newerNumeric()
{
    QVERIFY(isVersionNewer(QStringLiteral("1.0.0"), QStringLiteral("1.0.1")));
    QVERIFY(isVersionNewer(QStringLiteral("0.5"), QStringLiteral("0.6")));
    QVERIFY(!isVersionNewer(QStringLiteral("2.0.0"), QStringLiteral("1.9.9")));
}

void TestVersionCompare::sameVersion()
{
    QVERIFY(!isVersionNewer(QStringLiteral("1.0.0"), QStringLiteral("1.0.0")));
    QVERIFY(!isVersionNewer(QStringLiteral("0.6b"), QStringLiteral("0.6b")));
}

void TestVersionCompare::suffixOrdering()
{
    QVERIFY(isVersionNewer(QStringLiteral("0.6a"), QStringLiteral("0.6b")));
    QVERIFY(!isVersionNewer(QStringLiteral("0.6b"), QStringLiteral("0.6a")));
}

void TestVersionCompare::releaseBeatsPrerelease()
{
    QVERIFY(isVersionNewer(QStringLiteral("0.6-beta"), QStringLiteral("0.6")));
    QVERIFY(!isVersionNewer(QStringLiteral("0.6"), QStringLiteral("0.6-beta")));
}

void TestVersionCompare::nonSemverFallback()
{
    QVERIFY(isVersionNewer(QStringLiteral("0.5b"), QStringLiteral("0.6b")));
    QVERIFY(!isVersionNewer(QStringLiteral("0.6b"), QStringLiteral("0.5b")));
}

// Pre-release suffixes were compared as plain strings, which puts "-rc10" below
// "-rc9" because '1' sorts before '9'. Anyone running rc9 was therefore never
// offered rc10, and the longer a pre-release cycle ran the more people it left
// behind — silently, since to them it simply looked like no update existed.
void TestVersionCompare::preReleasesOrderByNumberNotByText()
{
    QVERIFY2(isVersionNewer(QStringLiteral("1.2.0-rc9"), QStringLiteral("1.2.0-rc10")),
             "rc10 was not offered to rc9");
    QVERIFY(!isVersionNewer(QStringLiteral("1.2.0-rc10"), QStringLiteral("1.2.0-rc9")));

    // Two digits are not a special case; any run of them counts.
    QVERIFY(isVersionNewer(QStringLiteral("1.2.0-beta2"), QStringLiteral("1.2.0-beta11")));
    QVERIFY(!isVersionNewer(QStringLiteral("1.2.0-beta11"), QStringLiteral("1.2.0-beta2")));

    // Leading zeros are a spelling, not a value.
    QVERIFY(!isVersionNewer(QStringLiteral("1.2.0-rc9"), QStringLiteral("1.2.0-rc09")));

    // The rules that already held must keep holding: a release beats its own
    // pre-releases, and a pre-release never beats the release.
    QVERIFY(isVersionNewer(QStringLiteral("1.2.0-rc10"), QStringLiteral("1.2.0")));
    QVERIFY(!isVersionNewer(QStringLiteral("1.2.0"), QStringLiteral("1.2.0-rc10")));

    // A shorter suffix sorts first, so "-rc" precedes "-rc1".
    QVERIFY(isVersionNewer(QStringLiteral("1.2.0-rc"), QStringLiteral("1.2.0-rc1")));

    // And the numeric part still dominates the suffix entirely.
    QVERIFY(isVersionNewer(QStringLiteral("1.2.0-rc10"), QStringLiteral("1.3.0-rc1")));
}

// isVersionNewer() compares the numeric part first and returns false outright
// when the remote is older; only an equal number falls through to the suffix.
// docs/security-threats.md leans on that: an attacker who can forge the release
// metadata can replay an older, genuinely signed release, and this is what stops
// it from rolling the user backwards.
//
// The existing downgrade check, !isVersionNewer("2.0.0", "1.9.9"), does not
// actually exercise the guard. Delete it and that assertion still passes, because
// both versions have empty suffixes and the suffix comparison returns the same
// answer by accident. Every suffix test here keeps the numeric part equal or
// moves it forward, so nothing covered the one combination where the two
// disagree — found by a mechanical sweep, not by reading.
void TestVersionCompare::aNumericDowngradeIsRefusedEvenWhenTheSuffixLooksNewer()
{
    // Older number, newer-looking suffix. Without the numeric guard the suffix
    // comparison wins and the updater offers a downgrade.
    QVERIFY2(!isVersionNewer(QStringLiteral("2.0.0-rc1"), QStringLiteral("1.9.9-rc2")),
             "a numerically older release must never be offered, whatever its suffix says");
    QVERIFY(!isVersionNewer(QStringLiteral("1.2.0-rc1"), QStringLiteral("1.1.0-rc9")));
    QVERIFY(!isVersionNewer(QStringLiteral("1.2.0-beta2"), QStringLiteral("1.1.0-beta11")));

    // The mirror of "-rc sorts before -rc1": going back from rc1 to rc is not an
    // update either, which is the half of that comparison nothing asserted.
    QVERIFY2(!isVersionNewer(QStringLiteral("1.2.0-rc1"), QStringLiteral("1.2.0-rc")),
             "a shorter suffix is older, so rc1 -> rc is a downgrade");

    // Controls: the suffix still decides when the numbers agree, and a genuine
    // upgrade is still offered.
    QVERIFY(isVersionNewer(QStringLiteral("2.0.0-rc1"), QStringLiteral("2.0.0-rc2")));
    QVERIFY(isVersionNewer(QStringLiteral("1.9.9-rc2"), QStringLiteral("2.0.0-rc1")));
}

QTEST_MAIN(TestVersionCompare)
#include "test_versioncompare.moc"
