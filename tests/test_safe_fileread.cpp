// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include "core/AppUiUtils.h"

#include <QDir>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QTemporaryFile>

class TestSafeFileRead : public QObject {
    Q_OBJECT

private slots:
    void readsFileInHome();
    void readsFileUrlInHome();
    void rejectsSystemPaths();
    void rejectsOversized();
    void rejectsASymlinkEvenWhenItsTargetIsAllowed();
    void theRootBoundaryIsADirectorySeparator();
};

void TestSafeFileRead::readsFileInHome()
{
    QTemporaryFile tf(QDir::homePath() + QStringLiteral("/.ft-test-read-XXXXXX.pem"));
    tf.setAutoRemove(true);
    QVERIFY(tf.open());
    tf.write("-----BEGIN CERTIFICATE-----\nTEST\n");
    tf.close();

    const QString content = safeReadUserTextFile(tf.fileName());
    QVERIFY(content.contains(QStringLiteral("BEGIN CERTIFICATE")));
}

void TestSafeFileRead::readsFileUrlInHome()
{
    QTemporaryFile tf(QDir::homePath() + QStringLiteral("/.ft-test-read-XXXXXX.pem"));
    tf.setAutoRemove(true);
    QVERIFY(tf.open());
    tf.write("PEM");
    tf.close();

    const QUrl url = QUrl::fromLocalFile(tf.fileName());
    QCOMPARE(safeReadUserTextFile(url.toString()), QStringLiteral("PEM"));
}

void TestSafeFileRead::rejectsSystemPaths()
{
    QVERIFY(safeReadUserTextFile(QStringLiteral("/etc/passwd")).isEmpty());
#if defined(Q_OS_UNIX)
    QVERIFY(safeReadUserTextFile(QStringLiteral("/etc/hosts")).isEmpty());
#endif
}

void TestSafeFileRead::rejectsOversized()
{
    QTemporaryFile tf(QDir::homePath() + QStringLiteral("/.ft-test-big-XXXXXX.pem"));
    tf.setAutoRemove(true);
    QVERIFY(tf.open());
    tf.write(QByteArray(2 * 1024 * 1024, 'A'));
    tf.close();

    QVERIFY(safeReadUserTextFile(tf.fileName(), 1024 * 1024).isEmpty());
}

// docs/security-threats.md says of this function: "symlinks are rejected". No
// test created one, so the claim rested on a single `fi.isSymLink()` that could
// have been deleted without a murmur — which is how it was found.
//
// The target here is itself allowed, which is the point: the rejection must be
// about the link, not about where it happens to lead. Canonicalising first and
// judging the destination would pass this file and still leave the indirection
// (and the window between check and read) that the check exists to refuse.
void TestSafeFileRead::rejectsASymlinkEvenWhenItsTargetIsAllowed()
{
#ifndef Q_OS_UNIX
    QSKIP("creating a symlink needs elevation on Windows");
#else
    QTemporaryFile target(QDir::homePath() + QStringLiteral("/.ft-test-target-XXXXXX.pem"));
    target.setAutoRemove(true);
    QVERIFY(target.open());
    target.write("-----BEGIN CERTIFICATE-----\nTEST\n");
    target.close();

    // Sanity first: read directly, the content is allowed through.
    QVERIFY(!safeReadUserTextFile(target.fileName()).isEmpty());

    const QString link = QDir::homePath() + QStringLiteral("/.ft-test-link.pem");
    QFile::remove(link);
    QVERIFY(QFile::link(target.fileName(), link));
    const auto cleanup = qScopeGuard([&] { QFile::remove(link); });

    QVERIFY2(safeReadUserTextFile(link).isEmpty(),
             "a symlink must be refused even when it points at a file we would read");
#endif
}

// pathUnderRoot() compares against `root + '/'`, not bare `root`, and the extra
// separator is the whole guard: without it a sibling directory whose name merely
// begins with the root's name reads as living inside it. /home/alice-backup is
// not in /home/alice.
//
// Testing that hermetically means every allowed root has to be somewhere we
// control, or the "outside" directory lands inside one of the others — the temp
// root in particular swallows anything under /tmp. So point HOME and TMPDIR into
// one sandbox and put the impostor beside them.
void TestSafeFileRead::theRootBoundaryIsADirectorySeparator()
{
#ifndef Q_OS_UNIX
    QSKIP("redirects HOME and TMPDIR, which is a Unix arrangement");
#else
    QTemporaryDir sandbox;
    QVERIFY(sandbox.isValid());
    const QString home = sandbox.filePath(QStringLiteral("home"));
    const QString tmp = sandbox.filePath(QStringLiteral("tmp"));
    const QString impostor = sandbox.filePath(QStringLiteral("homeevil")); // shares "home"
    QVERIFY(QDir().mkpath(home));
    QVERIFY(QDir().mkpath(tmp));
    QVERIFY(QDir().mkpath(impostor));

    const QByteArray oldHome = qgetenv("HOME");
    const QByteArray oldTmpdir = qgetenv("TMPDIR");
    qputenv("HOME", home.toUtf8());
    qputenv("TMPDIR", tmp.toUtf8());
    // Restore no matter which assertion below ends the test: a leaked HOME would
    // quietly reroute every test that runs after this one.
    const auto restore = qScopeGuard([&] {
        if (oldHome.isEmpty()) qunsetenv("HOME"); else qputenv("HOME", oldHome);
        if (oldTmpdir.isEmpty()) qunsetenv("TMPDIR"); else qputenv("TMPDIR", oldTmpdir);
    });
    QCOMPARE(QDir::homePath(), home); // the redirection actually took

    const QString inside = home + QStringLiteral("/ok.pem");
    QFile fi(inside);
    QVERIFY(fi.open(QIODevice::WriteOnly));
    fi.write("INSIDE");
    fi.close();

    const QString outside = impostor + QStringLiteral("/stolen.pem");
    QFile fo(outside);
    QVERIFY(fo.open(QIODevice::WriteOnly));
    fo.write("OUTSIDE");
    fo.close();

    // The guard is only meaningful if the allowed case still works.
    QCOMPARE(safeReadUserTextFile(inside), QStringLiteral("INSIDE"));
    QVERIFY2(safeReadUserTextFile(outside).isEmpty(),
             "a directory that merely shares the root's name prefix is not inside it");
#endif
}

QTEST_MAIN(TestSafeFileRead)
#include "test_safe_fileread.moc"
