// cppcheck-suppress-file missingIncludeSystem
#include <QtTest>

#include <QGuiApplication>
#include <QStandardPaths>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQmlContext>
#include <QQmlExpression>
#include <QQuickItem>
#include <QQuickWindow>

#include "ui/MockBackend.h"
#include "ui/MockShell.h"
#include "ui/UiTheme.h"

class TestQmlUi : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void homePageLoads();
    void configsPageLoads();
    void splitPageLoads();
    void settingsPageLoads();
    void logsPageLoads();
    void createConfigOverlayLoads();
    void mainWindowLoads();
    void mainWindowPageNavigation();
    void everyComponentLoadsOnItsOwn();
    void everyComponentLoadsOnItsOwn_data();
    void confirmDialogShowsTheThirdButtonOnlyWhenItHasOne();
    void confirmDialogAnswersReturnAndEscape();
    void aSecondConfirmQueuesInsteadOfReplacingTheLiveOne();

private:
    QObject *loadPage(const char *qmlPath);

    QQmlEngine m_engine;
    MockBackend m_backend;
    MockShell m_shell;
    UiTheme m_theme;
};

void TestQmlUi::initTestCase()
{
    // Icons load through backend.readBundledText — no QML XHR file access needed.
    m_engine.rootContext()->setContextProperty(QStringLiteral("backend"), &m_backend);
}

QObject *TestQmlUi::loadPage(const char *qmlPath)
{
    QQmlComponent component(&m_engine, QUrl(QStringLiteral("qrc:/%1").arg(QLatin1String(qmlPath))));
    if (!QTest::qVerify(component.isReady(), "component.isReady()", component.errorString().toUtf8().constData(), __FILE__, __LINE__))
        return nullptr;
    QVariantMap props;
    props[QStringLiteral("shell")] = QVariant::fromValue(static_cast<QObject *>(&m_shell));
    props[QStringLiteral("backend")] = QVariant::fromValue(static_cast<QObject *>(&m_backend));
    props[QStringLiteral("theme")] = QVariant::fromValue(static_cast<QObject *>(&m_theme));
    QObject *root = component.createWithInitialProperties(props, m_engine.rootContext());
    if (!QTest::qVerify(root != nullptr, "root != nullptr", component.errorString().toUtf8().constData(), __FILE__, __LINE__))
        return nullptr;
    return root;
}

void TestQmlUi::homePageLoads()
{
    QObject *root = loadPage("pages/HomePage.qml");
    QVERIFY(root);
    QVERIFY(root->property("backend").isValid());
    delete root;
}

void TestQmlUi::configsPageLoads()
{
    QObject *root = loadPage("pages/ConfigsPage.qml");
    QVERIFY(root);
    delete root;
}

void TestQmlUi::splitPageLoads()
{
    QObject *root = loadPage("pages/SplitPage.qml");
    QVERIFY(root);
    delete root;
}

void TestQmlUi::settingsPageLoads()
{
    QObject *root = loadPage("pages/SettingsPage.qml");
    QVERIFY(root);
    delete root;
}

void TestQmlUi::logsPageLoads()
{
    QObject *root = loadPage("pages/LogsPage.qml");
    QVERIFY(root);
    delete root;
}

void TestQmlUi::createConfigOverlayLoads()
{
    m_shell.setEditIndex(-1);
    QObject *root = loadPage("CreateConfigOverlay.qml");
    QVERIFY(root);
    delete root;
}

void TestQmlUi::mainWindowLoads()
{
    QQmlComponent component(&m_engine, QUrl(QStringLiteral("qrc:/Main.qml")));
    QVERIFY2(component.isReady(), component.errorString().toUtf8().constData());
    QObject *root = component.create();
    QVERIFY2(root, component.errorString().toUtf8().constData());
    QVERIFY(qobject_cast<QQuickWindow *>(root));
    delete root;
}

void TestQmlUi::mainWindowPageNavigation()
{
    QQmlComponent component(&m_engine, QUrl(QStringLiteral("qrc:/Main.qml")));
    QVERIFY2(component.isReady(), component.errorString().toUtf8().constData());
    QObject *root = component.create();
    QVERIFY(root);
    for (int page = 0; page < 5; ++page) {
        root->setProperty("currentPage", page);
        QCoreApplication::processEvents();
        QCOMPARE(root->property("currentPage").toInt(), page);
    }
    delete root;
}

// The pages instantiate most of these, but not all on every path — a component
// behind a Loader or a conditional can be broken for weeks and only show up as
// an empty panel when a user finally opens it. Loading each one on its own turns
// that into a build failure.
void TestQmlUi::everyComponentLoadsOnItsOwn_data()
{
    QTest::addColumn<QString>("path");
    for (const char *p : {"components/ChipX.qml", "components/ConfirmDialog.qml",
                          "components/Dropdown.qml", "components/HotkeyField.qml",
                          "components/Icon.qml", "components/SectionLabel.qml",
                          "components/Sep.qml", "Field.qml", "Toggle.qml"}) {
        QTest::newRow(p) << QString::fromLatin1(p);
    }
}

void TestQmlUi::everyComponentLoadsOnItsOwn()
{
    QFETCH(QString, path);
    QObject *root = loadPage(path.toLatin1().constData());
    QVERIFY(root);
    delete root;
}

// The deep-link dialog grew a third button so a link that collides with an
// existing config can offer Replace next to Add copy. Every other caller —
// delete a config, remove a profile — must still get two buttons: an extra
// destructive-looking action appearing in those would be its own bug.
// Return confirms and Escape cancels, but Return only after the dialog has been
// on screen for a moment. A deep link can raise this dialog with no warning while
// the user is typing, and a keystroke already in flight must not answer a
// question nobody has read yet.
void TestQmlUi::confirmDialogAnswersReturnAndEscape()
{
    QObject *root = loadPage("components/ConfirmDialog.qml");
    QVERIFY(root);
    auto *item = qobject_cast<QQuickItem *>(root);
    QVERIFY(item);
    QQuickWindow window;
    item->setParentItem(window.contentItem());
    item->setWidth(400);
    item->setHeight(400);
    window.show();
    QVERIFY(QTest::qWaitForWindowExposed(&window));

    QSignalSpy confirmed(root, SIGNAL(confirmed()));
    QVERIFY(confirmed.isValid());

    QMetaObject::invokeMethod(root, "open");
    QVERIFY(root->property("visible").toBool());

    // Immediately after opening the dialog is deliberately deaf to Return.
    QVERIFY(!root->property("armed").toBool());
    QTest::keyClick(&window, Qt::Key_Return);
    QCOMPARE(confirmed.count(), 0);
    QVERIFY2(root->property("visible").toBool(),
             "Return closed the dialog before it had been on screen long enough to read");

    // Once armed, Return is the confirm button.
    QTRY_VERIFY(root->property("armed").toBool());
    QTest::keyClick(&window, Qt::Key_Return);
    QCOMPARE(confirmed.count(), 1);
    QVERIFY(!root->property("visible").toBool());

    // Escape cancels: the dialog closes and confirmed() must NOT fire.
    QMetaObject::invokeMethod(root, "open");
    QTRY_VERIFY(root->property("armed").toBool());
    QTest::keyClick(&window, Qt::Key_Escape);
    QVERIFY(!root->property("visible").toBool());
    QCOMPARE(confirmed.count(), 1);

    // The three-button form is the deep-link name collision: its primary action
    // replaces an existing config with one a link chose, so there is no answer
    // safe enough to be the keyboard default and Return must stay inert.
    root->setProperty("altText", QStringLiteral("Add copy"));
    QMetaObject::invokeMethod(root, "open");
    QTRY_VERIFY(root->property("armed").toBool());
    QTest::keyClick(&window, Qt::Key_Return);
    QCOMPARE(confirmed.count(), 1);
    QVERIFY(root->property("visible").toBool());
}

void TestQmlUi::confirmDialogShowsTheThirdButtonOnlyWhenItHasOne()
{
    QObject *root = loadPage("components/ConfirmDialog.qml");
    QVERIFY(root);

    // A Quick item reports EFFECTIVE visibility, which stays false while it is
    // not in a scene — so put it in a window before judging any of it.
    auto *item = qobject_cast<QQuickItem *>(root);
    QVERIFY(item);
    QQuickWindow window;
    item->setParentItem(window.contentItem());
    window.show();

    QObject *alternate = root->findChild<QObject *>(QStringLiteral("alternateButton"));
    QVERIFY2(alternate, "the dialog has no alternate button at all");
    QVERIFY(root->findChild<QObject *>(QStringLiteral("cancelButton")));
    QVERIFY(root->findChild<QObject *>(QStringLiteral("confirmButton")));

    // The dialog starts hidden and open()/close() drive it. A child item reports
    // EFFECTIVE visibility, so the buttons can only be judged while it is open.
    QVERIFY(!root->property("visible").toBool());
    QMetaObject::invokeMethod(root, "open");
    QVERIFY(root->property("visible").toBool());

    // Default: a plain two-button confirmation, as every delete/remove uses.
    QVERIFY2(!alternate->property("visible").toBool(),
             "a third button showed up in an ordinary confirmation");

    root->setProperty("altText", QStringLiteral("Add copy"));
    QVERIFY2(alternate->property("visible").toBool(),
             "the collision dialog offers no way to add a copy");

    QMetaObject::invokeMethod(root, "close");
    QVERIFY(!root->property("visible").toBool());
}

// Main.qml carries a comment describing a bug that already happened: a second
// confirm request used to overwrite the live dialog in place, so the user
// answered a question they never read, with the buttons of the previous one, and
// the callback that ran belonged to the new one. Deep links arrive
// asynchronously and can legitimately land back to back, so the fix was to queue.
//
// Nothing tested the queue. Both halves could be deleted — the queueing itself
// and the Qt.callLater that defers the next dialog — with the suite still green.
// Checked first that a QML edit reaches this binary at all, by breaking Main.qml
// on purpose and watching qml_ui fail: a mutation that never got into the
// resource would have "survived" for the wrong reason entirely.
void TestQmlUi::aSecondConfirmQueuesInsteadOfReplacingTheLiveOne()
{
    QQmlComponent component(&m_engine, QUrl(QStringLiteral("qrc:/Main.qml")));
    QVERIFY2(component.isReady(), component.errorString().toUtf8().constData());
    QScopedPointer<QObject> root(component.create());
    QVERIFY2(!root.isNull(), component.errorString().toUtf8().constData());

    // The dialog is an unnamed child of the window; find it by the property set it
    // exposes rather than by an id C++ cannot see.
    QObject *dialog = nullptr;
    const QList<QObject *> children = root->findChildren<QObject *>();
    for (QObject *child : children) {
        if (child->property("confirmText").isValid() && child->property("armed").isValid()) {
            dialog = child;
            break;
        }
    }
    QVERIFY2(dialog, "could not find the confirm dialog inside Main.qml");

    auto showConfirm = [&](const QString &message) {
        return QMetaObject::invokeMethod(root.data(), "showConfirm",
                                         Q_ARG(QVariant, QVariant(message)),
                                         Q_ARG(QVariant, QVariant(QStringLiteral("Yes"))),
                                         Q_ARG(QVariant, QVariant()));
    };

    QVERIFY(showConfirm(QStringLiteral("first question")));
    QVERIFY(dialog->property("visible").toBool());
    QCOMPARE(dialog->property("text").toString(), QStringLiteral("first question"));

    // The second request must wait its turn, and the dialog on screen must still
    // be asking the first question — that is the whole point.
    QVERIFY(showConfirm(QStringLiteral("second question")));
    QCOMPARE(root->property("confirmQueue").toList().size(), 1);
    QVERIFY2(dialog->property("text").toString() == QStringLiteral("first question"),
             "the second request replaced the question already on screen");

    // Answering the first hands over to the second, deferred so the current answer
    // runs before confirmCb is reassigned.
    QVERIFY(QMetaObject::invokeMethod(dialog, "close"));
    QTRY_COMPARE(dialog->property("text").toString(), QStringLiteral("second question"));
    QVERIFY(dialog->property("visible").toBool());
    QCOMPARE(root->property("confirmQueue").toList().size(), 0);

    // And nothing queues behind the last one.
    QVERIFY(QMetaObject::invokeMethod(dialog, "close"));
    QTRY_VERIFY(!dialog->property("visible").toBool());

    // The other half of the fix is that showNextConfirm is DEFERRED. The dialog
    // clears `visible` before it emits confirmed(), so handing over inline would
    // reassign win.confirmCb before the answer to the question on screen had run —
    // the user confirms one thing and a different callback fires. Queueing alone
    // does not prevent that, and the check above cannot see it, because close()
    // never emits confirmed() at all.
    //
    // Driven exactly as the confirm button does it: visible = false, then
    // confirmed(). The callbacks record into the mock backend because a QML
    // closure has nowhere else to write that C++ can read back.
    m_backend.setProperty("confirmLog", QString());
    QQmlExpression setup(qmlContext(root.data()), root.data(),
                         QStringLiteral(
                                 "showConfirm('first', 'Yes', function() { "
                                 "    backend.confirmLog = backend.confirmLog + 'A' });"
                                 "showConfirm('second', 'Yes', function() { "
                                 "    backend.confirmLog = backend.confirmLog + 'B' });"));
    setup.evaluate();
    QVERIFY2(!setup.hasError(), qPrintable(setup.error().toString()));
    QCOMPARE(dialog->property("text").toString(), QStringLiteral("first"));

    dialog->setProperty("visible", false);
    QVERIFY(QMetaObject::invokeMethod(dialog, "confirmed"));
    QCOMPARE(m_backend.property("confirmLog").toString(), QStringLiteral("A"));

    // Only now does the second question appear, with its own callback intact.
    QTRY_COMPARE(dialog->property("text").toString(), QStringLiteral("second"));
    dialog->setProperty("visible", false);
    QVERIFY(QMetaObject::invokeMethod(dialog, "confirmed"));
    QCOMPARE(m_backend.property("confirmLog").toString(), QStringLiteral("AB"));
}

int main(int argc, char *argv[])
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    // Isolate from the real app's on-disk state: never read or clobber the
    // user's configs.json / settings under the production app/org names.
    QStandardPaths::setTestModeEnabled(true);
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("QmlUiTest"));
    app.setOrganizationName(QStringLiteral("FreeTunnelTest"));
    TestQmlUi tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_qml_ui.moc"
