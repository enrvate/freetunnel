import QtQuick
import QtQuick.Layouts
import Qt.labs.platform as Platform
import "components"

// Pick a program from the ones the system already knows about, so nobody has to
// go hunting through a file manager for a path they have never needed to know.
// The file dialog stays available for anything the list does not cover —
// portable programs, things installed outside the usual places.
Item {
    id: pickerRoot
    required property var shell
    required property var backend
    required property var theme

    readonly property bool isMac: Qt.platform.os === "osx"
    readonly property int safeTop: isMac ? 32 : 40
    readonly property int cardWidth: Math.min(width - 28, 420)

    anchors.fill: parent

    Rectangle { anchors.fill: parent; color: "#000000"; opacity: 0.45
        MouseArea { anchors.fill: parent; onClicked: pickerRoot.shell.overlay = "" } }
    Shortcut { sequences: ["Escape"]
               enabled: !pickerRoot.shell.windowPopupOpen
               onActivated: pickerRoot.shell.overlay = "" }

    // The scan touches the filesystem, so it happens once when the card opens
    // rather than on every keystroke in the search field.
    property var allApps: []
    Component.onCompleted: {
        allApps = backend.installedApplications()
        appList.model = allApps
        searchField.forceActiveFocus()
    }

    function applyFilter(text) {
        var q = text.trim().toLowerCase()
        if (q.length === 0) { appList.model = allApps; return }
        var out = []
        for (var i = 0; i < allApps.length; ++i) {
            var a = allApps[i]
            // Match the path as well as the name: someone who knows they want
            // the one in /opt can type that, and it is the only way to tell two
            // copies of one program apart.
            if (a.name.toLowerCase().indexOf(q) !== -1 || a.path.toLowerCase().indexOf(q) !== -1)
                out.push(a)
        }
        appList.model = out
    }

    Rectangle {
        id: card
        x: (parent.width - width) / 2
        y: Math.max(pickerRoot.safeTop, (parent.height - height) / 2)
        width: pickerRoot.cardWidth
        height: Math.min(parent.height - pickerRoot.safeTop - 12, 460)
        radius: 14; color: theme.bg; border.color: theme.border; border.width: 1

        ColumnLayout {
            anchors.fill: parent; anchors.margins: 14; spacing: 10

            // Back arrow before the title, the same as the config editor: this
            // is a step into a list and out again, not a dialog to be dismissed.
            RowLayout {
                Layout.fillWidth: true; spacing: 12
                Text { text: "←"; color: backMa.containsMouse ? theme.text : theme.textDim
                       font.pixelSize: 20
                    MouseArea { id: backMa; anchors.fill: parent; anchors.margins: -6
                        hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                        onClicked: pickerRoot.shell.overlay = "" } }
                Text { Layout.fillWidth: true; text: qsTr("Add an application")
                       color: theme.text; font.pixelSize: 15; font.weight: Font.Medium }
            }

            Rectangle {
                Layout.fillWidth: true; Layout.preferredHeight: 34; radius: 8
                color: theme.inputBg; border.width: 1
                border.color: searchField.activeFocus ? theme.accent : theme.inputBorder
                TextInput {
                    id: searchField
                    anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10
                    verticalAlignment: TextInput.AlignVCenter; clip: true
                    font.pixelSize: 13; color: theme.text
                    onTextChanged: pickerRoot.applyFilter(text)
                    Keys.onEscapePressed: pickerRoot.shell.overlay = ""
                    // Enter takes the first match. This one may pass a bare name
                    // straight through — a sandboxed program's rule IS a bare
                    // name — because it comes from the list, not from a guess.
                    onAccepted: {
                        if (appList.model.length > 0) {
                            backend.addAppRule(appList.model[0].path)
                            pickerRoot.shell.overlay = ""
                        }
                    }
                }
                Text { anchors.left: parent.left; anchors.leftMargin: 10
                       anchors.verticalCenter: parent.verticalCenter
                       text: qsTr("Search"); color: theme.textFaint; font.pixelSize: 13
                       visible: searchField.text.length === 0 }
            }

            ListView {
                id: appList
                Layout.fillWidth: true; Layout.fillHeight: true
                clip: true; spacing: 2
                model: []
                delegate: Rectangle {
                    required property var modelData
                    width: appList.width; height: 42; radius: 8
                    color: rowMa.containsMouse ? theme.surface : "transparent"
                    Column {
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.left: parent.left; anchors.leftMargin: 10
                        anchors.right: parent.right; anchors.rightMargin: 10
                        spacing: 1
                        Text { text: modelData.name; color: theme.text; font.pixelSize: 13
                               width: parent.width; elide: Text.ElideRight }
                        // The path is shown here and nowhere else: this is the
                        // moment someone needs it, to tell two copies of one
                        // program apart before choosing.
                        Text { text: modelData.path; color: theme.textFaint; font.pixelSize: 11
                               width: parent.width; elide: Text.ElideLeft }
                    }
                    MouseArea {
                        id: rowMa; anchors.fill: parent; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            backend.addAppRule(modelData.path)
                            pickerRoot.shell.overlay = ""
                        }
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                visible: appList.model.length === 0
                text: pickerRoot.allApps.length === 0
                      ? qsTr("No installed applications were found. Choose a file instead.")
                      : qsTr("Nothing matches that.")
                color: theme.textFaint; font.pixelSize: 12; wrapMode: Text.WordWrap
            }

            Sep { Layout.fillWidth: true; theme: pickerRoot.theme }

            Text {
                Layout.fillWidth: true
                text: qsTr("Choose a file instead…"); font.pixelSize: 12
                color: browseMa.containsMouse ? theme.text : theme.accent
                font.underline: browseMa.containsMouse
                MouseArea { id: browseMa; anchors.fill: parent; anchors.margins: -4
                    hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                    onClicked: fileDlg.open() }
            }
        }
    }

    Platform.FileDialog {
        id: fileDlg
        title: qsTr("Choose an application")
        nameFilters: Qt.platform.os === "windows"
                     ? [qsTr("Programs and shortcuts (*.exe *.lnk)"), qsTr("All files (*)")]
                     : [qsTr("Applications (*.desktop *.app)"), qsTr("All files (*)")]
        onAccepted: {
            pickerRoot.backend.addApplicationFromPath(fileDlg.file.toString())
            pickerRoot.shell.overlay = ""
        }
    }
}
