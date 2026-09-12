import QtQuick
import QtQuick.Layouts
import QtQuick.Effects
import "../components"
import ".."

Item {
    id: splitRoot
    required property var shell
    required property var backend
    required property var theme

    // Clicking empty page area clears focus from a text field.
    TapHandler { onTapped: splitRoot.forceActiveFocus() }
    Flickable {
        anchors.fill: parent
        contentWidth: width // pin content to the viewport so margins stay symmetric
        contentHeight: scol.height; clip: true
        interactive: contentHeight > height // don't steal clicks from inputs when it fits
        ColumnLayout {
            id: scol
            anchors.left: parent.left; anchors.right: parent.right
            anchors.leftMargin: 18; anchors.rightMargin: 18
            spacing: 0
            Item { Layout.preferredHeight: 10 }
            RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42
                Text { text: qsTr("Split Tunneling"); color: theme.text; font.pixelSize: 14 }
                Item { Layout.fillWidth: true }
                Toggle { accent: theme.accent; offColor: theme.toggleOff; checked: backend.splitEnabled; onToggled: function(v){ backend.splitEnabled = v } }
            }
            Dropdown { label: qsTr("Mode"); value: backend.vpnMode; shell: splitRoot.shell; theme: splitRoot.theme
                model: [{v:"general",t:qsTr("Bypass VPN")},{v:"selective",t:qsTr("Through VPN")}]
                onPicked: function(v){ backend.vpnMode = v } }
            // "Through VPN" with no rules would route nothing; the backend keeps the
            // full tunnel instead. Standing notice rather than a one-off toast: the
            // mode stays chosen but inactive, so the explanation has to stay visible
            // for as long as that is true.
            Rectangle {
                Layout.fillWidth: true; Layout.topMargin: 6
                visible: backend.selectiveModeWouldLeak
                height: visible ? warnText.implicitHeight + 16 : 0
                radius: 8; color: theme.infoBg
                Text {
                    id: warnText
                    anchors.centerIn: parent; width: parent.width - 20
                    wrapMode: Text.WordWrap; font.pixelSize: 12; color: theme.warn
                    // One literal, not a concatenation: lupdate can only extract a
                    // literal argument, and a split string silently drops out of the
                    // catalogue.
                    text: qsTr("Add a rule to use \"Through VPN\" — with an empty list nothing would go through the tunnel, so the full tunnel stays on.")
                }
            }
            Item { Layout.preferredHeight: 6 }
            SectionLabel { text: qsTr("Profile"); theme: splitRoot.theme }
            Flow {
                Layout.fillWidth: true; Layout.topMargin: 2; spacing: 6
                Repeater {
                    model: backend.profiles
                    Rectangle {
                        id: chip
                        required property string modelData
                        property bool isActive: modelData === backend.activeProfile
                        property bool isDefault: modelData === "Default"
                        radius: 13; height: 28
                        implicitWidth: plabel.width + (chip.isDefault ? 22 : 39)
                        color: isActive ? theme.accent : (chipMa.containsMouse ? theme.border : theme.surface)
                        Behavior on color { ColorAnimation { duration: 120 } }
                        MouseArea { id: chipMa; anchors.fill: parent; hoverEnabled: true
                                    onClicked: backend.selectProfile(chip.modelData) }
                        Text { id: plabel; anchors.left: parent.left; anchors.leftMargin: 11
                               anchors.verticalCenter: parent.verticalCenter; text: chip.modelData
                               width: Math.min(implicitWidth, 130); elide: Text.ElideRight
                               color: chip.isActive ? "white" : theme.text; font.pixelSize: 13 }
                        ChipX { visible: !chip.isDefault; onAccent: chip.isActive; theme: splitRoot.theme
                                anchors.left: plabel.right; anchors.leftMargin: 5
                                anchors.verticalCenter: parent.verticalCenter
                                onClicked: shell.showConfirm(qsTr("Delete profile “%1”?").arg(shell.elideMiddle(chip.modelData, 36)),
                                    qsTr("Delete"), function(){ backend.removeProfile(chip.modelData) }) }
                    }
                }
                Rectangle {
                    radius: 13; height: 28; implicitWidth: 34
                    color: addChipMa.containsMouse ? theme.border : theme.surface
                    Behavior on color { ColorAnimation { duration: 120 } }
                    border.color: theme.border; border.width: 1
                    Text { anchors.centerIn: parent; text: "+"; color: theme.accent; font.pixelSize: 17 }
                    MouseArea { id: addChipMa; anchors.fill: parent; hoverEnabled: true
                                onClicked: { npRow.visible = true; npInput.forceActiveFocus() } }
                }
            }
            Rectangle {
                id: npRow; visible: false
                Layout.fillWidth: true; Layout.topMargin: 6; Layout.preferredHeight: 36; radius: 8
                color: theme.inputBg; border.color: theme.accent; border.width: 1
                TextInput {
                    id: npInput; anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 12
                    verticalAlignment: TextInput.AlignVCenter; clip: true; font.pixelSize: 13; color: theme.text
                    maximumLength: 16
                    onAccepted: { backend.addProfile(text); text = ""; npRow.visible = false }
                    Keys.onEscapePressed: { text = ""; npRow.visible = false }
                    // Collapse the field when it loses focus (e.g. clicking elsewhere).
                    onActiveFocusChanged: if (!activeFocus) { text = ""; npRow.visible = false }
                }
                Text { anchors.left: parent.left; anchors.leftMargin: 12; anchors.verticalCenter: parent.verticalCenter
                       anchors.right: parent.right; anchors.rightMargin: 12; elide: Text.ElideRight
                       text: qsTr("profile name, then Enter"); color: theme.textFaint; font.pixelSize: 13
                       visible: npInput.text.length === 0 }
            }
            Item { Layout.preferredHeight: 14 }
            RowLayout { Layout.fillWidth: true; spacing: 10
                SectionLabel { Layout.fillWidth: true; elide: Text.ElideRight; theme: splitRoot.theme
                    text: backend.vpnMode === "selective" ? qsTr("Rules — via VPN") : qsTr("Rules — bypass VPN") }
                Text { text: qsTr("Recommended for Russia"); font.pixelSize: 12
                       color: recMa.containsMouse ? theme.text : theme.accent; font.underline: recMa.containsMouse
                    MouseArea { id: recMa; anchors.fill: parent; anchors.margins: -4; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor; onClicked: backend.addRecommendedRussia() } }
                Text { text: qsTr("Clear all"); font.pixelSize: 12; visible: backend.domains.length > 0
                       color: clrDomMa.containsMouse ? Qt.lighter(theme.danger, 1.25) : theme.danger
                       font.underline: clrDomMa.containsMouse
                    MouseArea { id: clrDomMa; anchors.fill: parent; anchors.margins: -4; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor; onClicked: shell.showConfirm(qsTr("Clear all domains?"),
                        qsTr("Clear"), function(){ backend.clearDomains() }) } }
            }
            Flow {
                Layout.fillWidth: true; spacing: 6
                visible: backend.domains.length > 0
                Layout.topMargin: visible ? 6 : 0
                Layout.preferredHeight: visible ? implicitHeight : 0
                Repeater {
                    model: backend.domains
                    Rectangle {
                        id: domChip
                        required property string modelData
                        required property int index
                        radius: 13; color: theme.surface
                        implicitWidth: dlabel.width + 39; implicitHeight: 28
                        Text { id: dlabel; anchors.left: parent.left; anchors.leftMargin: 11
                               anchors.verticalCenter: parent.verticalCenter; text: domChip.modelData
                               width: Math.min(implicitWidth, 190); elide: Text.ElideRight
                               color: theme.text; font.pixelSize: 13 }
                        ChipX { theme: splitRoot.theme; anchors.left: dlabel.right; anchors.leftMargin: 5
                                anchors.verticalCenter: parent.verticalCenter
                                onClicked: backend.removeDomain(domChip.index) }
                    }
                }
            }
            Rectangle {
                Layout.fillWidth: true; Layout.preferredHeight: 36; radius: 8
                Layout.topMargin: 6
                color: theme.inputBg; border.color: domInput.activeFocus ? theme.accent : theme.inputBorder; border.width: 1
                TextInput {
                    id: domInput
                    anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 12
                    verticalAlignment: TextInput.AlignVCenter; clip: true
                    font.pixelSize: 13; color: theme.text
                    onAccepted: { if (backend.addDomain(text)) text = "" }
                    Keys.onEscapePressed: focus = false
                }
                Text { anchors.left: parent.left; anchors.leftMargin: 12; anchors.verticalCenter: parent.verticalCenter
                       anchors.right: parent.right; anchors.rightMargin: 12; elide: Text.ElideRight
                       text: qsTr("domain or domains (comma/space separated), then Enter"); color: theme.textFaint; font.pixelSize: 13
                       visible: domInput.text.length === 0 && !domInput.activeFocus }
                MouseArea { anchors.fill: parent; acceptedButtons: Qt.NoButton; cursorShape: Qt.IBeamCursor }
            }

            Item { Layout.preferredHeight: 14 }

            // ----- Applications -----
            // Here rather than in Settings, because the Mode control at the top of
            // this page is what decides which way this list points: the same names
            // mean "only these go through the tunnel" or "these alone stay out of
            // it". A list whose meaning is flipped from another screen is a list
            // nobody can read with confidence.
            RowLayout { Layout.fillWidth: true; spacing: 10
                SectionLabel { Layout.fillWidth: true; elide: Text.ElideRight; theme: splitRoot.theme
                    text: backend.vpnMode === "selective" ? qsTr("Applications — via VPN")
                                                          : qsTr("Applications — bypass VPN") }
                Text { text: qsTr("Choose…"); font.pixelSize: 12
                       color: pickMa.containsMouse ? theme.text : theme.accent; font.underline: pickMa.containsMouse
                    MouseArea { id: pickMa; anchors.fill: parent; anchors.margins: -4; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor; onClicked: shell.overlay = "apps" } }
                Text { text: qsTr("Clear all"); font.pixelSize: 12; visible: backend.appRules.length > 0
                       color: clrApMa.containsMouse ? Qt.lighter(theme.danger, 1.25) : theme.danger
                       font.underline: clrApMa.containsMouse
                    MouseArea { id: clrApMa; anchors.fill: parent; anchors.margins: -4; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor; onClicked: shell.showConfirm(qsTr("Clear all applications?"),
                        qsTr("Clear"), function(){ backend.clearAppRules() }) } }
            }
            Flow {
                Layout.fillWidth: true; spacing: 6
                visible: backend.appRules.length > 0
                Layout.topMargin: visible ? 6 : 0
                Layout.preferredHeight: visible ? implicitHeight : 0
                Repeater {
                    model: backend.appRules
                    Rectangle {
                        id: apChip
                        required property string modelData
                        required property int index
                        radius: 13; color: theme.surface
                        implicitWidth: alabel.width + 39; implicitHeight: 28
                        // Just the program. A rule may be stored as a long path,
                        // but the path is not what the person recognises: they
                        // added Firefox, so the chip says firefox.
                        Text { id: alabel; anchors.left: parent.left; anchors.leftMargin: 11
                               anchors.verticalCenter: parent.verticalCenter
                               text: apChip.modelData.split(/[\\/]/).pop()
                               width: Math.min(implicitWidth, 190); elide: Text.ElideRight
                               color: theme.text; font.pixelSize: 13 }
                        ChipX { theme: splitRoot.theme; anchors.left: alabel.right; anchors.leftMargin: 5
                                anchors.verticalCenter: parent.verticalCenter
                                onClicked: backend.removeAppRule(apChip.index) }
                    }
                }
            }
            Rectangle {
                Layout.fillWidth: true; Layout.preferredHeight: 36; radius: 8
                Layout.topMargin: 6
                color: apDrop.containsDrag ? theme.surface : theme.inputBg
                border.width: 1
                border.color: apDrop.containsDrag || apInput.activeFocus ? theme.accent : theme.inputBorder
                TextInput {
                    id: apInput
                    anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 12
                    verticalAlignment: TextInput.AlignVCenter; clip: true
                    font.pixelSize: 13; color: theme.text
                    onAccepted: { if (backend.addApplicationFromPath(text)) text = "" }
                    Keys.onEscapePressed: focus = false
                }
                Text { anchors.left: parent.left; anchors.leftMargin: 12; anchors.verticalCenter: parent.verticalCenter
                       anchors.right: parent.right; anchors.rightMargin: 12; elide: Text.ElideRight
                       text: apDrop.containsDrag ? qsTr("Drop to add this application")
                                                 : qsTr("Drop an application here, or paste its full path")
                       color: apDrop.containsDrag ? theme.accent : theme.textFaint; font.pixelSize: 13
                       visible: apInput.text.length === 0 && !apInput.activeFocus }
                // Dropping the icon is the natural gesture, and the only one that
                // works for someone who does not know where their program lives.
                // Whatever lands here — the program, a .desktop entry, a .lnk, an
                // .app bundle — the backend follows it to the executable.
                DropArea {
                    id: apDrop
                    anchors.fill: parent
                    keys: ["text/uri-list"]
                    onDropped: function(drop) {
                        if (!drop.hasUrls) { drop.accepted = false; return }
                        for (var i = 0; i < drop.urls.length; ++i)
                            backend.addApplicationFromPath(drop.urls[i].toString())
                        drop.accepted = true
                    }
                }
                MouseArea { anchors.fill: parent; acceptedButtons: Qt.NoButton; cursorShape: Qt.IBeamCursor }
            }
            Item { Layout.preferredHeight: 16 }
        }
    }
}
