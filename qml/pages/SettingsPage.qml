import QtQuick
import QtQuick.Layouts
import QtQuick.Effects
import "../components"
import ".."

Item {
    id: settingsRoot
    required property var shell
    required property var backend
    required property var theme

    TapHandler { onTapped: settingsRoot.forceActiveFocus() }
    Flickable {
        anchors.fill: parent
        contentWidth: width // pin content to the viewport so margins stay symmetric
        contentHeight: setcol.height; clip: true
        interactive: contentHeight > height
        ColumnLayout {
            id: setcol; anchors.left: parent.left; anchors.right: parent.right
            anchors.leftMargin: 18; anchors.rightMargin: 18; spacing: 0
            Item { Layout.preferredHeight: 6 }
            SectionLabel { text: qsTr("General"); theme: settingsRoot.theme }
            Dropdown { label: qsTr("Language"); value: backend.language; shell: settingsRoot.shell; theme: settingsRoot.theme
                model: [{v:"en",t:"English"},{v:"ru",t:"Русский"}]
                onPicked: function(v){ backend.language = v } }
            Sep { theme: settingsRoot.theme }
            Dropdown { label: qsTr("Theme"); value: backend.themeMode; shell: settingsRoot.shell; theme: settingsRoot.theme
                model: [{v:"system",t:qsTr("System")},{v:"light",t:qsTr("Light")},{v:"dark",t:qsTr("Dark")}]
                onPicked: function(v){ backend.themeMode = v } }
            Sep { theme: settingsRoot.theme }
            RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42
                Text { Layout.fillWidth: true; Layout.minimumWidth: 0; elide: Text.ElideRight
                       text: qsTr("Launch at system startup"); color: theme.text; font.pixelSize: 14 }
                Toggle { accent: theme.accent; offColor: theme.toggleOff; checked: backend.autoStart; onToggled: function(v){ backend.autoStart = v } } }
            Sep { theme: settingsRoot.theme }
            RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42
                Text { Layout.fillWidth: true; Layout.minimumWidth: 0; elide: Text.ElideRight
                       text: qsTr("Connect on startup"); color: theme.text; font.pixelSize: 14 }
                Toggle { accent: theme.accent; offColor: theme.toggleOff; checked: backend.autoConnect; onToggled: function(v){ backend.autoConnect = v } } }
            Item { Layout.preferredHeight: 16 }
            SectionLabel { text: qsTr("Security"); theme: settingsRoot.theme }
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: credWarnCol.implicitHeight + 20
                radius: 8
                visible: backend.credentialStorageWarning.length > 0
                color: Qt.rgba(1, 0.75, 0.2, theme.dark ? 0.12 : 0.18)
                border.color: Qt.rgba(1, 0.75, 0.2, 0.45)
                border.width: 1
                ColumnLayout {
                    id: credWarnCol
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 4
                    Text {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        text: backend.credentialStorageWarning
                        color: theme.text
                        font.pixelSize: 13
                    }
                }
            }
            Item {
                Layout.preferredHeight: 8
                visible: backend.credentialStorageWarning.length > 0
            }
            RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42
                ColumnLayout {
                    Layout.fillWidth: true; Layout.minimumWidth: 0; spacing: 0
                    Text { Layout.fillWidth: true; elide: Text.ElideRight
                           text: qsTr("Kill switch"); color: theme.text; font.pixelSize: 14 }
                    Text { Layout.fillWidth: true; elide: Text.ElideRight
                           text: qsTr("block traffic outside the VPN"); color: theme.textFaint; font.pixelSize: 12 }
                }
                Toggle { accent: theme.accent; offColor: theme.toggleOff; checked: backend.killSwitch; onToggled: function(v){ backend.killSwitch = v } } }
            Item { Layout.preferredHeight: 16 }

            // ----- Excluded routes (subnets that bypass the tunnel) -----
            RowLayout { Layout.fillWidth: true; spacing: 10
                SectionLabel { Layout.fillWidth: true; Layout.minimumWidth: 0; elide: Text.ElideRight; theme: settingsRoot.theme; text: qsTr("Excluded routes") }
                Text { Layout.maximumWidth: 120; elide: Text.ElideRight
                       text: qsTr("Restore defaults"); font.pixelSize: 12
                       color: rdMa.containsMouse ? theme.text : theme.accent; font.underline: rdMa.containsMouse
                    MouseArea { id: rdMa; anchors.fill: parent; anchors.margins: -4; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor; onClicked: backend.restoreDefaultExcludedRoutes() } }
                Text { Layout.maximumWidth: 80; elide: Text.ElideRight
                    visible: backend.excludedRoutes.length > 0
                    text: qsTr("Clear all"); font.pixelSize: 12
                    color: clrRtMa.containsMouse ? Qt.lighter(theme.danger, 1.25) : theme.danger
                    font.underline: clrRtMa.containsMouse
                    MouseArea { id: clrRtMa; anchors.fill: parent; anchors.margins: -4; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor; onClicked: shell.showConfirm(qsTr("Clear all excluded routes?"),
                        qsTr("Clear"), function(){ backend.clearExcludedRoutes() }) } }
            }
            Flow {
                Layout.fillWidth: true; spacing: 6
                visible: backend.excludedRoutes.length > 0
                Layout.topMargin: visible ? 6 : 0
                Repeater {
                    model: backend.excludedRoutes
                    Rectangle {
                        id: rtChip
                        required property string modelData
                        required property int index
                        radius: 13; color: theme.surface
                        implicitWidth: rlabel.width + 39; implicitHeight: 28
                        Text { id: rlabel; anchors.left: parent.left; anchors.leftMargin: 11
                               anchors.verticalCenter: parent.verticalCenter; text: rtChip.modelData
                               width: Math.min(implicitWidth, 190); elide: Text.ElideRight
                               color: theme.text; font.pixelSize: 13 }
                        ChipX { theme: settingsRoot.theme; anchors.left: rlabel.right; anchors.leftMargin: 5
                                anchors.verticalCenter: parent.verticalCenter
                                onClicked: backend.removeExcludedRoute(rtChip.index) }
                    }
                }
            }
            Rectangle {
                Layout.fillWidth: true; Layout.preferredHeight: 36; radius: 8; Layout.topMargin: 6
                color: theme.inputBg; border.color: rtInput.activeFocus ? theme.accent : theme.inputBorder; border.width: 1
                TextInput {
                    id: rtInput
                    anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 12
                    verticalAlignment: TextInput.AlignVCenter; clip: true
                    font.pixelSize: 13; color: theme.text
                    onAccepted: { if (backend.addExcludedRoute(text)) text = "" }
                    Keys.onEscapePressed: focus = false
                }
                Text { anchors.left: parent.left; anchors.leftMargin: 12; anchors.verticalCenter: parent.verticalCenter
                       anchors.right: parent.right; anchors.rightMargin: 12; elide: Text.ElideRight
                       text: qsTr("IP or subnet (e.g. 10.0.0.0/8), then Enter"); color: theme.textFaint; font.pixelSize: 13
                       visible: rtInput.text.length === 0 && !rtInput.activeFocus }
            }
            Item { Layout.preferredHeight: 16 }

            SectionLabel { text: qsTr("Hotkeys"); theme: settingsRoot.theme }
            RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42
                ColumnLayout {
                    Layout.fillWidth: true; Layout.minimumWidth: 0; spacing: 0
                    Text { Layout.fillWidth: true; elide: Text.ElideRight
                           text: qsTr("Enable"); color: theme.text; font.pixelSize: 14 }
                    // Wayland can't deliver global hotkeys — say so where it's off.
                    Text { Layout.fillWidth: true; elide: Text.ElideRight; visible: !backend.hotkeysSupported
                           text: qsTr("Not available under Wayland — use an X11/Xorg session")
                           color: theme.textFaint; font.pixelSize: 12 }
                }
                Toggle { accent: theme.accent; offColor: theme.toggleOff
                         enabled: backend.hotkeysSupported
                         checked: backend.hotkeysSupported && backend.hotkeysEnabled
                         onToggled: function(v){ backend.hotkeysEnabled = v } } }
            // The shortcut fields dim out while the feature is off or unavailable.
            Item { Layout.fillWidth: true; implicitHeight: hkCol.implicitHeight
                readonly property bool hkActive: backend.hotkeysSupported && backend.hotkeysEnabled
                opacity: hkActive ? 1.0 : 0.4
                Behavior on opacity { NumberAnimation { duration: 150 } }
                enabled: hkActive
                ColumnLayout { id: hkCol; anchors.left: parent.left; anchors.right: parent.right; spacing: 0
                    HotkeyField { label: qsTr("Toggle VPN"); value: backend.hotkeyToggle; shell: settingsRoot.shell; theme: settingsRoot.theme
                        onCaptured: function(s){ backend.hotkeyToggle = s } }
                    Sep { theme: settingsRoot.theme }
                    HotkeyField { label: qsTr("Connect"); value: backend.hotkeyConnect; shell: settingsRoot.shell; theme: settingsRoot.theme
                        onCaptured: function(s){ backend.hotkeyConnect = s } }
                    Sep { theme: settingsRoot.theme }
                    HotkeyField { label: qsTr("Disconnect"); value: backend.hotkeyDisconnect; shell: settingsRoot.shell; theme: settingsRoot.theme
                        onCaptured: function(s){ backend.hotkeyDisconnect = s } }
                }
            }
            Item { Layout.preferredHeight: 16 }
            SectionLabel { text: qsTr("Logging"); theme: settingsRoot.theme }
            RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42
                ColumnLayout {
                    Layout.fillWidth: true; Layout.minimumWidth: 0; spacing: 0
                    Text { Layout.fillWidth: true; elide: Text.ElideRight
                           text: qsTr("Enable logging"); color: theme.text; font.pixelSize: 14 }
                    Text { Layout.fillWidth: true; elide: Text.ElideRight
                           text: qsTr("app and VPN core share one log file"); color: theme.textFaint; font.pixelSize: 12 }
                }
                Toggle { accent: theme.accent; offColor: theme.toggleOff; checked: backend.loggingEnabled
                         onToggled: function(v){ backend.loggingEnabled = v } } }
            RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42; enabled: backend.loggingEnabled
                opacity: backend.loggingEnabled ? 1 : 0.45
                ColumnLayout {
                    Layout.fillWidth: true; Layout.minimumWidth: 0; spacing: 0
                    Text { Layout.fillWidth: true; elide: Text.ElideRight
                           text: qsTr("Verbose logs"); color: theme.text; font.pixelSize: 14 }
                    Text { Layout.fillWidth: true; elide: Text.ElideRight
                           text: qsTr("full VPN core detail for debugging (noisy)"); color: theme.textFaint; font.pixelSize: 12 }
                }
                Toggle { accent: theme.accent; offColor: theme.toggleOff; checked: backend.verboseLogs
                         onToggled: function(v){ backend.verboseLogs = v } } }
            Item { Layout.preferredHeight: 16 }
            SectionLabel { text: qsTr("Maintenance"); theme: settingsRoot.theme }
            Item { Layout.fillWidth: true; Layout.preferredHeight: 42
                RowLayout {
                    anchors.fill: parent
                    Text { id: updTxt; Layout.fillWidth: true; Layout.minimumWidth: 0; elide: Text.ElideRight
                           // Surface the backend's status line (download %, error
                           // text, "Version X is available") while an update flow
                           // is active — the icons alone don't say what happened.
                           readonly property bool updActive: backend.updateState !== ""
                                                             && backend.updateState !== "current"
                           text: (updActive && backend.updateMessage.length > 0)
                                 ? backend.updateMessage : qsTr("Check for updates")
                           font.pixelSize: 14
                           color: updTxtMa.containsMouse ? theme.accent : theme.text
                           font.underline: updTxtMa.containsMouse
                        MouseArea { id: updTxtMa; anchors.fill: parent; hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: backend.checkForUpdates() } }
                    Row {
                        spacing: 5
                        Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                        Text {
                            visible: backend.updateState === "current"
                            text: "✓"; font.pixelSize: 14; color: theme.success
                        }
                        Text {
                            visible: backend.updateState === "checking"
                                   || backend.updateState === "downloading"
                            text: "…"; font.pixelSize: 14; color: theme.textDim
                        }
                        Text {
                            id: updIcon
                            visible: backend.updateState === "available"
                                   || backend.updateState === "error"
                                   || backend.updateState === "ready"
                            // Download vs retry are different offers and must not
                            // look identical: a failed CHECK used to show the same
                            // glyph as "a new version is waiting for you", which
                            // reads as an update that does not exist.
                            text: backend.updateState === "error" ? "↻" : "↓"
                            font.pixelSize: 17
                            color: updIconMa.containsMouse ? theme.text : theme.accent
                            rotation: updIconMa.containsMouse ? -30 : 0
                            Behavior on rotation { NumberAnimation { duration: 140; easing.type: Easing.OutCubic } }
                            MouseArea { id: updIconMa; anchors.fill: parent; anchors.margins: -6
                                        hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                                        onClicked: backend.openLatestRelease() }
                        }
                        Text {
                            visible: backend.updateState === "" || backend.updateState === "current"
                            text: backend.appVersion
                            color: theme.textFaint; font.pixelSize: 13
                        }
                    }
                }
            }
            Item { Layout.preferredHeight: 14 }
            // Footer: project names link to their repos.
            Row { Layout.alignment: Qt.AlignHCenter; spacing: 0
                Text { text: "FreeTunnel " + backend.appVersion; font.pixelSize: 12
                       color: ftMa.containsMouse ? theme.accent : theme.textFaint
                       MouseArea { id: ftMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                           onClicked: backend.openUrl("https://github.com/dimmmmmmmer/freetunnel") } }
                Text { text: "  ·  "; color: theme.textFaint; font.pixelSize: 12 }
                Text { text: qsTr("TrustTunnel core ") + backend.coreVersion; font.pixelSize: 12
                       color: ttMa.containsMouse ? theme.accent : theme.textFaint
                       MouseArea { id: ttMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                           onClicked: backend.openUrl("https://github.com/TrustTunnel/TrustTunnelClient") } }
            }
            Item { Layout.preferredHeight: 14 }
        }
    }

}
