import QtQuick
import QtQuick.Window
import QtQuick.Layouts
import QtQuick.Effects
import Qt.labs.platform as Platform
import "components"

// FreeTunnel main window: centered top nav + pages, plus back-arrow sub-screens.
// Consumes a `backend` context object injected from C++ (main.cpp).
Window {
    id: win
    visible: true
    // Default size; 400px min keeps frameless nav clear of window controls on Linux/Windows.
    width: 400
    height: 460
    minimumWidth: 400
    minimumHeight: 460
    color: theme.bg
    title: "FreeTunnel"

    // macOS keeps its native (unified) title bar; Linux/Windows go frameless
    // with our own window controls + drag/resize, so the chrome matches macOS.
    readonly property bool isMac: Qt.platform.os === "osx"
    // Custom min/max/close on frameless Linux/Windows (must match nav offset below).
    readonly property int framelessChromeWidth: 108 // 9 + 3×30 + 2×3 + 9
    // Log view and certificate editor need a fixed-pitch face. "Menlo" exists only
    // on macOS, so elsewhere it silently fell back to the proportional UI font and
    // log columns stopped lining up.
    readonly property string monoFont: Qt.platform.os === "windows" ? "Consolas"
                                     : (isMac ? "Menlo" : "monospace")
    flags: isMac ? Qt.Window : (Qt.Window | Qt.FramelessWindowHint)

    // The window's own ✕ never quits: on macOS the red traffic-light is retargeted
    // to hide natively (installMacWindowCloseToTray); on Linux and Windows the
    // custom ✕ minimizes (keeps the taskbar entry and the VPN running). So any
    // close event that actually reaches this handler is a real quit — tray «Quit»,
    // ⌘Q (macOS), Ctrl+Q / Alt+F4.
    property bool shuttingDown: false
    onClosing: function(close) {
        close.accepted = true
        if (shuttingDown || backend.applicationClosingDown())
            return
        backend.quitApplication()
    }

    Connections {
        target: backend
        function onAboutToShutdown() {
            shuttingDown = true
            // Defer so tray/dock menu items can finish closing before we tear down.
            Qt.callLater(function() { tray.visible = false })
        }
        // Every deep-link import is confirmed, not just the ones that disable
        // certificate verification — so the button is a plain «Import»; the
        // backend's message carries any warning about the link itself.
        function onDeepLinkImportConfirmationRequired(message, link, existingName) {
            if (existingName === "") {
                showConfirm(message, qsTr("Import"), function() {
                    backend.confirmDeepLinkImport(link, false)
                })
                return
            }
            // Name collision: replacing is what the user usually means when a link
            // updates a server they already have, but it is destructive, so it is
            // an explicit third choice rather than the default.
            // "Replace" is the destructive one, so it takes the danger-styled
            // primary button; "Add copy" is the safe fallback and stays neutral.
            showConfirmWithAlternate(message, qsTr("Replace"), qsTr("Add copy"),
                                     function() { backend.confirmDeepLinkImport(link, true) },
                                     function() { backend.confirmDeepLinkImport(link, false) })
        }
    }

    Shortcut { sequences: [StandardKey.Quit]; onActivated: backend.quitApplication() }

    // ---------- system tray ----------
    Platform.SystemTrayIcon {
        id: tray
        visible: true
        // Green mark when connected — the configs-page "connected" badge
        // color — dimmed when off.
        icon.source: backend.connected ? "qrc:/assets/logo-green.svg" : "qrc:/assets/logo-dim.svg"
        tooltip: backend.connected ? qsTr("FreeTunnel — %1").arg(backend.activeConfig)
                                    : "FreeTunnel"
        // Right-click opens the menu (below). Double-click — or a single left-click
        // on Windows, the expected tray gesture there — brings the window forward.
        // macOS is excluded outright: there the status item owns an NSMenu, so Qt
        // emits activated() from NSMenuDidBeginTracking and derives the reason from
        // NSApp.currentEvent.clickCount — a second quick click on the icon arrives
        // as DoubleClick even though the user only opened the menu, which popped the
        // hidden window back open. The menu's «Show FreeTunnel» item and the Dock
        // icon are the macOS ways back.
        onActivated: function(reason) {
            if (win.isMac)
                return
            if (reason === Platform.SystemTrayIcon.DoubleClick
                    || (reason === Platform.SystemTrayIcon.Trigger && Qt.platform.os === "windows")) {
                win.show(); win.raise(); win.requestActivate()
            }
        }
        menu: Platform.Menu {
            // Plain connect/disconnect action button.
            Platform.MenuItem {
                text: backend.disconnecting ? qsTr("Disconnecting…")
                      : backend.connecting ? qsTr("Connecting…")
                      : backend.connected ? qsTr("Disconnect") : qsTr("Connect")
                enabled: backend.configs.length > 0
                onTriggered: backend.toggle()
            }
            // Active config + session time on one line (only while connected).
            Platform.MenuItem {
                enabled: false; visible: backend.connected
                text: backend.activeConfig + "  ·  " + backend.sessionTime
            }
            Platform.MenuSeparator {}
            // Configs listed inline; the active one carries a checkmark.
            Instantiator {
                model: backend.configs
                delegate: Platform.MenuItem {
                    required property int index
                    required property string modelData
                    text: modelData
                    checkable: true
                    checked: index === backend.activeIndex
                    onTriggered: backend.selectConfig(index)
                }
                onObjectAdded: (i, obj) => tray.menu.insertItem(i + 3, obj)
                onObjectRemoved: (i, obj) => tray.menu.removeItem(obj)
            }
            Platform.MenuSeparator { visible: backend.configs.length > 0 }
            Platform.MenuItem {
                text: qsTr("Show FreeTunnel")
                onTriggered: { win.show(); win.raise(); win.requestActivate() }
            }
            Platform.MenuItem {
                text: qsTr("Quit")
                onTriggered: backend.quitApplication()
            }
        }
    }

    // Active palette: light/dark, or follow the OS when themeMode === "system".
    readonly property bool systemDark: Application.styleHints.colorScheme === Qt.Dark
    readonly property QtObject theme: QtObject {
        readonly property bool dark: backend.themeMode === "dark"
                                     || (backend.themeMode === "system" && win.systemDark)
        // Pure neutral gray ramp — true monochrome (R = G = B), no tint.
        readonly property color bg: dark ? "#181818" : "#ececec"
        readonly property color surface: dark ? "#262626" : "#e2e2e2"
        readonly property color tile: dark ? "#202020" : "#d8d8d8"
        readonly property color inputBg: dark ? "#101010" : "#d6d6d6" // darker than the card
        // A clearly visible outline for input fields (the plain border is too
        // faint against the light background).
        readonly property color inputBorder: dark ? "#3a3a3a" : "#c2c2c2"
        readonly property color text: dark ? "#eaeaea" : "#1b1b1b"
        readonly property color textDim: dark ? "#9a9a9a" : "#6b6b6b"
        readonly property color textFaint: dark ? "#6a6a6a" : "#9a9a9a"
        readonly property color accent: dark ? "#b0b0b0" : "#4f4f4f"
        readonly property color border: dark ? "#2e2e2e" : "#e5e5e5"
        // Off-state track for switches: clearly darker than the (light) accent
        // in dark mode so on/off don't blur together.
        readonly property color toggleOff: dark ? "#3a3a3a" : "#c4c4c4"
        readonly property color success: dark ? "#3fbf93" : "#1d9e75"
        readonly property color warn: dark ? "#d99634" : "#ba7517"
        readonly property color danger: dark ? "#e06a6a" : "#a32d2d"
        readonly property color infoBg: dark ? Qt.rgba(0.69, 0.69, 0.69, 0.16)
                                             : Qt.rgba(0.31, 0.31, 0.31, 0.12)
    }

    property int currentPage: 0
    property string overlay: "" // "", "create", "apps"
    property int editIndex: -1  // config being edited in the create overlay (-1 = new)
    // True while a window-level popup already owns Escape (the select dropdown or
    // the confirm dialog). Sub-screens must disable their own Escape shortcut
    // then: two *enabled* shortcuts on the same key make Qt report the press as
    // ambiguous and neither handler runs, so Escape would go dead entirely.
    readonly property bool windowPopupOpen: selectPopup.open || winConfirm.visible
    // nav order: Home, Configs, Split, Settings, Logs (configs before split)
    readonly property var navIcons: ["connection", "configs", "network", "settings", "log"]
    readonly property var pagePaths: ["pages/HomePage.qml", "pages/ConfigsPage.qml",
                                      "pages/SplitPage.qml", "pages/SettingsPage.qml",
                                      "pages/LogsPage.qml"]

    // Pages/overlay get shell+backend+theme as *initial* properties via
    // Loader.setSource so their `required` properties are satisfied at creation.
    // Setting them later in onLoaded runs after the component is built, which
    // breaks the required-property contract and leaves the page blank.
    function pageProps() { return { shell: win, backend: backend, theme: win.theme } }
    onCurrentPageChanged: pageLoader.setSource(pagePaths[currentPage], pageProps())
    onOverlayChanged: {
        var src = overlay === "create" ? "CreateConfigOverlay.qml"
                : overlay === "apps" ? "AppPickerOverlay.qml" : ""
        overlayLoader.setSource(src, src === "" ? {} : pageProps())
    }

    // Map a Qt key code to a portable QKeySequence name (used by HotkeyField).
    function keyName(key, text) {
        if (key >= Qt.Key_A && key <= Qt.Key_Z) return String.fromCharCode(key)
        if (key >= Qt.Key_0 && key <= Qt.Key_9) return String.fromCharCode(key)
        if (key >= Qt.Key_F1 && key <= Qt.Key_F12) return "F" + (key - Qt.Key_F1 + 1)
        var m = {}
        m[Qt.Key_Space] = "Space"; m[Qt.Key_Tab] = "Tab"; m[Qt.Key_Return] = "Return"
        m[Qt.Key_Enter] = "Enter"; m[Qt.Key_Home] = "Home"; m[Qt.Key_End] = "End"
        m[Qt.Key_Insert] = "Ins"; m[Qt.Key_PageUp] = "PgUp"; m[Qt.Key_PageDown] = "PgDown"
        m[Qt.Key_Up] = "Up"; m[Qt.Key_Down] = "Down"; m[Qt.Key_Left] = "Left"; m[Qt.Key_Right] = "Right"
        if (m[key] !== undefined) return m[key]
        // ASCII printable only — a non-Latin layout (e.g. Russian) reports a
        // Cyrillic char here, which QKeySequence/QHotkey can't use. Returning ""
        // lets HotkeyField recover the Latin letter from the physical key code.
        if (text && text.length === 1) {
            var cc = text.charCodeAt(0)
            if (cc >= 33 && cc < 127) return text.toUpperCase()
        }
        return ""
    }

    // Truncate a long string with an ellipsis (used in confirm messages).
    function elide(s, n) { return s.length > n ? s.substring(0, n - 1) + "…" : s }
    // Keep both ends of a long name visible inside quoted confirm text.
    function elideMiddle(s, n) {
        if (s.length <= n) return s
        if (n <= 1) return "…"
        var keep = n - 1
        var head = Math.ceil(keep / 2)
        var tail = Math.floor(keep / 2)
        return s.substring(0, head) + "…" + s.substring(s.length - tail)
    }

    // Render a portable shortcut ("Ctrl+Alt+T") with OS-native modifier glyphs.
    function keyGlyphs(seq) {
        if (!seq) return ""
        if (Qt.platform.os === "osx")
            return seq.replace(/Ctrl/g, "⌘").replace(/Meta/g, "⌃")
                      .replace(/Alt/g, "⌥").replace(/Shift/g, "⇧").replace(/\+/g, "")
        return seq
    }

    function showToast(m) { toast.show(m) }

    // Neutral focus target: clicking empty space moves focus here, blurring any
    // text field that was being edited.
    Item { id: focusSink }
    // Backmost catcher (declared first → behind everything): a press on empty
    // background clears text-field focus.
    MouseArea {
        anchors.fill: parent
        onPressed: function(m) { focusSink.forceActiveFocus(); m.accepted = false }
    }

    // ---------- title-bar drag region ----------
    // Sits above the back-catcher but below the nav buttons; catches presses on
    // the empty top band and starts a native window move.
    MouseArea {
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        height: Qt.platform.os === "osx" ? 70 : 52
        onPressed: backend.startWindowDrag(win)
    }

    // ---------- custom window controls (Linux/Windows) ----------
    // macOS keeps its native traffic lights; elsewhere we draw our own so the
    // frameless window can still minimize / maximize / close.
    Row {
        visible: !win.isMac
        z: 60
        anchors.top: parent.top; anchors.right: parent.right
        anchors.topMargin: 9; anchors.rightMargin: 9
        spacing: 3
        // minimize
        Rectangle { width: 30; height: 24; radius: 6
            // Fade out to a *transparent surface* (same RGB, 0 alpha), not to
            // "transparent" (= transparent black): a ColorAnimation to/from black
            // lerps the RGB channels and flashes dark before reaching the light hue.
            color: minMa.containsMouse ? theme.surface : Qt.rgba(theme.surface.r, theme.surface.g, theme.surface.b, 0)
            Behavior on color { ColorAnimation { duration: 100 } }
            Rectangle { anchors.centerIn: parent; width: 11; height: 1.4; radius: 1; color: theme.textDim }
            MouseArea { id: minMa; anchors.fill: parent; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor; onClicked: win.showMinimized() }
        }
        // maximize / restore
        Rectangle { width: 30; height: 24; radius: 6
            color: maxMa.containsMouse ? theme.surface : Qt.rgba(theme.surface.r, theme.surface.g, theme.surface.b, 0)
            Behavior on color { ColorAnimation { duration: 100 } }
            Rectangle { anchors.centerIn: parent; width: 10; height: 10; radius: 2
                        color: "transparent"; border.color: theme.textDim; border.width: 1.4 }
            MouseArea { id: maxMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                        onClicked: win.visibility = (win.visibility === Window.Maximized ? Window.Windowed : Window.Maximized) }
        }
        // close: minimize to the taskbar/dock (Linux and Windows alike) rather than
        // hide. A hidden window vanishes from the taskbar entirely, which is
        // disorienting (and on Linux/GNOME a hidden window can't be reliably
        // brought back). Minimizing keeps the entry and the VPN running; the tray
        // icon is always present too.
        Rectangle { width: 30; height: 24; radius: 6
            color: closeMa.containsMouse ? theme.danger : Qt.rgba(theme.danger.r, theme.danger.g, theme.danger.b, 0)
            Behavior on color { ColorAnimation { duration: 100 } }
            Item { anchors.centerIn: parent; width: 12; height: 12
                Rectangle { anchors.centerIn: parent; width: 13; height: 1.4; radius: 1; rotation: 45
                            color: closeMa.containsMouse ? "white" : theme.textDim }
                Rectangle { anchors.centerIn: parent; width: 13; height: 1.4; radius: 1; rotation: -45
                            color: closeMa.containsMouse ? "white" : theme.textDim }
            }
            MouseArea { id: closeMa; anchors.fill: parent; hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: win.showMinimized() }
        }
    }

    // ---------- resize grips (frameless Linux/Windows) ----------
    Item {
        visible: !win.isMac; anchors.fill: parent; z: 55
        MouseArea { height: 5; anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
            cursorShape: Qt.SizeVerCursor; onPressed: win.startSystemResize(Qt.TopEdge) }
        MouseArea { height: 5; anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
            cursorShape: Qt.SizeVerCursor; onPressed: win.startSystemResize(Qt.BottomEdge) }
        MouseArea { width: 5; anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.left: parent.left
            cursorShape: Qt.SizeHorCursor; onPressed: win.startSystemResize(Qt.LeftEdge) }
        MouseArea { width: 5; anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.right: parent.right
            cursorShape: Qt.SizeHorCursor; onPressed: win.startSystemResize(Qt.RightEdge) }
        MouseArea { width: 11; height: 11; anchors.top: parent.top; anchors.left: parent.left
            cursorShape: Qt.SizeFDiagCursor; onPressed: win.startSystemResize(Qt.TopEdge | Qt.LeftEdge) }
        MouseArea { width: 11; height: 11; anchors.top: parent.top; anchors.right: parent.right
            cursorShape: Qt.SizeBDiagCursor; onPressed: win.startSystemResize(Qt.TopEdge | Qt.RightEdge) }
        MouseArea { width: 11; height: 11; anchors.bottom: parent.bottom; anchors.left: parent.left
            cursorShape: Qt.SizeBDiagCursor; onPressed: win.startSystemResize(Qt.BottomEdge | Qt.LeftEdge) }
        MouseArea { width: 11; height: 11; anchors.bottom: parent.bottom; anchors.right: parent.right
            cursorShape: Qt.SizeFDiagCursor; onPressed: win.startSystemResize(Qt.BottomEdge | Qt.RightEdge) }
    }

    // ---------- main content (nav + page) ----------
    // Stays visible behind the create popup (dimmed by its backdrop).
    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: Qt.platform.os === "osx" ? 26 : 36
            Layout.bottomMargin: 6
            spacing: 0

            // Mirror the top-right window controls on the left so the nav sits
            // in the true horizontal centre of the title bar (Linux/Windows).
            Item { Layout.preferredWidth: win.isMac ? 0 : win.framelessChromeWidth
                   Layout.maximumWidth: win.isMac ? 0 : win.framelessChromeWidth }

            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: 38
                Row {
                    anchors.horizontalCenter: parent.horizontalCenter
                    spacing: 8
                    Repeater {
                        model: win.navIcons
                        Rectangle {
                            id: navItem
                            required property int index
                            required property string modelData
                            property bool active: index === win.currentPage
                            width: 46; height: 38; radius: 8
                            color: theme.bg
                            Rectangle {
                                anchors.fill: parent; radius: parent.radius; color: theme.surface
                                opacity: (nma.containsMouse && !navItem.active) ? 1 : 0
                                Behavior on opacity { NumberAnimation { duration: 120 } }
                            }
                            Rectangle {
                                anchors.fill: parent; radius: parent.radius; color: theme.infoBg
                                opacity: navItem.active ? 1 : 0
                                Behavior on opacity { NumberAnimation { duration: 120 } }
                            }
                            scale: nma.containsMouse && !active ? 1.08 : 1.0
                            Behavior on scale { NumberAnimation { duration: 120; easing.type: Easing.OutCubic } }
                            Image {
                                visible: navItem.modelData === "connection"
                                anchors.centerIn: parent; width: 22; height: 22
                                source: "qrc:/assets/logo.svg"; sourceSize: Qt.size(44, 44)
                                opacity: navItem.active ? 1.0 : 0.8
                            }
                            Icon {
                                visible: navItem.modelData !== "connection"
                                anchors.centerIn: parent; width: 22; height: 22
                                theme: win.theme
                                svg: navItem.modelData === "configs" ? "qrc:/icons/connection.svg"
                                                                     : "qrc:/icons/" + navItem.modelData + ".svg"
                                color: navItem.active ? theme.accent : theme.textDim
                            }
                            // Dot on Settings when a newer release was found at startup.
                            Rectangle {
                                visible: navItem.index === 3 && backend.updateState === "available"
                                width: 7; height: 7; radius: 3.5
                                color: theme.warn
                                anchors.top: parent.top; anchors.right: parent.right
                                anchors.topMargin: 5; anchors.rightMargin: 8
                            }
                            MouseArea { id: nma; anchors.fill: parent; hoverEnabled: true
                                        onClicked: win.currentPage = navItem.index }
                        }
                    }
                }
            }

            Item { Layout.preferredWidth: win.isMac ? 0 : win.framelessChromeWidth
                   Layout.maximumWidth: win.isMac ? 0 : win.framelessChromeWidth }
        }

        Loader {
            id: pageLoader
            Layout.fillWidth: true
            Layout.fillHeight: true
            Component.onCompleted: setSource(win.pagePaths[win.currentPage], win.pageProps())
        }
    }

    // ---------- sub-screen overlay ----------
    // Loaded on demand by win.onOverlayChanged via setSource (see above).
    Loader {
        id: overlayLoader
        anchors.fill: parent
    }

    // ---------- toast (errors/notices) ----------
    Connections {
        target: backend
        function onErrorOccurred(msg) { toast.show(msg) }
        function onConfigImported(name) { toast.show(qsTr("Config added: %1").arg(name)) }
        function onUpdateChanged() {
            if (backend.updateState === "available")
                toast.show(qsTr("Update available: %1").arg(backend.latestVersion))
        }
    }
    Rectangle {
        id: toast
        z: 1000
        property string message: ""
        TextMetrics { id: toastMetrics; font.pixelSize: 13 }
        function show(m) {
            toastMetrics.text = m
            message = m
            opacity = 0.97
            toastTimer.restart()
        }
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom; anchors.bottomMargin: 26
        // Size to the message text (TextMetrics), not tmsg.implicitWidth — binding
        // tmsg.width to toast.width made implicitWidth inflate and left empty margins.
        width: Math.min(parent.width - 36, Math.max(80, Math.ceil(toastMetrics.boundingRect.width) + 24))
        height: Math.max(40, tmsg.contentHeight + 18)
        radius: 9; color: theme.surface; border.color: theme.border; border.width: 1
        opacity: 0; visible: opacity > 0
        Text {
            id: tmsg; anchors.centerIn: parent; width: toast.width - 24
            text: toast.message; color: theme.text; font.pixelSize: 13
            horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
            maximumLineCount: 3; elide: Text.ElideRight
        }
        Behavior on opacity { NumberAnimation { duration: 180 } }
        Timer { id: toastTimer; interval: 3200; onTriggered: toast.opacity = 0 }
        MouseArea { anchors.fill: parent; onClicked: toast.opacity = 0 }
    }

    // ---------- window-level select popup (used by Dropdown) ----------
    TextMetrics { id: spMetrics; font.pixelSize: 14 }
    readonly property int spRowH: 36
    function showSelect(anchorItem, model, value, cb) {
        selectPopup.model = model
        selectPopup.value = value
        selectPopup.cb = cb
        // Size to the widest option (+ room for the left pad and check mark),
        // clamped to the window so it never spills off the edge.
        var w = 140
        for (var i = 0; i < model.length; i++) {
            spMetrics.text = model[i].t
            w = Math.max(w, spMetrics.advanceWidth + 56)
        }
        selectPopup.width = Math.min(w, overlayLayer.width - 16)

        // Vertical placement: always keep the whole popup inside the window.
        // Prefer opening just under the anchor; flip above it when there isn't
        // room below; and when neither side can show every row (many profiles,
        // or an export menu on the bottom config row) cap the height and let the
        // list scroll — same as the config list on the home page.
        var below = anchorItem.mapToItem(overlayLayer, anchorItem.width, anchorItem.height + 4)
        var above = anchorItem.mapToItem(overlayLayer, anchorItem.width, -4)
        var spaceBelow = overlayLayer.height - below.y - 8
        var spaceAbove = above.y - 8
        var minH = spRowH + 12
        // A sanity cap so a long list never becomes a full-height wall on big screens.
        var natural = Math.min(model.length, 8) * spRowH + 12

        var h, y
        if (natural <= spaceBelow)        { h = natural; y = below.y }
        else if (natural <= spaceAbove)   { h = natural; y = above.y - natural }
        else if (spaceBelow >= spaceAbove) { h = Math.max(minH, spaceBelow); y = below.y }
        else                               { h = Math.max(minH, spaceAbove); y = above.y - h }
        // Final clamp guards rounding and very short windows on both edges.
        y = Math.max(8, Math.min(y, overlayLayer.height - h - 8))
        selectPopup.height = h
        selectPopup.y = y

        // Anchor under the right edge of the value (so it opens where the choice is).
        selectPopup.x = Math.max(8, Math.min(below.x - selectPopup.width, overlayLayer.width - selectPopup.width - 8))
        selectPopup.open = true
    }
    Item {
        id: overlayLayer; anchors.fill: parent; z: 1500
        visible: selectPopup.open
        MouseArea { anchors.fill: parent; onClicked: selectPopup.open = false }
        // Stand down while a confirm dialog is up: it owns Escape then, and two
        // enabled shortcuts on the same key make Qt report the press as
        // ambiguous — Escape would do nothing at all.
        Shortcut { sequence: "Escape"
                   enabled: selectPopup.open && !winConfirm.visible
                   onActivated: selectPopup.open = false }
        Rectangle {
            id: selectPopup
            property bool open: false
            property var model: []
            property string value: ""
            property var cb: null
            visible: opacity > 0
            opacity: open ? 1 : 0
            Behavior on opacity { NumberAnimation { duration: 130 } }
            transform: Translate { y: selectPopup.open ? 0 : -8
                                   Behavior on y { NumberAnimation { duration: 140; easing.type: Easing.OutCubic } } }
            width: 200
            // height is set imperatively in showSelect() so the popup can flip /
            // scroll to stay inside the window.
            radius: 10; color: theme.bg; border.color: theme.border; border.width: 1
            layer.enabled: true
            layer.effect: MultiEffect {
                shadowEnabled: true; shadowColor: "#000000"
                shadowOpacity: theme.dark ? 0.5 : 0.2; shadowBlur: 0.7; shadowVerticalOffset: 5
            }
            ListView {
                id: spList
                anchors.fill: parent; anchors.margins: 6
                clip: true
                model: selectPopup.model
                // Scroll only when the rows don't all fit (e.g. many profiles).
                interactive: contentHeight > height
                boundsBehavior: Flickable.StopAtBounds
                delegate: Rectangle {
                    required property var modelData
                    width: spList.width; height: win.spRowH; radius: 6
                    color: spMa.containsMouse ? theme.surface : theme.bg
                    Text { anchors.verticalCenter: parent.verticalCenter; x: 12
                           text: modelData.t
                           color: modelData.v === selectPopup.value ? theme.accent : theme.text
                           font.pixelSize: 14 }
                    Text { visible: modelData.v === selectPopup.value; text: "✓"; color: theme.accent
                           anchors.right: parent.right; rightPadding: 12; anchors.verticalCenter: parent.verticalCenter }
                    MouseArea { id: spMa; anchors.fill: parent; hoverEnabled: true
                                onClicked: { selectPopup.open = false; if (selectPopup.cb) selectPopup.cb(modelData.v) } }
                }
            }
        }
    }

    // ---------- window-level confirm dialog (covers the whole window) --------
    property var confirmCb: null
    property var confirmAltCb: null
    // Requests that arrived while a dialog was already up, oldest first.
    property var confirmQueue: []
    function showConfirm(message, confirmLabel, cb) {
        showConfirmWithAlternate(message, confirmLabel, "", cb, null)
    }
    // altLabel === "" keeps the plain two-button dialog.
    function showConfirmWithAlternate(message, confirmLabel, altLabel, cb, altCb) {
        // A second request used to overwrite the live dialog in place, so the
        // user answered a question they never read using the buttons of the
        // previous one — and the callback that ran was the new one. Deep links
        // arrive asynchronously and can legitimately land back to back, so
        // queue instead of clobbering.
        if (winConfirm.visible) {
            confirmQueue.push({ message: message, confirmLabel: confirmLabel,
                                altLabel: altLabel, cb: cb, altCb: altCb })
            return
        }
        applyConfirm(message, confirmLabel, altLabel, cb, altCb)
    }
    function applyConfirm(message, confirmLabel, altLabel, cb, altCb) {
        winConfirm.text = message
        winConfirm.confirmText = confirmLabel
        winConfirm.altText = altLabel
        win.confirmCb = cb
        win.confirmAltCb = altCb
        winConfirm.open()
    }
    function showNextConfirm() {
        if (winConfirm.visible || confirmQueue.length === 0)
            return
        var next = confirmQueue.shift()
        applyConfirm(next.message, next.confirmLabel, next.altLabel, next.cb, next.altCb)
    }
    ConfirmDialog { id: winConfirm; z: 2500; theme: win.theme
                    escapeOwner: !(overlayLoader.item && overlayLoader.item.confirmVisible)
        onConfirmed: if (win.confirmCb) win.confirmCb()
        onAlternate: if (win.confirmAltCb) win.confirmAltCb()
        // Deferred: the dialog clears `visible` before it emits confirmed()/
        // alternate(), so showing the next one inline would replace confirmCb
        // before the answer to the current question had run.
        onVisibleChanged: if (!visible) Qt.callLater(win.showNextConfirm) }

}
