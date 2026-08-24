pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// The Nexthop panel: header verdict, five tabs, one alive at a time.
//
// All data arrives through files the daemon writes — live.json via FileView
// for the always-current numbers, recent.json for the default graphs, and
// `nexthop query` through a Process when a tab asks for a longer window.
// The panel never probes anything itself.
Panel {
  id: root
  moduleName: "io.github.x3me.nexthop"
  ipcTarget: "io.github.x3me.nexthop"
  manageIpc: false

  property var anchorItem: null
  property bool openedFromHotkey: false
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  // ---- palette -------------------------------------------------------------
  readonly property color fg: bar ? bar.foreground : Color.popups.text
  readonly property color dim: Color.muted
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color okTone: "#9ece6a"
  readonly property color warnTone: "#e0af68"

  function bandColor(idx) {
    if (idx === null || idx === undefined) return dim
    if (idx >= 80) return okTone
    if (idx >= 50) return warnTone
    return Color.urgent
  }

  // ---- state files ---------------------------------------------------------
  readonly property string stateDir: {
    var base = Quickshell.env("XDG_STATE_HOME")
    if (!base || base.length === 0) base = Quickshell.env("HOME") + "/.local/state"
    return base + "/nexthop"
  }
  readonly property string pluginDir:
    Qt.resolvedUrl(".").toString().replace(/^file:\/\//, "").replace(/\/$/, "")

  property var live: null
  property var recent: null

  // Every state file has a known small size; a file past its bound is not
  // ours and is never parsed. live ~1 KB, apps ~8 KB, recent ~30 KB.
  function parseBounded(raw, cap) {
    if (!raw || raw.length > cap) return null
    try { return JSON.parse(raw) } catch (e) { return null }
  }

  FileView {
    path: root.stateDir + "/live.json"
    watchChanges: true
    printErrors: false
    onLoaded: {
      var v = root.parseBounded(text(), 262144)
      if (v !== null) root.live = v
    }
    onFileChanged: reload()
  }

  property var appsData: null

  FileView {
    path: root.stateDir + "/apps.json"
    watchChanges: true
    printErrors: false
    onLoaded: {
      var v = root.parseBounded(text(), 1048576)
      if (v !== null) root.appsData = v
    }
    onFileChanged: reload()
  }

  FileView {
    path: root.stateDir + "/recent.json"
    watchChanges: true
    printErrors: false
    onLoaded: {
      var v = root.parseBounded(text(), 1048576)
      if (v !== null) root.recent = v
    }
    onFileChanged: reload()
  }

  // recent.json points, trimmed to the slots that actually have data.
  readonly property var recentPoints: {
    if (!recent || !recent.points) return []
    var pts = recent.points
    var first = -1
    for (var i = 0; i < pts.length; i++) {
      if (pts[i].total !== null) { first = i; break }
    }
    return first < 0 ? [] : pts.slice(first)
  }

  // ---- daemon config -------------------------------------------------------
  // Settings live in shell.json; the daemon can't read that, so mirror the
  // keys it cares about into its config file whenever they change.
  onSettingsChanged: writeDaemonConfig()
  Component.onCompleted: writeDaemonConfig()

  function writeDaemonConfig() {
    var cfg = {
      internetAnchor: setting("internetAnchor", "1.1.1.1"),
      probeIntervalMs: setting("probeIntervalMs", 500),
      contentSpeed: setting("contentSpeed", true),
      contentSpeedIntervalMin: setting("contentSpeedIntervalMin", 60),
      peakEngine: setting("peakEngine", "Auto"),
      planDownMbps: setting("planDownMbps", 0),
      planUpMbps: setting("planUpMbps", 0),
      notifyOutage: setting("notifyOutage", true),
      historyDays: setting("historyDays", 7),
      throughputWindowS: setting("throughputWindowS", 3),
    }
    configWriter.command = ["sh", "-c",
      "mkdir -p \"$2\" && printf %s \"$1\" > \"$2/config.json\"",
      "sh", JSON.stringify(cfg), stateDir]
    configWriter.running = true
  }

  Process { id: configWriter }

  // ---- history queries -----------------------------------------------------
  // Tabs ask for a window; results land in `history` tagged by the request.
  property var history: null
  property string historyWindow: ""
  property bool historyLoading: false

  function requestHistory(window) {
    historyWindow = window
    historyLoading = true
    historyProc.command = ["sh", "-c",
      "cd \"$1\" && exec python3 -m nexthopd.cli query --window \"$2\"",
      "sh", pluginDir, window]
    historyProc.running = true
  }

  Process {
    id: historyProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.historyLoading = false
        try { root.history = JSON.parse(text) } catch (e) { root.history = null }
      }
    }
  }

  property var testsData: null
  function requestTests() {
    testsProc.command = ["sh", "-c",
      "cd \"$1\" && exec python3 -m nexthopd.cli tests --limit 24",
      "sh", pluginDir]
    testsProc.running = true
  }
  Process {
    id: testsProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: { try { root.testsData = JSON.parse(text) } catch (e) {} }
    }
  }

  property var eventsData: null
  function requestEvents(window) {
    eventsProc.command = ["sh", "-c",
      "cd \"$1\" && exec python3 -m nexthopd.cli events --window \"$2\"",
      "sh", pluginDir, window || "7d"]
    eventsProc.running = true
  }
  Process {
    id: eventsProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: { try { root.eventsData = JSON.parse(text) } catch (e) {} }
    }
  }

  function runPeakTest() {
    peakProc.command = ["sh", "-c",
      "cd \"$1\" && exec python3 -m nexthopd.cli peak", "sh", pluginDir]
    peakProc.running = true
  }
  Process { id: peakProc }

  function copyReport(window) {
    reportProc.command = ["sh", "-c",
      "cd \"$1\" && python3 -m nexthopd.cli report --window \"$2\" | wl-copy",
      "sh", pluginDir, window || "24h"]
    reportProc.running = true
  }
  Process { id: reportProc }

  // ---- open / close --------------------------------------------------------
  function open() {
    openedFromHotkey = false
    setCenterHoverRevealSuppressed(false)
    root.controller.show()
  }

  function openFromHotkey() {
    openedFromHotkey = true
    root.controller.show()
    Qt.callLater(function() {
      if (root.opened) setCenterHoverRevealSuppressed(true)
    })
  }

  function close() {
    setCenterHoverRevealSuppressed(false)
    root.controller.hide()
  }

  function toggle() { root.opened ? root.close() : root.openFromHotkey() }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  function setCenterHoverRevealSuppressed(value) {
    if (root.bar && "centerHoverRevealSuppressed" in root.bar)
      root.bar.centerHoverRevealSuppressed = value
  }

  onOpenedChanged: {
    if (opened) Qt.callLater(function() {
      if (keyCatcher) keyCatcher.forceActiveFocus()
    })
  }

  // ---- tabs ----------------------------------------------------------------
  readonly property var tabNames: ["Overview", "Latency", "Speed", "Wi-Fi", "Apps", "Events"]
  property int currentTab: 0

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.openFromHotkey() }
    function close(): void { root.close() }
    function show(): void { root.openFromHotkey() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function speedTest(): void { root.runPeakTest() }
    function showTab(name: string): void {
      var i = root.tabNames.indexOf(name)
      if (i >= 0) root.currentTab = i
      root.openFromHotkey()
    }
  }

  // ---- surface -------------------------------------------------------------
  KeyboardPanel {
    id: panelCard
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panelCard.fittedContentWidth(Style.space(524))
    contentHeight: panelCard.fittedContentHeight(bodyColumn.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Keys.onPressed: function(event) {
        // Left/right walk the tab strip; 1-5 jump straight to a tab.
        if (event.key === Qt.Key_Left) {
          root.currentTab = (root.currentTab + root.tabNames.length - 1) % root.tabNames.length
          event.accepted = true
        } else if (event.key === Qt.Key_Right) {
          root.currentTab = (root.currentTab + 1) % root.tabNames.length
          event.accepted = true
        } else if (event.key >= Qt.Key_1 && event.key <= Qt.Key_6) {
          root.currentTab = event.key - Qt.Key_1
          event.accepted = true
        }
      }

      Column {
        id: bodyColumn
        width: parent.width
        spacing: Style.space(12)

        // ---- header: identity + verdict ---------------------------------
        Item {
          width: parent.width
          height: Math.max(headerLeft.implicitHeight, headerRight.implicitHeight)

          Row {
            id: headerLeft
            spacing: Style.space(10)

            Text {
              textFormat: Text.PlainText
              text: {
                var s = root.live ? root.live.state : ""
                if (s === "local-down" || s === "wan-down") return "󱚵"
                return "󰓅"
              }
              color: root.bandColor(root.live ? root.live.index : null)
              font.family: root.fontFamily
              font.pixelSize: Style.fontPx(1.6)
              anchors.verticalCenter: parent.verticalCenter
            }

            Column {
              spacing: Style.space(2)
              anchors.verticalCenter: parent.verticalCenter

              Text {
                textFormat: Text.PlainText
                text: {
                  var l = root.live
                  if (!l || !l.link) return "Nexthop"
                  return l.link.ssid || l.link.name || l.link.iface || "Nexthop"
                }
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.heading
                font.weight: Font.Bold
              }
              Text {
                textFormat: Text.PlainText
                text: {
                  var l = root.live
                  if (!l) return "WAITING FOR DAEMON"
                  if (l.state === "local-down") return "ROUTER UNREACHABLE"
                  if (l.state === "wan-down") return "NO INTERNET · ROUTER OK"
                  return (l.band || "").toUpperCase()
                }
                color: root.live && root.live.state !== "online"
                  ? Color.urgent : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.letterSpacing: 1
              }
            }
          }

          Column {
            id: headerRight
            anchors.right: parent.right
            spacing: Style.space(1)

            Text {
              textFormat: Text.PlainText
              anchors.right: parent.right
              text: root.live && root.live.index !== null && root.live.index !== undefined
                ? String(root.live.index) : "--"
              color: root.bandColor(root.live ? root.live.index : null)
              font.family: root.fontFamily
              font.pixelSize: Style.fontPx(2.4)
              font.weight: Font.Bold
            }
            Text {
              textFormat: Text.PlainText
              anchors.right: parent.right
              text: "EXPERIENCE"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.letterSpacing: 1
            }
          }
        }

        // ---- tab strip ---------------------------------------------------
        Row {
          width: parent.width
          spacing: Style.space(6)

          Repeater {
            model: root.tabNames

            Rectangle {
              id: tabButton
              required property string modelData
              required property int index
              readonly property bool selected: root.currentTab === index

              width: (parent.width - Style.space(6) * (root.tabNames.length - 1))
                / root.tabNames.length
              height: Style.space(26)
              color: selected
                ? Style.selectedFillFor(root.fg, Color.accent)
                : (tabHover.hovered
                   ? Style.hoverFillFor(root.fg, Color.accent)
                   : Style.normalFillFor(root.fg, Color.accent))
              border.width: selected ? 0 : Style.normalBorderWidth
              border.color: Style.normalBorderFor(root.fg, Color.accent)

              Text {
                textFormat: Text.PlainText
                anchors.centerIn: parent
                text: tabButton.modelData
                color: tabButton.selected ? root.fg : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              HoverHandler { id: tabHover }
              TapHandler { onTapped: root.currentTab = tabButton.index }
            }
          }
        }

        PanelSeparator { width: parent.width }

        // ---- the selected tab -------------------------------------------
        Loader {
          width: parent.width
          active: root.opened
          sourceComponent: [overviewTab, latencyTab, speedTab, wifiTab,
                            appsTab, eventsTab][root.currentTab]
        }
      }
    }
  }

  Component { id: overviewTab; OverviewTab { panel: root } }
  Component { id: latencyTab; LatencyTab { panel: root } }
  Component { id: speedTab; SpeedTab { panel: root } }
  Component { id: wifiTab; WifiTab { panel: root } }
  Component { id: appsTab; AppsTab { panel: root } }
  Component { id: eventsTab; EventsTab { panel: root } }
}
