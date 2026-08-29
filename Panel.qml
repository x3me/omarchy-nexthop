pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// The Nexthop panel: header verdict, five tabs, one alive at a time.
//
// All data arrives through files the daemon writes, but never through a
// file handle the shell holds: `nexthop stream` reads live.json (the
// always-current numbers), apps.json and recent.json (the default graphs)
// and feeds them here as lines, and `nexthop query` runs on demand when a
// tab asks for a longer window. The panel never probes anything itself.
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

  // The panel opens no file of its own. The bar widget that creates it
  // owns the single `nexthop stream` reader — a bounded, non-blocking,
  // no-follow, regular-file-only read out in a small helper — and the
  // panel binds to what it already parsed.
  readonly property var live: hostWidget ? hostWidget.live : null
  readonly property var recent: hostWidget ? hostWidget.recent : null
  readonly property var appsData: hostWidget ? hostWidget.appsData : null

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
    // Written atomically via mkstemp + rename — the same discipline the
    // daemon's own writers use. A shell redirection here would be a
    // truncating, symlink-following write at a predictable path: exactly
    // the class the security review flagged on the lock file.
    configWriter.command = ["python3", "-c",
      "import os, sys, tempfile\n" +
      "d = sys.argv[2]\n" +
      "os.makedirs(d, mode=0o700, exist_ok=True)\n" +
      "fd, tmp = tempfile.mkstemp(dir=d)\n" +
      "try:\n" +
      "    os.write(fd, sys.argv[1].encode())\n" +
      "    os.close(fd)\n" +
      "    os.replace(tmp, os.path.join(d, 'config.json'))\n" +
      "except BaseException:\n" +
      "    os.unlink(tmp)\n" +
      "    raise\n",
      JSON.stringify(cfg), stateDir]
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

          Item {
            id: headerRight
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            width: indexText.implicitWidth + experienceLabel.implicitWidth
              + Style.space(8)
            height: indexText.implicitHeight

            Text {
              id: indexText
              textFormat: Text.PlainText
              anchors.right: parent.right
              text: root.live && root.live.index !== null && root.live.index !== undefined
                ? String(root.live.index) : "--"
              color: root.bandColor(root.live ? root.live.index : null)
              font.family: root.fontFamily
              font.pixelSize: Style.fontPx(2.4)
              font.weight: Font.Bold
            }
            // On the number's baseline rather than under it — the label is
            // one word, and a whole row of header for it was dead space.
            Text {
              id: experienceLabel
              textFormat: Text.PlainText
              anchors.right: indexText.left
              anchors.rightMargin: Style.space(8)
              anchors.baseline: indexText.baseline
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
