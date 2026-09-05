pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// The Nexthop panel: header verdict, seven tabs, one alive at a time.
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
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  // ---- palette -------------------------------------------------------------
  readonly property color fg: bar ? bar.foreground : Color.popups.text
  readonly property color dim: Color.muted
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color okTone: "#9ece6a"
  readonly property color warnTone: "#e0af68"

  // Right-now congestion, from score.pressure: the fast channel the index
  // cannot be. Empty unless it is worth saying.
  readonly property string pressureSuffix: {
    var p = live && live.pressure ? live.pressure : null
    if (!p || !p.state || p.state === "clear") return ""
    return " \u00b7 " + p.state.toUpperCase()
  }

  // Disclosure state for the panel's optional detail blocks. Lives here, not
  // on the tab, so moving between tabs does not fold them shut again. Resets
  // with the shell, which is the right lifetime for a view preference.
  property bool instrumentsExpanded: false
  property bool underLoadExpanded: false

  // A newer version is published. The daemon only ever reports this; the
  // panel only ever mentions it. Updating stays with `omarchy plugin update`,
  // which shows the diff and asks.
  readonly property bool updateAvailable:
    !!(live && live.update && live.update.available)

  function updateTip() {
    return "A newer version of Nexthop is published.\n\n"
      + "omarchy plugin update io.github.x3me.nexthop\n\n"
      + "That shows you what changed before applying it. "
      + "These checks can be turned off in the panel's Setup tab (the cog)."
  }

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
      updateCheck: setting("updateCheck", true),
      meteredCare: setting("meteredCare", true),
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

  // A phone sharing its data, and whether we are being careful with it.
  readonly property var metered: live && live.metered ? live.metered : null
  readonly property bool meteredCare: !!(metered && metered.care)

  // The peak test is sized to saturate the link for a fixed duration, not
  // to a fixed size, so it costs whatever the connection can carry: 285 MB
  // measured on a fibre line, tens of megabytes on a phone. It also fires
  // from a middle-click on the bar, which is easy to hit by accident. So on
  // a metered link the first press arms it and the second runs it — never
  // blocked, because measuring the cellular link is sometimes exactly what
  // you want.
  property bool peakArmed: false

  Timer {
    id: peakDisarm
    interval: 8000
    onTriggered: root.peakArmed = false
  }

  function runPeakTest() {
    if (meteredCare && !peakArmed) {
      peakArmed = true
      peakDisarm.restart()
      return
    }
    peakArmed = false
    peakDisarm.stop()
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
    setCenterHoverRevealSuppressed(false)
    root.controller.show()
  }

  function openFromHotkey() {
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
  readonly property var tabNames: ["Overview", "Latency", "Speed", "Wi-Fi",
                                   "Apps", "Events", "Setup"]
  // Setup carries a glyph rather than a word: it is a destination you visit
  // rarely, and giving it an equal seventh of the strip would cost the six
  // tabs that are read constantly. Its name stays in tabNames so the IPC
  // route (`showTab Setup`) and the arrow keys treat it like any other.
  readonly property int setupTab: tabNames.length - 1
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
        // Left/right walk the tab strip; 1-6 jump straight to a tab (Setup,
        // the seventh, has no digit — it is reached by arrow, click or IPC).
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
                if (s === "captive") return "󰦝"   // nf-md-shield_lock: a gate, not a fault
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
                  if (!l) return "Nexthop"
                  var name = l.link
                    ? (l.link.ssid || l.link.name || l.link.iface || "") : ""
                  if (name) return name
                  // The link is gone, so there is no network to name. The
                  // app's own name sat here reading like a network called
                  // Nexthop; say what is true instead.
                  return l.state === "local-down" || l.state === "wan-down"
                    ? "No network" : "Nexthop"
                }
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.heading
                font.weight: Font.Bold
              }
              Row {
                spacing: Style.space(6)

                Text {
                  textFormat: Text.PlainText
                  text: {
                    var l = root.live
                    if (!l) return "WAITING FOR DAEMON"
                    if (l.state === "captive") return "SIGN-IN REQUIRED"
                    if (l.state === "local-down") return "ROUTER UNREACHABLE"
                    if (l.state === "wan-down") return "NO INTERNET · ROUTER OK"
                    // The index is a weakest-link score whose slowest
                    // component can pin it, so it answers "how has this
                    // connection been" and not "is it bad right now".
                    // Queueing answers the second, and only earns a word
                    // here when it has one to say — clear adds nothing, so
                    // the common case costs no space at all.
                    var band = (l.band || "").toUpperCase()
                    return band + root.pressureSuffix
                  }
                  color: root.live && root.live.state !== "online"
                    ? Color.urgent : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.letterSpacing: 1
                }

                // A newer version exists. Deliberately the quietest thing
                // that can still be found: one dim glyph beside the verdict,
                // the command on hover, and nothing that acts on its own.
                // Same grammar as the bench glyph on the Overview.
                Text {
                  visible: root.updateAvailable
                  textFormat: Text.PlainText
                  text: "󰚰"   // nf-md-update
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  anchors.verticalCenter: parent.verticalCenter

                  HoverHandler { id: updateHover }
                  PanelToolTip {
                    visible: updateHover.hovered && root.updateAvailable
                    text: root.updateTip()
                  }
                }
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

              readonly property bool isSetup: index === root.setupTab
              readonly property real setupWidth: Style.space(34)

              width: isSetup ? setupWidth
                : (parent.width - Style.space(6) * (root.tabNames.length - 1)
                   - setupWidth) / (root.tabNames.length - 1)
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
                text: tabButton.isSetup ? "󰒓" : tabButton.modelData  // nf-md-cog
                color: tabButton.selected ? root.fg : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              HoverHandler { id: tabHover }
              TapHandler { onTapped: root.currentTab = tabButton.index }
              // A glyph does not name itself.
              PanelToolTip {
                visible: tabButton.isSetup && tabHover.hovered
                text: "Settings"
              }
            }
          }
        }

        PanelSeparator { width: parent.width }

        // ---- the selected tab -------------------------------------------
        Loader {
          width: parent.width
          active: root.opened
          sourceComponent: [overviewTab, latencyTab, speedTab, wifiTab,
                            appsTab, eventsTab, settingsTab][root.currentTab]
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
  Component { id: settingsTab; SettingsTab { panel: root } }
}
