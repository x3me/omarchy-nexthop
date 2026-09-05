import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Nexthop's bar entry: the one always-visible surface. Colour carries the
// state — the number is detail, the colour is the verdict. Clicking opens
// the panel; middle-click asks the daemon for a peak speed test.
BarWidget {
  id: root
  moduleName: "io.github.x3me.nexthop"

  // ---- live state ----------------------------------------------------------
  //
  // The shell never opens a state file itself. `nexthop stream` performs a
  // bounded, non-blocking, no-follow, regular-file-only read and hands us
  // whole lines, so an oversized file, a FIFO or a symlink swapped in at
  // the predictable path is refused in a small short-lived process instead
  // of allocating or stalling inside the long-lived shell.
  // A URL, not a path: percent-encoded, so a space in the way becomes %20
  // and `cd` fails. Decode before it is used as a filesystem path.
  readonly property string pluginDir:
    decodeURIComponent(Qt.resolvedUrl(".").toString())
      .replace(/^file:\/\//, "").replace(/\/$/, "")

  // One reader serves the whole widget: the panel below is created by this
  // component and binds to these properties rather than opening anything
  // itself, so the shell runs a single helper, not one per surface.
  property var live: null
  property var recent: null
  property var appsData: null

  Process {
    id: stateStream
    running: true
    command: ["sh", "-c",
              'cd "$1" && exec python3 -m nexthopd.cli stream live apps recent',
              "sh", root.pluginDir]
    stdout: SplitParser {
      splitMarker: "\n"
      onRead: function (line) { root.applyStream(line) }
    }
    onExited: streamRestart.start()
  }

  // The reader dies with the daemon's package on an update; bring it back.
  Timer {
    id: streamRestart
    interval: 2000
    onTriggered: stateStream.running = true
  }

  // Each file has a known small size; a line past its bound is not ours.
  // live ~3 KB, apps ~8 KB, recent ~30 KB.
  function applyStream(line) {
    var sp = line ? line.indexOf(" ") : -1
    if (sp <= 0) return
    var key = line.slice(0, sp)
    if (line.length - sp - 1 > (key === "live" ? 262144 : 1048576)) return
    var v
    try { v = JSON.parse(line.slice(sp + 1)) } catch (e) { return }
    if (v === null || v === undefined) return
    if (key === "live") root.live = v
    else if (key === "apps") root.appsData = v
    else if (key === "recent") root.recent = v
  }

  // ---- derived -------------------------------------------------------------
  readonly property string displayMode: setting("displayMode", "Index")
  readonly property string netState: live ? (live.state || "online") : "no-daemon"
  readonly property var index: live && live.index !== null && live.index !== undefined
    ? live.index : null
  readonly property var lagNow: live && live.lag ? live.lag.now : null

  readonly property color okColor: bar ? bar.foreground : Color.foreground
  // State colours resolve through the theme palette: green/yellow/red exist
  // in every Omarchy theme's colors.toml, surfaced via Color singleton.
  readonly property color stateColor: {
    // A sign-in page is a gate, not a fault: warn, not urgent.
    if (netState === "captive") return "#e0af68"
    if (netState === "local-down" || netState === "wan-down") return Color.urgent
    if (netState === "degraded") return "#e0af68"
    if (index === null) return okColor
    if (index >= 80) return okColor
    if (index >= 50) return "#e0af68"
    return Color.urgent
  }

  readonly property string glyph: {
    if (netState === "captive") return "󰦝"     // nf-md-shield_lock: a gate
    if (netState === "local-down") return "󱚵"   // nf-md-wifi_strength_alert
    if (netState === "wan-down") return "󰲛"     // nf-md-web_off / broken link
    return "󰓅"                                   // nf-md-speedometer
  }

  readonly property string barText: {
    if (netState === "no-daemon") return glyph
    if (netState === "captive") return glyph
    if (netState === "local-down" || netState === "wan-down") {
      var since = live && live.down_since ? live.down_since : 0
      if (!since) return glyph
      var s = Math.max(0, Math.round(Date.now() / 1000 - since))
      var m = Math.floor(s / 60)
      return glyph + " " + (m > 0 ? m + "m" + (s % 60) + "s" : s + "s")
    }
    if (displayMode === "Icon only") return glyph
    if (displayMode === "Lag")
      return glyph + " " + (lagNow !== null ? Math.round(lagNow) + "ms" : "--")
    return glyph + " " + (index !== null ? index : "--")
  }

  // ---- panel wiring (same shape contract as weather / vitals) --------------
  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  function togglePanel() {
    if (panelLoader.item && panelLoader.item.toggle) panelLoader.item.toggle()
  }

  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  function open() {
    if (panelLoader.item && panelLoader.item.openFromHotkey) panelLoader.item.openFromHotkey()
  }

  function close() {
    if (panelLoader.item && panelLoader.item.close) panelLoader.item.close()
  }

  readonly property bool popoutSwitchClosing: panelLoader.item
    ? panelLoader.item.popoutSwitchClosing === true : false

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  // The path travels as a positional argument, never spliced into the
  // script — the same form every other Process here uses.
  Process {
    id: peakRequest
    command: ["sh", "-c", 'cd "$1" && exec python3 -m nexthopd.cli peak',
              "sh", root.pluginDir]
  }

  // Why the width is measured here rather than left to the control:
  // BarIconButton is an *icon* button — it pins `fixedWidth` to a
  // single-glyph slot (27 px by default), so its implicitWidth is that slot
  // no matter what text it holds. Our text is variable ("󰓅 92", "󰓅 1024ms",
  // "󱚵 1m3s"), so the bar reserved one icon's worth of space and the text
  // painted straight over the neighbouring widget. Longest during an
  // outage, which is when it was noticed.
  //
  // TextMetrics measures the string against the same font without
  // rendering it, so the width can drive the slot with no binding loop
  // back through the glyph that is being laid out.
  TextMetrics {
    id: textWidth
    font.family: button.fontFamily
    font.pixelSize: button.fontSize
    text: root.barText
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.barText
    // Never narrower than a normal icon slot, so an icon-only display mode
    // still lines up with its neighbours.
    slotSize: Math.max(Style.bar.iconSlot,
                       Math.ceil(textWidth.advanceWidth) + Style.space(10))
    foreground: root.stateColor
    useActiveColor: false
    tooltipText: {
      if (!root.live) return "Nexthop: waiting for the daemon"
      var l = root.live
      var name = l.link && (l.link.ssid || l.link.name) || ""
      var parts = [name, (l.index !== null ? l.index + " " + l.band : "")]
      if (l.local && l.local.p50 !== null && l.wan && l.wan.p50 !== null)
        parts.push("local " + l.local.p50 + " ms · wan " + l.wan.p50 + " ms")
      return parts.filter(function(p) { return p && p.length }).join("\n")
    }

    onPressed: function(b) {
      if (b === Qt.MiddleButton) {
        // The easiest way to spend a phone's data by accident: a stray
        // middle-click saturating the link. On a metered connection this
        // opens the panel instead, where the button asks twice.
        if (root.live && root.live.metered && root.live.metered.care)
          root.open()
        else
          peakRequest.running = true
      } else {
        root.togglePanel()
      }
    }
  }
}
