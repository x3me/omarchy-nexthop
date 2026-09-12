pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui
import "pathspark.js" as Spark

// laptop — router — internet, with per-leg latency on the connecting lines.
// The answer to "is it me or is it them", drawn rather than written.
Item {
  id: root

  property var live: null
  // The configured anchor: the far node's fallback label when no WAN
  // address has been proven yet (see middle/far node text below).
  property string anchor: ""
  property color textColor: Color.popups.text
  property color dimColor: Color.muted

  // A phone sharing its data, as detected by the daemon from the gateway
  // range. `label` is what to call it — iPhone, Phone, Hotspot.
  readonly property var metered: live && live.metered ? live.metered : null
  readonly property bool tethered: !!(metered && metered.tethered)

  readonly property string middleTitle: tethered ? metered.label : "Router"

  readonly property string middleDetail: {
    if (!live || !live.link) return ""
    // On a hotspot the gateway is always the same fixed address for the
    // platform, so it carries no information; the phone's own name does.
    // iOS names the hotspot after the device, so the network name IS the
    // handset's name.
    if (tethered) return live.link.ssid || live.link.gateway || ""
    return live.link.gateway || ""
  }

  // Three minutes of each leg for the connectors. The ISP leg arrives already
  // subtracted per point — see score.wan_point_ms — so nothing here re-derives
  // it and the inversion guard keeps one implementation.
  readonly property var points: panel ? panel.recentPoints : []
  readonly property var localSeries: Spark.slots(points, "local", Spark.SLOTS)
  readonly property var wanSeries: Spark.slots(points, "wan", Spark.SLOTS)
  // One zero-based scale for both, so a 2 ms wobble cannot outdraw the WAN.
  readonly property real sparkMax: Spark.sharedMax([localSeries, wanSeries],
                                                   Spark.SCALE_FLOOR_MS)
  // The panel already knows whether readings are arriving: the daemon writes
  // live.json at 2 Hz and the bar widget calls it stale after five seconds.
  // The ring is that fact drawn, not a second rule with a second clock.
  readonly property bool sparkLive: !!(panel && !panel.stale)

  readonly property var localMs: live && live.local ? live.local.p50 : null
  readonly property var wanMs: live && live.wan ? live.wan.p50 : null
  readonly property bool localDown: live && live.state === "local-down"
  readonly property bool wanDown: live && live.state === "wan-down"

  // The address this connection appears from, published by the daemon.
  // Shown masked: Overview screenshots end up on forums, and a screenshot
  // must not carry the poster's IP. Tapping the node reveals it; the
  // reveal is never persisted anywhere.
  readonly property var wanIp: live && live.wan_ip ? live.wan_ip : null
  readonly property var seated: {
    if (!live || !live.instruments) return []
    return live.instruments.filter(function(i) { return i.active })
  }

  // What the info glyph on the Internet node explains on hover: which
  // instruments hold the scored seats right now. A caption line said
  // "2 probes live" here once — permanent height for a once-read fact.
  function benchTip() {
    var lines = []
    for (var i = 0; i < seated.length; i++) {
      var ins = seated[i]
      lines.push(ins.kind + " \u00b7 " + ins.target
        + (ins.p50 !== null && ins.p50 !== undefined
           ? "  \u2014  " + ins.p50.toFixed(1) + " ms" : ""))
    }
    var standby = live && live.instruments
      ? live.instruments.length - seated.length : 0
    if (standby > 0)
      lines.push(standby + " on standby \u2014 full bench on the Latency tab")
    lines.push(detailOpen ? "tap to close" : "tap for detail")
    return lines.join("\n")
  }

  // Opening the detail is the deliberate act that reveals the address, so
  // the two are one gesture. Held by the Panel so switching tabs does not
  // close it; it resets with the shell, which is the right lifetime for a
  // view preference. Never persisted — an Overview screenshot taken
  // without opening this carries a masked address.
  // Held by the Panel, like the other disclosure toggles, so switching
  // tabs does not close it. Null-guarded: without a panel the detail
  // simply never opens rather than throwing on every tap.
  property var panel: null
  readonly property bool detailOpen: !!(panel && panel.wanDetailOpen)
  readonly property bool revealIp: detailOpen

  function ipLine() {
    if (!wanIp || !wanIp.ip) return ""
    var parts = [String(wanIp.ip)]
    // Country and edge ride along in the response the reachability check
    // already fetches. The edge is Cloudflare's datacentre, not the
    // user's location, so it is labelled as the route and not as a place.
    if (wanIp.country) parts.push(wanIp.country)
    if (wanIp.edge) parts.push("via Cloudflare " + wanIp.edge)
    return parts.join(" \u00b7 ")
  }

  function legLine() {
    var l = localMs, w = wanMs
    if ((l === null || l === undefined) && (w === null || w === undefined))
      return ""
    var f = function(v) {
      return v === null || v === undefined ? "\u2014" : v.toFixed(2) + " ms"
    }
    return "local " + f(l) + "  \u00b7  wan " + f(w)
  }

  function probeLine() {
    if (seated.length === 0) return ""
    var parts = []
    for (var i = 0; i < seated.length; i++) {
      var ins = seated[i]
      parts.push(ins.kind + " " + ins.target
        + (ins.p50 !== null && ins.p50 !== undefined
           ? " " + ins.p50.toFixed(1) : ""))
    }
    var standby = live && live.instruments
      ? live.instruments.length - seated.length : 0
    var out = parts.join("  \u00b7  ")
    if (standby > 0) out += "   (+" + standby + " standby)"
    return out
  }

  function loadLine() {
    var lag = live && live.lag ? live.lag : null
    if (!lag || lag.idle === null || lag.idle === undefined
        || lag.loaded === null || lag.loaded === undefined) return ""
    // The daemon withholds `inflation` when the two populations are too
    // close to separate or the ratio came out backwards. Absent inflation
    // means the pair is not trustworthy either, so the whole row goes —
    // printing "idle 13.0 -> loaded 10.9" states that the link answers
    // FASTER while busy, which queueing cannot do. A result that is wrong
    // in direction is not a result, and it is not made safe by dropping
    // only the ratio computed from it.
    if (lag.inflation === null || lag.inflation === undefined) return ""
    return "idle " + lag.idle.toFixed(1)
      + " \u2192 loaded " + lag.loaded.toFixed(1) + " ms"
      + "  (" + lag.inflation.toFixed(2) + "\u00d7)"
  }

  function appsLine() {
    var s = live && live.sockets ? live.sockets : null
    if (!s || s.queue_p50 === null || s.queue_p50 === undefined) return ""
    var out = "queue " + s.queue_p50.toFixed(1) + " ms typical"
    if (s.queue_p95 !== null && s.queue_p95 !== undefined)
      out += ", " + s.queue_p95.toFixed(1) + " worst"
    if (s.sockets) out += " over " + s.sockets + " connections"
    return out
  }

  function maskedIp(w) {
    if (!w || !w.ip) return ""
    var full = String(w.ip)
    if (revealIp) return full
    if (w.family === "v6")
      return full.split(":").slice(0, 2).join(":") + ":\u2026"
    return full.split(".").slice(0, 2).join(".") + ".\u2026"
  }

  function legColor(ms, down) {
    if (down) return Color.urgent
    if (ms === null || ms === undefined) return dimColor
    if (ms <= 15) return "#9ece6a"
    if (ms <= 50) return "#e0af68"
    return Color.urgent
  }

  // One animator for both legs, stopped the moment the liveness claim stops
  // being true: a panel left open must never keep pulsing over stale data.
  property real ringPhase: 0
  NumberAnimation on ringPhase {
    running: root.sparkLive && root.motionOk
    loops: Animation.Infinite
    from: 0; to: 1; duration: 1400
  }
  // Omarchy's own animation preference; a user who turns the bar's motion off
  // gets a static second circle rather than nothing, so the claim still reads.
  readonly property bool motionOk: {
    var b = panel ? panel.bar : null
    if (!b || !("foregroundAnimationEnabled" in b)) return true
    return b.foregroundAnimationEnabled === true
  }

  implicitHeight: stack.implicitHeight

  Column {
    id: stack
    width: parent.width
    spacing: Style.space(10)

  Row {
    id: row
    width: parent.width

    component Node: Column {
      property string icon: ""
      property string title: ""
      property string detail: ""
      width: Style.space(84)
      spacing: Style.space(4)

      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: parent.icon
        color: root.textColor
        font.family: Style.font.family
        font.pixelSize: Style.font.iconLarge
      }
      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: parent.title
        color: root.textColor
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: parent.detail
        color: root.dimColor
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        elide: Text.ElideMiddle
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
      }
    }

    component Leg: Column {
      property var ms: null
      property bool down: false
      property string label: ""
      property var series: []
      width: (row.width - Style.space(84) * 3) / 2
      spacing: Style.space(4)
      // Sits a little above the node centres so the line meets the icons.
      topPadding: Style.space(8)

      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: parent.down ? "down"
          : (parent.ms === null || parent.ms === undefined
             ? "--" : parent.ms.toFixed(1) + " ms")
        color: root.legColor(parent.ms, parent.down)
        font.family: Style.font.family
        font.pixelSize: Style.font.bodySmall
      }
      Canvas {
        id: spark
        width: parent.width - Style.space(12)
        anchors.horizontalCenter: parent.horizontalCenter
        // 16 left the plot 9 px tall with nothing spare, so the ring was
        // cut on every side it could reach. The margin the ring needs is
        // fixed; buying it out of the plot would have left a 3 px band.
        // This keeps the same 9 px of plot and costs six pixels once —
        // the connectors are side by side, so it is six for the panel,
        // not six per leg.
        height: Style.space(22)
        antialiasing: true
        // Repainting on every phase tick is what the ring costs; the series
        // only changes every five seconds.
        property real phase: root.ringPhase
        property var series: parent.series
        property real sparkScale: root.sparkMax
        onPhaseChanged: requestPaint()
        onSeriesChanged: requestPaint()
        onSparkScaleChanged: requestPaint()
        onPaint: {
          var ctx = getContext("2d")
          Spark.draw(ctx, width, height, series, {
            max: sparkScale,
            phase: phase,
            live: root.sparkLive,
            motion: root.motionOk,
            downColor: Color.urgent,
            colorFor: root.legColor
          })
        }
      }
      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: parent.label
        color: root.dimColor
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        font.letterSpacing: 1
      }
    }

    Node {
      icon: "󰌢"   // nf-md-laptop
      title: "This machine"
      detail: root.live && root.live.link ? (root.live.link.iface || "") : ""
    }
    Leg {
      ms: root.localMs
      down: root.localDown
      label: "LOCAL"
      series: root.localSeries
    }
    // When the connection comes from a phone, this node is the phone. Drawing
    // a router here mislabelled both legs at once: the local leg is the hop
    // to the handset, and everything past it is cellular, not an ISP line.
    Node {
      icon: root.tethered ? "󰄜" : "󰑩"   // nf-md-cellphone / nf-md-router_wireless
      title: root.middleTitle
      detail: root.middleDetail
    }
    Leg {
      ms: root.wanMs
      down: root.wanDown
      label: "WAN"
      series: root.wanSeries
    }
    Node {
      icon: "󰖟"   // nf-md-web
      title: "Internet"
      // Your address out there, not the probe target: with a bench of
      // instruments there is no single anchor to name, and naming one
      // read as "this monitors Cloudflare". Masked — screenshots end up
      // on forums; tap to reveal, never persisted.
      detail: (root.wanIp ? root.maskedIp(root.wanIp) : root.anchor)
        + (root.seated.length > 0 ? "  󰋽" : "")

      TapHandler {
        onTapped: if (root.panel) root.panel.wanDetailOpen = !root.panel.wanDetailOpen
      }
      HoverHandler { id: inetHover }
      PanelToolTip {
        visible: inetHover.hovered && root.seated.length > 0
        text: root.benchTip()
      }
    }
  }

  // What the far node knows, shown only when asked for. Everything here
  // is already measured — no extra request, no new destination — and it
  // is deliberately what a single-number internet score cannot show: two
  // legs, which instruments produced them, and what the machine's own
  // connections are experiencing.
  Column {
    id: detail
    width: parent.width
    spacing: Style.space(4)
    visible: root.detailOpen
    // A visible:false child still takes its share of a Column's spacing.
    height: visible ? implicitHeight : 0

    component DetailRow: Row {
      property string label: ""
      property string value: ""
      visible: value !== ""
      height: visible ? implicitHeight : 0
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: parent.label
        color: root.dimColor
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        font.letterSpacing: 1
        width: Style.space(72)
      }
      Text {
        textFormat: Text.PlainText
        text: parent.value
        color: root.textColor
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        elide: Text.ElideRight
        width: detail.width - Style.space(80)
      }
    }

    DetailRow { label: "ADDRESS"; value: root.ipLine() }
    DetailRow { label: "LEGS"; value: root.legLine() }
    DetailRow { label: "PROBES"; value: root.probeLine() }
    DetailRow { label: "UNDER LOAD"; value: root.loadLine() }
    DetailRow { label: "APPS SEE"; value: root.appsLine() }
  }

  }
}
