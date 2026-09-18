pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui
import "format.js" as Fmt

// The default tab: is it me or is it them, in one glance.
Column {
  id: tab

  required property var panel
  readonly property var live: panel.live

  spacing: Style.space(12)

  readonly property bool outage: live
    && (live.state === "wan-down" || live.state === "local-down"
        || live.state === "tunnel-down")

  // Whether any point of the recent history went through a VPN — each point
  // carries its own flag, so the legend names the tunnel only when the chart
  // actually draws some.
  readonly property bool tunnelInView: {
    var pts = panel.recentPoints || []
    for (var i = 0; i < pts.length; i++) if (pts[i] && pts[i].vpn) return true
    return false
  }

  // The Speed pillar's hover text: what its number is made of and, when the
  // pillar is dim, why the index is ignoring it. The caption under the pillar
  // has room for about 21 characters ("114 Mbps · test: 365"); this is the
  // sentence it abbreviates. Pure — takes live's speed_ctx and metered, reads
  // nothing else — so test/overview_tip.js can run it.
  function speedTip(ctx, metered) {
    function hhmm(ts) {
      var d = new Date(ts * 1000)
      return (d.getHours() < 10 ? "0" : "") + d.getHours() + ":"
        + (d.getMinutes() < 10 ? "0" : "") + d.getMinutes()
    }
    if (!ctx) return ""
    if (metered && metered.care)
      return "Hourly checks are paused on " + metered.label + ",\n"
        + "which is sharing its mobile data. Setup turns this off."
    if (ctx.last_down === null || ctx.last_down === undefined)
      return ctx.vpn ? "No speed check through this VPN yet."
        : "No speed check on this network yet."
    var lines = []
    if (ctx.basis === "plan") {
      lines.push("Scored against your plan: " + Math.round(ctx.plan_down)
        + " Mbps down.")
      lines.push("Latest check: " + Math.round(ctx.last_down) + " Mbps.")
      return lines.join("\n")
    }
    var checks = ctx.checks_down || []
    if (checks.length > 1)
      lines.push("Median of the last " + checks.length + " checks here, newest first:\n"
        + checks.map(function (v) { return Math.round(v) }).join(" · ") + " Mbps")
    else
      lines.push("One check on this network so far: "
        + Math.round(ctx.last_down) + " Mbps")
    if (ctx.vpn) lines.push("Through the VPN, so this measures the tunnel.")
    if (ctx.scored === false) {
      if (ctx.peak_down && ctx.peak_ts)
        lines.push("Not counted in the score: a speed test at " + hhmm(ctx.peak_ts)
          + "\nread " + Math.round(ctx.peak_down) + " Mbps, far above this."
          + (ctx.peak_until ? "\nCounted again from " + hhmm(ctx.peak_until) + "." : ""))
      else if (ctx.min_samples && (ctx.samples || 0) < ctx.min_samples)
        lines.push("Not counted in the score until there are "
          + ctx.min_samples + " checks here.")
    }
    return lines.join("\n")
  }

  // Same shape the bar shows, so the two agree at a glance.
  function elapsed(since) {
    if (!since) return ""
    var s = Math.max(0, Math.round(Date.now() / 1000 - since))
    var m = Math.floor(s / 60)
    return m > 0 ? m + "m" + (s % 60) + "s" : s + "s"
  }

  // Only on a captive network, so it costs no height the rest of the time.
  // It goes first because it is the one thing worth reading here: without
  // it, every number below is the portal answering rather than the
  // connection, and the panel would be blaming the router for a sign-in
  // page.
  Text {
    textFormat: Text.PlainText
    visible: tab.live && tab.live.state === "captive"
    height: visible ? implicitHeight : 0
    width: parent.width
    wrapMode: Text.WordWrap
    text: "This network wants you to sign in. Something here is answering "
      + "for the internet, so treat the numbers below as the sign-in page, "
      + "not your connection."
    color: tab.panel.warnTone
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }

  // Only while names fail to resolve, so it costs no height otherwise. Leads
  // with how long, then says what still works: every leg below reads healthy
  // and is right to, so without this line the panel contradicts the user,
  // whose websites will not open.
  Text {
    textFormat: Text.PlainText
    visible: tab.live && tab.live.state === "dns-failing"
    height: visible ? implicitHeight : 0
    width: parent.width
    wrapMode: Text.WordWrap
    text: {
      var lk = tab.live ? tab.live.lookups : null
      var d = lk ? tab.elapsed(lk.since) : ""
      return (d ? "Failing for " + d + ". " : "")
        + "Names are not resolving, so most websites won't open. The router "
        + "and the internet still answer by address: this is DNS, not your line."
    }
    color: tab.panel.warnTone
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }

  // Only while the tunnel is down, so it costs no height otherwise. Says
  // what failed and, just as plainly, whose fault it is not: a VPN outage is
  // charged to this connection's Reliability but never to the ISP.
  Text {
    textFormat: Text.PlainText
    visible: tab.live && tab.live.state === "tunnel-down"
    height: visible ? implicitHeight : 0
    width: parent.width
    wrapMode: Text.WordWrap
    text: {
      var d = tab.live ? tab.elapsed(tab.live.down_since) : ""
      return (d ? "Down " + d + ". " : "")
        + "The router answers; the VPN tunnel does not. "
        + "Charged to this connection, not to your ISP."
    }
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }

  Text {
    textFormat: Text.PlainText
    text: "PATH"
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    font.letterSpacing: 1
  }

  PathChain {
    width: parent.width
    live: tab.live
    panel: tab.panel
    anchor: tab.panel.setting("internetAnchor", "1.1.1.1")
    textColor: tab.panel.fg
    dimColor: tab.panel.dim
  }

  // Lag summary line, Orb vocabulary: best / typical / worst.
  Item {
    width: parent.width
    height: lagLabel.implicitHeight

    Text {
      id: lagLabel
      textFormat: Text.PlainText
      text: "LAG"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: {
        var l = tab.live
        if (!l || !l.lag) return "--"
        // The band is null when the whole window was lost. `lag.now` is
        // still 1500 there because Responsiveness needs an anchor to land
        // on, but 1500 is not a round trip and printing it three times
        // said the link was replying slowly when it was not replying.
        if (l.lag.typical === null || l.lag.typical === undefined)
          return tab.outage ? "no reply" : "--"
        var best = l.lag.best !== null ? Math.round(l.lag.best) : "--"
        var worst = l.lag.worst !== null ? Math.round(l.lag.worst) : "--"
        return "best " + best + " · typical " + Math.round(l.lag.typical)
          + " ms · worst " + worst
      }
      color: tab.panel.fg
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }

  PanelSeparator { width: parent.width }

  // The three pillars.
  Row {
    width: parent.width
    spacing: Style.space(14)

    readonly property real cell: (width - Style.space(14) * 2) / 3
    readonly property var scores: tab.live && tab.live.scores ? tab.live.scores : {}

    ScorePillar {
      width: parent.cell
      label: "RESPONSIVENESS"
      value: parent.scores.responsiveness !== undefined ? parent.scores.responsiveness : null
      note: {
        var l = tab.live
        if (!l || !l.lag) return "no data yet"
        if (l.lag.typical === null || l.lag.typical === undefined)
          return tab.outage ? "nothing is answering" : "no data yet"
        return "lag " + Math.round(l.lag.typical) + " ms typical"
      }
      textColor: tab.panel.fg
      dimColor: tab.panel.dim
    }
    ScorePillar {
      width: parent.cell
      label: "RELIABILITY"
      value: parent.scores.reliability !== undefined ? parent.scores.reliability : null
      // A 24-hour score barely moves in the first minute of an outage, so
      // the number stays 100 and is honest. Green is not: it reads as
      // reassurance next to a dead link. The caption carries the live fact
      // instead of restating the window, and it is short enough to fit —
      // the previous wording truncated mid-word in this column.
      toneOverride: tab.outage ? tab.panel.warnTone : null
      note: {
        var l = tab.live
        if (!l) return ""
        if (l.state === "captive") return "not signed in yet"
        if (tab.outage) {
          var d = tab.elapsed(l.down_since)
          return d ? "down " + d : "outage now"
        }
        // Charged against the time actually watched (a laptop that slept
        // most of the day watched a few hours of it), so say how much when
        // it is short of the day. Under the floor the number is withheld.
        var c = tab.live.reliability_ctx
        if (c && c.watched_s < c.min_s)
          return "watched " + Math.floor(c.watched_s / 60) + " of "
            + Math.round(c.min_s / 60) + " min"
        if (c && c.watched_s < c.window_s - 1800)
          return "watched " + Math.round(c.watched_s / 3600) + " of "
            + Math.round(c.window_s / 3600) + " h"
        return "last 24 h"
      }
      textColor: tab.panel.fg
      dimColor: tab.panel.dim
    }
    ScorePillar {
      width: parent.cell
      label: "SPEED"
      tip: tab.speedTip(tab.live ? tab.live.speed_ctx : null,
                        tab.live ? tab.live.metered : null)
      value: parent.scores.speed !== undefined ? parent.scores.speed : null
      // A figure the index is ignoring must not shout in red as though it
      // were the verdict — it is being reported, not counted.
      toneOverride: {
        var c = tab.live ? tab.live.speed_ctx : null
        return c && c.scored === false ? tab.panel.dim : null
      }
      note: {
        // Say why it is blank, or the pause reads as a fault. This is the
        // whole point of detecting the hotspot: the checks are ~14 MB each
        // and hourly, which is data the user did not offer.
        var m = tab.live ? tab.live.metered : null
        var ctx = tab.live ? tab.live.speed_ctx : null
        var held = m && m.care
        if (!ctx || ctx.last_down === null || ctx.last_down === undefined)
          return held ? "checks paused on " + m.label
            : (ctx && ctx.vpn ? "no check via VPN yet" : "no content check yet")
        var mbps = Math.round(ctx.last_down) + " Mbps"
        // No content check runs while the line is down, so this figure is
        // from before it. Saying "measured" would imply it is current.
        if (tab.outage) return mbps + " before the drop"
        if (held) return mbps + " · checks paused"
        // Checks through a tunnel measure the tunnel. Run and said so, and
        // judged only against other checks through the same one.
        if (ctx.vpn) return mbps + " · via VPN"
        if (ctx.basis === "plan")
          return mbps + " vs " + Math.round(ctx.plan_down) + " plan"
        // Not counted, and why. One check is the arrival check on a link
        // that may still have been settling; a peak test that read far
        // higher has already disproved this figure.
        // Kept inside the column: "63 Mbps · usually 384" is the widest
        // caption that fits here, so anything longer elides mid-word. The
        // dim number already says it is not counted; this says why.
        if (ctx.scored === false) {
          if (ctx.peak_down)
            return mbps + " · test: " + Math.round(ctx.peak_down)
          return mbps + " · unconfirmed"
        }
        if (ctx.baseline_down && ctx.last_down < ctx.baseline_down * 0.6)
          return mbps + " · usually " + Math.round(ctx.baseline_down)
        return mbps + " measured"
      }
      textColor: tab.panel.fg
      dimColor: tab.panel.dim
    }
  }

  PanelSeparator { width: parent.width }

  // 30-minute latency chart from recent.json.
  Item {
    width: parent.width
    height: chartLabel.implicitHeight

    Text {
      id: chartLabel
      textFormat: Text.PlainText
      text: "LATENCY · LAST 30 MIN"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: {
        var l = tab.live
        if (!l || !l.total || l.total.p50 === null) return ""
        return "p50 " + Math.round(l.total.p50) + " ms · p95 "
          + Math.round(l.total.p95) + " ms · jitter "
          + (l.total.jitter !== null ? l.total.jitter.toFixed(1) : "--") + " ms"
      }
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  LegChart {
    width: parent.width
    height: Style.space(96)
    points: tab.panel.recentPoints
    wanColor: Color.accent
    localColor: tab.panel.dim
    showScale: true
    fontFamily: tab.panel.fontFamily
  }

  Row {
    spacing: Style.space(16)

    component LegendEntry: Row {
      property color tint: "white"
      property string label: ""
      property bool tick: false
      spacing: Style.space(6)
      Rectangle {
        width: parent.tick ? 2 : Style.space(10)
        height: parent.tick ? Style.space(8) : 2
        color: parent.tint
        anchors.verticalCenter: parent.verticalCenter
      }
      Text {
        textFormat: Text.PlainText
        text: parent.label
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.caption
        anchors.verticalCenter: parent.verticalCenter
      }
    }

    LegendEntry { tint: Color.accent; label: "wan leg" }
    LegendEntry { tint: "#bb9af7"; label: "tunnel"; visible: tab.tunnelInView }
    LegendEntry { tint: tab.panel.dim; label: "local leg" }
    LegendEntry { tint: Color.urgent; label: "packet loss"; tick: true }
  }

  PanelSeparator { width: parent.width }

  // Speed strip + the run button.
  Item {
    width: parent.width
    height: speedCol.implicitHeight

    Column {
      id: speedCol
      spacing: Style.space(4)

      Text {
        textFormat: Text.PlainText
        text: "THROUGHPUT NOW"
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.caption
        font.letterSpacing: 1
      }
      Row {
        spacing: Style.space(14)

        Text {
          textFormat: Text.PlainText
          text: {
            var r = tab.live && tab.live.rates ? tab.live.rates.rx_bps : null
            return "󰇚 " + Fmt.rate(r)
          }
          color: Color.accent
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.subtitle
        }
        Text {
          textFormat: Text.PlainText
          text: {
            var r = tab.live && tab.live.rates ? tab.live.rates.tx_bps : null
            return "󰕒 " + Fmt.rate(r)
          }
          color: tab.panel.warnTone
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.subtitle
        }
      }
    }

    Rectangle {
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      width: runLabel.implicitWidth + Style.space(24)
      height: Style.space(28)
      color: runHover.hovered
        ? Style.hoverFillFor(tab.panel.fg, Color.accent)
        : Style.normalFillFor(tab.panel.fg, Color.accent)
      border.width: Style.normalBorderWidth
      border.color: Style.normalBorderFor(tab.panel.fg, Color.accent)

      Text {
        id: runLabel
        textFormat: Text.PlainText
        anchors.centerIn: parent
        text: tab.live && tab.live.peak_running ? "󰓅 Testing…"
          : tab.panel.peakArmed ? "󰓅 Uses data · press again"
          : "󰓅 Run test"
        color: tab.panel.fg
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      HoverHandler { id: runHover }
      TapHandler {
        enabled: !(tab.live && tab.live.peak_running)
        onTapped: tab.panel.runPeakTest()
      }
    }
  }

}
