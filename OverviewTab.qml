pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui

// The default tab: is it me or is it them, in one glance.
Column {
  id: tab

  required property var panel
  readonly property var live: panel.live

  spacing: Style.space(12)

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
        if (!l || !l.lag || l.lag.now === null) return "--"
        var best = l.lag.best !== null ? Math.round(l.lag.best) : "--"
        var worst = l.lag.worst !== null ? Math.round(l.lag.worst) : "--"
        return "best " + best + " · typical " + Math.round(l.lag.now)
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
        if (!l || !l.lag || l.lag.now === null) return "no data yet"
        return "lag " + Math.round(l.lag.now) + " ms typical"
      }
      textColor: tab.panel.fg
      dimColor: tab.panel.dim
    }
    ScorePillar {
      width: parent.cell
      label: "RELIABILITY"
      value: parent.scores.reliability !== undefined ? parent.scores.reliability : null
      note: {
        var l = tab.live
        if (!l) return ""
        if (l.state === "wan-down" || l.state === "local-down") return "outage in progress"
        return "last 24 h"
      }
      textColor: tab.panel.fg
      dimColor: tab.panel.dim
    }
    ScorePillar {
      width: parent.cell
      label: "SPEED"
      value: parent.scores.speed !== undefined ? parent.scores.speed : null
      note: {
        var ctx = tab.live ? tab.live.speed_ctx : null
        if (!ctx || ctx.last_down === null || ctx.last_down === undefined)
          return "no content check yet"
        var mbps = Math.round(ctx.last_down) + " Mbps"
        if (ctx.basis === "plan")
          return mbps + " vs " + Math.round(ctx.plan_down) + " plan"
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
            return "󰇚 " + tab.formatRate(r)
          }
          color: Color.accent
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.subtitle
        }
        Text {
          textFormat: Text.PlainText
          text: {
            var r = tab.live && tab.live.rates ? tab.live.rates.tx_bps : null
            return "󰕒 " + tab.formatRate(r)
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
        text: tab.live && tab.live.peak_running ? "󰓅 Testing…" : "󰓅 Run test"
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

  function formatRate(bps) {
    if (bps === null || bps === undefined || !isFinite(bps)) return "--"
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " GB/s"
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " MB/s"
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " KB/s"
    return Math.round(bps) + " B/s"
  }
}
