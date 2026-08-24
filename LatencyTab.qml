pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui

// Latency in detail: window picker, the two-leg chart at full height, and
// the per-leg statistics table.
Column {
  id: tab

  required property var panel

  spacing: Style.space(12)

  Component.onCompleted: panel.requestTests()

  // The last peak test that captured latency both ways.
  readonly property var loadTest: {
    var tests = panel.testsData && panel.testsData.tests ? panel.testsData.tests : []
    for (var i = 0; i < tests.length; i++) {
      var t = tests[i]
      if (t.kind === "peak" && t.ok && t.ping_idle !== null && t.ping_loaded !== null)
        return t
    }
    return null
  }
  readonly property real addedMs: loadTest
    ? Math.max(0, loadTest.ping_loaded - loadTest.ping_idle) : 0
  // Waveform's grading of latency added under load.
  readonly property string bloatGrade: {
    if (!loadTest) return ""
    if (addedMs < 5) return "A+"
    if (addedMs < 30) return "A"
    if (addedMs < 60) return "B"
    if (addedMs < 200) return "C"
    if (addedMs < 400) return "D"
    return "F"
  }
  readonly property color bloatTone: {
    if (bloatGrade === "A+" || bloatGrade === "A") return panel.okTone
    if (bloatGrade === "B" || bloatGrade === "C") return panel.warnTone
    return Color.urgent
  }

  readonly property var windows: ["5m", "30m", "6h", "24h", "7d"]
  property string window: "30m"

  // 5m/30m paint straight from recent.json; longer windows query history.
  readonly property bool fromRecent: window === "5m" || window === "30m"

  onWindowChanged: if (!fromRecent) panel.requestHistory(window)

  readonly property var chartPoints: {
    if (fromRecent) {
      var pts = panel.recentPoints
      if (window === "5m") {
        var cut = Date.now() / 1000 - 300
        pts = pts.filter(function(p) { return p.t >= cut })
      }
      return pts
    }
    var h = panel.history
    if (!h || !h.rows || panel.historyWindow !== window) return []
    return h.rows.map(function(r) {
      return {
        t: r.ts,
        local: r.local_p50,
        total: (r.local_p50 !== null && r.wan_p50 !== null)
          ? r.local_p50 + r.wan_p50 : null,
        loss: ((r.local_loss || 0) + (r.wan_loss || 0)) > 0
          ? (r.local_loss || 0) + (r.wan_loss || 0) : null,
      }
    })
  }

  Row {
    spacing: Style.space(5)

    Repeater {
      model: tab.windows

      Rectangle {
        id: pill
        required property string modelData
        readonly property bool selected: tab.window === modelData

        width: pillLabel.implicitWidth + Style.space(22)
        height: Style.space(22)
        color: selected
          ? Style.selectedFillFor(tab.panel.fg, Color.accent)
          : (pillHover.hovered
             ? Style.hoverFillFor(tab.panel.fg, Color.accent)
             : Style.normalFillFor(tab.panel.fg, Color.accent))
        border.width: selected ? 0 : Style.normalBorderWidth
        border.color: Style.normalBorderFor(tab.panel.fg, Color.accent)

        Text {
          id: pillLabel
          textFormat: Text.PlainText
          anchors.centerIn: parent
          text: pill.modelData.toUpperCase()
          color: pill.selected ? tab.panel.fg : tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
        }
        HoverHandler { id: pillHover }
        TapHandler { onTapped: tab.window = pill.modelData }
      }
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: !tab.fromRecent && tab.panel.historyLoading
    text: "loading…"
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }

  LegChart {
    width: parent.width
    height: Style.space(140)
    points: tab.chartPoints
    wanColor: Color.accent
    localColor: tab.panel.dim
    minScaleMs: 10
    showScale: true
    fontFamily: tab.panel.fontFamily
  }

  Row {
    spacing: Style.space(16)

    component LegendEntry: Row {
      property color tint: "white"
      property string label: ""
      spacing: Style.space(6)
      Rectangle {
        width: Style.space(10); height: 2
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

    LegendEntry { tint: Color.accent; label: "wan leg (router → internet)" }
    LegendEntry { tint: tab.panel.dim; label: "local leg (you → router)" }
  }

  PanelSeparator { width: parent.width }

  // Stats table: rows of metric, local, wan — from live.json's 30 s window.
  Grid {
    width: parent.width
    columns: 3
    columnSpacing: Style.space(14)
    rowSpacing: Style.space(6)

    readonly property real cell: (width - Style.space(14) * 2) / 3
    readonly property var local: tab.panel.live ? tab.panel.live.local : null
    readonly property var wan: tab.panel.live ? tab.panel.live.wan : null

    component HeadCell: Text {
      textFormat: Text.PlainText
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
      horizontalAlignment: Text.AlignRight
    }
    component NameCell: Text {
      textFormat: Text.PlainText
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
    component ValCell: Text {
      textFormat: Text.PlainText
      color: tab.panel.fg
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      horizontalAlignment: Text.AlignRight
    }

    function ms(v) { return v === null || v === undefined ? "--" : v.toFixed(1) + " ms" }
    function pct(v) { return v === null || v === undefined ? "--" : (v * 100).toFixed(2) + " %" }

    HeadCell { width: parent.cell; text: "LAST 30 S" ; horizontalAlignment: Text.AlignLeft }
    HeadCell { width: parent.cell; text: "LOCAL LEG" }
    HeadCell { width: parent.cell; text: "WAN LEG" }

    NameCell { width: parent.cell; text: "median" }
    ValCell { width: parent.cell; text: parent.ms(parent.local ? parent.local.p50 : null) }
    ValCell { width: parent.cell; text: parent.ms(parent.wan ? parent.wan.p50 : null) }

    NameCell { width: parent.cell; text: "p95" }
    ValCell { width: parent.cell; text: parent.ms(parent.local ? parent.local.p95 : null) }
    ValCell { width: parent.cell; text: parent.ms(parent.wan ? parent.wan.p95 : null) }

    NameCell { width: parent.cell; text: "worst" }
    ValCell { width: parent.cell; text: parent.ms(parent.local ? parent.local.max : null) }
    ValCell { width: parent.cell; text: parent.ms(parent.wan ? parent.wan.max : null) }

    NameCell { width: parent.cell; text: "jitter" }
    ValCell { width: parent.cell; text: parent.ms(parent.local ? parent.local.jitter : null) }
    ValCell { width: parent.cell; text: parent.ms(parent.wan ? parent.wan.jitter : null) }

    NameCell { width: parent.cell; text: "loss" }
    ValCell {
      width: parent.cell
      text: parent.pct(parent.local ? parent.local.loss : null)
      color: parent.local && parent.local.loss > 0 ? tab.panel.warnTone : tab.panel.fg
    }
    ValCell {
      width: parent.cell
      text: parent.pct(parent.wan ? parent.wan.loss : null)
      color: parent.wan && parent.wan.loss > 0 ? tab.panel.warnTone : tab.panel.fg
    }
  }

  PanelSeparator { width: parent.width }

  // ---- latency under load (bufferbloat) -----------------------------------
  Item {
    width: parent.width
    height: loadLabel.implicitHeight

    Text {
      id: loadLabel
      textFormat: Text.PlainText
      text: "LATENCY UNDER LOAD"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: tab.loadTest ? "measured during the last peak test" : ""
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: tab.loadTest === null
    width: parent.width
    text: "No measurement yet — run a peak test and the probes will time the "
      + "connection while it is saturated."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  Row {
    width: parent.width
    visible: tab.loadTest !== null
    spacing: Style.space(12)

    Column {
      width: parent.width - gradeCol.width - Style.space(12)
      spacing: Style.space(6)
      anchors.verticalCenter: parent.verticalCenter

      readonly property real scaleMs: tab.loadTest
        ? Math.max(1, Math.max(tab.loadTest.ping_idle, tab.loadTest.ping_loaded) * 2.2)
        : 1

      component LoadBar: Row {
        property string label: ""
        property var ms: null
        property color tint: tab.panel.okTone
        width: parent.width
        spacing: Style.space(9)

        Text {
          textFormat: Text.PlainText
          width: Style.space(44)
          text: parent.label
          color: tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
          anchors.verticalCenter: parent.verticalCenter
        }
        Rectangle {
          width: parent.width - Style.space(44) - Style.space(52) - Style.space(9) * 2
          height: Style.space(8)
          color: Qt.rgba(tab.panel.fg.r, tab.panel.fg.g, tab.panel.fg.b, 0.10)
          anchors.verticalCenter: parent.verticalCenter

          Rectangle {
            height: parent.height
            width: parent.width * (parent.parent.ms !== null
              ? Math.min(1, parent.parent.ms / parent.parent.parent.scaleMs) : 0)
            color: parent.parent.tint
          }
        }
        Text {
          textFormat: Text.PlainText
          width: Style.space(52)
          horizontalAlignment: Text.AlignRight
          text: parent.ms !== null ? Math.round(parent.ms) + " ms" : "--"
          color: tab.panel.fg
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.bodySmall
          anchors.verticalCenter: parent.verticalCenter
        }
      }

      LoadBar {
        label: "idle"
        ms: tab.loadTest ? tab.loadTest.ping_idle : null
        tint: tab.panel.okTone
      }
      LoadBar {
        label: "loaded"
        ms: tab.loadTest ? tab.loadTest.ping_loaded : null
        tint: tab.addedMs < 30 ? tab.panel.okTone : tab.panel.warnTone
      }
    }

    Column {
      id: gradeCol
      width: Style.space(76)
      spacing: Style.space(2)
      anchors.verticalCenter: parent.verticalCenter

      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: tab.bloatGrade
        color: tab.bloatTone
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.fontPx(1.7)
        font.weight: Font.Bold
      }
      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: "BUFFERBLOAT"
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.caption
        font.letterSpacing: 1
      }
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: tab.loadTest !== null
    width: parent.width
    text: "+" + Math.round(tab.addedMs) + " ms added under full load. Below 30 ms "
      + "a video call stays clean while someone else is downloading."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }
}
