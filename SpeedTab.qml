pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui

// Speed: live throughput, content-check history as paired bars, and the
// last peak result in full.
Column {
  id: tab

  required property var panel

  spacing: Style.space(12)

  Component.onCompleted: panel.requestTests()

  readonly property var tests: panel.testsData && panel.testsData.tests
    ? panel.testsData.tests : []
  readonly property var contentTests: {
    var out = tests.filter(function(t) { return t.kind === "content" && t.ok })
    out.reverse()  // oldest first for the bars
    return out.slice(-12)
  }
  readonly property var lastPeak: {
    for (var i = 0; i < tests.length; i++)
      if (tests[i].kind === "peak" && tests[i].ok) return tests[i]
    return null
  }
  readonly property real bestRate: {
    var best = 0
    for (var i = 0; i < contentTests.length; i++) {
      best = Math.max(best, contentTests[i].down_mbps || 0)
      best = Math.max(best, contentTests[i].up_mbps || 0)
    }
    return Math.max(1, best)
  }

  function fmtBytes(b) {
    if (b === null || b === undefined) return "--"
    if (b >= 1e9) return (b / 1e9).toFixed(2) + " GB"
    if (b >= 1e6) return (b / 1e6).toFixed(0) + " MB"
    return (b / 1e3).toFixed(0) + " KB"
  }

  function fmtRate(bps) {
    if (bps === null || bps === undefined || !isFinite(bps)) return "--"
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " MB/s"
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " KB/s"
    return Math.round(bps) + " B/s"
  }

  // ---- live throughput ----------------------------------------------------
  Text {
    textFormat: Text.PlainText
    text: "LIVE THROUGHPUT · LAST 3 MIN"
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    font.letterSpacing: 1
  }

  // Download above the axis, upload mirrored below — the mockup's cluster
  // shape. Both directions share one scale so the asymmetry is honest.
  Canvas {
    id: flowChart
    width: parent.width
    height: Style.space(84)

    property real hoverX: -1
    onHoverXChanged: requestPaint()

    HoverHandler {
      onPointChanged: flowChart.hoverX = hovered ? point.position.x : -1
      onHoveredChanged: if (!hovered) flowChart.hoverX = -1
    }

    function fmt(bps) {
      if (bps === null || bps === undefined) return "--"
      if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " MB/s"
      if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " KB/s"
      return Math.round(bps) + " B/s"
    }

    readonly property var pts: {
      var cut = Date.now() / 1000 - 180
      return tab.panel.recentPoints.filter(function(p) { return p.t >= cut })
    }
    onPtsChanged: requestPaint()
    onWidthChanged: requestPaint()

    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      ctx.clearRect(0, 0, width, height)
      var mid = Math.round(height / 2)
      ctx.strokeStyle = Qt.rgba(tab.panel.fg.r, tab.panel.fg.g,
                                tab.panel.fg.b, 0.22)
      ctx.lineWidth = 1
      ctx.beginPath()
      ctx.moveTo(0, mid + 0.5)
      ctx.lineTo(width, mid + 0.5)
      ctx.stroke()

      var p = pts
      if (!p || p.length < 2) return
      var peak = 10 * 1024
      for (var i = 0; i < p.length; i++) {
        if (p[i].rx !== null) peak = Math.max(peak, p[i].rx)
        if (p[i].tx !== null) peak = Math.max(peak, p[i].tx)
      }
      peak *= 1.1
      var t0 = p[0].t, span = Math.max(1, p[p.length - 1].t - t0)
      var half = mid - 2

      function draw(key, up, tint) {
        var runs = [], cur = []
        for (var i = 0; i < p.length; i++) {
          var v = p[i][key]
          if (v === null || v === undefined) {
            if (cur.length > 1) runs.push(cur)
            cur = []
          } else {
            cur.push([(p[i].t - t0) * (width - 1) / span,
                      mid + (up ? -1 : 1) * half * Math.min(1, v / peak)])
          }
        }
        if (cur.length > 1) runs.push(cur)
        for (var r = 0; r < runs.length; r++) {
          var run = runs[r]
          ctx.beginPath()
          ctx.moveTo(run[0][0], mid)
          for (var j = 0; j < run.length; j++) ctx.lineTo(run[j][0], run[j][1])
          ctx.lineTo(run[run.length - 1][0], mid)
          ctx.closePath()
          ctx.fillStyle = Qt.rgba(tint.r, tint.g, tint.b, 0.2)
          ctx.fill()
          ctx.beginPath()
          for (j = 0; j < run.length; j++) {
            if (j === 0) ctx.moveTo(run[j][0], run[j][1])
            else ctx.lineTo(run[j][0], run[j][1])
          }
          ctx.strokeStyle = tint
          ctx.lineWidth = 1.4
          ctx.stroke()
        }
      }
      draw("rx", true, Color.accent)
      draw("tx", false, tab.panel.warnTone)

      // Top-of-scale label so the silhouette has magnitude.
      ctx.font = "10px " + tab.panel.fontFamily
      ctx.textBaseline = "top"
      ctx.fillStyle = tab.panel.dim
      ctx.fillText("\u2264 " + fmt(peak), 4, 3)

      if (hoverX >= 0) {
        var tAt = t0 + hoverX * span / (width - 1)
        var best = null, bestD = Infinity
        for (var h = 0; h < p.length; h++) {
          var d = Math.abs(p[h].t - tAt)
          if (d < bestD) { bestD = d; best = p[h] }
        }
        if (best) {
          var cx = (best.t - t0) * (width - 1) / span
          ctx.strokeStyle = Qt.rgba(tab.panel.fg.r, tab.panel.fg.g,
                                    tab.panel.fg.b, 0.4)
          ctx.lineWidth = 1
          ctx.beginPath()
          ctx.moveTo(cx + 0.5, 0)
          ctx.lineTo(cx + 0.5, height)
          ctx.stroke()
          // Same readout box, same centring rule as LegChart: the
          // alphabetic baseline half a cap-height below the box centre,
          // because "middle" centres the em box and leaves descender-free
          // digits sitting high in it.
          ctx.textBaseline = "alphabetic"
          var label = Qt.formatTime(new Date(best.t * 1000), "HH:mm:ss")
            + "  ·  \u2193 " + fmt(best.rx) + "  ·  \u2191 " + fmt(best.tx)
          var w = ctx.measureText(label).width + 12
          var bx = Math.max(2, Math.min(width - w - 2, cx - w / 2))
          var bg = Color.popups.background
          ctx.fillStyle = Qt.rgba(bg.r, bg.g, bg.b, 0.92)
          ctx.fillRect(bx, 2, w, 16)
          ctx.strokeStyle = Qt.rgba(tab.panel.fg.r, tab.panel.fg.g,
                                    tab.panel.fg.b, 0.25)
          ctx.strokeRect(bx + 0.5, 2.5, w - 1, 15)
          ctx.fillStyle = tab.panel.fg
          ctx.fillText(label, bx + 6, 10 + 3.65)   // half a 7.3 px cap height
        }
      }
    }
  }

  Row {
    width: parent.width
    spacing: Style.space(14)
    readonly property real cell: (width - Style.space(14) * 3) / 4

    component BigStat: Column {
      property string label: ""
      property string value: ""
      property color tint: tab.panel.fg
      spacing: Style.space(3)
      Text {
        textFormat: Text.PlainText
        text: parent.label
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.caption
        font.letterSpacing: 1
      }
      Text {
        textFormat: Text.PlainText
        text: parent.value
        color: parent.tint
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.title
        font.weight: Font.Medium
      }
    }

    BigStat {
      width: parent.cell
      label: "RECEIVING"
      tint: Color.accent
      value: tab.fmtRate(tab.panel.live && tab.panel.live.rates
        ? tab.panel.live.rates.rx_bps : null)
    }
    BigStat {
      width: parent.cell
      label: "SENDING"
      tint: tab.panel.warnTone
      value: tab.fmtRate(tab.panel.live && tab.panel.live.rates
        ? tab.panel.live.rates.tx_bps : null)
    }
    BigStat {
      width: parent.cell
      label: "DOWNLOADED"
      value: tab.fmtBytes(tab.panel.live && tab.panel.live.rates
        ? tab.panel.live.rates.rx_total : null)
    }
    BigStat {
      width: parent.cell
      label: "UPLOADED"
      value: tab.fmtBytes(tab.panel.live && tab.panel.live.rates
        ? tab.panel.live.rates.tx_total : null)
    }
  }

  PanelSeparator { width: parent.width }

  // ---- content-check history ---------------------------------------------
  Item {
    width: parent.width
    height: historyLabel.implicitHeight

    Text {
      id: historyLabel
      textFormat: Text.PlainText
      text: "CONTENT SPEED · FEEDS YOUR SCORE"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: tab.contentTests.length + " checks kept"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Item {
    width: parent.width
    height: Style.space(80)
    visible: tab.contentTests.length > 0

    Rectangle {
      anchors.bottom: parent.bottom
      width: parent.width
      height: 1
      color: Qt.rgba(tab.panel.fg.r, tab.panel.fg.g, tab.panel.fg.b, 0.15)
    }

    Row {
      anchors.fill: parent

      readonly property real slot: width / Math.max(1, tab.contentTests.length)

      Repeater {
        model: tab.contentTests

        Item {
          id: barSlot
          required property var modelData
          width: parent.slot
          height: parent.height

          // The pair sits centered in its slot with capped widths, so a
          // panel with two checks still reads as two paired results, not
          // four unrelated bars.
          Row {
            anchors.bottom: parent.bottom
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(3)

            Rectangle {
              anchors.bottom: parent.bottom
              width: Math.min(Style.space(22), barSlot.width * 0.4)
              height: Math.max(2, barSlot.height *
                (barSlot.modelData.down_mbps || 0) / tab.bestRate)
              color: Color.accent
            }
            Rectangle {
              anchors.bottom: parent.bottom
              width: Math.min(Style.space(12), barSlot.width * 0.25)
              height: Math.max(2, barSlot.height *
                (barSlot.modelData.up_mbps || 0) / tab.bestRate)
              color: tab.panel.warnTone
            }
          }
        }
      }
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: tab.contentTests.length === 0
    text: "No content checks yet — the first runs shortly after the daemon starts."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  PanelSeparator { width: parent.width }

  // ---- last peak ----------------------------------------------------------
  Item {
    width: parent.width
    height: peakLabel.implicitHeight

    Text {
      id: peakLabel
      textFormat: Text.PlainText
      text: tab.lastPeak
        ? "PEAK · " + new Date(tab.lastPeak.ts * 1000).toLocaleString(Qt.locale(), "d MMM HH:mm").toUpperCase()
        : "PEAK SPEED"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: "informational, not scored"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Grid {
    width: parent.width
    columns: 2
    columnSpacing: Style.space(24)
    rowSpacing: Style.space(6)
    visible: tab.lastPeak !== null

    readonly property real cell: (width - Style.space(24)) / 2
    readonly property var p: tab.lastPeak

    component KvRow: Item {
      property string k: ""
      property string v: ""
      property color vColor: tab.panel.fg
      height: kText.implicitHeight
      Text {
        id: kText
        textFormat: Text.PlainText
        text: parent.k
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        textFormat: Text.PlainText
        anchors.right: parent.right
        width: parent.width - kText.implicitWidth - Style.space(10)
        horizontalAlignment: Text.AlignRight
        elide: Text.ElideLeft
        text: parent.v
        color: parent.vColor
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
    }

    KvRow { width: parent.cell; k: "Download"
      v: parent.p ? (parent.p.down_mbps || 0).toFixed(1) + " Mbps" : "" }
    KvRow { width: parent.cell; k: "Upload"
      v: parent.p && parent.p.up_mbps ? parent.p.up_mbps.toFixed(1) + " Mbps" : "--" }
    KvRow { width: parent.cell; k: "Idle ping"
      v: parent.p && parent.p.ping_idle ? Math.round(parent.p.ping_idle) + " ms" : "--" }
    KvRow {
      width: parent.cell; k: "Loaded ping"
      v: parent.p && parent.p.ping_loaded ? Math.round(parent.p.ping_loaded) + " ms" : "--"
      vColor: parent.p && parent.p.ping_loaded && parent.p.ping_idle
        && parent.p.ping_loaded > parent.p.ping_idle * 3
        ? tab.panel.warnTone : tab.panel.fg
    }
    KvRow { width: parent.cell; k: "Data used"
      v: parent.p && parent.p.bytes ? (parent.p.bytes / 1e6).toFixed(0) + " MB" : "--" }
    KvRow { width: parent.cell; k: "Engine"
      v: parent.p ? parent.p.engine : "" }
  }

  Item {
    width: parent.width
    height: serverKey.implicitHeight
    visible: tab.lastPeak !== null && !!tab.lastPeak.server

    Text {
      id: serverKey
      textFormat: Text.PlainText
      text: "Server"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      width: parent.width - serverKey.implicitWidth - Style.space(10)
      horizontalAlignment: Text.AlignRight
      elide: Text.ElideLeft
      text: tab.lastPeak && tab.lastPeak.server ? tab.lastPeak.server : ""
      color: tab.panel.fg
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: tab.lastPeak === null
    text: "No peak test yet."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  PanelSeparator { width: parent.width }

  Item {
    width: parent.width
    height: Style.space(28)

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width - runButton.width - Style.space(12)
      text: "A peak test saturates the line for ~10 s each way — up to ~600 MB on a fast line. It only runs when you ask."
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }

    Rectangle {
      id: runButton
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      width: runText.implicitWidth + Style.space(24)
      height: Style.space(28)
      color: runHover.hovered
        ? Style.hoverFillFor(tab.panel.fg, Color.accent)
        : Style.normalFillFor(tab.panel.fg, Color.accent)
      border.width: Style.normalBorderWidth
      border.color: Style.normalBorderFor(tab.panel.fg, Color.accent)

      Text {
        id: runText
        textFormat: Text.PlainText
        anchors.centerIn: parent
        text: tab.panel.live && tab.panel.live.peak_running ? "󰓅 Testing…" : "󰓅 Run test"
        color: tab.panel.fg
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      HoverHandler { id: runHover }
      TapHandler {
        enabled: !(tab.panel.live && tab.panel.live.peak_running)
        onTapped: { tab.panel.runPeakTest(); refreshTimer.start() }
      }
    }
  }

  // While a peak test runs, poll the tests list so the result appears.
  Timer {
    id: refreshTimer
    interval: 3000
    repeat: true
    running: tab.panel.live && tab.panel.live.peak_running === true
    onTriggered: tab.panel.requestTests()
    onRunningChanged: if (!running) tab.panel.requestTests()
  }
}
