pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui

// The local leg in detail: signal on a labelled scale, link facts, and the
// airtime counters that explain "signal looks fine but Wi-Fi feels slow".
Column {
  id: tab

  required property var panel

  Component.onCompleted: panel.requestEvents("7d")

  readonly property var linkEvents: {
    var all = panel.eventsData && panel.eventsData.events
      ? panel.eventsData.events : []
    var kinds = {"roam": 1, "associate": 1, "rate-drop": 1, "channel-change": 1}
    var cut = Date.now() / 1000 - 86400
    var out = []
    for (var i = 0; i < all.length && out.length < 6; i++)
      if (kinds[all[i].kind] && all[i].ts >= cut) out.push(all[i])
    return out
  }

  readonly property var roamMarks: {
    var all = panel.eventsData && panel.eventsData.events
      ? panel.eventsData.events : []
    var cut = Date.now() / 1000 - 1800
    var out = []
    for (var i = 0; i < all.length; i++)
      if (all[i].kind === "roam" && all[i].ts >= cut) out.push(all[i].ts)
    return out
  }

  readonly property var link: panel.live ? panel.live.link : null
  readonly property var station: link ? link.station : null
  readonly property bool isWifi: link && link.kind === "wifi"

  spacing: Style.space(12)

  Text {
    textFormat: Text.PlainText
    visible: !tab.isWifi
    text: tab.link && tab.link.kind === "ethernet"
      ? "Wired connection — no radio to report on. The local leg lives on the Latency tab."
      : "Not connected."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
    width: parent.width
  }

  // ---- signal -------------------------------------------------------------
  Column {
    width: parent.width
    visible: tab.isWifi
    spacing: Style.space(12)

    Text {
      textFormat: Text.PlainText
      text: "THE LOCAL LEG · THIS MACHINE TO THE ROUTER"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }

    Row {
      width: parent.width
      spacing: Style.space(20)

      readonly property var dbm: tab.link ? tab.link.signal_dbm : null
      readonly property color tone: {
        if (dbm === null || dbm === undefined) return tab.panel.dim
        if (dbm >= -60) return tab.panel.okTone
        if (dbm >= -70) return tab.panel.warnTone
        return Color.urgent
      }

      Column {
        spacing: Style.space(2)
        anchors.bottom: parent.bottom

        Text {
          textFormat: Text.PlainText
          text: parent.parent.dbm !== null && parent.parent.dbm !== undefined
            ? parent.parent.dbm + " dBm" : "--"
          color: parent.parent.tone
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.fontPx(2.0)
          font.weight: Font.Bold
        }
        Text {
          textFormat: Text.PlainText
          text: "SIGNAL"
          color: tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
          font.letterSpacing: 1
        }
      }

      Column {
        width: parent.width - Style.space(130)
        anchors.bottom: parent.bottom
        anchors.bottomMargin: Style.space(4)
        spacing: Style.space(5)

        Rectangle {
          width: parent.width
          height: Style.space(8)
          color: Qt.rgba(tab.panel.fg.r, tab.panel.fg.g, tab.panel.fg.b, 0.10)

          Rectangle {
            readonly property var dbm: tab.link ? tab.link.signal_dbm : null
            height: parent.height
            // -90 dBm is unusable, -30 is rail: map onto 0..1.
            width: parent.width * (dbm === null || dbm === undefined
              ? 0 : Math.max(0, Math.min(1, (dbm + 90) / 60)))
            color: parent.parent.parent.tone
            Behavior on width { NumberAnimation { duration: 300 } }
          }
          // The marginal mark at -67 dBm, where video calls start to suffer.
          Rectangle {
            x: parent.width * ((-67 + 90) / 60)
            y: -Style.space(3)
            width: 1
            height: parent.height + Style.space(6)
            color: Qt.rgba(tab.panel.fg.r, tab.panel.fg.g, tab.panel.fg.b, 0.35)
          }
        }

        Item {
          width: parent.width
          height: scaleLeft.implicitHeight

          Text {
            id: scaleLeft
            textFormat: Text.PlainText
            text: "−90 unusable"
            color: tab.panel.dim
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
          Text {
            textFormat: Text.PlainText
            x: parent.width * ((-67 + 90) / 60) - implicitWidth / 2
            text: "−67 marginal"
            color: tab.panel.dim
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
          Text {
            textFormat: Text.PlainText
            anchors.right: parent.right
            text: "−30 max"
            color: tab.panel.dim
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
        }
      }
    }

    // ---- signal & local lag history ---------------------------------------
    Item {
      width: parent.width
      height: sigLabel.implicitHeight

      Text {
        id: sigLabel
        textFormat: Text.PlainText
        text: "SIGNAL & LOCAL LAG · LAST 30 MIN"
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.caption
        font.letterSpacing: 1
      }
      Text {
        textFormat: Text.PlainText
        anchors.right: parent.right
        text: {
          var n = tab.roamMarks.length
          return n === 0 ? "" : n === 1 ? "one roam" : n + " roams"
        }
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.caption
      }
    }

    Canvas {
      id: sigChart
      width: parent.width
      height: Style.space(78)

      readonly property var pts: tab.panel.recentPoints
      readonly property var roams: tab.roamMarks
      onPtsChanged: requestPaint()
      onRoamsChanged: requestPaint()
      onWidthChanged: requestPaint()

      onPaint: {
        var ctx = getContext("2d")
        ctx.reset()
        ctx.clearRect(0, 0, width, height)
        var bottom = height - 1
        ctx.strokeStyle = Qt.rgba(tab.panel.fg.r, tab.panel.fg.g,
                                  tab.panel.fg.b, 0.16)
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.moveTo(0, bottom + 0.5)
        ctx.lineTo(width, bottom + 0.5)
        ctx.stroke()

        var p = pts
        if (!p || p.length < 2) return
        var t0 = p[0].t, span = Math.max(1, p[p.length - 1].t - t0)
        function xAt(t) { return (t - t0) * (width - 1) / span }

        // Roam markers first, dashed, under the series.
        ctx.strokeStyle = Qt.rgba(0.73, 0.6, 0.97, 0.55)
        ctx.setLineDash([2, 3])
        for (var m = 0; m < roams.length; m++) {
          var rx = xAt(roams[m])
          if (rx < 0 || rx > width) continue
          ctx.beginPath()
          ctx.moveTo(rx, 0)
          ctx.lineTo(rx, height)
          ctx.stroke()
        }
        ctx.setLineDash([])

        function runs(key, yAt) {
          var out = [], cur = []
          for (var i = 0; i < p.length; i++) {
            var v = p[i][key]
            if (v === null || v === undefined) {
              if (cur.length > 1) out.push(cur)
              cur = []
            } else {
              cur.push([xAt(p[i].t), yAt(v)])
            }
          }
          if (cur.length > 1) out.push(cur)
          return out
        }

        // Signal on the fixed -90..-30 dBm scale, as a filled band.
        var ok = tab.panel.okTone
        var sigRuns = runs("sig", function(v) {
          var f = Math.max(0, Math.min(1, (v + 90) / 60))
          return bottom - (bottom - 3) * f
        })
        for (var r = 0; r < sigRuns.length; r++) {
          var run = sigRuns[r]
          ctx.beginPath()
          ctx.moveTo(run[0][0], bottom)
          for (var j = 0; j < run.length; j++) ctx.lineTo(run[j][0], run[j][1])
          ctx.lineTo(run[run.length - 1][0], bottom)
          ctx.closePath()
          ctx.fillStyle = Qt.rgba(ok.r, ok.g, ok.b, 0.14)
          ctx.fill()
          ctx.beginPath()
          for (j = 0; j < run.length; j++) {
            if (j === 0) ctx.moveTo(run[j][0], run[j][1])
            else ctx.lineTo(run[j][0], run[j][1])
          }
          ctx.strokeStyle = ok
          ctx.lineWidth = 1.4
          ctx.stroke()
        }

        // Local lag on its own scale, a thin dim line.
        var lagPeak = 8
        for (var i = 0; i < p.length; i++) {
          if (p[i].local !== null && p[i].local !== undefined)
            lagPeak = Math.max(lagPeak, p[i].local)
        }
        lagPeak *= 1.15
        var lagRuns = runs("local", function(v) {
          return bottom - (bottom - 3) * Math.min(1, v / lagPeak)
        })
        ctx.strokeStyle = tab.panel.dim
        ctx.lineWidth = 1
        for (r = 0; r < lagRuns.length; r++) {
          run = lagRuns[r]
          ctx.beginPath()
          for (j = 0; j < run.length; j++) {
            if (j === 0) ctx.moveTo(run[j][0], run[j][1])
            else ctx.lineTo(run[j][0], run[j][1])
          }
          ctx.stroke()
        }
      }
    }

    Row {
      spacing: Style.space(16)

      component ChartKey: Row {
        property color tint: "white"
        property string label: ""
        property bool dashed: false
        spacing: Style.space(6)
        Rectangle {
          width: parent.dashed ? 1 : Style.space(10)
          height: parent.dashed ? Style.space(9) : 2
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

      ChartKey { tint: tab.panel.okTone; label: "signal" }
      ChartKey { tint: tab.panel.dim; label: "local lag" }
      ChartKey { tint: "#bb9af7"; label: "roam"; dashed: true }
    }

    PanelSeparator { width: parent.width }

    // ---- link facts -------------------------------------------------------
    Grid {
      width: parent.width
      columns: 2
      columnSpacing: Style.space(24)
      rowSpacing: Style.space(6)

      readonly property real cell: (width - Style.space(24)) / 2

      component KvRow: Item {
        property string k: ""
        property string v: ""
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
          text: parent.v
          color: tab.panel.fg
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideLeft
          width: parent.width - kText.implicitWidth - Style.space(8)
          horizontalAlignment: Text.AlignRight
        }
      }

      KvRow { width: parent.cell; k: "Band"
        v: tab.link && tab.link.band ? tab.link.band : "--" }
      KvRow { width: parent.cell; k: "Channel"
        v: tab.link && tab.link.channel
          ? tab.link.channel + (tab.link.width_mhz ? " · " + tab.link.width_mhz + " MHz" : "")
          : "--" }
      KvRow { width: parent.cell; k: "Tx rate"
        v: tab.link && tab.link.tx_mbps ? tab.link.tx_mbps + " Mbps" : "--" }
      KvRow { width: parent.cell; k: "Rx rate"
        v: tab.link && tab.link.rx_mbps ? tab.link.rx_mbps + " Mbps" : "--" }
      KvRow { width: parent.cell; k: "Standard"
        v: tab.link && tab.link.standard ? tab.link.standard : "--" }
      KvRow { width: parent.cell; k: "Interface"
        v: tab.link && tab.link.iface ? tab.link.iface : "--" }
      KvRow { width: parent.cell; k: "BSSID"
        v: tab.link && tab.link.bssid ? tab.link.bssid : "--" }
      KvRow { width: parent.cell; k: "Gateway"
        v: tab.link && tab.link.gateway ? tab.link.gateway : "--" }
    }

    PanelSeparator { width: parent.width }

    // ---- airtime health ---------------------------------------------------
    Text {
      textFormat: Text.PlainText
      text: "AIRTIME · WHY WI-FI FEELS SLOW WHEN SIGNAL LOOKS FINE"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }

    Row {
      width: parent.width
      spacing: Style.space(14)
      readonly property real cell: (width - Style.space(14) * 2) / 3

      component AirStat: Column {
        property string label: ""
        property string display: "--"
        property real frac: 0        // 0..1 meter fill
        property bool bad: false
        spacing: Style.space(4)
        Text {
          textFormat: Text.PlainText
          text: parent.display
          color: parent.bad ? tab.panel.warnTone : tab.panel.okTone
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.heading
          font.weight: Font.Bold
        }
        Text {
          textFormat: Text.PlainText
          text: parent.label
          color: tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
          font.letterSpacing: 1
        }
        Rectangle {
          width: parent.width
          height: Math.max(2, Style.space(3))
          color: Qt.rgba(tab.panel.fg.r, tab.panel.fg.g, tab.panel.fg.b, 0.12)
          Rectangle {
            height: parent.height
            width: parent.width * Math.max(0, Math.min(1, parent.parent.frac))
            color: parent.parent.bad ? tab.panel.warnTone : tab.panel.okTone
          }
        }
      }

      AirStat {
        width: parent.cell
        label: "TX RETRIES"
        display: tab.station && tab.station.retry_pct !== undefined
          ? tab.station.retry_pct.toFixed(1) + " %"
          : (tab.station && tab.station.tx_retries !== undefined
             ? String(tab.station.tx_retries) : "--")
        // 10% retries fills the meter; past ~5% the air is genuinely busy.
        frac: tab.station && tab.station.retry_pct !== undefined
          ? tab.station.retry_pct / 10 : 0
        bad: tab.station && tab.station.retry_pct > 5
      }
      AirStat {
        width: parent.cell
        label: "TX FAILED"
        display: tab.station && tab.station.tx_failed !== undefined
          ? String(tab.station.tx_failed) : "--"
        frac: tab.station && tab.station.tx_failed !== undefined
          ? tab.station.tx_failed / 50 : 0
        bad: tab.station && tab.station.tx_failed > 10
      }
      AirStat {
        width: parent.cell
        label: "BEACON LOSS"
        display: tab.station && tab.station.beacon_loss !== undefined
          ? String(tab.station.beacon_loss) : "--"
        frac: tab.station && tab.station.beacon_loss !== undefined
          ? tab.station.beacon_loss / 10 : 0
        bad: tab.station && tab.station.beacon_loss > 0
      }
    }

    Text {
      textFormat: Text.PlainText
      width: parent.width
      text: "Counters since association. Retries mean a noisy channel; failures mean "
        + "frames given up on; beacon loss means the router's heartbeat went missing."
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }

    PanelSeparator { width: parent.width }

    // ---- link events ------------------------------------------------------
    Text {
      textFormat: Text.PlainText
      text: "LINK EVENTS · LAST 24 H"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }

    Text {
      textFormat: Text.PlainText
      visible: tab.linkEvents.length === 0
      text: "None. The link has been steady."
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    Column {
      width: parent.width
      spacing: Style.space(8)

      Repeater {
        model: tab.linkEvents

        Row {
          id: linkRow
          required property var modelData
          width: parent.width
          spacing: Style.space(10)

          readonly property color tone: {
            var k = linkRow.modelData.kind
            if (k === "roam") return "#bb9af7"
            if (k === "rate-drop") return tab.panel.warnTone
            if (k === "associate") return tab.panel.okTone
            return Color.accent
          }

          Text {
            textFormat: Text.PlainText
            width: Style.space(42)
            text: {
              var d = new Date(linkRow.modelData.ts * 1000)
              return d.toLocaleString(Qt.locale(), "HH:mm")
            }
            color: tab.panel.dim
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
          Rectangle {
            width: Style.space(5)
            height: Style.space(5)
            color: linkRow.tone
            anchors.verticalCenter: parent.verticalCenter
          }
          Text {
            textFormat: Text.PlainText
            width: parent.width - Style.space(42) - Style.space(5)
              - Style.space(58) - Style.space(10) * 3
            text: linkRow.modelData.detail
            color: tab.panel.fg
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }
          Text {
            textFormat: Text.PlainText
            width: Style.space(58)
            horizontalAlignment: Text.AlignRight
            text: {
              var e = linkRow.modelData
              if (!e.ended_ts || e.ended_ts === e.ts) return ""
              var s = e.ended_ts - e.ts
              return s < 60 ? "for " + s + " s"
                : "for " + Math.round(s / 60) + " m"
            }
            color: tab.panel.dim
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
        }
      }
    }
  }
}
