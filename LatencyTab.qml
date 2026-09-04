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
  // A peak test whose loaded latency came out BELOW its idle latency did
  // not measure the link under load: a queue cannot make packets arrive
  // sooner. The old code clamped the difference at zero, which graded that
  // A+ and handed back the best possible verdict on an unusable
  // measurement. Withhold it instead — the same wrong-direction rule the
  // daemon applies to the loaded/idle ratio.
  readonly property bool loadTestUsable: loadTest
    && loadTest.ping_idle > 0
    && loadTest.ping_loaded >= loadTest.ping_idle * 0.95

  readonly property real addedMs: loadTestUsable
    ? Math.max(0, loadTest.ping_loaded - loadTest.ping_idle) : 0
  // Waveform's grading of latency added under load.
  readonly property string bloatGrade: {
    if (!loadTestUsable) return ""
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

  // The kernel's timing for the machine's own TCP connections, or null while
  // too few qualify — the daemon publishes nothing rather than a
  // distribution drawn from a handful of sockets.
  readonly property var sockets: panel.live ? panel.live.sockets : null

  readonly property string socketsNote: {
    if (!sockets) return ""
    var q = sockets.queue_p50
    var head = "Measured from your own traffic, no probe. "
    if (q === null || q === undefined) return head
    // Deliberately a claim about the ABSOLUTE delay, not its share of the
    // round trip: a socket to another continent is mostly distance, and
    // saying "almost none of it is queueing" there would be false.
    if (q < 10) return head + "Queueing is a few milliseconds at most, so "
      + "nothing on the path is holding your traffic up. The rest of each "
      + "round trip is distance to the servers themselves."
    if (q < 30) return head + "There is real queueing on the path now \u2014 "
      + "enough for a video call to start feeling it while something else "
      + "is downloading."
    return head + "Queueing dominates what your apps feel. Something on the "
      + "path is holding packets \u2014 the legs above say which side of the "
      + "router it is on."
  }

  // What the instruments line says when folded shut. A count is worth more
  // than the word "instruments" on its own, so the collapsed state still
  // carries the fact most worth knowing: how many are feeding the score.
  readonly property string instrumentSummary: {
    var ins = panel.live && panel.live.instruments ? panel.live.instruments : []
    if (!ins.length) return "NOT YET MEASURED"
    var scored = 0, quarantined = 0
    for (var i = 0; i < ins.length; i++) {
      if (ins[i].active) scored++
      else if (ins[i].quarantined) quarantined++
    }
    var parts = [scored + " SCORED"]
    var standby = ins.length - scored - quarantined
    if (standby > 0) parts.push(standby + " STANDBY")
    if (quarantined > 0) parts.push(quarantined + " QUARANTINED")
    return parts.join(" \u00b7 ")
  }

  // The idle/loaded split, published on `lag`. Null until enough probes have
  // landed on each side of it to be worth comparing.
  readonly property var underLoad: {
    var l = panel.live && panel.live.lag ? panel.live.lag : null
    if (!l || l.loaded_p50 === null || l.loaded_p50 === undefined) return null
    return l
  }

  // Collapsed, this line is the block: typical and worst while the link was
  // actually carrying traffic, which is the pair the headline 30 s window
  // averages away.
  readonly property string underLoadSummary: {
    var u = underLoad
    if (!u) return "NOT YET MEASURED"
    var p50 = u.loaded_p50 !== null && u.loaded_p50 !== undefined
      ? Math.round(u.loaded_p50) : null
    var p95 = u.loaded_p95 !== null && u.loaded_p95 !== undefined
      ? Math.round(u.loaded_p95) : null
    if (p50 === null) return "NOT YET MEASURED"
    var out = p50 + " MS TYPICAL"
    if (p95 !== null) out += " \u00b7 " + p95 + " WORST"
    return out
  }

  readonly property string underLoadNote: {
    var u = underLoad
    if (!u) return ""
    var parts = []
    if (u.loaded_samples !== undefined)
      parts.push(u.loaded_samples + " of "
        + (u.loaded_samples + (u.idle_samples || 0)) + " probes landed while "
        + "the link was carrying traffic")
    // Depth is what everyone reports. Duration is what you feel after the
    // download has finished, and it is the half nobody shows.
    if (u.drain_ms !== null && u.drain_ms !== undefined) {
      var secs = (u.drain_ms / 1000).toFixed(1)
      parts.push(u.drain_settled
        ? "the queue drained " + secs + " s after traffic stopped"
        : "still above its quiet level " + secs + " s after traffic stopped")
    }
    return parts.join(". ") + "."
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

  // ---- what the machine's own connections are experiencing ----------------
  // The table above is our probe. This is the kernel's own timing for the
  // user's real TCP traffic to their real destinations: no probe, no
  // privilege. `floor` is the lowest round trip each path has ever shown, so
  // "queueing" is the delay left once distance is divided out — which is the
  // only figure that compares a socket next door with one on another
  // continent.
  Text {
    textFormat: Text.PlainText
    text: "AS YOUR APPS SEE IT"
      + (tab.sockets ? " \u00b7 " + tab.sockets.sockets + " CONNECTIONS" : "")
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    font.letterSpacing: 1
  }

  Text {
    textFormat: Text.PlainText
    visible: !tab.sockets
    width: parent.width
    wrapMode: Text.WordWrap
    text: "Not enough measured connections yet. This fills in once a few "
      + "apps are talking over TCP."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }

  Grid {
    width: parent.width
    visible: !!tab.sockets
    columns: 3
    columnSpacing: Style.space(14)
    rowSpacing: Style.space(6)

    readonly property real cell: (width - Style.space(14) * 2) / 3
    readonly property var s: tab.sockets

    component HeadCell2: Text {
      textFormat: Text.PlainText
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
      horizontalAlignment: Text.AlignRight
    }
    component NameCell2: Text {
      textFormat: Text.PlainText
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
    component ValCell2: Text {
      textFormat: Text.PlainText
      color: tab.panel.fg
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      horizontalAlignment: Text.AlignRight
    }

    function ms2(v) { return v === null || v === undefined ? "--" : v.toFixed(1) + " ms" }

    HeadCell2 { width: parent.cell; text: "TCP, LIVE"; horizontalAlignment: Text.AlignLeft }
    HeadCell2 { width: parent.cell; text: "TYPICAL" }
    HeadCell2 { width: parent.cell; text: "WORST" }

    NameCell2 { width: parent.cell; text: "round trip" }
    ValCell2 { width: parent.cell; text: parent.ms2(parent.s ? parent.s.rtt_p50 : null) }
    ValCell2 { width: parent.cell; text: parent.ms2(parent.s ? parent.s.rtt_p95 : null) }

    NameCell2 { width: parent.cell; text: "path floor" }
    ValCell2 { width: parent.cell; text: parent.ms2(parent.s ? parent.s.floor_p50 : null) }
    ValCell2 { width: parent.cell; text: "\u2014" }

    NameCell2 { width: parent.cell; text: "queueing" }
    ValCell2 {
      width: parent.cell
      text: parent.ms2(parent.s ? parent.s.queue_p50 : null)
      color: parent.s && parent.s.queue_p50 > 30 ? tab.panel.warnTone : tab.panel.fg
    }
    ValCell2 {
      width: parent.cell
      text: parent.ms2(parent.s ? parent.s.queue_p95 : null)
      color: parent.s && parent.s.queue_p95 > 60 ? tab.panel.warnTone : tab.panel.fg
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: !!tab.sockets
    width: parent.width
    wrapMode: Text.WordWrap
    text: tab.socketsNote
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }

  PanelSeparator { width: parent.width }

  // Folded shut by default: four rows and a paragraph is a lot of the tab's
  // height for something that only matters when you are asking which probe
  // produced the number. The header still reports the count, and the whole
  // row is the control — no separate button, no extra line.
  Item {
    width: parent.width
    height: instHeader.implicitHeight

    Text {
      id: instHeader
      textFormat: Text.PlainText
      text: "INSTRUMENTS \u00b7 " + (tab.panel.instrumentsExpanded
        ? "WHAT MEASURES THE INTERNET LEG" : tab.instrumentSummary)
      color: instHover.hovered ? tab.panel.fg : tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }

    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      anchors.verticalCenter: instHeader.verticalCenter
      // nf-md-chevron_down / nf-md-chevron_right
      text: tab.panel.instrumentsExpanded ? "\u{f0140}" : "\u{f0142}"
      color: instHover.hovered ? tab.panel.fg : tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }

    HoverHandler { id: instHover }
    TapHandler {
      onTapped: tab.panel.instrumentsExpanded = !tab.panel.instrumentsExpanded
    }
  }

  // The bench: the two with the fewest losses and steadiest tails hold
  // the seats and feed the score; the rest idle at a tenth of the rate.
  Column {
    width: parent.width
    visible: tab.panel.instrumentsExpanded
    height: visible ? implicitHeight : 0
    spacing: Style.space(6)

    Repeater {
      model: tab.panel.live && tab.panel.live.instruments
        ? tab.panel.live.instruments : []

      Row {
        id: instRow
        required property var modelData
        width: parent.width
        spacing: Style.space(8)

        Rectangle {
          width: Style.space(5)
          height: Style.space(5)
          color: instRow.modelData.active ? tab.panel.okTone : tab.panel.dim
          anchors.verticalCenter: parent.verticalCenter
        }
        Text {
          textFormat: Text.PlainText
          width: parent.width - Style.space(5) - Style.space(60)
            - Style.space(56) - Style.space(74) - Style.space(8) * 4
          text: instRow.modelData.kind + " \u00b7 " + instRow.modelData.target
          color: tab.panel.fg
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideMiddle
        }
        Text {
          textFormat: Text.PlainText
          width: Style.space(60)
          horizontalAlignment: Text.AlignRight
          text: instRow.modelData.p50 !== null && instRow.modelData.p50 !== undefined
            ? instRow.modelData.p50.toFixed(1) + " ms" : "--"
          color: tab.panel.fg
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.bodySmall
        }
        Text {
          textFormat: Text.PlainText
          width: Style.space(56)
          horizontalAlignment: Text.AlignRight
          text: {
            var l = instRow.modelData.loss
            return l !== null && l !== undefined ? (l * 100).toFixed(1) + "%" : "--"
          }
          color: instRow.modelData.loss ? tab.panel.warnTone : tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
        }
        Text {
          textFormat: Text.PlainText
          width: Style.space(74)
          horizontalAlignment: Text.AlignRight
          text: instRow.modelData.active ? "scored"
            : instRow.modelData.quarantined ? "quarantined" : "standby"
          color: instRow.modelData.active ? tab.panel.okTone : tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: tab.panel.instrumentsExpanded
    height: visible ? implicitHeight : 0
    width: parent.width
    text: "Two instruments feed the score at a time, re-ranked every five "
      + "minutes on loss and tail stability \u2014 one bad anchor cannot "
      + "poison the number."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
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
      text: tab.loadTestUsable ? "measured during the last peak test" : ""
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  PanelSeparator { width: parent.width }

  Text {
    textFormat: Text.PlainText
    visible: !tab.loadTestUsable
    width: parent.width
    text: tab.loadTest && !tab.loadTestUsable
      ? "The last peak test read a lower latency under load than at rest, "
        + "which is not something a busy link can do — so it is not graded. "
        + "Run another and it should settle."
      : "No measurement yet — run a peak test and the probes will time the "
      + "connection while it is saturated."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  Row {
    width: parent.width
    visible: tab.loadTestUsable
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
    visible: tab.loadTestUsable
    width: parent.width
    text: "+" + Math.round(tab.addedMs) + " ms added under full load. Below 30 ms "
      + "a video call stays clean while someone else is downloading."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  // ---- under load, from the traffic you were already sending -------------
  // The block above needs a peak test. This one needs nothing: every probe
  // carries whether the link was busy when it landed, so the same samples
  // answer both "how bad does it get while in use" and "how fast does it
  // recover" without generating a byte.
  PanelSeparator { width: parent.width; visible: !!tab.underLoad }

  // Folded shut like the bench above it: adding a table and a note pushed
  // the tab past the panel's height again, and the collapsed line already
  // carries the two numbers worth reading.
  Item {
    width: parent.width
    visible: !!tab.underLoad
    height: visible ? ulHeader.implicitHeight : 0

    Text {
      id: ulHeader
      textFormat: Text.PlainText
      text: "WHILE YOU WERE USING IT \u00b7 " + (tab.panel.underLoadExpanded
        ? "LAST 5 MIN" : tab.underLoadSummary)
      color: ulHover.hovered ? tab.panel.fg : tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      anchors.verticalCenter: ulHeader.verticalCenter
      text: tab.panel.underLoadExpanded ? "\u{f0140}" : "\u{f0142}"
      color: ulHover.hovered ? tab.panel.fg : tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
    HoverHandler { id: ulHover }
    TapHandler {
      onTapped: tab.panel.underLoadExpanded = !tab.panel.underLoadExpanded
    }
  }

  Grid {
    width: parent.width
    visible: !!tab.underLoad && tab.panel.underLoadExpanded
    height: visible ? implicitHeight : 0
    columns: 3
    columnSpacing: Style.space(14)
    rowSpacing: Style.space(6)

    readonly property real cell: (width - Style.space(14) * 2) / 3
    readonly property var u: tab.underLoad

    component H3: Text {
      textFormat: Text.PlainText
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
      horizontalAlignment: Text.AlignRight
    }
    component N3: Text {
      textFormat: Text.PlainText
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
    component V3: Text {
      textFormat: Text.PlainText
      color: tab.panel.fg
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      horizontalAlignment: Text.AlignRight
    }

    function ms3(v) {
      return v === null || v === undefined ? "\u2014" : v.toFixed(1) + " ms"
    }

    H3 { width: parent.cell; text: "PROBES"; horizontalAlignment: Text.AlignLeft }
    H3 { width: parent.cell; text: "TYPICAL" }
    H3 { width: parent.cell; text: "WORST" }

    N3 { width: parent.cell; text: "while busy" }
    V3 {
      width: parent.cell
      text: parent.ms3(parent.u ? parent.u.loaded_p50 : null)
    }
    // Scoped to the samples taken under load, so a short burst is not
    // averaged away by the quiet either side of it — which is what the
    // headline 30 s window does to it.
    V3 {
      width: parent.cell
      text: parent.ms3(parent.u ? parent.u.loaded_p95 : null)
      color: parent.u && parent.u.loaded_p95 > 100
        ? tab.panel.warnTone : tab.panel.fg
    }

    N3 { width: parent.cell; text: "while quiet" }
    V3 {
      width: parent.cell
      text: parent.ms3(parent.u ? parent.u.idle_p50 : null)
    }
    V3 { width: parent.cell; text: "\u2014" }
  }

  Text {
    textFormat: Text.PlainText
    visible: !!tab.underLoad && tab.panel.underLoadExpanded
    height: visible ? implicitHeight : 0
    width: parent.width
    wrapMode: Text.WordWrap
    text: tab.underLoadNote
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }
}
