pragma ComponentBehavior: Bound

import QtQuick
import Quickshell.Io
import qs.Commons
import qs.Ui

// What happened: outages and disruptions with durations and the leg named,
// plus the copy-report affordance — the ISP-ticket artifact.
Column {
  id: tab

  required property var panel

  spacing: Style.space(12)

  Component.onCompleted: {
    panel.requestEvents("24h")
    ribbonProc.command = ["sh", "-c",
      "cd \"$1\" && exec python3 -m nexthopd.cli query --window 24h --resolution minute",
      "sh", panel.pluginDir]
    ribbonProc.running = true
    weekProc.command = ["sh", "-c",
      "cd \"$1\" && exec python3 -m nexthopd.cli query --window 7d",
      "sh", panel.pluginDir]
    weekProc.running = true
  }

  property var ribbonRows: []
  property var weekDays: []

  Process {
    id: ribbonProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var d = JSON.parse(text)
          tab.ribbonRows = d.rows || []
        } catch (e) {}
      }
    }
  }

  Process {
    id: weekProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var d = JSON.parse(text)
          tab.weekDays = tab.foldDays(d.rows || [])
        } catch (e) {}
      }
    }
  }

  // Hourly rows -> trailing seven local days, averaged experience each.
  function foldDays(rows) {
    var byDay = {}
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i]
      if (r.idx === null || r.idx === undefined) continue
      var d = new Date(r.ts * 1000)
      var key = d.getFullYear() * 10000 + (d.getMonth() + 1) * 100 + d.getDate()
      var slot = byDay[key] || (byDay[key] = { sum: 0, n: 0, ts: r.ts })
      slot.sum += r.idx
      slot.n += 1
    }
    var out = []
    var names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    for (var day = 6; day >= 0; day--) {
      var when = new Date(Date.now() - day * 86400 * 1000)
      var k = when.getFullYear() * 10000 + (when.getMonth() + 1) * 100 + when.getDate()
      var s = byDay[k]
      out.push({
        name: names[when.getDay()],
        idx: s ? Math.round(s.sum / s.n) : null,
      })
    }
    return out
  }

  function bandColor(idx) {
    if (idx === null || idx === undefined)
      return Qt.rgba(tab.panel.fg.r, tab.panel.fg.g, tab.panel.fg.b, 0.08)
    if (idx >= 90) return "#9ece6a"
    if (idx >= 80) return "#b9f27c"
    if (idx >= 70) return "#e0af68"
    if (idx >= 50) return "#eb927b"
    return "#f7768e"
  }

  readonly property var events: panel.eventsData && panel.eventsData.events
    ? panel.eventsData.events : []

  // Consecutive events of the same kind, this close together, are one
  // episode rather than several: a laptop bouncing between two access
  // points is a single story, and listing each hop separately buries the
  // outages that actually matter under a wall of roams.
  readonly property int episodeGapS: 600
  // Beyond this the list stops being readable and the report is the right
  // tool. Nothing is discarded — the count of what is not shown is stated.
  readonly property int maxRows: 12

  readonly property var episodes: foldEvents(events)
  readonly property var shownEpisodes: episodes.slice(0, maxRows)
  readonly property int hiddenEvents: {
    var n = 0
    for (var i = maxRows; i < episodes.length; i++) n += episodes[i].count
    return n
  }

  // Outages and associations are never folded: each one is its own fact.
  function groupable(kind) {
    return kind === "roam" || kind === "kick" || kind === "drop"
      || kind === "rate-drop" || kind === "disruption"
      || kind === "icmp-quiet"
  }

  function foldEvents(list) {
    var out = []
    for (var i = 0; i < list.length; i++) {
      var e = list[i]
      var g = out.length ? out[out.length - 1] : null
      if (g && g.kind === e.kind && groupable(e.kind)
          && (g.oldestTs - e.ts) <= episodeGapS) {
        g.count += 1
        g.oldestTs = e.ts
        g.members.push(e)
      } else {
        out.push({kind: e.kind, ts: e.ts, oldestTs: e.ts,
                  count: 1, members: [e], first: e})
      }
    }
    return out
  }

  // The first four octets are the same across every access point on one
  // site, so they carry no information — only the last two identify which
  // radio this was. The stored event keeps the full address for the report.
  function shortMac(text) {
    return String(text).replace(
      /\b(?:[0-9a-fA-F]{2}:){4}([0-9a-fA-F]{2}:[0-9a-fA-F]{2})\b/g, "…$1")
  }

  function roamTargets(members) {
    var seen = []
    for (var i = 0; i < members.length; i++) {
      var m = /Roamed to ([0-9a-fA-F:]{17})/.exec(members[i].detail || "")
      if (!m) continue
      var short = shortMac(m[1])
      if (seen.indexOf(short) < 0) seen.push(short)
    }
    return seen
  }

  // Which access points did the kicking, and every distinct reason given.
  function kickSources(members) {
    var aps = [], whys = []
    for (var i = 0; i < members.length; i++) {
      var m = /Kicked by AP ([0-9a-fA-F:]{17}) \((reason [^)]*)\)/
        .exec(members[i].detail || "")
      if (!m) continue
      var short = shortMac(m[1])
      if (aps.indexOf(short) < 0) aps.push(short)
      if (whys.indexOf(m[2]) < 0) whys.push(m[2])
    }
    return {aps: aps, why: whys.length ? whys.join("; ") : null}
  }

  function lowestRate(members) {
    var low = null
    for (var i = 0; i < members.length; i++) {
      var m = /dropped to (\d+)/.exec(members[i].detail || "")
      if (m && (low === null || Number(m[1]) < low)) low = Number(m[1])
    }
    return low
  }

  function describeEpisode(g) {
    if (g.count === 1) return describe(g.first)
    if (g.kind === "roam") {
      var aps = roamTargets(g.members)
      return "Roamed " + g.count + "×"
        + (aps.length > 1 ? " between " + aps.join(" ↔ ")
           : aps.length === 1 ? " to " + aps[0] : "")
    }
    if (g.kind === "kick") {
      var k = kickSources(g.members)
      return "Kicked by AP " + g.count + "\u00d7"
        + (k.aps.length ? " \u2014 " + k.aps.join(", ") : "")
        + (k.why ? " (" + k.why + ")" : "")
    }
    if (g.kind === "drop")
      return "Dropped by this machine " + g.count + "\u00d7"
    if (g.kind === "rate-drop") {
      var low = lowestRate(g.members)
      return "Tx rate dropped " + g.count + "×"
        + (low !== null ? ", lowest " + low + " Mbps" : "")
    }
    return describe(g.first) + " · " + g.count + "×"
  }

  // A folded episode reports how long it went on; a single event reports
  // its own duration, which for an instant event is nothing.
  function episodeDuration(g) {
    if (g.count === 1) return duration(g.first)
    var s = g.ts - g.oldestTs
    if (s < 60) return s + "s"
    if (s < 3600) return Math.floor(s / 60) + "m"
    return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m"
  }

  property bool copied: false

  function describe(e) {
    if (e.kind === "outage" && e.leg === "wan")
      return "No internet. The router still answered, so the fault was upstream."
    if (e.kind === "outage" && e.leg === "local")
      return "Router unreachable — nothing on the local network answered."
    return shortMac(e.detail || e.kind)
  }

  function duration(e) {
    if (e.ended_ts === e.ts) return "\u2014"
    if (!e.ended_ts) return "ongoing"
    var s = e.ended_ts - e.ts
    if (s < 60) return s + "s"
    if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s"
    return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m"
  }

  Item {
    width: parent.width
    height: ribbonLabel.implicitHeight

    Text {
      id: ribbonLabel
      textFormat: Text.PlainText
      text: "EXPERIENCE, LAST 24 HOURS"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: "1-minute buckets"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Canvas {
    id: ribbon
    width: parent.width
    height: Style.space(22)

    readonly property var rows: tab.ribbonRows
    onRowsChanged: requestPaint()
    onWidthChanged: requestPaint()

    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      ctx.clearRect(0, 0, width, height)
      // The unmonitored floor: minutes with no data stay this dark strip.
      ctx.fillStyle = Qt.rgba(tab.panel.fg.r, tab.panel.fg.g,
                              tab.panel.fg.b, 0.06)
      ctx.fillRect(0, 0, width, height)
      var start = Date.now() / 1000 - 86400
      var slice = width / 1440
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i]
        if (r.idx === null || r.idx === undefined) continue
        var x = (r.ts - start) / 86400 * width
        if (x < 0 || x > width) continue
        ctx.fillStyle = tab.bandColor(r.idx)
        ctx.fillRect(x, 0, Math.max(1, slice + 0.5), height)
      }
    }
  }

  Item {
    width: parent.width
    height: axisLeft.implicitHeight

    Text {
      id: axisLeft
      textFormat: Text.PlainText
      text: {
        var d = new Date(Date.now() - 86400 * 1000)
        return d.toLocaleString(Qt.locale(), "HH:mm") + " yest."
      }
      color: Qt.darker(tab.panel.dim, 1.2)
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.fontPx(0.75)
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: "now"
      color: Qt.darker(tab.panel.dim, 1.2)
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.fontPx(0.75)
    }
  }

  Row {
    spacing: Style.space(12)

    component BandKey: Row {
      property color tint: "white"
      property string label: ""
      spacing: Style.space(5)
      Rectangle {
        width: Style.space(8); height: Style.space(8)
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

    BandKey { tint: "#9ece6a"; label: "90+" }
    BandKey { tint: "#b9f27c"; label: "80" }
    BandKey { tint: "#e0af68"; label: "70" }
    BandKey { tint: "#eb927b"; label: "50" }
    BandKey { tint: "#f7768e"; label: "under 50" }
  }

  PanelSeparator { width: parent.width }

  Text {
    textFormat: Text.PlainText
    text: "LAST 7 DAYS"
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    font.letterSpacing: 1
  }

  Row {
    width: parent.width
    spacing: Style.space(8)
    readonly property real cell: (width - Style.space(8) * 6) / 7

    Repeater {
      model: tab.weekDays

      Column {
        id: dayCol
        required property var modelData
        width: parent.cell
        spacing: Style.space(4)

        Text {
          textFormat: Text.PlainText
          anchors.horizontalCenter: parent.horizontalCenter
          text: dayCol.modelData.idx === null ? "·" : String(dayCol.modelData.idx)
          color: dayCol.modelData.idx === null
            ? tab.panel.dim : tab.panel.fg
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
        }
        Rectangle {
          width: parent.width
          height: Style.space(30)
          color: Qt.rgba(tab.panel.fg.r, tab.panel.fg.g, tab.panel.fg.b, 0.07)

          Rectangle {
            anchors.bottom: parent.bottom
            width: parent.width
            height: dayCol.modelData.idx === null
              ? 0 : parent.height * Math.max(0.08, dayCol.modelData.idx / 100)
            color: tab.bandColor(dayCol.modelData.idx)
          }
        }
        Text {
          textFormat: Text.PlainText
          anchors.horizontalCenter: parent.horizontalCenter
          text: dayCol.modelData.name
          color: Qt.darker(tab.panel.dim, 1.2)
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.fontPx(0.75)
        }
      }
    }
  }

  PanelSeparator { width: parent.width }

  Item {
    width: parent.width
    height: eventsLabel.implicitHeight

    Text {
      id: eventsLabel
      textFormat: Text.PlainText
      text: "WHAT HAPPENED · LAST 24 H"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: tab.events.length === 0 ? "" :
        tab.events.length + (tab.events.length === 1 ? " event" : " events")
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: tab.events.length === 0
    text: "Nothing to report. A quiet log is the good outcome."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  Column {
    width: parent.width
    spacing: Style.space(9)

    Repeater {
      model: tab.shownEpisodes

      Row {
        id: eventRow
        required property var modelData
        width: parent.width
        spacing: Style.space(10)

        readonly property color tone: {
          var k = modelData.kind
          if (k === "outage") return Color.urgent
          if (k === "disruption" || k === "rate-drop"
              || k === "icmp-quiet") return tab.panel.warnTone
          if (k === "roam") return "#bb9af7"
          if (k === "kick" || k === "drop") return tab.panel.warnTone
          if (k === "associate") return tab.panel.okTone
          return Color.accent
        }

        Text {
          textFormat: Text.PlainText
          width: Style.space(64)
          text: {
            var d = new Date(eventRow.modelData.ts * 1000)
            return d.toLocaleString(Qt.locale(), "ddd HH:mm")
          }
          color: tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
        }

        Rectangle {
          width: Style.space(5)
          height: Style.space(5)
          color: eventRow.tone
          anchors.verticalCenter: parent.verticalCenter
        }

        Text {
          textFormat: Text.PlainText
          width: parent.width - Style.space(64) - Style.space(5)
            - Style.space(54) - Style.space(10) * 3
          text: tab.describeEpisode(eventRow.modelData)
          color: tab.panel.fg
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        Text {
          textFormat: Text.PlainText
          width: Style.space(54)
          horizontalAlignment: Text.AlignRight
          text: tab.episodeDuration(eventRow.modelData)
          color: eventRow.modelData.count === 1 && !eventRow.modelData.first.ended_ts
            ? Color.urgent : tab.panel.dim
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
  }

  Text {
    width: parent.width
    visible: tab.hiddenEvents > 0
    textFormat: Text.PlainText
    text: "+ " + tab.hiddenEvents + " earlier "
      + (tab.hiddenEvents === 1 ? "event" : "events")
      + " — the copied report has the full list."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  PanelSeparator { width: parent.width }

  Item {
    width: parent.width
    height: Math.max(copyHint.implicitHeight, copyButton.height)

    Text {
      id: copyHint
      textFormat: Text.PlainText
      width: parent.width - copyButton.width - Style.space(12)
      anchors.verticalCenter: parent.verticalCenter
      text: "Copies a plain-text summary of the last 24 hours — timestamps, "
        + "both legs, loss and events. The thing an ISP asks for."
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }

    Rectangle {
      id: copyButton
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      width: copyText.implicitWidth + Style.space(24)
      height: Style.space(28)
      color: copyHover.hovered
        ? Style.hoverFillFor(tab.panel.fg, Color.accent)
        : Style.normalFillFor(tab.panel.fg, Color.accent)
      border.width: Style.normalBorderWidth
      border.color: Style.normalBorderFor(tab.panel.fg, Color.accent)

      Text {
        id: copyText
        textFormat: Text.PlainText
        anchors.centerIn: parent
        text: tab.copied ? "󰄬 Copied" : "󰆏 Copy report"
        color: tab.panel.fg
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      HoverHandler { id: copyHover }
      TapHandler {
        onTapped: {
          tab.panel.copyReport("24h")
          tab.copied = true
          copiedReset.restart()
        }
      }
      Timer {
        id: copiedReset
        interval: 2000
        onTriggered: tab.copied = false
      }
    }
  }
}
