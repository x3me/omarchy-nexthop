pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui

// What happened: outages and disruptions with durations and the leg named,
// plus the copy-report affordance — the ISP-ticket artifact.
Column {
  id: tab

  required property var panel

  spacing: Style.space(12)

  Component.onCompleted: panel.requestEvents("7d")

  readonly property var events: panel.eventsData && panel.eventsData.events
    ? panel.eventsData.events : []

  property bool copied: false

  function describe(e) {
    if (e.kind === "outage" && e.leg === "wan")
      return "No internet. The router still answered, so the fault was upstream."
    if (e.kind === "outage" && e.leg === "local")
      return "Router unreachable — nothing on the local network answered."
    return e.detail || e.kind
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
    height: eventsLabel.implicitHeight

    Text {
      id: eventsLabel
      textFormat: Text.PlainText
      text: "WHAT HAPPENED · LAST 7 DAYS"
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
      model: tab.events

      Row {
        id: eventRow
        required property var modelData
        width: parent.width
        spacing: Style.space(10)

        readonly property color tone: {
          var k = modelData.kind
          if (k === "outage") return Color.urgent
          if (k === "disruption" || k === "rate-drop") return tab.panel.warnTone
          if (k === "roam") return "#bb9af7"
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
          text: tab.describe(eventRow.modelData)
          color: tab.panel.fg
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        Text {
          textFormat: Text.PlainText
          width: Style.space(54)
          horizontalAlignment: Text.AlignRight
          text: tab.duration(eventRow.modelData)
          color: eventRow.modelData.ended_ts ? tab.panel.dim : Color.urgent
          font.family: tab.panel.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
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
