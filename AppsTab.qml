pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui
import "format.js" as Fmt

// Who is using the connection: top applications by TCP traffic, with an
// honest bucket for what no unprivileged tool can attribute (QUIC/UDP,
// protocol overhead). Rates are the last few seconds; totals are since the
// daemon started.
Column {
  id: tab

  required property var panel

  spacing: Style.space(12)

  readonly property var apps: panel.appsData && panel.appsData.apps
    ? panel.appsData.apps : []
  readonly property var other: panel.appsData ? panel.appsData.other : null


  Item {
    width: parent.width
    height: appsLabel.implicitHeight

    Text {
      id: appsLabel
      textFormat: Text.PlainText
      text: "TOP APPLICATIONS · TCP"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.letterSpacing: 1
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: "totals since the daemon started"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: tab.apps.length === 0
    text: "Collecting — the first sample lands within a few seconds."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  Column {
    width: parent.width
    spacing: Style.space(10)

    Repeater {
      model: tab.apps

      Column {
        id: appRow
        required property var modelData
        width: parent.width
        spacing: Style.space(4)

        Item {
          width: parent.width
          height: nameText.implicitHeight

          Text {
            id: nameText
            textFormat: Text.PlainText
            text: appRow.modelData.name
              + (appRow.modelData.conns > 0
                 ? "  ·  " + appRow.modelData.conns
                   + (appRow.modelData.conns === 1 ? " conn" : " conns")
                 : "")
              // The kernel's round trip for this app's own sockets. Absent
              // for an app the kernel has not timed — QUIC-only traffic
              // shows no figure rather than a misleading zero.
              + (appRow.modelData.rtt_ms
                 ? "  ·  " + appRow.modelData.rtt_ms.toFixed(0) + " ms"
                 : "")
            color: tab.panel.fg
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
          Text {
            textFormat: Text.PlainText
            anchors.right: parent.right
            text: "󰇚 " + Fmt.rate(appRow.modelData.rx_bps)
              + "   󰕒 " + Fmt.rate(appRow.modelData.tx_bps)
            color: tab.panel.dim
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        // Second row: the last minute as a half-width strip of stacked
        // mini-bars (download in accent, upload above in amber, newest on
        // the right, scaled to this app's own busiest moment) with the
        // session totals beside it.
        Item {
          width: parent.width
          height: Math.max(strip.height, sessionText.implicitHeight)

          Row {
            id: strip
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            width: Math.round(parent.width * 0.5)
            height: Style.space(9)
            spacing: Math.max(1, Style.spaceReal(1.5))

            readonly property var hist: appRow.modelData.hist || []
            readonly property int slots: 20
            readonly property real slotW:
              (width - spacing * (slots - 1)) / slots
            readonly property real peak: {
              var p = 1024
              for (var i = 0; i < hist.length; i++)
                p = Math.max(p, hist[i][0] + hist[i][1])
              return p
            }

            Repeater {
              model: strip.slots

              Item {
                id: histSlot
                required property int index
                readonly property var sample: {
                  var h = strip.hist
                  var i = h.length - strip.slots + index
                  return i >= 0 && i < h.length ? h[i] : null
                }
                width: strip.slotW
                height: strip.height

                Rectangle {
                  anchors.bottom: parent.bottom
                  width: parent.width
                  height: 1
                  color: Qt.rgba(tab.panel.fg.r, tab.panel.fg.g,
                                 tab.panel.fg.b, 0.12)
                }
                Rectangle {
                  id: rxSeg
                  anchors.bottom: parent.bottom
                  width: parent.width
                  height: histSlot.sample
                    ? Math.min(parent.height,
                        parent.height * histSlot.sample[0] / strip.peak)
                    : 0
                  color: Color.accent
                }
                Rectangle {
                  anchors.bottom: rxSeg.top
                  width: parent.width
                  height: histSlot.sample
                    ? Math.min(parent.height - rxSeg.height,
                        parent.height * histSlot.sample[1] / strip.peak)
                    : 0
                  color: tab.panel.warnTone
                }
              }
            }
          }

          Text {
            id: sessionText
            textFormat: Text.PlainText
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: Fmt.bytes(appRow.modelData.rx_total)
              + " down · " + Fmt.bytes(appRow.modelData.tx_total) + " up"
            color: tab.panel.dim
            font.family: tab.panel.fontFamily
            font.pixelSize: Style.font.caption
          }
        }
      }
    }
  }

  PanelSeparator {
    width: parent.width
    visible: tab.other !== null
  }

  Item {
    width: parent.width
    visible: tab.other !== null
    height: otherText.implicitHeight

    Text {
      id: otherText
      textFormat: Text.PlainText
      text: "Unattributed (QUIC, UDP, overhead)"
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
    Text {
      textFormat: Text.PlainText
      anchors.right: parent.right
      text: tab.other
        ? "󰇚 " + Fmt.rate(tab.other.rx_bps) + "   󰕒 " + Fmt.rate(tab.other.tx_bps)
        : ""
      color: tab.panel.dim
      font.family: tab.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: "Per-app numbers come from each TCP connection's own counters — no "
      + "packet capture, no root. QUIC (much of Chrome and YouTube) is UDP, "
      + "which Linux only attributes to privileged tools; it shows above as "
      + "unattributed instead of pretending the TCP list is everything."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }
}
