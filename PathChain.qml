import QtQuick
import qs.Commons

// laptop — router — internet, with per-leg latency on the connecting lines.
// The answer to "is it me or is it them", drawn rather than written.
Item {
  id: root

  property var live: null
  // What the wan probe actually pings — the honest label for the far node.
  property string anchor: ""
  property color textColor: Color.popups.text
  property color dimColor: Color.muted

  readonly property var localMs: live && live.local ? live.local.p50 : null
  readonly property var wanMs: live && live.wan ? live.wan.p50 : null
  readonly property bool localDown: live && live.state === "local-down"
  readonly property bool wanDown: live && live.state === "wan-down"

  // The address this connection appears from, published by the daemon.
  // Shown masked: Overview screenshots end up on forums, and a screenshot
  // must not carry the poster's IP. Tapping the node reveals it; the
  // reveal is never persisted anywhere.
  readonly property var wanIp: live && live.wan_ip ? live.wan_ip : null
  readonly property int probeCount: {
    if (!live || !live.instruments) return 0
    var n = 0
    for (var i = 0; i < live.instruments.length; i++)
      if (live.instruments[i].active) n += 1
    return n
  }
  property bool revealIp: false

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

  implicitHeight: row.implicitHeight

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
      Rectangle {
        width: parent.width - Style.space(12)
        anchors.horizontalCenter: parent.horizontalCenter
        height: 2
        color: root.legColor(parent.ms, parent.down)
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
    }
    Node {
      icon: "󰑩"   // nf-md-router_wireless
      title: "Router"
      detail: root.live && root.live.link ? (root.live.link.gateway || "") : ""
    }
    Leg {
      ms: root.wanMs
      down: root.wanDown
      label: "WAN"
    }
    Node {
      icon: "󰖟"   // nf-md-web
      title: "Internet"
      // Your address out there, not the probe target: with a bench of
      // instruments there is no single anchor to name, and naming one
      // read as "this monitors Cloudflare". Masked — screenshots end up
      // on forums; tap to reveal, never persisted.
      detail: root.wanIp ? root.maskedIp(root.wanIp) : root.anchor

      Text {
        textFormat: Text.PlainText
        visible: root.probeCount > 0
        text: root.probeCount === 1 ? "1 probe live" : root.probeCount + " probes live"
        color: root.dimColor
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
      }
      TapHandler { onTapped: root.revealIp = !root.revealIp }
    }
  }
}
