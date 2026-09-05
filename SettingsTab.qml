pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons
import qs.Ui

// The four settings worth reaching without leaving the panel, and an honest
// pointer to the rest.
//
// Why this tab exists: Omarchy has no settings editor. Setup > Plugins
// enables, disables, adds, clones and removes — nothing anywhere edits a
// widget's own settings, and the shell keeps them inline on the bar entry in
// shell.json. So every option this plugin has was, until now, reachable only
// by hand-editing that file. Thirteen settings nobody can find is worse than
// four they can.
//
// Only booleans are here. An enum or a number needs a picker and a keyboard,
// and a half-built editor in a monitoring panel would be worse than sending
// someone to the file that already works.
Column {
  id: tab

  required property var panel
  readonly property var live: panel.live

  spacing: Style.space(12)

  // Writing goes through the host: the shell owns shell.json and rewrites the
  // whole entry, so a setting is changed by handing back the entry with one
  // field replaced. Absent that API — an older shell — the toggles stay
  // visible but inert, and the note below says so rather than failing
  // silently on a tap.
  readonly property bool canWrite: !!(panel.bar && panel.bar.shell
    && typeof panel.bar.shell.updateEntryInline === "function")

  function put(key, value) {
    if (!canWrite) return
    var id = "io.github.x3me.nexthop"
    var s = panel.settings
    // The shell REPLACES the entry with what it is handed, so writing from
    // an absent settings object would hand back {id, key} and drop every
    // other setting the user has. Better to do nothing than to do that.
    if (!s || typeof s !== "object") return
    var entry = { "id": id }
    for (var k in s) if (k !== "id") entry[k] = s[k]
    entry[key] = value
    panel.bar.shell.updateEntryInline(id, entry)
  }

  Text {
    textFormat: Text.PlainText
    text: "WHAT NEXTHOP MAY DO"
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    font.letterSpacing: 1
  }

  // One row per toggle: name and one line of consequence on the left, the
  // switch on the right. The consequence line is the point — a toggle whose
  // effect you have to guess is not a setting, it is a dare.
  component Row_: Item {
    id: row
    required property string label
    required property string detail
    required property bool value
    required property string settingKey

    width: parent.width
    height: Math.max(texts.implicitHeight, sw.implicitHeight)

    Column {
      id: texts
      width: parent.width - sw.width - Style.space(14)
      spacing: Style.space(2)
      anchors.verticalCenter: parent.verticalCenter

      Text {
        textFormat: Text.PlainText
        text: row.label
        color: tab.panel.fg
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        textFormat: Text.PlainText
        width: parent.width
        wrapMode: Text.WordWrap
        text: row.detail
        color: tab.panel.dim
        font.family: tab.panel.fontFamily
        font.pixelSize: Style.font.caption
      }
    }

    ToggleSwitch {
      id: sw
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      checked: row.value
      interactive: tab.canWrite
      foreground: tab.panel.fg
      onToggled: tab.put(row.settingKey, !row.value)
    }
  }

  Row_ {
    label: "Go easy on phone hotspots"
    detail: "When the connection comes from a phone, pause the hourly speed "
      + "checks and ask twice before a full test. About 14 MB an hour of "
      + "someone's data plan."
    value: tab.panel.setting("meteredCare", true)
    settingKey: "meteredCare"
  }

  PanelSeparator { width: parent.width }

  Row_ {
    label: "Measure speed automatically"
    detail: "A small download every hour so the Speed score means something. "
      + "Off, Speed goes blank rather than guessing."
    value: tab.panel.setting("contentSpeed", true)
    settingKey: "contentSpeed"
  }

  PanelSeparator { width: parent.width }

  Row_ {
    label: "Notify on outages"
    detail: "A desktop notification when the connection drops and when it "
      + "returns. Brief interruptions are logged either way and never "
      + "notified."
    value: tab.panel.setting("notifyOutage", true)
    settingKey: "notifyOutage"
  }

  PanelSeparator { width: parent.width }

  Row_ {
    label: "Tell me about updates"
    detail: "Once a day, asks the repository you installed from whether a "
      + "newer version exists. Sends nothing about you, and installs nothing."
    value: tab.panel.setting("updateCheck", true)
    settingKey: "updateCheck"
  }

  PanelSeparator { width: parent.width }

  Text {
    textFormat: Text.PlainText
    text: "EVERYTHING ELSE"
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
    font.letterSpacing: 1
  }

  // The honest part. Nine more settings exist and this panel is not the
  // place to build a form for them, so say plainly where they live and what
  // they are, rather than pretending these four are all there is.
  Text {
    textFormat: Text.PlainText
    width: parent.width
    wrapMode: Text.WordWrap
    text: tab.canWrite
      ? "Nine more settings live on this widget's entry in "
        + "~/.config/omarchy/shell.json — what the bar shows, the internet "
        + "anchor, probe interval, check frequency, speed-test engine, your "
        + "plan speeds, throughput smoothing, and how long history is kept. "
        + "Add them beside \"id\" and they apply without a restart."
      : "This shell cannot write widget settings back, so the switches above "
        + "are read-only. Edit this widget's entry in "
        + "~/.config/omarchy/shell.json instead; changes apply without a "
        + "restart."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    wrapMode: Text.WordWrap
    text: "Defaults are sensible and nothing here needs changing to use it."
    color: tab.panel.dim
    font.family: tab.panel.fontFamily
    font.pixelSize: Style.font.caption
  }
}
