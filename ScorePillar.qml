import QtQuick
import qs.Commons

// One of the three component scores: label, number, meter, one-line note.
Column {
  id: root

  property string label: ""
  property var value: null       // 0-100 or null
  property string note: ""
  property color textColor: Color.popups.text
  property color dimColor: Color.muted

  readonly property color tone: {
    if (value === null || value === undefined) return dimColor
    if (value >= 80) return "#9ece6a"
    if (value >= 50) return "#e0af68"
    return Color.urgent
  }

  spacing: Style.space(5)

  Text {
    textFormat: Text.PlainText
    text: root.label
    color: root.dimColor
    font.family: Style.font.family
    font.pixelSize: Style.font.caption
    font.letterSpacing: 1
  }

  Text {
    textFormat: Text.PlainText
    text: root.value === null || root.value === undefined
      ? "--" : String(Math.round(root.value))
    color: root.tone
    font.family: Style.font.family
    font.pixelSize: Style.fontPx(1.8)
    font.weight: Font.Bold
  }

  Rectangle {
    width: parent.width
    height: Math.max(2, Style.space(3))
    color: Qt.rgba(root.textColor.r, root.textColor.g, root.textColor.b, 0.12)

    Rectangle {
      height: parent.height
      width: parent.width * (root.value === null || root.value === undefined
        ? 0 : Math.max(0, Math.min(1, root.value / 100)))
      color: root.tone
      Behavior on width { NumberAnimation { duration: 300; easing.type: Easing.OutCubic } }
    }
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: root.note
    color: root.dimColor
    font.family: Style.font.family
    font.pixelSize: Style.font.caption
    elide: Text.ElideRight
  }
}
