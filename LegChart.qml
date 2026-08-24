pragma ComponentBehavior: Bound

import QtQuick
import qs.Commons

// The two-leg latency chart: local leg as a dim band from the baseline, wan
// leg stacked on top in the accent colour, loss as ticks along the floor.
// Stacking is the point — the top line is the latency you feel, and the
// split says which side of the router owns it.
//
// `points` is an array of {t, local, total, loss} — local/total in ms or
// null, loss 0..1 or null. X is time, so a suspend shows as a gap.
Canvas {
  id: chart

  property var points: []
  property color wanColor: Color.accent
  property color localColor: Color.muted
  property color lossColor: Color.urgent
  property color axisColor: Qt.rgba(Color.popups.text.r, Color.popups.text.g,
                                    Color.popups.text.b, 0.15)
  property real minScaleMs: 20
  // Larger charts label their scale; the compact overview chart stays clean.
  property bool showScale: false
  property string fontFamily: Style.font.family

  readonly property real peakMs: {
    var peak = 0
    for (var i = 0; i < points.length; i++) {
      var p = points[i]
      if (p.total !== null && p.total !== undefined) peak = Math.max(peak, p.total)
    }
    return Math.max(minScaleMs, peak) * 1.08
  }

  onPointsChanged: requestPaint()
  onWidthChanged: requestPaint()
  onHeightChanged: requestPaint()
  onWanColorChanged: requestPaint()

  onPaint: {
    var ctx = getContext("2d")
    ctx.reset()
    ctx.clearRect(0, 0, width, height)

    var top = 2, bottom = height - 1

    ctx.strokeStyle = axisColor
    ctx.lineWidth = 1
    ctx.beginPath()
    ctx.moveTo(0, bottom + 0.5)
    ctx.lineTo(width, bottom + 0.5)
    ctx.stroke()

    if (showScale) {
      // Quarter gridlines plus the top-of-scale label, so a quiet line
      // reads as "3 ms on a 10 ms scale" rather than as an empty box.
      ctx.strokeStyle = Qt.rgba(axisColor.r, axisColor.g, axisColor.b, 0.5)
      for (var g = 1; g <= 3; g++) {
        var gy = Math.round(bottom - (bottom - top) * g / 4) + 0.5
        ctx.beginPath()
        ctx.moveTo(0, gy)
        ctx.lineTo(width, gy)
        ctx.stroke()
      }
      ctx.fillStyle = Qt.rgba(localColor.r, localColor.g, localColor.b, 0.9)
      ctx.font = "10px " + fontFamily
      ctx.textBaseline = "top"
      ctx.fillText(Math.round(peakMs) + " ms", 4, 3)
    }

    var pts = points
    if (!pts || pts.length < 2) return

    var t0 = pts[0].t, t1 = pts[pts.length - 1].t
    var span = Math.max(1, t1 - t0)
    var peak = peakMs

    function xAt(t) { return (t - t0) * (width - 1) / span }
    function yAt(ms) { return bottom - (bottom - top) * Math.max(0, ms) / peak }

    // Runs of consecutive non-null samples paint as separate segments so a
    // gap in the data is a gap on screen, not a line drawn through it.
    function runs(key) {
      var out = [], current = []
      for (var i = 0; i < pts.length; i++) {
        var v = pts[i][key]
        if (v === null || v === undefined) {
          if (current.length > 1) out.push(current)
          current = []
        } else {
          current.push([xAt(pts[i].t), yAt(v)])
        }
      }
      if (current.length > 1) out.push(current)
      return out
    }

    function area(run, tint, alpha) {
      ctx.beginPath()
      ctx.moveTo(run[0][0], bottom)
      for (var i = 0; i < run.length; i++) ctx.lineTo(run[i][0], run[i][1])
      ctx.lineTo(run[run.length - 1][0], bottom)
      ctx.closePath()
      ctx.fillStyle = Qt.rgba(tint.r, tint.g, tint.b, alpha)
      ctx.fill()
    }

    function line(run, tint, w) {
      ctx.beginPath()
      for (var i = 0; i < run.length; i++) {
        if (i === 0) ctx.moveTo(run[i][0], run[i][1])
        else ctx.lineTo(run[i][0], run[i][1])
      }
      ctx.strokeStyle = tint
      ctx.lineWidth = w
      ctx.stroke()
    }

    var i, r
    var totalRuns = runs("total")
    for (i = 0; i < totalRuns.length; i++) {
      r = totalRuns[i]
      area(r, wanColor, 0.20)
      line(r, wanColor, 1.5)
    }
    var localRuns = runs("local")
    for (i = 0; i < localRuns.length; i++) {
      r = localRuns[i]
      area(r, localColor, 0.5)
      line(r, localColor, 1)
    }

    ctx.fillStyle = lossColor
    for (i = 0; i < pts.length; i++) {
      if (pts[i].loss !== null && pts[i].loss !== undefined && pts[i].loss > 0)
        ctx.fillRect(xAt(pts[i].t) - 1, bottom - 8, 2, 8)
    }
  }
}
