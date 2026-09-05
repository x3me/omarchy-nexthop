// The hover readout box shared by every chart that has one.
//
// This existed three times — LegChart, SpeedTab, WifiTab — as the same ten
// lines copied around, which is how two of them got centred correctly in
// 0.2.6 and the third kept drawing its text against the bottom border. One
// copy means the next chart cannot inherit the old bug.
//
// Centring, since it took measuring to get right: the box runs y=2..18 so
// its centre is 10, but a "middle" baseline centres the EM box, and these
// labels are digits and lower-case with no descenders, so their ink rides
// high inside it. Placing the alphabetic baseline half a cap height below
// the box centre centres the ink itself. Verified by reading the pixel rows
// of a screenshot: four rows of clearance above the glyphs and four below.

// Cap height of the 10 px label font. JetBrains Mono is ~0.73 em; anything
// in that neighbourhood lands within a pixel, which is the resolution that
// matters in a 16 px box.
var CAP_HEIGHT = 7.3
var BOX_TOP = 2
var BOX_HEIGHT = 16
var PAD_X = 6

/**
 * Draw the readout centred on `cx`, kept inside `canvasWidth`.
 * `fg` and `bg` are colour values; the border is fg at low alpha.
 */
function draw(ctx, fontFamily, label, cx, canvasWidth, fg, bg) {
    ctx.font = "10px " + fontFamily
    var w = ctx.measureText(label).width + PAD_X * 2
    var bx = Math.max(2, Math.min(canvasWidth - w - 2, cx - w / 2))

    ctx.fillStyle = Qt.rgba(bg.r, bg.g, bg.b, 0.92)
    ctx.fillRect(bx, BOX_TOP, w, BOX_HEIGHT)
    ctx.strokeStyle = Qt.rgba(fg.r, fg.g, fg.b, 0.25)
    ctx.strokeRect(bx + 0.5, BOX_TOP + 0.5, w - 1, BOX_HEIGHT - 1)

    ctx.fillStyle = fg
    ctx.textBaseline = "alphabetic"
    ctx.fillText(label, bx + PAD_X,
                 BOX_TOP + BOX_HEIGHT / 2 + CAP_HEIGHT / 2)
    return bx
}
