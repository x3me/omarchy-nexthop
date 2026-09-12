// The recent history drawn into the path connectors on the Overview.
//
// The two lines between the nodes were flat 2 px bars coloured by the current
// value. They already occupied this space, so showing three minutes of each
// leg there costs no new row — the constraint that decides most of this
// panel's layout.
//
// What this file owns is slot derivation and the paint. It owns no arithmetic
// about the legs: the ISP leg is subtracted in the daemon (`score.wan_point_ms`)
// and arrives per point, because the rule that matters there is the one that
// REFUSES to answer when a gateway reads slower than the internet behind it,
// and a second copy of a refusal is the copy that forgets. Colours come in as
// a function so `PathChain.legColor` stays the only place thresholds live.
//
// No `.pragma library`: it would drop the QML context and `Qt.rgba` with it.

// 36 slots of 5 s is three minutes. recent.json holds 360 of them, but the
// Latency tab already draws the whole half hour; a second long window here
// would be the same chart twice. Three minutes is what changes while you
// watch, which is the point of putting it here.
var SLOTS = 36;

// Both legs share one zero-based scale at least this tall, so a wobble on a
// 2 ms local leg cannot be drawn larger than a slower WAN. The cost is that a
// fast local leg is a flat line near the floor. That is honest: it IS flat.
var SCALE_FLOOR_MS = 50;

var PAD_TOP = 3;
var DOWN_BAND = 4;

/**
 * One leg's last `n` slots, newest last.
 *
 * Three outcomes, and keeping them apart is the whole job:
 *   {v: ms}      measured
 *   {down: true} probes went out and nothing came back
 *   null         nothing to say — no probe was sent, or the figure is withheld
 *
 * `loss === null` is the daemon's way of saying it sampled nothing in that
 * bucket, which is a gap rather than an outage. A bucket that sampled and got
 * no reply carries a loss figure with no `total`, and that is down.
 */
function slots(points, key, n) {
    var out = [];
    var pts = points || [];
    var from = Math.max(0, pts.length - (n || SLOTS));
    for (var i = from; i < pts.length; i++) {
        var p = pts[i];
        if (!p || p.loss === null || p.loss === undefined) { out.push(null); continue; }
        if (key === "local") {
            // The router itself did not answer.
            if (p.local === null || p.local === undefined) { out.push({ down: true }); continue; }
            out.push({ v: p.local });
            continue;
        }
        // Nothing beyond the router answered at all.
        if (p.total === null || p.total === undefined) { out.push({ down: true }); continue; }
        // It answered, but the subtraction was withheld — unknown, not zero,
        // and certainly not an outage.
        if (p.wan === null || p.wan === undefined) { out.push(null); continue; }
        out.push({ v: p.wan });
    }
    while (out.length < (n || SLOTS)) out.unshift(null);
    return out;
}

/** The tallest measured value across every leg, floored. */
function sharedMax(seriesList, floor) {
    var m = floor === undefined ? SCALE_FLOOR_MS : floor;
    for (var i = 0; i < seriesList.length; i++) {
        var s = seriesList[i] || [];
        for (var j = 0; j < s.length; j++) {
            if (s[j] && !s[j].down && s[j].v > m) m = s[j].v;
        }
    }
    return m;
}

/** The newest slot that carries anything at all, or -1. */
function newestIndex(series) {
    for (var i = series.length - 1; i >= 0; i--) if (series[i]) return i;
    return -1;
}

/**
 * Paint one leg.
 *
 * `opts`: { max, phase, live, motion, colorFor, downColor, dimColor }
 * `phase` runs 0..1 and drives the ring; `colorFor(ms, down)` is the panel's
 * own `legColor`, passed in rather than reimplemented.
 */
function draw(ctx, w, h, series, opts) {
    ctx.clearRect(0, 0, w, h);
    if (!series || series.length === 0 || w <= 0 || h <= 0) return;

    var plotH = h - PAD_TOP - DOWN_BAND;
    var max = opts.max || SCALE_FLOOR_MS;
    var step = series.length > 1 ? w / (series.length - 1) : w;
    var downY = h - 1.5;

    function yOf(v) { return PAD_TOP + plotH - (Math.min(v, max) / max) * plotH; }

    // The measured line, cut at every gap so nothing is ever drawn across one.
    var run = [];
    function flushLine() {
        if (run.length > 1) {
            ctx.beginPath();
            for (var i = 0; i < run.length; i++) {
                if (i === 0) ctx.moveTo(run[i].x, run[i].y);
                else ctx.lineTo(run[i].x, run[i].y);
            }
            ctx.strokeStyle = run[run.length - 1].c;
            ctx.lineWidth = 1.5;
            ctx.lineJoin = "round";
            ctx.lineCap = "round";
            ctx.stroke();
        } else if (run.length === 1) {
            ctx.fillStyle = run[0].c;
            ctx.fillRect(run[0].x - 0.75, run[0].y - 0.75, 1.5, 1.5);
        }
        run = [];
    }

    // A run of down slots is ONE outage, so it is one bar along the bottom
    // rather than a row of ticks: its length is the duration.
    var downRun = null;
    function flushDown() {
        if (!downRun) return;
        ctx.fillStyle = opts.downColor;
        ctx.fillRect(downRun.x0 - 1, downY - 1.5,
                     Math.max(2, downRun.x1 - downRun.x0 + 2), 3);
        downRun = null;
    }

    for (var i = 0; i < series.length; i++) {
        var p = series[i], x = i * step;
        if (!p) { flushLine(); flushDown(); continue; }
        if (p.down) {
            flushLine();
            if (downRun) downRun.x1 = x; else downRun = { x0: x, x1: x };
            continue;
        }
        flushDown();
        run.push({ x: x, y: yOf(p.v), c: opts.colorFor(p.v, false) });
    }
    flushLine();
    flushDown();

    // The ring goes on the LAST SLOT DRAWN, whatever kind it is.
    //
    // A down sample is a measurement: a probe went out and nothing answered,
    // which is a reading arriving. So it pulses, in red, like any other newest
    // mark. Only a gap gets no ring, because nothing arrived to claim. The
    // reference implementation never pulses a down marker, and it strands the
    // ring back at the last measured point while the line's real end sits
    // somewhere else, which reads as a rendering fault.
    // [D, Plamen, 2026-09-12]
    var last = series.length - 1;
    if (!series[last]) return;
    var lx = last * step;
    var ly = series[last].down ? downY : yOf(series[last].v);
    var col = series[last].down ? opts.downColor
                                : opts.colorFor(series[last].v, false);

    if (opts.live) {
        ctx.beginPath();
        if (opts.motion) {
            ctx.arc(lx, ly, 2.5 + opts.phase * 5.5, 0, Math.PI * 2);
            ctx.globalAlpha = 0.5 * (1 - opts.phase);
        } else {
            // The claim is still made, without motion.
            ctx.arc(lx, ly, 5, 0, Math.PI * 2);
            ctx.globalAlpha = 0.4;
        }
        ctx.strokeStyle = col;
        ctx.lineWidth = 1.2;
        ctx.stroke();
        ctx.globalAlpha = 1;
    }
    ctx.beginPath();
    ctx.arc(lx, ly, 2, 0, Math.PI * 2);
    ctx.fillStyle = col;
    ctx.fill();
}
