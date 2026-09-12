// Nothing pathspark draws may land outside the canvas it was given.
//
// Two geometry defects shipped from this file in one day: the ring on the
// wrong slot (0.2.39) and the ring drawn half outside the right edge
// (0.2.41). Both were invisible to every other check in the battery —
// qmllint does not evaluate it, and the Python suite cannot reach it.
// `draw()` is pure, so a fake 2d context can.
//
// Run by test/test_pathspark.py, which skips when node is absent.

const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(
  path.join(__dirname, "..", "pathspark.js"), "utf8");
const Spark = new Function(
  src + "\nreturn { draw: draw, slots: slots, sharedMax: sharedMax };")();

function recorder(w, h) {
  const marks = [];
  let lw = 1, cur = null;
  const note = (what, x0, y0, x1, y1) =>
    marks.push({ what, x0, y0, x1, y1 });
  return {
    marks,
    set lineWidth(v) { lw = v; },
    get lineWidth() { return lw; },
    set strokeStyle(v) {}, set fillStyle(v) {},
    set lineJoin(v) {}, set lineCap(v) {}, set globalAlpha(v) {},
    clearRect() {},
    beginPath() { cur = []; },
    moveTo(x, y) { cur.push([x, y]); },
    lineTo(x, y) { cur.push([x, y]); },
    arc(x, y, r) { cur.push(["arc", x, y, r]); },
    stroke() {
      for (const p of cur || []) {
        if (p[0] === "arc") {
          const [, x, y, r] = p;
          note("ring", x - r - lw / 2, y - r - lw / 2,
                       x + r + lw / 2, y + r + lw / 2);
        } else {
          note("line", p[0] - lw / 2, p[1] - lw / 2,
                       p[0] + lw / 2, p[1] + lw / 2);
        }
      }
      cur = null;
    },
    fill() {
      for (const p of cur || []) {
        if (p[0] === "arc") {
          const [, x, y, r] = p;
          note("dot", x - r, y - r, x + r, y + r);
        }
      }
      cur = null;
    },
    fillRect(x, y, rw, rh) { note("bar", x, y, x + rw, y + rh); },
  };
}

const opts = (phase, live, motion) => ({
  max: 50, phase, live, motion,
  colorFor: () => "#9ece6a", downColor: "#f7768e", dimColor: "#565f89",
});

const N = 36;
const cases = {
  "all at the top of the scale": Array(N).fill({ v: 50 }),
  "all at zero": Array(N).fill({ v: 0 }),
  "over the scale max": Array(N).fill({ v: 5000 }),
  "all down": Array(N).fill({ down: true }),
  "all gaps": Array(N).fill(null),
  "newest is down": Array(N).fill({ v: 5 }).map((p, i) =>
    i >= N - 3 ? { down: true } : p),
  "newest is a gap": Array(N).fill({ v: 5 }).map((p, i) =>
    i === N - 1 ? null : p),
  "one lone measured slot": Array(N).fill(null).map((p, i) =>
    i === N - 1 ? { v: 50 } : p),
  "alternating gaps": Array(N).fill(null).map((p, i) =>
    i % 2 ? { v: 50 } : null),
};

let checks = 0, bad = [];
for (const [w, h] of [[120, 22], [60, 22], [200, 22], [120, 16], [40, 12]]) {
  for (const [name, series] of Object.entries(cases)) {
    for (const phase of [0, 0.25, 0.5, 0.75, 1]) {
      for (const [live, motion] of [[true, true], [true, false], [false, false]]) {
        const ctx = recorder(w, h);
        Spark.draw(ctx, w, h, series, opts(phase, live, motion));
        for (const m of ctx.marks) {
          checks++;
          const out = m.x0 < -0.01 || m.y0 < -0.01
                   || m.x1 > w + 0.01 || m.y1 > h + 0.01;
          if (out) {
            bad.push(`${w}x${h} ${name} phase=${phase} motion=${motion}: `
              + `${m.what} spans x[${m.x0.toFixed(2)},${m.x1.toFixed(2)}] `
              + `y[${m.y0.toFixed(2)},${m.y1.toFixed(2)}]`);
          }
        }
      }
    }
  }
}

if (!checks) {
  console.error("the harness drew nothing — it is not testing anything");
  process.exit(1);
}
const seen = [...new Set(bad)];
if (seen.length) {
  console.error(`${seen.length} marks outside the canvas:`);
  for (const b of seen.slice(0, 12)) console.error("  " + b);
  process.exit(1);
}
console.log(`ok — ${checks} marks, all inside the canvas`);
