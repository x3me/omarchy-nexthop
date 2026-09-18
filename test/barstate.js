// Exercise barstate.js — the bar entry's and panel header's shared glyph
// choice, and the contrast guard on the warn colour — in a real JS engine.

const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "..", "barstate.js"), "utf8");
const B = new Function(src +
  "\nreturn {stateGlyph: stateGlyph, contrast: contrast, readable: readable};")();

function equal(actual, expected, label) {
  const got = JSON.stringify(actual);
  const want = JSON.stringify(expected);
  if (got !== want) throw new Error(label + ": " + got + " != " + want);
}

function rgb(hex) {
  const h = hex.replace("#", "");
  return {r: parseInt(h.slice(0, 2), 16) / 255,
          g: parseInt(h.slice(2, 4), 16) / 255,
          b: parseInt(h.slice(4, 6), 16) / 255};
}

// Every state names itself; a fault glyph wins over the index band.
const SPEEDO = "\u{F04C5}", MEDIUM = "\u{F0FBE}", SLOW = "\u{F0FBF}";
equal(B.stateGlyph("online", 100), SPEEDO, "good band");
equal(B.stateGlyph("online", 80), SPEEDO, "80 is good");
equal(B.stateGlyph("online", 79), MEDIUM, "79 is fair");
equal(B.stateGlyph("online", 50), MEDIUM, "50 is fair");
equal(B.stateGlyph("online", 49), SLOW, "49 is poor");
equal(B.stateGlyph("online", 0), SLOW, "0 is poor");
equal(B.stateGlyph("online", null), SPEEDO, "no index");
equal(B.stateGlyph("no-daemon", null), SPEEDO, "no daemon");
equal(B.stateGlyph("degraded", 95), MEDIUM, "degraded outranks the index");
equal(B.stateGlyph("captive", 10), "\u{F099D}", "captive");
equal(B.stateGlyph("dns-failing", 10), "\u{F01D6}", "dns");
equal(B.stateGlyph("local-down", 10), "\u{F16B5}", "router down");
equal(B.stateGlyph("wan-down", null), "\u{F0C9B}", "internet down");
equal(B.stateGlyph("tunnel-down", null), "\u{F0C9B}", "tunnel down");

// The amber against the bar backgrounds Omarchy ships (colors.toml
// `background`, which the shell's template makes the opaque bar's colour).
const AMBER = rgb("#e0af68");
const light = {"flexoki-light": "#FFFCF0", "white": "#ffffff",
               "catppuccin-latte": "#eff1f5", "rose-pine": "#faf4ed",
               "lupine": "#fafafa"};
const dark = {"tokyo-night": "#1a1b26", "lumon": "#16242d",
              "vantablack": "#000000", "nord": "#2e3440",
              "everforest": "#2d353b"};   // the last two: closest to the line
for (const [name, bg] of Object.entries(light))
  equal(B.readable(AMBER, rgb(bg)), false, "amber on " + name);
for (const [name, bg] of Object.entries(dark))
  equal(B.readable(AMBER, rgb(bg)), true, "amber on " + name);

// The ratio itself, against the WCAG reference points.
equal(Math.round(B.contrast(rgb("#000000"), rgb("#ffffff")) * 10) / 10, 21, "black/white");
equal(B.contrast(rgb("#777777"), rgb("#777777")), 1, "same colour");
equal(Math.round(B.contrast(AMBER, rgb("#FFFCF0")) * 10) / 10, 1.9, "flexoki-light, as #12 said");

console.log("bar state ok");
