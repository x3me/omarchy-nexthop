// Exercise the event functions directly from EventsTab.qml and WifiTab.qml.

const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(
  path.join(__dirname, "..", "EventsTab.qml"), "utf8");
const wifiSrc = fs.readFileSync(
  path.join(__dirname, "..", "WifiTab.qml"), "utf8");

function extract(name, text = src) {
  const start = text.indexOf("function " + name + "(");
  if (start < 0) throw new Error("missing function " + name);
  const open = text.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    if (text[i] === "}" && --depth === 0) return text.slice(start, i + 1);
  }
  throw new Error("unterminated function " + name);
}

const Fold = new Function(
  extract("shortMac") + "\n" + extract("roamTargets") + "\n"
  + extract("kickSources")
  + "\nreturn {roamTargets: roamTargets, kickSources: kickSources};")();

function equal(actual, expected, label) {
  const got = JSON.stringify(actual);
  const want = JSON.stringify(expected);
  if (got !== want) throw new Error(label + ": " + got + " != " + want);
}

const roams = [
  {detail: "Roamed to Hallway AP (02:00:00:00:00:01), channel 37 → 149"},
  {detail: "Roamed to Hallway AP (02:00:00:00:00:02), channel 149 → 37"},
];
equal(Fold.roamTargets(roams),
      ["Hallway AP (…00:01)", "Hallway AP (…00:02)"],
      "named roam targets");

equal(Fold.roamTargets([{detail: "Roamed to 02:00:00:00:00:03"}]),
      ["…00:03"], "raw roam target");

const kicks = [
  {detail: "Kicked by AP Kitchen AP (02:00:00:00:00:04) "
    + "(reason 8: the AP is leaving the BSS), rejoined after 3 s"},
];
equal(Fold.kickSources(kicks), {
  aps: ["Kitchen AP (…00:04)"],
  why: "reason 8: the AP is leaving the BSS",
}, "named kick source");

equal(Fold.kickSources([{
  detail: "Kicked by AP 02:00:00:00:00:05 (reason 4: beacon loss)",
}]), {
  aps: ["…00:05"],
  why: "reason 4: beacon loss",
}, "raw kick source");

console.log("named event folding ok");

// An end nobody saw is said in words, never as the placeholder second the
// next daemon stored for it (#9).
const Dur = new Function(extract("duration") + "\nreturn duration;")();
equal(Dur({ts: 100, ended_ts: 101, end_unknown: 1}), "unknown", "orphan");
equal(Dur({ts: 100, ended_ts: 101, end_unknown: null}), "1s", "seen second");
equal(Dur({ts: 100, ended_ts: 100}), "\u2014", "instant");
equal(Dur({ts: 100, ended_ts: null}), "ongoing", "open");
equal(Dur({ts: 100, ended_ts: 3825}), "1h 2m", "long");

const Link = new Function(
  extract("linkDuration", wifiSrc) + "\nreturn linkDuration;")();
equal(Link({ts: 100, ended_ts: 101, end_unknown: 1}), "unknown", "link orphan");
equal(Link({ts: 100, ended_ts: 112, end_unknown: null}), "for 12 s", "link seen");
equal(Link({ts: 100, ended_ts: 100}), "", "link instant");

// A wan outage that began as the router came back is not blamed upstream.
const Describe = new Function(extract("shortMac") + "\n" + extract("describe")
  + "\nreturn describe;")();
equal(Describe({kind: "outage", leg: "wan",
                detail: "internet not back yet after the router returned"}),
      "Internet not back yet after the router returned.", "not back yet");
equal(Describe({kind: "outage", leg: "wan",
                detail: "router answers, nothing past it does"}),
      "No internet. The router still answered, so the fault was upstream.",
      "ordinary wan outage");
console.log("event durations ok");
