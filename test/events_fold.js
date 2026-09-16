// Exercise the event-folding functions directly from EventsTab.qml.

const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(
  path.join(__dirname, "..", "EventsTab.qml"), "utf8");

function extract(name) {
  const start = src.indexOf("function " + name + "(");
  if (start < 0) throw new Error("missing function " + name);
  const open = src.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth++;
    if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
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
