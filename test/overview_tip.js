// Run OverviewTab.qml's speedTip() — the Speed pillar's hover text — in node.
// Run with TZ=UTC (test_overview_qml.py does) so clock times are fixed.

const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "..", "OverviewTab.qml"), "utf8");

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

const tip = new Function(extract("speedTip") + "\nreturn speedTip;")();

function equal(actual, expected, label) {
  if (actual !== expected)
    throw new Error(label + ":\n  got  " + JSON.stringify(actual)
                    + "\n  want " + JSON.stringify(expected));
}

const T1551 = Date.UTC(2026, 8, 17, 15, 51, 29) / 1000;
const auto = {basis: "auto", last_down: 113.8, samples: 3, min_samples: 2,
              checks_down: [165.3, 96.3, 113.8], scored: true, vpn: false};

equal(tip(null, null), "", "no context");

equal(tip(auto, null),
      "Median of the last 3 checks here, newest first:\n165 · 96 · 114 Mbps",
      "scored: the median's inputs");

// The case that started this: dimmed by a speed test run by hand.
equal(tip(Object.assign({}, auto, {scored: false, peak_down: 365.3,
                                    peak_ts: T1551, peak_until: T1551 + 3600}), null),
      "Median of the last 3 checks here, newest first:\n165 · 96 · 114 Mbps\n"
      + "Not counted in the score: a speed test at 15:51\n"
      + "read 365 Mbps, far above this.\nCounted again from 16:51.",
      "withdrawn by a test");

equal(tip({basis: "auto", last_down: 88.4, samples: 1, min_samples: 2,
           checks_down: [88.4], scored: false, vpn: false}, null),
      "One recent check on this network: 88 Mbps\n"
      + "Not counted in the score until there are 2 checks here.",
      "too few checks");

equal(tip(Object.assign({}, auto, {vpn: true}), null),
      "Median of the last 3 checks here, newest first:\n165 · 96 · 114 Mbps\n"
      + "Through the VPN, so this measures the tunnel.", "through a VPN");

// Checks exist but none describes the link now: said, not shown as "none yet".
equal(tip({basis: "auto", last_down: null, stale: "age", stale_ts: T1551,
           max_age_s: 10800, vpn: false}, null),
      "The last check here was at 15:51, over 3 h ago.\n"
      + "Left out of the score until a new one runs.", "stale by age");
equal(tip({basis: "auto", last_down: null, stale: "band", stale_ts: T1551,
           band: "5 GHz", max_age_s: 10800, vpn: false}, null),
      "The Wi-Fi moved to 5 GHz after the last check here.\n"
      + "Left out of the score until a check on this band.", "stale by band");

equal(tip({basis: "auto", last_down: null, pending: true, vpn: false}, null),
      "No speed check on this network yet.", "none yet");
equal(tip({basis: "auto", last_down: null, pending: true, vpn: true}, null),
      "No speed check through this VPN yet.", "none yet via VPN");

equal(tip({basis: "plan", plan_down: 300, last_down: 281.6}, null),
      "Scored against your plan: 300 Mbps down.\nLatest check: 282 Mbps.", "plan");

equal(tip(auto, {care: true, label: "Plamen's iPhone"}),
      "Hourly checks are paused on Plamen's iPhone,\n"
      + "which is sharing its mobile data. Setup turns this off.", "hotspot");
// A hotspot the user chose to keep measuring is an ordinary network.
equal(tip(auto, {care: false, label: "Plamen's iPhone"}),
      "Median of the last 3 checks here, newest first:\n165 · 96 · 114 Mbps",
      "hotspot, care off");

console.log("speed tip ok");
