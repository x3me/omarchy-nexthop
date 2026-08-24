"""Unit tests for nexthopd. Fixtures are recorded from a real Arch laptop
(ping from iputils, iw 6.x) — the formats these parsers exist to survive.

Run: python3 -m unittest discover -s test
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd import net, score  # noqa: E402
from nexthopd.daemon import LinkWatch  # noqa: E402
from nexthopd.apps import AppTraffic, parse_ss  # noqa: E402
from nexthopd.probes import Series, PingProbe, RE_REPLY, RE_PENDING, RE_UNREACH  # noqa: E402
from nexthopd.store import Store  # noqa: E402
from nexthopd.state import write_atomic, read_json  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


class PingParsing(unittest.TestCase):
    def test_reply_lines(self):
        hits = []
        for line in (FIXTURES / "ping-replies.txt").read_text().splitlines():
            m = RE_REPLY.match(line)
            if m:
                hits.append((float(m.group(1)), int(m.group(2)), float(m.group(3))))
        self.assertEqual(len(hits), 5)
        self.assertEqual(hits[0], (1787562260.703963, 1, 9.13))
        self.assertEqual(hits[2][2], 11.3)

    def test_loss_lines(self):
        pending, unreach = 0, 0
        for line in (FIXTURES / "ping-losses.txt").read_text().splitlines():
            if RE_PENDING.match(line):
                pending += 1
            elif RE_UNREACH.match(line):
                unreach += 1
        self.assertEqual(pending, 6)
        self.assertEqual(unreach, 1)

    def test_probe_consume_counts_loss_once(self):
        """A seq reported pending, then unreachable, is one loss — not two."""
        s = Series()
        p = PingProbe("192.0.2.1", s, 500)
        p._consume("[100.0] no answer yet for icmp_seq=1\n")
        p._consume("[100.5] no answer yet for icmp_seq=1\n")
        p._consume("[101.0] From 10.0.0.1 icmp_seq=1 Destination Host Unreachable\n")
        stats = Series.stats(s.all())
        self.assertEqual(stats["count"], 1)
        self.assertEqual(stats["loss"], 1.0)

    def test_probe_expires_silent_losses(self):
        """A pending seq that never resolves is counted after the grace period."""
        s = Series()
        p = PingProbe("192.0.2.1", s, 500)
        p._consume("[100.0] no answer yet for icmp_seq=7\n")
        # A reply for a later seq far past the grace window flushes it.
        p._consume("[200.0] 64 bytes from 1.1.1.1: icmp_seq=9 ttl=60 time=5.0 ms\n")
        stats = Series.stats(s.all())
        self.assertEqual(stats["count"], 2)
        self.assertEqual(stats["loss"], 0.5)


class IwParsing(unittest.TestCase):
    def test_link_fixture(self):
        raw = (FIXTURES / "iw-link.txt").read_text()
        original = net._run
        net._run = lambda cmd, timeout=2.0: raw
        try:
            info = net.wifi_link("wlo1")
        finally:
            net._run = original
        self.assertEqual(info["ssid"], "Excitel")
        self.assertEqual(info["freq_mhz"], 5180)   # float in fixture, int out
        self.assertEqual(info["signal_dbm"], -64)
        self.assertEqual(info["band"], "5 GHz")
        self.assertEqual(info["channel"], 36)
        self.assertEqual(info["standard"], "802.11ax")
        self.assertEqual(info["width_mhz"], 40)

    def test_channel_map(self):
        self.assertEqual(net._freq_to_channel(2412), 1)
        self.assertEqual(net._freq_to_channel(2484), 14)
        self.assertEqual(net._freq_to_channel(5180), 36)
        self.assertEqual(net._freq_to_channel(5955), 1)


class Stats(unittest.TestCase):
    def test_empty_and_all_lost(self):
        self.assertEqual(Series.stats([])["count"], 0)
        s = Series.stats([(0, None), (1, None)])
        self.assertEqual(s["loss"], 1.0)
        self.assertIsNone(s["p50"])

    def test_jitter_is_ipdv_not_stdev(self):
        # 10/40 alternation: IPDV is 30, stdev would be ~15.
        samples = [(i, 10.0 if i % 2 == 0 else 40.0) for i in range(10)]
        self.assertEqual(Series.stats(samples)["jitter"], 30.0)

    def test_window_eviction(self):
        s = Series(window_s=10)
        now = time.time()
        s.add(now - 20, 5.0)
        s.add(now, 6.0)
        self.assertEqual(len(s.all()), 1)


class Scoring(unittest.TestCase):
    def test_lag_charges_for_loss(self):
        clean = {"count": 100, "loss": 0.0, "p75": 10.0, "jitter": 1.0}
        lossy = {"count": 100, "loss": 0.02, "p75": 10.0, "jitter": 1.0}
        self.assertGreater(score.lag_ms(lossy), score.lag_ms(clean) + 15)

    def test_score_bands(self):
        self.assertEqual(score.band(94), "excellent")
        self.assertEqual(score.band(85), "good")
        self.assertEqual(score.band(74), "okay")
        self.assertEqual(score.band(55), "fair")
        self.assertEqual(score.band(10), "poor")
        self.assertEqual(score.band(None), "unknown")

    def test_index_skips_unknown_components(self):
        self.assertEqual(score.index(90.0, 100.0, None), 95)
        self.assertIsNone(score.index(None, None, None))

    def test_wan_subtraction_monotone(self):
        w = score.wan_from(
            {"count": 60, "loss": 0.0, "p50": 11.5, "p75": 15.5, "p95": 22.5,
             "max": 25.2, "jitter": 4.9, "last": 8.0},
            {"count": 60, "loss": 0.0, "p50": 8.6, "p75": 9.8, "p95": 19.8,
             "max": 21.2, "jitter": 4.2, "last": 7.8})
        self.assertLessEqual(w["p50"], w["p75"])
        self.assertLessEqual(w["p75"], w["p95"])
        self.assertLessEqual(w["p95"], w["max"])

    def test_wan_loss_never_negative(self):
        w = score.wan_from({"count": 10, "loss": 0.0, "p50": 5.0},
                           {"count": 10, "loss": 0.1, "p50": 2.0})
        self.assertEqual(w["loss"], 0.0)

    def test_speed_prefers_download(self):
        # Full download, empty upload should still score well above 50.
        self.assertGreater(score.speed(450, 0.1, 450, 50), 70)

    def test_speed_absolute_needs_no_config(self):
        # The default basis scores without a plan and saturates sensibly.
        self.assertIsNotNone(score.speed(230, 100))
        self.assertGreater(score.speed(230, 100), 90)
        self.assertLess(score.speed(10, 2), 40)
        # Past the perception ceiling extra speed barely moves the score.
        self.assertLess(score.speed(900, 200) - score.speed(500, 100), 3)

    def test_degradation_penalty_only_on_big_drops(self):
        # Ordinary shared-line variance is free; a real drop is not.
        self.assertEqual(score.degradation_penalty(200, 300), 0.0)
        self.assertGreater(score.degradation_penalty(60, 300), 15)
        # No baseline, no penalty — cold start stays honest.
        self.assertEqual(score.degradation_penalty(60, None), 0.0)

    def test_plan_overrides_absolute(self):
        # A configured plan switches the basis entirely.
        with_plan = score.speed(412, 48, 450, 50)
        without = score.speed(412, 48)
        self.assertNotEqual(with_plan, without)


class StoreRoundtrip(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.dir.name) / "t.db")

    def tearDown(self):
        self.store.close()
        self.dir.cleanup()

    def test_minute_hour_resolution_switch(self):
        now = int(time.time())
        for i in range(300):
            self.store.put_minute(now - (300 - i) * 60, {"lag": 20.0})
        rows, table = self.store.series(3600, now=now)
        self.assertEqual(table, "minute")
        self.assertEqual(len(rows), 60)
        self.store.rollup_hours(now)
        rows, table = self.store.series(7 * 86400, now=now)
        self.assertEqual(table, "hour")
        self.assertGreaterEqual(len(rows), 4)

    def test_outage_accounting(self):
        now = time.time()
        eid = self.store.open_event(int(now - 600), "outage", "critical",
                                    "wan", "test")
        self.store.close_event(eid, int(now - 540))
        frac, disruptions = self.store.outage_stats(3600, now=now)
        self.assertAlmostEqual(frac, 60 / 3600, places=3)
        self.assertEqual(disruptions, 0)

    def test_ongoing_outage_counts_to_now(self):
        now = time.time()
        self.store.open_event(int(now - 120), "outage", "critical", "wan", "t")
        frac, _ = self.store.outage_stats(3600, now=now)
        self.assertAlmostEqual(frac, 120 / 3600, places=3)

    def test_baseline_is_p90_per_network(self):
        now = int(time.time())
        for i, v in enumerate([100, 200, 210, 220, 230, 240, 900]):
            self.store.put_test(now - i * 3600, "content", "cloudflare",
                                down_mbps=v, ok=True, network="Office")
        # p90 shrugs off the one lucky 900 run.
        self.assertLess(self.store.baseline_speed(network="Office", now=now), 900)
        self.assertGreaterEqual(self.store.baseline_speed(network="Office", now=now), 240)
        # Too few samples on an unknown network falls back to all networks.
        self.assertIsNotNone(self.store.baseline_speed(network="Home", now=now))

    def test_baseline_needs_enough_samples(self):
        now = int(time.time())
        for i in range(3):
            self.store.put_test(now - i * 3600, "content", "x",
                                down_mbps=100, ok=True)
        self.assertIsNone(self.store.baseline_speed(now=now))


class LinkEvents(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.dir.name) / "t.db")
        self.watch = LinkWatch(self.store)

    def tearDown(self):
        self.store.close()
        self.dir.cleanup()

    def kinds(self):
        return [e["kind"] for e in self.store.events()]

    def test_associate_and_roam(self):
        t = time.time()
        self.watch.sample(t, {})
        self.watch.sample(t + 2, {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "Office",
                                  "channel": 149, "signal_dbm": -61})
        self.watch.sample(t + 4, {"bssid": "bb:bb:bb:bb:bb:bb", "ssid": "Office",
                                  "channel": 44, "signal_dbm": -47})
        kinds = self.kinds()
        self.assertIn("associate", kinds)
        self.assertIn("roam", kinds)
        roam = [e for e in self.store.events() if e["kind"] == "roam"][0]
        self.assertIn("149", roam["detail"])
        self.assertIn("44", roam["detail"])
        self.assertIn("-61", roam["detail"])

    def test_rate_drop_needs_sustain(self):
        t = time.time()
        link = {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X", "channel": 44}
        for i in range(5):
            self.watch.sample(t + i * 2, dict(link, tx_mbps=500))
        # A momentary dip is not an event.
        self.watch.sample(t + 12, dict(link, tx_mbps=120))
        self.watch.sample(t + 14, dict(link, tx_mbps=500))
        self.assertNotIn("rate-drop", self.kinds())
        # A sustained one is, and it closes with the recovery.
        for i in range(8):
            self.watch.sample(t + 20 + i * 2, dict(link, tx_mbps=110))
        self.assertIn("rate-drop", self.kinds())
        self.watch.sample(t + 40, dict(link, tx_mbps=480))
        drop = [e for e in self.store.events() if e["kind"] == "rate-drop"][0]
        self.assertIsNotNone(drop["ended_ts"])
        self.assertIn("110", drop["detail"])

    def test_throttled_to_one_hz(self):
        t = time.time()
        self.watch.sample(t, {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X"})
        # Two samples inside the same second: the second is ignored, so a
        # bssid flap faster than 1 Hz cannot spam the log.
        self.watch.sample(t + 0.4, {"bssid": "bb:bb:bb:bb:bb:bb", "ssid": "X"})
        self.assertNotIn("roam", self.kinds())


class AppAttribution(unittest.TestCase):
    def fixture(self):
        return (FIXTURES / "ss-tinp.txt").read_text()

    def test_parse_ss(self):
        socks = parse_ss(self.fixture())
        # The unattributed ssh socket (no users:()) is skipped.
        self.assertEqual(len(socks), 3)
        apps = sorted({v[0] for v in socks.values()})
        self.assertEqual(apps, ["chrome", "slack"])
        chrome = [v for v in socks.values() if v[0] == "chrome"]
        self.assertEqual(sum(v[3] for v in chrome), 2724692 + 8142)

    def test_rates_are_deltas_not_lifetimes(self):
        t = AppTraffic()
        base = parse_ss(self.fixture())
        t._fold(base, 100.0)
        # Baseline sample must not count connection lifetimes as traffic.
        self.assertEqual(t.rates, [])
        grown = {k: (a, p, s + 1000, r + 3000) for k, (a, p, s, r) in base.items()}
        t._fold(grown, 103.0)
        by_name = {a["name"]: a for a in t.rates}
        self.assertAlmostEqual(by_name["chrome"]["rx_bps"], 2 * 3000 / 3, delta=1)
        self.assertEqual(by_name["chrome"]["conns"], 2)
        self.assertEqual(by_name["slack"]["rx_total"], 3000)

    def test_new_socket_counts_whole_life(self):
        t = AppTraffic()
        t._fold({}, 100.0)
        t._fold(parse_ss(self.fixture()), 103.0)
        by_name = {a["name"]: a for a in t.rates}
        # Born between samples: its full counters are this interval's traffic.
        self.assertEqual(by_name["slack"]["rx_total"], 65451)


class AtomicState(unittest.TestCase):
    def test_write_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "live.json"
            write_atomic(p, {"x": 1})
            self.assertEqual(read_json(p), {"x": 1})
            self.assertEqual(read_json(Path(d) / "missing.json", 42), 42)
            # No temp files left behind.
            self.assertEqual([f.name for f in Path(d).iterdir()], ["live.json"])


if __name__ == "__main__":
    unittest.main()
