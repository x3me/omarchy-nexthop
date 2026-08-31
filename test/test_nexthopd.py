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
from nexthopd.daemon import Config, LinkWatch  # noqa: E402
from nexthopd.apps import AppTraffic, parse_ss  # noqa: E402
from nexthopd.probes import Series, PingProbe, RE_REPLY, RE_PENDING, RE_UNREACH  # noqa: E402
from nexthopd.store import Store  # noqa: E402
from nexthopd.state import write_atomic, read_json  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parent.parent


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


class LoadTagging(unittest.TestCase):
    """Idle vs loaded latency, from the same probe stream.

    The gap between them is bufferbloat — the failure a plain latency
    number misses, where a line answers in 15 ms at rest and 300 ms
    whenever anyone uses it.
    """

    def test_samples_carry_the_link_state_they_saw(self):
        s = Series()
        now = time.time()
        s.add(now, 12.0)                 # default: idle
        s.add(now + 1, 250.0, True)      # under load
        idle, loaded = Series.split_by_load(s.all())
        self.assertEqual(len(idle), 1)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(idle[0][1], 12.0)
        self.assertEqual(loaded[0][1], 250.0)

    def test_two_element_samples_still_read_as_idle(self):
        # Anything holding the old sample shape must not raise.
        idle, loaded = Series.split_by_load([(0.0, 10.0), (1.0, None)])
        self.assertEqual(len(idle), 2)
        self.assertEqual(loaded, [])
        self.assertEqual(Series.stats([(0.0, 10.0), (1.0, 30.0)])["p50"], 20.0)

    def test_bufferbloat_shows_as_inflation_between_the_two(self):
        idle = [(float(i), 15.0, False) for i in range(20)]
        loaded = [(float(i + 20), 300.0, True) for i in range(20)]
        i_lag = score.lag_ms(Series.stats(idle))
        l_lag = score.lag_ms(Series.stats(loaded))
        self.assertLess(i_lag, 20)
        self.assertGreater(l_lag, 250)
        self.assertGreater(l_lag / i_lag, 10)

    def test_loss_is_still_counted_per_load_state(self):
        samples = [(0.0, 10.0, False), (1.0, None, False),
                   (2.0, 40.0, True), (3.0, None, True), (4.0, None, True)]
        idle, loaded = Series.split_by_load(samples)
        self.assertAlmostEqual(Series.stats(idle)["loss"], 0.5)
        self.assertAlmostEqual(Series.stats(loaded)["loss"], 2 / 3)

    def test_inflation_needs_enough_samples_on_both_sides(self):
        import os as _os
        from nexthopd.daemon import Daemon, MIN_LOAD_SPLIT_SAMPLES
        with tempfile.TemporaryDirectory() as d:
            _os.environ["XDG_STATE_HOME"] = d
            try:
                dm = Daemon()
                try:
                    now = time.time()
                    # Plenty idle, only a couple loaded: no ratio yet.
                    for i in range(30):
                        dm.total.add(now - 60 + i, 15.0, False)
                    for i in range(MIN_LOAD_SPLIT_SAMPLES - 1):
                        dm.total.add(now - 5 + i * 0.1, 300.0, True)
                    b = dm.bufferbloat(300.0)
                    self.assertIsNotNone(b["idle"])
                    self.assertIsNotNone(b["loaded"])
                    self.assertIsNone(b["inflation"])
                    # One more loaded sample and the comparison is allowed.
                    dm.total.add(now, 300.0, True)
                    b = dm.bufferbloat(300.0)
                    self.assertIsNotNone(b["inflation"])
                    self.assertGreater(b["inflation"], 5)
                finally:
                    dm.store.close()
            finally:
                del _os.environ["XDG_STATE_HOME"]

    def test_probe_tags_from_its_predicate_and_never_raises(self):
        from nexthopd.probes import PingProbe
        s = Series()
        state = {"busy": False}
        p = PingProbe("192.0.2.1", s, 500, "t", loaded_fn=lambda: state["busy"])
        self.assertFalse(p._loaded())
        state["busy"] = True
        self.assertTrue(p._loaded())
        # A predicate that blows up must not take the probe with it.
        broken = PingProbe("192.0.2.1", s, 500, "t",
                           loaded_fn=lambda: 1 / 0)
        self.assertFalse(broken._loaded())


class ApplicationPath(unittest.TestCase):
    """The TCP-handshake probe that sits beside ICMP.

    ICMP is answered by fast paths in hardware and can be spoofed by
    anything on the way; a handshake to port 443 has to reach a listener
    that completes it. The gap between the two is the measurement.
    """

    def setUp(self):
        import os as _os
        from nexthopd.daemon import Daemon
        self.dir = tempfile.TemporaryDirectory()
        _os.environ["XDG_STATE_HOME"] = self.dir.name
        self.daemon = Daemon()
        self._os = _os

    def tearDown(self):
        self.daemon.store.close()
        del self._os.environ["XDG_STATE_HOME"]
        self.dir.cleanup()

    def test_reports_the_gap_against_icmp(self):
        now = time.time()
        for i in range(30):
            self.daemon.total.add(now - 30 + i, 7.0)     # ICMP: fast-pathed
            self.daemon.app.add(now - 30 + i, 12.0)      # handshake: honest
        ap = self.daemon.app_path(300.0)
        self.assertTrue(ap["available"])
        self.assertAlmostEqual(ap["icmp_delta_ms"], 5.0, places=1)

    def test_anchor_that_refuses_443_reads_as_unavailable_not_broken(self):
        # Every sample failing is a fact about the target, not a fault in
        # the connection — it must not surface as 100% packet loss.
        now = time.time()
        for i in range(20):
            self.daemon.total.add(now - 20 + i, 8.0)
            self.daemon.app.add(now - 20 + i, None)
        ap = self.daemon.app_path(300.0)
        self.assertFalse(ap["available"])
        self.assertIsNone(ap["icmp_delta_ms"])

    def test_no_samples_yet_is_unavailable_without_a_delta(self):
        ap = self.daemon.app_path(300.0)
        self.assertFalse(ap["available"])
        self.assertIsNone(ap["icmp_delta_ms"])
        self.assertIsNone(ap["request"])

    def test_tcp_probe_records_a_failure_rather_than_raising(self):
        from nexthopd.probes import TcpProbe
        s = Series()
        # Reserved-for-documentation address; nothing answers.
        p = TcpProbe("192.0.2.1", s, 1.0, "t", port=9)
        p.CONNECT_TIMEOUT_S = 0.25
        p._once()
        self.assertEqual(len(s.all()), 1)
        self.assertIsNone(s.all()[0][1])
        self.assertFalse(p.ever_connected)

    def test_tcp_probe_tags_load_like_the_ping_probe(self):
        from nexthopd.probes import TcpProbe
        s = Series()
        p = TcpProbe("192.0.2.1", s, 1.0, "t", loaded_fn=lambda: True, port=9)
        p.CONNECT_TIMEOUT_S = 0.25
        p._once()
        self.assertTrue(s.all()[0][2])


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
        # Weakest-link: 90 owns the number, 100 nudges it up slightly.
        self.assertEqual(score.index(90.0, 100.0, None), 91)
        self.assertIsNone(score.index(None, None, None))
        # A single measurable component is that component.
        self.assertEqual(score.index(None, 73.0, None), 73)

    def test_index_does_not_let_good_components_mask_a_broken_one(self):
        # A line whose calls do not work, with a fast download and no
        # outages. The mean called this 78 ("okay"); the bottleneck is 40.
        idx = score.index(40.0, 100.0, 95.0)
        self.assertLess(idx, 50)
        self.assertEqual(score.band(idx), "poor")

    def test_index_still_rewards_an_otherwise_excellent_connection(self):
        # All three healthy: the number stays where the components are.
        self.assertGreaterEqual(score.index(96.0, 100.0, 94.0), 94)

    def test_index_ties_do_not_lose_a_component(self):
        self.assertEqual(score.index(70.0, 70.0, 70.0), 70)

    def test_loss_costs_the_same_as_before_on_an_ordinary_link(self):
        # The flat 1000 ms/unit-loss was right for normal round trips, so
        # nothing changes for them — only the shape above the RTO floor.
        for p75 in (5.0, 15.0, 40.0, 66.0):
            self.assertEqual(score.loss_cost_ms(p75), 1000.0)

    def test_loss_costs_more_on_a_high_latency_link(self):
        # A retransmit on a 600 ms link is not the same 10 ms per percent
        # that it is on fibre.
        self.assertGreater(score.loss_cost_ms(600.0),
                           score.loss_cost_ms(15.0) * 5)
        fibre = score.lag_ms({"count": 100, "p75": 15.0, "jitter": 3.0,
                              "loss": 0.01})
        sat = score.lag_ms({"count": 100, "p75": 600.0, "jitter": 30.0,
                            "loss": 0.01})
        self.assertAlmostEqual(fibre - 19.5, 10.0, places=1)   # 10 ms, as before
        self.assertAlmostEqual(sat - 645.0, 90.0, places=1)    # 90 ms, scaled

    def test_loss_cost_never_drops_below_the_rto_floor(self):
        self.assertEqual(score.loss_cost_ms(0.0),
                         score.LOSS_STALL_FACTOR * score.LOSS_RTO_FLOOR_MS)

    def test_reliability_charges_outages_harder_than_self_healed_blips(self):
        # The inversion this replaced: three brief disruptions used to cost
        # 18 points while a ten-minute outage cost 0.7, so the milder event
        # was punished twenty-six times harder.
        day = 24 * 3600
        outage = score.reliability(600 / day, 0)
        blips = score.reliability(0.0, 3, disruption_fraction=45 / day)
        self.assertLess(outage, blips,
                        "ten minutes fully down must cost more than three "
                        "short self-healed blips")

    def test_reliability_scales_with_downtime(self):
        day = 24 * 3600
        self.assertGreater(score.reliability(600 / day, 0),
                           score.reliability(3600 / day, 0))
        self.assertGreater(score.reliability(3600 / day, 0),
                           score.reliability(6 * 3600 / day, 0))

    def test_a_bad_evening_of_blips_cannot_zero_reliability(self):
        # Seventeen disruptions used to land on exactly 0.0.
        day = 24 * 3600
        rel = score.reliability(0.0, 17, disruption_fraction=17 * 30 / day)
        self.assertGreater(rel, 90.0)   # not a catastrophe
        self.assertLess(rel, 100.0)     # but not free either

    def test_repeated_blips_still_cost_more_than_one(self):
        day = 24 * 3600
        one = score.reliability(0.0, 1, disruption_fraction=300 / day)
        many = score.reliability(0.0, 10, disruption_fraction=300 / day)
        self.assertLess(many, one)

    def test_total_downtime_floors_at_zero(self):
        self.assertEqual(score.reliability(1.0, 0), 0.0)

    def test_uncovered_window_is_not_punished(self):
        self.assertEqual(score.reliability(0.0, 5, covered=False), 100.0)

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
        frac, disruptions, disrupt_frac = self.store.outage_stats(3600, now=now)
        self.assertAlmostEqual(frac, 60 / 3600, places=3)
        self.assertEqual(disruptions, 0)
        self.assertEqual(disrupt_frac, 0.0)

    def test_ongoing_outage_counts_to_now(self):
        now = time.time()
        self.store.open_event(int(now - 120), "outage", "critical", "wan", "t")
        frac, _, _ = self.store.outage_stats(3600, now=now)
        self.assertAlmostEqual(frac, 120 / 3600, places=3)

    def test_disruptions_report_duration_not_just_count(self):
        now = time.time()
        for start, length in ((900, 20), (600, 40)):
            eid = self.store.open_event(int(now - start), "disruption",
                                        "warning", "wan", "t")
            self.store.close_event(eid, int(now - start + length))
        frac, disruptions, disrupt_frac = self.store.outage_stats(3600, now=now)
        self.assertEqual(frac, 0.0)
        self.assertEqual(disruptions, 2)
        self.assertAlmostEqual(disrupt_frac, 60 / 3600, places=3)

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

    def test_baseline_no_fallback_without_local_samples(self):
        now = int(time.time())
        for i in range(6):
            self.store.put_test(now - i * 3600, "content", "x",
                                down_mbps=300, ok=True, network="OfficeA")
        # Another network's history must not become this network's normal.
        self.assertIsNone(self.store.baseline_speed(network="OfficeB",
                                                    now=now, fallback=False))
        self.assertIsNotNone(self.store.baseline_speed(network="OfficeB",
                                                       now=now))

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

    def test_first_sighting_is_not_an_association(self):
        # A daemon restart sees an existing link — that is not an event.
        t = time.time()
        self.watch.sample(t, {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "Office"})
        self.assertEqual(self.kinds(), [])

    def test_roam_and_detail(self):
        t = time.time()
        self.watch.sample(t, {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "Office",
                              "channel": 149, "signal_dbm": -61})
        self.watch.sample(t + 2, {"bssid": "bb:bb:bb:bb:bb:bb", "ssid": "Office",
                                  "channel": 44, "signal_dbm": -47})
        kinds = self.kinds()
        self.assertIn("roam", kinds)
        self.assertNotIn("associate", kinds)
        roam = [e for e in self.store.events() if e["kind"] == "roam"][0]
        self.assertIn("149", roam["detail"])
        self.assertIn("44", roam["detail"])
        self.assertIn("-61", roam["detail"])

    def test_associate_needs_a_confirmed_gap(self):
        t = time.time()
        link = {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "Office"}
        self.watch.sample(t, link)
        # A brief iw hiccup (fewer empty reads than the threshold) is not a
        # disassociation, so the recovery is not an association.
        for i in range(LinkWatch.GAP_SAMPLES - 1):
            self.watch.sample(t + 2 + i * 2, {})
        self.watch.sample(t + 20, link)
        self.assertEqual(self.kinds(), [])
        # A confirmed gap is, and the recovery is logged once.
        for i in range(LinkWatch.GAP_SAMPLES):
            self.watch.sample(t + 30 + i * 2, {})
        self.watch.sample(t + 60, link)
        self.assertEqual(self.kinds(), ["associate"])

    BUSY = 1_000_000  # bytes/sec, well above the idle floor

    def test_rate_drop_needs_sustain(self):
        t = time.time()
        link = {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X", "channel": 44}
        for i in range(5):
            self.watch.sample(t + i * 2, dict(link, tx_mbps=500), self.BUSY)
        # A momentary dip is not an event.
        self.watch.sample(t + 12, dict(link, tx_mbps=120), self.BUSY)
        self.watch.sample(t + 14, dict(link, tx_mbps=500), self.BUSY)
        self.assertNotIn("rate-drop", self.kinds())
        # A sustained one is, and it closes with the recovery.
        for i in range(8):
            self.watch.sample(t + 20 + i * 2, dict(link, tx_mbps=110), self.BUSY)
        self.assertIn("rate-drop", self.kinds())
        self.watch.sample(t + 40, dict(link, tx_mbps=480), self.BUSY)
        drop = [e for e in self.store.events() if e["kind"] == "rate-drop"][0]
        self.assertIsNotNone(drop["ended_ts"])
        self.assertIn("110", drop["detail"])

    def test_idle_rate_drops_are_not_events(self):
        # Power save renegotiates a low bitrate the moment the link idles;
        # with no traffic that is invisible to the user and must not log.
        t = time.time()
        link = {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X", "channel": 44}
        for i in range(5):
            self.watch.sample(t + i * 2, dict(link, tx_mbps=2000), self.BUSY)
        for i in range(20):
            self.watch.sample(t + 20 + i * 2, dict(link, tx_mbps=120), 500)
        self.assertNotIn("rate-drop", self.kinds())

    def test_throttled_to_one_hz(self):
        t = time.time()
        self.watch.sample(t, {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X"})
        # Two samples inside the same second: the second is ignored, so a
        # bssid flap faster than 1 Hz cannot spam the log.
        self.watch.sample(t + 0.4, {"bssid": "bb:bb:bb:bb:bb:bb", "ssid": "X"})
        self.assertNotIn("roam", self.kinds())


class ConfigValidation(unittest.TestCase):
    def make(self, payload):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        cfg = Config(Path(d.name))
        cfg.path.write_text(payload)
        cfg.refresh()
        return cfg

    def test_out_of_range_values_fall_back_to_defaults(self):
        cfg = self.make('{"throughputWindowS": 999999999, "probeIntervalMs": 1,'
                        ' "historyDays": -5}')
        self.assertEqual(cfg["throughputWindowS"], 3)
        self.assertEqual(cfg["probeIntervalMs"], 500)
        self.assertEqual(cfg["historyDays"], 7)

    def test_wrong_types_rejected(self):
        cfg = self.make('{"probeIntervalMs": "500", "contentSpeed": "yes",'
                        ' "peakEngine": "evil"}')
        self.assertEqual(cfg["probeIntervalMs"], 500)
        self.assertEqual(cfg["contentSpeed"], True)
        self.assertEqual(cfg["peakEngine"], "Auto")

    def test_anchor_charset_enforced(self):
        cfg = self.make('{"internetAnchor": "1.1.1.1; rm -rf /"}')
        self.assertEqual(cfg["internetAnchor"], "1.1.1.1")
        cfg2 = self.make('{"internetAnchor": "ping.example-host.net"}')
        self.assertEqual(cfg2["internetAnchor"], "ping.example-host.net")

    def test_oversized_file_ignored(self):
        cfg = self.make('{"historyDays": 30, "pad": "' + 'x' * (70 * 1024) + '"}')
        self.assertEqual(cfg["historyDays"], 7)

    def test_valid_values_accepted(self):
        cfg = self.make('{"throughputWindowS": 10, "planDownMbps": 450}')
        self.assertEqual(cfg["throughputWindowS"], 10)
        self.assertEqual(cfg["planDownMbps"], 450)


class FdSafety(unittest.TestCase):
    def test_config_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target.json"
            target.write_text('{"historyDays": 30}')
            cfg = Config(Path(d) / "sub")
            cfg.path.parent.mkdir()
            cfg.path.symlink_to(target)
            cfg.refresh()
            # A symlinked config is refused outright (O_NOFOLLOW).
            self.assertEqual(cfg["historyDays"], 7)

    def test_config_bound_is_on_the_read(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(Path(d))
            cfg.path.write_text('{"pad": "' + 'x' * (70 * 1024)
                                + '", "historyDays": 30}')
            cfg.refresh()
            self.assertEqual(cfg["historyDays"], 7)

    def test_lock_symlink_never_truncates_target(self):
        import os as _os
        from nexthopd.daemon import Daemon
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / "victim"
            victim.write_text("precious data that must survive")
            _os.environ["XDG_STATE_HOME"] = d
            try:
                state = Path(d) / "nexthop"
                state.mkdir()
                (state / "nexthopd.lock").symlink_to(victim)
                daemon = Daemon()
                try:
                    self.assertFalse(daemon.acquire_lock())
                finally:
                    daemon.store.close()
            finally:
                del _os.environ["XDG_STATE_HOME"]
            self.assertEqual(victim.read_text(),
                             "precious data that must survive")


class StateReadSafety(unittest.TestCase):
    """The read the QML side consumes: bounded, non-blocking, no-follow,
    regular files only. Every property is enforced on the fd actually read,
    so a state file swapped at its predictable path can neither redirect
    the read, stall it, nor allocate without limit."""

    def setUp(self):
        from nexthopd.state import read_text_bounded
        self.read = read_text_bounded
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_regular_file_reads(self):
        (self.d / "live.json").write_text('{"a":1}')
        got = self.read(self.d / "live.json", 1024)
        self.assertIsNotNone(got)
        self.assertEqual(got[0], '{"a":1}')

    def test_symlink_refused_and_target_unread(self):
        secret = self.d / "secret"
        secret.write_text("SENSITIVE")
        (self.d / "live.json").symlink_to(secret)
        self.assertIsNone(self.read(self.d / "live.json", 1024))

    def test_fifo_refused_without_blocking(self):
        import os as _os
        _os.mkfifo(self.d / "live.json")
        # No writer will ever open this; a blocking open would hang here.
        self.assertIsNone(self.read(self.d / "live.json", 1024))

    def test_oversized_refused_by_the_read_itself(self):
        (self.d / "live.json").write_text("x" * 5000)
        self.assertIsNone(self.read(self.d / "live.json", 1024))

    def test_exactly_at_the_cap_is_allowed(self):
        (self.d / "live.json").write_text("y" * 1024)
        got = self.read(self.d / "live.json", 1024)
        self.assertIsNotNone(got)
        self.assertEqual(len(got[0]), 1024)

    def test_directory_refused(self):
        self.assertIsNone(self.read(self.d, 1024))

    def test_missing_file_is_none(self):
        self.assertIsNone(self.read(self.d / "nope.json", 1024))

    def test_stamp_changes_only_when_the_file_does(self):
        p = self.d / "live.json"
        p.write_text('{"a":1}')
        first = self.read(p, 1024)[1]
        self.assertEqual(self.read(p, 1024)[1], first)
        import os as _os
        p.write_text('{"a":2}')
        _os.utime(p, ns=(0, 12345))
        self.assertNotEqual(self.read(p, 1024)[1], first)

    def test_stream_keys_are_a_closed_set(self):
        from nexthopd.cli import STREAMABLE
        # The QML side names a key, never a path — nothing it passes can
        # widen what gets opened.
        self.assertEqual(sorted(STREAMABLE),
                         ["apps", "live", "manifest", "recent"])

    def test_indented_json_still_streams_as_one_line(self):
        # manifest.json is pretty-printed. Forwarding it verbatim would
        # emit several lines and the shell service would never learn the
        # version, silently disabling the update handover.
        import json as _json
        p = self.d / "manifest.json"
        p.write_text(_json.dumps({"version": "9.9.9", "kinds": ["service"]},
                                 indent=2))
        text = self.read(p, 1024)[0]
        self.assertIn("\n", text)
        line = _json.dumps(_json.loads(text), separators=(",", ":"))
        self.assertNotIn("\n", line)
        self.assertEqual(_json.loads(line)["version"], "9.9.9")

    def test_embedded_newline_cannot_break_framing(self):
        import json as _json
        p = self.d / "live.json"
        p.write_text(_json.dumps({"note": "one\ntwo", "v": 1}))
        text = self.read(p, 4096)[0]
        line = _json.dumps(_json.loads(text), separators=(",", ":"))
        self.assertNotIn("\n", line)
        self.assertEqual(_json.loads(line)["note"], "one\ntwo")


class RetireAuthorization(unittest.TestCase):
    """The guard that stands between a version mismatch and a SIGTERM.

    It used to be a shell one-liner that could not be tested; it passed a
    NUL to `tr`, so execve truncated the script and no daemon was ever
    actually retired. These cases pin each fact it checks.
    """

    def setUp(self):
        from nexthopd.cli import authorized_to_retire
        self.auth = authorized_to_retire
        from nexthopd.daemon import proc_start_ticks
        self.ticks = proc_start_ticks

    def spawn(self, args, cwd=None):
        import subprocess
        p = subprocess.Popen(args, cwd=cwd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        time.sleep(0.4)
        return p

    def daemon_shaped(self):
        """A process whose argv is exactly `python -m nexthopd`.

        A stand-in rather than the real daemon: the real one would lose the
        flock race against whatever is already running and exit before the
        guard could look at it, and a test has no business probing the
        network. The guard reads argv, owner and start time — all of which
        this reproduces exactly.
        """
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        pkg = Path(d) / "nexthopd"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "__main__.py").write_text("import time\ntime.sleep(30)\n")
        return self.spawn([sys.executable, "-m", "nexthopd"], cwd=d)

    def test_daemon_argv_with_matching_start_is_authorized(self):
        p = self.daemon_shaped()
        self.assertTrue(self.auth(p.pid, self.ticks(p.pid)))

    def test_wrong_start_time_refused(self):
        p = self.daemon_shaped()
        self.assertFalse(self.auth(p.pid, self.ticks(p.pid) + 1))

    def test_zero_start_skips_only_the_time_check(self):
        # live.json from a daemon too old to publish pid_start: argv and
        # ownership still have to hold.
        p = self.daemon_shaped()
        self.assertTrue(self.auth(p.pid, 0))

    def test_other_python_process_refused(self):
        # Same interpreter, different module: never ours to signal.
        p = self.spawn([sys.executable, "-c", "import time; time.sleep(30)"])
        self.assertFalse(self.auth(p.pid, 0))

    def test_lookalike_argv_refused(self):
        # A process that merely mentions nexthopd is not the daemon.
        p = self.spawn([sys.executable, "-c",
                        "import time; time.sleep(30)  # -m nexthopd"])
        self.assertFalse(self.auth(p.pid, 0))

    def test_extra_arguments_refused(self):
        p = self.spawn([sys.executable, "-m", "nexthopd.cli", "stream", "live"])
        self.assertFalse(self.auth(p.pid, 0))

    def test_pid_that_does_not_exist_refused(self):
        self.assertFalse(self.auth(999999, 0))

    def test_pid_one_refused(self):
        # Owned by root, so the ownership check alone stops us.
        self.assertFalse(self.auth(1, 0))

    def test_command_string_carries_no_nul(self):
        # The regression itself: the argv QML hands to sh must survive
        # execve, which a NUL byte would truncate.
        import subprocess
        cmd = ('cd "$1" && exec python3 -m nexthopd.cli retire '
               '--pid "$2" --start "$3"')
        self.assertNotIn("\0", cmd)
        r = subprocess.run(["sh", "-c", cmd, "sh", str(REPO), "999999", "0"],
                           capture_output=True)
        self.assertEqual(r.returncode, 1)      # refused, not a syntax error
        self.assertEqual(r.stderr, b"")


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

    def test_socket_cap_bounds_parsing(self):
        # Thousands of distinct sockets parse to at most the cap.
        lines = []
        for i in range(3000):
            lines.append(
                'ESTAB 0 0 192.0.2.10:%d 198.51.100.7:443 '
                'users:(("app%d",pid=%d,fd=4))' % (10000 + i, i % 7, 100 + i))
            lines.append('\t cubic bytes_sent:100 bytes_received:200')
        socks = parse_ss("\n".join(lines), max_sockets=50)
        self.assertEqual(len(socks), 50)

    def test_new_socket_counts_whole_life(self):
        t = AppTraffic()
        t._fold({}, 100.0)
        t._fold(parse_ss(self.fixture()), 103.0)
        by_name = {a["name"]: a for a in t.rates}
        # Born between samples: its full counters are this interval's traffic.
        self.assertEqual(by_name["slack"]["rx_total"], 65451)


class SpeedScoring(unittest.TestCase):
    """Daemon.speed_score against a real store, no probes started."""

    def setUp(self):
        import os as _os
        from nexthopd.daemon import Daemon
        self.dir = tempfile.TemporaryDirectory()
        _os.environ["XDG_STATE_HOME"] = self.dir.name
        self.daemon = Daemon()
        self._os = _os

    def tearDown(self):
        self.daemon.store.close()
        del self._os.environ["XDG_STATE_HOME"]
        self.dir.cleanup()

    def put(self, ago_s, down, up, network):
        self.daemon.store.put_test(int(time.time() - ago_s), "content",
                                   "cloudflare", down_mbps=down, up_mbps=up,
                                   ok=True, network=network)

    def test_other_networks_checks_do_not_score_here(self):
        self.put(600, 300, 100, "OfficeA")
        spd, ctx = self.daemon.speed_score(time.time(), "OfficeB")
        self.assertIsNone(spd)
        self.assertTrue(ctx.get("pending"))

    def test_median_shrugs_off_one_bad_check(self):
        self.put(7200, 220, 90, "OfficeA")
        self.put(3600, 240, 95, "OfficeA")
        self.put(600, 18, 5, "OfficeA")       # the mid-roam outlier
        spd, ctx = self.daemon.speed_score(time.time(), "OfficeA")
        self.assertEqual(ctx["last_down"], 220)   # median, not the outlier
        self.assertGreater(spd, 85)

    def test_no_cross_network_penalty(self):
        # A fast history elsewhere must not depress a slower network.
        for i in range(6):
            self.put(3600 * (i + 2), 300, 100, "FastOffice")
        self.put(600, 30, 10, "SlowCafe")
        spd, ctx = self.daemon.speed_score(time.time(), "SlowCafe")
        self.assertIsNone(ctx["baseline_down"])
        # Pure absolute curve for 30/10: mid-50s to 60 — no minus-35 cliff.
        self.assertGreater(spd, 50)


class PeakSizing(unittest.TestCase):
    """The sustained pass is sized from the estimate, floored and capped."""

    def test_sized_for_ten_seconds_at_measured_rate(self):
        from nexthopd import speedtest
        # 160 Mbps line over 4 streams: each stream carries 40 Mbps.
        n = speedtest._sized_pass(160.0 / speedtest.PEAK_STREAMS,
                                  speedtest.PEAK_DOWN_FLOOR,
                                  speedtest.CLOUDFLARE_DOWN_MAX)
        self.assertEqual(n, 50_000_000)
        self.assertAlmostEqual(speedtest._pass_seconds(40.0, n), 10.0)

    def test_slow_line_stays_small(self):
        from nexthopd import speedtest
        n = speedtest._sized_pass(10.0, speedtest.PEAK_DOWN_FLOOR,
                                  speedtest.CLOUDFLARE_DOWN_MAX)
        self.assertEqual(n, 12_500_000)

    def test_caps_bound_both_directions(self):
        from nexthopd import speedtest
        # __down 403s at 100 MB and above — the per-stream cap must stay under.
        self.assertLess(speedtest.CLOUDFLARE_DOWN_MAX, 100_000_000)
        self.assertEqual(speedtest._sized_pass(10_000.0, speedtest.PEAK_DOWN_FLOOR,
                                               speedtest.CLOUDFLARE_DOWN_MAX),
                         speedtest.CLOUDFLARE_DOWN_MAX)
        self.assertEqual(speedtest._sized_pass(0.1, speedtest.PEAK_UP_FLOOR,
                                               speedtest.PEAK_UP_CAP),
                         speedtest.PEAK_UP_FLOOR)


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
