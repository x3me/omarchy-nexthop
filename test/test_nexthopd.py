"""Unit tests for nexthopd. Fixtures are recorded from a real Arch laptop
(ping from iputils, iw 6.x) — the formats these parsers exist to survive.

Run: python3 -m unittest discover -s test
"""

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd import net, score  # noqa: E402
from nexthopd.daemon import (CaptiveWatch, Config, LinkWatch,  # noqa: E402
                             LocalEventArbiter, WanEventArbiter)
from nexthopd.linkevents import NlEvents, reason_text  # noqa: E402
from nexthopd.net import trace_verdict  # noqa: E402
from nexthopd.instruments import Bench, MergedSeries, penalty  # noqa: E402
from nexthopd.apps import (AppTraffic, Sock, latency_stats,  # noqa: E402
                           parse_ss, socket_timing)
from nexthopd.probes import Series, PingProbe, RE_REPLY, RE_PENDING, RE_UNREACH  # noqa: E402
from nexthopd.store import Store  # noqa: E402
from nexthopd.update import RE_SHA, UpdateWatch, verdict  # noqa: E402
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


class UntrustedTargets(unittest.TestCase):
    """fast.com nominates its own download hosts, so that JSON decides
    what this daemon connects to and is hostile input, not a server list.

    Literal addresses throughout, so nothing here touches DNS.
    """

    def setUp(self):
        from nexthopd.speedtest import vet_target
        self.vet = vet_target

    def test_plaintext_is_refused(self):
        self.assertIsNone(self.vet("http://93.184.216.34/download"))

    def test_non_http_schemes_are_refused(self):
        for url in ("file:///etc/passwd", "ftp://93.184.216.34/x",
                    "gopher://93.184.216.34/x", "scp://93.184.216.34/x",
                    "dict://93.184.216.34/x"):
            self.assertIsNone(self.vet(url), url)

    def test_loopback_is_refused(self):
        for url in ("https://127.0.0.1/x", "https://127.1.2.3/x",
                    "https://[::1]/x"):
            self.assertIsNone(self.vet(url), url)

    def test_private_ranges_are_refused(self):
        for url in ("https://192.168.1.1/x", "https://10.0.0.1/x",
                    "https://172.16.4.2/x", "https://[fd00::1]/x"):
            self.assertIsNone(self.vet(url), url)

    def test_cloud_metadata_address_is_refused(self):
        # The link-local address every SSRF write-up ends at.
        self.assertIsNone(self.vet("https://169.254.169.254/latest/meta-data/"))

    def test_ipv4_mapped_private_address_is_refused(self):
        # ::ffff:192.168.1.1 is a private address wearing an IPv6 coat.
        self.assertIsNone(self.vet("https://[::ffff:192.168.1.1]/x"))

    def test_unspecified_and_broadcast_refused(self):
        self.assertIsNone(self.vet("https://0.0.0.0/x"))
        self.assertIsNone(self.vet("https://255.255.255.255/x"))

    def test_garbage_is_refused_without_raising(self):
        for url in ("", "not a url", "https://", "https:///x", "https://:443/x"):
            self.assertIsNone(self.vet(url), repr(url))

    def test_public_https_is_accepted_and_pinned(self):
        got = self.vet("https://8.8.8.8/download?size=25000000")
        self.assertIsNotNone(got)
        url, resolve = got
        self.assertEqual(url, "https://8.8.8.8/download?size=25000000")
        # The vetted address is pinned, so curl cannot resolve the name
        # again and be handed a different one.
        self.assertEqual(resolve, "8.8.8.8:443:8.8.8.8")

    def test_explicit_port_is_carried_into_the_pin(self):
        got = self.vet("https://8.8.8.8:8443/x")
        self.assertIsNotNone(got)
        self.assertEqual(got[1], "8.8.8.8:8443:8.8.8.8")

    def test_a_bad_target_costs_one_candidate_not_the_test(self):
        urls = ["http://93.184.216.34/a", "https://169.254.169.254/b",
                "https://8.8.8.8/c"]
        vetted = [v for v in (self.vet(u) for u in urls) if v]
        self.assertEqual(len(vetted), 1)
        self.assertEqual(vetted[0][0], "https://8.8.8.8/c")

    def test_curl_is_invoked_with_a_scheme_floor(self):
        # Belt and braces beside the vetting: curl itself refuses
        # anything but TLS, whatever it is handed.
        import inspect
        from nexthopd import speedtest
        src = inspect.getsource(speedtest._curl)
        self.assertIn('"--proto", "=https"', src)


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
                        dm.icmp_anchor.add(now - 60 + i, 15.0, False)
                    for i in range(MIN_LOAD_SPLIT_SAMPLES - 1):
                        dm.icmp_anchor.add(now - 5 + i * 0.1, 300.0, True)
                    b = dm.bufferbloat(300.0)
                    self.assertIsNotNone(b["idle"])
                    self.assertIsNotNone(b["loaded"])
                    self.assertIsNone(b["inflation"])
                    # One more loaded sample and the comparison is allowed.
                    dm.icmp_anchor.add(now, 300.0, True)
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
            self.daemon.icmp_anchor.add(now - 30 + i, 7.0)     # ICMP: fast-pathed
            self.daemon.app.add(now - 30 + i, 12.0)      # handshake: honest
        ap = self.daemon.app_path(300.0)
        self.assertTrue(ap["available"])
        self.assertAlmostEqual(ap["icmp_delta_ms"], 5.0, places=1)

    def test_anchor_that_refuses_443_reads_as_unavailable_not_broken(self):
        # Every sample failing is a fact about the target, not a fault in
        # the connection — it must not surface as 100% packet loss.
        now = time.time()
        for i in range(20):
            self.daemon.icmp_anchor.add(now - 20 + i, 8.0)
            self.daemon.app.add(now - 20 + i, None)
        ap = self.daemon.app_path(300.0)
        self.assertFalse(ap["available"])
        self.assertIsNone(ap["icmp_delta_ms"])

    def test_no_samples_yet_is_unavailable_without_a_delta(self):
        ap = self.daemon.app_path(300.0)
        self.assertFalse(ap["available"])
        self.assertIsNone(ap["icmp_delta_ms"])
        self.assertIsNone(ap["request"])

    def test_h3_target_follows_the_anchor(self):
        from nexthopd.daemon import h3_target
        # one.one.one.one IS 1.1.1.1 — the name exists so TLS can validate,
        # not to reach somewhere else.
        self.assertEqual(h3_target("1.1.1.1"), "one.one.one.one")
        self.assertEqual(h3_target("8.8.8.8"), "dns.google")
        self.assertEqual(h3_target("dns.example.net"), "dns.example.net")

    def test_unknown_bare_ip_anchor_is_skipped_not_redirected(self):
        from nexthopd.daemon import h3_target
        # Sending the sample to Cloudflare when the user chose another
        # anchor would measure a different path and a different operator.
        self.assertIsNone(h3_target("192.0.2.1"))
        self.daemon.config.values["internetAnchor"] = "192.0.2.1"
        self.daemon.sample_app_request()
        self.assertFalse(self.daemon.app_request["ok"])
        self.assertIn("skipped", self.daemon.app_request)

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
        grown = {k: v._replace(sent=v.sent + 1000, recv=v.recv + 3000)
                 for k, v in base.items()}
        t._fold(grown, 103.0)
        by_name = {a["name"]: a for a in t.rates}
        self.assertAlmostEqual(by_name["chrome"]["rx_bps"], 2 * 3000 / 3, delta=1)
        self.assertEqual(by_name["chrome"]["conns"], 2)
        self.assertEqual(by_name["slack"]["rx_total"], 3000)

    # ------------------------------------------------- kernel socket timing

    def guards(self):
        return (FIXTURES / "ss-rtt-guards.txt").read_text()

    def test_parse_ss_reads_kernel_timing(self):
        socks = parse_ss(self.fixture())
        slack = next(v for v in socks.values() if v.app == "slack")
        self.assertEqual(slack.srtt, 31.2)
        self.assertEqual(slack.minrtt, 29.004)
        self.assertEqual(slack.retrans, 108)
        # A socket the kernel has not timed reports None, never zero — zero
        # would read as "instant", which is the opposite of "unknown".
        untimed = parse_ss(
            'ESTAB 0 0 192.0.2.10:1 198.51.100.7:443 users:(("x",pid=9,fd=1))\n'
            '\t cubic bytes_sent:99999 bytes_received:99999\n')
        self.assertIsNone(next(iter(untimed.values())).srtt)
        self.assertIsNone(next(iter(untimed.values())).minrtt)

    def test_latency_stats_from_fixture(self):
        st = latency_stats(parse_ss(self.fixture()))
        self.assertEqual(st["sockets"], 3)
        self.assertEqual(st["rejected"], 0)
        self.assertEqual(st["rtt_p50"], 15.0)
        self.assertEqual(st["floor_p50"], 8.41)
        # Queueing is the median of 12.8-8.412, 31.2-29.004, 15.0-6.55.
        self.assertEqual(st["queue_p50"], 4.39)
        self.assertEqual(st["retrans_sockets"], 1)

    def test_queueing_divides_out_distance(self):
        """The point of the metric: a far socket and a near one with the
        same queueing must report the same queueing."""
        near = Sock("near", 1, 50_000, 50_000, srtt=15.0, minrtt=5.0)
        far = Sock("far", 2, 50_000, 50_000, srtt=310.0, minrtt=300.0)
        self.assertEqual(socket_timing(near)[2], socket_timing(far)[2])
        st = latency_stats({"a": near, "b": far,
                            "c": Sock("mid", 3, 50_000, 50_000,
                                      srtt=60.0, minrtt=50.0)})
        self.assertEqual(st["queue_p50"], 10.0)
        # ...while the raw round trips stay far apart, as they should.
        self.assertEqual(st["rtt_p50"], 60.0)
        self.assertEqual(st["floor_p50"], 50.0)

    def test_guards_reject_implausible_and_thin_sockets(self):
        socks = parse_ss(self.guards())
        self.assertEqual(len(socks), 7)
        st = latency_stats(socks)
        # good-a, good-b, good-c qualify.
        self.assertEqual(st["sockets"], 3)
        # tiny (under the byte floor), implausible (past the ceiling) and
        # inverted (floor above the average) are rejected...
        self.assertEqual(st["rejected"], 3)
        # ...but the socket the kernel simply has not timed is NOT counted as
        # a rejection: absent evidence is not bad evidence.
        untimed = [v for v in socks.values() if v.srtt is None]
        self.assertEqual(len(untimed), 1)
        self.assertEqual(st["retrans_sockets"], 1)

    def test_each_guard_individually(self):
        ok = Sock("ok", 1, 50_000, 50_000, srtt=20.0, minrtt=10.0)
        self.assertIsNotNone(socket_timing(ok))
        # Below the byte floor the path's own minimum is not trustworthy.
        self.assertIsNone(socket_timing(ok._replace(sent=100, recv=100)))
        # Plausibility ceiling: a broken measurement, not a slow link.
        self.assertIsNone(socket_timing(ok._replace(srtt=99_999.0)))
        # A floor above the average cannot happen; the field is stale.
        self.assertIsNone(socket_timing(ok._replace(minrtt=40.0)))
        # Rounding in `ss` output must not trip the inversion check.
        self.assertIsNotNone(socket_timing(ok._replace(srtt=20.0, minrtt=20.02)))
        # Zero or missing timing yields nothing rather than a zero RTT.
        self.assertIsNone(socket_timing(ok._replace(srtt=0.0)))
        self.assertIsNone(socket_timing(ok._replace(minrtt=None)))

    def test_under_sampled_publishes_nothing(self):
        two = {"a": Sock("a", 1, 50_000, 50_000, srtt=20.0, minrtt=10.0),
               "b": Sock("b", 2, 50_000, 50_000, srtt=22.0, minrtt=11.0)}
        # Two qualifying sockets is not a distribution.
        self.assertIsNone(latency_stats(two))
        three = dict(two, c=Sock("c", 3, 50_000, 50_000, srtt=24.0, minrtt=12.0))
        self.assertIsNotNone(latency_stats(three))
        self.assertIsNone(latency_stats({}))

    def test_per_app_timing_medians(self):
        t = AppTraffic()
        base = parse_ss(self.guards())
        t._fold(base, 100.0)
        t._fold({k: v._replace(sent=v.sent + 500, recv=v.recv + 500)
                 for k, v in base.items()}, 103.0)
        by_name = {a["name"]: a for a in t.rates}
        self.assertEqual(by_name["good-a"]["rtt_ms"], 20.0)
        self.assertEqual(by_name["good-a"]["queue_ms"], 10.0)
        self.assertEqual(by_name["good-c"]["queue_ms"], 20.0)
        # An app whose sockets all failed the guard reports no timing at all
        # rather than a fabricated zero.
        self.assertIsNone(by_name["tiny"]["rtt_ms"])
        self.assertIsNone(by_name["no-timing"]["rtt_ms"])
        self.assertIsNone(by_name["inverted"]["queue_ms"])
        # The aggregate rides along on the same fold.
        self.assertEqual(t.latency["sockets"], 3)

    def test_idle_apps_report_no_timing(self):
        t = AppTraffic()
        base = parse_ss(self.fixture())
        t._fold(base, 100.0)
        t._fold(base, 103.0)
        t._fold({}, 106.0)
        idle = {a["name"]: a for a in t.top()}
        # No live socket means no measurement, not a stale one.
        self.assertIsNone(idle["chrome"]["rtt_ms"])
        self.assertIsNone(idle["chrome"]["queue_ms"])

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


class StubEvents:
    """Stands in for NlEvents: answers cause_for() with a fixed cause."""

    def __init__(self, cause=None, raise_=False):
        self.cause, self.raise_, self.calls = cause, raise_, []

    def cause_for(self, bssid, now, window):
        self.calls.append((bssid, now, window))
        if self.raise_:
            raise RuntimeError("boom")
        return self.cause


class LinkAttribution(unittest.TestCase):
    """A BSSID change says who ended the previous association."""

    OLD = "aa:aa:aa:aa:aa:aa"
    NEW = "bb:bb:bb:bb:bb:bb"

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.dir.name) / "t.db")

    def tearDown(self):
        self.store.close()
        self.dir.cleanup()

    @staticmethod
    def cause(by_ap, reason, gap_s):
        return {"by_ap": by_ap, "reason": reason, "gap_s": gap_s,
                "frame": "deauth", "t": 0.0}

    def change(self, cause, raise_=False):
        events = StubEvents(cause, raise_)
        watch = LinkWatch(self.store, events)
        t = time.time()
        watch.sample(t, {"bssid": self.OLD, "ssid": "Office",
                         "channel": 149, "signal_dbm": -30})
        watch.sample(t + 2, {"bssid": self.NEW, "ssid": "Office",
                             "channel": 13, "signal_dbm": -53})
        evs = self.store.events()
        self.assertEqual(len(evs), 1)
        return evs[0], events

    def test_ap_deauth_is_a_kick(self):
        e, events = self.change(self.cause(True, 2, 3.0))
        self.assertEqual(e["kind"], "kick")
        self.assertIn("Kicked by AP " + self.OLD, e["detail"])
        self.assertIn("reason 2: previous authentication no longer valid",
                      e["detail"])
        self.assertIn("rejoined via " + self.NEW + " after 3 s", e["detail"])
        self.assertIn("channel 149 \u2192 13", e["detail"])
        self.assertIn("-30 \u2192 -53 dBm", e["detail"])
        # It asked about the AP we left, over a window reaching back to
        # when that link was last seen up.
        bssid, now, window = events.calls[0]
        self.assertEqual(bssid, self.OLD)
        self.assertGreaterEqual(window, 2.0)

    def test_local_deauth_with_instant_reauth_is_a_roam(self):
        # mac80211 emits the deauth from inside the call that starts the
        # new authentication, so a roam's gap is milliseconds.
        e, _ = self.change(self.cause(False, 1, 0.004))
        self.assertEqual(e["kind"], "roam")
        self.assertTrue(e["detail"].startswith("Roamed to " + self.NEW))

    def test_local_deauth_with_a_scan_first_is_a_drop(self):
        e, _ = self.change(self.cause(False, 4, 2.8))
        self.assertEqual(e["kind"], "drop")
        self.assertIn("Dropped by this machine (reason 4: beacon loss)",
                      e["detail"])
        self.assertIn("rejoined via " + self.NEW + " after 3 s", e["detail"])

    def test_unknown_cause_stays_a_roam(self):
        e, _ = self.change(None)
        self.assertEqual(e["kind"], "roam")
        self.assertTrue(e["detail"].startswith("Roamed to " + self.NEW))

    def test_without_an_event_source_nothing_changes(self):
        watch = LinkWatch(self.store)
        t = time.time()
        watch.sample(t, {"bssid": self.OLD, "ssid": "Office"})
        watch.sample(t + 2, {"bssid": self.NEW, "ssid": "Office"})
        self.assertEqual([e["kind"] for e in self.store.events()], ["roam"])

    def test_attribution_failure_never_costs_the_event(self):
        e, _ = self.change(self.cause(True, 2, 3.0), raise_=True)
        self.assertEqual(e["kind"], "roam")

    def test_kick_with_a_confirmed_gap_is_one_row(self):
        # Kicked, off the air long enough to count as disassociated, back
        # on the same radio: one row says all of that, not a bare
        # "Associated with".
        events = StubEvents(self.cause(True, 2, None))
        watch = LinkWatch(self.store, events)
        t = time.time()
        link = {"bssid": self.OLD, "ssid": "Office"}
        watch.sample(t, link)
        for i in range(LinkWatch.GAP_SAMPLES):
            watch.sample(t + 2 + i * 2, {})
        watch.sample(t + 14, link)
        evs = self.store.events()
        self.assertEqual([e["kind"] for e in evs], ["kick"])
        self.assertIn("rejoined after 14 s", evs[0]["detail"])
        self.assertNotIn(" via ", evs[0]["detail"])
        # The lookup window reached back to the last time the link was up.
        self.assertGreaterEqual(events.calls[-1][2], 14.0)

    def test_gap_nobody_claimed_is_a_plain_association(self):
        watch = LinkWatch(self.store, StubEvents(None))
        t = time.time()
        link = {"bssid": self.OLD, "ssid": "Office"}
        watch.sample(t, link)
        for i in range(LinkWatch.GAP_SAMPLES):
            watch.sample(t + 2 + i * 2, {})
        watch.sample(t + 14, link)
        self.assertEqual([e["kind"] for e in self.store.events()], ["associate"])


class NlEventParsing(unittest.TestCase):
    """`iw event -t` lines become causes; everything else is ignored."""

    AP = "02:11:22:33:44:05"
    ME = "02:aa:bb:cc:dd:ee"
    NEW = "02:11:22:33:44:09"

    def feed(self, lines):
        ev = NlEvents()
        for line in lines:
            ev.consume(line)
        return ev

    def test_ap_kick_then_rejoin_after_a_scan(self):
        ev = self.feed([
            "1000.000100: wlo1 (phy #0): deauth %s -> %s reason 2: "
            "Previous authentication no longer valid" % (self.AP, self.ME),
            "1000.000200: wlo1 (phy #0): disconnected (by AP) reason: 2: "
            "Previous authentication no longer valid",
            "1000.100000: wlo1 (phy #0): scan started",
            '1002.900000: wlo1 (phy #0): scan finished: 2412 2437, ""',
            "1003.000100: wlo1 (phy #0): auth %s -> %s status: 0: Successful"
            % (self.NEW, self.ME),
            "1003.010000: wlo1 (phy #0): assoc %s -> %s status: 0: Successful"
            % (self.NEW, self.ME),
            "1003.012000: wlo1 (phy #0): connected to %s" % self.NEW,
        ])
        c = ev.cause_for(self.AP, 1004.0, 30.0)
        self.assertTrue(c["by_ap"])
        self.assertEqual(c["reason"], 2)
        self.assertEqual(c["frame"], "deauth")
        self.assertAlmostEqual(c["gap_s"], 3.0, places=2)
        # The new AP ended nothing; and a cause ages out of the window.
        self.assertIsNone(ev.cause_for(self.NEW, 1004.0, 30.0))
        self.assertIsNone(ev.cause_for(self.AP, 1100.0, 30.0))

    def test_client_roam_is_local_and_instant(self):
        ev = self.feed([
            "2000.000000: wlo1 (phy #0): deauth %s -> %s reason 1: Unspecified"
            % (self.ME, self.AP),
            "2000.004000: wlo1 (phy #0): auth %s -> %s status: 0: Successful"
            % (self.NEW, self.ME),
        ])
        c = ev.cause_for(self.AP, 2001.0, 30.0)
        self.assertFalse(c["by_ap"])
        self.assertLess(c["gap_s"], LinkWatch.ROAM_FOLLOW_S)

    def test_ap_disassoc_counts_and_case_does_not_matter(self):
        ev = self.feed([
            "3000.5: wlo1 (phy #0): disassoc %s -> %s reason 4: Disassociated "
            "due to inactivity" % (self.AP.upper(), self.ME.upper()),
        ])
        c = ev.cause_for(self.AP, 3001.0, 10.0)
        self.assertEqual((c["by_ap"], c["reason"], c["frame"], c["gap_s"]),
                         (True, 4, "disassoc", None))

    def test_forged_and_junk_lines_are_ignored(self):
        ev = self.feed([
            "4000.0: wlo1 (phy #0): unprotected deauth %s -> %s reason 7: x"
            % (self.AP, self.ME),
            "4000.1: wlo1 (phy #0): deauth %s -> %s reason 99999999: x"
            % (self.AP, self.ME),
            "4000.2: wlo1 (phy #0): deauth not-a-mac -> %s reason 2: x" % self.ME,
            "garbage", "", "x" * 5000,
        ])
        self.assertIsNone(ev.cause_for(self.AP, 4001.0, 1e9))

    def test_untimestamped_lines_take_the_clock_given(self):
        ev = NlEvents()
        ev.consume("wlo1: deauth %s -> %s reason 3: Leaving" % (self.ME, self.AP),
                   now=5000.0)
        ev.consume("wlo1: connected to %s" % self.NEW, now=5002.5)
        c = ev.cause_for(self.AP, 5003.0, 10.0)
        self.assertEqual((c["by_ap"], c["reason"]), (False, 3))
        self.assertAlmostEqual(c["gap_s"], 2.5, places=3)

    def test_follow_up_binds_to_the_newest_cause_only(self):
        ev = self.feed([
            "6000.0: wlo1 (phy #0): deauth %s -> %s reason 2: x" % (self.AP, self.ME),
            "6001.0: wlo1 (phy #0): auth %s -> %s status: 0: Successful"
            % (self.NEW, self.ME),
            "6002.0: wlo1 (phy #0): assoc %s -> %s status: 0: Successful"
            % (self.NEW, self.ME),
        ])
        self.assertAlmostEqual(ev.cause_for(self.AP, 6003.0, 10.0)["gap_s"], 1.0)

    def test_reason_words_depend_on_who_sent_it(self):
        self.assertEqual(reason_text(4, True), "reason 4: inactivity")
        self.assertEqual(reason_text(4, False), "reason 4: beacon loss")
        self.assertEqual(reason_text(3, True), "reason 3: the AP is leaving")
        self.assertEqual(reason_text(8, True), "reason 8: the AP is leaving the BSS")
        self.assertEqual(reason_text(8, False), "reason 8: leaving the BSS")
        self.assertIn("previous authentication", reason_text(2, True))
        self.assertEqual(reason_text(250, True), "reason 250")


class NlEventRecording(unittest.TestCase):
    """A real kick, recorded with `iw event -t` on an Intel BE201 while the
    gateway ran `iwpriv ra1 set DisConnectSta=<this laptop>`: the AP's
    deauth, a scan, and the re-association on another radio 2.9 s later.
    Addresses are substituted; timings and formats are as recorded."""

    OLD = "02:11:22:33:44:01"
    NEW = "02:11:22:33:44:05"

    def setUp(self):
        path = Path(__file__).parent / "fixtures" / "iw-event.txt"
        self.lines = path.read_text().splitlines()
        self.events = NlEvents()
        for line in self.lines:
            self.events.consume(line)

    def test_recording_parses_as_an_ap_kick(self):
        c = self.events.cause_for(self.OLD, 1788278083.0, 30.0)
        self.assertEqual((c["by_ap"], c["reason"], c["frame"]),
                         (True, 8, "deauth"))
        self.assertAlmostEqual(c["gap_s"], 2.93, places=1)
        # The radio we landed on ended nothing.
        self.assertIsNone(self.events.cause_for(self.NEW, 1788278083.0, 30.0))

    def test_link_watch_logs_it_as_one_kick(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        store = Store(Path(d.name) / "t.db")
        self.addCleanup(store.close)
        watch = LinkWatch(store, self.events)
        watch.sample(1788278078.0, {"bssid": self.OLD, "ssid": "x",
                                    "channel": 1, "signal_dbm": -30})
        watch.sample(1788278083.0, {"bssid": self.NEW, "ssid": "x",
                                    "channel": 149, "signal_dbm": -40})
        evs = store.events()
        self.assertEqual([e["kind"] for e in evs], ["kick"])
        self.assertEqual(
            evs[0]["detail"],
            "Kicked by AP 02:11:22:33:44:01 (reason 8: the AP is leaving the "
            "BSS), rejoined via 02:11:22:33:44:05 after 3 s, "
            "channel 1 \u2192 149, -30 \u2192 -40 dBm")


class TraceParsing(unittest.TestCase):
    """The cdn-cgi/trace response yields one validated address or nothing."""

    def test_recorded_response(self):
        # Recorded from a real fetch of speed.cloudflare.com/cdn-cgi/trace
        # (address substituted): sixteen key=value lines, ip= among them.
        text = (FIXTURES / "cf-trace.txt").read_text()
        self.assertEqual(net.parse_trace(text),
                         {"ip": "198.51.100.7", "family": "v4"})

    def test_v6_is_labelled(self):
        self.assertEqual(net.parse_trace("h=x\nip=2001:db8::7\nts=1\n"),
                         {"ip": "2001:db8::7", "family": "v6"})

    def test_only_a_real_address_gets_out(self):
        # Whatever else the response holds must never reach the shell.
        self.assertIsNone(net.parse_trace("ip=<b>not-an-ip</b>\n"))
        self.assertIsNone(net.parse_trace("ip=1.2.3.4.5\n"))
        self.assertIsNone(net.parse_trace("h=x\nts=1\n"))
        self.assertIsNone(net.parse_trace(""))

    def test_input_is_bounded_before_parsing(self):
        # An ip= line beyond the size cap is as good as absent.
        self.assertIsNone(net.parse_trace("x=" + "a" * 5000 + "\nip=1.2.3.4\n"))
        self.assertIsNone(net.parse_trace("k=v\n" * 100 + "ip=1.2.3.4\n"))


class WanArbitration(unittest.TestCase):
    """Eight lost pings say the anchor went quiet; only both probes
    failing say the internet did."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.dir.name) / "t.db")
        self.notices = []
        self.arb = WanEventArbiter(
            self.store, lambda *a, **k: self.notices.append(a))

    def tearDown(self):
        self.store.close()
        self.dir.cleanup()

    def test_quiet_when_tcp_still_answers(self):
        t = time.time()
        self.arb.down(t, app_ok=True)
        self.assertFalse(self.arb.real_outage)
        self.assertEqual(self.notices, [])       # the user's internet works
        self.arb.up(t + 30)
        evs = self.store.events()
        self.assertEqual([e["kind"] for e in evs], ["icmp-quiet"])
        self.assertIsNotNone(evs[0]["ended_ts"])
        self.assertEqual(self.notices, [])

    def test_outage_when_both_probes_fail(self):
        t = time.time()
        self.arb.down(t, app_ok=False)
        self.assertTrue(self.arb.real_outage)
        self.assertEqual(len(self.notices), 1)
        self.arb.up(t + 30)
        self.assertEqual([e["kind"] for e in self.store.events()], ["outage"])
        self.assertEqual(len(self.notices), 2)   # down + recovered

    def test_escalates_one_way_when_tcp_stops_too(self):
        t = time.time()
        self.arb.down(t, app_ok=True)
        self.arb.tick(t + 2, app_ok=True)        # still quiet, still no alarm
        self.assertEqual(self.notices, [])
        self.arb.tick(t + 5, app_ok=False)       # now it is an outage
        self.assertTrue(self.arb.real_outage)
        self.assertEqual(len(self.notices), 1)
        self.arb.up(t + 60)
        evs = self.store.events()
        self.assertEqual(sorted(e["kind"] for e in evs),
                         ["icmp-quiet", "outage"])
        for e in evs:
            self.assertIsNotNone(e["ended_ts"])

    def test_quiet_never_charges_reliability(self):
        t = time.time()
        self.arb.down(t, app_ok=True)
        self.arb.up(t + 600)
        self.assertEqual(self.store.outage_stats(3600, now=t + 700),
                         (0.0, 0, 0.0))


def _st(count=60, loss=0.0, p50=20.0, p95=30.0):
    return {"count": count, "loss": loss, "p50": p50, "p95": p95}


class InstrumentRanking(unittest.TestCase):
    def test_loss_dominates_then_spread_then_median(self):
        clean = penalty(_st(loss=0.0, p50=20, p95=30))
        lossy = penalty(_st(loss=0.05, p50=10, p95=12))
        wobbly = penalty(_st(loss=0.0, p50=20, p95=200))
        slower = penalty(_st(loss=0.0, p50=60, p95=70))
        self.assertLess(clean, lossy)      # 5% loss loses to 10 ms spread
        self.assertLess(clean, wobbly)     # tail spread beats nothing
        self.assertLess(clean, slower)     # median only as tiebreak
        self.assertLess(slower, wobbly)    # 40 ms slower < 170 ms wobblier

    def test_too_few_samples_judge_nothing(self):
        self.assertIsNone(penalty(_st(count=Bench.MIN_SAMPLES - 1)))
        self.assertIsNone(penalty(None))
        self.assertIsNone(penalty({}))

    def test_full_loss_is_dead_not_slow(self):
        dead = penalty({"count": 60, "loss": 1.0, "p50": None, "p95": None})
        self.assertGreaterEqual(dead, Bench.DEAD_AT)


class BenchSeats(unittest.TestCase):
    POOL = [("icmp-a", "icmp", "1.1.1.1"), ("tcp-a", "tcp", "1.1.1.1:443"),
            ("tcp-b", "tcp", "cf:443"), ("tcp-c", "tcp", "google:443")]

    def bench(self):
        return Bench(self.POOL)

    def keys(self, b):
        return sorted(i.key for i in b.actives())

    def test_first_two_start_seated(self):
        self.assertEqual(self.keys(self.bench()), ["icmp-a", "tcp-a"])

    def test_dead_seat_is_replaced_immediately(self):
        b = self.bench()
        stats = {"icmp-a": _st(), "tcp-a": _st(loss=1.0, p50=None, p95=None),
                 "tcp-b": _st(p50=25, p95=35), "tcp-c": _st(p50=40, p95=60)}
        changes = b.evaluate(1000.0, stats)
        self.assertEqual(sorted(changes), [("tcp-a", False), ("tcp-b", True)])
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-b"])

    def test_no_churn_during_a_full_outage(self):
        b = self.bench()
        dead = _st(loss=1.0, p50=None, p95=None)
        stats = {k: dict(dead) for k in ("icmp-a", "tcp-a", "tcp-b", "tcp-c")}
        self.assertEqual(b.evaluate(1000.0, stats), [])
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-a"])

    def test_challenger_needs_two_consecutive_clear_wins(self):
        b = self.bench()
        # tcp-b is 20%+ better than the worst seat; one win is not enough.
        stats = {"icmp-a": _st(p50=10, p95=14), "tcp-a": _st(p50=100, p95=160),
                 "tcp-b": _st(p50=20, p95=24), "tcp-c": _st(p50=90, p95=150)}
        self.assertEqual(b.evaluate(1000.0, stats), [])
        changes = b.evaluate(1000.0 + Bench.RESELECT_EVERY_S, stats)
        self.assertEqual(sorted(changes), [("tcp-a", False), ("tcp-b", True)])
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-b"])

    def test_a_win_streak_broken_starts_over(self):
        b = self.bench()
        better = {"icmp-a": _st(p50=10, p95=14), "tcp-a": _st(p50=100, p95=160),
                  "tcp-b": _st(p50=20, p95=24), "tcp-c": _st(p50=90, p95=150)}
        level = {"icmp-a": _st(p50=10, p95=14), "tcp-a": _st(p50=19, p95=24),
                 "tcp-b": _st(p50=20, p95=24), "tcp-c": _st(p50=90, p95=150)}
        t = 1000.0
        self.assertEqual(b.evaluate(t, better), [])
        self.assertEqual(b.evaluate(t + 300, level), [])   # streak broken
        self.assertEqual(b.evaluate(t + 600, better), [])  # back to one win
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-a"])

    def test_flapping_instrument_is_quarantined(self):
        b = self.bench()
        inst = b.instruments["tcp-b"]
        t = 1000.0
        # Three seat changes inside an hour is a flap.
        for k, active in (("tcp-b", True), ("tcp-b", False), ("tcp-b", True)):
            b._seat(inst, t, active)
            t += 60
        self.assertGreater(inst.quarantined_until, t)
        # While quarantined it cannot be promoted, even over a corpse.
        b._seat(inst, t, False)
        stats = {"icmp-a": _st(), "tcp-a": _st(loss=1.0, p50=None, p95=None),
                 "tcp-b": _st(p50=5, p95=6), "tcp-c": _st(p50=40, p95=60)}
        b.evaluate(t + 60, stats)
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-c"])

    def test_snapshot_names_the_seats(self):
        b = self.bench()
        snap = b.snapshot(1000.0, {"icmp-a": _st(p50=7)})
        by_key = {row["key"]: row for row in snap}
        self.assertTrue(by_key["icmp-a"]["active"])
        self.assertEqual(by_key["icmp-a"]["p50"], 7)
        self.assertFalse(by_key["tcp-c"]["active"])
        self.assertEqual(len(snap), 4)


class MergedView(unittest.TestCase):
    def test_merges_and_orders_the_seated_series(self):
        from nexthopd.probes import Series
        a, c = Series(), Series()
        now = time.time()
        a.add(now - 3, 10.0)
        c.add(now - 2, None)
        a.add(now - 1, 12.0)
        m = MergedSeries(lambda: [a, c])
        self.assertEqual([s[1] for s in m.since(10)], [10.0, None, 12.0])
        self.assertEqual(len(m.all()), 3)
        m2 = MergedSeries(lambda: [a])
        self.assertEqual(len(m2.since(10)), 2)


class MinuteProvenance(unittest.TestCase):
    def test_minute_rows_carry_basis_and_seats(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        store = Store(Path(d.name) / "t.db")
        self.addCleanup(store.close)
        ts = int(time.time() // 60) * 60
        store.put_minute(ts, {"lag": 30.0, "lag_icmp": 24.0},
                         iface="wlo1", network="x", probes="icmp-anchor+tcp-cf")
        rows, _ = store.series(3600)
        row = rows[-1]
        self.assertEqual(row["lag_icmp"], 24.0)
        self.assertEqual(row["probes"], "icmp-anchor+tcp-cf")

    def test_old_databases_gain_the_columns(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = Path(d.name) / "t.db"
        import sqlite3 as sq
        from nexthopd.store import SAMPLE_COLUMNS
        old_cols = ", ".join(f"{c} REAL" for c in SAMPLE_COLUMNS
                             if c != "lag_icmp")
        db = sq.connect(path)
        db.execute(f"CREATE TABLE minute (ts INTEGER PRIMARY KEY, {old_cols}, "
                   "iface TEXT, network TEXT)")
        db.commit(); db.close()
        store = Store(path)
        self.addCleanup(store.close)
        store.put_minute(60, {"lag": 1.0}, probes="a+b")   # must not raise


class UpdateNotice(unittest.TestCase):
    """The update check reports; it must never act, and never trust a remote
    string far enough to hand it to a subprocess unchecked."""

    A = "a" * 40
    B = "b" * 40

    def test_verdict_states(self):
        self.assertEqual(verdict(self.A, self.A, True, False, False), "current")
        # Origin holds a commit we have never seen.
        self.assertEqual(verdict(self.A, self.B, False, False, False), "behind")
        # THE CASE THAT MATTERS: `omarchy plugin update` fetches before it
        # shows its diff, so a user who looked and declined already holds
        # origin's commit while still being behind it. Deciding from "we have
        # never seen that object" alone would show that user nothing.
        self.assertEqual(verdict(self.A, self.B, True, True, False), "behind")
        # A developer checkout ahead of origin must not be nagged.
        self.assertEqual(verdict(self.A, self.B, True, False, True), "ahead")
        self.assertEqual(verdict(self.A, self.B, True, False, False), "diverged")
        # Not knowing is its own answer, not a guess in either direction.
        self.assertEqual(verdict("", self.B, False, False, False), "unknown")
        self.assertEqual(verdict(self.A, "", False, False, False), "unknown")

    def test_remote_sha_must_be_an_object_id(self):
        # This is the guard that matters: the value arrives from the network
        # and is then passed as an argument to git.
        for bad in ("", "HEAD", "a" * 39, "a" * 41, "A" * 40, "g" * 40,
                    "../../etc/passwd", "a" * 40 + " --upload-pack=sh",
                    "--upload-pack=evil", "a" * 40 + "\n" + "b" * 40):
            self.assertIsNone(RE_SHA.match(bad), bad)
        self.assertIsNotNone(RE_SHA.match(self.A))

    def test_junk_from_the_remote_yields_unknown_not_a_crash(self):
        w = UpdateWatch(repo=REPO)
        calls = []

        def fake(*args, capture=True):
            calls.append(args)
            if args[0] == "rev-parse":
                return 0, self.A
            if args[0] == "ls-remote":
                return 0, "not-a-sha\tHEAD"
            return 0, ""

        w._git = fake
        self.assertEqual(w.check(), "unknown")
        # Having refused the answer, it must not go on to use it.
        self.assertNotIn("cat-file", [c[0] for c in calls])

    def test_behind_is_reported_without_any_write(self):
        w = UpdateWatch(repo=REPO)
        seen = []

        def fake(*args, capture=True):
            seen.append(args[0])
            if args[0] == "rev-parse":
                return 0, self.A
            if args[0] == "ls-remote":
                return 0, self.B + "\tHEAD"
            if args[0] == "cat-file":
                return 1, ""          # we do not hold origin's commit
            return 0, ""

        w._git = fake
        self.assertEqual(w.check(), "behind")
        # Every git verb used must be read-only. A fetch, pull, merge or
        # checkout here would make this self-updating code.
        self.assertTrue(set(seen) <= {"rev-parse", "ls-remote", "cat-file",
                                      "merge-base"}, seen)

    def test_cadence_delays_the_first_check_and_then_spaces_them(self):
        w = UpdateWatch(repo=REPO)
        w.check = lambda: "behind"
        w.tick(1000.0)
        # Nothing on the first tick: the daemon restarts with the shell, and
        # a check on every restart would be noise.
        self.assertIsNone(w.checked_ts)
        w.tick(1000.0 + 299)
        self.assertIsNone(w.checked_ts)
        w.tick(1000.0 + 301)
        self.assertEqual(w.state, "behind")
        self.assertTrue(w.snapshot()["available"])
        # ...and then not again for a day.
        first = w.checked_ts
        w.check = lambda: "current"
        w.tick(1000.0 + 3600)
        self.assertEqual(w.checked_ts, first)
        w.tick(1000.0 + 301 + 24 * 3600 + 1)
        self.assertEqual(w.state, "current")
        self.assertFalse(w.snapshot()["available"])

    def test_disabled_makes_no_check_and_clears_any_notice(self):
        w = UpdateWatch(repo=REPO)
        w.check = lambda: "behind"
        w.tick(1000.0)
        w.tick(1000.0 + 301)
        self.assertTrue(w.snapshot()["available"])
        # Turning the setting off must retract the notice, not leave a stale
        # one on screen.
        w.enabled = False
        called = []
        w.check = lambda: called.append(1) or "behind"
        w.tick(1000.0 + 301 + 24 * 3600 + 1)
        self.assertEqual(called, [])
        self.assertIsNone(w.snapshot())

    def test_nothing_published_until_something_is_known(self):
        w = UpdateWatch(repo=REPO)
        self.assertIsNone(w.snapshot())

    def test_real_checkout_is_read_only_and_answers(self):
        """Against this actual repository: a real answer, and the working
        tree and refs are untouched afterwards."""
        before = subprocess.run(["git", "-C", str(REPO), "status",
                                 "--porcelain"], capture_output=True, text=True)
        head_before = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                                     capture_output=True, text=True).stdout
        w = UpdateWatch(repo=REPO)
        self.assertIn(w.check(), ("current", "behind", "ahead", "diverged",
                                  "unknown"))
        after = subprocess.run(["git", "-C", str(REPO), "status",
                                "--porcelain"], capture_output=True, text=True)
        head_after = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                                    capture_output=True, text=True).stdout
        self.assertEqual(before.stdout, after.stdout)
        self.assertEqual(head_before, head_after)

    def test_real_clone_one_commit_behind_reports_behind(self):
        """End to end against real git: a checkout that already holds
        origin's commit but sits one behind it must offer the update."""
        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp) / "c"
            r = subprocess.run(["git", "clone", "--quiet", str(REPO), str(clone)],
                               capture_output=True)
            if r.returncode != 0:
                self.skipTest("git clone unavailable")
            head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD~1"],
                                  capture_output=True, text=True)
            if head.returncode != 0:
                self.skipTest("shallow history")
            subprocess.run(["git", "-C", str(clone), "reset", "--quiet",
                            "--hard", "HEAD~1"], check=True,
                           capture_output=True)
            w = UpdateWatch(repo=clone)
            self.assertEqual(w.check(), "behind")
            self.assertTrue(w.snapshot() is None)   # nothing until tick() runs
            w.tick(1000.0)
            w.tick(1000.0 + 301)
            self.assertTrue(w.snapshot()["available"])

    def test_config_default_is_on_and_validates_as_a_boolean(self):
        cfg = Config.SCHEMA["updateCheck"]
        self.assertTrue(cfg[0])
        self.assertIs(cfg[1](True), True)
        self.assertIs(cfg[1](False), False)
        # A wrong type falls back to the default rather than being coerced,
        # the same rule every other setting follows.
        self.assertIsNone(cfg[1]("yes"))

    def test_manifest_exposes_the_setting(self):
        m = json.loads((REPO / "manifest.json").read_text())
        entry = next(e for e in m["barWidget"]["schema"]
                     if e["key"] == "updateCheck")
        self.assertEqual(entry["type"], "boolean")
        self.assertIs(entry["defaultValue"], True)
        self.assertIn("never installs", entry["description"])


class FakeStore:
    def __init__(self):
        self.opened = []
        self.closed = []

    def open_event(self, ts, kind, sev, leg, detail):
        self.opened.append((kind, sev, leg, detail))
        return len(self.opened)

    def close_event(self, event_id, ts):
        self.closed.append(event_id)


class LocalArbitration(unittest.TestCase):
    """A gateway that refuses pings is not a gateway that is unreachable.

    This is the hotel case: every local ping lost, ROUTER UNREACHABLE on
    screen, and the machine online the whole time.
    """

    def setUp(self):
        self.store = FakeStore()
        self.notes = []
        self.arb = LocalEventArbiter(
            self.store, lambda *a, **k: self.notes.append(a))

    def test_silent_gateway_with_traffic_crossing_it_is_not_an_outage(self):
        self.arb.down(100.0, beyond_ok=True)
        self.assertEqual(self.arb.kind, "gateway-quiet")
        self.assertFalse(self.arb.real_outage)
        kind, sev, leg, _ = self.store.opened[0]
        self.assertEqual((kind, sev, leg), ("gateway-quiet", "warn", "local"))
        # Warn-toned and unnotified: the user experienced nothing.
        self.assertEqual(self.notes, [])

    def test_nothing_answering_anywhere_is_a_real_outage(self):
        self.arb.down(100.0, beyond_ok=False)
        self.assertEqual(self.arb.kind, "outage")
        self.assertTrue(self.arb.real_outage)
        self.assertEqual(self.store.opened[0][0:3],
                         ("outage", "critical", "local"))
        self.assertEqual(len(self.notes), 1)

    def test_escalation_is_one_way(self):
        self.arb.down(100.0, beyond_ok=True)
        # The far side goes quiet too: an outage starting mid-spell must alarm.
        self.arb.tick(110.0, beyond_ok=False)
        self.assertTrue(self.arb.real_outage)
        self.assertEqual(len(self.notes), 1)
        # Nothing walks it back down again — flapping teaches people to
        # ignore both verdicts.
        self.arb.tick(120.0, beyond_ok=True)
        self.assertTrue(self.arb.real_outage)

    def test_recovery_only_notifies_for_a_real_outage(self):
        self.arb.down(100.0, beyond_ok=True)
        self.arb.up(130.0)
        self.assertEqual(self.notes, [])
        self.assertIsNone(self.arb.kind)
        self.arb.down(200.0, beyond_ok=False)
        self.arb.up(230.0)
        self.assertEqual(len(self.notes), 2)   # down + recovered


class UnknownWanLeg(unittest.TestCase):
    def test_missing_local_yields_unknown_not_the_whole_round_trip(self):
        total = {"count": 500, "p50": 3.5, "p75": 4.0, "p95": 18.0,
                 "max": 26.0, "loss": 0.0, "jitter": 4.8, "last": 3.5}
        gone = {"count": 0, "p50": None, "p75": None, "p95": None,
                "max": None, "loss": 1.0, "jitter": None, "last": None}
        w = score.wan_from(total, gone)
        # Substituting zero used to make the derived leg equal the total, so
        # a silent gateway produced a confident healthy internet figure that
        # was really the whole round trip wearing the wan leg's label.
        for key in ("p50", "p75", "p95", "max"):
            self.assertIsNone(w[key], key)

    def test_known_local_still_subtracts(self):
        total = {"count": 500, "p50": 10.0, "p75": 12.0, "p95": 20.0,
                 "max": 30.0, "loss": 0.0, "jitter": 1.0, "last": 10.0}
        local = {"count": 500, "p50": 2.0, "p75": 2.5, "p95": 5.0,
                 "max": 8.0, "loss": 0.0, "jitter": 0.4, "last": 2.0}
        w = score.wan_from(total, local)
        self.assertEqual(w["p50"], 8.0)
        self.assertGreaterEqual(w["p95"], w["p50"])


class LagBand(unittest.TestCase):
    def test_one_scale_so_the_range_cannot_read_backwards(self):
        # The reported case: "best 4 · typical 644 ms · worst 26" — two raw
        # round trips either side of a loss-charged composite.
        lossy = {"count": 500, "p50": 3.5, "p75": 4.0, "p95": 18.0,
                 "max": 26.0, "loss": 1.0, "jitter": 4.8}
        b = score.lag_band(lossy)
        self.assertLessEqual(b["best"], b["typical"])
        self.assertLessEqual(b["typical"], b["worst"])
        # Loss moves all three together, which is what a range implies.
        self.assertGreater(b["best"], 1000)

    def test_monotonic_across_loss_levels_and_degenerate_windows(self):
        base = {"count": 500, "p50": 5.0, "p75": 5.0, "p95": 5.0,
                "max": 5.0, "jitter": 0.0}
        for loss in (0.0, 0.01, 0.35, 1.0):
            b = score.lag_band(dict(base, loss=loss))
            vals = [b["best"], b["typical"], b["worst"]]
            self.assertEqual(vals, sorted(vals), loss)

    def test_no_samples_reports_nothing(self):
        b = score.lag_band({"count": 0})
        self.assertEqual(b, {"best": None, "typical": None, "worst": None})


class CaptiveDetection(unittest.TestCase):
    """Replies prove a packet came back, not what sent it."""

    def test_trace_verdicts(self):
        self.assertEqual(trace_verdict("fl=1\nip=103.87.1.2\nts=2"), "open")
        # A portal answering with its sign-in page.
        self.assertEqual(trace_verdict("<html>Please sign in</html>"),
                         "intercepted")
        self.assertEqual(trace_verdict("ip=not-an-address"), "intercepted")
        # Nothing came back at all, which is a different thing.
        self.assertEqual(trace_verdict(""), "silent")
        self.assertEqual(trace_verdict(None), "silent")

    def test_needs_both_halves_of_the_evidence(self):
        c = CaptiveWatch.captive
        # Replies but no proof of internet, confirmed: that is a portal.
        self.assertTrue(c("intercepted", True, 2))
        self.assertTrue(c("silent", True, 2))
        # Proof of internet: never captive, however many strikes.
        self.assertFalse(c("open", True, 9))
        # Nothing answering at all is an outage, not a sign-in page — a
        # portal prompt in front of a dead line would be worse than silence.
        self.assertFalse(c("intercepted", False, 9))
        # One failed fetch is a failed fetch.
        self.assertFalse(c("intercepted", True, 1))

    def test_confirms_on_the_second_check_and_clears_on_proof(self):
        answers = ["intercepted", "intercepted", "open"]
        calls = []

        def check():
            v = answers[min(len(calls), len(answers) - 1)]
            calls.append(v)
            return {"verdict": v, "proof": None}

        w = CaptiveWatch(check)
        w.tick(1000.0, probes_answering=True)
        self.assertFalse(w.confirmed)          # one strike
        w.tick(1000.0 + 31, probes_answering=True)
        self.assertTrue(w.confirmed)
        self.assertTrue(w.snapshot()["captive"])
        # Proof of the real internet retracts it immediately.
        w.tick(1000.0 + 62, probes_answering=True)
        self.assertFalse(w.confirmed)
        self.assertEqual(w.verdict, "open")

    def test_rate_limited_between_checks(self):
        calls = []

        def check():
            calls.append(1)
            return {"verdict": "intercepted", "proof": None}

        w = CaptiveWatch(check)
        w.tick(1000.0, True)
        w.tick(1001.0, True)
        w.tick(1029.0, True)
        self.assertEqual(len(calls), 1)        # 30 s floor holds
        w.tick(1031.0, True)
        self.assertEqual(len(calls), 2)

    def test_suspicion_drops_when_nothing_answers(self):
        w = CaptiveWatch(lambda: {"verdict": "intercepted", "proof": None})
        w.tick(1000.0, True)
        w.tick(1031.0, True)
        self.assertTrue(w.confirmed)
        # The line goes down for real: hand it to the outage path.
        w.tick(1062.0, probes_answering=False)
        self.assertFalse(w.confirmed)
        self.assertEqual(w.strikes, 0)

    def test_publishes_nothing_before_it_knows_anything(self):
        w = CaptiveWatch(lambda: {"verdict": "open", "proof": None})
        self.assertIsNone(w.snapshot())


class OutagePresentation(unittest.TestCase):
    """What the panel may say when nothing is replying."""

    DEAD = {"count": 60, "p50": None, "p75": None, "p95": None,
            "max": None, "loss": 1.0, "jitter": None}

    def test_scoring_keeps_its_anchor(self):
        # Responsiveness must still land on zero, which is what 1500 is for.
        self.assertEqual(score.lag_ms(self.DEAD), 1500.0)
        self.assertEqual(score.responsiveness(score.lag_ms(self.DEAD)), 0.0)

    def test_display_band_shows_nothing_rather_than_the_anchor(self):
        # 1500 is an anchor, not a round trip. The panel printed it three
        # times as "best 1500 · typical 1500 ms · worst 1500", which says
        # the link is replying slowly when it is not replying.
        self.assertEqual(score.lag_band(self.DEAD),
                         {"best": None, "typical": None, "worst": None})

    def test_partial_loss_still_reports_a_band(self):
        lossy = {"count": 500, "p50": 5.0, "p75": 6.0, "p95": 20.0,
                 "max": 30.0, "loss": 0.4, "jitter": 1.0}
        b = score.lag_band(lossy)
        self.assertIsNotNone(b["typical"])
        self.assertLessEqual(b["best"], b["typical"])
        self.assertLessEqual(b["typical"], b["worst"])


class RouteChangeKeepsHistoryThroughAnOutage(unittest.TestCase):
    """Losing the route must not discard the window that explains why."""

    def test_no_gateway_is_an_outage_not_a_new_network(self):
        import types
        from nexthopd import daemon as dmod

        calls = {"reset": 0}
        d = types.SimpleNamespace(
            config={"internetAnchor": "1.1.1.1"},
            route={"gateway": "192.168.1.1", "iface": "wlan0"},
            probes=[],
        )

        def fake_route_to(anchor):
            return fake_route_to.answer

        original = dmod.net.route_to
        dmod.net.route_to = fake_route_to
        try:
            # Bind the real method to our stand-in object and count resets
            # by watching for the attribute the reset path writes first.
            def start_probes():
                calls["reset"] += 1
            d.start_probes = start_probes
            d._new_instrument_series = lambda: None
            d.counter_samples = []
            d.wan_ip = "x"
            d._wan_ip_at = 1.0
            d._instrument_probes = {}
            d.local = object()

            # The route vanishes: no reset, history kept, probes untouched.
            fake_route_to.answer = {}
            dmod.Daemon.restart_probes_if_route_changed(d)
            self.assertEqual(calls["reset"], 0)
            self.assertEqual(d.route, {"gateway": "192.168.1.1",
                                       "iface": "wlan0"})
            self.assertEqual(d.wan_ip, "x")

            # It comes back on the same network: still no reset.
            fake_route_to.answer = {"gateway": "192.168.1.1",
                                    "iface": "wlan0"}
            dmod.Daemon.restart_probes_if_route_changed(d)
            self.assertEqual(calls["reset"], 0)

            # A genuinely different network does reset, exactly once.
            fake_route_to.answer = {"gateway": "10.0.0.1", "iface": "wlan0"}
            dmod.Daemon.restart_probes_if_route_changed(d)
            self.assertEqual(calls["reset"], 1)
            self.assertIsNone(d.wan_ip)
        finally:
            dmod.net.route_to = original
