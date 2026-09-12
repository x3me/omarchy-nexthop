"""Tests for score.py — the anchor tables, the folds, and the wrong-direction sweep.

Run: python3 -m unittest discover -s test
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd import score  # noqa: E402


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


class DrainAfterLoad(unittest.TestCase):
    """Depth is what everyone reports; duration is what you feel after the
    download has finished."""

    def test_measures_from_the_last_loaded_sample(self):
        sm = [(1, 10, False), (2, 10, False), (3, 60, True), (4, 80, True),
              (5, 70, True), (5.4, 40, False), (6.2, 12, False),
              (7, 10, False)]
        d = score.drain_after_load(sm, 10.0)
        # Load ended at t=5; latency was back inside tolerance at t=6.2.
        self.assertEqual(d["ms"], 1200.0)
        self.assertTrue(d["settled"])

    def test_tolerance_not_exactness(self):
        # A queue does not empty to the exact millisecond it started from.
        sm = [(1, 10, True), (2, 12.4, False)]
        self.assertTrue(score.drain_after_load(sm, 10.0)["settled"])
        sm = [(1, 10, True), (2, 20.0, False)]
        self.assertFalse(score.drain_after_load(sm, 10.0)["settled"])

    def test_still_under_load_says_nothing(self):
        sm = [(1, 10, False), (2, 80, True)]
        self.assertIsNone(score.drain_after_load(sm, 10.0)["ms"])

    def test_no_burst_says_nothing(self):
        sm = [(1, 10, False), (2, 11, False)]
        self.assertIsNone(score.drain_after_load(sm, 10.0)["ms"])

    def test_unrecovered_reports_a_floor_not_a_recovery(self):
        sm = [(1, 10, True), (2, 90, False), (3, 88, False), (4, 86, False)]
        d = score.drain_after_load(sm, 10.0)
        self.assertEqual(d["ms"], 3000.0)
        self.assertFalse(d["settled"])   # never came back

    def test_beyond_the_cap_is_not_a_drain(self):
        sm = [(0, 10, True), (score.DRAIN_MAX_S + 5, 10, False)]
        self.assertIsNone(score.drain_after_load(sm, 10.0)["ms"])

    def test_lost_probes_are_skipped_not_treated_as_recovery(self):
        sm = [(1, 90, True), (2, None, False), (3, None, False),
              (4, 11, False)]
        d = score.drain_after_load(sm, 10.0)
        self.assertEqual(d["ms"], 3000.0)
        self.assertTrue(d["settled"])

    def test_no_baseline_no_claim(self):
        sm = [(1, 90, True), (2, 10, False)]
        self.assertIsNone(score.drain_after_load(sm, None)["ms"])
        self.assertIsNone(score.drain_after_load(sm, 0)["ms"])


class Pressure(unittest.TestCase):
    """The fast channel the index cannot be."""

    def test_bands(self):
        self.assertEqual(score.pressure(socket_queue_ms=5.1)["state"], "clear")
        self.assertEqual(score.pressure(socket_queue_ms=18.4)["state"], "busy")
        self.assertEqual(score.pressure(socket_queue_ms=64.0)["state"],
                         "congested")

    def test_real_traffic_beats_an_inference_from_probes(self):
        p = score.pressure(socket_queue_ms=3.0, loaded_ms=99.0, idle_ms=10.0)
        self.assertEqual(p["source"], "sockets")
        self.assertEqual(p["queue_ms"], 3.0)

    def test_probes_are_the_fallback(self):
        p = score.pressure(loaded_ms=48.0, idle_ms=12.0)
        self.assertEqual(p["source"], "probes")
        self.assertEqual(p["queue_ms"], 36.0)

    def test_a_backwards_difference_is_withheld(self):
        # Queueing cannot be negative; that means the split is unreliable,
        # not that load made the link quicker. Same rule as the inflation
        # plausibility floor.
        self.assertIsNone(score.pressure(loaded_ms=10.0, idle_ms=12.0)["state"])

    def test_nothing_to_say_is_a_valid_answer(self):
        self.assertIsNone(score.pressure()["state"])
        self.assertIsNone(score.pressure(loaded_ms=50.0)["state"])


class WrongDirectionSweep(unittest.TestCase):
    """A result wrong in DIRECTION is not a result.

    Four instances turned up one at a time this session — the loaded/idle
    ratio at 0.87, the 1500 ms scoring anchor printed as a latency, the
    internet leg substituting zero for an unknown local leg, and a peak test
    graded A+ for measuring lower latency under load than at rest. This
    class pins the class rather than the instances, so a fifth cannot be
    introduced quietly.
    """

    TOTAL = {"count": 500, "p50": 8.1, "p75": 10.4, "p95": 14.4,
             "max": 26.0, "loss": 0.0, "jitter": 2.3, "last": 8.0}

    def test_a_slower_router_than_internet_withholds_the_isp_leg(self):
        # Gateways commonly deprioritise ICMP addressed to themselves, so
        # their own replies are slow while everything they forward is fast.
        # That is a fact about the control plane, not the ISP's share.
        slow_gateway = {"count": 500, "p50": 20.0, "p75": 25.0, "p95": 40.0,
                        "max": 60.0, "loss": 0.0, "jitter": 3.0, "last": 20.0}
        w = score.wan_from(self.TOTAL, slow_gateway)
        for key in ("p50", "p75", "p95", "max", "last"):
            self.assertIsNone(w[key], key)

    def test_a_genuinely_near_zero_isp_leg_is_still_reported(self):
        # An anchor a hop past the gateway really can cost almost nothing;
        # withholding that would be its own kind of dishonesty.
        near = dict(self.TOTAL, p50=8.4, p75=10.6, p95=14.6, max=26.2)
        w = score.wan_from(self.TOTAL, near)
        self.assertEqual(w["p50"], 0.0)

    def test_normal_subtraction_untouched(self):
        local = {"count": 500, "p50": 2.1, "p75": 2.5, "p95": 5.0,
                 "max": 8.0, "loss": 0.0, "jitter": 0.4, "last": 2.0}
        w = score.wan_from(self.TOTAL, local)
        self.assertEqual(w["p50"], 6.0)
        self.assertEqual(w["last"], 6.0)

    def test_loss_subtraction_stays_clamped_and_that_is_correct(self):
        # Unlike latency, this one is legitimate: loss on the local link
        # shows up in both probes, so if the internet probe lost nothing the
        # wan leg genuinely lost nothing, however much the router probe lost.
        lossy_local = dict(self.TOTAL, loss=0.3)
        w = score.wan_from(dict(self.TOTAL, loss=0.0), lossy_local)
        self.assertEqual(w["loss"], 0.0)

    def test_the_signed_difference_stays_signed(self):
        # icmp_delta_ms is MEANT to go both ways: our own measurements show
        # ICMP optimistic at the median and pessimistic in the tail, so a
        # negative delta is a finding, not an error. Guarding it would
        # destroy the comparison it exists for.
        self.assertLess(score.lag_ms(dict(self.TOTAL, p75=4.0)),
                        score.lag_ms(dict(self.TOTAL, p75=40.0)))


class SpeedTrust(unittest.TestCase):
    """Weakest-link means the lowest component is the headline, so the
    thinnest input must not hold a veto over it."""

    def test_one_sample_is_not_enough(self):
        self.assertFalse(score.speed_scored(63.4, 1))
        self.assertTrue(score.speed_scored(63.4, 2))

    def test_a_contradicting_peak_withdraws_the_figure(self):
        # 251 Mbps measured by hand on the same line disproves 63.
        self.assertFalse(score.speed_scored(63.4, 3, 251.4))
        # Within the same order of magnitude it stands: a saturating test
        # reading somewhat higher than an everyday sample is normal.
        self.assertTrue(score.speed_scored(200.0, 3, 251.4))

    def test_nothing_measured_is_never_scored(self):
        self.assertFalse(score.speed_scored(None, 9))

    def test_the_index_leaves_an_untrusted_figure_out(self):
        # The reported case: a healthy line read POOR because one check
        # pinned the headline.
        pinned = score.index(97.3, 97.0, 42.4)
        honest = score.index(97.3, 97.0, None)
        self.assertLess(pinned, 50)
        self.assertGreater(honest, 90)


class HeadlineDuringAnOutage(unittest.TestCase):
    """The index must not contradict the verdict printed beside it.

    Observed 2026-09-08 on a real 61 s Wi-Fi drop: EXPERIENCE 100 directly
    beneath ROUTER UNREACHABLE, because Lag's 30 s window still held
    pre-outage replies and 61 s against 24 h rounds Reliability to 100.
    """

    def test_a_confirmed_outage_withholds_the_headline(self):
        for state in ("local-down", "wan-down"):
            self.assertFalse(score.scored_now(state), state)

    def test_ordinary_states_keep_it(self):
        for state in ("online", "degraded", "captive"):
            self.assertTrue(score.scored_now(state), state)

    def test_a_quiet_spell_is_not_an_outage(self):
        # gateway-quiet and icmp-quiet leave the state calm on purpose:
        # traffic still crosses the leg, so the index still means something.
        self.assertTrue(score.scored_now("online"))

    def test_the_components_that_produced_it_still_stand(self):
        # Only the headline is withheld. Reliability really is 100 over the
        # window, and its pillar says so in amber with the live downtime.
        self.assertEqual(score.index(100.0, 100.0, None), 100)
        self.assertFalse(score.scored_now("local-down"))

    def test_withholding_is_a_band_of_unknown_not_of_poor(self):
        # A withheld index must not colour as a bad one. band(None) is the
        # same "unknown" every other absent figure uses.
        self.assertEqual(score.band(None), "unknown")


class WanPerPoint(unittest.TestCase):
    """One pair of readings to one ISP-leg figure.

    Factored out of `wan_from` so the per-point series in recent.json and the
    per-window statistics cannot drift: the rule that matters here is the one
    that REFUSES to answer, and a second copy of it is a copy that can forget.
    """

    def test_it_subtracts_the_router_share(self):
        self.assertEqual(score.wan_point_ms(11.13, 3.92), 7.21)

    def test_a_gateway_slower_than_the_internet_says_nothing(self):
        # Plenty of routers deprioritise ICMP addressed to themselves, so the
        # local leg reads slower than the total that crosses it. The
        # subtraction has nothing to say about the line; a clamped zero would
        # report a perfect ISP leg from an invalid measurement.
        self.assertIsNone(score.wan_point_ms(5.0, 9.0))

    def test_inside_the_tolerance_it_still_answers(self):
        # A hair over is measurement noise, not an inversion.
        self.assertEqual(score.wan_point_ms(5.0, 5.5), 0.0)
        self.assertIsNone(
            score.wan_point_ms(5.0, 5.0 + score.WAN_INVERSION_TOLERANCE_MS + 0.01))

    def test_either_reading_missing_is_unknown_not_zero(self):
        self.assertIsNone(score.wan_point_ms(5.0, None))
        self.assertIsNone(score.wan_point_ms(None, 2.0))
        self.assertIsNone(score.wan_point_ms(None, None))

    def test_the_per_point_rule_refuses_exactly_when_wan_from_does(self):
        """The two must never disagree about WHAT THEY REFUSE.

        Raised by the HopSense session 2026-09-12: their Go port is pinned to
        `wan_from` by golden vectors, and a per-point refusal is a surface
        those vectors do not cover. They cannot diverge today because
        `wan_from` calls this helper — this pins that they still cannot after
        someone inlines it back for speed.
        """
        cases = [(10.0, 2.0), (10.0, 10.0), (10.0, 10.5), (10.0, 11.5),
                 (10.0, 30.0), (0.5, 0.4), (None, 2.0), (10.0, None),
                 (None, None), (0.0, 0.0)]
        for total, local in cases:
            point = score.wan_point_ms(total, local)
            window = score.wan_from({"p50": total, "count": 9}, {"p50": local})
            self.assertEqual(
                point is None, window["p50"] is None,
                "disagreed on total=%s local=%s: point=%s window=%s"
                % (total, local, point, window["p50"]))

    def test_wan_from_still_floors_each_statistic_at_the_last(self):
        # The helper is unfloored by design; `wan_from` carries the floor
        # forward FLOORED, which is what keeps a derived leg reading like a
        # distribution. Extracting the arithmetic broke this once.
        w = score.wan_from(
            {"p50": 10.0, "p75": 12.0, "p95": 13.0, "max": 13.5, "count": 9},
            {"p50": 1.0, "p75": 1.0, "p95": 8.0, "max": 12.0})
        self.assertLessEqual(w["p50"], w["p75"])
        self.assertLessEqual(w["p75"], w["p95"])
        self.assertLessEqual(w["p95"], w["max"])


if __name__ == "__main__":
    unittest.main()
