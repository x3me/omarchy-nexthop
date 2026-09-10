"""Tests for probes.py — ping parsing, series statistics, load tagging, the TCP probe.

Run: python3 -m unittest discover -s test
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd import score  # noqa: E402
from nexthopd.probes import (  # noqa: E402
    Series,
    PingProbe,
    TcpProbe,
    RE_REPLY,
    RE_PENDING,
    RE_UNREACH)
from support import FIXTURES  # noqa: E402


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

    def test_a_loss_charged_at_expiry_is_not_charged_again(self):
        """The real recording, replayed whole.

        seq 1 goes unanswered, the grace period gives up on it, and the
        gateway's Destination Host Unreachable for that same seq arrives
        0.35 s after that. One packet left, so one loss is recorded. Before
        this, the series held two — and overcharging is the direction that
        matters, because undercharging a loss is the safe error and this was
        the other one.
        """
        s = Series()
        p = PingProbe("192.0.2.1", s, 500)
        for line in (FIXTURES / "ping-losses.txt").read_text().splitlines():
            p._consume(line + "\n")
        rows = s.all()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0][1])

    def test_a_reply_after_the_grace_period_adds_nothing(self):
        """A packet already called lost cannot be un-lost by a late reply.

        The window it belonged to has been read and scored. Recording the RTT
        now would put two samples on the wire's one packet, and flatter the
        sample count of every window that reads it.
        """
        s = Series()
        p = PingProbe("192.0.2.1", s, 500)
        p._consume("[100.0] no answer yet for icmp_seq=4\n")
        p._consume("[110.0] no answer yet for icmp_seq=9\n")   # expires seq 4
        p._consume("[110.5] 64 bytes from 1.1.1.1: icmp_seq=4 ttl=60 time=9.0 ms\n")
        rows = s.all()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0][1])

    def test_a_repeated_pending_line_cannot_recharge_a_lost_seq(self):
        """`ping -O` repeats "no answer yet" for the same seq — the recording
        does it for seq 5 — so a charged seq must not go back on the list."""
        s = Series()
        p = PingProbe("192.0.2.1", s, 500)
        p._consume("[100.0] no answer yet for icmp_seq=4\n")
        p._consume("[110.0] no answer yet for icmp_seq=4\n")   # charges it
        p._consume("[110.5] no answer yet for icmp_seq=4\n")   # must not re-arm
        p._consume("[113.0] no answer yet for icmp_seq=4\n")   # would re-charge
        self.assertEqual(len(s.all()), 1)

    def test_a_new_ping_process_can_lose_seq_1_again(self):
        """`ping` numbers from 1 on every respawn.

        Remembering a charged seq past the process that produced it would
        suppress a genuine loss on the next one, which is the same defect
        facing the other way.
        """
        s = Series()
        p = PingProbe("192.0.2.1", s, 500)
        p._consume("[100.0] no answer yet for icmp_seq=1\n")
        p._consume("[110.0] no answer yet for icmp_seq=9\n")   # charges seq 1
        self.assertEqual(len(s.all()), 1)
        p._reset_tracking()                                    # ping respawned
        p._consume("[200.0] no answer yet for icmp_seq=1\n")
        p._consume("[210.0] no answer yet for icmp_seq=2\n")   # charges it again
        self.assertEqual(len(s.all()), 2)

    def test_the_charged_map_does_not_grow_without_bound(self):
        """It is drained by the same clock that fills it."""
        s = Series()
        p = PingProbe("192.0.2.1", s, 500)
        for seq in range(1, 40):
            p._consume("[%d.0] no answer yet for icmp_seq=%d\n" % (100 + seq, seq))
        self.assertLess(len(p._charged), 5)
        self.assertLess(len(p._pending), 5)

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


class SynRetransmits(unittest.TestCase):
    """A handshake rescued by a retransmitted SYN is loss, not latency.

    Found 2026-09-10 from the HopSense side and confirmed here in this
    machine's own history: an internet-leg p95 sitting at 1032-1041 ms,
    constant to within 1% across a twenty-minute episode, while p50 was
    5.5 ms and `lag_icmp` never left 12-22 ms. Congestion does not produce
    the same number twenty times; a timer does. Folded through
    `lag = p75 + 1.5 * jitter` those samples read as 473 ms of lag and took
    Responsiveness to 26 on a link ICMP called healthy.

    The threshold is RELATIVE, and that is the whole design. `connect()`
    returns one RTT after the SYN that survives, so a rescued handshake lands
    at one RTO PLUS the path's own round trip — 1008 ms on an 8 ms path,
    1150 ms on a 150 ms one. A fixed cutoff would label a congestion spike on
    an ordinary intercontinental path as a lost packet, which is a different
    fault with a different owner.
    """

    def probe(self, baseline_ms=None, samples=None):
        p = TcpProbe("192.0.2.1", Series(), 1.0)
        if baseline_ms is not None:
            n = p.RETRANSMIT_MIN_SAMPLES if samples is None else samples
            for i in range(n):
                p._recent.append((1000.0 + i, baseline_ms))
        return p

    def test_a_second_above_a_fast_path_is_a_retransmit(self):
        p = self.probe(baseline_ms=8.5)
        self.assertEqual(p._classify(1100.0, 1045.0), "retransmit")
        self.assertEqual(p._classify(1100.0, 1004.0), "retransmit")

    def test_an_ordinary_round_trip_is_not(self):
        p = self.probe(baseline_ms=8.5)
        for rtt in (8.0, 45.0, 300.0, 899.0):
            self.assertEqual(p._classify(1100.0, rtt), "reply", rtt)

    def test_a_congestion_spike_on_a_distant_path_stays_a_measurement(self):
        """The case a fixed cutoff gets wrong.

        On a 150 ms path a real retransmit lands at ~1150 ms, so a 1045 ms
        sample is 895 ms of something that is not a timer. 150-250 ms is
        ordinary for a subscriber reaching another continent, so this band is
        normal traffic rather than an edge case.
        """
        p = self.probe(baseline_ms=150.0)
        self.assertEqual(p._classify(1100.0, 1045.0), "reply")
        self.assertEqual(p._classify(1100.0, 1150.0), "retransmit")

    def test_a_satellite_link_keeps_its_latency(self):
        p = self.probe(baseline_ms=600.0)
        self.assertEqual(p._classify(1100.0, 1045.0), "reply")
        self.assertEqual(p._classify(1100.0, 1600.0), "retransmit")

    def test_before_a_baseline_it_is_neither(self):
        # Inventing a loss and publishing a suspect latency are both claims.
        p = self.probe(baseline_ms=8.5,
                       samples=TcpProbe.RETRANSMIT_MIN_SAMPLES - 1)
        self.assertEqual(p._classify(1100.0, 1045.0), "unknown")
        self.assertEqual(p._classify(1100.0, 8.0), "reply")

    def test_a_slow_path_bootstraps_instead_of_going_silent(self):
        """The hazard in the third verdict, named.

        On a link whose real round trip is past the floor, every sample lands
        unclassified. A baseline deque that only accepted classified samples
        would never reach its minimum, so the instrument would stay
        unclassified for ever — nothing recorded, count never growing,
        `penalty()` returning None, and the bench able neither to seat it nor
        to call it dead. Silent and unrankable, invisible because it is not
        failing but merely absent.
        """
        p = TcpProbe("192.0.2.1", Series(), 1.0)
        verdicts = []
        for i in range(20):
            v = p._classify(1000.0 + i, 1200.0)
            verdicts.append(v)
            if v in ("reply", "unknown"):
                p._recent.append((1000.0 + i, 1200.0))
        self.assertEqual(set(verdicts[:p.RETRANSMIT_MIN_SAMPLES]), {"unknown"})
        self.assertEqual(set(verdicts[p.RETRANSMIT_MIN_SAMPLES:]), {"reply"})
        self.assertAlmostEqual(p._baseline_ms(1020.0), 1200.0)

    def test_retransmits_do_not_raise_the_bar_that_catches_them(self):
        # Feeding them back would ratchet the threshold up on the
        # instrument's own retransmits and the rule would stop firing.
        p = TcpProbe("192.0.2.1", Series(), 1.0)
        for i in range(10):
            p._recent.append((1000.0 + i, 8.5))
        for i, rtt in enumerate((1045.0, 8.6, 1044.0, 8.4, 1046.0)):
            v = p._classify(1010.0 + i, rtt)
            if v == "reply":
                p._recent.append((1010.0 + i, rtt))
        self.assertAlmostEqual(p._baseline_ms(1015.0), 8.5, places=1)
        self.assertEqual(p._classify(1015.0, 1045.0), "retransmit")

    def test_the_baseline_window_is_a_duration_not_a_count(self):
        # An instrument benched to a slower cadence would otherwise have
        # "recent" silently mean a longer stretch of wall clock.
        p = TcpProbe("192.0.2.1", Series(), 1.0)
        for i in range(20):
            p._recent.append((1000.0 + i, 8.5))
        self.assertIsNotNone(p._baseline_ms(1020.0))
        self.assertIsNone(p._baseline_ms(1020.0 + TcpProbe.RETRANSMIT_WINDOW_S))

    def test_the_window_matches_what_the_bench_ranks_on(self):
        # "Recent" should mean one thing across the daemon.
        from nexthopd.instruments import Bench
        self.assertEqual(TcpProbe.RETRANSMIT_WINDOW_S, Bench.WINDOW_S)
        self.assertEqual(TcpProbe.RETRANSMIT_MIN_SAMPLES, Bench.MIN_SAMPLES)

    def test_the_two_retransmit_case_was_already_loss(self):
        """Why the old boundary was arbitrary.

        Two retransmits wait 1 s + 2 s, which is past CONNECT_TIMEOUT_S, so
        that handshake already timed out and was recorded as loss. One
        retransmit came back inside the timeout and was recorded as latency.
        The same event, accounted two opposite ways, and the line between them
        was wherever the timeout happened to fall.
        """
        self.assertLess(TcpProbe.CONNECT_TIMEOUT_S * 1000.0, 3000.0)
        self.assertLess(TcpProbe.RETRANSMIT_MARGIN_MS,
                        TcpProbe.CONNECT_TIMEOUT_S * 1000.0)


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


class TcpProbeBehaviour(unittest.TestCase):
    """The TCP-handshake instruments beside ICMP.

    ICMP is answered by fast paths in hardware and can be spoofed by
    anything on the way; a handshake to port 443 has to reach a listener
    that completes it. Since 0.2.0 these are seated instruments in the
    bench (instruments.py), not a comparison probe on the side.
    """

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


if __name__ == "__main__":
    unittest.main()
