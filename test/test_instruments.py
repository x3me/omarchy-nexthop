"""Tests for instruments.py — ranking, the bench, the merged view and the equal-weight fold.

Run: python3 -m unittest discover -s test
"""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd import score  # noqa: E402
from nexthopd.instruments import Bench, MergedSeries, penalty  # noqa: E402
from nexthopd.probes import Series  # noqa: E402
from support import _st  # noqa: E402


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

    def test_the_opening_pair_spans_two_hosts(self):
        """Not `pool[:2]`, which was one host wearing two protocols.

        `icmp-a` and `tcp-a` both point at 1.1.1.1, so seating both put every
        scored instrument on one address before any evidence existed. On a
        network that blocks it, that is a false outage at 4 s and a desktop
        notification at 5 s on every daemon start, with no way back until the
        bench's next pass a minute later (#5).
        """
        self.assertEqual(self.keys(self.bench()), ["icmp-a", "tcp-b"])

    def test_a_blocked_anchor_still_leaves_a_working_seat(self):
        """The property the pairing exists for.

        One live instrument is enough: the leg answers if either does, so no
        outage is declared while the bench re-ranks.
        """
        b = self.bench()
        hosts = {i.target.rpartition(":")[0] or i.target for i in b.actives()}
        self.assertEqual(len(hosts), 2)
        anchor_seats = [i for i in b.actives() if i.target.startswith("1.1.1.1")]
        self.assertEqual(len(anchor_seats), 1)

    def test_a_pool_with_one_host_still_fills_both_seats(self):
        # Fewer scored instruments than the bench expects is the worse
        # failure, so a pool that cannot offer two hosts falls back to order.
        b = Bench([("icmp-a", "icmp", "1.1.1.1"), ("tcp-a", "tcp", "1.1.1.1:443")])
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-a"])

    def test_dead_seat_is_replaced_immediately(self):
        b = self.bench()
        stats = {"icmp-a": _st(), "tcp-b": _st(loss=1.0, p50=None, p95=None),
                 "tcp-a": _st(p50=25, p95=35), "tcp-c": _st(p50=40, p95=60)}
        changes = b.evaluate(1000.0, stats)
        self.assertEqual(sorted(changes), [("tcp-a", True), ("tcp-b", False)])
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-a"])

    def test_no_churn_during_a_full_outage(self):
        b = self.bench()
        dead = _st(loss=1.0, p50=None, p95=None)
        stats = {k: dict(dead) for k in ("icmp-a", "tcp-a", "tcp-b", "tcp-c")}
        self.assertEqual(b.evaluate(1000.0, stats), [])
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-b"])

    def test_challenger_needs_two_consecutive_clear_wins(self):
        b = self.bench()
        # tcp-a is 20%+ better than the worst seat; one win is not enough.
        stats = {"icmp-a": _st(p50=10, p95=14), "tcp-b": _st(p50=100, p95=160),
                 "tcp-a": _st(p50=20, p95=24), "tcp-c": _st(p50=90, p95=150)}
        self.assertEqual(b.evaluate(1000.0, stats), [])
        changes = b.evaluate(1000.0 + Bench.RESELECT_EVERY_S, stats)
        self.assertEqual(sorted(changes), [("tcp-a", True), ("tcp-b", False)])
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-a"])

    def test_a_win_streak_broken_starts_over(self):
        b = self.bench()
        better = {"icmp-a": _st(p50=10, p95=14), "tcp-b": _st(p50=100, p95=160),
                  "tcp-a": _st(p50=20, p95=24), "tcp-c": _st(p50=90, p95=150)}
        level = {"icmp-a": _st(p50=10, p95=14), "tcp-b": _st(p50=19, p95=24),
                 "tcp-a": _st(p50=20, p95=24), "tcp-c": _st(p50=90, p95=150)}
        t = 1000.0
        self.assertEqual(b.evaluate(t, better), [])
        self.assertEqual(b.evaluate(t + 300, level), [])   # streak broken
        self.assertEqual(b.evaluate(t + 600, better), [])  # back to one win
        self.assertEqual(self.keys(b), ["icmp-a", "tcp-b"])

    def test_flapping_instrument_is_quarantined(self):
        b = self.bench()
        inst = b.instruments["tcp-a"]
        t = 1000.0
        # Three seat changes inside an hour is a flap.
        for _, active in (("tcp-a", True), ("tcp-a", False), ("tcp-a", True)):
            b._seat(inst, t, active)
            t += 60
        self.assertGreater(inst.quarantined_until, t)
        # While quarantined it cannot be promoted, even over a corpse.
        b._seat(inst, t, False)
        stats = {"icmp-a": _st(), "tcp-b": _st(loss=1.0, p50=None, p95=None),
                 "tcp-a": _st(p50=5, p95=6), "tcp-c": _st(p50=40, p95=60)}
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


class EqualWeightMerge(unittest.TestCase):
    """The scored internet leg is two instruments. Each must count once
    whatever its cadence, and jitter must never be measured across them."""

    @staticmethod
    def stream(value_fn, interval, span=30.0, offset=0.0, now=None):
        now = now or time.time()
        s = Series()
        t, i = now - span + offset, 0
        while t <= now:
            s.add(t, value_fn(i), False)
            t += interval
            i += 1
        return s

    def test_cadence_cannot_move_the_statistics(self):
        from nexthopd.instruments import merged_stats
        now = time.time()
        merged, pooled = set(), set()
        for icmp_iv in (0.2, 0.5, 1.0):
            a = self.stream(lambda i: 5.0, icmp_iv, now=now)
            b = self.stream(lambda i: 15.0, 1.0, offset=0.25, now=now)
            st = merged_stats([a.since(30), b.since(30)])
            merged.add((st["p50"], st["p75"], st["p95"], st["jitter"], st["loss"]))
            # The pooled stream, which is what used to be scored.
            old = Series.stats(MergedSeries(lambda: [a, b]).since(30))
            pooled.add((old["p75"], old["jitter"]))
        self.assertEqual(len(merged), 1, merged)
        self.assertEqual(merged.pop(), (5.0, 15.0, 15.0, 0.0, 0.0))
        # ...whereas the setting alone used to move p75 and jitter.
        self.assertGreater(len(pooled), 1, pooled)

    def test_jitter_never_crosses_instruments(self):
        from nexthopd.instruments import merged_stats
        now = time.time()
        steady_a = self.stream(lambda i: 5.0, 0.5, now=now)
        steady_b = self.stream(lambda i: 15.0, 1.0, offset=0.25, now=now)
        self.assertEqual(merged_stats([steady_a.since(30),
                                       steady_b.since(30)])["jitter"], 0.0)
        # Two streams with no jitter read as jittery when pooled: the defect.
        self.assertGreater(Series.stats(
            MergedSeries(lambda: [steady_a, steady_b]).since(30))["jitter"], 5.0)
        # An instrument that really alternates contributes its own IPDV,
        # averaged with the steady one's zero.
        swinging = self.stream(lambda i: 10.0 if i % 2 else 40.0, 1.0, now=now)
        st = merged_stats([swinging.since(30), steady_a.since(30)])
        self.assertEqual(st["jitter"], 15.0)

    def test_loss_is_the_mean_of_the_instruments_loss_rates(self):
        from nexthopd.instruments import merged_stats
        now = time.time()
        lossy = self.stream(lambda i: None if i % 10 == 0 else 5.0, 0.5, now=now)
        clean = self.stream(lambda i: 15.0, 1.0, offset=0.25, now=now)
        a, b = lossy.since(30), clean.since(30)
        a_loss = sum(1 for s in a if s[1] is None) / len(a)
        st = merged_stats([a, b])
        self.assertAlmostEqual(st["loss"], a_loss / 2, places=9)
        # Not the count-weighted figure the pool gave, which the faster
        # instrument dominated.
        self.assertNotAlmostEqual(st["loss"], a_loss * len(a) / (len(a) + len(b)),
                                  places=3)

    def test_one_instrument_is_series_stats_exactly(self):
        from nexthopd.instruments import merged_stats
        a = self.stream(lambda i: 5.0 + (i % 3), 0.5)
        self.assertEqual(merged_stats([a.since(30)]), Series.stats(a.since(30)))
        # A seated instrument with nothing yet does not dilute the other.
        self.assertEqual(merged_stats([a.since(30), []]), Series.stats(a.since(30)))
        self.assertEqual(merged_stats([])["count"], 0)

    def test_this_line_as_built(self):
        """ICMP 3.41 ms at 500 ms and TCP 4.82 ms at 1 s — live.json's own
        figures on 2026-09-08. Two stable instruments: no jitter, and Lag
        is the slower instrument's round trip."""
        from nexthopd.instruments import merged_stats
        now = time.time()
        a = self.stream(lambda i: 3.41, 0.5, now=now)
        b = self.stream(lambda i: 4.82, 1.0, offset=0.25, now=now)
        # lag_ms rounds to a tenth: the slower instrument's 4.82 and nothing added.
        self.assertEqual(score.lag_ms(merged_stats([a.since(30), b.since(30)])), 4.8)
        # The pool manufactured 0.93 ms of jitter and 1.4 ms of Lag.
        old = score.lag_ms(Series.stats(MergedSeries(lambda: [a, b]).since(30)))
        self.assertAlmostEqual(old, 6.2, delta=0.1)

    def test_merged_series_stats_is_the_equal_weight_fold(self):
        from nexthopd.instruments import merged_stats
        a = self.stream(lambda i: 5.0, 0.5)
        b = self.stream(lambda i: 15.0, 1.0, offset=0.25)
        m = MergedSeries(lambda: [a, b])
        self.assertEqual(m.stats(30), merged_stats([a.since(30), b.since(30)]))
        self.assertEqual(len(m.each(30)), 2)
        self.assertEqual(len(m.each()), 2)


if __name__ == "__main__":
    unittest.main()
