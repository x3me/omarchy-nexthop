"""Tests for apps.py — ss parsing, per-app attribution, kernel socket timing, the bounded read.

Run: python3 -m unittest discover -s test
"""

import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd.apps import (  # noqa: E402
    AppTraffic,
    Sock,
    latency_stats,
    parse_ss,
    socket_timing)
from support import FIXTURES  # noqa: E402


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


class SubprocessBounds(unittest.TestCase):
    def test_ss_read_gives_up_at_the_deadline_and_reaps(self):
        from nexthopd.apps import read_bounded
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import sys, time; sys.stdout.write('abc'); sys.stdout.flush();"
             " time.sleep(30)"], stdout=subprocess.PIPE)
        t0 = time.monotonic()
        self.assertIsNone(read_bounded(proc, 4096, 0.3))
        # The deadline bounds the CALL. The old 3.0 here was slack hiding
        # the fact that reaping ran on its own clock afterwards.
        self.assertLess(time.monotonic() - t0, 0.3 + 0.4)
        self.assertIsNotNone(proc.returncode)    # reaped, not a zombie

    def test_reaping_a_child_that_will_not_die_still_returns_the_loop(self):
        """`ss` in uninterruptible sleep must not hold the daemon's loop.

        This is the case the budget exists for: terminate ignored, kill
        not collectable. Before the budget was shared, reaping spent a
        flat 2 s here on top of a deadline that had already expired, so
        the loop could block for the deadline plus 2.1 s — past the age
        at which the bar declares the daemon dead.
        """
        from nexthopd.apps import _reap

        class Undying:
            returncode = None

            def poll(self):
                return None

            def terminate(self):
                pass

            def kill(self):
                pass

            def wait(self, timeout=None):
                time.sleep(timeout)
                raise subprocess.TimeoutExpired("ss", timeout)

        t0 = time.monotonic()
        _reap(Undying(), 0.4)
        self.assertLess(time.monotonic() - t0, 0.4 + 0.3)

    def test_ss_read_is_capped_and_still_reaps(self):
        from nexthopd.apps import read_bounded
        proc = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000)"],
            stdout=subprocess.PIPE)
        out = read_bounded(proc, 1000, 5.0)
        self.assertEqual(len(out), 1000)
        self.assertIsNotNone(proc.returncode)

    def test_ss_read_returns_complete_output(self):
        from nexthopd.apps import read_bounded
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('line1'); print('line2')"],
            stdout=subprocess.PIPE)
        self.assertEqual(read_bounded(proc, 4096, 5.0), "line1\nline2\n")


if __name__ == "__main__":
    unittest.main()
