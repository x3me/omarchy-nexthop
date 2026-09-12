"""Tests for daemon.py — config, the leg watches and arbiters, captive detection, the loop's helpers.

Run: python3 -m unittest discover -s test
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd import daemon as daemon_mod  # noqa: E402
from nexthopd import score  # noqa: E402
from nexthopd.daemon import (  # noqa: E402
    CHECK_DEFER_MAX_S,
    CHECK_SETTLE_S,
    DISRUPTION_AFTER_S,
    LEG_STALE_S,
    MIN_PLAUSIBLE_INFLATION,
    NOTIFY_AFTER_S,
    OUTAGE_AFTER_S,
    PEAK_FRESH_S,
    CaptiveWatch,
    Config,
    Daemon,
    LOAD_FLOOR_BPS,
    LegState,
    LegWatch,
    LocalEventArbiter,
    WanEventArbiter,
    check_ready,
    leg_state)
from nexthopd.net import trace_verdict  # noqa: E402
from nexthopd.store import Store  # noqa: E402
from support import REPO, run_now, FakeStore, _FakeDaemonForDisruption  # noqa: E402


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

    def test_quiet_when_another_instrument_still_answers(self):
        t = time.time()
        self.arb.down(t, beyond_ok=True)
        self.assertFalse(self.arb.real_outage)
        self.assertEqual(self.notices, [])       # the user's internet works
        self.arb.up(t + 30)
        evs = self.store.events()
        self.assertEqual([e["kind"] for e in evs], ["icmp-quiet"])
        self.assertIsNotNone(evs[0]["ended_ts"])
        self.assertEqual(self.notices, [])

    def test_outage_when_every_instrument_fails(self):
        t = time.time()
        self.arb.down(t, beyond_ok=False)
        self.assertTrue(self.arb.real_outage)
        # Logged at once; alarmed only once it has lasted — an outage the
        # user could do nothing about should not interrupt them.
        self.assertEqual(self.notices, [])
        self.arb.tick(t + NOTIFY_AFTER_S + 0.1, beyond_ok=False)
        self.assertEqual(len(self.notices), 1)
        self.arb.up(t + 30)
        self.assertEqual([e["kind"] for e in self.store.events()], ["outage"])
        self.assertEqual(len(self.notices), 2)   # down + recovered

    def test_a_brief_outage_is_logged_and_never_alarms(self):
        t = time.time()
        self.arb.down(t, beyond_ok=False)
        self.arb.tick(t + 1, beyond_ok=False)
        self.arb.up(t + 2)                       # healed inside the window
        self.assertEqual(self.notices, [])       # neither alarm nor recovery
        self.assertEqual([e["kind"] for e in self.store.events()], ["outage"])

    def test_the_alarm_fires_once_not_every_tick(self):
        t = time.time()
        self.arb.down(t, beyond_ok=False)
        for i in range(10):
            self.arb.tick(t + NOTIFY_AFTER_S + i, beyond_ok=False)
        self.assertEqual(len(self.notices), 1)

    def test_escalates_one_way_when_the_rest_stop_too(self):
        t = time.time()
        self.arb.down(t, beyond_ok=True)
        self.arb.tick(t + 2, beyond_ok=True)        # still quiet, still no alarm
        self.assertEqual(self.notices, [])
        self.arb.tick(t + 5, beyond_ok=False)       # now it is an outage
        self.assertTrue(self.arb.real_outage)
        self.assertEqual(self.notices, [])       # still inside the delay
        self.arb.tick(t + 5 + NOTIFY_AFTER_S + 0.1, beyond_ok=False)
        self.assertEqual(len(self.notices), 1)
        self.arb.up(t + 60)
        evs = self.store.events()
        self.assertEqual(sorted(e["kind"] for e in evs),
                         ["icmp-quiet", "outage"])
        for e in evs:
            self.assertIsNotNone(e["ended_ts"])

    def test_quiet_never_charges_reliability(self):
        t = time.time()
        self.arb.down(t, beyond_ok=True)
        self.arb.up(t + 600)
        self.assertEqual(self.store.outage_stats(3600, now=t + 700),
                         (0.0, 0, 0.0))


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
        # Logged at once, alarmed only after NOTIFY_AFTER_S.
        self.assertEqual(self.notes, [])
        self.arb.tick(100.0 + NOTIFY_AFTER_S + 0.1, beyond_ok=False)
        self.assertEqual(len(self.notes), 1)

    def test_escalation_is_one_way(self):
        self.arb.down(100.0, beyond_ok=True)
        # The far side goes quiet too: an outage starting mid-spell must alarm.
        self.arb.tick(110.0, beyond_ok=False)
        self.assertTrue(self.arb.real_outage)
        self.assertEqual(self.notes, [])         # inside the alarm delay
        self.arb.tick(110.0 + NOTIFY_AFTER_S + 0.1, beyond_ok=False)
        self.assertEqual(len(self.notes), 1)
        # Nothing walks it back down again — flapping teaches people to
        # ignore both verdicts.
        self.arb.tick(140.0, beyond_ok=True)
        self.assertTrue(self.arb.real_outage)

    def test_recovery_only_notifies_for_a_real_outage(self):
        self.arb.down(100.0, beyond_ok=True)
        self.arb.up(130.0)
        self.assertEqual(self.notes, [])
        self.assertIsNone(self.arb.kind)
        self.arb.down(200.0, beyond_ok=False)
        self.arb.tick(200.0 + NOTIFY_AFTER_S + 0.1, beyond_ok=False)
        self.arb.up(230.0)
        self.assertEqual(len(self.notes), 2)   # down + recovered


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

        w = CaptiveWatch(check, spawn=run_now)
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

        w = CaptiveWatch(check, spawn=run_now)
        w.tick(1000.0, True)
        w.tick(1001.0, True)
        w.tick(1029.0, True)
        self.assertEqual(len(calls), 1)        # 30 s floor holds
        w.tick(1031.0, True)
        self.assertEqual(len(calls), 2)

    def test_suspicion_drops_when_nothing_answers(self):
        w = CaptiveWatch(lambda: {"verdict": "intercepted", "proof": None},
                         spawn=run_now)
        w.tick(1000.0, True)
        w.tick(1031.0, True)
        self.assertTrue(w.confirmed)
        # The line goes down for real: hand it to the outage path.
        w.tick(1062.0, probes_answering=False)
        self.assertFalse(w.confirmed)
        self.assertEqual(w.strikes, 0)

    def test_publishes_nothing_before_it_knows_anything(self):
        w = CaptiveWatch(lambda: {"verdict": "open", "proof": None},
                         spawn=run_now)
        self.assertIsNone(w.snapshot())


class CaptiveCheckOffTheLoop(unittest.TestCase):
    """The reachability curl must never stall the 2 Hz loop, and it runs on
    suspicion rather than on a clock. Until 0.2.13 it did both wrong."""

    OPEN = {"verdict": "open", "proof": {"ip": "203.0.113.9", "family": "v4"}}

    def test_tick_returns_before_a_slow_check_finishes(self):
        import threading
        release, done = threading.Event(), threading.Event()

        def slow_check():
            release.wait(5)
            done.set()
            return dict(self.OPEN)

        w = CaptiveWatch(slow_check)             # the real thread spawn
        t0 = time.monotonic()
        w.tick(1000.0, True)
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertEqual(w.verdict, "unknown")   # nothing has landed yet
        release.set()
        self.assertTrue(done.wait(5))
        for _ in range(100):                     # a later tick collects it
            w.tick(1000.5, True)
            if w.verdict != "unknown":
                break
            time.sleep(0.01)
        self.assertEqual(w.verdict, "open")
        self.assertEqual(w.proof["ip"], "203.0.113.9")

    def test_proof_of_internet_backs_off_to_hourly(self):
        calls = []

        def check():
            calls.append(1)
            return dict(self.OPEN)

        w = CaptiveWatch(check, spawn=run_now)
        w.tick(1000.0, True)
        for t in (1031.0, 1600.0, 4599.0):
            w.tick(t, True)
        self.assertEqual(len(calls), 1)          # not the old 30 s clock
        w.tick(1000.0 + CaptiveWatch.RECHECK_OPEN_S, True)
        self.assertEqual(len(calls), 2)

    def test_request_starts_over_and_drops_a_stale_answer(self):
        held = []
        w = CaptiveWatch(lambda: dict(self.OPEN), spawn=held.append)
        w.tick(1000.0, True)                     # a check for network A
        self.assertEqual(len(held), 1)
        w.request()                              # the route changed
        self.assertEqual(w.verdict, "unknown")
        held[0]()                                # A's answer arrives late
        w.tick(1001.0, True)
        self.assertIsNone(w.proof)               # dropped, not adopted
        self.assertEqual(len(held), 2)           # and B is being asked
        held[1]()
        w.tick(1002.0, True)
        self.assertEqual(w.verdict, "open")

    def test_daemon_adopts_the_address_from_the_proof_once(self):
        import os as _os
        from nexthopd.daemon import Daemon
        with tempfile.TemporaryDirectory() as d:
            _os.environ["XDG_STATE_HOME"] = d
            try:
                dm = Daemon()
                try:
                    dm.captive.proof = dict(self.OPEN["proof"])
                    dm.captive.checked_ts = 1234
                    dm.adopt_wan_ip()
                    self.assertEqual(dm.wan_ip,
                                     {"ip": "203.0.113.9", "family": "v4",
                                      "checked_ts": 1234})
                    # A later check that could not prove the internet
                    # leaves the last answer standing.
                    dm.captive.proof = None
                    dm.adopt_wan_ip()
                    self.assertEqual(dm.wan_ip["ip"], "203.0.113.9")
                finally:
                    dm.store.close()
            finally:
                del _os.environ["XDG_STATE_HOME"]


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
            d.probes = []
            # The reset path also asks the reachability check to start over.
            d.captive = type("Captive", (), {"request": lambda self: None})()
            d._rebuild_probes = lambda fresh: dmod.Daemon._rebuild_probes(d, fresh)

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


class DisruptionProducer(unittest.TestCase):
    """A run of losses that recovers before it becomes an outage.

    Until now nothing opened a `disruption` event, so half the reliability
    formula — a half-weight on duration, a 300 s recovery charge, a 25-point
    cap, all designed against real history in 0.1.10 — could never fire, and
    a blip the user felt cost the score nothing.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.dir.name) / "t.db")

    def tearDown(self):
        self.store.close()
        self.dir.cleanup()

    def run_losses(self, n, cadence=0.5, t0=None):
        """`n` lost samples at `cadence`, then a reply, with a watch tick at
        each sample — which is how the default 500 ms cadence behaves."""
        t0 = time.time() if t0 is None else t0
        w = LegWatch()
        moves = []
        for i in range(n):
            t = t0 + i * cadence
            moves.append(w.sample(LegState(False, t, t0, i + 1), t))
        t = t0 + n * cadence
        moves.append(w.sample(LegState(True, t, None, 0), t))
        return w, moves

    def test_a_single_loss_is_noise(self):
        w, moves = self.run_losses(1)
        self.assertEqual(moves, [None, None])
        self.assertIsNone(w.blip)

    def test_below_the_threshold_stays_silent(self):
        w, moves = self.run_losses(2)
        self.assertIsNone(moves[-1])
        self.assertIsNone(w.blip)

    def test_three_losses_that_recover_are_a_disruption(self):
        t0 = time.time()
        w, moves = self.run_losses(3, t0=t0)
        self.assertEqual(moves[-1], "disruption")
        began, ended = w.blip
        # Timed from the FIRST loss, not from the threshold being crossed:
        # the interruption started when the packets started going missing.
        self.assertEqual(began, t0)
        # 1.5 s of silence on the stream itself: three lost probes at the
        # default 500 ms, exactly DISRUPTION_AFTER_S. Until 0.2.15 a "loss"
        # was an empty 3 s window, and this same blip could not register.
        self.assertEqual(ended, t0 + DISRUPTION_AFTER_S)

    def test_reaching_the_outage_threshold_is_an_outage_not_a_disruption(self):
        # Nine lost probes at 500 ms: the ninth lands 4.0 s after the first,
        # which is OUTAGE_AFTER_S of unbroken silence.
        w, moves = self.run_losses(9)
        self.assertEqual(moves[8], "down")
        self.assertEqual(moves[-1], "up")
        self.assertIsNone(w.blip)

    def test_a_run_recovering_just_short_of_the_threshold_is_a_disruption(self):
        w, moves = self.run_losses(8)         # 3.5 s of silence, then a reply
        self.assertNotIn("down", moves)
        self.assertEqual(moves[-1], "disruption")

    def test_thresholds_are_seconds_not_ticks(self):
        # The same 1.5 s blip seen by a loop ticking five times as often
        # must read the same: the stream carries the time, not the tick.
        t0 = 1000.0
        w = LegWatch()
        for k in range(15):
            t = t0 + k * 0.1
            w.sample(LegState(False, t, t0, 1 + k // 5), t)
        self.assertEqual(w.sample(LegState(True, t0 + 1.5, None, 0), t0 + 1.5),
                         "disruption")

    def test_the_outage_starts_when_the_packets_stopped(self):
        t0 = 1000.0
        w, _ = self.run_losses(9, t0=t0)
        w2 = LegWatch()
        for i in range(9):
            t = t0 + i * 0.5
            move = w2.sample(LegState(False, t, t0, i + 1), t)
        self.assertEqual(move, "down")
        self.assertEqual(w2.down_since, t0)   # not the tick that noticed

    def test_one_lost_probe_is_never_an_event_at_any_cadence(self):
        # At a 5 s probe interval a single loss is followed by 5 s with no
        # sample at all. Measured in seconds alone that would be an outage;
        # two lost probes are the floor.
        t0 = 1000.0
        w = LegWatch()
        self.assertIsNone(w.sample(LegState(False, t0, t0, 1), t0 + 4.5))
        self.assertIsNone(w.down_since)
        self.assertEqual(w.sample(LegState(False, t0 + 5.0, t0, 2), t0 + 5.0),
                         "down")

    def test_recorded_closed_with_a_duration_and_charged(self):
        w, _ = self.run_losses(4)
        d = _FakeDaemonForDisruption(self.store)
        d.record_disruption("local", w, beyond_ok=False)
        evs = self.store.events()
        self.assertEqual([e["kind"] for e in evs], ["disruption"])
        self.assertIsNotNone(evs[0]["ended_ts"])
        # And it now actually reaches Reliability, which was the point.
        frac, count, disrupted = self.store.outage_stats(
            3600, now=time.time() + 10)
        self.assertEqual(count, 1)
        self.assertGreater(disrupted, 0.0)
        self.assertEqual(frac, 0.0)          # a blip is not downtime
        self.assertLess(score.reliability(frac, count,
                                          disruption_fraction=disrupted),
                        100.0)

    def test_arbitrated_like_an_outage(self):
        w, _ = self.run_losses(4)
        d = _FakeDaemonForDisruption(self.store)
        # Something past this leg kept answering, so the leg interrupted
        # nothing — a gateway dropping pings while traffic crosses it.
        d.record_disruption("local", w, beyond_ok=True)
        self.assertEqual(self.store.events(), [])
        self.assertIsNone(w.blip)            # consumed either way

    def test_never_stored_with_a_zero_span(self):
        # outage_stats drops any row whose end is not after its start, so a
        # blip must never round away to nothing.
        base = time.time()
        w = LegWatch()
        w.blip = (base + 0.4, base + 0.6)
        d = _FakeDaemonForDisruption(self.store)
        d.record_disruption("wan", w, beyond_ok=False)
        e = self.store.events()[0]
        self.assertGreater(e["ended_ts"], e["ts"])
        _, count, disrupted = self.store.outage_stats(3600, now=base + 10)
        self.assertEqual(count, 1)
        self.assertGreater(disrupted, 0.0)


class InflationPlausibility(unittest.TestCase):
    """Queueing can only add delay, so a ratio below 1 is not a reading."""

    @staticmethod
    def ratio(loaded, idle):
        """The published value for a given pair, with the floor applied."""
        r = loaded / idle
        if r < MIN_PLAUSIBLE_INFLATION:
            return None
        return round(max(1.0, r), 2)

    def test_the_case_seen_live_is_withheld(self):
        # 0.87 was published on 716 samples per side: the sample floor
        # cannot catch a wrong-direction result, only a thin one.
        self.assertIsNone(self.ratio(20.3, 23.4))

    def test_indistinguishable_reads_as_no_inflation(self):
        # Within noise of 1, the honest statement is "no inflation", not
        # "faster under load".
        self.assertEqual(self.ratio(9.8, 10.0), 1.0)
        self.assertEqual(self.ratio(10.0, 10.0), 1.0)

    def test_real_inflation_still_reported(self):
        self.assertEqual(self.ratio(13.0, 10.0), 1.3)
        # A badly queued link is not implausible, however large.
        self.assertEqual(self.ratio(250.0, 10.0), 25.0)


class SettingsApplyLive(unittest.TestCase):
    """The anchor and the probe interval used to be read only when probes
    were built, while the Setup tab said settings apply without a restart."""

    def setUp(self):
        from nexthopd.daemon import Daemon
        self.dir = tempfile.TemporaryDirectory()
        os.environ["XDG_STATE_HOME"] = self.dir.name
        self.d = Daemon()
        self.calls = []
        self.d._rebuild_probes = lambda route: self.calls.append(("rebuild", route))
        self.d._apply_seats = lambda changes: self.calls.append(("seats", changes))

    def tearDown(self):
        self.d.store.close()
        del os.environ["XDG_STATE_HOME"]
        self.dir.cleanup()

    def test_nothing_happens_before_probes_exist(self):
        self.d.config.values["probeIntervalMs"] = 1000
        self.d.restart_probes_if_settings_changed()
        self.assertEqual(self.calls, [])

    def test_interval_change_moves_the_cadence_in_place(self):
        class Probe:
            interval = None

            def set_interval(self, v):
                self.interval = v

        anchor = self.d.config["internetAnchor"]
        self.d._probe_settings = (anchor, 500)
        self.d._local_probe = Probe()
        self.d.config.values["probeIntervalMs"] = 1000
        self.d.restart_probes_if_settings_changed()
        self.assertEqual(self.d._local_probe.interval, 1.0)
        self.assertEqual([c[0] for c in self.calls], ["seats"])
        self.assertEqual(self.d._probe_settings, (anchor, 1000))
        # Applied once, not on every tick.
        self.d.restart_probes_if_settings_changed()
        self.assertEqual(len(self.calls), 1)

    def test_anchor_change_rebuilds_the_probes(self):
        import nexthopd.daemon as dmod
        self.d._probe_settings = (self.d.config["internetAnchor"], 500)
        real = dmod.net.route_to
        dmod.net.route_to = lambda a: {"gateway": "192.0.2.1", "iface": "x"}
        try:
            self.d.config.values["internetAnchor"] = "9.9.9.9"
            self.d.restart_probes_if_settings_changed()
        finally:
            dmod.net.route_to = real
        self.assertEqual(self.calls, [("rebuild", {"gateway": "192.0.2.1",
                                                   "iface": "x"})])


class LegStateReading(unittest.TestCase):
    """leg_state() turns a probe stream into what the outage watch consumes:
    is the newest sample a reply, and if not, since when has it been quiet."""

    def test_empty_and_stale_streams_are_unknown_not_outages(self):
        now = 1000.0
        self.assertIsNone(leg_state([], now))
        # The probe stopped talking: ping -O keeps emitting losses through
        # a real outage, so a silent stream is a dead probe, not a dead line.
        self.assertIsNone(leg_state([(now - LEG_STALE_S - 1, None, False)], now))

    def test_a_reply_at_the_head_is_ok(self):
        now = 1000.0
        st = leg_state([(now - 1.0, None, False), (now - 0.5, 8.0, False)], now)
        self.assertTrue(st.ok)
        self.assertEqual(st.lost, 0)
        self.assertIsNone(st.run_since)

    def test_the_trailing_run_is_measured_from_its_first_loss(self):
        now = 1000.0
        samples = [(now - 3.0, 7.0, False), (now - 2.5, None, False),
                   (now - 2.0, None, False), (now - 1.5, None, False),
                   (now - 1.0, None, False)]
        st = leg_state(samples, now)
        self.assertFalse(st.ok)
        self.assertEqual(st.run_since, now - 2.5)
        self.assertEqual(st.lost, 4)
        self.assertEqual(st.ts, now - 1.0)

    def test_a_merged_stream_ends_the_run_on_any_instruments_reply(self):
        # ICMP at 2 Hz losing everything while the TCP instrument answers:
        # the newest sample decides, whichever instrument produced it.
        now = 1000.0
        merged = sorted([(now - 1.5, None, False), (now - 1.0, None, False),
                         (now - 0.5, None, False),      # icmp
                         (now - 0.2, 21.0, False)],     # tcp, replied
                        key=lambda s: s[0])
        self.assertTrue(leg_state(merged, now).ok)

    def test_a_two_second_blip_is_now_seen_end_to_end(self):
        # The case the old any-reply window could not register at all.
        t0 = 1000.0
        w = LegWatch()
        stream = [(t0 - 0.5, 6.0, False)]
        move = None
        for k in range(4):                          # 4 losses over 1.5 s
            stream.append((t0 + k * 0.5, None, False))
            move = w.sample(leg_state(stream, t0 + k * 0.5), t0 + k * 0.5)
        self.assertIsNone(move)
        stream.append((t0 + 2.0, 6.5, False))
        move = w.sample(leg_state(stream, t0 + 2.0), t0 + 2.0)
        self.assertEqual(move, "disruption")
        self.assertEqual(w.blip, (t0, t0 + 2.0))

    def test_outage_rows_start_when_the_silence_began(self):
        # The arbiters take the run's start, so the stored row carries the
        # true onset rather than the tick that crossed the threshold.
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.db")
            try:
                now = time.time()
                WanEventArbiter(store, lambda *a, **k: None).down(
                    now, False, since=now - OUTAGE_AFTER_S)
                LocalEventArbiter(store, lambda *a, **k: None).down(
                    now, True, since=now - OUTAGE_AFTER_S)
                rows = {e["kind"]: e["ts"] for e in store.events()}
                self.assertEqual(rows["outage"], int(now - OUTAGE_AFTER_S))
                self.assertEqual(rows["gateway-quiet"], int(now - OUTAGE_AFTER_S))
            finally:
                store.close()


class ContentCheckReadiness(unittest.TestCase):
    """A link that has just associated is not the line yet.

    The case this is built from: a check 55 s after associating read
    63 Mbps on a 380 Mbps line, taken on 2.4 GHz at a 16 Mbps tx rate,
    nine minutes before the link moved itself to 5 GHz.
    """

    def test_a_fresh_association_waits(self):
        now = 1000.0
        self.assertFalse(check_ready(now, now - 5, None, None))
        self.assertFalse(check_ready(now, now - CHECK_SETTLE_S + 1, None, None))

    def test_a_settled_association_is_ready(self):
        now = 1000.0
        self.assertTrue(check_ready(now, now - CHECK_SETTLE_S, None, None))

    def test_a_link_with_its_rate_down_waits(self):
        # The same signal that opens a rate-drop event.
        now = 1000.0
        self.assertFalse(check_ready(now, now - 600, now - 3, None))

    def test_a_wired_link_is_always_ready(self):
        # No association and no rate tracking: nothing to wait for.
        self.assertTrue(check_ready(1000.0, None, None, None))

    def test_the_deferral_is_capped_so_a_slow_link_still_scores(self):
        now = 1000.0
        waiting = now - CHECK_DEFER_MAX_S
        # Still associating, still rate-limited, but we have waited long
        # enough: an honest low number beats no number for ever.
        self.assertTrue(check_ready(now, now - 1, now - 1, waiting))
        self.assertFalse(check_ready(now, now - 1, now - 1, now - 5))


class SpeedTrustEndToEnd(unittest.TestCase):
    """The same thing through speed_score, where the samples come from the
    store and the peak has to be matched to this network."""

    NET = "x3me"

    def setUp(self):
        from nexthopd.daemon import Daemon
        self.dir = tempfile.TemporaryDirectory()
        os.environ["XDG_STATE_HOME"] = self.dir.name
        self.d = Daemon()
        self.now = time.time()

    def tearDown(self):
        self.d.store.close()
        del os.environ["XDG_STATE_HOME"]
        self.dir.cleanup()

    def content(self, down, ago, network=None):
        self.d.store.put_test(int(self.now - ago), "content", "cloudflare",
                              down_mbps=down, up_mbps=10.0, ok=True,
                              network=self.NET if network is None else network)

    def peak(self, down, ago, network=None):
        self.d.store.put_test(int(self.now - ago), "peak", "cloudflare",
                              down_mbps=down, up_mbps=50.0, ok=True,
                              network=self.NET if network is None else network)

    def test_the_arrival_check_alone_is_reported_but_not_counted(self):
        self.content(63.4, 300)
        spd, ctx = self.d.speed_score(self.now, self.NET)
        self.assertIsNotNone(spd)              # still shown
        self.assertEqual(ctx["samples"], 1)
        self.assertFalse(ctx["scored"])        # but not the headline

    def test_a_second_check_makes_it_count(self):
        self.content(63.4, 300)
        self.content(380.0, 60)
        spd, ctx = self.d.speed_score(self.now, self.NET)
        self.assertTrue(ctx["scored"])
        # Median of two takes the higher, so one clean check recovers it.
        self.assertEqual(ctx["last_down"], 380.0)

    def test_a_fresh_peak_here_withdraws_a_contradicted_figure(self):
        self.content(63.4, 900)
        self.content(70.0, 300)
        self.peak(251.4, 120)
        spd, ctx = self.d.speed_score(self.now, self.NET)
        self.assertEqual(ctx["peak_down"], 251.4)
        self.assertFalse(ctx["scored"])

    def test_a_peak_from_another_network_says_nothing_about_this_one(self):
        self.content(63.4, 900)
        self.content(70.0, 300)
        self.peak(251.4, 120, network="SomeHotel")
        _, ctx = self.d.speed_score(self.now, self.NET)
        self.assertIsNone(ctx["peak_down"])
        self.assertTrue(ctx["scored"])

    def test_a_stale_peak_no_longer_speaks_for_the_line(self):
        self.content(63.4, 900)
        self.content(70.0, 300)
        self.peak(251.4, PEAK_FRESH_S + 60)
        _, ctx = self.d.speed_score(self.now, self.NET)
        self.assertIsNone(ctx["peak_down"])
        self.assertTrue(ctx["scored"])


class AnchorSetting(unittest.TestCase):
    def test_a_leading_dash_is_not_an_anchor(self):
        check = Config.SCHEMA["internetAnchor"][1]
        for bad in ("-1.1.1.1", "--help", "-", "-x.example", ".x", ""):
            self.assertIsNone(check(bad), bad)
        for ok in ("1.1.1.1", "::1", "2606:4700:4700::1111", "dns.google", "a"):
            self.assertEqual(check(ok), ok)


class BandwidthTestsTakeTurns(unittest.TestCase):
    def test_one_test_at_a_time(self):
        import types
        from nexthopd.daemon import Daemon

        def idle(peak, content):
            return Daemon.tests_idle(types.SimpleNamespace(
                peak_running=peak, content_running=content))

        self.assertTrue(idle(False, False))
        self.assertFalse(idle(True, False))
        self.assertFalse(idle(False, True))


class LinkOffTheLoop(unittest.TestCase):
    """The local-end snapshot is three subprocesses with 2 s timeouts each;
    the loop reads the collector's latest dict and never waits for them."""

    def test_reading_never_waits_for_a_slow_snapshot(self):
        import threading
        from nexthopd.daemon import LinkCollector
        calls = []
        gate = threading.Event()

        def slow(anchor):
            calls.append(anchor)
            if len(calls) > 1:
                gate.wait(5.0)          # the second read hangs like a wedged iw
            return {"iface": "wlo1", "kind": "wifi", "n": len(calls),
                    "station": {"tx_retries": 1}}

        c = LinkCollector(lambda: "1.1.1.1", snapshot_fn=slow, interval_s=0.01)
        c.start()
        self.addCleanup(c.stop)
        self.addCleanup(gate.set)
        # start() took the first snapshot itself, so there is one to read...
        self.assertEqual(c.latest["n"], 1)
        # ...and reading while the thread is stuck costs nothing.
        deadline = time.monotonic() + 2.0
        while len(calls) < 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        t0 = time.monotonic()
        snap = c.latest
        self.assertLess(time.monotonic() - t0, 0.05)
        self.assertEqual(snap["n"], 1)
        # A copy: annotating it does not reach the collector's own dict.
        snap["station"]["retry_pct"] = 50.0
        self.assertNotIn("retry_pct", c.latest["station"])

    def test_a_failing_snapshot_keeps_the_last_good_one(self):
        from nexthopd.daemon import LinkCollector
        state = {"n": 0}

        def flaky(anchor):
            state["n"] += 1
            if state["n"] > 1:
                raise OSError("iw went away")
            return {"iface": "wlo1", "n": 1}

        c = LinkCollector(lambda: "x", snapshot_fn=flaky, interval_s=0.01)
        c.start()
        self.addCleanup(c.stop)
        deadline = time.monotonic() + 2.0
        while state["n"] < 3 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertGreaterEqual(state["n"], 3)
        self.assertEqual(c.latest, {"iface": "wlo1", "n": 1})
        self.assertTrue(c.is_alive())


class SnapshotFreshnessBudget(unittest.TestCase):
    """Nothing on the loop may be budgeted for longer than the snapshot it
    delays is allowed to be old.

    The loop writes live.json and then does work. `AppTraffic.poll()` is
    the only blocking call left in that stretch, so its deadline is how
    stale live.json can get — and past `BarWidget.staleAfterS` the bar
    stops believing the daemon: glyph only, no index, no headline, and
    since 0.2.39 no liveness ring on the path sparklines. Both numbers
    were 5: one file's worst case was exactly the other file's failure
    threshold, so a single slow `ss` could report a perfectly healthy
    daemon as absent.

    Pin the relationship, not either number — they live in different
    files and in different languages, and neither one is wrong alone.
    """

    def stale_after_s(self):
        import re
        src = (REPO / "BarWidget.qml").read_text()
        m = re.search(r"property\s+int\s+staleAfterS\s*:\s*(\d+)", src)
        self.assertIsNotNone(
            m, "staleAfterS is gone from BarWidget — find where the "
               "staleness contract moved and re-point this test")
        return float(m.group(1))

    def test_the_blocking_poll_fits_well_inside_the_staleness_contract(self):
        from nexthopd.apps import AppTraffic
        contract = self.stale_after_s()
        self.assertLess(
            AppTraffic.POLL_DEADLINE_S, contract / 2.0,
            "a full-deadline ss read would age live.json into the "
            "bar's no-data state on a healthy daemon")

    def test_the_poll_deadline_covers_the_reap_too(self):
        """The budget is the call's, not the read's — see `_reap`."""
        from nexthopd.apps import REAP_RESERVE_S, AppTraffic
        self.assertLess(REAP_RESERVE_S, AppTraffic.POLL_DEADLINE_S)


class LiveJsonContract(unittest.TestCase):
    """Every key the QML reads off live.json must be one compose_live
    publishes. The dict literal is the contract; this pins the two halves
    to each other, so a renamed or dropped key fails here rather than as a
    blank in the panel."""

    @staticmethod
    def published():
        import ast
        src = (REPO / "nexthopd" / "daemon.py").read_text()
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "compose_live")
        ret = [n for n in ast.walk(fn)
               if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)][-1]
        keys, nested = set(), {}
        for k, v in zip(ret.value.keys, ret.value.values):
            if isinstance(k, ast.Constant):
                keys.add(k.value)
                if isinstance(v, ast.Dict):
                    nested[k.value] = {kk.value for kk in v.keys
                                       if isinstance(kk, ast.Constant)}
        return keys, nested

    @staticmethod
    def read_by_qml():
        import re
        reads, nested = set(), {}
        for q in REPO.glob("*.qml"):
            for m in re.finditer(r"\blive\.([A-Za-z_]\w*)(?:\.([A-Za-z_]\w*))?",
                                 q.read_text()):
                if m.group(1) == "json":       # the file's name, in prose
                    continue
                reads.add(m.group(1))
                if m.group(2):
                    nested.setdefault(m.group(1), set()).add(m.group(2))
        return reads, nested

    def test_qml_reads_only_what_the_daemon_publishes(self):
        keys, nested_keys = self.published()
        reads, nested_reads = self.read_by_qml()
        self.assertTrue(reads, "the scan found nothing — the regex is broken")
        self.assertEqual(reads - keys, set())
        for parent, fields in nested_reads.items():
            if parent in nested_keys:
                self.assertEqual(fields - nested_keys[parent], set(), parent)

    def test_the_keys_the_shell_service_relies_on_are_published(self):
        keys, _ = self.published()
        # The version handover and the liveness watch cannot work without these.
        self.assertTrue({"t", "pid", "pid_start", "daemon_version", "state"} <= keys)


class ContentHint(unittest.TestCase):
    """What the daemon hands the check to size itself with."""

    class Store:
        def __init__(self, rows):
            self.rows = rows

        def tests(self, limit=20, kind=None):
            return self.rows[:limit]

    def hint(self, rows, network):
        d = Daemon.__new__(Daemon)
        d.store = self.Store(rows)
        return Daemon._content_hint(d, network)

    def row(self, network, down, up, ok=True):
        return {"ok": ok, "network": network, "down_mbps": down, "up_mbps": up}

    def test_nothing_stored_gives_no_hint(self):
        self.assertEqual(self.hint([], "home"), (None, None))

    def test_only_this_network_counts(self):
        rows = [self.row("cafe", 900.0, 400.0), self.row("home", 90.0, 20.0)]
        self.assertEqual(self.hint(rows, "home"), (90.0, 20.0))

    def test_the_best_recent_reading_wins_not_the_last(self):
        # A check that came in low must not shrink the next transfer, which
        # would read lower again: sizing off the last reading is a ratchet.
        rows = [self.row("home", 40.0, 5.0),
                self.row("home", 380.0, 90.0),
                self.row("home", 350.0, 88.0)]
        self.assertEqual(self.hint(rows, "home"), (380.0, 90.0))

    def test_failed_and_empty_readings_are_skipped(self):
        rows = [self.row("home", 900.0, 400.0, ok=False),
                self.row("home", None, None),
                self.row("home", 120.0, 30.0)]
        self.assertEqual(self.hint(rows, "home"), (120.0, 30.0))

    def test_a_direction_with_no_readings_stays_none(self):
        rows = [self.row("home", 120.0, None)]
        self.assertEqual(self.hint(rows, "home"), (120.0, None))


class LoadFloor(unittest.TestCase):
    """What counts as a busy link, for the loaded/idle latency split.

    The split used to borrow the Wi-Fi power-save floor of 25 kB/s, which on
    this laptop sat inside the idle distribution: median minute 18 kB/s, p75
    42 kB/s, and 36.6% of all minutes tagged loaded. Across 8,971 stored
    minutes the loaded half read FASTER than the idle half 57% of the time —
    a link cannot answer faster while busy, and a coin flip is what two
    buckets holding the same thing look like.
    """

    class Link:
        latest = {"ssid": "home"}

    class Store:
        def __init__(self, mbps):
            self.mbps = mbps
            self.calls = 0

        def baseline_speed(self, **kw):
            self.calls += 1
            return self.mbps

    def daemon(self, mbps):
        d = Daemon.__new__(Daemon)
        d.link = self.Link()
        d.store = self.Store(mbps)
        return d

    def test_the_floor_is_a_tenth_of_what_the_line_carries(self):
        d = self.daemon(400.0)                       # 400 Mbps = 50 MB/s
        self.assertAlmostEqual(d.load_floor_bps(1000.0), 5_000_000.0, delta=1)

    def test_a_slow_line_is_not_held_to_a_fast_line_s_bar(self):
        # The whole reason the number is a fraction: 5 MB/s is a tenth of
        # this laptop's line and more than a 10 Mbps line can ever carry, so
        # a fixed rate would switch the split off entirely down there.
        d = self.daemon(10.0)
        floor = d.load_floor_bps(1000.0)
        self.assertLess(floor, 10.0 * 1e6 / 8)
        self.assertGreaterEqual(floor, LOAD_FLOOR_BPS)

    def test_an_unmeasured_line_falls_back_to_the_floor(self):
        self.assertEqual(self.daemon(None).load_floor_bps(1000.0), LOAD_FLOOR_BPS)

    def test_background_chatter_never_reaches_the_floor(self):
        # The stored median minute and p75 on this machine.
        d = self.daemon(400.0)
        floor = d.load_floor_bps(1000.0)
        for chatter in (18_020, 42_290, 182_094):
            self.assertLess(chatter, floor)

    def test_it_is_read_once_a_minute_not_twice_a_second(self):
        d = self.daemon(400.0)
        for tick in range(0, 120, 1):
            d.load_floor_bps(1000.0 + tick * 0.5)
        self.assertLessEqual(d.store.calls, 2)

    def test_a_store_that_throws_does_not_stop_the_probes(self):
        d = self.daemon(400.0)

        def boom(**kw):
            raise RuntimeError("db is busy")

        d.store.baseline_speed = boom
        self.assertEqual(d.load_floor_bps(1000.0), LOAD_FLOOR_BPS)


class RoamDoesNotResetTheSeries(unittest.TestCase):
    """A roam is the same network, so the history must survive it.

    Raised by the HopSense session 2026-09-12: their sparkline filters rows by
    network fingerprint because their sink keeps every network a device has
    been on. Ours resets upstream instead, on a route change — so the question
    is whether a BSSID change without a gateway change counts as one. It must
    not: this laptop's own network kicked every station once a minute for a
    while, and a series that reset on each roam would be permanently empty.
    """

    def daemon(self, route):
        d = Daemon.__new__(Daemon)
        d.route = route
        d.config = {"internetAnchor": "1.1.1.1"}
        d.rebuilt = []
        d._rebuild_probes = lambda fresh: d.rebuilt.append(fresh)
        return d

    def run_with(self, current, fresh):
        d = self.daemon(current)
        real = daemon_mod.net.route_to
        daemon_mod.net.route_to = lambda anchor: fresh
        try:
            Daemon.restart_probes_if_route_changed(d)
        finally:
            daemon_mod.net.route_to = real
        return d.rebuilt

    def test_a_roam_keeps_the_series(self):
        # Same gateway, same interface: only the access point changed.
        here = {"gateway": "192.168.10.1", "iface": "wlo1"}
        self.assertEqual(self.run_with(here, dict(here)), [])

    def test_a_different_gateway_resets(self):
        rebuilt = self.run_with({"gateway": "192.168.10.1", "iface": "wlo1"},
                                {"gateway": "10.0.0.1", "iface": "wlo1"})
        self.assertEqual(len(rebuilt), 1)

    def test_a_different_interface_resets(self):
        # Docking: the same address on a different link is a different path.
        rebuilt = self.run_with({"gateway": "192.168.10.1", "iface": "wlo1"},
                                {"gateway": "192.168.10.1", "iface": "eth0"})
        self.assertEqual(len(rebuilt), 1)

    def test_losing_the_route_is_an_outage_not_a_new_network(self):
        # Resetting here throws away the run-up to the drop, which is the one
        # window a user wants afterwards.
        self.assertEqual(
            self.run_with({"gateway": "192.168.10.1", "iface": "wlo1"},
                          {"gateway": None, "iface": "wlo1"}), [])


if __name__ == "__main__":
    unittest.main()
