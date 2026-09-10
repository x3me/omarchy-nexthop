"""Tests for store.py — rows, rollups, events, and the one connection three threads share.

Run: python3 -m unittest discover -s test
"""

import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd.store import Store  # noqa: E402


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


class TailStatisticsAreRecorded(unittest.TestCase):
    """p75 and max per leg, written but never scored.

    Comparing our headline against Orb's and LibreQoS's could only be done
    as an upper bound because neither statistic was ever stored; p50 and
    p95 cannot reconstruct them. Recorded now so the choice can be argued
    from real days rather than bounded — the rule 0.1.11 held loaded
    latency to.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "history.db"

    def tearDown(self):
        self.dir.cleanup()

    def test_the_columns_exist_and_round_trip(self):
        st = Store(self.path)
        st.put_minute(60, {"local_p50": 1.0, "local_p75": 2.0,
                           "local_max": 9.0, "wan_p50": 3.0,
                           "wan_p75": 4.0, "wan_max": 77.7})
        row = st.db.execute("SELECT * FROM minute WHERE ts = 60").fetchone()
        self.assertEqual(row["local_p75"], 2.0)
        self.assertEqual(row["local_max"], 9.0)
        self.assertEqual(row["wan_p75"], 4.0)
        self.assertEqual(row["wan_max"], 77.7)
        st.close()

    def test_an_older_database_is_migrated_in_place(self):
        # The invariant across nine schema-touching releases: additive
        # ALTER TABLE, never a rewrite. An existing row must survive it.
        import sqlite3 as sq
        st = Store(self.path)
        st.put_minute(60, {"local_p50": 1.0})
        st.close()
        db = sq.connect(self.path)
        for col in ("local_p75", "local_max", "wan_p75", "wan_max"):
            db.execute("ALTER TABLE minute DROP COLUMN %s" % col)
            db.execute("ALTER TABLE hour DROP COLUMN %s" % col)
        db.commit()
        db.close()

        st = Store(self.path)                 # reopening must migrate
        cols = [r[1] for r in st.db.execute("PRAGMA table_info(minute)")]
        for col in ("local_p75", "local_max", "wan_p75", "wan_max"):
            self.assertIn(col, cols)
        row = st.db.execute("SELECT * FROM minute WHERE ts = 60").fetchone()
        self.assertEqual(row["local_p50"], 1.0)   # the old row survived
        self.assertIsNone(row["local_max"])       # and is honestly blank
        st.close()

    def test_they_are_recorded_but_not_scored(self):
        # Nothing in the scoring path may read them yet. If that changes it
        # should be a deliberate release, not a drift.
        src = Path(__file__).resolve().parent.parent / "nexthopd" / "score.py"
        text = src.read_text()
        for col in ("local_p75", "local_max", "wan_p75", "wan_max"):
            self.assertNotIn(col, text)


class StoreConcurrency(unittest.TestCase):
    """One connection shared by the loop and two test workers. Every call
    must serialise: sqlite3 raises on an overlapping use of one connection
    and the row it was writing is lost."""

    def test_overlapping_writers_and_readers_lose_nothing(self):
        import threading
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        store = Store(Path(d.name) / "t.db")
        self.addCleanup(store.close)
        errors, n = [], 150

        def guard(fn):
            def run():
                try:
                    fn()
                except Exception as e:      # noqa: BLE001 — recorded, asserted
                    errors.append(repr(e))
            return run

        def tests(kind, base):
            for i in range(n):
                store.put_test(base + i, kind, "x", down_mbps=1.0, ok=True,
                               network="n")

        def loop():
            for i in range(n):
                store.put_minute(1_000_000 + i * 60, {"lag": 1.0})
                store.outage_stats(3600, now=2_000_000)

        def events():
            for i in range(n):
                eid = store.open_event(3_000_000 + i, "outage", "critical",
                                       "wan", "t")
                store.close_event(eid, 3_000_000 + i + 1)
                store.events(86400, now=3_000_000 + n)

        threads = [threading.Thread(target=guard(lambda: tests("content", 10_000))),
                   threading.Thread(target=guard(lambda: tests("peak", 20_000))),
                   threading.Thread(target=guard(loop)),
                   threading.Thread(target=guard(events))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(len(store.tests(limit=1000, kind="content")), n)
        self.assertEqual(len(store.tests(limit=1000, kind="peak")), n)
        rows, _ = store.series(10 ** 9, now=1_000_000 + n * 60 + 1,
                               resolution="minute")
        self.assertEqual(len(rows), n)


class EventWindowSemantics(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.store = Store(Path(self.dir.name) / "t.db")
        self.addCleanup(self.store.close)
        self.now = 1_000_000

    def details(self, seconds):
        return [e["detail"] for e in self.store.events(seconds, now=self.now)]

    def test_an_event_that_ended_inside_the_window_is_listed(self):
        # Began 25 h ago, ended an hour ago: it overlaps the last 24 h and
        # is exactly the row the user opens the list to find.
        eid = self.store.open_event(self.now - 90_000, "outage", "critical",
                                    "wan", "straddles")
        self.store.close_event(eid, self.now - 3_600)
        # Began and ended before the window: not listed.
        eid = self.store.open_event(self.now - 90_000, "outage", "critical",
                                    "wan", "old")
        self.store.close_event(eid, self.now - 89_000)
        listed = self.details(86_400)
        self.assertIn("straddles", listed)
        self.assertNotIn("old", listed)

    def test_orphans_are_closed_at_the_shortest_span(self):
        self.store.open_event(self.now - 90_000, "outage", "critical", "wan",
                              "orphan")
        # Left NULL, it charges every window forever.
        frac, _, _ = self.store.outage_stats(3600, now=self.now)
        self.assertAlmostEqual(frac, 1.0, places=3)
        self.assertEqual(self.store.close_orphans(self.now), 1)
        frac, _, _ = self.store.outage_stats(3600, now=self.now)
        self.assertEqual(frac, 0.0)
        row = self.store.events(10 ** 6, now=self.now)[0]
        self.assertEqual(row["ended_ts"], row["ts"] + 1)
        # Idempotent, and it never touches a properly closed row.
        self.assertEqual(self.store.close_orphans(self.now), 0)

    def test_prune_removes_events_past_the_hourly_horizon(self):
        eid = self.store.open_event(self.now - 500 * 86_400, "info", "info",
                                    "local", "ancient")
        self.store.close_event(eid, self.now - 500 * 86_400 + 1)
        eid = self.store.open_event(self.now - 10, "info", "info", "local",
                                    "recent")
        self.store.close_event(eid, self.now - 9)
        self.store.prune(now=self.now)
        listed = self.details(10 ** 9)
        self.assertNotIn("ancient", listed)
        self.assertIn("recent", listed)


class RollupNetworkLabel(unittest.TestCase):
    def test_an_hour_spanning_two_networks_is_labelled_neither(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        store = Store(Path(d.name) / "t.db")
        self.addCleanup(store.close)
        hour = 3_600_000
        store.put_minute(hour + 60, {"lag": 1.0}, iface="wlo1", network="Home")
        store.put_minute(hour + 120, {"lag": 1.0}, iface="wlo1", network="Office")
        store.put_minute(hour + 3660, {"lag": 1.0}, iface="wlo1", network="Office")
        store.rollup_hours(now=hour + 3 * 3600)
        rows, _ = store.series(10 ** 6, now=hour + 3 * 3600, resolution="hour")
        by_ts = {r["ts"]: r for r in rows}
        self.assertEqual(by_ts[hour]["network"], "")
        self.assertEqual(by_ts[hour]["iface"], "wlo1")
        self.assertEqual(by_ts[hour + 3600]["network"], "Office")


class DrainIsStored(unittest.TestCase):
    """The drain was published and never stored, so it could not be audited.

    That is why the distribution proving it is quantised by probe cadence had
    to come from the other implementation: this one had no history to look at.
    """

    def store(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        s = Store(Path(d.name) / "t.db")
        self.addCleanup(s.close)
        return s

    def test_a_minute_carries_the_drain_and_what_produced_it(self):
        s = self.store()
        s.put_minute(60, {"lag": 12.0, "drain_ms": 2000.0,
                          "drain_min_ms": 1000.0, "drain_settled": 1.0,
                          "drain_src": "tcp-anchor"},
                     iface="wlan0", network="home", probes="icmp+tcp")
        rows, _ = s.series(seconds=3600, now=120, resolution="minute")
        row = rows[0]
        self.assertEqual(row["drain_ms"], 2000.0)
        self.assertEqual(row["drain_min_ms"], 1000.0)
        self.assertEqual(row["drain_settled"], 1.0)
        self.assertEqual(row["drain_src"], "tcp-anchor")

    def test_never_measured_and_did_not_settle_stay_different(self):
        # None is "no drain in this minute"; 0.0 is "measured, never came
        # back inside the window". Collapsing them would turn a censored
        # observation into a real one.
        s = self.store()
        s.put_minute(60, {"drain_ms": 30000.0, "drain_settled": 0.0}, network="home")
        s.put_minute(120, {"lag": 9.0}, network="home")
        got, _ = s.series(seconds=3600, now=180, resolution="minute")
        rows = {r["ts"]: r for r in got}
        self.assertEqual(rows[60]["drain_settled"], 0.0)
        self.assertIsNone(rows[120]["drain_settled"])
        self.assertIsNone(rows[120]["drain_ms"])

    def test_the_drain_does_not_roll_up_into_an_hour(self):
        """A mean of drains destroys the only thing it is stored for.

        The value is quantised by probe cadence, so what has to survive is
        the distribution. Sixty of them averaged has none of that in it —
        the same objection the rollup already carries for percentiles, but
        binding harder, because here the spread IS the finding.
        """
        from nexthopd.store import SAMPLE_COLUMNS
        for c in ("drain_ms", "drain_min_ms", "drain_settled", "drain_src"):
            self.assertNotIn(c, SAMPLE_COLUMNS)
        s = self.store()
        cols = [r[1] for r in s.db.execute("PRAGMA table_info(hour)")]
        for c in ("drain_ms", "drain_min_ms", "drain_settled", "drain_src"):
            self.assertNotIn(c, cols)

    def test_an_older_database_gains_the_columns(self):
        # Additive migration only, as every schema change here has been.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = Path(d.name) / "old.db"
        old = sqlite3.connect(path)
        old.execute("CREATE TABLE minute (ts INTEGER PRIMARY KEY, lag REAL)")
        old.execute("CREATE TABLE hour (ts INTEGER PRIMARY KEY, lag REAL)")
        old.execute("CREATE TABLE tests (ts INTEGER, kind TEXT)")
        old.execute("CREATE TABLE events (ts INTEGER, kind TEXT)")
        old.commit()
        old.close()
        s = Store(path)
        self.addCleanup(s.close)
        cols = [r[1] for r in s.db.execute("PRAGMA table_info(minute)")]
        for c in ("drain_ms", "drain_min_ms", "drain_settled", "drain_src"):
            self.assertIn(c, cols)


if __name__ == "__main__":
    unittest.main()
