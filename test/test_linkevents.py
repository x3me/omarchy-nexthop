"""Tests for linkevents.py and LinkWatch — who ended the association.

Run: python3 -m unittest discover -s test
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd.daemon import LinkWatch  # noqa: E402
from nexthopd.linkevents import NlEvents, reason_text  # noqa: E402
from nexthopd.store import Store  # noqa: E402
from support import StubEvents  # noqa: E402


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
        # Read the log on the recording's own clock. store.events() windows
        # on wall-clock now, so anchoring it anywhere else makes this test
        # pass until the fixture is a week old and fail every day after.
        evs = store.events(now=1788278083.0)
        self.assertEqual([e["kind"] for e in evs], ["kick"])
        self.assertEqual(
            evs[0]["detail"],
            "Kicked by AP 02:11:22:33:44:01 (reason 8: the AP is leaving the "
            "BSS), rejoined via 02:11:22:33:44:05 after 3 s, "
            "channel 1 \u2192 149, -30 \u2192 -40 dBm")


if __name__ == "__main__":
    unittest.main()
