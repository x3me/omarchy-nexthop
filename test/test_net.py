"""Tests for net.py — iw parsing, the trace verdict, tethering, the connection-name cache.

Run: python3 -m unittest discover -s test
"""

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexthopd import net  # noqa: E402
from nexthopd.net import nm_metered, tether_from_gateway  # noqa: E402
from support import FIXTURES  # noqa: E402


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


class TraceParsing(unittest.TestCase):
    """The cdn-cgi/trace response yields one validated address or nothing."""

    def test_recorded_response(self):
        # Recorded from a real fetch of speed.cloudflare.com/cdn-cgi/trace
        # (address substituted): sixteen key=value lines, ip= among them.
        text = (FIXTURES / "cf-trace.txt").read_text()
        # The recorded fixture carries loc=XX (Cloudflare's "unknown"), so
        # no country survives; its colo passes through validated.
        self.assertEqual(net.parse_trace(text),
                         {"ip": "198.51.100.7", "family": "v4",
                          "edge": "XXX"})

    def test_country_and_edge_come_free_with_the_address(self):
        # Both are already in the response the reachability check fetches.
        self.assertEqual(
            net.parse_trace("ip=1.2.3.4\nloc=IN\ncolo=DEL\n"),
            {"ip": "1.2.3.4", "family": "v4",
             "country": "IN", "edge": "DEL"})

    def test_unknown_country_is_withheld_not_shown(self):
        # Cloudflare answers XX when it does not know. Showing a country
        # called XX would be inventing one.
        got = net.parse_trace("ip=1.2.3.4\nloc=XX\ncolo=DEL\n")
        self.assertNotIn("country", got)
        self.assertEqual(got["edge"], "DEL")

    def test_only_a_country_shaped_country_gets_out(self):
        # Nothing free-form from the wire reaches the shell, same rule as
        # the address itself.
        for bad in ("in", "IND", "I", "I1", "<b>", "\u00cd\u00d1"):
            got = net.parse_trace("ip=1.2.3.4\nloc=%s\n" % bad)
            self.assertNotIn("country", got, bad)
        for bad in ("del", "D", "TOOLONG", "D3L", "<i>"):
            got = net.parse_trace("ip=1.2.3.4\ncolo=%s\n" % bad)
            self.assertNotIn("edge", got, bad)

    def test_country_and_edge_never_stand_in_for_an_address(self):
        # The address is the point; decoration alone is not a result.
        self.assertIsNone(net.parse_trace("loc=IN\ncolo=DEL\n"))
        self.assertIsNone(net.parse_trace("ip=nope\nloc=IN\ncolo=DEL\n"))

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


class TetherDetection(unittest.TestCase):
    """A phone sharing its data, from the one signal that is reliable."""

    def test_the_documented_ranges(self):
        self.assertEqual(tether_from_gateway("172.20.10.1"),
                         {"kind": "ios", "label": "iPhone"})
        self.assertEqual(tether_from_gateway("192.168.43.1")["kind"], "android")
        self.assertEqual(tether_from_gateway("192.168.42.129")["kind"],
                         "android")
        self.assertEqual(tether_from_gateway("192.168.137.1")["kind"],
                         "windows")

    def test_ordinary_gateways_are_not_phones(self):
        # Including the hotel gateway that started this: 172.20.0.1 is close
        # to the iOS range and outside it, so the /28 matters.
        for gw in ("192.168.1.1", "172.20.0.1", "10.0.0.1", "172.20.11.1"):
            self.assertIsNone(tether_from_gateway(gw), gw)

    def test_nothing_and_nonsense_are_not_phones(self):
        for gw in ("", None, "not-an-ip", "999.1.1.1"):
            self.assertIsNone(tether_from_gateway(gw))

    def test_ipv6_gateway_does_not_raise(self):
        self.assertIsNone(tether_from_gateway("fe80::1"))

    def test_a_guess_from_networkmanager_is_not_evidence(self):
        # A live iPhone hotspot reports "no (guessed)", so only an explicit
        # answer may count — and a guessed YES must not either.
        import nexthopd.net as netmod
        original = netmod._run
        try:
            for raw, expected in (
                ("GENERAL.METERED:yes", True),
                ("GENERAL.METERED:yes (guessed)", False),
                ("GENERAL.METERED:no", False),
                ("GENERAL.METERED:no (guessed)", False),
                ("", False),
                (None, False),
            ):
                netmod._run = lambda *a, **k: raw
                self.assertEqual(nm_metered("wlan0"), expected, raw)
        finally:
            netmod._run = original


class ConnectionNameCache(unittest.TestCase):
    def test_nmcli_is_asked_on_a_new_key_or_after_the_ttl_only(self):
        calls = []
        orig = net.connection_name
        net.connection_name = lambda iface: calls.append(iface) or "Home"
        net._name_cache.clear()
        self.addCleanup(setattr, net, "connection_name", orig)
        self.addCleanup(net._name_cache.clear)
        key = ("wlo1", "192.168.1.1", "aa:bb")
        self.assertEqual(net.connection_name_cached("wlo1", key, now=100), "Home")
        self.assertEqual(net.connection_name_cached("wlo1", key, now=130), "Home")
        self.assertEqual(len(calls), 1)
        # A new gateway or BSSID is a new network: ask again.
        net.connection_name_cached("wlo1", ("wlo1", "10.0.0.1", "aa:bb"), now=131)
        self.assertEqual(len(calls), 2)
        # ...and so is a rename the user made, eventually.
        net.connection_name_cached("wlo1", ("wlo1", "10.0.0.1", "aa:bb"),
                                   now=131 + net.NAME_CACHE_TTL_S + 1)
        self.assertEqual(len(calls), 3)


class AccessPointInventory(unittest.TestCase):
    def test_csv_maps_bssid_to_access_point_name(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bssid_to_ap_inventory.csv"
            path.write_text(
                "bssid,ap_name,band,channel,ssid\n"
                "8C:30:66:72:62:5F,Upstairs Hallway,6 GHz,209,PoolPartyUltra\n"
            )
            inventory = net.ApInventory(path)
            self.assertEqual(
                inventory.lookup("8c:30:66:72:62:5f"), "Upstairs Hallway")

    def test_utf8_bom_from_spreadsheet_exports_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bssid_to_ap_inventory.csv"
            path.write_text(
                "bssid,ap_name\n8c:30:66:72:62:5f,Upstairs Hallway\n",
                encoding="utf-8-sig")
            inventory = net.ApInventory(path)
            self.assertEqual(
                inventory.lookup("8c:30:66:72:62:5f"), "Upstairs Hallway")

    def test_invalid_rows_and_unknown_bssids_have_no_name(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bssid_to_ap_inventory.csv"
            path.write_text(
                "bssid,ap_name,band,channel,ssid\n"
                "not-a-bssid,Wrong,5 GHz,36,Office\n"
                "aa:bb:cc:dd:ee:ff,,5 GHz,36,Office\n"
            )
            inventory = net.ApInventory(path)
            self.assertIsNone(inventory.lookup("not-a-bssid"))
            self.assertIsNone(inventory.lookup("aa:bb:cc:dd:ee:ff"))
            self.assertIsNone(inventory.lookup("11:22:33:44:55:66"))

    def test_same_size_rewrite_is_seen_even_when_mtime_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bssid_to_ap_inventory.csv"
            before = ("bssid,ap_name\n"
                      "aa:bb:cc:dd:ee:ff,Kitchen\n")
            after = ("bssid,ap_name\n"
                     "aa:bb:cc:dd:ee:ff,Hallway\n")
            self.assertEqual(len(before), len(after))
            path.write_text(before)
            inventory = net.ApInventory(path)
            self.assertEqual(inventory.lookup("aa:bb:cc:dd:ee:ff"), "Kitchen")
            old_mtime = path.stat().st_mtime_ns
            path.write_text(after)
            os.utime(path, ns=(old_mtime, old_mtime))
            self.assertEqual(inventory.lookup("aa:bb:cc:dd:ee:ff"), "Hallway")

    def test_fifo_inventory_path_cannot_block_a_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bssid_to_ap_inventory.csv"
            os.mkfifo(path)
            inventory = net.ApInventory(path)
            done = threading.Event()
            worker = threading.Thread(
                target=lambda: (inventory.lookup("aa:bb:cc:dd:ee:ff"), done.set()),
                daemon=True)
            worker.start()
            completed_without_writer = done.wait(0.25)
            if not completed_without_writer:
                writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                os.close(writer)
                worker.join(1)
            self.assertTrue(completed_without_writer)

    def test_snapshot_publishes_the_known_access_point_name(self):
        originals = (net.route_to, net.is_wireless, net.wifi_link,
                     net.wifi_station, net.connection_name_cached,
                     net.AP_INVENTORY)
        net.route_to = lambda anchor: {
            "iface": "wlo1", "gateway": "192.168.1.1", "src": "192.168.1.2"}
        net.is_wireless = lambda iface: True
        net.wifi_link = lambda iface: {
            "bssid": "8c:30:66:72:62:5f", "ssid": "PoolPartyUltra"}
        net.wifi_station = lambda iface: {}
        net.connection_name_cached = lambda iface, key: "PoolPartyUltra"
        net.AP_INVENTORY = type("Inventory", (), {
            "lookup": lambda self, bssid: "Upstairs Hallway"})()
        try:
            self.assertEqual(net.snapshot()["ap_name"], "Upstairs Hallway")
        finally:
            (net.route_to, net.is_wireless, net.wifi_link,
             net.wifi_station, net.connection_name_cached,
             net.AP_INVENTORY) = originals

    def test_historical_event_bssids_are_decorated_for_display(self):
        inventory = type("Inventory", (), {
            "lookup": lambda self, bssid: {
                "aa:aa:aa:aa:aa:aa": "Kitchen",
                "bb:bb:bb:bb:bb:bb": "Upstairs Hallway",
            }.get(bssid)})()
        detail = "Roamed from aa:aa:aa:aa:aa:aa to bb:bb:bb:bb:bb:bb"
        self.assertEqual(
            net.decorate_bssids(detail, inventory),
            "Roamed from Kitchen (aa:aa:aa:aa:aa:aa) to "
            "Upstairs Hallway (bb:bb:bb:bb:bb:bb)")

    def test_already_decorated_event_is_not_decorated_twice(self):
        inventory = type("Inventory", (), {
            "lookup": lambda self, bssid: "Upstairs Hallway"})()
        detail = "Roamed to Upstairs Hallway (bb:bb:bb:bb:bb:bb)"
        self.assertEqual(net.decorate_bssids(detail, inventory), detail)

    def test_stored_name_survives_an_inventory_rename_without_nesting(self):
        inventory = type("Inventory", (), {
            "lookup": lambda self, bssid: "Current Hallway Name"})()
        detail = "Roamed to Stored Hallway Name (bb:bb:bb:bb:bb:bb)"
        self.assertEqual(net.decorate_bssids(detail, inventory), detail)

    def test_bssid_shaped_substrings_inside_words_are_not_decorated(self):
        inventory = type("Inventory", (), {
            "lookup": lambda self, bssid: "Hallway"})()
        detail = "xaa:bb:cc:dd:ee:ff and aa:bb:cc:dd:ee:ffz"
        self.assertEqual(net.decorate_bssids(detail, inventory), detail)


if __name__ == "__main__":
    unittest.main()
