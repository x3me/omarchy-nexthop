"""Tests for net.py — iw parsing, the trace verdict, tethering, the connection-name cache.

Run: python3 -m unittest discover -s test
"""

import sys
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


class TunnelDetection(unittest.TestCase):
    """Which link a route leaves by, read from the kernel, never from a name.

    The shapes come from emulating each setup in an `unshare -rn` namespace
    against the real route code (2026-09-13): wg-quick and a Tailscale exit
    node give the anchor a route with no gateway, OpenVPN def1 gives it the
    tunnel peer. The link types are what this laptop's own kernel reports:
    wlo1 1, docker0 1, tailscale0 65534 with tun_flags.
    """

    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.sys = self.dir.name
        self.link("wlo1", 1, uevent="DEVTYPE=wlan\n")
        self.link("docker0", 1, uevent="DEVTYPE=bridge\n")
        self.link("wg0", 65534, uevent="DEVTYPE=wireguard\n")
        self.link("tailscale0", 65534, tun_flags="0x5001\n")
        self.link("tun0", 65534, tun_flags="0x1001\n")
        self.link("ppp0", 512)
        self.link("ipip0", 768)

    def link(self, name, arphrd, uevent="", tun_flags=None):
        d = Path(self.sys) / name
        d.mkdir()
        (d / "type").write_text("%d\n" % arphrd)
        (d / "uevent").write_text(uevent)
        if tun_flags is not None:
            (d / "tun_flags").write_text(tun_flags)

    def test_tunnels_are_known_by_link_type(self):
        for name in ("wg0", "tailscale0", "tun0", "ppp0", "ipip0"):
            self.assertTrue(net.is_tunnel_link(name, self.sys), name)
        for name in ("wlo1", "docker0", "absent0"):
            self.assertFalse(net.is_tunnel_link(name, self.sys), name)

    def test_a_name_that_did_not_come_from_the_kernel_is_not_read(self):
        (Path(self.sys) / "type").write_text("65534\n")
        for bad in ("", "..", ".", "../wg0", "wg0/../wg0", "a" * 16, "wg 0"):
            self.assertFalse(net.is_tunnel_link(bad, self.sys), repr(bad))

    def test_the_label_comes_from_the_kernel_where_it_can(self):
        self.assertEqual(net.tunnel_type("wg0", self.sys), "wireguard")
        self.assertEqual(net.tunnel_type("tailscale0", self.sys), "tailscale")
        self.assertEqual(net.tunnel_type("tun0", self.sys), "tun")
        self.assertEqual(net.tunnel_type("ppp0", self.sys), "ppp")
        self.assertEqual(net.tunnel_type("ipip0", self.sys), "tunnel")

    # `ip -j route show default` on this laptop, plus the default route
    # NetworkManager's OpenVPN adds beside it with a lower metric.
    DEFAULTS = ('[{"dst":"default","gateway":"10.8.0.1","dev":"tun0","metric":50,"flags":[]},'
                '{"dst":"default","gateway":"192.168.10.1","dev":"wlo1","protocol":"dhcp",'
                '"prefsrc":"192.168.10.219","metric":600,"flags":[]}]')

    def test_the_physical_default_skips_a_tunnel_with_a_better_metric(self):
        self.assertEqual(net.physical_default(self.DEFAULTS, self.sys),
                         {"iface": "wlo1", "gateway": "192.168.10.1",
                          "src": "192.168.10.219"})

    def test_no_physical_default_is_an_empty_answer(self):
        only_ppp = '[{"dst":"default","dev":"ppp0","flags":[]}]'
        self.assertEqual(net.physical_default(only_ppp, self.sys), {})
        self.assertEqual(net.physical_default("not json", self.sys), {})
        self.assertEqual(net.physical_default(None, self.sys), {})

    def route(self, table):
        return lambda target: dict(table.get(target, {}))

    def test_an_ordinary_link_costs_no_extra_read(self):
        def defaults():
            raise AssertionError("ip route show default must not run")
        here = {"iface": "wlo1", "gateway": "192.168.10.1", "src": "192.168.10.219"}
        got = net.local_route("1.1.1.1", self.sys,
                              route=self.route({"1.1.1.1": here}), defaults=defaults)
        self.assertEqual(got, here)

    def test_under_wg_quick_the_router_is_still_the_physical_gateway(self):
        # Before: no gateway, so no router probe was created at all.
        tunnel = {"iface": "wg0", "gateway": "", "src": "10.66.66.2"}
        got = net.local_route("1.1.1.1", self.sys,
                              route=self.route({"1.1.1.1": tunnel}),
                              defaults=lambda: self.DEFAULTS)
        self.assertEqual(got["iface"], "wlo1")
        self.assertEqual(got["gateway"], "192.168.10.1")
        self.assertEqual(got["tunnel_iface"], "wg0")

    def test_under_openvpn_def1_the_peer_is_not_taken_for_the_router(self):
        # Before: the router leg pinged 10.8.0.1, the VPN server's end.
        tunnel = {"iface": "tun0", "gateway": "10.8.0.1", "src": "10.8.0.6"}
        got = net.local_route("1.1.1.1", self.sys,
                              route=self.route({"1.1.1.1": tunnel}),
                              defaults=lambda: self.DEFAULTS)
        self.assertEqual(got["gateway"], "192.168.10.1")

    def test_pppoe_is_the_line_not_a_vpn(self):
        # ppp0 with nothing physical underneath it IS the internet link.
        line = {"iface": "ppp0", "gateway": "", "src": "203.0.113.7"}
        got = net.local_route("1.1.1.1", self.sys,
                              route=self.route({"1.1.1.1": line}),
                              defaults=lambda: '[{"dst":"default","dev":"ppp0"}]')
        self.assertEqual(got, line)
        self.assertNotIn("tunnel_iface", got)

    TARGETS = {"icmp-anchor": "1.1.1.1", "tcp-anchor": "1.1.1.1",
               "tcp-cf": "speed.cloudflare.com", "tcp-google": "dns.google"}

    def resolve(self, table):
        def fake(host, port, type=None):
            if host not in table:
                raise OSError("no such host")
            return [(2, 1, 6, "", (table[host], port))]
        return fake

    NAMES = {"speed.cloudflare.com": "198.51.100.10", "dns.google": "198.51.100.20"}

    def test_a_full_tunnel(self):
        via = {"iface": "wg0"}
        got = net.tunnel_routes(self.TARGETS, "wlo1", self.sys,
                                route=lambda t: via, resolve=self.resolve(self.NAMES))
        self.assertEqual(got, {"iface": "wg0", "type": "wireguard", "scope": "full",
                               "via": ["icmp-anchor", "tcp-anchor", "tcp-cf",
                                       "tcp-google"], "probed": 4})

    def test_a_split_tunnel_says_how_much_of_it(self):
        table = {"1.1.1.1": {"iface": "wlo1"}, "198.51.100.10": {"iface": "tun0"},
                 "198.51.100.20": {"iface": "wlo1"}}
        got = net.tunnel_routes(self.TARGETS, "wlo1", self.sys,
                                route=self.route(table), resolve=self.resolve(self.NAMES))
        self.assertEqual((got["scope"], got["via"], got["probed"]),
                         ("partial", ["tcp-cf"], 4))

    def test_a_tunnel_that_carries_no_probe_is_not_a_vpn(self):
        # Tailscale connected without an exit node — on this laptop and on
        # the M4 Air in the first real test — routes nothing of ours.
        got = net.tunnel_routes(self.TARGETS, "wlo1", self.sys,
                                route=lambda t: {"iface": "wlo1"},
                                resolve=self.resolve(self.NAMES))
        self.assertIsNone(got)

    def test_the_physical_link_itself_is_never_the_tunnel(self):
        got = net.tunnel_routes(self.TARGETS, "ppp0", self.sys,
                                route=lambda t: {"iface": "ppp0"},
                                resolve=self.resolve(self.NAMES))
        self.assertIsNone(got)

    def test_an_unresolvable_target_is_left_out_not_guessed(self):
        got = net.tunnel_routes(self.TARGETS, "wlo1", self.sys,
                                route=lambda t: {"iface": "wg0"},
                                resolve=self.resolve({}))
        self.assertEqual((got["scope"], got["probed"]), ("full", 2))
        self.assertEqual(got["via"], ["icmp-anchor", "tcp-anchor"])


if __name__ == "__main__":
    unittest.main()
