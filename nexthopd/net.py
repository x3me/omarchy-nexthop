"""Reading the local end of the connection: route, interface, Wi-Fi link.

Everything here is a cheap read of /sys or a short-lived `ip` / `iw` call.
Nothing in this module blocks for longer than its subprocess timeout, and
every function degrades to None or {} rather than raising, because a laptop
that just suspended will fail all of them at once.
"""

import json
import ipaddress
import re
import shutil
import subprocess
from typing import Optional


def _run(cmd, timeout=2.0) -> Optional[str]:
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return out.stdout if out.returncode == 0 else None


# Gateway ranges that phone and desktop tethering hand out. Each is fixed by
# its vendor and documented, so this is a table lookup with no network call
# and nothing to keep up to date. It is the only reliable signal available:
# iOS randomises both the hotspot BSSID and the gateway's hardware address
# (checked on a live hotspot — `66:f8:f9:…` and `a2:ee:1a:…`, both with the
# locally-administered bit set), so vendor lookup on either is useless, and
# NetworkManager reports such a connection as "no (guessed)" rather than
# metered.
TETHER_RANGES = (
    # iOS Personal Hotspot, over Wi-Fi or USB. A /28 with the phone at .1.
    ("172.20.10.0/28", "ios", "iPhone"),
    # Android Wi-Fi tethering, and its USB counterpart.
    ("192.168.43.0/24", "android", "Phone"),
    ("192.168.42.0/24", "android", "Phone"),
    # Windows mobile hotspot.
    ("192.168.137.0/24", "windows", "Hotspot"),
)


def tether_from_gateway(gateway: str):
    """Is this gateway a phone sharing its connection? Pure, so it is tested.

    Returns `{"kind", "label"}` or None. `label` is what to call the middle
    node of the path — it is a phone, not a router, and drawing a router
    there quietly mislabels both legs.
    """
    if not gateway:
        return None
    try:
        addr = ipaddress.ip_address(gateway)
    except ValueError:
        return None
    for cidr, kind, label in TETHER_RANGES:
        try:
            if addr in ipaddress.ip_network(cidr):
                return {"kind": kind, "label": label}
        except ValueError:
            continue
    return None


def nm_metered(iface: str) -> bool:
    """Has the user explicitly marked this connection metered?

    Only an explicit answer counts. NetworkManager guesses by default and
    guesses wrong on a phone hotspot — a live one reports
    `no (guessed)` — so a guess is treated as no answer at all rather than
    as evidence either way.
    """
    if not iface or not shutil.which("nmcli"):
        return False
    raw = _run(["nmcli", "-t", "-f", "GENERAL.METERED", "dev", "show", iface],
               timeout=4.0)
    if not raw:
        return False
    value = raw.split(":", 1)[-1].strip().lower() if ":" in raw else ""
    return value.startswith("yes") and "guess" not in value


def route_to(anchor: str = "1.1.1.1") -> dict:
    """The interface, gateway and source address used to reach the anchor.

    This is the single source of truth for "which connection am I on" — the
    gateway it returns is the router leg's ping target.
    """
    raw = _run(["ip", "-j", "route", "get", anchor])
    if not raw:
        return {}
    try:
        rows = json.loads(raw)
    except ValueError:
        return {}
    if not rows:
        return {}
    r = rows[0]
    return {
        "iface": r.get("dev") or "",
        "gateway": r.get("gateway") or "",
        "src": r.get("prefsrc") or "",
    }


def is_wireless(iface: str) -> bool:
    if not iface:
        return False
    from pathlib import Path

    return Path(f"/sys/class/net/{iface}/wireless").is_dir()


def counters(iface: str) -> Optional[tuple]:
    """(rx_bytes, tx_bytes) straight off /sys, or None if the iface vanished."""
    if not iface:
        return None
    try:
        base = f"/sys/class/net/{iface}/statistics/"
        with open(base + "rx_bytes") as f:
            rx = int(f.read().strip())
        with open(base + "tx_bytes") as f:
            tx = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return rx, tx


def _num(text: str):
    """First number in a string, as int when it is whole.

    `iw` is inconsistent across versions — this machine reports
    `freq: 5180.0` where older builds print `freq: 5180`.
    """
    m = re.search(r"-?\d+(?:\.\d+)?", text or "")
    if not m:
        return None
    v = float(m.group(0))
    return int(v) if v.is_integer() else v


def wifi_link(iface: str) -> dict:
    """SSID, signal, band and negotiated rates from `iw dev <iface> link`."""
    raw = _run(["iw", "dev", iface, "link"])
    if not raw or "Not connected" in raw:
        return {}
    info = {}
    bssid = re.search(r"Connected to ([0-9a-fA-F:]{17})", raw)
    if bssid:
        info["bssid"] = bssid.group(1)
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("SSID:"):
            info["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("freq:"):
            info["freq_mhz"] = _num(line)
        elif line.startswith("signal:"):
            info["signal_dbm"] = _num(line)
        elif line.startswith("rx bitrate:"):
            info["rx_mbps"] = _num(line)
        elif line.startswith("tx bitrate:"):
            info["tx_mbps"] = _num(line)
            width = re.search(r"(\d+)MHz", line)
            if width:
                info["width_mhz"] = int(width.group(1))
            for std, tag in (("HE", "802.11ax"), ("VHT", "802.11ac"), ("HT", "802.11n")):
                if f"{std}-MCS" in line:
                    info["standard"] = tag
                    break
    freq = info.get("freq_mhz")
    if freq:
        info["band"] = "6 GHz" if freq >= 5955 else "5 GHz" if freq >= 4900 else "2.4 GHz"
        info["channel"] = _freq_to_channel(freq)
    return info


def _freq_to_channel(freq) -> Optional[int]:
    f = int(freq)
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5160 <= f <= 5885:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    return None


def wifi_station(iface: str) -> dict:
    """Airtime health from `iw station dump`.

    Retries and failures are why Wi-Fi feels slow while the signal bar still
    looks full, so they are worth the extra call.
    """
    raw = _run(["iw", "dev", iface, "station", "dump"])
    if not raw:
        return {}
    fields = {
        "tx retries:": "tx_retries",
        "tx failed:": "tx_failed",
        "beacon loss:": "beacon_loss",
        "rx drop misc:": "rx_drop_misc",
        "tx packets:": "tx_packets",
        "rx packets:": "rx_packets",
        "signal avg:": "signal_avg_dbm",
        "inactive time:": "inactive_ms",
    }
    out = {}
    for line in raw.splitlines():
        s = line.strip()
        for prefix, key in fields.items():
            if s.startswith(prefix):
                v = _num(s[len(prefix):])
                if v is not None:
                    out[key] = v
                break
    return out


def connection_name(iface: str) -> str:
    """The name NetworkManager shows, which is what the user calls this network."""
    raw = _run(["nmcli", "-t", "-f", "GENERAL.CONNECTION", "dev", "show", iface])
    if not raw:
        return ""
    for line in raw.splitlines():
        if line.startswith("GENERAL.CONNECTION:"):
            name = line.split(":", 1)[1].strip()
            return "" if name in ("", "--") else name
    return ""


def snapshot(anchor: str = "1.1.1.1") -> dict:
    """Everything about the local end, in one call, safe to run once a second."""
    route = route_to(anchor)
    iface = route.get("iface", "")
    snap = {
        "iface": iface,
        "gateway": route.get("gateway", ""),
        "src": route.get("src", ""),
        "kind": "none",
    }
    if not iface:
        return snap
    snap["kind"] = "wifi" if is_wireless(iface) else "ethernet"
    snap["name"] = connection_name(iface) or iface
    if snap["kind"] == "wifi":
        snap.update(wifi_link(iface))
        snap["station"] = wifi_station(iface)
    return snap


# ------------------------------------------------------------- wan address

TRACE_URL = "https://speed.cloudflare.com/cdn-cgi/trace"


def parse_trace(text: str) -> Optional[dict]:
    """The `ip=` line of a cdn-cgi/trace response, validated or nothing.

    Only a value that `ipaddress` accepts ever leaves this function —
    whatever else the response carries is discarded unread. Input is
    bounded before it is split, so an oversized body costs one slice.
    """
    for line in text[:4096].splitlines()[:64]:
        if not line.startswith("ip="):
            continue
        try:
            addr = ipaddress.ip_address(line[3:].strip())
        except ValueError:
            return None
        return {"ip": str(addr), "family": "v6" if addr.version == 6 else "v4"}
    return None


def trace_verdict(raw) -> str:
    """Did the real internet answer? `open` | `intercepted` | `silent`.

    The same fetch that reads the WAN address is also the only thing here
    that can tell the real internet from something standing in for it. A
    probe reply proves a packet came back; it does not prove what sent it.
    A captive portal, a transparent proxy or any middlebox will happily
    complete a handshake and answer for an address it does not own — which
    is how an unauthenticated hotel network produced a healthy-looking
    internet leg with no internet behind it.

    `open` is the only positive claim, and it needs the response to parse as
    a trace with an address `ipaddress` accepts. Something that answered with
    anything else is `intercepted`. Nothing at all is `silent`.

    Honest limit: the fetch runs `curl -f`, so a portal that answers with a
    4xx/5xx, a redirect with an empty body, or a certificate that does not
    validate for the host all come back as nothing — `silent`. In practice
    `intercepted` needs a portal that serves a 200 over a certificate valid
    for speed.cloudflare.com, which is rare. The captive decision does not
    care (both verdicts count against `open`); only this label does.
    """
    if not raw:
        return "silent"
    return "open" if parse_trace(raw) else "intercepted"


def reachability() -> dict:
    """One reachability check: the verdict, plus the address when proven.

    This is also where the WAN address comes from — the `proof` — so the
    machine's address is only ever asked of a host the daemon talks to
    anyway, never of an ifconfig-style third party. The URL is our
    constant, never anything a response handed us. Cadence is the caller's
    (CaptiveWatch): on every new network, hourly once the internet has
    answered, every 30 s only while it has not.
    """
    raw = _run(["curl", "-sf", "--proto", "=https", "--max-time", "5",
                "--max-filesize", "4096", TRACE_URL], timeout=8.0)
    verdict = trace_verdict(raw)
    return {"verdict": verdict,
            "proof": parse_trace(raw) if verdict == "open" else None}
