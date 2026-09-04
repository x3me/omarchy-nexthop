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


def wan_ip() -> Optional[dict]:
    """The address this connection appears from.

    Asked of a host the daemon already fetches from every hour — no new
    destination learns the user's address, which is the reason this is not
    an ifconfig-style third-party lookup. The URL is our constant, never
    anything a response handed us.
    """
    raw = _run(["curl", "-sf", "--proto", "=https", "--max-time", "5",
                "--max-filesize", "4096", TRACE_URL], timeout=8.0)
    return parse_trace(raw) if raw else None


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
    anything else is `intercepted`. Nothing at all is `silent`, which is not
    the same thing and must not be reported as one.
    """
    if not raw:
        return "silent"
    return "open" if parse_trace(raw) else "intercepted"


def reachability() -> dict:
    """One reachability check: the verdict, plus the address when proven."""
    raw = _run(["curl", "-sf", "--proto", "=https", "--max-time", "5",
                "--max-filesize", "4096", TRACE_URL], timeout=8.0)
    verdict = trace_verdict(raw)
    return {"verdict": verdict,
            "proof": parse_trace(raw) if verdict == "open" else None}
