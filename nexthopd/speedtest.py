"""Speed measurement, two kinds.

Content speed: a short ranged download and a small upload, on a schedule, small enough to
be honest about the connection without being a burden on it. This is what
feeds the Speed score, following Orb's split — score the everyday number,
keep the fireworks manual.

Peak speed: saturates the line, only ever on demand. Prefers the official
Ookla CLI when installed (server choice, shareable result), falls back to
Cloudflare's endpoints via curl, then fast.com via the same API Omarchy's
built-in speed test uses. Both fallbacks need nothing installed beyond curl.

Loaded latency is sampled during the peak download by the daemon's existing
probes, not here — the test just records the window it ran in.
"""

import ipaddress
import json
import shutil
import socket
import subprocess
import time
from typing import Optional
from urllib.parse import urlparse

CLOUDFLARE_DOWN = "https://speed.cloudflare.com/__down?bytes={n}"
CLOUDFLARE_UP = "https://speed.cloudflare.com/__up"
# The token fast.com's own web client uses; Omarchy's built-in speed test
# ships the same one.
FAST_API = ("https://api.fast.com/netflix/speedtest/v2"
            "?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3")


def vet_target(url: str):
    """(url, --resolve argument) for a target we will fetch, else None.

    Only for URLs WE DID NOT CHOOSE. fast.com nominates its own download
    hosts, so that JSON decides what this daemon connects to, and it has
    to be treated as hostile input rather than as a list of Netflix
    servers. Three things must hold:

    1. the scheme is https, so a nominated target cannot downgrade the
       transfer to plaintext or hand curl a `file://` path;
    2. EVERY address the host resolves to is public, so a speed test can
       never be aimed at a router's admin page, a service on loopback,
       or a link-local metadata address;
    3. the address that passed (2) is the one curl actually connects to.

    The third is the point most of this class gets wrong: resolving here
    and letting curl resolve again is a check-then-use race, and a DNS
    answer that returns a public address to us and a private one to curl
    wins it. Pinning the vetted addresses with --resolve closes that
    window, the same way every other read in this daemon is enforced on
    the thing actually used rather than on a name looked up earlier.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    port = parsed.port or 443
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except (OSError, ValueError, UnicodeError):
        return None
    addrs = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return None
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        # Spelled out rather than leaning on is_global alone, whose range
        # table has been corrected across Python versions we may run on.
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return None
        addrs.append(str(ip))
    if not addrs:
        return None
    return url, "%s:%d:%s" % (parsed.hostname, port, ",".join(addrs))


def _curl(args, timeout) -> Optional[subprocess.CompletedProcess]:
    if not shutil.which("curl"):
        return None
    try:
        # --proto =https refuses anything but TLS even if a target or a
        # server tries something else; we never pass -L, so there is no
        # redirect for it to follow either.
        return subprocess.run(["curl", "-fsS", "--proto", "=https",
                               "--max-time", str(int(timeout))] + args,
                              capture_output=True, text=True, timeout=timeout + 5,
                              check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None


# A transfer shorter than this carried too few bytes for its own duration to
# be worth dividing by: the timing error, not the line, would set the answer.
MIN_TIMED_WINDOW_S = 0.05


def _rate_over_payload(size: float, t_total: float, t_payload_start: float):
    """Mbps over the part of the request that actually carried bytes.

    curl's own `speed_download` divides the bytes by the WHOLE request —
    DNS, the TCP connect, the TLS handshake and the wait for the first byte
    included. None of that carried payload, and none of it shrinks when the
    line gets faster, so it is a fixed tax on a measurement whose useful part
    keeps getting shorter: a 3 MB stream is ~240 ms of payload on a 400 Mbps
    line and ~107 ms on a gigabit one, against the same ~70-90 ms of setup.
    That is not noise. It is a bias that grows with the quantity being
    measured, which made the check read a 900 Mbps line as roughly 220 and
    put a ceiling near 480 on a scale whose top two anchors are 500 and 750.

    Dividing by a window instead of by the total is only honest while the
    window is long enough to divide by, so a sample too short to time is
    withheld rather than published — the same rule the rest of the daemon
    uses for a figure it cannot stand behind.
    """
    window = t_total - t_payload_start
    if window < MIN_TIMED_WINDOW_S or size <= 0:
        return None
    return size * 8 / 1e6 / window


def _curl_timed_download(url: str, timeout: float, resolve: str = None):
    """(mbps, bytes), timed over the payload rather than the whole request."""
    pin = ["--resolve", resolve] if resolve else []
    r = _curl(pin + ["-o", "/dev/null",
                     "-w", "%{size_download} %{time_total} %{time_starttransfer}",
                     url],
              timeout)
    if not r or r.returncode != 0:
        return None, 0
    try:
        size, t_total, t_start = (float(x) for x in r.stdout.split())
    except ValueError:
        return None, 0
    return _rate_over_payload(size, t_total, t_start), int(size)


def _curl_timed_upload(url: str, n_bytes: int, timeout: float):
    """Upload n_bytes of zeros. The body is piped in — pointing curl at
    /dev/zero directly would have it read the file to its end, which
    /dev/zero does not have."""
    if not shutil.which("curl"):
        return None, 0
    cmd = ["curl", "-fsS", "--proto", "=https", "--max-time", str(int(timeout)),
           "-o", "/dev/null", "-X", "POST", "--data-binary", "@-",
           "-H", "Content-Type: application/octet-stream",
           # Not time_starttransfer: on a POST that lands part way through
           # the body, not after it. The TLS handshake completing is when
           # this request starts putting bytes on the wire.
           "-w", "%{size_upload} %{time_total} %{time_appconnect}", url]
    try:
        r = subprocess.run(cmd, input=b"\0" * n_bytes, capture_output=True,
                           timeout=timeout + 5, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None, 0
    if r.returncode != 0:
        return None, 0
    try:
        size, t_total, t_app = (float(x) for x in r.stdout.decode().split())
    except (ValueError, UnicodeDecodeError):
        return None, 0
    return _rate_over_payload(size, t_total, t_app), int(size)


def _parallel_download(url: str, streams: int, timeout: float):
    """Sum of concurrent stream rates.

    One TCP stream at ~10 ms of latency tops out far below a fast line's
    capacity — a single-stream check read this 450 Mbps connection as 54.
    Real page loads and video players open several connections, so several
    streams is the honest simulation, and their sum is the number.
    """
    if not shutil.which("curl"):
        return None, 0
    procs = []
    for _ in range(streams):
        try:
            procs.append(subprocess.Popen(
                ["curl", "-fsS", "--proto", "=https",
                 "--max-time", str(int(timeout)), "-o", "/dev/null",
                 "-w", "%{size_download} %{time_total} %{time_starttransfer}",
                 url],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True))
        except OSError:
            pass
    total_mbps, total_bytes, any_ok = 0.0, 0, False
    for p in procs:
        try:
            out, _ = p.communicate(timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            continue
        if p.returncode != 0:
            continue
        try:
            size, t_total, t_start = (float(x) for x in out.split())
        except ValueError:
            continue
        mbps = _rate_over_payload(size, t_total, t_start)
        total_bytes += int(size)
        # A stream too short to time is dropped, not counted as zero: summing
        # a withheld stream in as 0 would understate the line by exactly the
        # bias this accounting exists to remove.
        if mbps is None:
            continue
        any_ok = True
        total_mbps += mbps
    return (total_mbps if any_ok else None), total_bytes


def content_test(down_bytes: int = 12_000_000, up_bytes: int = 2_000_000,
                 streams: int = 4) -> dict:
    """The scheduled check: ~14 MB total, a handful of seconds."""
    started = time.time()
    per_stream = max(1_000_000, down_bytes // streams)
    down_mbps, down_n = _parallel_download(
        CLOUDFLARE_DOWN.format(n=per_stream), streams, timeout=30)
    up_mbps, up_n = _curl_timed_upload(CLOUDFLARE_UP, up_bytes, timeout=30)
    return {
        "kind": "content",
        "engine": "cloudflare",
        "ok": down_mbps is not None,
        "down_mbps": round(down_mbps, 1) if down_mbps else None,
        "up_mbps": round(up_mbps, 1) if up_mbps else None,
        "bytes": down_n + up_n,
        "started": started,
        "ended": time.time(),
    }


def _peak_ookla() -> Optional[dict]:
    """The official Speedtest CLI, when the user has installed it."""
    if not shutil.which("speedtest"):
        return None
    try:
        r = subprocess.run(
            ["speedtest", "--format=json", "--accept-license", "--accept-gdpr"],
            capture_output=True, text=True, timeout=120, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    try:
        j = json.loads(r.stdout)
        return {
            "engine": "ookla",
            "ok": True,
            "down_mbps": round(j["download"]["bandwidth"] * 8 / 1e6, 1),
            "up_mbps": round(j["upload"]["bandwidth"] * 8 / 1e6, 1),
            "ping_idle": round(j["ping"]["latency"], 1),
            "jitter": round(j["ping"].get("jitter", 0), 1),
            "bytes": j["download"].get("bytes", 0) + j["upload"].get("bytes", 0),
            "server": f'{j["server"].get("name", "")} · {j["server"].get("location", "")}',
            "url": j.get("result", {}).get("url", ""),
        }
    except (ValueError, KeyError, TypeError, AttributeError):
        # Someone else's JSON: a missing key, a string where a number was
        # expected, a list where an object was. Any of those is a failed
        # engine, not a dead worker thread.
        return None


PEAK_TARGET_S = 10           # aim each sustained pass at about this long
PEAK_STREAMS = 4
# __down 403s any single request of 100 MB or more; each parallel stream
# stays under that and the streams together still carry a fast line.
CLOUDFLARE_DOWN_MAX = 99_999_999
PEAK_DOWN_FLOOR = 10_000_000
PEAK_UP_FLOOR = 5_000_000
PEAK_UP_CAP = 100_000_000    # also bounds the in-memory upload body


def _sized_pass(mbps: float, floor: int, cap: int) -> int:
    """Bytes that should take about PEAK_TARGET_S at the measured rate."""
    return max(floor, min(cap, int(mbps / 8 * PEAK_TARGET_S * 1e6)))


def _pass_seconds(mbps: float, n_bytes: int) -> float:
    return n_bytes * 8 / (mbps * 1e6)


def _peak_cloudflare() -> Optional[dict]:
    """An estimate pass sizes a sustained pass.

    Fixed sizes made the whole test finish inside TCP ramp-up on a fast
    line (2-3 s end to end), which both under-reads the line and leaves
    the loaded-latency window with a handful of probe samples. The
    estimate pass measures the rate; the sustained pass is sized to hold
    that rate for ~PEAK_TARGET_S, split over parallel streams because a
    single stream can neither exceed the per-request byte cap nor fill a
    fast line by itself. A slow line's estimate pass already runs that
    long and doubles as the sustained pass.
    """
    total = 0
    best_down, size = _curl_timed_download(CLOUDFLARE_DOWN.format(n=25_000_000),
                                           timeout=40)
    total += size
    if best_down and _pass_seconds(best_down, size) < PEAK_TARGET_S * 0.6:
        n = _sized_pass(best_down / PEAK_STREAMS, PEAK_DOWN_FLOOR,
                        CLOUDFLARE_DOWN_MAX)
        mbps, size = _parallel_download(CLOUDFLARE_DOWN.format(n=n),
                                        PEAK_STREAMS, timeout=40)
        total += size
        if mbps:
            best_down = max(best_down, mbps)
    best_up = 0.0
    up_est, size = _curl_timed_upload(CLOUDFLARE_UP, 10_000_000, timeout=40)
    total += size
    if up_est:
        best_up = up_est
        if _pass_seconds(up_est, size) < PEAK_TARGET_S * 0.6:
            n = _sized_pass(up_est, PEAK_UP_FLOOR, PEAK_UP_CAP)
            mbps, size = _curl_timed_upload(CLOUDFLARE_UP, n, timeout=40)
            total += size
            if mbps:
                best_up = max(best_up, mbps)
    if not best_down:
        return None
    return {
        "engine": "cloudflare",
        "ok": True,
        "down_mbps": round(best_down, 1),
        "up_mbps": round(best_up, 1) if best_up else None,
        "bytes": total,
        "server": "speed.cloudflare.com",
    }


def _peak_fast() -> Optional[dict]:
    """Download-only, via the Netflix OCA endpoints fast.com hands out.

    The API picks the hosts, so each one is vetted before it is fetched
    (see vet_target) and a target that does not pass is skipped rather
    than failing the test — a bad entry in someone else's JSON should
    cost us one candidate, not the measurement.
    """
    r = _curl([FAST_API], timeout=15)
    if not r or r.returncode != 0:
        return None
    try:
        targets = [t["url"] for t in json.loads(r.stdout).get("targets", []) if t.get("url")]
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    vetted = [v for v in (vet_target(u) for u in targets if isinstance(u, str)) if v]
    best = 0.0
    total = 0
    for url, resolve in vetted[:3]:
        mbps, size = _curl_timed_download(url, timeout=30, resolve=resolve)
        total += size
        if mbps:
            best = max(best, mbps)
    if not best:
        return None
    return {"engine": "fast.com", "ok": True, "down_mbps": round(best, 1),
            "up_mbps": None, "bytes": total, "server": "Netflix OCA"}


def peak_test(engine: str = "Auto") -> dict:
    """On-demand, engine per the user's setting."""
    started = time.time()
    order = {
        "Auto": (_peak_ookla, _peak_cloudflare, _peak_fast),
        "Ookla": (_peak_ookla,),
        "Cloudflare": (_peak_cloudflare,),
        "fast.com": (_peak_fast,),
    }.get(engine, (_peak_ookla, _peak_cloudflare, _peak_fast))
    for fn in order:
        result = fn()
        if result:
            result.update({"kind": "peak", "started": started, "ended": time.time()})
            return result
    return {"kind": "peak", "engine": engine, "ok": False,
            "started": started, "ended": time.time()}
