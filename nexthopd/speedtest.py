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
import threading
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


def _upload_argv(url: str, timeout: float):
    """The one upload invocation, shared by the single and parallel forms.

    The body is piped in — pointing curl at /dev/zero directly would have it
    read the file to its end, which /dev/zero does not have."""
    return ["curl", "-fsS", "--proto", "=https", "--max-time", str(int(timeout)),
            "-o", "/dev/null", "-X", "POST", "--data-binary", "@-",
            "-H", "Content-Type: application/octet-stream",
            # Not time_starttransfer: on a POST that is the first byte of the
            # RESPONSE, and against speed.cloudflare.com it arrives right after
            # the handshake (the 100-continue), not after the body. The TLS
            # handshake completing is when this request starts putting bytes
            # on the wire.
            "-w", "%{size_upload} %{time_total} %{time_appconnect}", url]


def _parallel_upload(url: str, per_stream: int, streams: int, timeout: float):
    """Sum of concurrent upload stream rates.

    The download learned in 0.1.x that one TCP stream cannot fill a fast line —
    a single-stream check read this 450 Mbps connection as 54 — and grew
    `_parallel_download` for it. The upload never did, in either the hourly
    check or the peak, so both were reading one stream's ceiling and calling
    it the line. Measured here: the same 2 MB carried by four streams instead
    of one read 36% higher, and 4 MB over four streams read more than twice
    what the shipping 2 MB over one did.

    Every stream is handed the same immutable buffer, so the memory cost is
    one stream's worth of zeros rather than N.
    """
    if not shutil.which("curl"):
        return None, 0
    body = b"\0" * per_stream
    procs = []
    for _ in range(streams):
        try:
            spawned = time.monotonic()
            procs.append((subprocess.Popen(
                _upload_argv(url, timeout), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL), spawned))
        except OSError:
            pass
    # A pipe holds far less than a stream's body, so writing them in turn
    # would serialise the very thing being parallelised: each child gets a
    # thread that feeds it and collects its result.
    outs = [None] * len(procs)

    def feed(i, proc):
        try:
            outs[i] = proc.communicate(input=body, timeout=timeout + 10)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    workers = [threading.Thread(target=feed, args=(i, proc), daemon=True)
               for i, (proc, _) in enumerate(procs)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout + 15)

    windows, total_bytes = [], 0
    for i, (proc, spawned) in enumerate(procs):
        if proc.returncode != 0 or not outs[i]:
            continue
        try:
            size, t_total, t_app = (float(x) for x in outs[i].decode().split())
        except (ValueError, UnicodeDecodeError):
            continue
        total_bytes += int(size)
        windows.append((size, spawned + t_app, spawned + t_total))
    return _aggregate_rate(windows), total_bytes


def _curl_timed_upload(url: str, n_bytes: int, timeout: float):
    """One upload stream. Kept for the peak's estimate pass, which only needs
    a rough rate to size the real one."""
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


def _aggregate_rate(windows):
    """Mbps carried by a set of parallel streams.

    NOT the sum of their individual rates. Streams do not start or finish
    together — TLS handshakes complete tens to hundreds of milliseconds apart
    — so a stream that outlives the others has the line to itself and measures
    all of it. Adding that to what its siblings measured while sharing counts
    the same link two, three, four times. Observed on this ~450 Mbps line:
    summing gave 647 / 629 / 538 Mbps for transfers that actually carried
    323 / 276 / 269.

    The honest figure is what crossed the wire divided by the time the wire
    spent carrying it: total bytes over the union of the streams' payload
    windows. The union rather than first-start-to-last-finish, so a gap
    between streams is not billed as throughput.

    `windows` is (bytes, absolute start, absolute end) per stream.
    """
    windows = [w for w in windows if w[0] > 0 and w[2] > w[1]]
    if not windows:
        return None
    total_bytes = sum(w[0] for w in windows)
    spans = sorted((w[1], w[2]) for w in windows)
    union, cur_s, cur_e = 0.0, spans[0][0], spans[0][1]
    for s, e in spans[1:]:
        if s > cur_e:
            union += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    union += cur_e - cur_s
    if union < MIN_TIMED_WINDOW_S:
        return None
    return total_bytes * 8 / 1e6 / union


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
            # curl times everything from its own start, and the children are
            # spawned a few milliseconds apart, so their clocks have to be
            # put on a common origin before their windows can be compared.
            spawned = time.monotonic()
            procs.append((subprocess.Popen(
                ["curl", "-fsS", "--proto", "=https",
                 "--max-time", str(int(timeout)), "-o", "/dev/null",
                 "-w", "%{size_download} %{time_total} %{time_starttransfer}",
                 url],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True),
                spawned))
        except OSError:
            pass
    windows, total_bytes = [], 0
    for p, spawned in procs:
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
        total_bytes += int(size)
        windows.append((size, spawned + t_start, spawned + t_total))
    return _aggregate_rate(windows), total_bytes


# Each stream aims for about this much time actually carrying bytes: long
# enough that TCP's ramp-up is a small share of what is timed, short enough
# that the check stays something nobody notices.
CONTENT_TARGET_S = 0.5
# A stream never goes below this, so a hint that came in low cannot shrink
# the next transfer into a degenerate one.
CONTENT_STREAM_FLOOR = 500_000
# And never above this, which is what bounds the hourly data budget. Only a
# fast line reaches either cap; everything slower asks for less and gets it.
CONTENT_DOWN_STREAM_CAP = 3_000_000
CONTENT_UP_STREAM_CAP = 2_000_000


def content_stream_bytes(hint_mbps, streams: int, cap: int) -> int:
    """Bytes for one stream: about CONTENT_TARGET_S of payload at the rate
    this line last showed, bounded both ways.

    A fixed size cannot serve both ends of the range it has to. Twelve MB is
    a quarter of a second on a fast line and nine seconds of a saturated link
    on a 10 Mbps one — the users least able to spare it were paying the most
    for it, hourly. Sizing by time inverts that: the cap is reached only by
    lines that can afford it, and a slow line asks for a fraction.

    With no hint — the first check on a network — the cap is what it sends,
    because there is nothing yet to size against and one honest measurement
    is what produces the hint for every check after it.
    """
    if not hint_mbps or hint_mbps <= 0:
        return cap
    per_stream_mbps = float(hint_mbps) / max(1, streams)
    want = int(per_stream_mbps / 8 * CONTENT_TARGET_S * 1e6)
    return max(CONTENT_STREAM_FLOOR, min(cap, want))


def content_test(down_hint_mbps=None, up_hint_mbps=None,
                 streams: int = 4) -> dict:
    """The scheduled check.

    Both directions are carried by `streams` parallel connections, each sized
    for a target duration rather than by dividing a fixed budget. Dividing a
    budget was how the download bug worked from one side and the upload's from
    the other: more streams meant shorter streams, and a stream too short to
    time is withheld.

    Costs up to ~20 MB on a line fast enough to reach both caps, and a
    fraction of that below — about 2 MB on a 25 Mbps line, where the old fixed
    16 MB took nine seconds of the link every hour.
    """
    started = time.time()
    per_stream = content_stream_bytes(down_hint_mbps, streams,
                                      CONTENT_DOWN_STREAM_CAP)
    up_per_stream = content_stream_bytes(up_hint_mbps, streams,
                                         CONTENT_UP_STREAM_CAP)
    down_mbps, down_n = _parallel_download(
        CLOUDFLARE_DOWN.format(n=per_stream), streams, timeout=30)
    if down_mbps is None and per_stream < CONTENT_DOWN_STREAM_CAP:
        # Sized from history, and the line turned out to be faster than that
        # history says — so fast that the streams finished inside the window
        # too short to time, and were withheld. Nothing is stored for a
        # withheld check, so the hint would never learn better and every
        # check after this one would ask for the same too-short transfer and
        # report nothing, forever. One pass at the cap re-anchors it.
        retry_mbps, retry_n = _parallel_download(
            CLOUDFLARE_DOWN.format(n=CONTENT_DOWN_STREAM_CAP), streams,
            timeout=30)
        down_mbps, down_n = retry_mbps, down_n + retry_n

    up_mbps, up_n = _parallel_upload(CLOUDFLARE_UP, up_per_stream, streams,
                                     timeout=30)
    if up_mbps is None and up_per_stream < CONTENT_UP_STREAM_CAP:
        retry_mbps, retry_n = _parallel_upload(
            CLOUDFLARE_UP, CONTENT_UP_STREAM_CAP, streams, timeout=30)
        up_mbps, up_n = retry_mbps, up_n + retry_n
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
            # Per stream, as the download pass already sizes itself: the same
            # total goes up, split four ways, so this costs no more data than
            # the single stream it replaces and stops reading one stream's
            # ceiling as the line.
            n = _sized_pass(up_est / PEAK_STREAMS, PEAK_UP_FLOOR // PEAK_STREAMS,
                            PEAK_UP_CAP // PEAK_STREAMS)
            mbps, size = _parallel_upload(CLOUDFLARE_UP, n, PEAK_STREAMS,
                                          timeout=40)
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
