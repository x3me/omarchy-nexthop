"""Per-application traffic, without root.

Linux only hands per-process byte counts to privileged tooling (pcap, eBPF)
— that is why nethogs needs root. The unprivileged truth available is
`ss -tinp`: every TCP socket's bytes_sent / bytes_received with the owning
process. Sampled on an interval, socket deltas aggregate into honest
per-app rates and running totals.

What this cannot see: UDP — and with it QUIC, which is how Chrome talks to
much of Google. That traffic surfaces as the gap between the interface
counters and the TCP sum, shown as its own "unattributed" bucket rather
than silently missing.

The same `ss` line also carries what the kernel already knows about each
connection's timing: `rtt:<srtt>/<rttvar>` (its smoothed round trip),
`minrtt` (the lowest it has ever seen on that path) and `bytes_retrans`.
That is a latency measurement of the user's own traffic, to the hosts they
actually talk to, costing no probe and no privilege — so we read it rather
than throw it away.

`minrtt` is the path's structural floor: distance, switching, serialisation.
`srtt - minrtt` is therefore queueing delay with distance divided out, and
every connection is its own control — which is what makes a 300 ms socket to
another continent comparable with a 5 ms socket next door. A raw `srtt` is
never a verdict on its own; only the difference travels.
"""

import re
import shutil
import statistics
import subprocess
import time
from collections import deque
from typing import NamedTuple

from .probes import nearest_rank

# users:(("chrome",pid=4958,fd=66))  — first process owning the socket.
RE_USER = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
RE_SENT = re.compile(r"bytes_sent:(\d+)")
RE_RECV = re.compile(r"bytes_received:(\d+)")
# rtt:<srtt>/<rttvar> — both milliseconds. minrtt is printed separately.
RE_RTT = re.compile(r"\brtt:([\d.]+)/([\d.]+)")
RE_MINRTT = re.compile(r"\bminrtt:([\d.]+)")
RE_RETRANS = re.compile(r"\bbytes_retrans:(\d+)")


class Sock(NamedTuple):
    """One socket's sample. Indexable, so older positional callers still work."""
    app: str
    pid: int
    sent: int
    recv: int
    srtt: float = None      # kernel smoothed RTT, ms
    minrtt: float = None    # lowest RTT seen on this path, ms
    retrans: int = 0        # bytes retransmitted by the kernel


# A connection has to have carried something before its floor is worth
# trusting: `minrtt` is a minimum over the connection's life, so a socket
# that has only ever been busy may never have seen a quiet moment. Note the
# error direction — a floor biased high UNDER-states queueing, so this
# threshold is about honesty, not safety. Argue with the number, not the rule.
MIN_LATENCY_BYTES = 4096
# A plausibility ceiling, distinct from a sample-count floor: past this, the
# number describes a broken measurement rather than a slow link, and a
# measurement we cannot believe is worth less than no measurement.
MAX_PLAUSIBLE_RTT_MS = 10_000.0
# `ss` prints three decimals, so allow rounding before calling an inverted
# pair (floor above the average, which cannot happen) a stale field.
RTT_INVERSION_TOLERANCE_MS = 0.05
# Below this many qualifying sockets we publish nothing rather than a
# distribution drawn from a handful of connections.
MIN_LATENCY_SOCKETS = 3


def socket_timing(s) -> tuple:
    """(srtt, floor, queue) for one socket, or None if it does not qualify.

    One guard, used by both the aggregate and the per-app medians, so a
    socket rejected in one place cannot be silently counted in the other.
    """
    if s.srtt is None or s.minrtt is None:
        return None                       # kernel has no timing for it yet
    if s.sent + s.recv < MIN_LATENCY_BYTES:
        return None                       # too little traffic to trust the floor
    if s.srtt <= 0 or s.minrtt <= 0:
        return None
    if s.srtt > MAX_PLAUSIBLE_RTT_MS or s.minrtt > MAX_PLAUSIBLE_RTT_MS:
        return None                       # implausible: a broken measurement
    if s.minrtt > s.srtt + RTT_INVERSION_TOLERANCE_MS:
        return None                       # floor above the average: stale field
    return (s.srtt, s.minrtt, max(0.0, s.srtt - s.minrtt))


def latency_stats(socks: dict) -> dict:
    """What the user's own TCP connections are experiencing, or None.

    Pure and injected so it can be tested without a live socket table.
    Returns None when too few connections qualify — an honest blank beats a
    distribution invented from three sockets.
    """
    srtts, floors, queues, retrans_socks, rejected = [], [], [], 0, 0
    for s in socks.values():
        if s.srtt is None or s.minrtt is None:
            continue        # not a rejection: the kernel simply has no timing
        t = socket_timing(s)
        if t is None:
            rejected += 1
            continue
        srtts.append(t[0])
        floors.append(t[1])
        queues.append(t[2])
        if s.retrans:
            retrans_socks += 1
    if len(srtts) < MIN_LATENCY_SOCKETS:
        return None
    srtts.sort(); floors.sort(); queues.sort()
    return {
        "sockets": len(srtts),
        "rejected": rejected,
        # What the applications see, end to end, including distance.
        "rtt_p50": round(statistics.median(srtts), 2),
        "rtt_p95": round(nearest_rank(srtts, 0.95), 2),
        # The structural floor of the paths in use.
        "floor_p50": round(statistics.median(floors), 2),
        # Queueing, with distance divided out. This is the number that
        # compares across connections.
        "queue_p50": round(statistics.median(queues), 2),
        "queue_p95": round(nearest_rank(queues, 0.95), 2),
        "retrans_sockets": retrans_socks,
    }


def parse_ss(raw: str, max_sockets: int = 10_000) -> dict:
    """{socket_key: (app, pid, sent, received)} from `ss -tinpH` output.

    Sockets are keyed by local/peer address pair plus pid, which survives
    across samples for the life of the connection. Sockets without process
    attribution (other users' processes) are skipped, and parsing stops at
    max_sockets so a pathological table cannot expand retained state.
    """
    out = {}
    addr = None
    app = None
    pid = None
    for line in raw.splitlines():
        if not line.startswith(("\t", " ")):
            # Header line: state, queues, local, peer, users.
            parts = line.split()
            addr = None
            app = None
            m = RE_USER.search(line)
            if m and len(parts) >= 5:
                addr = parts[3] + ">" + parts[4]
                app = m.group(1)
                pid = int(m.group(2))
            continue
        if addr is None:
            continue
        sent = RE_SENT.search(line)
        recv = RE_RECV.search(line)
        if sent or recv:
            if len(out) >= max_sockets:
                break
            # The kernel's own timing, off the same line. Absent on a socket
            # it has not measured yet, which is why these stay None rather
            # than defaulting to zero.
            rtt = RE_RTT.search(line)
            minrtt = RE_MINRTT.search(line)
            retrans = RE_RETRANS.search(line)
            out[addr + "#" + str(pid)] = Sock(
                app, pid,
                int(sent.group(1)) if sent else 0,
                int(recv.group(1)) if recv else 0,
                float(rtt.group(1)) if rtt else None,
                float(minrtt.group(1)) if minrtt else None,
                int(retrans.group(1)) if retrans else 0,
            )
            addr = None
    return out


class AppTraffic:
    """Aggregates socket samples into per-app rates and session totals."""

    # How many poll intervals of history each app keeps. At the 3-second
    # poll that is one minute — enough to show the shape of usage, small
    # enough to ride along in apps.json.
    HISTORY = 20

    def __init__(self):
        self.prev = {}
        self.prev_t = None
        self.totals = {}     # app -> [rx_bytes, tx_bytes]
        self.rates = []      # last interval's list, ready for apps.json
        self.history = {}    # app -> deque of [rx_bps, tx_bps]
        self.latency = None  # last latency_stats(), or None while under-sampled

    # Enumeration bounds: a machine with an enormous socket table must not
    # make the daemon allocate without limit every three seconds. 4 MB of
    # `ss` output is roughly 8000 sockets — far past any laptop, and the
    # cap degrades to "top apps among the first N sockets", not a crash.
    MAX_SS_BYTES = 4 * 1024 * 1024
    MAX_SOCKETS = 10_000

    def poll(self) -> bool:
        if not shutil.which("ss"):
            return False
        try:
            proc = subprocess.Popen(["ss", "-tinpH"], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
        except OSError:
            return False
        try:
            raw = proc.stdout.read(self.MAX_SS_BYTES)
            if proc.stdout.read(1):
                # More than the cap: stop reading and reap the process —
                # the sample stays bounded and simply under-counts.
                proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
            return False
        now = time.time()
        cur = parse_ss(raw, max_sockets=self.MAX_SOCKETS)
        self._fold(cur, now)
        return True

    def _fold(self, cur: dict, now: float):
        if self.prev_t is None:
            # First sample is the baseline: the counters carry each
            # connection's whole history, which is not this interval's
            # traffic.
            self.prev, self.prev_t = cur, now
            return
        dt = max(0.5, now - self.prev_t)
        interval = {}   # app -> [rx, tx, conns]
        per_app_rtt = {}    # app -> list of srtt
        per_app_queue = {}  # app -> list of srtt - minrtt
        for key, s in cur.items():
            app, sent, recv = s.app, s.sent, s.recv
            prev = self.prev.get(key)
            if prev is not None:
                d_tx = max(0, sent - prev[2])
                d_rx = max(0, recv - prev[3])
            else:
                # Born since the last sample: its whole life is this
                # interval.
                d_tx, d_rx = sent, recv
            slot = interval.setdefault(app, [0, 0, 0])
            slot[0] += d_rx
            slot[1] += d_tx
            slot[2] += 1
            # Per-app timing shares the aggregate's guard, so a socket
            # rejected there cannot be silently counted here.
            t = socket_timing(s)
            if t is not None:
                per_app_rtt.setdefault(app, []).append(t[0])
                per_app_queue.setdefault(app, []).append(t[2])
        # Sockets that closed between samples take their final delta with
        # them — the tail of a closed connection is the one thing this
        # method genuinely cannot count.
        for app, (rx, tx, _conns) in interval.items():
            tot = self.totals.setdefault(app, [0, 0])
            tot[0] += rx
            tot[1] += tx
        # Every known app gets a history sample each interval — an app that
        # went quiet records zeros, so its strip shows the quiet.
        for app in self.totals:
            v = interval.get(app)
            h = self.history.setdefault(app, deque(maxlen=self.HISTORY))
            h.append([round(v[0] / dt, 1), round(v[1] / dt, 1)] if v else [0.0, 0.0])
        self.rates = [
            {
                "name": app,
                "rx_bps": round(v[0] / dt, 1),
                "tx_bps": round(v[1] / dt, 1),
                "conns": v[2],
                "rx_total": self.totals.get(app, [0, 0])[0],
                "tx_total": self.totals.get(app, [0, 0])[1],
                "hist": list(self.history.get(app, [])),
                # Median across this app's qualifying sockets. None when it
                # has none — an app talking only QUIC shows no latency here,
                # which is honest rather than zero.
                "rtt_ms": (round(statistics.median(per_app_rtt[app]), 2)
                           if per_app_rtt.get(app) else None),
                "queue_ms": (round(statistics.median(per_app_queue[app]), 2)
                             if per_app_queue.get(app) else None),
            }
            for app, v in interval.items()
        ]
        self.latency = latency_stats(cur)
        self.prev, self.prev_t = cur, now

    def top(self, n: int = 8) -> list:
        """Busiest apps first; idle-but-heavy session users still listed."""
        ranked = sorted(self.rates,
                        key=lambda a: (a["rx_bps"] + a["tx_bps"],
                                       a["rx_total"] + a["tx_total"]),
                        reverse=True)
        seen = {a["name"] for a in ranked}
        # Apps with session history but no sockets this interval.
        idle = [
            {"name": app, "rx_bps": 0.0, "tx_bps": 0.0, "conns": 0,
             "rx_total": t[0], "tx_total": t[1],
             "hist": list(self.history.get(app, [])),
             "rtt_ms": None, "queue_ms": None}
            for app, t in self.totals.items() if app not in seen
        ]
        idle.sort(key=lambda a: a["rx_total"] + a["tx_total"], reverse=True)
        return (ranked + idle)[:n]
