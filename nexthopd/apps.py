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
"""

import re
import shutil
import subprocess
import time
from collections import deque

# users:(("chrome",pid=4958,fd=66))  — first process owning the socket.
RE_USER = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
RE_SENT = re.compile(r"bytes_sent:(\d+)")
RE_RECV = re.compile(r"bytes_received:(\d+)")


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
            out[addr + "#" + str(pid)] = (
                app, pid,
                int(sent.group(1)) if sent else 0,
                int(recv.group(1)) if recv else 0,
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
        for key, (app, _pid, sent, recv) in cur.items():
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
            }
            for app, v in interval.items()
        ]
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
             "hist": list(self.history.get(app, []))}
            for app, t in self.totals.items() if app not in seen
        ]
        idle.sort(key=lambda a: a["rx_total"] + a["tx_total"], reverse=True)
        return (ranked + idle)[:n]
