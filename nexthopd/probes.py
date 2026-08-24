"""Persistent ping probes and the rolling windows they feed.

One long-lived `ping` process per target rather than one process per sample.
At two samples a second, spawning a process each time would mean 172,800
forks a day inside a laptop's idle budget; `ping -i` already does the timing
for us, and `-O` makes it say so out loud when a packet goes missing.
"""

import re
import shutil
import statistics
import subprocess
import threading
import time
from collections import deque

# [1787562260.703963] 64 bytes from 10.10.0.1: icmp_seq=1 ttl=64 time=9.13 ms
RE_REPLY = re.compile(r"^\[(\d+\.\d+)\].*icmp_seq=(\d+).*time=([\d.]+)\s*ms")
# [1787562369.690501] no answer yet for icmp_seq=1
RE_PENDING = re.compile(r"^\[(\d+\.\d+)\]\s+no answer yet for icmp_seq=(\d+)")
# [...] From 10.10.0.147 icmp_seq=1 Destination Host Unreachable
RE_UNREACH = re.compile(r"^\[(\d+\.\d+)\].*icmp_seq=(\d+).*(?:Unreachable|unreachable)")


class Series:
    """A rolling window of (timestamp, rtt_ms or None) for one target.

    None means the probe went out and nothing came back. Keeping losses in
    the same series as the replies is what lets a single pass compute both
    latency and loss over any sub-window.
    """

    def __init__(self, window_s: float = 1830.0):
        self.window_s = window_s
        self._samples = deque()
        self._lock = threading.Lock()

    def add(self, t: float, rtt):
        with self._lock:
            self._samples.append((t, rtt))
            cutoff = t - self.window_s
            while self._samples and self._samples[0][0] < cutoff:
                self._samples.popleft()

    def since(self, seconds: float):
        cutoff = time.time() - seconds
        with self._lock:
            return [s for s in self._samples if s[0] >= cutoff]

    def all(self):
        with self._lock:
            return list(self._samples)

    @staticmethod
    def stats(samples) -> dict:
        """Latency percentiles, jitter and loss over the samples given.

        Jitter is mean absolute difference between consecutive replies
        (RFC 3550's IPDV), not standard deviation: a connection that
        alternates 10/40/10/40 ms feels far worse than one that drifts
        smoothly across the same range, and only IPDV says so.
        """
        total = len(samples)
        if total == 0:
            return {"count": 0, "loss": None, "p50": None, "p75": None,
                    "p95": None, "jitter": None, "last": None, "max": None}

        rtts = [r for _, r in samples if r is not None]
        lost = total - len(rtts)
        loss = lost / total

        if not rtts:
            return {"count": total, "loss": loss, "p50": None, "p75": None,
                    "p95": None, "jitter": None, "last": None, "max": None}

        ordered = sorted(rtts)

        def pct(p):
            if len(ordered) == 1:
                return ordered[0]
            idx = min(len(ordered) - 1, max(0, int(round(p * (len(ordered) - 1)))))
            return ordered[idx]

        deltas = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
        last = next((r for _, r in reversed(samples) if r is not None), None)

        return {
            "count": total,
            "loss": loss,
            "p50": round(statistics.median(ordered), 2),
            "p75": round(pct(0.75), 2),
            "p95": round(pct(0.95), 2),
            "max": round(ordered[-1], 2),
            "jitter": round(statistics.fmean(deltas), 2) if deltas else 0.0,
            "last": round(last, 2) if last is not None else None,
        }


class PingProbe(threading.Thread):
    """Runs one `ping` forever, restarting it if it dies, feeding a Series.

    A probe never raises into the daemon: if `ping` is missing, the target
    stops resolving, or the interface goes away, the thread backs off and
    keeps trying while the series simply records losses.
    """

    daemon = True

    def __init__(self, target: str, series: Series, interval_ms: int = 500,
                 name: str = ""):
        super().__init__(name=f"probe-{name or target}", daemon=True)
        self.target = target
        self.series = series
        self.interval = max(0.2, interval_ms / 1000.0)
        self._stop = threading.Event()
        self._proc = None
        # seq -> timestamp first seen unanswered, drained by _expire()
        self._pending = {}

    def stop(self):
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    def _expire(self, now: float):
        """A packet still unanswered after the grace period is a lost packet.

        `ping -O` reports "no answer yet" as soon as it sends the next probe,
        but a slow reply can still land, so a pending seq is only counted as
        lost once it is too old to come back.
        """
        grace = self.interval * 2.5 + 1.0
        for seq, t in list(self._pending.items()):
            if now - t > grace:
                del self._pending[seq]
                self.series.add(t, None)

    def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            if not shutil.which("ping") or not self.target:
                time.sleep(min(backoff, 30.0))
                backoff = min(backoff * 2, 30.0)
                continue
            try:
                self._run_once()
                backoff = 1.0
            except Exception:
                # Never let a parse or spawn failure take the daemon with it.
                time.sleep(min(backoff, 30.0))
                backoff = min(backoff * 2, 30.0)

    def _run_once(self):
        cmd = ["ping", "-n", "-O", "-D", "-i", f"{self.interval:g}",
               "-W", "1", self.target]
        self._pending.clear()
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                self._consume(line)
            # ping exited: whatever was outstanding never arrived.
            for seq, t in self._pending.items():
                self.series.add(t, None)
            self._pending.clear()
        finally:
            proc, self._proc = self._proc, None
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    def _consume(self, line: str):
        m = RE_REPLY.match(line)
        if m:
            t, seq, rtt = float(m.group(1)), int(m.group(2)), float(m.group(3))
            self._pending.pop(seq, None)
            self.series.add(t, rtt)
            self._expire(t)
            return

        m = RE_UNREACH.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            self._pending.pop(seq, None)
            self.series.add(t, None)
            self._expire(t)
            return

        m = RE_PENDING.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            self._pending.setdefault(seq, t)
            self._expire(t)
