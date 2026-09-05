"""Persistent ping and TCP-handshake probes, and the rolling windows they feed.

One long-lived `ping` process per target rather than one process per sample.
At two samples a second, spawning a process each time would mean 172,800
forks a day inside a laptop's idle budget; `ping -i` already does the timing
for us, and `-O` makes it say so out loud when a packet goes missing.
"""

import re
import shutil
import socket
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

    def add(self, t: float, rtt, loaded: bool = False):
        """Record one probe result, tagged with whether the link was busy.

        The tag is what makes bufferbloat visible: the same connection can
        answer in 15 ms while idle and 300 ms while a download runs, and a
        score built only on the idle number calls that line excellent right
        up until someone uses it.
        """
        with self._lock:
            self._samples.append((t, rtt, bool(loaded)))
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
    def split_by_load(samples):
        """(idle, loaded) — probes taken while the link was quiet vs busy.

        Samples are indexed rather than unpacked throughout, so a caller
        holding older two-element samples still reads as idle instead of
        raising.
        """
        idle = [s for s in samples if not (len(s) > 2 and s[2])]
        loaded = [s for s in samples if len(s) > 2 and s[2]]
        return idle, loaded

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

        rtts = [s[1] for s in samples if s[1] is not None]
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
        last = next((x[1] for x in reversed(samples) if x[1] is not None), None)

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
                 name: str = "", loaded_fn=None):
        super().__init__(name=f"probe-{name or target}", daemon=True)
        self.target = target
        self.series = series
        # Asked at the moment a sample lands, so each probe is tagged with
        # the link state it actually experienced rather than whatever the
        # link was doing when the window is later read.
        self.loaded_fn = loaded_fn
        self.interval = max(0.2, interval_ms / 1000.0)
        self._stop = threading.Event()
        self._proc = None
        # seq -> timestamp first seen unanswered, drained by _expire()
        self._pending = {}

    def _loaded(self) -> bool:
        try:
            return bool(self.loaded_fn()) if self.loaded_fn else False
        except Exception:
            return False        # a probe never raises into the daemon

    def stop(self):
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    def set_interval(self, seconds: float):
        """Change cadence in place — a benched instrument idles, a seated
        one probes at full rate, without tearing the thread down. `ping`
        takes its interval on the command line, so the running process is
        retired and the run loop respawns it with the new one."""
        seconds = max(0.2, float(seconds))
        if abs(seconds - self.interval) < 1e-9:
            return
        self.interval = seconds
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
                self.series.add(t, None, self._loaded())

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
                self.series.add(t, None, self._loaded())
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
            self.series.add(t, rtt, self._loaded())
            self._expire(t)
            return

        m = RE_UNREACH.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            self._pending.pop(seq, None)
            self.series.add(t, None, self._loaded())
            self._expire(t)
            return

        m = RE_PENDING.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            self._pending.setdefault(seq, t)
            self._expire(t)


class TcpProbe(threading.Thread):
    """Connect-time RTT to the anchor's TLS port, feeding a Series.

    ICMP measures what routers choose to answer, and they answer it fast:
    many devices handle it in hardware, in an ASIC or via XDP, while real
    traffic waits in the user-space path behind the queues that actually
    hold it up. Anything on the way can also reply on the destination's
    behalf, because there is nothing in ICMP to prove otherwise.

    A TCP handshake cannot be shortcut that way. The SYN has to reach a
    listener that completes it, over port 443 where the user's own traffic
    goes, so its round trip is the one applications experience. One
    connection per sample, opened and closed — no payload, no TLS, nothing
    kept.

    Since 0.2.0 these are seated instruments in the bench (instruments.py):
    the two best of four feed the scored internet leg, so a TCP series moves
    the score whenever it holds a seat. The anchor's ICMP figure is still
    recorded beside it per minute (`lag_icmp`) so the switch stays auditable.
    """

    daemon = True
    CONNECT_TIMEOUT_S = 2.0

    def __init__(self, target: str, series: Series, interval_s: float = 1.0,
                 name: str = "", loaded_fn=None, port: int = 443):
        super().__init__(name=f"tcp-{name or target}", daemon=True)
        self.target = target
        self.port = port
        self.series = series
        self.interval = max(0.25, interval_s)
        self.loaded_fn = loaded_fn
        self._stop = threading.Event()
        self.ever_connected = False

    def stop(self):
        self._stop.set()

    def set_interval(self, seconds: float):
        """Picked up on the next cycle; nothing to tear down here."""
        self.interval = max(0.25, float(seconds))

    def _loaded(self) -> bool:
        try:
            return bool(self.loaded_fn()) if self.loaded_fn else False
        except Exception:
            return False

    def _once(self):
        started = time.time()
        t0 = time.monotonic()
        try:
            sock = socket.create_connection((self.target, self.port),
                                            timeout=self.CONNECT_TIMEOUT_S)
        except (OSError, ValueError):
            self.series.add(started, None, self._loaded())
            return
        rtt = (time.monotonic() - t0) * 1000.0
        try:
            sock.close()
        except OSError:
            pass
        self.ever_connected = True
        self.series.add(started, round(rtt, 2), self._loaded())

    def run(self):
        while not self._stop.is_set():
            if not self.target:
                self._stop.wait(5.0)
                continue
            t0 = time.monotonic()
            try:
                self._once()
            except Exception:
                # Never let a socket or DNS failure take the daemon with it.
                pass
            self._stop.wait(max(0.0, self.interval - (time.monotonic() - t0)))
