"""Persistent ping and TCP-handshake probes, and the rolling windows they feed.

One long-lived `ping` process per target rather than one process per sample.
At two samples a second, spawning a process each time would mean 172,800
forks a day inside a laptop's idle budget; `ping -i` already does the timing
for us, and `-O` makes it say so out loud when a packet goes missing.
"""

import collections
import re
import shutil
import socket
import statistics
import subprocess
import threading
import time
from collections import deque


def nearest_rank(ordered, p: float):
    """Nearest-rank percentile of a NON-EMPTY sorted sequence.

    One implementation shared by the probe stats, the per-app socket stats
    and the speed baseline, so the three cannot drift apart — they read the
    same figure off the same rule. The index formula already collapses to
    element 0 for a single-element input, so no length special-case.
    """
    i = min(len(ordered) - 1, max(0, int(round(p * (len(ordered) - 1)))))
    return ordered[i]

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

        deltas = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
        last = next((x[1] for x in reversed(samples) if x[1] is not None), None)

        return {
            "count": total,
            "loss": loss,
            "p50": round(statistics.median(ordered), 2),
            "p75": round(nearest_rank(ordered, 0.75), 2),
            "p95": round(nearest_rank(ordered, 0.95), 2),
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
        # seq -> when it was charged as lost. A packet the grace period gave
        # up on can still be reported afterwards — the gateway's Destination
        # Host Unreachable for it arrives later than the grace, in the real
        # recording by 0.35 s — and without this it would be charged twice.
        # Held for one further grace period, which is as long as a late report
        # can be believed to belong to that packet.
        self._charged = {}

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

    def _reset_tracking(self):
        """Forget both maps together.

        `ping` numbers from 1 again on every respawn, so a seq remembered past
        the process that produced it would suppress a real loss on the next
        one — turning a guard against overcharging into an undercount, which
        is the same defect facing the other way.
        """
        self._pending.clear()
        self._charged.clear()

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
                self._charged[seq] = now
                self.series.add(t, None, self._loaded())
        # Bounded by the same clock that fills it: a seq stops being
        # remembered once no report about it could still arrive.
        for seq, t in list(self._charged.items()):
            if now - t > grace:
                del self._charged[seq]

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
        self._reset_tracking()
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
            self._reset_tracking()
        finally:
            proc, self._proc = self._proc, None
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Would not go quietly: do not leave it running.
                    try:
                        proc.kill()
                        proc.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                except OSError:
                    pass

    def _consume(self, line: str):
        m = RE_REPLY.match(line)
        if m:
            t, seq, rtt = float(m.group(1)), int(m.group(2)), float(m.group(3))
            self._pending.pop(seq, None)
            # A reply this late cannot un-lose the packet — the window it
            # belonged to has already been read — and recording the RTT as
            # well would put two samples on the wire's one packet.
            if seq not in self._charged:
                self.series.add(t, rtt, self._loaded())
            self._expire(t)
            return

        m = RE_UNREACH.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            self._pending.pop(seq, None)
            if seq not in self._charged:
                self.series.add(t, None, self._loaded())
            self._expire(t)
            return

        m = RE_PENDING.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            # `ping -O` repeats "no answer yet" for the same seq, so one that
            # has already been charged must not be put back on the pending
            # list to be charged a second time.
            if seq not in self._charged:
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

    CONNECT_TIMEOUT_S = 2.0
    # Linux and macOS both start TCP's retransmit timer at one second, so a
    # handshake that comes back at or past this did not measure a slow path:
    # its SYN was dropped and the kernel sent another. The number is the
    # kernel's constant, not the network's round trip, and folding it into a
    # latency percentile reports the line as slow when what happened is that
    # a packet was lost.
    #
    # The connect timeout was already drawing this line, in the wrong place
    # and for the wrong reason: a handshake needing TWO retransmits waits
    # 1 s + 2 s, exceeds CONNECT_TIMEOUT_S and is recorded as loss, while one
    # needing a single retransmit returns at ~1 s and was recorded as a round
    # trip. The same event, accounted two opposite ways, with the boundary
    # wherever the timeout happened to fall.
    # One initial RTO, with slop for timer granularity and scheduling. The
    # first retransmit fires at 1000 ms on Linux, macOS and Windows alike.
    RETRANSMIT_MARGIN_MS = 900.0
    # The baseline is this instrument's own recent p50, over the same window
    # and sample floor the bench ranks instruments on, so "recent" means the
    # same thing everywhere in the daemon.
    RETRANSMIT_WINDOW_S = 300.0
    RETRANSMIT_MIN_SAMPLES = 8

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
        # The recent round trips this probe has actually seen, for the
        # comparison above. Bounded, and its own — the series it feeds is
        # merged with other instruments and cannot answer "what does THIS
        # path usually do". Held as (when, rtt) so the window is a duration
        # rather than a count, which is what makes it survive a cadence
        # change: a benched instrument probes at a fraction of the rate.
        self._recent = collections.deque(maxlen=1024)
        # Samples this probe declined to call latency, so the reclassification
        # can be seen rather than inferred from a loss rate. A dropped SYN and
        # a slow line are different faults with different owners.
        self.retransmits = 0
        self.unclassified = 0

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
        # The handshake completed, so the target is reachable, whatever the
        # kernel had to do to get there.
        self.ever_connected = True
        verdict = self._classify(started, rtt)
        if verdict == "retransmit":
            # Loss on new connections, which is what it is. Recorded the same
            # way a refused or timed-out connect already is, so it charges the
            # loss term and Reliability rather than the latency percentiles.
            self.retransmits += 1
            self.series.add(started, None, self._loaded())
            return
        if verdict == "unknown":
            # Past the floor before this probe has a baseline to judge it
            # against. It is either a retransmit or a genuinely slow path and
            # nothing here can tell which, so it is not recorded as either —
            # inventing a loss and publishing a suspect latency are both
            # claims, and the honest move is to make neither.
            #
            # It still feeds the baseline, and that is not an oversight. A
            # link whose real round trip is past the floor — p50 1200 ms, say
            # — has every sample land here, so a deque that only accepted
            # classified samples would never reach its minimum, the baseline
            # would never form, and the instrument would stay unclassified
            # for ever: nothing recorded, count never growing, `penalty()`
            # returning None, and the bench able neither to seat it nor to
            # call it dead. A silent unrankable instrument, invisible because
            # it is not failing, merely absent.
            self.unclassified += 1
            self._recent.append((started, rtt))
            return
        self._recent.append((started, rtt))
        self.series.add(started, round(rtt, 2), self._loaded())

    def _baseline_ms(self, now: float):
        """This instrument's own recent p50, or None while it has too few."""
        cutoff = now - self.RETRANSMIT_WINDOW_S
        recent = [rtt for t, rtt in self._recent if t >= cutoff]
        if len(recent) < self.RETRANSMIT_MIN_SAMPLES:
            return None
        return statistics.median(recent)

    def _classify(self, now: float, rtt_ms: float) -> str:
        """"reply", "retransmit" or "unknown" for a handshake that completed.

        A connect rescued by a retransmitted SYN is a lost packet, not a slow
        path, and the threshold has to be relative or it mislabels distance as
        loss: one full RTO ABOVE what this instrument usually sees. A satellite
        link whose p50 is 600 ms gets a threshold of 1500, so a 1045 ms sample
        there stays the measurement it is.
        """
        if rtt_ms < self.RETRANSMIT_MARGIN_MS:
            return "reply"
        baseline = self._baseline_ms(now)
        if baseline is None:
            return "unknown"
        # Note what does NOT reach the baseline once one exists: a sample this
        # returns "retransmit" for. Feeding those back would raise the
        # threshold on the instrument's own retransmits and the rule would
        # quietly stop firing exactly where it is needed most.
        return "retransmit" if rtt_ms >= baseline + self.RETRANSMIT_MARGIN_MS \
            else "reply"

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
