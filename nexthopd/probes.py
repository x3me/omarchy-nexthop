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


# How much recent history judges an instrument, and the fewest samples that
# can carry a judgement at all.
#
# Shared, deliberately, by the two places that ask "what has this instrument
# been doing lately": the bench, which ranks instruments over a window, and
# TcpProbe, which needs its own recent p50 to tell a retransmit from a slow
# path. They live here rather than on the bench because `instruments` imports
# this module and not the other way round, and an alias in the direction the
# imports already run is the only one Python will take.
#
# The point of aliasing rather than repeating the number: two literals plus a
# test catches drift on the next test run, an alias makes the drift
# impossible. `test_the_window_matches_what_the_bench_ranks_on` is kept even
# though it now passes by construction — it catches someone replacing an
# alias with a literal, which is the drift it was written against.
RECENT_WINDOW_S = 300.0
RECENT_MIN_SAMPLES = 8


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


# `icmp_seq` is a 16-bit field: ping's sequence wraps to 0 after 65535.
SEQ_MOD = 65536


def seq_after(a: int, b: int) -> bool:
    """Is sequence `a` later than `b`, allowing for the wrap? Serial-number
    arithmetic (RFC 1982): later means less than half the space ahead."""
    return 0 < (a - b) % SEQ_MOD < SEQ_MOD // 2


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
        # Whether ping itself stopped running (a suspend freezes it with the
        # daemon): the timestamp of the last line and the newest sequence
        # seen, and — after such a stop — the newest sequence that was sent
        # before it, until when that can still be printed. See _before_a_stop.
        self._last_line_t = None
        self._last_seq = None
        self._stale_upto = None
        self._stale_until = None

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
        self._last_line_t = None
        self._last_seq = None
        self._stale_upto = None
        self._stale_until = None

    def _grace(self) -> float:
        return self.interval * 2.5 + 1.0

    def _before_a_stop(self, t: float, seq: int) -> bool:
        """Does this line describe a packet sent before ping stopped running?

        `ping -D` stamps a line when ping prints it, not when the packet
        arrived. A reply that reached the socket just before a laptop froze is
        printed the instant ping thaws, stamped after the wake — measured in a
        namespace: frozen with SIGSTOP while a reply was in flight, thawed four
        seconds later, and the reply printed 200 us after the thaw with the
        thaw's timestamp (its RTT is honest; its time is not). Read as a fresh
        answer it ended the post-wake settle early (#6: a 5 s gateway-quiet two
        seconds after a wake).

        `-O` makes ping print a line every interval, a reply or "no answer
        yet", so a jump between consecutive lines longer than the grace means
        ping was not running at all. Packets sent before the jump carry a
        sequence at most one past the highest printed before it (the last one
        sent is announced only when the next is). Those are neither answered
        nor lost as far as the leg is concerned: nobody was watching when they
        were, and the gap is the daemon's to account for.

        Two limits, both learned from one night (2026-09-24). The rule lives
        one grace period after the thaw and no longer: a packet sent before
        the stop is printed by then or never. And `icmp_seq` is 16 bits, so
        sequences compare modulo 65536 — at 0.5 s it wraps every 9.1 h, and a
        rule kept for ever as "seq <= N" dropped every line after the wrap,
        blanking the router leg over a working line from 02:42 until morning.
        """
        if self._last_line_t is not None and t - self._last_line_t > self._grace() \
                and self._last_seq is not None:
            self._stale_upto = (self._last_seq + 1) % SEQ_MOD
            self._stale_until = t + self._grace()
        self._last_line_t = t
        if self._last_seq is None or seq_after(seq, self._last_seq):
            self._last_seq = seq
        if self._stale_upto is None:
            return False
        if t > self._stale_until:
            self._stale_upto = self._stale_until = None
            return False
        return not seq_after(seq, self._stale_upto)

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
            if self._before_a_stop(t, seq):
                self._pending.pop(seq, None)
                return
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
            if self._before_a_stop(t, seq):
                self._pending.pop(seq, None)
                return
            self._pending.pop(seq, None)
            if seq not in self._charged:
                self.series.add(t, None, self._loaded())
            self._expire(t)
            return

        m = RE_PENDING.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            if self._before_a_stop(t, seq):
                self._pending.pop(seq, None)
                self._expire(t)
                return
            # `ping -O` repeats "no answer yet" for the same seq, so one that
            # has already been charged must not be put back on the pending
            # list to be charged a second time.
            if seq not in self._charged:
                self._pending.setdefault(seq, t)
            self._expire(t)


class NameLookup:
    """Where a named instrument's handshakes go, found apart from timing them.

    Until 0.2.47 TcpProbe handed the host name to `create_connection`, which
    looked it up inside the timed interval. Three things followed from that,
    all found on 2026-09-14 when a resolver died while every address kept
    answering (HopSense's pilot house, `docs/lookups-failing-2026-09-14.md` in
    that repo): a failed lookup was recorded as a lost packet on the path; a
    slow one was folded into the round trip, where it could pass for a
    retransmitted SYN; and nothing anywhere could say that names had stopped
    resolving, which is the one thing the user was experiencing.

    So the lookup is its own observation. Each sample collects the lookup
    the previous one started and starts the next, on a worker thread, because
    `getaddrinfo` cannot be cancelled and a resolver that has gone away can
    hold it far longer than a probe interval (glibc's default is two 5 s
    attempts). A lookup still unanswered past DEADLINE_S counts as FAILED on
    every sample it is stuck through, rather than as no reading: HopSense
    recorded nothing for those at first, so a dead resolver showed as "no
    data" for half the minutes it was dead. One lookup is ever in flight.

    The handshake does not wait for it. It goes to the last addresses that
    did resolve: the path to them has not changed because the resolver
    stopped answering, and measuring it on its own cadence is still this
    instrument's job. Waiting was tried first, and a blackholed resolver held
    the seated instrument's samples 4 s apart — with the connect timeout on
    top, past the 6 s at which a leg's stream stops being read at all. Only a
    probe with no address yet waits, since it has nothing to measure without
    one; one that never gets an answer records nothing, because a DNS failure
    is not a lost packet on the line. Probes are rebuilt on a network change,
    so an address never outlives the network it was resolved on.

    Same number of lookups as before — one per sample — so no new traffic
    and no new destination: the resolver was already being asked.
    """

    DEADLINE_S = 4.0
    # Outcomes kept for the daemon to read, newest last. At the fastest cadence
    # (one a second) this is over a minute, several times what LookupWatch
    # reads between two passes.
    KEEP = 128
    MAX_ADDRESSES = 8

    def __init__(self, host: str, port: int, resolve=None, spawn=None):
        self.host, self.port = host, port
        self._resolve = resolve or socket.getaddrinfo
        self._spawn = spawn or self._in_thread
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._result = None          # addresses list, or None for a failure
        self._finished_at = None     # wall clock when it came back
        self._started = None         # monotonic start of the lookup in flight
        self.addresses = []          # the last answer
        self.outcomes = deque(maxlen=self.KEEP)   # (wall ts, answered)
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET,
                             host)
            self.literal = True
            self.addresses = [host]
        except (OSError, ValueError):
            self.literal = False

    @staticmethod
    def _in_thread(fn):
        threading.Thread(target=fn, name="lookup", daemon=True).start()

    def _run(self):
        try:
            infos = self._resolve(self.host, self.port, type=socket.SOCK_STREAM)
            found = []
            for info in infos:
                addr = info[4][0]
                if addr not in found:
                    found.append(addr)
            result = found[:self.MAX_ADDRESSES] or None
        except Exception:
            # Anything at all. A lookup that raised past this would never
            # report, and every later sample would count as stuck.
            result = None
        with self._lock:
            # Stamped under the lock, so it can never be earlier than a
            # "still stuck" failure recorded for this same lookup.
            self._finished_at = time.time()
            self._result = result
            self._done.set()

    def resolve(self, wall: float = None) -> list:
        """The addresses to connect to for this sample.

        At most one outcome per call on a named host: the answer to the lookup
        in flight, or a failure while it is stuck past DEADLINE_S. A literal
        address records nothing — there was no lookup to fail. Answers are
        stamped when they came back and stuck lookups when found stuck (`wall`
        overrides both, for tests), so each probe's outcomes are in order.
        """
        if self.literal:
            return list(self.addresses)
        self._collect(wall)
        if self._started is None:
            self._done.clear()
            self._started = time.monotonic()
            self._spawn(self._run)
            if not self.addresses:
                self._done.wait(self.DEADLINE_S)
                self._collect(wall)
        return list(self.addresses)

    def _collect(self, wall):
        if self._started is None:
            return
        with self._lock:
            finished = self._done.is_set()
            result, finished_at = self._result, self._finished_at
            if finished:
                self._result = None
                self._done.clear()
        if finished:
            self._started = None
            if result:
                self.addresses = result
            self.outcomes.append((finished_at if wall is None else wall,
                                  bool(result)))
        elif time.monotonic() - self._started >= self.DEADLINE_S:
            self.outcomes.append((time.time() if wall is None else wall, False))


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
    # The baseline is this instrument's own recent p50 over the shared window
    # above — aliases, not copies, so "recent" cannot come to mean two things.
    RETRANSMIT_WINDOW_S = RECENT_WINDOW_S
    RETRANSMIT_MIN_SAMPLES = RECENT_MIN_SAMPLES

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
        self.lookup = NameLookup(target, port)

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
        addresses = self.lookup.resolve()
        if not addresses:
            # The name has never resolved on this network, so there is no
            # path to measure. Not a loss: nothing was sent. See NameLookup.
            return
        started = time.time()
        t0 = time.monotonic()
        # In the order create_connection tries them, with its timeout per
        # attempt — the same connect as before, minus the lookup it used to
        # time along with it.
        sock = None
        for address in addresses:
            try:
                sock = socket.create_connection((address, self.port),
                                                timeout=self.CONNECT_TIMEOUT_S)
                break
            except (OSError, ValueError):
                continue
        if sock is None:
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
