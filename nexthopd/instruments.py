"""Two best instruments for the internet leg.

One anchor is one opinion. A single probe target that rate-limits, gets
DDoSed, or sits behind a bad peering path poisons the score for everyone
behind it — and there is no way to tell "my internet is slow" from "the
anchor is having a day" with one instrument. Orb's answer, adopted here:
keep a small pool of instruments, score from the best two, re-rank them
continuously, and never let one flapping target churn the pair.

An instrument is a (protocol, target) pair. The pool mixes protocols on
purpose: TCP handshakes travel the application path, ICMP is the cheapest
edge detector — each can fail alone, and the pair means neither failing
alone moves the score. Ranking is arguable-by-design, one number at a
time, like the score anchors:

    penalty = 2000·loss + (p95 − p50) + 0.1·p50

Loss dominates (5 % of packets lost costs as much as 100 ms of tail spread), the
tail spread comes second because Lag leans on p75, and the median is a
tiebreak — an instrument must not win its seat merely by being close.

Damping, because re-selection is where naive versions of this oscillate:
a challenger must beat the worst active instrument by 20 % on two
consecutive evaluations; an instrument whose seat changes three or more
times in an hour is quarantined for thirty minutes; and a dead active
instrument is replaced immediately, hysteresis notwithstanding — waiting
two rounds to bench a corpse helps nobody.

Everything here is pure bookkeeping over injected stats. No probe, no
subprocess, no clock of its own — which is what makes it testable, and
tested.
"""

import statistics
from collections import deque

from .probes import RECENT_MIN_SAMPLES, RECENT_WINDOW_S, Series

DEAD_PENALTY = 2000.0     # loss = 1.0 and nothing else to say


def penalty(stats):
    """Rank one instrument's recent window; None = not enough to judge."""
    if not stats:
        return None
    count = stats.get("count") or 0
    if count < Bench.MIN_SAMPLES:
        return None
    loss = stats.get("loss") or 0.0
    p50, p95 = stats.get("p50"), stats.get("p95")
    if p50 is None:
        return DEAD_PENALTY * loss if loss > 0 else None
    spread = (p95 - p50) if p95 is not None else 0.0
    return DEAD_PENALTY * loss + spread + 0.1 * p50


def host_of(target: str) -> str:
    """The address part of an instrument's target.

    So that two instruments pointed at the same machine are recognisable as
    such: `1.1.1.1` and `1.1.1.1:443` are one host wearing two protocols. A
    trailing `:port` is stripped only when what remains holds no colon of its
    own, which leaves an IPv6 literal intact rather than truncating it.
    """
    head, sep, tail = target.rpartition(":")
    if sep and tail.isdigit() and ":" not in head:
        return head
    return target


class Instrument:
    def __init__(self, key: str, kind: str, target: str = ""):
        self.key = key
        self.kind = kind          # "icmp" | "tcp"
        self.target = target
        self.active = False
        self.pending_wins = 0     # consecutive evaluations won as challenger
        self.seat_changes = deque(maxlen=32)   # timestamps, for flap tracking
        self.quarantined_until = 0.0

    def flapping(self, now, window_s, limit) -> bool:
        return sum(1 for t in self.seat_changes if now - t <= window_s) >= limit


class Bench:
    """Holds the pool, decides who sits in the two scored seats."""

    ACTIVE_N = 2
    WINDOW_S = RECENT_WINDOW_S  # ranking window, shared with TcpProbe
    RESELECT_EVERY_S = 300.0  # ordinary re-ranking cadence
    MIN_SAMPLES = RECENT_MIN_SAMPLES  # below this a window judges nothing
    MARGIN = 0.8              # challenger must be 20% better than the seat
    CONSECUTIVE_WINS = 2
    FLAP_WINDOW_S = 3600.0
    FLAP_LIMIT = 3
    QUARANTINE_S = 1800.0
    # An active instrument at or past this penalty is not "worse", it is
    # gone — full loss, or no samples arriving at all.
    DEAD_AT = DEAD_PENALTY * 0.95

    def __init__(self, pool):
        """pool: ordered [(key, kind, target)].

        The opening seats span two DISTINCT hosts rather than being the first
        two in the pool. They used to be `pool[:2]` — ICMP and TCP to the
        anchor, the pre-0.2.0 pair, kept for continuity until the first
        ranking. On any network that blocks the anchor outright that put both
        scored seats on a dead host at every start: the outage watch opens at
        4 s, the notification fires at 5 s, and the bench cannot reseat until
        its next pass a minute later. A false outage and a desktop alert on
        every daemon start, and the daemon restarts on a shell restart, a
        version handover and a probe-settings change (#5).

        One working seat is enough to prevent it — the leg answers if either
        instrument does — so the rule is simply that the pair must not be one
        host twice. The bench re-ranks from there as it always did; this only
        decides what is seated before there is anything to rank.

        Not fixed by changing the default anchor: every candidate address is
        blocked on somebody's network, so that moves the report rather than
        closing it.
        """
        self.instruments = {}
        for key, kind, target in pool:
            self.instruments[key] = Instrument(key, kind, target)
        for inst in self._opening_seats():
            inst.active = True
        self._last_reselect = 0.0

    def _opening_seats(self):
        """The first instruments of the pool that do not share a host."""
        seats, hosts = [], set()
        for inst in self.instruments.values():
            if len(seats) >= self.ACTIVE_N:
                break
            host = host_of(inst.target)
            if host in hosts:
                continue
            seats.append(inst)
            hosts.add(host)
        # A pool offering fewer distinct hosts than there are seats fills the
        # rest in order: fewer scored instruments than the bench expects is a
        # worse failure than two of them sharing a host.
        if len(seats) < self.ACTIVE_N:
            for inst in self.instruments.values():
                if len(seats) >= self.ACTIVE_N:
                    break
                if inst not in seats:
                    seats.append(inst)
        return seats

    def actives(self):
        return [i for i in self.instruments.values() if i.active]

    def _healthy(self, pens, inst, now):
        p = pens.get(inst.key)
        return (p is not None and p < self.DEAD_AT
                and now >= inst.quarantined_until)

    def _seat(self, inst, now, active: bool):
        if inst.active == active:
            return None
        inst.active = active
        inst.pending_wins = 0
        inst.seat_changes.append(now)
        if inst.flapping(now, self.FLAP_WINDOW_S, self.FLAP_LIMIT):
            inst.quarantined_until = now + self.QUARANTINE_S
        return (inst.key, active)

    def evaluate(self, now, stats_by_key):
        """One pass; returns [(key, now_active)] seat changes.

        Call every minute or so: emergency replacement of a dead seat acts
        on any pass, ordinary re-ranking only every RESELECT_EVERY_S.
        """
        pens = {k: penalty(stats_by_key.get(k)) for k in self.instruments}
        changes = []

        # A dead seat is replaced now. No hysteresis for corpses — but no
        # churn during a full outage either: promotion needs a healthy
        # standby, and when everything is dead the pair stands still.
        for inst in self.actives():
            p = pens.get(inst.key)
            if p is not None and p < self.DEAD_AT:
                continue
            standbys = [i for i in self.instruments.values()
                        if not i.active and self._healthy(pens, i, now)]
            if not standbys:
                continue
            best = min(standbys, key=lambda i: pens[i.key])
            changes += filter(None, [self._seat(inst, now, False),
                                     self._seat(best, now, True)])

        if now - self._last_reselect < self.RESELECT_EVERY_S:
            return changes
        self._last_reselect = now

        # Ordinary re-ranking, damped. The worst seat defends against the
        # best healthy challenger; a challenger that stops winning starts
        # over from zero.
        actives = [i for i in self.actives() if pens.get(i.key) is not None]
        challengers = [i for i in self.instruments.values()
                       if not i.active and self._healthy(pens, i, now)]
        for inst in self.instruments.values():
            if not inst.active and inst not in challengers:
                inst.pending_wins = 0
        if not actives or not challengers:
            return changes
        worst = max(actives, key=lambda i: pens[i.key])
        best = min(challengers, key=lambda i: pens[i.key])
        for c in challengers:
            if c is not best:
                c.pending_wins = 0
        if pens[best.key] < pens[worst.key] * self.MARGIN:
            best.pending_wins += 1
            if best.pending_wins >= self.CONSECUTIVE_WINS:
                changes += filter(None, [self._seat(worst, now, False),
                                         self._seat(best, now, True)])
        else:
            best.pending_wins = 0
        return changes

    def snapshot(self, now, stats_by_key):
        """For live.json: who is in the pool, who holds a seat, and how
        each has been measuring — so the shell can show the bench."""
        out = []
        for inst in self.instruments.values():
            st = stats_by_key.get(inst.key) or {}
            out.append({
                "key": inst.key, "kind": inst.kind, "target": inst.target,
                "active": inst.active,
                "quarantined": now < inst.quarantined_until,
                "p50": st.get("p50"), "p95": st.get("p95"),
                # Per instrument, so the field can show what the merged
                # figure used to hide: jitter measured within one stream.
                "jitter": st.get("jitter"),
                "loss": st.get("loss"), "count": st.get("count") or 0,
            })
        return out


def merged_stats(sample_lists) -> dict:
    """Series.stats over several instruments, each counting once.

    Pooling the seated instruments' raw samples and calling Series.stats on
    the pile — what this replaces — got two things wrong, and both moved
    the score:

    * Jitter is RFC 3550 IPDV, the difference between consecutive replies,
      and consecutive replies in a pooled stream come from different
      instruments. Two perfectly stable instruments with different base
      round trips read as jittery: replayed at this line's own figures
      (ICMP 3.41 ms at 500 ms, TCP 4.82 ms at 1 s) the pool reported
      0.93 ms of jitter from two streams with none, and on a router that
      fast-paths ICMP (5 vs 15 ms) it reported 6.6 ms and took ten points
      off Responsiveness for nothing.
    * Every instrument was weighted by how often it happened to probe.
      ICMP follows the probeIntervalMs setting and TCP is fixed at one a
      second, so changing a setting changed p75, loss and the index while
      the network stayed the same: the 5/15 case scored 100, 92.7 or 90.3
      depending only on that number.

    Here each instrument's replies carry weight 1/n, percentiles are the
    weighted nearest rank over the pool, jitter is the mean of the
    instruments' own IPDVs, and loss is the mean of their loss rates.
    One instrument reduces to Series.stats exactly, so `lag_icmp` and the
    local leg are untouched.
    """
    lists = [lst for lst in sample_lists if lst]
    if not lists:
        return Series.stats([])
    if len(lists) == 1:
        return Series.stats(lists[0])
    per = [Series.stats(lst) for lst in lists]
    count = sum(p["count"] for p in per)
    loss = statistics.fmean(p["loss"] for p in per)
    replies = [[smp[1] for smp in lst if smp[1] is not None] for lst in lists]
    voiced = [r for r in replies if r]
    if not voiced:
        return {"count": count, "loss": loss, "p50": None, "p75": None,
                "p95": None, "jitter": None, "last": None, "max": None}
    pooled = []
    for r in voiced:
        w = 1.0 / len(r)
        pooled.extend((v, w) for v in r)
    pooled.sort(key=lambda x: x[0])
    total_w = float(len(voiced))

    def pct(p):
        target = p * total_w - 1e-9
        cum = 0.0
        for v, w in pooled:
            cum += w
            if cum >= target:
                return v
        return pooled[-1][0]

    jitters = [p["jitter"] for p in per if p["jitter"] is not None]
    newest = None
    for lst in lists:
        for smp in reversed(lst):
            if smp[1] is not None:
                if newest is None or smp[0] > newest[0]:
                    newest = smp
                break
    return {
        "count": count,
        "loss": loss,
        "p50": round(pct(0.5), 2),
        "p75": round(pct(0.75), 2),
        "p95": round(pct(0.95), 2),
        "max": round(pooled[-1][0], 2),
        "jitter": round(statistics.fmean(jitters), 2) if jitters else 0.0,
        "last": round(newest[1], 2) if newest else None,
    }


class MergedSeries:
    """A read-only view over whichever instruments hold the seats.

    `.since()` and `.all()` return the pooled stream in time order — right
    for anything that asks "did anyone reply between these two moments",
    which is what outage detection does. Anything that turns the leg into
    statistics goes through `.stats()` / `.each()` and `merged_stats`,
    where the instruments count equally; see that function for why the
    pooled stream must not be fed to Series.stats.
    """

    def __init__(self, series_fn):
        self._series_fn = series_fn   # -> [Series] of the active seats

    def each(self, seconds: float = None):
        """One sample list per seated instrument, the shape merged_stats wants."""
        if seconds is None:
            return [s.all() for s in self._series_fn()]
        return [s.since(seconds) for s in self._series_fn()]

    def stats(self, seconds: float) -> dict:
        return merged_stats(self.each(seconds))

    def since(self, seconds: float):
        out = []
        for s in self._series_fn():
            out.extend(s.since(seconds))
        out.sort(key=lambda smp: smp[0])
        return out

    def all(self):
        out = []
        for s in self._series_fn():
            out.extend(s.all())
        out.sort(key=lambda smp: smp[0])
        return out
