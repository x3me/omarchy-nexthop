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

Loss dominates (5 % of packets lost outweighs 100 ms of tail spread), the
tail spread comes second because Lag leans on p75, and the median is a
tiebreak — an instrument must not win its seat merely by being close.

Damping, because re-selection is where naive versions of this oscillate:
a challenger must beat the worst active instrument by 20 % on two
consecutive evaluations; an instrument whose seat changes more than three
times an hour is quarantined for thirty minutes; and a dead active
instrument is replaced immediately, hysteresis notwithstanding — waiting
two rounds to bench a corpse helps nobody.

Everything here is pure bookkeeping over injected stats. No probe, no
subprocess, no clock of its own — which is what makes it testable, and
tested.
"""

from collections import deque

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
    WINDOW_S = 300.0          # ranking window
    RESELECT_EVERY_S = 300.0  # ordinary re-ranking cadence
    MIN_SAMPLES = 8           # below this a window judges nothing
    MARGIN = 0.8              # challenger must be 20% better than the seat
    CONSECUTIVE_WINS = 2
    FLAP_WINDOW_S = 3600.0
    FLAP_LIMIT = 3
    QUARANTINE_S = 1800.0
    # An active instrument at or past this penalty is not "worse", it is
    # gone — full loss, or no samples arriving at all.
    DEAD_AT = DEAD_PENALTY * 0.95

    def __init__(self, pool):
        """pool: ordered [(key, kind, target)]; the first two start active,
        which is the pre-0.2.0 pair — continuity until the first ranking."""
        self.instruments = {}
        for i, (key, kind, target) in enumerate(pool):
            inst = Instrument(key, kind, target)
            inst.active = i < self.ACTIVE_N
            self.instruments[key] = inst
        self._last_reselect = 0.0

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
                "loss": st.get("loss"), "count": st.get("count") or 0,
            })
        return out


class MergedSeries:
    """A read-only Series view over whichever instruments hold the seats,
    so every scored consumer keeps calling .since()/.all() as if a single
    probe produced the internet leg."""

    def __init__(self, series_fn):
        self._series_fn = series_fn   # -> [Series] of the active seats

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
