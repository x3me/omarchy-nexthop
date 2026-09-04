"""Turning measurements into the three component scores and the index.

The shape follows Orb: Responsiveness, Reliability and Speed each score
0-100 and weigh equally, because the alternative — ranking a connection by
its download number — is exactly the habit that leaves people with a fast
line that feels broken on a video call.

Every threshold below is an anchor table rather than a formula. Anchors are
arguable in public, which is the point: someone who disagrees that 60 ms of
lag is a 78 can say so about one number instead of reverse-engineering a
curve.
"""

# Lag in ms -> Responsiveness score. Interpolated linearly between anchors.
LAG_ANCHORS = [
    (10, 100), (20, 95), (35, 88), (60, 78), (100, 68),
    (200, 50), (400, 30), (800, 10), (1500, 0),
]

# Fraction of the plan achieved -> Speed score, used only when the user has
# configured a plan. Deliberately forgiving in the middle: an ISP delivering
# 80% of a sold plan is doing fine, and a score that punished that would cry
# wolf every evening.
SPEED_ANCHORS = [
    (0.0, 0), (0.1, 15), (0.25, 35), (0.5, 60),
    (0.7, 75), (0.85, 88), (1.0, 96), (1.15, 100),
]

# The default basis: Mbps -> score, anchored to what applications need
# rather than to any plan. Speed has steep diminishing returns — 25 Mbps
# carries a 4K stream, ~100 feels instant for nearly everything, and past
# ~300 a person cannot tell the difference — so the curve saturates.
SPEED_ABS_DOWN = [
    (0, 0), (5, 25), (25, 55), (50, 70), (100, 82),
    (200, 90), (300, 94), (500, 98), (750, 100),
]
SPEED_ABS_UP = [
    (0, 0), (2, 30), (5, 55), (10, 70), (20, 82),
    (50, 92), (100, 100),
]

BANDS = [(90, "excellent"), (80, "good"), (70, "okay"), (50, "fair"), (0, "poor")]


def _interp(anchors, x):
    if x <= anchors[0][0]:
        return float(anchors[0][1])
    if x >= anchors[-1][0]:
        return float(anchors[-1][1])
    for i in range(1, len(anchors)):
        x0, y0 = anchors[i - 1]
        x1, y1 = anchors[i]
        if x <= x1:
            span = x1 - x0
            return float(y0 + (y1 - y0) * ((x - x0) / span if span else 0))
    return float(anchors[-1][1])


# What one lost packet costs, in milliseconds. It is a retransmit timeout,
# so it scales with the link's own round trip rather than being a constant:
# RTO is roughly SRTT + 4·RTTVAR, and nothing recovers faster than Linux's
# 200 ms floor. The stall factor is on top, because a drop costs more than
# the resent packet — everything behind it waits (head-of-line blocking)
# and the congestion window has to climb back.
LOSS_RTO_FLOOR_MS = 200.0
LOSS_RTT_MULTIPLIER = 3.0
LOSS_STALL_FACTOR = 5.0


def loss_cost_ms(p75_ms: float) -> float:
    """Milliseconds of felt lag per unit of loss, for a link this fast.

    Below ~67 ms p75 this returns 1000, which is exactly the flat constant
    it replaces — so ordinary connections score as they always did. Above
    it the charge grows with the round trip, which is the part the constant
    got wrong: on a 600 ms satellite link a dropped packet does not cost the
    same 10 ms per percent that it costs on fibre.
    """
    return LOSS_STALL_FACTOR * max(LOSS_RTO_FLOOR_MS,
                                   LOSS_RTT_MULTIPLIER * max(0.0, p75_ms))


def lag_ms(stats: dict):
    """One number for how the connection feels, in milliseconds.

    Latency alone under-reports: a link that is 10 ms most of the time but
    swings to 90 ms and drops a packet every few seconds feels much worse
    than its median suggests. So lag leans on p75 rather than the median,
    adds the jitter the user actually perceives, and charges for loss at a
    rate that reflects a retransmit round trip on THIS link.
    """
    if not stats or stats.get("count", 0) == 0:
        return None
    loss = stats.get("loss") or 0.0
    if stats.get("p75") is None:
        # Everything was lost. There is no latency to report, only a verdict.
        return None if loss < 1.0 else 1500.0
    base = stats["p75"]
    jitter = stats.get("jitter") or 0.0
    return round(base + 1.5 * jitter + loss * loss_cost_ms(base), 1)


def lag_band(stats: dict) -> dict:
    """Lag at three latency percentiles: best, typical, worst.

    All three go through the same fold, differing only in which percentile
    they lean on, and that is the whole point. The panel used to pair a
    loss-charged "typical" with raw millisecond figures either side of it,
    so a lossy link displayed "best 4 · typical 644 · worst 26" — three
    numbers that cannot all be true at once, because two were round trips
    and one was a composite.

    Sharing the fold makes the ordering hold by construction and makes loss
    move all three together, which is what a reader assumes a range means.
    """
    if not stats or stats.get("count", 0) == 0:
        return {"best": None, "typical": None, "worst": None}
    if stats.get("p75") is None:
        # Everything in the window was lost. `lag_ms` answers 1500 here so
        # Responsiveness lands on zero, which is its job — but 1500 is an
        # anchor, not a measurement, and the panel used to print it three
        # times as though the link were replying slowly. There is no latency
        # to display, so display none.
        return {"best": None, "typical": None, "worst": None}
    out = {}
    prev = None
    for name, key in (("best", "p50"), ("typical", "p75"), ("worst", "p95")):
        v = lag_ms(dict(stats, p75=stats.get(key)))
        # p95 can equal p75 on a short window, and a percentile can be
        # missing; neither may let the range read backwards.
        if v is not None and prev is not None:
            v = max(v, prev)
        out[name] = v
        if v is not None:
            prev = v
    return out


def responsiveness(lag):
    if lag is None:
        return 0.0
    return round(_interp(LAG_ANCHORS, lag), 1)


RELIABILITY_WINDOW_S = 24 * 3600

# A self-healed interruption is real but not as bad as being down, so its
# time is charged at a discount.
DISRUPTION_TIME_WEIGHT = 0.5
# Each interruption also costs recovery beyond its own length — a dropped
# call is redialled, a stream rebuffers, a download restarts — so every
# event carries this much equivalent disruption. Expressed in SECONDS on
# purpose: a penalty in raw points cannot be compared with downtime, which
# is exactly how the old flat "6 points per disruption" ended up charging a
# brief blip more than an hour offline.
DISRUPTION_RECOVERY_S = 300.0
# Backstop so a pathological count can never dominate the component.
DISRUPTION_MAX_PENALTY = 25.0


def reliability(outage_fraction: float, disruptions: int, covered: bool = True,
                disruption_fraction: float = 0.0,
                window_s: float = RELIABILITY_WINDOW_S):
    """Uptime, not smoothness — everything charged in one currency: time.

    Orb moved reliability to bite only during true outages, and that is the
    right call: a wobbly ten minutes is already punished by responsiveness,
    and double-counting it made the overall score swing on a single bad
    evening. Here an outage is total loss on the wan leg; a disruption is a
    shorter interruption that resolved on its own.

    Both are now charged by DURATION. They used to be charged in different
    currencies — outages by their share of the window, disruptions at a flat
    6 points each — and the units did not meet: over a 24 h window one
    ten-minute outage cost 0.7 points while three self-healed blips cost 18,
    so the milder event was punished twenty-six times harder, and seventeen
    blips zeroed the component outright. Time is the honest unit for "how
    much of today was this connection unusable", and an event's recovery
    cost is expressed in seconds so it lands on the same scale.
    """
    if not covered:
        return 100.0
    window = window_s if window_s and window_s > 0 else RELIABILITY_WINDOW_S
    down = max(0.0, min(1.0, outage_fraction))
    disrupted_s = (max(0.0, min(1.0, disruption_fraction)) * window
                   + max(0, disruptions) * DISRUPTION_RECOVERY_S)
    penalty = min(DISRUPTION_MAX_PENALTY,
                  100.0 * DISRUPTION_TIME_WEIGHT * min(1.0, disrupted_s / window))
    score = 100.0 - 100.0 * down - penalty
    return round(max(0.0, min(100.0, score)), 1)


def speed_absolute(down_mbps, up_mbps):
    """Is it fast enough — scored against what applications need.

    Download is weighted 3:1 over upload. That is not a claim that upload
    matters less in general — it is that most lines are asymmetric by
    design, so equal weighting would score every ordinary connection as
    broken.
    """
    if down_mbps is None:
        return None
    parts = [(_interp(SPEED_ABS_DOWN, down_mbps), 3.0)]
    if up_mbps is not None:
        parts.append((_interp(SPEED_ABS_UP, up_mbps), 1.0))
    weighted = sum(v * w for v, w in parts)
    return round(weighted / sum(w for _, w in parts), 1)


def degradation_penalty(down_mbps, baseline_down):
    """Is it normal for this network — a penalty for big drops only.

    The baseline is the connection's own recent p90. Sharing an office line
    means honest hour-to-hour variance, so nothing below a 40% shortfall
    counts; from there the penalty grows to 35 points at zero. This is what
    catches "we normally get 300 here and today it is 60" on a line whose
    absolute score would still look comfortable.
    """
    if down_mbps is None or not baseline_down or baseline_down <= 0:
        return 0.0
    ratio = down_mbps / baseline_down
    if ratio >= 0.6:
        return 0.0
    return round((0.6 - ratio) / 0.6 * 35.0, 1)


def speed(down_mbps, up_mbps, plan_down=0, plan_up=0, baseline_down=None):
    """The Speed component.

    With a configured plan: scored against the plan (ISP accountability —
    opt-in, because almost nobody configures a plan and shared office lines
    have no meaningful one). Without: the absolute experience curve, minus
    the degradation penalty against the connection's own baseline.
    """
    if down_mbps is None:
        return None
    if plan_down and plan_down > 0:
        ratios = [(down_mbps / plan_down, 3.0)]
        if plan_up and plan_up > 0 and up_mbps is not None:
            ratios.append((up_mbps / plan_up, 1.0))
        weighted = sum(_interp(SPEED_ANCHORS, r) * w for r, w in ratios)
        return round(weighted / sum(w for _, w in ratios), 1)
    base = speed_absolute(down_mbps, up_mbps)
    if base is None:
        return None
    return round(max(0.0, base - degradation_penalty(down_mbps, baseline_down)), 1)


# How much of the index the worst component owns. The remainder lets the
# other two nudge it up a little, so "everything else is excellent" still
# reads differently from "everything is mediocre".
INDEX_WORST_WEIGHT = 0.92


def index(resp, rel, spd):
    """Weakest-link, skipping any component we genuinely cannot measure.

    A mean let one broken dimension hide behind two good ones: a line
    scoring Responsiveness 40, Reliability 100, Speed 95 averaged to 78 and
    read as "okay" — while video calls on it did not work. That is exactly
    the habit this module exists to avoid, reintroduced at the last step.
    People experience the bottleneck, not the average, so the worst
    component sets the number and the others only nudge it.

    This also puts us where the rest of the field is: Pulse aggregates
    weakest-link (validated against a real fleet) and IETF
    draft-ietf-ippm-qoo takes a strict minimum. A mean was the outlier.

    Scoring an unmeasured component as zero would be a lie; scoring it as
    100 would be a different lie. Leaving it out and saying so is honest,
    and it means the index is useful within seconds of starting rather than
    after the first speed test lands.
    """
    parts = [p for p in (resp, rel, spd) if p is not None]
    if not parts:
        return None
    worst = min(parts)
    others = list(parts)
    others.remove(worst)          # by equality: one instance, ties keep the rest
    if not others:
        return int(round(worst))
    rest = sum(others) / len(others)
    return int(round(INDEX_WORST_WEIGHT * worst + (1.0 - INDEX_WORST_WEIGHT) * rest))


def band(score):
    if score is None:
        return "unknown"
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "poor"


def wan_from(total: dict, local: dict) -> dict:
    """The ISP leg: what is left of the round trip once the router's share is gone.

    The two probes are not synchronised, so this subtracts distributions
    rather than individual packets — p50 from p50, p75 from p75. Loss on the
    wan leg is whatever the internet probe lost beyond what the router probe
    lost, since loss on the local link shows up in both.
    """
    out = {"count": total.get("count", 0)}
    prev = 0.0
    for key in ("p50", "p75", "p95", "max"):
        t, l = total.get(key), local.get(key)
        if t is None or l is None:
            # Unknown, not zero. Substituting 0 for a local statistic we do
            # not have made the derived leg equal the whole round trip, so a
            # silent gateway produced a confident, healthy-looking internet
            # figure that was really the total wearing the wan leg's label.
            # We do not know the ISP's share without the router's, and
            # saying so beats inventing one.
            out[key] = None
            continue
        # Subtracting two independent distributions statistic-by-statistic
        # can invert the order (a wan p95 below the wan p50) when the local
        # leg's tail is fatter than the total's. Each statistic is floored
        # at the one before it so the derived leg reads like a distribution.
        v = max(prev, max(0.0, t - (l or 0.0)))
        out[key] = round(v, 2)
        prev = v
    t, l = total.get("last"), local.get("last")
    out["last"] = None if t is None else round(max(0.0, t - (l or 0.0)), 2)
    # Jitter does not subtract: variance on the local link propagates into
    # the total, so the honest reading is "no less than the total's jitter
    # minus the local's", floored at zero.
    tj, lj = total.get("jitter"), local.get("jitter")
    out["jitter"] = None if tj is None else round(max(0.0, tj - (lj or 0.0)), 2)
    tl, ll = total.get("loss"), local.get("loss")
    out["loss"] = None if tl is None else max(0.0, tl - (ll or 0.0))
    return out


# How close to the idle baseline counts as drained. A queue does not empty
# to the exact millisecond it started from, and demanding that would report
# "never recovered" on a link that plainly had.
DRAIN_TOLERANCE = 1.25
# Longest drain worth reporting. Past this the link did not recover from a
# burst, it is simply in a different state, and calling that a drain time
# would flatter it.
DRAIN_MAX_S = 30.0


def drain_after_load(samples, baseline_ms: float) -> dict:
    """How long latency took to fall back to baseline after load stopped.

    Bufferbloat is reported everywhere as a depth — how much delay a busy
    link adds. Depth alone cannot tell apart two links a user experiences
    very differently: one whose queue fills and empties the instant traffic
    stops, and one that stays full for seconds afterwards. The second ruins
    a call after the download has finished; the first does not.

    Pure, and fed the sample stream it already has: `(t, rtt, loaded)`
    tuples, where the third element is the load tag added in 0.1.11. No
    extra traffic, and nothing to schedule — the user's own usage supplies
    the burst.

    Returns `{"ms": None}` when there is nothing to say, which is most of
    the time: no burst in the window, or the link never came back inside
    `DRAIN_MAX_S`, or the baseline is unknown.
    """
    out = {"ms": None, "settled": None}
    if not samples or not baseline_ms or baseline_ms <= 0:
        return out
    # The most recent load -> idle transition, which is the only one whose
    # recovery is still visible in this window.
    last_loaded = None
    for i, sm in enumerate(samples):
        if len(sm) > 2 and sm[2]:
            last_loaded = i
    if last_loaded is None or last_loaded == len(samples) - 1:
        return out                      # no burst, or still under load
    ended_t = samples[last_loaded][0]
    target = baseline_ms * DRAIN_TOLERANCE
    for sm in samples[last_loaded + 1:]:
        if sm[1] is None:
            continue                    # a lost probe says nothing either way
        if sm[1] <= target:
            span = sm[0] - ended_t
            if span > DRAIN_MAX_S:
                return out
            out["ms"] = round(max(0.0, span) * 1000.0, 0)
            out["settled"] = True
            return out
    # Still above the baseline at the end of the window: report the floor it
    # has already exceeded rather than a number implying it recovered.
    span = samples[-1][0] - ended_t
    if 0 < span <= DRAIN_MAX_S:
        out["ms"] = round(span * 1000.0, 0)
        out["settled"] = False
    return out


# Queueing delay, in milliseconds, that separates a link carrying traffic
# comfortably from one holding packets up. Deliberately the same shape as
# the bufferbloat grades and the Latency tab's copy, and deliberately about
# the ABSOLUTE delay rather than its share of the round trip: a socket to
# another continent is mostly distance, and a proportion would call that
# congested.
PRESSURE_BUSY_MS = 10.0
PRESSURE_CONGESTED_MS = 30.0


def pressure(socket_queue_ms=None, loaded_ms=None, idle_ms=None) -> dict:
    """What the connection is doing RIGHT NOW, as opposed to lately.

    The index cannot answer this and is not meant to. It is a weakest-link
    score over three components, one of which — Speed — moves at
    content-check cadence, so when it is the weakest the index barely
    responds to anything else. Measured live: a saturating test drove
    Responsiveness down 14.6 points while the index moved from 75.0 to
    75.0, because Speed sat permanently lowest at 73.1. Both numbers were
    correct; neither answered "is it bad right now".

    So this is a separate, fast channel rather than a change to the index.
    It reports queueing delay, which is the thing a user actually feels
    during a burst, and it prefers the figure taken from their own TCP
    connections (`sockets.queue_p50`, the kernel's own timing) over our
    probes' loaded-minus-idle difference, because real traffic to real
    destinations beats an inference from two sample populations.

    Returns `state: None` when neither source can say, which is honest and
    common on an idle machine with nothing to measure.
    """
    src, q = None, None
    if socket_queue_ms is not None and socket_queue_ms >= 0:
        src, q = "sockets", float(socket_queue_ms)
    elif (loaded_ms is not None and idle_ms is not None
          and loaded_ms >= idle_ms):
        # Only when the difference points the right way; queueing cannot be
        # negative, and a negative difference means the split is unreliable
        # rather than that load helped.
        src, q = "probes", float(loaded_ms - idle_ms)
    if q is None:
        return {"state": None, "queue_ms": None, "source": None}
    if q >= PRESSURE_CONGESTED_MS:
        state = "congested"
    elif q >= PRESSURE_BUSY_MS:
        state = "busy"
    else:
        state = "clear"
    return {"state": state, "queue_ms": round(q, 1), "source": src}
