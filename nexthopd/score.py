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


def lag_ms(stats: dict):
    """One number for how the connection feels, in milliseconds.

    Latency alone under-reports: a link that is 10 ms most of the time but
    swings to 90 ms and drops a packet every few seconds feels much worse
    than its median suggests. So lag leans on p75 rather than the median,
    adds the jitter the user actually perceives, and charges for loss at a
    rate that reflects a retransmit round trip.
    """
    if not stats or stats.get("count", 0) == 0:
        return None
    loss = stats.get("loss") or 0.0
    if stats.get("p75") is None:
        # Everything was lost. There is no latency to report, only a verdict.
        return None if loss < 1.0 else 1500.0
    base = stats["p75"]
    jitter = stats.get("jitter") or 0.0
    return round(base + 1.5 * jitter + loss * 1000.0, 1)


def responsiveness(lag):
    if lag is None:
        return 0.0
    return round(_interp(LAG_ANCHORS, lag), 1)


def reliability(outage_fraction: float, disruptions: int, covered: bool = True):
    """Uptime, not smoothness.

    Orb moved reliability to bite only during true outages, and that is the
    right call: a wobbly ten minutes is already punished by responsiveness,
    and double-counting it made the overall score swing on a single bad
    evening. Here an outage is total loss on the wan leg; a disruption is a
    shorter interruption that resolved on its own.
    """
    if not covered:
        return 100.0
    score = 100.0 - 100.0 * max(0.0, min(1.0, outage_fraction))
    score -= 6.0 * max(0, disruptions)
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


def index(resp, rel, spd):
    """Equal thirds, skipping any component we genuinely cannot measure.

    Scoring an unmeasured component as zero would be a lie; scoring it as
    100 would be a different lie. Leaving it out and saying so is honest,
    and it means the index is useful within seconds of starting rather than
    after the first speed test lands.
    """
    parts = [p for p in (resp, rel, spd) if p is not None]
    if not parts:
        return None
    return int(round(sum(parts) / len(parts)))


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
        if t is None:
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
