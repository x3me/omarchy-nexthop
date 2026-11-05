use serde::Serialize;

use crate::probes::{Sample, Stats};
use crate::util::{py_round, py_round_int};

#[cfg(test)]
mod tests;

pub const LAG_ANCHORS: &[(f64, f64)] = &[
    (10.0, 100.0),
    (20.0, 95.0),
    (35.0, 88.0),
    (60.0, 78.0),
    (100.0, 68.0),
    (200.0, 50.0),
    (400.0, 30.0),
    (800.0, 10.0),
    (1500.0, 0.0),
];

pub const SPEED_ANCHORS: &[(f64, f64)] =
    &[(0.0, 0.0), (0.1, 15.0), (0.25, 35.0), (0.5, 60.0), (0.7, 75.0), (0.85, 88.0), (1.0, 96.0), (1.15, 100.0)];

pub const SPEED_ABS_DOWN: &[(f64, f64)] = &[
    (0.0, 0.0),
    (5.0, 25.0),
    (25.0, 55.0),
    (50.0, 70.0),
    (100.0, 82.0),
    (200.0, 90.0),
    (300.0, 94.0),
    (500.0, 98.0),
    (750.0, 100.0),
];

pub const SPEED_ABS_UP: &[(f64, f64)] =
    &[(0.0, 0.0), (2.0, 30.0), (5.0, 55.0), (10.0, 70.0), (20.0, 82.0), (50.0, 92.0), (100.0, 100.0)];

pub const BANDS: &[(i64, &str)] = &[(90, "excellent"), (80, "good"), (70, "okay"), (50, "fair"), (0, "poor")];

fn interp(anchors: &[(f64, f64)], x: f64) -> f64 {
    let (first, last) = (anchors[0], anchors[anchors.len() - 1]);
    if x <= first.0 {
        return first.1;
    }
    if x >= last.0 {
        return last.1;
    }
    for pair in anchors.windows(2) {
        let ((x0, y0), (x1, y1)) = (pair[0], pair[1]);
        if x <= x1 {
            let span = x1 - x0;
            return y0 + (y1 - y0) * if span != 0.0 { (x - x0) / span } else { 0.0 };
        }
    }
    last.1
}

pub const LOSS_RTO_FLOOR_MS: f64 = 200.0;
pub const LOSS_RTT_MULTIPLIER: f64 = 3.0;
pub const LOSS_STALL_FACTOR: f64 = 5.0;

pub fn loss_cost_ms(p75_ms: f64) -> f64 {
    LOSS_STALL_FACTOR * LOSS_RTO_FLOOR_MS.max(LOSS_RTT_MULTIPLIER * p75_ms.max(0.0))
}

pub fn lag_ms(stats: &Stats) -> Option<f64> {
    if stats.count == 0 {
        return None;
    }
    let loss = stats.loss.unwrap_or(0.0);
    let Some(base) = stats.p75 else {
        return if loss < 1.0 { None } else { Some(1500.0) };
    };
    let jitter = stats.jitter.unwrap_or(0.0);
    Some(py_round(base + 1.5 * jitter + loss * loss_cost_ms(base), 1))
}

pub fn measured_lag(stats: &Stats) -> Option<f64> {
    stats.p75?;
    lag_ms(stats)
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LagBand {
    pub best: Option<f64>,
    pub typical: Option<f64>,
    pub worst: Option<f64>,
}

pub fn lag_band(stats: &Stats) -> LagBand {
    let mut prev: Option<f64> = None;
    let mut fold = |percentile: Option<f64>| {
        let mut v = measured_lag(&Stats { p75: percentile, ..stats.clone() });
        if let (Some(x), Some(p)) = (v, prev) {
            v = Some(x.max(p));
        }
        if v.is_some() {
            prev = v;
        }
        v
    };
    let best = fold(stats.p50);
    let typical = fold(stats.p75);
    let worst = fold(stats.p95);
    LagBand { best, typical, worst }
}

pub fn responsiveness(lag: Option<f64>) -> f64 {
    match lag {
        None => 0.0,
        Some(lag) => py_round(interp(LAG_ANCHORS, lag), 1),
    }
}

// INFO: fc 17oct26 integer on purpose: live.json publishes reliability_ctx.window_s as 86400, not 86400.0
pub const RELIABILITY_WINDOW_S: i64 = 24 * 3600;
pub const RELIABILITY_MIN_WATCHED_S: f64 = 3600.0;
pub const DISRUPTION_TIME_WEIGHT: f64 = 0.5;
pub const DISRUPTION_RECOVERY_S: f64 = 300.0;
pub const DISRUPTION_MAX_PENALTY: f64 = 25.0;

pub fn reliability(outage_fraction: f64, disruptions: i64, disruption_fraction: f64, window_s: f64) -> Option<f64> {
    let window = window_s;
    if window < RELIABILITY_MIN_WATCHED_S {
        return None;
    }
    let down = outage_fraction.clamp(0.0, 1.0);
    let disrupted_s = disruption_fraction.clamp(0.0, 1.0) * window + disruptions.max(0) as f64 * DISRUPTION_RECOVERY_S;
    let penalty = DISRUPTION_MAX_PENALTY.min(100.0 * DISRUPTION_TIME_WEIGHT * (disrupted_s / window).min(1.0));
    let score = 100.0 - 100.0 * down - penalty;
    Some(py_round(score.clamp(0.0, 100.0), 1))
}

fn weighted_mean(parts: &[(f64, f64)]) -> f64 {
    let weighted: f64 = parts.iter().map(|(v, w)| v * w).sum();
    weighted / parts.iter().map(|(_, w)| w).sum::<f64>()
}

pub fn speed_absolute(down_mbps: Option<f64>, up_mbps: Option<f64>) -> Option<f64> {
    let down = down_mbps?;
    let mut parts = vec![(interp(SPEED_ABS_DOWN, down), 3.0)];
    if let Some(up) = up_mbps {
        parts.push((interp(SPEED_ABS_UP, up), 1.0));
    }
    Some(py_round(weighted_mean(&parts), 1))
}

pub const MIN_SPEED_SAMPLES: usize = 2;
pub const PEAK_CONTRADICTION_RATIO: f64 = 2.0;

pub fn speed_scored(down_mbps: Option<f64>, samples: usize, peak_down: Option<f64>) -> bool {
    let Some(down) = down_mbps else {
        return false;
    };
    if samples < MIN_SPEED_SAMPLES {
        return false;
    }
    !peak_down.is_some_and(|peak| peak != 0.0 && peak >= down * PEAK_CONTRADICTION_RATIO)
}

pub fn degradation_penalty(down_mbps: Option<f64>, baseline_down: Option<f64>) -> f64 {
    let (Some(down), Some(baseline)) = (down_mbps, baseline_down) else {
        return 0.0;
    };
    if baseline <= 0.0 {
        return 0.0;
    }
    let ratio = down / baseline;
    if ratio >= 0.6 {
        return 0.0;
    }
    py_round((0.6 - ratio) / 0.6 * 35.0, 1)
}

pub fn speed(
    down_mbps: Option<f64>,
    up_mbps: Option<f64>,
    plan_down: f64,
    plan_up: f64,
    baseline_down: Option<f64>,
) -> Option<f64> {
    let down = down_mbps?;
    if plan_down > 0.0 {
        let mut ratios = vec![(interp(SPEED_ANCHORS, down / plan_down), 3.0)];
        if let Some(up) = up_mbps.filter(|_| plan_up > 0.0) {
            ratios.push((interp(SPEED_ANCHORS, up / plan_up), 1.0));
        }
        return Some(py_round(weighted_mean(&ratios), 1));
    }
    let base = speed_absolute(down_mbps, up_mbps)?;
    Some(py_round((base - degradation_penalty(down_mbps, baseline_down)).max(0.0), 1))
}

pub const INDEX_WORST_WEIGHT: f64 = 0.92;

pub fn index(resp: Option<f64>, rel: Option<f64>, spd: Option<f64>) -> Option<i64> {
    let mut parts: Vec<f64> = [resp, rel, spd].into_iter().flatten().collect();
    let (at, worst) = parts.iter().copied().enumerate().min_by(|a, b| a.1.total_cmp(&b.1))?;
    parts.remove(at);
    if parts.is_empty() {
        return Some(py_round_int(worst));
    }
    let rest = parts.iter().sum::<f64>() / parts.len() as f64;
    Some(py_round_int(INDEX_WORST_WEIGHT * worst + (1.0 - INDEX_WORST_WEIGHT) * rest))
}

pub const OUTAGE_STATES: &[&str] = &["local-down", "wan-down", "tunnel-down"];

pub fn scored_now(state: &str) -> bool {
    !OUTAGE_STATES.contains(&state)
}

pub fn band(score: Option<i64>) -> &'static str {
    let Some(score) = score else {
        return "unknown";
    };
    BANDS.iter().find(|(floor, _)| score >= *floor).map_or("poor", |(_, name)| name)
}

pub const WAN_INVERSION_TOLERANCE_MS: f64 = 1.0;

pub fn wan_point_ms(total_ms: Option<f64>, local_ms: Option<f64>) -> Option<f64> {
    let (total, local) = (total_ms?, local_ms?);
    if local > total + WAN_INVERSION_TOLERANCE_MS {
        return None;
    }
    Some(py_round((total - local).max(0.0), 2))
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct WanStats {
    pub count: usize,
    pub p50: Option<f64>,
    pub p75: Option<f64>,
    pub p95: Option<f64>,
    pub max: Option<f64>,
    pub last: Option<f64>,
    pub jitter: Option<f64>,
    pub loss: Option<f64>,
}

pub fn wan_from(total: &Stats, local: &Stats) -> WanStats {
    let mut prev = 0.0_f64;
    let mut floored = |t: Option<f64>, l: Option<f64>| {
        let v = prev.max(wan_point_ms(t, l)?);
        prev = v;
        Some(py_round(v, 2))
    };
    let p50 = floored(total.p50, local.p50);
    let p75 = floored(total.p75, local.p75);
    let p95 = floored(total.p95, local.p95);
    let max = floored(total.max, local.max);
    let heard = local.last.is_some();
    let last = match (total.last, local.last) {
        (Some(t), Some(l)) if l <= t + WAN_INVERSION_TOLERANCE_MS => Some(py_round((t - l).max(0.0), 2)),
        _ => None,
    };
    let jitter = match (total.jitter, local.jitter) {
        (Some(tj), Some(lj)) if heard => Some(py_round((tj - lj).max(0.0), 2)),
        _ => None,
    };
    let loss = match (total.loss, local.loss) {
        (Some(tl), Some(ll)) if heard => Some((tl - ll).max(0.0)),
        _ => None,
    };
    WanStats { count: total.count, p50, p75, p95, max, last, jitter, loss }
}

pub const DRAIN_TOLERANCE: f64 = 1.25;
pub const DRAIN_MAX_S: f64 = 30.0;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Drain {
    pub ms: Option<f64>,
    pub settled: Option<bool>,
}

pub fn drain_after_load(samples: &[Sample], baseline_ms: Option<f64>) -> Drain {
    let mut out = Drain::default();
    let Some(baseline) = baseline_ms.filter(|b| *b > 0.0) else {
        return out;
    };
    let Some(last_loaded) = samples.iter().rposition(|s| s.loaded) else {
        return out;
    };
    if last_loaded == samples.len() - 1 {
        return out;
    }
    let ended_t = samples[last_loaded].t;
    let target = baseline * DRAIN_TOLERANCE;
    for sm in &samples[last_loaded + 1..] {
        let Some(rtt) = sm.rtt else {
            continue;
        };
        if rtt <= target {
            let span = sm.t - ended_t;
            if span > DRAIN_MAX_S {
                return out;
            }
            out.ms = Some(py_round(span.max(0.0) * 1000.0, 0));
            out.settled = Some(true);
            return out;
        }
    }
    let span = samples[samples.len() - 1].t - ended_t;
    if 0.0 < span && span <= DRAIN_MAX_S {
        out.ms = Some(py_round(span * 1000.0, 0));
        out.settled = Some(false);
    }
    out
}

pub const PRESSURE_BUSY_MS: f64 = 10.0;
pub const PRESSURE_CONGESTED_MS: f64 = 30.0;
pub const TUNNEL_SPREAD_FACTOR: f64 = 2.0;
pub const TUNNEL_BASELINE_MIN_MINUTES: usize = 30;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TunnelBands {
    pub baseline_ms: f64,
    pub spread_ms: f64,
    pub amber_ms: f64,
    pub red_ms: f64,
    pub minutes: usize,
}

pub fn tunnel_bands(baseline_ms: Option<f64>, p90_ms: Option<f64>, minutes: usize) -> Option<TunnelBands> {
    let (baseline, p90) = (baseline_ms?, p90_ms?);
    if minutes < TUNNEL_BASELINE_MIN_MINUTES {
        return None;
    }
    let spread = (p90 - baseline).max(0.0);
    let margin = TUNNEL_SPREAD_FACTOR * spread;
    Some(TunnelBands {
        baseline_ms: py_round(baseline, 1),
        spread_ms: py_round(spread, 1),
        amber_ms: py_round(baseline + PRESSURE_BUSY_MS + margin, 1),
        red_ms: py_round(baseline + PRESSURE_CONGESTED_MS + margin, 1),
        minutes,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Pressure {
    pub state: Option<&'static str>,
    pub queue_ms: Option<f64>,
    pub source: Option<&'static str>,
}

pub fn pressure(socket_queue_ms: Option<f64>, loaded_ms: Option<f64>, idle_ms: Option<f64>) -> Pressure {
    let (source, queue) = match (socket_queue_ms, loaded_ms, idle_ms) {
        (Some(s), _, _) if s >= 0.0 => ("sockets", s),
        (_, Some(loaded), Some(idle)) if loaded >= idle => ("probes", loaded - idle),
        _ => return Pressure::default(),
    };
    let state = if queue >= PRESSURE_CONGESTED_MS {
        "congested"
    } else if queue >= PRESSURE_BUSY_MS {
        "busy"
    } else {
        "clear"
    };
    Pressure { state: Some(state), queue_ms: Some(py_round(queue, 1)), source: Some(source) }
}
