use super::*;

mod golden;
mod legs;
mod scoring;

pub(super) fn st(count: usize) -> Stats {
    Stats { count, ..Stats::empty() }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn full(
    count: usize,
    p50: Option<f64>,
    p75: Option<f64>,
    p95: Option<f64>,
    max: Option<f64>,
    loss: Option<f64>,
    jitter: Option<f64>,
    last: Option<f64>,
) -> Stats {
    Stats { count, loss, p50, p75, p95, max, jitter, last }
}

pub(super) fn s(t: f64, rtt: Option<f64>, loaded: bool) -> Sample {
    Sample::new(t, rtt, loaded)
}
