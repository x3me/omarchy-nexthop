mod icmp;
mod lookup;
mod ping;
mod tcp;
mod wake;

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub use lookup::NameLookup;
pub use ping::PingProbe;
pub use tcp::TcpProbe;

pub type LoadedFn = Arc<dyn Fn() -> bool + Send + Sync>;

use crate::util::{fmean, median, py_round, py_round_int};

pub fn nearest_rank(ordered: &[f64], p: f64) -> f64 {
    let last = ordered.len() as i64 - 1;
    let i = py_round_int(p * last as f64).clamp(0, last.max(0));
    ordered[i as usize]
}

pub const RECENT_WINDOW_S: f64 = 300.0;
pub const RECENT_MIN_SAMPLES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    pub t: f64,
    pub rtt: Option<f64>,
    pub loaded: bool,
}

impl Sample {
    pub fn new(t: f64, rtt: Option<f64>, loaded: bool) -> Self {
        Self { t, rtt, loaded }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Stats {
    pub count: usize,
    pub loss: Option<f64>,
    pub p50: Option<f64>,
    pub p75: Option<f64>,
    pub p95: Option<f64>,
    pub max: Option<f64>,
    pub jitter: Option<f64>,
    pub last: Option<f64>,
}

impl Stats {
    pub fn empty() -> Self {
        Self::default()
    }
}

pub struct Series {
    pub window_s: f64,
    samples: Mutex<VecDeque<Sample>>,
}

impl Default for Series {
    fn default() -> Self {
        Self::new(1830.0)
    }
}

impl Series {
    pub fn new(window_s: f64) -> Self {
        Self { window_s, samples: Mutex::new(VecDeque::new()) }
    }

    pub fn add(&self, t: f64, rtt: Option<f64>, loaded: bool) {
        let mut samples = self.samples.lock().unwrap();
        samples.push_back(Sample::new(t, rtt, loaded));
        let cutoff = t - self.window_s;
        while samples.front().is_some_and(|s| s.t < cutoff) {
            samples.pop_front();
        }
    }

    pub fn since_at(&self, seconds: f64, at: f64) -> Vec<Sample> {
        let cutoff = at - seconds;
        self.samples.lock().unwrap().iter().filter(|s| s.t >= cutoff).copied().collect()
    }

    pub fn all(&self) -> Vec<Sample> {
        self.samples.lock().unwrap().iter().copied().collect()
    }

    pub fn split_by_load(samples: &[Sample]) -> (Vec<Sample>, Vec<Sample>) {
        samples.iter().partition(|s| !s.loaded)
    }

    pub fn stats(samples: &[Sample]) -> Stats {
        let total = samples.len();
        if total == 0 {
            return Stats::empty();
        }
        let rtts: Vec<f64> = samples.iter().filter_map(|s| s.rtt).collect();
        let loss = (total - rtts.len()) as f64 / total as f64;
        if rtts.is_empty() {
            return Stats { count: total, loss: Some(loss), ..Stats::empty() };
        }
        let mut ordered = rtts.clone();
        ordered.sort_by(f64::total_cmp);
        let deltas: Vec<f64> = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).collect();
        let last = samples.iter().rev().find_map(|s| s.rtt);
        Stats {
            count: total,
            loss: Some(loss),
            p50: Some(py_round(median(&ordered), 2)),
            p75: Some(py_round(nearest_rank(&ordered, 0.75), 2)),
            p95: Some(py_round(nearest_rank(&ordered, 0.95), 2)),
            max: Some(py_round(ordered[ordered.len() - 1], 2)),
            jitter: Some(if deltas.is_empty() { 0.0 } else { py_round(fmean(&deltas), 2) }),
            last: last.map(|v| py_round(v, 2)),
        }
    }
}

#[cfg(test)]
mod ping_tests;
#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
pub(crate) mod tests;
