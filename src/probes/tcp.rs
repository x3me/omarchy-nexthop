use std::collections::VecDeque;
use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::lookup::NameLookup;
use super::wake::Wake;
use super::{LoadedFn, RECENT_MIN_SAMPLES, RECENT_WINDOW_S, Series};
use crate::util::{median, monotonic, now, py_round};

const MIN_INTERVAL_S: f64 = 0.25;
const RECENT_KEEP: usize = 1024;
const NO_TARGET_WAIT_S: f64 = 5.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Reply,
    Retransmit,
    Unknown,
}

pub struct TcpProbe {
    pub target: String,
    pub port: u16,
    pub lookup: Arc<NameLookup>,
    thread_name: String,
    series: Arc<Series>,
    loaded_fn: Option<LoadedFn>,
    interval: Mutex<f64>,
    wake: Wake,
    recent: Mutex<VecDeque<(f64, f64)>>,
    pub(crate) connect_timeout_s: f64,
    pub(crate) retransmit_min_samples: usize,
}

impl TcpProbe {
    pub const CONNECT_TIMEOUT_S: f64 = 2.0;
    pub const RETRANSMIT_MARGIN_MS: f64 = 900.0;
    pub const RETRANSMIT_WINDOW_S: f64 = RECENT_WINDOW_S;
    pub const RETRANSMIT_MIN_SAMPLES: usize = RECENT_MIN_SAMPLES;

    pub fn new(
        target: &str,
        series: Arc<Series>,
        interval_s: f64,
        name: &str,
        loaded_fn: Option<LoadedFn>,
        port: u16,
    ) -> Self {
        let label = if name.is_empty() { target } else { name };
        Self {
            target: target.to_string(),
            port,
            lookup: Arc::new(NameLookup::new(target, port)),
            thread_name: format!("tcp-{label}"),
            series,
            loaded_fn,
            interval: Mutex::new(interval_s.max(MIN_INTERVAL_S)),
            wake: Wake::new(),
            recent: Mutex::new(VecDeque::new()),
            connect_timeout_s: Self::CONNECT_TIMEOUT_S,
            retransmit_min_samples: Self::RETRANSMIT_MIN_SAMPLES,
        }
    }

    pub fn start(self: &Arc<Self>) -> io::Result<()> {
        let me = Arc::clone(self);
        thread::Builder::new().name(self.thread_name.clone()).spawn(move || me.run())?;
        Ok(())
    }

    pub fn stop(&self) {
        self.wake.stop();
    }

    pub fn interval(&self) -> f64 {
        *self.interval.lock().unwrap()
    }

    pub fn set_interval(&self, seconds: f64) {
        *self.interval.lock().unwrap() = seconds.max(MIN_INTERVAL_S);
    }

    fn loaded(&self) -> bool {
        self.loaded_fn.as_ref().is_some_and(|f| f())
    }

    pub(crate) fn remember(&self, t: f64, rtt: f64) {
        let mut recent = self.recent.lock().unwrap();
        if recent.len() == RECENT_KEEP {
            recent.pop_front();
        }
        recent.push_back((t, rtt));
    }

    #[cfg(test)]
    pub(crate) fn recent_len(&self) -> usize {
        self.recent.lock().unwrap().len()
    }

    pub(crate) fn once(&self) {
        let addresses = self.lookup.resolve(None);
        if addresses.is_empty() {
            return;
        }
        let started = now();
        let t0 = monotonic();
        let timeout = Duration::from_secs_f64(self.connect_timeout_s);
        let connected = addresses.into_iter().any(|mut addr| {
            addr.set_port(self.port);
            TcpStream::connect_timeout(&addr, timeout).is_ok()
        });
        if !connected {
            self.series.add(started, None, self.loaded());
            return;
        }
        let rtt = (monotonic() - t0) * 1000.0;
        match self.classify(started, rtt) {
            Verdict::Retransmit => self.series.add(started, None, self.loaded()),
            Verdict::Unknown => {
                // INFO: fc 17oct26 unclassified samples still feed the baseline, else a path slower than the floor never gets one
                self.remember(started, rtt);
            }
            Verdict::Reply => {
                self.remember(started, rtt);
                self.series.add(started, Some(py_round(rtt, 2)), self.loaded());
            }
        }
    }

    pub(crate) fn baseline_ms(&self, now: f64) -> Option<f64> {
        let cutoff = now - Self::RETRANSMIT_WINDOW_S;
        let mut recent: Vec<f64> =
            self.recent.lock().unwrap().iter().filter(|(t, _)| *t >= cutoff).map(|(_, rtt)| *rtt).collect();
        if recent.len() < self.retransmit_min_samples {
            return None;
        }
        recent.sort_by(f64::total_cmp);
        Some(median(&recent))
    }

    pub(crate) fn classify(&self, now: f64, rtt_ms: f64) -> Verdict {
        if rtt_ms < Self::RETRANSMIT_MARGIN_MS {
            return Verdict::Reply;
        }
        match self.baseline_ms(now) {
            None => Verdict::Unknown,
            Some(base) if rtt_ms >= base + Self::RETRANSMIT_MARGIN_MS => Verdict::Retransmit,
            Some(_) => Verdict::Reply,
        }
    }

    fn run(&self) {
        while !self.wake.is_stopped() {
            if self.target.is_empty() {
                self.wake.wait(NO_TARGET_WAIT_S);
                continue;
            }
            let t0 = monotonic();
            self.once();
            self.wake.wait((self.interval() - (monotonic() - t0)).max(0.0));
        }
    }
}
