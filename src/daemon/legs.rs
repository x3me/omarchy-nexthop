use super::consts::{DISRUPTION_AFTER_S, LEG_STALE_S, MIN_LOST_SAMPLES, OUTAGE_AFTER_S};
use crate::probes::Sample;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LegState {
    pub ok: bool,
    pub ts: f64,
    pub run_since: Option<f64>,
    pub lost: u32,
}

impl LegState {
    pub fn new(ok: bool, ts: f64, run_since: Option<f64>, lost: u32) -> Self {
        Self { ok, ts, run_since, lost }
    }
}

pub fn leg_state(samples: &[Sample], now: f64) -> Option<LegState> {
    let ts = samples.last()?.t;
    if now - ts > LEG_STALE_S {
        return None;
    }
    let mut lost = 0;
    let mut run_since = None;
    for smp in samples.iter().rev() {
        if smp.rtt.is_some() {
            break;
        }
        lost += 1;
        run_since = Some(smp.t);
    }
    if lost == 0 {
        return Some(LegState::new(true, ts, None, 0));
    }
    Some(LegState::new(false, ts, run_since, lost))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegMove {
    Down,
    Up,
    Disruption,
}

#[derive(Debug, Default)]
pub struct LegWatch {
    pub down_since: Option<f64>,
    pub run_since: Option<f64>,
    pub lost: u32,
    pub blip: Option<(f64, f64)>,
    pub resumed_at: Option<f64>,
    pub settle_until: Option<f64>,
}

impl LegWatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lost_sight(&mut self, resumed_at: f64, settle_s: f64) -> bool {
        let was_down = self.down_since.is_some();
        self.down_since = None;
        self.run_since = None;
        self.blip = None;
        self.lost = 0;
        self.resumed_at = Some(resumed_at);
        self.settle_until = Some(resumed_at + settle_s);
        was_down
    }

    pub fn sample(&mut self, mut state: LegState, now: f64) -> Option<LegMove> {
        if let Some(resumed_at) = self.resumed_at {
            if state.ts < resumed_at {
                return None;
            }
            let settle_until = self.settle_until.unwrap_or(resumed_at);
            if state.ok {
                self.resumed_at = None;
                self.settle_until = None;
            } else if now < settle_until {
                return None;
            } else {
                state.run_since = Some(state.run_since.map_or(settle_until, |r| r.max(settle_until)));
            }
        }
        if state.ok {
            let (began, lost) = (self.run_since.take(), std::mem::take(&mut self.lost));
            if self.down_since.take().is_some() {
                return Some(LegMove::Up);
            }
            if let Some(began) = began
                && lost >= MIN_LOST_SAMPLES
                && state.ts - began >= DISRUPTION_AFTER_S
            {
                self.blip = Some((began, state.ts));
                return Some(LegMove::Disruption);
            }
            return None;
        }
        let state_since = state.run_since.unwrap_or(state.ts);
        let run_since = match self.run_since {
            Some(r) if state_since >= r => r,
            _ => state_since,
        };
        self.run_since = Some(run_since);
        self.lost = self.lost.max(state.lost);
        if self.down_since.is_none() && self.lost >= MIN_LOST_SAMPLES && now - run_since >= OUTAGE_AFTER_S {
            self.down_since = Some(run_since);
            return Some(LegMove::Down);
        }
        None
    }
}
