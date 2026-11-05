use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use serde::Serialize;

use crate::probes::{RECENT_MIN_SAMPLES, RECENT_WINDOW_S, Sample, Series, Stats};
use crate::util::{fmean, py_round};

pub const DEAD_PENALTY: f64 = 2000.0;
const SEAT_CHANGES_KEPT: usize = 32;

pub fn penalty(stats: Option<&Stats>) -> Option<f64> {
    let stats = stats?;
    if stats.count < Bench::MIN_SAMPLES {
        return None;
    }
    let loss = stats.loss.unwrap_or(0.0);
    let Some(p50) = stats.p50 else {
        return (loss > 0.0).then_some(DEAD_PENALTY * loss);
    };
    let spread = stats.p95.map_or(0.0, |p95| p95 - p50);
    Some(DEAD_PENALTY * loss + spread + 0.1 * p50)
}

pub fn host_of(target: &str) -> &str {
    if let Some((head, tail)) = target.rsplit_once(':')
        && !tail.is_empty()
        && tail.chars().all(|c| c.is_ascii_digit())
        && !head.contains(':')
    {
        return head;
    }
    target
}

#[derive(Clone, Debug)]
pub struct Instrument {
    pub key: String,
    pub kind: String,
    pub target: String,
    pub active: bool,
    pub pending_wins: u32,
    pub seat_changes: VecDeque<f64>,
    pub quarantined_until: f64,
}

impl Instrument {
    pub fn new(key: &str, kind: &str, target: &str) -> Self {
        Self {
            key: key.to_string(),
            kind: kind.to_string(),
            target: target.to_string(),
            active: false,
            pending_wins: 0,
            seat_changes: VecDeque::new(),
            quarantined_until: 0.0,
        }
    }

    pub fn flapping(&self, now: f64, window_s: f64, limit: usize) -> bool {
        self.seat_changes.iter().filter(|&&t| now - t <= window_s).count() >= limit
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BenchRow {
    pub key: String,
    pub kind: String,
    pub target: String,
    pub active: bool,
    pub quarantined: bool,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub jitter: Option<f64>,
    pub loss: Option<f64>,
    pub count: usize,
}

pub struct Bench {
    pub instruments: Vec<Instrument>,
    last_reselect: f64,
}

fn first_min_by(items: &[usize], key: impl Fn(usize) -> f64) -> usize {
    items.iter().copied().fold(items[0], |best, i| if key(i) < key(best) { i } else { best })
}

fn first_max_by(items: &[usize], key: impl Fn(usize) -> f64) -> usize {
    items.iter().copied().fold(items[0], |best, i| if key(i) > key(best) { i } else { best })
}

impl Bench {
    pub const ACTIVE_N: usize = 2;
    pub const WINDOW_S: f64 = RECENT_WINDOW_S;
    pub const RESELECT_EVERY_S: f64 = 300.0;
    pub const MIN_SAMPLES: usize = RECENT_MIN_SAMPLES;
    pub const MARGIN: f64 = 0.8;
    pub const CONSECUTIVE_WINS: u32 = 2;
    pub const FLAP_WINDOW_S: f64 = 3600.0;
    pub const FLAP_LIMIT: usize = 3;
    pub const QUARANTINE_S: f64 = 1800.0;
    pub const DEAD_AT: f64 = DEAD_PENALTY * 0.95;

    pub fn new<S: AsRef<str>>(pool: &[(S, S, S)]) -> Self {
        let mut instruments: Vec<Instrument> = Vec::new();
        for (key, kind, target) in pool {
            let (key, kind, target) = (key.as_ref(), kind.as_ref(), target.as_ref());
            match instruments.iter_mut().find(|i| i.key == key) {
                Some(existing) => *existing = Instrument::new(key, kind, target),
                None => instruments.push(Instrument::new(key, kind, target)),
            }
        }
        let mut bench = Self { instruments, last_reselect: 0.0 };
        for i in bench.opening_seats() {
            bench.instruments[i].active = true;
        }
        bench
    }

    fn opening_seats(&self) -> Vec<usize> {
        let mut seats = Vec::new();
        let mut hosts = HashSet::new();
        for (i, inst) in self.instruments.iter().enumerate() {
            if seats.len() >= Self::ACTIVE_N {
                break;
            }
            let host = host_of(&inst.target);
            if hosts.contains(host) {
                continue;
            }
            seats.push(i);
            hosts.insert(host);
        }
        for i in 0..self.instruments.len() {
            if seats.len() >= Self::ACTIVE_N {
                break;
            }
            if !seats.contains(&i) {
                seats.push(i);
            }
        }
        seats
    }

    pub fn instrument(&self, key: &str) -> Option<&Instrument> {
        self.instruments.iter().find(|i| i.key == key)
    }

    pub fn instrument_mut(&mut self, key: &str) -> Option<&mut Instrument> {
        self.instruments.iter_mut().find(|i| i.key == key)
    }

    pub fn actives(&self) -> Vec<&Instrument> {
        self.instruments.iter().filter(|i| i.active).collect()
    }

    fn active_indices(&self) -> Vec<usize> {
        (0..self.instruments.len()).filter(|&i| self.instruments[i].active).collect()
    }

    fn healthy(&self, pens: &[Option<f64>], i: usize, now: f64) -> bool {
        pens[i].is_some_and(|p| p < Self::DEAD_AT) && now >= self.instruments[i].quarantined_until
    }

    pub(crate) fn seat(&mut self, i: usize, now: f64, active: bool) -> Option<(String, bool)> {
        let inst = &mut self.instruments[i];
        if inst.active == active {
            return None;
        }
        inst.active = active;
        inst.pending_wins = 0;
        if inst.seat_changes.len() == SEAT_CHANGES_KEPT {
            inst.seat_changes.pop_front();
        }
        inst.seat_changes.push_back(now);
        if inst.flapping(now, Self::FLAP_WINDOW_S, Self::FLAP_LIMIT) {
            inst.quarantined_until = now + Self::QUARANTINE_S;
        }
        Some((inst.key.clone(), active))
    }

    fn swap(&mut self, out: usize, inn: usize, now: f64, changes: &mut Vec<(String, bool)>) {
        changes.extend(self.seat(out, now, false));
        changes.extend(self.seat(inn, now, true));
    }

    pub fn evaluate(&mut self, now: f64, stats_by_key: &HashMap<String, Stats>) -> Vec<(String, bool)> {
        let pens: Vec<Option<f64>> = self.instruments.iter().map(|i| penalty(stats_by_key.get(&i.key))).collect();
        let pen = |i: usize| pens[i].unwrap_or(f64::NAN);
        let mut changes = Vec::new();

        for inst in self.active_indices() {
            if pens[inst].is_some_and(|p| p < Self::DEAD_AT) {
                continue;
            }
            let standbys: Vec<usize> = (0..self.instruments.len())
                .filter(|&i| !self.instruments[i].active && self.healthy(&pens, i, now))
                .collect();
            if standbys.is_empty() {
                continue;
            }
            let best = first_min_by(&standbys, pen);
            self.swap(inst, best, now, &mut changes);
        }

        if now - self.last_reselect < Self::RESELECT_EVERY_S {
            return changes;
        }
        self.last_reselect = now;

        let actives: Vec<usize> = self.active_indices().into_iter().filter(|&i| pens[i].is_some()).collect();
        let challengers: Vec<usize> = (0..self.instruments.len())
            .filter(|&i| !self.instruments[i].active && self.healthy(&pens, i, now))
            .collect();
        for i in 0..self.instruments.len() {
            if !self.instruments[i].active && !challengers.contains(&i) {
                self.instruments[i].pending_wins = 0;
            }
        }
        if actives.is_empty() || challengers.is_empty() {
            return changes;
        }
        let worst = first_max_by(&actives, pen);
        let best = first_min_by(&challengers, pen);
        for &c in &challengers {
            if c != best {
                self.instruments[c].pending_wins = 0;
            }
        }
        if pen(best) < pen(worst) * Self::MARGIN {
            self.instruments[best].pending_wins += 1;
            if self.instruments[best].pending_wins >= Self::CONSECUTIVE_WINS {
                self.swap(worst, best, now, &mut changes);
            }
        } else {
            self.instruments[best].pending_wins = 0;
        }
        changes
    }

    pub fn snapshot(&self, now: f64, stats_by_key: &HashMap<String, Stats>) -> Vec<BenchRow> {
        self.instruments
            .iter()
            .map(|inst| {
                let st = stats_by_key.get(&inst.key).cloned().unwrap_or_default();
                BenchRow {
                    key: inst.key.clone(),
                    kind: inst.kind.clone(),
                    target: inst.target.clone(),
                    active: inst.active,
                    quarantined: now < inst.quarantined_until,
                    p50: st.p50,
                    p95: st.p95,
                    jitter: st.jitter,
                    loss: st.loss,
                    count: st.count,
                }
            })
            .collect()
    }
}

pub fn merged_stats(sample_lists: &[Vec<Sample>]) -> Stats {
    let lists: Vec<&Vec<Sample>> = sample_lists.iter().filter(|l| !l.is_empty()).collect();
    match lists.len() {
        0 => return Series::stats(&[]),
        1 => return Series::stats(lists[0]),
        _ => {}
    }
    let per: Vec<Stats> = lists.iter().map(|l| Series::stats(l)).collect();
    let count = per.iter().map(|p| p.count).sum();
    let loss = fmean(&per.iter().map(|p| p.loss.unwrap_or(0.0)).collect::<Vec<_>>());
    let voiced: Vec<Vec<f64>> =
        lists.iter().map(|l| l.iter().filter_map(|s| s.rtt).collect::<Vec<f64>>()).filter(|r| !r.is_empty()).collect();
    if voiced.is_empty() {
        return Stats { count, loss: Some(loss), ..Stats::empty() };
    }
    let mut pooled: Vec<(f64, f64)> = Vec::new();
    for r in &voiced {
        let w = 1.0 / r.len() as f64;
        pooled.extend(r.iter().map(|&v| (v, w)));
    }
    pooled.sort_by(|a, b| a.0.total_cmp(&b.0));
    let total_w = voiced.len() as f64;
    let top = pooled[pooled.len() - 1].0;
    let pct = |p: f64| {
        let target = p * total_w - 1e-9;
        let mut cum = 0.0;
        for &(v, w) in &pooled {
            cum += w;
            if cum >= target {
                return v;
            }
        }
        top
    };
    let jitters: Vec<f64> = per.iter().filter_map(|p| p.jitter).collect();
    let mut newest: Option<Sample> = None;
    for l in &lists {
        if let Some(smp) = l.iter().rev().find(|s| s.rtt.is_some())
            && newest.is_none_or(|n| smp.t > n.t)
        {
            newest = Some(*smp);
        }
    }
    Stats {
        count,
        loss: Some(loss),
        p50: Some(py_round(pct(0.5), 2)),
        p75: Some(py_round(pct(0.75), 2)),
        p95: Some(py_round(pct(0.95), 2)),
        max: Some(py_round(top, 2)),
        jitter: Some(if jitters.is_empty() { 0.0 } else { py_round(fmean(&jitters), 2) }),
        last: newest.and_then(|n| n.rtt).map(|v| py_round(v, 2)),
    }
}

pub type SeriesFn = Box<dyn Fn() -> Vec<Arc<Series>> + Send + Sync>;

pub struct MergedSeries {
    series_fn: SeriesFn,
}

fn by_time(mut out: Vec<Sample>) -> Vec<Sample> {
    out.sort_by(|a, b| a.t.total_cmp(&b.t));
    out
}

impl MergedSeries {
    pub fn new(series_fn: SeriesFn) -> Self {
        Self { series_fn }
    }

    pub fn each_at(&self, seconds: Option<f64>, at: f64) -> Vec<Vec<Sample>> {
        (self.series_fn)()
            .iter()
            .map(|s| match seconds {
                None => s.all(),
                Some(sec) => s.since_at(sec, at),
            })
            .collect()
    }

    pub fn stats_at(&self, seconds: f64, at: f64) -> Stats {
        merged_stats(&self.each_at(Some(seconds), at))
    }

    pub fn since_at(&self, seconds: f64, at: f64) -> Vec<Sample> {
        by_time((self.series_fn)().iter().flat_map(|s| s.since_at(seconds, at)).collect())
    }
}

#[cfg(test)]
mod tests;
