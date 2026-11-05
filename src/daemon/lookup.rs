use serde_json::{Value, json};
use std::sync::Arc;

use super::consts::{RESUME_SETTLE_S, STANDBY_FACTOR, TCP_PROBE_INTERVAL_S};
use super::events::{EventLog, StoreResult};
use crate::probes::NameLookup;
use crate::util::py_round_int;

pub trait OutcomeSource: Send + Sync {
    fn outcomes(&self) -> Vec<(f64, bool)>;
}

impl OutcomeSource for NameLookup {
    fn outcomes(&self) -> Vec<(f64, bool)> {
        NameLookup::outcomes(self)
    }
}

pub struct LookupWatch {
    store: Arc<dyn EventLog>,
    pub event_id: Option<i64>,
    pub since: Option<i64>,
    pub answered: bool,
    pub last_ok: Option<f64>,
    pub newest: Option<f64>,
    pub refuse_until: Option<f64>,
    run_since: Option<f64>,
    run_n: u32,
    cursor: Vec<(Arc<dyn OutcomeSource>, f64)>,
}

impl LookupWatch {
    pub const FAIL_RUN: u32 = 3;
    pub const FAIL_SPAN_S: f64 = 10.0;
    pub const STALE_S: f64 = 2.0 * TCP_PROBE_INTERVAL_S * STANDBY_FACTOR + NameLookup::DEADLINE_S;
    pub const KIND: &'static str = "dns-failing";
    pub const DETAIL: &'static str = "Name lookups failing; the internet answered by address";

    pub fn new(store: Arc<dyn EventLog>) -> Self {
        Self {
            store,
            event_id: None,
            since: None,
            answered: false,
            last_ok: None,
            newest: None,
            refuse_until: None,
            run_since: None,
            run_n: 0,
            cursor: Vec::new(),
        }
    }

    pub fn failing(&self) -> bool {
        self.since.is_some()
    }

    #[cfg(test)]
    pub fn run_n(&self) -> u32 {
        self.run_n
    }

    fn read_fresh(&mut self, lookups: &[Arc<dyn OutcomeSource>]) -> Vec<(f64, bool)> {
        let mut fresh = Vec::new();
        for lookup in lookups {
            let slot = self.cursor.iter().position(|(seen, _)| Arc::ptr_eq(seen, lookup));
            let last = slot.map(|i| self.cursor[i].1);
            let got: Vec<(f64, bool)> =
                lookup.outcomes().into_iter().filter(|o| last.is_none_or(|l| o.0 > l)).collect();
            if let Some(&(newest, _)) = got.last() {
                match slot {
                    Some(i) => self.cursor[i].1 = newest,
                    None => self.cursor.push((Arc::clone(lookup), newest)),
                }
                fresh.extend(got);
            }
        }
        fresh.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        fresh
    }

    pub fn feed(
        &mut self,
        now: f64,
        lookups: &[Arc<dyn OutcomeSource>],
        answering: bool,
        legs_down: bool,
    ) -> StoreResult<()> {
        let fresh = self.read_fresh(lookups);
        if let Some(&(last, _)) = fresh.last() {
            self.newest = Some(self.newest.unwrap_or(last).max(last));
        }
        if legs_down {
            self.close(now)?;
            self.drop_run();
            for &(ts, ok) in &fresh {
                if ok {
                    self.answered = true;
                    self.last_ok = Some(ts);
                }
            }
            return Ok(());
        }
        for &(ts, ok) in &fresh {
            if ok {
                self.answered = true;
                self.last_ok = Some(ts);
                self.refuse_until = None;
                self.drop_run();
                self.close(ts)?;
                continue;
            }
            if !self.answered || self.refuse_until.is_some_and(|r| ts < r) {
                continue;
            }
            let run_since = *self.run_since.get_or_insert(ts);
            self.run_n += 1;
            if self.since.is_none() && answering && self.run_n >= Self::FAIL_RUN && ts - run_since >= Self::FAIL_SPAN_S
            {
                let since = run_since as i64;
                self.since = Some(since);
                self.event_id = Some(self.store.open_event(since, Self::KIND, "warn", "", Self::DETAIL)?);
            }
        }
        if let Some(newest) = self.newest
            && self.since.is_some()
            && now - newest > Self::STALE_S
        {
            self.close(newest)?;
            self.drop_run();
        }
        Ok(())
    }

    pub fn lost_sight(&mut self, watched_until: f64, resumed_at: f64) -> StoreResult<()> {
        self.close(watched_until)?;
        self.drop_run();
        self.refuse_until = Some(resumed_at + RESUME_SETTLE_S);
        Ok(())
    }

    pub fn reset(&mut self, now: f64) -> StoreResult<()> {
        self.close(now)?;
        self.drop_run();
        self.answered = false;
        self.cursor.clear();
        Ok(())
    }

    pub fn snapshot(&self) -> Option<Value> {
        if self.newest.is_none() && self.since.is_none() {
            return None;
        }
        let last_ok_ts = self.last_ok.filter(|t| *t != 0.0).map(py_round_int);
        Some(json!({
            "failing": self.failing(),
            "since": self.since,
            "answered": self.answered,
            "last_ok_ts": last_ok_ts,
        }))
    }

    fn drop_run(&mut self) {
        self.run_since = None;
        self.run_n = 0;
    }

    fn close(&mut self, at: f64) -> StoreResult<()> {
        let Some(since) = self.since else {
            return Ok(());
        };
        if let Some(eid) = self.event_id.take() {
            self.store.close_event(eid, (at as i64).max(since + 1), None)?;
        }
        self.since = None;
        Ok(())
    }
}
