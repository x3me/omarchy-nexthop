use serde_json::json;
use std::sync::{Arc, Mutex};

use super::support::MemStore;
use crate::daemon::consts::RESUME_SETTLE_S;
use crate::daemon::lookup::{LookupWatch, OutcomeSource};

#[derive(Default)]
struct Lookups(Mutex<Vec<(f64, bool)>>);

impl Lookups {
    fn new() -> Arc<Self> {
        Arc::default()
    }

    fn add(&self, ts: f64, ok: bool) {
        self.0.lock().unwrap().push((ts, ok));
    }
}

impl OutcomeSource for Lookups {
    fn outcomes(&self) -> Vec<(f64, bool)> {
        self.0.lock().unwrap().clone()
    }
}

struct Fixture {
    store: Arc<MemStore>,
    w: LookupWatch,
    lk: Arc<Lookups>,
}

impl Fixture {
    fn new() -> Self {
        let store = MemStore::new();
        Self { w: LookupWatch::new(store.clone()), store, lk: Lookups::new() }
    }

    fn feed_with(&mut self, now: f64, answering: bool, legs_down: bool, lookups: &[Arc<Lookups>]) {
        let lookups: Vec<Arc<dyn OutcomeSource>> =
            lookups.iter().map(|l| l.clone() as Arc<dyn OutcomeSource>).collect();
        self.w.feed(now, &lookups, answering, legs_down).unwrap();
    }

    fn feed_as(&mut self, now: f64, answering: bool, legs_down: bool) {
        let lk = self.lk.clone();
        self.feed_with(now, answering, legs_down, &[lk]);
    }

    fn feed(&mut self, now: f64) {
        self.feed_as(now, true, false);
    }

    fn arm(&mut self, at: f64) {
        self.lk.add(at, true);
        self.feed(at);
    }

    fn fail_every_as(&mut self, start: f64, step: f64, n: u32, answering: bool) -> f64 {
        let mut t = start;
        for _ in 0..n {
            self.lk.add(t, false);
            self.feed_as(t, answering, false);
            t += step;
        }
        t - step
    }

    fn fail_every(&mut self, start: f64, step: f64, n: u32) -> f64 {
        self.fail_every_as(start, step, n, true)
    }
}

#[test]
fn three_failures_across_ten_seconds_open_it_dated_from_the_first() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.fail_every(110.0, 5.0, 2);
    assert!(!f.w.failing());
    f.fail_every(120.0, 5.0, 1);
    assert!(f.w.failing());
    assert_eq!(f.w.since, Some(110));
    assert_eq!(f.store.opened(), [("dns-failing".into(), "warn".into(), "".into(), LookupWatch::DETAIL.into())]);
}

#[test]
fn many_failures_in_a_few_seconds_are_not_yet_enough() {
    let mut f = Fixture::new();
    f.arm(100.0);
    let last = f.fail_every(110.0, 0.5, 19);
    assert!(!f.w.failing());
    f.fail_every(last + 1.0, 1.0, 1);
    assert!(f.w.failing());
}

#[test]
fn the_first_answer_closes_it_there() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.fail_every(110.0, 5.0, 3);
    f.lk.add(140.0, true);
    f.feed(140.5);
    assert!(!f.w.failing());
    assert_eq!(f.store.closed(), [1]);
}

#[test]
fn never_armed_on_a_network_where_names_never_resolved() {
    let mut f = Fixture::new();
    f.fail_every(110.0, 1.0, 60);
    assert!(!f.w.failing());
    assert!(!f.w.answered);
}

#[test]
fn an_answer_breaks_a_run() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.fail_every(110.0, 5.0, 2);
    f.lk.add(119.0, true);
    f.feed(119.0);
    f.fail_every(120.0, 5.0, 2);
    assert!(!f.w.failing());
}

#[test]
fn not_while_nothing_answers_that_is_an_outage() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.fail_every_as(110.0, 5.0, 5, false);
    assert!(!f.w.failing());
}

#[test]
fn a_confirmed_outage_drops_the_run_and_closes_an_open_one() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.fail_every(110.0, 5.0, 2);
    f.lk.add(120.0, false);
    f.feed_as(120.0, true, true);
    assert!(!f.w.failing());
    f.fail_every(130.0, 5.0, 2);
    assert!(!f.w.failing());
    f.fail_every(140.0, 5.0, 1);
    assert_eq!(f.w.since, Some(130));
    f.lk.add(150.0, false);
    f.feed_as(150.0, true, true);
    assert!(!f.w.failing());
    assert_eq!(f.store.closed(), [1]);
}

#[test]
fn refused_while_rejoining_after_a_sleep_and_closed_where_watching_stopped() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.fail_every(110.0, 5.0, 3);
    assert!(f.w.failing());
    f.w.lost_sight(121.0, 5000.0).unwrap();
    assert!(!f.w.failing());
    assert_eq!(f.store.closed().len(), 1);
    let last = f.fail_every(5001.0, 1.0, RESUME_SETTLE_S as u32 - 2);
    assert!(!f.w.failing());
    f.fail_every(last + 3.0, 5.0, 3);
    assert!(f.w.failing());
    assert!(f.w.since.unwrap() as f64 >= 5000.0 + RESUME_SETTLE_S);
}

#[test]
fn an_answer_ends_the_wake_window_early() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.w.lost_sight(121.0, 5000.0).unwrap();
    f.lk.add(5002.0, true);
    f.feed(5002.0);
    f.fail_every(5003.0, 5.0, 3);
    assert!(f.w.failing());
}

#[test]
fn closed_at_the_last_outcome_when_they_stop_arriving() {
    let mut f = Fixture::new();
    f.arm(100.0);
    let last = f.fail_every(110.0, 5.0, 3);
    f.feed(last + LookupWatch::STALE_S - 1.0);
    assert!(f.w.failing());
    f.feed(last + LookupWatch::STALE_S + 1.0);
    assert!(!f.w.failing());
    assert_eq!(f.store.closed_at(), [last as i64]);
}

#[test]
fn a_new_network_closes_it_and_disarms() {
    let mut f = Fixture::new();
    f.arm(100.0);
    f.fail_every(110.0, 5.0, 3);
    f.w.reset(130.0).unwrap();
    assert!(!f.w.failing());
    assert!(!f.w.answered);
    let fresh = Lookups::new();
    for t in [131.0, 136.0, 141.0, 146.0] {
        fresh.add(t, false);
        f.feed_with(t, true, false, std::slice::from_ref(&fresh));
    }
    assert!(!f.w.failing());
}

#[test]
fn each_outcome_is_read_once_across_two_instruments() {
    let mut f = Fixture::new();
    f.arm(100.0);
    let (a, b) = (Lookups::new(), Lookups::new());
    a.add(110.0, false);
    b.add(111.0, false);
    for _ in 0..5 {
        f.feed_with(112.0, true, false, &[a.clone(), b.clone()]);
    }
    assert_eq!(f.w.run_n(), 2);
    assert!(!f.w.failing());
    b.add(121.0, false);
    f.feed_with(121.0, true, false, &[a.clone(), b.clone()]);
    assert!(f.w.failing());
    assert_eq!(f.w.since, Some(110));
}

#[test]
fn the_snapshot() {
    let mut f = Fixture::new();
    assert_eq!(f.w.snapshot(), None);
    f.arm(100.4);
    assert_eq!(f.w.snapshot(), Some(json!({"failing": false, "since": null, "answered": true, "last_ok_ts": 100})));
    f.fail_every(110.0, 5.0, 3);
    let snap = f.w.snapshot().unwrap();
    assert_eq!(snap["since"], 110);
    assert_eq!(snap["failing"], true);
}

#[test]
fn stale_after_two_benched_samples_and_a_lookup_deadline() {
    assert_eq!(LookupWatch::STALE_S, 24.0);
}
