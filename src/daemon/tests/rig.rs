use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

use crate::daemon::collector::Snapshot;
use crate::daemon::core::{Daemon, Hooks};
use crate::probes::Series;
use crate::speedtest::ContentResult;
use crate::store::{Store, TestRow};
use crate::testutil::{TempDir, obj};

pub type Clock = Arc<Mutex<f64>>;
pub fn int(row: &Map<String, Value>, key: &str) -> Option<i64> {
    row.get(key).and_then(Value::as_i64)
}

pub fn ctx_f(ctx: &Map<String, Value>, key: &str) -> Option<f64> {
    ctx.get(key).and_then(Value::as_f64)
}

pub type Notices = Arc<Mutex<Vec<(String, String, bool)>>>;

pub fn failed_content(_: Option<f64>, _: Option<f64>) -> ContentResult {
    ContentResult {
        kind: "content",
        engine: "cloudflare",
        ok: false,
        down_mbps: None,
        up_mbps: None,
        bytes: 0,
        started: 0.0,
        ended: 0.0,
    }
}

pub fn hooks(clock: &Clock, notices: &Notices) -> Hooks {
    let (c, n) = (Arc::clone(clock), Arc::clone(notices));
    Hooks {
        clock: Arc::new(move || *c.lock().unwrap()),
        local_route: Box::new(|_| Map::new()),
        counters: Box::new(|_| None),
        tether_from_gateway: Box::new(|_| None),
        nm_metered: Box::new(|_| false),
        start_probe: Box::new(|_| Ok(())),
        reachability: Arc::new(|| obj(json!({"verdict": "silent", "proof": null}))),
        content_test: Arc::new(failed_content),
        peak_test: Arc::new(|engine| obj(json!({"kind": "peak", "engine": engine, "ok": false, "started": 0.0}))),
        spawn: Arc::new(|_, job| {
            job();
            Ok(())
        }),
        notify: Arc::new(move |s, b, u| n.lock().unwrap().push((s.into(), b.into(), u))),
    }
}

pub struct Rig {
    pub d: Daemon,
    pub clock: Clock,
    pub notices: Notices,
    pub dir: TempDir,
}

impl Rig {
    pub fn new() -> Rig {
        Rig::at(crate::util::now())
    }

    pub fn at(t: f64) -> Rig {
        Rig::with(t, |_| {})
    }

    pub fn with(t: f64, tweak: impl FnOnce(&mut Hooks)) -> Rig {
        let dir = TempDir::new();
        let clock: Clock = Arc::new(Mutex::new(t));
        let notices: Notices = Arc::default();
        let mut h = hooks(&clock, &notices);
        tweak(&mut h);
        let d =
            Daemon::with(&dir.path().join("state").join("nexthop"), &dir.path().join("run"), h).expect("test daemon");
        Rig { d, clock, notices, dir }
    }

    pub fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }

    pub fn set_clock(&self, t: f64) {
        *self.clock.lock().unwrap() = t;
    }

    pub fn store(&self) -> &Store {
        &self.d.store
    }

    pub fn link(&self, snap: Value) {
        self.d.link.set_latest(obj(snap));
    }

    pub fn put_test(&self, ts: f64, kind: &str, row: TestRow) {
        self.d.store.put_test(ts as i64, kind, "cloudflare", &row).unwrap();
    }

    pub fn events(&self, now: f64) -> Vec<Map<String, Value>> {
        self.d.store.events(1e9, 100, Some(now)).unwrap()
    }

    pub fn single_instrument(&mut self) -> Arc<Series> {
        let s = Arc::new(Series::default());
        self.d.bench = crate::instruments::Bench::new(&[("tcp", "tcp", "x:443")]);
        self.d.instrument_series = vec![("tcp".into(), Arc::clone(&s))];
        self.d.sync_active();
        s
    }
}

pub fn content(down: f64, up: Option<f64>, network: &str) -> TestRow {
    TestRow { down_mbps: Some(down), up_mbps: up, ok: true, network: Some(network.into()), ..TestRow::default() }
}

pub fn snapshot(v: Value) -> Snapshot {
    obj(v)
}
