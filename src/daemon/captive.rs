use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

use crate::util::{Spawn, py_round_int, spawn_named};

pub type Check = Arc<dyn Fn() -> Map<String, Value> + Send + Sync>;

#[derive(Default)]
struct Shared {
    pending: Option<(u64, Map<String, Value>)>,
    inflight: bool,
}

pub struct CaptiveWatch {
    check: Check,
    spawn: Spawn,
    shared: Arc<Mutex<Shared>>,
    generation: u64,
    pub verdict: String,
    pub proof: Option<Value>,
    pub checked_ts: Option<i64>,
    pub strikes: u32,
    next: f64,
    confirmed: bool,
    names: (bool, bool),
}

impl CaptiveWatch {
    pub const CHECK_EVERY_S: f64 = 30.0;
    pub const RECHECK_OPEN_S: f64 = 3600.0;
    pub const CONFIRM_AFTER: u32 = 2;

    pub fn new(check: Check, spawn: Option<Spawn>) -> Self {
        Self {
            check,
            spawn: spawn.unwrap_or_else(|| Box::new(|job| spawn_named("reach", job))),
            shared: Arc::new(Mutex::new(Shared::default())),
            generation: 0,
            verdict: "unknown".into(),
            proof: None,
            checked_ts: None,
            strikes: 0,
            next: 0.0,
            confirmed: false,
            names: (false, false),
        }
    }

    pub fn explained_by_names(verdict: &str, names_answered: bool, names_failing: bool) -> bool {
        if verdict == "unresolved" {
            return names_answered || names_failing;
        }
        verdict == "silent" && names_failing
    }

    pub fn captive(
        verdict: &str,
        probes_answering: bool,
        strikes: u32,
        names_answered: bool,
        names_failing: bool,
    ) -> bool {
        probes_answering
            && matches!(verdict, "intercepted" | "silent" | "unresolved")
            && strikes >= Self::CONFIRM_AFTER
            && !Self::explained_by_names(verdict, names_answered, names_failing)
    }

    pub fn confirmed(&self) -> bool {
        self.confirmed
    }

    pub fn request(&mut self) {
        self.generation += 1;
        self.shared.lock().unwrap().inflight = false;
        self.next = 0.0;
        self.verdict = "unknown".into();
        self.proof = None;
        self.strikes = 0;
        self.confirmed = false;
    }

    pub fn tick(&mut self, now: f64, probes_answering: bool, names_answered: bool, names_failing: bool) {
        self.names = (names_answered, names_failing);
        self.collect(now);
        if !probes_answering {
            self.strikes = 0;
            self.confirmed = false;
            return;
        }
        let inflight = self.shared.lock().unwrap().inflight;
        if inflight || now < self.next {
            self.confirmed =
                Self::captive(&self.verdict, probes_answering, self.strikes, names_answered, names_failing);
            return;
        }
        self.shared.lock().unwrap().inflight = true;
        let (generation, check, shared) = (self.generation, Arc::clone(&self.check), Arc::clone(&self.shared));
        let started = (self.spawn)(Box::new(move || {
            let mut result = check();
            if result.is_empty() {
                result = silent();
            }
            let mut shared = shared.lock().unwrap();
            shared.pending = Some((generation, result));
            shared.inflight = false;
        }));
        if let Err(e) = started {
            crate::util::complain!("nexthopd: cannot start the reachability check: {e}");
            self.shared.lock().unwrap().inflight = false;
        }
        self.collect(now);
    }

    fn collect(&mut self, now: f64) {
        let Some((generation, result)) = self.shared.lock().unwrap().pending.take() else {
            return;
        };
        if generation != self.generation {
            return;
        }
        self.verdict = match result.get("verdict").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => "silent".into(),
        };
        self.proof = result.get("proof").filter(|p| !p.is_null()).cloned();
        let (names_answered, names_failing) = self.names;
        if self.verdict == "open" {
            self.strikes = 0;
        } else if !Self::explained_by_names(&self.verdict, names_answered, names_failing) {
            self.strikes += 1;
        }
        self.checked_ts = Some(py_round_int(now));
        self.next = now + if self.verdict == "open" { Self::RECHECK_OPEN_S } else { Self::CHECK_EVERY_S };
        self.confirmed = Self::captive(&self.verdict, true, self.strikes, names_answered, names_failing);
    }

    pub fn snapshot(&self) -> Option<Value> {
        if self.verdict == "unknown" {
            return None;
        }
        Some(json!({"verdict": self.verdict, "captive": self.confirmed, "checked_ts": self.checked_ts}))
    }
}

fn silent() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("verdict".into(), "silent".into());
    m.insert("proof".into(), Value::Null);
    m
}
