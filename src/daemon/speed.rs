use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::consts::{
    CHECK_QUIET_S, CONTENT_RETRY_S, Gate, PEAK_FRESH_S, SPEED_CHECK_MAX_AGE_S, check_gate, check_ready,
};
use super::core::{Daemon, Fallible, Workers, field, network_of};
use super::events::StoreResult;
use crate::instruments::merged_stats;
use crate::pyjson::{py_str, truthy};
use crate::score;
use crate::store::{TestRow, vpn_matches};

type Row = Map<String, Value>;
use crate::util::py_round;

struct Running(Arc<Workers>, fn(&Workers) -> &AtomicBool);

impl Drop for Running {
    fn drop(&mut self) {
        (self.1)(&self.0).store(false, Ordering::SeqCst);
    }
}

fn num(row: &Row, key: &str) -> Option<f64> {
    row.get(key).and_then(Value::as_f64)
}

fn opt_text(row: &Row, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).map(str::to_string)
}

fn band_of(snap: &Map<String, Value>) -> Value {
    field(snap, "band").clone()
}

impl Daemon {
    pub fn collect_workers(&mut self) {
        if self.workers.baseline_stale.swap(false, Ordering::SeqCst) {
            self.baseline_cache = None;
        }
        if let Some(at) = self.workers.retry_at.lock().unwrap().take() {
            self.content_boost_at = Some(at);
        }
    }

    pub fn maybe_content_test(&mut self, now: f64) -> Fallible<()> {
        self.collect_workers();
        if !self.config.content_speed() {
            return Ok(());
        }
        let interval = (self.config.content_speed_interval_min().max(15) * 60) as f64;
        let due = now - self.last_content_test >= interval || self.content_boost_at.is_some_and(|b| now >= b);
        if !due {
            return Ok(());
        }
        if self.watch_wan.down_since.is_some() || self.watch_local.down_since.is_some() || !self.tests_idle() {
            return Ok(());
        }
        if self.metered.is_some() && self.config.metered_care() {
            return Ok(());
        }

        match check_gate(now, self.busy_at, Some(self.watching_since), self.quiet_waiting_since) {
            Gate::Wait => {
                if self.busy_at.is_some_and(|b| now - b < CHECK_QUIET_S) && self.quiet_waiting_since.is_none() {
                    self.quiet_waiting_since = Some(now);
                }
                return Ok(());
            }
            Gate::Skip => {
                let row = TestRow {
                    ok: false,
                    detail: Some("skipped-busy".into()),
                    network: Some(self.network_name()),
                    vpn: self.vpn_identity(),
                    quiet_s: self.busy_at.map(|b| py_round(now - b, 1)),
                    awake_s: Some(py_round(now - self.watching_since, 1)),
                    asked: Some(false),
                    ..TestRow::default()
                };
                self.store.put_test(now as i64, "content", "", &row)?;
                self.quiet_waiting_since = None;
                self.content_boost_at = None;
                self.last_content_test = now;
                return Ok(());
            }
            Gate::Run => {}
        }
        self.quiet_waiting_since = None;

        if !check_ready(now, self.link_watch.assoc_since, self.link_watch.low_since, self.check_waiting_since) {
            if self.check_waiting_since.is_none() {
                self.check_waiting_since = Some(now);
            }
            return Ok(());
        }
        self.check_waiting_since = None;
        self.content_boost_at = None;
        self.last_content_test = now;
        let quiet_s = self.busy_at.map(|b| py_round(now - b, 1));
        let awake_s = Some(py_round(now - self.watching_since, 1));

        let snap = self.latest();
        let network = network_of(&snap);
        let band_before = band_of(&snap);
        let tunnel_before = self.vpn.as_ref().map(|v| py_str(field(v, "iface")));
        let (down_hint, up_hint) = self.content_hint(&network, self.vpn_identity().as_deref())?;
        self.publish_path();
        self.workers.content_running.store(true, Ordering::SeqCst);

        let (workers, store, link) = (Arc::clone(&self.workers), Arc::clone(&self.store), Arc::clone(&self.link));
        let (content, clock) = (Arc::clone(&self.hooks.content_test), Arc::clone(&self.hooks.clock));
        let job = Box::new(move || {
            let _running = Running(Arc::clone(&workers), |w| &w.content_running);
            let r = content(down_hint, up_hint);
            let after = link.latest();
            let (tunnel_now, vpn) = workers.path.lock().unwrap().clone();
            if network_of(&after) != network || band_of(&after) != band_before || tunnel_now != tunnel_before {
                return;
            }
            if r.ok {
                let row = TestRow {
                    down_mbps: r.down_mbps,
                    up_mbps: r.up_mbps,
                    bytes: Some(r.bytes),
                    ok: true,
                    network: Some(network),
                    vpn,
                    quiet_s,
                    awake_s,
                    asked: Some(false),
                    band: band_before.as_str().map(str::to_string),
                    ..TestRow::default()
                };
                if let Err(e) = store.put_test(r.started as i64, "content", r.engine, &row) {
                    crate::util::complain!("nexthopd: storing the content check: {e}");
                    return;
                }
                workers.baseline_stale.store(true, Ordering::SeqCst);
                workers.content_retry_used.store(false, Ordering::SeqCst);
            } else if !workers.content_retry_used.swap(true, Ordering::SeqCst) {
                *workers.retry_at.lock().unwrap() = Some(clock() + CONTENT_RETRY_S);
            }
        });
        if let Err(e) = (self.hooks.spawn)("content-test", job) {
            self.workers.content_running.store(false, Ordering::SeqCst);
            return Err(e.into());
        }
        Ok(())
    }

    pub fn content_hint(&self, network: &str, vpn: Option<&str>) -> StoreResult<(Option<f64>, Option<f64>)> {
        let (mut downs, mut ups) = (Vec::new(), Vec::new());
        for t in self.store.tests(8, Some("content"))? {
            if !truthy(t.get("ok"))
                || t.get("network").and_then(Value::as_str).unwrap_or("") != network
                || !vpn_matches(t.get("vpn").and_then(Value::as_str), vpn)
            {
                continue;
            }
            if let Some(d) = num(&t, "down_mbps").filter(|d| *d != 0.0) {
                downs.push(d);
            }
            if let Some(u) = num(&t, "up_mbps").filter(|u| *u != 0.0) {
                ups.push(u);
            }
        }
        Ok((downs.into_iter().reduce(f64::max), ups.into_iter().reduce(f64::max)))
    }

    pub fn run_peak_test(&mut self) -> Fallible<()> {
        if !self.tests_idle() {
            return Ok(());
        }
        self.workers.peak_running.store(true, Ordering::SeqCst);
        let network = self.network_name();
        let vpn = self.vpn_identity();
        let engine = self.config.peak_engine();
        let (workers, store, total) = (Arc::clone(&self.workers), Arc::clone(&self.store), Arc::clone(&self.total));
        let (peak, clock) = (Arc::clone(&self.hooks.peak_test), Arc::clone(&self.hooks.clock));
        let job = Box::new(move || {
            let _running = Running(Arc::clone(&workers), |w| &w.peak_running);
            let idle = score::measured_lag(&total.stats_at(60.0, clock()));
            let started = clock();
            let r = peak(&engine);
            let lists: Vec<_> = total
                .each_at(None, clock())
                .into_iter()
                .map(|l| l.into_iter().filter(|s| s.t >= started).collect())
                .collect();
            let loaded = merged_stats(&lists).p50.map(|p| py_round(p, 1));
            let ts = r.get("started").and_then(Value::as_f64).unwrap_or(started) as i64;
            let engine = r.get("engine").and_then(Value::as_str).unwrap_or_default().to_string();
            let row = if truthy(r.get("ok")) {
                TestRow {
                    down_mbps: num(&r, "down_mbps"),
                    up_mbps: num(&r, "up_mbps"),
                    ping_idle: num(&r, "ping_idle").filter(|p| *p != 0.0).or(idle),
                    ping_loaded: loaded,
                    jitter: num(&r, "jitter"),
                    bytes: r.get("bytes").and_then(|b| b.as_i64().or_else(|| b.as_f64().map(|f| f as i64))),
                    server: opt_text(&r, "server"),
                    ok: true,
                    detail: Some(opt_text(&r, "url").unwrap_or_default()),
                    network: Some(network),
                    vpn,
                    asked: Some(true),
                    ..TestRow::default()
                }
            } else {
                TestRow { ok: false, network: Some(network), vpn, asked: Some(true), ..TestRow::default() }
            };
            if let Err(e) = store.put_test(ts, "peak", &engine, &row) {
                crate::util::complain!("nexthopd: storing the peak test: {e}");
            }
        });
        if let Err(e) = (self.hooks.spawn)("peak-test", job) {
            self.workers.peak_running.store(false, Ordering::SeqCst);
            return Err(e.into());
        }
        Ok(())
    }

    pub fn speed_score(&mut self, now: f64, network: &str) -> StoreResult<(Option<f64>, Map<String, Value>)> {
        self.collect_workers();
        let vpn = self.vpn_identity();
        let on_vpn = vpn.is_some();
        let tests: Vec<Row> = self
            .store
            .tests(12, Some("content"))?
            .into_iter()
            .filter(|t| {
                truthy(t.get("ok"))
                    && num(t, "down_mbps").is_some()
                    && vpn_matches(t.get("vpn").and_then(Value::as_str), vpn.as_deref())
            })
            .collect();
        let as_map = |v: Value| match v {
            Value::Object(m) => m,
            _ => Map::new(),
        };

        let plan_d = self.config.get("planDownMbps").clone();
        let plan_u = self.config.get("planUpMbps").clone();
        let plan_down = plan_d.as_f64().unwrap_or(0.0);
        if plan_down != 0.0 {
            let Some(last) = tests.first() else {
                return Ok((
                    None,
                    as_map(json!({"basis": "plan", "plan_down": plan_d, "last_down": null, "last_up": null,
                                  "vpn": on_vpn})),
                ));
            };
            let plan_up = plan_u.as_f64().unwrap_or(0.0);
            let spd = score::speed(num(last, "down_mbps"), num(last, "up_mbps"), plan_down, plan_up, None);
            return Ok((
                spd,
                as_map(json!({"basis": "plan", "plan_down": plan_d, "plan_up": plan_u,
                              "last_down": field(last, "down_mbps"), "last_up": field(last, "up_mbps"),
                              "vpn": on_vpn})),
            ));
        }

        let mine: Vec<&Row> = tests
            .iter()
            .filter(|t| network.is_empty() || t.get("network").and_then(Value::as_str).unwrap_or("") == network)
            .collect();
        if mine.is_empty() {
            return Ok((
                None,
                as_map(json!({"basis": "auto", "baseline_down": null, "last_down": null, "last_up": null,
                              "pending": true, "vpn": on_vpn})),
            ));
        }
        let wifi_band = band_of(&self.latest()).as_str().filter(|b| !b.is_empty()).map(str::to_string);
        let mut now_checks: Vec<&Row> = Vec::new();
        let mut stale = "age";
        for t in &mine {
            if now - num(t, "ts").unwrap_or(0.0) > SPEED_CHECK_MAX_AGE_S {
                break;
            }
            let band = t.get("band").and_then(Value::as_str).filter(|b| !b.is_empty());
            if let (Some(w), Some(b)) = (&wifi_band, band)
                && b != w
            {
                stale = "band";
                break;
            }
            now_checks.push(t);
        }
        if now_checks.is_empty() {
            return Ok((
                None,
                as_map(json!({"basis": "auto", "baseline_down": null, "last_down": null, "last_up": null,
                              "stale": stale, "stale_ts": field(mine[0], "ts"), "band": wifi_band,
                              "max_age_s": SPEED_CHECK_MAX_AGE_S, "vpn": on_vpn})),
            ));
        }

        let recent: Vec<&Row> = now_checks.into_iter().take(3).collect();
        let mut downs: Vec<f64> = recent.iter().filter_map(|t| num(t, "down_mbps")).collect();
        downs.sort_by(f64::total_cmp);
        let down = downs[downs.len() / 2];
        let mut ups: Vec<f64> = recent.iter().filter_map(|t| num(t, "up_mbps")).collect();
        ups.sort_by(f64::total_cmp);
        let up = ups.get(ups.len() / 2).copied();

        let key = (network.to_string(), vpn.clone());
        let baseline = match &self.baseline_cache {
            Some((at, baseline, seen)) if now - at <= 60.0 && *seen == key => *baseline,
            _ => {
                let baseline = self.store.baseline_speed(30, network, 5, Some(now), false, vpn.as_deref())?;
                self.baseline_cache = Some((now, baseline, key));
                baseline
            }
        };
        let spd = score::speed(Some(down), up, 0.0, 0.0, baseline);

        let (mut peak_down, mut peak_ts) = (None, None);
        for t in self.store.tests(6, Some("peak"))? {
            if !truthy(t.get("ok")) || num(&t, "down_mbps").is_none() {
                continue;
            }
            if !network.is_empty() && t.get("network").and_then(Value::as_str).unwrap_or("") != network {
                continue;
            }
            if !vpn_matches(t.get("vpn").and_then(Value::as_str), vpn.as_deref()) {
                continue;
            }
            if now - num(&t, "ts").unwrap_or(0.0) > PEAK_FRESH_S {
                break;
            }
            peak_down = num(&t, "down_mbps");
            peak_ts = t.get("ts").and_then(Value::as_i64);
            break;
        }

        let scored = score::speed_scored(Some(down), recent.len(), peak_down);
        let checks_down: Vec<Value> = recent.iter().map(|t| field(t, "down_mbps").clone()).collect();
        Ok((
            spd,
            as_map(json!({"basis": "auto", "baseline_down": baseline, "last_down": down, "last_up": up,
                          "samples": recent.len(), "scored": scored, "peak_down": peak_down, "vpn": on_vpn,
                          "checks_down": checks_down, "min_samples": score::MIN_SPEED_SAMPLES,
                          "peak_ts": peak_ts, "peak_until": peak_ts.map(|t| t as f64 + PEAK_FRESH_S)})),
        ))
    }
}
