use serde::Serialize;
use serde_json::{Value, json};

use super::consts::{CONTENT_SETTLE_AFTER_CHANGE_S, MIN_LOAD_SPLIT_SAMPLES, MIN_PLAUSIBLE_INFLATION};
use super::core::{Daemon, Fallible, network_of};
use crate::instruments::{Bench, merged_stats};
use crate::probes::{Sample, Series};
use crate::pyjson::{text, truthy};
use crate::score;
use crate::util::{proc_start_ticks, py_round, py_round_int};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct DrainPick {
    pub ms: Option<f64>,
    pub settled: Option<bool>,
    pub min_ms: Option<f64>,
    pub src: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Bloat {
    pub idle: Option<f64>,
    pub loaded: Option<f64>,
    pub inflation: Option<f64>,
    pub loaded_samples: usize,
    pub idle_samples: usize,
    pub loaded_p50: Option<f64>,
    pub loaded_p95: Option<f64>,
    pub idle_p50: Option<f64>,
    pub drain: DrainPick,
}

type Split = (Vec<Sample>, Vec<Sample>);

pub fn drain(lists: &[Vec<Sample>], splits: &[Split], keys: &[String]) -> DrainPick {
    let mut out = DrainPick::default();
    for (i, (samples, (idle, _))) in lists.iter().zip(splits).enumerate() {
        let base = if idle.is_empty() { None } else { Series::stats(idle).p50 };
        let d = score::drain_after_load(samples, base);
        let Some(ms) = d.ms else {
            continue;
        };
        if out.ms.is_none_or(|m| ms > m) {
            out.ms = Some(ms);
            out.settled = d.settled;
            out.src = keys.get(i).cloned();
        }
        if out.min_ms.is_none_or(|m| ms < m) {
            out.min_ms = Some(ms);
        }
    }
    out
}

pub fn bloat_of(lists: Vec<Vec<Sample>>, keys: &[String]) -> Bloat {
    let splits: Vec<Split> = lists.iter().map(|l| Series::split_by_load(l)).collect();
    let idle_lists: Vec<Vec<Sample>> = splits.iter().map(|s| s.0.clone()).collect();
    let loaded_lists: Vec<Vec<Sample>> = splits.iter().map(|s| s.1.clone()).collect();
    let idle_st = merged_stats(&idle_lists);
    let loaded_st = merged_stats(&loaded_lists);
    let idle_lag = score::measured_lag(&idle_st);
    let loaded_lag = score::measured_lag(&loaded_st);
    let mut inflation = None;
    if let (Some(idle), Some(loaded)) = (idle_lag, loaded_lag)
        && idle != 0.0
        && loaded != 0.0
        && idle > 0.0
        && idle_st.count >= MIN_LOAD_SPLIT_SAMPLES
        && loaded_st.count >= MIN_LOAD_SPLIT_SAMPLES
    {
        let ratio = loaded / idle;
        if ratio >= MIN_PLAUSIBLE_INFLATION {
            inflation = Some(py_round(ratio.max(1.0), 2));
        }
    }
    Bloat {
        idle: idle_lag,
        loaded: loaded_lag,
        inflation,
        loaded_samples: loaded_st.count,
        idle_samples: idle_st.count,
        loaded_p50: loaded_st.p50,
        loaded_p95: loaded_st.p95,
        idle_p50: idle_st.p50,
        drain: drain(&lists, &splits, keys),
    }
}

impl Daemon {
    pub fn bufferbloat(&self, window_s: f64) -> Bloat {
        bloat_of(self.total.each_at(Some(window_s), self.now()), &self.active_keys())
    }

    pub fn compose_live(&mut self, now: f64) -> Fallible<Value> {
        let at = self.now();
        let ls = Series::stats(&self.local.since_at(30.0, at));
        let ts = self.total.stats_at(30.0, at);
        let ws = score::wan_from(&ts, &ls);
        let lag = score::lag_ms(&ts);
        let resp = (ts.count != 0).then(|| score::responsiveness(lag));
        let bloat = self.bufferbloat(300.0);
        let (rel, watched) = self.reliability(now)?;

        let mut snap = self.latest();
        let network = network_of(&snap);
        self.last_signal = snap.get("signal_dbm").cloned().unwrap_or(Value::Null);
        if !network.is_empty() && self.content_network.as_ref().is_some_and(|prev| *prev != network) {
            self.content_boost_at = Some(now + CONTENT_SETTLE_AFTER_CHANGE_S);
        }
        if !network.is_empty() {
            self.content_network = Some(network.clone());
        }
        let band = snap.get("band").and_then(Value::as_str).map(str::to_string);
        self.follow_band(now, &network, band.as_deref());
        if text(&snap, "kind") == "wifi" {
            let traffic = self.rates.0.unwrap_or(0.0) + self.rates.1.unwrap_or(0.0);
            self.link_watch.sample(now, &snap, traffic)?;
            if let Some(Value::Object(st)) = snap.get_mut("station")
                && truthy(st.get("tx_packets"))
            {
                let packets = st.get("tx_packets").and_then(Value::as_f64).unwrap_or(1.0);
                let retries = st.get("tx_retries").and_then(Value::as_f64).unwrap_or(0.0);
                st.insert("retry_pct".into(), json!(py_round(100.0 * retries / packets, 2)));
            }
        }
        let (spd, speed_ctx) = self.speed_score(now, &network)?;
        let lag_band = score::lag_band(&ts);
        let scored_speed = if truthy(speed_ctx.get("scored")) { spd } else { None };
        let idx = score::index(resp, rel, scored_speed);
        let state = self.connection_state(idx);
        let headline = if score::scored_now(state) { idx } else { None };

        let vpn = match self.vpn.clone() {
            Some(mut v) => {
                v.insert("bands".into(), serde_json::to_value(self.tunnel_bands(now))?);
                Value::Object(v)
            }
            None => Value::Null,
        };
        let metered = match &self.metered {
            Some(m) => {
                let mut m = m.clone();
                m.insert("care".into(), json!(self.config.metered_care()));
                Value::Object(m)
            }
            None => Value::Null,
        };
        let queue_p50 = self.app_traffic.latency.as_ref().map(|l| l.queue_p50);
        let pid = std::process::id();
        let last_counters = self.counter_samples.last();
        let instruments = self.bench.snapshot(now, &self.instrument_stats(Bench::WINDOW_S));
        Ok(json!({
            "v": 1,
            "t": py_round(now, 3),
            "state": state,
            "index": headline,
            "band": score::band(headline),
            "scores": {"responsiveness": resp, "reliability": rel, "speed": spd},
            "speed_ctx": speed_ctx,
            "vpn": vpn,
            "reliability_ctx": {"watched_s": py_round_int(watched),
                                "window_s": score::RELIABILITY_WINDOW_S,
                                "min_s": score::RELIABILITY_MIN_WATCHED_S},
            "lag": {"now": lag,
                    "best": lag_band.best, "worst": lag_band.worst,
                    "typical": lag_band.typical,
                    "idle": bloat.idle, "loaded": bloat.loaded,
                    "inflation": bloat.inflation,
                    "loaded_samples": bloat.loaded_samples,
                    "idle_samples": bloat.idle_samples,
                    "loaded_p50": bloat.loaded_p50,
                    "loaded_p95": bloat.loaded_p95,
                    "idle_p50": bloat.idle_p50,
                    "drain_ms": bloat.drain.ms,
                    "drain_settled": bloat.drain.settled},
            "local": ls, "total": ts, "wan": ws,
            "wan_ip": self.wan_ip,
            "metered": metered,
            "reach": self.captive.snapshot(),
            "lookups": self.lookup_watch.snapshot(),
            "sockets": self.app_traffic.latency,
            "pressure": score::pressure(queue_p50, bloat.loaded, bloat.idle),
            "update": self.update_watch.snapshot(),
            "instruments": instruments,
            "rates": {"rx_bps": self.rates.0, "tx_bps": self.rates.1,
                      "rx_total": last_counters.map(|c| c.1),
                      "tx_total": last_counters.map(|c| c.2)},
            "link": snap,
            "down_since": self.watch_local.down_since.or(self.watch_wan.down_since),
            "peak_running": self.peak_running(),
            "content_running": self.content_running(),
            "pid": pid,
            "pid_start": proc_start_ticks(pid.into()),
            "daemon_version": env!("CARGO_PKG_VERSION"),
        }))
    }
}
