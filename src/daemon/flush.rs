use serde_json::{Map, Value, json};
use std::collections::HashMap;

use super::core::{AUX_RING_LEN, Daemon, Fallible};
use crate::probes::{Sample, Series};
use crate::pyjson::text;
use crate::score;
use crate::state::write_atomic;
use crate::util::{py_round, py_sum};

const BUCKET_S: f64 = 5.0;
const RECENT_SPAN_S: f64 = 1800.0;

type Buckets = HashMap<i64, Vec<Option<f64>>>;

fn fold(samples: &[Sample], start: f64) -> Buckets {
    let mut out: Buckets = HashMap::new();
    for smp in samples.iter().filter(|s| s.t >= start) {
        out.entry(((smp.t - start) / BUCKET_S) as i64).or_default().push(smp.rtt);
    }
    out
}

fn mean(values: &[f64]) -> f64 {
    py_sum(values.iter().copied()) / values.len() as f64
}

fn round_opt(v: Option<f64>, n: usize) -> Option<f64> {
    v.map(|x| py_round(x, n))
}

impl Daemon {
    pub fn compose_recent(&mut self, now: f64) -> Value {
        self.last_recent_flush = now;
        if self.aux_ring.len() == AUX_RING_LEN {
            self.aux_ring.pop_front();
        }
        self.aux_ring.push_back((now, self.rates.0, self.rates.1, self.last_signal.clone()));
        let start = now - RECENT_SPAN_S;
        let lb = fold(&self.local.all(), start);
        let tbs: Vec<Buckets> = self.total.each_at(None, self.now()).iter().map(|l| fold(l, start)).collect();
        let mut aux_b: HashMap<i64, (Option<f64>, Option<f64>, Value)> = HashMap::new();
        for (at, rx, tx, sig) in &self.aux_ring {
            if *at >= start {
                aux_b.insert(((at - start) / BUCKET_S) as i64, (*rx, *tx, sig.clone()));
            }
        }
        let empty = Vec::new();
        let mut points = Vec::with_capacity((RECENT_SPAN_S / BUCKET_S) as usize);
        for b in 0..(RECENT_SPAN_S / BUCKET_S) as i64 {
            let l = lb.get(&b).unwrap_or(&empty);
            let lr: Vec<f64> = l.iter().flatten().copied().collect();
            let (mut means, mut n_t, mut lost_t) = (Vec::new(), 0usize, 0usize);
            for t in tbs.iter().map(|tb| tb.get(&b).unwrap_or(&empty)) {
                let tr: Vec<f64> = t.iter().flatten().copied().collect();
                n_t += t.len();
                lost_t += t.len() - tr.len();
                if !tr.is_empty() {
                    means.push(mean(&tr));
                }
            }
            let a = aux_b.get(&b);
            let b0 = start + b as f64 * BUCKET_S;
            let tunnel = self.vpn_during(b0, b0 + BUCKET_S);
            let total = (!means.is_empty()).then(|| py_round(mean(&means), 2));
            let local = (!lr.is_empty()).then(|| py_round(mean(&lr), 2));
            let sent = l.len() + n_t;
            let mut point = json!({
                "t": py_round(b0, 1),
                "local": local,
                "total": total,
                "wan": score::wan_point_ms(total, local),
                "loss": (sent > 0).then(|| py_round((l.len() - lr.len() + lost_t) as f64 / sent.max(1) as f64, 3)),
                "local_loss": (!l.is_empty()).then(|| py_round((l.len() - lr.len()) as f64 / l.len() as f64, 3)),
                "total_loss": (n_t > 0).then(|| py_round(lost_t as f64 / n_t as f64, 3)),
                "rx": round_opt(a.and_then(|a| a.0), 1),
                "tx": round_opt(a.and_then(|a| a.1), 1),
                "sig": a.map_or(Value::Null, |a| a.2.clone()),
            });
            if tunnel {
                point["vpn"] = json!(1);
            }
            points.push(point);
        }
        json!({"v": 1, "t": now, "bucket_s": BUCKET_S, "points": points})
    }

    pub fn flush_recent(&mut self, now: f64) -> std::io::Result<()> {
        let payload = self.compose_recent(now);
        write_atomic(&self.recent_path(), &payload, false)
    }

    pub fn flush_minute(&mut self, now: f64) -> Fallible<()> {
        let at = self.now();
        let ls = Series::stats(&self.local.since_at(60.0, at));
        let ts = self.total.stats_at(60.0, at);
        let ws = score::wan_from(&ts, &ls);
        let lag = score::lag_ms(&ts);
        let resp = (ts.count != 0).then(|| score::responsiveness(lag));
        let icmp_stats = Series::stats(&self.icmp_anchor.since_at(60.0, at));
        let icmp_lag = if icmp_stats.count != 0 { score::lag_ms(&icmp_stats) } else { None };

        let (rel, _) = self.reliability(now)?;
        let bloat = self.bufferbloat(300.0);
        let mut snap_link = self.latest();
        if text(&snap_link, "kind") != "wifi" {
            snap_link = Map::new();
        }
        let ssid = text(&snap_link, "ssid").to_string();
        let (spd, spd_ctx) = self.speed_score(now, &ssid)?;
        let scored = crate::pyjson::truthy(spd_ctx.get("scored"));
        let idx = score::index(resp, rel, if scored { spd } else { None });
        let drain = &bloat.drain;
        let values = json!({
            "local_p50": ls.p50, "local_p95": ls.p95,
            "local_jitter": ls.jitter, "local_loss": ls.loss,
            "wan_p50": ws.p50, "wan_p95": ws.p95,
            "wan_jitter": ws.jitter, "wan_loss": ws.loss,
            "local_p75": ls.p75, "local_max": ls.max,
            "wan_p75": ws.p75, "wan_max": ws.max,
            "lag": lag,
            "rx_bps": self.rates.0, "tx_bps": self.rates.1,
            "signal_dbm": snap_link.get("signal_dbm").cloned().unwrap_or(Value::Null),
            "resp": resp, "rel": rel, "spd": spd, "idx": idx,
            "lag_idle": bloat.idle, "lag_loaded": bloat.loaded,
            "lag_icmp": icmp_lag,
            "drain_ms": drain.ms,
            "drain_min_ms": drain.min_ms,
            "drain_settled": drain.settled.map(|s| if s { 1.0 } else { 0.0 }),
            "drain_src": drain.src,
            "vpn": self.vpn_identity(),
        });
        let Value::Object(values) = values else {
            unreachable!("json! object literal");
        };
        let mut probes: Vec<String> = self.bench.actives().iter().map(|i| i.key.clone()).collect();
        probes.sort();
        self.store.put_minute(
            (now / 60.0).floor() as i64 * 60,
            &values,
            text(&self.route, "iface"),
            &ssid,
            &probes.join("+"),
        )?;
        Ok(())
    }

    pub fn flush_apps(&mut self, now: f64) -> std::io::Result<()> {
        if !self.app_traffic.poll() {
            return Ok(());
        }
        let tcp_rx = py_sum(self.app_traffic.rates.iter().map(|a| a.rx_bps));
        let tcp_tx = py_sum(self.app_traffic.rates.iter().map(|a| a.tx_bps));
        let iface_rx = self.rates.0.unwrap_or(0.0);
        let iface_tx = self.rates.1.unwrap_or(0.0);
        let payload = json!({
            "v": 1,
            "t": py_round(now, 1),
            "apps": self.app_traffic.top(8),
            "other": {
                "rx_bps": py_round((iface_rx - tcp_rx).max(0.0), 1),
                "tx_bps": py_round((iface_tx - tcp_tx).max(0.0), 1),
            },
        });
        write_atomic(&self.apps_path(), &payload, false)
    }
}
