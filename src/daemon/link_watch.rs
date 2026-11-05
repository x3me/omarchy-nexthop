use serde_json::{Map, Value};
use std::sync::Arc;

use super::events::{EventLog, StoreResult};
use crate::linkevents::{Cause, NlEvents, reason_text};
use crate::pyjson::{py_str, text, truthy};
use crate::util::py_round_int;

pub trait CauseSource: Send + Sync {
    fn cause_for(&self, bssid: &str, now: f64, window: f64) -> std::io::Result<Option<Cause>>;
}

impl CauseSource for NlEvents {
    fn cause_for(&self, bssid: &str, now: f64, window: f64) -> std::io::Result<Option<Cause>> {
        Ok(NlEvents::cause_for(self, bssid, now, window))
    }
}

pub struct LinkWatch {
    store: Arc<dyn EventLog>,
    events: Option<Arc<dyn CauseSource>>,
    pub prev: Option<Map<String, Value>>,
    pub last_link_t: Option<f64>,
    pub gap_count: u32,
    pub disassociated: bool,
    pub rate_ceiling: f64,
    pub low_since: Option<f64>,
    pub low_floor: Option<f64>,
    pub rate_event_id: Option<i64>,
    pub last_sample: f64,
    pub assoc_since: Option<f64>,
}

fn py_eq(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

pub fn short_duration(seconds: f64) -> String {
    let s = py_round_int(seconds);
    if s < 60 {
        return format!("{} s", s.max(1));
    }
    if s < 3600 {
        return format!("{} min", s / 60);
    }
    format!("{} h {} min", s / 3600, (s % 3600) / 60)
}

impl LinkWatch {
    pub const LOW_FRACTION: f64 = 0.4;
    pub const RECOVER_FRACTION: f64 = 0.6;
    pub const SUSTAIN_S: f64 = 10.0;
    pub const TRAFFIC_FLOOR_BPS: f64 = 25_000.0;
    pub const GAP_SAMPLES: u32 = 5;
    pub const ROAM_FOLLOW_S: f64 = 1.0;

    pub fn new(store: Arc<dyn EventLog>, events: Option<Arc<dyn CauseSource>>) -> Self {
        Self {
            store,
            events,
            prev: None,
            last_link_t: None,
            gap_count: 0,
            disassociated: false,
            rate_ceiling: 0.0,
            low_since: None,
            low_floor: None,
            rate_event_id: None,
            last_sample: 0.0,
            assoc_since: None,
        }
    }

    fn instant(&self, ts: f64, kind: &str, detail: &str) -> StoreResult<()> {
        let severity = if matches!(kind, "kick" | "drop") { "warn" } else { "info" };
        let eid = self.store.open_event(ts as i64, kind, severity, "local", detail)?;
        self.store.close_event(eid, ts as i64, None)
    }

    fn cause(&self, bssid: &str, since: Option<f64>, now: f64) -> Option<Cause> {
        let (Some(events), Some(since)) = (&self.events, since) else {
            return None;
        };
        if bssid.is_empty() {
            return None;
        }
        events.cause_for(bssid, now, now - since + 2.0).ok().flatten()
    }

    fn blame(&self, cause: &Cause, old: &str, new: &str, gap_s: Option<f64>) -> (&'static str, String) {
        let why = reason_text(cause.reason, cause.by_ap);
        let follow = cause.gap_s;
        let (kind, lead) = if cause.by_ap {
            ("kick", format!("Kicked by AP {old} ({why})"))
        } else if gap_s.is_none() && follow.is_some_and(|f| f < Self::ROAM_FOLLOW_S) {
            return ("roam", format!("Roamed to {new}"));
        } else {
            ("drop", format!("Dropped by this machine ({why})"))
        };
        let down = gap_s.or(follow);
        let mut text = lead + ", rejoined";
        if new != old {
            text += &format!(" via {new}");
        }
        if let Some(down) = down.filter(|d| *d >= 0.5) {
            text += &format!(" after {}", short_duration(down));
        }
        (kind, text)
    }

    pub fn sample(&mut self, now: f64, link: &Map<String, Value>, traffic_bps: f64) -> StoreResult<()> {
        if now - self.last_sample < 1.0 {
            return Ok(());
        }
        self.last_sample = now;

        if !truthy(link.get("bssid")) {
            self.gap_count += 1;
            if self.gap_count == Self::GAP_SAMPLES {
                self.disassociated = true;
                self.close_rate_event(now)?;
                self.rate_ceiling = 0.0;
            }
            return Ok(());
        }
        self.gap_count = 0;

        let since = self.last_link_t.replace(now);
        let Some(prev) = self.prev.replace(link.clone()) else {
            self.disassociated = false;
            self.assoc_since = Some(now);
            return Ok(());
        };
        let bssid = text(link, "bssid");
        let prev_bssid = text(&prev, "bssid");
        let ssid = text(link, "ssid");
        let channel_changed =
            truthy(prev.get("channel")) && truthy(link.get("channel")) && !py_eq(&prev["channel"], &link["channel"]);

        if self.disassociated {
            self.disassociated = false;
            self.assoc_since = Some(now);
            if let Some(cause) = self.cause(prev_bssid, since, now) {
                let gap = since.map(|s| now - s);
                let (kind, text) = self.blame(&cause, prev_bssid, bssid, gap);
                self.instant(now, kind, &text)?;
            } else {
                let names: Vec<&str> = [ssid, bssid].into_iter().filter(|x| !x.is_empty()).collect();
                self.instant(now, "associate", &format!("Associated with {}", names.join(", ")))?;
            }
        } else if !bssid.is_empty() && !prev_bssid.is_empty() && bssid != prev_bssid {
            let (kind, lead) = match self.cause(prev_bssid, since, now) {
                Some(cause) => self.blame(&cause, prev_bssid, bssid, None),
                None => ("roam", format!("Roamed to {bssid}")),
            };
            let mut parts = vec![lead];
            if channel_changed {
                parts.push(format!("channel {} \u{2192} {}", py_str(&prev["channel"]), py_str(&link["channel"])));
            }
            let signal = |l: &Map<String, Value>| l.get("signal_dbm").filter(|v| !v.is_null()).cloned();
            if let (Some(before), Some(after)) = (signal(&prev), signal(link)) {
                parts.push(format!("{} \u{2192} {} dBm", py_str(&before), py_str(&after)));
            }
            self.instant(now, kind, &parts.join(", "))?;
            self.rate_ceiling = 0.0;
            self.assoc_since = Some(now);
            self.close_rate_event(now)?;
        } else if bssid == prev_bssid && channel_changed {
            let detail = format!(
                "Channel changed {} \u{2192} {} on the same AP",
                py_str(&prev["channel"]),
                py_str(&link["channel"])
            );
            self.instant(now, "channel-change", &detail)?;
        }

        let Some(tx) = link.get("tx_mbps").and_then(Value::as_f64).filter(|t| *t > 0.0) else {
            return Ok(());
        };
        if traffic_bps < Self::TRAFFIC_FLOOR_BPS {
            return self.close_rate_event(now);
        }
        self.rate_ceiling = tx.max(self.rate_ceiling * 0.998);
        if self.rate_ceiling < 100.0 {
            return Ok(());
        }
        if tx < self.rate_ceiling * Self::LOW_FRACTION {
            let floor = self.low_floor.map_or(tx, |f| f.min(tx));
            self.low_floor = Some(floor);
            match self.low_since {
                None => self.low_since = Some(now),
                Some(low_since) if self.rate_event_id.is_none() && now - low_since >= Self::SUSTAIN_S => {
                    let detail = format!("Tx rate dropped to {} Mbps", py_round_int(floor));
                    self.rate_event_id =
                        Some(self.store.open_event(low_since as i64, "rate-drop", "warn", "local", &detail)?);
                }
                Some(_) => {}
            }
        } else if tx >= self.rate_ceiling * Self::RECOVER_FRACTION {
            self.close_rate_event(now)?;
        }
        Ok(())
    }

    fn close_rate_event(&mut self, now: f64) -> StoreResult<()> {
        if let Some(eid) = self.rate_event_id {
            let detail = format!("Tx rate dropped to {} Mbps", py_round_int(self.low_floor.unwrap_or(0.0)));
            self.store.close_event(eid, now as i64, Some(&detail))?;
            self.rate_event_id = None;
        }
        self.low_since = None;
        self.low_floor = None;
        Ok(())
    }
}
