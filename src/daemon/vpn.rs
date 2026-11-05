use serde_json::{Map, Value};

use super::consts::{BAND_CHECK_MIN_GAP_S, CONTENT_SETTLE_AFTER_CHANGE_S};
use super::core::{Daemon, VPN_SPANS_LEN, field};
use super::events::StoreResult;
use crate::pyjson::{py_str, truthy};
use crate::score::{self, TunnelBands};

fn found_vpn(snap: &Map<String, Value>) -> Option<Map<String, Value>> {
    match snap.get("vpn") {
        Some(Value::Object(m)) if !m.is_empty() => Some(m.clone()),
        _ => None,
    }
}

impl Daemon {
    pub fn follow_path_states(&mut self, now: f64) -> StoreResult<()> {
        let found = found_vpn(&self.latest());
        let prev = self.vpn.take();
        let same_span = match (&found, &prev) {
            (Some(f), Some(p)) => field(f, "iface") == field(p, "iface") && field(f, "scope") == field(p, "scope"),
            _ => false,
        };
        self.vpn = found.as_ref().map(|f| {
            let mut v = f.clone();
            let since =
                if same_span { field(prev.as_ref().unwrap(), "since").clone() } else { Value::from(now as i64) };
            v.insert("since".into(), since);
            v
        });
        let moved = found.is_some() != prev.is_some()
            || matches!((&found, &prev), (Some(f), Some(p)) if field(f, "iface") != field(p, "iface"));

        let detail = self.vpn.as_ref().map(|v| {
            let iface = py_str(field(v, "iface"));
            if field(v, "scope").as_str() == Some("full") {
                format!("Measured through a VPN ({iface})")
            } else {
                format!("Partly measured through a VPN ({iface})")
            }
        });
        self.vpn_events.update(now, detail.as_deref())?;
        self.wan_events.tunnel = self.vpn.is_some();

        let tether = self
            .metered
            .as_ref()
            .filter(|m| truthy(m.get("tethered")))
            .map(|m| format!("Measured through a hotspot ({})", py_str(field(m, "label"))));
        self.tether_events.update(now, tether.as_deref())?;

        if found.is_some() != prev.is_some() {
            if found.is_some() {
                if self.vpn_spans.len() == VPN_SPANS_LEN {
                    self.vpn_spans.pop_front();
                }
                self.vpn_spans.push_back((now, None));
            } else if let Some(last) = self.vpn_spans.back_mut()
                && last.1.is_none()
            {
                last.1 = Some(now);
            }
        }
        if moved {
            self.wan_ip = None;
            self.wan_ip_at = 0;
            self.captive.request();
            self.content_boost_at = Some(now + CONTENT_SETTLE_AFTER_CHANGE_S);
        }
        self.publish_path();
        Ok(())
    }

    pub fn follow_band(&mut self, now: f64, network: &str, wifi_band: Option<&str>) {
        let prev = self.band_seen.clone();
        let band = wifi_band.filter(|b| !b.is_empty());
        if let Some(b) = band {
            self.band_seen = Some((network.to_string(), b.to_string()));
        }
        let (Some(band), Some(prev)) = (band, prev) else {
            return;
        };
        if prev.0 != network || prev.1 == band {
            return;
        }
        if self.band_check_at.is_some_and(|last| now - last < BAND_CHECK_MIN_GAP_S) {
            return;
        }
        self.band_check_at = Some(now);
        self.content_boost_at = Some(now + CONTENT_SETTLE_AFTER_CHANGE_S);
    }

    pub fn lose_sight_of_path_states(&mut self, watched_until: f64) -> StoreResult<()> {
        self.vpn_events.lost_sight(watched_until)?;
        self.tether_events.lost_sight(watched_until)?;
        if let Some(last) = self.vpn_spans.back_mut()
            && last.1.is_none()
        {
            last.1 = Some(watched_until);
        }
        self.vpn = None;
        self.publish_path();
        Ok(())
    }

    pub fn vpn_identity(&self) -> Option<String> {
        let vpn = self.vpn.as_ref()?;
        let iface = py_str(field(vpn, "iface"));
        let edge = self.wan_ip.as_ref().map(|w| field(w, "edge")).filter(|e| truthy(Some(e)));
        Some(match edge {
            Some(e) => format!("{iface}@{}", py_str(e)),
            None => iface,
        })
    }

    pub fn publish_path(&self) {
        let iface = self.vpn.as_ref().map(|v| py_str(field(v, "iface")));
        *self.workers.path.lock().unwrap() = (iface, self.vpn_identity());
    }

    pub fn vpn_during(&self, a: f64, b: f64) -> bool {
        self.vpn_spans.iter().any(|&(start, end)| start < b && end.is_none_or(|e| e > a))
    }

    pub fn tunnel_bands(&mut self, now: f64) -> Option<TunnelBands> {
        let ident = self.vpn_identity()?;
        if let Some((at, seen, bands)) = &self.tunnel_bands_cache
            && *seen == ident
            && now - at < 60.0
        {
            return bands.clone();
        }
        let bands = match self.store.tunnel_level(&ident, 24.0 * 3600.0, Some(now)) {
            Ok((med, p90, n)) => score::tunnel_bands(med, p90, n),
            Err(_) => None,
        };
        self.tunnel_bands_cache = Some((now, ident, bands.clone()));
        bands
    }

    pub fn adopt_wan_ip(&mut self) {
        let (Some(proof), Some(checked)) = (self.captive.proof.clone(), self.captive.checked_ts) else {
            return;
        };
        let Value::Object(proof) = proof else {
            return;
        };
        if proof.is_empty() || checked == 0 || checked == self.wan_ip_at {
            return;
        }
        let before = self.wan_ip.as_ref().map(|w| field(w, "ip").clone()).filter(|ip| truthy(Some(ip)));
        self.wan_ip_at = checked;
        let mut wan_ip = proof;
        wan_ip.insert("checked_ts".into(), Value::from(checked));
        let ip = field(&wan_ip, "ip").clone();
        self.wan_ip = Some(wan_ip);
        if let Some(before) = before
            && !ip.is_null()
            && ip != before
        {
            self.content_boost_at = Some(self.now() + CONTENT_SETTLE_AFTER_CHANGE_S);
        }
        self.publish_path();
    }
}
