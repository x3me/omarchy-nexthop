use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

use super::support::MemStore;
use crate::daemon::link_watch::{CauseSource, LinkWatch, short_duration};
use crate::linkevents::Cause;
use crate::testutil::obj;

const T: f64 = 1_000_000.0;
const BUSY: f64 = 1_000_000.0;

fn with_tx(base: &Map<String, Value>, tx: f64) -> Map<String, Value> {
    let mut m = base.clone();
    m.insert("tx_mbps".into(), tx.into());
    m
}

struct StubEvents {
    cause: Option<Cause>,
    raise: bool,
    calls: Mutex<Vec<(String, f64, f64)>>,
}

impl StubEvents {
    fn new(cause: Option<Cause>, raise: bool) -> Arc<Self> {
        Arc::new(Self { cause, raise, calls: Mutex::default() })
    }
}

impl CauseSource for StubEvents {
    fn cause_for(&self, bssid: &str, now: f64, window: f64) -> std::io::Result<Option<Cause>> {
        self.calls.lock().unwrap().push((bssid.into(), now, window));
        if self.raise {
            return Err(std::io::Error::other("boom"));
        }
        Ok(self.cause.clone())
    }
}

mod link_events {
    use super::*;

    #[test]
    fn first_sighting_is_not_an_association() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        watch.sample(T, &obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "Office"})), 0.0).unwrap();
        assert!(store.kinds().is_empty());
    }

    #[test]
    fn roam_and_detail() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        let first = json!({"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "Office", "channel": 149, "signal_dbm": -61});
        let second = json!({"bssid": "bb:bb:bb:bb:bb:bb", "ssid": "Office", "channel": 44, "signal_dbm": -47});
        watch.sample(T, &obj(first), 0.0).unwrap();
        watch.sample(T + 2.0, &obj(second), 0.0).unwrap();
        let kinds = store.kinds();
        assert!(kinds.contains(&"roam".to_string()));
        assert!(!kinds.contains(&"associate".to_string()));
        let roam = store.events().into_iter().find(|e| e.kind == "roam").unwrap();
        assert!(roam.detail.contains("149"));
        assert!(roam.detail.contains("44"));
        assert!(roam.detail.contains("-61"));
        assert_eq!(roam.detail, "Roamed to bb:bb:bb:bb:bb:bb, channel 149 \u{2192} 44, -61 \u{2192} -47 dBm");
    }

    #[test]
    fn roam_stores_bssid_not_access_point_name() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        watch
            .sample(T, &obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "ap_name": "Kitchen", "channel": 149})), 0.0)
            .unwrap();
        watch
            .sample(T + 2.0, &obj(json!({"bssid": "bb:bb:bb:bb:bb:bb", "ap_name": "Hallway AP", "channel": 44})), 0.0)
            .unwrap();
        let roam = store.events().into_iter().find(|e| e.kind == "roam").unwrap();
        assert!(roam.detail.starts_with("Roamed to bb:bb:bb:bb:bb:bb"));
        assert!(!roam.detail.contains("Hallway AP"));
    }

    #[test]
    fn same_named_radios_are_stored_as_distinct_bssids() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        watch
            .sample(T, &obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "ap_name": "Hallway AP", "channel": 157})), 0.0)
            .unwrap();
        watch
            .sample(T + 2.0, &obj(json!({"bssid": "bb:bb:bb:bb:bb:bb", "ap_name": "Hallway AP", "channel": 209})), 0.0)
            .unwrap();
        let roam = store.events().into_iter().find(|e| e.kind == "roam").unwrap();
        assert!(roam.detail.contains("bb:bb:bb:bb:bb:bb"));
        assert!(!roam.detail.contains("Hallway AP"));
    }

    #[test]
    fn associate_needs_a_confirmed_gap() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        let up = obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "Office"}));
        watch.sample(T, &up, 0.0).unwrap();
        for i in 0..LinkWatch::GAP_SAMPLES - 1 {
            watch.sample(T + 2.0 + i as f64 * 2.0, &Map::new(), 0.0).unwrap();
        }
        watch.sample(T + 20.0, &up, 0.0).unwrap();
        assert!(store.kinds().is_empty());
        for i in 0..LinkWatch::GAP_SAMPLES {
            watch.sample(T + 30.0 + i as f64 * 2.0, &Map::new(), 0.0).unwrap();
        }
        watch.sample(T + 60.0, &up, 0.0).unwrap();
        assert_eq!(store.kinds(), ["associate"]);
    }

    #[test]
    fn rate_drop_needs_sustain() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        let base = obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X", "channel": 44}));
        for i in 0..5 {
            watch.sample(T + i as f64 * 2.0, &with_tx(&base, 500.0), BUSY).unwrap();
        }
        watch.sample(T + 12.0, &with_tx(&base, 120.0), BUSY).unwrap();
        watch.sample(T + 14.0, &with_tx(&base, 500.0), BUSY).unwrap();
        assert!(!store.kinds().contains(&"rate-drop".to_string()));
        for i in 0..8 {
            watch.sample(T + 20.0 + i as f64 * 2.0, &with_tx(&base, 110.0), BUSY).unwrap();
        }
        assert!(store.kinds().contains(&"rate-drop".to_string()));
        watch.sample(T + 40.0, &with_tx(&base, 480.0), BUSY).unwrap();
        let drop = store.events().into_iter().find(|e| e.kind == "rate-drop").unwrap();
        assert!(drop.ended_ts.is_some());
        assert!(drop.detail.contains("110"));
    }

    #[test]
    fn idle_rate_drops_are_not_events() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        let base = obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X", "channel": 44}));
        for i in 0..5 {
            watch.sample(T + i as f64 * 2.0, &with_tx(&base, 2000.0), BUSY).unwrap();
        }
        for i in 0..20 {
            watch.sample(T + 20.0 + i as f64 * 2.0, &with_tx(&base, 120.0), 500.0).unwrap();
        }
        assert!(!store.kinds().contains(&"rate-drop".to_string()));
    }

    #[test]
    fn throttled_to_one_hz() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        watch.sample(T, &obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "X"})), 0.0).unwrap();
        watch.sample(T + 0.4, &obj(json!({"bssid": "bb:bb:bb:bb:bb:bb", "ssid": "X"})), 0.0).unwrap();
        assert!(!store.kinds().contains(&"roam".to_string()));
    }

    #[test]
    fn a_channel_change_on_the_same_ap_is_recorded() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        watch.sample(T, &obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "channel": 36})), 0.0).unwrap();
        watch.sample(T + 2.0, &obj(json!({"bssid": "aa:aa:aa:aa:aa:aa", "channel": 149})), 0.0).unwrap();
        let row = &store.events()[0];
        assert_eq!((row.kind.as_str(), row.severity.as_str()), ("channel-change", "info"));
        assert_eq!(row.detail, "Channel changed 36 \u{2192} 149 on the same AP");
    }
}

mod link_attribution {
    use super::*;

    const OLD: &str = "aa:aa:aa:aa:aa:aa";
    const NEW: &str = "bb:bb:bb:bb:bb:bb";

    fn cause(by_ap: bool, reason: u32, gap_s: Option<f64>) -> Cause {
        Cause { t: 0.0, frame: "deauth".into(), by_ap, reason, gap_s }
    }

    fn change(cause: Option<Cause>, raise: bool) -> (super::super::support::Row, Arc<StubEvents>) {
        let store = MemStore::new();
        let events = StubEvents::new(cause, raise);
        let mut watch = LinkWatch::new(store.clone(), Some(events.clone()));
        watch.sample(T, &obj(json!({"bssid": OLD, "ssid": "Office", "channel": 149, "signal_dbm": -30})), 0.0).unwrap();
        watch
            .sample(T + 2.0, &obj(json!({"bssid": NEW, "ssid": "Office", "channel": 13, "signal_dbm": -53})), 0.0)
            .unwrap();
        let evs = store.events();
        assert_eq!(evs.len(), 1);
        (evs[0].clone(), events)
    }

    fn after_a_gap(events: Arc<StubEvents>, first: Value, back: Value) -> super::super::support::Row {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), Some(events));
        watch.sample(T, &obj(first), 0.0).unwrap();
        for i in 0..LinkWatch::GAP_SAMPLES {
            watch.sample(T + 2.0 + i as f64 * 2.0, &Map::new(), 0.0).unwrap();
        }
        watch.sample(T + 14.0, &obj(back), 0.0).unwrap();
        let evs = store.events();
        assert_eq!(evs.len(), 1);
        evs[0].clone()
    }

    #[test]
    fn ap_deauth_is_a_kick() {
        let (e, events) = change(Some(cause(true, 2, Some(3.0))), false);
        assert_eq!(e.kind, "kick");
        assert!(e.detail.contains(&format!("Kicked by AP {OLD}")));
        assert!(e.detail.contains("reason 2: previous authentication no longer valid"));
        assert!(e.detail.contains(&format!("rejoined via {NEW} after 3 s")));
        assert!(e.detail.contains("channel 149 \u{2192} 13"));
        assert!(e.detail.contains("-30 \u{2192} -53 dBm"));
        let (bssid, _, window) = events.calls.lock().unwrap()[0].clone();
        assert_eq!(bssid, OLD);
        assert!(window >= 2.0);
    }

    #[test]
    fn local_deauth_with_instant_reauth_is_a_roam() {
        let (e, _) = change(Some(cause(false, 1, Some(0.004))), false);
        assert_eq!(e.kind, "roam");
        assert!(e.detail.starts_with(&format!("Roamed to {NEW}")));
    }

    #[test]
    fn local_deauth_with_a_scan_first_is_a_drop() {
        let (e, _) = change(Some(cause(false, 4, Some(2.8))), false);
        assert_eq!(e.kind, "drop");
        assert!(e.detail.contains("Dropped by this machine (reason 4: beacon loss)"));
        assert!(e.detail.contains(&format!("rejoined via {NEW} after 3 s")));
    }

    #[test]
    fn unknown_cause_stays_a_roam() {
        let (e, _) = change(None, false);
        assert_eq!(e.kind, "roam");
        assert!(e.detail.starts_with(&format!("Roamed to {NEW}")));
    }

    #[test]
    fn without_an_event_source_nothing_changes() {
        let store = MemStore::new();
        let mut watch = LinkWatch::new(store.clone(), None);
        watch.sample(T, &obj(json!({"bssid": OLD, "ssid": "Office"})), 0.0).unwrap();
        watch.sample(T + 2.0, &obj(json!({"bssid": NEW, "ssid": "Office"})), 0.0).unwrap();
        assert_eq!(store.kinds(), ["roam"]);
    }

    #[test]
    fn attribution_failure_never_costs_the_event() {
        let (e, _) = change(Some(cause(true, 2, Some(3.0))), true);
        assert_eq!(e.kind, "roam");
    }

    #[test]
    fn kick_with_a_confirmed_gap_is_one_row() {
        let events = StubEvents::new(Some(cause(true, 2, None)), false);
        let e = after_a_gap(
            events.clone(),
            json!({"bssid": OLD, "ssid": "Office"}),
            json!({"bssid": OLD, "ssid": "Office"}),
        );
        assert_eq!(e.kind, "kick");
        assert!(e.detail.contains("rejoined after 14 s"));
        assert!(!e.detail.contains(" via "));
        assert!(events.calls.lock().unwrap().last().unwrap().2 >= 14.0);
    }

    #[test]
    fn name_change_is_not_persisted_in_event_history() {
        let events = StubEvents::new(Some(cause(true, 2, None)), false);
        let e = after_a_gap(
            events,
            json!({"bssid": OLD, "ap_name": "Old Hallway Name"}),
            json!({"bssid": OLD, "ap_name": "Hallway AP"}),
        );
        assert!(e.detail.contains(&format!("Kicked by AP {OLD}")));
        assert!(!e.detail.contains("Old Hallway Name"));
        assert!(!e.detail.contains("Hallway AP"));
        assert!(!e.detail.contains(" via "));
    }

    #[test]
    fn gap_nobody_claimed_stores_the_network_and_the_bssid() {
        let up = json!({"bssid": OLD, "ssid": "Private Network", "ap_name": "Hallway AP"});
        let e = after_a_gap(StubEvents::new(None, false), up.clone(), up);
        assert_eq!(e.detail, format!("Associated with Private Network, {OLD}"));
        assert!(!e.detail.contains("Hallway AP"));
    }

    #[test]
    fn an_association_with_no_network_name_is_still_the_bssid() {
        let e = after_a_gap(StubEvents::new(None, false), json!({"bssid": OLD}), json!({"bssid": OLD}));
        assert_eq!(e.detail, format!("Associated with {OLD}"));
    }
}

#[test]
fn short_durations_read_like_python() {
    assert_eq!(short_duration(0.2), "1 s");
    // round(2.5) is 2 in Python
    assert_eq!(short_duration(2.5), "2 s");
    assert_eq!(short_duration(59.4), "59 s");
    assert_eq!(short_duration(125.0), "2 min");
    assert_eq!(short_duration(3600.0 * 2.0 + 61.0), "2 h 1 min");
}
