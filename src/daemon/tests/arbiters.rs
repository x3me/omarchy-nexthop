use super::support::{MemStore, count, quiet, recorder};
use crate::daemon::arbiters::{IntervalEvent, LocalEventArbiter, WanEventArbiter};
use crate::daemon::consts::{NOTIFY_AFTER_S, OUTAGE_AFTER_S};

const T: f64 = 1_000_000.0;

mod wan_arbitration {
    use super::*;

    #[test]
    fn quiet_when_another_instrument_still_answers() {
        let store = MemStore::new();
        let (notify, notices) = recorder();
        let mut arb = WanEventArbiter::new(store.clone(), notify);
        arb.down(T, true, None, false).unwrap();
        assert!(!arb.real_outage());
        assert_eq!(count(&notices), 0);
        arb.up(T + 30.0).unwrap();
        let evs = store.events();
        assert_eq!(store.kinds(), ["icmp-quiet"]);
        assert!(evs[0].ended_ts.is_some());
        assert_eq!(count(&notices), 0);
    }

    #[test]
    fn outage_when_every_instrument_fails() {
        let store = MemStore::new();
        let (notify, notices) = recorder();
        let mut arb = WanEventArbiter::new(store.clone(), notify);
        arb.down(T, false, None, false).unwrap();
        assert!(arb.real_outage());
        assert_eq!(count(&notices), 0);
        arb.tick(T + NOTIFY_AFTER_S + 0.1, false, None).unwrap();
        assert_eq!(count(&notices), 1);
        arb.up(T + 30.0).unwrap();
        assert_eq!(store.kinds(), ["outage"]);
        assert_eq!(count(&notices), 2);
    }

    #[test]
    fn a_brief_outage_is_logged_and_never_alarms() {
        let store = MemStore::new();
        let (notify, notices) = recorder();
        let mut arb = WanEventArbiter::new(store.clone(), notify);
        arb.down(T, false, None, false).unwrap();
        arb.tick(T + 1.0, false, None).unwrap();
        arb.up(T + 2.0).unwrap();
        assert_eq!(count(&notices), 0);
        assert_eq!(store.kinds(), ["outage"]);
    }

    #[test]
    fn the_alarm_fires_once_not_every_tick() {
        let (notify, notices) = recorder();
        let mut arb = WanEventArbiter::new(MemStore::new(), notify);
        arb.down(T, false, None, false).unwrap();
        for i in 0..10 {
            arb.tick(T + NOTIFY_AFTER_S + i as f64, false, None).unwrap();
        }
        assert_eq!(count(&notices), 1);
    }

    #[test]
    fn escalates_when_the_rest_stop_too() {
        let store = MemStore::new();
        let (notify, notices) = recorder();
        let mut arb = WanEventArbiter::new(store.clone(), notify);
        arb.down(T, true, None, false).unwrap();
        arb.tick(T + 2.0, true, None).unwrap();
        assert_eq!(count(&notices), 0);
        arb.tick(T + 5.0, false, None).unwrap();
        assert!(arb.real_outage());
        assert_eq!(count(&notices), 0);
        arb.tick(T + 5.0 + NOTIFY_AFTER_S + 0.1, false, None).unwrap();
        assert_eq!(count(&notices), 1);
        arb.up(T + 60.0).unwrap();
        let mut kinds = store.kinds();
        kinds.sort();
        assert_eq!(kinds, ["icmp-quiet", "outage"]);
        assert!(store.events().iter().all(|e| e.ended_ts.is_some()));
    }

    #[test]
    fn quiet_never_charges_reliability() {
        // outage_stats charges only outage and disruption rows.
        let store = MemStore::new();
        let mut arb = WanEventArbiter::new(store.clone(), quiet());
        arb.down(T, true, None, false).unwrap();
        arb.up(T + 600.0).unwrap();
        assert!(store.events().iter().all(|e| e.kind != "outage" && e.kind != "disruption"));
    }
}

mod local_arbitration {
    use super::*;

    #[test]
    fn silent_gateway_with_traffic_crossing_it_is_not_an_outage() {
        let store = MemStore::new();
        let (notify, notices) = recorder();
        let mut arb = LocalEventArbiter::new(store.clone(), notify);
        arb.down(100.0, true, None, false).unwrap();
        assert_eq!(arb.kind, Some("gateway-quiet"));
        assert!(!arb.real_outage());
        let (kind, sev, leg, _) = store.opened()[0].clone();
        assert_eq!((kind.as_str(), sev.as_str(), leg.as_str()), ("gateway-quiet", "warn", "local"));
        assert_eq!(count(&notices), 0);
    }

    #[test]
    fn nothing_answering_anywhere_is_a_real_outage() {
        let store = MemStore::new();
        let (notify, notices) = recorder();
        let mut arb = LocalEventArbiter::new(store.clone(), notify);
        arb.down(100.0, false, None, false).unwrap();
        assert_eq!(arb.kind, Some("outage"));
        assert!(arb.real_outage());
        let (kind, sev, leg, _) = store.opened()[0].clone();
        assert_eq!((kind.as_str(), sev.as_str(), leg.as_str()), ("outage", "critical", "local"));
        assert_eq!(count(&notices), 0);
        arb.tick(100.0 + NOTIFY_AFTER_S + 0.1, false, None).unwrap();
        assert_eq!(count(&notices), 1);
    }

    #[test]
    fn the_verdict_follows_the_evidence_both_ways() {
        let (notify, notices) = recorder();
        let mut arb = LocalEventArbiter::new(MemStore::new(), notify);
        arb.down(100.0, true, None, false).unwrap();
        arb.tick(110.0, false, None).unwrap();
        assert!(arb.real_outage());
        assert_eq!(count(&notices), 0);
        arb.tick(110.0 + NOTIFY_AFTER_S + 0.1, false, None).unwrap();
        assert_eq!(count(&notices), 1);
        arb.tick(140.0, true, None).unwrap();
        assert!(!arb.real_outage());
        assert_eq!(arb.kind, Some("gateway-quiet"));
        assert_eq!(count(&notices), 2);
        arb.tick(150.0, false, None).unwrap();
        assert!(arb.real_outage());
        arb.tick(150.0 + NOTIFY_AFTER_S + 0.1, false, None).unwrap();
        assert_eq!(count(&notices), 3);
    }

    #[test]
    fn a_walk_back_before_the_alarm_sends_nothing() {
        let (notify, notices) = recorder();
        let mut arb = LocalEventArbiter::new(MemStore::new(), notify);
        arb.down(100.0, false, None, false).unwrap();
        arb.tick(102.0, true, None).unwrap();
        assert_eq!(arb.kind, Some("gateway-quiet"));
        assert_eq!(count(&notices), 0);
    }

    #[test]
    fn recovery_only_notifies_for_a_real_outage() {
        let (notify, notices) = recorder();
        let mut arb = LocalEventArbiter::new(MemStore::new(), notify);
        arb.down(100.0, true, None, false).unwrap();
        arb.up(130.0).unwrap();
        assert_eq!(count(&notices), 0);
        assert_eq!(arb.kind, None);
        arb.down(200.0, false, None, false).unwrap();
        arb.tick(200.0 + NOTIFY_AFTER_S + 0.1, false, None).unwrap();
        arb.up(230.0).unwrap();
        assert_eq!(count(&notices), 2);
    }
}

#[test]
fn outage_rows_start_when_the_silence_began() {
    let store = MemStore::new();
    WanEventArbiter::new(store.clone(), quiet()).down(T, false, Some(T - OUTAGE_AFTER_S), false).unwrap();
    LocalEventArbiter::new(store.clone(), quiet()).down(T, true, Some(T - OUTAGE_AFTER_S), false).unwrap();
    let ts = |kind: &str| store.events().into_iter().find(|e| e.kind == kind).unwrap().ts;
    assert_eq!(ts("outage"), (T - OUTAGE_AFTER_S) as i64);
    assert_eq!(ts("gateway-quiet"), (T - OUTAGE_AFTER_S) as i64);
}

#[test]
fn an_arbiter_that_loses_sight_drops_its_pending_alarm() {
    let store = MemStore::new();
    let (notify, notices) = recorder();
    let mut arb = WanEventArbiter::new(store.clone(), notify);
    arb.down(100.0, false, Some(96.0), false).unwrap();
    arb.lost_sight(101.0).unwrap();
    arb.tick(100.0 + NOTIFY_AFTER_S + 60.0, false, None).unwrap();
    assert_eq!(count(&notices), 0);
    assert_eq!(arb.event_id, None);
    assert_eq!(store.events()[0].ended_ts, Some(101));
}

#[test]
fn a_tunnel_keeps_its_own_words_after_the_router_returns() {
    let mut arb = WanEventArbiter::new(MemStore::new(), quiet());
    arb.tunnel = true;
    let words = arb.words(true);
    assert_eq!((words.leg, words.outage_detail), (WanEventArbiter::TUNNEL_LEG, WanEventArbiter::TUNNEL_OUTAGE_DETAIL));
    arb.tunnel = false;
    assert_eq!(arb.words(true).outage_detail, WanEventArbiter::NOT_BACK_DETAIL);
}

#[test]
fn the_events_tab_matches_the_stored_words() {
    let qml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/EventsTab.qml")).unwrap();
    assert!(qml.contains(&format!("\"{}\"", WanEventArbiter::NOT_BACK_DETAIL)));
}

mod tunnel_outage_words {
    use super::*;

    #[test]
    fn an_outage_through_a_tunnel_is_the_tunnel_s() {
        let store = MemStore::new();
        let (notify, notices) = recorder();
        let mut arb = WanEventArbiter::new(store.clone(), notify);
        arb.tunnel = true;
        arb.down(1000.0, false, Some(996.0), false).unwrap();
        arb.tick(1000.0 + NOTIFY_AFTER_S + 1.0, false, None).unwrap();
        let row = &store.events()[0];
        assert_eq!((row.leg.as_str(), row.detail.as_str()), ("tunnel", "VPN tunnel silent; the router answered"));
        assert_eq!(arb.leg(), "tunnel");
        let first = notices.lock().unwrap()[0].clone();
        assert_eq!(first.0, "No connection through the VPN");
        assert!(!format!("{} {}", first.0, first.1).contains("ISP"));
    }

    #[test]
    fn the_words_are_fixed_when_the_outage_opens() {
        let (notify, notices) = recorder();
        let mut arb = WanEventArbiter::new(MemStore::new(), notify);
        arb.tunnel = true;
        arb.down(1000.0, false, None, false).unwrap();
        arb.tick(1000.0 + NOTIFY_AFTER_S + 1.0, false, None).unwrap();
        arb.tunnel = false;
        arb.up(1100.0).unwrap();
        assert_eq!(notices.lock().unwrap().last().unwrap().0, "VPN connection recovered");
    }

    #[test]
    fn without_a_tunnel_nothing_changes() {
        let store = MemStore::new();
        let mut arb = WanEventArbiter::new(store.clone(), quiet());
        arb.down(1000.0, false, None, false).unwrap();
        let row = &store.events()[0];
        assert_eq!((row.leg.as_str(), row.detail.as_str()), ("wan", "router answers, nothing past it does"));
    }
}

#[test]
fn an_escalation_is_dated_where_the_silence_began_never_before_the_quiet_row() {
    let store = MemStore::new();
    let mut arb = LocalEventArbiter::new(store.clone(), quiet());
    arb.down(100.0, true, None, false).unwrap();
    arb.tick(110.0, false, Some(105.5)).unwrap();
    arb.up(120.0).unwrap();
    arb.down(200.0, true, None, false).unwrap();
    arb.tick(210.0, false, Some(150.0)).unwrap();
    let rows = store.events();
    let quiet_rows: Vec<_> = rows.iter().filter(|e| e.kind == "gateway-quiet").map(|e| (e.ts, e.ended_ts)).collect();
    let outages: Vec<_> = rows.iter().filter(|e| e.kind == "outage").map(|e| e.ts).collect();
    assert_eq!(quiet_rows, [(200, Some(200)), (100, Some(105))]);
    assert_eq!(outages, [200, 105]);
}

#[test]
fn an_interval_event_is_one_row_per_description() {
    let store = MemStore::new();
    let mut span = IntervalEvent::new(store.clone(), "vpn", "info", "tunnel");
    assert!(span.update(100.0, Some("Measured through a VPN (wg0)")).unwrap());
    assert!(!span.update(101.0, Some("Measured through a VPN (wg0)")).unwrap());
    assert!(span.update(200.0, Some("Partly measured through a VPN (wg0)")).unwrap());
    span.lost_sight(250.0).unwrap();
    assert!(span.update(900.0, Some("Partly measured through a VPN (wg0)")).unwrap());
    assert!(span.update(950.0, None).unwrap());
    let rows: Vec<_> = store.events().into_iter().map(|e| (e.ts, e.ended_ts)).collect();
    assert_eq!(rows, [(900, Some(950)), (200, Some(250)), (100, Some(200))]);
}
