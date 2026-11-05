use serde_json::{Map, Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::rig::{Rig, content, int};
use crate::daemon::consts::CONTENT_SETTLE_AFTER_CHANGE_S;
use crate::daemon::core::AnyProbe;
use crate::daemon::lookup::OutcomeSource;
use crate::probes::{PingProbe, Series, TcpProbe};
use crate::pyjson::text;
use crate::score;
use crate::testutil::obj;

mod vpn_on_the_path {
    use super::*;

    fn vpn() -> Value {
        json!({"iface": "wg0", "type": "wireguard", "scope": "full",
               "via": ["icmp-anchor", "tcp-anchor", "tcp-cf", "tcp-google"], "probed": 4})
    }

    struct Path {
        rig: Rig,
        requests: usize,
    }

    impl Path {
        fn new() -> Path {
            let mut rig = Rig::new();
            rig.d.wan_ip = Some(obj(json!({"ip": "198.51.100.7", "country": "BG", "edge": "SOF"})));
            rig.d.wan_ip_at = 5;
            Path { rig, requests: 0 }
        }

        fn see(&mut self, now: f64, vpn: Value) {
            self.rig.link(json!({"iface": "wlo1", "vpn": vpn}));
            self.rig.d.captive.verdict = "seen".into();
            self.rig.d.follow_path_states(now).unwrap();
            if self.rig.d.captive.verdict == "unknown" {
                self.requests += 1;
            }
        }

        fn rows(&self, kind: &str) -> Vec<Map<String, Value>> {
            let mut rows: Vec<_> = self
                .rig
                .store()
                .events(1e9, 100, Some(1e7))
                .unwrap()
                .into_iter()
                .filter(|e| text(e, "kind") == kind)
                .collect();
            rows.sort_by_key(|e| int(e, "ts"));
            rows
        }
    }

    #[test]
    fn a_vpn_coming_up_opens_a_span_and_changes_whose_words_are_used() {
        let mut p = Path::new();
        p.see(100.0, vpn());
        let rows = p.rows("vpn");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            (int(row, "ts"), int(row, "ended_ts"), text(row, "leg"), text(row, "detail")),
            (Some(100), None, "tunnel", "Measured through a VPN (wg0)")
        );
        assert!(p.rig.d.wan_events.tunnel);
        assert_eq!(p.rig.d.vpn.as_ref().unwrap()["since"], 100);
        assert_eq!(p.rig.d.wan_ip, None);
        assert_eq!(p.requests, 1);
        assert_eq!(p.rig.d.content_boost_at, Some(190.0));
    }

    #[test]
    fn a_steady_vpn_is_one_span() {
        let mut p = Path::new();
        p.see(100.0, vpn());
        p.see(101.0, vpn());
        assert_eq!(p.rows("vpn").len(), 1);
        assert_eq!(p.rig.d.vpn.as_ref().unwrap()["since"], 100);
        assert_eq!(p.requests, 1);
    }

    #[test]
    fn full_becoming_partial_is_a_new_span_not_a_new_address() {
        let mut p = Path::new();
        p.see(100.0, vpn());
        p.rig.d.wan_ip = Some(obj(json!({"ip": "203.0.113.9", "edge": "AMS"})));
        let mut partial = vpn();
        partial["scope"] = json!("partial");
        partial["via"] = json!(["tcp-cf"]);
        p.see(200.0, partial);
        let rows = p.rows("vpn");
        assert_eq!(int(&rows[0], "ended_ts"), Some(200));
        assert_eq!(text(&rows[1], "detail"), "Partly measured through a VPN (wg0)");
        assert!(p.rig.d.wan_ip.is_some());
        assert_eq!(p.requests, 1);
    }

    #[test]
    fn the_vpn_going_away_closes_the_span_and_drops_the_exit_address() {
        let mut p = Path::new();
        p.see(100.0, vpn());
        p.rig.d.wan_ip = Some(obj(json!({"ip": "203.0.113.9", "edge": "AMS"})));
        p.see(300.0, Value::Null);
        let rows = p.rows("vpn");
        assert_eq!(rows.len(), 1);
        assert_eq!(int(&rows[0], "ended_ts"), Some(300));
        assert!(!p.rig.d.wan_events.tunnel);
        assert_eq!(p.rig.d.wan_ip, None);
        assert_eq!(p.requests, 2);
        assert!(p.rig.d.vpn_during(150.0, 155.0));
        assert!(p.rig.d.vpn_during(295.0, 305.0));
        assert!(!p.rig.d.vpn_during(301.0, 306.0));
    }

    #[test]
    fn a_hotspot_is_a_span_too() {
        let mut p = Path::new();
        p.rig.d.metered = Some(obj(json!({"tethered": true, "label": "iPhone"})));
        p.see(100.0, Value::Null);
        p.rig.d.metered = None;
        p.see(400.0, Value::Null);
        let rows = p.rows("tether");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            (int(row, "ts"), int(row, "ended_ts"), text(row, "leg"), text(row, "detail")),
            (Some(100), Some(400), "local", "Measured through a hotspot (iPhone)")
        );
    }

    #[test]
    fn an_unwatched_gap_ends_the_span_where_watching_stopped() {
        let mut p = Path::new();
        p.see(100.0, vpn());
        p.rig.d.lose_sight_of_path_states(150.0).unwrap();
        p.see(900.0, vpn());
        let rows = p.rows("vpn");
        assert_eq!((int(&rows[0], "ended_ts"), int(&rows[1], "ts")), (Some(150), Some(900)));
        assert!(!p.rig.d.vpn_during(151.0, 899.0));
    }

    #[test]
    fn the_stored_identity_names_the_exit_edge_once_known() {
        let mut p = Path::new();
        p.see(100.0, vpn());
        assert_eq!(p.rig.d.vpn_identity().as_deref(), Some("wg0"));
        p.rig.d.wan_ip = Some(obj(json!({"ip": "203.0.113.9", "edge": "AMS"})));
        assert_eq!(p.rig.d.vpn_identity().as_deref(), Some("wg0@AMS"));
        p.see(200.0, Value::Null);
        assert_eq!(p.rig.d.vpn_identity(), None);
    }
}

mod tunnel_state_and_history {
    use super::*;

    #[test]
    fn an_outage_opened_through_a_tunnel_is_tunnel_down() {
        let mut rig = Rig::new();
        rig.d.watch_wan.down_since = Some(990.0);
        rig.d.wan_events.tunnel = true;
        rig.d.wan_events.down(1000.0, false, Some(990.0), false).unwrap();
        assert_eq!(rig.d.connection_state(Some(90)), "tunnel-down");
        let mut plain = Rig::new();
        plain.d.watch_wan.down_since = Some(990.0);
        plain.d.wan_events.down(1000.0, false, Some(990.0), false).unwrap();
        assert_eq!(plain.d.connection_state(Some(90)), "wan-down");
    }

    #[test]
    fn recent_points_carry_their_own_tunnel_flag() {
        let mut rig = Rig::new();
        let now = rig.now();
        rig.d.vpn_spans.push_back((now - 600.0, Some(now - 300.0)));
        let written = rig.d.compose_recent(now);
        let pts = written["points"].as_array().unwrap();
        let flagged: Vec<f64> =
            pts.iter().filter(|p| p.get("vpn").is_some()).map(|p| p["t"].as_f64().unwrap()).collect();
        assert!(!flagged.is_empty());
        assert!(flagged.iter().all(|t| now - 605.0 <= *t && *t < now - 300.0));
        assert!(pts[0].get("vpn").is_none());
    }

    // `loss` pools both legs, so a bucket where only the internet probes ran read as the router down.
    #[test]
    fn each_leg_reports_loss_over_its_own_sends() {
        let now = 2_000_000.0;
        let mut rig = Rig::at(now);
        let total = rig.single_instrument();
        rig.d.local.add(now - 1800.0 + 5.5, Some(2.0), false);
        rig.d.local.add(now - 1800.0 + 6.5, None, false);
        total.add(now - 1800.0 + 0.5, Some(8.0), false);
        total.add(now - 1800.0 + 5.2, Some(8.0), false);
        rig.d.flush_recent(now).unwrap();
        let written: Value = serde_json::from_slice(&std::fs::read(rig.d.recent_path()).unwrap()).unwrap();
        let pts = written["points"].as_array().unwrap();
        let (first, second, third) = (&pts[0], &pts[1], &pts[2]);
        assert_eq!((&first["local"], &first["loss"]), (&Value::Null, &json!(0.0)));
        assert_eq!(first["local_loss"], Value::Null);
        assert_eq!(first["total_loss"], json!(0.0));
        assert_eq!((&second["local_loss"], &second["total_loss"]), (&json!(0.5), &json!(0.0)));
        assert_eq!(
            (&third["local_loss"], &third["total_loss"], &third["loss"]),
            (&Value::Null, &Value::Null, &Value::Null)
        );
        assert!(third.as_object().unwrap().contains_key("local_loss"));
        assert_eq!(written["bucket_s"], json!(5.0));
        assert_eq!(pts.len(), 360);
    }

    #[test]
    fn an_unwatched_gap_closes_the_vpn_span_where_watching_stopped() {
        let mut rig = Rig::at(1000.0);
        rig.link(json!({"vpn": {"iface": "wg0", "scope": "full"}}));
        rig.d.follow_path_states(1000.0).unwrap();
        rig.d.watch_outages(1000.0, Some(0.0)).unwrap();
        rig.set_clock(40000.0);
        rig.d.watch_outages(40000.0, Some(39000.0)).unwrap();
        let rows: Vec<_> =
            rig.store().events(1e9, 100, Some(1e6)).unwrap().into_iter().filter(|e| text(e, "kind") == "vpn").collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(int(&rows[0], "ended_ts"), Some(1000));
    }
}

mod names_failing {
    use super::*;

    #[derive(Default)]
    struct Lookups(Mutex<VecDeque<(f64, bool)>>);

    impl OutcomeSource for Lookups {
        fn outcomes(&self) -> Vec<(f64, bool)> {
            self.0.lock().unwrap().iter().copied().collect()
        }
    }

    fn feed(rig: &mut Rig, lk: &Arc<Lookups>, t: f64, ok: bool) {
        lk.0.lock().unwrap().push_back((t, ok));
        let src: Arc<dyn OutcomeSource> = lk.clone();
        rig.d.lookup_watch.feed(t, &[src], true, false).unwrap();
    }

    #[test]
    fn the_state_says_so_below_an_outage_and_the_index_stands() {
        let mut rig = Rig::new();
        let lk = Arc::new(Lookups::default());
        feed(&mut rig, &lk, 100.0, true);
        for t in [110.0, 115.0, 120.0] {
            feed(&mut rig, &lk, t, false);
        }
        assert_eq!(rig.d.connection_state(Some(95)), "dns-failing");
        assert_eq!(rig.d.connection_state(Some(40)), "dns-failing");
        assert!(score::scored_now("dns-failing"));
        rig.d.watch_wan.down_since = Some(990.0);
        rig.d.wan_events.down(1000.0, false, Some(990.0), false).unwrap();
        assert_eq!(rig.d.connection_state(Some(95)), "wan-down");
    }

    #[test]
    fn the_daemon_feeds_it_from_the_named_instruments_only() {
        let mut rig = Rig::new();
        let series = || Arc::new(Series::default());
        let named = Arc::new(TcpProbe::new("probe.example", series(), 1.0, "tcp-cf", None, 443));
        let literal = Arc::new(TcpProbe::new("192.0.2.1", series(), 1.0, "tcp-anchor", None, 443));
        let ping = Arc::new(PingProbe::new("192.0.2.1", series(), 500.0, "", None));
        rig.d.set_instrument_probes(vec![
            ("tcp-cf".into(), AnyProbe::Tcp(Arc::clone(&named))),
            ("tcp-anchor".into(), AnyProbe::Tcp(literal)),
            ("icmp-anchor".into(), AnyProbe::Ping(ping)),
        ]);
        let seen = rig.d.named_lookups();
        assert_eq!(seen.len(), 1);
        assert!(Arc::ptr_eq(&seen[0], &named.lookup));
        rig.d.follow_lookups(100.0).unwrap();
        assert!(!rig.d.lookup_watch.failing());
    }
}

mod public_address {
    use super::*;

    #[test]
    fn daemon_adopts_the_address_from_the_proof_once() {
        let mut rig = Rig::new();
        rig.d.captive.proof = Some(json!({"ip": "203.0.113.9", "family": "v4"}));
        rig.d.captive.checked_ts = Some(1234);
        rig.d.adopt_wan_ip();
        assert_eq!(rig.d.wan_ip, Some(obj(json!({"ip": "203.0.113.9", "family": "v4", "checked_ts": 1234}))));
        rig.d.captive.proof = None;
        rig.d.adopt_wan_ip();
        assert_eq!(rig.d.wan_ip.as_ref().unwrap()["ip"], "203.0.113.9");
        assert_eq!(rig.d.content_boost_at, None);
    }

    fn holding_an_address() -> Rig {
        let mut rig = Rig::new();
        rig.d.wan_ip = Some(obj(json!({"ip": "203.0.113.9", "family": "v4", "checked_ts": 10})));
        rig.d.wan_ip_at = 10;
        rig.d.content_boost_at = None;
        rig
    }

    fn adopt(rig: &mut Rig, ip: &str, checked: i64) {
        rig.d.captive.proof = Some(json!({"ip": ip, "family": "v4"}));
        rig.d.captive.checked_ts = Some(checked);
        rig.d.adopt_wan_ip();
    }

    #[test]
    fn a_different_address_books_one() {
        let mut rig = holding_an_address();
        adopt(&mut rig, "198.51.100.7", 20);
        assert_eq!(rig.d.content_boost_at, Some(rig.now() + CONTENT_SETTLE_AFTER_CHANGE_S));
    }

    #[test]
    fn the_same_address_books_nothing() {
        let mut rig = holding_an_address();
        adopt(&mut rig, "203.0.113.9", 20);
        assert_eq!(rig.d.content_boost_at, None);
    }

    #[test]
    fn the_baseline_is_left_alone() {
        let mut rig = holding_an_address();
        let now = rig.now();
        for h in 0..8 {
            rig.put_test(now - h as f64 * 3600.0, "content", content(300.0, Some(50.0), "home"));
        }
        adopt(&mut rig, "198.51.100.7", 20);
        assert_eq!(rig.store().tests(20, Some("content")).unwrap().len(), 8);
        assert!(rig.store().baseline_speed(30, "home", 5, Some(now), true, None).unwrap().is_some());
    }
}
