use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

use super::rig::{Rig, content, ctx_f, failed_content};
use crate::daemon::consts::{CHECK_QUIET_MAX_WAIT_S, LOAD_FLOOR_BPS, PEAK_FRESH_S};
use crate::score;
use crate::store::TestRow;
use crate::testutil::obj;

mod speed_through_a_tunnel {
    use super::*;

    fn check(rig: &Rig, ago: f64, mbps: f64, vpn: Option<&str>) {
        let row = TestRow { vpn: vpn.map(str::to_string), ..content(mbps, Some(mbps / 3.0), "home") };
        rig.put_test(rig.now() - ago, "content", row);
    }

    fn four_line_checks(rig: &Rig) {
        for i in 0..4 {
            check(rig, 3600.0 * (i + 1) as f64, 400.0, None);
        }
    }

    #[test]
    fn the_line_is_scored_on_the_line_s_checks() {
        let mut rig = Rig::new();
        four_line_checks(&rig);
        check(&rig, 60.0, 90.0, Some("wg0"));
        let (_, ctx) = rig.d.speed_score(rig.now(), "home").unwrap();
        assert_eq!((ctx_f(&ctx, "last_down"), &ctx["vpn"]), (Some(400.0), &json!(false)));
    }

    #[test]
    fn a_tunnel_with_no_checks_of_its_own_is_unknown_not_the_line() {
        let mut rig = Rig::new();
        four_line_checks(&rig);
        rig.d.vpn = Some(obj(json!({"iface": "wg0"})));
        let (spd, ctx) = rig.d.speed_score(rig.now(), "home").unwrap();
        assert_eq!(spd, None);
        assert_eq!((&ctx["pending"], &ctx["vpn"]), (&json!(true), &json!(true)));
    }

    #[test]
    fn a_tunnel_is_scored_on_its_own_checks() {
        let mut rig = Rig::new();
        four_line_checks(&rig);
        check(&rig, 60.0, 90.0, Some("wg0@AMS"));
        rig.d.vpn = Some(obj(json!({"iface": "wg0"})));
        rig.d.wan_ip = Some(obj(json!({"edge": "AMS"})));
        let (_, ctx) = rig.d.speed_score(rig.now(), "home").unwrap();
        assert_eq!((ctx_f(&ctx, "last_down"), &ctx["vpn"]), (Some(90.0), &json!(true)));
        assert_eq!(rig.d.content_hint("home", Some("wg0@AMS")).unwrap().0, Some(90.0));
        assert_eq!(rig.d.content_hint("home", None).unwrap().0, Some(400.0));
    }
}

mod check_gate_end_to_end {
    use super::*;

    type Calls = Arc<Mutex<Vec<(Option<f64>, Option<f64>)>>>;

    fn rig() -> (Rig, Calls) {
        let calls: Calls = Arc::default();
        let seen = Arc::clone(&calls);
        let started = crate::util::now();
        let mut rig = Rig::with(started, move |h| {
            h.content_test = Arc::new(move |down, up| {
                seen.lock().unwrap().push((down, up));
                crate::speedtest::ContentResult {
                    ok: true,
                    started,
                    down_mbps: Some(300.0),
                    up_mbps: Some(100.0),
                    bytes: 1,
                    ..failed_content(None, None)
                }
            });
        });
        let now = rig.now();
        rig.d.metered = None;
        rig.d.last_content_test = now - 7200.0;
        rig.d.watching_since = now - 3600.0;
        (rig, calls)
    }

    fn run_check(rig: &mut Rig) -> Vec<Map<String, Value>> {
        rig.d.maybe_content_test(rig.now()).unwrap();
        rig.store().tests(5, Some("content")).unwrap()
    }

    #[test]
    fn a_run_records_what_the_gate_saw() {
        let (mut rig, calls) = rig();
        rig.d.busy_at = Some(rig.now() - 100.0);
        let rows = run_check(&mut rig);
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(
            (&rows[0]["quiet_s"], &rows[0]["awake_s"], &rows[0]["asked"]),
            (&json!(100.0), &json!(3600.0), &json!(0))
        );
        assert!(!rig.d.content_running());
    }

    #[test]
    fn busy_waits_and_stores_nothing() {
        let (mut rig, calls) = rig();
        rig.d.busy_at = Some(rig.now() - 2.0);
        assert!(run_check(&mut rig).is_empty());
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(rig.d.quiet_waiting_since, Some(rig.now()));
    }

    #[test]
    fn busy_for_the_whole_wait_is_stored_as_skipped() {
        let (mut rig, calls) = rig();
        rig.d.busy_at = Some(rig.now() - 2.0);
        rig.d.quiet_waiting_since = Some(rig.now() - CHECK_QUIET_MAX_WAIT_S);
        let rows = run_check(&mut rig);
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!((&rows[0]["ok"], &rows[0]["detail"]), (&json!(0), &json!("skipped-busy")));
        assert_eq!(rig.d.last_content_test, rig.now());
        assert_eq!(rig.d.quiet_waiting_since, None);
    }

    #[test]
    fn a_fresh_wake_waits() {
        let (mut rig, calls) = rig();
        rig.d.watching_since = rig.now() - 30.0;
        assert!(run_check(&mut rig).is_empty());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_failed_check_is_retried_once_after_the_retry_delay() {
        let mut rig = Rig::new();
        let now = rig.now();
        rig.d.last_content_test = now - 7200.0;
        rig.d.watching_since = now - 3600.0;
        rig.d.maybe_content_test(now).unwrap();
        rig.d.collect_workers();
        assert_eq!(rig.d.content_boost_at, Some(now + crate::daemon::consts::CONTENT_RETRY_S));
        rig.d.content_boost_at = Some(now);
        rig.d.maybe_content_test(now + 1.0).unwrap();
        rig.d.collect_workers();
        assert_eq!(rig.d.content_boost_at, None);
    }
}

mod speed_trust_end_to_end {
    use super::*;

    const NET: &str = "x3me";

    fn add(rig: &Rig, kind: &str, down: f64, up: f64, ago: f64, network: &str) {
        rig.put_test(rig.now() - ago, kind, content(down, Some(up), network));
    }

    fn checks(rig: &Rig, pairs: &[(f64, f64)]) {
        for &(down, ago) in pairs {
            add(rig, "content", down, 10.0, ago, NET);
        }
    }

    fn score_now(rig: &mut Rig) -> (Option<f64>, Map<String, Value>) {
        rig.d.speed_score(rig.now(), NET).unwrap()
    }

    #[test]
    fn the_arrival_check_alone_is_reported_but_not_counted() {
        let mut rig = Rig::new();
        checks(&rig, &[(63.4, 300.0)]);
        let (spd, ctx) = score_now(&mut rig);
        assert!(spd.is_some());
        assert_eq!((&ctx["samples"], &ctx["scored"]), (&json!(1), &json!(false)));
    }

    #[test]
    fn a_second_check_makes_it_count() {
        let mut rig = Rig::new();
        checks(&rig, &[(63.4, 300.0), (380.0, 60.0)]);
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx["scored"], json!(true));
        assert_eq!(ctx_f(&ctx, "last_down"), Some(380.0));
    }

    #[test]
    fn a_fresh_peak_here_withdraws_a_contradicted_figure() {
        let mut rig = Rig::new();
        checks(&rig, &[(63.4, 900.0), (70.0, 300.0)]);
        add(&rig, "peak", 251.4, 50.0, 120.0, NET);
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx_f(&ctx, "peak_down"), Some(251.4));
        assert_eq!(ctx["scored"], json!(false));
    }

    #[test]
    fn the_context_says_what_the_tooltip_needs() {
        let mut rig = Rig::new();
        checks(&rig, &[(165.3, 600.0), (96.3, 1800.0), (113.8, 3600.0)]);
        add(&rig, "peak", 365.3, 50.0, 120.0, NET);
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx["checks_down"], json!([165.3, 96.3, 113.8]));
        assert_eq!(ctx_f(&ctx, "last_down"), Some(113.8));
        let peak_ts = (rig.now() - 120.0) as i64;
        assert_eq!(ctx["peak_ts"], json!(peak_ts));
        assert_eq!(ctx["peak_until"], json!(peak_ts as f64 + PEAK_FRESH_S));
        assert_eq!(ctx["min_samples"], json!(score::MIN_SPEED_SAMPLES));
        assert_eq!(ctx["scored"], json!(false));
    }

    #[test]
    fn no_fresh_peak_means_no_peak_times() {
        let mut rig = Rig::new();
        checks(&rig, &[(63.4, 900.0), (70.0, 300.0)]);
        let (_, ctx) = score_now(&mut rig);
        assert_eq!((&ctx["peak_ts"], &ctx["peak_until"]), (&Value::Null, &Value::Null));
    }

    #[test]
    fn a_peak_from_another_network_says_nothing_about_this_one() {
        let mut rig = Rig::new();
        checks(&rig, &[(63.4, 900.0), (70.0, 300.0)]);
        add(&rig, "peak", 251.4, 50.0, 120.0, "SomeHotel");
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx["peak_down"], Value::Null);
        assert_eq!(ctx["scored"], json!(true));
    }

    #[test]
    fn a_stale_peak_no_longer_speaks_for_the_line() {
        let mut rig = Rig::new();
        checks(&rig, &[(63.4, 900.0), (70.0, 300.0)]);
        add(&rig, "peak", 251.4, 50.0, PEAK_FRESH_S + 60.0, NET);
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx["peak_down"], Value::Null);
        assert_eq!(ctx["scored"], json!(true));
    }
}

mod content_hint {
    use super::*;

    fn hint(rows: &[(&str, Option<f64>, Option<f64>, bool)], network: &str) -> (Option<f64>, Option<f64>) {
        let rig = Rig::new();
        for (i, &(net, down, up, ok)) in rows.iter().enumerate() {
            let row = TestRow { down_mbps: down, up_mbps: up, ok, network: Some(net.into()), ..TestRow::default() };
            rig.put_test(rig.now() - i as f64, "content", row);
        }
        rig.d.content_hint(network, None).unwrap()
    }

    #[test]
    fn nothing_stored_gives_no_hint() {
        assert_eq!(hint(&[], "home"), (None, None));
    }

    #[test]
    fn only_this_network_counts() {
        let rows = [("cafe", Some(900.0), Some(400.0), true), ("home", Some(90.0), Some(20.0), true)];
        assert_eq!(hint(&rows, "home"), (Some(90.0), Some(20.0)));
    }

    // Sizing off the last reading is a ratchet: a low one shrinks the next transfer, which reads lower again.
    #[test]
    fn the_best_recent_reading_wins_not_the_last() {
        let rows = [
            ("home", Some(40.0), Some(5.0), true),
            ("home", Some(380.0), Some(90.0), true),
            ("home", Some(350.0), Some(88.0), true),
        ];
        assert_eq!(hint(&rows, "home"), (Some(380.0), Some(90.0)));
    }

    #[test]
    fn failed_and_empty_readings_are_skipped() {
        let rows = [
            ("home", Some(900.0), Some(400.0), false),
            ("home", None, None, true),
            ("home", Some(120.0), Some(30.0), true),
        ];
        assert_eq!(hint(&rows, "home"), (Some(120.0), Some(30.0)));
    }

    #[test]
    fn a_direction_with_no_readings_stays_none() {
        assert_eq!(hint(&[("home", Some(120.0), None, true)], "home"), (Some(120.0), None));
    }
}

mod load_floor {
    use super::*;

    fn measured(mbps: Option<f64>) -> Rig {
        let rig = Rig::at(1000.0);
        rig.link(json!({"ssid": "home"}));
        if let Some(mbps) = mbps {
            for i in 0..5 {
                rig.put_test(900.0 - i as f64, "content", content(mbps, None, "home"));
            }
        }
        rig
    }

    #[test]
    fn the_floor_is_a_tenth_of_what_the_line_carries() {
        let mut rig = measured(Some(400.0));
        assert!((rig.d.load_floor_bps(1000.0) - 5_000_000.0).abs() <= 1.0);
    }

    #[test]
    fn a_slow_line_is_not_held_to_a_fast_line_s_bar() {
        let mut rig = measured(Some(10.0));
        let floor = rig.d.load_floor_bps(1000.0);
        assert!(floor < 10.0 * 1e6 / 8.0);
        assert!(floor >= LOAD_FLOOR_BPS);
    }

    #[test]
    fn an_unmeasured_line_falls_back_to_the_floor() {
        assert_eq!(measured(None).d.load_floor_bps(1000.0), LOAD_FLOOR_BPS);
    }

    #[test]
    fn background_chatter_never_reaches_the_floor() {
        let floor = measured(Some(400.0)).d.load_floor_bps(1000.0);
        for chatter in [18_020.0, 42_290.0, 182_094.0] {
            assert!(chatter < floor);
        }
    }

    #[test]
    fn it_is_read_once_a_minute_not_twice_a_second() {
        let mut rig = measured(None);
        assert_eq!(rig.d.load_floor_bps(1000.0), LOAD_FLOOR_BPS);
        for i in 0..5 {
            rig.put_test(950.0 - i as f64, "content", content(400.0, None, "home"));
        }
        for tick in 0..120 {
            assert_eq!(rig.d.load_floor_bps(1000.0 + tick as f64 * 0.5), LOAD_FLOOR_BPS);
        }
        assert!((rig.d.load_floor_bps(1061.0) - 5_000_000.0).abs() <= 1.0);
    }

    #[test]
    fn a_store_that_throws_does_not_stop_the_probes() {
        let mut rig = measured(Some(400.0));
        rig.store().close();
        assert_eq!(rig.d.load_floor_bps(1000.0), LOAD_FLOOR_BPS);
    }
}
