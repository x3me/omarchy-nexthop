use serde_json::{Map, Value, json};

use super::rig::{Rig, content, ctx_f};
use crate::daemon::consts::{BAND_CHECK_MIN_GAP_S, CONTENT_SETTLE_AFTER_CHANGE_S};
use crate::store::TestRow;

mod speed_scoring {
    use super::*;

    fn put(rig: &Rig, ago: f64, down: f64, up: f64, network: &str) {
        rig.put_test(rig.now() - ago, "content", content(down, Some(up), network));
    }

    #[test]
    fn other_networks_checks_do_not_score_here() {
        let mut rig = Rig::new();
        put(&rig, 600.0, 300.0, 100.0, "OfficeA");
        let (spd, ctx) = rig.d.speed_score(rig.now(), "OfficeB").unwrap();
        assert_eq!(spd, None);
        assert_eq!(ctx["pending"], json!(true));
    }

    #[test]
    fn median_shrugs_off_one_bad_check() {
        let mut rig = Rig::new();
        put(&rig, 7200.0, 220.0, 90.0, "OfficeA");
        put(&rig, 3600.0, 240.0, 95.0, "OfficeA");
        put(&rig, 600.0, 18.0, 5.0, "OfficeA");
        let (spd, ctx) = rig.d.speed_score(rig.now(), "OfficeA").unwrap();
        assert_eq!(ctx_f(&ctx, "last_down"), Some(220.0));
        assert!(spd.unwrap() > 85.0);
    }

    #[test]
    fn no_cross_network_penalty() {
        let mut rig = Rig::new();
        for i in 0..6 {
            put(&rig, 3600.0 * (i + 2) as f64, 300.0, 100.0, "FastOffice");
        }
        put(&rig, 600.0, 30.0, 10.0, "SlowCafe");
        let (spd, ctx) = rig.d.speed_score(rig.now(), "SlowCafe").unwrap();
        assert_eq!(ctx["baseline_down"], Value::Null);
        assert!(spd.unwrap() > 50.0);
    }
}

mod speed_from_the_link_now {
    use super::*;

    fn rig() -> Rig {
        let rig = Rig::new();
        rig.link(json!({"band": "5 GHz"}));
        rig
    }

    fn put(rig: &Rig, ago: f64, mbps: f64, band: Option<&str>) {
        let row = TestRow { band: band.map(str::to_string), ..content(mbps, Some(mbps / 3.0), "home") };
        rig.put_test(rig.now() - ago, "content", row);
    }

    fn score_now(rig: &mut Rig) -> (Option<f64>, Map<String, Value>) {
        rig.d.speed_score(rig.now(), "home").unwrap()
    }

    #[test]
    fn an_evening_check_does_not_describe_the_morning() {
        let mut rig = rig();
        put(&rig, 4.0 * 3600.0, 30.0, Some("5 GHz"));
        put(&rig, 3.0 * 3600.0 + 60.0, 40.0, Some("5 GHz"));
        let (spd, ctx) = score_now(&mut rig);
        assert_eq!(spd, None);
        assert_eq!(ctx["stale"], json!("age"));
        assert_eq!(ctx["stale_ts"], json!((rig.now() - 3.0 * 3600.0 - 60.0) as i64));
        assert_eq!(ctx["last_down"], Value::Null);
    }

    #[test]
    fn old_checks_leave_the_median() {
        let mut rig = rig();
        put(&rig, 5.0 * 3600.0, 20.0, Some("5 GHz"));
        put(&rig, 2.0 * 3600.0, 300.0, Some("5 GHz"));
        put(&rig, 600.0, 320.0, Some("5 GHz"));
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx["checks_down"], json!([320.0, 300.0]));
        assert_eq!(ctx["scored"], json!(true));
    }

    #[test]
    fn one_recent_check_is_shown_and_cannot_score() {
        let mut rig = rig();
        put(&rig, 5.0 * 3600.0, 300.0, Some("5 GHz"));
        put(&rig, 600.0, 310.0, Some("5 GHz"));
        let (spd, ctx) = score_now(&mut rig);
        assert!(spd.is_some());
        assert_eq!((&ctx["samples"], &ctx["scored"]), (&json!(1), &json!(false)));
    }

    #[test]
    fn checks_from_before_a_band_change_are_retired() {
        let mut rig = rig();
        put(&rig, 1800.0, 40.0, Some("2.4 GHz"));
        put(&rig, 1200.0, 45.0, Some("2.4 GHz"));
        let (spd, ctx) = score_now(&mut rig);
        assert_eq!(spd, None);
        assert_eq!((&ctx["stale"], &ctx["band"]), (&json!("band"), &json!("5 GHz")));
        put(&rig, 2400.0, 300.0, Some("5 GHz"));
        assert_eq!(score_now(&mut rig).0, None);
        put(&rig, 300.0, 310.0, Some("5 GHz"));
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx["checks_down"], json!([310.0]));
    }

    #[test]
    fn rows_stored_before_bands_were_recorded_are_not_cut_on_band() {
        let mut rig = rig();
        put(&rig, 1200.0, 300.0, None);
        put(&rig, 600.0, 310.0, None);
        assert_eq!(score_now(&mut rig).1["samples"], json!(2));
    }

    #[test]
    fn wired_has_no_band_to_cut_on() {
        let mut rig = rig();
        rig.link(json!({}));
        put(&rig, 1200.0, 300.0, Some("2.4 GHz"));
        put(&rig, 600.0, 310.0, Some("2.4 GHz"));
        assert_eq!(score_now(&mut rig).1["samples"], json!(2));
    }

    #[test]
    fn the_30_day_baseline_is_not_cut() {
        let mut rig = rig();
        for i in 0..6 {
            put(&rig, 86400.0 * (i + 1) as f64, 400.0, Some("5 GHz"));
        }
        put(&rig, 600.0, 380.0, Some("5 GHz"));
        put(&rig, 300.0, 390.0, Some("5 GHz"));
        let (_, ctx) = score_now(&mut rig);
        assert_eq!(ctx_f(&ctx, "baseline_down"), Some(400.0));
    }
}

mod band_change_schedules_a_check {
    use super::*;

    #[test]
    fn a_band_change_on_the_same_network_checks_again_soon() {
        let mut rig = Rig::new();
        rig.d.follow_band(100.0, "home", Some("2.4 GHz"));
        assert_eq!(rig.d.content_boost_at, None);
        rig.d.follow_band(200.0, "home", Some("5 GHz"));
        assert_eq!(rig.d.content_boost_at, Some(200.0 + CONTENT_SETTLE_AFTER_CHANGE_S));
    }

    #[test]
    fn at_most_once_per_gap() {
        let mut rig = Rig::new();
        rig.d.follow_band(0.0, "home", Some("2.4 GHz"));
        rig.d.follow_band(10.0, "home", Some("5 GHz"));
        rig.d.content_boost_at = None;
        rig.d.follow_band(20.0, "home", Some("2.4 GHz"));
        assert_eq!(rig.d.content_boost_at, None);
        rig.d.follow_band(10.0 + BAND_CHECK_MIN_GAP_S, "home", Some("5 GHz"));
        assert!(rig.d.content_boost_at.is_some());
    }

    #[test]
    fn a_new_network_is_not_a_band_change() {
        let mut rig = Rig::new();
        rig.d.follow_band(0.0, "home", Some("2.4 GHz"));
        rig.d.follow_band(10.0, "cafe", Some("5 GHz"));
        assert_eq!(rig.d.content_boost_at, None);
        rig.d.follow_band(20.0, "cafe", Some("5 GHz"));
        assert_eq!(rig.d.content_boost_at, None);
    }
}
