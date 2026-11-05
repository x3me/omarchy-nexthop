use super::*;
use serde_json::json;

struct Unwatched {
    _dir: TempDir,
    store: Store,
    now: f64,
    day: f64,
}

impl Unwatched {
    fn new() -> Self {
        let dir = TempDir::new();
        let store = open(&dir);
        Unwatched { _dir: dir, store, now: 2_000_040.0, day: 86_400.0 }
    }

    fn base(&self) -> f64 {
        (self.now / 60.0).floor() * 60.0
    }

    fn minutes(&self, first: i64, last: i64) {
        let rel = obj(json!({"rel": 100.0}));
        for ago in (first..=last).step_by(60) {
            self.store.put_minute(self.base() as i64 - ago, &rel, "", "", "").unwrap();
        }
    }

    fn gaps(&self, seconds: f64) -> Vec<(f64, f64)> {
        self.store.unwatched(seconds, Some(self.now)).unwrap()
    }
}

#[test]
fn a_daemon_watching_all_day_has_no_gaps() {
    let u = Unwatched::new();
    u.minutes(0, 86_400);
    assert_eq!(u.gaps(u.day), vec![]);
}

#[test]
fn a_skipped_bucket_is_drift_not_a_gap() {
    let u = Unwatched::new();
    u.minutes(0, 3660);
    u.store.with_db(|db| db.execute("DELETE FROM minute WHERE ts = ?", [u.base() as i64 - 1200])).unwrap();
    assert_eq!(u.gaps(3600.0), vec![]);
}

#[test]
fn a_night_asleep_is_one_gap_bounded_by_the_rows_either_side() {
    let u = Unwatched::new();
    u.minutes(0, 7 * 3600);
    u.minutes(17 * 3600, 86_400);
    let gaps = u.gaps(u.day);
    assert_eq!(gaps, vec![(u.base() - 17.0 * 3600.0 + 60.0, u.base() - 7.0 * 3600.0)]);
}

#[test]
fn before_the_first_row_is_unwatched() {
    let u = Unwatched::new();
    u.minutes(0, 2 * 3600);
    let gaps = u.gaps(u.day);
    assert_eq!(gaps, vec![(u.now - u.day, u.base() - 2.0 * 3600.0)]);
}

#[test]
fn just_after_waking_the_sleep_is_already_a_gap() {
    let u = Unwatched::new();
    u.minutes(3 * 3600, 86_400);
    assert_eq!(u.gaps(u.day).last().unwrap().1, u.now);
}

#[test]
fn no_rows_at_all_is_the_whole_window() {
    let u = Unwatched::new();
    assert_eq!(u.gaps(3600.0), vec![(u.now - 3600.0, u.now)]);
}

#[test]
fn an_old_suspend_outage_is_charged_only_where_it_was_watched() {
    let u = Unwatched::new();
    let base = u.base() as i64;
    u.minutes(0, 7 * 3600);
    u.minutes(17 * 3600 + 60, 86_400);
    let eid = u
        .store
        .open_event(base - 17 * 3600, "outage", "critical", "wan", "router answers, nothing past it does")
        .unwrap();
    u.store.close_event(eid, base - 7 * 3600 + 30, None).unwrap();
    let (naive, _, _) = u.store.outage_stats(u.day, Some(u.now), &[]).unwrap();
    let gaps = u.gaps(u.day);
    let (frac, _, _) = u.store.outage_stats(u.day, Some(u.now), &gaps).unwrap();
    let watched = u.day - gaps.iter().map(|(a, b)| b - a).sum::<f64>();
    assert!((naive - 10.0 * 3600.0 / u.day).abs() <= 0.01);
    assert!(frac * watched <= 3.0 * 60.0);
    assert!(frac < 0.01);
}

#[test]
fn a_disruption_wholly_unwatched_is_not_counted() {
    let u = Unwatched::new();
    u.minutes(0, 3600);
    let start = (u.now - 3.0 * 3600.0) as i64;
    let eid = u.store.open_event(start, "disruption", "warn", "wan", "t").unwrap();
    u.store.close_event(eid, start + 20, None).unwrap();
    let gaps = u.gaps(u.day);
    let (_, count, disrupted) = u.store.outage_stats(u.day, Some(u.now), &gaps).unwrap();
    assert_eq!((count, disrupted), (0, 0.0));
}

#[test]
fn a_watched_outage_is_a_share_of_the_watched_time() {
    let u = Unwatched::new();
    let base = u.base() as i64;
    u.minutes(0, 6 * 3600);
    let eid = u.store.open_event(base - 3600, "outage", "critical", "wan", "t").unwrap();
    u.store.close_event(eid, base - 1800, None).unwrap();
    let gaps = u.gaps(u.day);
    let watched = u.day - gaps.iter().map(|(a, b)| b - a).sum::<f64>();
    let (frac, _, _) = u.store.outage_stats(u.day, Some(u.now), &gaps).unwrap();
    assert!((frac * watched - 1800.0).abs() <= 1.0);
    assert!((watched - (6.0 * 3600.0 + 60.0)).abs() <= 60.0);
}

#[test]
fn identity_matching() {
    assert!(vpn_matches(None, None));
    assert!(vpn_matches(Some(""), None));
    assert!(!vpn_matches(Some("wg0"), None));
    assert!(!vpn_matches(None, Some("wg0")));
    assert!(vpn_matches(Some("wg0@AMS"), Some("wg0@AMS")));
    assert!(!vpn_matches(Some("wg0@AMS"), Some("wg0@FRA")));
    assert!(!vpn_matches(Some("wg0@AMS"), Some("tun0@AMS")));
    assert!(vpn_matches(Some("wg0"), Some("wg0@AMS")));
    assert!(vpn_matches(Some("wg0@AMS"), Some("wg0")));
}

const TUNNEL_NOW: i64 = 3_000_000;

fn checks(store: &Store, network: &str, vpn: Option<&str>, values: &[f64]) {
    for (i, v) in values.iter().enumerate() {
        let ts = TUNNEL_NOW - 3600 * (i as i64 + 1) - if vpn.is_none() { 0 } else { 30 };
        store.put_test(ts, "content", "cloudflare", &content(*v, network, vpn)).unwrap();
    }
}

#[test]
fn the_speed_baseline_is_kept_per_tunnel() {
    let dir = TempDir::new();
    let store = open(&dir);
    let now = Some(TUNNEL_NOW as f64);
    checks(&store, "home", None, &[400.0, 410.0, 420.0, 390.0, 405.0]);
    checks(&store, "home", Some("wg0@AMS"), &[90.0, 95.0, 100.0, 85.0, 92.0]);
    let line = store.baseline_speed(30, "home", 5, now, false, None).unwrap().unwrap();
    let tunnel = store.baseline_speed(30, "home", 5, now, false, Some("wg0@AMS")).unwrap().unwrap();
    assert!(line >= 400.0);
    assert!(tunnel <= 100.0);
    assert_eq!(store.baseline_speed(30, "home", 5, now, false, Some("tun0")).unwrap(), None);
}

#[test]
fn tests_carry_the_tunnel() {
    let dir = TempDir::new();
    let store = open(&dir);
    checks(&store, "home", Some("wg0"), &[100.0]);
    assert_eq!(store.tests(1, None).unwrap()[0]["vpn"], json!("wg0"));
    checks(&store, "home", None, &[400.0]);
    assert_eq!(store.tests(1, None).unwrap()[0]["vpn"], Value::Null);
}

fn tunnel_minutes(store: &Store, vpn: Option<&str>, medians: &[f64], start_ago: i64) {
    let base = TUNNEL_NOW / 60 * 60;
    for (i, v) in medians.iter().enumerate() {
        let row = json!({"wan_p50": v, "vpn": vpn});
        store.put_minute(base - start_ago + 60 * i as i64, &obj(row), "", "", "").unwrap();
    }
}

#[test]
fn a_tunnel_s_usual_level_reads_only_its_own_minutes() {
    let dir = TempDir::new();
    let store = open(&dir);
    let now = Some(TUNNEL_NOW as f64);
    tunnel_minutes(&store, None, &[6.0; 40], 7200);
    let mut wg = vec![150.0; 30];
    wg.extend([160.0; 10]);
    tunnel_minutes(&store, Some("wg0@AMS"), &wg, 3000);
    tunnel_minutes(&store, Some("tun0"), &[40.0; 40], 12000);
    assert_eq!(store.tunnel_level("wg0@AMS", 86400.0, now).unwrap(), (Some(150.0), Some(160.0), 40));
    assert_eq!(store.tunnel_level("ppp0", 86400.0, now).unwrap(), (None, None, 0));
}

#[test]
fn an_hour_row_says_whether_a_tunnel_carried_it() {
    let dir = TempDir::new();
    let store = open(&dir);
    let base = TUNNEL_NOW / 3600 * 3600 - 3 * 3600;
    for m in 0..60 {
        store.put_minute(base + 60 * m, &obj(json!({"wan_p50": 150.0, "vpn": "wg0"})), "", "", "").unwrap();
        store.put_minute(base + 3600 + 60 * m, &obj(json!({"wan_p50": 6.0})), "", "", "").unwrap();
        let vpn = if m < 20 { json!("wg0") } else { Value::Null };
        store.put_minute(base + 7200 + 60 * m, &obj(json!({"wan_p50": 6.0, "vpn": vpn})), "", "", "").unwrap();
    }
    store.rollup_hours(Some(TUNNEL_NOW as f64)).unwrap();
    let rows = store.with_db(|db| reads::fetch_rows(db, "SELECT ts, vpn FROM hour", [])).unwrap();
    let vpn_at = |ts: i64| rows.iter().find(|r| r["ts"] == json!(ts)).unwrap()["vpn"].clone();
    assert_eq!(vpn_at(base), json!("wg0"));
    assert_eq!(vpn_at(base + 3600), Value::Null);
    assert_eq!(vpn_at(base + 7200), json!(""));
}

#[test]
fn an_older_database_gains_the_vpn_columns() {
    let dir = TempDir::new();
    let path = dir.path().join("old.db");
    let st = Store::new(&path, false).unwrap();
    st.put_test(60, "content", "x", &content(1.0, "", None)).unwrap();
    st.close();
    let db = Connection::open(&path).unwrap();
    for table in ["minute", "hour", "tests"] {
        db.execute_batch(&format!("ALTER TABLE {table} DROP COLUMN vpn")).unwrap();
    }
    drop(db);
    let st = Store::new(&path, false).unwrap();
    for table in ["minute", "hour", "tests"] {
        assert!(columns(&st, table).iter().any(|c| c == "vpn"), "{table}");
    }
    assert_eq!(st.tests(1, None).unwrap()[0]["vpn"], Value::Null);
}
