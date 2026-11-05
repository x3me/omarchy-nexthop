mod history;

use super::*;
use crate::testutil::{TempDir, obj};
use serde_json::json;

const NOW: f64 = 1_800_000_000.0;

fn open(dir: &TempDir) -> Store {
    Store::new(&dir.path().join("t.db"), false).unwrap()
}

fn content(down: f64, network: &str, vpn: Option<&str>) -> TestRow {
    TestRow { down_mbps: Some(down), network: Some(network.into()), vpn: vpn.map(String::from), ..TestRow::default() }
}

fn columns(store: &Store, table: &str) -> Vec<String> {
    store
        .with_db(|db| {
            let mut stmt = db.prepare(&format!("PRAGMA table_info({table})"))?;
            let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
            names.collect()
        })
        .unwrap()
}

fn assert_close(a: f64, b: f64, places: i32) {
    assert!((a - b).abs() < 0.5 * 10f64.powi(-places), "{a} != {b}");
}

#[test]
fn minute_hour_resolution_switch() {
    let dir = TempDir::new();
    let store = open(&dir);
    let now = NOW as i64;
    for i in 0..300 {
        store.put_minute(now - (300 - i) * 60, &obj(json!({"lag": 20.0})), "", "", "").unwrap();
    }
    let (rows, table) = store.series(3600.0, Some(NOW), "auto").unwrap();
    assert_eq!(table, "minute");
    assert_eq!(rows.len(), 60);
    store.rollup_hours(Some(NOW)).unwrap();
    let (rows, table) = store.series(7.0 * 86400.0, Some(NOW), "auto").unwrap();
    assert_eq!(table, "hour");
    assert!(rows.len() >= 4);
}

#[test]
fn outage_accounting() {
    let dir = TempDir::new();
    let store = open(&dir);
    let eid = store.open_event((NOW - 600.0) as i64, "outage", "critical", "wan", "test").unwrap();
    store.close_event(eid, (NOW - 540.0) as i64, None).unwrap();
    let (frac, disruptions, disrupt_frac) = store.outage_stats(3600.0, Some(NOW), &[]).unwrap();
    assert_close(frac, 60.0 / 3600.0, 3);
    assert_eq!(disruptions, 0);
    assert_eq!(disrupt_frac, 0.0);
}

#[test]
fn ongoing_outage_counts_to_now() {
    let dir = TempDir::new();
    let store = open(&dir);
    store.open_event((NOW - 120.0) as i64, "outage", "critical", "wan", "t").unwrap();
    let (frac, _, _) = store.outage_stats(3600.0, Some(NOW), &[]).unwrap();
    assert_close(frac, 120.0 / 3600.0, 3);
}

#[test]
fn disruptions_report_duration_not_just_count() {
    let dir = TempDir::new();
    let store = open(&dir);
    for (start, length) in [(900.0, 20.0), (600.0, 40.0)] {
        let eid = store.open_event((NOW - start) as i64, "disruption", "warning", "wan", "t").unwrap();
        store.close_event(eid, (NOW - start + length) as i64, None).unwrap();
    }
    let (frac, disruptions, disrupt_frac) = store.outage_stats(3600.0, Some(NOW), &[]).unwrap();
    assert_eq!(frac, 0.0);
    assert_eq!(disruptions, 2);
    assert_close(disrupt_frac, 60.0 / 3600.0, 3);
}

#[test]
fn baseline_is_p90_per_network() {
    let dir = TempDir::new();
    let store = open(&dir);
    let now = NOW as i64;
    for (i, v) in [100.0, 200.0, 210.0, 220.0, 230.0, 240.0, 900.0].into_iter().enumerate() {
        store.put_test(now - i as i64 * 3600, "content", "cloudflare", &content(v, "Office", None)).unwrap();
    }
    let office = store.baseline_speed(30, "Office", 5, Some(NOW), true, None).unwrap().unwrap();
    assert!(office < 900.0);
    assert!(office >= 240.0);
    assert!(store.baseline_speed(30, "Home", 5, Some(NOW), true, None).unwrap().is_some());
}

#[test]
fn baseline_no_fallback_without_local_samples() {
    let dir = TempDir::new();
    let store = open(&dir);
    for i in 0..6 {
        store.put_test(NOW as i64 - i * 3600, "content", "x", &content(300.0, "OfficeA", None)).unwrap();
    }
    assert_eq!(store.baseline_speed(30, "OfficeB", 5, Some(NOW), false, None).unwrap(), None);
    assert!(store.baseline_speed(30, "OfficeB", 5, Some(NOW), true, None).unwrap().is_some());
}

#[test]
fn baseline_needs_enough_samples() {
    let dir = TempDir::new();
    let store = open(&dir);
    for i in 0..3 {
        store.put_test(NOW as i64 - i * 3600, "content", "x", &content(100.0, "", None)).unwrap();
    }
    assert_eq!(store.baseline_speed(30, "", 5, Some(NOW), true, None).unwrap(), None);
}

#[test]
fn minute_rows_carry_basis_and_seats() {
    let dir = TempDir::new();
    let store = open(&dir);
    let ts = (NOW / 60.0).floor() as i64 * 60;
    store.put_minute(ts, &obj(json!({"lag": 30.0, "lag_icmp": 24.0})), "wlo1", "x", "icmp-anchor+tcp-cf").unwrap();
    let (rows, _) = store.series(3600.0, Some(NOW), "auto").unwrap();
    let row = rows.last().unwrap();
    assert_eq!(row["lag_icmp"], json!(24.0));
    assert_eq!(row["probes"], json!("icmp-anchor+tcp-cf"));
}

#[test]
fn old_databases_gain_the_columns() {
    let dir = TempDir::new();
    let path = dir.path().join("t.db");
    let old_cols: Vec<String> =
        SAMPLE_COLUMNS.iter().filter(|c| **c != "lag_icmp").map(|c| format!("{c} REAL")).collect();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "CREATE TABLE minute (ts INTEGER PRIMARY KEY, {}, iface TEXT, network TEXT)",
        old_cols.join(", ")
    ))
    .unwrap();
    drop(db);
    let store = Store::new(&path, false).unwrap();
    store.put_minute(60, &obj(json!({"lag": 1.0})), "", "", "a+b").unwrap();
}

#[test]
fn the_columns_exist_and_round_trip() {
    let dir = TempDir::new();
    let st = Store::new(&dir.path().join("history.db"), false).unwrap();
    let v =
        json!({"local_p50": 1.0, "local_p75": 2.0, "local_max": 9.0, "wan_p50": 3.0, "wan_p75": 4.0, "wan_max": 77.7});
    st.put_minute(60, &obj(v), "", "", "").unwrap();
    let row = st.with_db(|db| reads::fetch_rows(db, "SELECT * FROM minute WHERE ts = 60", [])).unwrap();
    assert_eq!(row[0]["local_p75"], json!(2.0));
    assert_eq!(row[0]["local_max"], json!(9.0));
    assert_eq!(row[0]["wan_p75"], json!(4.0));
    assert_eq!(row[0]["wan_max"], json!(77.7));
    st.close();
}

#[test]
fn an_older_database_is_migrated_in_place() {
    let dir = TempDir::new();
    let path = dir.path().join("history.db");
    let st = Store::new(&path, false).unwrap();
    st.put_minute(60, &obj(json!({"local_p50": 1.0})), "", "", "").unwrap();
    st.close();
    let db = Connection::open(&path).unwrap();
    for col in ["local_p75", "local_max", "wan_p75", "wan_max"] {
        db.execute_batch(&format!("ALTER TABLE minute DROP COLUMN {col}; ALTER TABLE hour DROP COLUMN {col};"))
            .unwrap();
    }
    drop(db);
    let st = Store::new(&path, false).unwrap();
    let cols = columns(&st, "minute");
    for col in ["local_p75", "local_max", "wan_p75", "wan_max"] {
        assert!(cols.iter().any(|c| c == col), "{col}");
    }
    let row = st.with_db(|db| reads::fetch_rows(db, "SELECT * FROM minute WHERE ts = 60", [])).unwrap();
    assert_eq!(row[0]["local_p50"], json!(1.0));
    assert_eq!(row[0]["local_max"], Value::Null);
    st.close();
}

#[test]
fn they_are_recorded_but_not_scored() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = vec![root.join("score.rs")];
    if let Ok(dir) = std::fs::read_dir(root.join("score")) {
        sources.extend(dir.filter_map(|e| e.ok()).map(|e| e.path()));
    }
    for src in sources {
        let Ok(text) = std::fs::read_to_string(&src) else {
            continue;
        };
        for col in ["local_p75", "local_max", "wan_p75", "wan_max"] {
            assert!(!text.contains(col), "{} reads {col}", src.display());
        }
    }
}

#[test]
fn overlapping_writers_and_readers_lose_nothing() {
    let dir = TempDir::new();
    let store = open(&dir);
    let n = 150i64;
    let lag = obj(json!({"lag": 1.0}));
    std::thread::scope(|s| {
        for (kind, base) in [("content", 10_000), ("peak", 20_000)] {
            let store = &store;
            s.spawn(move || {
                for i in 0..n {
                    store.put_test(base + i, kind, "x", &content(1.0, "n", None)).unwrap();
                }
            });
        }
        s.spawn(|| {
            for i in 0..n {
                store.put_minute(1_000_000 + i * 60, &lag, "", "", "").unwrap();
                store.outage_stats(3600.0, Some(2_000_000.0), &[]).unwrap();
            }
        });
        s.spawn(|| {
            for i in 0..n {
                let eid = store.open_event(3_000_000 + i, "outage", "critical", "wan", "t").unwrap();
                store.close_event(eid, 3_000_000 + i + 1, None).unwrap();
                store.events(86400.0, 100, Some((3_000_000 + n) as f64)).unwrap();
            }
        });
    });
    assert_eq!(store.tests(1000, Some("content")).unwrap().len(), n as usize);
    assert_eq!(store.tests(1000, Some("peak")).unwrap().len(), n as usize);
    let (rows, _) = store.series(1e9, Some((1_000_000 + n * 60 + 1) as f64), "minute").unwrap();
    assert_eq!(rows.len(), n as usize);
}

const EVENTS_NOW: i64 = 1_000_000;

fn details(store: &Store, seconds: f64) -> Vec<Value> {
    store.events(seconds, 100, Some(EVENTS_NOW as f64)).unwrap().into_iter().map(|e| e["detail"].clone()).collect()
}

#[test]
fn an_event_that_ended_inside_the_window_is_listed() {
    let dir = TempDir::new();
    let store = open(&dir);
    let eid = store.open_event(EVENTS_NOW - 90_000, "outage", "critical", "wan", "straddles").unwrap();
    store.close_event(eid, EVENTS_NOW - 3_600, None).unwrap();
    let eid = store.open_event(EVENTS_NOW - 90_000, "outage", "critical", "wan", "old").unwrap();
    store.close_event(eid, EVENTS_NOW - 89_000, None).unwrap();
    let listed = details(&store, 86_400.0);
    assert!(listed.contains(&json!("straddles")));
    assert!(!listed.contains(&json!("old")));
}

#[test]
fn orphans_are_closed_at_the_shortest_span() {
    let dir = TempDir::new();
    let store = open(&dir);
    let now = Some(EVENTS_NOW as f64);
    store.open_event(EVENTS_NOW - 90_000, "outage", "critical", "wan", "orphan").unwrap();
    let (frac, _, _) = store.outage_stats(3600.0, now, &[]).unwrap();
    assert_close(frac, 1.0, 3);
    assert_eq!(store.close_orphans(now).unwrap(), 1);
    let (frac, _, _) = store.outage_stats(3600.0, now, &[]).unwrap();
    assert_eq!(frac, 0.0);
    let row = &store.events(1e6, 100, now).unwrap()[0];
    assert_eq!(row["ended_ts"].as_i64().unwrap(), row["ts"].as_i64().unwrap() + 1);
    assert_eq!(row["end_unknown"], json!(1));
    assert_eq!(store.close_orphans(now).unwrap(), 0);
}

#[test]
fn an_end_that_was_seen_is_not_marked_unknown() {
    let dir = TempDir::new();
    let store = open(&dir);
    let now = Some(EVENTS_NOW as f64);
    let eid = store.open_event(EVENTS_NOW - 60, "outage", "critical", "wan", "seen").unwrap();
    store.close_event(eid, EVENTS_NOW - 50, None).unwrap();
    store.close_orphans(now).unwrap();
    let row = &store.events(1e6, 100, now).unwrap()[0];
    assert_eq!(row["ended_ts"].as_i64().unwrap() - row["ts"].as_i64().unwrap(), 10);
    assert_eq!(row["end_unknown"], Value::Null);
}

#[test]
fn an_older_events_table_gains_the_marker() {
    let dir = TempDir::new();
    let path = dir.path().join("old-events.db");
    let st = Store::new(&path, false).unwrap();
    let eid = st.open_event(100, "outage", "critical", "wan", "old").unwrap();
    st.close_event(eid, 101, None).unwrap();
    st.close();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("ALTER TABLE events DROP COLUMN end_unknown").unwrap();
    drop(db);
    let st = Store::new(&path, false).unwrap();
    assert!(columns(&st, "events").iter().any(|c| c == "end_unknown"));
    assert_eq!(st.events(1e9, 100, Some(200.0)).unwrap()[0]["end_unknown"], Value::Null);
}

#[test]
fn prune_removes_events_past_the_hourly_horizon() {
    let dir = TempDir::new();
    let store = open(&dir);
    let eid = store.open_event(EVENTS_NOW - 500 * 86_400, "info", "info", "local", "ancient").unwrap();
    store.close_event(eid, EVENTS_NOW - 500 * 86_400 + 1, None).unwrap();
    let eid = store.open_event(EVENTS_NOW - 10, "info", "info", "local", "recent").unwrap();
    store.close_event(eid, EVENTS_NOW - 9, None).unwrap();
    store.prune(7, 400, Some(EVENTS_NOW as f64)).unwrap();
    let listed = details(&store, 1e9);
    assert!(!listed.contains(&json!("ancient")));
    assert!(listed.contains(&json!("recent")));
}

#[test]
fn an_hour_spanning_two_networks_is_labelled_neither() {
    let dir = TempDir::new();
    let store = open(&dir);
    let hour = 3_600_000;
    let lag = obj(json!({"lag": 1.0}));
    store.put_minute(hour + 60, &lag, "wlo1", "Home", "").unwrap();
    store.put_minute(hour + 120, &lag, "wlo1", "Office", "").unwrap();
    store.put_minute(hour + 3660, &lag, "wlo1", "Office", "").unwrap();
    let now = Some((hour + 3 * 3600) as f64);
    store.rollup_hours(now).unwrap();
    let (rows, _) = store.series(1e6, now, "hour").unwrap();
    let at = |ts: i64| rows.iter().find(|r| r["ts"] == json!(ts)).unwrap();
    assert_eq!(at(hour)["network"], json!(""));
    assert_eq!(at(hour)["iface"], json!("wlo1"));
    assert_eq!(at(hour + 3600)["network"], json!("Office"));
}

#[test]
fn a_minute_carries_the_drain_and_what_produced_it() {
    let dir = TempDir::new();
    let s = open(&dir);
    let v = json!({"lag": 12.0, "drain_ms": 2000.0, "drain_min_ms": 1000.0, "drain_settled": 1.0, "drain_src": "tcp-anchor"});
    s.put_minute(60, &obj(v), "wlan0", "home", "icmp+tcp").unwrap();
    let (rows, _) = s.series(3600.0, Some(120.0), "minute").unwrap();
    let row = &rows[0];
    assert_eq!(row["drain_ms"], json!(2000.0));
    assert_eq!(row["drain_min_ms"], json!(1000.0));
    assert_eq!(row["drain_settled"], json!(1.0));
    assert_eq!(row["drain_src"], json!("tcp-anchor"));
}

#[test]
fn never_measured_and_did_not_settle_stay_different() {
    let dir = TempDir::new();
    let s = open(&dir);
    s.put_minute(60, &obj(json!({"drain_ms": 30000.0, "drain_settled": 0.0})), "", "home", "").unwrap();
    s.put_minute(120, &obj(json!({"lag": 9.0})), "", "home", "").unwrap();
    let (rows, _) = s.series(3600.0, Some(180.0), "minute").unwrap();
    assert_eq!(rows[0]["drain_settled"], json!(0.0));
    assert_eq!(rows[1]["drain_settled"], Value::Null);
    assert_eq!(rows[1]["drain_ms"], Value::Null);
}

#[test]
fn the_drain_does_not_roll_up_into_an_hour() {
    for c in ["drain_ms", "drain_min_ms", "drain_settled", "drain_src"] {
        assert!(!SAMPLE_COLUMNS.contains(&c));
    }
    let dir = TempDir::new();
    let s = open(&dir);
    let cols = columns(&s, "hour");
    for c in ["drain_ms", "drain_min_ms", "drain_settled", "drain_src"] {
        assert!(!cols.iter().any(|x| x == c), "{c}");
    }
}

#[test]
fn an_older_database_gains_the_drain_columns() {
    let dir = TempDir::new();
    let path = dir.path().join("old.db");
    let old = Connection::open(&path).unwrap();
    old.execute_batch(
        "CREATE TABLE minute (ts INTEGER PRIMARY KEY, lag REAL);
         CREATE TABLE hour (ts INTEGER PRIMARY KEY, lag REAL);
         CREATE TABLE tests (ts INTEGER, kind TEXT);
         CREATE TABLE events (ts INTEGER, kind TEXT);",
    )
    .unwrap();
    drop(old);
    let s = Store::new(&path, false).unwrap();
    let cols = columns(&s, "minute");
    for c in ["drain_ms", "drain_min_ms", "drain_settled", "drain_src"] {
        assert!(cols.iter().any(|x| x == c), "{c}");
    }
}

#[test]
fn a_fresh_database_has_the_python_schema_text() {
    let dir = TempDir::new();
    let s = open(&dir);
    let sql: String =
        s.with_db(|db| db.query_row("SELECT sql FROM sqlite_master WHERE name = 'hour'", [], |r| r.get(0))).unwrap();
    assert!(sql.starts_with("CREATE TABLE hour (\n  ts INTEGER PRIMARY KEY, local_p50 REAL, local_p95 REAL,"));
    assert!(sql.ends_with("lag_icmp REAL, iface TEXT, network TEXT\n, vpn TEXT)"), "{sql}");
}

#[test]
fn rows_keep_sqlite_types_and_column_order() {
    let dir = TempDir::new();
    let s = open(&dir);
    s.put_test(60, "peak", "ookla", &TestRow { bytes: Some(1234), down_mbps: Some(5.0), ..TestRow::default() })
        .unwrap();
    let row = &s.tests(1, None).unwrap()[0];
    let keys: Vec<&str> = row.keys().map(String::as_str).take(4).collect();
    assert_eq!(keys, ["ts", "kind", "engine", "down_mbps"]);
    assert_eq!(crate::pyjson::to_string(&row["bytes"]).unwrap(), "1234");
    assert_eq!(crate::pyjson::to_string(&row["down_mbps"]).unwrap(), "5.0");
    assert_eq!(row["ok"], json!(1));
    assert_eq!(row["vpn"], Value::Null);
}

#[test]
fn read_only_store_reads_but_refuses_writes() {
    let dir = TempDir::new();
    let path = dir.path().join("t.db");
    let rw = Store::new(&path, false).unwrap();
    rw.put_minute(60, &obj(json!({"lag": 1.0})), "", "", "").unwrap();
    let ro = Store::new(&path, true).unwrap();
    assert_eq!(ro.series(3600.0, Some(120.0), "minute").unwrap().0.len(), 1);
    assert!(ro.put_minute(120, &obj(json!({"lag": 1.0})), "", "", "").is_err());
    rw.close();
    assert!(rw.tests(1, None).is_err());
}

#[test]
#[ignore]
fn live_check_opens_a_copy_of_the_python_database_read_write() {
    let Ok(path) = std::env::var("NEXTHOP_DB_COPY") else {
        eprintln!("skipped: set NEXTHOP_DB_COPY to a copy of history.db");
        return;
    };
    let store = Store::new(std::path::Path::new(&path), false).unwrap();
    let (rows, _) = store.series(86400.0, None, "minute").unwrap();
    assert!(!rows.is_empty());
    store.rollup_hours(std::env::var("NEXTHOP_ROLLUP_NOW").ok().and_then(|v| v.parse().ok())).unwrap();
    store.close();
}
