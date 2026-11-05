use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::rig::Rig;
use crate::apps::AppTraffic;
use crate::daemon::compose::bloat_of;
use crate::daemon::consts::{MIN_LOAD_SPLIT_SAMPLES, UNWATCHED_AFTER_S};
use crate::daemon::run::TICK_S;
use crate::probes::Sample;
use crate::score;
use crate::testutil::obj;

fn stream(idle_rtt: Option<f64>, loaded_rtt: Option<f64>, n: usize) -> Vec<Sample> {
    let t = 1_000_000.0;
    let idle = (0..n).map(|i| Sample::new(t + i as f64, idle_rtt, false));
    let loaded = (0..n).map(|i| Sample::new(t + (n + i) as f64, loaded_rtt, true));
    idle.chain(loaded).collect()
}

mod bufferbloat_with_no_replies {
    use super::*;

    #[test]
    fn a_loaded_half_with_no_replies_has_no_latency() {
        let b = bloat_of(vec![stream(Some(8.0), None, 12)], &[]);
        assert_eq!(b.idle, Some(8.0));
        assert_eq!(b.loaded_samples, 12);
        assert_eq!((b.loaded, b.inflation), (None, None));
        assert_eq!(score::pressure(None, b.loaded, b.idle).state, None);
    }

    #[test]
    fn an_idle_half_with_no_replies_has_no_latency() {
        let b = bloat_of(vec![stream(None, Some(40.0), 12)], &[]);
        assert_eq!((b.idle, b.loaded, b.inflation), (None, Some(40.0), None));
    }

    #[test]
    fn a_real_split_is_untouched() {
        let b = bloat_of(vec![stream(Some(8.0), Some(40.0), 12)], &[]);
        assert_eq!((b.idle, b.loaded, b.inflation), (Some(8.0), Some(40.0), Some(5.0)));
    }
}

mod inflation_plausibility {
    use super::*;

    fn ratio(loaded: f64, idle: f64) -> Option<f64> {
        bloat_of(vec![stream(Some(idle), Some(loaded), 12)], &[]).inflation
    }

    // 0.87 was published on 716 samples per side: the sample floor cannot catch a wrong-direction result.
    #[test]
    fn the_case_seen_live_is_withheld() {
        assert_eq!(ratio(20.3, 23.4), None);
    }

    #[test]
    fn indistinguishable_reads_as_no_inflation() {
        assert_eq!(ratio(9.8, 10.0), Some(1.0));
        assert_eq!(ratio(10.0, 10.0), Some(1.0));
    }

    #[test]
    fn real_inflation_still_reported() {
        assert_eq!(ratio(13.0, 10.0), Some(1.3));
        assert_eq!(ratio(250.0, 10.0), Some(25.0));
    }
}

#[test]
fn inflation_needs_enough_samples_on_both_sides() {
    let rig = Rig::new();
    let now = rig.now();
    for i in 0..30 {
        rig.d.icmp_anchor.add(now - 60.0 + i as f64, Some(15.0), false);
    }
    for i in 0..MIN_LOAD_SPLIT_SAMPLES - 1 {
        rig.d.icmp_anchor.add(now - 5.0 + i as f64 * 0.1, Some(300.0), true);
    }
    let b = rig.d.bufferbloat(300.0);
    assert!(b.idle.is_some() && b.loaded.is_some());
    assert_eq!(b.inflation, None);
    rig.d.icmp_anchor.add(now, Some(300.0), true);
    let b = rig.d.bufferbloat(300.0);
    assert!(b.inflation.unwrap() > 5.0);
}

#[test]
fn the_drain_names_the_slowest_seat_and_the_tightest_bound() {
    let mk = |t0: f64, gap: f64| {
        let mut s: Vec<Sample> = (0..10).map(|i| Sample::new(t0 + i as f64, Some(10.0), false)).collect();
        s.push(Sample::new(t0 + 10.0, Some(80.0), true));
        s.push(Sample::new(t0 + 10.0 + gap, Some(10.0), false));
        s
    };
    let keys = ["a".to_string(), "b".to_string()];
    let b = bloat_of(vec![mk(0.0, 0.5), mk(0.0, 2.0)], &keys);
    assert_eq!((b.drain.ms, b.drain.min_ms, b.drain.settled), (Some(2000.0), Some(500.0), Some(true)));
    assert_eq!(b.drain.src.as_deref(), Some("b"));
}

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

mod snapshot_freshness_budget {
    use super::*;

    fn stale_after_s() -> f64 {
        let src = std::fs::read_to_string(repo().join("BarWidget.qml")).unwrap();
        let at = src.find("staleAfterS").expect("staleAfterS is gone from BarWidget");
        let rest = &src[at..];
        let digits: String =
            rest[rest.find(':').unwrap() + 1..].trim_start().chars().take_while(char::is_ascii_digit).collect();
        digits.parse().unwrap()
    }

    #[test]
    fn the_blocking_poll_fits_well_inside_the_staleness_contract() {
        assert!(AppTraffic::POLL_DEADLINE_S < stale_after_s() / 2.0);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn a_slow_pass_is_not_mistaken_for_time_nobody_watched() {
        assert!(TICK_S + AppTraffic::POLL_DEADLINE_S < UNWATCHED_AFTER_S / 2.0);
    }
}

fn ident_at(text: &str) -> &str {
    let end = text
        .char_indices()
        .find(|(i, c)| !(c.is_ascii_alphabetic() || *c == '_' || (*i > 0 && c.is_ascii_digit())))
        .map_or(text.len(), |(i, _)| i);
    &text[..end]
}

fn read_by_qml() -> (BTreeSet<String>, BTreeMap<String, BTreeSet<String>>) {
    let (mut reads, mut nested) = (BTreeSet::new(), BTreeMap::<String, BTreeSet<String>>::new());
    for entry in std::fs::read_dir(repo()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "qml") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        for (at, _) in src.match_indices("live.") {
            if src[..at].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let rest = &src[at + 5..];
            let first = ident_at(rest);
            if first.is_empty() || first == "json" {
                continue;
            }
            reads.insert(first.to_string());
            if let Some(after) = rest[first.len()..].strip_prefix('.') {
                let second = ident_at(after);
                if !second.is_empty() {
                    nested.entry(first.to_string()).or_default().insert(second.to_string());
                }
            }
        }
    }
    (reads, nested)
}

fn published() -> Map<String, Value> {
    let mut rig = Rig::new();
    let now = rig.now();
    obj(rig.d.compose_live(now).unwrap())
}

#[test]
fn qml_reads_only_what_the_daemon_publishes() {
    let live = published();
    let (reads, nested) = read_by_qml();
    assert!(!reads.is_empty(), "the scan found nothing");
    let missing: Vec<&String> = reads.iter().filter(|k| !live.contains_key(*k)).collect();
    assert!(missing.is_empty(), "{missing:?}");
    for parent in ["scores", "reliability_ctx", "lag", "rates"] {
        let keys = live[parent].as_object().unwrap();
        for field in nested.get(parent).into_iter().flatten() {
            assert!(keys.contains_key(field), "{parent}.{field}");
        }
    }
}

#[test]
fn the_keys_the_shell_service_relies_on_are_published() {
    let live = published();
    for key in ["t", "pid", "pid_start", "daemon_version", "state"] {
        assert!(live.contains_key(key), "{key}");
    }
    assert_eq!(live["daemon_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(live["pid"], std::process::id());
    assert!(live["pid_start"].as_i64().is_some_and(|t| t > 0));
}

#[test]
fn one_pass_writes_the_snapshots_and_a_minute_row() {
    let mut rig = Rig::new();
    let now = rig.now();
    rig.d.last_apps_poll = now;
    rig.d.tick(now).unwrap();
    let live = std::fs::read_to_string(rig.d.live_path()).unwrap();
    assert!(live.contains("\"window_s\":86400,"), "{live}");
    assert!(live.contains("\"min_s\":3600.0}"), "{live}");
    assert!(live.contains("\"v\":1,"));
    let live: Value = serde_json::from_str(&live).unwrap();
    assert_eq!(live["state"], "online");
    assert_eq!(live["instruments"].as_array().unwrap().len(), 4);
    let recent: Value = serde_json::from_slice(&std::fs::read(rig.d.recent_path()).unwrap()).unwrap();
    assert_eq!(recent["points"].as_array().unwrap().len(), 360);
    let (rows, table) = rig.store().series(120.0, Some(now), "minute").unwrap();
    assert_eq!((rows.len(), table), (1, "minute"));
    assert_eq!(rows[0]["ts"], (now / 60.0).floor() as i64 * 60);
    assert_eq!(rows[0]["probes"], "icmp-anchor+tcp-cf");
    assert!(!rig.d.apps_path().exists());
}
