use serde_json::Value;

use crate::daemon::config::Config;
use crate::testutil::TempDir;

fn make(payload: &str) -> (Config, TempDir) {
    let dir = TempDir::new();
    let mut cfg = Config::new(dir.path());
    std::fs::write(&cfg.path, payload).unwrap();
    cfg.refresh();
    (cfg, dir)
}

#[test]
fn out_of_range_values_fall_back_to_defaults() {
    let (cfg, _d) = make(r#"{"throughputWindowS": 999999999, "probeIntervalMs": 1, "historyDays": -5}"#);
    assert_eq!(cfg["throughputWindowS"], 3);
    assert_eq!(cfg["probeIntervalMs"], 500);
    assert_eq!(cfg["historyDays"], 7);
}

#[test]
fn wrong_types_rejected() {
    let (cfg, _d) = make(r#"{"probeIntervalMs": "500", "contentSpeed": "yes", "peakEngine": "evil"}"#);
    assert_eq!(cfg.probe_interval_ms(), 500);
    assert!(cfg.content_speed());
    assert_eq!(cfg.peak_engine(), "Auto");
}

#[test]
fn anchor_charset_enforced() {
    let (cfg, _d) = make(r#"{"internetAnchor": "1.1.1.1; rm -rf /"}"#);
    assert_eq!(cfg.internet_anchor(), "1.1.1.1");
    let (cfg2, _d2) = make(r#"{"internetAnchor": "ping.example-host.net"}"#);
    assert_eq!(cfg2.internet_anchor(), "ping.example-host.net");
}

#[test]
fn oversized_file_ignored() {
    let (cfg, _d) = make(&format!(r#"{{"historyDays": 30, "pad": "{}"}}"#, "x".repeat(70 * 1024)));
    assert_eq!(cfg.history_days(), 7);
}

#[test]
fn valid_values_accepted() {
    let (cfg, _d) = make(r#"{"throughputWindowS": 10, "planDownMbps": 450}"#);
    assert_eq!(cfg.throughput_window_s(), 10);
    assert_eq!(cfg["planDownMbps"], 450);
}

#[test]
fn floats_are_truncated_like_python_int_and_bools_are_not_numbers() {
    let (cfg, _d) = make(r#"{"probeIntervalMs": 750.9, "historyDays": true, "planUpMbps": null}"#);
    assert_eq!(cfg["probeIntervalMs"], 750);
    assert_eq!(cfg.history_days(), 7);
    assert_eq!(cfg["planUpMbps"], 0);
}

#[test]
fn an_unchanged_file_is_not_read_again() {
    let (mut cfg, _d) = make(r#"{"historyDays": 30}"#);
    cfg.values.insert("historyDays".into(), Value::from(1));
    cfg.refresh();
    assert_eq!(cfg.history_days(), 1);
}

#[test]
fn config_symlink_refused() {
    let dir = TempDir::new();
    let target = dir.path().join("target.json");
    std::fs::write(&target, r#"{"historyDays": 30}"#).unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let mut cfg = Config::new(&sub);
    std::os::unix::fs::symlink(&target, &cfg.path).unwrap();
    cfg.refresh();
    assert_eq!(cfg.history_days(), 7);
}

#[test]
fn config_bound_is_on_the_read() {
    let (cfg, _d) = make(&format!(r#"{{"pad": "{}", "historyDays": 30}}"#, "x".repeat(70 * 1024)));
    assert_eq!(cfg.history_days(), 7);
}

#[test]
fn a_leading_dash_is_not_an_anchor() {
    for bad in ["-1.1.1.1", "--help", "-", "-x.example", ".x", ""] {
        assert_eq!(Config::validate("internetAnchor", &Value::from(bad)), None, "{bad}");
    }
    for ok in ["1.1.1.1", "::1", "2606:4700:4700::1111", "dns.google", "a"] {
        assert_eq!(Config::validate("internetAnchor", &Value::from(ok)), Some(Value::from(ok)));
    }
}

#[test]
fn defaults_mirror_the_manifest() {
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json")).unwrap())
            .unwrap();
    let declared = &manifest["barWidget"]["defaults"];
    for (key, value) in Config::defaults() {
        assert_eq!(declared[&key], value, "{key}");
    }
}

#[test]
#[ignore]
fn live_config_and_start_ticks() {
    let mut cfg = Config::new(&crate::paths::state_dir());
    cfg.refresh();
    println!("CONFIG {}", Value::Object(cfg.values.clone()));
    println!("TICKS {:?}", crate::util::proc_start_ticks(1));
}
