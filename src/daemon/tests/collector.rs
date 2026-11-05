use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use crate::daemon::collector::{Clock, LinkCollector, SnapshotFn, Targets, TargetsFn, TunnelFn, is_address};
use crate::testutil::obj;

fn anchor(a: &'static str) -> Box<dyn Fn() -> String + Send + Sync> {
    Box::new(move || a.to_string())
}

fn fixed_snapshot(v: Value) -> Option<SnapshotFn> {
    let snap = obj(v);
    Some(Box::new(move |_| Ok(snap.clone())))
}

fn targets(pairs: &[(&str, &str)]) -> Targets {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn shared_clock(clock: &Arc<Mutex<f64>>) -> Option<Clock> {
    let clock = Arc::clone(clock);
    Some(Box::new(move || *clock.lock().unwrap()))
}

mod tunnel_check_cadence {
    use super::*;

    #[test]
    fn checked_on_change_and_on_the_minute_only() {
        let clock = Arc::new(Mutex::new(0.0));
        let snap = Arc::new(Mutex::new(obj(json!({"iface": "wlo1", "tunnel_iface": ""}))));
        let calls: Arc<Mutex<Vec<(f64, String)>>> = Arc::default();
        let (snap_in, clock_in, calls_in) = (snap.clone(), clock.clone(), calls.clone());
        let tunnel: TunnelFn = Box::new(move |_, physical| {
            calls_in.lock().unwrap().push((*clock_in.lock().unwrap(), physical.to_string()));
            let up = snap_in.lock().unwrap()["tunnel_iface"] != "";
            Ok(up.then(|| obj(json!({"iface": "wg0"}))))
        });
        let snap_fn = snap.clone();
        let c = LinkCollector::new(
            anchor("1.1.1.1"),
            Some(Box::new(move |_| Ok(snap_fn.lock().unwrap().clone()))),
            LinkCollector::INTERVAL_S,
            Some(Box::new(|| targets(&[("icmp-anchor", "1.1.1.1")]))),
            Some(tunnel),
            shared_clock(&clock),
        );
        c.take();
        *clock.lock().unwrap() = 30.0;
        c.take();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(c.latest()["vpn"], Value::Null);
        snap.lock().unwrap().insert("tunnel_iface".into(), "wg0".into());
        *clock.lock().unwrap() = 31.0;
        c.take();
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(c.latest()["vpn"], json!({"iface": "wg0"}));
        *clock.lock().unwrap() = 31.0 + LinkCollector::TUNNEL_CHECK_S;
        c.take();
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn a_failing_check_keeps_the_last_answer() {
        let clock = Arc::new(Mutex::new(0.0));
        let answers = Mutex::new(vec![obj(json!({"iface": "wg0"}))]);
        let tunnel: TunnelFn = Box::new(move |_, _| match answers.lock().unwrap().pop() {
            Some(a) => Ok(Some(a)),
            None => Err(std::io::Error::other("ip went away")),
        });
        let c = LinkCollector::new(
            anchor("x"),
            fixed_snapshot(json!({"iface": "wlo1"})),
            LinkCollector::INTERVAL_S,
            Some(Box::new(Targets::new)),
            Some(tunnel),
            shared_clock(&clock),
        );
        c.take();
        *clock.lock().unwrap() = 1000.0;
        c.take();
        assert_eq!(c.latest()["vpn"], json!({"iface": "wg0"}));
    }
}

mod never_waits_on_a_resolver {
    use super::*;

    #[test]
    fn the_default_check_finds_no_tunnel_for_a_name_without_an_address() {
        let c = LinkCollector::new(
            anchor("1.1.1.1"),
            fixed_snapshot(json!({"iface": "wlo1"})),
            LinkCollector::INTERVAL_S,
            Some(Box::new(|| targets(&[("tcp-cf", "speed.cloudflare.com")]))),
            None,
            None,
        );
        c.take();
        assert_eq!(c.latest()["vpn"], Value::Null);
    }

    #[test]
    fn rechecked_when_a_probe_gains_an_address_not_when_it_changes() {
        let current = Arc::new(Mutex::new(targets(&[("icmp-anchor", "1.1.1.1")])));
        let calls: Arc<Mutex<Vec<Targets>>> = Arc::default();
        let (current_in, calls_in) = (current.clone(), calls.clone());
        let targets_fn: TargetsFn = Box::new(move || current_in.lock().unwrap().clone());
        let tunnel: TunnelFn = Box::new(move |t, _| {
            calls_in.lock().unwrap().push(t.clone());
            Ok(None)
        });
        let c = LinkCollector::new(
            anchor("1.1.1.1"),
            fixed_snapshot(json!({"iface": "wlo1"})),
            LinkCollector::INTERVAL_S,
            Some(targets_fn),
            Some(tunnel),
            Some(Box::new(|| 10.0)),
        );
        c.take();
        current.lock().unwrap().insert("tcp-cf".into(), "198.51.100.10".into());
        c.take();
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(calls.lock().unwrap().last().unwrap()["tcp-cf"], "198.51.100.10");
        current.lock().unwrap().insert("tcp-cf".into(), "198.51.100.11".into());
        c.take();
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn without_targets_no_vpn_key_is_added() {
        let c = LinkCollector::new(anchor("x"), fixed_snapshot(json!({"iface": "wlo1"})), 0.5, None, None, None);
        c.take();
        assert_eq!(c.latest(), obj(json!({"iface": "wlo1"})));
    }
}

mod link_off_the_loop {
    use super::*;

    #[test]
    fn reading_never_waits_for_a_slow_snapshot() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let (second_tx, second_rx) = mpsc::channel::<()>();
        let gate_rx = Mutex::new(gate_rx);
        let second_tx = Mutex::new(second_tx);
        let counter = calls.clone();
        let slow: SnapshotFn = Box::new(move |_| {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            if n > 1 {
                let _ = second_tx.lock().unwrap().send(());
                let _ = gate_rx.lock().unwrap().recv_timeout(Duration::from_secs(5));
            }
            Ok(obj(json!({"iface": "wlo1", "kind": "wifi", "n": n, "station": {"tx_retries": 1}})))
        });
        let c = LinkCollector::new(anchor("1.1.1.1"), Some(slow), 0.01, None, None, None);
        c.start().unwrap();
        assert_eq!(c.latest()["n"], 1);
        second_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let t0 = Instant::now();
        let mut snap = c.latest();
        assert!(t0.elapsed() < Duration::from_millis(50));
        assert_eq!(snap["n"], 1);
        snap["station"].as_object_mut().unwrap().insert("retry_pct".into(), 50.0.into());
        assert!(c.latest()["station"].get("retry_pct").is_none());
        c.stop();
        drop(gate_tx);
    }

    #[test]
    fn a_failing_snapshot_keeps_the_last_good_one() {
        let (third_tx, third_rx) = mpsc::channel::<()>();
        let third_tx = Mutex::new(third_tx);
        let n = Arc::new(AtomicUsize::new(0));
        let counter = n.clone();
        let flaky: SnapshotFn = Box::new(move |_| {
            let k = counter.fetch_add(1, Ordering::SeqCst) + 1;
            if k == 3 {
                let _ = third_tx.lock().unwrap().send(());
            }
            if k > 1 {
                return Err(std::io::Error::other("iw went away"));
            }
            Ok(obj(json!({"iface": "wlo1", "n": 1})))
        });
        let c = LinkCollector::new(anchor("x"), Some(flaky), 0.01, None, None, None);
        c.start().unwrap();
        third_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(n.load(Ordering::SeqCst) >= 3);
        assert_eq!(c.latest(), obj(json!({"iface": "wlo1", "n": 1})));
        assert!(c.is_alive());
        c.stop();
    }

    #[test]
    fn stop_ends_the_thread_promptly() {
        let c = LinkCollector::new(anchor("x"), fixed_snapshot(json!({})), 3600.0, None, None, None);
        c.start().unwrap();
        assert!(c.is_alive());
        c.stop();
        let deadline = Instant::now() + Duration::from_secs(2);
        while c.is_alive() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!c.is_alive());
        assert_eq!(c.latest(), Map::new());
    }
}

#[test]
fn addresses_and_names() {
    for a in ["1.1.1.1", "::1", "2606:4700:4700::1111", "fe80::1%wlo1"] {
        assert!(is_address(a), "{a}");
    }
    for n in ["dns.google", "", "1.1.1", "01.1.1.1", "fe80::1%", "1.1.1.1%x"] {
        assert!(!is_address(n), "{n}");
    }
}
