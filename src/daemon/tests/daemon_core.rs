use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::rig::{Rig, snapshot};
use crate::daemon::collector::Snapshot;
use crate::daemon::core::{AnyProbe, instrument_pool, probe_targets, tests_idle};
use crate::daemon::probes_pool::{fresh_route_from, route_differs};
use crate::probes::{NameLookup, PingProbe, Series, TcpProbe};

fn tcp(host: &str, addresses: &[&str]) -> AnyProbe {
    let mut p = TcpProbe::new(host, Arc::new(Series::default()), 1.0, "", None, 443);
    let found: Vec<SocketAddr> = addresses.iter().map(|a| SocketAddr::new(a.parse().unwrap(), 443)).collect();
    p.lookup = Arc::new(NameLookup::with(host, 443, Arc::new(move |_, _| Ok(found.clone())), Box::new(|job| job())));
    p.lookup.resolve(None);
    AnyProbe::Tcp(Arc::new(p))
}

fn ping(host: &str) -> AnyProbe {
    AnyProbe::Ping(Arc::new(PingProbe::new(host, Arc::new(Series::default()), 500.0, "", None)))
}

fn targets(anchor: &str, probes: Vec<(&str, AnyProbe)>) -> Vec<(String, String)> {
    let probes: Vec<(String, AnyProbe)> = probes.into_iter().map(|(k, p)| (k.to_string(), p)).collect();
    probe_targets(anchor, &probes).into_iter().collect()
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
    v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
}

#[test]
fn lock_symlink_never_truncates_target() {
    let rig = Rig::new();
    let victim = rig.dir.path().join("victim");
    std::fs::write(&victim, "precious data that must survive").unwrap();
    std::os::unix::fs::symlink(&victim, rig.d.lock_path()).unwrap();
    let mut d = rig.d;
    assert!(!d.acquire_lock());
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious data that must survive");
}

#[test]
fn the_lock_is_exclusive_and_names_its_holder() {
    let mut rig = Rig::new();
    std::fs::write(rig.d.lock_path(), "stale contents from an older daemon").unwrap();
    assert!(rig.d.acquire_lock());
    assert_eq!(std::fs::read_to_string(rig.d.lock_path()).unwrap(), std::process::id().to_string());
    assert!(crate::daemon::run::acquire_lock(&rig.d.lock_path()).is_none());
    rig.d.lock_fd = None;
    assert!(crate::daemon::run::acquire_lock(&rig.d.lock_path()).is_some());
}

#[test]
fn the_content_checks_host_is_never_a_latency_instrument() {
    for anchor in ["1.1.1.1", "1.0.0.1", "9.9.9.9"] {
        assert!(instrument_pool(anchor).iter().all(|(_, _, t)| !t.contains("speed.cloudflare.com")));
    }
}

#[test]
fn the_default_pool() {
    let pool: Vec<(String, String)> = instrument_pool("1.1.1.1").into_iter().map(|(k, _, t)| (k, t)).collect();
    assert_eq!(
        pool,
        pairs(&[
            ("icmp-anchor", "1.1.1.1"),
            ("tcp-anchor", "1.1.1.1:443"),
            ("tcp-cf", "1.0.0.1:443"),
            ("tcp-google", "dns.google:443")
        ])
    );
}

#[test]
fn no_instrument_twice_when_the_anchor_is_the_cloudflare_address() {
    let pool = instrument_pool("1.0.0.1");
    let mut tcp: Vec<&String> = pool.iter().filter(|(_, k, _)| *k == "tcp").map(|(_, _, t)| t).collect();
    let n = tcp.len();
    tcp.sort();
    tcp.dedup();
    assert_eq!(tcp.len(), n);
    assert!(pool.contains(&("tcp-cf".into(), "tcp", "1.1.1.1:443".into())));
}

#[test]
fn targets_are_the_addresses_the_probes_connect_to() {
    let got = targets(
        "1.1.1.1",
        vec![
            ("icmp-anchor", ping("1.1.1.1")),
            ("tcp-anchor", tcp("1.1.1.1", &["1.1.1.1"])),
            ("tcp-cf", tcp("1.0.0.1", &["1.0.0.1"])),
            ("tcp-google", tcp("dns.google", &["198.51.100.10", "198.51.100.11"])),
        ],
    );
    assert_eq!(
        got,
        pairs(&[
            ("icmp-anchor", "1.1.1.1"),
            ("tcp-anchor", "1.1.1.1"),
            ("tcp-cf", "1.0.0.1"),
            ("tcp-google", "198.51.100.10")
        ])
    );
    let got = targets("1.1.1.1", vec![("tcp-google", tcp("dns.google", &[]))]);
    assert!(!got.iter().any(|(k, _)| k == "tcp-google"));
}

#[test]
fn a_named_anchor_takes_the_address_its_tcp_probe_resolved() {
    let got = targets("one.one.one.one", vec![("tcp-anchor", tcp("one.one.one.one", &["198.51.100.1"]))]);
    assert_eq!(got, pairs(&[("icmp-anchor", "198.51.100.1"), ("tcp-anchor", "198.51.100.1"), ("tcp-cf", "1.0.0.1")]));
    assert_eq!(targets("one.one.one.one", vec![]), pairs(&[("tcp-cf", "1.0.0.1")]));
}

#[test]
fn nothing_happens_before_probes_exist() {
    let mut rig = Rig::new();
    let local = Arc::clone(&rig.d.local);
    rig.d.config.values.insert("probeIntervalMs".into(), json!(1000));
    rig.d.restart_probes_if_settings_changed().unwrap();
    assert!(Arc::ptr_eq(&local, &rig.d.local));
    assert_eq!(rig.d.probe_settings, None);
}

#[test]
fn interval_change_moves_the_cadence_in_place() {
    let mut rig = Rig::new();
    let anchor = rig.d.anchor();
    rig.d.probe_settings = Some((anchor.clone(), 500));
    rig.d.local_probe = Some(ping("192.0.2.1"));
    let (seated, benched) = (ping("1.1.1.1"), tcp("dns.google", &[]));
    rig.d.set_instrument_probes(vec![("icmp-anchor".into(), seated.clone()), ("tcp-google".into(), benched.clone())]);
    let local = Arc::clone(&rig.d.local);
    rig.d.config.values.insert("probeIntervalMs".into(), json!(1000));
    rig.d.restart_probes_if_settings_changed().unwrap();
    assert_eq!(rig.d.local_probe.as_ref().unwrap().interval(), 1.0);
    assert_eq!(seated.interval(), 1.0);
    assert_eq!(benched.interval(), 10.0);
    assert_eq!(rig.d.probe_settings, Some((anchor.clone(), 1000)));
    assert!(Arc::ptr_eq(&local, &rig.d.local));
    benched.set_interval(3.0);
    rig.d.restart_probes_if_settings_changed().unwrap();
    assert_eq!(benched.interval(), 3.0);
}

fn answering(route: &Arc<Mutex<Snapshot>>, calls: &Arc<Mutex<Vec<String>>>) -> Rig {
    let (route, calls) = (Arc::clone(route), Arc::clone(calls));
    Rig::with(crate::util::now(), move |h| {
        h.local_route = Box::new(move |anchor| {
            calls.lock().unwrap().push(anchor.to_string());
            route.lock().unwrap().clone()
        });
    })
}

#[test]
fn anchor_change_rebuilds_the_probes() {
    let route = Arc::new(Mutex::new(snapshot(json!({"gateway": "192.0.2.1", "iface": "x"}))));
    let calls = Arc::default();
    let mut rig = answering(&route, &calls);
    rig.d.probe_settings = Some((rig.d.anchor(), 500));
    let local = Arc::clone(&rig.d.local);
    rig.d.config.values.insert("internetAnchor".into(), json!("9.9.9.9"));
    rig.d.restart_probes_if_settings_changed().unwrap();
    assert!(!Arc::ptr_eq(&local, &rig.d.local));
    assert_eq!(rig.d.route, snapshot(json!({"gateway": "192.0.2.1", "iface": "x"})));
    assert_eq!(rig.d.probe_settings, Some(("9.9.9.9".into(), 500)));
    let ping_targets: Vec<String> = rig
        .d
        .probes
        .iter()
        .filter_map(|p| match p {
            AnyProbe::Ping(p) => Some(p.target.clone()),
            AnyProbe::Tcp(_) => None,
        })
        .collect();
    assert_eq!(ping_targets, ["192.0.2.1", "9.9.9.9"]);
    assert!(calls.lock().unwrap().iter().all(|a| a == "9.9.9.9"));
}

fn rebuilt_by(current: Value, fresh: Value) -> bool {
    let route = Arc::new(Mutex::new(snapshot(fresh.clone())));
    let calls = Arc::default();
    let mut rig = answering(&route, &calls);
    rig.d.route = snapshot(current);
    let local = Arc::clone(&rig.d.local);
    rig.d.restart_probes_if_route_changed(Some(snapshot(fresh))).unwrap();
    !Arc::ptr_eq(&local, &rig.d.local)
}

#[test]
fn a_roam_keeps_the_series() {
    let here = json!({"gateway": "192.168.10.1", "iface": "wlo1"});
    assert!(!rebuilt_by(here.clone(), here));
}

#[test]
fn a_different_gateway_resets() {
    assert!(rebuilt_by(
        json!({"gateway": "192.168.10.1", "iface": "wlo1"}),
        json!({"gateway": "10.0.0.1", "iface": "wlo1"})
    ));
}

#[test]
fn a_different_interface_resets() {
    assert!(rebuilt_by(
        json!({"gateway": "192.168.10.1", "iface": "wlo1"}),
        json!({"gateway": "192.168.10.1", "iface": "eth0"})
    ));
}

#[test]
fn losing_the_route_is_an_outage_not_a_new_network() {
    assert!(!rebuilt_by(
        json!({"gateway": "192.168.10.1", "iface": "wlo1"}),
        json!({"gateway": null, "iface": "wlo1"})
    ));
}

#[test]
fn a_new_gateway_is_followed_from_the_link_snapshot() {
    let snap = snapshot(json!({"iface": "wlo1", "gateway": "192.168.1.1", "src": "192.168.1.20",
                               "kind": "wifi", "bssid": "b4:86:18:8c:25:fe"}));
    assert_eq!(
        fresh_route_from(&snap),
        snapshot(json!({"iface": "wlo1", "gateway": "192.168.1.1", "src": "192.168.1.20"}))
    );
    let route = Arc::new(Mutex::new(snapshot(json!({"gateway": "192.168.1.1", "iface": "wlo1"}))));
    let calls = Arc::default();
    let mut rig = answering(&route, &calls);
    rig.d.route = snapshot(json!({"gateway": "192.168.10.1", "iface": "wlo1"}));
    rig.d.link.set_latest(snap);
    let local = Arc::clone(&rig.d.local);
    rig.d.follow_route().unwrap();
    assert!(!Arc::ptr_eq(&local, &rig.d.local));
    // One read of the route: start_probes's own, never a second one to decide.
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn following_the_snapshot_keeps_the_roam_and_outage_rules() {
    let here = snapshot(json!({"gateway": "192.168.10.1", "iface": "wlo1"}));
    for snap in [
        json!({"gateway": "192.168.10.1", "iface": "wlo1", "bssid": "aa:bb"}),
        json!({"iface": "", "gateway": "", "kind": "none"}),
        json!({}),
    ] {
        assert!(!route_differs(&here, &fresh_route_from(&snapshot(snap))));
    }
    let calls = Arc::default();
    let mut rig = answering(&Arc::new(Mutex::new(here.clone())), &calls);
    rig.d.route = here;
    rig.d.link.set_latest(snapshot(json!({})));
    rig.d.follow_route().unwrap();
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn no_gateway_is_an_outage_not_a_new_network() {
    let route = Arc::new(Mutex::new(snapshot(json!({}))));
    let calls = Arc::default();
    let mut rig = answering(&route, &calls);
    rig.d.route = snapshot(json!({"gateway": "192.168.1.1", "iface": "wlan0"}));
    rig.d.wan_ip = Some(snapshot(json!({"ip": "x"})));
    rig.d.wan_ip_at = 1;
    let local = Arc::clone(&rig.d.local);
    rig.d.restart_probes_if_route_changed(None).unwrap();
    assert!(Arc::ptr_eq(&local, &rig.d.local));
    assert_eq!(rig.d.route, snapshot(json!({"gateway": "192.168.1.1", "iface": "wlan0"})));
    assert!(rig.d.wan_ip.is_some());

    *route.lock().unwrap() = snapshot(json!({"gateway": "192.168.1.1", "iface": "wlan0"}));
    rig.d.restart_probes_if_route_changed(None).unwrap();
    assert!(Arc::ptr_eq(&local, &rig.d.local));

    *route.lock().unwrap() = snapshot(json!({"gateway": "10.0.0.1", "iface": "wlan0"}));
    rig.d.restart_probes_if_route_changed(None).unwrap();
    assert!(!Arc::ptr_eq(&local, &rig.d.local));
    assert!(rig.d.wan_ip.is_none());
    let reset = Arc::clone(&rig.d.local);
    rig.d.restart_probes_if_route_changed(None).unwrap();
    assert!(Arc::ptr_eq(&reset, &rig.d.local));
}

#[test]
fn one_test_at_a_time() {
    assert!(tests_idle(false, false));
    assert!(!tests_idle(true, false));
    assert!(!tests_idle(false, true));
}

#[test]
fn the_crate_version_is_the_manifest_version() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json")).unwrap();
    let manifest: Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn notifications_go_through_the_desktop_tools_as_python_sends_them() {
    let both = |_: &str| true;
    assert_eq!(
        crate::daemon::run::notify_command("No internet", "body", true, &both).unwrap(),
        ["omarchy-notification-send", "No internet", "body"]
    );
    let plain = |name: &str| name == "notify-send";
    assert_eq!(
        crate::daemon::run::notify_command("No internet", "body", true, &plain).unwrap(),
        ["notify-send", "-a", "Nexthop", "-u", "critical", "No internet", "body"]
    );
    assert_eq!(
        crate::daemon::run::notify_command("Back", "body", false, &plain).unwrap(),
        ["notify-send", "-a", "Nexthop", "Back", "body"]
    );
    assert_eq!(crate::daemon::run::notify_command("x", "y", false, &|_| false), None);
}
