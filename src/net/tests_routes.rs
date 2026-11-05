use super::routes::{is_tunnel_link, line_route, local_route_from, tunnel_type};
use super::tests::fixture;
use super::*;
use crate::testutil::{TempDir, obj};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

struct Sys(TempDir);

impl Sys {
    fn new() -> Self {
        let sys = Sys(TempDir::new());
        sys.link("wlo1", 1, "DEVTYPE=wlan\n", None);
        sys.link("docker0", 1, "DEVTYPE=bridge\n", None);
        sys.link("wg0", 65534, "DEVTYPE=wireguard\n", None);
        sys.link("tailscale0", 65534, "", Some("0x5001\n"));
        sys.link("tun0", 65534, "", Some("0x1001\n"));
        sys.link("ppp0", 512, "", None);
        sys.link("ppp1", 512, "", None);
        sys.link("ipip0", 768, "", None);
        sys.link("eth0", 1, "", None);
        sys
    }

    fn link(&self, name: &str, arphrd: u32, uevent: &str, tun_flags: Option<&str>) {
        let d = self.0.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("type"), format!("{arphrd}\n")).unwrap();
        std::fs::write(d.join("uevent"), uevent).unwrap();
        if let Some(flags) = tun_flags {
            std::fs::write(d.join("tun_flags"), flags).unwrap();
        }
    }

    fn path(&self) -> &str {
        self.0.path().to_str().expect("utf-8 temp path")
    }
}

fn rows(text: &str) -> Option<Vec<RouteRow>> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(text) else {
        return None;
    };
    let s = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Some(
        items
            .iter()
            .filter(|r| r.is_object())
            .map(|r| RouteRow {
                dst: s(r, "dst"),
                gateway: s(r, "gateway"),
                dev: s(r, "dev"),
                prefsrc: s(r, "prefsrc"),
                metric: r.get("metric").and_then(Value::as_u64).unwrap_or(0),
            })
            .collect(),
    )
}

fn table(name: &str) -> Option<Vec<RouteRow>> {
    rows(&fixture(&format!("routes/{name}.json")))
}

fn line(text: Option<Vec<RouteRow>>, sys: &Sys) -> Snapshot {
    line_route(text.as_deref(), sys.path())
}

const DEFAULTS: &str = r#"[{"dst":"default","gateway":"10.8.0.1","dev":"tun0","metric":50,"flags":[]},{"dst":"default","gateway":"192.168.10.1","dev":"wlo1","protocol":"dhcp","prefsrc":"192.168.10.219","metric":600,"flags":[]}]"#;

#[test]
fn tunnels_are_known_by_link_type() {
    let sys = Sys::new();
    for name in ["wg0", "tailscale0", "tun0", "ppp0", "ipip0"] {
        assert!(is_tunnel_link(name, sys.path()), "{name}");
    }
    for name in ["wlo1", "docker0", "absent0"] {
        assert!(!is_tunnel_link(name, sys.path()), "{name}");
    }
}

#[test]
fn a_name_that_did_not_come_from_the_kernel_is_not_read() {
    let sys = Sys::new();
    std::fs::write(sys.0.path().join("type"), "65534\n").unwrap();
    let long = "a".repeat(16);
    for bad in ["", "..", ".", "../wg0", "wg0/../wg0", long.as_str(), "wg 0"] {
        assert!(!is_tunnel_link(bad, sys.path()), "{bad:?}");
    }
}

#[test]
fn the_label_comes_from_the_kernel_where_it_can() {
    let sys = Sys::new();
    assert_eq!(tunnel_type("wg0", sys.path()), "wireguard");
    assert_eq!(tunnel_type("tailscale0", sys.path()), "tailscale");
    assert_eq!(tunnel_type("tun0", sys.path()), "tun");
    assert_eq!(tunnel_type("ppp0", sys.path()), "ppp");
    assert_eq!(tunnel_type("ipip0", sys.path()), "tunnel");
}

#[test]
fn a_physical_default_beats_any_tunnel_default() {
    let sys = Sys::new();
    assert_eq!(
        line(rows(DEFAULTS), &sys),
        obj(json!({"iface": "wlo1", "gateway": "192.168.10.1", "src": "192.168.10.219"}))
    );
    assert_eq!(line(table("openvpn-beside-physical-default"), &sys)["iface"], "eth0");
}

#[test]
fn a_replaced_default_is_found_through_the_server_host_route() {
    let sys = Sys::new();
    for name in ["openvpn-replaced-default", "networkmanager-vpn"] {
        let l = line(table(name), &sys);
        assert_eq!((l["iface"].as_str(), l["gateway"].as_str()), (Some("eth0"), Some("192.168.1.1")), "{name}");
    }
}

#[test]
fn pppoe_is_the_line() {
    let l = line(table("pppoe-default"), &Sys::new());
    assert_eq!((l["iface"].as_str(), l["gateway"].as_str()), (Some("ppp0"), Some("")));
}

#[test]
fn a_clat_is_the_line() {
    let l = line(table("clat-default"), &Sys::new());
    assert_eq!((l["iface"].as_str(), l["gateway"].as_str()), (Some("tun0"), Some("")));
}

#[test]
fn a_vpn_over_pppoe_is_found_under_ppp_on_both_sides() {
    let l = line(table("vpn-over-pppoe"), &Sys::new());
    assert_eq!((l["iface"].as_str(), l["gateway"].as_str()), (Some("ppp0"), Some("10.0.0.1")));
}

#[test]
fn host_routes_without_a_gateway_or_on_the_default_s_link_never_qualify() {
    let sys = Sys::new();
    let l = line(table("host-routes-that-never-qualify"), &sys);
    assert_eq!((l["iface"].as_str(), l["gateway"].as_str()), (Some("wg0"), Some("")));
    let same_link = r#"[{"dst":"default","dev":"tun0"},{"dst":"203.0.113.5","gateway":"10.8.0.1","dev":"tun0"}]"#;
    assert_eq!(line(rows(same_link), &sys), obj(json!({"iface": "tun0", "gateway": "", "src": ""})));
}

#[test]
fn a_gatewayed_subnet_route_is_not_a_server_route() {
    let t = r#"[{"dst":"default","dev":"tun0"},{"dst":"10.99.0.0/16","gateway":"192.168.1.1","dev":"eth0"}]"#;
    assert_eq!(line(rows(t), &Sys::new())["iface"], "tun0");
}

#[test]
fn step_one_needs_a_gateway_not_just_a_lower_metric() {
    let t = r#"[{"dst":"default","dev":"eth0","metric":10},{"dst":"default","gateway":"192.168.10.1","dev":"wlo1","metric":600}]"#;
    assert_eq!(line(rows(t), &Sys::new())["iface"], "wlo1");
}

#[test]
fn the_lowest_metric_underlay_wins_and_ties_keep_table_order() {
    let t = r#"[{"dst":"default","dev":"tun0"},
        {"dst":"203.0.113.5","gateway":"192.168.1.1","dev":"eth0","metric":100},
        {"dst":"203.0.113.6","gateway":"192.168.10.1","dev":"wlo1","metric":50},
        {"dst":"203.0.113.7","gateway":"192.168.1.9","dev":"eth0","metric":50}]"#;
    assert_eq!(line(rows(t), &Sys::new())["gateway"], "192.168.10.1");
}

#[test]
fn no_default_is_no_line() {
    let sys = Sys::new();
    assert!(line(table("no-default"), &sys).is_empty());
    assert!(line(None, &sys).is_empty());
    assert!(line(Some(Vec::new()), &sys).is_empty());
}

fn route_of(table: Vec<(&'static str, Value)>) -> impl FnMut(&str) -> Snapshot {
    let table: HashMap<&str, Value> = table.into_iter().collect();
    move |target| table.get(target).map(|v| obj(v.clone())).unwrap_or_default()
}

#[test]
fn an_ordinary_link_costs_no_extra_read() {
    let sys = Sys::new();
    let here = json!({"iface": "wlo1", "gateway": "192.168.10.1", "src": "192.168.10.219"});
    let mut route = route_of(vec![("1.1.1.1", here.clone())]);
    let got = local_route_from(route("1.1.1.1"), sys.path(), &mut || panic!("the main table must not be read"));
    assert_eq!(Value::Object(got), here);
}

fn local(sys: &Sys, anchor_route: Value, routes: Option<Vec<RouteRow>>) -> Snapshot {
    let mut route = route_of(vec![("1.1.1.1", anchor_route)]);
    local_route_from(route("1.1.1.1"), sys.path(), &mut || routes.clone())
}

#[test]
fn under_wg_quick_the_router_is_still_the_physical_gateway() {
    let got = local(&Sys::new(), json!({"iface": "wg0", "gateway": "", "src": "10.66.66.2"}), rows(DEFAULTS));
    assert_eq!(got["iface"], "wlo1");
    assert_eq!(got["gateway"], "192.168.10.1");
    assert_eq!(got["tunnel_iface"], "wg0");
}

#[test]
fn under_openvpn_def1_the_peer_is_not_taken_for_the_router() {
    let got = local(&Sys::new(), json!({"iface": "tun0", "gateway": "10.8.0.1", "src": "10.8.0.6"}), rows(DEFAULTS));
    assert_eq!(got["gateway"], "192.168.10.1");
}

#[test]
fn pppoe_is_the_line_not_a_vpn() {
    let l = json!({"iface": "ppp0", "gateway": "", "src": "203.0.113.7"});
    let got = local(&Sys::new(), l.clone(), table("pppoe-default"));
    assert_eq!(Value::Object(got), l);
}

#[test]
fn a_vpn_that_replaced_the_default_keeps_the_real_router() {
    let tunnel = json!({"iface": "tun0", "gateway": "10.8.0.1", "src": "10.8.0.6"});
    let got = local(&Sys::new(), tunnel, table("openvpn-replaced-default"));
    assert_eq!(
        Value::Object(got),
        json!({"iface": "eth0", "gateway": "192.168.1.1", "src": "", "tunnel_iface": "tun0"})
    );
}

#[test]
fn a_clat_is_not_a_vpn() {
    let got = local(&Sys::new(), json!({"iface": "tun0", "gateway": "", "src": "192.0.0.2"}), table("clat-default"));
    assert!(!got.contains_key("tunnel_iface"));
}

#[test]
fn an_unreadable_table_leaves_the_anchor_route_standing() {
    let tunnel = json!({"iface": "tun0", "gateway": "10.8.0.1", "src": "10.8.0.6"});
    assert_eq!(Value::Object(local(&Sys::new(), tunnel.clone(), None)), tunnel);
}

fn targets() -> BTreeMap<String, String> {
    [
        ("icmp-anchor", "1.1.1.1"),
        ("tcp-anchor", "1.1.1.1"),
        ("tcp-cf", "speed.cloudflare.com"),
        ("tcp-google", "dns.google"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

fn resolver(names: &'static [(&'static str, &'static str)]) -> impl FnMut(&str) -> Option<String> {
    move |host| names.iter().find(|(h, _)| *h == host).map(|(_, a)| a.to_string())
}

const NAMES: &[(&str, &str)] = &[("speed.cloudflare.com", "198.51.100.10"), ("dns.google", "198.51.100.20")];

#[test]
fn a_full_tunnel() {
    let sys = Sys::new();
    let got =
        tunnel_routes_with(&targets(), "wlo1", sys.path(), &mut |_| obj(json!({"iface": "wg0"})), &mut resolver(NAMES));
    let expected = json!({"iface": "wg0", "type": "wireguard", "scope": "full",
        "via": ["icmp-anchor", "tcp-anchor", "tcp-cf", "tcp-google"], "probed": 4});
    let got = got.unwrap();
    assert_eq!(Value::Object(got.clone()), expected);
    assert_eq!(got.keys().collect::<Vec<_>>(), ["iface", "type", "scope", "via", "probed"]);
}

#[test]
fn a_split_tunnel_says_how_much_of_it() {
    let sys = Sys::new();
    let mut route = route_of(vec![
        ("1.1.1.1", json!({"iface": "wlo1"})),
        ("198.51.100.10", json!({"iface": "tun0"})),
        ("198.51.100.20", json!({"iface": "wlo1"})),
    ]);
    let got = tunnel_routes_with(&targets(), "wlo1", sys.path(), &mut route, &mut resolver(NAMES)).unwrap();
    assert_eq!((&got["scope"], &got["via"], &got["probed"]), (&json!("partial"), &json!(["tcp-cf"]), &json!(4)));
}

#[test]
fn a_tunnel_that_carries_no_probe_is_not_a_vpn() {
    let sys = Sys::new();
    let got = tunnel_routes_with(
        &targets(),
        "wlo1",
        sys.path(),
        &mut |_| obj(json!({"iface": "wlo1"})),
        &mut resolver(NAMES),
    );
    assert!(got.is_none());
}

#[test]
fn the_physical_link_itself_is_never_the_tunnel() {
    let sys = Sys::new();
    let got = tunnel_routes_with(
        &targets(),
        "ppp0",
        sys.path(),
        &mut |_| obj(json!({"iface": "ppp0"})),
        &mut resolver(NAMES),
    );
    assert!(got.is_none());
}

#[test]
fn an_unresolvable_target_is_left_out_not_guessed() {
    let sys = Sys::new();
    let got = tunnel_routes_with(&targets(), "wlo1", sys.path(), &mut |_| obj(json!({"iface": "wg0"})), &mut no_lookup);
    let got = got.unwrap();
    assert_eq!((&got["scope"], &got["probed"]), (&json!("full"), &json!(2)));
    assert_eq!(got["via"], json!(["icmp-anchor", "tcp-anchor"]));
}
