use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use super::rtnl::RouteRow;
use super::trace::py_ip_address;
use crate::pyjson::text;
use crate::util::py_strip;

pub const SYS_NET: &str = "/sys/class/net";
pub const TUNNEL_LINK_TYPES: [i64; 3] = [65534, 512, 768];
pub const ROUTE_TABLE_MAX_BYTES: usize = 1 << 20;

const TETHER_RANGES: [([u8; 4], u32, &str, &str); 4] = [
    ([172, 20, 10, 0], 28, "ios", "iPhone"),
    ([192, 168, 43, 0], 24, "android", "Phone"),
    ([192, 168, 42, 0], 24, "android", "Phone"),
    ([192, 168, 137, 0], 24, "windows", "Hotspot"),
];

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Tether {
    pub kind: &'static str,
    pub label: &'static str,
}

pub fn tether_from_gateway(gateway: &str) -> Option<Tether> {
    let IpAddr::V4(addr) = py_ip_address(gateway)?.addr else {
        return None;
    };
    let bits = u32::from(addr);
    TETHER_RANGES.iter().find_map(|&(net, prefix, kind, label)| {
        let mask = u32::MAX << (32 - prefix);
        (bits & mask == u32::from(Ipv4Addr::from(net))).then_some(Tether { kind, label })
    })
}

pub fn iface_ok(iface: &str) -> bool {
    let n = iface.len();
    (1..=15).contains(&n)
        && iface.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:@-".contains(&b))
        && iface != "."
        && iface != ".."
}

pub fn sys_read(iface: &str, name: &str, sys_net: &str) -> Option<String> {
    if !iface_ok(iface) {
        return None;
    }
    let buf = crate::util::read_capped(format!("{sys_net}/{iface}/{name}"), 4096).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

pub fn is_tunnel_link(iface: &str, sys_net: &str) -> bool {
    sys_read(iface, "type", sys_net)
        .and_then(|raw| py_strip(&raw).parse::<i64>().ok())
        .is_some_and(|t| TUNNEL_LINK_TYPES.contains(&t))
}

pub fn tunnel_type(iface: &str, sys_net: &str) -> &'static str {
    let uevent = sys_read(iface, "uevent", sys_net).unwrap_or_default();
    if uevent.contains("DEVTYPE=wireguard") {
        return "wireguard";
    }
    if sys_read(iface, "tun_flags", sys_net).is_some() {
        return if iface.starts_with("tailscale") { "tailscale" } else { "tun" };
    }
    let raw = sys_read(iface, "type", sys_net).unwrap_or_default();
    if py_strip(&raw) == "512" { "ppp" } else { "tunnel" }
}

fn is_host_route(dst: &str) -> bool {
    py_ip_address(dst).is_some_and(|ip| ip.addr.is_ipv4())
}

pub fn route_map(iface: &str, gateway: &str, src: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("iface".into(), iface.into());
    m.insert("gateway".into(), gateway.into());
    m.insert("src".into(), src.into());
    m
}

pub fn line_route(rows: Option<&[RouteRow]>, sys_net: &str) -> Map<String, Value> {
    let rows: Vec<&RouteRow> = rows.unwrap_or_default().iter().filter(|r| iface_ok(&r.dev)).collect();
    let pick = |candidates: Vec<(usize, &RouteRow)>| -> Option<RouteRow> {
        candidates.into_iter().min_by_key(|(i, r)| (r.metric, *i)).map(|(_, r)| r.clone())
    };
    let as_line = |r: RouteRow| route_map(&r.dev, &r.gateway, &r.prefsrc);
    let defaults: Vec<(usize, &RouteRow)> =
        rows.iter().copied().enumerate().filter(|(_, r)| r.dst == "default").collect();
    if defaults.is_empty() {
        return Map::new();
    }
    let physical: Vec<_> =
        defaults.iter().copied().filter(|(_, r)| !r.gateway.is_empty() && !is_tunnel_link(&r.dev, sys_net)).collect();
    if let Some(r) = pick(physical) {
        return as_line(r);
    }
    let Some(d) = pick(defaults) else {
        return Map::new();
    };
    let underlay: Vec<_> = rows
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, r)| is_host_route(&r.dst) && !r.gateway.is_empty() && r.dev != d.dev)
        .collect();
    match pick(underlay) {
        Some(r) => as_line(r),
        None => as_line(d),
    }
}

pub fn local_route_from(
    r: Map<String, Value>,
    sys_net: &str,
    routes: &mut dyn FnMut() -> Option<Vec<RouteRow>>,
) -> Map<String, Value> {
    let iface = text(&r, "iface");
    if iface.is_empty() || !is_tunnel_link(iface, sys_net) {
        return r;
    }
    let table = routes();
    let mut line = line_route(table.as_deref(), sys_net);
    if line.is_empty() || text(&line, "iface") == iface {
        return r;
    }
    line.insert("tunnel_iface".into(), iface.into());
    line
}

pub fn no_lookup(_host: &str) -> Option<String> {
    None
}

fn first_address(host: &str, resolve: &mut dyn FnMut(&str) -> Option<String>) -> Option<String> {
    if py_ip_address(host).is_some() {
        return Some(host.to_string());
    }
    resolve(host)
}

pub fn tunnel_routes_with(
    targets: &BTreeMap<String, String>,
    physical_iface: &str,
    sys_net: &str,
    route: &mut dyn FnMut(&str) -> Map<String, Value>,
    resolve: &mut dyn FnMut(&str) -> Option<String>,
) -> Option<Map<String, Value>> {
    let mut via: Vec<String> = Vec::new();
    let mut ifaces: BTreeMap<String, usize> = BTreeMap::new();
    let mut probed = 0usize;
    for (key, host) in targets {
        let Some(addr) = first_address(host, resolve) else {
            continue;
        };
        let r = route(&addr);
        let iface = text(&r, "iface");
        if iface.is_empty() {
            continue;
        }
        probed += 1;
        if iface != physical_iface && is_tunnel_link(iface, sys_net) {
            via.push(key.clone());
            *ifaces.entry(iface.to_string()).or_default() += 1;
        }
    }
    if via.is_empty() {
        return None;
    }
    let best = ifaces.values().copied().max().unwrap_or(0);
    let iface = ifaces.iter().find(|(_, n)| **n == best).map(|(i, _)| i.clone()).unwrap_or_default();
    let kind = tunnel_type(&iface, sys_net);
    let mut out = Map::new();
    out.insert("iface".into(), iface.into());
    out.insert("type".into(), kind.into());
    out.insert("scope".into(), if via.len() == probed { "full" } else { "partial" }.into());
    out.insert("via".into(), via.into());
    out.insert("probed".into(), probed.into());
    Some(out)
}
