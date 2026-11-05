pub mod genl;
mod inventory;
mod iw;
mod names;
pub mod netlink;
pub mod nl80211;
mod routes;
mod rtnl;
mod run;
mod trace;
mod unicode;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_live;
#[cfg(test)]
mod tests_nl;
#[cfg(test)]
mod tests_routes;

use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

use crate::pyjson::text;

pub use inventory::ApInventory;
pub use iw::{iw_link_text, parse_link, render_link_scan, station_map};
pub use names::{NAME_CACHE_TTL_S, NameCache, NameKey, decorate_bssids, nm_metered};
pub use netlink::NlError;
pub use nl80211::Nl80211;
pub use routes::{ROUTE_TABLE_MAX_BYTES, SYS_NET, Tether, no_lookup, tether_from_gateway, tunnel_routes_with};
pub use rtnl::{RouteRow, Rtnl};
pub use trace::reachability;

pub type Snapshot = Map<String, Value>;

pub fn is_wireless(iface: &str) -> bool {
    !iface.is_empty() && Path::new(&format!("{SYS_NET}/{iface}/wireless")).is_dir()
}

pub fn counters(iface: &str) -> Option<(u64, u64)> {
    if iface.is_empty() {
        return None;
    }
    let read = |name: &str| -> Option<u64> {
        let raw = std::fs::read_to_string(format!("{SYS_NET}/{iface}/statistics/{name}")).ok()?;
        crate::util::py_strip(&raw).parse().ok()
    };
    Some((read("rx_bytes")?, read("tx_bytes")?))
}

pub trait LinkSource {
    fn is_wireless(&mut self, iface: &str) -> bool;
    fn wifi(&mut self, iface: &str) -> (Snapshot, Snapshot);
    fn ap_name(&mut self, bssid: &str) -> Option<String>;
    fn connection_name_cached(&mut self, iface: &str, key: &NameKey) -> String;
}

pub fn snapshot_from(route: Snapshot, source: &mut dyn LinkSource) -> Snapshot {
    let iface = text(&route, "iface").to_string();
    let mut snap = Map::new();
    snap.insert("iface".into(), iface.clone().into());
    snap.insert("gateway".into(), text(&route, "gateway").into());
    snap.insert("src".into(), text(&route, "src").into());
    snap.insert("tunnel_iface".into(), text(&route, "tunnel_iface").into());
    snap.insert("kind".into(), "none".into());
    if iface.is_empty() {
        return snap;
    }
    let wireless = source.is_wireless(&iface);
    snap.insert("kind".into(), if wireless { "wifi" } else { "ethernet" }.into());
    if wireless {
        let (link, station) = source.wifi(&iface);
        snap.extend(link);
        snap.insert("station".into(), Value::Object(station));
        let bssid = text(&snap, "bssid").to_string();
        if let Some(name) = source.ap_name(&bssid).filter(|n| !n.is_empty()) {
            snap.insert("ap_name".into(), name.into());
        }
    }
    let key = (iface.clone(), text(&snap, "gateway").to_string(), text(&snap, "bssid").to_string());
    let name = source.connection_name_cached(&iface, &key);
    snap.insert("name".into(), if name.is_empty() { iface } else { name }.into());
    snap
}

pub struct NetReader {
    rtnl: Rtnl,
    wifi: Option<Nl80211>,
    pub inventory: ApInventory,
    pub names: NameCache,
}

impl NetReader {
    pub fn new() -> std::io::Result<Self> {
        Ok(NetReader {
            rtnl: Rtnl::open()?,
            wifi: None,
            inventory: ApInventory::new(None),
            names: NameCache::default(),
        })
    }

    pub fn route_to(&mut self, anchor: &str) -> Snapshot {
        let Some(addr) = rtnl::parse_destination(anchor) else {
            return Map::new();
        };
        match self.rtnl.route_get(addr) {
            Ok(r) => routes::route_map(&r.dev, &r.gateway, &r.prefsrc),
            Err(_) => Map::new(),
        }
    }

    pub fn main_table(&mut self) -> Option<Vec<RouteRow>> {
        self.rtnl.main_table(ROUTE_TABLE_MAX_BYTES).ok()
    }

    pub fn local_route(&mut self, anchor: &str) -> Snapshot {
        let r = self.route_to(anchor);
        routes::local_route_from(r, SYS_NET, &mut || self.main_table())
    }

    pub fn tunnel_routes(
        &mut self,
        targets: &BTreeMap<String, String>,
        physical_iface: &str,
        resolve: &mut dyn FnMut(&str) -> Option<String>,
    ) -> Option<Snapshot> {
        tunnel_routes_with(targets, physical_iface, SYS_NET, &mut |a| self.route_to(a), resolve)
    }

    fn nl80211(&mut self) -> Option<&mut Nl80211> {
        if self.wifi.is_none() {
            self.wifi = Nl80211::open().ok();
        }
        self.wifi.as_mut()
    }

    fn wifi_read(&mut self, iface: &str) -> (Snapshot, Snapshot) {
        let Some(index) = self.rtnl.ifindex(iface) else {
            return (Map::new(), Map::new());
        };
        let Some(nl) = self.nl80211() else {
            return (Map::new(), Map::new());
        };
        let scan = nl.scan_dump(index);
        let stations = nl.station_dump(index);
        let broken = matches!(&scan, Err(NlError::Io(_))) || matches!(&stations, Err(NlError::Io(_)));
        let link = match (&scan, &stations) {
            (Ok(bsses), Ok(st)) => iw_link_text(bsses, st, iface).map(|t| parse_link(&t)).unwrap_or_default(),
            (Ok(bsses), Err(_)) => {
                let rendered = render_link_scan(bsses, iface);
                if rendered.sta_addr.is_none() { parse_link(&rendered.text) } else { Map::new() }
            }
            _ => Map::new(),
        };
        let station = stations.as_deref().map(station_map).unwrap_or_default();
        if broken {
            self.wifi = None;
        }
        (link, station)
    }

    pub fn snapshot(&mut self, anchor: &str) -> Snapshot {
        let route = self.local_route(anchor);
        snapshot_from(route, self)
    }
}

impl LinkSource for NetReader {
    fn is_wireless(&mut self, iface: &str) -> bool {
        is_wireless(iface)
    }

    fn wifi(&mut self, iface: &str) -> (Snapshot, Snapshot) {
        self.wifi_read(iface)
    }

    fn ap_name(&mut self, bssid: &str) -> Option<String> {
        self.inventory.lookup(bssid)
    }

    fn connection_name_cached(&mut self, iface: &str, key: &NameKey) -> String {
        self.names.connection_name_cached(iface, key, None, NAME_CACHE_TTL_S)
    }
}

pub fn local_route(anchor: &str) -> Snapshot {
    NetReader::new().map(|mut r| r.local_route(anchor)).unwrap_or_default()
}
