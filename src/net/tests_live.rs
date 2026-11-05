use super::names::connection_name;
use super::routes::{is_tunnel_link, line_route};
use super::*;

#[test]
#[ignore]
fn live_snapshot_prints_json() {
    let mut reader = NetReader::new().expect("rtnetlink socket");
    let snap = reader.snapshot("1.1.1.1");
    println!("SNAPSHOT {}", serde_json::to_string(&snap).unwrap());
    let table = reader.main_table().expect("main table");
    println!("MAIN {table:?}");
    println!("LINE {}", serde_json::to_string(&line_route(Some(&table), SYS_NET)).unwrap());
}

#[test]
#[ignore]
fn live_snapshot_cost_per_call() {
    let mut reader = NetReader::new().expect("rtnetlink socket");
    reader.snapshot("1.1.1.1");
    let n = 1000;
    let start = std::time::Instant::now();
    for _ in 0..n {
        std::hint::black_box(reader.snapshot("1.1.1.1"));
    }
    let per = start.elapsed() / n;
    println!("PER_CALL {per:?}");
}

#[test]
#[ignore]
fn live_cost_breakdown() {
    let mut r = NetReader::new().expect("rtnetlink socket");
    r.snapshot("1.1.1.1");
    let n = 1000u32;
    let time = |label: &str, f: &mut dyn FnMut()| {
        let start = std::time::Instant::now();
        for _ in 0..n {
            f();
        }
        println!("COST {label} {:?}", start.elapsed() / n);
    };
    time("route_to", &mut || {
        std::hint::black_box(r.route_to("1.1.1.1"));
    });
    time("tunnel_check", &mut || {
        std::hint::black_box(is_tunnel_link("wlp0s20f3", SYS_NET));
    });
    time("is_wireless", &mut || {
        std::hint::black_box(is_wireless("wlp0s20f3"));
    });
    let mut inv = ApInventory::new(None);
    time("inventory", &mut || {
        std::hint::black_box(inv.lookup("08:3e:5d:f5:a9:a7"));
    });
    let mut nl = Nl80211::open().expect("nl80211");
    time("scan_dump", &mut || {
        std::hint::black_box(nl.scan_dump(2).ok());
    });
    time("station_dump", &mut || {
        std::hint::black_box(nl.station_dump(2).ok());
    });
}

#[test]
#[ignore]
fn live_subprocess_paths() {
    println!("METERED {}", nm_metered("wlp0s20f3"));
    println!("NAME {}", connection_name("wlp0s20f3"));
    println!("REACH {}", serde_json::to_string(&reachability()).unwrap());
    let mut reader = NetReader::new().expect("rtnetlink socket");
    println!("ROUTE_NAME {:?}", reader.route_to("dns.google"));
    println!("ROUTE_SHORT {:?}", reader.route_to("1.1"));
}
