use super::diag::{DiagSock, TcpInfo};
use super::owners::Owner;
use super::*;
use std::collections::HashMap;

mod live;
mod netlink;
mod proc_owners;

struct Fixture {
    records: Vec<DiagSock>,
    owners: HashMap<u32, Owner>,
}

impl Fixture {
    fn new() -> Self {
        Self { records: Vec::new(), owners: HashMap::new() }
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        local: &str,
        peer: &str,
        owner: Option<(&str, i32)>,
        rtt_us: u32,
        min_rtt_us: u32,
        sent: u64,
        recv: u64,
        retrans: u64,
    ) {
        let inode = self.records.len() as u32 + 100;
        if let Some((name, pid)) = owner {
            self.owners.insert(inode, Owner { pid, name: name.to_string() });
        }
        self.records.push(DiagSock {
            local: local.parse().unwrap(),
            peer: peer.parse().unwrap(),
            ifindex: 0,
            inode,
            info: Some(TcpInfo { rtt_us, min_rtt_us, bytes_sent: sent, bytes_received: recv, bytes_retrans: retrans }),
        });
    }

    fn parse(&self) -> Socks {
        self.parse_capped(10_000)
    }

    fn parse_capped(&self, max_sockets: usize) -> Socks {
        socks_from(&self.records, |ino| self.owners.get(&ino), max_sockets)
    }
}

fn fixture() -> Fixture {
    let mut f = Fixture::new();
    let me = "192.0.2.10";
    f.add(&format!("{me}:36900"), "198.51.100.7:443", Some(("chrome", 4958)), 12_800, 8_412, 328_028, 2_724_692, 0);
    f.add(&format!("{me}:54430"), "203.0.113.9:443", Some(("slack", 7753)), 31_200, 29_004, 14_099, 65_451, 108);
    f.add(&format!("{me}:39590"), "198.51.100.7:443", Some(("chrome", 4958)), 15_000, 6_550, 4_858, 8_142, 0);
    f.add(&format!("{me}:41000"), "203.0.113.20:22", None, 10_000, 0, 999, 888, 0);
    f
}

fn guards() -> Fixture {
    let mut f = Fixture::new();
    let peer = "198.51.100.7:443";
    f.add("192.0.2.10:36900", peer, Some(("good-a", 1001)), 20_000, 10_000, 40_000, 120_000, 0);
    f.add("192.0.2.10:36901", peer, Some(("good-b", 1002)), 34_000, 14_000, 9_000, 31_000, 0);
    f.add("192.0.2.10:36902", peer, Some(("good-c", 1003)), 120_500, 100_500, 8_000, 90_000, 2_400);
    f.add("192.0.2.10:36903", peer, Some(("tiny", 1004)), 9_000, 5_000, 500, 900, 0);
    f.add("192.0.2.10:36904", peer, Some(("no-timing", 1005)), 0, 0, 50_000, 70_000, 0);
    f.add("192.0.2.10:36905", peer, Some(("implausible", 1006)), 99_999_000, 12_000_000, 60_000, 80_000, 0);
    f.add("192.0.2.10:36906", peer, Some(("inverted", 1007)), 11_000, 40_000, 70_000, 90_000, 0);
    f
}

fn key(n: u16) -> SockKey {
    SockKey {
        local: SocketAddr::from(([192, 0, 2, 10], n)),
        peer: SocketAddr::from(([198, 51, 100, 7], 443)),
        ifindex: 0,
        pid: n as i32,
    }
}

fn timed(app: &str, pid: i32, srtt: f64, minrtt: f64) -> Sock {
    Sock { srtt: Some(srtt), minrtt: Some(minrtt), ..Sock::new(app, pid, 50_000, 50_000) }
}

fn socks(items: Vec<Sock>) -> Socks {
    let mut out = Socks::default();
    for (i, s) in items.into_iter().enumerate() {
        out.insert(key(i as u16), s);
    }
    out
}

fn grown(base: &Socks, sent: u64, recv: u64) -> Socks {
    let mut out = Socks::default();
    for (k, v) in base.iter() {
        out.insert(*k, Sock { sent: v.sent + sent, recv: v.recv + recv, ..v.clone() });
    }
    out
}

fn by_name(t: &AppTraffic) -> HashMap<String, AppRate> {
    t.rates.iter().map(|a| (a.name.clone(), a.clone())).collect()
}

#[test]
fn socks_from_records_skips_unowned_sockets() {
    let socks = fixture().parse();
    assert_eq!(socks.len(), 3);
    let mut apps: Vec<&str> = socks.values().map(|s| s.app.as_str()).collect();
    apps.sort();
    apps.dedup();
    assert_eq!(apps, ["chrome", "slack"]);
    let chrome_rx: u64 = socks.values().filter(|s| s.app == "chrome").map(|s| s.recv).sum();
    assert_eq!(chrome_rx, 2_724_692 + 8_142);
}

#[test]
fn rates_are_deltas_not_lifetimes() {
    let mut t = AppTraffic::new();
    let base = fixture().parse();
    t.fold(base.clone(), 100.0);
    assert!(t.rates.is_empty());
    t.fold(grown(&base, 1000, 3000), 103.0);
    let by = by_name(&t);
    assert!((by["chrome"].rx_bps - 2.0 * 3000.0 / 3.0).abs() <= 1.0);
    assert_eq!(by["chrome"].conns, 2);
    assert_eq!(by["slack"].rx_total, 3000);
}

#[test]
fn socks_from_records_reads_kernel_timing() {
    let socks = fixture().parse();
    let slack = socks.values().find(|s| s.app == "slack").unwrap();
    assert_eq!(slack.srtt, Some(31.2));
    assert_eq!(slack.minrtt, Some(29.004));
    assert_eq!(slack.retrans, 108);
    let mut f = Fixture::new();
    f.add("192.0.2.10:1", "198.51.100.7:443", Some(("x", 9)), 0, 0, 99_999, 99_999, 0);
    let untimed = f.parse();
    let s = untimed.values().next().unwrap();
    assert_eq!(s.srtt, None);
    assert_eq!(s.minrtt, None);
}

#[test]
fn latency_stats_from_fixture() {
    let st = latency_stats(fixture().parse().values()).unwrap();
    assert_eq!(st.sockets, 3);
    assert_eq!(st.rejected, 0);
    assert_eq!(st.rtt_p50, 15.0);
    assert_eq!(st.floor_p50, 8.41);
    // median of 12.8-8.412, 31.2-29.004, 15.0-6.55
    assert_eq!(st.queue_p50, 4.39);
    assert_eq!(st.retrans_sockets, 1);
}

#[test]
fn queueing_divides_out_distance() {
    let near = timed("near", 1, 15.0, 5.0);
    let far = timed("far", 2, 310.0, 300.0);
    assert_eq!(socket_timing(&near).unwrap().2, socket_timing(&far).unwrap().2);
    let st = latency_stats(&[near, far, timed("mid", 3, 60.0, 50.0)]).unwrap();
    assert_eq!(st.queue_p50, 10.0);
    assert_eq!(st.rtt_p50, 60.0);
    assert_eq!(st.floor_p50, 50.0);
}

#[test]
fn guards_reject_implausible_and_thin_sockets() {
    let socks = guards().parse();
    assert_eq!(socks.len(), 7);
    let st = latency_stats(socks.values()).unwrap();
    assert_eq!(st.sockets, 3);
    assert_eq!(st.rejected, 3);
    assert_eq!(socks.values().filter(|s| s.srtt.is_none()).count(), 1);
    assert_eq!(st.retrans_sockets, 1);
}

#[test]
fn each_guard_individually() {
    let ok = timed("ok", 1, 20.0, 10.0);
    assert!(socket_timing(&ok).is_some());
    assert!(socket_timing(&Sock { sent: 100, recv: 100, ..ok.clone() }).is_none());
    assert!(socket_timing(&Sock { srtt: Some(99_999.0), ..ok.clone() }).is_none());
    assert!(socket_timing(&Sock { minrtt: Some(40.0), ..ok.clone() }).is_none());
    assert!(socket_timing(&Sock { srtt: Some(20.0), minrtt: Some(20.02), ..ok.clone() }).is_some());
    assert!(socket_timing(&Sock { srtt: Some(0.0), ..ok.clone() }).is_none());
    assert!(socket_timing(&Sock { minrtt: None, ..ok.clone() }).is_none());
}

#[test]
fn under_sampled_publishes_nothing() {
    let mut two = vec![timed("a", 1, 20.0, 10.0), timed("b", 2, 22.0, 11.0)];
    assert!(latency_stats(&two).is_none());
    two.push(timed("c", 3, 24.0, 12.0));
    assert!(latency_stats(&two).is_some());
    assert!(latency_stats(&[] as &[Sock]).is_none());
}

#[test]
fn per_app_timing_medians() {
    let mut t = AppTraffic::new();
    let base = guards().parse();
    t.fold(base.clone(), 100.0);
    t.fold(grown(&base, 500, 500), 103.0);
    let by = by_name(&t);
    assert_eq!(by["good-a"].rtt_ms, Some(20.0));
    assert_eq!(by["good-a"].queue_ms, Some(10.0));
    assert_eq!(by["good-c"].queue_ms, Some(20.0));
    assert_eq!(by["tiny"].rtt_ms, None);
    assert_eq!(by["no-timing"].rtt_ms, None);
    assert_eq!(by["inverted"].queue_ms, None);
    assert_eq!(t.latency.as_ref().unwrap().sockets, 3);
}

#[test]
fn idle_apps_report_no_timing() {
    let mut t = AppTraffic::new();
    let base = fixture().parse();
    t.fold(base.clone(), 100.0);
    t.fold(base, 103.0);
    t.fold(Socks::default(), 106.0);
    let idle: HashMap<String, AppRate> = t.top(8).into_iter().map(|a| (a.name.clone(), a)).collect();
    assert_eq!(idle["chrome"].rtt_ms, None);
    assert_eq!(idle["chrome"].queue_ms, None);
}

#[test]
fn socket_cap_bounds_parsing() {
    let mut f = Fixture::new();
    for i in 0..3000u32 {
        let name = format!("app{}", i % 7);
        f.add(
            &format!("192.0.2.10:{}", 10_000 + i),
            "198.51.100.7:443",
            Some((&name, 100 + i as i32)),
            0,
            0,
            100,
            200,
            0,
        );
    }
    assert_eq!(f.parse_capped(50).len(), 50);
}

#[test]
fn new_socket_counts_whole_life() {
    let mut t = AppTraffic::new();
    t.fold(Socks::default(), 100.0);
    t.fold(fixture().parse(), 103.0);
    assert_eq!(by_name(&t)["slack"].rx_total, 65_451);
}

#[test]
fn top_ranks_busiest_then_idle_by_session_total() {
    let mut t = AppTraffic::new();
    t.fold(Socks::default(), 100.0);
    let first =
        socks(vec![Sock::new("small", 1, 10, 10), Sock::new("big", 2, 1_000_000, 0), Sock::new("mid", 3, 1000, 1000)]);
    t.fold(first.clone(), 103.0);
    t.fold(socks(vec![Sock { sent: 20, ..Sock::new("small", 1, 10, 10) }]), 106.0);
    let names: Vec<String> = t.top(8).into_iter().map(|a| a.name).collect();
    assert_eq!(names, ["small", "big", "mid"]);
    assert_eq!(t.top(2).len(), 2);
    let small = &t.top(1)[0];
    assert_eq!(small.hist, vec![[3.3, 3.3], [0.0, 3.3]]);
    assert_eq!(t.history.get("big").unwrap().len(), 2);
}

#[test]
fn apps_tracked_are_bounded_by_dropping_the_quietest_idle_ones() {
    let mut t = AppTraffic::new();
    t.fold(Socks::default(), 0.0);
    for i in 1..=100u16 {
        let mut fresh = Socks::default();
        fresh.insert(key(i), Sock::new(&format!("app{i}"), i as i32, 0, 1000 + u64::from(i)));
        t.fold(fresh, 3.0 * f64::from(i));
    }
    assert_eq!(t.totals.len(), AppTraffic::MAX_APPS);
    assert_eq!(t.history.len(), AppTraffic::MAX_APPS);
    assert!(t.totals.get("app100").is_some());
    assert!(t.totals.get("app99").is_some());
    assert!(t.totals.get("app1").is_none());
    assert_eq!(t.top(8)[0].name, "app100");
}

#[test]
fn history_keeps_twenty_intervals() {
    let mut t = AppTraffic::new();
    let base = socks(vec![Sock::new("a", 1, 0, 0)]);
    t.fold(base.clone(), 0.0);
    for i in 1..=25u64 {
        t.fold(socks(vec![Sock::new("a", 1, 0, 3 * i)]), 3.0 * i as f64);
    }
    assert_eq!(t.top(1)[0].hist.len(), AppTraffic::HISTORY);
}

#[test]
fn json_shapes_match_python_keys() {
    let mut t = AppTraffic::new();
    t.fold(Socks::default(), 100.0);
    t.fold(guards().parse(), 103.0);
    let app = serde_json::to_value(&t.top(1)[0]).unwrap();
    let keys: Vec<&str> = app.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["name", "rx_bps", "tx_bps", "conns", "rx_total", "tx_total", "hist", "rtt_ms", "queue_ms"]);
    let lat = serde_json::to_value(t.latency.as_ref().unwrap()).unwrap();
    let keys: Vec<&str> = lat.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["sockets", "rejected", "rtt_p50", "rtt_p95", "floor_p50", "queue_p50", "queue_p95", "retrans_sockets"]
    );
}

#[test]
fn ss_user_follows_the_python_users_regex() {
    assert_eq!(ss_user("chrome", 4958), Some(("chrome".to_string(), 4958)));
    assert_eq!(ss_user("", 1), None);
    assert_eq!(ss_user("a\"b", 1), None);
    assert_eq!(ss_user("\"ab", 1), None);
    assert_eq!(ss_user("x\",pid=12", 99), Some(("x".to_string(), 12)));
    assert_eq!(ss_user("x\",pid=", 99), None);
    assert_eq!(ss_user("two\nlines", 1), None);
    assert_eq!(ss_user("sep\u{2028}x", 1), None);
    assert_eq!(ss_user("Web Content", 7), Some(("Web Content".to_string(), 7)));
}

#[test]
fn ss_ms_keeps_six_significant_digits_like_percent_g() {
    assert_eq!(ss_ms(0), None);
    assert_eq!(ss_ms(12_800), Some(12.8));
    assert_eq!(ss_ms(29_004), Some(29.004));
    assert_eq!(ss_ms(1_234_567), Some(1234.57));
    // an unsampled min_rtt is ~0U: 4294967.295 printed as 4.29497e+06
    assert_eq!(ss_ms(u32::MAX), Some(4_294_970.0));
}

#[test]
fn records_without_tcp_info_or_bytes_are_skipped() {
    let mut f = fixture();
    f.records[0].info = None;
    f.records[1].info = Some(TcpInfo { bytes_sent: 0, bytes_received: 0, ..f.records[1].info.unwrap() });
    f.records[2].inode = 0;
    assert!(f.parse().is_empty());
}
