use super::super::*;
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

struct SsSock {
    app: String,
    sent: u64,
    recv: u64,
    srtt: Option<f64>,
    minrtt: Option<f64>,
    retrans: u64,
}

fn field<T: std::str::FromStr>(line: &str, name: &str) -> Option<T> {
    line.split_whitespace().find_map(|w| w.strip_prefix(name)?.parse().ok())
}

fn strip_iface(addr: &str) -> String {
    match addr.find('%') {
        Some(i) => format!("{}{}", &addr[..i], &addr[addr.rfind(':').unwrap()..]),
        None => addr.to_string(),
    }
}

fn ss_now() -> HashMap<String, SsSock> {
    let out = Command::new("ss").arg("-tinpH").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut socks = HashMap::new();
    let mut head: Option<(String, String)> = None;
    for line in text.lines() {
        if !line.starts_with(['\t', ' ']) {
            head = None;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(u) = line.find("users:((\"") {
                let rest = &line[u + 9..];
                let q = rest.find('"').unwrap();
                let pid: String = rest[q + 6..].chars().take_while(char::is_ascii_digit).collect();
                let key = format!("{}>{}#{pid}", strip_iface(parts[3]), strip_iface(parts[4]));
                head = Some((key, rest[..q].to_string()));
            }
            continue;
        }
        let Some((key, app)) = head.take() else {
            continue;
        };
        let sent = field(line, "bytes_sent:").unwrap_or(0);
        let recv = field(line, "bytes_received:").unwrap_or(0);
        if sent == 0 && recv == 0 {
            continue;
        }
        let rtt = line.split_whitespace().find_map(|w| w.strip_prefix("rtt:"));
        socks.insert(
            key,
            SsSock {
                app,
                sent,
                recv,
                srtt: rtt.and_then(|r| r.split('/').next()?.parse().ok()),
                minrtt: field(line, "minrtt:"),
                retrans: field(line, "bytes_retrans:").unwrap_or(0),
            },
        );
    }
    socks
}

fn ours_by_text(socks: &Socks) -> HashMap<String, Sock> {
    socks.iter().map(|(k, s)| (format!("{}>{}#{}", k.local, k.peer, k.pid), s.clone())).collect()
}

#[test]
#[ignore]
fn live_compare_with_ss() {
    let mut t = AppTraffic::new();
    let c0 = Instant::now();
    t.sample().unwrap();
    let cold = c0.elapsed();
    let ss = ss_now();
    let w0 = Instant::now();
    let ours = ours_by_text(&t.sample().unwrap());
    let warm = w0.elapsed();

    let (mut same, mut owner_diff, mut max_byte_diff, mut timing_diff) = (0, 0, 0u64, 0);
    for (k, s) in &ours {
        let Some(o) = ss.get(k) else {
            println!("only ours: {k} {} sent={} recv={}", s.app, s.sent, s.recv);
            continue;
        };
        same += 1;
        if o.app != s.app {
            owner_diff += 1;
            println!("owner differs: {k} ours={} ss={}", s.app, o.app);
        }
        max_byte_diff = max_byte_diff.max(o.sent.abs_diff(s.sent)).max(o.recv.abs_diff(s.recv));
        if (o.srtt, o.minrtt, o.retrans) != (s.srtt, s.minrtt, s.retrans) {
            timing_diff += 1;
        }
    }
    for (k, o) in &ss {
        if !ours.contains_key(k) {
            println!("only ss: {k} {} sent={} recv={}", o.app, o.sent, o.recv);
        }
    }
    println!(
        "ours={} ss={} matched={same} owner_diff={owner_diff} max_byte_diff={max_byte_diff} timing_changed={timing_diff}",
        ours.len(),
        ss.len()
    );
    println!("cold sample (full /proc scan) {cold:?}, warm sample {warm:?}, scans so far {}", t.owners.scans);
    assert!(same * 10 >= ss.len().max(ours.len()) * 9, "socket sets diverge");
    assert_eq!(owner_diff, 0);

    assert!(t.poll());
    std::thread::sleep(Duration::from_secs(3));
    let p0 = Instant::now();
    assert!(t.poll());
    let one_poll = p0.elapsed();
    println!("top(8): {}", serde_json::to_string_pretty(&t.top(8)).unwrap());
    println!("latency: {}", serde_json::to_string(&t.latency).unwrap());
    println!("one poll {one_poll:?}, scans {}", t.owners.scans);

    let n = 20;
    let s0 = Instant::now();
    for _ in 0..n {
        t.sample().unwrap();
    }
    let per_sample = s0.elapsed() / n;
    let e0 = Instant::now();
    for _ in 0..n {
        Command::new("ss").arg("-tinpH").output().unwrap();
    }
    let per_ss = e0.elapsed() / n;
    println!("mean sample {per_sample:?} vs ss -tinpH spawn+run {per_ss:?}, scans {}", t.owners.scans);
}

#[test]
#[ignore]
fn live_profile_sample() {
    let mut o = owners::Owners::new();
    for _ in 0..3 {
        let t0 = Instant::now();
        let recs = diag::dump(AppTraffic::MAX_DIAG_BYTES, monotonic() + 1.5).unwrap();
        let t1 = Instant::now();
        o.resolve(recs.iter().map(|r| r.inode), monotonic() + 1.5);
        let t2 = Instant::now();
        println!("records {} dump {:?} resolve {:?} scans {}", recs.len(), t1 - t0, t2 - t1, o.scans);
    }
}
