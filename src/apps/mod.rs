pub mod diag;
pub mod owners;
#[cfg(test)]
mod tests;

use serde::Serialize;
use std::borrow::Borrow;
use std::cmp::{Ordering, Reverse};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::io;
use std::net::SocketAddr;

use crate::probes::nearest_rank;
use crate::util::{is_py_line_break, median, monotonic, now, py_round};
use diag::DiagSock;
use owners::{Owner, Owners};

pub const MIN_LATENCY_BYTES: u64 = 4096;
pub const MAX_PLAUSIBLE_RTT_MS: f64 = 10_000.0;
pub const RTT_INVERSION_TOLERANCE_MS: f64 = 0.05;
pub const MIN_LATENCY_SOCKETS: usize = 3;

#[derive(Clone, Debug, PartialEq)]
pub struct Sock {
    pub app: String,
    pub pid: i32,
    pub sent: u64,
    pub recv: u64,
    pub srtt: Option<f64>,
    pub minrtt: Option<f64>,
    pub retrans: u64,
}

#[cfg(test)]
impl Sock {
    pub fn new(app: &str, pid: i32, sent: u64, recv: u64) -> Self {
        Self { app: app.to_string(), pid, sent, recv, srtt: None, minrtt: None, retrans: 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SockKey {
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub ifindex: u32,
    pub pid: i32,
}

#[derive(Clone, Debug)]
pub struct Ordered<K, V> {
    index: HashMap<K, usize>,
    items: Vec<(K, V)>,
}

impl<K: Hash + Eq + Clone, V> Default for Ordered<K, V> {
    fn default() -> Self {
        Self { index: HashMap::new(), items: Vec::new() }
    }
}

impl<K: Hash + Eq + Clone, V> Ordered<K, V> {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn get<Q: Hash + Eq + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.index.get(key).map(|&i| &self.items[i].1)
    }

    pub fn insert(&mut self, key: K, value: V) {
        match self.index.get(&key) {
            Some(&i) => self.items[i].1 = value,
            None => {
                self.index.insert(key.clone(), self.items.len());
                self.items.push((key, value));
            }
        }
    }

    pub fn entry_or(&mut self, key: K, default: impl FnOnce() -> V) -> &mut V {
        let i = match self.index.get(&key) {
            Some(&i) => i,
            None => {
                self.index.insert(key.clone(), self.items.len());
                self.items.push((key, default()));
                self.items.len() - 1
            }
        };
        &mut self.items[i].1
    }

    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.items.iter()
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        self.items.retain(|(k, v)| keep(k, v));
        self.index = self.items.iter().enumerate().map(|(i, (k, _))| (k.clone(), i)).collect();
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.items.iter().map(|(_, v)| v)
    }
}

pub type Socks = Ordered<SockKey, Sock>;

pub fn socket_timing(s: &Sock) -> Option<(f64, f64, f64)> {
    let (srtt, minrtt) = (s.srtt?, s.minrtt?);
    if s.sent + s.recv < MIN_LATENCY_BYTES {
        return None;
    }
    if srtt <= 0.0 || minrtt <= 0.0 {
        return None;
    }
    if srtt > MAX_PLAUSIBLE_RTT_MS || minrtt > MAX_PLAUSIBLE_RTT_MS {
        return None;
    }
    if minrtt > srtt + RTT_INVERSION_TOLERANCE_MS {
        return None;
    }
    Some((srtt, minrtt, (srtt - minrtt).max(0.0)))
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LatencyStats {
    pub sockets: usize,
    pub rejected: usize,
    pub rtt_p50: f64,
    pub rtt_p95: f64,
    pub floor_p50: f64,
    pub queue_p50: f64,
    pub queue_p95: f64,
    pub retrans_sockets: usize,
}

fn sorted(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(f64::total_cmp);
    v
}

pub fn latency_stats<'a>(socks: impl IntoIterator<Item = &'a Sock>) -> Option<LatencyStats> {
    let (mut srtts, mut floors, mut queues) = (Vec::new(), Vec::new(), Vec::new());
    let (mut retrans_socks, mut rejected) = (0, 0);
    for s in socks {
        if s.srtt.is_none() || s.minrtt.is_none() {
            continue;
        }
        let Some((srtt, floor, queue)) = socket_timing(s) else {
            rejected += 1;
            continue;
        };
        srtts.push(srtt);
        floors.push(floor);
        queues.push(queue);
        if s.retrans != 0 {
            retrans_socks += 1;
        }
    }
    if srtts.len() < MIN_LATENCY_SOCKETS {
        return None;
    }
    let (srtts, floors, queues) = (sorted(srtts), sorted(floors), sorted(queues));
    Some(LatencyStats {
        sockets: srtts.len(),
        rejected,
        rtt_p50: py_round(median(&srtts), 2),
        rtt_p95: py_round(nearest_rank(&srtts, 0.95), 2),
        floor_p50: py_round(median(&floors), 2),
        queue_p50: py_round(median(&queues), 2),
        queue_p95: py_round(nearest_rank(&queues, 0.95), 2),
        retrans_sockets: retrans_socks,
    })
}

// INFO: fc 17oct26 Mirrors what Python's users:(("name",pid=N regex extracted from raw, unescaped ss output
pub fn ss_user(name: &str, pid: i32) -> Option<(String, i32)> {
    if name.chars().any(is_py_line_break) {
        return None;
    }
    let Some(quote) = name.find('"') else {
        return (!name.is_empty()).then(|| (name.to_string(), pid));
    };
    if quote == 0 {
        return None;
    }
    let digits: String = name[quote..].strip_prefix("\",pid=")?.chars().take_while(char::is_ascii_digit).collect();
    Some((name[..quote].to_string(), digits.parse().ok()?))
}

// INFO: fc 17oct26 ss prints rtt and minrtt with %g (6 significant digits) and Python parsed that text
pub fn ss_ms(us: u32) -> Option<f64> {
    if us == 0 {
        return None;
    }
    format!("{:.5e}", us as f64 / 1000.0).parse().ok()
}

pub fn socks_from<'a>(records: &[DiagSock], owner_of: impl Fn(u32) -> Option<&'a Owner>, max_sockets: usize) -> Socks {
    let mut out = Socks::default();
    for r in records {
        if r.inode == 0 {
            continue;
        }
        let Some(owner) = owner_of(r.inode) else {
            continue;
        };
        let Some((app, pid)) = ss_user(&owner.name, owner.pid) else {
            continue;
        };
        let Some(info) = r.info else {
            continue;
        };
        if info.bytes_sent == 0 && info.bytes_received == 0 {
            continue;
        }
        if out.len() >= max_sockets {
            break;
        }
        let key = SockKey { local: r.local, peer: r.peer, ifindex: r.ifindex, pid };
        out.insert(
            key,
            Sock {
                app,
                pid,
                sent: info.bytes_sent,
                recv: info.bytes_received,
                srtt: ss_ms(info.rtt_us),
                minrtt: ss_ms(info.min_rtt_us),
                retrans: info.bytes_retrans,
            },
        );
    }
    out
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AppRate {
    pub name: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub conns: u64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub hist: Vec<[f64; 2]>,
    pub rtt_ms: Option<f64>,
    pub queue_ms: Option<f64>,
}

fn median_of(values: Option<&Vec<f64>>) -> Option<f64> {
    let values = values.filter(|v| !v.is_empty())?;
    Some(py_round(median(&sorted(values.clone())), 2))
}

pub struct AppTraffic {
    pub prev: Socks,
    pub prev_t: Option<f64>,
    pub totals: Ordered<String, [u64; 2]>,
    pub rates: Vec<AppRate>,
    pub history: Ordered<String, VecDeque<[f64; 2]>>,
    pub latency: Option<LatencyStats>,
    owners: Owners,
    last_error: Option<String>,
}

impl Default for AppTraffic {
    fn default() -> Self {
        Self::new()
    }
}

impl AppTraffic {
    pub const HISTORY: usize = 20;
    pub const MAX_APPS: usize = 64;
    pub const MAX_DIAG_BYTES: usize = 4 * 1024 * 1024;
    pub const MAX_SOCKETS: usize = 10_000;
    pub const POLL_DEADLINE_S: f64 = 1.5;

    pub fn new() -> Self {
        Self {
            prev: Socks::default(),
            prev_t: None,
            totals: Ordered::default(),
            rates: Vec::new(),
            history: Ordered::default(),
            latency: None,
            owners: Owners::new(),
            last_error: None,
        }
    }

    pub fn sample(&mut self) -> io::Result<Socks> {
        let deadline = monotonic() + Self::POLL_DEADLINE_S;
        let records = diag::dump(Self::MAX_DIAG_BYTES, deadline)?;
        self.owners.resolve(records.iter().map(|r| r.inode), deadline);
        Ok(socks_from(&records, |ino| self.owners.get(ino), Self::MAX_SOCKETS))
    }

    pub fn poll(&mut self) -> bool {
        match self.sample() {
            Ok(cur) => {
                self.last_error = None;
                self.fold(cur, now());
                true
            }
            Err(e) => {
                let msg = e.to_string();
                if self.last_error.as_deref() != Some(msg.as_str()) {
                    crate::util::complain!("nexthop: app traffic: sock_diag failed: {msg}");
                }
                self.last_error = Some(msg);
                false
            }
        }
    }

    pub fn fold(&mut self, cur: Socks, now: f64) {
        let Some(prev_t) = self.prev_t else {
            self.prev = cur;
            self.prev_t = Some(now);
            return;
        };
        let dt = (now - prev_t).max(0.5);
        let mut interval: Ordered<String, [u64; 3]> = Ordered::default();
        let mut per_app_rtt: HashMap<&str, Vec<f64>> = HashMap::new();
        let mut per_app_queue: HashMap<&str, Vec<f64>> = HashMap::new();
        for (key, s) in cur.iter() {
            let (d_tx, d_rx) = match self.prev.get(key) {
                Some(p) => (s.sent.saturating_sub(p.sent), s.recv.saturating_sub(p.recv)),
                None => (s.sent, s.recv),
            };
            let slot = interval.entry_or(s.app.clone(), || [0, 0, 0]);
            slot[0] += d_rx;
            slot[1] += d_tx;
            slot[2] += 1;
            if let Some((srtt, _, queue)) = socket_timing(s) {
                per_app_rtt.entry(&s.app).or_default().push(srtt);
                per_app_queue.entry(&s.app).or_default().push(queue);
            }
        }
        for (app, v) in interval.iter() {
            let tot = self.totals.entry_or(app.clone(), || [0, 0]);
            tot[0] += v[0];
            tot[1] += v[1];
        }
        self.forget_quietest_idle_apps(&interval);
        for (app, _) in self.totals.iter() {
            let point = match interval.get(app) {
                Some(v) => [py_round(v[0] as f64 / dt, 1), py_round(v[1] as f64 / dt, 1)],
                None => [0.0, 0.0],
            };
            let h = self.history.entry_or(app.clone(), VecDeque::new);
            h.push_back(point);
            if h.len() > Self::HISTORY {
                h.pop_front();
            }
        }
        self.rates = interval
            .iter()
            .map(|(app, v)| {
                let tot = self.totals.get(app).copied().unwrap_or([0, 0]);
                AppRate {
                    name: app.clone(),
                    rx_bps: py_round(v[0] as f64 / dt, 1),
                    tx_bps: py_round(v[1] as f64 / dt, 1),
                    conns: v[2],
                    rx_total: tot[0],
                    tx_total: tot[1],
                    hist: self.hist(app),
                    rtt_ms: median_of(per_app_rtt.get(app.as_str())),
                    queue_ms: median_of(per_app_queue.get(app.as_str())),
                }
            })
            .collect();
        self.latency = latency_stats(cur.values());
        self.prev = cur;
        self.prev_t = Some(now);
    }

    fn forget_quietest_idle_apps(&mut self, active: &Ordered<String, [u64; 3]>) {
        let excess = self.totals.len().saturating_sub(Self::MAX_APPS);
        if excess == 0 {
            return;
        }
        let mut idle: Vec<(u64, String)> = self
            .totals
            .iter()
            .filter(|(app, _)| active.get(app.as_str()).is_none())
            .map(|(app, t)| (t[0] + t[1], app.clone()))
            .collect();
        idle.sort();
        let gone: HashSet<String> = idle.into_iter().take(excess).map(|(_, app)| app).collect();
        self.totals.retain(|app, _| !gone.contains(app));
        self.history.retain(|app, _| !gone.contains(app));
    }

    fn hist(&self, app: &str) -> Vec<[f64; 2]> {
        self.history.get(app).map(|h| h.iter().copied().collect()).unwrap_or_default()
    }

    pub fn top(&self, n: usize) -> Vec<AppRate> {
        let mut ranked = self.rates.clone();
        ranked.sort_by(|a, b| {
            (b.rx_bps + b.tx_bps)
                .partial_cmp(&(a.rx_bps + a.tx_bps))
                .unwrap_or(Ordering::Equal)
                .then((b.rx_total + b.tx_total).cmp(&(a.rx_total + a.tx_total)))
        });
        let seen: HashSet<&str> = ranked.iter().map(|a| a.name.as_str()).collect();
        let mut idle: Vec<AppRate> = self
            .totals
            .iter()
            .filter(|(app, _)| !seen.contains(app.as_str()))
            .map(|(app, t)| AppRate {
                name: app.clone(),
                rx_bps: 0.0,
                tx_bps: 0.0,
                conns: 0,
                rx_total: t[0],
                tx_total: t[1],
                hist: self.hist(app),
                rtt_ms: None,
                queue_ms: None,
            })
            .collect();
        idle.sort_by_key(|a| Reverse(a.rx_total + a.tx_total));
        ranked.extend(idle);
        ranked.truncate(n);
        ranked
    }
}
