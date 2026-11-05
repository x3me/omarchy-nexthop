use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::arbiters::{IntervalEvent, LocalEventArbiter, WanEventArbiter};
use super::captive::{CaptiveWatch, Check};
use super::collector::{LinkCollector, Snapshot, Targets, is_address};
use super::config::Config;
use super::consts::{CF_EDGE_FALLBACK, CF_EDGE_HOST, DIVERSITY_HOST};
use super::events::Notify;
use super::legs::LegWatch;
use super::link_watch::{CauseSource, LinkWatch};
use super::lookup::LookupWatch;
use crate::apps::AppTraffic;
use crate::instruments::{Bench, MergedSeries};
use crate::linkevents::NlEvents;
use crate::net::Tether;
use crate::probes::{PingProbe, Series, Stats, TcpProbe};
use crate::pyjson::text;
use crate::score::TunnelBands;
use crate::speedtest::ContentResult;
use crate::store::Store;
use crate::update::UpdateWatch;
use crate::util::{Job, spawn_named};

pub type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
pub type SpawnFn = Arc<dyn Fn(&str, Job) -> io::Result<()> + Send + Sync>;
pub type WallClock = Arc<dyn Fn() -> f64 + Send + Sync>;
pub type ContentFn = Arc<dyn Fn(Option<f64>, Option<f64>) -> ContentResult + Send + Sync>;
pub type PeakFn = Arc<dyn Fn(&str) -> Map<String, Value> + Send + Sync>;
pub type NotifyFn = Arc<dyn Fn(&str, &str, bool) + Send + Sync>;
pub type Pool = Vec<(String, &'static str, String)>;
pub type RouteFn = Box<dyn Fn(&str) -> Snapshot>;
pub type CountersFn = Box<dyn Fn(&str) -> Option<(u64, u64)>>;
pub type TetherFn = Box<dyn Fn(&str) -> Option<Tether>>;
pub type StartFn = Box<dyn Fn(&AnyProbe) -> io::Result<()>>;
pub type BaselineCache = (f64, Option<f64>, (String, Option<String>));

pub struct Hooks {
    pub clock: WallClock,
    pub local_route: RouteFn,
    pub counters: CountersFn,
    pub tether_from_gateway: TetherFn,
    pub nm_metered: Box<dyn Fn(&str) -> bool>,
    pub start_probe: StartFn,
    pub reachability: Check,
    pub content_test: ContentFn,
    pub peak_test: PeakFn,
    pub spawn: SpawnFn,
    pub notify: NotifyFn,
}

impl Hooks {
    pub fn real() -> Hooks {
        Hooks {
            clock: Arc::new(crate::util::now),
            local_route: Box::new(crate::net::local_route),
            counters: Box::new(crate::net::counters),
            tether_from_gateway: Box::new(crate::net::tether_from_gateway),
            nm_metered: Box::new(crate::net::nm_metered),
            start_probe: Box::new(AnyProbe::start),
            reachability: Arc::new(crate::net::reachability),
            content_test: Arc::new(crate::speedtest::content_test),
            peak_test: Arc::new(crate::speedtest::peak_test),
            spawn: Arc::new(spawn_named),
            notify: Arc::new(super::run::notify_send),
        }
    }
}

#[derive(Clone)]
pub enum AnyProbe {
    Ping(Arc<PingProbe>),
    Tcp(Arc<TcpProbe>),
}

impl AnyProbe {
    pub fn start(&self) -> io::Result<()> {
        match self {
            AnyProbe::Ping(p) => p.start(),
            AnyProbe::Tcp(p) => p.start(),
        }
    }

    pub fn stop(&self) {
        match self {
            AnyProbe::Ping(p) => p.stop(),
            AnyProbe::Tcp(p) => p.stop(),
        }
    }

    pub fn set_interval(&self, seconds: f64) {
        match self {
            AnyProbe::Ping(p) => p.set_interval(seconds),
            AnyProbe::Tcp(p) => p.set_interval(seconds),
        }
    }

    #[cfg(test)]
    pub fn interval(&self) -> f64 {
        match self {
            AnyProbe::Ping(p) => p.interval(),
            AnyProbe::Tcp(p) => p.interval(),
        }
    }

    pub fn tcp(&self) -> Option<&Arc<TcpProbe>> {
        match self {
            AnyProbe::Tcp(p) => Some(p),
            AnyProbe::Ping(_) => None,
        }
    }
}

pub type InstrumentProbes = Vec<(String, AnyProbe)>;

#[derive(Default)]
pub struct Shared {
    pub anchor: Mutex<String>,
    pub instrument_probes: Mutex<InstrumentProbes>,
}

#[derive(Default)]
pub struct Workers {
    pub peak_running: AtomicBool,
    pub content_running: AtomicBool,
    pub content_retry_used: AtomicBool,
    pub baseline_stale: AtomicBool,
    pub retry_at: Mutex<Option<f64>>,
    pub path: Mutex<(Option<String>, Option<String>)>,
}

pub fn instrument_pool(anchor: &str) -> Pool {
    let cf = if anchor == CF_EDGE_HOST { CF_EDGE_FALLBACK } else { CF_EDGE_HOST };
    vec![
        ("icmp-anchor".into(), "icmp", anchor.to_string()),
        ("tcp-anchor".into(), "tcp", format!("{anchor}:443")),
        ("tcp-cf".into(), "tcp", format!("{cf}:443")),
        ("tcp-google".into(), "tcp", format!("{DIVERSITY_HOST}:443")),
    ]
}

pub fn bench_for(pool: &Pool) -> Bench {
    let rows: Vec<(&str, &str, &str)> = pool.iter().map(|(k, kind, t)| (k.as_str(), *kind, t.as_str())).collect();
    Bench::new(&rows)
}

pub fn probe_host<'a>(kind: &str, target: &'a str) -> &'a str {
    if kind == "tcp" { target.rsplit_once(':').map_or(target, |(host, _)| host) } else { target }
}

pub fn probe_targets(anchor: &str, probes: &[(String, AnyProbe)]) -> Targets {
    let mut resolved: HashMap<&str, String> = HashMap::new();
    for (_, p) in probes {
        if let Some(tcp) = p.tcp()
            && let Some(first) = tcp.lookup.addresses().first()
        {
            resolved.insert(&tcp.target, first.ip().to_string());
        }
    }
    let mut out = Targets::new();
    for (key, kind, target) in instrument_pool(anchor) {
        let host = probe_host(kind, &target);
        let address = if is_address(host) { Some(host.to_string()) } else { resolved.get(host).cloned() };
        if let Some(address) = address.filter(|a| !a.is_empty()) {
            out.insert(key, address);
        }
    }
    out
}

pub struct Daemon {
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub config: Config,
    pub store: Arc<Store>,
    pub local: Arc<Series>,
    pub bench: Bench,
    pub instrument_series: Vec<(String, Arc<Series>)>,
    pub icmp_anchor: Arc<Series>,
    pub active: Arc<Mutex<Vec<Arc<Series>>>>,
    pub total: Arc<MergedSeries>,
    pub last_bench_eval: f64,
    pub probes: Vec<AnyProbe>,
    pub local_probe: Option<AnyProbe>,
    pub probe_settings: Option<(String, i64)>,
    pub route: Snapshot,
    pub counter_samples: Vec<(f64, u64, u64)>,
    pub rates: (Option<f64>, Option<f64>),
    pub link_loaded: Arc<AtomicBool>,
    pub busy_at: Option<f64>,
    pub aux_ring: VecDeque<(f64, Option<f64>, Option<f64>, Value)>,
    pub last_recent_flush: f64,
    pub last_signal: Value,
    pub watch_local: LegWatch,
    pub watch_wan: LegWatch,
    pub wan_sampled_at: Option<f64>,
    pub wan_unwatched: bool,
    pub wan_resumed_at: Option<f64>,
    pub wan_events: WanEventArbiter,
    pub local_events: LocalEventArbiter,
    pub watched: Option<(f64, f64)>,
    pub watching_since: f64,
    pub captive: CaptiveWatch,
    pub lookup_watch: LookupWatch,
    pub metered: Option<Map<String, Value>>,
    pub vpn: Option<Map<String, Value>>,
    pub vpn_events: IntervalEvent,
    pub tether_events: IntervalEvent,
    pub vpn_spans: VecDeque<(f64, Option<f64>)>,
    pub wan_ip: Option<Map<String, Value>>,
    pub wan_ip_at: i64,
    pub nl_events: NlEvents,
    pub link_watch: LinkWatch,
    pub update_watch: UpdateWatch,
    pub app_traffic: AppTraffic,
    pub link: Arc<LinkCollector>,
    pub last_apps_poll: f64,
    pub last_content_test: f64,
    pub check_waiting_since: Option<f64>,
    pub quiet_waiting_since: Option<f64>,
    pub last_minute_flush: f64,
    pub last_rollup: f64,
    pub content_boost_at: Option<f64>,
    pub content_network: Option<String>,
    pub band_seen: Option<(String, String)>,
    pub band_check_at: Option<f64>,
    pub tunnel_bands_cache: Option<(f64, String, Option<TunnelBands>)>,
    pub load_floor_cache: Option<(f64, f64)>,
    pub baseline_cache: Option<BaselineCache>,
    pub notify_enabled: Arc<AtomicBool>,
    pub shared: Arc<Shared>,
    pub workers: Arc<Workers>,
    pub hooks: Hooks,
    pub lock_fd: Option<OwnedFd>,
}

pub const AUX_RING_LEN: usize = 400;
pub const VPN_SPANS_LEN: usize = 64;

fn gated(notify: &NotifyFn, enabled: &Arc<AtomicBool>) -> Notify {
    let (notify, enabled) = (Arc::clone(notify), Arc::clone(enabled));
    Box::new(move |summary, body, urgent| {
        if enabled.load(Ordering::SeqCst) {
            notify(summary, body, urgent);
        }
    })
}

fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

impl Daemon {
    pub fn new() -> Fallible<Daemon> {
        let state_dir = crate::paths::ensure_state_dir()?;
        let runtime_dir = crate::paths::ensure_runtime_dir()?;
        Daemon::with(&state_dir, &runtime_dir, Hooks::real())
    }

    pub fn with(state_dir: &Path, runtime_dir: &Path, hooks: Hooks) -> Fallible<Daemon> {
        private_dir(state_dir)?;
        private_dir(runtime_dir)?;
        let mut config = Config::new(state_dir);
        config.refresh();
        let store = Arc::new(Store::new(&state_dir.join(crate::paths::DB), false)?);
        let anchor = config.internet_anchor();
        let pool = instrument_pool(&anchor);
        let bench = bench_for(&pool);
        let active: Arc<Mutex<Vec<Arc<Series>>>> = Arc::default();
        let seats = Arc::clone(&active);
        let total = Arc::new(MergedSeries::new(Box::new(move || seats.lock().unwrap().clone())));
        let notify_enabled = Arc::new(AtomicBool::new(config.notify_outage()));
        let shared = Arc::new(Shared { anchor: Mutex::new(anchor), instrument_probes: Mutex::default() });
        let nl_events = NlEvents::new()?;
        let causes: Arc<dyn CauseSource> = Arc::new(nl_events.clone());
        let (for_anchor, for_targets) = (Arc::clone(&shared), Arc::clone(&shared));
        let link = LinkCollector::new(
            Box::new(move || for_anchor.anchor.lock().unwrap().clone()),
            None,
            LinkCollector::INTERVAL_S,
            Some(Box::new(move || {
                let anchor = for_targets.anchor.lock().unwrap().clone();
                let probes = for_targets.instrument_probes.lock().unwrap().clone();
                probe_targets(&anchor, &probes)
            })),
            None,
            None,
        );
        let events_store: Arc<dyn super::events::EventLog> = store.clone();
        let watching_since = (hooks.clock)();
        let mut daemon = Daemon {
            state_dir: state_dir.to_path_buf(),
            runtime_dir: runtime_dir.to_path_buf(),
            store: Arc::clone(&store),
            local: Arc::new(Series::default()),
            bench,
            instrument_series: Vec::new(),
            icmp_anchor: Arc::new(Series::default()),
            active,
            total,
            last_bench_eval: 0.0,
            probes: Vec::new(),
            local_probe: None,
            probe_settings: None,
            route: Map::new(),
            counter_samples: Vec::new(),
            rates: (None, None),
            link_loaded: Arc::new(AtomicBool::new(false)),
            busy_at: None,
            aux_ring: VecDeque::with_capacity(AUX_RING_LEN),
            last_recent_flush: 0.0,
            last_signal: Value::Null,
            watch_local: LegWatch::new(),
            watch_wan: LegWatch::new(),
            wan_sampled_at: None,
            wan_unwatched: false,
            wan_resumed_at: None,
            wan_events: WanEventArbiter::new(Arc::clone(&events_store), gated(&hooks.notify, &notify_enabled)),
            local_events: LocalEventArbiter::new(Arc::clone(&events_store), gated(&hooks.notify, &notify_enabled)),
            watched: None,
            watching_since,
            captive: CaptiveWatch::new(Arc::clone(&hooks.reachability), None),
            lookup_watch: LookupWatch::new(Arc::clone(&events_store)),
            metered: None,
            vpn: None,
            vpn_events: IntervalEvent::new(Arc::clone(&events_store), "vpn", "info", "tunnel"),
            tether_events: IntervalEvent::new(Arc::clone(&events_store), "tether", "info", "local"),
            vpn_spans: VecDeque::with_capacity(VPN_SPANS_LEN),
            wan_ip: None,
            wan_ip_at: 0,
            link_watch: LinkWatch::new(Arc::clone(&events_store), Some(causes)),
            nl_events,
            update_watch: UpdateWatch::new(None, config.update_check(), None),
            app_traffic: AppTraffic::new(),
            link: Arc::new(link),
            last_apps_poll: 0.0,
            last_content_test: 0.0,
            check_waiting_since: None,
            quiet_waiting_since: None,
            last_minute_flush: 0.0,
            last_rollup: 0.0,
            content_boost_at: None,
            content_network: None,
            band_seen: None,
            band_check_at: None,
            tunnel_bands_cache: None,
            load_floor_cache: None,
            baseline_cache: None,
            notify_enabled,
            shared,
            workers: Arc::default(),
            hooks,
            lock_fd: None,
            config,
        };
        daemon.new_instrument_series();
        Ok(daemon)
    }

    pub fn now(&self) -> f64 {
        (self.hooks.clock)()
    }

    pub fn anchor(&self) -> String {
        self.config.internet_anchor()
    }

    pub fn instrument_pool(&self) -> Pool {
        instrument_pool(&self.anchor())
    }

    pub fn instrument_probes(&self) -> InstrumentProbes {
        self.shared.instrument_probes.lock().unwrap().clone()
    }

    pub fn set_instrument_probes(&self, probes: InstrumentProbes) {
        *self.shared.instrument_probes.lock().unwrap() = probes;
    }

    pub fn new_instrument_series(&mut self) {
        self.instrument_series =
            self.instrument_pool().into_iter().map(|(key, _, _)| (key, Arc::new(Series::default()))).collect();
        if let Some(s) = self.series("icmp-anchor") {
            self.icmp_anchor = Arc::clone(s);
        }
        self.sync_active();
    }

    pub fn series(&self, key: &str) -> Option<&Arc<Series>> {
        self.instrument_series.iter().find(|(k, _)| k == key).map(|(_, s)| s)
    }

    pub fn active_keys(&self) -> Vec<String> {
        self.bench.actives().into_iter().filter(|i| self.series(&i.key).is_some()).map(|i| i.key.clone()).collect()
    }

    pub fn active_series(&self) -> Vec<Arc<Series>> {
        self.active_keys().iter().filter_map(|k| self.series(k)).cloned().collect()
    }

    pub fn sync_active(&self) {
        *self.active.lock().unwrap() = self.active_series();
    }

    pub fn instrument_stats(&self, window_s: f64) -> HashMap<String, Stats> {
        let at = self.now();
        self.instrument_series.iter().map(|(k, s)| (k.clone(), Series::stats(&s.since_at(window_s, at)))).collect()
    }

    pub fn peak_running(&self) -> bool {
        self.workers.peak_running.load(Ordering::SeqCst)
    }

    pub fn content_running(&self) -> bool {
        self.workers.content_running.load(Ordering::SeqCst)
    }

    pub fn tests_idle(&self) -> bool {
        tests_idle(self.peak_running(), self.content_running())
    }

    pub fn latest(&self) -> Snapshot {
        self.link.latest()
    }

    pub fn network_name(&self) -> String {
        network_of(&self.latest())
    }

    pub fn live_path(&self) -> PathBuf {
        self.runtime_dir.join(crate::paths::LIVE)
    }

    pub fn recent_path(&self) -> PathBuf {
        self.runtime_dir.join(crate::paths::RECENT)
    }

    pub fn apps_path(&self) -> PathBuf {
        self.runtime_dir.join(crate::paths::APPS)
    }

    pub fn lock_path(&self) -> PathBuf {
        self.state_dir.join(crate::paths::LOCK)
    }
}

pub fn tests_idle(peak_running: bool, content_running: bool) -> bool {
    !(peak_running || content_running)
}

pub fn field<'a>(map: &'a Map<String, Value>, key: &str) -> &'a Value {
    map.get(key).unwrap_or(&Value::Null)
}

pub fn network_of(snap: &Snapshot) -> String {
    let ssid = text(snap, "ssid");
    if ssid.is_empty() { text(snap, "name").to_string() } else { ssid.to_string() }
}
