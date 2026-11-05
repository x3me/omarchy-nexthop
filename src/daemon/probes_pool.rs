use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::collector::Snapshot;
use super::consts::{LOAD_FLOOR_BPS, LOAD_FRACTION_OF_LINE, STANDBY_FACTOR, TCP_PROBE_INTERVAL_S, TCP_PROBE_PORT};
use super::core::{AnyProbe, Daemon, Fallible, field, network_of, probe_host};
use crate::probes::{LoadedFn, PingProbe, Series, TcpProbe};
use crate::pyjson::{text, truthy};

pub fn fresh_route_from(snap: &Snapshot) -> Snapshot {
    ["iface", "gateway", "src"]
        .into_iter()
        .map(|k| {
            let v = match snap.get(k) {
                Some(v) if truthy(Some(v)) => v.clone(),
                _ => Value::from(""),
            };
            (k.to_string(), v)
        })
        .collect()
}

pub fn route_differs(current: &Snapshot, fresh: &Snapshot) -> bool {
    if !truthy(fresh.get("gateway")) {
        return false;
    }
    field(fresh, "gateway") != field(current, "gateway") || field(fresh, "iface") != field(current, "iface")
}

impl Daemon {
    fn loaded_fn(&self) -> LoadedFn {
        let loaded = Arc::clone(&self.link_loaded);
        Arc::new(move || loaded.load(Ordering::SeqCst))
    }

    pub fn apply_seats(&self, changes: &[(String, bool)]) {
        let interval = self.config.probe_interval_ms() as f64 / 1000.0;
        let probes = self.instrument_probes();
        for (key, active) in changes {
            let Some((_, probe)) = probes.iter().find(|(k, _)| k == key) else {
                continue;
            };
            let Some(inst) = self.bench.instrument(key) else {
                continue;
            };
            let base = if inst.kind == "icmp" { interval } else { TCP_PROBE_INTERVAL_S };
            probe.set_interval(if *active { base } else { base * STANDBY_FACTOR });
        }
    }

    fn start(&mut self, probe: AnyProbe) -> std::io::Result<AnyProbe> {
        (self.hooks.start_probe)(&probe)?;
        self.probes.push(probe.clone());
        Ok(probe)
    }

    pub fn start_probes(&mut self) -> Fallible<()> {
        let anchor = self.anchor();
        self.route = (self.hooks.local_route)(&anchor);
        self.refresh_metered();
        let interval = self.config.probe_interval_ms();
        self.probe_settings = Some((anchor, interval));
        let gw = text(&self.route, "gateway").to_string();
        self.local_probe = None;
        if !gw.is_empty() {
            let p = PingProbe::new(&gw, Arc::clone(&self.local), interval as f64, "local", Some(self.loaded_fn()));
            self.local_probe = Some(self.start(AnyProbe::Ping(Arc::new(p)))?);
        }
        let mut started = Vec::new();
        for (key, kind, target) in self.instrument_pool() {
            let series: Arc<Series> = match self.series(&key) {
                Some(s) => Arc::clone(s),
                None => continue,
            };
            let host = probe_host(kind, &target);
            let (probe, base) = if kind == "icmp" {
                let p = PingProbe::new(host, series, interval as f64, &key, Some(self.loaded_fn()));
                (AnyProbe::Ping(Arc::new(p)), interval as f64 / 1000.0)
            } else {
                let p = TcpProbe::new(host, series, TCP_PROBE_INTERVAL_S, &key, Some(self.loaded_fn()), TCP_PROBE_PORT);
                (AnyProbe::Tcp(Arc::new(p)), TCP_PROBE_INTERVAL_S)
            };
            if let Some(inst) = self.bench.instrument_mut(&key) {
                inst.target = target.clone();
                if !inst.active {
                    probe.set_interval(base * STANDBY_FACTOR);
                }
            }
            let probe = self.start(probe)?;
            started.push((key, probe));
            self.set_instrument_probes(started.clone());
        }
        Ok(())
    }

    pub fn restart_probes_if_route_changed(&mut self, fresh: Option<Snapshot>) -> Fallible<()> {
        let fresh = fresh.unwrap_or_else(|| (self.hooks.local_route)(&self.anchor()));
        if route_differs(&self.route, &fresh) {
            self.rebuild_probes(fresh)?;
        }
        Ok(())
    }

    pub fn follow_route(&mut self) -> Fallible<()> {
        let fresh = fresh_route_from(&self.latest());
        self.restart_probes_if_route_changed(Some(fresh))
    }

    pub fn restart_probes_if_settings_changed(&mut self) -> Fallible<()> {
        let Some((old_anchor, old_interval)) = self.probe_settings.clone() else {
            return Ok(());
        };
        let anchor = self.anchor();
        let interval = self.config.probe_interval_ms();
        if anchor == old_anchor && interval == old_interval {
            return Ok(());
        }
        if anchor != old_anchor {
            let route = (self.hooks.local_route)(&anchor);
            return self.rebuild_probes(route);
        }
        self.probe_settings = Some((anchor, interval));
        if let Some(p) = &self.local_probe {
            p.set_interval(interval as f64 / 1000.0);
        }
        let seats: Vec<(String, bool)> = self.bench.instruments.iter().map(|i| (i.key.clone(), i.active)).collect();
        self.apply_seats(&seats);
        Ok(())
    }

    pub fn rebuild_probes(&mut self, route: Snapshot) -> Fallible<()> {
        for p in self.probes.drain(..) {
            p.stop();
        }
        self.set_instrument_probes(Vec::new());
        self.local = Arc::new(Series::default());
        self.new_instrument_series();
        self.route = route;
        self.counter_samples.clear();
        self.wan_ip = None;
        self.wan_ip_at = 0;
        self.captive.request();
        let now = self.now();
        self.lookup_watch.reset(now)?;
        self.start_probes()
    }

    pub fn refresh_metered(&mut self) {
        let gw = text(&self.route, "gateway").to_string();
        let iface = text(&self.route, "iface").to_string();
        let tether = (self.hooks.tether_from_gateway)(&gw);
        let explicit = (self.hooks.nm_metered)(&iface);
        if tether.is_none() && !explicit {
            self.metered = None;
            return;
        }
        let mut m = Map::new();
        m.insert("tethered".into(), json!(tether.is_some()));
        m.insert("kind".into(), json!(tether.as_ref().map_or("declared", |t| t.kind)));
        m.insert("label".into(), json!(tether.as_ref().map_or("Metered link", |t| t.label)));
        m.insert("explicit".into(), json!(explicit));
        self.metered = Some(m);
    }

    pub fn load_floor_bps(&mut self, now: f64) -> f64 {
        if let Some((at, floor)) = self.load_floor_cache
            && now - at <= 60.0
        {
            return floor;
        }
        let network = network_of(&self.latest());
        let vpn = self.vpn_identity();
        let baseline = self.store.baseline_speed(30, &network, 5, Some(now), false, vpn.as_deref()).ok().flatten();
        let mut floor = LOAD_FLOOR_BPS;
        if let Some(b) = baseline.filter(|b| *b != 0.0) {
            floor = floor.max(b * 1e6 / 8.0 * LOAD_FRACTION_OF_LINE);
        }
        self.load_floor_cache = Some((now, floor));
        floor
    }

    pub fn throughput(&mut self, now: f64, iface: &str) {
        let Some((rx, tx)) = (self.hooks.counters)(iface) else {
            self.counter_samples.clear();
            self.rates = (None, None);
            self.link_loaded.store(false, Ordering::SeqCst);
            return;
        };
        let window = self.config.throughput_window_s().clamp(1, 30) as f64;
        self.counter_samples.push((now, rx, tx));
        let cutoff = now - window - 0.25;
        while self.counter_samples.len() > 2 && self.counter_samples[0].0 < cutoff {
            self.counter_samples.remove(0);
        }
        if self.counter_samples.len() > 128 {
            let excess = self.counter_samples.len() - 128;
            self.counter_samples.drain(..excess);
        }
        if self.counter_samples.len() < 2 {
            return;
        }
        let (t0, rx0, tx0) = self.counter_samples[0];
        let (t1, rx1, tx1) = self.counter_samples[self.counter_samples.len() - 1];
        let dt = t1 - t0;
        if dt > 0.0 && rx1 >= rx0 && tx1 >= tx0 {
            let rates = ((rx1 - rx0) as f64 / dt, (tx1 - tx0) as f64 / dt);
            self.rates = (Some(rates.0), Some(rates.1));
            let loaded = rates.0 + rates.1 >= self.load_floor_bps(now);
            self.link_loaded.store(loaded, Ordering::SeqCst);
            if loaded {
                self.busy_at = Some(now);
            }
        } else {
            let last = self.counter_samples[self.counter_samples.len() - 1];
            self.counter_samples = vec![last];
        }
    }
}
