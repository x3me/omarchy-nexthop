use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::pyjson::text;
use crate::util::monotonic;

pub type Snapshot = Map<String, Value>;
pub type Targets = BTreeMap<String, String>;
pub type AnchorFn = Box<dyn Fn() -> String + Send + Sync>;
pub type SnapshotFn = Box<dyn Fn(&str) -> std::io::Result<Snapshot> + Send + Sync>;
pub type TargetsFn = Box<dyn Fn() -> Targets + Send + Sync>;
pub type TunnelFn = Box<dyn Fn(&Targets, &str) -> std::io::Result<Option<Snapshot>> + Send + Sync>;
pub type Clock = Box<dyn Fn() -> f64 + Send + Sync>;

pub fn is_address(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    match host.split_once('%') {
        Some((addr, scope)) => !scope.is_empty() && !scope.contains('%') && addr.parse::<Ipv6Addr>().is_ok(),
        None => false,
    }
}

type TunnelKey = (String, String, Vec<String>);

#[derive(Default)]
struct TunnelState {
    vpn: Option<Snapshot>,
    checked: Option<(f64, TunnelKey)>,
}

struct Inner {
    anchor_fn: AnchorFn,
    snapshot: SnapshotFn,
    interval: Duration,
    targets_fn: Option<TargetsFn>,
    tunnel: TunnelFn,
    clock: Clock,
    latest: Mutex<Snapshot>,
    tunnel_state: Mutex<TunnelState>,
    stopped: Mutex<bool>,
    wake: Condvar,
}

pub struct LinkCollector {
    inner: Arc<Inner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Inner {
    fn check_tunnel(&self, snap: &Snapshot, targets_fn: &TargetsFn) {
        let now = (self.clock)();
        let targets = targets_fn();
        let iface = text(snap, "iface").to_string();
        let key = (text(snap, "tunnel_iface").to_string(), iface.clone(), targets.keys().cloned().collect());
        let mut state = self.tunnel_state.lock().unwrap();
        if let Some((at, seen)) = &state.checked
            && *seen == key
            && now - at < LinkCollector::TUNNEL_CHECK_S
        {
            return;
        }
        state.checked = Some((now, key));
        if let Ok(vpn) = (self.tunnel)(&targets, &iface) {
            state.vpn = vpn;
        }
    }

    fn take(&self) {
        let Ok(mut snap) = (self.snapshot)(&(self.anchor_fn)()) else {
            return;
        };
        if let Some(targets_fn) = &self.targets_fn {
            self.check_tunnel(&snap, targets_fn);
            let vpn = self.tunnel_state.lock().unwrap().vpn.clone();
            snap.insert("vpn".into(), vpn.map_or(Value::Null, Value::Object));
        }
        *self.latest.lock().unwrap() = snap;
    }

    fn run(&self) {
        let mut stopped = self.stopped.lock().unwrap();
        loop {
            let (guard, _) = self.wake.wait_timeout_while(stopped, self.interval, |s| !*s).unwrap();
            stopped = guard;
            if *stopped {
                return;
            }
            drop(stopped);
            self.take();
            stopped = self.stopped.lock().unwrap();
        }
    }
}

impl LinkCollector {
    pub const INTERVAL_S: f64 = 0.5;
    pub const TUNNEL_CHECK_S: f64 = 60.0;

    pub fn new(
        anchor_fn: AnchorFn,
        snapshot_fn: Option<SnapshotFn>,
        interval_s: f64,
        targets_fn: Option<TargetsFn>,
        tunnel_fn: Option<TunnelFn>,
        clock: Option<Clock>,
    ) -> Self {
        let reader = SharedReader::default();
        let inner = Inner {
            anchor_fn,
            snapshot: snapshot_fn.unwrap_or_else(|| {
                let reader = reader.clone();
                Box::new(move |anchor| reader.with(|r| r.snapshot(anchor)))
            }),
            interval: Duration::from_secs_f64(interval_s),
            targets_fn,
            tunnel: tunnel_fn.unwrap_or_else(|| {
                Box::new(move |targets, iface| {
                    reader.with(|r| r.tunnel_routes(targets, iface, &mut crate::net::no_lookup))
                })
            }),
            clock: clock.unwrap_or_else(|| Box::new(monotonic)),
            latest: Mutex::new(Map::new()),
            tunnel_state: Mutex::new(TunnelState::default()),
            stopped: Mutex::new(false),
            wake: Condvar::new(),
        };
        Self { inner: Arc::new(inner), handle: Mutex::new(None) }
    }

    #[cfg(test)]
    pub(crate) fn take(&self) {
        self.inner.take();
    }

    pub fn start(&self) -> std::io::Result<()> {
        self.inner.take();
        let inner = Arc::clone(&self.inner);
        let handle = std::thread::Builder::new().name("link".into()).spawn(move || inner.run())?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    pub fn stop(&self) {
        *self.inner.stopped.lock().unwrap() = true;
        self.inner.wake.notify_all();
    }

    #[cfg(test)]
    pub fn is_alive(&self) -> bool {
        self.handle.lock().unwrap().as_ref().is_some_and(|h| !h.is_finished())
    }

    pub fn latest(&self) -> Snapshot {
        self.inner.latest.lock().unwrap().clone()
    }

    #[cfg(test)]
    pub fn set_latest(&self, snap: Snapshot) {
        *self.inner.latest.lock().unwrap() = snap;
    }
}

impl Drop for LinkCollector {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Default)]
struct SharedReader(Arc<Mutex<Option<crate::net::NetReader>>>);

impl SharedReader {
    fn with<T>(&self, read: impl FnOnce(&mut crate::net::NetReader) -> T) -> std::io::Result<T> {
        let mut slot = self.0.lock().unwrap();
        if slot.is_none() {
            *slot = Some(crate::net::NetReader::new()?);
        }
        Ok(read(slot.as_mut().unwrap()))
    }
}
