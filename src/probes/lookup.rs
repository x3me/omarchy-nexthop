use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::util::{Job, monotonic, now, spawn_named};

pub type ResolveFn = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;
pub type SpawnFn = Box<dyn Fn(Job) + Send + Sync>;
pub type ClockFn = Arc<dyn Fn() -> f64 + Send + Sync>;

#[derive(Default)]
struct Slot {
    done: bool,
    result: Option<Vec<SocketAddr>>,
    finished_at: f64,
}

pub struct NameLookup {
    pub host: String,
    pub port: u16,
    pub literal: bool,
    resolve_fn: ResolveFn,
    pub(crate) spawn: SpawnFn,
    pub(crate) deadline_s: f64,
    pub(crate) monotonic: ClockFn,
    pub(crate) wall: ClockFn,
    slot: Arc<(Mutex<Slot>, Condvar)>,
    started: Mutex<Option<f64>>,
    addresses: Mutex<Vec<SocketAddr>>,
    outcomes: Mutex<VecDeque<(f64, bool)>>,
}

pub fn getaddrinfo(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

fn in_thread(job: Job) {
    if let Err(err) = spawn_named("lookup", job) {
        crate::util::complain!("nexthop: lookup thread: {err}");
    }
}

impl NameLookup {
    pub const DEADLINE_S: f64 = 4.0;
    pub const KEEP: usize = 128;
    pub const MAX_ADDRESSES: usize = 8;

    pub fn new(host: &str, port: u16) -> Self {
        Self::with(host, port, Arc::new(getaddrinfo), Box::new(in_thread))
    }

    pub fn with(host: &str, port: u16, resolve_fn: ResolveFn, spawn: SpawnFn) -> Self {
        let literal = host.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port));
        Self {
            host: host.to_string(),
            port,
            literal: literal.is_some(),
            resolve_fn,
            spawn,
            deadline_s: Self::DEADLINE_S,
            monotonic: Arc::new(monotonic),
            wall: Arc::new(now),
            slot: Arc::new((Mutex::new(Slot::default()), Condvar::new())),
            started: Mutex::new(None),
            addresses: Mutex::new(literal.into_iter().collect()),
            outcomes: Mutex::new(VecDeque::new()),
        }
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.addresses.lock().unwrap().clone()
    }

    pub fn outcomes(&self) -> Vec<(f64, bool)> {
        self.outcomes.lock().unwrap().iter().copied().collect()
    }

    fn record(&self, ts: f64, ok: bool) {
        let mut outcomes = self.outcomes.lock().unwrap();
        if outcomes.len() == Self::KEEP {
            outcomes.pop_front();
        }
        outcomes.push_back((ts, ok));
    }

    fn job(&self) -> Job {
        let (slot, resolve_fn, wall) = (self.slot.clone(), self.resolve_fn.clone(), self.wall.clone());
        let (host, port) = (self.host.clone(), self.port);
        Box::new(move || {
            let result = resolve_fn(&host, port).ok().and_then(|infos| {
                let mut found: Vec<SocketAddr> = Vec::new();
                for addr in infos {
                    if !found.contains(&addr) {
                        found.push(addr);
                    }
                }
                found.truncate(Self::MAX_ADDRESSES);
                (!found.is_empty()).then_some(found)
            });
            let (lock, cv) = &*slot;
            let mut s = lock.lock().unwrap();
            s.finished_at = wall();
            s.result = result;
            s.done = true;
            cv.notify_all();
        })
    }

    pub fn resolve(&self, wall: Option<f64>) -> Vec<SocketAddr> {
        if self.literal {
            return self.addresses();
        }
        self.collect(wall);
        let idle = self.started.lock().unwrap().is_none();
        if idle {
            self.slot.0.lock().unwrap().done = false;
            *self.started.lock().unwrap() = Some((self.monotonic)());
            (self.spawn)(self.job());
            if self.addresses.lock().unwrap().is_empty() {
                let (lock, cv) = &*self.slot;
                let guard = lock.lock().unwrap();
                let timeout = Duration::from_secs_f64(self.deadline_s.max(0.0));
                drop(cv.wait_timeout_while(guard, timeout, |s| !s.done).unwrap());
                self.collect(wall);
            }
        }
        self.addresses()
    }

    fn collect(&self, wall: Option<f64>) {
        let Some(started) = *self.started.lock().unwrap() else {
            return;
        };
        let taken = {
            let mut s = self.slot.0.lock().unwrap();
            if s.done {
                s.done = false;
                Some((s.result.take(), s.finished_at))
            } else {
                None
            }
        };
        match taken {
            Some((result, finished_at)) => {
                *self.started.lock().unwrap() = None;
                let ok = result.is_some();
                if let Some(found) = result {
                    *self.addresses.lock().unwrap() = found;
                }
                self.record(wall.unwrap_or(finished_at), ok);
            }
            None if (self.monotonic)() - started >= self.deadline_s => {
                self.record(wall.unwrap_or_else(|| (self.wall)()), false);
            }
            None => {}
        }
    }
}
