use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use super::icmp::{self, IcmpSocket, Received};
use super::wake::{Wake, poll_for};
use super::{LoadedFn, Series};
use crate::util::now;

pub const SEQ_MOD: u32 = 65536;
const MIN_INTERVAL_S: f64 = 0.2;
const MAX_BACKOFF_S: f64 = 30.0;
const DRAIN_BATCH: usize = 64;

pub fn seq_after(a: u16, b: u16) -> bool {
    let d = a.wrapping_sub(b) as u32;
    0 < d && d < SEQ_MOD / 2
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PingEvent {
    Reply { t: f64, seq: u16, rtt: f64 },
    Unreachable { t: f64, seq: u16 },
    Pending { t: f64, seq: u16 },
}

pub struct PingTracker {
    pub interval: f64,
    series: Arc<Series>,
    loaded_fn: Option<LoadedFn>,
    pub(crate) pending: Vec<(u16, f64)>,
    pub(crate) charged: Vec<(u16, f64)>,
    last_line_t: Option<f64>,
    last_seq: Option<u16>,
    pub(crate) stale_upto: Option<u16>,
    stale_until: Option<f64>,
}

fn remove(map: &mut Vec<(u16, f64)>, seq: u16) {
    if let Some(i) = map.iter().position(|e| e.0 == seq) {
        map.remove(i);
    }
}

fn contains(map: &[(u16, f64)], seq: u16) -> bool {
    map.iter().any(|e| e.0 == seq)
}

impl PingTracker {
    pub fn new(interval: f64, series: Arc<Series>, loaded_fn: Option<LoadedFn>) -> Self {
        Self {
            interval,
            series,
            loaded_fn,
            pending: Vec::new(),
            charged: Vec::new(),
            last_line_t: None,
            last_seq: None,
            stale_upto: None,
            stale_until: None,
        }
    }

    fn loaded(&self) -> bool {
        self.loaded_fn.as_ref().is_some_and(|f| f())
    }

    fn add(&self, t: f64, rtt: Option<f64>) {
        self.series.add(t, rtt, self.loaded());
    }

    pub fn reset_tracking(&mut self) {
        self.pending.clear();
        self.charged.clear();
        self.last_line_t = None;
        self.last_seq = None;
        self.stale_upto = None;
        self.stale_until = None;
    }

    pub fn drain(&mut self) {
        for &(_, t) in &self.pending {
            self.add(t, None);
        }
        self.reset_tracking();
    }

    fn grace(&self) -> f64 {
        self.interval * 2.5 + 1.0
    }

    fn before_a_stop(&mut self, t: f64, seq: u16) -> bool {
        if let (Some(last_t), Some(last_seq)) = (self.last_line_t, self.last_seq)
            && t - last_t > self.grace()
        {
            self.stale_upto = Some(last_seq.wrapping_add(1));
            self.stale_until = Some(t + self.grace());
        }
        self.last_line_t = Some(t);
        if self.last_seq.is_none_or(|last| seq_after(seq, last)) {
            self.last_seq = Some(seq);
        }
        let (Some(upto), Some(until)) = (self.stale_upto, self.stale_until) else {
            return false;
        };
        if t > until {
            self.stale_upto = None;
            self.stale_until = None;
            return false;
        }
        !seq_after(seq, upto)
    }

    fn expire(&mut self, now: f64) {
        let grace = self.grace();
        let mut i = 0;
        while i < self.pending.len() {
            let (seq, t) = self.pending[i];
            if now - t > grace {
                self.pending.remove(i);
                match self.charged.iter_mut().find(|e| e.0 == seq) {
                    Some(e) => e.1 = now,
                    None => self.charged.push((seq, now)),
                }
                self.add(t, None);
            } else {
                i += 1;
            }
        }
        self.charged.retain(|&(_, t)| now - t <= grace);
    }

    pub fn consume(&mut self, event: PingEvent) {
        match event {
            PingEvent::Reply { t, seq, rtt } => self.answered(t, seq, Some(rtt)),
            PingEvent::Unreachable { t, seq } => self.answered(t, seq, None),
            PingEvent::Pending { t, seq } => {
                if self.before_a_stop(t, seq) {
                    remove(&mut self.pending, seq);
                    self.expire(t);
                    return;
                }
                if !contains(&self.charged, seq) && !contains(&self.pending, seq) {
                    self.pending.push((seq, t));
                }
                self.expire(t);
            }
        }
    }

    fn answered(&mut self, t: f64, seq: u16, rtt: Option<f64>) {
        if self.before_a_stop(t, seq) {
            remove(&mut self.pending, seq);
            return;
        }
        remove(&mut self.pending, seq);
        if !contains(&self.charged, seq) {
            self.add(t, rtt);
        }
        self.expire(t);
    }
}

#[derive(Debug)]
pub struct Sequencer {
    pub next: u16,
    pub unanswered: Option<u16>,
}

impl Default for Sequencer {
    fn default() -> Self {
        Self { next: 1, unanswered: None }
    }
}

impl Sequencer {
    pub fn due(&self, t: f64) -> Option<PingEvent> {
        self.unanswered.map(|seq| PingEvent::Pending { t, seq })
    }

    pub fn sent(&mut self, deferred: bool) {
        if !deferred {
            self.unanswered = Some(self.next);
            self.next = self.next.wrapping_add(1);
        }
    }

    pub fn answered(&mut self, seq: u16) {
        if self.unanswered == Some(seq) {
            self.unanswered = None;
        }
    }
}

pub struct PingProbe {
    pub target: String,
    thread_name: String,
    series: Arc<Series>,
    loaded_fn: Option<LoadedFn>,
    interval: Mutex<f64>,
    restart: AtomicBool,
    wake: Wake,
}

impl PingProbe {
    pub fn new(target: &str, series: Arc<Series>, interval_ms: f64, name: &str, loaded_fn: Option<LoadedFn>) -> Self {
        let label = if name.is_empty() { target } else { name };
        Self {
            target: target.to_string(),
            thread_name: format!("probe-{label}"),
            series,
            loaded_fn,
            interval: Mutex::new((interval_ms / 1000.0).max(MIN_INTERVAL_S)),
            restart: AtomicBool::new(false),
            wake: Wake::new(),
        }
    }

    pub fn start(self: &Arc<Self>) -> io::Result<()> {
        let me = Arc::clone(self);
        thread::Builder::new().name(self.thread_name.clone()).spawn(move || me.run())?;
        Ok(())
    }

    pub fn stop(&self) {
        self.wake.stop();
    }

    pub fn interval(&self) -> f64 {
        *self.interval.lock().unwrap()
    }

    pub fn set_interval(&self, seconds: f64) {
        let seconds = seconds.max(MIN_INTERVAL_S);
        {
            let mut interval = self.interval.lock().unwrap();
            if (seconds - *interval).abs() < 1e-9 {
                return;
            }
            *interval = seconds;
        }
        self.restart.store(true, Ordering::SeqCst);
        self.wake.notify();
    }

    fn run(&self) {
        let mut tracker = PingTracker::new(self.interval(), self.series.clone(), self.loaded_fn.clone());
        let mut backoff: f64 = 1.0;
        while !self.wake.is_stopped() {
            let outcome = if self.target.is_empty() {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "no target"))
            } else {
                self.run_once(&mut tracker)
            };
            match outcome {
                Ok(()) => backoff = 1.0,
                Err(err) => {
                    if backoff == 1.0 && !self.target.is_empty() {
                        crate::util::complain!("nexthop: {} {}: {err}", self.thread_name, self.target);
                    }
                    self.wake.wait(backoff.min(MAX_BACKOFF_S));
                    backoff = (backoff * 2.0).min(MAX_BACKOFF_S);
                }
            }
        }
    }

    fn run_once(&self, tracker: &mut PingTracker) -> io::Result<()> {
        self.restart.store(false, Ordering::SeqCst);
        tracker.reset_tracking();
        tracker.interval = self.interval();
        let result = self.session(tracker);
        tracker.drain();
        result
    }

    fn session(&self, tracker: &mut PingTracker) -> io::Result<()> {
        let dest = icmp::resolve_target(&self.target)?;
        icmp::check_route(dest)?;
        let sock = IcmpSocket::open(dest)?;
        let interval = tracker.interval;
        let mut seqs = Sequencer::default();
        let mut next_send = icmp::clock_ns(libc::CLOCK_BOOTTIME) as f64 / 1e9;
        loop {
            if self.wake.is_stopped() || self.restart.load(Ordering::SeqCst) {
                return Ok(());
            }
            let boot_ns = icmp::clock_ns(libc::CLOCK_BOOTTIME);
            let boot = boot_ns as f64 / 1e9;
            if boot >= next_send {
                if let Some(event) = seqs.due(now()) {
                    tracker.consume(event);
                }
                seqs.sent(send_was_deferred(sock.send(seqs.next, boot_ns as u64)));
                next_send += interval;
                if next_send <= boot {
                    next_send = boot + interval;
                }
            }
            let mut fds = [
                libc::pollfd { fd: sock.raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: self.wake.raw_fd(), events: libc::POLLIN, revents: 0 },
            ];
            let wait = next_send - icmp::clock_ns(libc::CLOCK_BOOTTIME) as f64 / 1e9;
            poll_for(&mut fds, wait, self.wake.tick_cap())?;
            if fds[0].revents & libc::POLLERR != 0 {
                self.read_errors(&sock, tracker, &mut seqs);
            }
            if fds[0].revents & libc::POLLIN != 0 {
                self.read_replies(&sock, tracker, &mut seqs);
            }
            if fds[1].revents != 0 {
                self.wake.drain();
            }
        }
    }

    fn read_replies(&self, sock: &IcmpSocket, tracker: &mut PingTracker, seqs: &mut Sequencer) {
        for _ in 0..DRAIN_BATCH {
            let Ok(Some(received)) = sock.recv(false) else {
                return;
            };
            if let Received::Reply(reply, rx_wall) = received {
                let rtt_us = icmp::rtt_us(
                    reply.sent_ns,
                    icmp::clock_ns(libc::CLOCK_BOOTTIME),
                    icmp::clock_ns(libc::CLOCK_REALTIME),
                    rx_wall,
                );
                seqs.answered(reply.seq);
                let rtt = icmp::ping_display_ms(rtt_us);
                tracker.consume(PingEvent::Reply { t: now(), seq: reply.seq, rtt });
            }
        }
    }

    fn read_errors(&self, sock: &IcmpSocket, tracker: &mut PingTracker, seqs: &mut Sequencer) {
        let mut read_any = false;
        for _ in 0..DRAIN_BATCH {
            let Ok(Some(received)) = sock.recv(true) else {
                break;
            };
            read_any = true;
            if let Received::Error(err) = received {
                on_icmp_error(err, now(), tracker, seqs);
            }
        }
        if !read_any {
            sock.clear_pending_error();
        }
    }
}

// INFO: fc 17oct26 as ping -O: only unreachable answers a request, any other error leaves it pending and so charged as lost
pub fn on_icmp_error(err: icmp::IcmpError, t: f64, tracker: &mut PingTracker, seqs: &mut Sequencer) {
    if err.unreachable {
        seqs.answered(err.seq);
        tracker.consume(PingEvent::Unreachable { t, seq: err.seq });
    }
}

fn send_was_deferred(result: io::Result<()>) -> bool {
    // INFO: fc 17oct26 like iputils, only a full buffer defers a send; any other failure counts as sent and goes unanswered
    matches!(result, Err(e) if matches!(e.raw_os_error(), Some(libc::EAGAIN | libc::ENOBUFS | libc::ENOMEM)))
}
