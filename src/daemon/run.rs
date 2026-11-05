use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::consts::BENCH_EVAL_EVERY_S;
use super::core::{Daemon, Fallible};
use crate::instruments::Bench;
use crate::pyjson::text;
use crate::state::{retire_legacy_snapshots, write_atomic};

pub const EXIT_LOCK_HELD: i32 = 3;
pub const TICK_S: f64 = 0.5;

static STOP: AtomicBool = AtomicBool::new(false);
static PEAK: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" fn on_peak(_: libc::c_int) {
    PEAK.store(true, Ordering::SeqCst);
}

fn install(signal: libc::c_int, handler: extern "C" fn(libc::c_int)) -> io::Result<()> {
    // SAFETY: a zeroed sigaction is valid; the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|dir| dir.join(name)).find(|candidate| {
        std::fs::metadata(candidate).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

pub fn notify_command(summary: &str, body: &str, urgent: bool, which: &dyn Fn(&str) -> bool) -> Option<Vec<String>> {
    if which("omarchy-notification-send") {
        return Some(vec!["omarchy-notification-send".into(), summary.into(), body.into()]);
    }
    if !which("notify-send") {
        return None;
    }
    let mut cmd: Vec<String> = vec!["notify-send".into(), "-a".into(), "Nexthop".into()];
    if urgent {
        cmd.extend(["-u".into(), "critical".into()]);
    }
    cmd.extend([summary.into(), body.into()]);
    Some(cmd)
}

pub fn notify_send(summary: &str, body: &str, urgent: bool) {
    let Some(argv) = notify_command(summary, body, urgent, &|name| which(name).is_some()) else {
        return;
    };
    let spawned = Command::new(&argv[0]).args(&argv[1..]).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
    if let Ok(mut child) = spawned {
        let _ = std::thread::Builder::new().name("notify".into()).spawn(move || child.wait());
    }
}

pub fn acquire_lock(path: &Path) -> Option<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600)).ok()?;
    // SAFETY: flock on a descriptor we own; the result is checked.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    let mut file = file;
    file.set_len(0).ok()?;
    file.write_all(std::process::id().to_string().as_bytes()).ok()?;
    Some(OwnedFd::from(file))
}

impl Daemon {
    pub fn acquire_lock(&mut self) -> bool {
        self.lock_fd = acquire_lock(&self.lock_path());
        self.lock_fd.is_some()
    }

    pub fn tick(&mut self, now: f64) -> Fallible<()> {
        self.collect_workers();
        self.config.refresh();
        *self.shared.anchor.lock().unwrap() = self.config.internet_anchor();
        self.notify_enabled.store(self.config.notify_outage(), Ordering::SeqCst);
        self.restart_probes_if_settings_changed()?;
        self.follow_route()?;

        self.watch_outages(now, None)?;
        self.follow_path_states(now)?;
        self.follow_lookups(now)?;
        let iface = text(&self.route, "iface").to_string();
        self.throughput(now, &iface);

        let live = self.compose_live(now)?;
        write_atomic(&self.live_path(), &live, false)?;

        if now - self.last_apps_poll >= 3.0 {
            self.last_apps_poll = now;
            self.flush_apps(now)?;
        }

        if now - self.last_minute_flush >= 60.0 {
            self.last_minute_flush = now;
            self.flush_minute(now)?;
            self.flush_recent(now)?;
        } else if now - self.last_recent_flush >= 5.0 {
            self.flush_recent(now)?;
        }

        if now - self.last_rollup >= 3600.0 {
            self.last_rollup = now;
            self.store.rollup_hours(Some(now))?;
            self.store.prune(self.config.history_days(), 400, Some(now))?;
        }

        let answering = self.any_instrument_alive(6.0);
        self.captive.tick(now, answering, self.lookup_watch.answered, self.lookup_watch.failing());
        self.adopt_wan_ip();

        self.update_watch.enabled = self.config.update_check();
        self.update_watch.tick(now);

        self.maybe_content_test(now)?;

        if now - self.last_bench_eval >= BENCH_EVAL_EVERY_S {
            self.last_bench_eval = now;
            let changes = self.bench.evaluate(now, &self.instrument_stats(Bench::WINDOW_S));
            self.apply_seats(&changes);
            self.sync_active();
        }

        if PEAK.load(Ordering::SeqCst) && !self.content_running() {
            PEAK.store(false, Ordering::SeqCst);
            self.run_peak_test()?;
        }
        Ok(())
    }

    pub fn run_loop(&mut self) -> Fallible<()> {
        while !STOP.load(Ordering::SeqCst) {
            let now = self.now();
            self.tick(now)?;
            let left = TICK_S - (self.now() - now);
            std::thread::sleep(Duration::from_secs_f64(left.max(0.1)));
        }
        Ok(())
    }

    fn start_all(&mut self) -> Fallible<()> {
        install(libc::SIGTERM, on_stop)?;
        install(libc::SIGINT, on_stop)?;
        install(libc::SIGUSR1, on_peak)?;
        self.nl_events.start()?;
        self.link.start()?;
        self.start_probes()?;
        self.run_loop()
    }

    pub fn run(&mut self) -> i32 {
        if !self.acquire_lock() {
            crate::util::complain!("nexthopd: another instance holds the lock, exiting");
            return EXIT_LOCK_HELD;
        }
        let now = self.now();
        let prepared = self.store.close_orphans(Some(now)).map(drop).map_err(|e| e.to_string()).and_then(|_| {
            retire_legacy_snapshots(&self.state_dir, &self.runtime_dir, Some(now)).map_err(|e| e.to_string())
        });
        if let Err(e) = prepared {
            crate::util::complain!("nexthopd: {e}");
            return 1;
        }
        let outcome = self.start_all();
        for p in &self.probes {
            p.stop();
        }
        self.link.stop();
        self.nl_events.stop();
        self.store.close();
        match outcome {
            Ok(()) => 0,
            Err(e) => {
                crate::util::complain!("nexthopd: {e}");
                1
            }
        }
    }
}

pub fn main() -> i32 {
    match Daemon::new() {
        Ok(mut daemon) => daemon.run(),
        Err(e) => {
            crate::util::complain!("nexthopd: {e}");
            1
        }
    }
}
