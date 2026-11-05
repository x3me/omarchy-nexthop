use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::util::monotonic;

const FALLBACK_TICK_S: f64 = 0.2;

pub struct Wake {
    fd: Option<OwnedFd>,
    stopped: AtomicBool,
}

impl Default for Wake {
    fn default() -> Self {
        Self::new()
    }
}

impl Wake {
    pub fn new() -> Self {
        // SAFETY: eventfd takes no pointers; a non-negative return is a fresh fd we own.
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        // SAFETY: raw is a valid, owned descriptor when non-negative.
        let fd = (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw) });
        Self { fd, stopped: AtomicBool::new(false) }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_ref().map_or(-1, |fd| fd.as_raw_fd())
    }

    pub fn notify(&self) {
        if let Some(fd) = &self.fd {
            let one: u64 = 1;
            // SAFETY: writes 8 bytes from a live u64 to an eventfd we own.
            unsafe { libc::write(fd.as_raw_fd(), (&one as *const u64).cast(), 8) };
        }
    }

    pub fn drain(&self) {
        if let Some(fd) = &self.fd {
            let mut value: u64 = 0;
            // SAFETY: reads at most 8 bytes into a live u64 from a non-blocking eventfd.
            unsafe { libc::read(fd.as_raw_fd(), (&mut value as *mut u64).cast(), 8) };
        }
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.notify();
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    pub fn tick_cap(&self) -> Option<f64> {
        self.fd.is_none().then_some(FALLBACK_TICK_S)
    }

    pub fn wait(&self, seconds: f64) -> bool {
        let deadline = monotonic() + seconds;
        loop {
            if self.is_stopped() {
                return true;
            }
            let remaining = deadline - monotonic();
            if remaining <= 0.0 {
                return false;
            }
            let mut fds = [libc::pollfd { fd: self.raw_fd(), events: libc::POLLIN, revents: 0 }];
            if poll_for(&mut fds, remaining, self.tick_cap()).is_err() {
                return self.is_stopped();
            }
            self.drain();
        }
    }
}

pub fn poll_for(fds: &mut [libc::pollfd], seconds: f64, cap: Option<f64>) -> io::Result<usize> {
    let seconds = cap.map_or(seconds, |c| seconds.min(c)).max(0.0);
    let ms = (seconds * 1000.0).ceil().min(i32::MAX as f64) as libc::c_int;
    // SAFETY: fds is a live, correctly sized slice of pollfd for the duration of the call.
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(err);
    }
    Ok(n as usize)
}
