use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::args::py_int;
use crate::util::{read_capped, start_ticks_from_stat};

pub fn is_daemon_argv(argv: &[String]) -> bool {
    match argv {
        [exe, verb] => (exe == "nexthop" || exe.ends_with("/nexthop")) && verb == "daemon",
        [python, flag, module] => is_python_daemon(python, flag, module),
        _ => false,
    }
}

// TODO: fc 17oct26 the Python daemon this release replaces must stay retirable; remove once 0.2.71 installs have updated
fn is_python_daemon(python: &str, flag: &str, module: &str) -> bool {
    let name = python.rsplit('/').next().unwrap_or(python);
    name.contains("python") && flag == "-m" && module == "nexthopd"
}

pub fn authorized_to_retire(pid: i64, want_start: i64) -> bool {
    let Ok(meta) = fs::metadata(format!("/proc/{pid}")) else {
        return false;
    };
    // SAFETY: getuid has no preconditions and cannot fail.
    if meta.uid() != unsafe { libc::getuid() } {
        return false;
    }
    let (Ok(cmdline), Ok(stat)) =
        (read_capped(format!("/proc/{pid}/cmdline"), 4096), read_capped(format!("/proc/{pid}/stat"), 4096))
    else {
        return false;
    };
    let argv: Vec<String> =
        cmdline.split(|&b| b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    if !is_daemon_argv(&argv) {
        return false;
    }
    if want_start != 0 {
        match start_ticks_from_stat(&stat) {
            Some(start) if start == want_start => {}
            _ => return false,
        }
    }
    true
}

pub fn lock_holder_pid(lock: &Path) -> i64 {
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let Ok(mut file) = OpenOptions::new().read(true).custom_flags(flags).open(lock) else {
        return 0;
    };
    match file.metadata() {
        Ok(meta) if meta.file_type().is_file() => {}
        _ => return 0,
    }
    let fd = file.as_raw_fd();
    // SAFETY: fd is a valid open descriptor owned by `file` for the duration of the call.
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let mut buf = [0u8; 32];
        return match file.read(&mut buf) {
            Ok(n) => py_int(&String::from_utf8_lossy(&buf[..n])).unwrap_or(0),
            Err(_) => 0,
        };
    }
    // SAFETY: as above; releases the lock this call just took.
    unsafe { libc::flock(fd, libc::LOCK_UN) };
    0
}

pub struct Pinned {
    #[cfg(test)]
    pub pid: i64,
    fd: OwnedFd,
}

pub fn pin(pid: i64) -> io::Result<Pinned> {
    let raw = libc::pid_t::try_from(pid).map_err(|_| io::Error::from_raw_os_error(libc::ESRCH))?;
    // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, raw, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a freshly opened descriptor nobody else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    Ok(Pinned {
        #[cfg(test)]
        pid,
        fd,
    })
}

pub fn kill(target: &Pinned, sig: i32) -> io::Result<()> {
    // SAFETY: the pidfd stays open for the call; a null siginfo is allowed.
    let rc = unsafe {
        libc::syscall(libc::SYS_pidfd_send_signal, target.fd.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0)
    };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_daemon_argv_passes() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_daemon_argv(&argv(&["nexthop", "daemon"])));
        assert!(is_daemon_argv(&argv(&["/home/u/.config/omarchy/plugins/x/bin/nexthop", "daemon"])));
        assert!(!is_daemon_argv(&argv(&["/usr/bin/notnexthop", "daemon"])));
        assert!(!is_daemon_argv(&argv(&["nexthop", "daemon", "--x"])));
        assert!(!is_daemon_argv(&argv(&["nexthop", "stream", "live"])));
        assert!(!is_daemon_argv(&argv(&["nexthop"])));
        assert!(is_daemon_argv(&argv(&["python3", "-m", "nexthopd"])));
        assert!(is_daemon_argv(&argv(&["/usr/bin/python3.14", "-m", "nexthopd"])));
        assert!(!is_daemon_argv(&argv(&["python3", "-m", "nexthopd.cli"])));
        assert!(!is_daemon_argv(&argv(&["python3", "-c", "nexthopd"])));
        assert!(!is_daemon_argv(&argv(&["/usr/bin/sh", "-m", "nexthopd"])));
    }
}
