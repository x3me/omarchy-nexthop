use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

use crate::util::monotonic;

const MAX_CAPTURE: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq)]
pub struct Finished {
    pub code: i32,
    pub stdout: Vec<u8>,
}

struct Running<'a> {
    child: Child,
    pidfd: OwnedFd,
    stdin: Option<ChildStdin>,
    input: &'a [u8],
    written: usize,
    stdout: Option<ChildStdout>,
    captured: Vec<u8>,
    code: Option<i32>,
}

#[derive(Clone, Copy)]
enum Watch {
    Stdin,
    Stdout,
    Exit,
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| -status.signal().unwrap_or(0))
}

fn pidfd_open(pid: u32) -> std::io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by the kernel and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    // SAFETY: fcntl on an fd we own, with integer arguments only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

impl<'a> Running<'a> {
    fn new(mut child: Child, input: &'a [u8]) -> std::io::Result<Self> {
        let prepared = pidfd_open(child.id()).and_then(|pidfd| {
            if let Some(stdin) = &child.stdin {
                set_nonblocking(stdin.as_raw_fd())?;
            }
            Ok(pidfd)
        });
        let pidfd = match prepared {
            Ok(fd) => fd,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let mut stdin = child.stdin.take();
        if input.is_empty() {
            stdin = None;
        }
        let stdout = child.stdout.take();
        Ok(Running { child, pidfd, stdin, input, written: 0, stdout, captured: Vec::new(), code: None })
    }

    fn feed(&mut self) {
        let Some(stdin) = self.stdin.as_mut() else {
            return;
        };
        match stdin.write(&self.input[self.written..]) {
            Ok(n) => {
                self.written += n;
                if self.written >= self.input.len() {
                    self.stdin = None;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(_) => self.stdin = None,
        }
    }

    fn drain(&mut self) {
        let Some(stdout) = self.stdout.as_mut() else {
            return;
        };
        let mut chunk = [0u8; 16 * 1024];
        match stdout.read(&mut chunk) {
            Ok(0) => self.stdout = None,
            Ok(n) => {
                let room = MAX_CAPTURE.saturating_sub(self.captured.len());
                self.captured.extend_from_slice(&chunk[..n.min(room)]);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(_) => self.stdout = None,
        }
    }

    fn reap(&mut self) {
        match self.child.try_wait() {
            Ok(Some(status)) => self.code = Some(exit_code(status)),
            Ok(None) => {}
            Err(e) => {
                crate::util::complain!("nexthop: waiting for child {}: {e}", self.child.id());
                self.code = Some(-1);
            }
        }
    }

    fn done(&self) -> bool {
        self.stdin.is_none() && self.stdout.is_none() && self.code.is_some()
    }

    fn finish(mut self) -> Option<Finished> {
        if self.done() {
            return Some(Finished { code: self.code.unwrap_or(-1), stdout: self.captured });
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        None
    }
}

pub fn run(cmd: Command, input: Option<&[u8]>, capture: bool, timeout: f64) -> Option<Finished> {
    run_many(vec![cmd], input, capture, timeout).pop().and_then(|(_, done)| done)
}

pub fn run_many(cmds: Vec<Command>, input: Option<&[u8]>, capture: bool, timeout: f64) -> Vec<(f64, Option<Finished>)> {
    let mut procs = Vec::with_capacity(cmds.len());
    for mut cmd in cmds {
        cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(if capture { Stdio::piped() } else { Stdio::null() })
            .stderr(Stdio::null());
        let spawned = monotonic();
        let Ok(child) = cmd.spawn() else { continue };
        match Running::new(child, input.unwrap_or_default()) {
            Ok(running) => procs.push((spawned, running)),
            Err(e) => crate::util::complain!("nexthop: cannot watch {:?}: {e}", cmd.get_program()),
        }
    }
    let deadline = monotonic() + timeout;
    let mut fds: Vec<libc::pollfd> = Vec::new();
    let mut owners: Vec<(usize, Watch)> = Vec::new();
    loop {
        fds.clear();
        owners.clear();
        for (i, (_, p)) in procs.iter().enumerate() {
            if let Some(stdin) = &p.stdin {
                fds.push(libc::pollfd { fd: stdin.as_raw_fd(), events: libc::POLLOUT, revents: 0 });
                owners.push((i, Watch::Stdin));
            }
            if let Some(stdout) = &p.stdout {
                fds.push(libc::pollfd { fd: stdout.as_raw_fd(), events: libc::POLLIN, revents: 0 });
                owners.push((i, Watch::Stdout));
            }
            if p.code.is_none() {
                fds.push(libc::pollfd { fd: p.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 });
                owners.push((i, Watch::Exit));
            }
        }
        if fds.is_empty() {
            break;
        }
        let left = deadline - monotonic();
        if left <= 0.0 {
            break;
        }
        let ms = (left * 1000.0).ceil().min(i32::MAX as f64) as libc::c_int;
        // SAFETY: fds is a live, correctly sized array of pollfd.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            crate::util::complain!("nexthop: poll on child pipes: {err}");
            break;
        }
        for (fd, &(i, watch)) in fds.iter().zip(&owners) {
            if fd.revents == 0 {
                continue;
            }
            let p = &mut procs[i].1;
            match watch {
                Watch::Stdin => p.feed(),
                Watch::Stdout => p.drain(),
                Watch::Exit => p.reap(),
            }
        }
    }
    procs.into_iter().map(|(spawned, p)| (spawned, p.finish())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[test]
    fn captures_stdout_and_exit_code() {
        let done = run(sh("printf 'hi there'; exit 3"), None, true, 5.0).expect("finished");
        assert_eq!(done.code, 3);
        assert_eq!(done.stdout, b"hi there");
    }

    #[test]
    fn feeds_an_input_larger_than_a_pipe_while_reading() {
        let body = vec![7u8; 1_000_000];
        let done = run(Command::new("cat"), Some(&body), true, 10.0).expect("finished");
        assert_eq!(done.code, 0);
        assert_eq!(done.stdout.len(), body.len());
    }

    #[test]
    fn uncaptured_child_still_reports_its_code() {
        let done = run(sh("echo ignored; exit 1"), None, false, 5.0).expect("finished");
        assert_eq!(done, Finished { code: 1, stdout: Vec::new() });
    }

    #[test]
    fn a_child_past_its_timeout_is_killed_and_yields_none() {
        let started = monotonic();
        assert_eq!(run(sh("exec sleep 30"), None, true, 0.2), None);
        assert!(monotonic() - started < 5.0);
    }

    #[test]
    fn a_missing_program_is_skipped_like_an_oserror() {
        let got = run_many(vec![Command::new("/nonexistent/nexthop-test"), sh("exit 0")], None, true, 5.0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1.as_ref().map(|f| f.code), Some(0));
    }

    #[test]
    fn children_run_concurrently() {
        let started = monotonic();
        let cmds = (0..4).map(|_| sh("sleep 0.3; echo done")).collect();
        let got = run_many(cmds, None, true, 10.0);
        assert!(got.iter().all(|(_, f)| f.as_ref().is_some_and(|f| f.stdout == b"done\n")));
        assert!(monotonic() - started < 1.0);
    }
}
