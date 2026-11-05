#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::paths;
use crate::subproc;
use crate::util::{Job, Spawn, py_round_int, spawn_named};

pub const CHECK_INTERVAL_S: f64 = 24.0 * 3600.0;
pub const FIRST_CHECK_DELAY_S: f64 = 300.0;
pub const GIT_TIMEOUT_S: f64 = 20.0;
pub const MAX_LS_REMOTE_BYTES: usize = 64 * 1024;

pub fn is_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn verdict(
    local: &str,
    remote: &str,
    have_remote: bool,
    head_before_remote: bool,
    remote_before_head: bool,
) -> &'static str {
    if local.is_empty() || remote.is_empty() {
        return "unknown";
    }
    if local == remote {
        return "current";
    }
    if !have_remote || head_before_remote {
        return "behind";
    }
    if remote_before_head {
        return "ahead";
    }
    "diverged"
}

pub type Git<'a> = &'a dyn Fn(&[&str], bool) -> (Option<i32>, String);
type CheckFn = Arc<dyn Fn() -> &'static str + Send + Sync>;

pub fn git(repo: &Path, args: &[&str], capture: bool) -> (Option<i32>, String) {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .args(["-c", "credential.helper=", "-c", "core.askPass="])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_ASKPASS")
        .env_remove("SSH_ASKPASS")
        // INFO: fc 17oct26 stops git walking up into an enclosing repo (dotfiles) when the plugin dir has no .git
        .env("GIT_CEILING_DIRECTORIES", repo.parent().unwrap_or(repo));
    let Some(done) = subproc::run(cmd, None, capture, GIT_TIMEOUT_S) else {
        return (None, String::new());
    };
    let mut out = String::new();
    if capture && !done.stdout.is_empty() {
        let head = &done.stdout[..done.stdout.len().min(MAX_LS_REMOTE_BYTES)];
        out = String::from_utf8_lossy(head).trim().to_string();
    }
    (Some(done.code), out)
}

pub fn local_head(git: Git) -> Option<String> {
    let (code, out) = git(&["rev-parse", "HEAD"], true);
    (code == Some(0) && is_sha(&out)).then_some(out)
}

pub fn remote_head(git: Git) -> Option<String> {
    let (code, out) = git(&["ls-remote", "origin", "HEAD"], true);
    if code != Some(0) || out.is_empty() {
        return None;
    }
    let sha = out.split_whitespace().next().unwrap_or("");
    is_sha(sha).then(|| sha.to_string())
}

pub fn check_with(git: Git) -> &'static str {
    let Some(local) = local_head(git) else {
        return "unknown";
    };
    let Some(remote) = remote_head(git) else {
        return "unknown";
    };
    if local == remote {
        return "current";
    }
    let object = format!("{remote}^{{commit}}");
    let have = git(&["cat-file", "-e", &object], false).0 == Some(0);
    let (mut before, mut after) = (false, false);
    if have {
        before = git(&["merge-base", "--is-ancestor", &local, &remote], false).0 == Some(0);
        after = git(&["merge-base", "--is-ancestor", &remote, &local], false).0 == Some(0);
    }
    verdict(&local, &remote, have, before, after)
}

#[derive(Default)]
struct Shared {
    inflight: bool,
    pending: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpdateSnapshot {
    pub state: &'static str,
    pub available: bool,
    pub checked_ts: Option<i64>,
}

pub struct UpdateWatch {
    pub enabled: bool,
    pub state: &'static str,
    pub checked_ts: Option<i64>,
    next: Option<f64>,
    spawn: Spawn,
    check: CheckFn,
    shared: Arc<Mutex<Shared>>,
}

impl UpdateWatch {
    pub fn new(repo: Option<PathBuf>, enabled: bool, spawn: Option<Spawn>) -> UpdateWatch {
        let repo = repo.unwrap_or_else(paths::plugin_dir);
        let check: CheckFn = Arc::new(move || check_with(&|args, capture| git(&repo, args, capture)));
        UpdateWatch {
            enabled,
            state: "unknown",
            checked_ts: None,
            next: None,
            spawn: spawn.unwrap_or_else(|| Box::new(|job| spawn_named("update-check", job))),
            check,
            shared: Arc::new(Mutex::new(Shared::default())),
        }
    }

    #[cfg(test)]
    pub fn check(&self) -> &'static str {
        (self.check)()
    }

    fn run_check(&self) -> Job {
        let check = Arc::clone(&self.check);
        let shared = Arc::clone(&self.shared);
        Box::new(move || {
            let state = check();
            let mut s = shared.lock().unwrap();
            s.pending = Some(state);
            s.inflight = false;
        })
    }

    fn collect(&mut self, now: f64) {
        let state = self.shared.lock().unwrap().pending.take();
        if let Some(state) = state {
            self.state = state;
            self.checked_ts = Some(py_round_int(now));
        }
    }

    pub fn tick(&mut self, now: f64) {
        if !self.enabled {
            (self.state, self.checked_ts, self.next) = ("unknown", None, None);
            self.shared.lock().unwrap().pending = None;
            return;
        }
        self.collect(now);
        let Some(next) = self.next else {
            self.next = Some(now + FIRST_CHECK_DELAY_S);
            return;
        };
        if now < next {
            return;
        }
        self.next = Some(now + CHECK_INTERVAL_S);
        {
            let mut s = self.shared.lock().unwrap();
            if s.inflight {
                return;
            }
            s.inflight = true;
        }
        if let Err(e) = (self.spawn)(self.run_check()) {
            crate::util::complain!("nexthop: cannot start the update check: {e}");
            self.shared.lock().unwrap().inflight = false;
        }
        self.collect(now);
    }

    pub fn snapshot(&self) -> Option<UpdateSnapshot> {
        if !self.enabled || self.state == "unknown" {
            return None;
        }
        Some(UpdateSnapshot { state: self.state, available: self.state == "behind", checked_ts: self.checked_ts })
    }
}
