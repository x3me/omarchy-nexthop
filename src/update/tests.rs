use std::cell::RefCell;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::*;
use crate::testutil::{TempDir, run_inline};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn always(state: &'static str) -> CheckFn {
    Arc::new(move || state)
}

#[test]
fn verdict_states() {
    assert_eq!(verdict(A, A, true, false, false), "current");
    assert_eq!(verdict(A, B, false, false, false), "behind");
    // `omarchy plugin update` fetches before showing its diff, so a user who declined holds origin's commit.
    assert_eq!(verdict(A, B, true, true, false), "behind");
    assert_eq!(verdict(A, B, true, false, true), "ahead");
    assert_eq!(verdict(A, B, true, false, false), "diverged");
    assert_eq!(verdict("", B, false, false, false), "unknown");
    assert_eq!(verdict(A, "", false, false, false), "unknown");
}

#[test]
fn remote_sha_must_be_an_object_id() {
    let bad = [
        String::new(),
        "HEAD".into(),
        "a".repeat(39),
        "a".repeat(41),
        "A".repeat(40),
        "g".repeat(40),
        "../../etc/passwd".into(),
        format!("{A} --upload-pack=sh"),
        "--upload-pack=evil".into(),
        format!("{A}\n{B}"),
        format!("{A}\n"),
    ];
    for s in &bad {
        assert!(!is_sha(s), "{s:?}");
    }
    assert!(is_sha(A));
}

#[test]
fn junk_from_the_remote_yields_unknown_not_a_crash() {
    let calls = RefCell::new(Vec::new());
    let fake = |args: &[&str], _capture: bool| {
        calls.borrow_mut().push(args[0].to_string());
        match args[0] {
            "rev-parse" => (Some(0), A.to_string()),
            "ls-remote" => (Some(0), "not-a-sha\tHEAD".to_string()),
            _ => (Some(0), String::new()),
        }
    };
    assert_eq!(check_with(&fake), "unknown");
    assert!(!calls.borrow().iter().any(|c| c == "cat-file"));
}

#[test]
fn behind_is_reported_without_any_write() {
    let seen = RefCell::new(Vec::new());
    let fake = |args: &[&str], _capture: bool| {
        seen.borrow_mut().push(args[0].to_string());
        match args[0] {
            "rev-parse" => (Some(0), A.to_string()),
            "ls-remote" => (Some(0), format!("{B}\tHEAD")),
            "cat-file" => (Some(1), String::new()),
            _ => (Some(0), String::new()),
        }
    };
    assert_eq!(check_with(&fake), "behind");
    let read_only = ["rev-parse", "ls-remote", "cat-file", "merge-base"];
    assert!(seen.borrow().iter().all(|v| read_only.contains(&v.as_str())), "{:?}", seen.borrow());
}

#[test]
fn every_git_argv_is_the_python_one() {
    let seen = RefCell::new(Vec::new());
    let fake = |args: &[&str], capture: bool| {
        seen.borrow_mut().push((args.join(" "), capture));
        match args[0] {
            "rev-parse" => (Some(0), A.to_string()),
            "ls-remote" => (Some(0), format!("{B}\tHEAD")),
            "merge-base" => (Some(if args[2] == A { 0 } else { 1 }), String::new()),
            _ => (Some(0), String::new()),
        }
    };
    assert_eq!(check_with(&fake), "behind");
    let expected = [
        ("rev-parse HEAD".to_string(), true),
        ("ls-remote origin HEAD".to_string(), true),
        (format!("cat-file -e {B}^{{commit}}"), false),
        (format!("merge-base --is-ancestor {A} {B}"), false),
        (format!("merge-base --is-ancestor {B} {A}"), false),
    ];
    assert_eq!(*seen.borrow(), expected);
}

#[test]
fn cadence_delays_the_first_check_and_then_spaces_them() {
    let mut w = UpdateWatch::new(Some(repo()), true, run_inline());
    w.check = always("behind");
    w.tick(1000.0);
    assert_eq!(w.checked_ts, None);
    w.tick(1000.0 + 299.0);
    assert_eq!(w.checked_ts, None);
    w.tick(1000.0 + 301.0);
    assert_eq!(w.state, "behind");
    assert!(w.snapshot().expect("snapshot").available);
    let first = w.checked_ts;
    w.check = always("current");
    w.tick(1000.0 + 3600.0);
    assert_eq!(w.checked_ts, first);
    w.tick(1000.0 + 301.0 + 24.0 * 3600.0 + 1.0);
    assert_eq!(w.state, "current");
    assert!(!w.snapshot().expect("snapshot").available);
}

#[test]
fn disabled_makes_no_check_and_clears_any_notice() {
    let mut w = UpdateWatch::new(Some(repo()), true, run_inline());
    w.check = always("behind");
    w.tick(1000.0);
    w.tick(1000.0 + 301.0);
    assert!(w.snapshot().expect("snapshot").available);
    w.enabled = false;
    let called = Arc::new(Mutex::new(0));
    let counter = Arc::clone(&called);
    w.check = Arc::new(move || {
        *counter.lock().unwrap() += 1;
        "behind"
    });
    w.tick(1000.0 + 301.0 + 24.0 * 3600.0 + 1.0);
    assert_eq!(*called.lock().unwrap(), 0);
    assert_eq!(w.snapshot(), None);
}

#[test]
fn nothing_published_until_something_is_known() {
    let w = UpdateWatch::new(Some(repo()), true, None);
    assert_eq!(w.snapshot(), None);
}

#[test]
fn snapshot_serializes_with_python_keys() {
    let mut w = UpdateWatch::new(Some(repo()), true, run_inline());
    w.check = always("ahead");
    w.tick(1000.0);
    w.tick(1300.5);
    let json = serde_json::to_string(&w.snapshot()).expect("json");
    assert_eq!(json, r#"{"state":"ahead","available":false,"checked_ts":1300}"#);
}

fn git_out(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("git").arg("-C").arg(dir).args(args).stderr(Stdio::null()).output().expect("git runs");
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
#[ignore = "contacts the checkout's real origin over the network"]
fn real_checkout_is_read_only_and_answers() {
    let before = git_out(&repo(), &["status", "--porcelain"]);
    let head_before = git_out(&repo(), &["rev-parse", "HEAD"]);
    let w = UpdateWatch::new(Some(repo()), true, None);
    assert!(["current", "behind", "ahead", "diverged", "unknown"].contains(&w.check()));
    assert_eq!(before, git_out(&repo(), &["status", "--porcelain"]));
    assert_eq!(head_before, git_out(&repo(), &["rev-parse", "HEAD"]));
}

#[test]
fn real_clone_one_commit_behind_reports_behind() {
    let tmp = TempDir::new();
    let clone = tmp.path().join("c");
    let cloned = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(repo())
        .arg(&clone)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !cloned.is_ok_and(|s| s.success()) {
        eprintln!("skipped: git clone unavailable");
        return;
    }
    if !git_out(&clone, &["rev-parse", "HEAD~1"]).0 {
        eprintln!("skipped: shallow history");
        return;
    }
    assert!(git_out(&clone, &["reset", "--quiet", "--hard", "HEAD~1"]).0);
    let mut w = UpdateWatch::new(Some(clone), true, run_inline());
    assert_eq!(w.check(), "behind");
    assert_eq!(w.snapshot(), None);
    w.tick(1000.0);
    w.tick(1000.0 + 301.0);
    assert!(w.snapshot().expect("snapshot").available);
}

#[test]
fn manifest_exposes_the_setting() {
    let text = std::fs::read_to_string(repo().join("manifest.json")).expect("manifest");
    let m: serde_json::Value = serde_json::from_str(&text).expect("json");
    let entry = m["barWidget"]["schema"]
        .as_array()
        .expect("schema")
        .iter()
        .find(|e| e["key"] == "updateCheck")
        .expect("updateCheck entry");
    assert_eq!(entry["type"], "boolean");
    assert_eq!(entry["defaultValue"], true);
    assert!(entry["description"].as_str().expect("description").contains("never installs"));
}

#[test]
fn a_plain_directory_inside_a_repo_is_not_that_repo() {
    let tmp = TempDir::new();
    if !git_out(tmp.path(), &["init", "-q"]).0 {
        eprintln!("skipped: git not installed");
        return;
    }
    let sub = tmp.path().join("plugins").join("io.github.x3me.nexthop");
    std::fs::create_dir_all(&sub).expect("subdir");
    let w = UpdateWatch::new(Some(sub.clone()), true, None);
    assert_eq!(local_head(&|args, capture| git(&sub, args, capture)), None);
    assert_eq!(w.check(), "unknown");
}

type Held = Arc<Mutex<Vec<Job>>>;

fn held_watch() -> (UpdateWatch, Held) {
    let held: Held = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&held);
    let spawn: Spawn = Box::new(move |job| {
        sink.lock().unwrap().push(job);
        Ok(())
    });
    let mut w = UpdateWatch::new(Some(repo()), true, Some(spawn));
    w.check = always("behind");
    (w, held)
}

fn finish_first(held: &Held) {
    let job = held.lock().unwrap().remove(0);
    job();
}

#[test]
fn tick_returns_before_the_check_finishes() {
    let (mut w, held) = held_watch();
    w.tick(1000.0);
    w.tick(1000.0 + 301.0);
    assert_eq!(held.lock().unwrap().len(), 1);
    assert_eq!(w.state, "unknown");
    assert_eq!(w.snapshot(), None);
    finish_first(&held);
    w.tick(1000.0 + 302.0);
    assert_eq!(w.state, "behind");
    assert_eq!(w.checked_ts, Some(1302));
}

#[test]
fn no_second_check_while_one_is_in_flight() {
    let (mut w, held) = held_watch();
    w.tick(1000.0);
    w.tick(1000.0 + 301.0);
    w.tick(1000.0 + 301.0 + 24.0 * 3600.0 + 1.0);
    assert_eq!(held.lock().unwrap().len(), 1);
}

#[test]
fn disabling_drops_an_answer_still_in_flight() {
    let (mut w, held) = held_watch();
    w.tick(1000.0);
    w.tick(1000.0 + 301.0);
    w.enabled = false;
    w.tick(1000.0 + 302.0);
    finish_first(&held);
    w.tick(1000.0 + 303.0);
    assert_eq!(w.snapshot(), None);
    w.enabled = true;
    w.tick(1000.0 + 304.0);
    assert_eq!(w.snapshot(), None);
}

#[test]
fn a_spawn_failure_does_not_wedge_the_watch() {
    let mut w = UpdateWatch::new(Some(repo()), true, Some(Box::new(|_job| Err(std::io::Error::other("no threads")))));
    w.tick(1000.0);
    w.tick(1000.0 + 301.0);
    assert!(!w.shared.lock().unwrap().inflight);
}
