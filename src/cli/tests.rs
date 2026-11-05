use super::stream::{STREAMABLE, Streamer};
use super::*;
use crate::store::TestRow;
use crate::testutil::TempDir;
use serde_json::Map;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

struct Spawned(Child);

impl Spawned {
    fn pid(&self) -> i64 {
        self.0.id() as i64
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// INFO: fc 17oct26 `yes` blocks once the pipe fills, idling with exactly our argv; its first byte proves exec finished
fn spawn_as(argv0: &str, args: &[&str]) -> Spawned {
    let mut child = Command::new("yes")
        .arg0(argv0)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn yes");
    let mut first = [0u8; 1];
    child.stdout.as_mut().unwrap().read_exact(&mut first).expect("yes started");
    Spawned(child)
}

fn daemon_shaped(dir: &TempDir) -> Spawned {
    spawn_as(dir.path().join("bin").join("nexthop").to_str().unwrap(), &["daemon"])
}

fn ticks(pid: i64) -> i64 {
    crate::util::proc_start_ticks(pid).unwrap()
}

#[test]
fn daemon_argv_with_matching_start_is_authorized() {
    let d = TempDir::new();
    let p = daemon_shaped(&d);
    assert!(authorized_to_retire(p.pid(), ticks(p.pid())));
}

#[test]
fn bare_program_name_is_authorized() {
    let p = spawn_as("nexthop", &["daemon"]);
    assert!(authorized_to_retire(p.pid(), ticks(p.pid())));
}

#[test]
fn wrong_start_time_refused() {
    let d = TempDir::new();
    let p = daemon_shaped(&d);
    assert!(!authorized_to_retire(p.pid(), ticks(p.pid()) + 1));
}

#[test]
fn zero_start_skips_only_the_time_check() {
    let d = TempDir::new();
    let p = daemon_shaped(&d);
    assert!(authorized_to_retire(p.pid(), 0));
}

#[test]
fn other_nexthop_command_refused() {
    let d = TempDir::new();
    let p = spawn_as(d.path().join("nexthop").to_str().unwrap(), &["report"]);
    assert!(!authorized_to_retire(p.pid(), 0));
}

#[test]
fn lookalike_argv_refused() {
    let p = spawn_as("yes", &["nexthop daemon"]);
    assert!(!authorized_to_retire(p.pid(), 0));
    let p = spawn_as("/usr/bin/notnexthop", &["daemon"]);
    assert!(!authorized_to_retire(p.pid(), 0));
}

#[test]
fn extra_arguments_refused() {
    let d = TempDir::new();
    let p = spawn_as(d.path().join("nexthop").to_str().unwrap(), &["daemon", "stream"]);
    assert!(!authorized_to_retire(p.pid(), 0));
}

#[test]
fn pid_that_does_not_exist_refused() {
    assert!(!authorized_to_retire(2_147_483_646, 0));
}

#[test]
fn pid_one_refused() {
    assert!(!authorized_to_retire(1, 0));
}

#[test]
fn retire_refuses_a_stranger_without_signalling() {
    assert_eq!(main(["retire", "--pid", "999999", "--start", "0"].map(String::from).to_vec()), 1);
    let mut killed = Vec::new();
    let p = spawn_as("yes", &[]);
    assert_eq!(
        retire(p.pid(), 0, &mut |target, sig| {
            killed.push((target.pid, sig));
            Ok(())
        }),
        1
    );
    assert_eq!(
        retire(std::process::id() as i64, 0, &mut |target, sig| {
            killed.push((target.pid, sig));
            Ok(())
        }),
        1
    );
    assert!(killed.is_empty());
}

#[test]
fn retire_signals_a_verified_daemon_with_sigterm() {
    let d = TempDir::new();
    let p = daemon_shaped(&d);
    let mut killed = Vec::new();
    assert_eq!(
        retire(p.pid(), ticks(p.pid()), &mut |target, sig| {
            killed.push((target.pid, sig));
            Ok(())
        }),
        0
    );
    assert_eq!(killed, [(p.pid(), libc::SIGTERM)]);
}

struct Peak {
    dir: TempDir,
    killed: Vec<(i64, i32)>,
}

impl Peak {
    fn new() -> Peak {
        Peak { dir: TempDir::new(), killed: Vec::new() }
    }

    fn lock(&self) -> std::path::PathBuf {
        self.dir.path().join("nexthopd.lock")
    }

    fn live(&self) -> std::path::PathBuf {
        self.dir.path().join("live.json")
    }

    fn run(&mut self) -> (i32, Value) {
        let (lock, live) = (self.lock(), self.live());
        let killed = &mut self.killed;
        peak(&lock, &live, &mut |target, sig| {
            killed.push((target.pid, sig));
            Ok(())
        })
    }

    fn hold(&self, pid: i64) -> fs::File {
        let f = fs::File::create(self.lock()).unwrap();
        // SAFETY: f is an open descriptor for the duration of the call.
        assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0, "lock already held");
        fs::write(self.lock(), pid.to_string()).unwrap();
        f
    }
}

#[test]
fn a_lock_nobody_holds_is_not_a_daemon() {
    let mut t = Peak::new();
    fs::write(t.lock(), std::process::id().to_string()).unwrap();
    assert_eq!(t.run().0, 1);
    assert!(t.killed.is_empty());
}

#[test]
fn a_held_lock_still_needs_the_holders_identity() {
    let mut t = Peak::new();
    let held = t.hold(std::process::id() as i64);
    assert_eq!(t.run(), (1, json!({"ok": false, "error": "daemon not running"})));
    drop(held);
    let stranger = spawn_as("yes", &[]);
    let _held = t.hold(stranger.pid());
    assert_eq!(t.run(), (1, json!({"ok": false, "error": "lock holder is not nexthopd"})));
    assert!(t.killed.is_empty());
}

#[test]
fn a_verified_lock_holder_gets_sigusr1() {
    let mut t = Peak::new();
    let daemon = daemon_shaped(&t.dir);
    let _held = t.hold(daemon.pid());
    fs::write(t.live(), json!({"pid": daemon.pid(), "pid_start": ticks(daemon.pid()) + 1}).to_string()).unwrap();
    assert_eq!(t.run().0, 1);
    fs::write(t.live(), json!({"pid": daemon.pid(), "pid_start": ticks(daemon.pid())}).to_string()).unwrap();
    assert_eq!(t.run(), (0, json!({"ok": true})));
    assert_eq!(t.killed, [(daemon.pid(), libc::SIGUSR1)]);
}

#[test]
fn a_symlink_at_the_lock_path_is_refused() {
    let mut t = Peak::new();
    std::os::unix::fs::symlink("/proc/self/stat", t.lock()).unwrap();
    assert_eq!(t.run().0, 1);
    assert!(t.killed.is_empty());
}

#[test]
fn missing_lock_file_is_not_a_daemon() {
    let mut t = Peak::new();
    assert_eq!(t.run().0, 1);
    assert!(t.killed.is_empty());
}

fn values(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn wall() -> f64 {
    crate::util::now()
}

#[test]
fn tunnel_minutes_are_kept_out_of_the_wan_leg_and_named() {
    let d = TempDir::new();
    let store = Store::new(&d.path().join("t.db"), false).unwrap();
    let now = wall();
    let base = (now / 60.0).floor() as i64 * 60;
    for m in 0..30 {
        let line = json!({"local_p50": 2.0, "wan_p50": 6.0, "wan_p95": 9.0, "wan_loss": 0.0, "local_loss": 0.0});
        store.put_minute(base - 3600 + 60 * m, &values(line), "", "", "").unwrap();
        let tunnel = json!({"local_p50": 2.0, "wan_p50": 150.0, "wan_p95": 190.0, "wan_loss": 0.0,
                            "local_loss": 0.0, "vpn": "wg0"});
        store.put_minute(base - 1800 + 60 * m, &values(tunnel), "", "", "").unwrap();
    }
    let eid = store.open_event(base - 1800, "vpn", "info", "tunnel", "Measured through a VPN (wg0)").unwrap();
    store.close_event(eid, base, None).unwrap();
    let row = TestRow { down_mbps: Some(90.0), up_mbps: Some(30.0), vpn: Some("wg0".into()), ..TestRow::default() };
    store.put_test((now - 60.0) as i64, "content", "cloudflare", &row).unwrap();
    let text = report_text(Some(&store), &json!({}), 2.0 * 3600.0, "2h", &mut |_| None).unwrap();
    let wan = text.lines().find(|l| l.starts_with("wan leg")).unwrap();
    assert!(wan.contains("median 6.0 ms"), "{wan}");
    assert!(text.contains("through a VPN (past router, not the ISP line): median 150.0 ms"));
    assert!(text.contains("measured through a VPN (wg0): figures in this span describe the tunnel, not the ISP line."));
    assert!(text.lines().find(|l| l.contains("90/30")).unwrap().contains("via VPN"));
}

#[test]
fn a_newline_in_an_ssid_does_not_forge_a_line() {
    // What net.wifi_link hands over for the SSID "Cafe\x0aevents: none".
    let link = json!({"ssid": "Cafe\u{fffd}events: none", "kind": "wifi", "gateway": "192.168.1.1"});
    let text = report_text(None, &json!({"link": link}), 3600.0, "1h", &mut |_| None).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("connection:")).collect();
    assert_eq!(lines, ["connection: Cafe\u{fffd}events: none (wifi), gateway 192.168.1.1"]);
    assert!(!text.contains("\nevents: none"));
}

#[test]
fn an_orphan_is_reported_without_a_length() {
    let d = TempDir::new();
    let store = Store::new(&d.path().join("t.db"), false).unwrap();
    let now = wall() as i64;
    store.open_event(now - 600, "outage", "critical", "wan", "router answers, nothing past it does").unwrap();
    store.open_event(now - 900, "vpn", "info", "tunnel", "Measured through a VPN (wg0)").unwrap();
    let seen = store.open_event(now - 300, "disruption", "warn", "local", "brief interruption").unwrap();
    store.close_event(seen, now - 297, None).unwrap();
    store.close_orphans(Some(now as f64)).unwrap();
    let text = report_text(Some(&store), &json!({}), 3600.0, "1h", &mut |_| None).unwrap();
    let outage = text.lines().find(|l| l.contains("outage on wan")).unwrap();
    assert!(outage.contains("duration unknown (monitoring stopped first)"));
    assert!(!outage.contains(", 1s"));
    assert!(text.contains("onwards (end not seen) measured through a VPN (wg0)"));
    assert!(text.contains("disruption on local leg, 3s"));
}

#[test]
fn report_without_history_is_header_only() {
    let text = report_text(None, &json!({}), 3600.0, "1h", &mut |_| None).unwrap();
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines[0], "Nexthop report \u{2014} last 1h");
    assert!(lines[1].starts_with("generated "));
    assert_eq!(lines[2], "");
    assert_eq!(lines.len(), 3);
}

#[test]
fn vpn_iface_is_the_trailing_parenthesis() {
    assert_eq!(report::vpn_detail_iface("Measured through a VPN (wg0)"), Some("wg0"));
    assert_eq!(report::vpn_detail_iface("x (wg0)  \n"), Some("wg0"));
    assert_eq!(report::vpn_detail_iface("x (wg0) tail"), None);
    assert_eq!(report::vpn_detail_iface("x ()"), None);
    assert_eq!(report::vpn_detail_iface("x (a(b)"), Some("b"));
    assert_eq!(report::vpn_detail_iface("x (a)b)"), None);
    assert_eq!(report::vpn_detail_iface(&format!("({})", "x".repeat(33))), None);
}

#[test]
fn stream_keys_are_a_closed_set() {
    let mut keys: Vec<&str> = STREAMABLE.iter().map(|(k, _)| *k).collect();
    keys.sort();
    assert_eq!(keys, ["apps", "live", "manifest", "recent"]);
}

fn stream_lines(s: &mut Streamer) -> Vec<String> {
    let mut out = Vec::new();
    s.poll(&mut out).unwrap();
    String::from_utf8(out).unwrap().lines().map(String::from).collect()
}

#[test]
fn stream_emits_once_per_change() {
    let d = TempDir::new();
    let p = d.path().join("live.json");
    fs::write(&p, r#"{"a": 1}"#).unwrap();
    let mut s = Streamer::new(vec![("live".into(), p.clone(), 1024)]);
    assert_eq!(stream_lines(&mut s), [r#"live {"a":1}"#]);
    assert!(stream_lines(&mut s).is_empty());
    fs::write(&p, r#"{"a": 22}"#).unwrap();
    assert_eq!(stream_lines(&mut s), [r#"live {"a":22}"#]);
}

#[test]
fn stream_skips_a_bad_file_until_it_changes() {
    let d = TempDir::new();
    let p = d.path().join("live.json");
    fs::write(&p, "{half").unwrap();
    let mut s = Streamer::new(vec![("live".into(), p.clone(), 16)]);
    assert!(stream_lines(&mut s).is_empty());
    fs::write(&p, "x".repeat(17)).unwrap();
    assert!(stream_lines(&mut s).is_empty());
    fs::write(&p, "[1, 2.5]").unwrap();
    assert_eq!(stream_lines(&mut s), ["live [1,2.5]"]);
}

#[test]
fn indented_json_still_streams_as_one_line() {
    let d = TempDir::new();
    let p = d.path().join("manifest.json");
    fs::write(&p, "{\n  \"version\": \"9.9.9\",\n  \"kinds\": [\n    \"service\"\n  ]\n}").unwrap();
    let mut s = Streamer::new(vec![("manifest".into(), p, 1024)]);
    assert_eq!(stream_lines(&mut s), [r#"manifest {"version":"9.9.9","kinds":["service"]}"#]);
}

#[test]
fn embedded_newline_cannot_break_framing() {
    let d = TempDir::new();
    let p = d.path().join("live.json");
    fs::write(&p, json!({"note": "one\ntwo", "v": 1, "ssid": "caf\u{e9}"}).to_string()).unwrap();
    let mut s = Streamer::new(vec![("live".into(), p, 4096)]);
    assert_eq!(stream_lines(&mut s), [r#"live {"note":"one\ntwo","v":1,"ssid":"caf\u00e9"}"#]);
}

#[test]
fn stream_keys_are_deduplicated_in_order() {
    let keys = ["recent", "live", "recent"].map(String::from);
    let s = Streamer::for_keys(&keys);
    assert!(!s.is_empty());
    assert!(Streamer::for_keys(&["nope".to_string()]).is_empty());
}

#[test]
fn windows_parse_like_python() {
    assert_eq!(parse_window("30m"), 1800.0);
    assert_eq!(parse_window("24h"), 86400.0);
    assert_eq!(parse_window("7d"), 604800.0);
    assert_eq!(parse_window(" 2H "), 7200.0);
    assert_eq!(parse_window("1.5h"), 5400.0);
    assert_eq!(parse_window("90"), 90.0);
    assert_eq!(parse_window("1_0m"), 600.0);
    assert_eq!(parse_window(""), 1800.0);
    assert_eq!(parse_window("abc"), 1800.0);
    assert_eq!(parse_window("-1h"), -3600.0);
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn parsed(a: &[&str]) -> Args {
    match parse(&argv(a)) {
        Parsed::Run(args) => args,
        other => panic!("{a:?}: {other:?}"),
    }
}

fn exit_code(a: &[&str]) -> i32 {
    match parse(&argv(a)) {
        Parsed::Exit { code, .. } => code,
        Parsed::Run(args) => panic!("{a:?} parsed: {args:?}"),
    }
}

#[test]
fn arguments_parse_like_argparse() {
    let q = parsed(&["query", "--win=24h", "--res", "minute"]);
    assert_eq!((q.get("--window", "30m"), q.get("--resolution", "auto")), ("24h", "minute"));
    assert_eq!(parsed(&["query"]).get("--window", "30m"), "30m");
    assert_eq!(parsed(&["query", "--window", "-1h"]).get("--window", ""), "-1h");
    assert_eq!(parsed(&["stream", "--interval", "1", "live", "apps"]).keys, ["live", "apps"]);
    assert_eq!(parsed(&["retire", "--pid", "12", "--start=5"]).get("--start", "0"), "5");
    assert_eq!(exit_code(&[]), 2);
    assert_eq!(exit_code(&["-h"]), 0);
    assert_eq!(exit_code(&["query", "-h"]), 0);
    assert_eq!(exit_code(&["foo"]), 2);
    assert_eq!(exit_code(&["query", "--resolution", "x"]), 2);
    assert_eq!(exit_code(&["query", "--window"]), 2);
    assert_eq!(exit_code(&["query", "--window", "-x"]), 2);
    assert_eq!(exit_code(&["tests", "--limit", "x"]), 2);
    assert_eq!(exit_code(&["retire"]), 2);
    assert_eq!(exit_code(&["stream"]), 2);
    assert_eq!(exit_code(&["stream", "foo"]), 2);
    assert_eq!(exit_code(&["stream", "live", "--interval", "1", "apps"]), 2);
    assert_eq!(exit_code(&["live", "extra"]), 2);
}

#[test]
fn argparse_messages_are_kept() {
    let Parsed::Exit { stderr, .. } = parse(&argv(&["query", "--bogus", "1"])) else { panic!() };
    assert_eq!(
        stderr,
        "usage: nexthop [-h] {live,query,events,tests,peak,report,stream,retire,save-config} ...\n\
         nexthop: error: unrecognized arguments: --bogus 1\n"
    );
    let Parsed::Exit { stderr, .. } = parse(&argv(&["tests", "--limit", "x"])) else { panic!() };
    assert_eq!(
        stderr,
        "usage: nexthop tests [-h] [--kind KIND] [--limit LIMIT]\n\
         nexthop tests: error: argument --limit: invalid int value: 'x'\n"
    );
}

#[test]
fn event_bssids_are_decorated_in_the_report() {
    let dir = TempDir::new();
    let store = Store::new(&dir.path().join("t.db"), false).unwrap();
    store.open_event(crate::util::now() as i64, "roam", "info", "local", "Roamed to 02:00:00:00:00:01").unwrap();
    let text = report_text(Some(&store), &json!({}), 3600.0, "1h", &mut |_| Some("Hallway AP".into())).unwrap();
    assert!(text.contains("Roamed to Hallway AP (02:00:00:00:00:01)"), "{text}");
}

#[test]
fn save_config_writes_the_object_atomically() {
    let dir = TempDir::new();
    let state = dir.path().join("nexthop");
    assert_eq!(save_config(r#"{"probeIntervalMs":500}"#, &state).unwrap(), 0);
    assert_eq!(fs::read_to_string(state.join("config.json")).unwrap(), r#"{"probeIntervalMs":500}"#);
    assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
}

#[test]
fn save_config_refuses_anything_but_an_object() {
    let dir = TempDir::new();
    assert!(save_config("[1]", dir.path()).is_err());
    assert!(save_config("{", dir.path()).is_err());
    assert!(!dir.path().join("config.json").exists());
}

#[test]
fn save_config_takes_exactly_one_argument() {
    assert!(matches!(parse(&["save-config".into()]), Parsed::Exit { code: 2, .. }));
    assert!(matches!(parse(&["save-config".into(), "{}".into(), "{}".into()]), Parsed::Exit { code: 2, .. }));
    let Parsed::Run(args) = parse(&["save-config".into(), "{}".into()]) else { panic!() };
    assert_eq!(args.keys, ["{}"]);
}

#[test]
fn a_fifo_at_the_lock_path_is_not_a_daemon_and_does_not_block() {
    let d = TempDir::new();
    let lock = d.path().join("nexthopd.lock");
    let c = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: c is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert_eq!(lock_holder_pid(&lock), 0);
}

#[test]
fn a_pinned_process_that_exited_cannot_be_signalled() {
    let mut p = spawn_as("yes", &[]);
    let target = procs::pin(p.pid()).unwrap();
    p.0.kill().unwrap();
    p.0.wait().unwrap();
    assert!(procs::kill(&target, 0).is_err());
}
