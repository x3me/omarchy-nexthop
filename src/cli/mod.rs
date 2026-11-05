mod args;
mod procs;
mod report;
mod stream;
#[cfg(test)]
mod tests;

use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::Path;

use crate::net;
use crate::paths::{db_path, live_path, lock_path};
use crate::pyjson;
use crate::state::{READ_JSON_MAX, read_json};
use crate::store::Store;

pub use args::{Args, Parsed, parse};
pub use procs::{authorized_to_retire, lock_holder_pid};
pub use report::report_text;

pub fn parse_window(text: &str) -> f64 {
    let text = if text.is_empty() { "30m" } else { text };
    let text = text.trim().to_lowercase();
    let unit = match text.chars().last() {
        Some('m') => Some(60.0),
        Some('h') => Some(3600.0),
        Some('d') => Some(86400.0),
        _ => None,
    };
    if let Some(scale) = unit
        && let Some(n) = args::py_float(&text[..text.len() - 1])
    {
        return n * scale;
    }
    args::py_float(&text).unwrap_or(1800.0)
}

fn emit(out: &mut dyn Write, obj: &Value) -> io::Result<()> {
    let mut line = pyjson::to_vec(obj).map_err(io::Error::other)?;
    line.push(b'\n');
    out.write_all(&line)
}

type Sink<'a> = &'a mut dyn Write;
type Kill<'a> = &'a mut dyn FnMut(&procs::Pinned, i32) -> io::Result<()>;

fn cmd_live(out: Sink) -> io::Result<i32> {
    emit(out, &read_json(&live_path(), READ_JSON_MAX).unwrap_or_else(|| json!({"state": "no-daemon"})))?;
    Ok(0)
}

pub fn retire(pid: i64, start: i64, kill: Kill) -> i32 {
    if pid <= 0 || pid == std::process::id() as i64 {
        return 1;
    }
    let Ok(target) = procs::pin(pid) else {
        return 1;
    };
    if !authorized_to_retire(pid, start) {
        return 1;
    }
    match kill(&target, libc::SIGTERM) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn open_store() -> Option<Store> {
    let path = db_path();
    if !path.exists() {
        return None;
    }
    Store::new(&path, true).ok()
}

fn sql(e: rusqlite::Error) -> io::Error {
    io::Error::other(format!("history.db: {e}"))
}

fn cmd_query(args: &Args, out: Sink) -> io::Result<i32> {
    let Some(store) = open_store() else {
        emit(out, &json!({"error": "no history yet"}))?;
        return Ok(1);
    };
    let seconds = parse_window(args.get("--window", "30m"));
    let (rows, table) = store.series(seconds, None, args.get("--resolution", "auto")).map_err(sql)?;
    emit(out, &json!({"window_s": seconds, "resolution": table, "rows": rows}))?;
    Ok(0)
}

fn cmd_events(args: &Args, out: Sink) -> io::Result<i32> {
    let Some(store) = open_store() else {
        emit(out, &json!({"events": []}))?;
        return Ok(0);
    };
    let mut events = store.events(parse_window(args.get("--window", "7d")), 100, None).map_err(sql)?;
    let mut inventory = net::ApInventory::new(None);
    for row in &mut events {
        let text = row.get("detail").and_then(Value::as_str).unwrap_or("");
        let detail = net::decorate_bssids(text, &mut |bssid| inventory.lookup(bssid));
        row.insert("detail".into(), Value::String(detail));
    }
    emit(out, &json!({"events": events}))?;
    Ok(0)
}

fn cmd_tests(args: &Args, out: Sink) -> io::Result<i32> {
    let Some(store) = open_store() else {
        emit(out, &json!({"tests": []}))?;
        return Ok(0);
    };
    let limit = args::py_int(args.get("--limit", "20")).unwrap_or(20);
    let tests = store.tests(limit, args.opts.get("--kind").map(String::as_str)).map_err(sql)?;
    emit(out, &json!({"tests": tests}))?;
    Ok(0)
}

fn py_int_of(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Bool(b)) => *b as i64,
        Some(Value::Number(n)) => {
            n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f as i64)).unwrap_or(0)
        }
        Some(Value::String(s)) if !s.is_empty() => args::py_int(s).unwrap_or(0),
        _ => 0,
    }
}

pub fn peak(lock: &Path, live: &Path, kill: Kill) -> (i32, Value) {
    let not_running = || (1, json!({"ok": false, "error": "daemon not running"}));
    let pid = lock_holder_pid(lock);
    if pid <= 0 || pid == std::process::id() as i64 {
        return not_running();
    }
    let live = read_json(live, READ_JSON_MAX).unwrap_or(Value::Null);
    let named = live.get("pid").and_then(Value::as_f64) == Some(pid as f64);
    let want_start = if named { py_int_of(live.get("pid_start")) } else { 0 };
    let Ok(target) = procs::pin(pid) else {
        return not_running();
    };
    if !authorized_to_retire(pid, want_start) {
        return (1, json!({"ok": false, "error": "lock holder is not nexthopd"}));
    }
    match kill(&target, libc::SIGUSR1) {
        Ok(()) => (0, json!({"ok": true})),
        Err(_) => not_running(),
    }
}

fn cmd_report(args: &Args, out: Sink) -> io::Result<i32> {
    let window = args.get("--window", "24h");
    let live = read_json(&live_path(), READ_JSON_MAX).unwrap_or_else(|| json!({}));
    let store = open_store();
    let mut inventory = net::ApInventory::new(None);
    let text = report_text(store.as_ref(), &live, parse_window(window), window, &mut |bssid| inventory.lookup(bssid))
        .map_err(sql)?;
    out.write_all(format!("{text}\n").as_bytes())?;
    Ok(0)
}

fn run(args: &Args, out: Sink) -> io::Result<i32> {
    let int = |opt: &str, default: i64| args.opts.get(opt).and_then(|v| args::py_int(v)).unwrap_or(default);
    match args.cmd.as_str() {
        "live" => cmd_live(out),
        "query" => cmd_query(args, out),
        "events" => cmd_events(args, out),
        "tests" => cmd_tests(args, out),
        "report" => cmd_report(args, out),
        "peak" => {
            let (code, reply) = peak(&lock_path(), &live_path(), &mut procs::kill);
            emit(out, &reply)?;
            Ok(code)
        }
        "retire" => Ok(retire(int("--pid", 0), int("--start", 0), &mut procs::kill)),
        "stream" => {
            let interval = args.opts.get("--interval").and_then(|v| args::py_float(v)).unwrap_or(0.5);
            Ok(stream::cmd_stream(&args.keys, interval))
        }
        "save-config" => save_config(&args.keys[0], &crate::paths::state_dir()),
        other => Err(io::Error::other(format!("unknown command {other}"))),
    }
}

pub fn save_config(text: &str, state_dir: &Path) -> io::Result<i32> {
    let config: Value = serde_json::from_str(text).map_err(|e| io::Error::other(format!("config is not JSON: {e}")))?;
    if !config.is_object() {
        return Err(io::Error::other("config must be a JSON object"));
    }
    std::fs::create_dir_all(state_dir)?;
    std::fs::set_permissions(state_dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    crate::state::write_atomic(&state_dir.join("config.json"), &config, false)?;
    Ok(0)
}

pub fn main(argv: Vec<String>) -> i32 {
    let args = match parse(&argv) {
        Parsed::Run(args) => args,
        Parsed::Exit { code, stdout, stderr } => {
            print!("{stdout}");
            eprint!("{stderr}");
            return code;
        }
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match run(&args, &mut out).and_then(|code| out.flush().map(|_| code)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("nexthop {}: {e}", args.cmd);
            1
        }
    }
}
