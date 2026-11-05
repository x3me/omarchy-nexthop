mod vet;

#[cfg(test)]
mod tests;

use std::process::Command;

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::pyjson::py_str;
use crate::subproc::{self, Finished};
use crate::util::{now, py_round};

pub use vet::vet_target;

pub const CLOUDFLARE_UP: &str = "https://speed.cloudflare.com/__up";
pub const FAST_API: &str =
    "https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3";

pub const MIN_TIMED_WINDOW_S: f64 = 0.05;

pub const CONTENT_TARGET_S: f64 = 1.5;
pub const CONTENT_STREAM_FLOOR: i64 = 500_000;
pub const CONTENT_DOWN_STREAM_CAP: i64 = 8_000_000;
pub const CONTENT_UP_STREAM_CAP: i64 = 2_000_000;
pub const CONTENT_STREAMS: usize = 4;

pub const PEAK_TARGET_S: f64 = 10.0;
pub const PEAK_STREAMS: usize = 4;
pub const CLOUDFLARE_DOWN_MAX: i64 = 99_999_999;
pub const PEAK_DOWN_FLOOR: i64 = 10_000_000;
pub const PEAK_UP_FLOOR: i64 = 5_000_000;
pub const PEAK_UP_CAP: i64 = 100_000_000;

const DOWN_TIMING: &str = "%{size_download} %{time_total} %{time_starttransfer}";
// INFO: fc 17oct26 appconnect, not starttransfer: on a POST the first response byte lands before the body is sent
const UP_TIMING: &str = "%{size_upload} %{time_total} %{time_appconnect}";

pub type Spawn<'a> = &'a dyn Fn(&[Vec<String>], Option<&[u8]>, f64) -> Vec<(f64, Option<Finished>)>;

pub fn spawn_real(argvs: &[Vec<String>], input: Option<&[u8]>, timeout: f64) -> Vec<(f64, Option<Finished>)> {
    let cmds = argvs
        .iter()
        .map(|argv| {
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]);
            cmd
        })
        .collect();
    subproc::run_many(cmds, input, true, timeout)
}

fn spawn_one(spawn: Spawn, argv: Vec<String>, input: Option<&[u8]>, timeout: f64) -> Option<Finished> {
    spawn(&[argv], input, timeout).pop().and_then(|(_, done)| done)
}

fn cloudflare_down(n: i64) -> String {
    format!("https://speed.cloudflare.com/__down?bytes={n}")
}

fn curl_argv(args: &[&str], timeout: f64) -> Vec<String> {
    let max_time = (timeout as i64).to_string();
    let head = ["curl", "-fsS", "--proto", "=https", "--max-time", &max_time];
    head.iter().chain(args).map(|s| s.to_string()).collect()
}

fn curl(spawn: Spawn, args: &[&str], timeout: f64) -> Option<Finished> {
    spawn_one(spawn, curl_argv(args, timeout), None, timeout + 5.0)
}

fn parse_timing(out: &[u8]) -> Option<(f64, f64, f64)> {
    let text = std::str::from_utf8(out).ok()?;
    let mut fields = text.split_whitespace().map(str::parse::<f64>);
    let parsed = (fields.next()?.ok()?, fields.next()?.ok()?, fields.next()?.ok()?);
    fields.next().is_none().then_some(parsed)
}

pub fn rate_over_payload(size: f64, t_total: f64, t_payload_start: f64) -> Option<f64> {
    let window = t_total - t_payload_start;
    if window < MIN_TIMED_WINDOW_S || size <= 0.0 {
        return None;
    }
    Some(size * 8.0 / 1e6 / window)
}

fn download_args<'a>(url: &'a str, resolve: Option<&'a str>) -> Vec<&'a str> {
    let mut args = Vec::with_capacity(7);
    if let Some(pin) = resolve {
        args.extend(["--resolve", pin]);
    }
    args.extend(["-o", "/dev/null", "-w", DOWN_TIMING, url]);
    args
}

fn curl_timed_download(spawn: Spawn, url: &str, timeout: f64, resolve: Option<&str>) -> (Option<f64>, i64) {
    let Some(r) = curl(spawn, &download_args(url, resolve), timeout) else {
        return (None, 0);
    };
    if r.code != 0 {
        return (None, 0);
    }
    let Some((size, t_total, t_start)) = parse_timing(&r.stdout) else {
        return (None, 0);
    };
    (rate_over_payload(size, t_total, t_start), size as i64)
}

fn upload_argv(url: &str, timeout: f64) -> Vec<String> {
    curl_argv(
        &[
            "-o",
            "/dev/null",
            "-X",
            "POST",
            "--data-binary",
            "@-",
            "-H",
            "Content-Type: application/octet-stream",
            "-w",
            UP_TIMING,
            url,
        ],
        timeout,
    )
}

fn streamed(spawned: f64, done: Option<Finished>) -> Option<(f64, f64, f64)> {
    let done = done?;
    if done.code != 0 || done.stdout.is_empty() {
        return None;
    }
    let (size, t_total, t_payload) = parse_timing(&done.stdout)?;
    Some((size, spawned + t_payload, spawned + t_total))
}

fn tally(runs: Vec<(f64, Option<Finished>)>) -> (Option<f64>, i64) {
    let mut windows = Vec::new();
    let mut total_bytes = 0i64;
    for (spawned, done) in runs {
        if let Some(window) = streamed(spawned, done) {
            total_bytes += window.0 as i64;
            windows.push(window);
        }
    }
    (aggregate_rate(windows), total_bytes)
}

fn parallel_upload(spawn: Spawn, url: &str, per_stream: i64, streams: usize, timeout: f64) -> (Option<f64>, i64) {
    let body = vec![0u8; per_stream.max(0) as usize];
    let argvs = vec![upload_argv(url, timeout); streams];
    tally(spawn(&argvs, Some(&body), timeout + 10.0))
}

fn curl_timed_upload(spawn: Spawn, url: &str, n_bytes: i64, timeout: f64) -> (Option<f64>, i64) {
    let body = vec![0u8; n_bytes.max(0) as usize];
    let Some(r) = spawn_one(spawn, upload_argv(url, timeout), Some(&body), timeout + 5.0) else {
        return (None, 0);
    };
    if r.code != 0 {
        return (None, 0);
    }
    let Some((size, t_total, t_app)) = parse_timing(&r.stdout) else {
        return (None, 0);
    };
    (rate_over_payload(size, t_total, t_app), size as i64)
}

pub fn aggregate_rate(windows: Vec<(f64, f64, f64)>) -> Option<f64> {
    let windows: Vec<_> = windows.into_iter().filter(|w| w.0 > 0.0 && w.2 > w.1).collect();
    if windows.is_empty() {
        return None;
    }
    let total_bytes: f64 = windows.iter().map(|w| w.0).sum();
    let mut spans: Vec<(f64, f64)> = windows.iter().map(|w| (w.1, w.2)).collect();
    spans.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.total_cmp(&b.1)));
    let (mut union, mut cur_s, mut cur_e) = (0.0, spans[0].0, spans[0].1);
    for &(s, e) in &spans[1..] {
        if s > cur_e {
            union += cur_e - cur_s;
            (cur_s, cur_e) = (s, e);
        } else {
            cur_e = cur_e.max(e);
        }
    }
    union += cur_e - cur_s;
    if union < MIN_TIMED_WINDOW_S {
        return None;
    }
    Some(total_bytes * 8.0 / 1e6 / union)
}

fn parallel_download(spawn: Spawn, url: &str, streams: usize, timeout: f64) -> (Option<f64>, i64) {
    let argvs = vec![curl_argv(&download_args(url, None), timeout); streams];
    tally(spawn(&argvs, None, timeout + 10.0))
}

pub fn content_stream_bytes(hint_mbps: Option<f64>, streams: usize, cap: i64, target_s: Option<f64>) -> i64 {
    let Some(hint) = hint_mbps.filter(|h| *h > 0.0) else {
        return cap;
    };
    let per_stream_mbps = hint / streams.max(1) as f64;
    let target = target_s.filter(|t| *t != 0.0).unwrap_or(CONTENT_TARGET_S);
    let want = (per_stream_mbps / 8.0 * target * 1e6) as i64;
    CONTENT_STREAM_FLOOR.max(cap.min(want))
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContentResult {
    pub kind: &'static str,
    pub engine: &'static str,
    pub ok: bool,
    pub down_mbps: Option<f64>,
    pub up_mbps: Option<f64>,
    pub bytes: i64,
    pub started: f64,
    pub ended: f64,
}

pub fn content_test(down_hint_mbps: Option<f64>, up_hint_mbps: Option<f64>) -> ContentResult {
    content_test_with(
        down_hint_mbps,
        up_hint_mbps,
        CONTENT_STREAMS,
        &mut |url, streams, timeout| parallel_download(&spawn_real, url, streams, timeout),
        &mut |url, per_stream, streams, timeout| parallel_upload(&spawn_real, url, per_stream, streams, timeout),
    )
}

type DownFn<'a> = &'a mut dyn FnMut(&str, usize, f64) -> (Option<f64>, i64);
type UpFn<'a> = &'a mut dyn FnMut(&str, i64, usize, f64) -> (Option<f64>, i64);

fn round1_nonzero(x: Option<f64>) -> Option<f64> {
    x.filter(|v| *v != 0.0).map(|v| py_round(v, 1))
}

fn content_test_with(
    down_hint_mbps: Option<f64>,
    up_hint_mbps: Option<f64>,
    streams: usize,
    download: DownFn,
    upload: UpFn,
) -> ContentResult {
    let started = now();
    let per_stream = content_stream_bytes(down_hint_mbps, streams, CONTENT_DOWN_STREAM_CAP, None);
    let up_per_stream = content_stream_bytes(up_hint_mbps, streams, CONTENT_UP_STREAM_CAP, None);
    let (mut down_mbps, mut down_n) = download(&cloudflare_down(per_stream), streams, 30.0);
    if down_mbps.is_none() && per_stream < CONTENT_DOWN_STREAM_CAP {
        let (retry_mbps, retry_n) = download(&cloudflare_down(CONTENT_DOWN_STREAM_CAP), streams, 30.0);
        (down_mbps, down_n) = (retry_mbps, down_n + retry_n);
    }
    let (mut up_mbps, mut up_n) = upload(CLOUDFLARE_UP, up_per_stream, streams, 30.0);
    if up_mbps.is_none() && up_per_stream < CONTENT_UP_STREAM_CAP {
        let (retry_mbps, retry_n) = upload(CLOUDFLARE_UP, CONTENT_UP_STREAM_CAP, streams, 30.0);
        (up_mbps, up_n) = (retry_mbps, up_n + retry_n);
    }
    ContentResult {
        kind: "content",
        engine: "cloudflare",
        ok: down_mbps.is_some(),
        down_mbps: round1_nonzero(down_mbps),
        up_mbps: round1_nonzero(up_mbps),
        bytes: down_n + up_n,
        started,
        ended: now(),
    }
}

fn round1(v: &Value) -> Option<Value> {
    if v.is_i64() || v.is_u64() {
        return Some(v.clone());
    }
    Some(json!(py_round(v.as_f64()?, 1)))
}

fn add_numbers(a: &Value, b: &Value) -> Option<Value> {
    if let (Some(x), Some(y)) = (a.as_i64(), b.as_i64()) {
        return Some(x.checked_add(y).map_or_else(|| json!(x as f64 + y as f64), |s| json!(s)));
    }
    Some(json!(a.as_f64()? + b.as_f64()?))
}

fn parse_ookla(stdout: &[u8]) -> Option<Map<String, Value>> {
    let j: Value = serde_json::from_slice(stdout).ok()?;
    let j = j.as_object()?;
    let download = j.get("download")?.as_object()?;
    let upload = j.get("upload")?.as_object()?;
    let ping = j.get("ping")?.as_object()?;
    let zero = json!(0);
    let empty = json!("");
    let down_mbps = py_round(download.get("bandwidth")?.as_f64()? * 8.0 / 1e6, 1);
    let up_mbps = py_round(upload.get("bandwidth")?.as_f64()? * 8.0 / 1e6, 1);
    let ping_idle = round1(ping.get("latency")?)?;
    let jitter = round1(ping.get("jitter").unwrap_or(&zero))?;
    let bytes = add_numbers(download.get("bytes").unwrap_or(&zero), upload.get("bytes").unwrap_or(&zero))?;
    let server = j.get("server")?.as_object()?;
    let server = format!(
        "{} \u{b7} {}",
        py_str(server.get("name").unwrap_or(&empty)),
        py_str(server.get("location").unwrap_or(&empty))
    );
    let url = match j.get("result") {
        None => empty.clone(),
        Some(result) => result.as_object()?.get("url").cloned().unwrap_or(empty),
    };
    let mut out = Map::new();
    out.insert("engine".into(), json!("ookla"));
    out.insert("ok".into(), json!(true));
    out.insert("down_mbps".into(), json!(down_mbps));
    out.insert("up_mbps".into(), json!(up_mbps));
    out.insert("ping_idle".into(), ping_idle);
    out.insert("jitter".into(), jitter);
    out.insert("bytes".into(), bytes);
    out.insert("server".into(), json!(server));
    out.insert("url".into(), url);
    Some(out)
}

fn peak_ookla(spawn: Spawn) -> Option<Map<String, Value>> {
    let argv = ["speedtest", "--format=json", "--accept-license", "--accept-gdpr"].map(String::from).to_vec();
    let r = spawn_one(spawn, argv, None, 120.0)?;
    if r.code != 0 {
        return None;
    }
    parse_ookla(&r.stdout)
}

pub fn sized_pass(mbps: f64, floor: i64, cap: i64) -> i64 {
    floor.max(cap.min((mbps / 8.0 * PEAK_TARGET_S * 1e6) as i64))
}

pub fn pass_seconds(mbps: f64, n_bytes: i64) -> f64 {
    n_bytes as f64 * 8.0 / (mbps * 1e6)
}

fn peak_cloudflare(spawn: Spawn) -> Option<Map<String, Value>> {
    let mut total = 0i64;
    let (mut best_down, size) = curl_timed_download(spawn, &cloudflare_down(25_000_000), 40.0, None);
    total += size;
    if let Some(est) = best_down.filter(|v| *v != 0.0)
        && pass_seconds(est, size) < PEAK_TARGET_S * 0.6
    {
        let n = sized_pass(est / PEAK_STREAMS as f64, PEAK_DOWN_FLOOR, CLOUDFLARE_DOWN_MAX);
        let (mbps, size) = parallel_download(spawn, &cloudflare_down(n), PEAK_STREAMS, 40.0);
        total += size;
        if let Some(m) = mbps.filter(|v| *v != 0.0) {
            best_down = Some(est.max(m));
        }
    }
    let mut best_up = 0.0f64;
    let (up_est, size) = curl_timed_upload(spawn, CLOUDFLARE_UP, 10_000_000, 40.0);
    total += size;
    if let Some(est) = up_est.filter(|v| *v != 0.0) {
        best_up = est;
        if pass_seconds(est, size) < PEAK_TARGET_S * 0.6 {
            let streams = PEAK_STREAMS as i64;
            let n = sized_pass(est / PEAK_STREAMS as f64, PEAK_UP_FLOOR / streams, PEAK_UP_CAP / streams);
            let (mbps, size) = parallel_upload(spawn, CLOUDFLARE_UP, n, PEAK_STREAMS, 40.0);
            total += size;
            if let Some(m) = mbps.filter(|v| *v != 0.0) {
                best_up = best_up.max(m);
            }
        }
    }
    let best_down = best_down.filter(|v| *v != 0.0)?;
    let mut out = Map::new();
    out.insert("engine".into(), json!("cloudflare"));
    out.insert("ok".into(), json!(true));
    out.insert("down_mbps".into(), json!(py_round(best_down, 1)));
    out.insert("up_mbps".into(), json!(round1_nonzero(Some(best_up))));
    out.insert("bytes".into(), json!(total));
    out.insert("server".into(), json!("speed.cloudflare.com"));
    Some(out)
}

fn fast_targets(stdout: &[u8]) -> Option<Vec<String>> {
    let body: Value = serde_json::from_slice(stdout).ok()?;
    let targets = match body.as_object()?.get("targets") {
        None => return Some(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(Value::String(s)) if s.is_empty() => return Some(Vec::new()),
        Some(Value::Object(m)) if m.is_empty() => return Some(Vec::new()),
        Some(_) => return None,
    };
    let mut urls = Vec::new();
    for t in targets {
        if let Some(Value::String(url)) = t.as_object()?.get("url")
            && !url.is_empty()
        {
            urls.push(url.clone());
        }
    }
    Some(urls)
}

fn peak_fast(spawn: Spawn) -> Option<Map<String, Value>> {
    let r = curl(spawn, &[FAST_API], 15.0)?;
    if r.code != 0 {
        return None;
    }
    let targets = fast_targets(&r.stdout)?;
    let vetted: Vec<(String, String)> = targets.iter().filter_map(|u| vet_target(u)).collect();
    let mut best = 0.0f64;
    let mut total = 0i64;
    for (url, resolve) in vetted.iter().take(3) {
        let (mbps, size) = curl_timed_download(spawn, url, 30.0, Some(resolve));
        total += size;
        if let Some(m) = mbps.filter(|v| *v != 0.0) {
            best = best.max(m);
        }
    }
    if best == 0.0 {
        return None;
    }
    let mut out = Map::new();
    out.insert("engine".into(), json!("fast.com"));
    out.insert("ok".into(), json!(true));
    out.insert("down_mbps".into(), json!(py_round(best, 1)));
    out.insert("up_mbps".into(), Value::Null);
    out.insert("bytes".into(), json!(total));
    out.insert("server".into(), json!("Netflix OCA"));
    Some(out)
}

pub fn peak_test(engine: &str) -> Map<String, Value> {
    peak_test_with(engine, &spawn_real)
}

type Engine = fn(Spawn) -> Option<Map<String, Value>>;

fn peak_test_with(engine: &str, spawn: Spawn) -> Map<String, Value> {
    let started = now();
    let order: &[Engine] = match engine {
        "Ookla" => &[peak_ookla],
        "Cloudflare" => &[peak_cloudflare],
        "fast.com" => &[peak_fast],
        _ => &[peak_ookla, peak_cloudflare, peak_fast],
    };
    for run in order {
        if let Some(mut result) = run(spawn) {
            result.insert("kind".into(), json!("peak"));
            result.insert("started".into(), json!(started));
            result.insert("ended".into(), json!(now()));
            return result;
        }
    }
    let mut out = Map::new();
    out.insert("kind".into(), json!("peak"));
    out.insert("engine".into(), json!(engine));
    out.insert("ok".into(), json!(false));
    out.insert("started".into(), json!(started));
    out.insert("ended".into(), json!(now()));
    out
}
