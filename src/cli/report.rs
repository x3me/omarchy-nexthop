use serde_json::{Map, Value};
use std::ffi::{CStr, CString};

use crate::net;
use crate::pyjson::{py_float_repr, py_str, truthy};
use crate::store::Store;
use crate::util::{is_py_space, now, py_sum};

unsafe extern "C" {
    fn tzset();
}

pub fn strftime_local(fmt: &str, ts: i64) -> String {
    let Ok(cfmt) = CString::new(fmt) else {
        return String::new();
    };
    let t = ts as libc::time_t;
    static TZSET: std::sync::Once = std::sync::Once::new();
    // SAFETY: tzset only initialises libc's timezone state from TZ.
    TZSET.call_once(|| unsafe { tzset() });
    // SAFETY: zeroed tm is a valid value; localtime_r writes into it, strftime writes at most buf.len() bytes.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return String::new();
        }
        let mut buf = [0 as libc::c_char; 256];
        let n = libc::strftime(buf.as_mut_ptr(), buf.len(), cfmt.as_ptr(), &tm);
        if n == 0 {
            return String::new();
        }
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

fn or<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    if truthy(a) { a } else { b }
}

fn int_of(v: Option<&Value>) -> i64 {
    v.and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0)
}

pub fn vpn_detail_iface(detail: &str) -> Option<&str> {
    let inner = detail.trim_end_matches(is_py_space).strip_suffix(')')?;
    let open = inner.rfind(['(', ')'])?;
    let name = &inner[open + 1..];
    let n = name.chars().count();
    (inner.as_bytes()[open] == b'(' && (1..=32).contains(&n)).then_some(name)
}

type Row = Map<String, Value>;

fn block(lines: &mut Vec<String>, table: &str, name: &str, subset: &[&Row], keys: [&str; 3]) {
    let vals = |k: &str| -> Vec<f64> { subset.iter().filter_map(|r| r.get(k).and_then(Value::as_f64)).collect() };
    let (p50, p95, loss) = (vals(keys[0]), vals(keys[1]), vals(keys[2]));
    if p50.is_empty() {
        lines.push(format!("{name}: no data"));
        return;
    }
    let worst = p95.iter().copied().fold(None, |m: Option<f64>, x| Some(m.map_or(x, |m| if x > m { x } else { m })));
    let loss_pct = if loss.is_empty() { 0.0 } else { py_sum(loss.iter().copied()) / loss.len() as f64 * 100.0 };
    lines.push(format!(
        "{name}: median {:.1} ms, p95 {:.1} ms (worst {table} bucket), loss {loss_pct:.2}%",
        py_sum(p50.iter().copied()) / p50.len() as f64,
        worst.unwrap_or(0.0),
    ));
}

pub type ApLookup<'a> = &'a mut dyn FnMut(&str) -> Option<String>;

pub fn report_text(
    store: Option<&Store>,
    live: &Value,
    seconds: f64,
    window: &str,
    ap_name: ApLookup,
) -> rusqlite::Result<String> {
    let mut lines = vec![
        format!("Nexthop report \u{2014} last {window}"),
        format!("generated {}", strftime_local("%Y-%m-%d %H:%M %Z", now() as i64)),
    ];
    let empty = Map::new();
    let link = live.get("link").and_then(Value::as_object).unwrap_or(&empty);
    if !link.is_empty() {
        let iface = link.get("iface").map_or("?".into(), py_str);
        let what = match or(link.get("ssid"), link.get("name")) {
            Some(v) if truthy(Some(v)) => py_str(v),
            _ => iface,
        };
        let kind = link.get("kind").map_or("?".into(), py_str);
        let gateway = link.get("gateway").map_or("?".into(), py_str);
        lines.push(format!("connection: {what} ({kind}), gateway {gateway}"));
    }
    lines.push(String::new());
    if let Some(store) = store {
        store_sections(&mut lines, store, seconds, ap_name)?;
    }
    Ok(lines.join("\n"))
}

fn store_sections(lines: &mut Vec<String>, store: &Store, seconds: f64, ap_name: ApLookup) -> rusqlite::Result<()> {
    let (rows, table) = store.series(seconds, None, "auto")?;
    let all: Vec<&Row> = rows.iter().collect();
    let on_line = |r: &&Row| r.get("vpn").is_none_or(Value::is_null);
    let line_rows: Vec<&Row> = all.iter().copied().filter(on_line).collect();
    let tunnel_rows: Vec<&Row> = all.iter().copied().filter(|r| !on_line(r)).collect();
    block(lines, table, "local leg (to router)", &all, ["local_p50", "local_p95", "local_loss"]);
    block(lines, table, "wan leg (past router)", &line_rows, ["wan_p50", "wan_p95", "wan_loss"]);
    if !tunnel_rows.is_empty() {
        let name = "through a VPN (past router, not the ISP line)";
        block(lines, table, name, &tunnel_rows, ["wan_p50", "wan_p95", "wan_loss"]);
    }
    lines.push(String::new());
    let events = store.events(seconds, 100, None)?;
    let mut spans: Vec<&Row> = events.iter().filter(|e| e.get("kind").and_then(Value::as_str) == Some("vpn")).collect();
    if !spans.is_empty() {
        lines.push("measured through a VPN:".into());
        spans.sort_by_key(|e| int_of(e.get("ts")));
        for e in spans {
            let start = strftime_local("%a %H:%M", int_of(e.get("ts")));
            let span = if truthy(e.get("end_unknown")) {
                format!("{start} onwards (end not seen)")
            } else {
                let end = if truthy(e.get("ended_ts")) {
                    strftime_local("%H:%M", int_of(e.get("ended_ts")))
                } else {
                    "now".into()
                };
                format!("{start}\u{2013}{end}")
            };
            let detail = e.get("detail").and_then(Value::as_str).unwrap_or("");
            let iface = vpn_detail_iface(detail).unwrap_or("VPN");
            lines.push(format!(
                "  {span} measured through a VPN ({iface}): figures in this span describe the tunnel, not the ISP line."
            ));
        }
        lines.push(String::new());
    }
    if events.is_empty() {
        lines.push("events: none".into());
    } else {
        lines.push("events:".into());
        for e in &events {
            let start = strftime_local("%a %H:%M", int_of(e.get("ts")));
            let dur = if truthy(e.get("end_unknown")) {
                "duration unknown (monitoring stopped first)".to_string()
            } else if truthy(e.get("ended_ts")) {
                match (e.get("ended_ts").and_then(Value::as_i64), e.get("ts").and_then(Value::as_i64)) {
                    (Some(end), Some(ts)) => format!("{}s", end - ts),
                    _ => {
                        let f = |k| e.get(k).and_then(Value::as_f64).unwrap_or(0.0);
                        format!("{}s", py_float_repr(f("ended_ts") - f("ts")))
                    }
                }
            } else {
                "ongoing".to_string()
            };
            let text = e.get("detail").and_then(Value::as_str).unwrap_or("");
            let detail = net::decorate_bssids(text, ap_name);
            lines.push(format!(
                "  {start}  {} on {} leg, {dur} \u{2014} {detail}",
                py_str(e.get("kind").unwrap_or(&Value::Null)),
                py_str(e.get("leg").unwrap_or(&Value::Null))
            ));
        }
    }
    let tests = store.tests(5, None)?;
    if !tests.is_empty() {
        lines.push(String::new());
        lines.push("speed tests:".into());
        for t in &tests {
            let when = strftime_local("%a %H:%M", int_of(t.get("ts")));
            let kind = py_str(t.get("kind").unwrap_or(&Value::Null));
            if t.get("detail").and_then(Value::as_str) == Some("skipped-busy") {
                lines.push(format!("  {when}  {kind:<8} skipped: this machine kept the line busy"));
                continue;
            }
            let rate = |k: &str| match t.get(k) {
                v if truthy(v) => format!("{:.0}", v.and_then(Value::as_f64).unwrap_or(0.0)),
                _ => "--".into(),
            };
            let via = if truthy(t.get("vpn")) { "  via VPN" } else { "" };
            lines.push(format!(
                "  {when}  {kind:<8} {}/{} Mbps  ({}){via}",
                rate("down_mbps"),
                rate("up_mbps"),
                py_str(t.get("engine").unwrap_or(&Value::Null))
            ));
        }
    }
    Ok(())
}
