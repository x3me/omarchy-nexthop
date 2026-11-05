use serde_json::{Map, Value};
use std::net::IpAddr;

use super::run::run_status;
use crate::util::{is_py_line_break, py_strip};

pub const TRACE_URL: &str = "https://speed.cloudflare.com/cdn-cgi/trace";
pub const CURL_COULDNT_RESOLVE_HOST: i32 = 6;

pub fn py_splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut iter = text.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if is_py_line_break(c) {
            out.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r'
                && let Some(&(j, '\n')) = iter.peek()
            {
                iter.next();
                end = j + 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

pub struct PyIp {
    pub addr: IpAddr,
    pub text: String,
}

pub fn py_ip_address(text: &str) -> Option<PyIp> {
    if let Ok(v4) = text.parse::<std::net::Ipv4Addr>() {
        return Some(PyIp { addr: IpAddr::V4(v4), text: v4.to_string() });
    }
    let (addr, scope) = match text.split_once('%') {
        Some((a, s)) if !s.is_empty() && !s.contains('%') => (a, Some(s)),
        Some(_) => return None,
        None => (text, None),
    };
    let v6 = addr.parse::<std::net::Ipv6Addr>().ok()?;
    let text = match scope {
        Some(s) => format!("{v6}%{s}"),
        None => v6.to_string(),
    };
    Some(PyIp { addr: IpAddr::V6(v6), text })
}

fn upper_ascii_alpha(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase())
}

pub fn parse_trace(text: &str) -> Option<Map<String, Value>> {
    let bounded: &str = match text.char_indices().nth(4096) {
        Some((i, _)) => &text[..i],
        None => text,
    };
    let mut out = Map::new();
    for line in py_splitlines(bounded).into_iter().take(64) {
        if let Some(rest) = line.strip_prefix("ip=") {
            let ip = py_ip_address(py_strip(rest))?;
            out.insert("ip".into(), ip.text.into());
            out.insert("family".into(), if ip.addr.is_ipv6() { "v6" } else { "v4" }.into());
        } else if let Some(rest) = line.strip_prefix("loc=") {
            let code = py_strip(rest);
            if code.chars().count() == 2 && upper_ascii_alpha(code) && code != "XX" {
                out.insert("country".into(), code.into());
            }
        } else if let Some(rest) = line.strip_prefix("colo=") {
            let edge = py_strip(rest);
            if (2..=5).contains(&edge.chars().count()) && upper_ascii_alpha(edge) {
                out.insert("edge".into(), edge.into());
            }
        }
    }
    out.contains_key("ip").then_some(out)
}

pub fn trace_verdict(raw: Option<&str>, curl_exit: Option<i32>) -> &'static str {
    if curl_exit == Some(CURL_COULDNT_RESOLVE_HOST) {
        return "unresolved";
    }
    match raw {
        None | Some("") => "silent",
        Some(text) if parse_trace(text).is_some() => "open",
        Some(_) => "intercepted",
    }
}

pub fn reachability() -> Map<String, Value> {
    let (code, raw) =
        run_status(&["curl", "-sf", "--proto", "=https", "--max-time", "5", "--max-filesize", "4096", TRACE_URL], 8.0);
    let body = if code == Some(0) { raw.as_deref() } else { None };
    let verdict = trace_verdict(body, code);
    let proof = if verdict == "open" { body.and_then(parse_trace).map(Value::Object) } else { None };
    let mut out = Map::new();
    out.insert("verdict".into(), verdict.into());
    out.insert("proof".into(), proof.unwrap_or(Value::Null));
    out
}
