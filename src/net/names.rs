use std::collections::HashMap;

use super::run::run;
use super::unicode::{UNSAFE_RANGES, WORD_RANGES_NON_ASCII};
use crate::util::py_strip;

pub const SSID_MAX_CHARS: usize = 32;
pub const NAME_MAX_CHARS: usize = 64;
pub const NAME_CACHE_TTL_S: f64 = 60.0;

fn in_ranges(ranges: &[(u32, u32)], c: char) -> bool {
    let cp = c as u32;
    ranges
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

pub fn is_unsafe_char(c: char) -> bool {
    in_ranges(UNSAFE_RANGES, c)
}

pub fn is_py_word(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_alphanumeric() || c == '_' } else { in_ranges(WORD_RANGES_NON_ASCII, c) }
}

pub fn unescape_iw_ssid(text: &str) -> String {
    if !text.contains("\\x") {
        return text.to_string();
    }
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hi = b.get(i + 2).and_then(|&c| (c as char).to_digit(16));
        let lo = b.get(i + 3).and_then(|&c| (c as char).to_digit(16));
        if let (b'\\', Some(b'x'), Some(hi), Some(lo)) = (b[i], b.get(i + 1), hi, lo) {
            out.push((hi * 16 + lo) as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn clean_name(text: &str, limit: usize) -> String {
    text.chars().take(limit).map(|c| if is_unsafe_char(c) { '\u{FFFD}' } else { c }).collect()
}

pub fn nm_metered(iface: &str) -> bool {
    if iface.is_empty() {
        return false;
    }
    nm_metered_from(run(&["nmcli", "-t", "-f", "GENERAL.METERED", "dev", "show", iface], 4.0).as_deref())
}

pub fn nm_metered_from(raw: Option<&str>) -> bool {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return false;
    };
    let value = match raw.split_once(':') {
        Some((_, v)) => py_strip(v).to_lowercase(),
        None => String::new(),
    };
    value.starts_with("yes") && !value.contains("guess")
}

pub fn connection_name(iface: &str) -> String {
    connection_name_from(run(&["nmcli", "-t", "-f", "GENERAL.CONNECTION", "dev", "show", iface], 2.0).as_deref())
}

pub fn connection_name_from(raw: Option<&str>) -> String {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return String::new();
    };
    for line in super::trace::py_splitlines(raw) {
        if let Some(rest) = line.strip_prefix("GENERAL.CONNECTION:") {
            let name = py_strip(rest);
            return if name.is_empty() || name == "--" { String::new() } else { clean_name(name, NAME_MAX_CHARS) };
        }
    }
    String::new()
}

pub type NameKey = (String, String, String);

pub struct NameCache {
    lookup: Box<dyn FnMut(&str) -> String + Send>,
    entries: HashMap<String, (NameKey, String, f64)>,
}

impl Default for NameCache {
    fn default() -> Self {
        NameCache::new(Box::new(connection_name))
    }
}

impl NameCache {
    pub fn new(lookup: Box<dyn FnMut(&str) -> String + Send>) -> Self {
        NameCache { lookup, entries: HashMap::new() }
    }

    pub fn connection_name_cached(&mut self, iface: &str, key: &NameKey, now: Option<f64>, ttl: f64) -> String {
        let now = now.unwrap_or_else(crate::util::now);
        if let Some((k, name, expires)) = self.entries.get(iface)
            && k == key
            && now < *expires
        {
            return name.clone();
        }
        let name = (self.lookup)(iface);
        self.entries.insert(iface.to_string(), (key.clone(), name.clone(), now + ttl));
        name
    }
}

pub fn is_bssid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17 && b.iter().enumerate().all(|(i, &c)| if i % 3 == 2 { c == b':' } else { c.is_ascii_hexdigit() })
}

pub fn decorate_bssids(text: &str, lookup: &mut dyn FnMut(&str) -> Option<String>) -> String {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let blocks = |c: char| is_py_word(c) || c == ':';
    while i < chars.len() {
        let start = chars[i].0;
        let candidate = text.get(start..start + 17).filter(|s| is_bssid(s));
        let before_ok = i == 0 || !blocks(chars[i - 1].1);
        if let (Some(token), true) = (candidate, before_ok) {
            let after_ok = text[start + 17..].chars().next().is_none_or(|c| !blocks(c));
            if after_ok {
                let bssid = token.to_lowercase();
                match lookup(&bssid) {
                    Some(name) => out.push_str(&format!("{name} ({bssid})")),
                    None => out.push_str(token),
                }
                i += 17;
                continue;
            }
        }
        out.push(chars[i].1);
        i += 1;
    }
    out
}
