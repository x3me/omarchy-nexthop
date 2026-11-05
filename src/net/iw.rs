use serde_json::{Map, Value};
use std::fmt::Write;

use super::names::{SSID_MAX_CHARS, clean_name, unescape_iw_ssid};
use super::nl80211::{
    BSS_STATUS_ASSOCIATED, BSS_STATUS_AUTHENTICATED, BSS_STATUS_IBSS_JOINED, BssEntry, Mac, StaEntry, StaInfo, mac_text,
};
use crate::util::py_strip;

const EID_SSID: u8 = 0;
const EID_MESH_ID: u8 = 114;

pub struct LinkScan {
    pub text: String,
    pub sta_addr: Option<Mac>,
}

fn print_ssid_escaped(out: &mut String, data: &[u8]) {
    let last = data.len().saturating_sub(1);
    for (i, &b) in data.iter().enumerate() {
        if (0x21..=0x7e).contains(&b) && b != b'\\' {
            out.push(b as char);
        } else if b == b' ' && i != 0 && i != last {
            out.push(' ');
        } else {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
}

fn print_ies(out: &mut String, ies: &[u8], with_mesh_id: bool) {
    let mut rest = ies;
    while rest.len() >= 2 && rest.len() - 2 >= rest[1] as usize {
        let (id, len) = (rest[0], rest[1] as usize);
        let data = &rest[2..2 + len];
        let label = match id {
            EID_SSID => Some("\tSSID:"),
            EID_MESH_ID if with_mesh_id => Some("\tMESH ID:"),
            _ => None,
        };
        if let Some(label) = label.filter(|_| len > 0) {
            out.push_str(label);
            if len > 32 {
                let _ = write!(out, " <invalid: {len} bytes:");
                for b in data {
                    let _ = write!(out, " {b:02x}");
                }
                out.push_str(">\n");
            } else {
                out.push(' ');
                print_ssid_escaped(out, data);
                out.push('\n');
            }
        }
        rest = &rest[2 + len..];
    }
}

pub fn render_link_scan(bsses: &[BssEntry], dev: &str) -> LinkScan {
    let mut out = String::new();
    let (mut mld, mut anything_found, mut link_found) = (false, false, false);
    let mut sta_addr: Mac = [0; 6];
    for bss in bsses {
        let mut mac = mac_text(&bss.bssid);
        let link_id = bss.link_id.map(i32::from).unwrap_or(-1);
        let mut link_addr = mac.clone();
        let mut indent = "\t";
        if let Some(mld_addr) = bss.mld_addr {
            link_addr = mac_text(&bss.bssid);
            indent = "\t\t";
            if mld {
                if sta_addr != mld_addr {
                    let _ = writeln!(out, "!! inconsistent MLD address information ({})", mac_text(&mld_addr));
                    mac = mac_text(&mld_addr);
                }
            } else {
                mac = mac_text(&mld_addr);
                mld = true;
                sta_addr = mld_addr;
                if bss.status == BSS_STATUS_ASSOCIATED {
                    let _ = writeln!(out, "Connected to {mac} (on {dev})");
                }
                if let Some(ies) = &bss.ies {
                    print_ies(&mut out, ies, false);
                }
            }
        } else {
            sta_addr = bss.bssid;
        }
        match bss.status {
            BSS_STATUS_ASSOCIATED if mld => {
                let _ = writeln!(out, "\tLink {link_id} BSSID {link_addr}");
            }
            BSS_STATUS_ASSOCIATED => {
                let _ = writeln!(out, "Connected to {mac} (on {dev})");
            }
            BSS_STATUS_AUTHENTICATED => {
                let _ = writeln!(out, "Authenticated with {mac} (on {dev})");
                continue;
            }
            BSS_STATUS_IBSS_JOINED => {
                let _ = writeln!(out, "Joined IBSS {mac} (on {dev})");
            }
            _ => continue,
        }
        anything_found = true;
        if let Some(ies) = &bss.ies
            && !mld
        {
            print_ies(&mut out, ies, true);
        }
        if let Some(freq) = bss.freq {
            let _ = writeln!(out, "{indent}freq: {freq}.{}", bss.freq_offset);
        }
        if bss.status == BSS_STATUS_ASSOCIATED {
            link_found = true;
        }
    }
    if !link_found && !anything_found {
        out.push_str("Not connected.\n");
    }
    LinkScan { text: out, sta_addr: link_found.then_some(sta_addr) }
}

pub fn render_link_station(out: &mut String, info: &StaInfo) {
    if let Some(s) = info.signal {
        let _ = writeln!(out, "\tsignal: {s} dBm");
    }
    if let Some(r) = &info.rx_bitrate {
        let _ = writeln!(out, "\trx bitrate: {r}");
    }
    if let Some(r) = &info.tx_bitrate {
        let _ = writeln!(out, "\ttx bitrate: {r}");
    }
}

pub fn iw_link_text(bsses: &[BssEntry], stations: &[StaEntry], dev: &str) -> Option<String> {
    let scan = render_link_scan(bsses, dev);
    let mut text = scan.text;
    if let Some(addr) = scan.sta_addr {
        let sta = stations.iter().find(|s| s.mac == addr)?;
        render_link_station(&mut text, &sta.info);
    }
    Some(text)
}

pub struct PyNum {
    pub value: f64,
}

impl PyNum {
    pub fn json(&self) -> Value {
        if self.value.fract() == 0.0 && self.value.abs() < 9.2e18 {
            Value::from(self.value as i64)
        } else {
            Value::from(self.value)
        }
    }
}

pub fn py_num(text: &str) -> Option<PyNum> {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        let neg = b[i] == b'-' && b.get(i + 1).is_some_and(u8::is_ascii_digit);
        let digits_from = if neg { i + 1 } else { i };
        if b.get(digits_from).is_some_and(u8::is_ascii_digit) {
            let mut j = digits_from;
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            if b.get(j) == Some(&b'.') && b.get(j + 1).is_some_and(u8::is_ascii_digit) {
                j += 1;
                while b.get(j).is_some_and(u8::is_ascii_digit) {
                    j += 1;
                }
            }
            return text[start..j].parse().ok().map(|value| PyNum { value });
        }
        i += 1;
    }
    None
}

fn first_width(line: &str) -> Option<i64> {
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if line[j..].starts_with("MHz") {
                return line[i..j].parse().ok();
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

fn connected_bssid(raw: &str) -> Option<String> {
    for (pos, _) in raw.match_indices("Connected to ") {
        let rest = &raw[pos + 13..];
        let cand: String = rest.chars().take(17).collect();
        if cand.len() == 17 && cand.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Some(cand);
        }
    }
    None
}

pub fn freq_to_channel(freq: f64) -> Option<i64> {
    let f = freq.trunc() as i64;
    match f {
        2484 => Some(14),
        2412..=2472 => Some((f - 2407).div_euclid(5)),
        5160..=5885 => Some((f - 5000).div_euclid(5)),
        5955..=7115 => Some((f - 5950).div_euclid(5)),
        _ => None,
    }
}

pub fn parse_link(raw: &str) -> Map<String, Value> {
    let mut info = Map::new();
    if raw.is_empty() || raw.contains("Not connected") {
        return info;
    }
    if let Some(b) = connected_bssid(raw) {
        info.insert("bssid".into(), b.into());
    }
    let mut freq = None;
    for line in raw.lines() {
        let line = py_strip(line);
        if let Some(rest) = line.strip_prefix("SSID:") {
            let text = py_strip(rest);
            info.insert("ssid".into(), clean_name(&unescape_iw_ssid(text), SSID_MAX_CHARS).into());
        } else if line.starts_with("freq:") {
            let n = py_num(line);
            freq = n.as_ref().map(|n| n.value);
            info.insert("freq_mhz".into(), n.map(|n| n.json()).unwrap_or(Value::Null));
        } else if line.starts_with("signal:") {
            info.insert("signal_dbm".into(), py_num(line).map(|n| n.json()).unwrap_or(Value::Null));
        } else if line.starts_with("rx bitrate:") {
            info.insert("rx_mbps".into(), py_num(line).map(|n| n.json()).unwrap_or(Value::Null));
        } else if line.starts_with("tx bitrate:") {
            info.insert("tx_mbps".into(), py_num(line).map(|n| n.json()).unwrap_or(Value::Null));
            if let Some(w) = first_width(line) {
                info.insert("width_mhz".into(), w.into());
            }
            for (mcs, tag) in [("HE-MCS", "802.11ax"), ("VHT-MCS", "802.11ac"), ("HT-MCS", "802.11n")] {
                if line.contains(mcs) {
                    info.insert("standard".into(), tag.into());
                    break;
                }
            }
        }
    }
    if let Some(f) = freq.filter(|f| *f != 0.0) {
        let band = if f >= 5955.0 {
            "6 GHz"
        } else if f >= 4900.0 {
            "5 GHz"
        } else {
            "2.4 GHz"
        };
        info.insert("band".into(), band.into());
        info.insert("channel".into(), freq_to_channel(f).map(Value::from).unwrap_or(Value::Null));
    }
    info
}

pub fn station_map(stations: &[StaEntry]) -> Map<String, Value> {
    let mut out = Map::new();
    for sta in stations {
        for info in std::iter::once(&sta.info).chain(sta.links.iter()) {
            let fields: [(&str, Option<i64>); 8] = [
                ("inactive_ms", info.inactive_ms.map(i64::from)),
                ("rx_packets", info.rx_packets.map(i64::from)),
                ("tx_packets", info.tx_packets.map(i64::from)),
                ("tx_retries", info.tx_retries.map(i64::from)),
                ("tx_failed", info.tx_failed.map(i64::from)),
                ("beacon_loss", info.beacon_loss.map(i64::from)),
                ("rx_drop_misc", info.rx_drop_misc.map(|v| v as f64 as i64)),
                ("signal_avg_dbm", info.signal_avg.map(i64::from)),
            ];
            for (key, value) in fields {
                if let Some(v) = value {
                    out.insert(key.into(), v.into());
                }
            }
        }
    }
    out
}
