use super::inventory::{csv_records, parse_inventory};
use super::iw::freq_to_channel;
use super::names::{NAME_MAX_CHARS, SSID_MAX_CHARS, clean_name, unescape_iw_ssid};
use super::names::{connection_name_from, nm_metered_from};
use super::trace::{CURL_COULDNT_RESOLVE_HOST, parse_trace, trace_verdict};
use super::*;
use crate::testutil::TempDir;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test/fixtures").join(name))
        .expect("fixture")
}

#[test]
fn link_fixture() {
    let info = parse_link(&fixture("iw-link.txt"));
    assert_eq!(info["ssid"], "Excitel");
    assert_eq!(info["freq_mhz"], json!(5180));
    assert!(info["freq_mhz"].is_i64());
    assert_eq!(info["signal_dbm"], -64);
    assert_eq!(info["band"], "5 GHz");
    assert_eq!(info["channel"], 36);
    assert_eq!(info["standard"], "802.11ax");
    assert_eq!(info["width_mhz"], 40);
    assert_eq!(info["rx_mbps"], json!(309.7));
}

#[test]
fn ssid_hex_escapes_are_decoded() {
    let cases = [
        (r"\xe3\x83\x8f\xe3\x83\x83\xe3\x82\xab\xe3\x83\xbc", "\u{30CF}\u{30C3}\u{30AB}\u{30FC}"),
        (r"Cafe\x20Wifi\xc3\xa9", "Cafe Wifi\u{E9}"),
        (r"Plain-SSID", "Plain-SSID"),
        (r"back\x5cslash", "back\\slash"),
        (r"bad\xffbytes", "bad\u{FFFD}bytes"),
    ];
    for (escaped, expected) in cases {
        assert_eq!(unescape_iw_ssid(escaped), expected, "{escaped}");
    }
}

#[test]
fn a_hostile_ssid_cannot_carry_control_characters() {
    let raw =
        "Connected to 02:00:00:00:00:01 (on wlo1)\n\tSSID: Cafe\\x0agateway 10.0.0.1, loss 0.00%\n\tfreq: 5180.0\n";
    let info = parse_link(raw);
    let ssid = info["ssid"].as_str().unwrap();
    assert!(!ssid.contains('\n'));
    let expected: String = "Cafe\u{FFFD}gateway 10.0.0.1, loss 0.00%".chars().take(32).collect();
    assert_eq!(ssid, expected);
}

#[test]
fn clean_name_keeps_names_and_refuses_the_rest() {
    for text in ["Excitel", "\u{30CF}\u{30C3}\u{30AB}\u{30FC}", "Caf\u{E9} \u{1F4F6}", "Guest (2.4 GHz)"] {
        assert_eq!(clean_name(text, NAME_MAX_CHARS), text);
    }
    for (bad, expected) in [
        ("Cafe\nforged", "Cafe\u{FFFD}forged"),
        ("Home\rgone", "Home\u{FFFD}gone"),
        ("free\u{202e}wifi", "free\u{FFFD}wifi"),
        ("A\u{200b}B", "A\u{FFFD}B"),
        ("bell\x07", "bell\u{FFFD}"),
    ] {
        assert_eq!(clean_name(bad, NAME_MAX_CHARS), expected, "{bad:?}");
    }
    assert_eq!(clean_name(&"x".repeat(90), SSID_MAX_CHARS), "x".repeat(SSID_MAX_CHARS));
    assert_eq!(clean_name("", NAME_MAX_CHARS), "");
}

#[test]
fn unassigned_code_points_are_refused_too() {
    assert_eq!(clean_name("a\u{378}b", NAME_MAX_CHARS), "a\u{FFFD}b");
    assert_eq!(clean_name("a\u{E0001}b", NAME_MAX_CHARS), "a\u{FFFD}b");
}

#[test]
fn a_connection_name_is_cleaned_too() {
    assert_eq!(connection_name_from(Some("GENERAL.CONNECTION:free\u{202e}wifi\n")), "free\u{FFFD}wifi");
    assert_eq!(connection_name_from(Some("GENERAL.CONNECTION:--\n")), "");
    assert_eq!(connection_name_from(None), "");
}

#[test]
fn channel_map() {
    assert_eq!(freq_to_channel(2412.0), Some(1));
    assert_eq!(freq_to_channel(2484.0), Some(14));
    assert_eq!(freq_to_channel(5180.0), Some(36));
    assert_eq!(freq_to_channel(5955.0), Some(1));
    assert_eq!(freq_to_channel(900.0), None);
}

#[test]
fn recorded_response() {
    let got = parse_trace(&fixture("cf-trace.txt")).unwrap();
    assert_eq!(Value::Object(got), json!({"ip": "198.51.100.7", "family": "v4", "edge": "XXX"}));
}

#[test]
fn country_and_edge_come_free_with_the_address() {
    let got = parse_trace("ip=1.2.3.4\nloc=IN\ncolo=DEL\n").unwrap();
    assert_eq!(Value::Object(got), json!({"ip": "1.2.3.4", "family": "v4", "country": "IN", "edge": "DEL"}));
}

#[test]
fn unknown_country_is_withheld_not_shown() {
    let got = parse_trace("ip=1.2.3.4\nloc=XX\ncolo=DEL\n").unwrap();
    assert!(!got.contains_key("country"));
    assert_eq!(got["edge"], "DEL");
}

#[test]
fn only_a_country_shaped_country_gets_out() {
    for bad in ["in", "IND", "I", "I1", "<b>", "\u{cd}\u{d1}"] {
        let got = parse_trace(&format!("ip=1.2.3.4\nloc={bad}\n")).unwrap();
        assert!(!got.contains_key("country"), "{bad}");
    }
    for bad in ["del", "D", "TOOLONG", "D3L", "<i>"] {
        let got = parse_trace(&format!("ip=1.2.3.4\ncolo={bad}\n")).unwrap();
        assert!(!got.contains_key("edge"), "{bad}");
    }
}

#[test]
fn country_and_edge_never_stand_in_for_an_address() {
    assert!(parse_trace("loc=IN\ncolo=DEL\n").is_none());
    assert!(parse_trace("ip=nope\nloc=IN\ncolo=DEL\n").is_none());
}

#[test]
fn v6_is_labelled() {
    let got = parse_trace("h=x\nip=2001:db8::7\nts=1\n").unwrap();
    assert_eq!(Value::Object(got), json!({"ip": "2001:db8::7", "family": "v6"}));
}

#[test]
fn only_a_real_address_gets_out() {
    assert!(parse_trace("ip=<b>not-an-ip</b>\n").is_none());
    assert!(parse_trace("ip=1.2.3.4.5\n").is_none());
    assert!(parse_trace("ip=01.2.3.4\n").is_none());
    assert!(parse_trace("h=x\nts=1\n").is_none());
    assert!(parse_trace("").is_none());
}

#[test]
fn input_is_bounded_before_parsing() {
    assert!(parse_trace(&format!("x={}\nip=1.2.3.4\n", "a".repeat(5000))).is_none());
    assert!(parse_trace(&format!("{}ip=1.2.3.4\n", "k=v\n".repeat(100))).is_none());
}

#[test]
fn trace_verdict_names_each_outcome() {
    assert_eq!(trace_verdict(None, Some(CURL_COULDNT_RESOLVE_HOST)), "unresolved");
    assert_eq!(trace_verdict(None, Some(28)), "silent");
    assert_eq!(trace_verdict(Some(""), Some(0)), "silent");
    assert_eq!(trace_verdict(Some("<html>portal</html>"), Some(0)), "intercepted");
    assert_eq!(trace_verdict(Some("ip=1.2.3.4\n"), Some(0)), "open");
}

#[test]
fn the_documented_ranges() {
    assert_eq!(tether_from_gateway("172.20.10.1"), Some(Tether { kind: "ios", label: "iPhone" }));
    assert_eq!(tether_from_gateway("192.168.43.1").unwrap().kind, "android");
    assert_eq!(tether_from_gateway("192.168.42.129").unwrap().kind, "android");
    assert_eq!(tether_from_gateway("192.168.137.1").unwrap().kind, "windows");
}

#[test]
fn ordinary_gateways_are_not_phones() {
    for gw in ["192.168.1.1", "172.20.0.1", "10.0.0.1", "172.20.11.1"] {
        assert_eq!(tether_from_gateway(gw), None, "{gw}");
    }
}

#[test]
fn nothing_and_nonsense_are_not_phones() {
    for gw in ["", "not-an-ip", "999.1.1.1"] {
        assert_eq!(tether_from_gateway(gw), None);
    }
}

#[test]
fn ipv6_gateway_does_not_raise() {
    assert_eq!(tether_from_gateway("fe80::1"), None);
}

#[test]
fn a_guess_from_networkmanager_is_not_evidence() {
    for (raw, expected) in [
        (Some("GENERAL.METERED:yes"), true),
        (Some("GENERAL.METERED:yes (guessed)"), false),
        (Some("GENERAL.METERED:no"), false),
        (Some("GENERAL.METERED:no (guessed)"), false),
        (Some(""), false),
        (None, false),
    ] {
        assert_eq!(nm_metered_from(raw), expected, "{raw:?}");
    }
}

#[test]
fn nmcli_is_asked_on_a_new_key_or_after_the_ttl_only() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let mut cache = NameCache::new(Box::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        "Home".to_string()
    }));
    let key: NameKey = ("wlo1".into(), "192.168.1.1".into(), "aa:bb".into());
    assert_eq!(cache.connection_name_cached("wlo1", &key, Some(100.0), NAME_CACHE_TTL_S), "Home");
    assert_eq!(cache.connection_name_cached("wlo1", &key, Some(130.0), NAME_CACHE_TTL_S), "Home");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let moved: NameKey = ("wlo1".into(), "10.0.0.1".into(), "aa:bb".into());
    cache.connection_name_cached("wlo1", &moved, Some(131.0), NAME_CACHE_TTL_S);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    cache.connection_name_cached("wlo1", &moved, Some(131.0 + NAME_CACHE_TTL_S + 1.0), NAME_CACHE_TTL_S);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

fn inventory_with(text: &[u8]) -> (TempDir, ApInventory) {
    let dir = TempDir::new();
    let path = dir.path().join("bssid_to_ap_inventory.csv");
    std::fs::write(&path, text).unwrap();
    (dir, ApInventory::new(Some(path)))
}

#[test]
fn csv_maps_bssid_to_access_point_name() {
    let (_d, mut inv) =
        inventory_with(b"bssid,ap_name,band,channel,ssid\n02:00:00:00:00:01,Hallway AP,6 GHz,37,TestNet\n");
    assert_eq!(inv.lookup("02:00:00:00:00:01").as_deref(), Some("Hallway AP"));
    assert_eq!(inv.lookup(" 02:00:00:00:00:01 ").as_deref(), Some("Hallway AP"));
}

#[test]
fn utf8_bom_from_spreadsheet_exports_is_accepted() {
    let (_d, mut inv) = inventory_with(b"\xEF\xBB\xBFbssid,ap_name\n02:00:00:00:00:01,Hallway AP\n");
    assert_eq!(inv.lookup("02:00:00:00:00:01").as_deref(), Some("Hallway AP"));
}

#[test]
fn invalid_rows_and_unknown_bssids_have_no_name() {
    let (_d, mut inv) = inventory_with(
        b"bssid,ap_name,band,channel,ssid\nnot-a-bssid,Wrong,5 GHz,36,Office\naa:bb:cc:dd:ee:ff,,5 GHz,36,Office\n",
    );
    assert_eq!(inv.lookup("not-a-bssid"), None);
    assert_eq!(inv.lookup("aa:bb:cc:dd:ee:ff"), None);
    assert_eq!(inv.lookup("11:22:33:44:55:66"), None);
}

#[test]
fn same_size_rewrite_is_seen_even_when_mtime_is_preserved() {
    let before = b"bssid,ap_name\naa:bb:cc:dd:ee:ff,Kitchen\n";
    let after = b"bssid,ap_name\naa:bb:cc:dd:ee:ff,Hallway\n";
    assert_eq!(before.len(), after.len());
    let (_d, mut inv) = inventory_with(before);
    assert_eq!(inv.lookup("aa:bb:cc:dd:ee:ff").as_deref(), Some("Kitchen"));
    let old = std::fs::metadata(&inv.path).unwrap().modified().unwrap();
    std::fs::write(&inv.path, after).unwrap();
    std::fs::File::options().write(true).open(&inv.path).unwrap().set_modified(old).unwrap();
    assert_eq!(inv.lookup("aa:bb:cc:dd:ee:ff").as_deref(), Some("Hallway"));
}

#[test]
fn fifo_inventory_path_cannot_block_a_snapshot() {
    let dir = TempDir::new();
    let path = dir.path().join("bssid_to_ap_inventory.csv");
    let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: c is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let mut inv = ApInventory::new(Some(path));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(inv.lookup("aa:bb:cc:dd:ee:ff"));
    });
    assert_eq!(rx.recv_timeout(std::time::Duration::from_millis(250)), Ok(None));
}

#[test]
fn csv_reader_matches_python() {
    let rec = |s: &str| csv_records(s);
    let v = |rows: &[&[&str]]| {
        Some(rows.iter().map(|r| r.iter().map(|f| f.to_string()).collect()).collect::<Vec<Vec<String>>>())
    };
    assert_eq!(rec("a,b\n\"x\ny\",z\n"), v(&[&["a", "b"], &["x\ny", "z"]]));
    assert_eq!(rec("a,b\n\"unterminated,q\n"), v(&[&["a", "b"], &["unterminated,q\n"]]));
    assert_eq!(rec("a,b\nx\"y,z\n"), v(&[&["a", "b"], &["x\"y", "z"]]));
    assert_eq!(rec("a,b\n\"q\"r,s\n"), v(&[&["a", "b"], &["qr", "s"]]));
    assert_eq!(rec("a,b\rc\n"), None);
    assert_eq!(rec("bssid,ap_name\n\n\naa,bb\n"), v(&[&["bssid", "ap_name"], &[], &[], &["aa", "bb"]]));
    assert!(parse_inventory(b"\nbssid,ap_name\naa:bb:cc:dd:ee:ff,X\n").is_empty());
}

struct FakeLink;

impl LinkSource for FakeLink {
    fn is_wireless(&mut self, _iface: &str) -> bool {
        true
    }

    fn wifi(&mut self, _iface: &str) -> (Snapshot, Snapshot) {
        let link = json!({"bssid": "02:00:00:00:00:01", "ssid": "TestNet"});
        (link.as_object().unwrap().clone(), Map::new())
    }

    fn ap_name(&mut self, _bssid: &str) -> Option<String> {
        Some("Hallway AP".into())
    }

    fn connection_name_cached(&mut self, _iface: &str, _key: &NameKey) -> String {
        "TestNet".into()
    }
}

#[test]
fn snapshot_publishes_the_known_access_point_name() {
    let route = json!({"iface": "wlo1", "gateway": "192.168.1.1", "src": "192.168.1.2"});
    let snap = snapshot_from(route.as_object().unwrap().clone(), &mut FakeLink);
    assert_eq!(snap["ap_name"], "Hallway AP");
    let keys: Vec<&str> = snap.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["iface", "gateway", "src", "tunnel_iface", "kind", "bssid", "ssid", "station", "ap_name", "name"]
    );
}

#[test]
fn snapshot_without_a_route_is_kind_none() {
    let snap = snapshot_from(Map::new(), &mut FakeLink);
    assert_eq!(Value::Object(snap), json!({"iface": "", "gateway": "", "src": "", "tunnel_iface": "", "kind": "none"}));
}

#[test]
fn historical_event_bssids_use_current_names_for_display() {
    let mut names = std::collections::HashMap::from([
        ("02:00:00:00:00:01", "Kitchen AP"),
        ("02:00:00:00:00:02", "Old Hallway Name"),
    ]);
    let detail = "Roamed from 02:00:00:00:00:01 to 02:00:00:00:00:02";
    let got = decorate_bssids(detail, &mut |b| names.get(b).map(|s| s.to_string()));
    assert_eq!(got, "Roamed from Kitchen AP (02:00:00:00:00:01) to Old Hallway Name (02:00:00:00:00:02)");
    names.insert("02:00:00:00:00:02", "Current Hallway Name");
    let got = decorate_bssids(detail, &mut |b| names.get(b).map(|s| s.to_string()));
    assert_eq!(got, "Roamed from Kitchen AP (02:00:00:00:00:01) to Current Hallway Name (02:00:00:00:00:02)");
}

#[test]
fn bssid_shaped_substrings_inside_words_are_not_decorated() {
    let detail = "xaa:bb:cc:dd:ee:ff and aa:bb:cc:dd:ee:ffz and \u{E9}aa:bb:cc:dd:ee:ff";
    assert_eq!(decorate_bssids(detail, &mut |_| Some("Hallway".into())), detail);
    assert_eq!(decorate_bssids("AA:BB:CC:DD:EE:FF.", &mut |_| Some("H".into())), "H (aa:bb:cc:dd:ee:ff).");
}
