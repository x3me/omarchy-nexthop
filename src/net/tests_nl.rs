use super::genl::{decode_family, genl_header};
use super::netlink::{AttrWriter, Attrs, Messages, frame_message};
use super::nl80211::*;
use super::rtnl::{decode_main_route, decode_route_get, parse_destination, rtmsg};
use super::*;
use serde_json::json;

const AP: Mac = [0x08, 0x3e, 0x5d, 0xf5, 0xa9, 0xa7];

fn rtm(table: u8, flags: u32, dst_len: u8) -> Vec<u8> {
    let mut h = rtmsg(libc::AF_INET as u8, dst_len).to_vec();
    h[4] = table;
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h
}

#[test]
fn route_get_reply_gives_dev_gateway_and_source() {
    let mut w = AttrWriter::with_header(&rtm(254, 0, 32));
    w.put(1, &[1, 1, 1, 1]).put_u32(4, 2).put(5, &[192, 168, 0, 1]).put(7, &[192, 168, 0, 41]).put_u32(15, 254);
    let (oif, r) = decode_route_get(&w.buf).unwrap();
    assert_eq!((oif, r.gateway.as_str(), r.prefsrc.as_str()), (2, "192.168.0.1", "192.168.0.41"));
}

#[test]
fn main_table_rows_read_like_ip_json() {
    let mut w = AttrWriter::with_header(&rtm(254, 0, 0));
    w.put_u32(4, 2).put(5, &[192, 168, 0, 1]).put_u32(6, 600);
    let (row, oif) = decode_main_route(&w.buf).unwrap();
    assert_eq!((row.dst.as_str(), row.gateway.as_str(), row.metric, oif), ("default", "192.168.0.1", 600, 2));
    let mut w = AttrWriter::with_header(&rtm(254, 0, 32));
    w.put(1, &[203, 0, 113, 5]).put_u32(4, 3);
    assert_eq!(decode_main_route(&w.buf).unwrap().0.dst, "203.0.113.5");
    let mut w = AttrWriter::with_header(&rtm(254, 0, 24));
    w.put(1, &[192, 168, 0, 0]).put_u32(4, 2);
    let (row, _) = decode_main_route(&w.buf).unwrap();
    assert_eq!((row.dst.as_str(), row.metric), ("192.168.0.0/24", 0));
}

#[test]
fn other_tables_and_cloned_routes_are_not_the_main_table() {
    let local = AttrWriter::with_header(&rtm(255, 0, 32));
    assert!(decode_main_route(&local.buf).is_none());
    let mut policy = AttrWriter::with_header(&rtm(252, 0, 0));
    policy.put_u32(15, 51820);
    assert!(decode_main_route(&policy.buf).is_none());
    let cloned = AttrWriter::with_header(&rtm(254, 0x200, 32));
    assert!(decode_main_route(&cloned.buf).is_none());
}

#[test]
fn destinations_parse_the_way_ip_route_get_does() {
    assert_eq!(parse_destination("1.1.1.1").unwrap().to_string(), "1.1.1.1");
    assert_eq!(parse_destination("1.1").unwrap().to_string(), "1.1.0.0");
    assert_eq!(parse_destination("2606:4700::1111").unwrap().to_string(), "2606:4700::1111");
    assert!(parse_destination("dns.google").is_none());
    assert!(parse_destination("1.1.1.256").is_none());
    assert!(parse_destination("1.1.1.1.1").is_none());
}

#[test]
fn messages_split_a_multipart_buffer_and_skip_a_short_tail() {
    let mut buf = frame_message(24, 7, &[1, 2, 3]);
    buf.extend(frame_message(3, 7, &[0, 0, 0, 0]));
    buf.extend_from_slice(&[9, 9]);
    let got: Vec<(u16, u32, usize)> = Messages::new(&buf).map(|(h, b)| (h.msg_type, h.seq, b.len())).collect();
    assert_eq!(got, [(24, 7, 3), (3, 7, 4)]);
}

#[test]
fn family_reply_yields_id_and_multicast_groups() {
    let mut w = AttrWriter::with_header(&genl_header(1));
    w.put(2, b"nl80211\0").put_u16(1, 0x1c).begin(7);
    for (i, (name, id)) in [("config", 4u32), ("scan", 5), ("mlme", 7)].iter().enumerate() {
        w.begin(i as u16 + 1).put(1, format!("{name}\0").as_bytes()).put_u32(2, *id).end();
    }
    w.end();
    let fam = decode_family(&w.buf).unwrap();
    assert_eq!((fam.id, fam.group("mlme"), fam.group("vendor")), (0x1c, Some(7), None));
}

fn rate(w: &mut AttrWriter, kind: u16, attrs: &[(u16, Option<u8>)], bitrate: u16) {
    w.begin(kind).put_u16(1, bitrate);
    for &(k, v) in attrs {
        match v {
            Some(v) => w.put_u8(k, v),
            None => w.put_flag(k),
        };
    }
    w.end();
}

#[test]
fn bitrates_print_exactly_as_iw_does() {
    let mut w = AttrWriter::default();
    rate(&mut w, 8, &[(6, Some(9)), (8, None), (4, None), (7, Some(2))], 8667);
    assert_eq!(
        format_bitrate(Attrs::new(&w.buf).get(8).unwrap().nested()),
        "866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2"
    );
    let mut w = AttrWriter::default();
    rate(&mut w, 8, &[(3, None), (13, Some(6)), (14, Some(2)), (15, Some(0)), (16, Some(0))], 3097);
    assert_eq!(
        format_bitrate(Attrs::new(&w.buf).get(8).unwrap().nested()),
        "309.7 MBit/s 40MHz HE-MCS 6 HE-NSS 2 HE-GI 0 HE-DCM 0"
    );
    let mut w = AttrWriter::default();
    rate(&mut w, 8, &[(2, Some(7))], 0);
    assert_eq!(format_bitrate(Attrs::new(&w.buf).get(8).unwrap().nested()), "(unknown) MCS 7");
}

fn bss_msg(bssid: Mac, status: u32, ies: &[u8], freq: u32, mld: Option<(Mac, u8)>) -> Vec<u8> {
    let mut w = AttrWriter::with_header(&genl_header(CMD_GET_SCAN));
    w.put_u32(ATTR_IFINDEX, 2).begin(ATTR_BSS).put(BSS_BSSID, &bssid).put_u32(BSS_FREQUENCY, freq);
    w.put(BSS_INFORMATION_ELEMENTS, ies).put_u32(BSS_STATUS, status);
    if let Some((addr, link)) = mld {
        w.put(BSS_MLD_ADDR, &addr).put_u8(BSS_MLO_LINK_ID, link);
    }
    w.end();
    w.buf
}

fn ssid_ie(ssid: &[u8]) -> Vec<u8> {
    let mut ie = vec![0, ssid.len() as u8];
    ie.extend_from_slice(ssid);
    ie.extend_from_slice(&[1, 2, 0x8c, 0x12]);
    ie
}

fn sta_msg(mac: Mac, signal: i8, avg: i8, links: &[(u8, u32)]) -> Vec<u8> {
    let mut w = AttrWriter::with_header(&genl_header(CMD_GET_STATION));
    w.put_u32(ATTR_IFINDEX, 2).put(ATTR_MAC, &mac).begin(ATTR_STA_INFO);
    w.put_u32(STA_INFO_INACTIVE_TIME, 5).put_u32(STA_INFO_RX_PACKETS, 427909).put_u32(STA_INFO_TX_PACKETS, 282376);
    w.put_u32(STA_INFO_TX_RETRIES, 24577).put_u32(STA_INFO_TX_FAILED, 0).put_u32(STA_INFO_BEACON_LOSS, 0);
    w.put_u64(STA_INFO_RX_DROP_MISC, 580).put_u8(STA_INFO_SIGNAL, signal as u8).put_u8(STA_INFO_SIGNAL_AVG, avg as u8);
    rate(&mut w, STA_INFO_TX_BITRATE, &[(6, Some(9)), (8, None), (4, None), (7, Some(2))], 7800);
    rate(&mut w, STA_INFO_RX_BITRATE, &[(6, Some(9)), (8, None), (4, None), (7, Some(2))], 8667);
    w.end();
    if !links.is_empty() {
        w.begin(ATTR_MLO_LINKS);
        for (i, &(id, retries)) in links.iter().enumerate() {
            w.begin(i as u16 + 1)
                .put_u8(ATTR_MLO_LINK_ID, id)
                .begin(ATTR_STA_INFO)
                .put_u32(STA_INFO_TX_RETRIES, retries)
                .end()
                .end();
        }
        w.end();
    }
    w.buf
}

#[test]
fn associated_bss_and_station_give_the_python_link_fields() {
    let bss = decode_bss(&bss_msg(AP, BSS_STATUS_ASSOCIATED, &ssid_ie(b"AlpinAir"), 5180, None)).unwrap();
    let sta = decode_station(&sta_msg(AP, -36, -43, &[])).unwrap();
    let text = iw_link_text(std::slice::from_ref(&bss), std::slice::from_ref(&sta), "wlp0s20f3").unwrap();
    assert_eq!(
        text,
        "Connected to 08:3e:5d:f5:a9:a7 (on wlp0s20f3)\n\tSSID: AlpinAir\n\tfreq: 5180.0\n\tsignal: -36 dBm\n\
         \trx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2\n\ttx bitrate: 780.0 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2\n"
    );
    let expected = json!({"bssid": "08:3e:5d:f5:a9:a7", "ssid": "AlpinAir", "freq_mhz": 5180, "signal_dbm": -36,
        "rx_mbps": 866.7, "tx_mbps": 780, "width_mhz": 80, "standard": "802.11ac", "band": "5 GHz", "channel": 36});
    let got = parse_link(&text);
    assert_eq!(Value::Object(got.clone()), expected);
    let keys: Vec<&str> = got.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["bssid", "ssid", "freq_mhz", "signal_dbm", "rx_mbps", "tx_mbps", "width_mhz", "standard", "band", "channel"]
    );
}

#[test]
fn station_counters_come_in_iw_order() {
    let sta = decode_station(&sta_msg(AP, -36, -43, &[])).unwrap();
    let got = station_map(&[sta]);
    let expected = json!({"inactive_ms": 5, "rx_packets": 427909, "tx_packets": 282376, "tx_retries": 24577,
        "tx_failed": 0, "beacon_loss": 0, "rx_drop_misc": 580, "signal_avg_dbm": -43});
    assert_eq!(Value::Object(got.clone()), expected);
    assert_eq!(got.keys().next().map(String::as_str), Some("inactive_ms"));
}

#[test]
fn mlo_link_counters_override_the_mld_totals_like_the_last_iw_line() {
    let sta = decode_station(&sta_msg(AP, -36, -43, &[(0, 10), (1, 11)])).unwrap();
    assert_eq!(station_map(&[sta])["tx_retries"], 11);
}

#[test]
fn no_associated_bss_is_not_connected() {
    let bss = decode_bss(&bss_msg(AP, BSS_STATUS_AUTHENTICATED, &ssid_ie(b"X"), 2412, None)).unwrap();
    let text = iw_link_text(&[bss], &[], "wlo1").unwrap();
    assert_eq!(text, "Authenticated with 08:3e:5d:f5:a9:a7 (on wlo1)\nNot connected.\n");
    assert!(parse_link(&text).is_empty());
    assert!(parse_link(&iw_link_text(&[], &[], "wlo1").unwrap()).is_empty());
}

#[test]
fn a_vanished_station_fails_the_link_like_iw_does() {
    let bss = decode_bss(&bss_msg(AP, BSS_STATUS_ASSOCIATED, &ssid_ie(b"X"), 2412, None)).unwrap();
    assert_eq!(iw_link_text(&[bss], &[], "wlo1"), None);
}

#[test]
fn ssid_bytes_are_escaped_then_decoded_and_cleaned() {
    let cases: [(&[u8], &str); 4] = [
        (b"Cafe\ngateway", "Cafe\u{FFFD}gateway"),
        (b" edge ", " edge "),
        ("\u{30CF}\u{30C3}\u{30AB}\u{30FC}".as_bytes(), "\u{30CF}\u{30C3}\u{30AB}\u{30FC}"),
        (b"bad\xffbytes", "bad\u{FFFD}bytes"),
    ];
    for (raw, expected) in cases {
        let bss = decode_bss(&bss_msg(AP, BSS_STATUS_ASSOCIATED, &ssid_ie(raw), 2412, None)).unwrap();
        let sta = decode_station(&sta_msg(AP, -50, -50, &[])).unwrap();
        let link = parse_link(&iw_link_text(&[bss], &[sta], "wlo1").unwrap());
        assert_eq!(link["ssid"], expected, "{raw:?}");
    }
}

#[test]
fn hidden_and_oversized_ssids_read_as_iw_prints_them() {
    let sta = decode_station(&sta_msg(AP, -50, -50, &[])).unwrap();
    let hidden = decode_bss(&bss_msg(AP, BSS_STATUS_ASSOCIATED, &ssid_ie(b""), 2412, None)).unwrap();
    let link = parse_link(&iw_link_text(&[hidden], std::slice::from_ref(&sta), "wlo1").unwrap());
    assert!(!link.contains_key("ssid"));
    assert_eq!(link["channel"], 1);
    let big = decode_bss(&bss_msg(AP, BSS_STATUS_ASSOCIATED, &ssid_ie(&[0x41; 33]), 2412, None)).unwrap();
    let link = parse_link(&iw_link_text(&[big], &[sta], "wlo1").unwrap());
    // iw prints "<invalid: 33 bytes: 41 41 ...>", cut to 32 characters.
    assert_eq!(link["ssid"], "<invalid: 33 bytes: 41 41 41 41 ");
}

#[test]
fn an_mld_connection_names_the_mld_and_its_links() {
    let mld: Mac = [2, 0, 0, 0, 0, 9];
    let a = decode_bss(&bss_msg(AP, BSS_STATUS_ASSOCIATED, &ssid_ie(b"Seven"), 5180, Some((mld, 0)))).unwrap();
    let b = decode_bss(&bss_msg([2, 0, 0, 0, 0, 8], BSS_STATUS_ASSOCIATED, &ssid_ie(b"Seven"), 6115, Some((mld, 1))))
        .unwrap();
    let sta = decode_station(&sta_msg(mld, -40, -41, &[])).unwrap();
    let text = iw_link_text(&[a, b], &[sta], "wlo1").unwrap();
    assert!(text.starts_with(
        "Connected to 02:00:00:00:00:09 (on wlo1)\n\tSSID: Seven\n\tLink 0 BSSID 08:3e:5d:f5:a9:a7\n\t\tfreq: 5180.0\n"
    ));
    let link = parse_link(&text);
    assert_eq!(
        (&link["bssid"], &link["freq_mhz"], &link["band"]),
        (&json!("02:00:00:00:00:09"), &json!(6115), &json!("6 GHz"))
    );
}
