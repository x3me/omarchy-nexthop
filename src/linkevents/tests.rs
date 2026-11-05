use super::*;
use crate::net::genl::genl_header;
use crate::net::netlink::{AttrWriter, Messages, frame_message};

const FAMILY: u16 = 0x1c;
const AP: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x05];
const ME: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
const NEW: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x09];
const AP_S: &str = "02:11:22:33:44:05";
const NEW_S: &str = "02:11:22:33:44:09";
const CMD_DISCONNECT: u8 = 48;
const CMD_TRIGGER_SCAN: u8 = 33;
const CMD_NEW_SCAN_RESULTS: u8 = 34;
const CMD_UNPROT_DEAUTHENTICATE: u8 = 70;
const ATTR_WIPHY: u16 = 1;

fn mgmt(subtype: u8, sa: [u8; 6], da: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut f = vec![subtype, 0, 0x3a, 0x01];
    f.extend_from_slice(&da);
    f.extend_from_slice(&sa);
    f.extend_from_slice(&sa);
    f.extend_from_slice(&[0x10, 0x00]);
    f.extend_from_slice(body);
    f
}

fn event(cmd: u8, build: impl FnOnce(&mut AttrWriter)) -> Vec<u8> {
    let mut w = AttrWriter::with_header(&genl_header(cmd));
    w.put_u32(ATTR_WIPHY, 0).put_u32(ATTR_IFINDEX, 2);
    build(&mut w);
    frame_message(FAMILY, 0, &w.buf)
}

fn deauth(sa: [u8; 6], da: [u8; 6], reason: u16) -> Vec<u8> {
    event(CMD_DEAUTHENTICATE, |w| {
        w.put(ATTR_FRAME, &mgmt(0xc0, sa, da, &reason.to_le_bytes()));
    })
}

fn disassoc(sa: [u8; 6], da: [u8; 6], reason: u16) -> Vec<u8> {
    event(CMD_DISASSOCIATE, |w| {
        w.put(ATTR_FRAME, &mgmt(0xa0, sa, da, &reason.to_le_bytes()));
    })
}

fn auth(sa: [u8; 6], da: [u8; 6], status: u16) -> Vec<u8> {
    event(CMD_AUTHENTICATE, |w| {
        let mut body = vec![0, 0, 2, 0];
        body.extend_from_slice(&status.to_le_bytes());
        w.put(ATTR_FRAME, &mgmt(0xb0, sa, da, &body));
    })
}

fn assoc(sa: [u8; 6], da: [u8; 6], status: u16) -> Vec<u8> {
    event(CMD_ASSOCIATE, |w| {
        let mut body = vec![0x11, 0x04];
        body.extend_from_slice(&status.to_le_bytes());
        body.extend_from_slice(&[0x01, 0xc0]);
        w.put(ATTR_FRAME, &mgmt(0x10, sa, da, &body));
    })
}

fn connected(bssid: [u8; 6]) -> Vec<u8> {
    event(CMD_CONNECT, |w| {
        w.put_u16(ATTR_STATUS_CODE, 0).put(ATTR_MAC, &bssid);
    })
}

fn other(cmd: u8) -> Vec<u8> {
    event(cmd, |w| {
        w.put_u16(54, 2).put_flag(0xa1);
    })
}

fn feed(ev: &NlEvents, msgs: &[(f64, Vec<u8>)]) {
    for (t, buf) in msgs {
        for (hdr, body) in Messages::new(buf) {
            if let Some(e) = decode_message(FAMILY, hdr.msg_type, body) {
                ev.consume(&e, Some(*t));
            }
        }
    }
}

fn events(msgs: &[(f64, Vec<u8>)]) -> NlEvents {
    let ev = NlEvents::new().unwrap();
    feed(&ev, msgs);
    ev
}

#[test]
fn ap_kick_then_rejoin_after_a_scan() {
    let ev = events(&[
        (1000.0001, deauth(AP, ME, 2)),
        (1000.0002, other(CMD_DISCONNECT)),
        (1000.1, other(CMD_TRIGGER_SCAN)),
        (1002.9, other(CMD_NEW_SCAN_RESULTS)),
        (1003.0001, auth(NEW, ME, 0)),
        (1003.01, assoc(NEW, ME, 0)),
        (1003.012, connected(NEW)),
    ]);
    let c = ev.cause_for(AP_S, 1004.0, 30.0).unwrap();
    assert!(c.by_ap);
    assert_eq!((c.reason, c.frame.as_str()), (2, "deauth"));
    assert!((c.gap_s.unwrap() - 3.0).abs() < 0.005);
    assert!(ev.cause_for(NEW_S, 1004.0, 30.0).is_none());
    assert!(ev.cause_for(AP_S, 1100.0, 30.0).is_none());
}

#[test]
fn client_roam_is_local_and_instant() {
    let ev = events(&[(2000.0, deauth(ME, AP, 1)), (2000.004, auth(NEW, ME, 0))]);
    let c = ev.cause_for(AP_S, 2001.0, 30.0).unwrap();
    assert!(!c.by_ap);
    assert!(c.gap_s.unwrap() < crate::daemon::LinkWatch::ROAM_FOLLOW_S);
}

#[test]
fn ap_disassoc_counts_and_case_does_not_matter() {
    let ev = events(&[(3000.5, disassoc(AP, ME, 4))]);
    let c = ev.cause_for(&AP_S.to_uppercase(), 3001.0, 10.0).unwrap();
    assert_eq!((c.by_ap, c.reason, c.frame.as_str(), c.gap_s), (true, 4, "disassoc", None));
    let ev = NlEvents::new().unwrap();
    let upper = NlEvent::Frame { frame: "deauth", sa: AP_S.to_uppercase(), da: "02:AA:BB:CC:DD:EE".into(), reason: 4 };
    ev.consume(&upper, Some(3000.5));
    assert!(ev.cause_for(AP_S, 3001.0, 10.0).unwrap().by_ap);
}

#[test]
fn forged_and_junk_messages_are_ignored() {
    let unprotected = event(CMD_UNPROT_DEAUTHENTICATE, |w| {
        w.put(ATTR_FRAME, &mgmt(0xc0, AP, ME, &7u16.to_le_bytes()));
    });
    let short = event(CMD_DEAUTHENTICATE, |w| {
        w.put(ATTR_FRAME, &mgmt(0xc0, AP, ME, &[]));
    });
    let wrong_subtype = event(CMD_DEAUTHENTICATE, |w| {
        w.put(ATTR_FRAME, &mgmt(0xb0, AP, ME, &[2, 0, 0, 0, 0, 0]));
    });
    let mut no_ifindex = AttrWriter::with_header(&genl_header(CMD_DEAUTHENTICATE));
    no_ifindex.put_u32(ATTR_WIPHY, 0).put(ATTR_FRAME, &mgmt(0xc0, AP, ME, &2u16.to_le_bytes()));
    let other_family = frame_message(FAMILY + 1, 0, &deauth(AP, ME, 2)[16..]);
    let ev = events(&[
        (4000.0, unprotected),
        (4000.1, short),
        (4000.2, wrong_subtype),
        (4000.3, frame_message(FAMILY, 0, &no_ifindex.buf)),
        (4000.4, other_family),
        (4000.5, vec![0xff; 40]),
        (4000.6, Vec::new()),
    ]);
    assert!(ev.cause_for(AP_S, 4001.0, 1e9).is_none());
}

#[test]
fn a_failed_authentication_is_not_the_follow_up() {
    let ev = events(&[(4500.0, deauth(AP, ME, 2)), (4501.0, auth(NEW, ME, 1)), (4502.0, assoc(NEW, ME, 17))]);
    assert_eq!(ev.cause_for(AP_S, 4503.0, 10.0).unwrap().gap_s, None);
}

#[test]
fn a_roam_event_is_a_follow_up() {
    let roam = event(CMD_ROAM, |w| {
        w.put(ATTR_MAC, &NEW);
    });
    let ev = events(&[(4600.0, deauth(ME, AP, 1)), (4600.25, roam)]);
    assert_eq!(ev.cause_for(AP_S, 4601.0, 10.0).unwrap().gap_s, Some(0.25));
}

#[test]
fn events_take_the_clock_given() {
    let ev = NlEvents::new().unwrap();
    feed(&ev, &[(5000.0, deauth(ME, AP, 3)), (5002.5, connected(NEW))]);
    let c = ev.cause_for(AP_S, 5003.0, 10.0).unwrap();
    assert_eq!((c.by_ap, c.reason), (false, 3));
    assert!((c.gap_s.unwrap() - 2.5).abs() < 1e-3);
}

#[test]
fn follow_up_binds_to_the_newest_cause_only() {
    let ev = events(&[(6000.0, deauth(AP, ME, 2)), (6001.0, auth(NEW, ME, 0)), (6002.0, assoc(NEW, ME, 0))]);
    assert_eq!(ev.cause_for(AP_S, 6003.0, 10.0).unwrap().gap_s, Some(1.0));
}

#[test]
fn only_the_last_sixty_four_causes_are_kept() {
    let ev = NlEvents::new().unwrap();
    feed(&ev, &[(7000.0, deauth(NEW, ME, 2))]);
    let flood: Vec<(f64, Vec<u8>)> = (0..MAX_CAUSES).map(|i| (7000.1 + i as f64 * 0.001, deauth(AP, ME, 1))).collect();
    feed(&ev, &flood);
    assert!(ev.cause_for(NEW_S, 7001.0, 1e9).is_none());
    assert!(ev.cause_for(AP_S, 7001.0, 1e9).is_some());
}

#[test]
fn reason_words_depend_on_who_sent_it() {
    assert_eq!(reason_text(4, true), "reason 4: inactivity");
    assert_eq!(reason_text(4, false), "reason 4: beacon loss");
    assert_eq!(reason_text(3, true), "reason 3: the AP is leaving");
    assert_eq!(reason_text(8, true), "reason 8: the AP is leaving the BSS");
    assert_eq!(reason_text(8, false), "reason 8: leaving the BSS");
    assert!(reason_text(2, true).contains("previous authentication"));
    assert_eq!(reason_text(250, true), "reason 250");
}

// The iw-event.txt recording (an AP kick on an Intel BE201), as the netlink messages behind each line.
#[test]
fn recording_parses_as_an_ap_kick() {
    let old = [0x02, 0x11, 0x22, 0x33, 0x44, 0x01];
    let ev = events(&[
        (1788278079.141547, other(20)),
        (1788278079.142551, deauth(old, ME, 8)),
        (1788278079.142608, other(CMD_DISCONNECT)),
        (1788278079.250838, other(CMD_TRIGGER_SCAN)),
        (1788278082.019194, other(CMD_NEW_SCAN_RESULTS)),
        (1788278082.068166, other(19)),
        (1788278082.07023, auth(AP, ME, 0)),
        (1788278082.079172, assoc(AP, ME, 0)),
        (1788278082.079235, connected(AP)),
        (1788278082.101842, other(60)),
    ]);
    let c = ev.cause_for("02:11:22:33:44:01", 1788278083.0, 30.0).unwrap();
    assert_eq!((c.by_ap, c.reason, c.frame.as_str()), (true, 8, "deauth"));
    assert!((c.gap_s.unwrap() - 2.93).abs() < 0.05);
    assert!(ev.cause_for(AP_S, 1788278083.0, 30.0).is_none());
}

#[test]
fn stop_ends_the_thread_without_a_kernel_event() {
    let ev = NlEvents::new().unwrap();
    let handle = ev.start().unwrap();
    ev.stop();
    handle.join().unwrap();
}

#[test]
#[ignore]
fn live_mlme_subscription_succeeds() {
    let (sock, family) = subscribe().expect("nl80211 mlme subscription");
    println!("SUBSCRIBED family={:#x} mlme={:?} fd={}", family.id, family.group(MLME_GROUP), sock.raw_fd());
}

#[test]
fn link_watch_logs_it_as_one_kick() {
    let old = [0x02, 0x11, 0x22, 0x33, 0x44, 0x01];
    let ev = events(&[
        (1788278079.142551, deauth(old, ME, 8)),
        (1788278079.142608, other(CMD_DISCONNECT)),
        (1788278079.250838, other(CMD_TRIGGER_SCAN)),
        (1788278082.019194, other(CMD_NEW_SCAN_RESULTS)),
        (1788278082.07023, auth(AP, ME, 0)),
        (1788278082.079172, assoc(AP, ME, 0)),
        (1788278082.079235, connected(AP)),
    ]);
    let dir = crate::testutil::TempDir::new();
    let store = std::sync::Arc::new(crate::store::Store::new(&dir.path().join("t.db"), false).unwrap());
    let causes: std::sync::Arc<dyn crate::daemon::CauseSource> = std::sync::Arc::new(ev);
    let mut watch = crate::daemon::LinkWatch::new(store.clone(), Some(causes));
    let link = |bssid: &str, channel: i64, signal: i64| {
        crate::testutil::obj(serde_json::json!({"bssid": bssid, "ssid": "x", "channel": channel, "signal_dbm": signal}))
    };
    watch.sample(1788278078.0, &link("02:11:22:33:44:01", 1, -30), 0.0).unwrap();
    watch.sample(1788278083.0, &link(AP_S, 149, -40), 0.0).unwrap();
    // Read on the recording's own clock, or the test fails once the fixture is a week old.
    let evs = store.events(7.0 * 86400.0, 100, Some(1788278083.0)).unwrap();
    assert_eq!(evs.iter().map(|e| e["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["kick"]);
    assert_eq!(
        evs[0]["detail"],
        "Kicked by AP 02:11:22:33:44:01 (reason 8: the AP is leaving the BSS), rejoined via 02:11:22:33:44:05 \
         after 3 s, channel 1 \u{2192} 149, -30 \u{2192} -40 dBm"
    );
}
