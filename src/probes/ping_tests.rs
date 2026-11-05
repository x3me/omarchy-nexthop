use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::icmp::*;
use super::ping::{PingEvent, PingTracker, Sequencer, on_icmp_error, seq_after};
use super::*;

fn reply(t: f64, seq: u16, rtt: f64) -> PingEvent {
    PingEvent::Reply { t, seq, rtt }
}

fn pending(t: f64, seq: u16) -> PingEvent {
    PingEvent::Pending { t, seq }
}

fn unreachable(t: f64, seq: u16) -> PingEvent {
    PingEvent::Unreachable { t, seq }
}

fn replay(events: &[PingEvent]) -> (Arc<Series>, PingTracker) {
    let series = Arc::new(Series::default());
    let mut tracker = PingTracker::new(0.5, series.clone(), None);
    for &e in events {
        tracker.consume(e);
    }
    (series, tracker)
}

fn ts(series: &Series) -> Vec<f64> {
    series.all().iter().map(|s| s.t).collect()
}

// The recorded ping-losses.txt fixture, as the events the socket loop emits.
const LOSSES: [PingEvent; 7] = [
    PingEvent::Pending { t: 1787562369.690501, seq: 1 },
    PingEvent::Pending { t: 1787562370.195259, seq: 2 },
    PingEvent::Pending { t: 1787562370.698418, seq: 3 },
    PingEvent::Pending { t: 1787562371.202303, seq: 4 },
    PingEvent::Pending { t: 1787562371.707355, seq: 5 },
    PingEvent::Pending { t: 1787562372.221354, seq: 5 },
    PingEvent::Unreachable { t: 1787562372.290416, seq: 1 },
];

#[test]
fn probe_consume_counts_loss_once() {
    let (s, _) = replay(&[pending(100.0, 1), pending(100.5, 1), unreachable(101.0, 1)]);
    let st = Series::stats(&s.all());
    assert_eq!(st.count, 1);
    assert_eq!(st.loss, Some(1.0));
}

#[test]
fn a_loss_charged_at_expiry_is_not_charged_again() {
    let (s, _) = replay(&LOSSES);
    let rows = s.all();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rtt, None);
}

#[test]
fn a_reply_after_the_grace_period_adds_nothing() {
    let events: Vec<PingEvent> = (0..6).map(|i| pending(100.0 + i as f64 * 0.5, 4 + i as u16)).collect();
    let (s, mut p) = replay(&events);
    assert!(p.charged.iter().any(|e| e.0 == 4));
    p.consume(reply(103.0, 4, 9.0));
    assert!(s.all().iter().all(|r| r.rtt.is_none()));
}

#[test]
fn a_repeated_pending_line_cannot_recharge_a_lost_seq() {
    let events: Vec<PingEvent> = (0..12).map(|k| pending(100.0 + k as f64 * 0.5, 4)).collect();
    let (s, _) = replay(&events);
    assert_eq!(s.all().len(), 1);
}

#[test]
fn a_new_ping_session_can_lose_seq_1_again() {
    let (s, mut p) = replay(&(0..6).map(|k| pending(100.0 + k as f64 * 0.5, 1)).collect::<Vec<_>>());
    assert_eq!(s.all().len(), 1);
    p.reset_tracking();
    for k in 0..6 {
        p.consume(pending(200.0 + k as f64 * 0.5, 1));
    }
    assert_eq!(s.all().len(), 2);
}

#[test]
fn the_charged_map_does_not_grow_without_bound() {
    let events: Vec<PingEvent> = (1..40).map(|seq| pending(100.0 + seq as f64, seq)).collect();
    let (_, p) = replay(&events);
    assert!(p.charged.len() < 5);
    assert!(p.pending.len() < 5);
}

#[test]
fn probe_expires_silent_losses() {
    let (s, _) = replay(&[pending(100.0, 7), reply(101.5, 8, 5.0), reply(103.0, 9, 5.0)]);
    let st = Series::stats(&s.all());
    assert_eq!(st.count, 3);
    assert!((st.loss.unwrap() - 1.0 / 3.0).abs() < 1e-12);
}

#[test]
fn a_session_end_charges_what_was_still_pending() {
    let (s, mut p) = replay(&[reply(100.0, 1, 2.0), pending(100.5, 2)]);
    p.drain();
    assert_eq!(s.all().iter().map(|r| (r.t, r.rtt)).collect::<Vec<_>>(), [(100.0, Some(2.0)), (100.5, None)]);
    assert!(p.pending.is_empty());
}

const BEFORE: [PingEvent; 2] =
    [PingEvent::Reply { t: 100.0, seq: 1, rtt: 2.1 }, PingEvent::Reply { t: 100.5, seq: 2, rtt: 2.0 }];
// 98 minutes asleep; seq 3 was sent just before, and its reply was waiting.
const THAW: [PingEvent; 2] =
    [PingEvent::Pending { t: 5980.9, seq: 3 }, PingEvent::Reply { t: 5980.9, seq: 3, rtt: 2.2 }];

fn before_and_thaw(more: &[PingEvent]) -> Vec<PingEvent> {
    [&BEFORE[..], &THAW[..], more].concat()
}

#[test]
fn a_reply_printed_on_thaw_is_not_an_answer_after_waking() {
    let (s, _) = replay(&before_and_thaw(&[]));
    assert_eq!(ts(&s), [100.0, 100.5]);
}

#[test]
fn a_probe_sent_after_waking_counts_as_usual() {
    let (s, _) = replay(&before_and_thaw(&[reply(5981.4, 4, 2.3)]));
    let last = *s.all().last().unwrap();
    assert_eq!((last.t, last.rtt), (5981.4, Some(2.3)));
}

#[test]
fn the_new_losses_after_waking_are_charged_at_their_own_time() {
    let more: Vec<PingEvent> = (0..8).map(|k| pending(5981.4 + k as f64 * 0.5, 4 + k as u16)).collect();
    let (s, _) = replay(&before_and_thaw(&more));
    let losses: Vec<f64> = s.all().iter().filter(|r| r.rtt.is_none()).map(|r| r.t).collect();
    assert!(!losses.is_empty());
    assert!(losses.iter().all(|&t| t >= 5981.4));
}

#[test]
fn a_loss_from_before_the_stop_is_charged_before_it() {
    let (s, _) = replay(&[reply(100.0, 1, 2.1), pending(100.5, 2), pending(5980.9, 3)]);
    let rows: Vec<(f64, Option<f64>)> = s.all().iter().map(|r| (r.t, r.rtt)).collect();
    assert_eq!(rows, [(100.0, Some(2.1)), (100.5, None)]);
}

#[test]
fn a_short_pause_in_output_is_not_a_stop() {
    let (s, p) = replay(&[BEFORE[0], BEFORE[1], reply(102.0, 3, 2.2)]);
    assert_eq!(p.stale_upto, None);
    assert_eq!(s.all().len(), 3);
}

#[test]
fn the_sequence_wrapping_after_a_stop_is_not_the_stop() {
    let mut events = vec![reply(1000.0, 32759, 2.0), reply(1000.5, 32760, 2.0), reply(1023.0, 32762, 2.1)];
    let mut t = 1023.0;
    for seq in (32763..=65535u32).chain(0..40) {
        t += 0.5;
        events.push(reply(t, seq as u16, 2.0));
    }
    let (s, _) = replay(&events);
    assert_eq!(s.all().iter().filter(|r| r.t > t - 20.0).count(), 40);
}

#[test]
fn a_stop_across_the_wrap_still_drops_only_its_own_packet() {
    let (s, _) =
        replay(&[reply(100.0, 65534, 2.1), reply(100.5, 65535, 2.1), reply(5980.9, 0, 2.2), reply(5981.4, 1, 2.3)]);
    // seq 0 was sent before the stop, however small its number; seq 1 not.
    assert_eq!(ts(&s).into_iter().filter(|&t| t > 5000.0).collect::<Vec<_>>(), [5981.4]);
}

#[test]
fn seq_after_compares_modulo_the_16_bit_space() {
    assert!(seq_after(2, 1));
    assert!(!seq_after(1, 1));
    assert!(!seq_after(1, 2));
    assert!(seq_after(0, 65535));
    assert!(!seq_after(32769, 1));
}

#[test]
fn probe_tags_from_its_predicate() {
    let busy = Arc::new(AtomicBool::new(false));
    let flag = busy.clone();
    let loaded: LoadedFn = Arc::new(move || flag.load(Ordering::SeqCst));
    let series = Arc::new(Series::default());
    let mut p = PingTracker::new(0.5, series.clone(), Some(loaded));
    p.consume(reply(100.0, 1, 3.0));
    busy.store(true, Ordering::SeqCst);
    p.consume(reply(100.5, 2, 3.0));
    assert_eq!(series.all().iter().map(|r| r.loaded).collect::<Vec<_>>(), [false, true]);
}

#[test]
fn the_unanswered_seq_is_announced_when_the_next_goes_out() {
    let mut q = Sequencer::default();
    assert_eq!(q.due(1.0), None);
    q.sent(false);
    assert_eq!(q.due(1.5), Some(pending(1.5, 1)));
    q.sent(false);
    q.answered(2);
    assert_eq!(q.due(2.0), None);
    assert_eq!(q.next, 3);
}

#[test]
fn an_unreachable_error_answers_once_and_a_deferred_send_repeats_the_announcement() {
    let (series, mut tracker) = replay(&[]);
    let mut q = Sequencer::default();
    q.sent(false);
    on_icmp_error(IcmpError { seq: 1, unreachable: true }, 1.0, &mut tracker, &mut q);
    assert_eq!(q.due(1.5), None);
    assert_eq!(series.all().iter().map(|s| s.rtt).collect::<Vec<_>>(), [None]);
    q.sent(false);
    q.sent(true);
    // seq 2 is still the newest sent, as with the fixture's repeated seq 5
    assert_eq!(q.due(2.0), Some(pending(2.0, 2)));
    assert_eq!(q.next, 3);
}

// ping -O prints "no answer yet" after a Time to live exceeded, so Python charged the request as lost
#[test]
fn an_error_that_is_not_unreachable_leaves_the_request_to_be_charged_lost() {
    let (series, mut tracker) = replay(&[]);
    let mut q = Sequencer::default();
    q.sent(false);
    on_icmp_error(IcmpError { seq: 1, unreachable: false }, 1.0, &mut tracker, &mut q);
    assert!(series.all().is_empty());
    let announced = q.due(1.5).unwrap();
    assert_eq!(announced, pending(1.5, 1));
    tracker.consume(announced);
    for (i, t) in [2.0, 2.5, 3.0, 3.5, 4.0].into_iter().enumerate() {
        tracker.consume(reply(t, 2 + i as u16, 10.0));
    }
    let lost: Vec<f64> = series.all().iter().filter(|s| s.rtt.is_none()).map(|s| s.t).collect();
    assert_eq!(lost, [1.5]);
}

#[test]
fn set_interval_has_a_floor_and_ignores_no_change() {
    let p = PingProbe::new("192.0.2.1", Arc::new(Series::default()), 50.0, "t", None);
    assert_eq!(p.interval(), 0.2);
    p.set_interval(5.0);
    assert_eq!(p.interval(), 5.0);
    p.set_interval(0.01);
    assert_eq!(p.interval(), 0.2);
}

#[test]
fn echo_request_carries_seq_and_send_time() {
    let pkt = echo_request(0x1234, 42, false);
    assert_eq!(pkt.len(), 64);
    assert_eq!(&pkt[..8], &[8, 0, 0, 0, 0, 0, 0x12, 0x34]);
    assert_eq!(echo_request(1, 0, true)[0], 128);
    let mut back = pkt;
    back[0] = 0;
    assert_eq!(decode_echo_reply(&back, false), Some(EchoReply { seq: 0x1234, sent_ns: 42 }));
    assert_eq!(decode_echo_reply(&pkt, false), None);
    assert_eq!(decode_echo_reply(&back[..12], false), None);
    back[0] = 129;
    assert_eq!(decode_echo_reply(&back, true), Some(EchoReply { seq: 0x1234, sent_ns: 42 }));
}

#[test]
fn only_what_iputils_calls_unreachable_is_unreachable() {
    for code in [0, 1, 2, 3, 11, 12, 16] {
        assert!(is_unreachable(false, 3, code), "code {code}");
    }
    for code in [4, 5, 6, 7, 9, 10, 13, 15] {
        assert!(!is_unreachable(false, 3, code), "code {code}");
    }
    assert!(!is_unreachable(false, 11, 0));
    assert!(is_unreachable(true, 1, 3));
    assert!(!is_unreachable(true, 3, 0));
}

#[test]
fn an_icmp_error_names_the_seq_of_the_echo_it_quotes() {
    let original = echo_request(7, 0, false);
    let host_unreach = ExtendedErr { origin: 2, icmp_type: 3, icmp_code: 1 };
    assert_eq!(decode_error(host_unreach, &original, false), Some(IcmpError { seq: 7, unreachable: true }));
    let ttl = ExtendedErr { origin: 2, icmp_type: 11, icmp_code: 0 };
    assert_eq!(decode_error(ttl, &original, false), Some(IcmpError { seq: 7, unreachable: false }));
    let local = ExtendedErr { origin: 1, icmp_type: 0, icmp_code: 0 };
    assert_eq!(decode_error(local, &original, false), None);
    let v6 = ExtendedErr { origin: 3, icmp_type: 1, icmp_code: 3 };
    assert_eq!(decode_error(v6, &echo_request(9, 0, true), true), Some(IcmpError { seq: 9, unreachable: true }));
}

#[test]
fn rtt_is_shown_to_three_significant_digits_like_ping() {
    assert_eq!(ping_display_ms(9130), 9.13);
    assert_eq!(ping_display_ms(11_300), 11.3);
    assert_eq!(ping_display_ms(4_384), 4.38);
    assert_eq!(ping_display_ms(4_385), 4.39);
    assert_eq!(ping_display_ms(913), 0.913);
    assert_eq!(ping_display_ms(150_400), 150.0);
    assert_eq!(ping_display_ms(99_960), 100.0);
    assert_eq!(ping_display_ms(9_996), 10.0);
    assert_eq!(ping_display_ms(20_122), 20.1);
}

fn push_cmsg(buf: &mut Vec<u8>, level: i32, kind: i32, data: &[u8]) {
    let align = |n: usize| (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
    let head = align(size_of::<libc::cmsghdr>());
    let start = buf.len();
    buf.resize(start + align(head + data.len()), 0);
    // SAFETY: zeroed cmsghdr is valid; written unaligned into a buffer sized for it.
    let mut hdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
    hdr.cmsg_len = (head + data.len()) as _;
    hdr.cmsg_level = level;
    hdr.cmsg_type = kind;
    // SAFETY: buf has at least head bytes from start.
    unsafe { std::ptr::write_unaligned(buf[start..].as_mut_ptr().cast(), hdr) };
    buf[start + head..start + head + data.len()].copy_from_slice(data);
}

#[test]
fn control_messages_yield_the_receive_stamp_and_the_icmp_error() {
    let mut buf = Vec::new();
    let mut stamp = 1_700_000_000i64.to_ne_bytes().to_vec();
    stamp.extend_from_slice(&250_000_000i64.to_ne_bytes());
    push_cmsg(&mut buf, libc::SOL_SOCKET, 35, &stamp);
    let mut ee = 113u32.to_ne_bytes().to_vec();
    ee.extend_from_slice(&[2, 3, 1, 0]);
    ee.extend_from_slice(&[0; 8]);
    ee.extend_from_slice(&[0; 16]);
    push_cmsg(&mut buf, libc::IPPROTO_IP, libc::IP_RECVERR, &ee);
    let cm = cmsgs(&buf);
    assert_eq!(cm.len(), 2);
    assert_eq!(rx_wall_ns(&cm), Some(1_700_000_000_250_000_000));
    assert_eq!(extended_err(&cm, false), Some(ExtendedErr { origin: 2, icmp_type: 3, icmp_code: 1 }));
    assert_eq!(extended_err(&cm, true), None);
    assert!(cmsgs(&buf[..10]).is_empty());
}

#[test]
fn rtt_ends_at_the_kernel_receive_stamp_when_it_is_believable() {
    let sent = 1_000_000_000u64;
    let boot_now = 1_020_000_000i128;
    let wall_now = 5_000_000_000i128;
    // 20 ms since the send, of which the reply sat 3 ms in the socket
    assert_eq!(rtt_us(sent, boot_now, wall_now, Some(wall_now - 3_000_000)), 17_000);
    assert_eq!(rtt_us(sent, boot_now, wall_now, None), 20_000);
    assert_eq!(rtt_us(sent, boot_now, wall_now, Some(wall_now + 1)), 20_000);
    assert_eq!(rtt_us(sent, boot_now, wall_now, Some(wall_now - 30_000_000)), 20_000);
    assert_eq!(rtt_us(2_000_000_000, boot_now, wall_now, None), 0);
}

fn run_probe(target: &str, interval_ms: f64, seconds: f64) -> Vec<Sample> {
    let series = Arc::new(Series::default());
    let probe = Arc::new(PingProbe::new(target, series.clone(), interval_ms, "live", None));
    probe.start().unwrap();
    std::thread::sleep(std::time::Duration::from_secs_f64(seconds));
    let stopped = std::time::Instant::now();
    probe.stop();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(stopped.elapsed().as_secs_f64() < 0.2);
    series.all()
}

#[test]
#[ignore]
fn live_loopback_answers_in_under_a_millisecond() {
    let rows = run_probe("127.0.0.1", 200.0, 1.5);
    assert!(rows.len() >= 6, "{rows:?}");
    assert!(rows.iter().all(|r| r.rtt.is_some_and(|v| v < 1.0)), "{rows:?}");
}

fn default_gateway() -> String {
    let out = std::process::Command::new("ip").args(["-4", "route", "show", "default"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let words: Vec<&str> = text.split_whitespace().collect();
    words[words.iter().position(|w| *w == "via").unwrap() + 1].to_string()
}

fn ping_rtts(target: String) -> std::thread::JoinHandle<Vec<f64>> {
    std::thread::spawn(move || {
        let out = std::process::Command::new("ping").args(["-n", "-c", "10", &target]).output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split("time=").nth(1)?.split_whitespace().next()?.parse().ok())
            .collect()
    })
}

#[test]
#[ignore]
fn live_compare_with_ping() {
    for target in [default_gateway(), "1.1.1.1".to_string()] {
        let reference = ping_rtts(target.clone());
        let rows = run_probe(&target, 1000.0, 10.0);
        let mut theirs = reference.join().unwrap();
        theirs.sort_by(f64::total_cmp);
        let ours = Series::stats(&rows);
        println!("{target}: ours {ours:?}");
        println!("{target}: ping -c 10 sorted {theirs:?}");
        assert!(ours.count >= 9);
    }
}
