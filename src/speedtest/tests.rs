use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;

type Call = (Vec<Vec<String>>, Option<usize>, f64);

struct Fake {
    outputs: RefCell<VecDeque<Finished>>,
    calls: RefCell<Vec<Call>>,
}

impl Fake {
    fn new(outputs: &[(i32, &str)]) -> Fake {
        let outputs = outputs.iter().map(|&(code, out)| Finished { code, stdout: out.as_bytes().to_vec() });
        Fake { outputs: RefCell::new(outputs.collect()), calls: RefCell::new(Vec::new()) }
    }

    fn ok(outputs: &[&str]) -> Fake {
        Fake::new(&outputs.iter().map(|o| (0, *o)).collect::<Vec<_>>())
    }

    fn spawn(&self, argvs: &[Vec<String>], input: Option<&[u8]>, timeout: f64) -> Vec<(f64, Option<Finished>)> {
        self.calls.borrow_mut().push((argvs.to_vec(), input.map(<[u8]>::len), timeout));
        argvs.iter().map(|_| (0.0, self.outputs.borrow_mut().pop_front())).collect()
    }
}

#[test]
fn curl_is_invoked_with_a_scheme_floor() {
    let argv = curl_argv(&["https://x/y"], 15.0);
    assert_eq!(&argv[..6], ["curl", "-fsS", "--proto", "=https", "--max-time", "15"]);
}

#[test]
fn sized_for_ten_seconds_at_measured_rate() {
    let n = sized_pass(160.0 / PEAK_STREAMS as f64, PEAK_DOWN_FLOOR, CLOUDFLARE_DOWN_MAX);
    assert_eq!(n, 50_000_000);
    assert!((pass_seconds(40.0, n) - 10.0).abs() < 1e-7);
}

#[test]
fn slow_line_stays_small() {
    assert_eq!(sized_pass(10.0, PEAK_DOWN_FLOOR, CLOUDFLARE_DOWN_MAX), 12_500_000);
}

#[test]
fn caps_bound_both_directions() {
    const { assert!(CLOUDFLARE_DOWN_MAX < 100_000_000) };
    assert_eq!(sized_pass(10_000.0, PEAK_DOWN_FLOOR, CLOUDFLARE_DOWN_MAX), CLOUDFLARE_DOWN_MAX);
    assert_eq!(sized_pass(0.1, PEAK_UP_FLOOR, PEAK_UP_CAP), PEAK_UP_FLOOR);
}

#[test]
fn fast_com_wrong_shapes_fail_closed() {
    for body in ["[1, 2]", r#"{"targets": [1, 2]}"#, r#"{"targets": "x"}"#, r#"{"targets": [{"url": 5}]}"#, "null"] {
        let fake = Fake::ok(&[body]);
        assert_eq!(peak_fast(&|a, i, t| fake.spawn(a, i, t)), None, "{body}");
        assert_eq!(fake.calls.borrow().len(), 1, "{body}");
    }
}

#[test]
fn ookla_wrong_shapes_fail_closed() {
    for body in [
        r#"{"download": "x"}"#,
        "[1]",
        "null",
        r#"{"download": {"bandwidth": "fast"}, "upload": {"bandwidth": 1}, "ping": {"latency": 1}, "server": {}}"#,
    ] {
        let fake = Fake::ok(&[body]);
        assert_eq!(peak_ookla(&|a, i, t| fake.spawn(a, i, t)), None, "{body}");
    }
}

#[test]
fn ookla_result_keeps_python_shape() {
    let body = r#"{"download": {"bandwidth": 50000000, "bytes": 100}, "upload": {"bandwidth": 12500000, "bytes": 20},
        "ping": {"latency": 9.876, "jitter": 1.25}, "server": {"name": "Acme", "location": "Paris"},
        "result": {"url": "https://www.speedtest.net/result/c/x"}}"#;
    let fake = Fake::ok(&[body]);
    let got = peak_ookla(&|a, i, t| fake.spawn(a, i, t)).expect("parsed");
    let calls = fake.calls.borrow();
    assert_eq!(calls[0].0[0], ["speedtest", "--format=json", "--accept-license", "--accept-gdpr"]);
    assert_eq!(calls[0].2, 120.0);
    let expected = concat!(
        r#"{"engine":"ookla","ok":true,"down_mbps":400.0,"up_mbps":100.0,"ping_idle":9.9,"jitter":1.2,"#,
        "\"bytes\":120,\"server\":\"Acme \u{b7} Paris\",",
        r#""url":"https://www.speedtest.net/result/c/x"}"#
    );
    assert_eq!(Value::Object(got).to_string(), expected);
}

#[test]
fn peak_test_reports_failure_with_the_asked_engine() {
    let fake = Fake::new(&[(6, "")]);
    let got = peak_test_with("fast.com", &|a, i, t| fake.spawn(a, i, t));
    let keys: Vec<&str> = got.keys().map(String::as_str).collect();
    assert_eq!(keys, ["kind", "engine", "ok", "started", "ended"]);
    assert_eq!(got["engine"], "fast.com");
    assert_eq!(got["ok"], false);
    assert_eq!(fake.calls.borrow()[0].0[0].last().map(String::as_str), Some(FAST_API));
}

fn rate(size: f64, setup_s: f64, payload_s: f64) -> Option<f64> {
    rate_over_payload(size, setup_s + payload_s, setup_s)
}

fn close(a: f64, b: f64, delta: f64) -> bool {
    (a - b).abs() <= delta
}

#[test]
fn setup_time_is_not_counted_as_transfer() {
    assert!(close(rate(1_500_000.0, 0.09, 0.10).expect("rate"), 120.0, 1e-6));
}

#[test]
fn the_error_no_longer_grows_with_the_line() {
    for line_mbps in [50.0, 400.0, 1000.0] {
        let per_stream = line_mbps / 4.0;
        let payload = (3_000_000.0 * 8.0 / 1e6) / per_stream;
        let got = rate(3_000_000.0, 0.09, payload).expect("rate") * 4.0;
        assert!(close(got / line_mbps, 1.0, 1e-6), "{line_mbps} Mbps read as {got}");
    }
}

#[test]
fn the_shipping_sizing_can_time_a_gigabit_line() {
    let per_stream_at_1g = (3_000_000.0 * 8.0 / 1e6) / (1000.0 / 4.0);
    assert!(per_stream_at_1g > MIN_TIMED_WINDOW_S);
    let per_stream_at_2g = (3_000_000.0 * 8.0 / 1e6) / (2000.0 / 4.0);
    assert!(per_stream_at_2g < MIN_TIMED_WINDOW_S);
}

#[test]
fn a_window_too_short_to_time_is_withheld() {
    assert_eq!(rate(3_000_000.0, 0.09, 0.012), None);
}

#[test]
fn the_floor_is_the_window_not_the_total() {
    assert_eq!(rate(3_000_000.0, 5.0, 0.01), None);
    assert!(rate(3_000_000.0, 0.0, 0.20).is_some());
}

#[test]
fn nothing_transferred_is_not_a_rate() {
    assert_eq!(rate(0.0, 0.09, 1.0), None);
}

#[test]
fn an_impossible_window_is_withheld_not_negated() {
    assert_eq!(rate_over_payload(1_000_000.0, 0.05, 0.20), None);
}

#[test]
fn downloads_are_timed_from_the_first_byte() {
    let single = download_args("https://x/y", Some("x:443:8.8.8.8")).join(" ");
    let fake = Fake::ok(&[]);
    parallel_download(&|a, i, t| fake.spawn(a, i, t), "https://x/y", 2, 30.0);
    let parallel = fake.calls.borrow()[0].0[0].join(" ");
    for argv in [single, parallel] {
        assert!(argv.contains("%{time_starttransfer}"), "{argv}");
        assert!(!argv.contains("%{speed_download}"), "{argv}");
    }
}

#[test]
fn uploads_are_timed_from_the_handshake() {
    let argv = upload_argv("https://x/y", 30.0).join(" ");
    assert!(argv.contains("%{time_appconnect}"));
    assert!(!argv.contains("%{speed_upload}"));
}

fn parallel(outputs: &[&str]) -> (Option<f64>, i64) {
    let fake = Fake::ok(outputs);
    parallel_download(&|a, i, t| fake.spawn(a, i, t), "https://x/y", outputs.len(), 5.0)
}

#[test]
fn overlapping_download_streams_are_the_bytes_over_the_time_they_took() {
    let out = "3000000 0.29 0.09";
    let (mbps, size) = parallel(&[out, out]);
    assert!(close(mbps.expect("rate"), 240.0, 1.0));
    assert_eq!(size, 6_000_000);
}

#[test]
fn a_download_stream_that_outlives_the_others_does_not_double_the_line() {
    let (mbps, size) = parallel(&["3000000 0.29 0.09", "3000000 0.49 0.29"]);
    assert!(close(mbps.expect("rate"), 120.0, 2.0));
    assert_eq!(size, 6_000_000);
}

#[test]
fn a_gap_between_streams_is_not_billed_as_throughput() {
    let (mbps, _) = parallel(&["3000000 0.29 0.09", "3000000 1.49 1.29"]);
    assert!(close(mbps.expect("rate"), 120.0, 2.0));
}

#[test]
fn every_download_stream_untimeable_reports_no_rate_not_zero() {
    let (mbps, size) = parallel(&["3000000 0.101 0.09", "3000000 0.101 0.09"]);
    assert_eq!(mbps, None);
    assert_eq!(size, 6_000_000);
}

#[test]
fn bytes_are_counted_even_when_the_rate_is_withheld() {
    let (_, size) = parallel(&["3000000 0.101 0.09", "3000000 0.29 0.09"]);
    assert_eq!(size, 6_000_000);
}

fn parallel_up(fake: &Fake, streams: usize, per_stream: i64) -> (Option<f64>, i64) {
    parallel_upload(&|a, i, t| fake.spawn(a, i, t), "https://x/y", per_stream, streams, 5.0)
}

#[test]
fn overlapping_upload_streams_are_the_bytes_over_the_time_they_took() {
    let out = "1000000 0.29 0.09";
    let fake = Fake::ok(&[out, out, out, out]);
    let (mbps, size) = parallel_up(&fake, 4, 1_000_000);
    assert!(close(mbps.expect("rate"), 160.0, 1.0));
    assert_eq!(size, 4_000_000);
}

#[test]
fn an_upload_stream_that_outlives_the_others_does_not_double_the_line() {
    let fake = Fake::ok(&["1000000 0.29 0.09", "1000000 0.49 0.29"]);
    let (mbps, size) = parallel_up(&fake, 2, 1_000_000);
    assert!(close(mbps.expect("rate"), 40.0, 1.0));
    assert_eq!(size, 2_000_000);
}

#[test]
fn every_stream_is_fed_the_same_buffer() {
    let out = "1000000 0.29 0.09";
    let fake = Fake::ok(&[out, out, out]);
    parallel_up(&fake, 3, 1_000_000);
    let calls = fake.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.len(), 3);
    assert_eq!(calls[0].1, Some(1_000_000));
    assert_eq!(calls[0].2, 15.0);
}

#[test]
fn every_upload_stream_untimeable_reports_no_rate_not_zero() {
    let out = "1000000 0.101 0.09";
    let fake = Fake::ok(&[out, out]);
    let (mbps, size) = parallel_up(&fake, 2, 1_000_000);
    assert_eq!(mbps, None);
    assert_eq!(size, 2_000_000);
}

#[test]
fn a_failed_stream_costs_its_own_share_and_no_more() {
    let fake = Fake::new(&[(0, "1000000 0.29 0.09"), (1, "")]);
    let (mbps, size) = parallel_up(&fake, 2, 1_000_000);
    assert!(close(mbps.expect("rate"), 40.0, 1e-4));
    assert_eq!(size, 1_000_000);
}

#[test]
fn the_upload_invocation_keeps_its_scheme_floor_and_timing_field() {
    let argv = upload_argv("https://x/y", 30.0);
    assert!(argv.iter().any(|a| a == "--proto"));
    assert!(argv.iter().any(|a| a == "=https"));
    let joined = argv.join(" ");
    assert!(joined.contains("%{time_appconnect}"));
    assert!(!joined.contains("%{speed_upload}"));
    assert!(!joined.contains("%{time_starttransfer}"));
}

fn sized(hint: Option<f64>, cap: i64) -> i64 {
    content_stream_bytes(hint, 4, cap, None)
}

#[test]
fn a_slow_line_is_asked_for_far_less() {
    assert_eq!(sized(Some(10.0), CONTENT_DOWN_STREAM_CAP), CONTENT_STREAM_FLOOR);
    assert!(sized(Some(100.0), CONTENT_DOWN_STREAM_CAP) < CONTENT_DOWN_STREAM_CAP);
    assert!(sized(Some(100.0), CONTENT_DOWN_STREAM_CAP) > CONTENT_STREAM_FLOOR);
}

#[test]
fn a_fast_line_reaches_the_cap_and_stops() {
    assert_eq!(sized(Some(1000.0), CONTENT_DOWN_STREAM_CAP), CONTENT_DOWN_STREAM_CAP);
    assert_eq!(sized(Some(10000.0), CONTENT_DOWN_STREAM_CAP), CONTENT_DOWN_STREAM_CAP);
}

#[test]
fn the_size_never_leaves_its_bounds() {
    for hint in [0.001, 1.0, 10.0, 50.0, 250.0, 900.0, 5000.0] {
        let n = sized(Some(hint), CONTENT_DOWN_STREAM_CAP);
        assert!((CONTENT_STREAM_FLOOR..=CONTENT_DOWN_STREAM_CAP).contains(&n), "{hint}");
    }
}

#[test]
fn no_hint_sends_the_cap() {
    for hint in [None, Some(0.0), Some(-5.0)] {
        assert_eq!(sized(hint, CONTENT_DOWN_STREAM_CAP), CONTENT_DOWN_STREAM_CAP);
    }
}

#[test]
fn a_stream_sized_for_a_rate_can_be_timed_at_that_rate() {
    for cap in [CONTENT_DOWN_STREAM_CAP, CONTENT_UP_STREAM_CAP] {
        for hint in [1.0, 10.0, 100.0, 400.0, 900.0, 1200.0] {
            let n = sized(Some(hint), cap);
            let payload_s = (n as f64 * 8.0 / 1e6) / (hint / 4.0);
            assert!(payload_s >= MIN_TIMED_WINDOW_S, "hint {hint} Mbps, cap {cap} -> {n} bytes is {payload_s:.3} s");
        }
    }
}

#[test]
fn the_line_speed_each_direction_can_still_time() {
    let ceiling = |cap: i64| (cap as f64 * 8.0 / 1e6) / MIN_TIMED_WINDOW_S * 4.0;
    assert!(close(ceiling(CONTENT_DOWN_STREAM_CAP), 5120.0, 0.05));
    assert!(close(ceiling(CONTENT_UP_STREAM_CAP), 1280.0, 0.05));
}

#[test]
fn the_whole_check_stays_within_its_declared_budget() {
    let worst = (CONTENT_DOWN_STREAM_CAP + CONTENT_UP_STREAM_CAP) * 4;
    assert!(worst <= 40_000_000);
    let typical = (sized(Some(50.0), CONTENT_DOWN_STREAM_CAP) + sized(Some(10.0), CONTENT_UP_STREAM_CAP)) * 4;
    assert!((typical as f64) < worst as f64 / 3.0);
}

#[test]
fn the_window_each_shape_actually_holds() {
    for mbps in [25.0, 100.0, 170.0] {
        let n = content_stream_bytes(Some(mbps), 4, CONTENT_DOWN_STREAM_CAP, None);
        assert!(close((n as f64 * 8.0 / 1e6) / (mbps / 4.0), CONTENT_TARGET_S, 0.05), "{mbps}");
    }
    let hourly = content_stream_bytes(Some(400.0), 4, CONTENT_DOWN_STREAM_CAP, None);
    assert!(close((hourly as f64 * 8.0 / 1e6) / (400.0 / 4.0), 0.64, 0.005));
}

struct Check {
    result: ContentResult,
    downs: Vec<String>,
    ups: Vec<i64>,
}

fn run_check(
    down_results: &[(Option<f64>, i64)],
    up_results: &[(Option<f64>, i64)],
    down_hint: Option<f64>,
    up_hint: Option<f64>,
) -> Check {
    let mut downs_left: VecDeque<_> = down_results.iter().copied().collect();
    let mut ups_left: VecDeque<_> = up_results.iter().copied().collect();
    let (mut downs, mut ups) = (Vec::new(), Vec::new());
    let result = content_test_with(
        down_hint,
        up_hint,
        4,
        &mut |url, _, _| {
            downs.push(url.to_string());
            downs_left.pop_front().expect("download result")
        },
        &mut |_, per_stream, _, _| {
            ups.push(per_stream);
            ups_left.pop_front().expect("upload result")
        },
    );
    Check { result, downs, ups }
}

#[test]
fn a_withheld_download_is_retried_once_at_the_cap() {
    let c =
        run_check(&[(None, 2_000_000), (Some(420.0), 12_000_000)], &[(Some(90.0), 2_000_000)], Some(25.0), Some(20.0));
    assert_eq!(c.downs.len(), 2);
    assert!(c.downs[1].contains(&CONTENT_DOWN_STREAM_CAP.to_string()));
    assert_eq!(c.result.down_mbps, Some(420.0));
    assert_eq!(c.result.bytes, 2_000_000 + 12_000_000 + 2_000_000);
}

#[test]
fn a_withheld_upload_is_retried_once_at_the_cap() {
    let c =
        run_check(&[(Some(420.0), 12_000_000)], &[(None, 1_000_000), (Some(95.0), 8_000_000)], Some(900.0), Some(20.0));
    assert_eq!(c.ups.len(), 2);
    assert_eq!(c.ups[1], CONTENT_UP_STREAM_CAP);
    assert_eq!(c.result.up_mbps, Some(95.0));
}

#[test]
fn a_check_already_at_the_cap_is_not_retried() {
    let c = run_check(&[(None, 12_000_000)], &[(None, 8_000_000)], None, None);
    assert_eq!(c.downs.len(), 1);
    assert_eq!(c.result.down_mbps, None);
    assert!(!c.result.ok);
}

#[test]
fn a_genuinely_slow_line_is_not_retried() {
    let c = run_check(&[(Some(9.5), 2_000_000)], &[(Some(2.1), 2_000_000)], Some(10.0), Some(2.0));
    assert_eq!(c.downs.len(), 1);
    assert_eq!(c.ups.len(), 1);
    assert_eq!(c.result.bytes, 4_000_000);
}

#[test]
fn content_result_serializes_with_python_keys() {
    let c = run_check(&[(Some(123.456), 1)], &[(Some(0.04), 2)], Some(10.0), Some(2.0));
    let v = serde_json::to_value(&c.result).expect("json");
    let keys: Vec<&str> = v.as_object().expect("object").keys().map(String::as_str).collect();
    assert_eq!(keys, ["kind", "engine", "ok", "down_mbps", "up_mbps", "bytes", "started", "ended"]);
    assert_eq!(v["down_mbps"], 123.5);
    assert_eq!(v["up_mbps"], 0.0);
}

#[test]
fn the_cap_still_bounds_the_whole_pass() {
    let per_stream_cap = PEAK_UP_CAP / PEAK_STREAMS as i64;
    assert!(per_stream_cap * PEAK_STREAMS as i64 <= PEAK_UP_CAP);
}

#[test]
fn a_pass_is_sized_for_the_rate_one_stream_carries() {
    let streams = PEAK_STREAMS as i64;
    let n = sized_pass(400.0 / PEAK_STREAMS as f64, PEAK_UP_FLOOR / streams, PEAK_UP_CAP / streams);
    assert!(n * streams <= PEAK_UP_CAP);
    assert!(n >= PEAK_UP_FLOOR / streams);
}

#[test]
#[ignore = "real network: a few MB against speed.cloudflare.com"]
fn live_content_test() {
    let r = content_test(Some(50.0), Some(10.0));
    println!("{}", serde_json::to_string(&r).expect("json"));
    assert!(r.ok);
}
