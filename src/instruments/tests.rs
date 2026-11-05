use std::collections::HashMap;
use std::sync::Arc;

use super::*;
use crate::probes::tests::lossless_lag_ms;

const NOW: f64 = 1000.0;

fn st() -> Stats {
    Stats { count: 60, loss: Some(0.0), p50: Some(20.0), p95: Some(30.0), ..Stats::empty() }
}

fn with(loss: f64, p50: Option<f64>, p95: Option<f64>) -> Stats {
    Stats { loss: Some(loss), p50, p95, ..st() }
}

fn lat(p50: f64, p95: f64) -> Stats {
    with(0.0, Some(p50), Some(p95))
}

fn dead() -> Stats {
    with(1.0, None, None)
}

fn map(entries: &[(&str, Stats)]) -> HashMap<String, Stats> {
    entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

const POOL: [(&str, &str, &str); 4] = [
    ("icmp-a", "icmp", "1.1.1.1"),
    ("tcp-a", "tcp", "1.1.1.1:443"),
    ("tcp-b", "tcp", "cf:443"),
    ("tcp-c", "tcp", "google:443"),
];

fn keys(b: &Bench) -> Vec<String> {
    let mut k: Vec<String> = b.actives().iter().map(|i| i.key.clone()).collect();
    k.sort();
    k
}

fn sorted(mut changes: Vec<(String, bool)>) -> Vec<(String, bool)> {
    changes.sort();
    changes
}

fn change(key: &str, active: bool) -> (String, bool) {
    (key.to_string(), active)
}

#[test]
fn loss_dominates_then_spread_then_median() {
    let clean = penalty(Some(&with(0.0, Some(20.0), Some(30.0)))).unwrap();
    let lossy = penalty(Some(&with(0.05, Some(10.0), Some(12.0)))).unwrap();
    let wobbly = penalty(Some(&with(0.0, Some(20.0), Some(200.0)))).unwrap();
    let slower = penalty(Some(&with(0.0, Some(60.0), Some(70.0)))).unwrap();
    assert!(clean < lossy);
    assert!(clean < wobbly);
    assert!(clean < slower);
    assert!(slower < wobbly);
}

#[test]
fn too_few_samples_judge_nothing() {
    assert_eq!(penalty(Some(&Stats { count: Bench::MIN_SAMPLES - 1, ..st() })), None);
    assert_eq!(penalty(None), None);
    assert_eq!(penalty(Some(&Stats::empty())), None);
}

#[test]
fn full_loss_is_dead_not_slow() {
    let full = Stats { count: 60, loss: Some(1.0), ..Stats::empty() };
    assert!(penalty(Some(&full)).unwrap() >= Bench::DEAD_AT);
}

#[test]
fn host_of_strips_a_port_but_not_an_ipv6_literal() {
    assert_eq!(host_of("1.1.1.1:443"), "1.1.1.1");
    assert_eq!(host_of("1.1.1.1"), "1.1.1.1");
    assert_eq!(host_of("2606:4700::1111"), "2606:4700::1111");
    assert_eq!(host_of("cf:"), "cf:");
}

#[test]
fn the_opening_pair_spans_two_hosts() {
    assert_eq!(keys(&Bench::new(&POOL)), ["icmp-a", "tcp-b"]);
}

#[test]
fn a_blocked_anchor_still_leaves_a_working_seat() {
    let b = Bench::new(&POOL);
    let hosts: HashSet<&str> = b.actives().iter().map(|i| host_of(&i.target)).collect();
    assert_eq!(hosts.len(), 2);
    assert_eq!(b.actives().iter().filter(|i| i.target.starts_with("1.1.1.1")).count(), 1);
}

#[test]
fn a_pool_with_one_host_still_fills_both_seats() {
    let b = Bench::new(&[("icmp-a", "icmp", "1.1.1.1"), ("tcp-a", "tcp", "1.1.1.1:443")]);
    assert_eq!(keys(&b), ["icmp-a", "tcp-a"]);
}

#[test]
fn dead_seat_is_replaced_immediately() {
    let mut b = Bench::new(&POOL);
    let stats = map(&[("icmp-a", st()), ("tcp-b", dead()), ("tcp-a", lat(25.0, 35.0)), ("tcp-c", lat(40.0, 60.0))]);
    let changes = b.evaluate(1000.0, &stats);
    assert_eq!(sorted(changes), [change("tcp-a", true), change("tcp-b", false)]);
    assert_eq!(keys(&b), ["icmp-a", "tcp-a"]);
}

#[test]
fn no_churn_during_a_full_outage() {
    let mut b = Bench::new(&POOL);
    let stats = map(&[("icmp-a", dead()), ("tcp-a", dead()), ("tcp-b", dead()), ("tcp-c", dead())]);
    assert!(b.evaluate(1000.0, &stats).is_empty());
    assert_eq!(keys(&b), ["icmp-a", "tcp-b"]);
}

fn better() -> HashMap<String, Stats> {
    map(&[
        ("icmp-a", lat(10.0, 14.0)),
        ("tcp-b", lat(100.0, 160.0)),
        ("tcp-a", lat(20.0, 24.0)),
        ("tcp-c", lat(90.0, 150.0)),
    ])
}

#[test]
fn challenger_needs_two_consecutive_clear_wins() {
    let mut b = Bench::new(&POOL);
    assert!(b.evaluate(1000.0, &better()).is_empty());
    let changes = b.evaluate(1000.0 + Bench::RESELECT_EVERY_S, &better());
    assert_eq!(sorted(changes), [change("tcp-a", true), change("tcp-b", false)]);
    assert_eq!(keys(&b), ["icmp-a", "tcp-a"]);
}

#[test]
fn a_win_streak_broken_starts_over() {
    let mut b = Bench::new(&POOL);
    let level = map(&[
        ("icmp-a", lat(10.0, 14.0)),
        ("tcp-b", lat(19.0, 24.0)),
        ("tcp-a", lat(20.0, 24.0)),
        ("tcp-c", lat(90.0, 150.0)),
    ]);
    let t = 1000.0;
    assert!(b.evaluate(t, &better()).is_empty());
    assert!(b.evaluate(t + 300.0, &level).is_empty());
    assert!(b.evaluate(t + 600.0, &better()).is_empty());
    assert_eq!(keys(&b), ["icmp-a", "tcp-b"]);
}

#[test]
fn flapping_instrument_is_quarantined() {
    let mut b = Bench::new(&POOL);
    let tcp_a = 1;
    let mut t = 1000.0;
    for active in [true, false, true] {
        b.seat(tcp_a, t, active);
        t += 60.0;
    }
    assert!(b.instruments[tcp_a].quarantined_until > t);
    b.seat(tcp_a, t, false);
    let stats = map(&[("icmp-a", st()), ("tcp-b", dead()), ("tcp-a", lat(5.0, 6.0)), ("tcp-c", lat(40.0, 60.0))]);
    b.evaluate(t + 60.0, &stats);
    assert_eq!(keys(&b), ["icmp-a", "tcp-c"]);
}

#[test]
fn snapshot_names_the_seats() {
    let b = Bench::new(&POOL);
    let snap = b.snapshot(1000.0, &map(&[("icmp-a", Stats { p50: Some(7.0), ..st() })]));
    let row = |k: &str| snap.iter().find(|r| r.key == k).unwrap().clone();
    assert!(row("icmp-a").active);
    assert_eq!(row("icmp-a").p50, Some(7.0));
    assert!(!row("tcp-c").active);
    assert_eq!(row("tcp-c").count, 0);
    assert_eq!(snap.len(), 4);
}

#[test]
fn snapshot_rows_keep_the_python_keys_in_order() {
    let b = Bench::new(&POOL);
    let json = serde_json::to_string(&b.snapshot(1000.0, &HashMap::new())[0]).unwrap();
    assert_eq!(
        json,
        r#"{"key":"icmp-a","kind":"icmp","target":"1.1.1.1","active":true,"quarantined":false,"p50":null,"p95":null,"jitter":null,"loss":null,"count":0}"#
    );
}

fn merged(series: Vec<Arc<Series>>) -> MergedSeries {
    MergedSeries::new(Box::new(move || series.clone()))
}

#[test]
fn merges_and_orders_the_seated_series() {
    let (a, c) = (Arc::new(Series::default()), Arc::new(Series::default()));
    a.add(NOW - 3.0, Some(10.0), false);
    c.add(NOW - 2.0, None, false);
    a.add(NOW - 1.0, Some(12.0), false);
    let m = merged(vec![a.clone(), c]);
    assert_eq!(m.since_at(10.0, NOW).iter().map(|s| s.rtt).collect::<Vec<_>>(), [Some(10.0), None, Some(12.0)]);
    assert_eq!(merged(vec![a]).since_at(10.0, NOW).len(), 2);
}

fn stream(value: impl Fn(usize) -> Option<f64>, interval: f64, offset: f64) -> Arc<Series> {
    let s = Arc::new(Series::default());
    let (mut t, mut i) = (NOW - 30.0 + offset, 0);
    while t <= NOW {
        s.add(t, value(i), false);
        t += interval;
        i += 1;
    }
    s
}

fn last30(s: &Series) -> Vec<Sample> {
    s.since_at(30.0, NOW)
}

#[test]
fn cadence_cannot_move_the_statistics() {
    let mut merged_set = Vec::new();
    let mut pooled_set = Vec::new();
    for icmp_iv in [0.2, 0.5, 1.0] {
        let a = stream(|_| Some(5.0), icmp_iv, 0.0);
        let b = stream(|_| Some(15.0), 1.0, 0.25);
        let st = merged_stats(&[last30(&a), last30(&b)]);
        let row = (st.p50, st.p75, st.p95, st.jitter, st.loss);
        if !merged_set.contains(&row) {
            merged_set.push(row);
        }
        let old = Series::stats(&merged(vec![a, b]).since_at(30.0, NOW));
        if !pooled_set.contains(&(old.p75, old.jitter)) {
            pooled_set.push((old.p75, old.jitter));
        }
    }
    assert_eq!(merged_set, [(Some(5.0), Some(15.0), Some(15.0), Some(0.0), Some(0.0))]);
    assert!(pooled_set.len() > 1, "{pooled_set:?}");
}

#[test]
fn jitter_never_crosses_instruments() {
    let steady_a = stream(|_| Some(5.0), 0.5, 0.0);
    let steady_b = stream(|_| Some(15.0), 1.0, 0.25);
    assert_eq!(merged_stats(&[last30(&steady_a), last30(&steady_b)]).jitter, Some(0.0));
    let pooled = Series::stats(&merged(vec![steady_a.clone(), steady_b]).since_at(30.0, NOW));
    assert!(pooled.jitter.unwrap() > 5.0);
    let swinging = stream(|i| Some(if i % 2 == 1 { 10.0 } else { 40.0 }), 1.0, 0.0);
    assert_eq!(merged_stats(&[last30(&swinging), last30(&steady_a)]).jitter, Some(15.0));
}

#[test]
fn loss_is_the_mean_of_the_instruments_loss_rates() {
    let lossy = stream(|i| if i % 10 == 0 { None } else { Some(5.0) }, 0.5, 0.0);
    let clean = stream(|_| Some(15.0), 1.0, 0.25);
    let (a, b) = (last30(&lossy), last30(&clean));
    let a_loss = a.iter().filter(|s| s.rtt.is_none()).count() as f64 / a.len() as f64;
    let st = merged_stats(&[a.clone(), b.clone()]);
    assert!((st.loss.unwrap() - a_loss / 2.0).abs() < 1e-9);
    let count_weighted = a_loss * a.len() as f64 / (a.len() + b.len()) as f64;
    assert!((st.loss.unwrap() - count_weighted).abs() > 1e-3);
}

#[test]
fn one_instrument_is_series_stats_exactly() {
    let a = stream(|i| Some(5.0 + (i % 3) as f64), 0.5, 0.0);
    assert_eq!(merged_stats(&[last30(&a)]), Series::stats(&last30(&a)));
    assert_eq!(merged_stats(&[last30(&a), vec![]]), Series::stats(&last30(&a)));
    assert_eq!(merged_stats(&[]).count, 0);
}

#[test]
fn this_line_as_built() {
    let a = stream(|_| Some(3.41), 0.5, 0.0);
    let b = stream(|_| Some(4.82), 1.0, 0.25);
    // lag_ms rounds to a tenth: the slower instrument's 4.82 and nothing added.
    assert_eq!(lossless_lag_ms(&merged_stats(&[last30(&a), last30(&b)])), 4.8);
    let old = lossless_lag_ms(&Series::stats(&merged(vec![a, b]).since_at(30.0, NOW)));
    assert!((old - 6.2).abs() <= 0.1, "{old}");
}

#[test]
fn merged_series_stats_is_the_equal_weight_fold() {
    let a = stream(|_| Some(5.0), 0.5, 0.0);
    let b = stream(|_| Some(15.0), 1.0, 0.25);
    let m = merged(vec![a.clone(), b.clone()]);
    assert_eq!(m.stats_at(30.0, NOW), merged_stats(&[last30(&a), last30(&b)]));
    assert_eq!(m.each_at(Some(30.0), NOW).len(), 2);
    assert_eq!(m.each_at(None, NOW).len(), 2);
}
