use super::*;
use crate::instruments::Bench;

pub(crate) fn lossless_lag_ms(st: &Stats) -> f64 {
    // score.lag_ms with loss == 0: round(p75 + 1.5 * jitter, 1)
    assert_eq!(st.loss, Some(0.0));
    crate::util::py_round(st.p75.unwrap() + 1.5 * st.jitter.unwrap_or(0.0), 1)
}

fn s(t: f64, rtt: Option<f64>) -> Sample {
    Sample::new(t, rtt, false)
}

#[test]
fn nearest_rank_rounds_half_to_even_like_python() {
    let seven = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
    // 0.75 * 6 = 4.5, which Python's round() takes to 4
    assert_eq!(nearest_rank(&seven, 0.75), 5.0);
    assert_eq!(nearest_rank(&[9.0], 0.95), 9.0);
}

#[test]
fn stats_count_losses_and_ipdv_jitter() {
    let samples = [
        Sample::new(1.0, Some(10.0), false),
        Sample::new(2.0, None, false),
        Sample::new(3.0, Some(40.0), false),
        Sample::new(4.0, Some(10.0), true),
    ];
    let st = Series::stats(&samples);
    assert_eq!(st.count, 4);
    assert_eq!(st.loss, Some(0.25));
    assert_eq!(st.p50, Some(10.0));
    assert_eq!(st.max, Some(40.0));
    assert_eq!(st.jitter, Some(30.0));
    assert_eq!(st.last, Some(10.0));
}

#[test]
fn empty_and_all_lost() {
    assert_eq!(Series::stats(&[]).count, 0);
    let st = Series::stats(&[s(0.0, None), s(1.0, None)]);
    assert_eq!(st.loss, Some(1.0));
    assert_eq!(st.p50, None);
}

#[test]
fn jitter_is_ipdv_not_stdev() {
    // 10/40 alternation: IPDV is 30, stdev would be ~15.
    let samples: Vec<Sample> = (0..10).map(|i| s(i as f64, Some(if i % 2 == 0 { 10.0 } else { 40.0 }))).collect();
    assert_eq!(Series::stats(&samples).jitter, Some(30.0));
}

#[test]
fn window_eviction() {
    let series = Series::new(10.0);
    series.add(980.0, Some(5.0), false);
    series.add(1000.0, Some(6.0), false);
    assert_eq!(series.all().len(), 1);
}

#[test]
fn samples_carry_the_link_state_they_saw() {
    let series = Series::default();
    series.add(1000.0, Some(12.0), false);
    series.add(1001.0, Some(250.0), true);
    let (idle, loaded) = Series::split_by_load(&series.all());
    assert_eq!(idle.len(), 1);
    assert_eq!(loaded.len(), 1);
    assert_eq!(idle[0].rtt, Some(12.0));
    assert_eq!(loaded[0].rtt, Some(250.0));
}

#[test]
fn an_even_count_of_replies_takes_the_mean_of_the_middle_two() {
    assert_eq!(Series::stats(&[s(0.0, Some(10.0)), s(1.0, Some(30.0))]).p50, Some(20.0));
}

#[test]
fn bufferbloat_shows_as_inflation_between_the_two() {
    let idle: Vec<Sample> = (0..20).map(|i| Sample::new(i as f64, Some(15.0), false)).collect();
    let loaded: Vec<Sample> = (0..20).map(|i| Sample::new((i + 20) as f64, Some(300.0), true)).collect();
    let i_lag = lossless_lag_ms(&Series::stats(&idle));
    let l_lag = lossless_lag_ms(&Series::stats(&loaded));
    assert!(i_lag < 20.0);
    assert!(l_lag > 250.0);
    assert!(l_lag / i_lag > 10.0);
}

#[test]
fn loss_is_still_counted_per_load_state() {
    let samples = [
        Sample::new(0.0, Some(10.0), false),
        Sample::new(1.0, None, false),
        Sample::new(2.0, Some(40.0), true),
        Sample::new(3.0, None, true),
        Sample::new(4.0, None, true),
    ];
    let (idle, loaded) = Series::split_by_load(&samples);
    assert_eq!(Series::stats(&idle).loss, Some(0.5));
    assert!((Series::stats(&loaded).loss.unwrap() - 2.0 / 3.0).abs() < 1e-12);
}

#[test]
fn the_window_matches_what_the_bench_ranks_on() {
    assert_eq!(TcpProbe::RETRANSMIT_WINDOW_S, Bench::WINDOW_S);
    assert_eq!(TcpProbe::RETRANSMIT_MIN_SAMPLES, Bench::MIN_SAMPLES);
}
