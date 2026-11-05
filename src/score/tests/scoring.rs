use super::*;

const DAY: f64 = 24.0 * 3600.0;
const W: f64 = RELIABILITY_WINDOW_S as f64;

fn rel(outage: f64, disruptions: i64) -> Option<f64> {
    reliability(outage, disruptions, 0.0, W)
}

#[test]
fn lag_charges_for_loss() {
    let clean = Stats { loss: Some(0.0), p75: Some(10.0), jitter: Some(1.0), ..st(100) };
    let lossy = Stats { loss: Some(0.02), ..clean.clone() };
    assert!(lag_ms(&lossy).unwrap() > lag_ms(&clean).unwrap() + 15.0);
}

#[test]
fn score_bands() {
    assert_eq!(band(Some(94)), "excellent");
    assert_eq!(band(Some(85)), "good");
    assert_eq!(band(Some(74)), "okay");
    assert_eq!(band(Some(55)), "fair");
    assert_eq!(band(Some(10)), "poor");
    assert_eq!(band(None), "unknown");
}

#[test]
fn index_skips_unknown_components() {
    assert_eq!(index(Some(90.0), Some(100.0), None), Some(91));
    assert_eq!(index(None, None, None), None);
    assert_eq!(index(None, Some(73.0), None), Some(73));
}

#[test]
fn index_does_not_let_good_components_mask_a_broken_one() {
    let idx = index(Some(40.0), Some(100.0), Some(95.0));
    assert!(idx.unwrap() < 50);
    assert_eq!(band(idx), "poor");
}

#[test]
fn index_still_rewards_an_otherwise_excellent_connection() {
    assert!(index(Some(96.0), Some(100.0), Some(94.0)).unwrap() >= 94);
}

#[test]
fn index_ties_do_not_lose_a_component() {
    assert_eq!(index(Some(70.0), Some(70.0), Some(70.0)), Some(70));
}

#[test]
fn loss_costs_the_same_as_before_on_an_ordinary_link() {
    for p75 in [5.0, 15.0, 40.0, 66.0] {
        assert_eq!(loss_cost_ms(p75), 1000.0);
    }
}

#[test]
fn loss_costs_more_on_a_high_latency_link() {
    assert!(loss_cost_ms(600.0) > loss_cost_ms(15.0) * 5.0);
    let fibre = lag_ms(&Stats { p75: Some(15.0), jitter: Some(3.0), loss: Some(0.01), ..st(100) }).unwrap();
    let sat = lag_ms(&Stats { p75: Some(600.0), jitter: Some(30.0), loss: Some(0.01), ..st(100) }).unwrap();
    assert!((fibre - 19.5 - 10.0).abs() < 0.05);
    assert!((sat - 645.0 - 90.0).abs() < 0.05);
}

#[test]
fn loss_cost_never_drops_below_the_rto_floor() {
    assert_eq!(loss_cost_ms(0.0), LOSS_STALL_FACTOR * LOSS_RTO_FLOOR_MS);
}

#[test]
fn reliability_charges_outages_harder_than_self_healed_blips() {
    let outage = rel(600.0 / DAY, 0).unwrap();
    let blips = reliability(0.0, 3, 45.0 / DAY, W).unwrap();
    assert!(outage < blips, "ten minutes fully down must cost more than three short blips");
}

#[test]
fn reliability_scales_with_downtime() {
    assert!(rel(600.0 / DAY, 0) > rel(3600.0 / DAY, 0));
    assert!(rel(3600.0 / DAY, 0) > rel(6.0 * 3600.0 / DAY, 0));
}

#[test]
fn a_bad_evening_of_blips_cannot_zero_reliability() {
    let r = reliability(0.0, 17, 17.0 * 30.0 / DAY, W).unwrap();
    assert!(r > 90.0);
    assert!(r < 100.0);
}

#[test]
fn repeated_blips_still_cost_more_than_one() {
    let one = reliability(0.0, 1, 300.0 / DAY, W).unwrap();
    let many = reliability(0.0, 10, 300.0 / DAY, W).unwrap();
    assert!(many < one);
}

#[test]
fn total_downtime_floors_at_zero() {
    assert_eq!(rel(1.0, 0), Some(0.0));
}

#[test]
fn a_window_too_thin_to_judge_is_withheld_not_perfect() {
    let floor = RELIABILITY_MIN_WATCHED_S;
    assert_eq!(reliability(0.0, 0, 0.0, floor - 1.0), None);
    assert_eq!(reliability(0.0, 0, 0.0, 0.0), None);
    assert_eq!(reliability(0.0, 0, 0.0, floor), Some(100.0));
}

#[test]
fn an_outage_costs_its_share_of_the_time_watched() {
    let watched = 6.0 * 3600.0;
    let r = reliability(1800.0 / watched, 0, 0.0, watched).unwrap();
    assert_eq!(r, py_round(100.0 - 100.0 * 1800.0 / watched, 1));
    assert!(r < rel(1800.0 / 86400.0, 0).unwrap());
}

#[test]
fn the_thinnest_scored_window_does_not_amplify_a_blip_to_ruin() {
    let floor = RELIABILITY_MIN_WATCHED_S;
    assert_eq!(reliability(36.0 / floor, 0, 0.0, floor), Some(99.0));
}

#[test]
fn wan_subtraction_monotone() {
    let w = wan_from(
        &full(60, Some(11.5), Some(15.5), Some(22.5), Some(25.2), Some(0.0), Some(4.9), Some(8.0)),
        &full(60, Some(8.6), Some(9.8), Some(19.8), Some(21.2), Some(0.0), Some(4.2), Some(7.8)),
    );
    assert!(w.p50 <= w.p75);
    assert!(w.p75 <= w.p95);
    assert!(w.p95 <= w.max);
}

#[test]
fn wan_loss_never_negative() {
    let w = wan_from(
        &Stats { loss: Some(0.0), p50: Some(5.0), last: Some(5.0), ..st(10) },
        &Stats { loss: Some(0.1), p50: Some(2.0), last: Some(2.0), ..st(10) },
    );
    assert_eq!(w.loss, Some(0.0));
}

#[test]
fn speed_prefers_download() {
    assert!(speed(Some(450.0), Some(0.1), 450.0, 50.0, None).unwrap() > 70.0);
}

#[test]
fn speed_absolute_needs_no_config() {
    let auto = |d: f64, u: f64| speed(Some(d), Some(u), 0.0, 0.0, None).unwrap();
    assert!(auto(230.0, 100.0) > 90.0);
    assert!(auto(10.0, 2.0) < 40.0);
    assert!(auto(900.0, 200.0) - auto(500.0, 100.0) < 3.0);
}

#[test]
fn degradation_penalty_only_on_big_drops() {
    assert_eq!(degradation_penalty(Some(200.0), Some(300.0)), 0.0);
    assert!(degradation_penalty(Some(60.0), Some(300.0)) > 15.0);
    assert_eq!(degradation_penalty(Some(60.0), None), 0.0);
}

#[test]
fn plan_overrides_absolute() {
    let with_plan = speed(Some(412.0), Some(48.0), 450.0, 50.0, None);
    let without = speed(Some(412.0), Some(48.0), 0.0, 0.0, None);
    assert_ne!(with_plan, without);
}
