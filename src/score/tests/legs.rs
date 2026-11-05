use super::*;

#[test]
fn missing_local_yields_unknown_not_the_whole_round_trip() {
    let total = full(500, Some(3.5), Some(4.0), Some(18.0), Some(26.0), Some(0.0), Some(4.8), Some(3.5));
    let gone = Stats { loss: Some(1.0), ..st(0) };
    let w = wan_from(&total, &gone);
    for (key, v) in [
        ("p50", w.p50),
        ("p75", w.p75),
        ("p95", w.p95),
        ("max", w.max),
        ("last", w.last),
        ("jitter", w.jitter),
        ("loss", w.loss),
    ] {
        assert_eq!(v, None, "{key}");
    }
}

fn total_60() -> Stats {
    full(60, Some(9.0), Some(11.0), Some(20.0), Some(30.0), Some(0.2), Some(3.0), Some(9.0))
}

#[test]
fn a_router_that_sent_nothing_charges_the_isp_nothing() {
    let w = wan_from(&total_60(), &st(0));
    assert_eq!((w.last, w.jitter, w.loss), (None, None, None));
}

#[test]
fn a_router_that_answered_nothing_cannot_zero_the_isp_loss() {
    let refused = Stats { loss: Some(1.0), ..st(60) };
    assert_eq!(wan_from(&total_60(), &refused).loss, None);
}

#[test]
fn known_local_still_subtracts() {
    let total = full(500, Some(10.0), Some(12.0), Some(20.0), Some(30.0), Some(0.0), Some(1.0), Some(10.0));
    let local = full(500, Some(2.0), Some(2.5), Some(5.0), Some(8.0), Some(0.0), Some(0.4), Some(2.0));
    let w = wan_from(&total, &local);
    assert_eq!(w.p50, Some(8.0));
    assert!(w.p95 >= w.p50);
    assert_eq!(w.last, Some(8.0));
    assert_eq!(w.jitter, Some(0.6));
    assert_eq!(w.loss, Some(0.0));
}

#[test]
fn one_scale_so_the_range_cannot_read_backwards() {
    let lossy = full(500, Some(3.5), Some(4.0), Some(18.0), Some(26.0), Some(1.0), Some(4.8), None);
    let b = lag_band(&lossy);
    assert!(b.best <= b.typical);
    assert!(b.typical <= b.worst);
    assert!(b.best.unwrap() > 1000.0);
}

#[test]
fn monotonic_across_loss_levels_and_degenerate_windows() {
    let five = Some(5.0);
    for loss in [0.0, 0.01, 0.35, 1.0] {
        let b = lag_band(&full(500, five, five, five, five, Some(loss), Some(0.0), None));
        let vals = [b.best.unwrap(), b.typical.unwrap(), b.worst.unwrap()];
        assert!(vals.is_sorted(), "{loss}");
    }
}

#[test]
fn no_samples_reports_nothing() {
    assert_eq!(lag_band(&st(0)), LagBand { best: None, typical: None, worst: None });
}

fn dead() -> Stats {
    Stats { loss: Some(1.0), ..st(60) }
}

fn lossy_06() -> Stats {
    full(500, Some(5.0), Some(6.0), Some(20.0), Some(30.0), Some(0.4), Some(1.0), None)
}

#[test]
fn scoring_keeps_its_anchor() {
    assert_eq!(lag_ms(&dead()), Some(1500.0));
    assert_eq!(responsiveness(lag_ms(&dead())), 0.0);
}

#[test]
fn display_band_shows_nothing_rather_than_the_anchor() {
    assert_eq!(lag_band(&dead()), LagBand { best: None, typical: None, worst: None });
}

#[test]
fn measured_lag_refuses_the_anchor_scoring_keeps() {
    assert_eq!(measured_lag(&dead()), None);
    // Python's None and {"count": 0} both arrive here as an empty Stats.
    assert_eq!(measured_lag(&Stats::empty()), None);
    assert_eq!(lag_ms(&dead()), Some(1500.0));
    assert_eq!(measured_lag(&lossy_06()), lag_ms(&lossy_06()));
}

#[test]
fn partial_loss_still_reports_a_band() {
    let b = lag_band(&lossy_06());
    assert!(b.typical.is_some());
    assert!(b.best <= b.typical);
    assert!(b.typical <= b.worst);
}

#[test]
fn measures_from_the_last_loaded_sample() {
    let sm = [
        s(1.0, Some(10.0), false),
        s(2.0, Some(10.0), false),
        s(3.0, Some(60.0), true),
        s(4.0, Some(80.0), true),
        s(5.0, Some(70.0), true),
        s(5.4, Some(40.0), false),
        s(6.2, Some(12.0), false),
        s(7.0, Some(10.0), false),
    ];
    let d = drain_after_load(&sm, Some(10.0));
    assert_eq!(d.ms, Some(1200.0));
    assert_eq!(d.settled, Some(true));
}

#[test]
fn tolerance_not_exactness() {
    let sm = [s(1.0, Some(10.0), true), s(2.0, Some(12.4), false)];
    assert_eq!(drain_after_load(&sm, Some(10.0)).settled, Some(true));
    let sm = [s(1.0, Some(10.0), true), s(2.0, Some(20.0), false)];
    assert_eq!(drain_after_load(&sm, Some(10.0)).settled, Some(false));
}

#[test]
fn still_under_load_says_nothing() {
    let sm = [s(1.0, Some(10.0), false), s(2.0, Some(80.0), true)];
    assert_eq!(drain_after_load(&sm, Some(10.0)).ms, None);
}

#[test]
fn no_burst_says_nothing() {
    let sm = [s(1.0, Some(10.0), false), s(2.0, Some(11.0), false)];
    assert_eq!(drain_after_load(&sm, Some(10.0)).ms, None);
}

#[test]
fn unrecovered_reports_a_floor_not_a_recovery() {
    let sm =
        [s(1.0, Some(10.0), true), s(2.0, Some(90.0), false), s(3.0, Some(88.0), false), s(4.0, Some(86.0), false)];
    let d = drain_after_load(&sm, Some(10.0));
    assert_eq!(d.ms, Some(3000.0));
    assert_eq!(d.settled, Some(false));
}

#[test]
fn beyond_the_cap_is_not_a_drain() {
    let sm = [s(0.0, Some(10.0), true), s(DRAIN_MAX_S + 5.0, Some(10.0), false)];
    assert_eq!(drain_after_load(&sm, Some(10.0)).ms, None);
}

#[test]
fn lost_probes_are_skipped_not_treated_as_recovery() {
    let sm = [s(1.0, Some(90.0), true), s(2.0, None, false), s(3.0, None, false), s(4.0, Some(11.0), false)];
    let d = drain_after_load(&sm, Some(10.0));
    assert_eq!(d.ms, Some(3000.0));
    assert_eq!(d.settled, Some(true));
}

#[test]
fn no_baseline_no_claim() {
    let sm = [s(1.0, Some(90.0), true), s(2.0, Some(10.0), false)];
    assert_eq!(drain_after_load(&sm, None).ms, None);
    assert_eq!(drain_after_load(&sm, Some(0.0)).ms, None);
}

#[test]
fn pressure_bands() {
    assert_eq!(pressure(Some(5.1), None, None).state, Some("clear"));
    assert_eq!(pressure(Some(18.4), None, None).state, Some("busy"));
    assert_eq!(pressure(Some(64.0), None, None).state, Some("congested"));
}

#[test]
fn real_traffic_beats_an_inference_from_probes() {
    let p = pressure(Some(3.0), Some(99.0), Some(10.0));
    assert_eq!(p.source, Some("sockets"));
    assert_eq!(p.queue_ms, Some(3.0));
}

#[test]
fn probes_are_the_fallback() {
    let p = pressure(None, Some(48.0), Some(12.0));
    assert_eq!(p.source, Some("probes"));
    assert_eq!(p.queue_ms, Some(36.0));
}

#[test]
fn a_backwards_difference_is_withheld() {
    assert_eq!(pressure(None, Some(10.0), Some(12.0)).state, None);
}

#[test]
fn nothing_to_say_is_a_valid_answer() {
    assert_eq!(pressure(None, None, None).state, None);
    assert_eq!(pressure(None, Some(50.0), None).state, None);
}

fn sweep_total() -> Stats {
    full(500, Some(8.1), Some(10.4), Some(14.4), Some(26.0), Some(0.0), Some(2.3), Some(8.0))
}

#[test]
fn a_slower_router_than_internet_withholds_the_isp_leg() {
    let slow_gateway = full(500, Some(20.0), Some(25.0), Some(40.0), Some(60.0), Some(0.0), Some(3.0), Some(20.0));
    let w = wan_from(&sweep_total(), &slow_gateway);
    for (key, v) in [("p50", w.p50), ("p75", w.p75), ("p95", w.p95), ("max", w.max), ("last", w.last)] {
        assert_eq!(v, None, "{key}");
    }
}

#[test]
fn a_genuinely_near_zero_isp_leg_is_still_reported() {
    let near = Stats { p50: Some(8.4), p75: Some(10.6), p95: Some(14.6), max: Some(26.2), ..sweep_total() };
    assert_eq!(wan_from(&sweep_total(), &near).p50, Some(0.0));
}

#[test]
fn normal_subtraction_untouched() {
    let local = full(500, Some(2.1), Some(2.5), Some(5.0), Some(8.0), Some(0.0), Some(0.4), Some(2.0));
    let w = wan_from(&sweep_total(), &local);
    assert_eq!(w.p50, Some(6.0));
    assert_eq!(w.last, Some(6.0));
}

#[test]
fn loss_subtraction_stays_clamped_and_that_is_correct() {
    let lossy_local = Stats { loss: Some(0.3), ..sweep_total() };
    let w = wan_from(&Stats { loss: Some(0.0), ..sweep_total() }, &lossy_local);
    assert_eq!(w.loss, Some(0.0));
}

#[test]
fn the_signed_difference_stays_signed() {
    let at = |p75: f64| lag_ms(&Stats { p75: Some(p75), ..sweep_total() }).unwrap();
    assert!(at(4.0) < at(40.0));
}

#[test]
fn one_sample_is_not_enough() {
    assert!(!speed_scored(Some(63.4), 1, None));
    assert!(speed_scored(Some(63.4), 2, None));
}

#[test]
fn a_contradicting_peak_withdraws_the_figure() {
    assert!(!speed_scored(Some(63.4), 3, Some(251.4)));
    assert!(speed_scored(Some(200.0), 3, Some(251.4)));
}

#[test]
fn nothing_measured_is_never_scored() {
    assert!(!speed_scored(None, 9, None));
}

#[test]
fn the_index_leaves_an_untrusted_figure_out() {
    let pinned = index(Some(97.3), Some(97.0), Some(42.4)).unwrap();
    let honest = index(Some(97.3), Some(97.0), None).unwrap();
    assert!(pinned < 50);
    assert!(honest > 90);
}

#[test]
fn a_confirmed_outage_withholds_the_headline() {
    for state in ["local-down", "wan-down"] {
        assert!(!scored_now(state), "{state}");
    }
}

#[test]
fn ordinary_states_keep_it() {
    for state in ["online", "degraded", "captive"] {
        assert!(scored_now(state), "{state}");
    }
}

#[test]
fn a_quiet_spell_is_not_an_outage() {
    assert!(scored_now("online"));
}

#[test]
fn the_components_that_produced_it_still_stand() {
    assert_eq!(index(Some(100.0), Some(100.0), None), Some(100));
    assert!(!scored_now("local-down"));
}

#[test]
fn withholding_is_a_band_of_unknown_not_of_poor() {
    assert_eq!(band(None), "unknown");
}

#[test]
fn it_subtracts_the_router_share() {
    assert_eq!(wan_point_ms(Some(11.13), Some(3.92)), Some(7.21));
}

#[test]
fn a_gateway_slower_than_the_internet_says_nothing() {
    assert_eq!(wan_point_ms(Some(5.0), Some(9.0)), None);
}

#[test]
fn inside_the_tolerance_it_still_answers() {
    assert_eq!(wan_point_ms(Some(5.0), Some(5.5)), Some(0.0));
    assert_eq!(wan_point_ms(Some(5.0), Some(5.0 + WAN_INVERSION_TOLERANCE_MS + 0.01)), None);
}

#[test]
fn either_reading_missing_is_unknown_not_zero() {
    assert_eq!(wan_point_ms(Some(5.0), None), None);
    assert_eq!(wan_point_ms(None, Some(2.0)), None);
    assert_eq!(wan_point_ms(None, None), None);
}

#[test]
fn the_per_point_rule_refuses_exactly_when_wan_from_does() {
    let cases = [
        (Some(10.0), Some(2.0)),
        (Some(10.0), Some(10.0)),
        (Some(10.0), Some(10.5)),
        (Some(10.0), Some(11.5)),
        (Some(10.0), Some(30.0)),
        (Some(0.5), Some(0.4)),
        (None, Some(2.0)),
        (Some(10.0), None),
        (None, None),
        (Some(0.0), Some(0.0)),
    ];
    for (total, local) in cases {
        let point = wan_point_ms(total, local);
        let window = wan_from(&Stats { p50: total, ..st(9) }, &Stats { p50: local, ..st(0) }).p50;
        assert_eq!(
            point.is_none(),
            window.is_none(),
            "disagreed on total={total:?} local={local:?}: point={point:?} window={window:?}"
        );
    }
}

#[test]
fn wan_from_still_floors_each_statistic_at_the_last() {
    let w = wan_from(
        &Stats { p50: Some(10.0), p75: Some(12.0), p95: Some(13.0), max: Some(13.5), ..st(9) },
        &Stats { p50: Some(1.0), p75: Some(1.0), p95: Some(8.0), max: Some(12.0), ..st(0) },
    );
    assert!(w.p50 <= w.p75);
    assert!(w.p75 <= w.p95);
    assert!(w.p95 <= w.max);
}

#[test]
fn no_usual_level_yet_means_no_judgement() {
    assert_eq!(tunnel_bands(None, None, 0), None);
    assert_eq!(tunnel_bands(Some(150.0), Some(152.0), TUNNEL_BASELINE_MIN_MINUTES - 1), None);
}

#[test]
fn thresholds_are_the_pressure_bands_above_the_usual_level() {
    let b = tunnel_bands(Some(150.0), Some(152.0), 40).unwrap();
    assert_eq!(b.amber_ms, 150.0 + PRESSURE_BUSY_MS + 2.0 * 2.0);
    assert_eq!(b.red_ms, 150.0 + PRESSURE_CONGESTED_MS + 2.0 * 2.0);
}

#[test]
fn a_distant_tunnel_still_shows_a_real_slowdown() {
    let b = tunnel_bands(Some(150.0), Some(152.0), 40).unwrap();
    // 180 is +30 ms, yet only 1.2x the 150 ms baseline
    assert!(180.0 >= b.amber_ms);
}

#[test]
fn a_fast_tunnel_s_wobble_is_not_a_slowdown() {
    let b = tunnel_bands(Some(6.0), Some(7.7), 40).unwrap();
    // 12 is 2x the 6 ms baseline
    assert!(12.0 < b.amber_ms);
}

#[test]
fn a_wobbly_tunnel_needs_more_to_be_called_worse() {
    let calm = tunnel_bands(Some(150.0), Some(152.0), 40).unwrap();
    let wobbly = tunnel_bands(Some(150.0), Some(170.0), 40).unwrap();
    assert!(wobbly.amber_ms > calm.amber_ms);
}

#[test]
fn the_index_is_withheld_while_the_tunnel_is_down() {
    assert!(!scored_now("tunnel-down"));
}

#[test]
fn json_shapes_match_python_key_order() {
    let w = wan_from(&sweep_total(), &st(0));
    assert_eq!(
        serde_json::to_string(&w).unwrap(),
        r#"{"count":500,"p50":null,"p75":null,"p95":null,"max":null,"last":null,"jitter":null,"loss":null}"#
    );
    assert_eq!(
        serde_json::to_string(&pressure(Some(5.94), None, None)).unwrap(),
        r#"{"state":"clear","queue_ms":5.9,"source":"sockets"}"#
    );
    assert_eq!(
        serde_json::to_string(&tunnel_bands(Some(150.0), Some(152.0), 40)).unwrap(),
        r#"{"baseline_ms":150.0,"spread_ms":2.0,"amber_ms":164.0,"red_ms":184.0,"minutes":40}"#
    );
    assert_eq!(serde_json::to_string(&lag_band(&st(0))).unwrap(), r#"{"best":null,"typical":null,"worst":null}"#);
    assert_eq!(serde_json::to_string(&Drain::default()).unwrap(), r#"{"ms":null,"settled":null}"#);
    assert_eq!(serde_json::json!(RELIABILITY_WINDOW_S).to_string(), "86400");
    assert_eq!(serde_json::json!(RELIABILITY_MIN_WATCHED_S).to_string(), "3600.0");
}
