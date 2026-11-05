use crate::daemon::consts::{DISRUPTION_AFTER_S, LEG_STALE_S, RESUME_SETTLE_S};
use crate::daemon::legs::{LegMove, LegState, LegWatch, leg_state};
use crate::probes::Sample;

fn lost(t: f64, run_since: f64, n: u32) -> LegState {
    LegState::new(false, t, Some(run_since), n)
}

fn ok(t: f64) -> LegState {
    LegState::new(true, t, None, 0)
}

fn s(t: f64, rtt: Option<f64>) -> Sample {
    Sample::new(t, rtt, false)
}

fn run_losses(n: u32, cadence: f64, t0: f64) -> (LegWatch, Vec<Option<LegMove>>) {
    let mut w = LegWatch::new();
    let mut moves = Vec::new();
    for i in 0..n {
        let t = t0 + i as f64 * cadence;
        moves.push(w.sample(lost(t, t0, i + 1), t));
    }
    let t = t0 + n as f64 * cadence;
    moves.push(w.sample(ok(t), t));
    (w, moves)
}

const T0: f64 = 1_000_000.0;

mod disruption_producer {
    use super::*;

    #[test]
    fn a_single_loss_is_noise() {
        let (w, moves) = run_losses(1, 0.5, T0);
        assert_eq!(moves, [None, None]);
        assert_eq!(w.blip, None);
    }

    #[test]
    fn below_the_threshold_stays_silent() {
        let (w, moves) = run_losses(2, 0.5, T0);
        assert_eq!(moves.last(), Some(&None));
        assert_eq!(w.blip, None);
    }

    #[test]
    fn three_losses_that_recover_are_a_disruption() {
        let (w, moves) = run_losses(3, 0.5, T0);
        assert_eq!(moves.last(), Some(&Some(LegMove::Disruption)));
        let (began, ended) = w.blip.unwrap();
        assert_eq!(began, T0);
        assert_eq!(ended, T0 + DISRUPTION_AFTER_S);
    }

    #[test]
    fn reaching_the_outage_threshold_is_an_outage_not_a_disruption() {
        // The ninth lost probe lands 4.0 s after the first.
        let (w, moves) = run_losses(9, 0.5, T0);
        assert_eq!(moves[8], Some(LegMove::Down));
        assert_eq!(moves.last(), Some(&Some(LegMove::Up)));
        assert_eq!(w.blip, None);
    }

    #[test]
    fn a_run_recovering_just_short_of_the_threshold_is_a_disruption() {
        let (_, moves) = run_losses(8, 0.5, T0);
        assert!(!moves.contains(&Some(LegMove::Down)));
        assert_eq!(moves.last(), Some(&Some(LegMove::Disruption)));
    }

    #[test]
    fn thresholds_are_seconds_not_ticks() {
        let t0 = 1000.0;
        let mut w = LegWatch::new();
        for k in 0..15u32 {
            let t = t0 + k as f64 * 0.1;
            w.sample(lost(t, t0, 1 + k / 5), t);
        }
        assert_eq!(w.sample(ok(t0 + 1.5), t0 + 1.5), Some(LegMove::Disruption));
    }

    #[test]
    fn the_outage_starts_when_the_packets_stopped() {
        let t0 = 1000.0;
        let mut w = LegWatch::new();
        let mut last = None;
        for i in 0..9u32 {
            let t = t0 + i as f64 * 0.5;
            last = w.sample(lost(t, t0, i + 1), t);
        }
        assert_eq!(last, Some(LegMove::Down));
        assert_eq!(w.down_since, Some(t0));
    }

    #[test]
    fn one_lost_probe_is_never_an_event_at_any_cadence() {
        let t0 = 1000.0;
        let mut w = LegWatch::new();
        assert_eq!(w.sample(lost(t0, t0, 1), t0 + 4.5), None);
        assert_eq!(w.down_since, None);
        assert_eq!(w.sample(lost(t0 + 5.0, t0, 2), t0 + 5.0), Some(LegMove::Down));
    }
}

mod leg_state_reading {
    use super::*;

    const NOW: f64 = 1000.0;

    #[test]
    fn empty_and_stale_streams_are_unknown_not_outages() {
        assert_eq!(leg_state(&[], NOW), None);
        assert_eq!(leg_state(&[s(NOW - LEG_STALE_S - 1.0, None)], NOW), None);
    }

    #[test]
    fn a_reply_at_the_head_is_ok() {
        let st = leg_state(&[s(NOW - 1.0, None), s(NOW - 0.5, Some(8.0))], NOW).unwrap();
        assert!(st.ok);
        assert_eq!(st.lost, 0);
        assert_eq!(st.run_since, None);
    }

    #[test]
    fn the_trailing_run_is_measured_from_its_first_loss() {
        let samples =
            [s(NOW - 3.0, Some(7.0)), s(NOW - 2.5, None), s(NOW - 2.0, None), s(NOW - 1.5, None), s(NOW - 1.0, None)];
        let st = leg_state(&samples, NOW).unwrap();
        assert!(!st.ok);
        assert_eq!(st.run_since, Some(NOW - 2.5));
        assert_eq!(st.lost, 4);
        assert_eq!(st.ts, NOW - 1.0);
    }

    #[test]
    fn a_merged_stream_ends_the_run_on_any_instruments_reply() {
        let merged = [s(NOW - 1.5, None), s(NOW - 1.0, None), s(NOW - 0.5, None), s(NOW - 0.2, Some(21.0))];
        assert!(leg_state(&merged, NOW).unwrap().ok);
    }

    #[test]
    fn a_two_second_blip_is_now_seen_end_to_end() {
        let t0 = 1000.0;
        let mut w = LegWatch::new();
        let mut stream = vec![s(t0 - 0.5, Some(6.0))];
        let mut last = None;
        for k in 0..4 {
            let t = t0 + k as f64 * 0.5;
            stream.push(s(t, None));
            last = w.sample(leg_state(&stream, t).unwrap(), t);
        }
        assert_eq!(last, None);
        stream.push(s(t0 + 2.0, Some(6.5)));
        assert_eq!(w.sample(leg_state(&stream, t0 + 2.0).unwrap(), t0 + 2.0), Some(LegMove::Disruption));
        assert_eq!(w.blip, Some((t0, t0 + 2.0)));
    }
}

mod unwatched_time {
    use super::*;

    #[test]
    fn samples_from_before_the_gap_cannot_start_the_next_run() {
        let mut w = LegWatch::new();
        w.sample(lost(100.0, 99.5, 2), 100.0);
        w.lost_sight(110.0, RESUME_SETTLE_S);
        assert_eq!(w.sample(lost(100.0, 99.5, 2), 110.5), None);
        assert_eq!(w.run_since, None);
    }

    #[test]
    fn a_reply_from_before_the_gap_does_not_end_the_settle() {
        let mut w = LegWatch::new();
        w.lost_sight(110.0, RESUME_SETTLE_S);
        w.sample(ok(109.9), 110.5);
        assert_eq!(w.resumed_at, Some(110.0));
    }

    #[test]
    fn losing_sight_forgets_a_pending_disruption() {
        let mut w = LegWatch::new();
        w.blip = Some((1.0, 3.0));
        w.lost_sight(50.0, RESUME_SETTLE_S);
        assert_eq!(w.blip, None);
    }

    #[test]
    fn losing_sight_reports_whether_the_leg_was_down() {
        let mut w = LegWatch::new();
        w.down_since = Some(90.0);
        assert!(w.lost_sight(100.0, RESUME_SETTLE_S));
        assert!(!w.lost_sight(200.0, RESUME_SETTLE_S));
    }

    #[test]
    fn a_line_still_silent_after_the_settle_is_dated_from_its_end() {
        let mut w = LegWatch::new();
        w.lost_sight(100.0, RESUME_SETTLE_S);
        assert_eq!(w.sample(lost(110.0, 100.5, 20), 110.0), None);
        let end = 100.0 + RESUME_SETTLE_S;
        assert_eq!(w.sample(lost(end + 4.0, 100.5, 60), end + 4.0), Some(LegMove::Down));
        assert_eq!(w.down_since, Some(end));
    }
}
