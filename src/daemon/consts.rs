pub const OUTAGE_AFTER_S: f64 = 4.0;
pub const DISRUPTION_AFTER_S: f64 = 1.5;
pub const MIN_LOST_SAMPLES: u32 = 2;
pub const CHECK_SETTLE_S: f64 = 60.0;
pub const CHECK_DEFER_MAX_S: f64 = 600.0;
pub const CHECK_QUIET_S: f64 = 30.0;
pub const CHECK_QUIET_MAX_WAIT_S: f64 = 1800.0;
pub const CHECK_AWAKE_S: f64 = 120.0;
pub const PEAK_FRESH_S: f64 = 3600.0;

pub const LEG_STALE_S: f64 = 6.0;
pub const LEG_STREAM_WINDOW_S: f64 = 12.0;
pub const UNWATCHED_AFTER_S: f64 = LEG_STALE_S;
pub const RESUME_SETTLE_S: f64 = 30.0;

pub const MIN_LOAD_SPLIT_SAMPLES: usize = 10;
pub const LOAD_FRACTION_OF_LINE: f64 = 0.10;
pub const LOAD_FLOOR_BPS: f64 = 125_000.0;
pub const MIN_PLAUSIBLE_INFLATION: f64 = 0.95;

pub const TCP_PROBE_INTERVAL_S: f64 = 1.0;
pub const TCP_PROBE_PORT: u16 = 443;
pub const CF_EDGE_HOST: &str = "1.0.0.1";
pub const CF_EDGE_FALLBACK: &str = "1.1.1.1";
pub const DIVERSITY_HOST: &str = "dns.google";
pub const STANDBY_FACTOR: f64 = 10.0;
pub const BENCH_EVAL_EVERY_S: f64 = 60.0;

pub const NOTIFY_AFTER_S: f64 = 5.0;
pub const CONTENT_RETRY_S: f64 = 300.0;
pub const CONTENT_SETTLE_AFTER_CHANGE_S: f64 = 90.0;
pub const SPEED_CHECK_MAX_AGE_S: f64 = 3.0 * 3600.0;
pub const BAND_CHECK_MIN_GAP_S: f64 = 900.0;

pub fn check_ready(
    now: f64,
    assoc_since: Option<f64>,
    rate_low_since: Option<f64>,
    waiting_since: Option<f64>,
) -> bool {
    if waiting_since.is_some_and(|w| now - w >= CHECK_DEFER_MAX_S) {
        return true;
    }
    if assoc_since.is_some_and(|a| now - a < CHECK_SETTLE_S) {
        return false;
    }
    rate_low_since.is_none()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Run,
    Wait,
    Skip,
}

pub fn check_gate(now: f64, busy_at: Option<f64>, awake_since: Option<f64>, quiet_waiting_since: Option<f64>) -> Gate {
    if awake_since.is_some_and(|a| now - a < CHECK_AWAKE_S) {
        return Gate::Wait;
    }
    if busy_at.is_some_and(|b| now - b < CHECK_QUIET_S) {
        if quiet_waiting_since.is_some_and(|q| now - q >= CHECK_QUIET_MAX_WAIT_S) {
            return Gate::Skip;
        }
        return Gate::Wait;
    }
    Gate::Run
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: f64 = 1000.0;

    #[test]
    fn a_fresh_association_waits() {
        assert!(!check_ready(NOW, Some(NOW - 5.0), None, None));
        assert!(!check_ready(NOW, Some(NOW - CHECK_SETTLE_S + 1.0), None, None));
    }

    #[test]
    fn a_settled_association_is_ready() {
        assert!(check_ready(NOW, Some(NOW - CHECK_SETTLE_S), None, None));
    }

    #[test]
    fn a_link_with_its_rate_down_waits() {
        assert!(!check_ready(NOW, Some(NOW - 600.0), Some(NOW - 3.0), None));
    }

    #[test]
    fn a_wired_link_is_always_ready() {
        assert!(check_ready(NOW, None, None, None));
    }

    #[test]
    fn the_deferral_is_capped_so_a_slow_link_still_scores() {
        let waiting = NOW - CHECK_DEFER_MAX_S;
        assert!(check_ready(NOW, Some(NOW - 1.0), Some(NOW - 1.0), Some(waiting)));
        assert!(!check_ready(NOW, Some(NOW - 1.0), Some(NOW - 1.0), Some(NOW - 5.0)));
    }

    const GATE_NOW: f64 = 100_000.0;

    fn gate(busy_ago: Option<f64>, awake_for: f64, waiting_for: Option<f64>) -> Gate {
        check_gate(
            GATE_NOW,
            busy_ago.map(|b| GATE_NOW - b),
            Some(GATE_NOW - awake_for),
            waiting_for.map(|w| GATE_NOW - w),
        )
    }

    #[test]
    fn a_quiet_awake_machine_runs() {
        assert_eq!(gate(None, 3600.0, None), Gate::Run);
        assert_eq!(gate(Some(CHECK_QUIET_S), 3600.0, None), Gate::Run);
    }

    #[test]
    fn the_machines_own_traffic_holds_it() {
        assert_eq!(gate(Some(5.0), 3600.0, None), Gate::Wait);
        assert_eq!(gate(Some(CHECK_QUIET_S - 1.0), 3600.0, None), Gate::Wait);
    }

    #[test]
    fn a_line_busy_for_half_an_hour_gives_the_slot_up() {
        let cap = CHECK_QUIET_MAX_WAIT_S;
        assert_eq!(gate(Some(1.0), 3600.0, Some(cap - 1.0)), Gate::Wait);
        assert_eq!(gate(Some(1.0), 3600.0, Some(cap)), Gate::Skip);
        assert_eq!(gate(Some(60.0), 3600.0, Some(cap * 2.0)), Gate::Run);
    }

    #[test]
    fn a_brief_wake_never_measures() {
        assert_eq!(gate(None, 40.0, None), Gate::Wait);
        assert_eq!(gate(None, CHECK_AWAKE_S - 1.0, None), Gate::Wait);
        assert_eq!(gate(None, CHECK_AWAKE_S, None), Gate::Run);
        assert_eq!(gate(Some(1.0), 40.0, Some(CHECK_QUIET_MAX_WAIT_S)), Gate::Wait);
    }
}
