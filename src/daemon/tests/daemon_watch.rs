use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::rig::{Rig, int};
use crate::daemon::arbiters::{ArbiterKind, Wan, WanEventArbiter};
use crate::daemon::consts::{OUTAGE_AFTER_S, RESUME_SETTLE_S};
use crate::daemon::legs::{LegState, LegWatch};
use crate::probes::Series;
use crate::pyjson::text;
use crate::score;

struct Replay {
    rig: Rig,
    local: Arc<Series>,
    total: Arc<Series>,
    t0: f64,
}

impl Replay {
    fn new(t0: f64) -> Replay {
        let mut rig = Rig::at(t0);
        let total = rig.single_instrument();
        let local = Arc::clone(&rig.d.local);
        Replay { rig, local, total, t0 }
    }

    fn tick(&mut self, now: f64, awake_offset: f64) {
        self.rig.set_clock(now);
        self.rig.d.watch_outages(now, Some(now - self.t0 + awake_offset)).unwrap();
    }

    fn events(&self, seconds: f64, now: f64) -> Vec<Map<String, Value>> {
        self.rig.store().events(seconds, 100, Some(now)).unwrap()
    }

    fn notices(&self) -> Vec<String> {
        self.rig.notices.lock().unwrap().iter().map(|n| n.0.clone()).collect()
    }
}

mod unwatched_time_is_not_an_outage {
    use super::*;

    const T: f64 = 1_000_000.0;
    const SLEEP: f64 = 36_000.0;
    // PingProbe charges a lost ping after interval x 2.5 + 1 s; a TCP connect fails at once.
    const PING_GRACE_S: f64 = 0.5 * 2.5 + 1.0;

    fn awake_before_sleep(r: &mut Replay, wan_down_for: f64) {
        let mut t = T - 20.0;
        while t <= T {
            r.local.add(t, Some(2.0), false);
            let lost = t > T - wan_down_for || t >= T - 0.5;
            r.total.add(t, if lost { None } else { Some(8.0) }, false);
            r.tick(t, 0.0);
            t += 0.5;
        }
    }

    fn resume(r: &mut Replay, wifi_back_after: f64, wan_back_after: Option<f64>, until: f64, awake_offset: f64) -> f64 {
        let wan_back_after = wan_back_after.unwrap_or(wifi_back_after);
        let wake = T + SLEEP;
        let mut k = 1.0;
        while k * 0.5 <= until {
            let t = wake + k * 0.5;
            let since = t - wake;
            if since >= wifi_back_after {
                r.local.add(t, Some(2.0), false);
            }
            let lost_at = t - PING_GRACE_S;
            if wake < lost_at && lost_at < wake + wifi_back_after {
                r.local.add(lost_at, None, false);
            }
            r.total.add(t, if since >= wan_back_after { Some(8.0) } else { None }, false);
            r.tick(t, awake_offset);
            k += 1.0;
        }
        wake
    }

    #[test]
    fn the_reported_sequence_leaves_no_event() {
        let mut r = Replay::new(T);
        awake_before_sleep(&mut r, 0.0);
        resume(&mut r, 6.0, None, 60.0, 0.0);
        assert!(r.events(1e9, T + SLEEP + 60.0).is_empty());
        assert!(r.notices().is_empty());
    }

    // Guard on the replay: with the gap check defeated, the same inputs produce the reported rows.
    #[test]
    fn the_old_behaviour_is_what_this_replays() {
        let mut r = Replay::new(T);
        awake_before_sleep(&mut r, 0.0);
        let wake = resume(&mut r, 6.0, None, 60.0, -SLEEP);
        let mut rows: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        for row in r.events(1e9, wake + 60.0) {
            rows.insert(text(&row, "leg").to_string(), row);
        }
        assert_eq!(rows.keys().collect::<Vec<_>>(), ["local", "wan"]);
        let wan = &rows["wan"];
        assert_eq!((text(wan, "kind"), text(wan, "detail")), ("outage", "router answers, nothing past it does"));
        assert!((int(wan, "ts").unwrap() as f64) < T + 1.0);
        assert!((int(wan, "ended_ts").unwrap() - int(wan, "ts").unwrap()) as f64 > SLEEP);
        assert_eq!((text(&rows["local"], "kind"), int(&rows["local"], "ts")), ("outage", Some(wake as i64)));
    }

    #[test]
    fn a_slow_wifi_rejoin_is_still_not_the_router() {
        let mut r = Replay::new(T);
        awake_before_sleep(&mut r, 0.0);
        resume(&mut r, 26.0, None, 60.0, 0.0);
        assert!(r.events(1e9, T + SLEEP + 60.0).is_empty());
    }

    #[test]
    fn an_outage_seen_before_sleeping_ends_where_watching_stopped() {
        let mut r = Replay::new(T);
        awake_before_sleep(&mut r, 10.0);
        let rows = r.events(1e9, T);
        assert_eq!(rows.iter().map(|e| text(e, "kind")).collect::<Vec<_>>(), ["outage"]);
        assert_eq!(int(&rows[0], "ended_ts"), None);
        let alarms = r.notices().len();
        resume(&mut r, 6.0, None, 60.0, 0.0);
        let row = &r.events(1e9, T + SLEEP + 60.0)[0];
        assert_eq!(int(row, "ended_ts"), Some(T as i64));
        assert_eq!(r.notices().len(), alarms);
    }

    #[test]
    fn a_line_dead_on_waking_is_charged_from_the_settle() {
        let mut r = Replay::new(T);
        awake_before_sleep(&mut r, 0.0);
        let wake = resume(&mut r, 6.0, Some(1e9), RESUME_SETTLE_S + 20.0, 0.0);
        let rows = r.events(1e9, wake + 120.0);
        let got: Vec<(&str, &str)> = rows.iter().map(|e| (text(e, "kind"), text(e, "leg"))).collect();
        assert_eq!(got, [("outage", "wan")]);
        assert_eq!(int(&rows[0], "ts"), Some((wake + RESUME_SETTLE_S) as i64));
    }

    #[test]
    fn a_wall_clock_step_alone_is_not_a_gap() {
        let mut r = Replay::new(T);
        r.rig.d.watch_wan = LegWatch::new();
        awake_before_sleep(&mut r, 0.0);
        r.tick(T + 3600.0, -3600.0 + 0.5);
        assert_eq!(r.rig.d.watch_wan.resumed_at, None);
    }

    #[test]
    fn reliability_is_charged_against_what_was_watched() {
        let r = Replay::new(T);
        let now = T + 20.0;
        let base = (now / 60.0).floor() as i64 * 60;
        for ago in (0..=6 * 3600).step_by(60) {
            r.rig.store().put_minute(base - ago, &Map::new(), "", "", "").unwrap();
        }
        let eid = r.rig.store().open_event(base - 3600, "outage", "critical", "wan", "t").unwrap();
        r.rig.store().close_event(eid, base - 1800, None).unwrap();
        let (rel, watched) = r.rig.d.reliability(now).unwrap();
        assert!((watched - (6.0 * 3600.0 + 20.0)).abs() <= 60.0);
        assert_eq!(rel, Some(crate::util::py_round(100.0 - 100.0 * 1800.0 / watched, 1)));
        assert!(rel.unwrap() < score::reliability(1800.0 / 86400.0, 0, 0.0, 86400.0).unwrap());
    }

    #[test]
    fn reliability_is_withheld_before_an_hour_has_been_watched() {
        let r = Replay::new(T);
        let now = T + 20.0;
        let base = (now / 60.0).floor() as i64 * 60;
        for ago in (0..1800).step_by(60) {
            r.rig.store().put_minute(base - ago, &Map::new(), "", "", "").unwrap();
        }
        let (rel, watched) = r.rig.d.reliability(now).unwrap();
        assert_eq!(rel, None);
        assert!(watched < score::RELIABILITY_MIN_WATCHED_S);
    }
}

mod wan_run_across_a_local_outage {
    use super::*;

    const T: f64 = 2_000_000.0;

    fn run_legs(r: &mut Replay, until: f64, local_ok: impl Fn(f64) -> bool, wan_ok: impl Fn(f64) -> bool) {
        let mut t = T - 20.0;
        while t <= until {
            r.local.add(t, local_ok(t).then_some(2.0), false);
            r.total.add(t, (local_ok(t) && wan_ok(t)).then_some(8.0), false);
            r.tick(t, 0.0);
            t += 0.5;
        }
    }

    fn rows(r: &Replay, kind: &str) -> Vec<(String, i64, Option<i64>)> {
        let mut out: Vec<_> = r
            .events(1e7, T + 1000.0)
            .iter()
            .filter(|e| text(e, "kind") == kind)
            .map(|e| (text(e, "leg").to_string(), int(e, "ts").unwrap(), int(e, "ended_ts")))
            .collect();
        out.sort();
        out
    }

    fn of_leg(rows: Vec<(String, i64, Option<i64>)>, leg: &str) -> Vec<(String, i64, Option<i64>)> {
        rows.into_iter().filter(|r| r.0 == leg).collect()
    }

    fn charged(r: &Replay) -> (i64, i64) {
        let (down, _, disrupted) = r.rig.store().outage_stats(3600.0, Some(T + 1000.0), &[]).unwrap();
        (crate::util::py_round_int(down * 3600.0), crate::util::py_round_int(disrupted * 3600.0))
    }

    fn wan_rows(r: &Replay) -> Vec<(i64, Option<i64>, String)> {
        let mut events = r.events(1e7, T + 1000.0);
        events.sort_by_key(|e| int(e, "ts"));
        events
            .iter()
            .filter(|e| text(e, "kind") == "outage" && text(e, "leg") == "wan")
            .map(|e| (int(e, "ts").unwrap(), int(e, "ended_ts"), text(e, "detail").to_string()))
            .collect()
    }

    fn router_out(t: f64) -> bool {
        !(T + 10.0..T + 40.0).contains(&t)
    }

    #[test]
    fn a_wan_outage_stops_where_the_router_went_dark() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 60.0, router_out, |t| t < T || t >= T + 40.0);
        let wan = of_leg(rows(&r, "outage"), "wan");
        let local = of_leg(rows(&r, "outage"), "local");
        assert_eq!((wan.len(), local.len()), (1, 1));
        assert_eq!(wan[0].1, T as i64);
        assert!(wan[0].2.unwrap() <= (T + 10.0) as i64);
        assert!(wan[0].2.unwrap() <= local[0].1 + 1);
        assert!(charged(&r).0 <= 41);
    }

    #[test]
    fn a_wan_run_under_way_is_not_carried_into_the_router_outage() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 80.0, router_out, |t| t < T + 8.0 || t >= T + 60.0);
        let wan = of_leg(rows(&r, "outage"), "wan");
        assert_eq!(wan.len(), 1);
        assert_eq!(wan[0].1, (T + 40.0) as i64);
        assert!(wan[0].2.unwrap() <= (T + 61.0) as i64);
    }

    #[test]
    fn no_wan_disruption_is_made_of_the_router_outage() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 60.0, router_out, |t| t < T + 8.0 || t >= T + 40.0);
        assert!(of_leg(rows(&r, "disruption"), "wan").is_empty());
        assert!(of_leg(rows(&r, "outage"), "wan").is_empty());
    }

    #[test]
    fn a_redial_after_the_router_returns_is_not_blamed_on_the_isp() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 70.0, router_out, |t| t < T + 10.0 || t >= T + 55.0);
        assert_eq!(
            wan_rows(&r),
            [((T + 40.0) as i64, Some((T + 55.0) as i64), WanEventArbiter::NOT_BACK_DETAIL.to_string())]
        );
        let alarms = r.notices();
        assert!(alarms.iter().any(|a| a == "No internet yet"));
        assert!(!alarms.iter().any(|a| a == "No internet"));
    }

    #[test]
    fn a_short_redial_is_a_blip() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 60.0, router_out, |t| t < T + 10.0 || t >= T + 43.0);
        assert!(wan_rows(&r).is_empty());
        assert_eq!(
            of_leg(rows(&r, "disruption"), "wan"),
            [("wan".to_string(), (T + 40.0) as i64, Some((T + 43.0) as i64))]
        );
    }

    #[test]
    fn an_outage_after_the_internet_came_back_keeps_its_words() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 90.0, router_out, |t| {
            !((T + 10.0..T + 40.0).contains(&t) || (T + 60.0..T + 75.0).contains(&t))
        });
        let wan = wan_rows(&r);
        assert_eq!(wan.len(), 1);
        assert_eq!(wan[0].0, (T + 60.0) as i64);
        assert_eq!(wan[0].2, Wan::OUTAGE_DETAIL);
    }

    #[test]
    fn one_lost_gateway_ping_does_not_split_an_isp_outage() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 50.0, |t| t != T + 15.0, |t| !(T..T + 30.0).contains(&t));
        let wan = of_leg(rows(&r, "outage"), "wan");
        assert_eq!(wan.len(), 1);
        assert_eq!((wan[0].1, wan[0].2), (T as i64, Some((T + 30.0) as i64)));
    }

    // The reply that ended a wan blip is a seated sample; counted as an answer during it, it cancelled every blip.
    #[test]
    fn a_clean_internet_blip_is_stored_and_charged() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 30.0, |_| true, |t| !(T + 10.0..T + 13.0).contains(&t));
        assert_eq!(
            of_leg(rows(&r, "disruption"), "wan"),
            [("wan".to_string(), (T + 10.0) as i64, Some((T + 13.0) as i64))]
        );
        assert!(charged(&r).1 > 0);
    }
}

mod router_that_never_answers_pings {
    use super::*;

    const T: f64 = 3_000_000.0;

    fn run_legs(r: &mut Replay, until: f64, wan_ok: impl Fn(f64) -> bool) {
        let mut t = T - 20.0;
        while t <= until {
            r.local.add(t, (t < T).then_some(2.0), false);
            r.total.add(t, wan_ok(t).then_some(8.0), false);
            r.tick(t, 0.0);
            t += 0.5;
        }
    }

    fn local_rows(r: &Replay) -> Vec<(String, i64, Option<i64>)> {
        let mut events = r.events(1e7, T + 5000.0);
        events.sort_by_key(|e| int(e, "ts"));
        events
            .iter()
            .filter(|e| text(e, "leg") == "local")
            .map(|e| (text(e, "kind").to_string(), int(e, "ts").unwrap(), int(e, "ended_ts")))
            .collect()
    }

    fn kinds(r: &Replay) -> Vec<String> {
        local_rows(r).into_iter().map(|r| r.0).collect()
    }

    #[test]
    fn the_airport() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 1200.0, |t| t < T || t >= T + 40.0);
        let rows = local_rows(&r);
        assert_eq!(rows[0], ("outage".to_string(), T as i64, Some((T + 40.0) as i64)));
        assert_eq!((rows[1].0.as_str(), rows[1].1), ("gateway-quiet", (T + 40.0) as i64));
        assert_eq!(rows[1].2, None);
        assert!(!r.rig.d.local_events.real_outage());
        let (down, _, _) = r.rig.store().outage_stats(3600.0, Some(T + 1200.0), &[]).unwrap();
        assert_eq!(crate::util::py_round_int(down * 3600.0), 40);
    }

    #[test]
    fn silence_after_the_walk_back_is_an_outage_again() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 200.0, |t| t < T || (T + 40.0..T + 100.0).contains(&t) || t >= T + 120.0);
        assert_eq!(kinds(&r), ["outage", "gateway-quiet", "outage", "gateway-quiet"]);
        let rows = local_rows(&r);
        let (quiet, second) = (&rows[1], &rows[2]);
        assert_eq!(second.1, (T + 100.0) as i64);
        assert_eq!(quiet.2, Some((T + 100.0) as i64));
        assert_eq!(second.2, Some((T + 120.0) as i64));
    }

    #[test]
    fn a_confirmation_that_never_came_leaves_it_quiet() {
        let mut r = Replay::new(T);
        run_legs(&mut r, T + 200.0, |t| {
            t < T || (T + 40.0..T + 100.0).contains(&t) || t >= T + 100.0 + OUTAGE_AFTER_S - 1.0
        });
        assert_eq!(kinds(&r), ["outage", "gateway-quiet"]);
    }

    #[test]
    fn silence_onset_is_the_first_unanswered_sample() {
        let r = Replay::new(T);
        r.total.add(10.0, Some(8.0), false);
        r.total.add(10.5, None, false);
        r.total.add(11.0, None, false);
        r.rig.set_clock(16.0);
        assert_eq!(r.rig.d.beyond_silent_since(16.0), Some(10.5));
        let mut rig = Rig::at(16.0);
        let fresh = rig.single_instrument();
        fresh.add(12.0, None, false);
        assert_eq!(rig.d.beyond_silent_since(16.0), None);
    }
}

mod disruption_producer {
    use super::*;

    fn run_losses(n: u32, cadence: f64, t0: f64) -> LegWatch {
        let mut w = LegWatch::new();
        for i in 0..n {
            let t = t0 + i as f64 * cadence;
            w.sample(LegState::new(false, t, Some(t0), i + 1), t);
        }
        let t = t0 + n as f64 * cadence;
        w.sample(LegState::new(true, t, None, 0), t);
        w
    }

    #[test]
    fn recorded_closed_with_a_duration_and_charged() {
        let rig = Rig::new();
        let now = rig.now();
        let mut w = run_losses(4, 0.5, now);
        rig.d.record_disruption("local", w.blip.take(), Some(false)).unwrap();
        let evs = rig.events(now);
        assert_eq!(evs.iter().map(|e| text(e, "kind")).collect::<Vec<_>>(), ["disruption"]);
        assert!(int(&evs[0], "ended_ts").is_some());
        let (frac, count, disrupted) = rig.store().outage_stats(3600.0, Some(now + 10.0), &[]).unwrap();
        assert_eq!(count, 1);
        assert!(disrupted > 0.0);
        assert_eq!(frac, 0.0);
        assert!(score::reliability(frac, count, disrupted, 86400.0).unwrap() < 100.0);
    }

    #[test]
    fn arbitrated_like_an_outage() {
        let rig = Rig::new();
        let mut w = run_losses(4, 0.5, rig.now());
        rig.d.record_disruption("local", w.blip.take(), Some(true)).unwrap();
        assert!(rig.events(rig.now()).is_empty());
        assert_eq!(w.blip, None);
    }

    #[test]
    fn judged_on_the_run_itself_when_no_verdict_is_given() {
        let mut rig = Rig::new();
        let now = rig.now();
        let s = rig.single_instrument();
        s.add(now - 3.0, Some(8.0), false);
        rig.d.record_disruption("local", Some((now - 4.0, now - 2.0)), None).unwrap();
        assert!(rig.events(now).is_empty());
        rig.d.record_disruption("local", Some((now - 2.0, now - 1.0)), None).unwrap();
        assert_eq!(rig.events(now).len(), 1);
    }

    #[test]
    fn never_stored_with_a_zero_span() {
        let rig = Rig::new();
        let base = rig.now();
        rig.d.record_disruption("wan", Some((base + 0.4, base + 0.6)), Some(false)).unwrap();
        let e = &rig.events(base)[0];
        assert!(int(e, "ended_ts") > int(e, "ts"));
        let (_, count, disrupted) = rig.store().outage_stats(3600.0, Some(base + 10.0), &[]).unwrap();
        assert_eq!(count, 1);
        assert!(disrupted > 0.0);
    }

    #[test]
    fn a_disruption_through_a_tunnel_is_the_tunnel_s() {
        let mut rig = Rig::new();
        rig.d.vpn = Some(crate::testutil::obj(serde_json::json!({"iface": "wg0"})));
        rig.d.record_disruption("wan", Some((1000.0, 1002.0)), Some(false)).unwrap();
        let rows = rig.store().events(1e9, 100, Some(2000.0)).unwrap();
        assert_eq!(
            (text(&rows[0], "leg"), text(&rows[0], "detail")),
            ("tunnel", "Brief interruption through the VPN, recovered on its own")
        );
    }
}
