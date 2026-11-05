use std::sync::Arc;

use super::consts::{LEG_STREAM_WINDOW_S, OUTAGE_AFTER_S, RESUME_SETTLE_S, UNWATCHED_AFTER_S};
use super::core::Daemon;
use super::events::StoreResult;
use super::legs::{LegMove, leg_state};
use super::lookup::OutcomeSource;
use crate::probes::NameLookup;
use crate::score;
use crate::util::{awake_clock, py_sum};

impl Daemon {
    pub fn watch_outages(&mut self, now: f64, awake: Option<f64>) -> StoreResult<()> {
        let awake = awake.unwrap_or_else(awake_clock);
        if let Some((watched_wall, watched_awake)) = self.watched
            && awake - watched_awake > UNWATCHED_AFTER_S
        {
            let watched_until = watched_wall;
            self.watch_local.lost_sight(now, RESUME_SETTLE_S);
            self.local_events.lost_sight(watched_until)?;
            self.watch_wan.lost_sight(now, RESUME_SETTLE_S);
            self.wan_events.lost_sight(watched_until)?;
            self.lose_sight_of_path_states(watched_until)?;
            self.lookup_watch.lost_sight(watched_until, now)?;
            self.watching_since = now;
        }
        self.watched = Some((now, awake));

        let at = self.now();
        let local = leg_state(&self.local.since_at(LEG_STREAM_WINDOW_S, at), now);
        let total = leg_state(&self.total.since_at(LEG_STREAM_WINDOW_S, at), now);
        let local_ok = local.map(|l| l.ok);

        if let Some(local) = local {
            match self.watch_local.sample(local, now) {
                Some(LegMove::Down) => {
                    let since = self.watch_local.down_since;
                    let beyond_ok = self.any_instrument_replied_between(since.unwrap_or(now), now);
                    self.local_events.down(now, beyond_ok, since, false)?;
                }
                Some(LegMove::Up) => self.local_events.up(now)?,
                Some(LegMove::Disruption) => {
                    let blip = self.watch_local.blip.take();
                    self.record_disruption("local", blip, None)?;
                }
                None if self.watch_local.down_since.is_some() => {
                    let (beyond_ok, silent_since) = self.escalation(now);
                    self.local_events.tick(now, beyond_ok, silent_since)?;
                }
                None => {}
            }
        }

        let local_down = self.watch_local.down_since.is_some();
        let gateway_quiet = local_down && !self.local_events.real_outage();
        let router_dark = local_down && self.local_events.real_outage();
        if router_dark && !self.wan_unwatched {
            self.wan_unwatched = true;
            self.wan_events.lost_sight(self.wan_sampled_at.unwrap_or(now))?;
            self.watch_wan.lost_sight(now, RESUME_SETTLE_S);
        }
        let Some(total) = total else {
            return Ok(());
        };
        if local_ok == Some(false) && !gateway_quiet {
            return Ok(());
        }
        if self.wan_unwatched {
            self.wan_unwatched = false;
            self.wan_resumed_at = Some(now);
            self.watch_wan.lost_sight(now, 0.0);
        }
        self.wan_sampled_at = Some(now);
        match self.watch_wan.sample(total, now) {
            Some(LegMove::Down) => {
                let since = self.watch_wan.down_since;
                let beyond_ok = self.any_instrument_replied_between(since.unwrap_or(now), now);
                let after_router = since == self.wan_resumed_at;
                self.wan_events.down(now, beyond_ok, since, after_router)?;
            }
            Some(LegMove::Up) => {
                self.wan_events.up(now)?;
                self.captive.request();
            }
            Some(LegMove::Disruption) => {
                let blip = self.watch_wan.blip.take();
                self.record_disruption("wan", blip, None)?;
            }
            None if self.watch_wan.down_since.is_some() => {
                let (beyond_ok, silent_since) = self.escalation(now);
                self.wan_events.tick(now, beyond_ok, silent_since)?;
            }
            None => {}
        }
        Ok(())
    }

    pub fn record_disruption(&self, leg: &str, blip: Option<(f64, f64)>, beyond_ok: Option<bool>) -> StoreResult<()> {
        let Some((began, ended)) = blip else {
            return Ok(());
        };
        let beyond_ok = beyond_ok.unwrap_or_else(|| self.any_instrument_replied_between(began, ended));
        if beyond_ok {
            return Ok(());
        }
        let (leg, detail) = if leg == "wan" && self.vpn.is_some() {
            ("tunnel", "Brief interruption through the VPN, recovered on its own")
        } else {
            (leg, "brief interruption, recovered on its own")
        };
        let eid = self.store.open_event(began as i64, "disruption", "warn", leg, detail)?;
        self.store.close_event(eid, (ended as i64).max(began as i64 + 1), None)
    }

    pub fn named_lookups(&self) -> Vec<Arc<NameLookup>> {
        self.instrument_probes()
            .iter()
            .filter_map(|(_, p)| p.tcp())
            .filter(|p| !p.lookup.literal)
            .map(|p| Arc::clone(&p.lookup))
            .collect()
    }

    pub fn follow_lookups(&mut self, now: f64) -> StoreResult<()> {
        let lookups: Vec<Arc<dyn OutcomeSource>> =
            self.named_lookups().into_iter().map(|l| l as Arc<dyn OutcomeSource>).collect();
        let legs_down = (self.watch_local.down_since.is_some() && self.local_events.real_outage())
            || (self.watch_wan.down_since.is_some() && self.wan_events.real_outage());
        let answering = self.any_instrument_alive(OUTAGE_AFTER_S);
        self.lookup_watch.feed(now, &lookups, answering, legs_down)
    }

    pub fn any_instrument_alive(&self, window_s: f64) -> bool {
        let at = self.now();
        self.instrument_series.iter().any(|(_, s)| s.since_at(window_s, at).iter().any(|smp| smp.rtt.is_some()))
    }

    pub fn beyond_silent_since(&self, now: f64) -> Option<f64> {
        let at = self.now();
        let streams: Vec<_> = self.instrument_series.iter().map(|(_, s)| s.since_at(LEG_STREAM_WINDOW_S, at)).collect();
        let newest = streams.iter().flatten().filter(|s| s.rtt.is_some()).map(|s| s.t).reduce(f64::max)?;
        let first = streams.iter().flatten().filter(|s| s.rtt.is_none() && s.t > newest).map(|s| s.t).reduce(f64::min);
        first.filter(|f| *f <= now)
    }

    pub fn escalation(&self, now: f64) -> (bool, Option<f64>) {
        let alive = self.any_instrument_alive(OUTAGE_AFTER_S);
        (alive, if alive { None } else { self.beyond_silent_since(now) })
    }

    pub fn any_instrument_replied_between(&self, a: f64, b: f64) -> bool {
        let at = self.now();
        let span = (at - a).max(0.0) + 1.0;
        self.instrument_series
            .iter()
            .any(|(_, s)| s.since_at(span, at).iter().any(|smp| smp.rtt.is_some() && a <= smp.t && smp.t < b))
    }

    pub fn reliability(&self, now: f64) -> StoreResult<(Option<f64>, f64)> {
        let window = score::RELIABILITY_WINDOW_S as f64;
        let gaps = self.store.unwatched(window, Some(now))?;
        let watched = window - py_sum(gaps.iter().map(|(a, b)| b - a));
        let (out_frac, disruptions, disrupt_frac) = self.store.outage_stats(window, Some(now), &gaps)?;
        Ok((score::reliability(out_frac, disruptions, disrupt_frac, watched), watched))
    }

    pub fn connection_state(&self, idx: Option<i64>) -> &'static str {
        if self.captive.confirmed() {
            "captive"
        } else if self.watch_local.down_since.is_some() && self.local_events.real_outage() {
            "local-down"
        } else if self.watch_wan.down_since.is_some() && self.wan_events.real_outage() {
            if self.wan_events.leg() == "tunnel" { "tunnel-down" } else { "wan-down" }
        } else if self.lookup_watch.failing() {
            "dns-failing"
        } else if idx.is_some_and(|i| i < 70) {
            "degraded"
        } else {
            "online"
        }
    }
}
