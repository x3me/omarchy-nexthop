use std::marker::PhantomData;
use std::sync::Arc;

use super::consts::NOTIFY_AFTER_S;
use super::events::{EventLog, Notify, StoreResult};

pub type Notice = (&'static str, &'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words {
    pub leg: &'static str,
    pub outage_detail: &'static str,
    pub alarm: Notice,
    pub recovered: Notice,
}

pub trait ArbiterKind {
    const LEG: &'static str;
    const QUIET_KIND: &'static str;
    const QUIET_DETAIL: &'static str;
    const OUTAGE_DETAIL: &'static str;
    const ALARM: Notice;
    const RECOVERED: Notice;

    fn words(_tunnel: bool, _after_router: bool) -> Words {
        Words { leg: Self::LEG, outage_detail: Self::OUTAGE_DETAIL, alarm: Self::ALARM, recovered: Self::RECOVERED }
    }
}

pub struct Wan;
pub struct Local;

pub type WanEventArbiter = LegArbiter<Wan>;
pub type LocalEventArbiter = LegArbiter<Local>;

impl ArbiterKind for Wan {
    const LEG: &'static str = "wan";
    const QUIET_KIND: &'static str = "icmp-quiet";
    const QUIET_DETAIL: &'static str = "Scored probes went quiet; another instrument on the same path kept answering";
    const OUTAGE_DETAIL: &'static str = "router answers, nothing past it does";
    const ALARM: Notice =
        ("No internet", "The router answers but nothing past it does \u{2014} the fault is on the ISP side.");
    const RECOVERED: Notice = ("Internet recovered", "Replies from the internet again.");

    fn words(tunnel: bool, after_router: bool) -> Words {
        if tunnel {
            return Words {
                leg: WanEventArbiter::TUNNEL_LEG,
                outage_detail: WanEventArbiter::TUNNEL_OUTAGE_DETAIL,
                alarm: WanEventArbiter::TUNNEL_ALARM,
                recovered: WanEventArbiter::TUNNEL_RECOVERED,
            };
        }
        if after_router {
            return Words {
                leg: Self::LEG,
                outage_detail: WanEventArbiter::NOT_BACK_DETAIL,
                alarm: WanEventArbiter::NOT_BACK_ALARM,
                recovered: Self::RECOVERED,
            };
        }
        Words { leg: Self::LEG, outage_detail: Self::OUTAGE_DETAIL, alarm: Self::ALARM, recovered: Self::RECOVERED }
    }
}

impl LegArbiter<Wan> {
    pub const NOT_BACK_DETAIL: &'static str = "internet not back yet after the router returned";
    pub const NOT_BACK_ALARM: Notice = ("No internet yet", "The router is back, but nothing past it answers yet.");
    pub const TUNNEL_LEG: &'static str = "tunnel";
    pub const TUNNEL_OUTAGE_DETAIL: &'static str = "VPN tunnel silent; the router answered";
    pub const TUNNEL_ALARM: Notice =
        ("No connection through the VPN", "The router answers; the tunnel or its server does not.");
    pub const TUNNEL_RECOVERED: Notice = ("VPN connection recovered", "Replies through the tunnel again.");
}

impl ArbiterKind for Local {
    const LEG: &'static str = "local";
    const QUIET_KIND: &'static str = "gateway-quiet";
    const QUIET_DETAIL: &'static str = "Router stopped answering pings; traffic through it kept working";
    const OUTAGE_DETAIL: &'static str = "router unreachable";
    const ALARM: Notice = ("Router unreachable", "Nothing on the local network is answering.");
    const RECOVERED: Notice = ("Local network recovered", "The router is answering again.");
}

pub struct LegArbiter<K: ArbiterKind> {
    store: Arc<dyn EventLog>,
    notify: Notify,
    pub event_id: Option<i64>,
    pub kind: Option<&'static str>,
    pub tunnel: bool,
    notify_at: Option<f64>,
    notified: bool,
    opened_at: Option<i64>,
    words: Words,
    _kind: PhantomData<K>,
}

impl<K: ArbiterKind> LegArbiter<K> {
    pub fn new(store: Arc<dyn EventLog>, notify: Notify) -> Self {
        Self {
            store,
            notify,
            event_id: None,
            kind: None,
            tunnel: false,
            notify_at: None,
            notified: false,
            opened_at: None,
            words: K::words(false, false),
            _kind: PhantomData,
        }
    }

    pub fn real_outage(&self) -> bool {
        self.kind == Some("outage")
    }

    pub fn leg(&self) -> &'static str {
        self.words.leg
    }

    pub fn words(&self, after_router: bool) -> Words {
        K::words(self.tunnel, after_router)
    }

    pub fn down(&mut self, now: f64, beyond_ok: bool, since: Option<f64>, after_router: bool) -> StoreResult<()> {
        let began = since.unwrap_or(now) as i64;
        self.opened_at = Some(began);
        self.words = self.words(after_router);
        if beyond_ok {
            self.kind = Some(K::QUIET_KIND);
            self.event_id =
                Some(self.store.open_event(began, K::QUIET_KIND, "warn", self.words.leg, K::QUIET_DETAIL)?);
            return Ok(());
        }
        self.kind = Some("outage");
        self.event_id =
            Some(self.store.open_event(began, "outage", "critical", self.words.leg, self.words.outage_detail)?);
        self.notify_at = Some(now + NOTIFY_AFTER_S);
        self.notified = false;
        Ok(())
    }

    pub fn tick(&mut self, now: f64, beyond_ok: bool, silent_since: Option<f64>) -> StoreResult<()> {
        if self.kind == Some(K::QUIET_KIND) && !beyond_ok {
            let onset = match silent_since {
                None => now,
                Some(s) => {
                    let opened = match self.opened_at {
                        Some(o) if o != 0 => o as f64,
                        _ => s,
                    };
                    now.min(s.max(opened))
                }
            };
            self.close_open(onset as i64)?;
            return self.down(now, false, Some(onset), false);
        }
        if self.real_outage() && beyond_ok {
            self.close_open(now as i64)?;
            if self.notified {
                let (summary, body) = self.words.recovered;
                (self.notify)(summary, body, false);
            }
            self.clear();
            return self.down(now, true, None, false);
        }
        if self.real_outage() && !self.notified && self.notify_at.is_some_and(|at| now >= at) {
            self.notified = true;
            let (summary, body) = self.words.alarm;
            (self.notify)(summary, body, true);
        }
        Ok(())
    }

    pub fn up(&mut self, now: f64) -> StoreResult<()> {
        if self.event_id.is_some() {
            self.close_open(now as i64)?;
            if self.real_outage() && self.notified {
                let (summary, body) = self.words.recovered;
                (self.notify)(summary, body, false);
            }
        }
        self.clear();
        Ok(())
    }

    pub fn lost_sight(&mut self, watched_until: f64) -> StoreResult<()> {
        self.close_open(watched_until as i64)?;
        self.clear();
        Ok(())
    }

    fn close_open(&self, at: i64) -> StoreResult<()> {
        match self.event_id {
            Some(eid) => self.store.close_event(eid, at, None),
            None => Ok(()),
        }
    }

    fn clear(&mut self) {
        self.event_id = None;
        self.kind = None;
        self.notify_at = None;
        self.notified = false;
    }
}

pub struct IntervalEvent {
    store: Arc<dyn EventLog>,
    pub kind: &'static str,
    pub severity: &'static str,
    pub leg: &'static str,
    pub event_id: Option<i64>,
    pub detail: Option<String>,
}

impl IntervalEvent {
    pub fn new(store: Arc<dyn EventLog>, kind: &'static str, severity: &'static str, leg: &'static str) -> Self {
        Self { store, kind, severity, leg, event_id: None, detail: None }
    }

    pub fn update(&mut self, now: f64, detail: Option<&str>) -> StoreResult<bool> {
        if detail == self.detail.as_deref() {
            return Ok(false);
        }
        if let Some(eid) = self.event_id.take() {
            self.store.close_event(eid, now as i64, None)?;
        }
        if let Some(d) = detail.filter(|d| !d.is_empty()) {
            self.event_id = Some(self.store.open_event(now as i64, self.kind, self.severity, self.leg, d)?);
        }
        self.detail = detail.map(str::to_string);
        Ok(true)
    }

    pub fn lost_sight(&mut self, watched_until: f64) -> StoreResult<()> {
        if let Some(eid) = self.event_id.take() {
            self.store.close_event(eid, watched_until as i64, None)?;
        }
        self.detail = None;
        Ok(())
    }
}
