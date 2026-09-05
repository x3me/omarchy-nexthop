"""The nexthopd main loop.

Owns the probes, folds their samples into live.json / recent.json /
history.db, detects outages, and runs the scheduled content check. The QML
side never talks to this process — the files are the whole contract, so
either side can restart without the other noticing.
"""

import fcntl
import json
import os
import re
import shutil
import signal
import stat as stat_module
import subprocess
import sys
import threading
import time
from collections import deque

from . import __version__, apps, linkevents, net, score, speedtest
from .paths import (ensure_state_dir, live_path, recent_path, db_path,
                    lock_path, state_dir)
from .instruments import Bench, MergedSeries
from .probes import Series, PingProbe, TcpProbe
from .state import write_atomic
from .store import Store
from .update import UpdateWatch

# Consecutive losses on a leg before we call it down. At 500 ms per probe,
# eight of them is four seconds — long enough to skip a Wi-Fi roam, short
# enough that the notification still feels immediate.
OUTAGE_AFTER_LOSSES = 8
# A run of losses shorter than an outage but longer than noise: an
# interruption the user may well have felt — a call breaking up, a stream
# rebuffering — that used to leave no trace at all and cost Reliability
# nothing, because only runs reaching OUTAGE_AFTER_LOSSES were ever
# recorded.
#
# CAUTION, and the comment first written here got this wrong: a "loss" is
# NOT a lost probe. `watch_outages` runs every 0.5 s but asks whether any
# probe replied in the last 3 s, so one loss already means ~3 s of unbroken
# silence, three mean ~4.0 s and eight mean ~6.5 s. The band this threshold
# opens is therefore only ~4.0-6.5 s wide, and an interruption shorter than
# 3 s registers nothing at all — which is most of the blips it was meant to
# catch. Lowering this number cannot help; the fix is to count losses from
# the probe stream instead of from a rolling any-reply window, and that
# touches the outage path so it wants its own change.
DISRUPTION_AFTER_LOSSES = 3

# Probes needed on each side of the idle/loaded split before their ratio is
# reported. Below this the comparison is sampling noise.
MIN_LOAD_SPLIT_SAMPLES = 10
# Queueing can only ADD delay, so a loaded/idle ratio below 1 says the link
# answered faster while busy, which is not a measurement. The sample floor
# above does not catch it: 0.87 was published live on 716 samples per side.
# Within a few percent of 1 the two populations are simply indistinguishable
# and the honest reading is "no inflation"; further below, the split itself
# is untrustworthy — the loaded samples likely landed in a quiet moment — so
# withhold rather than report. A plausibility floor, distinct from a sample
# floor, and the guard the socket metric already has.
MIN_PLAUSIBLE_INFLATION = 0.95

# The application-path probe: a TCP handshake to the anchor's TLS port,
# once a second. Slower than the ICMP cadence on purpose — this exists to
# characterise the gap against ICMP, not to detect outages, and it opens a
# real connection to someone else's server every time it runs.
TCP_PROBE_INTERVAL_S = 1.0
TCP_PROBE_PORT = 443
# The rest of the instrument pool (see instruments.py). Cloudflare edge
# is a host the daemon already fetches from; dns.google is the one
# probe target outside Cloudflare, so a Cloudflare incident cannot
# silence the whole pool. TCP handshakes only — no payload.
CF_EDGE_HOST = "speed.cloudflare.com"
DIVERSITY_HOST = "dns.google"
# A benched instrument idles at a tenth of its seated cadence: enough
# to stay rankable, cheap enough to keep around.
STANDBY_FACTOR = 10.0
BENCH_EVAL_EVERY_S = 60.0

# One real HTTP/3 request every five minutes, as ground truth for what a
# request actually costs end to end. A HEAD request returns no body at all,
# so the sample costs only the handshake — a few KB, about 1 MB a day
# against the ~11 MB a day the continuous probing already spends.
H3_SAMPLE_INTERVAL_S = 300.0
# How often to re-ask which address this connection appears from.
WAN_IP_REFRESH_S = 3600.0
H3_TIMEOUT_S = 10.0

# TLS needs a name the certificate covers, and a bare IP has none. These
# map the well-known anchor addresses to the name that serves the SAME
# host — one.one.one.one *is* 1.1.1.1 — so the request measures the path
# everything else measures, not some other operator's. An anchor we have
# no name for is skipped rather than quietly redirected elsewhere.
H3_HOSTS = {
    "1.1.1.1": "one.one.one.one", "1.0.0.1": "one.one.one.one",
    "8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
    "9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net",
}


def h3_target(anchor: str):
    """The hostname to request, for an anchor — or None if there isn't one."""
    if anchor in H3_HOSTS:
        return H3_HOSTS[anchor]
    # A hostname anchor already validates; a bare address never will.
    return anchor if any(c.isalpha() for c in anchor) else None


def proc_start_ticks(pid):
    """The process start time in clock ticks, from /proc/<pid>/stat.

    Together with the pid it forms a start identity: pids are recycled,
    but a recycled pid never reproduces the same start time. The shell
    service checks this before it will signal anything.
    """
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read(4096)
        # Field 22, counted after the parenthesised comm (which may itself
        # contain spaces and parentheses).
        rest = data[data.rindex(b")") + 2:].split()
        return int(rest[19])
    except (OSError, ValueError, IndexError):
        return None
# An interruption that self-heals in under this is recorded but not
# notified. The constant was written with 0.1.0 and never read: outages
# alarmed the instant they were declared, so a four-second blip on a flaky
# link fired a desktop notification the user could do nothing about. The
# event is always logged; only the interruption goes quiet.
NOTIFY_AFTER_S = 5.0


class Config:
    """Settings, read from the file the QML side writes.

    Every value is validated against the same ranges the manifest schema
    promises, and the file itself has a size cap — a config the daemon
    cannot trust in full is a config it ignores in full. Nothing read
    here can grow retained state beyond its documented bounds.
    """

    MAX_BYTES = 64 * 1024
    # key -> (default, validator). Ranges mirror manifest.json's schema.
    ANCHOR_RE = re.compile(r"^[A-Za-z0-9.:\-]{1,253}$")

    @staticmethod
    def _int(lo, hi):
        def check(v):
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                return None
            n = int(v)
            return n if lo <= n <= hi else None
        return check

    @staticmethod
    def _bool(v):
        return v if isinstance(v, bool) else None

    SCHEMA = {
        "internetAnchor": ("1.1.1.1",
                           lambda v: v if isinstance(v, str)
                           and Config.ANCHOR_RE.match(v) else None),
        "probeIntervalMs": (500, None),          # filled below
        "contentSpeed": (True, None),
        "contentSpeedIntervalMin": (60, None),
        "peakEngine": ("Auto",
                       lambda v: v if v in ("Auto", "Ookla", "Cloudflare",
                                            "fast.com") else None),
        "planDownMbps": (0, None),
        "planUpMbps": (0, None),
        "notifyOutage": (True, None),
        "updateCheck": (True, None),
        "historyDays": (7, None),
        "throughputWindowS": (3, None),
    }

    DEFAULTS = {k: v[0] for k, v in SCHEMA.items()}

    def __init__(self, state_dir):
        self.path = state_dir / "config.json"
        self.values = dict(self.DEFAULTS)
        self._mtime = 0

    def refresh(self):
        # Everything is checked on the file descriptor actually read — a
        # stat followed by a separate open is a race an attacker wins by
        # swapping the file in between. O_NOFOLLOW refuses symlinks, fstat
        # types and dates the very fd we read, and the size bound is
        # enforced by the bounded read itself, not by a prior check.
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return
        try:
            st = os.fstat(fd)
            if not stat_module.S_ISREG(st.st_mode):
                return
            if st.st_mtime == self._mtime:
                return
            self._mtime = st.st_mtime
            chunks = []
            remaining = self.MAX_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        except OSError:
            return
        finally:
            os.close(fd)
        if len(data) > self.MAX_BYTES:
            return
        try:
            loaded = json.loads(data)
        except ValueError:
            return
        if not isinstance(loaded, dict):
            return
        merged = dict(self.DEFAULTS)
        for key, (default, validate) in self.SCHEMA.items():
            if key not in loaded or loaded[key] is None:
                continue
            checked = validate(loaded[key]) if validate else None
            if checked is not None:
                merged[key] = checked
        self.values = merged

    def __getitem__(self, key):
        return self.values[key]


# Range validators mirror the manifest schema exactly; a value outside its
# documented range is discarded, never clamped — silence over surprise.
Config.SCHEMA["probeIntervalMs"] = (500, Config._int(250, 5000))
Config.SCHEMA["contentSpeed"] = (True, Config._bool)
Config.SCHEMA["contentSpeedIntervalMin"] = (60, Config._int(15, 1440))
Config.SCHEMA["planDownMbps"] = (0, Config._int(0, 10000))
Config.SCHEMA["planUpMbps"] = (0, Config._int(0, 10000))
Config.SCHEMA["notifyOutage"] = (True, Config._bool)
Config.SCHEMA["updateCheck"] = (True, Config._bool)
Config.SCHEMA["historyDays"] = (7, Config._int(1, 90))
Config.SCHEMA["throughputWindowS"] = (3, Config._int(1, 30))


class LinkWatch:
    """Watches the Wi-Fi link state and writes events worth remembering:
    roams, kicks, drops, associations, sustained rate drops. Instant events
    are stored closed; a rate drop stays open until the rate recovers, so
    its row carries a duration.

    A BSSID change is attributed when `events` (an NlEvents) knows who
    ended the previous association: the AP (a kick, with its 802.11
    reason), this machine with the next authentication already under way
    (a roam), or this machine after a scan (a drop — the link was lost).
    Without that knowledge every change is a roam, as it always was.
    """

    # A drop only counts when the rate stays below this fraction of the
    # recent ceiling for a sustained stretch — rate control flaps all the
    # time and a log that records every flap teaches people to ignore it.
    LOW_FRACTION = 0.4
    RECOVER_FRACTION = 0.6
    SUSTAIN_S = 10.0
    # Rate drops are only meaningful under traffic: Wi-Fi power save
    # renegotiates a low bitrate the moment the link idles, and logging
    # that teaches people to ignore the log. Below this many bytes/sec of
    # combined throughput the link counts as idle.
    TRAFFIC_FLOOR_BPS = 25_000
    # Consecutive empty link reads before the link counts as genuinely
    # gone. A single failed `iw` call is a hiccup, not a disassociation —
    # and its recovery must not be logged as a fresh association.
    GAP_SAMPLES = 5
    # A local deauth followed by a new authentication within this long is
    # the client roaming: mac80211 emits that deauth from inside the call
    # that starts the new authentication, so a roam's gap is milliseconds.
    # A lost link is followed by a scan first, and its gap is seconds. The
    # threshold sits between the two by orders of magnitude.
    ROAM_FOLLOW_S = 1.0

    def __init__(self, store, events=None):
        self.store = store
        self.events = events      # NlEvents, or anything with cause_for()
        self.prev = None          # last non-empty link, None until first seen
        self.last_link_t = None   # when the link was last seen up
        self.gap_count = 0
        self.disassociated = False
        self.rate_ceiling = 0.0
        self.low_since = None
        self.low_floor = None
        self.rate_event_id = None
        self.last_sample = 0.0

    def _instant(self, ts, kind, detail):
        eid = self.store.open_event(int(ts), kind, "info", "local", detail)
        self.store.close_event(eid, int(ts))

    def _cause(self, bssid, since, now):
        """Who ended our association with `bssid`, if anything was seen
        since we last saw that link up."""
        if not self.events or not bssid or since is None:
            return None
        try:
            return self.events.cause_for(bssid, now, now - since + 2.0)
        except Exception:
            return None       # an attribution failure must not cost the event

    def _blame(self, cause, old, new, gap_s=None):
        """(kind, text) for a change away from `old` with a known cause.

        gap_s is how long the link was down when that is known (a confirmed
        gap); otherwise the deauth-to-reauth delay stands in for it.
        """
        why = linkevents.reason_text(cause["reason"], cause["by_ap"])
        follow = cause.get("gap_s")
        if cause["by_ap"]:
            kind, lead = "kick", "Kicked by AP %s (%s)" % (old, why)
        elif gap_s is None and follow is not None and follow < self.ROAM_FOLLOW_S:
            return "roam", "Roamed to " + new
        else:
            kind, lead = "drop", "Dropped by this machine (%s)" % why
        down = gap_s if gap_s is not None else follow
        text = lead + ", rejoined" + ("" if new == old else " via " + new)
        if down is not None and down >= 0.5:
            text += " after " + _short_duration(down)
        return kind, text

    def sample(self, now, link, traffic_bps=0.0):
        # The caller runs twice a second; once a second is plenty here.
        if now - self.last_sample < 1.0:
            return
        self.last_sample = now

        if not link or not link.get("bssid"):
            # An empty read is a hiccup until it persists: `iw` times out
            # now and then, and treating each blink as a disassociation
            # spammed the log with fake re-associations.
            self.gap_count += 1
            if self.gap_count == self.GAP_SAMPLES:
                self.disassociated = True
                self._close_rate_event(now)
                self.rate_ceiling = 0.0
            return
        self.gap_count = 0

        since, self.last_link_t = self.last_link_t, now
        prev, self.prev = self.prev, dict(link)
        bssid = link.get("bssid", "")
        prev_bssid = prev.get("bssid", "") if prev else ""
        ssid = link.get("ssid", "")

        if prev is None:
            # The daemon's first sighting of an existing link is not an
            # association — logging it stamped every daemon restart into
            # the event log.
            self.disassociated = False
            return

        if self.disassociated:
            self.disassociated = False
            cause = self._cause(prev_bssid, since, now)
            if cause:
                # One row for the whole incident: who ended it, how long it
                # took to come back, and where. The plain association is
                # for gaps nobody claimed — suspend, or no `iw event`.
                kind, text = self._blame(cause, prev_bssid, bssid, gap_s=now - since)
                self._instant(now, kind, text)
            else:
                self._instant(now, "associate", "Associated with " + (ssid or bssid))
        elif bssid and prev_bssid and bssid != prev_bssid:
            cause = self._cause(prev_bssid, since, now)
            kind, lead = self._blame(cause, prev_bssid, bssid) if cause \
                else ("roam", "Roamed to " + bssid)
            parts = [lead]
            if prev.get("channel") and link.get("channel") \
                    and prev["channel"] != link["channel"]:
                parts.append("channel %s \u2192 %s" % (prev["channel"], link["channel"]))
            if prev.get("signal_dbm") is not None and link.get("signal_dbm") is not None:
                parts.append("%s \u2192 %s dBm" % (prev["signal_dbm"], link["signal_dbm"]))
            self._instant(now, kind, ", ".join(parts))
            # A different AP has a different honest ceiling.
            self.rate_ceiling = 0.0
            self._close_rate_event(now)
        elif bssid == prev_bssid and prev.get("channel") and link.get("channel") \
                and prev["channel"] != link["channel"]:
            self._instant(now, "channel-change",
                          "Channel changed %s \u2192 %s on the same AP"
                          % (prev["channel"], link["channel"]))

        tx = link.get("tx_mbps")
        if tx is None or tx <= 0:
            return
        if (traffic_bps or 0) < self.TRAFFIC_FLOOR_BPS:
            # Idle link: whatever bitrate power save negotiated is
            # unobservable to the user. Freeze the tracker — and close an
            # open drop event, since its duration would otherwise count
            # idle time as suffering.
            self._close_rate_event(now)
            return
        # A slowly decaying ceiling: the best rate seen lately, with a
        # half-life of a few minutes so an old burst does not set the bar
        # forever. Only rates seen under traffic feed it.
        self.rate_ceiling = max(tx, self.rate_ceiling * 0.998)
        if self.rate_ceiling < 100:
            return  # too slow a link for a drop to mean anything
        if tx < self.rate_ceiling * self.LOW_FRACTION:
            self.low_floor = tx if self.low_floor is None else min(self.low_floor, tx)
            if self.low_since is None:
                self.low_since = now
            elif self.rate_event_id is None and now - self.low_since >= self.SUSTAIN_S:
                self.rate_event_id = self.store.open_event(
                    int(self.low_since), "rate-drop", "info", "local",
                    "Tx rate dropped to %d Mbps" % round(self.low_floor))
        elif tx >= self.rate_ceiling * self.RECOVER_FRACTION:
            self._close_rate_event(now)

    def _close_rate_event(self, now):
        if self.rate_event_id is not None:
            detail = "Tx rate dropped to %d Mbps" % round(self.low_floor or 0)
            self.store.close_event(self.rate_event_id, int(now), detail)
            self.rate_event_id = None
        self.low_since = None
        self.low_floor = None


def _short_duration(seconds):
    s = int(round(seconds))
    if s < 60:
        return "%d s" % max(1, s)
    if s < 3600:
        return "%d min" % (s // 60)
    return "%d h %d min" % (s // 3600, (s % 3600) // 60)


class LegWatch:
    """Outage state for one leg: counts consecutive losses, opens and
    closes events, and remembers what to say when it recovers."""

    def __init__(self, leg: str):
        self.leg = leg
        self.losses = 0
        self.down_since = None
        self.event_id = None
        self.run_since = None      # when the current run of losses began
        self.blip = None           # (from, to) of a run that just recovered

    def sample(self, ok: bool, now: float):
        """Returns 'down' / 'up' / 'disruption' on a transition, else None.

        `disruption` is a run that recovered before reaching the outage
        threshold. It is reported at recovery rather than at onset because
        that is the first moment its length is known, and its length is what
        Reliability charges.
        """
        if ok:
            run, began = self.losses, self.run_since
            self.losses = 0
            self.run_since = None
            if self.down_since is not None:
                self.down_since = None
                return "up"
            if run >= DISRUPTION_AFTER_LOSSES and began is not None:
                self.blip = (began, now)
                return "disruption"
            return None
        if self.losses == 0:
            self.run_since = now
        self.losses += 1
        if self.losses == OUTAGE_AFTER_LOSSES and self.down_since is None:
            self.down_since = now
            return "down"
        return None


class WanEventArbiter:
    """What a wan-leg "down" means, given the second probe's testimony.

    Eight lost pings say the anchor went quiet; only both probes failing
    say the internet did. An ISP or middlebox that stops answering ICMP
    while TCP still flows used to be recorded — notified, and charged to
    Reliability — as an outage the user never experienced.

    A down with the TCP probe still answering opens an `icmp-quiet` event
    instead: in the log, excluded from outage_stats, no notification.
    Escalation is one-way — if TCP stops answering during a quiet spell,
    the quiet event closes and a real outage opens, because an outage that
    begins mid-spell must still alarm. Nothing downgrades the other way:
    flapping between verdicts would teach people to ignore both.
    """

    QUIET_DETAIL = ("Scored probes went quiet; another instrument on "
                    "the same path kept answering")

    def __init__(self, store, notify):
        self.store = store
        self.notify = notify
        self.event_id = None
        self.kind = None          # "outage" | "icmp-quiet" while down
        self._notify_at = None    # when the alarm becomes due
        self._notified = False    # whether it actually fired

    @property
    def real_outage(self) -> bool:
        return self.kind == "outage"

    def down(self, now, app_ok: bool):
        if app_ok:
            self.kind = "icmp-quiet"
            self.event_id = self.store.open_event(
                int(now), "icmp-quiet", "warn", "wan", self.QUIET_DETAIL)
            return
        self.kind = "outage"
        self.event_id = self.store.open_event(
            int(now), "outage", "critical", "wan",
            "router answers, nothing past it does")
        # Logged now, alarmed only if it lasts — see NOTIFY_AFTER_S.
        self._notify_at = now + NOTIFY_AFTER_S
        self._notified = False

    def tick(self, now, app_ok: bool):
        if self.kind == "icmp-quiet" and not app_ok:
            self.store.close_event(self.event_id, int(now))
            self.down(now, False)
            return
        if (self.kind == "outage" and not self._notified
                and self._notify_at is not None and now >= self._notify_at):
            self._notified = True
            self.notify("No internet",
                        "The router answers but nothing past it does — "
                        "the fault is on the ISP side.", True)

    def up(self, now):
        if self.event_id is not None:
            self.store.close_event(self.event_id, int(now))
            # Only say it came back if we said it went away.
            if self.kind == "outage" and self._notified:
                self.notify("Internet recovered",
                            "Replies from the internet again.")
        self.event_id = None
        self.kind = None
        self._notify_at = None
        self._notified = False


class CaptiveWatch:
    """Are we behind a sign-in page rather than on the internet?

    A probe reply proves a packet came back; it does not prove what sent it.
    So this asks for two things at once and only claims interception when it
    has both: something IS answering our probes, and the content check
    cannot prove the real internet answered. Packets going somewhere, but
    not to the internet, is what a captive portal looks like from here.

    Neither half is enough alone. Probes answering with no content check is
    the state we were in before, and it read as a healthy internet. A failed
    content check with nothing answering is simply no internet, which the
    wan arbiter already handles — calling that "captive" would put a sign-in
    prompt in front of a user whose line is down.

    Confirmation takes two consecutive checks, because one failed fetch is a
    failed fetch. The decision itself is pure so it can be argued with and
    tested; only the fetching is not.
    """

    # A suspicion is worth re-checking soon, but not on the 2 Hz loop.
    CHECK_EVERY_S = 30.0
    CONFIRM_AFTER = 2

    def __init__(self, check):
        self._check = check        # injected: () -> {"verdict", "proof"}
        self.verdict = "unknown"
        self.proof = None
        self.checked_ts = None
        self.strikes = 0
        self._next = 0.0

    @staticmethod
    def captive(verdict: str, probes_answering: bool, strikes: int) -> bool:
        """The whole claim, in one place: replies but no proof of internet."""
        return (probes_answering
                and verdict in ("intercepted", "silent")
                and strikes >= CaptiveWatch.CONFIRM_AFTER)

    @property
    def confirmed(self) -> bool:
        return self._confirmed

    _confirmed = False

    def tick(self, now: float, probes_answering: bool):
        if not probes_answering:
            # Nothing is answering at all: not our verdict to make. Drop the
            # suspicion rather than carrying it into a real outage.
            self.strikes = 0
            self._confirmed = False
            return
        if now < self._next:
            self._confirmed = self.captive(
                self.verdict, probes_answering, self.strikes)
            return
        self._next = now + self.CHECK_EVERY_S
        result = self._check() or {"verdict": "silent", "proof": None}
        self.verdict = result.get("verdict") or "silent"
        self.proof = result.get("proof")
        if self.verdict == "open":
            self.strikes = 0
        else:
            self.strikes += 1
        self.checked_ts = round(now)
        self._confirmed = self.captive(
            self.verdict, probes_answering, self.strikes)

    def snapshot(self) -> dict:
        if self.verdict == "unknown":
            return None
        return {"verdict": self.verdict, "captive": self._confirmed,
                "checked_ts": self.checked_ts}


class LocalEventArbiter:
    """What a local "down" means, given that packets may still be crossing.

    The gateway going silent is not the gateway being unreachable. Plenty of
    networks — hotel and captive ones especially — rate-limit or simply drop
    ICMP addressed to the router while forwarding everything through it. On
    such a link every local ping is lost and the panel used to say ROUTER
    UNREACHABLE, notify, and charge Reliability, while the machine was
    online the whole time.

    The evidence that settles it is already in hand: if anything past the
    gateway is answering, packets are crossing the gateway, so it cannot be
    unreachable. That opens a `gateway-quiet` event instead — logged,
    warn-toned, excluded from outage_stats, no notification, and the bar
    stays its ordinary colour.

    This is 0.1.17's wan arbitration applied to the leg it was never applied
    to. Escalation is one-way for the same reason: if the far side goes quiet
    too during a quiet spell, this closes and a real local outage opens,
    because an outage that begins mid-spell must still alarm.
    """

    QUIET_DETAIL = ("Router stopped answering pings; traffic through it "
                    "kept working")

    def __init__(self, store, notify):
        self.store = store
        self.notify = notify
        self.event_id = None
        self.kind = None          # "outage" | "gateway-quiet" while down
        self._notify_at = None    # when the alarm becomes due
        self._notified = False    # whether it actually fired

    @property
    def real_outage(self) -> bool:
        return self.kind == "outage"

    def down(self, now, beyond_ok: bool):
        if beyond_ok:
            self.kind = "gateway-quiet"
            self.event_id = self.store.open_event(
                int(now), "gateway-quiet", "warn", "local", self.QUIET_DETAIL)
            return
        self.kind = "outage"
        self.event_id = self.store.open_event(
            int(now), "outage", "critical", "local", "router unreachable")
        # Logged now, alarmed only if it lasts — see NOTIFY_AFTER_S.
        self._notify_at = now + NOTIFY_AFTER_S
        self._notified = False

    def tick(self, now, beyond_ok: bool):
        if self.kind == "gateway-quiet" and not beyond_ok:
            self.store.close_event(self.event_id, int(now))
            self.down(now, False)
            return
        if (self.kind == "outage" and not self._notified
                and self._notify_at is not None and now >= self._notify_at):
            self._notified = True
            self.notify("Router unreachable",
                        "Nothing on the local network is answering.", True)

    def up(self, now):
        if self.event_id is not None:
            self.store.close_event(self.event_id, int(now))
            # Only say it came back if we said it went away. A recovery
            # notice with no matching alarm is a message about nothing.
            if self.kind == "outage" and self._notified:
                self.notify("Local network recovered",
                            "The router is answering again.")
        self.event_id = None
        self.kind = None
        self._notify_at = None
        self._notified = False


class Daemon:
    def __init__(self):
        self.state_dir = ensure_state_dir()
        self.config = Config(self.state_dir)
        self.config.refresh()
        self.store = Store(db_path())
        self.local = Series()
        # The internet leg is measured by a bench of instruments — see
        # instruments.py. Each instrument feeds its own Series; the scored
        # series (self.total) is a merged view over whichever two hold the
        # seats, so every consumer downstream keeps reading one "internet
        # leg". self.app stays the anchor's TCP series: its gap against
        # the anchor's ICMP series is the protocol comparison it always was.
        self.bench = Bench(self._instrument_pool())
        self._instrument_series = {}
        self._instrument_probes = {}
        self._new_instrument_series()
        self.total = MergedSeries(self._active_series)
        self._last_bench_eval = 0.0
        self.app_request = None          # last HTTP/3 request sample
        self._curl_h3 = None             # cached curl capability
        self.last_app_request = 0.0
        self.probes = []
        self.running = True
        self.route = {}
        # Sliding window of (t, rx, tx) counter samples. Rates are computed
        # across the whole window, not tick-to-tick — a half-second sample is
        # instantaneous chatter, and displaying it twice a second reads as
        # flicker rather than as a number.
        self.counter_samples = []
        self.rates = (None, None)       # bytes/sec
        # Whether the link is carrying real traffic right now. Probes read
        # this as each sample lands, which is what separates idle latency
        # from latency under load — the gap between them IS bufferbloat.
        # Same floor the link-event logic uses, for the same reason: below
        # it, Wi-Fi power save makes the link look busy when nobody is.
        self.link_loaded = False
        # 5-second aux samples riding along in recent.json: throughput and
        # signal, so the panel's charts have history the moment they open.
        self.aux_ring = deque(maxlen=400)
        self.last_signal = None
        self.watch_local = LegWatch("local")
        self.watch_wan = LegWatch("wan")
        self.wan_events = WanEventArbiter(self.store, self.notify)
        self.local_events = LocalEventArbiter(self.store, self.notify)
        self.captive = CaptiveWatch(net.reachability)
        # The address this connection appears from — live.json only, never
        # recent.json or history: shown, not archived.
        self.wan_ip = None
        self._wan_ip_at = 0.0
        # Who ended each Wi-Fi association — read from nl80211 via `iw
        # event`, unprivileged. Without it the link log still works; it
        # just cannot tell a kick from a roam.
        self.nl_events = linkevents.NlEvents()
        self.link_watch = LinkWatch(self.store, self.nl_events)
        # Notify-only: asks origin whether this checkout is behind and
        # never touches it. Off when the user turns updateCheck off.
        self.update_watch = UpdateWatch(enabled=bool(self.config["updateCheck"]))
        self.app_traffic = apps.AppTraffic()
        self.last_apps_poll = 0.0
        self.last_content_test = 0.0
        self.last_minute_flush = 0.0
        self.last_rollup = 0.0
        self.peak_requested = threading.Event()
        self.peak_running = False
        self.peak_progress = {}
        self._lock_fh = None

    # ------------------------------------------------------------- lifecycle

    def acquire_lock(self) -> bool:
        """One daemon per user. The shell service and a systemd unit can both
        try to start us; whoever loses the lock just exits quietly.

        The lock file sits at a predictable path, so it is opened without
        truncation and without following symlinks — a planted symlink must
        fail the open, never redirect a truncation somewhere else — and it
        is only ever truncated after this process holds the flock.
        """
        try:
            fd = os.open(lock_path(),
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600)
        except OSError:
            return False
        try:
            if not stat_module.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                return False
            # The creation mode only applies to new files; a lock file left
            # by an older version keeps its old permissions until this.
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self._lock_fh = os.fdopen(fd, "r+")
        return True

    def _instrument_pool(self):
        anchor = self.config["internetAnchor"]
        return [("icmp-anchor", "icmp", anchor),
                ("tcp-anchor", "tcp", "%s:443" % anchor),
                ("tcp-cf", "tcp", CF_EDGE_HOST + ":443"),
                ("tcp-google", "tcp", DIVERSITY_HOST + ":443")]

    def _new_instrument_series(self):
        self._instrument_series = {
            key: Series() for key, _, _ in self._instrument_pool()}
        # The names the rest of the daemon has always read.
        self.icmp_anchor = self._instrument_series["icmp-anchor"]
        self.app = self._instrument_series["tcp-anchor"]

    def _active_series(self):
        return [self._instrument_series[i.key] for i in self.bench.actives()
                if i.key in self._instrument_series]

    def _instrument_stats(self, window_s: float = Bench.WINDOW_S):
        return {k: Series.stats(v.since(window_s))
                for k, v in self._instrument_series.items()}

    def _apply_seats(self, changes):
        interval = int(self.config["probeIntervalMs"]) / 1000.0
        for key, active in changes:
            probe = self._instrument_probes.get(key)
            if not probe:
                continue
            kind = self.bench.instruments[key].kind
            base = interval if kind == "icmp" else TCP_PROBE_INTERVAL_S
            probe.set_interval(base if active else base * STANDBY_FACTOR)

    def start_probes(self):
        anchor = self.config["internetAnchor"]
        self.route = net.route_to(anchor)
        interval = int(self.config["probeIntervalMs"])
        gw = self.route.get("gateway", "")
        if gw:
            p = PingProbe(gw, self.local, interval, "local",
                          loaded_fn=lambda: self.link_loaded)
            p.start()
            self.probes.append(p)
        for key, kind, target in self._instrument_pool():
            series = self._instrument_series[key]
            host = target.rsplit(":", 1)[0] if kind == "tcp" else target
            if kind == "icmp":
                p = PingProbe(host, series, interval, key,
                              loaded_fn=lambda: self.link_loaded)
                base = interval / 1000.0
            else:
                p = TcpProbe(host, series, TCP_PROBE_INTERVAL_S, key,
                             loaded_fn=lambda: self.link_loaded,
                             port=TCP_PROBE_PORT)
                base = TCP_PROBE_INTERVAL_S
            self.bench.instruments[key].target = target
            if not self.bench.instruments[key].active:
                p.set_interval(base * STANDBY_FACTOR)
            p.start()
            self.probes.append(p)
            self._instrument_probes[key] = p

    def restart_probes_if_route_changed(self):
        """New default route (roamed networks, docked, VPN up) — new targets."""
        anchor = self.config["internetAnchor"]
        fresh = net.route_to(anchor)
        if not fresh.get("gateway"):
            # No route at all is an outage, not a different network, and
            # resetting on it threw away the one window a user wants
            # afterwards — the run-up to the drop. It also fired twice per
            # disconnect, once on the way down and once on the way back.
            # Nothing new can contaminate the distributions while there is
            # no network, so keep them, and keep the probes running: their
            # losses are what the outage watch is reading.
            return
        if fresh.get("gateway") == self.route.get("gateway") and \
           fresh.get("iface") == self.route.get("iface"):
            return
        for p in self.probes:
            p.stop()
        self.probes.clear()
        self._instrument_probes = {}
        self.local = Series()
        # Fresh network, fresh distributions: every instrument starts
        # over. The bench keeps its seats — continuity until the new
        # windows hold enough samples to argue about.
        self._new_instrument_series()
        self.route = fresh
        self.counter_samples = []
        # A new route means a new apparent address; drop the stale one now
        # rather than display it wrong for up to an hour.
        self.wan_ip = None
        self._wan_ip_at = 0.0
        self.start_probes()

    def stop(self, *_):
        self.running = False

    # ------------------------------------------------------------ measuring

    def throughput(self, now: float, iface: str):
        c = net.counters(iface)
        if c is None:
            self.counter_samples = []
            self.rates = (None, None)
            self.link_loaded = False
            return
        window = max(1, min(30, int(self.config["throughputWindowS"])))
        self.counter_samples.append((now, c[0], c[1]))
        cutoff = now - window - 0.25
        while len(self.counter_samples) > 2 and self.counter_samples[0][0] < cutoff:
            self.counter_samples.pop(0)
        # Hard cap independent of config: the window can never retain more
        # than a minute of half-second samples, whatever the file says.
        if len(self.counter_samples) > 128:
            del self.counter_samples[:len(self.counter_samples) - 128]
        if len(self.counter_samples) >= 2:
            t0, rx0, tx0 = self.counter_samples[0]
            t1, rx1, tx1 = self.counter_samples[-1]
            dt = t1 - t0
            if dt > 0 and rx1 >= rx0 and tx1 >= tx0:
                self.rates = ((rx1 - rx0) / dt, (tx1 - tx0) / dt)
                self.link_loaded = ((self.rates[0] or 0.0) + (self.rates[1] or 0.0)
                                    >= LinkWatch.TRAFFIC_FLOOR_BPS)
            else:
                # Counter reset (interface bounced) — start the window over.
                self.counter_samples = [self.counter_samples[-1]]

    def notify(self, summary: str, body: str, urgent: bool = False):
        if not self.config["notifyOutage"]:
            return
        import shutil, subprocess
        cmd = None
        if shutil.which("omarchy-notification-send"):
            cmd = ["omarchy-notification-send", summary, body]
        elif shutil.which("notify-send"):
            cmd = ["notify-send", "-a", "Nexthop"]
            if urgent:
                cmd += ["-u", "critical"]
            cmd += [summary, body]
        if cmd:
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            except OSError:
                pass

    def watch_outages(self, now: float, ls: dict, ts: dict):
        """Outage logic on the freshest sample of each series.

        The wan watch only counts a loss when the local leg answered — if
        the router itself is unreachable, the internet probe's losses say
        nothing about the ISP.
        """
        recent_local = self.local.since(3.0)
        recent_total = self.total.since(3.0)
        local_ok = any(s[1] is not None for s in recent_local) if recent_local else None
        total_ok = any(s[1] is not None for s in recent_total) if recent_total else None

        if local_ok is not None:
            move = self.watch_local.sample(local_ok, now)
            if move == "down":
                # Is anything past the gateway answering? If so the gateway
                # is forwarding and merely refuses pings — see
                # LocalEventArbiter.
                self.local_events.down(now, self._any_instrument_alive(4.5))
            elif move == "up":
                self.local_events.up(now)
            elif move == "disruption":
                self.record_disruption("local", self.watch_local,
                                       self._any_instrument_alive(4.5))
            elif self.watch_local.down_since is not None:
                self.local_events.tick(now, self._any_instrument_alive(5.0))

        # The wan watch normally ignores any window where the local leg lost
        # packets: if the router is unreachable, the internet probe's losses
        # say nothing about the ISP. But a gateway that merely refuses pings
        # is "lost" forever, and skipping the wan watch on such a link would
        # mean never noticing a real internet outage there. So the skip
        # applies to a confirmed local outage, not to a quiet gateway.
        gateway_quiet = (self.watch_local.down_since is not None
                         and not self.local_events.real_outage)
        if total_ok is not None and (local_ok is not False or gateway_quiet):
            move = self.watch_wan.sample(total_ok, now)
            if move == "down":
                # Did TCP keep answering while the pings failed? Samples
                # are stamped at send time, so a handshake that merely
                # straddled the moment the line died cannot vouch for the
                # window after it.
                self.wan_events.down(now, self._any_instrument_alive(4.5))
            elif move == "up":
                self.wan_events.up(now)
            elif move == "disruption":
                self.record_disruption("wan", self.watch_wan,
                                       self._any_instrument_alive(4.5))
            elif self.watch_wan.down_since is not None:
                self.wan_events.tick(now, self._any_instrument_alive(5.0))

    def record_disruption(self, leg: str, watch, beyond_ok: bool):
        """A run that recovered before it became an outage.

        Arbitrated exactly like an outage: if something past this leg kept
        answering, the leg did not interrupt anything — a gateway dropping
        three pings while traffic crosses it is not a disruption, and
        logging it would fill the log with noise the user never felt.
        """
        if not watch.blip:
            return
        began, ended = watch.blip
        watch.blip = None
        if beyond_ok:
            return
        # Stored closed, with its duration, because Reliability charges
        # interruptions in time. Integer seconds are what the table holds,
        # so guarantee a non-zero span: outage_stats drops any row whose
        # end is not after its start, and a blip that vanished from the
        # score would be worse than one rounded up by a second.
        eid = self.store.open_event(
            int(began), "disruption", "warn", leg,
            "brief interruption, recovered on its own")
        self.store.close_event(eid, max(int(ended), int(began) + 1))

    def _any_instrument_alive(self, window_s: float) -> bool:
        """Some instrument — seated or benched — heard the internet this
        recently. The outage arbiter treats that as proof the leg carries."""
        for series in self._instrument_series.values():
            if any(s[1] is not None for s in series.since(window_s)):
                return True
        return False

    def refresh_wan_ip(self):
        """Off the loop: a curl with a timeout, and the bar must not wait
        on it. A failed fetch keeps the last answer — the route is the
        thing that invalidates it, and the route path clears it."""
        info = net.wan_ip()
        if info:
            info["checked_ts"] = int(time.time())
            self.wan_ip = info

    def maybe_content_test(self, now: float):
        if not self.config["contentSpeed"]:
            return
        interval = max(15, int(self.config["contentSpeedIntervalMin"])) * 60
        boost_at = getattr(self, "_content_boost_at", None)
        due = (now - self.last_content_test >= interval) or \
              (boost_at is not None and now >= boost_at)
        if not due:
            return
        self._content_boost_at = None
        # Skip while down — a failed transfer during an outage is not a
        # speed measurement, and skip while a peak test owns the line.
        if self.watch_wan.down_since or self.watch_local.down_since or self.peak_running:
            return
        self.last_content_test = now

        snap = net.snapshot(self.config["internetAnchor"])
        network = snap.get("ssid") or snap.get("name") or ""

        def run():
            r = speedtest.content_test()
            if r["ok"]:
                self.store.put_test(int(r["started"]), "content", r["engine"],
                                    down_mbps=r["down_mbps"], up_mbps=r["up_mbps"],
                                    bytes=r["bytes"], ok=True, network=network)
                # A fresh result should reprice the baseline promptly.
                self._baseline_cache = None

        threading.Thread(target=run, daemon=True, name="content-test").start()

    def run_peak_test(self):
        """On demand, in its own thread; loaded latency comes from the probes."""
        if self.peak_running:
            return
        self.peak_running = True

        def run():
            try:
                idle = score.lag_ms(Series.stats(self.total.since(60)))
                started = time.time()
                r = speedtest.peak_test(self.config["peakEngine"])
                loaded_window = [s for s in self.total.all()
                                 if s[0] >= started and s[1] is not None]
                loaded = (round(sorted(s[1] for s in loaded_window)[len(loaded_window) // 2], 1)
                          if loaded_window else None)
                if r["ok"]:
                    self.store.put_test(
                        int(r["started"]), "peak", r["engine"],
                        down_mbps=r.get("down_mbps"), up_mbps=r.get("up_mbps"),
                        ping_idle=r.get("ping_idle") or idle, ping_loaded=loaded,
                        jitter=r.get("jitter"), bytes=r.get("bytes"),
                        server=r.get("server"), ok=True, detail=r.get("url", ""))
                else:
                    self.store.put_test(int(r["started"]), "peak", r["engine"],
                                        ok=False)
            finally:
                self.peak_running = False

        threading.Thread(target=run, daemon=True, name="peak-test").start()

    # -------------------------------------------------------------- writing

    def speed_score(self, now: float, network: str):
        """(score, ctx) for the Speed component.

        Plan configured -> scored against it. Otherwise the absolute
        experience curve, with a degradation penalty against this network's
        own recent p90. The baseline is cached for a minute — it moves at
        content-check cadence, not at probe cadence.
        """
        tests = [t for t in self.store.tests(limit=12, kind="content")
                 if t["ok"] and t["down_mbps"] is not None]

        plan_d = self.config["planDownMbps"]
        plan_u = self.config["planUpMbps"]
        if plan_d:
            if not tests:
                return None, {"basis": "plan", "plan_down": plan_d,
                              "last_down": None, "last_up": None}
            last = tests[0]
            spd = score.speed(last["down_mbps"], last["up_mbps"],
                              plan_d, plan_u or 0)
            return spd, {"basis": "plan", "plan_down": plan_d,
                         "plan_up": plan_u,
                         "last_down": last["down_mbps"],
                         "last_up": last["up_mbps"]}

        # Checks describe the network they ran on. A result from another
        # network says nothing about this one, so on a network with no
        # checks yet the component is honestly unknown (and the changed
        # network has already scheduled a prompt check).
        mine = [t for t in tests
                if (t.get("network") or "") == network] if network else tests
        if not mine:
            return None, {"basis": "auto", "baseline_down": None,
                          "last_down": None, "last_up": None,
                          "pending": True}

        # Median of the last few checks here, so one bad sample — a check
        # that ran mid-roam or during someone's upload — cannot pin the
        # score until the next hourly run.
        recent = mine[:3]
        downs = sorted(t["down_mbps"] for t in recent)
        down = downs[len(downs) // 2]
        ups = sorted(t["up_mbps"] for t in recent
                     if t["up_mbps"] is not None)
        up = ups[len(ups) // 2] if ups else None

        cache = getattr(self, "_baseline_cache", None)
        if not cache or now - cache[0] > 60 or cache[2] != network:
            baseline = self.store.baseline_speed(network=network, now=now,
                                                 fallback=False)
            cache = (now, baseline, network)
            self._baseline_cache = cache
        baseline = cache[1]
        spd = score.speed(down, up, baseline_down=baseline)
        return spd, {"basis": "auto", "baseline_down": baseline,
                     "last_down": down, "last_up": up,
                     "samples": len(recent)}

    def sample_app_request(self):
        """One real HTTP/3 request, for what a request actually costs.

        The TCP probe gives a round trip comparable with ICMP; this gives
        what neither measures — handshake plus first byte over the protocol
        a browser would use. Degrades to HTTP/2 where curl has no HTTP/3
        rather than reporting nothing.
        """
        if not shutil.which("curl"):
            return
        host = h3_target(self.config["internetAnchor"])
        if not host:
            self.app_request = {"ok": False, "skipped": "no TLS name for anchor",
                                "at": time.time()}
            return
        proto = ["--http3"] if self._curl_has_http3() else ["--http2"]
        cmd = (["curl", "-sS", "-I", "-o", "/dev/null", "--proto", "=https",
                "--max-time", str(int(H3_TIMEOUT_S))]
               + proto
               + ["-w", "%{http_version} %{time_appconnect} "
                        "%{time_starttransfer} %{size_download} %{http_code}",
                  f"https://{host}/"])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=H3_TIMEOUT_S + 5)
        except (subprocess.TimeoutExpired, OSError):
            self.app_request = {"ok": False, "at": time.time()}
            return
        if r.returncode != 0:
            self.app_request = {"ok": False, "at": time.time()}
            return
        try:
            version, appconnect, ttfb, size, code = r.stdout.split()
            self.app_request = {
                "ok": code.startswith("2"),
                "protocol": "h3" if version.startswith("3") else "h" + version,
                "handshake_ms": round(float(appconnect) * 1000.0, 1),
                "ttfb_ms": round(float(ttfb) * 1000.0, 1),
                "bytes": int(size),
                "at": time.time(),
            }
        except (ValueError, IndexError):
            self.app_request = {"ok": False, "at": time.time()}

    def _curl_has_http3(self) -> bool:
        """Cached once: curl is not rebuilt mid-run."""
        if self._curl_h3 is None:
            try:
                out = subprocess.run(["curl", "--version"], capture_output=True,
                                     text=True, timeout=5).stdout
                self._curl_h3 = "HTTP3" in out
            except (subprocess.TimeoutExpired, OSError):
                self._curl_h3 = False
        return self._curl_h3

    def app_path(self, window_s: float = 300.0) -> dict:
        """The application path beside the ICMP one, and the gap between.

        `icmp_delta_ms` is what this probe exists to produce: how much
        lower ICMP reads than a handshake over the same path to the same
        host. A large positive gap means the ICMP figure — and any score
        built on it — is flattering the connection.
        """
        app_stats = Series.stats(self.app.since(window_s))
        icmp_stats = Series.stats(self.icmp_anchor.since(window_s))
        out = {"rtt": app_stats, "request": self.app_request}
        # Every sample failing means the anchor does not answer on this
        # port: a fact about the target, not a fault in the connection.
        out["available"] = bool(app_stats["count"]) and app_stats["loss"] != 1.0
        delta = None
        if (out["available"] and app_stats.get("p50") is not None
                and icmp_stats.get("p50") is not None):
            delta = round(app_stats["p50"] - icmp_stats["p50"], 2)
        out["icmp_delta_ms"] = delta
        return out

    def bufferbloat(self, window_s: float = 300.0) -> dict:
        """Lag while the link was idle vs while it was carrying traffic.

        The gap between them is bufferbloat, and it is the failure a plain
        latency number misses entirely: a line can answer in 15 ms at rest,
        sit at 300 ms whenever anyone downloads anything, and still look
        excellent on every idle measurement anyone takes of it.

        Both figures come from the same probe stream — no extra traffic is
        generated to produce them. That is the whole point of tagging each
        sample as it lands: the user's own usage supplies the load.
        """
        window = self.total.since(window_s)
        idle_s, loaded_s = Series.split_by_load(window)
        idle_st = Series.stats(idle_s) if idle_s else {}
        loaded_st = Series.stats(loaded_s) if loaded_s else {}
        idle_lag = score.lag_ms(idle_st) if idle_s else None
        loaded_lag = score.lag_ms(loaded_st) if loaded_s else None
        # A handful of samples on either side produces noise, not a ratio —
        # observed live, a five-sample loaded window read as 0.59, i.e. the
        # link answering *faster* under load. Both sides need enough
        # samples before the comparison means anything.
        inflation = None
        if (idle_lag and loaded_lag and idle_lag > 0
                and len(idle_s) >= MIN_LOAD_SPLIT_SAMPLES
                and len(loaded_s) >= MIN_LOAD_SPLIT_SAMPLES):
            ratio = loaded_lag / idle_lag
            if ratio >= MIN_PLAUSIBLE_INFLATION:
                # Clamped at 1: a ratio a hair under it means the two are
                # indistinguishable, not that load made the link quicker.
                inflation = round(max(1.0, ratio), 2)
        # Percentiles over the loaded samples ALONE. The headline stats span
        # a fixed 30 s window, so a ten-second burst is averaged with twenty
        # seconds of quiet and reads far milder than it was: measured against
        # another tool on the same event, 107 ms against its 246. Scoping the
        # percentile to the samples that were actually taken under load is
        # the same idea as their per-phase percentile, using the tagging
        # 0.1.11 already put on every probe.
        return {"idle": idle_lag, "loaded": loaded_lag,
                "inflation": inflation, "loaded_samples": len(loaded_s),
                "idle_samples": len(idle_s),
                "loaded_p50": loaded_st.get("p50") if loaded_s else None,
                "loaded_p95": loaded_st.get("p95") if loaded_s else None,
                "idle_p50": idle_st.get("p50") if idle_s else None,
                # How fast the queue emptied once traffic stopped. Depth is
                # what everyone reports; duration is what a user feels after
                # the download finishes.
                "drain": score.drain_after_load(window, idle_st.get("p50"))}

    def compose_live(self, now: float) -> dict:
        ls = Series.stats(self.local.since(30))
        ts = Series.stats(self.total.since(30))
        ws = score.wan_from(ts, ls)
        lag = score.lag_ms(ts)
        resp = score.responsiveness(lag) if ts["count"] else None
        # Idle vs loaded over a longer window than the headline: bufferbloat
        # only shows when the link has actually been used, and 30 s of an
        # idle laptop would almost never contain a loaded sample. Reported,
        # not yet scored — the number has to be trusted before it can move
        # anyone's index.
        bloat = self.bufferbloat(300.0)

        out_frac, disruptions, disrupt_frac = self.store.outage_stats(24 * 3600, now)
        rel = score.reliability(out_frac, disruptions,
                                disruption_fraction=disrupt_frac)

        snap = net.snapshot(self.config["internetAnchor"])
        network = snap.get("ssid") or snap.get("name") or ""
        self.last_signal = snap.get("signal_dbm")
        prev = getattr(self, "_content_network", None)
        if network and prev is not None and network != prev:
            # New network: the hourly cadence would leave Speed unknown or
            # stale for up to an hour here. Measure soon — after a settle
            # delay, so a roam in progress is not sampled as the network's
            # capability.
            self._content_boost_at = now + 90
        if network:
            self._content_network = network
        if snap.get("kind") == "wifi":
            self.link_watch.sample(now, snap,
                                   (self.rates[0] or 0) + (self.rates[1] or 0))
            st = snap.get("station") or {}
            if st.get("tx_packets"):
                st["retry_pct"] = round(
                    100.0 * (st.get("tx_retries") or 0) / st["tx_packets"], 2)
                st["failed_pct"] = round(
                    100.0 * (st.get("tx_failed") or 0) / st["tx_packets"], 3)
        spd, speed_ctx = self.speed_score(now, network)

        band = score.lag_band(ts)

        idx = score.index(resp, rel, spd)

        state = "online"
        if self.captive.confirmed:
            # Outranks both leg verdicts because it explains them: on a
            # portal the gateway often refuses pings and something answers
            # for the anchor, so "router unreachable" and "internet fine"
            # are both artefacts of the same interception.
            state = "captive"
        elif self.watch_local.down_since and self.local_events.real_outage:
            # A silent gateway is not an unreachable one; the arbiter decides.
            state = "local-down"
        elif self.watch_wan.down_since and self.wan_events.real_outage:
            # Pings alone cannot declare this; see WanEventArbiter. During
            # an icmp-quiet spell the bar stays its ordinary colour — the
            # user's internet is working, and the log holds the anomaly.
            state = "wan-down"
        elif idx is not None and idx < 70:
            state = "degraded"

        return {
            "v": 1,
            "t": round(now, 3),
            "state": state,
            "index": idx,
            "band": score.band(idx),
            "scores": {"responsiveness": resp, "reliability": rel, "speed": spd},
            "speed_ctx": speed_ctx,
            # best/typical/worst all come from the same fold — see
            # score.lag_band. `now` stays the scored p75-based figure.
            "lag": {"now": lag,
                    "best": band.get("best"), "worst": band.get("worst"),
                    "typical": band.get("typical"),
                    "idle": bloat["idle"], "loaded": bloat["loaded"],
                    "inflation": bloat["inflation"],
                    "loaded_samples": bloat["loaded_samples"],
                    "idle_samples": bloat["idle_samples"],
                    "loaded_p50": bloat["loaded_p50"],
                    "loaded_p95": bloat["loaded_p95"],
                    "idle_p50": bloat["idle_p50"],
                    "drain_ms": bloat["drain"]["ms"],
                    "drain_settled": bloat["drain"]["settled"]},
            "local": ls, "total": ts, "wan": ws,
            "wan_ip": self.wan_ip,
            # Proof the real internet answered, or why it did not.
            "reach": self.captive.snapshot(),
            "app": self.app_path(300.0),
            # What the user's own TCP connections are experiencing, straight
            # from the kernel. `app` above is our anchor probe; this is their
            # real traffic to their real destinations.
            "sockets": self.app_traffic.latency,
            # What the connection is doing right now, as opposed to lately.
            # The index answers the second question and cannot answer the
            # first — see score.pressure.
            "pressure": score.pressure(
                socket_queue_ms=(self.app_traffic.latency or {}).get("queue_p50"),
                loaded_ms=bloat["loaded"], idle_ms=bloat["idle"]),
            # Whether a newer version is published. A notice, not an
            # action: nothing here updates anything.
            "update": self.update_watch.snapshot(),
            "instruments": self.bench.snapshot(now, self._instrument_stats()),
            "rates": {"rx_bps": self.rates[0], "tx_bps": self.rates[1],
                      "rx_total": self.counter_samples[-1][1] if self.counter_samples else None,
                      "tx_total": self.counter_samples[-1][2] if self.counter_samples else None},
            "link": snap,
            "down_since": self.watch_local.down_since or self.watch_wan.down_since,
            "peak_running": self.peak_running,
            "pid": os.getpid(),
            "pid_start": proc_start_ticks(os.getpid()),
            "daemon_version": __version__,
        }

    def flush_recent(self, now: float):
        """recent.json: last 30 min at 5-second resolution, ~360 points."""
        self.aux_ring.append((now, self.rates[0], self.rates[1],
                              self.last_signal))
        points = []
        bucket = 5.0
        start = now - 1800
        locs = self.local.all()
        tots = self.total.all()

        def fold(samples):
            out = {}
            for smp in samples:
                t, r = smp[0], smp[1]
                if t < start:
                    continue
                b = int((t - start) / bucket)
                out.setdefault(b, []).append(r)
            return out

        lb, tb = fold(locs), fold(tots)
        aux_b = {}
        for at, rx, tx, sig in self.aux_ring:
            if at >= start:
                aux_b[int((at - start) / bucket)] = (rx, tx, sig)
        for b in range(int(1800 / bucket)):
            l = lb.get(b, [])
            t = tb.get(b, [])
            lr = [x for x in l if x is not None]
            tr = [x for x in t if x is not None]
            a = aux_b.get(b)
            points.append({
                "t": round(start + b * bucket, 1),
                "local": round(sum(lr) / len(lr), 2) if lr else None,
                "total": round(sum(tr) / len(tr), 2) if tr else None,
                "loss": round((len(l) - len(lr) + len(t) - len(tr)) /
                              max(1, len(l) + len(t)), 3) if (l or t) else None,
                "rx": round(a[0], 1) if a and a[0] is not None else None,
                "tx": round(a[1], 1) if a and a[1] is not None else None,
                "sig": a[2] if a else None,
            })
        write_atomic(recent_path(), {"v": 1, "t": now, "bucket_s": bucket,
                                     "points": points})

    def flush_minute(self, now: float):
        ls = Series.stats(self.local.since(60))
        ts = Series.stats(self.total.since(60))
        ws = score.wan_from(ts, ls)
        lag = score.lag_ms(ts)
        resp = score.responsiveness(lag) if ts["count"] else None
        # The old basis kept beside the new: the 0.2.0 switch to
        # instrument-scored lag must stay auditable against what ICMP
        # alone would have said — the 0.1.10 discipline, applied to
        # ourselves.
        icmp_stats = Series.stats(self.icmp_anchor.since(60))
        icmp_lag = score.lag_ms(icmp_stats) if icmp_stats["count"] else None

        out_frac, disruptions, disrupt_frac = self.store.outage_stats(24 * 3600, now)
        rel = score.reliability(out_frac, disruptions,
                                disruption_fraction=disrupt_frac)
        bloat = self.bufferbloat(300.0)
        snap_link = net.wifi_link(self.route.get("iface", "")) \
            if net.is_wireless(self.route.get("iface", "")) else {}
        spd, _ = self.speed_score(now, snap_link.get("ssid", ""))
        idx = score.index(resp, rel, spd)
        self.store.put_minute(
            int(now // 60) * 60,
            {
                "local_p50": ls.get("p50"), "local_p95": ls.get("p95"),
                "local_jitter": ls.get("jitter"), "local_loss": ls.get("loss"),
                "wan_p50": ws.get("p50"), "wan_p95": ws.get("p95"),
                "wan_jitter": ws.get("jitter"), "wan_loss": ws.get("loss"),
                "lag": lag,
                "rx_bps": self.rates[0], "tx_bps": self.rates[1],
                "signal_dbm": snap_link.get("signal_dbm"),
                "resp": resp, "rel": rel, "spd": spd, "idx": idx,
                "lag_idle": bloat["idle"], "lag_loaded": bloat["loaded"],
                "lag_icmp": icmp_lag,
            },
            iface=self.route.get("iface", ""),
            network=snap_link.get("ssid", ""),
            probes="+".join(sorted(i.key for i in self.bench.actives())),
        )

    def flush_apps(self, now: float):
        """apps.json: top apps by TCP traffic, plus the honest remainder.

        The interface moves bytes that no unprivileged tool can attribute —
        UDP and with it QUIC, protocol overhead, other users' processes.
        That remainder is published as its own bucket instead of being
        left to look like the top apps account for everything.
        """
        if not self.app_traffic.poll():
            return
        tcp_rx = sum(a["rx_bps"] for a in self.app_traffic.rates)
        tcp_tx = sum(a["tx_bps"] for a in self.app_traffic.rates)
        iface_rx = self.rates[0] or 0.0
        iface_tx = self.rates[1] or 0.0
        write_atomic(state_dir() / "apps.json", {
            "v": 1,
            "t": round(now, 1),
            "apps": self.app_traffic.top(8),
            "other": {
                "rx_bps": round(max(0.0, iface_rx - tcp_rx), 1),
                "tx_bps": round(max(0.0, iface_tx - tcp_tx), 1),
            },
        })

    # ----------------------------------------------------------------- main

    def loop(self):
        tick = 0.5
        while self.running:
            now = time.time()
            self.config.refresh()

            ls = Series.stats(self.local.since(30))
            ts = Series.stats(self.total.since(30))
            self.watch_outages(now, ls, ts)
            self.throughput(now, self.route.get("iface", ""))

            write_atomic(live_path(), self.compose_live(now))

            if now - self.last_apps_poll >= 3.0:
                self.last_apps_poll = now
                self.flush_apps(now)

            if now - self.last_minute_flush >= 60:
                self.last_minute_flush = now
                self.flush_minute(now)
                self.flush_recent(now)
                self.restart_probes_if_route_changed()
            elif int(now) % 5 == 0:
                self.flush_recent(now)

            if now - self.last_rollup >= 3600:
                self.last_rollup = now
                self.store.rollup_hours(now)
                self.store.prune(minute_days=int(self.config["historyDays"]),
                                 now=now)

            self.captive.tick(now, self._any_instrument_alive(6.0))

            self.update_watch.enabled = bool(self.config["updateCheck"])
            self.update_watch.tick(now)

            self.maybe_content_test(now)

            if now - self._last_bench_eval >= BENCH_EVAL_EVERY_S:
                self._last_bench_eval = now
                self._apply_seats(
                    self.bench.evaluate(now, self._instrument_stats()))

            if now - self._wan_ip_at >= WAN_IP_REFRESH_S:
                self._wan_ip_at = now
                threading.Thread(target=self.refresh_wan_ip,
                                 name="wan-ip", daemon=True).start()

            if now - self.last_app_request >= H3_SAMPLE_INTERVAL_S:
                self.last_app_request = now
                # Off the loop: a request can block for seconds and the
                # bar must keep updating at 2 Hz while it does.
                threading.Thread(target=self.sample_app_request,
                                 name="app-request", daemon=True).start()

            if self.peak_requested.is_set():
                self.peak_requested.clear()
                self.run_peak_test()

            time.sleep(max(0.1, tick - (time.time() - now)))

    # Exit code contract with the shell service: LOCK_HELD means another
    # instance owns the measurement and the service must not respawn us.
    # Every other exit — including a clean 0 from SIGTERM — deserves a
    # respawn, because a daemon that was asked to stop is still a daemon
    # that is no longer measuring.
    EXIT_LOCK_HELD = 3

    def run(self):
        if not self.acquire_lock():
            print("nexthopd: another instance holds the lock, exiting",
                  file=sys.stderr)
            return self.EXIT_LOCK_HELD
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        # SIGUSR1 is the "run a peak test" doorbell — file-free, and safe to
        # send from a QML Process one-liner.
        signal.signal(signal.SIGUSR1, lambda *_: self.peak_requested.set())
        self.nl_events.start()
        self.start_probes()
        try:
            self.loop()
        finally:
            for p in self.probes:
                p.stop()
            self.nl_events.stop()
            self.store.close()
        return 0


def main():
    return Daemon().run()


if __name__ == "__main__":
    sys.exit(main())
