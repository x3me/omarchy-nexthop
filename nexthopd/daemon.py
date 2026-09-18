"""The nexthopd main loop.

Owns the probes, folds their samples into live.json / recent.json /
apps.json / history.db, detects outages, and runs the scheduled content
check. The QML side never talks to this process — the files are the whole
contract, so either side can restart without the other noticing.
"""

import fcntl
import ipaddress
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
from typing import NamedTuple
from collections import deque

from . import __version__, apps, linkevents, net, score, speedtest
from .paths import (ensure_state_dir, ensure_runtime_dir, runtime_dir,
                    live_path, recent_path, db_path, lock_path, apps_path)
from .instruments import Bench, MergedSeries, merged_stats
from .probes import Series, PingProbe, TcpProbe, NameLookup
from .state import write_atomic, retire_legacy_snapshots
from .store import Store, vpn_matches
from .update import UpdateWatch

# Unbroken silence on a leg — no probe of any kind answering — before we
# call it down. Measured on the probe stream itself, from the timestamp of
# the first lost sample after the last reply, so it means four seconds
# whatever the probe cadence or the loop's tick. Long enough to skip a
# Wi-Fi roam, short enough that the alarm still feels immediate.
#
# History, because it cost a year: until 0.2.15 this was a COUNT of loop
# ticks (eight) in which a 3 s any-reply window came back empty, so a
# "loss" was three seconds wide, an outage took ~6.5 s while every comment
# said four, and an interruption shorter than 3 s could not register at
# all. Reading the stream is what makes the number mean what it says.
OUTAGE_AFTER_S = 4.0
# A run of silence shorter than an outage but longer than noise: an
# interruption the user may well have felt — a call breaking up, a stream
# rebuffering. Recorded at recovery, when its length is known, and charged
# to Reliability at half weight (score.reliability). Three lost probes at
# the default 500 ms.
DISRUPTION_AFTER_S = 1.5
# One lost probe is never an event, at any cadence. At a slow probe interval
# a single loss is followed by seconds with no sample at all, and measured
# in seconds alone that would read as an outage.
MIN_LOST_SAMPLES = 2
# A content check measures the line, and a Wi-Fi link that has just
# associated is not the line yet: it may still be on the band it landed on
# rather than the one it will roam to, and its transmit rate may still be
# climbing. Measured on this laptop: a check 55 s after associating read
# 63 Mbps on a 380 Mbps line, from 2.4 GHz at a 16 Mbps tx rate, nine
# minutes before the link moved itself to 5 GHz.
CHECK_SETTLE_S = 60.0
# But a link that is simply slow must still be measured eventually, or Speed
# never scores at all. Defer this long at most, then take what is there.
CHECK_DEFER_MAX_S = 600.0
# How recently a peak test must have run, on this network, to be allowed to
# contradict the everyday basis.
PEAK_FRESH_S = 3600.0


def check_ready(now: float, assoc_since, rate_low_since, waiting_since,
                settle_s: float = CHECK_SETTLE_S,
                max_defer_s: float = CHECK_DEFER_MAX_S) -> bool:
    """Is the link in a fit state to be measured? Pure, so it is testable.

    Two reasons to wait: the association is younger than the settle window,
    or the transmit rate is currently down (`LinkWatch.low_since`, the same
    signal that opens a rate-drop event). Either way the cap wins in the
    end — a permanently poor link gets an honest low number rather than no
    number, and the median guard is what protects the score from one bad
    sample.
    """
    if waiting_since is not None and now - waiting_since >= max_defer_s:
        return True
    if assoc_since is not None and now - assoc_since < settle_s:
        return False
    if rate_low_since is not None:
        return False
    return True


# A stream whose newest sample is older than this has stopped talking — a
# dead ping process, a stopped probe — which is not an outage. `ping -O`
# and the TCP probe keep emitting losses through a real one, so a stale
# stream is never mistaken for a dead line: it is unknown, and not counted.
LEG_STALE_S = 6.0
# How far back to read a leg's stream for the start of the current run. Past
# OUTAGE_AFTER_S with margin; the watch remembers an older start itself.
LEG_STREAM_WINDOW_S = 12.0
# More than this between two passes of the outage watch, on a clock that
# keeps counting through suspend, and the daemon was not watching: the
# machine slept, or the process was stopped. The loop passes every half
# second and nothing on it may block for long (see AppTraffic's budget), so
# this is a stream's own staleness horizon applied to the watcher.
#
# Why it exists (#6): the watch remembers when a run of losses began, and
# that memory survived a freeze. One lost probe in the last half-second
# before a laptop slept — the TCP probe fails at once when NetworkManager
# takes the Wi-Fi down — plus one after it woke made a run as long as the
# sleep, and the first tick after waking declared it: a ten-hour outage
# dated before the lid closed, blamed on the ISP. Every such row began a
# second BEFORE the kernel's "PM: suspend entry", too soon for the 4 s
# threshold to have been crossed while awake, which is how it was placed.
UNWATCHED_AFTER_S = LEG_STALE_S
# After such a gap the first losses are the machine re-joining its own
# network, not the network failing: on this laptop Wi-Fi came back 3 to
# 26 s after resume across twenty wakes (median 5), and every one of those
# seconds used to be logged as the router being unreachable. So a leg must
# answer once, or this long must pass, before its silence counts again. A
# line that really is dead on waking is charged from the end of the settle,
# which undercharges by at most this much.
RESUME_SETTLE_S = 30.0

# Probes needed on each side of the idle/loaded split before their ratio is
# reported. Below this the comparison is sampling noise.
MIN_LOAD_SPLIT_SAMPLES = 10
# What counts as a busy link, for the loaded/idle latency split only.
#
# This used to borrow `LinkWatch.TRAFFIC_FLOOR_BPS`, whose own comment says it
# exists so Wi-Fi power save does not fire spurious rate-drop events. That is
# a question about the radio; this is a question about the line, and one
# constant cannot answer both. At 25 kB/s it answered neither: on this laptop
# the median minute carries 18 kB/s and p75 is 42 kB/s, so the floor sat
# inside the IDLE distribution and tagged 36.6% of all minutes "loaded".
#
# The proof it measured nothing is in the stored history: across 8,971
# minutes carrying both figures, the loaded half was FASTER than the idle
# half 57% of the time, with medians 18.7 and 18.8 ms. A link cannot answer
# faster while busy; a coin flip is what two buckets holding the same thing
# look like. Selecting minutes by how much they actually carried recovers the
# signal, and only well up the range: at 250 kB/s inversions are 51%, at
# 1 MB/s 50%, at 2.5 MB/s 47%, and only at 5 MB/s do they fall to 29% with
# loaded 19.9 ms against idle 16.6 — the direction physics requires.
#
# That selection is weaker than it looks and the fraction below rests mostly
# on the 57% above, not on it. A minute's stored `rx_bps` is `self.rates`,
# the 3-second sliding window, so it describes the END of a minute rather
# than the minute: of 151 content checks, the median stored rate in the
# check's own minute is 29 kB/s, below even the whole-minute average of
# 233 kB/s, because a sub-second check rarely lands in the stored window.
# The probes' own load flags — which is what the 57% is built from — are
# unaffected, since each probe carries the tag it was measured under.
#
# 5 MB/s is a tenth of what this line carries, and a tenth is the number
# worth keeping rather than the 5, because a fixed rate cannot serve a
# 10 Mbps line and a gigabit one at once — the same lesson the content check
# learned about fixed transfer sizes. Below the floor nothing is called busy,
# so a line whose capacity is unknown does not tag its own background chatter.
LOAD_FRACTION_OF_LINE = 0.10
LOAD_FLOOR_BPS = 125_000
# Queueing can only ADD delay, so a loaded/idle ratio below 1 says the link
# answered faster while busy, which is not a measurement. The sample floor
# above does not catch it: 0.87 was published live on 716 samples per side.
# Within a few percent of 1 the two populations are simply indistinguishable
# and the honest reading is "no inflation"; further below, the split itself
# is untrustworthy — the loaded samples likely landed in a quiet moment — so
# withhold rather than report. A plausibility floor, distinct from a sample
# floor, and the guard the socket metric already has.
MIN_PLAUSIBLE_INFLATION = 0.95

# The TCP instruments: a handshake to port 443, once a second per target.
# Slower than the ICMP cadence on purpose — each one opens a real connection
# to someone else's server. Since 0.2.0 these are seated instruments in the
# bench, so a TCP series feeds the scored internet leg and the outage watch
# whenever it holds a seat (instruments.py).
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
# alarmed the instant they were declared, so a six-second blip on a flaky
# link fired a desktop notification the user could do nothing about. The
# event is always logged; only the interruption goes quiet.
NOTIFY_AFTER_S = 5.0

# A content check that failed outright (curl error, endpoint down) used to
# wait the full interval before trying again — an hour of stale Speed for
# a transient fault. One retry after this long; a second failure waits the
# interval, so a blocked endpoint is not hammered.
CONTENT_RETRY_S = 300.0


class Config:
    """Settings, read from the file the QML side writes.

    Every value is validated against the same ranges the manifest schema
    promises, and the file itself has a size cap — a config the daemon
    cannot trust in full is a config it ignores in full. Nothing read
    here can grow retained state beyond its documented bounds.
    """

    MAX_BYTES = 64 * 1024
    # key -> (default, validator). Ranges mirror manifest.json's schema.
    # A hostname or address never begins with a dash, and the anchor is
    # the last argument to `ping` and `ip route get`, where a leading dash
    # would be read as an option. Refused at the setting, so no call site
    # has to remember an option terminator.
    ANCHOR_RE = re.compile(r"^[A-Za-z0-9:][A-Za-z0-9.:\-]{0,252}$")

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
        "meteredCare": (True, None),
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
Config.SCHEMA["meteredCare"] = (True, Config._bool)
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
        # When the current association began, so a measurement can wait for
        # a link that has only just come up — see check_ready.
        self.assoc_since = None

    def _instant(self, ts, kind, detail):
        # Severity travels WITH the event so the panel can colour a kind it
        # has never heard of. A kick or a drop is a fault; a roam, an
        # association or a channel change is information.
        severity = "warn" if kind in ("kick", "drop") else "info"
        eid = self.store.open_event(int(ts), kind, severity, "local", detail)
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
            # the event log. It is still the moment we learned of this one,
            # so the settle window starts here.
            self.disassociated = False
            self.assoc_since = now
            return

        if self.disassociated:
            self.disassociated = False
            self.assoc_since = now
            cause = self._cause(prev_bssid, since, now)
            if cause:
                # One row for the whole incident: who ended it, how long it
                # took to come back, and where. The plain association is
                # for gaps nobody claimed — suspend, or no `iw event`.
                kind, text = self._blame(
                    cause, prev_bssid, bssid, gap_s=now - since)
                self._instant(now, kind, text)
            else:
                # Both, when both are known. The network name is what the
                # user recognises the connection by, and dropping it for the
                # BSSID alone left a row reading "Associated with
                # 02:00:00:…" for everyone without an AP inventory. The
                # BSSID says which radio, and is the half a later rename
                # decorates at display time (net.decorate_bssids); neither
                # is a name that can go stale in the row itself.
                self._instant(now, "associate", "Associated with "
                              + ", ".join(x for x in (ssid, bssid) if x))
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
            # A different AP has a different honest ceiling, and a different
            # band: this is a fresh association as far as measuring goes.
            self.rate_ceiling = 0.0
            self.assoc_since = now
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
                    int(self.low_since), "rate-drop", "warn", "local",
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


_AWAKE_CLOCK = getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)


def awake_clock() -> float:
    """Seconds on a clock that keeps counting through suspend and never
    steps. CLOCK_MONOTONIC stops while the machine sleeps, so it cannot see
    a sleep at all; time.time() can, but also jumps whenever NTP steps it."""
    return time.clock_gettime(_AWAKE_CLOCK)


class LegState(NamedTuple):
    """What a leg's probe stream says right now — see leg_state()."""
    ok: bool             # the newest sample is a reply
    ts: float            # timestamp of the newest sample
    run_since: object    # first lost sample of the trailing run; None when ok
    lost: int            # lost samples in that run; 0 when ok


def leg_state(samples, now: float):
    """Read a leg's recent samples into a LegState, or None when the stream
    is empty or stale — the probe stopped talking, which is not an outage.

    `samples` are (ts, rtt_or_None, ...) in time order: one Series, or the
    MergedSeries of the seated instruments. The trailing run of losses is
    the whole question — how long since anything answered, counted from the
    first sample that did not. This replaces a rolling "did anything reply
    in the last 3 s" window, whose width was silently added to every
    threshold built on it.
    """
    if not samples:
        return None
    ts = samples[-1][0]
    if now - ts > LEG_STALE_S:
        return None
    lost, run_since = 0, None
    for smp in reversed(samples):
        if smp[1] is not None:
            break
        lost += 1
        run_since = smp[0]
    if lost == 0:
        return LegState(True, ts, None, 0)
    return LegState(False, ts, run_since, lost)


class LegWatch:
    """Outage state for one leg: how long its stream has been silent, when
    that silence became an outage, and what a recovered run looked like."""

    def __init__(self):
        self.down_since = None
        self.run_since = None      # first lost sample of the current run
        self.lost = 0              # lost samples seen in that run
        self.blip = None           # (from, to) of a run that just recovered
        self.resumed_at = None     # set by lost_sight(); cleared by a reply
        self.settle_until = None

    def lost_sight(self, resumed_at: float, settle_s: float = RESUME_SETTLE_S):
        """We stopped watching and have just started again (UNWATCHED_AFTER_S).

        Forget the run in progress: the silence before the gap and the
        silence after it are not one run, because nobody saw what lay
        between. Returns whether the leg had been declared down, so the
        caller can close that event where watching stopped.
        """
        was_down = self.down_since is not None
        self.down_since = self.run_since = self.blip = None
        self.lost = 0
        self.resumed_at = resumed_at
        self.settle_until = resumed_at + settle_s
        return was_down

    def sample(self, state: LegState, now: float):
        """Returns 'down' / 'up' / 'disruption' on a transition, else None.

        `disruption` is a run that recovered before reaching the outage
        threshold. It is reported at recovery rather than at onset because
        that is the first moment its length is known, and its length is what
        Reliability charges. Both thresholds are seconds of silence on the
        stream, from the first lost sample to the first reply after it.
        """
        if self.resumed_at is not None:
            if state.ts < self.resumed_at:
                return None               # nothing from this side of the gap yet
            if state.ok:
                self.resumed_at = self.settle_until = None
            elif now < self.settle_until:
                return None               # still re-joining; see RESUME_SETTLE_S
            else:
                # Never answered since waking. Count it, from the end of the
                # settle rather than from samples taken while re-joining.
                state = state._replace(
                    run_since=max(state.run_since, self.settle_until))
        if state.ok:
            began, lost = self.run_since, self.lost
            self.run_since, self.lost = None, 0
            if self.down_since is not None:
                self.down_since = None
                return "up"
            if (began is not None and lost >= MIN_LOST_SAMPLES
                    and state.ts - began >= DISRUPTION_AFTER_S):
                self.blip = (began, state.ts)
                return "disruption"
            return None
        # The run began when the packets started going missing, not when we
        # noticed: keep the earliest start seen for this run.
        if self.run_since is None or state.run_since < self.run_since:
            self.run_since = state.run_since
        self.lost = max(self.lost, state.lost)
        if (self.down_since is None and self.lost >= MIN_LOST_SAMPLES
                and now - self.run_since >= OUTAGE_AFTER_S):
            self.down_since = self.run_since
            return "down"
        return None


class LegArbiter:
    """What a leg going quiet MEANS, given whether anything beyond it answered.

    A run of losses on one leg is not the same event as the internet being
    gone. The evidence that separates them is already in hand: if anything
    past this leg is still answering, packets are crossing it, so it is not
    unreachable — it is merely refusing our probes. That opens a warn-toned
    "quiet" event (`QUIET_KIND`) instead of an outage: logged, excluded from
    outage_stats, no notification, the bar stays calm. Only every path
    falling silent opens a real `outage`, which alarms once it has lasted
    NOTIFY_AFTER_S.

    Escalation is one-way. If the far side goes quiet too during a quiet
    spell, the quiet event closes and a real outage opens, because an outage
    that begins mid-spell must still alarm. Nothing walks back the other
    way: flapping between verdicts would teach people to ignore both.

    The two legs differ only in wording — which kind, which detail, which
    notification — so those are class attributes and the mechanism is shared.
    Until 0.2.16 this was two classes that had been copied and string-edited
    apart, which is exactly how 0.2.4's gateway-quiet reached the store
    correctly and the Events tab not at all: a fix to one copy that missed
    the other.
    """

    LEG = None            # "wan" | "local"
    QUIET_KIND = None     # "icmp-quiet" | "gateway-quiet" (names predate the
    QUIET_DETAIL = None   # bench/arbiter; not worth a stored-value migration)
    OUTAGE_DETAIL = None
    ALARM = None          # (summary, body) when a real outage is declared
    RECOVERED = None      # (summary, body) when a real outage recovers

    def __init__(self, store, notify):
        self.store = store
        self.notify = notify
        self.event_id = None
        self.kind = None          # QUIET_KIND | "outage" while down
        self._notify_at = None    # when the alarm becomes due
        self._notified = False    # whether it actually fired
        self._words = self.words()

    @property
    def real_outage(self) -> bool:
        return self.kind == "outage"

    @property
    def leg(self) -> str:
        """The leg the current (or last) event was opened on."""
        return self._words[0]

    def words(self):
        """(leg, outage detail, alarm, recovery) for an event opened now."""
        return self.LEG, self.OUTAGE_DETAIL, self.ALARM, self.RECOVERED

    def down(self, now, beyond_ok: bool, since=None):
        # `since` is when the silence began; the row carries the onset, not
        # the tick that crossed the threshold.
        began = int(since if since is not None else now)
        # Fixed when the event opens: an outage that began through a VPN is
        # announced and recovered in the VPN's words even if the tunnel is
        # gone by the time it ends.
        self._words = self.words()
        leg, outage_detail = self._words[0], self._words[1]
        if beyond_ok:
            self.kind = self.QUIET_KIND
            self.event_id = self.store.open_event(
                began, self.QUIET_KIND, "warn", leg, self.QUIET_DETAIL)
            return
        self.kind = "outage"
        self.event_id = self.store.open_event(
            began, "outage", "critical", leg, outage_detail)
        # Logged now, alarmed only if it lasts — see NOTIFY_AFTER_S.
        self._notify_at = now + NOTIFY_AFTER_S
        self._notified = False

    def tick(self, now, beyond_ok: bool):
        if self.kind == self.QUIET_KIND and not beyond_ok:
            self.store.close_event(self.event_id, int(now))
            self.down(now, False)
            return
        if (self.kind == "outage" and not self._notified
                and self._notify_at is not None and now >= self._notify_at):
            self._notified = True
            alarm = self._words[2]
            self.notify(alarm[0], alarm[1], True)

    def up(self, now):
        if self.event_id is not None:
            self.store.close_event(self.event_id, int(now))
            # Only say it came back if we said it went away. A recovery
            # notice with no matching alarm is a message about nothing.
            if self.kind == "outage" and self._notified:
                recovered = self._words[3]
                self.notify(recovered[0], recovered[1])
        self._clear()

    def lost_sight(self, watched_until):
        """Watching stopped with this event open (UNWATCHED_AFTER_S). Close it
        where we last saw it, not when watching resumed: what happened in
        between is unknown, and closing it at wake charged the whole sleep.
        No recovery notice, and a pending alarm is dropped — nothing was
        seen to recover, and an alarm raised on waking would be about a
        silence nobody observed."""
        if self.event_id is not None:
            self.store.close_event(self.event_id, int(watched_until))
        self._clear()

    def _clear(self):
        self.event_id = None
        self.kind = None
        self._notify_at = None
        self._notified = False


class WanEventArbiter(LegArbiter):
    """The internet leg. `beyond_ok` here means some instrument still
    answered: an ISP or middlebox that stops answering one probe while
    others still flow used to be recorded — notified, charged to Reliability
    — as an outage the user never experienced. See LegArbiter."""

    LEG = "wan"
    QUIET_KIND = "icmp-quiet"
    QUIET_DETAIL = ("Scored probes went quiet; another instrument on "
                    "the same path kept answering")
    OUTAGE_DETAIL = "router answers, nothing past it does"
    ALARM = ("No internet",
             "The router answers but nothing past it does — "
             "the fault is on the ISP side.")
    RECOVERED = ("Internet recovered", "Replies from the internet again.")

    # While the internet probes go through a VPN, what goes silent past the
    # router is the tunnel or its server, and nothing may name the ISP for it
    # [D, Plamen, 2026-09-13]. Stored on its own leg, because the Events tab
    # words every `wan` outage as "the fault was upstream". Still charged to
    # Reliability: it is the connection the user has.
    TUNNEL_LEG = "tunnel"
    TUNNEL_OUTAGE_DETAIL = "VPN tunnel silent; the router answered"
    TUNNEL_ALARM = ("No connection through the VPN",
                    "The router answers; the tunnel or its server does not.")
    TUNNEL_RECOVERED = ("VPN connection recovered",
                        "Replies through the tunnel again.")
    tunnel = False          # set by the daemon each pass from its VPN state

    def words(self):
        if self.tunnel:
            return (self.TUNNEL_LEG, self.TUNNEL_OUTAGE_DETAIL,
                    self.TUNNEL_ALARM, self.TUNNEL_RECOVERED)
        return super().words()


class LocalEventArbiter(LegArbiter):
    """The local leg. `beyond_ok` here means something past the gateway
    answered, so packets are crossing it and it is not unreachable — just
    refusing pings, which hotel and captive networks routinely do. This is
    0.1.17's wan arbitration applied to the leg it had never covered. See
    LegArbiter."""

    LEG = "local"
    QUIET_KIND = "gateway-quiet"
    QUIET_DETAIL = ("Router stopped answering pings; traffic through it "
                    "kept working")
    OUTAGE_DETAIL = "router unreachable"
    ALARM = ("Router unreachable",
             "Nothing on the local network is answering.")
    RECOVERED = ("Local network recovered",
                 "The router is answering again.")


class IntervalEvent:
    """A state with a start and an end — a VPN, a phone hotspot — as one
    event row, rather than a fault.

    `update(now, detail)` is called with the state's current description, or
    None when the state is absent; a different description closes the old
    row and opens a new one, so a full tunnel becoming a partial one reads as
    two spans. Like the arbiters, it closes at the last watched moment across
    an unwatched gap and opens again on the next update if the state is still
    there, so a night asleep on a VPN is two spans with nothing in between.
    """

    def __init__(self, store, kind, severity, leg):
        self.store = store
        self.kind, self.severity, self.leg = kind, severity, leg
        self.event_id = None
        self.detail = None

    def update(self, now, detail) -> bool:
        """Returns whether anything changed."""
        if detail == self.detail:
            return False
        if self.event_id is not None:
            self.store.close_event(self.event_id, int(now))
            self.event_id = None
        if detail:
            self.event_id = self.store.open_event(
                int(now), self.kind, self.severity, self.leg, detail)
        self.detail = detail
        return True

    def lost_sight(self, watched_until):
        if self.event_id is not None:
            self.store.close_event(self.event_id, int(watched_until))
        self.event_id = None
        self.detail = None


class LookupWatch:
    """Names have stopped resolving while the internet still answers.

    Every leg can read healthy while nothing opens: on 2026-09-14 a resolver
    went away on a working line (HopSense's pilot house, eight minutes), the
    router and every instrument answered by address, and the laptop could not
    turn one name into an address. The index said 95. Nexthop would have said
    the same, because every probe it scores is sent to an address — and a day
    later it would have called the trace fetch failing on the name a sign-in
    page (CaptiveWatch).

    The evidence is already being gathered: the two named TCP instruments look
    their host up on every sample (NameLookup), so this reads their outcomes
    and adds no traffic. HopSense's rule, kept identical so the two can be
    compared:

    - a `dns-failing` interval opens once FAIL_RUN consecutive lookups have
      failed across at least FAIL_SPAN_S, dated from the first failure, and
      only while some instrument still answers — otherwise it is an outage,
      which the leg watches own. It closes on the first answer;
    - it is armed only once a lookup has answered on this network (probes are
      rebuilt on a network change, and so is this). A network whose resolver
      filters or blocks these names from the start therefore never raises a
      permanent false alarm — and that same "never answered here" is what
      lets CaptiveWatch keep treating a portal that blocks DNS as a portal;
    - never while a leg is in a confirmed outage: the run is dropped, not
      back-dated, and an open interval closes when the outage is confirmed;
    - not inside the wake window (RESUME_SETTLE_S) — lookups fail while the
      Wi-Fi re-joins — and closed at the last watched moment across a gap;
    - closed at the newest outcome if outcomes stop arriving for STALE_S.

    Observed, never scored: not charged to Reliability (outage_stats counts
    outages and disruptions only), and the index keeps standing, because the
    line it describes is working. The state says what is not.
    """

    FAIL_RUN = 3
    FAIL_SPAN_S = 10.0
    # Both named instruments benched is the slowest outcomes can arrive: one
    # sample each per STANDBY_FACTOR probe intervals, collecting the lookup the
    # previous sample started, which may itself have waited out its deadline.
    # Two such gaps with nothing is a watch that stopped.
    STALE_S = 2 * TCP_PROBE_INTERVAL_S * STANDBY_FACTOR + NameLookup.DEADLINE_S
    KIND = "dns-failing"
    DETAIL = "Name lookups failing; the internet answered by address"

    def __init__(self, store):
        self.store = store
        self.event_id = None
        self.since = None           # onset of the open interval
        self.answered = False       # a lookup has answered on this network
        self.last_ok = None
        self.newest = None          # newest outcome read
        self.refuse_until = None    # the wake window
        self._run_since = None
        self._run_n = 0
        self._cursor = {}           # NameLookup -> newest stamp read from it

    @property
    def failing(self) -> bool:
        return self.since is not None

    def feed(self, now: float, lookups, answering: bool, legs_down: bool):
        """One pass: read what the lookups recorded since the last one.

        `answering`: some instrument heard the internet just now. `legs_down`:
        either leg is in a confirmed outage."""
        fresh = []
        for lookup in lookups:
            last = self._cursor.get(lookup)
            got = [o for o in list(lookup.outcomes) if last is None or o[0] > last]
            if got:
                self._cursor[lookup] = got[-1][0]
                fresh.extend(got)
        fresh.sort()
        if fresh:
            self.newest = max(self.newest or fresh[-1][0], fresh[-1][0])
        if legs_down:
            self._close(now)
            self._drop_run()
            for ts, ok in fresh:
                if ok:
                    self.answered = True
                    self.last_ok = ts
            return
        for ts, ok in fresh:
            if ok:
                self.answered = True
                self.last_ok = ts
                self.refuse_until = None
                self._drop_run()
                self._close(ts)
                continue
            if not self.answered:
                continue
            if self.refuse_until is not None and ts < self.refuse_until:
                continue
            if self._run_since is None:
                self._run_since = ts
            self._run_n += 1
            if (self.since is None and answering
                    and self._run_n >= self.FAIL_RUN
                    and ts - self._run_since >= self.FAIL_SPAN_S):
                self.since = int(self._run_since)
                self.event_id = self.store.open_event(
                    self.since, self.KIND, "warn", "", self.DETAIL)
        if self.since is not None and self.newest is not None \
                and now - self.newest > self.STALE_S:
            self._close(self.newest)
            self._drop_run()

    def lost_sight(self, watched_until: float, resumed_at: float,
                   settle_s: float = RESUME_SETTLE_S):
        """Watching stopped (UNWATCHED_AFTER_S): close where it stopped, and
        refuse the failures of re-joining the network after it."""
        self._close(watched_until)
        self._drop_run()
        self.refuse_until = resumed_at + settle_s

    def reset(self, now: float):
        """A new network, new probes: what failed belonged to the old one."""
        self._close(now)
        self._drop_run()
        self.answered = False
        self._cursor = {}

    def snapshot(self):
        if self.newest is None and self.since is None:
            return None
        return {"failing": self.failing, "since": self.since,
                "answered": self.answered,
                "last_ok_ts": round(self.last_ok) if self.last_ok else None}

    def _drop_run(self):
        self._run_since = None
        self._run_n = 0

    def _close(self, at: float):
        if self.since is None:
            return
        if self.event_id is not None:
            # Integer seconds, and never an empty span: a row whose end is
            # not after its start reads as an instant.
            self.store.close_event(self.event_id,
                                   max(int(at), self.since + 1))
        self.event_id = None
        self.since = None


class CaptiveWatch:
    """Are we behind a sign-in page rather than on the internet?

    A probe reply proves a packet came back; it does not prove what sent it.
    So this asks for two things at once and only claims interception when it
    has both: something IS answering our probes, and the reachability check
    cannot prove the real internet answered. Packets going somewhere, but
    not to the internet, is what a captive portal looks like from here.

    Neither half is enough alone. Probes answering with no reachability check
    is the state we were in before, and it read as a healthy internet. A
    failed check with nothing answering is simply no internet, which the
    wan arbiter already handles — calling that "captive" would put a sign-in
    prompt in front of a user whose line is down.

    Confirmation takes two consecutive checks, because one failed fetch is a
    failed fetch. The decision itself is pure so it can be argued with and
    tested; only the fetching is not.

    The fetch runs OFF the loop and on suspicion, not on a clock. `tick()`
    starts a check when one is due and collects the result on a later tick;
    it never waits. Until 0.2.13 it ran the curl inline every 30 s for as
    long as anything answered — i.e. always — which stalled the bar for up
    to 8 s on exactly the slow networks this exists for, and cost 2,880
    fetches a day where the WAN-address fetch it duplicated cost 24. Now: a
    check on every new network and whenever the internet comes back; every
    30 s only while the last answer was not proof of the internet; hourly
    once it was. That hourly check is also where the WAN address comes
    from, so the separate fetch is gone.
    """

    # While a sign-in page is suspected, re-check soon.
    CHECK_EVERY_S = 30.0
    # Once the real internet has answered, once an hour keeps the address
    # fresh and would notice a portal that appears mid-session.
    RECHECK_OPEN_S = 3600.0
    CONFIRM_AFTER = 2

    def __init__(self, check, spawn=None):
        self._check = check        # injected: () -> {"verdict", "proof"}
        # How a check is run. Off the loop by default; tests pass a
        # synchronous spawn so the result lands within the same tick.
        self._spawn = spawn or self._in_thread
        self._lock = threading.Lock()
        self._pending = None       # (generation, result) awaiting a tick
        self._inflight = False
        self._gen = 0              # bumped by request(): stale results drop
        self.verdict = "unknown"
        self.proof = None
        self.checked_ts = None
        self.strikes = 0
        self._next = 0.0
        self._confirmed = False
        # (lookups answered on this network, lookups failing now), from
        # LookupWatch each tick.
        self._names = (False, False)

    @staticmethod
    def _in_thread(fn):
        threading.Thread(target=fn, name="reach", daemon=True).start()

    @staticmethod
    def explained_by_names(verdict: str, names_answered: bool,
                           names_failing: bool) -> bool:
        """Is a failed check just names failing to resolve, not a portal?

        A resolver dying on a working line gives CaptiveWatch both of its
        halves — probes answering by address, the fetch failing on the name —
        and until 0.2.47 that was called SIGN-IN REQUIRED. Two cases say it is
        not a portal. curl reporting that the name did not resolve
        (`unresolved`) on a network where names HAVE resolved: a portal that
        blocks DNS does so from the moment you join, before anything answers.
        And, for curl's own timeout, which is also what a lookup stuck in a
        dead resolver looks like, LookupWatch already holding an open failure.
        An `intercepted` answer is never explained: a name resolved and
        something that is not the internet answered it.
        """
        if verdict == "unresolved":
            return names_answered or names_failing
        return verdict == "silent" and names_failing

    @staticmethod
    def captive(verdict: str, probes_answering: bool, strikes: int,
                names_answered: bool = False,
                names_failing: bool = False) -> bool:
        """The whole claim, in one place: replies but no proof of internet."""
        return (probes_answering
                and verdict in ("intercepted", "silent", "unresolved")
                and strikes >= CaptiveWatch.CONFIRM_AFTER
                and not CaptiveWatch.explained_by_names(
                    verdict, names_answered, names_failing))

    @property
    def confirmed(self) -> bool:
        return self._confirmed

    def request(self):
        """A new network, or the internet just came back: start over.

        The old verdict described a different situation, and a check still
        in flight for it must not be mistaken for an answer about this one.
        """
        self._gen += 1
        self._inflight = False
        self._next = 0.0
        self.verdict = "unknown"
        self.proof = None
        self.strikes = 0
        self._confirmed = False

    def tick(self, now: float, probes_answering: bool,
             names_answered: bool = False, names_failing: bool = False):
        self._names = (names_answered, names_failing)
        self._collect(now)
        if not probes_answering:
            # Nothing is answering at all: not our verdict to make. Drop the
            # suspicion rather than carrying it into a real outage.
            self.strikes = 0
            self._confirmed = False
            return
        if self._inflight or now < self._next:
            self._confirmed = self.captive(
                self.verdict, probes_answering, self.strikes, *self._names)
            return
        self._inflight = True
        gen = self._gen
        self._spawn(lambda: self._run(gen))
        # A synchronous spawn has already delivered; a thread delivers to a
        # later tick.
        self._collect(now)

    def _run(self, gen: int):
        try:
            result = self._check() or {"verdict": "silent", "proof": None}
        except Exception:
            result = {"verdict": "silent", "proof": None}
        with self._lock:
            self._pending = (gen, result)
            self._inflight = False

    def _collect(self, now: float):
        with self._lock:
            pending, self._pending = self._pending, None
        if pending is None:
            return
        gen, result = pending
        if gen != self._gen:
            return                 # answered a question we stopped asking
        self.verdict = result.get("verdict") or "silent"
        self.proof = result.get("proof")
        if self.verdict == "open":
            self.strikes = 0
        elif not self.explained_by_names(self.verdict, *self._names):
            self.strikes += 1
        self.checked_ts = round(now)
        self._next = now + (self.RECHECK_OPEN_S if self.verdict == "open"
                            else self.CHECK_EVERY_S)
        self._confirmed = self.captive(self.verdict, True, self.strikes,
                                       *self._names)

    def snapshot(self) -> dict:
        if self.verdict == "unknown":
            return None
        return {"verdict": self.verdict, "captive": self._confirmed,
                "checked_ts": self.checked_ts}


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class LinkCollector(threading.Thread):
    """Reads the local end — route, interface, Wi-Fi link and station — on
    its own thread, and keeps the latest snapshot for the loop to read.

    net.snapshot() is three subprocesses (ip, iw link, iw station): about
    10 ms when all is well, and up to their 2 s timeouts EACH when it is
    not — a laptop coming out of suspend fails all of them at once, and
    the loop that owns the outage watch used to wait for every one, twice
    a second. Now it reads a dict. The first snapshot is taken
    synchronously in start(), so there is always one to read.

    A snapshot is never "too old" to hand out: if this thread is stuck
    behind a wedged `iw`, the loop keeps the last known link, which is
    what a timed-out read produced before as well — only now the loop
    does not stop for it.
    """

    INTERVAL_S = 0.5
    # How often every probe target's route is re-checked for a tunnel when
    # nothing prompted it. The anchor's own route is read twice a second as
    # part of the snapshot, so a full tunnel coming up or down is seen at
    # once; this cadence is for a split tunnel that leaves the anchor alone.
    TUNNEL_CHECK_S = 60.0

    def __init__(self, anchor_fn, snapshot_fn=None, interval_s=INTERVAL_S,
                 targets_fn=None, tunnel_fn=None, clock=time.monotonic):
        super().__init__(name="link", daemon=True)
        self._anchor_fn = anchor_fn
        self._snapshot = snapshot_fn or net.snapshot
        self.interval = interval_s
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._latest = {}
        self.taken_at = 0.0
        # VPN detection is off unless the daemon says what to look at.
        self._targets_fn = targets_fn
        # Never a name lookup on this thread, whatever reaches it: a target
        # without an address is left out rather than waited for. The daemon
        # hands over addresses (Daemon._probe_targets); this is the backstop.
        self._tunnel = tunnel_fn or (lambda targets, iface: net.tunnel_routes(
            targets, iface, resolve=net.no_lookup))
        self._clock = clock
        self._vpn = None
        self._checked = None       # (monotonic time, tunnel_iface, iface) of the last check

    def _check_tunnel(self, snap):
        """Re-read which probes go through a tunnel, when it may have changed.

        Also when the set of instruments with an address changes: at start
        the probes have not resolved anything yet, and without this the first
        check with every address in hand would wait for the minute. Keyed on
        which instruments have one, not on the addresses — an anycast name
        whose answers rotate would otherwise re-check twice a second."""
        now = self._clock()
        try:
            targets = self._targets_fn()
        except Exception:          # noqa: BLE001 — a collector never raises into the daemon
            return
        key = (snap.get("tunnel_iface") or "", snap.get("iface") or "",
               tuple(sorted(targets)))
        if self._checked is not None and self._checked[1:] == key \
                and now - self._checked[0] < self.TUNNEL_CHECK_S:
            return
        self._checked = (now,) + key
        try:
            self._vpn = self._tunnel(targets, snap.get("iface") or "")
        except Exception:          # noqa: BLE001 — a collector never raises into the daemon
            pass                   # keep the last answer, as a failed snapshot does

    def _take(self):
        try:
            snap = self._snapshot(self._anchor_fn())
        except Exception:          # noqa: BLE001 — a collector never raises into the daemon
            return
        snap = snap if isinstance(snap, dict) else {}
        if self._targets_fn is not None:
            self._check_tunnel(snap)
            snap["vpn"] = self._vpn
        with self._lock:
            self._latest = snap
            self.taken_at = time.time()

    def start(self):
        self._take()
        super().start()

    def run(self):
        while not self._stop.wait(self.interval):
            self._take()

    def stop(self):
        self._stop.set()

    @property
    def latest(self) -> dict:
        """A copy: callers annotate it (retry_pct) and must not share."""
        with self._lock:
            snap = dict(self._latest)
        if isinstance(snap.get("station"), dict):
            snap["station"] = dict(snap["station"])
        return snap


class Daemon:
    def __init__(self):
        self.state_dir = ensure_state_dir()
        ensure_runtime_dir()
        self.config = Config(self.state_dir)
        self.config.refresh()
        self.store = Store(db_path())
        self.local = Series()
        # The internet leg is measured by a bench of instruments — see
        # instruments.py. Each instrument feeds its own Series; the scored
        # series (self.total) is a merged view over whichever two hold the
        # seats, so every consumer downstream keeps reading one "internet
        # leg". The anchor's ICMP series keeps a name of its own too: the
        # minute rows record what ICMP alone would have scored (`lag_icmp`).
        self.bench = Bench(self._instrument_pool())
        self._instrument_series = {}
        self._instrument_probes = {}
        self._new_instrument_series()
        self.total = MergedSeries(self._active_series)
        self._last_bench_eval = 0.0
        self.probes = []
        self._local_probe = None
        # (anchor, interval) the running probes were built from, so a
        # settings change is noticed on the next tick — see
        # restart_probes_if_settings_changed.
        self._probe_settings = None
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
        # Elapsed-time gate for the 5 s flush. It used to be `int(now) % 5
        # == 0`, which is true on BOTH half-second ticks of a qualifying
        # second, so the ring filled twice as fast and the Wi-Fi and
        # throughput charts held ~17 min under a 30-minute label.
        self.last_recent_flush = 0.0
        self.last_signal = None
        self.watch_local = LegWatch()
        self.watch_wan = LegWatch()
        self.wan_events = WanEventArbiter(self.store, self.notify)
        self.local_events = LocalEventArbiter(self.store, self.notify)
        self._watched = None       # (wall, awake_clock) of the last watch pass
        self.captive = CaptiveWatch(net.reachability)
        self.lookup_watch = LookupWatch(self.store)
        # Is this connection someone's phone sharing its data? Recomputed
        # whenever the route changes, which is the only thing that can
        # change the answer.
        self.metered = None
        # Whether the internet probes go through a VPN, and since when — see
        # follow_path_states. None when they do not.
        self.vpn = None
        self.vpn_events = IntervalEvent(self.store, "vpn", "info", "tunnel")
        self.tether_events = IntervalEvent(self.store, "tether", "info", "local")
        # [start, end or None] while a tunnel carried the probes, kept long
        # enough to flag every point of the 30-minute recent.json.
        self._vpn_spans = deque(maxlen=64)
        # The address this connection appears from — live.json only, never
        # recent.json or history: shown, not archived.
        self.wan_ip = None
        # checked_ts of the reachability result the address came from, so
        # one proof is not re-adopted every tick.
        self._wan_ip_at = 0
        # Who ended each Wi-Fi association — read from nl80211 via `iw
        # event`, unprivileged. Without it the link log still works; it
        # just cannot tell a kick from a roam.
        self.nl_events = linkevents.NlEvents()
        self.link_watch = LinkWatch(self.store, self.nl_events)
        # Notify-only: asks origin whether this checkout is behind and
        # never touches it. Off when the user turns updateCheck off.
        self.update_watch = UpdateWatch(enabled=bool(self.config["updateCheck"]))
        self.app_traffic = apps.AppTraffic()
        # The local end, read off the loop — see LinkCollector.
        self.link = LinkCollector(lambda: self.config["internetAnchor"],
                                  targets_fn=self._probe_targets)
        self.last_apps_poll = 0.0
        self.last_content_test = 0.0
        # Set while a due content check is waiting for the link to settle.
        self._check_waiting_since = None
        self.last_minute_flush = 0.0
        self.last_rollup = 0.0
        self.peak_requested = threading.Event()
        self.peak_running = False
        self.content_running = False
        self._content_retry_used = False
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

    def _probe_targets(self) -> dict:
        """Instrument key -> the address its probes are sent to, for the tunnel
        check. Read on the link thread.

        The address each TCP probe actually connects to, from its own lookup
        (NameLookup), rather than a name to be resolved again. Until 0.2.48
        this handed tunnel_routes the host names and it looked them up there,
        synchronously and with no deadline, on the thread that takes the link
        snapshot — so a silent resolver (glibc: two 5 s attempts a name) held
        the route and Wi-Fi reading ~20 s once a minute, and held the daemon's
        start, whose first snapshot is taken on the main thread. HopSense's
        port found the same shape in its own rebuild; this one came to light
        from theirs.

        An instrument whose probe has no address yet is left out, as an
        unresolvable one always was; the ICMP anchor, when it is a name, takes
        the address the TCP probe to the same host resolved.
        """
        probes = dict(self._instrument_probes)   # the loop replaces it on a rebuild
        resolved = {}
        for p in probes.values():
            if isinstance(p, TcpProbe) and p.lookup.addresses:
                resolved[p.target] = p.lookup.addresses[0]
        out = {}
        for key, kind, target in self._instrument_pool():
            host = target.rsplit(":", 1)[0] if kind == "tcp" else target
            address = host if _is_address(host) else resolved.get(host)
            if address:
                out[key] = address
        return out

    def _new_instrument_series(self):
        self._instrument_series = {
            key: Series() for key, _, _ in self._instrument_pool()}
        # The name the rest of the daemon has always read.
        self.icmp_anchor = self._instrument_series["icmp-anchor"]

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
        self.route = net.local_route(anchor)
        # Answer this before the first content check can be due, not only
        # when the route later changes — a daemon started on a hotspot must
        # not spend a check to find out it is on one.
        self.refresh_metered()
        interval = int(self.config["probeIntervalMs"])
        self._probe_settings = (anchor, interval)
        gw = self.route.get("gateway", "")
        self._local_probe = None
        if gw:
            p = PingProbe(gw, self.local, interval, "local",
                          loaded_fn=lambda: self.link_loaded)
            p.start()
            self.probes.append(p)
            self._local_probe = p
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

    def restart_probes_if_route_changed(self, fresh=None):
        """New default route (roamed networks, docked, VPN up) — new targets.

        `fresh` is a route already read (see follow_route); without one it
        is read here."""
        if fresh is None:
            fresh = net.local_route(self.config["internetAnchor"])
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
        self._rebuild_probes(fresh)

    def follow_path_states(self, now: float):
        """Turn what the link thread found into state, once per pass: whether
        the internet probes go through a VPN, and whether the link is a phone.

        Detection is the link thread's (net.tunnel_routes); this owns what
        follows from it. The `vpn` and `tether` spans. The words the internet
        arbiter will use for an outage opened from here on. And a fresh
        reachability check when the tunnel appears, goes or moves: the public
        address from before belongs to the other side of the change, and
        showing a VPN exit's address as the line's (or the line's as the
        tunnel's) is exactly the attribution this exists to prevent.
        """
        found = self.link.latest.get("vpn") if self.link else None
        prev = self.vpn
        if found and prev and (found["iface"], found["scope"]) == \
                (prev["iface"], prev["scope"]):
            self.vpn = dict(found, since=prev["since"])
        else:
            self.vpn = dict(found, since=int(now)) if found else None
        moved = bool(found) != bool(prev) or \
            bool(found and prev and found["iface"] != prev["iface"])

        detail = None
        if self.vpn:
            detail = ("Measured through a VPN (%s)" if self.vpn["scope"] == "full"
                      else "Partly measured through a VPN (%s)") % self.vpn["iface"]
        self.vpn_events.update(now, detail)
        self.wan_events.tunnel = bool(self.vpn)

        m = self.metered
        self.tether_events.update(
            now, ("Measured through a hotspot (%s)" % m["label"])
            if m and m.get("tethered") else None)

        if bool(found) != bool(prev):
            if found:
                self._vpn_spans.append([now, None])
            elif self._vpn_spans and self._vpn_spans[-1][1] is None:
                self._vpn_spans[-1][1] = now
        if moved:
            self.wan_ip = None
            self._wan_ip_at = 0
            self.captive.request()
            # Speed is kept per (network, tunnel), so the other side of the
            # change may have no check at all; measure it soon, after the
            # same settle a network change gets.
            self._content_boost_at = now + 90

    def _lose_sight_of_path_states(self, watched_until):
        """An unwatched gap ends every open span where watching stopped; the
        next pass opens them again if the state is still there."""
        self.vpn_events.lost_sight(watched_until)
        self.tether_events.lost_sight(watched_until)
        if self._vpn_spans and self._vpn_spans[-1][1] is None:
            self._vpn_spans[-1][1] = watched_until
        self.vpn = None

    def vpn_identity(self):
        """What minute rows and speed checks store as the tunnel: `iface`, or
        `iface@EDGE` once the trace through it has named the Cloudflare edge.
        None when the probes are not going through one. See vpn_matches."""
        vpn = getattr(self, "vpn", None)
        if not vpn:
            return None
        edge = (getattr(self, "wan_ip", None) or {}).get("edge")
        return vpn["iface"] + ("@" + edge if edge else "")

    def vpn_during(self, a: float, b: float) -> bool:
        """Did a tunnel carry the probes at any point in [a, b)?"""
        for start, end in self._vpn_spans:
            if start < b and (end is None or end > a):
                return True
        return False

    def tunnel_bands(self, now: float):
        """The tunnel leg's usual level and thresholds (score.tunnel_bands),
        cached for a minute — it moves at minute-row cadence."""
        ident = self.vpn_identity()
        if not ident:
            return None
        cache = getattr(self, "_tunnel_bands_cache", None)
        if cache and cache[1] == ident and now - cache[0] < 60:
            return cache[2]
        try:
            med, p90, n = self.store.tunnel_level(ident, now=now)
            bands = score.tunnel_bands(med, p90, n)
        except Exception:
            bands = None
        self._tunnel_bands_cache = (now, ident, bands)
        return bands

    def follow_route(self):
        """Rebuild the probes on the tick a new gateway appears.

        The link thread already reads the route twice a second, so the loop
        compares against that instead of running `ip route get` itself. It
        used to do that once a minute, at the minute flush, and until then
        the router leg kept pinging the PREVIOUS network's gateway: every
        wake on a different network than the one the laptop slept on logged
        61 s of "router unreachable" — ten of ten such wakes here, against
        5-7 s for every wake on the same network (#6). Switching networks
        while awake paid the same minute.
        """
        snap = self.link.latest
        self.restart_probes_if_route_changed(
            {k: snap.get(k) or "" for k in ("iface", "gateway", "src")})

    def restart_probes_if_settings_changed(self):
        """The anchor or the probe interval changed under us.

        Both used to be read only when probes were built, so a change sat
        unapplied until the next network change or restart while the panel
        said settings apply live. An interval change is applied in place —
        the distributions stay valid, only the cadence moves. A new anchor
        rebuilds the probes: half the instruments now point somewhere else,
        and their old samples describe a host nobody is measuring any more.
        """
        if self._probe_settings is None:
            return                       # probes not started yet
        anchor = self.config["internetAnchor"]
        interval = int(self.config["probeIntervalMs"])
        if (anchor, interval) == self._probe_settings:
            return
        if anchor != self._probe_settings[0]:
            self._rebuild_probes(net.local_route(anchor))
            return
        self._probe_settings = (anchor, interval)
        if self._local_probe is not None:
            self._local_probe.set_interval(interval / 1000.0)
        self._apply_seats([(k, i.active)
                           for k, i in self.bench.instruments.items()])

    def _rebuild_probes(self, route: dict):
        """Stop every probe and start over against `route`: fresh network,
        fresh distributions. The bench keeps its seats — continuity until
        the new windows hold enough samples to argue about."""
        for p in self.probes:
            p.stop()
        self.probes.clear()
        self._instrument_probes = {}
        self.local = Series()
        self._new_instrument_series()
        self.route = route
        self.counter_samples = []
        # A new route means a new apparent address; drop the stale one
        # rather than display it wrong until the next check — and ask for
        # that check now: a new network is exactly where a sign-in page is
        # likeliest.
        self.wan_ip = None
        self._wan_ip_at = 0
        self.captive.request()
        lookups = getattr(self, "lookup_watch", None)
        if lookups is not None:
            lookups.reset(time.time())
        self.start_probes()

    def stop(self, *_):
        self.running = False

    # ------------------------------------------------------------ measuring

    def load_floor_bps(self, now: float) -> float:
        """Bytes per second above which this line counts as busy.

        A tenth of what the line has been measured to carry, floored. Read
        from the same baseline the Speed score uses — this network's own p90
        download — and cached for a minute, because it moves at content-check
        cadence and this is asked twice a second.
        """
        cache = getattr(self, "_load_floor_cache", None)
        if not cache or now - cache[0] > 60:
            snap = self.link.latest if self.link else {}
            network = snap.get("ssid") or snap.get("name") or ""
            try:
                baseline = self.store.baseline_speed(network=network, now=now,
                                                     fallback=False,
                                                     vpn=self.vpn_identity())
            except Exception:
                baseline = None
            floor = LOAD_FLOOR_BPS
            if baseline:
                floor = max(floor, baseline * 1e6 / 8 * LOAD_FRACTION_OF_LINE)
            cache = (now, floor)
            self._load_floor_cache = cache
        return cache[1]

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
                                    >= self.load_floor_bps(now))
            else:
                # Counter reset (interface bounced) — start the window over.
                self.counter_samples = [self.counter_samples[-1]]

    def notify(self, summary: str, body: str, urgent: bool = False):
        if not self.config["notifyOutage"]:
            return
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

    def watch_outages(self, now: float, awake: float = None):
        """Outage logic on each leg's probe stream (leg_state / LegWatch).

        The wan watch counts silence only when the local leg answered, or
        when the gateway is merely quiet (LocalEventArbiter): if the router
        is confirmed unreachable, the internet probes' losses say nothing
        about the ISP.

        Arbitration is judged on the run itself — did anything beyond the
        leg answer DURING the silence — not on a trailing window: a reply
        from just before a 1.5 s blip must not vouch for the blip.

        A pass that finds the previous one more than UNWATCHED_AFTER_S ago
        on `awake` (awake_clock(), injectable for tests) first tells both
        watches and both arbiters that watching stopped.
        """
        awake = awake_clock() if awake is None else awake
        if self._watched is not None and \
                awake - self._watched[1] > UNWATCHED_AFTER_S:
            watched_until = self._watched[0]
            for watch, events in ((self.watch_local, self.local_events),
                                  (self.watch_wan, self.wan_events)):
                watch.lost_sight(now)
                events.lost_sight(watched_until)
            self._lose_sight_of_path_states(watched_until)
            lookups = getattr(self, "lookup_watch", None)
            if lookups is not None:
                lookups.lost_sight(watched_until, now)
        self._watched = (now, awake)

        local = leg_state(self.local.since(LEG_STREAM_WINDOW_S), now)
        total = leg_state(self.total.since(LEG_STREAM_WINDOW_S), now)
        local_ok = None if local is None else local.ok

        if local is not None:
            move = self.watch_local.sample(local, now)
            if move == "down":
                # Is anything past the gateway answering? If so the gateway
                # is forwarding and merely refuses pings — see
                # LocalEventArbiter.
                since = self.watch_local.down_since
                self.local_events.down(
                    now, self._any_instrument_replied_between(since, now), since)
            elif move == "up":
                self.local_events.up(now)
            elif move == "disruption":
                self.record_disruption("local", self.watch_local)
            elif self.watch_local.down_since is not None:
                self.local_events.tick(
                    now, self._any_instrument_alive(OUTAGE_AFTER_S))

        # The wan watch normally ignores any window where the local leg lost
        # packets: if the router is unreachable, the internet probe's losses
        # say nothing about the ISP. But a gateway that merely refuses pings
        # is "lost" forever, and skipping the wan watch on such a link would
        # mean never noticing a real internet outage there. So the skip
        # applies to a confirmed local outage, not to a quiet gateway.
        gateway_quiet = (self.watch_local.down_since is not None
                         and not self.local_events.real_outage)
        if total is not None and (local_ok is not False or gateway_quiet):
            move = self.watch_wan.sample(total, now)
            if move == "down":
                # Did another instrument keep answering while the seated
                # pair fell silent? Samples are stamped at send time, so a
                # handshake that merely straddled the moment the line died
                # cannot vouch for the window after it.
                since = self.watch_wan.down_since
                self.wan_events.down(
                    now, self._any_instrument_replied_between(since, now), since)
            elif move == "up":
                self.wan_events.up(now)
                # The internet is back — or something answering for it is.
                # Ask the reachability check now rather than wait its hour.
                self.captive.request()
            elif move == "disruption":
                self.record_disruption("wan", self.watch_wan)
            elif self.watch_wan.down_since is not None:
                self.wan_events.tick(
                    now, self._any_instrument_alive(OUTAGE_AFTER_S))

    def record_disruption(self, leg: str, watch, beyond_ok=None):
        """A run that recovered before it became an outage.

        Arbitrated exactly like an outage: if something past this leg kept
        answering DURING the run, the leg did not interrupt anything — a
        gateway dropping three pings while traffic crosses it is not a
        disruption, and logging it would fill the log with noise the user
        never felt. `beyond_ok` is computed from the run's own interval
        unless a caller supplies it.
        """
        if not watch.blip:
            return
        began, ended = watch.blip
        watch.blip = None
        if beyond_ok is None:
            beyond_ok = self._any_instrument_replied_between(began, ended)
        if beyond_ok:
            return
        # Stored closed, with its duration, because Reliability charges
        # interruptions in time. Integer seconds are what the table holds,
        # so guarantee a non-zero span: outage_stats drops any row whose
        # end is not after its start, and a blip that vanished from the
        # score would be worse than one rounded up by a second.
        detail = "brief interruption, recovered on its own"
        if leg == "wan" and getattr(self, "vpn", None):
            # Through a VPN the interruption was the tunnel's, never the ISP's.
            leg, detail = ("tunnel",
                           "Brief interruption through the VPN, recovered on its own")
        eid = self.store.open_event(int(began), "disruption", "warn", leg, detail)
        self.store.close_event(eid, max(int(ended), int(began) + 1))

    def follow_lookups(self, now: float):
        """Feed LookupWatch what the named instruments' lookups recorded."""
        lookups = [p.lookup for p in self._instrument_probes.values()
                   if isinstance(p, TcpProbe) and not p.lookup.literal]
        legs_down = bool(
            (self.watch_local.down_since and self.local_events.real_outage)
            or (self.watch_wan.down_since and self.wan_events.real_outage))
        self.lookup_watch.feed(now, lookups,
                               self._any_instrument_alive(OUTAGE_AFTER_S),
                               legs_down)

    def _any_instrument_alive(self, window_s: float) -> bool:
        """Some instrument — seated or benched — heard the internet this
        recently. While a leg is down, the arbiters read this each tick to
        decide whether a quiet spell has become an outage."""
        for series in self._instrument_series.values():
            if any(s[1] is not None for s in series.since(window_s)):
                return True
        return False

    def _any_instrument_replied_between(self, a: float, b: float) -> bool:
        """Did some instrument hear the internet during [a, b]? Judged on the
        interval itself, so a reply from just before a run of silence cannot
        vouch for it — which a trailing window longer than the run would."""
        span = max(0.0, time.time() - a) + 1.0
        for series in self._instrument_series.values():
            for smp in series.since(span):
                if smp[1] is not None and a <= smp[0] <= b:
                    return True
        return False

    def adopt_wan_ip(self):
        """The address this connection appears from, taken from the
        reachability check's proof — the same fetch, so no second request
        and no second host learns the address. A check that could not prove
        the internet leaves the last answer standing: the route is what
        invalidates it, and the route path clears it."""
        proof, checked = self.captive.proof, self.captive.checked_ts
        if not proof or not checked or checked == self._wan_ip_at:
            return
        self._wan_ip_at = checked
        self.wan_ip = dict(proof, checked_ts=checked)

    def refresh_metered(self):
        """Tethering, or a connection the user has marked metered.

        Two independent signals, and neither is a guess: the gateway sitting
        in a range only tethering hands out, and NetworkManager being told
        so explicitly. Published so the panel can name the phone instead of
        drawing a router, and consulted before anything spends data.
        """
        gw = self.route.get("gateway", "")
        iface = self.route.get("iface", "")
        tether = net.tether_from_gateway(gw)
        explicit = net.nm_metered(iface)
        if not tether and not explicit:
            self.metered = None
            return
        self.metered = {
            "tethered": tether is not None,
            "kind": tether["kind"] if tether else "declared",
            # What to call the middle node of the path.
            "label": tether["label"] if tether else "Metered link",
            "explicit": explicit,
        }

    def maybe_content_test(self, now: float):
        if not self.config["contentSpeed"]:
            return
        interval = max(15, int(self.config["contentSpeedIntervalMin"])) * 60
        boost_at = getattr(self, "_content_boost_at", None)
        due = (now - self.last_content_test >= interval) or \
              (boost_at is not None and now >= boost_at)
        if not due:
            return
        # Skip while down — a failed transfer during an outage is not a
        # speed measurement, and skip while another test owns the line.
        if self.watch_wan.down_since or self.watch_local.down_since \
                or not self.tests_idle():
            return
        # Someone's phone is paying for this. The check is ~14 MB and runs
        # hourly, which is around 336 MB a day of a data plan the user did
        # not offer. Skipped rather than shrunk: a smaller sample would
        # still cost money and would measure worse. Speed then scores None
        # on this network, and the index already skips a component it does
        # not have rather than inventing one.
        if self.metered and self.config["meteredCare"]:
            return

        # Wait for a link worth measuring, but not forever — see check_ready.
        if not check_ready(now, self.link_watch.assoc_since,
                           self.link_watch.low_since,
                           self._check_waiting_since):
            if self._check_waiting_since is None:
                self._check_waiting_since = now
            return
        self._check_waiting_since = None
        self._content_boost_at = None
        self.last_content_test = now

        snap = self.link.latest
        network = snap.get("ssid") or snap.get("name") or ""
        tunnel_before = (self.vpn or {}).get("iface")
        self.content_running = True

        down_hint, up_hint = self._content_hint(network, self.vpn_identity())

        def run():
            try:
                r = speedtest.content_test(down_hint_mbps=down_hint,
                                           up_hint_mbps=up_hint)
                after = self.link.latest
                if (after.get("ssid") or after.get("name") or "") != network \
                        or (self.vpn or {}).get("iface") != tunnel_before:
                    # The network, or the tunnel, changed under the transfer,
                    # so the sample belongs to neither side. The change has
                    # already scheduled a fresh check of its own.
                    return
                if r["ok"]:
                    self.store.put_test(int(r["started"]), "content", r["engine"],
                                        down_mbps=r["down_mbps"], up_mbps=r["up_mbps"],
                                        bytes=r["bytes"], ok=True, network=network,
                                        vpn=self.vpn_identity())
                    # A fresh result should reprice the baseline promptly.
                    self._baseline_cache = None
                    self._content_retry_used = False
                elif not self._content_retry_used:
                    self._content_retry_used = True
                    self._content_boost_at = time.time() + CONTENT_RETRY_S
            finally:
                self.content_running = False

        threading.Thread(target=run, daemon=True, name="content-test").start()

    def _content_hint(self, network: str, vpn: str = None):
        """What this network has shown, so the next check can size itself.

        The best of the recent checks rather than the last. Sizing from a
        reading that happened to come in low would make the next transfer
        shorter, which reads lower again — a ratchet the floor alone would
        stop only at the bottom. The best recent reading is also the honest
        answer to "what can this line do", which is the question the size is
        being chosen against.

        None for a network with no history: the first check sends the cap and
        produces the hint that every check after it uses.
        """
        downs, ups = [], []
        for t in self.store.tests(limit=8, kind="content"):
            if not t["ok"] or (t["network"] or "") != network \
                    or not vpn_matches(t.get("vpn"), vpn):
                continue
            if t["down_mbps"]:
                downs.append(t["down_mbps"])
            if t["up_mbps"]:
                ups.append(t["up_mbps"])
        return (max(downs) if downs else None), (max(ups) if ups else None)

    def tests_idle(self) -> bool:
        """May a bandwidth test start? One at a time.

        Two saturating transfers invalidate each other's rate and share the
        probes' loaded-latency window. The scheduled check always yielded
        to a running peak; until 0.2.21 a peak did not yield to a running
        check, because nothing recorded that one was running.
        """
        return not (self.peak_running or self.content_running)

    def run_peak_test(self):
        """On demand, in its own thread; loaded latency comes from the probes."""
        if not self.tests_idle():
            return
        self.peak_running = True

        snap = self.link.latest
        network = snap.get("ssid") or snap.get("name") or ""
        vpn = self.vpn_identity()

        def run():
            try:
                idle = score.measured_lag(self.total.stats(60))
                started = time.time()
                r = speedtest.peak_test(self.config["peakEngine"])
                loaded_st = merged_stats([[s for s in lst if s[0] >= started]
                                          for lst in self.total.each()])
                loaded = (round(loaded_st["p50"], 1)
                          if loaded_st.get("p50") is not None else None)
                if r["ok"]:
                    self.store.put_test(
                        int(r["started"]), "peak", r["engine"],
                        down_mbps=r.get("down_mbps"), up_mbps=r.get("up_mbps"),
                        ping_idle=r.get("ping_idle") or idle, ping_loaded=loaded,
                        jitter=r.get("jitter"), bytes=r.get("bytes"),
                        server=r.get("server"), ok=True,
                        detail=r.get("url", ""), network=network, vpn=vpn)
                else:
                    self.store.put_test(int(r["started"]), "peak", r["engine"],
                                        ok=False, network=network, vpn=vpn)
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
        # Only checks through the tunnel the probes use now, or through none:
        # a VPN's checks describe the VPN, and the home line's must not be
        # judged against them (nor a plan against a tunnel's figure).
        vpn = self.vpn_identity()
        tests = [t for t in self.store.tests(limit=12, kind="content")
                 if t["ok"] and t["down_mbps"] is not None
                 and vpn_matches(t.get("vpn"), vpn)]

        plan_d = self.config["planDownMbps"]
        plan_u = self.config["planUpMbps"]
        if plan_d:
            if not tests:
                return None, {"basis": "plan", "plan_down": plan_d,
                              "last_down": None, "last_up": None,
                              "vpn": bool(vpn)}
            last = tests[0]
            spd = score.speed(last["down_mbps"], last["up_mbps"],
                              plan_d, plan_u or 0)
            return spd, {"basis": "plan", "plan_down": plan_d,
                         "plan_up": plan_u,
                         "last_down": last["down_mbps"],
                         "last_up": last["up_mbps"], "vpn": bool(vpn)}

        # Checks describe the network they ran on. A result from another
        # network says nothing about this one, so on a network with no
        # checks yet the component is honestly unknown (and the changed
        # network has already scheduled a prompt check).
        mine = [t for t in tests
                if (t.get("network") or "") == network] if network else tests
        if not mine:
            return None, {"basis": "auto", "baseline_down": None,
                          "last_down": None, "last_up": None,
                          "pending": True, "vpn": bool(vpn)}

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
        if not cache or now - cache[0] > 60 or cache[2] != (network, vpn):
            baseline = self.store.baseline_speed(network=network, now=now,
                                                 fallback=False, vpn=vpn)
            cache = (now, baseline, (network, vpn))
            self._baseline_cache = cache
        baseline = cache[1]
        spd = score.speed(down, up, baseline_down=baseline)

        # A saturating test of the same line, run recently and by hand, is
        # better evidence of what the line can do than a 12 MB sample. It
        # still does not become the score — a manual test must not flatter
        # it — but it can withdraw a figure it contradicts.
        peak_down = None
        for t in self.store.tests(limit=6, kind="peak"):
            if not t["ok"] or t["down_mbps"] is None:
                continue
            if network and (t.get("network") or "") != network:
                continue
            if not vpn_matches(t.get("vpn"), vpn):
                continue
            if now - t["ts"] > PEAK_FRESH_S:
                break
            peak_down = t["down_mbps"]
            break

        scored = score.speed_scored(down, len(recent), peak_down)
        return spd, {"basis": "auto", "baseline_down": baseline,
                     "last_down": down, "last_up": up,
                     "samples": len(recent), "scored": scored,
                     "peak_down": peak_down, "vpn": bool(vpn)}

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
        # Split each seated instrument's own stream by load, then merge the
        # idle halves and the loaded halves with the instruments counting
        # equally — see merged_stats for why the pooled stream may not be
        # fed to Series.stats.
        lists = self.total.each(window_s)
        splits = [Series.split_by_load(lst) for lst in lists]
        idle_st = merged_stats([sp[0] for sp in splits])
        loaded_st = merged_stats([sp[1] for sp in splits])
        n_idle, n_loaded = idle_st["count"], loaded_st["count"]
        # measured_lag, not lag_ms: a half in which every probe was lost has
        # no latency, and lag_ms's 1500 anchor published as `loaded` became a
        # 187x "inflation" and, through pressure, a congested verdict.
        idle_lag = score.measured_lag(idle_st)
        loaded_lag = score.measured_lag(loaded_st)
        # A handful of samples on either side produces noise, not a ratio —
        # observed live, a five-sample loaded window read as 0.59, i.e. the
        # link answering *faster* under load. Both sides need enough
        # samples before the comparison means anything.
        inflation = None
        if (idle_lag and loaded_lag and idle_lag > 0
                and n_idle >= MIN_LOAD_SPLIT_SAMPLES
                and n_loaded >= MIN_LOAD_SPLIT_SAMPLES):
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
                "inflation": inflation, "loaded_samples": n_loaded,
                "idle_samples": n_idle,
                "loaded_p50": loaded_st.get("p50"),
                "loaded_p95": loaded_st.get("p95"),
                "idle_p50": idle_st.get("p50"),
                # How fast the queue emptied once traffic stopped. Depth is
                # what everyone reports; duration is what a user feels after
                # the download finishes.
                "drain": self._drain(lists, splits, self._active_keys())}

    def _active_keys(self):
        """Seated instrument keys, in the order `_active_series` yields them."""
        return [i.key for i in self.bench.actives()
                if i.key in self._instrument_series]

    @staticmethod
    def _drain(lists, splits, keys=None) -> dict:
        """drain_after_load per instrument, each against its own idle
        floor, the slowest one reported. Two instruments with different
        base round trips cannot share a baseline: measured against the
        lower one's floor the higher one never settles, and the lower one
        settles the moment its first post-load sample lands. The queue
        they drained through is the same, so the pessimistic view is the
        honest one.

        That last sentence is under review and the numbers beside `ms` are
        why. Each instrument's value is the gap to its next observation, so
        it is an UPPER BOUND floored at that instrument's own cadence —
        which means taking the largest reliably selects whichever instrument
        looks least often, and publishes it as the line being slow to drain.
        `min_ms` is the tightest bound the same window offers and `src` names
        the instrument the published value came from. Both are recorded per
        minute so the choice can be settled from stored history rather than
        argued from first principles, which is how it has been argued so far.
        """
        out = {"ms": None, "settled": None, "min_ms": None, "src": None}
        keys = keys or []
        for i, (samples, (idle, _)) in enumerate(zip(lists, splits)):
            base = Series.stats(idle).get("p50") if idle else None
            d = score.drain_after_load(samples, base)
            ms = d.get("ms")
            if ms is None:
                continue
            if out["ms"] is None or ms > out["ms"]:
                out["ms"] = ms
                out["settled"] = d.get("settled")
                out["src"] = keys[i] if i < len(keys) else None
            if out["min_ms"] is None or ms < out["min_ms"]:
                out["min_ms"] = ms
        return out

    def reliability(self, now: float):
        """(score or None, seconds watched) over RELIABILITY_WINDOW_S.

        Charged against the time actually watched — see
        score.RELIABILITY_MIN_WATCHED_S and Store.unwatched. One place, because
        live.json and the minute row must not disagree about what was
        watched."""
        window = score.RELIABILITY_WINDOW_S
        gaps = self.store.unwatched(window, now)
        watched = window - sum(b - a for a, b in gaps)
        out_frac, disruptions, disrupt_frac = self.store.outage_stats(
            window, now, unwatched=gaps)
        return score.reliability(out_frac, disruptions,
                                 disruption_fraction=disrupt_frac,
                                 window_s=watched), watched

    def connection_state(self, idx) -> str:
        """The one-word verdict live.json leads with. See compose_live."""
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
            # Through a VPN it is the tunnel that went silent, not the
            # internet — judged by the leg the outage was opened on.
            state = "tunnel-down" if self.wan_events.leg == "tunnel" else "wan-down"
        elif getattr(self, "lookup_watch", None) is not None \
                and self.lookup_watch.failing:
            # Every leg answers and names do not resolve, so almost nothing
            # opens. Not an outage of the line — the index stands, see
            # LookupWatch — but the one fact the user needs, so it outranks
            # a band.
            state = "dns-failing"
        elif idx is not None and idx < 70:
            state = "degraded"
        return state

    def compose_live(self, now: float) -> dict:
        """live.json, twice a second.

        Some keys here have no panel reader — `reach`, `lag.inflation`,
        `pressure.source`, `metered.kind`, `update.state`, `sockets.rejected`
        and a few more. They stay on purpose: `nexthop live` is how every
        measurement in this file was verified, and a payload trimmed to what
        the panel draws would leave the operator blind. Trim deliberately,
        never because a grep found no reader.
        """
        ls = Series.stats(self.local.since(30))
        ts = self.total.stats(30)
        ws = score.wan_from(ts, ls)
        lag = score.lag_ms(ts)
        resp = score.responsiveness(lag) if ts["count"] else None
        # Idle vs loaded over a longer window than the headline: bufferbloat
        # only shows when the link has actually been used, and 30 s of an
        # idle laptop would almost never contain a loaded sample. Reported,
        # not yet scored — the number has to be trusted before it can move
        # anyone's index.
        bloat = self.bufferbloat(300.0)

        rel, watched = self.reliability(now)

        snap = self.link.latest
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
        spd, speed_ctx = self.speed_score(now, network)

        band = score.lag_band(ts)

        # An under-sampled or contradicted Speed figure is published and
        # left out of the headline — see score.speed_scored.
        idx = score.index(resp, rel, spd if speed_ctx.get("scored") else None)

        state = self.connection_state(idx)

        # An index computed while a leg is confirmed down scores a
        # connection that is not there — see score.scored_now. Withheld,
        # not lowered; the state is the headline and the panel draws "--".
        headline = idx if score.scored_now(state) else None

        return {
            "v": 1,
            "t": round(now, 3),
            "state": state,
            "index": headline,
            "band": score.band(headline),
            "scores": {"responsiveness": resp, "reliability": rel, "speed": spd},
            "speed_ctx": speed_ctx,
            # The internet probes' routes leave through a tunnel: which, how
            # many of them, since when, and the leg's usual level to judge
            # its colour against (score.tunnel_bands; None until there is
            # one). Null when no probe goes through a VPN.
            "vpn": (dict(self.vpn, bands=self.tunnel_bands(now))
                    if self.vpn else None),
            # What Reliability was charged against, so the panel can say so
            # when it is less than the day the caption would otherwise imply.
            "reliability_ctx": {"watched_s": round(watched),
                                "window_s": score.RELIABILITY_WINDOW_S,
                                "min_s": score.RELIABILITY_MIN_WATCHED_S},
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
            # A phone sharing its data, or a link the user marked metered.
            # `care` rides along so the panel can say whether anything is
            # actually being held back, and is read fresh each time rather
            # than frozen when the link was detected.
            "metered": (dict(self.metered, care=bool(self.config["meteredCare"]))
                        if self.metered else None),
            # Proof the real internet answered, or why it did not.
            "reach": self.captive.snapshot(),
            # Whether names resolve: the named instruments' own lookups, see
            # LookupWatch. Null before the first one has been read.
            "lookups": self.lookup_watch.snapshot(),
            # What the user's own TCP connections are experiencing, straight
            # from the kernel: their real traffic to their real destinations.
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
            "content_running": self.content_running,
            "pid": os.getpid(),
            "pid_start": proc_start_ticks(os.getpid()),
            "daemon_version": __version__,
        }

    def flush_recent(self, now: float):
        """recent.json: last 30 min at 5-second resolution, ~360 points."""
        self.last_recent_flush = now
        self.aux_ring.append((now, self.rates[0], self.rates[1],
                              self.last_signal))
        points = []
        bucket = 5.0
        start = now - 1800
        locs = self.local.all()
        insts = self.total.each()

        def fold(samples):
            out = {}
            for smp in samples:
                t, r = smp[0], smp[1]
                if t < start:
                    continue
                b = int((t - start) / bucket)
                out.setdefault(b, []).append(r)
            return out

        lb, tbs = fold(locs), [fold(lst) for lst in insts]
        aux_b = {}
        for at, rx, tx, sig in self.aux_ring:
            if at >= start:
                aux_b[int((at - start) / bucket)] = (rx, tx, sig)
        for b in range(int(1800 / bucket)):
            l = lb.get(b, [])
            lr = [x for x in l if x is not None]
            # Each seated instrument's bucket mean, then the mean of those:
            # a seat that probes twice as often must not count twice. Loss
            # stays a pooled count — on the chart it is a tick, present or
            # not, and the readout's percentage is of everything sent.
            means, n_t, lost_t = [], 0, 0
            for t in (tb.get(b, []) for tb in tbs):
                tr = [x for x in t if x is not None]
                n_t += len(t)
                lost_t += len(t) - len(tr)
                if tr:
                    means.append(sum(tr) / len(tr))
            a = aux_b.get(b)
            tunnel = self.vpn_during(start + b * bucket, start + (b + 1) * bucket)
            points.append({
                "t": round(start + b * bucket, 1),
                "local": round(sum(lr) / len(lr), 2) if lr else None,
                "total": round(sum(means) / len(means), 2) if means else None,
                # The ISP leg per point, derived here rather than in QML so
                # the inversion guard has one implementation. A panel that
                # subtracted these itself would be a second copy of a rule
                # whose whole purpose is refusing to answer, and the copy
                # that forgets to refuse is the one that ships.
                "wan": score.wan_point_ms(
                    round(sum(means) / len(means), 2) if means else None,
                    round(sum(lr) / len(lr), 2) if lr else None),
                # None means no probe was sent in this bucket, which is a gap.
                # A figure with no `total` means probes went out and nothing
                # came back, which is down. The two must stay distinguishable:
                # a gap is drawn as nothing, a down as an outage.
                "loss": round((len(l) - len(lr) + lost_t) /
                              max(1, len(l) + n_t), 3) if (l or n_t) else None,
                "rx": round(a[0], 1) if a and a[0] is not None else None,
                "tx": round(a[1], 1) if a and a[1] is not None else None,
                "sig": a[2] if a else None,
            })
            # Each point says for itself whether a tunnel carried it. A chart
            # that labelled its history from the current state relabelled a
            # pre-VPN hour as the tunnel's the moment one came up (seen in
            # HopSense 0.1.15). Absent rather than false, to keep the file
            # the size it was for everyone not on a VPN.
            if tunnel:
                points[-1]["vpn"] = 1
        write_atomic(recent_path(), {"v": 1, "t": now, "bucket_s": bucket,
                                     "points": points})

    def flush_minute(self, now: float):
        ls = Series.stats(self.local.since(60))
        ts = self.total.stats(60)
        ws = score.wan_from(ts, ls)
        lag = score.lag_ms(ts)
        resp = score.responsiveness(lag) if ts["count"] else None
        # The old basis kept beside the new: the 0.2.0 switch to
        # instrument-scored lag must stay auditable against what ICMP
        # alone would have said — the 0.1.10 discipline, applied to
        # ourselves.
        icmp_stats = Series.stats(self.icmp_anchor.since(60))
        icmp_lag = score.lag_ms(icmp_stats) if icmp_stats["count"] else None

        rel, _ = self.reliability(now)
        bloat = self.bufferbloat(300.0)
        snap_link = self.link.latest
        if snap_link.get("kind") != "wifi":
            snap_link = {}
        spd, spd_ctx = self.speed_score(now, snap_link.get("ssid", ""))
        idx = score.index(resp, rel, spd if spd_ctx.get("scored") else None)
        self.store.put_minute(
            int(now // 60) * 60,
            {
                "local_p50": ls.get("p50"), "local_p95": ls.get("p95"),
                "local_jitter": ls.get("jitter"), "local_loss": ls.get("loss"),
                "wan_p50": ws.get("p50"), "wan_p95": ws.get("p95"),
                "wan_jitter": ws.get("jitter"), "wan_loss": ws.get("loss"),
                # Recorded, not scored — see SAMPLE_COLUMNS.
                "local_p75": ls.get("p75"), "local_max": ls.get("max"),
                "wan_p75": ws.get("p75"), "wan_max": ws.get("max"),
                "lag": lag,
                "rx_bps": self.rates[0], "tx_bps": self.rates[1],
                "signal_dbm": snap_link.get("signal_dbm"),
                "resp": resp, "rel": rel, "spd": spd, "idx": idx,
                "lag_idle": bloat["idle"], "lag_loaded": bloat["loaded"],
                "lag_icmp": icmp_lag,
                # Stored so a published figure can be checked afterwards.
                # `settled` as 1/0 rather than a bool: the column is REAL like
                # its neighbours, and None stays None so "never measured" and
                # "measured, did not settle" remain different answers.
                "drain_ms": (bloat.get("drain") or {}).get("ms"),
                "drain_min_ms": (bloat.get("drain") or {}).get("min_ms"),
                "drain_settled": (
                    None if (bloat.get("drain") or {}).get("settled") is None
                    else float(bool((bloat["drain"])["settled"]))),
                "drain_src": (bloat.get("drain") or {}).get("src"),
                # Which tunnel the probes went through this minute, if any.
                # Nothing is attributed to the ISP from a minute with one.
                "vpn": self.vpn_identity(),
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
        write_atomic(apps_path(), {
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
            self.restart_probes_if_settings_changed()
            self.follow_route()

            self.watch_outages(now)
            self.follow_path_states(now)
            self.follow_lookups(now)
            self.throughput(now, self.route.get("iface", ""))

            write_atomic(live_path(), self.compose_live(now))

            if now - self.last_apps_poll >= 3.0:
                self.last_apps_poll = now
                self.flush_apps(now)

            if now - self.last_minute_flush >= 60:
                self.last_minute_flush = now
                self.flush_minute(now)
                self.flush_recent(now)
            elif now - self.last_recent_flush >= 5.0:
                self.flush_recent(now)

            if now - self.last_rollup >= 3600:
                self.last_rollup = now
                self.store.rollup_hours(now)
                self.store.prune(minute_days=int(self.config["historyDays"]),
                                 now=now)

            # Off the loop: the check is a curl, and the bar must keep
            # updating at 2 Hz while it runs. tick() only starts and
            # collects it; the address it proves is adopted here.
            self.captive.tick(now, self._any_instrument_alive(6.0),
                              names_answered=self.lookup_watch.answered,
                              names_failing=self.lookup_watch.failing)
            self.adopt_wan_ip()

            self.update_watch.enabled = bool(self.config["updateCheck"])
            self.update_watch.tick(now)

            self.maybe_content_test(now)

            if now - self._last_bench_eval >= BENCH_EVAL_EVERY_S:
                self._last_bench_eval = now
                self._apply_seats(
                    self.bench.evaluate(now, self._instrument_stats()))

            # A peak asked for during the scheduled check waits for it to
            # finish rather than being dropped or run on top of it.
            if self.peak_requested.is_set() and not self.content_running:
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
        # Only now that the lock is ours: whatever a previous daemon left
        # open, it will never close. See Store.close_orphans.
        self.store.close_orphans(time.time())
        retire_legacy_snapshots(self.state_dir, runtime_dir(), time.time())
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        # SIGUSR1 is the "run a peak test" doorbell — file-free, and safe to
        # send from a QML Process one-liner.
        signal.signal(signal.SIGUSR1, lambda *_: self.peak_requested.set())
        self.nl_events.start()
        self.link.start()
        self.start_probes()
        try:
            self.loop()
        finally:
            for p in self.probes:
                p.stop()
            self.link.stop()
            self.nl_events.stop()
            self.store.close()
        return 0


def main():
    return Daemon().run()


if __name__ == "__main__":
    sys.exit(main())
