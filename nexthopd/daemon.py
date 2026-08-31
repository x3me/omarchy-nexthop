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
import signal
import stat as stat_module
import sys
import threading
import time
from collections import deque

from . import __version__, apps, net, score, speedtest
from .paths import (ensure_state_dir, live_path, recent_path, db_path,
                    lock_path, state_dir)
from .probes import Series, PingProbe
from .state import write_atomic
from .store import Store

# Consecutive losses on a leg before we call it down. At 500 ms per probe,
# eight of them is four seconds — long enough to skip a Wi-Fi roam, short
# enough that the notification still feels immediate.
OUTAGE_AFTER_LOSSES = 8


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
# A disruption that self-heals in under this is recorded but not notified.
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
Config.SCHEMA["historyDays"] = (7, Config._int(1, 90))
Config.SCHEMA["throughputWindowS"] = (3, Config._int(1, 30))


class LinkWatch:
    """Watches the Wi-Fi link state and writes events worth remembering:
    roams, associations, sustained rate drops. Instant events are stored
    closed; a rate drop stays open until the rate recovers, so its row
    carries a duration.
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

    def __init__(self, store):
        self.store = store
        self.prev = None          # last non-empty link, None until first seen
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
            self._instant(now, "associate", "Associated with " + (ssid or bssid))
        elif bssid and prev_bssid and bssid != prev_bssid:
            parts = ["Roamed to " + bssid]
            if prev.get("channel") and link.get("channel") \
                    and prev["channel"] != link["channel"]:
                parts.append("channel %s \u2192 %s" % (prev["channel"], link["channel"]))
            if prev.get("signal_dbm") is not None and link.get("signal_dbm") is not None:
                parts.append("%s \u2192 %s dBm" % (prev["signal_dbm"], link["signal_dbm"]))
            self._instant(now, "roam", ", ".join(parts))
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


class LegWatch:
    """Outage state for one leg: counts consecutive losses, opens and
    closes events, and remembers what to say when it recovers."""

    def __init__(self, leg: str):
        self.leg = leg
        self.losses = 0
        self.down_since = None
        self.event_id = None

    def sample(self, ok: bool, now: float):
        """Returns 'down' / 'up' on a transition, else None."""
        if ok:
            self.losses = 0
            if self.down_since is not None:
                self.down_since = None
                return "up"
            return None
        self.losses += 1
        if self.losses == OUTAGE_AFTER_LOSSES and self.down_since is None:
            self.down_since = now
            return "down"
        return None


class Daemon:
    def __init__(self):
        self.state_dir = ensure_state_dir()
        self.config = Config(self.state_dir)
        self.config.refresh()
        self.store = Store(db_path())
        self.local = Series()
        self.total = Series()
        self.probes = []
        self.running = True
        self.route = {}
        # Sliding window of (t, rx, tx) counter samples. Rates are computed
        # across the whole window, not tick-to-tick — a half-second sample is
        # instantaneous chatter, and displaying it twice a second reads as
        # flicker rather than as a number.
        self.counter_samples = []
        self.rates = (None, None)       # bytes/sec
        # 5-second aux samples riding along in recent.json: throughput and
        # signal, so the panel's charts have history the moment they open.
        self.aux_ring = deque(maxlen=400)
        self.last_signal = None
        self.watch_local = LegWatch("local")
        self.watch_wan = LegWatch("wan")
        self.link_watch = LinkWatch(self.store)
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

    def start_probes(self):
        anchor = self.config["internetAnchor"]
        self.route = net.route_to(anchor)
        interval = int(self.config["probeIntervalMs"])
        gw = self.route.get("gateway", "")
        if gw:
            p = PingProbe(gw, self.local, interval, "local")
            p.start()
            self.probes.append(p)
        p = PingProbe(anchor, self.total, interval, "total")
        p.start()
        self.probes.append(p)

    def restart_probes_if_route_changed(self):
        """New default route (roamed networks, docked, VPN up) — new targets."""
        anchor = self.config["internetAnchor"]
        fresh = net.route_to(anchor)
        if fresh.get("gateway") == self.route.get("gateway") and \
           fresh.get("iface") == self.route.get("iface"):
            return
        for p in self.probes:
            p.stop()
        self.probes.clear()
        self.local = Series()
        self.total = Series()
        self.route = fresh
        self.counter_samples = []
        self.start_probes()

    def stop(self, *_):
        self.running = False

    # ------------------------------------------------------------ measuring

    def throughput(self, now: float, iface: str):
        c = net.counters(iface)
        if c is None:
            self.counter_samples = []
            self.rates = (None, None)
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
        local_ok = any(r is not None for _, r in recent_local) if recent_local else None
        total_ok = any(r is not None for _, r in recent_total) if recent_total else None

        if local_ok is not None:
            move = self.watch_local.sample(local_ok, now)
            if move == "down":
                self.watch_local.event_id = self.store.open_event(
                    int(now), "outage", "critical", "local",
                    "router unreachable")
                self.notify("Router unreachable",
                            "Nothing on the local network is answering.", True)
            elif move == "up" and self.watch_local.event_id:
                self.store.close_event(self.watch_local.event_id, int(now))
                self.watch_local.event_id = None
                self.notify("Local network recovered", "The router is answering again.")

        if total_ok is not None and local_ok is not False:
            move = self.watch_wan.sample(total_ok, now)
            if move == "down":
                self.watch_wan.event_id = self.store.open_event(
                    int(now), "outage", "critical", "wan",
                    "router answers, nothing past it does")
                self.notify("No internet",
                            "The router answers but nothing past it does — "
                            "the fault is on the ISP side.", True)
            elif move == "up" and self.watch_wan.event_id:
                self.store.close_event(self.watch_wan.event_id, int(now))
                self.watch_wan.event_id = None
                self.notify("Internet recovered", "Replies from the internet again.")

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
                loaded = (round(sorted(x for _, x in loaded_window)[len(loaded_window) // 2], 1)
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

    def compose_live(self, now: float) -> dict:
        ls = Series.stats(self.local.since(30))
        ts = Series.stats(self.total.since(30))
        ws = score.wan_from(ts, ls)
        lag = score.lag_ms(ts)
        resp = score.responsiveness(lag) if ts["count"] else None

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

        idx = score.index(resp, rel, spd)

        state = "online"
        if self.watch_local.down_since:
            state = "local-down"
        elif self.watch_wan.down_since:
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
            "lag": {"now": lag,
                    "best": ts.get("p50"), "worst": ts.get("max")},
            "local": ls, "total": ts, "wan": ws,
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
            for t, r in samples:
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

        out_frac, disruptions, disrupt_frac = self.store.outage_stats(24 * 3600, now)
        rel = score.reliability(out_frac, disruptions,
                                disruption_fraction=disrupt_frac)
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
            },
            iface=self.route.get("iface", ""),
            network=snap_link.get("ssid", ""),
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

            self.maybe_content_test(now)

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
        self.start_probes()
        try:
            self.loop()
        finally:
            for p in self.probes:
                p.stop()
            self.store.close()
        return 0


def main():
    return Daemon().run()


if __name__ == "__main__":
    sys.exit(main())
