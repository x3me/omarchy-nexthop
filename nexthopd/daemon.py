"""The nexthopd main loop.

Owns the probes, folds their samples into live.json / recent.json /
history.db, detects outages, and runs the scheduled content check. The QML
side never talks to this process — the files are the whole contract, so
either side can restart without the other noticing.
"""

import fcntl
import json
import os
import signal
import sys
import threading
import time

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
# A disruption that self-heals in under this is recorded but not notified.
NOTIFY_AFTER_S = 5.0


class Config:
    """Settings, read from the file the QML side writes.

    The plugin writes its settings dict here on change; the daemon re-reads
    it once a loop. Defaults match manifest.json.
    """

    DEFAULTS = {
        "internetAnchor": "1.1.1.1",
        "probeIntervalMs": 500,
        "contentSpeed": True,
        "contentSpeedIntervalMin": 60,
        "peakEngine": "Auto",
        "planDownMbps": 0,
        "planUpMbps": 0,
        "notifyOutage": True,
        "historyDays": 7,
        "throughputWindowS": 3,
    }

    def __init__(self, state_dir):
        self.path = state_dir / "config.json"
        self.values = dict(self.DEFAULTS)
        self._mtime = 0

    def refresh(self):
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if mtime == self._mtime:
            return
        self._mtime = mtime
        try:
            with open(self.path) as f:
                loaded = json.load(f)
        except (OSError, ValueError):
            return
        merged = dict(self.DEFAULTS)
        for k in merged:
            if k in loaded and loaded[k] is not None:
                merged[k] = loaded[k]
        self.values = merged

    def __getitem__(self, key):
        return self.values[key]


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

    def __init__(self, store):
        self.store = store
        self.prev = {}
        self.rate_ceiling = 0.0
        self.low_since = None
        self.low_floor = None
        self.rate_event_id = None
        self.last_sample = 0.0

    def _instant(self, ts, kind, detail):
        eid = self.store.open_event(int(ts), kind, "info", "local", detail)
        self.store.close_event(eid, int(ts))

    def sample(self, now, link):
        # The caller runs twice a second; once a second is plenty here.
        if now - self.last_sample < 1.0:
            return
        self.last_sample = now
        prev, self.prev = self.prev, dict(link) if link else {}
        if not link or not link.get("bssid"):
            self._close_rate_event(now)
            self.rate_ceiling = 0.0
            return

        bssid = link.get("bssid", "")
        prev_bssid = prev.get("bssid", "")
        ssid = link.get("ssid", "")

        if bssid and not prev_bssid:
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
        # A slowly decaying ceiling: the best rate seen lately, with a
        # half-life of a few minutes so an old burst does not set the bar
        # forever.
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
        try to start us; whoever loses the lock just exits quietly."""
        self._lock_fh = open(lock_path(), "w")
        try:
            fcntl.flock(self._lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        self._lock_fh.write(str(os.getpid()))
        self._lock_fh.flush()
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
        window = max(1, int(self.config["throughputWindowS"]))
        self.counter_samples.append((now, c[0], c[1]))
        cutoff = now - window - 0.25
        while len(self.counter_samples) > 2 and self.counter_samples[0][0] < cutoff:
            self.counter_samples.pop(0)
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
        if now - self.last_content_test < interval:
            return
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
        content = self.store.tests(limit=1, kind="content")
        if not content or not content[0]["ok"]:
            return None, {"basis": "auto", "baseline_down": None,
                          "last_down": None, "last_up": None}
        last = content[0]

        plan_d = self.config["planDownMbps"]
        plan_u = self.config["planUpMbps"]
        if plan_d:
            spd = score.speed(last["down_mbps"], last["up_mbps"],
                              plan_d, plan_u or 0)
            return spd, {"basis": "plan", "plan_down": plan_d,
                         "plan_up": plan_u,
                         "last_down": last["down_mbps"],
                         "last_up": last["up_mbps"]}

        cache = getattr(self, "_baseline_cache", None)
        if not cache or now - cache[0] > 60 or cache[2] != network:
            baseline = self.store.baseline_speed(network=network, now=now)
            cache = (now, baseline, network)
            self._baseline_cache = cache
        baseline = cache[1]
        spd = score.speed(last["down_mbps"], last["up_mbps"],
                          baseline_down=baseline)
        return spd, {"basis": "auto", "baseline_down": baseline,
                     "last_down": last["down_mbps"],
                     "last_up": last["up_mbps"]}

    def compose_live(self, now: float) -> dict:
        ls = Series.stats(self.local.since(30))
        ts = Series.stats(self.total.since(30))
        ws = score.wan_from(ts, ls)
        lag = score.lag_ms(ts)
        resp = score.responsiveness(lag) if ts["count"] else None

        out_frac, disruptions = self.store.outage_stats(24 * 3600, now)
        rel = score.reliability(out_frac, disruptions)

        snap = net.snapshot(self.config["internetAnchor"])
        network = snap.get("ssid") or snap.get("name") or ""
        if snap.get("kind") == "wifi":
            self.link_watch.sample(now, snap)
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
            "rates": {"rx_bps": self.rates[0], "tx_bps": self.rates[1]},
            "link": snap,
            "down_since": self.watch_local.down_since or self.watch_wan.down_since,
            "peak_running": self.peak_running,
            "pid": os.getpid(),
            "daemon_version": __version__,
        }

    def flush_recent(self, now: float):
        """recent.json: last 30 min at 5-second resolution, ~360 points."""
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
        for b in range(int(1800 / bucket)):
            l = lb.get(b, [])
            t = tb.get(b, [])
            lr = [x for x in l if x is not None]
            tr = [x for x in t if x is not None]
            points.append({
                "t": round(start + b * bucket, 1),
                "local": round(sum(lr) / len(lr), 2) if lr else None,
                "total": round(sum(tr) / len(tr), 2) if tr else None,
                "loss": round((len(l) - len(lr) + len(t) - len(tr)) /
                              max(1, len(l) + len(t)), 3) if (l or t) else None,
            })
        write_atomic(recent_path(), {"v": 1, "t": now, "bucket_s": bucket,
                                     "points": points})

    def flush_minute(self, now: float):
        ls = Series.stats(self.local.since(60))
        ts = Series.stats(self.total.since(60))
        ws = score.wan_from(ts, ls)
        lag = score.lag_ms(ts)
        resp = score.responsiveness(lag) if ts["count"] else None

        out_frac, disruptions = self.store.outage_stats(24 * 3600, now)
        rel = score.reliability(out_frac, disruptions)
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

    def run(self):
        if not self.acquire_lock():
            print("nexthopd: another instance holds the lock, exiting",
                  file=sys.stderr)
            return 0
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
