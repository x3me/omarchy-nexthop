"""Persistence: per-minute rows, hourly rollups, tests and events.

sqlite from the standard library, in WAL mode so the CLI can read a window
of history while the daemon is mid-write. Raw half-second samples never
reach the disk — they are folded into a minute row and discarded, which is
what keeps a month of continuous monitoring under about 12 MB.
"""

import functools
import sqlite3
import threading
import time
from pathlib import Path

from .probes import nearest_rank

SAMPLE_COLUMNS = [
    "local_p50", "local_p95", "local_jitter", "local_loss",
    "wan_p50", "wan_p95", "wan_jitter", "wan_loss",
    # 0.2.20: the two order statistics the scored fold and its critics
    # actually turn on. Lag leans on p75; Orb headlines a high-water max;
    # LibreQoS takes a phase percentile. Comparing those against our own
    # history was only possible as an upper bound because neither was ever
    # written down — p50 and p95 alone cannot reconstruct either. Recorded
    # now, scored never: the decision needs real days behind it, the same
    # rule loaded latency was held to in 0.1.11.
    "local_p75", "local_max", "wan_p75", "wan_max",
    "lag", "rx_bps", "tx_bps", "signal_dbm",
    "resp", "rel", "spd", "idx",
    # Latency split by what the link was doing at the time. The gap between
    # them is bufferbloat, and it only accumulates into something worth
    # scoring if it is recorded minute by minute first.
    "lag_idle", "lag_loaded",
    # 0.2.0: what ICMP alone would have scored, beside the instrument-
    # scored lag — the basis switch stays auditable per minute.
    "lag_icmp",
]

# Minute-only, and deliberately not in SAMPLE_COLUMNS: `rollup_hours` averages
# everything in that list, and a mean of drains destroys the one thing the
# drain is being stored for. Its value is quantised by probe cadence, so what
# has to survive is the DISTRIBUTION — sixty of them averaged is a number with
# none of that in it.
#
# 0.2.37. Until now the drain was published to live.json and stored nowhere,
# so a figure on screen could never be checked afterwards; the distribution
# that showed it was quantised had to come from the other implementation
# because this one had no history to look at.
#
# Three numbers rather than one. `drain_settled` says whether the link
# recovered or the window merely ended, so a censored floor is not read as a
# measurement. `drain_min_ms` is the tightest bound across the seated
# instruments beside the loosest, which is what is published today — carrying
# both is what lets the choice between them be settled from history instead of
# argued. `drain_src` names the instrument the published value came from,
# because each instrument's value is floored at its own cadence and knowing
# which one won is the difference between an auditable figure and a guess.
MINUTE_ONLY_REAL = ["drain_ms", "drain_min_ms", "drain_settled"]
MINUTE_ONLY_TEXT = ["drain_src"]

_COLS_SQL = ", ".join(f"{c} REAL" for c in SAMPLE_COLUMNS)
_MINUTE_EXTRA_SQL = ", ".join(
    [f"{c} REAL" for c in MINUTE_ONLY_REAL] + [f"{c} TEXT" for c in MINUTE_ONLY_TEXT])

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS minute (
  ts INTEGER PRIMARY KEY, {_COLS_SQL}, {_MINUTE_EXTRA_SQL},
  iface TEXT, network TEXT, probes TEXT
);
CREATE TABLE IF NOT EXISTS hour (
  ts INTEGER PRIMARY KEY, {_COLS_SQL}, iface TEXT, network TEXT
);
CREATE TABLE IF NOT EXISTS tests (
  ts INTEGER PRIMARY KEY, kind TEXT, engine TEXT,
  down_mbps REAL, up_mbps REAL, ping_idle REAL, ping_loaded REAL,
  jitter REAL, bytes INTEGER, server TEXT, ok INTEGER, detail TEXT,
  network TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL, ended_ts INTEGER, kind TEXT, severity TEXT,
  leg TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS tests_kind_ts ON tests(kind, ts);
"""


def _locked(method):
    """Serialise access to the one connection — see Store."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class Store:
    """One connection, one lock.

    Three threads reach this object: the daemon loop (minute rows, events,
    a read for Reliability on every tick), the content-test worker and the
    peak-test worker (one row each when they finish). The connection is
    opened with `check_same_thread=False`, which only tells the sqlite3
    module to allow that — it does not make concurrent use of one
    connection safe, and a forced overlap reproduces "bad parameter or
    other API misuse" and a lost row. Every transaction here is a few
    milliseconds, so a mutex is the whole fix; a writer thread with a
    queue was considered and is more machinery than three callers need.
    """

    def __init__(self, path: Path, read_only: bool = False):
        self.path = Path(path)
        self._lock = threading.RLock()
        if read_only:
            uri = f"file:{self.path}?mode=ro"
            self.db = sqlite3.connect(uri, uri=True, timeout=5.0)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(self.path, timeout=5.0,
                                      check_same_thread=False)
            self.db.executescript(SCHEMA)
            self._migrate()
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.commit()
        self.db.row_factory = sqlite3.Row

    def _migrate(self):
        """Additive migrations for databases created by older versions."""
        for table, column in (("tests", "network"),
                              ("minute", "lag_idle"), ("minute", "lag_loaded"),
                              ("hour", "lag_idle"), ("hour", "lag_loaded"),
                              ("minute", "lag_icmp"), ("hour", "lag_icmp"),
                              ("minute", "probes"),
                              ("minute", "local_p75"), ("hour", "local_p75"),
                              ("minute", "local_max"), ("hour", "local_max"),
                              ("minute", "wan_p75"), ("hour", "wan_p75"),
                              ("minute", "wan_max"), ("hour", "wan_max"),
                              ("minute", "drain_ms"),
                              ("minute", "drain_min_ms"),
                              ("minute", "drain_settled"),
                              ("minute", "drain_src")):
            try:
                self.db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} "
                    f"{'TEXT' if column in ('network', 'probes', 'drain_src') else 'REAL'}")
            except sqlite3.OperationalError:
                pass  # column already there

    @_locked
    def close(self):
        try:
            self.db.close()
        except sqlite3.Error:
            pass

    # ---------------------------------------------------------------- writes

    @_locked
    def put_minute(self, ts: int, values: dict, iface: str = "",
                   network: str = "", probes: str = ""):
        extra = MINUTE_ONLY_REAL + MINUTE_ONLY_TEXT
        cols = ["ts"] + SAMPLE_COLUMNS + extra + ["iface", "network", "probes"]
        row = ([int(ts)]
               + [values.get(c) for c in SAMPLE_COLUMNS]
               + [values.get(c) for c in extra]
               + [iface, network, probes])
        placeholders = ", ".join("?" * len(cols))
        self.db.execute(
            f"INSERT OR REPLACE INTO minute ({', '.join(cols)}) VALUES ({placeholders})",
            row,
        )
        self.db.commit()

    @_locked
    def put_test(self, ts: int, kind: str, engine: str, **kw):
        self.db.execute(
            """INSERT OR REPLACE INTO tests
               (ts, kind, engine, down_mbps, up_mbps, ping_idle, ping_loaded,
                jitter, bytes, server, ok, detail, network)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (int(ts), kind, engine, kw.get("down_mbps"), kw.get("up_mbps"),
             kw.get("ping_idle"), kw.get("ping_loaded"), kw.get("jitter"),
             kw.get("bytes"), kw.get("server"), 1 if kw.get("ok", True) else 0,
             kw.get("detail", ""), kw.get("network", "")),
        )
        self.db.commit()

    @_locked
    def open_event(self, ts: int, kind: str, severity: str, leg: str, detail: str) -> int:
        cur = self.db.execute(
            "INSERT INTO events (ts, kind, severity, leg, detail) VALUES (?,?,?,?,?)",
            (int(ts), kind, severity, leg, detail),
        )
        self.db.commit()
        return cur.lastrowid

    @_locked
    def close_event(self, event_id: int, ended_ts: int, detail: str = None):
        if detail is None:
            self.db.execute("UPDATE events SET ended_ts=? WHERE id=?",
                            (int(ended_ts), event_id))
        else:
            self.db.execute("UPDATE events SET ended_ts=?, detail=? WHERE id=?",
                            (int(ended_ts), detail, event_id))
        self.db.commit()

    # ------------------------------------------------------------- maintenance

    @_locked
    def rollup_hours(self, now: float = None):
        """Fold complete minutes into hour rows.

        Averages the averages, which is fair because every minute row covers
        the same span. Percentiles do not survive that — an hourly p95 built
        from sixty per-minute p95s is a mean of p95s, and it is labelled as
        such wherever it is displayed. The same caveat binds harder to the
        new max columns: an hourly `local_max` is a mean of sixty maxima,
        which is not the hour's worst sample and must never be shown as one.
        Use the minute rows for anything that reasons about the tail.

        An hour that spanned two networks is labelled with neither: MAX()
        would pick whichever name sorts last and file the other network's
        minutes under it. Blank is "mixed", which no consumer can mistake
        for a network.
        """
        now = now or time.time()
        current_hour = int(now // 3600) * 3600
        avg = ", ".join(f"AVG({c}) AS {c}" for c in SAMPLE_COLUMNS)
        self.db.execute(
            f"""INSERT OR REPLACE INTO hour
                (ts, {', '.join(SAMPLE_COLUMNS)}, iface, network)
                SELECT (ts / 3600) * 3600 AS bucket, {avg},
                       CASE WHEN COUNT(DISTINCT iface) > 1 THEN ''
                            ELSE MAX(iface) END,
                       CASE WHEN COUNT(DISTINCT network) > 1 THEN ''
                            ELSE MAX(network) END
                FROM minute WHERE ts < ? GROUP BY bucket""",
            (current_hour,),
        )
        self.db.commit()

    @_locked
    def prune(self, minute_days: int = 7, hour_days: int = 400, now: float = None):
        now = now or time.time()
        self.db.execute("DELETE FROM minute WHERE ts < ?",
                        (int(now - minute_days * 86400),))
        self.db.execute("DELETE FROM hour WHERE ts < ?",
                        (int(now - hour_days * 86400),))
        # Events were never pruned before 0.2.21 — about sixty rows a day,
        # unbounded. They keep the hourly history's horizon.
        self.db.execute("DELETE FROM events WHERE ts < ?",
                        (int(now - hour_days * 86400),))
        self.db.commit()

    @_locked
    def close_orphans(self, now: float = None) -> int:
        """Close events a previous daemon left open. Returns how many.

        Only the daemon that opened an event can close it, so one that
        died mid-outage — or was retired by the version handover with a
        rate-drop open — leaves `ended_ts` NULL for good. Two readers
        treat NULL as "still happening": `outage_stats` would charge such
        an outage against every Reliability window forever, and `events`
        would list it as ongoing. When it actually ended is unknowable,
        so it is closed at the shortest span the store accepts rather
        than at a guessed later time: undercharging by the lost tail is
        the safe direction, and inventing a duration is not.

        Called once, after the lock is held — a second daemon that loses
        the flock must not close the running one's events on its way out.
        """
        cur = self.db.execute(
            "UPDATE events SET ended_ts = ts + 1 WHERE ended_ts IS NULL")
        self.db.commit()
        return cur.rowcount

    # ---------------------------------------------------------------- reads

    @_locked
    def series(self, seconds: float, now: float = None,
               resolution: str = "auto") -> list:
        """History over a window, at whichever resolution suits it.

        Auto: under six hours reads per-minute rows; anything longer reads
        hourly ones, so a seven-day graph is 168 points rather than 10,080.
        Callers that genuinely want the fine rows (the 24 h experience
        ribbon) ask for "minute" explicitly.
        """
        now = now or time.time()
        if resolution in ("minute", "hour"):
            table = resolution
        else:
            table = "minute" if seconds <= 6 * 3600 else "hour"
        rows = self.db.execute(
            f"SELECT * FROM {table} WHERE ts >= ? ORDER BY ts",
            (int(now - seconds),),
        ).fetchall()
        return [dict(r) for r in rows], table

    @_locked
    def tests(self, limit: int = 20, kind: str = None) -> list:
        if kind:
            rows = self.db.execute(
                "SELECT * FROM tests WHERE kind=? ORDER BY ts DESC LIMIT ?",
                (kind, limit)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM tests ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    @_locked
    def events(self, seconds: float = 7 * 86400, limit: int = 100,
               now: float = None) -> list:
        """Events overlapping the window, newest first.

        Filtering on start time alone dropped an outage that began before
        the window and ended inside it — the one the user opens the list
        to see. Same overlap rule `outage_stats` has always used.
        """
        now = now or time.time()
        start = int(now - seconds)
        rows = self.db.execute(
            """SELECT * FROM events
               WHERE ts >= ? OR ended_ts IS NULL OR ended_ts >= ?
               ORDER BY ts DESC LIMIT ?""",
            (start, start, limit)).fetchall()
        return [dict(r) for r in rows]

    @_locked
    def baseline_speed(self, days: int = 30, network: str = "",
                       min_samples: int = 5, now: float = None,
                       fallback: bool = True):
        """This connection's own normal: the p90 of recent content downloads.

        p90 rather than max so one lucky quiet-hour run does not set a bar
        the line can never reach again. Scoped to the current network when
        it has enough samples — the office's normal is not the home's —
        falling back to all networks, and to None until there is enough
        history to mean anything.
        """
        now = now or time.time()
        since = int(now - days * 86400)

        def p90(rows):
            vals = sorted(r["down_mbps"] for r in rows
                          if r["down_mbps"] is not None)
            if len(vals) < min_samples:
                return None
            return nearest_rank(vals, 0.9)

        if network:
            rows = self.db.execute(
                """SELECT down_mbps FROM tests
                   WHERE kind='content' AND ok=1 AND ts >= ? AND network = ?""",
                (since, network)).fetchall()
            result = p90(rows)
            if result is not None:
                return result
        # The caller decides whether a cross-network baseline is meaningful.
        # For the degradation penalty it is not: "is it normal here" cannot
        # be answered with another network's normal.
        if not fallback:
            return None
        rows = self.db.execute(
            """SELECT down_mbps FROM tests
               WHERE kind='content' AND ok=1 AND ts >= ?""",
            (since,)).fetchall()
        return p90(rows)

    @_locked
    def outage_stats(self, seconds: float, now: float = None):
        """(fraction fully down, count of disruptions, fraction disrupted).

        Disruptions carry their duration as well as their count because
        reliability charges both kinds of interruption in the same currency —
        time. Counting alone made three brief blips outweigh an hour offline.
        """
        now = now or time.time()
        start = now - seconds
        rows = self.db.execute(
            """SELECT ts, ended_ts, kind FROM events
               WHERE kind IN ('outage', 'disruption') AND (ended_ts IS NULL OR ended_ts >= ?)""",
            (int(start),)).fetchall()
        down = 0.0
        disrupted = 0.0
        disruptions = 0
        for r in rows:
            begin = max(r["ts"], start)
            end = r["ended_ts"] if r["ended_ts"] else now
            end = min(end, now)
            if end <= begin:
                continue
            if r["kind"] == "outage":
                down += end - begin
            else:
                disruptions += 1
                disrupted += end - begin
        span = seconds if seconds else 0.0
        return ((down / span if span else 0.0), disruptions,
                (disrupted / span if span else 0.0))
