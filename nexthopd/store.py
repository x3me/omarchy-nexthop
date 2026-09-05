"""Persistence: per-minute rows, hourly rollups, tests and events.

sqlite from the standard library, in WAL mode so the CLI can read a window
of history while the daemon is mid-write. Raw half-second samples never
reach the disk — they are folded into a minute row and discarded, which is
what keeps a month of continuous monitoring under about 12 MB.
"""

import sqlite3
import time
from pathlib import Path

SAMPLE_COLUMNS = [
    "local_p50", "local_p95", "local_jitter", "local_loss",
    "wan_p50", "wan_p95", "wan_jitter", "wan_loss",
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

_COLS_SQL = ", ".join(f"{c} REAL" for c in SAMPLE_COLUMNS)

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS minute (
  ts INTEGER PRIMARY KEY, {_COLS_SQL}, iface TEXT, network TEXT, probes TEXT
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


class Store:
    def __init__(self, path: Path, read_only: bool = False):
        self.path = Path(path)
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
                              ("minute", "probes")):
            try:
                self.db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} "
                    f"{'TEXT' if column in ('network', 'probes') else 'REAL'}")
            except sqlite3.OperationalError:
                pass  # column already there

    def close(self):
        try:
            self.db.close()
        except sqlite3.Error:
            pass

    # ---------------------------------------------------------------- writes

    def put_minute(self, ts: int, values: dict, iface: str = "",
                   network: str = "", probes: str = ""):
        cols = ["ts"] + SAMPLE_COLUMNS + ["iface", "network", "probes"]
        row = ([int(ts)] + [values.get(c) for c in SAMPLE_COLUMNS]
               + [iface, network, probes])
        placeholders = ", ".join("?" * len(cols))
        self.db.execute(
            f"INSERT OR REPLACE INTO minute ({', '.join(cols)}) VALUES ({placeholders})",
            row,
        )
        self.db.commit()

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

    def open_event(self, ts: int, kind: str, severity: str, leg: str, detail: str) -> int:
        cur = self.db.execute(
            "INSERT INTO events (ts, kind, severity, leg, detail) VALUES (?,?,?,?,?)",
            (int(ts), kind, severity, leg, detail),
        )
        self.db.commit()
        return cur.lastrowid

    def close_event(self, event_id: int, ended_ts: int, detail: str = None):
        if detail is None:
            self.db.execute("UPDATE events SET ended_ts=? WHERE id=?",
                            (int(ended_ts), event_id))
        else:
            self.db.execute("UPDATE events SET ended_ts=?, detail=? WHERE id=?",
                            (int(ended_ts), detail, event_id))
        self.db.commit()

    # ------------------------------------------------------------- maintenance

    def rollup_hours(self, now: float = None):
        """Fold complete minutes into hour rows.

        Averages the averages, which is fair because every minute row covers
        the same span. Percentiles do not survive that — an hourly p95 built
        from sixty per-minute p95s is a mean of p95s, and it is labelled as
        such wherever it is displayed.
        """
        now = now or time.time()
        current_hour = int(now // 3600) * 3600
        avg = ", ".join(f"AVG({c}) AS {c}" for c in SAMPLE_COLUMNS)
        self.db.execute(
            f"""INSERT OR REPLACE INTO hour
                (ts, {', '.join(SAMPLE_COLUMNS)}, iface, network)
                SELECT (ts / 3600) * 3600 AS bucket, {avg},
                       MAX(iface), MAX(network)
                FROM minute WHERE ts < ? GROUP BY bucket""",
            (current_hour,),
        )
        self.db.commit()

    def prune(self, minute_days: int = 7, hour_days: int = 400, now: float = None):
        now = now or time.time()
        self.db.execute("DELETE FROM minute WHERE ts < ?",
                        (int(now - minute_days * 86400),))
        self.db.execute("DELETE FROM hour WHERE ts < ?",
                        (int(now - hour_days * 86400),))
        self.db.commit()

    # ---------------------------------------------------------------- reads

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

    def tests(self, limit: int = 20, kind: str = None) -> list:
        if kind:
            rows = self.db.execute(
                "SELECT * FROM tests WHERE kind=? ORDER BY ts DESC LIMIT ?",
                (kind, limit)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM tests ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def events(self, seconds: float = 7 * 86400, limit: int = 100,
               now: float = None) -> list:
        now = now or time.time()
        rows = self.db.execute(
            "SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
            (int(now - seconds), limit)).fetchall()
        return [dict(r) for r in rows]

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
            return vals[min(len(vals) - 1, int(round(0.9 * (len(vals) - 1))))]

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
