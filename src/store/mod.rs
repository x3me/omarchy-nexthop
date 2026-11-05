mod reads;
#[cfg(test)]
mod tests;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use crate::util::now as wall_now;

pub use reads::vpn_matches;

pub const SAMPLE_COLUMNS: [&str; 23] = [
    "local_p50",
    "local_p95",
    "local_jitter",
    "local_loss",
    "wan_p50",
    "wan_p95",
    "wan_jitter",
    "wan_loss",
    "local_p75",
    "local_max",
    "wan_p75",
    "wan_max",
    "lag",
    "rx_bps",
    "tx_bps",
    "signal_dbm",
    "resp",
    "rel",
    "spd",
    "idx",
    "lag_idle",
    "lag_loaded",
    "lag_icmp",
];

pub const MINUTE_ONLY_REAL: [&str; 3] = ["drain_ms", "drain_min_ms", "drain_settled"];
pub const MINUTE_ONLY_TEXT: [&str; 2] = ["drain_src", "vpn"];

pub const UNWATCHED_GAP_S: f64 = 120.0;

const MIGRATIONS: [(&str, &str); 28] = [
    ("tests", "network"),
    ("minute", "lag_idle"),
    ("minute", "lag_loaded"),
    ("hour", "lag_idle"),
    ("hour", "lag_loaded"),
    ("minute", "lag_icmp"),
    ("hour", "lag_icmp"),
    ("minute", "probes"),
    ("minute", "local_p75"),
    ("hour", "local_p75"),
    ("minute", "local_max"),
    ("hour", "local_max"),
    ("minute", "wan_p75"),
    ("hour", "wan_p75"),
    ("minute", "wan_max"),
    ("hour", "wan_max"),
    ("minute", "drain_ms"),
    ("minute", "drain_min_ms"),
    ("minute", "drain_settled"),
    ("minute", "drain_src"),
    ("minute", "vpn"),
    ("tests", "vpn"),
    ("hour", "vpn"),
    ("events", "end_unknown"),
    ("tests", "quiet_s"),
    ("tests", "awake_s"),
    ("tests", "asked"),
    ("tests", "band"),
];

pub fn schema() -> String {
    let cols = SAMPLE_COLUMNS.iter().map(|c| format!("{c} REAL")).collect::<Vec<_>>().join(", ");
    let extra = MINUTE_ONLY_REAL
        .iter()
        .map(|c| format!("{c} REAL"))
        .chain(MINUTE_ONLY_TEXT.iter().map(|c| format!("{c} TEXT")))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "
CREATE TABLE IF NOT EXISTS minute (
  ts INTEGER PRIMARY KEY, {cols}, {extra},
  iface TEXT, network TEXT, probes TEXT
);
CREATE TABLE IF NOT EXISTS hour (
  ts INTEGER PRIMARY KEY, {cols}, iface TEXT, network TEXT
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
  leg TEXT, detail TEXT, end_unknown INTEGER
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS tests_kind_ts ON tests(kind, ts);
"
    )
}

#[derive(Clone, Debug, PartialEq)]
pub struct TestRow {
    pub down_mbps: Option<f64>,
    pub up_mbps: Option<f64>,
    pub ping_idle: Option<f64>,
    pub ping_loaded: Option<f64>,
    pub jitter: Option<f64>,
    pub bytes: Option<i64>,
    pub server: Option<String>,
    pub ok: bool,
    pub detail: Option<String>,
    pub network: Option<String>,
    pub vpn: Option<String>,
    pub quiet_s: Option<f64>,
    pub awake_s: Option<f64>,
    pub asked: Option<bool>,
    pub band: Option<String>,
}

impl Default for TestRow {
    fn default() -> Self {
        TestRow {
            down_mbps: None,
            up_mbps: None,
            ping_idle: None,
            ping_loaded: None,
            jitter: None,
            bytes: None,
            server: None,
            ok: true,
            detail: Some(String::new()),
            network: Some(String::new()),
            vpn: None,
            quiet_s: None,
            awake_s: None,
            asked: None,
            band: None,
        }
    }
}

pub struct Store {
    pub path: PathBuf,
    db: Mutex<Option<Connection>>,
}

fn failure(code: std::ffi::c_int, message: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some(message))
}

fn resolve_now(now: Option<f64>) -> f64 {
    now.filter(|&n| n != 0.0).unwrap_or_else(wall_now)
}

fn bind_json(column: &str, value: Option<&Value>) -> rusqlite::Result<SqlValue> {
    Ok(match value {
        None | Some(Value::Null) => SqlValue::Null,
        Some(Value::Bool(b)) => SqlValue::Integer(*b as i64),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => SqlValue::Integer(i),
            None => SqlValue::Real(n.as_f64().unwrap_or(f64::NAN)),
        },
        Some(Value::String(s)) => SqlValue::Text(s.clone()),
        Some(other) => {
            return Err(rusqlite::Error::ToSqlConversionFailure(format!("{column}: cannot store {other}").into()));
        }
    })
}

impl Store {
    pub fn new(path: &Path, read_only: bool) -> rusqlite::Result<Store> {
        let conn = if read_only {
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| failure(rusqlite::ffi::SQLITE_CANTOPEN, format!("{}: {e}", parent.display())))?;
            }
            Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?
        };
        conn.busy_timeout(Duration::from_secs(5))?;
        if !read_only {
            conn.execute_batch(&schema())?;
            Self::migrate(&conn)?;
            conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
            conn.execute_batch("PRAGMA synchronous=NORMAL")?;
        }
        Ok(Store { path: path.to_path_buf(), db: Mutex::new(Some(conn)) })
    }

    fn migrate(conn: &Connection) -> rusqlite::Result<()> {
        for (table, column) in MIGRATIONS {
            let kind = match column {
                "network" | "probes" | "drain_src" | "vpn" | "band" => "TEXT",
                "end_unknown" | "asked" => "INTEGER",
                _ => "REAL",
            };
            let mut info = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let present = info
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .iter()
                .any(|c| c.eq_ignore_ascii_case(column));
            if !present {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"))?;
            }
        }
        Ok(())
    }

    pub(crate) fn with_db<R>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<R>) -> rusqlite::Result<R> {
        let guard = self.db.lock().unwrap();
        match guard.as_ref() {
            Some(conn) => f(conn),
            None => Err(failure(rusqlite::ffi::SQLITE_MISUSE, "store is closed".into())),
        }
    }

    pub fn close(&self) {
        if let Some(conn) = self.db.lock().unwrap().take()
            && let Err((_, e)) = conn.close()
        {
            crate::util::complain!("nexthop: closing {}: {e}", self.path.display());
        }
    }

    pub fn put_minute(
        &self,
        ts: i64,
        values: &Map<String, Value>,
        iface: &str,
        network: &str,
        probes: &str,
    ) -> rusqlite::Result<()> {
        let extra = MINUTE_ONLY_REAL.iter().chain(MINUTE_ONLY_TEXT.iter());
        let named: Vec<&str> = SAMPLE_COLUMNS.iter().chain(extra).copied().collect();
        let mut row = vec![SqlValue::Integer(ts)];
        for c in &named {
            row.push(bind_json(c, values.get(*c))?);
        }
        row.extend([iface, network, probes].map(|s| SqlValue::Text(s.to_string())));
        let cols = std::iter::once("ts").chain(named.iter().copied()).chain(["iface", "network", "probes"]);
        let cols = cols.collect::<Vec<_>>().join(", ");
        let placeholders = vec!["?"; row.len()].join(", ");
        self.with_db(|db| {
            db.execute(
                &format!("INSERT OR REPLACE INTO minute ({cols}) VALUES ({placeholders})"),
                rusqlite::params_from_iter(row),
            )
            .map(drop)
        })
    }

    pub fn put_test(&self, ts: i64, kind: &str, engine: &str, kw: &TestRow) -> rusqlite::Result<()> {
        let non_empty = |s: &Option<String>| s.clone().filter(|v| !v.is_empty());
        self.with_db(|db| {
            db.execute(
                "INSERT OR REPLACE INTO tests
               (ts, kind, engine, down_mbps, up_mbps, ping_idle, ping_loaded,
                jitter, bytes, server, ok, detail, network, vpn,
                quiet_s, awake_s, asked, band)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    ts,
                    kind,
                    engine,
                    kw.down_mbps,
                    kw.up_mbps,
                    kw.ping_idle,
                    kw.ping_loaded,
                    kw.jitter,
                    kw.bytes,
                    kw.server,
                    kw.ok as i64,
                    kw.detail,
                    kw.network,
                    non_empty(&kw.vpn),
                    kw.quiet_s,
                    kw.awake_s,
                    kw.asked.map(|a| a as i64),
                    non_empty(&kw.band),
                ],
            )
            .map(drop)
        })
    }

    pub fn open_event(&self, ts: i64, kind: &str, severity: &str, leg: &str, detail: &str) -> rusqlite::Result<i64> {
        self.with_db(|db| {
            db.execute(
                "INSERT INTO events (ts, kind, severity, leg, detail) VALUES (?,?,?,?,?)",
                params![ts, kind, severity, leg, detail],
            )?;
            Ok(db.last_insert_rowid())
        })
    }

    pub fn close_event(&self, event_id: i64, ended_ts: i64, detail: Option<&str>) -> rusqlite::Result<()> {
        self.with_db(|db| {
            match detail {
                None => db.execute("UPDATE events SET ended_ts=? WHERE id=?", params![ended_ts, event_id])?,
                Some(d) => {
                    db.execute("UPDATE events SET ended_ts=?, detail=? WHERE id=?", params![ended_ts, d, event_id])?
                }
            };
            Ok(())
        })
    }

    pub fn rollup_hours(&self, now: Option<f64>) -> rusqlite::Result<()> {
        let now = resolve_now(now);
        let current_hour = (now / 3600.0).floor() as i64 * 3600;
        let avg = SAMPLE_COLUMNS.iter().map(|c| format!("AVG({c}) AS {c}")).collect::<Vec<_>>().join(", ");
        let cols = SAMPLE_COLUMNS.join(", ");
        self.with_db(|db| {
            db.execute(
                &format!(
                    "INSERT OR REPLACE INTO hour
                (ts, {cols}, iface, network, vpn)
                SELECT (ts / 3600) * 3600 AS bucket, {avg},
                       CASE WHEN COUNT(DISTINCT iface) > 1 THEN ''
                            ELSE MAX(iface) END,
                       CASE WHEN COUNT(DISTINCT network) > 1 THEN ''
                            ELSE MAX(network) END,
                       CASE WHEN COUNT(vpn) = 0 THEN NULL
                            WHEN COUNT(vpn) = COUNT(*)
                                 AND COUNT(DISTINCT vpn) = 1 THEN MAX(vpn)
                            ELSE '' END
                FROM minute WHERE ts < ? GROUP BY bucket"
                ),
                [current_hour],
            )
            .map(drop)
        })
    }

    pub fn prune(&self, minute_days: i64, hour_days: i64, now: Option<f64>) -> rusqlite::Result<()> {
        let now = resolve_now(now);
        let minute_cut = (now - (minute_days * 86400) as f64) as i64;
        let hour_cut = (now - (hour_days * 86400) as f64) as i64;
        self.with_db(|db| {
            db.execute_batch("BEGIN")?;
            let done = (|| {
                db.execute("DELETE FROM minute WHERE ts < ?", [minute_cut])?;
                db.execute("DELETE FROM hour WHERE ts < ?", [hour_cut])?;
                db.execute("DELETE FROM events WHERE ts < ?", [hour_cut])?;
                db.execute_batch("COMMIT")
            })();
            if done.is_err() {
                let _ = db.execute_batch("ROLLBACK");
            }
            done
        })
    }

    pub fn close_orphans(&self, _now: Option<f64>) -> rusqlite::Result<usize> {
        self.with_db(|db| db.execute("UPDATE events SET ended_ts = ts + 1, end_unknown = 1 WHERE ended_ts IS NULL", []))
    }
}
