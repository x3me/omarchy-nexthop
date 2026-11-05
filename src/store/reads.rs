use rusqlite::types::{Type, ValueRef};
use rusqlite::{Connection, Params, params};
use serde_json::{Map, Number, Value};

use super::{Store, UNWATCHED_GAP_S, resolve_now};
use crate::probes::nearest_rank;
use crate::util::py_sum;

pub type Row = Map<String, Value>;

pub fn vpn_matches(stored: Option<&str>, current: Option<&str>) -> bool {
    let stored = stored.unwrap_or("");
    let current = current.unwrap_or("");
    if current.is_empty() {
        return stored.is_empty();
    }
    if stored.is_empty() {
        return false;
    }
    let (si, se) = stored.split_once('@').unwrap_or((stored, ""));
    let (ci, ce) = current.split_once('@').unwrap_or((current, ""));
    si == ci && (se.is_empty() || ce.is_empty() || se == ce)
}

pub(crate) fn fetch_rows<P: Params>(db: &Connection, sql: &str, params: P) -> rusqlite::Result<Vec<Row>> {
    let mut stmt = db.prepare(sql)?;
    let names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();
    let mut rows = stmt.query(params)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut map = Map::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            let value = match row.get_ref(i)? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(n) => Value::from(n),
                ValueRef::Real(f) => Number::from_f64(f).map_or(Value::Null, Value::Number),
                ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
                ValueRef::Blob(_) => {
                    return Err(rusqlite::Error::InvalidColumnType(i, name.clone(), Type::Blob));
                }
            };
            map.insert(name.clone(), value);
        }
        out.push(map);
    }
    Ok(out)
}

impl Store {
    pub fn series(
        &self,
        seconds: f64,
        now: Option<f64>,
        resolution: &str,
    ) -> rusqlite::Result<(Vec<Row>, &'static str)> {
        let now = resolve_now(now);
        let table = match resolution {
            "minute" => "minute",
            "hour" => "hour",
            _ if seconds <= 6.0 * 3600.0 => "minute",
            _ => "hour",
        };
        let since = (now - seconds) as i64;
        let rows =
            self.with_db(|db| fetch_rows(db, &format!("SELECT * FROM {table} WHERE ts >= ? ORDER BY ts"), [since]))?;
        Ok((rows, table))
    }

    pub fn tests(&self, limit: i64, kind: Option<&str>) -> rusqlite::Result<Vec<Row>> {
        self.with_db(|db| match kind.filter(|k| !k.is_empty()) {
            Some(kind) => {
                fetch_rows(db, "SELECT * FROM tests WHERE kind=? ORDER BY ts DESC LIMIT ?", params![kind, limit])
            }
            None => fetch_rows(db, "SELECT * FROM tests ORDER BY ts DESC LIMIT ?", [limit]),
        })
    }

    pub fn events(&self, seconds: f64, limit: i64, now: Option<f64>) -> rusqlite::Result<Vec<Row>> {
        let start = (resolve_now(now) - seconds) as i64;
        self.with_db(|db| {
            fetch_rows(
                db,
                "SELECT * FROM events
               WHERE ts >= ? OR ended_ts IS NULL OR ended_ts >= ?
               ORDER BY ts DESC LIMIT ?",
                params![start, start, limit],
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn baseline_speed(
        &self,
        days: i64,
        network: &str,
        min_samples: usize,
        now: Option<f64>,
        fallback: bool,
        vpn: Option<&str>,
    ) -> rusqlite::Result<Option<f64>> {
        let since = (resolve_now(now) - (days * 86400) as f64) as i64;
        let p90 = |rows: Vec<(Option<f64>, Option<String>)>| {
            let mut vals: Vec<f64> =
                rows.into_iter().filter(|(_, v)| vpn_matches(v.as_deref(), vpn)).filter_map(|(d, _)| d).collect();
            vals.sort_by(f64::total_cmp);
            (vals.len() >= min_samples && !vals.is_empty()).then(|| nearest_rank(&vals, 0.9))
        };
        let read = |sql: &str, params: &[&dyn rusqlite::ToSql]| {
            self.with_db(|db| {
                let mut stmt = db.prepare(sql)?;
                let rows = stmt.query_map(params, |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
        };
        if !network.is_empty() {
            let rows = read(
                "SELECT down_mbps, vpn FROM tests
                   WHERE kind='content' AND ok=1 AND ts >= ? AND network = ?",
                params![since, network],
            )?;
            if let Some(result) = p90(rows) {
                return Ok(Some(result));
            }
        }
        if !fallback {
            return Ok(None);
        }
        let rows = read(
            "SELECT down_mbps, vpn FROM tests
               WHERE kind='content' AND ok=1 AND ts >= ?",
            params![since],
        )?;
        Ok(p90(rows))
    }

    pub fn tunnel_level(
        &self,
        vpn: &str,
        seconds: f64,
        now: Option<f64>,
    ) -> rusqlite::Result<(Option<f64>, Option<f64>, usize)> {
        let now = resolve_now(now);
        let rows: Vec<(f64, Option<String>)> = self.with_db(|db| {
            let mut stmt = db.prepare(
                "SELECT wan_p50, vpn FROM minute
               WHERE ts >= ? AND ts <= ? AND vpn IS NOT NULL
                 AND wan_p50 IS NOT NULL",
            )?;
            let rows = stmt.query_map(params![(now - seconds) as i64, now as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })?;
        let mut vals: Vec<f64> =
            rows.into_iter().filter(|(_, v)| vpn_matches(v.as_deref(), Some(vpn))).map(|(w, _)| w).collect();
        if vals.is_empty() {
            return Ok((None, None, 0));
        }
        vals.sort_by(f64::total_cmp);
        Ok((Some(nearest_rank(&vals, 0.5)), Some(nearest_rank(&vals, 0.9)), vals.len()))
    }

    pub fn unwatched(&self, seconds: f64, now: Option<f64>) -> rusqlite::Result<Vec<(f64, f64)>> {
        let now = resolve_now(now);
        let start = now - seconds;
        let rows: Vec<i64> = self.with_db(|db| {
            let mut stmt = db.prepare("SELECT ts FROM minute WHERE ts >= ? AND ts <= ? ORDER BY ts")?;
            let rows = stmt.query_map(params![start as i64 - 60, now as i64], |r| r.get(0))?;
            rows.collect()
        })?;
        let mut gaps = Vec::new();
        let mut edge = start;
        for ts in rows.into_iter().map(|t| t as f64).chain([now]) {
            if ts - edge > UNWATCHED_GAP_S {
                gaps.push((edge, ts.min(now)));
            }
            edge = edge.max(ts + 60.0);
        }
        Ok(gaps)
    }

    pub fn outage_stats(
        &self,
        seconds: f64,
        now: Option<f64>,
        unwatched: &[(f64, f64)],
    ) -> rusqlite::Result<(f64, i64, f64)> {
        let now = resolve_now(now);
        let start = now - seconds;
        let rows: Vec<(i64, Option<i64>, Option<String>)> = self.with_db(|db| {
            let mut stmt = db.prepare(
                "SELECT ts, ended_ts, kind FROM events
               WHERE kind IN ('outage', 'disruption') AND (ended_ts IS NULL OR ended_ts >= ?)",
            )?;
            let rows = stmt.query_map([start as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })?;
        let (mut down, mut disrupted, mut disruptions) = (0.0, 0.0, 0);
        for (ts, ended_ts, kind) in rows {
            let begin = (ts as f64).max(start);
            let end = ended_ts.filter(|&e| e != 0).map_or(now, |e| e as f64).min(now);
            let length = (end - begin) - py_sum(unwatched.iter().map(|&(a, b)| (end.min(b) - begin.max(a)).max(0.0)));
            if length <= 0.0 {
                continue;
            }
            if kind.as_deref() == Some("outage") {
                down += length;
            } else {
                disruptions += 1;
                disrupted += length;
            }
        }
        let span = seconds - py_sum(unwatched.iter().map(|&(a, b)| b - a));
        let share = |x: f64| if span > 0.0 { x / span } else { 0.0 };
        Ok((share(down), disruptions, share(disrupted)))
    }
}
