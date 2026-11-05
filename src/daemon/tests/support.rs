use std::sync::{Arc, Mutex};

use crate::daemon::events::{EventLog, Notify, StoreResult};

#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub severity: String,
    pub leg: String,
    pub detail: String,
    pub ended_ts: Option<i64>,
}

#[derive(Default)]
pub struct MemStore {
    rows: Mutex<Vec<Row>>,
    closes: Mutex<Vec<(i64, i64)>>,
}

impl MemStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn events(&self) -> Vec<Row> {
        let mut rows = self.rows.lock().unwrap().clone();
        rows.sort_by(|a, b| b.ts.cmp(&a.ts).then(b.id.cmp(&a.id)));
        rows
    }

    pub fn kinds(&self) -> Vec<String> {
        self.events().into_iter().map(|r| r.kind).collect()
    }

    pub fn opened(&self) -> Vec<(String, String, String, String)> {
        let rows = self.rows.lock().unwrap();
        rows.iter().map(|r| (r.kind.clone(), r.severity.clone(), r.leg.clone(), r.detail.clone())).collect()
    }

    pub fn closed(&self) -> Vec<i64> {
        self.closes.lock().unwrap().iter().map(|c| c.0).collect()
    }

    pub fn closed_at(&self) -> Vec<i64> {
        self.closes.lock().unwrap().iter().map(|c| c.1).collect()
    }
}

impl EventLog for MemStore {
    fn open_event(&self, ts: i64, kind: &str, severity: &str, leg: &str, detail: &str) -> StoreResult<i64> {
        let mut rows = self.rows.lock().unwrap();
        let id = rows.len() as i64 + 1;
        rows.push(Row {
            id,
            ts,
            kind: kind.into(),
            severity: severity.into(),
            leg: leg.into(),
            detail: detail.into(),
            ended_ts: None,
        });
        Ok(id)
    }

    fn close_event(&self, event_id: i64, ended_ts: i64, detail: Option<&str>) -> StoreResult<()> {
        self.closes.lock().unwrap().push((event_id, ended_ts));
        let mut rows = self.rows.lock().unwrap();
        if let Some(row) = rows.iter_mut().find(|r| r.id == event_id) {
            row.ended_ts = Some(ended_ts);
            if let Some(d) = detail {
                row.detail = d.into();
            }
        }
        Ok(())
    }
}

pub type Notices = Arc<Mutex<Vec<(String, String, bool)>>>;

pub fn recorder() -> (Notify, Notices) {
    let notices: Notices = Arc::default();
    let sink = Arc::clone(&notices);
    let notify: Notify =
        Box::new(move |summary, body, urgent| sink.lock().unwrap().push((summary.into(), body.into(), urgent)));
    (notify, notices)
}

pub fn quiet() -> Notify {
    Box::new(|_, _, _| {})
}

pub fn count(notices: &Notices) -> usize {
    notices.lock().unwrap().len()
}
