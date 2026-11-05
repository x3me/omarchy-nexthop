pub type StoreResult<T> = Result<T, rusqlite::Error>;

pub trait EventLog: Send + Sync {
    fn open_event(&self, ts: i64, kind: &str, severity: &str, leg: &str, detail: &str) -> StoreResult<i64>;
    fn close_event(&self, event_id: i64, ended_ts: i64, detail: Option<&str>) -> StoreResult<()>;
}

impl EventLog for crate::store::Store {
    fn open_event(&self, ts: i64, kind: &str, severity: &str, leg: &str, detail: &str) -> StoreResult<i64> {
        crate::store::Store::open_event(self, ts, kind, severity, leg, detail)
    }

    fn close_event(&self, event_id: i64, ended_ts: i64, detail: Option<&str>) -> StoreResult<()> {
        crate::store::Store::close_event(self, event_id, ended_ts, detail)
    }
}

pub type Notify = Box<dyn Fn(&str, &str, bool) + Send + Sync>;
