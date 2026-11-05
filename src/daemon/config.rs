use serde_json::{Map, Value};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

type Validator = fn(&Value) -> Option<Value>;

pub struct Config {
    pub path: PathBuf,
    pub values: Map<String, Value>,
    mtime: Option<(i64, i64)>,
}

fn anchor(v: &Value) -> Option<Value> {
    let s = v.as_str()?;
    let bytes = s.as_bytes();
    let first_ok = bytes.first().is_some_and(|b| b.is_ascii_alphanumeric() || *b == b':');
    let rest_ok = bytes.iter().skip(1).all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'));
    (first_ok && rest_ok && bytes.len() <= 253).then(|| v.clone())
}

fn int_in(v: &Value, lo: i64, hi: i64) -> Option<Value> {
    let n = match v {
        Value::Number(n) => {
            n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc().clamp(-1e18, 1e18) as i64))?
        }
        _ => return None,
    };
    (lo..=hi).contains(&n).then(|| Value::from(n))
}

fn boolean(v: &Value) -> Option<Value> {
    v.is_boolean().then(|| v.clone())
}

fn peak_engine(v: &Value) -> Option<Value> {
    matches!(v.as_str(), Some("Auto" | "Ookla" | "Cloudflare" | "fast.com")).then(|| v.clone())
}

fn schema() -> [(&'static str, Value, Validator); 12] {
    [
        ("internetAnchor", Value::from("1.1.1.1"), anchor),
        ("probeIntervalMs", Value::from(500), |v| int_in(v, 250, 5000)),
        ("contentSpeed", Value::from(true), boolean),
        ("contentSpeedIntervalMin", Value::from(60), |v| int_in(v, 15, 1440)),
        ("peakEngine", Value::from("Auto"), peak_engine),
        ("planDownMbps", Value::from(0), |v| int_in(v, 0, 10000)),
        ("planUpMbps", Value::from(0), |v| int_in(v, 0, 10000)),
        ("notifyOutage", Value::from(true), boolean),
        ("updateCheck", Value::from(true), boolean),
        ("meteredCare", Value::from(true), boolean),
        ("historyDays", Value::from(7), |v| int_in(v, 1, 90)),
        ("throughputWindowS", Value::from(3), |v| int_in(v, 1, 30)),
    ]
}

impl Config {
    pub const MAX_BYTES: usize = 64 * 1024;

    pub fn defaults() -> Map<String, Value> {
        schema().into_iter().map(|(k, d, _)| (k.to_string(), d)).collect()
    }

    #[cfg(test)]
    pub fn validate(key: &str, value: &Value) -> Option<Value> {
        schema().into_iter().find(|(k, _, _)| *k == key).and_then(|(_, _, check)| check(value))
    }

    pub fn new(state_dir: &Path) -> Self {
        Self { path: state_dir.join("config.json"), values: Self::defaults(), mtime: None }
    }

    pub fn refresh(&mut self) {
        let Some(data) = self.read_if_changed() else {
            return;
        };
        if data.len() > Self::MAX_BYTES {
            return;
        }
        let Ok(Value::Object(loaded)) = serde_json::from_slice::<Value>(&data) else {
            return;
        };
        let mut merged = Self::defaults();
        for (key, _, check) in schema() {
            match loaded.get(key) {
                None | Some(Value::Null) => continue,
                Some(v) => {
                    if let Some(checked) = check(v) {
                        merged.insert(key.to_string(), checked);
                    }
                }
            }
        }
        self.values = merged;
    }

    fn read_if_changed(&mut self) -> Option<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.path)
            .ok()?;
        let meta = file.metadata().ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        let mtime = (meta.mtime(), meta.mtime_nsec());
        if self.mtime == Some(mtime) {
            return None;
        }
        self.mtime = Some(mtime);
        let mut data = Vec::new();
        (&mut file).take(Self::MAX_BYTES as u64 + 1).read_to_end(&mut data).ok()?;
        Some(data)
    }

    pub fn get(&self, key: &str) -> &Value {
        &self.values[key]
    }

    fn int(&self, key: &str) -> i64 {
        self.get(key).as_i64().unwrap_or_default()
    }

    fn flag(&self, key: &str) -> bool {
        self.get(key).as_bool().unwrap_or_default()
    }

    pub fn internet_anchor(&self) -> String {
        self.get("internetAnchor").as_str().unwrap_or_default().to_string()
    }

    pub fn probe_interval_ms(&self) -> i64 {
        self.int("probeIntervalMs")
    }

    pub fn content_speed(&self) -> bool {
        self.flag("contentSpeed")
    }

    pub fn content_speed_interval_min(&self) -> i64 {
        self.int("contentSpeedIntervalMin")
    }

    pub fn peak_engine(&self) -> String {
        self.get("peakEngine").as_str().unwrap_or_default().to_string()
    }

    pub fn notify_outage(&self) -> bool {
        self.flag("notifyOutage")
    }

    pub fn update_check(&self) -> bool {
        self.flag("updateCheck")
    }

    pub fn metered_care(&self) -> bool {
        self.flag("meteredCare")
    }

    pub fn history_days(&self) -> i64 {
        self.int("historyDays")
    }

    pub fn throughput_window_s(&self) -> i64 {
        self.int("throughputWindowS")
    }
}

impl std::ops::Index<&str> for Config {
    type Output = Value;

    fn index(&self, key: &str) -> &Value {
        self.get(key)
    }
}
