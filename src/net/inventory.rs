use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use super::names::is_bssid;
use crate::util::py_strip;

pub const MAX_BYTES: usize = 128 * 1024;
const RACY_WINDOW_NS: i128 = 2_000_000_000;

type Stamp = (u64, u64, u64, i64, i64, i64, i64);

pub struct ApInventory {
    pub path: PathBuf,
    content: Option<Vec<u8>>,
    names: HashMap<String, String>,
    stamp: Option<Stamp>,
}

pub fn default_inventory_path() -> PathBuf {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    config_home.join("nexthop").join("bssid_to_ap_inventory.csv")
}

impl ApInventory {
    pub fn new(path: Option<PathBuf>) -> Self {
        ApInventory {
            path: path.unwrap_or_else(default_inventory_path),
            content: None,
            names: HashMap::new(),
            stamp: None,
        }
    }

    fn forget(&mut self) {
        self.content = None;
        self.names.clear();
        self.stamp = None;
    }

    fn refresh(&mut self) {
        let Ok(meta) = std::fs::symlink_metadata(&self.path) else {
            return self.forget();
        };
        let stamp =
            (meta.dev(), meta.ino(), meta.size(), meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec());
        if meta.file_type().is_file() && self.stamp == Some(stamp) {
            return;
        }
        self.stamp = None;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.path);
        let Ok(mut file) = file else {
            return self.forget();
        };
        let Ok(meta) = file.metadata() else {
            return self.forget();
        };
        if !meta.file_type().is_file() {
            return self.forget();
        }
        let mut data = Vec::new();
        if (&mut file).take(MAX_BYTES as u64 + 1).read_to_end(&mut data).is_err() {
            return self.forget();
        }
        let ctime_ns = meta.ctime() as i128 * 1_000_000_000 + meta.ctime_nsec() as i128;
        let now_ns = (crate::util::now() * 1e9) as i128;
        // INFO: fc 17oct26 a stamp taken within the timestamp granularity of a write is not trusted, like git's racy-clean rule
        if now_ns - ctime_ns > RACY_WINDOW_NS {
            self.stamp = Some((
                meta.dev(),
                meta.ino(),
                meta.size(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec(),
            ));
        }
        if self.content.as_deref() == Some(data.as_slice()) {
            return;
        }
        self.names = if data.len() > MAX_BYTES { HashMap::new() } else { parse_inventory(&data) };
        self.content = Some(data);
    }

    pub fn lookup(&mut self, bssid: &str) -> Option<String> {
        self.refresh();
        let key = py_strip(bssid).to_lowercase();
        if !is_bssid(&key) {
            return None;
        }
        self.names.get(&key).cloned()
    }
}

pub fn parse_inventory(data: &[u8]) -> HashMap<String, String> {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return HashMap::new();
    };
    let Some(records) = csv_records(text) else {
        return HashMap::new();
    };
    let mut records = records.into_iter();
    let Some(fieldnames) = records.next().filter(|f| !f.is_empty()) else {
        return HashMap::new();
    };
    let column = |name: &str| fieldnames.iter().rposition(|f| f == name);
    let (Some(bssid_col), Some(name_col)) = (column("bssid"), column("ap_name")) else {
        return HashMap::new();
    };
    let mut names = HashMap::new();
    for row in records.filter(|r| !r.is_empty()) {
        let field = |i: usize| row.get(i).map(String::as_str).unwrap_or("");
        let bssid = py_strip(field(bssid_col)).to_lowercase();
        let name = py_strip(field(name_col));
        if is_bssid(&bssid) && !name.is_empty() && name.chars().count() <= 128 {
            names.insert(bssid, name.to_string());
        }
    }
    names
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    StartRecord,
    StartField,
    InField,
    InQuotedField,
    QuoteInQuotedField,
    EatCrnl,
}

// INFO: fc 17oct26 mirrors CPython _csv.c's default-dialect state machine, so odd files parse or fail as they did
pub fn csv_records(text: &str) -> Option<Vec<Vec<String>>> {
    let mut records = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut state = State::StartRecord;
    let mut lines = text.split_inclusive('\n').peekable();
    loop {
        let Some(line) = lines.next() else {
            if !field.is_empty() || state == State::InQuotedField {
                fields.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut fields));
            }
            return Some(records);
        };
        for c in line.chars().map(Some).chain(std::iter::once(None)) {
            state = step(state, c, &mut field, &mut fields)?;
        }
        if state == State::StartRecord {
            records.push(std::mem::take(&mut fields));
        }
    }
}

fn step(state: State, c: Option<char>, field: &mut String, fields: &mut Vec<String>) -> Option<State> {
    let is_nl = matches!(c, Some('\n' | '\r'));
    let mut save = |field: &mut String| fields.push(std::mem::take(field));
    let end_of_line = |c: Option<char>| {
        if c.is_none() { State::StartRecord } else { State::EatCrnl }
    };
    Some(match state {
        State::StartRecord if c.is_none() => State::StartRecord,
        State::StartRecord if is_nl => State::EatCrnl,
        State::StartRecord | State::StartField => match c {
            None | Some('\n' | '\r') => {
                save(field);
                end_of_line(c)
            }
            Some('"') => State::InQuotedField,
            Some(',') => {
                save(field);
                State::StartField
            }
            Some(ch) => {
                field.push(ch);
                State::InField
            }
        },
        State::InField => match c {
            None | Some('\n' | '\r') => {
                save(field);
                end_of_line(c)
            }
            Some(',') => {
                save(field);
                State::StartField
            }
            Some(ch) => {
                field.push(ch);
                State::InField
            }
        },
        State::InQuotedField => match c {
            None => State::InQuotedField,
            Some('"') => State::QuoteInQuotedField,
            Some(ch) => {
                field.push(ch);
                State::InQuotedField
            }
        },
        State::QuoteInQuotedField => match c {
            Some('"') => {
                field.push('"');
                State::InQuotedField
            }
            Some(',') => {
                save(field);
                State::StartField
            }
            None | Some('\n' | '\r') => {
                save(field);
                end_of_line(c)
            }
            Some(ch) => {
                field.push(ch);
                State::InField
            }
        },
        State::EatCrnl => match c {
            Some('\n' | '\r') => State::EatCrnl,
            None => State::StartRecord,
            Some(_) => return None,
        },
    })
}
