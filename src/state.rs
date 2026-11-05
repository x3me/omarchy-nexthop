use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::paths::{APPS, LIVE, RECENT};
use crate::util::{now, py_round};

pub type Stamp = (i64, u64);

pub fn write_atomic(path: &Path, payload: &Value, durable: bool) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let (tmp, mut file) = create_temp(dir, name)?;
    let written = (|| {
        file.write_all(&crate::pyjson::to_vec(payload)?)?;
        if durable {
            file.sync_all()?;
        }
        fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

fn create_temp(dir: &Path, name: &str) -> std::io::Result<(std::path::PathBuf, File)> {
    let pid = std::process::id();
    for attempt in 0..100u32 {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let tmp = dir.join(format!(".{name}.{pid}.{nanos:x}{attempt}"));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no free temp name"))
}

pub fn read_text_bounded(path: &Path, max_bytes: usize) -> Option<(String, Stamp)> {
    read_text_bounded_if_changed(path, max_bytes, None)
}

pub fn read_text_bounded_if_changed(path: &Path, max_bytes: usize, last: Option<Stamp>) -> Option<(String, Stamp)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let stamp = (meta.mtime() * 1_000_000_000 + meta.mtime_nsec(), meta.size());
    if last == Some(stamp) {
        return None;
    }
    let mut buf = Vec::with_capacity(meta.len().min(max_bytes as u64 + 1) as usize);
    let mut chunk = [0u8; 65536];
    while buf.len() <= max_bytes {
        let want = chunk.len().min(max_bytes + 1 - buf.len());
        match file.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    if buf.len() > max_bytes {
        return None;
    }
    String::from_utf8(buf).ok().map(|text| (text, stamp))
}

pub fn read_json(path: &Path, max_bytes: usize) -> Option<Value> {
    let (text, _) = read_text_bounded(path, max_bytes)?;
    serde_json::from_str(&text).ok()
}

pub const READ_JSON_MAX: usize = 4 * 1024 * 1024;

pub fn retire_legacy_snapshots(old_dir: &Path, new_dir: &Path, at: Option<f64>) -> std::io::Result<()> {
    if old_dir == new_dir {
        return Ok(());
    }
    let at = at.unwrap_or_else(now);
    for name in [RECENT, APPS] {
        let _ = fs::remove_file(old_dir.join(name));
    }
    let live = old_dir.join(LIVE);
    let Some((text, _)) = read_text_bounded(&live, 256 * 1024) else {
        return Ok(());
    };
    let Ok(Value::Object(mut payload)) = serde_json::from_str::<Value>(&text) else {
        let _ = fs::remove_file(&live);
        return Ok(());
    };
    for key in ["pid", "pid_start", "daemon_version"] {
        payload.shift_remove(key);
    }
    payload.insert("t".into(), py_round(at, 3).into());
    payload.insert("state".into(), "no-daemon".into());
    for key in ["index", "band", "down_since"] {
        payload.insert(key.into(), Value::Null);
    }
    write_atomic(&live, &Value::Object(payload), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::{APPS, LIVE, RECENT};
    use crate::testutil::TempDir;
    use serde_json::json;

    #[test]
    fn write_read() {
        let d = TempDir::new();
        let p = d.path().join("live.json");
        write_atomic(&p, &json!({"x": 1}), false).unwrap();
        assert_eq!(read_json(&p, READ_JSON_MAX), Some(json!({"x": 1})));
        assert_eq!(read_json(&d.path().join("missing.json"), READ_JSON_MAX), None);
        let names: Vec<_> = fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["live.json"]);
    }

    #[test]
    fn regular_file_reads() {
        let d = TempDir::new();
        fs::write(d.path().join("live.json"), r#"{"a":1}"#).unwrap();
        assert_eq!(read_text_bounded(&d.path().join("live.json"), 1024).unwrap().0, r#"{"a":1}"#);
    }

    #[test]
    fn symlink_refused_and_target_unread() {
        let d = TempDir::new();
        fs::write(d.path().join("secret"), "SENSITIVE").unwrap();
        std::os::unix::fs::symlink(d.path().join("secret"), d.path().join("live.json")).unwrap();
        assert_eq!(read_text_bounded(&d.path().join("live.json"), 1024), None);
    }

    #[test]
    fn fifo_refused_without_blocking() {
        let d = TempDir::new();
        let p = d.path().join("live.json");
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_text_bounded(&p, 1024), None);
    }

    #[test]
    fn oversized_refused_by_the_read_itself() {
        let d = TempDir::new();
        fs::write(d.path().join("live.json"), "x".repeat(5000)).unwrap();
        assert_eq!(read_text_bounded(&d.path().join("live.json"), 1024), None);
    }

    #[test]
    fn exactly_at_the_cap_is_allowed() {
        let d = TempDir::new();
        fs::write(d.path().join("live.json"), "y".repeat(1024)).unwrap();
        assert_eq!(read_text_bounded(&d.path().join("live.json"), 1024).unwrap().0.len(), 1024);
    }

    #[test]
    fn directory_refused() {
        let d = TempDir::new();
        assert_eq!(read_text_bounded(d.path(), 1024), None);
    }

    #[test]
    fn missing_file_is_none() {
        let d = TempDir::new();
        assert_eq!(read_text_bounded(&d.path().join("nope.json"), 1024), None);
    }

    fn set_mtime_ns(p: &Path, ns: u64) {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ns);
        File::options().write(true).open(p).unwrap().set_modified(t).unwrap();
    }

    #[test]
    fn stamp_changes_only_when_the_file_does() {
        let d = TempDir::new();
        let p = d.path().join("live.json");
        fs::write(&p, r#"{"a":1}"#).unwrap();
        let first = read_text_bounded(&p, 1024).unwrap().1;
        assert_eq!(read_text_bounded(&p, 1024).unwrap().1, first);
        fs::write(&p, r#"{"a":2}"#).unwrap();
        set_mtime_ns(&p, 12345);
        assert_ne!(read_text_bounded(&p, 1024).unwrap().1, first);
    }

    #[test]
    fn an_unchanged_stamp_skips_the_read() {
        let d = TempDir::new();
        let p = d.path().join("live.json");
        fs::write(&p, r#"{"a":1}"#).unwrap();
        set_mtime_ns(&p, 1_000_000_000);
        let (_, stamp) = read_text_bounded_if_changed(&p, 1024, None).unwrap();
        fs::write(&p, r#"{"a":2}"#).unwrap();
        set_mtime_ns(&p, 1_000_000_000);
        assert_eq!(read_text_bounded_if_changed(&p, 1024, Some(stamp)), None);
        assert_eq!(read_text_bounded_if_changed(&p, 1024, None).unwrap().0, r#"{"a":2}"#);
    }

    #[test]
    fn legacy_snapshots_are_retired_with_a_tombstone() {
        let tmp = TempDir::new();
        let old = tmp.path().join("state");
        fs::create_dir(&old).unwrap();
        for name in [RECENT, APPS] {
            fs::write(old.join(name), "{}").unwrap();
        }
        let live = json!({"v": 1, "state": "online", "index": 93, "t": 1.0, "pid": 42, "pid_start": 7,
                          "daemon_version": "0.2.21", "link": {"ssid": "Home"}});
        write_atomic(&old.join(LIVE), &live, false).unwrap();
        retire_legacy_snapshots(&old, &tmp.path().join("runtime"), Some(2.0)).unwrap();
        assert!(!old.join(RECENT).exists());
        assert!(!old.join(APPS).exists());
        let tomb = read_json(&old.join(LIVE), READ_JSON_MAX).unwrap();
        assert_eq!(tomb["state"], json!("no-daemon"));
        assert_eq!(tomb["index"], Value::Null);
        assert_eq!(tomb["t"], json!(2.0));
        for key in ["pid", "pid_start", "daemon_version"] {
            assert!(tomb.get(key).is_none(), "{key}");
        }
        assert_eq!(tomb["link"], json!({"ssid": "Home"}));
        retire_legacy_snapshots(&old, &old, Some(3.0)).unwrap();
        assert_eq!(read_json(&old.join(LIVE), READ_JSON_MAX).unwrap()["t"], json!(2.0));
    }
}
