use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use crate::paths::{apps_path, live_path, manifest_path, recent_path};
use crate::pyjson;
use crate::state::{Stamp, read_text_bounded_if_changed};

pub const STREAMABLE: [(&str, usize); 4] =
    [("live", 256 * 1024), ("apps", 1024 * 1024), ("recent", 1024 * 1024), ("manifest", 256 * 1024)];

fn resolve(key: &str) -> PathBuf {
    match key {
        "live" => live_path(),
        "apps" => apps_path(),
        "recent" => recent_path(),
        _ => manifest_path(),
    }
}

pub struct Streamer {
    targets: Vec<(String, PathBuf, usize)>,
    last: HashMap<String, Stamp>,
}

impl Streamer {
    pub fn new(targets: Vec<(String, PathBuf, usize)>) -> Streamer {
        Streamer { targets, last: HashMap::new() }
    }

    pub fn for_keys(keys: &[String]) -> Streamer {
        let mut targets: Vec<(String, PathBuf, usize)> = Vec::new();
        for key in keys {
            let Some(&(name, cap)) = STREAMABLE.iter().find(|(k, _)| k == key) else {
                continue;
            };
            if !targets.iter().any(|(k, _, _)| k == name) {
                targets.push((name.to_string(), resolve(name), cap));
            }
        }
        Streamer::new(targets)
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn poll(&mut self, out: &mut dyn Write) -> io::Result<()> {
        for (key, path, cap) in &self.targets {
            let Some((text, stamp)) = read_text_bounded_if_changed(path, *cap, self.last.get(key).copied()) else {
                continue;
            };
            self.last.insert(key.clone(), stamp);
            let Ok(payload) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let line = pyjson::to_string(&payload).map_err(io::Error::other)?;
            out.write_all(format!("{key} {line}\n").as_bytes())?;
            out.flush()?;
        }
        Ok(())
    }
}

pub fn cmd_stream(keys: &[String], interval: f64) -> i32 {
    let mut streamer = Streamer::for_keys(keys);
    if streamer.is_empty() {
        eprintln!("stream: nothing to watch");
        return 2;
    }
    let interval = Duration::from_secs_f64(if interval.is_nan() { 0.1 } else { interval.clamp(0.1, 60.0) });
    let stdout = io::stdout();
    loop {
        if let Err(e) = streamer.poll(&mut stdout.lock()) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                return 0;
            }
            eprintln!("stream: {e}");
            return 1;
        }
        std::thread::sleep(interval);
    }
}
