use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const LIVE: &str = "live.json";
pub const RECENT: &str = "recent.json";
pub const APPS: &str = "apps.json";
pub const DB: &str = "history.db";
pub const LOCK: &str = "nexthopd.lock";

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

fn non_empty_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

pub fn state_dir() -> PathBuf {
    non_empty_env("XDG_STATE_HOME").unwrap_or_else(|| home().join(".local").join("state")).join("nexthop")
}

pub fn ensure_state_dir() -> std::io::Result<PathBuf> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    Ok(dir)
}

pub fn runtime_dir() -> PathBuf {
    runtime_dir_for(non_empty_env("XDG_RUNTIME_DIR"), state_dir())
}

fn runtime_dir_for(base: Option<PathBuf>, state: PathBuf) -> PathBuf {
    match base {
        Some(base) if base.is_dir() => base.join("nexthop"),
        _ => state,
    }
}

pub fn ensure_runtime_dir() -> std::io::Result<PathBuf> {
    let dir = runtime_dir();
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    Ok(dir)
}

pub fn live_path() -> PathBuf {
    runtime_dir().join(LIVE)
}

pub fn recent_path() -> PathBuf {
    runtime_dir().join(RECENT)
}

pub fn apps_path() -> PathBuf {
    runtime_dir().join(APPS)
}

pub fn db_path() -> PathBuf {
    state_dir().join(DB)
}

pub fn lock_path() -> PathBuf {
    state_dir().join(LOCK)
}

pub fn plugin_dir() -> PathBuf {
    let exe = std::env::current_exe().and_then(|p| p.canonicalize()).unwrap_or_default();
    plugin_dir_for(non_empty_env("NEXTHOP_PLUGIN_DIR"), &exe)
}

fn plugin_dir_for(launcher_root: Option<PathBuf>, exe: &Path) -> PathBuf {
    launcher_root
        .filter(|dir| dir.join("manifest.json").is_file())
        .or_else(|| exe.ancestors().skip(1).find(|dir| dir.join("manifest.json").is_file()).map(Path::to_path_buf))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

pub fn manifest_path() -> PathBuf {
    plugin_dir().join("manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn the_plugin_dir_is_the_launcher_root_even_when_the_binary_is_cached_elsewhere() {
        let tmp = TempDir::new();
        let root = tmp.path().join("plugin");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("manifest.json"), "{}").unwrap();
        let cached = tmp.path().join("cache").join("abc").join("nexthop");
        assert_eq!(plugin_dir_for(Some(root.clone()), &cached), root);
        assert_eq!(plugin_dir_for(None, &root.join("bin").join("nexthop")), root);
        assert_ne!(plugin_dir_for(Some(tmp.path().join("cache")), &cached), tmp.path().join("cache"));
    }

    #[test]
    fn runtime_dir_prefers_xdg_runtime_dir() {
        let tmp = TempDir::new();
        let state = tmp.path().join("state").join("nexthop");
        assert_eq!(runtime_dir_for(Some(tmp.path().to_path_buf()), state.clone()), tmp.path().join("nexthop"));
        assert_eq!(runtime_dir_for(Some(tmp.path().join("missing")), state.clone()), state);
        assert_eq!(runtime_dir_for(None, state.clone()), state);
        for path in [live_path(), recent_path(), apps_path()] {
            assert_eq!(path.parent().unwrap(), runtime_dir());
        }
        for path in [db_path(), lock_path()] {
            assert_eq!(path.parent().unwrap(), state_dir());
        }
    }
}
