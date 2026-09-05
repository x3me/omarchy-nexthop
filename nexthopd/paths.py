"""Where Nexthop keeps its state.

One directory: the four files the daemon writes (live.json, recent.json,
apps.json, history.db), the config.json the panel writes for it, and a lock
so two daemons never fight over them. Honours XDG_STATE_HOME like the rest
of Omarchy.
"""

import os
from pathlib import Path


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(Path.home(), ".local", "state")
    return Path(base) / "nexthop"


def ensure_state_dir() -> Path:
    """Create the state dir, private to the user (0700).

    The files inside carry the daemon's pid and the version string the
    shell service uses to authorize a SIGTERM — nothing another account
    has any business reading, let alone writing.
    """
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


LIVE = "live.json"
RECENT = "recent.json"
APPS = "apps.json"
DB = "history.db"
LOCK = "nexthopd.lock"


def live_path() -> Path:
    return state_dir() / LIVE


def recent_path() -> Path:
    return state_dir() / RECENT


def apps_path() -> Path:
    return state_dir() / APPS


def manifest_path() -> Path:
    """The plugin's own manifest, beside this package rather than in the
    state dir — the shell service reads it to spot a fast-forwarded
    checkout."""
    return Path(__file__).resolve().parent.parent / "manifest.json"


def db_path() -> Path:
    return state_dir() / DB


def lock_path() -> Path:
    return state_dir() / LOCK
