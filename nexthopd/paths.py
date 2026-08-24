"""Where Nexthop keeps its state.

One directory, three files the QML side reads, and a lock so two daemons
never fight over them. Honours XDG_STATE_HOME like the rest of Omarchy.
"""

import os
from pathlib import Path


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(Path.home(), ".local", "state")
    return Path(base) / "nexthop"


def ensure_state_dir() -> Path:
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


LIVE = "live.json"
RECENT = "recent.json"
DB = "history.db"
LOCK = "nexthopd.lock"


def live_path() -> Path:
    return state_dir() / LIVE


def recent_path() -> Path:
    return state_dir() / RECENT


def db_path() -> Path:
    return state_dir() / DB


def lock_path() -> Path:
    return state_dir() / LOCK
