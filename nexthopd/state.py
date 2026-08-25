"""The two JSON files the QML side reads.

live.json is rewritten at the probe cadence and is all the bar widget ever
looks at. recent.json is a pre-downsampled 30-minute window so the panel's
default graphs paint without a subprocess. Both are written to a temp file
and renamed, so a reader never sees a half-written file — QML's FileView
would happily parse one and blank the widget.
"""

import json
import os
import tempfile
from pathlib import Path


def write_atomic(path: Path, payload: dict):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: Path, default=None, max_bytes: int = 4 * 1024 * 1024):
    """Bounded read of a state file. The bound lives on the read, not on a
    prior stat, for the same reason as the daemon's config read."""
    try:
        with open(path) as f:
            data = f.read(max_bytes + 1)
    except (OSError, UnicodeDecodeError):
        return default
    if len(data) > max_bytes:
        return default
    try:
        return json.loads(data)
    except ValueError:
        return default
