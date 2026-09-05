"""Reading and writing the JSON state files, safely.

live.json is rewritten twice a second and is all the bar widget ever looks
at; recent.json is a pre-downsampled 30-minute window so the panel's default
graphs paint without a query; apps.json is per-application traffic. All are
written to a temp file and renamed, so a reader never sees a half-written
file. The QML side does not open any of them itself (0.1.9): `nexthop
stream` reads them through `read_text_bounded` — no symlink following, a
regular file or nothing, a size cap on the read itself — and hands the shell
one re-serialised line per record.
"""

import json
import os
import stat
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


def read_text_bounded(path: Path, max_bytes: int):
    """Read a state file, enforcing every property on the fd actually read.

    `O_NOFOLLOW` refuses a symlinked path outright, `O_NONBLOCK` means a
    FIFO left at the path returns instead of stalling the caller, `fstat`
    on the descriptor proves it is a regular file, and the cap bounds the
    read itself rather than trusting a size sampled beforehand. Returns
    (text, stamp) or None; `stamp` is (mtime_ns, size), enough for a
    caller to skip re-reading an unchanged file.

    This is the only way state reaches a reader — the QML side consumes it
    through `nexthop stream` rather than opening these paths itself, so an
    oversized or non-regular file can never allocate or block inside the
    long-lived shell process.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        chunks, total = [], 0
        while total <= max_bytes:
            try:
                chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            except BlockingIOError:
                break
            except OSError:
                return None
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            return None
        stamp = (st.st_mtime_ns, st.st_size)
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8"), stamp
    except UnicodeDecodeError:
        return None


def read_json(path: Path, default=None, max_bytes: int = 4 * 1024 * 1024):
    """Bounded read of a state file, parsed. The bound lives on the read,
    not on a prior stat, for the same reason as the daemon's config read."""
    got = read_text_bounded(path, max_bytes)
    if got is None:
        return default
    try:
        return json.loads(got[0])
    except ValueError:
        return default
