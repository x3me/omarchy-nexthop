"""`nexthop` — the query CLI the panel (and you) use for history.

Everything answers in JSON on stdout, because the consumer is a QML
Process { } as often as it is a person. The daemon is not involved: reads
go straight to the sqlite file, which WAL mode makes safe.

  nexthop query --window 24h     history series at the right resolution
  nexthop live                   the current live.json
  nexthop events --window 7d     outages, disruptions, changes
  nexthop tests [--kind peak]    speed test results
  nexthop report --window 24h    plain-text summary for an ISP ticket
  nexthop peak                   ask the running daemon for a peak test
"""

import argparse
import json
import os
import signal
import sys
import time

from .paths import (apps_path, db_path, live_path, lock_path, manifest_path,
                    recent_path)
from .state import read_json, read_text_bounded

WINDOWS = {"m": 60, "h": 3600, "d": 86400}


def parse_window(text: str) -> float:
    text = (text or "30m").strip().lower()
    unit = text[-1]
    if unit in WINDOWS:
        try:
            return float(text[:-1]) * WINDOWS[unit]
        except ValueError:
            pass
    try:
        return float(text)
    except ValueError:
        return 1800.0


def emit(obj):
    json.dump(obj, sys.stdout, separators=(",", ":"))
    print()


def cmd_live(_args):
    emit(read_json(live_path(), {"state": "no-daemon"}))
    return 0


# The QML side never opens a state file itself. It runs `nexthop stream`
# and reads whole lines, so the only code that touches these paths is the
# bounded no-follow non-blocking read in state.py — an oversized file, a
# FIFO or a symlink swap is refused here, in a small short-lived process,
# instead of allocating or stalling inside the long-lived shell.
#
# Keys, never paths: the caller picks from this table, so no argument it
# passes can widen what gets opened. Caps match each file's real size
# (live ~1 KB, apps ~8 KB, recent ~30 KB) with generous headroom.
STREAMABLE = {
    "live": (live_path, 256 * 1024),
    "apps": (apps_path, 1024 * 1024),
    "recent": (recent_path, 1024 * 1024),
    "manifest": (manifest_path, 256 * 1024),
}


def cmd_stream(args):
    """Emit `<key> <json>` lines whenever a watched file's contents change.

    The payload is re-serialised here rather than forwarded verbatim: it
    guarantees one line per record whatever the file's own formatting
    (manifest.json is indented, the state files are not), and it means
    only JSON this process already parsed successfully is ever handed to
    the shell.
    """
    keys = [k for k in dict.fromkeys(args.keys) if k in STREAMABLE]
    if not keys:
        print("stream: nothing to watch", file=sys.stderr)
        return 2
    interval = min(max(args.interval, 0.1), 60.0)
    last = {}
    while True:
        for key in keys:
            resolve, cap = STREAMABLE[key]
            got = read_text_bounded(resolve(), cap)
            if got is None:
                continue
            text, stamp = got
            if last.get(key) == stamp:
                continue
            last[key] = stamp
            try:
                payload = json.loads(text)
            except ValueError:
                continue          # a half-written or foreign file; skip it
            # ensure_ascii escapes any newline inside a string, so the
            # record cannot break the line framing.
            line = json.dumps(payload, separators=(",", ":"))
            try:
                sys.stdout.write(f"{key} {line}\n")
                sys.stdout.flush()
            except (BrokenPipeError, ValueError):
                # The shell went away; so do we. _exit skips the
                # interpreter's final flush, which would only raise the
                # same broken pipe again and print it to stderr.
                os._exit(0)
        time.sleep(interval)


def authorized_to_retire(pid: int, want_start: int) -> bool:
    """Is this pid really our daemon, and the same one live.json named?

    Three independent facts, all read from /proc and none of them a name
    match: the process must belong to this user, its argv must be exactly
    a python interpreter running `-m nexthopd`, and its start time must
    equal the one the daemon published. A recycled pid can reproduce the
    number but never the start time.

    This lives here rather than in a shell one-liner because the one-liner
    could not be tested and, as it turned out, did not run at all: the
    NUL it passed to `tr` truncated the script at execve.
    """
    try:
        if os.stat(f"/proc/{pid}").st_uid != os.getuid():
            return False
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = [a.decode("utf-8", "replace")
                    for a in f.read(4096).split(b"\0") if a]
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read(4096)
    except (OSError, ValueError):
        return False
    if len(argv) < 3 or "python" not in os.path.basename(argv[0]):
        return False
    if argv[1] != "-m" or argv[2] != "nexthopd" or len(argv) > 3:
        return False
    if want_start:
        try:
            start = int(data[data.rindex(b")") + 2:].split()[19])
        except (ValueError, IndexError):
            return False
        if start != want_start:
            return False
    return True


def cmd_retire(args):
    """SIGTERM a stale daemon, but only once its identity checks out."""
    if args.pid <= 0 or args.pid == os.getpid():
        return 1
    if not authorized_to_retire(args.pid, args.start):
        return 1
    try:
        os.kill(args.pid, signal.SIGTERM)
    except OSError:
        return 1
    return 0


def open_store():
    # Imported here, not at module scope: `stream` runs for the life of the
    # shell and has no use for sqlite3, so it should not pay to load it.
    from .store import Store
    path = db_path()
    if not path.exists():
        return None
    try:
        return Store(path, read_only=True)
    except Exception:
        return None


def cmd_query(args):
    store = open_store()
    if not store:
        emit({"error": "no history yet"})
        return 1
    seconds = parse_window(args.window)
    rows, table = store.series(seconds, resolution=args.resolution)
    emit({"window_s": seconds, "resolution": table, "rows": rows})
    return 0


def cmd_events(args):
    store = open_store()
    if not store:
        emit({"events": []})
        return 0
    emit({"events": store.events(parse_window(args.window))})
    return 0


def cmd_tests(args):
    store = open_store()
    if not store:
        emit({"tests": []})
        return 0
    emit({"tests": store.tests(limit=args.limit, kind=args.kind)})
    return 0


def cmd_peak(_args):
    """Ring the daemon's doorbell. SIGUSR1 is the whole protocol."""
    try:
        with open(lock_path()) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGUSR1)
    except (OSError, ValueError):
        emit({"ok": False, "error": "daemon not running"})
        return 1
    emit({"ok": True})
    return 0


def fmt_ms(v):
    return "--" if v is None else f"{v:.1f} ms"


def fmt_pct(v):
    return "--" if v is None else f"{v * 100:.2f}%"


def cmd_report(args):
    """The paste-into-a-ticket summary. Plain text by design."""
    store = open_store()
    live = read_json(live_path(), {})
    seconds = parse_window(args.window)
    lines = []
    link = live.get("link", {})
    lines.append(f"Nexthop report — last {args.window}")
    lines.append(f"generated {time.strftime('%Y-%m-%d %H:%M %Z')}")
    if link:
        what = link.get("ssid") or link.get("name") or link.get("iface", "?")
        lines.append(f"connection: {what} ({link.get('kind', '?')}), "
                     f"gateway {link.get('gateway', '?')}")
    lines.append("")
    if store:
        rows, table = store.series(seconds)
        vals = lambda k: [r[k] for r in rows if r.get(k) is not None]

        def block(name, p50key, p95key, losskey):
            p50, p95, loss = vals(p50key), vals(p95key), vals(losskey)
            if not p50:
                lines.append(f"{name}: no data")
                return
            lines.append(
                f"{name}: median {sum(p50)/len(p50):.1f} ms, "
                f"p95 {max(p95) if p95 else 0:.1f} ms (worst {table} bucket), "
                f"loss {sum(loss)/len(loss)*100 if loss else 0:.2f}%")

        block("local leg (to router)", "local_p50", "local_p95", "local_loss")
        block("wan leg (past router)", "wan_p50", "wan_p95", "wan_loss")
        lines.append("")
        events = store.events(seconds)
        if events:
            lines.append("events:")
            for e in events:
                start = time.strftime("%a %H:%M", time.localtime(e["ts"]))
                dur = (f"{e['ended_ts'] - e['ts']}s" if e["ended_ts"]
                       else "ongoing")
                lines.append(f"  {start}  {e['kind']} on {e['leg']} leg, {dur}"
                             f" — {e['detail']}")
        else:
            lines.append("events: none")
        tests = store.tests(limit=5)
        if tests:
            lines.append("")
            lines.append("speed tests:")
            for t in tests:
                when = time.strftime("%a %H:%M", time.localtime(t["ts"]))
                down = f"{t['down_mbps']:.0f}" if t["down_mbps"] else "--"
                up = f"{t['up_mbps']:.0f}" if t["up_mbps"] else "--"
                lines.append(f"  {when}  {t['kind']:<8} {down}/{up} Mbps"
                             f"  ({t['engine']})")
    print("\n".join(lines))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nexthop")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("live")
    q = sub.add_parser("query")
    q.add_argument("--window", default="30m")
    q.add_argument("--resolution", default="auto",
                   choices=["auto", "minute", "hour"])
    e = sub.add_parser("events")
    e.add_argument("--window", default="7d")
    t = sub.add_parser("tests")
    t.add_argument("--kind", default=None)
    t.add_argument("--limit", type=int, default=20)
    sub.add_parser("peak")
    r = sub.add_parser("report")
    r.add_argument("--window", default="24h")
    s = sub.add_parser("stream")
    s.add_argument("keys", nargs="+", choices=sorted(STREAMABLE))
    s.add_argument("--interval", type=float, default=0.5)
    rt = sub.add_parser("retire")
    rt.add_argument("--pid", type=int, required=True)
    rt.add_argument("--start", type=int, default=0)
    args = ap.parse_args(argv)
    return {"live": cmd_live, "query": cmd_query, "events": cmd_events,
            "tests": cmd_tests, "peak": cmd_peak, "report": cmd_report,
            "stream": cmd_stream, "retire": cmd_retire}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
