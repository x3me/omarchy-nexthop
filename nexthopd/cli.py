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

from .paths import db_path, live_path, lock_path
from .state import read_json
from .store import Store

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


def open_store():
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
    args = ap.parse_args(argv)
    return {"live": cmd_live, "query": cmd_query, "events": cmd_events,
            "tests": cmd_tests, "peak": cmd_peak, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
