"""Who ended the last Wi-Fi association: the access point, this machine,
or nobody (the link fell over).

A BSSID change seen through `iw dev link` is only a fact: we were on one
radio and now we are on another. Whether that was the client's decision,
the access point's, or a link failure is the difference between a laptop
that roams, a router that kicks, and a driver that drops — three problems
with three owners, and the log used to call all of them "Roamed to".

`iw event` is the unprivileged view of nl80211's mlme multicast group.
Every deauthentication and disassociation frame the kernel sends or
receives is reported with its sender, receiver and 802.11 reason code, and
the authentication that follows is reported too. That is enough:

- the frame's sender says who ended it — the AP's address means it kicked
  us, our own means this machine did;
- the reason code says why, in the AP's or the driver's own words;
- the delay before the next authentication says whether the client already
  knew where it was going. mac80211 emits the local deauth from inside the
  call that starts the new authentication when it roams, so a roam's gap is
  milliseconds; a lost link is followed by a scan first, and its gap is
  seconds.

Only the kernel talks to this module, through `iw`. Lines are read with a
length cap and matched against fixed patterns; two MACs and a reason code
are the only fields kept, and only our own reason texts reach the shell.
"""

import re
import shutil
import subprocess
import threading
import time
from collections import deque

# `iw event -t` line: "<secs>.<usecs>: <ifname> (phy #N): <event...>". The
# timestamp is CLOCK_REALTIME — the clock the daemon stamps with — and it
# is optional so recorded fixtures read the same with or without it.
_PREFIX = r"^(?:(\d+\.\d+): )?\S+(?: \(phy #\d+\))?: "
_MAC = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
_ANY_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
# A deauth/disassoc frame: "<sender> -> <receiver> reason N: <text>".
# "unprotected deauth" (a forged frame the kernel refused) does not match:
# the frame word must follow the prefix directly.
RE_FRAME = re.compile(_PREFIX + r"(deauth|disassoc) " + _MAC + " -> " + _MAC
                      + r" reason (\d{1,5})\b")
# The first sign of the next association landing.
RE_NEXT = re.compile(_PREFIX + r"(?:(?:auth|assoc) " + _ANY_MAC + " -> "
                     + _ANY_MAC + r" status: 0\b|(?:connected|roamed) to "
                     + _ANY_MAC + r"\b)")

# 802.11 reason codes, in the words a person would use. Codes 3 and 4 mean
# different things depending on who sent them, so they get a side each
# (a GX gateway's per-station kick arrives as 8, for instance).
REASONS = {
    1: "unspecified",
    2: "previous authentication no longer valid",
    5: "the AP is full",
    6: "class 2 frame from an unauthenticated station",
    7: "class 3 frame from an unassociated station",
    9: "not authenticated",
    14: "MIC failure",
    15: "4-way handshake timeout",
    16: "group key handshake timeout",
    17: "IE mismatch in the 4-way handshake",
    23: "802.1X authentication failed",
    34: "poor channel conditions",
    39: "timeout",
}
AP_REASONS = {3: "the AP is leaving", 4: "inactivity", 8: "the AP is leaving the BSS"}
LOCAL_REASONS = {3: "leaving", 4: "beacon loss", 8: "leaving the BSS"}


def reason_text(code, by_ap):
    """'reason 2: previous authentication no longer valid'. Only our own
    words, never the tool's: nothing from the wire reaches the shell."""
    side = AP_REASONS if by_ap else LOCAL_REASONS
    text = side.get(code) or REASONS.get(code)
    return "reason %d: %s" % (code, text) if text else "reason %d" % code


class NlEvents(threading.Thread):
    """Runs `iw event` forever, restarting it if it dies, keeping the last
    few deauth/disassoc frames and when the next authentication followed.

    Like the probes, this never raises into the daemon: without `iw`, or
    when the socket is refused, the thread backs off and `cause_for`
    answers None — and the link log falls back to plain "Roamed to".
    """

    MAX_CAUSES = 64
    LINE_CAP = 1024

    def __init__(self):
        super().__init__(name="nl-events", daemon=True)
        self._stop = threading.Event()
        self._proc = None
        self._lock = threading.Lock()
        self._causes = deque(maxlen=self.MAX_CAUSES)

    def stop(self):
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            if not shutil.which("iw"):
                time.sleep(min(backoff, 30.0))
                backoff = min(backoff * 2, 30.0)
                continue
            try:
                self._run_once()
            except Exception:
                pass    # a spawn or parse failure is a retry, not a crash
            if not self._stop.is_set():
                # `iw event` never exits on its own; if it did, nl80211
                # refused us or the tool is broken — do not spin on it.
                time.sleep(min(backoff, 30.0))
                backoff = min(backoff * 2, 30.0)

    def _run_once(self):
        self._proc = subprocess.Popen(
            ["iw", "event", "-t"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, errors="replace", bufsize=1,
        )
        try:
            while not self._stop.is_set():
                # A capped read: an over-long line comes back in pieces
                # that match nothing, instead of growing a buffer.
                line = self._proc.stdout.readline(self.LINE_CAP)
                if not line:
                    break
                self.consume(line)
        finally:
            proc, self._proc = self._proc, None
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    def consume(self, line: str, now: float = None):
        m = RE_FRAME.match(line)
        if m:
            t = float(m.group(1)) if m.group(1) else (now or time.time())
            with self._lock:
                self._causes.append({
                    "t": t, "frame": m.group(2),
                    "sa": m.group(3).lower(), "da": m.group(4).lower(),
                    "reason": min(int(m.group(5)), 65535), "next_at": None,
                })
            return
        m = RE_NEXT.match(line)
        if m:
            t = float(m.group(1)) if m.group(1) else (now or time.time())
            with self._lock:
                # Only the newest cause is still waiting for its follow-up.
                if self._causes and self._causes[-1]["next_at"] is None:
                    self._causes[-1]["next_at"] = t

    def cause_for(self, bssid: str, now: float, window: float):
        """The latest frame within `window` seconds that ended our
        association with `bssid`, or None.

        by_ap: the AP sent it. gap_s: seconds until the next authentication
        was seen, None if none has been yet.
        """
        bssid = (bssid or "").lower()
        if not bssid:
            return None
        with self._lock:
            for c in reversed(self._causes):
                if now - c["t"] > window:
                    break
                if bssid not in (c["sa"], c["da"]):
                    continue
                gap = None if c["next_at"] is None else max(0.0, c["next_at"] - c["t"])
                return {"t": c["t"], "frame": c["frame"], "by_ap": c["sa"] == bssid,
                        "reason": c["reason"], "gap_s": gap}
        return None
