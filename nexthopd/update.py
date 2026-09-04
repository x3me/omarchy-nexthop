"""Is a newer version published? Notify, never install.

Omarchy checks itself for updates (`omarchy-update-available` looks at its own
checkout and its package) but nothing checks plugins, so a user can sit on an
old Nexthop indefinitely without ever being told. This closes that gap the
smallest way it can be closed.

**This module never updates anything.** It answers one question — is the
installed checkout behind its origin — and the answer becomes a quiet glyph in
the panel naming the command the user can run. Updating stays where Omarchy
put it: `omarchy plugin update`, which shows the diff and asks. A plugin that
fetched and ran new code would be self-modifying code inside a system that
deliberately gates updates behind human review, and it would reopen a security
review that took four rounds to clear.

How it stays cheap and read-only:

* `git ls-remote` asks the remote for its HEAD without writing a single byte
  into the user's checkout — no fetch, no new objects, no refs touched. It
  takes well under a second and needs no credentials.
* Whether we are *behind* rather than merely *different* is then decided from
  objects we already have, so a developer checkout that is ahead of origin is
  never nagged.
* Egress is to the repository the user installed from and nowhere else. It
  carries nothing about them or their network. It is still egress, so it is
  disclosed and `updateCheck` turns it off.

The one piece of untrusted input here is the commit id the remote hands back,
and it goes on to be an argument to another `git` call — so it is validated
against the exact 40-hex shape before it reaches a subprocess, the same
doctrine `vet_target()` applies to URLs we did not choose.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

# A git object id and nothing else. This is the guard that matters: the value
# arrives from the network and is then passed as an argument to git.
RE_SHA = re.compile(r"^[0-9a-f]{40}$")

# A release is a rare event, and the check exists to catch the user who would
# otherwise never look. Daily is generous.
CHECK_INTERVAL_S = 24 * 3600
# Not at startup: the daemon restarts with the shell, and a check on every
# restart would be noise for no benefit. Nothing is lost by waiting.
FIRST_CHECK_DELAY_S = 300
# The remote may be slow, unreachable, or a captive portal that answers
# everything. None of those may stall the daemon.
GIT_TIMEOUT_S = 20
# `ls-remote` prints one short line per ref; this is far past HEAD alone.
MAX_LS_REMOTE_BYTES = 64 * 1024


def verdict(local: str, remote: str, have_remote: bool,
            head_before_remote: bool, remote_before_head: bool) -> str:
    """Where the checkout stands relative to origin. Pure, so it is testable.

    * `current`  — the same commit.
    * `behind`   — origin is strictly ahead of us: an update.
    * `ahead`    — we are strictly ahead of origin: a dev checkout.
    * `diverged` — neither contains the other.
    * `unknown`  — we could not tell, and say so rather than guessing.

    Both ancestry directions are needed, and the reason is the likeliest
    case of all: `omarchy plugin update` fetches before it shows its diff, so
    a user who looked and said "not now" already *holds* origin's commit
    while still being behind it. Deciding "behind" from "we have never seen
    that object" alone would show that user nothing.
    """
    if not local or not remote:
        return "unknown"
    if local == remote:
        return "current"
    if not have_remote:
        # We do not hold origin's commit at all, so it is newer than anything
        # we know about.
        return "behind"
    if head_before_remote:
        return "behind"
    if remote_before_head:
        return "ahead"
    return "diverged"


class UpdateWatch:
    """Asks origin, on a slow cadence, whether this checkout is behind.

    The result lives in memory only. A daemon restart forgets it and waits
    `FIRST_CHECK_DELAY_S` before asking again, which is why no fifth state
    file was added for this.
    """

    def __init__(self, repo: Path = None, enabled: bool = True):
        # Derived from this file, not from the working directory: the daemon
        # can be started from anywhere.
        self.repo = Path(repo) if repo else Path(__file__).resolve().parent.parent
        self.enabled = enabled
        self.state = "unknown"
        self.checked_ts = None
        self.remote = None
        self._next = None

    def _git(self, *args, capture: bool = True):
        """One git call. Fixed argv, no shell, bounded, always timed out."""
        env = dict(os.environ)
        # A credential prompt on a private or moved remote would otherwise
        # block until the timeout every single time.
        env["GIT_TERMINAL_PROMPT"] = "0"
        env.pop("GIT_ASKPASS", None)
        env.pop("SSH_ASKPASS", None)
        try:
            proc = subprocess.run(
                ["git", "-C", str(self.repo), *args],
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=GIT_TIMEOUT_S, env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, ""
        out = ""
        if capture and proc.stdout:
            out = proc.stdout[:MAX_LS_REMOTE_BYTES].decode(
                "utf-8", "replace").strip()
        return proc.returncode, out

    def _local_head(self):
        code, out = self._git("rev-parse", "HEAD")
        return out if code == 0 and RE_SHA.match(out) else None

    def _remote_head(self):
        """Origin's HEAD, or None. Writes nothing into the checkout."""
        code, out = self._git("ls-remote", "origin", "HEAD")
        if code != 0 or not out:
            return None
        sha = out.split()[0] if out.split() else ""
        # The guard: this value came off the network and is about to become a
        # git argument. Anything but a bare object id is refused outright.
        return sha if RE_SHA.match(sha) else None

    def check(self) -> str:
        """Run one check now and return the verdict. Read-only throughout."""
        if not shutil.which("git"):
            return "unknown"
        local = self._local_head()
        if not local:
            return "unknown"          # not a git checkout, or no commits
        remote = self._remote_head()
        if not remote:
            return "unknown"          # offline, no origin, or a junk answer
        self.remote = remote
        if local == remote:
            return "current"
        # Do we already hold origin's commit? Only objects we have are
        # consulted from here on, so no fetch is ever needed.
        code, _ = self._git("cat-file", "-e", remote + "^{commit}",
                            capture=False)
        have = code == 0
        before, after = False, False
        if have:
            # Exit 1 means "not an ancestor", which is an answer, not an error.
            code, _ = self._git("merge-base", "--is-ancestor", local, remote,
                                capture=False)
            before = code == 0
            code, _ = self._git("merge-base", "--is-ancestor", remote, local,
                                capture=False)
            after = code == 0
        return verdict(local, remote, have, before, after)

    def tick(self, now: float):
        """Called from the daemon loop; does nothing until the cadence is due."""
        if not self.enabled:
            # Turning the setting off clears any standing notice, so the
            # glyph disappears rather than lingering with a stale answer.
            self.state, self.checked_ts, self._next = "unknown", None, None
            return
        if self._next is None:
            self._next = now + FIRST_CHECK_DELAY_S
            return
        if now < self._next:
            return
        self._next = now + CHECK_INTERVAL_S
        self.state = self.check()
        self.checked_ts = round(now)

    def snapshot(self) -> dict:
        """What the panel reads. None while nothing has been established."""
        if not self.enabled or self.state == "unknown":
            return None
        return {
            "state": self.state,
            "available": self.state == "behind",
            "checked_ts": self.checked_ts,
        }
