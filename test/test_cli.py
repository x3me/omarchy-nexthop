"""Tests for cli.py — the two signal paths and what authorizes them.

Run: python3 -m unittest discover -s test
"""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from support import REPO  # noqa: E402


class RetireAuthorization(unittest.TestCase):
    """The guard that stands between a version mismatch and a SIGTERM.

    It used to be a shell one-liner that could not be tested; it passed a
    NUL to `tr`, so execve truncated the script and no daemon was ever
    actually retired. These cases pin each fact it checks.
    """

    def setUp(self):
        from nexthopd.cli import authorized_to_retire
        self.auth = authorized_to_retire
        from nexthopd.daemon import proc_start_ticks
        self.ticks = proc_start_ticks

    def spawn(self, args, cwd=None):
        import subprocess
        p = subprocess.Popen(args, cwd=cwd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        time.sleep(0.4)
        return p

    def daemon_shaped(self):
        """A process whose argv is exactly `python -m nexthopd`.

        A stand-in rather than the real daemon: the real one would lose the
        flock race against whatever is already running and exit before the
        guard could look at it, and a test has no business probing the
        network. The guard reads argv, owner and start time — all of which
        this reproduces exactly.
        """
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        pkg = Path(d) / "nexthopd"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "__main__.py").write_text("import time\ntime.sleep(30)\n")
        return self.spawn([sys.executable, "-m", "nexthopd"], cwd=d)

    def test_daemon_argv_with_matching_start_is_authorized(self):
        p = self.daemon_shaped()
        self.assertTrue(self.auth(p.pid, self.ticks(p.pid)))

    def test_wrong_start_time_refused(self):
        p = self.daemon_shaped()
        self.assertFalse(self.auth(p.pid, self.ticks(p.pid) + 1))

    def test_zero_start_skips_only_the_time_check(self):
        # live.json from a daemon too old to publish pid_start: argv and
        # ownership still have to hold.
        p = self.daemon_shaped()
        self.assertTrue(self.auth(p.pid, 0))

    def test_other_python_process_refused(self):
        # Same interpreter, different module: never ours to signal.
        p = self.spawn([sys.executable, "-c", "import time; time.sleep(30)"])
        self.assertFalse(self.auth(p.pid, 0))

    def test_lookalike_argv_refused(self):
        # A process that merely mentions nexthopd is not the daemon.
        p = self.spawn([sys.executable, "-c",
                        "import time; time.sleep(30)  # -m nexthopd"])
        self.assertFalse(self.auth(p.pid, 0))

    def test_extra_arguments_refused(self):
        p = self.spawn([sys.executable, "-m", "nexthopd.cli", "stream", "live"])
        self.assertFalse(self.auth(p.pid, 0))

    def test_pid_that_does_not_exist_refused(self):
        self.assertFalse(self.auth(999999, 0))

    def test_pid_one_refused(self):
        # Owned by root, so the ownership check alone stops us.
        self.assertFalse(self.auth(1, 0))

    def test_command_string_carries_no_nul(self):
        # The regression itself: the argv QML hands to sh must survive
        # execve, which a NUL byte would truncate.
        import subprocess
        cmd = ('cd "$1" && exec python3 -m nexthopd.cli retire '
               '--pid "$2" --start "$3"')
        self.assertNotIn("\0", cmd)
        r = subprocess.run(["sh", "-c", cmd, "sh", str(REPO), "999999", "0"],
                           capture_output=True)
        self.assertEqual(r.returncode, 1)      # refused, not a syntax error
        self.assertEqual(r.stderr, b"")


class PeakSignalAuthorization(unittest.TestCase):
    """`nexthop peak` signals only a verified lock holder. SIGUSR1's default
    disposition is terminate, so the wrong pid is not a harmless miss."""

    def setUp(self):
        import contextlib, io
        from nexthopd import cli, paths
        self.dir = tempfile.TemporaryDirectory()
        os.environ["XDG_STATE_HOME"] = self.dir.name
        self.cli = cli
        self.lock = str(paths.lock_path())
        os.makedirs(os.path.dirname(self.lock), mode=0o700, exist_ok=True)
        self.killed = []
        self._kill = os.kill
        os.kill = lambda pid, sig: self.killed.append((pid, sig))
        self._quiet = contextlib.redirect_stdout(io.StringIO())
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)
        os.kill = self._kill
        del os.environ["XDG_STATE_HOME"]
        self.dir.cleanup()

    def test_a_lock_nobody_holds_is_not_a_daemon(self):
        # A dead daemon's pid, recycled by a live process — this one.
        Path(self.lock).write_text(str(os.getpid()))
        self.assertEqual(self.cli.cmd_peak(None), 1)
        self.assertEqual(self.killed, [])

    def test_a_held_lock_still_needs_the_holders_identity(self):
        import fcntl
        # Hold the lock ourselves: our argv is the test runner, not
        # `python -m nexthopd`, so the identity check must refuse it.
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, str(os.getpid()).encode())
        try:
            self.assertEqual(self.cli.cmd_peak(None), 1)
            self.assertEqual(self.killed, [])
        finally:
            os.close(fd)

    def test_a_symlink_at_the_lock_path_is_refused(self):
        os.symlink("/proc/self/stat", self.lock)
        self.assertEqual(self.cli.cmd_peak(None), 1)
        self.assertEqual(self.killed, [])

    def test_missing_lock_file_is_not_a_daemon(self):
        self.assertEqual(self.cli.cmd_peak(None), 1)
        self.assertEqual(self.killed, [])


class ReportThroughAVpn(unittest.TestCase):
    """The report is the document handed to an ISP, so a VPN's minutes must
    never appear as the line's [D, Plamen, 2026-09-13]."""

    def test_tunnel_minutes_are_kept_out_of_the_wan_leg_and_named(self):
        from nexthopd.cli import report_text
        from nexthopd.store import Store
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.db")
            try:
                now = time.time()
                base = int(now // 60) * 60
                for m in range(30):
                    store.put_minute(base - 3600 + 60 * m,
                                     {"local_p50": 2.0, "wan_p50": 6.0, "wan_p95": 9.0,
                                      "wan_loss": 0.0, "local_loss": 0.0})
                    store.put_minute(base - 1800 + 60 * m,
                                     {"local_p50": 2.0, "wan_p50": 150.0, "wan_p95": 190.0,
                                      "wan_loss": 0.0, "local_loss": 0.0, "vpn": "wg0"})
                eid = store.open_event(base - 1800, "vpn", "info", "tunnel",
                                       "Measured through a VPN (wg0)")
                store.close_event(eid, base)
                store.put_test(int(now - 60), "content", "cloudflare",
                               down_mbps=90.0, up_mbps=30.0, ok=True, vpn="wg0")
                text = report_text(store, {}, 2 * 3600, "2h")
            finally:
                store.close()
        wan = next(l for l in text.splitlines() if l.startswith("wan leg"))
        self.assertIn("median 6.0 ms", wan)              # the line alone
        self.assertIn("through a VPN (past router, not the ISP line): median 150.0 ms", text)
        self.assertIn("measured through a VPN (wg0): figures in this span describe "
                      "the tunnel, not the ISP line.", text)
        self.assertIn("via VPN", next(l for l in text.splitlines() if "90/30" in l))

    def test_event_bssids_are_decorated_in_the_report(self):
        from nexthopd import net
        from nexthopd.cli import report_text
        from nexthopd.store import Store
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.db")
            original = net.AP_INVENTORY
            net.AP_INVENTORY = type("Inventory", (), {
                "lookup": lambda self, bssid: "Hallway AP"})()
            try:
                store.open_event(int(time.time()), "roam", "info", "local",
                                 "Roamed to 02:00:00:00:00:01")
                text = report_text(store, {}, 3600, "1h")
            finally:
                net.AP_INVENTORY = original
                store.close()
        self.assertIn(
            "Roamed to Hallway AP (02:00:00:00:00:01)", text)


class ReportUnseenEnds(unittest.TestCase):
    """An event closed by the next daemon has a placeholder end. The report
    is handed to an ISP, so it must not print that second as a length (#9)."""

    def test_an_orphan_is_reported_without_a_length(self):
        from nexthopd.cli import report_text
        from nexthopd.store import Store
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.db")
            try:
                now = int(time.time())
                store.open_event(now - 600, "outage", "critical", "wan",
                                 "router answers, nothing past it does")
                store.open_event(now - 900, "vpn", "info", "tunnel",
                                 "Measured through a VPN (wg0)")
                seen = store.open_event(now - 300, "disruption", "warn",
                                        "local", "brief interruption")
                store.close_event(seen, now - 297)
                store.close_orphans(now)
                text = report_text(store, {}, 3600, "1h")
            finally:
                store.close()
        outage = next(l for l in text.splitlines() if "outage on wan" in l)
        self.assertIn("duration unknown (monitoring stopped first)", outage)
        self.assertNotIn(", 1s", outage)
        self.assertIn("onwards (end not seen) measured through a VPN (wg0)", text)
        self.assertIn("disruption on local leg, 3s", text)   # seen ends keep theirs


if __name__ == "__main__":
    unittest.main()
