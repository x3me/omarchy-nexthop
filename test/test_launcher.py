import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import REPO  # noqa: E402

FAKE_BINARY = '#!/bin/sh\necho "ran $0 $* from $NEXTHOP_PLUGIN_DIR"\n'

FAKE_CURL = """#!/bin/sh
while [ $# -gt 1 ]; do
  case "$1" in -o) out=$2; shift ;; esac
  shift
done
echo "$1" >> "$CURL_LOG"
[ -f "$CURL_SERVES" ] || exit 22
cp "$CURL_SERVES" "$out"
"""


class Launcher(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = self.tmp / "plugin"
        (self.root / "bin").mkdir(parents=True)
        shutil.copy(REPO / "bin" / "nexthop", self.root / "bin" / "nexthop")
        shutil.copytree(REPO / "nexthopd", self.root / "nexthopd")
        (self.root / "manifest.json").write_text(json.dumps({"version": "9.9.9"}))
        self.served = self.tmp / "served"
        self.served.write_text(FAKE_BINARY)
        self.pin(FAKE_BINARY)
        self.origin("git@github.com:someone/omarchy-nexthop.git")
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        (stubs / "curl").write_text(FAKE_CURL)
        (stubs / "curl").chmod(0o755)
        self.log = self.tmp / "curl.log"
        self.cache = self.tmp / "xdg-cache"
        self.env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", XDG_CACHE_HOME=str(self.cache),
                        CURL_LOG=str(self.log), CURL_SERVES=str(self.served))

    def pin(self, content):
        self.digest = hashlib.sha256(content.encode()).hexdigest()
        (self.root / "bin" / "nexthop.sha256").write_text(f"{self.digest}  nexthop-x86_64\n")

    def origin(self, url):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "remote", "remove", "origin"], capture_output=True)
        subprocess.run(["git", "-C", str(self.root), "remote", "add", "origin", url], check=True)

    def run_in_root(self, *argv):
        return subprocess.run(list(argv), cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)

    def run_launcher(self, *args):
        return self.run_in_root(str(self.root / "bin" / "nexthop"), *args)

    def downloads(self):
        return self.log.read_text().split() if self.log.exists() else []

    def exe(self):
        return self.cache / "nexthop" / self.digest / "nexthop"

    def test_fetches_the_release_of_its_own_origin_once_then_runs_it(self):
        first = self.run_launcher("stream", "live")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, f"ran {self.exe()} stream live from {self.root}\n")
        self.run_launcher("live")
        self.assertEqual(self.downloads(), [
            "https://github.com/someone/omarchy-nexthop/releases/download/v9.9.9/nexthop-x86_64"])

    # The shell reloads a plugin, killing its processes, on any write inside the plugin folder
    def test_nothing_is_written_inside_the_plugin_folder(self):
        before = sorted(str(p) for p in self.root.rglob("*") if ".git" not in p.parts)
        self.run_launcher("live")
        after = sorted(str(p) for p in self.root.rglob("*") if ".git" not in p.parts)
        self.assertEqual(after, before)

    def test_the_lock_never_writes_through_a_file_planted_in_the_cache(self):
        precious = self.tmp / "precious"
        precious.write_text("keep me")
        (self.cache / "nexthop").mkdir(parents=True)
        (self.cache / "nexthop" / ".lock").symlink_to(precious)
        self.assertEqual(self.run_launcher("live").returncode, 0)
        self.assertEqual(precious.read_text(), "keep me")

    def test_a_download_that_does_not_match_the_pinned_checksum_is_refused(self):
        self.served.write_text(FAKE_BINARY + "tampered\n")
        result = self.run_launcher("daemon")
        self.assertEqual(result.returncode, 1)
        self.assertIn("expects", result.stderr)
        self.assertFalse(self.exe().exists())
        self.assertEqual([p.name for p in self.exe().parent.iterdir()], [])

    def test_a_failed_download_is_not_retried_for_five_minutes(self):
        self.served.unlink()
        self.assertEqual(self.run_launcher("live").returncode, 1)
        again = self.run_launcher("live")
        self.assertEqual(again.returncode, 1)
        self.assertIn("less than 5 minutes ago", again.stderr)
        self.assertEqual(len(self.downloads()), 1)

    def test_an_origin_that_is_not_github_is_refused_without_a_download(self):
        self.origin("https://gitlab.com/someone/omarchy-nexthop.git")
        result = self.run_launcher("daemon")
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not a GitHub repository", result.stderr)
        self.assertEqual(self.downloads(), [])

    def test_a_plugin_folder_without_git_never_borrows_the_origin_of_a_repository_around_it(self):
        shutil.rmtree(self.root / ".git")
        subprocess.run(["git", "init", "-q", str(self.tmp)], check=True)
        subprocess.run(["git", "-C", str(self.tmp), "remote", "add", "origin",
                        "https://github.com/dotfiles/elsewhere.git"], check=True)
        result = self.run_launcher("live")
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no origin remote", result.stderr)
        self.assertEqual(self.downloads(), [])

    def test_a_new_checksum_fetches_again_into_its_own_folder(self):
        self.run_launcher("live")
        self.served.write_text(FAKE_BINARY + "# next build\n")
        self.pin(FAKE_BINARY + "# next build\n")
        self.assertEqual(self.run_launcher("live").returncode, 0)
        self.assertEqual(len(self.downloads()), 2)
        self.assertTrue(self.exe().exists())

    def test_the_python_entry_points_of_0_2_71_run_the_launcher(self):
        daemon = self.run_in_root(sys.executable, "-B", "-m", "nexthopd")
        self.assertEqual(daemon.stdout, f"ran {self.exe()} daemon from {self.root}\n", daemon.stderr)
        cli = self.run_in_root(sys.executable, "-B", "-m", "nexthopd.cli", "retire", "--pid", "7")
        self.assertEqual(cli.stdout, f"ran {self.exe()} retire --pid 7 from {self.root}\n", cli.stderr)


if __name__ == "__main__":
    unittest.main()
