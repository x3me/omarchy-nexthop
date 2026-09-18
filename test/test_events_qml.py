"""Folded event summaries, checked in a real JavaScript engine."""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import REPO  # noqa: E402

HARNESS = REPO / "test" / "events_fold.js"


class EventFolding(unittest.TestCase):
    def test_named_access_points_survive_episode_folding(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not on PATH")
        result = subprocess.run([node, str(HARNESS)], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 0,
                         f"{result.stdout}\n{result.stderr}")
        self.assertIn("named event folding ok", result.stdout)
        self.assertIn("event durations ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
