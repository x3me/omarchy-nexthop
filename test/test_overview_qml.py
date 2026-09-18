"""The Speed pillar's hover text, checked in a real JavaScript engine.

`speedTip()` in OverviewTab.qml is pure — speed_ctx and metered in, text
out — so the harness extracts it and runs every case the pillar can be in.
Skipped where node is absent (the runner-like PATH); CI enforces it.
"""
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import REPO  # noqa: E402

HARNESS = REPO / "test" / "overview_tip.js"


class SpeedPillarTip(unittest.TestCase):
    def test_every_state_is_explained(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not on PATH")
        result = subprocess.run([node, str(HARNESS)], capture_output=True,
                                text=True, timeout=60,
                                env=dict(os.environ, TZ="UTC"))
        self.assertEqual(result.returncode, 0,
                         f"{result.stdout}\n{result.stderr}")
        self.assertIn("speed tip ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
