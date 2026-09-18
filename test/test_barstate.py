"""The bar's glyph choice and warn-colour guard, checked in a real JS engine.

`barstate.js` is plain JavaScript beside the QML, shared by the bar entry and
the panel header. Like `pathspark.js` it is outside everything else in the
battery — qmllint does not evaluate it and the Python suite cannot import
it — so the harness `test/barstate.js` runs it in node. Skipped where node is
absent (the runner-like PATH), so it is CI that enforces it.
"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import REPO  # noqa: E402

HARNESS = REPO / "test" / "barstate.js"


class BarState(unittest.TestCase):
    def test_glyphs_and_the_light_bar_guard(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not on PATH")
        result = subprocess.run([node, str(HARNESS)], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 0,
                         f"{result.stdout}\n{result.stderr}")
        self.assertIn("bar state ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
