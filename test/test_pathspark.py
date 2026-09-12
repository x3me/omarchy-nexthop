"""The sparkline geometry, checked in a real JS engine.

`pathspark.js` is plain JavaScript beside the QML, which puts it outside
everything else in the battery: qmllint does not evaluate it and the
Python suite cannot import it. Two geometry defects shipped from it in a
single day — the ring on the wrong slot, then the ring drawn half outside
the canvas — and neither could have failed a test that existed.

`draw()` takes a context and a size and calls nothing else, so a fake 2d
context recording every mark is enough. The harness is
`test/pathspark_bounds.js`; this runs it. Skipped where node is absent
(the runner-like PATH), so it is CI that enforces it.
"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import REPO  # noqa: E402

HARNESS = REPO / "test" / "pathspark_bounds.js"


class SparklineGeometry(unittest.TestCase):
    def test_nothing_is_drawn_outside_the_canvas(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not on PATH")
        r = subprocess.run([node, str(HARNESS)], capture_output=True,
                           text=True, timeout=60)
        self.assertEqual(r.returncode, 0,
                         f"{r.stdout}\n{r.stderr}")
        self.assertIn("all inside the canvas", r.stdout)


if __name__ == "__main__":
    unittest.main()
