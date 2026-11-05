# TODO: fc 17oct26 0.2.71 shells run python3 -m nexthopd.cli; remove once those installs have updated
import os
import sys
from pathlib import Path

launcher = str(Path(__file__).resolve().parent.parent / "bin" / "nexthop")
os.execv(launcher, [launcher, *sys.argv[1:]])
