# TODO: fc 17oct26 0.2.71 shells and systemd units run python3 -m nexthopd; remove once those installs have updated
import os
from pathlib import Path

launcher = str(Path(__file__).resolve().parent.parent / "bin" / "nexthop")
os.execv(launcher, [launcher, "daemon"])
