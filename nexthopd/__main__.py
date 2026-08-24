"""`python3 -m nexthopd` runs the daemon; the CLI lives at nexthopd.cli."""
import sys
from .daemon import main

sys.exit(main())
