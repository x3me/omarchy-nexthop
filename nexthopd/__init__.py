"""nexthopd — the measurement daemon behind the Nexthop Omarchy plugin.

Standard library only, on purpose: the plugin is installed by cloning a git
repo, and the marketplace installer never builds or runs anything. Anything
that needed pip or a compiler would make installation a second, manual step.
"""

__version__ = "0.1.8"
