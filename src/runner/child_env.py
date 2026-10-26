"""Clean environment for every process the runner starts.

The development shell sources ROS (/opt/ros/jazzy/setup.bash), which sets
PYTHONPATH and LD_LIBRARY_PATH. Neither should reach a measured client or a lab
service: PYTHONPATH can change which Python modules load, and LD_LIBRARY_PATH can
change which shared libraries curl or Chromium link against.

Every subprocess (curl, Chromium/Playwright, the DNS server, nginx, tcpdump) must
be started with env=child_env() (or child_env_with_removed() to record what was stripped).
"""

from __future__ import annotations

import os
from collections.abc import Mapping

STRIPPED_VARS = ("PYTHONPATH", "LD_LIBRARY_PATH")


def child_env_with_removed(base: Mapping[str, str] | None = None) -> tuple[dict[str, str], list[str]]:
    """Return (env, removed): a copy of base (default os.environ) without STRIPPED_VARS."""
    src = os.environ if base is None else base
    removed = sorted(k for k in STRIPPED_VARS if k in src)
    env = {k: v for k, v in src.items() if k not in STRIPPED_VARS}
    return env, removed


def child_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    return child_env_with_removed(base)[0]


def describe(removed: list[str]) -> str:
    """Text for the run record's environment.child_env field."""
    stripped = ", ".join(STRIPPED_VARS)
    if removed:
        return f"inherited, with {stripped} removed (present in parent: {', '.join(removed)})"
    return f"inherited, with {stripped} removed (none were set in parent)"
