#!/usr/bin/env bash
# Run the test suite without the ROS environment leaking in.
# The dev shell sources /opt/ros/jazzy/setup.bash, whose PYTHONPATH makes pytest
# autoload ROS plugins that fail to import. Extra arguments go to pytest.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

exec env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/pytest "$@"
