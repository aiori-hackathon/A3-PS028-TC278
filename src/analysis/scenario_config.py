"""The one place that says which scenario IDs exist: src/config/scenarios.yaml.

The orchestrator (via runner.clients) and the dataset manifests (summarise.dataset_sessions)
both read the IDs from here, in file order, instead of keeping their own lists.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

SCENARIOS_FILE = Path(__file__).resolve().parents[2] / "src" / "config" / "scenarios.yaml"


class ScenarioConfigError(Exception):
    """scenarios.yaml is missing, unreadable or has no scenarios."""


@lru_cache(maxsize=None)
def scenario_ids(path: Path = SCENARIOS_FILE) -> tuple[str, ...]:
    """Scenario IDs defined in scenarios.yaml, in the order they appear there."""
    try:
        cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ScenarioConfigError(f"cannot read {path}: {exc}") from exc
    scenarios = (cfg or {}).get("scenarios") if isinstance(cfg, dict) else None
    if not isinstance(scenarios, dict) or not scenarios:
        raise ScenarioConfigError(f"{path}: no 'scenarios' mapping")
    return tuple(str(k) for k in scenarios)
