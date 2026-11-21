"""The one place that says which scenarios exist.

Two files, read together:
- src/config/scenarios.yaml: hand-written. C0 (baseline) and S1-S6, PS-028's six required
  scenarios. Never generated, never overridden.
- src/config/scenarios_generated.yaml: written by src/runner/scenario_grid.py from
  src/config/scenario_grid.yaml. Extensions only (IDs like Gv6d200), each marked extension: true.
  Optional: without it, only the hand-written scenarios exist.

The orchestrator (via runner.clients) and the dataset manifests (summarise.dataset_sessions)
read the IDs and definitions from here, in file order (hand-written first), instead of keeping
their own lists.
"""

from __future__ import annotations

import copy
from functools import lru_cache
from pathlib import Path

import yaml

from analysis.names import InvalidName, check_generated_id

CONFIG_DIR = Path(__file__).resolve().parents[2] / "src" / "config"
SCENARIOS_FILE = CONFIG_DIR / "scenarios.yaml"
GENERATED_FILE = CONFIG_DIR / "scenarios_generated.yaml"


class ScenarioConfigError(Exception):
    """A scenario file is missing, unreadable, has no scenarios, or a generated entry is not allowed."""


def _read(path: Path) -> dict:
    try:
        cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ScenarioConfigError(f"cannot read {path}: {exc}") from exc
    scenarios = cfg.get("scenarios") if isinstance(cfg, dict) else None
    if not isinstance(scenarios, dict) or not scenarios:
        raise ScenarioConfigError(f"{path}: no 'scenarios' mapping")
    return cfg


AUTO = "auto"   # generated file: GENERATED_FILE next to the default scenarios.yaml, none for another path


def _generated_for(path: Path, generated) -> Path | None:
    if generated == AUTO:
        return GENERATED_FILE if Path(path) == SCENARIOS_FILE else None
    return generated


def load_config(path: Path = SCENARIOS_FILE, generated: Path | None | str = AUTO) -> dict:
    """{"baseline": ..., "scenarios": {id: definition}}: the hand-written file, then the generated one.

    A generated entry must have a generated-style ID that collides with nothing hand-written
    (analysis.names.check_generated_id) and must be marked extension: true. Callers get a copy
    they may change; the files are read once per process.
    """
    return copy.deepcopy(_load(Path(path), _generated_for(path, generated)))


@lru_cache(maxsize=None)
def _load(path: Path, generated: Path | None) -> dict:
    cfg = _read(path)
    scenarios = {str(k): v for k, v in cfg["scenarios"].items()}
    if generated is not None and Path(generated).is_file():
        gen = _read(generated)
        if gen.get("extension") is not True:
            raise ScenarioConfigError(f"{generated}: must be marked 'extension: true' at the top")
        if gen.get("baseline") != cfg["baseline"]:
            raise ScenarioConfigError(f"{generated}: baseline differs from {path}; regenerate it")
        for sid, sc in gen["scenarios"].items():
            try:
                check_generated_id(str(sid), set(scenarios))
            except InvalidName as exc:
                raise ScenarioConfigError(f"{generated}: {exc}") from exc
            if not (isinstance(sc, dict) and sc.get("extension") is True):
                raise ScenarioConfigError(f"{generated}: scenario {sid} must be marked 'extension: true'")
            scenarios[str(sid)] = sc
    return {"baseline": cfg["baseline"], "scenarios": scenarios}


def scenario_ids(path: Path = SCENARIOS_FILE, generated: Path | None | str = AUTO) -> tuple[str, ...]:
    """Every scenario ID, hand-written ones first, each file in its own order."""
    return tuple(load_config(path, generated)["scenarios"])
