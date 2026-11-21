"""Generate extension scenarios from a grid. Never touches the core scenarios.

    .venv/bin/python src/runner/scenario_grid.py           # write src/config/scenarios_generated.yaml
    .venv/bin/python src/runner/scenario_grid.py --check   # exit 1 if that file is out of date

Reads src/config/scenario_grid.yaml (family, kind, values) and writes one scenario per value,
following the rules of src/config/scenarios.yaml:
- delay N ("+N ms RTT" on that family): delay_ms_each_way = 10 + N/2, verify_target = 20 + N
  (from the baseline: each way = baseline each way + N/2, target = baseline RTT + N); the other
  family stays at the baseline.
- loss N (N% in each direction on that family, baseline delay): verify_target "loss:N". The lab's
  verify.sh cannot check partial loss yet, so the orchestrator refuses these scenarios until it can.
DNS is never delayed in a generated scenario.

Every generated scenario is an extension (extension: true), with an ID like Gv6d200 or Gv6l5;
an ID that collides with C0, S1-S6 or anything in scenarios.yaml is rejected (analysis.names).
The output is deterministic, so --check (and a test) can say whether it matches the grid.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml  # noqa: E402

from analysis.names import InvalidName, check_generated_id  # noqa: E402
from analysis.scenario_config import CONFIG_DIR, GENERATED_FILE, SCENARIOS_FILE  # noqa: E402

GRID_FILE = CONFIG_DIR / "scenario_grid.yaml"
FAMILIES = ("v4", "v6")
KINDS = {"delay": "d", "loss": "l"}


class GridError(Exception):
    pass


def _whole(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def scenario_for(family: str, kind: str, value: int, baseline: dict) -> tuple[str, dict]:
    """(id, definition) for one grid point."""
    each, rtt = baseline["delay_ms_each_way"], baseline["rtt_ms"]
    other = "v4" if family == "v6" else "v6"
    ip = f"IPv{family[1]}"
    sid = f"G{family}{KINDS[kind]}{value}"
    if kind == "delay":
        if value <= 0 or value % 2:
            raise GridError(f"{family} delay {value}: '+N ms RTT' needs an even N > 0 (each way gets N/2)")
        impaired = {"delay_ms_each_way": each + value // 2, "loss_pct": 0}
        target = rtt + value
        label = f"{ip} +{value} ms RTT"
    else:
        if not 0 < value < 100:
            raise GridError(f"{family} loss {value}: must be 1-99 % (100 % is the core blackhole, S1/S4)")
        impaired = {"delay_ms_each_way": each, "loss_pct": value}
        target = f"loss:{value}"
        label = f"{ip} {value}% loss each way"
    sc = {"label": f"{label} (generated extension)", "extension": True,
          "grid": {"family": family, "kind": kind, "value": value},
          family: impaired, other: {"delay_ms_each_way": each, "loss_pct": 0},
          "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
          "verify_target": {f: (target if f == family else rtt) for f in FAMILIES}}
    sc = {k: sc[k] for k in ("label", "extension", "grid", "v4", "v6", "dns", "verify_target")}
    return sid, sc


def build(grid: dict, core: dict) -> dict[str, dict]:
    """Generated scenarios for a grid, given the hand-written config ({"baseline", "scenarios"})."""
    base = core["baseline"]
    if base["rtt_ms"] != 2 * base["delay_ms_each_way"]:
        raise GridError(f"baseline rtt_ms {base['rtt_ms']} is not twice delay_ms_each_way {base['delay_ms_each_way']}")
    entries = grid.get("grids") if isinstance(grid, dict) else None
    if not isinstance(entries, list) or not entries:
        raise GridError("grid file needs a non-empty 'grids' list")
    defined = set(core["scenarios"])
    out: dict[str, dict] = {}
    for i, g in enumerate(entries, 1):
        if not isinstance(g, dict) or set(g) != {"family", "kind", "values"}:
            raise GridError(f"grid entry {i}: needs exactly family, kind and values; got {g!r}")
        fam, kind, values = g["family"], g["kind"], g["values"]
        if fam not in FAMILIES:
            raise GridError(f"grid entry {i}: family must be one of {FAMILIES}, got {fam!r}")
        if kind not in KINDS:
            raise GridError(f"grid entry {i}: kind must be one of {tuple(KINDS)}, got {kind!r}")
        if not (isinstance(values, list) and values and all(_whole(v) for v in values)):
            raise GridError(f"grid entry {i}: values must be a non-empty list of whole numbers")
        for v in values:
            sid, sc = scenario_for(fam, kind, v, base)
            try:
                check_generated_id(sid, defined)
            except InvalidName as exc:
                raise GridError(str(exc)) from exc
            if sid in out:
                raise GridError(f"grid entry {i}: {sid} is generated twice")
            out[sid] = sc
    return out


def _flow(d: dict) -> str:
    return "{" + ", ".join(f"{k}: {_flow(v) if isinstance(v, dict) else _scalar(v)}" for k, v in d.items()) + "}"


def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def render(scenarios: dict[str, dict], baseline: dict) -> str:
    lines = ["# GENERATED by src/runner/scenario_grid.py from src/config/scenario_grid.yaml. Do not edit:",
             "# change the grid and regenerate. Every scenario here is an EXTENSION; the baseline C0 and",
             "# PS-028's six required scenarios S1-S6 are only in scenarios.yaml.",
             "# Values are provisional, like those in scenarios.yaml; the real RTT is measured before every run.",
             "", "schema_version: 1", "extension: true", "",
             f"baseline: {_flow(baseline)}", "", "scenarios:"]
    for sid, sc in scenarios.items():
        lines.append(f"  {sid}:")
        for k, v in sc.items():
            lines.append(f"    {k}: {_flow(v) if isinstance(v, dict) else _scalar(v)}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def generate(grid_file: Path = GRID_FILE, scenarios_file: Path = SCENARIOS_FILE) -> str:
    from analysis.scenario_config import load_config
    core = load_config(scenarios_file, generated=None)
    try:
        grid = yaml.safe_load(Path(grid_file).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise GridError(f"cannot read {grid_file}: {exc}") from exc
    text = render(build(grid, core), core["baseline"])
    if yaml.safe_load(text)["scenarios"] != build(grid, core):  # the hand-formatted YAML reads back exactly
        raise GridError("internal error: rendered YAML does not read back as the generated scenarios")
    return text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--grid", type=Path, default=GRID_FILE)
    ap.add_argument("--out", type=Path, default=GENERATED_FILE)
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if --out differs from the grid")
    a = ap.parse_args(argv)
    try:
        text = generate(a.grid)
    except GridError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    current = a.out.read_text(encoding="utf-8") if a.out.is_file() else None
    if a.check:
        if current != text:
            print(f"{a.out} is out of date with {a.grid}; run src/runner/scenario_grid.py", file=sys.stderr)
            return 1
        print(f"{a.out} is up to date")
        return 0
    a.out.write_text(text, encoding="utf-8")
    n = len(yaml.safe_load(text)["scenarios"])
    print(f"wrote {a.out} ({n} extension scenario(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
