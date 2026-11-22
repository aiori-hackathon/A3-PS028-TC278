"""Generate extension scenarios from a grid. Never touches the core scenarios.

    .venv/bin/python src/runner/scenario_grid.py           # write src/config/scenarios_generated.yaml
    .venv/bin/python src/runner/scenario_grid.py --check   # exit 1 if that file is out of date

Reads src/config/scenario_grid.yaml (family, kind, values) and writes one scenario per value,
following the rules of src/config/scenarios.yaml:
- delay N ("+N ms RTT" on that family): delay_ms_each_way = 10 + N/2, verify_target = 20 + N
  (from the baseline: each way = baseline each way + N/2, target = baseline RTT + N); the other
  family stays at the baseline. An odd N gives a half ms each way (+125: 72.5 ms); whether netem
  realises it is checked by src/runner/fractional_delay_check.py before such a scenario is used.
- loss N (N% in each direction on that family, baseline delay): a band verify target (loss_band):
  round-trip ping loss 1 - (1 - N/100)^2 within 4 binomial standard errors over 200 pings.
- jitter J (each way, netem 'distribution normal', base delay 10 + 2J so negative draws are rare):
  a band verify target (jitter_band) on the RTT median and standard deviation. With delay_twin: true
  the delay-only scenario with the same mean RTT (+4J ms) is generated too.
- loss_sole_path N (compound): loss N on that family as above, and the OTHER family blackholed
  (100 % loss, verify target "blackhole", as in S1/S4). That family is then the only working path,
  so a lost SYN can only be answered by the kernel's SYN retransmission on the same socket: the one
  configuration where the retransmission timer is observable in the winning handshake. ID G<fam>c<N>.
  It is not X1 (the optional compound stress of the proposal, never configured).
DNS is never delayed in a generated scenario.

Every generated scenario is an extension (extension: true), with an ID like Gv6d200 or Gv6l5;
an ID that collides with C0, S1-S6 or anything in scenarios.yaml is rejected (analysis.names).
The output is deterministic, so --check (and a test) can say whether it matches the grid.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml  # noqa: E402

from analysis.names import InvalidName, check_generated_id  # noqa: E402
from analysis.scenario_config import CONFIG_DIR, GENERATED_FILE, SCENARIOS_FILE  # noqa: E402

GRID_FILE = CONFIG_DIR / "scenario_grid.yaml"
FAMILIES = ("v4", "v6")
KINDS = {"delay": "d", "loss": "l", "jitter": "j", "loss_sole_path": "c"}


class GridError(Exception):
    pass


def _whole(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


BAND_PINGS = 200          # pings per band verify (lab.env BAND_PING_INTERVAL_S apart)
BAND_SIGMAS = 4           # band half-width in standard errors: a correct link fails about 1 in 16 000 checks
MEDIAN_SE_FACTOR = 1.2533  # standard error of a normal sample's median = 1.2533 * sigma / sqrt(N)


def loss_band(loss_pct_each_way: int, rtt_ms: int, pings: int = BAND_PINGS) -> dict:
    """verify_target for a partial-loss link. A ping crosses the link twice (request and reply),
    each with independent loss p, so the expected round-trip ping loss is 1 - (1 - p)^2; the
    tolerance is BAND_SIGMAS binomial standard errors for that many pings, rounded up."""
    p = loss_pct_each_way / 100
    q = 1 - (1 - p) ** 2
    tol = math.ceil(BAND_SIGMAS * 100 * math.sqrt(q * (1 - q) / pings))
    return {"band": "loss", "expect_loss_pct": round(100 * q, 2), "tolerance_pct": tol, "rtt_ms": rtt_ms,
            "pings": pings}


def jitter_band(delay_ms_each_way: int, jitter_ms: int, pings: int = BAND_PINGS) -> dict:
    """verify_target for a jitter link. Each direction adds a normal delay (mean D, sd J; netem with
    'distribution normal'); the two directions are independent netem instances, so the ping RTT is
    about normal with mean 2D and sd J*sqrt(2). Bands are BAND_SIGMAS standard errors wide:
    median 1.2533*sd/sqrt(N) (at least 2 ms), sd sd/sqrt(2(N-1)); rounded outwards to 0.1 ms."""
    mean, sd = 2 * delay_ms_each_way, jitter_ms * math.sqrt(2)
    m_tol = max(2.0, BAND_SIGMAS * MEDIAN_SE_FACTOR * sd / math.sqrt(pings))
    s_tol = BAND_SIGMAS * sd / math.sqrt(2 * (pings - 1))
    lo = lambda x: math.floor(x * 10) / 10   # noqa: E731
    hi = lambda x: math.ceil(x * 10) / 10    # noqa: E731
    return {"band": "jitter", "median_ms": [lo(mean - m_tol), hi(mean + m_tol)],
            "sd_ms": [lo(sd - s_tol), hi(sd + s_tol)], "pings": pings}


def scenario_for(family: str, kind: str, value: int, baseline: dict) -> tuple[str, dict]:
    """(id, definition) for one grid point."""
    each, rtt = baseline["delay_ms_each_way"], baseline["rtt_ms"]
    other = "v4" if family == "v6" else "v6"
    ip = f"IPv{family[1]}"
    sid = f"G{family}{KINDS[kind]}{value}"
    if kind == "delay":
        if value <= 0:
            raise GridError(f"{family} delay {value}: '+N ms RTT' needs N > 0 (each way gets N/2)")
        # Odd N gives a half ms each way (e.g. +125: 72.5 ms), which netem takes; even N stays whole.
        impaired = {"delay_ms_each_way": each + value // 2 if value % 2 == 0 else each + value / 2, "loss_pct": 0}
        target = rtt + value
        label = f"{ip} +{value} ms RTT"
    elif kind in ("loss", "loss_sole_path"):
        if not 0 < value < 100:
            raise GridError(f"{family} {kind} {value}: must be 1-99 % (100 % is the core blackhole, S1/S4)")
        impaired = {"delay_ms_each_way": each, "loss_pct": value}
        target = loss_band(value, rtt)
        label = f"{ip} {value}% loss each way"
        if kind == "loss_sole_path":
            label += f", IPv{other[1]} blackholed (compound, {ip} is the only working path)"
    else:
        if value <= 0:
            raise GridError(f"{family} jitter {value}: must be > 0 ms")
        # Base delay 10 + 2J each way keeps negative draws about 2 sd away (decision 2026-11-21),
        # so the RTT mean is 20 + 4J; the delay twin Gv6d<4J> has the same mean without jitter.
        impaired = {"delay_ms_each_way": each + 2 * value, "loss_pct": 0, "jitter_ms_each_way": value}
        target = jitter_band(each + 2 * value, value)
        label = f"{ip} jitter {value} ms each way (normal), base delay {each + 2 * value} ms each way"
    sc = {"label": f"{label} (generated extension)", "extension": True,
          "grid": {"family": family, "kind": kind, "value": value},
          family: impaired, other: {"delay_ms_each_way": each, "loss_pct": 100 if kind == "loss_sole_path" else 0},
          "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
          "verify_target": {f: (target if f == family else "blackhole" if kind == "loss_sole_path" else rtt)
                            for f in FAMILIES}}
    sc = {k: sc[k] for k in ("label", "extension", "grid", "v4", "v6", "dns", "verify_target")}
    return sid, sc


def _physics(sc: dict) -> tuple:
    return tuple(json.dumps(sc[k], sort_keys=True) for k in ("v4", "v6", "dns", "verify_target"))


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
        allowed = {"family", "kind", "values"} | ({"delay_twin"} if isinstance(g, dict) and g.get("kind") == "jitter"
                                                 else set())
        if not isinstance(g, dict) or not {"family", "kind", "values"} <= set(g) or set(g) - allowed:
            raise GridError(f"grid entry {i}: needs exactly family, kind and values (and, for jitter only, "
                            f"delay_twin); got {g!r}")
        fam, kind, values = g["family"], g["kind"], g["values"]
        if fam not in FAMILIES:
            raise GridError(f"grid entry {i}: family must be one of {FAMILIES}, got {fam!r}")
        if kind not in KINDS:
            raise GridError(f"grid entry {i}: kind must be one of {tuple(KINDS)}, got {kind!r}")
        if not (isinstance(values, list) and values and all(_whole(v) for v in values)):
            raise GridError(f"grid entry {i}: values must be a non-empty list of whole numbers")
        twin = g.get("delay_twin", False)
        if not isinstance(twin, bool):
            raise GridError(f"grid entry {i}: delay_twin must be true or false")
        if len(set(values)) != len(values):
            raise GridError(f"grid entry {i}: a value is listed twice: {values}")
        for v in values:
            points = [scenario_for(fam, kind, v, base)]
            if twin:   # the same mean RTT without jitter: +4J ms RTT
                tid, tsc = scenario_for(fam, "delay", 4 * v, base)
                points[0][1]["grid"]["delay_twin"] = tid
                points.append((tid, tsc))
            for sid, sc in points:
                try:
                    check_generated_id(sid, defined)
                except InvalidName as exc:
                    raise GridError(str(exc)) from exc
                if sid in out:
                    if _physics(out[sid]) != _physics(sc):
                        raise GridError(f"grid entry {i}: {sid} is generated twice, with different settings")
                    continue   # the same scenario from two entries (a jitter's delay twin): kept once
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
