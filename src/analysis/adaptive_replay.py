"""Replay the adaptive stopping rule on runs already recorded. Read-only; runs nothing.

    .venv/bin/python src/analysis/adaptive_replay.py                         # core dataset, 5 20, widths 0.25 0.5 1 2
    .venv/bin/python src/analysis/adaptive_replay.py --min 5 --max 20 --width 1
    .venv/bin/python src/analysis/adaptive_replay.py --dataset NAME --json out.json

For every cell, the recorded runs are taken in repetition order (the order they were measured)
and analysis.metrics.adaptive_decision is applied after each one, exactly as
`orchestrate.py --reps-adaptive MIN MAX --ci-width-ms W` would have applied it. The first "stop"
gives the number of runs the rule needed. Runs after that are the ones it would have skipped;
their measured wall time and pcap bytes are the saving.

This is a replay of recorded runs, not an adaptive campaign: it assumes the first N runs of a
session would have come out the same if the session had stopped after N, which holds because
runs are independent and sequential, but no adaptive session was actually run. MAX must not
exceed the recorded repetitions, since the replay cannot invent runs.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.metrics import adaptive_decision  # noqa: E402
from analysis.summarise import CORE_DATASET, DatasetError, Run, build, load_dataset  # noqa: E402

DEFAULT_WIDTHS = (0.25, 0.5, 1.0, 2.0)


def replay_cell(runs: list[Run], min_reps: int, max_reps: int, width: float) -> dict:
    """Where the rule stops in one cell's runs (in repetition order), and what the rest cost."""
    ordered = sorted(runs, key=lambda r: r.repetition)
    if max_reps > len(ordered):
        raise ValueError(f"max {max_reps} is more than the {len(ordered)} recorded runs; a replay cannot add runs")
    setups = [r.setup_ms for r in ordered]
    state = None
    for n in range(1, max_reps + 1):
        state = adaptive_decision(setups[:n], min_reps, max_reps, width)
        if state["decision"] == "stop":
            break
    n = state["n_runs"]
    skipped = ordered[n:]
    full = [x for x in setups if x is not None]
    walls = [r.wall_s for r in skipped]
    med_all = round(statistics.median(full), 3) if full else None
    ci = state["ci"]
    sizes = [r.pcap_bytes for r in skipped]
    return {
        "stop_after": n, "reason": state["reason"], "recorded": len(ordered),
        "median_at_stop_ms": state["median_ms"], "ci_at_stop": state["ci"],
        "median_all_recorded_ms": med_all,
        # does the CI at the stop contain the median of all recorded runs? (that median is itself an
        # estimate, not a true value; a miss shows the early CI was too narrow or off-centre)
        "ci_at_stop_contains_median_all": (None if ci is None or med_all is None
                                           else ci["lo"] <= med_all <= ci["hi"]),
        "runs_skipped": len(skipped),
        "wall_s_skipped": round(sum(walls), 2) if all(w is not None for w in walls) else None,
        "pcap_bytes_skipped": sum(sizes) if all(b is not None for b in sizes) else None,
        "wall_s_recorded": (round(sum(r.wall_s for r in ordered), 2)
                            if all(r.wall_s is not None for r in ordered) else None),
    }


def replay(runs: list[Run], cells: list[tuple[str, str]], min_reps: int, max_reps: int,
           widths: list[float]) -> dict:
    out = {"min_reps": min_reps, "max_reps": max_reps, "widths": {}}
    for w in widths:
        per = {f"{c}/{s}": replay_cell([r for r in runs if r.client == c and r.scenario == s], min_reps, max_reps, w)
               for c, s in cells}
        known = [x for x in per.values() if x["wall_s_skipped"] is not None]
        out["widths"][str(w)] = {
            "cells": per,
            "runs_needed": sum(x["stop_after"] for x in per.values()),
            "runs_recorded": sum(x["recorded"] for x in per.values()),
            "wall_s_skipped": round(sum(x["wall_s_skipped"] for x in known), 1),
            "wall_s_recorded": round(sum(x["wall_s_recorded"] or 0 for x in per.values()), 1),
            "cells_without_wall_time": len(per) - len(known),
            "cells_ci_missing_median_all": sorted(k for k, x in per.items()
                                                  if x["ci_at_stop_contains_median_all"] is False),
            "max_abs_median_shift_ms": max((round(abs(x["median_at_stop_ms"] - x["median_all_recorded_ms"]), 3)
                                            for x in per.values()
                                            if x["median_at_stop_ms"] is not None
                                            and x["median_all_recorded_ms"] is not None), default=None),
        }
    return out


def report(res: dict) -> str:
    lines = [f"REPLAY of the adaptive stopping rule on recorded runs (--reps-adaptive {res['min_reps']} "
             f"{res['max_reps']}); not an adaptive campaign. Wall time is measured, per skipped run."]
    for w, x in res["widths"].items():
        lines.append(f"\nci_width_ms {w}: {x['runs_needed']} of {x['runs_recorded']} runs needed; "
                     f"{x['wall_s_skipped']} s of {x['wall_s_recorded']} s wall time skipped "
                     f"({round(100 * x['wall_s_skipped'] / x['wall_s_recorded'], 1) if x['wall_s_recorded'] else '-'}%); "
                     f"largest shift of a median against all recorded runs {x['max_abs_median_shift_ms']} ms"
                     + (f"; {x['cells_without_wall_time']} cell(s) without wall times" if x["cells_without_wall_time"] else ""))
        miss = x["cells_ci_missing_median_all"]
        lines.append(f"  CI at the stop excludes the median of all recorded runs in {len(miss)} cell(s)"
                     + (f": {', '.join(miss)}" if miss else ""))
        lines.append(f"  {'cell':14} {'stop':>4} {'reason':17} {'median@stop':>11} {'CI@stop':>22} "
                     f"{'median(all)':>11} {'skipped':>7} {'wall s skipped':>14}")
        for cell, c in x["cells"].items():
            ci = c["ci_at_stop"]
            ci_txt = f"[{ci['lo']}, {ci['hi']}]" if ci else "-"
            lines.append(f"  {cell:14} {c['stop_after']:>4} {c['reason']:17} {c['median_at_stop_ms']!s:>11} "
                         f"{ci_txt:>22} {c['median_all_recorded_ms']!s:>11} {c['runs_skipped']:>7} "
                         f"{c['wall_s_skipped']!s:>14}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=CORE_DATASET)
    ap.add_argument("--min", dest="min_reps", type=int, default=5)
    ap.add_argument("--max", dest="max_reps", type=int, default=20)
    ap.add_argument("--width", type=float, nargs="+", default=list(DEFAULT_WIDTHS), help="ci_width_ms value(s)")
    ap.add_argument("--json", type=Path, help="also write the full result as JSON")
    a = ap.parse_args(argv)
    try:
        m = load_dataset(a.dataset)
        _, runs, _ = build(manifest=m)
        res = replay(runs, m.shape.cells, a.min_reps, a.max_reps, a.width)
    except (DatasetError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(report(res))
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
