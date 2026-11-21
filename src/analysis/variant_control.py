"""Validation control: curl@he200 against plain curl on S1. Read-only; reports, never adjusts.

    .venv/bin/python src/analysis/variant_control.py --dataset NAME [--variant curl@he200] [--scenario S1]

200 ms is curl's documented default Happy Eyeballs timeout (curl man page, --happy-eyeballs-timeout-ms),
so setting it explicitly should change nothing: curl@he200 should behave like plain curl. Up to
three deltas of median TCP setup time (packet-level), each "first minus second":

1. flag: curl@he200 minus plain curl, both in dataset NAME. Same code and (normally) the same
   kernel, so this isolates the flag. This is the control proper.
2. cross-kernel: plain curl in dataset NAME minus plain curl in the frozen core dataset
   (2026-10-26, an earlier kernel). No flag on either side, so a difference comes from what changed
   on the host (kernel and anything else), not from the flag.
3. variant vs core: curl@he200 minus core plain curl. Flag and host change together; printed for
   completeness, it separates neither.

The kernels and client versions of every side are read from the records and printed.

The delta is reported as measured. A delta is called non-trivial when the two medians' 95% bootstrap
CIs (analysis.metrics.bootstrap_median_ci) do not overlap. That is a descriptive flag, not a
significance test. A non-trivial delta prints a proposed limitation line for the report; nothing is
written to the report automatically, and nothing is tuned to make the delta zero.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.metrics import bootstrap_median_ci  # noqa: E402
from analysis.names import InvalidName, parse_client  # noqa: E402
from analysis.summarise import (CORE_DATASET, REPO, RUNS_DIR, DatasetError, Manifest,  # noqa: E402
                                load_dataset, load_runs, out_dir_for)


def side(name: str, setup_ms: list[float], kernels: list[str], versions: list[str], session: str) -> dict:
    v = [x for x in setup_ms if x is not None]
    return {"name": name, "session": session, "n": len(v),
            "median_ms": round(statistics.median(v), 3) if v else None,
            "ci": bootstrap_median_ci(v), "kernels": sorted(set(kernels)), "client_versions": sorted(set(versions))}


def compare(variant: dict, reference: dict) -> dict:
    """Delta of one side's median minus the other's, and whether their CIs overlap."""
    if variant["median_ms"] is None or reference["median_ms"] is None:
        return {"reference": reference["name"], "delta_ms": None, "ci_overlap": None, "non_trivial": None,
                "same_kernel": None, "note": "no TCP setup time on one side"}
    a, b = variant["ci"], reference["ci"]
    overlap = None if not (a and b) else (a["lo"] <= b["hi"] and b["lo"] <= a["hi"])
    return {"reference": reference["name"], "delta_ms": round(variant["median_ms"] - reference["median_ms"], 3),
            "ci_overlap": overlap, "non_trivial": None if overlap is None else not overlap,
            "same_kernel": variant["kernels"] == reference["kernels"]}


FLAG = "flag"            # variant against plain curl, same dataset: the control proper
CROSS_KERNEL = "kernel"  # plain curl in this dataset against plain curl in the core dataset
VARIANT_CORE = "variant_core"  # variant against core plain curl: flag and kernel together
PURPOSE = {FLAG: "flag (same dataset)", CROSS_KERNEL: "cross-kernel (plain curl, this dataset vs core)",
           VARIANT_CORE: "variant vs core (flag and kernel not separated)"}


def limitation_line(a: dict, b: dict, cmp: dict, purpose: str = FLAG) -> str:
    kern = ("on the same kernel" if cmp["same_kernel"]
            else f"on kernel {', '.join(a['kernels'])} against {', '.join(b['kernels'])}")
    what = {FLAG: (f"Validation control: {a['name']} (an explicit 200 ms, curl's documented default) differed "
                   f"from {b['name']}"),
            CROSS_KERNEL: f"Cross-kernel comparison: {a['name']} differed from {b['name']}",
            VARIANT_CORE: f"{a['name']} differed from {b['name']}"}[purpose]
    return (f"{what} by {cmp['delta_ms']:+.3f} ms in median TCP setup time "
            f"({a['median_ms']} ms, 95% CI {a['ci']['lo']}-{a['ci']['hi']}, n={a['n']}, "
            f"against {b['median_ms']} ms, 95% CI {b['ci']['lo']}-{b['ci']['hi']}, n={b['n']}; {kern}). "
            "The intervals do not overlap. The cause is not established by these data.")


def _records_by_session(sessions: set[str], runs_dir: Path) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for p in sorted(runs_dir.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        sid = r.get("environment", {}).get("session_id")
        if sid in sessions:
            out.setdefault(sid, []).append(r)
    return out


def _session(m: Manifest, client: str, scenario: str) -> str | None:
    hits = [sid for c, s, sid in m.sessions if (c, s) == (client, scenario)]
    return hits[0] if hits else None


def load_side(m: Manifest, client: str, scenario: str, name: str, runs_dir: Path = RUNS_DIR,
              repo: Path | None = REPO) -> dict | None:
    sid = _session(m, client, scenario)
    if sid is None:
        return None
    runs = load_runs([(client, scenario, sid)], runs_dir, expected=m.shape.reps, repo=repo, adaptive=m.shape.adaptive)
    recs = _records_by_session({sid}, runs_dir).get(sid, [])
    return side(name, [r.setup_ms for r in runs], [r["environment"].get("kernel", "?") for r in recs],
                [r["client"].get("version", "?") for r in recs], sid)


def _fmt_side(s: dict) -> str:
    ci = s["ci"]
    ci_txt = f"95% CI [{ci['lo']}, {ci['hi']}]" if ci else "no CI"
    return (f"  {s['name']:44} n={s['n']:>3} median {s['median_ms']} ms  {ci_txt}  kernel {', '.join(s['kernels'])}"
            f"  {', '.join(s['client_versions'])}  session {s['session']}")


def report(sides: list[dict], pairs: list[tuple[str, dict, dict, dict]]) -> str:
    """pairs: (purpose, a, b, compare(a, b)); each delta is a minus b."""
    lines = ["VALIDATION CONTROL (packet-level TCP setup time; CIs describe precision, they are not significance tests)"]
    lines += [_fmt_side(s) for s in sides]
    for purpose, a, b, cmp in pairs:
        head = f"  [{PURPOSE[purpose]}] {a['name']} minus {b['name']}"
        if cmp["delta_ms"] is None:
            lines.append(f"{head}: not computed ({cmp['note']})")
            continue
        kern = "same kernel" if cmp["same_kernel"] else "DIFFERENT kernels"
        verdict = ("non-trivial (CIs do not overlap)" if cmp["non_trivial"]
                   else "trivial (CIs overlap)" if cmp["non_trivial"] is False else "no CI on one side")
        lines.append(f"{head}: {cmp['delta_ms']:+.3f} ms; {verdict}; {kern}")
        if cmp["non_trivial"]:
            lines.append("    LIMITATION (proposed line for the report; not written automatically):")
            lines.append("      " + limitation_line(a, b, cmp, purpose))
    return "\n".join(lines)


def run(dataset: str, variant_label: str = "curl@he200", scenario: str = "S1",
        runs_dir: Path = RUNS_DIR, repo: Path | None = REPO) -> dict:
    """Up to three deltas: the flag (variant minus plain curl, same dataset), cross-kernel (plain curl
    in this dataset minus core plain curl), and variant minus core plain curl (both effects together)."""
    cn = parse_client(variant_label)
    if not cn.variant or cn.implementation != "curl":
        raise DatasetError(f"{variant_label}: the control compares a curl variant with plain curl")
    m = load_dataset(dataset)
    variant = load_side(m, variant_label, scenario, f"{variant_label} {scenario} ({dataset})", runs_dir, repo)
    if variant is None:
        raise DatasetError(f"dataset {dataset} has no {variant_label}/{scenario} session")
    same = load_side(m, "curl", scenario, f"curl {scenario} ({dataset})", runs_dir, repo)
    core = load_side(load_dataset(CORE_DATASET), "curl", scenario, f"curl {scenario} (core dataset)", runs_dir, repo)
    pairs = []
    if same is not None:
        pairs.append((FLAG, variant, same))
        if core is not None:
            pairs.append((CROSS_KERNEL, same, core))
    if core is not None:
        pairs.append((VARIANT_CORE, variant, core))
    done = [(p, a, b, compare(a, b)) for p, a, b in pairs]
    sides = [x for x in (variant, same, core) if x is not None]
    return {"sides": sides,
            "comparisons": [dict(cmp, purpose=p, a=a["name"], b=b["name"]) for p, a, b, cmp in done],
            "text": report(sides, done)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True, help="named dataset (docs/datasets/NAME.md) with the variant's session")
    ap.add_argument("--variant", default="curl@he200")
    ap.add_argument("--scenario", default="S1")
    a = ap.parse_args(argv)
    try:
        res = run(a.dataset, a.variant, a.scenario)
    except (DatasetError, InvalidName) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    out = out_dir_for(a.dataset)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "variant_control.json"
    path.write_text(json.dumps({k: v for k, v in res.items() if k != "text"}, indent=2) + "\n", encoding="utf-8")
    print(res["text"])
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
