"""Oracle baseline for a dataset: per-run oracle setup and cost of racing, and a per-cell summary.

    .venv/bin/python src/analysis/oracle.py                     # the core dataset (docs/dataset.md)
    .venv/bin/python src/analysis/oracle.py --dataset NAME      # docs/datasets/NAME.md
    .venv/bin/python src/analysis/oracle.py --csv runs.csv      # also write one row per run

Per run (metrics.oracle_baseline):
  oracle_setup_ms   = the winning family's RTT measured by the lab verify step before the run
  cost_of_racing_ms = TCP setup time (packet-level, from the pcap) minus oracle_setup_ms

Evidence level: derived. TCP setup is packet-level; the RTT is the lab's ping check, not the pcap.
Reading the oracle as what a client "could have" achieved is interpretation: it uses the winning
family in hindsight, which no client knows before connecting.

Uses exactly the runs summarise.build() accepts, so an incomplete or unclean dataset is refused.
Needs no new measurements.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.metrics import ORACLE_EVIDENCE  # noqa: E402
from analysis.summarise import CORE_DATASET, DatasetError, Run, build, load_dataset  # noqa: E402

CSV_FIELDS = ("run_id", "client", "scenario", "repetition", "winner", "tcp_setup_time_ms",
              "oracle_setup_ms", "cost_of_racing_ms", "status", "single_family", "dns_time_ms", "note")


def run_rows(runs: list[Run]) -> list[dict]:
    return [{"run_id": r.run_id, "client": r.client, "scenario": r.scenario, "repetition": r.repetition,
             "winner": r.winner, "tcp_setup_time_ms": r.setup_ms, "oracle_setup_ms": r.oracle_setup_ms,
             "cost_of_racing_ms": r.cost_of_racing_ms, "status": r.oracle_status,
             "single_family": r.single_family, "dns_time_ms": r.dns_ms, "note": r.oracle_note or ""}
            for r in runs]


def _num(v) -> str:
    return "-" if v is None else f"{v}"


def cell_report(summary: dict) -> str:
    lines = [f"Oracle baseline ({ORACLE_EVIDENCE})",
             f"{'client':9} {'scn':4} {'n':>3} {'computed':>8} {'oracle median':>13} "
             f"{'cost median':>11} {'cost Q1, Q3':>18}  notes"]
    for c, by_s in summary["cells"].items():
        for s, x in by_s.items():
            o = x["oracle"]
            cost, orc = o["cost_of_racing_ms"], o["oracle_setup_ms"]
            notes = [f"{k} {v}" for k, v in o["status"].items() if k != "computed"]
            if o["single_family_runs"]:
                notes.append(f"{o['single_family_runs']} single-family (no race)")
            if o["dns_note"]:
                notes.append("DNS delay not in cost; report with DNS time")
            q = f"{cost['q1']}, {cost['q3']}" if cost else "-"
            lines.append(f"{c:9} {s:4} {x['n']:>3} {o['status'].get('computed', 0):>8} "
                         f"{_num(orc and orc['median']):>13} {_num(cost and cost['median']):>11} {q:>18}  "
                         + "; ".join(notes))
    lines.append("\nInterpretation (labelled): the oracle uses the winning family in hindsight; it is a "
                 "reference for comparison, not a time any client could be expected to reach.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=CORE_DATASET,
                    help="dataset name: 'core' (docs/dataset.md, the default) or NAME for docs/datasets/NAME.md")
    ap.add_argument("--csv", type=Path, default=None, help="write one row per run to this CSV file")
    a = ap.parse_args(argv)
    try:
        _, runs, summary = build(manifest=load_dataset(a.dataset))
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(cell_report(summary))
    if a.csv:
        a.csv.parent.mkdir(parents=True, exist_ok=True)
        with a.csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            w.writeheader()
            w.writerows(run_rows(runs))
        print(f"\nwrote {a.csv} ({len(runs)} runs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
