"""Export run records as CSV, one row per run, for loading into another system.

    .venv/bin/python src/analysis/export_csv.py                          # core dataset, CSV to stdout
    .venv/bin/python src/analysis/export_csv.py --dataset NAME --out runs.csv
    .venv/bin/python src/analysis/export_csv.py examples/                # any record files or folders
    .venv/bin/python src/analysis/export_csv.py --columns                # the column table (Markdown)

Which records:
  - default, or --dataset NAME: exactly the sessions the manifest lists (docs/dataset.md, or
    docs/datasets/NAME.md), through summarise.load_runs, so an incomplete or unclean dataset is
    refused exactly as summarise refuses it (count, repetitions, cross_checks, lab verify, -dirty code).
  - PATH arguments (record files or folders of *.json): those records, schema-validated
    (validate_record) but NOT certified as a dataset. Use this for pilots and examples.

Output goes to stdout unless --out is given; the script writes nothing else. Read-only on records.

Every column has a source, listed by --columns and in docs/integration.md:
  packet       from the packet capture (the record's packet_observations and metrics)
  client       from client/runner logs (the record's outcome): what the client reported
  derived      packet-level TCP setup time combined with the lab's pre-run ping RTT (metrics.oracle_baseline)
  lab verify   the lab's ping check before the run (verify.sh), not the capture
  cross-check  the record's comparison of the client log with the capture
  metadata     identity, versions and configuration; not evidence about client behaviour
No column is an interpretation: interpretations never go in a run record.

A wrapped {value, status} field becomes two columns, NAME (the value, empty unless computed) and
NAME_status, so an empty cell always says why it is empty.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.metrics import oracle_baseline  # noqa: E402
from analysis.names import label_of  # noqa: E402
from analysis.summarise import CORE_DATASET, RUNS_DIR, DatasetError, load_dataset, load_runs  # noqa: E402
from analysis.validate_record import validate  # noqa: E402

SOURCES = ("packet", "client", "derived", "lab verify", "cross-check", "metadata")


@dataclass(frozen=True)
class Column:
    name: str
    source: str
    description: str
    get: Callable[[dict], Any]


def _wrapped(*path: str) -> Callable[[dict], dict | None]:
    def get(r: dict) -> dict | None:
        node: Any = r
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        return node if isinstance(node, dict) else None
    return get


def _attempts(r: dict) -> list[dict]:
    a = r["packet_observations"]["attempts"]
    return sorted(a["value"], key=lambda x: x["first_syn_ns"]) if a.get("status") == "computed" else []


def _oracle(r: dict) -> dict:
    v = lambda w: w.get("value") if w.get("status") == "computed" else None  # noqa: E731
    return oracle_baseline(v(r["packet_observations"]["winning_family"]), v(r["metrics"]["tcp_setup_time_ms"]),
                           r["scenario"].get("measured_rtt_ms"), [a["family"] for a in _attempts(r)],
                           (r["scenario"].get("dns") or {}).get("delay_ms"))


def _pair(name: str, source: str, description: str, get_wrapped: Callable[[dict], dict | None]) -> list[Column]:
    """A wrapped field as NAME (value when computed, else empty) and NAME_status."""
    def value(r: dict) -> Any:
        w = get_wrapped(r)
        return w.get("value") if w and w.get("status") == "computed" else None

    def status(r: dict) -> Any:
        w = get_wrapped(r)
        return w.get("status") if w else "missing"

    return [Column(name, source, description, value),
            Column(f"{name}_status", source, f"status of {name}: computed, not_observed, not_applicable, "
                                             "not_yet_computed (or not_available for derived columns)", status)]


def _env(key: str) -> Callable[[dict], Any]:
    return lambda r: r.get("environment", {}).get(key)


COLUMNS: list[Column] = [
    # identity and configuration
    Column("run_id", "metadata", "`<UTC>_<scenario>_<client>_r<NN>`; the record's file name", lambda r: r["run_id"]),
    Column("schema_version", "metadata", "run record schema version", lambda r: r["schema_version"]),
    Column("session_id", "metadata", "orchestrator session (one batch)", _env("session_id")),
    Column("scenario", "metadata", "scenario ID (C0, S1-S6, or a generated extension ID)",
           lambda r: r["scenario"]["id"]),
    Column("scenario_label", "metadata", "scenario name", lambda r: r["scenario"].get("label")),
    Column("repetition", "metadata", "repetition number within the session, from 1",
           lambda r: r["scenario"]["repetition"]),
    Column("client", "metadata", "client label, e.g. `curl`, `chromium`, `curl@he200`", lambda r: label_of(r["client"])),
    Column("client_name", "metadata", "client implementation: `curl` or `chromium`", lambda r: r["client"]["name"]),
    Column("client_variant", "metadata", "curl configuration variant, e.g. `he200`; empty for none",
           lambda r: r["client"].get("variant")),
    Column("client_version", "metadata", "version string as the client reported it", lambda r: r["client"]["version"]),
    Column("git_commit", "metadata", "code version that made the record (`-dirty` = uncommitted changes)",
           _env("git_commit")),
    Column("kernel", "metadata", "lab host kernel", _env("kernel")),
    Column("run_start_utc", "metadata", "run start, ISO 8601 UTC", lambda r: r["timestamps"]["run_start_utc"]),
    # lab verify before the run
    *_pair("measured_rtt_v4_ms", "lab verify", "IPv4 RTT measured by ping before the run (median); "
           "not_observed for a blackhole", _wrapped("scenario", "measured_rtt_ms", "v4")),
    *_pair("measured_rtt_v6_ms", "lab verify", "IPv6 RTT measured by ping before the run (median); "
           "not_observed for a blackhole", _wrapped("scenario", "measured_rtt_ms", "v6")),
    Column("pre_verify_ok", "lab verify", "lab verify passed before the run", lambda r: r["evidence"]["pre_verify_ok"]),
    Column("post_restore_verify_ok", "lab verify", "lab verify passed after restoring the baseline",
           lambda r: r["evidence"]["post_restore_verify_ok"]),
    # client/runner logs
    Column("success", "client", "client completed the request and got an HTTP response",
           lambda r: r["outcome"]["success"]),
    Column("exit_code", "client", "process exit code (empty for clients without one)",
           lambda r: r["outcome"].get("exit_code")),
    Column("http_status", "client", "HTTP status the client reported", lambda r: r["outcome"].get("http_status")),
    Column("error", "client", "client error text, if any", lambda r: r["outcome"].get("error")),
    Column("client_remote_ip", "client", "address the client says it connected to",
           lambda r: (r["outcome"].get("client_report") or {}).get("remote_ip")),
    # packet capture
    *_pair("winning_family", "packet", "`v4` or `v6`: family of the completed handshake that carried data",
           _wrapped("packet_observations", "winning_family")),
    *_pair("tcp_setup_time_ms", "packet", "first SYN to the ACK completing the winning handshake; excludes DNS",
           _wrapped("metrics", "tcp_setup_time_ms")),
    *_pair("inter_family_attempt_delay_ms", "packet", "second family's first SYN minus first family's first SYN; "
           "not_observed if only one family was tried", _wrapped("metrics", "inter_family_attempt_delay_ms")),
    *_pair("dns_time_ms", "packet", "first DNS query to last DNS answer for the target name, before the first SYN",
           _wrapped("metrics", "dns_time_ms")),
    *_pair("failed_or_abandoned_attempts", "packet", "attempts that did not win",
           _wrapped("packet_observations", "failed_or_abandoned_attempts")),
    Column("attempts", "packet", "number of connection attempts (SYNs to port 80 on distinct 4-tuples)",
           lambda r: len(_attempts(r)) if r["packet_observations"]["attempts"].get("status") == "computed" else None),
    Column("attempt_shape", "packet", "families of the attempts in SYN order, e.g. `v6>v6>v4`",
           lambda r: ">".join(a["family"] for a in _attempts(r)) or None),
    Column("syn_retransmits", "packet", "kernel SYN retransmissions, summed over attempts (not attempts)",
           lambda r: sum(a["syn_retransmits"] for a in _attempts(r))
           if r["packet_observations"]["attempts"].get("status") == "computed" else None),
    # derived
    *_pair("oracle_setup_ms", "derived", "the winning family's pre-run ping RTT (`metrics.oracle_baseline`)",
           lambda r: _oracle(r)["oracle_setup_ms"]),
    *_pair("cost_of_racing_ms", "derived", "tcp_setup_time_ms minus oracle_setup_ms; not clamped, may be negative",
           lambda r: _oracle(r)["cost_of_racing_ms"]),
    # cross-checks and evidence files
    Column("cross_checks_status", "cross-check", "`agree`, `conflict`, `not_yet_computed` or `not_applicable`",
           lambda r: r.get("cross_checks", {}).get("status", "missing (schema 0.1)")),
    Column("cross_check_conflicts", "cross-check", "conflicting fields, `;`-separated; empty when they agree",
           lambda r: ";".join(c.get("field", "?") for c in r.get("cross_checks", {}).get("conflicts", []))),
    Column("pcap_path", "metadata", "packet capture, relative to the repo root", lambda r: r["evidence"]["pcap_path"]),
    Column("pcap_sha256", "metadata", "SHA-256 of the capture as saved", lambda r: r["evidence"]["pcap_sha256"]),
]
FIELDNAMES = [c.name for c in COLUMNS]
assert len(set(FIELDNAMES)) == len(FIELDNAMES) and {c.source for c in COLUMNS} <= set(SOURCES)


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    return str(v)


def row(record: dict) -> dict[str, str]:
    return {c.name: _cell(c.get(record)) for c in COLUMNS}


def column_table() -> str:
    """The column list as a Markdown table (docs/integration.md carries exactly this)."""
    lines = ["| Column | Source | Meaning |", "|---|---|---|"]
    lines += [f"| `{c.name}` | {c.source} | {c.description} |" for c in COLUMNS]
    return "\n".join(lines)


def records_from_paths(paths: list[Path]) -> list[dict]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files += sorted(p.glob("*.json"))
        elif p.is_file():
            files.append(p)
        else:
            raise DatasetError(f"{p}: no such file or folder")
    if not files:
        raise DatasetError("no record files found")
    records, problems = [], []
    for f in files:
        r = json.loads(f.read_text(encoding="utf-8"))
        errs = validate(r)
        if errs:
            problems.append(f"{f}: " + "; ".join(errs))
        records.append(r)
    if problems:
        raise DatasetError("invalid record(s):\n  " + "\n  ".join(problems))
    return records


def records_from_dataset(name: str = CORE_DATASET, runs_dir: Path = RUNS_DIR) -> list[dict]:
    """The raw records of exactly the runs summarise accepts for this dataset."""
    m = load_dataset(name)
    accepted = load_runs(m.sessions, runs_dir, expected=m.shape.reps, repo=None, adaptive=m.shape.adaptive)
    wanted = {r.run_id for r in accepted}
    by_id = {}
    for p in sorted(runs_dir.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        if r.get("run_id") in wanted:
            by_id[r["run_id"]] = r
    return [by_id[r.run_id] for r in accepted]


def write_csv(records: list[dict], fh) -> int:
    w = csv.DictWriter(fh, fieldnames=FIELDNAMES, lineterminator="\n")
    w.writeheader()
    for r in sorted(records, key=lambda r: r["run_id"]):
        w.writerow(row(r))
    return len(records)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path, help="record files or folders (default: the --dataset records)")
    ap.add_argument("--dataset", default=None,
                    help="dataset name: 'core' (docs/dataset.md, the default) or NAME for docs/datasets/NAME.md")
    ap.add_argument("--out", type=Path, default=None, help="CSV file to write (default: stdout)")
    ap.add_argument("--columns", action="store_true", help="print the column table (Markdown) and exit")
    a = ap.parse_args(argv)
    if a.columns:
        print(column_table())
        return 0
    if a.paths and a.dataset:
        ap.error("give record paths or --dataset, not both")
    try:
        records = records_from_paths(a.paths) if a.paths else records_from_dataset(a.dataset or CORE_DATASET)
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if a.out is None:
        write_csv(records, sys.stdout)
        return 0
    with a.out.open("w", newline="", encoding="utf-8") as fh:
        n = write_csv(records, fh)
    print(f"wrote {a.out} ({n} runs)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
