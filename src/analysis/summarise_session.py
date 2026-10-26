"""Print a per-run table for one orchestrator session (reads records and the session log only).

    .venv/bin/python src/analysis/summarise_session.py 20261026T064544Z

Values come from the run records: measured RTT is from verify.sh pings before the run,
winner/setup/inter-family/DNS are packet-level (pcap), outcome is client-reported.
Wall time is the orchestrator's whole-run time (DNS restart, apply, verify, capture,
client, restore, verify, parse), read from the session log.
"""

from __future__ import annotations

import json
import re
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "data" / "generated" / "runs"
LAB_LOGS = REPO / "data" / "generated" / "lab"

COLUMNS = ["run_id", "scn", "rtt_v4", "rtt_v6", "outcome", "win", "setup_ms", "inter_fam_ms",
           "fail/aband", "dns_ms", "cross_chk", "wall_s"]
_WALL_RE = re.compile(r"^(\S+)\s.*\swall_s=([\d.]+)\s*$")


def _v(field: dict):
    return field["value"] if field["status"] == "computed" else field["status"]


def _rtt(field: dict) -> str:
    if field["status"] == "computed":
        return f"{field['value']:g}"
    note = field.get("note", "")
    return "blackhole" if note.startswith("blackhole") else field["status"]


def row(r: dict, wall: float | None) -> list[str]:
    met, obs, out = r["metrics"], r["packet_observations"], r["outcome"]
    outcome = f"ok {out['http_status']}" if out["success"] else f"FAIL {out['error'] or out['exit_code']}"
    cells = [r["run_id"], r["scenario"]["id"], _rtt(r["scenario"]["measured_rtt_ms"]["v4"]),
             _rtt(r["scenario"]["measured_rtt_ms"]["v6"]), outcome, _v(obs["winning_family"]),
             _v(met["tcp_setup_time_ms"]), _v(met["inter_family_attempt_delay_ms"]),
             _v(obs["failed_or_abandoned_attempts"]), _v(met["dns_time_ms"]),
             r["cross_checks"]["status"], f"{wall:.2f}" if wall is not None else "?"]
    return [str(c) for c in cells]


def parse_walls(session_log: str) -> dict[str, float]:
    out = {}
    for line in session_log.splitlines():
        m = _WALL_RE.match(line.strip())
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def format_table(rows: list[list[str]]) -> str:
    widths = [max(len(c) for c in col) for col in zip(COLUMNS, *rows)]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in [COLUMNS, *rows]]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def load_session(session_id: str, runs: Path = RUNS) -> list[dict]:
    recs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(runs.glob("*.json"))]
    return [r for r in recs if r.get("environment", {}).get("session_id") == session_id]


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    sid = argv[0]
    records = load_session(sid)
    if not records:
        print(f"no records for session {sid}", file=sys.stderr)
        return 1
    log = LAB_LOGS / f"{sid}_session.log"
    walls = parse_walls(log.read_text(encoding="utf-8")) if log.exists() else {}
    print(format_table([row(r, walls.get(r["run_id"])) for r in records]))
    w = [walls[r["run_id"]] for r in records if r["run_id"] in walls]
    if w:
        print(f"\nwall time per run: mean {statistics.mean(w):.2f} s, median {statistics.median(w):.2f} s, "
              f"min {min(w):.2f} s, max {max(w):.2f} s (n={len(w)})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
