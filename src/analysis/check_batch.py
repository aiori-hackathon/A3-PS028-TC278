"""Check one measurement batch (one client x one scenario) after it has run. Read-only.

    .venv/bin/python src/analysis/check_batch.py --client curl --scenario S1 --expect 20 \
        --session 20261027T090000Z [--session <re-run session> ...]

A batch can span several sessions: the original one plus any re-runs that complete it.
Runs belong to a session if their run log says "session: <id>".

Checks, per run:
  - a pcap and a record exist for every run that started (the pcap count equals the record count)
  - the record validates and has a pcap_sha256 that matches the pcap on disk
  - pre-run and post-restore lab verify passed
  - cross_checks agree
  - client and scenario match the batch, and the code version is not "-dirty"
A repetition counts as good only if one of its records passes every check. Nothing is edited,
deleted or re-labelled: flagged runs stay on disk as evidence, and missing or flagged
repetitions are listed with the command to run them again under new run IDs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.validate_record import validate  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
_RUN_RE = re.compile(r"^(?P<ts>\d{8}T\d{6}Z)_(?P<scenario>\w+?)_(?P<client>curl|chromium)_r(?P<rep>\d+)$")


@dataclass
class RunCheck:
    run_id: str
    rep: int
    problems: list[str] = field(default_factory=list)

    @property
    def good(self) -> bool:
        return not self.problems


@dataclass
class BatchResult:
    client: str
    scenario: str
    expect: int
    sessions: list[str]
    started: list[str]
    records: int
    pcaps: int
    runs: list[RunCheck]
    batch_problems: list[str]

    @property
    def good_reps(self) -> set[int]:
        return {r.rep for r in self.runs if r.good}

    @property
    def missing_reps(self) -> list[int]:
        return [n for n in range(1, self.expect + 1) if n not in self.good_reps]

    @property
    def ok(self) -> bool:
        return not self.missing_reps and not self.batch_problems and all(r.good for r in self.runs)


def runs_in_sessions(logs: Path, sessions: list[str]) -> list[str]:
    """Run IDs whose run log names one of the sessions (includes runs that never wrote a record)."""
    wanted = {f"session: {s}" for s in sessions}
    out = []
    for log in sorted(logs.glob("*.log")):
        if not _RUN_RE.match(log.stem):
            continue
        try:
            head = log.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
        except OSError:
            continue
        if any(line.strip() in wanted for line in head):
            out.append(log.stem)
    return out


def check_run(run_id: str, client: str, scenario: str, runs: Path, captures: Path, repo: Path) -> tuple[RunCheck, bool, bool]:
    """Returns (check, has_record, has_pcap)."""
    m = _RUN_RE.match(run_id)
    rc = RunCheck(run_id=run_id, rep=int(m["rep"]) if m else 0)
    if m and (m["client"], m["scenario"]) != (client, scenario):
        rc.problems.append(f"run is {m['client']}/{m['scenario']}, not {client}/{scenario}")
    pcap = captures / f"{run_id}.pcap"
    rec_path = runs / f"{run_id}.json"
    has_pcap, has_record = pcap.exists(), rec_path.exists()
    if not has_record:
        rc.problems.append("no record (run stopped before writing it; see its run log)")
    if not has_pcap:
        rc.problems.append("no pcap")
    if not has_record:
        return rc, has_record, has_pcap
    try:
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        rc.problems.append(f"record unreadable: {exc}")
        return rc, has_record, has_pcap
    rc.problems += [f"invalid record: {p}" for p in validate(rec)]
    ev = rec.get("evidence", {})
    sha = ev.get("pcap_sha256")
    if not sha:
        rc.problems.append("pcap_sha256 missing")
    elif has_pcap and hashlib.sha256(pcap.read_bytes()).hexdigest() != sha:
        rc.problems.append("pcap hash does not match the record")
    if ev.get("pcap_path") and (repo / ev["pcap_path"]).resolve() != pcap.resolve():
        rc.problems.append(f"record points at a different pcap: {ev['pcap_path']}")
    if ev.get("pre_verify_ok") is not True:
        rc.problems.append("pre-run verify did not pass")
    if ev.get("post_restore_verify_ok") is not True:
        rc.problems.append("post-restore verify did not pass")
    cc = rec.get("cross_checks", {})
    if cc.get("status") != "agree":
        fields = ", ".join(c.get("field", "?") for c in cc.get("conflicts", []))
        rc.problems.append(f"cross_checks {cc.get('status')}" + (f" ({fields})" if fields else ""))
    if str(rec.get("environment", {}).get("git_commit", "")).endswith("-dirty"):
        rc.problems.append("code version is -dirty (uncommitted changes)")
    return rc, has_record, has_pcap


def check_batch(client: str, scenario: str, expect: int, sessions: list[str], repo: Path = REPO) -> BatchResult:
    gen = repo / "data" / "generated"
    started = runs_in_sessions(gen / "logs", sessions)
    checks, records, pcaps = [], 0, 0
    for run_id in started:
        rc, has_record, has_pcap = check_run(run_id, client, scenario, gen / "runs", repo / "captures", repo)
        checks.append(rc)
        records += has_record
        pcaps += has_pcap
    problems = []
    if not started:
        problems.append(f"no runs found for session(s) {', '.join(sessions)}")
    if pcaps != records:
        problems.append(f"pcap count ({pcaps}) differs from record count ({records})")
    reps = [c.rep for c in checks if c.good]
    dupes = sorted({r for r in reps if reps.count(r) > 1})
    if dupes:
        problems.append(f"repetition(s) with more than one good record: {dupes} (pick none silently; review)")
    extra = sorted({c.rep for c in checks if c.rep > expect})
    if extra:
        problems.append(f"repetition number(s) above --expect {expect}: {extra}")
    return BatchResult(client, scenario, expect, sessions, started, records, pcaps, checks, problems)


def rerun_commands(res: BatchResult) -> list[str]:
    """One orchestrator command per contiguous block of missing repetitions."""
    cmds, missing = [], res.missing_reps
    i = 0
    while i < len(missing):
        j = i
        while j + 1 < len(missing) and missing[j + 1] == missing[j] + 1:
            j += 1
        cmds.append(f"sudo .venv/bin/python src/runner/orchestrate.py --client {res.client} "
                    f"--scenario {res.scenario} --first-rep {missing[i]} --reps {j - i + 1}")
        i = j + 1
    return cmds


def report(res: BatchResult) -> str:
    lines = [f"BATCH {res.client}/{res.scenario}  sessions {', '.join(res.sessions)}",
             f"  runs started {len(res.started)}, records {res.records}, pcaps {res.pcaps}, "
             f"good repetitions {len(res.good_reps)}/{res.expect}"]
    for r in res.runs:
        if not r.good:
            lines.append(f"  FLAG {r.run_id}: " + "; ".join(r.problems))
    for p in res.batch_problems:
        lines.append(f"  FLAG batch: {p}")
    if res.missing_reps:
        lines.append(f"  missing or flagged repetitions: {res.missing_reps}")
        lines.append("  to complete the batch (flagged runs stay on disk, unchanged):")
        lines += [f"    {c}" for c in rerun_commands(res)]
    lines.append(f"  RESULT: {'PASS' if res.ok else 'FAIL'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--client", required=True, choices=["curl", "chromium"])
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--expect", type=int, default=20)
    ap.add_argument("--session", action="append", required=True, help="session ID (repeatable)")
    a = ap.parse_args(argv)
    res = check_batch(a.client, a.scenario, a.expect, a.session)
    print(report(res))
    return 0 if res.ok else 1


if __name__ == "__main__":
    sys.exit(main())
