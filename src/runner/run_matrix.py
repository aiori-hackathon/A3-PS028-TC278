"""Run the full HappyLab matrix (7 scenarios x 2 clients x 20 reps), one batch at a time, unattended.

Adapted from Sam's run_full_matrix.py. Batches run strictly one after another: the lab's netem
and neighbour state is shared, so orchestrator sessions must never overlap.

    .venv/bin/python src/runner/run_matrix.py --dry-run                 # print the plan (no sudo)
    sudo .venv/bin/python src/runner/run_matrix.py                      # all 14 batches
    sudo .venv/bin/python src/runner/run_matrix.py --from 5             # resume at batch 5
    sudo .venv/bin/python src/runner/run_matrix.py --only S3:chromium   # one batch

Plain sudo only, never sudo -E (the ROS variables would reach the orchestrator, which refuses them).

After every batch it runs the read-only batch check (src/analysis/check_batch.py): pcap count
equals record count, every record has a matching pcap hash, lab verify passed before and after
every run, cross_checks agree, code version not -dirty, 20 good repetitions. It then STOPS on:
  - orchestrator exit 1: the session stopped (failed verify, incomplete capture, error)
  - orchestrator exit 3: the session finished but some runs have log/pcap conflicts
  - a failed batch check
It never retries by itself: re-running is a decision for a person. The check prints the exact
command to complete the batch (flagged runs stay on disk, unchanged), and --from resumes.
Output goes to data/generated/lab/<UTC>_matrix/ (gitignored) and is chowned to the sudo user.
"""

from __future__ import annotations

import argparse
import os
import pwd
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.check_batch import check_batch, report  # noqa: E402
from runner.child_env import STRIPPED_VARS, child_env  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SCENARIOS = ["C0", "S1", "S2", "S3", "S4", "S5", "S6"]
CLIENTS = ["curl", "chromium"]
REPS = 20
PLAN = [(scenario, client) for scenario in SCENARIOS for client in CLIENTS]
_SESSION_RE = re.compile(r"session log data/generated/lab/(\d{8}T\d{6}Z)_session\.log")
EXIT_MEANING = {0: "completed", 1: "stopped (failed verify, incomplete capture or error)",
                3: "completed with log/pcap conflicts"}


def orchestrator_cmd(scenario: str, client: str, reps: int = REPS) -> list[str]:
    return [str(REPO / ".venv" / "bin" / "python"), str(REPO / "src" / "runner" / "orchestrate.py"),
            "--client", client, "--scenario", scenario, "--reps", str(reps)]


def session_id(output: str) -> str | None:
    m = _SESSION_RE.search(output)
    return m.group(1) if m else None


def select(plan: list[tuple[str, str]], start: int = 1, only: str | None = None) -> list[tuple[int, str, str]]:
    numbered = [(i, s, c) for i, (s, c) in enumerate(plan, start=1)]
    if only:
        scenario, _, client = only.partition(":")
        return [x for x in numbered if x[1] == scenario and x[2] == client]
    return [x for x in numbered if x[0] >= start]


class Log:
    def __init__(self, path: Path):
        self.path = path
        self.f = path.open("x", encoding="utf-8")

    def __call__(self, text: str = "") -> None:
        print(text, flush=True)
        self.f.write(text + "\n")
        self.f.flush()


def run_batch(n: int, scenario: str, client: str, out_dir: Path, log: Log) -> tuple[int, str, str | None]:
    cmd = orchestrator_cmd(scenario, client)
    path = out_dir / f"{n:02d}_{scenario}_{client}.log"
    log(f"\n[{n}/{len(PLAN)}] {client} {scenario} x{REPS}: {' '.join(cmd)}")
    t0 = time.monotonic()
    captured = []
    with path.open("x", encoding="utf-8") as f:
        f.write(f"# command: {' '.join(cmd)}\n# started: {datetime.now(timezone.utc).isoformat()}\n\n")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                bufsize=1, env=child_env())
        for line in proc.stdout:
            sys.stdout.write(line)
            f.write(line)
            captured.append(line)
        proc.wait()
        f.write(f"\n# finished: {datetime.now(timezone.utc).isoformat()}\n# exit code: {proc.returncode}\n")
    log(f"  exit {proc.returncode} ({EXIT_MEANING.get(proc.returncode, 'unexpected')}), "
        f"{time.monotonic() - t0:.0f} s, output {path.relative_to(REPO)}")
    return proc.returncode, str(path), session_id("".join(captured))


def chown_tree(path: Path, user: str) -> None:
    pw = pwd.getpwnam(user)
    for p in [path, *path.rglob("*")]:
        try:
            os.chown(p, pw.pw_uid, pw.pw_gid)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--from", dest="start", type=int, default=1, help="first batch number to run (1-14)")
    ap.add_argument("--only", help="run just one batch, e.g. S3:chromium")
    a = ap.parse_args(argv)
    todo = select(PLAN, a.start, a.only)
    if not todo:
        ap.error("nothing selected")

    if a.dry_run:
        print(f"Plan: {len(todo)} of {len(PLAN)} batches, {REPS} reps each, one at a time; "
              "batch check after each; stop on any failure.")
        for n, s, c in todo:
            print(f"  [{n:2d}] {' '.join(orchestrator_cmd(s, c))}")
        return 0

    leaked = [k for k in STRIPPED_VARS if k in os.environ]
    if leaked:
        sys.exit(f"{', '.join(leaked)} set: run with plain sudo, never sudo -E")
    if os.geteuid() != 0:
        sys.exit("run with sudo: sudo .venv/bin/python src/runner/run_matrix.py")
    user = os.environ.get("SUDO_USER", "")
    if not user or user == "root":
        sys.exit("SUDO_USER is not set: start this with sudo from your normal account")

    out_dir = REPO / "data" / "generated" / "lab" / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}_matrix"
    out_dir.mkdir(parents=True)
    log = Log(out_dir / "matrix.log")
    log(f"HappyLab matrix: {len(todo)} batch(es), output {out_dir.relative_to(REPO)}")
    done: list[str] = []
    status = 0
    t_all = time.monotonic()
    try:
        for n, scenario, client in todo:
            code, _, sid = run_batch(n, scenario, client, out_dir, log)
            if sid is None:
                log(f"  STOP: no session ID in the orchestrator output (exit {code}); see the batch output")
                status = 1
                break
            res = check_batch(client, scenario, REPS, [sid])
            log(report(res))
            done.append(f"[{n:2d}] {client:8} {scenario}  session {sid}  exit {code}  "
                        f"check {'PASS' if res.ok else 'FAIL'}")
            if code != 0 or not res.ok:
                log(f"\nSTOP after batch {n}: {EXIT_MEANING.get(code, f'exit {code}')}; "
                    f"batch check {'PASS' if res.ok else 'FAIL'}.")
                log("Review the flagged runs above. To complete this batch use the command(s) printed "
                    "by the check, then resume with:")
                log(f"  sudo .venv/bin/python src/runner/run_matrix.py --from {n + 1}")
                status = 1
                break
    except KeyboardInterrupt:
        log("\nInterrupted. The orchestrator restores the lab baseline on Ctrl-C; confirm with "
            "sudo src/lab/verify.sh up 20 20")
        status = 130
    finally:
        log(f"\nSummary ({(time.monotonic() - t_all) / 60:.1f} min)")
        for line in done:
            log("  " + line)
        log.f.close()
        chown_tree(out_dir, user)
    return status


if __name__ == "__main__":
    sys.exit(main())
