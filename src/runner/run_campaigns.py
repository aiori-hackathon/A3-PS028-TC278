"""Campaign 2 (latency sweep) then campaign 3 (curl@he sweep), unattended, each with its own manifest.

    .venv/bin/python src/runner/run_campaigns.py --dry-run     # plans, totals, time estimates (no sudo)
    sudo .venv/bin/python src/runner/run_campaigns.py          # plain sudo, never -E

Order, stopping at the first failure:
  0. Pre-flight: clean tree (the batch check refuses a -dirty code version), generated scenarios
     up to date, neither manifest exists yet.
  1. src/runner/fractional_delay_check.py: does netem realise a half ms each way? Campaign 2's odd
     steps depend on it. If the check does not pass, nothing else runs.
  2. Campaign 2, run_matrix.py --only <36 batches> --reps 5, then docs/datasets/latency-sweep.md.
  3. Campaign 3, run_matrix.py --only <27 batches> --reps 10, then docs/datasets/he-sweep.md.
A manifest is written only when every batch of its campaign passed its batch check, and it is
loaded back with summarise.load_manifest before the next step starts. Finally, also on an error or
Ctrl-C, both links are restored to the baseline and verified (verify.sh up 20 20).

Campaign 2 cells (deterministic delay, "+N ms RTT" on IPv6, RTT = 20 + N):
  - coarse: +100..+400 in 25 ms steps, for both clients;
  - fine: 5 ms steps around each client's packet-measured crossover from the jitter-loss dataset
    (curl T = 222.0 ms: RTT 210-235, +190..+215; Chromium T = 322.5 ms: RTT 310-335, +290..+315),
    for that client only. The other client's fine cells are declared in absent_cells.
Campaign 3 cells: curl and curl@he50, he100, he150, he200, he250, he300, he400, he500 on C0, S1, S3.
curl@he200 against plain curl is the validation control.

Nothing retries by itself. run_matrix.py's own STOP message says how to complete a batch.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner.child_env import STRIPPED_VARS, child_env  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PY = str(REPO / ".venv" / "bin" / "python")
DATASETS = REPO / "docs" / "datasets"

COARSE = list(range(100, 401, 25))
FINE = {"curl": [190, 195, 205, 210, 215], "chromium": [290, 295, 305, 310, 315]}
HE_VARIANTS = [50, 100, 150, 200, 250, 300, 400, 500]

# Measured on 2026-11-21/22 (batch logs' "wall time per run" and matrix.log batch times):
# a run takes 12.85 s for curl and 13.65 s for chromium on delay cells, and up to 14.7 s for curl
# and its variants on S1 (used for every campaign-3 cell, so that estimate is the upper end).
# Batch start-up added 4-10 s; 10 s per batch is used.
S_PER_RUN = {"curl": 12.85, "chromium": 13.65}
S_PER_RUN_CAMPAIGN3 = 14.7
BATCH_OVERHEAD_S = 10.0
REFERENCE_S_PER_RUN = 13.8


def gid(n: int) -> str:
    return f"Gv6d{n}"


def campaign2() -> dict:
    vals = sorted(set(COARSE) | {v for vs in FINE.values() for v in vs})
    batches = []
    for v in vals:
        for c in ("curl", "chromium"):
            if v in COARSE or v in FINE[c]:
                batches.append((gid(v), c))
    absent = [f"{c}:{gid(v)}" for c in ("curl", "chromium") for v in vals if v not in COARSE and v not in FINE[c]]
    return {"name": "latency-sweep", "reps": 5, "clients": ["curl", "chromium"],
            "scenarios": [gid(v) for v in vals], "absent": absent, "batches": batches}


def campaign3() -> dict:
    clients = ["curl"] + [f"curl@he{n}" for n in HE_VARIANTS]
    scen = ["C0", "S1", "S3"]
    return {"name": "he-sweep", "reps": 10, "clients": clients, "scenarios": scen, "absent": [],
            "batches": [(s, c) for s in scen for c in clients]}


def only_arg(c: dict) -> str:
    return ",".join(f"{s}:{cl}" for s, cl in c["batches"])


def matrix_cmd(c: dict, dry_run: bool) -> list[str]:
    return [PY, str(REPO / "src" / "runner" / "run_matrix.py")] + (["--dry-run"] if dry_run else []) + \
        ["--only", only_arg(c), "--reps", str(c["reps"])]


def estimate_s(c: dict) -> float:
    per_run = (lambda cl: S_PER_RUN_CAMPAIGN3) if c["name"] == "he-sweep" else (lambda cl: S_PER_RUN[cl])
    return sum(c["reps"] * per_run(cl) + BATCH_OVERHEAD_S for _, cl in c["batches"])


def _hm(sec: float) -> str:
    return f"{int(sec // 3600)} h {round(sec % 3600 / 60):02d} min"


# --- manifests ------------------------------------------------------------------------------

_SUMMARY_RE = re.compile(r"^\s+\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+session (\d{8}T\d{6}Z)\s+exit (\d+)\s+check (PASS|FAIL)\s*$")


def summary_rows(matrix_log: str) -> list[tuple[str, str, str]]:
    """(client, scenario, session) from run_matrix's Summary block; only exit 0 + check PASS rows."""
    parts = re.split(r"^Summary \(", matrix_log, maxsplit=1, flags=re.M)
    block = parts[1] if len(parts) == 2 else ""
    rows = []
    for line in block.splitlines():
        m = _SUMMARY_RE.match(line)
        if m and m.group(5) == "0" and m.group(6) == "PASS":
            rows.append((m.group(2), m.group(3), m.group(4)))
    return rows


TEXT = {
    "latency-sweep": (
        "IPv6 latency sweep",
        "deterministic IPv6 delay, +100..+400 ms RTT in 25 ms steps for both clients, plus 5 ms steps "
        "around each client's packet-measured crossover for that client only",
        "Deterministic IPv6 delay (generated `Gv6d<N>`, \"+N ms RTT\": RTT = 20 + N ms, IPv4 at the baseline), "
        "5 repetitions per cell. Coarse cells run +100..+400 in 25 ms steps for both clients. Fine cells run "
        "5 ms steps around each client's packet-measured crossover from the `jitter-loss` dataset, for that "
        "client only: curl T = 222.0 ms, so RTT 210-235 ms (+190..+215); Chromium T = 322.5 ms, so RTT "
        "310-335 ms (+290..+315). The other client's fine cells are declared in `absent_cells`. Odd N gives a "
        "half ms each way; `src/runner/fractional_delay_check.py` checked it before this campaign (log in "
        "`data/generated/lab/`). The purpose is to locate each client's outcome flip to within 5 ms and test "
        "the measured T independently of the packet times."),
    "he-sweep": (
        "curl Happy Eyeballs timeout sweep",
        "plain curl and curl@he50..he500 on C0, S1 and S3, 10 repetitions; curl@he200 against plain curl is "
        "the validation control",
        "Plain curl and eight curl variants with an explicit `--happy-eyeballs-timeout-ms` (50, 100, 150, "
        "200, 250, 300, 400, 500) on C0, S1 and S3, 10 repetitions per cell. curl@he200 sets curl's "
        "documented default explicitly and is compared with plain curl as the validation control (see "
        "[`docs/client_variants.md`](../client_variants.md)). S2 is left out: it was within 0.04 ms of S1 "
        "in the core data. A variant is a configuration of curl, not another client."),
}


def manifest_text(c: dict, rows: list[tuple[str, str, str]], code: str, when: str) -> str:
    title, desc, intro = TEXT[c["name"]]
    head = ["---", f"title: {title}", f"description: {desc}", f"clients: [{', '.join(c['clients'])}]",
            f"scenarios: [{', '.join(c['scenarios'])}]", f"reps: {c['reps']}"]
    if c["absent"]:
        head.append(f"absent_cells: [{', '.join(c['absent'])}]")
    head.append("---")
    order = {b: i for i, b in enumerate(c["batches"])}
    rows = sorted(rows, key=lambda r: order[(r[1], r[0])])
    table = ["| # | Client | Scenario | Session | Note |", "|---|---|---|---|---|"]
    table += [f"| {i} | {cl} | {s} | `{sid}` | {c['reps']}/{c['reps']} good repetitions, batch check PASS |"
              for i, (cl, s, sid) in enumerate(rows, 1)]
    return "\n".join(head + [f"# {title}", "", intro, "",
                             f"Run on {when} with `src/runner/run_campaigns.py` (run_matrix.py --only, --reps "
                             f"{c['reps']}) from code version `{code}` with a clean tree. This is not the core dataset.",
                             "", "## Sessions in the dataset", ""] + table) + "\n"


# --- running ------------------------------------------------------------------------------

def stream(cmd: list[str]) -> tuple[int, str]:
    """Run a step with the clean environment, echoing its output; Ctrl-C reaches it too (same group)."""
    out = []
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                            env=child_env())
    try:
        for line in proc.stdout:
            sys.stdout.write(line)
            out.append(line)
        proc.wait()
    except KeyboardInterrupt:
        proc.wait()   # let the child restore its own state first
        raise
    return proc.returncode, "".join(out)


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, env=child_env()).stdout.strip()


def preflight(campaigns: list[dict]) -> list[str]:
    problems = []
    if git("status", "--porcelain", "--untracked-files=no"):
        problems.append("the tree has uncommitted changes to tracked files: commit first (the batch check refuses -dirty)")
    chk = subprocess.run([PY, str(REPO / "src" / "runner" / "scenario_grid.py"), "--check"], capture_output=True,
                         text=True, env=child_env())
    if chk.returncode != 0:
        problems.append("src/config/scenarios_generated.yaml is out of date: run src/runner/scenario_grid.py")
    for c in campaigns:
        if (DATASETS / f"{c['name']}.md").exists():
            problems.append(f"docs/datasets/{c['name']}.md already exists: it is never overwritten")
    return problems


def restore() -> int:
    lab = REPO / "src" / "lab"
    for fam in ("v4", "v6"):
        subprocess.run([str(lab / "netem.sh"), fam, "10", "0"], env=child_env())
    return subprocess.run([str(lab / "verify.sh"), "up", "20", "20"], env=child_env()).returncode


def dry_run(campaigns: list[dict]) -> int:
    print("DRY RUN: nothing is executed. Step 1, the fractional-delay check:")
    code, _ = stream([PY, str(REPO / "src" / "runner" / "fractional_delay_check.py"), "--dry-run"])
    if code:
        return code
    total_runs = total_s = 0
    for i, c in enumerate(campaigns, 2):
        print(f"\nStep {i}, campaign {i}: {c['name']} -> docs/datasets/{c['name']}.md")
        code, out = stream(matrix_cmd(c, dry_run=True))
        if code or not out.startswith(f"Plan: {len(c['batches'])} batches"):
            print(f"ERROR: run_matrix dry run did not plan {len(c['batches'])} batches", file=sys.stderr)
            return code or 1
        runs, est = len(c["batches"]) * c["reps"], estimate_s(c)
        total_runs += runs
        total_s += est
        print(f"  {len(c['batches'])} cells x {c['reps']} reps = {runs} runs; estimated {_hm(est)} "
              f"(measured s/run plus 10 s start-up per batch), {_hm(runs * REFERENCE_S_PER_RUN)} at {REFERENCE_S_PER_RUN} s/run")
        print(f"  clients {c['clients']}; {len(c['scenarios'])} scenarios"
              + (f"; absent_cells ({len(c['absent'])}): {', '.join(c['absent'])}" if c["absent"] else ""))
    print(f"\nTOTAL: {total_runs} runs, estimated {_hm(total_s)} "
          f"({_hm(total_runs * REFERENCE_S_PER_RUN)} at {REFERENCE_S_PER_RUN} s/run), "
          "plus about 1 min for the fractional-delay check")
    problems = preflight(campaigns)
    print("\nPre-flight now: " + ("OK" if not problems else "would refuse:\n  - " + "\n  - ".join(problems)))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    campaigns = [campaign2(), campaign3()]
    if a.dry_run:
        return dry_run(campaigns)

    leaked = [k for k in STRIPPED_VARS if k in os.environ]
    if leaked:
        sys.exit(f"{', '.join(leaked)} set: run with plain sudo, never sudo -E")
    if os.geteuid() != 0 or os.environ.get("SUDO_USER", "root") == "root":
        sys.exit("run with plain sudo from your normal account: sudo .venv/bin/python src/runner/run_campaigns.py")
    problems = preflight(campaigns)
    if problems:
        sys.exit("refusing to start:\n  - " + "\n  - ".join(problems))
    from analysis.summarise import DatasetError, load_manifest
    import pwd
    pw = pwd.getpwnam(os.environ["SUDO_USER"])
    code_version = git("rev-parse", "--short", "HEAD")
    status, t0 = 0, time.monotonic()
    try:
        print("== Step 1: fractional-delay check", flush=True)
        code, _ = stream([PY, str(REPO / "src" / "runner" / "fractional_delay_check.py")])
        if code != 0:
            print(f"STOP: fractional-delay check exit {code}; campaign 2's odd steps are not usable. "
                  "Nothing else was run.", flush=True)
            return 3 if code == 3 else 1
        for i, c in enumerate(campaigns, 2):
            print(f"\n== Step {i}: campaign {i}, {c['name']} ({len(c['batches'])} batches x {c['reps']} reps)", flush=True)
            code, out = stream(matrix_cmd(c, dry_run=False))
            m = re.search(r"output (data/generated/lab/\d{8}T\d{6}Z_matrix)", out)
            log_text = (REPO / m.group(1) / "matrix.log").read_text(encoding="utf-8") if m else ""
            rows = summary_rows(log_text)
            if code != 0 or len(rows) != len(c["batches"]):
                print(f"STOP: campaign {i} did not complete ({len(rows)}/{len(c['batches'])} batches passed, "
                      f"run_matrix exit {code}); no manifest written; later campaigns not started.", flush=True)
                status = 1
                break
            path = DATASETS / f"{c['name']}.md"
            path.write_text(manifest_text(c, rows, code_version, datetime.now(timezone.utc).strftime("%Y-%m-%d")),
                            encoding="utf-8")
            os.chown(path, pw.pw_uid, pw.pw_gid)
            try:
                load_manifest(path, require_header=True)
            except DatasetError as exc:
                print(f"STOP: {path.relative_to(REPO)} does not load: {exc}", flush=True)
                status = 1
                break
            print(f"wrote {path.relative_to(REPO)} ({len(rows)} sessions); it loads with summarise.load_manifest",
                  flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted.", flush=True)
        status = 130
    finally:
        print("\n== Restore baseline (both links 10 ms each way, no loss) and verify", flush=True)
        rc = restore()
        print(f"RESTORE: verify exit {rc} ({'PASS' if rc == 0 else 'FAIL: check the lab'}); "
              f"total {(time.monotonic() - t0) / 60:.1f} min", flush=True)
        if rc != 0 and status == 0:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
