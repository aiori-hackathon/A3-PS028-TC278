"""Band-verify pilot: apply each band scenario's netem and run verify.sh, nothing else.

    sudo .venv/bin/python src/runner/band_pilot.py [--scenario ID ...] [--trials N]   # plain sudo, never -E
    .venv/bin/python src/runner/band_pilot.py --dry-run                                # print the commands only

No client, no capture, no DNS server, no nginx, no run records: this only checks that the
declared loss and jitter bands pass on a correct link before the campaign relies on them.
The lab must already be up (src/lab/setup.sh). The netem and verify.sh arguments come from the
orchestrator's own builders (netem_for, cmd_verify), so they are exactly what a run would use.

For each scenario: apply both families' netem, then run `verify.sh up` N times and keep what each
verify measured (scenario.verify_observed's format). After the last scenario, and on any error
or Ctrl-C, both links are restored to the baseline and verified at the baseline RTT.

It also reads (never sets) net.ipv4.tcp_syn_retries in hl-client and tcp_synack_retries in hl-server.

Output: data/generated/lab/<UTC>_band_pilot.json and .log (owned by the invoking user).
A FAIL here is a pilot result to report, not something to tune away: the bands are 4 standard
errors wide by construction, so repeated FAILs mean the band or the link is wrong.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import orchestrate as o  # noqa: E402
from runner.child_env import child_env_with_removed, describe  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
BAND_SCENARIOS = ("Gv6l10", "Gv6l30", "Gv6l50", "Gv6j50", "Gv6j70", "Gv6c30")


def plan(scenarios: dict, sids: list[str], trials: int) -> list[tuple[str, str, list[str]]]:
    """(scenario, step, argv) in execution order, restore and baseline verify last."""
    base = scenarios["_baseline"]
    steps = []
    for sid in sids:
        sc = scenarios[sid]
        t = sc["verify_target"]
        steps += [(sid, "apply", o.netem_for("v4", sc["v4"])), (sid, "apply", o.netem_for("v6", sc["v6"]))]
        steps += [(sid, f"verify {i}", o.cmd_verify(t["v4"], t["v6"])) for i in range(1, trials + 1)]
    steps += [("baseline", "restore", o.cmd_netem(f, base["delay_ms_each_way"], 0)) for f in ("v4", "v6")]
    steps.append(("baseline", "verify", o.cmd_verify(base["rtt_ms"], base["rtt_ms"])))
    return steps


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", nargs="+", default=list(BAND_SCENARIOS))
    ap.add_argument("--trials", type=int, default=5, help="verify.sh runs per scenario (default 5)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.trials < 1:
        ap.error("--trials must be at least 1")
    try:
        scenarios = o.load_scenarios(a.scenario, client="curl")
        user, uid, gid = o.check_environment(a.dry_run)
    except o.OrchestratorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    steps = plan(scenarios, a.scenario, a.trials)
    if a.dry_run:
        print(f"DRY RUN: {len(a.scenario)} scenario(s) x {a.trials} verify each; nothing is executed.")
        for sid, step, cmd in steps:
            print(f"  {sid:9} {step:9} {shlex.join(cmd)}")
        return 0

    env, removed = child_env_with_removed()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lab_dir = REPO / "data" / "generated" / "lab"
    lab_dir.mkdir(parents=True, exist_ok=True)
    log_path, out_path = lab_dir / f"{stamp}_band_pilot.log", lab_dir / f"{stamp}_band_pilot.json"
    ctx = o.Ctx(user=user, uid=uid, gid=gid, lab=o.load_lab_env(), session_id=stamp, env=env, env_removed=removed)
    ctx.created += [log_path, out_path]
    log = o.RunLog(log_path)
    log.write(f"band pilot {stamp}, code {o.git_commit()}, child_env: {describe(removed)}")
    base = scenarios["_baseline"]
    result = {"pilot": stamp, "code_version": o.git_commit(), "trials": a.trials, "scenarios": {}, "restore": None}
    status = 0
    # Kernel limits under both clients' own time limits (read-only): SYN retries in hl-client,
    # SYN-ACK retries in hl-server. Recorded for the scenario doc; nothing is changed.
    result["kernel"] = {}
    for ns, key in ((ctx.lab["NS_CLIENT"], "net.ipv4.tcp_syn_retries"), (ctx.lab["NS_SERVER"], "net.ipv4.tcp_synack_retries")):
        p = o.sh(ctx, ["ip", "netns", "exec", ns, "sysctl", "-n", key], log, check=False)
        result["kernel"][f"{ns} {key}"] = p.stdout.strip() if p.returncode == 0 else None
        print(f"{ns} {key} = {result['kernel'][f'{ns} {key}']}")
    try:
        for sid in a.scenario:
            sc = scenarios[sid]
            t = sc["verify_target"]
            o.sh(ctx, o.netem_for("v4", sc["v4"]), log)
            o.sh(ctx, o.netem_for("v6", sc["v6"]), log)
            entry = {"label": sc["label"], "verify_target": t, "trials": []}
            for i in range(1, a.trials + 1):
                p = o.sh(ctx, o.cmd_verify(t["v4"], t["v6"]), log, check=False)
                obs = o.verify_observed(o.parse_verify_rtt(p.stdout), {"v4": t["v4"], "v6": t["v6"]})
                entry["trials"].append({"exit": p.returncode, "verify_observed": obs})
                v6 = obs["v6"]["observed"] or {}
                print(f"{sid} trial {i}: verify exit {p.returncode}; v4 {obs['v4']['verdict']}, v6 {obs['v6']['verdict']} "
                      f"(loss {v6.get('loss_pct')}%, median {v6.get('median_ms')} ms, sd {v6.get('sd_ms')} ms, "
                      f"{v6.get('received')}/{v6.get('sent')} replies)", flush=True)
            entry["passed"] = sum(1 for tr in entry["trials"] if tr["exit"] == 0)
            result["scenarios"][sid] = entry
            print(f"== {sid}: {entry['passed']}/{a.trials} verify runs passed", flush=True)
    except (o.OrchestratorError, KeyboardInterrupt) as exc:
        print(f"STOPPED: {exc or 'interrupted'}", file=sys.stderr)
        log.write(f"STOPPED: {exc or 'interrupted'}")
        status = 1
    finally:
        for fam in ("v4", "v6"):
            o.sh(ctx, o.cmd_netem(fam, base["delay_ms_each_way"], 0), log, check=False)
        p = o.sh(ctx, o.cmd_verify(base["rtt_ms"], base["rtt_ms"]), log, check=False)
        result["restore"] = {"exit": p.returncode,
                             "verify_observed": o.verify_observed(o.parse_verify_rtt(p.stdout),
                                                                  {"v4": base["rtt_ms"], "v6": base["rtt_ms"]})}
        print(f"RESTORE baseline: verify exit {p.returncode} ({'PASS' if p.returncode == 0 else 'FAIL: check the lab'})")
        out_path.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        for path in ctx.created:
            ctx.chown(path)
        print(f"wrote {out_path.relative_to(REPO)} and {log_path.relative_to(REPO)}")
    if p.returncode != 0:
        status = 1
    if status == 0 and any(e["passed"] < a.trials for e in result["scenarios"].values()):
        status = 3   # a band verify failed at least once: a result to look at, not an error
    return status


if __name__ == "__main__":
    sys.exit(main())
