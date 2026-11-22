"""Check that netem realises a half-millisecond delay, before any odd-N scenario is used.

    sudo .venv/bin/python src/runner/fractional_delay_check.py [--scenario ID ...]   # plain sudo, never -E
    .venv/bin/python src/runner/fractional_delay_check.py --dry-run                   # print the commands only

An odd "+N ms RTT" scenario sets a half ms each way (Gv6d195: 107.5 ms). Two things could go wrong
unseen: tc could accept "107.5ms" but netem could round or truncate it, and the scenario's own
point verify cannot catch that. Its tolerance is max(2 ms, 10% of target), about 21 ms at 215 ms,
and above 100 ms ping prints whole ms only. So for each scenario this runs a differential check on
the IPv6 link (IPv4 stays at the baseline):

  1. Each way E - 0.5, E, E + 0.5 ms (E = the scenario's each-way delay), 200 pings each at 0.02 s
     (ICMP; the values ping prints, truncated to whole ms above 100 ms). If the RTT moves by
     exactly 1 ms, the truncated values move by exactly 1 ms too, whatever the fixed overhead. So
     the mean must step up by 1 ms each time: PASS when both steps are within 1 +/- STEP_TOL_MS.
     A truncated half ms shows a 0 ms step, and one rounded up a 2 ms step.
  2. The scenario's own verify (verify.sh up with its targets), as a run would do it.

The tc settings read back from the qdisc are logged as configuration, not as evidence. After the
last scenario, and on any error or Ctrl-C, the IPv6 and IPv4 links are restored to the baseline and
verified. No client, no capture, no run records. Output: data/generated/lab/<UTC>_fractional_delay.json/.log.
Exit 0 when every check passed, 3 when a check failed (a result to look at; the fine steps are then
not usable), and 1 on an error.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import orchestrate as o  # noqa: E402
from runner.child_env import child_env_with_removed, describe  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIOS = ("Gv6d195", "Gv6d305")   # one odd step in each fine window (curl, Chromium)
PINGS, INTERVAL_S = 200, "0.02"
STEP_TOL_MS = 0.5
_TIME_RE = re.compile(r"time=([0-9.]+) ms")


def ping_cmd(lab: dict) -> list[str]:
    return ["ip", "netns", "exec", lab["NS_CLIENT"], "ping", "-6", "-n", "-c", str(PINGS), "-i", INTERVAL_S,
            "-W", "2", lab["V6_ADDR_S"]]


def ping_times(output: str) -> list[float]:
    """RTT values exactly as ping printed them (ms)."""
    return [float(x) for x in _TIME_RE.findall(output)]


def steps_verdict(means: list[float], tol: float = STEP_TOL_MS) -> dict:
    """means at each way E-0.5, E, E+0.5: each step must be 1 ms (RTT) within tol."""
    steps = [round(b - a, 3) for a, b in zip(means, means[1:])]
    ok = len(steps) == 2 and all(abs(s - 1.0) <= tol for s in steps)
    return {"steps_ms": steps, "expected_step_ms": 1.0, "tolerance_ms": tol, "verdict": "PASS" if ok else "FAIL"}


def plan(scenarios: dict, sids: list[str]) -> list[tuple[str, str, list[str]]]:
    base = scenarios["_baseline"]
    lab = o.load_lab_env()
    steps = []
    for sid in sids:
        sc = scenarios[sid]
        e = sc["v6"]["delay_ms_each_way"]
        steps.append((sid, "apply v4", o.netem_for("v4", sc["v4"])))
        for d in (e - 0.5, e, e + 0.5):
            steps += [(sid, f"set v6 {d:g}", o.cmd_netem("v6", d, 0)), (sid, "ping", ping_cmd(lab))]
        t = sc["verify_target"]
        steps += [(sid, "apply v6", o.netem_for("v6", sc["v6"])), (sid, "verify", o.cmd_verify(t["v4"], t["v6"]))]
    steps += [("baseline", "restore", o.cmd_netem(f, base["delay_ms_each_way"], 0)) for f in ("v4", "v6")]
    steps.append(("baseline", "verify", o.cmd_verify(base["rtt_ms"], base["rtt_ms"])))
    return steps


def check_ids(scenarios: dict, sids: list[str]) -> None:
    for sid in sids:
        e = scenarios[sid]["v6"]["delay_ms_each_way"]
        if float(e).is_integer() or scenarios[sid]["v4"]["delay_ms_each_way"] != scenarios["_baseline"]["delay_ms_each_way"]:
            raise o.OrchestratorError(f"{sid}: not an odd-N IPv6 delay scenario (each way {e} ms)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", nargs="+", default=list(DEFAULT_SCENARIOS))
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    try:
        scenarios = o.load_scenarios(a.scenario, client="curl")
        check_ids(scenarios, a.scenario)
        user, uid, gid = o.check_environment(a.dry_run)
    except o.OrchestratorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    steps = plan(scenarios, a.scenario)
    if a.dry_run:
        print(f"DRY RUN: fractional-delay check, {len(a.scenario)} scenario(s) "
              f"({', '.join(a.scenario)}): 3 x {PINGS} pings at {INTERVAL_S} s plus the scenario's verify each; "
              "nothing is executed.")
        for sid, step, cmd in steps:
            print(f"  {sid:9} {step:13} {shlex.join(cmd)}")
        return 0

    env, removed = child_env_with_removed()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lab_dir = REPO / "data" / "generated" / "lab"
    lab_dir.mkdir(parents=True, exist_ok=True)
    log_path, out_path = lab_dir / f"{stamp}_fractional_delay.log", lab_dir / f"{stamp}_fractional_delay.json"
    ctx = o.Ctx(user=user, uid=uid, gid=gid, lab=o.load_lab_env(), session_id=stamp, env=env, env_removed=removed)
    ctx.created += [log_path, out_path]
    log = o.RunLog(log_path)
    log.write(f"fractional-delay check {stamp}, code {o.git_commit()}, child_env: {describe(removed)}")
    base = scenarios["_baseline"]
    result = {"check": stamp, "code_version": o.git_commit(), "pings": PINGS, "interval_s": float(INTERVAL_S),
              "scenarios": {}, "restore": None}
    status, p = 0, None
    try:
        for sid in a.scenario:
            sc = scenarios[sid]
            e = sc["v6"]["delay_ms_each_way"]
            entry = {"each_way_ms": e, "rtt_target_ms": sc["verify_target"]["v6"], "settings": []}
            o.sh(ctx, o.netem_for("v4", sc["v4"]), log)
            for d in (e - 0.5, e, e + 0.5):
                o.sh(ctx, o.cmd_netem("v6", d, 0), log)
                qd = o.sh(ctx, ["tc", "-n", ctx.lab["NS_SERVER"], "qdisc", "show", "dev", ctx.lab["V6_IF_S"]], log,
                          check=False).stdout.strip()
                pp = o.sh(ctx, ping_cmd(ctx.lab), log, check=False, timeout=60)
                ts = ping_times(pp.stdout)
                entry["settings"].append({"each_way_ms": d, "tc_readback (config, not evidence)": qd,
                                          "replies": len(ts), "sent": PINGS,
                                          "mean_ms": round(statistics.mean(ts), 3) if ts else None,
                                          "median_ms": statistics.median(ts) if ts else None,
                                          "min_ms": min(ts) if ts else None, "max_ms": max(ts) if ts else None})
                print(f"{sid} each way {d:g} ms: {len(ts)}/{PINGS} replies, mean {entry['settings'][-1]['mean_ms']} ms "
                      f"(ping values; whole ms above 100 ms)", flush=True)
            means = [s["mean_ms"] for s in entry["settings"]]
            complete = all(m is not None for m in means) and all(s["replies"] == PINGS for s in entry["settings"])
            entry["differential"] = steps_verdict(means) if complete else {"verdict": "FAIL", "reason": "lost pings"}
            t = sc["verify_target"]
            o.sh(ctx, o.netem_for("v6", sc["v6"]), log)
            pv = o.sh(ctx, o.cmd_verify(t["v4"], t["v6"]), log, check=False)
            entry["verify"] = {"exit": pv.returncode,
                               "verify_observed": o.verify_observed(o.parse_verify_rtt(pv.stdout), {"v4": t["v4"], "v6": t["v6"]})}
            entry["passed"] = entry["differential"]["verdict"] == "PASS" and pv.returncode == 0
            result["scenarios"][sid] = entry
            print(f"== {sid}: steps {entry['differential'].get('steps_ms')} ms (expect 1.0 +/- {STEP_TOL_MS}) "
                  f"{entry['differential']['verdict']}; scenario verify exit {pv.returncode} "
                  f"-> {'PASS' if entry['passed'] else 'FAIL'}", flush=True)
    except (o.OrchestratorError, KeyboardInterrupt) as exc:
        print(f"STOPPED: {exc or 'interrupted'}", file=sys.stderr)
        log.write(f"STOPPED: {exc or 'interrupted'}")
        status = 1
    finally:
        for fam in ("v4", "v6"):
            o.sh(ctx, o.cmd_netem(fam, base["delay_ms_each_way"], 0), log, check=False)
        p = o.sh(ctx, o.cmd_verify(base["rtt_ms"], base["rtt_ms"]), log, check=False)
        result["restore"] = {"exit": p.returncode}
        print(f"RESTORE baseline: verify exit {p.returncode} ({'PASS' if p.returncode == 0 else 'FAIL: check the lab'})")
        out_path.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        for path in ctx.created:
            ctx.chown(path)
        print(f"wrote {out_path.relative_to(REPO)} and {log_path.relative_to(REPO)}")
    if p is not None and p.returncode != 0:
        status = 1
    if status == 0 and not all(e["passed"] for e in result["scenarios"].values()):
        status = 3
    return status


if __name__ == "__main__":
    sys.exit(main())
