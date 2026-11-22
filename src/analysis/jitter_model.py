"""Jitter win-fraction model: predicted P(IPv6 wins) against the observed fraction. Read-only.

    .venv/bin/python src/analysis/jitter_model.py --dataset NAME [--json]

Model (derived; every input is measured in this lab, none is taken from a client's documentation
or source code):

    P(IPv6 wins) = Phi((T - mu) / sigma)

- T, the client's crossover time (packet-level times, derived value). It is measured in the client's
  own no-jitter delay-twin runs: the time from the run's first SYN to the first SYN-ACK of its IPv4
  attempt, median over every twin run in which that SYN-ACK appears (with its range and IQR). If the
  first IPv6 attempt's handshake takes less than T, IPv6 completes first. Separately, as a weaker
  independent check, the twins' outcomes bracket T: above the highest twin RTT that IPv6 won every
  time, below the lowest that IPv4 won every time. With two twins per client that bracket is coarse
  and may be open on one side; it corroborates the measured T and is not used by the model.
- mu and sigma: the mean and SD of the IPv6 RTT, from the verify pings before every run in the
  jitter cell (ICMP, scenario.verify_observed; derived, not from client packets). mu is the mean of
  the per-run medians, and sigma the mean of the per-run SDs. The design value J*sqrt(2) is printed
  next to sigma for comparison.

Two assumptions, both stated in the output: the first IPv6 attempt's handshake time follows the
ping RTT distribution, and only that attempt and the IPv4 attempt race. Runs that a later IPv6
attempt won (a new source port) are counted, so the model's miss is visible, not hidden.

Nothing here says how a client chooses when to start its IPv4 attempt. T is only when its IPv4
SYN-ACK arrived in these captures.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.metrics import wilson_ci  # noqa: E402
from analysis.parse_pcap import parse  # noqa: E402
from analysis.scenario_config import load_config  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
HTTP_PORT = 80
PHI = statistics.NormalDist().cdf

ASSUMPTIONS = ("the first IPv6 attempt's handshake time follows the verify-ping RTT distribution; "
               "only that attempt and the IPv4 attempt race")
PROVENANCE = ("every input is measured in this lab (T from the delay twins' packets, mu and sigma from "
              "the verify pings); none is taken from either client's documentation or source code")


def predict(t_ms: float, mu_ms: float, sigma_ms: float) -> float:
    """Phi((T - mu) / sigma)."""
    return PHI((t_ms - mu_ms) / sigma_ms)


def _val(field: dict):
    return field.get("value") if field.get("status") == "computed" else None


def _attempts(rec: dict, repo: Path):
    ts = rec["timestamps"]
    tl = parse(repo / rec["evidence"]["pcap_path"], (ts["client_start_epoch_ns"], ts["capture_end_epoch_ns"]))
    return sorted((a for a in tl.attempts if a.dport == HTTP_PORT), key=lambda a: a.first_syn_ns)


def v4_synack_ms(rec: dict, repo: Path = REPO) -> float | None:
    """Time from the run's first SYN to the first SYN-ACK of the first IPv4 attempt (None if not seen)."""
    atts = _attempts(rec, repo)
    v4 = [a for a in atts if a.family == "v4" and a.synack_times_ns]
    if not atts or not v4:
        return None
    return round((v4[0].synack_times_ns[0] - atts[0].first_syn_ns) / 1e6, 3)


def won_by_later_v6_attempt(rec: dict, repo: Path = REPO) -> bool:
    """IPv6 won, but not on the run's first IPv6 socket (a new source port)."""
    if _val(rec["packet_observations"]["winning_family"]) != "v6":
        return False
    v6 = [a for a in _attempts(rec, repo) if a.family == "v6"]
    return bool(v6) and not v6[0].handshake_completed


def twin_bracket(twins: list[dict]) -> dict:
    """From the twin cells' outcomes: T lies above lo (IPv6 won every run) and below hi (IPv4 won every run)."""
    lo = [t["rtt_ms"] for t in twins if t["v6_wins"] == t["n"]]
    hi = [t["rtt_ms"] for t in twins if t["v6_wins"] == 0]
    return {"above_ms": max(lo) if lo else None, "below_ms": min(hi) if hi else None}


def analyse(records: dict[tuple[str, str], list[dict]], config: dict, repo: Path = REPO) -> list[dict]:
    scen = config["scenarios"]
    jitter = sorted(sid for sid, sc in scen.items() if sc.get("grid", {}).get("kind") == "jitter")
    twin_of = {sid: scen[sid]["grid"]["delay_twin"] for sid in jitter}
    out = []
    for client in sorted({c for c, _ in records}):
        twins, t_runs = [], []
        for sid in sorted(set(twin_of.values())):
            recs = records.get((client, sid))
            if not recs:
                continue
            rtt = statistics.median(r["scenario"]["verify_observed"]["v6"]["observed"]["median_ms"] for r in recs)
            k = sum(1 for r in recs if _val(r["packet_observations"]["winning_family"]) == "v6")
            vals = [v for v in (v4_synack_ms(r, repo) for r in recs) if v is not None]
            t_runs += vals
            twins.append({"scenario": sid, "rtt_ms": rtt, "n": len(recs), "v6_wins": k, "v4_synack_seen": len(vals)})
        if not t_runs:
            continue
        t_ms = round(statistics.median(t_runs), 3)
        t_iqr = [round(q, 3) for q in statistics.quantiles(t_runs, n=4)[::2]] if len(t_runs) > 1 else [t_ms, t_ms]
        bracket = twin_bracket(twins)
        for sid in jitter:
            recs = records.get((client, sid))
            if not recs:
                continue
            obs = [r["scenario"]["verify_observed"]["v6"]["observed"] for r in recs]
            mu = round(statistics.mean(o["median_ms"] for o in obs), 2)
            sigma = round(statistics.mean(o["sd_ms"] for o in obs), 2)
            j = scen[sid]["grid"]["value"]
            n = len(recs)
            k = sum(1 for r in recs if _val(r["packet_observations"]["winning_family"]) == "v6")
            ci = wilson_ci(k, n)
            p = round(predict(t_ms, mu, sigma), 3)
            over_iqr = [round(predict(t, mu, sigma), 3) for t in t_iqr]
            edges = {name: (round(predict(v, mu, sigma), 3) if v is not None else None)
                     for name, v in (("at_bracket_above", bracket["above_ms"]), ("at_bracket_below", bracket["below_ms"]))}
            out.append({"client": client, "scenario": sid, "jitter_ms_each_way": j, "delay_twin": twin_of[sid],
                        "T_ms": t_ms, "T_runs": len(t_runs), "T_range_ms": [min(t_runs), max(t_runs)], "T_iqr_ms": t_iqr,
                        "twins": twins, "twin_bracket": bracket,
                        "mu_ms": mu, "sigma_ms": sigma, "sigma_design_ms": round(j * 2 ** 0.5, 1),
                        "predicted": p, "predicted_over_T_iqr": over_iqr, "predicted_at_bracket": edges,
                        "observed": {"v6_wins": k, "n": n, "fraction": round(k / n, 3), "ci": ci},
                        "predicted_inside_ci": ci["lo"] <= p <= ci["hi"],
                        "won_by_later_v6_attempt": sum(1 for r in recs if won_by_later_v6_attempt(r, repo))})
    return out


def _bracket_text(b: dict) -> str:
    lo = f"above {b['above_ms']:g} ms" if b["above_ms"] is not None else "no lower bound"
    hi = f"below {b['below_ms']:g} ms" if b["below_ms"] is not None else "no upper bound (IPv4 never won a twin)"
    return f"{lo}, {hi}"


def _in_bracket(t: float, b: dict) -> bool:
    return (b["above_ms"] is None or t > b["above_ms"]) and (b["below_ms"] is None or t < b["below_ms"])


def report(rows: list[dict]) -> str:
    out = [f"[derived] P(IPv6 wins) = Phi((T - mu) / sigma); {PROVENANCE}.", f"Assumptions: {ASSUMPTIONS}.", ""]
    for r in rows:
        o, ci, b = r["observed"], r["observed"]["ci"], r["twin_bracket"]
        twins = "; ".join(f"{t['scenario']} RTT {t['rtt_ms']:g} ms: IPv6 won {t['v6_wins']}/{t['n']}" for t in r["twins"])
        out += [f"== {r['client']} / {r['scenario']} (J={r['jitter_ms_each_way']} ms each way, twin {r['delay_twin']})",
                f"  T = {r['T_ms']} ms [packet times, derived: IPv4 SYN-ACK after the first SYN, median of "
                f"{r['T_runs']} twin runs, range {r['T_range_ms'][0]}-{r['T_range_ms'][1]}, IQR {r['T_iqr_ms'][0]}-{r['T_iqr_ms'][1]}]",
                f"  twin outcomes (packet-level): {twins}",
                f"  corroboration from twin outcomes (weaker, independent; two points only): T {_bracket_text(b)}"
                + (" -> contains the measured T" if _in_bracket(r['T_ms'], b) else " -> DOES NOT contain the measured T"),
                f"  mu = {r['mu_ms']} ms, sigma = {r['sigma_ms']} ms (design J*sqrt(2) = {r['sigma_design_ms']} ms) "
                f"[verify pings, ICMP; derived]",
                f"  predicted {r['predicted']} (over the measured T's IQR: {r['predicted_over_T_iqr'][0]}-{r['predicted_over_T_iqr'][1]})",
                f"  observed  {o['v6_wins']}/{o['n']} = {o['fraction']}, 95% Wilson CI [{ci['lo']}, {ci['hi']}] "
                f"[packet-level] -> prediction {'inside' if r['predicted_inside_ci'] else 'OUTSIDE'} the interval",
                f"  IPv6 wins on a later IPv6 attempt (outside the model): {r['won_by_later_v6_attempt']}", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    from analysis.summarise import DatasetError, load_dataset
    from analysis.syn_retransmit import load_records
    try:
        sessions = {sid for _, _, sid in load_dataset(a.dataset).sessions}
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    rows = analyse(load_records(sessions), load_config())
    if not rows:
        print("ERROR: no jitter cell with a delay twin in this dataset", file=sys.stderr)
        return 2
    print(json.dumps(rows, indent=1) if a.json else report(rows), end="" if not a.json else "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
