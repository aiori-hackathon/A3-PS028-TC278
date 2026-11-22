"""Crossover reports for the latency sweep and the curl@he sweep, from the packet captures. Read-only.

    .venv/bin/python src/analysis/crossover.py --dataset latency-sweep [--json]
    .venv/bin/python src/analysis/crossover.py --dataset he-sweep [--json]

Both use two packet-level quantities per run:
  - the outcome: which family completed the winning handshake;
  - t_v4_synack: time from the run's first SYN to the first SYN-ACK of its IPv4 attempt, if one
    appears. That is when the IPv4 handshake could complete (packet times; T is their median).

latency sweep (`Gv6d<N>` cells): per client, the cells in order of their measured IPv6 RTT
  (median of the per-run verify-ping medians; ICMP, derived), each with IPv6 wins k/n. The outcome
  flip is bracketed by the highest RTT at which IPv6 won every run and the lowest at which IPv4 won
  every run; cells with mixed outcomes lie between and are listed. The bracket uses no packet
  times, so it is an independent check of T, the median t_v4_synack over the client's runs in
  this dataset that have an IPv4 SYN-ACK. They agree when T lies inside the bracket.

he sweep (curl and curl@he<N> on C0, S1, S3): per client label, T from the S1 runs (IPv6
  blackholed, so every run has an IPv4 attempt), the second family's first SYN after the first
  (packet-level), and the IPv4 handshake time (IPv4 SYN to its SYN-ACK). Prediction to compare
  against: T ~ timeout + IPv4 handshake time, as plain curl's T came out at 222.0 ms in jitter-loss.
  S3 runs are reported separately; T there appears only when an IPv4 attempt was made.

What this says: which family won and when each SYN and SYN-ACK was seen. It does not say how curl
or Chromium decide when to start an attempt, or that either implements any particular algorithm.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.names import parse_client  # noqa: E402
from analysis.parse_pcap import parse  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
HTTP_PORT = 80


def _val(field: dict):
    return field.get("value") if field.get("status") == "computed" else None


def _attempts(rec: dict, repo: Path):
    """The run's port-80 attempts in its window (client start to capture end), first SYN first."""
    ts = rec["timestamps"]
    tl = parse(repo / rec["evidence"]["pcap_path"], (ts["client_start_epoch_ns"], ts["capture_end_epoch_ns"]))
    return sorted((a for a in tl.attempts if a.dport == HTTP_PORT), key=lambda a: a.first_syn_ns)


def run_times(rec: dict, repo: Path = REPO) -> dict:
    """Packet times for one run (ms after the run's first SYN); None where not seen."""
    atts = _attempts(rec, repo)
    out = {"winner": _val(rec["packet_observations"]["winning_family"]), "t_v4_syn": None,
           "t_v4_synack": None, "v4_handshake_ms": None}
    if not atts:
        return out
    t0 = atts[0].first_syn_ns
    v4 = [a for a in atts if a.family == "v4"]
    if v4:
        out["t_v4_syn"] = round((v4[0].first_syn_ns - t0) / 1e6, 3)
        if v4[0].synack_times_ns:
            out["t_v4_synack"] = round((v4[0].synack_times_ns[0] - t0) / 1e6, 3)
            out["v4_handshake_ms"] = round((v4[0].synack_times_ns[0] - v4[0].first_syn_ns) / 1e6, 3)
    return out


def _median(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 3) if xs else None


def flip_bracket(cells: list[dict]) -> dict:
    """cells: [{rtt_ms, n, v6_wins}]. IPv6 won every run at or below 'above_ms'; IPv4 every run from 'below_ms'."""
    all6 = [c["rtt_ms"] for c in cells if c["v6_wins"] == c["n"]]
    all4 = [c["rtt_ms"] for c in cells if c["v6_wins"] == 0]
    above = max(all6) if all6 else None
    below = min((r for r in all4 if above is None or r > above), default=None)
    mixed = [c["rtt_ms"] for c in cells if 0 < c["v6_wins"] < c["n"]]
    out_of_order = [r for r in all6 if below is not None and r > below] + [r for r in all4 if above is not None and r < above]
    return {"above_ms": above, "below_ms": below, "width_ms": (below - above) if above is not None and below is not None else None,
            "mixed_rtts_ms": sorted(mixed), "non_monotonic_rtts_ms": sorted(out_of_order)}


def latency_sweep(records: dict[tuple[str, str], list[dict]], repo: Path = REPO) -> list[dict]:
    out = []
    for client in sorted({c for c, _ in records}):
        cells, t_all = [], []
        for (c, sid), recs in sorted(records.items()):
            if c != client or not sid.startswith("Gv6d"):
                continue
            rtt = statistics.median(r["scenario"]["verify_observed"]["v6"]["observed"]["median_ms"] for r in recs)
            times = [run_times(r, repo) for r in recs]
            k = sum(1 for t in times if t["winner"] == "v6")
            t_all += [t["t_v4_synack"] for t in times if t["t_v4_synack"] is not None]
            cells.append({"scenario": sid, "rtt_ms": rtt, "n": len(recs), "v6_wins": k,
                          "t_v4_synack_median_ms": _median(t["t_v4_synack"] for t in times)})
        cells.sort(key=lambda c: c["rtt_ms"])
        b = flip_bracket(cells)
        t = _median(t_all)
        out.append({"client": client, "cells": cells, "flip_bracket": b, "T_ms": t, "T_runs": len(t_all),
                    "T_inside_bracket": (t is not None and (b["above_ms"] is None or t > b["above_ms"])
                                         and (b["below_ms"] is None or t < b["below_ms"]))})
    return out


def he_sweep(records: dict[tuple[str, str], list[dict]], repo: Path = REPO) -> list[dict]:
    out = []
    for client in sorted({c for c, _ in records}, key=lambda c: (parse_client(c).he_timeout_ms or 0, c)):
        row = {"client": client, "timeout_ms": parse_client(client).he_timeout_ms}
        for sid in ("S1", "S3"):
            recs = records.get((client, sid), [])
            times = [run_times(r, repo) for r in recs]
            row[sid] = {"n": len(recs), "v6_wins": sum(1 for t in times if t["winner"] == "v6"),
                        "v4_wins": sum(1 for t in times if t["winner"] == "v4"),
                        "runs_with_v4_synack": sum(1 for t in times if t["t_v4_synack"] is not None),
                        "T_ms": _median(t["t_v4_synack"] for t in times),
                        "v4_first_syn_ms": _median(t["t_v4_syn"] for t in times),
                        "v4_handshake_ms": _median(t["v4_handshake_ms"] for t in times)}
        s1 = row["S1"]
        if row["timeout_ms"] is not None and s1["v4_handshake_ms"] is not None:
            row["predicted_T_ms"] = round(row["timeout_ms"] + s1["v4_handshake_ms"], 3)
            row["T_minus_predicted_ms"] = (round(s1["T_ms"] - row["predicted_T_ms"], 3) if s1["T_ms"] is not None else None)
        else:
            row["predicted_T_ms"] = row["T_minus_predicted_ms"] = None
        out.append(row)
    return out


def report_latency(rows: list[dict]) -> str:
    out = ["[packet-level outcomes; RTT from the verify pings, derived] latency sweep", ""]
    for r in rows:
        b = r["flip_bracket"]
        out.append(f"== {r['client']}")
        out += [f"  {c['scenario']:8} RTT {c['rtt_ms']:7g} ms  IPv6 won {c['v6_wins']}/{c['n']}"
                f"  (IPv4 SYN-ACK median {c['t_v4_synack_median_ms']} ms)" for c in r["cells"]]
        lo = f"{b['above_ms']:g}" if b["above_ms"] is not None else "-"
        hi = f"{b['below_ms']:g}" if b["below_ms"] is not None else "-"
        out.append(f"  outcome flip (no packet times): above {lo} ms, below {hi} ms"
                   + (f" (width {b['width_ms']:g} ms)" if b["width_ms"] is not None else "")
                   + (f"; mixed cells at {b['mixed_rtts_ms']}" if b["mixed_rtts_ms"] else "")
                   + (f"; NOT MONOTONIC at {b['non_monotonic_rtts_ms']}" if b["non_monotonic_rtts_ms"] else ""))
        out.append(f"  T from packets (IPv4 SYN-ACK after the first SYN, median of {r['T_runs']} runs): {r['T_ms']} ms"
                   f" -> {'inside' if r['T_inside_bracket'] else 'OUTSIDE'} the outcome bracket")
        out.append("")
    return "\n".join(out)


def report_he(rows: list[dict]) -> str:
    out = ["[packet-level times; prediction T ~ timeout + IPv4 handshake, derived] curl@he sweep", "",
           f"  {'client':12} {'timeout':>8} {'S1 T':>9} {'IPv4 SYN':>9} {'IPv4 hs':>8} {'predicted':>10} {'T - pred':>9}"
           f"   S3: IPv6/IPv4 wins, T"]
    for r in rows:
        s1, s3 = r["S1"], r["S3"]
        f = lambda x: "-" if x is None else f"{x:g}"
        out.append(f"  {r['client']:12} {('not set' if r['timeout_ms'] is None else f(r['timeout_ms'])):>8} {f(s1['T_ms']):>9} "
                   f"{f(s1['v4_first_syn_ms']):>9} {f(s1['v4_handshake_ms']):>8} {f(r['predicted_T_ms']):>10} "
                   f"{f(r['T_minus_predicted_ms']):>9}   {s3['v6_wins']}/{s3['v4_wins']} of {s3['n']}, T {f(s3['T_ms'])}")
    out += ["", "  (times in ms after the run's first SYN; 'IPv4 hs' = IPv4 SYN to its SYN-ACK. Plain curl sets no",
            "  timeout; compare it with curl@he200, the validation control.)"]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    from analysis.summarise import DatasetError, load_dataset
    from analysis.syn_retransmit import load_records
    try:
        m = load_dataset(a.dataset)
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    records = load_records({sid for _, _, sid in m.sessions})
    if any(parse_client(c).variant for c in m.shape.clients):
        rows, text = he_sweep(records), report_he
    else:
        rows, text = latency_sweep(records), report_latency
    print(json.dumps(rows, indent=1) if a.json else text(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
