"""SYN retransmission timing and setup-time clusters, from the packet captures. Read-only.

    .venv/bin/python src/analysis/syn_retransmit.py --session ID [ID ...] [--json]
    .venv/bin/python src/analysis/syn_retransmit.py --dataset NAME [--json]

For each (client, scenario) cell it reports, from the pcaps only:

1. Retransmission timing (packet-level). A SYN retransmission is a further SYN on the SAME 4-tuple
   (same socket); a SYN from a new source port is a new connection attempt and is not counted here
   (docs/findings/chromium_s1_second_v6_syn.md). For every attempt, the gap from each SYN to the
   next one on that 4-tuple, by ordinal (1st retransmission, 2nd ...), and likewise for the
   server's repeated SYN-ACKs. Linux's initial retransmission timeout is 1 s (TCP_TIMEOUT_INIT,
   RFC 6298 section 2). For the client's SYNs, net.ipv4.tcp_syn_linear_timeouts (4 on this lab's
   kernel, 7.0) keeps the gap at 1 s for the first 4 retransmissions; after that the timeout doubles
   again, starting from 1 s. So the SYN reference gaps are 1000 ms for ordinals 1-5, then 2000,
   4000 ms. That sysctl does not apply to the server's SYN-ACKs, so their reference doubles:
   1000, 2000, 4000 ms. These are references, not thresholds. It is the KERNEL's timer, visible in
   packets; it is not a client decision. An attempt
   abandoned before its timer fired (the capture ends, or the socket is closed once another attempt
   has won) shows no retransmission: absence of a retransmission is censored, not evidence.
2. Setup-time clusters (packet-level values, grouping is descriptive). The run's TCP setup times
   (record metrics, first SYN to the ACK completing the winning handshake), sorted and split
   wherever two neighbours are more than CLUSTER_GAP_MS apart; each cluster's median, and the
   spacing between neighbouring cluster medians, compared with the 1000 ms reference. Whether
   clusters 1 s apart appear at all is an observation: with a healthy other family, a run can be
   won by that family before any retransmission timer fires.
3. Outcomes (packet-level: which family completed the winning handshake), over EVERY run, three
   ways: IPv6 won, IPv4 won, no winner, each with a 95% Wilson interval. A run with no winner is
   never dropped. The median setup time is over every run too, a run without one ranked above all
   observed values, so the slowest runs cannot fall out of it. A no-winner rate depends on the
   client's own time limit and is reported with that caveat (metrics.FAILURE_RATE_CAVEAT).
4. Adaptive stop: if the cell was run with --reps-adaptive, whether the rule stopped while the win
   fraction was still poorly determined (it decided on the median CI alone, or stopped at the
   maximum with the win CI wider than requested). Said out loud, never dropped.

Nothing here says what a client decided internally: only which family won and when each SYN was sent.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.metrics import FAILURE_RATE_CAVEAT, bootstrap_median_ci_ranked, wilson_ci  # noqa: E402
from analysis.names import label_of  # noqa: E402
from analysis.parse_pcap import parse  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO / "data" / "generated" / "runs"
INITIAL_RTO_MS = 1000.0     # Linux TCP_TIMEOUT_INIT (RFC 6298 2.1); reference only, not a threshold
SYN_LINEAR_TIMEOUTS = 4     # net.ipv4.tcp_syn_linear_timeouts on the lab kernel; SYN side only
CLUSTER_GAP_MS = 400.0      # neighbours further apart than this start a new cluster
HTTP_PORT = 80


def _ms(ns: int) -> float:
    return round(ns / 1e6, 3)


def gaps_ms(times_ns: list[int]) -> list[float]:
    """Gaps between successive packets (ms): [t1 - t0, t2 - t1, ...]."""
    return [_ms(b - a) for a, b in zip(times_ns, times_ns[1:])]


def attempt_rows(timeline) -> list[dict]:
    """Per attempt to port 80: family, source port, SYN and SYN-ACK times relative to the run's first SYN."""
    atts = [a for a in timeline.attempts if a.dport == HTTP_PORT]
    if not atts:
        return []
    t0 = min(a.first_syn_ns for a in atts)
    return [{"family": a.family, "sport": a.sport,
             "syn_ms": [_ms(t - t0) for t in a.syn_times_ns],
             "syn_gaps_ms": gaps_ms(a.syn_times_ns),
             "synack_ms": [_ms(t - t0) for t in a.synack_times_ns],
             "synack_gaps_ms": gaps_ms(a.synack_times_ns),
             "completed": a.handshake_completed} for a in atts]


def clusters(values: list[float], gap_ms: float = CLUSTER_GAP_MS) -> list[dict]:
    """Sorted values split where neighbours are more than gap_ms apart."""
    vs = sorted(values)
    out: list[list[float]] = []
    for v in vs:
        if out and v - out[-1][-1] <= gap_ms:
            out[-1].append(v)
        else:
            out.append([v])
    return [{"n": len(c), "median_ms": round(statistics.median(c), 3), "min_ms": c[0], "max_ms": c[-1]} for c in out]


def syn_reference_ms(k: int, linear: int = SYN_LINEAR_TIMEOUTS) -> float:
    """Reference gap before the k-th SYN retransmission: 1 s for k <= linear + 1, then doubling."""
    return INITIAL_RTO_MS * 2 ** max(0, k - linear - 1)


def synack_reference_ms(k: int) -> float:
    """Reference gap before the k-th repeated SYN-ACK: 1000 * 2^(k-1) ms (no linear phase)."""
    return INITIAL_RTO_MS * 2 ** (k - 1)


def _by_ordinal(gap_lists: list[list[float]], reference=synack_reference_ms) -> list[dict]:
    """Gap statistics by retransmission ordinal, each with its reference gap."""
    by: dict[int, list[float]] = defaultdict(list)
    for gaps in gap_lists:
        for k, g in enumerate(gaps, 1):
            by[k].append(g)
    return [{"ordinal": k, "n": len(v), "median_ms": round(statistics.median(v), 3), "min_ms": min(v),
             "max_ms": max(v), "reference_ms": reference(k)} for k, v in sorted(by.items())]


def _val(field: dict):
    return field.get("value") if field.get("status") == "computed" else None


def adaptive_note(records: list[dict]) -> str | None:
    """Flag an adaptive stop that left the IPv6 win fraction poorly determined (None if fine or not adaptive)."""
    last = max(records, key=lambda r: r["scenario"]["repetition"])
    ad = last.get("adaptive")
    if not ad:
        return None
    st = ad["after_this_run"]
    win_w = ad.get("win_ci_width")
    n = len(records)
    k = sum(1 for r in records if _val(r["packet_observations"]["winning_family"]) == "v6")
    ci = wilson_ci(k, n)
    if win_w is None and 0 < k < n:
        return (f"adaptive stop after {n} runs ({st['reason']}) decided on the median setup-time CI alone; "
                f"the IPv6 win fraction {k}/{n} is not determined by it (95% Wilson CI width {ci['width']})")
    if win_w is not None and ci["width"] > win_w:
        return (f"adaptive stop after {n} runs ({st['reason']}) with the IPv6 win fraction's 95% Wilson CI "
                f"{ci['width']} wide, above the requested {win_w}: still poorly determined")
    return None


def analyse_cell(records: list[dict], repo: Path = REPO) -> dict:
    """One (client, scenario) cell: retransmission gaps, setup-time clusters, win fraction."""
    runs, syn_gaps, synack_gaps, setups = [], [], [], []
    winners: list[str | None] = []
    for r in sorted(records, key=lambda r: r["scenario"]["repetition"]):
        ts = r["timestamps"]
        tl = parse(repo / r["evidence"]["pcap_path"], (ts["client_start_epoch_ns"], ts["capture_end_epoch_ns"]))
        rows = attempt_rows(tl)
        win = _val(r["packet_observations"]["winning_family"])
        setup = _val(r["metrics"]["tcp_setup_time_ms"])
        winners.append(win)
        if setup is not None:
            setups.append(setup)
        for a in rows:
            if a["syn_gaps_ms"]:
                syn_gaps.append(a["syn_gaps_ms"])
            if a["synack_gaps_ms"]:
                synack_gaps.append(a["synack_gaps_ms"])
        runs.append({"run_id": r["run_id"], "winning_family": win, "tcp_setup_time_ms": setup, "attempts": rows})
    cl = clusters(setups)
    spacing = [round(b["median_ms"] - a["median_ms"], 3) for a, b in zip(cl, cl[1:])]
    n = len(winners)
    k6 = sum(1 for w in winners if w == "v6")
    k4 = sum(1 for w in winners if w == "v4")
    all_runs = [rr["tcp_setup_time_ms"] for rr in runs]
    ranked = sorted(all_runs, key=lambda x: (x is None, x or 0))
    mid = ranked[(n - 1) // 2: n // 2 + 1] if n else []
    median = (None if not mid or None in mid else round(sum(mid) / len(mid), 3))
    limits = sorted({r["client"].get("config", {}).get("run_time_limit", "not recorded") for r in records})
    return {"client": label_of(records[0]["client"]),
            "scenario": records[0]["scenario"]["id"], "n_runs": n,
            "attempts_with_syn_retransmission": len(syn_gaps),
            "syn_retransmission_gaps": _by_ordinal(syn_gaps, syn_reference_ms),
            "synack_retransmission_gaps": _by_ordinal(synack_gaps, synack_reference_ms),
            "setup_clusters": cl, "cluster_spacing_ms": spacing,
            "median_all_runs_ms": median, "median_ci_all_runs": bootstrap_median_ci_ranked(all_runs),
            "runs_without_setup_time": sum(1 for x in all_runs if x is None),
            "win": {"v6": {"wins": k6, "ci": wilson_ci(k6, n)}, "v4": {"wins": k4, "ci": wilson_ci(k4, n)},
                    "none": {"wins": n - k6 - k4, "ci": wilson_ci(n - k6 - k4, n)}},
            "client_run_time_limit": limits,
            "adaptive_note": adaptive_note(records), "runs": runs}


def load_records(sessions: set[str], runs_dir: Path = RUNS_DIR) -> dict[tuple[str, str], list[dict]]:
    cells: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for p in sorted(runs_dir.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        if r.get("environment", {}).get("session_id") in sessions:
            cells[(label_of(r["client"]), r["scenario"]["id"])].append(r)
    return dict(cells)


def _fmt_gaps(rows: list[dict]) -> str:
    if not rows:
        return ("    none observed (an attempt abandoned before its timer fired shows none; whether the capture "
                "ended first or the socket was closed is not visible in packets)")
    return "\n".join(f"    #{g['ordinal']}: n={g['n']} median {g['median_ms']} ms (range {g['min_ms']}-{g['max_ms']}), "
                     f"reference {g['reference_ms']:g} ms" for g in rows)


def report(cells: list[dict]) -> str:
    out = []
    for c in cells:
        w6, w4 = c["win"]["v6"], c["win"]["v4"]
        out += [f"== {c['client']} / {c['scenario']}: {c['n_runs']} runs",
                "  [packet-level] SYN retransmissions on the same 4-tuple (gap to the previous SYN):",
                _fmt_gaps(c["syn_retransmission_gaps"]),
                "  [packet-level] repeated SYN-ACKs from the server (gap to the previous one):",
                _fmt_gaps(c["synack_retransmission_gaps"]),
                "  [packet-level values, descriptive grouping] TCP setup-time clusters "
                f"(split at gaps > {CLUSTER_GAP_MS:g} ms):"]
        out += [f"    n={k['n']} median {k['median_ms']} ms (range {k['min_ms']}-{k['max_ms']})" for k in c["setup_clusters"]]
        out.append(f"    spacing between cluster medians: {c['cluster_spacing_ms'] or 'one cluster only'} "
                   f"(reference {INITIAL_RTO_MS:g} ms)")
        if c["runs_without_setup_time"]:
            out.append(f"    ({c['runs_without_setup_time']} run(s) without a setup time are not in the clusters)")
        mci = c["median_ci_all_runs"]
        med = c["median_all_runs_ms"]
        out.append(f"  [packet-level] median TCP setup time over all {c['n_runs']} runs (no setup time ranked highest): "
                   + (f"{med} ms" if med is not None else "above every observed value")
                   + (f", 95% CI [{mci['lo']}, {mci['hi']}]" + (" unbounded" if mci["unbounded"] else "") if mci else ""))
        wn = c["win"]["none"]
        out.append("  [packet-level] outcomes over all runs (95% Wilson CI): "
                   + "; ".join(f"{name} {x['wins']}/{c['n_runs']} [{x['ci']['lo']}, {x['ci']['hi']}]"
                               for name, x in (("IPv6 won", w6), ("IPv4 won", w4), ("no winner", wn))))
        if wn["wins"]:
            out.append(f"  CAVEAT: {FAILURE_RATE_CAVEAT}. This client's limit: {'; '.join(c['client_run_time_limit'])}")
        if c["adaptive_note"]:
            out.append(f"  NOTE: {c['adaptive_note']}")
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--session", nargs="+")
    g.add_argument("--dataset")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.dataset:
        from analysis.summarise import DatasetError, load_dataset
        try:
            sessions = {sid for _, _, sid in load_dataset(a.dataset).sessions}
        except DatasetError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    else:
        sessions = set(a.session)
    cells = [analyse_cell(recs) for _, recs in sorted(load_records(sessions).items())]
    if not cells:
        print("ERROR: no run records for those sessions", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(cells, indent=1))
    else:
        print(report(cells), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
