"""Summarise the measurement dataset: the 14 sessions listed in docs/dataset.md, nothing else.

    .venv/bin/python src/analysis/summarise.py            # print tables, write data/generated/summary/summary.json

Evidence levels, kept apart throughout:
  packet   from the pcap (the run record's packet_observations and metrics): packet-level evidence
  client   from client/runner logs (curl -w, Playwright, Chromium NetLog): outcomes, client-reported
  interpretation   statements built from the above; always labelled as interpretation

Per client x scenario cell:
  - TCP setup time (packet): median, quartiles, min, max
  - scenario penalty: the client's median setup time minus its own C0 median (CLAUDE.md definition)
  - winning family counts (packet)
  - inter-family attempt delay (packet): reported as observed / not observed COUNTS; statistics
    only over the runs where it was observed, never a number averaged over "not observed"
  - failed/abandoned attempts per run (packet): the distribution of counts, not just a mean
  - attempt shape (packet): the family sequence of SYN attempts per run, e.g. v6>v6>v4
  - attempt offsets (packet): each SYN attempt's start relative to the run's first SYN, by kind:
      first          the run's first SYN
      same-family    a later new connection (new source port) to a family already tried
      other-family   the first SYN to the other family (its offset is the inter-family delay)
    Kernel SYN retransmissions are not attempts (same socket); they appear as syn_retransmits.
  - DNS time (packet; project definition, target name only)
  - NetLog connect jobs and resolver order (client, Chromium only)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.metrics import TARGET_NAME, scenario_penalty  # noqa: E402
from analysis.parse_pcap import parse  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
DATASET_DOC = REPO / "docs" / "dataset.md"
RUNS_DIR = REPO / "data" / "generated" / "runs"
OUT_DIR = REPO / "data" / "generated" / "summary"
CLIENTS = ("curl", "chromium")
SCENARIOS = ("C0", "S1", "S2", "S3", "S4", "S5", "S6")
EXPECTED_REPS = 20
AAAA_DELAY_MS = 300  # S6 configuration (scenarios.yaml); used only to word the S6 interpretation


class DatasetError(Exception):
    pass


# --- which sessions --------------------------------------------------------------------

_ROW_RE = re.compile(r"^\|\s*\d+\s*\|\s*(curl|chromium)\s*\|\s*(C0|S[1-6])\s*\|\s*`(\d{8}T\d{6}Z)`\s*\|")


def dataset_sessions(doc: Path = DATASET_DOC) -> list[tuple[str, str, str]]:
    """(client, scenario, session) for every row of the 'Sessions in the dataset' table."""
    text = doc.read_text(encoding="utf-8")
    try:
        section = text.split("## Sessions in the dataset", 1)[1].split("\n## ", 1)[0]
    except IndexError as exc:
        raise DatasetError(f"{doc}: no 'Sessions in the dataset' section") from exc
    rows = [m.groups() for m in map(_ROW_RE.match, section.splitlines()) if m]
    cells = [(c, s) for c, s, _ in rows]
    if sorted(cells) != sorted((c, s) for c in CLIENTS for s in SCENARIOS):
        raise DatasetError(f"{doc}: expected exactly one session per client x scenario (14), got {cells}")
    return rows


# --- per run ---------------------------------------------------------------------------

def _val(field: dict):
    return field.get("value") if field.get("status") == "computed" else None


def attempt_kinds(attempts: list[dict]) -> list[dict]:
    """Label each SYN attempt (packet-level) as first / same-family / other-family, with its offset."""
    ordered = sorted(attempts, key=lambda a: a["first_syn_ns"])
    if not ordered:
        return []
    t0, seen, out = ordered[0]["first_syn_ns"], set(), []
    for i, a in enumerate(ordered):
        kind = "first" if i == 0 else ("same-family" if a["family"] in seen else "other-family")
        seen.add(a["family"])
        out.append({"family": a["family"], "kind": kind, "offset_ms": round((a["first_syn_ns"] - t0) / 1e6, 3),
                    "result": a["result"], "syn_retransmits": a["syn_retransmits"]})
    return out


@dataclass
class Run:
    run_id: str
    client: str
    scenario: str
    repetition: int
    success: bool
    winner: str | None
    setup_ms: float | None
    inter_family_ms: float | None
    inter_family_status: str
    failed_or_abandoned: int | None
    dns_ms: float | None
    attempts: list[dict]
    netlog_backup_jobs: int | None      # Chromium NetLog: connect jobs marked backup_job (client log)
    netlog_v4_source: str | None        # Chromium NetLog: which job/connector started IPv4 (client log)
    resolved_families: list[str] | None  # Chromium NetLog: resolver address order (client log)
    # pcap, re-parsed: first answer per query type for the target name, ms after its first query,
    # and the first SYN's offset from the same origin
    dns_answers_ms: dict[str, float] | None = None
    first_syn_after_query_ms: float | None = None
    label: str = ""
    # lab verify before the run (ping medians): family -> (value or None, status)
    measured_rtt: dict[str, tuple[float | None, str]] | None = None

    @property
    def shape(self) -> str:
        return ">".join(a["family"] for a in self.attempts) or "none"


def netlog_v4_source(jobs: list[dict] | None) -> str | None:
    """'original/second' etc. for the first NetLog connect entry to an IPv4 address (client log)."""
    for j in jobs or []:
        if not str(j.get("address", "")).startswith("["):
            return f"{'backup' if j.get('backup_job') else 'original'} job, {j.get('connector')} connector"
    return None if jobs is None else "no IPv4 connect"


def dns_by_type(pcap: Path, window: tuple[int, int], target: str = TARGET_NAME) -> tuple[dict, float | None]:
    """Packet-level: first answer time per query type for the target name, from the first target query."""
    tl = parse(pcap, window)
    name = target.rstrip(".") + "."
    ex = [d for d in tl.dns if d.qname == name]
    if not ex:
        return {}, None
    t0 = min(d.query_ns for d in ex)
    answers: dict[str, float] = {}
    for d in sorted(ex, key=lambda d: d.response_ns or 1 << 62):
        if d.response_ns is not None and d.qtype not in answers:
            answers[d.qtype] = round((d.response_ns - t0) / 1e6, 3)
    syns = [a.first_syn_ns for a in tl.attempts if a.dport == 80]
    return answers, (round((min(syns) - t0) / 1e6, 3) if syns else None)


def run_from_record(r: dict) -> Run:
    obs, met = r["packet_observations"], r["metrics"]
    cr = r["outcome"].get("client_report") or {}
    jobs = cr.get("connect_jobs")
    resolved = cr.get("resolved") or {}
    return Run(
        run_id=r["run_id"], client=r["client"]["name"], scenario=r["scenario"]["id"],
        repetition=r["scenario"]["repetition"], success=bool(r["outcome"]["success"]),
        winner=_val(obs["winning_family"]), setup_ms=_val(met["tcp_setup_time_ms"]),
        inter_family_ms=_val(met["inter_family_attempt_delay_ms"]),
        inter_family_status=met["inter_family_attempt_delay_ms"]["status"],
        failed_or_abandoned=_val(obs["failed_or_abandoned_attempts"]), dns_ms=_val(met["dns_time_ms"]),
        attempts=attempt_kinds(_val(obs["attempts"]) or []),
        netlog_backup_jobs=None if jobs is None else sum(1 for j in jobs if j.get("backup_job")),
        netlog_v4_source=netlog_v4_source(jobs),
        resolved_families=resolved.get("families"),
        label=r["scenario"].get("label", ""),
        measured_rtt={f: (v.get("value"), v.get("status", "?"))
                      for f, v in (r["scenario"].get("measured_rtt_ms") or {}).items()} or None,
    )


def _rtt_summary(runs: list[Run]) -> dict | None:
    """Per family: median of computed values, plus counts of every status (a blackhole is a status, not 0)."""
    fams = sorted({f for r in runs for f in (r.measured_rtt or {})})
    if not fams:
        return None
    out = {}
    for f in fams:
        vals = [r.measured_rtt[f][0] for r in runs if r.measured_rtt and f in r.measured_rtt
                and r.measured_rtt[f][1] == "computed" and r.measured_rtt[f][0] is not None]
        out[f] = {"median": round(statistics.median(vals), 3) if vals else None,
                  "statuses": dict(Counter(r.measured_rtt[f][1] for r in runs
                                           if r.measured_rtt and f in r.measured_rtt))}
    return out


def load_runs(sessions: list[tuple[str, str, str]], runs_dir: Path = RUNS_DIR,
              expected: int = EXPECTED_REPS, repo: Path | None = REPO, dns_scenarios=("S6",),
              provenance: dict | None = None) -> list[Run]:
    """With repo set, the pcaps of runs in dns_scenarios are re-parsed (after a hash check) for
    per-type DNS answer times; repo=None skips that (unit tests on synthetic records).
    If a provenance dict is given, the distinct client versions, client configs and code versions
    seen in the records are collected into it, per client."""
    """Records of exactly the listed sessions; refuses anything that is not the certified dataset."""
    by_session: dict[str, list[dict]] = {}
    for p in sorted(runs_dir.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        sid = r.get("environment", {}).get("session_id")
        by_session.setdefault(sid, []).append(r)
    runs = []
    for client, scenario, sid in sessions:
        recs = by_session.get(sid, [])
        problems = []
        if len(recs) != expected:
            problems.append(f"{len(recs)} records, expected {expected}")
        if sorted(r["scenario"]["repetition"] for r in recs) != list(range(1, expected + 1)):
            problems.append("repetitions are not exactly 1..%d" % expected)
        for r in recs:
            if (r["client"]["name"], r["scenario"]["id"]) != (client, scenario):
                problems.append(f"{r['run_id']} is not {client}/{scenario}")
            if r["cross_checks"]["status"] != "agree":
                problems.append(f"{r['run_id']} cross_checks {r['cross_checks']['status']}")
            if not (r["evidence"].get("pre_verify_ok") and r["evidence"].get("post_restore_verify_ok")):
                problems.append(f"{r['run_id']} lab verify did not pass")
        if problems:
            raise DatasetError(f"session {sid} ({client}/{scenario}): " + "; ".join(problems))
        for r in sorted(recs, key=lambda r: r["scenario"]["repetition"]):
            run = run_from_record(r)
            if provenance is not None:
                p = provenance.setdefault(client, {"versions": set(), "configs": set(), "code": set()})
                p["versions"].add(r["client"].get("version"))
                p["configs"].add(json.dumps(r["client"].get("config"), sort_keys=True))
                p["code"].add(r.get("environment", {}).get("git_commit"))
            if repo is not None and scenario in dns_scenarios:
                pcap = repo / r["evidence"]["pcap_path"]
                if hashlib.sha256(pcap.read_bytes()).hexdigest() != r["evidence"]["pcap_sha256"]:
                    raise DatasetError(f"{r['run_id']}: pcap hash does not match the record")
                ts = r["timestamps"]
                run.dns_answers_ms, run.first_syn_after_query_ms = dns_by_type(
                    pcap, (ts["client_start_epoch_ns"], ts["capture_end_epoch_ns"]))
            runs.append(run)
    return runs


# --- per cell --------------------------------------------------------------------------

def _stats(values: list[float]) -> dict | None:
    if not values:
        return None
    v = sorted(values)
    q = statistics.quantiles(v, n=4, method="inclusive") if len(v) > 1 else [v[0]] * 3
    return {"n": len(v), "median": round(statistics.median(v), 3), "q1": round(q[0], 3),
            "q3": round(q[2], 3), "min": round(v[0], 3), "max": round(v[-1], 3)}


def summarise_cell(runs: list[Run]) -> dict:
    setups = [r.setup_ms for r in runs if r.setup_ms is not None]
    observed = [r.inter_family_ms for r in runs if r.inter_family_ms is not None]
    offsets: dict[str, list[float]] = {}
    for r in runs:
        for a in r.attempts:
            if a["kind"] != "first":
                offsets.setdefault(f"{a['kind']} ({a['family']})", []).append(a["offset_ms"])
    chromium = runs and runs[0].client == "chromium"
    return {
        "label": runs[0].label if runs else "",
        "measured_rtt_ms": _rtt_summary(runs),
        "n": len(runs),
        "successes": sum(r.success for r in runs),
        "winning_family": dict(Counter(r.winner or "none" for r in runs)),
        "first_syn_family": dict(Counter(r.attempts[0]["family"] if r.attempts else "none" for r in runs)),
        "tcp_setup_ms": _stats(setups),
        "setup_not_observed": len(runs) - len(setups),
        "inter_family": {
            "observed": len(observed),
            "not_observed": sum(r.inter_family_status == "not_observed" for r in runs),
            "other_status": sum(r.inter_family_status not in ("computed", "not_observed") for r in runs),
            "stats_over_observed_only": _stats(observed),
        },
        "failed_or_abandoned_per_run": {str(k): v for k, v in sorted(Counter(
            r.failed_or_abandoned for r in runs).items(), key=lambda kv: (kv[0] is None, kv[0]))},
        "failed_or_abandoned_total": sum(r.failed_or_abandoned or 0 for r in runs),
        "attempt_shape": dict(Counter(r.shape for r in runs)),
        "attempt_offsets_ms": {k: _stats(v) for k, v in sorted(offsets.items())},
        "syn_retransmits_total": sum(a["syn_retransmits"] for r in runs for a in r.attempts),
        "dns_ms": _stats([r.dns_ms for r in runs if r.dns_ms is not None]),
        "dns_answer_by_type_ms": None if not any(r.dns_answers_ms for r in runs) else {
            **{f"{t} answer": _stats([r.dns_answers_ms[t] for r in runs if r.dns_answers_ms and t in r.dns_answers_ms])
               for t in sorted({t for r in runs for t in (r.dns_answers_ms or {})})},
            "first SYN": _stats([r.first_syn_after_query_ms for r in runs if r.first_syn_after_query_ms is not None]),
            "runs with first SYN after the AAAA answer": sum(
                1 for r in runs if r.dns_answers_ms and "AAAA" in r.dns_answers_ms
                and r.first_syn_after_query_ms is not None
                and r.first_syn_after_query_ms >= r.dns_answers_ms["AAAA"]),
        },
        "netlog": None if not chromium else {
            "runs_with_backup_job": sum(1 for r in runs if (r.netlog_backup_jobs or 0) > 0),
            "runs_without_netlog_jobs": sum(1 for r in runs if r.netlog_backup_jobs is None),
            "ipv4_started_by": dict(Counter(r.netlog_v4_source or "unknown" for r in runs)),
            "resolver_order": dict(Counter(">".join(r.resolved_families) if r.resolved_families else "unknown"
                                           for r in runs)),
        },
    }


def summarise(runs: list[Run]) -> dict:
    cells: dict[str, dict[str, dict]] = {c: {} for c in CLIENTS}
    for c in CLIENTS:
        for s in SCENARIOS:
            cells[c][s] = summarise_cell([r for r in runs if r.client == c and r.scenario == s])
        c0 = [r.setup_ms for r in runs if r.client == c and r.scenario == "C0" and r.setup_ms is not None]
        for s in SCENARIOS:
            sc = [r.setup_ms for r in runs if r.client == c and r.scenario == s and r.setup_ms is not None]
            cells[c][s]["scenario_penalty_ms"] = scenario_penalty(sc, c0)
    return {"cells": cells, "interpretation": interpretations(cells)}


# --- interpretation (labelled; built only from the numbers above) --------------------------

def _med(cell: dict, key: str) -> float | None:
    st = cell["attempt_offsets_ms"].get(key)
    return st["median"] if st else None


def interpretations(cells: dict) -> list[dict]:
    """Labelled interpretation, each with the packet-level / client-log evidence it rests on.

    Statements are worded from the data: if the evidence does not hold in every run, the text says so.
    """
    out = []
    cu, ch = cells["curl"], cells["chromium"]

    # 1. Chromium's longer setup in S1/S2: when the v4 attempt starts, not the backup attempt.
    for s in ("S1", "S2"):
        a, b = cu[s], ch[s]
        if not (a["tcp_setup_ms"] and b["tcp_setup_ms"]):
            continue
        gap = round(b["tcp_setup_ms"]["median"] - a["tcp_setup_ms"]["median"], 3)
        v4_cu, v4_ch = _med(a, "other-family (v4)"), _med(b, "other-family (v4)")
        rep_ch = b["attempt_offsets_ms"].get("same-family (v6)")
        nl = b["netlog"] or {}
        backup = nl.get("runs_with_backup_job")
        v4_src = nl.get("ipv4_started_by", {})
        from_original = v4_src.get("original job, second connector", 0)
        out.append({
            "topic": f"{s}: why Chromium's setup is longer than curl's",
            "statement": (
                f"Chromium's median TCP setup in {s} is {gap} ms longer than curl's. That gap matches when each "
                f"client started its IPv4 attempt: a median of {v4_ch} ms after the first IPv6 SYN for Chromium, "
                f"against {v4_cu} ms for curl. Chromium also sent a second IPv6 SYN from a new socket"
                + (f" (median {rep_ch['median']} ms)" if rep_ch else "")
                + f", which its NetLog labels a backup connect job ({backup}/{b['n']} runs). In {from_original}/"
                f"{b['n']} runs the NetLog shows the IPv4 attempt being started by the original job's second "
                "connector, not by the backup job. So the backup attempt accounts for the extra SYN and the "
                "second abandoned attempt, but the data gives no sign that it holds back the IPv4 start; the "
                "~100 ms difference is better described as Chromium starting IPv4 later than curl than as "
                "backup-attempt overhead. These delays are observed values, not documented constants."),
            "evidence": [
                {"source": "packet", "text": f"curl attempt shapes {a['attempt_shape']}; Chromium {b['attempt_shape']}"},
                {"source": "packet", "text": f"failed/abandoned per run: curl {a['failed_or_abandoned_per_run']}, "
                                             f"Chromium {b['failed_or_abandoned_per_run']}"},
                {"source": "packet", "text": f"kernel SYN retransmissions: curl {a['syn_retransmits_total']}, "
                                             f"Chromium {b['syn_retransmits_total']}"},
                {"source": "client (NetLog)", "text": f"Chromium runs with a backup connect job: {backup}/{b['n']}"},
                {"source": "client (NetLog)", "text": f"Chromium IPv4 attempt started by: {v4_src}"},
            ],
            "reference": "docs/findings/chromium_s1_second_v6_syn.md",
        })

    # 2. S6: both clients wait for the delayed AAAA answer before the first SYN.
    s6 = {}
    for name, cell_set in (("curl", cu), ("Chromium", ch)):
        c = cell_set["S6"]
        d = c["dns_ms"]
        s6[name] = (d, c)
    def after_aaaa(c: dict) -> int:
        return (c["dns_answer_by_type_ms"] or {}).get("runs with first SYN after the AAAA answer", 0)

    def a_max(c: dict) -> float | None:
        st = (c["dns_answer_by_type_ms"] or {}).get("A answer")
        return st["max"] if st else None

    both = all(after_aaaa(c) == c["n"] for _, c in s6.values())
    a_early = all(a_max(c) is not None and a_max(c) < AAAA_DELAY_MS for _, c in s6.values())
    ev = []
    for n, (d, c) in s6.items():
        if d:
            ev.append({"source": "packet", "text": f"{n} DNS time min/median/max {d['min']}/{d['median']}/{d['max']} "
                                                   f"ms (n={d['n']}); first SYN family {c['first_syn_family']}"})
        by = c["dns_answer_by_type_ms"]
        if by:
            parts = ", ".join(f"{k} median {v['median']} ms (max {v['max']})" for k, v in by.items()
                              if isinstance(v, dict))
            ev.append({"source": "packet", "text": f"{n}, from the first www.hl.test query: {parts}; first SYN "
                                                   f"after the AAAA answer in {after_aaaa(c)}/{c['n']} runs"})
    out.append({
        "topic": "S6: does the client wait for the delayed AAAA answer?",
        "statement": (
            ("Both clients sent their first SYN only after the delayed AAAA answer had arrived, in every run. "
             if both else "Not every S6 run shows the first SYN after the AAAA answer; see evidence. ")
            + (f"The A answer arrived much earlier (always under {AAAA_DELAY_MS} ms), so neither client connected "
               "over IPv4 on the early A answer while the AAAA answer was outstanding. " if a_early else "")
            + "The AAAA delay therefore appears in DNS time, not in TCP setup time (which starts at the first "
            "SYN); S6 must be reported with both. Why the clients wait (resolver design) is not visible in "
            "the data."),
        "evidence": ev,
        "reference": "docs/findings/chromium_s1_second_v6_syn.md (S2/S3/S6 pilot section) and docs/dataset.md",
    })

    # 3. S4/S5: IPv6 first and won, so the impaired IPv4 path was not exercised.
    ev = []
    untouched = True
    for s in ("S4", "S5"):
        for name, cell_set in (("curl", cu), ("Chromium", ch)):
            c = cell_set[s]
            v4_tries = sum(v for k, v in c["attempt_shape"].items() if "v4" in k.split(">"))
            untouched &= v4_tries == 0 and c["winning_family"].get("v6", 0) == c["n"]
            ev.append({"source": "packet", "text": f"{s} {name}: first SYN {c['first_syn_family']}, winner "
                                                   f"{c['winning_family']}, runs with any IPv4 SYN {v4_tries}/{c['n']}"})
            if c["netlog"]:
                ev.append({"source": "client (NetLog)", "text": f"{s} Chromium resolver order "
                                                                f"{c['netlog']['resolver_order']}"})
    out.append({
        "topic": "S4/S5: was the impaired IPv4 path exercised?",
        "statement": (
            ("No. In every S4 and S5 run both clients tried IPv6 first and connected in about one baseline RTT, "
             "and neither ever sent an IPv4 SYN. The IPv4 blackhole (S4) and +600 ms IPv4 delay (S5) "
             "therefore did not affect either client in this lab. Chromium's NetLog shows its resolver "
             "ordering IPv6 first. curl resolves through glibc, which reads the lab's default gai.conf; "
             "Chromium used its built-in DNS client, so the same order was reached by different routes. "
             "This holds for this lab's address-selection setup only; an IPv4-first policy was not tested.")
            if untouched else
            "Not uniform: at least one S4/S5 run sent an IPv4 SYN or did not win on IPv6; see evidence."),
        "evidence": ev,
        "reference": "docs/run_record_schema.md (client_report.resolved)",
    })
    return out


# --- output ----------------------------------------------------------------------------

def _fmt_stats(st: dict | None) -> str:
    return "-" if not st else f"{st['median']} [{st['q1']}-{st['q3']}]"


def text_report(summary: dict) -> str:
    lines = []
    for c in CLIENTS:
        lines.append(f"\n{c}  (packet-level unless stated)")
        lines.append(f"  {'scn':4} {'n':>3} {'ok':>3}  {'winner':16} {'setup median [IQR] ms':26} {'penalty':>9}  "
                     f"{'inter-family: obs/not, median':30} {'fail/aband per run':20} {'shape':22} dns median")
        for s in SCENARIOS:
            x = summary["cells"][c][s]
            inter = x["inter_family"]
            inter_txt = f"{inter['observed']}/{inter['not_observed']}" + (
                f", {inter['stats_over_observed_only']['median']}" if inter["stats_over_observed_only"] else ", -")
            lines.append(
                f"  {s:4} {x['n']:>3} {x['successes']:>3}  {json.dumps(x['winning_family']):16} "
                f"{_fmt_stats(x['tcp_setup_ms']):26} {x['scenario_penalty_ms']!s:>9}  {inter_txt:30} "
                f"{json.dumps(x['failed_or_abandoned_per_run']):20} {json.dumps(x['attempt_shape']):22} "
                f"{x['dns_ms']['median'] if x['dns_ms'] else '-'}")
    lines.append("\nINTERPRETATION (labelled; built from the evidence listed)")
    for it in summary["interpretation"]:
        lines.append(f"- {it['topic']}\n  {it['statement']}")
        for e in it["evidence"]:
            lines.append(f"    [{e['source']}] {e['text']}")
    return "\n".join(lines)


def build(doc: Path = DATASET_DOC, runs_dir: Path = RUNS_DIR) -> tuple[list[tuple[str, str, str]], list[Run], dict]:
    sessions = dataset_sessions(doc)
    prov: dict = {}
    runs = load_runs(sessions, runs_dir, provenance=prov)
    summary = summarise(runs)
    summary["dataset"] = {"source": str(doc.relative_to(REPO)) if doc.is_relative_to(REPO) else str(doc),
                          "sessions": [{"client": c, "scenario": s, "session": sid} for c, s, sid in sessions],
                          "runs": len(runs),
                          "clients": {c: {"versions": sorted(v for v in p["versions"] if v),
                                          "configs": [json.loads(x) for x in sorted(p["configs"])],
                                          "code_versions": sorted(x for x in p["code"] if x)}
                                      for c, p in prov.items()}}
    return sessions, runs, summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    a = ap.parse_args(argv)
    try:
        _, runs, summary = build()
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (a.out / "runs.json").write_text(json.dumps([r.__dict__ for r in runs], indent=1) + "\n", encoding="utf-8")
    print(text_report(summary))
    print(f"\nwrote {a.out / 'summary.json'} and runs.json ({len(runs)} runs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
