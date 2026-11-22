"""Summarise a measurement dataset: exactly the sessions its manifest lists, nothing else.

    .venv/bin/python src/analysis/summarise.py                  # the core dataset (docs/dataset.md)
    .venv/bin/python src/analysis/summarise.py --dataset NAME   # docs/datasets/NAME.md
    .venv/bin/python src/analysis/summarise.py --cost           # measurement cost per cell

The core dataset is the 14 sessions (2 clients x C0-S6 x 20 reps) in docs/dataset.md; its output goes
to data/generated/summary/. Any other dataset is a manifest in docs/datasets/ that declares its own
shape (clients, scenarios, reps) in a YAML header, and is checked against that shape; its output goes
to data/generated/summary/NAME/. Either way an incomplete or unclean dataset is refused, including
any record whose code version (environment.git_commit) ends in -dirty, as check_batch also refuses.

Evidence levels, kept apart throughout:
  packet   from the pcap (the run record's packet_observations and metrics): packet-level evidence
  client   from client/runner logs (curl -w, Playwright, Chromium NetLog): outcomes, client-reported
  interpretation   statements built from the above; always labelled as interpretation

Per client x scenario cell:
  - TCP setup time (packet): median, quartiles, min, max, and a 95% percentile-bootstrap CI on the
    median (metrics.bootstrap_median_ci; seeded). No mean or standard deviation is reported.
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
  - oracle baseline (derived; metrics.oracle_baseline): oracle setup = the winning family's pre-run
    measured RTT (lab verify ping), cost of racing = TCP setup (packet) minus that; statistics only
    over runs where it was computed, with the other statuses counted
  - NetLog connect jobs and resolver order (client, Chromium only)
  - measurement cost (runner): runs, wall time, pcap bytes, client peak RSS where recorded.
    Records from schema 0.3 carry a profile block; for older records the wall time comes from the
    session log (wall_s=) and the pcap size from the file on disk, and the source is stated.

Adaptive datasets declare reps as {min, max, ci_width_ms} instead of a number. Each session must
then hold between min and max runs whose adaptive blocks match those settings, with "continue"
on every run but the last and "stop" on the last; the stopping rule is recomputed from the setup
times and must give the same decisions.
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

import yaml  # noqa: E402

from analysis.metrics import (FAILED_EXCLUDED, ORACLE_EVIDENCE, TARGET_NAME, adaptive_decision,  # noqa: E402
                              bootstrap_median_ci, oracle_baseline, scenario_penalty)
from analysis.names import (CLIENT_LABEL_PATTERN, InvalidName, group_by_implementation,  # noqa: E402
                            label_of, parse_client)
from analysis.parse_pcap import parse  # noqa: E402
from analysis.scenario_config import scenario_ids  # noqa: E402
from analysis.summarise_session import parse_walls  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
DATASET_DOC = REPO / "docs" / "dataset.md"          # the frozen core dataset
DATASETS_DIR = REPO / "docs" / "datasets"           # further datasets: <name>.md manifests
CORE_DATASET = "core"
RUNS_DIR = REPO / "data" / "generated" / "runs"
LAB_DIR = REPO / "data" / "generated" / "lab"        # session logs (per-run wall_s for pre-0.3 records)
OUT_DIR = REPO / "data" / "generated" / "summary"
# Shape of the frozen core dataset (docs/dataset.md has no header; this is its declared shape).
CLIENTS = ("curl", "chromium")
SCENARIOS = ("C0", "S1", "S2", "S3", "S4", "S5", "S6")
EXPECTED_REPS = 20
KNOWN_CLIENTS = CLIENTS  # the client implementations; a dataset may also list curl variants (curl@he<N>)
AAAA_DELAY_MS = 300  # S6 configuration (scenarios.yaml); used only to word the S6 interpretation


class DatasetError(Exception):
    pass


@dataclass(frozen=True)
class Shape:
    """What a dataset declares it contains: every client x every scenario, reps runs each.

    For an adaptive dataset, reps is the maximum and adaptive is (min, max, ci_width_ms).
    """
    clients: tuple[str, ...]
    scenarios: tuple[str, ...]
    reps: int
    adaptive: tuple | None = None
    absent: frozenset = frozenset()   # (client, scenario) cells the manifest declares were not run

    @property
    def cells(self) -> list[tuple[str, str]]:
        return [(c, s) for c in self.clients for s in self.scenarios if (c, s) not in self.absent]


CORE_SHAPE = Shape(CLIENTS, SCENARIOS, EXPECTED_REPS)


@dataclass(frozen=True)
class Manifest:
    path: Path
    shape: Shape
    sessions: list[tuple[str, str, str]]   # (client, scenario, session id), in table order


# --- which sessions --------------------------------------------------------------------

def _row_re() -> re.Pattern:
    """A session row: | n | client | scenario | `session` | ... (scenario IDs from scenarios.yaml)."""
    scenarios = "|".join(map(re.escape, scenario_ids()))
    return re.compile(rf"^\|\s*\d+\s*\|\s*({CLIENT_LABEL_PATTERN})\s*\|\s*({scenarios})\s*\|\s*`(\d{{8}}T\d{{6}}Z)`\s*\|")


_ROW_LIKE_RE = re.compile(r"^\|\s*\d+\s*\|")   # any numbered table row, to catch rows that do not parse
_HEADER_KEYS = {"clients", "scenarios", "reps"}
_OPTIONAL_KEYS = {"title", "description", "absent_cells"}


def _front_matter(doc: Path, text: str) -> tuple[dict | None, str]:
    """A leading '---' YAML block, if any, and the text after it."""
    if not text.startswith("---\n"):
        return None, text
    end = text.find("\n---\n", 4)
    if end < 0:
        raise DatasetError(f"{doc}: header starts with '---' but has no closing '---'")
    try:
        header = yaml.safe_load(text[4:end])
    except yaml.YAMLError as exc:
        raise DatasetError(f"{doc}: header is not valid YAML: {exc}") from exc
    if not isinstance(header, dict):
        raise DatasetError(f"{doc}: header must be a mapping with clients, scenarios and reps")
    return header, text[end + 5:]


def _shape_from_header(doc: Path, h: dict) -> Shape:
    missing = sorted(_HEADER_KEYS - set(h))
    unknown = sorted(set(h) - _HEADER_KEYS - _OPTIONAL_KEYS)
    if missing:
        raise DatasetError(f"{doc}: header is missing {', '.join(missing)}")
    if unknown:
        raise DatasetError(f"{doc}: header has unknown keys {', '.join(unknown)}")
    clients, scenarios, reps = h["clients"], h["scenarios"], h["reps"]
    for key, val in (("clients", clients), ("scenarios", scenarios)):
        if not isinstance(val, list) or not val or not all(isinstance(v, str) for v in val):
            raise DatasetError(f"{doc}: header {key} must be a non-empty list of names")
        if len(set(val)) != len(val):
            raise DatasetError(f"{doc}: header {key} lists a name twice: {val}")
    for c in clients:
        try:
            parse_client(c)
        except InvalidName as exc:
            raise DatasetError(f"{doc}: {exc}") from exc
    valid = scenario_ids()
    bad_s = [s for s in scenarios if s not in valid]
    if bad_s:
        raise DatasetError(f"{doc}: scenario(s) {bad_s} are not defined in src/config/scenarios.yaml "
                           f"(defined: {list(valid)})")
    absent = _absent_cells(doc, h.get("absent_cells", []), clients, scenarios)
    if isinstance(reps, dict):
        return Shape(tuple(clients), tuple(scenarios), *_adaptive_reps(doc, reps), absent=absent)
    if isinstance(reps, bool) or not isinstance(reps, int) or reps < 1:
        raise DatasetError(f"{doc}: header reps must be a whole number of at least 1, or "
                           f"{{min, max, ci_width_ms}} for adaptive repetitions; got {reps!r}")
    return Shape(tuple(clients), tuple(scenarios), reps, absent=absent)


def _absent_cells(doc: Path, items, clients: list[str], scenarios: list[str]) -> frozenset:
    """absent_cells: ["client:scenario", ...], cells of the declared grid deliberately not run.
    Each must name a declared client and scenario, once; every client and scenario keeps at least one cell."""
    if not isinstance(items, list) or not all(isinstance(x, str) and x.count(":") == 1 for x in items):
        raise DatasetError(f"{doc}: absent_cells must be a list of 'client:scenario' strings; got {items!r}")
    if len(set(items)) != len(items):
        raise DatasetError(f"{doc}: absent_cells lists a cell twice: {items}")
    out = set()
    for x in items:
        s, c = x.split(":")[1], x.split(":")[0]
        if c not in clients or s not in scenarios:
            raise DatasetError(f"{doc}: absent cell {x!r} is not a declared client x scenario")
        out.add((c, s))
    for c in clients:
        if all((c, s) in out for s in scenarios):
            raise DatasetError(f"{doc}: absent_cells leaves client {c} with no cell; drop it from clients")
    for s in scenarios:
        if all((c, s) in out for c in clients):
            raise DatasetError(f"{doc}: absent_cells leaves scenario {s} with no cell; drop it from scenarios")
    return frozenset(out)


def _adaptive_reps(doc: Path, reps: dict) -> tuple[int, tuple]:
    """(max, (min, max, ci_width_ms)) or, with win_ci_width, (max, (min, max, ci_width_ms, win_ci_width))."""
    if not {"min", "max", "ci_width_ms"} <= set(reps) or set(reps) - {"min", "max", "ci_width_ms", "win_ci_width"}:
        raise DatasetError(f"{doc}: adaptive reps must have min, max and ci_width_ms (and optionally "
                           f"win_ci_width); got {sorted(reps)}")
    lo, hi, w = reps["min"], reps["max"], reps["ci_width_ms"]
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (lo, hi)) or not 1 <= lo <= hi:
        raise DatasetError(f"{doc}: adaptive reps need whole numbers 1 <= min <= max; got {lo!r}, {hi!r}")
    if isinstance(w, bool) or not isinstance(w, (int, float)) or w <= 0:
        raise DatasetError(f"{doc}: adaptive ci_width_ms must be a positive number; got {w!r}")
    if "win_ci_width" in reps:
        f = reps["win_ci_width"]
        if isinstance(f, bool) or not isinstance(f, (int, float)) or not 0 < f < 1:
            raise DatasetError(f"{doc}: adaptive win_ci_width must be between 0 and 1; got {f!r}")
        return hi, (lo, hi, float(w), float(f))
    return hi, (lo, hi, float(w))


def load_manifest(doc: Path = DATASET_DOC, require_header: bool = False) -> Manifest:
    """Read a dataset manifest and check its session table against the shape it declares.

    A manifest without a header is the core dataset and has the core shape (docs/dataset.md);
    with require_header, a missing header is an error (every docs/datasets/ manifest needs one).
    """
    text = doc.read_text(encoding="utf-8")
    header, body = _front_matter(doc, text)
    if header is None:
        if require_header:
            raise DatasetError(f"{doc}: no header; a dataset manifest must declare clients, scenarios and reps")
        shape = CORE_SHAPE
    else:
        shape = _shape_from_header(doc, header)
    try:
        section = body.split("## Sessions in the dataset", 1)[1].split("\n## ", 1)[0]
    except IndexError as exc:
        raise DatasetError(f"{doc}: no 'Sessions in the dataset' section") from exc
    row_re, rows = _row_re(), []
    for line in section.splitlines():
        m = row_re.match(line)
        if m:
            rows.append(m.groups())
        elif _ROW_LIKE_RE.match(line):
            raise DatasetError(f"{doc}: cannot read session row (unknown client or scenario?): {line.strip()}")
    cells = [(c, s) for c, s, _ in rows]
    if sorted(cells) != sorted(shape.cells):
        raise DatasetError(f"{doc}: expected exactly one session per client x scenario"
                           + (" (less the absent_cells)" if shape.absent else "")
                           + f" ({len(shape.cells)}), got {cells}")
    return Manifest(doc, shape, rows)


def dataset_sessions(doc: Path = DATASET_DOC) -> list[tuple[str, str, str]]:
    """(client, scenario, session) for every row of the 'Sessions in the dataset' table."""
    return load_manifest(doc).sessions


def dataset_path(name: str = CORE_DATASET) -> Path:
    """'core' is docs/dataset.md; any other name is docs/datasets/<name>.md, which must exist."""
    if name == CORE_DATASET:
        return DATASET_DOC
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
        raise DatasetError(f"dataset name {name!r}: use lower-case letters, digits, '-' and '_'")
    path = DATASETS_DIR / f"{name}.md"
    if not path.is_file():
        raise DatasetError(f"no dataset manifest {path}")
    return path


def load_dataset(name: str = CORE_DATASET) -> Manifest:
    return load_manifest(dataset_path(name), require_header=name != CORE_DATASET)


def out_dir_for(name: str = CORE_DATASET) -> Path:
    """Core output stays where it always was; other datasets never overwrite it."""
    return OUT_DIR if name == CORE_DATASET else OUT_DIR / name


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
    # the first SYN's offset from the same origin, and the first SYN's offset from the first A answer
    dns_answers_ms: dict[str, float] | None = None
    first_syn_after_query_ms: float | None = None
    first_syn_after_a_answer_ms: float | None = None
    label: str = ""
    # lab verify before the run (ping medians): family -> (value or None, status)
    measured_rtt: dict[str, tuple[float | None, str]] | None = None
    # oracle baseline (derived): see metrics.oracle_baseline
    oracle_setup_ms: float | None = None
    cost_of_racing_ms: float | None = None
    oracle_status: str = "not_yet_computed"
    oracle_note: str | None = None
    single_family: bool | None = None
    dns_delay_ms: dict[str, float] | None = None   # configured DNS answer delay per type (scenario config)
    # measurement cost (runner): from the record's profile block, else session log / pcap on disk
    wall_s: float | None = None
    pcap_bytes: int | None = None
    peak_rss_kib: int | None = None
    cost_source: str = "not recorded"

    @property
    def shape(self) -> str:
        return ">".join(a["family"] for a in self.attempts) or "none"


def netlog_v4_source(jobs: list[dict] | None) -> str | None:
    """'original/second' etc. for the first NetLog connect entry to an IPv4 address (client log)."""
    for j in jobs or []:
        if not str(j.get("address", "")).startswith("["):
            return f"{'backup' if j.get('backup_job') else 'original'} job, {j.get('connector')} connector"
    return None if jobs is None else "no IPv4 connect"


def dns_by_type(pcap: Path, window: tuple[int, int],
                target: str = TARGET_NAME) -> tuple[dict, float | None, float | None]:
    """Packet-level: first answer time per query type for the target name, from the first target query.

    Returns (answers by type, first SYN from the same origin, first SYN minus the first A answer).
    The last is computed from the raw timestamps, so it is not a difference of rounded values.
    """
    tl = parse(pcap, window)
    name = target.rstrip(".") + "."
    ex = [d for d in tl.dns if d.qname == name]
    if not ex:
        return {}, None, None
    t0 = min(d.query_ns for d in ex)
    answers: dict[str, float] = {}
    for d in sorted(ex, key=lambda d: d.response_ns or 1 << 62):
        if d.response_ns is not None and d.qtype not in answers:
            answers[d.qtype] = round((d.response_ns - t0) / 1e6, 3)
    syns = [a.first_syn_ns for a in tl.attempts if a.dport == 80]
    a_ns = [d.response_ns for d in ex if d.qtype == "A" and d.response_ns is not None]
    after_a = round((min(syns) - min(a_ns)) / 1e6, 3) if syns and a_ns else None
    return answers, (round((min(syns) - t0) / 1e6, 3) if syns else None), after_a


def run_from_record(r: dict) -> Run:
    obs, met = r["packet_observations"], r["metrics"]
    cr = r["outcome"].get("client_report") or {}
    jobs = cr.get("connect_jobs")
    resolved = cr.get("resolved") or {}
    dns_delay = (r["scenario"].get("dns") or {}).get("delay_ms")
    run = Run(
        run_id=r["run_id"], client=label_of(r["client"]), scenario=r["scenario"]["id"],
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
        dns_delay_ms=dns_delay,
    )
    o = oracle_baseline(run.winner, run.setup_ms, r["scenario"].get("measured_rtt_ms"),
                        [a["family"] for a in run.attempts], dns_delay)
    run.oracle_setup_ms = _val(o["oracle_setup_ms"])
    run.cost_of_racing_ms = _val(o["cost_of_racing_ms"])
    # the cost's status is the run's oracle status (it is not computed whenever the oracle is not)
    run.oracle_status = o["cost_of_racing_ms"]["status"]
    run.oracle_note = o["cost_of_racing_ms"].get("note")
    run.single_family = o["single_family"]
    pr = r.get("profile")
    if pr:
        run.wall_s, run.pcap_bytes, run.peak_rss_kib = pr["wall_time_s"], pr["pcap_bytes"], pr["client_peak_rss_kib"]
        run.cost_source = "record profile"
    return run


def _fill_cost(run: Run, r: dict, repo: Path, walls: dict[str, float]) -> None:
    """Pre-0.3 records: wall time from the session log, pcap size from the file on disk."""
    if run.cost_source != "not recorded":
        return
    run.wall_s = walls.get(run.run_id)
    pcap = repo / r["evidence"]["pcap_path"] if r["evidence"].get("pcap_path") else None
    run.pcap_bytes = pcap.stat().st_size if pcap and pcap.is_file() else None
    if run.wall_s is not None or run.pcap_bytes is not None:
        run.cost_source = "session log and pcap on disk"


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


def _check_adaptive_session(recs: list[dict], adaptive: tuple) -> list[str]:
    """An adaptive session must have stopped by its own rule, and the rule must replay identically."""
    lo, hi, w, *rest = adaptive
    win_w = rest[0] if rest else None
    recs = sorted(recs, key=lambda r: r["scenario"]["repetition"])
    n = len(recs)
    problems = []
    if not lo <= n <= hi:
        problems.append(f"{n} records, adaptive range is {lo}-{hi}")
    if [r["scenario"]["repetition"] for r in recs] != list(range(1, n + 1)):
        problems.append("repetitions are not exactly 1..%d" % n)
    setups: list[float | None] = []
    winners: list[str | None] = []
    for i, r in enumerate(recs, 1):
        ad = r.get("adaptive")
        if not ad:
            problems.append(f"{r['run_id']} has no adaptive block")
            continue
        rec_win_w = ad.get("win_ci_width")
        if (ad["min_reps"], ad["max_reps"], float(ad["ci_width_ms"]), rec_win_w) != (lo, hi, w, win_w):
            problems.append(f"{r['run_id']} adaptive settings {ad['min_reps']}-{ad['max_reps']}/"
                            f"{ad['ci_width_ms']}/win {rec_win_w} differ from the manifest {lo}-{hi}/{w}/win {win_w}")
        f = r["metrics"]["tcp_setup_time_ms"]
        setups.append(f["value"] if f["status"] == "computed" else None)
        wf = r["packet_observations"]["winning_family"]
        winners.append(wf["value"] if wf["status"] == "computed" else None)
        want = "stop" if i == n else "continue"
        got = ad["after_this_run"]["decision"]
        if got != want:
            problems.append(f"{r['run_id']} decision {got!r}, expected {want!r} at run {i} of {n}")
        tracked = "win" in ad["after_this_run"]   # 0.5 sessions carry the win fraction in every state
        replay = adaptive_decision(setups, lo, hi, w, winners=winners if tracked else None, win_ci_width=win_w,
                                   failed_runs=ad.get("failed_runs", FAILED_EXCLUDED))
        if replay["decision"] != got or replay["reason"] != ad["after_this_run"]["reason"]:
            problems.append(f"{r['run_id']}: stopping rule replays as {replay['decision']}/{replay['reason']}, "
                            f"record says {got}/{ad['after_this_run']['reason']}")
    return problems


def load_runs(sessions: list[tuple[str, str, str]], runs_dir: Path = RUNS_DIR,
              expected: int = EXPECTED_REPS, repo: Path | None = REPO, dns_scenarios=("S6",),
              provenance: dict | None = None, adaptive: tuple | None = None,
              lab_dir: Path = LAB_DIR) -> list[Run]:
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
        if adaptive:
            problems += _check_adaptive_session(recs, adaptive)
        else:
            if len(recs) != expected:
                problems.append(f"{len(recs)} records, expected {expected}")
            if sorted(r["scenario"]["repetition"] for r in recs) != list(range(1, expected + 1)):
                problems.append("repetitions are not exactly 1..%d" % expected)
        for r in recs:
            if (label_of(r["client"]), r["scenario"]["id"]) != (client, scenario):
                problems.append(f"{r['run_id']} is not {client}/{scenario}")
            if r["cross_checks"]["status"] != "agree":
                problems.append(f"{r['run_id']} cross_checks {r['cross_checks']['status']}")
            if not (r["evidence"].get("pre_verify_ok") and r["evidence"].get("post_restore_verify_ok")):
                problems.append(f"{r['run_id']} lab verify did not pass")
            # same rule as check_batch: a record made from uncommitted code cannot be reproduced
            if str(r.get("environment", {}).get("git_commit", "")).endswith("-dirty"):
                problems.append(f"{r['run_id']} code version is -dirty (uncommitted changes)")
        if problems:
            raise DatasetError(f"session {sid} ({client}/{scenario}): " + "; ".join(problems))
        walls: dict[str, float] = {}
        if repo is not None:
            log = lab_dir / f"{sid}_session.log"
            walls = parse_walls(log.read_text(encoding="utf-8")) if log.is_file() else {}
        for r in sorted(recs, key=lambda r: r["scenario"]["repetition"]):
            run = run_from_record(r)
            if repo is not None:
                _fill_cost(run, r, repo, walls)
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
                run.dns_answers_ms, run.first_syn_after_query_ms, run.first_syn_after_a_answer_ms = dns_by_type(
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


def oracle_cell(runs: list[Run]) -> dict:
    """Per-cell oracle summary (derived). Statistics only over runs where the cost was computed."""
    ok = [r for r in runs if r.oracle_status == "computed"]
    delays = {t: v for r in runs for t, v in (r.dns_delay_ms or {}).items() if v}
    return {
        "evidence": ORACLE_EVIDENCE,
        "oracle_setup_ms": _stats([r.oracle_setup_ms for r in ok]),
        "cost_of_racing_ms": _stats([r.cost_of_racing_ms for r in ok]),
        "status": dict(Counter(r.oracle_status for r in runs)),
        "not_computed_notes": sorted({r.oracle_note for r in runs if r.oracle_status != "computed" and r.oracle_note}),
        "single_family_runs": sum(1 for r in ok if r.single_family),
        "dns_note": None if not delays else (
            "DNS answer delay configured (" + ", ".join(f"{t} {v} ms" for t, v in sorted(delays.items()))
            + "); TCP setup excludes DNS, so that delay is not in the cost of racing; see DNS time"),
    }


def cost_cell(runs: list[Run]) -> dict:
    """Measurement cost of a cell (runner measurements). Totals only over runs where it was recorded."""
    walls = [r.wall_s for r in runs if r.wall_s is not None]
    sizes = [r.pcap_bytes for r in runs if r.pcap_bytes is not None]
    rss = [r.peak_rss_kib for r in runs if r.peak_rss_kib is not None]
    return {
        "runs": len(runs),
        "wall_time_s": None if not walls else {"n": len(walls), "total": round(sum(walls), 2),
                                               "median": round(statistics.median(walls), 2)},
        "pcap_bytes": None if not sizes else {"n": len(sizes), "total": sum(sizes),
                                              "median": statistics.median(sizes)},
        "client_peak_rss_kib": None if not rss else {"n": len(rss), "median": statistics.median(rss),
                                                     "max": max(rss)},
        "source": dict(Counter(r.cost_source for r in runs)),
    }


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
        "tcp_setup_median_ci95": bootstrap_median_ci(setups),
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
        "oracle": oracle_cell(runs),
        "cost": cost_cell(runs),
        "dns_answer_by_type_ms": None if not any(r.dns_answers_ms for r in runs) else {
            **{f"{t} answer": _stats([r.dns_answers_ms[t] for r in runs if r.dns_answers_ms and t in r.dns_answers_ms])
               for t in sorted({t for r in runs for t in (r.dns_answers_ms or {})})},
            "first SYN": _stats([r.first_syn_after_query_ms for r in runs if r.first_syn_after_query_ms is not None]),
            "first SYN after the A answer": _stats([r.first_syn_after_a_answer_ms for r in runs
                                                    if r.first_syn_after_a_answer_ms is not None]),
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


def client_order(clients) -> list[str]:
    """Implementations in order of first appearance; each one's variants right after it."""
    groups = group_by_implementation(clients)
    impls = list(dict.fromkeys(parse_client(c).implementation for c in clients))
    return [lb for impl in impls for lb in groups[impl]]


def summarise(runs: list[Run], shape: Shape = CORE_SHAPE) -> dict:
    """Cells per client label (a curl variant is its own cell, beside plain curl) and scenario.

    A variant's scenario penalty uses its own C0, never plain curl's."""
    clients = client_order(shape.clients)
    cells: dict[str, dict[str, dict]] = {c: {} for c in clients}
    for c in clients:
        mine = [s for s in shape.scenarios if (c, s) not in shape.absent]
        for s in mine:
            cells[c][s] = summarise_cell([r for r in runs if r.client == c and r.scenario == s])
        c0 = [r.setup_ms for r in runs if r.client == c and r.scenario == "C0" and r.setup_ms is not None]
        for s in mine:
            sc = [r.setup_ms for r in runs if r.client == c and r.scenario == s and r.setup_ms is not None]
            cells[c][s]["scenario_penalty_ms"] = scenario_penalty(sc, c0)
            if "C0" not in shape.scenarios:   # never borrowed from another dataset's C0
                cells[c][s]["scenario_penalty_note"] = "no C0 in this dataset"
    return {"cells": cells, "interpretation": interpretations(cells) + oracle_interpretation(cells)}


# --- interpretation (labelled; built only from the numbers above) --------------------------

def _med(cell: dict, key: str) -> float | None:
    st = cell["attempt_offsets_ms"].get(key)
    return st["median"] if st else None


def interpretations(cells: dict) -> list[dict]:
    """Labelled interpretation, each with the packet-level / client-log evidence it rests on.

    Statements are worded from the data: if the evidence does not hold in every run, the text says so.
    """
    out = []
    if "curl" not in cells or "chromium" not in cells:
        return out  # every statement below compares the two clients
    cu, ch = cells["curl"], cells["chromium"]

    def have(*scenarios: str) -> bool:
        return all(s in cu and s in ch for s in scenarios)

    # 1. Chromium's longer setup in S1/S2: when the v4 attempt starts, not the backup attempt.
    for s in ("S1", "S2"):
        if not have(s):
            continue
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

    if have("S6"):
        # 2. S6: when the first SYN goes out relative to the A and AAAA answers (packet timing only).
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

        def v4_runs(c: dict) -> int:
            return sum(v for k, v in c["attempt_shape"].items() if "v4" in k.split(">"))

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
                                  if isinstance(v, dict) and k != "first SYN after the A answer")
                ev.append({"source": "packet", "text": f"{n}, from the first www.hl.test query: {parts}; first SYN "
                                                       f"after the AAAA answer in {after_aaaa(c)}/{c['n']} runs"})
                off = by.get("first SYN after the A answer")
                if off:
                    ev.append({"source": "packet", "text": f"{n}: first SYN after the first A answer min/median/max "
                                                           f"{off['min']}/{off['median']}/{off['max']} ms (n={off['n']})"})
            ev.append({"source": "packet", "text": f"{n}: runs with any IPv4 SYN {v4_runs(c)}/{c['n']}"})
        out.append({
            "topic": "S6: when is the first SYN sent, relative to the A and AAAA answers?",
            "statement": (
                ("Both clients sent their first SYN only after the delayed AAAA answer had arrived, in every run. "
                 if both else "Not every S6 run shows the first SYN after the AAAA answer; see evidence. ")
                + (f"The A answer arrived much earlier (always under {AAAA_DELAY_MS} ms), and no IPv4 SYN was sent "
                   "in any S6 run. " if a_early and all(v4_runs(c) == 0 for _, c in s6.values()) else "")
                + "The AAAA delay therefore appears in DNS time, not in TCP setup time (which starts at the first "
                "SYN); S6 must be reported with both. The captures show when each packet was sent, not why: they "
                "say nothing about how either client's resolver or connection logic is built."),
            "evidence": ev,
            "reference": "docs/findings/chromium_s1_second_v6_syn.md (S2/S3/S6 pilot section) and docs/dataset.md",
        })

    if have("S4", "S5"):
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


def oracle_interpretation(cells: dict) -> list[dict]:
    """One labelled statement on the oracle baseline, for whatever cells the dataset has.

    The oracle is a hindsight reference: it uses the family that won, which no client knows in advance.
    """
    ev = []
    for c, by_s in cells.items():
        for s, x in by_s.items():
            o = x["oracle"]
            st, cost = o["status"], o["cost_of_racing_ms"]
            if cost:
                ev.append({"source": "derived", "text": (
                    f"{s} {c}: cost of racing median {cost['median']} ms [IQR {cost['q1']}, {cost['q3']}] over "
                    f"{cost['n']}/{x['n']} runs; oracle setup median {o['oracle_setup_ms']['median']} ms; "
                    f"winner {x['winning_family']}"
                    + (f"; {o['single_family_runs']} single-family runs" if o["single_family_runs"] else "")
                    + (f"; not computed: { {k: v for k, v in st.items() if k != 'computed'} }"
                       if len(st) > 1 or "computed" not in st else ""))})
            else:
                ev.append({"source": "derived", "text": f"{s} {c}: cost of racing not computed in any run ({st})"})
    if not any(x["oracle"]["cost_of_racing_ms"] for by_s in cells.values() for x in by_s.values()):
        return []
    return [{
        "topic": "Oracle baseline: how much time did racing add over a direct connection to the winning family?",
        "statement": (
            "If each client had connected straight to the family that eventually won, with no racing, we take "
            "its TCP setup to be about one measured RTT of that family (the oracle setup). The cost of racing is "
            "the measured TCP setup time minus that reference, listed per scenario and client below. It is a "
            "hindsight reference: the oracle uses the winner, which no client can know before connecting, so it "
            "is a lower bound for comparison, not a target any client could meet. The value says how much time "
            "the observed attempt order and timing added in this lab; it says nothing about how either client "
            "is built. In single-family runs no race took place, and the value is only the handshake time "
            "against the ping RTT. Where a DNS answer was delayed, that delay is outside TCP setup and so is "
            "not in this value."),
        "evidence": ev,
        "reference": "src/analysis/metrics.py (oracle_baseline)",
    }]


# --- output ----------------------------------------------------------------------------

def _fmt_stats(st: dict | None) -> str:
    return "-" if not st else f"{st['median']} [{st['q1']}-{st['q3']}]"


def _fmt_cost(st: dict | None) -> str:
    """Median [Q1, Q3]; a comma, because the cost can be negative."""
    return "-" if not st else f"{st['median']} [{st['q1']}, {st['q3']}]"


def text_report(summary: dict) -> str:
    lines = []
    for c, by_scenario in summary["cells"].items():
        cn = parse_client(c)
        variant = (f"; a variant of {cn.implementation}, not another client: --happy-eyeballs-timeout-ms "
                   f"{cn.he_timeout_ms}") if cn.variant else ""
        lines.append(f"\n{c}  (packet-level unless stated{variant})")
        lines.append(f"  {'scn':4} {'n':>3} {'ok':>3}  {'winner':16} {'setup median [IQR] ms':26} {'penalty':>9}  "
                     f"{'inter-family: obs/not, median':30} {'fail/aband per run':20} {'shape':22} dns median")
        for s, x in by_scenario.items():
            inter = x["inter_family"]
            inter_txt = f"{inter['observed']}/{inter['not_observed']}" + (
                f", {inter['stats_over_observed_only']['median']}" if inter["stats_over_observed_only"] else ", -")
            lines.append(
                f"  {s:4} {x['n']:>3} {x['successes']:>3}  {json.dumps(x['winning_family']):16} "
                f"{_fmt_stats(x['tcp_setup_ms']):26} {x['scenario_penalty_ms']!s:>9}  {inter_txt:30} "
                f"{json.dumps(x['failed_or_abandoned_per_run']):20} {json.dumps(x['attempt_shape']):22} "
                f"{x['dns_ms']['median'] if x['dns_ms'] else '-'}")
    lines.append("\nMEDIAN TCP SETUP TIME, 95% CI (packet-level; percentile bootstrap of the median, "
                 "10 000 resamples, seed 0; a description of spread, not a significance test)")
    for c, by_scenario in summary["cells"].items():
        for s, x in by_scenario.items():
            ci, st = x["tcp_setup_median_ci95"], x["tcp_setup_ms"]
            lines.append(f"  {c:9} {s:4} median {st['median'] if st else '-':>9}  "
                         + (f"CI [{ci['lo']}, {ci['hi']}] width {ci['width']} (n={ci['n']})" if ci else "no CI (n < 2)"))
    lines.append("\nORACLE BASELINE (derived: pcap TCP setup minus the winning family's pre-run ping RTT)")
    lines.append(f"  {'client':9} {'scn':4} {'oracle median':>13} {'cost median [IQR] ms':26} statuses / notes")
    for c, by_scenario in summary["cells"].items():
        for s, x in by_scenario.items():
            o = x["oracle"]
            notes = [json.dumps(o["status"])]
            if o["single_family_runs"]:
                notes.append(f"{o['single_family_runs']} single-family runs (no race)")
            if o["dns_note"]:
                notes.append("DNS delay not in cost; see DNS time")
            lines.append(f"  {c:9} {s:4} {o['oracle_setup_ms']['median'] if o['oracle_setup_ms'] else '-':>13} "
                         f"{_fmt_cost(o['cost_of_racing_ms']):26} {'; '.join(notes)}")
    lines.append("\nINTERPRETATION (labelled; built from the evidence listed)")
    for it in summary["interpretation"]:
        lines.append(f"- {it['topic']}\n  {it['statement']}")
        for e in it["evidence"]:
            lines.append(f"    [{e['source']}] {e['text']}")
    return "\n".join(lines)


def cost_report(summary: dict) -> str:
    """Measurement cost per cell (runner measurements, not packet evidence)."""
    lines = ["MEASUREMENT COST PER CELL (runner measurements: wall time per run, pcap size, client peak RSS)",
             f"  {'client':9} {'scn':4} {'runs':>4} {'wall total s':>12} {'wall median s':>13} "
             f"{'pcap total B':>12} {'pcap median B':>13} {'peak RSS median/max KiB':>24}  source"]
    tot_w = tot_b = tot_n = 0
    for c, by_scenario in summary["cells"].items():
        for s, x in by_scenario.items():
            k = x["cost"]
            w, b, m = k["wall_time_s"], k["pcap_bytes"], k["client_peak_rss_kib"]
            tot_n += k["runs"]
            tot_w += w["total"] if w else 0
            tot_b += b["total"] if b else 0
            lines.append(f"  {c:9} {s:4} {k['runs']:>4} {w['total'] if w else '-':>12} {w['median'] if w else '-':>13} "
                         f"{b['total'] if b else '-':>12} {b['median'] if b else '-':>13} "
                         f"{(str(m['median']) + ' / ' + str(m['max'])) if m else 'not recorded':>24}  "
                         + ", ".join(f"{src} {n}" for src, n in k["source"].items()))
    lines.append(f"  total: {tot_n} runs, {round(tot_w, 1)} s wall time ({round(tot_w / 60, 1)} min), "
                 f"{tot_b} pcap bytes ({round(tot_b / 1e6, 2)} MB)")
    return "\n".join(lines)


def build(doc: Path = DATASET_DOC, runs_dir: Path = RUNS_DIR, manifest: Manifest | None = None,
          repo: Path | None = REPO) -> tuple[list[tuple[str, str, str]], list[Run], dict]:
    m = manifest or load_manifest(doc)
    doc, sessions, shape = m.path, m.sessions, m.shape
    prov: dict = {}
    runs = load_runs(sessions, runs_dir, expected=shape.reps, repo=repo, provenance=prov, adaptive=shape.adaptive)
    summary = summarise(runs, shape)
    summary["dataset"] = {"source": str(doc.relative_to(REPO)) if doc.is_relative_to(REPO) else str(doc),
                          "sessions": [{"client": c, "scenario": s, "session": sid} for c, s, sid in sessions],
                          "runs": len(runs),
                          "clients": {c: {"versions": sorted(v for v in p["versions"] if v),
                                          "configs": [json.loads(x) for x in sorted(p["configs"])],
                                          "code_versions": sorted(x for x in p["code"] if x)}
                                      for c, p in prov.items()},
                          "implementations": group_by_implementation(shape.clients)}
    if doc != DATASET_DOC:  # a named dataset records the shape it declared (core output stays as it was)
        summary["dataset"]["shape"] = {"clients": list(shape.clients), "scenarios": list(shape.scenarios),
                                       "reps": shape.reps}
        if shape.absent:
            summary["dataset"]["shape"]["absent_cells"] = sorted(f"{c}:{s}" for c, s in shape.absent)
        if shape.adaptive:
            lo, hi, w, *rest = shape.adaptive
            summary["dataset"]["shape"]["adaptive"] = {"min": lo, "max": hi, "ci_width_ms": w,
                                                       **({"win_ci_width": rest[0]} if rest else {})}
    return sessions, runs, summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=CORE_DATASET,
                    help="dataset name: 'core' (docs/dataset.md, the default) or NAME for docs/datasets/NAME.md")
    ap.add_argument("--out", type=Path, default=None,
                    help="output folder (default: data/generated/summary/, or .../summary/NAME/ for a named dataset)")
    ap.add_argument("--cost", action="store_true", help="print the measurement cost per cell instead of the tables")
    a = ap.parse_args(argv)
    try:
        _, runs, summary = build(manifest=load_dataset(a.dataset))
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    a.out = a.out or out_dir_for(a.dataset)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (a.out / "runs.json").write_text(json.dumps([r.__dict__ for r in runs], indent=1) + "\n", encoding="utf-8")
    print(cost_report(summary) if a.cost else text_report(summary))
    print(f"\nwrote {a.out / 'summary.json'} and runs.json ({len(runs)} runs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
