"""Data for the website's Extensions page and the Playground's measured replays (used by export_web.py).

Two sources, both read-only:

1. The four certified extension datasets (docs/datasets/<name>.md). Each must pass the same
   certification summarise.py applies (summarise.load_runs: every declared cell present, the right
   repetitions, cross-checks "agree", lab verify passed before and after, no -dirty code). A dataset
   that is not a manifest in docs/datasets/, or that fails certification, is refused: nothing from it
   reaches the page. The core dataset is not an extension and is refused here too.
   Values come from the existing analysis code only (figures.collect, summarise.build,
   syn_retransmit.analyse_cell); this module formats them as the findings docs print them and adds
   no metric of its own.

2. The three committed example runs in examples/: record and capture, each capture checked against
   SHA256SUMS and the record's pcap_sha256, then re-parsed with parse_pcap for the packet times the
   Playground replays. A record whose TCP setup time or inter-family delay does not match its own
   capture is refused.

Formatting follows the docs: T and the oracle costs to two decimals, rounded half up from the
stored three-decimal value; SYN times to three decimals; negative numbers with a real minus sign.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.summarise import CORE_DATASET, REPO, RUNS_DIR, DatasetError, load_dataset, load_runs  # noqa: E402

EXTENSION_DATASETS = ("variant-control", "jitter-loss", "latency-sweep", "he-sweep")
EXAMPLES = REPO / "examples"
CORE_RUNS = 280   # the frozen core dataset (docs/dataset.md); export_web checks it against the core block


class ExtensionError(Exception):
    pass


# --- formatting (as the findings docs print numbers) -----------------------------------------

def _q(x: float, places: str) -> Decimal:
    return Decimal(str(x)).quantize(Decimal(places), rounding=ROUND_HALF_UP)


def f1(x: float) -> str:
    return str(_q(x, "0.1"))


def f2(x: float) -> str:
    return str(_q(x, "0.01"))


def f3(x: float) -> str:
    return f"{x:.3f}"


def signed2(x: float) -> str:
    """+0.73 / −0.19 (U+2212), two decimals half up, as the docs write a cost or a residual."""
    v = _q(x, "0.01")
    return ("−" if v < 0 else "+") + str(abs(v))


def frac2(k: int, n: int) -> str:
    return f2(k / n)


# --- certification ---------------------------------------------------------------------------

def certify(name: str, runs_dir: Path = RUNS_DIR):
    """(manifest, runs) for a certified extension dataset; refuses anything else."""
    if name == CORE_DATASET:
        raise ExtensionError("the core dataset is not an extension; it is written by export_web's core block")
    if name not in EXTENSION_DATASETS:
        raise ExtensionError(f"{name!r} is not one of the extension datasets the page shows "
                             f"({', '.join(EXTENSION_DATASETS)})")
    try:
        m = load_dataset(name)
        runs = load_runs(m.sessions, runs_dir, expected=m.shape.reps, repo=None, adaptive=m.shape.adaptive)
    except (DatasetError, OSError, KeyError) as exc:
        raise ExtensionError(f"dataset {name} is not certified: {exc}") from exc
    return m, runs


def dataset_rows(certified: dict, runs_dir: Path = RUNS_DIR) -> list[dict]:
    """One row per extension dataset: its manifest title and what its certified runs record."""
    out = []
    by_session: dict[str, dict] = {}
    for p in sorted(runs_dir.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        sid = r.get("environment", {}).get("session_id")
        if sid not in by_session:
            by_session[sid] = r
    for name, (m, runs) in certified.items():
        first = [by_session[sid] for _, _, sid in m.sessions if sid in by_session]
        header = m.path.read_text(encoding="utf-8").split("---", 2)[1]
        title = next((ln.split(":", 1)[1].strip() for ln in header.splitlines() if ln.startswith("title:")), name)
        out.append({"name": name, "title": title, "doc": f"docs/datasets/{name}.md",
                    "sessions": len(m.sessions), "runs": len(runs),
                    "clients": list(m.shape.clients), "scenarios": len(m.shape.scenarios),
                    "code": sorted({r["environment"]["git_commit"] for r in first}),
                    "kernel": sorted({r["environment"]["kernel"] for r in first}),
                    "dates": sorted({r["timestamps"]["run_start_utc"][:10] for r in first})})
    return out


# --- the numbers -----------------------------------------------------------------------------

def _cost_ranges(lat_runs) -> dict:
    """Latency sweep, derived (pcap − lab RTT): cell medians of the cost of racing, by client and outcome."""
    cells: dict[tuple, list] = {}
    for r in lat_runs:
        if r.oracle_status == "computed":
            cells.setdefault((r.client, r.scenario), []).append(r)
    out: dict = {}
    for (client, _), rs in cells.items():
        winners = {r.winner for r in rs}
        if len(winners) != 1:
            raise ExtensionError(f"latency-sweep {client}: a cell with mixed winners; the page has no wording for it")
        win = winners.pop()
        raced = not all(r.single_family for r in rs)
        key = "v4" if win == "v4" else ("v6_raced" if raced else "v6_single")
        out.setdefault(client, {}).setdefault(key, []).append(statistics.median(r.cost_of_racing_ms for r in rs))
    return out


def _range(xs: list[float], fmt) -> str:
    return f"{fmt(min(xs))} to {fmt(max(xs))} ms"


def numbers(d: dict, lat_runs, retx: dict) -> dict[str, str]:
    """Display strings keyed like deck/deck_numbers.json, wherever the deck has the same number."""
    lat = {r["client"]: r for r in d["latency_sweep"]}
    jit = {(r["client"], r["scenario"]): r for r in d["jitter"]}
    he = {r["client"]: r for r in d["he_sweep"]}
    res = d["residuals"]
    cost = _cost_ranges(lat_runs)
    n: dict[str, str] = {}
    for c, k in (("curl", "curl"), ("chromium", "chr")):
        b = lat[c]["flip_bracket"]
        n[f"{k}_flip"] = f"{b['above_ms']:g}–{b['below_ms']:g} ms"
        n[f"{k}_T_ls"] = f2(lat[c]["T_ms"])
        n[f"{k}_T_jl"] = f2(jit[(c, "Gv6j50")]["T_ms"])
        n[f"{k}_cost_v4"] = f"{f2(min(cost[c]['v4']))}–{f2(max(cost[c]['v4']))} ms"
        n[f"{k}_cost_v6_raced"] = _range(cost[c]["v6_raced"], signed2)
        for j in ("50", "70"):
            row = jit[(c, f"Gv6j{j}")]
            o = row["observed"]
            n[f"j_{k}{j}_pred"] = f2(row["predicted"])
            n[f"j_{k}{j}_obs"] = (f"{o['v6_wins']}/{o['n']} = {frac2(o['v6_wins'], o['n'])} "
                                  f"[{f2(o['ci']['lo'])}, {f2(o['ci']['hi'])}]")
        for g in retx[c]["gaps"]:
            n[f"rto_{k}_{g['ordinal']}"] = (f"n={g['n']}, " + ("median " if g["ordinal"] == 1 else "")
                                            + f"{f1(g['median_ms'])} ms")
    all_res = list(res["by_client"].values())
    n["he_resid_all"] = _range(all_res, signed2)
    n["he_resid_low"] = _range(res["below"], signed2)
    n["he_resid_high"] = _range(res["from"], signed2)
    n["he200_v4syn"] = f3(he["curl@he200"]["S1"]["v4_first_syn_ms"])
    n["plain_v4syn"] = f3(he["curl"]["S1"]["v4_first_syn_ms"])
    return n


def he_rows(d: dict) -> list[dict]:
    out = []
    for r in d["he_sweep"]:
        s1 = r["S1"]
        timed = r["timeout_ms"] is not None
        out.append({"client": r["client"], "timeout": str(r["timeout_ms"]) if timed else "not set",
                    "syn": f3(s1["v4_first_syn_ms"]), "hs": f3(s1["v4_handshake_ms"]),
                    "pred": f2(r["predicted_T_ms"]) if timed else "–", "T": f2(s1["T_ms"]),
                    "resid": signed2(r["T_minus_predicted_ms"]) if timed else "–",
                    "v4won": f"{s1['v4_wins']}/{s1['n']}"})
    return out


def jitter_rows(d: dict, config: dict) -> list[dict]:
    out = []
    for r in d["jitter"]:
        o = r["observed"]
        j = config["scenarios"][r["scenario"]]["grid"]["value"]
        out.append({"client": r["client"], "cell": r["scenario"], "T": f2(r["T_ms"]), "mu": f1(r["mu_ms"]),
                    "sigma": f1(r["sigma_ms"]), "design": f1(j * 2 ** 0.5), "pred": f2(r["predicted"]),
                    "obs": f"{o['v6_wins']}/{o['n']} = {frac2(o['v6_wins'], o['n'])} "
                           f"[{f2(o['ci']['lo'])}, {f2(o['ci']['hi'])}]",
                    "inside": bool(r["predicted_inside_ci"])})
    return out


def retransmissions(jl_manifest, runs_dir: Path = RUNS_DIR, repo: Path = REPO) -> dict:
    """syn_retransmit.analyse_cell over the jitter-loss cells: Gv6c30 gaps, and the healthy-IPv4 total."""
    from analysis.syn_retransmit import analyse_cell, load_records
    recs = load_records({sid for _, _, sid in jl_manifest.sessions}, runs_dir)
    out: dict = {"healthy": {"runs": 0, "attempts_with_syn_retransmission": 0}}
    for (client, scen), rs in sorted(recs.items()):
        cell = analyse_cell(rs, repo)
        if scen == "Gv6c30":
            out[client] = {"runs": cell["n_runs"], "attempts": cell["attempts_with_syn_retransmission"],
                           "gaps": [{"ordinal": g["ordinal"], "n": g["n"], "median_ms": g["median_ms"],
                                     "min_ms": g["min_ms"], "max_ms": g["max_ms"]}
                                    for g in cell["syn_retransmission_gaps"]]}
        else:
            out["healthy"]["runs"] += cell["n_runs"]
            out["healthy"]["attempts_with_syn_retransmission"] += cell["attempts_with_syn_retransmission"]
    return out


def retx_rows(retx: dict) -> list[dict]:
    rows = []
    for c in ("curl", "chromium"):
        by = {g["ordinal"]: g for g in retx[c]["gaps"]}
        cells = []
        for k in (1, 2, 3, 4):
            g = by.get(k)
            cells.append("none" if g is None else
                         f"n={g['n']}, " + ("median " if k == 1 else "") + f"{f1(g['median_ms'])} ms "
                         f"({f1(g['min_ms'])}–{f1(g['max_ms'])})")
        rows.append({"client": c, "gaps": cells, "attempts": retx[c]["attempts"], "runs": retx[c]["runs"]})
    return rows


def repro_rows(d: dict) -> list[dict]:
    return [{"campaign": r["campaign"], "condition": r["condition"].replace("<br>", " "), "n": r["n"],
             "T": f2(r["T_ms"]), "code": r["code"], "kernel": r["kernel"]} for r in d["T_reproducibility"]]


def build(runs_dir: Path = RUNS_DIR, repo: Path = REPO) -> dict:
    """Everything the Extensions page shows from the four certified extension datasets."""
    from analysis import figures
    from analysis.dashboard import TAG_LABEL
    from analysis.scenario_config import load_config
    from analysis.summarise import build as summarise_build

    certified = {name: certify(name, runs_dir) for name in EXTENSION_DATASETS}
    d = figures.collect()
    _, lat_runs, _ = summarise_build(manifest=certified["latency-sweep"][0])
    retx = retransmissions(certified["jitter-loss"][0], runs_dir, repo)
    ds = dataset_rows(certified, runs_dir)
    n = numbers(d, lat_runs, retx)
    n |= {key: f"{x['runs']} runs" for x in ds
          for key in [{"latency-sweep": "ls_runs", "he-sweep": "he_runs", "jitter-loss": "jl_runs"}.get(x["name"])] if key}
    return {
        "tags": dict(TAG_LABEL),
        "datasets": ds,
        "runs": {"core": CORE_RUNS, "extensions": sum(x["runs"] for x in ds),
                 "total": CORE_RUNS + sum(x["runs"] for x in ds)},
        "N": n,
        "he": he_rows(d),
        "jitter": jitter_rows(d, load_config()),
        "retx": retx_rows(retx),
        "retx_healthy": retx["healthy"],
        "repro": repro_rows(d),
        "repro_spread": f2(d["T_spread_ms"]),
        "claims": figures.claims(d),
    }


# --- examples/: the Playground's measured replays -------------------------------------------

def _sums(folder: Path) -> dict[str, str]:
    out = {}
    for ln in (folder / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if ln.strip():
            h, name = ln.split(maxsplit=1)
            out[name.lstrip("*")] = h
    return out


def _v(field: dict):
    return field.get("value") if field.get("status") == "computed" else None


def _rtt_text(m: dict) -> str:
    if m.get("value") is not None:
        return f"{m['value']:g} ms RTT"
    return "blackholed" if "blackhole" in (m.get("note") or "") else "not measured"


def replay(run_id: str, folder: Path = EXAMPLES) -> dict:
    """One stored run, as packet times (ms after its first www.hl.test DNS query)."""
    from analysis.parse_pcap import parse
    rec = json.loads((folder / f"{run_id}.json").read_text(encoding="utf-8"))
    pcap = folder / f"{run_id}.pcap"
    digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
    sums = _sums(folder)
    if sums.get(pcap.name) != digest or rec["evidence"]["pcap_sha256"] != digest:
        raise ExtensionError(f"{pcap}: sha256 does not match SHA256SUMS and the record")
    if rec["cross_checks"]["status"] != "agree":
        raise ExtensionError(f"{run_id}: cross-checks are {rec['cross_checks']['status']}, not agree")
    ts = rec["timestamps"]
    tl = parse(pcap, (ts["client_start_epoch_ns"], ts["capture_end_epoch_ns"]))
    dns = sorted((x for x in tl.dns if x.qname.rstrip(".") == "www.hl.test"), key=lambda x: x.query_ns)
    if not dns:
        raise ExtensionError(f"{run_id}: no www.hl.test query in the capture")
    t0 = dns[0].query_ns

    def ms(ns):
        return None if ns is None else round((ns - t0) / 1e6, 3)

    recorded = {(a["family"], a["src_port"]): a["result"] for a in _v(rec["packet_observations"]["attempts"])}
    atts = []
    for a in sorted((a for a in tl.attempts if a.dport == 80), key=lambda a: a.first_syn_ns):
        if (a.family, a.sport) not in recorded:
            raise ExtensionError(f"{run_id}: attempt {a.family} port {a.sport} is in the capture but not the record")
        atts.append({"f": a.family, "port": a.sport, "syn": ms(a.first_syn_ns), "synack": ms(a.synack_ns),
                     "ack": ms(a.handshake_ack_ns), "syns": len(a.syn_times_ns), "res": recorded[(a.family, a.sport)],
                     "http": a.http_status})
    won = [a for a in atts if a["res"] == "won"]
    if len(won) != 1:
        raise ExtensionError(f"{run_id}: expected one winning attempt, got {len(won)}")
    first = atts[0]["syn"]
    setup = round(won[0]["ack"] - first, 3)
    fams = [a["f"] for a in atts]
    ifd = None if len(set(fams)) < 2 else round(next(a["syn"] for a in atts if a["f"] != fams[0]) - first, 3)
    m = rec["metrics"]
    # The record's values must be what its own capture shows (a 1 µs tolerance for rounding).
    for name, mine, theirs in (("tcp_setup_time_ms", setup, _v(m["tcp_setup_time_ms"])),
                               ("inter_family_attempt_delay_ms", ifd, _v(m["inter_family_attempt_delay_ms"]))):
        if (mine is None) != (theirs is None) or (mine is not None and abs(mine - theirs) > 0.002):
            raise ExtensionError(f"{run_id}: {name} is {theirs} in the record but {mine} from the capture")
    ev = []
    for x in dns:
        ev.append([ms(x.query_ns), "dns", f"query {x.qtype} www.hl.test"])
        if x.response_ns is not None:
            ev.append([ms(x.response_ns), "dns", f"answer {x.qtype} " + (", ".join(x.answers) or "(no records)")])
    for i, a in enumerate(atts, 1):
        ev.append([a["syn"], "syn", f"SYN {a['f']} attempt {i}, port {a['port']}"])
        if a["synack"] is not None:
            ev.append([a["synack"], "ok", f"SYN-ACK {a['f']} attempt {i}"])
        if a["ack"] is not None:
            ev.append([a["ack"], "ok", f"ACK {a['f']} attempt {i}: handshake complete"])
    ev.sort(key=lambda e: e[0])
    sc = rec["scenario"]
    return {"id": run_id, "sc": sc["id"], "label": sc["label"], "cl": rec["client"]["name"],
            "version": rec["client"].get("version", "").split(" (")[0],
            "loss": {f: sc["netem"][f]["loss_pct"] for f in ("v4", "v6")},
            # configured, not measured: what the Playground's sliders are set to for this run
            "added": {f: round(2 * (sc["netem"][f]["delay_ms_each_way"] - 10), 3) for f in ("v4", "v6")},
            "aaaa": sc.get("dns", {}).get("delay_ms", {}).get("AAAA", 0),
            "rtt": {f: _rtt_text(sc["measured_rtt_ms"][f]) for f in ("v4", "v6")},
            "atts": atts, "ev": ev, "first_syn": first, "setup": setup, "ifd": ifd,
            "dns": _v(m["dns_time_ms"]), "win": _v(rec["packet_observations"]["winning_family"]),
            "ab": _v(rec["packet_observations"]["failed_or_abandoned_attempts"]),
            "http": rec["outcome"].get("http_status"), "sha": digest}


def replays(folder: Path = EXAMPLES) -> list[dict]:
    ids = sorted(p.stem for p in folder.glob("*.json"))
    if not ids:
        raise ExtensionError(f"no example runs in {folder}")
    return [replay(i, folder) for i in ids]
