"""Connection race timeline: per-run swimlane data for the dashboard. Reads existing records; no new runs.

Two evidence levels, kept apart in the data and on the chart:
  packet   every SYN, SYN retransmission, SYN-ACK, handshake ACK and DNS query/answer time. The record's
           packet_observations and metrics give the SYN times, results and TCP setup time. When the
           run's capture is present and its SHA-256 matches the record, it is re-read for the times the
           record does not store (retransmitted SYNs, SYN-ACKs, DNS answers), and every re-read value
           the record also holds is checked against it; a mismatch is refused, not drawn.
  derived  the oracle setup time and cost of racing (metrics.oracle_baseline): packet-level TCP setup
           minus the winning family's RTT from the lab's ping check before the run.

All times are milliseconds from the run's first SYN, the origin of the TCP setup time.

Without a capture the run is still drawn from its record alone: SYNs and the handshake ACK are placed,
but retransmission times, SYN-ACKs and the DNS answer's position are marked as not available. The
three runs committed in examples/ also carry their parsed packet rows, so the chart can link to them.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dnslib import QTYPE, DNSRecord  # noqa: E402

from analysis.metrics import ORACLE_EVIDENCE, TARGET_NAME, TARGET_PORT, _name  # noqa: E402
from analysis.parse_pcap import ACK, FIN, PSH, RST, SYN, Packet, analyse, read_pcap  # noqa: E402
from analysis.summarise import REPO, RUNS_DIR, DatasetError, Run  # noqa: E402

EXAMPLES_DIR = REPO / "examples"
TOLERANCE_MS = 0.001  # record values are rounded to 3 decimals


def _ms(ns: int, t0: int) -> float:
    return round((ns - t0) / 1e6, 3)


def _val(block):
    return block.get("value") if isinstance(block, dict) else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- choosing runs ---------------------------------------------------------------------

def representative(runs: list[Run]) -> Run | None:
    """The run nearest its cell's median TCP setup time (ties: lower repetition); same rule as export_web."""
    done = [r for r in runs if r.setup_ms is not None]
    if not done:
        return min(runs, key=lambda r: r.repetition) if runs else None
    med = statistics.median(r.setup_ms for r in done)
    return min(done, key=lambda r: (abs(r.setup_ms - med), r.repetition))


def default_run(runs: list[Run], clients, scenarios, prefer: str = "S1") -> tuple[Run | None, str]:
    """(run, why). The representative S1 run of the first client; a dataset without S1 falls back to the
    first scenario that has runs, and says so."""
    order = [prefer] + [s for s in scenarios if s != prefer]
    for s in order:
        for c in clients:
            cell = [r for r in runs if r.scenario == s and r.client == c]
            if cell:
                rep = representative(cell)
                if s == prefer:
                    why = f"representative {s} run: nearest the {s} median TCP setup time for this client"
                else:
                    why = (f"this dataset has no {prefer} runs, so the default is the representative {s} run "
                           "(nearest that cell's median TCP setup time)")
                return rep, why
    return None, "this dataset has no runs"


# --- re-reading the capture --------------------------------------------------------------

def _flags(p: Packet) -> str:
    names = [n for bit, n in ((SYN, "SYN"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (ACK, "ACK")) if p.flags & bit]
    return "-".join(names) or "none"


def _dns_name_type(p: Packet) -> tuple[str, str, bool, list[str]] | None:
    try:
        rec = DNSRecord.parse(p.payload)
    except Exception:  # noqa: BLE001  (undecodable DNS is reported by the parser, not here)
        return None
    if not rec.questions:
        return None
    q = rec.questions[0]
    return (str(q.qname), QTYPE.get(q.qtype, str(q.qtype)), bool(rec.header.qr),
            [str(rr.rdata) for rr in rec.rr])


def wire(pcap: Path, record: dict, rows: bool = False, target: str = TARGET_NAME,
         port: int = TARGET_PORT) -> dict:
    """Packet-level events of one run from its capture, checked against the record.

    Returns {"attempts": [...], "dns": [...], "rows": [...] or None, "rows_note": str or None}; each event
    carries its time (ms from the first SYN) and its frame number in the pcap.
    """
    linktype, packets = read_pcap(pcap)
    ts = record["timestamps"]
    window = (ts["client_start_epoch_ns"], ts["capture_end_epoch_ns"])
    tl = analyse(linktype, packets, window)
    inwin = [p for p in packets if window[0] <= p.ts_ns <= window[1]]
    rec_att = sorted(_val(record["packet_observations"]["attempts"]) or [], key=lambda a: a["first_syn_ns"])
    rid = record["run_id"]
    if not rec_att:
        raise DatasetError(f"{rid}: no attempts in the record")
    t0 = rec_att[0]["first_syn_ns"]

    def ev(p: Packet) -> dict:
        return {"t": _ms(p.ts_ns, t0), "f": p.frame_no}

    out_att, tcp_frames, winner_ack_ns = [], {}, None
    for i, a in enumerate(rec_att, 1):
        tla = next((x for x in tl.attempts if x.sport == a["src_port"] and x.dport == port
                    and x.family == a["family"] and x.first_syn_ns == a["first_syn_ns"]), None)
        if tla is None:
            raise DatasetError(f"{rid}: attempt {a['family']} port {a['src_port']} is not in the capture")
        own = [p for p in inwin if p.proto == "tcp" and (
            (p.src == tla.src and p.sport == tla.sport and p.dst == tla.dst and p.dport == port)
            or (p.dst == tla.src and p.dport == tla.sport and p.src == tla.dst and p.sport == port))]
        syns = [p for p in own if p.sport == tla.sport and p.flags & SYN and not p.flags & ACK]
        if len(syns) - 1 != a["syn_retransmits"]:
            raise DatasetError(f"{rid}: capture has {len(syns) - 1} SYN retransmits for port {a['src_port']}, "
                               f"record {a['syn_retransmits']}")
        synack = next((p for p in own if p.ts_ns == tla.synack_ns and p.sport == port and p.flags & SYN), None)
        ack = next((p for p in own if p.ts_ns == tla.handshake_ack_ns and p.sport == tla.sport), None)
        rst = next((p for p in own if p.flags & RST), None)
        if a["result"] == "won":
            winner_ack_ns = tla.handshake_ack_ns
        for p in own:
            tcp_frames[p.frame_no] = (i, p)
        out_att.append({"n": i, "fam": a["family"], "dst": a["dst"], "port": a["src_port"],
                        "res": a["result"], "rtx": a["syn_retransmits"], "syn": ev(syns[0]),
                        "rtx_ev": [ev(p) for p in syns[1:]], "synack": ev(synack) if synack else None,
                        "ack": ev(ack) if ack else None,
                        "rst": dict(ev(rst), by="client" if rst.sport == tla.sport else "server") if rst else None})

    setup = _val(record["metrics"]["tcp_setup_time_ms"])
    if setup is not None and (winner_ack_ns is None or abs(_ms(winner_ack_ns, t0) - setup) > TOLERANCE_MS):
        raise DatasetError(f"{rid}: handshake ACK in the capture does not match the record's TCP setup time")

    # DNS: the exchanges the record's DNS time counts (target name, queried no later than the first SYN)
    counted = [d for d in tl.dns if _name(d.qname) == _name(target) and d.query_ns <= t0]
    dns, dns_frames = [], {}
    for d in sorted(counted, key=lambda d: d.query_ns):
        q = next(p for p in inwin if p.ts_ns == d.query_ns and p.proto == "udp" and p.dport == 53)
        r = next((p for p in inwin if p.ts_ns == d.response_ns and p.proto == "udp" and p.sport == 53), None)
        dns.append({"type": d.qtype, "q": ev(q), "a": ev(r) if r else None, "rcode": d.rcode,
                    "answers": d.answers})
        dns_frames[q.frame_no] = ("query", d)
        if r:
            dns_frames[r.frame_no] = ("answer", d)
    dns_time = _val(record["metrics"]["dns_time_ms"])
    if dns_time is not None and dns and all(x["a"] for x in dns):
        span = round(max(x["a"]["t"] for x in dns) - min(x["q"]["t"] for x in dns), 3)
        if abs(span - dns_time) > 2 * TOLERANCE_MS:
            raise DatasetError(f"{rid}: DNS span in the capture ({span} ms) does not match the record ({dns_time})")

    out = {"attempts": out_att, "dns": dns, "rows": None, "rows_note": None}
    if rows:
        out["rows"], out["rows_note"] = packet_rows(inwin, tcp_frames, dns_frames, winner_ack_ns, t0,
                                                    record.get("environment", {}).get("capture_interfaces") or {})
    return out


def packet_rows(inwin: list[Packet], tcp_frames: dict, dns_frames: dict, winner_ack_ns: int | None, t0: int,
                ifaces: dict) -> tuple[list[dict], str]:
    """The packets behind the chart, in capture order: the counted DNS exchanges and each attempt's TCP
    packets up to the ACK completing the winning handshake (RSTs at any time)."""
    rows, later = [], 0
    for p in inwin:
        what = None
        if p.frame_no in dns_frames:
            kind, d = dns_frames[p.frame_no]
            what = (f"DNS query {d.qtype} {d.qname.rstrip('.')}" if kind == "query" else
                    f"DNS answer {d.qtype} {d.rcode}" + (f": {', '.join(d.answers)}" if d.answers else ", no records"))
            attempt = None
        elif p.frame_no in tcp_frames:
            attempt, _ = tcp_frames[p.frame_no]
            if winner_ack_ns is not None and p.ts_ns > winner_ack_ns and not p.flags & RST:
                later += 1
                continue
            what = _flags(p) + (f", {len(p.payload)} bytes" if p.payload else "")
            if p.ts_ns == winner_ack_ns:
                what += ": completes the winning handshake (end of TCP setup time)"
        if what is None:
            continue
        rows.append({"f": p.frame_no, "t": _ms(p.ts_ns, t0),
                     "if": ifaces.get(str(p.ifindex), f"#{p.ifindex}") if p.ifindex is not None else "",
                     "dir": "" if p.outgoing is None else ("out" if p.outgoing else "in"), "fam": p.family,
                     "src": _addr(p.src, p.sport), "dst": _addr(p.dst, p.dport), "what": what, "att": attempt})
    other = len(inwin) - len(rows) - later
    note = (f"{len(rows)} of {len(inwin)} packets in the run's capture window. Not listed: {later} later packets "
            f"of the attempts (the HTTP exchange and close) and {other} other packets (DNS for other names, "
            "neighbour discovery, anything not to the target port).")
    return rows, note


def _addr(a: str | None, port: int | None) -> str:
    if a is None:
        return ""
    if port is None:
        return a
    return f"[{a}]:{port}" if ":" in a else f"{a}:{port}"


# --- per-run payload ----------------------------------------------------------------------

def record_only(record: dict) -> dict:
    """Events from the record alone (no capture): SYN times and the winner's handshake ACK."""
    rec_att = sorted(_val(record["packet_observations"]["attempts"]) or [], key=lambda a: a["first_syn_ns"])
    if not rec_att:
        return {"attempts": [], "dns": None, "rows": None, "rows_note": None}
    t0 = rec_att[0]["first_syn_ns"]
    setup = _val(record["metrics"]["tcp_setup_time_ms"])
    return {"attempts": [{"n": i, "fam": a["family"], "dst": a["dst"], "port": a["src_port"], "res": a["result"],
                          "rtx": a["syn_retransmits"], "syn": {"t": _ms(a["first_syn_ns"], t0), "f": None},
                          "rtx_ev": None, "synack": None,
                          "ack": {"t": setup, "f": None} if a["result"] == "won" and setup is not None else None,
                          "rst": None}
                         for i, a in enumerate(rec_att, 1)],
            "dns": None, "rows": None, "rows_note": None}


def payload(run: Run, record: dict, events: dict, source: str, capture: str | None) -> dict:
    met = record["metrics"]
    return {
        "id": run.run_id, "cl": run.client, "sc": run.scenario, "rep": run.repetition, "label": run.label,
        "ok": run.success, "win": run.winner, "setup": run.setup_ms,
        "ifd": run.inter_family_ms, "ifd_note": met["inter_family_attempt_delay_ms"].get("note"),
        "dns": run.dns_ms, "dns_note": met["dns_time_ms"].get("note"),
        "src": source, "capture": capture,
        "att": events["attempts"], "dq": events["dns"], "rows": events["rows"], "rows_note": events["rows_note"],
        "orc": {"setup": run.oracle_setup_ms, "cost": run.cost_of_racing_ms, "status": run.oracle_status,
                "note": run.oracle_note, "single": run.single_family},
    }


def find_capture(run_id: str, record: dict, repo: Path, examples: Path | None) -> tuple[Path | None, str | None]:
    """(path, shown path) of a capture whose SHA-256 matches the record; examples/ first. A present but
    mismatching capture is refused."""
    want = record["evidence"]["pcap_sha256"]
    for path, shown in (((examples / f"{run_id}.pcap"), f"examples/{run_id}.pcap") if examples else (None, None),
                        (repo / record["evidence"]["pcap_path"], record["evidence"]["pcap_path"])):
        if path is not None and path.is_file():
            if _sha256(path) != want:
                raise DatasetError(f"{run_id}: {shown} does not match the record's pcap_sha256")
            return path, shown
    return None, None


def build(runs: list[Run], clients, scenarios, records: dict[str, dict], repo: Path | None = REPO,
          examples: Path | None = EXAMPLES_DIR) -> dict:
    """Everything the dashboard's race timeline needs, for every run of the dataset.

    records: run_id -> run record. repo=None draws every run from its record alone (no capture read).
    """
    example_ids = sorted(p.stem for p in examples.glob("*.json")) if examples and examples.is_dir() else []
    out_runs, cells = {}, {}
    for run in runs:
        rec = records[run.run_id]
        path = shown = None
        if repo is not None:
            path, shown = find_capture(run.run_id, rec, repo, examples)
        if path is not None:
            ev, src = wire(path, rec, rows=run.run_id in example_ids), "pcap"
        else:
            ev, src = record_only(rec), "record"
        out_runs[run.run_id] = payload(run, rec, ev, src, shown)
        cells.setdefault(run.scenario, {}).setdefault(run.client, []).append(run)
    reps = {}
    for s, by_c in cells.items():
        for c, rs in by_c.items():
            rep = representative(rs)
            reps.setdefault(s, {})[c] = rep.run_id if rep else None
            by_c[c] = [r.run_id for r in sorted(rs, key=lambda r: r.repetition)]
    default, why = default_run(runs, clients, scenarios)
    shown_examples = [i for i in example_ids if i in out_runs and out_runs[i]["rows"] is not None]
    return {"runs": out_runs, "cells": cells, "representative": reps,
            "scenarios": [s for s in scenarios if s in cells], "clients": [c for c in clients
                                                                         if any(c in v for v in cells.values())],
            "default": default.run_id if default else None, "default_why": why,
            "examples": shown_examples, "oracle_evidence": ORACLE_EVIDENCE}


def load_records(runs: list[Run], runs_dir: Path = RUNS_DIR) -> dict[str, dict]:
    out = {}
    for run in runs:
        rec = json.loads((runs_dir / f"{run.run_id}.json").read_text(encoding="utf-8"))
        if rec["run_id"] != run.run_id:
            raise DatasetError(f"{runs_dir / run.run_id}.json holds run {rec['run_id']}")
        out[run.run_id] = rec
    return out
