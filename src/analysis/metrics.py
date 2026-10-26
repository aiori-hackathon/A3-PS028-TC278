"""Metrics from a reconstructed packet timeline, exactly as fixed in CLAUDE.md.

Fixed definitions (do not redefine):
- TCP setup time = first SYN of the run to the ACK completing the winning handshake.
  DNS time is separate.
- Inter-family attempt delay = second family's first SYN minus first family's first SYN;
  "not observed" if only one family is tried.
- Scenario penalty = client's median setup time in a scenario minus its own median in C0.

Project rules used here (documented in docs/run_record_schema.md):
- Winning attempt: the completed handshake on which the client sent data. If several
  connections carried data the run is ambiguous and nothing is picked.
- Attempt results: won; failed (server answered with RST); abandoned (any other
  attempt when a winner exists); no_reply (no SYN-ACK and no winner at all).
- DNS time: first DNS query to the last DNS answer, among queries sent before the first SYN.

Values are milliseconds rounded to the microsecond (pcap resolution).
Runner/client logs are never overwritten by packet data: disagreements are reported
by cross_check() and left for a person to resolve.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from analysis.parse_pcap import Attempt, Timeline


def _ms(ns: int) -> float:
    return round(ns / 1_000_000, 3)


def _wrapped(value=None, status="computed", note=None) -> dict:
    out = {"value": value, "status": status}
    if note:
        out["note"] = note
    return out


@dataclass
class RunMetrics:
    winner: Attempt | None
    results: list[tuple[Attempt, str]]
    first_syn_ns: int | None
    tcp_setup_time_ms: float | None
    inter_family_attempt_delay_ms: float | None
    dns_time_ms: float | None
    families_tried: list[str]
    notes: list[str] = field(default_factory=list)
    ambiguous: bool = False

    @property
    def winning_family(self) -> str | None:
        return self.winner.family if self.winner else None

    @property
    def failed_or_abandoned(self) -> int:
        return sum(1 for _, r in self.results if r != "won")


def classify(attempts: list[Attempt]) -> tuple[Attempt | None, list[tuple[Attempt, str]], list[str], bool]:
    """Return (winner, [(attempt, result)], notes, ambiguous)."""
    notes: list[str] = []
    used = [a for a in attempts if a.handshake_completed and a.client_data_bytes > 0]
    completed = [a for a in attempts if a.handshake_completed]
    ambiguous = False
    if len(used) == 1:
        winner = used[0]
    elif len(used) > 1:
        winner, ambiguous = None, True
        notes.append(f"ambiguous: {len(used)} connections carried client data; "
                     "capture probably spans more than one run (pass a time window)")
    elif completed:
        winner = completed[0]
        notes.append("no connection carried client data; winner is the first completed handshake")
    else:
        winner = None

    results = []
    for a in attempts:
        if a is winner:
            r = "won"
        elif a.server_rst_ns is not None and not a.handshake_completed:
            r = "failed"
        elif winner is not None or ambiguous or a.handshake_completed:
            r = "abandoned"
        else:
            r = "no_reply"
        results.append((a, r))
    return winner, results, notes, ambiguous


def compute(tl: Timeline) -> RunMetrics:
    winner, results, notes, ambiguous = classify(tl.attempts)
    first_syn = min((a.first_syn_ns for a in tl.attempts), default=None)

    setup = None
    if winner is not None and first_syn is not None:
        setup = _ms(winner.handshake_ack_ns - first_syn)

    first_by_family: dict[str, int] = {}
    for a in tl.attempts:
        first_by_family.setdefault(a.family, a.first_syn_ns)  # attempts are sorted by first SYN
    families = sorted(first_by_family, key=first_by_family.get)
    inter = None
    if len(families) >= 2:
        inter = _ms(first_by_family[families[1]] - first_by_family[families[0]])

    dns_time = None
    queries = [d for d in tl.dns if first_syn is None or d.query_ns <= first_syn]
    if queries:
        answered = [d.response_ns for d in queries if d.response_ns is not None]
        if len(answered) == len(queries):
            dns_time = _ms(max(answered) - min(d.query_ns for d in queries))
        else:
            notes.append("a DNS query before the first SYN got no answer; DNS time not computed")

    return RunMetrics(winner=winner, results=results, first_syn_ns=first_syn,
                      tcp_setup_time_ms=setup, inter_family_attempt_delay_ms=inter,
                      dns_time_ms=dns_time, families_tried=families, notes=notes,
                      ambiguous=ambiguous)


def record_fields(m: RunMetrics, tl: Timeline) -> tuple[dict, dict]:
    """Return (packet_observations, metrics) blocks for a run record."""
    review = "; ".join(m.notes) if m.notes else None
    if m.ambiguous:
        pending = _wrapped(None, "not_yet_computed", review)
        winning = setup = pending
    else:
        winning = (_wrapped(m.winning_family) if m.winner
                   else _wrapped(None, "not_observed", "no completed handshake in capture"))
        setup = (_wrapped(m.tcp_setup_time_ms) if m.tcp_setup_time_ms is not None
                 else _wrapped(None, "not_observed", "no completed handshake in capture"))

    attempts = [{"family": a.family, "dst": a.dst, "src_port": a.sport,
                 "first_syn_ns": a.first_syn_ns, "syn_retransmits": a.syn_retransmits,
                 "result": r} for a, r in m.results]
    obs = {
        "winning_family": winning,
        "attempts": _wrapped(attempts) if attempts else _wrapped(None, "not_observed", "no SYN in capture"),
        "failed_or_abandoned_attempts": (_wrapped(None, "not_yet_computed", review) if m.ambiguous
                                         else _wrapped(m.failed_or_abandoned)),
    }
    if m.inter_family_attempt_delay_ms is not None:
        inter = _wrapped(m.inter_family_attempt_delay_ms)
    else:
        tried = ", ".join(m.families_tried) or "none"
        inter = _wrapped(None, "not_observed", f"only one family tried ({tried})")
    metrics = {
        "dns_time_ms": (_wrapped(m.dns_time_ms) if m.dns_time_ms is not None
                        else _wrapped(None, "not_observed", "no complete DNS exchange before the first SYN")),
        "tcp_setup_time_ms": setup,
        "inter_family_attempt_delay_ms": inter,
        "scenario_penalty_ms": _wrapped(None, "not_applicable",
                                        "per-scenario aggregate; see scenario summary"),
    }
    return obs, metrics


def scenario_penalty(setup_times_ms: list[float], c0_setup_times_ms: list[float]) -> float | None:
    """Median setup time in a scenario minus the same client's median in C0 (None if either is empty)."""
    if not setup_times_ms or not c0_setup_times_ms:
        return None
    return round(statistics.median(setup_times_ms) - statistics.median(c0_setup_times_ms), 3)


def cross_check(outcome: dict, client_report: dict | None, m: RunMetrics) -> dict:
    """Compare what the client/runner logs say with the capture. Never picks a side.

    outcome: the record's outcome block (success, http_status).
    client_report: optional extra values the client printed, e.g. {"remote_ip": "192.0.2.2"}.
    Returns {"status": "agree" | "conflict", "conflicts": [...]}.
    """
    conflicts = []

    def conflict(fld, log_value, pcap_value, note):
        conflicts.append({"field": fld, "log_value": log_value, "pcap_value": pcap_value, "note": note})

    pcap_success = m.winner is not None and m.winner.http_status is not None
    if m.ambiguous:
        conflict("winner", None, None, "capture is ambiguous (more than one connection carried data)")
    elif outcome.get("success") and not pcap_success:
        conflict("success", True, False, "client reports success but the capture has no "
                 "completed connection with an HTTP response")
    elif outcome.get("success") is False and pcap_success:
        conflict("success", False, True, "client reports failure but the capture shows an HTTP response")

    pcap_status = m.winner.http_status if m.winner else None
    log_status = outcome.get("http_status")
    if log_status is not None and pcap_status is not None and log_status != pcap_status:
        conflict("http_status", log_status, pcap_status, "HTTP status differs")

    remote_ip = (client_report or {}).get("remote_ip")
    if remote_ip and m.winner is not None and remote_ip != m.winner.dst:
        conflict("remote_ip", remote_ip, m.winner.dst,
                 "client's connected address differs from the winning handshake's destination")

    return {"status": "conflict" if conflicts else "agree", "conflicts": conflicts}
