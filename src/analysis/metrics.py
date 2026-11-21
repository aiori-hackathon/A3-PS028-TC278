"""Metrics from a reconstructed packet timeline, exactly as fixed in CLAUDE.md.

Fixed definitions (do not redefine):
- TCP setup time = first SYN of the run to the ACK completing the winning handshake.
  DNS time is separate.
- Inter-family attempt delay = second family's first SYN minus first family's first SYN;
  "not observed" if only one family is tried.
- Scenario penalty = client's median setup time in a scenario minus its own median in C0.

Project addition (see oracle_baseline): oracle setup = the winning family's pre-run measured RTT;
cost of racing = TCP setup time minus that. It reads existing records and changes no fixed metric.

Project rules used here (documented in docs/run_record_schema.md):
- Winning attempt: the completed handshake on which the client sent data. If several
  connections carried data the run is ambiguous and nothing is picked.
- Attempt results: won; failed (server answered with RST); abandoned (any other
  attempt when a winner exists); no_reply (no SYN-ACK and no winner at all).
- Only TCP attempts to the target port (80) count as attempts. Any TCP attempt to another
  port, and any UDP/TCP traffic on 443 (QUIC, HTTPS upgrade), is "unexpected traffic".
- DNS time: first DNS query to the last DNS answer, among queries for the target name
  (www.hl.test) sent before the first SYN. Queries for other names are listed in notes.

Values are milliseconds rounded to the microsecond (pcap resolution).
Runner/client logs are never overwritten by packet data: disagreements are reported
by cross_check() and left for a person to resolve.
"""

from __future__ import annotations

import ipaddress
import random
import statistics
from dataclasses import dataclass, field

from analysis.parse_pcap import Attempt, Timeline

TARGET_PORT = 80
TARGET_NAME = "www.hl.test"
WATCHED_PORTS = (443,)  # QUIC (UDP) and HTTPS upgrade (TCP): must never appear in a run


def _name(qname: str) -> str:
    return qname.rstrip(".").lower()


def same_address(a: str | None, b: str | None) -> bool:
    """Compare addresses canonically ('[2001:DB8::2]' == '2001:db8::2')."""
    if a is None or b is None:
        return False

    def canon(x: str) -> str:
        x = x.strip()
        if x.startswith("[") and x.endswith("]"):
            x = x[1:-1]
        try:
            return str(ipaddress.ip_address(x))
        except ValueError:
            return x
    return canon(a) == canon(b)


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
    unexpected_traffic: list[str] = field(default_factory=list)
    dns_note: str | None = None

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


def unexpected_traffic(tl: Timeline, target_port: int = TARGET_PORT) -> list[str]:
    out = []
    for a in tl.attempts:
        if a.dport != target_port:
            out.append(f"TCP attempt to {a.dst} port {a.dport} (not the target port {target_port})")
    for p in tl.other_udp:
        if p.sport in WATCHED_PORTS or p.dport in WATCHED_PORTS:
            out.append(f"UDP {p.src}:{p.sport} -> {p.dst}:{p.dport} (QUIC port)")
    return out


def compute(tl: Timeline, target_port: int = TARGET_PORT, target_name: str | None = TARGET_NAME) -> RunMetrics:
    attempts = [a for a in tl.attempts if a.dport == target_port]
    winner, results, notes, ambiguous = classify(attempts)
    first_syn = min((a.first_syn_ns for a in attempts), default=None)
    unexpected = unexpected_traffic(tl, target_port)

    setup = None
    if winner is not None and first_syn is not None:
        setup = _ms(winner.handshake_ack_ns - first_syn)

    first_by_family: dict[str, int] = {}
    for a in attempts:
        first_by_family.setdefault(a.family, a.first_syn_ns)  # attempts are sorted by first SYN
    families = sorted(first_by_family, key=first_by_family.get)
    inter = None
    if len(families) >= 2:
        inter = _ms(first_by_family[families[1]] - first_by_family[families[0]])

    dns_time = None
    before = [d for d in tl.dns if first_syn is None or d.query_ns <= first_syn]
    queries = [d for d in before if target_name is None or _name(d.qname) == _name(target_name)]
    others = sorted({_name(d.qname) for d in before if d not in queries})
    dns_note = None
    if others:
        n_other = sum(1 for d in before if d not in queries)
        dns_note = (f"only {target_name} queries counted; {n_other} queries for other names "
                    f"before the first SYN not counted: {', '.join(others)}")
    if queries:
        answered = [d.response_ns for d in queries if d.response_ns is not None]
        if len(answered) == len(queries):
            dns_time = _ms(max(answered) - min(d.query_ns for d in queries))
        else:
            notes.append("a DNS query before the first SYN got no answer; DNS time not computed")

    return RunMetrics(winner=winner, results=results, first_syn_ns=first_syn,
                      tcp_setup_time_ms=setup, inter_family_attempt_delay_ms=inter,
                      dns_time_ms=dns_time, families_tried=families, notes=notes,
                      ambiguous=ambiguous, unexpected_traffic=unexpected, dns_note=dns_note)


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
        "dns_time_ms": (_wrapped(m.dns_time_ms, note=m.dns_note) if m.dns_time_ms is not None
                        else _wrapped(None, "not_observed", "; ".join(
                            x for x in ("no complete DNS exchange before the first SYN", m.dns_note) if x))),
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


ORACLE_EVIDENCE = ("derived: packet-level TCP setup time (pcap) minus the winning family's RTT measured by "
                   "the lab verify step before the run (ping median)")


def oracle_baseline(winning_family: str | None, tcp_setup_time_ms: float | None,
                    measured_rtt_ms: dict | None, families_tried: list[str] | None = None,
                    dns_delay_ms: dict | None = None) -> dict:
    """Oracle baseline for one run (project metric, added alongside the fixed ones, not replacing them).

    oracle_setup_ms   = the measured RTT of the family that won this run
                        (the record's scenario.measured_rtt_ms[winning_family]; never a modelled constant)
    cost_of_racing_ms = tcp_setup_time_ms - oracle_setup_ms

    measured_rtt_ms is the record block: {family: {"value", "status", ...}}. Both outputs use the
    record's {"value", "status", "note"} convention. Nothing is clamped: a negative cost (setup faster
    than the pre-run ping median) is reported as it is. Cases handled explicitly:
      - no winning family, or no setup time       -> not_observed
      - winning family's RTT not computed/missing -> not_available, with the RTT's own status
      - only one family tried                     -> computed, single_family=True, with a note:
                                                     no race took place, the value is handshake
                                                     time against ping RTT only
      - a configured DNS answer delay             -> computed, with a note: TCP setup excludes DNS,
                                                     so that delay is not in cost_of_racing_ms
    """
    tried = list(families_tried or [])
    single = len(set(tried)) == 1 if tried else None
    notes = []
    if single:
        notes.append(f"only {tried[0]} was tried: no race took place, so this is the handshake time "
                     "minus the pre-run ping RTT, not a cost of racing")
    delayed = {t: v for t, v in (dns_delay_ms or {}).items() if v}
    if delayed:
        what = ", ".join(f"{t} {v} ms" for t, v in sorted(delayed.items()))
        notes.append(f"DNS answer delay configured ({what}); TCP setup excludes DNS, so that delay is not "
                     "in cost_of_racing_ms and shows in dns_time_ms instead")

    def out(oracle, cost):
        return {"oracle_setup_ms": oracle, "cost_of_racing_ms": cost, "single_family": single,
                "evidence": ORACLE_EVIDENCE}

    if winning_family is None:
        nw = _wrapped(None, "not_observed", "no winning family in this run")
        return out(nw, nw)
    rtt = (measured_rtt_ms or {}).get(winning_family)
    if not rtt or rtt.get("status") != "computed" or rtt.get("value") is None:
        status = rtt.get("status", "missing") if rtt else "missing"
        na = _wrapped(None, "not_available",
                      f"measured RTT for the winning family {winning_family} is {status}")
        return out(na, na)
    oracle = _wrapped(round(float(rtt["value"]), 3), note="; ".join(notes) or None)
    if tcp_setup_time_ms is None:
        return out(oracle, _wrapped(None, "not_observed", "no TCP setup time in this run"))
    cost = _wrapped(round(tcp_setup_time_ms - float(rtt["value"]), 3), note="; ".join(notes) or None)
    return out(oracle, cost)


# --- bootstrap CI on the median and the adaptive stopping rule -----------------------------

BOOT_LEVEL = 0.95
BOOT_RESAMPLES = 10_000
BOOT_SEED = 0          # fixed, so a CI can be recomputed exactly from the same values
BOOT_METHOD = "percentile bootstrap of the median"


def bootstrap_median_ci(values: list[float], level: float = BOOT_LEVEL, resamples: int = BOOT_RESAMPLES,
                        seed: int = BOOT_SEED) -> dict | None:
    """Percentile bootstrap confidence interval for the median. None with fewer than 2 values.

    Resamples the values with replacement `resamples` times (seeded, so it is reproducible), takes
    each resample's median, and returns the (1-level)/2 and (1+level)/2 percentiles of those medians.
    With few values (about 10 or fewer) a percentile bootstrap tends to give intervals that are too
    narrow, and the interval can only take values near the observed order statistics; read it as a
    description of spread, not an exact coverage guarantee. It is not a significance test.
    """
    v = [float(x) for x in values if x is not None]
    if len(v) < 2:
        return None
    rng = random.Random(seed)
    n = len(v)
    meds = sorted(statistics.median(rng.choices(v, k=n)) for _ in range(resamples))
    lo_i = int((1 - level) / 2 * resamples)
    hi_i = min(resamples - 1, int((1 + level) / 2 * resamples) - 1)
    lo, hi = meds[lo_i], meds[hi_i]
    return {"lo": round(lo, 3), "hi": round(hi, 3), "width": round(hi - lo, 3), "level": level, "n": n,
            "resamples": resamples, "seed": seed, "method": BOOT_METHOD}


STOP_CI = "ci_width_reached"
STOP_MAX = "max_reps_reached"


def adaptive_decision(setup_times_ms: list[float | None], min_reps: int, max_reps: int, ci_width_ms: float,
                      resamples: int = BOOT_RESAMPLES, seed: int = BOOT_SEED) -> dict:
    """Stopping rule after the runs so far (one entry per run; None where no TCP setup time was observed).

    - fewer than min_reps runs: continue
    - CI on the median of the observed setup times no wider than ci_width_ms: stop (ci_width_reached)
    - otherwise, max_reps runs reached: stop (max_reps_reached)
    - otherwise: continue
    The rule looks only at the CI width, never at the median's value, so it cannot stop on a
    convenient result. Runs without a setup time count towards max_reps but not towards the CI.
    """
    if not (1 <= min_reps <= max_reps):
        raise ValueError(f"need 1 <= min_reps <= max_reps, got {min_reps}, {max_reps}")
    if not ci_width_ms > 0:
        raise ValueError(f"ci_width_ms must be positive, got {ci_width_ms}")
    n_runs = len(setup_times_ms)
    values = [x for x in setup_times_ms if x is not None]
    ci = bootstrap_median_ci(values, resamples=resamples, seed=seed)
    if n_runs < min_reps:
        decision, reason = "continue", None
    elif ci is not None and ci["width"] <= ci_width_ms:
        decision, reason = "stop", STOP_CI
    elif n_runs >= max_reps:
        decision, reason = "stop", STOP_MAX
    else:
        decision, reason = "continue", None
    return {"n_runs": n_runs, "n_values": len(values),
            "median_ms": round(statistics.median(values), 3) if values else None,
            "ci": ci, "decision": decision, "reason": reason}


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
    if remote_ip and m.winner is not None and not same_address(remote_ip, m.winner.dst):
        conflict("remote_ip", remote_ip, m.winner.dst,
                 "client's connected address differs from the winning handshake's destination")
    elif not remote_ip and outcome.get("success") and client_report is not None:
        conflict("remote_ip", None, m.winner.dst if m.winner else None,
                 "client reported success without a connected address; winning family unchecked")

    if m.unexpected_traffic:
        conflict("unexpected_traffic", None, m.unexpected_traffic,
                 "traffic other than DNS and TCP to the target port (QUIC/HTTPS upgrade not off, "
                 "or another connection)")

    return {"status": "conflict" if conflicts else "agree", "conflicts": conflicts}
