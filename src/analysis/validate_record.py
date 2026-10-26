"""Validate HappyLab run records against schema version 0.1.

The schema is documented in docs/run_record_schema.md. Standard library only.

Usage: python -m analysis.validate_record FILE [FILE ...]   (with src/ on the path)
Exit code 0 if every file is valid, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0.2"
# 0.1 records (Milestone 1 harness runs) stay valid; 0.2 adds the required cross_checks block.
SUPPORTED_VERSIONS = {"0.1", "0.2"}
CROSS_CHECK_STATUSES = {"agree", "conflict", "not_yet_computed", "not_applicable"}

STATUSES = {"computed", "not_yet_computed", "not_observed", "not_applicable"}
SCENARIO_IDS = {"C0", "S1", "S2", "S3", "S4", "S5", "S6", "X1", "harness-test"}
CLIENT_NAMES = {"curl", "chromium"}
FAMILIES = {"v4", "v6"}
ATTEMPT_RESULTS = {"won", "failed", "abandoned", "no_reply"}

TOP_LEVEL_KEYS = {
    "schema_version", "run_id", "scenario", "client", "environment",
    "timestamps", "outcome", "evidence", "packet_observations", "metrics",
}
PACKET_OBSERVATION_KEYS = {"winning_family", "attempts", "failed_or_abandoned_attempts"}
METRIC_KEYS = {
    "dns_time_ms", "tcp_setup_time_ms", "inter_family_attempt_delay_ms", "scenario_penalty_ms",
}
NON_NEGATIVE_METRICS = {"dns_time_ms", "tcp_setup_time_ms", "inter_family_attempt_delay_ms"}

RUN_ID_RE = re.compile(
    r"^\d{8}T\d{6}Z_(?P<scenario>C0|S[1-6]|X1|harness-test)_(?P<client>curl|chromium)_r\d{2,}$"
)


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _check_wrapped(errors: list[str], path: str, field: Any) -> bool:
    """Check the {value, status[, note]} shape. Returns True if the value should be type-checked."""
    if not isinstance(field, dict):
        errors.append(f"{path}: must be an object with 'value' and 'status'")
        return False
    missing = {"value", "status"} - field.keys()
    if missing:
        errors.append(f"{path}: missing {sorted(missing)}")
        return False
    extra = field.keys() - {"value", "status", "note"}
    if extra:
        errors.append(f"{path}: unexpected keys {sorted(extra)}")
    if "note" in field and not isinstance(field["note"], str):
        errors.append(f"{path}.note: must be a string")
    status = field["status"]
    if status not in STATUSES:
        errors.append(f"{path}.status: {status!r} not in {sorted(STATUSES)}")
        return False
    if status == "computed":
        if field["value"] is None:
            errors.append(f"{path}: status 'computed' but value is null")
            return False
        return True
    if field["value"] is not None:
        errors.append(f"{path}: status {status!r} requires value null")
    return False


def _require_keys(errors: list[str], path: str, obj: Any, keys: set[str]) -> bool:
    if not isinstance(obj, dict):
        errors.append(f"{path}: must be an object")
        return False
    missing = keys - obj.keys()
    if missing:
        errors.append(f"{path}: missing {sorted(missing)}")
    return True


def _check_attempt(errors: list[str], path: str, a: Any) -> None:
    keys = {"family", "dst", "src_port", "first_syn_ns", "syn_retransmits", "result"}
    if not _require_keys(errors, path, a, keys):
        return
    if a.get("family") not in FAMILIES:
        errors.append(f"{path}.family: must be one of {sorted(FAMILIES)}")
    if not isinstance(a.get("dst"), str):
        errors.append(f"{path}.dst: must be a string")
    for k in ("src_port", "first_syn_ns", "syn_retransmits"):
        if k in a and not (_is_int(a[k]) and a[k] >= 0):
            errors.append(f"{path}.{k}: must be a non-negative integer")
    if a.get("result") not in ATTEMPT_RESULTS:
        errors.append(f"{path}.result: must be one of {sorted(ATTEMPT_RESULTS)}")


def _check_cross_checks(errors: list[str], cc: Any) -> None:
    """Log-versus-pcap comparison. Conflicts keep both values; nothing is chosen silently."""
    if not _require_keys(errors, "cross_checks", cc, {"status", "conflicts"}):
        return
    status, conflicts = cc.get("status"), cc.get("conflicts")
    if status not in CROSS_CHECK_STATUSES:
        errors.append(f"cross_checks.status: must be one of {sorted(CROSS_CHECK_STATUSES)}")
    if not isinstance(conflicts, list):
        errors.append("cross_checks.conflicts: must be a list")
        return
    if status == "conflict" and not conflicts:
        errors.append("cross_checks: status 'conflict' but no conflicts listed")
    if status != "conflict" and conflicts:
        errors.append(f"cross_checks: status {status!r} must have no conflicts")
    for i, c in enumerate(conflicts):
        p = f"cross_checks.conflicts[{i}]"
        if _require_keys(errors, p, c, {"field", "log_value", "pcap_value", "note"}):
            for k in ("field", "note"):
                if not isinstance(c.get(k), str):
                    errors.append(f"{p}.{k}: must be a string")


def validate(record: Any) -> list[str]:
    """Return a list of human-readable problems; an empty list means the record is valid."""
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record: must be a JSON object"]

    version = record.get("schema_version")
    if version not in SUPPORTED_VERSIONS:
        errors.append(f"schema_version: must be one of {sorted(SUPPORTED_VERSIONS)}")
    top_keys = TOP_LEVEL_KEYS | ({"cross_checks"} if version != "0.1" else set())
    missing = top_keys - record.keys()
    if missing:
        errors.append(f"record: missing {sorted(missing)}")
    extra = record.keys() - top_keys
    if extra:
        errors.append(f"record: unexpected keys {sorted(extra)}")
    if "cross_checks" in top_keys and "cross_checks" in record:
        _check_cross_checks(errors, record["cross_checks"])

    # scenario
    sc = record.get("scenario")
    if _require_keys(errors, "scenario", sc,
                     {"id", "label", "repetition", "netem", "dns", "measured_rtt_ms"}):
        if sc.get("id") not in SCENARIO_IDS:
            errors.append(f"scenario.id: {sc.get('id')!r} not in {sorted(SCENARIO_IDS)}")
        if not isinstance(sc.get("label"), str):
            errors.append("scenario.label: must be a string")
        rep = sc.get("repetition")
        if not (_is_int(rep) and rep >= 1):
            errors.append("scenario.repetition: must be an integer >= 1")
        for k in ("netem", "dns"):
            if k in sc and sc[k] is not None and not isinstance(sc[k], dict):
                errors.append(f"scenario.{k}: must be an object or null")
        rtt = sc.get("measured_rtt_ms")
        if _require_keys(errors, "scenario.measured_rtt_ms", rtt, FAMILIES):
            for fam in sorted(FAMILIES & rtt.keys()):
                p = f"scenario.measured_rtt_ms.{fam}"
                if _check_wrapped(errors, p, rtt[fam]) and not (
                        _is_number(rtt[fam]["value"]) and rtt[fam]["value"] >= 0):
                    errors.append(f"{p}.value: must be a non-negative number")

    # client
    cl = record.get("client")
    if _require_keys(errors, "client", cl, {"name", "version", "argv", "config"}):
        if cl.get("name") not in CLIENT_NAMES:
            errors.append(f"client.name: must be one of {sorted(CLIENT_NAMES)}")
        if not (isinstance(cl.get("version"), str) and cl.get("version")):
            errors.append("client.version: must be a non-empty string")
        argv = cl.get("argv")
        if not (isinstance(argv, list) and argv and all(isinstance(x, str) for x in argv)):
            errors.append("client.argv: must be a non-empty list of strings")
        if "config" in cl and not isinstance(cl["config"], dict):
            errors.append("client.config: must be an object")

    # run_id must agree with scenario and client
    run_id = record.get("run_id")
    m = RUN_ID_RE.match(run_id) if isinstance(run_id, str) else None
    if not m:
        errors.append("run_id: must look like <yyyymmddThhmmssZ>_<scenario>_<client>_r<NN>")
    else:
        if isinstance(sc, dict) and m["scenario"] != sc.get("id"):
            errors.append("run_id: scenario part does not match scenario.id")
        if isinstance(cl, dict) and m["client"] != cl.get("name"):
            errors.append("run_id: client part does not match client.name")

    if not isinstance(record.get("environment"), dict):
        errors.append("environment: must be an object")

    # timestamps
    ts = record.get("timestamps")
    ts_keys = {"run_start_utc", "client_start_epoch_ns", "client_end_epoch_ns",
               "capture_start_epoch_ns", "capture_end_epoch_ns"}
    if _require_keys(errors, "timestamps", ts, ts_keys):
        start = ts.get("run_start_utc")
        try:
            if not (isinstance(start, str) and start.endswith("Z")):
                raise ValueError
            datetime.fromisoformat(start.replace("Z", "+00:00"))
        except ValueError:
            errors.append("timestamps.run_start_utc: must be ISO 8601 UTC ending in 'Z'")
        for k in ("client_start_epoch_ns", "client_end_epoch_ns"):
            if k in ts and not (_is_int(ts[k]) and ts[k] > 0):
                errors.append(f"timestamps.{k}: must be a positive integer")
        for k in ("capture_start_epoch_ns", "capture_end_epoch_ns"):
            if k in ts and ts[k] is not None and not (_is_int(ts[k]) and ts[k] > 0):
                errors.append(f"timestamps.{k}: must be a positive integer or null")
        for a, b in (("client_start_epoch_ns", "client_end_epoch_ns"),
                     ("capture_start_epoch_ns", "capture_end_epoch_ns")):
            if _is_int(ts.get(a)) and _is_int(ts.get(b)) and ts[b] < ts[a]:
                errors.append(f"timestamps.{b}: earlier than {a}")

    # outcome
    oc = record.get("outcome")
    if _require_keys(errors, "outcome", oc,
                     {"success", "exit_code", "http_status", "error", "source"}):
        if not isinstance(oc.get("success"), bool):
            errors.append("outcome.success: must be true or false")
        for k in ("exit_code", "http_status"):
            if k in oc and oc[k] is not None and not _is_int(oc[k]):
                errors.append(f"outcome.{k}: must be an integer or null")
        if "error" in oc and oc["error"] is not None and not isinstance(oc["error"], str):
            errors.append("outcome.error: must be a string or null")
        if not isinstance(oc.get("source"), str):
            errors.append("outcome.source: must be a string")

    # evidence
    ev = record.get("evidence")
    if _require_keys(errors, "evidence", ev, {"pcap_path", "pcap_sha256", "client_log_path",
                                               "pre_verify_ok", "post_restore_verify_ok"}):
        for k in ("pcap_path", "client_log_path"):
            if k in ev and ev[k] is not None and not isinstance(ev[k], str):
                errors.append(f"evidence.{k}: must be a string or null")
        sha = ev.get("pcap_sha256")
        if sha is not None and not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
            errors.append("evidence.pcap_sha256: must be 64 lowercase hex characters or null")
        if sha is not None and ev.get("pcap_path") is None:
            errors.append("evidence.pcap_sha256: set but pcap_path is null")
        for k in ("pre_verify_ok", "post_restore_verify_ok"):
            if k in ev and ev[k] is not None and not isinstance(ev[k], bool):
                errors.append(f"evidence.{k}: must be true, false or null")

    # packet observations
    po = record.get("packet_observations")
    if _require_keys(errors, "packet_observations", po, PACKET_OBSERVATION_KEYS):
        extra = po.keys() - PACKET_OBSERVATION_KEYS
        if extra:
            errors.append(f"packet_observations: unexpected keys {sorted(extra)}")
        if "winning_family" in po and _check_wrapped(
                errors, "packet_observations.winning_family", po["winning_family"]):
            if po["winning_family"]["value"] not in FAMILIES:
                errors.append("packet_observations.winning_family.value: must be 'v4' or 'v6'")
        if "attempts" in po and _check_wrapped(errors, "packet_observations.attempts",
                                               po["attempts"]):
            val = po["attempts"]["value"]
            if not isinstance(val, list):
                errors.append("packet_observations.attempts.value: must be a list")
            else:
                for i, a in enumerate(val):
                    _check_attempt(errors, f"packet_observations.attempts.value[{i}]", a)
        p = "packet_observations.failed_or_abandoned_attempts"
        if "failed_or_abandoned_attempts" in po and _check_wrapped(
                errors, p, po["failed_or_abandoned_attempts"]):
            v = po["failed_or_abandoned_attempts"]["value"]
            if not (_is_int(v) and v >= 0):
                errors.append(f"{p}.value: must be a non-negative integer")

    # metrics
    me = record.get("metrics")
    if _require_keys(errors, "metrics", me, METRIC_KEYS):
        extra = me.keys() - METRIC_KEYS
        if extra:
            errors.append(f"metrics: unexpected keys {sorted(extra)}")
        for k in sorted(METRIC_KEYS & me.keys()):
            p = f"metrics.{k}"
            if _check_wrapped(errors, p, me[k]):
                v = me[k]["value"]
                if not _is_number(v):
                    errors.append(f"{p}.value: must be a number")
                elif k in NON_NEGATIVE_METRICS and v < 0:
                    errors.append(f"{p}.value: must be >= 0")
        pen = me.get("scenario_penalty_ms")
        if isinstance(pen, dict) and pen.get("status") != "not_applicable":
            errors.append("metrics.scenario_penalty_ms: must be 'not_applicable' in a per-run record")

    return errors


def validate_file(path: str | Path) -> list[str]:
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"could not read JSON: {exc}"]
    return validate(record)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    ok = True
    for name in argv:
        problems = validate_file(name)
        if problems:
            ok = False
            print(f"INVALID {name}")
            for p in problems:
                print(f"  - {p}")
        else:
            print(f"OK      {name}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
