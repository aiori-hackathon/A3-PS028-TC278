"""Tests for the run-record validator (schema 0.1)."""

import copy
import json
from pathlib import Path

import pytest

from analysis.validate_record import main, validate, validate_file

REPO = Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "docs" / "examples" / "run_record_example.json"


@pytest.fixture
def record():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def computed(value):
    return {"value": value, "status": "computed"}


def test_example_is_valid(record):
    assert validate(record) == []


def test_validate_file_on_example():
    assert validate_file(EXAMPLE) == []


def test_unreadable_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert validate_file(bad)[0].startswith("could not read JSON")


def test_non_object_record():
    assert validate([]) == ["record: must be a JSON object"]


# --- {value, status} pattern -------------------------------------------------

def test_computed_with_null_value_rejected(record):
    record["metrics"]["tcp_setup_time_ms"] = {"value": None, "status": "computed"}
    assert any("status 'computed' but value is null" in e for e in validate(record))


@pytest.mark.parametrize("status", ["not_yet_computed", "not_observed", "not_applicable"])
def test_non_computed_status_requires_null(record, status):
    record["metrics"]["dns_time_ms"] = {"value": 12.0, "status": status}
    assert any("requires value null" in e for e in validate(record))


def test_unknown_status_rejected(record):
    record["metrics"]["dns_time_ms"] = {"value": None, "status": "pending"}
    assert any("dns_time_ms.status" in e for e in validate(record))


def test_bare_null_rejected(record):
    record["metrics"]["dns_time_ms"] = None
    assert any("must be an object with 'value' and 'status'" in e for e in validate(record))


def test_missing_status_rejected(record):
    record["metrics"]["dns_time_ms"] = {"value": None}
    assert any("missing ['status']" in e for e in validate(record))


def test_note_allowed_extra_key_rejected(record):
    record["metrics"]["dns_time_ms"]["note"] = "fine"
    assert validate(record) == []
    record["metrics"]["dns_time_ms"]["extra"] = 1
    assert any("unexpected keys ['extra']" in e for e in validate(record))


def test_inter_family_not_observed_is_valid(record):
    record["metrics"]["inter_family_attempt_delay_ms"] = {
        "value": None, "status": "not_observed", "note": "only one family attempted"}
    assert validate(record) == []


# --- computed values ---------------------------------------------------------

def test_fully_computed_record_is_valid(record):
    record["packet_observations"] = {
        "winning_family": computed("v4"),
        "attempts": computed([
            {"family": "v6", "dst": "2001:db8:28:6::2", "src_port": 40000,
             "first_syn_ns": 1, "syn_retransmits": 1, "result": "abandoned"},
            {"family": "v4", "dst": "192.0.2.2", "src_port": 40001,
             "first_syn_ns": 2, "syn_retransmits": 0, "result": "won"},
        ]),
        "failed_or_abandoned_attempts": computed(1),
    }
    record["metrics"]["dns_time_ms"] = computed(1.5)
    record["metrics"]["tcp_setup_time_ms"] = computed(221.3)
    record["metrics"]["inter_family_attempt_delay_ms"] = computed(200)
    record["scenario"]["measured_rtt_ms"]["v4"] = computed(20.4)
    assert validate(record) == []


def test_bad_winning_family(record):
    record["packet_observations"]["winning_family"] = computed("ipv4")
    assert any("winning_family.value" in e for e in validate(record))


def test_negative_setup_time_rejected(record):
    record["metrics"]["tcp_setup_time_ms"] = computed(-1)
    assert any("tcp_setup_time_ms.value: must be >= 0" in e for e in validate(record))


def test_bool_is_not_a_number(record):
    record["metrics"]["tcp_setup_time_ms"] = computed(True)
    assert any("tcp_setup_time_ms.value: must be a number" in e for e in validate(record))


def test_bad_attempt_rejected(record):
    record["packet_observations"]["attempts"] = computed([{"family": "v5"}])
    errors = validate(record)
    assert any("attempts.value[0]: missing" in e for e in errors)
    assert any("attempts.value[0].family" in e for e in errors)


def test_negative_failed_attempts_rejected(record):
    record["packet_observations"]["failed_or_abandoned_attempts"] = computed(-1)
    assert any("failed_or_abandoned_attempts.value" in e for e in validate(record))


def test_penalty_must_be_not_applicable_per_run(record):
    record["metrics"]["scenario_penalty_ms"] = computed(5.0)
    assert any("scenario_penalty_ms: must be 'not_applicable'" in e for e in validate(record))


# --- structure ---------------------------------------------------------------

def test_missing_and_extra_top_level_keys(record):
    del record["evidence"]
    record["typo"] = 1
    errors = validate(record)
    assert any("missing ['evidence']" in e for e in errors)
    assert any("unexpected keys ['typo']" in e for e in errors)


def test_wrong_schema_version(record):
    record["schema_version"] = "9.9"
    assert any(e.startswith("schema_version") for e in validate(record))


def test_v01_record_without_cross_checks_still_valid(record):
    record["schema_version"] = "0.1"
    del record["cross_checks"]
    assert validate(record) == []


def test_v01_record_must_not_have_cross_checks(record):
    record["schema_version"] = "0.1"
    assert any("unexpected keys ['cross_checks']" in e for e in validate(record))


def test_v02_requires_cross_checks(record):
    del record["cross_checks"]
    assert any("missing ['cross_checks']" in e for e in validate(record))


def test_cross_check_conflict_keeps_both_values(record):
    record["cross_checks"] = {"status": "conflict", "conflicts": [
        {"field": "remote_ip", "log_value": "192.0.2.2", "pcap_value": "2001:db8:28:6::2",
         "note": "differs"}]}
    assert validate(record) == []


@pytest.mark.parametrize("cc,msg", [
    ({"status": "conflict", "conflicts": []}, "no conflicts listed"),
    ({"status": "agree", "conflicts": [{"field": "x", "log_value": 1, "pcap_value": 2, "note": "n"}]},
     "must have no conflicts"),
    ({"status": "maybe", "conflicts": []}, "cross_checks.status"),
    ({"status": "conflict", "conflicts": [{"field": "x"}]}, "missing"),
])
def test_bad_cross_checks(record, cc, msg):
    record["cross_checks"] = cc
    assert any(msg in e for e in validate(record))


def test_unknown_scenario_rejected(record):
    record["scenario"]["id"] = "S9"
    assert any("scenario.id" in e for e in validate(record))


def test_run_id_must_match_scenario_and_client(record):
    record["run_id"] = "20261026T101500Z_C0_chromium_r03"
    errors = validate(record)
    assert any("scenario part does not match" in e for e in errors)
    assert any("client part does not match" in e for e in errors)


def test_malformed_run_id(record):
    record["run_id"] = "run-3"
    assert any(e.startswith("run_id: must look like") for e in validate(record))


def test_harness_test_record_with_no_capture_is_valid(record):
    r = copy.deepcopy(record)
    r["run_id"] = "20261025T120000Z_harness-test_curl_r01"
    r["scenario"].update(id="harness-test", label="loopback harness test", repetition=1,
                         netem=None, dns=None)
    r["timestamps"]["capture_start_epoch_ns"] = None
    r["timestamps"]["capture_end_epoch_ns"] = None
    r["evidence"].update(pcap_path=None, pcap_sha256=None,
                         pre_verify_ok=None, post_restore_verify_ok=None)
    assert validate(r) == []


def test_end_before_start_rejected(record):
    ts = record["timestamps"]
    ts["client_end_epoch_ns"] = ts["client_start_epoch_ns"] - 1
    assert any("client_end_epoch_ns: earlier than" in e for e in validate(record))


def test_run_start_must_be_utc_z(record):
    record["timestamps"]["run_start_utc"] = "2026-10-26 10:15:00"
    assert any("run_start_utc" in e for e in validate(record))


def test_success_must_be_bool(record):
    record["outcome"]["success"] = "yes"
    assert any("outcome.success" in e for e in validate(record))


def test_empty_argv_rejected(record):
    record["client"]["argv"] = []
    assert any("client.argv" in e for e in validate(record))


def test_sha_without_pcap_rejected(record):
    record["evidence"]["pcap_path"] = None
    record["evidence"]["pcap_sha256"] = "a" * 64
    assert any("pcap_path is null" in e for e in validate(record))


def test_cli_exit_codes(tmp_path, record, capsys):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(record), encoding="utf-8")
    record["schema_version"] = "9"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(record), encoding="utf-8")
    assert main([str(good)]) == 0
    assert main([str(good), str(bad)]) == 1
    assert "INVALID" in capsys.readouterr().out
