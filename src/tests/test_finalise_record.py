"""Tests for finalise_record: writing the pcap hash into a run record."""

import hashlib
import json
from datetime import datetime, timezone

import pytest

from analysis.validate_record import validate
from runner import client_curl as cc
from runner.finalise_record import FinaliseError, finalise, main

PCAP_BYTES = bytes.fromhex("d4c3b2a1") + b"\x00" * 20  # pcap magic + dummy header


@pytest.fixture
def run(tmp_path):
    """A repo-like tmp dir with one record, its log and its capture."""
    start = datetime(2026, 10, 25, 12, 0, 5, tzinfo=timezone.utc)
    run_id = cc.make_run_id(start, 1)
    (tmp_path / "captures").mkdir()
    (tmp_path / "logs").mkdir()
    pcap = tmp_path / "captures" / f"{run_id}.pcap"
    pcap.write_bytes(PCAP_BYTES)
    log = tmp_path / "logs" / f"{run_id}.log"
    log.write_text("run log\n", encoding="utf-8")
    record = cc.build_record(
        run_id=run_id, repetition=1, run_start=start, argv=["curl", "x"], version="curl 8.5.0",
        start_ns=10, end_ns=20, returncode=0, stdout="200", stderr="",
        pcap_path=f"captures/{run_id}.pcap", log_path=f"logs/{run_id}.log")
    path = tmp_path / f"{run_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return tmp_path, path, pcap, log


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_fills_hash_and_stays_valid(run):
    repo, path, pcap, log = run
    digest, changed = finalise(path, repo)
    assert changed
    assert digest == hashlib.sha256(PCAP_BYTES).hexdigest()
    rec = load(path)
    assert rec["evidence"]["pcap_sha256"] == digest
    assert validate(rec) == []
    assert f"pcap_sha256={digest}" in log.read_text()
    assert not path.with_suffix(".json.tmp").exists()


def test_second_run_is_a_no_op(run):
    repo, path, _, log = run
    finalise(path, repo)
    before = log.read_text()
    _, changed = finalise(path, repo)
    assert not changed
    assert log.read_text() == before


def test_changed_capture_is_an_error(run):
    repo, path, pcap, _ = run
    finalise(path, repo)
    pcap.write_bytes(PCAP_BYTES + b"extra")
    with pytest.raises(FinaliseError, match="capture changed"):
        finalise(path, repo)


def test_missing_capture(run):
    repo, path, pcap, _ = run
    pcap.unlink()
    with pytest.raises(FinaliseError, match="capture not found"):
        finalise(path, repo)


def test_not_a_pcap(run):
    repo, path, pcap, _ = run
    pcap.write_bytes(b"hello world")
    with pytest.raises(FinaliseError, match="not a pcap"):
        finalise(path, repo)


def test_pcapng_magic_accepted(run):
    repo, path, pcap, _ = run
    pcap.write_bytes(bytes.fromhex("0a0d0d0a") + b"\x00" * 20)
    assert finalise(path, repo)[1]


def test_record_without_pcap_path(run):
    repo, path, _, _ = run
    rec = load(path)
    rec["evidence"]["pcap_path"] = None
    path.write_text(json.dumps(rec), encoding="utf-8")
    with pytest.raises(FinaliseError, match="pcap_path is null"):
        finalise(path, repo)


def test_cli_reports_failure(tmp_path, capsys):
    assert main([str(tmp_path / "missing.json")]) == 1
    assert "FAILED" in capsys.readouterr().out
