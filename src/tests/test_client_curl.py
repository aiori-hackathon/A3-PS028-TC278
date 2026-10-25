"""Tests for the Milestone 1 curl harness runner."""

import json
import shutil
import socket
from datetime import datetime, timezone

import pytest

from analysis.validate_record import validate
from runner import client_curl as cc


@pytest.mark.parametrize("stdout,expected", [
    ("200", 200), ("404\n", 404), ("000", None), ("", None), ("abc", None),
])
def test_parse_http_code(stdout, expected):
    assert cc.parse_http_code(stdout) == expected


def test_make_run_id():
    start = datetime(2026, 10, 25, 12, 0, 5, tzinfo=timezone.utc)
    assert cc.make_run_id(start, 3) == "20261025T120005Z_harness-test_curl_r03"


def test_argv_ignores_curlrc_first():
    argv = cc.curl_argv("http://127.0.0.1:8080/")
    assert argv[:2] == ["curl", "-q"]
    assert argv[-1] == "http://127.0.0.1:8080/"


def _record(returncode=0, stdout="200", stderr=""):
    start = datetime(2026, 10, 25, 12, 0, 5, tzinfo=timezone.utc)
    return cc.build_record(
        run_id=cc.make_run_id(start, 1), repetition=1, run_start=start,
        argv=cc.curl_argv("http://127.0.0.1:8080/"), version="curl 8.5.0",
        start_ns=10, end_ns=20, returncode=returncode, stdout=stdout, stderr=stderr,
        pcap_path=None, log_path="data/generated/logs/x.log")


def test_build_record_success_is_valid():
    r = _record()
    assert validate(r) == []
    assert r["outcome"]["success"] is True
    assert r["metrics"]["tcp_setup_time_ms"] == {"value": None, "status": "not_yet_computed"}
    assert r["scenario"]["id"] == "harness-test"


def test_build_record_failure_is_valid_and_reports_error():
    r = _record(returncode=7, stdout="000", stderr="curl: (7) Failed to connect")
    assert validate(r) == []
    assert r["outcome"]["success"] is False
    assert r["outcome"]["http_status"] is None
    assert "Failed to connect" in r["outcome"]["error"]


def test_build_record_failure_without_stderr_still_has_error():
    r = _record(returncode=28, stdout="000", stderr="")
    assert r["outcome"]["error"] == "curl exit code 28, no HTTP response"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
def test_end_to_end_on_loopback(tmp_path):
    path, record = cc.run(1, None, None, tmp_path, port=_free_port())
    assert path.exists()
    on_disk = json.loads(path.read_text())
    assert validate(on_disk) == []
    assert on_disk["outcome"]["success"] is True
    assert on_disk["outcome"]["http_status"] == 200
    ts = on_disk["timestamps"]
    assert ts["client_end_epoch_ns"] >= ts["client_start_epoch_ns"]
    with pytest.raises(FileExistsError):
        cc.run(1, record["run_id"], None, tmp_path, port=_free_port())
