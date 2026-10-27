"""Tests for the batch checker and the matrix runner's pure parts (no sudo, no lab)."""

import hashlib
import json
from pathlib import Path

import pytest

from analysis import check_batch as cb
from runner import run_matrix as rm
from tests.test_orchestrate import _s1_record


def _make_run(repo: Path, session: str, rep: int, *, record=True, pcap=True, tamper=False,
              post_ok=True, dirty=False, scenario="S1", client="curl", ts=None):
    """One run as the orchestrator leaves it: run log, pcap and a valid record built from the S1 fixture."""
    ts = ts or f"20261027T09{rep:02d}00Z"
    run_id = f"{ts}_{scenario}_{client}_r{rep:02d}"
    gen = repo / "data" / "generated"
    for d in ("logs", "runs"):
        (gen / d).mkdir(parents=True, exist_ok=True)
    (repo / "captures").mkdir(exist_ok=True)
    (gen / "logs" / f"{run_id}.log").write_text(f"run_id: {run_id}\nscenario: {scenario} {{}}\nsession: {session}\n")
    data = b"pcap-bytes-" + run_id.encode()
    if pcap:
        (repo / "captures" / f"{run_id}.pcap").write_bytes(data)
    if record:
        r = _s1_record()
        r["run_id"] = run_id
        r["scenario"]["repetition"] = rep
        r["evidence"]["pcap_path"] = f"captures/{run_id}.pcap"
        r["evidence"]["pcap_sha256"] = hashlib.sha256(b"other" if tamper else data).hexdigest()
        r["evidence"]["post_restore_verify_ok"] = post_ok
        r["environment"] = {"git_commit": "15ffa67-dirty" if dirty else "15ffa67", "session_id": session}
        (gen / "runs" / f"{run_id}.json").write_text(json.dumps(r))
    return run_id


def test_clean_batch_passes(tmp_path):
    for rep in (1, 2, 3):
        _make_run(tmp_path, "SESS", rep)
    _make_run(tmp_path, "OTHER", 1, ts="20261027T080000Z")  # another session: ignored
    res = cb.check_batch("curl", "S1", 3, ["SESS"], repo=tmp_path)
    assert res.ok and res.records == res.pcaps == 3 and res.missing_reps == []
    assert "RESULT: PASS" in cb.report(res)


def test_flags_and_rerun_commands(tmp_path):
    _make_run(tmp_path, "SESS", 1)
    _make_run(tmp_path, "SESS", 2, tamper=True)          # hash mismatch
    _make_run(tmp_path, "SESS", 3, post_ok=False)        # failed post-restore verify
    _make_run(tmp_path, "SESS", 4, record=False)         # stopped before writing the record
    _make_run(tmp_path, "SESS", 5, dirty=True)           # uncommitted code
    res = cb.check_batch("curl", "S1", 7, ["SESS"], repo=tmp_path)
    assert not res.ok
    flags = {r.rep: r.problems for r in res.runs if not r.good}
    assert flags[2] == ["pcap hash does not match the record"]
    assert flags[3] == ["post-restore verify did not pass"]
    assert flags[4] == ["no record (run stopped before writing it; see its run log)"]
    assert flags[5] == ["code version is -dirty (uncommitted changes)"]
    assert res.missing_reps == [2, 3, 4, 5, 6, 7]
    assert "pcap count (5) differs from record count (4)" in res.batch_problems
    assert cb.rerun_commands(res) == [
        "sudo .venv/bin/python src/runner/orchestrate.py --client curl --scenario S1 --first-rep 2 --reps 6"]
    # nothing was changed on disk
    assert len(list((tmp_path / "data/generated/runs").glob("*.json"))) == 4


def test_rerun_session_completes_batch(tmp_path):
    _make_run(tmp_path, "FIRST", 1)
    _make_run(tmp_path, "FIRST", 2, post_ok=False)
    _make_run(tmp_path, "RERUN", 2, ts="20261027T100000Z")
    res = cb.check_batch("curl", "S1", 2, ["FIRST", "RERUN"], repo=tmp_path)
    assert res.missing_reps == [] and not res.ok  # still FAIL: the flagged run is reported, never hidden
    assert [r.rep for r in res.runs if not r.good] == [2]


def test_rerun_commands_split_gaps(tmp_path):
    for rep in (2, 3, 5):
        _make_run(tmp_path, "S", rep)
    res = cb.check_batch("curl", "S1", 6, ["S"], repo=tmp_path)
    assert [c.split("--first-rep ")[1] for c in cb.rerun_commands(res)] == ["1 --reps 1", "4 --reps 1", "6 --reps 1"]


def test_wrong_client_and_duplicates_flagged(tmp_path):
    _make_run(tmp_path, "S", 1, client="chromium")
    _make_run(tmp_path, "S", 1)
    _make_run(tmp_path, "S", 1, ts="20261027T110000Z")
    res = cb.check_batch("curl", "S1", 1, ["S"], repo=tmp_path)
    assert any("not curl/S1" in p for r in res.runs for p in r.problems)
    assert any("more than one good record: [1]" in p for p in res.batch_problems)


def test_no_runs_found(tmp_path):
    res = cb.check_batch("curl", "S1", 20, ["NOPE"], repo=tmp_path)
    assert not res.ok and res.batch_problems[0].startswith("no runs found")


# --- run_matrix -----------------------------------------------------------------------

def test_matrix_plan_is_14_batches_in_scenario_order():
    assert len(rm.PLAN) == 14 and rm.REPS == 20
    assert rm.PLAN[:3] == [("C0", "curl"), ("C0", "chromium"), ("S1", "curl")]
    assert rm.PLAN[-1] == ("S6", "chromium")


def test_select():
    assert [n for n, _, _ in rm.select(rm.PLAN, start=13)] == [13, 14]
    assert rm.select(rm.PLAN, only="S3:chromium") == [(8, "S3", "chromium")]


def test_orchestrator_cmd_and_session_id():
    cmd = rm.orchestrator_cmd("S4", "chromium")
    assert cmd[0].endswith(".venv/bin/python") and cmd[1].endswith("src/runner/orchestrate.py")
    assert cmd[2:] == ["--client", "chromium", "--scenario", "S4", "--reps", "20"]
    assert rm.session_id("x\n20 record(s) written; session log data/generated/lab/20261027T090000Z_session.log\n") \
        == "20261027T090000Z"
    assert rm.session_id("no session here") is None


def test_matrix_dry_run_needs_no_sudo(capsys):
    assert rm.main(["--dry-run", "--from", "13"]) == 0
    out = capsys.readouterr().out
    assert "2 of 14 batches" in out and "--scenario S6" in out and "--client chromium" in out


def test_matrix_refuses_sudo_e(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/opt/ros/jazzy/lib/python3.12/site-packages")
    with pytest.raises(SystemExit, match="sudo -E"):
        rm.main([])
