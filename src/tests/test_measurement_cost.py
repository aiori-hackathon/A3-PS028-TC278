"""Measurement cost (profile block), bootstrap CI on the median, adaptive repetitions and the replay."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from analysis import adaptive_replay as ar
from analysis import dashboard
from analysis import summarise as sm
from analysis.metrics import STOP_CI, STOP_MAX, adaptive_decision, bootstrap_median_ci
from analysis.validate_record import SCHEMA_VERSION, validate
from runner import orchestrate as o
from runner import run_matrix as rm
from tests.test_dataset_manifest import A, B, manifest
from tests.test_summarise import make_record, write

REPO = Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "examples" / "20261026T193106Z_S1_curl_r08.json"
FAST = {"resamples": 2000}


# --- bootstrap CI on the median ----------------------------------------------------------------

def test_ci_needs_two_values():
    assert bootstrap_median_ci([]) is None
    assert bootstrap_median_ci([20.0]) is None
    assert bootstrap_median_ci([20.0, None]) is None


def test_ci_is_reproducible_and_contains_the_median():
    v = [20.1, 20.4, 20.2, 20.9, 20.15, 20.3, 20.25]
    a, b = bootstrap_median_ci(v, **FAST), bootstrap_median_ci(v, **FAST)
    assert a == b
    assert a["lo"] <= 20.25 <= a["hi"] and a["width"] == pytest.approx(a["hi"] - a["lo"], abs=1e-3)
    assert a["n"] == 7 and a["level"] == 0.95 and a["method"] == "percentile bootstrap of the median"


def test_identical_values_give_a_zero_width_ci():
    ci = bootstrap_median_ci([20.0] * 5, **FAST)
    assert ci["lo"] == ci["hi"] == 20.0 and ci["width"] == 0


def test_ci_ignores_missing_values():
    assert bootstrap_median_ci([20.0, None, 21.0], **FAST)["n"] == 2


# --- stopping rule -----------------------------------------------------------------------------

NARROW = [20.0, 20.01, 20.02, 20.01, 20.0]


def test_continues_below_min_even_when_narrow():
    st = adaptive_decision(NARROW[:3], 5, 20, 1.0, **FAST)
    assert st["decision"] == "continue" and st["reason"] is None and st["ci"]["width"] <= 1.0


def test_stops_on_ci_width_at_min():
    st = adaptive_decision(NARROW, 5, 20, 0.5, **FAST)
    assert (st["decision"], st["reason"], st["n_runs"]) == ("stop", STOP_CI, 5)


def test_stops_at_max_when_still_wide():
    wide = [20.0, 30.0, 25.0, 40.0, 22.0, 35.0]
    assert adaptive_decision(wide[:5], 5, 6, 0.5, **FAST)["decision"] == "continue"
    st = adaptive_decision(wide, 5, 6, 0.5, **FAST)
    assert (st["decision"], st["reason"]) == ("stop", STOP_MAX)


def test_rule_ignores_the_level_of_the_median():
    shifted = [x + 200 for x in NARROW]
    a, b = adaptive_decision(NARROW, 5, 20, 0.5, **FAST), adaptive_decision(shifted, 5, 20, 0.5, **FAST)
    assert (a["decision"], a["reason"]) == (b["decision"], b["reason"])


def test_runs_without_setup_count_towards_max_only():
    st = adaptive_decision([20.0, None, 20.01, None], 2, 4, 0.001, **FAST)
    assert st["n_runs"] == 4 and st["n_values"] == 2 and st["reason"] == STOP_MAX


@pytest.mark.parametrize("args", [(0, 5, 1.0), (6, 5, 1.0), (5, 20, 0), (5, 20, -1)])
def test_bad_rule_settings_raise(args):
    with pytest.raises(ValueError):
        adaptive_decision([20.0], *args)


# --- schema 0.3 --------------------------------------------------------------------------------

def base_record() -> dict:
    r = json.loads(EXAMPLE.read_text())
    r["schema_version"] = "0.3"
    return r


PROFILE = o.profile_block(13.2, 1670, 4096)


def adaptive_rec(decision="continue", reason=None):
    return {"min_reps": 5, "max_reps": 20, "ci_width_ms": 0.5, "metric": "tcp_setup_time_ms",
            "after_this_run": {"n_runs": 5, "n_values": 5, "median_ms": 20.0,
                               "ci": bootstrap_median_ci(NARROW, **FAST), "decision": decision, "reason": reason}}


def test_schema_version_is_0_3_and_older_records_still_validate():
    assert SCHEMA_VERSION == "0.3"
    assert validate(json.loads(EXAMPLE.read_text())) == []      # a 0.2 record from the dataset


def test_0_3_record_with_profile_and_adaptive_is_valid():
    r = base_record()
    r["profile"], r["adaptive"] = PROFILE, adaptive_rec("stop", STOP_CI)
    assert validate(r) == []


def test_profile_and_adaptive_are_optional_in_0_3():
    assert validate(base_record()) == []


def test_0_2_record_may_not_carry_the_new_blocks():
    r = json.loads(EXAMPLE.read_text())
    r["profile"] = PROFILE
    assert any("unexpected keys ['profile']" in e for e in validate(r))


@pytest.mark.parametrize("change, message", [
    (lambda p: p.update(wall_time_s=-1), "wall_time_s"),
    (lambda p: p.update(pcap_bytes=1.5), "pcap_bytes"),
    (lambda p: p.update(client_peak_rss_kib="4 MB"), "client_peak_rss_kib"),
    (lambda p: p.pop("wall_time_scope"), "missing ['wall_time_scope']"),
    (lambda p: p.update(extra=1), "unexpected keys ['extra']"),
])
def test_bad_profile_is_refused(change, message):
    r = base_record()
    r["profile"] = copy.deepcopy(PROFILE)
    change(r["profile"])
    assert any(message in e for e in validate(r))


def test_peak_rss_may_be_null():
    r = base_record()
    r["profile"] = o.profile_block(13.2, 1670, None)
    assert validate(r) == []


@pytest.mark.parametrize("decision, reason, message", [
    ("stop", None, "a stop needs one of"),
    ("continue", STOP_CI, "must be null when the decision is 'continue'"),
    ("maybe", None, "decision: must be one of"),
])
def test_bad_adaptive_state_is_refused(decision, reason, message):
    r = base_record()
    r["adaptive"] = adaptive_rec(decision, reason)
    assert any(message in e for e in validate(r))


def test_adaptive_settings_are_checked():
    r = base_record()
    r["adaptive"] = adaptive_rec()
    r["adaptive"]["min_reps"] = 30
    assert any("min_reps <= max_reps" in e for e in validate(r))


# --- orchestrator: client runner, profile and adaptive blocks, CLI -----------------------------

def test_run_client_returns_output_exit_code_and_peak_rss():
    code = "import sys; b = bytearray(64 * 1024 * 1024); print('out'); print('err', file=sys.stderr); sys.exit(3)"
    proc, rss = o.run_client([sys.executable, "-c", code], {}, 30)
    assert (proc.returncode, proc.stdout, proc.stderr) == (3, "out\n", "err\n")
    assert rss >= 64 * 1024     # KiB: at least the 64 MiB it allocated


def test_run_client_times_out_like_subprocess_run():
    with pytest.raises(subprocess.TimeoutExpired):
        o.run_client([sys.executable, "-c", "import time; time.sleep(10)"], {}, 0.3)


@pytest.mark.parametrize("var", ["PYTHONPATH", "LD_LIBRARY_PATH"])
def test_run_client_refuses_an_env_with_stripped_vars(var, tmp_path):
    marker = tmp_path / "started"
    code = f"open({str(marker)!r}, 'w').close()"
    with pytest.raises(o.OrchestratorError, match=var):
        o.run_client([sys.executable, "-c", code], {var: "/opt/ros/jazzy/lib"}, 30)
    assert not marker.exists()      # refused before anything was started


def test_run_client_accepts_a_child_env():
    from runner.child_env import child_env
    proc, _ = o.run_client([sys.executable, "-c", "print('ok')"],
                           child_env({"PATH": "/usr/bin:/bin", "PYTHONPATH": "/x", "LD_LIBRARY_PATH": "/y"}), 30)
    assert proc.stdout == "ok\n"


def test_adaptive_block_adds_this_run_to_the_earlier_ones():
    rec = {"metrics": {"tcp_setup_time_ms": {"value": 20.0, "status": "computed"}}}
    blk = o.adaptive_block(NARROW[:4], rec, 5, 20, 0.5)
    assert blk["after_this_run"]["n_runs"] == 5 and blk["after_this_run"]["reason"] == STOP_CI
    rec["metrics"]["tcp_setup_time_ms"] = {"value": None, "status": "not_observed"}
    assert o.adaptive_block(NARROW[:4], rec, 5, 20, 0.5)["after_this_run"]["n_values"] == 4


def test_adaptive_summary_line():
    st = adaptive_decision(NARROW, 5, 20, 0.5, **FAST)
    line = o.adaptive_summary_line("S3", st)
    assert line.startswith("ADAPTIVE S3: stopped after 5 run(s), reason ci_width_reached") and "CI [" in line


@pytest.mark.parametrize("args", [
    ["--reps", "3", "--reps-adaptive", "5", "20", "--ci-width-ms", "1"],
    ["--reps-adaptive", "5", "20"],
    ["--reps-adaptive", "20", "5", "--ci-width-ms", "1"],
    ["--reps-adaptive", "5", "20", "--ci-width-ms", "0"],
    ["--reps-adaptive", "5", "20", "--ci-width-ms", "1", "--first-rep", "3"],
    ["--ci-width-ms", "1"],
])
def test_cli_refuses_inconsistent_adaptive_options(args):
    with pytest.raises(SystemExit):
        o.main(["--scenario", "S3", "--dry-run", *args])


def test_adaptive_dry_run(capsys):
    assert o.main(["--scenario", "S3", "--reps-adaptive", "5", "20", "--ci-width-ms", "0.5", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "at least 5, at most 20" in out and "no wider than 0.5 ms" in out and "repetition 1 of up to 20" in out


def test_write_adaptive_file(tmp_path):
    path = tmp_path / "s_adaptive.json"
    o.write_adaptive_file(path, [{"session": "S", "scenario": "S3", "status": "stopped_by_rule",
                                  "final": {"n_runs": 7}}])
    assert json.loads(path.read_text())["scenarios"][0]["final"]["n_runs"] == 7


# --- run_matrix --------------------------------------------------------------------------------

def test_matrix_passes_adaptive_options_through():
    cmd = rm.orchestrator_cmd("S3", "curl", adaptive=(10, 20, 0.5))
    assert cmd[-6:] == ["S3", "--reps-adaptive", "10", "20", "--ci-width-ms", "0.5"] and "--reps" not in cmd
    assert rm.orchestrator_cmd("S3", "curl")[-2:] == ["--reps", "20"]


def test_matrix_reads_the_adaptive_stop_from_the_session_file(tmp_path):
    o.write_adaptive_file(tmp_path / "X_adaptive.json", [
        {"session": "X", "scenario": "S3", "status": "stopped_by_rule", "final": {"n_runs": 12}}])
    assert rm.adaptive_runs("X", "S3", tmp_path) == 12
    assert rm.adaptive_runs("X", "S1", tmp_path) is None
    assert rm.adaptive_runs("missing", "S3", tmp_path) is None


# --- summarise: CI, cost, adaptive manifests ---------------------------------------------------

def adaptive_session(session, scenario, candidates, lo=3, hi=6, w=0.5, past_stop=0):
    """Records as the orchestrator writes them: the rule runs after each one, and the session ends at
    its first stop (past_stop > 0 keeps going that many runs further, to build a bad session)."""
    recs, prev = [], []
    for i, v in enumerate(candidates, 1):
        r = make_record(session, "curl", scenario, i, setup_ms=v)
        r["client"].update(version="curl 8.5.0 (test)", config={})
        r["adaptive"] = o.adaptive_block(prev, r, lo, hi, w)
        r["profile"] = o.profile_block(12.0 + i, 1700, 4000 + i)
        prev.append(v)
        recs.append(r)
        if r["adaptive"]["after_this_run"]["decision"] == "stop":
            if past_stop == 0:
                return recs
            past_stop -= 1
    raise AssertionError("candidates ran out before the rule stopped")


ADAPTIVE_HEADER = "clients: [curl]\nscenarios: [C0, S3]\nreps: {min: 3, max: 6, ci_width_ms: 0.5}\n"
ROWS = [("curl", "C0", A), ("curl", "S3", B)]


C0_VALUES = (20.0, 20.1, 20.05, 20.02)                 # narrow: stops by CI width at min (3)
S3_VALUES = (171.0, 175.0, 168.0, 171.1, 179.0, 171.05)  # wide: stops at max (6)


def adaptive_build(tmp_path, c0=C0_VALUES, s3=S3_VALUES):
    runs = tmp_path / "runs"
    write(runs, adaptive_session(A, "C0", list(c0)) + adaptive_session(B, "S3", list(s3)))
    doc = manifest(tmp_path, ADAPTIVE_HEADER, ROWS)
    return sm.build(manifest=sm.load_manifest(doc, require_header=True), runs_dir=runs, repo=None), runs, doc


def test_adaptive_manifest_builds_with_different_run_counts(tmp_path):
    (_, runs, summary), _, _ = adaptive_build(tmp_path)
    assert sm.load_manifest(manifest(tmp_path, ADAPTIVE_HEADER, ROWS, "m2.md")).shape.adaptive == (3, 6, 0.5)
    cells = summary["cells"]["curl"]
    assert cells["C0"]["n"] == 3 and cells["S3"]["n"] == 6
    assert summary["dataset"]["shape"]["adaptive"] == {"min": 3, "max": 6, "ci_width_ms": 0.5}


def test_adaptive_session_that_ran_past_its_stop_is_refused(tmp_path):
    (_, _, _), runs, doc = adaptive_build(tmp_path)
    extra = adaptive_session(A, "C0", list(C0_VALUES), past_stop=1)[-1]    # a 4th run after the stop
    write(runs, [extra])
    with pytest.raises(sm.DatasetError, match="decision 'stop', expected 'continue'"):
        sm.build(manifest=sm.load_manifest(doc, require_header=True), runs_dir=runs, repo=None)


def test_adaptive_record_whose_decision_does_not_replay_is_refused(tmp_path):
    (_, _, _), runs, doc = adaptive_build(tmp_path)
    p = next(runs.glob(f"{A}_C0_curl_r03.json"))             # the run where C0 stopped by CI width
    r = json.loads(p.read_text())
    r["metrics"]["tcp_setup_time_ms"]["value"] = 25.0         # changed after the decision: CI now wide
    p.write_text(json.dumps(r))
    with pytest.raises(sm.DatasetError, match="replays as"):
        sm.build(manifest=sm.load_manifest(doc, require_header=True), runs_dir=runs, repo=None)


def test_adaptive_settings_must_match_the_manifest(tmp_path):
    (_, _, _), runs, _ = adaptive_build(tmp_path)
    doc = manifest(tmp_path, ADAPTIVE_HEADER.replace("0.5", "0.25"), ROWS, "other.md")
    with pytest.raises(sm.DatasetError, match="differ from the manifest"):
        sm.build(manifest=sm.load_manifest(doc, require_header=True), runs_dir=runs, repo=None)


def test_fixed_reps_session_is_refused_by_an_adaptive_manifest(tmp_path):
    runs = tmp_path / "runs"
    recs = [make_record(A, "curl", "C0", i) for i in (1, 2, 3)] + [make_record(B, "curl", "S3", i) for i in (1, 2, 3)]
    write(runs, recs)
    doc = manifest(tmp_path, ADAPTIVE_HEADER, ROWS)
    with pytest.raises(sm.DatasetError, match="has no adaptive block"):
        sm.build(manifest=sm.load_manifest(doc, require_header=True), runs_dir=runs, repo=None)


@pytest.mark.parametrize("reps, message", [
    ("{min: 3, max: 6}", "exactly min, max and ci_width_ms"),
    ("{min: 7, max: 6, ci_width_ms: 1}", "1 <= min <= max"),
    ("{min: 3, max: 6, ci_width_ms: 0}", "positive number"),
    ("{min: 3, max: 6, ci_width_ms: 1, extra: 2}", "exactly min, max and ci_width_ms"),
])
def test_bad_adaptive_header_is_refused(tmp_path, reps, message):
    doc = manifest(tmp_path, f"clients: [curl]\nscenarios: [C0, S3]\nreps: {reps}\n", ROWS)
    with pytest.raises(sm.DatasetError, match=message):
        sm.load_manifest(doc, require_header=True)


def test_every_cell_gets_a_ci_and_no_mean_or_sd(tmp_path):
    (_, _, summary), _, _ = adaptive_build(tmp_path)
    for cell in summary["cells"]["curl"].values():
        assert cell["tcp_setup_median_ci95"]["n"] == cell["n"]
        flat = json.dumps(cell)
        assert '"mean"' not in flat and '"sd"' not in flat and "stdev" not in flat
    assert "MEDIAN TCP SETUP TIME, 95% CI" in sm.text_report(summary)


def test_cost_from_the_profile_block(tmp_path):
    (_, runs, summary), _, _ = adaptive_build(tmp_path)
    k = summary["cells"]["curl"]["C0"]["cost"]
    assert k["runs"] == 3 and k["wall_time_s"]["total"] == pytest.approx(13 + 14 + 15)
    assert k["pcap_bytes"]["total"] == 3 * 1700 and k["client_peak_rss_kib"]["max"] == 4003
    assert k["source"] == {"record profile": 3}
    report = sm.cost_report(summary)
    assert "total: 9 runs" in report and "4002 / 4003" in report


def test_cost_falls_back_to_session_log_and_pcap_for_old_records(tmp_path):
    runs, lab, caps = tmp_path / "runs", tmp_path / "lab", tmp_path / "captures"
    lab.mkdir()
    caps.mkdir()
    recs = [make_record(A, "curl", "C0", i) for i in (1, 2)]
    lines = []
    for r in recs:
        r["evidence"]["pcap_path"] = f"captures/{r['run_id']}.pcap"
        (tmp_path / r["evidence"]["pcap_path"]).write_bytes(b"x" * 100)
        lines.append(f"{r['run_id']}  http=200  win=v6  wall_s=12.50")
    (lab / f"{A}_session.log").write_text("\n".join(lines) + "\n")
    write(runs, recs)
    got = sm.load_runs([("curl", "C0", A)], runs, expected=2, repo=tmp_path, dns_scenarios=(), lab_dir=lab)
    assert [(r.wall_s, r.pcap_bytes, r.peak_rss_kib, r.cost_source) for r in got] == \
        [(12.5, 100, None, "session log and pcap on disk")] * 2


def test_dashboard_shows_the_ci_and_the_adaptive_shape(tmp_path):
    (_, runs, summary), _, _ = adaptive_build(tmp_path)
    page = dashboard.render(summary, runs, "")
    assert "3–6 adaptive repetitions (stop at a 95% CI width of 0.5 ms)" in page
    ci = summary["cells"]["curl"]["S3"]["tcp_setup_median_ci95"]
    assert f"CI {ci['lo']}–{ci['hi']}" in page


# --- replay ------------------------------------------------------------------------------------

def replay_runs(values, walls):
    return [sm.Run(run_id=f"r{i}", client="curl", scenario="C0", repetition=i, success=True, winner="v6",
                   setup_ms=v, inter_family_ms=None, inter_family_status="not_observed", failed_or_abandoned=0,
                   dns_ms=1.0, attempts=[], netlog_backup_jobs=None, netlog_v4_source=None,
                   resolved_families=None, wall_s=w, pcap_bytes=1000)
            for i, (v, w) in enumerate(zip(values, walls), 1)]


def test_replay_stops_where_the_rule_would_and_sums_measured_wall_time_of_the_rest():
    vals = NARROW + [20.3, 20.4, 19.9]
    walls = [10, 11, 12, 13, 14, 15, 16, 17]
    res = ar.replay_cell(replay_runs(vals, walls), 5, 8, 0.5)
    assert res["stop_after"] == 5 and res["reason"] == STOP_CI and res["runs_skipped"] == 3
    assert res["wall_s_skipped"] == 15 + 16 + 17 and res["pcap_bytes_skipped"] == 3000
    assert res["ci_at_stop_contains_median_all"] in (True, False)


def test_replay_cannot_go_beyond_the_recorded_runs():
    with pytest.raises(ValueError, match="cannot add runs"):
        ar.replay_cell(replay_runs(NARROW, [10] * 5), 5, 20, 0.5)


def test_replay_reports_missing_wall_times_as_unknown_not_zero():
    res = ar.replay_cell(replay_runs(NARROW + [20.0], [10, 10, 10, 10, 10, None]), 5, 6, 0.5)
    assert res["wall_s_skipped"] is None
