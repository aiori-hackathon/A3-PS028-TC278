"""Half-ms delays, manifests with absent cells, fixed --reps, the campaign chain and crossover reports."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from analysis import crossover as cx
from analysis.scenario_config import load_config
from analysis.summarise import DatasetError, load_manifest
from runner import fractional_delay_check as fd
from runner import orchestrate as o
from runner import run_campaigns as rc
from runner import run_matrix as rm
from runner.child_env import child_env

REPO = Path(__file__).resolve().parents[2]
NETEM = str(REPO / "src" / "lab" / "netem.sh")


# --- half-ms delay ---------------------------------------------------------------------------

def test_delay_arg_keeps_whole_ms_verbatim_and_allows_a_half():
    assert o.delay_arg(10) == "10" and o.delay_arg(310) == "310" and o.delay_arg(110.0) == "110"
    assert o.delay_arg(72.5) == "72.5" and o.delay_arg(107.5) == "107.5"
    for bad in (72.25, -1, "10", True, 0.1):
        with pytest.raises(o.OrchestratorError):
            o.delay_arg(bad)


def test_odd_n_scenarios_get_exact_half_ms_netem_commands():
    sc = load_config()["scenarios"]
    assert o.netem_for("v6", sc["Gv6d125"]["v6"]) == [NETEM, "v6", "72.5", "0"]
    assert o.netem_for("v6", sc["Gv6d195"]["v6"]) == [NETEM, "v6", "107.5", "0"]
    assert o.netem_for("v6", sc["Gv6d305"]["v6"]) == [NETEM, "v6", "162.5", "0"]
    assert o.netem_for("v6", sc["Gv6d300"]["v6"]) == [NETEM, "v6", "160", "0"]     # even N: whole ms as before
    assert sc["Gv6d195"]["verify_target"]["v6"] == 215 and sc["Gv6d305"]["verify_target"]["v6"] == 325


# --- the fractional-delay check -------------------------------------------------------------

def test_fractional_check_steps_must_be_one_ms():
    assert fd.steps_verdict([214.0, 215.0, 216.0])["verdict"] == "PASS"
    assert fd.steps_verdict([214.2, 214.9, 216.1])["verdict"] == "PASS"
    assert fd.steps_verdict([214.0, 214.0, 216.0])["verdict"] == "FAIL"    # half ms truncated
    assert fd.steps_verdict([214.0, 216.0, 216.0])["verdict"] == "FAIL"    # half ms rounded up
    assert fd.steps_verdict([214.0, 215.0])["verdict"] == "FAIL"


def test_fractional_check_reads_ping_values_and_refuses_whole_ms_scenarios():
    out = "64 bytes from 2001:db8:28:6::2: icmp_seq=1 ttl=64 time=215 ms\n" \
          "64 bytes from 2001:db8:28:6::2: icmp_seq=2 ttl=64 time=216 ms\n"
    assert fd.ping_times(out) == [215.0, 216.0]
    with pytest.raises(o.OrchestratorError):
        fd.check_ids(o.load_scenarios(["Gv6d200"]), ["Gv6d200"])
    fd.check_ids(o.load_scenarios(["Gv6d195"]), ["Gv6d195"])


def test_fractional_check_plan_restores_the_baseline_last():
    steps = fd.plan(o.load_scenarios(["Gv6d195"]), ["Gv6d195"])
    assert [s[2][2] for s in steps if s[1].startswith("set v6")] == ["107", "107.5", "108"]
    assert steps[-3:] == [("baseline", "restore", [NETEM, "v4", "10", "0"]),
                          ("baseline", "restore", [NETEM, "v6", "10", "0"]),
                          ("baseline", "verify", o.cmd_verify(20, 20))]


# --- manifests with absent cells -------------------------------------------------------------

def _manifest(tmp: Path, header_extra: str, rows: list[tuple[str, str]]) -> Path:
    p = tmp / "m.md"
    table = "\n".join(f"| {i} | {c} | {s} | `2026120{i}T100000Z` | x |" for i, (c, s) in enumerate(rows, 1))
    p.write_text(f"---\nclients: [curl, chromium]\nscenarios: [Gv6d190, Gv6d290]\nreps: 5\n{header_extra}---\n"
                 f"# t\n\n## Sessions in the dataset\n\n| # | Client | Scenario | Session | Note |\n|---|---|---|---|---|\n"
                 f"{table}\n", encoding="utf-8")
    return p


def test_manifest_with_absent_cells(tmp_path):
    m = load_manifest(_manifest(tmp_path, "absent_cells: [chromium:Gv6d190, curl:Gv6d290]\n",
                                [("curl", "Gv6d190"), ("chromium", "Gv6d290")]), require_header=True)
    assert sorted(m.shape.cells) == [("chromium", "Gv6d290"), ("curl", "Gv6d190")]


@pytest.mark.parametrize("extra, rows, msg", [
    ("", [("curl", "Gv6d190"), ("chromium", "Gv6d290")], "exactly one session"),          # absent not declared
    ("absent_cells: [chromium:Gv6d190]\n", [("curl", "Gv6d190"), ("chromium", "Gv6d290")], "exactly one session"),
    ("absent_cells: [chromium:Gv6d190, curl:Gv6d290]\n", [("curl", "Gv6d190"), ("chromium", "Gv6d290"),
                                                          ("curl", "Gv6d290")], "exactly one session"),  # absent but listed
    ("absent_cells: [chromium:Gv6d999]\n", [], "not a declared"),
    ("absent_cells: [chromium:Gv6d190, chromium:Gv6d190]\n", [], "twice"),
    ("absent_cells: [chromium:Gv6d190, chromium:Gv6d290]\n", [], "no cell"),
    ("absent_cells: chromium:Gv6d190\n", [], "list of 'client:scenario'"),
])
def test_manifest_absent_cells_refusals(tmp_path, extra, rows, msg):
    with pytest.raises(DatasetError, match=msg):
        load_manifest(_manifest(tmp_path, extra, rows), require_header=True)


# --- run_matrix --reps -----------------------------------------------------------------------

def test_run_matrix_fixed_reps_in_the_plan(capsys):
    assert rm.main(["--dry-run", "--only", "Gv6d125:curl,S1:curl@he50", "--reps", "5"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Plan: 2 batches from the --only list, 5 reps each")
    assert out.count("--reps 5") == 2


@pytest.mark.parametrize("args", [["--reps", "0"], ["--reps", "5", "--reps-adaptive", "5", "10", "--ci-width-ms", "5"]])
def test_run_matrix_refuses_bad_reps(args):
    with pytest.raises(SystemExit):
        rm.main(["--dry-run", "--only", "Gv6d125:curl", *args])


# --- the campaign chain ----------------------------------------------------------------------

def test_campaign2_cells():
    c = rc.campaign2()
    assert len(c["batches"]) == 36 and c["reps"] == 5 and len(c["absent"]) == 10
    coarse = {f"Gv6d{n}" for n in range(100, 401, 25)}
    assert len(coarse) == 13
    for sid in coarse:
        assert (sid, "curl") in c["batches"] and (sid, "chromium") in c["batches"]
    assert {s for s, cl in c["batches"] if cl == "curl"} - coarse == {f"Gv6d{n}" for n in (190, 195, 205, 210, 215)}
    assert {s for s, cl in c["batches"] if cl == "chromium"} - coarse == {f"Gv6d{n}" for n in (290, 295, 305, 310, 315)}
    assert set(c["scenarios"]) <= set(load_config()["scenarios"])
    assert len(rm.select_list(rc.only_arg(c))) == 36


def test_campaign3_cells():
    c = rc.campaign3()
    assert c["reps"] == 10 and len(c["batches"]) == 27 and c["scenarios"] == ["C0", "S1", "S3"]
    assert c["clients"] == ["curl"] + [f"curl@he{n}" for n in (50, 100, 150, 200, 250, 300, 400, 500)]
    assert len(rm.select_list(rc.only_arg(c))) == 27


def test_manifest_from_matrix_summary_loads(tmp_path):
    c = rc.campaign2()
    log = "...\nSummary (40.0 min)\n" + "\n".join(
        f"  [{i:2d}] {cl:8} {s}  session 202612{i:02d}T100000Z  exit 0  check PASS"
        for i, (s, cl) in enumerate(c["batches"], 1)) + "\n"
    rows = rc.summary_rows(log)
    assert len(rows) == 36
    p = tmp_path / "latency-sweep.md"
    p.write_text(rc.manifest_text(c, rows, "abc1234", "2026-12-01"), encoding="utf-8")
    m = load_manifest(p, require_header=True)
    assert len(m.sessions) == 36 and len(m.shape.absent) == 10 and m.shape.reps == 5
    c3 = rc.campaign3()
    log3 = "Summary (1 min)\n" + "\n".join(f"  [{i:2d}] {cl:8} {s}  session 202612{i:02d}T110000Z  exit 0  check PASS"
                                          for i, (s, cl) in enumerate(c3["batches"], 1))
    p3 = tmp_path / "he-sweep.md"
    p3.write_text(rc.manifest_text(c3, rc.summary_rows(log3), "abc1234", "2026-12-01"), encoding="utf-8")
    assert len(load_manifest(p3, require_header=True).sessions) == 27


def test_summary_rows_drop_failed_batches():
    log = "Summary (1 min)\n  [ 1] curl     Gv6d100  session 20261201T100000Z  exit 0  check PASS\n" \
          "  [ 2] chromium Gv6d100  session 20261201T100500Z  exit 1  check FAIL\n"
    assert rc.summary_rows(log) == [("curl", "Gv6d100", "20261201T100000Z")]


def test_campaign_dry_run_needs_no_sudo_and_changes_nothing():
    p = subprocess.run([sys.executable, str(REPO / "src" / "runner" / "run_campaigns.py"), "--dry-run"],
                       capture_output=True, text=True, env=child_env())
    assert p.returncode == 0, p.stderr
    assert "TOTAL: 450 runs" in p.stdout
    assert "Plan: 36 batches" in p.stdout and "Plan: 27 batches" in p.stdout


# --- crossover reports -----------------------------------------------------------------------

def test_flip_bracket():
    cells = [{"rtt_ms": 205, "n": 5, "v6_wins": 5}, {"rtt_ms": 220, "n": 5, "v6_wins": 5},
             {"rtt_ms": 225, "n": 5, "v6_wins": 2}, {"rtt_ms": 230, "n": 5, "v6_wins": 0},
             {"rtt_ms": 245, "n": 5, "v6_wins": 0}]
    b = cx.flip_bracket(cells)
    assert (b["above_ms"], b["below_ms"], b["width_ms"], b["mixed_rtts_ms"]) == (220, 230, 10, [225])
    assert b["non_monotonic_rtts_ms"] == []
    b2 = cx.flip_bracket([{"rtt_ms": 220, "n": 5, "v6_wins": 0}, {"rtt_ms": 230, "n": 5, "v6_wins": 5}])
    assert b2["non_monotonic_rtts_ms"] == [220]
