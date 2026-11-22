"""Scenario grid generator, generated-ID rules, and the core scenarios staying byte-identical."""

import hashlib
from datetime import datetime, timezone

import pytest
import yaml

from analysis import summarise as sm
from analysis.names import CORE_SCENARIOS, InvalidName, check_generated_id, is_generated_id
from analysis.scenario_config import (GENERATED_FILE, SCENARIOS_FILE, ScenarioConfigError, load_config,
                                      scenario_ids)
from analysis.validate_record import validate
from runner import orchestrate as o
from runner import scenario_grid as sg
from tests.test_dataset_manifest import A, manifest
from tests.test_summarise import make_record, write

# --- core scenarios: byte-identical -------------------------------------------------------------

# sha256 of src/config/scenarios.yaml as used for the frozen core dataset (commit ecba28c, 2026-10-26).
# If this fails, the file that defines C0 and S1-S6 has changed: that is not allowed. Extensions go
# in scenario_grid.yaml (generated), never in scenarios.yaml.
CORE_FILE_SHA256 = "509ecd95f454fba1dc859ff39c3d21f9c24b6b7eb1a77a5a87089b3ccfe8ae6a"

CORE = {
    "C0": {"label": "Healthy baseline (control)", "v4": {"delay_ms_each_way": 10, "loss_pct": 0},
           "v6": {"delay_ms_each_way": 10, "loss_pct": 0}, "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
           "verify_target": {"v4": 20, "v6": 20}},
    "S1": {"label": "IPv6 blackhole", "v4": {"delay_ms_each_way": 10, "loss_pct": 0},
           "v6": {"delay_ms_each_way": 10, "loss_pct": 100}, "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
           "verify_target": {"v4": 20, "v6": "blackhole"}},
    "S2": {"label": "IPv6 +600 ms RTT", "v4": {"delay_ms_each_way": 10, "loss_pct": 0},
           "v6": {"delay_ms_each_way": 310, "loss_pct": 0}, "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
           "verify_target": {"v4": 20, "v6": 620}},
    "S3": {"label": "IPv6 +150 ms RTT", "v4": {"delay_ms_each_way": 10, "loss_pct": 0},
           "v6": {"delay_ms_each_way": 85, "loss_pct": 0}, "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
           "verify_target": {"v4": 20, "v6": 170}},
    "S4": {"label": "IPv4 blackhole", "v4": {"delay_ms_each_way": 10, "loss_pct": 100},
           "v6": {"delay_ms_each_way": 10, "loss_pct": 0}, "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
           "verify_target": {"v4": "blackhole", "v6": 20}},
    "S5": {"label": "IPv4 +600 ms RTT", "v4": {"delay_ms_each_way": 310, "loss_pct": 0},
           "v6": {"delay_ms_each_way": 10, "loss_pct": 0}, "dns": {"delay_ms": {"A": 0, "AAAA": 0}},
           "verify_target": {"v4": 620, "v6": 20}},
    "S6": {"label": "AAAA answer delayed 300 ms", "v4": {"delay_ms_each_way": 10, "loss_pct": 0},
           "v6": {"delay_ms_each_way": 10, "loss_pct": 0}, "dns": {"delay_ms": {"A": 0, "AAAA": 300}},
           "verify_target": {"v4": 20, "v6": 20}},
}


def test_core_scenario_file_is_byte_identical():
    assert hashlib.sha256(SCENARIOS_FILE.read_bytes()).hexdigest() == CORE_FILE_SHA256


def test_core_scenarios_as_loaded_with_the_generated_file_are_unchanged():
    cfg = load_config()                                  # scenarios.yaml + scenarios_generated.yaml
    assert {k: cfg["scenarios"][k] for k in CORE_SCENARIOS} == CORE
    assert list(cfg["scenarios"])[:7] == list(CORE_SCENARIOS)
    assert cfg["baseline"] == {"delay_ms_each_way": 10, "rtt_ms": 20}
    assert {k: o.load_scenarios([k])[k] for k in CORE_SCENARIOS} == CORE   # what the orchestrator runs


def test_core_ids_are_never_in_the_generated_file():
    gen = yaml.safe_load(GENERATED_FILE.read_text())
    assert not set(gen["scenarios"]) & set(CORE_SCENARIOS)
    assert all(is_generated_id(k) and v["extension"] is True for k, v in gen["scenarios"].items())
    assert gen["extension"] is True


# --- the generated file matches the grid ---------------------------------------------------------

def test_generated_file_is_up_to_date_with_the_grid():
    assert sg.generate() == GENERATED_FILE.read_text(), "run src/runner/scenario_grid.py"
    assert sg.main(["--check"]) == 0


def test_check_reports_an_out_of_date_file(tmp_path):
    out = tmp_path / "gen.yaml"
    out.write_text("# stale\n")
    assert sg.main(["--check", "--out", str(out)]) == 1
    assert sg.main(["--out", str(out)]) == 0 and out.read_text() == sg.generate()


# --- generation rules ------------------------------------------------------------------------------

BASE = {"delay_ms_each_way": 10, "rtt_ms": 20}
CORE_CFG = {"baseline": BASE, "scenarios": CORE}


def test_delay_follows_the_scenarios_yaml_rule():
    # "+N ms RTT": each way 10 + N/2, verify target 20 + N; the other family at baseline
    sid, sc = sg.scenario_for("v6", "delay", 200, BASE)
    assert sid == "Gv6d200"
    assert sc == {"label": "IPv6 +200 ms RTT (generated extension)", "extension": True,
                  "grid": {"family": "v6", "kind": "delay", "value": 200},
                  "v4": {"delay_ms_each_way": 10, "loss_pct": 0}, "v6": {"delay_ms_each_way": 110, "loss_pct": 0},
                  "dns": {"delay_ms": {"A": 0, "AAAA": 0}}, "verify_target": {"v4": 20, "v6": 220}}
    _, v4 = sg.scenario_for("v4", "delay", 600, BASE)
    assert v4["v4"] == {"delay_ms_each_way": 310, "loss_pct": 0} and v4["verify_target"] == {"v4": 620, "v6": 20}


def test_the_rule_reproduces_the_hand_written_core_delays():
    for core_id, fam, n in (("S2", "v6", 600), ("S3", "v6", 150), ("S5", "v4", 600)):
        _, sc = sg.scenario_for(fam, "delay", n, BASE)
        assert {k: sc[k] for k in ("v4", "v6", "verify_target")} == \
               {k: CORE[core_id][k] for k in ("v4", "v6", "verify_target")}


def test_loss_scenario_declares_a_loss_band():
    sid, sc = sg.scenario_for("v6", "loss", 10, BASE)
    assert sid == "Gv6l10"
    assert sc["v6"] == {"delay_ms_each_way": 10, "loss_pct": 10}
    # a ping crosses the link twice: 1 - 0.9^2 = 19 %; 4 binomial SEs over 200 pings = 11.1 -> 12
    assert sc["verify_target"] == {"v4": 20, "v6": {"band": "loss", "expect_loss_pct": 19.0, "tolerance_pct": 12,
                                                     "rtt_ms": 20, "pings": 200}}
    assert o.verify_arg(sc["verify_target"]["v6"]) == "band:loss:19:12:20:200"


@pytest.mark.parametrize("grid, msg", [
    ({"grids": [{"family": "v6", "kind": "delay", "values": [0]}]}, "needs N > 0"),
    ({"grids": [{"family": "v6", "kind": "loss", "values": [100]}]}, "core blackhole"),
    ({"grids": [{"family": "v6", "kind": "loss", "values": [0]}]}, "1-99"),
    ({"grids": [{"family": "v5", "kind": "delay", "values": [100]}]}, "family must be"),
    ({"grids": [{"family": "v6", "kind": "spike", "values": [10]}]}, "kind must be"),
    ({"grids": [{"family": "v6", "kind": "delay", "values": [100], "delay_twin": True}]}, "for jitter only"),
    ({"grids": [{"family": "v6", "kind": "jitter", "values": [0]}]}, "must be > 0"),
    ({"grids": [{"family": "v6", "kind": "delay", "values": [100.5]}]}, "whole numbers"),
    ({"grids": [{"family": "v6", "kind": "delay", "values": []}]}, "whole numbers"),
    ({"grids": [{"family": "v6", "kind": "delay", "values": [100], "id": "S1"}]}, "exactly family, kind and values"),
    ({"grids": [{"family": "v6", "kind": "delay", "values": [100, 100]}]}, "listed twice"),
    ({"grids": []}, "non-empty 'grids'"),
])
def test_bad_grids_are_refused(grid, msg):
    with pytest.raises(sg.GridError, match=msg):
        sg.build(grid, CORE_CFG)


# --- ID collisions -----------------------------------------------------------------------------------

@pytest.mark.parametrize("sid", CORE_SCENARIOS)
def test_a_generated_id_equal_to_a_core_id_is_rejected(sid):
    with pytest.raises(InvalidName, match="collides with a core scenario ID"):
        check_generated_id(sid)


@pytest.mark.parametrize("sid, msg", [("X1", "already defined"), ("S7", "looks like a core ID"),
                                      ("C1", "looks like a core ID"), ("Gv6d0200", "does not match"),
                                      ("v6d200", "does not match"), ("Gv6x200", "does not match")])
def test_other_confusable_ids_are_rejected(sid, msg):
    with pytest.raises(InvalidName, match=msg):
        check_generated_id(sid)


def test_generator_rejects_an_id_already_written_by_hand(tmp_path):
    cfg = {"baseline": BASE, "scenarios": {**CORE, "Gv6d200": CORE["C0"]}}
    with pytest.raises(sg.GridError, match="already defined"):
        sg.build({"grids": [{"family": "v6", "kind": "delay", "values": [200]}]}, cfg)


def _gen_file(tmp_path, scenarios: dict, top_extension=True, baseline=BASE):
    p = tmp_path / "gen.yaml"
    p.write_text(yaml.safe_dump({"extension": top_extension, "baseline": baseline, "scenarios": scenarios}))
    return p


def test_loader_rejects_a_hand_edited_generated_file_that_redefines_s1(tmp_path):
    bad = _gen_file(tmp_path, {"S1": dict(CORE["C0"], extension=True)})
    with pytest.raises(ScenarioConfigError, match="collides with a core scenario ID"):
        load_config(SCENARIOS_FILE, bad)


@pytest.mark.parametrize("kw, msg", [
    ({"scenarios": {"Gv6d200": dict(CORE["C0"])}}, "must be marked 'extension: true'"),
    ({"scenarios": {"Gv6d200": dict(CORE["C0"], extension=True)}, "top_extension": False}, "at the top"),
    ({"scenarios": {"Gv6d200": dict(CORE["C0"], extension=True)},
      "baseline": {"delay_ms_each_way": 5, "rtt_ms": 10}}, "baseline differs"),
])
def test_loader_rejects_unmarked_or_mismatched_generated_files(tmp_path, kw, msg):
    with pytest.raises(ScenarioConfigError, match=msg):
        load_config(SCENARIOS_FILE, _gen_file(tmp_path, **kw))


# --- generated scenarios through the orchestrator, records and manifests -----------------------------

def test_orchestrator_dry_run_of_a_generated_scenario(capsys):
    assert o.main(["--scenario", "Gv6d200", "--reps", "1", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "netem.sh v6 110 0" in out and "verify.sh up 20 220" in out and "_Gv6d200_curl_r01" in out


def test_orchestrator_refuses_an_unverifiable_target_before_touching_the_lab(tmp_path, monkeypatch):
    _, sc = sg.scenario_for("v6", "loss", 5, BASE)
    sc["verify_target"]["v6"] = "loss:5"               # the old placeholder form: not a lab target
    gen = _gen_file(tmp_path, {"Gv6l5": sc})
    monkeypatch.setitem(o.SUPPORTED, "curl", o.SUPPORTED["curl"] + ("Gv6l5",))
    with pytest.raises(o.OrchestratorError, match="cannot be checked by src/lab/verify.sh"):
        o.load_scenarios(["Gv6l5"], SCENARIOS_FILE, "curl", generated=gen)


def test_generated_ids_validate_only_in_0_4_records():
    from tests.test_client_variants import _record
    r = _record("curl")
    r["scenario"]["id"] = "Gv6d200"
    r["run_id"] = r["run_id"].replace("_S1_", "_Gv6d200_")
    assert validate(r) == []
    r["schema_version"] = "0.3"
    r.pop("profile", None)
    assert any("scenario.id" in p for p in validate(r))


def test_a_manifest_may_list_a_generated_scenario(tmp_path):
    doc = manifest(tmp_path, "clients: [curl]\nscenarios: [Gv6d200]\nreps: 1\n", [("curl", "Gv6d200", A)])
    m = sm.load_manifest(doc, require_header=True)
    assert m.shape.scenarios == ("Gv6d200",)
    runs = tmp_path / "runs"
    write(runs, [make_record(A, "curl", "Gv6d200", 1, setup_ms=220.0)])
    _, _, summary = sm.build(manifest=m, runs_dir=runs, repo=None)
    assert summary["cells"]["curl"]["Gv6d200"]["scenario_penalty_note"] == "no C0 in this dataset"


def test_scenario_ids_lists_core_then_generated():
    ids = scenario_ids()
    assert ids[:7] == CORE_SCENARIOS and all(is_generated_id(i) for i in ids[7:]) and len(ids) > 7
    start = datetime(2026, 11, 21, tzinfo=timezone.utc)
    assert o.make_run_id(start, "Gv6d200", 1) == "20261121T000000Z_Gv6d200_curl_r01"


def test_odd_delay_gives_a_half_ms_each_way_and_even_stays_whole():
    base = {"delay_ms_each_way": 10, "rtt_ms": 20}
    sid, sc = sg.scenario_for("v6", "delay", 125, base)
    assert sid == "Gv6d125" and sc["v6"]["delay_ms_each_way"] == 72.5 and sc["verify_target"]["v6"] == 145
    _, even = sg.scenario_for("v6", "delay", 200, base)
    assert even["v6"]["delay_ms_each_way"] == 110 and isinstance(even["v6"]["delay_ms_each_way"], int)
