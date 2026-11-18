"""Oracle baseline: metrics.oracle_baseline, its summary cells, the dashboard section and oracle.py."""

import csv

import pytest

from analysis import dashboard
from analysis import oracle as oracle_cli
from analysis import summarise as sm
from analysis.metrics import ORACLE_EVIDENCE, oracle_baseline
from tests.test_dataset_manifest import A, B, C, manifest
from tests.test_summarise import make_record, write


def rtt(v4=21.0, v6=21.0, v4_status="computed", v6_status="computed"):
    return {"v4": {"value": v4 if v4_status == "computed" else None, "status": v4_status},
            "v6": {"value": v6 if v6_status == "computed" else None, "status": v6_status}}


# --- the per-run function ------------------------------------------------------------------

def test_raced_run_cost_is_setup_minus_winning_family_rtt():
    o = oracle_baseline("v4", 222.254, rtt(v4=21.15, v6_status="not_observed"), ["v6", "v4"])
    assert o["oracle_setup_ms"] == {"value": 21.15, "status": "computed"}
    assert o["cost_of_racing_ms"] == {"value": 201.104, "status": "computed"}
    assert o["single_family"] is False
    assert o["evidence"] == ORACLE_EVIDENCE


def test_uses_the_winning_familys_rtt_not_the_other_one():
    o = oracle_baseline("v6", 171.2, rtt(v4=21.0, v6=171.0), ["v6"])
    assert o["oracle_setup_ms"]["value"] == 171.0
    assert o["cost_of_racing_ms"]["value"] == pytest.approx(0.2)


def test_negative_cost_is_reported_not_clamped():
    o = oracle_baseline("v6", 20.6, rtt(v6=21.0), ["v6"])
    assert o["cost_of_racing_ms"]["value"] == pytest.approx(-0.4)


def test_single_family_run_is_computed_and_says_no_race_took_place():
    o = oracle_baseline("v6", 20.7, rtt(), ["v6"])
    assert o["single_family"] is True
    assert o["cost_of_racing_ms"]["status"] == "computed"
    assert "no race took place" in o["cost_of_racing_ms"]["note"]


def test_two_attempts_on_one_family_are_still_single_family():
    o = oracle_baseline("v6", 20.7, rtt(), ["v6", "v6"])
    assert o["single_family"] is True


def test_dns_delay_is_noted_as_outside_the_cost():
    o = oracle_baseline("v6", 20.8, rtt(), ["v6"], {"A": 0, "AAAA": 300})
    note = o["cost_of_racing_ms"]["note"]
    assert "AAAA 300 ms" in note and "dns_time_ms" in note
    assert o["cost_of_racing_ms"]["value"] == pytest.approx(-0.2)   # the delay is not added in


def test_no_dns_delay_means_no_dns_note():
    o = oracle_baseline("v4", 222.0, rtt(), ["v6", "v4"], {"A": 0, "AAAA": 0})
    assert "note" not in o["cost_of_racing_ms"]


@pytest.mark.parametrize("measured, status_word", [
    (rtt(v4_status="not_observed"), "not_observed"),   # e.g. a blackholed family's ping
    ({"v6": {"value": 21.0, "status": "computed"}}, "missing"),
    (None, "missing"),
    ({"v4": {"value": None, "status": "computed"}}, "computed"),   # computed but empty: still refused
])
def test_winning_family_rtt_not_computed_is_not_available(measured, status_word):
    o = oracle_baseline("v4", 222.0, measured, ["v6", "v4"])
    for k in ("oracle_setup_ms", "cost_of_racing_ms"):
        assert o[k]["value"] is None and o[k]["status"] == "not_available"
        assert f"winning family v4 is {status_word}" in o[k]["note"]


def test_no_winner_is_not_observed():
    o = oracle_baseline(None, None, rtt(), ["v6", "v4"])
    assert o["oracle_setup_ms"]["status"] == o["cost_of_racing_ms"]["status"] == "not_observed"


def test_winner_without_setup_time_keeps_the_oracle_but_not_the_cost():
    o = oracle_baseline("v4", None, rtt(), ["v4"])
    assert o["oracle_setup_ms"]["value"] == 21.0
    assert o["cost_of_racing_ms"]["status"] == "not_observed"


def test_no_attempts_leaves_single_family_unknown():
    assert oracle_baseline(None, None, rtt(), [])["single_family"] is None


# --- in the summary ------------------------------------------------------------------------

def with_rtt(rec, measured, dns=None):
    rec["scenario"]["measured_rtt_ms"] = measured
    if dns is not None:
        rec["scenario"]["dns"] = {"delay_ms": dns}
    return rec


def oracle_runs(tmp_path):
    """curl C0 (single family), S1 (raced, one run with no v4 RTT), S6 (AAAA delayed)."""
    recs = []
    for i in (1, 2):
        recs.append(with_rtt(make_record(A, "curl", "C0", i, setup_ms=20.0 + i), rtt(v4=21.0, v6=21.0)))
        recs.append(with_rtt(make_record(B, "curl", "S1", i, families=("v6", "v4"), offsets_ms=(0, 200),
                                         winner_idx=1, setup_ms=221.0 + i),
                             rtt(v4=21.0 if i == 1 else None, v6_status="not_observed",
                                 v4_status="computed" if i == 1 else "not_observed")))
        recs.append(with_rtt(make_record(C, "curl", "S6", i, setup_ms=21.0), rtt(v6=20.5),
                             dns={"A": 0, "AAAA": 300}))
    for r in recs:
        r["client"].update(version="curl 8.5.0 (test)", config={})
    runs = tmp_path / "runs"
    write(runs, recs)
    return runs


def build(tmp_path, header="clients: [curl]\nscenarios: [C0, S1, S6]\nreps: 2\n",
          rows=(("curl", "C0", A), ("curl", "S1", B), ("curl", "S6", C))):
    doc = manifest(tmp_path, header, list(rows))
    return sm.build(manifest=sm.load_manifest(doc, require_header=True), runs_dir=oracle_runs(tmp_path), repo=None)


def test_runs_carry_the_oracle_fields(tmp_path):
    _, runs, _ = build(tmp_path)
    s1 = {r.repetition: r for r in runs if r.scenario == "S1"}
    assert s1[1].oracle_setup_ms == 21.0 and s1[1].cost_of_racing_ms == pytest.approx(201.0)
    assert s1[1].oracle_status == "computed" and s1[1].single_family is False
    assert s1[2].oracle_setup_ms is None and s1[2].cost_of_racing_ms is None
    assert s1[2].oracle_status == "not_available"


def test_cell_stats_cover_computed_runs_only_and_count_the_rest(tmp_path):
    _, _, summary = build(tmp_path)
    o = summary["cells"]["curl"]["S1"]["oracle"]
    assert o["cost_of_racing_ms"]["n"] == 1 and o["cost_of_racing_ms"]["median"] == pytest.approx(201.0)
    assert o["status"] == {"computed": 1, "not_available": 1}
    assert o["not_computed_notes"] == ["measured RTT for the winning family v4 is not_observed"]
    assert o["evidence"] == ORACLE_EVIDENCE


def test_c0_cell_is_single_family_and_s6_cell_carries_the_dns_note(tmp_path):
    _, _, summary = build(tmp_path)
    c0, s6 = summary["cells"]["curl"]["C0"]["oracle"], summary["cells"]["curl"]["S6"]["oracle"]
    assert c0["single_family_runs"] == 2 and c0["dns_note"] is None
    assert c0["cost_of_racing_ms"]["median"] == pytest.approx(0.5)     # 21.5 - 21.0
    assert "AAAA 300 ms" in s6["dns_note"] and "see DNS time" in s6["dns_note"]
    assert s6["cost_of_racing_ms"]["median"] == pytest.approx(0.5)     # 21.0 - 20.5; the 300 ms is not added


def test_oracle_statement_is_labelled_interpretation_with_derived_evidence(tmp_path):
    _, _, summary = build(tmp_path)
    items = [i for i in summary["interpretation"] if i["topic"].startswith("Oracle baseline")]
    assert len(items) == 1
    it = items[0]
    assert {e["source"] for e in it["evidence"]} == {"derived"}
    assert "hindsight" in it["statement"] and "not a target" in it["statement"]
    assert any("S1 curl" in e["text"] and "not_available" in e["text"] for e in it["evidence"])


def test_no_oracle_statement_without_any_computed_cost(tmp_path):
    runs = tmp_path / "runs"
    write(runs, [make_record(A, "curl", "C0", i) for i in (1, 2)])   # no measured RTT in these records
    doc = manifest(tmp_path, "clients: [curl]\nscenarios: [C0]\nreps: 2\n", [("curl", "C0", A)])
    _, _, summary = sm.build(manifest=sm.load_manifest(doc, require_header=True), runs_dir=runs, repo=None)
    assert summary["cells"]["curl"]["C0"]["oracle"]["status"] == {"not_available": 2}
    assert summary["interpretation"] == []


def test_manifest_without_s1_or_s6_does_not_crash(tmp_path):
    _, _, summary = build(tmp_path, "clients: [curl]\nscenarios: [C0]\nreps: 2\n", [("curl", "C0", A)])
    assert list(summary["cells"]["curl"]) == ["C0"]
    assert "ORACLE BASELINE" in sm.text_report(summary)


def test_text_report_has_an_oracle_row_per_cell(tmp_path):
    _, _, summary = build(tmp_path)
    report = sm.text_report(summary)
    block = report.split("ORACLE BASELINE", 1)[1].split("INTERPRETATION", 1)[0]
    assert block.count("\n  curl ") == 3
    assert "not_available" in block and "DNS delay not in cost" in block


# --- dashboard -----------------------------------------------------------------------------

def test_dashboard_has_the_oracle_section_labelled_derived(tmp_path):
    _, runs, summary = build(tmp_path)
    page = dashboard.render(summary, runs, "")
    assert "Oracle baseline and cost of racing" in page
    assert "<span class='tag tag-derived'>Derived (pcap − lab RTT)</span>" in page
    assert "<span class='tag tag-derived'>Derived</span> S1 curl" in page   # not shown as a client log
    assert "not_available 1" in page


def test_cost_chart_plots_computed_runs_only(tmp_path):
    _, runs, _ = build(tmp_path)
    fig = dashboard.fig_cost(runs, ("curl",), ("C0", "S1", "S6"))
    (trace,) = fig["data"]
    assert len(trace.y) == 5   # 6 runs, one S1 run not computed


# --- standalone script ---------------------------------------------------------------------

def test_script_rows_and_cell_report(tmp_path):
    _, runs, summary = build(tmp_path)
    rows = oracle_cli.run_rows(runs)
    assert len(rows) == 6 and set(rows[0]) == set(oracle_cli.CSV_FIELDS)
    na = [r for r in rows if r["status"] != "computed"]
    assert len(na) == 1 and na[0]["cost_of_racing_ms"] is None
    report = oracle_cli.cell_report(summary)
    assert "Interpretation (labelled)" in report and "not_available 1" in report


def test_script_writes_csv(tmp_path, monkeypatch):
    built = build(tmp_path)
    monkeypatch.setattr(oracle_cli, "load_dataset", lambda name: None)
    monkeypatch.setattr(oracle_cli, "build", lambda manifest: built)
    out = tmp_path / "o" / "runs.csv"
    assert oracle_cli.main(["--csv", str(out)]) == 0
    with out.open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 6 and rows[0]["run_id"]
