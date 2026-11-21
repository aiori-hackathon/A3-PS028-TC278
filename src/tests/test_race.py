"""Connection race timeline (analysis/race.py): checked against the three runs committed in examples/."""

import copy
import json
import shutil
from pathlib import Path

import pytest

from analysis import race
from analysis import summarise as sm
from analysis.parse_pcap import read_pcap

REPO = Path(__file__).resolve().parents[2]
EX = REPO / "examples"
CHROMIUM_S1 = "20261026T193420Z_S1_chromium_r01"
CURL_S1 = "20261026T193106Z_S1_curl_r08"
CURL_C0 = "20261026T192159Z_C0_curl_r07"


def rec(run_id):
    return json.loads((EX / f"{run_id}.json").read_text(encoding="utf-8"))


def test_frame_numbers_count_every_record_from_one():
    _, pkts = read_pcap(EX / f"{CURL_S1}.pcap")
    assert [p.frame_no for p in pkts] == list(range(1, len(pkts) + 1))


def test_chromium_s1_events_match_the_record_and_carry_frames():
    r = rec(CHROMIUM_S1)
    ev = race.wire(EX / f"{CHROMIUM_S1}.pcap", r, rows=True)
    a = ev["attempts"]
    assert [(x["fam"], x["res"], x["syn"]["t"]) for x in a] == [
        ("v6", "abandoned", 0.0), ("v6", "abandoned", 250.29), ("v4", "won", 301.266)]
    assert a[0]["synack"] is None and a[1]["synack"] is None and a[0]["rtx_ev"] == []
    assert a[2]["ack"]["t"] == r["metrics"]["tcp_setup_time_ms"]["value"] == 324.766
    assert a[2]["syn"]["t"] == r["metrics"]["inter_family_attempt_delay_ms"]["value"]
    # every frame the chart links to is a row of the table
    frames = {x["f"] for x in ev["rows"]}
    linked = {e["f"] for x in a for e in (x["syn"], x["synack"], x["ack"]) if e}
    linked |= {e["f"] for d in ev["dns"] for e in (d["q"], d["a"]) if e}
    assert linked <= frames
    assert {"hl-v6c", "hl-v4c", "hl-ctlc"} == {x["if"] for x in ev["rows"]}
    # DNS: only www.hl.test exchanges before the first SYN, and their span is the record's DNS time
    assert {d["type"] for d in ev["dns"]} == {"A", "AAAA", "HTTPS"}
    span = max(d["a"]["t"] for d in ev["dns"]) - min(d["q"]["t"] for d in ev["dns"])
    assert span == pytest.approx(r["metrics"]["dns_time_ms"]["value"], abs=0.002)
    assert "180 other packets" in ev["rows_note"]


def test_rows_stop_at_the_winning_ack():
    ev = race.wire(EX / f"{CURL_C0}.pcap", rec(CURL_C0), rows=True)
    assert ev["rows"][-1]["what"].startswith("ACK: completes the winning handshake")
    assert [x["what"].split()[0] for x in ev["rows"][:4]] == ["DNS"] * 4


def test_a_capture_that_disagrees_with_the_record_is_refused():
    r = rec(CURL_S1)
    bad = copy.deepcopy(r)
    bad["metrics"]["tcp_setup_time_ms"]["value"] = 200.0
    with pytest.raises(sm.DatasetError, match="TCP setup time"):
        race.wire(EX / f"{CURL_S1}.pcap", bad)
    bad = copy.deepcopy(r)
    bad["packet_observations"]["attempts"]["value"][0]["syn_retransmits"] = 1
    with pytest.raises(sm.DatasetError, match="retransmits"):
        race.wire(EX / f"{CURL_S1}.pcap", bad)


def test_a_capture_whose_hash_does_not_match_is_refused(tmp_path):
    (tmp_path / "examples").mkdir()
    pcap = tmp_path / "examples" / f"{CURL_S1}.pcap"
    shutil.copy(EX / f"{CURL_S1}.pcap", pcap)
    with pcap.open("ab") as f:
        f.write(b"\0")
    with pytest.raises(sm.DatasetError, match="pcap_sha256"):
        race.find_capture(CURL_S1, rec(CURL_S1), tmp_path, tmp_path / "examples")


def test_without_a_capture_the_record_alone_is_drawn_and_says_so(tmp_path):
    r = rec(CHROMIUM_S1)
    run = sm.run_from_record(r)
    out = race.build([run], ["chromium"], ["S1"], {run.run_id: r}, repo=tmp_path, examples=None)
    p = out["runs"][run.run_id]
    assert p["src"] == "record" and p["dq"] is None and p["rows"] is None
    assert [x["syn"]["t"] for x in p["att"]] == [0.0, 250.29, 301.266]
    assert p["att"][2]["ack"]["t"] == 324.766 and p["att"][2]["synack"] is None
    assert p["att"][0]["rtx_ev"] is None  # times unknown, not "none"


def _example_runs():
    recs = {i: rec(i) for i in (CURL_C0, CURL_S1, CHROMIUM_S1)}
    return [sm.run_from_record(r) for r in recs.values()], recs


def test_build_defaults_to_the_s1_run_and_lists_the_examples_with_rows():
    runs, recs = _example_runs()
    out = race.build(runs, sm.CLIENTS, sm.SCENARIOS, recs)
    assert out["default"] == CURL_S1 and "representative S1" in out["default_why"]
    assert out["examples"] == sorted([CURL_C0, CURL_S1, CHROMIUM_S1])
    assert all(out["runs"][i]["capture"] == f"examples/{i}.pcap" for i in out["examples"])
    o = out["runs"][CURL_S1]["orc"]
    assert o["setup"] == 21.15 and o["cost"] == pytest.approx(222.254 - 21.15, abs=0.001)
    assert out["oracle_evidence"].startswith("derived")


def test_a_dataset_without_s1_falls_back_and_says_so():
    runs, recs = _example_runs()
    c0 = [r for r in runs if r.scenario == "C0"]
    out = race.build(c0, ["curl"], ["C0"], recs)
    assert out["default"] == CURL_C0 and "no S1 runs" in out["default_why"]
    empty = race.build([], ["curl"], ["C0"], {})
    assert empty["default"] is None and empty["runs"] == {}


def test_representative_is_nearest_the_median_then_lowest_repetition():
    def r(rep, setup):
        return sm.Run(run_id=f"r{rep}", client="curl", scenario="S1", repetition=rep, success=True, winner="v4",
                      setup_ms=setup, inter_family_ms=None, inter_family_status="", failed_or_abandoned=0,
                      dns_ms=None, attempts=[], netlog_backup_jobs=None, netlog_v4_source=None,
                      resolved_families=None)
    assert race.representative([r(1, 10), r(2, 30), r(3, 20), r(4, 21)]).run_id == "r3"  # median 20.5: tie -> r3
    assert race.representative([r(2, None), r(1, None)]).run_id == "r1"


def test_dashboard_renders_the_race_section_and_escapes_its_data():
    dashboard = pytest.importorskip("analysis.dashboard")
    runs, recs = _example_runs()
    out = race.build(runs, sm.CLIENTS, sm.SCENARIOS, recs)
    out["runs"][CURL_S1]["label"] = "</script><b>x"
    curl = [r for r in runs if r.client == "curl"]  # a complete curl-only shape for the other sections
    summary = sm.summarise(curl, sm.Shape(clients=("curl",), scenarios=("C0", "S1"), reps=1))
    summary["dataset"] = {"source": "x", "runs": 2, "sessions": [], "shape": {"reps": 1},
                          "clients": {"curl": {"versions": ["x 1.0"], "configs": [{}], "code_versions": ["abc"]}}}
    page = dashboard.render(summary, curl, "", out)
    assert "id=race-section" in page and "Connection race timeline" in page
    assert "</script><b>x" not in page and "<\\/script>" in page
    assert page.index("id=race-section") < page.index("TCP setup time and scenario penalty")
