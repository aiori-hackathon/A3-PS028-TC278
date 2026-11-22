"""CSV export of run records (src/analysis/export_csv.py) and its documentation in docs/integration.md."""

import copy
import csv
import io
import json
import re
from pathlib import Path

import pytest

from analysis import export_csv as ec
from analysis import summarise as sm
from analysis.dashboard import TAG_LABEL

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples"
S1_CURL = EXAMPLES / "20261026T193106Z_S1_curl_r08.json"
C0_CURL = EXAMPLES / "20261026T192159Z_C0_curl_r07.json"
INTEGRATION = REPO / "docs" / "integration.md"
REPORT = REPO / "docs" / "report.md"


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _csv(records) -> list[dict]:
    buf = io.StringIO()
    ec.write_csv(records, buf)
    return list(csv.DictReader(io.StringIO(buf.getvalue())))


# --- rows --------------------------------------------------------------------------------

def test_s1_curl_row_carries_the_record_values():
    rec = _load(S1_CURL)
    [row] = _csv([rec])
    assert list(row) == ec.FIELDNAMES
    assert row["run_id"] == rec["run_id"] and row["client"] == "curl" and row["scenario"] == "S1"
    assert row["winning_family"] == "v4" and row["winning_family_status"] == "computed"
    assert row["tcp_setup_time_ms"] == str(rec["metrics"]["tcp_setup_time_ms"]["value"])
    assert row["inter_family_attempt_delay_ms"] == str(rec["metrics"]["inter_family_attempt_delay_ms"]["value"])
    assert row["attempt_shape"] == "v6>v4" and row["attempts"] == "2" and row["syn_retransmits"] == "0"
    assert row["failed_or_abandoned_attempts"] == "1"
    assert row["success"] == "true" and row["http_status"] == "200" and row["client_remote_ip"] == "192.0.2.2"
    assert row["cross_checks_status"] == "agree" and row["cross_check_conflicts"] == ""
    assert row["pcap_sha256"] == rec["evidence"]["pcap_sha256"]


def test_blackholed_family_rtt_is_empty_with_its_status():
    [row] = _csv([_load(S1_CURL)])
    assert row["measured_rtt_v6_ms"] == "" and row["measured_rtt_v6_ms_status"] == "not_observed"
    assert row["measured_rtt_v4_ms"] == "21.15" and row["measured_rtt_v4_ms_status"] == "computed"


def test_single_family_run_has_inter_family_not_observed():
    [row] = _csv([_load(C0_CURL)])
    assert row["inter_family_attempt_delay_ms"] == ""
    assert row["inter_family_attempt_delay_ms_status"] == "not_observed"
    assert row["attempt_shape"] == "v6" and row["attempts"] == "1"


def test_derived_columns_are_setup_minus_the_winning_familys_rtt():
    [row] = _csv([_load(S1_CURL)])
    assert float(row["oracle_setup_ms"]) == 21.15                     # v4 won: the v4 ping median
    assert float(row["cost_of_racing_ms"]) == pytest.approx(222.254 - 21.15, abs=1e-3)


def test_no_winner_leaves_value_columns_empty_and_says_why():
    rec = _load(S1_CURL)
    rec["packet_observations"]["winning_family"] = {"value": None, "status": "not_observed"}
    rec["metrics"]["tcp_setup_time_ms"] = {"value": None, "status": "not_observed"}
    [row] = _csv([rec])
    for col in ("winning_family", "tcp_setup_time_ms", "oracle_setup_ms", "cost_of_racing_ms"):
        assert row[col] == "" and row[f"{col}_status"] == "not_observed", col


def test_rows_are_sorted_by_run_id():
    rows = _csv([_load(S1_CURL), _load(C0_CURL)])
    assert [r["run_id"] for r in rows] == sorted(r["run_id"] for r in rows)


# --- inputs ------------------------------------------------------------------------------

def test_paths_mode_reads_a_folder_and_validates(tmp_path):
    assert len(ec.records_from_paths([EXAMPLES])) == 3
    bad = _load(C0_CURL)
    del bad["metrics"]
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    with pytest.raises(sm.DatasetError, match="invalid record"):
        ec.records_from_paths([tmp_path])
    with pytest.raises(sm.DatasetError, match="no such file"):
        ec.records_from_paths([tmp_path / "missing"])


def _session(runs_dir: Path, session: str, commits: list[str]) -> None:
    base = _load(C0_CURL)
    runs_dir.mkdir(exist_ok=True)
    for rep, commit in enumerate(commits, 1):
        r = copy.deepcopy(base)
        r["run_id"] = f"20261101T0000{rep:02d}Z_C0_curl_r{rep:02d}_{session}"
        r["scenario"]["repetition"] = rep
        r["environment"].update(session_id=session, git_commit=commit)
        (runs_dir / f"{r['run_id']}.json").write_text(json.dumps(r))


@pytest.fixture
def one_cell_dataset(monkeypatch):
    m = sm.Manifest(Path("test.md"), sm.Shape(("curl",), ("C0",), 2), [("curl", "C0", "A")])
    monkeypatch.setattr(ec, "load_dataset", lambda name: m)


def test_dataset_mode_exports_only_the_listed_sessions(tmp_path, one_cell_dataset):
    runs = tmp_path / "runs"
    _session(runs, "A", ["c283448", "c283448"])
    _session(runs, "PILOT", ["c283448-dirty"])               # not in the dataset: ignored, not refused
    recs = ec.records_from_dataset("test", runs)
    assert [r["environment"]["session_id"] for r in recs] == ["A", "A"]


def test_dataset_mode_refuses_a_dirty_record_like_summarise(tmp_path, one_cell_dataset):
    runs = tmp_path / "runs"
    _session(runs, "A", ["c283448", "c283448-dirty"])
    with pytest.raises(sm.DatasetError, match="-dirty"):
        ec.records_from_dataset("test", runs)


def test_main_writes_only_the_out_file(tmp_path, capsys):
    out = tmp_path / "x.csv"
    assert ec.main([str(EXAMPLES), "--out", str(out)]) == 0
    assert [p.name for p in tmp_path.iterdir()] == ["x.csv"]
    assert len(list(csv.DictReader(out.open()))) == 3
    assert ec.main([str(C0_CURL)]) == 0
    assert capsys.readouterr().out.startswith("run_id,schema_version,")


def test_main_rejects_paths_together_with_dataset():
    with pytest.raises(SystemExit):
        ec.main([str(EXAMPLES), "--dataset", "core"])


# --- documentation -----------------------------------------------------------------------

def test_integration_doc_carries_the_column_table_exactly():
    assert ec.column_table() in INTEGRATION.read_text(encoding="utf-8"), \
        "docs/integration.md is out of date: paste `export_csv.py --columns` into it"


def _doc_tags(text: str, heading: str) -> list[str]:
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| \*\*\[([^\]]+)\]\*\* \|", section, re.MULTILINE)


def test_integration_doc_lists_the_four_evidence_tags_of_the_dashboard():
    tags = _doc_tags(INTEGRATION.read_text(encoding="utf-8"), "## Evidence tags")
    assert tags == list(TAG_LABEL[k] for k in ("packet", "client", "derived", "interp"))


FOUR_TAGS = [TAG_LABEL[k] for k in ("packet", "client", "derived", "interp")]


def test_report_names_the_four_dashboard_tags():
    line = next(x for x in REPORT.read_text(encoding="utf-8").splitlines() if x.startswith("**Evidence labels.**"))
    assert "four labels the dashboard uses" in line
    assert all(tag in line for tag in FOUR_TAGS), line


def test_readme_lists_the_four_dashboard_tags():
    section = (REPO / "README.md").read_text(encoding="utf-8").split("## Method and evidence labels", 1)[1]
    section = section.split("Fixed metric definitions", 1)[0]
    assert re.findall(r"^- \*\*(.+?)\*\*:", section, re.MULTILINE) == FOUR_TAGS


def test_pseudocode_lists_the_four_dashboard_tags():
    section = (REPO / "docs" / "pseudocode.md").read_text(encoding="utf-8").split("## Evidence labels", 1)[1]
    section = section.split("\n## ", 1)[0]
    assert re.findall(r"^\| \*\*(.+?)\*\* \|", section, re.MULTILINE) == FOUR_TAGS


def test_no_doc_uses_another_spelling_of_the_tags():
    for p in [REPO / "README.md", *sorted((REPO / "docs").rglob("*.md"))]:
        text = p.read_text(encoding="utf-8")
        assert "Derived (pcap - lab RTT)" not in text, f"{p}: use the dashboard's minus sign (U+2212)"
        assert "three labels" not in text, p
