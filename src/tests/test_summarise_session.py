"""Tests for the session summary table (pure, no lab)."""

import importlib.util
import sys
from pathlib import Path

from tests.test_orchestrate import _s1_record

_PATH = Path(__file__).resolve().parents[1] / "analysis" / "summarise_session.py"
_spec = importlib.util.spec_from_file_location("analysis.summarise_session", _PATH)
ss = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ss
_spec.loader.exec_module(ss)


def test_row_from_s1_record():
    r = _s1_record()
    cells = ss.row(r, 12.5)
    assert cells[1:] == ["S1", "21", "blackhole", "ok 200", "v4", "220.593", "200.443", "1",
                         str(r["metrics"]["dns_time_ms"]["value"]), "agree", "12.50"]
    assert ss.row(r, None)[-1] == "?"


def test_parse_walls_from_session_log():
    log = ("[1] + curl --version  (exit 0)\n"
           "20261026T070000Z_S2_curl_r01  http=200  win=v4  setup_ms=220.1  inter_family_ms=200.2  "
           "failed/abandoned=1  cross_checks=agree  wall_s=14.03\n"
           "20261026T064544Z_C0_curl_r01  http=200  win=v6  setup_ms=20.168  cross_checks=agree\n")
    assert ss.parse_walls(log) == {"20261026T070000Z_S2_curl_r01": 14.03}


def test_format_table_aligns_columns():
    out = ss.format_table([ss.row(_s1_record(), 1.0)]).splitlines()
    assert out[0].startswith("run_id") and set(out[1]) <= {"-", " "} and len(out) == 3
    assert out[0].index("scn") == out[2].index("  S1  ") + 2  # not the "_S1_" inside run_id


def test_load_session_filters_by_session_id(tmp_path):
    import json
    for sid, name in (("A", "a.json"), ("B", "b.json")):
        (tmp_path / name).write_text(json.dumps({"run_id": name, "environment": {"session_id": sid}}))
    assert [r["run_id"] for r in ss.load_session("B", tmp_path)] == ["b.json"]
