import json
from pathlib import Path

import pytest

from analysis import export_web as ew
from analysis import summarise as sm
from tests.test_summarise import make_record

FIX = Path(__file__).resolve().parent / "fixtures"

PAGE = f"""<script>
var FIND=[];
{ew.START}var D={{
  curl:{{
    C0:{{med:20.1,win:"v6",ifd:null,runs:[3,20],src:"pil"}},
    S1:{{med:220.0,win:"v4",ifd:200.0,runs:[3,20],src:"pil"}},
    X1:{{med:320.6,win:"v6",ifd:200.1,runs:[0,20],src:"ph"}}
  }},
  chromium:{{
    C0:{{med:21.4,win:"v6",ifd:null,runs:[0,20],src:"ph"}},
    S1:{{med:320.7,win:"v4",ifd:300.2,runs:[0,20],src:"ph"}},
    X1:{{med:322.4,win:"v6",ifd:300.4,runs:[0,20],src:"ph"}}
  }}
}};
var WIN={{
  curl:{{C0:[20,0,0],S1:[0,20,0],X1:[13,7,0]}},
  chromium:{{C0:[20,0,0],S1:[0,20,0],X1:[11,9,0]}}
}};
var RUNS=[];
var CAPS=[];
{ew.END}function drawResults(){{}}
</script>"""


def _complete(rec, pcap: Path):
    """Add the record fields the exporter reads beyond make_record()'s."""
    rec["schema_version"] = "0.2"
    rec["client"]["version"] = "test 1.0"
    rec["outcome"].update(http_status=200, exit_code=0, source="test")
    rec["evidence"].update(pcap_path=str(pcap), pcap_sha256=ew.hashlib.sha256(pcap.read_bytes()).hexdigest())
    rec["environment"]["git_commit"] = "abc1234"
    rec["timestamps"] = {"run_start_utc": "2026-10-26T19:00:00Z"}
    rec["cross_checks"].setdefault("conflicts", [])
    return rec


def write_runs(tmp_path, records):
    runs = tmp_path / "runs"
    runs.mkdir()
    for r in records:
        (runs / f"{r['run_id']}.json").write_text(json.dumps(r))
    return runs


def s1(session, client, rep, winner="v4", setup=222.0, **kw):
    fams = ("v6", "v6", "v4") if client == "chromium" else ("v6", "v4")
    offs = (0, 250, 301) if client == "chromium" else (0, 200)
    idx = fams.index(winner) if winner in fams else 0
    return make_record(session, client, "S1", rep, families=fams, offsets_ms=offs, winner_idx=idx,
                       setup_ms=setup, **kw)


def records(tmp_path, n=20, conflict_reps=(), s1_winners=None):
    pcap = FIX / "s1_manual_curl.pcap"
    out = []
    for rep in range(1, n + 1):
        out.append(make_record("a", "curl", "C0", rep, setup_ms=20.0 + rep / 100))
        winner = (s1_winners or {}).get(rep, "v4")
        r = s1("b", "curl", rep, winner=winner, setup=222.0 + rep / 100,
               cross="conflict" if rep in conflict_reps else "agree")
        if rep in conflict_reps:
            r["cross_checks"]["conflicts"] = [{"field": "remote_ip", "note": "test"}]
        out.append(r)
        out.append(make_record("c", "chromium", "C0", rep, setup_ms=20.1))
        out.append(s1("d", "chromium", rep, setup=322.0))
    for r in out:
        r["run_id"] = r["run_id"].replace("_S", "x_S").replace("_C", "x_C")  # unique ids per session
        _complete(r, pcap)
    return write_runs(tmp_path, out)


SESSIONS = [("curl", "C0", "a"), ("curl", "S1", "b"), ("chromium", "C0", "c"), ("chromium", "S1", "d")]


def run_export(tmp_path, runs, monkeypatch, sessions=SESSIONS):
    monkeypatch.setattr(ew, "REPRESENTATIVE", (("C0", "curl"), ("S1", "curl")))
    return ew.export(PAGE, sessions, runs_dir=runs, repo=Path("/"), fixtures=FIX)


def block_values(block: str):
    d, w = ew.parse_existing(block)
    return d, w


# --- a cell with no runs ----------------------------------------------------------------------

def test_cell_with_no_runs_keeps_placeholder_values(tmp_path, monkeypatch):
    res = run_export(tmp_path, records(tmp_path), monkeypatch)
    d, w = block_values(res.block)
    assert d["curl"]["X1"] == {"med": 320.6, "win": "v6", "ifd": 200.1, "runs": [0, 20], "src": "ph"}
    assert w["chromium"]["X1"] == [11, 9, 0]
    assert res.ok and not res.warnings


def test_dataset_cell_listed_but_with_no_records_falls_back_to_placeholder(tmp_path, monkeypatch):
    runs = records(tmp_path)
    sessions = SESSIONS[:3] + [("chromium", "S1", "missing-session")]
    res = run_export(tmp_path, runs, monkeypatch, sessions)
    d, _ = block_values(res.block)
    assert d["chromium"]["S1"] == {"med": 320.7, "win": "v4", "ifd": 300.2, "runs": [0, 20], "src": "ph"}


# --- a cell with a conflict -------------------------------------------------------------------

def test_conflict_run_is_excluded_named_and_fails_the_export(tmp_path, monkeypatch):
    res = run_export(tmp_path, records(tmp_path, conflict_reps=(7,)), monkeypatch)
    d, w = block_values(res.block)
    assert d["curl"]["S1"]["runs"] == [19, 20] and d["curl"]["S1"]["src"] == "pil"
    assert sum(w["curl"]["S1"]) == 19
    excluded = [x for x in res.warnings if x.startswith("excluded")]
    assert len(excluded) == 1 and "_S1_curl_r07" in excluded[0] and "remote_ip" in excluded[0]
    assert res.ok is False
    # the conflicting run's setup (222.07) is not in the median of the other 19 (222.01..222.20 without .07)
    assert d["curl"]["S1"]["med"] == pytest.approx(222.11)


def test_clean_complete_cells_are_val_with_real_medians(tmp_path, monkeypatch):
    res = run_export(tmp_path, records(tmp_path), monkeypatch)
    d, w = block_values(res.block)
    assert d["curl"]["S1"] == {"med": 222.105, "win": "v4", "ifd": 200.0, "runs": [20, 20], "src": "val"}
    assert d["curl"]["C0"]["ifd"] is None                      # not observed is null, never 0
    assert d["chromium"]["S1"]["ifd"] == 301.0                 # the backup v6 is not the second family
    assert w["chromium"]["S1"] == [0, 20, 0]


# --- modal winner -----------------------------------------------------------------------------

def _runs(winners):
    return [sm.run_from_record(s1("x", "curl", i + 1, winner=w)) for i, w in enumerate(winners)]


@pytest.mark.parametrize("winners, mode", [
    (["v4"] * 15 + ["v6"] * 5, "v4"),
    (["v6"] * 11 + ["v4"] * 9, "v6"),
    (["v6"] * 10 + ["v4"] * 10, None),          # tie: no mode
    ([], None),
])
def test_modal_winner(winners, mode):
    assert ew.modal_winner(_runs(winners)) == mode


def test_modal_winner_ignores_runs_without_a_winner():
    runs = _runs(["v4"] * 3 + ["v6"] * 2)
    for r in runs[:2]:
        r.winner = None
    assert ew.modal_winner(runs) == "v6"
    assert ew.win_counts(runs) == [2, 1, 2]


def test_tied_cell_is_reported_and_fails_the_export(tmp_path, monkeypatch):
    winners = {rep: "v6" for rep in range(1, 11)}
    res = run_export(tmp_path, records(tmp_path, s1_winners=winners), monkeypatch)
    assert res.ok is False and any("no single modal winner" in x for x in res.warnings)


# --- the page block ---------------------------------------------------------------------------

def test_only_the_marked_block_changes_and_rewriting_is_idempotent(tmp_path, monkeypatch):
    res = run_export(tmp_path, records(tmp_path), monkeypatch)
    before, old, after = ew.split_page(PAGE)
    page2 = before + res.block + after
    assert page2.startswith(PAGE[:PAGE.index(ew.START)]) and page2.endswith(PAGE[PAGE.index(ew.END):])
    assert run_export(tmp_path, tmp_path / "runs", monkeypatch).block == res.block
    assert ew.split_page(page2)[1] == res.block


@pytest.mark.parametrize("page", [PAGE.replace(ew.START, ""), PAGE + ew.END, PAGE.replace(ew.END, "").replace(
    ew.START, ew.END + ew.START)])
def test_missing_or_duplicate_markers_are_refused(page):
    with pytest.raises(ew.ExportError):
        ew.split_page(page)


def test_runs_entries_carry_the_stored_record_verbatim(tmp_path, monkeypatch):
    res = run_export(tmp_path, records(tmp_path), monkeypatch)
    line = next(x for x in res.block.splitlines() if "_S1_curl_r" in x and x.strip().startswith("{id:"))
    rec_text = json.loads(line[line.index("rec:") + 4:line.index(",chk:")])
    rec = json.loads(rec_text)
    assert rec["metrics"]["inter_family_attempt_delay_ms"] == {"value": 200.0, "status": "computed"}
    assert rec["cross_checks"]["status"] == "agree"
    assert '"first_syn_ns": 1000000000' in rec_text    # integers kept as text, no float rounding in JS
