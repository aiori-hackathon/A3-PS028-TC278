"""Dataset manifests (docs/datasets/<name>.md) and the single source of scenario IDs.

The core dataset (docs/dataset.md) keeps its own tests in test_summarise.py; these cover a
manifest that declares a different shape, and manifests that do not match their runs.
"""

import pytest

from analysis import dashboard
from analysis import export_web as ew
from analysis import summarise as sm
from analysis.scenario_config import ScenarioConfigError, scenario_ids
from runner import clients, orchestrate
from tests.test_summarise import REPO, make_record, write

A, B, C = "20261101T100000Z", "20261101T110000Z", "20261101T120000Z"


def manifest(tmp_path, header: str | None, rows: list[tuple[str, str, str]], name="small.md"):
    head = f"---\n{header}---\n" if header is not None else ""
    table = "\n".join(f"| {i} | {c} | {s} | `{sid}` | test |" for i, (c, s, sid) in enumerate(rows, 1))
    doc = tmp_path / name
    doc.write_text(f"{head}# Small dataset\n\n## Sessions in the dataset\n\n"
                   f"| # | Client | Scenario | Session | Note |\n|---|---|---|---|---|\n{table}\n\n## Notes\n\nnone\n")
    return doc


SMALL = "clients: [curl]\nscenarios: [C0, S1]\nreps: 2\n"
SMALL_ROWS = [("curl", "C0", A), ("curl", "S1", B)]


def small_runs(tmp_path, reps=2):
    runs = tmp_path / "runs"
    recs = ([make_record(A, "curl", "C0", i, setup_ms=20.0 + i) for i in range(1, reps + 1)]
            + [make_record(B, "curl", "S1", i, families=("v6", "v4"), offsets_ms=(0, 200), winner_idx=1,
                           setup_ms=220.0 + i) for i in range(1, reps + 1)])
    for r in recs:
        r["client"].update(version="curl 8.5.0 (test)", config={"happy_eyeballs_timeout_ms": 200})
    write(runs, recs)
    return runs


# --- one source of scenario IDs ------------------------------------------------------------

def test_scenario_ids_come_from_scenarios_yaml_in_file_order():
    # hand-written core scenarios first, then the generated extensions, each file in its own order
    assert scenario_ids() == ("C0", "S1", "S2", "S3", "S4", "S5", "S6") + tuple(f"Gv6d{n}" for n in (100, 200, 250, 300, 350, 400))
    assert scenario_ids(generated=None) == ("C0", "S1", "S2", "S3", "S4", "S5", "S6")


def test_runner_and_orchestrator_read_the_same_ids():
    assert clients.ALL_SCENARIOS == scenario_ids()
    assert orchestrate.ALL_SUPPORTED == scenario_ids()
    assert orchestrate.SCENARIOS_FILE == REPO / "src" / "config" / "scenarios.yaml"


def test_a_scenario_added_to_the_yaml_is_picked_up(tmp_path):
    y = tmp_path / "scenarios.yaml"
    y.write_text("baseline: {rtt_ms: 20}\nscenarios:\n  C0: {label: a}\n  X1: {label: b}\n  S1: {label: c}\n")
    assert scenario_ids(y) == ("C0", "X1", "S1")


@pytest.mark.parametrize("text", ["", "scenarios: {}\n", "scenarios: [C0]\n", "key: [unclosed\n"])
def test_a_yaml_without_scenarios_is_refused(tmp_path, text):
    y = tmp_path / "scenarios.yaml"
    y.write_text(text)
    with pytest.raises(ScenarioConfigError):
        scenario_ids(y)


# --- a manifest with a different shape -------------------------------------------------------

def test_core_doc_has_the_core_shape_and_no_header():
    m = sm.load_manifest(REPO / "docs" / "dataset.md")
    assert m.shape == sm.CORE_SHAPE and len(m.sessions) == 14
    assert not (REPO / "docs" / "dataset.md").read_text().startswith("---")


def test_manifest_with_a_different_shape_builds_end_to_end(tmp_path):
    m = sm.load_manifest(manifest(tmp_path, SMALL, SMALL_ROWS), require_header=True)
    assert m.shape == sm.Shape(("curl",), ("C0", "S1"), 2)
    sessions, runs, summary = sm.build(manifest=m, runs_dir=small_runs(tmp_path), repo=None)
    assert sessions == [("curl", "C0", A), ("curl", "S1", B)]
    assert len(runs) == 4
    cells = summary["cells"]
    assert list(cells) == ["curl"] and list(cells["curl"]) == ["C0", "S1"]
    assert cells["curl"]["S1"]["winning_family"] == {"v4": 2}
    assert cells["curl"]["S1"]["scenario_penalty_ms"] == pytest.approx(200.0)
    assert summary["dataset"]["shape"] == {"clients": ["curl"], "scenarios": ["C0", "S1"], "reps": 2}
    assert summary["interpretation"] == []   # every statement compares curl with Chromium
    report = sm.text_report(summary)
    assert "curl" in report and "chromium" not in report and "S2" not in report


def test_manifest_without_c0_reports_no_penalty_and_says_why(tmp_path):
    doc = manifest(tmp_path, "clients: [curl]\nscenarios: [S1]\nreps: 2\n", [("curl", "S1", B)])
    _, _, summary = sm.build(manifest=sm.load_manifest(doc, require_header=True),
                             runs_dir=small_runs(tmp_path), repo=None)
    cell = summary["cells"]["curl"]["S1"]
    assert cell["scenario_penalty_ms"] is None
    assert cell["scenario_penalty_note"] == "no C0 in this dataset"


def test_dashboard_draws_only_the_manifest_shape(tmp_path):
    _, runs, summary = sm.build(manifest=sm.load_manifest(manifest(tmp_path, SMALL, SMALL_ROWS)),
                                runs_dir=small_runs(tmp_path), repo=None)
    page = dashboard.render(summary, runs, "")
    assert "1 client implementation(s) × 2 scenario(s) (C0, S1) × 2 repetitions" in page and "Not the core dataset" in page
    timeline = dashboard.fig_timeline(runs, ("curl",), ("C0", "S1"), 2)
    assert timeline["layout"]["yaxis"]["ticktext"] == ["C0 · curl", "S1 · curl"]
    assert "<td>Chromium</td>" not in page
    assert dashboard.fig_winner(summary["cells"], 2)["layout"]["xaxis"]["range"] == [0, 2]


# --- a manifest that does not match its runs: refused loudly ----------------------------------

def test_manifest_declaring_more_reps_than_its_runs_is_refused(tmp_path):
    doc = manifest(tmp_path, SMALL.replace("reps: 2", "reps: 3"), SMALL_ROWS)
    with pytest.raises(sm.DatasetError, match="2 records, expected 3"):
        sm.build(manifest=sm.load_manifest(doc), runs_dir=small_runs(tmp_path), repo=None)


def test_manifest_whose_runs_are_unclean_is_refused(tmp_path):
    runs = small_runs(tmp_path)
    bad = make_record(B, "curl", "S1", 2, cross="conflict")
    write(runs, [bad])   # overwrites r02 of the S1 session
    with pytest.raises(sm.DatasetError, match="cross_checks conflict"):
        sm.build(manifest=sm.load_manifest(manifest(tmp_path, SMALL, SMALL_ROWS)), runs_dir=runs, repo=None)


def test_manifest_row_pointing_at_the_wrong_session_is_refused(tmp_path):
    doc = manifest(tmp_path, SMALL, [("curl", "C0", A), ("curl", "S1", A)])   # S1 row names the C0 session
    with pytest.raises(sm.DatasetError, match="is not curl/S1"):
        sm.build(manifest=sm.load_manifest(doc), runs_dir=small_runs(tmp_path), repo=None)


@pytest.mark.parametrize("rows, message", [
    ([("curl", "C0", A)], r"\(2\)"),                                        # a declared cell missing
    (SMALL_ROWS + [("curl", "S1", C)], r"\(2\)"),                            # a cell twice
    (SMALL_ROWS + [("chromium", "C0", C)], r"\(2\)"),                        # a client not declared
    ([("curl", "C0", A), ("curl", "S2", B)], r"\(2\)"),                      # a scenario not declared
])
def test_table_that_does_not_match_the_declared_shape_is_refused(tmp_path, rows, message):
    with pytest.raises(sm.DatasetError, match="expected exactly one session per client x scenario " + message):
        sm.load_manifest(manifest(tmp_path, SMALL, rows))


@pytest.mark.parametrize("header, message", [
    ("clients: [curl]\nscenarios: [C0, X9]\nreps: 2\n", r"\['X9'\] are not defined in src/config/scenarios.yaml"),
    ("clients: [wget]\nscenarios: [C0]\nreps: 2\n", "unknown client"),
    ("clients: [curl]\nscenarios: [C0]\n", "missing reps"),
    ("clients: [curl]\nscenarios: [C0]\nreps: 0\n", "at least 1"),
    ("clients: [curl]\nscenarios: [C0]\nreps: true\n", "at least 1"),
    ("clients: [curl]\nscenarios: [C0, C0]\nreps: 2\n", "twice"),
    ("clients: curl\nscenarios: [C0]\nreps: 2\n", "non-empty list"),
    ("clients: [curl]\nscenarios: []\nreps: 2\n", "non-empty list"),
    ("clients: [curl]\nscenarios: [C0]\nreps: 2\nshape: big\n", "unknown keys shape"),
    ("- just a list\n", "must be a mapping"),
])
def test_bad_header_is_refused(tmp_path, header, message):
    with pytest.raises(sm.DatasetError, match=message):
        sm.load_manifest(manifest(tmp_path, header, [("curl", "C0", A)]))


def test_unclosed_header_is_refused(tmp_path):
    doc = tmp_path / "x.md"
    doc.write_text("---\nclients: [curl]\n## Sessions in the dataset\n")
    with pytest.raises(sm.DatasetError, match="no closing"):
        sm.load_manifest(doc)


def test_named_manifest_must_have_a_header(tmp_path):
    doc = manifest(tmp_path, None, SMALL_ROWS)
    with pytest.raises(sm.DatasetError, match="no header"):
        sm.load_manifest(doc, require_header=True)


def test_row_with_an_unknown_scenario_is_refused_not_skipped(tmp_path):
    doc = manifest(tmp_path, SMALL, SMALL_ROWS + [("curl", "S9", C)])
    with pytest.raises(sm.DatasetError, match="cannot read session row"):
        sm.load_manifest(doc)


# --- --dataset ------------------------------------------------------------------------------

def test_dataset_names_resolve(tmp_path, monkeypatch):
    assert sm.dataset_path() == sm.dataset_path("core") == REPO / "docs" / "dataset.md"
    assert sm.out_dir_for() == sm.OUT_DIR and sm.out_dir_for("small") == sm.OUT_DIR / "small"
    monkeypatch.setattr(sm, "DATASETS_DIR", tmp_path)
    manifest(tmp_path, SMALL, SMALL_ROWS)
    assert sm.load_dataset("small").shape.reps == 2
    with pytest.raises(sm.DatasetError, match="no dataset manifest"):
        sm.dataset_path("absent")
    with pytest.raises(sm.DatasetError, match="lower-case"):
        sm.dataset_path("../dataset")


@pytest.mark.parametrize("main", [sm.main, dashboard.main])
def test_unknown_dataset_fails_loudly(main, capsys):
    assert main(["--dataset", "absent", "--out", "/nonexistent/never-written"]) == 1
    assert "no dataset manifest" in capsys.readouterr().err


def test_export_web_refuses_a_named_dataset_into_the_public_page(capsys):
    assert ew.main(["--dataset", "small", "--check"]) == 2
    assert ew.main(["--dataset", "small", "--page", str(ew.PAGE), "--check"]) == 2
    assert "core dataset only" in capsys.readouterr().err
