"""The website against the report and the deck (web_check), and the Extensions/replay generator (web_extensions).

None of these needs the lab's data: they read the committed page, docs, deck numbers, figures and examples/.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from analysis import export_web as ew
from analysis import web_check as wc
from analysis import web_extensions as wx

REPO = Path(__file__).resolve().parents[2]
PAGE = (REPO / "web" / "index.html").read_text(encoding="utf-8")


def problems(text: str) -> list[str]:
    return wc.check_page(text, REPO)


def swap(text: str, old: str, new: str) -> str:
    assert old in text, f"{old!r} is not on the page"
    return text.replace(old, new, 1)


# --- the committed page ----------------------------------------------------------------------

def test_committed_page_matches_the_report_and_the_deck():
    assert problems(PAGE) == []


def test_tags_are_the_dashboards_four_verbatim():
    from analysis.dashboard import TAG_LABEL
    assert wc.TAG_LABEL == TAG_LABEL
    ext = wc.js_var(wc.block(PAGE, wc.EXT_START, wc.EXT_END), "EXT")
    assert ext["tags"] == TAG_LABEL


def test_extensions_page_is_reachable_from_the_top_bar_and_the_mobile_menu():
    assert PAGE.count('data-tab="extensions"') == 2
    assert '"extensions"' in PAGE.split("var TABS=")[1].split(";")[0]


def test_page_lists_four_extension_datasets_and_the_deck_total():
    ext = wc.js_var(wc.block(PAGE, wc.EXT_START, wc.EXT_END), "EXT")
    assert [d["name"] for d in ext["datasets"]] == list(wx.EXTENSION_DATASETS)
    assert ext["runs"] == {"core": 280, "extensions": 1048, "total": 1328}


# --- each kind of divergence fails -----------------------------------------------------------

def test_a_generated_number_that_differs_from_the_deck_fails():
    bad = swap(PAGE, '"curl_flip": "221–226 ms"', '"curl_flip": "221–231 ms"')
    assert any(p.startswith("curl_flip:") for p in problems(bad))


def test_a_core_median_that_differs_from_the_deck_fails():
    bad = swap(PAGE, "S1:{med:222.221,", "S1:{med:222.231,")
    assert any(p.startswith("curl_S1:") for p in problems(bad))


def test_a_hand_written_number_not_in_the_docs_fails():
    bad = swap(PAGE, "250.625 ms (S1)", "250.627 ms (S1)")
    assert any("number 250.627" in p for p in problems(bad))


def test_a_data_deck_quote_that_differs_fails():
    bad = swap(PAGE, "curl's Connection Attempt Delay is 200 ms</span>", "curl waits 200 ms</span>")
    assert any(p.startswith("sattler_curl:") for p in problems(bad))


def test_an_unknown_evidence_tag_fails():
    bad = swap(PAGE, '<span class="tag" data-tag="derived"></span>', '<span class="tag" data-tag="measured"></span>')
    assert any("data-tag=\"measured\"" in p for p in problems(bad))


@pytest.mark.parametrize("old, new, expect", [
    ("so it is not a prediction registered before they existed", "so it was predicted before the data", "predicted before"),
    ("tracks the configured timeout", "equals the configured timeout", "'equals'"),
    ("Our measured crossovers <b>reproduce</b>", "We discovered", "discover"),
    ("the jitter cells show 95% Wilson intervals", "the jitter cells show 95% Wilson intervals; colour is analyzed",
     "British spelling"),
])
def test_banned_or_missing_wording_fails(old, new, expect):
    assert any(expect in p for p in problems(swap(PAGE, old, new)))


def test_a_cited_title_is_not_read_as_our_claim():
    assert "Happy Eyeballs Implementations" in PAGE      # the paper's title, inside <cite>
    assert not any("client internals" in p for p in problems(PAGE))


def test_an_external_font_or_script_fails():
    bad = swap(PAGE, "<style>", '<link rel="stylesheet" href="https://fonts.example/x.css"><style>')
    assert any("external request" in p for p in problems(bad))
    bad = swap(PAGE, "<style>", "<script src=//cdn.example/x.js></script><style>")
    assert any("external request" in p for p in problems(bad))


def test_plain_links_to_sources_are_allowed():
    assert 'href="https://doi.org/10.1145/3730567.3732925"' in PAGE and problems(PAGE) == []


def test_a_figure_that_is_not_in_docs_figures_fails():
    bad = swap(PAGE, "figures/fig2_he_linearity_full.svg", "figures/fig9_made_up.svg")
    assert any("fig9_made_up.svg" in p for p in problems(bad))


def test_a_web_figure_that_differs_from_docs_figures_fails(tmp_path):
    repo = tmp_path / "repo"
    for d in ("docs", "deck", "examples", "web"):
        shutil.copytree(REPO / d, repo / d, ignore=shutil.ignore_patterns("node_modules", "*.pptx", "*.pdf", "*.pcap"))
    shutil.copy(REPO / "README.md", repo / "README.md")
    assert wc.check_page(PAGE, repo) == []
    (repo / "web" / "figures" / "fig2_he_linearity_full.svg").write_text("<svg/>")
    (repo / "web" / "figures" / "stray.svg").write_text("<svg/>")
    found = wc.check_page(PAGE, repo)
    assert any("web/figures/fig2_he_linearity_full.svg" in p for p in found)
    assert any("stray.svg" in p for p in found)


def test_numbers_are_tokenised_without_trailing_punctuation():
    assert wc.checked_numbers("221–226, 1,328 runs; RFC 6555 (2012) and 0.5 and 20") == ["221", "226", "1,328", "2012", "0.5"]
    assert not hasattr(wc, "ALLOWED_NUMBERS")       # no exemptions: every number has a source


# --- the generator ---------------------------------------------------------------------------

@pytest.mark.parametrize("x, f2, s2", [(222.135, "222.14", "+222.14"), (-0.19, "-0.19", "−0.19"), (0.895, "0.90", "+0.90"),
                                       (200.757, "200.76", "+200.76")])
def test_formatting_is_half_up_with_a_real_minus(x, f2, s2):
    assert wx.f2(x) == f2 and wx.signed2(x) == s2


@pytest.mark.parametrize("name", ["core", "made-up", "../dataset"])
def test_only_the_four_extension_datasets_are_accepted(name):
    with pytest.raises(wx.ExtensionError):
        wx.certify(name)


def test_an_extension_dataset_that_fails_certification_is_refused(tmp_path):
    with pytest.raises(wx.ExtensionError, match="not certified"):
        wx.certify("he-sweep", runs_dir=tmp_path)      # no records at all


def test_core_block_still_refuses_variant_sessions():
    with pytest.raises(ew.ExportError, match="certified extension dataset"):
        ew.export(PAGE, [("curl@he200", "S1", "x")])


def test_replays_read_the_committed_examples():
    r = {x["id"]: x for x in wx.replays()}
    assert set(r) == {"20261026T192159Z_C0_curl_r07", "20261026T193106Z_S1_curl_r08", "20261026T193420Z_S1_chromium_r01"}
    c0, s1, ch = (r["20261026T192159Z_C0_curl_r07"], r["20261026T193106Z_S1_curl_r08"],
                  r["20261026T193420Z_S1_chromium_r01"])
    # the values examples/README.md states, recomputed from each capture
    assert (c0["setup"], c0["ifd"], c0["win"]) == (20.695, None, "v6")
    assert (s1["setup"], s1["ifd"], s1["win"], s1["ab"]) == (222.254, 200.976, "v4", 1)
    assert (ch["setup"], ch["ifd"], ch["ab"]) == (324.766, 301.266, 2)
    v6 = [a for a in ch["atts"] if a["f"] == "v6"]
    assert len(v6) == 2 and round(v6[1]["syn"] - v6[0]["syn"], 3) == 250.29
    assert all(a["syns"] == 1 for x in r.values() for a in x["atts"])     # no SYN retransmissions
    assert s1["rtt"] == {"v4": "21.15 ms RTT", "v6": "blackholed"}


def test_a_replay_whose_capture_does_not_match_its_hash_is_refused(tmp_path):
    for p in (REPO / "examples").iterdir():
        shutil.copy(p, tmp_path / p.name)
    rid = "20261026T193106Z_S1_curl_r08"
    sums = (tmp_path / "SHA256SUMS").read_text().replace(json.loads(
        (tmp_path / f"{rid}.json").read_text())["evidence"]["pcap_sha256"], "0" * 64)
    (tmp_path / "SHA256SUMS").write_text(sums)
    with pytest.raises(wx.ExtensionError, match="sha256"):
        wx.replay(rid, tmp_path)


def test_committed_replays_are_what_the_generator_makes_from_examples():
    blk = wc.block(PAGE, wc.EXT_START, wc.EXT_END)
    assert wc.js_var(blk, "REPLAY") == json.loads(json.dumps(wx.replays()))


def test_extensions_block_round_trips_through_the_checker():
    ext = {"tags": wc.TAG_LABEL, "datasets": [{"name": "he-sweep", "runs": 270}], "runs": {}}
    blk = ew.render_extensions(ext | {"runs": {"extensions": 270}}, [{"id": "r"}])
    assert wc.js_var(blk, "EXT")["datasets"][0]["runs"] == 270 and wc.js_var(blk, "REPLAY") == [{"id": "r"}]


def test_sync_figures_copies_used_figures_and_removes_others(tmp_path):
    (tmp_path / "docs" / "figures").mkdir(parents=True)
    (tmp_path / "web" / "figures").mkdir(parents=True)
    (tmp_path / "docs" / "figures" / "a.svg").write_text("<svg>a</svg>")
    (tmp_path / "web" / "figures" / "old.svg").write_text("x")
    page = '<img src="figures/a.svg">'
    assert ew.sync_figures(page, write=False, repo=tmp_path) == ["copy docs/figures/a.svg", "remove web/figures/old.svg"]
    assert (tmp_path / "web" / "figures" / "old.svg").exists()            # --check writes nothing
    ew.sync_figures(page, write=True, repo=tmp_path)
    assert [p.name for p in (tmp_path / "web" / "figures").iterdir()] == ["a.svg"]
    assert ew.sync_figures(page, write=False, repo=tmp_path) == []
    with pytest.raises(ew.ExportError):
        ew.sync_figures('<img src="figures/missing.svg">', write=False, repo=tmp_path)


# --- numbers come from the report (with the docs it links) or the deck -----------------------

def test_number_sources_are_the_report_its_linked_docs_and_the_deck():
    names = {str(p.relative_to(REPO)) for p in wc.number_sources(REPO)}
    assert {"docs/report.md", "deck/deck_numbers.json", "docs/findings/latency_and_he_sweeps.md",
            "docs/findings/syn_retransmission_partial_loss.md"} <= names
    assert "README.md" not in names and "examples/README.md" not in names


def test_a_number_found_only_in_the_readme_fails():
    bad = swap(PAGE, "<b>Ubuntu · Linux network namespaces", "<b>Ubuntu 24.04 · Linux network namespaces")
    assert any("number 24.04" in p for p in problems(bad))


def test_a_stored_run_value_is_accepted_but_a_changed_one_is_not():
    assert "222.254" in wc.page_text(PAGE) and problems(PAGE) == []      # Overview's worked record, from examples/
    bad = swap(PAGE, '"tcp_setup_time_ms":\n      { "value": 222.254', '"tcp_setup_time_ms":\n      { "value": 222.264')
    assert any("number 222.264" in p for p in problems(bad))


# --- connect timeout and overclaims ----------------------------------------------------------

@pytest.mark.parametrize("old, new", [
    ("on Linux, many seconds, set by", "on Linux, around 130 seconds with default SYN retries, set by"),
    ("on Linux, many seconds, set by", "on Linux, tens of seconds, set by"),
    ("TCP gives up — many seconds", "TCP gives up — ~130 s"),
    ("waiting on the kernel's SYN retries (many seconds)", "waiting on the OS TCP timeout (~130 s)"),   # Playground script
])
def test_connect_timeout_figures_fail(old, new):
    assert any("connect timeout" in p for p in problems(swap(PAGE, old, new)))


@pytest.mark.parametrize("old, new", [
    ("that bounds this penalty to a short fallback delay", "that eliminates this penalty"),
    ("(RFC 8305) bounds that wait", "(RFC 8305) removes that wait"),
    ("then show the packets behind it", "then prove it"),
])
def test_audit_overclaims_fail(old, new):
    assert any("bounds the wait" in p for p in problems(swap(PAGE, old, new)))


def test_audit_fixes_are_on_the_page():
    for text in ("bounds that wait", "bounds this penalty to a short fallback delay",
                 "then show the packets behind it", "(curl C0 and S5 are both 20.697 ms)",
                 "(our reading of why)", "many seconds, set by the kernel's SYN retry settings"):
        assert text in PAGE, text
