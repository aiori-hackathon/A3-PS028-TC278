"""The presentation deck (deck/): figures exist, numbers match their source docs, the committed .pptx matches both."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DECK = REPO / "deck"
BUILD = DECK / "build_deck.js"
NUMBERS = DECK / "deck_numbers.json"
PPTX = DECK / "HappyLab_PS028_TC278.pptx"
PDF = DECK / "HappyLab_PS028_TC278.pdf"


def _numbers() -> dict[str, dict]:
    return {k: v for k, v in json.loads(NUMBERS.read_text(encoding="utf-8")).items() if not k.startswith("_")}


def _figure_paths() -> list[str]:
    return sorted(set(re.findall(r"docs/figures/[\w./-]+", BUILD.read_text(encoding="utf-8"))))


def test_every_figure_the_deck_references_exists():
    paths = _figure_paths()
    assert paths, "build_deck.js names no figures"
    missing = [p for p in paths if not (REPO / p).is_file()]
    assert not missing, f"figures referenced by the deck but missing from docs/figures/: {missing}"


def test_every_deck_number_appears_verbatim_in_its_source():
    for key, v in _numbers().items():
        src = REPO / v["src"]
        assert src.is_file(), f"{key}: source {v['src']} does not exist"
        assert v["text"] in src.read_text(encoding="utf-8"), f"{key}: {v['text']!r} not found in {v['src']}"


def test_every_number_key_used_by_the_deck_is_defined():
    used = set(re.findall(r"""\bn\("(\w+)"\)|\bg\("(\w+)"\)""", BUILD.read_text(encoding="utf-8")))
    used = {a or b for a, b in used}
    assert used, "build_deck.js reads no numbers"
    assert used <= set(_numbers()), f"undefined keys: {sorted(used - set(_numbers()))}"


def test_T_is_never_rounded_to_one_decimal():
    text = BUILD.read_text(encoding="utf-8")
    for bad in ("222.0 ", "222.0)", "322.5"):
        assert bad not in text, f"T must be given to two decimals with its campaign, found {bad!r}"


def test_run_total_on_the_scale_slide_adds_up():
    report = (REPO / "docs" / "report.md").read_text(encoding="utf-8")
    sweeps = (REPO / "docs" / "findings" / "latency_and_he_sweeps.md").read_text(encoding="utf-8")
    jitter = (REPO / "docs" / "findings" / "syn_retransmission_partial_loss.md").read_text(encoding="utf-8")
    vc = (REPO / "docs" / "datasets" / "variant-control.md").read_text(encoding="utf-8")
    assert "**280 runs**" in report and "180 runs" in sweeps and "270 runs" in sweeps and "558 runs" in jitter
    vc_sessions = len(re.findall(r"^\| \d+ \|", vc, re.MULTILINE))
    vc_reps = int(re.search(r"^reps: (\d+)$", vc, re.MULTILINE).group(1))
    total = 280 + vc_sessions * vc_reps + 558 + 180 + 270
    assert total == 1328
    assert '"1,328"' in BUILD.read_text(encoding="utf-8")
    manifests = [REPO / "docs" / "dataset.md", *(REPO / "docs" / "datasets").glob("*.md")]
    assert len([m for m in manifests if m.name != "README.md"]) == 5, "the deck says five certified datasets"


def _pptx_text() -> str:
    with zipfile.ZipFile(PPTX) as z:
        return "\n".join(z.read(n).decode("utf-8") for n in z.namelist()
                         if re.match(r"ppt/(slides|notesSlides)/\w+\.xml$", n))


@pytest.mark.skipif(not PPTX.exists(), reason="deck not built (cd deck && npm ci && node build_deck.js)")
def test_committed_pptx_carries_the_current_numbers():
    text = _pptx_text().replace("&amp;", "&")
    for key, v in _numbers().items():
        token = re.search(r"[−+]?\d[\d,.]*", v["text"])
        if token and f'"{key}"' in BUILD.read_text(encoding="utf-8"):
            assert token.group(0) in text, f"{key}: {token.group(0)} is not in the committed .pptx; rebuild the deck"


@pytest.mark.skipif(not PPTX.exists(), reason="deck not built (cd deck && npm ci && node build_deck.js)")
def test_committed_pptx_embeds_the_exported_figures_unchanged():
    with zipfile.ZipFile(PPTX) as z:
        media = {hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith("ppt/media/")}
    for p in _figure_paths():
        digest = hashlib.sha256((REPO / p).read_bytes()).hexdigest()
        assert digest in media, f"{p} differs from the image in the .pptx; rebuild the deck"


@pytest.mark.skipif(not PPTX.exists(), reason="deck not built")
def test_every_slide_has_speaker_notes_with_a_time_budget():
    with zipfile.ZipFile(PPTX) as z:
        slides = [n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)]
        notes = [z.read(n).decode("utf-8") for n in z.namelist() if re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n)]
    assert len(notes) == len(slides) == 14
    assert all("TIME: " in x and "NUMBER NOT TO FORGET" in x for x in notes)


def test_pdf_is_committed_next_to_the_pptx():
    if PPTX.exists():
        assert PDF.exists(), "export the deck to PDF too (see deck/README.md)"


def _demo_slide_source() -> str:
    text = BUILD.read_text(encoding="utf-8")
    return text[text.index("// 6. Demo"):text.index("// 7. ")]


def test_demo_slide_notes_drive_the_demo_with_make_demo():
    block = _demo_slide_source()
    notes = block[block.index("notes(s,"):]
    assert "make demo" in notes and "make demo SCENARIO=" in notes and "make demo-check" in notes
    for old in ("verify.sh up", "orchestrate.py", "summarise_session.py", "tcpdump -n -tt -r"):
        assert old not in notes, f"slide 6 notes still spell out {old}; make demo replaces it"
    assert "sudo src/lab/setup.sh" in notes and "sudo src/lab/teardown.sh" in notes   # before and after the talk
    assert "examples/" in notes   # the stated fallback


def test_demo_slide_beats_fill_its_three_minutes_forty():
    block = _demo_slide_source()
    assert 'notes(s, "3m40s (20s slide + 3m20s terminal)", "3:40-7:20"' in block
    beats = [int(x) for x in re.findall(r'^\s*\["(\d+)s", "', block, re.MULTILINE)]
    assert sum(beats) == 220, beats


@pytest.mark.skipif(not PPTX.exists(), reason="deck not built")
def test_committed_pptx_carries_the_make_demo_notes():
    text = _pptx_text()
    assert "make demo SCENARIO=S4 CLIENT=chromium" in text and "summarise_session.py" not in text
