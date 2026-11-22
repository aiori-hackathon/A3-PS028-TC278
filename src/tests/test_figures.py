"""P9 comparison figures: the pure parts (rounding, data shaping, claims table, PNG dpi). No browser."""

from __future__ import annotations

import json
import struct
import zlib
from types import SimpleNamespace

import pytest

from analysis import figures as fg
from analysis import summarise as sm
from analysis.dashboard import TAG_LABEL


def test_evidence_tags_are_the_dashboards_four():
    assert fg.TAG == TAG_LABEL
    assert len(set(fg.TAG.values())) == 4


@pytest.mark.parametrize("x, out", [(222.135, "222.14"), (221.964, "221.96"), (221.529, "221.53"), (0.895, "0.90"),
                                    (1.156, "1.16"), (0.61, "0.61"), (221.84, "221.84")])
def test_two_decimals_round_half_up_like_the_docs(x, out):
    assert fg.f2(x) == out


def _he_rows():
    vals = {50: 0.687, 100: 0.792, 150: 0.759, 200: 0.895, 250: 0.819, 300: 1.896, 400: 1.156, 500: 1.986}
    rows = [{"client": "curl", "timeout_ms": None, "T_minus_predicted_ms": None}]
    rows += [{"client": f"curl@he{k}", "timeout_ms": k, "T_minus_predicted_ms": v} for k, v in vals.items()]
    return rows


def test_residual_groups_keep_the_unevenness():
    g = fg.residual_groups(_he_rows())
    assert g["below"] == [0.687, 0.895] and g["from"] == [1.156, 1.986]
    assert g["upper_monotonic"] is False          # he400 sits below he300 and he500
    assert "curl" not in g["by_client"]           # plain curl has no prediction


def test_spread():
    assert fg.spread([221.529, 221.964, 221.84, 222.135]) == 0.61


def test_setup_oracle_cells_median_per_cell_and_skips_uncomputed_oracle():
    R = SimpleNamespace
    runs = [R(client="curl", scenario="Gv6d205", setup_ms=s, oracle_setup_ms=o, oracle_status=st)
            for s, o, st in ((221.5, 21.0, "computed"), (221.9, 20.9, "computed"), (222.4, None, "not_available"))]
    (cell,) = fg.setup_oracle_cells(runs, {("curl", "Gv6d205"): 226.0})
    assert cell == {"client": "curl", "scenario": "Gv6d205", "rtt_ms": 226.0, "n": 3,
                    "setup_median_ms": 221.9, "oracle_setup_median_ms": 20.95}


def _data():
    lat = [{"client": c, "flip_bracket": {"above_ms": a, "below_ms": b}, "T_ms": T}
           for c, a, b, T in (("curl", 221.0, 226.0, 221.84), ("chromium", 321.0, 326.0, 321.99))]
    he = [{"client": "curl", "S1": {"v4_first_syn_ms": 200.832}}, {"client": "curl@he200", "S1": {"v4_first_syn_ms": 200.833}}]
    rep = [{"campaign": c, "T_ms": t} for c, t in (("variant-control", 221.529), ("jitter-loss", 221.964),
                                                   ("latency-sweep", 221.84), ("he-sweep", 222.135))]
    return {"latency_sweep": lat, "he_sweep": he, "residuals": fg.residual_groups(_he_rows()),
            "T_reproducibility": rep, "T_spread_ms": 0.61}


def test_claims_table_separates_core_from_extensions():
    rows = fg.claims(_data())
    core = [r for r in rows if r["section"] == "core"]
    ext = [r for r in rows if r["section"] == "ext"]
    assert core and ext and len(core) + len(ext) == len(rows)
    assert all(r["dataset"] == "core (280 runs)" for r in core)
    assert not any("core" in r["dataset"] for r in ext)
    assert {r["tag"] for r in rows} <= set(fg.TAG)
    assert {"packet", "client"} <= {r["tag"] for r in core}


def test_claims_table_numbers_come_from_the_data():
    text = " | ".join(r["claim"] for r in fg.claims(_data()))
    assert "curl 221–226, Chromium 321–326 ms; latency-sweep T 221.84 / 321.99 ms inside both" in text
    assert "+0.69 to +0.90 ms up to he250 and +1.16 to +1.99 ms from he300 (not monotonic)" in text
    assert ("variant-control 221.53, jitter-loss 221.96, latency-sweep 221.84, he-sweep 222.14 ms; "
            "within 0.61 ms; one host and one kernel") in text
    assert "200.833 vs 200.832" in text


def test_he150_stays_a_boundary_case():
    (row,) = [r for r in fg.claims(_data()) if "he150" in r["claim"]]
    assert row["claim"].startswith("BOUNDARY CASE, NOT A FINDING") and row["section"] == "ext"


def _png(w=4, h=2, extra=b""):
    def chunk(t, body):
        return struct.pack(">I", len(body)) + t + body + struct.pack(">I", zlib.crc32(t + body) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x00" * (3 * w) for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + extra + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def test_png_gets_one_300_dpi_phys_chunk_after_ihdr():
    out = fg.png_with_dpi(_png())
    assert fg.png_info(out) == {"width": 4, "height": 2, "dpi": 300}
    assert out.index(b"pHYs") < out.index(b"IDAT")
    # an existing pHYs is replaced, not duplicated
    old = struct.pack(">I", 9) + b"pHYs" + struct.pack(">IIB", 2835, 2835, 1)
    old += struct.pack(">I", zlib.crc32(old[4:]) & 0xFFFFFFFF)
    again = fg.png_with_dpi(_png(extra=old))
    assert again.count(b"pHYs") == 1 and fg.png_info(again)["dpi"] == 300


def test_png_with_dpi_refuses_non_png():
    with pytest.raises(ValueError):
        fg.png_with_dpi(b"GIF89a")


def test_slide_sizes():
    assert tuple(x * fg.SCALE for x in fg.FULL) == (3300, 1875)
    assert tuple(x * fg.SCALE for x in fg.HALF) == (1650, 1875)


def test_stable_svg_replaces_only_the_plot_uid():
    svg = ('<defs id="defs-2c85e2"><clipPath id="clip2c85e2xyplot"/></defs><g id="topdefs-2c85e2"/>'
           '<g clip-path="url(#clip2c85e2xy)"/><g class="legend" clip-path="url(#legend2c85e2)"/><text>2c85e2</text>')
    out = fg.stable_svg(svg)
    assert "clip2c85e2" not in out and "defs-2c85e2" not in out and "#legend2c85e2" not in out
    assert 'id="defs-hlfig"' in out and "url(#cliphlfigxy)" in out
    assert "<text>2c85e2</text>" in out          # a matching string elsewhere is left alone
    assert fg.stable_svg("<svg/>") == "<svg/>"


# --- figure 1: the sweep points are labelled "n=5, unanimous" only while that is true ------------

def test_sweep_label_requires_unanimous_cells_with_one_n():
    cells = [{"scenario": "Gv6d100", "n": 5, "v6_wins": 5}, {"scenario": "Gv6d205", "n": 5, "v6_wins": 0}]
    assert fg.sweep_n_unanimous(cells) == 5
    with pytest.raises(ValueError, match="Gv6d205"):
        fg.sweep_n_unanimous([cells[0], {"scenario": "Gv6d205", "n": 5, "v6_wins": 3}])
    with pytest.raises(ValueError):
        fg.sweep_n_unanimous([cells[0], {"scenario": "Gv6d205", "n": 4, "v6_wins": 0}])


# --- figure 3: the core rows against summarise --------------------------------------------------

def _cell(n=20, win="v6", first="v6", setup=20.0, inter=None, dns=1.0, netlog=None, offs=None, aaaa_after=None):
    return {"n": n, "successes": n, "winning_family": {win: n}, "first_syn_family": {first: n},
            "tcp_setup_ms": {"median": setup},
            "inter_family": {"observed": n if inter is not None else 0,
                             "stats_over_observed_only": None if inter is None else {"median": inter}},
            "dns_ms": {"median": dns}, "netlog": netlog, "attempt_offsets_ms": offs or {},
            "dns_answer_by_type_ms": None if aaaa_after is None else {"runs with first SYN after the AAAA answer": aaaa_after}}


def _core_summary():
    """A summary shaped like summarise.summarise() output, with the frozen dataset's numbers."""
    nl = {"runs_with_backup_job": 20}
    offs = {"same-family (v6)": {"median": 250.625}}
    cells = {}
    for c, c0, s1, s6dns, s6set, s3 in (("curl", 20.697, 200.956, 302.07, 20.812, 171.171),
                                         ("chromium", 20.135, 301.067, 301.851, 21.317, 171.109)):
        ch = c == "chromium"
        cells[c] = {
            "C0": _cell(setup=c0, netlog={"runs_with_backup_job": 0} if ch else None),
            "S1": _cell(win="v4", inter=s1, setup=222.0, netlog=nl if ch else None, offs=offs if ch else None),
            "S2": _cell(win="v4", inter=s1, setup=222.0, netlog=nl if ch else None, offs=offs if ch else None),
            "S3": _cell(setup=s3), "S4": _cell(), "S5": _cell(),
            "S6": _cell(setup=s6set, dns=s6dns, aaaa_after=20),
        }
    return {"cells": cells}


def test_core_facts_reads_summarise_output():
    assert fg.core_facts(_core_summary()) == fg.CORE_FACTS


def test_core_facts_notices_a_changed_number():
    s = _core_summary()
    s["cells"]["curl"]["S3"]["first_syn_family"] = {"v6": 19, "v4": 1}
    s["cells"]["chromium"]["S6"]["dns_ms"]["median"] = 301.9
    got = fg.core_facts(s)
    assert got["S3"]["runs_with_v4_syn"] == 1 and got["S6"]["dns_ms"]["chromium"] == 301.9


def test_core_rows_are_built_from_core_facts():
    core = [r["claim"] for r in fg.claims(_data()) if r["section"] == "core"]
    text = " | ".join(core)
    k = fg.CORE_FACTS
    for v in (k["C0"]["setup_ms"]["curl"], k["C0"]["setup_ms"]["chromium"], k["S6"]["dns_ms"]["curl"],
              k["S6"]["dns_ms"]["chromium"], *k["S1S2"]["v4_syn_after_first_v6_ms_S1"].values()):
        assert f"{v:.3f}" in text
    assert "[CHECK]" not in text


FROZEN = sm.RUNS_DIR.is_dir() and any(sm.RUNS_DIR.glob("20261026T*_C0_*.json"))


@pytest.mark.skipif(not FROZEN, reason="frozen core run records are not on this machine (data/generated/ is not committed)")
def test_core_rows_match_summarise_on_the_frozen_dataset():
    """Figure 3's core numbers come from summarise.build() on docs/dataset.md, not from report.md."""
    sessions, runs, summary = sm.build()
    facts = fg.core_facts(summary)
    ids = {sid for _, _, sid in sessions}
    status = [r["outcome"]["http_status"] for p in sm.RUNS_DIR.glob("*.json")
              for r in [json.loads(p.read_text(encoding="utf-8"))] if r.get("environment", {}).get("session_id") in ids]
    facts["http_200"] = sum(s == 200 for s in status)
    assert len(status) == len(runs) == facts["runs"]
    assert facts == fg.CORE_FACTS
