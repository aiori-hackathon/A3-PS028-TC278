"""Slide versions of the comparison figures, simplified for the deck (one idea per chart).

    .venv/bin/python src/analysis/slide_figures.py          # render docs/figures/slides/ (SVG + 300 dpi PNG)

The report figures in docs/figures/ are not touched. These are separate, simpler drawings of the same
data, sized for the slide they sit on:
  - every value comes from docs/figures/figures_data.json, which figures.py --check verifies against the
    datasets; nothing is recomputed here;
  - one logical pixel is one point on the slide, so font sizes below are the sizes the audience sees;
  - styled like the project proposal's illustrations: thin lines, direct labels instead of legends, light
    dotted gridlines, and few annotations.

  slide8_setup_vs_oracle   TCP setup and oracle setup against IPv6 RTT, both clients, one panel
  slide9_latency_budget    IPv6 win fraction (top) and TCP setup (bottom) against IPv6 RTT, one column
                           per client: sweep points, flip bracket, T line; jitter cells as small diamonds
  slide10_he_linearity     curl T against the configured timeout (top) and the residual T − reference
                           (bottom): all eight residuals as dots inside two labelled bands, as measured
"""

from __future__ import annotations

import argparse
import inspect
import base64
import json
import sys
import urllib.parse
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.figures import CLIENT, DATA_FILE, OUT, _JS, f2, png_with_dpi, residual_groups, stable_svg  # noqa: E402

SLIDES_OUT = OUT / "slides"
SPLIT_MS = inspect.signature(residual_groups).parameters["split_ms"].default   # the report's own split
PT_PER_IN, DPI = 72, 300
SCALE = DPI / PT_PER_IN            # logical px are points; the PNG is 300 dpi at its size on the slide
FONT = "Carlito, Calibri, sans-serif"   # the deck's typeface (Carlito is Calibri's metric twin)
INK, MUTED, GRID = "#1B1F2A", "#5A6275", "#D5DAE8"
BAND = "rgba(18,38,200,0.07)"      # the proposal's blue, very light
TICK, AXIS, LABEL, PANEL = 14, 15, 14, 16
LINE, MARK = 2, 8

# (width, height) in inches as placed on the slide; build_deck.js uses the same sizes
SIZES = {"slide8_setup_vs_oracle": (6.4, 5.3), "slide9_latency_budget": (9.4, 5.3),
         "slide10_he_linearity": (9.4, 5.3)}


def _go():
    import plotly.graph_objects as go
    return go


def _px(name: str) -> tuple[int, int]:
    w, h = SIZES[name]
    return round(w * PT_PER_IN), round(h * PT_PER_IN)


def _layout(name: str, **kw) -> dict:
    w, h = _px(name)
    lay = {"width": w, "height": h, "paper_bgcolor": "rgba(0,0,0,0)", "plot_bgcolor": "rgba(0,0,0,0)", "showlegend": False,
           "font": {"family": FONT, "size": TICK, "color": INK}, "margin": {"l": 58, "r": 12, "t": 12, "b": 46}}
    lay.update(kw)
    return lay


def _axis(title: str = "", **kw) -> dict:
    a = {"title": {"text": title, "font": {"size": AXIS, "color": INK}, "standoff": 6},
         "tickfont": {"size": TICK, "color": MUTED}, "showgrid": False, "zeroline": False, "showline": True,
         "linecolor": MUTED, "linewidth": 1, "ticks": "outside", "ticklen": 4, "tickcolor": MUTED}
    a.update(kw)
    return a


def _ygrid(**kw) -> dict:
    return _axis(showgrid=True, gridcolor=GRID, gridwidth=1, griddash="dot", **kw)


def _label(fig, x, y, text, xref="x", yref="y", **kw):
    style = {"showarrow": False, "font": {"size": LABEL, "color": INK}}
    style.update(kw)
    fig.add_annotation(x=x, y=y, xref=xref, yref=yref, text=text, **style)


# --- slide 8 --------------------------------------------------------------------------------------

def fig_setup_oracle(d: dict):
    """One idea: where IPv4 wins, setup stays flat while the oracle drops, and the gap is the cost of racing."""
    go = _go()
    fig = go.Figure()
    for c in ("curl", "chromium"):
        so = [k for k in d["setup_oracle"] if k["client"] == c]
        col, sym = CLIENT[c]["colour"], CLIENT[c]["symbol"]
        xs = [k["rtt_ms"] for k in so]
        fig.add_trace(go.Scatter(x=xs, y=[k["oracle_setup_median_ms"] for k in so], mode="lines",
                                 line={"color": col, "width": LINE, "dash": "dash"}))
        fig.add_trace(go.Scatter(x=xs, y=[k["setup_median_ms"] for k in so], mode="lines+markers",
                                 line={"color": col, "width": LINE},
                                 marker={"size": MARK, "color": col, "symbol": sym, "line": {"color": "#ffffff", "width": 1}}))
        last = so[-1]
        _label(fig, last["rtt_ms"], last["setup_median_ms"], f"<b>{CLIENT[c]['name']}</b>", xanchor="right",
               yanchor="bottom", yshift=8)
    _label(fig, 106, 6, "oracle (dashed):<br>the winner's<br>ping RTT", xanchor="left", yanchor="bottom",
           align="left", font={"size": LABEL, "color": MUTED})
    # The gap at one real cell per client (curl at its second-last cell, Chromium at its last), drawn from that
    # cell's own setup median down to its own oracle median: an arrow with no number (the slide gives the numbers).
    gap = {"curl": [k for k in d["setup_oracle"] if k["client"] == "curl"][-2],
           "chromium": [k for k in d["setup_oracle"] if k["client"] == "chromium"][-1]}
    for k in gap.values():
        fig.add_annotation(x=k["rtt_ms"], y=k["oracle_setup_median_ms"], ax=k["rtt_ms"], ay=k["setup_median_ms"],
                           xref="x", yref="y", axref="x", ayref="y", showarrow=True, arrowhead=2, arrowside="end+start",
                           standoff=5, startstandoff=7, arrowwidth=1.5, arrowcolor=MUTED, text="")
    c = gap["curl"]
    _label(fig, c["rtt_ms"], (c["setup_median_ms"] + c["oracle_setup_median_ms"]) / 2, "cost of<br>racing",
           xanchor="right", xshift=-8, font={"size": LABEL, "color": MUTED}, align="right")
    fig.update_layout(**_layout("slide8_setup_vs_oracle"))
    fig.update_yaxes(_ygrid(title="Median per cell (ms)", range=[0, 360], tickvals=[0, 100, 200, 300]))
    fig.update_xaxes(_axis("IPv6 RTT (ms, lab ping)", range=[100, 445], tickvals=[100, 200, 300, 400]))
    return fig


# --- slide 9 --------------------------------------------------------------------------------------

def fig_latency_budget(d: dict):
    """Both rows, simplified: sweep points, flip bracket, one T line per client, small unlabelled jitter diamonds."""
    from plotly.subplots import make_subplots
    go = _go()
    clients = ("curl", "chromium")
    lat = {r["client"]: r for r in d["latency_sweep"]}
    fig = make_subplots(rows=2, cols=2, shared_xaxes=True, vertical_spacing=0.09, horizontal_spacing=0.09,
                        row_heights=[0.5, 0.5],
                        subplot_titles=[f"<b>{CLIENT[c]['name']}</b> " + ("●" if c == "curl" else "▲") for c in clients])
    for a in fig.layout.annotations:
        a.font = {"size": PANEL, "color": INK}
    for col, c in enumerate(clients, 1):
        colour, sym = CLIENT[c]["colour"], CLIENT[c]["symbol"]
        row = lat[c]
        br = row["flip_bracket"]
        for r_ in (1, 2):
            fig.add_vrect(x0=br["above_ms"], x1=br["below_ms"], fillcolor="rgba(27,31,42,0.16)", line_width=0,
                          row=r_, col=col, layer="below", exclude_empty_subplots=False)
            fig.add_vline(x=row["T_ms"], line={"color": INK, "width": 1.5}, row=r_, col=col,
                          exclude_empty_subplots=False)
        ref = "" if col == 1 else "2"
        _label(fig, row["T_ms"], 1.32, "T", xref=f"x{ref}", yref=f"y{ref}", xanchor="left", xshift=4,
               font={"size": LABEL, "color": INK})
        cells = row["cells"]
        fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in cells], y=[k["v6_wins"] / k["n"] for k in cells], mode="markers",
                                 marker={"size": MARK, "color": colour, "symbol": sym,
                                         "line": {"color": "#ffffff", "width": 1}}), row=1, col=col)
        jit = [j for j in d["jitter"] if j["client"] == c]
        fig.add_trace(go.Scatter(x=[j["mu_ms"] for j in jit], y=[j["observed"]["fraction"] for j in jit], mode="markers",
                                 marker={"size": MARK - 1, "color": "#ffffff", "symbol": "diamond",
                                         "line": {"color": colour, "width": 1.5}}), row=1, col=col)
        so = [k for k in d["setup_oracle"] if k["client"] == c]
        fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in so], y=[k["oracle_setup_median_ms"] for k in so], mode="lines",
                                 line={"color": colour, "width": LINE, "dash": "dash"}), row=2, col=col)
        fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in so], y=[k["setup_median_ms"] for k in so], mode="lines+markers",
                                 line={"color": colour, "width": LINE},
                                 marker={"size": MARK - 2, "color": colour, "symbol": sym,
                                         "line": {"color": "#ffffff", "width": 1}}), row=2, col=col)
        if col == 1:   # name the dashed line once, where it runs flat (IPv4 winning)
            _label(fig, so[-1]["rtt_ms"], so[-1]["oracle_setup_median_ms"], "oracle (dashed)", xref="x3", yref="y3",
                   xanchor="right", yanchor="bottom", yshift=4, font={"size": LABEL - 1, "color": MUTED})
    fig.update_layout(**_layout("slide9_latency_budget", margin={"l": 64, "r": 12, "t": 30, "b": 46}))
    for col in (1, 2):
        fig.update_yaxes(_ygrid(title="IPv6 win fraction" if col == 1 else "", range=[-0.08, 1.45], tickvals=[0, 0.5, 1]),
                         row=1, col=col)
        fig.update_yaxes(_ygrid(title="Median per cell (ms)" if col == 1 else "", range=[0, 420], tickvals=[0, 200, 400]),
                         row=2, col=col)
        fig.update_xaxes(_axis(range=[100, 440], tickvals=[100, 200, 300, 400], showticklabels=False), row=1, col=col)
        fig.update_xaxes(_axis(range=[100, 440], tickvals=[100, 200, 300, 400]), row=2, col=col)
    _label(fig, 0.5, 0, "IPv6 RTT (ms, lab ping)", xref="paper", yref="paper", yanchor="top", yshift=-26,
           font={"size": AXIS, "color": INK})
    return fig


# --- slide 10 -------------------------------------------------------------------------------------

def fig_he_linearity(d: dict):
    """T tracks timeout + IPv4 handshake; the residuals stay visible as eight dots, uneven as measured."""
    from plotly.subplots import make_subplots
    go = _go()
    rows = d["he_sweep"]
    var = sorted((r for r in rows if r["timeout_ms"] is not None), key=lambda r: r["timeout_ms"])
    plain = next(r for r in rows if r["timeout_ms"] is None)
    res = d["residuals"]
    blue = CLIENT["curl"]["colour"]
    xs = [r["timeout_ms"] for r in var]
    fig = make_subplots(rows=2, cols=1, shared_xaxes=True, vertical_spacing=0.1, row_heights=[0.6, 0.4])
    fig.add_trace(go.Scatter(x=xs, y=[r["predicted_T_ms"] for r in var], mode="lines",
                             line={"color": MUTED, "width": LINE, "dash": "dot"}), row=1, col=1)
    fig.add_trace(go.Scatter(x=xs, y=[r["S1"]["T_ms"] for r in var], mode="markers",
                             marker={"size": MARK + 1, "color": blue, "line": {"color": "#ffffff", "width": 1}}), row=1, col=1)
    fig.add_trace(go.Scatter(x=[200], y=[plain["S1"]["T_ms"]], mode="markers",
                             marker={"size": MARK + 8, "color": INK, "symbol": "star-open", "line": {"width": 1.5}}),
                  row=1, col=1)
    _label(fig, 40, 540, "dotted line: timeout + IPv4 handshake (reference)", xanchor="left", yanchor="top",
           font={"size": LABEL, "color": MUTED})
    _label(fig, 200, plain["S1"]["T_ms"], f"plain curl, no flag: {f2(plain['S1']['T_ms'])} ms<br>(placed at the documented default, 200)",
           xanchor="left", align="left",
           xshift=14, yshift=-14, yanchor="top")
    rv = [r["T_minus_predicted_ms"] for r in var]
    # the two groups exactly as residual_groups() in figures.py forms them: timeouts below 300 ms, and from 300 ms
    lo = [t for t in xs if t < SPLIT_MS]
    hi = [t for t in xs if t >= SPLIT_MS]
    assert [min(rv[:len(lo)]), max(rv[:len(lo)])] == res["below"] and [min(rv[len(lo):]), max(rv[len(lo):])] == res["from"]
    groups = ((lo[0] - 15, lo[-1] + 18, res["below"], f"{lo[0]}–{lo[-1]} ms"),
              (hi[0] - 18, hi[-1] + 15, res["from"],
               f"{hi[0]}–{hi[-1]} ms" + ("" if res["upper_monotonic"] else ", not monotonic")))
    for (x0, x1, rng, lab) in groups:
        fig.add_shape(type="rect", x0=x0, x1=x1, y0=rng[0] - 0.15, y1=rng[1] + 0.15, xref="x2", yref="y2",
                      fillcolor=BAND, line={"color": MUTED, "width": 1}, layer="below")
        _label(fig, (x0 + x1) / 2, rng[1] + 0.15, f"{lab}: +{f2(rng[0])} to +{f2(rng[1])} ms", xref="x2", yref="y2",
               yanchor="bottom", font={"size": LABEL, "color": INK})
    fig.add_trace(go.Scatter(x=xs, y=rv, mode="markers",
                             marker={"size": MARK + 1, "color": blue, "line": {"color": "#ffffff", "width": 1}}),
                  row=2, col=1)
    fig.update_layout(**_layout("slide10_he_linearity", margin={"l": 64, "r": 12, "t": 12, "b": 46}))
    fig.update_yaxes(_ygrid(title="T (ms)", range=[0, 560], tickvals=[0, 200, 400]), row=1, col=1)
    fig.update_yaxes(_ygrid(title="T − reference (ms)", range=[0, 2.7], tickvals=[0, 1, 2]), row=2, col=1)
    tv = [50, 100, 200, 300, 400, 500]
    fig.update_xaxes(_axis(range=[25, 525], tickvals=tv), row=1, col=1)
    fig.update_xaxes(_axis("--happy-eyeballs-timeout-ms (configured)", range=[25, 525], tickvals=tv), row=2, col=1)
    return fig


def slide_figures(d: dict) -> dict:
    return {"slide8_setup_vs_oracle": fig_setup_oracle(d), "slide9_latency_budget": fig_latency_budget(d),
            "slide10_he_linearity": fig_he_linearity(d)}


def render(figs: dict, out: Path = SLIDES_OUT) -> list[Path]:
    from playwright.sync_api import sync_playwright
    from plotly.offline import get_plotlyjs
    from runner.child_env import child_env
    out.mkdir(parents=True, exist_ok=True)
    written = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, env=child_env())
        page = browser.new_page()
        page.set_content(f"<!doctype html><meta charset=utf-8><script>{get_plotlyjs()}</script><body></body>")
        for name, fig in figs.items():
            spec = json.loads(fig.to_json())
            for i, tr in enumerate(spec["data"]):   # fixed trace ids, so re-renders are byte-identical
                tr["uid"] = f"t{i:03d}"
            w, h = _px(name)
            svg_url, png_url = page.evaluate(_JS, [spec, w, h, SCALE])
            svg = stable_svg(urllib.parse.unquote(svg_url.split(",", 1)[1]))
            (out / f"{name}.svg").write_text(svg, encoding="utf-8")
            (out / f"{name}.png").write_bytes(png_with_dpi(base64.b64decode(png_url.split(",", 1)[1]), DPI))
            written += [out / f"{name}.svg", out / f"{name}.png"]
        browser.close()
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args(argv)
    d = json.loads((OUT / DATA_FILE).read_text(encoding="utf-8"))
    for p in render(slide_figures(d)):
        print(f"wrote {p.relative_to(OUT.parents[1])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
