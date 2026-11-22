"""Comparison figures for the report and the deck (P9): presentation of results already established.

    .venv/bin/python src/analysis/figures.py             # render docs/figures/ (SVG + 300 dpi PNG) and figures_data.json
    .venv/bin/python src/analysis/figures.py --check     # recompute the figure data and compare with figures_data.json
    .venv/bin/python src/analysis/figures.py --data-only # write figures_data.json only (no browser needed)

Every value comes from the existing datasets through the existing analysis code: crossover.py
(latency sweep, he sweep), jitter_model.py (jitter cells and the model), summarise.build (TCP setup
and the oracle baseline) and the frozen core numbers as docs/report.md states them. Nothing here
computes a new metric or makes a new claim; the table text restates the findings docs.

Rendering uses no extra dependency: Plotly figures are drawn in the Playwright Chromium that the
lab already installs (started with child_env), and Plotly.toImage writes the SVG and the PNG.
PNGs carry a 300 dpi pHYs chunk. Sizes: full slide 3300 x 1875 px, half slide 1650 x 1875 px
(logical 1100 x 625 and 550 x 625 at scale 3); the SVGs have the logical size.

Evidence tags are the dashboard's four, each with its own mark style in every legend:
  Packet-level (pcap)        filled markers, solid lines, shaded bands
  Derived (pcap − lab RTT)   dashed lines (the oracle baseline only)
  Interpretation             dotted lines (the jitter model; the timeout + handshake reference)
  Client log                 table rows only (Chromium NetLog; HTTP status)
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import statistics
import struct
import sys
import urllib.parse
import zlib
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "docs" / "figures"
DATA_FILE = "figures_data.json"

# The dashboard's four evidence tags, verbatim (a test checks they stay identical to dashboard.TAG_LABEL).
TAG = {"packet": "Packet-level (pcap)", "client": "Client log", "interp": "Interpretation",
       "derived": "Derived (pcap − lab RTT)"}

# Light theme only (projectors wash out dark themes). Client colours are the dashboard's; identity is
# never colour alone: every panel is titled with its client and each client also has its own marker.
INK, INK2, MUTED, GRID, BG = "#0b0b0b", "#52514e", "#898781", "#d9d8d0", "#ffffff"
CLIENT = {"curl": {"name": "curl", "colour": "#2a78d6", "symbol": "circle"},
          "chromium": {"name": "Chromium", "colour": "#eb6834", "symbol": "triangle-up"}}
BAND = "rgba(11,11,11,0.10)"
FONT = "Liberation Sans, Arial, Helvetica, sans-serif"
FULL, HALF, REPORT, SCALE, DPI = (1100, 625), (550, 625), (1100, 1300), 3, 300
F_TITLE, F_AXIS, F_TICK, F_LEGEND, F_NOTE = 30, 24, 22, 20, 20
LINE, MARK = 4, 14   # no hairlines: data lines 4 px logical (12 px in the PNG)


# --- data (pure where possible; collect() reads the datasets) ----------------------------------

def f2(x: float) -> str:
    """Two decimals, half up from the stored 3-decimal value (222.135 -> 222.14, as the docs print it)."""
    return str(Decimal(str(x)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _median(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 3) if xs else None


def setup_oracle_cells(runs, rtt_by_cell: dict) -> list[dict]:
    """Per (client, scenario): median packet-level TCP setup and median derived oracle setup."""
    by = {}
    for r in runs:
        by.setdefault((r.client, r.scenario), []).append(r)
    out = []
    for (client, sid), rs in sorted(by.items()):
        out.append({"client": client, "scenario": sid, "rtt_ms": rtt_by_cell[(client, sid)], "n": len(rs),
                    "setup_median_ms": _median(r.setup_ms for r in rs),
                    "oracle_setup_median_ms": _median(r.oracle_setup_ms for r in rs if r.oracle_status == "computed")})
    return sorted(out, key=lambda c: (c["client"], c["rtt_ms"]))


def residual_groups(he_rows: list[dict], split_ms: int = 300) -> dict:
    """T − (timeout + IPv4 handshake) per variant, and the range below and from split_ms."""
    res = {r["client"]: r["T_minus_predicted_ms"] for r in he_rows if r["timeout_ms"] is not None}
    lo = [v for r in he_rows if r["timeout_ms"] is not None and r["timeout_ms"] < split_ms for v in [res[r["client"]]]]
    hi = [v for r in he_rows if r["timeout_ms"] is not None and r["timeout_ms"] >= split_ms for v in [res[r["client"]]]]
    upper = [(r["timeout_ms"], res[r["client"]]) for r in he_rows if r["timeout_ms"] and r["timeout_ms"] >= split_ms]
    monotonic = all(b[1] >= a[1] for a, b in zip(upper, upper[1:]))
    return {"by_client": res, "below": [min(lo), max(lo)], "from": [min(hi), max(hi)], "upper_monotonic": monotonic}


def spread(values: list[float]) -> float:
    return round(max(values) - min(values), 2)


def _env(recs: list[dict], key: str) -> list[str]:
    return sorted({r["environment"][key] for r in recs})


def collect() -> dict:
    from analysis import crossover as cx
    from analysis import jitter_model as jm
    from analysis.scenario_config import load_config
    from analysis.summarise import build, load_dataset
    from analysis.syn_retransmit import load_records

    def records(name):
        m = load_dataset(name)
        return m, load_records({sid for _, _, sid in m.sessions})

    lat_m, lat_rec = records("latency-sweep")
    lat = cx.latency_sweep(lat_rec)
    rtt = {(row["client"], c["scenario"]): c["rtt_ms"] for row in lat for c in row["cells"]}
    _, lat_runs, _ = build(manifest=lat_m)
    jit_m, jit_rec = records("jitter-loss")
    jit = [r for r in jm.analyse(jit_rec, load_config()) if r["scenario"].startswith("Gv6j")]
    he_m, he_rec = records("he-sweep")
    he = cx.he_sweep(he_rec)
    vc_m, vc_rec = records("variant-control")

    def t_runs(recs):
        return [t for t in (cx.run_times(r)["t_v4_synack"] for r in recs) if t is not None]

    lat_curl = [r for (c, s), rs in lat_rec.items() if c == "curl" for r in rs]
    twins = jit_rec[("curl", "Gv6d200")] + jit_rec[("curl", "Gv6d280")]
    campaigns = [
        ("variant-control", "S1<br>IPv6 blackhole", vc_rec[("curl", "S1")]),
        ("jitter-loss", "IPv6 delay<br>+200, +280 ms", twins),
        ("latency-sweep", "IPv6 delay<br>+190 to +400 ms", lat_curl),
        ("he-sweep", "S1<br>IPv6 blackhole", he_rec[("curl", "S1")]),
    ]
    repro = []
    for name, cond, recs in campaigns:
        ts = t_runs(recs)
        stamps = sorted(r["environment"]["session_id"] for r in recs)
        repro.append({"campaign": name, "condition": cond, "n": len(ts), "T_ms": _median(ts), "runs_ms": sorted(ts),
                      "code": _env(recs, "git_commit"), "kernel": _env(recs, "kernel"),
                      "first_session": stamps[0], "last_session": stamps[-1]})
    return {"latency_sweep": lat, "setup_oracle": setup_oracle_cells(lat_runs, rtt),
            "jitter": [{k: r[k] for k in ("client", "scenario", "mu_ms", "sigma_ms", "T_ms", "predicted",
                                          "predicted_inside_ci")} | {"observed": r["observed"]} for r in jit],
            "he_sweep": he, "residuals": residual_groups(he), "T_reproducibility": repro,
            "T_spread_ms": spread([r["T_ms"] for r in repro]),
            "datasets": {m.path.stem: len(m.sessions) for m in (lat_m, jit_m, he_m, vc_m)}}


# --- the claims table (restates docs/report.md and the findings docs; nothing new) --------------

# The frozen core dataset's numbers that figure 3 quotes, as summarise reports them. The table is
# built from this; src/tests/test_figures.py recomputes it with core_facts() from summarise.build()
# on the frozen dataset, so the table cannot drift from the data even if report.md is edited.
CORE_FACTS = {
    "runs": 280,
    "successes": 280,
    "http_200": 280,                     # from the run records' outcome.http_status (client log)
    "C0": {"v6_won": {"curl": "20/20", "chromium": "20/20"}, "setup_ms": {"curl": 20.697, "chromium": 20.135}},
    "S1S2": {"v4_won": "80/80", "v4_syn_after_first_v6_ms_S1": {"curl": 200.956, "chromium": 301.067}},
    "netlog_backup_job": {"S1": "20/20", "S2": "20/20"},
    "chromium_second_v6_syn_ms_about": 250,
    "S3": {"v6_won": "40/40", "setup_ms_about": 171, "runs_with_v4_syn": 0},
    "S4S5": {"v6_won": "80/80", "runs_with_v4_syn": 0},
    "S6": {"first_syn_after_aaaa": {"curl": "20/20", "chromium": "20/20"},
           "dns_ms": {"curl": 302.070, "chromium": 301.851}, "setup_ms": {"curl": 20.812, "chromium": 21.317}},
}


def core_facts(summary: dict) -> dict:
    """CORE_FACTS recomputed from summarise output (summary["cells"]); http_200 is left to the caller."""
    cells = summary["cells"]
    C = ("curl", "chromium")

    def frac(k, n):
        return f"{k}/{n}"

    def won(fam, scen):
        return (sum(cells[c][s]["winning_family"].get(fam, 0) for c in C for s in scen),
                sum(cells[c][s]["n"] for c in C for s in scen))

    def v4_syn_runs(scen):   # a first SYN over IPv4, or a second-family (IPv4) SYN after an IPv6 first
        return sum(cells[c][s]["first_syn_family"].get("v4", 0) + cells[c][s]["inter_family"]["observed"]
                   for c in C for s in scen)

    def med(c, s, key):
        return cells[c][s][key]["median"]

    s6 = {c: cells[c]["S6"] for c in C}
    offs = {round(cells["chromium"][s]["attempt_offsets_ms"]["same-family (v6)"]["median"], -1) for s in ("S1", "S2")}
    s3 = {round(med(c, "S3", "tcp_setup_ms")) for c in C}
    return {
        "runs": sum(x["n"] for by in cells.values() for x in by.values()),
        "successes": sum(x["successes"] for by in cells.values() for x in by.values()),
        "http_200": CORE_FACTS["http_200"],
        "C0": {"v6_won": {c: frac(cells[c]["C0"]["winning_family"].get("v6", 0), cells[c]["C0"]["n"]) for c in C},
               "setup_ms": {c: med(c, "C0", "tcp_setup_ms") for c in C}},
        "S1S2": {"v4_won": frac(*won("v4", ("S1", "S2"))),
                 "v4_syn_after_first_v6_ms_S1": {c: cells[c]["S1"]["inter_family"]["stats_over_observed_only"]["median"]
                                                 for c in C}},
        "netlog_backup_job": {s: frac(cells["chromium"][s]["netlog"]["runs_with_backup_job"], cells["chromium"][s]["n"])
                              for s in ("S1", "S2")},
        "chromium_second_v6_syn_ms_about": int(offs.pop()) if len(offs) == 1 else sorted(offs),
        "S3": {"v6_won": frac(*won("v6", ("S3",))), "setup_ms_about": s3.pop() if len(s3) == 1 else sorted(s3),
               "runs_with_v4_syn": v4_syn_runs(("S3",))},
        "S4S5": {"v6_won": frac(*won("v6", ("S4", "S5"))), "runs_with_v4_syn": v4_syn_runs(("S4", "S5"))},
        "S6": {"first_syn_after_aaaa": {c: frac(s6[c]["dns_answer_by_type_ms"]["runs with first SYN after the AAAA answer"],
                                                s6[c]["n"]) for c in C},
               "dns_ms": {c: s6[c]["dns_ms"]["median"] for c in C},
               "setup_ms": {c: s6[c]["tcp_setup_ms"]["median"] for c in C}},
    }


def sweep_n_unanimous(cells: list[dict]) -> int:
    """The latency sweep's runs per cell, checked to be the same everywhere and every cell unanimous.
    Figure 1 labels the sweep points "n=5, unanimous" instead of drawing intervals; this refuses to
    render that label if it stops being true."""
    ns = {k["n"] for k in cells}
    split = [k["scenario"] for k in cells if k["v6_wins"] not in (0, k["n"])]
    if len(ns) != 1 or split:
        raise ValueError(f"latency sweep cells are not all unanimous with one n: n={sorted(ns)}, mixed={split}")
    return ns.pop()


def claims(d: dict) -> list[dict]:
    """One row per claim: section, claim, dataset, evidence tag."""
    lat = {r["client"]: r for r in d["latency_sweep"]}
    b = {c: lat[c]["flip_bracket"] for c in lat}
    res = d["residuals"]
    he = {r["client"]: r["S1"] for r in d["he_sweep"]}
    rep = {r["campaign"]: r["T_ms"] for r in d["T_reproducibility"]}
    k = CORE_FACTS
    core = f"core ({k['runs']} runs)"
    c0, s12, s3, s45, s6, nl = k["C0"], k["S1S2"], k["S3"], k["S4S5"], k["S6"], k["netlog_backup_job"]

    def same(x):   # "20/20" when both clients agree
        assert x["curl"] == x["chromium"], x
        return x["curl"]

    def ms(v):
        return f"{v:.3f}"
    n45 = s45["v6_won"].split("/")[1]
    rows = [
        ("core", f"C0 baseline: IPv6 won {same(c0['v6_won'])} for each client; TCP setup {ms(c0['setup_ms']['curl'])} ms (curl), "
                 f"{ms(c0['setup_ms']['chromium'])} ms (Chromium)", core, "packet"),
        ("core", f"Every run succeeded with HTTP 200 ({k['http_200']}/{k['runs']})", core, "client"),
        ("core", f"S1/S2 IPv6 broken: IPv4 won {s12['v4_won']}; curl's IPv4 SYN {ms(s12['v4_syn_after_first_v6_ms_S1']['curl'])} ms "
                 f"after its first IPv6 SYN, Chromium's {ms(s12['v4_syn_after_first_v6_ms_S1']['chromium'])} ms (S1)", core, "packet"),
        ("core", f"Chromium NetLog marks its second IPv6 attempt (about {k['chromium_second_v6_syn_ms_about']} ms, new source port) "
                 f"as backup_job in {nl['S1']} runs in S1 and {nl['S2']} in S2", core, "client"),
        ("core", f"S3 IPv6 +150 ms: IPv6 won {s3['v6_won']}, setup about {s3['setup_ms_about']} ms, "
                 f"no IPv4 SYN" + ("" if s3["runs_with_v4_syn"] == 0 else " [CHECK]"), core, "packet"),
        ("core", f"S4/S5 IPv4 impaired: IPv6 won {s45['v6_won']}; no IPv4 SYN in any of the {n45} runs"
                 + ("" if s45["runs_with_v4_syn"] == 0 else " [CHECK]"), core, "packet"),
        ("core", f"S6 AAAA delayed 300 ms: first SYN after the AAAA answer in {same(s6['first_syn_after_aaaa'])} per client; "
                 f"DNS time {ms(s6['dns_ms']['curl'])} / {ms(s6['dns_ms']['chromium'])} ms, "
                 f"TCP setup {ms(s6['setup_ms']['curl'])} / {ms(s6['setup_ms']['chromium'])} ms", core, "packet"),
        ("ext", f"Outcome flip located to 5 ms of IPv6 RTT: curl {b['curl']['above_ms']:g}–{b['curl']['below_ms']:g}, "
                f"Chromium {b['chromium']['above_ms']:g}–{b['chromium']['below_ms']:g} ms; "
                f"latency-sweep T {f2(lat['curl']['T_ms'])} / {f2(lat['chromium']['T_ms'])} ms inside both",
         "latency-sweep (180 runs)", "packet"),
        ("ext", "Jitter model Φ((T − μ)/σ) inside the Wilson interval in all four jitter cells: consistent with the model, not a close test",
         "jitter-loss (558 runs)", "interp"),
        ("ext", "Gv6c30: SYN retransmissions about 1 s apart up to the 5th SYN, not doubling", "jitter-loss (558 runs)", "packet"),
        ("ext", f"curl T follows timeout + IPv4 handshake from 50 to 500 ms, late by +{f2(res['below'][0])} to +{f2(res['below'][1])} ms "
                f"up to he250 and +{f2(res['from'][0])} to +{f2(res['from'][1])} ms from he300 (not monotonic); no cause claimed",
         "he-sweep (270 runs)", "packet"),
        ("ext", f"Control: curl@he200 matches plain curl (IPv4 SYN {he['curl@he200']['v4_first_syn_ms']:.3f} vs "
                f"{he['curl']['v4_first_syn_ms']:.3f} ms)", "he-sweep (270 runs)", "packet"),
        ("ext", "Plain curl T: " + ", ".join(f"{c} {f2(rep[c])}" for c in ('variant-control', 'jitter-loss', 'latency-sweep', 'he-sweep'))
                + f" ms; within {f2(d['T_spread_ms'])} ms; one host and one kernel", "4 extension datasets", "packet"),
        ("ext", "BOUNDARY CASE, NOT A FINDING: S3 curl@he150, IPv6 won 10/10 by about 0.4 ms (n = 10)", "he-sweep (270 runs)", "packet"),
    ]
    return [{"section": s, "claim": c, "dataset": ds, "tag": t} for s, c, ds, t in rows]


# --- figures ---------------------------------------------------------------------------------

def _go():
    import plotly.graph_objects as go
    return go


def _base_layout(size, title: str, **kw) -> dict:
    w, h = size
    lay = {"width": w, "height": h, "paper_bgcolor": BG, "plot_bgcolor": BG,
           "font": {"family": FONT, "size": F_TICK, "color": INK},
           "title": {"text": title, "font": {"size": F_TITLE, "color": INK}, "x": 0.01, "xanchor": "left", "y": 0.985},
           "showlegend": True,
           "legend": {"font": {"size": F_LEGEND, "color": INK}, "bgcolor": "rgba(255,255,255,0.92)",
                      "bordercolor": INK2, "borderwidth": 2, "grouptitlefont": {"size": F_LEGEND, "color": INK},
                      "tracegroupgap": 6, "itemwidth": 40}}
    lay.update(kw)
    return lay


def _axis(title: str, **kw) -> dict:
    a = {"title": {"text": title, "font": {"size": F_AXIS, "color": INK}}, "tickfont": {"size": F_TICK, "color": INK},
         "showgrid": True, "gridcolor": GRID, "gridwidth": 2, "zeroline": False, "showline": True,
         "linecolor": INK2, "linewidth": 2, "ticks": "outside", "tickwidth": 2, "tickcolor": INK2, "ticklen": 8}
    a.update(kw)
    return a


def _legend_key(go, tag: str, label: str, **style):
    """A legend-only trace (no data) in ink, so the legend shows the mark style, not a client colour."""
    return go.Scatter(x=[None], y=[None], name=label, legendgroup=tag, legendgrouptitle={"text": f"<b>{TAG[tag]}</b>"},
                      showlegend=True, hoverinfo="skip", **style)


def _ref(row: int, col: int, ncol: int) -> str:
    i = (row - 1) * ncol + col
    return "" if i == 1 else str(i)


def fig_latency_budget(d: dict, clients=("curl", "chromium"), size=FULL, with_setup: bool = True) -> dict:
    """Outcome against IPv6 RTT (top) and, with_setup, TCP setup against the oracle (bottom); one column per client."""
    from plotly.subplots import make_subplots
    go = _go()
    from analysis import jitter_model as jm
    ncol, nrow = len(clients), 2 if with_setup else 1
    half = size == HALF
    lat = {r["client"]: r for r in d["latency_sweep"]}
    n_sweep = {c: sweep_n_unanimous(lat[c]["cells"]) for c in clients}
    jT = {j["client"]: j["T_ms"] for j in d["jitter"]}
    fig = make_subplots(rows=nrow, cols=ncol, shared_xaxes=True, vertical_spacing=0.07, horizontal_spacing=0.08,
                        row_heights=[0.52, 0.48] if with_setup else None,
                        subplot_titles=([f"<b>{CLIENT[c]['name']}</b>" for c in clients] + [""] * (ncol * (nrow - 1)))
                        if ncol > 1 else None)
    x_lo, x_hi = 100, 440
    for col, c in enumerate(clients, 1):
        col_c, sym = CLIENT[c]["colour"], CLIENT[c]["symbol"]
        row = lat[c]
        br = row["flip_bracket"]
        # flip bracket band and T line (packet-level), both rows
        ax = _ref(1, col, ncol)
        for r_ in range(1, nrow + 1):
            fig.add_vrect(x0=br["above_ms"], x1=br["below_ms"], fillcolor="rgba(11,11,11,0.28)", line_width=0, row=r_, col=col,
                          layer="below", exclude_empty_subplots=False)
            fig.add_vline(x=row["T_ms"], line={"color": INK, "width": 3}, row=r_, col=col, exclude_empty_subplots=False)
        right = c == "curl"
        fig.add_annotation(x=row["T_ms"], y=1.05, yanchor="bottom", xref=f"x{ax}", yref=f"y{ax}",
                           text=f"flip {br['above_ms']:g}–{br['below_ms']:g} ms<br>T = {f2(row['T_ms'])} ms<br>(latency-sweep)",
                           showarrow=False, xanchor="left" if right else "right", xshift=8 if right else -8,
                           align="left" if right else "right", font={"size": F_NOTE, "color": INK})
        cells = row["cells"]
        # the sweep points carry no interval: say why, in a corner no other mark uses
        if c == "curl":   # top right is empty for curl; bottom left for Chromium
            fig.add_annotation(x=x_hi, y=0.95, xref=f"x{ax}", yref=f"y{ax}", text=f"sweep cells:<br>n={n_sweep[c]}, unanimous",
                               showarrow=False, xanchor="right", yanchor="top", xshift=-6, align="right",
                               font={"size": F_NOTE - 2, "color": INK})
        else:
            fig.add_annotation(x=x_lo, y=0.04, xref=f"x{ax}", yref=f"y{ax}", text=f"sweep cells:{'<br>' if ncol > 1 else ' '}n={n_sweep[c]}, unanimous",
                               showarrow=False, xanchor="left", yanchor="bottom", xshift=6, align="left",
                               font={"size": F_NOTE - 2, "color": INK})
        fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in cells], y=[k["v6_wins"] / k["n"] for k in cells], mode="markers",
                                 marker={"size": MARK, "color": col_c, "symbol": sym, "line": {"color": INK, "width": 2}},
                                 showlegend=False, name=f"{c} sweep"), row=1, col=col)
        # jitter cells: observed fraction with Wilson interval (packet-level); model curve (interpretation)
        for j in [j for j in d["jitter"] if j["client"] == c]:
            high = j["mu_ms"] > 260
            xs = [x_lo + i * (x_hi - x_lo) / 200 for i in range(201)]
            fig.add_trace(go.Scatter(x=xs, y=[jm.predict(j["T_ms"], x, j["sigma_ms"]) for x in xs], mode="lines",
                                     line={"color": INK2, "width": LINE, "dash": "dot"}, showlegend=False,
                                     name=f"model {j['scenario']}"), row=1, col=col)
            o = j["observed"]
            fig.add_trace(go.Scatter(x=[j["mu_ms"]], y=[o["fraction"]], mode="markers",
                                     error_y={"type": "data", "symmetric": False, "array": [o["ci"]["hi"] - o["fraction"]],
                                              "arrayminus": [o["fraction"] - o["ci"]["lo"]], "thickness": 4, "width": 10, "color": INK},
                                     marker={"size": MARK + 6, "color": col_c, "symbol": "diamond", "line": {"color": INK, "width": 2}},
                                     showlegend=False, name=f"{c} {j['scenario']}"), row=1, col=col)
            fig.add_annotation(x=j["mu_ms"], y=o["fraction"], xref=f"x{ax}", yref=f"y{ax}",
                               text=f"σ {j['sigma_ms']:.0f} ms<br>{o['v6_wins']}/{o['n']}", showarrow=False, align="left" if high else "right",
                               xanchor="left" if high else "right", xshift=22 if high else -22,
                               yshift=0 if high else -34, font={"size": F_NOTE - 2, "color": INK}, bgcolor="rgba(255,255,255,0.85)")
        if with_setup:
            so = [k for k in d["setup_oracle"] if k["client"] == c]
            fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in so], y=[k["setup_median_ms"] for k in so], mode="lines+markers",
                                     line={"color": col_c, "width": LINE},
                                     marker={"size": MARK - 2, "color": col_c, "symbol": sym, "line": {"color": INK, "width": 1.5}},
                                     showlegend=False, name=f"{c} setup"), row=2, col=col)
            fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in so], y=[k["oracle_setup_median_ms"] for k in so], mode="lines",
                                     line={"color": INK2, "width": LINE, "dash": "dash"},
                                     showlegend=False, name=f"{c} oracle"), row=2, col=col)
    one = ncol == 1
    sym1 = CLIENT[clients[0]]["symbol"] if one else "circle"
    keys = [
        _legend_key(go, "packet", "Win fraction, sweep (n=5, unanimous)" if one else
                    "Win fraction, sweep (n=5, unanimous)<br>● curl, ▲ Chromium",
                    mode="markers", marker={"size": MARK, "color": INK2, "symbol": sym1, "line": {"color": INK, "width": 2}}),
        _legend_key(go, "packet", "Win fraction, jitter, 95% Wilson", mode="markers",
                    marker={"size": MARK + 4, "color": INK2, "symbol": "diamond", "line": {"color": INK, "width": 2}},
                    error_y={"type": "data", "array": [0], "thickness": 4, "color": INK}),
        _legend_key(go, "packet", "Flip bracket, 5 ms (shaded)", mode="markers",
                    marker={"size": 22, "color": BAND, "symbol": "square", "line": {"color": INK2, "width": 1.5}}),
        _legend_key(go, "packet", "T: 1st SYN to IPv4 SYN-ACK<br>(latency-sweep)", mode="lines", line={"color": INK, "width": 3}),
    ]
    if with_setup:
        keys += [
            _legend_key(go, "packet", "TCP setup, median per cell", mode="lines+markers",
                        line={"color": INK2, "width": LINE}, marker={"size": MARK - 2, "color": INK2}),
            _legend_key(go, "derived", "Oracle setup (winner's ping RTT)", mode="lines",
                        line={"color": INK2, "width": LINE, "dash": "dash"}),
        ]
    model = (f"Model Φ((T − μ)/σ), T = {f2(jT[clients[0]])} ms<br>(jitter-loss)" if one else
             f"Model Φ((T − μ)/σ), T from jitter-loss:<br>curl {f2(jT['curl'])}, Chromium {f2(jT['chromium'])} ms")
    keys.append(_legend_key(go, "interp", model, mode="lines", line={"color": INK2, "width": LINE, "dash": "dot"}))
    for k in keys:
        fig.add_trace(k, row=1, col=1)
    who = CLIENT[clients[0]]["name"] if ncol == 1 else "curl and Chromium"
    lay = _base_layout(size, f"IPv6 latency budget: {who}",
                       margin={"l": 100, "r": 20 if half else 420, "t": 100, "b": 320 if half else 90})
    if half:
        lay["legend"].update({"orientation": "v", "x": -0.14, "xanchor": "left", "y": -0.4, "yanchor": "top"})
    else:
        lay["legend"].update({"x": 1.02, "xanchor": "left", "y": 1.0, "yanchor": "top"})
    fig.update_layout(**lay)
    ticks = [100, 200, 300, 400]
    for col in range(1, ncol + 1):
        fig.update_yaxes(_axis("IPv6 win fraction" if col == 1 else "", range=[-0.08, 1.55], tickvals=[0, 0.5, 1]), row=1, col=col)
        fig.update_xaxes(_axis("" if with_setup else "IPv6 RTT (ms, lab ping)", range=[x_lo, x_hi], tickvals=ticks), row=1, col=col)
        if with_setup:
            fig.update_yaxes(_axis("TCP setup (ms)" if col == 1 else "", range=[0, 460], tickvals=[0, 100, 200, 300, 400]),
                             row=2, col=col)
            fig.update_xaxes(_axis("IPv6 RTT (ms, lab ping)", range=[x_lo, x_hi], tickvals=ticks), row=2, col=col)
    if ncol > 1:   # the subplot titles are the first annotations
        for a in fig.layout.annotations[:ncol]:
            a.font = {"size": F_AXIS + 2, "color": INK}
    return fig


def fig_setup_oracle(d: dict, size=HALF) -> dict:
    """TCP setup (packet-level) against the oracle setup (derived), both clients on one axis; half slide."""
    go = _go()
    fig = go.Figure()
    for c in ("curl", "chromium"):
        so = [k for k in d["setup_oracle"] if k["client"] == c]
        col_c, sym = CLIENT[c]["colour"], CLIENT[c]["symbol"]
        fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in so], y=[k["oracle_setup_median_ms"] for k in so], mode="lines",
                                 line={"color": col_c, "width": LINE, "dash": "dash"}, showlegend=False))
        fig.add_trace(go.Scatter(x=[k["rtt_ms"] for k in so], y=[k["setup_median_ms"] for k in so], mode="lines+markers",
                                 line={"color": col_c, "width": LINE},
                                 marker={"size": MARK, "color": col_c, "symbol": sym, "line": {"color": INK, "width": 2}},
                                 showlegend=False))
        last = so[-1]
        fig.add_annotation(x=last["rtt_ms"], y=last["setup_median_ms"], text=f"<b>{CLIENT[c]['name']}</b>", showarrow=False,
                           xanchor="right", yanchor="bottom", yshift=14, font={"size": F_NOTE, "color": INK})
    keys = [
        _legend_key(go, "packet", "TCP setup, curl (median per cell)", mode="lines+markers",
                    line={"color": CLIENT["curl"]["colour"], "width": LINE},
                    marker={"size": MARK, "color": CLIENT["curl"]["colour"], "symbol": "circle", "line": {"color": INK, "width": 2}}),
        _legend_key(go, "packet", "TCP setup, Chromium (median per cell)", mode="lines+markers",
                    line={"color": CLIENT["chromium"]["colour"], "width": LINE},
                    marker={"size": MARK, "color": CLIENT["chromium"]["colour"], "symbol": "triangle-up",
                            "line": {"color": INK, "width": 2}}),
        _legend_key(go, "derived", "Oracle setup, winner's ping RTT", mode="lines",
                    line={"color": INK2, "width": LINE, "dash": "dash"}),
    ]
    for k in keys:
        fig.add_trace(k)
    lay = _base_layout(size, "TCP setup against the oracle", margin={"l": 100, "r": 20, "t": 80, "b": 250})
    lay["legend"].update({"orientation": "v", "x": -0.14, "y": -0.32, "yanchor": "top"})
    fig.update_layout(**lay)
    fig.update_yaxes(_axis("Median per cell (ms)", range=[0, 460], tickvals=[0, 100, 200, 300, 400]))
    fig.update_xaxes(_axis("IPv6 RTT (ms, lab ping)", range=[100, 440], tickvals=[100, 200, 300, 400]))
    return fig


def fig_he_linearity(d: dict, size=FULL) -> dict:
    from plotly.subplots import make_subplots
    go = _go()
    rows = d["he_sweep"]
    var = [r for r in rows if r["timeout_ms"] is not None]
    plain = next(r for r in rows if r["timeout_ms"] is None)
    res = d["residuals"]
    half = size == HALF
    blue = CLIENT["curl"]["colour"]
    fig = make_subplots(rows=2, cols=1, shared_xaxes=True, vertical_spacing=0.08,
                        row_heights=[0.5, 0.5] if half else [0.6, 0.4])
    xs = [r["timeout_ms"] for r in var]
    fig.add_trace(go.Scatter(x=xs, y=[r["predicted_T_ms"] for r in var], mode="lines",
                             line={"color": INK2, "width": LINE, "dash": "dot"}, showlegend=False), row=1, col=1)
    fig.add_trace(go.Scatter(x=[200], y=[plain["S1"]["T_ms"]], mode="markers",
                             marker={"size": MARK + 20, "color": INK, "symbol": "star", "line": {"color": INK, "width": 1}},
                             showlegend=False), row=1, col=1)
    fig.add_trace(go.Scatter(x=xs, y=[r["S1"]["T_ms"] for r in var], mode="markers",
                             marker={"size": MARK + 2, "color": blue, "line": {"color": INK, "width": 2}}, showlegend=False), row=1, col=1)
    if not half:   # on the half slide the legend entry carries this text
        fig.add_annotation(x=200, y=plain["S1"]["T_ms"], xref="x", yref="y", ax=70, ay=65,
                           text=f"plain curl, no flag: {f2(plain['S1']['T_ms'])} ms<br>(placed at the documented default, 200)",
                           showarrow=True, arrowwidth=2, arrowcolor=INK2, xanchor="left", align="left",
                           font={"size": F_NOTE, "color": INK})
    # residual panel: every value shown, straight segments only between neighbours, no fit or smoothing
    rv = [r["T_minus_predicted_ms"] for r in var]
    fig.add_hline(y=0, line={"color": INK2, "width": 2}, row=2, col=1)
    fig.add_trace(go.Scatter(x=xs, y=rv, mode="markers",
                             marker={"size": MARK + 2, "color": blue, "line": {"color": INK, "width": 2}}, showlegend=False),
                  row=2, col=1)
    # the values themselves, on one row along the bottom of the panel, each under its timeout
    fig.add_trace(go.Scatter(x=xs, y=[(-0.1 if half else 0.17) if i % 2 == 0 else (0.38 if half else 0.4) for i in range(len(xs))],
                             mode="text", text=[f"+{f2(v)}" for v in rv],
                             textposition="middle center", textfont={"size": F_NOTE - (3 if half else 1), "color": INK},
                             showlegend=False, hoverinfo="skip"), row=2, col=1)
    for (x0, x1, rng) in ((35, 265, res["below"]), (280, 520, res["from"])):
        fig.add_shape(type="rect", x0=x0, x1=x1, y0=rng[0] - 0.12, y1=rng[1] + 0.12, xref="x2", yref="y2",
                      fillcolor="rgba(42,120,214,0.10)", line={"color": INK2, "width": 2, "dash": "solid"}, layer="below")
    if not half:
        fig.add_annotation(x=150, y=res["below"][1] + 0.14, xref="x2", yref="y2", yanchor="bottom", showarrow=False,
                           text=f"he50–he250: +{f2(res['below'][0])} to +{f2(res['below'][1])} ms",
                           font={"size": F_NOTE, "color": INK})
        fig.add_annotation(x=400, y=res["from"][1] + 0.14, xref="x2", yref="y2", yanchor="bottom", showarrow=False,
                           text=f"he300–he500: +{f2(res['from'][0])} to +{f2(res['from'][1])} ms, not monotonic",
                           font={"size": F_NOTE, "color": INK})
    keys = [
        _legend_key(go, "packet", "T, 1st SYN to IPv4 SYN-ACK (S1, median)" if half else
                    "T: first SYN to IPv4 SYN-ACK (S1, median of 10)", mode="markers",
                    marker={"size": MARK + 2, "color": INK2, "line": {"color": INK, "width": 2}}),
        _legend_key(go, "packet", f"Plain curl, no flag: {f2(plain['S1']['T_ms'])} ms (at 200)" if half else
                    "Plain curl, no flag (S1, median of 10)", mode="markers",
                    marker={"size": MARK + 8, "color": INK, "symbol": "star"}),
        _legend_key(go, "packet", "Residual: T − reference" if half else "Residual: T − (timeout + IPv4 handshake)", mode="markers",
                    marker={"size": MARK, "color": INK2, "line": {"color": INK, "width": 2}}),
        _legend_key(go, "interp", "Reference: timeout + IPv4 handshake", mode="lines",
                    line={"color": INK2, "width": LINE, "dash": "dot"}),
    ]
    for k in keys:
        fig.add_trace(k, row=1, col=1)
    title = "curl: T against timeout (he-sweep)" if half else "curl: T against configured Happy Eyeballs timeout (he-sweep, S1)"
    lay = _base_layout(size, title, margin={"l": 110, "r": 20 if half else 380, "t": 80, "b": 265 if half else 90})
    if half:
        lay["legend"].update({"orientation": "v", "x": -0.2, "y": -0.3, "yanchor": "top", "font": {"size": F_LEGEND - 2, "color": INK}})
    else:
        lay["legend"].update({"x": 1.02, "xanchor": "left", "y": 1.0, "yanchor": "top"})
    fig.update_layout(**lay)
    fig.update_yaxes(_axis("T (ms)", range=[0, 580], tickvals=[0, 100, 200, 300, 400, 500]), row=1, col=1)
    fig.update_yaxes(_axis("Residual (ms)", range=[-0.3, 2.4] if half else [0, 2.6], tickvals=[1, 2] if half else [1, 1.5, 2]),
                     row=2, col=1)
    tv = [100, 200, 300, 400, 500] if half else [50, 100, 150, 200, 250, 300, 400, 500]
    fig.update_xaxes(_axis("", range=[20, 535], tickvals=tv), row=1, col=1)
    fig.update_xaxes(_axis("timeout (ms, configuration)" if half else "--happy-eyeballs-timeout-ms (configuration)",
                           range=[20, 535], tickvals=tv), row=2, col=1)
    return fig


def fig_reproducibility(d: dict, size=FULL) -> dict:
    go = _go()
    rep = d["T_reproducibility"]
    half = size == HALF
    blue = CLIENT["curl"]["colour"]
    fig = go.Figure()
    meds = [r["T_ms"] for r in rep]
    fig.add_hrect(y0=min(meds), y1=max(meds), fillcolor=BAND, line_width=0, layer="below")
    cats = []
    for i, r in enumerate(rep):
        cat = f"<b>{r['campaign']}</b><br>{r['condition']}<br>n = {r['n']}<br>code {', '.join(r['code'])}" if not half \
            else f"<b>{r['campaign'].replace('-', '-<br>')}</b><br>n = {r['n']}"
        cats.append(cat)
        k = len(r["runs_ms"])
        offs = [((j * 0.6180339) % 1 - 0.5) * 0.5 for j in range(k)]   # deterministic spread, no randomness
        fig.add_trace(go.Scatter(x=[i + o for o in offs], y=r["runs_ms"], mode="markers", showlegend=False,
                                 marker={"size": 9, "color": blue, "opacity": 0.55, "line": {"width": 0}}))
        fig.add_trace(go.Scatter(x=[i - 0.32, i + 0.32], y=[r["T_ms"]] * 2, mode="lines", showlegend=False,
                                 line={"color": INK, "width": 6}))
        if half:   # above the bar: there is no room beside it
            fig.add_annotation(x=i, y=max(r["runs_ms"]), text=f"<b>{f2(r['T_ms'])}</b>", showarrow=False, yanchor="bottom",
                               yshift=4, font={"size": F_NOTE - 2, "color": INK})
        else:
            fig.add_annotation(x=i + 0.34, y=r["T_ms"], text=f"<b>{f2(r['T_ms'])}</b>", showarrow=False, xanchor="left",
                               font={"size": F_NOTE + 2, "color": INK}, bgcolor="rgba(255,255,255,0.85)")
    if not half:
        fig.add_annotation(x=1.0, y=(min(meds) + max(meds)) / 2, xref="paper", yref="y", xanchor="left", xshift=12, showarrow=False,
                           text=f"<b>medians within<br>{f2(d['T_spread_ms'])} ms</b>", align="left", font={"size": F_NOTE, "color": INK})
    keys = [
        _legend_key(go, "packet", "T per run", mode="markers", marker={"size": 10, "color": INK2, "opacity": 0.6}),
        _legend_key(go, "packet", "Median T per campaign", mode="lines", line={"color": INK, "width": 6}),
        _legend_key(go, "packet", "Range of the four medians (shaded)", mode="markers",
                    marker={"size": 22, "color": BAND, "symbol": "square", "line": {"color": INK2, "width": 1.5}}),
    ]
    for k in keys:
        fig.add_trace(k)
    kern = sorted({k for r in rep for k in r["kernel"]})
    if half:
        sub = (f"T = first SYN to IPv4 SYN-ACK. Medians within {f2(d['T_spread_ms'])} ms.<br>Reproduces across campaigns and code<br>"
               f"versions on one host and one kernel<br>({', '.join(kern)}). Not tested across<br>hosts or kernels.")
    else:
        sub = (f"T = first SYN to IPv4 SYN-ACK. Reproduces across campaigns and code versions<br>on one host and one kernel "
               f"({', '.join(kern)}). Not tested across hosts or kernels.")
    lay = _base_layout(size, "Plain curl's T in four campaigns" if not half else "Plain curl's T, four campaigns",
                       margin={"l": 110, "r": 20 if half else 360, "t": 150 if not half else 215, "b": 190 if not half else 230})
    lay["annotations"] = list(fig.layout.annotations) + [
        {"text": sub, "x": 0.0, "y": 1.0, "xref": "paper", "yref": "paper", "yanchor": "bottom", "yshift": 14,
         "xanchor": "left", "align": "left", "showarrow": False, "font": {"size": F_NOTE - (3 if half else 0), "color": INK}}]
    if half:
        lay["legend"].update({"orientation": "v", "x": -0.16, "y": -0.5, "yanchor": "top", "font": {"size": F_LEGEND - 2, "color": INK}})
    else:
        lay["legend"].update({"x": 1.02, "xanchor": "left", "y": 1.0, "yanchor": "top"})
    fig.update_layout(**lay)
    allv = [v for r in rep for v in r["runs_ms"]]
    fig.update_yaxes(_axis("T (ms)", range=[min(allv) - 0.3, max(allv) + (0.8 if half else 0.3)]))
    fig.update_xaxes(_axis("", tickvals=list(range(len(rep))), ticktext=cats, range=[-0.6, len(rep) - 0.2],
                           tickfont={"size": F_NOTE - (4 if half else 2), "color": INK}, showgrid=False,
                           tickangle=0))
    return fig


def fig_claims_table(d: dict, sections=("core", "ext"), size=FULL) -> dict:
    """The combined table (both sections) is a report page (REPORT size): 16 rows do not fit a slide legibly."""
    go = _go()
    rows = [r for r in claims(d) if r["section"] in sections]
    head = {"core": "SATISFIES PS-028: frozen core dataset, C0 + six scenarios S1–S6, 2 clients × 20 reps (2026-10-26)",
            "ext": "BEYOND PS-028: extension campaigns (2026-11-21/22)"}
    claim_col, ds_col, tag_col, fill = [], [], [], []
    for s in sections:
        claim_col.append(f"<b>{head[s]}</b>")
        ds_col.append("")
        tag_col.append("")
        fill.append("#e8e7e1")
        for r in [r for r in rows if r["section"] == s]:
            boundary = r["claim"].startswith("BOUNDARY")
            claim_col.append(("<i>" + r["claim"] + "</i>") if boundary else r["claim"])
            ds_col.append(r["dataset"])
            tag_col.append(f"[{TAG[r['tag']]}]")
            fill.append("#fff6e0" if boundary else BG)
    fs = 19
    fig = go.Figure(go.Table(
        columnwidth=[7.6, 2.3, 2.1],
        header={"values": ["<b>Claim</b>", "<b>Dataset</b>", "<b>Evidence tag</b>"], "fill_color": INK, "align": "left",
                "font": {"color": "#ffffff", "size": fs + 1, "family": FONT}, "height": fs * 2, "line": {"color": INK, "width": 2}},
        cells={"values": [claim_col, ds_col, tag_col], "fill_color": [fill] * 3, "align": "left",
               "font": {"color": INK, "size": fs, "family": FONT}, "height": int(fs * 1.9),
               "line": {"color": INK2, "width": 1.5}}))
    title = {("core", "ext"): "What each dataset supports", ("core",): "Results that satisfy PS-028",
             ("ext",): "Results beyond PS-028"}[tuple(sections)]
    lay = _base_layout(size, title, margin={"l": 20, "r": 20, "t": 70, "b": 10})
    lay["showlegend"] = False
    fig.update_layout(**lay)
    return fig


def figures(d: dict) -> dict[str, tuple]:
    return {
        "fig1_ipv6_latency_budget_full": (fig_latency_budget(d), FULL),
        "fig1_ipv6_latency_budget_curl_half": (fig_latency_budget(d, ("curl",), HALF, with_setup=False), HALF),
        "fig1_ipv6_latency_budget_chromium_half": (fig_latency_budget(d, ("chromium",), HALF, with_setup=False), HALF),
        "fig1_setup_vs_oracle_half": (fig_setup_oracle(d), HALF),
        "fig2_he_linearity_full": (fig_he_linearity(d), FULL),
        "fig2_he_linearity_half": (fig_he_linearity(d, HALF), HALF),
        "fig3_claims_table_report": (fig_claims_table(d, size=REPORT), REPORT),
        "fig3_claims_core_full": (fig_claims_table(d, ("core",)), FULL),
        "fig3_claims_extensions_full": (fig_claims_table(d, ("ext",)), FULL),
        "fig4_t_reproducibility_full": (fig_reproducibility(d), FULL),
        "fig4_t_reproducibility_half": (fig_reproducibility(d, HALF), HALF),
    }


# --- export ----------------------------------------------------------------------------------

def png_with_dpi(png: bytes, dpi: int = DPI) -> bytes:
    """Return the PNG with a single pHYs chunk (pixels per metre) placed straight after IHDR."""
    sig, pos, chunks = png[:8], 8, []
    if sig != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    while pos < len(png):
        (n,) = struct.unpack(">I", png[pos:pos + 4])
        typ = png[pos + 4:pos + 8]
        chunks.append((typ, png[pos:pos + 12 + n]))
        pos += 12 + n
    ppm = round(dpi / 0.0254)
    body = b"pHYs" + struct.pack(">IIB", ppm, ppm, 1)
    phys = struct.pack(">I", 9) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    out = [sig]
    for typ, raw in chunks:
        if typ == b"pHYs":
            continue
        out.append(raw)
        if typ == b"IHDR":
            out.append(phys)
    return b"".join(out)


_UID_RE = re.compile(r'id="defs-([0-9a-f]{6})"')


def stable_svg(svg: str) -> str:
    """Replace Plotly's random per-plot id (a 6-hex uid in clip/defs/legend ids) so re-renders are byte-identical."""
    m = _UID_RE.search(svg)
    if not m:
        return svg
    return re.sub(r"(clip|defs-|topdefs-|legend)" + m.group(1), r"\1hlfig", svg)


def png_info(png: bytes) -> dict:
    w, h = struct.unpack(">II", png[16:24])
    i = png.find(b"pHYs")
    ppm = struct.unpack(">I", png[i + 4:i + 8])[0] if i > 0 else None
    return {"width": w, "height": h, "dpi": round(ppm * 0.0254) if ppm else None}


_JS = """async ([spec, w, h, scale]) => {
  const d = document.createElement('div'); document.body.appendChild(d);
  await Plotly.newPlot(d, spec.data, spec.layout, {staticPlot: true});
  const svg = await Plotly.toImage(d, {format: 'svg', width: w, height: h});
  const png = await Plotly.toImage(d, {format: 'png', width: w, height: h, scale: scale});
  Plotly.purge(d); d.remove(); return [svg, png]; }"""


def render(figs: dict[str, tuple], out: Path = OUT) -> list[Path]:
    from playwright.sync_api import sync_playwright
    from plotly.offline import get_plotlyjs
    from runner.child_env import child_env
    out.mkdir(parents=True, exist_ok=True)
    written = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, env=child_env())
        page = browser.new_page()
        page.set_content(f"<!doctype html><meta charset=utf-8><script>{get_plotlyjs()}</script><body></body>")
        for name, (fig, (w, h)) in figs.items():
            spec = json.loads(fig.to_json())
            for i, tr in enumerate(spec["data"]):   # fixed trace ids: Plotly would draw random ones into the SVG
                tr["uid"] = f"t{i:03d}"
            svg_url, png_url = page.evaluate(_JS, [spec, w, h, SCALE])
            svg = stable_svg(urllib.parse.unquote(svg_url.split(",", 1)[1]))
            png = png_with_dpi(base64.b64decode(png_url.split(",", 1)[1]))
            (out / f"{name}.svg").write_text(svg, encoding="utf-8")
            (out / f"{name}.png").write_bytes(png)
            written += [out / f"{name}.svg", out / f"{name}.png"]
        browser.close()
    return written


def data_json(d: dict) -> str:
    return json.dumps(d | {"claims": claims(d)}, indent=1, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true")
    g.add_argument("--data-only", action="store_true")
    a = ap.parse_args(argv)
    d = collect()
    text = data_json(d)
    path = OUT / DATA_FILE
    if a.check:
        ok = path.exists() and path.read_text(encoding="utf-8") == text
        print(f"{path.relative_to(REPO)}: {'up to date' if ok else 'OUT OF DATE: re-run figures.py'}")
        return 0 if ok else 1
    OUT.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path.relative_to(REPO)}")
    if not a.data_only:
        for p in render(figures(d)):
            info = png_info(p.read_bytes()) if p.suffix == ".png" else None
            print(f"wrote {p.relative_to(REPO)}" + (f"  {info['width']}x{info['height']} px, {info['dpi']} dpi" if info else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
