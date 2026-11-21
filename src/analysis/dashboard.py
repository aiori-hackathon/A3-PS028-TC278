"""Build the HappyLab dashboard: one standalone HTML page from a dataset (default: docs/dataset.md).

    .venv/bin/python src/analysis/dashboard.py              # data/generated/summary/dashboard.html (Plotly inline, works offline)
    .venv/bin/python src/analysis/dashboard.py --cdn        # load plotly.js from jsDelivr instead (small file)
    .venv/bin/python src/analysis/dashboard.py --dataset NAME   # docs/datasets/NAME.md -> data/generated/summary/NAME/

Everything shown comes from summarise.build(), which reads only the sessions the dataset manifest
lists (the 14 core sessions by default) and refuses an incomplete or unclean session. Each section carries an evidence
label: packet-level (pcap), client log, derived, or interpretation.

The first section is the connection race timeline (analysis/race.py): one run at a time, selectable, defaulting to
the representative S1 run. Each run's capture is re-read when present and must match its record (SHA-256 and every
shared value); the runs committed in examples/ also list their packet rows. A link to one run: dashboard.html#run=ID.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import plotly  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
from plotly.offline import get_plotlyjs, get_plotlyjs_version  # noqa: E402

from analysis import race as race_mod  # noqa: E402
from analysis.names import group_by_implementation, implementation_of, parse_client  # noqa: E402
from analysis.summarise import (CLIENTS, CORE_DATASET, EXPECTED_REPS, SCENARIOS, DatasetError,  # noqa: E402
                                Run, build, load_dataset, out_dir_for)

# Validated with the dataviz palette checker (light and dark surfaces). The v6 aqua is below 3:1
# contrast on the light surface, so families are always named in legends, labels and tables.
PALETTE = {
    "light": {"curl": "#2a78d6", "chromium": "#eb6834", "v6": "#1baf7a", "v4": "#6250d6"},
    "dark": {"curl": "#3987e5", "chromium": "#d95926", "v6": "#199e70", "v4": "#9085e9"},
}
CLIENT_LABEL = {"curl": "curl", "chromium": "Chromium"}   # the implementations


def client_label(c: str) -> str:
    """Display name of a client label: the implementation, plus the variant for a curl variant."""
    cn = parse_client(c)
    base = CLIENT_LABEL[cn.implementation]
    return base if not cn.variant else f"{base} (HE timeout {cn.he_timeout_ms} ms)"


def role_of(c: str) -> str:
    """Colour role: a variant takes its implementation's colour and differs by mark shape
    (triangle points, hatched bars) and by its legend name."""
    return implementation_of(c)


def _bar_marks(c: str) -> dict:
    """Hatched bars for a variant; nothing for a plain client."""
    return {"marker": dict(pattern=dict(shape="/"))} if parse_client(c).variant else {}


def _box_marker(c: str) -> dict:
    return dict(size=6, opacity=0.75, **({"symbol": "triangle-up"} if parse_client(c).variant else {}))


KIND_SYMBOL = {"first": "circle", "same-family": "diamond", "other-family": "square"}
KIND_LABEL = {"first": "first SYN", "same-family": "new attempt, same family", "other-family": "first SYN, other family"}
RFC8305_REFERENCE_MS = 250
TAG_LABEL = {"packet": "Packet-level (pcap)", "client": "Client log", "interp": "Interpretation",
             "derived": "Derived (pcap − lab RTT)"}


def evidence_tag(source: str) -> tuple[str, str]:
    """(css kind, label) for an evidence source; 'derived' is never shown as packet-level or client log."""
    if source == "packet":
        return "packet", "Packet-level"
    if source == "derived":
        return "derived", "Derived"
    return "client", "Client log"


def _base_layout(**kw) -> dict:
    layout = dict(margin=dict(l=64, r=16, t=16, b=48), height=380, hovermode="closest",
                  legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, title=None),
                  font=dict(family="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif", size=13))
    layout.update(kw)
    return layout


def _jitter(rep: int, width: float = 0.5, reps: int = EXPECTED_REPS) -> float:
    return (rep - (reps + 1) / 2) / reps * width


def shape_of(cells: dict) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(clients, scenarios) of a summary, in its own order; the figures draw exactly these."""
    clients = tuple(cells)
    scenarios = tuple(dict.fromkeys(s for c in clients for s in cells[c]))
    return clients, scenarios


def fig_setup(runs: list[Run], clients=CLIENTS, scenarios=SCENARIOS) -> dict:
    data = []
    for c in clients:
        rs = [r for r in runs if r.client == c and r.setup_ms is not None]
        data.append(go.Box(
            x=[r.scenario for r in rs], y=[r.setup_ms for r in rs], name=client_label(c), meta={"role": role_of(c)},
            boxpoints="all", jitter=0.5, pointpos=0, marker=_box_marker(c), line=dict(width=1.5),
            fillcolor="rgba(0,0,0,0)", offsetgroup=c, customdata=[r.run_id for r in rs],
            hovertemplate="%{customdata}<br>TCP setup %{y:.3f} ms<extra>" + client_label(c) + "</extra>"))
    return {"data": data, "layout": _base_layout(
        boxmode="group", xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(scenarios)),
        yaxis=dict(title=dict(text="TCP setup time (ms)"), rangemode="tozero"))}


def fig_penalty(cells: dict) -> dict:
    clients, scenarios = shape_of(cells)
    data = []
    for c in clients:
        vals = [cells[c][s]["scenario_penalty_ms"] for s in scenarios]
        data.append(go.Bar(
            x=list(scenarios), y=vals, name=client_label(c), meta={"role": role_of(c)}, offsetgroup=c, **_bar_marks(c),
            text=[f"{v:.1f}" if v is not None and abs(v) >= 5 else "" for v in vals], textposition="outside",
            hovertemplate="%{x}: %{y:.3f} ms<extra>" + client_label(c) + " penalty</extra>"))
    return {"data": data, "layout": _base_layout(
        barmode="group", bargap=0.3, bargroupgap=0.08,
        xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(scenarios)),
        yaxis=dict(title=dict(text="Median setup minus own C0 median (ms)"), rangemode="tozero"))}


def timeline_rows(clients=CLIENTS, scenarios=SCENARIOS) -> list[tuple[str, str]]:
    return [(s, c) for s in scenarios for c in clients]


def fig_timeline(runs: list[Run], clients=CLIENTS, scenarios=SCENARIOS, reps: int = EXPECTED_REPS) -> dict:
    rows = timeline_rows(clients, scenarios)
    index = {row: i for i, row in enumerate(rows)}
    data = []
    for fam in ("v6", "v4"):
        for kind in ("first", "same-family", "other-family"):
            pts = [(r, a) for r in runs for a in r.attempts if a["family"] == fam and a["kind"] == kind]
            if not pts:
                continue
            data.append(go.Scatter(
                x=[a["offset_ms"] for _, a in pts],
                y=[index[(r.scenario, r.client)] + _jitter(r.repetition, reps=reps) for r, _ in pts],
                mode="markers", name=f"IPv{fam[1]} {KIND_LABEL[kind]}", meta={"role": fam},
                marker=dict(symbol=KIND_SYMBOL[kind], size=8, opacity=0.8, line=dict(width=0)),
                customdata=[[r.run_id, a["result"], a["syn_retransmits"]] for r, a in pts],
                hovertemplate=("%{customdata[0]}<br>IPv" + fam[1] + " SYN at +%{x:.3f} ms<br>"
                               "attempt %{customdata[1]}, kernel retransmits %{customdata[2]}<extra></extra>")))
    done = [r for r in runs if r.setup_ms is not None]
    data.append(go.Scatter(
        x=[r.setup_ms for r in done],
        y=[index[(r.scenario, r.client)] + _jitter(r.repetition, reps=reps) for r in done],
        mode="markers", name="winning handshake complete (ACK)", meta={"role": "ink"},
        marker=dict(symbol="line-ns-open", size=10, line=dict(width=2)),
        customdata=[[r.run_id, r.winner] for r in done],
        hovertemplate="%{customdata[0]}<br>handshake complete at +%{x:.3f} ms (winner %{customdata[1]})"
                      "<extra></extra>"))
    layout = _base_layout(
        height=560, margin=dict(l=120, r=16, t=16, b=48),
        xaxis=dict(title=dict(text="Time from the run's first SYN (ms)"),
                   range=[-10, max((r.setup_ms or 0) for r in runs) + 15], zeroline=False),
        yaxis=dict(tickvals=list(range(len(rows))), ticktext=[f"{s} · {client_label(c)}" for s, c in rows],
                   autorange="reversed", showgrid=False, zeroline=False),
        shapes=[dict(type="line", xref="x", yref="paper", x0=RFC8305_REFERENCE_MS, x1=RFC8305_REFERENCE_MS,
                     y0=0, y1=1, line=dict(dash="dot", width=1), meta={"role": "muted"})],
        annotations=[dict(x=RFC8305_REFERENCE_MS, y=1, xref="x", yref="paper", yanchor="bottom", showarrow=False,
                          text="250 ms: RFC 8305 suggested attempt delay (reference only)", font=dict(size=11))])
    n = len(clients)
    for i in range(1, len(scenarios)):
        layout["shapes"].append(dict(type="line", xref="paper", yref="y", x0=0, x1=1, y0=n * i - 0.5,
                                     y1=n * i - 0.5, line=dict(width=1), meta={"role": "grid"}))
    return {"data": data, "layout": layout}


def fig_inter_family(runs: list[Run], cells: dict) -> dict:
    clients, scenarios = shape_of(cells)
    data, annotations = [], []
    for k, c in enumerate(clients):
        rs = [r for r in runs if r.client == c and r.inter_family_ms is not None]
        data.append(go.Box(
            x=[r.scenario for r in rs], y=[r.inter_family_ms for r in rs], name=client_label(c), meta={"role": role_of(c)},
            boxpoints="all", jitter=0.5, pointpos=0, marker=_box_marker(c), line=dict(width=1.5),
            fillcolor="rgba(0,0,0,0)", offsetgroup=c, customdata=[r.run_id for r in rs],
            hovertemplate="%{customdata}<br>second family's first SYN +%{y:.3f} ms<extra>" + client_label(c)
                          + "</extra>"))
        for s in scenarios:
            inter = cells[c][s]["inter_family"]
            if inter["not_observed"]:
                annotations.append(dict(
                    x=s, y=0, xref="x", yref="y", yanchor="bottom", xshift=(-1 if k == 0 else 1) * 17,
                    showarrow=False, textangle=-90, font=dict(size=11),
                    text=f"{client_label(c)}: not observed ×{inter['not_observed']}"))
    # annotations are placed against an empty-but-ranged axis, so make sure every category exists
    data.append(go.Scatter(x=list(scenarios), y=[None] * len(scenarios), showlegend=False, hoverinfo="skip"))
    return {"data": data, "layout": _base_layout(
        boxmode="group", annotations=annotations,
        xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(scenarios)),
        yaxis=dict(title=dict(text="Inter-family attempt delay (ms)"), range=[0, 360]))}


def fig_winner(cells: dict, reps: int = EXPECTED_REPS) -> dict:
    rows = timeline_rows(*shape_of(cells))
    labels = [f"{s} · {client_label(c)}" for s, c in rows]
    data = []
    for fam in ("v6", "v4"):
        counts = [cells[c][s]["winning_family"].get(fam, 0) for s, c in rows]
        data.append(go.Bar(
            y=labels, x=counts, orientation="h", name=f"IPv{fam[1]} won", meta={"role": fam},
            text=[f"IPv{fam[1]} {n}" if n else "" for n in counts], textposition="inside", insidetextanchor="start",
            hovertemplate="%{y}: IPv" + fam[1] + " won %{x} runs<extra></extra>"))
    none = [cells[c][s]["winning_family"].get("none", 0) for s, c in rows]
    if any(none):
        data.append(go.Bar(y=labels, x=none, orientation="h", name="no winner", meta={"role": "muted"},
                           hovertemplate="%{y}: no winner in %{x} runs<extra></extra>"))
    return {"data": data, "layout": _base_layout(
        barmode="stack", height=480, margin=dict(l=120, r=16, t=16, b=48), bargap=0.25,
        xaxis=dict(title=dict(text="Runs"), range=[0, reps], dtick=5),
        yaxis=dict(autorange="reversed", showgrid=False))}


def fig_cost(runs: list[Run], clients=CLIENTS, scenarios=SCENARIOS) -> dict:
    """Cost of racing per run (derived): only runs where it was computed; the rest are counted in the table."""
    data = []
    for c in clients:
        rs = [r for r in runs if r.client == c and r.cost_of_racing_ms is not None]
        data.append(go.Box(
            x=[r.scenario for r in rs], y=[r.cost_of_racing_ms for r in rs], name=client_label(c), meta={"role": role_of(c)},
            boxpoints="all", jitter=0.5, pointpos=0, marker=_box_marker(c), line=dict(width=1.5),
            fillcolor="rgba(0,0,0,0)", offsetgroup=c,
            customdata=[[r.run_id, r.setup_ms, r.oracle_setup_ms] for r in rs],
            hovertemplate=("%{customdata[0]}<br>cost of racing %{y:.3f} ms<br>= TCP setup %{customdata[1]:.3f} ms"
                           " − oracle %{customdata[2]:.3f} ms<extra>" + client_label(c) + "</extra>")))
    return {"data": data, "layout": _base_layout(
        boxmode="group", xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(scenarios)),
        yaxis=dict(title=dict(text="TCP setup minus winning family's measured RTT (ms)"), zeroline=True))}


def fig_dns(runs: list[Run], clients=CLIENTS, scenarios=SCENARIOS) -> dict:
    data = []
    for c in clients:
        rs = [r for r in runs if r.client == c and r.dns_ms is not None]
        data.append(go.Box(
            x=[r.scenario for r in rs], y=[r.dns_ms for r in rs], name=client_label(c), meta={"role": role_of(c)},
            boxpoints="all", jitter=0.5, pointpos=0, marker=_box_marker(c), line=dict(width=1.5),
            fillcolor="rgba(0,0,0,0)", offsetgroup=c, customdata=[r.run_id for r in rs],
            hovertemplate="%{customdata}<br>DNS time %{y:.3f} ms<extra>" + client_label(c) + "</extra>"))
    return {"data": data, "layout": _base_layout(
        boxmode="group", xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(scenarios)),
        yaxis=dict(title=dict(text="DNS time, www.hl.test (ms, log scale)"), type="log"))}


# --- HTML --------------------------------------------------------------------------------

def _e(x) -> str:
    return html.escape(str(x))


def _counts(d: dict, fmt=lambda k: k) -> str:
    return ", ".join(f"{_e(fmt(k))} {v}" for k, v in d.items())


def _rtt(cell: dict) -> str:
    out = []
    for fam in ("v6", "v4"):
        x = (cell["measured_rtt_ms"] or {}).get(fam)
        if not x:
            out.append(f"IPv{fam[1]} -")
        elif x["median"] is None:
            out.append(f"IPv{fam[1]} no reply")
        else:
            out.append(f"IPv{fam[1]} {x['median']:g}")
    return "<br>".join(out)


def _penalty(x: dict) -> str:
    v = x["scenario_penalty_ms"]
    if v is not None:
        return f"{v:.3f}"
    return f"– <span class=muted>({_e(x.get('scenario_penalty_note', 'not available'))})</span>"


def _ci(cell: dict) -> str:
    ci = cell.get("tcp_setup_median_ci95")
    return "" if not ci else f"<br><span class=muted>CI {ci['lo']}–{ci['hi']} (width {ci['width']})</span>"


def summary_table(cells: dict) -> str:
    head = ("<tr><th>Scenario</th><th>Client</th><th>Measured RTT, ms <span class=src>lab verify</span></th>"
            "<th>Runs / success</th><th>Winner</th><th>Setup median [IQR], ms<br><span class=src>95% CI of median</span></th><th>Range, ms</th>"
            "<th>Penalty, ms</th><th>Inter-family delay</th><th>Failed / abandoned per run</th>"
            "<th>Attempt shape</th><th>DNS median, ms</th></tr>")
    body = []
    clients, scenarios = shape_of(cells)
    for s in scenarios:
        for c in clients:
            x = cells[c][s]
            st, inter = x["tcp_setup_ms"], x["inter_family"]
            io = inter["stats_over_observed_only"]
            inter_txt = (f"observed {inter['observed']}, not observed {inter['not_observed']}"
                         + (f"<br>median {io['median']} [{io['q1']}–{io['q3']}]" if io else ""))
            fa = ", ".join(f"{k} attempts ×{v}" for k, v in x["failed_or_abandoned_per_run"].items())
            body.append(
                f"<tr><td><b>{s}</b><br><span class=muted>{_e(x['label'])}</span></td><td>{client_label(c)}</td>"
                f"<td>{_rtt(x)}</td><td>{x['n']} / {x['successes']}</td>"
                f"<td>{_counts(x['winning_family'], lambda k: 'IPv' + k[1] if k.startswith('v') else k)}</td>"
                f"<td>{st['median']} [{st['q1']}–{st['q3']}]{_ci(x)}</td><td>{st['min']}–{st['max']}</td>"
                f"<td>{_penalty(x)}</td><td>{inter_txt}</td><td>{fa}</td>"
                f"<td>{_counts(x['attempt_shape'], lambda k: k.replace('>', ' → '))}</td>"
                f"<td>{x['dns_ms']['median'] if x['dns_ms'] else '-'}</td></tr>")
    return f"<table>{head}{''.join(body)}</table>"


def oracle_table(cells: dict) -> str:
    head = ("<tr><th>Scenario</th><th>Client</th><th>Winner</th><th>Oracle setup median, ms "
            "<span class=src>lab verify</span></th><th>Cost of racing median [IQR], ms</th><th>Range, ms</th>"
            "<th>Runs computed / total</th><th>Notes</th></tr>")
    body = []
    clients, scenarios = shape_of(cells)
    for s in scenarios:
        for c in clients:
            x = cells[c][s]
            o = x["oracle"]
            st, orc = o["cost_of_racing_ms"], o["oracle_setup_ms"]
            notes = [f"{_e(k)} {v}" for k, v in o["status"].items() if k != "computed"]
            notes += [_e(n) for n in o["not_computed_notes"]]
            if o["single_family_runs"]:
                notes.append(f"{o['single_family_runs']} runs tried one family only: no race took place")
            if o["dns_note"]:
                notes.append(_e(o["dns_note"]))
            # "to", not a dash: the cost can be negative
            cost_txt = f"{st['median']} [{st['q1']} to {st['q3']}]" if st else "–"
            range_txt = f"{st['min']} to {st['max']}" if st else "–"
            body.append(
                f"<tr><td><b>{s}</b><br><span class=muted>{_e(x['label'])}</span></td><td>{client_label(c)}</td>"
                f"<td>{_counts(x['winning_family'], lambda k: 'IPv' + k[1] if k.startswith('v') else k)}</td>"
                f"<td>{orc['median'] if orc else '–'}</td><td>{cost_txt}</td><td>{range_txt}</td>"
                f"<td>{o['status'].get('computed', 0)} / {x['n']}</td><td>{'<br>'.join(notes) or '–'}</td></tr>")
    return f"<table>{head}{''.join(body)}</table>"


def interpretation_html(items: list[dict]) -> str:
    out = []
    for it in items:
        ev = "".join(f"<li><span class='tag tag-{k}'>{lbl}</span> {_e(e['text'])}</li>"
                     for e in it["evidence"] for k, lbl in [evidence_tag(e["source"])])
        out.append(f"<article class='interp'><div class=interp-head><span class='tag tag-interp'>Interpretation"
                   f"</span><h3>{_e(it['topic'])}</h3></div><p>{_e(it['statement'])}</p>"
                   f"<details><summary>Evidence it rests on</summary><ul>{ev}</ul>"
                   f"<p class=muted>See {_e(it['reference'])}</p></details></article>")
    return "".join(out)


def provenance_html(ds: dict) -> str:
    sess = "".join(f"<tr><td>{x['scenario']}</td><td>{client_label(x['client'])}</td><td><code>{x['session']}"
                   f"</code></td></tr>" for x in ds["sessions"])
    clients = []
    for impl, labels in group_by_implementation(ds["clients"]).items():
        for i, c in enumerate(labels):   # a variant is listed under its implementation, not as a client
            p = ds["clients"][c]
            head = f"<h3>{CLIENT_LABEL[impl]}</h3>" if i == 0 else ""
            if parse_client(c).variant:
                head += (f"<h4>{_e(client_label(c))}: a configuration of {CLIENT_LABEL[impl]}, "
                         f"not another client implementation</h4>")
            cfg = p["configs"][0] if len(p["configs"]) == 1 else p["configs"]
            keep = {k: v for k, v in cfg.items() if k in ("happy_eyeballs_timeout_ms", "variant", "happy_eyeballs",
                                                         "resolver", "headless_mode", "quic", "secure_dns",
                                                         "https_upgrades", "playwright_version", "browser_per_run",
                                                         "url")}
            rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in keep.items())
            clients.append(f"{head}<p><code>{_e('; '.join(p['versions']))}</code><br>"
                           f"code version {_e(', '.join(p['code_versions']))}"
                           f"{' (configs differ between runs)' if len(p['configs']) > 1 else ''}</p>"
                           f"<table class=kv>{rows}</table>")
    return (f"<div class=grid2><div><h3>Sessions ({ds['runs']} runs, from {_e(ds['source'])})</h3>"
            f"<table class=compact><tr><th>Scenario</th><th>Client</th><th>Session</th></tr>{sess}</table></div>"
            f"<div>{''.join(clients)}</div></div>")


CSS = """
:root{--surface:#fcfcfb;--panel:#ffffff;--text:#0b0b0b;--text-2:#52514e;--muted:#898781;--grid:#e1e0d9;
--base:#c3c2b7;--border:#e1e0d9;--interp-bg:#f6f5f1;--v6:#1baf7a;--v4:#6250d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--surface:#1a1a19;--panel:#222221;--text:#f0efec;
--text-2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--base:#383835;--border:#2c2c2a;--interp-bg:#262624;--v6:#199e70;--v4:#9085e9}}
:root[data-theme="dark"]{--surface:#1a1a19;--panel:#222221;--text:#f0efec;--text-2:#c3c2b7;--muted:#898781;
--grid:#2c2c2a;--base:#383835;--border:#2c2c2a;--interp-bg:#262624;--v6:#199e70;--v4:#9085e9}
*{box-sizing:border-box}
body{margin:0;background:var(--surface);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1240px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:0}h3{font-size:1rem;margin:0}
p{margin:.5em 0}.muted{color:var(--muted)}.lede{color:var(--text-2);max-width:80ch}
header{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap;margin-bottom:16px}
button{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:4px 10px;cursor:pointer}
.legend-row{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 0}
section{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin:16px 0}
.sec-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:4px}
.note{color:var(--text-2);font-size:.92rem;max-width:90ch}
.tag{display:inline-block;font-size:.72rem;font-weight:600;letter-spacing:.02em;text-transform:uppercase;border-radius:4px;padding:1px 6px;border:1px solid var(--base);color:var(--text-2);white-space:nowrap}
.tag-packet{border-style:solid}.tag-client{border-style:dashed}
.tag-interp{border-style:dotted;font-style:italic}.tag-derived{border-style:double;border-width:3px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:16px}
.chart{width:100%;min-height:380px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;font-size:.85rem;font-variant-numeric:tabular-nums;width:100%}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--border)}
th{color:var(--text-2);font-weight:600}
.src{font-weight:400;color:var(--muted)}
table.kv th{width:40%}table.compact td,table.compact th{padding:3px 8px}
.interp{background:var(--interp-bg);border:1px dotted var(--base);border-radius:8px;padding:12px 14px;margin:12px 0}
.interp-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.interp p{max-width:95ch}details summary{cursor:pointer;color:var(--text-2)}
code{font-size:.85em;overflow-wrap:anywhere}
td,th{overflow-wrap:anywhere}.scroll td,.scroll th{overflow-wrap:normal}
.chart{overflow:hidden}
#race-section{border-width:2px}
#race-section:fullscreen{overflow:auto;margin:0;border-radius:0;padding:24px 32px;background:var(--panel)}
.race-title{font-size:1.6rem;font-weight:700;margin:6px 0 2px;line-height:1.25}
.race-controls{display:flex;gap:12px 18px;flex-wrap:wrap;align-items:flex-end;margin:12px 0}
.race-controls label{display:flex;flex-direction:column;gap:2px;font-size:.85rem;color:var(--text-2);font-weight:600;min-width:0;max-width:100%}
.race-controls select{max-width:calc(100vw - 64px)}
.race-controls select,.race-controls button{font:inherit;font-size:1rem;color:var(--text);background:var(--panel);border:1px solid var(--base);border-radius:6px;padding:6px 10px;max-width:100%}
.race-jump{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
button.linkish{border-style:dashed}
#race{width:100%;min-height:460px}
.race-key{display:flex;gap:6px 22px;flex-wrap:wrap;font-size:1rem;color:var(--text-2);margin:8px 0 4px}
.race-key b{color:var(--text)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr));gap:10px;margin:14px 0}
.stat{border:1px solid var(--base);border-radius:8px;padding:10px 12px}
.stat-derived{border:3px double var(--base);background:var(--interp-bg)}
.stat-name{font-weight:600;color:var(--text-2);margin-top:4px}
.stat-val{font-size:1.9rem;font-weight:700;line-height:1.2;font-variant-numeric:tabular-nums}
.stat-sub{font-size:.85rem;color:var(--muted)}
table.pkt td,table.pkt th{white-space:nowrap}
table.pkt tr.att-v6 td:first-child{box-shadow:inset 5px 0 0 var(--v6)}
table.pkt tr.att-v4 td:first-child{box-shadow:inset 5px 0 0 var(--v4)}
table.pkt tr.hit td{background:var(--interp-bg);outline:2px solid var(--text);outline-offset:-2px}
@media (max-width:719px){.race-title{font-size:1.2rem}.stat-val{font-size:1.4rem}}
"""

JS = r"""
const PALETTE = __PALETTE__;
const FIGS = __FIGS__;
function mode(){const t=document.documentElement.dataset.theme;
  if(t==='light'||t==='dark')return t;return matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}
function tok(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim();}
function roleColour(role,m){if(PALETTE[m][role])return PALETTE[m][role];
  if(role==='ink')return tok('--text');if(role==='grid')return tok('--grid');return tok('--muted');}
function themed(fig){const m=mode();const f=JSON.parse(JSON.stringify(fig));
  for(const t of f.data){const role=t.meta&&t.meta.role;if(!role)continue;const c=roleColour(role,m);
    t.marker=Object.assign({},t.marker,{color:c});
    if(t.marker.line&&t.marker.symbol==='line-ns-open')t.marker.line.color=c;
    if(t.type==='box')t.line=Object.assign({},t.line,{color:c});
    if(t.type==='bar'){t.marker.line={color:tok('--panel'),width:2};t.textfont={color:t.textposition==='inside'?'#ffffff':tok('--text-2')};}}
  const L=f.layout;L.paper_bgcolor=tok('--panel');L.plot_bgcolor=tok('--panel');
  L.font=Object.assign({},L.font,{color:tok('--text-2')});
  L.hoverlabel={bgcolor:tok('--panel'),bordercolor:tok('--base'),font:{color:tok('--text')}};
  for(const k of Object.keys(L))if(/^[xy]axis/.test(k)){L[k].gridcolor=tok('--grid');L[k].linecolor=tok('--base');
    L[k].zerolinecolor=tok('--base');L[k].tickfont={color:tok('--text-2')};
    if(L[k].title)L[k].title.font={color:tok('--text-2')};}
  for(const a of L.annotations||[])a.font=Object.assign({},a.font,{color:tok('--muted')});
  for(const s of L.shapes||[]){const r=s.meta&&s.meta.role;s.line=Object.assign({},s.line,{color:roleColour(r||'muted',m)});}
  return f;}
function draw(){for(const [id,fig] of Object.entries(FIGS)){const f=themed(fig);
  Plotly.react(id,f.data,f.layout,{displaylogo:false,responsive:true,modeBarButtonsToRemove:['lasso2d','select2d']});}
  if(typeof drawRace==='function')drawRace();}
function cycleTheme(){const r=document.documentElement;const order=['auto','light','dark'];
  const cur=r.dataset.theme||'auto';const next=order[(order.indexOf(cur)+1)%3];
  if(next==='auto')delete r.dataset.theme;else r.dataset.theme=next;
  document.getElementById('theme').textContent='Theme: '+next;draw();}
matchMedia('(prefers-color-scheme: dark)').addEventListener('change',draw);
document.getElementById('theme').addEventListener('click',cycleTheme);
"""

# The connection race timeline: one run at a time, drawn in the browser from RACE (analysis/race.py).
# Packet-level marks are solid shapes in the family lanes; the oracle (derived) has its own lane and a
# dash-dot reference line, and is never drawn with packet marks' styles.
RACE_JS = r"""
const RACE = __RACE__;
const RACE_LABEL = __LABELS__;
let raceId = null, raceClickBound = false;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fam(f){return 'IPv'+f[1];}
function fmt(x,d){return x==null?'–':(Math.round(x*10**(d==null?2:d))/10**(d==null?2:d)).toFixed(d==null?2:d);}
function signed(x){return (x<0?'−':'+')+fmt(Math.abs(x));}
function raceFigure(r,m,small){
  const fs=small?12:18, lab=small?13:20, C={v6:PALETTE[m].v6,v4:PALETTE[m].v4,grey:tok('--muted'),ink:tok('--text'),
    ink2:tok('--text-2'),panel:tok('--panel'),grid:tok('--grid'),base:tok('--base'),band:tok('--interp-bg')};
  const LANE={dns:3,v6:2,v4:1,orc:0}, data=[], shapes=[], ann=[], xs=[0];
  const PK='<br><i>Packet-level (pcap)</i>', DV='<br><i>Derived (pcap − lab RTT)</i>';
  const byFam={v6:[],v4:[]}; for(const a of r.att)(byFam[a.fam]=byFam[a.fam]||[]).push(a);
  const yOf=a=>{const L=byFam[a.fam],k=L.indexOf(a);return LANE[a.fam]+(L.length>1?((L.length-1)/2-k)*0.32:0);};
  const won=r.att.find(a=>a.res==='won'), end=won&&won.ack?won.ack.t:null;
  const frame=f=>f==null?'':'<br>pcap frame '+f+' (click for the packet row)';
  function mark(x,y,sym,size,col,filled,txt,pos,hover,f){
    data.push({type:'scatter',mode:txt?'markers+text':'markers',x:[x],y:[y],cliponaxis:false,showlegend:false,
      marker:{symbol:sym,size:size,color:filled?col:C.panel,line:{color:col,width:3}},
      text:txt?[txt]:undefined,textposition:pos||'bottom center',textfont:{size:fs,color:C.ink2},
      customdata:[f==null?null:f],hovertemplate:hover+frame(f)+'<extra></extra>'});xs.push(x);}
  function seg(x0,x1,y,col,w,dash){data.push({type:'scatter',mode:'lines',x:[x0,x1],y:[y,y],showlegend:false,
    hoverinfo:'skip',line:{color:col,width:w,dash:dash||'solid'}});xs.push(x0,x1);}
  // notes flip to the left of their point when it sits in the right part of the axis (see below)
  function note(x,y,txt,o){ann.push(Object.assign({x:x,y:y,xref:'x',yref:'y',text:txt,showarrow:false,
    bgcolor:C.panel,borderpad:2,font:{size:fs,color:C.ink2},_flip:true},o||{}));}
  // lane bands; the oracle lane is set apart because it is derived, not seen on the wire
  shapes.push({type:'rect',xref:'paper',yref:'y',x0:0,x1:1,y0:LANE.orc-0.46,y1:LANE.orc+0.46,layer:'below',
    line:{width:2,color:C.base,dash:'dot'},fillcolor:C.band});
  for(const y of [1.5,2.5])shapes.push({type:'line',xref:'paper',yref:'y',x0:0,x1:1,y0:y,y1:y,layer:'below',
    line:{width:1,color:C.grid}});
  // DNS lane (packet-level): each counted query to its answer
  if(r.dq&&r.dq.length){
    const ans=r.dq.filter(d=>d.a).sort((p,q)=>p.a.t-q.a.t);
    for(const d of r.dq){if(d.a)seg(d.q.t,d.a.t,LANE.dns,C.ink2,4);
      mark(d.q.t,LANE.dns,'square-open',small?9:13,C.ink2,false,'','',
        'DNS query '+esc(d.type)+' at '+signed(d.q.t)+' ms'+PK,d.q.f);
      if(d.a)mark(d.a.t,LANE.dns,'square',small?10:15,C.ink,true,'','',
        'DNS answer '+esc(d.type)+' ('+esc(d.rcode)+(d.answers.length?': '+esc(d.answers.join(', ')):'')+') at '+
        signed(d.a.t)+' ms'+PK,d.a.f);}
    r._dnsAns=ans;
  }
  for(const a of r.att){
    const y=yOf(a), col=a.res==='won'?C[a.fam]:C.grey, who='#'+a.n+' '+fam(a.fam)+', source port '+a.port;
    if(a.res==='won'){
      if(a.ack)seg(a.syn.t,a.ack.t,y,col,small?6:10);
      if(a.synack)mark(a.synack.t,y,'triangle-left',small?10:16,col,true,'','',
        'SYN-ACK for '+who+' at '+signed(a.synack.t)+' ms'+PK,a.synack.f);
      if(a.ack)mark(a.ack.t,y,'diamond',small?16:26,col,true,'','',
        'ACK completing the winning handshake ('+who+') at '+signed(a.ack.t)+' ms = TCP setup time'+PK,a.ack.f);
    }else{
      const stop=a.synack?a.synack.t:(end!=null?end:null);
      if(stop!=null)seg(a.syn.t,stop,y,col,small?3:5,'dot');
      if(a.synack)mark(a.synack.t,y,'triangle-left',small?10:16,col,true,'','',
        'late SYN-ACK for '+who+' at '+signed(a.synack.t)+' ms'+PK,a.synack.f);
      if(a.rst)mark(a.rst.t,y,'x-thin-open',small?12:20,col,false,'','',
        'RST from the '+a.rst.by+' on '+who+' at '+signed(a.rst.t)+' ms'+PK,a.rst.f);
      const why=a.synack?'abandoned: SYN-ACK came at '+signed(a.synack.t)+' ms':'abandoned: no SYN-ACK in the capture';
      note(a.syn.t,y,'#'+a.n+' '+why,{xanchor:'left',yanchor:'bottom',yshift:small?6:10,font:{size:fs,color:C.grey}});
    }
    mark(a.syn.t,y,'circle',small?12:20,col,true,a.res==='won'||r.att.length<3?'SYN':'','bottom center',
      'SYN, attempt '+who+' ('+a.res+') at '+signed(a.syn.t)+' ms'+PK,a.syn.f);
    for(const x of a.rtx_ev||[])mark(x.t,y,'circle-open',small?12:20,col,false,'SYN rtx','bottom center',
      'SYN retransmission, '+who+' at '+signed(x.t)+' ms'+PK,x.f);
    if(a.rtx_ev==null&&a.rtx>0)note(a.syn.t,y,'×'+a.rtx+' SYN retransmits: times need the capture',
      {xanchor:'left',yanchor:'top',yshift:-14});
  }
  // the winning handshake, called out
  // (on a narrow screen the stat cards below carry it instead)
  if(won&&won.ack&&!small)ann.push({x:won.ack.t,y:yOf(won),xref:'x',yref:'y',showarrow:false,xanchor:'left',xshift:22,
    align:'left',text:'<b>'+fam(won.fam)+' wins</b><br>TCP setup '+fmt(won.ack.t)+' ms',font:{size:lab,color:C.ink},
    bgcolor:C.panel,borderpad:3});
  // inter-family attempt delay (packet-level): first SYN of each family
  const firsts=[];for(const a of [...r.att].sort((p,q)=>p.syn.t-q.syn.t))if(!firsts.find(x=>x.fam===a.fam))firsts.push(a);
  if(firsts.length>1){
    const [p,q]=firsts, ym=(LANE[p.fam]+LANE[q.fam])/2;
    for(const a of [p,q])shapes.push({type:'line',xref:'x',yref:'y',x0:a.syn.t,x1:a.syn.t,y0:yOf(a),y1:ym,
      line:{color:C.ink2,width:2,dash:'dot'}});
    ann.push({x:q.syn.t,y:ym,ax:p.syn.t,ay:ym,xref:'x',yref:'y',axref:'x',ayref:'y',showarrow:true,arrowside:'end+start',
      arrowhead:2,arrowsize:1.2,arrowwidth:3,arrowcolor:C.ink,text:''});
    ann.push({x:(p.syn.t+q.syn.t)/2,y:ym,xref:'x',yref:'y',showarrow:false,bgcolor:C.panel,borderpad:2,
      yanchor:'bottom',yshift:small?3:5,
      text:'<b>inter-family delay '+fmt(r.ifd)+' ms</b>',font:{size:lab,color:C.ink}});
  }else if(r.att.length){
    note(firsts[0].syn.t,1.5,'inter-family delay: not observed, '+esc(r.ifd_note||'one family tried'),
      {xanchor:'left',font:{size:fs,color:C.ink2}});
  }
  // oracle lane (derived) and its reference line
  const o=r.orc;
  if(o.setup!=null){
    seg(0,o.setup,LANE.orc,C.ink2,small?8:14);
    data.push({type:'scatter',mode:'markers',x:[o.setup],y:[LANE.orc],showlegend:false,
      marker:{symbol:'line-ns',size:small?18:28,line:{color:C.ink2,width:3}},
      hovertemplate:'oracle setup '+fmt(o.setup)+' ms: '+(r.win?fam(r.win):'')+' RTT from the lab ping before this run'+DV+'<extra></extra>'});
    shapes.push({type:'line',xref:'x',yref:'y',x0:o.setup,x1:o.setup,y0:LANE.orc-0.4,y1:LANE.dns+0.46,
      line:{color:C.ink2,width:3,dash:'dashdot'}});
    note(0,LANE.orc+0.2,'oracle '+fmt(o.setup)+' ms ('+(r.win?fam(r.win):'')+' RTT, lab ping)',
      {xanchor:'left',yanchor:'bottom',bgcolor:C.band,font:{size:fs,color:C.ink}});
    ann.push({x:o.setup,y:1,xref:'x',yref:'paper',yanchor:'bottom',showarrow:false,text:'oracle · derived',
      font:{size:fs,color:C.ink2}});
    xs.push(o.setup);
  }
  if(o.cost!=null&&r.setup!=null){
    data.push({type:'bar',orientation:'h',base:[o.setup],x:[o.cost],y:[LANE.orc],width:[0.34],showlegend:false,
      marker:{color:C.panel,line:{color:C.ink,width:2},pattern:{shape:'/',fgcolor:C.ink2,bgcolor:C.panel,size:small?8:12,solidity:0.25}},
      hovertemplate:'cost of racing '+fmt(o.cost)+' ms = TCP setup '+fmt(r.setup)+' ms (packet-level) − oracle '+fmt(o.setup)+' ms'+DV+'<extra></extra>'});
    shapes.push({type:'line',xref:'x',yref:'y',x0:r.setup,x1:r.setup,y0:LANE.orc-0.3,y1:won?yOf(won):LANE.v4,
      line:{color:won?C[won.fam]:C.ink,width:2}});
    const wide=Math.abs(o.cost)>0.12*(Math.max(...xs)-Math.min(...xs));
    ann.push({x:wide?o.setup+o.cost/2:Math.min(o.setup,r.setup),y:LANE.orc-0.2,xref:'x',yref:'y',
      showarrow:false,_flip:!wide,xanchor:wide?'center':'left',xshift:0,yanchor:'top',
      bgcolor:C.band,borderpad:3,text:'<b>cost of racing '+(o.cost<0?'−':'')+fmt(Math.abs(o.cost))+' ms</b>'+
      (o.single?' · one family: no race':''),font:{size:lab,color:C.ink}});
  }else{
    note(0,LANE.orc,'oracle not available'+(o.note?': '+esc(o.note):''),{xanchor:'left'});
  }
  // DNS summary (packet-level), or where it is when only the record is available
  if(r.dq&&r.dq.length&&r._dnsAns.length){
    const last=r._dnsAns[r._dnsAns.length-1].a.t;
    note(last,LANE.dns,'DNS '+fmt(r.dns,3)+' ms, first query → last answer'+(r._dnsAns.length>1&&
      (last-r._dnsAns[0].a.t)>20?' (answers: '+r._dnsAns.map(d=>esc(d.type)+' '+signed(d.a.t)).join(', ')+' ms)':''),
      {xanchor:'left',yanchor:'bottom',yshift:small?6:12,font:{size:fs,color:C.ink}});
  }else if(r.dns!=null){
    note(0,LANE.dns,'DNS '+fmt(r.dns,3)+' ms (from the record; its position on this axis needs the capture)',
      {xanchor:'left',xshift:6});
  }
  const lo=Math.min(...xs), hi=Math.max(...xs), span=Math.max(hi-lo,10);
  // room right of the winning ACK for its label when the ACK is the rightmost mark
  const rpad=(!small&&won&&won.ack&&hi-won.ack.t<0.2*span)?0.24:0.1;
  const x0=lo-span*0.06, x1=hi+span*rpad;
  for(const a of ann){const flip=a._flip;delete a._flip;
    if(flip&&a.xanchor==='left'&&(a.x-x0)/(x1-x0)>0.5){a.xanchor='right';a.xshift=-Math.abs(a.xshift||0);}}
  const layout={height:small?460:640,margin:{l:small?64:118,r:small?16:36,t:small?34:44,b:small?52:70},
    showlegend:false,hovermode:'closest',barmode:'overlay',dragmode:'zoom',
    font:{family:"system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",size:fs,color:C.ink2},
    paper_bgcolor:C.panel,plot_bgcolor:C.panel,hoverlabel:{bgcolor:C.panel,bordercolor:C.base,font:{color:C.ink,size:fs}},
    xaxis:{title:{text:"ms from the run's first SYN",font:{size:fs,color:C.ink2}},range:[x0,x1],
      gridcolor:C.grid,linecolor:C.base,zeroline:true,zerolinecolor:C.ink2,zerolinewidth:2,tickfont:{size:fs,color:C.ink2}},
    yaxis:{range:[-0.55,3.55],fixedrange:true,showgrid:false,zeroline:false,tickvals:[0,1,2,3],
      ticktext:['<b>Oracle</b><br><i>derived</i>','<b>IPv4</b>','<b>IPv6</b>','<b>DNS</b>'],tickfont:{size:lab,color:C.ink}},
    shapes:shapes,annotations:ann};
  return {data:data,layout:layout};
}
function raceRunLabel(r){return RACE_LABEL[r.cl]+' · '+r.sc+' · r'+String(r.rep).padStart(2,'0');}
function stat(kind,tagText,name,value,sub){return '<div class="stat stat-'+kind+'"><span class="tag tag-'+kind+'">'+tagText+
  '</span><div class=stat-name>'+name+'</div><div class=stat-val>'+value+'</div><div class=stat-sub>'+sub+'</div></div>';}
function raceStats(r){
  const o=r.orc, win=r.win?fam(r.win):'none';
  return stat('packet','Packet-level','TCP setup time',r.setup==null?'–':fmt(r.setup)+' ms','first SYN → ACK completing the winning handshake')+
    stat('packet','Packet-level','Winning family',win,(r.att.length-(r.win?1:0))+' failed or abandoned attempt(s)')+
    stat('packet','Packet-level','Inter-family delay',r.ifd==null?'not observed':fmt(r.ifd)+' ms',
      r.ifd==null?esc(r.ifd_note||''):'second family’s first SYN − first family’s first SYN')+
    stat('packet','Packet-level','DNS time',r.dns==null?'–':fmt(r.dns,3)+' ms','www.hl.test, first query → last answer; not in TCP setup')+
    stat('derived','Derived','Oracle setup',o.setup==null?'not available':fmt(o.setup)+' ms','winning family’s RTT, lab ping before the run')+
    stat('derived','Derived','Cost of racing',o.cost==null?'not available':(o.cost<0?'−':'')+fmt(Math.abs(o.cost))+' ms',
      'TCP setup − oracle'+(o.single?'; one family tried, so no race took place':''));
}
function raceRows(r){
  const box=document.getElementById('race-rows');
  if(!r.rows){
    const ex=RACE.examples.map(id=>'<button type=button class=linkish data-run="'+esc(id)+'">'+esc(raceRunLabel(RACE.runs[id]))+'</button>').join(' ');
    box.innerHTML='<p class=note>'+(r.src==='pcap'?'Events re-read from <code>'+esc(r.capture)+'</code> (SHA-256 matches the record). ':
      '<b>Capture not present on this machine:</b> drawn from the run record alone. ')+
      (ex?'Packet rows are listed for the runs committed in <code>examples/</code>: '+ex:'')+'</p>';
    return;}
  const head='<tr><th>Frame</th><th>ms from first SYN</th><th>Interface</th><th>Dir</th><th>Family</th><th>Source</th><th>Destination</th><th>Packet</th><th>Attempt</th></tr>';
  const body=r.rows.map(x=>'<tr id="pkt-'+x.f+'"'+(x.att?' class="att-'+r.att[x.att-1].fam+'"':'')+'><td>'+x.f+'</td><td>'+signed(x.t)+'</td><td>'+esc(x.if)+
    '</td><td>'+esc(x.dir)+'</td><td>'+(x.fam?fam(x.fam):'')+'</td><td><code>'+esc(x.src)+'</code></td><td><code>'+esc(x.dst)+
    '</code></td><td>'+esc(x.what)+'</td><td>'+(x.att?'#'+x.att+' '+fam(r.att[x.att-1].fam)+' ('+esc(r.att[x.att-1].res)+')':'')+'</td></tr>').join('');
  box.innerHTML='<div class=sec-head><h3>Packet rows behind this chart</h3><span class="tag tag-packet">Packet-level (pcap)</span></div>'+
    '<p class=note>Parsed from <code>'+esc(r.capture)+'</code>; its SHA-256 matches the record. Click a mark in the chart to find its row. '+
    esc(r.rows_note)+' Interface names come from the record’s capture interface map (the capture stores numbers).</p>'+
    '<div class=scroll><table class=pkt>'+head+body+'</table></div>';
}
function raceSelectors(r){
  const s=document.getElementById('race-scn'),c=document.getElementById('race-cl'),n=document.getElementById('race-run');
  s.innerHTML=RACE.scenarios.map(x=>{const any=Object.values(RACE.cells[x])[0][0];
    return '<option value="'+x+'"'+(x===r.sc?' selected':'')+'>'+x+' · '+esc(RACE.runs[any].label)+'</option>';}).join('');
  c.innerHTML=Object.keys(RACE.cells[r.sc]).map(x=>'<option value="'+x+'"'+(x===r.cl?' selected':'')+'>'+RACE_LABEL[x]+'</option>').join('');
  const rep=RACE.representative[r.sc][r.cl];
  n.innerHTML=RACE.cells[r.sc][r.cl].map(id=>{const x=RACE.runs[id];return '<option value="'+esc(id)+'"'+(id===r.id?' selected':'')+'>r'+
    String(x.rep).padStart(2,'0')+' · '+(x.setup==null?'no setup time':fmt(x.setup)+' ms')+(id===rep?' · representative':'')+
    (RACE.examples.includes(id)?' · in examples/':'')+'</option>';}).join('');
}
function drawRace(){
  const el=document.getElementById('race');if(!el)return;
  if(!raceId){el.innerHTML='<p class=note>No runs to draw.</p>';return;}
  const r=RACE.runs[raceId], small=el.clientWidth<720, f=raceFigure(r,mode(),small);
  Plotly.react(el,f.data,f.layout,{displaylogo:false,responsive:true,modeBarButtonsToRemove:['lasso2d','select2d','autoScale2d']});
  el.setAttribute('aria-label','Connection race timeline, '+raceRunLabel(r)+': '+r.att.map(a=>fam(a.fam)+' SYN at '+fmt(a.syn.t)+' ms, '+a.res).join('; ')+
    (r.setup!=null?'; TCP setup '+fmt(r.setup)+' ms':'')+(r.orc.setup!=null?'; oracle (derived) '+fmt(r.orc.setup)+' ms':''));
  if(!raceClickBound){raceClickBound=true;el.on('plotly_click',ev=>{const p=ev.points&&ev.points[0];
    const f=p&&p.customdata;const row=f!=null&&document.getElementById('pkt-'+f);
    if(row){document.querySelectorAll('tr.hit').forEach(t=>t.classList.remove('hit'));row.classList.add('hit');
      row.scrollIntoView({behavior:'smooth',block:'center'});}});}
}
function showRace(id){
  if(!RACE.runs[id])return;raceId=id;const r=RACE.runs[id];
  document.getElementById('race-title').textContent=raceRunLabel(r)+' · '+r.label;
  document.getElementById('race-id').textContent=r.id;
  document.getElementById('race-stats').innerHTML=raceStats(r);
  raceSelectors(r);raceRows(r);drawRace();
  try{history.replaceState(null,'','#run='+encodeURIComponent(id));}catch(e){}
}
function raceInit(){
  const el=document.getElementById('race');if(!el)return;
  const pick=(sc,cl)=>{const cls=RACE.cells[sc];cl=cls[cl]?cl:Object.keys(cls)[0];return RACE.representative[sc][cl];};
  document.getElementById('race-scn').addEventListener('change',e=>showRace(pick(e.target.value,RACE.runs[raceId].cl)));
  document.getElementById('race-cl').addEventListener('change',e=>showRace(pick(RACE.runs[raceId].sc,e.target.value)));
  document.getElementById('race-run').addEventListener('change',e=>showRace(e.target.value));
  document.getElementById('race-section').addEventListener('click',e=>{const b=e.target.closest('[data-run]');if(b)showRace(b.dataset.run);});
  const fs=document.getElementById('race-full');
  if(fs)fs.addEventListener('click',()=>{const s=document.getElementById('race-section');
    if(document.fullscreenElement)document.exitFullscreen();else if(s.requestFullscreen)s.requestFullscreen();});
  document.addEventListener('fullscreenchange',()=>setTimeout(drawRace,50));
  const h=decodeURIComponent((location.hash.match(/^#run=(.+)$/)||[])[1]||'');
  raceId=RACE.runs[h]?h:RACE.default;
  if(raceId)showRace(raceId);else drawRace();
}
raceInit();
draw();
"""


def section(title: str, tags: list[str], note: str, body: str) -> str:
    t = "".join(f"<span class='tag tag-{k}'>{TAG_LABEL[k]}</span>" for k in tags)
    return f"<section><div class=sec-head><h2>{_e(title)}</h2>{t}</div><p class=note>{note}</p>{body}</section>"


def chart(id_: str) -> str:
    return f"<div id={id_} class=chart role=img aria-label='{_e(id_)} chart'></div>"


def race_section(race: dict | None) -> str:
    """The connection race timeline: the dashboard's first section (one run at a time)."""
    tags = "".join(f"<span class='tag tag-{k}'>{TAG_LABEL[k]}</span>" for k in ("packet", "derived"))
    race = race or {}
    ex = "".join(f"<button type=button class=linkish data-run='{_e(i)}'>{_e(_race_label(race['runs'][i]))}</button>"
                 for i in race.get("examples", []))
    default = race.get("default")
    why = _e(race.get("default_why", "no run records were given to the dashboard"))
    jump = (f"<button type=button data-run='{_e(default)}'>Default run</button>" if default else "") + (
        f"<span class=muted>Runs in examples/, with packet rows:</span>{ex}" if ex else "")
    return f"""<section id=race-section aria-labelledby=race-h>
<div class=sec-head><h2 id=race-h>Connection race timeline</h2>{tags}
<button id=race-full type=button title="Show this section full screen">Full screen</button></div>
<div class=race-title id=race-title></div><div class=muted><code id=race-id></code></div>
<div class=race-controls>
<label>Scenario<select id=race-scn></select></label><label>Client<select id=race-cl></select></label>
<label>Run<select id=race-run></select></label><div class=race-jump>{jump}</div></div>
<div id=race class=chart role=img aria-label="Connection race timeline"></div>
<div class=race-key>
<span><b>●</b> SYN &nbsp;<b>○</b> SYN retransmission &nbsp;<b>◀</b> SYN-ACK &nbsp;<b>◆</b> ACK completing the winning
handshake &nbsp;<b>✕</b> RST</span>
<span><b>Coloured:</b> the winning attempt. <b>Grey, dotted:</b> abandoned (drawn to its SYN-ACK, or to the winning
ACK if none came)</span>
<span><b>Oracle lane, dash-dot line, hatched gap:</b> derived, not seen on the wire</span></div>
<p class=note>Every mark in the DNS, IPv6 and IPv4 lanes is a packet in the run's capture, placed at its time from
the run's first SYN (the origin of TCP setup time; DNS comes before it and is measured separately). The oracle is
<b>derived</b>: the winning family's RTT from the lab's ping check before this run. The hatched gap is the cost of
racing (TCP setup minus oracle). <b>Interpretation:</b> the oracle is a hindsight reference; no client knows the
winner in advance. Default: {why}.</p>
<div id=race-stats class=stats></div>
<div id=race-rows></div>
</section>"""


def _race_label(r: dict) -> str:
    return f"{client_label(r['cl'])} · {r['sc']} · r{r['rep']:02d}"


def race_labels(clients) -> dict:
    """Display names for the race view: the implementations plus every client label shown."""
    return {**CLIENT_LABEL, **{c: client_label(c) for c in clients}}


def _clients_text(clients) -> str:
    impls = group_by_implementation(clients)
    variants = [c for c in clients if parse_client(c).variant]
    txt = f"{len(impls)} client implementation(s)"
    if variants:
        txt += (f" ({_e(', '.join(client_label(c) for c in variants))}: configuration variant(s) of curl, "
                "not further clients)")
    return txt


def _lede_scope(ds: dict, clients, scenarios, reps: int, code: str) -> str:
    if "shape" not in ds:  # the core dataset: wording unchanged
        return (f"{ds['runs']} runs: 2 clients × 7 scenarios × 20 repetitions, from the 14 sessions listed in\n"
                f"<code>{_e(ds['source'])}</code> (full matrix, 2026-10-26, code version <code>{_e(code)}</code>).")
    ad = ds["shape"].get("adaptive")
    reps_txt = (f"{ad['min']}–{ad['max']} adaptive repetitions (stop at a 95% CI width of {ad['ci_width_ms']:g} ms)"
                if ad else f"{reps} repetitions")
    return (f"{ds['runs']} runs: {_clients_text(clients)} × {len(scenarios)} scenario(s) ({_e(', '.join(scenarios))}) "
            f"× {reps_txt}, from the {len(ds['sessions'])} sessions listed in <code>{_e(ds['source'])}</code> "
            f"(code version <code>{_e(code)}</code>). Not the core dataset.")


def render(summary: dict, runs: list[Run], plotly_src: str, race: dict | None = None) -> str:
    cells = summary["cells"]
    clients, scenarios = shape_of(cells)
    ds = summary["dataset"]
    shape = ds.get("shape")  # recorded for named datasets; the core dataset has the core shape
    reps = shape["reps"] if shape else EXPECTED_REPS
    figs = {"setup": fig_setup(runs, clients, scenarios), "penalty": fig_penalty(cells),
            "timeline": fig_timeline(runs, clients, scenarios, reps), "inter": fig_inter_family(runs, cells),
            "winner": fig_winner(cells, reps), "dns": fig_dns(runs, clients, scenarios),
            "cost": fig_cost(runs, clients, scenarios)}
    figs_json = json.dumps({k: json.loads(json.dumps(v, cls=plotly.utils.PlotlyJSONEncoder)) for k, v in figs.items()})
    versions = "; ".join(f"{client_label(c)}: {p['versions'][0].split(' (')[0]}" for c, p in ds["clients"].items())
    code = ", ".join(sorted({v for p in ds["clients"].values() for v in p["code_versions"]}))
    body = f"""
<header><div><h1>HappyLab: IPv6/IPv4 fallback measurements</h1>
<p class=lede>{_lede_scope(ds, clients, scenarios, reps, code)} {_e(versions)}.
Times are from packet captures inside an isolated lab; every scenario's RTT was measured before each run.</p>
<div class=legend-row><span class='tag tag-packet'>Packet-level (pcap)</span><span class=muted>seen on the wire</span>
<span class='tag tag-client'>Client log</span><span class=muted>reported by the client (curl, Chromium NetLog)</span>
<span class='tag tag-derived'>Derived</span><span class=muted>pcap timing combined with the lab's pre-run RTT check</span>
<span class='tag tag-interp'>Interpretation</span><span class=muted>our reading of the evidence</span></div></div>
<button id=theme type=button>Theme: auto</button></header>
""" + race_section(race) + section("TCP setup time and scenario penalty", ["packet"],
              "TCP setup time runs from the first SYN to the ACK that completes the winning handshake; DNS is "
              "separate. The penalty is each client's median minus its own C0 median. Every dot is one run.",
              f"<div class=grid2><div>{chart('setup')}</div><div>{chart('penalty')}</div></div>") \
        + section("Connection attempts over time", ["packet"],
                  "Each SYN attempt is plotted at its offset from the run's first SYN, with one row per scenario "
                  "and client and the 20 runs spread vertically. A new attempt to a family already tried uses a "
                  "new source port; kernel SYN retransmissions are not counted as attempts (0 in the dataset). "
                  "The tick marks the ACK that completes the winning handshake. The 250 ms line is a reference "
                  "value from RFC 8305, not a threshold or a prediction.", chart("timeline")) \
        + section("Inter-family attempt delay", ["packet"],
                  "The delay is the second family's first SYN minus the first family's first SYN. Where a run used "
                  "only one family it is <b>not observed</b>; those runs are shown as counts and never averaged as "
                  "zero. Chromium's second IPv6 attempt does not count as the second family.", chart("inter")) \
        + section("Winning family", ["packet"],
                  "The family of the completed handshake that carried the HTTP request.",
                  chart("winner")) \
        + section("DNS time", ["packet"],
                  "From the first query to the last answer for www.hl.test sent before the first SYN (log scale). "
                  "In S6 the AAAA answer was delayed by 300 ms; the delay shows up here, not in TCP setup time, "
                  "so S6 is reported with both.", chart("dns")) \
        + section("Oracle baseline and cost of racing", ["derived"],
                  "Per run, the oracle setup is the measured RTT of the family that eventually won (the lab's "
                  "ping check before that run, not a modelled value), and the cost of racing is the packet-level "
                  "TCP setup time minus it. Values are not clamped: a small negative cost means the handshake "
                  "was faster than the ping median. Runs where it could not be computed are counted, never "
                  "plotted as zero. In single-family runs no race took place. TCP setup excludes DNS, so a "
                  "delayed DNS answer (S6) is not in this value; see DNS time. <b>Interpretation:</b> the oracle "
                  "is what a direct connection to the winning family would have cost in hindsight; no client "
                  "knows the winner in advance, so it is a reference, not a target.",
                  f"{chart('cost')}<div class=scroll>{oracle_table(cells)}</div>") \
        + section("All numbers", ["packet"],
                  "Medians with interquartile range, and a 95% percentile-bootstrap confidence interval on the "
                  "median (10 000 resamples, seed 0): a description of how precisely 20 runs pin the median "
                  "down, not a significance test. No mean or standard deviation is shown. Measured RTT is the pre-run lab check (ping median; "
                  "\"no reply\" means a verified blackhole). Failed/abandoned attempts are counted per run.",
                  f"<div class=scroll>{summary_table(cells)}</div>") \
        + section("What the evidence suggests", ["interp", "packet", "client"],
                  "Each statement below is interpretation. It is built from the counts listed under it; where "
                  "the evidence did not hold in every run, the statement says so. No statement is a claim about "
                  "standards conformance or undocumented client internals.",
                  interpretation_html(summary["interpretation"])) \
        + section("Dataset and client configuration", ["client"],
                  "Versions and settings are recorded in every run record; the values below were the same in all "
                  "runs unless marked.", provenance_html(ds))
    empty = {"runs": {}, "cells": {}, "representative": {}, "scenarios": [], "clients": [], "default": None,
             "examples": []}
    race_json = json.dumps(race or empty, separators=(",", ":")).replace("</", "<\\/")
    js = (JS.replace("__PALETTE__", json.dumps(PALETTE)).replace("__FIGS__", figs_json)
          + RACE_JS.replace("__RACE__", race_json).replace("__LABELS__", json.dumps(race_labels(clients))))
    return (f"<!doctype html><html lang=en-GB><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width, initial-scale=1'><title>HappyLab results</title>"
            f"<style>{CSS}</style>{plotly_src}</head><body><main>{body}</main><script>{js}</script></body></html>")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=CORE_DATASET,
                    help="dataset name: 'core' (docs/dataset.md, the default) or NAME for docs/datasets/NAME.md")
    ap.add_argument("--out", type=Path, default=None,
                    help="output file (default: data/generated/summary/dashboard.html, "
                         "or .../summary/NAME/dashboard.html)")
    ap.add_argument("--cdn", action="store_true", help="load plotly.js from jsDelivr instead of inlining it")
    a = ap.parse_args(argv)
    try:
        _, runs, summary = build(manifest=load_dataset(a.dataset))
        clients, scenarios = shape_of(summary["cells"])
        race = race_mod.build(runs, clients, scenarios, race_mod.load_records(runs))
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    a.out = a.out or out_dir_for(a.dataset) / "dashboard.html"
    ver = get_plotlyjs_version()
    src = (f"<script src='https://cdn.jsdelivr.net/npm/plotly.js-dist-min@{ver}/plotly.min.js'></script>" if a.cdn
           else f"<script>{get_plotlyjs()}</script>")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(render(summary, runs, src, race), encoding="utf-8")
    print(f"wrote {a.out} ({a.out.stat().st_size / 1e6:.1f} MB, {len(runs)} runs, plotly.js {ver})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
