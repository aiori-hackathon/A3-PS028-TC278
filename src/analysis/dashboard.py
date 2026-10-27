"""Build the HappyLab dashboard: one standalone HTML page from the dataset in docs/dataset.md.

    .venv/bin/python src/analysis/dashboard.py              # data/generated/summary/dashboard.html (Plotly inline, works offline)
    .venv/bin/python src/analysis/dashboard.py --cdn        # load plotly.js from jsDelivr instead (small file)

Everything shown comes from summarise.build(), which reads only the 14 sessions listed in
docs/dataset.md and refuses an incomplete or unclean session. Each section carries an evidence
label: packet-level (pcap), client log, or interpretation.
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

from analysis.summarise import CLIENTS, OUT_DIR, SCENARIOS, DatasetError, Run, build  # noqa: E402

# Validated with the dataviz palette checker (light and dark surfaces). The v6 aqua is below 3:1
# contrast on the light surface, so families are always named in legends, labels and tables.
PALETTE = {
    "light": {"curl": "#2a78d6", "chromium": "#eb6834", "v6": "#1baf7a", "v4": "#6250d6"},
    "dark": {"curl": "#3987e5", "chromium": "#d95926", "v6": "#199e70", "v4": "#9085e9"},
}
CLIENT_LABEL = {"curl": "curl", "chromium": "Chromium"}
KIND_SYMBOL = {"first": "circle", "same-family": "diamond", "other-family": "square"}
KIND_LABEL = {"first": "first SYN", "same-family": "new attempt, same family", "other-family": "first SYN, other family"}
RFC8305_REFERENCE_MS = 250


def _base_layout(**kw) -> dict:
    layout = dict(margin=dict(l=64, r=16, t=16, b=48), height=380, hovermode="closest",
                  legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, title=None),
                  font=dict(family="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif", size=13))
    layout.update(kw)
    return layout


def _jitter(rep: int, width: float = 0.5) -> float:
    return (rep - 10.5) / 20 * width


def fig_setup(runs: list[Run]) -> dict:
    data = []
    for c in CLIENTS:
        rs = [r for r in runs if r.client == c and r.setup_ms is not None]
        data.append(go.Box(
            x=[r.scenario for r in rs], y=[r.setup_ms for r in rs], name=CLIENT_LABEL[c], meta={"role": c},
            boxpoints="all", jitter=0.5, pointpos=0, marker=dict(size=6, opacity=0.75), line=dict(width=1.5),
            fillcolor="rgba(0,0,0,0)", offsetgroup=c, customdata=[r.run_id for r in rs],
            hovertemplate="%{customdata}<br>TCP setup %{y:.3f} ms<extra>" + CLIENT_LABEL[c] + "</extra>"))
    return {"data": data, "layout": _base_layout(
        boxmode="group", xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(SCENARIOS)),
        yaxis=dict(title=dict(text="TCP setup time (ms)"), rangemode="tozero"))}


def fig_penalty(cells: dict) -> dict:
    data = []
    for c in CLIENTS:
        vals = [cells[c][s]["scenario_penalty_ms"] for s in SCENARIOS]
        data.append(go.Bar(
            x=list(SCENARIOS), y=vals, name=CLIENT_LABEL[c], meta={"role": c}, offsetgroup=c,
            text=[f"{v:.1f}" if v is not None and abs(v) >= 5 else "" for v in vals], textposition="outside",
            hovertemplate="%{x}: %{y:.3f} ms<extra>" + CLIENT_LABEL[c] + " penalty</extra>"))
    return {"data": data, "layout": _base_layout(
        barmode="group", bargap=0.3, bargroupgap=0.08,
        xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(SCENARIOS)),
        yaxis=dict(title=dict(text="Median setup minus own C0 median (ms)"), rangemode="tozero"))}


def timeline_rows() -> list[tuple[str, str]]:
    return [(s, c) for s in SCENARIOS for c in CLIENTS]


def fig_timeline(runs: list[Run]) -> dict:
    rows = timeline_rows()
    index = {row: i for i, row in enumerate(rows)}
    data = []
    for fam in ("v6", "v4"):
        for kind in ("first", "same-family", "other-family"):
            pts = [(r, a) for r in runs for a in r.attempts if a["family"] == fam and a["kind"] == kind]
            if not pts:
                continue
            data.append(go.Scatter(
                x=[a["offset_ms"] for _, a in pts],
                y=[index[(r.scenario, r.client)] + _jitter(r.repetition) for r, _ in pts],
                mode="markers", name=f"IPv{fam[1]} {KIND_LABEL[kind]}", meta={"role": fam},
                marker=dict(symbol=KIND_SYMBOL[kind], size=8, opacity=0.8, line=dict(width=0)),
                customdata=[[r.run_id, a["result"], a["syn_retransmits"]] for r, a in pts],
                hovertemplate=("%{customdata[0]}<br>IPv" + fam[1] + " SYN at +%{x:.3f} ms<br>"
                               "attempt %{customdata[1]}, kernel retransmits %{customdata[2]}<extra></extra>")))
    done = [r for r in runs if r.setup_ms is not None]
    data.append(go.Scatter(
        x=[r.setup_ms for r in done], y=[index[(r.scenario, r.client)] + _jitter(r.repetition) for r in done],
        mode="markers", name="winning handshake complete (ACK)", meta={"role": "ink"},
        marker=dict(symbol="line-ns-open", size=10, line=dict(width=2)),
        customdata=[[r.run_id, r.winner] for r in done],
        hovertemplate="%{customdata[0]}<br>handshake complete at +%{x:.3f} ms (winner %{customdata[1]})"
                      "<extra></extra>"))
    layout = _base_layout(
        height=560, margin=dict(l=120, r=16, t=16, b=48),
        xaxis=dict(title=dict(text="Time from the run's first SYN (ms)"),
                   range=[-10, max((r.setup_ms or 0) for r in runs) + 15], zeroline=False),
        yaxis=dict(tickvals=list(range(len(rows))), ticktext=[f"{s} · {CLIENT_LABEL[c]}" for s, c in rows],
                   autorange="reversed", showgrid=False, zeroline=False),
        shapes=[dict(type="line", xref="x", yref="paper", x0=RFC8305_REFERENCE_MS, x1=RFC8305_REFERENCE_MS,
                     y0=0, y1=1, line=dict(dash="dot", width=1), meta={"role": "muted"})],
        annotations=[dict(x=RFC8305_REFERENCE_MS, y=1, xref="x", yref="paper", yanchor="bottom", showarrow=False,
                          text="250 ms: RFC 8305 suggested attempt delay (reference only)", font=dict(size=11))])
    for i in range(1, len(SCENARIOS)):
        layout["shapes"].append(dict(type="line", xref="paper", yref="y", x0=0, x1=1, y0=2 * i - 0.5,
                                     y1=2 * i - 0.5, line=dict(width=1), meta={"role": "grid"}))
    return {"data": data, "layout": layout}


def fig_inter_family(runs: list[Run], cells: dict) -> dict:
    data, annotations = [], []
    for k, c in enumerate(CLIENTS):
        rs = [r for r in runs if r.client == c and r.inter_family_ms is not None]
        data.append(go.Box(
            x=[r.scenario for r in rs], y=[r.inter_family_ms for r in rs], name=CLIENT_LABEL[c], meta={"role": c},
            boxpoints="all", jitter=0.5, pointpos=0, marker=dict(size=6, opacity=0.75), line=dict(width=1.5),
            fillcolor="rgba(0,0,0,0)", offsetgroup=c, customdata=[r.run_id for r in rs],
            hovertemplate="%{customdata}<br>second family's first SYN +%{y:.3f} ms<extra>" + CLIENT_LABEL[c]
                          + "</extra>"))
        for s in SCENARIOS:
            inter = cells[c][s]["inter_family"]
            if inter["not_observed"]:
                annotations.append(dict(
                    x=s, y=0, xref="x", yref="y", yanchor="bottom", xshift=(-1 if k == 0 else 1) * 17,
                    showarrow=False, textangle=-90, font=dict(size=11),
                    text=f"{CLIENT_LABEL[c]}: not observed ×{inter['not_observed']}"))
    # annotations are placed against an empty-but-ranged axis, so make sure every category exists
    data.append(go.Scatter(x=list(SCENARIOS), y=[None] * len(SCENARIOS), showlegend=False, hoverinfo="skip"))
    return {"data": data, "layout": _base_layout(
        boxmode="group", annotations=annotations,
        xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(SCENARIOS)),
        yaxis=dict(title=dict(text="Inter-family attempt delay (ms)"), range=[0, 360]))}


def fig_winner(cells: dict) -> dict:
    rows = timeline_rows()
    labels = [f"{s} · {CLIENT_LABEL[c]}" for s, c in rows]
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
        xaxis=dict(title=dict(text="Runs"), range=[0, 20], dtick=5),
        yaxis=dict(autorange="reversed", showgrid=False))}


def fig_dns(runs: list[Run]) -> dict:
    data = []
    for c in CLIENTS:
        rs = [r for r in runs if r.client == c and r.dns_ms is not None]
        data.append(go.Box(
            x=[r.scenario for r in rs], y=[r.dns_ms for r in rs], name=CLIENT_LABEL[c], meta={"role": c},
            boxpoints="all", jitter=0.5, pointpos=0, marker=dict(size=6, opacity=0.75), line=dict(width=1.5),
            fillcolor="rgba(0,0,0,0)", offsetgroup=c, customdata=[r.run_id for r in rs],
            hovertemplate="%{customdata}<br>DNS time %{y:.3f} ms<extra>" + CLIENT_LABEL[c] + "</extra>"))
    return {"data": data, "layout": _base_layout(
        boxmode="group", xaxis=dict(title=dict(text="Scenario"), categoryorder="array", categoryarray=list(SCENARIOS)),
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


def summary_table(cells: dict) -> str:
    head = ("<tr><th>Scenario</th><th>Client</th><th>Measured RTT, ms <span class=src>lab verify</span></th>"
            "<th>Runs / success</th><th>Winner</th><th>Setup median [IQR], ms</th><th>Range, ms</th>"
            "<th>Penalty, ms</th><th>Inter-family delay</th><th>Failed / abandoned per run</th>"
            "<th>Attempt shape</th><th>DNS median, ms</th></tr>")
    body = []
    for s in SCENARIOS:
        for c in CLIENTS:
            x = cells[c][s]
            st, inter = x["tcp_setup_ms"], x["inter_family"]
            io = inter["stats_over_observed_only"]
            inter_txt = (f"observed {inter['observed']}, not observed {inter['not_observed']}"
                         + (f"<br>median {io['median']} [{io['q1']}–{io['q3']}]" if io else ""))
            fa = ", ".join(f"{k} attempts ×{v}" for k, v in x["failed_or_abandoned_per_run"].items())
            body.append(
                f"<tr><td><b>{s}</b><br><span class=muted>{_e(x['label'])}</span></td><td>{CLIENT_LABEL[c]}</td>"
                f"<td>{_rtt(x)}</td><td>{x['n']} / {x['successes']}</td>"
                f"<td>{_counts(x['winning_family'], lambda k: 'IPv' + k[1] if k.startswith('v') else k)}</td>"
                f"<td>{st['median']} [{st['q1']}–{st['q3']}]</td><td>{st['min']}–{st['max']}</td>"
                f"<td>{x['scenario_penalty_ms']:.3f}</td><td>{inter_txt}</td><td>{fa}</td>"
                f"<td>{_counts(x['attempt_shape'], lambda k: k.replace('>', ' → '))}</td>"
                f"<td>{x['dns_ms']['median'] if x['dns_ms'] else '-'}</td></tr>")
    return f"<table>{head}{''.join(body)}</table>"


def interpretation_html(items: list[dict]) -> str:
    out = []
    for it in items:
        ev = "".join(f"<li><span class='tag tag-{'packet' if e['source'] == 'packet' else 'client'}'>"
                     f"{'Packet-level' if e['source'] == 'packet' else 'Client log'}</span> {_e(e['text'])}</li>"
                     for e in it["evidence"])
        out.append(f"<article class='interp'><div class=interp-head><span class='tag tag-interp'>Interpretation"
                   f"</span><h3>{_e(it['topic'])}</h3></div><p>{_e(it['statement'])}</p>"
                   f"<details><summary>Evidence it rests on</summary><ul>{ev}</ul>"
                   f"<p class=muted>See {_e(it['reference'])}</p></details></article>")
    return "".join(out)


def provenance_html(ds: dict) -> str:
    sess = "".join(f"<tr><td>{x['scenario']}</td><td>{CLIENT_LABEL[x['client']]}</td><td><code>{x['session']}"
                   f"</code></td></tr>" for x in ds["sessions"])
    clients = []
    for c, p in ds["clients"].items():
        cfg = p["configs"][0] if len(p["configs"]) == 1 else p["configs"]
        keep = {k: v for k, v in cfg.items() if k in ("happy_eyeballs_timeout_ms", "happy_eyeballs", "resolver",
                                                     "headless_mode", "quic", "secure_dns", "https_upgrades",
                                                     "playwright_version", "browser_per_run", "url")}
        rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in keep.items())
        clients.append(f"<h3>{CLIENT_LABEL[c]}</h3><p><code>{_e('; '.join(p['versions']))}</code><br>"
                       f"code version {_e(', '.join(p['code_versions']))}"
                       f"{' (configs differ between runs)' if len(p['configs']) > 1 else ''}</p>"
                       f"<table class=kv>{rows}</table>")
    return (f"<div class=grid2><div><h3>Sessions ({ds['runs']} runs, from {_e(ds['source'])})</h3>"
            f"<table class=compact><tr><th>Scenario</th><th>Client</th><th>Session</th></tr>{sess}</table></div>"
            f"<div>{''.join(clients)}</div></div>")


CSS = """
:root{--surface:#fcfcfb;--panel:#ffffff;--text:#0b0b0b;--text-2:#52514e;--muted:#898781;--grid:#e1e0d9;
--base:#c3c2b7;--border:#e1e0d9;--interp-bg:#f6f5f1}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--surface:#1a1a19;--panel:#222221;--text:#f0efec;
--text-2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--base:#383835;--border:#2c2c2a;--interp-bg:#262624}}
:root[data-theme="dark"]{--surface:#1a1a19;--panel:#222221;--text:#f0efec;--text-2:#c3c2b7;--muted:#898781;
--grid:#2c2c2a;--base:#383835;--border:#2c2c2a;--interp-bg:#262624}
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
.tag-interp{border-style:dotted;font-style:italic}
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
  Plotly.react(id,f.data,f.layout,{displaylogo:false,responsive:true,modeBarButtonsToRemove:['lasso2d','select2d']});}}
function cycleTheme(){const r=document.documentElement;const order=['auto','light','dark'];
  const cur=r.dataset.theme||'auto';const next=order[(order.indexOf(cur)+1)%3];
  if(next==='auto')delete r.dataset.theme;else r.dataset.theme=next;
  document.getElementById('theme').textContent='Theme: '+next;draw();}
matchMedia('(prefers-color-scheme: dark)').addEventListener('change',draw);
document.getElementById('theme').addEventListener('click',cycleTheme);
draw();
"""


def section(title: str, tags: list[str], note: str, body: str) -> str:
    t = "".join(f"<span class='tag tag-{k}'>{ {'packet': 'Packet-level (pcap)', 'client': 'Client log', 'interp': 'Interpretation'}[k]}</span>"
                for k in tags)
    return f"<section><div class=sec-head><h2>{_e(title)}</h2>{t}</div><p class=note>{note}</p>{body}</section>"


def chart(id_: str) -> str:
    return f"<div id={id_} class=chart role=img aria-label='{_e(id_)} chart'></div>"


def render(summary: dict, runs: list[Run], plotly_src: str) -> str:
    cells = summary["cells"]
    figs = {"setup": fig_setup(runs), "penalty": fig_penalty(cells), "timeline": fig_timeline(runs),
            "inter": fig_inter_family(runs, cells), "winner": fig_winner(cells), "dns": fig_dns(runs)}
    figs_json = json.dumps({k: json.loads(json.dumps(v, cls=plotly.utils.PlotlyJSONEncoder)) for k, v in figs.items()})
    ds = summary["dataset"]
    versions = "; ".join(f"{CLIENT_LABEL[c]}: {p['versions'][0].split(' (')[0]}" for c, p in ds["clients"].items())
    code = ", ".join(sorted({v for p in ds["clients"].values() for v in p["code_versions"]}))
    body = f"""
<header><div><h1>HappyLab: IPv6/IPv4 fallback measurements</h1>
<p class=lede>{ds['runs']} runs: 2 clients × 7 scenarios × 20 repetitions, from the 14 sessions listed in
<code>{_e(ds['source'])}</code> (full matrix, 2026-10-26, code version <code>{_e(code)}</code>). {_e(versions)}.
Times are from packet captures inside an isolated lab; every scenario's RTT was measured before each run.</p>
<div class=legend-row><span class='tag tag-packet'>Packet-level (pcap)</span><span class=muted>seen on the wire</span>
<span class='tag tag-client'>Client log</span><span class=muted>reported by the client (curl, Chromium NetLog)</span>
<span class='tag tag-interp'>Interpretation</span><span class=muted>our reading of the evidence</span></div></div>
<button id=theme type=button>Theme: auto</button></header>
""" + section("TCP setup time and scenario penalty", ["packet"],
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
        + section("All numbers", ["packet"],
                  "Medians with interquartile range. Measured RTT is the pre-run lab check (ping median; "
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
    js = JS.replace("__PALETTE__", json.dumps(PALETTE)).replace("__FIGS__", figs_json)
    return (f"<!doctype html><html lang=en-GB><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width, initial-scale=1'><title>HappyLab results</title>"
            f"<style>{CSS}</style>{plotly_src}</head><body><main>{body}</main><script>{js}</script></body></html>")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=OUT_DIR / "dashboard.html")
    ap.add_argument("--cdn", action="store_true", help="load plotly.js from jsDelivr instead of inlining it")
    a = ap.parse_args(argv)
    try:
        _, runs, summary = build()
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    ver = get_plotlyjs_version()
    src = (f"<script src='https://cdn.jsdelivr.net/npm/plotly.js-dist-min@{ver}/plotly.min.js'></script>" if a.cdn
           else f"<script>{get_plotlyjs()}</script>")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(render(summary, runs, src), encoding="utf-8")
    print(f"wrote {a.out} ({a.out.stat().st_size / 1e6:.1f} MB, {len(runs)} runs, plotly.js {ver})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
