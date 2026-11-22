# Comparison figures (P9)

These are the comparison figures for the report and the deck, ready to drop in. They present
results already established in [`docs/findings/`](../findings/) and the dataset manifests, and add
no new claim. Do not re-plot them; regenerate them from the script below.

All 11 figures are written twice:
- **SVG**, the vector original;
- **PNG** at 300 dpi.

`figures_data.json` holds every number the figures plot.

## Regenerate

```
.venv/bin/python src/analysis/figures.py            # render all SVG + PNG, rewrite figures_data.json
.venv/bin/python src/analysis/figures.py --check    # exit 1 if figures_data.json no longer matches the data
.venv/bin/python src/analysis/figures.py --data-only
```

- Rendering uses Plotly in Playwright's headless Chromium, started with `child_env()`. No new
  dependency was added.
- Re-rendering gives byte-identical files.

## Files

| File stem | PNG size | Slide use | Contents |
|---|---|---|---|
| `fig1_ipv6_latency_budget_full` | 3300 × 1875 | full slide | IPv6 win fraction against IPv6 RTT for both clients, plus TCP setup against the oracle |
| `fig1_ipv6_latency_budget_curl_half` | 1650 × 1875 | half slide | curl outcome panel only |
| `fig1_ipv6_latency_budget_chromium_half` | 1650 × 1875 | half slide | Chromium outcome panel only |
| `fig1_setup_vs_oracle_half` | 1650 × 1875 | half slide | TCP setup against the oracle, both clients |
| `fig2_he_linearity_full` | 3300 × 1875 | full slide | curl T against `--happy-eyeballs-timeout-ms`, with a residual panel |
| `fig2_he_linearity_half` | 1650 × 1875 | half slide | the same, with a compact legend |
| `fig3_claims_core_full` | 3300 × 1875 | full slide | claims resting on the frozen core dataset (satisfies PS-028) |
| `fig3_claims_extensions_full` | 3300 × 1875 | full slide | claims resting on the extension campaigns (beyond PS-028) |
| `fig3_claims_table_report` | 3300 × 3900 | report page | both sections in one table |
| `fig4_t_reproducibility_full` | 3300 × 1875 | full slide | plain curl's T in four campaigns |
| `fig4_t_reproducibility_half` | 1650 × 1875 | half slide | the same |

**Styling:**
- Light background, dark text, large type, and lines of 4 px or wider.
- curl is blue circles and Chromium is orange triangles. Shape always repeats colour, so no
  distinction relies on colour alone.

## Evidence tags

Every legend groups its entries under the dashboard's four tags. A test keeps these identical to
`dashboard.TAG_LABEL`.

| Tag | Line style | Used for |
|---|---|---|
| Packet-level (pcap) | filled markers, solid lines, shaded bands | win fractions, T, flip brackets, TCP setup, residuals |
| Client log | table only | HTTP status, Chromium NetLog `backup_job` |
| Derived (pcap − lab RTT) | dashed | oracle setup time (figure 1) |
| Interpretation | dotted | jitter model Φ((T − μ)/σ); reference timeout + IPv4 handshake |

he150 is shown as **"BOUNDARY CASE, NOT A FINDING"** (italic, shaded row) in the claims tables.
It does not appear as a result anywhere else.

## Sources and notes for each figure

**Figure 1, IPv6 latency budget.**
- Sources:
  - sweep cells, flip brackets and T: `crossover.latency_sweep` on `latency-sweep`;
  - jitter cells, Wilson intervals and the model: `jitter_model.analyse` on `jitter-loss`
    (Gv6j cells only).
- **Sweep points** have 5 runs per cell and carry no interval. Every cell went 5/5 or 0/5, so
  each panel and the legend label them "n=5, unanimous". The script checks this before rendering:
  `sweep_n_unanimous` refuses to draw the label if any cell is mixed or the n differs.
- **Jitter cells** show 95% Wilson intervals.
- **The oracle** is a setup time, not an outcome, so it cannot sit on the win-fraction axis. It
  has its own panel, TCP setup against the oracle.
  - Values: `summarise.build` output for `latency-sweep`, `oracle_setup_ms` where
    `oracle_status == "computed"`. That is all 180 runs.
  - The result it shows is stated in the findings: see "Oracle baseline" under the latency sweep
    in [`latency_and_he_sweeps.md`](../findings/latency_and_he_sweeps.md).
- **Two T values, each labelled with its campaign:**
  - the flip annotation and the T line use the latency-sweep T: 221.84 / 321.99 ms;
  - the model curve uses the jitter-loss T: 221.96 / 322.47 ms.

**Figure 2, he-sweep linearity.**
- Source: `crossover.he_sweep` on `he-sweep`, S1, medians of 10.
- Every residual is printed under its timeout. There is no fit or smoothing.
- The two shaded boxes mark the ranges +0.69 to +0.90 ms (he50–he250) and +1.16 to +1.99 ms
  (he300–he500). he400 sits below both he300 and he500, and is drawn where it falls.
- Plain curl has no timeout flag. Its star is placed at x = 200, curl's documented default, and
  labelled as placed there.

**Figure 3, claims table.**
- The extension rows' numbers come from the data at render time.
- The core rows are built from `CORE_FACTS` in `figures.py`, and a test pins `CORE_FACTS` to the
  data. `test_core_rows_match_summarise_on_the_frozen_dataset` runs `summarise.build()` on the
  frozen core dataset (`docs/dataset.md`) and recomputes every number with `core_facts()`. It also
  counts HTTP 200 in the run records. If either the data or the table changes, the test fails.
  Editing `report.md` cannot move the table.
- That test needs the frozen run records in `data/generated/runs/`, which are not committed. It
  is skipped, with a stated reason, on a machine without them.
- The combined table has 16 rows and is legible only at report-page size. For slides, use the
  two split tables.

**Figure 4, T reproducibility.**
- Source: per-run T from each campaign's sessions: variant-control, jitter-loss twins,
  latency-sweep and he-sweep S1.
- Labelled as reproducing across campaigns and code versions on one host and one kernel
  (7.0.0-43-generic), not across hosts or kernels.
- **Precision.** T is shown to two decimal places in every figure and in the findings text,
  always with its campaign:
  - variant-control 221.53;
  - jitter-loss 221.96;
  - latency-sweep 221.84;
  - he-sweep 222.14 ms.
- These are the same quantity measured in four campaigns.
- Values are rounded half-up from the stored three-decimal medians, so 222.135 prints as
  222.14.

**Dataset count.** The claims table and figure 4 draw on **four** extension datasets:
- variant-control;
- jitter-loss;
- latency-sweep;
- he-sweep.

variant-control contributes only the first T measurement.
