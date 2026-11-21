# Dataset manifests

[`docs/dataset.md`](../dataset.md) is the **core dataset**, the 14 sessions (2 clients × C0–S6 ×
20 repetitions, 2026-10-26) that the report, dashboard and website are built from. It is frozen: it
has no header, and its shape is fixed in `src/analysis/summarise.py` (`CORE_SHAPE`).

Any further dataset, for example one with a new scenario added to `src/config/scenarios.yaml`, gets
its own manifest here as `docs/datasets/<name>.md`. Names use lower-case letters, digits, `-` and `_`.
No manifest is committed yet: one is added only when its sessions have been run and checked.

## Format

A YAML header declaring the shape, then the same session table as the core dataset:

```markdown
---
title: Example extra scenario          # optional
description: what this dataset is for  # optional
clients: [curl, chromium]              # required: curl, chromium, or a curl variant such as curl@he200
scenarios: [C0, X1]                    # required, each defined in scenarios.yaml or scenarios_generated.yaml
reps: 20                               # required, repetitions per session (at least 1)
# or, for sessions run with --reps-adaptive MIN MAX --ci-width-ms W:
# reps: {min: 10, max: 20, ci_width_ms: 0.5}
---
# Example extra scenario

## Sessions in the dataset

| # | Client | Scenario | Session | Note |
|---|---|---|---|---|
| 1 | curl | C0 | `20261201T100000Z` | ... |
| 2 | chromium | C0 | `20261201T100500Z` | ... |
| 3 | curl | X1 | `20261201T101000Z` | ... |
| 4 | chromium | X1 | `20261201T101500Z` | ... |
```

(The session IDs above are placeholders that show the format; they are not real sessions.)

## What is checked (`summarise.load_manifest` and `load_runs`)

The manifest is checked against its own declared shape, and its runs against the manifest:

- The header must exist and have `clients`, `scenarios` and `reps`, with no other keys apart from
  `title` and `description`.
- Every client must be one the analysis knows: `curl`, `chromium`, or a curl variant `curl@he<N>`
  (`analysis.names.parse_client`). A variant is listed as its own client column in the table, but
  summaries and the dashboard group it under curl; its scenario penalty uses its own C0.
- Every scenario must be defined in `scenarios.yaml` or the generated `scenarios_generated.yaml`
  (`src/analysis/scenario_config.py` reads both).
- The table must have exactly one session per declared client × scenario. A missing, duplicated
  or undeclared cell, or a row that cannot be read, is refused.
- With adaptive `reps`, each session must hold between `min` and `max` records, repetitions 1..n,
  each with an `adaptive` block whose settings match the header, `continue` on every run but the
  last and `stop` on the last. The stopping rule is recomputed from the setup times and must give
  the same decisions; a session that ran past its stop, or was edited afterwards, is refused.
- Otherwise each session must have exactly `reps` records, repetitions 1..`reps` each once, the right client
  and scenario, cross-checks `agree`, and lab verify passed before and after every run. For S6, the
  pcap hash must also match the record.

Any failure stops the run with an error. Nothing is skipped or filled in.

## Using a manifest

```
.venv/bin/python src/analysis/summarise.py --dataset <name>    # data/generated/summary/<name>/
.venv/bin/python src/analysis/dashboard.py --dataset <name>    # data/generated/summary/<name>/dashboard.html
.venv/bin/python src/analysis/export_web.py --dataset <name> --page <copy of web/index.html>
```

- **Without `--dataset`:** every command uses the core dataset and writes where it always has.
- **Output folder:** a named dataset writes to its own folder and never overwrites the core output.
- **`export_web.py`:** never writes a named dataset into `web/index.html`, which shows the core
  dataset only. Every scenario in the dataset must already exist on the page given with `--page`.
- **Scenario penalty:** it is the client's median minus its own C0 median *in the same dataset*.
  If a manifest has no C0, the penalty is reported as not available ("no C0 in this dataset"). It
  is never borrowed from the core dataset. To compare against the core baseline, list the core C0
  session in the manifest.
- **Interpretation statements:** those in `summarise.interpretations()` are written for the core
  scenarios. Each one appears only when the scenarios it rests on are in the dataset for both clients.
