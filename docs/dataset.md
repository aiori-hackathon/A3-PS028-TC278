# Measurement dataset: full matrix, 2026-10-26

The full matrix was run with `src/runner/run_matrix.py`: 7 scenarios × 2 clients × 20 repetitions,
one batch at a time, code version `ecba28c`.
- Output folder: `data/generated/lab/20261026T192045Z_matrix/` (`matrix.log` and one output file per batch).
- Duration: 64.6 minutes. All 14 batches exited 0 and passed the batch check.
- The checks were re-run independently on 2026-10-27 with `src/analysis/check_batch.py`, and all passed:
  - 20 records and 20 pcaps per batch
  - repetitions 1–20, each exactly once
  - pcap hashes present and matching
  - lab verify passed before and after every run
  - cross_checks agree everywhere
  - no `-dirty` code version

## Sessions in the dataset (280 runs)

| # | Client | Scenario | Session | Median TCP setup (ms) |
|---|---|---|---|---|
| 1 | curl | C0 | `20261026T192045Z` | 20.697 |
| 2 | chromium | C0 | `20261026T192457Z` | 20.135 |
| 3 | curl | S1 | `20261026T192924Z` | 222.221 |
| 4 | chromium | S1 | `20261026T193419Z` | 322.392 |
| 5 | curl | S2 | `20261026T193931Z` | 222.188 |
| 6 | chromium | S2 | `20261026T194358Z` | 321.986 |
| 7 | curl | S3 | `20261026T194840Z` | 171.171 |
| 8 | chromium | S3 | `20261026T195259Z` | 171.109 |
| 9 | curl | S4 | `20261026T195733Z` | 20.715 |
| 10 | chromium | S4 | `20261026T200224Z` | 20.139 |
| 11 | curl | S5 | `20261026T200731Z` | 20.697 |
| 12 | chromium | S5 | `20261026T201154Z` | 20.139 |
| 13 | curl | S6 | `20261026T201633Z` | 20.812 |
| 14 | chromium | S6 | `20261026T202049Z` | 21.317 |

The medians are a quick check from the records (packet-level TCP setup time), not the analysis.
Scenario penalties and other summaries come from the analysis step.

## Not in the dataset (kept on disk, unchanged)

- **curl C0, session `20261026T190919Z`** (`data/generated/lab/20261026T190919Z_matrix/`). A standalone curl C0 batch run about 11 minutes
  before the full matrix, with the same code version. It is complete and clean: 20/20, check PASS,
  median TCP setup 20.681 ms.
  - **Decision (Sam, 2026-10-27):** the dataset uses the full-matrix run (`20261026T192045Z`), so
    every cell comes from the same unattended run.
  - `20261026T190919Z` may be reported only as a repeatability check for curl C0. It is not pooled
    into the baseline.
- **Pilot sessions:** curl `20261026T064544Z` and `20261026T074423Z`; Chromium `20261026T123827Z`,
  `20261026T125239Z`, `20261026T181302Z` and `20261026T182411Z`. They ran on earlier code
  versions (or with uncommitted changes) and with 1–3 repetitions; they validated the pipeline
  and are not measurement data. `20261026T123827Z` ran with a known-bad Chromium launch
  configuration; see `findings/chromium_s1_second_v6_syn.md`.
