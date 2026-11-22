---
title: curl Happy Eyeballs timeout sweep
description: plain curl and curl@he50..he500 on C0, S1 and S3, 10 repetitions; curl@he200 against plain curl is the validation control
clients: [curl, curl@he50, curl@he100, curl@he150, curl@he200, curl@he250, curl@he300, curl@he400, curl@he500]
scenarios: [C0, S1, S3]
reps: 10
---
# curl Happy Eyeballs timeout sweep

Plain curl and eight curl variants with an explicit `--happy-eyeballs-timeout-ms` (50, 100, 150, 200, 250, 300, 400, 500) on C0, S1 and S3, 10 repetitions per cell. curl@he200 sets curl's documented default explicitly and is compared with plain curl as the validation control (see [`docs/client_variants.md`](../client_variants.md)). S2 is left out: it was within 0.04 ms of S1 in the core data. A variant is a configuration of curl, not another client.

Run on 2026-11-22 from code version `9a6de27` with a clean tree, in two parts: `src/runner/run_campaigns.py` (run_matrix.py --only, --reps 10) ran the first 7 C0 batches (matrix `20261122T082011Z`); after the interruption below, `run_matrix.py --only <the remaining 20 cells> --reps 10` ran the other 20 (sessions `20261122T091923Z`..`20261122T100330Z`). This is not the core dataset.

## Sessions in the dataset

| # | Client | Scenario | Session | Note |
|---|---|---|---|---|
| 1 | curl | C0 | `20261122T082011Z` | 10/10 good repetitions, batch check PASS |
| 2 | curl@he50 | C0 | `20261122T082218Z` | 10/10 good repetitions, batch check PASS |
| 3 | curl@he100 | C0 | `20261122T082425Z` | 10/10 good repetitions, batch check PASS |
| 4 | curl@he150 | C0 | `20261122T082632Z` | 10/10 good repetitions, batch check PASS |
| 5 | curl@he200 | C0 | `20261122T082839Z` | 10/10 good repetitions, batch check PASS |
| 6 | curl@he250 | C0 | `20261122T083046Z` | 10/10 good repetitions, batch check PASS |
| 7 | curl@he300 | C0 | `20261122T083253Z` | 10/10 good repetitions, batch check PASS |
| 8 | curl@he400 | C0 | `20261122T091923Z` | 10/10 good repetitions, batch check PASS |
| 9 | curl@he500 | C0 | `20261122T092129Z` | 10/10 good repetitions, batch check PASS |
| 10 | curl | S1 | `20261122T092336Z` | 10/10 good repetitions, batch check PASS |
| 11 | curl@he50 | S1 | `20261122T092605Z` | 10/10 good repetitions, batch check PASS |
| 12 | curl@he100 | S1 | `20261122T092833Z` | 10/10 good repetitions, batch check PASS |
| 13 | curl@he150 | S1 | `20261122T093101Z` | 10/10 good repetitions, batch check PASS |
| 14 | curl@he200 | S1 | `20261122T093329Z` | 10/10 good repetitions, batch check PASS |
| 15 | curl@he250 | S1 | `20261122T093559Z` | 10/10 good repetitions, batch check PASS |
| 16 | curl@he300 | S1 | `20261122T093829Z` | 10/10 good repetitions, batch check PASS |
| 17 | curl@he400 | S1 | `20261122T094059Z` | 10/10 good repetitions, batch check PASS |
| 18 | curl@he500 | S1 | `20261122T094330Z` | 10/10 good repetitions, batch check PASS |
| 19 | curl | S3 | `20261122T094602Z` | 10/10 good repetitions, batch check PASS |
| 20 | curl@he50 | S3 | `20261122T094814Z` | 10/10 good repetitions, batch check PASS |
| 21 | curl@he100 | S3 | `20261122T095023Z` | 10/10 good repetitions, batch check PASS |
| 22 | curl@he150 | S3 | `20261122T095232Z` | 10/10 good repetitions, batch check PASS |
| 23 | curl@he200 | S3 | `20261122T095444Z` | 10/10 good repetitions, batch check PASS |
| 24 | curl@he250 | S3 | `20261122T095655Z` | 10/10 good repetitions, batch check PASS |
| 25 | curl@he300 | S3 | `20261122T095907Z` | 10/10 good repetitions, batch check PASS |
| 26 | curl@he400 | S3 | `20261122T100118Z` | 10/10 good repetitions, batch check PASS |
| 27 | curl@he500 | S3 | `20261122T100330Z` | 10/10 good repetitions, batch check PASS |

## Notes

- **Excluded session `20261122T083500Z` (curl@he400, C0).** The host laptop suspended during it: the lid was closed at 08:37:02 UTC and the journal shows `PM: suspend entry`; it resumed at 09:11:53 UTC. r01-r09 have run records; r10 has a pcap and a log but no record, because its post-run `verify.sh` hit the orchestrator's 120 s subprocess timeout after resume and the orchestrator stopped (netem was restored). A manifest takes one session per cell, so the cell was re-run whole as `20261122T091923Z`; none of the 9 records from `20261122T083500Z` is in this dataset.
- **Host default route.** The campaign chain's final baseline verify, right after resume while the host Wi-Fi was reconnecting, failed one check only: "host: IPv4 default route missing". This is a host-side artefact. The check exists to confirm the lab has not touched the host; the lab's traffic stays inside the `hl-` namespaces and their veths and never uses the host's Wi-Fi interface. Every run in this dataset passed the full verify, host checks included, before and after it.
- Every one of the 27 sessions has 10 run records, all from code `9a6de27`.
