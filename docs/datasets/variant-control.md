---
title: curl@he200 validation control
description: plain curl and curl@he200 on S1, back to back on one lab bring-up (kernel 7.0.0-43)
clients: [curl, curl@he200]
scenarios: [S1]
reps: 20
---
# curl@he200 validation control

Plain curl and curl with an explicit `--happy-eyeballs-timeout-ms 200` (curl's documented
default), on S1, measured back to back on 2026-11-21. Both sessions were run with
`run_matrix.py --only` from code version `72be111` (on main) with a clean tree, on kernel
7.0.0-43-generic and curl 8.5.0. The comparison is made by `src/analysis/variant_control.py`;
see [`docs/client_variants.md`](../client_variants.md). This is not the core dataset.

## Sessions in the dataset

| # | Client | Scenario | Session | Note |
|---|---|---|---|---|
| 1 | curl | S1 | `20261121T171100Z` | 20/20 good repetitions, batch check PASS |
| 2 | curl@he200 | S1 | `20261121T171558Z` | 20/20 good repetitions, batch check PASS |

## Notes

The two sessions ran one after the other (plain curl first), not in one orchestrator session:
a session runs one client.
