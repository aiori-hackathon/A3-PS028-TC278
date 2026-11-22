---
title: IPv6 latency sweep
description: deterministic IPv6 delay, +100..+400 ms RTT in 25 ms steps for both clients, plus 5 ms steps around each client's packet-measured crossover for that client only
clients: [curl, chromium]
scenarios: [Gv6d100, Gv6d125, Gv6d150, Gv6d175, Gv6d190, Gv6d195, Gv6d200, Gv6d205, Gv6d210, Gv6d215, Gv6d225, Gv6d250, Gv6d275, Gv6d290, Gv6d295, Gv6d300, Gv6d305, Gv6d310, Gv6d315, Gv6d325, Gv6d350, Gv6d375, Gv6d400]
reps: 5
absent_cells: [curl:Gv6d290, curl:Gv6d295, curl:Gv6d305, curl:Gv6d310, curl:Gv6d315, chromium:Gv6d190, chromium:Gv6d195, chromium:Gv6d205, chromium:Gv6d210, chromium:Gv6d215]
---
# IPv6 latency sweep

Deterministic IPv6 delay (generated `Gv6d<N>`, "+N ms RTT": RTT = 20 + N ms, IPv4 at the baseline), 5 repetitions per cell. Coarse cells run +100..+400 in 25 ms steps for both clients. Fine cells run 5 ms steps around each client's packet-measured crossover from the `jitter-loss` dataset, for that client only: curl T = 222.0 ms, so RTT 210-235 ms (+190..+215); Chromium T = 322.5 ms, so RTT 310-335 ms (+290..+315). The other client's fine cells are declared in `absent_cells`. Odd N gives a half ms each way; `src/runner/fractional_delay_check.py` checked it before this campaign (log in `data/generated/lab/`). The purpose is to locate each client's outcome flip to within 5 ms and test the measured T independently of the packet times.

Run on 2026-11-22 with `src/runner/run_campaigns.py` (run_matrix.py --only, --reps 5) from code version `9a6de27` with a clean tree. This is not the core dataset.

## Sessions in the dataset

| # | Client | Scenario | Session | Note |
|---|---|---|---|---|
| 1 | curl | Gv6d100 | `20261122T073736Z` | 5/5 good repetitions, batch check PASS |
| 2 | chromium | Gv6d100 | `20261122T073843Z` | 5/5 good repetitions, batch check PASS |
| 3 | curl | Gv6d125 | `20261122T073955Z` | 5/5 good repetitions, batch check PASS |
| 4 | chromium | Gv6d125 | `20261122T074102Z` | 5/5 good repetitions, batch check PASS |
| 5 | curl | Gv6d150 | `20261122T074214Z` | 5/5 good repetitions, batch check PASS |
| 6 | chromium | Gv6d150 | `20261122T074321Z` | 5/5 good repetitions, batch check PASS |
| 7 | curl | Gv6d175 | `20261122T074434Z` | 5/5 good repetitions, batch check PASS |
| 8 | chromium | Gv6d175 | `20261122T074543Z` | 5/5 good repetitions, batch check PASS |
| 9 | curl | Gv6d190 | `20261122T074656Z` | 5/5 good repetitions, batch check PASS |
| 10 | curl | Gv6d195 | `20261122T074804Z` | 5/5 good repetitions, batch check PASS |
| 11 | curl | Gv6d200 | `20261122T074913Z` | 5/5 good repetitions, batch check PASS |
| 12 | chromium | Gv6d200 | `20261122T075022Z` | 5/5 good repetitions, batch check PASS |
| 13 | curl | Gv6d205 | `20261122T075135Z` | 5/5 good repetitions, batch check PASS |
| 14 | curl | Gv6d210 | `20261122T075243Z` | 5/5 good repetitions, batch check PASS |
| 15 | curl | Gv6d215 | `20261122T075351Z` | 5/5 good repetitions, batch check PASS |
| 16 | curl | Gv6d225 | `20261122T075459Z` | 5/5 good repetitions, batch check PASS |
| 17 | chromium | Gv6d225 | `20261122T075607Z` | 5/5 good repetitions, batch check PASS |
| 18 | curl | Gv6d250 | `20261122T075721Z` | 5/5 good repetitions, batch check PASS |
| 19 | chromium | Gv6d250 | `20261122T075829Z` | 5/5 good repetitions, batch check PASS |
| 20 | curl | Gv6d275 | `20261122T075943Z` | 5/5 good repetitions, batch check PASS |
| 21 | chromium | Gv6d275 | `20261122T080051Z` | 5/5 good repetitions, batch check PASS |
| 22 | chromium | Gv6d290 | `20261122T080206Z` | 5/5 good repetitions, batch check PASS |
| 23 | chromium | Gv6d295 | `20261122T080321Z` | 5/5 good repetitions, batch check PASS |
| 24 | curl | Gv6d300 | `20261122T080436Z` | 5/5 good repetitions, batch check PASS |
| 25 | chromium | Gv6d300 | `20261122T080545Z` | 5/5 good repetitions, batch check PASS |
| 26 | chromium | Gv6d305 | `20261122T080700Z` | 5/5 good repetitions, batch check PASS |
| 27 | chromium | Gv6d310 | `20261122T080813Z` | 5/5 good repetitions, batch check PASS |
| 28 | chromium | Gv6d315 | `20261122T080927Z` | 5/5 good repetitions, batch check PASS |
| 29 | curl | Gv6d325 | `20261122T081041Z` | 5/5 good repetitions, batch check PASS |
| 30 | chromium | Gv6d325 | `20261122T081149Z` | 5/5 good repetitions, batch check PASS |
| 31 | curl | Gv6d350 | `20261122T081303Z` | 5/5 good repetitions, batch check PASS |
| 32 | chromium | Gv6d350 | `20261122T081411Z` | 5/5 good repetitions, batch check PASS |
| 33 | curl | Gv6d375 | `20261122T081525Z` | 5/5 good repetitions, batch check PASS |
| 34 | chromium | Gv6d375 | `20261122T081634Z` | 5/5 good repetitions, batch check PASS |
| 35 | curl | Gv6d400 | `20261122T081748Z` | 5/5 good repetitions, batch check PASS |
| 36 | chromium | Gv6d400 | `20261122T081857Z` | 5/5 good repetitions, batch check PASS |
