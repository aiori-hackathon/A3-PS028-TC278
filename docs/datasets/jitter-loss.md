---
title: IPv6 partial loss and jitter extension
description: generated extension scenarios (IPv6 loss 10/30/50 %, IPv6 jitter 50/70 ms with delay twins, IPv4 blackhole plus IPv6 30 % loss), adaptive 20-50 repetitions
clients: [curl, chromium]
scenarios: [Gv6l10, Gv6l30, Gv6l50, Gv6j50, Gv6j70, Gv6d200, Gv6d280, Gv6c30]
reps: {min: 20, max: 50, ci_width_ms: 25, win_ci_width: 0.3}
---
# IPv6 partial loss and jitter extension

Eight generated extension scenarios (`src/config/scenario_grid.yaml` →
`src/config/scenarios_generated.yaml`) for curl and Chromium, measured on 2026-11-21/22 with
`run_matrix.py --only` from code version `c283448` (on main) with a clean tree. Repetitions are
adaptive: at least 20 and at most 50 per session. A session stops early only when the bootstrap 95 %
CI of the median TCP setup time is at most 25 ms wide (no-winner runs ranked highest) **and** the
Wilson 95 % CI of the IPv6 win fraction is at most 0.3 wide. This is not the core dataset.

Gv6d200 and Gv6d280 are the delay twins of Gv6j50 and Gv6j70: the same mean RTT (220 and 300 ms)
without jitter. Gv6c30 blackholes IPv4 and gives IPv6 30 % loss each way, so IPv6 is the only working
path. Before every run, the loss and jitter scenarios were checked with verify.sh in band mode. The
band-verify pilot `20261121T182447Z` passed 30/30; see
[`docs/findings/syn_retransmission_partial_loss.md`](../findings/syn_retransmission_partial_loss.md).

## Sessions in the dataset

| # | Client | Scenario | Session | Note |
|---|---|---|---|---|
| 1 | curl | Gv6l10 | `20261121T190000Z` | 26 runs, stopped by rule (CI widths reached), batch check PASS |
| 2 | chromium | Gv6l10 | `20261121T190625Z` | 20 runs, stopped by rule (CI widths reached), batch check PASS |
| 3 | curl | Gv6l30 | `20261121T191141Z` | 50 runs, stopped at the cap (CI widths not reached), batch check PASS |
| 4 | chromium | Gv6l30 | `20261121T192411Z` | 50 runs, stopped at the cap (CI widths not reached), batch check PASS |
| 5 | curl | Gv6l50 | `20261121T193736Z` | 21 runs, stopped by rule (CI widths reached), batch check PASS |
| 6 | chromium | Gv6l50 | `20261121T194303Z` | 50 runs, stopped at the cap (CI widths not reached), batch check PASS |
| 7 | curl | Gv6j50 | `20261121T195626Z` | 39 runs, stopped by rule (CI widths reached), batch check PASS |
| 8 | chromium | Gv6j50 | `20261121T200633Z` | 50 runs, stopped at the cap (CI widths not reached), batch check PASS |
| 9 | curl | Gv6j70 | `20261121T202018Z` | 31 runs, stopped by rule (CI widths reached), batch check PASS |
| 10 | chromium | Gv6j70 | `20261121T202824Z` | 50 runs, stopped at the cap (CI widths not reached), batch check PASS |
| 11 | curl | Gv6d200 | `20261121T204215Z` | 20 runs, stopped by rule (CI widths reached), batch check PASS |
| 12 | chromium | Gv6d200 | `20261122T021043Z` | 20 runs, stopped by rule (CI widths reached), batch check PASS; re-run, see Notes |
| 13 | curl | Gv6d280 | `20261122T021525Z` | 20 runs, stopped by rule (CI widths reached), batch check PASS |
| 14 | chromium | Gv6d280 | `20261122T021946Z` | 20 runs, stopped by rule (CI widths reached), batch check PASS |
| 15 | curl | Gv6c30 | `20261122T022429Z` | 41 runs, stopped by rule (CI widths reached), batch check PASS |
| 16 | chromium | Gv6c30 | `20261122T023712Z` | 50 runs, stopped at the cap (CI widths not reached), batch check PASS |

## Notes

- **Two campaign runs.** Rows 1–11 come from matrix run `20261121T190000Z_matrix`, and rows 12–16
  from a second matrix run on 2026-11-22. The lab was taken down and set up again (setup.sh, then
  verify.sh PASS) between the two.
- **Excluded session `20261121T204637Z` (chromium Gv6d200).** It stopped after run r07, because the
  post-restore baseline verify measured an IPv4 median RTT of 22.20 ms against 20 ± 2 ms. The IPv4
  netem was 10 ms each way throughout, and r07's own pre-run verify had passed (IPv4 21.0 ms).
  Across 1,522 earlier IPv4 verifies at 20 ms, the median was 20.95 ms and the 99th percentile
  21.45 ms. This was the only one above 22 ms. The cause is not in the logs. The tolerance was not
  changed. An adaptive session is never resumed, so its 7 records stay on disk but are not part of
  this dataset, and the batch was re-run whole as row 12.
- **Different time limits.** curl runs with `--max-time 10`, and Chromium with Playwright's
  15 s navigation timeout (the runner kills it at 60 s). The no-winner rates of the two clients are
  therefore not comparable, and they say nothing about Happy Eyeballs.
