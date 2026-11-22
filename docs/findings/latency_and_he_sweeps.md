# Where the outcome flips: the latency sweep and the curl timeout sweep

Two extension datasets, run on 2026-11-22 from code `9a6de27`. Neither is part of the core dataset,
and nothing here changes the core summary, report or dashboard.

- [`latency-sweep`](../datasets/latency-sweep.md): 36 sessions, 180 runs.
- [`he-sweep`](../datasets/he-sweep.md): 27 sessions, 270 runs.

Both reports come from `src/analysis/crossover.py --dataset <name>`.

**Evidence levels.**
- **Packet-level:** which family completed the winning handshake, and the time of each SYN and
  SYN-ACK after the run's first SYN.
- **Derived:** the RTT of a cell, which is the median of the per-run verify-ping medians (ICMP,
  printed by ping in whole ms above 100 ms). Also derived: every median, bracket and predicted
  value below.
- **Interpretation:** marked where it appears.

Nothing here says how either client decides when to start an attempt, or that it implements any
particular algorithm.

## T

T is the time from the run's first SYN to the first SYN-ACK of its IPv4 attempt. It is a
packet-level time per run, and T below is the median over runs. When IPv6 is delayed, IPv6 wins
exactly when its handshake completes before T.

## Latency sweep: the outcome flip located to 5 ms

**Design.**
- Deterministic IPv6 delay `Gv6d<N>`, giving RTT = 20 + N ms. IPv4 stays at the baseline.
- 5 runs per cell.
- Coarse cells: +100 to +400 in 25 ms steps, for both clients.
- Fine cells: 5 ms steps around each client's T from
  [`jitter-loss`](syn_retransmission_partial_loss.md#jitter-win-fraction-model-derived-srcanalysisjitter_modelpy---dataset-jitter-loss),
  for that client only.
- Odd N needs a half ms each way. `src/runner/fractional_delay_check.py` checked that netem
  applies it, and the check passed twice:
  - at 20261122T071800Z;
  - at 20261122T073651Z, in the campaign chain before the first run. There each 0.5 ms change
    each way moved the mean ping RTT by 0.85–1.115 ms, against an expected 1.0 ± 0.5.

**Outcomes (packet-level; RTT derived).** Every cell went 5/5 one way:

| Client | IPv6 won 5/5 up to | IPv4 won 5/5 from | Mixed cells | Out of order |
|---|---|---|---|---|
| curl | RTT 221 ms (`Gv6d200`) | RTT 226 ms (`Gv6d205`) | none | none |
| Chromium | RTT 321 ms (`Gv6d300`) | RTT 326 ms (`Gv6d305`) | none | none |

The flip comes from the outcomes alone and uses no packet times. Each measured T falls inside its
client's flip bracket:

| Client | Flip bracket (outcomes) | T in this dataset (packets) | T in jitter-loss (packets) |
|---|---|---|---|
| curl | 221–226 ms | 221.84 ms (70 runs with an IPv4 SYN-ACK) | 222.0 ms (n=40) |
| Chromium | 321–326 ms | 321.99 ms (50 runs with an IPv4 SYN-ACK) | 322.5 ms (n=17) |

So the outcome flip and the packet-measured T agree. The jitter-loss findings said this
independent check was missing; this is that check.

**How tightly T stays put (packet-level).** T barely moves with the IPv6 delay once an IPv4
attempt is made. Across the cells where an IPv4 SYN-ACK appears, the per-cell medians are:
- curl: 221.26–222.27 ms, from +190 to +400;
- Chromium: 321.35–323.19 ms, from +290 to +400.

**Limits.**
- The bracket edges are verify-ping medians. Ping prints whole ms above 100 ms, and the medians
  run about 1 ms above the 20 + N target. So the edges are good to about 1 ms, and the flip is
  located to 5 ms, not finer.
- There are 5 runs per cell. A cell right at T could have mixed outcomes in a larger sample. None
  of these cells did.

## Timeout sweep: T against timeout + IPv4 handshake (curl only)

**Design.**
- Clients: plain curl, plus `curl@he50`, `he100`, `he150`, `he200`, `he250`, `he300`, `he400` and
  `he500`. Each variant is curl with `--happy-eyeballs-timeout-ms N`; see
  [client variants](../client_variants.md).
- Scenarios: C0, S1 and S3, 10 runs per cell.
- T is taken from S1, where IPv6 is blackholed, so every run makes an IPv4 attempt.
- The prediction was set before the run: T ≈ timeout + IPv4 handshake time. It is a derived
  comparison and says nothing about how curl schedules the attempt.

**Results (S1; packet-level medians in ms after the first SYN; predicted values derived):**

| Client | Timeout | IPv4 first SYN | IPv4 handshake | Predicted T | T | T − predicted |
|---|---|---|---|---|---|---|
| curl | not set | 200.832 | 21.024 | – | 222.135 | – |
| curl@he50 | 50 | 50.689 | 20.809 | 70.809 | 71.496 | +0.687 |
| curl@he100 | 100 | 100.799 | 20.941 | 120.941 | 121.733 | +0.792 |
| curl@he150 | 150 | 150.750 | 20.962 | 170.962 | 171.721 | +0.759 |
| curl@he200 | 200 | 200.833 | 20.987 | 220.987 | 221.882 | +0.895 |
| curl@he250 | 250 | 250.939 | 20.989 | 270.989 | 271.808 | +0.819 |
| curl@he300 | 300 | 301.650 | 20.941 | 320.941 | 322.837 | +1.896 |
| curl@he400 | 400 | 401.087 | 20.959 | 420.959 | 422.115 | +1.156 |
| curl@he500 | 500 | 501.629 | 20.941 | 520.941 | 522.927 | +1.986 |

IPv4 won all 10 runs in every S1 cell. T follows the prediction from 50 to 500 ms, always a
little late: +0.7 to +0.9 ms up to he250, and +1.2 to +2.0 ms from he300.

The IPv4 handshake is steady at 20.8–21.0 ms. So most of the excess is in when the IPv4 SYN
appears: 0.69–0.94 ms after the timeout up to he250, and 1.09–1.65 ms from he300. The columns are
medians taken separately, so the excess is not exactly their sum.

That growth with the timeout is what the packets show. These data do not explain it.

**Validation control (packet-level).** curl@he200 sets the default timeout that curl's man page
documents, so it should match plain curl:

| | curl@he200 | Plain curl | Difference |
|---|---|---|---|
| IPv4 first SYN | 200.833 ms | 200.832 ms | 0.001 ms |
| T | 221.882 ms | 222.135 ms | 0.25 ms |

Plain curl's T also matches the 221.84 ms from the latency sweep and the 222.0 ms from
jitter-loss.

**S3, IPv6 at +150 ms RTT (packet-level outcomes):**

| Client | IPv6/IPv4 wins of 10 | IPv4 attempt seen | T |
|---|---|---|---|
| curl@he50 | 0/10 | yes | 71.743 ms |
| curl@he100 | 0/10 | yes | 121.752 ms |
| curl@he150 | 10/0 | yes, in all 10 runs | 171.391 ms |
| curl, he200–he500 | 10/0 | no | – |

At he150 the IPv4 attempt went out, but IPv6 completed first in all 10 runs: the IPv6 oracle
setup median is 171.0 ms, against an IPv4 SYN-ACK at 171.39 ms. That margin is about 0.4 ms, so
this cell is a near tie. With 10 runs it shows which way the outcome fell in this lab, not a
stable margin.

**C0.** IPv6 won 10/10 in every cell, with no IPv4 attempt. The cost of racing is under 1 ms in
magnitude.

**Limits.**
- Each cell has 10 runs, and T is a median of 10.
- Only curl takes this flag, so the sweep has no Chromium counterpart.
- This is one host and one kernel (7.0.0-43-generic).

## Running conditions

- The first campaign chain ran latency-sweep completely, then the first 7 C0 cells of he-sweep.
- A lid-close suspend interrupted the 8th cell, `20261122T083500Z`. That session was excluded and
  re-run whole.
- The remaining 20 cells ran in one `run_matrix.py --only` batch, and every batch check passed.
- The final baseline verify, right after resume, failed only its host default-route check while
  the host Wi-Fi reconnected. That is a host-side artefact. Every run in both datasets passed the
  full verify, host checks included, before and after it.
- Details are in the [he-sweep manifest notes](../datasets/he-sweep.md#notes).
