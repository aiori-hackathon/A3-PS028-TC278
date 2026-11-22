# Where the outcome flips: the latency sweep and the curl timeout sweep

Two extension datasets, run on 2026-11-22 from code `9a6de27`. Neither is part of the core dataset,
and nothing here changes the core summary, report or dashboard.

- [`latency-sweep`](../datasets/latency-sweep.md): 36 sessions, 180 runs.
- [`he-sweep`](../datasets/he-sweep.md): 27 sessions, 270 runs.

Both reports come from `src/analysis/crossover.py --dataset <name>`.

**Evidence levels.**
- **Packet-level:** which family completed the winning handshake, and the time of each SYN and
  SYN-ACK after the run's first SYN.
- **Derived:**
  - the RTT of a cell, which is the median of the per-run verify-ping medians (ICMP, printed by
    ping in whole ms above 100 ms);
  - the oracle setup and cost of racing (pcap − lab RTT);
  - every median, bracket and predicted value below.
- **Precision:** T is given to two decimal places throughout, with the campaign it was measured
  in. 221.84 (latency-sweep), 221.96 (jitter-loss) and 222.14 ms (he-sweep) are the same quantity
  measured in different campaigns.
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
| curl | 221–226 ms | 221.84 ms (70 runs with an IPv4 SYN-ACK) | 221.96 ms (n=40) |
| Chromium | 321–326 ms | 321.99 ms (50 runs with an IPv4 SYN-ACK) | 322.47 ms (n=17) |

So the outcome flip and the packet-measured T agree. The jitter-loss findings said this
independent check was missing; this is that check.

**How tightly T stays put (packet-level).** T barely moves with the IPv6 delay once an IPv4
attempt is made. Across the cells where an IPv4 SYN-ACK appears, the per-cell medians are:
- curl: 221.26–222.27 ms, from +190 to +400;
- Chromium: 321.35–323.19 ms, from +290 to +400.

**Oracle baseline (derived: pcap − lab RTT).**
- **Definitions.** A run's oracle setup is the pre-run verify-ping RTT of the family that won the
  run. Its cost of racing is the packet-level TCP setup time minus that oracle; see
  `src/analysis/metrics.py`, `oracle_baseline`. The oracle is a hindsight reference: it uses the
  winner, which no client knows before connecting.
- **Source.** The values come from `src/analysis/summarise.py --dataset latency-sweep`, with the
  oracle computed in all 180 runs. Figure 1's "TCP setup against the oracle" panel plots them.
- **Single-family cells.** In the cells marked "no" in the Race column, only IPv6 was tried. No race
  took place, so the value there is only the handshake time against the ping RTT, not a cost of
  racing.

| Client | Cells (winner) | Runs | Race | Oracle setup, cell medians | TCP setup, cell medians | Cost of racing, cell medians | Cost of racing, per run |
|---|---|---|---|---|---|---|---|
| curl | `Gv6d100`–`Gv6d175` (IPv6) | 20 | no: IPv6 only | 121.0–196.0 ms | 120.66–196.01 ms | −0.03 to +0.21 ms | −0.47 to +1.83 ms |
| curl | `Gv6d190`–`Gv6d200` (IPv6) | 15 | yes | 211.0–221.0 ms | 210.81–220.98 ms | −0.19 to +0.73 ms | −0.83 to +1.06 ms |
| curl | `Gv6d205`–`Gv6d400` (IPv4) | 55 | yes | 20.85–21.0 ms | 221.76–222.34 ms | 200.76–201.48 ms | 199.66–202.96 ms |
| Chromium | `Gv6d100`–`Gv6d275` (IPv6) | 40 | no: IPv6 only | 121.0–296.0 ms | 120.13–296.03 ms | −0.85 to +0.03 ms | −0.89 to +1.39 ms |
| Chromium | `Gv6d290`–`Gv6d300` (IPv6) | 15 | yes | 311.0–321.0 ms | 311.28–320.60 ms | −0.44 to +0.28 ms | −0.84 to +1.27 ms |
| Chromium | `Gv6d305`–`Gv6d400` (IPv4) | 35 | yes | 20.9–21.0 ms | 321.43–323.27 ms | 300.43–302.17 ms | 299.93–304.92 ms |

- **Where IPv6 won.** Every cell median of the cost is within ±0.9 ms of zero. That is inside the
  1 ms resolution of the ping that sets the oracle above 100 ms, and negative values are reported,
  not clamped.
- **Where IPv4 won.** The oracle drops to the IPv4 RTT, about 21 ms. The cost of racing is then
  200.76–201.48 ms for curl and 300.43–302.17 ms for Chromium (cell medians), in every cell where
  IPv4 won.
- **Limits.** The cost is a derived value: packet-level setup minus a pre-run ping median. It says
  nothing about how either client chooses when to start an attempt.

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
| curl | not set | 200.832 | 21.024 | – | 222.14 | – |
| curl@he50 | 50 | 50.689 | 20.809 | 70.81 | 71.50 | +0.69 |
| curl@he100 | 100 | 100.799 | 20.941 | 120.94 | 121.73 | +0.79 |
| curl@he150 | 150 | 150.750 | 20.962 | 170.96 | 171.72 | +0.76 |
| curl@he200 | 200 | 200.833 | 20.987 | 220.99 | 221.88 | +0.90 |
| curl@he250 | 250 | 250.939 | 20.989 | 270.99 | 271.81 | +0.82 |
| curl@he300 | 300 | 301.650 | 20.941 | 320.94 | 322.84 | +1.90 |
| curl@he400 | 400 | 401.087 | 20.959 | 420.96 | 422.12 | +1.16 |
| curl@he500 | 500 | 501.629 | 20.941 | 520.94 | 522.93 | +1.99 |

T and the T-derived columns are given to two decimal places, as everywhere T is reported. The
SYN and handshake columns keep three, because the control below compares SYN times 0.001 ms apart.
Each value is rounded half-up on its own from its three-decimal median, so a difference can be
0.01 ms off. For example, he200 gives 221.88 − 220.99 = 0.89, while the residual from the unrounded
medians is +0.895, shown as +0.90.

IPv4 won all 10 runs in every S1 cell. T follows the prediction from 50 to 500 ms, always a
little late.

**The residual steps between he250 and he300 (packet-level; no explanation offered).** T −
predicted falls in two groups:

| Timeouts | T − predicted | IPv4 first SYN after the timeout |
|---|---|---|
| he50–he250 (5 cells) | +0.69 to +0.90 ms | 0.69 to 0.94 ms |
| he300–he500 (3 cells) | +1.16 to +1.99 ms | 1.09 to 1.65 ms |

- The step is not monotonic within the upper group: he400 (+1.16) is below both he300 (+1.90) and
  he500 (+1.99).
- The IPv4 handshake is steady at 20.8–21.0 ms in every cell. So the step is in when the IPv4 SYN
  appears, not in the handshake.
- The columns are medians taken separately, so the residual is not exactly their sum.

This is reported as observed in the packets. These data draw no conclusion about why it happens.

**Validation control (packet-level).** curl@he200 sets the default timeout that curl's man page
documents, so it should match plain curl:

| | curl@he200 | Plain curl | Difference |
|---|---|---|---|
| IPv4 first SYN | 200.833 ms | 200.832 ms | 0.001 ms |
| T | 221.88 ms | 222.14 ms | 0.25 ms (from the unrounded 221.882 and 222.135) |

Plain curl's T also matches its other measurements; see [Reproducibility of plain curl's
T](#reproducibility-of-plain-curls-t).

**S3, IPv6 at +150 ms RTT (packet-level outcomes):**

| Client | IPv6/IPv4 wins of 10 | IPv4 attempt seen | T |
|---|---|---|---|
| curl@he50 | 0/10 | yes | 71.74 ms |
| curl@he100 | 0/10 | yes | 121.75 ms |
| curl@he150 (boundary case) | 10/0 | yes, in all 10 runs | 171.39 ms |
| curl, he200–he500 | 10/0 | no | – |

**he150 is a boundary case, not a finding.** The IPv4 attempt went out, but IPv6 completed
first in all 10 runs. The IPv6 oracle setup median is 171.0 ms, against an IPv4 SYN-ACK at
171.39 ms.

That margin is about 0.4 ms at n = 10. It is smaller than:
- the 1 ms resolution of the verify pings that set the IPv6 RTT;
- the 0.30–0.61 ms spread of plain curl's T across campaigns (below).

So the 10/0 split records which way the outcome fell in these 10 runs. It is not evidence that
IPv6 wins at this setting.

**C0.** IPv6 won 10/10 in every cell, with no IPv4 attempt. The cost of racing is under 1 ms in
magnitude.

**Limits.**
- Each cell has 10 runs, and T is a median of 10.
- Only curl takes this flag, so the sweep has no Chromium counterpart.
- This is one host and one kernel (7.0.0-43-generic).

## Reproducibility of plain curl's T

Plain curl's T (median time from the first SYN to the IPv4 SYN-ACK; packet-level) has been
measured in four campaigns:

| Campaign | When (UTC) | Code | IPv6 condition | Runs | T |
|---|---|---|---|---|---|
| [`variant-control`](../datasets/variant-control.md) | 2026-11-21 17:11 | `72be111` | blackhole (S1) | 20 | 221.53 ms |
| [`jitter-loss`](../datasets/jitter-loss.md), twins | 2026-11-21 20:42 and 2026-11-22 02:15 | `c283448` | +200 and +280 ms delay | 40 | 221.96 ms |
| [`latency-sweep`](../datasets/latency-sweep.md) | 2026-11-22 07:47–08:18 | `9a6de27` | +190 to +400 ms delay | 70 | 221.84 ms |
| [`he-sweep`](../datasets/he-sweep.md), S1 | 2026-11-22 09:23 | `9a6de27` | blackhole (S1) | 10 | 222.14 ms |

**Reproducibility result.**
- The three campaigns from jitter-loss onwards agree within 0.30 ms (221.84–222.14).
- With variant-control included, all four agree within 0.61 ms (221.53–222.14).
- The four are separate sessions and campaigns, on three code versions. Two use an IPv6 blackhole
  and two an IPv6 delay.
- They are not independent of the host. All ran on the same machine and kernel (7.0.0-43-generic)
  within about 16 hours, from 2026-11-21 17:11 to 2026-11-22 09:23 UTC.
- So this shows T reproduces across campaigns on this host. It does not show T holds across hosts
  or kernels.

The core dataset's curl S1 median TCP setup time (222.221 ms, kernel 7.0.0-38) is a different
metric, the setup time and not T, so it is not in this table.

## Running conditions

- The first campaign chain ran latency-sweep completely, then the first 7 C0 cells of he-sweep.
- A lid-close suspend interrupted the 8th cell, `20261122T083500Z`. That session was excluded and
  re-run whole.
- The remaining 20 cells ran in one `run_matrix.py --only` batch, and every batch check passed.
- The final baseline verify, right after resume, failed only its host default-route check while
  the host Wi-Fi reconnected. That is a host-side artefact. Every run in both datasets passed the
  full verify, host checks included, before and after it.
- Details are in the [he-sweep manifest notes](../datasets/he-sweep.md#notes).
