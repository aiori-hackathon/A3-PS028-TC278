# SYN retransmission under IPv6 partial loss: what the captures can show

**Question:** in the IPv6 partial-loss extension scenarios (`Gv6l10`, `Gv6l30`, `Gv6l50`, and the
compound control `Gv6c30`), are
lost SYNs retried at Linux's initial retransmission timeout (about 1 s), and do TCP setup times
cluster about 1 s apart as a result?

**Status:** run on 2026-11-21/22 as dataset `jitter-loss` ([`docs/datasets/jitter-loss.md`](../datasets/jitter-loss.md),
16 sessions, 558 runs). The results are in [Results](#results). The sections before it were written
before the run and are kept as written, with corrections marked where the captures contradicted them.

This is about the **kernel's TCP retransmission timer**, seen in packets. A retransmitted SYN on
the same socket is sent by the kernel, not by curl or Chromium, and nothing here describes what
either client decided internally. The analysis states only which family won each run and when
each SYN was sent.

## Method

`src/analysis/syn_retransmit.py --session ID ...` (or `--dataset NAME`) re-reads each run's pcap
over the run's window (client start to capture end) and reports, per client and scenario:

- **SYN retransmissions (packet-level).** A retransmission is a further SYN on the **same
  4-tuple**, which means the same socket. A SYN from a new source port is a new connection
  attempt. Chromium's backup IPv6 attempt about 250 ms in is one example, see
  [`chromium_s1_second_v6_syn.md`](chromium_s1_second_v6_syn.md). New attempts are not counted
  as retransmissions. For each retransmission ordinal the tool reports the gap to the previous
  SYN as a median and range. The same is done for SYN-ACKs the server repeats, which is the
  server kernel's timer. Linux's initial RTO is 1 s (`TCP_TIMEOUT_INIT`, RFC 6298 §2). For SYN-ACKs
  the reference doubles: 1000, 2000, 4000 ms. For the client's SYNs, the reference is 1000 ms
  for ordinals 1–5, then 2000 and 4000 ms. The reason is `net.ipv4.tcp_syn_linear_timeouts`, which
  is 4 in hl-client (kernel 7.0.0-43; read 2026-11-22). These are references to compare against, not
  thresholds. *Correction (2026-11-22):* the tool first used the doubling reference for SYNs too,
  and the `Gv6c30` captures contradicted it; see Results.
- **Setup-time clusters (packet-level values, descriptive grouping).** TCP setup time is the
  fixed metric: first SYN to the ACK that completes the winning handshake. The tool sorts the
  setup times and starts a new cluster wherever neighbours are more than 400 ms apart. It
  reports each cluster's median and the spacing between neighbouring cluster medians.
- **Win fraction (packet-level).** The number of runs each family won, with a 95% Wilson
  interval.
- **Adaptive stop.** If a cell was run with `--reps-adaptive` and the rule stopped on the median
  CI alone while both families won some runs, the tool says so. This is the case where the win
  fraction is not settled, and the cell is flagged instead of quietly stopping at the floor.

The pcap parser now keeps every SYN and SYN-ACK time per attempt (`syn_times_ns` and
`synack_times_ns`). Before, it kept only the count. Tests use synthetic captures: one where a
retransmission is answered 1000 ms after the first SYN, and one where a new source port is
correctly not counted (`src/tests/test_jitter_loss.py`).

## What the existing captures already show (packet-level)

Same-socket SYN retransmissions in the 100% blackhole runs. These counts come from
`syn_retransmit.py`'s parser over the runs' windows:

| Dataset | Client | Scenario | Runs | Capture end after the first SYN | Same-socket SYN retransmissions |
|---|---|---|---|---|---|
| core | curl | S1 | 20 | 762–772 ms | 0 |
| core | curl | S4 | 20 | 557–571 ms | 0 |
| core | chromium | S1 | 20 | 988–1009 ms | 0 |
| core | chromium | S4 | 20 | 685–709 ms | 0 |
| variant-control | curl | S1 | 20 | 761–772 ms | 0 |
| variant-control | curl@he200 | S1 | 20 | 761–772 ms | 0 |

The capture stops 0.5 s after the client exits (`TAIL_WAIT_S` in `src/runner/orchestrate.py`).
In every run where the other family won, the window ends before or within a few ms of the 1 s
reference. **So a missing retransmission here is censored, not evidence that none would happen.**
The captures cannot show whether the abandoned socket would have retransmitted at 1 s. The
packets say only that it sent no second SYN before the capture ended.

**The absence may not be censoring at all (interpretation, not packet-level).** If the client closes
the IPv6 socket once IPv4 has won, the kernel discards that socket's retransmission timer with it,
and no SYN would follow however long the capture ran. A longer capture window would then show
nothing more. The packets cannot separate the two explanations: closing a socket that is still
connecting sends nothing on the wire (no FIN, no RST), so its closure is invisible in the pcap.
One packet-level hint, not proof: in the core Chromium S1 runs the window reached 988–1009 ms
after the first IPv6 SYN, at or past the 1 s reference, and the first IPv6 socket sent no second
SYN. Which explanation holds does not change the conclusion for the healthy-IPv4 scenarios: the
timer is not observable there.

## Predictions (interpretation, to be checked against the partial-loss captures)

These are predictions, not results. In the partial-loss scenarios IPv4 is healthy (20 ms RTT),
and per-direction loss p applies to IPv6 only.

1. **A 1 s cluster in the winning setup time may not appear at all.** If the first IPv6 SYN or
   its SYN-ACK is lost, the core captures show the IPv4 SYN starting about 200 ms (curl) or
   about 300 ms (Chromium) after the first IPv6 SYN. With a healthy IPv4 that attempt would
   complete about 20 ms later, well before a 1 s timer fires. The expected clusters are then
   about 20 ms (IPv6 first SYN answered) and about 220 or 320 ms (IPv4 won), not 1 s apart. For
   Chromium a third route exists: the backup IPv6 attempt about 250 ms in, on a new source port,
   might win at about 270 ms. That would be a new attempt, not a retransmission.
2. **The kernel's 1 s timer may be visible only rarely, or not at all.** It shows in packets
   only while the socket that sent the lost SYN still exists and the capture is still running.
   From the existing captures, neither is likely once IPv4 has won.
3. **If 1 s clusters do appear,** they would be runs where the same IPv6 socket's retransmitted
   SYN completed the winning handshake. They should sit about 1000 ms above the about-20 ms
   cluster, and the gap from the first SYN to its retransmission should be about 1000 ms.

If prediction 1 holds, the answer to the question will be **"not observable in these scenarios
with a healthy IPv4"**, and the report should say exactly that. It should not infer the timer.

## Compound control: `Gv6c30` (written before the run)

The timer can only show in the winning handshake when IPv6 is the only working path, so the
client has no working IPv4 to fall back to. `Gv6c30` (generator kind `loss_sole_path`) is IPv4
blackholed exactly as in S4 (`netem.sh v4 10 100`, verify target `blackhole`) plus 30% loss each
way on IPv6 (the same loss band as `Gv6l30`). It is a generated extension, not X1.

Expected, from the configuration only (prediction): a SYN round succeeds when both the SYN and
its SYN-ACK get through, with probability 0.7² = 0.49. The kernel retransmits a SYN after 1 s and
doubles the timeout each time, so the SYNs on one socket would go out at about 0, 1, 3 and 7 s,
and setup times would group near 20, 1020, 3020 and 7020 ms (about 49%, 25%, 13% and 6% of runs).
*Correction (2026-11-22): the doubling assumption was wrong for this kernel. The captures show
same-socket SYNs about 1 s apart up to the fifth SYN; see Results.*
About 7% of curl runs would end with no winner at curl's `--max-time 10` before a fifth SYN
(see the time limits below; this rate is not comparable with Chromium's). The server's own
SYN-ACK retransmissions (when a SYN arrived but its SYN-ACK was lost) can also complete a
handshake, and they are reported separately. Chromium may open further attempts on new source
ports; those are new attempts, not retransmissions, and are reported apart from them.
Raising `TAIL_WAIT_S` is not needed here: the retransmitted SYN is part of the winning handshake,
so it falls inside the window.

### Time limits of the two clients (configuration, recorded in each run's `client.config.run_time_limit`)

| Client | Limit set by the runner | Effect in `Gv6c30` (prediction) |
|---|---|---|
| curl 8.5.0 | `--max-time 10` (whole transfer, connection attempts included; exit 28 when reached) | SYN rounds at about 0, 1, 3, 7 s fit; a fifth at about 15 s does not |
| Chromium (Playwright 1.64.1) | `page.goto` timeout 15 000 ms (`NAV_TIMEOUT_MS`); the runner kills the process at 60 s. Chromium's own connection timeouts are not overridden and are not relied on | SYN rounds at about 0, 1, 3, 7 s fit; one at about 15 s meets the limit |

Beneath both, the kernel gives up on a connecting socket after `net.ipv4.tcp_syn_retries` SYN
retransmissions: **6 in hl-client** (read by the band pilot, 2026-11-21), so about 127 s in total
with the 1 s initial timeout doubling. That is far above both runner limits, so in this lab the
runner limits end a run first. *Correction (2026-11-22): the 127 s figure assumed doubling from the
first retransmission, which the `Gv6c30` captures contradict (see Results). The kernel's give-up
time with linear timeouts is not derived here. So whether the runner limit or the kernel ends a
no-winner run first is not established. No run in this dataset ended without a winner.* On the server side `net.ipv4.tcp_synack_retries` is **5 in
hl-server**, so the server can repeat a SYN-ACK several times within either client's limit;
`syn_retransmit.py` reports those repeats separately from the client's SYN retransmissions.

**Caveat, wherever a no-winner (failure) rate is reported:** a run without a winner ends at the
client's own time limit, and the two limits differ (10 s against 15 s). The no-winner rates of
curl and Chromium on `Gv6c30` are therefore **not comparable**, and their difference says
**nothing about Happy Eyeballs**. `syn_retransmit.py` and the orchestrator's adaptive summary print
this caveat with every non-zero no-winner count (`analysis.metrics.FAILURE_RATE_CAVEAT`).

### Runs without a winner are kept

Every run counts. Outcomes are reported three ways over all runs: IPv6 won, IPv4 won, no winner,
each with a 95% Wilson interval. The stopping rule's median (from schema 0.5,
`adaptive.failed_runs: ranked_highest`) keeps runs without a setup time and ranks them above every
observed value, because such a run took longer than the client allowed. Dropping them, which is
what the 0.3/0.4 rule did, would bias the median low and could stop a cell early. A median CI that
reaches those runs is unbounded and never counts as narrow enough. The cluster table lists
successes only and says how many runs it leaves out.

## Campaign settings (decided 2026-11-21)

Sixteen cells: curl and Chromium × `Gv6l10`, `Gv6l30`, `Gv6l50`, `Gv6j50`, `Gv6j70`, `Gv6d200`,
`Gv6d280`, `Gv6c30`, one `run_matrix.py --only <scenario>:<client>` batch each, with
`--reps-adaptive 20 50 --ci-width-ms 25 --win-ci-width 0.3`.

- 25 ms median CI width: these scenarios inform the fallback point, which is measured in hundreds
  of ms; 5 ms would be unreachable in the loss cells and drive every cell to the cap.
- 0.3 win-fraction CI width: in the loss and jitter cells the share of runs each family wins is
  the quantity of interest, so it is part of the stopping rule, not only reported.
- Cap 50. A cell that stops at 50 with either CI still wider than requested is reported as such.
- A run in `Gv6c30` that reaches its client's time limit is a recorded failure (no winner): it stays
  in the median (ranked highest) and in the outcome counts, and its rate carries the caveat above.

Before the campaign, `src/runner/band_pilot.py` applies each band scenario and runs verify only
(no clients, no captures), to check that the loss and jitter bands pass on a correct link.

## Band-verify pilot (2026-11-21, apply and verify only; no client runs)

`src/runner/band_pilot.py`, pilot `20261121T182447Z`, code `7f9b1a0` (clean tree), 5 verify runs per
scenario, 200 pings each on IPv6 (ICMP echo: packet-level). All 30 band verifies and the baseline
restore passed. The IPv4 link measured 0% loss in every trial, and 100% in `Gv6c30`, as configured.

| Scenario | Band | Observed (5 trials) |
|---|---|---|
| `Gv6l10` | loss 19 ± 12 % | 20.5, 17.5, 21.0, 18.0, 15.5 % (mean 18.5) |
| `Gv6l30` | loss 51 ± 15 % | 50.0, 53.0, 50.0, 61.5, 52.0 % (mean 53.3) |
| `Gv6l50` | loss 75 ± 13 % | 74.5, 75.0, 72.5, 72.5, 76.5 % (mean 74.2) |
| `Gv6c30` | loss 51 ± 15 %, IPv4 blackhole | 46.5, 55.5, 54.5, 49.0, 47.5 % (mean 50.6) |
| `Gv6j50` | median 194.9–245.1 ms, SD 56.5–84.9 ms | median 211.5–223.0 ms; SD 65.9–69.6 ms |
| `Gv6j70` | median 264.9–335.1 ms, SD 79.1–118.9 ms | median 293.0–314.0 ms; SD 93.6–104.6 ms |

The median RTT of the replies in the loss scenarios was 20.1–20.9 ms.

Observations, not conclusions (five trials per scenario are too few to calibrate a band):
- `Gv6l30` trial 4 (61.5%) is about 3 binomial standard errors above the expected 51%. It is
  inside the 4-SE band. Every campaign run records its own verify values
  (`scenario.verify_observed`), so the campaign itself will show whether such values recur.
- **Jitter spread (derived from the verify pings, ICMP; not from client packets).** For
  independent normal draws each way the RTT SD should be J·√2: 70.7 ms for `Gv6j50` and 99.0 ms
  for `Gv6j70`. The mean of five measured SDs was 67.6 ms (all five below 70.7) and 100.0 ms.
  The standard error of a five-trial mean is about 1.6 ms and 2.2 ms. So `Gv6j70` matches its
  prediction (+0.5 SE), and `Gv6j50` sits about 2 SE below it. Both are inside their bands.
- **What this does not show: whether negative draws are clamped.** With base delay 10 + 2J, a
  draw is negative about 1.4% (`Gv6j50`) and 1.6% (`Gv6j70`) of the time in each direction.
  Clamping those draws at 0 would lower the RTT SD by only about 0.9 ms and 1.4 ms (1.3–1.5%;
  computed by simulating 400 000 draws). That is smaller than the five-trial standard error, so
  this pilot cannot tell clamped draws from unclamped ones. The SD agreement is consistent with
  the design estimate that clamping is rare. It is not evidence that clamping is absent. Settling
  this would need the individual ping RTTs, which verify.sh does not keep, or many more trials.

Measured verify durations (pilot log timestamps): 8.1–8.2 s for a loss band, 8.5–8.9 s for a
jitter band, 10.1–10.2 s for `Gv6c30` (blackhole plus loss band). A point verify took 5.8 s in the
core C0 runs.

## Results

Dataset `jitter-loss`: 16 sessions, 558 runs, code `c283448`, kernel 7.0.0-43, curl 8.5.0,
Chromium 156.0.8078.4 (Playwright 1.64.1). Produced by `summarise.py --dataset jitter-loss` and
`syn_retransmit.py --dataset jitter-loss`. Every run passed its verify before and after (band mode for
the loss and jitter scenarios). One chromium `Gv6d200` session was excluded and re-run whole; the
manifest says why. "Won" means the family whose handshake completed first (packet-level), and
95% Wilson intervals are in brackets.

### Outcomes (packet-level)

| Client | Scenario | Runs | IPv6 won | IPv4 won | No winner | Same-socket SYN retransmissions | Client failed after a completed handshake (log) |
|---|---|---|---|---|---|---|---|
| curl | `Gv6l10` | 26 | 21 [0.62, 0.91] | 5 [0.09, 0.38] | 0 | 0 | 0 |
| curl | `Gv6l30` | 50 | 22 [0.31, 0.58] | 28 [0.42, 0.69] | 0 | 0 | 0 |
| curl | `Gv6l50` | 21 | 3 [0.05, 0.35] | 18 [0.65, 0.95] | 0 | 0 | 1 |
| curl | `Gv6j50` | 39 | 17 [0.29, 0.59] | 22 [0.41, 0.71] | 0 | 0 | 0 |
| curl | `Gv6j70` | 31 | 8 [0.14, 0.43] | 23 [0.57, 0.86] | 0 | 0 | 0 |
| curl | `Gv6d200` | 20 | 20 [0.84, 1.0] | 0 | 0 | 0 | 0 |
| curl | `Gv6d280` | 20 | 0 [0.0, 0.16] | 20 [0.84, 1.0] | 0 | 0 | 0 |
| curl | `Gv6c30` | 41 | 41 [0.91, 1.0] | 0 | 0 | 23 attempts | 2 |
| chromium | `Gv6l10` | 20 | 20 [0.84, 1.0] | 0 | 0 | 0 | 0 |
| chromium | `Gv6l30` | 50 | 40 [0.67, 0.89] | 10 [0.11, 0.33] | 0 | 0 | 0 |
| chromium | `Gv6l50` | 50 | 21 [0.29, 0.56] | 29 [0.44, 0.71] | 0 | 0 | 0 |
| chromium | `Gv6j50` | 50 | 46 [0.81, 0.97] | 4 [0.03, 0.19] | 0 | 0 | 0 |
| chromium | `Gv6j70` | 50 | 28 [0.42, 0.69] | 22 [0.31, 0.58] | 0 | 0 | 0 |
| chromium | `Gv6d200` | 20 | 20 [0.84, 1.0] | 0 | 0 | 0 | 0 |
| chromium | `Gv6d280` | 20 | 20 [0.84, 1.0] | 0 | 0 | 0 | 0 |
| chromium | `Gv6c30` | 50 | 50 [0.93, 1.0] | 0 | 0 | 29 attempts | 2 |

- **No winner: 0 in every cell.** The upper 95% bound is 0.07 at 50 runs and 0.16 at 20. So the
  time-limit caveat above has no non-zero rate to qualify in this dataset.
- **Five runs failed after a completed handshake** (outcome from the client logs, and the handshake
  is packet-level). Three are curl (`Gv6l50` r06, `Gv6c30` r11 and r15): exit 28, "Operation timed
  out after 10002 milliseconds with 0 bytes received". Two are Chromium (`Gv6c30` r40 and r46):
  "Page.goto: Timeout 15000ms exceeded". In each, IPv6 completed the handshake and the transfer did
  not finish within the client's limit. They count as IPv6 won in the table above and as failures
  in `summarise.py`'s success column. The two limits differ (10 s and 15 s), so these failure counts
  are not comparable between the clients and say nothing about Happy Eyeballs.
- **Second family's first SYN (packet-level, `summarise.py`):** the inter-family attempt delay
  median was 200.4–200.9 ms for curl and 300.3–301.1 ms for Chromium, in every cell where it was
  observed. In the runs with IPv6 loss, the Chromium captures also show a second IPv6 attempt on a new source port
  about 250 ms after the first (249.4–252.4 ms in `Gv6c30`). That attempt won 4/20 runs in
  `Gv6l10`, 13/50 in `Gv6l30`, 10/50 in `Gv6l50` and 15/50 in `Gv6c30`, at about 270 ms. These are
  new attempts, not retransmissions.

### Retransmission timer (packet-level)

**Loss and jitter scenarios with a healthy IPv4 (`Gv6l*`, `Gv6j*`, the delay twins): no same-socket
SYN retransmission in any of the 467 runs.** Every winning handshake came from a socket's first SYN.
This matches predictions 1 and 2: the winning setup times sit near 20 ms (first IPv6 SYN answered),
about 220 ms (curl, IPv4), about 270 ms (Chromium's second IPv6 attempt) and about 320 ms (Chromium,
IPv4). There is no 1 s cluster. As before, the absence is censored or the socket was closed: the
packets cannot tell which (see above). So the timer is **not observable in these scenarios with a
healthy IPv4**.

**`Gv6c30` (IPv6 the only working path): the timer is visible, and it does not double.** Gap from
each SYN to the next SYN on the same 4-tuple:

| Client | 1st retransmission | 2nd | 3rd | 4th |
|---|---|---|---|---|
| curl | n=23, median 1037.0 ms (1004.2–1059.7) | n=13, 1023.9 ms (1023.5–1024.5) | n=6, 1023.9 ms (1023.7–1024.5) | n=2, 1024.1 ms (1024.0–1024.2) |
| chromium | n=29, median 1038.8 ms (1005.4–1063.2) | n=12, 1023.7 ms (1022.5–1024.7) | n=3, 1024.3 ms (1024.0–1024.5) | none |

A doubling timer would give gaps of about 1, 2 and 4 s. The captures show about 1 s for every
gap up to the fifth SYN on a socket. *Interpretation:* this matches the Linux setting
`net.ipv4.tcp_syn_linear_timeouts`, which reads 4 inside hl-client
(`sysctl -n net.ipv4.tcp_syn_linear_timeouts`, read on 2026-11-22 after the campaign; the band pilot now records it too). No socket sent more than five SYNs,
so the change back to doubling after the linear phase is not observed.

Winning setup times, grouped by which SYN completed the winning handshake (packet-level):

| Client | First SYN, ~20 ms | Second IPv6 attempt, ~270 ms | 2nd SYN, ~1.05 s | 3rd SYN, ~2.07 s | 4th SYN, ~3.09 s | 5th SYN, ~4.13 s |
|---|---|---|---|---|---|---|
| curl (41) | 27 | n/a | 5 | 5 | 2 | 2 |
| chromium (50) | 27 | 15 | 5 first socket, 1 second socket (1307 ms) | 1 | 1 | 0 |

The cluster spacings for curl were 1035.8, 1017.2, 1015.3 and 1038.7 ms (reference 1000 ms).
Against the corrected `Gv6c30` prediction, the setup times group about 1 s apart (near 20, 1050,
2070, 3090 and 4130 ms), not near 20, 1020, 3020 and 7020 ms. 27/41 curl runs (0.66) were won by
the first SYN, against the 0.49 expected from 30% loss each way. That is about two binomial
standard errors above it, and is noted, not explained. The verify pings before these runs measured
51.2% round-trip loss on average (43.0–60.5%), which is inside the band.

The server's repeated SYN-ACKs are reported by `syn_retransmit.py` separately. Some came about
10 ms after the previous SYN-ACK, not 1 s. They are not interpreted here.

### Adaptive stopping

The IPv6 win-fraction CI reached the requested 0.3 or narrower in every cell, so `syn_retransmit.py`
flagged none. Six cells stopped at the cap of 50 because the median setup-time CI stayed wider than
25 ms:

| Cell | Median CI width |
|---|---|
| curl `Gv6l30` | 200.3 ms |
| chromium `Gv6l30` | 251.1 ms |
| chromium `Gv6l50` | 49.5 ms |
| chromium `Gv6j50` | 65.2 ms |
| chromium `Gv6j70` | 62.8 ms |
| chromium `Gv6c30` | 251.0 ms |

In these cells the setup times split between groups 200–300 ms apart, depending on which attempt
won. The median then depends on that split and is poorly determined. Report these cells by
their outcome shares and setup-time groups, not by the median.

### Jitter against the delay twins (packet-level outcomes; the comparison is descriptive)

| Mean IPv6 RTT | Scenario | curl IPv6 won | Chromium IPv6 won |
|---|---|---|---|
| 220 ms | `Gv6d200` (no jitter) | 20/20 | 20/20 |
| 220 ms | `Gv6j50` (J=50 ms each way) | 17/39 [0.29, 0.59] | 46/50 [0.81, 0.97] |
| 300 ms | `Gv6d280` (no jitter) | 0/20 | 20/20 |
| 300 ms | `Gv6j70` (J=70 ms each way) | 8/31 [0.14, 0.43] | 28/50 [0.42, 0.69] |

At the same mean RTT, jitter moved the outcome away from all-or-nothing for both clients. The
measured RTT SD in the verify pings before the runs was 69.7 ms for `Gv6j50` and 97.7 ms for
`Gv6j70` (expected 70.7 and 99.0 ms). That figure comes from ICMP, not client packets. Which family
won each run follows from when each handshake completed relative to the second family's first SYN
(about 200 ms for curl, about 300 ms for Chromium). The packets do not show anything about how
either client chose that time.

### Jitter win-fraction model (derived; `src/analysis/jitter_model.py --dataset jitter-loss`)

A simple model of the jitter cells: **P(IPv6 wins) = Φ((T − μ) / σ)**. The idea is that IPv6 wins when its
first attempt's handshake completes before the IPv4 SYN-ACK arrives. The model has three inputs, and
**every one is measured in this lab. None is taken from either client's documentation or source
code:**

- **T (crossover time; packet times, derived).** In the client's own no-jitter delay-twin runs
  (`Gv6d200`, `Gv6d280`): the time from the run's first SYN to the first SYN-ACK of its IPv4
  attempt, as a median over the twin runs where that SYN-ACK appears. This is when the IPv4
  handshake could complete, read from the packets. It says nothing about how the client chose
  when to start that attempt.
- **μ and σ (verify pings, ICMP; derived, not client packets).** Taken from the pre-run verify of
  every run in the jitter cell. μ is the mean of the per-run median RTTs. σ is the mean of the
  per-run RTT SDs, shown next to the design value J·√2.
- **Assumptions:** the first IPv6 attempt's handshake time follows the ping RTT distribution, and
  only that attempt and the IPv4 attempt race. A run won by a later IPv6 attempt would fall
  outside the model; there were none in the jitter cells.

| Client | Cell | T (ms) | μ (ms) | σ (ms) (J·√2) | Predicted | Observed [95% Wilson CI] |
|---|---|---|---|---|---|---|
| curl | `Gv6j50` | 222.0 | 221.3 | 69.4 (70.7) | 0.50 | 17/39 = 0.44 [0.29, 0.59] |
| curl | `Gv6j70` | 222.0 | 301.5 | 98.5 (99.0) | 0.21 | 8/31 = 0.26 [0.14, 0.43] |
| chromium | `Gv6j50` | 322.5 | 221.2 | 70.0 (70.7) | 0.93 | 46/50 = 0.92 [0.81, 0.97] |
| chromium | `Gv6j70` | 322.5 | 302.3 | 97.2 (99.0) | 0.58 | 28/50 = 0.56 [0.42, 0.69] |

**T, as measured (packet times, derived).** This is the value the model uses. It is measured
directly in the twin captures, not inferred from their outcomes:

| Client | T, median | Runs | Range | Interquartile range |
|---|---|---|---|---|
| curl | 222.0 ms | 40 (both twins) | 221.0–224.1 ms | 221.5–222.9 ms |
| chromium | 322.5 ms | 17 (`Gv6d280` runs where the IPv4 SYN-ACK appears) | 321.0–325.4 ms for 16 runs; one at 573.9 ms | 321.9–323.9 ms |

**The 573.9 ms Chromium value (packet-level, run `20261122T022248Z_Gv6d280_chromium_r14`):** the IPv4
SYN went out at 551.2 ms. That is 300.4 ms after the second IPv6 attempt's SYN (new source port,
250.8 ms; see [`chromium_s1_second_v6_syn.md`](chromium_s1_second_v6_syn.md)), not about 300 ms
after the first IPv6 SYN. The IPv4 SYN-ACK at 573.9 ms answers that SYN. So in this run the IPv4
attempt follows the later IPv6 attempt; the packets do not show why. The first IPv6 handshake had
already completed at 300.9 ms. The value stays listed separately and is inside the median above.

Across that measured spread the predictions barely move. For curl, the full range 221.0–224.1 ms
gives 0.50–0.52 (`Gv6j50`) and 0.21–0.22 (`Gv6j70`). For Chromium, 321.0–325.4 ms gives 0.92–0.93
and 0.58–0.59. Within these cells, the uncertainty in T is therefore small next to the width of the
observed intervals. T is measured in the no-jitter twins, not in the jitter cells; it is applied to
them because the IPv4 link is the same (10 ms each way, no jitter) in both.

**All four predictions fall inside the observed 95% interval.** With 31–50 runs per cell the
intervals are 0.16–0.30 wide, so this agreement is consistent with the model. It does not test the
model closely.

**Corroboration from the twins' outcomes (a weaker, independent check).** Which family won each twin
run also constrains T, without using any packet times. The constraint is coarse, because each client
has only two twins:

- **curl:** IPv6 won 20/20 at 221 ms and IPv4 won 20/20 at 301 ms, so T lies between 221 and
  301 ms.
- **Chromium:** IPv6 won 20/20 at both 221 and 301 ms, so T is above 301 ms. The outcomes give no
  upper end.

Both measured values fall inside these brackets, so the outcomes agree with the measurement. They
are not where the 222.0 and 322.5 ms come from, and they could not locate T more finely than this.

**Limitation.** T is measured at only two IPv6 delays per client. The outcome check therefore
brackets it coarsely, and for Chromium only from below; the outcome flip is not located. The latency
sweep `Gv6d100`–`Gv6d400` (generated, not yet run) would show where each client's outcome changes,
and so test the measured T independently of the packet times.
