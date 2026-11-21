# SYN retransmission under IPv6 partial loss: what the captures can show

**Question:** in the IPv6 partial-loss extension scenarios (`Gv6l10`, `Gv6l30`, `Gv6l50`, and the
compound control `Gv6c30`), are
lost SYNs retried at Linux's initial retransmission timeout (about 1 s), and do TCP setup times
cluster about 1 s apart as a result?

**Status:** method and tooling are in place; the partial-loss and compound scenarios **have not been run**.
No result below is about them. The only measurements quoted are from existing datasets, and
they are labelled with their source.

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
  server kernel's timer. The reference values are 1000, 2000 and 4000 ms. Linux's initial RTO is
  1 s (`TCP_TIMEOUT_INIT`, RFC 6298 §2) and doubles on each further timeout. These are
  references to compare against, not thresholds.
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

## Compound control: `Gv6c30` (configured, not run)

The timer can only show in the winning handshake when IPv6 is the only working path, so the
client has no working IPv4 to fall back to. `Gv6c30` (generator kind `loss_sole_path`) is IPv4
blackholed exactly as in S4 (`netem.sh v4 10 100`, verify target `blackhole`) plus 30% loss each
way on IPv6 (the same loss band as `Gv6l30`). It is a generated extension, not X1.

Expected, from the configuration only (prediction): a SYN round succeeds when both the SYN and
its SYN-ACK get through, with probability 0.7² = 0.49. The kernel retransmits a SYN after 1 s and
doubles the timeout each time, so the SYNs on one socket would go out at about 0, 1, 3 and 7 s,
and setup times would group near 20, 1020, 3020 and 7020 ms (about 49%, 25%, 13% and 6% of runs).
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
runner limits end a run first. On the server side `net.ipv4.tcp_synack_retries` is **5 in
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

## Campaign settings (decided 2026-11-21, not yet run)

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

Pending. The partial-loss scenarios have not been run.
