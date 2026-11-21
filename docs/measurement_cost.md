# Measurement cost, confidence intervals and adaptive repetitions

This page covers three things:
- what the core dataset cost to measure;
- how precisely its medians are pinned down;
- what an adaptive number of repetitions would have saved.

Every number here was produced by the commands shown, from the 280 core runs of 2026-10-26. No
run was repeated or changed.

Evidence levels:
- **TCP setup time** is packet-level evidence (from the pcap).
- **Wall time, pcap size and peak memory** are runner measurements.
- **Confidence intervals** are statistics computed from the packet-level values.
- **Savings** come from a replay of recorded runs, not from an adaptive campaign.

## 1. What the core dataset cost

```
.venv/bin/python src/analysis/summarise.py --cost
```

- **Total:** 280 runs, 3810.5 s wall time (63.5 min) and 2.78 MB of pcaps.
- **Wall time per run:** a median of 12.4–15.3 s, depending on the cell. Most of it is spent on
  the lab verifies (pings) before and after each run, not on the client.
- **pcap size per run:** about 1.7 KB for curl and 16–20 KB for Chromium.
- **Where the numbers come from:** the core records are schema 0.2, so they have no `profile`
  block. Wall times come from each session log (`wall_s=`) and pcap sizes from the files on disk;
  the report names that source.
- **Peak memory:** not recorded for the core dataset. Runs from schema 0.3 onwards record it
  (see the `profile` block in [`run_record_schema.md`](run_record_schema.md)).

## 2. How precisely 20 runs pin down each median

The dashboard and `summarise.py` now give a 95% confidence interval on the median TCP setup time
for every cell. The method is a percentile bootstrap of the median, with 10 000 resamples and a
fixed seed of 0, so the interval can be recomputed exactly. No mean or standard deviation is
reported.

| Cell | Median, ms | 95% CI, ms | Width, ms |
|---|---|---|---|
| curl C0 | 20.697 | 20.683 – 20.819 | 0.137 |
| curl S1 | 222.221 | 222.099 – 222.435 | 0.337 |
| curl S2 | 222.188 | 222.089 – 222.231 | 0.142 |
| curl S3 | 171.171 | 170.954 – 171.205 | 0.251 |
| curl S4 | 20.715 | 20.611 – 20.824 | 0.213 |
| curl S5 | 20.697 | 20.509 – 20.879 | 0.370 |
| curl S6 | 20.812 | 20.729 – 21.035 | 0.306 |
| Chromium C0 | 20.135 | 20.130 – 20.146 | 0.017 |
| Chromium S1 | 322.392 | 322.131 – 323.289 | 1.158 |
| Chromium S2 | 321.986 | 321.642 – 322.577 | 0.935 |
| Chromium S3 | 171.109 | 170.678 – 172.148 | 1.469 |
| Chromium S4 | 20.139 | 20.124 – 20.145 | 0.020 |
| Chromium S5 | 20.139 | 20.133 – 20.143 | 0.011 |
| Chromium S6 | 21.317 | 20.812 – 22.154 | 1.342 |

**No cell has zero variance.** In every cell all 20 runs had the same winning family. TCP setup
time still varies in every cell:
- each cell has 14–20 distinct values out of 20;
- the range is up to 1.6 ms in curl's C0, S4 and S5 cells and up to 3.5 ms in Chromium S1.

So no cell is left without an interval. A narrow interval, such as 0.011 ms for Chromium S5, is
the evidence that 20 runs were more than enough for that cell.

**What the intervals are not:** they describe how precisely each median is estimated. They are
not significance tests: no hypothesis is tested and no p-value is given. This partly addresses
limitation L6 ("no significance tests were run"): it adds the precision of each median, but no
comparison between cells is tested.

## 3. What adaptive repetitions would have saved

```
.venv/bin/python src/analysis/adaptive_replay.py                  # MIN 5, MAX 20, widths 0.25 0.5 1 2
.venv/bin/python src/analysis/adaptive_replay.py --min 10 --width 0.5 1
```

**The rule.** This is what `orchestrate.py --reps-adaptive MIN MAX --ci-width-ms W` does
(`analysis.metrics.adaptive_decision`):
1. Run MIN repetitions.
2. Then add one run at a time.
3. Stop when the 95% bootstrap CI on the median TCP setup time is no wider than W ms, or when MAX
   runs are done.

The rule looks only at the width of the interval and the run count. It never looks at the
median's value.

**How the replay works.** It applies the same function to the recorded runs in the order they
were measured. The time saved is the measured wall time of the runs the rule would have skipped.
- **Assumption:** the first N runs of a session would have come out the same if the session had
  stopped after N. Runs are independent and sequential, but no adaptive session was actually run.
- **Limit:** MAX cannot exceed the 20 recorded runs.

### At `--reps-adaptive 5 20`

| CI width W | Runs needed (of 280) | Wall time skipped (of 3810.5 s) | Largest median shift | CI at the stop excludes the 20-run median |
|---|---|---|---|---|
| 0.25 ms | 188 | 1250.3 s (32.8%) | 0.032 ms | none |
| 0.5 ms | 167 | 1520.7 s (39.9%) | 0.038 ms | none |
| 1 ms | 126 | 2074.5 s (54.4%) | 0.464 ms | curl S1 |
| 2 ms | 76 | 2765.7 s (72.6%) | 1.251 ms | curl S1, Chromium S3 |

"Largest median shift" is the largest difference, across cells, between the median at the stop
and the median of all 20 recorded runs.

The six C0, S4 and S5 cells (two clients × three scenarios) on their own:

| CI width W | Runs needed (of 120) | Wall time skipped (of 1630.3 s) |
|---|---|---|
| 0.25 ms | 54 | 914.1 s (56%) |
| 0.5 ms | 45 | 1031.2 s (63%) |
| 1 ms | 31 | 1209.1 s (74%) |
| 2 ms | 30 | 1221.5 s (75%) |

**The saving is not limited to C0, S4 and S5.** At W = 0.5 ms:
- curl S2 and S3 stop at 7 and 6 runs;
- curl S5 needs 13;
- curl S1 needs 19;
- Chromium S1, S2, S3 and S6 reach the maximum of 20.

The rule follows each cell's own spread, not its scenario label.

### Starting from 5 runs is too few when W is wide

At W = 1 ms, curl S1 stops after 6 runs:
- median 221.757 ms, with a CI of 221.233 – 222.137 ms;
- all 20 runs give a median of 222.221 ms, which is outside that interval.

At W = 2 ms, Chromium S3 also misses. Both follow from a known weakness of the percentile
bootstrap with about 10 values or fewer: its intervals tend to be too narrow.

With `--reps-adaptive 10 20`, no cell's interval misses at W = 0.5 ms or 1 ms:
- W = 0.5 ms: 197 runs needed; 1110.4 s skipped (29.1%); largest median shift 0.038 ms.
- W = 1 ms: 173 runs needed; 1441.9 s skipped (37.8%); largest median shift 0.224 ms.

**Recommendation for new campaigns:** `--reps-adaptive 10 20 --ci-width-ms 0.5`. On the core
data it would have saved about 18.5 minutes of the 63.5 without any interval missing the 20-run
median. Earlier stopping saves more time but gives less reliable intervals.

## Where the adaptive state is kept

- **Each record:** its `adaptive` block holds the rule's state after that run: number of runs,
  median, CI and the decision.
- **Last record of the session:** holds the final reason (`ci_width_reached` or
  `max_reps_reached`).
- **Session log:** an `ADAPTIVE <scenario>: stopped after ...` line.
- **`data/generated/lab/<session>_adaptive.json`:** the settings, run IDs and final state of each
  scenario.

A dataset manifest for adaptive sessions declares `reps: {min, max, ci_width_ms}`
(see [`datasets/README.md`](datasets/README.md)). `summarise.py` refuses a session whose recorded
decisions do not replay identically, or that ran past its stop.
