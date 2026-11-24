# Feeding HappyLab records into another system

This note is for anyone loading HappyLab results into another tool: a database, a notebook, a
monitoring system or another team's analysis. It covers what a run record contains, how to export
records as CSV, and what each evidence tag means. The full field reference is
[`run_record_schema.md`](run_record_schema.md); this page does not replace it.

## What there is to load

| Artefact | Where | One per | Notes |
|---|---|---|---|
| Run record (JSON) | `data/generated/runs/<run_id>.json` | run | The unit of exchange. Schema versions 0.1–0.5 exist; the core dataset's records are 0.2. |
| Packet capture | `captures/<run_id>.pcap` | run | The packet-level evidence itself. The record holds its path and SHA-256. |
| Client log | `data/generated/logs/<run_id>.log` | run | What the runner saw and ran. Chromium runs also keep a NetLog. |
| Dataset manifest | `docs/dataset.md`, `docs/datasets/<name>.md` | dataset | Which sessions make up a dataset. |
| CSV export | wherever `--out` points | run | One flat row per run, made by `src/analysis/export_csv.py` (below). |
| Summary | `data/generated/summary/summary.json` | dataset | Per-cell statistics, including the scenario penalty, from `src/analysis/summarise.py`. |

`data/generated/` and `captures/` are not in Git. Three real records with their captures and
SHA-256 sums are committed in [`../examples/`](../examples/) and make a good first test of an
importer.

## Which records to take

A folder of records is not a dataset. It also holds pilots, aborted sessions and test runs. Take
either:

- **A certified dataset**: exactly the sessions a manifest lists. `summarise.py`, `oracle.py` and
  `export_csv.py` (by default) all load records through `summarise.load_runs`, which refuses the
  whole dataset if any listed session has the wrong number of runs, repetitions that are not
  exactly 1..N, a run of another client or scenario, a `cross_checks` status other than `agree`,
  a failed lab verify before or after the run, or a record whose code version
  (`environment.git_commit`) ends in `-dirty` (made from uncommitted changes, so not reproducible).
- **Individual records**, for pilots or examples, by passing their files or folders to
  `export_csv.py`. These are schema-validated but not certified; treat them as such downstream.

Do not load a record with `cross_checks.status` of `conflict` without a person looking at it first:
the client's own report and the capture disagree about it.

## The run record

One JSON object per run. Top-level blocks and where their contents come from:

| Block | Contents | Source |
|---|---|---|
| `run_id`, `schema_version` | Identity: `<UTC yyyymmddThhmmssZ>_<scenario>_<client>_r<NN>`; in file names a client label's `@` is written `-` (`curl@he200` → `curl-he200`) | metadata |
| `scenario` | ID, label, repetition, configured netem and DNS delay, the RTT measured before the run (`measured_rtt_ms`), and from 0.5 the full verify result (`verify_observed`) | configuration (netem is **not** ground truth); `measured_rtt_ms` is the lab verify |
| `client` | Implementation (`curl`/`chromium`), optional curl `variant`, exact version string, exact argv, connection-relevant config | metadata |
| `environment` | Kernel, Python, `git_commit`, `session_id`, resolver, `gai.conf`, server, what was stripped from the child environment, the capture's interface-number map | metadata |
| `timestamps` | Run start (ISO 8601 UTC) and client and capture start/end (epoch ns, wall clock) | runner |
| `outcome` | Success, exit code, HTTP status, error, and `client_report` (curl `-w` output; Chromium's Playwright and NetLog fields) | client/runner logs |
| `evidence` | Capture path and SHA-256, client log path, lab verify results | runner |
| `packet_observations` | Winning family, every connection attempt, failed or abandoned attempts | packet capture |
| `metrics` | TCP setup time, inter-family attempt delay, DNS time, scenario penalty (always `not_applicable` per run) | packet capture |
| `cross_checks` | Client log against capture: `agree` or `conflict`, with both values of each conflict | comparison of the two |
| `profile`, `adaptive` | 0.3+, optional: measurement cost, and the adaptive stopping rule's state after this run | runner measurements and decisions |

Rules an importer should keep:

- **Wrapped values.** Every derived value is `{"value": ..., "status": ...}`, with an optional
  `note`. `value` is non-null only when `status` is `computed`. The other statuses say why it is
  null: `not_observed` (the event was not in the evidence, for example only one family was
  tried), `not_applicable` and `not_yet_computed`. Keep the status; do not turn a null into 0.
- **Fixed metric definitions.** Do not recompute these with other definitions under the same
  name. TCP setup time is first SYN to the ACK completing the winning handshake, and excludes
  DNS. Inter-family attempt delay is the second family's first SYN minus the first family's first
  SYN, and is `not_observed` when only one family was tried. Scenario penalty is the client's
  median setup time minus its own C0 median: a per-cell value, so take it from `summary.json`
  rather than from any one record.
- **S6 needs both times.** The AAAA delay shows in `dns_time_ms`, not in `tcp_setup_time_ms`.
  Report both for S6.
- **Measured, not configured.** Use `scenario.measured_rtt_ms`, not `scenario.netem`, for the
  RTT a run actually had.
- **Integrity.** Check the capture against `evidence.pcap_sha256` before trusting anything
  re-derived from it.
- **Interface names.** Captures use `tcpdump -i any`, which stores interface numbers. Map them
  with `environment.capture_interfaces`, not with names shown when the pcap is read elsewhere.
- **Join keys.** `run_id` is unique per run. `session_id` groups the runs of one batch, and a
  manifest maps sessions to client × scenario cells.

## CSV export

```bash
.venv/bin/python src/analysis/export_csv.py                          # core dataset, CSV to stdout
.venv/bin/python src/analysis/export_csv.py --out runs.csv           # ... to a file
.venv/bin/python src/analysis/export_csv.py --dataset NAME --out runs.csv
.venv/bin/python src/analysis/export_csv.py examples/                # any record files or folders
.venv/bin/python src/analysis/export_csv.py --columns                # print the column table below
```

The script only reads records. It writes the one file given with `--out`, or nothing (stdout).

Format:

- UTF-8, comma-separated, one header row, one row per run, sorted by `run_id`.
- Booleans are `true`/`false`. A missing value is an empty cell.
- A wrapped field becomes two columns, `NAME` and `NAME_status`. `NAME` is empty unless the status
  is `computed`, so an empty cell always has its reason beside it. The derived columns can also
  have the status `not_available`, when the winning family's RTT was not measured.
- Fields that are lists in the record are summarised (`attempts`, `attempt_shape`,
  `syn_retransmits`). The full attempt list, the client report and the configuration stay in the
  JSON record; load that when you need them.
- No column is an interpretation.

Every column has a **source** (provenance) value. Three of them correspond to evidence tags; the
others are not evidence about client behaviour (see the next section).

| Source | Evidence tag |
|---|---|
| `packet` | Packet-level (pcap) |
| `client` | Client log |
| `derived` | Derived (pcap − lab RTT) |
| `lab verify` | none: the lab's ping check before the run, an input to the derived columns |
| `cross-check` | none: the record's comparison of the client log with the capture |
| `metadata` | none: identity, versions, configuration and file references |

<!-- columns: generated by `export_csv.py --columns`; src/tests/test_export_csv.py checks this table -->

| Column | Source | Meaning |
|---|---|---|
| `run_id` | metadata | `<UTC>_<scenario>_<client>_r<NN>`; the record's file name |
| `schema_version` | metadata | run record schema version |
| `session_id` | metadata | orchestrator session (one batch) |
| `scenario` | metadata | scenario ID (C0, S1-S6, or a generated extension ID) |
| `scenario_label` | metadata | scenario name |
| `repetition` | metadata | repetition number within the session, from 1 |
| `client` | metadata | client label, e.g. `curl`, `chromium`, `curl@he200` |
| `client_name` | metadata | client implementation: `curl` or `chromium` |
| `client_variant` | metadata | curl configuration variant, e.g. `he200`; empty for none |
| `client_version` | metadata | version string as the client reported it |
| `git_commit` | metadata | code version that made the record (`-dirty` = uncommitted changes) |
| `kernel` | metadata | lab host kernel |
| `run_start_utc` | metadata | run start, ISO 8601 UTC |
| `measured_rtt_v4_ms` | lab verify | IPv4 RTT measured by ping before the run (median); not_observed for a blackhole |
| `measured_rtt_v4_ms_status` | lab verify | status of measured_rtt_v4_ms: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `measured_rtt_v6_ms` | lab verify | IPv6 RTT measured by ping before the run (median); not_observed for a blackhole |
| `measured_rtt_v6_ms_status` | lab verify | status of measured_rtt_v6_ms: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `pre_verify_ok` | lab verify | lab verify passed before the run |
| `post_restore_verify_ok` | lab verify | lab verify passed after restoring the baseline |
| `success` | client | client completed the request and got an HTTP response |
| `exit_code` | client | process exit code (empty for clients without one) |
| `http_status` | client | HTTP status the client reported |
| `error` | client | client error text, if any |
| `client_remote_ip` | client | address the client says it connected to |
| `winning_family` | packet | `v4` or `v6`: family of the completed handshake that carried data |
| `winning_family_status` | packet | status of winning_family: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `tcp_setup_time_ms` | packet | first SYN to the ACK completing the winning handshake; excludes DNS |
| `tcp_setup_time_ms_status` | packet | status of tcp_setup_time_ms: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `inter_family_attempt_delay_ms` | packet | second family's first SYN minus first family's first SYN; not_observed if only one family was tried |
| `inter_family_attempt_delay_ms_status` | packet | status of inter_family_attempt_delay_ms: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `dns_time_ms` | packet | first DNS query to last DNS answer for the target name, before the first SYN |
| `dns_time_ms_status` | packet | status of dns_time_ms: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `failed_or_abandoned_attempts` | packet | attempts that did not win |
| `failed_or_abandoned_attempts_status` | packet | status of failed_or_abandoned_attempts: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `attempts` | packet | number of connection attempts (SYNs to port 80 on distinct 4-tuples) |
| `attempt_shape` | packet | families of the attempts in SYN order, e.g. `v6>v6>v4` |
| `syn_retransmits` | packet | kernel SYN retransmissions, summed over attempts (not attempts) |
| `oracle_setup_ms` | derived | the winning family's pre-run ping RTT (`metrics.oracle_baseline`) |
| `oracle_setup_ms_status` | derived | status of oracle_setup_ms: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `cost_of_racing_ms` | derived | tcp_setup_time_ms minus oracle_setup_ms; not clamped, may be negative |
| `cost_of_racing_ms_status` | derived | status of cost_of_racing_ms: computed, not_observed, not_applicable, not_yet_computed (or not_available for derived columns) |
| `cross_checks_status` | cross-check | `agree`, `conflict`, `not_yet_computed` or `not_applicable` |
| `cross_check_conflicts` | cross-check | conflicting fields, `;`-separated; empty when they agree |
| `pcap_path` | metadata | packet capture, relative to the repo root |
| `pcap_sha256` | metadata | SHA-256 of the capture as saved |

## Evidence tags

The report, dashboard and summaries label every statement with one of four evidence tags, the
same four in the report's Conventions section ([`report.md`](report.md)), the dashboard
(`src/analysis/dashboard.py`), the [README](../README.md) and [`pseudocode.md`](pseudocode.md).
Derived is the tag of the oracle baseline and the cost of racing (`src/analysis/oracle.py`).

| Tag | Meaning | Where it lives | In the CSV |
|---|---|---|---|
| **[Packet-level (pcap)]** | From the packet capture taken inside the client namespace (`hl-client`). Packet-level evidence: all timings, the winning family, attempts and DNS times. | `packet_observations`, `metrics`, and the pcap itself | `packet` |
| **[Client log]** | What a client reported about itself, or what the runner recorded: curl's `-w` output, Chromium's NetLog and Playwright fields, exit codes, HTTP status. These are outcomes, not packet-level evidence. | `outcome`, `outcome.client_report`, the client log and NetLog | `client` |
| **[Derived (pcap − lab RTT)]** | Packet-level TCP setup time combined with the winning family's RTT measured by the lab's ping check before the run (`metrics.oracle_baseline`). It is computed, not seen on the wire, and is never shown as packet-level or client log. | not stored; computed from `metrics` and `scenario.measured_rtt_ms` | `derived` |
| **[Interpretation]** | Our reading of the evidence above. It is never a measurement. | the report, dashboard and `summary.json` only; never in a run record | never |

Keep the tags with the values when you load them. A system that merges them, for example by
storing a client-reported `remote_ip` next to the packet-level `winning_family` without saying
which is which, loses the distinction the measurements depend on. Where client log and capture
disagree, the record keeps both in `cross_checks.conflicts`; neither is overwritten.

Wording that applies to anything built on these records: RFC 8305's 250 ms is a reference, not a
threshold, and the records support no claim of conformance to RFC 8305 or the Happy Eyeballs v3
draft (pinned at draft-ietf-happy-happyeyeballs-v3-04; its status is in the
[report's references](report.md#47-references)). The latency scenarios are mobile-inspired latency conditions, not carrier measurements.
