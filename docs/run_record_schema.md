# Run-record schema (version 0.4)

Version 0.4 adds the optional `client.variant` (a curl configuration such as `he200`; see
[Client variants and file names](#client-variants-and-file-names)) and allows generated extension
scenario IDs such as `Gv6d200`. Earlier records remain valid and may contain neither.
Version 0.3 adds two optional blocks, `profile` (measurement cost) and `adaptive` (the
adaptive-repetition stopping rule's state). Records of earlier versions remain valid and may not
contain them; the core dataset's records are 0.2 and are not rewritten.
Version 0.2 adds the required `cross_checks` block. 0.1 records (the Milestone 1 harness
runs) remain valid and must not contain it.

One JSON file per run, written to `data/generated/runs/<run_id>.json`.
An illustrative example is in [`examples/run_record_example.json`](examples/run_record_example.json).
It was written by hand before any measurement ran, so it shows the field layout and the
`not_yet_computed` status, not real values; the validator tests use it as their base record.
Real records written by the orchestrator, with their packet captures, are in
[`../examples/`](../examples/).
The validator is `src/analysis/validate_record.py`:

```
.venv/bin/python -m analysis.validate_record <file.json> [...]   # run from src/, or with PYTHONPATH=src
```

## The `{value, status}` pattern

Every value that is derived from a capture or a measurement is wrapped:

```json
{ "value": null, "status": "not_yet_computed" }
```

| status | `value` must be | Meaning |
|---|---|---|
| `computed` | not null | Value was derived and is stored. |
| `not_yet_computed` | null | The derivation has not run yet (for example, the pcap has not been parsed). |
| `not_observed` | null | The derivation ran and the event was not in the evidence (for example, only one address family was tried). |
| `not_applicable` | null | The field does not apply to this record (for example, a per-scenario aggregate in a per-run record). |

A wrapped field may also carry an optional `"note"` string.
So a null always says *why* it is null, and "not observed" is never confused with "not computed".

## Evidence sources

- `packet_observations` and the packet-derived `metrics` come from the **packet capture**.
  These are packet-level evidence.
- `outcome` comes from the **client and runner logs**. It records what the client reported.
- `profile` and `adaptive` are **runner measurements and runner decisions**: what the run cost
  and whether the stopping rule asked for more runs. They are not evidence about client behaviour.
- Interpretations never go in a run record. They belong in the report and dashboard, labelled as interpretation.

## Fields

### Top level (all required, no other keys allowed)

| Key | Type | Notes |
|---|---|---|
| `schema_version` | string | `"0.4"` (`"0.3"`, `"0.2"` and `"0.1"` accepted for old records) |
| `run_id` | string | `<UTC yyyymmddThhmmssZ>_<scenario>_<client>_r<NN>`, e.g. `20261026T101500Z_C0_curl_r01`. `<client>` is the client label in its file-name form (`@` written as `-`), e.g. `20261121T101500Z_S1_curl-he200_r01` |
| `scenario` | object | see below |
| `client` | object | see below |
| `environment` | object | free-form strings: kernel, gai.conf in use, resolver, git commit, etc. |
| `timestamps` | object | see below |
| `outcome` | object | see below |
| `evidence` | object | see below |
| `packet_observations` | object | wrapped fields, see below |
| `metrics` | object | wrapped fields, see below |
| `cross_checks` | object | 0.2 and later: client/runner log versus pcap, see below |
| `profile` | object | 0.3 and later, optional: measurement cost of this run, see below |
| `adaptive` | object | 0.3 and later, optional: present only in adaptive sessions, see below |

### `scenario`

| Key | Type | Notes |
|---|---|---|
| `id` | string | One of `C0`, `S1`–`S6`, `X1`, or `harness-test`; from 0.4 also a generated extension ID (`G<v4\|v6><d\|l><N>`, e.g. `Gv6d200`, see below). `harness-test` marks runs that test the tooling (for example, the loopback curl run). They are never measurement data. |
| `label` | string | Human-readable name. |
| `repetition` | integer ≥ 1 | |
| `netem` | object or null | Configured impairment per link. Configuration only; it is **not** ground truth. null for `harness-test`. |
| `dns` | object or null | e.g. `{"aaaa_delay_ms": 300}`. |
| `measured_rtt_ms` | object | `{"v4": <wrapped>, "v6": <wrapped>}`. RTT measured before the scenario. |

### `client`

| Key | Type | Notes |
|---|---|---|
| `name` | string | The client **implementation**: `curl` or `chromium`. A variant never changes it. |
| `variant` | string | 0.4, optional, curl only: the configuration variant, e.g. `he200` for `--happy-eyeballs-timeout-ms 200`. Absent for plain curl and for Chromium. |
| `version` | string | Exact version string as reported by the client. |
| `argv` | list of strings | The exact command run (for Chromium: launch args). |
| `config` | object | Settings that affect connection behaviour, recorded even when left at default. For curl, `happy_eyeballs_timeout_ms` is `"default (not set)"` without a variant, and the value actually passed (an integer, e.g. `200`) with one. |

The validator checks that a variant is consistent: `argv` carries exactly one
`--happy-eyeballs-timeout-ms N` with the variant's N, `config.happy_eyeballs_timeout_ms` is that
N, and plain curl carries neither.

### Client variants and file names

A **client label** names what was run: `curl`, `chromium`, or a curl variant `curl@he<N>` (curl
with `--happy-eyeballs-timeout-ms N`, N a whole number 1–60000 written without a leading zero).
Chromium takes no variants. A variant is a configuration of curl, not another client: PS-028's
"2 client implementations or versions" are curl and Chromium. In records the label is split into
`client.name` (the implementation) and `client.variant`; summaries and the dashboard list a variant
under curl, beside plain curl, never as a further client.

**Sanitisation rule.** In every file name and path, a client label is written with `@` replaced by
`-`: `curl@he200` becomes `curl-he200`. The rule is applied once, in the run ID
(`orchestrate.make_run_id`, via `analysis.names.file_token`), and every per-run file is named after
the run ID: the record (`data/generated/runs/<run_id>.json`), the pcap (`captures/<run_id>.pcap`),
the client log and the Chromium NetLog. `run_matrix.py` batch logs use the same form. The mapping
is reversible (`analysis.names.label_from_file_token`) because implementation names contain no `-`.
Dataset manifests, CLI arguments and summaries use the label itself (`curl@he200`).

### Generated extension scenarios

C0 (baseline) and S1–S6 (PS-028's six required scenarios) are defined by hand in
`src/config/scenarios.yaml`. Further scenarios are generated from `src/config/scenario_grid.yaml`
by `src/runner/scenario_grid.py` into `src/config/scenarios_generated.yaml`, every one marked
`extension: true`. Their IDs are `G` + family + `d` (delay, "+N ms RTT") or `l` (loss, N %) + N,
e.g. `Gv6d200`. A generated ID that equals or looks like a core ID (`C0`, `S1`–`S6`, `X1`, or any
`C`/`S`/`X` + digits) is rejected by the generator and by the loader.

### `timestamps`

| Key | Type | Notes |
|---|---|---|
| `run_start_utc` | string | ISO 8601 UTC, ending in `Z`. |
| `client_start_epoch_ns`, `client_end_epoch_ns` | integer | Wall clock (`time.time_ns()`) just before starting and just after the client exits. End ≥ start. |
| `capture_start_epoch_ns`, `capture_end_epoch_ns` | integer or null | null when no capture was taken. |

### `outcome` (from client and runner logs)

| Key | Type | Notes |
|---|---|---|
| `success` | boolean | Client completed the request and got an HTTP response. |
| `exit_code` | integer or null | Process exit code (null for clients without one). |
| `http_status` | integer or null | |
| `error` | string or null | Client error text if any. |
| `source` | string | Where the outcome came from, e.g. `"client/runner log"`. |
| `client_report` | object, optional | What the client printed about itself. Client-reported, not packet-level. curl (`-w`): `http_code`, `remote_ip`, `time_namelookup_s`, `time_connect_s`, `time_total_s`, `num_connects`. Chromium (`src/runner/client_chromium.py`, Playwright): `ok`, `error`, `http_status`, `remote_ip`, `remote_port`, `timing_ms` (Navigation Timing), `browser_version`, `playwright_version`, `launch_args`, `headless_mode`, `sandbox`, `url`, `netlog_path` (the run's NetLog, relative to the repo root), `launch_check` (`ok`, or why the command line Chromium received was not as intended), `connect_jobs` (every TCP connection start the NetLog records for the target host: `t_ms`, `epoch_ms`, `job`, `backup_job`, `connector`, `address`; see [findings/chromium_s1_second_v6_syn.md](findings/chromium_s1_second_v6_syn.md)), `resolved` (address order from Chromium's built-in DNS task for the target host: `addresses`, `families`, `resolver`). |

### `evidence`

| Key | Type | Notes |
|---|---|---|
| `pcap_path` | string or null | Relative to the repo root. null when no capture was taken. |
| `pcap_sha256` | string or null | Hash of the pcap as saved. Raw captures are never modified. |
| `client_log_path` | string or null | |
| `pre_verify_ok`, `post_restore_verify_ok` | boolean or null | Lab verify results. null when not run (e.g. harness tests). |

### `packet_observations` (wrapped, from the pcap)

| Key | `value` when computed |
|---|---|
| `winning_family` | `"v4"` or `"v6"` |
| `attempts` | list of attempt objects (below) |
| `failed_or_abandoned_attempts` | integer ≥ 0 |

Attempt object: `family` (`v4`/`v6`), `dst` (address), `src_port`, `first_syn_ns`, `syn_retransmits`,
`result` (`won`, `failed`, `abandoned` or `no_reply`).

### `metrics` (wrapped)

Fixed definitions (from CLAUDE.md; do not redefine):

| Key | Definition | Unit |
|---|---|---|
| `dns_time_ms` | DNS query to answer, recorded separately from TCP setup. | ms, ≥ 0 |
| `tcp_setup_time_ms` | First SYN to the ACK completing the winning handshake. | ms, ≥ 0 |
| `inter_family_attempt_delay_ms` | Second family's first SYN minus first family's first SYN. `not_observed` if only one family is tried. | ms, ≥ 0 |
| `scenario_penalty_ms` | Client's median setup time in a scenario minus its own C0 median. A per-scenario aggregate, so always `not_applicable` in a per-run record; it lives in the scenario summary. | ms |

### How attempts are classified (`src/analysis/metrics.py`)

These are project rules applied to packet-level facts from `src/analysis/parse_pcap.py`:

- An **attempt** is one client SYN (plus its retransmissions on the same 4-tuple) **to the target
  port (80)**. SYNs to any other port are not attempts; they are reported as unexpected traffic.
- The **winning attempt** is the completed handshake on which the client sent data.
  If more than one connection carried data, the run is **ambiguous**: nothing is picked,
  winner-dependent fields stay `not_yet_computed` with a note, and `cross_checks` reports a conflict.
- Every other attempt is `failed` if the server answered with RST, otherwise `abandoned` when a
  winner exists, and `no_reply` when no attempt succeeded.
- **DNS time** (project definition, not one of the three fixed metrics): first DNS query to the
  last DNS answer, among queries **for the target name (`www.hl.test`)** sent before the first SYN.
  Queries for other names are listed in the notes and not counted.
- Each run is parsed within its own time window (client start to capture end), so stray packets
  from before or after the run are ignored.

### `cross_checks` (0.2, required)

Compares the client/runner log (outcome) with the capture (packet-level evidence).
Neither side is overwritten and nothing is chosen silently.

| Key | Type | Notes |
|---|---|---|
| `status` | string | `agree`, `conflict`, `not_yet_computed` or `not_applicable` |
| `conflicts` | list | Empty unless `status` is `conflict`. Each item: `field`, `log_value`, `pcap_value`, `note`. |

Checks, for every client:

| `field` | Conflict when |
|---|---|
| `winner` | more than one port-80 connection carried client data (ambiguous; nothing is picked) |
| `success` | the client's success/failure disagrees with whether the capture has a completed port-80 connection with an HTTP response |
| `http_status` | the client's HTTP status differs from the one in the captured response |
| `remote_ip` | the client's reported address differs from the winning handshake's destination (compared as canonical addresses), **or** the client reported success without any address, so the winning family could not be checked |
| `unexpected_traffic` | the capture has any TCP or UDP packet on port 443 (QUIC, HTTPS upgrade) or a TCP attempt to a port other than 80 |
| `capture` | tcpdump reports dropped packets or did not write every packet it matched |

A run with `status: conflict` needs a person to look at it before it is used in any summary.

#### Winning family for Chromium runs

curl prints the address it connected to (`%{remote_ip}`). Chromium does not print anything, so
the log side is defined explicitly for Chromium:

- **Log side (client-reported):** `client_report.remote_ip` is Playwright's
  `Response.server_addr()["ipAddress"]` for the **main document response**, which is the
  DevTools `Network.responseReceived` `remoteIPAddress`. It is normalised to the canonical form
  (DevTools may wrap IPv6 in `[...]`). Its family is `v6` if it parses as IPv6, otherwise `v4`.
  This is what the browser reports, not what was seen on the wire.
- **Packet side:** the same rule as curl: the completed handshake to port 80 that carried client data.
- They are compared by the `remote_ip` check above. If the browser reports success but no address,
  that is a conflict, not a silent pass.
- The Chromium page (`/chromium.html`) carries a `data:` icon so the browser does not open a second
  connection for `/favicon.ico`; with keep-alive off, that would make every run ambiguous.
- The run's NetLog is kept as raw client evidence but is **not** used in cross_checks yet.

### `profile` (0.3, optional; runner measurements)

| Key | Type | Notes |
|---|---|---|
| `wall_time_s` | number | From the start of the run (before the DNS and nginx checks) to the end of parsing the capture, before the record is written. Includes netem apply, both lab verifies, capture, client, restore and parsing. |
| `wall_time_scope` | string | That definition, stored with the value |
| `pcap_bytes` | integer | Size of this run's pcap file |
| `client_peak_rss_kib` | integer or null | `ru_maxrss` returned by `wait4` for the client command: the peak resident memory of the **largest single process** among the client command and its reaped descendants, in KiB. Not a sum over processes, so for Chromium it is not the browser's total memory. Nothing is sampled while the client runs, so the timed connection is not disturbed. |
| `client_peak_rss_scope` | string | That definition, stored with the value |

### `adaptive` (0.3, optional; runner decision)

Written only when the orchestrator runs with `--reps-adaptive MIN MAX --ci-width-ms W`. Records
are written once, as each run finishes, so each record holds the rule's state **after that run**.
The final stopping reason and CI per scenario are in the last record of the session and in
`data/generated/lab/<session>_adaptive.json`.

| Key | Type | Notes |
|---|---|---|
| `min_reps`, `max_reps` | integer | `1 <= min_reps <= max_reps` |
| `ci_width_ms` | number | Stop once the CI is no wider than this |
| `metric` | string | Always `tcp_setup_time_ms` |
| `after_this_run.n_runs` | integer | Runs in this scenario so far, including this one |
| `after_this_run.n_values` | integer | Of those, runs with a TCP setup time (the CI uses only these) |
| `after_this_run.median_ms` | number or null | Median TCP setup time so far |
| `after_this_run.ci` | object or null | `{lo, hi, width, level, n, resamples, seed, method}`: 95% percentile bootstrap of the median, 10 000 resamples, seed 0 (`analysis.metrics.bootstrap_median_ci`). Null with fewer than 2 values. |
| `after_this_run.decision` | string | `continue` or `stop` |
| `after_this_run.reason` | string or null | On a stop: `ci_width_reached` or `max_reps_reached`. Null on `continue`. |

The rule (`analysis.metrics.adaptive_decision`) never looks at the median's value, only at the CI
width and the run count. `summarise.py` recomputes it from the setup times and refuses a session
whose recorded decisions do not replay identically.

