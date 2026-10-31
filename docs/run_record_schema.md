# Run-record schema (version 0.2)

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
- Interpretations never go in a run record. They belong in the report and dashboard, labelled as interpretation.

## Fields

### Top level (all required, no other keys allowed)

| Key | Type | Notes |
|---|---|---|
| `schema_version` | string | `"0.2"` (`"0.1"` accepted for old records) |
| `run_id` | string | `<UTC yyyymmddThhmmssZ>_<scenario>_<client>_r<NN>`, e.g. `20261026T101500Z_C0_curl_r01` |
| `scenario` | object | see below |
| `client` | object | see below |
| `environment` | object | free-form strings: kernel, gai.conf in use, resolver, git commit, etc. |
| `timestamps` | object | see below |
| `outcome` | object | see below |
| `evidence` | object | see below |
| `packet_observations` | object | wrapped fields, see below |
| `metrics` | object | wrapped fields, see below |
| `cross_checks` | object | 0.2 only: client/runner log versus pcap, see below |

### `scenario`

| Key | Type | Notes |
|---|---|---|
| `id` | string | One of `C0`, `S1`–`S6`, `X1`, or `harness-test`. `harness-test` marks runs that test the tooling (for example, the loopback curl run). They are never measurement data. |
| `label` | string | Human-readable name. |
| `repetition` | integer ≥ 1 | |
| `netem` | object or null | Configured impairment per link. Configuration only; it is **not** ground truth. null for `harness-test`. |
| `dns` | object or null | e.g. `{"aaaa_delay_ms": 300}`. |
| `measured_rtt_ms` | object | `{"v4": <wrapped>, "v6": <wrapped>}`. RTT measured before the scenario. |

### `client`

| Key | Type | Notes |
|---|---|---|
| `name` | string | `curl` or `chromium` |
| `version` | string | Exact version string as reported by the client. |
| `argv` | list of strings | The exact command run (for Chromium: launch args). |
| `config` | object | Settings that affect connection behaviour, recorded even when left at default. |

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
