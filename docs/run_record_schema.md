# Run-record schema (version 0.1)

One JSON file per run, written to `data/generated/runs/<run_id>.json`.
A worked example is in [`examples/run_record_example.json`](examples/run_record_example.json).
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
| `schema_version` | string | `"0.1"` |
| `run_id` | string | `<UTC yyyymmddThhmmssZ>_<scenario>_<client>_r<NN>`, e.g. `20261026T101500Z_C0_curl_r01` |
| `scenario` | object | see below |
| `client` | object | see below |
| `environment` | object | free-form strings: kernel, gai.conf in use, resolver, git commit, etc. |
| `timestamps` | object | see below |
| `outcome` | object | see below |
| `evidence` | object | see below |
| `packet_observations` | object | wrapped fields, see below |
| `metrics` | object | wrapped fields, see below |

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
