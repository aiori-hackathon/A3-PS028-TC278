Include your code files in the src folder to demonstrate your implementation.

## Layout

| Path | Contents |
|---|---|
| `src/runner/` | Client runners and the orchestrator (`client_curl.py`, later `client_chromium.py`, `orchestrate.py`). |
| `src/analysis/` | Run-record validator, pcap parser and metric calculations. |
| `src/tests/` | pytest tests for parsing, validation and metrics. |
| `src/lab/` | Namespace setup, teardown and verify scripts (added when the lab is built). |
| `src/config/` | `scenarios.yaml`, nginx config (added when the lab is built). |
| `src/dns/` | Test-zone DNS server with AAAA delay (added for S6). |
| `src/dashboard/` | Dashboard (added after data collection). |

Data stays outside `src/`: packet captures in `captures/` and run records in
`data/generated/`. Both are gitignored.
