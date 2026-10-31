# HappyLab source

See the [top-level README](../README.md) for what the lab measures and how to reproduce it.

| Path | Contents |
|---|---|
| `lab/` | Lab scripts: `setup.sh`, `teardown.sh`, `verify.sh` (measures the real RTT), `netem.sh` (one link's impairment), shared `lib.sh`, and `lab.env` (all names and addresses). |
| `config/` | `scenarios.yaml` (C0 and S1–S6, with verify targets) and `nginx.conf` for the server in `hl-server`. |
| `dns/` | `hl_dns.py`: authoritative DNS for `www.hl.test` (dnslib), with an optional delay per record type. |
| `runner/` | `orchestrate.py` (the per-run loop), `run_matrix.py` (all 14 batches), `client_curl.py`, `client_chromium.py` (Playwright), `clients.py`, `child_env.py` (strips `PYTHONPATH`/`LD_LIBRARY_PATH` from every child process), `finalise_record.py`. |
| `analysis/` | `parse_pcap.py` (pcap reader and connection timeline), `metrics.py` (the fixed metrics and cross-checks), `validate_record.py`, `check_batch.py`, `summarise.py`, `summarise_session.py`, `dashboard.py`, `export_web.py`. |
| `tests/` | The pytest suite (run it with `scripts/test.sh`), `pcapgen.py` for synthetic captures, and two small lab-only fixture pcaps in `fixtures/`. |

Data stays outside `src/`. Packet captures go in `captures/` and run records in
`data/generated/`. Both are gitignored, and two example runs are committed in `../examples/`.
