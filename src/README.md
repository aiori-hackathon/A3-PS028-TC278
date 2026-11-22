# HappyLab source

See the [top-level README](../README.md) for what the lab measures and how to reproduce it.

| Path | Contents |
|---|---|
| `lab/` | Lab scripts: `setup.sh`, `teardown.sh`, `verify.sh` (measures the real RTT), `netem.sh` (one link's impairment), shared `lib.sh`, and `lab.env` (all names and addresses). |
| `config/` | `scenarios.yaml` (C0 and S1–S6, with verify targets; hand-written and pinned by a test), `scenario_grid.yaml` and the generated `scenarios_generated.yaml` (extension scenarios such as `Gv6d200`, `Gv6l10` (partial loss) and `Gv6j50` (jitter); regenerate with `runner/scenario_grid.py`), and `nginx.conf` for the server in `hl-server`. |
| `dns/` | `hl_dns.py`: authoritative DNS for `www.hl.test` (dnslib), with an optional delay per record type. |
| `runner/` | `orchestrate.py` (the per-run loop), `run_matrix.py` (all 14 batches), `client_curl.py`, `client_chromium.py` (Playwright), `clients.py` (including curl variants such as `curl@he200`), `scenario_grid.py` (writes the generated scenarios), `band_pilot.py` (applies each loss/jitter scenario and runs verify only, before a campaign), `child_env.py` (strips `PYTHONPATH`/`LD_LIBRARY_PATH` from every child process), `finalise_record.py`. |
| `analysis/` | `parse_pcap.py` (pcap reader and connection timeline), `metrics.py` (the fixed metrics and cross-checks), `validate_record.py`, `check_batch.py`, `scenario_config.py` (reads the scenario IDs from both scenario files), `names.py` (client labels, the `@`→`-` file-name rule, scenario-ID rules), `variant_control.py` (curl@he200 against plain curl), `syn_retransmit.py` (SYN retransmission timing, setup-time clusters and win fraction from the pcaps), `jitter_model.py` (predicted against observed IPv6 win fraction in the jitter cells, every input measured in the lab), `summarise.py` (`--dataset` selects a manifest), `summarise_session.py`, `dashboard.py`, `race.py` (race timeline data for the dashboard), `export_web.py`. |
| `tests/` | The pytest suite (run it with `scripts/test.sh`), `pcapgen.py` for synthetic captures, and two small lab-only fixture pcaps in `fixtures/`. |

Data stays outside `src/`. Packet captures go in `captures/` and run records in
`data/generated/`. Both are gitignored, and two example runs are committed in `../examples/`.

Campaign tooling for the latency and curl@he sweeps: `runner/run_campaigns.py` chains the
fractional-delay check, campaign 2 (`latency-sweep`) and campaign 3 (`he-sweep`). It writes each
manifest and restores the baseline at the end. `runner/fractional_delay_check.py` checks that netem
realises a half-millisecond delay each way, which odd "+N ms RTT" scenarios need, and
`analysis/crossover.py` reports the outcome flip and the packet-measured T for both datasets.
