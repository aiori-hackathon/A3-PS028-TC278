# Example runs: record and packet capture

The full dataset (280 run records and their captures) lives on the lab machine. `captures/` and
`data/generated/` are not in Git. This folder holds two runs from that dataset, copied unchanged, so
a reviewer can check a record against its capture without access to the lab.

| Run | Scenario | Client | Record | Capture |
|---|---|---|---|---|
| `20261026T192159Z_C0_curl_r07` | C0 healthy baseline | curl 8.5.0 | 4,219 bytes | 1,754 bytes |
| `20261026T193106Z_S1_curl_r08` | S1 IPv6 blackhole | curl 8.5.0 | 4,389 bytes | 1,670 bytes |

Both come from the dataset in [`docs/dataset.md`](../docs/dataset.md) (sessions `20261026T192045Z`
and `20261026T192924Z`, code `ecba28c`). They are the C0 and S1 curl runs that the website's Evidence
page shows.

## What the records say

All figures below are packet-level, read from the capture by `src/analysis/parse_pcap.py`.

| | C0 r07 | S1 r08 |
|---|---|---|
| Winning family | IPv6 | IPv4 |
| TCP setup time | 20.695 ms | 222.254 ms |
| Inter-family attempt delay | not observed (only IPv6 tried) | 200.976 ms |
| Failed or abandoned attempts | 0 | 1 (the IPv6 attempt) |
| DNS time | 1.092 ms | 1.069 ms |
| HTTP status (client log) | 200 | 200 |
| Cross-checks | agree | agree |
| Measured RTT before the run (ping) | v4 21.1 ms, v6 21.1 ms | v4 21.15 ms; v6 blackhole, 100% loss, 0 ICMP errors |

## Checking them

```
sha256sum -c SHA256SUMS                   # both captures and both records
grep pcap_sha256 *.json                   # each record stores its capture's SHA-256
tcpdump -nn -r 20261026T193106Z_S1_curl_r08.pcap
```

- **Stored paths:** the record's `evidence.pcap_path` still reads `captures/<run_id>.pcap`, the path on the lab machine.
  The records were not edited.
- **Link type:** the captures are Linux cooked v2 (`tcpdump -i any`), which stores interface numbers, not
  names. tcpdump warns that interface names may be wrong. The record's
  `environment.capture_interfaces` holds the map: 2 = `hl-v4c`, 3 = `hl-v6c`, 4 = `hl-ctlc`.
- **Re-parsing:** to re-parse a capture into its connection timeline (SYN, SYN-ACK and ACK times per attempt, and DNS exchanges), run `env -u PYTHONPATH .venv/bin/python -c "import sys;
  sys.path.insert(0,'src'); from analysis.parse_pcap import parse; print(parse('examples/<run_id>.pcap'))"`
  from the repository root.
