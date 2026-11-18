# Example runs: record and packet capture

The full dataset (280 run records and their captures) lives on the lab machine. `captures/` and
`data/generated/` are not in Git. This folder holds three runs from that dataset, copied unchanged, so
a reviewer can check a record against its capture without access to the lab.

| Run | Scenario | Client | Record | Capture |
|---|---|---|---|---|
| `20261026T192159Z_C0_curl_r07` | C0 healthy baseline | curl 8.5.0 | 4,219 bytes | 1,754 bytes |
| `20261026T193106Z_S1_curl_r08` | S1 IPv6 blackhole | curl 8.5.0 | 4,389 bytes | 1,670 bytes |
| `20261026T193420Z_S1_chromium_r01` | S1 IPv6 blackhole | Chromium 156.0.8078.4 | 8,757 bytes | 20,186 bytes |

All three come from the dataset in [`docs/dataset.md`](../docs/dataset.md) (sessions `20261026T192045Z`,
`20261026T192924Z` and `20261026T193419Z`, code `ecba28c`).
- **curl runs:** the C0 and S1 curl runs are the ones the website's Evidence page shows.
- **Chromium run:** it shows the second IPv6 SYN described in
  [`docs/findings/chromium_s1_second_v6_syn.md`](../docs/findings/chromium_s1_second_v6_syn.md).
  "Chromium" here is Google Chrome for Testing 156.0.8078.4 (branch-heads/8078@{#13}); see report §1.3.

## What the records say

All figures below are packet-level, read from the capture by `src/analysis/parse_pcap.py`.

| | curl C0 r07 | curl S1 r08 | Chromium S1 r01 |
|---|---|---|---|
| Winning family | IPv6 | IPv4 | IPv4 |
| TCP setup time | 20.695 ms | 222.254 ms | 324.766 ms |
| Inter-family attempt delay | not observed (only IPv6 tried) | 200.976 ms | 301.266 ms |
| Failed or abandoned attempts | 0 | 1 (the IPv6 attempt) | 2 (two IPv6 attempts, source ports 58826 and 58830; the second SYN at +250.290 ms) |
| DNS time | 1.092 ms | 1.069 ms | 0.756 ms |
| HTTP status (client log) | 200 | 200 | 200 |
| Cross-checks | agree | agree | agree |
| Measured RTT before the run (ping) | v4 21.1 ms, v6 21.1 ms | v4 21.15 ms; v6 blackhole, 100% loss, 0 ICMP errors | v4 21.2 ms; v6 blackhole, 100% loss, 0 ICMP errors |

- **SYN retransmissions:** none in any of the three runs.
- **The two IPv6 attempts in the Chromium run:** they come from different sockets: a different source port,
  initial sequence number and TCP timestamp.
- **Other traffic in the Chromium capture:** it also holds Chromium's startup DNS queries for Google hostnames,
  which the lab DNS server refuses. The record's DNS time counts only `www.hl.test` queries.

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
