# Chromium in S1: the second IPv6 SYN about 250 ms after the first

**Question:** in Chromium's S1 runs the capture shows two IPv6 SYNs about 250 ms apart before the
IPv4 SYN at about 301 ms. Is the second SYN the kernel's TCP SYN retransmission, or a new
connection attempt by Chromium?

**Answer:** it is a **new connection attempt made by Chromium**, not a kernel retransmission.
Chromium's NetLog records it as a separate socket-pool connect job marked `backup_job: true`.
The IPv4 SYN at about 301 ms comes from the **first** connect job's `second` connector.
It is not part of the backup job.

Runs examined: Chromium 156.0.8078.4 via Playwright 1.64.1, all on 2026-10-26.
- Clean pilot (session `20261026T125239Z`): `20261026T125321Z_S1_chromium_r01`, `…125337Z…r02`, `…125353Z…r03`.
- First pilot (session `20261026T123827Z`, superseded config): `20261026T123909Z_S1_chromium_r01`, `…123925Z…r02`. The same pattern appears there too.

## Packet-level evidence (pcap)

| Run | 1st v6 SYN | 2nd v6 SYN | v4 SYN | v6 source ports | SYNs per v6 socket |
|---|---|---|---|---|---|
| 125321Z r01 | +0 ms | +250 ms | +301 ms | 51398, 51400 | 1, 1 |
| 125337Z r02 | +0 ms | +250 ms | +300 ms | 46174, 46180 | 1, 1 |
| 125353Z r03 | +0 ms | +250 ms | +301 ms | 39426, 39440 | 1, 1 |
| 123909Z r01 | +0 ms | +250 ms | +302 ms | 51126, 51132 | 1, 1 |
| 123925Z r02 | +0 ms | +250 ms | +302 ms | 48846, 48856 | 1, 1 |

- **The second v6 SYN comes from a different source port** in every run, so it is a different
  socket. A kernel SYN retransmission reuses the same socket and 4-tuple; the parser counts those
  as `syn_retransmits`, which are 0 for every attempt here.
- **No v6 socket sent a second SYN.** Each capture continued 1053–1093 ms after the first v6 SYN.
  Neither v6 socket sent a FIN or RST, which is consistent with Chromium closing them while they
  were still connecting, once IPv4 had won.

## Client-log evidence (Chromium NetLog, `data/generated/logs/<run_id>_netlog.json`)

`TCP_CONNECT_JOB_CONNECTOR_CONNECT_START` events for the `http://www.hl.test` socket group
(identical shape in all five runs; times relative to the first entry):

| NetLog time | Connect job | `backup_job` | `connector` | Address |
|---|---|---|---|---|
| +0 ms | A (e.g. id 116) | false | first | `[2001:db8:28:6::2]:80` |
| +249–250 ms | B (e.g. id 149) | **true** | first | `[2001:db8:28:6::2]:80` |
| +300–302 ms | A | false | **second** | `192.0.2.2:80` |

Each NetLog entry lines up with a pcap SYN to within 1 ms once converted to wall-clock time
(NetLog time + `timeTickOffset`), and the v4 socket's local port matches the pcap's v4 SYN port.
In C0 there is only one entry (job A, `first`, IPv6), because the handshake finishes in about 20 ms.

## Interpretation (labelled as such)

- Chromium labels the second v6 SYN `backup_job: true`. It is an extra attempt to the same
  address, started when the first one hadn't connected after about 250 ms. It is not an
  IPv4/IPv6 Happy Eyeballs step: it targets the same family and address.
- The IPv4 attempt is the first job switching to its other connector about 300 ms after it started.
  That is the step that matches the scenario's purpose: falling back from IPv6 to IPv4.
- The 250 ms and 300 ms values are **observed** in 5 of 5 S1 runs. Calling them fixed timers
  would be an inference about Chromium internals; the report should give them as observed
  delays, not documented constants.
- The two abandoned attempts per S1 run counted in `failed_or_abandoned_attempts` are therefore
  one original IPv6 attempt and one backup IPv6 attempt. For curl in S1 the count is 1, because
  curl made no backup attempt.

## How it is recorded from now on

`client_chromium.py` now writes these NetLog entries into every Chromium record as
`outcome.client_report.connect_jobs`: `t_ms`, `epoch_ms`, `job`, `backup_job`, `connector` and `address`.
This is client-reported, not packet-level. The five records listed above were written before
this field existed, so this note is their reference.

## Suggested report wording

> In S1, Chromium's capture shows a second IPv6 SYN about 250 ms after the first, from a new
> source port. Chromium's NetLog records it as a separate backup connection attempt to the same
> IPv6 address, not a TCP retransmission. The IPv4 attempt followed about 300 ms after the first
> SYN, from the original connection attempt's second connector. These delays were observed in all
> five S1 runs; they are not documented values.
