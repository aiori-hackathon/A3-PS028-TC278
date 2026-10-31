# HappyLab technical report: Happy Eyeballs IPv4/IPv6 fallback measurement

AIORI-3 PS-028 · team code A3-PS028-TC278 · backend and measurement only (the website is out of scope).

Draft, 2026-11-01. Every number below comes from the 280-run dataset listed in
[`dataset.md`](dataset.md), as summarised by `src/analysis/summarise.py`, or from the Chromium
note in [`findings/chromium_s1_second_v6_syn.md`](findings/chromium_s1_second_v6_syn.md). Nothing
is estimated or carried over from configuration.

## Conventions

**Evidence labels.** These are the same three labels the dashboard uses.
- **[Packet-level (pcap)]** comes from the packet capture taken inside the client namespace.
- **[Client log]** comes from what a client reported about itself: curl's `-w` output, or Chromium's NetLog.
- **[Interpretation]** is our reading of the evidence. It is never a measurement.

**Wording rules.** These come from the project's CLAUDE.md, and both rules below are in it.
- RFC 8305 is a reference design, not a predictor. This report never says RFC 8305 predicts an
  exact completion time. Its 250 ms Connection Attempt Delay is a reference point, not a pass or fail threshold.
- The delay scenarios are **mobile-inspired latency conditions**. They are not carrier measurements.
- The Happy Eyeballs v3 draft is background only. The report makes no conformance claim from undocumented client internals.

**Metric definitions.** These are fixed and are not redefined here.
- **TCP setup time:** from the run's first SYN, of either family, to the ACK that completes the
  winning handshake. DNS time is reported separately.
- **Inter-family attempt delay:** the second family's first SYN minus the first family's first SYN.
  It is "not observed" when only one family was tried.
- **Scenario penalty:** the client's median TCP setup time minus its own median in C0.
- Every run also records the winning family, success or failure, and failed or abandoned attempts.

## 1. Methodology

### 1.1 Lab

The lab is two Linux network namespaces on one host: `hl-client` and `hl-server`. They are joined by three veth links.

| Link | Client end | Server end | Role |
|---|---|---|---|
| v6 | `hl-v6c` 2001:db8:28:6::1/64 | `hl-v6s` 2001:db8:28:6::2/64 | IPv6 data path, impaired by scenarios |
| v4 | `hl-v4c` 192.0.2.1/24 | `hl-v4s` 192.0.2.2/24 | IPv4 data path, impaired by scenarios |
| ctl | `hl-ctlc` 198.51.100.1/24 | `hl-ctls` 198.51.100.53/24 | DNS only, never impaired |

All addresses are documentation prefixes (RFC 5737, RFC 3849) and never leave the namespaces. The
host's default namespace, Wi-Fi interface, routes, firewall and `/etc/gai.conf` are not touched.

- **Server:** nginx 1.24.0 in `hl-server` serves `http://www.hl.test/`. It uses HTTP/1.1 with keep-alive off and returns a small fixed reply.
- **DNS:** `src/dns/hl_dns.py` (dnslib) is authoritative for `www.hl.test`, with A 192.0.2.2 and
  AAAA 2001:db8:28:6::2 at TTL 0. Each query type gets its own reply, and the delay can be set per type.
- **Client resolver files:** `hl-client` uses lab-only `resolv.conf` and `gai.conf` files from
  `/etc/netns/hl-client/`. `ip netns exec` mounts them over `/etc/` for processes in that namespace only.

### 1.2 Impairments

All impairments are applied on the server side. The client interfaces, which are the capture point,
carry no qdisc, so the capture sees every client packet at the moment it is sent.
- **Server to client:** netem on the server end of each link.
- **Client to server:** the server end's ingress is redirected to an ifb device (`hl-ifb4`/`hl-ifb6`), and netem is applied there.
- **Baseline:** 10 ms each way on both data links, which gives a 20 ms target RTT.
- **"+N ms RTT":** N ms is added to that 20 ms baseline and split equally across the two directions. Each way is 10 + N/2 ms and the target is 20 + N ms. For example, S2 and S5 use 310 ms each way, for a 620 ms target.
- **Blackhole:** 100% netem loss in both directions. Static `nud permanent` neighbour entries mean
  the loss is a silent drop, not an ARP/ND failure that would produce "host unreachable" errors.

| Scenario | IPv6 path | IPv4 path | DNS | Verify target (v4 / v6) |
|---|---|---|---|---|
| C0 healthy baseline | baseline | baseline | immediate | 20 / 20 ms |
| S1 IPv6 blackhole | 100% loss | baseline | immediate | 20 ms / blackhole |
| S2 IPv6 +600 ms RTT | 310 ms each way | baseline | immediate | 20 / 620 ms |
| S3 IPv6 +150 ms RTT | 85 ms each way | baseline | immediate | 20 / 170 ms |
| S4 IPv4 blackhole | baseline | 100% loss | immediate | blackhole / 20 ms |
| S5 IPv4 +600 ms RTT | baseline | 310 ms each way | immediate | 620 / 20 ms |
| S6 AAAA delayed 300 ms | baseline | baseline | AAAA reply held 300 ms, A immediate | 20 / 20 ms |
| X1 compound stress (optional) | not defined | not defined | n/a | **not measured** |

### 1.3 One run

`src/runner/orchestrate.py` runs each repetition in this order:
1. Apply the scenario with `src/lab/netem.sh`.
2. Run `src/lab/verify.sh` to measure the real RTT with 10 pings per family.
   - A numeric target passes when loss is 0 and the median is within max(2 ms, 10% of target) of it.
   - A blackhole passes only with 100% loss and no ICMP errors.
   - The control link must stay under 2 ms.
3. Start tcpdump in `hl-client` (`-i any --immediate-mode`).
4. Run the client in `hl-client` as the normal user, with `PYTHONPATH` and `LD_LIBRARY_PATH` removed from its environment.
5. Stop the capture and read tcpdump's dropped and written packet counts.
6. Restore the baseline and verify again.
7. Parse the capture for this run's time window and write a record (schema 0.2) with its SHA-256.

The orchestrator does not retry. A failed verify or an incomplete capture stops the session.

**Clients.** Versions and configuration are recorded in every run.
- **curl** 8.5.0 (libcurl 8.5.0, OpenSSL 3.0.13):
  - command: `curl -q -sS --noproxy '*' --max-time 10 -o /dev/null -w … http://www.hl.test/`
  - its Happy Eyeballs timeout was left at its default (not set)
  - it resolves through glibc
- **Chromium** 156.0.8078.4 via Playwright 1.64.1:
  - full Chromium in new headless mode, a fresh browser process and profile per run, with Playwright's default of no sandbox
  - loads `http://www.hl.test/chromium.html`
  - QUIC, DNS-over-HTTPS and HTTPS-Upgrades are disabled
  - a NetLog is written for every run, and the launch flags are read back from it and checked

**Records and cross-checks.** Each metric is stored as `{value, status}`, where the status is
`computed`, `not_observed` or `not_applicable`. Every record compares six fields between the
client's report and the capture:
- winning family
- success
- HTTP status
- connected address against the winning handshake
- unexpected traffic (port 443, QUIC, other ports)
- capture completeness

### 1.4 Dataset

- **Matrix:** the full matrix of 7 scenarios × 2 clients × 20 repetitions (**280 runs**, 14 sessions) ran
  unattended on 2026-10-26.
  - code version `ecba28c` (clean)
  - kernel 7.0.0-38-generic, Python 3.12.3
  - duration 64.6 min
- **Checks:** every batch passed the batch check, and the checks were re-run independently on 2026-10-27:
  - 20 records and 20 pcaps per cell
  - repetitions 1–20, each exactly once
  - hashes match
  - lab verify passed before and after every run
  - **0 cross-check conflicts**
- **Summaries:** produced by `summarise.py`, which reads only the 14 sessions in `dataset.md` and stops on any conflict or failed verify.

## 2. Results

### 2.1 Summary table

All figures are [Packet-level (pcap)] medians over 20 runs, with the interquartile range in brackets.
The winning family is shown as IPv6 wins / IPv4 wins. Attempt order is the order of first SYNs per
attempt; `v6>v6>v4` means two IPv6 attempts, then IPv4.

**curl**

| Scenario | Wins v6/v4 | TCP setup ms | Penalty ms | Inter-family delay | Abandoned per run | Attempt order | DNS ms |
|---|---|---|---|---|---|---|---|
| C0 | 20/0 | 20.697 [20.676–20.878] | 0 | not observed ×20 | 0 | v6 | 1.198 |
| S1 | 0/20 | 222.221 [222.016–222.541] | 201.524 | 200.956 ms (20/20) | 1 | v6>v4 | 1.131 |
| S2 | 0/20 | 222.188 [222.002–222.459] | 201.491 | 200.956 ms (20/20) | 1 | v6>v4 | 1.105 |
| S3 | 20/0 | 171.171 [170.757–171.214] | 150.474 | not observed ×20 | 0 | v6 | 0.994 |
| S4 | 20/0 | 20.715 [20.527–20.890] | 0.018 | not observed ×20 | 0 | v6 | 1.171 |
| S5 | 20/0 | 20.697 [20.474–21.032] | 0.001 | not observed ×20 | 0 | v6 | 1.123 |
| S6 | 20/0 | 20.812 [20.722–21.126] | 0.115 | not observed ×20 | 0 | v6 | **302.070** |

**Chromium**

| Scenario | Wins v6/v4 | TCP setup ms | Penalty ms | Inter-family delay | Abandoned per run | Attempt order | DNS ms |
|---|---|---|---|---|---|---|---|
| C0 | 20/0 | 20.135 [20.128–20.148] | 0 | not observed ×20 | 0 | v6 | 0.894 |
| S1 | 0/20 | 322.392 [322.115–323.402] | 302.257 | 301.067 ms (20/20) | 2 | v6>v6>v4 | 0.957 |
| S2 | 0/20 | 321.986 [321.593–322.708] | 301.851 | 301.120 ms (20/20) | 2 | v6>v6>v4 | 0.887 |
| S3 | 20/0 | 171.109 [170.672–172.360] | 150.975 | not observed ×20 | 0 | v6 | 0.844 |
| S4 | 20/0 | 20.139 [20.124–20.147] | 0.004 | not observed ×20 | 0 | v6 | 0.966 |
| S5 | 20/0 | 20.139 [20.130–20.146] | 0.004 | not observed ×20 | 0 | v6 | 0.939 |
| S6 | 20/0 | 21.317 [20.701–22.179] | 1.182 | not observed ×20 | 0 | v6 | **301.851** |

Every run succeeded with HTTP 200 (280/280) [Client log], and the capture agrees in every run.
- **SYN retransmissions:** there were no kernel SYN retransmissions on any of the 400 attempts in the dataset [Packet-level (pcap)].
- **Small penalties:** the S4, S5 and curl S6 penalties are well under 1 ms, which is inside the C0 interquartile ranges.
  [Interpretation] They should be read as no measurable penalty, not as small effects.
- **X1:** not measured. It has no figures.

### 2.2 IPv6 blackhole and +600 ms IPv6 (S1, S2)

[Packet-level (pcap)] Both clients started on IPv6. Neither IPv6 handshake completed before an IPv4
handshake did, so IPv4 won all 80 runs (both clients, S1 and S2).
- **curl:** opened IPv4 a median 200.956 ms after its first IPv6 SYN in both scenarios. Setup took 222.221 ms (S1)
  and 222.188 ms (S2), with one abandoned IPv6 attempt per run.
- **Chromium:** sent a **second IPv6 SYN from a new source port**, a median 250.625 ms (S1) and
  250.69 ms (S2) after the first. It then opened IPv4 at a median 301.067 ms (S1) and 301.12 ms (S2).
  Setup took 322.392 ms and 321.986 ms, with two abandoned IPv6 attempts per run.
- **Late IPv6 replies in S2:** in the S2 pilot captures, the IPv6 SYN-ACKs arrived about one 620 ms RTT after each
  IPv6 SYN. By then IPv4 had already won, and the client answered each with a RST (see the findings note).

[Client log] Chromium's NetLog marks the second IPv6 attempt as a separate socket-pool connect
job with `backup_job: true`, in 20/20 runs in each of S1 and S2. In 20/20 runs the IPv4 attempt
is started by the **original** job's second connector, not by the backup job. The pilot analysis
lined each NetLog entry up with its pcap SYN to within 1 ms, and matched the IPv4 socket's local port.

[Interpretation]
- The second IPv6 SYN is a Chromium backup attempt to the same address, not a TCP retransmission.
  A retransmission would reuse the socket and 4-tuple, and none was seen.
- It explains the extra SYN and the second abandoned attempt. But the data gives no sign that it
  holds back the IPv4 start.
- Chromium's setup in S1 is 100.171 ms longer than curl's, and in S2 99.798 ms longer. That gap
  matches the later IPv4 start (about 301 ms against about 201 ms). It is better described as Chromium
  starting IPv4 later than curl than as overhead from the backup attempt.
- The ~250 ms and ~301 ms values are **observed delays, not documented constants**. They are not
  presented as Chromium's internal timer values.

Against RFC 8305 as a reference design: both clients waited before trying IPv4 instead of starting
both families at once. Neither observed delay is a test of the RFC's 250 ms recommended Connection
Attempt Delay, and none is claimed.

### 2.3 Moderately slower IPv6 (S3, +150 ms)

[Packet-level (pcap)] Both clients connected over IPv6 in all 20 runs. Setup took a median
171.171 ms (curl) and 171.109 ms (Chromium), and neither sent a SYN of the other family. The penalty
was about 150 ms, which matches the added 150 ms of RTT.

[Interpretation] The IPv6 handshake (about 171 ms) completed before the point at which each
client started a further attempt in S1/S2: about 201 ms for curl, and about 250 ms for
Chromium's backup attempt. So no fallback was needed.

### 2.4 Impaired IPv4 (S4 blackhole, S5 +600 ms)

[Packet-level (pcap)] In all 80 S4/S5 runs both clients tried IPv6 first and connected in about one
baseline RTT. **No IPv4 SYN was sent in any run** (0/20 in each cell).

[Client log] Chromium's NetLog shows its resolver ordering IPv6 before IPv4 in 20/20 runs in each of S4 and S5.

[Interpretation] The impaired IPv4 path was never exercised, so S4 and S5 show no effect for
either client. That means the IPv4 impairment wasn't reached in this lab. It does not show that a
broken IPv4 path is harmless in general (see Limitations, L2).

### 2.5 Delayed AAAA answer (S6)

[Packet-level (pcap)] Times are measured from the first `www.hl.test` query.

| | A answer | AAAA answer | First SYN | DNS time min / median / max |
|---|---|---|---|---|
| curl | 0.993 ms (max 1.257) | 302.070 ms (max 302.915) | 302.763 ms (max 303.551) | 301.586 / 302.070 / 302.915 ms |
| Chromium | 0.837 ms (max 1.331) | 301.851 ms (max 304.467) | 302.695 ms (max 305.113) | 300.577 / 301.851 / 304.467 ms |

- **First SYN after the AAAA answer:** in **20/20 runs for each client**, the first SYN went out only after the delayed AAAA answer.
  It was over IPv6 every time, even though the A answer had arrived about 1 ms in.
- **Chromium's HTTPS query:** Chromium also queried the HTTPS record type, which was answered at a median 0.63 ms.
- **Setup time:** TCP setup stayed at baseline, 20.812 ms (curl) and 21.317 ms (Chromium).

[Interpretation] Neither client connected over IPv4 on the early A answer while the AAAA answer
was outstanding. The 300 ms delay therefore appears in DNS time, not in TCP setup time, which starts
at the first SYN. S6 must always be reported with both numbers. Why the clients wait (resolver
design) is not visible in this data.

### 2.6 Baseline repeatability (C0)

[Packet-level (pcap)] A separate, complete curl C0 batch (session `20261026T190919Z`, same code
version) ran about 11 minutes before the matrix, with a median setup of 20.681 ms against the dataset's
20.697 ms. It is reported only as a repeatability check and is not pooled into the baseline.

## 3. Limitations

**L1. Netem values are nominal; the measured RTT is what we report.**
- **Provisional values:** the configured delays in `src/config/scenarios.yaml` are marked provisional.
- **Measured before each run:** the real RTT was measured before every run, and the run went ahead only if `verify.sh` passed. The measured median RTT is stored in every record.
- **What the dataset measured:** baseline medians were 21.1–21.2 ms per cell (every run between 20.35 and 21.4 ms), S3 IPv6 171.0 ms, and S2 IPv6 and S5 IPv4 621.0 ms. Both blackholes were measured at 100% loss with 0 ICMP errors.
- **Pilots:** these values were validated with 1–3 repetition pilots before the full matrix ran:
  - every scenario, for curl (sessions `20261026T064544Z`, `20261026T074423Z`)
  - every scenario, for Chromium (sessions `20261026T125239Z`, `20261026T181302Z`, `20261026T182411Z`)
  - The pilots ran on earlier, uncommitted code and are not part of the dataset.
- **Timing of the measurement:** the RTT is measured with ICMP before the client runs, not during the TCP exchange.

**L2. The IPv6 preference belongs to this lab's resolver set-up, not a host or universal default.**
- **curl:** curl resolves through glibc. In `hl-client` it sees the lab's own
  `/etc/netns/hl-client/gai.conf`, which contains only comments. With no rules, glibc's built-in
  default policy applies, and that policy prefers IPv6.
- **Chromium:** Chromium did not take its order from `gai.conf`. It used its own built-in DNS client,
  which ordered IPv6 first in 140/140 runs [Client log]. The two clients reached the same order by different routes.
- **The host's own `/etc/gai.conf`:** it prefers IPv4 and was deliberately left untouched. It does not affect
  the measured processes: every client ran inside `hl-client`, where `ip netns exec` mounts the lab
  file over `/etc/gai.conf`.
- **Consequence:** the S4/S5 result (IPv4 never tried) holds only under this IPv6-preferred
  ordering. An IPv4-first policy was not tested.

**L3. Chromium's 250 ms and 301 ms points are observations, not documented values.** They are consistent
across 40 dataset runs plus 5 pilot runs. They come from one Chromium version (156.0.8078.4) in new
headless mode under Playwright, with QUIC, DNS-over-HTTPS and HTTPS-Upgrades disabled. Other
versions, headed mode or default feature settings may behave differently.

**L4. One version of each client, one host, and HTTP only.**
- curl 8.5.0 and Chromium 156.0.8078.4 on kernel 7.0.0-38-generic.
- Plain HTTP on port 80. TLS and QUIC were not measured.
- curl ran with its default Happy Eyeballs timeout.

**L5. The conditions are simplified.** The delay scenarios are mobile-inspired latency conditions on veth
links, not carrier measurements:
- fixed symmetric delay with no jitter
- no partial loss: loss is either 0% or 100%
- one family impaired at a time
- DNS on an unimpaired separate link, with only the AAAA answer delayed in S6

**L6. Sample size.** There are 20 runs per client and scenario. Medians and interquartile ranges are reported.
No significance tests were run, and sub-millisecond differences (for example the S4/S5 penalties) are
not interpreted.

**L7. Capture point and resolution.**
- All timings come from one capture inside `hl-client`, with microsecond timestamps.
- There is no server-side capture, so one-way delays are not measured separately.
- Client-reported values (curl `-w` output, NetLog) are used only where labelled [Client log].

**L8. X1 (compound stress) is not defined or measured.** It is optional in the problem statement, and
the report gives no figures for it.

**L9. RFC 8305 is a reference only.** The data shows when each client opened each attempt. It does not
test conformance to RFC 8305 or the Happy Eyeballs v3 draft, and none is claimed.

## 4. Reproducing the figures

```
scripts/test.sh                                   # 285 tests, including parser and metric checks
.venv/bin/python src/analysis/summarise.py        # tables above + interpretation, writes data/generated/summary/
.venv/bin/python src/analysis/dashboard.py        # the same data as an offline Plotly dashboard
```

The captures (`captures/`) and run records (`data/generated/`) are not in Git, so the commands
above need the lab machine's data. Each record carries its pcap's SHA-256. Each Chromium record carries
its NetLog path and connect-job entries.
