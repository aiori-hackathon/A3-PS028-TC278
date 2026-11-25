# HappyLab technical report: Happy Eyeballs IPv4/IPv6 fallback measurement

AIORI-3 PS-028 · team code A3-PS028-TC278 · backend and measurement only (the website is out of scope).

Draft, 2026-11-01. Every number below comes from the 280-run dataset listed in
[`dataset.md`](dataset.md), as summarised by `src/analysis/summarise.py`, or from the Chromium
note in [`findings/chromium_s1_second_v6_syn.md`](findings/chromium_s1_second_v6_syn.md). Nothing
is estimated or carried over from configuration. The one exception is section 4 (Related work). It
also cites the extension findings in [`findings/`](findings/), naming the campaign for each number,
and it quotes the prior work's published values, which are attributed to that paper's authors.

## Conventions

**Evidence labels.** These are the same four labels the dashboard uses: Packet-level (pcap), Client log, Derived (pcap − lab RTT) and Interpretation.
- **[Packet-level (pcap)]** comes from the packet capture taken inside the client namespace.
- **[Client log]** comes from what a client reported about itself: curl's `-w` output, or Chromium's NetLog.
- **[Derived (pcap − lab RTT)]** combines the packet-level TCP setup time with the winning family's RTT from the lab's ping check before the run (the oracle baseline and cost of racing). It is computed, not seen on the wire.
- **[Interpretation]** is our reading of the evidence. It is never a measurement.

**Wording rules.** These come from the project's CLAUDE.md, and both rules below are in it.
- RFC 8305 is a reference design, not a predictor. This report never says RFC 8305 predicts an
  exact completion time. Its 250 ms Connection Attempt Delay is a reference point, not a pass or fail threshold.
- The delay scenarios are **mobile-inspired latency conditions**. They are not carrier measurements.
- The Happy Eyeballs v3 draft (pinned at -04; status in section 4.7) is background only. The report makes no conformance claim from undocumented client internals.

**Metric definitions.** These are fixed and are not redefined here.
- **TCP setup time:** from the run's first SYN, of either family, to the ACK that completes the
  winning handshake. DNS time is reported separately.
- **Inter-family attempt delay:** the second family's first SYN minus the first family's first SYN.
  It is "not observed" when only one family was tried.
- **Scenario penalty:** the client's median TCP setup time minus its own median in C0.
- Every run also records the winning family, success or failure, and failed or abandoned attempts.

**Standard terms.** The report also uses the terms Connection Attempt Delay (CAD) and Resolution
Delay (RD) from RFC 8305. Section 4.2 maps them to the metrics above, which stay as defined.

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
| X1 compound stress (optional in our proposal) | not configured | not configured | n/a | **not measured** |

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
  - the full browser (not the headless shell) in new headless mode, a fresh browser process and profile per run, with Playwright's default of no sandbox
  - loads `http://www.hl.test/chromium.html`
  - QUIC, DNS-over-HTTPS and HTTPS-Upgrades are disabled
  - a NetLog is written for every run, and the launch flags are read back from it and checked

**Client builds.**
- **Browser:** the client referred to here as Chromium is Google Chrome for Testing 156.0.8078.4
  (branch-heads/8078@{#13}), as reported by NetLog clientInfo, installed by `playwright install chromium`.
  - All 166 Chromium NetLogs on the lab machine report the same clientInfo: name `Google Chrome for Testing`,
    version `156.0.8078.4`, `official` build, cl
    `f842f52ef39fd97b449eb27cff414bf05a98ddce-refs/branch-heads/8078@{#13}`.
  - The binary is `~/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome` (Playwright build 1248).
  - "Chromium" remains the short name in code, records and this report.
- **curl:** full `curl -V` output. Only its first line is stored in each run record.

  ```
  curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) libssh/0.10.6/openssl/zlib nghttp2/1.59.0 librtmp/2.3 OpenLDAP/2.6.10
  Release-Date: 2023-12-06, security patched: 8.5.0-2ubuntu10.16
  Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp
  Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd
  ```

  - **Provenance:** captured on 2026-11-18 from `/usr/bin/curl`, with `PYTHONPATH` and `LD_LIBRARY_PATH` unset.
    - The first line is identical to the one stored in the dataset records.
    - The dpkg log shows the `curl` and `libcurl4t64` packages (8.5.0-2ubuntu10.16) were last installed or upgraded on 2026-10-16, before the dataset was run on 2026-10-26.
    - The kernel has changed since then, from 7.0.0-38 to 7.0.0-43. That does not affect `curl -V` output.
  - **AsynchDNS is present,** and no c-ares library appears in the version line.
    - [Interpretation, from curl's documentation, not observed] This combination is curl's threaded resolver, which
      resolves through glibc's `getaddrinfo` in a separate thread rather than blocking the transfer.
    - AsynchDNS alone does not say whether the A and AAAA queries are sent in parallel.
  - [Packet-level (pcap)] **The A and AAAA queries were sent together.** In all 140 curl captures in the dataset:
    - both queries for `www.hl.test` were sent from the same source port, A first;
    - the AAAA query followed 0.024 / 0.038 / 0.056 ms (min / median / max) later.

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
- **No early IPv4 SYN:** in S6 no client sent an IPv4 SYN within 50 ms of the A answer, which differs
  from the 50 ms Resolution Delay RFC 8305 recommends. In fact neither client sent an IPv4 SYN at any
  point in S6 (0/20 runs each). From `summarise.py`, the first SYN of either family went out
  301.153 / 301.774 / 302.526 ms (min / median / max) after the first A answer for curl, and
  300.794 / 301.785 / 303.782 ms for Chromium.
- **Chromium's HTTPS query:** Chromium also queried the HTTPS record type, which was answered at a median 0.63 ms.
- **Setup time:** TCP setup stayed at baseline, 20.812 ms (curl) and 21.317 ms (Chromium).

[Interpretation] Because the first SYN followed the AAAA answer, the 300 ms delay appears in DNS
time, not in TCP setup time, which starts at the first SYN. S6 must always be reported with both
numbers. The captures show when each packet was sent, not why: they say nothing about how either
client's resolver or connection logic is built, and no claim is made about it. The observation holds
for these two client versions in this lab only.

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
links, not carrier measurements. In the core dataset (the jitter-loss extension adds IPv6 jitter, partial
loss and one compound control; see [its findings](findings/syn_retransmission_partial_loss.md)):
- fixed symmetric delay with no jitter
- no partial loss: loss is either 0% or 100%
- one family impaired at a time
- DNS on an unimpaired separate link, with only the AAAA answer delayed in S6

**L6. Sample size.** There are 20 runs per client and scenario in the core dataset (5 to 50 per cell in the extension campaigns). Medians and interquartile ranges are reported.
No significance tests were run, and sub-millisecond differences (for example the S4/S5 penalties) are
not interpreted.

**L7. Capture point and resolution.**
- All timings come from one capture inside `hl-client`, with microsecond timestamps.
- There is no server-side capture, so one-way delays are not measured separately.
- Client-reported values (curl `-w` output, NetLog) are used only where labelled [Client log].

**L8. X1 (compound stress) was not configured or measured.** [PS-028](../PS-028.pdf) asks for six scenarios and does
not mention X1. X1 was an optional extra in our own proposal, to run only if time allowed. It was never
added to `src/config/scenarios.yaml`, and the report gives no figures for it.

**L9. RFC 8305 is a reference only.** The data shows when each client opened each attempt. It does not
test conformance to RFC 8305 or the Happy Eyeballs v3 draft, and none is claimed. The v3 draft is
pinned at revision -04. Its status at the time of writing is in the references (section 4.7).

**L10. Cross-kernel comparison of curl S1 ([`variant-control`](datasets/variant-control.md), `src/analysis/variant_control.py`).**
Cross-kernel comparison: curl S1 (variant-control) differed from curl S1 (core dataset) by -0.618 ms in median TCP setup time (221.603 ms, 95% CI 221.214-222.002, n=20, against 222.221 ms, 95% CI 222.099-222.435, n=20; on kernel 7.0.0-43-generic against 7.0.0-38-generic). The intervals do not overlap. The cause is not established by these data. In context (interpretation): the difference is 0.28% of the core median and about 326 times smaller than curl's S1 scenario penalty in the core dataset (201.524 ms), so it does not affect conclusions that rest on differences of that size; it is, however, larger than the sub-millisecond quantities in the core results (S4–S6 penalties of 0.001–0.115 ms, costs of racing of −0.30 to −0.48 ms, median CI widths of 0.137–0.370 ms), whose sensitivity to the kernel change these data cannot rule out.

## 4. Related work

### 4.1 Prior work: Sattler et al.

The closest prior work is Sattler et al., "Lazy Eye Inspection: Capturing the State of Happy
Eyeballs Implementations" [R1].

**Their method, as they describe it.**
- A local testbed of two directly connected hosts, with tc-netem delaying IPv6 and DNS.
- The Connection Attempt Delay is inferred from packet captures.
- A public web-based tester as well as the testbed.
- Clients: Firefox, Chrome, Edge, Chromium, curl, wget and Safari, plus recursive resolvers.
- At least 20 repetitions per client, with delays stepped from 0 to 400 ms in 5 ms increments.

**Their published findings, as they state them.**
- curl's Connection Attempt Delay is 200 ms. Chromium-based browsers use 300 ms.
- Neither client implements the Resolution Delay.
- Chromium waits for the A record and relies on the resolver's timeout. A HEv3 feature flag added
  in April 2024 removes that behaviour.
- Both clients try only one IPv6 and one IPv4 address during fallback.

**Their claims stay theirs.** Wherever a statement says what a client implements, for example that it does
not implement the Resolution Delay, it is the authors' conclusion and is attributed to them here.
This report does not adopt claims about client internals. Our own S6 wording (section 2.5) stays at
what the packets show.

### 4.2 Standard terms: CAD and RD

RFC 8305 [R2] defines the two delays that the field's vocabulary is built on:
- **Connection Attempt Delay (CAD), section 5:** the time a client waits after starting one
  connection attempt before starting the next. The RFC recommends 250 ms.
- **Resolution Delay (RD), section 3:** the time a client waits for the AAAA answer when the A answer
  arrives first, before starting with IPv4. The RFC recommends 50 ms.

Our fixed metrics stay as defined in Conventions. They map to these terms as follows. Each of our
quantities is a measured interval between packets. It is not a reading of a client's configured timer.

| RFC 8305 term | Our measurement | Evidence | Section |
|---|---|---|---|
| CAD, when the next attempt uses the other family | Inter-family attempt delay: the second family's first SYN minus the first family's first SYN | Packet-level (pcap) | 2.1, 2.2 |
| CAD, when the next attempt uses the same family | Not one of our metrics. Reported as the gap between Chromium's two IPv6 SYNs | Packet-level (pcap) | 2.2, 4.4 |
| RD | Not one of our metrics. In S6 we report the time from the first A answer to the first SYN, and that SYN's family. DNS time is reported separately | Packet-level (pcap) | 2.5 |
| (no RFC term) | T: the run's first SYN to the first SYN-ACK of its IPv4 attempt. It is the inter-family attempt delay plus the IPv4 handshake | Packet-level (pcap); the decomposition is derived | 4.3 |

### 4.3 Independent reproduction of the published delays

Our measured crossovers **reproduce** the values Sattler et al. published: 200 ms for curl and
300 ms for Chromium. This is an independent reproduction in a separate lab with our own client
builds (curl 8.5.0, Chromium 156.0.8078.4). It is not a discovery: they published the values first.

T is given to two decimal places, with the campaign it was measured in, as in the findings docs.

| Client | Published CAD [R1] | Inter-family attempt delay, core S1 / S2 | T, jitter-loss | T, latency-sweep | Outcome flip, latency-sweep (IPv6 RTT) |
|---|---|---|---|---|---|
| curl | 200 ms | 200.956 / 200.956 ms | 221.96 ms (n=40) | 221.84 ms (n=70) | 221–226 ms |
| Chromium | 300 ms | 301.067 / 301.120 ms | 322.47 ms (n=17) | 321.99 ms (n=50) | 321–326 ms |

- **Evidence.** All the times are packet-level medians. The outcome flip comes from which family
  won and uses no packet times. Its edges are verify-ping RTTs and are good to about 1 ms. Sources:
  sections 2.1–2.2,
  [`syn_retransmission_partial_loss.md`](findings/syn_retransmission_partial_loss.md) and
  [`latency_and_he_sweeps.md`](findings/latency_and_he_sweeps.md).
- **T against the published values.** T is the attempt delay plus the IPv4 handshake, which takes
  about 21 ms in this lab [Derived]. So 221.96 ms corresponds to curl's 200 ms and 322.47 ms to
  Chromium's 300 ms.

**The he-sweep is the check (curl only).** We ran curl with `--happy-eyeballs-timeout-ms` set to eight
values from 50 to 500 ms, with IPv6 blackholed (he-sweep, 10 runs per cell).
- **Prediction.** It was set before the run: T ≈ configured timeout + IPv4 handshake.
- **Result.** T minus that prediction was +0.69 to +1.99 ms in all eight variants [Derived from
  packet-level medians]. So T minus the handshake tracks the configured timeout in every variant,
  slightly late each time.
- **A step we don't explain.** The residual steps up between 250 and 300 ms, and these data offer
  no explanation for it.
- **Control.** curl@he200 sets curl's documented default [R4]. It sent its IPv4 SYN at 200.833 ms,
  against plain curl's 200.832 ms.
- **Chromium.** It takes no such option, so it has no equivalent check. Its 300 ms is an observed
  delay only (L3).

### 4.4 A refinement: one IPv6 address, two connection attempts

Sattler et al. report that both clients try only one IPv6 and one IPv4 address during fallback. Our
captures add a detail about attempts, not addresses.

[Packet-level (pcap)]
- **Two IPv6 SYNs.** In 40 of 40 Chromium S1 and S2 runs, the capture shows two IPv6 SYNs to the
  same address, 2001:db8:28:6::2, from different source ports.
- **Timing.** The second SYN follows the first by a median 250.625 ms (S1) and 250.69 ms (S2),
  about 250.6 ms.
- **No retransmissions.** No socket sent a second SYN: there were zero same-socket SYN
  retransmissions on any attempt in the dataset.
- **Then IPv4.** One IPv4 SYN follows at about 301 ms.
- **curl** made one attempt per family.

So Chromium used one IPv6 address and made two connection attempts to it. This refines the
published observation and does not contradict it.
- **Addresses.** The lab's DNS returns one AAAA and one A record, so our data cannot show how many
  addresses either client would try if offered more.
- **Wording.** This is packet-level only. It says nothing about what Chromium implements or
  intends (section 2.2 gives the client-log view).

The 250.6 ms interval sits near the 250 ms default that RFC 8305 section 5 recommends for the
Connection Attempt Delay.

### 4.5 What this work adds

| Addition | What it shows | Source |
|---|---|---|
| Cost of racing against an oracle baseline. Not measured in that work | TCP setup time minus the winning family's pre-run ping RTT, per run [Derived (pcap − lab RTT)]. Where IPv4 won in the latency sweep, the cell medians were 200.76–201.48 ms (curl) and 300.43–302.17 ms (Chromium). Where IPv6 won, they were within ±0.9 ms of zero | [`latency_and_he_sweeps.md`](findings/latency_and_he_sweeps.md) |
| Partial loss and jitter on IPv6, where outcomes become probabilistic | Win fractions with 95% Wilson intervals over 558 runs. A model, P(IPv6 wins) = Φ((T − μ)/σ), has inputs measured independently of the outcomes it predicts. T comes from the no-jitter twin captures, and μ and σ from the verify pings. Its values match all four jitter cells within their Wilson intervals. The model was written up together with the jitter results, so this is not a prediction registered before they existed. Its T values were fixed before the latency sweep ran, and the sweep confirmed them: both fall inside the outcome-flip brackets | [`syn_retransmission_partial_loss.md`](findings/syn_retransmission_partial_loss.md), [`latency_and_he_sweeps.md`](findings/latency_and_he_sweeps.md) |
| curl's timeout varied across eight values, rather than one default inferred | T tracks timeout + IPv4 handshake from 50 to 500 ms (section 4.3) | [`latency_and_he_sweeps.md`](findings/latency_and_he_sweeps.md) |
| A compound control, `Gv6c30`: IPv4 blackholed plus 30% loss each way on IPv6. It is a generated extension, not X1 | Kernel SYN retransmissions become visible [Packet-level (pcap)]. The gaps between same-socket SYNs were about 1 s up to the fifth SYN, with no doubling. [Interpretation] This matches `net.ipv4.tcp_syn_linear_timeouts` = 4 in hl-client | [`syn_retransmission_partial_loss.md`](findings/syn_retransmission_partial_loss.md) |
| Certified datasets | Every analysis reads only the sessions a manifest lists. Each record carries its pcap's SHA-256. `summarise.py` refuses a missing, duplicated or undeclared cell, a cross-check conflict or a failed verify, and nothing is skipped or filled in | [`datasets/README.md`](datasets/README.md), [`dataset.md`](dataset.md) |

### 4.6 Open question: Chromium in S6

S6 delays the AAAA answer by 300 ms, and the A answer arrives about 1 ms in.
- **What the packets show.** Chromium 156.0.8078.4 sent no IPv4 SYN at any point in S6 (0/20 runs).
  Its first SYN was IPv6, after the AAAA answer (section 2.5).
- **What the prior work describes.** Sattler et al. describe a HEv3 feature flag, added in
  April 2024, that removes Chromium's wait for the A record.
- **The question.** Is the behaviour behind that flag now the default in the version we ran?

Our data do not resolve this, and we assert nothing either way:
- S6 delays the AAAA answer, not the A answer.
- We set no feature flag for this behaviour, and our records do not show its state.
- We ran a single Chromium version.

### 4.7 References

- **[R1]** P. Sattler, M. Kirstein, L. Wüstrich, J. Zirngibl and G. Carle, "Lazy Eye Inspection:
  Capturing the State of Happy Eyeballs Implementations", ACM IMC 2025,
  doi:[10.1145/3730567.3732925](https://doi.org/10.1145/3730567.3732925). Preprint
  [arXiv:2412.00263](https://arxiv.org/abs/2412.00263). It is also listed by TUM as
  `sattler2025happyeyeballs`.
- **[R2]** D. Schinazi and T. Pauly, "Happy Eyeballs Version 2: Better Connectivity Using
  Concurrency", [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305), IETF, December 2017.
- **[R3]** T. Pauly, D. Schinazi, N. Jaju and K. Ishibashi, "Happy Eyeballs Version 3: Better
  Connectivity Using Concurrency",
  [draft-ietf-happy-happyeyeballs-v3-04](https://datatracker.ietf.org/doc/draft-ietf-happy-happyeyeballs-v3/04/),
  2026-07-01. It is work in progress and background only.
  - **Pin.** We pinned revision -04 and keep it.
  - **Status, checked on IETF Datatracker on 2026-11-24.** The current revision is -05, dated
    2026-11-02. It is still an Internet-Draft, a working-group document of the HAPPY working
    group, and is not an RFC.
  - **History.** The document began as the individual draft `draft-pauly-v6ops-happy-eyeballs-v3`
    (last revision -02, 2024), named for v6ops. That was replaced by
    `draft-pauly-happy-happyeyeballs-v3`, and in April 2025 the HAPPY working group adopted it as
    `draft-ietf-happy-happyeyeballs-v3`.
  - **PS-028 condition.** [PS-028](../PS-028.pdf) asks for v3 to be treated as pinned "unless its publication
    status is confirmed at launch". We checked that status on 2026-11-24: v3 is not published as
    an RFC, so the pin stands and v3 remains background only.
- **[R4]** curl's documented Happy Eyeballs default (200 ms):
  [`--happy-eyeballs-timeout-ms`](https://curl.se/docs/manpage.html#--happy-eyeballs-timeout-ms).

## 5. Reproducing the figures

```
scripts/test.sh                                   # the full test suite, including parser and metric checks
.venv/bin/python src/analysis/summarise.py        # tables above + interpretation, writes data/generated/summary/
.venv/bin/python src/analysis/dashboard.py        # the same data as an offline Plotly dashboard
```

The captures (`captures/`) and run records (`data/generated/`) are not in Git, so the commands
above need the lab machine's data. Each record carries its pcap's SHA-256. Each Chromium record carries
its NetLog path and connect-job entries.
