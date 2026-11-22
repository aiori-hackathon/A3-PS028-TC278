# HappyLab pseudocode

AIORI-3 PS-028 · team code A3-PS028-TC278

> **PS-028 deliverable:** "Prototype Demonstration with a Pseudocode Snippet to the mentor".
>
> **PS-028 measurement scope:** "evaluate connection racing across two existing web clients over
> six failure scenarios, measuring connection setup time, winning address family, and fallback
> behavior across at least 20 repetitions per case."
>
> The snippet shown during the demo is the next section. Everything after it is supporting detail
> for anyone who wants to trace a step into the code.

## Demo snippet: the core measurement loop

```
for client in {curl, chromium}:
  for scenario in {C0, S1, S2, S3, S4, S5, S6}:                 # scenarios.yaml
    start DNS server with the scenario's answer delay            # S6: AAAA +300 ms
    repeat 20 times:                                             # orchestrate.run_one
      apply netem to the v4 and v6 links (server side only)      # lib.sh hl_set_link
      verify-before: ping RTT on target, else STOP               # verify.sh up
      start tcpdump in hl-client
      run the client once against http://www.hl.test/
      stop tcpdump
      restore baseline (10 ms each way); verify-after, else STOP
      parse the pcap; hash it; build, validate and write the run record
    batch check: 20 clean runs, hashes match, verify passed      # check_batch.py

# Per run, from the packets (metrics.compute)
TCP setup time        = ACK completing the winning handshake − first SYN   (DNS excluded)
Inter-family delay    = second family's first SYN − first family's first SYN
                        ("not observed" if only one family is tried)
# Per client and scenario (summarise.py)
Scenario penalty      = median setup time in scenario − same client's median in C0

summarise refuses any dataset that isn't complete and clean
```

All three metrics come from packet timestamps in the capture. They describe what each client did
on the wire in this lab, and make no claim about RFC 8305 conformance.

---

## Supporting detail

Each step below is labelled `[file → function]` so it can be found in the code. The pseudocode
describes what the code does, in the same order. It leaves out logging, file ownership (`chown`)
and argument parsing.

## Evidence labels

The code keeps these sources separate, and so does this file. These are the same four labels the
dashboard and the report use:

| Label | Meaning |
|---|---|
| **Packet-level (pcap)** | Read from the tcpdump capture of the client namespace. |
| **Client log** | What the client or the runner reported (curl `-w`, Playwright, Chromium NetLog). These are outcomes, not packet evidence. |
| **Derived (pcap − lab RTT)** | Packet-level TCP setup time combined with the lab's pre-run ping RTT. |
| **Interpretation** | Our reading of the evidence above. It is never a measurement. |

"(lab check)" in the pseudocode below marks a value from `verify.sh` (ping RTT and configuration
checks). It is an input to Derived values, not a fifth evidence label.

Nothing below says whether a client conforms to RFC 8305 or any other specification. The metrics
are times between packets. They describe what each client did on the wire in this lab, not why it
did it.

## Overview

```
setup lab ─► for each client × scenario batch:
                start DNS server (with the scenario's answer delay) and nginx
                for each repetition:
                    apply netem ─► verify-before ─► capture + client ─► restore ─► verify-after
                    ─► parse pcap ─► hash pcap ─► build + validate record ─► write
                batch check
          ─► list certified sessions in the dataset manifest
          ─► summarise (refuses anything uncertified) ─► dashboard / report
teardown lab ─► verify-down
```

---

## 1. Lab setup and scenario application

### 1.1 Topology constants `[src/lab/lab.env]`

```
NAMESPACES   hl-client, hl-server            # never the host namespace
LINKS (veth, client end in hl-client, server end in hl-server)
    v4   hl-v4c 192.0.2.1/24        <-> hl-v4s 192.0.2.2         IPv4 only, impaired by scenarios
    v6   hl-v6c 2001:db8:28:6::1/64 <-> hl-v6s 2001:db8:28:6::2  IPv6 only, impaired by scenarios
    ctl  hl-ctlc 198.51.100.1/24    <-> hl-ctls 198.51.100.53    carries DNS, never impaired
IFB devices  hl-ifb4, hl-ifb6 (inside hl-server)
BASELINE     10 ms each way on v4 and v6  ->  20 ms RTT
CTL_MAX_RTT  2 ms
```

### 1.2 Build the lab `[src/lab/setup.sh]`

Run with plain `sudo` (`need_root`). The script is idempotent: every step converges to the same
state, so running it again finishes a half-built lab.

```
procedure SETUP_LAB:
    load kernel modules sch_netem, ifb (numifbs=0: no ifb devices in the host namespace)

    for ns in {hl-client, hl-server}:
        create ns if absent; bring lo up
        disable IPv6 DAD and router adverts in ns     # no "tentative" addresses after setup

    for link in {v4, v6, ctl}:
        if absent: create the veth pair directly inside the namespaces (nothing in the host ns)
        on each end: set fixed MAC; set address
            IPv4-only end -> disable IPv6 on that interface
            IPv6-only end -> add address with nodad
        bring both ends up

    add static neighbour entries (nud permanent) on both ends of v4 and v6
        # so a 100% loss blackhole stays a silent drop, not an ARP/ND failure

    in hl-client: default IPv4 route via 192.0.2.2; default IPv6 route via 2001:db8:28:6::2
    in hl-server: allow unprivileged ports from 0 (DNS and nginx run as the normal user)

    remove any netem left on the client interfaces    # the client side is the capture point
    for (dev, ifb) in {(hl-v4s, hl-ifb4), (hl-v6s, hl-ifb6)}:
        create ifb in hl-server if absent; bring it up
        rebuild an ingress qdisc on dev that redirects every incoming packet to ifb

    HL_SET_LINK(v4, 10 ms, 0 %)                       # baseline
    HL_SET_LINK(v6, 10 ms, 0 %)

    write /etc/netns/hl-client/resolv.conf  ->  "nameserver 198.51.100.53"
    write /etc/netns/hl-client/gai.conf     ->  no rules (glibc built-in default policy)
        # host /etc/gai.conf and /etc/resolv.conf are never touched

    exec VERIFY_UP(v4_target = 20, v6_target = 20)
```

### 1.3 Impair one link `[src/lab/lib.sh → hl_set_link]`, called by `[src/lab/netem.sh]`

```
procedure HL_SET_LINK(family, delay_ms_each_way, loss_pct):
    validate: family ∈ {v4, v6}; delay is a whole number; 0 ≤ loss ≤ 100   (else exit 2, nothing changed)
    dev, ifb := (hl-v4s, hl-ifb4) if family = v4 else (hl-v6s, hl-ifb6)
    qdisc := netem delay <delay>ms [loss <loss>% if loss > 0]
    in hl-server: replace root qdisc on dev with qdisc    # server -> client direction
    in hl-server: replace root qdisc on ifb with qdisc    # client -> server direction
```

The impairment is the same in both directions and sits only on the server side. The client
interfaces carry no qdisc, so the capture in hl-client sees every SYN the client sends, at the
moment it sends it.

### 1.4 Scenario table `[src/config/scenarios.yaml]`

The values are provisional and are configuration only. The measured RTT (1.6) is what goes into
the record.

| ID | v4 each way / loss | v6 each way / loss | DNS answer delay | verify target v4 / v6 |
|---|---|---|---|---|
| C0 | 10 ms / 0 % | 10 ms / 0 % | none | 20 / 20 |
| S1 | 10 / 0 | 10 / **100** | none | 20 / blackhole |
| S2 | 10 / 0 | **310** / 0 | none | 20 / 620 |
| S3 | 10 / 0 | **85** / 0 | none | 20 / 170 |
| S4 | 10 / **100** | 10 / 0 | none | blackhole / 20 |
| S5 | **310** / 0 | 10 / 0 | none | 620 / 20 |
| S6 | 10 / 0 | 10 / 0 | **AAAA 300 ms** | 20 / 20 |

"+N ms RTT" means `each way = 10 + N/2` and `target = 20 + N`.

### 1.5 DNS answer delay `[src/dns/hl_dns.py → answer, _Protocol.datagram_received]`, started by `[src/runner/orchestrate.py → Services.ensure_dns, cmd_dns]`

The DNS delay is not applied with netem. The lab's DNS server holds back its own answer.

```
procedure ENSURE_DNS(delays):                           # called before every run
    if the DNS server is running with exactly these delays: return
    stop the old server; start, inside hl-server as the normal user, with env = child_env():
        hl_dns.py --listen 198.51.100.53 --port 53 [--delay AAAA=300]
    wait (≤ 5 s) for its "listening" log line, else stop the session

on each UDP query:                                      # zone hl.test, TTL 0 (nothing cached)
    www.hl.test A     -> 192.0.2.2
    www.hl.test AAAA  -> 2001:db8:28:6::2
    www.hl.test other -> NOERROR, no answer     other names in hl.test -> NXDOMAIN     outside -> REFUSED
    delay := configured delay for this qtype if rcode = NOERROR else 0
    schedule the reply after delay (non-blocking: a delayed AAAA never holds up the A answer)
    log one JSON line with receive and send times
```

### 1.6 Verify before and after `[src/lab/verify.sh → verify_up]`, using `[src/lab/lib.sh → hl_rtt_stats, hl_rtt_check]`

`verify.sh` is read-only. All checks run, then it exits 1 if any failed.

```
procedure VERIFY_UP(v4_target, v6_target):
    both namespaces exist
    every interface end: up, expected MAC, expected address, no address of the other family,
        IPv6 address not tentative / not dadfailed
    static neighbours present and PERMANENT
    hl-client default routes via the v4 and v6 links
    hl-server unprivileged port start = 0
    ifb up; ingress redirect present; netem qdisc present on server end and ifb
        (netem settings printed as INFO: configuration, not ground truth)
    no netem on any client interface, nor on either ctl end
    hl-client sees the lab resolv.conf and gai.conf (bind mount works)
    HOST_CHECKS: no hl-* interfaces and no lab prefixes in the host namespace,
                 host IPv4 default route present, /etc/hosts does not mention hl.test

    # real RTT, measured from inside hl-client (lab check)
    for (label, dst, target) in {(v4, 192.0.2.2, v4_target), (v6, 2001:db8:28:6::2, v6_target),
                                 (ctl, 198.51.100.53, "max:2")}:
        out   := ping -c 10 -i 0.2 -W 2 dst
        stats := median, min, max, loss % (from sent/received counts), ICMP error count
        RTT_CHECK(target, stats)  ->  PASS / FAIL line "RTT <label> median_ms=… loss_pct=… …"

function RTT_CHECK(target, stats):                     # hl_rtt_check
    if target = "blackhole": PASS iff loss = 100 % and ICMP errors = 0   (a silent drop)
    if target = "max:N":     PASS iff loss = 0 and median < N
    else:                    PASS iff loss = 0 and |median − target| ≤ max(2 ms, 10 % of target)
```

### 1.7 Teardown `[src/lab/teardown.sh]` and verify-down `[src/lab/verify.sh → verify_down]`

```
procedure TEARDOWN_LAB:
    for ns in {hl-client, hl-server}:
        if present: SIGTERM its processes, wait ≤ 2 s, then SIGKILL; delete ns
            # deleting a namespace removes its veths, qdiscs, routes and neighbours
    remove only the two files setup wrote in /etc/netns/hl-client/; rmdir the folders if empty
    exec VERIFY_DOWN

procedure VERIFY_DOWN:
    no hl-client, no hl-server, no hl-* namespace left; /etc/netns/hl-client gone; HOST_CHECKS
```

---

## 2. One measurement run

### 2.1 Session wrapper `[src/runner/orchestrate.py → run_session]`

```
procedure RUN_SESSION(client, scenario_ids, reps):
    refuse if PYTHONPATH or LD_LIBRARY_PATH is set, or not run as root via sudo   [check_environment]
    refuse if hl-client does not exist (lab not set up)
    env, removed := child_env_with_removed()          [src/runner/child_env.py]
        # every subprocess gets env; the record states what was stripped
    record client version (curl --version, or the Chromium runner's --version) and nginx version
    environment := {kernel, python, git commit (+"-dirty" if uncommitted changes), session id,
                    resolver, gai.conf, server, child_env}
    try:
        for sid in scenario_ids:
            repeat reps times (or until the adaptive rule stops, see 4.4):
                ENSURE_DNS(scenario[sid].dns.delay_ms); ensure nginx is listening on v4 and v6 port 80
                record := RUN_ONE(...)
                if record.cross_checks.status = "conflict": print every conflict; exit status 3
    on any error or Ctrl-C: stop the session (exit status 1)
    finally: stop DNS and nginx; HL_SET_LINK(v4, 10, 0); HL_SET_LINK(v6, 10, 0)
```

### 2.2 The run itself `[src/runner/orchestrate.py → run_one]`

```
procedure RUN_ONE(client, sid, sc, rep):
    run_id := "<UTC start>_<sid>_<client>_r<rep>"      # wait for a new second if the ID exists
    try:
        # 1-2. apply the scenario, then verify-before
        HL_SET_LINK(v4, sc.v4.delay_ms_each_way, sc.v4.loss_pct)        [netem.sh]
        HL_SET_LINK(v6, sc.v6.delay_ms_each_way, sc.v6.loss_pct)
        pre := VERIFY_UP(sc.verify_target.v4, sc.verify_target.v6)
        if pre failed: STOP SESSION                    # no run on an unverified lab
        pre_rtt := RTT lines parsed from pre's output   [parse_verify_rtt]

        # 3. start capture
        ifmap := interface number -> name in hl-client  [parse_ifindex_map]
            # tcpdump -i any (SLL2) stores interface numbers only
        start, in hl-client:                            [cmd_tcpdump, start_capture]
            tcpdump -i any --immediate-mode -s 65535 -B 65536 -U -w <run_id>.pcap
                "tcp port 80 or tcp port 443 or udp port 443 or udp port 53 or icmp or icmp6 or arp"
        wait (≤ 5 s) for "listening on", else STOP SESSION
        capture_start_ns := now

        # 4. run the client, inside hl-client as the normal user, env = child_env()
        client_start_ns := now
        proc, peak_rss := RUN_CLIENT(argv, env, timeout)  [run_client]
            # refuses to start if a stripped variable is in env; reaps with wait4 for peak RSS
            curl:     curl -q -sS --noproxy '*' --max-time 10 -o /dev/null -w <report format> http://www.hl.test/
            chromium: client_chromium.py --url http://www.hl.test/chromium.html --netlog <run>_netlog.json
        client_end_ns := now

        # 5. stop capture
        sleep 0.5 s                                    # closing FIN/ACKs
        SIGINT tcpdump; keep its exit summary (captured / received / dropped)   [stop_capture]
        capture_end_ns := now

        # 6-7. restore the baseline, then verify-after
        HL_SET_LINK(v4, 10, 0); HL_SET_LINK(v6, 10, 0)  [restore_baseline]
        post_ok := VERIFY_UP(20, 20) passed
    on error:
        stop tcpdump if running; restore the baseline; re-raise (the session stops)

    # 8. parse the pcap for this run's window only
    timeline := PARSE_PCAP(<run_id>.pcap, window = [client_start_ns, capture_end_ns])   (§3.1)
    sha256   := SHA-256 of the pcap bytes

    # 9. build the run record                          [build_record]
    outcome := client's own report: success, exit code, HTTP status, error,
               client_report (curl -w fields / Playwright report)        (client log)
    m       := COMPUTE_METRICS(timeline)                                 (§3.2)
    packet_observations, metrics := RECORD_FIELDS(m)                     (packet-level)
    cross_checks := CROSS_CHECK(outcome, m)                              (§3.3)
    if the tcpdump summary is incomplete, or dropped > 0, or captured < received:   [capture_problem]
        add conflict "capture incomplete"; cross_checks.status := "conflict"
    record := {schema_version "0.3", run_id,
               scenario {id, label, repetition, netem config, dns config,
                         measured_rtt_ms {v4, v6} from pre_rtt},          (lab check)
               client {name, version, argv, config}, environment + ifmap,
               timestamps {client start/end, capture start/end, epoch ns},
               outcome, evidence {pcap path, pcap_sha256, client log path,
                                  pre_verify_ok, post_restore_verify_ok},
               packet_observations, metrics, cross_checks}
    record.profile := {wall time, pcap bytes, client peak RSS}           (runner measurement)
    record.adaptive := stopping-rule state after this run (adaptive sessions only, §4.4)

    if VALIDATE(record) lists problems: STOP SESSION   [src/analysis/validate_record.py → validate]
    write data/generated/runs/<run_id>.json, exclusive create (an existing file is never overwritten)

    if not post_ok: STOP SESSION                       # the lab may not be at baseline
    if a capture conflict was recorded: STOP SESSION   # record kept, flagged
    return record
```

The record, the pcap and the run log stay on disk even when a run is flagged. Nothing is deleted
or relabelled.

---

## 3. Metric derivation

### 3.1 Reconstruct the timeline from packets `[src/analysis/parse_pcap.py → parse, read_pcap, analyse, _track_tcp, _track_dns]`

Packet-level only. This step decides nothing about which attempt won.

```
function PARSE_PCAP(path, window):
    read classic pcap (pcapng is rejected); decode Ethernet / raw IP / Linux cooked v1 / v2
    keep packets with window.start ≤ ts ≤ window.end; sort by timestamp (stable)
    for each packet p:
        ARP or ICMPv6 neighbour discovery -> count neighbour packets
        ICMP / ICMPv6 error               -> icmp_errors
        TCP                               -> TRACK_TCP(p)
        UDP port 53                       -> TRACK_DNS(p)
        other UDP                         -> other_udp (e.g. QUIC on 443)
    anomalies += TCP packets matching no SYN in the window; DNS queries without a response
    return timeline {attempts sorted by first SYN, dns exchanges, icmp_errors, anomalies, …}

TRACK_TCP(p):                                          # an attempt is keyed by (src, sport, dst, dport) of its SYN
    SYN without ACK, new 4-tuple        -> new Attempt {family, first_syn_ns = p.ts, client_isn = p.seq}
    SYN without ACK, known 4-tuple      -> syn_count += 1        # kernel retransmission, same socket
    server -> client SYN+ACK with ack = client_isn + 1 (first one) -> synack_ns, server_isn
    client -> server ACK after SYN-ACK with ack = server_isn + 1 (first one) -> handshake_ack_ns
    client payload                      -> client_data_bytes, first_client_data_ns
    RST from either side                -> server_rst_ns / client_rst_ns
    server segment starting "HTTP/"     -> http_status

TRACK_DNS(p):
    query    -> new exchange {client addr:port, id, qname, qtype, query_ns}
    response -> match the open query with the same client addr:port and id -> response_ns, rcode, answers
```

### 3.2 Per-run metrics `[src/analysis/metrics.py → compute, classify, record_fields]`

The three metric definitions are fixed in `CLAUDE.md`. The code implements them as follows.

```
function COMPUTE_METRICS(timeline):
    attempts := timeline.attempts with dport = 80      # other ports count as unexpected traffic

    # winning attempt (project rule)                   [classify]
    used := attempts with a completed handshake and client data > 0
    if |used| = 1:      winner := that attempt
    elif |used| > 1:    winner := none; ambiguous := true    # metrics left "not_yet_computed"
    elif any completed: winner := first completed handshake (with a note)
    else:               winner := none
    result of each attempt:
        won        it is the winner
        failed     server sent RST and the handshake never completed
        abandoned  any other attempt, when a winner exists (or the run is ambiguous, or it completed)
        no_reply   no SYN-ACK and no winner at all

    first_syn := min(first_syn_ns over attempts)       # first SYN of the run, either family

    # TCP setup time = first SYN to the ACK completing the winning handshake (DNS excluded)
    tcp_setup_time_ms := winner.handshake_ack_ns − first_syn      if winner exists
                         else "not_observed"

    # Inter-family attempt delay = second family's first SYN − first family's first SYN
    first_by_family := earliest first_syn_ns per family
    if two families were tried: inter_family_attempt_delay_ms := later − earlier
    else:                       "not_observed" ("only one family tried (v6)")

    # DNS time (project definition; kept separate from TCP setup)
    queries := DNS queries for www.hl.test sent at or before first_syn
    if every query was answered: dns_time_ms := max(response_ns) − min(query_ns)
    else:                        "not_observed"
    queries for other names before first_syn are listed in a note, not counted

    # always recorded (packet-level)
    winning_family, attempts [{family, dst, src_port, first_syn_ns, syn_retransmits, result}],
    failed_or_abandoned_attempts := count of attempts whose result ≠ won

    scenario_penalty_ms := "not_applicable" in the run record (it is a per-scenario value, §4.3)
```

All values are in milliseconds, rounded to the microsecond. Every field is
`{value, status, note}`, where `status ∈ {computed, not_observed, not_yet_computed, not_applicable}`.
A value that wasn't observed stays a status and is never replaced with a number.

### 3.3 Client log against the capture `[src/analysis/metrics.py → cross_check]`

```
function CROSS_CHECK(outcome, client_report, m):
    conflicts := []
    if m.ambiguous:                                       conflict "winner"
    elif client says success but the pcap has no winner with an HTTP response:   conflict "success"
    elif client says failure but the pcap shows an HTTP response:                conflict "success"
    if client and pcap HTTP statuses both exist and differ:                      conflict "http_status"
    if client's remote_ip ≠ winning handshake's destination:                     conflict "remote_ip"
    if client reported success without a connected address:                     conflict "remote_ip"
    if any TCP to a port other than 80, or UDP to/from 443:                      conflict "unexpected_traffic"
    return {status: "conflict" if conflicts else "agree", conflicts}
```

`CROSS_CHECK` never chooses between the log and the pcap. A disagreement is written down, and a
person has to resolve it.

### 3.4 Scenario penalty `[src/analysis/metrics.py → scenario_penalty]`, applied in `[src/analysis/summarise.py → summarise]`

```
for each client c, scenario s in the dataset:
    S  := computed TCP setup times of c in s
    C0 := computed TCP setup times of c in C0 (same dataset; never borrowed from another)
    scenario_penalty_ms(c, s) := median(S) − median(C0)      (None if either list is empty)
```

### 3.5 Oracle baseline and cost of racing — Derived (pcap − lab RTT) `[src/analysis/metrics.py → oracle_baseline]`, called per run by `[src/analysis/summarise.py → run_from_record]`

This is a project addition alongside the fixed metrics. It replaces none of them and needs no new
measurements.

```
function ORACLE_BASELINE(winning_family, tcp_setup_time_ms, measured_rtt_ms, families_tried, dns_delay):
    if no winning family:                         both "not_observed"
    rtt := measured_rtt_ms[winning_family]        # pre-run ping median from VERIFY_UP (§1.6), never a constant
    if rtt is not computed:                       both "not_available" (with the RTT's own status)
    oracle_setup_ms := rtt
    if no TCP setup time:                         cost "not_observed"
    cost_of_racing_ms := tcp_setup_time_ms − rtt  # not clamped: a negative value is reported as it is
    notes:
        only one family tried -> single_family = true: no race took place; the value is handshake
                                 time against the ping RTT only
        DNS answer delay set  -> that delay is outside TCP setup, so it is not in the cost; see dns_time_ms
    evidence := "derived: packet-level TCP setup time (pcap) minus the winning family's RTT measured
                 by the lab verify step before the run (ping median)"
```

*Interpretation (labelled):* the oracle uses the winning family in hindsight. No client can know the
winner before it connects, so the oracle is a reference for comparison, not a time any client could
be expected to reach.

---

## 4. Aggregation

### 4.1 Batch check after every batch `[src/analysis/check_batch.py → check_batch, check_run]`, run by `[src/runner/run_matrix.py]`

Read-only. `run_matrix.py` runs the 14 batches (2 clients × C0–S6) one after another, never
overlapping, and stops on a failed check. It never retries a batch by itself.

```
function CHECK_BATCH(client, scenario, expect, sessions):
    started := every run whose run log names one of the sessions (including runs that never wrote a record)
    for each started run:
        good iff: record and pcap both exist; record validates; pcap_sha256 present and equal to
                  SHA-256 of the pcap on disk; record points at that pcap; pre_verify_ok and
                  post_restore_verify_ok are true; cross_checks = agree; client/scenario match;
                  git commit not "-dirty"
    batch problems: no runs; pcap count ≠ record count; a repetition with two good records;
                    repetition numbers above expect
    PASS iff repetitions 1..expect each have a good record, every run is good, and there are no batch problems
    on FAIL: list flagged runs (left on disk unchanged) and print the commands to re-run the missing repetitions
```

### 4.2 Refusal to analyse an uncertified dataset `[src/analysis/summarise.py → load_manifest, load_runs]`

In this file, **certified** means two things: the session is listed in a dataset manifest
(`docs/dataset.md` for the frozen core dataset, or `docs/datasets/<name>.md`), and every one of its
records passes the checks below. `summarise.py`, `oracle.py` and `dashboard.py` all read data only
through `summarise.build()`, so all three refuse the same things.

```
function BUILD(manifest):
    # the manifest
    shape := core shape (curl, chromium × C0–S6 × 20 reps), or the YAML header of a named manifest
             (clients, scenarios, reps or {min, max, ci_width_ms}; unknown keys, clients or scenarios refused)
    rows  := the "Sessions in the dataset" table; a numbered row that cannot be read -> REFUSE
    if the rows are not exactly one session per client × scenario of the shape: REFUSE

    # the records of exactly those sessions
    for each (client, scenario, session) row:
        recs := run records whose environment.session_id = session
        fixed reps:    REFUSE unless |recs| = reps and repetitions are exactly 1..reps
        adaptive reps: REFUSE unless min ≤ |recs| ≤ max, repetitions 1..n, every record's adaptive
                       settings match the manifest, the decision is "continue" on every run but the
                       last and "stop" on the last, and replaying the rule gives the same decisions
        for each record: REFUSE unless client/scenario match the row, cross_checks = agree,
                         pre_verify_ok and post_restore_verify_ok are true
        S6 only: REFUSE if the pcap's SHA-256 differs from the record, then re-parse the pcap
                 for the A/AAAA answer times and first-SYN offsets (packet-level)
    REFUSE := raise DatasetError -> the script prints the reason and exits 1, writing no summary
    return SUMMARISE(runs)
```

A record left out by the refusal is never dropped quietly, and the remaining runs are not analysed
as if the dataset were complete. The whole dataset is rejected.

### 4.3 Per-cell summary `[src/analysis/summarise.py → summarise_cell, summarise, oracle_cell]`

```
for each client × scenario cell:
    n, successes                                                       (client log)
    winning_family counts; first-SYN family counts                     (packet-level)
    tcp_setup_ms: median, Q1, Q3 (inclusive quartiles), min, max       (packet-level; no mean, no SD)
    tcp_setup_median_ci95 := BOOTSTRAP_MEDIAN_CI(setup times)          (§4.4)
    setup_not_observed := runs without a computed setup time
    inter_family: observed count, not_observed count,
                  statistics over observed runs only (never averaged with "not observed")
    failed/abandoned: distribution of per-run counts, and the total
    attempt shape per run (e.g. v6>v6>v4) and attempt offsets from the first SYN by kind
        (first / same-family / other-family); SYN retransmissions counted separately
    dns_ms statistics; for S6, A and AAAA answer times and first SYN relative to them
    measured_rtt_ms per family: median of computed values plus status counts (a blackhole is a status, not 0)
    oracle (Derived (pcap − lab RTT)): oracle_setup and cost_of_racing statistics over runs
        where they were computed, with the other statuses counted and single-family runs counted
    cost: wall time, pcap bytes, client peak RSS                       (runner measurement)
    Chromium only: NetLog connect jobs and resolver order              (client log)
then per client: scenario_penalty_ms for every scenario (§3.4)
then: interpretations, each labelled and listing the packet / client-log / derived evidence it rests on
```

### 4.4 Bootstrap CI and the adaptive stopping rule `[src/analysis/metrics.py → bootstrap_median_ci, adaptive_decision]`

```
function BOOTSTRAP_MEDIAN_CI(values, level = 0.95, resamples = 10 000, seed = 0):
    v := values that are not None
    if |v| < 2: return None
    rng := Random(seed)                          # fixed seed: the CI can be recomputed exactly
    meds := sorted( median(rng.choices(v, k = |v|)) repeated resamples times )
    lo := meds[ int(0.025 × resamples) ]         # index 250
    hi := meds[ int(0.975 × resamples) − 1 ]     # index 9749
    return {lo, hi, width = hi − lo, level, n, resamples, seed, method = "percentile bootstrap of the median"}
```

The CI describes spread. It is not a significance test, and with about 10 values or fewer a
percentile bootstrap tends to give intervals that are too narrow.

The adaptive rule is optional and is used only with `--reps-adaptive MIN MAX --ci-width-ms W`. The
core dataset used a fixed 20 repetitions.

```
function ADAPTIVE_DECISION(setup_times so far, min, max, W):
    ci := BOOTSTRAP_MEDIAN_CI(setup_times)
    if runs < min:                 continue
    elif ci exists and ci.width ≤ W: stop ("ci_width_reached")
    elif runs ≥ max:               stop ("max_reps_reached")
    else:                          continue
    # looks only at the CI width, never at the median's value
```

---

## What this pseudocode does not claim

- None of these steps says whether a client follows or breaks RFC 8305. The metrics are times
  between packets in this lab. RFC 8305's 250 ms is a reference value, not a threshold applied
  anywhere in the code.
- netem settings are configuration, and the ping RTT from `verify.sh` is what each record keeps.
  The capture is the evidence for every packet-level metric.
- Client reports (curl `-w`, Playwright, NetLog) are compared with the capture and never overwrite
  it.
