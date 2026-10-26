# HappyLab — Project Instructions

## Project
AIORI-3 PS-028:
Happy Eyeballs IPv4/IPv6 Fallback Measurement.

## Team
- Sam: Backend, network lab, orchestration and data collection.
- Pranav: Frontend, browser automation and testing.

## Required scope
- Two existing clients: curl and Chromium via Playwright.
- Six controlled failure/delay scenarios.
- At least 20 repetitions per client per scenario.
- A separate healthy baseline.
- Controlled DNS and network impairments.
- Connection timelines, packet captures and structured results.
- An explanatory dashboard and technical report.

## Measurement integrity
- Never invent experimental results.
- Distinguish packet-level observations from interpretations.
- Record client versions and configuration.
- Do not claim standards conformance from undocumented internals.

## Safety
- Use an isolated Linux network lab.
- Review all network-changing commands before execution.
- Do not modify the host's normal routes or physical-interface rules.
- Every impairment must have a cleanup and verification step.

## Development
- Inspect the repository before editing.
- Plan before making multi-file changes.
- Work in small, reviewable increments.
- Add tests for parsing and metric calculations.

## Fixed metric definitions (do not redefine)
- TCP setup time = first SYN to the ACK completing the winning handshake. DNS time is separate.
- Inter-family attempt delay = second family's first SYN minus first family's first SYN ("not observed" if only one family).
- Scenario penalty = client's median setup time minus its own median in C0.
- Always also record: winning family, success/failure, failed or abandoned attempts.

## Scenarios (values are provisional until pilots confirm them)
C0 healthy; S1 IPv6 blackhole; S2 IPv6 +600 ms RTT; S3 IPv6 +150 ms; S4 IPv4 blackhole;
S5 IPv4 +600 ms; S6 AAAA answer delayed 300 ms; X1 optional compound stress.
Baseline 10 ms each way. Measure the real RTT before every scenario; netem config is not ground truth.
"+N ms RTT" is added to the 20 ms baseline, split per direction on that family's link:
each way = 10 + N/2 ms, verify target = 20 + N ms (S2/S5: 310 ms each way, 620 ms target).
TCP setup time excludes DNS, so S6's delay shows only in dns_time_ms; always report both for S6.

## Wording rules
- Packet captures = packet-level evidence. Client/runner logs = outcomes. Anything else is interpretation, labelled as such.
- Never say RFC 8305 predicts an exact completion time. 250 ms is a reference, not a threshold.
- HE v3 draft is background only. No conformance claims from undocumented client internals.
- Mobile scenarios are "mobile-inspired latency conditions", never carrier measurements.
- British spelling in code comments, docs and report text.

## Lab safety
- All impairments live in namespaces prefixed `hl-`. Never touch the host's default namespace, Wi-Fi interface, routes or firewall.
- Every setup script has a matching teardown and a verify step. Scripts use `set -euo pipefail`.
- Claude writes network/sudo scripts; Sam reviews and runs them in a separate terminal and pastes the output back.

## Gotchas
- The dev shell sources ROS (`/opt/ros/jazzy/setup.bash`), which sets `PYTHONPATH` and `LD_LIBRARY_PATH`. Never let them reach tests, clients or lab services.
- Run tests with `scripts/test.sh`, never bare `pytest` (ROS pytest plugins fail to import and abort the run).
- Start every subprocess (curl, Chromium/Playwright, DNS server, nginx, tcpdump) with `env=child_env()` from `src/runner/child_env.py`, and record what was stripped in the run record.
- Never run the orchestrator with `sudo -E`; it would pass the ROS variables through.
- Host `/etc/gai.conf` prefers IPv4. The lab uses its own default `gai.conf` via `/etc/netns/hl-client/` only; never edit the host file.
- Apply netem only on the server-side link ends (egress, plus an ifb for ingress). netem on the
  client's egress acts before tcpdump's tap, so the client capture would miss dropped SYNs and
  timestamp delayed ones late.
- Keep the static `nud permanent` neighbour entries. Without them, a 100% loss blackhole turns into
  ARP/ND failure and "host unreachable" errors instead of a silent drop.
- tcpdump must use `--immediate-mode`. Without it, a capture shorter than about 1 s can be written
  empty ("0 packets captured, N received by filter"). The orchestrator stops on an incomplete capture.
- `tcpdump -i any` (SLL2) stores interface numbers, not names, so the run record keeps the
  hl-client interface map. Don't trust interface names shown when reading the pcap on the host.
- Test fixture pcaps live only in `src/tests/fixtures/` (small, lab-only traffic). `captures/` and
  `data/generated/` are gitignored and are never committed.
- `gh pr edit` fails on this repo (classic Projects deprecation error). Edit PR bodies with
  `gh api -X PATCH repos/aiori-hackathon/A3-PS028-TC278/pulls/<n> -F body=@file`.
