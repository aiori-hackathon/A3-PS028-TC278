<!-- DRAFT for happy@ietf.org. Sam posts it; nothing here has been sent. Plain text when sent. -->

**To:** happy@ietf.org
**Subject:** Measurement data: curl and Chromium under IPv6/IPv4 impairments, incl. delayed AAAA

Hello all,

We are a small team that built a lab to measure how two existing clients behave under controlled
IPv4/IPv6 failures and delays. We are sharing the data in case it is useful to the working group.
This message describes what we measured. It is not an evaluation of either client against RFC 8305
or draft-ietf-happy-happyeyeballs-v3. We pinned revision -04 as background and are aware that -05
(2026-11-02) is current.

**Setup**

- **Lab:** two Linux network namespaces on one host. The IPv4 and IPv6 data paths are on separate links,
  and DNS is on a third link that is never impaired. Baseline RTT is 20 ms. Impairments are applied
  with netem on the server side, and the actual RTT is measured before every run.
- **Clients:** curl 8.5.0 (Ubuntu package, 8.5.0-2ubuntu10.16) and Chrome for Testing 156.0.8078.4, driven by
  Playwright 1.64.1. Both use default Happy Eyeballs and resolver settings. Chromium has QUIC and DoH turned off.
- **curl's resolver:** `curl -V` lists AsynchDNS and no c-ares, which curl's documentation describes as its
  threaded resolver over the system `getaddrinfo`. That is our reading of the documentation, not something we observed.
  What the captures do show: in all 140 curl runs, the A and AAAA queries left together from one
  source port, A first, 0.024–0.056 ms apart.
- **Runs:** 7 conditions × 2 clients × 20 runs = 280 runs. The conditions are a healthy baseline, an IPv6 blackhole,
  IPv6 at +600 ms and +150 ms RTT, an IPv4 blackhole, IPv4 at +600 ms, and a delayed AAAA answer.
- **Data per run:** a packet capture taken on the client side, and a structured record with
  per-attempt SYN times, the winning family and DNS time. We keep packet-level observations
  separate from what the clients report about themselves.

**One observation: AAAA answer delayed by 300 ms, A answer immediate**

Our DNS server answered A at once and held only the AAAA answer for 300 ms. Over 20 runs per
client, the packet captures show:

- **A answer:** arrived after a median of 0.99 ms (curl) and 0.84 ms (Chromium) from the first query.
  For curl, the AAAA query had gone out with the A query, so the 300 ms gap is in the answer alone.
- **First SYN:** in 20/20 runs for each client, it was sent only after the AAAA answer arrived, and it was IPv6 every time.
  The median time after the first A answer was 301.8 ms for both clients. The range was 301.2–302.5 ms for curl and 300.8–303.8 ms for Chromium.
- **IPv4 SYN:** neither client sent one at any point (0/20 runs each).
- **TCP setup time:** this is measured from the first SYN, and it stayed at baseline, about 21 ms. The whole 300 ms appears as DNS time.

For comparison, RFC 8305 Section 3 describes a Resolution Delay, with a recommended value of
50 ms, after which a client that has only A records would start connecting. We did not see that
behaviour in these two client versions. We draw no conclusion about why. The captures show when
packets were sent, not how either client's resolver or connection logic is built. These results
apply only to these versions, in this lab, with 20 runs per cell.

**What we can offer**

- **Data:** the full dataset, with per-run captures and records, and the lab scripts. The scripts and
  two example runs are at https://github.com/aiori-hackathon/A3-PS028-TC278.
- **More runs:** we can run further conditions if they would help the group.
  Examples are other DNS timings, the HTTPS/SVCB cases in the v3 draft (-04 as pinned), or other clients and versions.
  Suggestions for what would be most useful are welcome.

Corrections to the method are welcome too.

Regards,
[names], AIORI-3 hackathon team A3-PS028-TC278
