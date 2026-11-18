<!-- DRAFT for the Chromium issue tracker. Sam posts it; nothing here has been sent. -->

**Title:** IPv6 unreachable (SYNs silently dropped): a second IPv6 SYN to the same address goes out about 250 ms after the first, before the IPv4 attempt at about 300 ms

**Component (suggested):** Internals>Network>Connectivity

**Type:** Bug. It could equally be a question: we do not know whether this behaviour is intended.

---

### Summary

In a controlled lab, the server's IPv6 address silently drops every packet, and the IPv4 path is
healthy. The packet capture on the client shows the same sequence in every run:

1. an IPv6 SYN at t = 0,
2. a **second IPv6 SYN to the same address and port, from a different source port**, at about t = 250 ms,
3. an IPv4 SYN at about t = 301 ms. The IPv4 connection completes and the page loads.

We are reporting what the packets show. We make no claim about how Chromium is built inside, or
what it is meant to do here. We are asking whether the second same-address IPv6 attempt is
intended, and whether the ~250 ms and ~300 ms delays are expected for this situation.

### Version and configuration

- **Browser:** Google Chrome for Testing 156.0.8078.4 (official build), `f842f52ef39fd97b449eb27cff414bf05a98ddce-refs/branch-heads/8078@{#13}`.
  This is the build Playwright 1.64.1 installs as `chromium-1248`, as reported in NetLog `clientInfo`.
- **Driver:** Playwright 1.64.1 (Python), `channel="chromium"`, new headless mode. There is one fresh browser process and fresh profile per run.
- **OS:** Ubuntu, Linux 7.0.0-38-generic x86_64.
- **Full command line,** as recorded by Chromium in the NetLog. The user-data-dir and netlog paths are abbreviated.

```
chrome --disable-field-trial-config --disable-background-networking --disable-background-timer-throttling
--disable-backgrounding-occluded-windows --disable-back-forward-cache --disable-breakpad
--disable-client-side-phishing-detection --disable-component-extensions-with-background-pages
--disable-component-update --no-default-browser-check --disable-default-apps --disable-dev-shm-usage
--disable-edgeupdater --disable-extensions --enable-features=CDPScreenshotNewSurface --allow-pre-commit-input
--disable-hang-monitor --disable-ipc-flooding-protection --disable-popup-blocking --disable-prompt-on-repost
--disable-renderer-backgrounding --disable-updater-scheduler --force-color-profile=srgb --metrics-recording-only
--no-first-run --password-store=basic --use-mock-keychain --no-service-autorun --export-tagged-pdf
--disable-search-engine-choice-screen --unsafely-disable-devtools-self-xss-warnings --edge-skip-compat-layer-relaunch
--disable-infobars --disable-search-engine-choice-screen --disable-sync --enable-unsafe-swiftshader --headless
--hide-scrollbars --mute-audio --blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4
--no-sandbox --disable-quic
--disable-features=AvoidUnnecessaryBeforeUnloadCheckSync,DestroyProfileOnBrowserClose,DialMediaRouteProvider,GlobalMediaControls,HttpsUpgrades,LensOverlay,MediaRouter,PaintHolding,ThirdPartyStoragePartitioning,BlockOriginHeaderModificationOnRedirect,AvoidCorsURLLoaderRestartOnRedirect,Translate,AutoDeElevate,OptimizationHints,NetworkTimeServiceQuerying,AimEnabled,msForceBrowserSignIn,msEdgeUpdateLaunchServicesPreferredVersion,DnsOverHttps
--log-net-log=<path> --net-log-capture-mode=Default --user-data-dir=<tmp> --remote-debugging-pipe
--no-startup-window --noerrdialogs --ozone-platform=headless --ozone-override-screen-size=800,600
--use-angle=swiftshader-webgl --flag-switches-begin --flag-switches-end --enable-unsafe-swiftshader
```

Note that `--disable-field-trial-config` is present, so no field-trial configuration was applied.
QUIC and DNS-over-HTTPS are off. Happy Eyeballs and resolver settings were left at their defaults.

### Lab setup

- Two Linux network namespaces on one host: a client and a server, joined by separate veth links for IPv4, IPv6 and DNS.
- Server: nginx 1.24.0, plain HTTP/1.1 on port 80. URL: `http://www.hl.test/chromium.html`.
- DNS: a local authoritative server on its own link, which is never impaired. `www.hl.test` has
  A 192.0.2.2 and AAAA 2001:db8:28:6::2, TTL 0. Both answers arrive within about 1 ms.
- Baseline: 10 ms one-way delay on each data link, so the RTT is about 20 ms.
- **Impairment:** 100% loss on the IPv6 link in both directions, applied by netem on the server side.
  The client interface has no qdisc, so the client-side capture records each packet when it is sent.
  Static permanent neighbour entries mean the drop is silent: no ICMPv6 errors are generated, and none appear in the capture.
- Before each run, ping measured IPv4 RTT at about 21 ms and IPv6 at 100% loss with 0 ICMP errors.
- The capture is `tcpdump -i any --immediate-mode` inside the client namespace.

### Steps to reproduce

The lab scripts are public: https://github.com/aiori-hackathon/A3-PS028-TC278 (commit `ecba28c` was used for the runs below).

```
sudo src/lab/setup.sh
sudo .venv/bin/python src/runner/orchestrate.py --client chromium --scenario S1 --reps 3
sudo src/lab/teardown.sh
```

Outside our lab, the conditions should be: a hostname with both A and AAAA records; IPv6 SYNs to
that address silently dropped with no ICMP and no RST; and a working IPv4 path. **We have only
observed this in our lab and have not reproduced it on another setup.**

### Observed: example capture

File: `examples/20261026T193420Z_S1_chromium_r01.pcap` in the repository. It is 20,186 bytes, and its SHA-256 is
`a42eaa79d9a0bee9ae9f4001c885b5368b1960f3e3fb8a5f2f63259a98bd2152`.

The capture is Linux cooked v2 (`-i any`), which stores interface **indices**. When it is read
on another host, tcpdump shows that host's interface names, which are wrong; in our own output they appear as
`docker0` and `wlp1s0`. The correct map is 2 = IPv4 client link, 3 = IPv6 client link, 4 = DNS link.
The capture also contains Chromium's startup DNS queries for Google hostnames. Our lab server
answers those with REFUSED, and they can be ignored.

`tcpdump -nn -tt -r` output for `www.hl.test`, with times relative to the first IPv6 SYN added on the left:

```
  -1.1 ms  198.51.100.1.33381 > 198.51.100.53.53: HTTPS? www.hl.test.
  -1.0 ms  198.51.100.1.19399 > 198.51.100.53.53: AAAA? www.hl.test.
  -0.9 ms  198.51.100.1.7426  > 198.51.100.53.53: A? www.hl.test.
  -0.3 ms  AAAA 2001:db8:28:6::2
  -0.3 ms  A 192.0.2.2
   0.000   IP6 2001:db8:28:6::1.58826 > 2001:db8:28:6::2.80: Flags [S], seq 2172840996, ... TS val 2513278021
 250.290   IP6 2001:db8:28:6::1.58830 > 2001:db8:28:6::2.80: Flags [S], seq 953043359,  ... TS val 196583256
 301.266   IP  192.0.2.1.34294 > 192.0.2.2.80: Flags [S]
 324.708   IP  192.0.2.2.80 > 192.0.2.1.34294: Flags [S.]
 324.766   IP  192.0.2.1.34294 > 192.0.2.2.80: Flags [.]
 325.482   IP  192.0.2.1.34294 > 192.0.2.2.80: GET /chromium.html HTTP/1.1
```

These are the packet-level facts that show the second IPv6 SYN is **not a TCP SYN retransmission**:
- It has a different source port (58826, then 58830).
- It has a different initial sequence number.
- It has an unrelated TCP timestamp value.
- Neither IPv6 socket sent a second SYN. The capture runs for more than 1 s after the first SYN.
- Neither IPv6 socket sent a FIN or RST.

### Observed: across runs (packet-level)

These are 20 runs per scenario, from one session each on 2026-10-26. All are measured from the first IPv6 SYN.

| Scenario | Runs showing v6, v6, v4 | 2nd v6 SYN, min / median / max | First v4 SYN, min / median / max | Kernel SYN retransmissions |
|---|---|---|---|---|
| IPv6 blackhole (100% loss) | 20/20 | 249.6 / 250.6 / 252.2 ms | 300.2 / 301.1 / 302.9 ms | 0 |
| IPv6 path at +600 ms RTT (620 ms total), no loss | 20/20 | 249.3 / 250.7 / 252.1 ms | 300.3 / 301.1 / 302.5 ms | 0 |

- **Second IPv6 source port:** in all 40 runs the second IPv6 SYN used a different source port from the first.
- **Late SYN-ACKs in the +600 ms case:** in three pilot runs we checked by hand, both IPv6 SYN-ACKs arrived about 620 ms after their SYNs,
  after IPv4 had already won. The client answered each one with a RST.
- **+150 ms case** (IPv6 RTT about 170 ms): the IPv6 handshake completed at about 170 ms. No second
  SYN of either family was sent (20/20 runs).
- **Healthy baseline:** a single IPv6 SYN was sent, and the connection completed in about 20 ms (20/20 runs).
- **Page loads:** every run loaded the page (HTTP 200). This report is not about a failure to connect.

### Question

The capture shows Chromium attempting the same IPv6 address twice before it tries IPv4, and
the first IPv4 SYN going out at about 300 ms. We'd like to know:
1. Is the second same-address IPv6 attempt intended when the first gets no answer?
2. Are the ~250 ms and ~300 ms delays expected here?

If both are intended, the issue can be closed. We would still find a pointer to where this is
documented useful.

We have a NetLog for each run and can attach one on request.
