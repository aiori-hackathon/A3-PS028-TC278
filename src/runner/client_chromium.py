"""HappyLab Chromium client: one fresh browser, one navigation, one JSON report on stdout.

Run by the orchestrator inside hl-client as the normal user, one process per run:
    ip netns exec hl-client runuser -u sr -- .venv/bin/python src/runner/client_chromium.py \
        --url http://www.hl.test/chromium.html --netlog data/generated/logs/<run_id>_netlog.json

Smoke test (launches and closes the browser, navigates nowhere):
    .venv/bin/python src/runner/client_chromium.py --version

Everything this prints is client-reported (Playwright / DevTools), not packet-level evidence.
Settings (decided in the project plan, recorded in every run record):
  - fresh browser process and fresh temporary profile per run
  - full Chromium in new headless mode (channel "chromium"), not the headless shell
  - QUIC off, Secure DNS (DoH) off, HTTPS-Upgrades off
  - no Happy Eyeballs or resolver overrides: Chromium's own defaults are what we measure
  - NetLog written per run as raw evidence; only its recorded command line is read here

Chromium honours only one --disable-features switch. Playwright passes its own list, so a second
switch from us silently replaced it in the first pilot (its startup-traffic blockers stopped
working). We now replace Playwright's switch with one merged switch, and after every run read the
command line Chromium actually received from the NetLog and fail the run if it is not exactly that.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from importlib import metadata

CHANNEL = "chromium"          # full Chromium, new headless mode
HEADLESS_MODE = "new headless (channel=chromium)"
SANDBOX = False               # Playwright's default (chromiumSandbox=False); recorded, not hidden
NAV_TIMEOUT_MS = 15_000
PINNED_PLAYWRIGHT = "1.64.1"
# Playwright 1.64.1's own --disable-features list, verbatim (driver coreBundle.js, chromiumSwitches).
PLAYWRIGHT_DISABLED_FEATURES = (
    "AvoidUnnecessaryBeforeUnloadCheckSync", "DestroyProfileOnBrowserClose", "DialMediaRouteProvider",
    "GlobalMediaControls", "HttpsUpgrades", "LensOverlay", "MediaRouter", "PaintHolding",
    "ThirdPartyStoragePartitioning", "BlockOriginHeaderModificationOnRedirect",
    "AvoidCorsURLLoaderRestartOnRedirect", "Translate", "AutoDeElevate", "OptimizationHints",
    "NetworkTimeServiceQuerying", "AimEnabled", "msForceBrowserSignIn",
    "msEdgeUpdateLaunchServicesPreferredVersion")
PLAYWRIGHT_DISABLE_SWITCH = "--disable-features=" + ",".join(PLAYWRIGHT_DISABLED_FEATURES)
REQUIRED_DISABLED = ("DnsOverHttps", "HttpsUpgrades")  # ours: Secure DNS off, HTTPS-Upgrades off
DISABLED_FEATURES = PLAYWRIGHT_DISABLED_FEATURES + tuple(
    f for f in REQUIRED_DISABLED if f not in PLAYWRIGHT_DISABLED_FEATURES)
TIMING_KEYS = ("domainLookupStart", "domainLookupEnd", "connectStart", "connectEnd",
               "requestStart", "responseStart", "responseEnd", "loadEventEnd")


def launch_args(netlog: str | None) -> list[str]:
    args = ["--disable-quic", f"--disable-features={','.join(DISABLED_FEATURES)}"]
    if netlog:
        args += [f"--log-net-log={netlog}", "--net-log-capture-mode=Default"]
    return args


def check_command_line(command_line: str) -> list[str]:
    """Problems with the command line Chromium actually received (from its NetLog). [] = as intended."""
    args = command_line.split()
    feature_switches = [a for a in args if a.startswith("--disable-features=")]
    problems = []
    if len(feature_switches) != 1:
        problems.append(f"{len(feature_switches)} --disable-features switches (Chromium uses only one)")
    elif set(feature_switches[0].split("=", 1)[1].split(",")) != set(DISABLED_FEATURES):
        problems.append(f"--disable-features is not the merged list: {feature_switches[0]}")
    if "--disable-quic" not in args:
        problems.append("--disable-quic missing")
    return problems


def netlog_command_line(path: str) -> str | None:
    """The command line Chromium recorded in a NetLog's constants (None if unreadable)."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return None
    for candidate in (text, text.rstrip().rstrip(",") + "]}"):  # a NetLog may lack its closing brackets
        try:
            return json.loads(candidate)["constants"]["clientInfo"]["command_line"]
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return None


def normalise_ip(addr: str | None) -> str | None:
    """'[2001:db8:28:6::2]' or '2001:DB8:28:6:0::2' -> '2001:db8:28:6::2'. None/'' -> None."""
    if not addr:
        return None
    addr = addr.strip()
    if addr.startswith("[") and addr.endswith("]"):
        addr = addr[1:-1]
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return addr


def ip_family(addr: str | None) -> str | None:
    addr = normalise_ip(addr)
    if addr is None:
        return None
    try:
        return "v6" if ipaddress.ip_address(addr).version == 6 else "v4"
    except ValueError:
        return None


REPORT_KEYS = ("ok", "error", "http_status", "remote_ip", "remote_port", "timing_ms",
               "browser_version", "playwright_version", "launch_args", "headless_mode",
               "sandbox", "netlog_path", "url", "launch_check")


def parse_report(stdout: str) -> dict:
    """The client's JSON line -> report dict with every key present (missing ones None)."""
    report: dict = {k: None for k in REPORT_KEYS}
    lines = [ln for ln in stdout.strip().splitlines() if ln.strip()]
    if not lines:
        report.update(ok=False, error="no report printed by client_chromium.py")
        return report
    try:
        data = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        report.update(ok=False, error=f"unreadable report: {exc}")
        return report
    report.update({k: data.get(k) for k in REPORT_KEYS})
    report["ok"] = bool(report["ok"])
    status = report["http_status"]
    report["http_status"] = status if isinstance(status, int) and status > 0 else None
    report["remote_ip"] = normalise_ip(report["remote_ip"])
    return report


def _playwright_version() -> str:
    try:
        return metadata.version("playwright")
    except metadata.PackageNotFoundError:
        return "unknown"


def run(url: str | None, netlog: str | None) -> dict:
    from playwright.sync_api import Error, sync_playwright

    report: dict = {k: None for k in REPORT_KEYS}
    args = launch_args(netlog)
    report.update(ok=False, playwright_version=_playwright_version(), launch_args=args,
                  headless_mode=HEADLESS_MODE, sandbox=SANDBOX, netlog_path=netlog, url=url)
    if report["playwright_version"] != PINNED_PLAYWRIGHT:
        report["error"] = (f"Playwright {report['playwright_version']} is not the pinned {PINNED_PLAYWRIGHT}; "
                           "its default --disable-features list must be re-checked first")
        return report
    with sync_playwright() as p:
        browser = p.chromium.launch(channel=CHANNEL, headless=True, chromium_sandbox=SANDBOX, args=args,
                                    ignore_default_args=[PLAYWRIGHT_DISABLE_SWITCH])
        try:
            report["browser_version"] = browser.version
            if url is None:
                report["ok"] = True
                return report
            context = browser.new_context()  # fresh, empty context in a fresh browser
            page = context.new_page()
            try:
                response = page.goto(url, wait_until="load", timeout=NAV_TIMEOUT_MS)
                if response is None:
                    report["error"] = "navigation returned no response"
                    return report
                report["http_status"] = response.status
                addr = response.server_addr()
                if addr:
                    report["remote_ip"] = normalise_ip(addr.get("ipAddress"))
                    report["remote_port"] = addr.get("port")
                timing = page.evaluate("() => { const e = performance.getEntriesByType('navigation')[0];"
                                       " return e ? e.toJSON() : null; }")
                if timing:
                    report["timing_ms"] = {k: timing.get(k) for k in TIMING_KEYS}
                report["ok"] = True
            except Error as exc:
                report["error"] = str(exc).splitlines()[0]
            finally:
                context.close()
        finally:
            browser.close()
    if netlog:  # the NetLog is complete once the browser has closed
        cmdline = netlog_command_line(netlog)
        problems = ["NetLog unreadable: launch settings not confirmed"] if cmdline is None else check_command_line(cmdline)
        report["launch_check"] = "ok" if not problems else "; ".join(problems)
        if problems:
            report["ok"] = False
            report["error"] = f"launch settings not as intended: {report['launch_check']}"
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url")
    ap.add_argument("--netlog", help="write a Chromium NetLog to this path")
    ap.add_argument("--version", action="store_true", help="launch, report the browser version, close")
    a = ap.parse_args(argv)
    if not a.version and not a.url:
        ap.error("--url is required (or use --version)")
    report = run(None if a.version else a.url, a.netlog)
    print(json.dumps(report), flush=True)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
