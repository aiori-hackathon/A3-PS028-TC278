"""Client definitions for the orchestrator: how to start each client and read what it reports.

Everything a client reports about itself (curl -w, Playwright/DevTools) is client-reported,
not packet-level evidence. The capture is checked against it in metrics.cross_check().
"""

from __future__ import annotations

import shlex
from pathlib import Path

from analysis.names import ClientName, parse_client
from analysis.scenario_config import scenario_ids
from runner import client_chromium

REPO = Path(__file__).resolve().parents[2]
VENV_PYTHON = REPO / ".venv" / "bin" / "python"
CHROMIUM_RUNNER = REPO / "src" / "runner" / "client_chromium.py"

CURL_URL = "http://www.hl.test/"
CHROMIUM_URL = "http://www.hl.test/chromium.html"  # HTML page with a data: icon (no favicon request)
CURL_FORMAT = "%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_connect}|%{time_total}|%{num_connects}"

# Every scenario defined in src/config/scenarios.yaml and scenarios_generated.yaml (analysis.scenario_config).
ALL_SCENARIOS = scenario_ids()


# --- curl -------------------------------------------------------------------------------

CURL_MAX_TIME_S = 10   # the whole transfer, connection attempts included


def curl_argv(url: str = CURL_URL, he_timeout_ms: int | None = None) -> list[str]:
    """-q must stay first (it stops curl reading ~/.curlrc). A variant adds its Happy Eyeballs timeout."""
    he = [] if he_timeout_ms is None else ["--happy-eyeballs-timeout-ms", str(he_timeout_ms)]
    return ["curl", "-q", "-sS", "--noproxy", "*", "--max-time", str(CURL_MAX_TIME_S), *he,
            "-o", "/dev/null", "-w", CURL_FORMAT, url]


def parse_curl_report(stdout: str) -> dict:
    """curl -w output (client-reported, not packet-level)."""
    parts = stdout.strip().split("|")
    keys = ["http_code", "remote_ip", "time_namelookup_s", "time_connect_s", "time_total_s", "num_connects"]
    report = dict(zip(keys, parts))
    code = report.get("http_code", "")
    report["http_code"] = int(code) if code.isdigit() and int(code) > 0 else None
    for k in ("time_namelookup_s", "time_connect_s", "time_total_s"):
        try:
            report[k] = float(report[k])
        except (KeyError, ValueError):
            report[k] = None
    try:
        report["num_connects"] = int(report["num_connects"])
    except (KeyError, ValueError):
        report["num_connects"] = None
    report["remote_ip"] = report.get("remote_ip") or None
    return report


class CurlClient:
    """curl, or a curl variant (a configuration of curl, not another client implementation)."""
    name = "curl"
    url = CURL_URL
    timeout_s = 30
    scenarios = ALL_SCENARIOS

    def __init__(self, client: ClientName = ClientName("curl")):
        if client.implementation != "curl":
            raise ValueError(f"not a curl label: {client.label}")
        self.client = client
        self.variant = client.variant
        self.label = client.label

    def argv(self, netlog: Path | None = None) -> list[str]:
        return curl_argv(self.url, self.client.he_timeout_ms)

    def netlog_path(self, logs: Path, run_id: str) -> Path | None:
        return None

    def version_argv(self) -> list[str]:
        return ["curl", "--version"]

    def parse_version(self, stdout: str) -> tuple[str, dict]:
        return stdout.splitlines()[0].strip(), {}

    def outcome(self, returncode: int, stdout: str, stderr: str) -> dict:
        report = parse_curl_report(stdout)
        http_status = report["http_code"]
        success = returncode == 0 and http_status is not None
        error = stderr.strip() or (None if success else f"curl exit code {returncode}")
        return {"success": success, "exit_code": returncode, "http_status": http_status,
                "error": error, "source": "client/runner log", "client_report": report}

    def config(self, launcher: list[str], info: dict) -> dict:
        he = self.client.he_timeout_ms
        return {"happy_eyeballs_timeout_ms": "default (not set)" if he is None else he,
                **({"variant": f"{self.variant} (--happy-eyeballs-timeout-ms {he})"} if self.variant else {}),
                "curlrc": "ignored (-q)",
                "run_time_limit": f"curl --max-time {CURL_MAX_TIME_S} s (set by the runner; a run that reaches it "
                                  "fails with exit 28)",
                "proxy": "disabled (--noproxy '*')", "url": self.url,
                "launcher": shlex.join(launcher)}


# --- Chromium via Playwright ------------------------------------------------------------------

class ChromiumClient:
    name = "chromium"
    variant = None
    label = "chromium"
    url = CHROMIUM_URL
    timeout_s = 60
    # Widened from C0/S1 to all seven scenarios by deliberate decision (2026-10-26), after the clean
    # C0/S1 pilot. Caveat kept: Chromium resolves with its own DNS client (NetLog), so it may not
    # follow the netns gai.conf like curl; S4/S5 get their own pilot before any full runs.
    scenarios = ALL_SCENARIOS

    def argv(self, netlog: Path | None = None) -> list[str]:
        argv = [str(VENV_PYTHON), str(CHROMIUM_RUNNER), "--url", self.url]
        if netlog is not None:
            argv += ["--netlog", str(netlog)]
        return argv

    def netlog_path(self, logs: Path, run_id: str) -> Path | None:
        return logs / f"{run_id}_netlog.json"

    def version_argv(self) -> list[str]:
        return [str(VENV_PYTHON), str(CHROMIUM_RUNNER), "--version"]

    def parse_version(self, stdout: str) -> tuple[str, dict]:
        report = client_chromium.parse_report(stdout)
        if not report["browser_version"]:
            raise ValueError(f"no browser version in {stdout!r}")
        return f"Chromium {report['browser_version']}", {
            "playwright_version": report["playwright_version"],
            "launch_args": report["launch_args"], "headless_mode": report["headless_mode"],
            "sandbox": report["sandbox"]}

    def outcome(self, returncode: int, stdout: str, stderr: str) -> dict:
        report = client_chromium.parse_report(stdout)
        http_status = report["http_status"]
        success = returncode == 0 and report["ok"] and http_status is not None
        error = report["error"]
        if not success and not error:
            tail = " | ".join(stderr.strip().splitlines()[-3:])
            error = tail or f"client exit code {returncode}"
        return {"success": success, "exit_code": returncode, "http_status": http_status,
                "error": error, "source": "client/runner log (Playwright)", "client_report": report}

    def config(self, launcher: list[str], info: dict) -> dict:
        return {
            "url": self.url,
            "browser_per_run": "fresh browser process and fresh temporary profile per run",
            "launch_args_extra": client_chromium.launch_args("<run netlog path>"),
            "launch_args_reported": info.get("launch_args"),
            "headless_mode": client_chromium.HEADLESS_MODE,
            "sandbox": "off (Playwright default chromiumSandbox=False)",
            "quic": "disabled (--disable-quic)",
            "secure_dns": "disabled (DnsOverHttps in the merged --disable-features)",
            "https_upgrades": "disabled (HttpsUpgrades in the merged --disable-features)",
            "feature_switch": ("one merged --disable-features: Playwright's default list plus ours; "
                               "Playwright's own switch removed with ignore_default_args; "
                               "checked per run against the NetLog command line (client_report.launch_check)"),
            "happy_eyeballs": "Chromium default (not overridden)",
            "run_time_limit": (f"Playwright page.goto timeout {client_chromium.NAV_TIMEOUT_MS} ms (set by the "
                               "runner); Chromium's own connection timeouts are not overridden"),
            "resolver": "Chromium default, not overridden (see the run's NetLog)",
            "navigation": f"page.goto wait_until=load timeout={client_chromium.NAV_TIMEOUT_MS} ms",
            "playwright_version": info.get("playwright_version"),
            "launcher": shlex.join(launcher),
        }


CLIENTS = {"curl": CurlClient(), "chromium": ChromiumClient()}   # the two implementations


def get_client(label: str):
    """The client for a label: 'curl', 'curl@he<N>' or 'chromium' (analysis.names.parse_client)."""
    c = parse_client(label)
    if c.variant is None:
        return CLIENTS[c.implementation]
    return CurlClient(c)

