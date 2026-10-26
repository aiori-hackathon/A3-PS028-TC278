"""Client definitions for the orchestrator: how to start each client and read what it reports.

Everything a client reports about itself (curl -w, Playwright/DevTools) is client-reported,
not packet-level evidence. The capture is checked against it in metrics.cross_check().
"""

from __future__ import annotations

import shlex
from pathlib import Path

from runner import client_chromium

REPO = Path(__file__).resolve().parents[2]
VENV_PYTHON = REPO / ".venv" / "bin" / "python"
CHROMIUM_RUNNER = REPO / "src" / "runner" / "client_chromium.py"

CURL_URL = "http://www.hl.test/"
CHROMIUM_URL = "http://www.hl.test/chromium.html"  # HTML page with a data: icon (no favicon request)
CURL_FORMAT = "%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_connect}|%{time_total}|%{num_connects}"

ALL_SCENARIOS = ("C0", "S1", "S2", "S3", "S4", "S5", "S6")


# --- curl -------------------------------------------------------------------------------

def curl_argv(url: str = CURL_URL) -> list[str]:
    return ["curl", "-q", "-sS", "--noproxy", "*", "--max-time", "10",
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
    name = "curl"
    url = CURL_URL
    timeout_s = 30
    scenarios = ALL_SCENARIOS

    def argv(self, netlog: Path | None = None) -> list[str]:
        return curl_argv(self.url)

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
        return {"happy_eyeballs_timeout_ms": "default (not set)", "curlrc": "ignored (-q)",
                "proxy": "disabled (--noproxy '*')", "url": self.url,
                "launcher": shlex.join(launcher)}


# --- Chromium via Playwright ------------------------------------------------------------------

class ChromiumClient:
    name = "chromium"
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
            "resolver": "Chromium default, not overridden (see the run's NetLog)",
            "navigation": f"page.goto wait_until=load timeout={client_chromium.NAV_TIMEOUT_MS} ms",
            "playwright_version": info.get("playwright_version"),
            "launcher": shlex.join(launcher),
        }


CLIENTS = {"curl": CurlClient(), "chromium": ChromiumClient()}

