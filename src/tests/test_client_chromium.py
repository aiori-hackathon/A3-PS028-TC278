"""Tests for the Chromium runner's pure parts (no browser started)."""

import json

import pytest

from runner import client_chromium as cc
from runner.clients import CLIENTS


def test_launch_args_turn_off_quic_doh_and_https_upgrades_in_one_merged_switch():
    args = cc.launch_args("/tmp/n.json")
    assert "--disable-quic" in args
    feats = [a for a in args if a.startswith("--disable-features=")]
    assert len(feats) == 1
    listed = feats[0].split("=", 1)[1].split(",")
    assert {"DnsOverHttps", "HttpsUpgrades"} <= set(listed)
    assert set(cc.PLAYWRIGHT_DISABLED_FEATURES) <= set(listed)  # Playwright's own list is kept
    assert "--log-net-log=/tmp/n.json" in args and "--net-log-capture-mode=Default" in args
    assert not any("happy" in a.lower() or "host-resolver" in a for a in args)  # no HE/resolver overrides


def test_pinned_feature_list_matches_installed_playwright():
    """If Playwright is upgraded, its default list may change: this fails until the copy is updated."""
    import re
    from importlib import metadata
    from pathlib import Path

    import playwright
    assert metadata.version("playwright") == cc.PINNED_PLAYWRIGHT
    bundle = Path(playwright.__file__).parent / "driver/package/lib/coreBundle.js"
    block = re.search(r"disabledFeatures = \[(.*?)\]\.filter", bundle.read_text(encoding="utf-8"), re.S).group(1)
    assert tuple(re.findall(r'^\s*"([^"]+)"', block, re.M)) == cc.PLAYWRIGHT_DISABLED_FEATURES


# Command line from the first Chromium pilot's NetLog (2026-10-26, run 20261026T123829Z_C0), trimmed:
# two --disable-features switches, so Playwright's list was replaced by ours.
PILOT1_CMDLINE = ("/home/sr/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome --disable-background-networking "
                  "--disable-features=AvoidUnnecessaryBeforeUnloadCheckSync,HttpsUpgrades,NetworkTimeServiceQuerying "
                  "--disable-quic --disable-features=DnsOverHttps,HttpsUpgrades --headless")


def test_check_command_line():
    assert cc.check_command_line(PILOT1_CMDLINE) == ["2 --disable-features switches (Chromium uses only one)"]
    good = f"chrome --disable-quic {cc.launch_args(None)[1]} --headless"
    assert cc.check_command_line(good) == []
    assert cc.check_command_line("chrome --disable-features=DnsOverHttps --disable-quic")[0].startswith(
        "--disable-features is not the merged list")
    assert cc.check_command_line(f"chrome {cc.launch_args(None)[1]}") == ["--disable-quic missing"]


def test_netlog_command_line(tmp_path):
    full = tmp_path / "full.json"
    full.write_text(json.dumps({"constants": {"clientInfo": {"command_line": "chrome --x"}}, "events": []}))
    assert cc.netlog_command_line(str(full)) == "chrome --x"
    cut = tmp_path / "cut.json"  # NetLog written by a browser that did not close cleanly
    cut.write_text('{"constants": {"clientInfo": {"command_line": "chrome --y"}}, "events": [{"a": 1},\n')
    assert cc.netlog_command_line(str(cut)) == "chrome --y"
    assert cc.netlog_command_line(str(tmp_path / "missing.json")) is None


def test_fresh_full_chromium_without_sandbox_is_recorded():
    assert cc.CHANNEL == "chromium" and cc.SANDBOX is False


@pytest.mark.parametrize("raw,canon", [
    ("[2001:db8:28:6::2]", "2001:db8:28:6::2"),
    ("2001:DB8:28:6:0:0:0:2", "2001:db8:28:6::2"),
    ("192.0.2.2", "192.0.2.2"),
    ("", None), (None, None),
])
def test_normalise_ip(raw, canon):
    assert cc.normalise_ip(raw) == canon


def test_ip_family():
    assert cc.ip_family("[2001:db8:28:6::2]") == "v6" and cc.ip_family("192.0.2.2") == "v4"
    assert cc.ip_family(None) is None


def test_parse_report_ok():
    r = cc.parse_report("some warning\n" + json.dumps(
        {"ok": True, "http_status": 200, "remote_ip": "[2001:db8:28:6::2]", "remote_port": 80}))
    assert r["ok"] and r["http_status"] == 200 and r["remote_ip"] == "2001:db8:28:6::2"
    assert set(r) == set(cc.REPORT_KEYS) and r["browser_version"] is None


@pytest.mark.parametrize("stdout,err", [("", "no report"), ("not json", "unreadable report")])
def test_parse_report_missing_or_broken(stdout, err):
    r = cc.parse_report(stdout)
    assert r["ok"] is False and err in r["error"] and r["http_status"] is None


def test_parse_report_rejects_zero_status():
    assert cc.parse_report(json.dumps({"ok": False, "http_status": 0}))["http_status"] is None


def test_main_requires_url_or_version():
    with pytest.raises(SystemExit):
        cc.main([])


def test_chromium_client_spec(tmp_path):
    spec = CLIENTS["chromium"]
    assert spec.url == "http://www.hl.test/chromium.html" and spec.scenarios == ("C0", "S1")
    assert spec.netlog_path(tmp_path, "R") == tmp_path / "R_netlog.json"
    argv = spec.argv(tmp_path / "R_netlog.json")
    assert argv[0].endswith(".venv/bin/python") and argv[1].endswith("src/runner/client_chromium.py")
    assert argv[2:] == ["--url", spec.url, "--netlog", str(tmp_path / "R_netlog.json")]
    version, info = spec.parse_version(json.dumps({"ok": True, "browser_version": "156.0.8078.4",
                                                   "playwright_version": "1.64.1"}))
    assert version == "Chromium 156.0.8078.4" and info["playwright_version"] == "1.64.1"
    with pytest.raises(ValueError):
        spec.parse_version("")


def test_curl_spec_unchanged():
    spec = CLIENTS["curl"]
    assert spec.netlog_path(None, "R") is None and spec.argv()[-1] == "http://www.hl.test/"


def _netlog(events):
    return {"constants": {"logEventTypes": {"SOCKET_POOL_CONNECT_JOB_CREATED": 1,
                                            "TCP_CONNECT_JOB_CONNECTOR_CONNECT_START": 2, "OTHER": 3},
                          "timeTickOffset": "1793019210000"},
            "events": events}


def test_connect_jobs_reproduce_s1_pattern():
    """Shape taken from the S1 NetLogs of 2026-10-26: first v6, backup v6 at +250 ms, v4 fallback at +301 ms."""
    grp = "http://www.hl.test <http://hl.test same_site>"
    log = _netlog([
        {"type": 1, "time": "800", "source": {"id": 116}, "params": {"backup_job": False, "group_id": grp}},
        {"type": 1, "time": "790", "source": {"id": 20}, "params": {"backup_job": False,
                                                                    "group_id": "pm/https://www.google.com <null>"}},
        {"type": 2, "time": "790", "source": {"id": 20}, "params": {"connector": "first", "address": "x"}},
        {"type": 2, "time": "800", "source": {"id": 116}, "params": {"connector": "first", "address": "[2001:db8:28:6::2]:80"}},
        {"type": 3, "time": "900", "source": {"id": 116}, "params": {}},
        {"type": 1, "time": "1050", "source": {"id": 149}, "params": {"backup_job": True, "group_id": grp}},
        {"type": 2, "time": "1050", "source": {"id": 149}, "params": {"connector": "first", "address": "[2001:db8:28:6::2]:80"}},
        {"type": 2, "time": "1101", "source": {"id": 116}, "params": {"connector": "second", "address": "192.0.2.2:80"}},
    ])
    jobs = cc.connect_jobs(log, "www.hl.test")
    assert [(j["t_ms"], j["job"], j["backup_job"], j["connector"], j["address"]) for j in jobs] == [
        (0, 116, False, "first", "[2001:db8:28:6::2]:80"),
        (250, 149, True, "first", "[2001:db8:28:6::2]:80"),
        (301, 116, False, "second", "192.0.2.2:80"),
    ]
    assert jobs[0]["epoch_ms"] == 1793019210800


def test_connect_jobs_tolerates_bad_input():
    assert cc.connect_jobs({}, "www.hl.test") == [] and cc.connect_jobs(None, "x") == []


def test_load_netlog(tmp_path):
    f = tmp_path / "n.json"
    f.write_text('{"constants": {}, "events": [{"a": 1},\n')
    assert cc.load_netlog(str(f)) == {"constants": {}, "events": [{"a": 1}]}
    assert cc.load_netlog(str(tmp_path / "none.json")) is None
