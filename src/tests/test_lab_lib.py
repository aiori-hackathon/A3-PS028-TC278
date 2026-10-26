"""Tests for the lab scripts that need no sudo and no network.

- every script parses (bash -n) and uses `set -euo pipefail`
- lab.env is plain KEY=value with sane names
- RTT parsing (hl_rtt_stats) and target checks (hl_rtt_check) on canned iputils ping output
"""

import re
import subprocess
from pathlib import Path

import pytest

from runner.child_env import child_env

LAB = Path(__file__).resolve().parents[2] / "src" / "lab"
SCRIPTS = ["setup.sh", "teardown.sh", "verify.sh"]


def bash(snippet: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", f'set -euo pipefail; source "{LAB}/lib.sh"; {snippet}'],
                          input=stdin, capture_output=True, text=True, env=child_env())


def stats(ping_output: str) -> subprocess.CompletedProcess:
    return bash("hl_rtt_stats", ping_output)


def check(target: str, stats_line: str) -> subprocess.CompletedProcess:
    # Arguments go in as positional parameters so no quoting is needed.
    return subprocess.run(
        ["bash", "-c", f'source "{LAB}/lib.sh"; hl_rtt_check "$1" "$2"', "_", target, stats_line],
        capture_output=True, text=True, env=child_env())


# --- scripts and config --------------------------------------------------------

@pytest.mark.parametrize("name", SCRIPTS + ["lib.sh"])
def test_bash_syntax(name):
    out = subprocess.run(["bash", "-n", str(LAB / name)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


@pytest.mark.parametrize("name", SCRIPTS)
def test_strict_mode_and_root_check(name):
    text = (LAB / name).read_text()
    assert "set -euo pipefail" in text
    assert "need_root" in text


def read_env() -> dict[str, str]:
    env = {}
    for line in (LAB / "lab.env").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        assert re.fullmatch(r"[A-Z0-9_]+=[^\s'\"$`]+", line), f"not plain KEY=value: {line!r}"
        key, value = line.split("=", 1)
        env[key] = value
    return env


def test_lab_env_names():
    env = read_env()
    for key in ("NS_CLIENT", "NS_SERVER"):
        assert env[key].startswith("hl-")
    for key, value in env.items():
        if key.endswith(("_IF_C", "_IF_S")):
            assert value.startswith("hl-") and len(value) <= 15, key  # IFNAMSIZ - 1
        if "_MAC_" in key:
            assert re.fullmatch(r"02(:[0-9a-f]{2}){5}", value), key  # locally administered
    assert env["NETNS_ETC"] == "/etc/netns/hl-client"
    assert int(env["BASELINE_RTT_MS"]) == 2 * int(env["BASELINE_DELAY_MS"])


def test_lab_files_contents():
    out = bash("hl_resolv_conf; hl_gai_conf")
    assert out.returncode == 0, out.stderr
    lines = [ln for ln in out.stdout.splitlines() if not ln.startswith("#")]
    assert lines == ["nameserver 198.51.100.53"]  # gai.conf has no rules at all


# --- hl_rtt_stats ----------------------------------------------------------------

PING_V4_OK = """\
PING 192.0.2.2 (192.0.2.2) 56(84) bytes of data.
64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=20.6 ms
64 bytes from 192.0.2.2: icmp_seq=2 ttl=64 time=20.2 ms
64 bytes from 192.0.2.2: icmp_seq=3 ttl=64 time=20.3 ms
64 bytes from 192.0.2.2: icmp_seq=4 ttl=64 time=20.1 ms

--- 192.0.2.2 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 603ms
rtt min/avg/max/mdev = 20.100/20.300/20.600/0.187 ms
"""

PING_V6_ODD = """\
PING 2001:db8:28:6::2 (2001:db8:28:6::2) 56 data bytes
64 bytes from 2001:db8:28:6::2: icmp_seq=1 ttl=64 time=21.0 ms
64 bytes from 2001:db8:28:6::2: icmp_seq=2 ttl=64 time=20.4 ms
64 bytes from 2001:db8:28:6::2: icmp_seq=3 ttl=64 time=20.5 ms

--- 2001:db8:28:6::2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 402ms
rtt min/avg/max/mdev = 20.400/20.633/21.000/0.262 ms
"""

PING_PARTIAL = """\
PING 192.0.2.2 (192.0.2.2) 56(84) bytes of data.
64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=20.2 ms
64 bytes from 192.0.2.2: icmp_seq=3 ttl=64 time=20.4 ms

--- 192.0.2.2 ping statistics ---
4 packets transmitted, 2 received, 50% packet loss, time 610ms
"""

PING_BLACKHOLE = """\
PING 2001:db8:28:6::2 (2001:db8:28:6::2) 56 data bytes

--- 2001:db8:28:6::2 ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 1840ms
"""

PING_ERRORS = """\
PING 192.0.2.2 (192.0.2.2) 56(84) bytes of data.
From 192.0.2.1 icmp_seq=1 Destination Host Unreachable

--- 192.0.2.2 ping statistics ---
5 packets transmitted, 0 received, +5 errors, 100% packet loss, time 4090ms
"""


def test_stats_even_count_median_is_mean_of_middle_pair():
    out = stats(PING_V4_OK)
    assert out.returncode == 0
    assert out.stdout.strip() == "median_ms=20.25 min_ms=20.10 max_ms=20.60 loss_pct=0 sent=4 received=4"


def test_stats_ipv6_odd_count():
    assert stats(PING_V6_ODD).stdout.strip() == (
        "median_ms=20.50 min_ms=20.40 max_ms=21.00 loss_pct=0 sent=3 received=3")


def test_stats_partial_loss():
    assert stats(PING_PARTIAL).stdout.strip() == (
        "median_ms=20.30 min_ms=20.20 max_ms=20.40 loss_pct=50 sent=4 received=2")


@pytest.mark.parametrize("text,sent", [(PING_BLACKHOLE, 10), (PING_ERRORS, 5)])
def test_stats_total_loss(text, sent):
    assert stats(text).stdout.strip() == (
        f"median_ms=NA min_ms=NA max_ms=NA loss_pct=100 sent={sent} received=0")


@pytest.mark.parametrize("text", ["", "ping: connect: Network is unreachable\n",
                                  "Cannot open network namespace \"hl-client\"\n"])
def test_stats_without_summary_fails(text):
    out = stats(text)
    assert out.returncode == 1
    assert "error=no_ping_summary" in out.stdout


# --- hl_rtt_check ----------------------------------------------------------------

def line(median, loss=0):
    return f"median_ms={median} min_ms=1 max_ms=1 loss_pct={loss} sent=10 received=10"


@pytest.mark.parametrize("median,ok", [
    ("20.00", True), ("21.90", True), ("22.00", True), ("18.00", True),
    ("22.10", False), ("17.90", False),
])
def test_check_baseline_tolerance_is_2ms(median, ok):
    out = check("20", line(median))
    assert (out.returncode == 0) is ok, out.stdout
    assert "target_ms=20 tol_ms=2.0" in out.stdout
    assert ("PASS" if ok else "FAIL") in out.stdout


@pytest.mark.parametrize("median,ok", [("620", True), ("681.9", True), ("558.1", True),
                                       ("683", False), ("557", False)])
def test_check_large_target_uses_ten_percent(median, ok):
    out = check("620", line(median))
    assert (out.returncode == 0) is ok, out.stdout
    assert "tol_ms=62.0" in out.stdout


def test_check_any_loss_fails_numeric_target():
    out = check("20", line("20.1", loss=10))
    assert out.returncode == 1 and "FAIL (loss 10%)" in out.stdout


def test_check_no_replies_fails_numeric_target():
    out = check("20", "median_ms=NA min_ms=NA max_ms=NA loss_pct=100 sent=10 received=0")
    assert out.returncode == 1


def test_check_blackhole():
    assert check("blackhole", "median_ms=NA loss_pct=100").returncode == 0
    out = check("blackhole", line("20.1"))
    assert out.returncode == 1 and "expected 100% loss" in out.stdout


@pytest.mark.parametrize("median,loss,ok", [("0.08", 0, True), ("1.99", 0, True),
                                            ("2.5", 0, False), ("0.08", 10, False)])
def test_check_max_target_for_ctl_link(median, loss, ok):
    assert (check("max:2", line(median, loss)).returncode == 0) is ok


@pytest.mark.parametrize("target", ["", "fast", "-5", "20ms"])
def test_check_bad_target(target):
    out = check(target, line("20"))
    assert out.returncode == 2 and "bad target" in out.stdout
