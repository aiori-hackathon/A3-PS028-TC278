"""Tests for the orchestrator's pure parts (no sudo, no lab, no network)."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from analysis.parse_pcap import parse
from analysis.validate_record import validate
from runner import orchestrate as o

FIX = Path(__file__).resolve().parent / "fixtures"
LAB = {"NS_CLIENT": "hl-client", "NS_SERVER": "hl-server", "DNS_ADDR": "198.51.100.53"}

VERIFY_S1_OUTPUT = """\
PASS hl-client sees lab gai.conf (bind mount works)
PASS RTT v4 median_ms=21.00 min_ms=20.10 max_ms=22.60 loss_pct=0 sent=10 received=10 errors=0 target_ms=20 tol_ms=2.0 PASS
PASS RTT v6 median_ms=NA min_ms=NA max_ms=NA loss_pct=100 sent=10 received=0 errors=0 target=blackhole PASS
PASS RTT ctl median_ms=0.07 min_ms=0.03 max_ms=0.07 loss_pct=0 sent=10 received=10 errors=0 target_ms=<2 PASS
VERIFY up: PASS (50 checks)
"""


def test_scope_per_client():
    assert o.SUPPORTED["curl"] == ("C0", "S1", "S2", "S3", "S4", "S5", "S6")
    assert o.SUPPORTED["chromium"] == o.SUPPORTED["curl"]  # widened deliberately, 2026-10-26
    for client in ("curl", "chromium"):
        with pytest.raises(o.OrchestratorError, match=f"out of scope for {client}"):
            o.load_scenarios(["X1"], client=client)
    assert set(o.load_scenarios(["S4", "S5"], client="chromium")) == {"S4", "S5", "_baseline"}


def test_cli_accepts_chromium_s4_s5(capsys):
    assert o.main(["--client", "chromium", "--scenario", "S4", "S5", "--reps", "3", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "_S4_chromium_r01" in out and "verify.sh up blackhole 20" in out and "netem.sh v4 310 0" in out


def test_capture_filter_includes_quic_and_https_ports():
    assert "tcp port 443" in o.CAPTURE_FILTER and "udp port 443" in o.CAPTURE_FILTER


def test_pilot_scenarios_targets():
    sc = o.load_scenarios(["S2", "S3", "S4", "S5", "S6"])
    assert [o.verify_targets(sc[s]) for s in ("S2", "S3", "S4", "S5", "S6")] == [
        (20, 620), (20, 170), ("blackhole", 20), (620, 20), (20, 20)]


def test_dry_run_shows_s6_dns_delay_and_s4_blackhole(capsys):
    assert o.main(["--scenario", "S4", "S6", "--dry-run"]) == 0
    out = capsys.readouterr().out
    s4, s6 = out[out.index("# S4"):out.index("# S6")], out[out.index("# S6"):]
    assert "netem.sh v4 10 100" in s4 and "verify.sh up blackhole 20" in s4
    assert "--delay AAAA=300" in s6 and "--delay" not in s4


def test_summary_line_wall_time():
    r = _s1_record()
    assert o.summary_line(r).endswith("cross_checks=agree")
    assert o.summary_line(r, 13.456).endswith("cross_checks=agree  wall_s=13.46")


def test_load_scenarios_and_targets():
    sc = o.load_scenarios(["C0", "S1"])
    assert o.verify_targets(sc["C0"]) == (20, 20)
    assert o.verify_targets(sc["S1"]) == (20, "blackhole")
    assert sc["_baseline"] == {"delay_ms_each_way": 10, "rtt_ms": 20}


def test_lab_env_matches_scripts():
    lab = o.load_lab_env()
    assert lab["NS_CLIENT"] == "hl-client" and lab["DNS_ADDR"] == "198.51.100.53"


def test_command_builders():
    assert o.cmd_netem("v6", 10, 100)[-3:] == ["v6", "10", "100"]
    assert o.cmd_netem("v6", 10, 100)[0].endswith("src/lab/netem.sh")
    assert o.cmd_verify(20, "blackhole")[-3:] == ["up", "20", "blackhole"]
    tcpdump = o.cmd_tcpdump("hl-client", Path("/x/captures/r.pcap"), "sr")
    assert tcpdump[:4] == ["ip", "netns", "exec", "hl-client"]
    assert ["-i", "any"] == tcpdump[5:7] and "-U" in tcpdump
    assert "--immediate-mode" in tcpdump  # without it a short capture can write nothing
    assert tcpdump[tcpdump.index("-s") + 1] == "65535" and tcpdump[tcpdump.index("-B") + 1] == "65536"
    assert tcpdump[tcpdump.index("-Z") + 1] == "sr" and tcpdump[-1] == o.CAPTURE_FILTER


def test_clients_and_services_drop_to_the_user():
    for argv in (o.in_ns_as_user("hl-client", "sr", o.curl_argv()),
                 o.cmd_dns(LAB, "sr", {}), o.cmd_nginx(LAB, "sr", Path("/p"))):
        assert argv[3] in ("hl-client", "hl-server")
        assert argv[4:8] == ["runuser", "-u", "sr", "--"]


def test_curl_argv_ignores_curlrc_and_reports_remote_ip():
    argv = o.curl_argv()
    assert argv[:2] == ["curl", "-q"] and argv[-1] == "http://www.hl.test/"
    assert "%{remote_ip}" in argv[argv.index("-w") + 1]


def test_dns_delay_flags_only_when_nonzero():
    assert "--delay" not in o.cmd_dns(LAB, "sr", {"A": 0, "AAAA": 0})
    assert o.cmd_dns(LAB, "sr", {"A": 0, "AAAA": 300})[-2:] == ["--delay", "AAAA=300"]


def test_run_id_format():
    t = datetime(2026, 10, 26, 5, 6, 7, tzinfo=timezone.utc)
    assert o.make_run_id(t, "S1", 3) == "20261026T050607Z_S1_curl_r03"
    assert o.make_run_id(t, "C0", 1, "chromium") == "20261026T050607Z_C0_chromium_r01"


def test_parse_verify_rtt():
    rtt = o.parse_verify_rtt(VERIFY_S1_OUTPUT)
    assert set(rtt) == {"v4", "v6", "ctl"}
    assert rtt["v4"]["median_ms"] == "21.00" and rtt["v4"]["verdict"] == "PASS"
    assert rtt["v6"]["loss_pct"] == "100" and rtt["v6"]["errors"] == "0"


def test_measured_rtt_field():
    rtt = o.parse_verify_rtt(VERIFY_S1_OUTPUT)
    assert o.measured_rtt_field(rtt["v4"], 20)["value"] == 21.0
    v6 = o.measured_rtt_field(rtt["v6"], "blackhole")
    assert v6["status"] == "not_observed" and "loss 100%" in v6["note"]
    assert o.measured_rtt_field(None, 20)["status"] == "not_yet_computed"


@pytest.mark.parametrize("stdout,code,ip,connect", [
    ("200|192.0.2.2|0.001807|0.222482|0.242880|2", 200, "192.0.2.2", 0.222482),
    ("000||0.001|0.000000|10.0|1", None, None, 0.0),
    ("", None, None, None),
])
def test_parse_curl_report(stdout, code, ip, connect):
    r = o.parse_curl_report(stdout)
    assert (r["http_code"], r["remote_ip"], r["time_connect_s"]) == (code, ip, connect)


def test_parse_ifindex_map():
    out = ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...\n"
           "2: hl-v4c@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...\n")
    assert o.parse_ifindex_map(out) == {"1": "lo", "2": "hl-v4c"}


GOOD_SUMMARY = "15 packets captured\n15 packets received by filter\n0 packets dropped by kernel\n"
# Exact summary from the first orchestrated S1 run (2026-10-26), before --immediate-mode:
EMPTY_SUMMARY = "0 packets captured\n15 packets received by filter\n0 packets dropped by kernel\n"


def test_parse_tcpdump_stats():
    assert o.parse_tcpdump_stats(GOOD_SUMMARY) == {"captured": 15, "received": 15, "dropped": 0}
    assert o.parse_tcpdump_stats("") == {}


@pytest.mark.parametrize("summary,problem", [
    (GOOD_SUMMARY, None),
    (EMPTY_SUMMARY, "only 0 of 15"),
    ("15 packets captured\n15 packets received by filter\n3 packets dropped by kernel\n", "3 packets dropped"),
    ("", "no complete exit summary"),
])
def test_capture_problem(summary, problem):
    got = o.capture_problem(o.parse_tcpdump_stats(summary))
    assert got is None if problem is None else problem in got


def _s1_record(stdout="200|192.0.2.2|0.001807|0.222482|0.242880|2", summary=GOOD_SUMMARY, returncode=0):
    sc = o.load_scenarios(["S1"])
    tl = parse(FIX / "s1_manual_curl.pcap")
    start = datetime(2026, 10, 26, 4, 21, 56, tzinfo=timezone.utc)
    return o.build_record(
        run_id=o.make_run_id(start, "S1", 1), scenario_id="S1", sc=sc["S1"], repetition=1,
        run_start=start, client_version="curl 8.5.0", argv=o.curl_argv(), user="sr",
        environment={"kernel": "test"}, client_start_ns=1792989112200000000,
        client_end_ns=1792989112480000000, capture_start_ns=1792989112100000000,
        capture_end_ns=1792989113000000000, returncode=returncode, stdout=stdout, stderr="",
        pre_rtt=o.parse_verify_rtt(VERIFY_S1_OUTPUT), pre_ok=True, post_ok=True,
        pcap_rel="captures/x.pcap", pcap_sha256="a" * 64, log_rel="data/generated/logs/x.log",
        timeline=tl, capture_stats=o.parse_tcpdump_stats(summary))


def test_build_record_from_s1_capture_is_valid_and_correct():
    r = _s1_record()
    assert validate(r) == []
    assert r["metrics"]["tcp_setup_time_ms"]["value"] == 220.593
    assert r["metrics"]["inter_family_attempt_delay_ms"]["value"] == 200.443
    assert r["packet_observations"]["winning_family"]["value"] == "v4"
    assert r["packet_observations"]["failed_or_abandoned_attempts"]["value"] == 1
    assert r["cross_checks"] == {"status": "agree", "conflicts": []}
    assert r["scenario"]["measured_rtt_ms"]["v4"]["value"] == 21.0
    assert r["outcome"]["client_report"]["remote_ip"] == "192.0.2.2"


def test_build_record_flags_log_pcap_disagreement():
    r = _s1_record(stdout="200|2001:db8:28:6::2|0.001|0.2|0.24|1")
    assert validate(r) == []
    assert r["cross_checks"]["status"] == "conflict"
    assert r["cross_checks"]["conflicts"][0]["field"] == "remote_ip"
    # neither side overwritten
    assert r["outcome"]["client_report"]["remote_ip"] == "2001:db8:28:6::2"
    assert r["packet_observations"]["winning_family"]["value"] == "v4"


def test_build_record_flags_kernel_drops():
    r = _s1_record(summary="15 packets captured\n15 packets received by filter\n4 packets dropped by kernel\n")
    assert validate(r) == []
    assert [c["field"] for c in r["cross_checks"]["conflicts"]] == ["capture"]


def test_build_record_flags_empty_capture_like_first_live_run(tmp_path):
    """Header-only pcap + "0 captured / 15 received": both the success and capture conflicts appear."""
    from tests import pcapgen as g
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(g.pcap([]))
    sc = o.load_scenarios(["S1"])
    start = datetime(2026, 10, 26, 6, 29, 19, tzinfo=timezone.utc)
    r = o.build_record(
        run_id=o.make_run_id(start, "S1", 1), scenario_id="S1", sc=sc["S1"], repetition=1,
        run_start=start, client_version="curl 8.5.0", argv=o.curl_argv(), user="sr", environment={},
        client_start_ns=1, client_end_ns=2, capture_start_ns=1, capture_end_ns=3, returncode=0,
        stdout="200|192.0.2.2|0.001587|0.222508|0.243730|1", stderr="",
        pre_rtt=o.parse_verify_rtt(VERIFY_S1_OUTPUT), pre_ok=True, post_ok=True,
        pcap_rel="captures/x.pcap", pcap_sha256="b" * 64, log_rel="data/generated/logs/x.log",
        timeline=parse(empty), capture_stats=o.parse_tcpdump_stats(EMPTY_SUMMARY))
    assert validate(r) == []
    assert {c["field"] for c in r["cross_checks"]["conflicts"]} == {"success", "capture"}
    assert r["metrics"]["tcp_setup_time_ms"]["status"] == "not_observed"


def test_dry_run_prints_full_loop_without_executing(capsys):
    assert o.main(["--scenario", "C0", "S1", "--reps", "2", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    for needle in ("netem.sh v6 10 100", "verify.sh up 20 blackhole", "tcpdump -i any",
                   "runuser -u", "netem.sh v6 10 0", "verify.sh up 20 20"):
        assert needle in out, needle
    s1 = out[out.index("# S1"):]
    order = [s1.index(s) for s in ("netem.sh v6 10 100", "verify.sh up 20 blackhole", "tcpdump",
                                   "curl -q", "kill -INT", "netem.sh v6 10 0", "verify.sh up 20 20")]
    assert order == sorted(order)


def test_refuses_without_root(monkeypatch):
    monkeypatch.setattr(o.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("LD_LIBRARY_PATH", raising=False)
    with pytest.raises(o.OrchestratorError, match="sudo"):
        o.check_environment(dry_run=False)


def test_refuses_sudo_e(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/opt/ros/jazzy/lib/python3.12/site-packages")
    with pytest.raises(o.OrchestratorError, match="sudo -E"):
        o.check_environment(dry_run=False)


# --- Chromium ---------------------------------------------------------------------------------

def test_chromium_dry_run(capsys):
    assert o.main(["--client", "chromium", "--scenario", "C0", "S1", "--reps", "3", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Client chromium" in out and "client_chromium.py --version" in out
    s1 = out[out.index("# S1"):]
    client = next(line for line in s1.splitlines() if line.strip().startswith("client"))
    assert "ip netns exec hl-client runuser -u" in client
    assert "client_chromium.py --url http://www.hl.test/chromium.html --netlog" in client
    assert "_S1_chromium_r01_netlog.json" in client
    assert "udp port 443" in s1 and "verify.sh up 20 blackhole" in s1


def _chromium_stdout(remote_ip="192.0.2.2", status=200, ok=True, error=None):
    import json
    return json.dumps({"ok": ok, "error": error, "http_status": status, "remote_ip": remote_ip,
                       "remote_port": 80, "browser_version": "156.0.8078.4",
                       "playwright_version": "1.64.1", "launch_args": ["--disable-quic"],
                       "headless_mode": "new headless (channel=chromium)", "sandbox": False,
                       "netlog_path": "/x/n.json", "url": "http://www.hl.test/chromium.html",
                       "timing_ms": {"connectStart": 1.0}})


def _chromium_s1_record(stdout, returncode=0):
    sc = o.load_scenarios(["S1"], client="chromium")
    tl = parse(FIX / "s1_manual_curl.pcap")
    start = datetime(2026, 10, 26, 4, 21, 56, tzinfo=timezone.utc)
    return o.build_record(
        run_id=o.make_run_id(start, "S1", 1, "chromium"), scenario_id="S1", sc=sc["S1"], repetition=1,
        run_start=start, client_version="Chromium 156.0.8078.4",
        argv=o.CLIENTS["chromium"].argv(Path("/x/n.json")), user="sr", environment={},
        client_start_ns=1792989112200000000, client_end_ns=1792989112480000000,
        capture_start_ns=1792989112100000000, capture_end_ns=1792989113000000000,
        returncode=returncode, stdout=stdout, stderr="", pre_rtt=o.parse_verify_rtt(VERIFY_S1_OUTPUT),
        pre_ok=True, post_ok=True, pcap_rel="captures/x.pcap", pcap_sha256="c" * 64,
        log_rel="data/generated/logs/x.log", timeline=tl, capture_stats=o.parse_tcpdump_stats(GOOD_SUMMARY),
        client="chromium", client_info={"playwright_version": "1.64.1"})


def test_chromium_record_from_s1_capture_agrees():
    """The S1 capture is curl's, but the packet side is client-independent; this checks the log side."""
    r = _chromium_s1_record(_chromium_stdout())
    assert validate(r) == []
    assert r["client"]["name"] == "chromium" and r["client"]["version"] == "Chromium 156.0.8078.4"
    cfg = r["client"]["config"]
    assert "--disable-quic" in cfg["launch_args_extra"] and "fresh browser" in cfg["browser_per_run"]
    assert "HttpsUpgrades" in cfg["https_upgrades"] and "DnsOverHttps" in cfg["secure_dns"]
    assert r["outcome"]["success"] and r["outcome"]["source"].startswith("client/runner log")
    assert r["cross_checks"] == {"status": "agree", "conflicts": []}


def test_chromium_bracketed_ipv6_mismatch_is_flagged():
    r = _chromium_s1_record(_chromium_stdout(remote_ip="[2001:db8:28:6::2]"))
    assert r["outcome"]["client_report"]["remote_ip"] == "2001:db8:28:6::2"
    assert [c["field"] for c in r["cross_checks"]["conflicts"]] == ["remote_ip"]


def test_chromium_success_without_server_addr_is_a_conflict():
    r = _chromium_s1_record(_chromium_stdout(remote_ip=None))
    assert validate(r) == []
    c = r["cross_checks"]["conflicts"]
    assert [x["field"] for x in c] == ["remote_ip"] and "unchecked" in c[0]["note"]


def test_chromium_navigation_error_is_failure():
    r = _chromium_s1_record(_chromium_stdout(remote_ip=None, status=None, ok=False,
                                             error="net::ERR_CONNECTION_TIMED_OUT"), returncode=1)
    assert r["outcome"]["success"] is False and r["outcome"]["error"] == "net::ERR_CONNECTION_TIMED_OUT"
    # the capture does show an HTTP response, so the disagreement is flagged, not resolved
    assert [x["field"] for x in r["cross_checks"]["conflicts"]] == ["success"]
