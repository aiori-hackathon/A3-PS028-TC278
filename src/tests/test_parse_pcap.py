"""Tests for analysis/parse_pcap.py (packet-level facts) and analysis/metrics.py.

Fixtures are byte-for-byte copies of real captures (hashes pinned below):
- s1_manual_curl.pcap            = captures/manual_S1_curl_20261026T042156Z.pcap
                                   (manual S1 check, 2026-10-26, curl in the lab, -i any)
- loopback_two_harness_runs.pcap = captures/loopback_harness_runs.pcap (renamed from C0-curl-001.pcap)
                                   (NOT a lab C0 run: loopback capture spanning both
                                    Milestone 1 harness runs on 2026-10-25)
"""

import hashlib
from pathlib import Path

import pytest

from analysis import metrics
from analysis.parse_pcap import (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL2, PcapError, analyse, parse,
                                 read_pcap)
from tests import pcapgen as g

FIX = Path(__file__).resolve().parent / "fixtures"
S1 = FIX / "s1_manual_curl.pcap"
LOOP = FIX / "loopback_two_harness_runs.pcap"
HASHES = {
    S1: "2e7479ca2f224fddaa4d8ac247782ecf24fc32423797d1160443a192e358a476",
    LOOP: "0a672c4aa5f158e55ba7ed00b3303fe2cbe787c819170db04764bac33914421c",
}
# Client windows from the two Milestone 1 harness records (client_start_epoch_ns, client_end_epoch_ns)
HARNESS_RUN_1 = (1792924107855295508, 1792924107865545636)
HARNESS_RUN_2 = (1792924467959920135, 1792924467970558649)


@pytest.mark.parametrize("path", [S1, LOOP])
def test_fixture_is_unmodified_copy(path):
    assert hashlib.sha256(path.read_bytes()).hexdigest() == HASHES[path]


# --- S1 manual capture: must reproduce the hand-checked values ----------------------

@pytest.fixture(scope="module")
def s1():
    tl = parse(S1)
    return tl, metrics.compute(tl)


def test_s1_reproduces_hand_checked_values(s1):
    _, m = s1
    assert m.tcp_setup_time_ms == pytest.approx(220.593, abs=0.0005)
    assert m.inter_family_attempt_delay_ms == pytest.approx(200.443, abs=0.0005)
    assert m.winning_family == "v4"
    assert m.failed_or_abandoned == 1
    assert [(a.family, r) for a, r in m.results] == [("v6", "abandoned"), ("v4", "won")]


def test_s1_packet_facts(s1):
    tl, _ = s1
    assert tl.linktype == LINKTYPE_LINUX_SLL2
    assert tl.packet_count == 15
    assert tl.neighbour_packets == 0 and tl.icmp_errors == [] and tl.anomalies == []
    v6, v4 = tl.attempts
    assert (v6.dst, v6.dport, v6.syn_count, v6.synack_ns, v6.server_rst_ns, v6.client_rst_ns) == (
        "2001:db8:28:6::2", 80, 1, None, None, None)
    assert v6.first_syn_ns == 1792989112233148000
    assert (v4.dst, v4.syn_count, v4.http_status) == ("192.0.2.2", 1, 200)
    assert v4.first_syn_ns == 1792989112433591000
    assert v4.synack_ns == 1792989112453705000
    assert v4.handshake_ack_ns == 1792989112453741000


def test_s1_dns_exchange(s1):
    tl, m = s1
    assert [(d.qtype, d.rcode, d.answers) for d in tl.dns] == [
        ("A", "NOERROR", ["192.0.2.2"]), ("AAAA", "NOERROR", ["2001:db8:28:6::2"])]
    assert m.dns_time_ms == pytest.approx(0.753, abs=0.0005)


def test_s1_cooked_capture_marks_direction():
    _, packets = read_pcap(S1)
    dns_query, dns_answer = packets[0], packets[2]
    assert dns_query.outgoing is True and dns_answer.outgoing is False
    assert all(p.ifindex is not None for p in packets)


def test_s1_record_fields_validate(s1):
    tl, m = s1
    obs, met = metrics.record_fields(m, tl)
    assert obs["winning_family"] == {"value": "v4", "status": "computed"}
    assert obs["failed_or_abandoned_attempts"] == {"value": 1, "status": "computed"}
    assert [a["result"] for a in obs["attempts"]["value"]] == ["abandoned", "won"]
    assert met["tcp_setup_time_ms"] == {"value": 220.593, "status": "computed"}
    assert met["inter_family_attempt_delay_ms"] == {"value": 200.443, "status": "computed"}
    assert met["scenario_penalty_ms"]["status"] == "not_applicable"


# --- loopback capture with two harness runs ------------------------------------------

def test_loopback_without_window_is_ambiguous_and_picks_nothing():
    tl = parse(LOOP)
    m = metrics.compute(tl)
    assert tl.linktype == LINKTYPE_ETHERNET and tl.packet_count == 26
    assert m.ambiguous and m.winner is None and m.tcp_setup_time_ms is None
    obs, met = metrics.record_fields(m, tl)
    assert obs["winning_family"]["status"] == "not_yet_computed"
    assert "ambiguous" in obs["winning_family"]["note"]
    assert met["tcp_setup_time_ms"]["status"] == "not_yet_computed"


@pytest.mark.parametrize("window,setup_ms", [(HARNESS_RUN_1, 0.029), (HARNESS_RUN_2, 0.022)])
def test_loopback_window_isolates_one_run(window, setup_ms):
    tl = parse(LOOP, window)
    m = metrics.compute(tl)
    assert tl.packet_count == 13 and len(tl.attempts) == 1
    assert m.winning_family == "v4" and m.failed_or_abandoned == 0
    assert m.tcp_setup_time_ms == pytest.approx(setup_ms, abs=0.0005)
    assert m.inter_family_attempt_delay_ms is None  # one family only -> not observed
    assert m.dns_time_ms is None                    # IP literal, no DNS
    _, met = metrics.record_fields(m, tl)
    assert met["inter_family_attempt_delay_ms"]["status"] == "not_observed"
    assert met["dns_time_ms"]["status"] == "not_observed"


def test_loopback_run_2_matches_milestone_1_hand_check():
    """Milestone 1 hand check: SYN 1792924467.968475, ACK .968497 -> 22 us."""
    tl = parse(LOOP, HARNESS_RUN_2)
    (a,) = tl.attempts
    assert a.first_syn_ns == 1792924467968475000 and a.handshake_ack_ns == 1792924467968497000


# --- synthetic edge cases ------------------------------------------------------------

T0 = 1_800_000_000 * 1_000_000_000


def run(frames, tmp_path, **kw):
    f = tmp_path / "x.pcap"
    f.write_bytes(g.pcap(frames, **kw))
    tl = parse(f)
    return tl, metrics.compute(tl)


def test_rst_means_failed(tmp_path):
    frames = [(T0, g.ip_tcp(g.C6, g.S6, 40000, 80, g.SYN, seq=1)),
              (T0 + 20 * g.MS, g.ip_tcp(g.S6, g.C6, 80, 40000, g.RST | g.ACK, ack=2))]
    frames += g.handshake(T0 + 25 * g.MS, g.C4, g.S4, 40001)
    tl, m = run(frames, tmp_path)
    assert [r for _, r in m.results] == ["failed", "won"]
    assert m.failed_or_abandoned == 1
    assert m.inter_family_attempt_delay_ms == 25.0
    assert m.tcp_setup_time_ms == pytest.approx(25 + 20 + 0.03, abs=0.0005)


def test_syn_retransmissions_are_counted(tmp_path):
    frames = [(T0, g.ip_tcp(g.C6, g.S6, 40000, 80, g.SYN, seq=1)),
              (T0 + 1000 * g.MS, g.ip_tcp(g.C6, g.S6, 40000, 80, g.SYN, seq=1))]
    frames += g.handshake(T0 + 300 * g.MS, g.C4, g.S4, 40001)
    tl, m = run(frames, tmp_path)
    v6 = tl.attempts[0]
    assert v6.syn_count == 2 and v6.syn_retransmits == 1
    obs, _ = metrics.record_fields(m, tl)
    assert obs["attempts"]["value"][0]["syn_retransmits"] == 1


def test_no_reply_anywhere_is_no_reply_not_abandoned(tmp_path):
    frames = [(T0, g.ip_tcp(g.C6, g.S6, 40000, 80, g.SYN, seq=1)),
              (T0 + 200 * g.MS, g.ip_tcp(g.C4, g.S4, 40001, 80, g.SYN, seq=1))]
    tl, m = run(frames, tmp_path)
    assert [r for _, r in m.results] == ["no_reply", "no_reply"]
    assert m.winner is None and m.tcp_setup_time_ms is None
    obs, met = metrics.record_fields(m, tl)
    assert obs["winning_family"]["status"] == "not_observed"
    assert met["tcp_setup_time_ms"]["status"] == "not_observed"
    assert met["inter_family_attempt_delay_ms"] == {"value": 200.0, "status": "computed"}


def test_ipv4_only_is_not_observed_inter_family(tmp_path):
    tl, m = run(g.handshake(T0, g.C4, g.S4, 40001), tmp_path)
    assert m.families_tried == ["v4"] and m.inter_family_attempt_delay_ms is None
    assert m.tcp_setup_time_ms == pytest.approx(20.03, abs=0.0005)


def test_completed_but_unused_connection_is_abandoned(tmp_path):
    frames = g.handshake(T0, g.C6, g.S6, 40000, rtt_ms=150, data=False)
    frames += g.handshake(T0 + 100 * g.MS, g.C4, g.S4, 40001, rtt_ms=20)
    tl, m = run(frames, tmp_path)
    assert [(a.family, r) for a, r in m.results] == [("v6", "abandoned"), ("v4", "won")]
    # first SYN (v6, T0) to the winning ACK (v4, T0 + 100 + 20 + 0.03 ms)
    assert m.tcp_setup_time_ms == pytest.approx(120.03, abs=0.0005)


def test_icmp_errors_and_neighbour_discovery_are_counted(tmp_path):
    frames = [(T0, g.ip_icmp(g.C6, g.S6, 135)),                 # neighbour solicitation
              (T0 + g.MS, g.ip_icmp(g.S6, g.C6, 1, 3)),         # address unreachable
              (T0 + 2 * g.MS, g.ip_icmp(g.S4, g.C4, 3, 1))]     # host unreachable
    tl, _ = run(frames, tmp_path)
    assert tl.neighbour_packets == 1 and len(tl.icmp_errors) == 2


def test_nanosecond_pcap(tmp_path):
    tl, m = run(g.handshake(T0 + 7, g.C4, g.S4, 40001), tmp_path, nanosecond=True)
    assert tl.attempts[0].first_syn_ns == T0 + 7


def test_pcapng_rejected(tmp_path):
    f = tmp_path / "x.pcapng"
    f.write_bytes(bytes.fromhex("0a0d0d0a") + b"\x00" * 40)
    with pytest.raises(PcapError, match="pcapng"):
        read_pcap(f)


def test_truncated_file_rejected(tmp_path):
    f = tmp_path / "x.pcap"
    f.write_bytes(g.pcap(g.handshake(T0, g.C4, g.S4, 40001))[:-5])
    with pytest.raises(PcapError, match="truncated"):
        read_pcap(f)


def test_window_is_inclusive(tmp_path):
    frames = g.handshake(T0, g.C4, g.S4, 40001)
    f = tmp_path / "x.pcap"
    f.write_bytes(g.pcap(frames))
    lt, pkts = read_pcap(f)
    assert analyse(lt, pkts, (T0, T0)).packet_count == 1


# --- scenario penalty -----------------------------------------------------------------

def test_scenario_penalty_is_median_minus_own_c0_median():
    assert metrics.scenario_penalty([220.0, 221.0, 230.0], [20.0, 21.0, 22.0, 40.0]) == pytest.approx(199.5)


def test_scenario_penalty_needs_both_sets():
    assert metrics.scenario_penalty([], [20.0]) is None
    assert metrics.scenario_penalty([20.0], []) is None


# --- log vs pcap cross-check ------------------------------------------------------------

def test_cross_check_agrees_on_s1(s1):
    _, m = s1
    cc = metrics.cross_check({"success": True, "http_status": 200}, {"remote_ip": "192.0.2.2"}, m)
    assert cc == {"status": "agree", "conflicts": []}


def test_cross_check_flags_remote_ip_and_keeps_both_values(s1):
    _, m = s1
    cc = metrics.cross_check({"success": True, "http_status": 200},
                             {"remote_ip": "2001:db8:28:6::2"}, m)
    assert cc["status"] == "conflict"
    (c,) = cc["conflicts"]
    assert (c["field"], c["log_value"], c["pcap_value"]) == ("remote_ip", "2001:db8:28:6::2", "192.0.2.2")


def test_cross_check_flags_status_and_success(s1):
    _, m = s1
    cc = metrics.cross_check({"success": False, "http_status": 503}, None, m)
    assert {c["field"] for c in cc["conflicts"]} == {"success", "http_status"}


def test_cross_check_success_without_handshake(tmp_path):
    _, m = run([(T0, g.ip_tcp(g.C4, g.S4, 40001, 80, g.SYN, seq=1))], tmp_path)
    cc = metrics.cross_check({"success": True, "http_status": 200}, None, m)
    assert cc["status"] == "conflict" and cc["conflicts"][0]["field"] == "success"


def test_cross_check_ambiguous_capture_is_a_conflict():
    m = metrics.compute(parse(LOOP))
    cc = metrics.cross_check({"success": True, "http_status": 200}, None, m)
    assert cc["status"] == "conflict" and cc["conflicts"][0]["field"] == "winner"
