"""Jitter and partial-loss support: lab commands, band verify, records, win fraction, SYN retransmissions.

The core scenarios C0 and S1-S6 must produce byte-identical netem commands and orchestrator
arguments to what they produced before jitter existed; the exact strings are pinned here.
"""

import json
import subprocess
from pathlib import Path

import pytest

from analysis import syn_retransmit as sr
from analysis.metrics import adaptive_decision, wilson_ci
from analysis.scenario_config import SCENARIOS_FILE, load_config
from analysis.validate_record import validate
from runner import orchestrate as o
from runner import scenario_grid as sg
from runner.child_env import child_env
from tests import pcapgen as g

LAB = Path(__file__).resolve().parents[2] / "src" / "lab"
CORE = load_config(SCENARIOS_FILE, generated=None)["scenarios"]
GEN = load_config(SCENARIOS_FILE)["scenarios"]


def set_link_cmds(*args: str) -> list[str]:
    """What hl_set_link would run, with run() replaced by a printer (no tc is executed)."""
    out = subprocess.run(
        ["bash", "-c", f'source "{LAB}/lib.sh"; run() {{ printf "+ %s\\n" "$*"; }}; hl_set_link "$@"', "_", *args],
        capture_output=True, text=True, env=child_env())
    assert out.returncode == 0, out.stderr
    return out.stdout.splitlines()


def netem_lines(v4: str, v6: str) -> list[str]:
    return [f"+ tc -n hl-server qdisc replace dev {d} root netem {a}"
            for d, a in (("hl-v4s", v4), ("hl-ifb4", v4), ("hl-v6s", v6), ("hl-ifb6", v6))]


# Captured from the scripts before jitter was added (2026-11-21); must never change.
GOLDEN_TC = {
    "C0": netem_lines("delay 10ms", "delay 10ms"),
    "S1": netem_lines("delay 10ms", "delay 10ms loss 100%"),
    "S2": netem_lines("delay 10ms", "delay 310ms"),
    "S3": netem_lines("delay 10ms", "delay 85ms"),
    "S4": netem_lines("delay 10ms loss 100%", "delay 10ms"),
    "S5": netem_lines("delay 310ms", "delay 10ms"),
    "S6": netem_lines("delay 10ms", "delay 10ms"),
}
GOLDEN_ARGV = {
    "C0": (["v4", "10", "0"], ["v6", "10", "0"]), "S1": (["v4", "10", "0"], ["v6", "10", "100"]),
    "S2": (["v4", "10", "0"], ["v6", "310", "0"]), "S3": (["v4", "10", "0"], ["v6", "85", "0"]),
    "S4": (["v4", "10", "100"], ["v6", "10", "0"]), "S5": (["v4", "310", "0"], ["v6", "10", "0"]),
    "S6": (["v4", "10", "0"], ["v6", "10", "0"]),
}


@pytest.mark.parametrize("sid", sorted(GOLDEN_TC))
def test_core_tc_commands_are_byte_identical(sid):
    sc = CORE[sid]
    got = []
    for fam in ("v4", "v6"):
        argv = o.netem_for(fam, sc[fam])
        assert argv[1:] == GOLDEN_ARGV[sid][0 if fam == "v4" else 1]   # three arguments, no jitter
        got += set_link_cmds(*argv[1:])
    assert got == GOLDEN_TC[sid]


@pytest.mark.parametrize("sid", sorted(GOLDEN_TC))
def test_core_verify_arguments_unchanged(sid):
    t = CORE[sid]["verify_target"]
    assert o.cmd_verify(t["v4"], t["v6"])[2:] == [str(t["v4"]), str(t["v6"])]


def test_jitter_names_its_distribution_and_keeps_loss_last():
    assert set_link_cmds("v6", "110", "0", "50")[0] == \
        "+ tc -n hl-server qdisc replace dev hl-v6s root netem delay 110ms 50ms distribution normal"
    assert set_link_cmds("v6", "110", "5", "50")[1].endswith("netem delay 110ms 50ms distribution normal loss 5%")
    assert set_link_cmds("v6", "10", "0", "0") == set_link_cmds("v6", "10", "0")


def test_bad_jitter_is_refused_before_anything_runs():
    out = subprocess.run(["bash", "-c", f'source "{LAB}/lib.sh"; run() {{ echo RAN; }}; hl_set_link v6 10 0 x'],
                         capture_output=True, text=True, env=child_env())
    assert out.returncode == 2 and "RAN" not in out.stdout


def test_generated_jitter_and_loss_commands():
    assert o.netem_for("v6", GEN["Gv6j50"]["v6"])[1:] == ["v6", "110", "0", "50"]
    assert o.netem_for("v6", GEN["Gv6j70"]["v6"])[1:] == ["v6", "150", "0", "70"]
    assert o.netem_for("v6", GEN["Gv6l30"]["v6"])[1:] == ["v6", "10", "30"]
    assert o.netem_for("v4", GEN["Gv6j50"]["v4"])[1:] == ["v4", "10", "0"]


# --- band verify (lib.sh) --------------------------------------------------------------

def _lib(snippet: str, *args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", f'source "{LAB}/lib.sh"; {snippet}', "_", *args],
                          input=stdin, capture_output=True, text=True, env=child_env())


def ping_output(rtts: list[float], sent: int) -> str:
    lines = [f"64 bytes from x: icmp_seq={i} ttl=64 time={t} ms" for i, t in enumerate(rtts, 1)]
    loss = round(100 * (sent - len(rtts)) / sent)
    return "\n".join(lines + [f"{sent} packets transmitted, {len(rtts)} received, {loss}% packet loss, time 1ms"]) + "\n"


def test_sd_is_appended_only_when_asked():
    out = ping_output([10.0, 20.0, 30.0], 3)
    plain = _lib("hl_rtt_stats", stdin=out).stdout.strip()
    with_sd = _lib('hl_rtt_stats sd', stdin=out).stdout.strip()
    assert plain == "median_ms=20.00 min_ms=10.00 max_ms=30.00 loss_pct=0 sent=3 received=3 errors=0"
    assert with_sd == plain + " sd_ms=8.16"


@pytest.mark.parametrize("stats,ok", [
    ("median_ms=20.5 loss_pct=20 errors=0", True),
    ("median_ms=20.5 loss_pct=31.5 errors=0", False),     # loss outside 19 +/- 12
    ("median_ms=20.5 loss_pct=7 errors=0", True),
    ("median_ms=20.5 loss_pct=20 errors=3", False),       # not silent
    ("median_ms=25 loss_pct=20 errors=0", False),         # median outside 20 +/- 2
    ("median_ms=NA loss_pct=100 errors=0", False),
])
def test_loss_band(stats, ok):
    r = _lib('hl_rtt_check "$1" "$2"', "band:loss:19:12:20:200", stats)
    assert (r.returncode == 0) == ok, r.stdout
    assert "observed_loss_pct=" in r.stdout and r.stdout.strip().endswith("PASS" if ok else ")")


@pytest.mark.parametrize("stats,ok", [
    ("median_ms=220 sd_ms=70 loss_pct=0", True),
    ("median_ms=250 sd_ms=70 loss_pct=0", False),
    ("median_ms=220 sd_ms=40 loss_pct=0", False),
    ("median_ms=220 sd_ms=70 loss_pct=0.5", False),
    ("median_ms=220 loss_pct=0", False),                  # no sd: stats made without "sd"
])
def test_jitter_band(stats, ok):
    r = _lib('hl_rtt_check "$1" "$2"', "band:jitter:194.9:245.1:56.5:84.9:200", stats)
    assert (r.returncode == 0) == ok, r.stdout
    assert "observed_sd_ms=" in r.stdout


def test_point_check_is_unchanged():
    assert _lib('hl_rtt_check "$1" "$2"', "20", "median_ms=20.5 loss_pct=0").stdout.strip() == \
        "target_ms=20 tol_ms=2.0 PASS"


def test_band_ping_count():
    assert _lib('hl_band_pings "$1"', "band:loss:19:12:20:200").stdout.strip() == "200"
    assert _lib('hl_band_pings "$1"', "band:jitter:1:2:3:4:150").stdout.strip() == "150"
    assert _lib('hl_band_pings "$1"', "620").stdout == ""


@pytest.mark.parametrize("target,ok", [
    ("20", True), ("blackhole", True), ("band:loss:19:12:20:200", True),
    ("band:jitter:194.9:245.1:56.5:84.9:200", True), ("loss:10", False), ("band:loss:19:12:20", False),
    ("band:jitter:1:2:3:4:x", False), ("max:30", False),
])
def test_verify_sh_valid_target(target, ok):
    fn = subprocess.run(["sed", "-n", "/^valid_target()/,/^}/p", str(LAB / "verify.sh")],
                        capture_output=True, text=True).stdout
    assert fn.startswith("valid_target()")
    r = subprocess.run(["bash", "-c", fn + '\nvalid_target "$1"', "_", target], env=child_env())
    assert (r.returncode == 0) == ok


# --- generator: bands, twins, IDs ------------------------------------------------------

BASE = {"delay_ms_each_way": 10, "rtt_ms": 20}


def test_loss_bands_follow_the_round_trip_formula():
    for each, q, tol in ((10, 19.0, 12), (30, 51.0, 15), (50, 75.0, 13)):
        b = GEN[f"Gv6l{each}"]["verify_target"]["v6"]
        assert (b["expect_loss_pct"], b["tolerance_pct"], b["pings"]) == (q, tol, 200)


def test_jitter_scenarios_and_their_bands():
    j50, j70 = GEN["Gv6j50"], GEN["Gv6j70"]
    assert j50["v6"] == {"delay_ms_each_way": 110, "loss_pct": 0, "jitter_ms_each_way": 50}
    assert j70["v6"] == {"delay_ms_each_way": 150, "loss_pct": 0, "jitter_ms_each_way": 70}
    assert j50["verify_target"]["v6"] == {"band": "jitter", "median_ms": [194.9, 245.1], "sd_ms": [56.5, 84.9],
                                          "pings": 200}
    lo, hi = j70["verify_target"]["v6"]["median_ms"]
    assert lo < 300 < hi                                   # mean RTT 20 + 4 * 70
    assert all(s["extension"] is True for k, s in GEN.items() if k.startswith("G"))


def test_delay_twins_have_the_same_mean_rtt_and_are_kept_once():
    assert GEN["Gv6j50"]["grid"]["delay_twin"] == "Gv6d200"
    assert GEN["Gv6j70"]["grid"]["delay_twin"] == "Gv6d280"
    assert GEN["Gv6d280"]["v6"] == {"delay_ms_each_way": 150, "loss_pct": 0}
    assert GEN["Gv6d280"]["verify_target"]["v6"] == 300
    ids = [k for k in GEN if k.startswith("G")]
    assert len(ids) == len(set(ids)) and ids.count("Gv6d200") == 1


def test_no_core_like_or_s8_names():
    assert not any(k.startswith(("S8", "S9")) for k in GEN)


def test_generated_file_is_up_to_date():
    assert sg.main(["--check"]) == 0


# --- orchestrator: verify arguments and the observed block ----------------------------

def test_verify_arg_for_bands_and_points():
    assert o.verify_arg(20) == "20" and o.verify_arg("blackhole") == "blackhole"
    assert o.verify_arg(GEN["Gv6l10"]["verify_target"]["v6"]) == "band:loss:19:12:20:200"
    assert o.verify_arg(GEN["Gv6j50"]["verify_target"]["v6"]) == "band:jitter:194.9:245.1:56.5:84.9:200"
    for bad in ({"band": "loss"}, {"band": "jitter", "median_ms": [2, 1], "sd_ms": [1, 2], "pings": 200},
                {"band": "loss", "expect_loss_pct": 19, "tolerance_pct": 12, "rtt_ms": 20, "pings": 5}, "loss:5"):
        with pytest.raises(o.OrchestratorError):
            o.verify_arg(bad)


def test_verify_observed_keeps_the_measured_values():
    pre = {"v4": {"verdict": "PASS", "median_ms": "20.4", "loss_pct": "0", "sent": "10", "received": "10",
                  "errors": "0"},
           "v6": {"verdict": "PASS", "median_ms": "221.3", "sd_ms": "71.2", "loss_pct": "0", "sent": "200",
                  "received": "200", "errors": "0"}}
    vo = o.verify_observed(pre, {"v4": 20, "v6": GEN["Gv6j50"]["verify_target"]["v6"]})
    assert vo["v4"]["mode"] == "point" and vo["v4"]["observed"]["sd_ms"] is None
    assert vo["v6"]["mode"] == "band" and vo["v6"]["observed"]["sd_ms"] == 71.2
    assert vo["v6"]["verify_arg"].startswith("band:jitter:")


def test_dry_run_prints_jitter_and_band(capsys):
    sc = o.load_scenarios(["Gv6j50"], SCENARIOS_FILE, "curl")
    o.dry_run(sc, 1, "sr", o.load_lab_env())
    out = capsys.readouterr().out
    assert "netem.sh v6 110 0 50" in out and "band:jitter:194.9:245.1:56.5:84.9:200" in out
    assert "netem.sh v4 10 0\n" in out                   # the healthy family keeps three arguments


# --- win fraction and the adaptive rule ------------------------------------------------

def test_wilson_interval():
    assert wilson_ci(10, 20) == {"lo": 0.2993, "hi": 0.7007, "width": 0.4014, "level": 0.95, "n": 20,
                                 "method": "Wilson score interval"}
    assert wilson_ci(0, 20)["lo"] == 0.0 and wilson_ci(20, 20)["hi"] == 1.0
    assert wilson_ci(0, 0) is None


def test_without_winners_the_rule_is_unchanged():
    xs = [100.0 + i % 3 for i in range(20)]
    assert "win" not in adaptive_decision(xs, 20, 60, 5.0)


def test_win_criterion_keeps_going_while_the_fraction_is_wide():
    xs = [220.0] * 20                                     # median CI is zero-width at once
    winners = ["v6", "v4"] * 10                            # 10/20: Wilson width 0.40
    st = adaptive_decision(xs, 20, 60, 5.0, winners=winners)
    assert st["decision"] == "stop" and st["win"]["wins"] == 10          # median-only: stops
    st = adaptive_decision(xs, 20, 60, 5.0, winners=winners, win_ci_width=0.3)
    assert st["decision"] == "continue"
    st = adaptive_decision([220.0] * 60, 20, 60, 5.0, winners=["v6", "v4"] * 30, win_ci_width=0.2)
    assert st["decision"] == "stop" and st["reason"] == "max_reps_reached"


def test_win_note_says_so_rather_than_stopping_quietly():
    st = adaptive_decision([220.0] * 20, 20, 60, 5.0, winners=["v6", "v4"] * 10)
    assert "median CI alone" in o.win_note(st, None)
    st = adaptive_decision([220.0] * 20, 20, 60, 5.0, winners=["v4"] * 20)
    assert o.win_note(st, None) is None                    # every run won by one family
    st = adaptive_decision([220.0] * 60, 20, 60, 5.0, winners=["v6", "v4"] * 30, win_ci_width=0.2)
    assert "poorly determined" in o.win_note(st, 0.2)


# --- SYN retransmissions from synthetic captures ---------------------------------------

MS = g.MS
T0 = 1_700_000_000 * 1_000_000_000


def _retransmitted_v6(t0: int) -> list:
    """v6 SYN lost, the same socket's SYN 1000 ms later is answered; no IPv4."""
    f = [(t0, g.ip_tcp(g.C6, g.S6, 40000, 80, g.SYN, seq=1000))]
    return f + g.handshake(t0 + 1000 * MS, g.C6, g.S6, 40000, rtt_ms=20)


def _v4_fallback(t0: int) -> list:
    """v6 SYN unanswered, v4 SYN 200 ms later wins."""
    return [(t0, g.ip_tcp(g.C6, g.S6, 40002, 80, g.SYN, seq=7000))] + g.handshake(t0 + 200 * MS, g.C4, g.S4, 40004)


def _record(tmp: Path, rep: int, frames: list, win: str, setup: float, adaptive: dict | None = None) -> dict:
    pcap = tmp / f"r{rep}.pcap"
    pcap.write_bytes(g.pcap(frames, nanosecond=True))
    t = frames[0][0]
    r = {"run_id": f"r{rep}", "client": {"name": "curl"}, "scenario": {"id": "Gv6l30", "repetition": rep},
         "timestamps": {"client_start_epoch_ns": t - MS, "capture_end_epoch_ns": t + 3000 * MS},
         "evidence": {"pcap_path": pcap.name},
         "packet_observations": {"winning_family": {"status": "computed", "value": win}},
         "metrics": {"tcp_setup_time_ms": {"status": "computed", "value": setup}}}
    if adaptive:
        r["adaptive"] = adaptive
    return r


def test_retransmission_gap_and_clusters_from_packets(tmp_path):
    recs = [_record(tmp_path, 1, _retransmitted_v6(T0), "v6", 1020.03),
            _record(tmp_path, 2, _v4_fallback(T0 + 5000 * MS), "v4", 220.03),
            _record(tmp_path, 3, _v4_fallback(T0 + 9000 * MS), "v4", 221.0)]
    c = sr.analyse_cell(recs, repo=tmp_path)
    gaps = c["syn_retransmission_gaps"]
    assert gaps == [{"ordinal": 1, "n": 1, "median_ms": 1000.0, "min_ms": 1000.0, "max_ms": 1000.0,
                     "reference_ms": 1000.0}]
    assert c["attempts_with_syn_retransmission"] == 1     # the fallback runs' v6 socket: censored, none seen
    assert [k["n"] for k in c["setup_clusters"]] == [2, 1]
    assert c["cluster_spacing_ms"] == [round(1020.03 - 220.515, 3)]
    assert c["win"]["v6"]["wins"] == 1 and c["win"]["v4"]["wins"] == 2
    text = sr.report([c])
    assert "[packet-level]" in text and "decid" not in text     # no statement about client decisions


def test_syn_reference_is_linear_then_doubling_and_synack_reference_doubles():
    # tcp_syn_linear_timeouts=4: SYN gaps 1, 1, 1, 1, 1, 2, 4 s; the server's SYN-ACKs have no linear phase
    assert [sr.syn_reference_ms(k) for k in range(1, 8)] == [1000.0] * 5 + [2000.0, 4000.0]
    assert [sr.syn_reference_ms(k, linear=0) for k in range(1, 4)] == [1000.0, 2000.0, 4000.0]
    assert [sr.synack_reference_ms(k) for k in range(1, 4)] == [1000.0, 2000.0, 4000.0]


def test_manifest_accepts_a_win_criterion():
    from analysis.summarise import DatasetError, _adaptive_reps
    assert _adaptive_reps(Path("x.md"), {"min": 20, "max": 60, "ci_width_ms": 5, "win_ci_width": 0.3}) == \
        (60, (20, 60, 5.0, 0.3))
    assert _adaptive_reps(Path("x.md"), {"min": 20, "max": 60, "ci_width_ms": 5}) == (60, (20, 60, 5.0))
    with pytest.raises(DatasetError):
        _adaptive_reps(Path("x.md"), {"min": 20, "max": 60, "ci_width_ms": 5, "win_ci_width": 1.5})


def test_a_new_source_port_is_not_a_retransmission(tmp_path):
    frames = [(T0, g.ip_tcp(g.C6, g.S6, 41000, 80, g.SYN, seq=1)),
              (T0 + 250 * MS, g.ip_tcp(g.C6, g.S6, 41002, 80, g.SYN, seq=9))] + g.handshake(
                  T0 + 300 * MS, g.C4, g.S4, 41004)
    c = sr.analyse_cell([_record(tmp_path, 1, frames, "v4", 320.0)], repo=tmp_path)
    assert c["syn_retransmission_gaps"] == []


def test_adaptive_note_on_a_median_only_stop(tmp_path):
    ad = {"min_reps": 2, "max_reps": 60, "ci_width_ms": 5.0, "metric": "tcp_setup_time_ms",
          "after_this_run": {"reason": "ci_width_reached"}}
    recs = [_record(tmp_path, 1, _retransmitted_v6(T0), "v6", 1020.0, ad),
            _record(tmp_path, 2, _v4_fallback(T0 + 5000 * MS), "v4", 220.0, ad)]
    assert "median setup-time CI alone" in sr.analyse_cell(recs, repo=tmp_path)["adaptive_note"]


def test_record_carries_verify_observed_and_it_validates_only_in_0_5():
    from tests.test_client_variants import _record as variant_record   # a full S1 record
    r = variant_record("curl")
    vo = r["scenario"]["verify_observed"]
    assert vo["v6"]["mode"] == "point" and vo["v6"]["target"] == "blackhole"
    assert vo["v4"]["observed"]["median_ms"] is not None
    assert validate(r) == []
    r["schema_version"] = "0.4"
    assert any("verify_observed" in e for e in validate(r))
    json.dumps(r)


def _session(setups, winners, lo, hi, w, win_w):
    recs, prev, prev_w = [], [], []
    for i, (s, wf) in enumerate(zip(setups, winners), 1):
        r = {"run_id": f"r{i}", "scenario": {"repetition": i},
             "metrics": {"tcp_setup_time_ms": {"status": "computed", "value": s}},
             "packet_observations": {"winning_family": {"status": "computed", "value": wf}}}
        r["adaptive"] = o.adaptive_block(prev, r, lo, hi, w, win_w, prev_w)
        recs.append(r)
        prev.append(s)
        prev_w.append(wf)
        if r["adaptive"]["after_this_run"]["decision"] == "stop":
            break
    return recs


def test_summarise_replays_a_win_criterion_session():
    from analysis.summarise import _check_adaptive_session
    setups, winners = [220.0] * 40, ["v6", "v4"] * 20
    recs = _session(setups, winners, 20, 40, 5.0, 0.3)
    assert len(recs) == 39                              # Wilson width <= 0.3 first at n = 39 (19-20 split)
    assert _check_adaptive_session(recs, (20, 40, 5.0, 0.3)) == []
    assert _check_adaptive_session(recs, (20, 40, 5.0)) != []      # manifest must declare the criterion
    median_only = _session(setups, winners, 20, 40, 5.0, None)
    assert len(median_only) == 20 and "win" in median_only[-1]["adaptive"]["after_this_run"]
    assert _check_adaptive_session(median_only, (20, 40, 5.0)) == []


@pytest.mark.parametrize("target", ["band:jitter:194.9:245.1:56.5:84.9:200", "band:loss:19:12:20:200", "20"])
def test_verify_line_keeps_the_measured_values_through_the_parser(target):
    """verify.sh prints 'PASS RTT v6 <stats> <verdict>' on one line; no verdict key may shadow a stats key."""
    stats = "median_ms=221.30 min_ms=60.10 max_ms=390.00 loss_pct=0 sent=200 received=200 errors=0 sd_ms=71.20"
    verdict = _lib('hl_rtt_check "$1" "$2"', target, stats).stdout.strip()
    parsed = o.parse_verify_rtt(f"PASS RTT v6 {stats} {verdict}\n")["v6"]
    assert parsed["median_ms"] == "221.30" and parsed["sd_ms"] == "71.20" and parsed["sent"] == "200"


def test_compound_scenario_blackholes_the_other_family():
    c = GEN["Gv6c30"]
    assert c["extension"] is True and c["grid"]["kind"] == "loss_sole_path"
    assert c["v4"] == {"delay_ms_each_way": 10, "loss_pct": 100} and c["v6"] == {"delay_ms_each_way": 10, "loss_pct": 30}
    assert c["verify_target"]["v4"] == "blackhole"
    assert c["verify_target"]["v6"] == GEN["Gv6l30"]["verify_target"]["v6"]
    assert o.netem_for("v4", c["v4"])[1:] == GOLDEN_ARGV["S4"][0]        # the same v4 blackhole as S4
    assert o.cmd_verify(c["verify_target"]["v4"], c["verify_target"]["v6"])[2:] == ["blackhole", "band:loss:51:15:20:200"]


def test_compound_kind_refuses_full_loss():
    with pytest.raises(sg.GridError, match="1-99"):
        sg.scenario_for("v6", "loss_sole_path", 100, BASE)


def test_band_pilot_plan_restores_and_verifies_the_baseline_last():
    from runner import band_pilot as bp
    sids = list(bp.BAND_SCENARIOS)
    steps = bp.plan(o.load_scenarios(sids, client="curl"), sids, 3)
    assert [s for s in steps if s[0] == "Gv6c30" and s[1] == "apply"][0][2][1:] == ["v4", "10", "100"]
    assert sum(1 for s in steps if s[1].startswith("verify ")) == 3 * len(sids)
    assert [s[1] for s in steps[-3:]] == ["restore", "restore", "verify"]
    assert steps[-1][2][2:] == ["20", "20"]
    assert not any("tcpdump" in " ".join(s[2]) or "curl" in s[2][0] for s in steps)   # apply and verify only


# --- runs without a winner: kept in the median and in the outcomes ----------------------

from analysis.metrics import (FAILED_RANKED, FAILURE_RATE_CAVEAT, bootstrap_median_ci,  # noqa: E402
                              bootstrap_median_ci_ranked)


def test_ranked_ci_is_identical_without_failures():
    xs = [220.0 + (i * 7) % 5 for i in range(25)]
    a, b = bootstrap_median_ci(xs), bootstrap_median_ci_ranked(xs)
    assert {k: b[k] for k in a} == a and b["unbounded"] is False and b["n_without_value"] == 0


def test_failed_runs_are_ranked_not_dropped():
    # 6 of 20 runs time out; the 14 successes are tight around 20 ms
    xs = [20.0 + i * 0.01 for i in range(14)] + [None] * 6
    legacy = adaptive_decision(xs, 20, 50, 25.0)
    ranked = adaptive_decision(xs, 20, 50, 25.0, failed_runs=FAILED_RANKED)
    assert legacy["decision"] == "stop" and legacy["median_ms"] < 20.1          # excluded: biased low, stops
    assert ranked["median_ms"] == legacy["median_ms"] or ranked["median_ms"] > legacy["median_ms"]
    assert ranked["ci"]["unbounded"] is True and ranked["ci"]["hi"] is None and ranked["ci"]["width"] is None
    assert ranked["decision"] == "continue"                                     # unbounded CI never stops it
    majority = adaptive_decision([20.0] * 9 + [None] * 11, 20, 50, 25.0, failed_runs=FAILED_RANKED)
    assert majority["median_ms"] is None                                        # above every observed value


def test_three_outcomes_cover_every_run():
    st = adaptive_decision([20.0, None, 220.0, None, 21.0], 1, 50, 25.0, winners=["v6", None, "v4", None, "v6"],
                           failed_runs=FAILED_RANKED)
    oc = st["win"]["outcomes"]
    assert (oc["v6"]["n"], oc["v4"]["n"], oc["none"]["n"]) == (2, 1, 2) and st["win"]["n"] == 5
    assert oc["none"]["ci"] == wilson_ci(2, 5)


def test_orchestrator_uses_the_ranked_rule_and_the_record_validates():
    from tests.test_client_variants import _record as variant_record
    r = variant_record("curl")
    prev, prev_w = [None] * 12 + [20.0] * 7, [None] * 12 + ["v6"] * 7
    r["adaptive"] = o.adaptive_block(prev, r, 20, 50, 25.0, 0.3, prev_w)
    st = r["adaptive"]["after_this_run"]
    assert r["adaptive"]["failed_runs"] == FAILED_RANKED and st["failed_runs"] == FAILED_RANKED
    assert st["ci"]["unbounded"] and st["median_ms"] is None and st["decision"] == "continue"
    assert validate(r) == []
    st["win"]["outcomes"]["none"]["n"] -= 1                                     # a dropped run is refused
    assert any("no run may be dropped" in e for e in validate(r))


def test_summary_line_carries_the_caveat_when_a_run_had_no_winner():
    st = adaptive_decision([20.0] * 19 + [None], 20, 50, 25.0, winners=["v6"] * 19 + [None], failed_runs=FAILED_RANKED)
    line = o.adaptive_summary_line("Gv6c30", st, 0.3)
    assert "no winner 1" in line and "CAVEAT" in line and "ranked highest" in line
    st = adaptive_decision([20.0] * 20, 20, 50, 25.0, winners=["v6"] * 20, failed_runs=FAILED_RANKED)
    assert "CAVEAT" not in o.adaptive_summary_line("Gv6c30", st, 0.3)


def test_caveat_states_the_runner_limits_actually_set():
    from runner import client_chromium
    from runner.clients import CURL_MAX_TIME_S, curl_argv
    argv = curl_argv()
    assert argv[argv.index("--max-time") + 1] == str(CURL_MAX_TIME_S)
    assert f"curl --max-time {CURL_MAX_TIME_S} s" in FAILURE_RATE_CAVEAT
    assert f"navigation timeout {client_chromium.NAV_TIMEOUT_MS // 1000} s" in FAILURE_RATE_CAVEAT


def test_analysis_keeps_a_no_winner_run_and_says_why_rates_differ(tmp_path):
    lost = [(T0, g.ip_tcp(g.C6, g.S6, 42000, 80, g.SYN, seq=1))]                # nothing answered
    recs = [_record(tmp_path, 1, _retransmitted_v6(T0), "v6", 1020.0),
            _record(tmp_path, 2, lost, None, None)]
    recs[1]["packet_observations"]["winning_family"] = {"status": "not_observed", "value": None}
    recs[1]["metrics"]["tcp_setup_time_ms"] = {"status": "not_observed", "value": None}
    c = sr.analyse_cell(recs, repo=tmp_path)
    assert c["win"]["none"]["wins"] == 1 and c["n_runs"] == 2 and c["runs_without_setup_time"] == 1
    assert c["median_all_runs_ms"] is None                                       # 1 of 2 runs has no value
    text = sr.report([c])
    assert "no winner 1/2" in text and "CAVEAT" in text


CAMPAIGN = ",".join(f"{s}:{c}" for s in ("Gv6l10", "Gv6l30", "Gv6l50", "Gv6j50", "Gv6j70", "Gv6d200", "Gv6d280",
                                         "Gv6c30") for c in ("curl", "chromium"))


def test_run_matrix_runs_an_only_list_in_order():
    from runner import run_matrix as rm
    todo = rm.select(rm.PLAN, 1, CAMPAIGN)
    assert [n for n, _, _ in todo] == list(range(1, 17))
    assert todo[0][1:] == ("Gv6l10", "curl") and todo[-1][1:] == ("Gv6c30", "chromium")
    assert rm.select(rm.PLAN, 1, "Gv6l10:curl,Gv6nope:curl") == []
    assert rm.select(rm.PLAN, 1, "Gv6l10:curl,Gv6l10:curl") == []
    assert rm.select(rm.PLAN, 1, "Gv6d200:curl") == [(0, "Gv6d200", "curl")]      # single extra: unchanged


def test_run_matrix_resume_command_keeps_the_settings():
    from runner import run_matrix as rm
    todo = rm.select(rm.PLAN, 1, CAMPAIGN)
    args = ["--only", CAMPAIGN, "--reps-adaptive", "20", "50", "--ci-width-ms", "25", "--win-ci-width", "0.3"]
    cmd = rm.resume_command(todo, 14, True, args)
    assert cmd == ("sudo .venv/bin/python src/runner/run_matrix.py --only Gv6c30:curl,Gv6c30:chromium "
                   "--reps-adaptive 20 50 --ci-width-ms 25 --win-ci-width 0.3")
    assert rm.resume_command(todo, 16, True, args) == "(nothing left in the --only list)"
    assert rm.resume_command(rm.select(rm.PLAN), 3, False, []).endswith("--from 4")


def test_run_matrix_dry_run_of_the_campaign(capsys):
    from runner import run_matrix as rm
    assert rm.main(["--dry-run", "--only", CAMPAIGN, "--reps-adaptive", "20", "50", "--ci-width-ms", "25",
                    "--win-ci-width", "0.3"]) == 0
    out = capsys.readouterr().out
    assert "16 batches from the --only list" in out and out.count("--win-ci-width 0.3") == 16


# --- jitter win-fraction model (analysis/jitter_model.py) ---------------------------------------

def test_jitter_model_prediction_is_phi_of_standardised_crossover():
    from analysis import jitter_model as jm
    assert jm.predict(220.0, 220.0, 70.0) == pytest.approx(0.5)
    assert jm.predict(320.0, 220.0, 100.0) == pytest.approx(0.8413, abs=1e-4)   # one SD above the mean
    assert jm.predict(220.0, 300.0, 99.0) < 0.25


def test_jitter_model_twin_bracket_can_be_open():
    from analysis import jitter_model as jm
    curl = [{"rtt_ms": 221, "n": 20, "v6_wins": 20}, {"rtt_ms": 301, "n": 20, "v6_wins": 0}]
    chromium = [{"rtt_ms": 221, "n": 20, "v6_wins": 20}, {"rtt_ms": 301, "n": 20, "v6_wins": 20}]
    assert jm.twin_bracket(curl) == {"above_ms": 221, "below_ms": 301}
    assert jm.twin_bracket(chromium) == {"above_ms": 301, "below_ms": None}   # IPv4 never won: no upper bound


def test_jitter_model_crossover_from_ipv4_synack_in_packets(tmp_path):
    from analysis import jitter_model as jm
    # v6 SYN at T0 answered after 300 ms; v4 SYN 200 ms in, SYN-ACK 21 ms later: crossover 221 ms
    frames = sorted([(T0, g.ip_tcp(g.C6, g.S6, 40010, 80, g.SYN, seq=1))]
                    + [(T0 + 300 * MS, g.ip_tcp(g.S6, g.C6, 80, 40010, g.SYN | g.ACK, seq=9, ack=2))]
                    + g.handshake(T0 + 200 * MS, g.C4, g.S4, 40012, rtt_ms=21), key=lambda f: f[0])
    rec = _record(tmp_path, 1, frames, "v4", 221.03)
    assert jm.v4_synack_ms(rec, repo=tmp_path) == 221.0
    assert not jm.won_by_later_v6_attempt(rec, repo=tmp_path)
    rec6 = _record(tmp_path, 2, _v4_fallback(T0 + 5000 * MS), "v4", 220.03)
    assert jm.v4_synack_ms(rec6, repo=tmp_path) == 220.0


def test_jitter_model_outcome_bracket_only_corroborates_the_measured_crossover():
    from analysis import jitter_model as jm
    assert jm._in_bracket(222.0, {"above_ms": 221, "below_ms": 301})
    assert jm._in_bracket(322.5, {"above_ms": 301, "below_ms": None})
    assert not jm._in_bracket(310.0, {"above_ms": 221, "below_ms": 301})
