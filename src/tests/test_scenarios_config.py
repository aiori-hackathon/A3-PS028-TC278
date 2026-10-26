"""Structure checks for src/config/scenarios.yaml."""

from pathlib import Path

import pytest
import yaml

CONFIG = Path(__file__).resolve().parents[1] / "config" / "scenarios.yaml"


@pytest.fixture(scope="module")
def cfg():
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


def test_has_c0_and_s1(cfg):
    assert cfg["schema_version"] == 1
    assert {"C0", "S1"} <= set(cfg["scenarios"])


def test_every_scenario_is_well_formed(cfg):
    for sid, sc in cfg["scenarios"].items():
        assert isinstance(sc["label"], str) and sc["label"], sid
        for fam in ("v4", "v6"):
            link = sc[fam]
            assert isinstance(link["delay_ms_each_way"], int) and link["delay_ms_each_way"] >= 0, sid
            assert 0 <= link["loss_pct"] <= 100, sid
            target = sc["verify_target"][fam]
            if link["loss_pct"] == 100:
                assert target == "blackhole", sid
            else:
                assert target == 2 * link["delay_ms_each_way"], f"{sid} {fam}: target != configured RTT"
        assert set(sc["dns"]["delay_ms"]) <= {"A", "AAAA"}, sid
        assert all(isinstance(v, int) and v >= 0 for v in sc["dns"]["delay_ms"].values()), sid


def test_c0_is_the_baseline(cfg):
    base = cfg["baseline"]["delay_ms_each_way"]
    c0 = cfg["scenarios"]["C0"]
    assert c0["v4"] == c0["v6"] == {"delay_ms_each_way": base, "loss_pct": 0}
    assert c0["dns"]["delay_ms"] == {"A": 0, "AAAA": 0}


def test_s1_blackholes_only_ipv6(cfg):
    s1, base = cfg["scenarios"]["S1"], cfg["scenarios"]["C0"]
    assert s1["v6"]["loss_pct"] == 100
    assert s1["v4"] == base["v4"] and s1["dns"] == base["dns"]


@pytest.mark.parametrize("sid,fam,extra_rtt", [("S2", "v6", 600), ("S3", "v6", 150), ("S5", "v4", 600)])
def test_added_rtt_is_split_equally_on_one_family(cfg, sid, fam, extra_rtt):
    base, sc = cfg["baseline"], cfg["scenarios"][sid]
    other = "v4" if fam == "v6" else "v6"
    assert sc[fam] == {"delay_ms_each_way": base["delay_ms_each_way"] + extra_rtt // 2, "loss_pct": 0}
    assert sc["verify_target"][fam] == base["rtt_ms"] + extra_rtt
    assert sc[other] == cfg["scenarios"]["C0"][other] and sc["dns"] == cfg["scenarios"]["C0"]["dns"]


def test_s4_blackholes_only_ipv4(cfg):
    s4, c0 = cfg["scenarios"]["S4"], cfg["scenarios"]["C0"]
    assert s4["v4"]["loss_pct"] == 100 and s4["verify_target"]["v4"] == "blackhole"
    assert s4["v6"] == c0["v6"] and s4["dns"] == c0["dns"]


def test_s6_delays_only_aaaa(cfg):
    s6, c0 = cfg["scenarios"]["S6"], cfg["scenarios"]["C0"]
    assert s6["dns"]["delay_ms"] == {"A": 0, "AAAA": 300}
    assert s6["v4"] == c0["v4"] and s6["v6"] == c0["v6"]


def test_x1_not_defined_yet(cfg):
    assert "X1" not in cfg["scenarios"]
