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
