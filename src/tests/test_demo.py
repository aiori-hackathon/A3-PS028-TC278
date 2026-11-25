"""make demo and make demo-check: demo runs stay out of every dataset; the read-back is right; the scripts are safe.

No sudo, no lab: the scripts are checked statically, the read-back on the committed example runs.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from analysis import demo_report as d
from analysis import summarise
from analysis import summary_fingerprint as fp
from analysis.validate_record import validate
from runner import orchestrate as o

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples"
S1_CURL = "20261026T193106Z_S1_curl_r08"
C0_CURL = "20261026T192159Z_C0_curl_r07"
S1_CHROMIUM = "20261026T193420Z_S1_chromium_r01"
DEMO_SH = REPO / "scripts" / "demo.sh"
CHECK_SH = REPO / "scripts" / "demo_check.sh"
NOW = datetime(2026, 11, 26, 9, 30, 0, tzinfo=timezone.utc)


def _example(run_id: str) -> dict:
    return json.loads((EXAMPLES / f"{run_id}.json").read_text(encoding="utf-8"))


def _as_demo(rec: dict) -> dict:
    rec = copy.deepcopy(rec)
    rec["environment"]["session_id"] = "demo-" + rec["environment"]["session_id"]
    rec["environment"]["purpose"] = o.DEMO_PURPOSE
    return rec


# --- isolation: where demo runs go, and that no manifest can name them -----------------------------

def test_demo_tree_is_one_place_and_shared_by_writer_and_reader():
    assert o.DEMO_ROOT == d.DEMO_ROOT == REPO / "data" / "demo"
    assert o.DEMO_SESSION_PREFIX == d.DEMO_SESSION_PREFIX == "demo-"


def test_demo_session_writes_nowhere_the_measurement_tree_or_any_reader_looks():
    demo, normal = o.session_dirs(demo=True), o.session_dirs(demo=False)
    assert set(demo) == set(normal)
    measured = [*normal.values(), summarise.RUNS_DIR, summarise.LAB_DIR, summarise.OUT_DIR, REPO / "captures"]
    for path in demo.values():
        assert path.is_relative_to(o.DEMO_ROOT)
        for m in measured:
            assert not path.is_relative_to(m) and not m.is_relative_to(path), (path, m)
    assert normal["runs"] == summarise.RUNS_DIR and normal["captures"] == REPO / "captures"


def test_demo_tree_is_gitignored():
    r = subprocess.run(["git", "-C", str(REPO), "check-ignore", "-q", "data/demo/runs/x.json"])
    assert r.returncode == 0


def test_a_demo_session_id_cannot_be_listed_in_any_manifest():
    row = "| 1 | curl | S1 | `{}` | 20 |"
    demo_id, normal_id = o.new_session_id(NOW, demo=True), o.new_session_id(NOW, demo=False)
    assert demo_id == "demo-20261126T093000Z" and normal_id == "20261126T093000Z"
    assert summarise._row_re().match(row.format(normal_id))
    assert not summarise._row_re().match(row.format(demo_id))
    # and the manifest reader refuses a numbered row it cannot parse rather than skipping it
    assert summarise._ROW_LIKE_RE.match(row.format(demo_id))


def test_demo_record_still_validates_with_its_purpose():
    rec = _as_demo(_example(S1_CURL))
    assert validate(rec) == []


@pytest.mark.parametrize("argv", [
    ["--scenario", "S1", "S4"], ["--scenario", "S1", "--reps", "2"], ["--scenario", "S1", "--first-rep", "3"],
    ["--scenario", "S1", "--reps-adaptive", "1", "3", "--ci-width-ms", "1"],
])
def test_demo_mode_is_exactly_one_run(argv):
    with pytest.raises(SystemExit):
        o.main(["--demo", "--dry-run", *argv])


def test_demo_dry_run_names_only_demo_paths(capsys):
    assert o.main(["--demo", "--dry-run", "--scenario", "S1"]) == 0
    out = capsys.readouterr().out
    assert "data/demo/runs/" in out and "data/demo/captures/" in out and "demo session: ID demo-" in out
    assert "data/generated" not in out and "/captures/" not in out.replace("data/demo/captures/", "")


def test_demo_progress_never_raises_on_a_closed_stdout(monkeypatch):
    def broken(*a, **k):
        raise BrokenPipeError
    monkeypatch.setattr("builtins.print", broken)
    o._demo_say("restoring the baseline")   # must not raise: clean-up calls it


def test_rtt_said_reads_the_verify_lines():
    rtt = o.parse_verify_rtt(
        "PASS RTT v4 median_ms=21.00 min_ms=20.1 max_ms=22.6 loss_pct=0 sent=10 received=10 errors=0 target_ms=20 PASS\n"
        "PASS RTT v6 median_ms=NA min_ms=NA max_ms=NA loss_pct=100 sent=10 received=0 errors=0 target=blackhole PASS\n")
    assert o.rtt_said(rtt, {"v4": 20, "v6": "blackhole"}) == \
        "measured RTT: IPv4 21.00 ms, IPv6 blackhole (100% loss, 0 ICMP errors)"


# --- the read-back ------------------------------------------------------------------------------------

def test_reader_refuses_a_record_that_is_not_a_demo_run(tmp_path):
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / f"{S1_CURL}.json").write_text(json.dumps(_example(S1_CURL)), encoding="utf-8")
    with pytest.raises(d.DemoError, match="not a demo record"):
        d.load_demo_record(S1_CURL, tmp_path)
    (tmp_path / "runs" / f"{S1_CURL}.json").write_text(json.dumps(_as_demo(_example(S1_CURL))), encoding="utf-8")
    assert d.load_demo_record(S1_CURL, tmp_path)["run_id"] == S1_CURL
    with pytest.raises(d.DemoError, match="not a run ID"):
        d.load_demo_record("../generated/runs/x", tmp_path)


def test_numbers_for_s1_curl_come_from_the_record():
    rec = _example(S1_CURL)
    n = d.numbers(rec)
    att = sorted(rec["packet_observations"]["attempts"]["value"], key=lambda a: a["first_syn_ns"])
    assert n["winner"] == rec["packet_observations"]["winning_family"]["value"] == "v4"
    assert n["first_syn_ms"]["v6"] == 0.0
    assert n["first_syn_ms"]["v4"] == round((att[1]["first_syn_ns"] - att[0]["first_syn_ns"]) / 1e6, 3)
    assert n["inter_family_ms"] == rec["metrics"]["inter_family_attempt_delay_ms"]["value"]
    assert n["setup_ms"] == rec["metrics"]["tcp_setup_time_ms"]["value"]
    assert n["oracle_ms"] == rec["scenario"]["measured_rtt_ms"]["v4"]["value"]
    assert n["cost_ms"] == pytest.approx(n["setup_ms"] - n["oracle_ms"], abs=0.001)


def test_numbers_for_a_single_family_run_say_not_observed():
    n = d.numbers(_example(C0_CURL))
    assert n["winner"] == "v6" and set(n["first_syn_ms"]) == {"v6"}
    assert n["inter_family_ms"] is None and n["inter_family_status"] == "not_observed"
    text = "\n".join(d.report_lines(n, large=False))
    assert "INTER-FAMILY ATTEMPT DELAY  not observed" in text
    assert "no race took place" in text


def test_report_labels_every_number_with_its_evidence_level():
    text = "\n".join(d.report_lines(d.numbers(_example(S1_CHROMIUM)), large=True, width=120))
    for label, tag in [("WINNING FAMILY", "Packet-level (pcap)"), ("FIRST SYN, IPv6", "Packet-level (pcap)"),
                       ("FIRST SYN, IPv4", "Packet-level (pcap)"), ("INTER-FAMILY ATTEMPT DELAY", "Packet-level (pcap)"),
                       ("TCP SETUP TIME", "Packet-level (pcap)"), ("ORACLE", "Derived (pcap − lab RTT)"),
                       ("COST OF RACING", "Derived (pcap − lab RTT)")]:
        line = next(x for x in text.splitlines() if x.strip().startswith(label + " "))
        assert tag in line, line
    assert "not part of any dataset" in text and "Interpretation (labelled)" in text


def test_s6_reports_dns_time_alongside_setup():
    n = dict(d.numbers(_example(S1_CURL)), scenario="S6", dns_ms=301.5)
    text = "\n".join(d.report_lines(n, large=False))
    assert "TCP SETUP TIME" in text and "DNS TIME  301.50 ms" in text


def test_conflicts_and_failed_verifies_are_flagged_not_hidden():
    n = dict(d.numbers(_example(S1_CURL)), cross_checks="conflict", verify_ok=False)
    text = "\n".join(d.report_lines(n, large=False))
    assert "do not quote these numbers" in text and "lab verify did not pass" in text


def test_large_digits():
    rows = d.big("200.96")
    assert len(rows) == 3 and all(set(r) <= set(" ▀▄█") for r in rows)
    assert d.big("IPv4") and d.big("−0.12")
    assert d.big("not observed") is None and d.big("") is None
    # falls back to one line when the terminal is too narrow for the digits
    narrow = d.report_lines(d.numbers(_example(S1_CURL)), large=True, width=20)
    assert not any("█" in x for x in narrow)


def test_two_decimals_and_a_true_minus():
    assert d.fmt_ms(221.8449) == "221.84" and d.fmt_ms(-0.126) == "−0.13" and d.fmt_ms(None) == "–"


def test_timeline_page_is_the_dashboards_race_view_for_one_run(tmp_path):
    from analysis import race
    rec = _example(S1_CURL)
    pcap = EXAMPLES / f"{S1_CURL}.pcap"
    events = race.wire(pcap, rec, rows=True)
    page = d.write_page(rec, events, pcap, tmp_path)
    html = page.read_text(encoding="utf-8")
    assert page.name == f"{S1_CURL}.html"
    assert "Connection race timeline" in html and "not part of any dataset" in html
    start = html.index("const RACE = ") + len("const RACE = ")
    blob, _ = json.JSONDecoder().raw_decode(html, start)
    assert list(blob["runs"]) == [S1_CURL] and blob["default"] == S1_CURL
    assert blob["runs"][S1_CURL]["rows"], "the packet rows behind the chart are listed"
    assert blob["representative"] == {"S1": {"curl": None}}   # one run: never labelled "representative"
    # plotly.js is inlined, not loaded from a CDN: the page works without a network at the venue
    assert "<script src=" not in html


# --- the fingerprint -----------------------------------------------------------------------------------

def test_fingerprint_names_every_difference(tmp_path):
    (tmp_path / "data" / "generated" / "runs").mkdir(parents=True)
    rec = tmp_path / "data" / "generated" / "runs" / "a.json"
    rec.write_text("{}", encoding="utf-8")
    before = {"files": fp.file_hashes(tmp_path), "rebuilt": {"core": "x"}}
    assert fp.compare(before, copy.deepcopy(before)) == []
    rec.write_text('{"changed": 1}', encoding="utf-8")
    (tmp_path / "captures").mkdir()
    (tmp_path / "captures" / "new.pcap").write_bytes(b"\0")
    after = {"files": fp.file_hashes(tmp_path), "rebuilt": {"core": "y"}}
    assert fp.compare(before, after) == ["files: added captures/new.pcap", "files: changed data/generated/runs/a.json",
                                         "rebuilt: changed core"]


def test_fingerprint_leaves_out_the_demo_tree_and_covers_every_dataset():
    assert not any(t.startswith("data/demo") for t in fp.TREES)
    assert {"data/generated", "captures"} <= set(fp.TREES)
    names = fp.dataset_names()
    assert names[0] == "core" and len(names) == 5 and "README" not in names


# --- the scripts ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("script", [DEMO_SH, CHECK_SH])
def test_scripts_parse_and_are_strict(script):
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    assert "set -euo pipefail" in script.read_text(encoding="utf-8")
    assert script.stat().st_mode & 0o111


def _code(script: Path) -> list[str]:
    """The script's command lines: comments dropped, continuation lines joined, quoted text removed (so a
    message that mentions sudo is not mistaken for a sudo call)."""
    joined = script.read_text(encoding="utf-8").replace("\\\n", " ")
    lines = [x for x in joined.splitlines() if x.strip() and not x.lstrip().startswith("#")]
    return [re.sub(r"'[^']*'", "''", re.sub(r'"(?:[^"\\]|\\.)*"', '""', x)) for x in lines]


def test_demo_asks_for_sudo_once_and_never_again():
    calls = [x for x in _code(DEMO_SH) if re.search(r"\bsudo\b", x)]
    assert len(calls) > 10
    prompting = [x for x in calls if re.search(r"\bsudo\b(?! -n)", x)]
    assert len(prompting) == 1 and "sudo -v" in prompting[0] and "timeout --foreground" in prompting[0]
    assert "sudo -E" not in DEMO_SH.read_text(encoding="utf-8")


def test_every_lab_step_of_the_demo_has_a_time_limit():
    for x in _code(DEMO_SH):
        if re.search(r"\bsudo -n\b", x) and "sudo -n true" not in x:
            assert "run_step" in x or "timeout" in x, x


def test_demo_cleans_up_on_exit_and_ctrl_c():
    text = DEMO_SH.read_text(encoding="utf-8")
    assert "trap on_exit EXIT" in text and re.search(r"trap '.*exit 130' INT", text)
    assert "trap '' INT TERM" in text   # the clean-up itself cannot be interrupted
    for step in ("netem.sh\" v4", "netem.sh\" v6", "verify.sh\" up", "setup.sh\"", "teardown.sh\""):
        assert step in text[text.index("restore_lab() {"):text.index("interrupted=0")], step


def test_demo_check_changes_nothing():
    for x in _code(CHECK_SH):
        if re.search(r"\bsudo\b", x) and "command -v" not in x and "for t in" not in x:
            assert "sudo -n true" in x, x
        assert not re.search(r"^\s*(modprobe|ip (netns|link) (add|del)|tc qdisc|rm |mkdir |touch )", x), x
        assert "playwright install" not in x or "fail " in x
    assert "chrome --version" not in CHECK_SH.read_text(encoding="utf-8")   # not even the browser is launched


def test_demo_check_expects_the_recorded_client_versions():
    text = CHECK_SH.read_text(encoding="utf-8")
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    curl = re.search(r'EXPECT_CURL="([\d.]+)"', text).group(1)
    pw = re.search(r'EXPECT_PLAYWRIGHT="([\d.]+)"', text).group(1)
    chromium = re.search(r'EXPECT_CHROMIUM="([\d.]+)"', text).group(1)
    assert f"| curl | curl {curl} " in readme
    assert f"| Chromium | Chromium {chromium} via Playwright {pw} |" in readme


def test_make_targets_exist():
    mk = (REPO / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"^demo:\n\tSCENARIO=\$\(SCENARIO\) CLIENT=\$\(CLIENT\) scripts/demo.sh$", mk, re.M)
    assert re.search(r"^demo-check:\n\tscripts/demo_check.sh$", mk, re.M)
    assert "SCENARIO ?= S1" in mk and "CLIENT   ?= curl" in mk
    recipes = [x for x in mk.splitlines() if x.startswith("\t") and "scripts/demo.sh" in x]
    assert len(recipes) == 3   # demo, and twice in demo-isolation-check
