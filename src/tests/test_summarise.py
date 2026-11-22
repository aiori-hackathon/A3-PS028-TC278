import json
from pathlib import Path

import pytest

from analysis import summarise as sm

FIX = Path(__file__).resolve().parent / "fixtures"
REPO = Path(__file__).resolve().parents[2]
MS = 1_000_000


def _computed(v):
    return {"value": v, "status": "computed"}


def _not_observed():
    return {"value": None, "status": "not_observed"}


def make_record(session, client, scenario, rep, families=("v6",), offsets_ms=(0,), winner_idx=0,
                setup_ms=20.0, dns_ms=1.0, jobs=None, resolved=None, cross="agree"):
    t0 = 1_000 * MS
    attempts = [{"family": f, "dst": "x", "src_port": 40000 + i, "first_syn_ns": t0 + int(o * MS),
                 "syn_retransmits": 0, "result": "won" if i == winner_idx else "abandoned"}
                for i, (f, o) in enumerate(zip(families, offsets_ms))]
    fams = [a["family"] for a in attempts]
    if len(set(fams)) > 1:
        second = next(a for a in attempts if a["family"] != fams[0])
        inter = _computed((second["first_syn_ns"] - t0) / MS)
    else:
        inter = _not_observed()
    report = {}
    if jobs is not None:
        report["connect_jobs"] = jobs
    if resolved is not None:
        report["resolved"] = {"families": resolved}
    return {
        "run_id": f"{session}_{scenario}_{client}_r{rep:02d}",
        "client": {"name": client},
        "scenario": {"id": scenario, "repetition": rep},
        "environment": {"session_id": session},
        "outcome": {"success": True, "client_report": report},
        "packet_observations": {"winning_family": _computed(families[winner_idx]),
                                "attempts": _computed(attempts),
                                "failed_or_abandoned_attempts": _computed(len(attempts) - 1)},
        "metrics": {"tcp_setup_time_ms": _computed(setup_ms), "inter_family_attempt_delay_ms": inter,
                    "dns_time_ms": _computed(dns_ms)},
        "cross_checks": {"status": cross},
        "evidence": {"pre_verify_ok": True, "post_restore_verify_ok": True},
    }


def write(runs_dir, records):
    runs_dir.mkdir(exist_ok=True)
    for r in records:
        (runs_dir / f"{r['run_id']}.json").write_text(json.dumps(r))


CHROMIUM_S1_JOBS = [
    {"t_ms": 0, "job": 1, "backup_job": False, "connector": "first", "address": "[2001:db8:28:6::2]:80"},
    {"t_ms": 250, "job": 2, "backup_job": True, "connector": "first", "address": "[2001:db8:28:6::2]:80"},
    {"t_ms": 301, "job": 1, "backup_job": False, "connector": "second", "address": "192.0.2.2:80"},
]


# --- dataset selection -------------------------------------------------------------------

def test_dataset_doc_lists_the_14_matrix_sessions_only():
    rows = sm.dataset_sessions(REPO / "docs" / "dataset.md")
    assert len(rows) == 14
    assert ("curl", "C0", "20261026T192045Z") in rows
    sessions = {sid for _, _, sid in rows}
    assert "20261026T190919Z" not in sessions          # repeatability check, not pooled
    assert not sessions & {"20261026T064544Z", "20261026T074423Z", "20261026T123827Z",
                           "20261026T125239Z", "20261026T181302Z", "20261026T182411Z"}  # pilots


def test_dataset_doc_with_a_missing_cell_is_refused(tmp_path):
    text = (REPO / "docs" / "dataset.md").read_text()
    doc = tmp_path / "dataset.md"
    doc.write_text("\n".join(line for line in text.splitlines() if "| chromium | S6 |" not in line))
    with pytest.raises(sm.DatasetError, match="14"):
        sm.dataset_sessions(doc)


def test_load_runs_reads_listed_sessions_and_ignores_others(tmp_path):
    runs = tmp_path / "runs"
    write(runs, [make_record("A", "curl", "C0", i) for i in (1, 2)]
          + [make_record("PILOT", "curl", "C0", i, setup_ms=999) for i in (1, 2, 3)])
    loaded = sm.load_runs([("curl", "C0", "A")], runs, expected=2, repo=None)
    assert [r.setup_ms for r in loaded] == [20.0, 20.0]


@pytest.mark.parametrize("records, message", [
    ([make_record("A", "curl", "C0", 1)], "1 records, expected 2"),
    ([make_record("A", "curl", "C0", 1), make_record("A", "curl", "C0", 1, setup_ms=21)], "repetitions"),
    ([make_record("A", "curl", "C0", 1), make_record("A", "curl", "C0", 2, cross="conflict")], "cross_checks"),
    ([make_record("A", "curl", "C0", 1), make_record("A", "chromium", "C0", 2)], "not curl/C0"),
])
def test_load_runs_refuses_an_incomplete_or_unclean_session(tmp_path, records, message):
    runs = tmp_path / "runs"
    for i, r in enumerate(records):
        r["run_id"] += f"_{i}"
    write(runs, records)
    with pytest.raises(sm.DatasetError, match=message):
        sm.load_runs([("curl", "C0", "A")], runs, expected=2, repo=None)


def _with_commit(record, commit):
    record["environment"]["git_commit"] = commit
    return record


def test_load_runs_refuses_a_session_with_a_dirty_record(tmp_path):
    runs = tmp_path / "runs"
    write(runs, [_with_commit(make_record("A", "curl", "C0", 1), "c283448"),
                 _with_commit(make_record("A", "curl", "C0", 2), "c283448-dirty")])
    with pytest.raises(sm.DatasetError, match=r"A_C0_curl_r02 code version is -dirty"):
        sm.load_runs([("curl", "C0", "A")], runs, expected=2, repo=None)


def test_load_runs_accepts_clean_commits_and_ignores_dirty_records_outside_the_dataset(tmp_path):
    runs = tmp_path / "runs"
    write(runs, [_with_commit(make_record("A", "curl", "C0", 1), "c283448"),
                 _with_commit(make_record("A", "curl", "C0", 2), "dirty00"),       # only a -dirty suffix counts
                 _with_commit(make_record("PILOT", "curl", "C0", 1), "c283448-dirty")])
    assert len(sm.load_runs([("curl", "C0", "A")], runs, expected=2, repo=None)) == 2


# --- attempt shapes ----------------------------------------------------------------------

def test_chromium_two_v6_attempts_are_first_same_family_other_family():
    rec = make_record("A", "chromium", "S1", 1, families=("v6", "v6", "v4"), offsets_ms=(0, 250.6, 301.1),
                      winner_idx=2, setup_ms=322.0, jobs=CHROMIUM_S1_JOBS)
    run = sm.run_from_record(rec)
    assert [a["kind"] for a in run.attempts] == ["first", "same-family", "other-family"]
    assert run.shape == "v6>v6>v4"
    assert run.failed_or_abandoned == 2
    assert run.inter_family_ms == pytest.approx(301.1)   # the backup v6 does not count as the second family
    assert run.netlog_backup_jobs == 1
    assert run.netlog_v4_source == "original job, second connector"


def test_cell_keeps_chromium_and_curl_shapes_apart():
    ch = [sm.run_from_record(make_record("A", "chromium", "S1", i, families=("v6", "v6", "v4"),
                                         offsets_ms=(0, 250 + i, 301), winner_idx=2, jobs=CHROMIUM_S1_JOBS))
          for i in (1, 2, 3)]
    cu = [sm.run_from_record(make_record("B", "curl", "S1", i, families=("v6", "v4"), offsets_ms=(0, 200),
                                         winner_idx=1)) for i in (1, 2, 3)]
    c, u = sm.summarise_cell(ch), sm.summarise_cell(cu)
    assert c["failed_or_abandoned_per_run"] == {"2": 3} and c["failed_or_abandoned_total"] == 6
    assert u["failed_or_abandoned_per_run"] == {"1": 3} and u["failed_or_abandoned_total"] == 3
    assert c["attempt_shape"] == {"v6>v6>v4": 3} and u["attempt_shape"] == {"v6>v4": 3}
    assert set(c["attempt_offsets_ms"]) == {"same-family (v6)", "other-family (v4)"}
    assert set(u["attempt_offsets_ms"]) == {"other-family (v4)"}
    assert c["attempt_offsets_ms"]["same-family (v6)"]["median"] == 252
    assert c["inter_family"]["stats_over_observed_only"]["median"] == 301
    assert c["netlog"]["runs_with_backup_job"] == 3 and u["netlog"] is None


# --- not observed is a count -------------------------------------------------------------

def test_inter_family_all_not_observed_is_a_count_without_statistics():
    cell = sm.summarise_cell([sm.run_from_record(make_record("A", "curl", "C0", i)) for i in (1, 2, 3)])
    assert cell["inter_family"] == {"observed": 0, "not_observed": 3, "other_status": 0,
                                    "stats_over_observed_only": None}


def test_inter_family_statistics_use_observed_runs_only():
    runs = [sm.run_from_record(make_record("A", "curl", "S1", 1, families=("v6", "v4"), offsets_ms=(0, 200),
                                           winner_idx=1)),
            sm.run_from_record(make_record("A", "curl", "S1", 2))]
    inter = sm.summarise_cell(runs)["inter_family"]
    assert (inter["observed"], inter["not_observed"]) == (1, 1)
    assert inter["stats_over_observed_only"]["median"] == 200      # not (200 + 0) / 2


# --- penalty -----------------------------------------------------------------------------

def test_penalty_is_against_the_same_clients_c0():
    recs = ([make_record("a", "curl", "C0", 1, setup_ms=20.0), make_record("b", "curl", "S3", 1, setup_ms=170.0),
             make_record("c", "chromium", "C0", 1, setup_ms=30.0),
             make_record("d", "chromium", "S3", 1, setup_ms=170.0)])
    runs = [sm.run_from_record(r) for r in recs]
    cells = sm.summarise(runs)["cells"]
    assert cells["curl"]["S3"]["scenario_penalty_ms"] == pytest.approx(150.0)
    assert cells["chromium"]["S3"]["scenario_penalty_ms"] == pytest.approx(140.0)
    assert cells["curl"]["C0"]["scenario_penalty_ms"] == pytest.approx(0.0)


# --- helpers -----------------------------------------------------------------------------

def test_netlog_v4_source_variants():
    assert sm.netlog_v4_source(None) is None
    assert sm.netlog_v4_source(CHROMIUM_S1_JOBS[:1]) == "no IPv4 connect"
    assert sm.netlog_v4_source([dict(CHROMIUM_S1_JOBS[2], backup_job=True)]) == "backup job, second connector"


def test_dns_by_type_on_the_s1_fixture():
    answers, first_syn, after_a = sm.dns_by_type(FIX / "s1_manual_curl.pcap", None)
    assert {"A", "AAAA"} <= set(answers)
    assert first_syn is not None and first_syn >= max(answers["A"], answers["AAAA"])
    # first SYN minus the first A answer, from raw timestamps: equal to the rounded difference within 1 µs
    assert after_a is not None and after_a > 0
    assert abs(after_a - (first_syn - answers["A"])) <= 0.0015


def _s6_like_pcap(path, a_ms, aaaa_ms, syn_ms):
    """A and AAAA queried together at t0; answers and an IPv6 handshake at the given offsets."""
    from tests import pcapgen as g
    t0, c, s = 1_800_000_000 * 1_000_000_000, "198.51.100.1", "198.51.100.53"
    qa, q6 = g.dns_query(1, "www.hl.test", "A"), g.dns_query(2, "www.hl.test", "AAAA")
    frames = [(t0, g.ip_udp(c, s, 5000, 53, qa)), (t0 + 40_000, g.ip_udp(c, s, 5000, 53, q6)),
              (t0 + int(a_ms * g.MS), g.ip_udp(s, c, 53, 5000, g.dns_reply(qa, g.S4))),
              (t0 + int(aaaa_ms * g.MS), g.ip_udp(s, c, 53, 5000, g.dns_reply(q6, g.S6)))]
    frames += g.handshake(t0 + int(syn_ms * g.MS), g.C6, g.S6, 40000)
    path.write_bytes(g.pcap(sorted(frames, key=lambda f: f[0]), nanosecond=True))
    return path


def test_dns_by_type_first_syn_after_the_a_answer(tmp_path):
    pcap = _s6_like_pcap(tmp_path / "s6.pcap", a_ms=1.0, aaaa_ms=302.0, syn_ms=302.75)
    answers, first_syn, after_a = sm.dns_by_type(pcap, None)
    assert answers == {"A": 1.0, "AAAA": 302.0}
    assert first_syn == 302.75
    assert after_a == 301.75                     # SYN at 302.75 ms minus the A answer at 1.0 ms


def test_dns_by_type_without_target_queries_returns_nothing(tmp_path):
    from tests import pcapgen as g
    pcap = tmp_path / "no_dns.pcap"
    pcap.write_bytes(g.pcap(g.handshake(1_800_000_000 * 1_000_000_000, g.C6, g.S6, 40000)))
    assert sm.dns_by_type(pcap, None) == ({}, None, None)


# --- dashboard ---------------------------------------------------------------------------

def test_dashboard_renders_every_section_and_keeps_not_observed_as_counts():
    dashboard = pytest.importorskip("analysis.dashboard")
    recs = []
    for c in sm.CLIENTS:
        for s in sm.SCENARIOS:
            if s in ("S1", "S2"):
                fams, offs = (("v6", "v6", "v4"), (0, 250, 301)) if c == "chromium" else (("v6", "v4"), (0, 200))
                recs.append(make_record(s + c, c, s, 1, families=fams, offsets_ms=offs, winner_idx=len(fams) - 1,
                                        jobs=CHROMIUM_S1_JOBS if c == "chromium" else None))
            else:
                recs.append(make_record(s + c, c, s, 1, resolved=["v6", "v4"] if c == "chromium" else None))
    runs = [sm.run_from_record(r) for r in recs]
    summary = sm.summarise(runs)
    summary["dataset"] = {"source": "docs/dataset.md", "runs": len(runs), "sessions": [],
                          "clients": {c: {"versions": ["x 1.0"], "configs": [{}], "code_versions": ["abc"]}
                                      for c in sm.CLIENTS}}
    page = dashboard.render(summary, runs, "")
    for id_ in ("setup", "penalty", "timeline", "inter", "winner", "dns"):
        assert f"id={id_} " in page
    assert "curl: not observed \\u00d71" in page and "Interpretation" in page
    assert "observed 0, not observed 1" in page
