"""Client variants (curl@he<N>): parsing, the '@' sanitisation rule, records, grouping and the control."""

import copy
import json
from datetime import datetime, timezone

import pytest

from analysis import check_batch as cb
from analysis import dashboard
from analysis import export_web
from analysis import summarise as sm
from analysis import variant_control as vc
from analysis.names import (InvalidName, client_sort_key, file_token, group_by_implementation,
                            label_from_file_token, label_of, parse_client)
from analysis.parse_pcap import parse
from analysis.validate_record import validate
from runner import orchestrate as o
from runner import run_matrix as rm
from runner.clients import CLIENTS, CURL_FORMAT, CurlClient, curl_argv, get_client
from tests.test_dataset_manifest import A, B, C, manifest
from tests.test_orchestrate import FIX, GOOD_SUMMARY, VERIFY_S1_OUTPUT
from tests.test_summarise import make_record, write

D = "20261101T130000Z"


# --- parsing ----------------------------------------------------------------------------------

@pytest.mark.parametrize("label, impl, variant, ms", [
    ("curl", "curl", None, None),
    ("chromium", "chromium", None, None),
    ("curl@he200", "curl", "he200", 200),
    ("curl@he1", "curl", "he1", 1),
    ("curl@he60000", "curl", "he60000", 60000),
])
def test_parse_client_accepts(label, impl, variant, ms):
    c = parse_client(label)
    assert (c.implementation, c.variant, c.he_timeout_ms, c.label) == (impl, variant, ms, label)


@pytest.mark.parametrize("label, msg", [
    ("chromium@he200", "chromium takes no variants"),
    ("firefox", "unknown client implementation"),
    ("curl@", "unknown variant"),
    ("curl@he", "unknown variant"),
    ("curl@he060", "unknown variant"),        # no leading zero: one spelling per value
    ("curl@he0", "unknown variant"),
    ("curl@he60001", "1-60000 ms"),
    ("curl@x200", "unknown variant"),
    ("curl@he200@he300", "unknown variant"),
    ("Curl", "unknown client implementation"),
])
def test_parse_client_rejects(label, msg):
    with pytest.raises(InvalidName, match=msg):
        parse_client(label)


# --- the sanitisation rule: '@' -> '-' in every file name ---------------------------------------

@pytest.mark.parametrize("label, token", [("curl", "curl"), ("chromium", "chromium"),
                                          ("curl@he200", "curl-he200"), ("curl@he1500", "curl-he1500")])
def test_file_token_replaces_at_and_round_trips(label, token):
    assert file_token(label) == token
    assert "@" not in token
    assert label_from_file_token(token) == label


@pytest.mark.parametrize("token", ["curl@he200", "curl-he", "chromium-he200", "curl_he200", "curl-he060"])
def test_label_from_file_token_rejects(token):
    with pytest.raises(InvalidName):
        label_from_file_token(token)


def test_run_id_and_every_file_named_after_it_use_the_token():
    start = datetime(2026, 11, 21, 10, 0, 0, tzinfo=timezone.utc)
    rid = o.make_run_id(start, "S1", 3, "curl@he200")
    assert rid == "20261121T100000Z_S1_curl-he200_r03"
    assert o.make_run_id(start, "S1", 3, "curl") == "20261121T100000Z_S1_curl_r03"   # unchanged
    assert CLIENTS["chromium"].netlog_path(FIX, rid) is not None   # netlogs are named after the run ID too


def test_dry_run_shows_the_flag_and_the_sanitised_names(capsys):
    assert o.main(["--client", "curl@he200", "--scenario", "S1", "--reps", "1", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "--happy-eyeballs-timeout-ms 200" in out
    assert "_S1_curl-he200_r01" in out and "curl@he200_r" not in out
    assert "captures/" in out and "@" not in out.split("captures/")[1].split()[0]


@pytest.mark.parametrize("bad", ["chromium@he200", "curl@he0", "wget"])
def test_orchestrator_cli_refuses_bad_clients(bad):
    with pytest.raises(SystemExit):
        o.main(["--client", bad, "--scenario", "S1", "--dry-run"])


def test_run_matrix_batch_log_uses_the_token_and_selects_extra_batches():
    assert rm.select(rm.PLAN, only="S1:curl@he200") == [(0, "S1", "curl@he200")]
    assert rm.select(rm.PLAN, only="S1:curl") == [(3, "S1", "curl")]            # a plan batch keeps its number
    assert rm.select(rm.PLAN, only="S1:chromium@he200") == []
    assert rm.select(rm.PLAN, only="S9:curl@he200") == []
    assert "--client curl@he200" in " ".join(rm.orchestrator_cmd("S1", "curl@he200"))


# --- the client: flag, argv and config ------------------------------------------------------------

def test_plain_curl_argv_and_config_are_unchanged():
    assert curl_argv() == ["curl", "-q", "-sS", "--noproxy", "*", "--max-time", "10",
                           "-o", "/dev/null", "-w", CURL_FORMAT, "http://www.hl.test/"]
    cfg = CLIENTS["curl"].config(["launcher"], {})
    assert cfg["happy_eyeballs_timeout_ms"] == "default (not set)" and "variant" not in cfg
    assert get_client("curl") is CLIENTS["curl"] and get_client("chromium") is CLIENTS["chromium"]


def test_variant_passes_the_flag_and_records_the_real_value():
    spec = get_client("curl@he200")
    argv = spec.argv()
    assert argv[:2] == ["curl", "-q"]                      # -q stays first
    i = argv.index("--happy-eyeballs-timeout-ms")
    assert argv[i + 1] == "200"
    cfg = spec.config(["launcher"], {})
    assert cfg["happy_eyeballs_timeout_ms"] == 200
    assert cfg["variant"] == "he200 (--happy-eyeballs-timeout-ms 200)"
    assert (spec.name, spec.variant, spec.label) == ("curl", "he200", "curl@he200")
    with pytest.raises(ValueError):
        CurlClient(parse_client("chromium"))


def _record(client="curl@he200"):
    sc = o.load_scenarios(["S1"])
    start = datetime(2026, 11, 21, 4, 21, 56, tzinfo=timezone.utc)
    return o.build_record(
        run_id=o.make_run_id(start, "S1", 1, client), scenario_id="S1", sc=sc["S1"], repetition=1,
        run_start=start, client_version="curl 8.5.0", argv=get_client(client).argv(), user="sr",
        environment={"kernel": "test"}, client_start_ns=1792989112200000000,
        client_end_ns=1792989112480000000, capture_start_ns=1792989112100000000,
        capture_end_ns=1792989113000000000, returncode=0, stdout="200|192.0.2.2|0.001807|0.222482|0.242880|2",
        stderr="", pre_rtt=o.parse_verify_rtt(VERIFY_S1_OUTPUT), pre_ok=True, post_ok=True,
        pcap_rel="captures/x.pcap", pcap_sha256="a" * 64, log_rel="data/generated/logs/x.log",
        timeline=parse(FIX / "s1_manual_curl.pcap"), capture_stats=o.parse_tcpdump_stats(GOOD_SUMMARY),
        client=client)


def test_variant_record_keeps_implementation_and_variant_apart_and_validates():
    r = _record()
    assert r["schema_version"] == "0.4"
    assert r["client"]["name"] == "curl" and r["client"]["variant"] == "he200"
    assert label_of(r["client"]) == "curl@he200"
    assert "_curl-he200_" in r["run_id"]
    assert validate(r) == []
    plain = _record("curl")
    assert "variant" not in plain["client"] and validate(plain) == []


@pytest.mark.parametrize("mutate, msg", [
    (lambda r: r["client"]["config"].update(happy_eyeballs_timeout_ms="default (not set)"), "must be 200"),
    (lambda r: r["client"].update(argv=curl_argv()), "needs exactly one '--happy-eyeballs-timeout-ms 200'"),
    (lambda r: r["client"].update(variant="he300"), "needs exactly one '--happy-eyeballs-timeout-ms 300'"),
    (lambda r: r["client"].update(name="chromium"), "chromium takes no variants"),
    (lambda r: r.update(run_id=r["run_id"].replace("curl-he200", "curl@he200")), "run_id: must look like"),
    (lambda r: r.update(run_id=r["run_id"].replace("curl-he200", "curl")), "run_id: client part"),
    (lambda r: r.update(schema_version="0.3"), "client: unexpected keys ['variant']"),
])
def test_validator_rejects_inconsistent_variant_records(mutate, msg):
    r = _record()
    mutate(r)
    assert any(msg in p for p in validate(r)), validate(r)


def test_validator_rejects_a_flag_on_plain_curl():
    r = _record("curl")
    r["client"]["argv"] = get_client("curl@he200").argv()
    assert any("client.variant is missing" in p for p in validate(r))


# --- grouping: variants sit under curl, they are not further clients ------------------------------

def test_group_by_implementation_and_order():
    labels = ["curl@he300", "chromium", "curl@he200", "curl"]
    assert sorted(labels, key=client_sort_key) == ["curl", "curl@he200", "curl@he300", "chromium"]
    assert group_by_implementation(labels) == {"curl": ["curl", "curl@he200", "curl@he300"],
                                               "chromium": ["chromium"]}


VARIANT = "clients: [curl@he200, curl]\nscenarios: [C0, S1]\nreps: 2\n"
VARIANT_ROWS = [("curl@he200", "C0", C), ("curl@he200", "S1", D), ("curl", "C0", A), ("curl", "S1", B)]


def variant_runs(tmp_path, v_s1=(221.0, 223.0)):
    runs = tmp_path / "runs"
    recs = []
    for sid, client, scn, setups in ((A, "curl", "C0", (20.0, 21.0)), (B, "curl", "S1", (221.0, 223.0)),
                                     (C, "curl@he200", "C0", (30.0, 31.0)), (D, "curl@he200", "S1", v_s1)):
        for i, ms in enumerate(setups, 1):
            r = make_record(sid, file_token(client), scn, i, setup_ms=ms)
            cn = parse_client(client)
            r["client"] = {"name": cn.implementation, **({"variant": cn.variant} if cn.variant else {}),
                           "version": "curl 8.5.0 (test)",
                           "config": get_client(client).config(["launcher"], {})}
            r["environment"]["kernel"] = "7.0.0-43-generic"
            recs.append(r)
    write(runs, recs)
    return runs


def test_manifest_with_a_variant_summarises_it_under_curl(tmp_path):
    m = sm.load_manifest(manifest(tmp_path, VARIANT, VARIANT_ROWS), require_header=True)
    _, runs, summary = sm.build(manifest=m, runs_dir=variant_runs(tmp_path), repo=None)
    assert list(summary["cells"]) == ["curl", "curl@he200"]           # the variant right after curl
    assert summary["dataset"]["implementations"] == {"curl": ["curl", "curl@he200"]}
    # a variant's penalty uses its own C0 (30.5), never plain curl's (20.5)
    assert summary["cells"]["curl@he200"]["S1"]["scenario_penalty_ms"] == pytest.approx(222.0 - 30.5)
    assert summary["cells"]["curl"]["S1"]["scenario_penalty_ms"] == pytest.approx(222.0 - 20.5)
    report = sm.text_report(summary)
    assert "curl@he200  (packet-level unless stated; a variant of curl, not another client" in report
    assert {r.client for r in runs} == {"curl", "curl@he200"}


def test_dashboard_lists_the_variant_under_curl(tmp_path):
    m = sm.load_manifest(manifest(tmp_path, VARIANT, VARIANT_ROWS), require_header=True)
    _, runs, summary = sm.build(manifest=m, runs_dir=variant_runs(tmp_path), repo=None)
    page = dashboard.render(summary, runs, "")
    assert "1 client implementation(s) (curl (HE timeout 200 ms): configuration variant(s) of curl" in page
    assert page.count("<h3>curl</h3>") == 1
    assert "<h4>curl (HE timeout 200 ms): a configuration of curl, not another client implementation</h4>" in page
    fig = dashboard.fig_setup(runs, ("curl", "curl@he200"), ("C0", "S1"))
    roles = [t["meta"]["role"] for t in fig["data"]]
    assert roles == ["curl", "curl"]                                    # same colour role as curl
    assert fig["data"][1]["marker"]["symbol"] == "triangle-up"
    assert fig["data"][0]["marker"]["symbol"] is None        # plain curl keeps the default points
    bars = dashboard.fig_penalty(summary["cells"])["data"]
    assert bars[1]["marker"]["pattern"]["shape"] == "/"


def test_unknown_client_label_in_a_manifest_is_refused(tmp_path):
    doc = manifest(tmp_path, "clients: [chromium@he200]\nscenarios: [S1]\nreps: 2\n", [("curl", "S1", B)])
    with pytest.raises(sm.DatasetError, match="chromium takes no variants"):
        sm.load_manifest(doc, require_header=True)


def test_web_export_refuses_variants():
    with pytest.raises(export_web.ExportError, match="curl and Chromium only"):
        export_web.export("", [("curl@he200", "S1", D)])


def test_check_batch_reads_the_token_back_as_the_label(tmp_path):
    rc, _, _ = cb.check_run("20261121T100000Z_S1_curl-he200_r01", "curl@he200", "S1", tmp_path, tmp_path, tmp_path)
    assert not any("not curl@he200/S1" in p for p in rc.problems)
    rc, _, _ = cb.check_run("20261121T100000Z_S1_curl_r01", "curl@he200", "S1", tmp_path, tmp_path, tmp_path)
    assert any("run is curl/S1, not curl@he200/S1" in p for p in rc.problems)


# --- validation control ---------------------------------------------------------------------------

def _side(name, values, kernel="7.0.0-43-generic"):
    return vc.side(name, values, [kernel] * len(values), ["curl 8.5.0"] * len(values), "S")


def test_control_reports_a_trivial_delta_when_cis_overlap():
    v = _side("curl@he200", [222.0, 222.2, 222.1, 222.3, 221.9])
    ref = _side("curl", [222.1, 222.0, 222.2, 222.3, 222.4])
    cmp = vc.compare(v, ref)
    assert cmp["delta_ms"] == pytest.approx(-0.1) and cmp["ci_overlap"] and cmp["non_trivial"] is False
    assert cmp["same_kernel"] and "LIMITATION" not in vc.report(v, [(ref, cmp)])


def test_control_flags_a_non_trivial_delta_and_proposes_a_limitation_without_adjusting():
    v = _side("curl@he200", [225.0, 225.1, 225.2, 224.9, 225.0])
    ref = _side("curl S1 (core dataset)", [222.2, 222.1, 222.3, 222.2, 222.0], kernel="7.0.0-38-generic")
    cmp = vc.compare(v, ref)
    assert cmp["delta_ms"] == pytest.approx(2.8) and cmp["non_trivial"] is True and cmp["same_kernel"] is False
    text = vc.report(v, [(ref, cmp)])
    assert "DIFFERENT kernels" in text and "LIMITATION (proposed" in text
    assert "+2.800 ms" in text and "The cause is not established" in text
    assert v["median_ms"] == 225.0 and ref["median_ms"] == 222.2         # reported as measured


def test_control_loads_the_variant_and_the_same_dataset_reference(tmp_path):
    m = sm.load_manifest(manifest(tmp_path, VARIANT, VARIANT_ROWS), require_header=True)
    runs = variant_runs(tmp_path, v_s1=(230.0, 231.0))
    v = vc.load_side(m, "curl@he200", "S1", "variant", runs, repo=None)
    ref = vc.load_side(m, "curl", "S1", "plain", runs, repo=None)
    assert (v["n"], v["median_ms"], v["kernels"]) == (2, 230.5, ["7.0.0-43-generic"])
    assert vc.compare(v, ref)["delta_ms"] == pytest.approx(8.5)
    assert vc.load_side(m, "curl@he300", "S1", "absent", runs, repo=None) is None


def test_control_refuses_a_non_variant():
    with pytest.raises(sm.DatasetError, match="compares a curl variant"):
        vc.run("whatever", "curl")


def test_core_records_are_untouched_by_variant_support():
    rec = json.loads((sm.REPO / "examples" / "20261026T193106Z_S1_curl_r08.json").read_text())
    assert validate(copy.deepcopy(rec)) == [] and label_of(rec["client"]) == "curl"
