"""Read back one demo run (make demo): re-parse its capture, write its race timeline page, print its numbers.

    .venv/bin/python src/analysis/demo_report.py RUN_ID            # page + large numbers
    .venv/bin/python src/analysis/demo_report.py RUN_ID --plain    # numbers as ordinary text
    .venv/bin/python src/analysis/demo_report.py RUN_ID --no-page  # numbers only

Reads only data/demo/ (written by orchestrate.py --demo). A record that is not a demo record (its session ID
must start with "demo-" and its environment must say it is a demo run) is refused, so this never touches the
measurement tree, and nothing here writes outside data/demo/.

Evidence levels, as everywhere else:
  packet-level  winning family, each family's first SYN, inter-family attempt delay, TCP setup time
                (from the capture; the capture is re-read here and every shared value must match the record)
  derived       oracle setup (the winning family's RTT from the lab ping before the run) and the cost of
                racing (TCP setup minus the oracle)
Times are milliseconds from the run's first SYN, the origin of the TCP setup time. DNS is separate.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json  # noqa: E402

from analysis.summarise import REPO, DatasetError, run_from_record  # noqa: E402

DEMO_ROOT = REPO / "data" / "demo"           # same tree as runner.orchestrate.DEMO_ROOT (a test pins this)
DEMO_SESSION_PREFIX = "demo-"
PAGES = DEMO_ROOT / "timeline"
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z_[A-Z]\d_[\w.-]+_r\d{2}$")


class DemoError(Exception):
    pass


# --- reading the run ----------------------------------------------------------------------

def load_demo_record(run_id: str, root: Path = DEMO_ROOT) -> dict:
    if not RUN_ID_RE.match(run_id):
        raise DemoError(f"not a run ID: {run_id!r}")
    path = root / "runs" / f"{run_id}.json"
    if not path.is_file():
        raise DemoError(f"no demo record {path}")
    rec = json.loads(path.read_text(encoding="utf-8"))
    env = rec.get("environment", {})
    if rec.get("run_id") != run_id:
        raise DemoError(f"{path} holds run {rec.get('run_id')}")
    if not str(env.get("session_id", "")).startswith(DEMO_SESSION_PREFIX) or "demo" not in str(env.get("purpose", "")):
        raise DemoError(f"{path} is not a demo record (session {env.get('session_id')!r}); refusing to read it")
    return rec


def _computed(field: dict):
    return field.get("value") if field.get("status") == "computed" else None


def numbers(rec: dict) -> dict:
    """The values the demo talks over, from the record (packet-level) and the oracle baseline (derived)."""
    run = run_from_record(rec)
    obs, met = rec["packet_observations"], rec["metrics"]
    attempts = sorted(_computed(obs["attempts"]) or [], key=lambda a: a["first_syn_ns"])
    first_syn: dict[str, float] = {}
    if attempts:
        t0 = attempts[0]["first_syn_ns"]
        for a in attempts:
            first_syn.setdefault(a["family"], round((a["first_syn_ns"] - t0) / 1e6, 3))
    ifd = met["inter_family_attempt_delay_ms"]
    return {
        "run_id": rec["run_id"], "client": run.client, "scenario": run.scenario, "label": run.label,
        "success": run.success, "http_status": rec["outcome"].get("http_status"),
        "error": rec["outcome"].get("error"),
        "winner": run.winner, "first_syn_ms": first_syn, "attempts": len(attempts),
        "failed_or_abandoned": run.failed_or_abandoned,
        "inter_family_ms": run.inter_family_ms, "inter_family_status": ifd["status"],
        "inter_family_note": ifd.get("note"),
        "setup_ms": run.setup_ms, "dns_ms": run.dns_ms,
        "oracle_ms": run.oracle_setup_ms, "cost_ms": run.cost_of_racing_ms, "oracle_note": run.oracle_note,
        "single_family": run.single_family,
        "measured_rtt": run.measured_rtt or {},
        "cross_checks": rec["cross_checks"]["status"],
        "verify_ok": bool(rec["evidence"].get("pre_verify_ok") and rec["evidence"].get("post_restore_verify_ok")),
    }


def reparse(rec: dict, root: Path = DEMO_ROOT) -> tuple[Path, dict]:
    """Re-read the run's capture (its SHA-256 must match the record) and check it against the record."""
    from analysis import race   # dnslib and the pcap reader: only needed here
    pcap = REPO / rec["evidence"]["pcap_path"]
    if not pcap.resolve().is_relative_to(root.resolve()):
        raise DemoError(f"{rec['run_id']}: capture {pcap} is outside {root}")
    try:
        path, _ = race.find_capture(rec["run_id"], rec, REPO, None)
        if path is None:
            raise DemoError(f"{rec['run_id']}: capture {pcap} is missing")
        return path, race.wire(path, rec, rows=True)
    except DatasetError as exc:
        raise DemoError(str(exc)) from exc


def write_page(rec: dict, events: dict, capture: Path, out_dir: Path = PAGES) -> Path:
    """The dashboard's race timeline for this one run, as a standalone page (plotly.js inlined: works offline)."""
    from plotly.offline import get_plotlyjs

    from analysis import dashboard, race
    run = run_from_record(rec)
    pay = race.payload(run, rec, events, "pcap", str(capture.relative_to(REPO)))
    data = {"runs": {run.run_id: pay}, "cells": {run.scenario: {run.client: [run.run_id]}},
            "representative": {run.scenario: {run.client: None}}, "scenarios": [run.scenario],
            "clients": [run.client], "default": run.run_id, "default_why": "this demo run", "examples": [],
            "oracle_evidence": race.ORACLE_EVIDENCE}
    html = dashboard.race_page(
        data, f"<script>{get_plotlyjs()}</script>", f"HappyLab demo: {run.client} in {run.scenario}",
        "A live demonstration run. It is not part of any dataset, and its numbers will differ slightly from "
        "the report.")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{run.run_id}.html"
    out.write_text(html, encoding="utf-8")
    return out


# --- large text -----------------------------------------------------------------------------
# A 3x5 pixel font (I, P and v for the family names), drawn with half blocks: two pixel rows per text row,
# so each character is 3 text rows tall and the pixels come out roughly square.

FONT = {
    "0": ["###", "#.#", "#.#", "#.#", "###"], "1": [".#.", "##.", ".#.", ".#.", "###"],
    "2": ["###", "..#", "###", "#..", "###"], "3": ["###", "..#", "###", "..#", "###"],
    "4": ["#.#", "#.#", "###", "..#", "..#"], "5": ["###", "#..", "###", "..#", "###"],
    "6": ["###", "#..", "###", "#.#", "###"], "7": ["###", "..#", "..#", "..#", "..#"],
    "8": ["###", "#.#", "###", "#.#", "###"], "9": ["###", "#.#", "###", "..#", "###"],
    ".": [".", ".", ".", ".", "#"], "-": ["...", "...", "###", "...", "..."],
    "−": ["...", "...", "###", "...", "..."], "+": ["...", ".#.", "###", ".#.", "..."],
    " ": ["..", "..", "..", "..", ".."],
    "I": ["###", ".#.", ".#.", ".#.", "###"], "P": ["###", "#.#", "###", "#..", "#.."],
    "v": ["...", "...", "#.#", "#.#", ".#."],
}
HALF = {(False, False): " ", (True, False): "▀", (False, True): "▄", (True, True): "█"}


def big(text: str) -> list[str] | None:
    """Three text rows drawing text in the pixel font, or None if a character has no glyph."""
    if not text or any(c not in FONT for c in text):
        return None
    pix = [""] * 6
    for i, c in enumerate(text):
        g = FONT[c] + ["." * len(FONT[c][0])]
        for r in range(6):
            pix[r] += ("." if i else "") + g[r]
    return ["".join(HALF[(a == "#", b == "#")] for a, b in zip(pix[2 * k], pix[2 * k + 1])).rstrip()
            for k in range(3)]


# --- the report ---------------------------------------------------------------------------------

def fmt_ms(v: float | None) -> str:
    """Two decimals; a negative value gets a true minus sign."""
    if v is None:
        return "–"
    return ("−" if v < 0 else "") + f"{abs(v):.2f}"


def fam(f: str | None) -> str:
    return f"IPv{f[1]}" if f else "none"


class Style:
    def __init__(self, colour: bool):
        self.on = colour

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text


def report_lines(n: dict, large: bool = True, colour: bool = False, width: int = 100) -> list[str]:
    st = Style(colour)
    tag_p, tag_d = st("Packet-level (pcap)", "36"), st("Derived (pcap − lab RTT)", "35")
    out = [st("=" * min(width, 78), "1"),
           st(f"  {n['client']} · {n['scenario']} ({n['label']}) · demo run {n['run_id']}", "1"),
           st("=" * min(width, 78), "1")]

    def item(label: str, value: str, unit: str, tag: str, sub: str = "") -> None:
        """One label line (label, evidence tag, what the value is), then the value in large digits."""
        rows = big(value) if large else None
        head = f"  {st(label, '1;33')}  ·  {tag}" + (f"  ·  {sub}" if sub else "")
        if rows and 4 + max(len(r) for r in rows) + 2 + len(unit) <= width:
            out.append(head)
            for i, r in enumerate(rows):
                out.append("    " + st(r, "1") + (f"  {st(unit, '1')}" if unit and i == 2 else ""))
        else:
            out.append(f"  {st(label, '1;33')}  {st(value + (' ' + unit if unit else ''), '1')}  ·  {tag}"
                       + (f"  ·  {sub}" if sub else ""))

    outcome = (f"HTTP {n['http_status']}" if n["success"] else f"FAILED: {n['error']}")
    item("WINNING FAMILY", fam(n["winner"]), "", tag_p, f"{n['attempts']} attempt(s), "
         f"{n['failed_or_abandoned']} failed or abandoned; client outcome {outcome} (client log)")
    for f in sorted(n["first_syn_ms"], key=lambda f: n["first_syn_ms"][f]):
        item(f"FIRST SYN, {fam(f)}", fmt_ms(n["first_syn_ms"][f]), "ms", tag_p,
             "the origin: the run's first SYN" if n["first_syn_ms"][f] == 0 else "after the run's first SYN")
    for f in ("v6", "v4"):
        if f not in n["first_syn_ms"]:
            item(f"FIRST SYN, {fam(f)}", "none", "", tag_p, f"no {fam(f)} SYN in the capture")
    if n["inter_family_ms"] is None:
        item("INTER-FAMILY ATTEMPT DELAY", "not observed", "", tag_p, n["inter_family_note"] or "one family tried")
    else:
        item("INTER-FAMILY ATTEMPT DELAY", fmt_ms(n["inter_family_ms"]), "ms", tag_p,
             "second family's first SYN − first family's first SYN")
    item("TCP SETUP TIME", fmt_ms(n["setup_ms"]), "ms" if n["setup_ms"] is not None else "", tag_p,
         "first SYN → ACK completing the winning handshake; DNS is separate")
    rtt_src = f"{fam(n['winner'])} RTT from the lab ping before this run" if n["winner"] else "no winner"
    item("ORACLE", fmt_ms(n["oracle_ms"]), "ms" if n["oracle_ms"] is not None else "", tag_d,
         rtt_src if n["oracle_ms"] is not None else f"not available: {n['oracle_note']}")
    item("COST OF RACING", fmt_ms(n["cost_ms"]), "ms" if n["cost_ms"] is not None else "", tag_d,
         ("TCP setup − oracle" + ("; one family tried, so no race took place" if n["single_family"] else ""))
         if n["cost_ms"] is not None else f"not available: {n['oracle_note']}")
    dns = f"DNS time {n['dns_ms']:.3f} ms (packet-level), not in TCP setup" if n["dns_ms"] is not None else "DNS time: none"
    if n["scenario"] == "S6":   # S6's delay shows only in DNS time: always report both
        item("DNS TIME", fmt_ms(n["dns_ms"]), "ms", tag_p, "the AAAA delay shows here, not in TCP setup time")
    else:
        out.append(f"  {dns}")
    out.append("")
    if n["cross_checks"] != "agree":
        out.append(st(f"  WARNING: client log and capture disagree (cross_checks {n['cross_checks']}): "
                      "do not quote these numbers", "1;31"))
    if not n["verify_ok"]:
        out.append(st("  WARNING: a lab verify did not pass for this run", "1;31"))
    out.append("  Interpretation (labelled): the oracle uses the winning family in hindsight; no client knows it "
               "in advance.")
    out.append("  A demo run is not part of any dataset; its numbers differ slightly from the report.")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_id")
    ap.add_argument("--plain", action="store_true", help="ordinary text instead of large digits")
    ap.add_argument("--no-page", action="store_true", help="do not write the timeline page")
    ap.add_argument("--parse-only", action="store_true", help="re-parse and write the page; print no numbers")
    ap.add_argument("--numbers-only", action="store_true", help="print the numbers; no re-parse, no page")
    ap.add_argument("--page-path-file", type=Path, default=None,
                    help="write the timeline page's path to this file (for scripts/demo.sh)")
    a = ap.parse_args(argv)
    try:
        rec = load_demo_record(a.run_id)
        n = numbers(rec)
        if a.numbers_only:
            return _print_numbers(n, a.plain)
        print(f"  re-reading the capture {rec['evidence']['pcap_path']} and checking it against the record",
              flush=True)
        capture, events = reparse(rec)
        print(f"  PASS capture SHA-256 matches the record; {len(events['attempts'])} connection attempt(s) and "
              f"{len(events['rows'] or [])} packet rows re-read, every shared value agrees", flush=True)
        if not a.no_page:
            page = write_page(rec, events, capture)
            print(f"  timeline page: {page.relative_to(REPO)}", flush=True)
            if a.page_path_file:
                a.page_path_file.write_text(str(page) + "\n", encoding="utf-8")
    except DemoError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0 if a.parse_only else _print_numbers(n, a.plain)


def _print_numbers(n: dict, plain: bool) -> int:
    """Exit 3 when the run's cross-checks or lab verifies did not pass (the numbers are still shown, flagged)."""
    width = shutil.get_terminal_size((100, 40)).columns
    colour = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print("\n".join(report_lines(n, large=not plain, colour=colour, width=width)))
    return 0 if n["cross_checks"] == "agree" and n["verify_ok"] else 3


if __name__ == "__main__":
    sys.exit(main())
