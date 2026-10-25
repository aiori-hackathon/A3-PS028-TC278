"""Milestone 1 harness test: one curl request to a local Python HTTP server.

This tests the runner and the run-record format. It is NOT a measurement:
it uses IPv4 loopback only, no lab namespaces, no impairments and no DNS.
Records are therefore always tagged scenario "harness-test".

Usage (from the repo root):
    .venv/bin/python src/runner/client_curl.py [--repetition N] [--run-id ID] [--pcap PATH]

--run-id and --pcap let the record point at a capture started in another
terminal. The pcap hash is left null: the capture may still be open when the
record is written, so hashing is done later, after tcpdump has stopped.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.validate_record import SCHEMA_VERSION, validate  # noqa: E402
from runner.child_env import child_env_with_removed, describe  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
HOST = "127.0.0.1"
PORT = 8080
SCENARIO = "harness-test"
BODY = b"HappyLab harness test\n"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_run_id(start: datetime, repetition: int) -> str:
    return f"{start:%Y%m%dT%H%M%SZ}_{SCENARIO}_curl_r{repetition:02d}"


def iso_utc(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def curl_argv(url: str) -> list[str]:
    # -q must come first: it stops curl reading ~/.curlrc, so user config cannot change behaviour.
    # --noproxy '*' stops proxy environment variables from rerouting the request.
    return ["curl", "-q", "-sS", "--noproxy", "*", "--max-time", "10",
            "-o", "/dev/null", "-w", "%{http_code}", url]


def parse_http_code(stdout: str) -> int | None:
    """curl -w %{http_code} prints 000 when no response was received."""
    text = stdout.strip()
    if not text.isdigit():
        return None
    code = int(text)
    return code if code > 0 else None


def curl_version(env: dict[str, str]) -> str:
    out = subprocess.run(["curl", "--version"], capture_output=True, text=True, env=env, check=True)
    return out.stdout.splitlines()[0].strip()


def git_commit() -> str:
    try:
        out = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain"],
                               capture_output=True, text=True, check=True).stdout.strip()
        return out.stdout.strip() + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def wrapped(status: str, note: str | None = None) -> dict:
    field = {"value": None, "status": status}
    if note:
        field["note"] = note
    return field


def build_record(*, run_id: str, repetition: int, run_start: datetime, argv: list[str],
                 version: str, start_ns: int, end_ns: int, returncode: int, stdout: str,
                 stderr: str, pcap_path: str | None, log_path: str,
                 env_removed: list[str] | None = None) -> dict:
    http_status = parse_http_code(stdout)
    success = returncode == 0 and http_status is not None
    error = stderr.strip() or None
    if not success and error is None:
        error = f"curl exit code {returncode}, no HTTP response"
    loopback = "loopback harness test: no lab link"
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "scenario": {
            "id": SCENARIO,
            "label": "Loopback harness test (not a measurement)",
            "repetition": repetition,
            "netem": None,
            "dns": None,
            "measured_rtt_ms": {"v4": wrapped("not_applicable", loopback),
                                "v6": wrapped("not_applicable", loopback)},
        },
        "client": {
            "name": "curl",
            "version": version,
            "argv": argv,
            "config": {
                "happy_eyeballs_timeout_ms": "default (not set)",
                "curlrc": "ignored (-q)",
                "proxy": "disabled (--noproxy '*')",
                "server": f"Python http.server on {HOST}:{PORT}",
            },
        },
        "environment": {
            "kernel": platform.release(),
            "python": platform.python_version(),
            "git_commit": git_commit(),
            "network": "host loopback (127.0.0.1); no namespaces, no impairments",
            "resolver": "not used: URL is an IPv4 literal",
            "child_env": describe(env_removed or []),
        },
        "timestamps": {
            "run_start_utc": iso_utc(run_start),
            "client_start_epoch_ns": start_ns,
            "client_end_epoch_ns": end_ns,
            # Capture was started by hand in another terminal, so the runner has no times for it.
            "capture_start_epoch_ns": None,
            "capture_end_epoch_ns": None,
        },
        "outcome": {
            "success": success,
            "exit_code": returncode,
            "http_status": http_status,
            "error": error,
            "source": "client/runner log",
        },
        "evidence": {
            "pcap_path": pcap_path,
            "pcap_sha256": None,
            "client_log_path": log_path,
            "pre_verify_ok": None,
            "post_restore_verify_ok": None,
        },
        "packet_observations": {
            "winning_family": wrapped("not_yet_computed"),
            "attempts": wrapped("not_yet_computed"),
            "failed_or_abandoned_attempts": wrapped("not_yet_computed"),
        },
        "metrics": {
            "dns_time_ms": wrapped("not_applicable", "URL is an IPv4 literal; no DNS lookup"),
            "tcp_setup_time_ms": wrapped("not_yet_computed"),
            "inter_family_attempt_delay_ms": wrapped("not_yet_computed"),
            "scenario_penalty_ms": wrapped("not_applicable",
                                           "per-scenario aggregate; see scenario summary"),
        },
    }


class _Handler(BaseHTTPRequestHandler):
    server_log: list[str] = []

    def do_GET(self):  # noqa: N802 (http.server naming)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        self.server_log.append(f"{time.time_ns()} {self.address_string()} {fmt % args}")


def start_server(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((HOST, port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run(repetition: int, run_id: str | None, pcap: str | None, out_dir: Path,
        port: int = PORT) -> tuple[Path, dict]:
    env, env_removed = child_env_with_removed()
    version = curl_version(env)
    run_start = utc_now()
    run_id = run_id or make_run_id(run_start, repetition)

    runs_dir, logs_dir = out_dir / "runs", out_dir / "logs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    record_path = runs_dir / f"{run_id}.json"
    log_path = logs_dir / f"{run_id}.log"
    if record_path.exists():
        raise FileExistsError(f"refusing to overwrite {record_path}")

    argv = curl_argv(f"http://{HOST}:{port}/")
    _Handler.server_log = []
    server = start_server(port)
    try:
        start_ns = time.time_ns()
        proc = subprocess.run(argv, capture_output=True, text=True, env=env)
        end_ns = time.time_ns()
    finally:
        server.shutdown()
        server.server_close()

    with log_path.open("x", encoding="utf-8") as log:
        log.write(f"run_id: {run_id}\nargv: {json.dumps(argv)}\n")
        log.write(f"client_start_epoch_ns: {start_ns}\nclient_end_epoch_ns: {end_ns}\n")
        log.write(f"returncode: {proc.returncode}\nstdout: {proc.stdout!r}\nstderr: {proc.stderr!r}\n")
        log.write("server log:\n" + "".join(f"  {line}\n" for line in _Handler.server_log))

    def rel(p: Path) -> str:
        p = p.resolve()
        return str(p.relative_to(REPO)) if p.is_relative_to(REPO) else str(p)

    record = build_record(
        run_id=run_id, repetition=repetition, run_start=run_start, argv=argv, version=version,
        start_ns=start_ns, end_ns=end_ns, returncode=proc.returncode, stdout=proc.stdout,
        stderr=proc.stderr, pcap_path=pcap, log_path=rel(log_path), env_removed=env_removed)

    problems = validate(record)
    if problems:
        raise ValueError("record failed validation:\n  " + "\n  ".join(problems))
    with record_path.open("x", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
    return record_path, record


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repetition", type=int, default=1)
    p.add_argument("--run-id", help="use this run ID (e.g. to match a capture file name)")
    p.add_argument("--pcap", help="path of a capture taken in another terminal, relative to repo root")
    p.add_argument("--out-dir", type=Path, default=REPO / "data" / "generated")
    args = p.parse_args(argv)
    if args.repetition < 1:
        p.error("--repetition must be >= 1")

    path, record = run(args.repetition, args.run_id, args.pcap, args.out_dir)
    oc = record["outcome"]
    print(f"run_id:  {record['run_id']}")
    print(f"outcome: success={oc['success']} exit_code={oc['exit_code']} http_status={oc['http_status']}")
    print(f"record:  {path}")
    return 0 if oc["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
