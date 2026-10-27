"""HappyLab orchestrator: the per-run measurement loop.

Scope: curl and Chromium (Playwright) on C0 and S1-S6; no X1.

Usage (lab already up via `sudo src/lab/setup.sh`; run with plain sudo, never sudo -E):
    .venv/bin/python src/runner/orchestrate.py --scenario S1 --reps 1 --dry-run   # review, no sudo
    sudo .venv/bin/python src/runner/orchestrate.py --scenario C0 --reps 1
    sudo .venv/bin/python src/runner/orchestrate.py --scenario C0 S1 --reps 3
    sudo .venv/bin/python src/runner/orchestrate.py --scenario S2 S3 S4 S5 S6 --reps 3   # pilot
    sudo .venv/bin/python src/runner/orchestrate.py --client chromium --scenario C0 S1 --reps 3

Session: start the DNS server and nginx inside hl-server (as the invoking user), then for
each scenario and repetition run one measurement:
    apply scenario -> verify (real RTT) -> start capture -> curl -> stop capture
    -> restore baseline -> verify -> parse capture -> write record -> chown to the user
The lab is restored to baseline after every run, and again on any error or Ctrl-C.
Any failed verify stops the session. A log-versus-pcap disagreement is written to the
record's cross_checks block and printed; it is never resolved silently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pwd
import re
import select
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml  # noqa: E402

from analysis import metrics  # noqa: E402
from analysis.parse_pcap import parse  # noqa: E402
from analysis.validate_record import SCHEMA_VERSION, validate  # noqa: E402
from runner.child_env import STRIPPED_VARS, child_env_with_removed, describe  # noqa: E402
from runner.clients import (CLIENTS, CURL_FORMAT, CURL_URL, curl_argv,  # noqa: E402,F401
                            parse_curl_report)

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "src" / "lab"
SCENARIOS_FILE = REPO / "src" / "config" / "scenarios.yaml"
NGINX_CONF = REPO / "src" / "config" / "nginx.conf"
DNS_SERVER = REPO / "src" / "dns" / "hl_dns.py"
VENV_PYTHON = REPO / ".venv" / "bin" / "python"

SUPPORTED = {name: c.scenarios for name, c in CLIENTS.items()}
ALL_SUPPORTED = tuple(dict.fromkeys(s for scns in SUPPORTED.values() for s in scns))
URL = CURL_URL
# Port 443 (TCP and UDP) is captured so an HTTPS upgrade or QUIC attempt is seen, not missed.
CAPTURE_FILTER = "tcp port 80 or tcp port 443 or udp port 443 or udp port 53 or icmp or icmp6 or arp"
TAIL_WAIT_S = 0.5  # keep capturing briefly after the client exits, for the closing FIN/ACKs


class OrchestratorError(Exception):
    pass


# --- configuration --------------------------------------------------------------------

def load_lab_env(path: Path = LAB / "lab.env") -> dict[str, str]:
    env = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            env[key] = value
    return env


def load_scenarios(ids: list[str], path: Path = SCENARIOS_FILE, client: str = "curl") -> dict[str, dict]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = {}
    supported = SUPPORTED[client]
    for sid in ids:
        if sid not in supported:
            raise OrchestratorError(f"scenario {sid} is out of scope for {client} for now "
                                    f"(supported: {', '.join(supported)})")
        if sid not in cfg["scenarios"]:
            raise OrchestratorError(f"scenario {sid} missing from {path}")
        out[sid] = cfg["scenarios"][sid]
    out["_baseline"] = cfg["baseline"]
    return out


# --- command builders (pure, tested) ----------------------------------------------------

def in_ns_as_user(ns: str, user: str, argv: list[str]) -> list[str]:
    """Run argv inside a namespace, dropped from root to the user (no password prompt)."""
    return ["ip", "netns", "exec", ns, "runuser", "-u", user, "--", *argv]


def cmd_netem(family: str, delay_ms: int, loss_pct: int) -> list[str]:
    return [str(LAB / "netem.sh"), family, str(delay_ms), str(loss_pct)]


def cmd_verify(v4_target, v6_target) -> list[str]:
    return [str(LAB / "verify.sh"), "up", str(v4_target), str(v6_target)]


def cmd_tcpdump(ns: str, pcap: Path, user: str) -> list[str]:
    # --immediate-mode: hand each packet to tcpdump as it arrives. Without it, Linux delivers
    # packets in blocks (up to ~1 s), and a capture stopped sooner than that writes nothing:
    # the first orchestrated runs logged "0 packets captured, 15 packets received by filter".
    # -s 65535 -B 65536: in immediate mode each ring slot is sized for the snapshot length, so with
    # -s 0 (262144) and the default 2 MiB buffer only a handful of packets fit; Chromium's startup
    # DNS burst overflowed it ("4 packets dropped by kernel"). 64 MiB / 64 KiB slots = 1024 packets.
    return ["ip", "netns", "exec", ns, "tcpdump", "-i", "any", "--immediate-mode", "-n", "-s", "65535",
            "-B", "65536", "-U", "-Z", user, "-w", str(pcap), CAPTURE_FILTER]


def cmd_dns(lab: dict, user: str, delays: dict[str, int]) -> list[str]:
    argv = [str(VENV_PYTHON), str(DNS_SERVER), "--listen", lab["DNS_ADDR"], "--port", "53"]
    for qtype, ms in sorted(delays.items()):
        if ms:
            argv += ["--delay", f"{qtype}={ms}"]
    return in_ns_as_user(lab["NS_SERVER"], user, argv)


def cmd_nginx(lab: dict, user: str, prefix: Path) -> list[str]:
    return in_ns_as_user(lab["NS_SERVER"], user, [
        "nginx", "-p", str(prefix), "-c", str(NGINX_CONF), "-e", str(prefix / "logs" / "error.log")])


def make_run_id(start: datetime, scenario: str, repetition: int, client: str = "curl") -> str:
    return f"{start:%Y%m%dT%H%M%SZ}_{scenario}_{client}_r{repetition:02d}"


def verify_targets(sc: dict) -> tuple:
    t = sc["verify_target"]
    return t["v4"], t["v6"]


# --- parsing tool output (pure, tested) ------------------------------------------------------

_RTT_RE = re.compile(r"^(PASS|FAIL) RTT (v4|v6|ctl) (.*)$")


def parse_verify_rtt(output: str) -> dict[str, dict]:
    """Pull the RTT lines out of verify.sh output: {"v4": {"verdict": "PASS", "median_ms": "20.50", ...}}."""
    out = {}
    for line in output.splitlines():
        m = _RTT_RE.match(line.strip())
        if m:
            fields = dict(kv.split("=", 1) for kv in m.group(3).split() if "=" in kv)
            out[m.group(2)] = {"verdict": m.group(1), **fields}
    return out


def measured_rtt_field(rtt: dict | None, target) -> dict:
    """Record field for one family's RTT measured by verify.sh before the run (packet-level: ping)."""
    if not rtt:
        return {"value": None, "status": "not_yet_computed", "note": "no RTT line from verify.sh"}
    if target == "blackhole":
        return {"value": None, "status": "not_observed",
                "note": f"blackhole: loss {rtt.get('loss_pct')}%, ICMP errors {rtt.get('errors')} (verify.sh {rtt['verdict']})"}
    try:
        return {"value": float(rtt["median_ms"]), "status": "computed",
                "note": f"median of {rtt.get('sent')} pings, loss {rtt.get('loss_pct')}% (verify.sh {rtt['verdict']})"}
    except (KeyError, ValueError):
        return {"value": None, "status": "not_observed", "note": f"no replies: {rtt}"}


def parse_ifindex_map(ip_link_output: str) -> dict[str, str]:
    """`ip -o link show` -> {"2": "hl-v4c", ...}. Needed because -i any pcaps store interface numbers only."""
    out = {}
    for line in ip_link_output.splitlines():
        m = re.match(r"^(\d+):\s+([^:@\s]+)", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def parse_tcpdump_stats(stderr: str) -> dict[str, int]:
    """tcpdump's exit summary: {"captured": N, "received": N, "dropped": N} (keys missing if not printed)."""
    stats = {}
    for key, pattern in (("captured", r"(\d+) packets? captured"),
                         ("received", r"(\d+) packets? received by filter"),
                         ("dropped", r"(\d+) packets? dropped by kernel")):
        m = re.search(pattern, stderr)
        if m:
            stats[key] = int(m.group(1))
    return stats


def capture_problem(stats: dict[str, int]) -> str | None:
    """Why a capture cannot be trusted as complete, or None."""
    if not {"captured", "received", "dropped"} <= stats.keys():
        return f"tcpdump printed no complete exit summary ({stats})"
    if stats["dropped"]:
        return f"{stats['dropped']} packets dropped by kernel"
    if stats["captured"] < stats["received"]:
        return (f"only {stats['captured']} of {stats['received']} packets matched by the filter "
                "were written; capture stopped before they were processed")
    return None


# --- record ------------------------------------------------------------------------------

def build_record(*, run_id: str, scenario_id: str, sc: dict, repetition: int, run_start: datetime,
                 client_version: str, argv: list[str], user: str, environment: dict,
                 client_start_ns: int, client_end_ns: int, capture_start_ns: int, capture_end_ns: int,
                 returncode: int, stdout: str, stderr: str, pre_rtt: dict, pre_ok: bool, post_ok: bool,
                 pcap_rel: str, pcap_sha256: str, log_rel: str, timeline, capture_stats: dict,
                 client: str = "curl", client_info: dict | None = None) -> dict:
    spec = CLIENTS[client]
    outcome = spec.outcome(returncode, stdout, stderr)
    report = outcome["client_report"]

    m = metrics.compute(timeline)
    obs, met = metrics.record_fields(m, timeline)
    cc = metrics.cross_check(outcome, report, m)
    problem = capture_problem(capture_stats)
    if problem:
        cc["conflicts"].append({"field": "capture", "log_value": capture_stats,
                                "pcap_value": timeline.packet_count,
                                "note": f"capture incomplete: {problem}"})
        cc["status"] = "conflict"

    v4_t, v6_t = verify_targets(sc)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "scenario": {
            "id": scenario_id, "label": sc["label"], "repetition": repetition,
            "netem": {"v4": sc["v4"], "v6": sc["v6"]},
            "dns": sc["dns"],
            "measured_rtt_ms": {"v4": measured_rtt_field(pre_rtt.get("v4"), v4_t),
                                "v6": measured_rtt_field(pre_rtt.get("v6"), v6_t)},
        },
        "client": {
            "name": spec.name, "version": client_version, "argv": argv,
            "config": spec.config(in_ns_as_user("hl-client", user, []), client_info or {}),
        },
        "environment": environment,
        "timestamps": {
            "run_start_utc": run_start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "client_start_epoch_ns": client_start_ns, "client_end_epoch_ns": client_end_ns,
            "capture_start_epoch_ns": capture_start_ns, "capture_end_epoch_ns": capture_end_ns,
        },
        "outcome": outcome,
        "evidence": {"pcap_path": pcap_rel, "pcap_sha256": pcap_sha256, "client_log_path": log_rel,
                     "pre_verify_ok": pre_ok, "post_restore_verify_ok": post_ok},
        "packet_observations": obs,
        "metrics": met,
        "cross_checks": cc,
    }


# --- execution ------------------------------------------------------------------------------

@dataclass
class Ctx:
    user: str
    uid: int
    gid: int
    lab: dict
    session_id: str
    env: dict
    env_removed: list[str]
    created: list[Path] = field(default_factory=list)  # files/dirs to chown at the end

    def chown(self, path: Path) -> None:
        try:
            os.chown(path, self.uid, self.gid)
        except FileNotFoundError:
            pass


class RunLog:
    def __init__(self, path: Path):
        self.path = path
        self.f = path.open("x", encoding="utf-8")

    def write(self, text: str) -> None:
        self.f.write(text if text.endswith("\n") else text + "\n")
        self.f.flush()

    def close(self) -> None:
        self.f.close()


def sh(ctx: Ctx, argv: list[str], log: RunLog | None, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess:
    """Run a command with the clean environment; log command, exit code and output."""
    t = time.time_ns()
    proc = subprocess.run(argv, capture_output=True, text=True, env=ctx.env, timeout=timeout)
    if log:
        log.write(f"[{t}] + {shlex.join(argv)}  (exit {proc.returncode})")
        for stream in (proc.stdout, proc.stderr):
            if stream.strip():
                log.write("".join(f"    {line}\n" for line in stream.splitlines()))
    if check and proc.returncode != 0:
        raise OrchestratorError(f"command failed (exit {proc.returncode}): {shlex.join(argv)}\n{proc.stdout}{proc.stderr}")
    return proc


def check_environment(dry_run: bool) -> tuple[str, int, int]:
    leaked = [k for k in STRIPPED_VARS if k in os.environ]
    if leaked and not dry_run:
        raise OrchestratorError(f"{', '.join(leaked)} set in the environment: run with plain sudo, never sudo -E")
    if dry_run:
        user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    else:
        if os.geteuid() != 0:
            raise OrchestratorError("run with sudo (it changes lab qdiscs and captures packets)")
        user = os.environ.get("SUDO_USER", "")
        if not user or user == "root":
            raise OrchestratorError("SUDO_USER is not set: start this with sudo from your normal account")
    pw = pwd.getpwnam(user)
    return user, pw.pw_uid, pw.pw_gid


def git_commit() -> str:
    try:
        rev = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True, check=True).stdout.strip()
        return rev + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


class Services:
    """DNS server and nginx inside hl-server, as the user, in their own process groups."""

    def __init__(self, ctx: Ctx, nginx_prefix: Path, lab_logs: Path):
        self.ctx, self.prefix, self.logs = ctx, nginx_prefix, lab_logs
        self.dns: subprocess.Popen | None = None
        self.nginx: subprocess.Popen | None = None
        self.dns_delays: dict | None = None

    def ensure_dns(self, delays: dict[str, int], log: RunLog) -> None:
        if self.dns is not None and self.dns.poll() is None and self.dns_delays == delays:
            return
        self._stop(self.dns)
        path = self.logs / f"{self.ctx.session_id}_dns.log"
        out = path.open("a", encoding="utf-8")
        self.ctx.created.append(path)
        argv = cmd_dns(self.ctx.lab, self.ctx.user, delays)
        log.write(f"+ {shlex.join(argv)} > {path}")
        self.dns = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=self.ctx.env,
                                    start_new_session=True)
        self.dns_delays = dict(delays)
        _wait_for(lambda: '"event": "listening"' in path.read_text(encoding="utf-8"), 5,
                  f"DNS server did not start (see {path})", self.dns)

    def ensure_nginx(self, log: RunLog) -> None:
        if self.nginx is not None and self.nginx.poll() is None:
            return
        argv = cmd_nginx(self.ctx.lab, self.ctx.user, self.prefix)
        log.write(f"+ {shlex.join(argv)}")
        self.nginx = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      env=self.ctx.env, start_new_session=True)
        lab = self.ctx.lab

        def listening() -> bool:
            out = subprocess.run(["ip", "netns", "exec", lab["NS_SERVER"], "ss", "-Hltn"],
                                 capture_output=True, text=True, env=self.ctx.env).stdout
            return f"{lab['V4_ADDR_S']}:80" in out and f"[{lab['V6_ADDR_S']}]:80" in out
        _wait_for(listening, 5, f"nginx did not start (see {self.prefix / 'logs' / 'error.log'})", self.nginx)

    @staticmethod
    def _stop(proc: subprocess.Popen | None) -> None:
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def stop(self) -> None:
        self._stop(self.nginx)
        self._stop(self.dns)


def _wait_for(cond, timeout_s: float, message: str, proc: subprocess.Popen | None = None) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise OrchestratorError(f"{message} (process exited {proc.returncode})")
        try:
            if cond():
                return
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    raise OrchestratorError(message)


def start_capture(ctx: Ctx, pcap: Path, log: RunLog) -> subprocess.Popen:
    argv = cmd_tcpdump(ctx.lab["NS_CLIENT"], pcap, ctx.user)
    log.write(f"+ {shlex.join(argv)}")
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=ctx.env)
    deadline = time.monotonic() + 5
    seen = ""
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stderr], [], [], 0.2)
        if ready:
            line = proc.stderr.readline()
            seen += line
            if "listening on" in line:
                log.write(f"    {line.strip()}")
                return proc
        if proc.poll() is not None:
            break
    proc.kill()
    raise OrchestratorError(f"tcpdump did not start: {seen.strip()}")


def stop_capture(proc: subprocess.Popen, log: RunLog) -> str:
    proc.send_signal(signal.SIGINT)  # ip netns exec execs tcpdump, so this pid is tcpdump
    try:
        _, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
    log.write("".join(f"    {line}\n" for line in (err or "").splitlines()) or "    (tcpdump: no summary)")
    return err or ""


def restore_baseline(ctx: Ctx, base_delay: int, log: RunLog | None) -> None:
    for fam in ("v4", "v6"):
        sh(ctx, cmd_netem(fam, base_delay, 0), log)


def run_one(ctx: Ctx, client: str, sid: str, sc: dict, rep: int, base: dict, client_version: str,
            client_info: dict, environment: dict, dirs: dict[str, Path]) -> dict:
    spec = CLIENTS[client]
    run_start = datetime.now(timezone.utc)
    run_id = make_run_id(run_start, sid, rep, client)
    record_path = dirs["runs"] / f"{run_id}.json"
    while record_path.exists():  # two runs in the same second: wait for a fresh ID
        time.sleep(1)
        run_start = datetime.now(timezone.utc)
        run_id = make_run_id(run_start, sid, rep, client)
        record_path = dirs["runs"] / f"{run_id}.json"
    pcap = dirs["captures"] / f"{run_id}.pcap"
    log_path = dirs["logs"] / f"{run_id}.log"
    netlog = spec.netlog_path(dirs["logs"], run_id)
    log = RunLog(log_path)
    ctx.created += [log_path, pcap] + ([netlog] if netlog else [])
    log.write(f"run_id: {run_id}\nscenario: {sid} {json.dumps(sc)}\nsession: {ctx.session_id}")
    v4_t, v6_t = verify_targets(sc)
    capture = None
    applied = False
    try:
        # 1-2. apply scenario, verify against its targets
        applied = True
        sh(ctx, cmd_netem("v4", sc["v4"]["delay_ms_each_way"], sc["v4"]["loss_pct"]), log)
        sh(ctx, cmd_netem("v6", sc["v6"]["delay_ms_each_way"], sc["v6"]["loss_pct"]), log)
        pre = sh(ctx, cmd_verify(v4_t, v6_t), log, check=False)
        pre_ok, pre_rtt = pre.returncode == 0, parse_verify_rtt(pre.stdout)
        if not pre_ok:
            raise OrchestratorError(f"pre-run verify failed for {run_id}; see {log_path}")

        # 3. capture (record the interface map: -i any pcaps store interface numbers only)
        ifmap = parse_ifindex_map(sh(ctx, ["ip", "-n", ctx.lab["NS_CLIENT"], "-o", "link", "show"], log).stdout)
        capture = start_capture(ctx, pcap, log)
        capture_start_ns = time.time_ns()

        # 4. client
        argv = spec.argv(netlog)
        full = in_ns_as_user(ctx.lab["NS_CLIENT"], ctx.user, argv)
        log.write(f"+ {shlex.join(full)}")
        client_start_ns = time.time_ns()
        proc = subprocess.run(full, capture_output=True, text=True, env=ctx.env, timeout=spec.timeout_s)
        client_end_ns = time.time_ns()
        log.write(f"    exit {proc.returncode} stdout {proc.stdout!r} stderr {proc.stderr!r}")
        log.write(f"    client_start_epoch_ns {client_start_ns} client_end_epoch_ns {client_end_ns}")

        # 5. stop capture
        time.sleep(TAIL_WAIT_S)
        tcpdump_err = stop_capture(capture, log)
        capture = None
        capture_end_ns = time.time_ns()

        # 6-7. restore baseline, verify baseline
        restore_baseline(ctx, base["delay_ms_each_way"], log)
        applied = False
        post = sh(ctx, cmd_verify(base["rtt_ms"], base["rtt_ms"]), log, check=False)
        post_ok = post.returncode == 0
    except BaseException:
        if capture is not None:
            stop_capture(capture, log)
        if applied:
            try:
                restore_baseline(ctx, base["delay_ms_each_way"], log)
                log.write("restored baseline after error")
            except Exception as exc:  # noqa: BLE001
                log.write(f"RESTORE FAILED: {exc}")
        log.close()
        for p in (log_path, pcap, netlog):
            if p:
                ctx.chown(p)
        raise

    # 8. parse the capture for this run's window only, write the record
    timeline = parse(pcap, (client_start_ns, capture_end_ns))
    sha = hashlib.sha256(pcap.read_bytes()).hexdigest()
    env = dict(environment, capture_interfaces=ifmap)
    record = build_record(
        run_id=run_id, scenario_id=sid, sc=sc, repetition=rep, run_start=run_start,
        client_version=client_version, argv=argv, user=ctx.user, environment=env,
        client=client, client_info=client_info,
        client_start_ns=client_start_ns, client_end_ns=client_end_ns,
        capture_start_ns=capture_start_ns, capture_end_ns=capture_end_ns,
        returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr,
        pre_rtt=pre_rtt, pre_ok=pre_ok, post_ok=post_ok,
        pcap_rel=str(pcap.relative_to(REPO)), pcap_sha256=sha, log_rel=str(log_path.relative_to(REPO)),
        timeline=timeline, capture_stats=parse_tcpdump_stats(tcpdump_err))
    if netlog is not None:
        record["outcome"]["client_report"]["netlog_path"] = (
            str(netlog.relative_to(REPO)) if netlog.exists() else None)
    problems = validate(record)
    if problems:
        log.write("RECORD INVALID:\n  " + "\n  ".join(problems))
        log.close()
        raise OrchestratorError(f"record for {run_id} failed validation; see {log_path}")
    with record_path.open("x", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
    log.write(f"record: {record_path.relative_to(REPO)}  cross_checks: {record['cross_checks']['status']}")
    log.close()
    for p in (record_path, log_path, pcap, netlog):
        if p:
            ctx.chown(p)
    if not post_ok:
        raise OrchestratorError(f"post-restore verify failed after {run_id}; lab may not be at baseline")
    if any(c["field"] == "capture" for c in record["cross_checks"]["conflicts"]):
        raise OrchestratorError(f"capture for {run_id} is incomplete; stopping so later runs are not wasted "
                                f"(record kept with cross_checks=conflict; see {log_path})")
    return record


def summary_line(r: dict, wall_s: float | None = None) -> str:
    met, obs = r["metrics"], r["packet_observations"]

    def v(f):
        return f["value"] if f["status"] == "computed" else f["status"]
    return (f"{r['run_id']}  http={r['outcome']['http_status']}  win={v(obs['winning_family'])}  "
            f"setup_ms={v(met['tcp_setup_time_ms'])}  inter_family_ms={v(met['inter_family_attempt_delay_ms'])}  "
            f"failed/abandoned={v(obs['failed_or_abandoned_attempts'])}  cross_checks={r['cross_checks']['status']}"
            + (f"  wall_s={wall_s:.2f}" if wall_s is not None else ""))


def dry_run(scenarios: dict, reps: int, user: str, lab: dict, client: str = "curl") -> None:
    spec = CLIENTS[client]
    base = scenarios["_baseline"]
    print(f"DRY RUN (nothing is executed). Client {client}. "
          f"Session would run as root and drop to '{user}' for clients and services.")
    print(f"session start: {shlex.join(in_ns_as_user(lab['NS_CLIENT'], user, spec.version_argv()))}")
    print(f"session start: {shlex.join(cmd_dns(lab, user, {}))}")
    print(f"session start: {shlex.join(cmd_nginx(lab, user, REPO / 'data/generated/nginx'))}")
    for sid, sc in scenarios.items():
        if sid.startswith("_"):
            continue
        rid = make_run_id(datetime.now(timezone.utc), sid, 1, client)
        pcap = REPO / "captures" / f"{rid}.pcap"
        print(f"\n# {sid} ({sc['label']}), repetition 1 of {reps}, run_id like {rid}")
        steps = [
            ("dns", cmd_dns(lab, user, sc["dns"]["delay_ms"])),
            ("apply", cmd_netem("v4", sc["v4"]["delay_ms_each_way"], sc["v4"]["loss_pct"])),
            ("apply", cmd_netem("v6", sc["v6"]["delay_ms_each_way"], sc["v6"]["loss_pct"])),
            ("verify", cmd_verify(*verify_targets(sc))),
            ("ifmap", ["ip", "-n", lab["NS_CLIENT"], "-o", "link", "show"]),
            ("capture", cmd_tcpdump(lab["NS_CLIENT"], pcap, user)),
            ("client", in_ns_as_user(lab["NS_CLIENT"], user,
                                     spec.argv(spec.netlog_path(REPO / "data/generated/logs", rid)))),
            ("stop", ["kill", "-INT", "<tcpdump pid>"]),
            ("restore", cmd_netem("v4", base["delay_ms_each_way"], 0)),
            ("restore", cmd_netem("v6", base["delay_ms_each_way"], 0)),
            ("verify", cmd_verify(base["rtt_ms"], base["rtt_ms"])),
        ]
        for label, argv in steps:
            print(f"  {label:8} {shlex.join(argv)}")
        print(f"  {'parse':8} window [client start, capture end] of {pcap.relative_to(REPO)}")
        print(f"  {'record':8} data/generated/runs/{rid}.json (validated), chown {user}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--client", choices=sorted(CLIENTS), default="curl")
    p.add_argument("--scenario", nargs="+", required=True, choices=ALL_SUPPORTED)
    p.add_argument("--reps", type=int, default=1)
    p.add_argument("--first-rep", type=int, default=1,
                   help="number of the first repetition (to complete a batch that stopped early)")
    p.add_argument("--dry-run", action="store_true", help="print the commands, execute nothing (no sudo needed)")
    args = p.parse_args(argv)
    if args.reps < 1:
        p.error("--reps must be >= 1")
    if args.first_rep < 1:
        p.error("--first-rep must be >= 1")

    try:
        user, uid, gid = check_environment(args.dry_run)
        lab = load_lab_env()
        scenarios = load_scenarios(args.scenario, client=args.client)
        if args.dry_run:
            dry_run(scenarios, args.reps, user, lab, args.client)
            return 0
        return run_session(args.scenario, args.reps, scenarios, lab, user, uid, gid, args.client,
                           first_rep=args.first_rep)
    except OrchestratorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def run_session(ids, reps, scenarios, lab, user, uid, gid, client: str = "curl", first_rep: int = 1) -> int:
    if not Path(f"/run/netns/{lab['NS_CLIENT']}").exists():
        raise OrchestratorError("lab is not up: run sudo src/lab/setup.sh first")
    env, removed = child_env_with_removed()
    session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ctx = Ctx(user=user, uid=uid, gid=gid, lab=lab, session_id=session_id, env=env, env_removed=removed)
    gen = REPO / "data" / "generated"
    dirs = {"runs": gen / "runs", "logs": gen / "logs", "lab": gen / "lab",
            "nginx": gen / "nginx", "captures": REPO / "captures"}
    for d in [*dirs.values(), gen / "nginx" / "logs", gen / "nginx" / "tmp"]:
        d.mkdir(parents=True, exist_ok=True)
        ctx.chown(d)

    base = scenarios["_baseline"]
    session_log = RunLog(dirs["lab"] / f"{session_id}_session.log")
    ctx.created.append(session_log.path)
    services = Services(ctx, dirs["nginx"], dirs["lab"])
    records = []
    walls: list[float] = []  # whole-run wall time incl. DNS restart, verifies and restore
    status = 0
    try:
        spec = CLIENTS[client]
        out = sh(ctx, in_ns_as_user(lab["NS_CLIENT"], user, spec.version_argv()), session_log,
                 timeout=spec.timeout_s).stdout
        try:
            client_version, client_info = spec.parse_version(out)
        except (ValueError, IndexError) as exc:
            raise OrchestratorError(f"could not read {client} version: {exc}") from exc
        nginx_version = sh(ctx, ["nginx", "-v"], session_log).stderr.strip()
        environment = {
            "kernel": platform.release(), "python": platform.python_version(), "git_commit": git_commit(),
            "session_id": session_id,
            "network": "HappyLab namespaces hl-client/hl-server; impairment server-side only (netem + ifb)",
            "resolver": f"{lab['DNS_ADDR']} (src/dns/hl_dns.py, TTL 0)",
            "gai_conf": "lab default (/etc/netns/hl-client/gai.conf)",
            "server": f"{nginx_version}, src/config/nginx.conf (HTTP/1.1, keep-alive off)",
            "child_env": describe(removed),
        }
        services.ensure_nginx(session_log)
        for sid in ids:
            sc = scenarios[sid]
            for rep in range(first_rep, first_rep + reps):
                t0 = time.monotonic()
                services.ensure_dns(sc["dns"]["delay_ms"], session_log)
                services.ensure_nginx(session_log)
                record = run_one(ctx, client, sid, sc, rep, base, client_version, client_info,
                                 environment, dirs)
                walls.append(time.monotonic() - t0)
                records.append(record)
                line = summary_line(record, walls[-1])
                session_log.write(line)
                print(line, flush=True)
                if record["cross_checks"]["status"] == "conflict":
                    status = 3
                    for c in record["cross_checks"]["conflicts"]:
                        print(f"  CONFLICT {c['field']}: log={c['log_value']!r} pcap={c['pcap_value']!r}  {c['note']}")
    except (OrchestratorError, KeyboardInterrupt) as exc:
        print(f"STOPPED: {exc or 'interrupted'}", file=sys.stderr)
        session_log.write(f"STOPPED: {exc or 'interrupted'}")
        status = 1
    finally:
        services.stop()
        try:
            restore_baseline(ctx, base["delay_ms_each_way"], session_log)
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: final restore failed: {exc}", file=sys.stderr)
            status = 1
        session_log.close()
        for path in ctx.created:
            ctx.chown(path)
        for d in (gen / "nginx" / "logs", gen / "nginx" / "tmp"):
            for f in [d, *d.rglob("*")]:
                ctx.chown(f)
    print(f"\n{len(records)} record(s) written; session log {session_log.path.relative_to(REPO)}")
    if walls:
        print(f"wall time per run: mean {sum(walls) / len(walls):.2f} s, min {min(walls):.2f} s, "
              f"max {max(walls):.2f} s over {len(walls)} run(s)")
    if status == 3:
        print("Some runs have log/pcap conflicts: review them before using the data.")
    return status


if __name__ == "__main__":
    sys.exit(main())
