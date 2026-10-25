"""Write the SHA-256 of a closed packet capture into its run record.

Run this only after tcpdump has stopped, so the hash covers the final file.

Usage (from the repo root):
    .venv/bin/python src/runner/finalise_record.py data/generated/runs/<run_id>.json [...]

Rules:
- The capture must exist and start with a pcap or pcapng magic number.
- If the record already has a hash, it must match. A different hash means the
  capture changed after it was recorded, which is an error (raw captures are never modified).
- The record is validated before it is replaced, and replaced atomically.
- A line is appended to the run log so the change is auditable.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

if __package__ in (None, ""):  # run as a script: make src/ importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.validate_record import validate  # noqa: E402

REPO = Path(__file__).resolve().parents[2]

PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"),  # pcap, microsecond
    bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d"),  # pcap, nanosecond
    bytes.fromhex("0a0d0d0a"),                             # pcapng
}


class FinaliseError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve(p: str, repo: Path) -> Path:
    path = Path(p)
    return path if path.is_absolute() else repo / path


def finalise(record_path: Path, repo: Path = REPO) -> tuple[str, bool]:
    """Fill evidence.pcap_sha256. Returns (sha256, changed)."""
    record = json.loads(record_path.read_text(encoding="utf-8"))
    ev = record.get("evidence") or {}
    pcap_rel = ev.get("pcap_path")
    if not pcap_rel:
        raise FinaliseError(f"{record_path}: evidence.pcap_path is null; nothing to finalise")
    pcap = _resolve(pcap_rel, repo)
    if not pcap.is_file():
        raise FinaliseError(f"{record_path}: capture not found: {pcap_rel}")
    with pcap.open("rb") as f:
        magic = f.read(4)
    if magic not in PCAP_MAGICS:
        raise FinaliseError(f"{pcap_rel}: not a pcap or pcapng file")

    digest = sha256_file(pcap)
    existing = ev.get("pcap_sha256")
    if existing is not None:
        if existing != digest:
            raise FinaliseError(
                f"{pcap_rel}: hash {digest} differs from recorded {existing}; capture changed")
        return digest, False

    ev["pcap_sha256"] = digest
    problems = validate(record)
    if problems:
        raise FinaliseError("record failed validation:\n  " + "\n  ".join(problems))

    tmp = record_path.with_suffix(".json.tmp")
    with tmp.open("x", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
    os.replace(tmp, record_path)

    log_rel = ev.get("client_log_path")
    if log_rel:
        log = _resolve(log_rel, repo)
        if log.is_file():
            with log.open("a", encoding="utf-8") as f:
                f.write(f"finalised: {time.time_ns()} pcap_sha256={digest} ({pcap_rel})\n")
    return digest, True


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    ok = True
    for name in argv:
        try:
            digest, changed = finalise(Path(name))
        except (FinaliseError, OSError, json.JSONDecodeError) as exc:
            ok = False
            print(f"FAILED    {name}: {exc}")
            continue
        print(f"{'FINALISED' if changed else 'UNCHANGED'} {name}: pcap_sha256={digest}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
