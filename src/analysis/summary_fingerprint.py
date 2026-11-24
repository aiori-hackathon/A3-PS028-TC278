"""Fingerprint everything a demo run must never change, and compare two fingerprints.

    .venv/bin/python src/analysis/summary_fingerprint.py snapshot OUT.json
    .venv/bin/python src/analysis/summary_fingerprint.py compare BEFORE.json AFTER.json

A fingerprint holds:
  files     the SHA-256 of every file in the measurement tree and the committed outputs: data/generated/
            (runs, logs, lab session logs, summaries, dashboards), captures/, docs/, examples/ and web/index.html
  rebuilt   the SHA-256 of each dataset's summary rebuilt from its manifest now (the core dataset and every
            docs/datasets/ manifest), so a record that a summary would pick up is caught even before anyone
            regenerates the files

`make demo-isolation-check` takes one before and one after two demo runs; compare exits 1 on any difference
and names it. data/demo/ is deliberately not fingerprinted: it is where demo runs go.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.summarise import CORE_DATASET, DATASETS_DIR, REPO, build, load_dataset  # noqa: E402

TREES = ("data/generated", "captures", "docs", "examples")
FILES = ("web/index.html",)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hashes(repo: Path = REPO, trees=TREES, files=FILES) -> dict[str, str]:
    out = {}
    for t in trees:
        root = repo / t
        if root.is_dir():
            for p in sorted(root.rglob("*")):
                if p.is_file() and not p.is_symlink():
                    out[str(p.relative_to(repo))] = _sha(p.read_bytes())
    for f in files:
        p = repo / f
        if p.is_file():
            out[f] = _sha(p.read_bytes())
    return out


def dataset_names(datasets_dir: Path = DATASETS_DIR) -> list[str]:
    return [CORE_DATASET] + sorted(p.stem for p in datasets_dir.glob("*.md") if p.name != "README.md")


def rebuilt_hashes(names: list[str] | None = None) -> dict[str, str]:
    out = {}
    for name in names or dataset_names():
        _, _, summary = build(manifest=load_dataset(name))
        out[name] = _sha(json.dumps(summary, sort_keys=True, default=str).encode("utf-8"))
    return out


def snapshot(repo: Path = REPO, rebuild: bool = True) -> dict:
    return {"files": file_hashes(repo), "rebuilt": rebuilt_hashes() if rebuild else {}}


def compare(before: dict, after: dict) -> list[str]:
    """Every difference, as readable lines; empty when the two are identical."""
    diffs = []
    for kind in ("files", "rebuilt"):
        a, b = before.get(kind, {}), after.get(kind, {})
        diffs += [f"{kind}: removed {k}" for k in sorted(a.keys() - b.keys())]
        diffs += [f"{kind}: added {k}" for k in sorted(b.keys() - a.keys())]
        diffs += [f"{kind}: changed {k}" for k in sorted(a.keys() & b.keys()) if a[k] != b[k]]
    return diffs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("out", type=Path)
    c = sub.add_parser("compare")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "snapshot":
        fp = snapshot()
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(fp, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"fingerprint: {len(fp['files'])} files and {len(fp['rebuilt'])} rebuilt dataset summaries -> {a.out}")
        return 0
    before = json.loads(a.before.read_text(encoding="utf-8"))
    after = json.loads(a.after.read_text(encoding="utf-8"))
    diffs = compare(before, after)
    if diffs:
        print("FAIL: the measurement tree or a summary changed:")
        print("\n".join(f"  {d}" for d in diffs))
        return 1
    print(f"PASS: all {len(after['files'])} files and {len(after['rebuilt'])} rebuilt dataset summaries "
          "are byte-identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
