#!/usr/bin/env python3
"""Normalized output inspection must not mutate canonical repository data."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_core


ROOT = dk_core.ROOT
COLLECTOR = ROOT / "collectors" / "collect.py"
SOURCE_TEXT = "<html><body><main>Fixture source text.</main></body></html>"


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


def write_fixture(root: Path) -> None:
    source_file = root / "fixture.html"
    source_file.write_text(SOURCE_TEXT, encoding="utf-8")
    write_json(
        root / "sources" / "registry.json",
        [
            {
                "id": "fixture-source",
                "title": "Fixture Source",
                "url": source_file.as_uri(),
                "trust": "authoritative",
                "enabled": True,
                "category": "fixture",
                "role": "Fixture source used by collector tests.",
                "collection_strategy": "change-detection",
                "checked_on": "2026-08-30",
                "provenance": "Local test fixture.",
                "version_semantics": {},
            }
        ],
    )


def run_collector(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(COLLECTOR),
            "--source",
            "fixture-source",
            "--root",
            str(root),
            *args,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def assert_no_canonical_output(root: Path) -> None:
    assert not (root / "sources" / "state" / "fixture-source.json").exists()
    assert not (root / "sources" / "snapshots" / "fixture-source").exists()
    assert not list((root / "discovery" / "candidates").glob("*.json"))


with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    write_fixture(root)

    dry_run = run_collector(root, "--dry-run")
    assert dry_run.returncode == 0, dry_run.stderr
    assert "fixture-source: BASELINE " in dry_run.stdout
    assert_no_canonical_output(root)

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    write_fixture(root)
    inspection_dir = root / "inspection"

    dry_run = run_collector(
        root,
        "--dry-run",
        "--normalized-output",
        str(inspection_dir),
    )
    assert dry_run.returncode == 0, dry_run.stderr
    inspection_file = inspection_dir / "fixture-source.txt"
    assert inspection_file.is_file()
    normalized = inspection_file.read_text(encoding="utf-8")
    assert f"fixture-source: BASELINE {dk_core.content_digest(normalized)}" in dry_run.stdout
    assert_no_canonical_output(root)

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    write_fixture(root)

    baseline = run_collector(root)
    assert baseline.returncode == 0, baseline.stderr
    state = json.loads((root / "sources" / "state" / "fixture-source.json").read_text())
    snapshot = (
        root
        / "sources"
        / "snapshots"
        / "fixture-source"
        / f"{state['content_sha256'].removeprefix('sha256:')}.txt"
    )
    assert snapshot.is_file()
    assert not list((root / "discovery" / "candidates").glob("*.json"))

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    write_fixture(root)

    without_dry_run = run_collector(
        root,
        "--normalized-output",
        str(root / "inspection"),
    )
    assert without_dry_run.returncode == 2
    assert "--normalized-output requires --dry-run" in without_dry_run.stderr
    assert_no_canonical_output(root)

    blocked_paths = [
        "sources/state",
        "sources/snapshots",
        "knowledge",
        ".tmp/../knowledge",
    ]
    for blocked in blocked_paths:
        blocked_run = run_collector(root, "--dry-run", "--normalized-output", blocked)
        assert blocked_run.returncode == 2
        assert "--normalized-output cannot write under" in blocked_run.stderr
    assert_no_canonical_output(root)


print("NORMALIZED_OUTPUT_HELPER_NON_INTRUSIVE=PASS")
