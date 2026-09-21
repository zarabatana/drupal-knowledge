#!/usr/bin/env python3
"""A changed source must never mutate trusted knowledge."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_core


ROOT = dk_core.ROOT
COLLECTOR = ROOT / "collectors" / "collect.py"


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    source_file = root / "fixture.html"
    source_file.write_text("<html><body><main>Initial source text.</main></body></html>", encoding="utf-8")
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
    write_json(
        root / "knowledge" / "records" / "sample.json",
        {"id": "drupal.fixture.sample", "value": "trusted knowledge must not change"},
    )

    baseline = subprocess.run(
        [
            sys.executable,
            str(COLLECTOR),
            "--source",
            "fixture-source",
            "--root",
            str(root),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert baseline.returncode == 0, baseline.stderr

    before_digest = dk_core.knowledge_tree_digest(root)
    state_path = root / "sources" / "state" / "fixture-source.json"
    state_before = json.loads(state_path.read_text(encoding="utf-8"))

    source_file.write_text("<html><body><main>Changed source text.</main></body></html>", encoding="utf-8")
    dry_run = subprocess.run(
        [
            sys.executable,
            str(COLLECTOR),
            "--source",
            "fixture-source",
            "--dry-run",
            "--root",
            str(root),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert dry_run.returncode == 0, dry_run.stderr
    assert "CHANGED" in dry_run.stdout
    assert json.loads(state_path.read_text(encoding="utf-8")) == state_before
    assert not list((root / "discovery" / "candidates").glob("*.json"))

    changed = subprocess.run(
        [
            sys.executable,
            str(COLLECTOR),
            "--source",
            "fixture-source",
            "--root",
            str(root),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert changed.returncode == 0, changed.stderr
    assert "CHANGED" in changed.stdout
    assert dk_core.knowledge_tree_digest(root) == before_digest

    candidates = list((root / "discovery" / "candidates").glob("*.json"))
    assert len(candidates) == 1
    candidate = json.loads(candidates[0].read_text(encoding="utf-8"))
    assert candidate["review_required"] is True
    assert candidate["can_promote_to_knowledge"] is False


print("SOURCE_CHANGE_DOES_NOT_MUTATE_KNOWLEDGE=PASS")
