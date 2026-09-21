#!/usr/bin/env python3
"""Analyzer work must not mutate canonical knowledge or freeze future versions."""

from __future__ import annotations

import shutil
import tempfile
from hashlib import sha256
from pathlib import Path

import dk_core
import dk_project_analyzer


CANONICAL_PATHS = [
    Path("VERSION"),
    Path("sources/registry.json"),
    Path("sources/state"),
    Path("sources/snapshots"),
    Path("knowledge/records"),
    Path("generated/knowledge.json"),
    Path("generated/coverage.json"),
    Path("public/index.html"),
]


def canonical_files(root: Path = dk_core.ROOT) -> list[Path]:
    files: list[Path] = []
    for relative in CANONICAL_PATHS:
        path = root / relative
        if path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file())
        elif path.is_file():
            files.append(path)
    return sorted(files)


def canonical_digest(root: Path = dk_core.ROOT) -> str:
    digest = sha256()
    for path in canonical_files(root):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def assert_analyzer_preserves_canonical_tree(root: Path) -> None:
    before = canonical_digest(root)
    fixture = dk_core.ROOT / "tests" / "fixtures" / "project-analyzer" / "recommended"
    dk_project_analyzer.analyze_project(fixture)
    after = canonical_digest(root)
    assert before == after


assert_analyzer_preserves_canonical_tree(dk_core.ROOT)
dk_core.validate_generated_current()

with tempfile.TemporaryDirectory() as workspace:
    future_root = Path(workspace) / "future-repo"
    future_root.mkdir()
    for relative in CANONICAL_PATHS:
        source = dk_core.ROOT / relative
        target = future_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        elif source.is_file():
            shutil.copy2(source, target)
    future_record = future_root / "knowledge" / "records" / "future.reviewed-knowledge.json"
    future_record.write_text(
        '{"id":"future.reviewed-knowledge","review_status":"reviewed"}\n',
        encoding="utf-8",
    )
    assert canonical_digest(future_root) != canonical_digest(dk_core.ROOT)
    assert_analyzer_preserves_canonical_tree(future_root)

print("ANALYZER_DOES_NOT_MUTATE_KNOWLEDGE=PASS")
print("V010_GUARD_DOES_NOT_FREEZE_FUTURE_KNOWLEDGE=PASS")
print("FUTURE_REVIEWED_KNOWLEDGE_CAN_EVOLVE=PASS")
