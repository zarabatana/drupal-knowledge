#!/usr/bin/env python3
"""Reviewed knowledge may cite only baselined source evidence."""

from __future__ import annotations

import tempfile
from pathlib import Path

import dk_core


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


def write_reviewed_record(root: Path, source_id: str = "fixture-source") -> None:
    write_json(
        root / "knowledge" / "records" / "reviewed.json",
        {
            "id": "drupal.fixture.reviewed-source",
            "review_status": "reviewed",
            "sources": [{"source_id": source_id, "locator": "Reviewed source evidence"}],
        },
    )


def write_state(root: Path, source_id: str, digest: str, content_length: int) -> None:
    write_json(
        root / "sources" / "state" / f"{source_id}.json",
        {
            "source_id": source_id,
            "url": "https://example.com/source",
            "fetch_url": "https://example.com/source",
            "content_sha256": digest,
            "last_changed_at": "2026-08-30T00:00:00Z",
            "content_length": content_length,
        },
    )


def assert_invalid(root: Path) -> None:
    try:
        dk_core.validate_reviewed_knowledge_sources_baselined(root)
    except dk_core.ValidationError:
        pass
    else:
        raise AssertionError("reviewed knowledge accepted invalid source evidence")


def fixture_root() -> tuple[tempfile.TemporaryDirectory, Path, str, str]:
    workspace = tempfile.TemporaryDirectory()
    root = Path(workspace.name)
    source_id = "fixture-source"
    text = "Reviewed source evidence.\n"
    digest = dk_core.content_digest(text)
    return workspace, root, source_id, digest


workspace, root, source_id, digest = fixture_root()
with workspace:
    text = "Reviewed source evidence.\n"
    dk_core.write_snapshot(root, source_id, digest, text)
    write_state(root, source_id, digest, len(text.encode("utf-8")))
    write_reviewed_record(root, source_id)
    dk_core.validate_reviewed_knowledge_sources_baselined(root)

workspace, root, source_id, digest = fixture_root()
with workspace:
    write_reviewed_record(root, source_id)
    assert_invalid(root)

workspace, root, source_id, digest = fixture_root()
with workspace:
    write_state(root, source_id, digest, len("Reviewed source evidence.\n".encode("utf-8")))
    write_reviewed_record(root, source_id)
    assert_invalid(root)

workspace, root, source_id, digest = fixture_root()
with workspace:
    text = "Reviewed source evidence.\n"
    dk_core.write_snapshot(root, source_id, digest, text)
    write_state(root, source_id, digest, len(text.encode("utf-8")))
    write_reviewed_record(root, source_id)
    (root / "sources" / "snapshots" / source_id / f"{digest.removeprefix('sha256:')}.txt").write_text(
        "Tampered source evidence.\n",
        encoding="utf-8",
    )
    assert_invalid(root)

workspace, root, source_id, digest = fixture_root()
with workspace:
    text = "Reviewed source evidence.\n"
    dk_core.write_snapshot(root, source_id, digest, text)
    write_state(root, source_id, digest, len(text.encode("utf-8")) + 1)
    write_reviewed_record(root, source_id)
    assert_invalid(root)


dk_core.validate_reviewed_knowledge_sources_baselined()

print("REVIEWED_KNOWLEDGE_SOURCES_BASELINED=PASS")
print("UNBASELINED_SOURCE_CANNOT_SUPPORT_REVIEWED_KNOWLEDGE=PASS")
