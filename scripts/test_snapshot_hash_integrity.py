#!/usr/bin/env python3
"""Snapshot filenames must match SHA-256(snapshot bytes)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import dk_core


with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    source_id = "fixture-source"
    text = "Stable normalized content\n"
    digest = dk_core.content_digest(text)
    path, created = dk_core.write_snapshot(root, source_id, digest, text)
    assert created is True
    assert path.name == f"{digest.removeprefix('sha256:')}.txt"
    assert dk_core.require_snapshot(root, source_id, digest) == path

    path.write_text("tampered\n", encoding="utf-8")
    try:
        dk_core.require_snapshot(root, source_id, digest)
    except dk_core.ValidationError:
        pass
    else:
        raise AssertionError("tampered snapshot was accepted")


print("SNAPSHOT_HASH_INTEGRITY=PASS")
