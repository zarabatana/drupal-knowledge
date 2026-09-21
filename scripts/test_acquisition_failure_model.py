#!/usr/bin/env python3
"""Failures must stay honest about what actually failed.

Three failure classes are kept apart because they mean different things:

    external_source_unavailable   the source could not be reached
    source_contract_failure       the source answered but broke its contract
    acquisition_engine_defect     our own bug

None of them may ever be reported as ``unchanged``, and an engine defect may
never be laundered into evidence about a Drupal source.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dk_acquisition
import dk_core


ROOT = dk_core.ROOT

REVISION_A = "<html><body><main>Drupal source revision A.</main></body></html>"


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


def build_workspace(root: Path, content: str = REVISION_A, **overrides) -> Path:
    document = root / "fixture.html"
    document.write_text(content, encoding="utf-8")
    source = {
        "id": "fixture-source",
        "title": "Fixture Source",
        "url": document.as_uri(),
        "trust": "authoritative",
        "enabled": True,
        "category": "fixture",
        "role": "Fixture source used by acquisition failure tests.",
        "collection_strategy": "change-detection",
        "check_cadence_days": 1,
        "lifecycle": "active",
        "checked_on": "2026-08-30",
        "provenance": "Local test fixture.",
        "version_semantics": {},
    }
    source.update(overrides)
    write_json(root / "sources" / "registry.json", [source])
    write_json(
        root / "knowledge" / "records" / "sample.json",
        {"id": "drupal.fixture.sample", "value": "trusted knowledge must not change"},
    )
    return document


def acquire(root: Path, **kwargs) -> dict:
    return dk_acquisition.acquire(root, source_ids=["fixture-source"], **kwargs)


def state_of(root: Path) -> dict:
    return json.loads((root / "sources" / "state" / "fixture-source.json").read_text())


# An unreachable source is explicitly unavailable and keeps its last snapshot.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root)
    baseline = acquire(root)["results"][0]
    baseline_digest = baseline["current_snapshot_sha256"]
    snapshot = dk_core.require_snapshot(root, "fixture-source", baseline_digest)
    snapshot_bytes = snapshot.read_bytes()

    document.unlink()
    run = acquire(root)
    result = run["results"][0]
    assert result["status"] == dk_acquisition.STATUS_UNAVAILABLE, result
    assert result["status"] != dk_acquisition.STATUS_UNCHANGED
    assert result["error"]["class"] == dk_acquisition.ERROR_EXTERNAL
    assert result["error"]["engine_defect"] is False
    assert run["engine_defects"] == []
    assert dk_acquisition.run_exit_code(run) == 1

    # Evidence survives the outage untouched.
    assert snapshot.read_bytes() == snapshot_bytes
    state = state_of(root)
    assert state["content_sha256"] == baseline_digest
    assert state["acquisition"]["last_attempt_status"] == dk_acquisition.STATUS_UNAVAILABLE
    assert state["acquisition"]["consecutive_failures"] == 1
    assert state["acquisition"]["last_error"]["class"] == dk_acquisition.ERROR_EXTERNAL
    assert state["acquisition"]["last_success_at"] is not None

    # Repeated outages accumulate rather than resetting.
    acquire(root)
    assert state_of(root)["acquisition"]["consecutive_failures"] == 2

    # A transport error quotes whatever path it failed on. That text is stored,
    # so the local path is redacted out of it before it is written. The
    # registry-declared url is repository data and is left as declared.
    detail = state_of(root)["acquisition"]["last_error"]["detail"]
    assert workspace not in detail, detail
    assert "<redacted-local-path>" in detail, detail

    # Redaction has to hold wherever this runs, not only where the temp root
    # happens to be one we thought of.
    probe = f"failed on {Path(tempfile.gettempdir()).resolve() / 'probe' / 'file.txt'}"
    assert "<redacted-local-path>" in dk_acquisition.sanitize_detail(probe), probe
    for machine_path in ("/Users/someone/x", "/home/runner/x", "/builds/group/project/x"):
        assert "<redacted-local-path>" in dk_acquisition.sanitize_detail(
            f"failed on {machine_path}"
        ), machine_path
    # A public url that merely contains such a segment is left alone.
    assert (
        dk_acquisition.sanitize_detail("HTTP 404 for https://www.drupal.org/tmp/report")
        == "HTTP 404 for https://www.drupal.org/tmp/report"
    )

    # Recovery clears the failure counter without rewriting history.
    document.write_text(REVISION_A, encoding="utf-8")
    recovered = acquire(root)["results"][0]
    assert recovered["status"] == dk_acquisition.STATUS_UNCHANGED
    assert state_of(root)["acquisition"]["consecutive_failures"] == 0
    assert state_of(root)["acquisition"]["last_error"] is None
    assert snapshot.read_bytes() == snapshot_bytes


# A source that answers but breaks its declared contract is malformed, not
# unchanged and not unavailable.
for label, overrides, content in (
    (
        "missing content window",
        {"content_start": "MARKER THAT IS NOT PRESENT"},
        REVISION_A,
    ),
    (
        "wrong content family",
        {"expected_content_type": "xml"},
        REVISION_A,
    ),
):
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        build_workspace(root, content, **overrides)
        run = acquire(root)
        result = run["results"][0]
        assert result["status"] == dk_acquisition.STATUS_INVALID_OR_MALFORMED, (label, result)
        assert result["status"] != dk_acquisition.STATUS_UNCHANGED
        assert result["error"]["class"] == dk_acquisition.ERROR_CONTRACT, label
        assert result["error"]["engine_defect"] is False
        assert run["engine_defects"] == []
        assert dk_acquisition.run_exit_code(run) == 1

        # Nothing was baselined, and the state says so instead of looking healthy.
        assert not (root / "sources" / "snapshots" / "fixture-source").exists()
        state = state_of(root)
        assert "content_sha256" not in state
        assert state["acquisition"]["last_success_at"] is None
        assert state["acquisition"]["last_attempt_status"] == (
            dk_acquisition.STATUS_INVALID_OR_MALFORMED
        )
        dk_core.validate_snapshot_states(root)

print("SOURCE_FAILURE_NOT_EQUAL_UNCHANGED=PASS")
print("EXTERNAL_SOURCE_FAILURE_NOT_ENGINE_DEFECT=PASS")


# A programming error inside acquisition is an engine defect. It is never
# rewritten as a statement about the source.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root)
    acquire(root)
    state_before = (root / "sources" / "state" / "fixture-source.json").read_bytes()

    def broken_fetcher(source, timeout):
        raise ZeroDivisionError("engine arithmetic defect")

    run = acquire(root, fetcher=broken_fetcher)
    assert run["results"] == [], run["results"]
    assert len(run["engine_defects"]) == 1, run["engine_defects"]
    defect = run["engine_defects"][0]
    assert defect["class"] == dk_acquisition.ERROR_ENGINE_DEFECT
    assert defect["engine_defect"] is True
    assert "ZeroDivisionError" in defect["detail"]
    assert run["failures"] == [], "an engine defect was filed as a source failure"
    assert dk_acquisition.run_exit_code(run) == 3

    # The source keeps its previous, honest state.
    assert (root / "sources" / "state" / "fixture-source.json").read_bytes() == state_before
    assert json.loads(state_before)["acquisition"]["last_attempt_status"] != (
        dk_acquisition.STATUS_UNAVAILABLE
    )

    # A defect inside recording is classified the same way.
    def corrupting_fetcher(source, timeout):
        return {
            "content_sha256": "not-a-digest",
            "content_length": 1,
            "normalized_text": "x",
            "etag": None,
            "last_modified": None,
            "content_type": "text/html",
            "http_status": 200,
            "fetch_url": source["url"],
        }

    corrupt_run = acquire(root, fetcher=corrupting_fetcher)
    assert corrupt_run["results"] == []
    assert len(corrupt_run["engine_defects"]) == 1
    assert corrupt_run["failures"] == []
    assert dk_acquisition.run_exit_code(corrupt_run) == 3

print("ENGINE_DEFECT_NOT_SWALLOWED_AS_SOURCE_FAILURE=PASS")


# Staleness is explicit, and it is neither incorrect nor changed.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root, check_cadence_days=7)
    acquire(root)
    source = dk_core.load_sources(root)[0]

    fresh = dk_acquisition.source_status(root, source)
    assert fresh["stale"] is False
    assert fresh["due"] is False
    assert fresh["check_cadence_days"] == 7

    later = datetime.now(timezone.utc) + timedelta(days=8)
    stale = dk_acquisition.source_status(root, source, later)
    assert stale["stale"] is True
    assert stale["due"] is True
    assert stale["age_days"] == 8
    # Stale describes the check, not the content: the last known snapshot is
    # still there and still the current one.
    assert stale["current_snapshot_sha256"] == fresh["current_snapshot_sha256"]
    assert stale["last_attempt_status"] == dk_acquisition.STATUS_FIRST_OBSERVATION
    assert stale["last_error"] is None

    # --due selects only what the cadence says is actually due.
    selected, skipped = dk_acquisition.select_sources(root, trust="authoritative", due_only=True)
    assert selected == []
    assert skipped == [{"source_id": "fixture-source", "reason": "not_due"}]
    selected_later, _ = dk_acquisition.select_sources(
        root, trust="authoritative", due_only=True, moment=later
    )
    assert [item["id"] for item in selected_later] == ["fixture-source"]

    # A source that has never been acquired is due and visibly not baselined.
    with tempfile.TemporaryDirectory() as empty_workspace:
        empty_root = Path(empty_workspace)
        build_workspace(empty_root)
        never = dk_acquisition.source_status(empty_root, dk_core.load_sources(empty_root)[0])
        assert never["baselined"] is False
        assert never["due"] is True
        assert never["stale"] is True
        assert never["last_success_at"] is None

print("STALE_SOURCE_STATE_EXPLICIT=PASS")


# Trusted knowledge survives every failure path untouched.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root)
    digest = dk_core.knowledge_tree_digest(root)
    acquire(root)
    document.unlink()
    unavailable = acquire(root)
    assert unavailable["trusted_knowledge_mutations"] == []
    assert dk_core.knowledge_tree_digest(root) == digest

    def broken(source, timeout):
        raise RuntimeError("unexpected engine state")

    defective = acquire(root, fetcher=broken)
    assert defective["trusted_knowledge_mutations"] == []
    assert dk_core.knowledge_tree_digest(root) == digest

print("TRUSTED_KNOWLEDGE_SURVIVES_ACQUISITION_FAILURE=PASS")
