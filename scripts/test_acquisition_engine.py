#!/usr/bin/env python3
"""Acquisition must produce immutable, deduplicated, deterministic snapshots.

Every assertion here is about observable behaviour: what identity the engine
gives content, what it writes, and what it refuses to write.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_acquisition
import dk_core


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"
COLLECTOR = ROOT / "collectors" / "collect.py"

SOURCE_A = "<html><body><main>Drupal source revision A.</main></body></html>"
SOURCE_B = "<html><body><main>Drupal source revision B with more text.</main></body></html>"


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


def build_workspace(root: Path, content: str, **overrides) -> Path:
    document = root / "fixture.html"
    document.write_text(content, encoding="utf-8")
    source = {
        "id": "fixture-source",
        "title": "Fixture Source",
        "url": document.as_uri(),
        "trust": "authoritative",
        "enabled": True,
        "category": "fixture",
        "role": "Fixture source used by acquisition engine tests.",
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


def only_result(run: dict) -> dict:
    assert len(run["results"]) == 1, run["results"]
    return run["results"][0]


# Same normalized content always yields the same snapshot identity, and the
# snapshot filename is the digest of its own bytes.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root, SOURCE_A)

    first = only_result(acquire(root))
    assert first["status"] == dk_acquisition.STATUS_FIRST_OBSERVATION, first
    assert first["snapshot"]["created"] is True
    digest = first["current_snapshot_sha256"]
    snapshot = dk_core.require_snapshot(root, "fixture-source", digest)
    assert snapshot.name == f"{digest.removeprefix('sha256:')}.txt"

    # Re-acquiring identical content must not create a second logical truth.
    second = only_result(acquire(root))
    assert second["status"] == dk_acquisition.STATUS_UNCHANGED, second
    assert second["current_snapshot_sha256"] == digest
    assert second["snapshot"]["reused"] is True
    assert second["snapshot"]["created"] is False
    assert second["review_candidate"]["result"] == "none"
    assert len(list((root / "sources" / "snapshots" / "fixture-source").glob("*.txt"))) == 1
    assert not list((root / "discovery" / "candidates").glob("*.json"))

print("IDENTICAL_SOURCE_CONTENT_DEDUPLICATED=PASS")


# A changed source produces a new immutable snapshot and leaves the old one
# byte-identical and addressable.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root, SOURCE_A)

    baseline = only_result(acquire(root))
    old_digest = baseline["current_snapshot_sha256"]
    old_path = dk_core.require_snapshot(root, "fixture-source", old_digest)
    old_bytes = old_path.read_bytes()

    document.write_text(SOURCE_B, encoding="utf-8")
    changed = only_result(acquire(root))
    assert changed["status"] == dk_acquisition.STATUS_CHANGED, changed
    new_digest = changed["current_snapshot_sha256"]
    assert new_digest != old_digest

    assert old_path.read_bytes() == old_bytes, "historical snapshot was rewritten"
    assert dk_core.require_snapshot(root, "fixture-source", old_digest) == old_path
    assert dk_core.require_snapshot(root, "fixture-source", new_digest).is_file()

    state = json.loads((root / "sources" / "state" / "fixture-source.json").read_text())
    assert state["content_sha256"] == new_digest
    assert state["acquisition"]["previous_snapshot_sha256"] == old_digest

print("SOURCE_SNAPSHOTS_IMMUTABLE=PASS")


# Normalization is a pure function of bytes plus registry configuration.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    raw = b"<html><body>\r\n<main>Deterministic   text</main>\r\n\r\n\r\n</body></html>"
    source = {"id": "fixture-source", "normalization": "auto"}
    repeated = {
        dk_acquisition.normalized_text(raw, "text/html", source) for _ in range(5)
    }
    assert len(repeated) == 1
    normalized = repeated.pop()
    assert "\r" not in normalized
    assert "   " not in normalized

    # An explicit strategy is honoured instead of sniffing.
    as_raw = dk_acquisition.normalized_text(
        raw, "text/html", {"id": "fixture-source", "normalization": "raw_text"}
    )
    assert "<main>" in as_raw and "<main>" not in normalized

    # A configured window trims chrome without inventing content.
    windowed = dk_acquisition.normalized_text(
        b"<html><body><p>Nav</p><p>START</p><p>Body</p><p>END</p><p>Footer</p></body></html>",
        "text/html",
        {"id": "fixture-source", "content_start": "START", "content_end": "END"},
    )
    assert windowed == "START\nBody"

print("SOURCE_NORMALIZATION_DETERMINISTIC=PASS")
print("SOURCE_NOISE_FILTERING_CONFIGURATION_DRIVEN=PASS")


# An authoritative snapshot is an observation, never trusted knowledge.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root, SOURCE_A)
    before = dk_core.knowledge_tree_digest(root)

    run = acquire(root)
    result = only_result(run)
    assert result["trust"] == "authoritative"
    assert run["trusted_knowledge_mutations"] == []
    assert run["trusted_knowledge_digest"]["before"] == before
    assert run["trusted_knowledge_digest"]["after"] == before

    document.write_text(SOURCE_B, encoding="utf-8")
    changed_run = acquire(root)
    assert only_result(changed_run)["status"] == dk_acquisition.STATUS_CHANGED
    assert changed_run["trusted_knowledge_mutations"] == []
    assert dk_core.knowledge_tree_digest(root) == before

    # Nothing the engine wrote lives in the trusted knowledge tree.
    assert sorted(path.name for path in (root / "knowledge" / "records").iterdir()) == [
        "sample.json"
    ]
    candidate = json.loads(
        next((root / "discovery" / "candidates").glob("*.json")).read_text()
    )
    assert candidate["can_promote_to_knowledge"] is False
    assert candidate["is_knowledge_proposal"] is False

print("AUTHORITATIVE_SOURCE_SNAPSHOT_NOT_AUTO_TRUSTED_KNOWLEDGE=PASS")
print("ACQUISITION_RUN_REPORTS_ZERO_TRUSTED_KNOWLEDGE_MUTATIONS=PASS")


# Dry run may fetch and compare but must not touch canonical state.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root, SOURCE_A)
    acquire(root)

    state_path = root / "sources" / "state" / "fixture-source.json"
    state_before = state_path.read_bytes()
    snapshots_before = sorted(
        path.name for path in (root / "sources" / "snapshots" / "fixture-source").iterdir()
    )
    knowledge_before = dk_core.knowledge_tree_digest(root)

    document.write_text(SOURCE_B, encoding="utf-8")
    inspection = root / "inspection"
    dry = only_result(acquire(root, dry_run=True, normalized_output=inspection))
    assert dry["status"] == dk_acquisition.STATUS_CHANGED, dry
    assert dry["dry_run"] is True
    assert dry["change_summary"]["deterministic"] is True

    assert state_path.read_bytes() == state_before
    assert (
        sorted(path.name for path in (root / "sources" / "snapshots" / "fixture-source").iterdir())
        == snapshots_before
    )
    assert not list((root / "discovery" / "candidates").glob("*.json"))
    assert dk_core.knowledge_tree_digest(root) == knowledge_before
    # Inspection output is real, it just lives outside canonical directories.
    assert (inspection / "fixture-source.txt").is_file()

# Inspection output and run reports cannot be aimed at canonical directories,
# so no flag turns a debugging aid into a write into evidence.
for protected in ("sources/state", "sources/snapshots", "discovery/candidates", "knowledge", "cases"):
    for flag in ("--normalized-output", "--report"):
        blocked = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "acquire",
                "--source",
                "drupal-api-11",
                "--dry-run",
                flag,
                f"{protected}/inspection",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert blocked.returncode == 2, (protected, flag, blocked.stdout)
        assert f"{flag} cannot write under {protected}" in blocked.stderr, blocked.stderr

requires_dry_run = subprocess.run(
    [
        sys.executable,
        str(CLI),
        "acquire",
        "--source",
        "drupal-api-11",
        "--normalized-output",
        "inspection",
    ],
    cwd=ROOT,
    capture_output=True,
    text=True,
    check=False,
)
assert requires_dry_run.returncode == 2
assert "--normalized-output requires --dry-run" in requires_dry_run.stderr

print("ACQUISITION_DRY_RUN_HAS_NO_CANONICAL_MUTATION=PASS")


# Targeted collection stays first class and shares one engine with the CLI and
# the scheduled entry point.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root, SOURCE_A)

    collected = subprocess.run(
        [sys.executable, str(COLLECTOR), "--source", "fixture-source", "--root", str(root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert collected.returncode == 0, collected.stderr
    assert "fixture-source: BASELINE " in collected.stdout

    targeted = only_result(acquire(root))
    assert targeted["status"] == dk_acquisition.STATUS_UNCHANGED, targeted

    # Scheduled selection is the same call with a different source filter, so
    # there is one acquisition behaviour rather than two.
    scheduled = dk_acquisition.acquire(root, trust="authoritative", due_only=False)
    assert [item["source_id"] for item in scheduled["results"]] == ["fixture-source"]
    assert only_result(scheduled)["status"] == dk_acquisition.STATUS_UNCHANGED
    assert scheduled["engine"] == {
        "name": dk_acquisition.ENGINE_NAME,
        "version": dk_acquisition.ENGINE_VERSION,
    }
    assert scheduled["trusted_knowledge_mutations"] == []

    # Selecting nothing at all is an error, never an implicit broad crawl.
    try:
        dk_acquisition.acquire(root)
    except dk_acquisition.AcquisitionInputError:
        pass
    else:
        raise AssertionError("acquisition ran without an explicit selection")

print("TARGETED_SOURCE_COLLECTION_PRESERVED=PASS")
print("MANUAL_AND_SCHEDULED_ACQUISITION_SHARE_ENGINE=PASS")


# Behaviour comes from the registry, not from branching on a source id.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root, SOURCE_A, normalization="raw_text")
    raw_result = only_result(acquire(root))
    raw_snapshot = dk_core.require_snapshot(
        root, "fixture-source", raw_result["current_snapshot_sha256"]
    ).read_text(encoding="utf-8")
    assert "<main>" in raw_snapshot
    assert raw_result["provenance"]["normalization"] == "raw_text"

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root, SOURCE_A, normalization="html_text")
    html_result = only_result(acquire(root))
    html_snapshot = dk_core.require_snapshot(
        root, "fixture-source", html_result["current_snapshot_sha256"]
    ).read_text(encoding="utf-8")
    assert "<main>" not in html_snapshot
    assert html_snapshot == "Drupal source revision A."

# The engine source itself must not special-case registered source ids.
engine_text = (ROOT / "scripts" / "dk_acquisition.py").read_text(encoding="utf-8")
for source in dk_core.load_sources():
    assert source["id"] not in engine_text, f"engine hardcodes source {source['id']}"

# A retired source is skipped by configuration, not by code.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root, SOURCE_A, lifecycle="retired")
    try:
        acquire(root)
    except dk_acquisition.AcquisitionInputError as exc:
        assert "source_retired" in str(exc), exc
    else:
        raise AssertionError("retired source was acquired")

print("SOURCE_BEHAVIOR_REGISTRY_DRIVEN=PASS")


# Provenance carries source identity and safe response metadata only.
with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    build_workspace(root, SOURCE_A)
    provenance = only_result(acquire(root))["provenance"]
    assert set(provenance) == set(dk_acquisition.PROVENANCE_FIELDS)
    assert provenance["acquisition_channel"] == "external_authoritative_source"
    assert provenance["acquired_by"]["name"] == dk_acquisition.ENGINE_NAME

    for forbidden in ("authorization", "cookie", "token", "secret", "password"):
        assert not any(forbidden in key.lower() for key in provenance)

    try:
        dk_acquisition.assert_provenance_safe({**provenance, "authorization": "Bearer x"})
    except dk_acquisition.AcquisitionEngineDefect:
        pass
    else:
        raise AssertionError("provenance accepted an authorization header")

    try:
        dk_acquisition.assert_provenance_safe(
            {**provenance, "canonical_url": "https://user:pass@example.invalid/x"}
        )
    except dk_acquisition.AcquisitionEngineDefect:
        pass
    else:
        raise AssertionError("provenance accepted embedded credentials")

    # A credential-bearing fetch url is refused before any request is made.
    try:
        dk_acquisition.fetch_source(
            {"id": "fixture-source", "url": "https://user:pass@example.invalid/x"}, 1
        )
    except dk_acquisition.SourceContractError:
        pass
    else:
        raise AssertionError("credential-bearing fetch url was accepted")

    assert (
        dk_acquisition.sanitize_detail("failed on /Users/someone/secret/path.txt")
        == "failed on <redacted-local-path>"
    )

print("ACQUISITION_PROVENANCE_EXCLUDES_SECRETS=PASS")


# Change detection and its summary are deterministic and model-free.
summary_one = dk_acquisition.build_change_summary("alpha\nbeta\n", "alpha\ngamma\n")
summary_two = dk_acquisition.build_change_summary("alpha\nbeta\n", "alpha\ngamma\n")
assert summary_one == summary_two
assert summary_one["method"] == "normalized_line_diff"
assert summary_one["added_sample"] == ["gamma"]
assert summary_one["removed_sample"] == ["beta"]
assert summary_one["first_changed_line"] == 2

# Detection is hashing plus a stdlib diff. Nothing in the engine reaches for a
# model, so a source change can always be decided offline and reproducibly.
engine_source = (ROOT / "scripts" / "dk_acquisition.py").read_text(encoding="utf-8")
for banned in ("openai", "anthropic", "llm", "prompt", "completion", "gpt", "inference"):
    assert not re.search(rf"\b{banned}\b", engine_source, re.IGNORECASE), (
        f"engine references {banned}"
    )
assert "import difflib" in engine_source and "import hashlib" in engine_source

print("SOURCE_CHANGE_DETECTION_DOES_NOT_REQUIRE_LLM=PASS")


# The engine reuses the architecture that already existed instead of standing
# up a parallel one.
assert dk_acquisition.STATE_RELATIVE_PATH == Path("sources") / "state"
assert dk_acquisition.CANDIDATES_RELATIVE_PATH == Path("discovery") / "candidates"
assert dk_acquisition.load_registry(ROOT) == dk_core.load_sources(ROOT)
engine_module = (ROOT / "scripts" / "dk_acquisition.py").read_text(encoding="utf-8")
assert "dk_core.write_snapshot" in engine_module
assert "dk_core.require_snapshot" in engine_module
assert not (ROOT / "sources" / "acquisition").exists(), "a second source tree appeared"
assert len(list((ROOT / "sources").glob("registry*.json"))) == 1

# The released interface surface advertises the acquisition contracts so a
# consumer can handshake on them.
released = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
)
assert released["interfaces"]["source_change_candidate_schema"] == "0.1"
assert (
    released["interfaces"]["acquisition_run_schema"]
    == dk_acquisition.ACQUISITION_RUN_SCHEMA_VERSION
)
assert released["acquisition_engine"]["name"] == dk_acquisition.ENGINE_NAME
assert released["acquisition_engine"]["channel"] == dk_acquisition.ACQUISITION_CHANNEL
# Interfaces released earlier keep their versions.
assert released["interfaces"]["solved_case_candidate_schema"] == "0.1"
assert released["interfaces"]["finding_evaluation_schema"] == "0.1"
assert released["interfaces"]["applicability_resolution_schema"] == "0.1"

print("EXISTING_DK_SOURCE_ARCHITECTURE_REUSED=PASS")


# ---------------------------------------------------------------------------
# A source the engine has never attempted, but which already carries a
# collector-era snapshot, is not a semantic change.
#
# `last_attempt_status == never_attempted` describes this engine's own history,
# not the source's content. Reconciling such a source must compare real hashes:
# it may report unchanged or changed, but it must never manufacture a first
# observation and must never invent a review candidate.
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root, SOURCE_A)

    # Stand in for a collector-era baseline: a snapshot and a state pointing at
    # it, with no acquisition block at all.
    normalized = dk_acquisition.normalized_text(
        SOURCE_A.encode("utf-8"), "text/html", {"id": "fixture-source"}
    )
    digest = dk_core.content_digest(normalized)
    dk_core.write_snapshot(root, "fixture-source", digest, normalized)
    write_json(
        root / "sources" / "state" / "fixture-source.json",
        {
            "source_id": "fixture-source",
            "url": document.as_uri(),
            "fetch_url": document.as_uri(),
            "content_sha256": digest,
            "content_length": len(normalized.encode("utf-8")),
            "etag": None,
            "last_modified": None,
            "last_changed_at": "2026-08-30T00:00:00Z",
        },
    )
    legacy_state = dk_core.read_json(root / "sources" / "state" / "fixture-source.json")
    assert "acquisition" not in legacy_state, "fixture must look collector-only"

    digest_before = dk_core.knowledge_tree_digest(root)
    reconciled = only_result(acquire(root))

    # Unchanged content stays unchanged, not "first observation" and not changed.
    assert reconciled["status"] == dk_acquisition.STATUS_UNCHANGED, reconciled
    assert reconciled["status"] != dk_acquisition.STATUS_FIRST_OBSERVATION
    assert reconciled["previous_snapshot_sha256"] == digest
    assert reconciled["current_snapshot_sha256"] == digest
    assert reconciled["snapshot"]["reused"] is True
    assert reconciled["snapshot"]["created"] is False
    print("FIRST_ENGINE_OBSERVATION_NOT_SOURCE_CHANGE=PASS")

    # No candidate was invented, and the pre-existing lineage is intact.
    assert reconciled["review_candidate"]["result"] == "none", reconciled["review_candidate"]
    assert reconciled["review_candidate"]["id"] is None
    assert dk_acquisition.iter_candidates(root) == []
    assert dk_core.require_snapshot(root, "fixture-source", digest).is_file()
    assert len(list((root / "sources" / "snapshots" / "fixture-source").glob("*.txt"))) == 1
    # The engine now records its own attempt history without rewriting content.
    state = dk_acquisition.load_state(root, "fixture-source")
    assert state["acquisition"]["last_attempt_status"] == dk_acquisition.STATUS_UNCHANGED
    assert state["content_sha256"] == digest
    assert dk_core.knowledge_tree_digest(root) == digest_before
    print("BASELINE_OBSERVATION_DOES_NOT_CREATE_FALSE_REVIEW_CANDIDATE=PASS")

    # A genuine content change on such a source is still detected as a change,
    # with the collector-era snapshot preserved as the superseded one.
    document.write_text(SOURCE_B, encoding="utf-8")
    changed = only_result(acquire(root))
    assert changed["status"] == dk_acquisition.STATUS_CHANGED, changed
    assert changed["previous_snapshot_sha256"] == digest
    assert changed["review_candidate"]["result"] == "created"
    assert dk_core.require_snapshot(root, "fixture-source", digest).is_file()
    assert dk_core.knowledge_tree_digest(root) == digest_before
    print("BASELINE_RECONCILIATION_STILL_DETECTS_REAL_CHANGE=PASS")
