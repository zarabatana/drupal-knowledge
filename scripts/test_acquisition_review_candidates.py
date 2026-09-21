#!/usr/bin/env python3
"""A source change creates review work, never knowledge.

The deterministic evolution proven here is the one the engine must survive:

    A -> A   no candidate
    A -> B   exactly one pending review candidate
    B -> B   the same candidate, never a duplicate

and through all of it the trusted knowledge tree stays byte-identical.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_acquisition
import dk_core
import dk_solved_case


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"

REVISION_A = "<html><body><main>Drupal source revision A.</main></body></html>"
REVISION_B = "<html><body><main>Drupal source revision B.</main></body></html>"


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


def build_workspace(root: Path, content: str) -> Path:
    document = root / "fixture.html"
    document.write_text(content, encoding="utf-8")
    write_json(
        root / "sources" / "registry.json",
        [
            {
                "id": "fixture-source",
                "title": "Fixture Source",
                "url": document.as_uri(),
                "trust": "authoritative",
                "enabled": True,
                "category": "security",
                "role": "Fixture source used by review candidate tests.",
                "collection_strategy": "change-detection",
                "check_cadence_days": 1,
                "lifecycle": "active",
                "checked_on": "2026-08-30",
                "provenance": "Local test fixture.",
                "version_semantics": {},
            }
        ],
    )
    write_json(
        root / "knowledge" / "records" / "sample.json",
        {
            "id": "drupal.fixture.sample",
            "review_status": "reviewed",
            "enforcement": {"intent": "blocking"},
            "value": "trusted knowledge must not change",
        },
    )
    return document


def acquire(root: Path, **kwargs) -> dict:
    return dk_acquisition.acquire(root, source_ids=["fixture-source"], **kwargs)


def candidates(root: Path) -> list[Path]:
    return sorted((root / "discovery" / "candidates").glob("*.json"))


with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root, REVISION_A)
    knowledge_digest = dk_core.knowledge_tree_digest(root)

    # A -> A: repeat acquisition of identical content creates no review work.
    acquire(root)
    assert candidates(root) == []
    acquire(root)
    assert candidates(root) == []
    assert dk_core.knowledge_tree_digest(root) == knowledge_digest

    # A -> B: exactly one pending candidate, carrying its own evidence.
    document.write_text(REVISION_B, encoding="utf-8")
    changed_run = acquire(root)
    assert len(candidates(root)) == 1, candidates(root)
    assert len(changed_run["review_candidates_created"]) == 1
    candidate_path = candidates(root)[0]
    candidate = json.loads(candidate_path.read_text())
    candidate_id = candidate["id"]
    assert candidate_path.name == f"{candidate_id}.json"
    assert candidate["review_state"] == dk_acquisition.REVIEW_PENDING
    assert candidate["status"] == "review_required"
    assert candidate["review_required"] is True
    assert candidate["review"] is None
    assert candidate["kind"] == "security-source-change"
    assert candidate["source_id"] == "fixture-source"
    assert candidate["trust"] == "authoritative"
    assert candidate["previous_hash"] != candidate["current_hash"]
    assert candidate["engine_version"] == dk_acquisition.ENGINE_VERSION
    assert candidate["run_id"] == changed_run["run_id"]
    assert candidate["change_summary"]["added_line_count"] >= 1
    assert candidate["provenance"]["acquisition_channel"] == "external_authoritative_source"
    assert dk_core.knowledge_tree_digest(root) == knowledge_digest

    # B -> B: the same content again is unchanged and never duplicates work.
    repeat = acquire(root)
    assert repeat["results"][0]["status"] == dk_acquisition.STATUS_UNCHANGED
    assert repeat["review_candidates_created"] == []
    assert candidates(root) == [candidate_path]
    assert json.loads(candidate_path.read_text()) == candidate

    # Even oscillating back and forth reuses the deterministic identity rather
    # than accumulating one candidate per observation.
    document.write_text(REVISION_A, encoding="utf-8")
    acquire(root)
    document.write_text(REVISION_B, encoding="utf-8")
    forward_again = acquire(root)
    assert forward_again["review_candidates_reused"] == [candidate_id], forward_again
    assert len(candidates(root)) == 2, "A->B and B->A are different changes"
    assert dk_core.knowledge_tree_digest(root) == knowledge_digest

print("SOURCE_CHANGE_CREATES_REVIEW_CANDIDATE=PASS")
print("SOURCE_CHANGE_REVIEW_CANDIDATE_IDEMPOTENT=PASS")


# Every review outcome leaves trusted knowledge exactly as it was, and none of
# them creates a knowledge proposal or a blocking rule.
for outcome in sorted(dk_acquisition.REVIEW_TERMINAL_STATES):
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        document = build_workspace(root, REVISION_A)
        acquire(root)
        document.write_text(REVISION_B, encoding="utf-8")
        acquire(root)

        candidate_id = json.loads(candidates(root)[0].read_text())["id"]
        before = dk_core.knowledge_tree_digest(root)
        knowledge_files_before = sorted(
            path.name for path in (root / "knowledge" / "records").iterdir()
        )

        result = dk_acquisition.review_candidate(
            root,
            candidate_id,
            review_state=outcome,
            actor="miguel",
            method="human_source_diff_review",
            note="fixture review",
        )
        assert result["review_state"] == outcome
        assert result["trusted_knowledge_mutations"] == []
        assert result["trusted_knowledge_digest_before"] == before
        assert result["trusted_knowledge_digest_after"] == before

        reviewed = json.loads(candidates(root)[0].read_text())
        assert reviewed["review_state"] == outcome
        assert reviewed["review"]["actor"] == "miguel"
        assert reviewed["review"]["outcome"] == outcome
        assert reviewed["review"]["trusted_knowledge_changed"] is False
        assert reviewed["is_knowledge_proposal"] is False
        assert reviewed["can_promote_to_knowledge"] is False
        assert (
            reviewed["review"]["authorizes_knowledge_proposal_work"]
            is (outcome == dk_acquisition.REVIEW_REQUIRES_PROPOSAL)
        )

        # No knowledge record appeared, changed, or gained blocking authority.
        assert dk_core.knowledge_tree_digest(root) == before
        assert (
            sorted(path.name for path in (root / "knowledge" / "records").iterdir())
            == knowledge_files_before
        )

        # A reviewed candidate is not re-reviewable by accident.
        try:
            dk_acquisition.review_candidate(
                root,
                candidate_id,
                review_state=dk_acquisition.REVIEW_NO_KNOWLEDGE_CHANGE,
                actor="miguel",
                method="human_source_diff_review",
            )
        except dk_acquisition.AcquisitionInputError:
            pass
        else:
            raise AssertionError("a settled candidate was silently re-reviewed")

print("REVIEW_CANDIDATE_NOT_KNOWLEDGE_PROPOSAL=PASS")
print("SOURCE_CHANGE_CANNOT_BYPASS_HUMAN_REVIEW=PASS")


# The CLI exposes review without ever exposing a way to accept a source change
# into trusted knowledge.
cli_help = subprocess.run(
    [sys.executable, str(CLI), "review-candidates", "review", "--help"],
    cwd=ROOT,
    capture_output=True,
    text=True,
    check=False,
)
assert cli_help.returncode == 0, cli_help.stderr
for forbidden in (
    "--accept-and-update-knowledge",
    "--auto-trust",
    "--promote",
    "--apply-to-knowledge",
):
    assert forbidden not in cli_help.stdout, f"CLI exposes {forbidden}"
assert "--state" in cli_help.stdout and "--actor" in cli_help.stdout

cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
for forbidden in ("accept-and-update-knowledge", "auto_trust", "auto-trust"):
    assert forbidden not in cli_source, f"CLI defines {forbidden}"

print("NO_AUTO_TRUST_INTERFACE=PASS")


# External source provenance and internal solved-case provenance stay separate
# channels with separate storage and separate producers.
assert dk_acquisition.ACQUISITION_CHANNEL == "external_authoritative_source"
assert dk_acquisition.ENGINE_NAME == "drupal-knowledge-acquisition-engine"
assert dk_solved_case.CAPTURE_NAME == "drupal-knowledge-solved-case-capture"
assert dk_acquisition.ENGINE_NAME != dk_solved_case.CAPTURE_NAME
assert (
    dk_acquisition.CANDIDATES_RELATIVE_PATH != dk_solved_case.CASES_RELATIVE_PATH
), "acquisition and solved cases must not share storage"

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    document = build_workspace(root, REVISION_A)
    acquire(root)
    document.write_text(REVISION_B, encoding="utf-8")
    acquire(root)
    candidate = json.loads(candidates(root)[0].read_text())

    # An acquisition candidate carries no solved-case identity, and its
    # provenance never claims internal proof.
    assert "case_identity" not in json.dumps(candidate)
    assert candidate["trust"] == "authoritative"
    assert candidate["trust"] != "internal-proven"
    assert candidate["provenance"]["acquired_by"]["name"] == dk_acquisition.ENGINE_NAME
    assert not (root / "cases" / "solved").exists()

print("EXTERNAL_SOURCE_AND_SOLVED_CASE_PROVENANCE_REMAIN_DISTINCT=PASS")
