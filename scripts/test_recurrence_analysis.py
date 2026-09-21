#!/usr/bin/env python3
"""Recurrence counts proven occurrences, and only proven ones.

The scenarios are the ones worth getting right: two genuinely independent
verified cases, the same project recaptured, a similar-looking case with a
different cause, aligned cases on incompatible versions, contradictory
evidence, and a case that was never verified at all.
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
from pathlib import Path

import dk_core
import dk_generalization
import dk_solved_case


ROOT = dk_core.ROOT
FIXTURE = ROOT / "tests" / "fixtures" / "solved-case" / "toolchain-module-resolution.candidate.json"
BASE = json.loads(FIXTURE.read_text(encoding="utf-8"))


def workspace(path: Path) -> Path:
    """A temp DK root carrying the contracts and a trusted-knowledge record."""
    shutil.copytree(ROOT / "schema", path / "schema")
    records = path / "knowledge" / "records"
    records.mkdir(parents=True)
    (records / "sample.json").write_text(
        dk_core.stable_json({"id": "drupal.fixture.sample", "value": "must not change"}),
        encoding="utf-8",
    )
    return path


def candidate(
    *,
    project: str,
    revision: str = "a" * 64,
    state: str = "verified",
    root_cause: str | None = None,
    core_version: str = "11.4.5",
    package_version: str = "11.4.5",
    package_name: str = "drupal/core",
    failed_result: bool = False,
    title: str | None = None,
) -> dict:
    item = copy.deepcopy(BASE)
    item["state"] = state
    if title:
        item["title"] = title
    item["project_context"]["project_fingerprint"] = f"sha256:{project}"
    item["project_context"]["revision_fingerprint"] = f"sha256:{revision}"
    item["project_context"]["drupal_core_version"] = core_version
    item["project_context"]["packages"] = [{"name": package_name, "version": package_version}]
    item["applicability"]["proven_on"]["drupal_core_versions"] = [core_version]
    if root_cause:
        item["root_cause"]["statement"] = root_cause
    if failed_result:
        # A verified case may still record that the fix did not hold somewhere.
        item["verification"]["results"].append(
            {
                "method": "reproduction_before_and_after",
                "outcome": "failed",
                "evidence_ref": "second reproduction attempt",
                "detail": "The symptom reappeared under otherwise matching conditions.",
            }
        )
    return item


def capture_all(root: Path, candidates: list[dict]) -> list[str]:
    stored = []
    for item in candidates:
        result = dk_solved_case.capture(item, root=root)
        assert result["stored"] is True, result
        stored.append(result["case_id"])
    assert len(set(stored)) == len(stored), f"fixture cases collided: {stored}"
    return stored


def only_analysis(run: dict) -> dict:
    assert len(run["recurrence_analyses"]) == 1, run["recurrence_analyses"]
    return run["recurrence_analyses"][0]


DIFFERENT_CAUSE = (
    "A configuration cache entry retained a stale service definition, so the "
    "entry point resolved a service that no longer matched the container."
)


# ---------------------------------------------------------------------------
# Case A + B: two independent verified cases with aligned evidence
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    case_a, case_b = capture_all(
        root,
        [candidate(project="a" * 64), candidate(project="b" * 64)],
    )
    before = dk_core.knowledge_tree_digest(root)

    run = dk_generalization.analyze(root)
    entry = only_analysis(run)
    analysis = dk_generalization.load_analysis(root, entry["id"])

    assert sorted(analysis["case_ids"]) == sorted([case_a, case_b]), analysis["case_ids"]
    assert analysis["independent_occurrences"]["count"] == 2, analysis["independent_occurrences"]
    assert analysis["independent_occurrences"]["duplicate_capture_count"] == 0
    assert analysis["shared_dimensions"]["root_cause_aligned"] is True
    assert analysis["contradictory_cases"] == []
    assert analysis["applicability_conflicts"] == []

    # Recurrence is not generalization and not knowledge.
    assert analysis["is_generalization"] is False
    assert analysis["is_trusted_knowledge"] is False
    assert analysis["review_required"] is True
    assert dk_core.knowledge_tree_digest(root) == before
    assert run["trusted_knowledge_mutations"] == []
    print("CASE_A_PLUS_B=recurrence_observed")

    # Two independent occurrences warrant a proposal, which is still a question.
    assert len(run["generalization_proposals"]) == 1, run["generalization_proposals"]
    proposal = dk_generalization.load_proposal(root, run["generalization_proposals"][0]["id"])
    assert proposal["review_state"] == dk_generalization.REVIEW_PENDING
    assert proposal["is_trusted_knowledge"] is False
    assert proposal["is_knowledge_record"] is False
    assert proposal["can_promote_to_knowledge"] is False
    assert proposal["generalizes_automatically"] is False
    assert proposal["proposed_statement"]["asserts_universal_truth"] is False
    assert proposal["evidence_confidence"]["count_alone_is_sufficient"] is False
    assert dk_core.knowledge_tree_digest(root) == before
    print("GENERALIZATION_PROPOSAL_NOT_TRUSTED_KNOWLEDGE=PASS")

    # Repeating the analysis over unchanged cases changes nothing at all.
    analysis_bytes = dk_generalization.recurrence_path(root, entry["id"]).read_bytes()
    proposal_bytes = dk_generalization.proposal_path(root, proposal["id"]).read_bytes()
    again = dk_generalization.analyze(root)
    assert only_analysis(again)["id"] == entry["id"]
    assert only_analysis(again)["result"] == "reused"
    assert again["generalization_proposals"][0]["result"] == "reused"
    assert dk_generalization.recurrence_path(root, entry["id"]).read_bytes() == analysis_bytes
    assert dk_generalization.proposal_path(root, proposal["id"]).read_bytes() == proposal_bytes
    assert len(dk_generalization.iter_analyses(root)) == 1
    assert len(dk_generalization.iter_proposals(root)) == 1
    print("RECURRENCE_ANALYSIS_IDEMPOTENT=PASS")
    print("GENERALIZATION_PROPOSAL_IDEMPOTENT=PASS")


# ---------------------------------------------------------------------------
# Case A recaptured: one project is one occurrence
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))

    # Capturing identical evidence twice collapses at the case layer: solved-case
    # identity already refuses to record one place twice.
    first = candidate(project="a" * 64, revision="1" * 64)
    assert dk_solved_case.capture(first, root=root)["result"] == "created"
    assert dk_solved_case.capture(copy.deepcopy(first), root=root)["result"] == "unchanged"
    assert len(dk_core.load_solved_cases(root)) == 1

    # Two distinct cases can still share one project fingerprint - here the same
    # project upgraded across core versions. Recurrence must count that as one
    # place, not two.
    capture_all(
        root,
        [candidate(project="a" * 64, revision="2" * 64, core_version="11.4.6")],
    )
    assert len(dk_core.load_solved_cases(root)) == 2
    run = dk_generalization.analyze(root)
    analysis = dk_generalization.load_analysis(root, only_analysis(run)["id"])

    assert len(analysis["case_ids"]) == 2, analysis["case_ids"]
    assert analysis["independent_occurrences"]["count"] == 1, analysis["independent_occurrences"]
    assert analysis["independent_occurrences"]["duplicate_capture_count"] == 1
    assert analysis["independent_occurrences"]["revision_count"] == 2
    duplicates = [
        item for item in analysis["excluded_cases"] if item["reason"] == "duplicate_occurrence"
    ]
    assert len(duplicates) == 1, analysis["excluded_cases"]

    # One place, however many captures, cannot support a generalization.
    assert run["generalization_proposals"] == [], run["generalization_proposals"]
    assert any(
        item["reason"] == "insufficient_independent_occurrences" for item in run["skipped"]
    ), run["skipped"]
    print("CASE_A_REPEATED=no_additional_occurrence")
    print("RECURRENCE_COUNTS_INDEPENDENT_OCCURRENCES=PASS")


# ---------------------------------------------------------------------------
# Case C: similar symptoms, different root cause
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    capture_all(
        root,
        [
            candidate(project="a" * 64),
            candidate(project="b" * 64),
            # Same title and symptoms, genuinely different cause.
            candidate(project="c" * 64, root_cause=DIFFERENT_CAUSE),
        ],
    )
    run = dk_generalization.analyze(root)

    # The aligned pair groups; the different cause does not join it.
    aligned = [item for item in run["recurrence_analyses"] if len(item["case_ids"]) == 2]
    assert len(aligned) == 1, run["recurrence_analyses"]
    analysis = dk_generalization.load_analysis(root, aligned[0]["id"])
    assert analysis["independent_occurrences"]["count"] == 2

    joined = {case_id for item in run["recurrence_analyses"] for case_id in item["case_ids"]}
    outlier = [
        item["case_ids"] for item in run["skipped"] if item["reason"] == "single_case_group"
    ]
    assert outlier, run["skipped"]
    assert len(joined) == 2, "a different root cause must not join the group"
    print("CASE_C=not_grouped_on_similarity")
    print("SIMILAR_CASES_NOT_AUTOMATICALLY_GROUPED=PASS")
    print("RECURRENCE_REQUIRES_STRUCTURAL_EVIDENCE=PASS")


# ---------------------------------------------------------------------------
# Case D: aligned cause and fix, incompatible version scope
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    capture_all(
        root,
        [
            candidate(project="a" * 64, core_version="11.4.5", package_version="11.4.5"),
            # Same cause and fix, proven on a different Drupal major.
            candidate(project="d" * 64, core_version="10.6.9", package_version="10.6.9"),
        ],
    )
    run = dk_generalization.analyze(root)
    analysis = dk_generalization.load_analysis(root, only_analysis(run)["id"])

    kinds = {item["kind"] for item in analysis["applicability_conflicts"]}
    assert "incompatible_drupal_major" in kinds, analysis["applicability_conflicts"]
    assert sorted(analysis["observed_scope"]["drupal_core_majors"]) == ["10", "11"]

    proposal = dk_generalization.load_proposal(root, run["generalization_proposals"][0]["id"])
    # Scope stays exactly what was observed. It is never widened to a range.
    assert proposal["proposed_applicability"]["claimed_scope"] == "observed_cases_only"
    assert sorted(proposal["proposed_applicability"]["drupal_core_versions"]) == [
        "10.6.9",
        "11.4.5",
    ]
    assert proposal["proposed_applicability"]["expansion_requires_review"] is True
    assert proposal["evidence_confidence"]["scope_conflict_present"] is True
    assert proposal["evidence_confidence"]["grade"] == dk_generalization.CONFIDENCE_WEAK
    assert (
        proposal["eligibility"]["recommended_review_state"]
        == dk_generalization.REVIEW_NARROW_SCOPE
    )
    assert any("Scope conflict" in item for item in proposal["proposed_limitations"])
    print("CASE_D=scope_limited_not_generalized")
    print("GENERALIZATION_SCOPE_BOUNDED_BY_OBSERVED_CASES=PASS")


# ---------------------------------------------------------------------------
# Case E: contradictory verified evidence stays visible
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    ids = capture_all(
        root,
        [
            candidate(project="a" * 64),
            candidate(project="b" * 64),
            candidate(project="e" * 64, failed_result=True),
        ],
    )
    run = dk_generalization.analyze(root)
    analysis = dk_generalization.load_analysis(root, only_analysis(run)["id"])

    contradictory = [item["case_id"] for item in analysis["contradictory_cases"]]
    assert contradictory == [ids[2]], analysis["contradictory_cases"]
    # It is retained in the group, not dropped from it.
    assert ids[2] in analysis["case_ids"]
    assert analysis["verification_quality"]["failed_result_count"] == 1
    assert analysis["verification_quality"]["grade"] == dk_generalization.GRADE_WEAK
    assert any("failed verification" in item for item in analysis["limitations"])

    proposal = dk_generalization.load_proposal(root, run["generalization_proposals"][0]["id"])
    assert proposal["contradictory_case_ids"] == [ids[2]]
    assert proposal["evidence_confidence"]["contradiction_present"] is True
    assert proposal["evidence_confidence"]["grade"] == dk_generalization.CONFIDENCE_WEAK
    assert (
        proposal["eligibility"]["recommended_review_state"]
        == dk_generalization.REVIEW_NEEDS_MORE_EVIDENCE
    )
    assert "no_contradictory_case" in proposal["eligibility"]["unmet_conditions"]
    print("CASE_E=contradiction_visible")
    print("CONTRADICTORY_SOLVED_CASES_FIRST_CLASS=PASS")


# ---------------------------------------------------------------------------
# A captured case is not evidence of anything recurring
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    ids = capture_all(
        root,
        [
            candidate(project="a" * 64),
            candidate(project="f" * 64, state="captured"),
        ],
    )
    run = dk_generalization.analyze(root)

    assert run["cases_eligible"] == [ids[0]], run["cases_eligible"]
    assert run["cases_excluded_unverified"] == [ids[1]], run["cases_excluded_unverified"]
    # Only one verified case remains, so there is nothing recurring at all.
    assert run["recurrence_analyses"] == [], run["recurrence_analyses"]
    assert run["generalization_proposals"] == []

    captured = dk_solved_case.load_case(root, ids[1])
    assert captured["status"] == "captured"
    assert dk_generalization.case_is_verified(captured) is False
    print("CAPTURED_ONLY_CASE=not_recurrence_evidence")
    print("UNVERIFIED_CASE_NOT_RECURRENCE_EVIDENCE=PASS")


# ---------------------------------------------------------------------------
# A captured case that matches structurally is excluded, not hidden
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    ids = capture_all(
        root,
        [
            candidate(project="a" * 64),
            candidate(project="b" * 64),
            candidate(project="0" * 64, state="captured"),
        ],
    )
    run = dk_generalization.analyze(root)
    analysis = dk_generalization.load_analysis(root, only_analysis(run)["id"])

    unverified = [
        item for item in analysis["excluded_cases"] if item["reason"] == "not_verified"
    ]
    assert [item["case_id"] for item in unverified] == [ids[2]], analysis["excluded_cases"]
    assert ids[2] not in analysis["case_ids"]
    assert analysis["independent_occurrences"]["count"] == 2
    print("UNVERIFIED_CASE_EXCLUDED_NOT_HIDDEN=PASS")

print("RECURRENCE_ANALYSIS_TESTS=PASS")
