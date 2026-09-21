#!/usr/bin/env python3
"""Generalization ends at human review, and review never touches knowledge.

These are the boundary tests: what a count is allowed to prove on its own, what
a reviewer may decide, which evidence channels may contribute, and what a
generalization artifact is permitted to reveal about a customer project.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_core
import dk_discovery
import dk_generalization
import dk_solved_case

from test_recurrence_analysis import candidate, capture_all, workspace


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"


def prepared(root: Path, **kwargs) -> tuple[str, dict]:
    """Two independent aligned verified cases and their proposal."""
    capture_all(
        root,
        [candidate(project="a" * 64, **kwargs), candidate(project="b" * 64, **kwargs)],
    )
    run = dk_generalization.analyze(root)
    proposal_id = run["generalization_proposals"][0]["id"]
    return proposal_id, run


# ---------------------------------------------------------------------------
# Every review outcome leaves trusted knowledge byte-identical
# ---------------------------------------------------------------------------

for outcome in dk_generalization.REVIEW_OUTCOMES:
    with tempfile.TemporaryDirectory() as tmp:
        root = workspace(Path(tmp))
        proposal_id, _ = prepared(root)

        before = dk_core.knowledge_tree_digest(root)
        records_before = {
            path.name: path.read_bytes()
            for path in (root / "knowledge" / "records").glob("*.json")
        }

        result = dk_generalization.review_proposal(
            root,
            proposal_id,
            outcome=outcome,
            actor="reviewer@example.invalid",
            method="human_generalization_review",
            note="fixture review",
        )

        records_after = {
            path.name: path.read_bytes()
            for path in (root / "knowledge" / "records").glob("*.json")
        }
        assert dk_core.knowledge_tree_digest(root) == before, f"{outcome} changed knowledge"
        assert records_before == records_after, f"{outcome} rewrote a knowledge record"
        assert result["trusted_knowledge_changed"] is False
        assert result["knowledge_record_created"] is False
        assert result["trusted_knowledge_digest"]["before"] == result[
            "trusted_knowledge_digest"
        ]["after"]

        proposal = dk_generalization.load_proposal(root, proposal_id)
        assert proposal["review_state"] == outcome
        assert proposal["review"]["outcome"] == outcome
        assert proposal["review"]["trusted_knowledge_changed"] is False
        assert proposal["review"]["knowledge_record_created"] is False
        assert proposal["is_trusted_knowledge"] is False
        assert proposal["is_knowledge_record"] is False
        assert proposal["can_promote_to_knowledge"] is False

        # Accepting for proposal work authorises work, and creates nothing.
        expected = outcome == dk_generalization.REVIEW_ACCEPTED
        assert proposal["review"]["authorizes_knowledge_proposal_work"] is expected
        assert result["authorizes_knowledge_proposal_work"] is expected
        if expected:
            assert len(list((root / "knowledge" / "records").glob("*.json"))) == len(
                records_before
            )
            assert not (root / "knowledge" / "proposals").exists()

print("GENERALIZATION_REVIEW_LEAVES_KNOWLEDGE_UNCHANGED=PASS")
print("KNOWLEDGE_PROPOSAL_NOT_AUTO_PROMOTED=PASS")


# ---------------------------------------------------------------------------
# Nothing reaches a reviewed state without a human
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    proposal_id, _ = prepared(root)

    assert (
        dk_generalization.load_proposal(root, proposal_id)["review_state"]
        == dk_generalization.REVIEW_PENDING
    )
    # Re-analyzing cannot advance review state.
    dk_generalization.analyze(root)
    proposal = dk_generalization.load_proposal(root, proposal_id)
    assert proposal["review_state"] == dk_generalization.REVIEW_PENDING
    assert proposal["review"] is None
    # The engine's recommendation is a suggestion, never the state itself.
    assert proposal["eligibility"]["recommended_review_state"] in (
        dk_generalization.REVIEW_PENDING,
        dk_generalization.REVIEW_NEEDS_MORE_EVIDENCE,
        dk_generalization.REVIEW_NARROW_SCOPE,
    )

    for bad_actor in ("", "   "):
        try:
            dk_generalization.review_proposal(
                root, proposal_id, outcome=dk_generalization.REVIEW_REJECTED, actor=bad_actor
            )
        except dk_generalization.GeneralizationInputError:
            pass
        else:
            raise AssertionError("review accepted an anonymous actor")

    for bad_outcome in ("promoted", "trusted", "accepted_for_knowledge", "approved"):
        try:
            dk_generalization.review_proposal(
                root, proposal_id, outcome=bad_outcome, actor="reviewer@example.invalid"
            )
        except dk_generalization.GeneralizationInputError:
            pass
        else:
            raise AssertionError(f"review accepted invented outcome {bad_outcome}")

print("GENERALIZATION_CANNOT_BYPASS_HUMAN_REVIEW=PASS")


# ---------------------------------------------------------------------------
# An occurrence count is never proof on its own
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    # Five independent occurrences, but each records a failed verification.
    capture_all(
        root,
        [
            candidate(project=char * 64, failed_result=True)
            for char in ("a", "b", "c", "d", "e")
        ],
    )
    run = dk_generalization.analyze(root)
    analysis = dk_generalization.load_analysis(root, run["recurrence_analyses"][0]["id"])
    proposal = dk_generalization.load_proposal(root, run["generalization_proposals"][0]["id"])

    assert analysis["independent_occurrences"]["count"] == 5
    confidence = proposal["evidence_confidence"]
    # Five is more than any threshold anyone might have hard-coded, and it still
    # does not make this strong.
    assert confidence["independent_occurrence_count"] == 5
    assert confidence["grade"] == dk_generalization.CONFIDENCE_WEAK, confidence
    assert confidence["count_alone_is_sufficient"] is False
    assert proposal["review_state"] == dk_generalization.REVIEW_PENDING
    assert (
        proposal["eligibility"]["recommended_review_state"]
        == dk_generalization.REVIEW_NEEDS_MORE_EVIDENCE
    )

    # The engine carries no bare count threshold that decides truth.
    engine = (ROOT / "scripts" / "dk_generalization.py").read_text(encoding="utf-8")
    assert "count_alone_is_sufficient" in engine
    assert not re.search(r"count\s*>=\s*3", engine)
    assert not re.search(r"if\s+.*count.*:\s*\n\s*return\s+True", engine)

print("RECURRENCE_COUNT_NOT_AUTOMATIC_TRUTH_THRESHOLD=PASS")


# ---------------------------------------------------------------------------
# Discovery evidence is a different channel and is never an occurrence
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    capture_all(root, [candidate(project="a" * 64)])

    # A discovery signal about the same component, sitting right there on disk.
    signals = root / "discovery" / "signals"
    signals.mkdir(parents=True)
    (signals / "signal.drupal.fixture-source.aaaaaaaaaaaaaaaa.json").write_text(
        dk_core.stable_json({"id": "signal.drupal.fixture-source.aaaaaaaaaaaaaaaa"}),
        encoding="utf-8",
    )

    run = dk_generalization.analyze(root)
    assert run["cases_considered"] == run["cases_eligible"]
    assert len(run["cases_considered"]) == 1
    assert run["discovery_signals_counted"] == 0
    # One verified case plus one discovery signal is still one occurrence.
    assert run["recurrence_analyses"] == [], run["recurrence_analyses"]
    assert run["generalization_proposals"] == []

    # The engine reads the solved-case tree and nothing else.
    engine = (ROOT / "scripts" / "dk_generalization.py").read_text(encoding="utf-8")
    assert "discovery/signals" not in engine
    assert "iter_signals" not in engine
    assert "dk_discovery" not in engine
    assert dk_generalization.EVIDENCE_CHANNEL != dk_discovery.DISCOVERY_CHANNEL
    assert dk_generalization.EVIDENCE_CHANNEL == dk_discovery.SOLVED_CASE_CHANNEL

print("DISCOVERY_SIGNAL_NOT_COUNTED_AS_SOLVED_CASE_RECURRENCE=PASS")


# ---------------------------------------------------------------------------
# Authoritative support may be attached without rewriting case provenance
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    case_ids = capture_all(
        root,
        [candidate(project="a" * 64), candidate(project="b" * 64)],
    )
    run = dk_generalization.analyze(root)
    proposal_id = run["generalization_proposals"][0]["id"]

    cases_before = {
        case_id: dk_solved_case.load_case(root, case_id) for case_id in case_ids
    }

    proposal = dk_generalization.load_proposal(root, proposal_id)
    proposal["provenance"]["authoritative_support"] = [
        {
            "source_id": "drupal-core-releases",
            "relation": "supports",
            "detail": "Authoritative release metadata is consistent with the observed scope.",
            "rewrites_case_provenance": False,
        }
    ]
    dk_generalization.validate_proposal(proposal)
    dk_generalization.proposal_path(root, proposal_id).write_text(
        dk_generalization.stable_json(proposal), encoding="utf-8"
    )

    # The cases behind it are untouched, and still internal-proven.
    for case_id, before in cases_before.items():
        assert dk_solved_case.load_case(root, case_id) == before, case_id
    stored = dk_generalization.load_proposal(root, proposal_id)
    assert stored["provenance"]["evidence_channel"] == dk_generalization.EVIDENCE_CHANNEL
    assert stored["provenance"]["authoritative_support"][0]["rewrites_case_provenance"] is False

    # A support entry claiming to rewrite provenance is refused outright.
    bad = copy.deepcopy(stored)
    bad["provenance"]["authoritative_support"][0]["rewrites_case_provenance"] = True
    try:
        dk_generalization.validate_proposal(bad)
    except dk_core.ValidationError:
        pass
    else:
        raise AssertionError("authoritative support was allowed to rewrite case provenance")

print("AUTHORITATIVE_SUPPORT_DOES_NOT_REWRITE_CASE_PROVENANCE=PASS")


# ---------------------------------------------------------------------------
# Project identity stays minimized
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    proposal_id, run = prepared(root)
    analysis = dk_generalization.load_analysis(root, run["recurrence_analyses"][0]["id"])
    proposal = dk_generalization.load_proposal(root, proposal_id)

    for artifact in (analysis, proposal):
        serialized = dk_generalization.stable_json(artifact)
        # Fingerprints only: no names, paths, domains, emails or secrets.
        assert "/Users/" not in serialized
        assert "@example.invalid" not in serialized or artifact is proposal
        for forbidden in ("project_name", "site_name", "hostname", "customer", "client"):
            assert forbidden not in serialized, forbidden
        assert artifact["provenance"]["project_identity_exposed"] is False

    for occurrence in analysis["supporting_cases"]:
        assert re.fullmatch(r"sha256:[a-f0-9]{64}", occurrence["project_fingerprint"])
        revision = occurrence["revision_fingerprint"]
        assert revision is None or re.fullmatch(r"sha256:[a-f0-9]{64}", revision)

    # An artifact carrying an identifying field is refused.
    leaky = copy.deepcopy(analysis)
    leaky["project_name"] = "acme-corp"
    try:
        dk_generalization.validate_analysis(leaky)
    except dk_core.ValidationError:
        pass
    else:
        raise AssertionError("an identifying field was accepted")

    pathy = copy.deepcopy(analysis)
    pathy["limitations"] = list(pathy["limitations"]) + ["/Users/someone/sites/acme"]
    try:
        dk_generalization.validate_analysis(pathy)
    except dk_core.ValidationError:
        pass
    else:
        raise AssertionError("a local machine path was accepted")

print("GENERALIZATION_PROVENANCE_MINIMIZES_PROJECT_IDENTITY=PASS")


# ---------------------------------------------------------------------------
# Dry run writes nothing
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = workspace(Path(tmp))
    capture_all(root, [candidate(project="a" * 64), candidate(project="b" * 64)])

    run = dk_generalization.analyze(root, dry_run=True)
    assert run["dry_run"] is True
    assert run["recurrence_analyses"][0]["result"] == "dry_run"
    assert run["generalization_proposals"][0]["result"] == "dry_run"
    assert dk_generalization.iter_analyses(root) == []
    assert dk_generalization.iter_proposals(root) == []
    assert run["trusted_knowledge_mutations"] == []

print("RECURRENCE_DRY_RUN_HAS_NO_CANONICAL_MUTATION=PASS")


# ---------------------------------------------------------------------------
# The existing solved-case architecture is reused, not replaced
# ---------------------------------------------------------------------------

engine = (ROOT / "scripts" / "dk_generalization.py").read_text(encoding="utf-8")
assert "import dk_solved_case" in engine
assert "dk_core.load_solved_cases" in engine
# No second case store, no second capture path, no second verification model.
assert "def capture(" not in engine
assert "def build_case_record(" not in engine
assert 'Path("cases") / "solved"' not in engine
assert dk_generalization.CASE_SOURCE == "cases/solved"
# Recurrence reuses the case lifecycle vocabulary rather than inventing one.
case_schema = json.loads((ROOT / "schema" / "solved-case.schema.json").read_text())
statuses = set(case_schema["properties"]["status"]["enum"])
assert {"captured", "verified", "recurring", "generalization_proposed"} <= statuses
print("EXISTING_SOLVED_CASE_ARCHITECTURE_REUSED=PASS")


# ---------------------------------------------------------------------------
# No CLI route from a proposal to trusted knowledge
# ---------------------------------------------------------------------------

# Default help is community-first, so maintainer commands are listed by
# `--help-all`. They stay reachable either way; what is checked here is that
# none of them offers a route across a trust boundary.
help_text = subprocess.run(
    [sys.executable, str(CLI), "--help-all"], capture_output=True, text=True, check=True
).stdout
for command in ("recurrence", "generalizations", "generalization-review"):
    assert command in help_text, f"missing CLI command: {command}"
    text = subprocess.run(
        [sys.executable, str(CLI), command, "--help"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for forbidden in (
        "--promote-to-knowledge",
        "--promote",
        "--trust-this",
        "--accept-and-update-knowledge",
        "--create-knowledge",
    ):
        assert forbidden not in text, f"{command} exposes {forbidden}"

cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
assert "promote_to_knowledge" not in cli_source
for module in ("dk_generalization.py",):
    source = (ROOT / "scripts" / module).read_text(encoding="utf-8")
    assert 'knowledge" / "records"' not in source, f"{module} writes to knowledge records"
    for forbidden in ("def promote", "write_knowledge_record", "create_knowledge_record"):
        assert forbidden not in source, f"{module} exposes {forbidden}"
    assert source.count('"can_promote_to_knowledge": False') == 1
    assert re.search(r'"can_promote_to_knowledge":\s*True', source) is None

report = subprocess.run(
    [sys.executable, str(CLI), "validate"], capture_output=True, text=True, check=True
).stdout
assert "RECURRENCE_ENGINE_CONTRACT_VALID=PASS" in report
assert "GENERALIZATION_CANNOT_PROMOTE_TRUSTED_KNOWLEDGE=PASS" in report
print("GENERALIZATION_CLI_HAS_NO_DIRECT_TRUST_PROMOTION=PASS")

# The released interface advertises recurrence, and advertises that recurrence
# output is not trusted knowledge.
released = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True
    ).stdout
)
assert (
    released["interfaces"]["recurrence_analysis_schema"]
    == dk_generalization.ANALYSIS_CONTRACT_VERSION
)
assert (
    released["interfaces"]["generalization_proposal_schema"]
    == dk_generalization.PROPOSAL_CONTRACT_VERSION
)
assert released["generalization_engine"]["name"] == dk_generalization.GENERALIZATION_ENGINE_NAME
assert released["generalization_engine"]["channel"] == dk_generalization.EVIDENCE_CHANNEL
assert released["generalization_engine"]["produces_trusted_knowledge"] is False
# Interfaces released earlier keep their versions.
assert released["interfaces"]["solved_case_candidate_schema"] == "0.1"
assert released["interfaces"]["discovery_signal_schema"] == "0.2"
assert released["interfaces"]["source_change_candidate_schema"] == "0.1"
print("RECURRENCE_RELEASED_INTERFACE_ADVERTISED=PASS")


# ---------------------------------------------------------------------------
# The gate is required, and shares the engine the CLI drives
# ---------------------------------------------------------------------------

ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert re.search(r"^on:\n  push:\n  pull_request:\n", ci, re.MULTILINE), "the workflow must run on push and pull request"
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
gate = re.search(r"^  engines:\n(?P<body>(?:    .*\n)+)", ci, re.MULTILINE)
assert gate, "missing required engines validation job"
body = gate.group("body")
assert "runs-on: ubuntu-latest" in body
assert "continue-on-error" not in body, "the recurrence gate must be required"
for script in (
    "scripts/test_recurrence_analysis.py",
    "scripts/test_generalization_boundaries.py",
):
    assert script in body, f"recurrence gate must run {script}"
assert engine.count("\ndef analyze(") == 1, "more than one recurrence entry point"
assert engine.count("\ndef review_proposal(") == 1

print("RECURRENCE_GATE_IS_REQUIRED=PASS")
print("GENERALIZATION_BOUNDARY_TESTS=PASS")
