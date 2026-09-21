#!/usr/bin/env python3
"""Discovery ends at human review, and review never touches trusted knowledge.

These are the boundary tests: what a reviewer may decide, what a decision is
allowed to change, and what the scheduled pipeline is permitted to do on its
own.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_acquisition
import dk_core
import dk_discovery

from test_corroboration_engine import (
    TOKEN_RELEASE,
    build,
    discovery_source,
    document,
    signal_for,
)


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"


def prepared(root: Path) -> tuple[str, str]:
    url = document(root, "a", [TOKEN_RELEASE])
    build(root, [discovery_source("source-a", url, origin="origin-a")])
    dk_discovery.discover(root, source_ids=["source-a"])
    signal_id = signal_for(root, "source-a")
    return signal_id, dk_discovery.dossier_identity(signal_id)


# ---------------------------------------------------------------------------
# Every review outcome leaves trusted knowledge byte-identical
# ---------------------------------------------------------------------------

for outcome in dk_discovery.REVIEW_OUTCOMES:
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        signal_id, dossier_id = prepared(root)

        before = dk_core.knowledge_tree_digest(root)
        records_before = {
            path.name: path.read_bytes()
            for path in (root / "knowledge" / "records").glob("*.json")
        }

        result = dk_discovery.review_dossier(
            root,
            dossier_id,
            outcome=outcome,
            actor="reviewer@example.invalid",
            method="human_signal_review",
            note="fixture review",
        )

        after = dk_core.knowledge_tree_digest(root)
        records_after = {
            path.name: path.read_bytes()
            for path in (root / "knowledge" / "records").glob("*.json")
        }

        assert before == after, f"{outcome} changed trusted knowledge"
        assert records_before == records_after, f"{outcome} rewrote a knowledge record"
        assert result["trusted_knowledge_changed"] is False
        assert result["trusted_knowledge_digest"]["before"] == result[
            "trusted_knowledge_digest"
        ]["after"]

        dossier = dk_discovery.load_dossier(root, dossier_id)
        assert dossier["review_state"] == outcome
        assert dossier["review"]["outcome"] == outcome
        assert dossier["review"]["trusted_knowledge_changed"] is False
        # No outcome makes the dossier into knowledge or a proposal.
        assert dossier["is_trusted_knowledge"] is False
        assert dossier["is_knowledge_proposal"] is False
        assert dossier["can_promote_to_knowledge"] is False

        signal = dk_discovery.load_signal(root, signal_id)
        assert signal["review_status"] == "reviewed"
        assert signal["is_trusted_knowledge"] is False

        # Only the proposal outcome authorises later work, and only as work.
        expected = outcome == dk_discovery.REVIEW_PROPOSAL_CANDIDATE
        assert dossier["review"]["authorizes_knowledge_proposal_work"] is expected
        assert result["authorizes_knowledge_proposal_work"] is expected
        if expected:
            # Authorising proposal work created no knowledge record at all.
            assert len(list((root / "knowledge" / "records").glob("*.json"))) == len(
                records_before
            )

print("DISCOVERY_REVIEW_OUTCOMES_LEAVE_KNOWLEDGE_UNCHANGED=PASS")
print("REVIEW_CANDIDATE_NOT_KNOWLEDGE_PROPOSAL=PASS")


# ---------------------------------------------------------------------------
# Nothing reaches a reviewed state without a human
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    signal_id, dossier_id = prepared(root)

    dossier = dk_discovery.load_dossier(root, dossier_id)
    assert dossier["review_state"] == dk_discovery.REVIEW_PENDING
    assert dossier["review"] is None

    # Re-running discovery and corroboration cannot advance review state.
    dk_discovery.discover(root, source_ids=["source-a"])
    dk_discovery.corroborate_signal(root, signal_id)
    dossier = dk_discovery.load_dossier(root, dossier_id)
    assert dossier["review_state"] == dk_discovery.REVIEW_PENDING
    assert dossier["review"] is None

    # A reviewer is required, and must be named.
    for bad_actor in ("", "   "):
        try:
            dk_discovery.review_dossier(
                root, dossier_id, outcome=dk_discovery.REVIEW_WATCH, actor=bad_actor
            )
        except dk_discovery.DiscoveryInputError:
            pass
        else:
            raise AssertionError("review accepted an anonymous actor")

    # Invented outcomes are refused.
    for bad_outcome in ("promote_to_knowledge", "trusted", "approved"):
        try:
            dk_discovery.review_dossier(
                root, dossier_id, outcome=bad_outcome, actor="reviewer@example.invalid"
            )
        except dk_discovery.DiscoveryInputError:
            pass
        else:
            raise AssertionError(f"review accepted invented outcome {bad_outcome}")

print("DISCOVERY_CANNOT_BYPASS_HUMAN_REVIEW=PASS")


# ---------------------------------------------------------------------------
# New evidence retires a stale human decision
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    signal_id, dossier_id = prepared(root)

    dk_discovery.review_dossier(
        root,
        dossier_id,
        outcome=dk_discovery.REVIEW_NO_ACTION,
        actor="reviewer@example.invalid",
    )
    assert dk_discovery.load_dossier(root, dossier_id)["review_state"] == "no_action"

    # A genuinely new independent origin appears.
    url_b = document(root, "b", [TOKEN_RELEASE])
    sources = dk_acquisition.load_registry(root)
    sources.append(discovery_source("source-b", url_b, origin="origin-b"))
    dk_core.iter_json_files  # noqa: B018 - keep the import meaningful
    (root / "sources" / "registry.json").write_text(
        dk_core.stable_json(sources), encoding="utf-8"
    )
    dk_discovery.discover(root, source_ids=["source-b"])
    dk_discovery.corroborate_signal(root, signal_id)

    dossier = dk_discovery.load_dossier(root, dossier_id)
    assert dossier["corroboration_state"] == dk_discovery.PARTIALLY_CORROBORATED, dossier
    # The old decision is preserved as history but no longer stands.
    assert dossier["review_state"] == dk_discovery.REVIEW_PENDING, dossier
    assert dossier["review"] is not None
    assert dk_discovery.EVIDENCE_CHANGED_AFTER_REVIEW in dossier["limitations"]

print("DISCOVERY_EVIDENCE_CHANGE_REOPENS_REVIEW=PASS")


# ---------------------------------------------------------------------------
# Provenance stays free of secrets and machine paths
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    signal_id, _ = prepared(root)
    signal = dk_discovery.load_signal(root, signal_id)

    for key in signal["provenance"]:
        lowered = key.lower()
        for forbidden in ("authorization", "cookie", "bearer", "secret", "password"):
            assert forbidden not in lowered, f"provenance key {key} looks like secret material"

    serialized = dk_discovery.stable_json(signal)
    for forbidden in ("Authorization", "Set-Cookie", "Bearer ", "api_key"):
        assert forbidden not in serialized, f"signal persisted {forbidden}"

    # A credentialed fetch url never becomes stored provenance.
    url = document(root, "cred", [TOKEN_RELEASE])
    build(
        root,
        [
            discovery_source("source-a", url, origin="origin-a"),
            discovery_source(
                "source-cred",
                "https://user:secretpassword@example.invalid/feed.xml",
                origin="origin-cred",
            ),
        ],
    )
    run = dk_discovery.discover(root, source_ids=["source-cred"])
    result = run["results"][0]
    assert result["status"] in ("source_contract_failure", "source_unavailable"), result
    assert result["signals_created"] == []
    assert "secretpassword" not in dk_discovery.stable_json(run), "credential leaked into the run"

    # Transport details that quote a local path are redacted before storage.
    missing = (root / "absent.xml").as_uri()
    build(root, [discovery_source("source-missing", missing, origin="origin-missing")])
    run = dk_discovery.discover(root, source_ids=["source-missing"])
    detail = run["results"][0]["error"]["detail"]
    assert dk_acquisition.REDACTED_LOCAL_PATH in detail or workspace not in detail, detail

print("DISCOVERY_PROVENANCE_EXCLUDES_SECRETS=PASS")
print("DISCOVERY_EXTERNAL_SOURCE_SAFETY=PASS")


# ---------------------------------------------------------------------------
# Manual and scheduled discovery are the same engine
# ---------------------------------------------------------------------------

ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert re.search(r"^on:\n  push:\n  pull_request:\n", ci, re.MULTILINE), "the workflow must run on push and pull request"
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
gate = re.search(r"^  engines:\n(?P<body>(?:    .*\n)+)", ci, re.MULTILINE)
assert gate, "missing required engines validation job"
gate_body = gate.group("body")
assert "runs-on: ubuntu-latest" in gate_body
assert "continue-on-error" not in gate_body, "the discovery gate must be required"
for script in (
    "scripts/test_discovery_signals.py",
    "scripts/test_corroboration_engine.py",
    "scripts/test_discovery_review_boundary.py",
):
    assert script in gate_body, f"discovery gate must run {script}"

# Validation never discovers: the workflow runs no acquisition or discovery,
# so a pull request cannot reach the network on the repository's behalf. A
# scheduler, when one is configured, must drive the same CLI entry point as a
# human would, with `--due` cadence and a trust filter, never `--all`.
assert "dk.py discover" not in ci and "dk.py acquire" not in ci
import dk as _cli
_parser = _cli.build_parser()
_sub = next(a for a in _parser._actions if isinstance(a, __import__("argparse")._SubParsersAction))
_discover_flags = {o for action in _sub.choices["discover"]._actions for o in action.option_strings}
assert {"--due", "--trust"} <= _discover_flags, _discover_flags

# There is exactly one discovery implementation for both paths to share.
engine_source = (ROOT / "scripts" / "dk_discovery.py").read_text(encoding="utf-8")
assert engine_source.count("\ndef discover(") == 1, "more than one discovery entry point"
assert engine_source.count("\ndef corroborate_signal(") == 1
cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
assert "dk_discovery.discover(" in cli_source
assert cli_source.count("dk_discovery.discover(") == 1

print("MANUAL_AND_SCHEDULED_DISCOVERY_SHARE_ENGINE=PASS")


# ---------------------------------------------------------------------------
# No path from discovery to trusted knowledge exists anywhere
# ---------------------------------------------------------------------------

for module in ("dk_discovery.py",):
    source = (ROOT / "scripts" / module).read_text(encoding="utf-8")
    # Nothing in the discovery path may write into the knowledge tree.
    assert 'knowledge" / "records"' not in source, f"{module} writes to knowledge records"
    for forbidden in ("def promote", "write_knowledge_record", "create_knowledge"):
        assert forbidden not in source, f"{module} exposes {forbidden}"
    # The promotion flag exists only to be pinned false, never assigned true.
    assert "can_promote_to_knowledge" in source
    assert re.search(r'"can_promote_to_knowledge":\s*True', source) is None
    assert source.count('"can_promote_to_knowledge": False') == 2, (
        "the promotion flag must be pinned false on both signals and dossiers"
    )

# Signals and dossiers on disk agree.
for record in dk_discovery.iter_signals(ROOT) + dk_discovery.iter_dossiers(ROOT):
    assert record["can_promote_to_knowledge"] is False, record["id"]
    assert record["is_trusted_knowledge"] is False, record["id"]
    assert record["is_knowledge_proposal"] is False, record["id"]
    assert record["review_required"] is True, record["id"]

report = subprocess.run(
    [sys.executable, str(CLI), "validate"], capture_output=True, text=True, check=True
).stdout
assert "DISCOVERY_ENGINE_CONTRACT_VALID=PASS" in report
assert "DISCOVERY_CANNOT_PROMOTE_TRUSTED_KNOWLEDGE=PASS" in report

print("DISCOVERY_RUN_REPORTS_ZERO_TRUSTED_KNOWLEDGE_MUTATIONS=PASS")
print("DISCOVERY_REVIEW_BOUNDARY_TESTS=PASS")
