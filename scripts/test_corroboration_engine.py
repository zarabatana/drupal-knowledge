#!/usr/bin/env python3
"""Corroboration counts independent evidence, not voices.

The scenarios below are the ones worth getting right: a lone report, genuine
independent agreement, a repost dressed up as a second opinion, authoritative
support, evidence about the wrong version, and outright contradiction.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import dk_acquisition
import dk_core
import dk_discovery

from test_discovery_signals import release_xml, write_json


TOKEN_RELEASE = {"version": "8.x-1.17", "type": "Bug fixes", "core": "^10.3 || ^11"}
ASSERTION_KEY = "project.token.release.8.x-1.17.release_type"


def discovery_source(
    source_id: str,
    url: str,
    *,
    trust: str = "ecosystem",
    origin: str | None = None,
    derived: str | None = None,
    role: str = "signal_source",
) -> dict:
    return {
        "id": source_id,
        "title": f"Fixture {source_id}",
        "url": url,
        "fetch_url": url,
        "trust": trust,
        "enabled": True,
        "category": "fixture",
        "role": "Fixture corroboration source used by corroboration engine tests.",
        "collection_strategy": "change-detection",
        "expected_content_type": "xml",
        "normalization": "raw_text",
        "check_cadence_days": 7,
        "lifecycle": "active",
        "checked_on": "2026-09-08",
        "provenance": "Local test fixture.",
        "version_semantics": {},
        "discovery": {
            "role": role,
            "extraction": "project_release_xml",
            "signal_kind": "project-release",
            "independence_group": origin or f"origin-{source_id}",
            "derived_from": derived,
            "max_items": 5,
            "expected_refresh_days": 30,
            "component": {"type": "module", "name": "token", "package": "drupal/token"},
        },
    }


def document(root: Path, name: str, releases: list[dict]) -> str:
    path = root / f"{name}.xml"
    path.write_text(release_xml("token", releases), encoding="utf-8")
    return path.as_uri()


def build(root: Path, sources: list[dict], cases: list[dict] | None = None) -> None:
    write_json(root / "sources" / "registry.json", sources)
    write_json(
        root / "knowledge" / "records" / "sample.json",
        {"id": "drupal.fixture.sample", "value": "trusted knowledge must not change"},
    )
    for case in cases or []:
        write_json(root / "cases" / "solved" / f"{case['id']}.json", case)


def signal_for(root: Path, source_id: str) -> str:
    for signal in dk_discovery.iter_signals(root):
        if (
            signal["source"]["source_id"] == source_id
            and signal["claim"]["assertion_key"] == ASSERTION_KEY
        ):
            return signal["id"]
    raise AssertionError(f"no signal for {source_id}")


def digest_guard(root: Path):
    return dk_core.knowledge_tree_digest(root)


# ---------------------------------------------------------------------------
# One lone report is not corroboration
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url = document(root, "a", [TOKEN_RELEASE])
    build(root, [discovery_source("source-a", url, origin="origin-a")])
    before = digest_guard(root)

    run = dk_discovery.discover(root, source_ids=["source-a"])
    signal_a = signal_for(root, "source-a")
    dossier = dk_discovery.load_dossier(root, dk_discovery.dossier_identity(signal_a))
    assert dossier["corroboration_state"] == dk_discovery.INSUFFICIENT_EVIDENCE, dossier
    assert dossier["independence_assessment"]["independent_origin_count"] == 0
    assert dossier["review_state"] == dk_discovery.REVIEW_PENDING
    assert digest_guard(root) == before
    print("SIGNAL_A_ALONE=insufficient_evidence")

    # Re-corroborating identical evidence rewrites nothing and duplicates nothing.
    stamp = dk_discovery.dossier_path(root, dossier["id"]).read_bytes()
    repeat = dk_discovery.corroborate_signal(root, signal_a)
    assert repeat["result"] == "reused", repeat
    assert dk_discovery.dossier_path(root, dossier["id"]).read_bytes() == stamp
    assert len(dk_discovery.iter_dossiers(root)) == 1
    print("CORROBORATION_IDEMPOTENT=PASS")


# ---------------------------------------------------------------------------
# Genuine independence versus a repost
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url_a = document(root, "a", [TOKEN_RELEASE])
    url_b = document(root, "b", [TOKEN_RELEASE])
    url_repost = document(root, "repost", [TOKEN_RELEASE])
    build(
        root,
        [
            discovery_source("source-a", url_a, origin="origin-a"),
            discovery_source("source-b", url_b, origin="origin-b"),
            # A republication of source-a: same origin lineage, not a new voice.
            discovery_source("source-repost", url_repost, origin="origin-repost", derived="origin-a"),
        ],
    )
    before = digest_guard(root)
    dk_discovery.discover(root, source_ids=["source-a", "source-b", "source-repost"])

    signal_a = signal_for(root, "source-a")
    dossier = dk_discovery.load_dossier(root, dk_discovery.dossier_identity(signal_a))

    supporting_origins = dossier["independence_assessment"]["independent_origins"]
    assert "origin-b" in supporting_origins, dossier["independence_assessment"]
    # The repost collapsed onto origin-a, which is the signal's own lineage.
    assert dossier["independence_assessment"]["independent_origin_count"] == 1, dossier[
        "independence_assessment"
    ]
    duplicates = [
        item for item in dossier["disqualified_evidence"] if item["relation"] == "duplicate"
    ]
    assert duplicates, "a repost must be recorded and disqualified, not silently dropped"
    assert any("repost" in item["detail"] or "lineage" in item["detail"] for item in duplicates)
    assert dossier["corroboration_state"] == dk_discovery.PARTIALLY_CORROBORATED, dossier
    assert digest_guard(root) == before
    print("INDEPENDENT_B=valid_support")
    print("REPOST_OF_A=not_independent")
    print("CORROBORATION_REQUIRES_INDEPENDENT_EVIDENCE=PASS")

    # A second genuinely independent origin is what raises the state.
    url_c = document(root, "c", [TOKEN_RELEASE])
    sources = dk_acquisition.load_registry(root)
    sources.append(discovery_source("source-c", url_c, origin="origin-c"))
    write_json(root / "sources" / "registry.json", sources)
    dk_discovery.discover(root, source_ids=["source-c"])
    dk_discovery.corroborate_signal(root, signal_a)
    dossier = dk_discovery.load_dossier(root, dk_discovery.dossier_identity(signal_a))
    assert dossier["independence_assessment"]["independent_origin_count"] == 2, dossier[
        "independence_assessment"
    ]
    assert dossier["corroboration_state"] == dk_discovery.CORROBORATED, dossier

    # Corroborated is still not trusted knowledge, and still needs a human.
    assert dossier["is_trusted_knowledge"] is False
    assert dossier["is_knowledge_proposal"] is False
    assert dossier["can_promote_to_knowledge"] is False
    assert dossier["review_required"] is True
    assert dossier["review_state"] == dk_discovery.REVIEW_PENDING
    assert digest_guard(root) == before
    print("CORROBORATED_SIGNAL_NOT_AUTO_PROMOTED=PASS")


# ---------------------------------------------------------------------------
# Authoritative support corroborates without rewriting provenance
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url_a = document(root, "a", [TOKEN_RELEASE])
    url_auth = document(root, "auth", [TOKEN_RELEASE])
    build(
        root,
        [
            discovery_source("source-a", url_a, origin="origin-a"),
            discovery_source(
                "source-authoritative",
                url_auth,
                trust="authoritative",
                origin="origin-authoritative",
                role="evidence_source",
            ),
        ],
    )
    before = digest_guard(root)

    # The authoritative evidence source is acquired by the acquisition engine;
    # corroboration reads its assertions back out of the stored snapshot.
    dk_acquisition.acquire(root, source_ids=["source-authoritative"])
    dk_discovery.discover(root, source_ids=["source-a"])

    signal_a = signal_for(root, "source-a")
    dossier = dk_discovery.load_dossier(root, dk_discovery.dossier_identity(signal_a))
    assert dossier["corroboration_state"] == dk_discovery.CORROBORATED, dossier
    authoritative = [
        item for item in dossier["supporting_evidence"] if item["channel"] == "authoritative_source"
    ]
    assert authoritative, dossier["supporting_evidence"]

    # The signal was and remains an ecosystem observation.
    assert dossier["signal_trust"] == "ecosystem"
    signal = dk_discovery.load_signal(root, signal_a)
    assert signal["source"]["trust"] == "ecosystem"
    assert signal["source"]["discovery_channel"] == dk_discovery.DISCOVERY_CHANNEL
    assert digest_guard(root) == before
    print("AUTHORITATIVE_C=authoritative_corroboration")
    print("ORIGINAL_SIGNAL_TRUST_TIER_PRESERVED=PASS")


# ---------------------------------------------------------------------------
# Evidence about an incompatible version is not support
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url_a = document(root, "a", [TOKEN_RELEASE])
    # Same project, same release identifier, but claimed for Drupal 9 only.
    url_d = document(root, "d", [{"version": "8.x-1.17", "type": "Bug fixes", "core": "^9"}])
    build(
        root,
        [
            discovery_source("source-a", url_a, origin="origin-a"),
            discovery_source(
                "source-mismatch", url_d, origin="origin-mismatch", role="evidence_source"
            ),
        ],
    )
    before = digest_guard(root)
    dk_acquisition.acquire(root, source_ids=["source-mismatch"])
    dk_discovery.discover(root, source_ids=["source-a"])

    signal_a = signal_for(root, "source-a")
    dossier = dk_discovery.load_dossier(root, dk_discovery.dossier_identity(signal_a))
    mismatched = [
        item
        for item in dossier["disqualified_evidence"]
        if item["relation"] == "scope_mismatch"
    ]
    assert mismatched, dossier
    assert dossier["corroboration_state"] == dk_discovery.INSUFFICIENT_EVIDENCE, dossier
    assert dossier["independence_assessment"]["independent_origin_count"] == 0
    assert dossier["version_alignment"]["notes"], dossier["version_alignment"]
    assert digest_guard(root) == before
    print("VERSION_MISMATCHED_D=not_valid_support")
    print("CORROBORATION_RESPECTS_VERSION_SCOPE=PASS")


# ---------------------------------------------------------------------------
# Contradiction is retained and outranks agreement
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url_a = document(root, "a", [TOKEN_RELEASE])
    url_b = document(root, "b", [TOKEN_RELEASE])
    # Authoritative evidence disagreeing about the very same assertion.
    url_e = document(
        root, "e", [{"version": "8.x-1.17", "type": "Security update", "core": "^10.3 || ^11"}]
    )
    build(
        root,
        [
            discovery_source("source-a", url_a, origin="origin-a"),
            discovery_source("source-b", url_b, origin="origin-b"),
            discovery_source(
                "source-contra",
                url_e,
                trust="authoritative",
                origin="origin-contra",
                role="evidence_source",
            ),
        ],
    )
    before = digest_guard(root)
    dk_acquisition.acquire(root, source_ids=["source-contra"])
    dk_discovery.discover(root, source_ids=["source-a", "source-b"])

    signal_a = signal_for(root, "source-a")
    dossier = dk_discovery.load_dossier(root, dk_discovery.dossier_identity(signal_a))
    assert dossier["corroboration_state"] == dk_discovery.CONTRADICTED, dossier
    assert dossier["contradictory_evidence"], "contradictory evidence must be retained"
    # Agreement from source-b is preserved too: nothing is discarded.
    assert dossier["supporting_evidence"], dossier
    assert any(
        "contradiction" in note.lower() or "contradictory" in note.lower()
        for note in dossier["limitations"]
    )
    signal = dk_discovery.load_signal(root, signal_a)
    assert signal["status"] == dk_discovery.SIGNAL_CONTRADICTED
    assert digest_guard(root) == before
    print("CONTRADICTORY_E=contradiction_preserved")
    print("CONTRADICTORY_EVIDENCE_FIRST_CLASS=PASS")


# ---------------------------------------------------------------------------
# Solved cases are recurrence evidence, not generalisation
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url_a = document(root, "a", [TOKEN_RELEASE])
    aligned_case = {
        "id": "case.drupal.solved.code-change.aaaaaaaaaaaaaaaa",
        "title": "Token replacement fails on entity save",
        "modules": [{"name": "drupal/token", "version": "8.x-1.17"}],
        "themes": [],
        "drupal_versions": ["11.2.1"],
        "applicability": {"claimed_scope": "proven_context_only"},
    }
    stale_case = {
        "id": "case.drupal.solved.code-change.bbbbbbbbbbbbbbbb",
        "title": "Token replacement fails on an older major",
        "modules": [{"name": "drupal/token", "version": "8.x-1.5"}],
        "themes": [],
        "drupal_versions": ["9.5.0"],
        "applicability": {"claimed_scope": "proven_context_only"},
    }
    build(
        root,
        [discovery_source("source-a", url_a, origin="origin-a")],
        cases=[aligned_case, stale_case],
    )
    before = digest_guard(root)
    dk_discovery.discover(root, source_ids=["source-a"])

    signal_a = signal_for(root, "source-a")
    dossier = dk_discovery.load_dossier(root, dk_discovery.dossier_identity(signal_a))

    solved = [
        item
        for item in dossier["supporting_evidence"]
        if item["channel"] == "internal_proven_solved_case"
    ]
    assert solved, dossier["supporting_evidence"]
    assert all(item["generalizes"] is False for item in solved)
    # One solved case plus one community report is not universal Drupal truth.
    assert dossier["corroboration_state"] == dk_discovery.PARTIALLY_CORROBORATED, dossier
    assert any("generalis" in note or "generaliz" in note for note in dossier["limitations"])
    assert dossier["generalizes_automatically"] is False

    # The Drupal 9 case cannot support a Drupal 11 signal.
    scope_rejected = [
        item
        for item in dossier["disqualified_evidence"]
        if item["channel"] == "internal_proven_solved_case"
    ]
    assert scope_rejected, dossier["disqualified_evidence"]
    assert digest_guard(root) == before
    print("SOLVED_CASE_SUPPORT_DOES_NOT_GENERALIZE_AUTOMATICALLY=PASS")


# ---------------------------------------------------------------------------
# Provenance channels stay separate
# ---------------------------------------------------------------------------

assert dk_discovery.DISCOVERY_CHANNEL != dk_discovery.ACQUISITION_CHANNEL
assert dk_discovery.DISCOVERY_CHANNEL != dk_discovery.SOLVED_CASE_CHANNEL
assert dk_discovery.ACQUISITION_CHANNEL != dk_discovery.SOLVED_CASE_CHANNEL
assert dk_discovery.TRUST_TO_CHANNEL["authoritative"] != dk_discovery.TRUST_TO_CHANNEL["ecosystem"]
assert dk_discovery.TRUST_TO_CHANNEL["internal-proven"] == dk_discovery.CHANNEL_SOLVED_CASE
print("ALL_KNOWLEDGE_PROVENANCE_CHANNELS_REMAIN_DISTINCT=PASS")

print("CORROBORATION_ENGINE_TESTS=PASS")
