#!/usr/bin/env python3
"""Advisory records say what the Security Team said, and nothing more.

The assertions that matter here are the negative ones: no severity where none
was published, no CVE where none was assigned, no remediation of our own, no
project identity guessed from a title, and no blocking policy implied by any of
it.
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
from pathlib import Path

import dk_acquisition
import dk_core
import dk_security as S


ROOT = dk_core.ROOT

CORE_NODE = {
    "nid": "3600001",
    "title": "Drupal core - Moderately critical - Cross-site scripting - SA-CORE-2026-012",
    "url": "https://www.drupal.org/sa-core-2026-012",
    "type": "sa",
    "created": "1767225600",
    "changed": "1767312000",
    "field_sa_advisory_id": "012",
    "field_is_psa": "0",
    "field_sa_type": "Cross-site scripting",
    "field_sa_criticality": "AC:Basic/A:User/CI:Some/II:Some/E:Theoretical/TD:Default",
    "field_affected_versions": "<10.6.13 || >=11.4.0 <11.4.4",
    "field_sa_cve": ["CVE-2026-55805"],
    "field_project": {"id": "3060", "resource": "node"},
    "field_fixed_in": [{"id": "9000001", "resource": "node"}],
    "field_sa_solution": [{"value": "Upgrade to the most recent supported release."}],
    "field_sa_description": {"value": "<p>An authoritative description.</p>"},
}

CONTRIB_NODE = {
    "nid": "3600002",
    "title": "Fixture Module - Critical - Access bypass - SA-CONTRIB-2026-901",
    "url": "https://www.drupal.org/sa-contrib-2026-901",
    "type": "sa",
    "created": "1767225600",
    "changed": "1767225600",
    "field_sa_advisory_id": "901",
    "field_is_psa": "0",
    "field_sa_type": "Access bypass",
    "field_sa_criticality": "AC:None/A:None/CI:Some/II:None/E:Theoretical/TD:All",
    "field_affected_versions": "<1.2.0",
    "field_sa_cve": ["CVE-2026-84921"],
    "field_project": {"id": "4100001", "resource": "node"},
    "field_fixed_in": [{"id": "9000002", "resource": "node"}],
    "field_sa_solution": [{"value": "Update to 1.2.0."}],
}

# An advisory the Security Team published with no risk metadata and no CVE.
BARE_NODE = {
    "nid": "3600003",
    "title": "Fixture Module - SA-CONTRIB-2026-902",
    "url": "https://www.drupal.org/sa-contrib-2026-902",
    "type": "sa",
    "created": "1767225600",
    "changed": "1767225600",
    "field_sa_advisory_id": "902",
    "field_is_psa": "0",
    "field_sa_type": None,
    "field_sa_criticality": None,
    "field_affected_versions": None,
    "field_sa_cve": [],
    "field_project": {"id": "4100001", "resource": "node"},
    "field_fixed_in": [],
    "field_sa_solution": [],
}

NODES = {
    "3060": {
        "nid": "3060",
        "title": "Drupal core",
        "type": "project_core",
        "field_project_machine_name": "drupal",
    },
    "4100001": {
        "nid": "4100001",
        "title": "Fixture Module",
        "type": "project_module",
        "field_project_machine_name": "fixture_module",
    },
    "9000001": {"nid": "9000001", "type": "project_release", "field_release_version": "11.4.4"},
    "9000002": {"nid": "9000002", "type": "project_release", "field_release_version": "8.x-1.2"},
}


def fetcher(nid):
    if nid not in NODES:
        raise dk_acquisition.SourceUnavailableError(f"node {nid} not available")
    return copy.deepcopy(NODES[nid])


def workspace(path: Path, nodes: list[dict], source_id: str = "fixture-advisories") -> Path:
    shutil.copytree(ROOT / "schema", path / "schema")
    records = path / "knowledge" / "records"
    records.mkdir(parents=True)
    (records / "sample.json").write_text(
        dk_core.stable_json({"id": "drupal.fixture.sample", "value": "must not change"}),
        encoding="utf-8",
    )
    feed = path / "feed.json"
    feed.write_text(json.dumps({"list": nodes}), encoding="utf-8")
    source = {
        "id": source_id,
        "title": "Fixture advisory feed",
        "url": feed.as_uri(),
        "fetch_url": feed.as_uri(),
        "trust": "authoritative",
        "enabled": True,
        "category": "security",
        "role": "Fixture advisory feed used by security engine tests.",
        "collection_strategy": "change-detection",
        "expected_content_type": "json",
        "normalization": "raw_text",
        "check_cadence_days": 1,
        "lifecycle": "active",
        "checked_on": "2026-09-08",
        "provenance": "Local test fixture.",
        "version_semantics": {},
        "security": {"role": "advisory_feed", "advisory_kind": "mixed"},
    }
    (path / "sources").mkdir(parents=True, exist_ok=True)
    (path / "sources" / "registry.json").write_text(
        dk_core.stable_json([source]), encoding="utf-8"
    )
    return feed


def acquire_and_ingest(root: Path, source_id: str = "fixture-advisories", **kwargs) -> dict:
    dk_acquisition.acquire(root, source_ids=[source_id])
    return S.ingest(root, source_ids=[source_id], node_fetcher=fetcher, **kwargs)


# ---------------------------------------------------------------------------
# Ingestion reads an acquired snapshot, and pins it
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    workspace(root, [CORE_NODE, CONTRIB_NODE, BARE_NODE])
    before = dk_core.knowledge_tree_digest(root)

    run = acquire_and_ingest(root)
    assert run["failures"] == [], run["failures"]
    assert sorted(run["advisories_created"]) == [
        "SA-CONTRIB-2026-901",
        "SA-CONTRIB-2026-902",
        "SA-CORE-2026-012",
    ], run["advisories_created"]
    assert run["record_class"] == S.RECORD_CLASS
    assert run["trusted_knowledge_mutations"] == []
    assert dk_core.knowledge_tree_digest(root) == before

    state = dk_acquisition.load_state(root, "fixture-advisories")
    core = S.load_advisory(root, "SA-CORE-2026-012")
    # The record cites the exact snapshot acquisition accepted.
    assert core["provenance"]["source_snapshot_sha256"] == state["content_sha256"]
    assert core["provenance"]["acquisition_channel"] == dk_acquisition.ACQUISITION_CHANNEL
    assert dk_core.require_snapshot(
        root, "fixture-advisories", core["provenance"]["source_snapshot_sha256"]
    ).is_file()
    print("SECURITY_ADVISORY_AUTHORITY_IS_AUTHORITATIVE_SOURCE=PASS")
    print("SECURITY_ADVISORY_PROVENANCE_MACHINE_READABLE=PASS")

    # An advisory is authoritative evidence, not a general Drupal rule.
    assert core["record_class"] == "source_derived_authoritative_record"
    assert core["is_trusted_knowledge"] is False
    assert core["is_general_knowledge_record"] is False
    assert not (root / "knowledge" / "records" / "SA-CORE-2026-012.json").exists()
    print("SECURITY_ADVISORY_NOT_GENERAL_KNOWLEDGE_RECORD=PASS")

    # Core and contrib are distinguished by the advisory's own published path.
    assert core["advisory"]["kind"] == "core"
    assert core["project"]["machine_name"] == "drupal"
    assert core["project"]["composer_package"] == "drupal/core"
    assert core["project"]["resolution"] == "authoritative_core_project"
    contrib = S.load_advisory(root, "SA-CONTRIB-2026-901")
    assert contrib["advisory"]["kind"] == "contrib"
    assert contrib["project"]["machine_name"] == "fixture_module"
    assert contrib["project"]["composer_package"] == "drupal/fixture_module"
    assert contrib["project"]["resolution"] == "authoritative_project_node"
    print("CORE_AND_CONTRIB_SECURITY_SCOPE_DISTINCT=PASS")

    # Severity is the published vector, preserved verbatim and never scored.
    assert core["severity"]["state"] == "sourced"
    assert core["severity"]["risk_vector"] == CORE_NODE["field_sa_criticality"]
    assert core["severity"]["source_field"] == "field_sa_criticality"
    assert core["severity"]["scored_by_drupal_knowledge"] is False
    assert core["severity"]["inferred"] is False
    # The advisory title says "Moderately critical". That human label is never
    # read out of the title into the record, and no numeric score is derived
    # from the published vector.
    serialized = dk_core.stable_json(core["severity"])
    assert "Moderately critical" in CORE_NODE["title"]
    assert "Moderately" not in serialized
    assert "moderately" not in serialized.lower()
    assert not any(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in core["severity"].values()
    ), "no numeric severity score may be derived from the risk vector"

    # Where the source published nothing, the record establishes nothing.
    bare = S.load_advisory(root, "SA-CONTRIB-2026-902")
    assert bare["severity"]["state"] == "not_established"
    assert bare["severity"]["risk_vector"] is None
    print("SECURITY_SEVERITY_NOT_SPECULATED=PASS")

    # CVEs are preserved when assigned and absent when not.
    assert core["cves"] == {
        "state": "sourced",
        "identifiers": ["CVE-2026-55805"],
        "inferred": False,
    }
    assert bare["cves"]["state"] == "none_published"
    assert bare["cves"]["identifiers"] == []
    assert bare["cves"]["inferred"] is False
    print("CVE_ONLY_WHEN_AUTHORITATIVELY_SOURCED=PASS")

    # Remediation is the advisory's own, and is never executed.
    assert core["remediation"]["state"] == "sourced"
    assert core["remediation"]["source_solution_present"] is True
    assert core["remediation"]["fixed_versions"] == ["11.4.4"]
    assert core["remediation"]["authored_by_drupal_knowledge"] is False
    assert core["remediation"]["executable"] is False
    assert bare["remediation"]["state"] == "not_provided"
    assert bare["fixed_in"]["state"] == "absent"
    print("SECURITY_REMEDIATION_AUTHORITATIVE_ONLY=PASS")

    # Severity and enforcement are independent.
    assert core["severity"]["state"] == "sourced"
    assert core["enforcement"] == {
        "intent": "guidance",
        "policy_controlled": True,
        "automatically_blocking": False,
    }
    print("SECURITY_SEVERITY_AND_ENFORCEMENT_SEPARATE=PASS")

    # An absent affected-version expression is absent, not "nothing affected".
    assert bare["affected_versions"]["state"] == "absent"
    assert bare["affected_versions"]["clauses"] == []

    # Re-ingesting unchanged evidence rewrites nothing.
    stamp = S.advisory_path(root, "SA-CORE-2026-012").read_bytes()
    again = acquire_and_ingest(root)
    assert again["advisories_created"] == []
    assert sorted(again["advisories_reused"]) == [
        "SA-CONTRIB-2026-901",
        "SA-CONTRIB-2026-902",
        "SA-CORE-2026-012",
    ]
    assert S.advisory_path(root, "SA-CORE-2026-012").read_bytes() == stamp
    print("SECURITY_ADVISORY_INGEST_IDEMPOTENT=PASS")


# ---------------------------------------------------------------------------
# Project identity is resolved authoritatively or left unresolved
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    ambiguous = copy.deepcopy(CONTRIB_NODE)
    ambiguous["url"] = "https://www.drupal.org/sa-contrib-2026-903"
    ambiguous["field_sa_advisory_id"] = "903"
    # A project reference that cannot be resolved.
    ambiguous["field_project"] = {"id": "7777777", "resource": "node"}
    workspace(root, [ambiguous])

    acquire_and_ingest(root)
    advisory = S.load_advisory(root, "SA-CONTRIB-2026-903")
    assert advisory["project"]["identity_state"] == "unresolved"
    assert advisory["project"]["machine_name"] is None
    assert advisory["project"]["composer_package"] is None
    assert advisory["project"]["resolution"] == "unresolved"
    # The advisory title says "Fixture Module". It is never turned into an
    # identity.
    assert "Fixture Module" in advisory["advisory"]["title"]
    assert "fixture" not in dk_core.stable_json(advisory["project"]).lower()
    print("SECURITY_PROJECT_IDENTITY_NOT_FUZZY_MATCHED=PASS")


# ---------------------------------------------------------------------------
# Ingestion cannot run ahead of acquisition
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    workspace(root, [CORE_NODE])
    # No acquisition has happened, so there is no accepted snapshot to read.
    run = S.ingest(root, source_ids=["fixture-advisories"], node_fetcher=fetcher)
    assert run["advisories_created"] == []
    assert run["failures"], "ingestion must refuse to read an unacquired source"
    assert run["failures"][0]["classification"] == "source_not_acquired"
    assert S.iter_advisories(root) == []
    print("SECURITY_SOURCE_CHANGE_CANNOT_BYPASS_REVIEW=PASS")


# ---------------------------------------------------------------------------
# A changed feed supersedes without rewriting snapshot history
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    feed = workspace(root, [CORE_NODE])
    acquire_and_ingest(root)
    first = S.load_advisory(root, "SA-CORE-2026-012")
    first_snapshot = first["provenance"]["source_snapshot_sha256"]

    # The Security Team corrects the advisory's affected range.
    corrected = copy.deepcopy(CORE_NODE)
    corrected["field_affected_versions"] = "<10.6.13 || >=11.4.0 <11.4.5"
    corrected["changed"] = "1767398400"
    feed.write_text(json.dumps({"list": [corrected]}), encoding="utf-8")

    outcome = dk_acquisition.acquire(root, source_ids=["fixture-advisories"])
    result = outcome["results"][0]
    assert result["status"] == dk_acquisition.STATUS_CHANGED, result
    # A changed authoritative feed creates review work.
    assert outcome["review_candidates_created"], outcome
    candidate = dk_acquisition.iter_candidates(root)[0]
    assert candidate["review_state"] == "pending_review"

    run = S.ingest(root, source_ids=["fixture-advisories"], node_fetcher=fetcher)
    assert run["advisories_updated"] == ["SA-CORE-2026-012"], run
    second = S.load_advisory(root, "SA-CORE-2026-012")
    assert second["affected_versions"]["source_value"] == "<10.6.13 || >=11.4.0 <11.4.5"
    assert second["provenance"]["source_snapshot_sha256"] != first_snapshot
    # Both snapshots remain addressable: advisory history is not rewritten.
    assert dk_core.require_snapshot(root, "fixture-advisories", first_snapshot).is_file()
    assert dk_core.require_snapshot(
        root, "fixture-advisories", second["provenance"]["source_snapshot_sha256"]
    ).is_file()
    print("SECURITY_ADVISORY_HISTORY_IMMUTABLE=PASS")


# ---------------------------------------------------------------------------
# Provenance carries no secrets
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    workspace(root, [CORE_NODE, CONTRIB_NODE])
    acquire_and_ingest(root)
    for advisory in S.iter_advisories(root):
        serialized = dk_core.stable_json(advisory)
        for forbidden in ("Authorization", "Set-Cookie", "Bearer ", "api_key", "password"):
            assert forbidden not in serialized, forbidden
        for key in advisory["provenance"]:
            lowered = key.lower()
            for forbidden in ("authorization", "cookie", "token", "secret", "credential"):
                assert forbidden not in lowered, key
    print("SECURITY_PROVENANCE_EXCLUDES_SECRETS=PASS")


# ---------------------------------------------------------------------------
# The contract refuses records that overreach
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    workspace(root, [CORE_NODE])
    acquire_and_ingest(root)
    good = S.load_advisory(root, "SA-CORE-2026-012")

    for mutate, why in [
        (lambda a: a.update({"is_trusted_knowledge": True}), "trusted knowledge"),
        (lambda a: a.update({"is_general_knowledge_record": True}), "general rule"),
        (lambda a: a["severity"].update({"scored_by_drupal_knowledge": True}), "scored severity"),
        (lambda a: a["severity"].update({"inferred": True}), "inferred severity"),
        (lambda a: a["cves"].update({"inferred": True}), "inferred CVE"),
        (
            lambda a: a["severity"].update({"state": "not_established", "risk_vector": "AC:Basic"}),
            "not_established with a value",
        ),
        (lambda a: a["cves"].update({"state": "none_published", "identifiers": ["CVE-2026-1"]}),
         "none_published with identifiers"),
        (lambda a: a["remediation"].update({"executable": True}), "executable remediation"),
        (lambda a: a["remediation"].update({"authored_by_drupal_knowledge": True}), "own remediation"),
        (lambda a: a["enforcement"].update({"automatically_blocking": True}), "auto blocking"),
        (lambda a: a["enforcement"].update({"intent": "blocking"}), "blocking intent"),
    ]:
        broken = copy.deepcopy(good)
        mutate(broken)
        try:
            S.validate_advisory(broken)
        except dk_core.ValidationError:
            pass
        else:
            raise AssertionError(f"contract accepted {why}")
    print("SECURITY_TRUTH_NOT_AUTOMATIC_BLOCKING_POLICY=PASS")

print("SECURITY_ADVISORY_CONTRACT_TESTS=PASS")
