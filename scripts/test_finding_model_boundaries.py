#!/usr/bin/env python3
"""Finding model authority and eligibility audit invariants."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import dk_core


ROOT = dk_core.ROOT
AUDIT_PATH = ROOT / "docs" / "finding-eligibility.json"
DOC_PATH = ROOT / "docs" / "FINDING_MODEL.md"

ALLOWED_CLASSIFICATIONS = {
    "FINDING_ELIGIBLE_NOW",
    "NEEDS_MORE_PROJECT_EVIDENCE",
    "HUMAN_JUDGMENT_REQUIRED",
    "APPLICABILITY_ONLY",
    "KNOWLEDGE_PROCESS_RULE",
    "NOT_A_PROJECT_FINDING",
    "MACHINE_FINDING_CONTRACT_ONLY",
}

EXPECTED_CLASSIFICATIONS = {
    "drupal.api.reference-drupal-11": "APPLICABILITY_ONLY",
    "drupal.api.version-aware-documentation": "KNOWLEDGE_PROCESS_RULE",
    "drupal.change-records.introduced-version": "KNOWLEDGE_PROCESS_RULE",
    "drupal.coding-standards.current-source": "KNOWLEDGE_PROCESS_RULE",
    "drupal.coding-standards.phpcs-coder-tooling": "NOT_A_PROJECT_FINDING",
    "drupal.security.advisory-streams-separated": "KNOWLEDGE_PROCESS_RULE",
    "drupal.security.csrf-route-protection": "NEEDS_MORE_PROJECT_EVIDENCE",
    "drupal.security.database-query-parameterization": "NEEDS_MORE_PROJECT_EVIDENCE",
    "drupal.security.twig-output-escaping": "NEEDS_MORE_PROJECT_EVIDENCE",
    "drupal.update.core-release-insecure-term-condition": "FINDING_ELIGIBLE_NOW",
    "drupal.update.core-release-state-update-feed": "KNOWLEDGE_PROCESS_RULE",
}

REQUIRED_ELIGIBILITY_CRITERIA = {
    "reviewed_knowledge",
    "definitive_applicability",
    "required_observation_domain_available",
    "machine_defined_expected_or_forbidden_condition",
    "observed_evidence_definitively_establishes_condition",
    "evidence_provenance_available",
    "no_required_semantic_judgment",
    "no_network_or_runtime_dependency",
}

REQUIRED_ANALYZER_DOMAINS = {
    "drupal_project_classification",
    "drupal_core_version",
    "composer_declarations",
    "installed_composer_packages",
    "enabled_extensions",
    "web_root",
    "custom_extensions",
    "config_inventory",
    "completeness",
    "evidence_provenance",
}

FORBIDDEN_ANALYZER_RELEASE_FACTS = {
    "supported",
    "unsupported",
    "eol",
    "current",
    "obsolete",
    "security_supported",
    "release_lifecycle",
    "release_support",
}

REQUIRED_PROVENANCE_FIELDS = {
    "finding_id",
    "knowledge_id",
    "applicability_result_identity",
    "project_fact_refs",
    "evidence_ids",
    "relative_paths",
    "condition_id",
    "reason_code",
    "effective_enforcement",
    "knowledge_set_identity",
    "analysis_identity",
}


def load_audit() -> dict[str, Any]:
    data = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    assert data["schema_version"] == "0.1"
    assert data["artifact_type"] == "finding-eligibility-audit"
    assert data["audit_status"] == "architecture-audit"
    assert data["not_canonical_drupal_truth"] is True
    return data


def records_by_id(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = audit["records"]
    assert isinstance(rows, list)
    by_id = {row["knowledge_id"]: row for row in rows}
    assert len(by_id) == len(rows)
    return by_id


def recursive_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        items: list[str] = []
        for key, child in value.items():
            items.append(str(key))
            items.extend(recursive_strings(child))
        return items
    if isinstance(value, list):
        items = []
        for child in value:
            items.extend(recursive_strings(child))
        return items
    if isinstance(value, str):
        return [value]
    return []


def assert_contains_missing(row: dict[str, Any], *domains: str) -> None:
    missing = set(row["current_evidence_missing"])
    for domain in domains:
        assert domain in missing, (row["knowledge_id"], domain, sorted(missing))


def non_advisory_authoritative(sources) -> int:
    """Authoritative sources excluding the separately declared functional classes.

    The count this guard protects is the reviewed documentation and semantic
    authority set. Advisory feeds, upgrade authority, API lifecycle authority and
    implementation-rule authority are separate functional classes, each declared
    by its own registry block and counted by its own contract. Excluding them
    keeps this guard measuring the thing it was written to measure, rather than
    every source the registry has since gained.
    """
    return sum(
        1
        for source in sources
        if source["trust"] == "authoritative"
        and (source.get("security") or {}).get("role") != "advisory_feed"
        and (source.get("upgrade") or {}).get("role") != "upgrade_authority"
        and (source.get("api_lifecycle") or {}).get("role") != "api_lifecycle_authority"
        and (source.get("implementation_authority") or {}).get("role")
        != "implementation_rule_authority"
    )


audit = load_audit()
doc = DOC_PATH.read_text(encoding="utf-8")
canonical_records = dk_core.load_knowledge_records()
canonical_ids = sorted(record["id"] for record in canonical_records)
audit_records = records_by_id(audit)

assert sorted(audit_records) == canonical_ids
assert set(audit_records) == set(EXPECTED_CLASSIFICATIONS)
assert all(
    row["finding_classification"] in ALLOWED_CLASSIFICATIONS
    for row in audit_records.values()
)
for knowledge_id, classification in EXPECTED_CLASSIFICATIONS.items():
    assert audit_records[knowledge_id]["finding_classification"] == classification

# The audit-time engine decision is frozen history; the additive
# engine_resolution block carries the current, dated decision.
assert audit["engine_decision"] == "CURRENT_FINDING_ENGINE_JUSTIFIED=NO"
assert audit["single_next_capability"] == "NORMALIZE_AUTHORITATIVE_RELEASE_LIFECYCLE_KNOWLEDGE"
engine_resolution = audit["engine_resolution"]
assert engine_resolution["original_engine_decision"] == audit["engine_decision"]
assert engine_resolution["original_engine_decision_retained"] is True
assert engine_resolution["historical_audit_rewritten"] is False
assert engine_resolution["engine_decision_now"] == (
    "CURRENT_FINDING_ENGINE_JUSTIFIED=YES_SINGLE_REVIEWED_CONTRACT"
)
assert engine_resolution["eligible_records_now"] == [
    "drupal.update.core-release-insecure-term-condition"
]
assert engine_resolution["executes_only_reviewed_machine_finding_contracts"] is True
assert engine_resolution["severity_still_not_established"] is True
assert engine_resolution["enforcement_still_guidance_only"] is True
assert engine_resolution["remediation_still_absent"] is True
assert (ROOT / engine_resolution["runtime_module"]).is_file()
assert (ROOT / engine_resolution["evaluation_schema"]).is_file()
eligible_now = sorted(
    knowledge_id
    for knowledge_id, row in audit_records.items()
    if row["finding_classification"] == "FINDING_ELIGIBLE_NOW"
)
assert eligible_now == engine_resolution["eligible_records_now"]
assert "CURRENT_FINDING_ENGINE_JUSTIFIED=NO" in doc
assert "CURRENT_FINDING_ENGINE_JUSTIFIED=YES_SINGLE_REVIEWED_CONTRACT" in doc
assert "NORMALIZE_AUTHORITATIVE_RELEASE_LIFECYCLE_KNOWLEDGE" in doc

layers = audit["authority_layers"]
assert len(layers) == len(set(layers))
assert layers.index("APPLICABILITY_RESULT") < layers.index("FINDING")
assert layers.index("FINDING") < layers.index("REMEDIATION")
assert "SOLVED_CASE" in layers

definitions = audit["definitions"]
for key in (
    "observation",
    "applicability",
    "candidate",
    "confirmed_finding",
    "unknown",
    "human_review",
    "remediation",
):
    assert key in definitions
    assert definitions[key]

assert set(audit["eligibility_criteria"]) == REQUIRED_ELIGIBILITY_CRITERIA
assert set(item["domain"] for item in audit["current_analyzer_evidence"]) == REQUIRED_ANALYZER_DOMAINS
for item in audit["current_analyzer_evidence"]:
    assert item["finding_authority_today"] != "confirmed_finding_authority"

authority = audit["authority_correction"]
assert authority["external_release_state_is_project_fact"] is False
assert authority["release_lifecycle_authority_layer"] == "TRUSTED_KNOWLEDGE_CONTEXT"
assert authority["correct_chain"] == [
    "AUTHORITATIVE_SOURCE_SNAPSHOT",
    "REVIEWED_NORMALIZED_RELEASE_LIFECYCLE_KNOWLEDGE",
    "PROJECT_FACT_INSTALLED_DRUPAL_CORE_VERSION",
    "APPLICABILITY_OR_FUTURE_FINDING_EVALUATION",
]
assert authority["incorrect_chain"] == ["AUTHORITATIVE_SOURCE", "PROJECT_EVIDENCE"]
assert "installed_drupal_core_version" in authority["project_evidence"]
assert "supported" in authority["analyzer_forbidden_outputs"]
profile_schema = dk_core.read_json(ROOT / "schema" / "project-profile.schema.json")
fact_names = set(profile_schema["properties"]["facts"]["properties"])
assert fact_names.isdisjoint(FORBIDDEN_ANALYZER_RELEASE_FACTS)

api_reference = audit_records["drupal.api.reference-drupal-11"]
assert api_reference["applicability_automation"] == "MACHINE_RESOLVABLE"
assert api_reference["finding_classification"] == "APPLICABILITY_ONLY"
assert "no_defective_project_condition" in api_reference["blockers"]

phpcs = audit_records["drupal.coding-standards.phpcs-coder-tooling"]
assert phpcs["finding_classification"] == "NOT_A_PROJECT_FINDING"
assert "tool_absence_not_policy_violation" in phpcs["blockers"]

advisory = audit_records["drupal.security.advisory-streams-separated"]
assert advisory["finding_classification"] == "KNOWLEDGE_PROCESS_RULE"
assert "advisory_affected_version_context" in advisory["current_evidence_missing"]

csrf = audit_records["drupal.security.csrf-route-protection"]
assert csrf["finding_classification"] == "NEEDS_MORE_PROJECT_EVIDENCE"
assert_contains_missing(csrf, "route_static_evidence", "route_operation_semantics")

query = audit_records["drupal.security.database-query-parameterization"]
assert query["finding_classification"] == "NEEDS_MORE_PROJECT_EVIDENCE"
assert_contains_missing(query, "php_query_static_evidence", "php_dataflow_or_trust_semantics")

twig = audit_records["drupal.security.twig-output-escaping"]
assert twig["finding_classification"] == "NEEDS_MORE_PROJECT_EVIDENCE"
assert_contains_missing(twig, "twig_static_evidence", "twig_trust_context_evidence")
assert "Twig raw or dynamic output patterns would be candidates" in twig["why"]

contract = audit["finding_contract"]
assert contract["separate_from_machine_applicability"] is True
assert contract["machine_applicability_purpose"] != contract["machine_finding_purpose"]
assert "machine_finding" in contract["machine_finding_purpose"]
assert set(contract["free_text_fields_non_executable"]) == {
    "actions",
    "checks",
    "evidence_requirements",
    "automation_hints",
}
assert "required_or_forbidden_condition" in contract["required_fields"]

# machine_finding is now a real, separately validated contract. The enduring
# invariant is separation: applicability semantics never become finding
# semantics, and a contract alone never authorizes runtime evaluation.
finding_contracts = [record for record in canonical_records if "machine_finding" in record]
assert len(finding_contracts) == dk_core.machine_finding_contract_count() == 1
for record in finding_contracts:
    machine_finding = record["machine_finding"]
    assert record.get("machine_applicability") != machine_finding
    assert machine_finding["evidence_domain"] in dk_core.MACHINE_FINDING_EVIDENCE_DOMAINS
    assert machine_finding["finding_type"] not in dk_core.MACHINE_FINDING_FORBIDDEN_TYPES
    assert machine_finding["runtime_status"] == "executed_by_reviewed_finding_runtime"
    authority = machine_finding["confirmation_authority"]
    if "confirmed" in set(machine_finding["states"].values()):
        assert authority["status"] == "semantic_authority_reviewed"
        assert authority["semantic_authority_refs"]
        assert machine_finding["term_semantics"]["state"] == (
            "DRUPAL_UPDATE_STATUS_SEMANTICS_REVIEWED"
        )
    else:
        assert authority["status"] == "not_established"
        assert authority["semantic_authority_refs"] == []
    assert dk_core.effective_enforcement(record) == "guidance"

states = audit["finding_states"]
assert states == ["confirmed", "not_observed", "unknown", "requires_human_review"]
assert "passed" not in states
assert audit["candidate_model"]["confirmed_requires_context"] is True

enforcement = audit["enforcement_model"]
assert enforcement["confirmed_finding_does_not_escalate_enforcement"] is True
assert enforcement["severity_source"] == "reviewed_knowledge"
assert enforcement["unreviewed_cannot_author_confirmed_finding"] is True
assert all(dk_core.effective_enforcement(record) == "guidance" for record in canonical_records)

assert set(audit["provenance_requirements"]) == REQUIRED_PROVENANCE_FIELDS
identity = audit["finding_identity"]
assert identity["timestamp_allowed"] is False
assert "knowledge_id" in identity["deterministic_key_fields"]
assert "condition_id" in identity["deterministic_key_fields"]
assert "project_evidence_identity" in identity["deterministic_key_fields"]
assert "project_entity_identity" in identity["deduplication_key_fields"]

gap_taxonomy = audit["gap_taxonomy"]
project_gap_domains = {
    item["required_evidence_domain"]
    for item in gap_taxonomy["project_evidence_gaps"]
}
for domain in (
    "route_static_evidence",
    "phpcs_configuration_evidence",
    "twig_static_evidence",
    "php_query_static_evidence",
):
    assert domain in project_gap_domains
assert all(item["analyzer_has_it_today"] is False for item in gap_taxonomy["project_evidence_gaps"])
context_gap_domains = {
    item["required_context"]
    for item in gap_taxonomy["authoritative_knowledge_context_gaps"]
}
assert "authoritative_release_lifecycle_context" in context_gap_domains
assert "advisory_affected_version_context" in context_gap_domains
assert "advisory_affected_version_context" not in project_gap_domains
assert "authoritative_release_lifecycle_context" not in project_gap_domains

release_semantics = audit["release_source_semantics"]
source_state = dk_core.read_json(ROOT / "sources" / "state" / "drupal-core-releases.json")
# The audit pins the snapshot it was reviewed against. That snapshot stays
# immutable and addressable after the reviewed baseline advances, so the
# audit's findings remain verifiable against exactly the bytes behind them.
assert release_semantics["snapshot_sha256"] == "sha256:c7de75d2508c7d134765affdea101e9bc7a4d534d8eaaa97fda3308a14ea0063"
lifecycle_context = dk_core.read_json(
    ROOT / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
)
assert source_state["content_sha256"] == lifecycle_context["source"]["current_state_sha256"]
snapshot = dk_core.require_snapshot(
    ROOT,
    release_semantics["source_id"],
    release_semantics["snapshot_sha256"],
)
xml_root = ET.fromstring(snapshot.read_text(encoding="utf-8"))
assert xml_root.findtext("supported_branches") == release_semantics["supported_branches"]
assert release_semantics["supported_branches"] == "10.6.,11.3.,11.4."
assert "supported_branches" in release_semantics["present_in_current_snapshot"]
assert "per_release_security_coverage_text_or_attribute" in release_semantics["present_in_current_snapshot"]
assert xml_root.findtext("project_status") == "published"
release_type_values = {
    term.findtext("value")
    for term in xml_root.findall("./releases/release/terms/term")
    if term.findtext("name") == "Release type"
}
assert {"Bug fixes", "Security update", "New features", "Insecure"}.issubset(release_type_values)
security_texts = {
    item.text
    for item in xml_root.findall("./releases/release/security")
    if item.text
}
assert "Covered by Drupal's security advisory policy" in security_texts
assert "RC releases are not covered by Drupal security advisories." in security_texts
assert "unsupported_status_from_branch_absence" in release_semantics["cannot_prove_without_additional_authority"]
assert "security_support_policy_beyond_explicit_feed_fields" in release_semantics["cannot_prove_without_additional_authority"]
assert "older_release_unsupported_from_newer_release_ordering" in release_semantics["not_inferred"]
assert "security_supported_without_explicit_authority" in release_semantics["not_inferred"]

ranking = audit["next_capability_ranking"]
assert [item["rank"] for item in ranking] == list(range(1, len(ranking) + 1))
assert ranking[0]["capability"] == "NORMALIZE_AUTHORITATIVE_RELEASE_LIFECYCLE_KNOWLEDGE"
assert ranking[0]["capability_type"] == "authoritative_knowledge_context"
assert "authority correction" in ranking[0]["reason"]
assert any(item["capability"] == "advisory_affected_version_context" for item in ranking)

for text in recursive_strings(audit):
    assert text.lower() not in {"vulnerable", "secure", "compliant", "non-compliant"}
assert "confirmed XSS finding" in doc
assert "A `|raw` occurrence may be a candidate" in doc
assert "not a vulnerability finding" in doc

assert not (ROOT / "scripts" / "dk_findings.py").exists()
assert not (ROOT / "schema" / "finding.schema.json").exists()

sources = dk_core.load_sources()
state_count = len(dk_core.iter_json_files(ROOT / "sources" / "state"))
snapshot_count = len(list((ROOT / "sources" / "snapshots").glob("*/*.txt")))
reviewed = sum(1 for record in canonical_records if record["review_status"] == "reviewed")
deferred = sum(
    1
    for record in canonical_records
    if record["review_status"] == "seed_needs_human_review"
)
guidance = sum(1 for record in canonical_records if dk_core.effective_enforcement(record) == "guidance")
blocking = sum(1 for record in canonical_records if dk_core.effective_enforcement(record) == "blocking")
cases = dk_core.load_solved_cases()
# The audit baseline is frozen history: 15 authoritative sources, each with a
# single baselined snapshot. Ecosystem discovery sources, advisory feeds,
# upgrade authority and later accepted source changes add to the live tree
# without touching that frozen history, so the baseline and the live counts are
# asserted separately.
assert (
    non_advisory_authoritative(sources)
    == audit["baseline"]["canonical_counts"]["source"]
    == 15
)
assert audit["baseline"]["canonical_counts"]["source_state"] == 15
assert audit["baseline"]["canonical_counts"]["snapshot"] == 15
assert state_count == len(sources), "every registered source keeps inspectable state"
assert len(sources) > 15, "the live registry has grown beyond the frozen baseline"
# Snapshots only ever accumulate: history is never rewritten or dropped.
assert snapshot_count >= len(sources) >= 15
assert len(canonical_records) == audit["baseline"]["canonical_counts"]["knowledge"] == 11
assert reviewed == audit["baseline"]["canonical_counts"]["reviewed"] == 11
assert deferred == audit["baseline"]["canonical_counts"]["deferred"] == 0
assert guidance == audit["baseline"]["canonical_counts"]["guidance"] == 11
assert blocking == audit["baseline"]["canonical_counts"]["blocking"] == 0
# The audit baseline is frozen v0.3.0 history, when no solved case existed.
# Solved-case capture (v0.8.0) adds cases without touching that history, so the
# frozen number and the live count are asserted separately.
assert audit["baseline"]["canonical_counts"]["solved_cases"] == 0
for case in cases:
    # A solved case is project evidence and never becomes trusted knowledge.
    assert case["id"] not in canonical_ids
    assert case.get("universal_rule") is not True
    capture = case.get("capture")
    if capture is not None:
        assert capture["promotion"]["automatic_promotion"] is False
        assert capture["promotion"]["trusted_knowledge_created"] is False
assert audit["baseline"]["canonical_counts"]["machine_finding_contracts"] == 1
assert dk_core.validate_generated_current() == ["GENERATED_KNOWLEDGE_CURRENT=PASS"]

ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert "test_finding_model_boundaries.py" in ci
assert "pull_request:" in ci and "push:" in ci
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
assert "continue-on-error" not in ci, "validation must be required"

print("APPLICABILITY_ALONE_CANNOT_AUTHOR_FINDING=PASS")
print("FINDING_IS_DISTINCT_AUTHORITY_LAYER=PASS")
print("MISSING_EVIDENCE_IS_NOT_FINDING=PASS")
print("UNOBSERVED_DOMAIN_CANNOT_CREATE_FINDING=PASS")
print("MACHINE_RESOLVABLE_DOES_NOT_IMPLY_FINDING_ELIGIBLE=PASS")
print("TOOL_ABSENCE_DOES_NOT_IMPLY_POLICY_VIOLATION=PASS")
print("ADVISORY_STREAM_EXISTENCE_IS_NOT_VULNERABILITY=PASS")
print("SUSPICIOUS_PATTERN_IS_NOT_CONFIRMED_FINDING=PASS")
print("FINDING_ELIGIBILITY_CRITERIA_DEFINED=PASS")
print("FREE_TEXT_CHECKS_CANNOT_AUTHOR_FINDINGS=PASS")
print("APPLICABILITY_AND_FINDING_CONTRACTS_SEPARATE=PASS")
print("NO_FALSE_PASS_FROM_PARTIAL_EVIDENCE=PASS")
print("CONFIRMED_FINDING_DOES_NOT_ESCALATE_ENFORCEMENT=PASS")
print("FINDING_SEVERITY_DERIVED_FROM_REVIEWED_KNOWLEDGE=PASS")
print("UNREVIEWED_KNOWLEDGE_CANNOT_AUTHOR_CONFIRMED_FINDING=PASS")
print("FINDING_PROVENANCE_MODEL_DEFINED=PASS")
print("FINDING_IDENTITY_DETERMINISTIC_BY_DESIGN=PASS")
print("FINDING_DEDUPLICATION_MODEL_DEFINED=PASS")
print("CANDIDATE_DISTINCT_FROM_CONFIRMED_FINDING=PASS")
print("FINDING_TYPE_DOES_NOT_OVERSTATE_SECURITY_IMPACT=PASS")
print("CURRENT_ANALYZER_FINDING_EVIDENCE_INVENTORIED=PASS")
print("CURRENT_FINDING_ELIGIBILITY_AUDITED=PASS")
print("NEXT_EVIDENCE_CAPABILITY_PRIORITIZED=PASS")
print("PROJECT_EVIDENCE_AND_RELEASE_KNOWLEDGE_SEPARATED=PASS")
print("EXTERNAL_RELEASE_STATE_NOT_PROJECT_FACT=PASS")
print("ANALYZER_REMAINS_PROJECT_OBSERVATION_ONLY=PASS")
print("NEXT_CAPABILITY_AUTHORITY_CLASSIFIED_CORRECTLY=PASS")
print("PROJECT_EVIDENCE_GAPS_DISTINCT_FROM_KNOWLEDGE_GAPS=PASS")
print("ADVISORY_RANGE_NOT_PROJECT_EVIDENCE=PASS")
print("NEXT_CAPABILITY_PRIORITY_REASSESSED=PASS")
print("CURRENT_RELEASE_SOURCE_SEMANTICS_AUDITED=PASS")
print("OLDER_RELEASE_NOT_AUTOMATICALLY_UNSUPPORTED=PASS")
print("SECURITY_SUPPORT_REQUIRES_EXPLICIT_AUTHORITY=PASS")
print("FINDING_AUDIT_DOES_NOT_CHANGE_DRUPAL_TRUTH=PASS")
