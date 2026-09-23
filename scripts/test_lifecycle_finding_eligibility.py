#!/usr/bin/env python3
"""First lifecycle finding eligibility audit invariants."""

from __future__ import annotations

import copy
import json
import xml.etree.ElementTree as ET
from typing import Any

import dk_core
import dk_project_analyzer
import dk_release_lifecycle_evaluator as evaluator


ROOT = dk_core.ROOT
AUDIT_PATH = ROOT / "docs" / "lifecycle-finding-eligibility.json"
DOC_PATH = ROOT / "docs" / "LIFECYCLE_FINDING_ELIGIBILITY.md"
CONTEXT_PATH = ROOT / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
FIXTURES = ROOT / "tests" / "fixtures" / "project-analyzer"

SOURCE_TERM = "Insecure"
TERM_NAME = "Release type"
TERM_XML_PATH = "/project/releases/release/terms/term/value"

ALLOWED_ELIGIBILITY = {
    "SAFE_CONFIRMED_FINDING",
    "CANDIDATE_ONLY",
    "HUMAN_REVIEW_REQUIRED",
    "NOT_AUTHORIZED",
}
ALLOWED_DECISIONS = {
    "FIRST_LIFECYCLE_FINDING_AUTHORIZED_NOW=YES",
    "FIRST_LIFECYCLE_FINDING_AUTHORIZED_NOW=NO_KNOWLEDGE_CONTRACT",
    "FIRST_LIFECYCLE_FINDING_AUTHORIZED_NOW=NO_SOURCE_SEMANTICS",
}
FORBIDDEN_LEXICAL_READINGS = {
    "exploitable",
    "vulnerable",
    "compromised",
    "unsupported",
    "unsafe",
    "critical",
}
BARE_VERDICT_WORDS = {
    "vulnerable",
    "secure",
    "compliant",
    "non-compliant",
    "unsupported",
    "eol",
    "exploitable",
    "compromised",
}
REQUIRED_PROVENANCE_FIELDS = [
    "knowledge_id",
    "finding_condition_id",
    "analysis_identity",
    "core_version_fact_ref",
    "core_version_evidence_ids",
    "lifecycle_assessment_identity",
    "lifecycle_context_id",
    "lifecycle_context_source_snapshot_sha256",
    "exact_matched_release",
    "exact_source_term_evidence",
    "context_freshness",
    "effective_enforcement",
    "severity_source",
]
RUNTIME_ARTIFACTS_FORBIDDEN = [
    "scripts/dk_findings.py",
    "scripts/dk_lifecycle_findings.py",
    "schema/finding.schema.json",
    "schema/lifecycle-finding.schema.json",
]


def recursive_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for child in value.values():
            keys.update(recursive_keys(child))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for child in value:
            keys.update(recursive_keys(child))
        return keys
    return set()


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


def analyze_fixture(name: str) -> dict[str, Any]:
    result = dk_project_analyzer.analyze_project(FIXTURES / name)
    assert result.exit_code == 0, (name, result.exit_code)
    return result.data


def with_core_version(analysis: dict[str, Any], version: str) -> dict[str, Any]:
    mutated = copy.deepcopy(analysis)
    fact = mutated["profile"]["facts"]["drupal_core_version"]
    fact["state"] = "known"
    fact["value"] = {"package": "drupal/core", "version": version}
    fact["source_evidence_ids"] = ["evidence.drupal.composer-lock.composer-lock"]
    fact["confidence"] = "high"
    fact["notes"] = "Synthetic analyzer-contract fixture for lifecycle eligibility audit tests."
    return mutated


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


def term_values(row: dict[str, Any]) -> list[str]:
    return list(row.get("release_type_source_values", []))


audit = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
doc = DOC_PATH.read_text(encoding="utf-8")
context = dk_core.read_json(CONTEXT_PATH)
records = dk_core.load_knowledge_records()
records_by_id = {record["id"]: record for record in records}

assert audit["schema_version"] == "0.1"
assert audit["artifact_type"] == "lifecycle-finding-eligibility-audit"
assert audit["audit_status"] == "authority-design-audit"
assert audit["not_canonical_drupal_truth"] is True
# Frozen audit-time statement; the additive runtime_resolution block below
# carries the current runtime truth.
assert audit["runtime_engine_implemented"] is False

rows = {
    row["version"]["source"]["source_value"]: row
    for row in context["releases"]
    if row.get("version", {}).get("source", {}).get("state") == "present"
}
snapshot_path = dk_core.require_snapshot(
    ROOT,
    context["source"]["source_id"],
    context["source"]["snapshot_sha256"],
)
xml_root = ET.fromstring(snapshot_path.read_text(encoding="utf-8"))
xml_releases = xml_root.findall("./releases/release")


# --- authority chain -------------------------------------------------------
chain = audit["authority_chain"]
assert chain["steps"] == [
    "PROJECT_ANALYZER_EXACT_INSTALLED_CORE_VERSION",
    "REVIEWED_LIFECYCLE_CONTEXT_EXACT_RELEASE_ROW",
    "NEUTRAL_LIFECYCLE_EVALUATOR_EXACT_RELEASE_MATCH",
    "LITERAL_AUTHORITATIVE_SOURCE_TERM_OBSERVATION",
    "REVIEWED_MACHINE_FINDING_CONTRACT",
    "CONFIRMED_NARROW_FINDING",
]
assert chain["audited_result"] == "INSUFFICIENT_WITHOUT_REVIEWED_MACHINE_FINDING_CONTRACT"
assert chain["evidence_sufficient_for_presence_assertion"] is True
assert chain["knowledge_contract_present"] is False

requirements = {item["id"]: item for item in audit["authority_requirements"]}
assert len(requirements) == len(audit["authority_requirements"])
assert all(item["status"] in {"satisfied", "missing", "conditional"} for item in requirements.values())
assert audit["satisfied_requirements"] == sorted(
    item["id"] for item in requirements.values() if item["status"] == "satisfied"
)
assert audit["missing_requirements"] == sorted(
    item["id"] for item in requirements.values() if item["status"] == "missing"
)
assert audit["conditional_requirements"] == sorted(
    item["id"] for item in requirements.values() if item["status"] == "conditional"
)
assert audit["missing_requirements"], "an audit that claims a gap must name it"
assert all(requirements[key]["blocker"] is True for key in audit["missing_requirements"])
assert "reviewed_machine_finding_contract" in audit["missing_requirements"]
assert "exact_release_match_state" in audit["satisfied_requirements"]
assert "literal_source_term_present_in_matched_row" in audit["satisfied_requirements"]


# --- finding is not a source attribute -------------------------------------
layers = audit["authority_layers"]
assert layers == [
    "SOURCE",
    "REVIEWED_LIFECYCLE_CONTEXT",
    "PROJECT_EVIDENCE",
    "LIFECYCLE_ASSESSMENT",
    "FINDING",
    "VULNERABILITY",
    "REMEDIATION",
]
assert len(layers) == len(set(layers))
assert layers.index("SOURCE") < layers.index("REVIEWED_LIFECYCLE_CONTEXT")
assert layers.index("REVIEWED_LIFECYCLE_CONTEXT") < layers.index("LIFECYCLE_ASSESSMENT")
assert layers.index("LIFECYCLE_ASSESSMENT") < layers.index("FINDING")
assert layers.index("FINDING") < layers.index("VULNERABILITY")
assert layers.index("VULNERABILITY") < layers.index("REMEDIATION")
assert chain["source_attribute_is_not_finding"] is True
assert chain["assessment_is_not_finding"] is True
assert {"finding", "findings"}.issubset(evaluator.FORBIDDEN_PROJECT_VERDICT_KEYS)
assessment_schema = dk_core.read_json(ROOT / "schema" / "release-lifecycle-assessment.schema.json")
assert "finding" not in assessment_schema["properties"]
assert recursive_keys(audit).isdisjoint(evaluator.FORBIDDEN_PROJECT_VERDICT_KEYS)


# --- eligibility decision --------------------------------------------------
candidate = audit["candidate_condition"]
assert candidate["eligibility_classification"] in ALLOWED_ELIGIBILITY
assert candidate["eligibility_classification"] == "CANDIDATE_ONLY"
assert candidate["wording_finalized"] is False
assert candidate["forbidden_finding_type"] == "vulnerability"
assert candidate["proposed_assertion"] == "installed_core_release_explicitly_marked_insecure_by_source"
assert SOURCE_TERM in candidate["audited_statement"]
assert audit["decision"] in ALLOWED_DECISIONS
assert audit["decision"] == "FIRST_LIFECYCLE_FINDING_AUTHORIZED_NOW=NO_KNOWLEDGE_CONTRACT"
assert (candidate["eligibility_classification"] == "SAFE_CONFIRMED_FINDING") == (
    audit["decision"] == "FIRST_LIFECYCLE_FINDING_AUTHORIZED_NOW=YES"
)
assert audit["decision"] in doc
assert candidate["audited_statement"] not in "", "audited statement must exist"
assert len(audit["decision_rationale"]) >= 3


# --- source term structure, re-derived from real artifacts -----------------
structure = audit["source_term_structure"]
assert structure["xml_field_path"] == TERM_XML_PATH
assert structure["taxonomy_term_name"] == TERM_NAME
assert structure["taxonomy_term_value"] == SOURCE_TERM
assert structure["match_mode"] == "literal_exact_string"

xml_term_paths = set()
xml_term_attributes = set()
xml_value_attributes = set()
for release in xml_releases:
    for term in release.findall("./terms/term"):
        if (term.findtext("value") or "").strip() != SOURCE_TERM:
            continue
        assert (term.findtext("name") or "").strip() == TERM_NAME
        xml_term_paths.add(TERM_XML_PATH)
        xml_term_attributes.update(term.attrib)
        for child in term:
            xml_value_attributes.update(child.attrib)
assert xml_term_paths == {TERM_XML_PATH}
assert not xml_term_attributes
assert not xml_value_attributes
assert structure["term_element_attributes"] == []
assert structure["term_value_element_attributes"] == []
assert structure["explicit_source_identifier_beyond_display_text"] is False
assert structure["attached_directly_to_release"] is True

project_terms = {
    (term.findtext("name") or "").strip(): (term.findtext("value") or "").strip()
    for term in xml_root.findall("./terms/term")
}
assert SOURCE_TERM not in project_terms.values()
assert structure["attached_to_project_level"] is False

snapshot_text = snapshot_path.read_text(encoding="utf-8")
# The frozen 2026-09-07 audit and the live reviewed context are different
# observations of the same source and are asserted separately. The audit is
# historical evidence and is never edited to match a later source state; the
# superseding review records what the current state is and why it differs.
assert structure["literal_occurrences_in_snapshot"] == 514
assert structure["release_rows_total"] == 553
assert structure["release_rows_with_term"] == 514
assert structure["release_rows_without_term"] == 39

review = dk_core.read_json(ROOT / "docs" / "lifecycle-finding-eligibility-review-2026-09-23.json")
assert review["supersedes"]["artifact"] == "docs/lifecycle-finding-eligibility.json"
assert review["supersedes"]["audit_date"] == audit["audit_date"]
assert review["supersedes"]["historical_evidence_mutated"] is False
live = review["current_reviewed_observation"]
drift = review["drift_from_frozen_audit"]

carrying = sorted(version for version, row in rows.items() if SOURCE_TERM in term_values(row))
not_carrying = sorted(version for version, row in rows.items() if SOURCE_TERM not in term_values(row))
# Live totals must match the reviewed observation exactly. If the source drifts
# again, these fail and force another human review rather than silently moving.
assert snapshot_text.count(SOURCE_TERM) == live["release_rows_with_term"] == len(carrying)
assert context["release_count"] == len(rows) == len(xml_releases) == live["release_rows_total"]
assert live["release_rows_without_term"] == len(not_carrying)
# A published release can acquire the term later, when a security release
# supersedes it, so an advance is not guaranteed to consist only of rows
# without the term. The drift is therefore stated as a conservation identity
# between the frozen audit and the current reviewed observation.
assert drift["frozen_release_rows_total"] == structure["release_rows_total"]
assert drift["frozen_release_rows_with_term"] == structure["release_rows_with_term"]
assert drift["frozen_release_rows_without_term"] == structure["release_rows_without_term"]
assert drift["rows_added_since_audit"] == len(rows) - structure["release_rows_total"]
assert drift["rows_newly_carrying_term_since_audit"] == len(carrying) - structure["release_rows_with_term"]
assert (
    drift["rows_added_since_audit"] - drift["rows_newly_carrying_term_since_audit"]
    == len(not_carrying) - structure["release_rows_without_term"]
)
assert review["drift_from_frozen_audit"]["superseded_statement"]["true_now"] is False
assert live["release_rows_newly_carrying_term_since_previous_context"], (
    "the review must name the releases that newly carry the term"
)
for version in live["release_rows_newly_carrying_term_since_previous_context"]:
    assert SOURCE_TERM in term_values(rows[version]), version
assert structure["release_rows_without_terms_container"] == sum(
    1 for release in xml_releases if release.find("terms") is None
) == 9
assert structure["duplicate_term_occurrences_within_a_row"] == 0
assert all(term_values(row).count(SOURCE_TERM) <= 1 for row in rows.values())

# A release that carried the term at audit time never loses it, so the frozen
# representatives carrying it must still carry it today.
for version in structure["representative_versions_with_term"]:
    assert SOURCE_TERM in term_values(rows[version]), version
# The reverse does not hold: a release without the term can acquire it later.
# The frozen list is historical, so it is checked against the superseding
# review's record of what happened to it, not against today's source.
assert drift["frozen_representative_versions_without_term"] == structure["representative_versions_without_term"]
for version in drift["frozen_representative_versions_without_term_now_carrying"]:
    assert SOURCE_TERM in term_values(rows[version]), version
for version in drift["frozen_representative_versions_without_term_still_without"]:
    assert SOURCE_TERM not in term_values(rows[version]), version
assert sorted(
    drift["frozen_representative_versions_without_term_now_carrying"]
    + drift["frozen_representative_versions_without_term_still_without"]
) == sorted(structure["representative_versions_without_term"])
# Current representatives are asserted against today's source.
for version in live["representative_versions_without_term"]:
    assert SOURCE_TERM not in term_values(rows[version]), version
for version in live["representative_versions_with_term"]:
    assert SOURCE_TERM in term_values(rows[version]), version

for path in structure["normalized_context_paths"]:
    assert path in {"releases[].terms[].value.source_value", "releases[].release_type_source_values[]"}
sample = rows[structure["representative_versions_with_term"][0]]
assert any(
    term["value"]["source_value"] == SOURCE_TERM and term["value"]["state"] == structure["normalized_state_marker"]
    for term in sample["terms"]
)
assert structure["distinct_from_security_update_term"] is True
assert structure["coexists_with_security_coverage_metadata"] is True


# --- presence versus semantics ---------------------------------------------
semantics = audit["source_term_semantics"]
assert semantics["presence_provable"] is True
assert semantics["meaning_provable_from_current_snapshot"] is False
assert semantics["established_by_snapshot"]
assert semantics["not_established_by_snapshot"]
assert not set(semantics["established_by_snapshot"]) & set(semantics["not_established_by_snapshot"])
assert requirements["source_term_semantic_authority"]["status"] == "conditional"
assert "literal_presence_assertion" in requirements["source_term_semantic_authority"]["not_required_for"]
assert "meaning_bearing_assertions" in requirements["source_term_semantic_authority"]["required_for"]


# --- semantics are not invented --------------------------------------------
assert semantics["classification"] == "TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY"
assert semantics["snapshot_defines_term"] is False
assert semantics["definitional_text_occurrences_in_snapshot"] == 0
assert semantics["vocabulary_documentation_in_snapshot"] is False
assert semantics["schema_or_dtd_in_snapshot"] is False
assert "<!DOCTYPE" not in snapshot_text
assert "xsd" not in snapshot_text.lower()
assert "vocabulary" not in snapshot_text.lower()
for definitional in ("<description", "<definition", "<help", "<documentation"):
    assert definitional not in snapshot_text.lower()
assert set(xml_root.attrib) <= {"xmlns:dc"}
assert audit["next_required_authority_source"]["collected_during_this_task"] is False
assert audit["next_required_authority_source"]["source_category"]
assert audit["next_required_authority_source"]["acceptable_categories"]
assert "TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY" in doc


# --- no lexical inference ---------------------------------------------------
assert semantics["lexical_inference_forbidden"] is True
forbidden_readings = " ".join(semantics["forbidden_lexical_readings"]).lower()
for word in FORBIDDEN_LEXICAL_READINGS:
    assert word in forbidden_readings, word
assert semantics["distribution_counter_evidence"]["contradicts_not_covered_by_security_policy_reading"] is True
assert 0.9 < semantics["distribution_counter_evidence"]["share_of_release_rows_carrying_term"] <= 1.0
bare = {text for text in recursive_strings(audit) if text.lower() in BARE_VERDICT_WORDS}
assert not bare, bare
# The audit recorded the share against its own frozen denominator. The live
# share is derived independently; both stay above the 0.9 threshold, so the
# counter-evidence reading the audit relies on survives the advance.
assert semantics["distribution_counter_evidence"]["share_of_release_rows_carrying_term"] == round(
    structure["release_rows_with_term"] / structure["release_rows_total"], 4
)
live_share = round(len(carrying) / context["release_count"], 4)
assert 0.9 < live_share <= 1.0, live_share


# --- exact release match ----------------------------------------------------
exact_rule = audit["exact_match_rule"]
assert exact_rule["requires_exact_release_match"] is True
assert exact_rule["approximate_matching_allowed"] is False
assert exact_rule["nearest_release_allowed"] is False
assert exact_rule["branch_only_inference_allowed"] is False
assert exact_rule["older_than_comparison_allowed"] is False

recommended = analyze_fixture("recommended")
matched_version = structure["representative_versions_with_term"][0]
matched = evaluator.evaluate_analysis_data(with_core_version(recommended, matched_version))
assert matched["evaluation_state"] == "evaluated"
assert matched["release_match"]["state"] == "matched"
assert matched["release_match"]["source_version"] == matched_version
assert SOURCE_TERM in matched["source_attributes"]["source_release_type_terms"]
assert matched["context_freshness"]["relation"] == "current"

# A release that is clean *today*, from the superseding review, not one that
# was clean when the frozen audit was written.
clean_version = live["representative_versions_without_term"][0]
clean = evaluator.evaluate_analysis_data(with_core_version(recommended, clean_version))
assert clean["release_match"]["state"] == "matched"
assert SOURCE_TERM not in clean["source_attributes"]["source_release_type_terms"]


# --- unknown core version ---------------------------------------------------
assert exact_rule["unknown_core_version_result"] == "no_finding"
assert exact_rule["unknown_core_version_state"] == "core_version_unknown"
unknown = evaluator.evaluate_analysis_data(analyze_fixture("no-lock"))
assert unknown["evaluation_state"] == "core_version_unknown"
assert unknown["core_version"]["state"] == "unknown"
assert unknown["release_match"]["state"] == "not_evaluated"
assert SOURCE_TERM not in json.dumps(unknown["source_attributes"])


# --- missing release row ----------------------------------------------------
assert exact_rule["missing_release_row_result"] == "no_finding"
assert exact_rule["missing_release_row_state"] == "release_not_found"
absent_version = "11.4.99"
assert absent_version not in rows
missing = evaluator.evaluate_analysis_data(with_core_version(recommended, absent_version))
assert missing["evaluation_state"] == "release_not_found"
assert missing["release_match"]["state"] == "not_found"
assert missing["source_attributes"]["state"] == "not_evaluated"
for conclusion in exact_rule["missing_release_row_is_not"]:
    assert conclusion.endswith("_conclusion")
assert "EXACT_RELEASE_ROW_NOT_FOUND" in {item["code"] for item in missing["limitations"]}


# --- canonical context ------------------------------------------------------
canonical_rule = audit["canonical_context_rule"]
assert canonical_rule["requires_canonical_reviewed_context"] is True
assert canonical_rule["self_declared_external_context_can_author_finding"] is False
assert canonical_rule["canonical_context_id"] == context["id"] == "drupal-core-release-lifecycle"
assert canonical_rule["canonical_context_path"] == "knowledge/context/drupal-core-release-lifecycle.json"
assert evaluator.CANONICAL_CONTEXT_RELATIVE_PATH.as_posix() == canonical_rule["canonical_context_path"]

self_declared = copy.deepcopy(context)
self_declared["source"]["snapshot_sha256"] = "sha256:" + "0" * 64
self_declared["review"]["status"] = "reviewed"
try:
    evaluator.evaluate_analysis_data_with_test_context(
        with_core_version(recommended, matched_version), self_declared
    )
except evaluator.LifecycleEvaluatorValidationError:
    pass
else:  # pragma: no cover - defensive
    raise AssertionError("self-declared context provenance must not be accepted")

unreviewed = copy.deepcopy(context)
unreviewed["review"]["status"] = "candidate"
try:
    evaluator.evaluate_analysis_data_with_test_context(
        with_core_version(recommended, matched_version), unreviewed
    )
except evaluator.LifecycleEvaluatorValidationError:
    pass
else:  # pragma: no cover - defensive
    raise AssertionError("unreviewed context must not author assessment or finding")


# --- branch membership is not authority ------------------------------------
signals = {item["signal"]: item for item in audit["non_authoritative_signals"]}
branch_signal = signals["branch_listed_in_source_supported_branches"]
assert branch_signal["can_author_candidate_condition"] is False
supported_values = [entry["source_value"] for entry in context["supported_branches"]["entries"]]
cross = {
    "supported_branch_with_term": 0,
    "supported_branch_without_term": 0,
    "unsupported_branch_with_term": 0,
    "unsupported_branch_without_term": 0,
}
for version, row in rows.items():
    token = evaluator.source_branch_token_for_version(version)
    listed = token["state"] == "known" and token["source_value"] in supported_values
    has_term = SOURCE_TERM in term_values(row)
    cross[("supported_branch_" if listed else "unsupported_branch_") + ("with_term" if has_term else "without_term")] += 1
# The audit cross-tabulated against its frozen baseline. The frozen table is
# historical and is asserted as recorded; the current table is asserted against
# the superseding review, and every cell difference must be accounted for by
# the reviewed delta rather than accepted silently.
frozen_cross = structure["branch_membership_cross_tabulation"]
live_cross = live["branch_membership_cross_tabulation"]
cross_delta = drift["branch_membership_cross_tabulation_delta"]
assert live_cross == cross, "the reviewed cross-tabulation must match today's source"
for cell in cross:
    assert cross[cell] - frozen_cross[cell] == cross_delta[cell], cell
assert cross["supported_branch_with_term"] + cross["unsupported_branch_with_term"] == len(carrying)
assert sum(frozen_cross.values()) == structure["release_rows_total"]
assert sum(cross.values()) == context["release_count"] == live["release_rows_total"]
# The term-carrying population grew only by releases a later security release
# superseded, never by the rows the advance itself added.
assert (
    cross_delta["supported_branch_with_term"] + cross_delta["unsupported_branch_with_term"]
    == drift["rows_newly_carrying_term_since_audit"]
)
assert cross["supported_branch_with_term"] > 0, "listed branches carry the term"
assert cross["unsupported_branch_without_term"] > 0, "unlisted branches lack the term"
# The audit's counter-evidence counts are frozen observations, so they are
# checked against the frozen table. What must still hold today is the
# qualitative claim they were recorded to support: branch membership predicts
# nothing about the term in either direction.
assert branch_signal["counter_evidence"]["supported_branch_rows_with_term"] == frozen_cross["supported_branch_with_term"]
assert branch_signal["counter_evidence"]["unsupported_branch_rows_without_term"] == frozen_cross["unsupported_branch_without_term"]
assert cross["supported_branch_without_term"] > 0, "listed branches do not all carry the term"
assert cross["unsupported_branch_with_term"] > 0, "unlisted branches still carry the term"
assert "branch_only_inference_allowed" in exact_rule and exact_rule["branch_only_inference_allowed"] is False


# --- security coverage is not authority ------------------------------------
coverage_signal = signals["source_security_coverage_text_or_covered_attribute"]
assert coverage_signal["can_author_candidate_condition"] is False


def covered(row: dict[str, Any]) -> bool:
    return row.get("security", {}).get("covered_attribute", {}).get("source_value") == "1"


with_term_covered = sum(1 for row in rows.values() if SOURCE_TERM in term_values(row) and covered(row))
without_term_covered = sum(1 for row in rows.values() if SOURCE_TERM not in term_values(row) and covered(row))
assert with_term_covered > 0 and without_term_covered > 0
# The counter-evidence that matters is qualitative and still holds: carrying
# the term and being covered by the security policy are not mutually exclusive,
# in either direction. The counts themselves are frozen observations and are
# asserted against the audit; today's counts come from the superseding review.
assert coverage_signal["counter_evidence"]["rows_with_term_and_covered_attribute"] == 376
assert coverage_signal["counter_evidence"]["rows_without_term_and_covered_attribute"] == 9
assert structure["rows_with_term_and_security_covered_attribute"] == 376
assert structure["rows_without_term_and_security_covered_attribute"] == 9
assert with_term_covered == live["rows_with_term_and_security_covered_attribute"]
assert without_term_covered == live["rows_without_term_and_security_covered_attribute"]
coverage_text = coverage_signal["counter_evidence"]["example_coverage_text"]
assert coverage_text == "Covered by Drupal's security advisory policy"
assert any(row["security"].get("text", {}).get("source_value") == coverage_text for row in rows.values())


# --- security update term is not the audited term ---------------------------
update_signal = signals["release_type_term_security_update"]
assert update_signal["can_author_candidate_condition"] is False
security_update_only = sorted(
    version
    for version, row in rows.items()
    if "Security update" in term_values(row) and SOURCE_TERM not in term_values(row)
)
assert security_update_only
# "Security update" and "Insecure" are different terms, which is the claim that
# must still hold. The exact row list is an observation: frozen in the audit,
# current in the superseding review. A release loses this list only by
# acquiring the audited term, which the review records explicitly.
assert update_signal["counter_evidence"]["rows_with_security_update_and_without_insecure"] == structure["rows_with_security_update_term_and_without_insecure_term"]
assert security_update_only == live["rows_with_security_update_term_and_without_insecure_term"]
assert sorted(
    set(structure["rows_with_security_update_term_and_without_insecure_term"])
    - set(security_update_only)
) == drift["security_update_only_rows_removed"]
for version in drift["security_update_only_rows_removed"]:
    assert SOURCE_TERM in term_values(rows[version]), version
assert len(update_signal["forbidden_inferences"]) >= 3
assert "Security update" != SOURCE_TERM
for version in security_update_only:
    assessment = evaluator.evaluate_analysis_data(with_core_version(recommended, version))
    assert "Security update" in assessment["source_attributes"]["source_release_type_terms"]
    assert SOURCE_TERM not in assessment["source_attributes"]["source_release_type_terms"]


# --- vulnerability is not overstated ---------------------------------------
contract = audit["machine_contract_design"]["draft"]
assert candidate["proposed_finding_type"] == contract["finding_type"] == "release_lifecycle"
assert contract["finding_type"] != "vulnerability"
assert candidate["alternate_finding_type"] == "authoritative_release_state"
forbidden_claims = set(contract["forbidden_output_claims"])
for claim in (
    "project_is_insecure",
    "site_is_vulnerable",
    "exploitable_vulnerability_exists",
    "project_is_compromised",
    "upgrade_is_mandatory",
):
    assert claim in forbidden_claims, claim
assert set(candidate["narrower_than"]) <= forbidden_claims


# --- severity is not invented ----------------------------------------------
severity = audit["severity_model"]
assert severity["derivable_from_reviewed_knowledge_record"] is False
assert severity["derivable_from_explicit_lifecycle_policy"] is False
assert severity["derivable_source"] == "neither"
assert severity["host_record_severity_transferable"] is False
assert severity["future_finding_severity_state"] == "not_established"
assert contract["severity"] == {"state": "not_established", "source": None}
assert contract["severity"]["state"] not in severity["forbidden_invented_severities"]
assert "severity" not in recursive_keys(context)
assert severity["lifecycle_context_contains_severity_field"] is False
feed_record = records_by_id["drupal.update.core-release-state-update-feed"]
assert feed_record["severity"] in severity["forbidden_invented_severities"]
assert feed_record["severity"] != contract["severity"]["state"]
assert severity["severity_from_term_wording_allowed"] is False


# --- enforcement does not escalate -----------------------------------------
enforcement = audit["enforcement_model"]
assert enforcement["confirmed_finding_escalates_enforcement"] is False
assert enforcement["future_finding_effective_enforcement"] == "guidance"
assert contract["effective_enforcement"] == "guidance"
effective = {dk_core.effective_enforcement(record) for record in records}
assert effective == set(enforcement["canonical_records_effective_enforcement"]) == {"guidance"}
assert enforcement["blocking_records"] == sum(
    1 for record in records if dk_core.effective_enforcement(record) == "blocking"
) == 0


# --- existing knowledge authority -------------------------------------------
knowledge = audit["existing_knowledge_authority"]
assert knowledge["audited_record_id"] == "drupal.update.core-release-state-update-feed"
assert knowledge["record_mutated_by_this_audit"] is False
assert knowledge["review_status"] == feed_record["review_status"] == "reviewed"
assert knowledge["severity_field"] == feed_record["severity"]
assert knowledge["enforcement_intent"] == feed_record["enforcement"]["intent"]
assert knowledge["effective_enforcement"] == dk_core.effective_enforcement(feed_record)
assert knowledge["declares_machine_finding_contract"] is False
assert "machine_finding" not in feed_record
assert knowledge["declares_machine_applicability_contract"] is False
assert "machine_applicability" not in feed_record
feed_text = json.dumps(feed_record).lower()
assert knowledge["mentions_the_source_term"] is False
assert SOURCE_TERM.lower() not in feed_text
assert knowledge["condition_bearing_fields_executable"] is False
for field in knowledge["condition_bearing_fields"]:
    assert field in feed_record
# Frozen historical audit value: zero contracts existed when the audit ran.
assert knowledge["records_with_machine_finding_contract"] == 0
assert knowledge["conclusion"] == "NO_EXISTING_REVIEWED_RECORD_AUTHORIZES_THE_CANDIDATE_CONDITION"
for other in knowledge["other_records_audited"]:
    assert other["id"] in records_by_id
    assert other["authorizes_candidate_condition"] is False
    assert "machine_finding" not in records_by_id[other["id"]]
assert knowledge["what_it_does_authorize"] and knowledge["what_it_does_not_authorize"]


# --- staleness rule ---------------------------------------------------------
freshness_rule = audit["context_freshness_rule"]
assert freshness_rule["current_confirmed_finding_requires"] == "current"
assert freshness_rule["stale_can_author_current_confirmed_finding"] is False
assert freshness_rule["stale_context_result"] == "historical_candidate"
assert freshness_rule["stale_context_secondary_result"] == "requires_refresh"
assert freshness_rule["alternative_formulation_considered"]
assert freshness_rule["alternative_rejected_because"]
assert contract["requires"]["context_relation"] == "current"
# Audit-time draft (frozen history): it proposed confirmed before the
# settlement; the live reviewed contract maps this state to candidate, which
# the contract_resolution assertions above pin against the canonical record.
assert contract["states"]["term_present_and_context_current"] == "confirmed"
assert contract["states"]["term_present_and_context_stale"] == freshness_rule["stale_context_result"]
relation_enum = assessment_schema["properties"]["context_freshness"]["properties"]["relation"]["enum"]
assert set(relation_enum) == {"current", "stale"}
stale_limitations = evaluator.limitations(
    {"state": "known", "version": matched_version},
    {"state": "matched"},
    {"branch_listed_in_source_supported_branches": {"state": "known"}},
    {"relation": "stale"},
)
assert "LIFECYCLE_CONTEXT_STALE" in {item["code"] for item in stale_limitations}


# --- machine contract design ------------------------------------------------
design = audit["machine_contract_design"]
assert design["implemented"] is False
assert design["declarative_only"] is True
assert design["free_text_execution_allowed"] is False
assert design["separate_from_machine_applicability"] is True
for key in ("id", "condition_id", "finding_type", "evidence_domain", "requires", "assertion", "severity", "states"):
    assert key in contract, key
requires = contract["requires"]
assert requires["exact_release_match"] is True
assert requires["source_term"] == SOURCE_TERM
assert requires["source_term_name"] == TERM_NAME
assert requires["source_field_path"] == TERM_XML_PATH
assert requires["match_mode"] == "literal_exact_string"
assert requires["canonical_context_id"] == context["id"]
assert requires["assessment_evaluation_state"] == "evaluated"
assert requires["assessment_evaluation_state"] in assessment_schema["properties"]["evaluation_state"]["enum"]
assert contract["evidence_domain"] == "release_lifecycle_assessment"
assert contract["assertion"] == candidate["proposed_assertion"]
assert contract["remediation_emitted"] is False
assert set(contract["states"].values()) <= {
    "confirmed",
    "historical_candidate",
    "not_observed",
    "unknown",
}
assert contract["states"]["term_absent_in_matched_row"] == "not_observed"
assert contract["states"]["release_not_found"] == "unknown"
assert contract["states"]["core_version_unknown"] == "unknown"
assert "passed" not in set(contract["states"].values())
assert "CORE_VERSION_UNKNOWN" in contract["reason_codes"]
assert "EXACT_RELEASE_ROW_NOT_FOUND" in contract["reason_codes"]
assert missing["release_match"]["reason_code"] in contract["reason_codes"]
assert unknown["core_version"]["reason_code"] in contract["reason_codes"]


# --- provenance -------------------------------------------------------------
assert audit["provenance_requirements"] == REQUIRED_PROVENANCE_FIELDS
detail = audit["provenance_detail"]
assert sorted(detail) == sorted(REQUIRED_PROVENANCE_FIELDS)
assert all(detail[field] for field in REQUIRED_PROVENANCE_FIELDS)
assert detail["lifecycle_context_id"] == context["id"]
assert matched["analysis"]["analysis_sha256"].startswith("sha256:")
assert matched["lifecycle_context"]["source_snapshot_sha256"] == context["source"]["snapshot_sha256"]
assert matched["core_version"]["fact_ref"] == "drupal_core_version"
assert matched["core_version"]["evidence_ids"]
assert matched["assessment_id"].startswith("sha256:")


# --- deterministic identity -------------------------------------------------
identity = audit["finding_identity"]
assert identity["timestamp_allowed"] is False
assert identity["volatile_inputs_allowed"] is False
assert identity["algorithm"].startswith("sha256")
key_fields = identity["deterministic_key_fields"]
assert len(key_fields) == len(set(key_fields))
for field in (
    "knowledge_id",
    "finding_condition_id",
    "assertion",
    "analysis_sha256",
    "matched_release_source_version",
    "lifecycle_context_sha256",
):
    assert field in key_fields, field
for excluded in ("evaluated_at", "wall_clock_time", "run_id", "hostname", "absolute_paths"):
    assert excluded in identity["excluded_fields"], excluded
assert not set(identity["excluded_fields"]) & set(key_fields)
assert "timestamp" not in " ".join(key_fields)
repeat = evaluator.evaluate_analysis_data(with_core_version(recommended, matched_version))
assert repeat["assessment_id"] == matched["assessment_id"], "identity inputs must be reproducible"


# --- deduplication ----------------------------------------------------------
dedup = audit["deduplication"]
assert dedup["max_instances_per_installed_release_per_condition"] == 1
dedup_fields = dedup["dedup_key_fields"]
assert len(dedup_fields) == len(set(dedup_fields))
assert len(dedup_fields) < len(key_fields), "dedup key must be coarser than finding identity"
for shared in ("knowledge_id", "finding_condition_id", "matched_release_source_version"):
    assert shared in dedup_fields and shared in key_fields
assert dedup["project_entity"] == "drupal/core"
assert len(dedup["duplicate_sources_collapsed"]) >= 3
assert dedup["collapsed_into"].startswith("one logical finding")
assert dedup["observed_duplicate_term_occurrences_within_a_row"] == 0
term_paths_for_matched_row = [
    sum(1 for term in rows[matched_version]["terms"] if term["value"]["source_value"] == SOURCE_TERM),
    term_values(rows[matched_version]).count(SOURCE_TERM),
    matched["source_attributes"]["source_release_type_terms"].count(SOURCE_TERM),
]
assert term_paths_for_matched_row == [1, 1, 1], "one source fact reachable by several paths"


# --- project version scope --------------------------------------------------
scope = audit["project_version_scope"]
assert scope["finding_is_scoped_to_exact_installed_release"] is True
assert scope["remains_current_after_project_moves_to_another_release"] is False
assert scope["on_move_to_release_without_the_term"] == "not_observed"
assert "matched_release_source_version" in key_fields
assert matched["release_match"]["source_version"] != clean["release_match"]["source_version"]
assert matched["assessment_id"] != clean["assessment_id"]
assert SOURCE_TERM not in clean["source_attributes"]["source_release_type_terms"]


# --- context change re-evaluation -------------------------------------------
change = audit["context_change_semantics"]
assert change["reevaluation_required_on_context_change"] is True
assert change["historical_evidence_mutated"] is False
assert change["source_collection_alone_promotes_context"] is False
assert change["stale_context_downgrade"].startswith("historical_candidate")
changed_context = copy.deepcopy(context)
dropped = [row for row in changed_context["releases"] if row["version"]["source"]["source_value"] == "dev-main"]
assert len(dropped) == 1
changed_context["releases"] = [row for row in changed_context["releases"] if row not in dropped]
changed_context["release_count"] = len(changed_context["releases"])
changed = evaluator.evaluate_analysis_data_with_test_context(
    with_core_version(recommended, matched_version), changed_context
)
assert changed["lifecycle_context"]["context_sha256"] != matched["lifecycle_context"]["context_sha256"]
assert changed["assessment_id"] != matched["assessment_id"]
assert changed["release_match"]["state"] == "matched"


# --- no remediation ---------------------------------------------------------
remediation = audit["remediation_boundary"]
assert remediation["upgrade_target_decided"] is False
assert remediation["version_recommended"] is False
assert remediation["composer_command_generated"] is False
audit_text = json.dumps(audit).lower()
assert "composer require" not in audit_text
assert "composer update" not in audit_text
assert "drush " not in audit_text
assert "composer require" not in doc.lower()
assert "upgrade to " not in doc.lower()
for relative in RUNTIME_ARTIFACTS_FORBIDDEN:
    assert not (ROOT / relative).exists(), relative
assert audit["runtime_artifacts_absent"] == RUNTIME_ARTIFACTS_FORBIDDEN


# --- canonical integrity ----------------------------------------------------
integrity = audit["canonical_integrity"]
assert integrity["knowledge_records_changed"] == 0
assert integrity["lifecycle_context_changed"] is False
assert integrity["sources_changed"] is False
assert integrity["snapshots_changed"] is False
assert integrity["generated_outputs_changed"] is False
assert integrity["analyzer_changed"] is False
assert integrity["resolver_changed"] is False
assert integrity["evaluator_runtime_changed"] is False
assert integrity["version_bumped"] is False
assert integrity["lifecycle_evaluator_authority_defect_found"] is False

baseline = audit["baseline"]
# The audit baseline is pinned to the v0.5.0 release it was performed against;
# the repository VERSION file has since moved on and is not part of the freeze.
assert baseline["version"] == "0.5.0"
assert baseline["tag"] == "v0.5.0"
assert baseline["main_sha"] == "90d6238e04adb22e1db5eed77606608c1e27e4f0"
# The baseline block is frozen v0.5.0 history and must never be rewritten.
counts = baseline["canonical_counts"]
assert counts["knowledge"] == 10
assert counts["reviewed"] == 10
assert counts["guidance"] == 10
assert counts["blocking"] == 0
assert counts["machine_finding_contracts"] == 0
assert counts["source"] == 12
assert counts["lifecycle_context_releases"] == 553

# Live canonical state is asserted through the additive resolution block.
resolution = audit["contract_resolution"]
assert resolution["original_decision"] == audit["decision"]
# Settlement preserved, then resolved: the contract could not bootstrap
# confirmed authority from a neutral source observation; reviewed Drupal
# update-status semantic authority later supplied the missing bridge through
# explicit references, so the live contract's strongest state is confirmed.
assert resolution["confirmation_semantics_pending"] is False
assert resolution["confirmed_finding_authority_established"] is True
assert resolution["strongest_machine_finding_state"] == "confirmed"
assert resolution["confirmation_authority_status"] == "semantic_authority_reviewed"
assert "candidate" in resolution["historical_draft_confirmed_state_superseded"]
assert resolution["conditional_requirements_now_satisfied"] == ["source_term_semantic_authority"]
assert resolution["semantic_authority_refs"] == [
    "drupal-update-project-release-semantics",
    "drupal-update-status-security-semantics",
    "drupal-update-manager-interface-semantics",
]
assert "NOT_SECURE" in resolution["semantic_authority_note"]
live_contract = records_by_id[resolution["supplied_by_record_id"]]["machine_finding"]
assert live_contract["states"]["term_present_and_context_current"] == "confirmed"
assert live_contract["confirmation_authority"]["status"] == "semantic_authority_reviewed"
assert live_contract["confirmation_authority"]["semantic_authority_refs"] == (
    resolution["semantic_authority_refs"]
)
assert live_contract["term_semantics"]["state"] == "DRUPAL_UPDATE_STATUS_SEMANTICS_REVIEWED"
assert resolution["original_decision_retained"] is True
assert resolution["historical_audit_rewritten"] is False
assert resolution["knowledge_contract_supplied"] is True
assert resolution["supplied_by_record_id"] in records_by_id
assert resolution["missing_requirements_now_satisfied"] == audit["missing_requirements"]
assert resolution["missing_requirements_still_open"] == []
assert resolution["conditional_requirements_still_open"] == []
assert resolution["meaning_bearing_claims_authorized"] is True
# The settled contract_resolution block is frozen v0.6.0 settlement history;
# its live-runtime statements are superseded by the additive runtime_resolution
# block asserted below.
assert resolution["runtime_finding_engine_present"] is False
assert resolution["runtime_consumers_of_machine_finding"] == 0
runtime_resolution = audit["runtime_resolution"]
assert runtime_resolution["historical_audit_rewritten"] is False
assert runtime_resolution["contract_resolution_live_runtime_fields_superseded"] is True
assert runtime_resolution["runtime_finding_engine_present"] is True
assert runtime_resolution["runtime_consumers_of_machine_finding"] == 1
runtime_module = ROOT / runtime_resolution["runtime_consumer_module"]
assert runtime_module.is_file()
assert "machine_finding" in runtime_module.read_text(encoding="utf-8")
assert (ROOT / runtime_resolution["evaluation_schema"]).is_file()
assert runtime_resolution["executed_contract_ids"] == [resolution["supplied_by_record_id"]]
assert runtime_resolution["executes_only_reviewed_machine_finding_contracts"] is True
assert runtime_resolution["confirmed_state_reachable_through_runtime"] is True
assert runtime_resolution["severity_still_not_established"] is True
assert runtime_resolution["enforcement_still_guidance_only"] is True
assert runtime_resolution["remediation_still_absent"] is True
assert runtime_resolution["network_and_source_collection_still_absent_from_evaluation"] is True
assert runtime_resolution["historical_runtime_artifacts_still_absent"] is True
for module in (
    "dk_project_analyzer.py",
    "dk_applicability.py",
    "dk_release_lifecycle.py",
    "dk_release_lifecycle_evaluator.py",
):
    assert "machine_finding" not in (ROOT / "scripts" / module).read_text(encoding="utf-8"), module
now = resolution["canonical_counts_now"]
assert now["knowledge"] == len(records) == 11
assert now["reviewed"] == sum(1 for record in records if record["review_status"] == "reviewed") == 11
assert now["guidance"] == sum(1 for record in records if dk_core.effective_enforcement(record) == "guidance") == 11
assert now["blocking"] == 0
assert now["machine_finding_contracts"] == dk_core.machine_finding_contract_count() == 1
assert now["source"] == 15 == non_advisory_authoritative(dk_core.load_sources())
# The semantic authority set is unchanged; the registry around it is not, and
# the difference is exactly the sources that declare their own functional role.
assert len(dk_core.load_sources()) > now["source"]
# Frozen audit identity stays frozen, and the snapshot behind it stays
# addressable; the live context is separately required to be reviewed and
# current against its own pinned snapshot.
assert now["lifecycle_context_releases"] == 553
assert context["release_count"] == live["release_rows_total"]
assert baseline["lifecycle_context"]["source_snapshot_sha256"] == "sha256:c7de75d2508c7d134765affdea101e9bc7a4d534d8eaaa97fda3308a14ea0063"
assert dk_core.require_snapshot(
    ROOT, context["source"]["source_id"], baseline["lifecycle_context"]["source_snapshot_sha256"]
).is_file()
assert baseline["lifecycle_context"]["review_status"] == "reviewed"
assert baseline["lifecycle_context"]["context_relation"] == "current"
assert context["review"]["status"] == "reviewed"
assert evaluator.validate_lifecycle_context_for_evaluation(context)["relation"] == "current"
source_state = dk_core.read_json(ROOT / "sources" / "state" / "drupal-core-releases.json")
assert source_state["content_sha256"] == context["source"]["snapshot_sha256"]
assert dk_core.validate_generated_current() == ["GENERATED_KNOWLEDGE_CURRENT=PASS"]


# --- CI topology ------------------------------------------------------------
ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert "test_lifecycle_finding_eligibility.py" in ci
assert "pull_request:" in ci and "push:" in ci
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
assert "continue-on-error" not in ci, "validation must be required"


print("LIFECYCLE_FINDING_AUTHORITY_AUDITED=PASS")
print("LIFECYCLE_FINDING_DISTINCT_FROM_SOURCE_ATTRIBUTE=PASS")
print("INSECURE_SOURCE_TERM_FINDING_ELIGIBILITY_DECIDED=PASS")
print("INSECURE_SOURCE_TERM_STRUCTURE_AUDITED=PASS")
print("SOURCE_TERM_PRESENCE_DISTINCT_FROM_TERM_SEMANTICS=PASS")
print("INSECURE_TERM_SEMANTICS_NOT_INFERRED=PASS")
print("INSECURE_LABEL_NOT_INTERPRETED_LEXICALLY=PASS")
print("LIFECYCLE_FINDING_REQUIRES_EXACT_RELEASE_MATCH=PASS")
print("UNKNOWN_CORE_VERSION_CANNOT_AUTHOR_LIFECYCLE_FINDING=PASS")
print("MISSING_RELEASE_ROW_CANNOT_AUTHOR_LIFECYCLE_FINDING=PASS")
print("LIFECYCLE_FINDING_REQUIRES_CANONICAL_CONTEXT=PASS")
print("SUPPORTED_BRANCH_MEMBERSHIP_CANNOT_AUTHOR_INSECURE_FINDING=PASS")
print("SECURITY_COVERAGE_CANNOT_AUTHOR_INSECURE_FINDING=PASS")
print("SECURITY_UPDATE_TERM_NOT_INSECURE_FINDING=PASS")
print("LIFECYCLE_FINDING_DOES_NOT_OVERSTATE_VULNERABILITY=PASS")
print("INSECURE_FINDING_SEVERITY_NOT_INVENTED=PASS")
print("LIFECYCLE_FINDING_DOES_NOT_ESCALATE_ENFORCEMENT=PASS")
print("EXISTING_KNOWLEDGE_FINDING_AUTHORITY_AUDITED=PASS")
print("CURRENT_LIFECYCLE_FINDING_REQUIRES_CURRENT_CONTEXT=PASS")
print("LIFECYCLE_FINDING_REQUIRES_CANONICAL_CONTEXT_NOT_SELF_DECLARED=PASS")
print("LIFECYCLE_MACHINE_FINDING_CONTRACT_DESIGNED=PASS")
print("LIFECYCLE_FINDING_PROVENANCE_DEFINED=PASS")
print("LIFECYCLE_FINDING_IDENTITY_DESIGNED=PASS")
print("LIFECYCLE_FINDING_DEDUPLICATION_DESIGNED=PASS")
print("LIFECYCLE_FINDING_PROJECT_VERSION_SCOPED=PASS")
print("LIFECYCLE_FINDING_REEVALUATES_ON_CONTEXT_CHANGE=PASS")
print("LIFECYCLE_FINDING_AUDIT_HAS_NO_REMEDIATION=PASS")
print("NEXT_REQUIRED_AUTHORITY_SOURCE_IDENTIFIED=PASS")
print("LIFECYCLE_FINDING_AUDIT_DOES_NOT_CHANGE_DRUPAL_TRUTH=PASS")
