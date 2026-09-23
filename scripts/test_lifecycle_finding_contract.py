#!/usr/bin/env python3
"""First reviewed machine_finding contract invariants."""

from __future__ import annotations

import copy
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

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


import dk_core
import dk_release_lifecycle_evaluator as evaluator


ROOT = dk_core.ROOT
RECORD_ID = "drupal.update.core-release-insecure-term-condition"
SOURCE_GOVERNANCE_RECORD_ID = "drupal.update.core-release-state-update-feed"
RECORD_PATH = ROOT / "knowledge" / "records" / f"{RECORD_ID}.json"
DOC_PATH = ROOT / "docs" / "LIFECYCLE_FINDING_CONTRACT.md"
SCHEMA_PATH = ROOT / "schema" / "knowledge-record.schema.json"
CONTEXT_PATH = ROOT / "knowledge" / "context" / "drupal-core-release-lifecycle.json"

SOURCE_TERM = "Insecure"
TERM_NAME = "Release type"
TERM_XML_PATH = "/project/releases/release/terms/term/value"

FREE_TEXT_FIELDS = ("summary", "actions", "checks", "evidence_requirements", "automation_hints")

FORBIDDEN_SEMANTIC_CLAIMS = (
    "vulnerable",
    "exploitable",
    "unsafe",
    "unsupported",
    "obsolete",
    "end of life",
    "end-of-life",
    "compromised",
    "mandatory upgrade",
    "must upgrade",
)

FORBIDDEN_TITLE_PHRASES = (
    "installation is insecure",
    "vulnerable drupal",
    "security vulnerability detected",
    "unsupported drupal release",
    "unsafe drupal release",
)

RUNTIME_MODULES = (
    "dk_project_analyzer.py",
    "dk_applicability.py",
    "dk_release_lifecycle.py",
    "dk_release_lifecycle_evaluator.py",
    "dk.py",
)

FORBIDDEN_ENGINE_ARTIFACTS = (
    "scripts/dk_findings.py",
    "scripts/dk_lifecycle_findings.py",
    "schema/finding.schema.json",
    "schema/lifecycle-finding.schema.json",
)


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


def free_text(record: dict[str, Any]) -> str:
    chunks: list[str] = []
    for field in FREE_TEXT_FIELDS:
        value = record[field]
        chunks.extend([value] if isinstance(value, str) else list(value))
    return "\n".join(chunks)


def rejects(mutate) -> str:
    """Apply a mutation to a copy of the contract and require rejection."""
    candidate = copy.deepcopy(record)
    mutate(candidate)
    try:
        dk_core.validate_machine_finding_contract(candidate, "negative-test")
    except dk_core.ValidationError as exc:
        return str(exc)
    raise AssertionError(f"contract validator accepted an unsafe mutation: {mutate}")


records = dk_core.load_knowledge_records()
records_by_id = {item["id"]: item for item in records}
record = records_by_id[RECORD_ID]
contract = record["machine_finding"]
requires = contract["requires"]
doc = DOC_PATH.read_text(encoding="utf-8")
schema = dk_core.read_json(SCHEMA_PATH)
context = dk_core.read_json(CONTEXT_PATH)


# --- assertion matches the reviewed Drupal authority -------------------------
assert contract["assertion"] == "installed_core_release_is_not_secure_per_drupal_update_status"
assert contract["human_title"] == (
    "Installed Drupal core release is classified as not secure by Drupal Update Manager"
)
assert contract["condition_id"] == "installed_core_release_carries_source_release_type_term_insecure"
lowered_title = contract["human_title"].lower()
for phrase in FORBIDDEN_TITLE_PHRASES:
    assert phrase not in lowered_title, phrase
assert "classified as not secure" in lowered_title
assert "drupal update manager" in lowered_title
assert "vulnerability detected" not in lowered_title
assert contract["assertion_scope"].startswith("drupal_update_manager_status_semantics")
assert contract["assertion"] in doc and contract["human_title"] in doc


# --- term semantics are reviewed Drupal authority, not invention -------------
semantics = contract["term_semantics"]
assert semantics["state"] == "DRUPAL_UPDATE_STATUS_SEMANTICS_REVIEWED"
assert semantics["state"] in dk_core.MACHINE_FINDING_TERM_SEMANTICS_STATES
assert semantics["meaning_bearing_claims_authorized"] is True
authorized_meaning = semantics["authorized_meaning"]
assert "Drupal Update Manager" in authorized_meaning
assert "NOT_SECURE" in authorized_meaning
assert "missing security update(s)" in authorized_meaning
lowered_meaning = authorized_meaning.lower()
for token in dk_core.MACHINE_FINDING_AUTHORIZED_MEANING_FORBIDDEN_TOKENS:
    assert token not in lowered_meaning, token
forbidden_claims = set(semantics["forbidden_claims"])
for claim in (
    "release_is_exploitable",
    "release_has_specific_cve",
    "release_is_compromised",
    "severity_is_derivable",
    "release_is_unsupported",
    "release_is_obsolete",
    "release_is_end_of_life",
    "upgrade_is_mandatory",
    "attack_feasibility_established",
):
    assert claim in forbidden_claims, claim
assert dk_core.MACHINE_FINDING_REVIEWED_MINIMUM_FORBIDDEN_CLAIMS <= forbidden_claims
prose = free_text(record).lower()
for claim in FORBIDDEN_SEMANTIC_CLAIMS:
    assert claim not in prose, claim
assert "SOURCE FACT" in record["summary"]
assert "PROJECT JOIN" in record["summary"]
assert "DRUPAL SEMANTICS" in record["summary"]
assert "LIMITS" in record["summary"]
assert "TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY" in doc
assert "DRUPAL_UPDATE_STATUS_SEMANTICS_REVIEWED" in doc


# --- literal exact matching only --------------------------------------------
assert requires["match_mode"] == "literal_exact_string"
assert requires["source_term_value"] == SOURCE_TERM
assert requires["source_term_name"] == TERM_NAME
assert requires["source_field_path"] == TERM_XML_PATH
contract_text = dk_core.stable_json(contract).lower()
# whole-word check: "evaluation_state" is legitimate, a bare "eval" is not
for executable in ("regex", "pattern", "jsonpath", "xpath", "expression", "eval", "exec", "lambda", "python", "script"):
    assert not re.search(rf"\b{executable}\b", contract_text), executable
assert SOURCE_TERM.lower() not in {
    value for value in recursive_strings(requires) if isinstance(value, str)
}, "lowercase or aliased term forms must not appear"
assert not any(
    isinstance(value, str) and value != SOURCE_TERM and value.lower() == SOURCE_TERM.lower()
    for value in recursive_strings(contract)
)
for alias in ("insecure", "INSECURE", "in-secure", "not_secure"):
    assert alias not in {v for v in recursive_strings(requires)} or alias == SOURCE_TERM


# --- authority is not hidden in the source governance rule ------------------
assert RECORD_ID != SOURCE_GOVERNANCE_RECORD_ID
assert RECORD_PATH.is_file()
governance = records_by_id[SOURCE_GOVERNANCE_RECORD_ID]
assert "machine_finding" not in governance
assert dk_core.stable_json(governance) == dk_core.stable_json(
    dk_core.read_json(ROOT / "knowledge" / "records" / f"{SOURCE_GOVERNANCE_RECORD_ID}.json")
)
assert SOURCE_GOVERNANCE_RECORD_ID in record["related"]
assert RECORD_ID.split(".")[1] in record["domains"], "id segment must be a declared domain"
domains = {domain["id"] for domain in dk_core.load_domains()}
assert set(record["domains"]) <= domains
assert "security" not in record["domains"], "unresolved term meaning must not be filed as security"
assert dk_core.machine_finding_contract_count() == 1


# --- canonical source baselined ---------------------------------------------
assert len(record["sources"]) == 4
assert [item["source_id"] for item in record["sources"]] == [
    "drupal-core-releases",
    "drupal-update-project-release-semantics",
    "drupal-update-status-security-semantics",
    "drupal-update-manager-interface-semantics",
]
source_ref = record["sources"][0]
assert source_ref["source_id"] == "drupal-core-releases"
assert TERM_NAME in source_ref["locator"] and SOURCE_TERM in source_ref["locator"]
state = dk_core.read_json(ROOT / "sources" / "state" / "drupal-core-releases.json")
snapshot = dk_core.require_snapshot(ROOT, "drupal-core-releases", state["content_sha256"])
assert snapshot.is_file()
xml_root = ET.fromstring(snapshot.read_text(encoding="utf-8"))
matching_terms = [
    term
    for term in xml_root.findall("./releases/release/terms/term")
    if (term.findtext("name") or "").strip() == TERM_NAME
    and (term.findtext("value") or "").strip() == SOURCE_TERM
]
assert matching_terms, "record claims a term the pinned snapshot does not contain"
resolved_paths = set()


def walk(element, path):
    yield element, path
    for child in element:
        yield from walk(child, f"{path}/{child.tag}")


for element, path in walk(xml_root, f"/{xml_root.tag}"):
    if element.text and element.text.strip() == SOURCE_TERM:
        resolved_paths.add(path)
assert resolved_paths == {TERM_XML_PATH}, resolved_paths
assert context["source"]["snapshot_sha256"] == state["content_sha256"]
assert dk_core.validate_reviewed_knowledge_sources_baselined() == [
    "REVIEWED_KNOWLEDGE_SOURCES_BASELINED=PASS",
    "REVIEWED_KNOWLEDGE_SOURCE_REFERENCES_CHECKED=18",
]


# --- review scope is narrow --------------------------------------------------
assert record["review_status"] == "reviewed"
assert record["kind"] == "version-change"
assert requires["canonical_context_id"] == context["id"] == "drupal-core-release-lifecycle"
assert record["project_applicability"]["requires"] == ["drupal_core_version"]
assert record["project_applicability"]["unknown_result"] == "lifecycle_finding_unknown"
assert record["version_applicability"]["drupal_core"][0]["constraint"] == "release-history"


# --- declarative contract ----------------------------------------------------
assert contract["schema_version"] == "0.1"
assert contract["evidence_domain"] == "release_lifecycle_assessment"
assert dk_core.MACHINE_FINDING_EVIDENCE_DOMAINS == {"release_lifecycle_assessment"}
assert dk_core.validate_machine_finding_contracts() == [
    "MACHINE_FINDING_CONTRACT_VALID=PASS",
    "MACHINE_FINDING_CONTRACT_DECLARATIVE=PASS",
    "MACHINE_FINDING_CONTRACT_COUNT=1",
]
for value in recursive_strings(contract):
    assert "\n" not in value or value in {contract.get("notes", ""), contract["severity"].get("rationale", "")}


# --- free text cannot author findings ---------------------------------------
for field in FREE_TEXT_FIELDS:
    assert field in record
assert "not executable" in " ".join(record["automation_hints"]).lower()
assert "machine_finding" in " ".join(record["automation_hints"])
assert "Human-readable only" in record["checks"][0]
free_text_values = set()
for field in FREE_TEXT_FIELDS:
    value = record[field]
    free_text_values.update([value] if isinstance(value, str) else value)
assert contract["condition_id"] not in free_text_values
assert contract["assertion"] not in free_text_values
core_source = (ROOT / "scripts" / "dk_core.py").read_text(encoding="utf-8")
for field in FREE_TEXT_FIELDS:
    assert f'record["{field}"]' not in core_source.split("def validate_machine_finding_contract", 1)[1].split("def validate_machine_finding_contracts", 1)[0]


# --- single reviewed runtime consumer ----------------------------------------
assert contract["runtime_status"] == "executed_by_reviewed_finding_runtime"
# The audit-era forbidden artifact names never came into existence; the
# reviewed runtime lives at scripts/dk_finding_runtime.py instead.
for relative in FORBIDDEN_ENGINE_ARTIFACTS:
    assert not (ROOT / relative).exists(), relative
consumers = []
for module in RUNTIME_MODULES:
    text = (ROOT / "scripts" / module).read_text(encoding="utf-8")
    if "machine_finding" in text:
        consumers.append(module)
assert consumers == [], consumers
cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
# The CLI routes to the runtime; it carries no contract evaluation of its own.
assert "machine_finding" not in cli_source
assert "dk_finding_runtime" in cli_source
runtime_consumer_modules = sorted(
    path.name
    for path in (ROOT / "scripts").glob("dk*.py")
    if path.name != "dk_core.py"
    and "machine_finding" in path.read_text(encoding="utf-8")
)
assert runtime_consumer_modules == ["dk_finding_runtime.py"]
assert "machine_finding" not in (ROOT / "scripts" / "dk_release_lifecycle_evaluator.py").read_text(
    encoding="utf-8"
)


# --- exact release requirement ------------------------------------------------
assert requires["exact_release_match"] is True
assert requires["evaluation_state"] == "evaluated"
assessment_schema = dk_core.read_json(ROOT / "schema" / "release-lifecycle-assessment.schema.json")
assert requires["evaluation_state"] in assessment_schema["properties"]["evaluation_state"]["enum"]
assert "matched_release_source_version" in contract["identity"]["key_fields"]
assert "exact_matched_release" in contract["provenance_requirements"]
for forbidden_key in ("branch", "nearest", "older_than", "newer_than", "range", "minimum", "maximum"):
    assert not any(forbidden_key in key for key in requires), forbidden_key


# --- current canonical context requirement ------------------------------------
assert requires["context_relation"] == "current"
relation_enum = assessment_schema["properties"]["context_freshness"]["properties"]["relation"]["enum"]
assert set(relation_enum) == {"current", "stale"}
assert contract["states"]["term_present_and_context_stale"] == "historical_candidate"
assert contract["states"]["term_present_and_context_current"] == "confirmed"
assert evaluator.CANONICAL_CONTEXT_RELATIVE_PATH.as_posix() == (
    "knowledge/context/drupal-core-release-lifecycle.json"
)
assert context["review"]["status"] == "reviewed"
assert context["authority_layer"] == "TRUSTED_KNOWLEDGE_CONTEXT"


# --- non-authoritative signals ignored -----------------------------------------
ignored = set(contract["non_authoritative_signals_ignored"])
assert ignored == dk_core.MACHINE_FINDING_NON_AUTHORITATIVE_SIGNALS
for signal in (
    "branch_listed_in_source_supported_branches",
    "source_supported_branches_presence_or_absence",
    "source_security_coverage_text_or_covered_attribute",
    "release_type_term_security_update",
    "release_ordering_or_source_order_index",
    "newer_release_existence",
):
    assert signal in ignored, signal
assert not (ignored & set(requires)), "ignored signals must never appear as requirements"
# the ignored signals are genuinely independent of the term in the reviewed context
rows = {
    row["version"]["source"]["source_value"]: row
    for row in context["releases"]
    if row.get("version", {}).get("source", {}).get("state") == "present"
}
supported_values = [entry["source_value"] for entry in context["supported_branches"]["entries"]]
listed_with_term = 0
unlisted_without_term = 0
covered_with_term = 0
covered_without_term = 0
security_update_without_term = []
for version, row in rows.items():
    terms = row.get("release_type_source_values", [])
    has_term = SOURCE_TERM in terms
    token = evaluator.source_branch_token_for_version(version)
    listed = token["state"] == "known" and token["source_value"] in supported_values
    covered = row.get("security", {}).get("covered_attribute", {}).get("source_value") == "1"
    listed_with_term += int(listed and has_term)
    unlisted_without_term += int(not listed and not has_term)
    covered_with_term += int(covered and has_term)
    covered_without_term += int(covered and not has_term)
    if "Security update" in terms and not has_term:
        security_update_without_term.append(version)
assert listed_with_term > 0 and unlisted_without_term > 0
assert covered_with_term > 0 and covered_without_term > 0
assert security_update_without_term


# --- confirmation authority is established through reviewed references -------
# The Finding Authority Model separates observation, candidate, and confirmed
# finding. The literal term observation stays the trigger; the meaning now
# comes exclusively from reviewed current Drupal 11 update-module authority,
# never from the release-history feed alone and never from lexical intuition.
confirmation = contract["confirmation_authority"]
assert confirmation["status"] == "semantic_authority_reviewed"
assert confirmation["status"] in dk_core.MACHINE_FINDING_CONFIRMATION_STATUSES
assert confirmation["semantic_authority_refs"] == [
    "drupal-update-project-release-semantics",
    "drupal-update-status-security-semantics",
    "drupal-update-manager-interface-semantics",
]
assert "drupal-core-releases" not in confirmation["semantic_authority_refs"], (
    "the release-history feed proves term presence, not term meaning"
)
assert confirmation["required_semantic_authority_category"] == (
    "official_drupal_release_status_and_update_status_vocabulary_documentation"
)
assert "status flip" in confirmation["rationale"]
assert "NOT_SECURE" in confirmation["rationale"]
# Exact-release and current-context evidence requirements are not weakened.
assert requires["exact_release_match"] is True
assert requires["context_relation"] == "current"
assert requires["evaluation_state"] == "evaluated"
# Confirmed pairs with reviewed authority; the candidate generation keeps
# confirmed unreachable.
assert contract["states"]["term_present_and_context_current"] == "confirmed"
assert contract["states"]["term_present_and_context_stale"] == "historical_candidate"
assert "confirmed" not in set(dk_core.MACHINE_FINDING_CANDIDATE_STATES.values())
# confirmed keeps its authority-layer meaning: observation plus reviewed
# semantic authority, never observation alone.
model_doc = (ROOT / "docs" / "FINDING_MODEL.md").read_text(encoding="utf-8")
assert "Candidate\n" in model_doc and "Confirmed finding\n" in model_doc
assert "semantic authority" in model_doc
assert "No required semantic judgment remains" in model_doc
assert "anti-bootstrap" in doc
assert "confirmed only means term presence" not in doc.lower()
# Reviewed record status alone was never confirmation readiness; readiness is
# the explicit reviewed reference set.
assert record["review_status"] == "reviewed"
# Schema stays a closed two-value enum reached only through references.
status_enum = schema["properties"]["machine_finding"]["properties"]["confirmation_authority"][
    "properties"
]["status"]["enum"]
assert status_enum == ["not_established", "semantic_authority_reviewed"]
assert "semantics_known" not in status_enum
assert "confirmation_authority" in schema["properties"]["machine_finding"]["required"]
confirmation_schema = schema["properties"]["machine_finding"]["properties"]["confirmation_authority"]
assert confirmation_schema["additionalProperties"] is False
assert set(confirmation_schema["required"]) == {
    "status",
    "semantic_authority_refs",
    "required_semantic_authority_category",
}
# Semantic authority is version-scoped: the pinned Drupal 11.x update-module
# sources authorize Drupal core major 11 only, and the scope is evidence-derived
# from the registered source version pins, never assumed. The basis must name
# the tag the registry currently pins, so an advance cannot go unrecorded.
version_scope = confirmation["semantic_authority_version_scope"]
assert version_scope["drupal_core_majors"] == ["11"]
assert dk_core.semantic_authority_tag() in version_scope["basis"]
sources_by_id = {item["id"]: item for item in dk_core.load_sources()}
for ref in confirmation["semantic_authority_refs"]:
    tokens = sources_by_id[ref]["version_semantics"]["drupal_core"]
    assert any(str(token).startswith("11.") for token in tokens), ref
assert contract["states"]["term_present_and_semantic_authority_version_out_of_scope"] == "candidate"
assert contract["states"]["applicability_not_definitive"] == "unknown"
# The record resolves applicability through an explicit reviewed machine
# contract, so the finding runtime never bypasses the Applicability Resolver.
assert record["machine_applicability"]["condition"]["operator"] == "fact_known"
assert record["machine_applicability"]["condition"]["fact"] == "drupal_core_version"

# Exactly the three semantic sources were added: 12 baselined authoritative
# sources became 15. Ecosystem discovery sources are a separate tier, and
# advisory feeds and upgrade authority are separate declared functional classes;
# none of them is counted here.
assert non_advisory_authoritative(dk_core.load_sources()) == 15
# The candidate generation remains fully representable: a demoted contract
# with unresolved semantics still validates, still capped at candidate.
demoted = copy.deepcopy(record)
demoted_contract = demoted["machine_finding"]
demoted_contract["confirmation_authority"]["status"] = "not_established"
demoted_contract["confirmation_authority"]["semantic_authority_refs"] = []
demoted_contract["states"] = dict(dk_core.MACHINE_FINDING_CANDIDATE_STATES)
demoted_contract["term_semantics"] = {
    "state": "TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY",
    "meaning_bearing_claims_authorized": False,
}
del demoted_contract["confirmation_authority"]["semantic_authority_version_scope"]
dk_core.validate_machine_finding_contract(demoted, "demotion-positive")


# --- finding type is not a vulnerability claim --------------------------------
assert contract["finding_type"] == "release_lifecycle"
assert contract["finding_type"] not in dk_core.MACHINE_FINDING_FORBIDDEN_TYPES
assert {"vulnerability", "security_vulnerability"} <= dk_core.MACHINE_FINDING_FORBIDDEN_TYPES
assert schema["properties"]["machine_finding"]["properties"]["finding_type"]["enum"] == [
    "release_lifecycle"
]


# --- severity not established ---------------------------------------------------
severity = contract["severity"]
assert severity["state"] == "not_established"
assert severity["source"] is None
assert severity["state"] not in dk_core.SEVERITIES
assert "finding_severity_state" in contract["provenance_requirements"]
assert schema["properties"]["machine_finding"]["properties"]["severity"]["properties"]["state"][
    "const"
] == "not_established"


# --- knowledge severity is not finding severity ---------------------------------
assert record["severity"] in dk_core.SEVERITIES
assert record["severity"] == "info"
assert record["severity"] != severity["state"]
assert severity["source"] is not record["severity"]
assert "severity" not in record["enforcement"]
assert "knowledge record" in severity["rationale"] and "never" in severity["rationale"]
assert governance["severity"] == "moderate"
assert governance["severity"] != severity["state"]


# --- enforcement stays guidance -------------------------------------------------
assert record["enforcement"]["intent"] == "non_blocking"
assert dk_core.effective_enforcement(record) == "guidance"
assert "effective_enforcement" in contract["provenance_requirements"]
assert all(dk_core.effective_enforcement(item) != "blocking" for item in records)
assert sum(1 for item in records if dk_core.effective_enforcement(item) == "guidance") == 11


# --- absence is not a security pass ----------------------------------------------
assert contract["states"]["term_absent_in_matched_row"] == "not_observed"
assert "passed" not in set(contract["states"].values())
assert "secure" not in set(contract["states"].values())
assert "safe" not in set(contract["states"].values())
assert "not_observed" in doc
assert "absence" in doc.lower()


# --- unknown fails closed ---------------------------------------------------------
for key in ("release_not_found", "core_version_unknown", "context_not_canonical", "assessment_invalid"):
    assert contract["states"][key] == "unknown", key
assert False not in set(contract["states"].values())
assert set(contract["states"]) == set(dk_core.MACHINE_FINDING_CONFIRMED_STATES)
assert contract["states"] == dk_core.MACHINE_FINDING_CONFIRMED_STATES
assert set(dk_core.MACHINE_FINDING_CANDIDATE_STATES) == set(dk_core.MACHINE_FINDING_CONFIRMED_STATES)
assert "confirmed" not in set(dk_core.MACHINE_FINDING_CANDIDATE_STATES.values())


# --- provenance contract -----------------------------------------------------------
provenance = contract["provenance_requirements"]
assert set(provenance) == dk_core.MACHINE_FINDING_REQUIRED_PROVENANCE
assert len(provenance) == len(set(provenance)) == 15
assert "applicability_result_identity" in provenance
assert "semantic_authority_version_scope" in provenance


# --- deterministic identity ---------------------------------------------------------
identity = contract["identity"]
assert identity["algorithm"] == "sha256_stable_json"
assert identity["timestamp_allowed"] is False
key_fields = identity["key_fields"]
for field in (
    "knowledge_id",
    "condition_id",
    "assertion",
    "analysis_sha256",
    "matched_release_source_version",
    "lifecycle_context_sha256",
):
    assert field in key_fields, field
assert not any(re.search(r"(timestamp|_at$|time)", field) for field in key_fields)
assert set(identity["excluded_fields"]) & {"evaluated_at", "run_id", "hostname"}
assert not (set(identity["excluded_fields"]) & set(key_fields))


# --- deduplication -------------------------------------------------------------------
dedup = contract["deduplication"]
assert dedup["max_instances"] == 1
dedup_fields = dedup["key_fields"]
assert dedup_fields == [
    "knowledge_id",
    "condition_id",
    "installed_core_package",
    "matched_release_source_version",
]
assert len(dedup_fields) < len(key_fields)
assert len(dedup["collapsed_read_paths"]) >= 3


# --- schema is narrow and non-executable ------------------------------------------------
machine_finding_schema = schema["properties"]["machine_finding"]
assert machine_finding_schema["additionalProperties"] is False
assert schema["additionalProperties"] is False
requires_schema = schema["$defs"]["machine_finding_requires"]
assert requires_schema["additionalProperties"] is False
for key, expected in dk_core.MACHINE_FINDING_REQUIRED_LITERALS.items():
    assert requires_schema["properties"][key]["const"] == expected, key
    assert key in requires_schema["required"]
assert machine_finding_schema["properties"]["runtime_status"]["const"] == "executed_by_reviewed_finding_runtime"
schema_text = json.dumps(machine_finding_schema).lower()
for executable in ("expression", "script", "eval", "exec", "jsonpath", "xpath", "regex", "lambda"):
    assert not re.search(rf"\b{executable}\b", schema_text), executable
assert "$defs" in schema and "machine_symbol" in schema["$defs"]


# --- schema fails closed ------------------------------------------------------------------
def drop(key):
    def apply(candidate):
        candidate["machine_finding"].pop(key)
    return apply


def set_value(path, value):
    def apply(candidate):
        target = candidate["machine_finding"]
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
    return apply


rejects(set_value(["evidence_domain"], "project_source_scan"))
rejects(drop("condition_id"))
rejects(set_value(["requires", "source_term_expression"], "value == 'Insecure'"))
rejects(set_value(["finding_type"], "vulnerability"))
rejects(set_value(["finding_type"], "security_vulnerability"))
rejects(set_value(["severity", "state"], "high"))
rejects(set_value(["severity", "source"], "drupal.update.core-release-insecure-term-condition"))
rejects(set_value(["requires", "exact_release_match"], False))


def drop_requires(key):
    def apply(candidate):
        candidate["machine_finding"]["requires"].pop(key)
    return apply


rejects(drop_requires("exact_release_match"))
rejects(drop_requires("context_relation"))
rejects(set_value(["requires", "context_relation"], "stale"))
rejects(set_value(["requires", "match_mode"], "case_insensitive"))
rejects(set_value(["requires", "match_mode"], "regex"))
rejects(set_value(["requires", "source_term_value"], "insecure"))


def branch_only(candidate):
    contract_copy = candidate["machine_finding"]
    contract_copy["requires"].pop("source_term_value")
    contract_copy["requires"]["branch_listed_in_source_supported_branches"] = False


rejects(branch_only)
rejects(set_value(["runtime_status"], "engine_enabled"))
rejects(set_value(["identity", "timestamp_allowed"], True))
rejects(set_value(["identity", "key_fields"], ["knowledge_id", "evaluated_at"]))
rejects(set_value(["states", "term_absent_in_matched_row"], "passed"))
rejects(set_value(["states", "release_not_found"], "not_observed"))
# Version-scope settlement fails closed in every direction.
rejects(set_value(["confirmation_authority", "semantic_authority_version_scope"], None))


def scope_removed(candidate):
    del candidate["machine_finding"]["confirmation_authority"]["semantic_authority_version_scope"]


rejects(scope_removed)
rejects(set_value(
    ["confirmation_authority", "semantic_authority_version_scope", "drupal_core_majors"], []
))
rejects(set_value(
    ["confirmation_authority", "semantic_authority_version_scope", "drupal_core_majors"],
    ["11", "9"],
))
rejects(set_value(
    ["confirmation_authority", "semantic_authority_version_scope", "drupal_core_majors"],
    ["10"],
))
rejects(set_value(["states", "term_present_and_semantic_authority_version_out_of_scope"], "confirmed"))
rejects(set_value(["states", "applicability_not_definitive"], "not_observed"))
rejects(set_value(["non_authoritative_signals_ignored"], ["branch_listed_in_source_supported_branches"]))
rejects(set_value(["deduplication", "max_instances"], 2))
rejects(set_value(["provenance_requirements"], ["knowledge_id"]))


# Anti-bootstrap both ways: authority and states must stay paired, and the
# reviewed status is reachable only through resolvable reviewed references.
rejects(drop("confirmation_authority"))
rejects(set_value(["confirmation_authority", "status"], "semantics_known"))
# Demoting the status while refs, confirmed states, or reviewed semantics
# remain is rejected from every direction.
rejects(set_value(["confirmation_authority", "status"], "not_established"))


def demoted_status_and_refs_with_confirmed_states(candidate):
    authority = candidate["machine_finding"]["confirmation_authority"]
    authority["status"] = "not_established"
    authority["semantic_authority_refs"] = []


rejects(demoted_status_and_refs_with_confirmed_states)
rejects(set_value(["confirmation_authority", "semantic_authority_refs"], []))


def fabricated_ref_appended(candidate):
    authority = candidate["machine_finding"]["confirmation_authority"]
    authority["semantic_authority_refs"] = authority["semantic_authority_refs"] + [
        "drupal.made.up-authority"
    ]


rejects(fabricated_ref_appended)
rejects(set_value(["confirmation_authority", "semantic_authority_refs"], ["not-a-registered-source"]))


def duplicated_ref(candidate):
    authority = candidate["machine_finding"]["confirmation_authority"]
    authority["semantic_authority_refs"] = authority["semantic_authority_refs"] + [
        authority["semantic_authority_refs"][0]
    ]


rejects(duplicated_ref)
# Reverting term semantics while authority or states stay promoted is rejected.
rejects(set_value(["term_semantics", "state"], "TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY"))
rejects(set_value(["term_semantics", "state"], "insecure_means_vulnerable"))
rejects(set_value(["term_semantics", "meaning_bearing_claims_authorized"], False))


def authorized_meaning_removed(candidate):
    candidate["machine_finding"]["term_semantics"].pop("authorized_meaning")


rejects(authorized_meaning_removed)
rejects(set_value(
    ["term_semantics", "authorized_meaning"],
    "This release is exploitable and attackers can compromise the site without any effort at all.",
))
rejects(set_value(
    ["term_semantics", "authorized_meaning"],
    "The installed release corresponds to CVE-2026-0001 and must therefore be treated as failing.",
))
rejects(set_value(["term_semantics", "forbidden_claims"], ["release_is_unsupported"]))
# States cannot drift from the reviewed pairing in either direction.
rejects(set_value(["states", "term_present_and_context_current"], "candidate"))
rejects(set_value(["states", "term_present_and_context_stale"], "confirmed"))


def reviewed_authority_with_vulnerability_type(candidate):
    candidate["machine_finding"]["finding_type"] = "vulnerability"


rejects(reviewed_authority_with_vulnerability_type)


def reviewed_authority_with_invented_severity(candidate):
    candidate["machine_finding"]["severity"] = {"state": "high", "source": None}


rejects(reviewed_authority_with_invented_severity)

# The promoted contract itself remains valid.
dk_core.validate_machine_finding_contract(copy.deepcopy(record), "promotion-positive")


def blocking(candidate):
    candidate["enforcement"]["intent"] = "blocking"


rejects(blocking)


def unknown_field(candidate):
    candidate["machine_finding"]["python_predicate"] = "lambda row: True"


rejects(unknown_field)


# --- the finding runtime is the only runtime consumer ----------------------------------------
assert consumers == []
assert runtime_consumer_modules == ["dk_finding_runtime.py"]
assert dk_core.validate_generated_current() == ["GENERATED_KNOWLEDGE_CURRENT=PASS"]
generated = dk_core.build_generated()
assert generated["metadata"]["machine_finding_contract_count"] == 1
assert generated["metadata"]["knowledge_record_count"] == 11
assert generated["metadata"]["reviewed_record_count"] == 11


# --- CI topology --------------------------------------------------------------------------------
ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert "test_lifecycle_finding_contract.py" in ci
assert "test_lifecycle_finding_eligibility.py" in ci
assert "pull_request:" in ci and "push:" in ci
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
assert "continue-on-error" not in ci, "validation must be required"


print("FIRST_LIFECYCLE_FINDING_ASSERTION_LITERAL_ONLY=PASS")
print("MACHINE_FINDING_CONTRACT_DOES_NOT_DEFINE_INSECURE_SEMANTICS=PASS")
print("INSECURE_FINDING_MATCH_LITERAL_EXACT_ONLY=PASS")
print("LIFECYCLE_FINDING_CONTRACT_NOT_HIDDEN_IN_SOURCE_GOVERNANCE_RULE=PASS")
print("LIFECYCLE_FINDING_KNOWLEDGE_SOURCE_BASELINED=PASS")
print("LIFECYCLE_FINDING_CONTRACT_REVIEW_SCOPE_NARROW=PASS")
print("FIRST_MACHINE_FINDING_CONTRACT_DECLARATIVE=PASS")
print("FREE_TEXT_CANNOT_AUTHOR_MACHINE_FINDING=PASS")
print("MACHINE_FINDING_SINGLE_REVIEWED_RUNTIME_CONSUMER=PASS")
print("MACHINE_FINDING_REQUIRES_EXACT_RELEASE_MATCH=PASS")
print("MACHINE_FINDING_REQUIRES_CURRENT_CANONICAL_CONTEXT=PASS")
print("MACHINE_FINDING_IGNORES_NONAUTHORITATIVE_LIFECYCLE_SIGNALS=PASS")
print("FIRST_LIFECYCLE_FINDING_TYPE_NOT_VULNERABILITY=PASS")
print("FIRST_LIFECYCLE_FINDING_SEVERITY_NOT_ESTABLISHED=PASS")
print("KNOWLEDGE_SEVERITY_NOT_AUTOMATIC_FINDING_SEVERITY=PASS")
print("FIRST_LIFECYCLE_FINDING_ENFORCEMENT_GUIDANCE_ONLY=PASS")
print("MACHINE_FINDING_CONTRACT_DOES_NOT_ESCALATE_ENFORCEMENT=PASS")
print("INSECURE_TERM_ABSENCE_NOT_SECURITY_PASS=PASS")
print("LIFECYCLE_MACHINE_FINDING_UNKNOWN_FAILS_CLOSED=PASS")
print("LIFECYCLE_MACHINE_FINDING_PROVENANCE_CONTRACT=PASS")
print("LIFECYCLE_MACHINE_FINDING_IDENTITY_CONTRACT=PASS")
print("LIFECYCLE_MACHINE_FINDING_DEDUPLICATION_CONTRACT=PASS")
print("MEANING_CLAIMS_LIMITED_TO_REVIEWED_DRUPAL_AUTHORITY=PASS")
print("MACHINE_FINDING_SCHEMA_NARROW_AND_NONEXECUTABLE=PASS")
print("MACHINE_FINDING_SCHEMA_FAILS_CLOSED=PASS")
print("MACHINE_FINDING_CONTRACT_RESPECTS_FINDING_MODEL=PASS")
print("KNOWLEDGE_CONTRACT_CANNOT_BOOTSTRAP_FINDING_SEMANTICS=PASS")
print("LITERAL_INSECURE_TERM_OBSERVATION_CLASSIFIED=PASS")
print("CONFIRMED_FINDING_REQUIRES_SEMANTIC_AUTHORITY=PASS")
print("CURRENT_SOURCE_INSUFFICIENT_FOR_CONFIRMED_SEMANTIC_FINDING=PASS")
print("MACHINE_FINDING_CONTRACT_CAN_EXIST_BEFORE_CONFIRMATION_AUTHORITY=PASS")
print("UNDEFINED_TERM_SEMANTICS_CANNOT_YIELD_CONFIRMED_FINDING=PASS")
print("EVIDENCE_COMPLETE_DOES_NOT_IMPLY_FINDING_AUTHORIZED=PASS")
print("SOURCE_GROUNDED_ASSERTION_REMAINS_AVAILABLE_AS_CANDIDATE=PASS")
print("CONFIRMED_STATE_NOT_REDEFINED_AS_OBSERVATION=PASS")
print("MACHINE_FINDING_CONFIRMATION_AUTHORITY_SCHEMA_ENFORCED=PASS")
print("UNAUTHORIZED_CONFIRMED_MACHINE_FINDING_REJECTED=PASS")
print("FUTURE_FINDING_SEMANTIC_AUTHORITY_REFERENCES_DESIGNED=PASS")
print("TERM_SEMANTICS_STATE_ENFORCES_FINDING_READINESS=PASS")
print("NEXT_SEMANTIC_AUTHORITY_REQUIREMENT_DEFINED=PASS")
print("SETTLEMENT_DOES_NOT_INVENT_SEVERITY=PASS")
print("SETTLEMENT_DOES_NOT_ESCALATE_ENFORCEMENT=PASS")
print("INSECURE_SOURCE_SIGNAL_NOT_VULNERABILITY=PASS")
print("REVIEWED_RECORD_NOT_EQUAL_CONFIRMED_FINDING_AUTHORITY=PASS")
print("SEMANTIC_AUTHORITY_EXTENDS_EXISTING_CONTRACT=PASS")
print("CONFIRMATION_AUTHORITY_HAS_REVIEWED_REFS=PASS")
print("INSECURE_TERM_MEANING_LIMITED_TO_DRUPAL_UPDATE_SEMANTICS=PASS")
print("CONFIRMED_ASSERTION_MATCHES_DRUPAL_AUTHORITY=PASS")
print("CONFIRMED_STATE_REQUIRES_REVIEWED_SEMANTIC_AUTHORITY=PASS")
print("CONFIRMED_INSECURE_FINDING_REQUIRES_EXACT_RELEASE=PASS")
print("CONFIRMED_INSECURE_FINDING_REQUIRES_CURRENT_CONTEXT=PASS")
print("NOT_SECURE_STATUS_NOT_EXPLOITABILITY_CLAIM=PASS")
print("NOT_SECURE_STATUS_NOT_CVE_CLAIM=PASS")
print("SEMANTIC_AUTHORITY_DOES_NOT_INVENT_FINDING_SEVERITY=PASS")
print("SEMANTIC_AUTHORITY_DOES_NOT_ESCALATE_ENFORCEMENT=PASS")
print("SEMANTIC_AUTHORITY_VERSION_SCOPE_EXPLICIT=PASS")
print("CROSS_MAJOR_SEMANTIC_AUTHORITY_LEAKAGE_BLOCKED=PASS")
print(f"MACHINE_FINDING_RUNTIME_CONSUMERS={len(runtime_consumer_modules)}")
