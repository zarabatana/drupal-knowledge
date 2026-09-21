#!/usr/bin/env python3
"""Evidence-backed applicability resolution for Drupal Knowledge."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

import dk_core
import dk_project_analyzer


RESOLVER_NAME = "drupal-knowledge-applicability-resolver"
RESOLVER_VERSION = "0.1"
SUPPORTED_ANALYSIS_SCHEMA = "0.1"
SUPPORTED_MACHINE_CONTRACT = "0.1"

TRUE = "TRUE"
FALSE = "FALSE"
UNKNOWN = "UNKNOWN"
TRUTH_VALUES = {TRUE, FALSE, UNKNOWN}

APPLICABILITY_STATES = {
    "applicable",
    "not_applicable",
    "unknown",
    "requires_human_review",
}
SUPPORTED_OPERATORS = {
    "fact_known",
    "equals",
    "list_contains",
    "list_not_contains",
    "list_non_empty",
    "version_matches",
    # Predicates over canonical project evidence. They read the evidence layer
    # rather than the analyzer facts directly, so a rule can require "package X
    # installed" without this resolver ever opening a project manifest itself.
    "evidence_matches",
    "evidence_absent",
}

# The evidence operators name an assertion and a subject instead of a fact.
EVIDENCE_OPERATORS = {"evidence_matches", "evidence_absent"}
ASSERTION_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
SUBJECT_RE = re.compile(r"^[\w./:@*+-]{1,200}$")
PATH_SEGMENT_RE = r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*"
PATH_RE = re.compile(rf"^{PATH_SEGMENT_RE}(?:\.{PATH_SEGMENT_RE})*$")
STABLE_VERSION_RE = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)$")
MAJOR_BRANCH_RE = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.x$")


class ResolverInputError(RuntimeError):
    """Raised when the resolver CLI input cannot be read."""


class ResolverValidationError(RuntimeError):
    """Raised when analysis, knowledge, or resolver output is invalid."""


@dataclass(frozen=True)
class PredicateOutcome:
    """Three-valued predicate result with provenance."""

    value: str
    evaluations: list[dict[str, Any]]
    reason_codes: set[str]
    fact_refs: set[str]
    evidence_ids: set[str]
    missing_facts: set[str]


@dataclass(frozen=True)
class LegacyOutcome:
    """Conservative applicability result for existing pre-contract records."""

    applicability: str
    automation_status: str
    evaluations: list[dict[str, Any]]
    reason_codes: set[str]
    fact_refs: set[str]
    evidence_ids: set[str]
    missing_facts: set[str]


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def tvl_and(values: list[str]) -> str:
    if any(value == FALSE for value in values):
        return FALSE
    if any(value == UNKNOWN for value in values):
        return UNKNOWN
    return TRUE


def tvl_or(values: list[str]) -> str:
    if any(value == TRUE for value in values):
        return TRUE
    if any(value == UNKNOWN for value in values):
        return UNKNOWN
    return FALSE


def tvl_not(value: str) -> str:
    if value == TRUE:
        return FALSE
    if value == FALSE:
        return TRUE
    return UNKNOWN


def merge_outcomes(value: str, outcomes: list[PredicateOutcome], group_code: str) -> PredicateOutcome:
    reason_codes = {group_code}
    fact_refs: set[str] = set()
    evidence_ids: set[str] = set()
    missing_facts: set[str] = set()
    evaluations: list[dict[str, Any]] = []
    for outcome in outcomes:
        reason_codes.update(outcome.reason_codes)
        fact_refs.update(outcome.fact_refs)
        evidence_ids.update(outcome.evidence_ids)
        missing_facts.update(outcome.missing_facts)
        evaluations.extend(outcome.evaluations)
    return PredicateOutcome(value, evaluations, reason_codes, fact_refs, evidence_ids, missing_facts)


def fact_object(analysis: dict[str, Any], fact_name: str) -> dict[str, Any] | None:
    facts = analysis.get("profile", {}).get("facts", {})
    item = facts.get(fact_name)
    return item if isinstance(item, dict) else None


def fact_evidence_ids(fact: dict[str, Any] | None) -> set[str]:
    if not isinstance(fact, dict):
        return set()
    ids = fact.get("source_evidence_ids", [])
    if not isinstance(ids, list):
        return set()
    return {item for item in ids if isinstance(item, str)}


def lookup_fact_value(
    analysis: dict[str, Any],
    fact_name: str,
    value_path: str | None,
) -> tuple[str, Any | None, set[str], set[str], set[str]]:
    if not PATH_RE.fullmatch(fact_name):
        return UNKNOWN, None, set(), set(), {fact_name}
    fact = fact_object(analysis, fact_name)
    if fact is None:
        return UNKNOWN, None, {fact_name}, set(), {fact_name}
    evidence_ids = fact_evidence_ids(fact)
    state = fact.get("state")
    if state == "unknown":
        return UNKNOWN, None, {fact_name}, evidence_ids, {fact_name}
    if state == "not_applicable":
        return FALSE, None, {fact_name}, evidence_ids, set()
    if state != "known":
        return UNKNOWN, None, {fact_name}, evidence_ids, {fact_name}
    current: Any = fact
    path = value_path or "value"
    if not PATH_RE.fullmatch(path):
        return UNKNOWN, None, {fact_name}, evidence_ids, {fact_name}
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return UNKNOWN, None, {fact_name}, evidence_ids, {fact_name}
        current = current[part]
    return TRUE, current, {fact_name}, evidence_ids, set()


def fact_domain_complete(analysis: dict[str, Any], fact_name: str) -> bool:
    completeness = analysis.get("completeness", {})
    if fact_name in {"modules", "themes", "installation_profile", "commerce", "views", "search_api", "authentication", "multilingual"}:
        return completeness.get("drupal_config") == "available"
    if fact_name in {"custom_modules", "custom_themes", "base_themes"}:
        custom = completeness.get("custom_extension_inventory", {})
        return isinstance(custom, dict) and custom.get("state") == "available"
    if fact_name == "composer_packages":
        return completeness.get("composer_declaration") == "available" or completeness.get("installed_package_evidence") == "available"
    return True


def predicate_result(
    predicate: dict[str, Any],
    value: str,
    reason_codes: set[str],
    fact_refs: set[str] | None = None,
    evidence_ids: set[str] | None = None,
    missing_facts: set[str] | None = None,
) -> PredicateOutcome:
    predicate_id = predicate.get("id", predicate.get("operator", "predicate"))
    evaluation = {
        "id": predicate_id,
        "operator": predicate.get("operator", "group"),
        "result": value,
        "reason_codes": sorted(reason_codes),
    }
    if "fact" in predicate:
        evaluation["fact"] = predicate["fact"]
    if "path" in predicate:
        evaluation["path"] = predicate["path"]
    if fact_refs:
        evaluation["fact_refs"] = sorted(fact_refs)
    if evidence_ids:
        evaluation["evidence_ids"] = sorted(evidence_ids)
    if missing_facts:
        evaluation["missing_facts"] = sorted(missing_facts)
    return PredicateOutcome(
        value,
        [evaluation],
        set(reason_codes),
        set(fact_refs or []),
        set(evidence_ids or []),
        set(missing_facts or []),
    )


def stable_version_parts(version: Any) -> tuple[int, int, int] | None:
    if not isinstance(version, str):
        return None
    match = STABLE_VERSION_RE.fullmatch(version)
    if not match:
        return None
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )


def version_constraint_result(version: Any, constraint: Any) -> tuple[str, str]:
    parts = stable_version_parts(version)
    if parts is None:
        return UNKNOWN, "UNSUPPORTED_VERSION_SEMANTICS"
    if not isinstance(constraint, str):
        return UNKNOWN, "UNSUPPORTED_VERSION_CONSTRAINT"
    branch = MAJOR_BRANCH_RE.fullmatch(constraint)
    if branch:
        return (TRUE if parts[0] == int(branch.group("major")) else FALSE), (
            "VERSION_CONSTRAINT_MATCH" if parts[0] == int(branch.group("major")) else "VERSION_CONSTRAINT_MISMATCH"
        )
    exact = stable_version_parts(constraint)
    if exact is not None:
        return (TRUE if parts == exact else FALSE), (
            "VERSION_CONSTRAINT_MATCH" if parts == exact else "VERSION_CONSTRAINT_MISMATCH"
        )
    return UNKNOWN, "UNSUPPORTED_VERSION_CONSTRAINT"


def evidence_predicate_result(
    predicate: dict[str, Any],
    value: str,
    reason_codes: set[str],
    subject: str,
    record: dict[str, Any] | None = None,
) -> PredicateOutcome:
    """A predicate outcome that carries the evidence record it read."""
    evaluation = {
        "id": predicate.get("id", predicate.get("operator", "predicate")),
        "operator": predicate.get("operator", "group"),
        "result": value,
        "reason_codes": sorted(reason_codes),
        "assertion": predicate.get("assertion"),
        "subject": subject,
    }
    evidence_ids: set[str] = set()
    if record is not None:
        evaluation["evidence_state"] = record["observation"]["state"]
        evaluation["evidence_quality"] = record["observation"]["quality"]
        evaluation["search_domain"] = record["completeness"]["search_domain"]
        evidence_ids = {record["evidence_id"]}
        evaluation["evidence_ids"] = sorted(evidence_ids)
    return PredicateOutcome(value, [evaluation], set(reason_codes), set(), evidence_ids, set())


def evaluate_evidence_predicate(
    predicate: dict[str, Any],
    evidence_index: dict[str, Any] | None,
) -> PredicateOutcome:
    """Evaluate one predicate against canonical project evidence.

    Three rules decide the answer. A heuristic observation never settles
    anything. A missing record is unknown unless the assertion's search domain
    is complete, because only a complete enumeration turns "not found" into
    "not there". And any state that is not a clean observation propagates as
    unknown rather than collapsing to false.
    """
    operator = predicate.get("operator")
    assertion = predicate.get("assertion")
    subject = predicate.get("subject")
    if not isinstance(assertion, str) or not isinstance(subject, str):
        return evidence_predicate_result(
            predicate, UNKNOWN, {"UNSUPPORTED_PREDICATE"}, str(subject)
        )
    if evidence_index is None:
        return evidence_predicate_result(
            predicate, UNKNOWN, {"PROJECT_EVIDENCE_UNAVAILABLE"}, subject
        )
    if assertion not in dk_evidence_assertions():
        return evidence_predicate_result(
            predicate, UNKNOWN, {"UNSUPPORTED_EVIDENCE_ASSERTION"}, subject
        )

    record = evidence_index["by_key"].get((assertion, subject))
    domain_complete = bool(evidence_index["assertion_complete"].get(assertion))

    if operator == "evidence_absent":
        if record is None:
            if domain_complete:
                return evidence_predicate_result(
                    predicate, TRUE, {"AUTHORITATIVE_ABSENCE"}, subject
                )
            return evidence_predicate_result(
                predicate, UNKNOWN, {"EVIDENCE_DOMAIN_INCOMPLETE"}, subject
            )
        state = record["observation"]["state"]
        if state == "not_observed":
            return evidence_predicate_result(
                predicate, TRUE, {"AUTHORITATIVE_ABSENCE"}, subject, record
            )
        if state == "observed":
            return evidence_predicate_result(
                predicate, FALSE, {"EVIDENCE_OBSERVED"}, subject, record
            )
        return evidence_predicate_result(
            predicate, UNKNOWN, {"EVIDENCE_STATE_NOT_DEFINITIVE"}, subject, record
        )

    # evidence_matches
    if record is None:
        return evidence_predicate_result(
            predicate, UNKNOWN, {"EVIDENCE_NOT_OBSERVED"}, subject
        )
    observation = record["observation"]
    if not observation["definitive"]:
        # A heuristic candidate, or a state that settles nothing. Either way it
        # is not allowed to decide a rule.
        return evidence_predicate_result(
            predicate,
            UNKNOWN,
            {"HEURISTIC_EVIDENCE_NOT_DEFINITIVE"}
            if observation["quality"] == "heuristic_candidate"
            else {"EVIDENCE_STATE_NOT_DEFINITIVE"},
            subject,
            record,
        )
    if observation["state"] == "not_observed":
        return evidence_predicate_result(
            predicate, FALSE, {"AUTHORITATIVE_ABSENCE"}, subject, record
        )
    if "value" not in predicate:
        return evidence_predicate_result(predicate, TRUE, {"EVIDENCE_OBSERVED"}, subject, record)

    import dk_evidence

    present, actual = dk_evidence.read_path(observation["value"], predicate.get("value_path"))
    if not present:
        return evidence_predicate_result(
            predicate, UNKNOWN, {"EVIDENCE_VALUE_PATH_ABSENT"}, subject, record
        )
    expected = predicate["value"]
    if type(actual) is not type(expected):  # noqa: E721 - exact JSON type safety is intentional.
        return evidence_predicate_result(
            predicate, UNKNOWN, {"PREDICATE_TYPE_MISMATCH"}, subject, record
        )
    matched = actual == expected
    return evidence_predicate_result(
        predicate,
        TRUE if matched else FALSE,
        {"EVIDENCE_VALUE_MATCH" if matched else "EVIDENCE_VALUE_CONTRADICTS_REQUIREMENT"},
        subject,
        record,
    )


def dk_evidence_assertions() -> tuple[str, ...]:
    import dk_evidence

    return dk_evidence.ASSERTIONS


def evaluate_leaf_predicate(
    predicate: dict[str, Any],
    analysis: dict[str, Any],
    evidence_index: dict[str, Any] | None = None,
) -> PredicateOutcome:
    operator = predicate.get("operator")
    if operator in EVIDENCE_OPERATORS:
        return evaluate_evidence_predicate(predicate, evidence_index)
    fact_name = predicate.get("fact")
    if operator not in SUPPORTED_OPERATORS or not isinstance(fact_name, str):
        return predicate_result(predicate, UNKNOWN, {"UNSUPPORTED_PREDICATE"}, missing_facts={str(fact_name)})

    if operator == "fact_known":
        state, _value, fact_refs, evidence_ids, missing = lookup_fact_value(analysis, fact_name, "state")
        if state == UNKNOWN:
            return predicate_result(predicate, UNKNOWN, {"FACT_UNKNOWN"}, fact_refs, evidence_ids, missing)
        fact = fact_object(analysis, fact_name)
        if fact and fact.get("state") == "known":
            return predicate_result(predicate, TRUE, {"FACT_KNOWN"}, fact_refs, evidence_ids)
        return predicate_result(predicate, FALSE, {"FACT_NOT_KNOWN"}, fact_refs, evidence_ids)

    path = predicate.get("path")
    if path is not None and not isinstance(path, str):
        return predicate_result(predicate, UNKNOWN, {"INVALID_FACT_PATH"}, {fact_name}, missing_facts={fact_name})
    state, actual, fact_refs, evidence_ids, missing = lookup_fact_value(analysis, fact_name, path)
    if state == UNKNOWN:
        return predicate_result(predicate, UNKNOWN, {"FACT_UNKNOWN"}, fact_refs, evidence_ids, missing)
    if state == FALSE:
        return predicate_result(predicate, FALSE, {"FACT_NOT_APPLICABLE"}, fact_refs, evidence_ids)

    if operator == "equals":
        expected = predicate.get("value")
        if type(actual) is not type(expected):  # noqa: E721 - exact JSON type safety is intentional.
            return predicate_result(predicate, UNKNOWN, {"PREDICATE_TYPE_MISMATCH"}, fact_refs, evidence_ids)
        return predicate_result(
            predicate,
            TRUE if actual == expected else FALSE,
            {"FACT_MATCH" if actual == expected else "FACT_CONTRADICTS_REQUIREMENT"},
            fact_refs,
            evidence_ids,
        )

    if operator in {"list_contains", "list_not_contains", "list_non_empty"}:
        if not fact_domain_complete(analysis, fact_name):
            return predicate_result(
                predicate,
                UNKNOWN,
                {"EVIDENCE_DOMAIN_INCOMPLETE"},
                fact_refs,
                evidence_ids,
                {fact_name},
            )
        if not isinstance(actual, list):
            return predicate_result(predicate, UNKNOWN, {"PREDICATE_TYPE_MISMATCH"}, fact_refs, evidence_ids)
        item_key = predicate.get("item_key")
        if item_key is not None and not isinstance(item_key, str):
            return predicate_result(predicate, UNKNOWN, {"PREDICATE_TYPE_MISMATCH"}, fact_refs, evidence_ids)
        if operator == "list_non_empty":
            return predicate_result(
                predicate,
                TRUE if len(actual) > 0 else FALSE,
                {"LIST_NON_EMPTY" if actual else "LIST_EMPTY"},
                fact_refs,
                evidence_ids,
            )
        expected = predicate.get("value")
        if item_key:
            if not all(isinstance(item, dict) for item in actual):
                return predicate_result(predicate, UNKNOWN, {"PREDICATE_TYPE_MISMATCH"}, fact_refs, evidence_ids)
            present = any(item.get(item_key) == expected for item in actual)
        else:
            present = any(type(item) is type(expected) and item == expected for item in actual)
        if operator == "list_contains":
            return predicate_result(
                predicate,
                TRUE if present else FALSE,
                {"FACT_MATCH" if present else "FACT_CONTRADICTS_REQUIREMENT"},
                fact_refs,
                evidence_ids,
            )
        return predicate_result(
            predicate,
            FALSE if present else TRUE,
            {"FACT_CONTRADICTS_EXCLUSION" if present else "AUTHORITATIVE_ABSENCE"},
            fact_refs,
            evidence_ids,
        )

    if operator == "version_matches":
        result, code = version_constraint_result(actual, predicate.get("constraint"))
        return predicate_result(predicate, result, {code}, fact_refs, evidence_ids)

    return predicate_result(predicate, UNKNOWN, {"UNSUPPORTED_PREDICATE"}, fact_refs, evidence_ids, {fact_name})


def evaluate_condition(
    condition: dict[str, Any],
    analysis: dict[str, Any],
    evidence_index: dict[str, Any] | None = None,
) -> PredicateOutcome:
    if not isinstance(condition, dict):
        return PredicateOutcome(UNKNOWN, [], {"UNSUPPORTED_PREDICATE"}, set(), set(), set())
    if "all" in condition:
        children = condition["all"]
        if not isinstance(children, list) or not children:
            return PredicateOutcome(UNKNOWN, [], {"UNSUPPORTED_PREDICATE"}, set(), set(), set())
        outcomes = [evaluate_condition(child, analysis, evidence_index) for child in children]
        return merge_outcomes(tvl_and([item.value for item in outcomes]), outcomes, "ALL_PREDICATES_EVALUATED")
    if "any" in condition:
        children = condition["any"]
        if not isinstance(children, list) or not children:
            return PredicateOutcome(UNKNOWN, [], {"UNSUPPORTED_PREDICATE"}, set(), set(), set())
        outcomes = [evaluate_condition(child, analysis, evidence_index) for child in children]
        return merge_outcomes(tvl_or([item.value for item in outcomes]), outcomes, "ANY_PREDICATES_EVALUATED")
    if "not" in condition:
        child = condition["not"]
        outcome = evaluate_condition(child, analysis, evidence_index)
        return merge_outcomes(tvl_not(outcome.value), [outcome], "NOT_PREDICATE_EVALUATED")
    return evaluate_leaf_predicate(condition, analysis, evidence_index)


def applicability_from_truth(value: str) -> str:
    if value == TRUE:
        return "applicable"
    if value == FALSE:
        return "not_applicable"
    return "unknown"


def evaluate_machine_applicability(
    record: dict[str, Any],
    analysis: dict[str, Any],
    evidence_index: dict[str, Any] | None = None,
) -> LegacyOutcome:
    contract = record.get("machine_applicability")
    if not isinstance(contract, dict):
        raise ResolverValidationError("machine_applicability must be an object")
    if contract.get("schema_version") != SUPPORTED_MACHINE_CONTRACT:
        return LegacyOutcome("requires_human_review", "requires_human_review", [], {"UNSUPPORTED_MACHINE_APPLICABILITY_SCHEMA"}, set(), set(), set())
    condition = contract.get("condition")
    if not isinstance(condition, dict):
        return LegacyOutcome("requires_human_review", "requires_human_review", [], {"NO_MACHINE_APPLICABILITY_CONTRACT"}, set(), set(), set())
    outcome = evaluate_condition(condition, analysis, evidence_index)
    return LegacyOutcome(
        applicability_from_truth(outcome.value),
        "machine_resolved" if outcome.value != UNKNOWN else "partially_machine_resolved",
        outcome.evaluations,
        outcome.reason_codes,
        outcome.fact_refs,
        outcome.evidence_ids,
        outcome.missing_facts,
    )


def evaluate_required_facts(record: dict[str, Any], analysis: dict[str, Any]) -> PredicateOutcome:
    requirements = record.get("project_applicability", {}).get("requires", [])
    if not isinstance(requirements, list):
        return PredicateOutcome(UNKNOWN, [], {"NO_MACHINE_APPLICABILITY_CONTRACT"}, set(), set(), set())
    outcomes: list[PredicateOutcome] = []
    for fact_name in requirements:
        if not isinstance(fact_name, str):
            outcomes.append(PredicateOutcome(UNKNOWN, [], {"UNSUPPORTED_PREDICATE"}, set(), set(), set()))
            continue
        predicate = {"id": f"legacy-requires-{fact_name}", "operator": "fact_known", "fact": fact_name}
        fact = fact_object(analysis, fact_name)
        if fact is None:
            outcomes.append(
                predicate_result(
                    predicate,
                    UNKNOWN,
                    {"FACT_NOT_IN_ANALYZER_CONTRACT"},
                    {fact_name},
                    missing_facts={fact_name},
                )
            )
        else:
            outcomes.append(evaluate_leaf_predicate(predicate, analysis))
    if not outcomes:
        return PredicateOutcome(UNKNOWN, [], {"NO_MACHINE_APPLICABILITY_CONTRACT"}, set(), set(), set())
    return merge_outcomes(tvl_and([item.value for item in outcomes]), outcomes, "LEGACY_REQUIRED_FACTS_EVALUATED")


def evaluate_legacy_core_version(record: dict[str, Any], analysis: dict[str, Any]) -> PredicateOutcome:
    entries = record.get("version_applicability", {}).get("drupal_core", [])
    if not isinstance(entries, list) or len(entries) != 1:
        return PredicateOutcome(UNKNOWN, [], {"NO_SUPPORTED_VERSION_APPLICABILITY"}, set(), set(), set())
    item = entries[0]
    if not isinstance(item, dict) or item.get("status") != "applicable":
        return PredicateOutcome(UNKNOWN, [], {"NO_SUPPORTED_VERSION_APPLICABILITY"}, set(), set(), set())
    constraint = item.get("constraint")
    predicate = {
        "id": "legacy-drupal-core-version",
        "operator": "version_matches",
        "fact": "drupal_core_version",
        "path": "value.version",
        "constraint": constraint,
    }
    return evaluate_leaf_predicate(predicate, analysis)


def evaluate_legacy_applicability(record: dict[str, Any], analysis: dict[str, Any]) -> LegacyOutcome:
    required = evaluate_required_facts(record, analysis)
    if required.value == UNKNOWN:
        missing_contract = "NO_MACHINE_APPLICABILITY_CONTRACT" in required.reason_codes
        return LegacyOutcome(
            "requires_human_review" if missing_contract else "unknown",
            "requires_human_review" if missing_contract else "insufficient_project_evidence",
            required.evaluations,
            required.reason_codes,
            required.fact_refs,
            required.evidence_ids,
            required.missing_facts,
        )
    if required.value == FALSE:
        return LegacyOutcome("not_applicable", "partially_machine_resolved", required.evaluations, required.reason_codes, required.fact_refs, required.evidence_ids, required.missing_facts)

    version = evaluate_legacy_core_version(record, analysis)
    merged = merge_outcomes(tvl_and([required.value, version.value]), [required, version], "LEGACY_APPLICABILITY_EVALUATED")
    if version.value == TRUE:
        return LegacyOutcome("applicable", "machine_resolved", merged.evaluations, merged.reason_codes, merged.fact_refs, merged.evidence_ids, merged.missing_facts)
    if version.value == FALSE:
        return LegacyOutcome("not_applicable", "machine_resolved", merged.evaluations, merged.reason_codes, merged.fact_refs, merged.evidence_ids, merged.missing_facts)
    if "UNSUPPORTED_VERSION_CONSTRAINT" in version.reason_codes or "NO_SUPPORTED_VERSION_APPLICABILITY" in version.reason_codes:
        return LegacyOutcome("requires_human_review", "requires_human_review", merged.evaluations, merged.reason_codes, merged.fact_refs, merged.evidence_ids, merged.missing_facts)
    return LegacyOutcome("unknown", "partially_machine_resolved", merged.evaluations, merged.reason_codes, merged.fact_refs, merged.evidence_ids, merged.missing_facts)


def resolve_record(
    record: dict[str, Any],
    analysis: dict[str, Any],
    evidence_index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if "machine_applicability" in record:
        outcome = evaluate_machine_applicability(record, analysis, evidence_index)
        contract = "machine_applicability"
    else:
        outcome = evaluate_legacy_applicability(record, analysis)
        contract = "legacy_structured_fields"
    return {
        "knowledge_id": record["id"],
        "title": record["title"],
        "review_status": record["review_status"],
        "applicability": outcome.applicability,
        "effective_enforcement": dk_core.effective_enforcement(record),
        "automation": {
            "status": outcome.automation_status,
            "contract": contract,
        },
        "reason_codes": sorted(outcome.reason_codes),
        "fact_refs": sorted(outcome.fact_refs),
        "evidence_ids": sorted(outcome.evidence_ids),
        "missing_facts": sorted(outcome.missing_facts),
        "predicate_evaluations": sorted(
            outcome.evaluations,
            key=lambda item: (item.get("id", ""), item.get("operator", ""), item.get("fact", "")),
        ),
    }


def validate_analysis_contract(analysis: dict[str, Any]) -> None:
    if not isinstance(analysis, dict):
        raise ResolverValidationError("analysis must be a JSON object")
    try:
        dk_project_analyzer.validate_project_analysis(analysis)
    except dk_core.ValidationError as exc:
        raise ResolverValidationError("analysis does not match project-analysis schema") from exc
    required = {"schema_version", "project_id", "analyzer", "profile", "evidence", "completeness", "unknowns", "diagnostics"}
    missing = sorted(required - set(analysis))
    if missing:
        raise ResolverValidationError("analysis missing required keys: " + ", ".join(missing))
    if analysis.get("schema_version") != SUPPORTED_ANALYSIS_SCHEMA:
        raise ResolverValidationError("unsupported analyzer schema_version")
    analyzer = analysis.get("analyzer")
    if not isinstance(analyzer, dict) or analyzer.get("name") != "drupal-project-analyzer":
        raise ResolverValidationError("analysis was not produced by the Drupal Project Analyzer contract")
    if analyzer.get("version") != "0.1":
        raise ResolverValidationError("unsupported analyzer version")
    profile = analysis.get("profile")
    if not isinstance(profile, dict) or not isinstance(profile.get("facts"), dict):
        raise ResolverValidationError("analysis profile facts must be an object")
    for name, fact in profile["facts"].items():
        if not isinstance(name, str) or not isinstance(fact, dict):
            raise ResolverValidationError("analysis facts must be named objects")
        if fact.get("state") not in {"known", "unknown", "not_applicable"}:
            raise ResolverValidationError(f"analysis fact {name}: invalid state")
    evidence = analysis.get("evidence")
    if not isinstance(evidence, list):
        raise ResolverValidationError("analysis evidence must be a list")
    seen = set()
    for item in evidence:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ResolverValidationError("analysis evidence entries must have string ids")
        if item["id"] in seen:
            raise ResolverValidationError("analysis evidence ids must be unique")
        seen.add(item["id"])


def validate_machine_condition(condition: dict[str, Any], context: str) -> None:
    if not isinstance(condition, dict):
        raise dk_core.ValidationError(f"{context}: machine condition must be an object")
    group_keys = [key for key in ("all", "any", "not") if key in condition]
    if group_keys:
        if len(group_keys) != 1 or "operator" in condition:
            raise dk_core.ValidationError(f"{context}: machine condition must be one group or one predicate")
        key = group_keys[0]
        children = condition[key]
        if key == "not":
            validate_machine_condition(children, f"{context}: not")
            return
        if not isinstance(children, list) or not children:
            raise dk_core.ValidationError(f"{context}: {key} must be a non-empty list")
        for index, child in enumerate(children):
            validate_machine_condition(child, f"{context}: {key}[{index}]")
        return
    operator = condition.get("operator")
    if operator in EVIDENCE_OPERATORS:
        dk_core.assert_only_keys(
            condition,
            {"id", "operator", "assertion", "subject", "value", "value_path"},
            context,
        )
        assertion = condition.get("assertion")
        subject = condition.get("subject")
        if not isinstance(assertion, str) or not ASSERTION_RE.fullmatch(assertion):
            raise dk_core.ValidationError(f"{context}: invalid evidence assertion")
        if not isinstance(subject, str) or not SUBJECT_RE.fullmatch(subject):
            raise dk_core.ValidationError(f"{context}: invalid evidence subject")
        if operator == "evidence_absent" and ("value" in condition or "value_path" in condition):
            raise dk_core.ValidationError(f"{context}: evidence_absent takes no value")
        if "value_path" in condition and (
            not isinstance(condition["value_path"], str)
            or not PATH_RE.fullmatch(condition["value_path"])
        ):
            raise dk_core.ValidationError(f"{context}: invalid evidence value path")
        return
    fact_name = condition.get("fact")
    dk_core.assert_only_keys(
        condition,
        {"id", "operator", "fact", "path", "value", "item_key", "constraint"},
        context,
    )
    if operator not in SUPPORTED_OPERATORS:
        raise dk_core.ValidationError(f"{context}: unsupported operator {operator!r}")
    if not isinstance(fact_name, str) or not PATH_RE.fullmatch(fact_name):
        raise dk_core.ValidationError(f"{context}: invalid fact reference")
    if "path" in condition and (
        not isinstance(condition["path"], str) or not PATH_RE.fullmatch(condition["path"])
    ):
        raise dk_core.ValidationError(f"{context}: invalid fact value path")
    if "item_key" in condition and not isinstance(condition["item_key"], str):
        raise dk_core.ValidationError(f"{context}: item_key must be a string")
    if operator == "version_matches" and not isinstance(condition.get("constraint"), str):
        raise dk_core.ValidationError(f"{context}: version_matches requires a string constraint")


def validate_machine_applicability(record: dict[str, Any], context: str) -> None:
    if "machine_applicability" not in record:
        return
    contract = record["machine_applicability"]
    if not isinstance(contract, dict):
        raise dk_core.ValidationError(f"{context}: machine_applicability must be an object")
    dk_core.assert_only_keys(contract, {"schema_version", "condition", "notes"}, f"{context}: machine_applicability")
    if contract.get("schema_version") != SUPPORTED_MACHINE_CONTRACT:
        raise dk_core.ValidationError(f"{context}: unsupported machine_applicability schema_version")
    validate_machine_condition(contract.get("condition"), f"{context}: machine_applicability.condition")


def knowledge_set_identity(records: list[dict[str, Any]], root: Path = dk_core.ROOT) -> dict[str, Any]:
    canonical = stable_json(sorted(records, key=lambda item: item["id"]))
    version_path = root / "VERSION"
    version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else "unknown"
    return {
        "version": version,
        "record_count": len(records),
        "records_sha256": sha256_text(canonical),
    }


def analysis_identity(analysis: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": analysis["schema_version"],
        "project_id": analysis["project_id"],
        "analysis_sha256": sha256_text(stable_json(analysis)),
    }


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {state: 0 for state in sorted(APPLICABILITY_STATES)}
    enforcement = {"advisory": 0, "blocking": 0, "guidance": 0}
    for result in results:
        counts[result["applicability"]] += 1
        if result["applicability"] == "applicable":
            enforcement[result["effective_enforcement"]] += 1
    return {
        "applicability_counts": counts,
        "applicable_effective_enforcement_counts": enforcement,
    }


def resolve_analysis_data(
    analysis: dict[str, Any],
    records: list[dict[str, Any]] | None = None,
    root: Path = dk_core.ROOT,
    validate_canonical_knowledge: bool = True,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_analysis_contract(analysis)
    if validate_canonical_knowledge:
        dk_core.validate_knowledge(root)
    selected_records = copy.deepcopy(records if records is not None else dk_core.load_knowledge_records(root))
    for record in selected_records:
        validate_machine_applicability(record, f"knowledge {record.get('id', '<unknown>')}")
    evidence_index = None
    if evidence is not None:
        import dk_evidence

        evidence_index = dk_evidence.index(evidence)
    results = [
        resolve_record(record, analysis, evidence_index)
        for record in sorted(selected_records, key=lambda item: item["id"])
    ]
    output = {
        "schema_version": "0.1",
        "resolver": {
            "name": RESOLVER_NAME,
            "version": RESOLVER_VERSION,
            "mode": "applicability-only",
        },
        "analysis": analysis_identity(analysis),
        "knowledge_set": knowledge_set_identity(selected_records, root),
        "project_evidence": (
            {
                "supplied": True,
                "evidence_set_id": evidence["evidence_set_id"],
                "revision_fingerprint": evidence["project"]["revision_fingerprint"],
                "records": len(evidence["records"]),
            }
            if evidence is not None
            # Without an evidence set, an evidence predicate stays unknown
            # rather than quietly resolving against nothing.
            else {"supplied": False, "evidence_set_id": None, "revision_fingerprint": None, "records": 0}
        ),
        "summary": build_summary(results),
        "results": results,
    }
    validate_resolution_output(output)
    return output


def resolve_analysis_file(path: str | Path, root: Path = dk_core.ROOT) -> dict[str, Any]:
    analysis_path = Path(path)
    if not analysis_path.is_file():
        raise ResolverInputError("analysis JSON file does not exist")
    try:
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        raise ResolverValidationError("analysis JSON is invalid") from exc
    return resolve_analysis_data(analysis, root=root)


def validate_resolution_output(output: dict[str, Any]) -> list[str]:
    if not isinstance(output, dict):
        raise ResolverValidationError("resolution output must be an object")
    required = {"schema_version", "resolver", "analysis", "knowledge_set", "summary", "results"}
    missing = sorted(required - set(output))
    if missing:
        raise ResolverValidationError("resolution output missing required keys: " + ", ".join(missing))
    if output.get("schema_version") != "0.1":
        raise ResolverValidationError("unsupported resolution schema_version")
    resolver = output.get("resolver")
    if not isinstance(resolver, dict) or resolver.get("name") != RESOLVER_NAME:
        raise ResolverValidationError("invalid resolver identity")
    results = output.get("results")
    if not isinstance(results, list):
        raise ResolverValidationError("resolution results must be a list")
    previous = ""
    for result in results:
        if not isinstance(result, dict):
            raise ResolverValidationError("resolution result must be an object")
        if result.get("knowledge_id", "") < previous:
            raise ResolverValidationError("resolution results must be sorted by knowledge_id")
        previous = result.get("knowledge_id", "")
        if result.get("applicability") not in APPLICABILITY_STATES:
            raise ResolverValidationError("invalid applicability state")
        if result.get("effective_enforcement") not in {"blocking", "guidance", "advisory"}:
            raise ResolverValidationError("invalid effective enforcement")
        for list_key in ("reason_codes", "fact_refs", "evidence_ids", "missing_facts", "predicate_evaluations"):
            if not isinstance(result.get(list_key), list):
                raise ResolverValidationError(f"result {result.get('knowledge_id')}: {list_key} must be a list")
    return ["RESOLUTION_OUTPUT_SCHEMA_VALID=PASS"]


def audit_current_knowledge(records: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    selected = records if records is not None else dk_core.load_knowledge_records()
    rows = []
    for record in sorted(selected, key=lambda item: item["id"]):
        record_id = record["id"]
        current = "project_applicability.requires + version_applicability"
        sufficient = "no"
        machine_state = "HUMAN_SEMANTIC_REVIEW_REQUIRED"
        reason = "No declarative machine applicability contract is present."
        requires = record.get("project_applicability", {}).get("requires", [])
        constraints = [
            item.get("constraint")
            for item in record.get("version_applicability", {}).get("drupal_core", [])
            if isinstance(item, dict)
        ]
        if record_id == "drupal.api.reference-drupal-11":
            sufficient = "yes"
            machine_state = "MACHINE_RESOLVABLE"
            reason = "Requires drupal_core_version and uses the supported 11.x core branch constraint."
        elif any(item in {"custom_routes", "route_operation_semantics", "database_query_code", "twig_templates"} for item in requires):
            machine_state = "INSUFFICIENT_PROJECT_EVIDENCE"
            reason = "Current analyzer does not produce the required static code/template/route semantics."
        elif "Project PHPCS/Coder/PHP_CodeSniffer configuration when evaluating a repository" in record.get("evidence_requirements", []):
            machine_state = "INSUFFICIENT_PROJECT_EVIDENCE"
            reason = "Current analyzer does not inspect PHPCS/Coder configuration."
        elif any(constraint in {"all-supported", "release-history"} for constraint in constraints):
            sufficient = "partial"
            machine_state = "PARTIALLY_MACHINE_RESOLVABLE"
            reason = "Project core version can be observed, but support/release semantics are not implemented."
        elif any(constraint in {"change-record-specific", "advisory-specific", "all-new-code", "current-documented-secure-code-guidance"} for constraint in constraints):
            machine_state = "HUMAN_SEMANTIC_REVIEW_REQUIRED"
            reason = "Applicability depends on record-specific semantics or code context beyond the safe contract."
        rows.append(
            {
                "knowledge_id": record_id,
                "current_applicability": current,
                "analyzer_evidence_sufficient": sufficient,
                "machine_state": machine_state,
                "reason": reason,
            }
        )
    return rows
