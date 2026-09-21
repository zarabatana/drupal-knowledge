#!/usr/bin/env python3
"""Finding runtime: executes reviewed machine_finding contracts.

The runtime consumes trusted layers only: reviewed knowledge records carrying
declarative machine_finding contracts, and the neutral release lifecycle
assessment built by the release lifecycle evaluator from Drupal Project
Analyzer output.

Authority boundaries enforced here:

- the analyzed project is never reopened or rescanned;
- no network access and no source collection ever happens during evaluation;
- knowledge, sources, snapshots, and the lifecycle context are read-only;
- finding states come exclusively from the reviewed contract state map plus
  the fail-closed runtime states of the Finding Authority Model;
- severity is never invented and enforcement is never escalated;
- no remediation is proposed or performed.
"""

from __future__ import annotations

import hashlib
import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any

import dk_applicability
import dk_core
import dk_release_lifecycle_evaluator


RUNTIME_NAME = "drupal-finding-runtime"
RUNTIME_VERSION = "0.1"
RUNTIME_MODE = "reviewed-machine-finding-contract-execution"
EVALUATION_SCHEMA_VERSION = "0.1"
SCHEMA_RELATIVE_PATH = Path("schema") / "finding-evaluation.schema.json"

SUPPORTED_CONTRACT_SCHEMA = "0.1"
SUPPORTED_EVIDENCE_DOMAINS = {"release_lifecycle_assessment"}
SUPPORTED_MATCH_MODES = {"literal_exact_string"}
SUPPORTED_IDENTITY_ALGORITHMS = {"sha256_stable_json"}

FINDING_STATES = [
    "confirmed",
    "candidate",
    "historical_candidate",
    "not_observed",
    "unknown",
    "requires_human_review",
]

# States a finding evaluation may never carry: absence of an adverse condition
# is not a conformance verdict.
FORBIDDEN_STATE_VALUES = {"passed", "secure", "safe", "compliant", "ok"}

# The runtime is a consumer, not an authority: it may not add these keys to
# any output document.
FORBIDDEN_OUTPUT_KEYS = {
    "remediation",
    "remediations",
    "fix",
    "fix_command",
    "upgrade_command",
    "upgrade_target",
    "recommended_version",
    "vulnerable",
    "exploitable",
    "compromised",
    "cve",
    "cve_ids",
    "secure",
    "insecure_project",
    "evaluated_at",
    "timestamp",
    "created_at",
    "wall_clock_time",
    "run_id",
    "hostname",
    "absolute_path",
    "absolute_paths",
}

# Evidence bindings join a contract's declared literal source term location to
# the lifecycle assessment field that preserves it. This is the only
# contract-to-evidence join table; a future reviewed contract using an already
# bound location needs no runtime change.
EVIDENCE_BINDINGS = {
    (
        "release_lifecycle_assessment",
        "/project/releases/release/terms/term/value",
        "Release type",
    ): ("source_attributes", "source_release_type_terms"),
}

REQUIRES_HUMAN_REVIEW = "requires_human_review"


class FindingRuntimeInputError(RuntimeError):
    """Raised when finding runtime CLI input cannot be read."""


class FindingRuntimeValidationError(RuntimeError):
    """Raised when a finding evaluation cannot be emitted safely."""


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def contract_bearing_records(root: Path = dk_core.ROOT) -> list[dict[str, Any]]:
    return [
        record
        for record in sorted(dk_core.load_knowledge_records(root), key=lambda item: item["id"])
        if "machine_finding" in record
    ]


def contract_execution_refusal(
    record: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any] | None:
    """Return a refusal entry when a contract may not be executed.

    Refusals fail closed: a refused contract produces no finding entry and can
    therefore never produce a confirmed finding.
    """
    contract = record["machine_finding"]

    def refusal(reason_code: str, detail: str) -> dict[str, Any]:
        return {
            "knowledge_id": record.get("id"),
            "condition_id": contract.get("condition_id"),
            "reason_code": reason_code,
            "detail": detail,
        }

    try:
        dk_core.validate_machine_finding_contract(record, f"knowledge {record.get('id')}", root)
    except dk_core.ValidationError as exc:
        return refusal("CONTRACT_INVALID", str(exc))
    if record.get("review_status") != "reviewed":
        return refusal(
            "UNREVIEWED_KNOWLEDGE_CANNOT_AUTHOR_FINDINGS",
            "Only reviewed knowledge records may author finding evaluations.",
        )
    if dk_core.effective_enforcement(record) == "blocking":
        return refusal(
            "BLOCKING_ENFORCEMENT_NOT_EXECUTABLE",
            "Machine finding contracts cannot carry blocking enforcement.",
        )
    if contract.get("schema_version") != SUPPORTED_CONTRACT_SCHEMA:
        return refusal("CONTRACT_SCHEMA_UNSUPPORTED", "Unsupported machine finding contract schema.")
    if contract.get("evidence_domain") not in SUPPORTED_EVIDENCE_DOMAINS:
        return refusal(
            "RUNTIME_EVIDENCE_DOMAIN_UNSUPPORTED",
            "The runtime has no reviewed evidence binding for this evidence domain.",
        )
    requires = contract.get("requires", {})
    if requires.get("match_mode") not in SUPPORTED_MATCH_MODES:
        return refusal(
            "RUNTIME_MATCH_MODE_UNSUPPORTED",
            "Only literal exact string matching is executable.",
        )
    if contract.get("identity", {}).get("algorithm") not in SUPPORTED_IDENTITY_ALGORITHMS:
        return refusal(
            "RUNTIME_IDENTITY_ALGORITHM_UNSUPPORTED",
            "Only sha256_stable_json finding identity is executable.",
        )
    binding_key = (
        contract["evidence_domain"],
        requires.get("source_field_path"),
        requires.get("source_term_name"),
    )
    if binding_key not in EVIDENCE_BINDINGS:
        return refusal(
            "RUNTIME_EVIDENCE_BINDING_MISSING",
            "The contract's literal source term location has no reviewed assessment binding.",
        )
    return None


def resolve_applicability(
    analysis: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Resolve canonical knowledge applicability through the Applicability Resolver.

    The runtime consumes the resolver's authority; it never reimplements
    applicability predicates. A resolver failure is not an input error: it
    degrades every dependent contract to its declared applicability_not_definitive
    state.
    """
    try:
        resolution = dk_applicability.resolve_analysis_data(analysis, root=root)
    except (
        dk_applicability.ResolverInputError,
        dk_applicability.ResolverValidationError,
        dk_core.ValidationError,
    ) as exc:
        return None, {
            "reason_code": "APPLICABILITY_RESOLUTION_UNAVAILABLE",
            "detail": str(exc),
        }
    return resolution, None


def applicability_entry(
    resolution: dict[str, Any] | None,
    knowledge_id: str,
) -> dict[str, Any] | None:
    if resolution is None:
        return None
    for item in resolution.get("results", []):
        if item.get("knowledge_id") == knowledge_id:
            return item
    return None


def applicability_identity(
    resolution: dict[str, Any] | None,
    entry: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if resolution is None or entry is None:
        return None
    return {
        "resolver": dict(resolution.get("resolver", {})),
        "knowledge_set_records_sha256": resolution.get("knowledge_set", {}).get("records_sha256"),
        "applicability": entry.get("applicability"),
        "automation_status": entry.get("automation", {}).get("status"),
        "fact_refs": sorted(entry.get("fact_refs", [])),
        "evidence_ids": sorted(entry.get("evidence_ids", [])),
        "reason_codes": sorted(entry.get("reason_codes", [])),
    }


def applicability_is_definitive(entry: dict[str, Any] | None) -> bool:
    return (
        isinstance(entry, dict)
        and entry.get("applicability") == "applicable"
        and entry.get("automation", {}).get("status") == "machine_resolved"
    )


def installed_core_major(version: Any) -> str | None:
    if not isinstance(version, str):
        return None
    head = version.split(".", 1)[0]
    return head if head.isdigit() else None


def semantic_version_scope(contract: dict[str, Any]) -> dict[str, Any] | None:
    scope = contract.get("confirmation_authority", {}).get("semantic_authority_version_scope")
    return scope if isinstance(scope, dict) else None


def build_assessment(
    analysis: dict[str, Any],
    root: Path = dk_core.ROOT,
    context: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Build the trusted lifecycle assessment for the evidence domain.

    Analysis-contract violations are input errors. Context or repository
    authority failures are not input errors: they degrade every dependent
    contract to its declared assessment_invalid state.
    """
    try:
        dk_release_lifecycle_evaluator.validate_analysis_contract(analysis)
    except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError as exc:
        raise FindingRuntimeValidationError(
            f"analysis is not trusted Drupal Project Analyzer output: {exc}"
        ) from exc
    try:
        if context is None:
            assessment = dk_release_lifecycle_evaluator.evaluate_analysis_data(analysis, root=root)
        else:
            assessment = dk_release_lifecycle_evaluator.evaluate_analysis_data_with_test_context(
                analysis,
                context,
                root=root,
            )
    except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError as exc:
        return None, {
            "reason_code": "ASSESSMENT_INVALID",
            "detail": str(exc),
        }
    return assessment, None


def observe_condition(
    contract: dict[str, Any],
    assessment: dict[str, Any] | None,
    assessment_error: dict[str, Any] | None,
    applicability: dict[str, Any] | None,
) -> tuple[str, str, str]:
    """Map trusted assessment facts onto a contract observation key.

    Returns (observation_key, reason_code, detail). The observation key is a
    key of the contract's declarative states map, or the special
    requires_human_review runtime state of the Finding Authority Model.
    """
    requires = contract["requires"]
    if assessment_error is not None:
        return (
            "assessment_invalid",
            "ASSESSMENT_INVALID",
            assessment_error.get("detail", "Lifecycle assessment could not be built."),
        )
    lifecycle_context = assessment.get("lifecycle_context", {})
    if (
        lifecycle_context.get("id") != requires["canonical_context_id"]
        or lifecycle_context.get("review_status") != "reviewed"
    ):
        return (
            "context_not_canonical",
            "CONTEXT_NOT_CANONICAL",
            "The assessment was not authored by the canonical reviewed lifecycle context.",
        )
    relation = lifecycle_context.get("context_relation")
    freshness = assessment.get("context_freshness", {})
    if relation not in {"current", "stale"} or freshness.get("relation") != relation:
        return (
            "assessment_invalid",
            "ASSESSMENT_CONTEXT_RELATION_INCONSISTENT",
            "The assessment context relation is internally inconsistent.",
        )
    evaluation_state = assessment.get("evaluation_state")
    if evaluation_state == "core_version_unknown":
        return (
            "core_version_unknown",
            "CORE_VERSION_UNKNOWN",
            "The analyzer did not establish a known installed Drupal core version.",
        )
    if evaluation_state == "release_not_found":
        return (
            "release_not_found",
            "EXACT_RELEASE_ROW_NOT_FOUND",
            "The exact installed Drupal core version has no release row in the reviewed context.",
        )
    if evaluation_state == REQUIRES_HUMAN_REVIEW:
        return (
            REQUIRES_HUMAN_REVIEW,
            "ASSESSMENT_REQUIRES_HUMAN_REVIEW",
            "The lifecycle assessment requires human review before contract evaluation.",
        )
    if evaluation_state != requires["evaluation_state"]:
        return (
            "assessment_invalid",
            "ASSESSMENT_EVALUATION_STATE_UNSUPPORTED",
            f"Unsupported lifecycle evaluation state: {evaluation_state!r}.",
        )
    release_match = assessment.get("release_match", {})
    if requires["exact_release_match"] is True and release_match.get("state") != "matched":
        return (
            "assessment_invalid",
            "EXACT_RELEASE_MATCH_MISSING",
            "The evaluated assessment did not carry an exact matched release row.",
        )
    if not applicability_is_definitive(applicability):
        if applicability is None:
            reason = "APPLICABILITY_RESOLUTION_UNAVAILABLE"
        elif applicability.get("applicability") == "not_applicable":
            reason = "APPLICABILITY_NOT_APPLICABLE"
        elif applicability.get("applicability") == "requires_human_review":
            reason = "APPLICABILITY_REQUIRES_HUMAN_REVIEW"
        else:
            reason = "APPLICABILITY_UNKNOWN"
        return (
            "applicability_not_definitive",
            reason,
            "Canonical knowledge applicability did not resolve definitively for this project; "
            "a finding cannot be authored without it.",
        )
    section_key, field_key = EVIDENCE_BINDINGS[
        (
            contract["evidence_domain"],
            requires["source_field_path"],
            requires["source_term_name"],
        )
    ]
    section = assessment.get(section_key, {})
    if not isinstance(section, dict) or section.get("state") != "present":
        return (
            "assessment_invalid",
            "SOURCE_ATTRIBUTES_UNAVAILABLE",
            "The matched release source attributes were not preserved in the assessment.",
        )
    terms = section.get(field_key)
    if not isinstance(terms, list):
        return (
            "assessment_invalid",
            "SOURCE_TERM_FIELD_UNAVAILABLE",
            "The bound literal source term field is missing from the assessment.",
        )
    term_present = any(
        isinstance(term, str) and term == requires["source_term_value"] for term in terms
    )
    if term_present:
        scope = semantic_version_scope(contract)
        if scope is not None:
            major = installed_core_major(release_match.get("source_version"))
            if major is None or major not in scope.get("drupal_core_majors", []):
                return (
                    "term_present_and_semantic_authority_version_out_of_scope",
                    "SEMANTIC_AUTHORITY_VERSION_OUT_OF_SCOPE",
                    "The literal source term is present on the exact installed release, but the "
                    "reviewed semantic authority does not cover this Drupal core major.",
                )
        if relation == "current":
            return (
                "term_present_and_context_current",
                "TERM_PRESENT_ON_EXACT_INSTALLED_RELEASE_CURRENT_CONTEXT",
                "The exact installed release row carries the literal source term under a current reviewed context.",
            )
        return (
            "term_present_and_context_stale",
            "TERM_PRESENT_ON_EXACT_INSTALLED_RELEASE_STALE_CONTEXT",
            "The exact installed release row carries the literal source term only under a stale reviewed context.",
        )
    return (
        "term_absent_in_matched_row",
        "TERM_ABSENT_IN_MATCHED_ROW",
        "The exact installed release row does not carry the literal source term in the reviewed context.",
    )


def resolve_state(contract: dict[str, Any], observation_key: str) -> str:
    if observation_key == REQUIRES_HUMAN_REVIEW:
        return REQUIRES_HUMAN_REVIEW
    states = contract["states"]
    if observation_key not in states:
        raise FindingRuntimeValidationError(
            f"contract states map has no key {observation_key!r}"
        )
    state = states[observation_key]
    if state not in FINDING_STATES or state in FORBIDDEN_STATE_VALUES:
        raise FindingRuntimeValidationError(f"contract declared unsupported state {state!r}")
    return state


def identity_value_map(
    record: dict[str, Any],
    contract: dict[str, Any],
    analysis_identity: dict[str, Any],
    assessment: dict[str, Any] | None,
) -> dict[str, Any]:
    assessment = assessment or {}
    core_version = assessment.get("core_version", {})
    release_match = assessment.get("release_match", {})
    lifecycle_context = assessment.get("lifecycle_context", {})
    return {
        "knowledge_id": record["id"],
        "condition_id": contract["condition_id"],
        "assertion": contract["assertion"],
        "analysis_project_id": analysis_identity["project_id"],
        "analysis_sha256": analysis_identity["analysis_sha256"],
        "core_version_fact_ref": core_version.get("fact_ref"),
        "core_version_evidence_ids": sorted(core_version.get("evidence_ids", [])),
        "matched_release_source_version": release_match.get("source_version"),
        "lifecycle_context_id": lifecycle_context.get("id"),
        "lifecycle_context_sha256": lifecycle_context.get("context_sha256"),
        "installed_core_package": core_version.get("package"),
    }


def finding_identity(
    contract: dict[str, Any],
    values: dict[str, Any],
) -> str:
    identity = contract["identity"]
    key_fields = identity["key_fields"]
    missing = sorted(set(key_fields) - set(values))
    if missing:
        raise FindingRuntimeValidationError(
            "contract identity key fields are not derivable from trusted evidence: "
            + ", ".join(missing)
        )
    if any("timestamp" in field or field.endswith("_at") for field in key_fields):
        raise FindingRuntimeValidationError("contract identity key fields must not include time")
    basis = {field: values[field] for field in sorted(key_fields)}
    return sha256_text(stable_json(basis))


def deduplication_key(
    contract: dict[str, Any],
    values: dict[str, Any],
) -> dict[str, Any]:
    key_fields = contract["deduplication"]["key_fields"]
    missing = sorted(set(key_fields) - set(values))
    if missing:
        raise FindingRuntimeValidationError(
            "contract deduplication key fields are not derivable from trusted evidence: "
            + ", ".join(missing)
        )
    return {field: values[field] for field in key_fields}


def provenance_version_scope(
    contract: dict[str, Any],
    release_match: dict[str, Any],
) -> dict[str, Any] | None:
    scope = semantic_version_scope(contract)
    if scope is None:
        return None
    major = installed_core_major(release_match.get("source_version"))
    majors = list(scope.get("drupal_core_majors", []))
    return {
        "drupal_core_majors": majors,
        "installed_core_major": major,
        "in_scope": (major in majors) if major is not None else None,
    }


def build_provenance(
    record: dict[str, Any],
    contract: dict[str, Any],
    analysis_identity: dict[str, Any],
    assessment: dict[str, Any] | None,
    observation_key: str,
    applicability_ref: dict[str, Any] | None,
) -> dict[str, Any]:
    assessment = assessment or {}
    requires = contract["requires"]
    core_version = assessment.get("core_version", {})
    release_match = assessment.get("release_match", {})
    lifecycle_context = assessment.get("lifecycle_context", {})
    term_present: bool | None
    if observation_key in {"term_present_and_context_current", "term_present_and_context_stale"}:
        term_present = True
    elif observation_key == "term_absent_in_matched_row":
        term_present = False
    else:
        term_present = None
    provenance = {
        "knowledge_id": record["id"],
        "condition_id": contract["condition_id"],
        "analysis_identity": dict(analysis_identity),
        "core_version_fact_ref": core_version.get("fact_ref"),
        "core_version_evidence_ids": sorted(core_version.get("evidence_ids", [])),
        "lifecycle_assessment_id": assessment.get("assessment_id"),
        "lifecycle_context_id": lifecycle_context.get("id"),
        "lifecycle_context_source_snapshot_sha256": lifecycle_context.get("source_snapshot_sha256"),
        "exact_matched_release": release_match.get("source_version"),
        "literal_source_term": {
            "name": requires["source_term_name"],
            "value": requires["source_term_value"],
            "source_field_path": requires["source_field_path"],
            "match_mode": requires["match_mode"],
            "present_on_matched_release": term_present,
        },
        "context_relation": lifecycle_context.get("context_relation"),
        "applicability_result_identity": applicability_ref,
        "semantic_authority_version_scope": provenance_version_scope(contract, release_match),
        "effective_enforcement": dk_core.effective_enforcement(record),
        "finding_severity_state": contract["severity"]["state"],
    }
    missing = sorted(set(contract["provenance_requirements"]) - set(provenance))
    if missing:
        raise FindingRuntimeValidationError(
            "finding provenance does not satisfy the contract: " + ", ".join(missing)
        )
    return provenance


def build_explanation(
    contract: dict[str, Any],
    state: str,
    reason_code: str,
    detail: str,
    provenance: dict[str, Any],
    assessment: dict[str, Any] | None,
) -> dict[str, str]:
    assessment = assessment or {}
    core_version = assessment.get("core_version", {})
    term = provenance["literal_source_term"]
    project_id = provenance["analysis_identity"]["project_id"]
    version = core_version.get("version")
    package = core_version.get("package")
    evidence_ids = ", ".join(provenance["core_version_evidence_ids"]) or "no analyzer evidence"
    if core_version.get("state") == "known":
        observed = (
            f"Drupal core {version} ({package}) is installed in project {project_id}, "
            f"observed from analyzer evidence {evidence_ids}."
        )
    else:
        observed = (
            f"No known installed Drupal core version was observed for project {project_id}."
        )
    snapshot = provenance["lifecycle_context_source_snapshot_sha256"]
    context_id = provenance["lifecycle_context_id"]
    if state in {"confirmed", "candidate", "historical_candidate"}:
        authority = (
            f"The reviewed Drupal core release lifecycle context ({context_id}, source snapshot "
            f"{snapshot}) attaches the {term['name']} term \"{term['value']}\" to exactly "
            f"release {provenance['exact_matched_release']}."
        )
    elif state == "not_observed":
        authority = (
            f"The reviewed Drupal core release lifecycle context ({context_id}, source snapshot "
            f"{snapshot}) does not attach the {term['name']} term \"{term['value']}\" to "
            f"release {provenance['exact_matched_release']}."
        )
    else:
        authority = (
            "The reviewed authority chain could not be applied: " + detail
        )
    semantics = contract.get("term_semantics", {})
    if semantics.get("meaning_bearing_claims_authorized") is True and state in {
        "confirmed",
        "historical_candidate",
    }:
        definition = semantics["authorized_meaning"]
    elif reason_code == "SEMANTIC_AUTHORITY_VERSION_OUT_OF_SCOPE":
        definition = (
            "The reviewed Drupal definition applies only to the Drupal core majors named in "
            "the semantic authority version scope; no meaning-bearing claim is authorized "
            "for this project's Drupal core major."
        )
    elif state == "candidate":
        definition = (
            "No reviewed semantic authority defines the meaning of this source term; "
            "the observation is a review candidate only."
        )
    else:
        definition = (
            "No meaning-bearing claim is attached: the reviewed Drupal definition applies "
            "only to a present term on the exact installed release."
        )
    if state == "confirmed":
        conclusion = (
            f"Confirmed lifecycle finding: {contract['human_title']}. "
            "Severity is not established, and this finding is guidance, not a blocker."
        )
    elif state == "candidate" and reason_code == "SEMANTIC_AUTHORITY_VERSION_OUT_OF_SCOPE":
        conclusion = (
            "Candidate for review: the literal source term is present on the exact installed "
            "release, but the reviewed semantic authority is not established for this "
            "project's Drupal core major, so no confirmed finding is authorized. This is "
            "not a security pass and not a statement that the release is secure."
        )
    elif state == "candidate":
        conclusion = (
            "Candidate for review: the literal source term was observed, but reviewed "
            "semantic authority for a confirmed finding is not established."
        )
    elif state == "historical_candidate":
        conclusion = (
            "Historical candidate: the term was present at the pinned reviewed snapshot, but "
            "the reviewed context no longer matches current source state, so no current "
            "confirmed finding is emitted."
        )
    elif state == "not_observed":
        conclusion = (
            "Not observed: the exact installed release row does not carry the term. "
            "This is not a security pass and not a statement that the release is secure."
        )
    elif state == REQUIRES_HUMAN_REVIEW:
        conclusion = (
            "Requires human review: the lifecycle assessment could not be consumed "
            "mechanically. No finding is confirmed."
        )
    elif reason_code.startswith("APPLICABILITY_"):
        conclusion = (
            f"Unknown ({reason_code}): canonical knowledge applicability did not resolve "
            "definitively, and a finding cannot be authored without it. Unknown is not "
            "false and is not a pass."
        )
    else:
        conclusion = (
            f"Unknown ({reason_code}): required evidence or reviewed authority context is "
            "unavailable. Unknown is not false and is not a pass."
        )
    return {
        "observed": observed,
        "authoritative_drupal_knowledge": authority,
        "drupal_definition": definition,
        "conclusion": conclusion,
    }


def build_finding(
    record: dict[str, Any],
    analysis_identity: dict[str, Any],
    assessment: dict[str, Any] | None,
    assessment_error: dict[str, Any] | None,
    applicability: dict[str, Any] | None,
    applicability_ref: dict[str, Any] | None,
) -> dict[str, Any]:
    contract = record["machine_finding"]
    observation_key, reason_code, detail = observe_condition(
        contract, assessment, assessment_error, applicability
    )
    state = resolve_state(contract, observation_key)
    values = identity_value_map(record, contract, analysis_identity, assessment)
    provenance = build_provenance(
        record, contract, analysis_identity, assessment, observation_key, applicability_ref
    )
    limitations: list[str] = []
    if provenance["context_relation"] == "stale":
        limitations.append("LIFECYCLE_CONTEXT_STALE")
    if state == "confirmed":
        incomplete = sorted(
            key
            for key, value in provenance.items()
            if value is None
        )
        if incomplete or provenance["context_relation"] != "current":
            raise FindingRuntimeValidationError(
                "confirmed finding lacks complete current provenance: "
                + ", ".join(incomplete or ["context_relation"])
            )
        scope = provenance["semantic_authority_version_scope"]
        if not isinstance(scope, dict) or scope.get("in_scope") is not True:
            raise FindingRuntimeValidationError(
                "confirmed finding requires the installed Drupal core major inside the "
                "reviewed semantic authority version scope"
            )
        if not applicability_is_definitive(applicability):
            raise FindingRuntimeValidationError(
                "confirmed finding requires definitive canonical knowledge applicability"
            )
    semantics = contract.get("term_semantics", {})
    claim_authorized = (
        semantics.get("meaning_bearing_claims_authorized") is True
        and state in {"confirmed", "historical_candidate"}
    )
    finding = {
        "finding_id": finding_identity(contract, values),
        "knowledge_id": record["id"],
        "condition_id": contract["condition_id"],
        "finding_type": contract["finding_type"],
        "assertion": contract["assertion"],
        "assertion_scope": contract.get("assertion_scope"),
        "human_title": contract["human_title"],
        "state": state,
        "observation_key": observation_key,
        "reason_code": reason_code,
        "detail": detail,
        "claim": {
            "meaning_authorized": claim_authorized,
            "authorized_meaning": semantics["authorized_meaning"] if claim_authorized else None,
            "temporality": (
                "current" if state == "confirmed"
                else "historical_at_pinned_snapshot" if state == "historical_candidate"
                else None
            ),
        },
        "not_claimed": sorted(semantics.get("forbidden_claims", [])),
        "severity": {
            "state": contract["severity"]["state"],
            "source": contract["severity"]["source"],
        },
        "effective_enforcement": dk_core.effective_enforcement(record),
        "provenance": provenance,
        "deduplication": {
            "max_instances": contract["deduplication"]["max_instances"],
            "key": deduplication_key(contract, values),
            "collapsed_read_paths": list(contract["deduplication"]["collapsed_read_paths"]),
        },
        "limitations": limitations,
        "explanation": build_explanation(
            contract, state, reason_code, detail, provenance, assessment
        ),
    }
    return finding


def knowledge_set_identity(
    records: list[dict[str, Any]],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    canonical = stable_json(sorted(records, key=lambda item: item["id"]))
    version_path = root / "VERSION"
    version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else "unknown"
    return {
        "version": version,
        "record_count": len(records),
        "records_sha256": sha256_text(canonical),
    }


def build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    states = {state: 0 for state in FINDING_STATES}
    enforcement = {"guidance": 0, "advisory": 0}
    for finding in findings:
        states[finding["state"]] += 1
        enforcement[finding["effective_enforcement"]] += 1
    return {"states": states, "effective_enforcement": enforcement}


def evaluate_analysis_data(
    analysis: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    return _evaluate(analysis, root=root, context=None)


def evaluate_analysis_data_with_test_context(
    analysis: dict[str, Any],
    context: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    return _evaluate(analysis, root=root, context=context)


def _evaluate(
    analysis: dict[str, Any],
    root: Path,
    context: dict[str, Any] | None,
) -> dict[str, Any]:
    assessment, assessment_error = build_assessment(analysis, root=root, context=context)
    analysis_identity = dk_release_lifecycle_evaluator.analysis_identity(analysis)
    resolution, _resolution_error = resolve_applicability(analysis, root=root)
    executed_records: list[dict[str, Any]] = []
    not_executed: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for record in contract_bearing_records(root):
        refusal = contract_execution_refusal(record, root)
        if refusal is not None:
            not_executed.append(refusal)
            continue
        executed_records.append(record)
        entry = applicability_entry(resolution, record["id"])
        findings.append(
            build_finding(
                record,
                analysis_identity,
                assessment,
                assessment_error,
                entry,
                applicability_identity(resolution, entry),
            )
        )
    if len(findings) != len({finding["finding_id"] for finding in findings}):
        raise FindingRuntimeValidationError("duplicate logical finding identities emitted")
    evidence = {
        "domain": "release_lifecycle_assessment",
        "lifecycle_assessment": (
            {
                "assessment_id": assessment["assessment_id"],
                "evaluation_state": assessment["evaluation_state"],
                "lifecycle_context": dict(assessment["lifecycle_context"]),
            }
            if assessment is not None
            else None
        ),
        "assessment_error": assessment_error,
    }
    limitations = sorted(
        {
            limitation
            for finding in findings
            for limitation in finding["limitations"]
        }
    )
    output = {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "runtime": {
            "name": RUNTIME_NAME,
            "version": RUNTIME_VERSION,
            "mode": RUNTIME_MODE,
        },
        "analysis": analysis_identity,
        "evidence": evidence,
        "knowledge_set": knowledge_set_identity(executed_records, root),
        "contracts": {
            "executed": len(executed_records),
            "not_executed": not_executed,
        },
        "findings": findings,
        "summary": build_summary(findings),
        "boundaries": {
            "statements": [
                "finding states come only from reviewed machine finding contracts",
                "severity is not established unless reviewed knowledge establishes it",
                "enforcement is guidance and is never escalated by the runtime",
                "term absence is not a security pass",
                "unknown is not false and is not a pass",
                "no remediation or upgrade recommendation is emitted",
                "the analyzed project is not reopened during finding evaluation",
                "no network access or source collection happens during finding evaluation",
            ]
        },
        "limitations": limitations,
    }
    output["evaluation_id"] = sha256_text(
        stable_json(
            {
                "runtime": output["runtime"],
                "analysis": output["analysis"],
                "knowledge_set": output["knowledge_set"],
                "finding_ids": [finding["finding_id"] for finding in findings],
                "states": [finding["state"] for finding in findings],
            }
        )
    )
    validate_finding_evaluation(output)
    return output


def evaluate_analysis_file(
    analysis_path: str | Path,
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    path = Path(analysis_path)
    if not path.is_file():
        raise FindingRuntimeInputError("analysis JSON file does not exist")
    try:
        analysis = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        raise FindingRuntimeValidationError("analysis JSON is invalid") from exc
    return evaluate_analysis_data(analysis, root=root)


FINDING_REQUIRED_KEYS = {
    "finding_id",
    "knowledge_id",
    "condition_id",
    "finding_type",
    "assertion",
    "assertion_scope",
    "human_title",
    "state",
    "observation_key",
    "reason_code",
    "detail",
    "claim",
    "not_claimed",
    "severity",
    "effective_enforcement",
    "provenance",
    "deduplication",
    "limitations",
    "explanation",
}

EVALUATION_REQUIRED_KEYS = {
    "schema_version",
    "evaluation_id",
    "runtime",
    "analysis",
    "evidence",
    "knowledge_set",
    "contracts",
    "findings",
    "summary",
    "boundaries",
    "limitations",
}


def validate_finding_evaluation(output: dict[str, Any], root: Path = dk_core.ROOT) -> list[str]:
    if not isinstance(output, dict):
        raise FindingRuntimeValidationError("finding evaluation must be an object")
    schema_path = root / SCHEMA_RELATIVE_PATH
    if not schema_path.is_file():
        raise FindingRuntimeValidationError("missing finding evaluation schema")
    dk_core.read_json(schema_path)
    missing = sorted(EVALUATION_REQUIRED_KEYS - set(output))
    if missing:
        raise FindingRuntimeValidationError(
            "finding evaluation missing required keys: " + ", ".join(missing)
        )
    extra = sorted(set(output) - EVALUATION_REQUIRED_KEYS)
    if extra:
        raise FindingRuntimeValidationError(
            "finding evaluation has unknown keys: " + ", ".join(extra)
        )
    if output["schema_version"] != EVALUATION_SCHEMA_VERSION:
        raise FindingRuntimeValidationError("unsupported finding evaluation schema_version")
    if "evaluation_id" in output and not dk_core.SHA256_RE.fullmatch(output["evaluation_id"]):
        raise FindingRuntimeValidationError("invalid evaluation_id")
    runtime = output["runtime"]
    if (
        not isinstance(runtime, dict)
        or runtime.get("name") != RUNTIME_NAME
        or runtime.get("version") != RUNTIME_VERSION
        or runtime.get("mode") != RUNTIME_MODE
    ):
        raise FindingRuntimeValidationError("invalid finding runtime identity")
    findings = output["findings"]
    if not isinstance(findings, list):
        raise FindingRuntimeValidationError("findings must be a list")
    seen_ids: set[str] = set()
    seen_dedup: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise FindingRuntimeValidationError("finding entries must be objects")
        entry_missing = sorted(FINDING_REQUIRED_KEYS - set(finding))
        if entry_missing:
            raise FindingRuntimeValidationError(
                "finding entry missing required keys: " + ", ".join(entry_missing)
            )
        entry_extra = sorted(set(finding) - FINDING_REQUIRED_KEYS)
        if entry_extra:
            raise FindingRuntimeValidationError(
                "finding entry has unknown keys: " + ", ".join(entry_extra)
            )
        if not dk_core.SHA256_RE.fullmatch(finding.get("finding_id", "")):
            raise FindingRuntimeValidationError("invalid finding_id")
        state = finding.get("state")
        if state not in FINDING_STATES or state in FORBIDDEN_STATE_VALUES:
            raise FindingRuntimeValidationError(f"invalid finding state {state!r}")
        severity = finding.get("severity")
        if (
            not isinstance(severity, dict)
            or severity.get("state") != "not_established"
            or severity.get("source") is not None
        ):
            raise FindingRuntimeValidationError(
                "finding severity must remain not_established with null source"
            )
        if severity.get("state") in dk_core.SEVERITIES:
            raise FindingRuntimeValidationError("finding severity level must not be invented")
        if finding.get("effective_enforcement") not in {"guidance", "advisory"}:
            raise FindingRuntimeValidationError(
                "finding enforcement must stay guidance or advisory, never blocking"
            )
        provenance = finding.get("provenance")
        if not isinstance(provenance, dict):
            raise FindingRuntimeValidationError("finding provenance must be an object")
        missing_provenance = sorted(dk_core.MACHINE_FINDING_REQUIRED_PROVENANCE - set(provenance))
        if missing_provenance:
            raise FindingRuntimeValidationError(
                "finding provenance incomplete: " + ", ".join(missing_provenance)
            )
        if state == "confirmed":
            null_fields = sorted(key for key, value in provenance.items() if value is None)
            if null_fields:
                raise FindingRuntimeValidationError(
                    "confirmed finding provenance has null fields: " + ", ".join(null_fields)
                )
            if provenance.get("context_relation") != "current":
                raise FindingRuntimeValidationError(
                    "confirmed finding requires a current canonical context"
                )
            scope = provenance.get("semantic_authority_version_scope")
            if not isinstance(scope, dict) or scope.get("in_scope") is not True:
                raise FindingRuntimeValidationError(
                    "confirmed finding requires an in-scope semantic authority version"
                )
            applicability_ref = provenance.get("applicability_result_identity")
            if (
                not isinstance(applicability_ref, dict)
                or applicability_ref.get("applicability") != "applicable"
                or applicability_ref.get("automation_status") != "machine_resolved"
            ):
                raise FindingRuntimeValidationError(
                    "confirmed finding requires definitive machine-resolved applicability"
                )
        if finding["finding_id"] in seen_ids:
            raise FindingRuntimeValidationError("duplicate finding_id in evaluation")
        seen_ids.add(finding["finding_id"])
        dedup = finding.get("deduplication", {})
        dedup_key = stable_json(dedup.get("key", {}))
        if dedup_key in seen_dedup:
            raise FindingRuntimeValidationError("deduplication key collision in evaluation")
        seen_dedup.add(dedup_key)
    summary = output.get("summary", {})
    states_summary = summary.get("states", {})
    for state in FINDING_STATES:
        expected = sum(1 for finding in findings if finding["state"] == state)
        if states_summary.get(state) != expected:
            raise FindingRuntimeValidationError("summary state counts are inconsistent")
    forbidden = recursive_keys(output) & FORBIDDEN_OUTPUT_KEYS
    if forbidden:
        raise FindingRuntimeValidationError(
            "finding evaluation carries forbidden keys: " + ", ".join(sorted(forbidden))
        )
    return ["FINDING_EVALUATION_SCHEMA_VALID=PASS"]


def render_explanation(output: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("DRUPAL KNOWLEDGE FINDING EVALUATION")
    lines.append(f"project: {output['analysis']['project_id']}")
    lines.append(f"evaluation: {output['evaluation_id']}")
    lines.append(f"knowledge set: v{output['knowledge_set']['version']}")
    lines.append(f"contracts executed: {output['contracts']['executed']}")
    lines.append("")
    for index, finding in enumerate(output["findings"], start=1):
        lines.append(f"[{index}] {finding['state'].upper()} — {finding['human_title']}")
        lines.append(f"    finding: {finding['finding_id']}")
        lines.append(f"    knowledge: {finding['knowledge_id']}")
        lines.append(f"    condition: {finding['condition_id']}")
        lines.append("")
        explanation = finding["explanation"]
        lines.append("    Observed:")
        lines.append(f"      {explanation['observed']}")
        lines.append("    Authoritative Drupal knowledge:")
        lines.append(f"      {explanation['authoritative_drupal_knowledge']}")
        lines.append("    Drupal definition:")
        lines.append(f"      {explanation['drupal_definition']}")
        lines.append("    Conclusion:")
        lines.append(f"      {explanation['conclusion']}")
        lines.append("")
        lines.append("    severity: not established")
        lines.append(f"    enforcement: {finding['effective_enforcement']} (non-blocking)")
        if finding["not_claimed"]:
            lines.append("    not claimed: " + ", ".join(finding["not_claimed"]))
        if finding["limitations"]:
            lines.append("    limitations: " + ", ".join(finding["limitations"]))
        lines.append("")
    if not output["findings"]:
        lines.append("No executable reviewed machine finding contracts produced entries.")
        lines.append("")
    for refusal in output["contracts"]["not_executed"]:
        lines.append(
            f"not executed: {refusal['knowledge_id']} ({refusal['reason_code']})"
        )
    if output["limitations"]:
        lines.append("evaluation limitations: " + ", ".join(output["limitations"]))
    return "\n".join(lines) + "\n"
