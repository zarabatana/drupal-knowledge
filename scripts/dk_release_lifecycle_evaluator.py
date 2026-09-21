#!/usr/bin/env python3
"""Neutral Drupal core release lifecycle assessment from analyzer output."""

from __future__ import annotations

import hashlib
import json
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any

import dk_core
import dk_project_analyzer
import dk_release_lifecycle


ASSESSMENT_SCHEMA_VERSION = "0.1"
EVALUATOR_NAME = "drupal-release-lifecycle-evaluator"
EVALUATOR_VERSION = "0.1"
EVALUATOR_MODE = "neutral-release-lifecycle-assessment"
SUPPORTED_ANALYSIS_SCHEMA = "0.1"
SUPPORTED_ANALYZER_VERSION = "0.1"
SCHEMA_PATH = dk_core.ROOT / "schema" / "release-lifecycle-assessment.schema.json"
CANONICAL_CONTEXT_RELATIVE_PATH = Path("knowledge") / "context" / "drupal-core-release-lifecycle.json"

RELEASE_BRANCH_VERSION_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?:alpha|beta|rc)[0-9]+)?$"
)

FORBIDDEN_PROJECT_VERDICT_KEYS = {
    "supported",
    "unsupported",
    "eol",
    "obsolete",
    "vulnerable",
    "secure",
    "insecure_project",
    "needs_upgrade",
    "compliant",
    "non_compliant",
    "finding",
    "findings",
    "remediation",
    "remediations",
    "project_supported",
    "project_unsupported",
    "project_is_supported",
    "project_is_unsupported",
    "project_is_eol",
    "project_is_obsolete",
    "project_is_vulnerable",
    "project_is_secure",
    "project_requires_upgrade",
}


class LifecycleEvaluatorInputError(RuntimeError):
    """Raised when lifecycle evaluator CLI input cannot be read."""


class LifecycleEvaluatorValidationError(RuntimeError):
    """Raised when lifecycle evaluation cannot safely proceed."""


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


def validate_analysis_contract(analysis: dict[str, Any]) -> None:
    if not isinstance(analysis, dict):
        raise LifecycleEvaluatorValidationError("analysis must be a JSON object")
    try:
        dk_project_analyzer.validate_project_analysis(analysis)
    except dk_core.ValidationError as exc:
        raise LifecycleEvaluatorValidationError(
            "analysis does not match project-analysis schema"
        ) from exc
    if analysis.get("schema_version") != SUPPORTED_ANALYSIS_SCHEMA:
        raise LifecycleEvaluatorValidationError("unsupported analyzer schema_version")
    analyzer = analysis.get("analyzer")
    if not isinstance(analyzer, dict):
        raise LifecycleEvaluatorValidationError("analysis analyzer identity is missing")
    if analyzer.get("name") != dk_project_analyzer.ANALYZER_NAME:
        raise LifecycleEvaluatorValidationError(
            "analysis was not produced by the Drupal Project Analyzer"
        )
    if analyzer.get("version") != SUPPORTED_ANALYZER_VERSION:
        raise LifecycleEvaluatorValidationError("unsupported analyzer version")


def release_version(row: dict[str, Any]) -> str | None:
    version = row.get("version", {})
    if not isinstance(version, dict):
        return None
    source = version.get("source", {})
    if not isinstance(source, dict) or source.get("state") != "present":
        return None
    value = source.get("source_value")
    return value if isinstance(value, str) else None


def validate_lifecycle_context_for_evaluation(
    context: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise LifecycleEvaluatorValidationError("lifecycle context must be a JSON object")
    if not SCHEMA_PATH.is_file():
        raise LifecycleEvaluatorValidationError("missing lifecycle assessment schema")
    dk_core.read_json(SCHEMA_PATH)
    if context.get("schema_version") != dk_release_lifecycle.CONTEXT_SCHEMA_VERSION:
        raise LifecycleEvaluatorValidationError(
            "unsupported lifecycle context schema_version"
        )
    if context.get("artifact_type") != "release-lifecycle-context":
        raise LifecycleEvaluatorValidationError("invalid lifecycle context artifact_type")
    if context.get("authority_layer") != "TRUSTED_KNOWLEDGE_CONTEXT":
        raise LifecycleEvaluatorValidationError(
            "lifecycle context must be trusted knowledge context"
        )
    review = context.get("review")
    if not isinstance(review, dict) or review.get("status") != "reviewed":
        raise LifecycleEvaluatorValidationError(
            "unreviewed lifecycle context cannot author assessment"
        )
    source = context.get("source")
    if not isinstance(source, dict):
        raise LifecycleEvaluatorValidationError("lifecycle context source is missing")
    source_id = source.get("source_id")
    snapshot_digest = source.get("snapshot_sha256")
    if not isinstance(source_id, str) or not isinstance(snapshot_digest, str):
        raise LifecycleEvaluatorValidationError(
            "lifecycle context source provenance is incomplete"
        )
    try:
        snapshot_path = dk_core.require_snapshot(root, source_id, snapshot_digest)
    except dk_core.ValidationError as exc:
        raise LifecycleEvaluatorValidationError(
            "lifecycle context source snapshot is invalid"
        ) from exc
    snapshot_bytes = len(snapshot_path.read_bytes())
    if source.get("snapshot_bytes") != snapshot_bytes:
        raise LifecycleEvaluatorValidationError(
            "lifecycle context source snapshot byte length mismatch"
        )
    state_path = root / "sources" / "state" / f"{source_id}.json"
    try:
        state = dk_core.read_json(state_path)
    except (FileNotFoundError, JSONDecodeError) as exc:
        raise LifecycleEvaluatorValidationError(
            "lifecycle source state is unavailable"
        ) from exc
    if state.get("source_id") != source_id:
        raise LifecycleEvaluatorValidationError("lifecycle source state id mismatch")
    current_digest = state.get("content_sha256")
    if not isinstance(current_digest, str):
        raise LifecycleEvaluatorValidationError(
            "lifecycle source state is missing content_sha256"
        )
    releases = context.get("releases")
    if not isinstance(releases, list):
        raise LifecycleEvaluatorValidationError("lifecycle context releases must be a list")
    seen_versions: set[str] = set()
    for row in releases:
        if not isinstance(row, dict):
            raise LifecycleEvaluatorValidationError(
                "lifecycle context release rows must be objects"
            )
        version = release_version(row)
        if version is None:
            continue
        if version in seen_versions:
            raise LifecycleEvaluatorValidationError(
                f"duplicate lifecycle release version: {version}"
            )
        seen_versions.add(version)
    if context.get("release_count") != len(releases):
        raise LifecycleEvaluatorValidationError(
            "lifecycle context release_count does not match releases"
        )
    forbidden = recursive_keys(context).intersection(FORBIDDEN_PROJECT_VERDICT_KEYS)
    if forbidden:
        raise LifecycleEvaluatorValidationError(
            "lifecycle context contains project verdict keys: "
            + ", ".join(sorted(forbidden))
        )
    relation = "current" if current_digest == snapshot_digest else "stale"
    return {
        "relation": relation,
        "source_id": source_id,
        "reviewed_snapshot_sha256": snapshot_digest,
        "current_state_sha256": current_digest,
        "semantics": (
            "freshness of the reviewed lifecycle context against current source state; "
            "not a project support verdict"
        ),
    }


def canonical_context_path(root: Path = dk_core.ROOT) -> Path:
    return root / CANONICAL_CONTEXT_RELATIVE_PATH


def load_context(root: Path = dk_core.ROOT) -> tuple[dict[str, Any], dict[str, Any]]:
    path = canonical_context_path(root)
    try:
        context = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, JSONDecodeError) as exc:
        raise LifecycleEvaluatorValidationError(
            "canonical lifecycle context JSON is unavailable or invalid"
        ) from exc
    freshness = validate_lifecycle_context_for_evaluation(context, root)
    return context, freshness


def analysis_identity(analysis: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": analysis["schema_version"],
        "project_id": analysis["project_id"],
        "analyzer": {
            "name": analysis["analyzer"]["name"],
            "version": analysis["analyzer"]["version"],
            "mode": analysis["analyzer"]["mode"],
        },
        "analysis_sha256": sha256_text(stable_json(analysis)),
    }


def context_identity(
    context: dict[str, Any],
    freshness: dict[str, Any],
) -> dict[str, Any]:
    source = context["source"]
    review = context["review"]
    return {
        "id": context["id"],
        "schema_version": context["schema_version"],
        "context_sha256": sha256_text(stable_json(context)),
        "source_id": source["source_id"],
        "source_snapshot_sha256": source["snapshot_sha256"],
        "source_snapshot_bytes": source["snapshot_bytes"],
        "review_status": review["status"],
        "reviewed_on": review["reviewed_on"],
        "context_relation": freshness["relation"],
    }


def core_version_from_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    fact = analysis.get("profile", {}).get("facts", {}).get("drupal_core_version")
    evidence_ids: list[str] = []
    if isinstance(fact, dict):
        evidence_ids = sorted(
            evidence_id
            for evidence_id in fact.get("source_evidence_ids", [])
            if isinstance(evidence_id, str)
        )
    if not isinstance(fact, dict) or fact.get("state") != "known":
        return {
            "state": "unknown",
            "fact_ref": "drupal_core_version",
            "evidence_ids": evidence_ids,
            "reason_code": "CORE_VERSION_UNKNOWN",
            "notes": fact.get("notes") if isinstance(fact, dict) else "Fact is missing.",
        }
    value = fact.get("value")
    if not isinstance(value, dict) or not isinstance(value.get("version"), str):
        return {
            "state": "unknown",
            "fact_ref": "drupal_core_version",
            "evidence_ids": evidence_ids,
            "reason_code": "CORE_VERSION_FACT_INVALID",
            "notes": "Known drupal_core_version fact did not contain a string version.",
        }
    result = {
        "state": "known",
        "fact_ref": "drupal_core_version",
        "evidence_ids": evidence_ids,
        "package": value.get("package"),
        "version": value["version"],
        "confidence": fact.get("confidence"),
        "notes": fact.get("notes"),
    }
    if isinstance(value.get("corroborated_by"), dict):
        result["corroborated_by"] = value["corroborated_by"]
    return result


def release_rows_by_version(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        version: row
        for row in context["releases"]
        if (version := release_version(row)) is not None
    }


def exact_release_match(
    core_version: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    if core_version["state"] != "known":
        return {
            "state": "not_evaluated",
            "reason_code": "CORE_VERSION_UNKNOWN",
        }
    version = core_version["version"]
    row = release_rows_by_version(context).get(version)
    if row is None:
        return {
            "state": "not_found",
            "source_version": version,
            "reason_code": "EXACT_RELEASE_ROW_NOT_FOUND",
            "semantics": (
                "missing exact source release row is not an unsupported, outdated, "
                "invalid, insecure, or EOL conclusion"
            ),
        }
    return {
        "state": "matched",
        "source_version": version,
        "source_order_index": row.get("source_order_index"),
        "source_release_link": row.get("release_link"),
        "reason_code": "EXACT_RELEASE_ROW_MATCHED",
        "semantics": "exact match against reviewed lifecycle context release.version source value",
    }


def source_branch_token_for_version(version: str) -> dict[str, Any]:
    match = RELEASE_BRANCH_VERSION_RE.fullmatch(version)
    if not match:
        return {
            "state": "unknown",
            "reason_code": "UNSUPPORTED_VERSION_BRANCH_MAPPING",
            "semantics": "version did not match the supported major.minor.patch prerelease-safe token rule",
        }
    return {
        "state": "known",
        "source_value": f"{match.group('major')}.{match.group('minor')}.",
        "normalized_lookup_value": f"{match.group('major')}.{match.group('minor')}",
        "rule": "major.minor.patch[-alphaN|-betaN|-rcN] -> major.minor.",
    }


def branch_match(
    core_version: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    supported = context.get("supported_branches", {})
    entries = supported.get("entries", []) if isinstance(supported, dict) else []
    source_values = [
        item["source_value"]
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("source_value"), str)
    ]
    if core_version["state"] != "known":
        return {
            "state": "unknown",
            "source_branch_token": {"state": "unknown", "reason_code": "CORE_VERSION_UNKNOWN"},
            "branch_listed_in_source_supported_branches": {
                "state": "unknown",
                "reason_code": "CORE_VERSION_UNKNOWN",
            },
            "source_supported_branch_values": source_values,
        }
    token = source_branch_token_for_version(core_version["version"])
    if token["state"] != "known":
        return {
            "state": "unknown",
            "source_branch_token": token,
            "branch_listed_in_source_supported_branches": {
                "state": "unknown",
                "reason_code": token["reason_code"],
            },
            "source_supported_branch_values": source_values,
        }
    if supported.get("state") != "present":
        membership = {
            "state": "unknown",
            "reason_code": "SUPPORTED_BRANCHES_NOT_PRESENT_IN_CONTEXT",
        }
    else:
        membership = {
            "state": "known",
            "value": token["source_value"] in source_values,
            "reason_code": "SOURCE_SUPPORTED_BRANCH_MEMBERSHIP_EVALUATED",
            "semantics": (
                "membership in the reviewed feed supported_branches source values only; "
                "not a project support verdict"
            ),
        }
    return {
        "state": "matched",
        "source_branch_token": token,
        "branch_listed_in_source_supported_branches": membership,
        "source_supported_branch_values": source_values,
    }


def source_attributes(
    release_match: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    if release_match["state"] != "matched":
        return {
            "state": "not_evaluated",
            "reason_code": release_match.get("reason_code"),
        }
    row = release_rows_by_version(context)[release_match["source_version"]]
    return {
        "state": "present",
        "source_release_status": row.get("status"),
        "source_release_type_terms": row.get("release_type_source_values", []),
        "source_security_coverage": row.get("security"),
        "source_published_timestamp": row.get("date"),
        "semantics": (
            "source release row attributes are preserved literally and are not "
            "project security, support, compliance, finding, or remediation verdicts"
        ),
    }


def evaluation_state(
    core_version: dict[str, Any],
    release_match: dict[str, Any],
) -> str:
    if core_version["state"] != "known":
        return "core_version_unknown"
    if release_match["state"] == "not_found":
        return "release_not_found"
    if release_match["state"] == "matched":
        return "evaluated"
    return "requires_human_review"


def limitations(
    core_version: dict[str, Any],
    release_match: dict[str, Any],
    branch: dict[str, Any],
    freshness: dict[str, Any],
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if freshness["relation"] == "stale":
        items.append(
            {
                "code": "LIFECYCLE_CONTEXT_STALE",
                "message": "Assessment is reproducible against the reviewed pinned context, but the context differs from current source state.",
            }
        )
    if core_version["state"] != "known":
        items.append(
            {
                "code": core_version.get("reason_code", "CORE_VERSION_UNKNOWN"),
                "message": "Analyzer output did not provide a known installed Drupal core version.",
            }
        )
    if release_match["state"] == "not_found":
        items.append(
            {
                "code": "EXACT_RELEASE_ROW_NOT_FOUND",
                "message": "The exact analyzer-observed Drupal core version was not present in the reviewed lifecycle context.",
            }
        )
    membership = branch.get("branch_listed_in_source_supported_branches", {})
    if isinstance(membership, dict) and membership.get("state") == "unknown":
        items.append(
            {
                "code": membership.get("reason_code", "BRANCH_MEMBERSHIP_UNKNOWN"),
                "message": "Source supported_branches membership could not be evaluated.",
            }
        )
    return sorted(items, key=lambda item: (item["code"], item["message"]))


def assessment_identity(
    analysis: dict[str, Any],
    context: dict[str, Any],
    freshness: dict[str, Any],
) -> str:
    basis = {
        "analysis": analysis_identity(analysis),
        "evaluator": {
            "name": EVALUATOR_NAME,
            "version": EVALUATOR_VERSION,
            "schema_version": ASSESSMENT_SCHEMA_VERSION,
        },
        "lifecycle_context": context_identity(context, freshness),
    }
    return sha256_text(stable_json(basis))


def evaluate_analysis_data(
    analysis: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    context, _freshness = load_context(root=root)
    return _evaluate_analysis_data_with_context(analysis, context, root=root)


def _evaluate_analysis_data_with_context(
    analysis: dict[str, Any],
    context: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    validate_analysis_contract(analysis)
    freshness = validate_lifecycle_context_for_evaluation(context, root)
    core_version = core_version_from_analysis(analysis)
    release_match = exact_release_match(core_version, context)
    branch = branch_match(core_version, context)
    attributes = source_attributes(release_match, context)
    output = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "assessment_id": assessment_identity(analysis, context, freshness),
        "evaluator": {
            "name": EVALUATOR_NAME,
            "version": EVALUATOR_VERSION,
            "mode": EVALUATOR_MODE,
        },
        "analysis": analysis_identity(analysis),
        "lifecycle_context": context_identity(context, freshness),
        "context_freshness": freshness,
        "evaluation_state": evaluation_state(core_version, release_match),
        "core_version": core_version,
        "release_match": release_match,
        "branch_match": branch,
        "source_attributes": attributes,
        "limitations": limitations(core_version, release_match, branch, freshness),
        "non_verdict": {
            "statements": [
                "lifecycle assessment is not a finding",
                "release terms are source attributes, not project verdicts",
                "supported_branches membership is not a project support verdict",
                "security coverage source fields are not project security verdicts",
                "no remediation or upgrade recommendation is emitted",
            ]
        },
    }
    validate_assessment_output(output)
    return output


def evaluate_analysis_data_with_test_context(
    analysis: dict[str, Any],
    context: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    return _evaluate_analysis_data_with_context(analysis, context, root=root)


def evaluate_analysis_file(
    analysis_path: str | Path,
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    path = Path(analysis_path)
    if not path.is_file():
        raise LifecycleEvaluatorInputError("analysis JSON file does not exist")
    try:
        analysis = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        raise LifecycleEvaluatorValidationError("analysis JSON is invalid") from exc
    return evaluate_analysis_data(analysis, root=root)


def validate_assessment_output(output: dict[str, Any]) -> list[str]:
    if not isinstance(output, dict):
        raise LifecycleEvaluatorValidationError("assessment output must be an object")
    required = {
        "schema_version",
        "assessment_id",
        "evaluator",
        "analysis",
        "lifecycle_context",
        "context_freshness",
        "evaluation_state",
        "core_version",
        "release_match",
        "branch_match",
        "source_attributes",
        "limitations",
        "non_verdict",
    }
    missing = sorted(required - set(output))
    if missing:
        raise LifecycleEvaluatorValidationError(
            "assessment output missing required keys: " + ", ".join(missing)
        )
    if output.get("schema_version") != ASSESSMENT_SCHEMA_VERSION:
        raise LifecycleEvaluatorValidationError("unsupported assessment schema_version")
    if not dk_core.SHA256_RE.fullmatch(output.get("assessment_id", "")):
        raise LifecycleEvaluatorValidationError("invalid assessment_id")
    evaluator = output.get("evaluator")
    if not isinstance(evaluator, dict) or evaluator.get("name") != EVALUATOR_NAME:
        raise LifecycleEvaluatorValidationError("invalid evaluator identity")
    if evaluator.get("version") != EVALUATOR_VERSION or evaluator.get("mode") != EVALUATOR_MODE:
        raise LifecycleEvaluatorValidationError("invalid evaluator version or mode")
    if output.get("evaluation_state") not in {
        "evaluated",
        "core_version_unknown",
        "release_not_found",
        "requires_human_review",
    }:
        raise LifecycleEvaluatorValidationError("invalid evaluation_state")
    freshness = output.get("context_freshness")
    if not isinstance(freshness, dict) or freshness.get("relation") not in {"current", "stale"}:
        raise LifecycleEvaluatorValidationError("invalid context_freshness")
    for key in ("analysis", "lifecycle_context", "core_version", "release_match", "branch_match", "source_attributes"):
        if not isinstance(output.get(key), dict):
            raise LifecycleEvaluatorValidationError(f"{key} must be an object")
    if not isinstance(output.get("limitations"), list):
        raise LifecycleEvaluatorValidationError("limitations must be a list")
    forbidden = recursive_keys(output).intersection(FORBIDDEN_PROJECT_VERDICT_KEYS)
    if forbidden:
        raise LifecycleEvaluatorValidationError(
            "assessment contains project verdict keys: " + ", ".join(sorted(forbidden))
        )
    return ["LIFECYCLE_ASSESSMENT_SCHEMA_VALID=PASS"]
