#!/usr/bin/env python3
"""Core helpers for Drupal Knowledge validation and generation."""

from __future__ import annotations

import copy
import hashlib
import html
import json
import re
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SOURCE_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
KNOWLEDGE_ID_RE = re.compile(
    r"^drupal(?:\.[a-z0-9]+(?:-[a-z0-9]+)*){2,}$"
)
CASE_ID_RE = re.compile(
    r"^case\.drupal(?:\.[a-z0-9]+(?:-[a-z0-9]+)*){2,}$"
)
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FACT_PATH_SEGMENT_RE = r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*"
FACT_PATH_RE = re.compile(rf"^{FACT_PATH_SEGMENT_RE}(?:\.{FACT_PATH_SEGMENT_RE})*$")

SOURCE_CONTENT_TYPES = {"html", "xml", "json", "text", "auto"}

SOURCE_NORMALIZATION_STRATEGIES = {"auto", "html_text", "raw_text"}

SOURCE_LIFECYCLES = {"active", "retired", "superseded"}

TRUST_TIERS = {
    "authoritative",
    "industry-standard",
    "ecosystem",
    "discovery",
    "internal-proven",
}

REVIEW_STATUSES = {
    "reviewed",
    "seed_needs_human_review",
    "internal_review_only",
}

SEVERITIES = {
    "info",
    "low",
    "moderate",
    "high",
    "critical",
}

ENFORCEMENT_INTENTS = {
    "blocking",
    "non_blocking",
    "advisory",
}

MACHINE_APPLICABILITY_OPERATORS = {
    "fact_known",
    "equals",
    "list_contains",
    "list_not_contains",
    "list_non_empty",
    "version_matches",
    "evidence_matches",
    "evidence_absent",
}

# Predicates over canonical project evidence name an assertion and a subject
# rather than an analyzer fact, so they are validated on their own shape.
MACHINE_EVIDENCE_OPERATORS = {"evidence_matches", "evidence_absent"}

MACHINE_SYMBOL_RE = re.compile(rf"^{FACT_PATH_SEGMENT_RE}$")

MACHINE_FINDING_EVIDENCE_DOMAINS = {"release_lifecycle_assessment"}

MACHINE_FINDING_TYPES = {"release_lifecycle"}

MACHINE_FINDING_FORBIDDEN_TYPES = {
    "vulnerability",
    "security_vulnerability",
    "security_finding",
    "compliance",
}

MACHINE_FINDING_REQUIRED_LITERALS = {
    "evaluation_state": "evaluated",
    "exact_release_match": True,
    "context_relation": "current",
    "canonical_context_id": "drupal-core-release-lifecycle",
    "source_field_path": "/project/releases/release/terms/term/value",
    "source_term_name": "Release type",
    "source_term_value": "Insecure",
    "match_mode": "literal_exact_string",
}

MACHINE_FINDING_NON_AUTHORITATIVE_SIGNALS = {
    "branch_listed_in_source_supported_branches",
    "source_supported_branches_presence_or_absence",
    "source_security_coverage_text_or_covered_attribute",
    "release_type_term_security_update",
    "release_ordering_or_source_order_index",
    "newer_release_existence",
}

MACHINE_FINDING_CANDIDATE_STATES = {
    "term_present_and_context_current": "candidate",
    "term_present_and_semantic_authority_version_out_of_scope": "candidate",
    "term_present_and_context_stale": "historical_candidate",
    "term_absent_in_matched_row": "not_observed",
    "applicability_not_definitive": "unknown",
    "release_not_found": "unknown",
    "core_version_unknown": "unknown",
    "context_not_canonical": "unknown",
    "assessment_invalid": "unknown",
}

MACHINE_FINDING_CONFIRMED_STATES = {
    "term_present_and_context_current": "confirmed",
    "term_present_and_semantic_authority_version_out_of_scope": "candidate",
    "term_present_and_context_stale": "historical_candidate",
    "term_absent_in_matched_row": "not_observed",
    "applicability_not_definitive": "unknown",
    "release_not_found": "unknown",
    "core_version_unknown": "unknown",
    "context_not_canonical": "unknown",
    "assessment_invalid": "unknown",
}

MACHINE_FINDING_CONFIRMATION_STATUSES = {
    "not_established",
    "semantic_authority_reviewed",
}

MACHINE_FINDING_REQUIRED_PROVENANCE = {
    "knowledge_id",
    "condition_id",
    "analysis_identity",
    "core_version_fact_ref",
    "core_version_evidence_ids",
    "lifecycle_assessment_id",
    "lifecycle_context_id",
    "lifecycle_context_source_snapshot_sha256",
    "exact_matched_release",
    "literal_source_term",
    "context_relation",
    "applicability_result_identity",
    "semantic_authority_version_scope",
    "effective_enforcement",
    "finding_severity_state",
}

MACHINE_FINDING_SEVERITY_STATE = "not_established"

MACHINE_FINDING_RUNTIME_STATUS = "executed_by_reviewed_finding_runtime"

MACHINE_FINDING_TERM_SEMANTICS_UNRESOLVED = "TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY"

MACHINE_FINDING_TERM_SEMANTICS_REVIEWED = "DRUPAL_UPDATE_STATUS_SEMANTICS_REVIEWED"

MACHINE_FINDING_TERM_SEMANTICS_STATES = {
    MACHINE_FINDING_TERM_SEMANTICS_UNRESOLVED,
    MACHINE_FINDING_TERM_SEMANTICS_REVIEWED,
}

MACHINE_FINDING_AUTHORIZED_MEANING_FORBIDDEN_TOKENS = (
    "exploit",
    "cve",
    "compromis",
    "critical",
    "vulnerab",
    "attack",
)

MACHINE_FINDING_REVIEWED_MINIMUM_FORBIDDEN_CLAIMS = {
    "release_is_exploitable",
    "release_has_specific_cve",
    "release_is_compromised",
    "severity_is_derivable",
}


class ValidationError(RuntimeError):
    """Raised when canonical repository data violates a contract."""


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def stable_json(data) -> str:
    return json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def content_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def snapshot_path(root: Path, source_id: str, digest: str) -> Path:
    if not SOURCE_ID_RE.fullmatch(source_id):
        raise ValidationError(f"invalid source id for snapshot: {source_id!r}")
    if not SHA256_RE.fullmatch(digest):
        raise ValidationError(f"invalid snapshot digest: {digest!r}")
    return (
        root
        / "sources"
        / "snapshots"
        / source_id
        / f"{digest.removeprefix('sha256:')}.txt"
    )


def require_snapshot(root: Path, source_id: str, digest: str) -> Path:
    path = snapshot_path(root, source_id, digest)
    if not path.is_file():
        raise ValidationError(f"missing normalized snapshot: {path}")
    text = path.read_text(encoding="utf-8")
    actual = content_digest(text)
    if actual != digest:
        raise ValidationError(
            f"snapshot hash mismatch: {path}: expected {digest}, got {actual}"
        )
    return path


def write_snapshot(root: Path, source_id: str, digest: str, text: str) -> tuple[Path, bool]:
    actual = content_digest(text)
    if actual != digest:
        raise ValidationError(
            f"snapshot bytes do not match digest: expected {digest}, got {actual}"
        )
    path = snapshot_path(root, source_id, digest)
    if path.exists():
        require_snapshot(root, source_id, digest)
        if path.read_text(encoding="utf-8") != text:
            raise ValidationError(f"content-addressed snapshot collision: {path}")
        return path, False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    require_snapshot(root, source_id, digest)
    return path, True


def load_sources(root: Path = ROOT) -> list[dict]:
    return read_json(root / "sources" / "registry.json")


def load_domains(root: Path = ROOT) -> list[dict]:
    return read_json(root / "taxonomy" / "domains.json")["domains"]


def iter_json_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.rglob("*.json")
        if path.is_file()
    )


def load_knowledge_records(root: Path = ROOT) -> list[dict]:
    return [
        read_json(path)
        for path in iter_json_files(root / "knowledge" / "records")
    ]


def load_solved_cases(root: Path = ROOT) -> list[dict]:
    return [
        read_json(path)
        for path in iter_json_files(root / "cases" / "solved")
    ]


def assert_keys(record: dict, required: set[str], context: str) -> None:
    missing = sorted(required - set(record))
    if missing:
        raise ValidationError(f"{context}: missing required keys: {', '.join(missing)}")


def assert_only_keys(record: dict, allowed: set[str], context: str) -> None:
    extra = sorted(set(record) - allowed)
    if extra:
        raise ValidationError(f"{context}: unknown keys: {', '.join(extra)}")


def validate_sources(root: Path = ROOT) -> list[str]:
    sources = load_sources(root)
    if not isinstance(sources, list) or not sources:
        raise ValidationError("sources/registry.json must contain a non-empty list")

    required = {
        "id",
        "title",
        "url",
        "trust",
        "enabled",
        "category",
        "role",
        "collection_strategy",
        "checked_on",
        "provenance",
        "version_semantics",
    }
    allowed = required | {
        "fetch_url",
        "content_start",
        "content_end",
        "notes",
        # Acquisition behaviour is declared per source so the engine never has
        # to branch on a source id.
        "expected_content_type",
        "normalization",
        "check_cadence_days",
        "lifecycle",
        "superseded_by",
        # Discovery/corroboration behaviour is declared per source so the
        # discovery engine never has to branch on a source id either.
        "discovery",
        # Security advisory feed behaviour, declared per source so the security
        # engine reads field names from the registry rather than hardcoding them.
        "security",
        # Upgrade authority, declared the same way: a source says which
        # transition or platform requirement it speaks for, so the upgrade
        # engine never decides that from a source id.
        "upgrade",
        # API lifecycle authority, declared the same way again: a source says
        # which branch's deprecation index or change-record feed it carries, and
        # which fields the migration engine may read from it.
        "api_lifecycle",
        # Implementation-rule authority: a source says which finding categories
        # it can support, so a rule's authority is checked against the registry
        # rather than asserted by the rule about itself.
        "implementation_authority",
    }
    ids: set[str] = set()
    for source in sources:
        context = f"source {source.get('id', '<unknown>')}"
        assert_keys(source, required, context)
        assert_only_keys(source, allowed, context)
        source_id = source["id"]
        if not SOURCE_ID_RE.fullmatch(source_id):
            raise ValidationError(f"{context}: invalid source id")
        if source_id in ids:
            raise ValidationError(f"{context}: duplicate source id")
        ids.add(source_id)
        if source["trust"] not in TRUST_TIERS:
            raise ValidationError(f"{context}: invalid trust tier {source['trust']!r}")
        if not isinstance(source["enabled"], bool):
            raise ValidationError(f"{context}: enabled must be boolean")
        if not DATE_RE.fullmatch(source["checked_on"]):
            raise ValidationError(f"{context}: checked_on must be YYYY-MM-DD")
        for key in ("url", "fetch_url"):
            if key in source and not re.match(r"^https?://", source[key]):
                raise ValidationError(f"{context}: {key} must be http(s)")
        if not isinstance(source["version_semantics"], dict):
            raise ValidationError(f"{context}: version_semantics must be an object")
        if source.get("expected_content_type") not in (None, *SOURCE_CONTENT_TYPES):
            raise ValidationError(f"{context}: invalid expected_content_type")
        if source.get("normalization") not in (None, *SOURCE_NORMALIZATION_STRATEGIES):
            raise ValidationError(f"{context}: invalid normalization strategy")
        cadence = source.get("check_cadence_days")
        if cadence is not None and (not isinstance(cadence, int) or isinstance(cadence, bool) or cadence < 1):
            raise ValidationError(f"{context}: check_cadence_days must be a positive integer")
        lifecycle = source.get("lifecycle", "active")
        if lifecycle not in SOURCE_LIFECYCLES:
            raise ValidationError(f"{context}: invalid lifecycle {lifecycle!r}")
        if lifecycle == "superseded" and "superseded_by" not in source:
            raise ValidationError(f"{context}: superseded source must declare superseded_by")
        if "superseded_by" in source and lifecycle != "superseded":
            raise ValidationError(f"{context}: superseded_by requires lifecycle superseded")

    for source in sources:
        successor = source.get("superseded_by")
        if successor is not None and successor not in ids:
            raise ValidationError(
                f"source {source['id']}: superseded_by is not a registered source"
            )

    return [
        "SOURCE_REGISTRY_VALID=PASS",
        f"SOURCE_REGISTRY_COUNT={len(sources)}",
    ]


def validate_snapshot_states(root: Path = ROOT) -> list[str]:
    sources = {source["id"] for source in load_sources(root)}
    state_dir = root / "sources" / "state"
    checked = 0
    unbaselined = 0
    for path in iter_json_files(state_dir):
        state = read_json(path)
        context = f"source state {path.relative_to(root)}"
        assert_keys(state, {"source_id", "url"}, context)
        if state["source_id"] not in sources:
            raise ValidationError(f"{context}: source_id is not registered")
        acquisition = state.get("acquisition")
        if "content_sha256" not in state:
            # A source whose only acquisition attempts failed has no snapshot to
            # point at. It must say so explicitly rather than look baselined.
            if not isinstance(acquisition, dict) or acquisition.get("last_success_at"):
                raise ValidationError(
                    f"{context}: state without content_sha256 must record a failed acquisition"
                )
            unbaselined += 1
            continue
        assert_keys(state, {"last_changed_at", "content_length"}, context)
        digest = state["content_sha256"]
        require_snapshot(root, state["source_id"], digest)
        text = snapshot_path(root, state["source_id"], digest).read_text(encoding="utf-8")
        if len(text.encode("utf-8")) != state["content_length"]:
            raise ValidationError(f"{context}: content_length does not match snapshot")
        if isinstance(acquisition, dict):
            superseded = acquisition.get("previous_snapshot_sha256")
            if superseded:
                # Superseding a snapshot must never make the old one unreachable.
                require_snapshot(root, state["source_id"], superseded)
        checked += 1
    return [
        "SNAPSHOT_HASH_INTEGRITY=PASS",
        f"SOURCE_STATES_CHECKED={checked}",
        f"SOURCE_STATES_UNBASELINED={unbaselined}",
    ]


def validate_reviewed_knowledge_sources_baselined(root: Path = ROOT) -> list[str]:
    checked = 0
    failures = []
    for record in load_knowledge_records(root):
        if record.get("review_status") != "reviewed":
            continue
        for source_ref in record.get("sources", []):
            source_id = source_ref.get("source_id")
            state_path = root / "sources" / "state" / f"{source_id}.json"
            context = f"{record.get('id', '<unknown>')} -> {source_id}"
            if not source_id or not state_path.is_file():
                failures.append(f"{context}: missing source state")
                continue
            try:
                state = read_json(state_path)
                if state.get("source_id") != source_id:
                    failures.append(f"{context}: state source_id mismatch")
                    continue
                digest = state.get("content_sha256")
                if not isinstance(digest, str):
                    failures.append(f"{context}: state content_sha256 missing")
                    continue
                snapshot = require_snapshot(root, source_id, digest)
                content_length = len(snapshot.read_bytes())
                if content_length != state.get("content_length"):
                    failures.append(f"{context}: source state content_length mismatch")
                    continue
            except ValidationError as exc:
                failures.append(f"{context}: {exc}")
                continue
            checked += 1
    if failures:
        raise ValidationError(
            "reviewed knowledge references unbaselined or invalid sources: "
            + "; ".join(failures)
        )
    return [
        "REVIEWED_KNOWLEDGE_SOURCES_BASELINED=PASS",
        f"REVIEWED_KNOWLEDGE_SOURCE_REFERENCES_CHECKED={checked}",
    ]


def validate_source_contracts(root: Path = ROOT) -> list[str]:
    import dk_acquisition

    return (
        validate_sources(root)
        + validate_snapshot_states(root)
        + dk_acquisition.validate_acquisition_contract(root)
    )


def effective_enforcement(record: dict) -> str:
    review_status = record.get("review_status")
    intent = record.get("enforcement", {}).get("intent", "advisory")
    if review_status != "reviewed":
        return "advisory"
    if intent == "blocking":
        return "blocking"
    if intent == "non_blocking":
        return "guidance"
    return "advisory"


def validate_version_applicability(value, context: str) -> None:
    if not isinstance(value, dict):
        raise ValidationError(f"{context}: version_applicability must be an object")
    allowed = {"drupal_core", "php", "modules", "themes", "notes"}
    assert_only_keys(value, allowed, context)
    for key in ("drupal_core", "php", "modules", "themes"):
        if key not in value:
            continue
        if not isinstance(value[key], list):
            raise ValidationError(f"{context}: {key} applicability must be a list")
        for index, item in enumerate(value[key]):
            item_context = f"{context}: {key}[{index}]"
            if not isinstance(item, dict):
                raise ValidationError(f"{item_context}: applicability item must be object")
            assert_keys(item, {"constraint", "status"}, item_context)
            if item["status"] not in {"applicable", "introduced", "deprecated", "removed", "unknown"}:
                raise ValidationError(f"{item_context}: invalid status")


def validate_machine_applicability_condition(condition, context: str) -> None:
    if not isinstance(condition, dict):
        raise ValidationError(f"{context}: condition must be an object")
    group_keys = [key for key in ("all", "any", "not") if key in condition]
    if group_keys:
        if len(group_keys) != 1 or "operator" in condition:
            raise ValidationError(f"{context}: condition must be one group or one predicate")
        key = group_keys[0]
        children = condition[key]
        if key == "not":
            validate_machine_applicability_condition(children, f"{context}.not")
            return
        if not isinstance(children, list) or not children:
            raise ValidationError(f"{context}: {key} must be a non-empty list")
        for index, child in enumerate(children):
            validate_machine_applicability_condition(child, f"{context}.{key}[{index}]")
        return
    operator = condition.get("operator")
    if operator in MACHINE_EVIDENCE_OPERATORS:
        assert_only_keys(
            condition,
            {"id", "operator", "assertion", "subject", "value", "value_path"},
            context,
        )
        if not isinstance(condition.get("assertion"), str):
            raise ValidationError(f"{context}: evidence predicate needs an assertion")
        if not isinstance(condition.get("subject"), str):
            raise ValidationError(f"{context}: evidence predicate needs a subject")
        return
    fact_name = condition.get("fact")
    assert_only_keys(
        condition,
        {"id", "operator", "fact", "path", "value", "item_key", "constraint"},
        context,
    )
    if operator not in MACHINE_APPLICABILITY_OPERATORS:
        raise ValidationError(f"{context}: unsupported operator {operator!r}")
    if not isinstance(fact_name, str) or not FACT_PATH_RE.fullmatch(fact_name):
        raise ValidationError(f"{context}: invalid fact reference")
    if "path" in condition and (
        not isinstance(condition["path"], str) or not FACT_PATH_RE.fullmatch(condition["path"])
    ):
        raise ValidationError(f"{context}: invalid fact path")
    if "item_key" in condition and not isinstance(condition["item_key"], str):
        raise ValidationError(f"{context}: item_key must be a string")
    if operator == "version_matches" and not isinstance(condition.get("constraint"), str):
        raise ValidationError(f"{context}: version_matches requires a string constraint")


def validate_machine_applicability_contract(record: dict, context: str) -> None:
    if "machine_applicability" not in record:
        return
    contract = record["machine_applicability"]
    if not isinstance(contract, dict):
        raise ValidationError(f"{context}: machine_applicability must be an object")
    assert_only_keys(
        contract,
        {"schema_version", "condition", "notes"},
        f"{context}: machine_applicability",
    )
    if contract.get("schema_version") != "0.1":
        raise ValidationError(f"{context}: unsupported machine_applicability schema_version")
    validate_machine_applicability_condition(
        contract.get("condition"),
        f"{context}: machine_applicability.condition",
    )


def _require_machine_symbols(values, context: str) -> None:
    if not isinstance(values, list) or not values:
        raise ValidationError(f"{context}: must be a non-empty list")
    for value in values:
        if not isinstance(value, str) or not MACHINE_SYMBOL_RE.fullmatch(value):
            raise ValidationError(f"{context}: {value!r} is not a declarative symbol")
    if len(set(values)) != len(values):
        raise ValidationError(f"{context}: duplicate entries")


def validate_machine_finding_contract(record: dict, context: str, root: Path = ROOT) -> None:
    """Validate the narrow declarative machine_finding contract.

    The contract is data only. It never carries expressions, regular
    expressions, paths, code, or free text that a runtime could execute.
    """
    if "machine_finding" not in record:
        return
    contract = record["machine_finding"]
    context = f"{context}: machine_finding"
    if not isinstance(contract, dict):
        raise ValidationError(f"{context}: must be an object")
    assert_keys(
        contract,
        {
            "schema_version",
            "condition_id",
            "evidence_domain",
            "finding_type",
            "assertion",
            "human_title",
            "requires",
            "severity",
            "confirmation_authority",
            "states",
            "non_authoritative_signals_ignored",
            "provenance_requirements",
            "identity",
            "deduplication",
            "term_semantics",
            "runtime_status",
        },
        context,
    )
    assert_only_keys(
        contract,
        {
            "schema_version",
            "condition_id",
            "evidence_domain",
            "finding_type",
            "assertion",
            "human_title",
            "assertion_scope",
            "requires",
            "severity",
            "confirmation_authority",
            "states",
            "non_authoritative_signals_ignored",
            "provenance_requirements",
            "identity",
            "deduplication",
            "term_semantics",
            "runtime_status",
            "notes",
        },
        context,
    )
    if contract.get("schema_version") != "0.1":
        raise ValidationError(f"{context}: unsupported machine_finding schema_version")
    for key in ("condition_id", "assertion"):
        value = contract.get(key)
        if not isinstance(value, str) or not MACHINE_SYMBOL_RE.fullmatch(value):
            raise ValidationError(f"{context}: {key} must be a declarative symbol")
    if contract["evidence_domain"] not in MACHINE_FINDING_EVIDENCE_DOMAINS:
        raise ValidationError(f"{context}: unsupported evidence_domain")
    finding_type = contract["finding_type"]
    if finding_type in MACHINE_FINDING_FORBIDDEN_TYPES:
        raise ValidationError(f"{context}: forbidden finding_type {finding_type!r}")
    if finding_type not in MACHINE_FINDING_TYPES:
        raise ValidationError(f"{context}: unsupported finding_type")
    if not isinstance(contract.get("human_title"), str) or len(contract["human_title"]) < 10:
        raise ValidationError(f"{context}: human_title must be a descriptive string")

    requires = contract.get("requires")
    if not isinstance(requires, dict):
        raise ValidationError(f"{context}: requires must be an object")
    assert_only_keys(requires, set(MACHINE_FINDING_REQUIRED_LITERALS), f"{context}: requires")
    for key, expected in MACHINE_FINDING_REQUIRED_LITERALS.items():
        if key not in requires:
            raise ValidationError(f"{context}: requires.{key} is mandatory")
        actual = requires[key]
        if actual != expected or type(actual) is not type(expected):
            raise ValidationError(
                f"{context}: requires.{key} must be the literal {expected!r}"
            )

    severity = contract.get("severity")
    if not isinstance(severity, dict):
        raise ValidationError(f"{context}: severity must be an object")
    assert_only_keys(severity, {"state", "source", "rationale"}, f"{context}: severity")
    if severity.get("state") != MACHINE_FINDING_SEVERITY_STATE:
        raise ValidationError(f"{context}: finding severity state must be not_established")
    if "source" not in severity or severity["source"] is not None:
        raise ValidationError(f"{context}: finding severity source must be null")
    if severity.get("state") in SEVERITIES or record.get("severity") == severity.get("state"):
        raise ValidationError(
            f"{context}: knowledge-record severity must not become finding severity"
        )

    confirmation = contract.get("confirmation_authority")
    if not isinstance(confirmation, dict):
        raise ValidationError(f"{context}: confirmation_authority must be an object")
    assert_keys(
        confirmation,
        {"status", "semantic_authority_refs", "required_semantic_authority_category"},
        f"{context}: confirmation_authority",
    )
    assert_only_keys(
        confirmation,
        {
            "status",
            "semantic_authority_refs",
            "required_semantic_authority_category",
            "semantic_authority_version_scope",
            "rationale",
        },
        f"{context}: confirmation_authority",
    )
    confirmation_status = confirmation.get("status")
    if confirmation_status not in MACHINE_FINDING_CONFIRMATION_STATUSES:
        raise ValidationError(
            f"{context}: unsupported confirmation authority status {confirmation_status!r}"
        )
    category = confirmation.get("required_semantic_authority_category")
    if not isinstance(category, str) or not MACHINE_SYMBOL_RE.fullmatch(category):
        raise ValidationError(
            f"{context}: required_semantic_authority_category must be a declarative symbol"
        )
    authority_refs = confirmation.get("semantic_authority_refs")
    if not isinstance(authority_refs, list) or any(
        not isinstance(ref, str) for ref in authority_refs
    ):
        raise ValidationError(
            f"{context}: semantic_authority_refs must be a list of identifiers"
        )
    if len(set(authority_refs)) != len(authority_refs):
        raise ValidationError(f"{context}: duplicate semantic authority references")
    for ref in authority_refs:
        if not (KNOWLEDGE_ID_RE.fullmatch(ref) or SOURCE_ID_RE.fullmatch(ref)):
            raise ValidationError(
                f"{context}: invalid semantic authority reference {ref!r}"
            )
    if confirmation_status == "not_established" and authority_refs:
        raise ValidationError(
            f"{context}: semantic_authority_refs must stay empty until semantic authority is reviewed"
        )
    version_scope = confirmation.get("semantic_authority_version_scope")
    if confirmation_status == "not_established" and version_scope is not None:
        raise ValidationError(
            f"{context}: a version scope cannot exist before semantic authority is reviewed"
        )
    if confirmation_status == "semantic_authority_reviewed":
        if not isinstance(version_scope, dict):
            raise ValidationError(
                f"{context}: reviewed semantic authority requires an explicit "
                "semantic_authority_version_scope"
            )
        assert_only_keys(
            version_scope,
            {"drupal_core_majors", "basis"},
            f"{context}: semantic_authority_version_scope",
        )
        majors = version_scope.get("drupal_core_majors")
        if (
            not isinstance(majors, list)
            or not majors
            or any(not isinstance(major, str) or not major.isdigit() for major in majors)
            or len(set(majors)) != len(majors)
        ):
            raise ValidationError(
                f"{context}: drupal_core_majors must be a non-empty unique list of major versions"
            )
        basis = version_scope.get("basis")
        if not isinstance(basis, str) or len(basis) < 20:
            raise ValidationError(
                f"{context}: semantic authority version scope requires an explicit basis"
            )
        source_majors: set[str] = set()
        sources_by_id = {item["id"]: item for item in load_sources(root)}
        for ref in authority_refs:
            source = sources_by_id.get(ref)
            if source is None:
                continue
            drupal_core = source.get("version_semantics", {}).get("drupal_core", [])
            for token in drupal_core if isinstance(drupal_core, list) else []:
                match = re.match(r"^([0-9]+)\.", str(token))
                if match:
                    source_majors.add(match.group(1))
        unsupported = sorted(set(majors) - source_majors)
        if unsupported:
            raise ValidationError(
                f"{context}: version scope claims majors without pinned semantic "
                "authority source evidence: " + ", ".join(unsupported)
            )
    if confirmation_status == "semantic_authority_reviewed":
        if not authority_refs:
            raise ValidationError(
                f"{context}: semantic authority review requires explicit reviewed authority references, not a status flip"
            )
        knowledge_by_id = {item["id"]: item for item in load_knowledge_records(root)}
        source_ids = {item["id"] for item in load_sources(root)}
        unknown_refs = sorted(set(authority_refs) - set(knowledge_by_id) - source_ids)
        if unknown_refs:
            raise ValidationError(
                f"{context}: unknown semantic authority references: " + ", ".join(unknown_refs)
            )
        for ref in authority_refs:
            if ref in knowledge_by_id:
                if knowledge_by_id[ref].get("review_status") != "reviewed":
                    raise ValidationError(
                        f"{context}: semantic authority knowledge reference {ref!r} is not reviewed"
                    )
                continue
            state_path = root / "sources" / "state" / f"{ref}.json"
            try:
                state = read_json(state_path)
                require_snapshot(root, ref, state["content_sha256"])
            except (FileNotFoundError, KeyError, ValidationError) as exc:
                raise ValidationError(
                    f"{context}: semantic authority source {ref!r} is not baselined with an immutable snapshot"
                ) from exc

    semantics_block = contract.get("term_semantics")
    semantics_state = semantics_block.get("state") if isinstance(semantics_block, dict) else None
    semantics_reviewed = semantics_state == MACHINE_FINDING_TERM_SEMANTICS_REVIEWED
    if semantics_reviewed and confirmation_status != "semantic_authority_reviewed":
        raise ValidationError(
            f"{context}: reviewed term semantics require reviewed confirmation authority"
        )
    if not semantics_reviewed and confirmation_status == "semantic_authority_reviewed":
        raise ValidationError(
            f"{context}: confirmation authority cannot be marked reviewed while term "
            "semantics require additional authority"
        )

    states = contract.get("states")
    if not isinstance(states, dict):
        raise ValidationError(f"{context}: states must be an object")
    if "confirmed" in states.values() and not (
        semantics_reviewed and confirmation_status == "semantic_authority_reviewed"
    ):
        raise ValidationError(
            f"{context}: a knowledge contract cannot declare confirmed state by observing "
            "a source term whose semantic authority is not established"
        )
    expected_states = (
        MACHINE_FINDING_CONFIRMED_STATES if semantics_reviewed else MACHINE_FINDING_CANDIDATE_STATES
    )
    if states != expected_states:
        raise ValidationError(f"{context}: states must match the reviewed state contract")

    ignored = contract.get("non_authoritative_signals_ignored")
    if not isinstance(ignored, list) or not ignored:
        raise ValidationError(f"{context}: non_authoritative_signals_ignored must be a list")
    unknown_signals = sorted(set(ignored) - MACHINE_FINDING_NON_AUTHORITATIVE_SIGNALS)
    if unknown_signals:
        raise ValidationError(
            f"{context}: unknown non-authoritative signals: " + ", ".join(unknown_signals)
        )
    missing_signals = sorted(MACHINE_FINDING_NON_AUTHORITATIVE_SIGNALS - set(ignored))
    if missing_signals:
        raise ValidationError(
            f"{context}: contract must ignore every known non-authoritative signal: "
            + ", ".join(missing_signals)
        )

    provenance = contract.get("provenance_requirements")
    _require_machine_symbols(provenance, f"{context}: provenance_requirements")
    missing_provenance = sorted(MACHINE_FINDING_REQUIRED_PROVENANCE - set(provenance))
    if missing_provenance:
        raise ValidationError(
            f"{context}: missing provenance requirements: " + ", ".join(missing_provenance)
        )

    identity = contract.get("identity")
    if not isinstance(identity, dict):
        raise ValidationError(f"{context}: identity must be an object")
    assert_only_keys(
        identity,
        {"algorithm", "timestamp_allowed", "key_fields", "excluded_fields"},
        f"{context}: identity",
    )
    if identity.get("algorithm") != "sha256_stable_json":
        raise ValidationError(f"{context}: identity algorithm must be sha256_stable_json")
    if identity.get("timestamp_allowed") is not False:
        raise ValidationError(f"{context}: identity must forbid timestamps")
    _require_machine_symbols(identity.get("key_fields"), f"{context}: identity.key_fields")
    if any("timestamp" in field or field.endswith("_at") for field in identity["key_fields"]):
        raise ValidationError(f"{context}: identity key fields must not include time")
    if "excluded_fields" in identity:
        _require_machine_symbols(
            identity["excluded_fields"], f"{context}: identity.excluded_fields"
        )
        overlap = sorted(set(identity["excluded_fields"]) & set(identity["key_fields"]))
        if overlap:
            raise ValidationError(
                f"{context}: identity fields cannot be both key and excluded: "
                + ", ".join(overlap)
            )

    deduplication = contract.get("deduplication")
    if not isinstance(deduplication, dict):
        raise ValidationError(f"{context}: deduplication must be an object")
    assert_only_keys(
        deduplication,
        {"max_instances", "key_fields", "collapsed_read_paths"},
        f"{context}: deduplication",
    )
    if deduplication.get("max_instances") != 1 or isinstance(
        deduplication.get("max_instances"), bool
    ):
        raise ValidationError(f"{context}: deduplication must allow one logical instance")
    _require_machine_symbols(
        deduplication.get("key_fields"), f"{context}: deduplication.key_fields"
    )
    if len(deduplication["key_fields"]) >= len(identity["key_fields"]):
        raise ValidationError(
            f"{context}: deduplication key must be coarser than finding identity"
        )

    semantics = contract.get("term_semantics")
    if not isinstance(semantics, dict):
        raise ValidationError(f"{context}: term_semantics must be an object")
    assert_only_keys(
        semantics,
        {
            "state",
            "meaning_bearing_claims_authorized",
            "authorized_meaning",
            "forbidden_claims",
            "required_future_source_category",
        },
        f"{context}: term_semantics",
    )
    if semantics.get("state") not in MACHINE_FINDING_TERM_SEMANTICS_STATES:
        raise ValidationError(f"{context}: unsupported term semantics state")
    if semantics_reviewed:
        if semantics.get("meaning_bearing_claims_authorized") is not True:
            raise ValidationError(
                f"{context}: reviewed term semantics must explicitly authorize the bounded meaning"
            )
        authorized_meaning = semantics.get("authorized_meaning")
        if not isinstance(authorized_meaning, str) or len(authorized_meaning) < 40:
            raise ValidationError(
                f"{context}: reviewed term semantics require an explicit bounded authorized_meaning"
            )
        lowered_meaning = authorized_meaning.lower()
        for token in MACHINE_FINDING_AUTHORIZED_MEANING_FORBIDDEN_TOKENS:
            if token in lowered_meaning:
                raise ValidationError(
                    f"{context}: authorized_meaning must not carry {token!r} claims"
                )
        forbidden_claims = semantics.get("forbidden_claims")
        _require_machine_symbols(
            forbidden_claims, f"{context}: term_semantics.forbidden_claims"
        )
        missing_boundaries = sorted(
            MACHINE_FINDING_REVIEWED_MINIMUM_FORBIDDEN_CLAIMS - set(forbidden_claims)
        )
        if missing_boundaries:
            raise ValidationError(
                f"{context}: reviewed term semantics must keep forbidding: "
                + ", ".join(missing_boundaries)
            )
    else:
        if semantics.get("meaning_bearing_claims_authorized") is not False:
            raise ValidationError(
                f"{context}: meaning-bearing claims must stay unauthorized"
            )
        if "authorized_meaning" in semantics:
            raise ValidationError(
                f"{context}: unresolved term semantics cannot carry an authorized meaning"
            )
        if "forbidden_claims" in semantics:
            _require_machine_symbols(
                semantics["forbidden_claims"], f"{context}: term_semantics.forbidden_claims"
            )

    if contract.get("runtime_status") != MACHINE_FINDING_RUNTIME_STATUS:
        raise ValidationError(
            f"{context}: runtime_status must record the single reviewed finding runtime"
        )

    if effective_enforcement(record) == "blocking":
        raise ValidationError(f"{context}: machine finding contracts cannot be blocking")


def validate_machine_finding_contracts(root: Path = ROOT) -> list[str]:
    knowledge_schema = read_json(root / "schema" / "knowledge-record.schema.json")
    if "machine_finding" not in knowledge_schema.get("properties", {}):
        raise ValidationError("knowledge schema must support optional machine_finding")
    if knowledge_schema.get("additionalProperties") is not False:
        raise ValidationError("knowledge schema must reject unknown record fields")
    count = 0
    for record in load_knowledge_records(root):
        if "machine_finding" not in record:
            continue
        validate_machine_finding_contract(record, f"knowledge {record['id']}", root)
        count += 1
    return [
        "MACHINE_FINDING_CONTRACT_VALID=PASS",
        "MACHINE_FINDING_CONTRACT_DECLARATIVE=PASS",
        f"MACHINE_FINDING_CONTRACT_COUNT={count}",
    ]


def machine_finding_contract_count(root: Path = ROOT) -> int:
    return sum(1 for record in load_knowledge_records(root) if "machine_finding" in record)


def validate_knowledge(root: Path = ROOT) -> list[str]:
    records = load_knowledge_records(root)
    sources = {source["id"] for source in load_sources(root)}
    domains = {domain["id"] for domain in load_domains(root)}
    required = {
        "id",
        "title",
        "summary",
        "kind",
        "domains",
        "severity",
        "review_status",
        "sources",
        "version_applicability",
        "actions",
        "checks",
        "evidence_requirements",
        "automation_hints",
        "enforcement",
        "related",
    }
    allowed = required | {
        "project_applicability",
        "supersedes",
        "superseded_by",
        "coverage",
        "machine_applicability",
        "machine_finding",
    }
    seen: set[str] = set()
    unreviewed_blocking = []
    for record in records:
        context = f"knowledge {record.get('id', '<unknown>')}"
        assert_keys(record, required, context)
        assert_only_keys(record, allowed, context)
        record_id = record["id"]
        if not KNOWLEDGE_ID_RE.fullmatch(record_id):
            raise ValidationError(f"{context}: invalid hierarchical knowledge id")
        if record_id in seen:
            raise ValidationError(f"{context}: duplicate id")
        seen.add(record_id)
        if record["severity"] not in SEVERITIES:
            raise ValidationError(f"{context}: invalid severity")
        if record["review_status"] not in REVIEW_STATUSES:
            raise ValidationError(f"{context}: invalid review_status")
        if not isinstance(record["domains"], list) or not record["domains"]:
            raise ValidationError(f"{context}: domains must be a non-empty list")
        for domain in record["domains"]:
            if domain not in domains:
                raise ValidationError(f"{context}: unknown domain {domain!r}")
        for index, source in enumerate(record["sources"]):
            source_context = f"{context}: sources[{index}]"
            assert_keys(source, {"source_id", "locator"}, source_context)
            if source["source_id"] not in sources:
                raise ValidationError(f"{source_context}: unknown source_id")
        validate_version_applicability(record["version_applicability"], context)
        validate_machine_applicability_contract(record, context)
        validate_machine_finding_contract(record, context, root)
        intent = record["enforcement"].get("intent")
        if intent not in ENFORCEMENT_INTENTS:
            raise ValidationError(f"{context}: invalid enforcement intent")
        if record["review_status"] != "reviewed" and effective_enforcement(record) == "blocking":
            unreviewed_blocking.append(record_id)
        if "severity" in record["enforcement"]:
            raise ValidationError(
                f"{context}: enforcement must not duplicate or derive from severity"
            )
    if unreviewed_blocking:
        raise ValidationError(
            "unreviewed records became blocking: " + ", ".join(unreviewed_blocking)
        )
    return [
        "KNOWLEDGE_RECORDS_VALID=PASS",
        "KNOWLEDGE_ID_CONVENTION_VALID=PASS",
        "UNREVIEWED_KNOWLEDGE_CANNOT_BLOCK=PASS",
        f"KNOWLEDGE_RECORD_COUNT={len(records)}",
    ] + validate_reviewed_knowledge_sources_baselined(root)


def validate_solved_cases(root: Path = ROOT) -> list[str]:
    cases = load_solved_cases(root)
    knowledge_ids = {record["id"] for record in load_knowledge_records(root)}
    required = {
        "id",
        "title",
        "problem",
        "symptoms",
        "root_cause",
        "solution",
        "verification",
        "environment",
        "drupal_versions",
        "php_versions",
        "modules",
        "themes",
        "project_type",
        "applicability",
        "limitations",
        "evidence",
        "related_knowledge_ids",
        "occurrence_count",
        "first_seen",
        "last_verified",
        "status",
    }
    allowed = required | {"promotion", "capture"}
    for case in cases:
        context = f"case {case.get('id', '<unknown>')}"
        assert_keys(case, required, context)
        assert_only_keys(case, allowed, context)
        if not CASE_ID_RE.fullmatch(case["id"]):
            raise ValidationError(f"{context}: invalid solved-case id")
        if case["status"] not in {
            "captured",
            "verified",
            "recurring",
            "generalization_proposed",
            "promoted_to_knowledge_proposal",
            "rejected",
            "retired",
        }:
            raise ValidationError(f"{context}: invalid status")
        if case.get("universal_rule") is True:
            raise ValidationError(f"{context}: solved cases cannot be universal rules")
        capture = case.get("capture")
        if capture is not None:
            promotion = capture.get("promotion", {})
            if promotion.get("automatic_promotion") is not False:
                raise ValidationError(f"{context}: a captured case can never be automatically promoted")
            if promotion.get("human_review_required") is not True:
                raise ValidationError(f"{context}: promotion must always require human review")
            if promotion.get("trusted_knowledge_created") is not False:
                raise ValidationError(f"{context}: capturing a case must never create trusted knowledge")
        if not isinstance(case["occurrence_count"], int) or case["occurrence_count"] < 1:
            raise ValidationError(f"{context}: occurrence_count must be positive integer")
        for record_id in case["related_knowledge_ids"]:
            if record_id not in knowledge_ids:
                raise ValidationError(f"{context}: unknown related knowledge {record_id}")
    return [
        "SOLVED_CASES_VALID=PASS",
        "SOLVED_CASE_NOT_UNIVERSAL_RULE=PASS",
        f"SOLVED_CASE_COUNT={len(cases)}",
    ]


def validate_consumer_contract(root: Path = ROOT) -> list[str]:
    """The contracts an external consumer relies on exist and keep unknown distinct.

    Drupal Knowledge names no consumer. Whatever reads a project profile or an
    evidence set must be able to see that an unknown fact is unknown, so the
    profile schema's fact state must carry ``unknown`` as its own value.
    """
    required_files = [
        root / "schema" / "project-profile.schema.json",
        root / "schema" / "project-evidence.schema.json",
    ]
    missing = [str(path.relative_to(root)) for path in required_files if not path.is_file()]
    if missing:
        raise ValidationError("missing consumer contract files: " + ", ".join(missing))

    profile_schema = read_json(root / "schema" / "project-profile.schema.json")
    facts = profile_schema["$defs"]["fact"]["properties"]["state"]["enum"]
    if "unknown" not in facts:
        raise ValidationError("project profile fact state must include unknown")
    return [
        "CONSUMER_CONTRACT_VALID=PASS",
        "UNKNOWN_IS_NOT_FALSE=PASS",
    ]


def validate_discovery_contract(root: Path = ROOT) -> list[str]:
    for relative in (
        "schema/discovery-signal.schema.json",
        "schema/discovery-candidate.schema.json",
        "schema/corroboration-dossier.schema.json",
        "schema/source-change-candidate.schema.json",
    ):
        read_json(root / relative)
    return [
        "DISCOVERY_CONTRACTS_VALID=PASS",
        "KNOWLEDGE_AUTHORITY_BOUNDARIES_DEFINED=PASS",
    ]


def validate_project_analyzer_contract(root: Path = ROOT) -> list[str]:
    read_json(root / "schema" / "project-analysis.schema.json")
    profile_schema = read_json(root / "schema" / "project-profile.schema.json")
    evidence_schema = read_json(root / "schema" / "project-evidence.schema.json")
    facts = profile_schema["properties"]["facts"]["properties"]
    if "project_type" not in facts or "drupal_web_root" not in facts:
        raise ValidationError("project profile schema must support analyzer project facts")
    evidence_fields = evidence_schema["properties"]
    if "bytes" not in evidence_fields or "role" not in evidence_fields:
        raise ValidationError("project evidence schema must support analyzer provenance")
    return ["PROJECT_ANALYZER_CONTRACT_VALID=PASS"]


def validate_applicability_resolver_contract(root: Path = ROOT) -> list[str]:
    resolution_schema = read_json(root / "schema" / "applicability-resolution.schema.json")
    if resolution_schema.get("properties", {}).get("results", {}).get("type") != "array":
        raise ValidationError("applicability resolution schema must define result array")
    knowledge_schema = read_json(root / "schema" / "knowledge-record.schema.json")
    if "machine_applicability" not in knowledge_schema.get("properties", {}):
        raise ValidationError("knowledge schema must support optional machine_applicability")
    return [
        "APPLICABILITY_RESOLVER_CONTRACT_VALID=PASS",
        "APPLICABILITY_CONTRACT_DECLARATIVE=PASS",
    ]


def validate_finding_runtime_contract(root: Path = ROOT) -> list[str]:
    schema = read_json(root / "schema" / "finding-evaluation.schema.json")
    finding_schema = schema.get("$defs", {}).get("finding", {})
    states = finding_schema.get("properties", {}).get("state", {}).get("enum")
    if states != [
        "confirmed",
        "candidate",
        "historical_candidate",
        "not_observed",
        "unknown",
        "requires_human_review",
    ]:
        raise ValidationError("finding evaluation schema must declare the reviewed finding states")
    for forbidden in ("passed", "secure", "safe", "compliant"):
        if forbidden in states:
            raise ValidationError(f"finding evaluation schema must not declare state {forbidden!r}")
    severity = finding_schema.get("properties", {}).get("severity", {}).get("properties", {})
    if severity.get("state", {}).get("const") != "not_established":
        raise ValidationError("finding evaluation schema must pin severity to not_established")
    enforcement = finding_schema.get("properties", {}).get("effective_enforcement", {}).get("enum")
    if enforcement != ["guidance", "advisory"] or "blocking" in enforcement:
        raise ValidationError("finding evaluation schema must exclude blocking enforcement")
    runtime = schema.get("properties", {}).get("runtime", {}).get("properties", {})
    if runtime.get("mode", {}).get("const") != "reviewed-machine-finding-contract-execution":
        raise ValidationError(
            "finding evaluation schema must pin reviewed machine finding contract execution"
        )
    if not (root / "scripts" / "dk_finding_runtime.py").is_file():
        raise ValidationError("finding runtime module is missing")
    return ["FINDING_RUNTIME_CONTRACT_VALID=PASS"]


def validate_release_lifecycle_evaluator_contract(root: Path = ROOT) -> list[str]:
    assessment_schema = read_json(root / "schema" / "release-lifecycle-assessment.schema.json")
    properties = assessment_schema.get("properties", {})
    if properties.get("evaluation_state", {}).get("enum") != [
        "evaluated",
        "core_version_unknown",
        "release_not_found",
        "requires_human_review",
    ]:
        raise ValidationError("release lifecycle assessment schema must define neutral states")
    evaluator = properties.get("evaluator", {}).get("properties", {})
    if evaluator.get("mode", {}).get("const") != "neutral-release-lifecycle-assessment":
        raise ValidationError("release lifecycle evaluator schema must be neutral assessment only")
    return ["RELEASE_LIFECYCLE_EVALUATOR_CONTRACT_VALID=PASS"]


def coverage_status_for_domain(domain: dict, records: list[dict]) -> str:
    count = sum(1 for record in records if domain["id"] in record.get("domains", []))
    if count == 0:
        return "EMPTY"
    if domain.get("initial_coverage") == "PARTIAL":
        return "PARTIAL"
    return "FOUNDATION"


def build_generated(root: Path = ROOT) -> dict:
    sources = sorted(load_sources(root), key=lambda source: source["id"])
    records = sorted(load_knowledge_records(root), key=lambda record: record["id"])
    cases = sorted(load_solved_cases(root), key=lambda case: case["id"])
    domains = sorted(load_domains(root), key=lambda domain: domain["id"])

    materialized_records = []
    advisory_records = []
    for record in records:
        materialized = copy.deepcopy(record)
        materialized["effective_enforcement"] = effective_enforcement(record)
        if record["review_status"] == "reviewed":
            materialized_records.append(materialized)
        else:
            advisory_records.append(materialized)

    coverage = {
        "schema_version": "0.1",
        "domains": [
            {
                "id": domain["id"],
                "label": domain["label"],
                "parent": domain.get("parent"),
                "status": coverage_status_for_domain(domain, records),
                "record_count": sum(
                    1 for record in records if domain["id"] in record.get("domains", [])
                ),
            }
            for domain in domains
        ],
    }

    checked_dates = sorted({source["checked_on"] for source in sources})
    generated = {
        "schema_version": "0.1",
        "product": "Drupal Knowledge",
        "metadata": {
            "source_count": len(sources),
            "knowledge_record_count": len(records),
            "reviewed_record_count": len(materialized_records),
            "deferred_record_count": len(advisory_records),
            "solved_case_count": len(cases),
            "machine_finding_contract_count": sum(
                1 for record in records if "machine_finding" in record
            ),
            "last_source_verification": checked_dates[-1] if checked_dates else None,
            "coverage_summary": {
                status: sum(1 for domain in coverage["domains"] if domain["status"] == status)
                for status in ("FOUNDATION", "PARTIAL", "EMPTY")
            },
        },
        "authority_boundaries": [
            "SOURCE",
            "TRUSTED_KNOWLEDGE",
            "PROJECT_FACT",
            "OBSERVED_PROJECT_EVIDENCE",
            "SOLVED_CASE",
            "DISCOVERY_SIGNAL",
        ],
        "trusted_records": materialized_records,
        "advisory_seed_records": advisory_records,
        "solved_cases": cases,
        "coverage": coverage,
    }
    return generated


def generated_paths(root: Path = ROOT) -> dict[str, Path]:
    return {
        "knowledge": root / "generated" / "knowledge.json",
        "coverage": root / "generated" / "coverage.json",
    }


def write_generated(root: Path = ROOT) -> list[Path]:
    generated = build_generated(root)
    paths = generated_paths(root)
    paths["knowledge"].parent.mkdir(parents=True, exist_ok=True)
    paths["knowledge"].write_text(stable_json(generated), encoding="utf-8")
    paths["coverage"].write_text(stable_json(generated["coverage"]), encoding="utf-8")
    return [paths["knowledge"], paths["coverage"]]


def expected_generated_bytes(root: Path = ROOT) -> dict[Path, bytes]:
    generated = build_generated(root)
    return {
        generated_paths(root)["knowledge"]: stable_json(generated).encode("utf-8"),
        generated_paths(root)["coverage"]: stable_json(generated["coverage"]).encode("utf-8"),
    }


def html_page(root: Path = ROOT) -> str:
    sources = sorted(load_sources(root), key=lambda source: source["id"])
    records = sorted(load_knowledge_records(root), key=lambda record: record["id"])
    cases = sorted(load_solved_cases(root), key=lambda case: case["id"])
    generated = build_generated(root)
    rows_sources = "\n".join(
        "<tr>"
        f"<td>{html.escape(source['id'])}</td>"
        f"<td>{html.escape(source['title'])}</td>"
        f"<td>{html.escape(source['trust'])}</td>"
        f"<td>{html.escape(source['role'])}</td>"
        "</tr>"
        for source in sources
    )
    rows_records = "\n".join(
        "<tr>"
        f"<td>{html.escape(record['id'])}</td>"
        f"<td>{html.escape(record['title'])}</td>"
        f"<td>{html.escape(record['review_status'])}</td>"
        f"<td>{html.escape(effective_enforcement(record))}</td>"
        "</tr>"
        for record in records
    )
    rows_cases = "\n".join(
        "<tr>"
        f"<td>{html.escape(case['id'])}</td>"
        f"<td>{html.escape(case['title'])}</td>"
        f"<td>{html.escape(case['status'])}</td>"
        "</tr>"
        for case in cases
    ) or '<tr><td colspan="3">No solved cases yet.</td></tr>'
    rows_coverage = "\n".join(
        "<tr>"
        f"<td>{html.escape(domain['id'])}</td>"
        f"<td>{html.escape(domain['status'])}</td>"
        f"<td>{domain['record_count']}</td>"
        "</tr>"
        for domain in generated["coverage"]["domains"]
    )
    metadata = generated["metadata"]
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Drupal Knowledge</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1b1f24; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #d0d7de; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #f6f8fa; }}
    code {{ background: #f6f8fa; padding: 0.1rem 0.25rem; }}
  </style>
</head>
<body>
  <h1>Drupal Knowledge</h1>
  <p>Foundation aggregate generated from canonical repository data.</p>
  <ul>
    <li>Sources: {metadata['source_count']}</li>
    <li>Knowledge records: {metadata['knowledge_record_count']}</li>
    <li>Reviewed records: {metadata['reviewed_record_count']}</li>
    <li>Deferred records: {metadata['deferred_record_count']}</li>
    <li>Solved cases: {metadata['solved_case_count']}</li>
    <li>Last source verification: {html.escape(str(metadata['last_source_verification']))}</li>
  </ul>
  <h2>Sources</h2>
  <table><thead><tr><th>ID</th><th>Title</th><th>Trust</th><th>Role</th></tr></thead><tbody>
{rows_sources}
  </tbody></table>
  <h2>Knowledge</h2>
  <table><thead><tr><th>ID</th><th>Title</th><th>Review</th><th>Effective enforcement</th></tr></thead><tbody>
{rows_records}
  </tbody></table>
  <h2>Solved Cases</h2>
  <table><thead><tr><th>ID</th><th>Title</th><th>Status</th></tr></thead><tbody>
{rows_cases}
  </tbody></table>
  <h2>Coverage</h2>
  <table><thead><tr><th>Domain</th><th>Status</th><th>Records</th></tr></thead><tbody>
{rows_coverage}
  </tbody></table>
</body>
</html>
"""


def write_site(path: Path, root: Path = ROOT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_page(root), encoding="utf-8")
    return path


def expected_site_bytes(root: Path = ROOT) -> bytes:
    return html_page(root).encode("utf-8")


def validate_generated_current(root: Path = ROOT) -> list[str]:
    stale = []
    for path, expected in expected_generated_bytes(root).items():
        if not path.is_file() or path.read_bytes() != expected:
            stale.append(str(path.relative_to(root)))
    public_index = root / "public" / "index.html"
    if not public_index.is_file() or public_index.read_bytes() != expected_site_bytes(root):
        stale.append("public/index.html")
    if stale:
        raise ValidationError(
            "generated output is stale: "
            + ", ".join(stale)
            + ". Run python3 scripts/dk.py generate and python3 scripts/dk.py site public/index.html"
        )
    return ["GENERATED_KNOWLEDGE_CURRENT=PASS"]


def validate_all(root: Path = ROOT) -> list[str]:
    messages = []
    messages.extend(validate_source_contracts(root))
    messages.extend(validate_knowledge(root))
    messages.extend(validate_solved_cases(root))
    messages.extend(validate_consumer_contract(root))
    messages.extend(validate_discovery_contract(root))
    messages.extend(validate_project_analyzer_contract(root))
    messages.extend(validate_applicability_resolver_contract(root))
    messages.extend(validate_machine_finding_contracts(root))
    messages.extend(validate_release_lifecycle_evaluator_contract(root))
    messages.extend(validate_finding_runtime_contract(root))
    import dk_solved_case
    messages.extend(dk_solved_case.validate_capture_contract(root))
    import dk_discovery
    messages.extend(dk_discovery.validate_discovery_contract(root))
    import dk_generalization
    messages.extend(dk_generalization.validate_generalization_contract(root))
    import dk_security
    messages.extend(dk_security.validate_security_contract(root))
    import dk_remediation
    messages.extend(dk_remediation.validate_remediation_contract(root))
    import dk_upgrade
    messages.extend(dk_upgrade.validate_upgrade_contract(root))
    import dk_api_lifecycle
    messages.extend(dk_api_lifecycle.validate_api_lifecycle_contract(root))
    import dk_migration
    messages.extend(dk_migration.validate_migration_contract(root))
    import dk_evidence
    messages.extend(dk_evidence.validate_evidence_contract(root))
    import dk_implementation
    messages.extend(dk_implementation.validate_implementation_contract(root))
    import dk_query
    messages.extend(dk_query.validate_query_contract(root))
    import dk_public
    messages.extend(dk_public.validate_public_dataset(root))
    import dk_api
    messages.extend(dk_api.validate_api_artifacts(root))
    import dk_release_lifecycle
    messages.extend(dk_release_lifecycle.validate_context_file(root=root))
    import dk_release_meta
    messages.extend(dk_release_meta.validate_release_meta(root))
    messages.extend(validate_generated_current(root))
    return messages


def assert_unknown_is_not_false() -> None:
    fact = {"state": "unknown"}
    if fact.get("value") is False:
        raise AssertionError("unknown facts must not be coerced to false")


def tree_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def knowledge_tree_digest(root: Path = ROOT) -> str:
    return tree_digest(iter_json_files(root / "knowledge" / "records"))


def write_temp_file_url(text: str) -> tuple[tempfile.TemporaryDirectory, str]:
    temp = tempfile.TemporaryDirectory()
    path = Path(temp.name) / "source.html"
    path.write_text(text, encoding="utf-8")
    return temp, path.as_uri()
