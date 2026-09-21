#!/usr/bin/env python3
"""Solved-case capture: turn proven project work into reviewable evidence.

A solved case records that a solution was proven in one concrete context. It
is deliberately not Drupal truth:

    PROJECT EXPERIENCE != UNIVERSAL DRUPAL TRUTH

This module owns the canonical capture path. External producers submit a
candidate through the released CLI; Drupal Knowledge validates
it and owns storage. Producers never write into canonical directories
themselves, and capture never touches trusted knowledge.

Authority rules enforced here:

- captured is not verified: promotion to verified requires real verification
  evidence, never an assertion that something was fixed;
- verified is not trusted knowledge: nothing here creates or edits a knowledge
  record, a source, or an applicability rule;
- applicability is bounded by the evidence actually presented;
- limitations and provenance are first-class machine-readable data;
- project identity is minimized to privacy-preserving technical fingerprints;
- obvious secret material is rejected rather than stored.
"""

from __future__ import annotations

import hashlib
import json
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any

import dk_core


CASE_CONTRACT_VERSION = "0.1"
CAPTURE_NAME = "drupal-knowledge-solved-case-capture"
CAPTURE_VERSION = "0.1"
SCHEMA_RELATIVE_PATH = Path("schema") / "solved-case-candidate.schema.json"
CASES_RELATIVE_PATH = Path("cases") / "solved"

# The two lifecycle states this capability fully supports. Later states exist
# in the canonical solved-case schema but are never reached automatically.
STATE_CAPTURED = "captured"
STATE_VERIFIED = "verified"
CAPTURE_SUPPORTED_STATES = (STATE_CAPTURED, STATE_VERIFIED)

ROOT_CAUSE_STATES = {"confirmed", "evidenced", "unknown"}

# Verification methods that can carry real evidence. A claim alone is never
# one of them.
VERIFICATION_METHODS = {
    "automated_test",
    "reproduction_before_and_after",
    "static_analysis",
    "deployment_acceptance",
    "finding_state_transition",
    "command_output",
    "manual_qa_with_method",
}

FIX_CATEGORIES = {
    "package_version",
    "drupal_configuration",
    "code_change",
    "theme_change",
    "infrastructure_or_runtime",
    "process_or_procedure",
}

# Causality: what the evidence proves versus what remains inference.
CAUSALITY_STATES = {"demonstrated", "consistent_with_evidence", "not_established"}

SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SHA256_FINGERPRINT_RE = re.compile(r"^sha256:[a-f0-9]{64}$")

# Conservative, pragmatic secret screening. Prefer rejection over storing
# suspicious material; this is not a general-purpose DLP system.
SECRET_PATTERNS = (
    (re.compile(r"\b(?:glpat|ghp|github_pat|gho|sk_live|pk_live|sk-proj|xox[abpr])-?[A-Za-z0-9_/-]{8,}"), "credential_token"),
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----"), "private_key"),
    (re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*\S{4,}"), "inline_credential"),
    (re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"), "credential_in_url"),
    (re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"), "cloud_access_key"),
    (re.compile(r"(?i)\bmysql://|\bpgsql://|\bpostgres://"), "database_dsn"),
)

# Absolute developer/machine paths must not be preserved in a shared case.
MACHINE_PATH_RE = re.compile(r"(?:^|[\s\"'(=])(/(?:Users|home|root|private/var|var/folders)/[^\s\"')]+)")

# Personal-data screening is deliberately narrow and conservative.
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class SolvedCaseInputError(RuntimeError):
    """Raised when solved-case CLI input cannot be read."""


class SolvedCaseValidationError(RuntimeError):
    """Raised when a solved-case candidate is not safe to capture."""


class SolvedCaseSecretError(SolvedCaseValidationError):
    """Raised when a candidate carries obvious secret or personal material."""


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def screen_for_secrets(candidate: dict[str, Any]) -> list[dict[str, str]]:
    """Return every obvious secret/personal finding in the candidate."""
    problems: list[dict[str, str]] = []
    for text in recursive_strings(candidate):
        for pattern, kind in SECRET_PATTERNS:
            if pattern.search(text):
                problems.append({"kind": kind, "sample": text[:60]})
        machine_path = MACHINE_PATH_RE.search(text)
        if machine_path:
            problems.append({"kind": "absolute_machine_path", "sample": machine_path.group(1)[:60]})
        if EMAIL_RE.search(text):
            problems.append({"kind": "personal_contact", "sample": text[:60]})
    return problems


def assert_no_secret_material(candidate: dict[str, Any]) -> None:
    problems = screen_for_secrets(candidate)
    if problems:
        kinds = sorted({problem["kind"] for problem in problems})
        raise SolvedCaseSecretError(
            "solved-case candidate carries material that must not be stored: "
            + ", ".join(kinds)
        )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SolvedCaseValidationError(message)


def require_str(value: Any, label: str, minimum: int = 1) -> str:
    require(isinstance(value, str) and len(value.strip()) >= minimum, f"{label} must be a non-empty string")
    return value


def validate_project_context(context: Any) -> None:
    require(isinstance(context, dict), "project_context must be an object")
    dk_core.assert_keys(
        context,
        {"drupal_core_version", "project_fingerprint"},
        "project_context",
    )
    dk_core.assert_only_keys(
        context,
        {
            "drupal_core_version",
            "php_version",
            "packages",
            "themes",
            "environment_class",
            "project_fingerprint",
            "revision_fingerprint",
        },
        "project_context",
    )
    require_str(context["drupal_core_version"], "project_context.drupal_core_version")
    fingerprint = context["project_fingerprint"]
    require(
        isinstance(fingerprint, str) and SHA256_FINGERPRINT_RE.fullmatch(fingerprint),
        "project_context.project_fingerprint must be a sha256 fingerprint, never a name or path",
    )
    if "revision_fingerprint" in context:
        require(
            SHA256_FINGERPRINT_RE.fullmatch(str(context["revision_fingerprint"])),
            "project_context.revision_fingerprint must be a sha256 fingerprint",
        )
    for key in ("packages", "themes"):
        if key in context:
            require(isinstance(context[key], list), f"project_context.{key} must be a list")
            for entry in context[key]:
                require(isinstance(entry, dict), f"project_context.{key} entries must be objects")
                dk_core.assert_keys(entry, {"name", "version"}, f"project_context.{key} entry")
                dk_core.assert_only_keys(entry, {"name", "version"}, f"project_context.{key} entry")


def validate_problem(problem: Any) -> None:
    require(isinstance(problem, dict), "problem must be an object")
    dk_core.assert_keys(problem, {"statement", "symptoms"}, "problem")
    dk_core.assert_only_keys(
        problem,
        {"statement", "symptoms", "origin_finding_id", "related_knowledge_ids", "evidence_refs"},
        "problem",
    )
    require_str(problem["statement"], "problem.statement", 10)
    symptoms = problem["symptoms"]
    require(isinstance(symptoms, list) and symptoms, "problem.symptoms must be a non-empty list")
    for symptom in symptoms:
        require_str(symptom, "problem.symptoms entry")
    if "origin_finding_id" in problem:
        require(
            dk_core.SHA256_RE.fullmatch(str(problem["origin_finding_id"])),
            "problem.origin_finding_id must be a deterministic finding identity",
        )
    if "related_knowledge_ids" in problem:
        require(isinstance(problem["related_knowledge_ids"], list), "problem.related_knowledge_ids must be a list")


def validate_root_cause(root_cause: Any) -> None:
    require(isinstance(root_cause, dict), "root_cause must be an object")
    dk_core.assert_keys(root_cause, {"state", "statement"}, "root_cause")
    dk_core.assert_only_keys(root_cause, {"state", "statement", "evidence_refs"}, "root_cause")
    state = root_cause["state"]
    require(state in ROOT_CAUSE_STATES, f"root_cause.state must be one of {sorted(ROOT_CAUSE_STATES)}")
    statement = require_str(root_cause["statement"], "root_cause.statement", 10)
    if state == "unknown":
        # An unknown root cause is valid and must stay honest: it may not be
        # written as a confident explanation.
        lowered = statement.lower()
        require(
            "unknown" in lowered or "not established" in lowered or "not determined" in lowered,
            "an unknown root cause must say so explicitly rather than assert an explanation",
        )
    else:
        require(
            isinstance(root_cause.get("evidence_refs"), list) and root_cause["evidence_refs"],
            "a confirmed or evidenced root cause requires evidence references",
        )


def validate_fix(fix: Any) -> None:
    require(isinstance(fix, dict), "fix must be an object")
    dk_core.assert_keys(fix, {"category", "description", "changes"}, "fix")
    dk_core.assert_only_keys(fix, {"category", "description", "changes", "rationale"}, "fix")
    require(fix["category"] in FIX_CATEGORIES, f"fix.category must be one of {sorted(FIX_CATEGORIES)}")
    require_str(fix["description"], "fix.description", 10)
    changes = fix["changes"]
    require(isinstance(changes, list) and changes, "fix.changes must be a non-empty list")
    for change in changes:
        require(isinstance(change, dict), "fix.changes entries must be objects")
        dk_core.assert_keys(change, {"scope", "summary"}, "fix.changes entry")
        dk_core.assert_only_keys(change, {"scope", "summary", "evidence_ref"}, "fix.changes entry")
        require_str(change["summary"], "fix.changes summary")
        # Whole-file or diff payloads are not the truth of a solved case.
        require(
            len(change["summary"]) <= 400,
            "fix.changes summary must reference evidence, not embed a whole diff",
        )


def validate_verification(verification: Any, state: str) -> None:
    require(isinstance(verification, dict), "verification must be an object")
    dk_core.assert_keys(verification, {"performed", "results"}, "verification")
    dk_core.assert_only_keys(verification, {"performed", "results", "causality"}, "verification")
    require(isinstance(verification["performed"], bool), "verification.performed must be boolean")
    results = verification["results"]
    require(isinstance(results, list), "verification.results must be a list")
    for result in results:
        require(isinstance(result, dict), "verification.results entries must be objects")
        dk_core.assert_keys(result, {"method", "outcome", "evidence_ref"}, "verification.results entry")
        dk_core.assert_only_keys(
            result,
            {"method", "outcome", "evidence_ref", "detail"},
            "verification.results entry",
        )
        require(
            result["method"] in VERIFICATION_METHODS,
            f"verification method must be one of {sorted(VERIFICATION_METHODS)}",
        )
        require(result["outcome"] in {"passed", "failed", "inconclusive"}, "verification outcome is invalid")
        require_str(result["evidence_ref"], "verification.results evidence_ref", 3)
    causality = verification.get("causality")
    if causality is not None:
        require(isinstance(causality, dict), "verification.causality must be an object")
        dk_core.assert_keys(causality, {"state", "statement"}, "verification.causality")
        dk_core.assert_only_keys(causality, {"state", "statement"}, "verification.causality")
        require(
            causality["state"] in CAUSALITY_STATES,
            f"verification.causality.state must be one of {sorted(CAUSALITY_STATES)}",
        )
        require_str(causality["statement"], "verification.causality.statement", 10)

    if state == STATE_VERIFIED:
        # This is the gate that stops "somebody said it is fixed" from
        # becoming a verified case.
        require(
            verification["performed"] is True,
            "a verified case requires verification to have been performed",
        )
        passed = [item for item in results if item["outcome"] == "passed"]
        require(
            passed,
            "a verified case requires at least one verification result that actually passed",
        )
        require(
            causality is not None,
            "a verified case must state what its evidence demonstrates about causality",
        )


def validate_applicability(applicability: Any, context: dict[str, Any]) -> None:
    """Applicability may never exceed the evidence the case actually carries."""
    require(isinstance(applicability, dict), "applicability must be an object")
    dk_core.assert_keys(applicability, {"proven_on", "claimed_scope"}, "applicability")
    dk_core.assert_only_keys(
        applicability,
        {"proven_on", "claimed_scope", "conditions", "expansion_requires_review"},
        "applicability",
    )
    proven = applicability["proven_on"]
    require(isinstance(proven, dict), "applicability.proven_on must be an object")
    dk_core.assert_keys(proven, {"drupal_core_versions"}, "applicability.proven_on")
    dk_core.assert_only_keys(
        proven,
        {"drupal_core_versions", "packages", "themes", "php_versions"},
        "applicability.proven_on",
    )
    versions = proven["drupal_core_versions"]
    require(
        isinstance(versions, list) and versions,
        "applicability.proven_on.drupal_core_versions must be a non-empty list",
    )
    observed = context["drupal_core_version"]
    require(
        observed in versions,
        "applicability.proven_on must include the Drupal core version the case was actually observed on",
    )
    # The evidence bound: a case proven on one release may not silently claim
    # more. Anything broader is a reviewable proposal, not a captured fact.
    require(
        len(versions) == len(set(versions)),
        "applicability.proven_on.drupal_core_versions must not repeat versions",
    )
    require(
        set(versions) == {observed},
        "applicability.proven_on may only list Drupal core versions the case was actually proven on",
    )
    claimed = applicability["claimed_scope"]
    require(
        claimed == "proven_context_only",
        "captured applicability scope must remain proven_context_only; broader scope requires review",
    )
    if "expansion_requires_review" in applicability:
        require(
            applicability["expansion_requires_review"] is True,
            "applicability expansion must always require review",
        )


def validate_candidate(candidate: Any, root: Path = dk_core.ROOT) -> list[str]:
    """Validate a solved-case candidate without storing anything."""
    require(isinstance(candidate, dict), "solved-case candidate must be a JSON object")
    dk_core.assert_keys(
        candidate,
        {
            "contract_version",
            "producer",
            "state",
            "title",
            "project_context",
            "problem",
            "root_cause",
            "fix",
            "verification",
            "applicability",
            "limitations",
        },
        "solved-case candidate",
    )
    dk_core.assert_only_keys(
        candidate,
        {
            "contract_version",
            "producer",
            "state",
            "title",
            "project_context",
            "problem",
            "root_cause",
            "fix",
            "verification",
            "applicability",
            "limitations",
            "evidence",
            "notes",
        },
        "solved-case candidate",
    )
    require(
        candidate["contract_version"] == CASE_CONTRACT_VERSION,
        "unsupported solved-case contract_version",
    )
    state = candidate["state"]
    require(
        state in CAPTURE_SUPPORTED_STATES,
        f"capture supports only {list(CAPTURE_SUPPORTED_STATES)}; later lifecycle states are never entered automatically",
    )
    producer = candidate["producer"]
    require(isinstance(producer, dict), "producer must be an object")
    dk_core.assert_keys(producer, {"name", "version"}, "producer")
    dk_core.assert_only_keys(producer, {"name", "version"}, "producer")
    require(SLUG_RE.fullmatch(str(producer["name"])), "producer.name must be a slug identifier")
    require_str(producer["version"], "producer.version")
    require_str(candidate["title"], "title", 10)

    validate_project_context(candidate["project_context"])
    validate_problem(candidate["problem"])
    validate_root_cause(candidate["root_cause"])
    validate_fix(candidate["fix"])
    validate_verification(candidate["verification"], state)
    validate_applicability(candidate["applicability"], candidate["project_context"])

    limitations = candidate["limitations"]
    require(
        isinstance(limitations, list) and limitations,
        "limitations must be a non-empty list: a single-project case always has limits",
    )
    for limitation in limitations:
        require_str(limitation, "limitations entry", 5)

    knowledge_ids = {record["id"] for record in dk_core.load_knowledge_records(root)}
    for knowledge_id in candidate["problem"].get("related_knowledge_ids", []):
        require(
            knowledge_id in knowledge_ids,
            f"related knowledge id is not a canonical record: {knowledge_id}",
        )

    assert_no_secret_material(candidate)
    return [
        "SOLVED_CASE_CANDIDATE_VALID=PASS",
        f"SOLVED_CASE_CANDIDATE_STATE={state}",
    ]


def case_identity(candidate: dict[str, Any]) -> str:
    """Deterministic identity from the evidence that defines the case.

    Two captures of the same logical case over the same project evidence
    collapse. A similar problem on a different project keeps a different
    fingerprint, so it stays a separate case and can later become recurrence
    evidence rather than being silently merged.
    """
    context = candidate["project_context"]
    problem = candidate["problem"]
    basis = {
        "contract_version": candidate["contract_version"],
        "drupal_core_version": context["drupal_core_version"],
        "fix_category": candidate["fix"]["category"],
        "origin_finding_id": problem.get("origin_finding_id"),
        "problem_statement": problem["statement"],
        "project_fingerprint": context["project_fingerprint"],
        "symptoms": sorted(problem["symptoms"]),
    }
    return sha256_text(stable_json(basis))


def case_slug(candidate: dict[str, Any]) -> str:
    digest = case_identity(candidate).removeprefix("sha256:")
    category = candidate["fix"]["category"].replace("_", "-")
    return f"case.drupal.solved.{category}.{digest[:16]}"


def case_path(root: Path, case_id: str) -> Path:
    return root / CASES_RELATIVE_PATH / f"{case_id}.json"


def build_case_record(candidate: dict[str, Any]) -> dict[str, Any]:
    """Materialize the canonical record stored by Drupal Knowledge."""
    context = candidate["project_context"]
    problem = candidate["problem"]
    identity = case_identity(candidate)
    case_id = case_slug(candidate)
    record = {
        "id": case_id,
        "title": candidate["title"],
        "problem": problem["statement"],
        "symptoms": list(problem["symptoms"]),
        "root_cause": candidate["root_cause"]["statement"],
        "solution": [change["summary"] for change in candidate["fix"]["changes"]],
        "verification": [
            f"{item['method']}: {item['outcome']} ({item['evidence_ref']})"
            for item in candidate["verification"]["results"]
        ],
        "environment": {
            "environment_class": context.get("environment_class", "unspecified"),
            "project_fingerprint": context["project_fingerprint"],
            "revision_fingerprint": context.get("revision_fingerprint"),
        },
        "drupal_versions": list(candidate["applicability"]["proven_on"]["drupal_core_versions"]),
        "php_versions": [context["php_version"]] if context.get("php_version") else [],
        "modules": list(context.get("packages", [])),
        "themes": list(context.get("themes", [])),
        "project_type": "drupal",
        "applicability": candidate["applicability"],
        "limitations": list(candidate["limitations"]),
        "evidence": list(candidate.get("evidence", [])),
        "related_knowledge_ids": list(problem.get("related_knowledge_ids", [])),
        # One capture is one occurrence. Recurrence is separate evidence and
        # is never inferred from a single project.
        "occurrence_count": 1,
        "first_seen": candidate["project_context"]["project_fingerprint"],
        "last_verified": (
            identity if candidate["state"] == STATE_VERIFIED else "not_verified"
        ),
        "status": candidate["state"],
        "capture": {
            "contract_version": candidate["contract_version"],
            "case_identity": identity,
            "captured_by": {
                "name": CAPTURE_NAME,
                "version": CAPTURE_VERSION,
            },
            "producer": dict(candidate["producer"]),
            "root_cause_state": candidate["root_cause"]["state"],
            "fix_category": candidate["fix"]["category"],
            "verification": candidate["verification"],
            "origin_finding_id": problem.get("origin_finding_id"),
            "promotion": {
                "automatic_promotion": False,
                "human_review_required": True,
                "trusted_knowledge_created": False,
            },
        },
    }
    return record


def capture(
    candidate: dict[str, Any],
    root: Path = dk_core.ROOT,
    force: bool = False,
) -> dict[str, Any]:
    """Validate and store a solved-case candidate. Idempotent by identity."""
    validate_candidate(candidate, root)
    record = build_case_record(candidate)
    path = case_path(root, record["id"])
    payload = stable_json(record)
    existing_state = "created"
    if path.is_file():
        current = json.loads(path.read_text(encoding="utf-8"))
        if current == record:
            existing_state = "unchanged"
        elif not force:
            # Same logical case, different content: a state transition is an
            # explicit verify operation, never a silent overwrite.
            existing_state = "conflict"
            return {
                "case_id": record["id"],
                "case_identity": record["capture"]["case_identity"],
                "result": existing_state,
                "state": current.get("status"),
                "stored": False,
                "detail": "a different record already exists for this case identity; use verify to transition state",
            }
        else:
            existing_state = "updated"
    if existing_state != "unchanged":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    validate_stored_case(root, record["id"])
    return {
        "case_id": record["id"],
        "case_identity": record["capture"]["case_identity"],
        "result": existing_state,
        "state": record["status"],
        "stored": True,
        "path": str(path.relative_to(root)),
    }


def load_case(root: Path, case_id: str) -> dict[str, Any]:
    path = case_path(root, case_id)
    if not path.is_file():
        raise SolvedCaseInputError(f"solved case not found: {case_id}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        raise SolvedCaseValidationError("stored solved case is not valid JSON") from exc


def validate_stored_case(root: Path, case_id: str) -> list[str]:
    record = load_case(root, case_id)
    require(record["id"] == case_id, "stored solved case id mismatch")
    dk_core.validate_solved_cases(root)
    return ["SOLVED_CASE_STORED_VALID=PASS"]


def verify_case(
    case_id: str,
    verification: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    """Transition captured -> verified using explicit verification evidence."""
    record = load_case(root, case_id)
    require(
        record["status"] == STATE_CAPTURED,
        f"only a captured case can be verified; current state is {record['status']}",
    )
    validate_verification(verification, STATE_VERIFIED)
    assert_no_secret_material({"verification": verification})
    record["status"] = STATE_VERIFIED
    record["verification"] = [
        f"{item['method']}: {item['outcome']} ({item['evidence_ref']})"
        for item in verification["results"]
    ]
    record["last_verified"] = record["capture"]["case_identity"]
    record["capture"]["verification"] = verification
    path = case_path(root, case_id)
    path.write_text(stable_json(record), encoding="utf-8")
    validate_stored_case(root, case_id)
    return {
        "case_id": case_id,
        "result": "verified",
        "state": record["status"],
        # Verified is still not trusted knowledge.
        "promoted_to_knowledge": False,
    }


def read_candidate_file(path: str | Path) -> dict[str, Any]:
    candidate_path = Path(path)
    if not candidate_path.is_file():
        raise SolvedCaseInputError("solved-case candidate file does not exist")
    try:
        return json.loads(candidate_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        raise SolvedCaseValidationError("solved-case candidate JSON is invalid") from exc


def validate_capture_contract(root: Path = dk_core.ROOT) -> list[str]:
    schema = dk_core.read_json(root / SCHEMA_RELATIVE_PATH)
    states = schema.get("properties", {}).get("state", {}).get("enum")
    if states != list(CAPTURE_SUPPORTED_STATES):
        raise dk_core.ValidationError(
            "solved-case candidate schema must support only captured and verified"
        )
    if "promotion" in schema.get("properties", {}):
        raise dk_core.ValidationError(
            "a producer candidate must not be able to request promotion"
        )
    return ["SOLVED_CASE_CAPTURE_CONTRACT_VALID=PASS"]
