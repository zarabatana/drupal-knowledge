#!/usr/bin/env python3
"""Implementation findings: what a reviewed rule and observed evidence together say.

Prompt 12 could tell you a project's `system.performance:cache.page.max_age` is
`0`. That is a fact and nothing more. This module is where a fact becomes
something worth acting on, and the whole design exists to keep that step honest:

    static observation  !=  bad practice

A finding needs two things that neither the evidence layer nor a developer's
taste can supply alone: a rule whose authority is a registered authoritative
source, and project evidence definitive enough to settle the rule's conditions.
Missing either one produces a candidate or an unknown, never a confirmation.

Three rules the evaluator will not break:

    unreviewed rule        -> cannot confirm, ever
    heuristic evidence     -> cannot confirm, ever
    missing context        -> candidate, not a verdict

The third is the subtle one. Drupal's own documentation says a site behind a
CDN can disable page caching deliberately. So a rule about page caching states
what context it needs, and where that context is unobservable the finding stays
guidance with the gap written down rather than an accusation.

The engine is read-only. It changes no configuration, no code and no Drupal
state, and it produces no trusted knowledge.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_applicability
import dk_core
import dk_evidence
import dk_finding_runtime


ENGINE_NAME = "drupal-knowledge-implementation-engine"
ENGINE_VERSION = "0.1"
RULE_CONTRACT_VERSION = "0.1"
FINDING_CONTRACT_VERSION = "0.1"

RESULT_DOMAIN = "implementation_finding"
RULES_RELATIVE_PATH = Path("rules") / "implementation"

# --- categories --------------------------------------------------------------

CATEGORY_PERFORMANCE = "performance"
CATEGORY_SECURITY = "security"
CATEGORY_CONFIGURATION_QUALITY = "configuration_quality"

CATEGORIES = (CATEGORY_PERFORMANCE, CATEGORY_SECURITY, CATEGORY_CONFIGURATION_QUALITY)

# --- rule review lifecycle ---------------------------------------------------

REVIEW_DRAFT = "draft"
REVIEW_REVIEWED = "reviewed"
REVIEW_DEPRECATED = "deprecated"
REVIEW_SUPERSEDED = "superseded"

REVIEW_STATES = (REVIEW_DRAFT, REVIEW_REVIEWED, REVIEW_DEPRECATED, REVIEW_SUPERSEDED)

# Only a reviewed rule may confirm anything. A draft rule still evaluates, so
# its author can see what it would say, but its findings are capped.
CONFIRMING_REVIEW_STATES = frozenset({REVIEW_REVIEWED})

# --- finding states, borrowed rather than reinvented -------------------------

CONFIRMED = "confirmed"
CANDIDATE = "candidate"
NOT_OBSERVED = "not_observed"
UNKNOWN = "unknown"
REQUIRES_HUMAN_REVIEW = "requires_human_review"

FINDING_STATES = (CONFIRMED, CANDIDATE, NOT_OBSERVED, UNKNOWN, REQUIRES_HUMAN_REVIEW)

# Absence of an adverse condition is not a conformance verdict. Taken from the
# finding runtime so both engines refuse the same words.
FORBIDDEN_STATE_VALUES = dk_finding_runtime.FORBIDDEN_STATE_VALUES

# --- enforcement -------------------------------------------------------------

ENFORCEMENT_GUIDANCE = "guidance"
ENFORCEMENT_ADVISORY = "advisory"
ENFORCEMENT_BLOCKING = "blocking"

ENFORCEMENT_INTENTS = (ENFORCEMENT_GUIDANCE, ENFORCEMENT_ADVISORY, ENFORCEMENT_BLOCKING)

# --- check kinds -------------------------------------------------------------
#
# Exactly two, with fixed semantics. This is not a rules language: a condition
# is evaluated by the existing applicability resolver, and a cross-reference is
# one declared join between two evidence assertions.

CHECK_CONDITION = "evidence_condition"
CHECK_CROSS_REFERENCE = "evidence_cross_reference"

CHECK_KINDS = (CHECK_CONDITION, CHECK_CROSS_REFERENCE)

SEVERITY_NOT_ESTABLISHED = "not_established"

RULE_ID_RE = re.compile(r"^(performance|security|configuration_quality)\.[a-z][a-z0-9-]*$")


class ImplementationInputError(RuntimeError):
    """Caller asked for something the rules or evidence do not describe."""


class ImplementationEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as an evidence problem."""


def now_iso(moment: datetime | None = None) -> str:
    return dk_evidence.now_iso(moment)


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def load_rules(root: Path = dk_core.ROOT) -> list[dict]:
    directory = root / RULES_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return sorted(
        (dk_core.read_json(path) for path in dk_core.iter_json_files(directory)),
        key=lambda item: item.get("rule_id", ""),
    )


def validate_rule(rule: dict, registered_sources: dict[str, dict], root: Path) -> None:
    """A rule may only claim authority the registry actually grants it."""
    required = {
        "rule_contract_version",
        "rule_id",
        "category",
        "title",
        "summary",
        "review",
        "authority",
        "scope",
        "check",
        "finding",
    }
    missing = sorted(required - set(rule))
    if missing:
        raise dk_core.ValidationError(
            f"implementation rule {rule.get('rule_id')}: missing keys: {', '.join(missing)}"
        )
    rule_id = rule["rule_id"]
    if not RULE_ID_RE.fullmatch(rule_id):
        raise dk_core.ValidationError(f"implementation rule {rule_id}: invalid rule id")
    if not rule_id.startswith(rule["category"] + "."):
        raise dk_core.ValidationError(
            f"implementation rule {rule_id}: id must be namespaced by its category"
        )
    if rule["category"] not in CATEGORIES:
        raise dk_core.ValidationError(f"implementation rule {rule_id}: unknown category")
    if rule["review"]["status"] not in REVIEW_STATES:
        raise dk_core.ValidationError(f"implementation rule {rule_id}: unknown review status")

    authority = rule["authority"]
    if not authority.get("sources"):
        raise dk_core.ValidationError(
            f"implementation rule {rule_id}: a rule with no authoritative source is a preference"
        )
    for reference in authority["sources"]:
        source = registered_sources.get(reference["source_id"])
        if source is None:
            raise dk_core.ValidationError(
                f"implementation rule {rule_id}: references unregistered source "
                f"{reference['source_id']}"
            )
        if source["trust"] != "authoritative":
            raise dk_core.ValidationError(
                f"implementation rule {rule_id}: source {source['id']} is not authoritative"
            )
        block = source.get("implementation_authority") or {}
        if block.get("role") != "implementation_rule_authority":
            raise dk_core.ValidationError(
                f"implementation rule {rule_id}: source {source['id']} does not declare "
                "itself implementation-rule authority"
            )
        if rule["category"] not in block.get("categories", []):
            raise dk_core.ValidationError(
                f"implementation rule {rule_id}: source {source['id']} does not support "
                f"the {rule['category']} category"
            )
        # The quoted line must still be present in the pinned snapshot, so a
        # rule cannot outlive the sentence it was built on.
        verify_quote(root, reference, f"implementation rule {rule_id}")

    check = rule["check"]
    if check["kind"] not in CHECK_KINDS:
        raise dk_core.ValidationError(f"implementation rule {rule_id}: unknown check kind")
    if check["kind"] == CHECK_CONDITION:
        dk_applicability.validate_machine_condition(
            check["condition"], f"implementation rule {rule_id}"
        )
    else:
        for key in ("source_assertion", "target_assertion"):
            if not isinstance(check.get(key), str):
                raise dk_core.ValidationError(
                    f"implementation rule {rule_id}: cross reference needs {key}"
                )
        if "source_value_path" in check and not isinstance(check["source_value_path"], str):
            raise dk_core.ValidationError(
                f"implementation rule {rule_id}: source_value_path must be a string"
            )
        if "source_subject_prefix" in check and not isinstance(check["source_subject_prefix"], str):
            raise dk_core.ValidationError(
                f"implementation rule {rule_id}: source_subject_prefix must be a string"
            )
        for assertion in (check["source_assertion"], check["target_assertion"]):
            if assertion not in dk_evidence.ASSERTIONS:
                raise dk_core.ValidationError(
                    f"implementation rule {rule_id}: unknown evidence assertion {assertion!r}"
                )

    finding = rule["finding"]
    if finding["enforcement_intent"] not in ENFORCEMENT_INTENTS:
        raise dk_core.ValidationError(f"implementation rule {rule_id}: unknown enforcement intent")
    if finding["severity_state"] != SEVERITY_NOT_ESTABLISHED:
        raise dk_core.ValidationError(
            f"implementation rule {rule_id}: severity is not established by this product"
        )
    for text in (finding["assertion"], finding["human_title"], finding["remediation"]["guidance"]):
        lowered = str(text).lower()
        for word in FORBIDDEN_STATE_VALUES:
            if re.search(rf"\b{re.escape(word)}\b", lowered):
                raise dk_core.ValidationError(
                    f"implementation rule {rule_id}: refuses conformance wording {word!r}"
                )
    if finding["remediation"].get("applied") is not False:
        raise dk_core.ValidationError(
            f"implementation rule {rule_id}: remediation must declare that it was not applied"
        )


def verify_quote(root: Path, reference: dict, where: str) -> None:
    """Assert the quoted authority line is still in its pinned snapshot."""
    source_id = reference["source_id"]
    state_path = root / "sources" / "state" / f"{source_id}.json"
    if not state_path.is_file():
        raise dk_core.ValidationError(f"{where}: source {source_id} has no acquisition state")
    state = dk_core.read_json(state_path)
    sha = state.get("content_sha256")
    if not isinstance(sha, str):
        raise dk_core.ValidationError(f"{where}: source {source_id} has no baselined snapshot")
    if reference.get("snapshot_sha256") != sha:
        # The rule was reviewed against a different snapshot. That is review
        # work, not a silent change of what the rule means.
        raise dk_core.ValidationError(
            f"{where}: source {source_id} has changed since the rule was reviewed; "
            "the rule needs re-review rather than a new interpretation"
        )
    snapshot = dk_core.require_snapshot(root, source_id, sha)
    text = snapshot.read_text(encoding="utf-8")
    for quote in reference.get("quotes", []):
        if quote not in text:
            raise dk_core.ValidationError(
                f"{where}: quoted authority is absent from snapshot {sha}: {quote!r}"
            )


def rule_is_stale(root: Path, rule: dict) -> list[dict]:
    """Authority references whose source has moved since the rule was reviewed."""
    stale = []
    for reference in rule["authority"]["sources"]:
        state_path = root / "sources" / "state" / f"{reference['source_id']}.json"
        current = None
        if state_path.is_file():
            current = dk_core.read_json(state_path).get("content_sha256")
        if current != reference.get("snapshot_sha256"):
            stale.append(
                {
                    "source_id": reference["source_id"],
                    "reviewed_snapshot_sha256": reference.get("snapshot_sha256"),
                    "current_snapshot_sha256": current,
                }
            )
    return stale


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


def scope_applies(rule: dict, evidence_set: dict) -> dict:
    """Whether the rule's declared scope covers this project."""
    scope = rule["scope"]
    index = dk_evidence.index(evidence_set)
    core = index["by_key"].get((dk_evidence.A_CORE_VERSION, "drupal/core"))
    version = core["observation"]["value"] if core and core["observation"]["state"] == "observed" else None

    minimum = scope.get("drupal_core_minimum_major")
    if minimum is None:
        return {"applies": True, "reason": "The rule declares no core-version scope.", "core_version": version}
    if version is None:
        return {
            "applies": None,
            "reason": "The installed Drupal core version was not observed, so scope is undecidable.",
            "core_version": None,
        }
    major = version.split(".", 1)[0]
    if not major.isdigit():
        return {
            "applies": None,
            "reason": f"The core version {version!r} could not be read as a major.",
            "core_version": version,
        }
    if int(major) < int(minimum):
        return {
            "applies": False,
            "reason": (
                f"The rule applies from Drupal {minimum} and the project runs {version}."
            ),
            "core_version": version,
        }
    return {
        "applies": True,
        "reason": f"The project runs Drupal {version}, within the rule's declared scope.",
        "core_version": version,
    }


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def evaluate_condition_check(rule: dict, evidence_set: dict) -> dict:
    """Run a rule's condition through the one applicability resolver."""
    index = dk_evidence.index(evidence_set)
    outcome = dk_applicability.evaluate_condition(rule["check"]["condition"], {}, index)
    return {
        "kind": CHECK_CONDITION,
        "truth": outcome.value,
        "reason_codes": sorted(outcome.reason_codes),
        "evidence_ids": sorted(outcome.evidence_ids),
        "evaluations": outcome.evaluations,
        "matches": [],
    }


def evaluate_cross_reference_check(rule: dict, evidence_set: dict) -> dict:
    """Join two evidence assertions and report every unmatched subject.

    One declared join with fixed semantics: for each value named by a source
    record, require a target record naming it. A match that is missing is only
    reported when the *target* domain is complete, because otherwise "no record"
    means "we did not look there".
    """
    check = rule["check"]
    source_assertion = check["source_assertion"]
    target_assertion = check["target_assertion"]
    value_path = check.get("source_value_path") or None
    prefix = check.get("source_subject_prefix")

    sources = [
        item
        for item in evidence_set["records"]
        if item["assertion"] == source_assertion
        # A rule may scope the join to one family of subjects, so a theme rule
        # reads system.theme and not every exported value in the project.
        and (prefix is None or item["subject"].startswith(prefix))
    ]
    targets = {
        item["subject"]: item
        for item in evidence_set["records"]
        if item["assertion"] == target_assertion
    }
    target_complete = any(
        item["completeness"]["supports_negative_conclusion"] for item in targets.values()
    )

    if not sources:
        return {
            "kind": CHECK_CROSS_REFERENCE,
            "truth": dk_applicability.UNKNOWN,
            "reason_codes": ["CROSS_REFERENCE_SOURCE_EVIDENCE_ABSENT"],
            "evidence_ids": [],
            "evaluations": [],
            "matches": [],
        }
    if not target_complete:
        return {
            "kind": CHECK_CROSS_REFERENCE,
            "truth": dk_applicability.UNKNOWN,
            "reason_codes": ["EVIDENCE_DOMAIN_INCOMPLETE"],
            "evidence_ids": sorted(item["evidence_id"] for item in sources),
            "evaluations": [],
            "matches": [],
        }

    matches: list[dict] = []
    used: set[str] = set()
    for item in sources:
        if not item["observation"]["definitive"]:
            continue
        present, value = dk_evidence.read_path(item["observation"]["value"], value_path)
        if not present:
            continue
        names = value if isinstance(value, list) else [value]
        for name in names:
            if not isinstance(name, str) or name in targets:
                continue
            matches.append(
                {
                    "subject": item["subject"],
                    "missing": name,
                    "path": item["scope"].get("path"),
                    "evidence_id": item["evidence_id"],
                }
            )
            used.add(item["evidence_id"])

    matches.sort(key=lambda entry: (entry["subject"], entry["missing"]))
    return {
        "kind": CHECK_CROSS_REFERENCE,
        "truth": dk_applicability.TRUE if matches else dk_applicability.FALSE,
        "reason_codes": (
            ["CROSS_REFERENCE_UNMATCHED"] if matches else ["CROSS_REFERENCE_FULLY_MATCHED"]
        ),
        "evidence_ids": sorted(used),
        "evaluations": [],
        "matches": matches,
    }


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


def evaluate_context(rule: dict, evidence_set: dict) -> dict:
    """Which declared context the evidence can and cannot supply.

    A rule states what it would need to know to be certain. Where that is
    unobservable, the rule is still evaluated and the gap is recorded, which is
    the difference between guidance and an accusation.
    """
    requirements = rule.get("context_requirements") or []
    index = dk_evidence.index(evidence_set)
    satisfied, unsatisfied = [], []
    for requirement in requirements:
        assertion = requirement.get("assertion")
        subject = requirement.get("subject")
        record = index["by_key"].get((assertion, subject)) if assertion and subject else None
        if record is not None and record["observation"]["definitive"]:
            satisfied.append({**requirement, "evidence_id": record["evidence_id"]})
        else:
            unsatisfied.append(requirement)
    return {
        "required": len(requirements),
        "satisfied": satisfied,
        "unsatisfied": unsatisfied,
        "complete": not unsatisfied,
    }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def resolve_state(
    rule: dict,
    check: dict,
    context: dict,
    stale: list[dict],
    scope: dict,
) -> tuple[str, str]:
    """The finding state, resolved conservatively at every step."""
    if scope["applies"] is None:
        return UNKNOWN, "RULE_SCOPE_UNDECIDABLE"
    if scope["applies"] is False:
        return NOT_OBSERVED, "RULE_OUT_OF_SCOPE"
    if stale:
        # The rule's authority moved. Reporting anything from it would be
        # asserting a sentence nobody has re-read.
        return REQUIRES_HUMAN_REVIEW, "RULE_AUTHORITY_SOURCE_CHANGED"
    if check["truth"] == dk_applicability.UNKNOWN:
        return UNKNOWN, (check["reason_codes"] or ["EVIDENCE_INSUFFICIENT"])[0]
    if check["truth"] == dk_applicability.FALSE:
        return NOT_OBSERVED, "RULE_CONDITION_NOT_MET"
    if rule["review"]["status"] not in CONFIRMING_REVIEW_STATES:
        return CANDIDATE, "RULE_NOT_REVIEWED"
    if not context["complete"]:
        return CANDIDATE, "REQUIRED_CONTEXT_NOT_OBSERVED"
    return CONFIRMED, "RULE_CONDITION_MET_WITH_DEFINITIVE_EVIDENCE"


def finding_identity(rule: dict, evidence_set: dict, state: str, occurrences: list[dict]) -> str:
    basis = {
        "rule_id": rule["rule_id"],
        "rule_contract_version": rule["rule_contract_version"],
        "project_fingerprint": evidence_set["project"]["project_fingerprint"],
        "revision_fingerprint": evidence_set["project"]["revision_fingerprint"],
        "state": state,
        "occurrences": occurrences,
    }
    return "implementation-finding." + sha256_text(stable_json(basis))[:16]


def build_finding(
    rule: dict,
    evidence_set: dict,
    scope: dict,
    check: dict,
    context: dict,
    stale: list[dict],
) -> dict:
    state, reason = resolve_state(rule, check, context, stale, scope)
    occurrences = check["matches"]
    finding = rule["finding"]

    limitations = list(finding.get("limitations", []))
    if not context["complete"]:
        for requirement in context["unsatisfied"]:
            limitations.append(requirement["why_it_matters"])
    if stale:
        limitations.append(
            "The authoritative source behind this rule changed after the rule was "
            "reviewed, so nothing is concluded from it until a human re-reads it."
        )
    for record in check["evidence_ids"]:
        pass

    return {
        "finding_contract_version": FINDING_CONTRACT_VERSION,
        "finding_id": finding_identity(rule, evidence_set, state, occurrences),
        "result_domain": RESULT_DOMAIN,
        "rule_id": rule["rule_id"],
        "category": rule["category"],
        "state": state,
        "reason_code": reason,
        "assertion": finding["assertion"],
        "human_title": finding["human_title"],
        "severity": {"state": finding["severity_state"], "source": None},
        # Category never sets enforcement. A security rule is guidance unless a
        # human reviewed it into something stronger.
        "effective_enforcement": (
            finding["enforcement_intent"]
            if rule["review"]["status"] == REVIEW_REVIEWED
            else ENFORCEMENT_ADVISORY
        ),
        "project": {
            "project_fingerprint": evidence_set["project"]["project_fingerprint"],
            "revision_fingerprint": evidence_set["project"]["revision_fingerprint"],
            "core_version": scope["core_version"],
        },
        "evidence": {
            "evidence_set_id": evidence_set["evidence_set_id"],
            "evidence_ids": check["evidence_ids"],
            "check_kind": check["kind"],
            "reason_codes": check["reason_codes"],
            "occurrences": occurrences,
        },
        "context": {
            "required": context["required"],
            "satisfied": [item["assertion"] for item in context["satisfied"]],
            "unsatisfied": [item["assertion"] for item in context["unsatisfied"]],
            "complete": context["complete"],
        },
        "authority": {
            "review_status": rule["review"]["status"],
            "reviewed_on": rule["review"].get("reviewed_on"),
            "sources": [
                {
                    "source_id": reference["source_id"],
                    "snapshot_sha256": reference["snapshot_sha256"],
                    "quotes": list(reference.get("quotes", [])),
                }
                for reference in rule["authority"]["sources"]
            ],
            "stale_sources": stale,
        },
        "explanation": {
            "what_rule": rule["title"],
            "why_it_applies": scope["reason"],
            "what_evidence": finding["evidence_explanation"],
            "evidence_completeness": describe_completeness(check, evidence_set),
            "what_remains_unknown": (
                "; ".join(item["why_it_matters"] for item in context["unsatisfied"])
                or "No declared context requirement is unmet."
            ),
            "authority": rule["authority"]["summary"],
            "conclusion": finding["conclusion"][state]
            if state in finding["conclusion"]
            else finding["conclusion"]["default"],
        },
        "remediation": {
            "guidance": finding["remediation"]["guidance"],
            "basis": finding["remediation"]["basis"],
            "applied": False,
        },
        "limitations": sorted(set(limitations)),
        "execution": {
            "configuration_modified": False,
            "code_modified": False,
            "composer_invoked": False,
            "drupal_state_changed": False,
        },
    }


def describe_completeness(check: dict, evidence_set: dict) -> str:
    if not check["evidence_ids"]:
        return "No evidence record settled this rule."
    by_id = {item["evidence_id"]: item for item in evidence_set["records"]}
    domains = sorted(
        {
            by_id[identifier]["completeness"]["search_domain"]
            for identifier in check["evidence_ids"]
            if identifier in by_id
        }
    )
    return "Evidence search domains: " + ", ".join(domains) if domains else "unknown"


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    evidence_set: dict,
    root: Path = dk_core.ROOT,
    rules: list[dict] | None = None,
    category: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Evaluate reviewed implementation rules against one evidence set."""
    if not isinstance(evidence_set, dict) or evidence_set.get("result_domain") != dk_evidence.RESULT_DOMAIN:
        raise ImplementationInputError("input is not a project evidence set")

    selected = rules if rules is not None else load_rules(root)
    if category:
        if category not in CATEGORIES:
            raise ImplementationInputError(f"unknown category {category!r}")
        selected = [rule for rule in selected if rule["category"] == category]

    registered = {source["id"]: source for source in dk_core.load_sources(root)}
    findings: list[dict] = []
    skipped: list[dict] = []

    for rule in sorted(selected, key=lambda item: item["rule_id"]):
        if rule["review"]["status"] in (REVIEW_DEPRECATED, REVIEW_SUPERSEDED):
            skipped.append(
                {
                    "rule_id": rule["rule_id"],
                    "reason": f"rule is {rule['review']['status']}",
                    "superseded_by": rule["review"].get("superseded_by"),
                }
            )
            continue
        stale = rule_is_stale(root, rule)
        scope = scope_applies(rule, evidence_set)
        if rule["check"]["kind"] == CHECK_CONDITION:
            check = evaluate_condition_check(rule, evidence_set)
        else:
            check = evaluate_cross_reference_check(rule, evidence_set)
        context = evaluate_context(rule, evidence_set)
        findings.append(build_finding(rule, evidence_set, scope, check, context, stale))

    by_state = {state: 0 for state in FINDING_STATES}
    by_category = {name: 0 for name in CATEGORIES}
    for item in findings:
        by_state[item["state"]] += 1
        by_category[item["category"]] += 1

    payload = {
        "schema_version": FINDING_CONTRACT_VERSION,
        "evaluation_id": "implementation-evaluation."
        + sha256_text(
            stable_json(
                {
                    "evidence_set": evidence_set["evidence_set_id"],
                    "findings": [item["finding_id"] for item in findings],
                }
            )
        )[:16],
        "result_domain": RESULT_DOMAIN,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
            "produces_trusted_knowledge": False,
        },
        "generated_at": generated_at or now_iso(),
        "evidence_set": {
            "evidence_set_id": evidence_set["evidence_set_id"],
            "project_fingerprint": evidence_set["project"]["project_fingerprint"],
            "revision_fingerprint": evidence_set["project"]["revision_fingerprint"],
            "records": len(evidence_set["records"]),
        },
        "rules": {
            "evaluated": [item["rule_id"] for item in findings],
            "skipped": skipped,
            "reviewed": sum(
                1 for rule in selected if rule["review"]["status"] == REVIEW_REVIEWED
            ),
            "draft": sum(1 for rule in selected if rule["review"]["status"] == REVIEW_DRAFT),
        },
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "by_state": by_state,
            "by_category": by_category,
            "confirmed": by_state[CONFIRMED],
            "blocking": sum(
                1
                for item in findings
                if item["state"] == CONFIRMED and item["effective_enforcement"] == ENFORCEMENT_BLOCKING
            ),
        },
        "boundaries": {
            "runtime_observed": False,
            "database_inspected": False,
            "statement": (
                "A rule and evidence together produce a finding. Neither an observation "
                "nor a preference produces one alone, and a bounded rule set finding "
                "nothing says nothing about the rest of the project."
            ),
            "advisory_relationship": (
                "These are implementation and configuration findings. Known-vulnerability "
                "applicability is the security advisory engine's domain, not this one."
            ),
            "migration_relationship": (
                "API migration work is its own domain. It does not become a performance, "
                "security or configuration-quality finding without a reviewed rule saying so."
            ),
        },
        "execution": {
            "configuration_modified": False,
            "code_modified": False,
            "composer_invoked": False,
            "drupal_state_changed": False,
        },
        "trusted_knowledge_mutations": {
            "knowledge_records": 0,
            "reviewed_context": 0,
            "source_derived_records": 0,
            "advisories": 0,
            "solved_cases": 0,
            "discovery": 0,
            "implementation_rules": 0,
        },
    }
    validate_evaluation(payload)
    return payload


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def validate_evaluation(payload: dict) -> None:
    required = {
        "schema_version",
        "evaluation_id",
        "result_domain",
        "engine",
        "generated_at",
        "evidence_set",
        "rules",
        "findings",
        "summary",
        "boundaries",
        "execution",
        "trusted_knowledge_mutations",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise ImplementationEngineDefect(
            f"implementation evaluation missing keys: {', '.join(missing)}"
        )
    if payload["result_domain"] != RESULT_DOMAIN:
        raise ImplementationEngineDefect("output must declare the implementation_finding domain")
    for value in payload["execution"].values():
        if value is not False:
            raise ImplementationEngineDefect("the implementation engine never changes a project")
    for count in payload["trusted_knowledge_mutations"].values():
        if count != 0:
            raise ImplementationEngineDefect("the implementation engine never mutates knowledge")
    for item in payload["findings"]:
        if item["state"] not in FINDING_STATES:
            raise ImplementationEngineDefect(f"unknown finding state in {item['finding_id']}")
        if item["state"] in FORBIDDEN_STATE_VALUES:
            raise ImplementationEngineDefect("a finding may not carry a conformance verdict")
        if item["severity"]["state"] != SEVERITY_NOT_ESTABLISHED:
            raise ImplementationEngineDefect(
                f"{item['finding_id']}: severity is not established by this product"
            )
        if item["remediation"]["applied"] is not False:
            raise ImplementationEngineDefect("remediation must never report itself as applied")
        if item["state"] == CONFIRMED:
            if item["authority"]["review_status"] != REVIEW_REVIEWED:
                raise ImplementationEngineDefect(
                    f"{item['finding_id']}: only a reviewed rule may confirm"
                )
            if item["authority"]["stale_sources"]:
                raise ImplementationEngineDefect(
                    f"{item['finding_id']}: a stale rule may not confirm"
                )
            if not item["context"]["complete"]:
                raise ImplementationEngineDefect(
                    f"{item['finding_id']}: confirmation requires the declared context"
                )
        if item["state"] == CONFIRMED and not item["evidence"]["evidence_ids"]:
            raise ImplementationEngineDefect(
                f"{item['finding_id']}: a confirmed finding must name its evidence"
            )


def render(payload: dict, explain: bool = False) -> str:
    lines: list[str] = []
    summary = payload["summary"]
    lines.append(f"IMPLEMENTATION FINDINGS {payload['evaluation_id']}")
    lines.append(f"  result domain      {payload['result_domain']}")
    lines.append(
        f"  evidence set       {payload['evidence_set']['evidence_set_id']} "
        f"({payload['evidence_set']['records']} records)"
    )
    lines.append(f"  revision           {payload['evidence_set']['revision_fingerprint'][:16]}")
    lines.append(
        f"  rules              {len(payload['rules']['evaluated'])} evaluated "
        f"({payload['rules']['reviewed']} reviewed, {payload['rules']['draft']} draft)"
    )
    lines.append("")
    lines.append("BY STATE")
    for state, count in payload["summary"]["by_state"].items():
        if count:
            lines.append(f"  {state:<24} {count}")
    lines.append("BY CATEGORY")
    for name, count in payload["summary"]["by_category"].items():
        lines.append(f"  {name:<24} {count}")
    lines.append("")

    for item in payload["findings"]:
        lines.append(f"Finding    {item['finding_id']}")
        lines.append(f"Rule:      {item['rule_id']}")
        lines.append(f"Category:  {item['category']}")
        lines.append(f"State:     {item['state']} ({item['reason_code']})")
        lines.append(f"Enforcement: {item['effective_enforcement']}   Severity: {item['severity']['state']}")
        lines.append(f"Assertion: {item['assertion']}")
        if item["evidence"]["evidence_ids"]:
            lines.append("Evidence:")
            for identifier in item["evidence"]["evidence_ids"][:6]:
                lines.append(f"  - {identifier}")
            if len(item["evidence"]["evidence_ids"]) > 6:
                lines.append(f"  - ... and {len(item['evidence']['evidence_ids']) - 6} more")
        if item["evidence"]["occurrences"]:
            lines.append("Occurrences:")
            for occurrence in item["evidence"]["occurrences"][:6]:
                lines.append(f"  - {occurrence['subject']} -> {occurrence['missing']}")
        if explain:
            explanation = item["explanation"]
            lines.append(f"Why:       {explanation['why_it_applies']}")
            lines.append(f"Observed:  {explanation['what_evidence']}")
            lines.append(f"Coverage:  {explanation['evidence_completeness']}")
            lines.append(f"Unknown:   {explanation['what_remains_unknown']}")
            lines.append(f"Authority: {explanation['authority']}")
            for reference in item["authority"]["sources"]:
                lines.append(f"  - {reference['source_id']} @ {reference['snapshot_sha256'][:23]}")
            lines.append(f"Conclusion: {explanation['conclusion']}")
            if item["limitations"]:
                lines.append("Limitations:")
                for limitation in item["limitations"]:
                    lines.append(f"  - {limitation}")
            lines.append(f"Recommended action: {item['remediation']['guidance']}")
        lines.append("No project changes were performed.")
        lines.append("")

    lines.append("BOUNDARIES")
    lines.append(f"  {payload['boundaries']['statement']}")
    lines.append(f"  {payload['boundaries']['advisory_relationship']}")
    lines.append(f"  {payload['boundaries']['migration_relationship']}")
    return "\n".join(lines) + "\n"


def validate_implementation_contract(root: Path = dk_core.ROOT) -> list[str]:
    dk_core.read_json(root / "schema" / "implementation-rule.schema.json")
    dk_core.read_json(root / "schema" / "implementation-finding.schema.json")
    registered = {source["id"]: source for source in dk_core.load_sources(root)}
    rules = load_rules(root)
    if not rules:
        raise dk_core.ValidationError("no implementation rules are present")
    seen: set[str] = set()
    for rule in rules:
        validate_rule(rule, registered, root)
        if rule["rule_id"] in seen:
            raise dk_core.ValidationError(f"duplicate implementation rule {rule['rule_id']}")
        seen.add(rule["rule_id"])
    by_category = {name: sum(1 for rule in rules if rule["category"] == name) for name in CATEGORIES}
    for name, count in by_category.items():
        if count == 0:
            raise dk_core.ValidationError(f"category {name} has no implementation rule")
        if count > 6:
            raise dk_core.ValidationError(
                f"category {name} has {count} rules; the initial set is deliberately bounded"
            )
    reviewed = sum(1 for rule in rules if rule["review"]["status"] == REVIEW_REVIEWED)
    return [
        "IMPLEMENTATION_RULE_CONTRACT_VALID=PASS",
        f"IMPLEMENTATION_ENGINE_VERSION={ENGINE_VERSION}",
        f"IMPLEMENTATION_RULES={len(rules)}",
        f"IMPLEMENTATION_RULES_REVIEWED={reviewed}",
        f"IMPLEMENTATION_RULES_PERFORMANCE={by_category[CATEGORY_PERFORMANCE]}",
        f"IMPLEMENTATION_RULES_SECURITY={by_category[CATEGORY_SECURITY]}",
        f"IMPLEMENTATION_RULES_CONFIGURATION_QUALITY={by_category[CATEGORY_CONFIGURATION_QUALITY]}",
        "IMPLEMENTATION_RULE_AUTHORITY_EXPLICIT=PASS",
        "IMPLEMENTATION_FINDING_SEVERITY_NOT_SPECULATED=PASS",
        "IMPLEMENTATION_REMEDIATION_READ_ONLY=PASS",
    ]
