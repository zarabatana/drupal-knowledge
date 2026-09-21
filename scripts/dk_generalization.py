#!/usr/bin/env python3
"""Recurrence and generalization over internal-proven solved cases.

This module answers one narrow question: has Drupal Knowledge now seen the same
proven problem, cause and fix in more than one independent place, and if so
what would a reusable rule look like for a human to judge?

The boundaries it exists to defend:

    RECURRENCE != GENERALIZATION != TRUSTED KNOWLEDGE

Recurrence is a count of proven occurrences in named contexts. A generalization
proposal is a question put to a reviewer. Neither is Drupal truth, and nothing
here may write into ``knowledge/``.

Two things it deliberately refuses to do. It never groups cases on description
similarity - grouping is exact structural identity over normalized root cause,
fix category, fix summaries and affected components. And it never treats an
occurrence count as proof: confidence is a conjunction of independence,
verification quality, agreement and the absence of contradiction, and every
factor is reported so a reviewer can disagree with it.
"""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_core
import dk_solved_case


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------

RECURRENCE_ENGINE_NAME = "drupal-knowledge-recurrence-engine"
GENERALIZATION_ENGINE_NAME = "drupal-knowledge-generalization-engine"
ENGINE_VERSION = "0.1"
ANALYSIS_CONTRACT_VERSION = "0.1"
PROPOSAL_CONTRACT_VERSION = "0.1"
RUN_SCHEMA_VERSION = "0.1"

# Solved cases are their own provenance channel. Discovery signals and
# authoritative snapshots are different channels and are never counted here.
EVIDENCE_CHANNEL = "internal_proven_solved_case"
CASE_SOURCE = "cases/solved"

RECURRENCE_RELATIVE_PATH = Path("cases") / "recurrence"
PROPOSAL_RELATIVE_PATH = Path("cases") / "generalizations"

RECURRENCE_ID_RE = re.compile(r"^recurrence\.drupal\.[a-z0-9.-]+$")
PROPOSAL_ID_RE = re.compile(r"^generalization\.drupal\.[a-z0-9.-]+$")


# ---------------------------------------------------------------------------
# Case eligibility
# ---------------------------------------------------------------------------

# A case whose lifecycle has moved past verification is still verified
# evidence. A captured, rejected or retired case is not.
INELIGIBLE_STATUSES = frozenset({"captured", "rejected", "retired"})

CAUSALITY_RANK = {"demonstrated": 2, "consistent_with_evidence": 1, "not_established": 0}
ROOT_CAUSE_RANK = {"confirmed": 2, "evidenced": 1, "unknown": 0}

EXCLUDED_NOT_VERIFIED = "not_verified"
EXCLUDED_DUPLICATE = "duplicate_occurrence"
EXCLUDED_KEY_MISMATCH = "structural_key_mismatch"
EXCLUDED_NO_COMPONENT = "no_component_overlap"

GRADE_STRONG = "strong"
GRADE_MODERATE = "moderate"
GRADE_WEAK = "weak"

CONFIDENCE_INSUFFICIENT = "insufficient"
CONFIDENCE_WEAK = "weak"
CONFIDENCE_MODERATE = "moderate"
CONFIDENCE_STRONG = "strong"

REVIEW_PENDING = "pending_review"
REVIEW_NEEDS_MORE_EVIDENCE = "needs_more_evidence"
REVIEW_ACCEPTED = "accepted_for_knowledge_proposal"
REVIEW_REJECTED = "rejected"
REVIEW_NARROW_SCOPE = "narrow_scope_required"

REVIEW_STATES = (
    REVIEW_PENDING,
    REVIEW_NEEDS_MORE_EVIDENCE,
    REVIEW_ACCEPTED,
    REVIEW_REJECTED,
    REVIEW_NARROW_SCOPE,
)

REVIEW_OUTCOMES = (
    REVIEW_NEEDS_MORE_EVIDENCE,
    REVIEW_ACCEPTED,
    REVIEW_REJECTED,
    REVIEW_NARROW_SCOPE,
)

# Only this outcome authorises later, explicit knowledge-proposal work, and it
# still creates nothing.
REVIEW_AUTHORIZING_OUTCOMES = frozenset({REVIEW_ACCEPTED})

REVIEW_METHODS = frozenset(
    {"human_generalization_review", "human_editorial_review", "human_security_review"}
)

# A generalization needs corroboration from more than one independent place.
MINIMUM_INDEPENDENT_OCCURRENCES = 2


class GeneralizationInputError(RuntimeError):
    """Caller asked for something the case tree does not describe."""


class GeneralizationEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as an evidence problem."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def now_iso(moment: datetime | None = None) -> str:
    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def digest(*parts: Any) -> str:
    accumulator = hashlib.sha256()
    for part in parts:
        accumulator.update(str(part).encode("utf-8"))
        accumulator.update(b"\0")
    return "sha256:" + accumulator.hexdigest()


WHITESPACE_RE = re.compile(r"\s+")


def normalize_statement(value: Any) -> str:
    """Normalize a statement for *exact* comparison.

    This is deliberately not similarity matching. Case, surrounding whitespace,
    internal whitespace runs and a trailing full stop are the only things
    collapsed; anything else that differs makes two statements different.
    """
    if not isinstance(value, str):
        return ""
    collapsed = WHITESPACE_RE.sub(" ", value).strip().lower()
    return collapsed.rstrip(".").strip()


def component_names(case: dict) -> list[str]:
    """Package names of the modules and themes a case names."""
    names: set[str] = set()
    for entry in list(case.get("modules") or []) + list(case.get("themes") or []):
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name:
                names.add(name)
        elif isinstance(entry, str) and entry:
            names.add(entry)
    return sorted(names)


def component_versions(cases: Iterable[dict]) -> dict[str, list[str]]:
    observed: dict[str, set[str]] = {}
    for case in cases:
        for entry in list(case.get("modules") or []) + list(case.get("themes") or []):
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if isinstance(name, str) and name:
                observed.setdefault(name, set())
                if isinstance(version, str) and version:
                    observed[name].add(version)
    return {name: sorted(values) for name, values in sorted(observed.items())}


MAJOR_RE = re.compile(r"^(\d+)")


def major_of(version: Any) -> str | None:
    if not isinstance(version, str):
        return None
    match = MAJOR_RE.match(version.strip())
    return match.group(1) if match else None


def majors(versions: Iterable[Any]) -> list[str]:
    found = {major_of(value) for value in versions}
    return sorted(value for value in found if value)


def case_verification(case: dict) -> dict:
    return (case.get("capture") or {}).get("verification") or {}


def verification_results(case: dict) -> list[dict]:
    results = case_verification(case).get("results")
    return [item for item in results if isinstance(item, dict)] if isinstance(results, list) else []


def causality_state(case: dict) -> str:
    causality = case_verification(case).get("causality") or {}
    state = causality.get("state")
    return state if isinstance(state, str) else "not_established"


def root_cause_state(case: dict) -> str:
    state = (case.get("capture") or {}).get("root_cause_state")
    return state if isinstance(state, str) else "unknown"


def case_is_verified(case: dict) -> bool:
    """Structural verification gate, independent of the status label.

    A case earns recurrence standing by carrying verification evidence, not by
    being labelled. This is the same bar solved-case capture applies to reach
    ``verified``: verification was performed, at least one result actually
    passed, and the case says what its evidence demonstrates about causality.
    """
    if case.get("status") in INELIGIBLE_STATUSES:
        return False
    verification = case_verification(case)
    if verification.get("performed") is not True:
        return False
    if not any(item.get("outcome") == "passed" for item in verification_results(case)):
        return False
    return bool(verification.get("causality"))


def case_is_contradictory(case: dict) -> bool:
    """A verified case whose own evidence records a failure.

    Under otherwise matching conditions this is important evidence that the
    rule does not hold universally, so it is surfaced rather than dropped.
    """
    return any(item.get("outcome") == "failed" for item in verification_results(case))


def verification_summary(case: dict) -> str:
    results = verification_results(case)
    outcomes: dict[str, int] = {}
    for item in results:
        outcome = str(item.get("outcome"))
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    parts = [f"{count} {name}" for name, count in sorted(outcomes.items())]
    return (
        f"causality={causality_state(case)}; root_cause={root_cause_state(case)}; "
        + (", ".join(parts) if parts else "no results")
    )


def project_fingerprint(case: dict) -> str:
    return ((case.get("environment") or {}).get("project_fingerprint")) or ""


def revision_fingerprint(case: dict) -> str | None:
    return (case.get("environment") or {}).get("revision_fingerprint")


def load_cases(root: Path = dk_core.ROOT) -> list[dict]:
    """Load solved cases. This is the only evidence source this engine reads."""
    return sorted(dk_core.load_solved_cases(root), key=lambda case: case.get("id", ""))


# ---------------------------------------------------------------------------
# Structural identity
#
# Two cases join the same recurrence group only if their normalized root cause,
# fix category, fix summaries and affected components are identical. Similar
# titles, overlapping symptom wording and a shared module name are not enough
# on their own, and none of them appear in the key.
# ---------------------------------------------------------------------------


def structural_key(case: dict) -> dict:
    root_cause_digest = digest(normalize_statement(case.get("root_cause")))
    fix_category = (case.get("capture") or {}).get("fix_category") or "unspecified"
    fix_summaries = sorted(
        normalize_statement(item) for item in (case.get("solution") or []) if isinstance(item, str)
    )
    fix_digest = digest(*fix_summaries)
    components = component_names(case)
    return {
        "digest": digest(root_cause_digest, fix_category, fix_digest, ",".join(components)),
        "root_cause_digest": root_cause_digest,
        "fix_category": fix_category,
        "fix_digest": fix_digest,
        "components": components,
        "method": "normalized_structural_identity",
    }


def group_by_structure(cases: Iterable[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for case in cases:
        groups.setdefault(structural_key(case)["digest"], []).append(case)
    return {
        key: sorted(members, key=lambda case: case.get("id", ""))
        for key, members in sorted(groups.items())
    }


# ---------------------------------------------------------------------------
# Independence
#
# One independent occurrence per distinct project fingerprint. Recapturing the
# same project, and the same project at a different revision, are additional
# evidence about one place - not a second place.
# ---------------------------------------------------------------------------


def independence(cases: list[dict]) -> tuple[dict, set[str]]:
    """Count independent occurrences and report which cases carry them."""
    seen: dict[str, str] = {}
    revisions: set[tuple[str, str | None]] = set()
    independent_case_ids: set[str] = set()
    duplicates = 0

    for case in cases:
        fingerprint = project_fingerprint(case)
        revisions.add((fingerprint, revision_fingerprint(case)))
        if fingerprint in seen:
            duplicates += 1
            continue
        seen[fingerprint] = case.get("id", "")
        independent_case_ids.add(case.get("id", ""))

    assessment = {
        "count": len(seen),
        "project_fingerprints": sorted(seen),
        "duplicate_capture_count": duplicates,
        "revision_count": len(revisions),
        "method": "distinct_project_fingerprint",
    }
    return assessment, independent_case_ids


# ---------------------------------------------------------------------------
# Observed scope and conflicts
# ---------------------------------------------------------------------------


def observed_scope(cases: list[dict]) -> dict:
    core_versions: set[str] = set()
    php_versions: set[str] = set()
    environments: set[str] = set()
    for case in cases:
        core_versions.update(value for value in (case.get("drupal_versions") or []) if isinstance(value, str))
        php_versions.update(value for value in (case.get("php_versions") or []) if isinstance(value, str))
        environment = (case.get("environment") or {}).get("environment_class")
        if isinstance(environment, str) and environment:
            environments.add(environment)
    return {
        "drupal_core_versions": sorted(core_versions),
        "drupal_core_majors": majors(core_versions),
        "php_versions": sorted(php_versions),
        "component_versions": component_versions(cases),
        "environment_classes": sorted(environments),
        "explicitly_evidenced": bool(core_versions or php_versions),
    }


def applicability_conflicts(cases: list[dict]) -> list[dict]:
    """Report scopes that align structurally but do not reconcile.

    A conflict does not merge away and does not widen: it constrains what any
    proposal built on these cases may claim.
    """
    conflicts: list[dict] = []
    case_ids = sorted(case.get("id", "") for case in cases)

    core_majors = majors(
        value for case in cases for value in (case.get("drupal_versions") or [])
    )
    if len(core_majors) > 1:
        conflicts.append(
            {
                "kind": "incompatible_drupal_major",
                "detail": (
                    "Participating cases were proven on more than one Drupal core major "
                    f"({', '.join(core_majors)}); evidence from one major does not carry "
                    "to another."
                ),
                "case_ids": case_ids,
            }
        )

    for name, versions in component_versions(cases).items():
        component_majors = majors(versions)
        if len(component_majors) > 1:
            conflicts.append(
                {
                    "kind": "incompatible_component_major",
                    "detail": (
                        f"Component {name} appears on more than one major line "
                        f"({', '.join(component_majors)}); a shared name is not a shared scope."
                    ),
                    "case_ids": case_ids,
                }
            )

    php_majors = majors(
        value for case in cases for value in (case.get("php_versions") or [])
    )
    if len(php_majors) > 1:
        conflicts.append(
            {
                "kind": "incompatible_php_major",
                "detail": (
                    f"Participating cases span PHP majors {', '.join(php_majors)}."
                ),
                "case_ids": case_ids,
            }
        )

    environments = {
        (case.get("environment") or {}).get("environment_class")
        for case in cases
    }
    environments.discard(None)
    if len(environments) > 1:
        conflicts.append(
            {
                "kind": "unreconciled_environment",
                "detail": (
                    "Participating cases were proven in different environment classes "
                    f"({', '.join(sorted(str(item) for item in environments))})."
                ),
                "case_ids": case_ids,
            }
        )

    return conflicts


def verification_quality(cases: list[dict]) -> dict:
    """Grade the evidence behind a group, deterministically."""
    passed = failed = inconclusive = 0
    methods: set[str] = set()
    causality: set[str] = set()
    root_causes: set[str] = set()

    for case in cases:
        for item in verification_results(case):
            outcome = item.get("outcome")
            if outcome == "passed":
                passed += 1
            elif outcome == "failed":
                failed += 1
            elif outcome == "inconclusive":
                inconclusive += 1
            method = item.get("method")
            if isinstance(method, str):
                methods.add(method)
        causality.add(causality_state(case))
        root_causes.add(root_cause_state(case))

    weakest_causality = min(CAUSALITY_RANK.get(state, 0) for state in causality) if causality else 0
    weakest_root_cause = min(ROOT_CAUSE_RANK.get(state, 0) for state in root_causes) if root_causes else 0

    if failed:
        grade = GRADE_WEAK
    elif weakest_causality == 2 and weakest_root_cause == 2 and len(methods) > 1:
        grade = GRADE_STRONG
    elif weakest_causality >= 1 and weakest_root_cause >= 1:
        grade = GRADE_MODERATE
    else:
        grade = GRADE_WEAK

    return {
        "grade": grade,
        "causality_states": sorted(causality),
        "root_cause_states": sorted(root_causes),
        "passed_result_count": passed,
        "failed_result_count": failed,
        "inconclusive_result_count": inconclusive,
        "methods": sorted(methods),
    }


# ---------------------------------------------------------------------------
# Recurrence analysis
# ---------------------------------------------------------------------------


def recurrence_identity(structural_digest: str) -> str:
    return f"recurrence.drupal.{structural_digest.removeprefix('sha256:')[:16]}"


def recurrence_path(root: Path, identity: str) -> Path:
    if not RECURRENCE_ID_RE.fullmatch(identity):
        raise GeneralizationInputError(f"invalid recurrence id: {identity!r}")
    return root / RECURRENCE_RELATIVE_PATH / f"{identity}.json"


def load_analysis(root: Path, identity: str) -> dict:
    path = recurrence_path(root, identity)
    if not path.is_file():
        raise GeneralizationInputError(f"unknown recurrence analysis: {identity}")
    return dk_core.read_json(path)


def iter_analyses(root: Path) -> list[dict]:
    directory = root / RECURRENCE_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def occurrence_entry(case: dict, *, counts_as_independent: bool) -> dict:
    return {
        "case_id": case.get("id", ""),
        # Fingerprints only. A project's name, domain and paths never reach here.
        "project_fingerprint": project_fingerprint(case),
        "revision_fingerprint": revision_fingerprint(case),
        "status": case.get("status", "unknown"),
        "drupal_core_versions": sorted(
            value for value in (case.get("drupal_versions") or []) if isinstance(value, str)
        ),
        "verification_summary": verification_summary(case),
        "counts_as_independent": counts_as_independent,
    }


def build_analysis(
    key: dict,
    eligible: list[dict],
    ineligible: list[dict],
    *,
    stamp: str,
    run_id: str,
) -> dict:
    """Assemble the recurrence analysis for one structural group."""
    supporting = [case for case in eligible if not case_is_contradictory(case)]
    contradictory = [case for case in eligible if case_is_contradictory(case)]

    assessment, independent_ids = independence(eligible)
    scope = observed_scope(eligible)
    conflicts = applicability_conflicts(eligible)
    quality = verification_quality(eligible)

    excluded = [
        {
            "case_id": case.get("id", ""),
            "reason": EXCLUDED_NOT_VERIFIED,
            "detail": (
                "Case does not carry verification evidence that passed with a stated "
                "causality, so it cannot contribute recurrence evidence."
            ),
        }
        for case in ineligible
    ]
    excluded.extend(
        {
            "case_id": case.get("id", ""),
            "reason": EXCLUDED_DUPLICATE,
            "detail": (
                "Another case already carries this project fingerprint, so this capture "
                "is further evidence about one place rather than a second place."
            ),
        }
        for case in eligible
        if case.get("id", "") not in independent_ids
    )

    limitations = [
        "Recurrence is evidence that a proven fix held in named contexts. It is not a "
        "generalization and it is not trusted Drupal knowledge.",
        "Occurrences are counted per distinct project fingerprint; repeat captures and "
        "additional revisions of one project do not raise the count.",
    ]
    if contradictory:
        limitations.append(
            "At least one participating case records a failed verification result under "
            "otherwise matching conditions."
        )
    if conflicts:
        limitations.append(
            "Participating cases do not share a single reconciled scope; see "
            "applicability_conflicts."
        )
    if assessment["count"] < MINIMUM_INDEPENDENT_OCCURRENCES:
        limitations.append(
            "Fewer than two independent occurrences: this is a single proven context."
        )

    return {
        "id": recurrence_identity(key["digest"]),
        "analysis_contract_version": ANALYSIS_CONTRACT_VERSION,
        "engine": {
            "name": RECURRENCE_ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "built_at": stamp,
        "run_id": run_id,
        "structural_key": key,
        "case_ids": sorted(case.get("id", "") for case in eligible),
        "supporting_cases": [
            occurrence_entry(case, counts_as_independent=case.get("id", "") in independent_ids)
            for case in sorted(supporting, key=lambda item: item.get("id", ""))
        ],
        "contradictory_cases": [
            occurrence_entry(case, counts_as_independent=case.get("id", "") in independent_ids)
            for case in sorted(contradictory, key=lambda item: item.get("id", ""))
        ],
        "excluded_cases": sorted(excluded, key=lambda item: (item["reason"], item["case_id"])),
        "independent_occurrences": assessment,
        "shared_dimensions": {
            # Guaranteed by the structural key, and stated so a reviewer can see
            # which dimensions actually agreed.
            "problem_aligned": True,
            "root_cause_aligned": True,
            "fix_aligned": True,
            "components_aligned": True,
            "dimensions": [
                "normalized_root_cause",
                "fix_category",
                "normalized_fix_summaries",
                "affected_components",
            ],
        },
        "observed_scope": scope,
        "applicability_conflicts": conflicts,
        "verification_quality": quality,
        "limitations": limitations,
        "provenance": {
            "evidence_channel": EVIDENCE_CHANNEL,
            "case_source": CASE_SOURCE,
            "project_identity_exposed": False,
            "discovery_signals_counted": 0,
        },
        "is_trusted_knowledge": False,
        "is_generalization": False,
        "review_required": True,
    }


def validate_analysis(analysis: dict) -> None:
    context = f"recurrence {analysis.get('id', '<unknown>')}"
    required = {
        "id",
        "analysis_contract_version",
        "engine",
        "built_at",
        "run_id",
        "structural_key",
        "case_ids",
        "supporting_cases",
        "contradictory_cases",
        "excluded_cases",
        "independent_occurrences",
        "shared_dimensions",
        "observed_scope",
        "applicability_conflicts",
        "verification_quality",
        "limitations",
        "provenance",
        "is_trusted_knowledge",
        "is_generalization",
        "review_required",
    }
    dk_core.assert_keys(analysis, required, context)
    if not RECURRENCE_ID_RE.fullmatch(analysis["id"]):
        raise dk_core.ValidationError(f"{context}: invalid recurrence id")

    engine = analysis["engine"]
    if engine.get("name") != RECURRENCE_ENGINE_NAME:
        raise dk_core.ValidationError(f"{context}: unexpected engine name")
    if engine.get("deterministic") is not True:
        raise dk_core.ValidationError(f"{context}: recurrence must be deterministic")
    if engine.get("language_model_used") is not False:
        raise dk_core.ValidationError(f"{context}: no language model may derive recurrence")

    # Recurrence may never describe itself as generalization or as knowledge.
    if analysis["is_trusted_knowledge"] is not False:
        raise dk_core.ValidationError(f"{context}: is_trusted_knowledge must be false")
    if analysis["is_generalization"] is not False:
        raise dk_core.ValidationError(f"{context}: is_generalization must be false")
    if analysis["review_required"] is not True:
        raise dk_core.ValidationError(f"{context}: review_required must be true")

    if analysis["structural_key"].get("method") != "normalized_structural_identity":
        raise dk_core.ValidationError(f"{context}: grouping must be structural")
    if analysis["independent_occurrences"].get("method") != "distinct_project_fingerprint":
        raise dk_core.ValidationError(f"{context}: independence method is not conservative")
    if analysis["verification_quality"].get("grade") not in (
        GRADE_STRONG,
        GRADE_MODERATE,
        GRADE_WEAK,
    ):
        raise dk_core.ValidationError(f"{context}: invalid verification grade")

    provenance = analysis["provenance"]
    if provenance.get("evidence_channel") != EVIDENCE_CHANNEL:
        raise dk_core.ValidationError(f"{context}: evidence channel must stay distinct")
    if provenance.get("discovery_signals_counted") != 0:
        raise dk_core.ValidationError(
            f"{context}: discovery signals may never count as solved-case recurrence"
        )
    if provenance.get("project_identity_exposed") is not False:
        raise dk_core.ValidationError(f"{context}: project identity must stay minimized")

    assert_identity_minimized(analysis, context)


PROJECT_IDENTITY_FORBIDDEN_KEYS = (
    "project_name",
    "project_path",
    "site_name",
    "domain",
    "hostname",
    "customer",
    "client",
    "url",
    "email",
)


def assert_identity_minimized(payload: dict, context: str) -> None:
    """Recurrence and proposal artifacts carry fingerprints, never identities.

    The rule protects the *analysed project's* identity, not the reviewer's. A
    review actor is deliberately a person, recorded the same way the rest of the
    repository records review authority, so it is exempt from the contact-detail
    check while still being screened for paths and secrets.
    """
    for key in recursive_keys(payload):
        lowered = key.lower()
        for forbidden in PROJECT_IDENTITY_FORBIDDEN_KEYS:
            if forbidden in lowered:
                raise dk_core.ValidationError(
                    f"{context}: field {key!r} risks exposing project identity"
                )

    review = payload.get("review")
    actor = review.get("actor") if isinstance(review, dict) else None

    for value in dk_solved_case.recursive_strings(payload):
        if dk_solved_case.MACHINE_PATH_RE.search(value):
            raise dk_core.ValidationError(f"{context}: local machine path in artifact")
        if value == actor:
            continue
        if dk_solved_case.EMAIL_RE.search(value):
            raise dk_core.ValidationError(f"{context}: email address in artifact")

    # Screen with the actor masked, for the same reason: a named reviewer is
    # review authority, not leaked project data.
    scanned = payload
    if actor:
        scanned = copy.deepcopy(payload)
        scanned["review"]["actor"] = "<reviewer>"
    findings = dk_solved_case.screen_for_secrets(scanned)
    if findings:
        kinds = sorted({finding["kind"] for finding in findings})
        raise dk_core.ValidationError(
            f"{context}: material that must not be stored: {', '.join(kinds)}"
        )


def recursive_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            keys.add(str(key))
            keys |= recursive_keys(item)
    elif isinstance(value, list):
        for item in value:
            keys |= recursive_keys(item)
    return keys


MATERIAL_ANALYSIS_KEYS = (
    "structural_key",
    "case_ids",
    "supporting_cases",
    "contradictory_cases",
    "excluded_cases",
    "independent_occurrences",
    "observed_scope",
    "applicability_conflicts",
    "verification_quality",
    "limitations",
)


def write_analysis(root: Path, analysis: dict) -> tuple[Path, str]:
    """Persist an analysis idempotently: unchanged evidence rewrites nothing."""
    validate_analysis(analysis)
    path = recurrence_path(root, analysis["id"])
    if path.is_file():
        existing = dk_core.read_json(path)
        if all(existing.get(key) == analysis.get(key) for key in MATERIAL_ANALYSIS_KEYS):
            return path, "reused"
        merged = dict(existing)
        for key in MATERIAL_ANALYSIS_KEYS:
            merged[key] = analysis[key]
        merged["built_at"] = analysis["built_at"]
        merged["run_id"] = analysis["run_id"]
        validate_analysis(merged)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stable_json(merged), encoding="utf-8")
        return path, "updated"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(analysis), encoding="utf-8")
    return path, "created"


# ---------------------------------------------------------------------------
# Generalization proposal
#
# Confidence is a conjunction. An occurrence count on its own never produces a
# grade, and every factor that fed the grade is reported so a reviewer can
# disagree with it on the evidence rather than on the number.
# ---------------------------------------------------------------------------


def evidence_confidence(analysis: dict) -> dict:
    independent = analysis["independent_occurrences"]["count"]
    quality = analysis["verification_quality"]["grade"]
    contradiction = bool(analysis["contradictory_cases"])
    scope_conflict = bool(analysis["applicability_conflicts"])

    factors = [
        f"independent_occurrences={independent}",
        f"verification_quality={quality}",
        f"contradiction_present={contradiction}",
        f"scope_conflict_present={scope_conflict}",
        f"root_cause_and_fix_agreement={analysis['shared_dimensions']['root_cause_aligned']}",
    ]

    if independent < MINIMUM_INDEPENDENT_OCCURRENCES:
        grade = CONFIDENCE_INSUFFICIENT
        factors.append(
            "a single independent occurrence cannot support a generalization however "
            "many times it was captured"
        )
    elif contradiction:
        grade = CONFIDENCE_WEAK
        factors.append("contradictory verified evidence caps confidence")
    elif scope_conflict:
        grade = CONFIDENCE_WEAK
        factors.append("unreconciled scope caps confidence until it is narrowed")
    elif quality == GRADE_STRONG:
        grade = CONFIDENCE_STRONG
    elif quality == GRADE_MODERATE:
        grade = CONFIDENCE_MODERATE
    else:
        grade = CONFIDENCE_WEAK

    return {
        "grade": grade,
        "independent_occurrence_count": independent,
        "verification_grade": quality,
        "contradiction_present": contradiction,
        "scope_conflict_present": scope_conflict,
        "factors": factors,
        # Stated in the artifact so no consumer can read the count as proof.
        "count_alone_is_sufficient": False,
    }


def eligibility(analysis: dict, cases: list[dict]) -> dict:
    independent = analysis["independent_occurrences"]["count"]
    quality = analysis["verification_quality"]["grade"]
    contradiction = bool(analysis["contradictory_cases"])
    scope_conflict = bool(analysis["applicability_conflicts"])

    conditions = {
        "all_participating_cases_verified": all(case_is_verified(case) for case in cases),
        "independent_occurrences_at_least_two": independent >= MINIMUM_INDEPENDENT_OCCURRENCES,
        "root_cause_agreement": analysis["shared_dimensions"]["root_cause_aligned"],
        "fix_agreement": analysis["shared_dimensions"]["fix_aligned"],
        "component_agreement": analysis["shared_dimensions"]["components_aligned"],
        "no_contradictory_case": not contradiction,
        "no_unreconciled_scope_conflict": not scope_conflict,
        "verification_quality_at_least_moderate": quality in (GRADE_STRONG, GRADE_MODERATE),
    }
    unmet = sorted(name for name, met in conditions.items() if not met)

    if contradiction:
        recommended = REVIEW_NEEDS_MORE_EVIDENCE
    elif scope_conflict:
        recommended = REVIEW_NARROW_SCOPE
    elif unmet:
        recommended = REVIEW_NEEDS_MORE_EVIDENCE
    else:
        recommended = REVIEW_PENDING

    return {
        "all_conditions": conditions,
        "unmet_conditions": unmet,
        "recommended_review_state": recommended,
    }


def proposal_identity(analysis_id: str) -> str:
    return f"generalization.drupal.{digest(analysis_id).removeprefix('sha256:')[:16]}"


def proposal_path(root: Path, identity: str) -> Path:
    if not PROPOSAL_ID_RE.fullmatch(identity):
        raise GeneralizationInputError(f"invalid generalization proposal id: {identity!r}")
    return root / PROPOSAL_RELATIVE_PATH / f"{identity}.json"


def load_proposal(root: Path, identity: str) -> dict:
    path = proposal_path(root, identity)
    if not path.is_file():
        raise GeneralizationInputError(f"unknown generalization proposal: {identity}")
    return dk_core.read_json(path)


def iter_proposals(root: Path) -> list[dict]:
    directory = root / PROPOSAL_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def build_proposal(analysis: dict, cases: list[dict], *, stamp: str, run_id: str) -> dict:
    """Assemble a proposal from the participating cases' own fields."""
    scope = analysis["observed_scope"]
    representative = cases[0]
    fix_summaries = sorted(
        {
            item
            for case in cases
            for item in (case.get("solution") or [])
            if isinstance(item, str) and item
        }
    )
    components = analysis["structural_key"]["components"]

    summary = (
        f"Across {analysis['independent_occurrences']['count']} independent verified "
        f"occurrence(s) affecting {', '.join(components) or 'unnamed components'}, the same "
        f"root cause was resolved by the same fix on Drupal core "
        f"{', '.join(scope['drupal_core_versions']) or 'unstated versions'}."
    )

    limitations = list(analysis["limitations"])
    limitations.append(
        "This proposal restates what the participating cases proved. It is not a Drupal "
        "rule until a human reviews it and separate proposal work is carried out."
    )
    for conflict in analysis["applicability_conflicts"]:
        limitations.append(f"Scope conflict ({conflict['kind']}): {conflict['detail']}")

    confidence = evidence_confidence(analysis)
    eligible = eligibility(analysis, cases)

    return {
        "id": proposal_identity(analysis["id"]),
        "proposal_contract_version": PROPOSAL_CONTRACT_VERSION,
        "engine": {
            "name": GENERALIZATION_ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "built_at": stamp,
        "run_id": run_id,
        "recurrence_analysis_id": analysis["id"],
        "structural_key_digest": analysis["structural_key"]["digest"],
        "supporting_case_ids": [item["case_id"] for item in analysis["supporting_cases"]],
        "contradictory_case_ids": [item["case_id"] for item in analysis["contradictory_cases"]],
        "proposed_statement": {
            "summary": summary,
            "root_cause": representative.get("root_cause", ""),
            "fix_summaries": fix_summaries,
            "assembled_from": "participating_solved_case_fields",
            "asserts_universal_truth": False,
        },
        "proposed_applicability": {
            # Bounded by observation. Widening is a reviewer's decision, and the
            # artifact says so rather than leaving it to convention.
            "claimed_scope": "observed_cases_only",
            "drupal_core_versions": scope["drupal_core_versions"],
            "drupal_core_majors": scope["drupal_core_majors"],
            "component_versions": scope["component_versions"],
            "php_versions": scope["php_versions"],
            "environment_classes": scope["environment_classes"],
            "expansion_requires_review": True,
            "bounded_by_observed_cases": True,
        },
        "proposed_limitations": limitations,
        "evidence_confidence": confidence,
        "eligibility": eligible,
        "provenance": {
            "evidence_channel": EVIDENCE_CHANNEL,
            "case_source": CASE_SOURCE,
            "project_identity_exposed": False,
            "discovery_signals_counted": 0,
            # Authoritative evidence may be attached by a reviewer. It never
            # rewrites the solved-case history the proposal rests on.
            "authoritative_support": [],
        },
        "review_required": True,
        "review_state": REVIEW_PENDING,
        "review": None,
        "is_trusted_knowledge": False,
        "is_knowledge_record": False,
        "generalizes_automatically": False,
        "can_promote_to_knowledge": False,
    }


def validate_proposal(proposal: dict) -> None:
    context = f"generalization {proposal.get('id', '<unknown>')}"
    required = {
        "id",
        "proposal_contract_version",
        "engine",
        "built_at",
        "run_id",
        "recurrence_analysis_id",
        "structural_key_digest",
        "supporting_case_ids",
        "contradictory_case_ids",
        "proposed_statement",
        "proposed_applicability",
        "proposed_limitations",
        "evidence_confidence",
        "eligibility",
        "provenance",
        "review_required",
        "review_state",
        "review",
        "is_trusted_knowledge",
        "is_knowledge_record",
        "generalizes_automatically",
        "can_promote_to_knowledge",
    }
    dk_core.assert_keys(proposal, required, context)
    if not PROPOSAL_ID_RE.fullmatch(proposal["id"]):
        raise dk_core.ValidationError(f"{context}: invalid proposal id")
    if not RECURRENCE_ID_RE.fullmatch(proposal["recurrence_analysis_id"]):
        raise dk_core.ValidationError(f"{context}: invalid recurrence reference")
    if proposal["review_state"] not in REVIEW_STATES:
        raise dk_core.ValidationError(f"{context}: invalid review state")

    engine = proposal["engine"]
    if engine.get("name") != GENERALIZATION_ENGINE_NAME:
        raise dk_core.ValidationError(f"{context}: unexpected engine name")
    if engine.get("deterministic") is not True:
        raise dk_core.ValidationError(f"{context}: generalization must be deterministic")
    if engine.get("language_model_used") is not False:
        raise dk_core.ValidationError(f"{context}: no language model may author a proposal")

    # A proposal is structurally incapable of describing itself as knowledge.
    if proposal["review_required"] is not True:
        raise dk_core.ValidationError(f"{context}: review_required must be true")
    for flag in (
        "is_trusted_knowledge",
        "is_knowledge_record",
        "generalizes_automatically",
        "can_promote_to_knowledge",
    ):
        if proposal[flag] is not False:
            raise dk_core.ValidationError(f"{context}: {flag} must be false")

    statement = proposal["proposed_statement"]
    if statement.get("asserts_universal_truth") is not False:
        raise dk_core.ValidationError(f"{context}: a proposal may not assert universal truth")
    if statement.get("assembled_from") != "participating_solved_case_fields":
        raise dk_core.ValidationError(f"{context}: statement must come from the cases")

    applicability = proposal["proposed_applicability"]
    if applicability.get("claimed_scope") != "observed_cases_only":
        raise dk_core.ValidationError(f"{context}: scope must stay bounded by observation")
    if applicability.get("expansion_requires_review") is not True:
        raise dk_core.ValidationError(f"{context}: expansion must require review")
    if applicability.get("bounded_by_observed_cases") is not True:
        raise dk_core.ValidationError(f"{context}: scope must be bounded by observed cases")

    confidence = proposal["evidence_confidence"]
    if confidence.get("count_alone_is_sufficient") is not False:
        raise dk_core.ValidationError(
            f"{context}: an occurrence count may never be sufficient on its own"
        )
    if confidence.get("grade") not in (
        CONFIDENCE_INSUFFICIENT,
        CONFIDENCE_WEAK,
        CONFIDENCE_MODERATE,
        CONFIDENCE_STRONG,
    ):
        raise dk_core.ValidationError(f"{context}: invalid confidence grade")

    provenance = proposal["provenance"]
    if provenance.get("evidence_channel") != EVIDENCE_CHANNEL:
        raise dk_core.ValidationError(f"{context}: evidence channel must stay distinct")
    if provenance.get("discovery_signals_counted") != 0:
        raise dk_core.ValidationError(
            f"{context}: discovery signals may never count as solved-case recurrence"
        )
    for support in provenance.get("authoritative_support", []):
        if support.get("rewrites_case_provenance") is not False:
            raise dk_core.ValidationError(
                f"{context}: authoritative support may not rewrite case provenance"
            )
        if support.get("relation") not in ("supports", "contradicts"):
            raise dk_core.ValidationError(f"{context}: invalid authoritative relation")

    review = proposal["review"]
    if review is not None:
        if review.get("outcome") not in REVIEW_OUTCOMES:
            raise dk_core.ValidationError(f"{context}: invalid review outcome")
        if review.get("method") not in REVIEW_METHODS:
            raise dk_core.ValidationError(f"{context}: invalid review method")
        if review.get("trusted_knowledge_changed") is not False:
            raise dk_core.ValidationError(f"{context}: review must not change trusted knowledge")
        if review.get("knowledge_record_created") is not False:
            raise dk_core.ValidationError(f"{context}: review must not create a knowledge record")
        if not review.get("actor"):
            raise dk_core.ValidationError(f"{context}: review requires an actor")

    assert_identity_minimized(proposal, context)


MATERIAL_PROPOSAL_KEYS = (
    "recurrence_analysis_id",
    "structural_key_digest",
    "supporting_case_ids",
    "contradictory_case_ids",
    "proposed_statement",
    "proposed_applicability",
    "proposed_limitations",
    "evidence_confidence",
    "eligibility",
)

EVIDENCE_CHANGED_AFTER_REVIEW = (
    "Evidence changed after this proposal was reviewed, so it returned to pending review."
)


def write_proposal(root: Path, proposal: dict) -> tuple[Path, str]:
    """Persist a proposal idempotently, one per recurrence analysis."""
    validate_proposal(proposal)
    path = proposal_path(root, proposal["id"])
    if path.is_file():
        existing = dk_core.read_json(path)
        if all(existing.get(key) == proposal.get(key) for key in MATERIAL_PROPOSAL_KEYS):
            return path, "reused"
        merged = dict(proposal)
        merged["review"] = existing.get("review")
        merged["review_state"] = REVIEW_PENDING
        merged["provenance"] = dict(proposal["provenance"])
        merged["provenance"]["authoritative_support"] = list(
            (existing.get("provenance") or {}).get("authoritative_support", [])
        )
        if existing.get("review") is not None:
            merged["proposed_limitations"] = list(merged["proposed_limitations"]) + [
                EVIDENCE_CHANGED_AFTER_REVIEW
            ]
        validate_proposal(merged)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stable_json(merged), encoding="utf-8")
        return path, "updated"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(proposal), encoding="utf-8")
    return path, "created"


# ---------------------------------------------------------------------------
# Orchestrated analysis
# ---------------------------------------------------------------------------


def build_run_id(stamp: str, case_ids: list[str]) -> str:
    compact = stamp.replace("-", "").replace(":", "").replace("Z", "")
    fingerprint = digest(stamp, ENGINE_VERSION, ",".join(sorted(case_ids)))
    return f"recurrence.{compact}.{fingerprint.removeprefix('sha256:')[:8]}"


def analyze(
    root: Path = dk_core.ROOT,
    *,
    min_cases: int = 2,
    propose: bool = True,
    dry_run: bool = False,
    moment: datetime | None = None,
) -> dict:
    """Analyze recurrence across verified solved cases and propose where warranted.

    Reads ``cases/solved`` and nothing else. Discovery signals and authoritative
    snapshots are different evidence channels and are not consulted here.
    """
    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)
    cases = load_cases(root)
    run_id = build_run_id(stamp, [case.get("id", "") for case in cases])

    digest_before = dk_core.knowledge_tree_digest(root)

    eligible = [case for case in cases if case_is_verified(case)]
    ineligible = [case for case in cases if not case_is_verified(case)]

    groups = group_by_structure(eligible)
    ineligible_by_key: dict[str, list[dict]] = {}
    for case in ineligible:
        ineligible_by_key.setdefault(structural_key(case)["digest"], []).append(case)

    analyses: list[dict] = []
    proposals: list[dict] = []
    skipped: list[dict] = []

    try:
        for key_digest, members in groups.items():
            if len(members) < min_cases:
                skipped.append(
                    {
                        "structural_key_digest": key_digest,
                        "case_ids": [case.get("id", "") for case in members],
                        "reason": "single_case_group",
                    }
                )
                continue

            key = structural_key(members[0])
            analysis = build_analysis(
                key,
                members,
                ineligible_by_key.get(key_digest, []),
                stamp=stamp,
                run_id=run_id,
            )
            if dry_run:
                validate_analysis(analysis)
                result = "dry_run"
            else:
                _, result = write_analysis(root, analysis)
            analyses.append(
                {
                    "id": analysis["id"],
                    "result": result,
                    "case_ids": analysis["case_ids"],
                    "independent_occurrences": analysis["independent_occurrences"]["count"],
                    "verification_grade": analysis["verification_quality"]["grade"],
                    "contradictory_case_count": len(analysis["contradictory_cases"]),
                    "scope_conflict_count": len(analysis["applicability_conflicts"]),
                }
            )

            if not propose:
                continue
            if analysis["independent_occurrences"]["count"] < MINIMUM_INDEPENDENT_OCCURRENCES:
                skipped.append(
                    {
                        "structural_key_digest": key_digest,
                        "case_ids": analysis["case_ids"],
                        "reason": "insufficient_independent_occurrences",
                    }
                )
                continue

            proposal = build_proposal(analysis, members, stamp=stamp, run_id=run_id)
            if dry_run:
                validate_proposal(proposal)
                proposal_result = "dry_run"
            else:
                _, proposal_result = write_proposal(root, proposal)
            proposals.append(
                {
                    "id": proposal["id"],
                    "result": proposal_result,
                    "recurrence_analysis_id": proposal["recurrence_analysis_id"],
                    "confidence": proposal["evidence_confidence"]["grade"],
                    "review_state": proposal["review_state"],
                    "recommended_review_state": proposal["eligibility"][
                        "recommended_review_state"
                    ],
                }
            )
    except (GeneralizationInputError, dk_core.ValidationError):
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise GeneralizationEngineDefect(
            f"recurrence engine defect: {type(exc).__name__}: {exc}"
        ) from exc

    digest_after = dk_core.knowledge_tree_digest(root)
    if digest_before != digest_after:
        raise GeneralizationEngineDefect(
            "recurrence analysis mutated trusted knowledge; this is an engine defect"
        )

    return {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "engine": {
            "recurrence": {"name": RECURRENCE_ENGINE_NAME, "version": ENGINE_VERSION},
            "generalization": {"name": GENERALIZATION_ENGINE_NAME, "version": ENGINE_VERSION},
            "deterministic": True,
            "language_model_used": False,
        },
        "evidence_channel": EVIDENCE_CHANNEL,
        "started_at": stamp,
        "completed_at": now_iso(),
        "dry_run": dry_run,
        "cases_considered": [case.get("id", "") for case in cases],
        "cases_eligible": [case.get("id", "") for case in eligible],
        "cases_excluded_unverified": [case.get("id", "") for case in ineligible],
        "recurrence_analyses": analyses,
        "generalization_proposals": proposals,
        "skipped": skipped,
        "discovery_signals_counted": 0,
        "trusted_knowledge_mutations": [],
        "trusted_knowledge_digest": {"before": digest_before, "after": digest_after},
    }


# ---------------------------------------------------------------------------
# Human review
# ---------------------------------------------------------------------------


def review_proposal(
    root: Path,
    proposal_id: str,
    *,
    outcome: str,
    actor: str,
    method: str = "human_generalization_review",
    note: str | None = None,
    moment: datetime | None = None,
) -> dict:
    """Record an explicit human decision on a generalization proposal.

    No outcome available here mutates trusted knowledge or creates a knowledge
    record. ``accepted_for_knowledge_proposal`` authorises later, separate
    proposal work and nothing more.
    """
    if outcome not in REVIEW_OUTCOMES:
        raise GeneralizationInputError(
            f"invalid review outcome {outcome!r}; expected one of {', '.join(REVIEW_OUTCOMES)}"
        )
    if method not in REVIEW_METHODS:
        raise GeneralizationInputError(f"invalid review method {method!r}")
    if not actor or not actor.strip():
        raise GeneralizationInputError("review requires an actor")

    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)
    digest_before = dk_core.knowledge_tree_digest(root)

    proposal = load_proposal(root, proposal_id)
    review = {
        "reviewed_at": stamp,
        "actor": actor.strip(),
        "method": method,
        "note": note,
        "outcome": outcome,
        "authorizes_knowledge_proposal_work": outcome in REVIEW_AUTHORIZING_OUTCOMES,
        "trusted_knowledge_changed": False,
        "knowledge_record_created": False,
    }
    proposal["review"] = review
    proposal["review_state"] = outcome
    validate_proposal(proposal)
    proposal_path(root, proposal_id).write_text(stable_json(proposal), encoding="utf-8")

    digest_after = dk_core.knowledge_tree_digest(root)
    if digest_before != digest_after:
        raise GeneralizationEngineDefect(
            "generalization review mutated trusted knowledge; this is an engine defect"
        )

    return {
        "proposal_id": proposal_id,
        "review_state": proposal["review_state"],
        "authorizes_knowledge_proposal_work": review["authorizes_knowledge_proposal_work"],
        "trusted_knowledge_changed": False,
        "knowledge_record_created": False,
        "trusted_knowledge_digest": {"before": digest_before, "after": digest_after},
    }


def recurrence_report(root: Path) -> list[dict]:
    proposals_by_analysis = {
        proposal["recurrence_analysis_id"]: proposal for proposal in iter_proposals(root)
    }
    rows = []
    for analysis in iter_analyses(root):
        proposal = proposals_by_analysis.get(analysis["id"])
        rows.append(
            {
                "recurrence_id": analysis["id"],
                "case_count": len(analysis["case_ids"]),
                "independent_occurrences": analysis["independent_occurrences"]["count"],
                "verification_grade": analysis["verification_quality"]["grade"],
                "contradictory_cases": len(analysis["contradictory_cases"]),
                "scope_conflicts": len(analysis["applicability_conflicts"]),
                "components": analysis["structural_key"]["components"],
                "proposal_id": proposal["id"] if proposal else None,
                "confidence": proposal["evidence_confidence"]["grade"] if proposal else None,
                "review_state": proposal["review_state"] if proposal else None,
            }
        )
    return sorted(rows, key=lambda row: row["recurrence_id"])


# ---------------------------------------------------------------------------
# Repository contract
# ---------------------------------------------------------------------------


def validate_generalization_contract(root: Path = dk_core.ROOT) -> list[str]:
    """Validate recurrence and generalization artifacts on disk."""
    for relative in (
        "schema/recurrence-analysis.schema.json",
        "schema/generalization-proposal.schema.json",
    ):
        dk_core.read_json(root / relative)

    case_ids = {case.get("id") for case in load_cases(root)}
    analyses = iter_analyses(root)
    analysis_ids = set()
    for analysis in analyses:
        validate_analysis(analysis)
        analysis_ids.add(analysis["id"])
        for case_id in analysis["case_ids"]:
            if case_id not in case_ids:
                raise dk_core.ValidationError(
                    f"recurrence {analysis['id']}: references unknown case {case_id}"
                )

    proposals = iter_proposals(root)
    authorized = 0
    for proposal in proposals:
        validate_proposal(proposal)
        if proposal["recurrence_analysis_id"] not in analysis_ids:
            raise dk_core.ValidationError(
                f"generalization {proposal['id']}: references unknown recurrence analysis"
            )
        for case_id in proposal["supporting_case_ids"] + proposal["contradictory_case_ids"]:
            if case_id not in case_ids:
                raise dk_core.ValidationError(
                    f"generalization {proposal['id']}: references unknown case {case_id}"
                )
        review = proposal.get("review")
        if review and review.get("authorizes_knowledge_proposal_work"):
            authorized += 1

    return [
        "RECURRENCE_ENGINE_CONTRACT_VALID=PASS",
        f"RECURRENCE_ENGINE_VERSION={ENGINE_VERSION}",
        f"RECURRENCE_ANALYSES={len(analyses)}",
        f"GENERALIZATION_PROPOSALS={len(proposals)}",
        f"GENERALIZATION_PROPOSALS_AUTHORIZING_PROPOSAL_WORK={authorized}",
        "GENERALIZATION_CANNOT_PROMOTE_TRUSTED_KNOWLEDGE=PASS",
    ]
