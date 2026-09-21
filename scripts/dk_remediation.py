#!/usr/bin/env python3
"""Security remediation intelligence: explain the path, never walk it.

This module answers a different question from the security engine. That one
says *this project is affected by advisory X*. This one says *here is the
nearest target the authoritative evidence supports, here is what it resolves,
here is what it does not, and here is what nobody can tell you yet*.

Three distinctions it exists to keep:

    advisory fixed version      != project-safe upgrade target
    minimum non-affected        != recommended supported version
    remediation plan            != executed remediation

Every candidate target is re-evaluated against the full applicable advisory set
by the security engine rather than compared against the finding that started the
plan. Upgrade compatibility is never inferred: without authoritative transition
evidence the answer is ``unknown`` and review is required.

The engine is read-only. It writes no project file, invokes no Composer, and
changes no enforcement policy. ``execution_performed`` is structurally false.
"""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_core
import dk_security


ENGINE_NAME = "drupal-knowledge-remediation-engine"
ENGINE_VERSION = "0.1"
PLAN_SCHEMA_VERSION = "0.1"

CONTEXT_RELATIVE_PATH = Path("knowledge") / "context" / "drupal-core-release-lifecycle.json"
RELEASE_STATE_SOURCE = "reviewed_release_lifecycle_context"

SUPPORTED = "supported"
UNSUPPORTED = "unsupported"
UNKNOWN = "unknown"
NOT_APPLICABLE = "not_applicable"

STABLE = "stable"
PRERELEASE = "prerelease"

CONSTRAINT_SATISFIED = "satisfied"
CONSTRAINT_NOT_SATISFIED = "not_satisfied"
CONSTRAINT_NOT_OBSERVED = "constraint_not_observed"

CHANGE_REQUIRED = "required"
CHANGE_NOT_REQUIRED = "not_required"

ORIGIN_ADVISORY = "advisory_fixed_version"
ORIGIN_SUPPORTED_STABLE = "newest_supported_stable_release"
ORIGIN_OPERATOR = "operator_supplied_target"

TRANSITION_NONE = "none_required"
TRANSITION_SAME_BRANCH = "same_branch"
TRANSITION_MINOR = "minor_within_major"
TRANSITION_MAJOR = "major_transition"

COMPLETENESS_NONE_APPLICABLE = "no_applicable_advisories_in_evaluated_set"
COMPLETENESS_COMPLETE = "complete_for_evaluated_security_set"
COMPLETENESS_PARTIAL = "partial_due_to_dependency_unknowns"
COMPLETENESS_BLOCKED_EOL = "blocked_by_unsupported_branch"
COMPLETENESS_COMPAT_REVIEW = "requires_compatibility_review"
COMPLETENESS_INSUFFICIENT = "insufficient_project_evidence"

# Drupal Knowledge holds no authoritative evidence that any particular
# major-version transition is supported for any particular project, so it says
# so rather than implying otherwise.
NO_TRANSITION_EVIDENCE = (
    "Drupal Knowledge holds no authoritative evidence that this transition is "
    "supported for this project. Compatibility review is required."
)
SAME_BRANCH_EVIDENCE = (
    "Target is on the branch already installed, so no major or minor transition "
    "is involved."
)
LOCK_NOT_OBSERVABLE = "not_separately_observable"

# Wording the engine must never produce, however clean an evaluation looks.
FORBIDDEN_SAFETY_WORDS = ("secure", "safe", "fully patched", "no vulnerabilities")


class RemediationInputError(RuntimeError):
    """Caller asked for something the evidence does not describe."""


class RemediationEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as an evidence problem."""


def now_iso(moment: datetime | None = None) -> str:
    return dk_security.now_iso(moment)


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def digest_hex(*parts: Any) -> str:
    accumulator = hashlib.sha256()
    for part in parts:
        accumulator.update(str(part).encode("utf-8"))
        accumulator.update(b"\0")
    return accumulator.hexdigest()


def parse_version(value: Any):
    return dk_security.parse_version(value)


def branch_of(version: Any) -> str | None:
    """The Drupal branch a version belongs to, e.g. 10.6.16 -> 10.6."""
    parsed = parse_version(version)
    if parsed is None:
        return None
    return f"{parsed.major}.{parsed.minor}"


# ---------------------------------------------------------------------------
# Composer constraint semantics
#
# Constraints are read to answer one question: would this target be reachable
# without changing the manifest? They are never rewritten.
# ---------------------------------------------------------------------------

STABILITY_FLAG_RE = re.compile(r"@(?:dev|alpha|beta|RC|rc|stable)\b")
CARET_RE = re.compile(r"^\^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$")
TILDE_RE = re.compile(r"^~\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$")
COMPARATOR_RE = re.compile(r"^(>=|<=|>|<|=)?\s*(\d+(?:\.\d+){0,2})$")
WILDCARD_RE = re.compile(r"^(\d+)(?:\.(\d+))?\.\*$")


def _bounds_from_caret(match: re.Match) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    # ^ allows changes that do not modify the left-most non-zero segment.
    if major > 0:
        return (major, minor, patch), (major + 1, 0, 0)
    if minor > 0:
        return (major, minor, patch), (major, minor + 1, 0)
    return (major, minor, patch), (major, minor, patch + 1)


def _bounds_from_tilde(match: re.Match) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    major = int(match.group(1))
    minor_given = match.group(2)
    patch_given = match.group(3)
    minor = int(minor_given or 0)
    patch = int(patch_given or 0)
    if patch_given is not None:
        # ~1.2.3 allows patch-level changes only.
        return (major, minor, patch), (major, minor + 1, 0)
    # ~1.2 allows minor-level changes.
    return (major, minor, 0), (major + 1, 0, 0)


def constraint_satisfied(target: Any, constraint: Any) -> str:
    """Would ``target`` satisfy ``constraint`` as written?

    Returns ``satisfied``, ``not_satisfied`` or ``unknown``. An unreadable
    constraint is unknown, never assumed permissive.
    """
    if constraint is None or not isinstance(constraint, str) or not constraint.strip():
        return CONSTRAINT_NOT_OBSERVED

    version = parse_version(target)
    if version is None:
        return UNKNOWN

    text = STABILITY_FLAG_RE.sub("", constraint).strip()
    if not text:
        return UNKNOWN

    # An OR of clauses: satisfied if any clause is satisfied, unknown if a
    # clause cannot be read and none of the readable ones matched.
    saw_unknown = False
    for raw_clause in text.split("||"):
        clause = raw_clause.strip()
        if not clause:
            continue
        outcome = _clause_satisfied(version, clause)
        if outcome == CONSTRAINT_SATISFIED:
            return CONSTRAINT_SATISFIED
        if outcome == UNKNOWN:
            saw_unknown = True
    return UNKNOWN if saw_unknown else CONSTRAINT_NOT_SATISFIED


def _clause_satisfied(version, clause: str) -> str:
    if clause == "*":
        return CONSTRAINT_SATISFIED

    caret = CARET_RE.match(clause)
    if caret:
        low, high = _bounds_from_caret(caret)
        return CONSTRAINT_SATISFIED if low <= version.key < high else CONSTRAINT_NOT_SATISFIED

    tilde = TILDE_RE.match(clause)
    if tilde:
        low, high = _bounds_from_tilde(tilde)
        return CONSTRAINT_SATISFIED if low <= version.key < high else CONSTRAINT_NOT_SATISFIED

    wildcard = WILDCARD_RE.match(clause)
    if wildcard:
        major = int(wildcard.group(1))
        minor_given = wildcard.group(2)
        if minor_given is None:
            return CONSTRAINT_SATISFIED if version.major == major else CONSTRAINT_NOT_SATISFIED
        return (
            CONSTRAINT_SATISFIED
            if (version.major, version.minor) == (major, int(minor_given))
            else CONSTRAINT_NOT_SATISFIED
        )

    # A space-separated AND of comparators, e.g. ">=1.0 <2.0".
    parts = clause.split()
    if not parts:
        return UNKNOWN
    for part in parts:
        match = COMPARATOR_RE.match(part)
        if not match:
            return UNKNOWN
        operator = match.group(1) or "="
        bound = parse_version(match.group(2))
        if bound is None:
            return UNKNOWN
        if operator == ">=" and not version.key >= bound.key:
            return CONSTRAINT_NOT_SATISFIED
        if operator == ">" and not version.key > bound.key:
            return CONSTRAINT_NOT_SATISFIED
        if operator == "<=" and not version.key <= bound.key:
            return CONSTRAINT_NOT_SATISFIED
        if operator == "<" and not version.key < bound.key:
            return CONSTRAINT_NOT_SATISFIED
        if operator == "=" and version.key != bound.key:
            return CONSTRAINT_NOT_SATISFIED
    return CONSTRAINT_SATISFIED


# ---------------------------------------------------------------------------
# Authoritative release state
#
# Supported branches and available releases come from the reviewed
# release-lifecycle context. Nothing about today's Drupal support window is
# hardcoded here.
# ---------------------------------------------------------------------------


def load_release_state(root: Path = dk_core.ROOT) -> dict:
    """Read Drupal core release and support state from the reviewed context."""
    path = root / CONTEXT_RELATIVE_PATH
    if not path.is_file():
        raise RemediationInputError(
            "the reviewed release-lifecycle context is missing; core remediation "
            "cannot determine branch support without it"
        )
    context = dk_core.read_json(path)

    supported = [
        entry["source_value"].rstrip(".")
        for entry in context.get("supported_branches", {}).get("entries", [])
        if isinstance(entry.get("source_value"), str)
    ]

    releases: dict[str, dict] = {}
    for row in context.get("releases", []):
        version = (row.get("version", {}).get("source", {}) or {}).get("source_value")
        if not isinstance(version, str) or not version:
            continue
        terms = row.get("release_type_source_values") or []
        releases[version] = {
            "version": version,
            "branch": branch_of(version),
            "stable": (row.get("version", {}).get("stable_semver", {}) or {}).get("state")
            == "present",
            "published": (row.get("status", {}) or {}).get("source_value") == "published",
            "insecure": "Insecure" in terms,
            "security_covered": (row.get("security", {}).get("covered_attribute", {}) or {}).get(
                "source_value"
            )
            == "1",
        }

    return {
        "supported_branches": sorted(supported),
        "releases": releases,
        "source": RELEASE_STATE_SOURCE,
        "provenance": {
            "source_id": (context.get("source", {}) or {}).get("source_id", "unknown"),
            "snapshot_sha256": (context.get("source", {}) or {}).get("snapshot_sha256", "unknown"),
            "review_status": (context.get("review", {}) or {}).get("status", "unknown"),
            "reviewed_on": (context.get("review", {}) or {}).get("reviewed_on", "unknown"),
            "release_count": context.get("release_count", 0),
        },
    }


def branch_support(branch: str | None, state: dict) -> str:
    if branch is None:
        return UNKNOWN
    return SUPPORTED if branch in state["supported_branches"] else UNSUPPORTED


def newest_supported_stable(state: dict) -> dict[str, str]:
    """Newest published, stable, non-Insecure release on each supported branch."""
    best: dict[str, tuple] = {}
    for release in state["releases"].values():
        branch = release["branch"]
        if branch not in state["supported_branches"]:
            continue
        if not (release["stable"] and release["published"]) or release["insecure"]:
            continue
        parsed = parse_version(release["version"])
        if parsed is None:
            continue
        if branch not in best or parsed.key > best[branch][0]:
            best[branch] = (parsed.key, release["version"])
    return {branch: value[1] for branch, value in sorted(best.items())}


# ---------------------------------------------------------------------------
# Candidate targets, re-evaluated by the security engine
#
# A candidate is only ever a version that authoritative evidence already
# mentions: a fixed release named by an advisory, the newest supported stable
# release in the reviewed context, or a target an operator asked about
# explicitly. Nothing is invented, and every candidate is put back through
# dk_security.evaluate against the full applicable advisory set.
# ---------------------------------------------------------------------------


def synthesize_analysis(analysis: dict, scope: str, package: str, target: str) -> dict:
    """A copy of the analyzer facts with one component's version replaced.

    This is how a proposed target is re-evaluated: the same security engine
    reads the same fact shape, so a target is judged by exactly the rules the
    current state was judged by.
    """
    projected = copy.deepcopy(analysis)
    facts = projected["profile"]["facts"]

    if scope == dk_security.SCOPE_CORE:
        facts["drupal_core_version"] = {
            "state": "known",
            "confidence": "high",
            "value": {"package": dk_security.DRUPAL_CORE_PACKAGE, "version": target},
        }
        return projected

    installed = (facts.get("composer_packages", {}).get("value", {}) or {}).get("installed")
    if isinstance(installed, dict):
        for entry in installed.get("drupal_packages") or []:
            if isinstance(entry, dict) and entry.get("name") == package:
                entry["version"] = target
    return projected


def evaluate_candidate(
    root: Path,
    analysis: dict,
    *,
    scope: str,
    package: str,
    target: str,
    advisory_ids: list[str],
) -> dict:
    """Re-evaluate one candidate target against the applicable advisory set."""
    projected = synthesize_analysis(analysis, scope, package, target)
    evaluation = dk_security.evaluate(projected, root, advisory_ids=advisory_ids)

    resolved: list[str] = []
    residual: list[str] = []
    unknown: list[str] = []
    for result in evaluation["results"]:
        state = result["applicability"]
        if state in (dk_security.NOT_APPLICABLE, dk_security.VERSION_OUT_OF_SCOPE):
            resolved.append(result["advisory_id"])
        elif state == dk_security.APPLICABLE:
            residual.append(result["advisory_id"])
        else:
            unknown.append(result["advisory_id"])

    return {
        "resolves_advisories": sorted(resolved),
        "residual_advisories": sorted(residual),
        "unknown_advisories": sorted(unknown),
    }


def candidate_versions(
    scope: str,
    fixed_versions: Iterable[str],
    release_state: dict,
    operator_target: str | None,
    installed_version: Any = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Build the candidate set, each tagged with where it came from.

    Candidates below the installed version are excluded. A lower version can
    look like it "resolves" an advisory simply by falling outside the majors it
    speaks about, and recommending a downgrade is not remediation. An
    operator-supplied target is always evaluated, because asking what a
    specific version would do is a legitimate read-only question.
    """
    installed = parse_version(installed_version)
    seen: dict[str, str] = {}
    excluded: list[str] = []

    def consider(version: str, origin: str) -> None:
        parsed = parse_version(version)
        if parsed is None:
            return
        if installed is not None and parsed.key < installed.key:
            excluded.append(version)
            return
        seen.setdefault(version, origin)

    for version in fixed_versions:
        consider(version, ORIGIN_ADVISORY)
    if scope == dk_security.SCOPE_CORE:
        for version in newest_supported_stable(release_state).values():
            consider(version, ORIGIN_SUPPORTED_STABLE)
    if operator_target:
        seen[operator_target] = ORIGIN_OPERATOR

    ordered = sorted(
        seen.items(),
        key=lambda item: (parse_version(item[0]).key if parse_version(item[0]) else (0, 0, 0)),
    )
    return ordered, sorted(set(excluded))


def describe_candidate(
    version: str, origin: str, scope: str, release_state: dict, constraint: Any
) -> dict:
    """Support, stability and constraint facts for one candidate."""
    branch = branch_of(version)
    release = release_state["releases"].get(version) if scope == dk_security.SCOPE_CORE else None
    parsed = parse_version(version)

    if scope == dk_security.SCOPE_CORE:
        support = branch_support(branch, release_state)
        if release is not None:
            stability = STABLE if release["stable"] else PRERELEASE
            insecure = release["insecure"]
        else:
            # Not present in the reviewed release feed: stability and feed flags
            # are unknown rather than assumed good.
            stability = STABLE if (parsed and parsed.suffix is None) else PRERELEASE
            insecure = None
    else:
        # Contrib release/support state is not modelled by the reviewed core
        # release context, so it stays explicitly unknown.
        support = NOT_APPLICABLE
        stability = STABLE if (parsed and parsed.suffix is None) else PRERELEASE
        insecure = None

    return {
        "version": version,
        "origin": origin,
        "branch": branch,
        "branch_support": support,
        "stable_release": stability,
        "flagged_insecure_in_release_feed": insecure,
        "satisfies_declared_constraint": constraint_satisfied(version, constraint),
        "reevaluated_by_security_engine": True,
    }


def pick_minimum_non_affected(candidates: list[dict], advisory_ids: list[str]) -> dict:
    """Lowest candidate that resolves every applicable advisory."""
    for candidate in candidates:
        if sorted(candidate["resolves_advisories"]) == sorted(advisory_ids):
            return {
                "state": "identified",
                "version": candidate["version"],
                "resolves_advisories": list(candidate["resolves_advisories"]),
                "branch_support": candidate["branch_support"],
            }
    return {
        "state": "none_available",
        "version": None,
        "resolves_advisories": [],
        "branch_support": UNKNOWN,
    }


def pick_recommended_supported(
    candidates: list[dict], advisory_ids: list[str], scope: str
) -> dict:
    """Lowest candidate that resolves everything *and* is worth recommending.

    Being non-affected is not enough. A recommended target must sit on a branch
    the authoritative release state still supports, be a stable published
    release, and not be flagged Insecure by the release feed.
    """
    fully = [
        candidate
        for candidate in candidates
        if sorted(candidate["resolves_advisories"]) == sorted(advisory_ids)
    ]
    if not fully:
        return {
            "state": "none_on_supported_branch",
            "version": None,
            "reason": (
                "No candidate drawn from authoritative evidence resolves every applicable "
                "advisory, so no supported target can be recommended from this evidence."
            ),
            "resolves_advisories": [],
            "residual_advisories": list(advisory_ids),
        }

    if scope == dk_security.SCOPE_CORE:
        eligible = [
            candidate
            for candidate in fully
            if candidate["branch_support"] == SUPPORTED
            and candidate["stable_release"] == STABLE
            and candidate["flagged_insecure_in_release_feed"] is not True
        ]
        if not eligible:
            unsupported = sorted({item["version"] for item in fully})
            return {
                "state": "none_on_supported_branch",
                "version": None,
                "reason": (
                    "Every candidate that resolves the applicable advisories sits on a branch "
                    "the authoritative release state no longer supports, or is not a stable "
                    f"published release: {', '.join(unsupported)}. Being non-affected is not "
                    "the same as being supported."
                ),
                "resolves_advisories": [],
                "residual_advisories": [],
            }
        chosen = eligible[0]
    else:
        chosen = fully[0]

    return {
        "state": "identified",
        "version": chosen["version"],
        "reason": (
            f"{chosen['version']} resolves every applicable advisory in the evaluated set and "
            + (
                "sits on a branch the authoritative release state still supports."
                if scope == dk_security.SCOPE_CORE
                else "is the lowest authoritative fixed release that covers the evaluated set."
            )
        ),
        "resolves_advisories": list(chosen["resolves_advisories"]),
        "residual_advisories": list(chosen["residual_advisories"]),
    }


def describe_transition(current: Any, target: str | None, scope: str) -> dict:
    """Classify the transition, and refuse to claim it is supported."""
    if target is None:
        return {
            "kind": UNKNOWN,
            "from_major": None,
            "to_major": None,
            "supported": UNKNOWN,
            "evidence": "No target was identified, so no transition is described.",
            "requires_compatibility_review": True,
        }

    from_version = parse_version(current)
    to_version = parse_version(target)
    if from_version is None or to_version is None:
        return {
            "kind": UNKNOWN,
            "from_major": str(from_version.major) if from_version else None,
            "to_major": str(to_version.major) if to_version else None,
            "supported": UNKNOWN,
            "evidence": "A version could not be read, so the transition is unknown.",
            "requires_compatibility_review": True,
        }

    from_major, to_major = str(from_version.major), str(to_version.major)

    if from_version.key == to_version.key:
        return {
            "kind": TRANSITION_NONE,
            "from_major": from_major,
            "to_major": to_major,
            "supported": SUPPORTED,
            "evidence": "The target is the installed version.",
            "requires_compatibility_review": False,
        }

    if (from_version.major, from_version.minor) == (to_version.major, to_version.minor):
        return {
            "kind": TRANSITION_SAME_BRANCH,
            "from_major": from_major,
            "to_major": to_major,
            # A patch move inside one branch is the case Drupal's own release
            # process is built around, so it needs no compatibility review.
            "supported": SUPPORTED,
            "evidence": SAME_BRANCH_EVIDENCE,
            "requires_compatibility_review": False,
        }

    kind = TRANSITION_MINOR if from_major == to_major else TRANSITION_MAJOR
    return {
        "kind": kind,
        "from_major": from_major,
        "to_major": to_major,
        "supported": UNKNOWN,
        "evidence": NO_TRANSITION_EVIDENCE,
        "requires_compatibility_review": True,
    }


# ---------------------------------------------------------------------------
# Plan assembly
# ---------------------------------------------------------------------------


def declared_constraint(analysis: dict, package: str) -> Any:
    declared = (
        (analysis.get("profile", {}).get("facts", {}).get("composer_packages", {}) or {})
        .get("value", {})
        or {}
    ).get("declared") or {}
    require = declared.get("require")
    if isinstance(require, dict):
        value = require.get(package)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def constraint_state(constraint: Any) -> str:
    if constraint is None:
        return "not_observed"
    return "observed" if constraint_satisfied("1.0.0", constraint) != UNKNOWN else "unparseable"


def build_steps(
    component: str,
    current: Any,
    recommended: dict,
    transition: dict,
    change_required: str,
    constraint: Any,
) -> list[dict]:
    """Deterministic recommendations. Nothing here is executed."""
    steps: list[dict] = []
    order = 1

    if recommended["state"] != "identified":
        steps.append(
            {
                "order": order,
                "action": "obtain_supported_target_evidence",
                "detail": (
                    f"No supported target for {component} follows from the evaluated evidence. "
                    f"{recommended['reason']}"
                ),
                "executed": False,
            }
        )
        return steps

    target = recommended["version"]

    if transition["requires_compatibility_review"]:
        steps.append(
            {
                "order": order,
                "action": "compatibility_review",
                "detail": (
                    f"Review whether {component} can move from {current} to {target} "
                    f"({transition['kind']}). {NO_TRANSITION_EVIDENCE}"
                ),
                "executed": False,
            }
        )
        order += 1

    if change_required == CHANGE_REQUIRED:
        steps.append(
            {
                "order": order,
                "action": "change_declared_constraint",
                "detail": (
                    f"The declared constraint {constraint!r} does not admit {target}. A human "
                    "must decide the new constraint; Drupal Knowledge does not edit manifests."
                ),
                "executed": False,
            }
        )
        order += 1
    elif change_required == UNKNOWN:
        steps.append(
            {
                "order": order,
                "action": "determine_declared_constraint",
                "detail": (
                    f"The declared constraint for {component} could not be read, so whether "
                    f"{target} is reachable without a manifest change is unknown."
                ),
                "executed": False,
            }
        )
        order += 1

    steps.append(
        {
            "order": order,
            "action": "update_component",
            "detail": (
                f"Move {component} to {target}. This is a recommendation: no dependency, "
                "manifest or lock file was changed."
            ),
            "executed": False,
        }
    )
    order += 1
    steps.append(
        {
            "order": order,
            "action": "reanalyze_and_reevaluate",
            "detail": (
                "Re-run the project analyzer and security evaluation afterwards, so the "
                "resulting state is observed rather than assumed."
            ),
            "executed": False,
        }
    )
    return steps


def build_component_plan(
    root: Path,
    analysis: dict,
    *,
    scope: str,
    package: str,
    component: str,
    installed_version: Any,
    installed_state: str,
    identity: dict,
    advisories: list[dict],
    release_state: dict,
    operator_target: str | None,
) -> dict:
    advisory_ids = sorted(item["id"] for item in advisories)
    fixed_by_advisory = {
        item["id"]: list(item["fixed_in"]["versions"]) for item in advisories
    }
    all_fixed = sorted({v for versions in fixed_by_advisory.values() for v in versions})

    constraint = declared_constraint(analysis, package)
    limitations: list[str] = []

    if installed_state != "known":
        limitations.append(
            f"The installed version of {component} was not definitively observed, so no target "
            "can be derived from it."
        )
        return {
            "component": component,
            "scope": scope,
            "package": package,
            "project_identity": identity,
            "current": {
                "installed_version": None,
                "installed_version_state": "unknown",
                "branch": None,
                "branch_support": UNKNOWN,
                "declared_constraint": constraint,
                "declared_constraint_state": constraint_state(constraint),
                "lock_resolution_state": LOCK_NOT_OBSERVABLE,
            },
            "applicable_advisories": advisory_ids,
            "authoritative_remediation": {
                "fixed_versions_by_advisory": fixed_by_advisory,
                "all_fixed_versions": all_fixed,
                "authored_by_drupal_knowledge": False,
            },
            "project_remediation_plan": {
                "minimum_non_affected_target": {
                    "state": UNKNOWN,
                    "version": None,
                    "resolves_advisories": [],
                    "branch_support": UNKNOWN,
                },
                "recommended_supported_target": {
                    "state": UNKNOWN,
                    "version": None,
                    "reason": "The installed version is unknown, so no target follows.",
                    "resolves_advisories": [],
                    "residual_advisories": advisory_ids,
                },
                "candidates": [],
                "transition": describe_transition(None, None, scope),
                "constraint_change_required": UNKNOWN,
                "steps": [
                    {
                        "order": 1,
                        "action": "observe_installed_version",
                        "detail": (
                            f"Establish the installed version of {component} before planning "
                            "remediation."
                        ),
                        "executed": False,
                    }
                ],
                "authored_by_drupal_knowledge": True,
            },
            "limitations": limitations,
        }

    candidates: list[dict] = []
    considered, below_installed = candidate_versions(
        scope, all_fixed, release_state, operator_target, installed_version
    )
    if below_installed:
        limitations.append(
            "Candidate release(s) below the installed version were excluded because a "
            "downgrade is not remediation: "
            + ", ".join(below_installed)
        )
    for version, origin in considered:
        described = describe_candidate(version, origin, scope, release_state, constraint)
        described.update(
            evaluate_candidate(
                root,
                analysis,
                scope=scope,
                package=package,
                target=version,
                advisory_ids=advisory_ids,
            )
        )
        candidates.append(described)

    minimum = pick_minimum_non_affected(candidates, advisory_ids)
    recommended = pick_recommended_supported(candidates, advisory_ids, scope)
    transition = describe_transition(installed_version, recommended["version"], scope)

    if recommended["version"] is None:
        change_required = UNKNOWN if constraint is not None else CONSTRAINT_NOT_OBSERVED
    else:
        satisfied = constraint_satisfied(recommended["version"], constraint)
        change_required = {
            CONSTRAINT_SATISFIED: CHANGE_NOT_REQUIRED,
            CONSTRAINT_NOT_SATISFIED: CHANGE_REQUIRED,
            CONSTRAINT_NOT_OBSERVED: CONSTRAINT_NOT_OBSERVED,
            UNKNOWN: UNKNOWN,
        }[satisfied]

    current_branch = branch_of(installed_version)
    support = (
        branch_support(current_branch, release_state)
        if scope == dk_security.SCOPE_CORE
        else NOT_APPLICABLE
    )

    if support == UNSUPPORTED:
        limitations.append(
            f"{component} is on branch {current_branch}, which the authoritative release state "
            "does not list as supported, so remaining on this branch cannot be recommended."
        )
    if minimum["state"] == "identified" and minimum["branch_support"] == UNSUPPORTED:
        limitations.append(
            f"The minimum non-affected target {minimum['version']} sits on an unsupported "
            "branch. Non-affected is not the same as supported."
        )
    if transition["requires_compatibility_review"]:
        limitations.append(
            "Whether this transition is supported for this project is not established by any "
            "evidence Drupal Knowledge holds."
        )
    if scope == dk_security.SCOPE_CONTRIB:
        limitations.append(
            "Contrib release and support state is not modelled by the reviewed core release "
            "context, so branch support for this component is not asserted."
        )

    return {
        "component": component,
        "scope": scope,
        "package": package,
        "project_identity": identity,
        "current": {
            "installed_version": installed_version,
            "installed_version_state": "known",
            "branch": current_branch,
            "branch_support": support,
            "declared_constraint": constraint,
            "declared_constraint_state": constraint_state(constraint),
            # The analyzer derives installed versions from composer.lock, so the
            # lock resolution is not a separately observable dimension here.
            "lock_resolution_state": LOCK_NOT_OBSERVABLE,
        },
        "applicable_advisories": advisory_ids,
        "authoritative_remediation": {
            "fixed_versions_by_advisory": fixed_by_advisory,
            "all_fixed_versions": all_fixed,
            "authored_by_drupal_knowledge": False,
        },
        "project_remediation_plan": {
            "minimum_non_affected_target": minimum,
            "recommended_supported_target": recommended,
            "candidates": candidates,
            "transition": transition,
            "constraint_change_required": change_required,
            "steps": build_steps(
                component, installed_version, recommended, transition, change_required, constraint
            ),
            "authored_by_drupal_knowledge": True,
        },
        "limitations": limitations,
    }


def plan(
    analysis: dict,
    root: Path = dk_core.ROOT,
    *,
    target: str | None = None,
    advisory_ids: Iterable[str] | None = None,
    moment: datetime | None = None,
) -> dict:
    """Build a read-only security remediation plan for one project."""
    moment = moment or datetime.now(timezone.utc)
    digest_before = dk_core.knowledge_tree_digest(root)

    evaluation = dk_security.evaluate(analysis, root, advisory_ids=advisory_ids, moment=moment)
    release_state = load_release_state(root)
    facts = evaluation["project"]

    advisories = {item["id"]: item for item in dk_security.iter_advisories(root)}

    # Group by component, not by finding: eighteen core advisories are one
    # core action, not eighteen identical recommendations.
    grouped: dict[tuple[str, str], list[dict]] = {}
    for finding in evaluation["findings"]:
        if finding["state"] != dk_security.FINDING_CONFIRMED:
            continue
        advisory = advisories.get(finding["advisory_id"])
        if advisory is None:
            continue
        package = (
            dk_security.DRUPAL_CORE_PACKAGE
            if finding["scope"] == dk_security.SCOPE_CORE
            else advisory["project"]["composer_package"]
        )
        grouped.setdefault((finding["scope"], package), []).append(advisory)

    components: list[dict] = []
    try:
        for (scope, package), items in sorted(grouped.items()):
            first = items[0]
            if scope == dk_security.SCOPE_CORE:
                installed = facts["core_version"]["value"]
                installed_state = facts["core_version"]["state"]
                component = "Drupal core"
                identity = {
                    "machine_name": dk_security.DRUPAL_CORE_MACHINE_NAME,
                    "resolution": first["project"]["resolution"],
                }
            else:
                entry = next(
                    (
                        item
                        for item in facts["installed_packages"]["packages"]
                        if item["name"] == package
                    ),
                    None,
                )
                installed = entry["version"] if entry else None
                installed_state = entry["version_state"] if entry else "unknown"
                component = package
                identity = {
                    "machine_name": first["project"]["machine_name"],
                    "resolution": first["project"]["resolution"],
                }

            components.append(
                build_component_plan(
                    root,
                    analysis,
                    scope=scope,
                    package=package,
                    component=component,
                    installed_version=installed,
                    installed_state=installed_state,
                    identity=identity,
                    advisories=items,
                    release_state=release_state,
                    operator_target=target,
                )
            )
    except (RemediationInputError, dk_security.SecurityInputError, dk_core.ValidationError):
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise RemediationEngineDefect(
            f"remediation engine defect: {type(exc).__name__}: {exc}"
        ) from exc

    resolved: list[str] = []
    still: list[str] = []
    unpredictable: list[str] = []
    for item in components:
        recommended = item["project_remediation_plan"]["recommended_supported_target"]
        if recommended["state"] == "identified":
            resolved.extend(recommended["resolves_advisories"])
            still.extend(recommended["residual_advisories"])
        else:
            unpredictable.extend(item["applicable_advisories"])

    evaluated_count = len(evaluation["advisories_considered"])
    if not components:
        statement = (
            f"No applicable advisories in the evaluated authoritative set of "
            f"{evaluated_count}. This is a statement about the advisories evaluated, not a "
            "judgement about the project overall."
        )
    else:
        statement = (
            f"Under the recommended targets, {len(set(resolved))} of the applicable advisories "
            f"in the evaluated set of {evaluated_count} would no longer apply, "
            f"{len(set(still))} would remain, and {len(set(unpredictable))} cannot be projected. "
            "This describes the evaluated authoritative set only."
        )

    completeness = determine_completeness(components, facts)
    limitations = [
        "Remediation covers only the advisories in the evaluated authoritative set; advisories "
        "outside it are not considered.",
        "Upgrade compatibility beyond security applicability is not modelled, so a target that "
        "resolves advisories may still require project work.",
        "The analyzer derives installed versions from lock evidence, so lock resolution is not a "
        "separately observable dimension from the installed version.",
    ]

    digest_after = dk_core.knowledge_tree_digest(root)
    if digest_before != digest_after:
        raise RemediationEngineDefect(
            "remediation planning mutated trusted knowledge; this is an engine defect"
        )

    built = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_id": "security-remediation."
        + digest_hex(
            facts["project_id"],
            facts["core_version"]["value"] or "",
            ",".join(sorted(grouped_key[1] for grouped_key in grouped)),
            ",".join(evaluation["advisories_considered"]),
            target or "",
        )[:16],
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "generated_at": now_iso(moment),
        "project": {
            "project_id": facts["project_id"],
            "facts_source": facts["facts_source"],
            "core_version": facts["core_version"]["value"],
            "installed_package_count": facts["installed_packages"]["count"],
            "applicable_finding_count": evaluation["summary"]["confirmed_findings"],
        },
        "evidence_sources": {
            "security_evaluation_id": evaluation["evaluation_id"],
            "advisory_ids": list(evaluation["advisories_considered"]),
            "release_context": release_state["provenance"],
            "analyzer_fact_paths": ["drupal_core_version", "composer_packages"],
        },
        "release_state": {
            "supported_branches": release_state["supported_branches"],
            "newest_supported_stable": newest_supported_stable(release_state),
            "source": release_state["source"],
        },
        "components": components,
        "residual": {
            "evaluated_advisory_count": evaluated_count,
            "resolved_by_recommended_targets": sorted(set(resolved)),
            "still_applicable": sorted(set(still)),
            "unpredictable": sorted(set(unpredictable)),
            "statement": statement,
        },
        "completeness": completeness,
        "limitations": limitations,
        "enforcement": {
            "intent": dk_security.ENFORCEMENT_INTENT,
            "policy_controlled": True,
            "automatically_blocking": False,
            "changed_by_plan": False,
        },
        "execution": {
            "execution_performed": False,
            "project_files_written": False,
            "composer_invoked": False,
            "engine_read_only": True,
        },
        "trusted_knowledge_mutations": [],
    }
    validate_plan(built)
    return built


def determine_completeness(components: list[dict], facts: dict) -> dict:
    """Deterministic completeness. Never a confidence score."""
    reasons: list[str] = []
    if not components:
        return {
            "state": COMPLETENESS_NONE_APPLICABLE,
            "reasons": [
                "No confirmed applicable advisory was found in the evaluated authoritative set."
            ],
        }

    if facts["core_version"]["state"] != "known" or facts["installed_packages"]["state"] != "known":
        reasons.append("The analyzer did not definitively observe core version or package set.")
        return {"state": COMPLETENESS_INSUFFICIENT, "reasons": reasons}

    blocked = [
        item["component"]
        for item in components
        if item["project_remediation_plan"]["recommended_supported_target"]["state"]
        != "identified"
    ]
    if blocked:
        reasons.append(
            "No supported target follows from the evaluated evidence for: "
            + ", ".join(blocked)
        )
        return {"state": COMPLETENESS_BLOCKED_EOL, "reasons": reasons}

    if any(
        item["project_remediation_plan"]["transition"]["requires_compatibility_review"]
        for item in components
    ):
        reasons.append(
            "A recommended target requires a transition whose support Drupal Knowledge cannot "
            "establish from evidence."
        )
        return {"state": COMPLETENESS_COMPAT_REVIEW, "reasons": reasons}

    if any(
        item["project_remediation_plan"]["constraint_change_required"]
        in (UNKNOWN, CONSTRAINT_NOT_OBSERVED)
        for item in components
    ):
        reasons.append("A declared dependency constraint could not be read.")
        return {"state": COMPLETENESS_PARTIAL, "reasons": reasons}

    reasons.append(
        "Every applicable advisory in the evaluated set has a supported target on the branch "
        "already installed."
    )
    return {"state": COMPLETENESS_COMPLETE, "reasons": reasons}


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

# "insecure" must not trip these: there is no word boundary before "secure"
# inside it, so \bsecure\b does not match it.
SAFETY_CLAIM_RE = re.compile(r"\b(secure|safe|invulnerable|fully patched)\b", re.IGNORECASE)


def assert_no_safety_claim(payload: Any, context: str) -> None:
    """A plan may report what no longer applies. It may not declare safety."""
    for value in dk_security_strings(payload):
        if SAFETY_CLAIM_RE.search(value):
            raise dk_core.ValidationError(
                f"{context}: remediation output claims security or safety: {value[:120]!r}"
            )


def dk_security_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        found: list[str] = []
        for item in value.values():
            found.extend(dk_security_strings(item))
        return found
    if isinstance(value, list):
        found = []
        for item in value:
            found.extend(dk_security_strings(item))
        return found
    return [value] if isinstance(value, str) else []


def validate_plan(plan_payload: dict) -> None:
    context = f"remediation plan {plan_payload.get('plan_id', '<unknown>')}"
    required = {
        "schema_version",
        "plan_id",
        "engine",
        "generated_at",
        "project",
        "evidence_sources",
        "release_state",
        "components",
        "residual",
        "completeness",
        "limitations",
        "enforcement",
        "execution",
        "trusted_knowledge_mutations",
    }
    dk_core.assert_keys(plan_payload, required, context)

    if not re.fullmatch(r"security-remediation\.[a-f0-9]{16}", plan_payload["plan_id"]):
        raise dk_core.ValidationError(f"{context}: invalid plan id")

    engine = plan_payload["engine"]
    if engine.get("name") != ENGINE_NAME:
        raise dk_core.ValidationError(f"{context}: unexpected engine name")
    if engine.get("deterministic") is not True:
        raise dk_core.ValidationError(f"{context}: planning must be deterministic")
    if engine.get("language_model_used") is not False:
        raise dk_core.ValidationError(f"{context}: no language model may author a plan")

    # The engine explains remediation. It never performs it.
    execution = plan_payload["execution"]
    for flag in ("execution_performed", "project_files_written", "composer_invoked"):
        if execution.get(flag) is not False:
            raise dk_core.ValidationError(f"{context}: {flag} must be false")
    if execution.get("engine_read_only") is not True:
        raise dk_core.ValidationError(f"{context}: the engine must declare itself read-only")

    # A plan changes no enforcement policy.
    enforcement = plan_payload["enforcement"]
    if enforcement.get("intent") != dk_security.ENFORCEMENT_INTENT:
        raise dk_core.ValidationError(f"{context}: enforcement intent must stay guidance")
    if enforcement.get("automatically_blocking") is not False:
        raise dk_core.ValidationError(f"{context}: a plan may not block automatically")
    if enforcement.get("changed_by_plan") is not False:
        raise dk_core.ValidationError(f"{context}: a plan may not change enforcement")

    if plan_payload["trusted_knowledge_mutations"]:
        raise dk_core.ValidationError(f"{context}: planning may not mutate trusted knowledge")

    if plan_payload["release_state"]["source"] != RELEASE_STATE_SOURCE:
        raise dk_core.ValidationError(
            f"{context}: branch support must come from the reviewed release context"
        )

    valid_completeness = {
        COMPLETENESS_NONE_APPLICABLE,
        COMPLETENESS_COMPLETE,
        COMPLETENESS_PARTIAL,
        COMPLETENESS_BLOCKED_EOL,
        COMPLETENESS_COMPAT_REVIEW,
        COMPLETENESS_INSUFFICIENT,
    }
    if plan_payload["completeness"]["state"] not in valid_completeness:
        raise dk_core.ValidationError(f"{context}: invalid completeness state")

    for component in plan_payload["components"]:
        label = f"{context} component {component.get('component')}"
        authoritative = component["authoritative_remediation"]
        if authoritative["authored_by_drupal_knowledge"] is not False:
            raise dk_core.ValidationError(
                f"{label}: authoritative remediation must not be authored here"
            )
        project_plan = component["project_remediation_plan"]
        if project_plan["authored_by_drupal_knowledge"] is not True:
            raise dk_core.ValidationError(
                f"{label}: the project plan must declare its own authorship"
            )
        for step in project_plan["steps"]:
            if step.get("executed") is not False:
                raise dk_core.ValidationError(f"{label}: a step claims to have been executed")
        for candidate in project_plan["candidates"]:
            if candidate.get("reevaluated_by_security_engine") is not True:
                raise dk_core.ValidationError(
                    f"{label}: every candidate must be re-evaluated by the security engine"
                )
            if candidate["origin"] not in (
                ORIGIN_ADVISORY,
                ORIGIN_SUPPORTED_STABLE,
                ORIGIN_OPERATOR,
            ):
                raise dk_core.ValidationError(f"{label}: candidate origin is not authoritative")
        # A target that is merely non-affected is never presented as recommended.
        recommended = project_plan["recommended_supported_target"]
        if recommended["state"] == "identified" and component["scope"] == dk_security.SCOPE_CORE:
            chosen = next(
                (
                    item
                    for item in project_plan["candidates"]
                    if item["version"] == recommended["version"]
                ),
                None,
            )
            if chosen is None or chosen["branch_support"] != SUPPORTED:
                raise dk_core.ValidationError(
                    f"{label}: a recommended core target must sit on a supported branch"
                )

    assert_no_safety_claim(plan_payload, context)


# ---------------------------------------------------------------------------
# Human rendering
# ---------------------------------------------------------------------------


def render(plan_payload: dict) -> str:
    """Concise human output. Deliberately makes no claim about being secure."""
    lines: list[str] = ["Security remediation", ""]
    project = plan_payload["project"]
    lines.append(f"Project: {project['project_id']}")
    lines.append(f"Drupal core: {project['core_version'] or 'not observed'}")
    lines.append(
        f"Confirmed applicable advisories: {project['applicable_finding_count']} "
        f"of {plan_payload['residual']['evaluated_advisory_count']} evaluated"
    )
    lines.append("")

    if not plan_payload["components"]:
        lines.append(plan_payload["residual"]["statement"])
        lines.append("")
        lines.append("No remediation is required for the advisories evaluated here.")
        lines.append("No project files were changed.")
        return "\n".join(lines)

    release = plan_payload["release_state"]
    lines.append(f"Supported core branches: {', '.join(release['supported_branches'])}")
    lines.append("")

    for component in plan_payload["components"]:
        current = component["current"]
        project_plan = component["project_remediation_plan"]
        minimum = project_plan["minimum_non_affected_target"]
        recommended = project_plan["recommended_supported_target"]
        transition = project_plan["transition"]

        lines.append(f"--- {component['component']} ---")
        lines.append(
            f"Installed: {current['installed_version']} "
            f"(branch {current['branch']}, {current['branch_support']})"
        )
        lines.append(
            f"Applicable advisories: {len(component['applicable_advisories'])} "
            f"-> one action for this component"
        )
        lines.append(
            "Authoritative fixed releases: "
            + (", ".join(component["authoritative_remediation"]["all_fixed_versions"]) or "none stated")
        )
        lines.append(
            f"Minimum non-affected target: {minimum['version'] or 'none available'}"
            + (
                f" (branch {minimum['branch_support']})"
                if minimum["version"]
                else ""
            )
        )
        if recommended["state"] == "identified":
            lines.append(f"Recommended supported target: {recommended['version']}")
        else:
            lines.append(f"Recommended supported target: {recommended['state']}")
        lines.append(f"  {recommended['reason']}")
        lines.append(
            f"Transition: {transition['kind']}, support {transition['supported']}"
            + (" (compatibility review required)" if transition["requires_compatibility_review"] else "")
        )
        lines.append(
            f"Declared constraint: {current['declared_constraint'] or 'not observed'} "
            f"-> constraint change {project_plan['constraint_change_required']}"
        )
        if project_plan["steps"]:
            lines.append("Steps (recommendations only):")
            for step in project_plan["steps"]:
                lines.append(f"  {step['order']}. {step['action']}: {step['detail']}")
        for limitation in component["limitations"]:
            lines.append(f"  - {limitation}")
        lines.append("")

    residual = plan_payload["residual"]
    lines.append("Projected result:")
    lines.append(f"  {residual['statement']}")
    lines.append(f"Completeness: {plan_payload['completeness']['state']}")
    for reason in plan_payload["completeness"]["reasons"]:
        lines.append(f"  - {reason}")
    lines.append("")
    lines.append(
        f"Enforcement: {plan_payload['enforcement']['intent']} "
        "(unchanged by this plan, no blocking policy created)"
    )
    lines.append("No project files were changed. No dependency command was run.")
    return "\n".join(lines)


def validate_remediation_contract(root: Path = dk_core.ROOT) -> list[str]:
    """Validate the remediation schema and engine invariants."""
    dk_core.read_json(root / "schema" / "security-remediation-plan.schema.json")
    state = load_release_state(root)
    if not state["supported_branches"]:
        raise dk_core.ValidationError(
            "remediation requires authoritative supported-branch evidence"
        )
    return [
        "REMEDIATION_CONTRACT_VALID=PASS",
        f"REMEDIATION_ENGINE_VERSION={ENGINE_VERSION}",
        f"REMEDIATION_SUPPORTED_BRANCHES={len(state['supported_branches'])}",
        f"REMEDIATION_SUPPORTED_STABLE_TARGETS={len(newest_supported_stable(state))}",
        "REMEDIATION_ENGINE_READ_ONLY=PASS",
        "REMEDIATION_PLAN_NOT_EXECUTION=PASS",
    ]
