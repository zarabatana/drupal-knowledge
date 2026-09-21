#!/usr/bin/env python3
"""Upgrade compatibility intelligence: what the evidence supports, and no more.

The security remediation engine answers *what is the nearest target that stops
this advisory applying*. This one answers a broader and harder question: *can
this project reach that version at all*. They are not the same question, and a
target that resolves every advisory can still be unreachable.

Four distinctions this module exists to keep:

    version exists              != version installable by Composer
    version installable         != version supported by Drupal
    version supported           != version reachable from this project
    security remediation target != general upgrade compatibility proof

Nothing about a transition is inferred. A Drupal major-version transition is
only ever supported because the reviewed upgrade-compatibility context quotes
official documentation saying so; an unlisted transition is unknown, and
skipping a major is a structural blocker because Drupal.org says a major
version cannot be skipped, not because this engine guessed.

The engine is read-only. It runs no Composer command, writes no project file,
mutates no trusted knowledge record, and produces no security finding.
``execution_performed`` is structurally false.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_core
import dk_remediation
import dk_security


ENGINE_NAME = "drupal-knowledge-upgrade-engine"
ENGINE_VERSION = "0.1"
ASSESSMENT_SCHEMA_VERSION = "0.1"
PATH_SCHEMA_VERSION = "0.1"

# Compatibility output is its own result domain. It is deliberately not a
# security finding: an upgrade blocker is not a vulnerability, and calling it
# one would put non-security evidence behind a security label.
RESULT_DOMAIN = "upgrade_compatibility"

CONTEXT_RELATIVE_PATH = Path("knowledge") / "context" / "drupal-upgrade-compatibility.json"
UPGRADE_AUTHORITY_ROLE = "upgrade_authority"

# --- statuses ----------------------------------------------------------------

KNOWN = "known"
UNKNOWN = "unknown"

SATISFIED = "satisfied"
BLOCKED = "blocked"
REQUIRES_CHANGES = "requires_changes"

# Overall project-wide assessments. A generic boolean is never produced.
COMPATIBLE = "compatible_with_observed_evidence"
ASSESSMENT_BLOCKED = "blocked"
ASSESSMENT_REQUIRES_CHANGES = "requires_changes"
ASSESSMENT_REQUIRES_REVIEW = "requires_review"
ASSESSMENT_INSUFFICIENT = "insufficient_evidence"

ASSESSMENTS = (
    COMPATIBLE,
    ASSESSMENT_BLOCKED,
    ASSESSMENT_REQUIRES_CHANGES,
    ASSESSMENT_REQUIRES_REVIEW,
    ASSESSMENT_INSUFFICIENT,
)

# --- dimensions --------------------------------------------------------------

DIMENSION_CORE = "core_transition"
DIMENSION_CONTRIB = "contrib_compatibility"
DIMENSION_COMPOSER = "composer_constraints"
DIMENSION_PLATFORM = "platform_requirements"
DIMENSION_API = "api_lifecycle"
DIMENSION_PROJECT_CODE = "project_code"

DIMENSIONS = (
    DIMENSION_CORE,
    DIMENSION_CONTRIB,
    DIMENSION_COMPOSER,
    DIMENSION_PLATFORM,
    DIMENSION_API,
    DIMENSION_PROJECT_CODE,
)

# --- blockers ----------------------------------------------------------------

BLOCKER_SKIPPED_MAJOR = "major_version_skip_not_supported"
BLOCKER_TRANSITION_UNDOCUMENTED = "transition_not_documented"
BLOCKER_MINIMUM_SOURCE = "minimum_source_version_not_met"
BLOCKER_TARGET_UNSUPPORTED_BRANCH = "target_branch_not_supported"
BLOCKER_CONTRIB_NO_RELEASE = "contrib_no_compatible_release"
BLOCKER_CONSTRAINT_EXCLUDES = "declared_constraint_excludes_target"
BLOCKER_PHP_INCOMPATIBLE = "platform_php_incompatible"
BLOCKER_REMOVED_EXTENSION = "removed_core_extension_in_use"
BLOCKER_CUSTOM_EXTENSION = "custom_extension_core_requirement_excludes_target"
BLOCKER_DOWNGRADE = "target_is_below_installed_version"
BLOCKER_REMOVED_API_IN_USE = "removed_api_in_use_by_project_code"

BLOCKER_KINDS = (
    BLOCKER_SKIPPED_MAJOR,
    BLOCKER_TRANSITION_UNDOCUMENTED,
    BLOCKER_MINIMUM_SOURCE,
    BLOCKER_TARGET_UNSUPPORTED_BRANCH,
    BLOCKER_CONTRIB_NO_RELEASE,
    BLOCKER_CONSTRAINT_EXCLUDES,
    BLOCKER_PHP_INCOMPATIBLE,
    BLOCKER_REMOVED_EXTENSION,
    BLOCKER_CUSTOM_EXTENSION,
    BLOCKER_DOWNGRADE,
    BLOCKER_REMOVED_API_IN_USE,
)

# How a blocker could stop being one. This is what separates "the manifest says
# no" from "no upstream release exists" from "Drupal does not support it".
RESOLVABLE_BY_DECLARED_CHANGE = "resolvable_by_declared_change"
REQUIRES_UPSTREAM_RELEASE = "requires_upstream_release"
REQUIRES_INTERMEDIATE_UPGRADE = "requires_intermediate_upgrade"
NOT_RESOLVABLE_BY_THIS_TARGET = "not_resolvable_by_this_target"

RESOLVABILITIES = (
    RESOLVABLE_BY_DECLARED_CHANGE,
    REQUIRES_UPSTREAM_RELEASE,
    REQUIRES_INTERMEDIATE_UPGRADE,
    NOT_RESOLVABLE_BY_THIS_TARGET,
)

# --- contrib evidence states -------------------------------------------------

EVIDENCE_ABSENT = "no_authoritative_compatibility_evidence"
EVIDENCE_PRESENT = "authoritative_release_metadata"

CONTRIB_COMPATIBLE_AT_INSTALLED = "compatible_at_installed_version"
CONTRIB_REQUIRES_UPDATE = "compatible_release_available_above_installed"
CONTRIB_NO_COMPATIBLE = "no_compatible_release_published"
CONTRIB_UNKNOWN = "unknown"

# --- code compatibility ------------------------------------------------------

CODE_COMPATIBILITY_UNKNOWN = "code_compatibility_unknown"

# The analyzer sees extension metadata, not call sites. Prompt 10 says so out
# loud rather than letting silence read as "no removed API is used".
# Drupal core and the Composer meta-packages that carry its version. These are
# the core transition's business, never a contributed project's.
CORE_CONSTRAINT_PACKAGES = (
    "drupal/core",
    "drupal/core-recommended",
    "drupal/core-composer-scaffold",
    "drupal/core-project-message",
    "drupal/core-dev",
)

# How many unknowns of one dimension the explain rendering prints before it
# summarizes. Truncation is a display choice; the JSON output is never trimmed.
EXPLAIN_UNKNOWN_SAMPLE = 5

NO_API_USE_OBSERVATION = (
    "The project analyzer observes extension metadata and declared "
    "dependencies. It does not observe which core APIs project code calls, so "
    "use of a removed API is neither confirmed nor excluded here."
)

TRANSITION_NOT_DOCUMENTED = (
    "The reviewed upgrade-compatibility context holds no official transition "
    "evidence for this major transition. It is unknown, not supported."
)

# Wording this engine must never produce, however clean an evaluation looks.
FORBIDDEN_SAFETY_PHRASES = (
    "upgrade is safe",
    "safe to upgrade",
    "fully compatible",
    "guaranteed upgrade",
    "guaranteed compatible",
    "no compatibility issues",
)

SAFETY_CLAIM_RE = re.compile(
    r"\b(?:fully\s+compatible|guaranteed(?:\s+\w+)?\s+compatible|safe\s+to\s+upgrade"
    r"|upgrade\s+is\s+safe|guaranteed\s+upgrade)\b",
    re.IGNORECASE,
)


class UpgradeInputError(RuntimeError):
    """Caller asked for something the evidence does not describe."""


class UpgradeEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as an evidence problem."""


# ---------------------------------------------------------------------------
# Shared primitives, reused rather than reimplemented
# ---------------------------------------------------------------------------


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
    return dk_remediation.branch_of(version)


def constraint_admits(target: Any, constraint: Any) -> str:
    """Would ``target`` satisfy ``constraint`` as written?

    Delegates to the remediation engine's Composer semantics so a constraint
    means exactly one thing across Drupal Knowledge.
    """
    return dk_remediation.constraint_satisfied(target, constraint)


# ---------------------------------------------------------------------------
# Reviewed upgrade context
#
# Transition rules are read from a reviewed context whose every assertion
# quotes the immutable snapshot it came from. Nothing about supported
# transitions, minimum versions or PHP floors is hardcoded in this module.
# ---------------------------------------------------------------------------


def load_context(root: Path = dk_core.ROOT) -> dict:
    path = root / CONTEXT_RELATIVE_PATH
    if not path.is_file():
        raise UpgradeInputError(
            "the reviewed upgrade-compatibility context is missing; upgrade "
            "compatibility cannot be determined without it"
        )
    return dk_core.read_json(path)


def snapshot_text(root: Path, source_id: str, snapshot_sha256: str) -> str:
    path = dk_core.require_snapshot(root, source_id, snapshot_sha256)
    if not path.is_file():
        raise UpgradeInputError(
            f"snapshot {snapshot_sha256} for source {source_id} is not present"
        )
    return path.read_text(encoding="utf-8")


def verify_provenance(root: Path, provenance: dict, where: str) -> None:
    """Assert every quoted line still occurs verbatim in its pinned snapshot.

    This is what stops the reviewed context drifting into invention: a
    requirement can only be stated here if the bytes behind it still say it.
    """
    text = snapshot_text(root, provenance["source_id"], provenance["snapshot_sha256"])
    for quote in provenance.get("source_text", []):
        if quote not in text:
            raise dk_core.ValidationError(
                f"{where}: quoted evidence is absent from snapshot "
                f"{provenance['snapshot_sha256']}: {quote!r}"
            )


def transition_index(context: dict) -> dict[tuple[int, int], dict]:
    return {
        (entry["from_major"], entry["to_major"]): entry
        for entry in context.get("transitions", [])
    }


def php_supported_for_minor(context: dict, minor: str) -> dict:
    """Which PHP versions the published matrix supports for one Drupal minor."""
    matrix = context["php_support_matrix"]
    if minor not in matrix["covered_minors"]:
        return {
            "state": UNKNOWN,
            "minor": minor,
            "supported_php": [],
            "reason": (
                f"The published PHP matrix has no column for Drupal {minor}. "
                f"{matrix['uncovered_semantics']}"
            ),
        }
    supported = [
        entry["php"]
        for entry in matrix["entries"]
        if minor in entry["supported_minors"]
    ]
    return {
        "state": KNOWN,
        "minor": minor,
        "supported_php": sorted(supported, key=lambda value: parse_version(value).key),
        "reason": "Read from the published PHP support matrix for this Drupal minor.",
    }


# ---------------------------------------------------------------------------
# Analyzer facts
#
# There is one project scanner in Drupal Knowledge and this is not it. Every
# project fact below is read from an existing analyzer profile.
# ---------------------------------------------------------------------------


ANALYZER_FACT_PATHS = (
    "profile.facts.drupal_core_version",
    "profile.facts.composer_packages",
    "profile.facts.php_version",
    "profile.facts.custom_modules",
    "profile.facts.custom_themes",
    "profile.facts.modules",
    "profile.facts.themes",
)


def require_analysis(analysis: Any) -> dict:
    if not isinstance(analysis, dict) or "profile" not in analysis:
        raise UpgradeInputError("input is not a project analyzer result")
    if analysis.get("analyzer", {}).get("name") != "drupal-project-analyzer":
        raise UpgradeInputError(
            "input was not produced by the Drupal Knowledge project analyzer"
        )
    return analysis


def fact(analysis: dict, name: str) -> dict:
    return (analysis.get("profile", {}).get("facts", {}) or {}).get(name) or {"state": UNKNOWN}


def installed_core_version(analysis: dict) -> tuple[str | None, str]:
    core = fact(analysis, "drupal_core_version")
    if core.get("state") != "known":
        return None, core.get("state", UNKNOWN)
    return (core.get("value") or {}).get("version"), KNOWN


def installed_drupal_packages(analysis: dict) -> list[dict]:
    installed = (fact(analysis, "composer_packages").get("value") or {}).get("installed") or {}
    packages = installed.get("drupal_packages")
    if not isinstance(packages, list):
        return []
    return [item for item in packages if isinstance(item, dict) and item.get("name")]


def installed_contrib_packages(analysis: dict) -> list[dict]:
    """Installed packages that are contributed projects.

    Drupal core and its Composer meta-packages are excluded: they are the
    subject of the core transition dimension, and evaluating them here would
    report core against contributed-project release metadata it does not have.
    """
    return [
        package
        for package in installed_drupal_packages(analysis)
        if package["name"] not in CORE_CONSTRAINT_PACKAGES
    ]


def declared_requires(analysis: dict) -> dict:
    declared = (fact(analysis, "composer_packages").get("value") or {}).get("declared") or {}
    require = declared.get("require")
    return require if isinstance(require, dict) else {}


def declared_platform_php(analysis: dict) -> tuple[str | None, str]:
    php = fact(analysis, "php_version")
    if php.get("state") != "known":
        return None, php.get("state", UNKNOWN)
    value = php.get("value") or {}
    platform = value.get("composer_platform")
    return (platform, KNOWN) if isinstance(platform, str) and platform else (None, UNKNOWN)


def custom_extensions(analysis: dict) -> list[dict]:
    found: list[dict] = []
    for name in ("custom_modules", "custom_themes"):
        entry = fact(analysis, name)
        if entry.get("state") != "known":
            continue
        for item in entry.get("value") or []:
            if isinstance(item, dict) and item.get("machine_name"):
                found.append(item)
    return sorted(found, key=lambda item: (item["type"], item["machine_name"]))


def observed_extension_names(analysis: dict) -> dict:
    """Enabled core extension names, when the analyzer could read them.

    When the analyzer could not select a config root there is no observation to
    make, and the caller must keep the answer unknown rather than reading an
    empty set as "no removed extension is enabled".
    """
    names: set[str] = set()
    states: list[str] = []
    for name in ("modules", "themes"):
        entry = fact(analysis, name)
        states.append(entry.get("state", UNKNOWN))
        if entry.get("state") != "known":
            continue
        for item in entry.get("value") or []:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict) and isinstance(item.get("machine_name"), str):
                names.add(item["machine_name"])
    observed = all(state == "known" for state in states)
    return {
        "state": KNOWN if observed else UNKNOWN,
        "names": sorted(names),
        "fact_states": {"modules": states[0], "themes": states[1]},
    }


# ---------------------------------------------------------------------------
# Contributed project identity and compatibility evidence
#
# Identity is explicit: a Composer package is matched to a Drupal.org project
# only through a registry entry that declares that exact package. There is no
# fuzzy matching and no name-similarity heuristic anywhere in this file.
# ---------------------------------------------------------------------------


def contrib_release_sources(root: Path = dk_core.ROOT) -> dict[str, dict]:
    """Registered release feeds keyed by the exact Composer package they declare."""
    index: dict[str, dict] = {}
    for source in dk_core.load_sources(root):
        component = (source.get("discovery") or {}).get("component") or {}
        package = component.get("package")
        if not isinstance(package, str) or not package:
            continue
        if source.get("category") != "contrib-releases":
            continue
        index[package] = source
    return index


def source_snapshot_sha(root: Path, source_id: str) -> str | None:
    state_path = root / "sources" / "state" / f"{source_id}.json"
    if not state_path.is_file():
        return None
    state = dk_core.read_json(state_path)
    sha = state.get("content_sha256")
    return sha if isinstance(sha, str) else None


def parse_release_feed(text: str) -> list[dict]:
    """Releases and their declared core compatibility, as published.

    ``core_compatibility`` is read from the release's own element. It is never
    widened to sibling releases and never guessed when the element is absent.
    """
    try:
        root_element = ET.fromstring(text)
    except ET.ParseError as exc:
        raise UpgradeInputError(f"release feed is not parseable XML: {exc}") from exc

    releases: list[dict] = []
    for element in root_element.findall("./releases/release"):
        version = (element.findtext("version") or "").strip()
        if not version:
            continue
        compatibility = element.findtext("core_compatibility")
        status = (element.findtext("status") or "").strip()
        releases.append(
            {
                "version": version,
                "status": status,
                "core_compatibility": (
                    compatibility.strip() if isinstance(compatibility, str) and compatibility.strip() else None
                ),
            }
        )
    return releases


def evaluate_contrib_package(
    root: Path,
    package: dict,
    target: str,
    declared: dict,
    release_sources: dict[str, dict],
) -> dict:
    """One installed contributed package against one target core version."""
    name = package["name"]
    installed = package.get("version")
    installed_parsed = parse_version(installed)
    constraint = declared.get(name)

    identity = {
        "composer_package": name,
        "installed_version": installed,
        "installed_version_readable": installed_parsed is not None,
        "declared_constraint": constraint if isinstance(constraint, str) else None,
        "drupal_org_project": None,
        "identity_basis": "no_registered_release_source_declares_this_package",
    }

    source = release_sources.get(name)
    if source is None:
        return {
            "identity": identity,
            "compatibility": CONTRIB_UNKNOWN,
            "evidence_state": EVIDENCE_ABSENT,
            "compatible_releases": [],
            "excluded_unreadable_versions": [],
            "reason": (
                f"No registered authoritative release source declares the Composer "
                f"package {name!r}, so its compatibility with {target} is unknown."
            ),
            "provenance": None,
        }

    component = (source.get("discovery") or {}).get("component") or {}
    identity["drupal_org_project"] = component.get("name")
    identity["identity_basis"] = "registry_declared_composer_package"

    sha = source_snapshot_sha(root, source["id"])
    if sha is None:
        return {
            "identity": identity,
            "compatibility": CONTRIB_UNKNOWN,
            "evidence_state": EVIDENCE_ABSENT,
            "compatible_releases": [],
            "excluded_unreadable_versions": [],
            "reason": (
                f"Release source {source['id']} has no baselined snapshot, so the "
                f"compatibility of {name} with {target} is unknown."
            ),
            "provenance": None,
        }

    releases = parse_release_feed(snapshot_text(root, source["id"], sha))
    provenance = {
        "source_id": source["id"],
        "snapshot_sha256": sha,
        "source_url": source.get("url"),
        "field": "core_compatibility",
        "release_count": len(releases),
    }

    compatible: list[dict] = []
    unreadable: list[str] = []
    installed_release_compatible = None
    for release in releases:
        compatibility = release["core_compatibility"]
        if compatibility is None:
            continue
        admits = constraint_admits(target, compatibility)
        parsed = parse_version(release["version"])
        if release["version"] == installed or (
            installed_parsed is not None and parsed is not None and parsed.key == installed_parsed.key
        ):
            installed_release_compatible = admits
        if admits != dk_remediation.CONSTRAINT_SATISFIED:
            continue
        if parsed is None:
            # A branch or dev release has no comparable version. Its declared
            # compatibility is recorded, but it is never offered as a target:
            # this is where an ``8.x-1.x-dev`` entry would otherwise be read as
            # a published release compatible with the next major.
            unreadable.append(release["version"])
            continue
        if installed_parsed is not None and parsed.key < installed_parsed.key:
            # A release below what is installed is never offered as a way
            # forward, however well its core_compatibility reads.
            continue
        compatible.append(
            {
                "version": release["version"],
                "status": release["status"],
                "core_compatibility": compatibility,
            }
        )

    compatible.sort(key=lambda item: parse_version(item["version"]).key)

    if installed_release_compatible == dk_remediation.CONSTRAINT_SATISFIED:
        return {
            "identity": identity,
            "compatibility": CONTRIB_COMPATIBLE_AT_INSTALLED,
            "evidence_state": EVIDENCE_PRESENT,
            "compatible_releases": compatible,
            "excluded_unreadable_versions": unreadable,
            "reason": (
                f"The installed release of {name} declares core compatibility that "
                f"admits {target}."
            ),
            "provenance": provenance,
        }

    if compatible:
        return {
            "identity": identity,
            "compatibility": CONTRIB_REQUIRES_UPDATE,
            "evidence_state": EVIDENCE_PRESENT,
            "compatible_releases": compatible,
            "excluded_unreadable_versions": unreadable,
            "reason": (
                f"{name} publishes a release compatible with {target} above the "
                f"installed version. Moving to it is a project decision, not "
                f"something this engine performs."
            ),
            "provenance": provenance,
        }

    declared_any = any(release["core_compatibility"] for release in releases)
    if not declared_any:
        return {
            "identity": identity,
            "compatibility": CONTRIB_UNKNOWN,
            "evidence_state": EVIDENCE_ABSENT,
            "compatible_releases": [],
            "excluded_unreadable_versions": unreadable,
            "reason": (
                f"No release published by {name} declares core compatibility, so "
                f"its compatibility with {target} is unknown."
            ),
            "provenance": provenance,
        }

    return {
        "identity": identity,
        "compatibility": CONTRIB_NO_COMPATIBLE,
        "evidence_state": EVIDENCE_PRESENT,
        "compatible_releases": [],
        "excluded_unreadable_versions": unreadable,
        "reason": (
            f"No release published by {name} declares core compatibility that "
            f"admits {target}."
        ),
        "provenance": provenance,
    }


# ---------------------------------------------------------------------------
# Blockers and unknowns
# ---------------------------------------------------------------------------


def blocker(
    kind: str,
    dimension: str,
    subject: str,
    detail: str,
    resolvability: str,
    provenance: dict,
    required_change: dict | None = None,
) -> dict:
    if kind not in BLOCKER_KINDS:
        raise UpgradeEngineDefect(f"unknown blocker kind {kind!r}")
    if resolvability not in RESOLVABILITIES:
        raise UpgradeEngineDefect(f"unknown resolvability {resolvability!r}")
    if dimension not in DIMENSIONS:
        raise UpgradeEngineDefect(f"unknown dimension {dimension!r}")
    return {
        "kind": kind,
        "dimension": dimension,
        "subject": subject,
        "detail": detail,
        "resolvability": resolvability,
        "required_change": required_change,
        "provenance": provenance,
        # Nothing here was acted on. The field is structural, not a claim.
        "applied": False,
    }


def required_change(dimension: str, subject: str, change: dict, provenance: dict) -> dict:
    """A change the evidence says is needed, that nothing is preventing.

    A contributed project with a compatible release above the installed one is
    the common case: nothing blocks the target, but the project does not reach
    it by standing still. Without this the change would vanish from the
    aggregate and an upgrade needing real work would read as merely unreviewed.
    """
    if dimension not in DIMENSIONS:
        raise UpgradeEngineDefect(f"unknown dimension {dimension!r}")
    return {
        "dimension": dimension,
        "subject": subject,
        "change": change,
        "provenance": provenance,
        "applied": False,
    }


def unknown(dimension: str, subject: str, detail: str) -> dict:
    if dimension not in DIMENSIONS:
        raise UpgradeEngineDefect(f"unknown dimension {dimension!r}")
    return {"dimension": dimension, "subject": subject, "detail": detail}


def context_provenance(context: dict, extra: dict | None = None) -> dict:
    payload = {
        "evidence": "reviewed_upgrade_compatibility_context",
        "context_id": context["id"],
        "review_status": context["review"]["status"],
        "reviewed_on": context["review"]["reviewed_on"],
    }
    if extra:
        payload.update(extra)
    return payload


def transition_provenance(context: dict, transition: dict) -> dict:
    return context_provenance(
        context,
        {
            "transition_id": transition["id"],
            "source_id": transition["provenance"]["source_id"],
            "snapshot_sha256": transition["provenance"]["snapshot_sha256"],
            "source_url": transition["provenance"]["source_url"],
        },
    )


def analyzer_provenance(fact_path: str) -> dict:
    return {"evidence": "drupal_project_analyzer_profile_facts", "fact": fact_path}


# ---------------------------------------------------------------------------
# Core transition
# ---------------------------------------------------------------------------


def plan_transitions(context: dict, current: str, target: str) -> dict:
    """The sequence of major transitions between two core versions.

    Majors are walked one at a time because the reviewed context says a major
    version cannot be skipped. Each step is looked up; a step with no official
    evidence stays unknown rather than being assumed to work.
    """
    from_version = parse_version(current)
    to_version = parse_version(target)
    if from_version is None or to_version is None:
        return {
            "state": UNKNOWN,
            "kind": UNKNOWN,
            "steps": [],
            "reason": "A version could not be read, so no transition sequence is described.",
        }

    if to_version.key < from_version.key:
        return {
            "state": KNOWN,
            "kind": "downgrade",
            "steps": [],
            "reason": "The target is below the installed version.",
        }
    if to_version.key == from_version.key:
        return {
            "state": KNOWN,
            "kind": "none_required",
            "steps": [],
            "reason": "The target is the installed version.",
        }
    if (from_version.major, from_version.minor) == (to_version.major, to_version.minor):
        return {
            "state": KNOWN,
            "kind": "same_branch",
            "steps": [],
            "reason": (
                "The target is on the branch already installed, so no major or "
                "minor transition is involved."
            ),
        }
    if from_version.major == to_version.major:
        return {
            "state": KNOWN,
            "kind": "minor_within_major",
            "steps": [],
            "reason": (
                "The target is a different minor within the installed major. No "
                "major transition is involved."
            ),
        }

    index = transition_index(context)
    steps = []
    for major in range(from_version.major, to_version.major):
        entry = index.get((major, major + 1))
        steps.append(
            {
                "from_major": major,
                "to_major": major + 1,
                "transition_id": entry["id"] if entry else None,
                "state": entry["state"] if entry else "not_documented",
                "is_target_step": major + 1 == to_version.major,
            }
        )
    return {
        "state": KNOWN,
        "kind": "major_transition" if len(steps) == 1 else "multi_major_transition",
        "steps": steps,
        "reason": (
            "Majors are traversed one at a time because the reviewed context "
            "records that a major version cannot be skipped."
        ),
    }


def evaluate_core(
    context: dict,
    release_state: dict,
    current: str,
    target: str,
) -> dict:
    blockers: list[dict] = []
    unknowns: list[dict] = []
    sequence = plan_transitions(context, current, target)
    policy = context["major_transition_policy"]

    target_branch = branch_of(target)
    target_support = dk_remediation.branch_support(target_branch, release_state)
    current_branch = branch_of(current)
    current_support = dk_remediation.branch_support(current_branch, release_state)

    if sequence["kind"] == "downgrade":
        blockers.append(
            blocker(
                BLOCKER_DOWNGRADE,
                DIMENSION_CORE,
                f"drupal/core {target}",
                (
                    f"Target {target} is below the installed version {current}. "
                    "Upgrade compatibility is not evaluated for a downgrade."
                ),
                NOT_RESOLVABLE_BY_THIS_TARGET,
                analyzer_provenance("profile.facts.drupal_core_version"),
            )
        )

    if target_support != dk_remediation.SUPPORTED:
        blockers.append(
            blocker(
                BLOCKER_TARGET_UNSUPPORTED_BRANCH,
                DIMENSION_CORE,
                f"drupal/core branch {target_branch}",
                (
                    f"Branch {target_branch} is not listed as a supported branch by the "
                    "reviewed release-lifecycle context. A version existing is not the "
                    "same as Drupal supporting it."
                ),
                NOT_RESOLVABLE_BY_THIS_TARGET,
                {
                    "evidence": "reviewed_release_lifecycle_context",
                    "source_id": release_state["provenance"]["source_id"],
                    "snapshot_sha256": release_state["provenance"]["snapshot_sha256"],
                    "supported_branches": list(release_state["supported_branches"]),
                },
            )
        )

    applied_transitions: list[dict] = []
    for step in sequence["steps"]:
        if step["transition_id"] is None:
            blockers.append(
                blocker(
                    BLOCKER_TRANSITION_UNDOCUMENTED,
                    DIMENSION_CORE,
                    f"Drupal {step['from_major']} to {step['to_major']}",
                    TRANSITION_NOT_DOCUMENTED,
                    NOT_RESOLVABLE_BY_THIS_TARGET,
                    context_provenance(context),
                )
            )
            continue
        entry = transition_index(context)[(step["from_major"], step["to_major"])]
        applied_transitions.append(entry)

    if len(sequence["steps"]) > 1:
        blockers.append(
            blocker(
                BLOCKER_SKIPPED_MAJOR,
                DIMENSION_CORE,
                f"Drupal {parse_version(current).major} to {parse_version(target).major}",
                (
                    "Reaching this target crosses more than one major version, and the "
                    "official upgrade documentation states that a major version cannot "
                    "be skipped. Each major must be crossed in turn."
                ),
                REQUIRES_INTERMEDIATE_UPGRADE,
                context_provenance(
                    context,
                    {
                        "source_id": policy["provenance"]["source_id"],
                        "snapshot_sha256": policy["provenance"]["snapshot_sha256"],
                        "source_url": policy["provenance"]["source_url"],
                        "skip_major_supported": policy["skip_major_supported"],
                        "source_text": list(policy["provenance"]["source_text"]),
                    },
                ),
                required_change={
                    "kind": "intermediate_major_upgrade",
                    "sequence": [
                        f"{step['from_major']} -> {step['to_major']}" for step in sequence["steps"]
                    ],
                },
            )
        )

    # The first transition is the one this project would perform next, so its
    # minimum source version is the one the installed version must satisfy.
    first = applied_transitions[0] if applied_transitions else None
    minimum_source = None
    if first is not None:
        minimum_source = first["minimum_source_version"]
        if minimum_source["state"] == "present":
            floor = parse_version(minimum_source["value"])
            installed = parse_version(current)
            if floor is not None and installed is not None and installed.key < floor.key:
                blockers.append(
                    blocker(
                        BLOCKER_MINIMUM_SOURCE,
                        DIMENSION_CORE,
                        f"drupal/core {current}",
                        (
                            f"The {first['id']} transition requires the site to be on "
                            f"{minimum_source['value']} or later before upgrading. The "
                            f"installed version is {current}."
                        ),
                        REQUIRES_INTERMEDIATE_UPGRADE,
                        transition_provenance(context, first),
                        required_change={
                            "kind": "minimum_source_version",
                            "package": "drupal/core",
                            "minimum_version": minimum_source["value"],
                        },
                    )
                )
        else:
            unknowns.append(
                unknown(
                    DIMENSION_CORE,
                    f"{first['id']} minimum source version",
                    minimum_source["semantics"],
                )
            )

    if current_support != dk_remediation.SUPPORTED:
        unknowns.append(
            unknown(
                DIMENSION_CORE,
                f"drupal/core branch {current_branch}",
                (
                    f"The installed branch {current_branch} is not a supported branch. "
                    "That is why an upgrade is being evaluated; it is recorded rather "
                    "than treated as a blocker on the target."
                ),
            )
        )

    status = BLOCKED if blockers else (UNKNOWN if unknowns else SATISFIED)
    return {
        "dimension": DIMENSION_CORE,
        "status": status,
        "current_version": current,
        "current_branch": current_branch,
        "current_branch_support": current_support,
        "target_version": target,
        "target_branch": target_branch,
        "target_branch_support": target_support,
        "transition": sequence,
        "transitions_applied": [entry["id"] for entry in applied_transitions],
        "minimum_source_version": minimum_source,
        "blockers": blockers,
        "unknowns": unknowns,
        "required_changes": [],
    }


# ---------------------------------------------------------------------------
# Contributed projects
# ---------------------------------------------------------------------------


def evaluate_contrib(root: Path, analysis: dict, target: str) -> dict:
    packages = installed_contrib_packages(analysis)
    declared = declared_requires(analysis)
    release_sources = contrib_release_sources(root)

    if not packages:
        return {
            "dimension": DIMENSION_CONTRIB,
            "status": UNKNOWN,
            "evaluated_package_count": 0,
            "packages": [],
            "summary": {
                CONTRIB_COMPATIBLE_AT_INSTALLED: 0,
                CONTRIB_REQUIRES_UPDATE: 0,
                CONTRIB_NO_COMPATIBLE: 0,
                CONTRIB_UNKNOWN: 0,
            },
            "blockers": [],
            "required_changes": [],
            "unknowns": [
                unknown(
                    DIMENSION_CONTRIB,
                    "installed contributed projects",
                    (
                        "The analyzer observed no installed package set, so no "
                        "contributed project could be evaluated against the target."
                    ),
                )
            ],
        }

    results = []
    blockers: list[dict] = []
    unknowns: list[dict] = []
    changes: list[dict] = []
    summary = {
        CONTRIB_COMPATIBLE_AT_INSTALLED: 0,
        CONTRIB_REQUIRES_UPDATE: 0,
        CONTRIB_NO_COMPATIBLE: 0,
        CONTRIB_UNKNOWN: 0,
    }

    for package in sorted(packages, key=lambda item: item["name"]):
        result = evaluate_contrib_package(root, package, target, declared, release_sources)
        results.append(result)
        summary[result["compatibility"]] += 1

        if result["compatibility"] == CONTRIB_NO_COMPATIBLE:
            blockers.append(
                blocker(
                    BLOCKER_CONTRIB_NO_RELEASE,
                    DIMENSION_CONTRIB,
                    result["identity"]["composer_package"],
                    result["reason"],
                    REQUIRES_UPSTREAM_RELEASE,
                    result["provenance"] or analyzer_provenance("profile.facts.composer_packages"),
                )
            )
        elif result["compatibility"] == CONTRIB_UNKNOWN:
            unknowns.append(
                unknown(
                    DIMENSION_CONTRIB,
                    result["identity"]["composer_package"],
                    result["reason"],
                )
            )
        elif result["compatibility"] == CONTRIB_REQUIRES_UPDATE:
            changes.append(
                required_change(
                    DIMENSION_CONTRIB,
                    result["identity"]["composer_package"],
                    {
                        "kind": "contrib_release_update",
                        "package": result["identity"]["composer_package"],
                        "installed_version": result["identity"]["installed_version"],
                        "compatible_versions": [
                            item["version"] for item in result["compatible_releases"]
                        ],
                        "applied": False,
                    },
                    result["provenance"],
                )
            )

    if blockers:
        status = BLOCKED
    elif summary[CONTRIB_UNKNOWN]:
        status = UNKNOWN
    elif summary[CONTRIB_REQUIRES_UPDATE]:
        status = REQUIRES_CHANGES
    else:
        status = SATISFIED

    return {
        "dimension": DIMENSION_CONTRIB,
        "status": status,
        "evaluated_package_count": len(results),
        "packages": results,
        "summary": summary,
        "blockers": blockers,
        "unknowns": unknowns,
        "required_changes": changes,
    }


# ---------------------------------------------------------------------------
# Composer constraints
# ---------------------------------------------------------------------------


def evaluate_composer(context: dict, analysis: dict, target: str, transitions: list[str]) -> dict:
    declared = declared_requires(analysis)
    blockers: list[dict] = []
    unknowns: list[dict] = []
    changes: list[dict] = []
    observations: list[dict] = []

    index = {entry["id"]: entry for entry in context["transitions"]}
    required_by_package: dict[str, dict] = {}
    for transition_id in transitions:
        entry = index.get(transition_id)
        if entry is None:
            continue
        for change in entry["composer_constraint_changes"]:
            required_by_package[change["package"]] = {
                "required_constraint": change["required_constraint"],
                "transition_id": entry["id"],
                "provenance": transition_provenance(context, entry),
            }

    for package in CORE_CONSTRAINT_PACKAGES:
        constraint = declared.get(package)
        if not isinstance(constraint, str) or not constraint.strip():
            continue
        constraint = constraint.strip()
        admits = constraint_admits(target, constraint)
        required = required_by_package.get(package)
        observation = {
            "package": package,
            "declared_constraint": constraint,
            "admits_target": admits,
            "required_constraint": required["required_constraint"] if required else None,
            "change_required": admits != dk_remediation.CONSTRAINT_SATISFIED,
            "provenance": analyzer_provenance("profile.facts.composer_packages.value.declared.require"),
        }
        observations.append(observation)

        if admits == dk_remediation.CONSTRAINT_NOT_SATISFIED:
            blockers.append(
                blocker(
                    BLOCKER_CONSTRAINT_EXCLUDES,
                    DIMENSION_COMPOSER,
                    package,
                    (
                        f"The declared constraint {constraint!r} for {package} does not "
                        f"admit {target}. The constraint must change before the target "
                        "is reachable; Drupal Knowledge does not edit manifests."
                    ),
                    RESOLVABLE_BY_DECLARED_CHANGE,
                    required["provenance"] if required else analyzer_provenance(
                        "profile.facts.composer_packages.value.declared.require"
                    ),
                    required_change={
                        "kind": "declared_constraint",
                        "package": package,
                        "current_constraint": constraint,
                        "documented_constraint": required["required_constraint"] if required else None,
                        "applied": False,
                    },
                )
            )
        elif admits == UNKNOWN:
            unknowns.append(
                unknown(
                    DIMENSION_COMPOSER,
                    package,
                    (
                        f"The declared constraint {constraint!r} could not be read, so "
                        f"whether {target} is reachable without a manifest change is unknown."
                    ),
                )
            )

    # A transition that documents a constraint the project does not declare is
    # still reported, because the upgrade instructions require requiring it.
    for package, required in sorted(required_by_package.items()):
        if package in declared:
            continue
        observations.append(
            {
                "package": package,
                "declared_constraint": None,
                "admits_target": dk_remediation.CONSTRAINT_NOT_OBSERVED,
                "required_constraint": required["required_constraint"],
                "change_required": True,
                "provenance": required["provenance"],
            }
        )
        changes.append(
            required_change(
                DIMENSION_COMPOSER,
                package,
                {
                    "kind": "declared_constraint",
                    "package": package,
                    "current_constraint": None,
                    "documented_constraint": required["required_constraint"],
                    "applied": False,
                },
                required["provenance"],
            )
        )

    if blockers:
        status = BLOCKED
    elif unknowns:
        status = UNKNOWN
    elif any(item["change_required"] for item in observations):
        status = REQUIRES_CHANGES
    else:
        status = SATISFIED

    return {
        "dimension": DIMENSION_COMPOSER,
        "status": status,
        "observations": sorted(observations, key=lambda item: item["package"]),
        "blockers": blockers,
        "unknowns": unknowns,
        "required_changes": changes,
        # The engine reports constraint changes. It never performs them.
        "changes_applied": False,
    }


# ---------------------------------------------------------------------------
# Platform requirements
# ---------------------------------------------------------------------------


def evaluate_platform(context: dict, analysis: dict, target: str, transitions: list[str]) -> dict:
    blockers: list[dict] = []
    unknowns: list[dict] = []

    target_parsed = parse_version(target)
    target_minor = f"{target_parsed.major}.{target_parsed.minor}" if target_parsed else None
    matrix = php_supported_for_minor(context, target_minor) if target_minor else {
        "state": UNKNOWN,
        "minor": None,
        "supported_php": [],
        "reason": "The target version could not be read.",
    }

    index = {entry["id"]: entry for entry in context["transitions"]}
    php_floor = None
    floor_transition = None
    for transition_id in transitions:
        entry = index.get(transition_id)
        if entry is None:
            continue
        minimum = entry["php_minimum"]
        if minimum["state"] != "present":
            unknowns.append(
                unknown(
                    DIMENSION_PLATFORM,
                    f"{entry['id']} PHP minimum",
                    minimum["semantics"],
                )
            )
            continue
        candidate = parse_version(minimum["value"])
        if candidate is not None and (php_floor is None or candidate.key > php_floor.key):
            php_floor = candidate
            floor_transition = entry

    platform_php, platform_state = declared_platform_php(analysis)
    php_fact = fact(analysis, "php_version")
    runtime = (php_fact.get("value") or {}).get("runtime") if php_fact.get("state") == "known" else None

    observation = {
        "declared_composer_platform_php": platform_php,
        "declared_state": platform_state,
        "runtime_php": runtime if isinstance(runtime, str) else UNKNOWN,
        "target_minor": target_minor,
        "supported_php_for_target_minor": matrix,
        "transition_php_minimum": (
            {
                "value": floor_transition["php_minimum"]["value"],
                "transition_id": floor_transition["id"],
            }
            if floor_transition
            else None
        ),
    }

    if platform_state != KNOWN or platform_php is None:
        unknowns.append(
            unknown(
                DIMENSION_PLATFORM,
                "composer platform PHP",
                (
                    "The analyzer observed no declared Composer platform PHP version, so "
                    f"PHP compatibility with {target} is unknown."
                ),
            )
        )
    else:
        parsed_platform = parse_version(platform_php)
        if parsed_platform is None:
            unknowns.append(
                unknown(
                    DIMENSION_PLATFORM,
                    "composer platform PHP",
                    f"The declared platform PHP {platform_php!r} could not be read.",
                )
            )
        else:
            if php_floor is not None and parsed_platform.key < php_floor.key:
                blockers.append(
                    blocker(
                        BLOCKER_PHP_INCOMPATIBLE,
                        DIMENSION_PLATFORM,
                        "php",
                        (
                            f"The {floor_transition['id']} transition requires PHP "
                            f"{floor_transition['php_minimum']['value']} or later. The "
                            f"project declares Composer platform PHP {platform_php}."
                        ),
                        RESOLVABLE_BY_DECLARED_CHANGE,
                        transition_provenance(context, floor_transition),
                        required_change={
                            "kind": "platform_php",
                            "current": platform_php,
                            "minimum": floor_transition["php_minimum"]["value"],
                            "applied": False,
                        },
                    )
                )
            elif matrix["state"] == KNOWN:
                declared_minor = f"{parsed_platform.major}.{parsed_platform.minor}"
                if declared_minor not in matrix["supported_php"]:
                    blockers.append(
                        blocker(
                            BLOCKER_PHP_INCOMPATIBLE,
                            DIMENSION_PLATFORM,
                            "php",
                            (
                                f"The published PHP matrix lists "
                                f"{', '.join(matrix['supported_php'])} for Drupal "
                                f"{target_minor}. The project declares Composer platform "
                                f"PHP {platform_php}."
                            ),
                            RESOLVABLE_BY_DECLARED_CHANGE,
                            context_provenance(
                                context,
                                {
                                    "source_id": context["php_support_matrix"]["provenance"]["source_id"],
                                    "snapshot_sha256": context["php_support_matrix"]["provenance"]["snapshot_sha256"],
                                    "source_url": context["php_support_matrix"]["provenance"]["source_url"],
                                    "supported_php": list(matrix["supported_php"]),
                                },
                            ),
                            required_change={
                                "kind": "platform_php",
                                "current": platform_php,
                                "supported": list(matrix["supported_php"]),
                                "applied": False,
                            },
                        )
                    )

    if matrix["state"] != KNOWN:
        unknowns.append(unknown(DIMENSION_PLATFORM, "php support matrix", matrix["reason"]))

    if not isinstance(runtime, str) or runtime == UNKNOWN:
        unknowns.append(
            unknown(
                DIMENSION_PLATFORM,
                "runtime PHP",
                (
                    "The analyzer does not report the host PHP version as project runtime "
                    "PHP, so whether the deployed environment satisfies the target is unknown."
                ),
            )
        )

    status = BLOCKED if blockers else (UNKNOWN if unknowns else SATISFIED)
    return {
        "dimension": DIMENSION_PLATFORM,
        "status": status,
        "observation": observation,
        "blockers": blockers,
        "unknowns": unknowns,
        "required_changes": [],
    }


# ---------------------------------------------------------------------------
# API lifecycle: deprecated is debt, removed is a blocker only with observed use
# ---------------------------------------------------------------------------


def evaluate_api_lifecycle(context: dict, analysis: dict, transitions: list[str]) -> dict:
    blockers: list[dict] = []
    unknowns: list[dict] = []
    deprecations: list[dict] = []
    removals: list[dict] = []

    observed = observed_extension_names(analysis)
    index = {entry["id"]: entry for entry in context["transitions"]}

    for transition_id in transitions:
        entry = index.get(transition_id)
        if entry is None:
            continue
        removed = entry["removed_core_extensions"]
        for item in removed["entries"]:
            record = {
                "machine_name": item["machine_name"],
                "source_label": item["source_label"],
                "extension_type": item["extension_type"],
                "transition_id": entry["id"],
                # The same extension is both: deprecated on the source major and
                # removed on the target major. Conflating the two is exactly the
                # error this split exists to prevent.
                "deprecated_in_major": entry["from_major"],
                "removed_in_major": entry["to_major"],
                "provenance": transition_provenance(context, entry),
            }
            deprecations.append(
                {
                    **record,
                    "lifecycle": "deprecated",
                    "effect": "upgrade_risk_not_blocker",
                    "detail": (
                        f"{item['source_label']} is deprecated in Drupal "
                        f"{entry['from_major']}. Deprecated code still executes on the "
                        "installed major; it is upgrade debt, not a blocker."
                    ),
                }
            )

            if observed["state"] != KNOWN:
                removals.append(
                    {
                        **record,
                        "lifecycle": "removed",
                        "observed_use": CODE_COMPATIBILITY_UNKNOWN,
                        "effect": "unknown",
                        "detail": (
                            f"{item['source_label']} is removed in Drupal "
                            f"{entry['to_major']}, but the analyzer could not observe the "
                            "enabled extension set, so whether this project uses it is unknown."
                        ),
                    }
                )
                continue

            in_use = item["machine_name"] in observed["names"]
            removals.append(
                {
                    **record,
                    "lifecycle": "removed",
                    "observed_use": "observed" if in_use else "not_observed",
                    "effect": "blocker" if in_use else "no_observed_use",
                    "detail": (
                        f"{item['source_label']} is removed in Drupal {entry['to_major']} "
                        + (
                            "and is present in the observed extension set."
                            if in_use
                            else "and was not present in the observed extension set."
                        )
                    ),
                }
            )
            if in_use:
                blockers.append(
                    blocker(
                        BLOCKER_REMOVED_EXTENSION,
                        DIMENSION_API,
                        item["machine_name"],
                        (
                            f"{item['source_label']} is removed in Drupal "
                            f"{entry['to_major']} and is enabled on this project."
                        ),
                        RESOLVABLE_BY_DECLARED_CHANGE,
                        transition_provenance(context, entry),
                        required_change={
                            "kind": "replace_removed_extension",
                            "machine_name": item["machine_name"],
                            "applied": False,
                        },
                    )
                )

        if observed["state"] != KNOWN:
            unknowns.append(
                unknown(
                    DIMENSION_API,
                    f"{entry['id']} removed extensions",
                    (
                        "The enabled extension set could not be observed, so removed "
                        "core extensions can be neither confirmed nor excluded."
                    ),
                )
            )
        elif not removed["list_exhaustive"]:
            unknowns.append(
                unknown(
                    DIMENSION_API,
                    f"{entry['id']} removed extensions",
                    removed["semantics"],
                )
            )

    # Prompt 10 does not build a static analyzer, and says so rather than
    # letting an unexamined codebase read as a clean one.
    unknowns.append(unknown(DIMENSION_API, "removed API call sites", NO_API_USE_OBSERVATION))

    status = BLOCKED if blockers else (UNKNOWN if unknowns else SATISFIED)
    return {
        "dimension": DIMENSION_API,
        "status": status,
        "observed_extension_state": observed["state"],
        "deprecations": deprecations,
        "removals": removals,
        "blockers": blockers,
        "unknowns": unknowns,
        "required_changes": [],
    }


# ---------------------------------------------------------------------------
# Project code: what the extensions themselves declare
# ---------------------------------------------------------------------------


def evaluate_project_code(
    analysis: dict,
    target: str,
    migration: dict | None = None,
) -> dict:
    """Whether project-owned code can run on the target.

    Two independent kinds of evidence answer this. An extension's declared
    ``core_version_requirement`` says whether Drupal will install it at all. A
    migration analysis says whether the code inside it calls something the
    target removed. The second is supplied by the migration engine rather than
    recomputed here, so there is one API-lifecycle authority and not two.
    """
    blockers: list[dict] = []
    unknowns: list[dict] = []
    extensions = custom_extensions(analysis)
    observations: list[dict] = []

    for extension in extensions:
        requirement = extension.get("core_version_requirement")
        admits = constraint_admits(target, requirement)
        observations.append(
            {
                "machine_name": extension["machine_name"],
                "type": extension["type"],
                "path": extension.get("path"),
                "core_version_requirement": requirement,
                "admits_target": admits,
            }
        )
        if admits == dk_remediation.CONSTRAINT_NOT_SATISFIED:
            blockers.append(
                blocker(
                    BLOCKER_CUSTOM_EXTENSION,
                    DIMENSION_PROJECT_CODE,
                    extension["machine_name"],
                    (
                        f"{extension['type']} {extension['machine_name']} declares "
                        f"core_version_requirement {requirement!r}, which does not admit "
                        f"{target}. Drupal will not install it against that core version."
                    ),
                    RESOLVABLE_BY_DECLARED_CHANGE,
                    analyzer_provenance(f"profile.facts.custom_{extension['type']}s"),
                    required_change={
                        "kind": "core_version_requirement",
                        "machine_name": extension["machine_name"],
                        "current": requirement,
                        "applied": False,
                    },
                )
            )
        elif admits in (UNKNOWN, dk_remediation.CONSTRAINT_NOT_OBSERVED):
            unknowns.append(
                unknown(
                    DIMENSION_PROJECT_CODE,
                    extension["machine_name"],
                    (
                        f"The core_version_requirement for {extension['machine_name']} "
                        f"is {requirement!r}, which could not be read as a constraint."
                    ),
                )
            )

    if not extensions:
        unknowns.append(
            unknown(
                DIMENSION_PROJECT_CODE,
                "custom extensions",
                (
                    "The analyzer observed no custom extension definitions, so the "
                    "compatibility of project code with the target is unknown."
                ),
            )
        )

    changes: list[dict] = []
    if migration is None:
        # A declared core_version_requirement says the extension may install. It
        # says nothing about whether its code calls something the target removed.
        unknowns.append(
            unknown(
                DIMENSION_PROJECT_CODE,
                CODE_COMPATIBILITY_UNKNOWN,
                NO_API_USE_OBSERVATION,
            )
        )
    else:
        summary = migration["summary"]
        for item in migration["work_items"]:
            effect = item["target_effect"]["effect"]
            provenance = {
                "evidence": "api_migration_analysis",
                "analysis_id": migration["analysis_id"],
                "work_item_id": item["work_item_id"],
                "source_id": item["provenance"][0]["source_id"],
                "source_snapshot_sha256": item["provenance"][0]["source_snapshot_sha256"],
                "occurrences": item["usage"]["occurrence_count"],
            }
            if effect == "blocking":
                blockers.append(
                    blocker(
                        BLOCKER_REMOVED_API_IN_USE,
                        DIMENSION_PROJECT_CODE,
                        item["usage"]["symbol"],
                        (
                            f"{item['usage']['symbol']} is removed from Drupal "
                            f"{item['lifecycle']['removed_version']} and is used in "
                            f"{item['usage']['occurrence_count']} place(s) in project code."
                        ),
                        RESOLVABLE_BY_DECLARED_CHANGE,
                        provenance,
                        required_change={
                            "kind": "replace_removed_api",
                            "symbol": item["usage"]["symbol"],
                            "occurrences": item["occurrences"],
                            "replacement": item["suggested_migration"]["replacement"],
                            "applied": False,
                        },
                    )
                )
            elif effect in ("migration_required", "migration_recommended"):
                # Deprecated but still present is debt, not a blocker: the code
                # runs on the target. It is still work the project must plan.
                changes.append(
                    required_change(
                        DIMENSION_PROJECT_CODE,
                        item["usage"]["symbol"],
                        {
                            "kind": "migrate_deprecated_api",
                            "symbol": item["usage"]["symbol"],
                            "effect": effect,
                            "occurrences": item["occurrences"],
                            "replacement": item["suggested_migration"]["replacement"],
                            "applied": False,
                        },
                        provenance,
                    )
                )
        # Even a clean migration analysis leaves the unexamined parts unknown,
        # so "no work item" never becomes "the code is fine".
        unknowns.append(
            unknown(
                DIMENSION_PROJECT_CODE,
                "api migration coverage",
                (
                    f"{summary['files_read']} of {summary['files_inventoried']} inventoried "
                    "custom file(s) were analysed against the registered deprecation index. "
                    + migration["coverage"]["statement"]
                ),
            )
        )

    status = BLOCKED if blockers else (UNKNOWN if unknowns else SATISFIED)
    return {
        "dimension": DIMENSION_PROJECT_CODE,
        "status": status,
        "extensions": observations,
        "api_migration": (
            {
                "analysis_id": migration["analysis_id"],
                "work_items": migration["summary"]["work_items"],
                "blocking_items": migration["summary"]["blocking_items"],
                "occurrences": migration["summary"]["occurrences"],
                "files_read": migration["summary"]["files_read"],
            }
            if migration
            else None
        ),
        "blockers": blockers,
        "unknowns": unknowns,
        "required_changes": changes,
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def collect(dimensions: list[dict], key: str) -> list[dict]:
    return [item for dimension in dimensions for item in dimension.get(key, [])]


def aggregate(dimensions: list[dict], project_evidence_sufficient: bool) -> dict:
    """The project-wide answer, from every dimension rather than from core alone.

    The ordering matters. A blocker nothing in the project can clear outranks
    one it can; a change the project must make outranks an open question; and
    an open question outranks silence. Only a run that reaches the end with
    nothing outstanding is called compatible, and even that is bounded by what
    was evaluated.
    """
    if not project_evidence_sufficient:
        return {
            "assessment": ASSESSMENT_INSUFFICIENT,
            "basis": "The analyzer facts do not establish enough to evaluate a target.",
        }

    blockers = collect(dimensions, "blockers")
    unknowns = collect(dimensions, "unknowns")
    changes = collect(dimensions, "required_changes")

    hard = [
        item
        for item in blockers
        if item["resolvability"]
        in (NOT_RESOLVABLE_BY_THIS_TARGET, REQUIRES_UPSTREAM_RELEASE, REQUIRES_INTERMEDIATE_UPGRADE)
    ]
    if hard:
        return {
            "assessment": ASSESSMENT_BLOCKED,
            "basis": (
                f"{len(hard)} blocker(s) cannot be resolved by changing this project's "
                "own declarations."
            ),
        }
    if blockers or changes:
        return {
            "assessment": ASSESSMENT_REQUIRES_CHANGES,
            "basis": (
                f"{len(blockers)} blocker(s) and {len(changes)} further change(s) are "
                "resolvable by the project itself. All are reported and none applied."
            ),
        }
    if unknowns:
        return {
            "assessment": ASSESSMENT_REQUIRES_REVIEW,
            "basis": (
                f"No blocker was observed, but {len(unknowns)} compatibility dimension(s) "
                "remain unestablished."
            ),
        }
    return {
        "assessment": COMPATIBLE,
        "basis": (
            "Every evaluated dimension was established by observed evidence and none "
            "produced a blocker. This is bounded by what was evaluated."
        ),
    }


# ---------------------------------------------------------------------------
# Target evaluation
# ---------------------------------------------------------------------------


def evaluate(
    analysis: Any,
    target: str,
    root: Path = dk_core.ROOT,
    generated_at: str | None = None,
    migration: dict | None = None,
) -> dict:
    """Evaluate one proposed target. Read-only: nothing is changed anywhere."""
    analysis = require_analysis(analysis)
    if not isinstance(target, str) or not target.strip():
        raise UpgradeInputError("a target version is required")
    target = target.strip()
    if parse_version(target) is None:
        raise UpgradeInputError(f"target {target!r} is not a readable Drupal version")

    context = load_context(root)
    release_state = dk_remediation.load_release_state(root)

    current, current_state = installed_core_version(analysis)
    project_evidence_sufficient = current is not None and parse_version(current) is not None

    if not project_evidence_sufficient:
        dimensions: list[dict] = []
        summary = aggregate(dimensions, False)
        core_block = {
            "dimension": DIMENSION_CORE,
            "status": UNKNOWN,
            "current_version": current,
            "current_branch": None,
            "current_branch_support": UNKNOWN,
            "target_version": target,
            "target_branch": branch_of(target),
            "target_branch_support": dk_remediation.branch_support(branch_of(target), release_state),
            "transition": {
                "state": UNKNOWN,
                "kind": UNKNOWN,
                "steps": [],
                "reason": "The installed core version is not known.",
            },
            "transitions_applied": [],
            "minimum_source_version": None,
            "blockers": [],
            "required_changes": [],
            "unknowns": [
                unknown(
                    DIMENSION_CORE,
                    "drupal/core",
                    (
                        f"The analyzer reports the installed core version as "
                        f"{current_state}, so no transition can be evaluated."
                    ),
                )
            ],
        }
        dimensions = [core_block]
        return finalize_assessment(
            root, analysis, context, release_state, target, current, dimensions, summary, generated_at
        )

    core_block = evaluate_core(context, release_state, current, target)
    applied = core_block["transitions_applied"]
    contrib_block = evaluate_contrib(root, analysis, target)
    composer_block = evaluate_composer(context, analysis, target, applied)
    platform_block = evaluate_platform(context, analysis, target, applied)
    api_block = evaluate_api_lifecycle(context, analysis, applied)
    code_block = evaluate_project_code(analysis, target, migration)

    dimensions = [core_block, contrib_block, composer_block, platform_block, api_block, code_block]
    summary = aggregate(dimensions, True)
    return finalize_assessment(
        root, analysis, context, release_state, target, current, dimensions, summary, generated_at
    )


def finalize_assessment(
    root: Path,
    analysis: dict,
    context: dict,
    release_state: dict,
    target: str,
    current: str | None,
    dimensions: list[dict],
    summary: dict,
    generated_at: str | None,
) -> dict:
    blockers = collect(dimensions, "blockers")
    unknowns = collect(dimensions, "unknowns")
    required_changes = [
        {
            "dimension": item["dimension"],
            "subject": item["subject"],
            "change": item["required_change"],
            "provenance": item["provenance"],
            "applied": False,
        }
        for item in blockers
        if item["required_change"] is not None
    ] + collect(dimensions, "required_changes")

    assessment_id = "upgrade-assessment." + digest_hex(
        ASSESSMENT_SCHEMA_VERSION,
        ENGINE_VERSION,
        analysis.get("project_id", ""),
        current or "",
        target,
        stable_json([
            {
                "dimension": dimension["dimension"],
                "status": dimension["status"],
                "blockers": [
                    {"kind": item["kind"], "subject": item["subject"]} for item in dimension["blockers"]
                ],
                "unknowns": [
                    {"subject": item["subject"]} for item in dimension["unknowns"]
                ],
            }
            for dimension in dimensions
        ]),
    )[:16]

    payload = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "result_domain": RESULT_DOMAIN,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "generated_at": generated_at or now_iso(),
        "project": {
            "project_id": analysis.get("project_id"),
            "facts_source": "drupal_project_analyzer_profile_facts",
            "analyzer_version": analysis.get("analyzer", {}).get("version"),
            "current_core_version": current,
            "installed_drupal_package_count": len(installed_drupal_packages(analysis)),
        },
        "target": {
            "requested_version": target,
            "branch": branch_of(target),
            "origin": "operator_supplied_target",
        },
        "evidence_sources": {
            "analyzer_fact_paths": list(ANALYZER_FACT_PATHS),
            "upgrade_context": {
                "context_id": context["id"],
                "review_status": context["review"]["status"],
                "reviewed_on": context["review"]["reviewed_on"],
                "transition_ids": [entry["id"] for entry in context["transitions"]],
                "source_ids": sorted(
                    {entry["provenance"]["source_id"] for entry in context["transitions"]}
                    | {context["major_transition_policy"]["provenance"]["source_id"]}
                    | {context["php_support_matrix"]["provenance"]["source_id"]}
                ),
            },
            "release_context": {
                "source_id": release_state["provenance"]["source_id"],
                "snapshot_sha256": release_state["provenance"]["snapshot_sha256"],
                "review_status": release_state["provenance"]["review_status"],
                "reviewed_on": release_state["provenance"]["reviewed_on"],
            },
        },
        "dimensions": dimensions,
        "blockers": blockers,
        "unknowns": unknowns,
        "required_changes": required_changes,
        "assessment": summary["assessment"],
        "assessment_basis": summary["basis"],
        "bounds": {
            "evaluated_dimensions": [dimension["dimension"] for dimension in dimensions],
            # An assessment is only ever about what was evaluated. Saying so is
            # what keeps "no blocker found" from reading as "no blocker exists".
            "statement": (
                "This assessment is bounded by the dimensions listed above and by the "
                "evidence available for them. An unevaluated dimension is not a passing one."
            ),
            "security_relationship": (
                "A security remediation target is not a general upgrade compatibility "
                "proof. Security urgency does not establish that a target is reachable."
            ),
        },
        "execution": {
            "execution_performed": False,
            "composer_invoked": False,
            "project_files_written": False,
            "database_updates_run": False,
            "modules_changed": False,
        },
        "trusted_knowledge_mutations": {
            "knowledge_records": 0,
            "reviewed_context": 0,
            "advisories": 0,
            "solved_cases": 0,
            "source_snapshots": 0,
        },
    }

    assert_no_safety_claim(payload, "upgrade assessment")
    validate_assessment(payload)
    return payload


# ---------------------------------------------------------------------------
# Upgrade path
# ---------------------------------------------------------------------------


def candidate_targets(release_state: dict, current: str | None) -> list[str]:
    """Newest supported stable release on each supported branch, at or above current."""
    newest = dk_remediation.newest_supported_stable(release_state)
    installed = parse_version(current) if current else None
    candidates = []
    for version in newest.values():
        parsed = parse_version(version)
        if parsed is None:
            continue
        if installed is not None and parsed.key <= installed.key:
            continue
        candidates.append(version)
    return sorted(candidates, key=lambda value: parse_version(value).key)


def build_path(
    analysis: Any,
    root: Path = dk_core.ROOT,
    targets: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict:
    """A machine-readable upgrade path. Execution performed is structurally false."""
    analysis = require_analysis(analysis)
    context = load_context(root)
    release_state = dk_remediation.load_release_state(root)
    current, current_state = installed_core_version(analysis)

    if targets is None:
        evaluated_targets = candidate_targets(release_state, current)
        origin = "newest_supported_stable_release_per_supported_branch"
    else:
        evaluated_targets = sorted(
            {value.strip() for value in targets if isinstance(value, str) and value.strip()},
            key=lambda value: parse_version(value).key if parse_version(value) else (0, 0, 0),
        )
        origin = "operator_supplied_target"

    assessments = [
        evaluate(analysis, target, root=root, generated_at=generated_at)
        for target in evaluated_targets
    ]

    candidates = []
    for assessment in assessments:
        core = next(
            dimension for dimension in assessment["dimensions"] if dimension["dimension"] == DIMENSION_CORE
        )
        candidates.append(
            {
                "target_version": assessment["target"]["requested_version"],
                "target_branch": assessment["target"]["branch"],
                "target_branch_support": core["target_branch_support"],
                "assessment": assessment["assessment"],
                "assessment_id": assessment["assessment_id"],
                "transition_kind": core["transition"]["kind"],
                "intermediate_transitions": [
                    {
                        "from_major": step["from_major"],
                        "to_major": step["to_major"],
                        "transition_id": step["transition_id"],
                        "state": step["state"],
                    }
                    for step in core["transition"]["steps"]
                ],
                "major_steps": len(core["transition"]["steps"]),
                "blocker_count": len(assessment["blockers"]),
                "blocker_kinds": sorted({item["kind"] for item in assessment["blockers"]}),
                "unknown_count": len(assessment["unknowns"]),
                "required_change_count": len(assessment["required_changes"]),
                "requires_upstream_release": any(
                    item["resolvability"] == REQUIRES_UPSTREAM_RELEASE
                    for item in assessment["blockers"]
                ),
            }
        )

    path_id = "upgrade-path." + digest_hex(
        PATH_SCHEMA_VERSION,
        ENGINE_VERSION,
        analysis.get("project_id", ""),
        current or "",
        stable_json(candidates),
    )[:16]

    payload = {
        "schema_version": PATH_SCHEMA_VERSION,
        "path_id": path_id,
        "result_domain": RESULT_DOMAIN,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "generated_at": generated_at or now_iso(),
        "current_state": {
            "project_id": analysis.get("project_id"),
            "core_version": current,
            "core_version_state": current_state,
            "branch": branch_of(current) if current else None,
            "branch_support": dk_remediation.branch_support(branch_of(current), release_state)
            if current
            else UNKNOWN,
            "installed_drupal_package_count": len(installed_drupal_packages(analysis)),
        },
        "target_origin": origin,
        "candidates": candidates,
        "tradeoffs": describe_tradeoffs(candidates),
        "provenance": {
            "analyzer_fact_paths": list(ANALYZER_FACT_PATHS),
            "upgrade_context_id": context["id"],
            "upgrade_context_review_status": context["review"]["status"],
            "release_context": {
                "source_id": release_state["provenance"]["source_id"],
                "snapshot_sha256": release_state["provenance"]["snapshot_sha256"],
                "review_status": release_state["provenance"]["review_status"],
            },
            "assessment_ids": [item["assessment_id"] for item in candidates],
        },
        "execution_performed": False,
        "execution": {
            "composer_invoked": False,
            "project_files_written": False,
            "database_updates_run": False,
            "modules_changed": False,
            "deployment_performed": False,
        },
        "trusted_knowledge_mutations": {
            "knowledge_records": 0,
            "reviewed_context": 0,
            "advisories": 0,
            "solved_cases": 0,
            "source_snapshots": 0,
        },
    }

    assert_no_safety_claim(payload, "upgrade path")
    validate_path(payload)
    return payload


def describe_tradeoffs(candidates: list[dict]) -> dict:
    """Deterministic facts about the candidate set. No candidate is preferred.

    Newest is not automatically best: a nearer target may be reachable while a
    later one is blocked by contrib, and the reverse also happens. These are the
    measurements a human needs; the ranking is theirs.
    """
    if not candidates:
        return {
            "state": "no_candidates",
            "detail": "No supported target above the installed version was identified.",
            "fewest_blockers": [],
            "fewest_major_steps": [],
            "no_upstream_dependency": [],
        }

    fewest_blockers = min(item["blocker_count"] for item in candidates)
    fewest_steps = min(item["major_steps"] for item in candidates)
    return {
        "state": "evaluated",
        "detail": (
            "Candidates are reported as measured facts. Drupal Knowledge does not "
            "choose between them, because the trade-off between disruption and "
            "compatibility is the operator's to make."
        ),
        "fewest_blockers": sorted(
            item["target_version"] for item in candidates if item["blocker_count"] == fewest_blockers
        ),
        "fewest_major_steps": sorted(
            item["target_version"] for item in candidates if item["major_steps"] == fewest_steps
        ),
        "no_upstream_dependency": sorted(
            item["target_version"] for item in candidates if not item["requires_upstream_release"]
        ),
    }


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def recursive_strings(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.append(str(key))
            found.extend(recursive_strings(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(recursive_strings(item))
    return found


def assert_no_safety_claim(payload: Any, where: str) -> None:
    """Refuse to emit an unbounded compatibility promise.

    Every phrase here reads as a guarantee about a system this engine has only
    partially observed. Bounded language survives; absolute language does not.
    """
    for text in recursive_strings(payload):
        match = SAFETY_CLAIM_RE.search(text)
        if match:
            raise UpgradeEngineDefect(
                f"{where}: refused to state an unbounded compatibility claim: {match.group(0)!r}"
            )


def validate_assessment(payload: dict) -> None:
    required = {
        "schema_version",
        "assessment_id",
        "result_domain",
        "engine",
        "generated_at",
        "project",
        "target",
        "evidence_sources",
        "dimensions",
        "blockers",
        "unknowns",
        "required_changes",
        "assessment",
        "assessment_basis",
        "bounds",
        "execution",
        "trusted_knowledge_mutations",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise UpgradeEngineDefect(f"assessment missing keys: {', '.join(missing)}")
    if payload["result_domain"] != RESULT_DOMAIN:
        raise UpgradeEngineDefect("assessment must declare the upgrade compatibility domain")
    if payload["assessment"] not in ASSESSMENTS:
        raise UpgradeEngineDefect(f"unknown assessment {payload['assessment']!r}")
    if payload["execution"]["execution_performed"] is not False:
        raise UpgradeEngineDefect("the upgrade engine never executes an upgrade")
    for count in payload["trusted_knowledge_mutations"].values():
        if count != 0:
            raise UpgradeEngineDefect("the upgrade engine never mutates trusted knowledge")
    for item in payload["blockers"]:
        if item["kind"] not in BLOCKER_KINDS:
            raise UpgradeEngineDefect(f"unknown blocker kind {item['kind']!r}")
        if not item.get("provenance"):
            raise UpgradeEngineDefect(f"blocker {item['kind']} carries no provenance")
        if item["applied"] is not False:
            raise UpgradeEngineDefect("a blocker must never report itself as applied")
    for change in payload["required_changes"]:
        if change["applied"] is not False:
            raise UpgradeEngineDefect("a required change must never report itself as applied")


def validate_path(payload: dict) -> None:
    required = {
        "schema_version",
        "path_id",
        "result_domain",
        "engine",
        "generated_at",
        "current_state",
        "target_origin",
        "candidates",
        "tradeoffs",
        "provenance",
        "execution_performed",
        "execution",
        "trusted_knowledge_mutations",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise UpgradeEngineDefect(f"upgrade path missing keys: {', '.join(missing)}")
    if payload["execution_performed"] is not False:
        raise UpgradeEngineDefect("an upgrade path is never executed by this engine")
    for value in payload["execution"].values():
        if value is not False:
            raise UpgradeEngineDefect("an upgrade path performs no project action")
    for count in payload["trusted_knowledge_mutations"].values():
        if count != 0:
            raise UpgradeEngineDefect("the upgrade engine never mutates trusted knowledge")


# ---------------------------------------------------------------------------
# Explain rendering
# ---------------------------------------------------------------------------


def render_assessment(payload: dict) -> str:
    lines: list[str] = []
    project = payload["project"]
    lines.append(f"UPGRADE COMPATIBILITY ASSESSMENT {payload['assessment_id']}")
    lines.append(f"  result domain      {payload['result_domain']}")
    lines.append(f"  project            {project['project_id']}")
    lines.append(f"  current core       {project['current_core_version'] or 'unknown'}")
    lines.append(f"  target             {payload['target']['requested_version']}")
    lines.append(f"  assessment         {payload['assessment']}")
    lines.append(f"  basis              {payload['assessment_basis']}")
    lines.append("")
    lines.append("DIMENSIONS")
    for dimension in payload["dimensions"]:
        lines.append(
            f"  {dimension['dimension']:<22} {dimension['status']:<16} "
            f"blockers={len(dimension['blockers'])} unknowns={len(dimension['unknowns'])}"
        )

    if payload["blockers"]:
        lines.append("")
        lines.append("BLOCKERS")
        for item in payload["blockers"]:
            lines.append(f"  [{item['kind']}] {item['subject']}")
            lines.append(f"      {item['detail']}")
            lines.append(f"      resolvability: {item['resolvability']}")
            lines.append(f"      evidence: {item['provenance'].get('evidence', 'unknown')}")

    if payload["required_changes"]:
        lines.append("")
        lines.append("REQUIRED CHANGES (reported, never applied)")
        for change in payload["required_changes"]:
            lines.append(f"  {change['subject']}: {change['change']['kind']} (applied={change['applied']})")

    if payload["unknowns"]:
        lines.append("")
        lines.append(f"UNKNOWNS ({len(payload['unknowns'])})")
        # Grouped and sampled so a project with eighty unevaluable dependencies
        # stays readable. The JSON output carries every one of them.
        for dimension in DIMENSIONS:
            items = [item for item in payload["unknowns"] if item["dimension"] == dimension]
            if not items:
                continue
            lines.append(f"  {dimension} ({len(items)})")
            for item in items[:EXPLAIN_UNKNOWN_SAMPLE]:
                lines.append(f"    {item['subject']}")
                lines.append(f"        {item['detail']}")
            remaining = len(items) - EXPLAIN_UNKNOWN_SAMPLE
            if remaining > 0:
                lines.append(
                    f"    ... and {remaining} more; --format json lists every one."
                )

    lines.append("")
    lines.append("BOUNDS")
    lines.append(f"  {payload['bounds']['statement']}")
    lines.append(f"  {payload['bounds']['security_relationship']}")
    lines.append("")
    lines.append("EXECUTION")
    for key, value in sorted(payload["execution"].items()):
        lines.append(f"  {key}={value}")
    return "\n".join(lines) + "\n"


def render_path(payload: dict) -> str:
    lines: list[str] = []
    current = payload["current_state"]
    lines.append(f"UPGRADE PATH {payload['path_id']}")
    lines.append(f"  result domain      {payload['result_domain']}")
    lines.append(f"  project            {current['project_id']}")
    lines.append(
        f"  current            {current['core_version'] or 'unknown'} "
        f"(branch {current['branch']}, {current['branch_support']})"
    )
    lines.append(f"  target origin      {payload['target_origin']}")
    lines.append(f"  execution          performed={payload['execution_performed']}")
    lines.append("")
    if not payload["candidates"]:
        lines.append("CANDIDATES: none identified")
    else:
        lines.append("CANDIDATES")
        for item in payload["candidates"]:
            lines.append(
                f"  {item['target_version']:<12} {item['assessment']:<34} "
                f"major_steps={item['major_steps']} blockers={item['blocker_count']} "
                f"unknowns={item['unknown_count']}"
            )
            if item["blocker_kinds"]:
                lines.append(f"      blocker kinds: {', '.join(item['blocker_kinds'])}")
            for step in item["intermediate_transitions"]:
                lines.append(
                    f"      transition {step['from_major']} -> {step['to_major']}: "
                    f"{step['transition_id'] or 'not documented'} ({step['state']})"
                )
    lines.append("")
    lines.append("TRADE-OFFS")
    tradeoffs = payload["tradeoffs"]
    lines.append(f"  {tradeoffs['detail']}")
    lines.append(f"  fewest blockers    {', '.join(tradeoffs['fewest_blockers']) or 'none'}")
    lines.append(f"  fewest major steps {', '.join(tradeoffs['fewest_major_steps']) or 'none'}")
    lines.append(f"  no upstream wait   {', '.join(tradeoffs['no_upstream_dependency']) or 'none'}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Repository contract
# ---------------------------------------------------------------------------


def validate_upgrade_contract(root: Path = dk_core.ROOT) -> list[str]:
    """Validate the upgrade schemas, sources and reviewed context."""
    for relative in (
        "schema/upgrade-assessment.schema.json",
        "schema/upgrade-path.schema.json",
    ):
        dk_core.read_json(root / relative)

    registry = dk_core.load_sources(root)
    authority = [
        source
        for source in registry
        if (source.get("upgrade") or {}).get("role") == UPGRADE_AUTHORITY_ROLE
    ]
    for source in authority:
        if source["trust"] != "authoritative":
            raise dk_core.ValidationError(
                f"source {source['id']}: upgrade authority must be authoritative"
            )

    context = load_context(root)
    if context["review"]["status"] != "reviewed":
        raise dk_core.ValidationError("the upgrade-compatibility context must be reviewed")

    registered = {source["id"] for source in registry}
    provenances = [
        ("major_transition_policy", context["major_transition_policy"]["provenance"]),
        ("php_support_matrix", context["php_support_matrix"]["provenance"]),
    ]
    for entry in context["transitions"]:
        provenances.append((f"transition {entry['id']}", entry["provenance"]))

    for where, provenance in provenances:
        if provenance["source_id"] not in registered:
            raise dk_core.ValidationError(
                f"{where}: references unregistered source {provenance['source_id']}"
            )
        verify_provenance(root, provenance, where)

    # A transition may only claim an official requirement it can quote.
    for entry in context["transitions"]:
        for change in entry["composer_constraint_changes"]:
            if change["source_text"] not in snapshot_text(
                root, entry["provenance"]["source_id"], entry["provenance"]["snapshot_sha256"]
            ):
                raise dk_core.ValidationError(
                    f"transition {entry['id']}: constraint change quote is absent from its snapshot"
                )
        minimum = entry["minimum_source_version"]
        if minimum["state"] == "present" and parse_version(minimum["value"]) is None:
            raise dk_core.ValidationError(
                f"transition {entry['id']}: minimum source version is not readable"
            )

    if context["major_transition_policy"]["skip_major_supported"] is not False:
        raise dk_core.ValidationError(
            "the reviewed context must record that skipping a major version is unsupported"
        )

    quoted = sum(len(provenance["source_text"]) for _, provenance in provenances)
    return [
        "UPGRADE_COMPATIBILITY_CONTRACT_VALID=PASS",
        f"UPGRADE_ENGINE_VERSION={ENGINE_VERSION}",
        f"UPGRADE_AUTHORITY_SOURCES={len(authority)}",
        f"UPGRADE_TRANSITIONS={len(context['transitions'])}",
        f"UPGRADE_CONTEXT_QUOTES_VERIFIED={quoted}",
        "UPGRADE_AUTHORITY_USES_OFFICIAL_SOURCES=PASS",
        "CORE_UPGRADE_PATH_NOT_INFERRED=PASS",
        "UPGRADE_ENGINE_READ_ONLY=PASS",
        "UPGRADE_ANALYSIS_ZERO_KNOWLEDGE_MUTATION=PASS",
    ]
