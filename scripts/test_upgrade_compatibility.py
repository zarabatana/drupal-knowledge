#!/usr/bin/env python3
"""The upgrade engine reports what the evidence supports, and nothing else.

The matrix below is the one that decides whether this engine is useful or
dangerous. A supported patch move, a documented major transition, a skipped
major, and then the three contributed-project cases that matter most: evidenced
compatible, evidenced incompatible, and no evidence at all. The third is the
one a careless engine turns into a pass.

Then the two halves of API lifecycle. A deprecated extension still runs, so it
is debt. A removed extension only blocks when its use is actually observed —
authoritative removal plus an unobservable project is unknown, never a blocker
and never a pass.

Running through all of it: no file is written, no Composer command runs, no
knowledge record moves, and no sentence promises the upgrade will be fine.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_core
import dk_remediation as R
import dk_upgrade as U


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"


# --- fixtures ----------------------------------------------------------------


def analysis(
    core_version: str | None = "10.6.0",
    *,
    installed: list[dict] | None = None,
    require: dict | None = None,
    platform_php: str | None = "8.3.0",
    custom: list[dict] | None = None,
    modules: dict | None = None,
    themes: dict | None = None,
) -> dict:
    """An analyzer profile in the exact shape the real analyzer emits."""
    core_fact = (
        {
            "state": "known",
            "confidence": "high",
            "value": {"package": "drupal/core", "version": core_version},
        }
        if core_version
        else {"state": "unknown", "notes": "no installed core package evidence"}
    )
    packages = list(installed or [])
    php_fact = (
        {
            "state": "known",
            "confidence": "high",
            "value": {
                "composer_platform": platform_php,
                "composer_requirement": ">=8.1",
                "runtime": "unknown",
            },
        }
        if platform_php
        else {"state": "unknown", "notes": "no declared platform php"}
    )
    return {
        "schema_version": "0.1",
        "project_id": "fixture/upgrade",
        "analyzer": {
            "name": "drupal-project-analyzer",
            "version": "0.1",
            "mode": "static-file-inspection",
        },
        "profile": {
            "schema_version": "0.1",
            "project_id": "fixture/upgrade",
            "facts": {
                "drupal_core_version": core_fact,
                "php_version": php_fact,
                "composer_packages": {
                    "state": "known",
                    "confidence": "high",
                    "value": {
                        "declared": {"require": dict(require or {})},
                        "installed": {
                            "available": True,
                            "drupal_packages": packages,
                            "packages": packages,
                            "counts": {"drupal_packages": len(packages)},
                        },
                    },
                },
                "custom_modules": (
                    {"state": "known", "confidence": "medium", "value": list(custom or [])}
                    if custom is not None
                    else {"state": "unknown", "notes": "no custom extension roots"}
                ),
                "custom_themes": {"state": "unknown", "notes": "no custom theme roots"},
                "modules": modules or {"state": "unknown", "notes": "no config root selected"},
                "themes": themes or {"state": "unknown", "notes": "no config root selected"},
            },
        },
        "evidence": [],
        "completeness": {},
        "unknowns": [],
        "diagnostics": [],
    }


def package(name: str, version: str) -> dict:
    return {"dev": False, "name": name, "type": "drupal-module", "version": version}


def blockers_of(assessment: dict, kind: str) -> list[dict]:
    return [item for item in assessment["blockers"] if item["kind"] == kind]


def dimension(assessment: dict, name: str) -> dict:
    return next(item for item in assessment["dimensions"] if item["dimension"] == name)


# The real supported set at the pinned reviewed context, so the fixtures below
# argue about compatibility rather than about which branches Drupal supports.
RELEASE_STATE = R.load_release_state(ROOT)
SUPPORTED = set(RELEASE_STATE["supported_branches"])
assert {"10.6", "11.3", "11.4"} <= SUPPORTED, sorted(SUPPORTED)


# --- fixture: supported same-major upgrade -----------------------------------
# A minor move inside one major, with nothing else in the way. This is the only
# shape allowed to come back compatible, and even then only for what was
# evaluated.

same_major = U.evaluate(
    analysis(
        "11.3.16",
        # Token 1.15.0 publishes ^9.2 || ^10 || ^11, so this dependency needs no
        # move to reach an 11.4 target. That is the point of the fixture.
        installed=[package("drupal/token", "1.15.0")],
        require={"drupal/core-recommended": "^11"},
        custom=[
            {
                "machine_name": "fixture_module",
                "type": "module",
                "path": "web/modules/custom/fixture_module/fixture_module.info.yml",
                "core_version_requirement": "^10 || ^11",
            }
        ],
        modules={"state": "known", "value": ["node", "user"]},
        themes={"state": "known", "value": ["olivero"]},
    ),
    "11.4.6",
)
assert same_major["assessment"] in (U.COMPATIBLE, U.ASSESSMENT_REQUIRES_REVIEW), same_major["assessment"]
core = dimension(same_major, U.DIMENSION_CORE)
assert core["status"] == U.SATISFIED, core
assert core["transition"]["kind"] == "minor_within_major"
assert core["transition"]["steps"] == []
assert not same_major["blockers"], same_major["blockers"]
assert not same_major["required_changes"], same_major["required_changes"]
token = next(
    item
    for item in dimension(same_major, U.DIMENSION_CONTRIB)["packages"]
    if item["identity"]["composer_package"] == "drupal/token"
)
assert token["compatibility"] == U.CONTRIB_COMPATIBLE_AT_INSTALLED
print("SUPPORTED_SAME_MAJOR_UPGRADE=PASS")


# The same move with an older dependency is not the same answer. Nothing blocks
# it, but the project does not reach the target by standing still, so it is
# reported as a required change rather than as an open question.
stale_dependency = U.evaluate(
    analysis(
        "11.3.16",
        installed=[package("drupal/token", "1.11.0")],
        require={"drupal/core-recommended": "^11"},
        modules={"state": "known", "value": ["node"]},
        themes={"state": "known", "value": ["olivero"]},
    ),
    "11.4.6",
)
assert stale_dependency["assessment"] == U.ASSESSMENT_REQUIRES_CHANGES
update = next(
    item for item in stale_dependency["required_changes"] if item["subject"] == "drupal/token"
)
assert update["change"]["kind"] == "contrib_release_update"
assert update["change"]["installed_version"] == "1.11.0"
assert update["change"]["compatible_versions"], "the evidenced versions are named"
assert update["applied"] is False
assert not stale_dependency["blockers"], "an available update is not a blocker"
print("AVAILABLE_CONTRIB_UPDATE_IS_A_REPORTED_CHANGE=PASS")


# --- fixture: supported major transition -------------------------------------
# Authoritative evidence explicitly allows 10 -> 11. The transition is applied
# by id, and the id traces to the snapshot the requirement was quoted from.

major = U.evaluate(
    analysis(
        "10.6.0",
        installed=[package("drupal/token", "1.17.0")],
        require={"drupal/core-recommended": "^10"},
        platform_php="8.3.0",
    ),
    "11.4.6",
)
core = dimension(major, U.DIMENSION_CORE)
assert core["transition"]["kind"] == "major_transition"
assert core["transitions_applied"] == ["10-to-11"], core["transitions_applied"]
assert core["minimum_source_version"]["value"] == "10.3.0"
assert not blockers_of(major, U.BLOCKER_SKIPPED_MAJOR)
assert not blockers_of(major, U.BLOCKER_TRANSITION_UNDOCUMENTED)
# The transition is documented, so the constraint change it documents is
# reported as a required change rather than being silently accepted.
constraint_blockers = blockers_of(major, U.BLOCKER_CONSTRAINT_EXCLUDES)
assert constraint_blockers, "a ^10 constraint cannot admit an 11.x target"
assert constraint_blockers[0]["required_change"]["documented_constraint"] == "^11"
assert constraint_blockers[0]["provenance"]["source_id"] == "drupal-upgrade-10-to-11"
print("SUPPORTED_MAJOR_TRANSITION=PASS")


# --- fixture: unsupported skipped major --------------------------------------
# Nothing here is assumed. Skipping a major is a blocker because the reviewed
# context quotes Drupal.org saying it cannot be done, and the required change is
# the intermediate sequence rather than a shrug.

skipped = U.evaluate(
    analysis("9.5.9", require={"drupal/core": "^9.3"}, platform_php="8.1.0"),
    "11.4.6",
)
skip_blockers = blockers_of(skipped, U.BLOCKER_SKIPPED_MAJOR)
assert skip_blockers, "a 9 -> 11 target must not be treated as reachable"
assert skip_blockers[0]["resolvability"] == U.REQUIRES_INTERMEDIATE_UPGRADE
assert skip_blockers[0]["required_change"]["sequence"] == ["9 -> 10", "10 -> 11"]
assert skip_blockers[0]["provenance"]["skip_major_supported"] is False
assert skipped["assessment"] == U.ASSESSMENT_BLOCKED
core = dimension(skipped, U.DIMENSION_CORE)
assert [step["transition_id"] for step in core["transition"]["steps"]] == ["9-to-10", "10-to-11"]
print("UNSUPPORTED_SKIPPED_MAJOR_NOT_ASSUMED=PASS")


# An undocumented transition is unknown, not supported. Drupal 12 to 13 has no
# entry, so a target beyond it produces a blocker rather than an assumption.
undocumented = U.evaluate(analysis("12.0.0"), "13.0.0")
assert blockers_of(undocumented, U.BLOCKER_TRANSITION_UNDOCUMENTED)
assert undocumented["assessment"] == U.ASSESSMENT_BLOCKED
print("UNDOCUMENTED_TRANSITION_IS_NOT_SUPPORT=PASS")


# --- fixture: contrib compatible ---------------------------------------------
# Token 1.11.0 declares ^9.2 || ^10 on its own release. That admits 10.6, and
# the answer names the field and snapshot it was read from.

contrib_ok = U.evaluate(
    analysis("10.5.0", installed=[package("drupal/token", "1.11.0")], require={"drupal/core-recommended": "^10"}),
    "10.6.16",
)
contrib = dimension(contrib_ok, U.DIMENSION_CONTRIB)
token = next(item for item in contrib["packages"] if item["identity"]["composer_package"] == "drupal/token")
assert token["compatibility"] == U.CONTRIB_COMPATIBLE_AT_INSTALLED, token
assert token["evidence_state"] == U.EVIDENCE_PRESENT
assert token["provenance"]["field"] == "core_compatibility"
assert token["provenance"]["source_id"] == "drupal-contrib-token-releases"
assert token["identity"]["identity_basis"] == "registry_declared_composer_package"
print("CONTRIB_COMPATIBLE_IS_EVIDENCED=PASS")


# --- fixture: contrib incompatible -------------------------------------------
# No published Token release declares compatibility with Drupal 13, so the
# answer is an explicit blocker that only an upstream release can clear.

contrib_bad = U.evaluate(
    analysis("11.4.0", installed=[package("drupal/token", "1.17.0")]),
    "12.0.0",
)
contrib = dimension(contrib_bad, U.DIMENSION_CONTRIB)
token = next(item for item in contrib["packages"] if item["identity"]["composer_package"] == "drupal/token")
assert token["compatibility"] == U.CONTRIB_NO_COMPATIBLE, token
blocked = blockers_of(contrib_bad, U.BLOCKER_CONTRIB_NO_RELEASE)
assert blocked, "an incompatible contributed project must block explicitly"
assert blocked[0]["resolvability"] == U.REQUIRES_UPSTREAM_RELEASE
assert blocked[0]["subject"] == "drupal/token"
assert contrib_bad["assessment"] == U.ASSESSMENT_BLOCKED
print("CONTRIB_INCOMPATIBLE_IS_EXPLICIT_BLOCKER=PASS")


# --- fixture: contrib unknown ------------------------------------------------
# The decisive case. No registered source declares this package, so there is no
# authoritative compatibility evidence. That is unknown. It is not a blocker,
# and it is emphatically not a pass.

contrib_unknown = U.evaluate(
    analysis(
        "10.6.0",
        installed=[package("drupal/webform", "6.2.0")],
        require={"drupal/core-recommended": "^10", "drupal/webform": "^6.2"},
    ),
    "10.6.16",
)
contrib = dimension(contrib_unknown, U.DIMENSION_CONTRIB)
webform = next(
    item for item in contrib["packages"] if item["identity"]["composer_package"] == "drupal/webform"
)
assert webform["compatibility"] == U.CONTRIB_UNKNOWN
assert webform["evidence_state"] == U.EVIDENCE_ABSENT
assert webform["identity"]["identity_basis"] == "no_registered_release_source_declares_this_package"
assert webform["identity"]["declared_constraint"] == "^6.2"
assert contrib["status"] == U.UNKNOWN
assert not blockers_of(contrib_unknown, U.BLOCKER_CONTRIB_NO_RELEASE)
assert contrib_unknown["assessment"] != U.COMPATIBLE, "unknown contrib must never read as compatible"
assert any(item["subject"] == "drupal/webform" for item in contrib_unknown["unknowns"])
print("CONTRIB_UNKNOWN_STAYS_UNKNOWN=PASS")


# Identity is explicit, never fuzzy. A package whose name merely resembles a
# registered one gets no evidence from it.
near_miss = U.evaluate(
    analysis("10.6.0", installed=[package("drupal/token_custom", "1.3.0")]),
    "10.6.16",
)
contrib = dimension(near_miss, U.DIMENSION_CONTRIB)
entry = next(
    item for item in contrib["packages"] if item["identity"]["composer_package"] == "drupal/token_custom"
)
assert entry["compatibility"] == U.CONTRIB_UNKNOWN, "token_custom must not borrow token's evidence"
assert entry["identity"]["drupal_org_project"] is None
print("CONTRIB_IDENTITY_IS_NOT_FUZZY_MATCHED=PASS")


# --- fixture: Composer blocker -----------------------------------------------
# A declared constraint that excludes the target is a blocker with a required
# change attached. The change is reported; it is never written to a manifest.

composer_blocked = U.evaluate(
    analysis("10.6.0", require={"drupal/core": "^9.3.11"}),
    "10.6.16",
)
excludes = blockers_of(composer_blocked, U.BLOCKER_CONSTRAINT_EXCLUDES)
assert excludes, "a ^9.3.11 constraint cannot admit a 10.6.16 target"
assert excludes[0]["resolvability"] == U.RESOLVABLE_BY_DECLARED_CHANGE
assert excludes[0]["required_change"]["current_constraint"] == "^9.3.11"
assert excludes[0]["required_change"]["applied"] is False
assert dimension(composer_blocked, U.DIMENSION_COMPOSER)["changes_applied"] is False
assert all(change["applied"] is False for change in composer_blocked["required_changes"])
print("COMPOSER_CONSTRAINT_BLOCKER_REPORTED_NOT_APPLIED=PASS")


# An unreadable constraint is unknown, never assumed permissive.
unreadable = U.evaluate(analysis("10.6.0", require={"drupal/core": "dev-main"}), "10.6.16")
composer = dimension(unreadable, U.DIMENSION_COMPOSER)
assert composer["status"] == U.UNKNOWN, composer
assert not blockers_of(unreadable, U.BLOCKER_CONSTRAINT_EXCLUDES)
print("UNREADABLE_CONSTRAINT_IS_UNKNOWN=PASS")


# --- fixture: deprecated API is debt, not a blocker --------------------------
# Book is deprecated in Drupal 10 and removed in Drupal 11. On a project that
# does not enable it, the deprecation is still reported as risk, and it does
# not block.

deprecated = U.evaluate(
    analysis(
        "10.6.0",
        require={"drupal/core-recommended": "^11"},
        modules={"state": "known", "value": ["node", "user", "views"]},
        themes={"state": "known", "value": ["olivero"]},
    ),
    "11.4.6",
)
api = dimension(deprecated, U.DIMENSION_API)
book_deprecation = next(item for item in api["deprecations"] if item["machine_name"] == "book")
assert book_deprecation["lifecycle"] == "deprecated"
assert book_deprecation["effect"] == "upgrade_risk_not_blocker"
assert book_deprecation["deprecated_in_major"] == 10
assert book_deprecation["removed_in_major"] == 11
book_removal = next(item for item in api["removals"] if item["machine_name"] == "book")
assert book_removal["observed_use"] == "not_observed"
assert book_removal["effect"] == "no_observed_use"
assert not blockers_of(deprecated, U.BLOCKER_REMOVED_EXTENSION)
# Deprecated and removed are separate records for the same extension, never one
# collapsed judgement.
assert book_deprecation["lifecycle"] != book_removal["lifecycle"]
print("DEPRECATED_IS_RISK_NOT_BLOCKER=PASS")
print("DEPRECATED_AND_REMOVED_ARE_DISTINCT=PASS")


# --- fixture: removed API with confirmed use ---------------------------------
# Authoritative removal plus observed use. Only both together make a blocker.

removed = U.evaluate(
    analysis(
        "10.6.0",
        require={"drupal/core-recommended": "^11"},
        modules={"state": "known", "value": ["node", "book", "forum"]},
        themes={"state": "known", "value": ["olivero"]},
    ),
    "11.4.6",
)
removal_blockers = blockers_of(removed, U.BLOCKER_REMOVED_EXTENSION)
assert {item["subject"] for item in removal_blockers} == {"book", "forum"}, removal_blockers
assert removal_blockers[0]["provenance"]["source_id"] == "drupal-upgrade-10-to-11"
api = dimension(removed, U.DIMENSION_API)
assert next(item for item in api["removals"] if item["machine_name"] == "book")["observed_use"] == "observed"
print("REMOVED_API_BLOCKS_ONLY_WITH_OBSERVED_USE=PASS")


# --- fixture: missing code-use evidence --------------------------------------
# The project analyzer could not select a config root, so the enabled extension
# set is unobservable. Every removal becomes unknown. None becomes a pass.

unobservable = U.evaluate(
    analysis("10.6.0", require={"drupal/core-recommended": "^11"}),
    "11.4.6",
)
api = dimension(unobservable, U.DIMENSION_API)
assert api["observed_extension_state"] == U.UNKNOWN
assert api["removals"], "removals are still reported when use is unobservable"
for record in api["removals"]:
    assert record["observed_use"] == U.CODE_COMPATIBILITY_UNKNOWN, record
    assert record["effect"] == "unknown"
assert not blockers_of(unobservable, U.BLOCKER_REMOVED_EXTENSION)
assert api["status"] == U.UNKNOWN
assert unobservable["assessment"] != U.COMPATIBLE
print("MISSING_CODE_USE_EVIDENCE_IS_UNKNOWN_NOT_PASS=PASS")


# Project code compatibility stays unknown even when every extension declares a
# requirement that admits the target: a declared requirement is not a claim
# about call sites.
code = dimension(
    U.evaluate(
        analysis(
            "10.6.0",
            custom=[
                {
                    "machine_name": "ok_module",
                    "type": "module",
                    "path": "web/modules/custom/ok_module/ok_module.info.yml",
                    "core_version_requirement": "^10 || ^11",
                }
            ],
        ),
        "10.6.16",
    ),
    U.DIMENSION_PROJECT_CODE,
)
assert code["status"] == U.UNKNOWN
assert any(item["subject"] == U.CODE_COMPATIBILITY_UNKNOWN for item in code["unknowns"])
print("UNKNOWN_CODE_COMPATIBILITY_REMAINS_UNKNOWN=PASS")


# A custom extension whose own declaration excludes the target is a real,
# observed blocker, and it is attributed to project code rather than to contrib.
custom_blocked = U.evaluate(
    analysis(
        "9.5.9",
        custom=[
            {
                "machine_name": "legacy_module",
                "type": "module",
                "path": "web/modules/custom/legacy_module/legacy_module.info.yml",
                "core_version_requirement": "^8 || ^9",
            }
        ],
    ),
    "10.6.16",
)
custom_blockers = blockers_of(custom_blocked, U.BLOCKER_CUSTOM_EXTENSION)
assert custom_blockers and custom_blockers[0]["dimension"] == U.DIMENSION_PROJECT_CODE
assert custom_blockers[0]["required_change"]["current"] == "^8 || ^9"
print("CUSTOM_EXTENSION_REQUIREMENT_IS_OBSERVED_EVIDENCE=PASS")


# --- platform requirements ---------------------------------------------------
# The PHP floor comes from the transition page; the per-minor matrix comes from
# the requirements page. Neither is guessed, and a major outside the published
# matrix stays unknown.

php_blocked = U.evaluate(
    analysis("10.6.0", require={"drupal/core-recommended": "^11"}, platform_php="8.1.0"),
    "11.4.6",
)
php_blockers = blockers_of(php_blocked, U.BLOCKER_PHP_INCOMPATIBLE)
assert php_blockers, "PHP 8.1 cannot satisfy the 10-to-11 floor of 8.3.0"
assert php_blockers[0]["required_change"]["minimum"] == "8.3.0"
assert php_blockers[0]["provenance"]["source_id"] == "drupal-upgrade-10-to-11"

context = U.load_context(ROOT)
assert U.php_supported_for_minor(context, "9.5")["state"] == U.UNKNOWN
assert U.php_supported_for_minor(context, "11.4")["supported_php"] == ["8.3", "8.4", "8.5"]
print("PLATFORM_REQUIREMENTS_ARE_SOURCED_NOT_GUESSED=PASS")


# --- version existence is not compatibility ----------------------------------
# 12.0.0-alpha1 exists in the release feed. That is not the same as 12.0 being
# a supported branch a project can be moved to.

existing_not_supported = U.evaluate(analysis("11.4.0"), "13.0.0")
unsupported = blockers_of(existing_not_supported, U.BLOCKER_TARGET_UNSUPPORTED_BRANCH)
assert unsupported, "an unsupported branch must be refused as a target"
assert unsupported[0]["provenance"]["evidence"] == "reviewed_release_lifecycle_context"
assert "13.0" not in unsupported[0]["provenance"]["supported_branches"]
print("VERSION_EXISTENCE_IS_NOT_UPGRADE_COMPATIBILITY=PASS")


# A downgrade is never offered as an upgrade path.
downgrade = U.evaluate(analysis("11.4.6"), "10.6.16")
assert blockers_of(downgrade, U.BLOCKER_DOWNGRADE)
assert downgrade["assessment"] == U.ASSESSMENT_BLOCKED
print("DOWNGRADE_IS_NOT_AN_UPGRADE_TARGET=PASS")


# --- insufficient project evidence -------------------------------------------
# With no installed core version there is nothing to evaluate a transition
# against, and the result says so instead of defaulting either way.

blind = U.evaluate(analysis(None), "11.4.6")
assert blind["assessment"] == U.ASSESSMENT_INSUFFICIENT
assert blind["project"]["current_core_version"] is None
assert dimension(blind, U.DIMENSION_CORE)["status"] == U.UNKNOWN
print("INSUFFICIENT_PROJECT_EVIDENCE_IS_ITS_OWN_ANSWER=PASS")


# --- aggregation --------------------------------------------------------------
# Core supporting a target is never enough on its own. The same core transition
# produces different project-wide answers as the other dimensions change.

base = dict(
    core_version="10.6.0",
    # Every constraint the 10-to-11 page documents, already declared at ^11, so
    # the only thing varying below is the non-core dimension.
    require={
        "drupal/core-recommended": "^11",
        "drupal/core-composer-scaffold": "^11",
        "drupal/core-project-message": "^11",
    },
    platform_php="8.3.0",
    modules={"state": "known", "value": ["node"]},
    themes={"state": "known", "value": ["olivero"]},
)
clean = U.evaluate(analysis(**base), "11.4.6")
with_custom_code = U.evaluate(
    analysis(
        **base,
        custom=[
            {
                "machine_name": "legacy_module",
                "type": "module",
                "path": "web/modules/custom/legacy_module/legacy_module.info.yml",
                "core_version_requirement": "^9 || ^10",
            }
        ],
    ),
    "11.4.6",
)
core_status = dimension(clean, U.DIMENSION_CORE)["status"]
assert core_status == dimension(with_custom_code, U.DIMENSION_CORE)["status"] == U.SATISFIED
# Identical, satisfied core transition; different project-wide answers. Core
# supporting a target is never the same as the project reaching it.
assert clean["assessment"] == U.ASSESSMENT_REQUIRES_REVIEW, clean["assessment"]
assert with_custom_code["assessment"] == U.ASSESSMENT_REQUIRES_CHANGES
# And a hard blocker in one non-core dimension decides the whole answer.
assert contrib_bad["assessment"] == U.ASSESSMENT_BLOCKED
assert blockers_of(contrib_bad, U.BLOCKER_CONTRIB_NO_RELEASE)[0]["dimension"] == U.DIMENSION_CONTRIB
print("PROJECT_COMPATIBILITY_IS_AGGREGATED_EVIDENCE=PASS")


# Every blocker carries provenance and a resolvability, and every dimension is
# represented in the aggregate.
for assessment in (skipped, contrib_bad, composer_blocked, removed, php_blocked):
    for item in assessment["blockers"]:
        assert item["provenance"], item
        assert item["resolvability"] in U.RESOLVABILITIES, item
        assert item["dimension"] in U.DIMENSIONS, item
        assert item["applied"] is False
    assert assessment["assessment"] in U.ASSESSMENTS
print("UPGRADE_BLOCKERS_MACHINE_READABLE=PASS")
print("UPGRADE_RECOMMENDATION_PROVENANCE_MACHINE_READABLE=PASS")


# --- upgrade path -------------------------------------------------------------

path = U.build_path(analysis("9.5.9", require={"drupal/core": "^9.3.11"}, platform_php="7.4.0"), ROOT)
assert path["execution_performed"] is False
assert path["current_state"]["branch_support"] == R.UNSUPPORTED
assert path["candidates"], "supported targets above 9.5.9 exist in the reviewed context"

by_version = {item["target_version"]: item for item in path["candidates"]}
ten = next(item for version, item in by_version.items() if version.startswith("10.6."))
eleven = next(item for version, item in by_version.items() if version.startswith("11.4."))
# The nearer target needs one major step; the later one needs two and is blocked
# for that reason. Newest is not automatically best, and the path says so with
# measurements rather than a preference.
assert ten["major_steps"] == 1 and eleven["major_steps"] == 2
assert U.BLOCKER_SKIPPED_MAJOR in eleven["blocker_kinds"]
assert U.BLOCKER_SKIPPED_MAJOR not in ten["blocker_kinds"]
assert eleven["assessment"] == U.ASSESSMENT_BLOCKED
assert path["tradeoffs"]["fewest_major_steps"] == [ten["target_version"]]
for candidate in path["candidates"]:
    assert candidate["assessment_id"] in path["provenance"]["assessment_ids"]
    for step in candidate["intermediate_transitions"]:
        assert step["to_major"] - step["from_major"] == 1, "majors are crossed one at a time"
print("UPGRADE_PATH_MACHINE_READABLE=PASS")
print("UPGRADE_TARGET_SELECTION_EXPLAINS_TRADEOFFS=PASS")


# Determinism: the same facts produce the same identity, and a changed fact
# produces a different one.
again = U.build_path(
    analysis("9.5.9", require={"drupal/core": "^9.3.11"}, platform_php="7.4.0"),
    ROOT,
    generated_at=path["generated_at"],
)
assert again["path_id"] == path["path_id"]
assert (
    U.build_path(
        analysis("9.5.9", require={"drupal/core": "^10"}, platform_php="7.4.0"),
        ROOT,
        generated_at=path["generated_at"],
    )["path_id"]
    != path["path_id"]
)
print("UPGRADE_OUTPUT_IS_DETERMINISTIC=PASS")


# --- the engine writes nothing ------------------------------------------------
# Run every entry point against a copy of the repository tree and prove the
# tree is byte-identical afterwards.

TRACKED = ("knowledge", "sources", "security", "cases", "schema", "generated", "discovery")


def tree_state(root: Path) -> dict[str, str]:
    import hashlib

    state = {}
    for directory in TRACKED:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file():
                state[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return state


before = tree_state(ROOT)
sample = analysis(
    "9.5.9",
    installed=[package("drupal/token", "1.11.0"), package("drupal/webform", "6.2.0")],
    require={"drupal/core": "^9.3.11"},
    custom=[
        {
            "machine_name": "legacy_module",
            "type": "module",
            "path": "web/modules/custom/legacy_module/legacy_module.info.yml",
            "core_version_requirement": "^8 || ^9",
        }
    ],
)
for target in ("10.6.16", "11.4.6"):
    U.evaluate(sample, target, ROOT)
U.build_path(sample, ROOT)
after = tree_state(ROOT)
assert before == after, sorted(set(before) ^ set(after)) or "content changed"
print("UPGRADE_ANALYSIS_ZERO_KNOWLEDGE_MUTATION=PASS")
print("UPGRADE_ENGINE_READ_ONLY=PASS")


# --- the CLI has no way to act ------------------------------------------------

with tempfile.TemporaryDirectory() as directory:
    workspace = Path(directory)
    analysis_path = workspace / "analysis.json"
    analysis_path.write_text(json.dumps(sample), encoding="utf-8")

    evaluated = subprocess.run(
        [sys.executable, str(CLI), "upgrade-evaluate", str(analysis_path), "--target", "10.6.16", "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(evaluated.stdout)
    assert payload["result_domain"] == U.RESULT_DOMAIN
    assert payload["execution"]["execution_performed"] is False

    walked = subprocess.run(
        [sys.executable, str(CLI), "upgrade-path", str(analysis_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(walked.stdout)["execution_performed"] is False

    explained = subprocess.run(
        [sys.executable, str(CLI), "upgrade-evaluate", str(analysis_path), "--target", "10.6.16"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "UPGRADE COMPATIBILITY ASSESSMENT" in explained.stdout
    assert "execution_performed=False" in explained.stdout

    # A target that cannot be read is a caller error, not a silent default.
    bad = subprocess.run(
        [sys.executable, str(CLI), "upgrade-evaluate", str(analysis_path), "--target", "not-a-version"],
        capture_output=True,
        text=True,
    )
    assert bad.returncode == 2, bad
    assert "ERROR:" in bad.stderr

    # The workspace the CLI was pointed at is unchanged.
    assert sorted(path.name for path in workspace.iterdir()) == ["analysis.json"]

help_text = subprocess.run(
    [sys.executable, str(CLI), "upgrade-evaluate", "--help"], capture_output=True, text=True, check=True
).stdout
path_help = subprocess.run(
    [sys.executable, str(CLI), "upgrade-path", "--help"], capture_output=True, text=True, check=True
).stdout
for forbidden in ("--apply", "--execute", "--write", "--install", "--update", "--fix"):
    assert forbidden not in help_text, f"upgrade-evaluate must not offer {forbidden}"
    assert forbidden not in path_help, f"upgrade-path must not offer {forbidden}"
print("UPGRADE_TARGET_EVALUATION_READ_ONLY=PASS")
print("UPGRADE_CLI_HAS_NO_EXECUTION_MODE=PASS")


# --- no false safety claims ---------------------------------------------------

for assessment in (same_major, major, clean, contrib_ok):
    for text in U.recursive_strings(assessment):
        lowered = text.lower()
        for phrase in U.FORBIDDEN_SAFETY_PHRASES:
            assert phrase not in lowered, (phrase, text)
    assert assessment["bounds"]["statement"]
    assert "not a general upgrade compatibility proof" in assessment["bounds"]["security_relationship"]

# Even the cleanest verdict is bounded language, never an unconditional promise.
assert U.COMPATIBLE == "compatible_with_observed_evidence"
try:
    U.assert_no_safety_claim({"detail": "this upgrade is safe"}, "guard")
except U.UpgradeEngineDefect:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("the safety-claim guard did not fire")
print("NO_FALSE_UPGRADE_SAFETY_CLAIMS=PASS")


# --- compatibility output is not a security finding ---------------------------

for assessment in (skipped, contrib_bad, removed):
    assert assessment["result_domain"] == "upgrade_compatibility"
    assert "finding" not in json.dumps(assessment).lower().replace("findings", "")
    for item in assessment["blockers"]:
        assert "severity" not in item and "advisory" not in item
print("UPGRADE_COMPATIBILITY_NOT_MISLABELED_SECURITY_FINDING=PASS")
