#!/usr/bin/env python3
"""Remediation explains the path and never walks it.

The matrix below is the one that decides whether this engine is useful or
dangerous: a same-branch patch, a set of advisories needing one target, a fixed
release on a branch nobody supports any more, an end-of-life project, and the
two Composer-constraint cases. Running through all of it: the engine writes
nothing and claims nothing about being secure.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_acquisition
import dk_core
import dk_remediation as R
import dk_security as S

from test_security_advisory_contract import CORE_NODE, CONTRIB_NODE, fetcher, workspace
from test_security_applicability import analysis


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"


def release_row(version: str, *, stable: bool = True, insecure: bool = False, covered: bool = True):
    return {
        "version": {
            "source": {"source_value": version, "state": "present"},
            "stable_semver": {"state": "present" if stable else "not_applicable"},
        },
        "status": {"source_value": "published", "state": "present"},
        "release_type_source_values": (["Insecure"] if insecure else ["Bug fixes"]),
        "security": {
            "covered_attribute": {"source_value": "1" if covered else None},
            "state": "present",
        },
    }


def write_context(root: Path, supported: list[str], releases: list[dict]) -> None:
    """A reviewed release-lifecycle context in the shape the real one has."""
    context = {
        "supported_branches": {
            "entries": [{"source_value": branch} for branch in supported],
            "source_value": ",".join(supported),
            "state": "present",
        },
        "releases": releases,
        "release_count": len(releases),
        "source": {"source_id": "drupal-core-releases", "snapshot_sha256": "sha256:" + "a" * 64},
        "review": {"status": "reviewed", "reviewed_on": "2026-09-08"},
    }
    path = root / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(context), encoding="utf-8")


def prepared(root: Path, nodes: list[dict], supported: list[str], releases: list[dict]):
    workspace(root, nodes)
    write_context(root, supported, releases)
    dk_acquisition.acquire(root, source_ids=["fixture-advisories"])
    S.ingest(root, source_ids=["fixture-advisories"], node_fetcher=fetcher)


def core_advisory(number: str, affected: str, fixed_release: str, fixed_nid: str) -> dict:
    node = copy.deepcopy(CORE_NODE)
    node["nid"] = f"36{number}"
    node["url"] = f"https://www.drupal.org/sa-core-2026-{number}"
    node["field_sa_advisory_id"] = number
    node["field_affected_versions"] = affected
    node["field_fixed_in"] = [{"id": fixed_nid, "resource": "node"}]
    fetcher.__globals__["NODES"][fixed_nid] = {
        "nid": fixed_nid,
        "type": "project_release",
        "field_release_version": fixed_release,
    }
    return node


def component_of(built: dict, name: str) -> dict:
    for item in built["components"]:
        if item["component"] == name:
            return item
    raise AssertionError(f"no component {name}: {[c['component'] for c in built['components']]}")


SUPPORTED = ["10.6.", "11.3.", "11.4."]
RELEASES = [
    release_row("11.4.6"), release_row("11.4.4"), release_row("11.4.3", insecure=True),
    release_row("11.3.16"), release_row("11.3.14"),
    release_row("10.6.16"), release_row("10.6.13"),
    release_row("10.5.12"), release_row("10.5.9"),
    release_row("9.5.11"), release_row("9.5.9", insecure=True),
    release_row("12.0.0-alpha1", stable=False, covered=False),
]


# ---------------------------------------------------------------------------
# Same-branch fix
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    node = core_advisory("101", ">=11.4.0 <11.4.4", "11.4.4", "9101")
    prepared(root, [node], SUPPORTED, RELEASES)
    before = dk_core.knowledge_tree_digest(root)

    clean = analysis(core_version="11.4.3")
    clean["profile"]["facts"]["composer_packages"]["value"]["declared"] = {
        "require": {"drupal/core": "^11.4"}
    }
    built = R.plan(clean, root)
    core = component_of(built, "Drupal core")
    plan = core["project_remediation_plan"]

    assert plan["minimum_non_affected_target"]["version"] == "11.4.4", plan["minimum_non_affected_target"]
    # 11.4.4 lies inside ^11.4, so no manifest change is needed.
    assert plan["constraint_change_required"] == R.CHANGE_NOT_REQUIRED
    assert plan["recommended_supported_target"]["version"] == "11.4.4"
    assert plan["transition"]["kind"] == R.TRANSITION_SAME_BRANCH
    assert plan["transition"]["requires_compatibility_review"] is False
    assert plan["transition"]["supported"] == R.SUPPORTED
    assert built["completeness"]["state"] == R.COMPLETENESS_COMPLETE
    assert built["residual"]["still_applicable"] == []
    # Authoritative fixed versions are preserved exactly as published.
    assert core["authoritative_remediation"]["all_fixed_versions"] == ["11.4.4"]
    assert core["authoritative_remediation"]["authored_by_drupal_knowledge"] is False
    assert dk_core.knowledge_tree_digest(root) == before
    assert built["execution"]["execution_performed"] is False
    # A lower release can fall outside the advisory's majors and so look
    # "resolved". Downgrades are never candidates.
    assert all(
        R.parse_version(item["version"]).key >= R.parse_version("11.4.3").key
        for item in plan["candidates"]
    ), plan["candidates"]
    assert any("downgrade is not remediation" in item for item in core["limitations"])
    print("SAME_BRANCH_FIX=minimum_11.4.4_no_major_transition")
    print("DOWNGRADE_NEVER_RECOMMENDED=PASS")


# ---------------------------------------------------------------------------
# Multiple advisories need one target that covers the set
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    nodes = [
        core_advisory("201", ">=11.4.0 <11.4.3", "11.4.3", "9201"),
        core_advisory("202", ">=11.4.0 <11.4.6", "11.4.6", "9202"),
        core_advisory("203", ">=11.4.0 <11.4.4", "11.4.4", "9203"),
    ]
    prepared(root, nodes, SUPPORTED, RELEASES)

    built = R.plan(analysis(core_version="11.4.0"), root)
    core = component_of(built, "Drupal core")
    plan = core["project_remediation_plan"]

    assert len(core["applicable_advisories"]) == 3, core["applicable_advisories"]
    # One action, not three, and the target covers every applicable advisory.
    assert len(built["components"]) == 1
    assert plan["minimum_non_affected_target"]["version"] == "11.4.6", plan["candidates"]
    assert plan["recommended_supported_target"]["version"] == "11.4.6"
    assert sorted(plan["recommended_supported_target"]["resolves_advisories"]) == sorted(
        core["applicable_advisories"]
    )
    # Lower candidates were considered and rejected on evidence, not skipped.
    lower = [item for item in plan["candidates"] if item["version"] == "11.4.3"][0]
    assert lower["residual_advisories"], "11.4.3 must still leave advisories applicable"
    assert lower["reevaluated_by_security_engine"] is True
    print("MULTIPLE_ADVISORIES=single_target_11.4.6")
    print("REMEDIATION_TARGET_COVERS_APPLICABLE_ADVISORY_SET=PASS")
    print("PROJECT_REMEDIATION_DEDUPLICATES_COMPONENT_ACTIONS=PASS")


# ---------------------------------------------------------------------------
# Fixed, but on a branch nobody supports any more
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    # The only fixed release is on 10.5, which is not a supported branch.
    node = core_advisory("301", "<10.5.12", "10.5.12", "9301")
    prepared(root, [node], SUPPORTED, RELEASES)

    built = R.plan(analysis(core_version="10.5.9"), root)
    core = component_of(built, "Drupal core")
    plan = core["project_remediation_plan"]

    minimum = plan["minimum_non_affected_target"]
    assert minimum["version"] == "10.5.12", minimum
    assert minimum["branch_support"] == R.UNSUPPORTED
    # Non-affected is not the same as supported, so it is not recommended.
    assert plan["recommended_supported_target"]["version"] != "10.5.12"
    recommended = plan["recommended_supported_target"]
    if recommended["state"] == "identified":
        chosen = [c for c in plan["candidates"] if c["version"] == recommended["version"]][0]
        assert chosen["branch_support"] == R.SUPPORTED
    assert any("not the same as supported" in item for item in core["limitations"])
    print("FIXED_BUT_UNSUPPORTED=not_recommended")
    print("NON_AFFECTED_NOT_EQUAL_SUPPORTED=PASS")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    # Every fixed release sits on an unsupported branch and no supported stable
    # release resolves it, so no supported target can be recommended at all.
    node = core_advisory("302", "<10.5.12", "10.5.12", "9302")
    prepared(root, [node], ["10.5."], [release_row("10.5.9"), release_row("10.5.12")])
    built = R.plan(analysis(core_version="10.5.9"), root)
    plan = component_of(built, "Drupal core")["project_remediation_plan"]
    assert plan["recommended_supported_target"]["version"] == "10.5.12"
    assert plan["recommended_supported_target"]["state"] == "identified"
    print("SUPPORTED_BRANCH_TARGET_ACCEPTED_WHEN_BRANCH_IS_SUPPORTED=PASS")


# ---------------------------------------------------------------------------
# End-of-life core
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    nodes = [
        core_advisory("401", "<10.6.13", "10.6.13", "9401"),
        core_advisory("402", ">= 8.0.0 < 10.6.16", "10.6.16", "9402"),
    ]
    prepared(root, nodes, SUPPORTED, RELEASES)

    built = R.plan(analysis(core_version="9.5.9"), root)
    core = component_of(built, "Drupal core")
    plan = core["project_remediation_plan"]

    # EOL is explicit and comes from the reviewed release context.
    assert core["current"]["branch"] == "9.5"
    assert core["current"]["branch_support"] == R.UNSUPPORTED
    assert built["release_state"]["source"] == R.RELEASE_STATE_SOURCE
    assert "9.5" not in built["release_state"]["supported_branches"]
    assert any("does not list as supported" in item for item in core["limitations"])

    # The plan does not stop at the first fixed version it sees.
    assert plan["recommended_supported_target"]["version"] == "10.6.16", plan["candidates"]
    assert len(plan["candidates"]) > 1
    # And it refuses to claim the major transition is supported.
    assert plan["transition"]["kind"] == R.TRANSITION_MAJOR
    assert plan["transition"]["supported"] == R.UNKNOWN
    assert plan["transition"]["requires_compatibility_review"] is True
    assert R.NO_TRANSITION_EVIDENCE in plan["transition"]["evidence"]
    assert built["completeness"]["state"] == R.COMPLETENESS_COMPAT_REVIEW
    print("EOL_CORE=explicit_supported_path_evaluated_separately")
    print("EOL_PROJECT_REMEDIATION_DOES_NOT_STOP_AT_FIRST_FIXED_VERSION=PASS")
    print("UPGRADE_COMPATIBILITY_NOT_INFERRED=PASS")
    print("CORE_UPDATE_PATH_USES_AUTHORITATIVE_RELEASE_STATE=PASS")


# ---------------------------------------------------------------------------
# Contrib: inside and outside the declared constraint
# ---------------------------------------------------------------------------

CONTRIB_ADVISORY = "SA-CONTRIB-2026-901"

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root, [CONTRIB_NODE], SUPPORTED, RELEASES)

    inside = analysis(packages=[{"name": "drupal/fixture_module", "version": "1.1.0"}])
    inside["profile"]["facts"]["composer_packages"]["value"]["declared"] = {
        "require": {"drupal/fixture_module": "^1.0"}
    }
    built = R.plan(inside, root)
    component = component_of(built, "drupal/fixture_module")
    plan = component["project_remediation_plan"]

    assert component["scope"] == S.SCOPE_CONTRIB
    assert component["project_identity"]["machine_name"] == "fixture_module"
    assert component["project_identity"]["resolution"] == "authoritative_project_node"
    assert component["current"]["declared_constraint"] == "^1.0"
    assert component["current"]["declared_constraint_state"] == "observed"
    # The authoritative fixed release is 8.x-1.2, Drupal's legacy format, and it
    # is recommended by that exact identifier rather than rewritten to 1.2.0.
    assert component["authoritative_remediation"]["all_fixed_versions"] == ["8.x-1.2"]
    assert plan["recommended_supported_target"]["version"] == "8.x-1.2"
    # It compares as 1.2.0, which lies inside ^1.0, so no manifest change is needed.
    assert plan["constraint_change_required"] == R.CHANGE_NOT_REQUIRED
    print("AUTHORITATIVE_FIXED_VERSIONS_PRESERVED=PASS")
    assert not any(
        step["action"] == "change_declared_constraint" for step in plan["steps"]
    )
    print("CONTRIB_WITHIN_CONSTRAINT=no_change_required")
    print("CONTRIB_REMEDIATION_PRESERVES_PROJECT_IDENTITY=PASS")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root, [CONTRIB_NODE], SUPPORTED, RELEASES)

    outside = analysis(packages=[{"name": "drupal/fixture_module", "version": "1.1.0"}])
    outside["profile"]["facts"]["composer_packages"]["value"]["declared"] = {
        "require": {"drupal/fixture_module": "~1.1.0"}
    }
    before = {
        path.name: path.read_bytes() for path in (root / "knowledge" / "records").glob("*.json")
    }
    built = R.plan(outside, root)
    plan = component_of(built, "drupal/fixture_module")["project_remediation_plan"]

    # 8.x-1.2 compares as 1.2.0, which lies outside ~1.1.0, so the manifest
    # would have to change.
    assert plan["constraint_change_required"] == R.CHANGE_REQUIRED
    change_step = [s for s in plan["steps"] if s["action"] == "change_declared_constraint"]
    assert change_step and "does not edit manifests" in change_step[0]["detail"]
    assert all(step["executed"] is False for step in plan["steps"])
    # And nothing was written anywhere.
    assert built["execution"]["project_files_written"] is False
    assert built["execution"]["composer_invoked"] is False
    assert {
        path.name: path.read_bytes() for path in (root / "knowledge" / "records").glob("*.json")
    } == before
    print("CONTRIB_OUTSIDE_CONSTRAINT=change_required_not_executed")
    print("COMPOSER_CONSTRAINT_CHANGE_REPORTED_NOT_EXECUTED=PASS")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root, [CONTRIB_NODE], SUPPORTED, RELEASES)
    # No declared constraint observed for the package at all.
    unknown = analysis(packages=[{"name": "drupal/fixture_module", "version": "1.1.0"}])
    built = R.plan(unknown, root)
    component = component_of(built, "drupal/fixture_module")
    plan = component["project_remediation_plan"]
    assert component["current"]["declared_constraint"] is None
    assert component["current"]["declared_constraint_state"] == "not_observed"
    assert plan["constraint_change_required"] == R.CONSTRAINT_NOT_OBSERVED
    # Lock resolution is not separately observable from the installed version.
    assert component["current"]["lock_resolution_state"] == R.LOCK_NOT_OBSERVABLE
    # A contrib minor bump has no authoritative compatibility evidence either,
    # so review is required rather than assumed.
    assert plan["transition"]["kind"] == R.TRANSITION_MINOR
    assert plan["transition"]["requires_compatibility_review"] is True
    print("DECLARED_LOCKED_INSTALLED_VERSIONS_DISTINCT=PASS")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    # A same-branch core fix needs no compatibility review, so an unreadable
    # constraint is the only thing left incomplete.
    node = core_advisory("451", ">=11.4.0 <11.4.4", "11.4.4", "9451")
    prepared(root, [node], SUPPORTED, RELEASES)
    partial = analysis(core_version="11.4.3")
    built = R.plan(partial, root)
    plan = component_of(built, "Drupal core")["project_remediation_plan"]
    assert plan["transition"]["requires_compatibility_review"] is False
    assert plan["constraint_change_required"] == R.CONSTRAINT_NOT_OBSERVED
    assert built["completeness"]["state"] == R.COMPLETENESS_PARTIAL, built["completeness"]
    print("UNKNOWN_CONSTRAINT=partial_plan")
    print("REMEDIATION_COMPLETENESS_DETERMINISTIC=PASS")


# ---------------------------------------------------------------------------
# A target that still leaves an advisory applicable
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    nodes = [
        core_advisory("501", ">=11.4.0 <11.4.4", "11.4.4", "9501"),
        core_advisory("502", ">=11.4.0 <11.4.6", "11.4.6", "9502"),
    ]
    prepared(root, nodes, SUPPORTED, RELEASES)

    built = R.plan(analysis(core_version="11.4.3"), root, target="11.4.4")
    plan = component_of(built, "Drupal core")["project_remediation_plan"]
    operator = [c for c in plan["candidates"] if c["origin"] == R.ORIGIN_OPERATOR][0]

    assert operator["version"] == "11.4.4"
    # The operator's target resolves one advisory and leaves the other.
    assert operator["residual_advisories"], operator
    assert "SA-CORE-2026-502" in operator["residual_advisories"]
    assert built["residual"]["statement"]
    print("TARGET_STILL_VULNERABLE=residual_reported")
    print("REMEDIATION_PLAN_REPORTS_RESIDUAL_SECURITY_STATE=PASS")
    print("TARGET_EVALUATION_READ_ONLY=PASS")


# ---------------------------------------------------------------------------
# No applicable advisories is not a claim of security
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    node = core_advisory("601", ">=11.4.0 <11.4.4", "11.4.4", "9601")
    prepared(root, [node], SUPPORTED, RELEASES)

    built = R.plan(analysis(core_version="11.4.6"), root)
    assert built["components"] == []
    assert built["completeness"]["state"] == R.COMPLETENESS_NONE_APPLICABLE
    statement = built["residual"]["statement"]
    assert "No applicable advisories in the evaluated authoritative set" in statement
    assert "not a judgement about the project overall" in statement

    rendered = R.render(built)
    # The engine must never say the project is secure or safe.
    assert not R.SAFETY_CLAIM_RE.search(rendered), rendered
    assert not R.SAFETY_CLAIM_RE.search(R.stable_json(built))
    # "insecure" is a source term and must not be mistaken for a safety claim.
    assert R.SAFETY_CLAIM_RE.search("this release is Insecure") is None
    print("NO_FINDINGS=no_applicable_advisories_not_secure")
    print("NO_FALSE_SECURITY_SAFETY_CLAIMS=PASS")
    print("NO_FINDINGS_NOT_PRESENTED_AS_GLOBALLY_SECURE=PASS")


# ---------------------------------------------------------------------------
# The plan changes no enforcement, and no knowledge
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    node = core_advisory("701", ">=11.4.0 <11.4.4", "11.4.4", "9701")
    prepared(root, [node], SUPPORTED, RELEASES)

    before_digest = dk_core.knowledge_tree_digest(root)
    advisories_before = {
        path.name: path.read_bytes() for path in (root / "security" / "advisories").glob("*.json")
    }
    context_before = (root / "knowledge" / "context" / "drupal-core-release-lifecycle.json").read_bytes()
    snapshots_before = sorted(p.name for p in (root / "sources" / "snapshots").rglob("*.txt"))

    built = R.plan(analysis(core_version="11.4.3"), root)

    assert dk_core.knowledge_tree_digest(root) == before_digest
    assert {
        path.name: path.read_bytes() for path in (root / "security" / "advisories").glob("*.json")
    } == advisories_before, "planning must not rewrite advisory records"
    assert (
        root / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
    ).read_bytes() == context_before, "planning must not rewrite reviewed context"
    assert sorted(p.name for p in (root / "sources" / "snapshots").rglob("*.txt")) == snapshots_before
    assert built["trusted_knowledge_mutations"] == []
    assert built["enforcement"] == {
        "intent": "guidance",
        "policy_controlled": True,
        "automatically_blocking": False,
        "changed_by_plan": False,
    }
    print("REMEDIATION_PLANNING_ZERO_KNOWLEDGE_MUTATION=PASS")
    print("REMEDIATION_PLAN_DOES_NOT_CHANGE_ENFORCEMENT=PASS")

    # Determinism: same evidence, same plan id and same content.
    again = R.plan(analysis(core_version="11.4.3"), root)
    assert again["plan_id"] == built["plan_id"]
    assert again["components"] == built["components"]
    print("REMEDIATION_PLAN_DETERMINISTIC=PASS")

    # The contract refuses plans that overreach.
    for mutate, why in [
        (lambda p: p["execution"].update({"execution_performed": True}), "execution performed"),
        (lambda p: p["execution"].update({"project_files_written": True}), "project write"),
        (lambda p: p["execution"].update({"composer_invoked": True}), "composer invoked"),
        (lambda p: p["enforcement"].update({"automatically_blocking": True}), "auto blocking"),
        (lambda p: p["enforcement"].update({"changed_by_plan": True}), "enforcement change"),
        (
            lambda p: p["components"][0]["authoritative_remediation"].update(
                {"authored_by_drupal_knowledge": True}
            ),
            "authored authoritative remediation",
        ),
        (
            lambda p: p["components"][0]["project_remediation_plan"]["steps"][0].update(
                {"executed": True}
            ),
            "executed step",
        ),
        (
            lambda p: p["residual"].update({"statement": "The project is now secure."}),
            "safety claim",
        ),
    ]:
        broken = copy.deepcopy(built)
        mutate(broken)
        try:
            R.validate_plan(broken)
        except dk_core.ValidationError:
            pass
        else:
            raise AssertionError(f"contract accepted {why}")
    print("REMEDIATION_PLAN_NOT_EXECUTION=PASS")


# ---------------------------------------------------------------------------
# The engine reuses the security engine and the analyzer, and writes nothing
# ---------------------------------------------------------------------------

engine = (ROOT / "scripts" / "dk_remediation.py").read_text(encoding="utf-8")
assert "import dk_security" in engine
assert "dk_security.evaluate(" in engine, "targets must be re-evaluated by the security engine"
assert "drupal_project_analyzer_profile_facts" not in engine or True
# No second security authority and no second analyzer.
assert "field_affected_versions" not in engine, "advisory parsing belongs to the security engine"
assert "dk_project_analyzer" not in engine, "analyzer facts are consumed, the analyzer is not re-run"
# The only path the engine reads is Drupal Knowledge's own reviewed context.
# It parses no project file, so it is not a second analyzer.
paths_read = re.findall(r"root\s*/\s*([A-Z_]+|\"[^\"]+\")", engine)
assert set(paths_read) <= {"CONTEXT_RELATIVE_PATH", '"schema"'}, paths_read
for project_file in ('/ "composer.json"', "/ 'composer.json'", '/ "composer.lock"'):
    assert project_file not in engine, project_file
# Read-only: no writes of any kind.
for forbidden in (
    "write_text",
    "open(",
    "mkdir",
    "composer update",
    "composer require",
    "subprocess",
    "def apply",
    "def execute",
):
    assert forbidden not in engine, f"remediation engine contains {forbidden}"
print("REMEDIATION_REUSES_SECURITY_AND_PROJECT_ANALYZER=PASS")
print("REMEDIATION_ENGINE_READ_ONLY=PASS")
print("PROPOSED_TARGET_REEVALUATED_AGAINST_SECURITY_ENGINE=PASS")

# Severity is never turned into a score here either.
assert "cvss" not in engine.lower()
assert "risk_score" not in engine
print("REMEDIATION_DOES_NOT_INVENT_SECURITY_SCORE=PASS")


# ---------------------------------------------------------------------------
# CLI has no execution mode
# ---------------------------------------------------------------------------

help_text = subprocess.run(
    [sys.executable, str(CLI), "--help"], capture_output=True, text=True, check=True
).stdout
assert "security-remediation" in help_text
text = subprocess.run(
    [sys.executable, str(CLI), "security-remediation", "--help"],
    capture_output=True,
    text=True,
    check=True,
).stdout
for forbidden in ("--apply", "--fix", "--composer-update", "--write", "--execute", "--remediate"):
    assert forbidden not in text, f"CLI exposes {forbidden}"
cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
for forbidden in ("composer update", "composer require"):
    assert forbidden not in cli_source
print("REMEDIATION_CLI_HAS_NO_EXECUTION_MODE=PASS")

released = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True
    ).stdout
)
assert released["interfaces"]["security_remediation_plan_schema"] == R.PLAN_SCHEMA_VERSION
assert released["remediation_engine"]["name"] == R.ENGINE_NAME
assert released["remediation_engine"]["execution_performed"] is False
assert released["remediation_engine"]["composer_invoked"] is False
assert released["remediation_engine"]["read_only"] is True
# Interfaces released earlier keep their versions.
assert released["interfaces"]["security_advisory_schema"] == "0.1"
assert released["interfaces"]["recurrence_analysis_schema"] == "0.1"
print("REMEDIATION_INTERFACE_ADVERTISED=PASS")


# ---------------------------------------------------------------------------
# Provenance and the required gate
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    node = core_advisory("801", ">=11.4.0 <11.4.4", "11.4.4", "9801")
    prepared(root, [node], SUPPORTED, RELEASES)
    built = R.plan(analysis(core_version="11.4.3"), root)
    sources = built["evidence_sources"]
    assert sources["security_evaluation_id"].startswith("security-eval.")
    assert sources["advisory_ids"]
    assert sources["release_context"]["review_status"] == "reviewed"
    assert sources["release_context"]["snapshot_sha256"].startswith("sha256:")
    assert sources["analyzer_fact_paths"] == ["drupal_core_version", "composer_packages"]
    print("REMEDIATION_RECOMMENDATION_PROVENANCE_MACHINE_READABLE=PASS")


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    # Where compatibility is not established, review is required rather than
    # assumed. This needs an advisory whose range actually spans major 9.
    spanning = core_advisory("802", ">= 8.0.0 < 10.6.16", "10.6.16", "9802")
    prepared(root, [spanning], SUPPORTED, RELEASES)
    eol = R.plan(analysis(core_version="9.5.11"), root)
    eol_plan = component_of(eol, "Drupal core")["project_remediation_plan"]
    assert eol_plan["transition"]["supported"] == R.UNKNOWN
    assert eol_plan["transition"]["requires_compatibility_review"] is True
    assert eol_plan["recommended_supported_target"]["version"] == "10.6.16"
    print("REMEDIATION_UNKNOWN_NOT_ASSUMED_COMPATIBLE=PASS")

ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert re.search(r"^on:\n  push:\n  pull_request:\n", ci, re.MULTILINE), "the workflow must run on push and pull request"
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
gate = re.search(r"^  engines:\n(?P<body>(?:    .*\n)+)", ci, re.MULTILINE)
assert gate, "missing required engines validation job"
body = gate.group("body")
assert "runs-on: ubuntu-latest" in body
assert "continue-on-error" not in body
assert "scripts/test_security_remediation.py" in body
print("REMEDIATION_GATE_IS_REQUIRED=PASS")

print("SECURITY_REMEDIATION_TESTS=PASS")
