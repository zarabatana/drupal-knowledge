#!/usr/bin/env python3
"""Security applicability confirms only what the project evidence supports.

The matrix below is the one that matters operationally: vulnerable and fixed,
core and contrib, and every way the evidence can be too thin to conclude. The
rule running through all of it is that unknown never quietly becomes safe.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_acquisition
import dk_core
import dk_security as S

from test_security_advisory_contract import (
    CONTRIB_NODE,
    CORE_NODE,
    acquire_and_ingest,
    workspace,
)


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"


def analysis(
    *,
    core_version: str | None = "11.4.3",
    core_state: str = "known",
    packages: list[dict] | None = None,
    packages_state: str = "known",
    packages_available: bool = True,
    project_id: str = "fixture/project",
) -> dict:
    """A Project Analyzer profile in the shape the analyzer actually emits."""
    entries = packages if packages is not None else []
    return {
        "schema_version": "0.1",
        "project_id": project_id,
        "analyzer": {"name": "drupal-knowledge-project-analyzer", "version": "0.1"},
        "completeness": {"state": "partial"},
        "unknowns": [],
        "diagnostics": [],
        "evidence": [],
        "profile": {
            "project_id": project_id,
            "schema_version": "0.1",
            "facts": {
                "drupal_core_version": {
                    "state": core_state,
                    "confidence": "high",
                    "value": {"package": "drupal/core", "version": core_version}
                    if core_state == "known"
                    else None,
                },
                "composer_packages": {
                    "state": packages_state,
                    "confidence": "high",
                    "value": {
                        "installed": {
                            "available": packages_available,
                            "counts": {"drupal_packages": len(entries)},
                            "drupal_packages": entries,
                        }
                    }
                    if packages_state == "known"
                    else None,
                },
            },
        },
    }


def prepared(root: Path, nodes=None):
    workspace(root, nodes if nodes is not None else [CORE_NODE, CONTRIB_NODE])
    acquire_and_ingest(root)


def result_for(evaluation: dict, advisory_id: str) -> dict:
    for item in evaluation["results"]:
        if item["advisory_id"] == advisory_id:
            return item
    raise AssertionError(f"no result for {advisory_id}")


def finding_for(evaluation: dict, advisory_id: str) -> dict | None:
    for item in evaluation["findings"]:
        if item["advisory_id"] == advisory_id:
            return item
    return None


# CORE_NODE affects "<10.6.13 || >=11.4.0 <11.4.4"; CONTRIB_NODE affects "<1.2.0"
# for drupal/fixture_module.
CORE_ADVISORY = "SA-CORE-2026-012"
CONTRIB_ADVISORY = "SA-CONTRIB-2026-901"


# ---------------------------------------------------------------------------
# Core vulnerable and core fixed
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root)
    before = dk_core.knowledge_tree_digest(root)

    vulnerable = S.evaluate(analysis(core_version="11.4.3"), root)
    result = result_for(vulnerable, CORE_ADVISORY)
    assert result["applicability"] == S.APPLICABLE, result
    assert result["scope"] == S.SCOPE_CORE
    assert result["matched_clause"] == ">=11.4.0 <11.4.4"
    finding = finding_for(vulnerable, CORE_ADVISORY)
    assert finding["state"] == S.FINDING_CONFIRMED, finding
    assert finding["installed_version"] == "11.4.3"
    assert finding["cves"] == ["CVE-2026-55805"]
    assert finding["severity_state"] == "sourced"
    assert finding["evidence"]["analyzer_fact_paths"] == ["drupal_core_version"]
    print("CORE_VULNERABLE=confirmed")

    fixed = S.evaluate(analysis(core_version="11.4.4"), root)
    result = result_for(fixed, CORE_ADVISORY)
    assert result["applicability"] == S.NOT_APPLICABLE, result
    assert finding_for(fixed, CORE_ADVISORY) is None
    print("CORE_FIXED=not_applicable")

    assert dk_core.knowledge_tree_digest(root) == before
    assert vulnerable["trusted_knowledge_mutations"] == []


# ---------------------------------------------------------------------------
# Contrib vulnerable and contrib fixed
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root)

    installed = [{"name": "drupal/fixture_module", "version": "1.1.0", "type": "drupal-module"}]
    vulnerable = S.evaluate(analysis(packages=installed), root)
    result = result_for(vulnerable, CONTRIB_ADVISORY)
    assert result["applicability"] == S.APPLICABLE, result
    assert result["scope"] == S.SCOPE_CONTRIB
    finding = finding_for(vulnerable, CONTRIB_ADVISORY)
    assert finding["state"] == S.FINDING_CONFIRMED
    assert finding["installed_version"] == "1.1.0"
    assert finding["remediation"]["fixed_versions"] == ["8.x-1.2"]
    assert finding["evidence"]["analyzer_fact_paths"] == ["composer_packages"]
    print("CONTRIB_VULNERABLE=confirmed")

    fixed = S.evaluate(
        analysis(packages=[{"name": "drupal/fixture_module", "version": "1.2.0"}]), root
    )
    assert result_for(fixed, CONTRIB_ADVISORY)["applicability"] == S.NOT_APPLICABLE
    assert finding_for(fixed, CONTRIB_ADVISORY) is None

    # The legacy release format resolves to the same conclusion.
    legacy = S.evaluate(
        analysis(packages=[{"name": "drupal/fixture_module", "version": "8.x-1.2"}]), root
    )
    legacy_result = result_for(legacy, CONTRIB_ADVISORY)
    assert legacy_result["applicability"] == S.NOT_APPLICABLE
    assert legacy_result["version_normalization"], "the normalization must be recorded"
    print("CONTRIB_FIXED=not_applicable")

    # A project that does not carry the package at all is not affected by it.
    absent = S.evaluate(analysis(packages=[{"name": "drupal/other", "version": "1.0.0"}]), root)
    assert result_for(absent, CONTRIB_ADVISORY)["applicability"] == S.NOT_APPLICABLE
    assert finding_for(absent, CONTRIB_ADVISORY) is None


# ---------------------------------------------------------------------------
# Thin evidence stays unknown
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root)

    # An installed package whose version was not observed.
    unknown_version = S.evaluate(
        analysis(packages=[{"name": "drupal/fixture_module", "version": None}]), root
    )
    result = result_for(unknown_version, CONTRIB_ADVISORY)
    assert result["applicability"] == S.UNKNOWN, result
    assert result["installed_version_state"] == "unknown"
    finding = finding_for(unknown_version, CONTRIB_ADVISORY)
    assert finding is not None and finding["state"] == S.FINDING_CANDIDATE
    print("UNKNOWN_VERSION=unknown_not_false")

    # No definitive core version at all.
    no_core = S.evaluate(analysis(core_state="unknown", core_version=None), root)
    result = result_for(no_core, CORE_ADVISORY)
    assert result["applicability"] == S.INSUFFICIENT_EVIDENCE, result
    assert finding_for(no_core, CORE_ADVISORY)["state"] == S.FINDING_UNKNOWN

    # No definitive package set at all.
    no_packages = S.evaluate(analysis(packages_state="unknown"), root)
    assert result_for(no_packages, CONTRIB_ADVISORY)["applicability"] == S.INSUFFICIENT_EVIDENCE

    # Unknown is never counted as not applicable anywhere in the summary.
    for evaluation in (unknown_version, no_core, no_packages):
        for item in evaluation["results"]:
            assert item["applicability"] in S.APPLICABILITY_STATES
        assert evaluation["summary"]["not_applicable"] + evaluation["summary"]["applicable"] + \
            evaluation["summary"]["unknown"] + evaluation["summary"]["insufficient_project_evidence"] + \
            evaluation["summary"]["version_out_of_scope"] == len(evaluation["results"])
    print("SECURITY_UNKNOWN_NOT_FALSE=PASS")


# ---------------------------------------------------------------------------
# Ambiguous project identity is never fuzzy-confirmed
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    ambiguous = copy.deepcopy(CONTRIB_NODE)
    ambiguous["field_project"] = {"id": "7777777", "resource": "node"}
    prepared(root, [ambiguous])

    # A package whose name looks exactly like the advisory's title subject.
    evaluation = S.evaluate(
        analysis(packages=[{"name": "drupal/fixture_module", "version": "1.0.0"}]), root
    )
    result = result_for(evaluation, CONTRIB_ADVISORY)
    assert result["applicability"] == S.UNKNOWN, result
    assert result["project_identity_state"] == "unresolved"
    finding = finding_for(evaluation, CONTRIB_ADVISORY)
    assert finding is None or finding["state"] != S.FINDING_CONFIRMED
    assert evaluation["summary"]["confirmed_findings"] == 0
    print("AMBIGUOUS_IDENTITY=unknown_never_fuzzy_confirmed")


# ---------------------------------------------------------------------------
# A confirmed finding requires all three pieces of evidence
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root)
    evaluation = S.evaluate(analysis(core_version="11.4.3"), root)
    for finding in evaluation["findings"]:
        if finding["state"] != S.FINDING_CONFIRMED:
            continue
        result = result_for(evaluation, finding["advisory_id"])
        assert result["applicability"] == S.APPLICABLE
        assert result["project_identity_state"] == "resolved"
        assert result["installed_version_state"] == "known"
    print("SECURITY_FINDING_REQUIRES_DEFINITIVE_APPLICABILITY=PASS")

    # Same advisory, same project, same version: same finding id.
    repeat = S.evaluate(analysis(core_version="11.4.3"), root)
    assert [item["id"] for item in repeat["findings"]] == [
        item["id"] for item in evaluation["findings"]
    ]
    assert repeat["evaluation_id"] == evaluation["evaluation_id"]
    # A different installed version is a different finding.
    other = S.evaluate(analysis(core_version="11.4.2"), root)
    assert finding_for(other, CORE_ADVISORY)["id"] != finding_for(evaluation, CORE_ADVISORY)["id"]
    for finding in evaluation["findings"]:
        assert S.FINDING_ID_RE.fullmatch(finding["id"]), finding["id"]
    print("SECURITY_FINDING_IDEMPOTENT=PASS")

    # Severity is published, enforcement is still guidance.
    confirmed = finding_for(evaluation, CORE_ADVISORY)
    assert confirmed["severity_state"] == "sourced"
    assert confirmed["severity_risk_vector"]
    assert confirmed["enforcement"] == {
        "intent": "guidance",
        "policy_controlled": True,
        "automatically_blocking": False,
    }
    assert confirmed["remediation"]["executed"] is False
    assert confirmed["is_trusted_knowledge"] is False
    assert evaluation["enforcement"]["blocking_requires_reviewed_policy"] is True
    assert evaluation["enforcement"]["automatically_blocking"] is False
    print("SECURITY_TRUTH_NOT_AUTOMATIC_BLOCKING_POLICY=PASS")


# ---------------------------------------------------------------------------
# The advisory's own scope decides which majors it speaks about
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    branch_only = copy.deepcopy(CORE_NODE)
    branch_only["field_affected_versions"] = "11.0.* || 11.1.*"
    prepared(root, [branch_only])

    out_of_scope = S.evaluate(analysis(core_version="9.5.9"), root)
    result = result_for(out_of_scope, CORE_ADVISORY)
    assert result["applicability"] == S.VERSION_OUT_OF_SCOPE, result
    assert finding_for(out_of_scope, CORE_ADVISORY) is None

    inside = S.evaluate(analysis(core_version="11.1.2"), root)
    assert result_for(inside, CORE_ADVISORY)["applicability"] == S.APPLICABLE
    print("SECURITY_DOES_NOT_BYPASS_EXISTING_VERSION_GUARDS=PASS")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    spanning = copy.deepcopy(CORE_NODE)
    spanning["field_affected_versions"] = ">= 8.0.0 < 10.3.13"
    prepared(root, [spanning])
    # A range spanning majors does speak about the majors inside it.
    evaluation = S.evaluate(analysis(core_version="9.5.9"), root)
    assert result_for(evaluation, CORE_ADVISORY)["applicability"] == S.APPLICABLE
    assert finding_for(evaluation, CORE_ADVISORY)["state"] == S.FINDING_CONFIRMED
    print("MAJOR_SPANNING_RANGE_NOT_DISMISSED=PASS")


# ---------------------------------------------------------------------------
# Facts come from the analyzer; this engine scans nothing
# ---------------------------------------------------------------------------

engine = (ROOT / "scripts" / "dk_security.py").read_text(encoding="utf-8")
assert "drupal_project_analyzer_profile_facts" in engine
assert "composer.lock" not in engine
assert "core.extension" not in engine
assert "rglob" not in engine and "os.walk" not in engine
assert "dk_project_analyzer" not in engine, "facts are consumed, the analyzer is not re-run"
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    prepared(root)
    facts = S.project_facts(analysis(core_version="11.4.3"))
    assert facts["facts_source"] == "drupal_project_analyzer_profile_facts"
    assert facts["core_version"]["value"] == "11.4.3"
    try:
        S.project_facts({"project_id": "x"})
    except S.SecurityInputError:
        pass
    else:
        raise AssertionError("evaluation accepted analysis without profile facts")
print("SECURITY_REUSES_PROJECT_ANALYZER_FACTS=PASS")


# ---------------------------------------------------------------------------
# The CLI evaluates and never remediates
# ---------------------------------------------------------------------------

help_text = subprocess.run(
    [sys.executable, str(CLI), "--help"], capture_output=True, text=True, check=True
).stdout
for command in ("security-advisories", "security-evaluate"):
    assert command in help_text, f"missing CLI command: {command}"
    text = subprocess.run(
        [sys.executable, str(CLI), command, "--help"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for forbidden in ("--remediate", "--fix", "--update", "--patch", "--composer-update", "--apply"):
        assert forbidden not in text, f"{command} exposes {forbidden}"

cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
for forbidden in ("composer update", "composer require", "subprocess.run([\"composer"):
    assert forbidden not in cli_source, forbidden
for forbidden in ("composer update", "composer require", "def remediate", "def apply_fix"):
    assert forbidden not in engine, forbidden
print("SECURITY_CLI_NO_AUTOMATIC_REMEDIATION=PASS")

released = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True
    ).stdout
)
assert released["interfaces"]["security_advisory_schema"] == S.ADVISORY_CONTRACT_VERSION
assert (
    released["interfaces"]["security_applicability_schema"] == S.APPLICABILITY_SCHEMA_VERSION
)
assert released["security_engine"]["record_class"] == S.RECORD_CLASS
assert released["security_engine"]["produces_trusted_knowledge"] is False
assert released["security_engine"]["automatically_blocking"] is False
assert released["security_engine"]["enforcement_intent"] == "guidance"
# Interfaces released earlier keep their versions.
assert released["interfaces"]["recurrence_analysis_schema"] == "0.1"
assert released["interfaces"]["source_change_candidate_schema"] == "0.1"
print("SECURITY_INTERFACE_ADVERTISED=PASS")


# ---------------------------------------------------------------------------
# The gate is required
# ---------------------------------------------------------------------------

ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert re.search(r"^on:\n  push:\n  pull_request:\n", ci, re.MULTILINE), "the workflow must run on push and pull request"
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
gate = re.search(r"^  engines:\n(?P<body>(?:    .*\n)+)", ci, re.MULTILINE)
assert gate, "missing required engines validation job"
body = gate.group("body")
assert "runs-on: ubuntu-latest" in body
assert "continue-on-error" not in body, "the security gate must be required"
for script in (
    "scripts/test_security_affected_versions.py",
    "scripts/test_security_advisory_contract.py",
    "scripts/test_security_applicability.py",
):
    assert script in body, f"security gate must run {script}"
print("SECURITY_GATE_IS_REQUIRED=PASS")

print("SECURITY_APPLICABILITY_TESTS=PASS")
