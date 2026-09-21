#!/usr/bin/env python3
"""Neutral release lifecycle evaluator invariants."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

import dk_applicability
import dk_core
import dk_project_analyzer
import dk_release_lifecycle
import dk_release_lifecycle_evaluator


ROOT = dk_core.ROOT
FIXTURES = ROOT / "tests" / "fixtures" / "project-analyzer"
CONTEXT_PATH = ROOT / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
# Both pinned to the currently reviewed context. They move only when a human
# re-reviews the context, never as a side effect of other work.
EXPECTED_CONTEXT_DIGEST = "4bb06cbfea41f2fb53951b71db9a2c08d0be2efb9bc96041cfc9e2f1f79b2d33"
EXPECTED_SOURCE_SHA = "sha256:2c6302dcfe0d2dd98afb22db753b6ee0761b9440555b71b1af2272b9ba84c2fb"
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


def analyze_fixture(name: str) -> dict[str, Any]:
    result = dk_project_analyzer.analyze_project(FIXTURES / name)
    assert result.exit_code == 0, (name, result.exit_code, result.data["diagnostics"])
    return result.data


def with_core_version(analysis: dict[str, Any], version: str) -> dict[str, Any]:
    mutated = copy.deepcopy(analysis)
    fact = mutated["profile"]["facts"]["drupal_core_version"]
    fact["state"] = "known"
    fact["value"] = {"package": "drupal/core", "version": version}
    fact["source_evidence_ids"] = ["evidence.drupal.composer-lock.composer-lock"]
    fact["confidence"] = "high"
    fact["notes"] = "Synthetic analyzer-contract fixture for lifecycle evaluator tests."
    return mutated


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


def digest_paths(paths: list[Path]) -> str:
    digest = sha256()
    for path in sorted(path for path in paths if path.is_file()):
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def protected_digest() -> str:
    paths: list[Path] = []
    for relative in (
        "knowledge/records",
        "knowledge/context",
        "sources/state",
        "sources/snapshots",
        "generated",
        "public",
    ):
        base = ROOT / relative
        paths.extend(path for path in base.rglob("*") if path.is_file())
    return digest_paths(paths)


def release_assessment(analysis: dict[str, Any]) -> dict[str, Any]:
    assessment = dk_release_lifecycle_evaluator.evaluate_analysis_data(analysis)
    assert dk_release_lifecycle_evaluator.validate_assessment_output(assessment) == [
        "LIFECYCLE_ASSESSMENT_SCHEMA_VALID=PASS"
    ]
    return assessment


def assert_no_verdict_fields(output: dict[str, Any]) -> None:
    assert recursive_keys(output).isdisjoint(FORBIDDEN_PROJECT_VERDICT_KEYS)
    text = dk_release_lifecycle_evaluator.stable_json(output)
    assert '"project_is_vulnerable"' not in text
    assert '"project_requires_upgrade"' not in text
    assert '"finding"' not in text
    assert '"remediation"' not in text


def assert_exact_release(
    output: dict[str, Any],
    version: str,
    branch_token: str,
    branch_listed: bool,
) -> None:
    assert output["evaluation_state"] == "evaluated"
    assert output["core_version"]["version"] == version
    assert output["release_match"]["state"] == "matched"
    assert output["release_match"]["source_version"] == version
    assert output["release_match"]["reason_code"] == "EXACT_RELEASE_ROW_MATCHED"
    assert output["branch_match"]["source_branch_token"]["source_value"] == branch_token
    membership = output["branch_match"]["branch_listed_in_source_supported_branches"]
    assert membership["state"] == "known"
    assert membership["value"] is branch_listed
    assert "not a project support verdict" in membership["semantics"]


context_before = CONTEXT_PATH.read_bytes()
assert sha256(context_before).hexdigest() == EXPECTED_CONTEXT_DIGEST
context = dk_release_lifecycle.load_context()
assert context["review"]["status"] == "reviewed"
assert context["source"]["snapshot_sha256"] == EXPECTED_SOURCE_SHA
assert dk_release_lifecycle_evaluator.validate_lifecycle_context_for_evaluation(context)["relation"] == "current"

recommended = analyze_fixture("recommended")
unknown_core = analyze_fixture("no-lock")
prerelease_fixture = analyze_fixture("prerelease-core")

before_applicability = dk_applicability.resolve_analysis_data(recommended)
before_protected = protected_digest()

recommended_assessment = release_assessment(recommended)
assert_exact_release(recommended_assessment, "11.2.3", "11.2.", False)
assert recommended_assessment["analysis"]["analysis_sha256"].startswith("sha256:")
assert recommended_assessment["analysis"]["analyzer"]["name"] == "drupal-project-analyzer"
assert recommended_assessment["core_version"]["fact_ref"] == "drupal_core_version"
assert recommended_assessment["core_version"]["evidence_ids"] == [
    "evidence.drupal.composer-lock.composer-lock"
]
assert recommended_assessment["lifecycle_context"]["id"] == "drupal-core-release-lifecycle"
assert recommended_assessment["lifecycle_context"]["source_snapshot_sha256"] == EXPECTED_SOURCE_SHA
assert recommended_assessment["context_freshness"]["relation"] == "current"
assert recommended_assessment["source_attributes"]["state"] == "present"
assert recommended_assessment["source_attributes"]["source_release_status"]["source_value"] == "published"
assert "Insecure" in recommended_assessment["source_attributes"]["source_release_type_terms"]
assert recommended_assessment["source_attributes"]["source_security_coverage"]["covered_attribute"]["source_value"] == "1"
assert_no_verdict_fields(recommended_assessment)

latest_stable = release_assessment(with_core_version(recommended, "11.4.5"))
assert_exact_release(latest_stable, "11.4.5", "11.4.", True)
assert latest_stable["source_attributes"]["source_release_type_terms"] == ["Bug fixes"]
assert latest_stable["source_attributes"]["source_security_coverage"]["text"]["source_value"] == (
    "Covered by Drupal's security advisory policy"
)
assert_no_verdict_fields(latest_stable)

security_update = release_assessment(with_core_version(recommended, "11.4.4"))
assert_exact_release(security_update, "11.4.4", "11.4.", True)
assert security_update["source_attributes"]["source_release_type_terms"] == ["Security update"]
assert_no_verdict_fields(security_update)

insecure = release_assessment(with_core_version(recommended, "11.4.3"))
assert_exact_release(insecure, "11.4.3", "11.4.", True)
assert insecure["source_attributes"]["source_release_type_terms"] == ["Bug fixes", "Insecure"]
assert "vulnerable" not in recursive_keys(insecure)
assert_no_verdict_fields(insecure)

prerelease = release_assessment(with_core_version(recommended, "11.4.0-rc2"))
assert_exact_release(prerelease, "11.4.0-rc2", "11.4.", True)
assert prerelease["source_attributes"]["source_release_type_terms"] == ["Security update", "Insecure"]
assert prerelease["source_attributes"]["source_security_coverage"]["covered_attribute"]["state"] == "not_present"
assert prerelease["source_attributes"]["source_security_coverage"]["text"]["source_value"] == (
    "RC releases are not covered by Drupal security advisories."
)
assert_no_verdict_fields(prerelease)

prerelease_existing = release_assessment(prerelease_fixture)
assert_exact_release(prerelease_existing, "11.0.0-rc1", "11.0.", False)
assert_no_verdict_fields(prerelease_existing)

unknown = release_assessment(unknown_core)
assert unknown["evaluation_state"] == "core_version_unknown"
assert unknown["release_match"]["state"] == "not_evaluated"
assert unknown["branch_match"]["branch_listed_in_source_supported_branches"]["state"] == "unknown"
assert {item["code"] for item in unknown["limitations"]} == {"CORE_VERSION_UNKNOWN"}
assert_no_verdict_fields(unknown)

missing = release_assessment(with_core_version(recommended, "11.99.99"))
assert missing["evaluation_state"] == "release_not_found"
assert missing["release_match"]["state"] == "not_found"
assert missing["branch_match"]["source_branch_token"]["source_value"] == "11.99."
assert missing["branch_match"]["branch_listed_in_source_supported_branches"]["value"] is False
assert "unsupported" not in recursive_keys(missing)
assert_no_verdict_fields(missing)

unknown_branch = release_assessment(with_core_version(recommended, "11.x-dev"))
assert unknown_branch["evaluation_state"] == "evaluated"
assert unknown_branch["release_match"]["state"] == "matched"
assert unknown_branch["branch_match"]["source_branch_token"]["state"] == "unknown"
assert unknown_branch["branch_match"]["branch_listed_in_source_supported_branches"]["state"] == "unknown"
assert_no_verdict_fields(unknown_branch)

candidate_context = copy.deepcopy(context)
candidate_context["review"]["status"] = "candidate"
candidate_context["review"]["reviewed_on"] = None
try:
    dk_release_lifecycle_evaluator.evaluate_analysis_data_with_test_context(
        recommended,
        candidate_context,
    )
except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError:
    pass
else:
    raise AssertionError("candidate lifecycle context must fail closed")

invalid_context = copy.deepcopy(context)
invalid_context["source"]["snapshot_bytes"] = 0
try:
    dk_release_lifecycle_evaluator.evaluate_analysis_data_with_test_context(
        recommended,
        invalid_context,
    )
except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError:
    pass
else:
    raise AssertionError("invalid lifecycle context must fail closed")

malformed_context = {"schema_version": dk_release_lifecycle.CONTEXT_SCHEMA_VERSION}
try:
    dk_release_lifecycle_evaluator.evaluate_analysis_data_with_test_context(
        recommended,
        malformed_context,
    )
except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError:
    pass
else:
    raise AssertionError("malformed lifecycle context must fail closed")

try:
    dk_release_lifecycle_evaluator.evaluate_analysis_data({"schema_version": "0.1"})
except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError:
    pass
else:
    raise AssertionError("invalid analyzer input must fail closed")

future_schema = copy.deepcopy(recommended)
future_schema["schema_version"] = "9.9"
try:
    dk_release_lifecycle_evaluator.evaluate_analysis_data(future_schema)
except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError:
    pass
else:
    raise AssertionError("unsupported analyzer schema must fail closed")

with tempfile.TemporaryDirectory() as temp:
    temp_root = Path(temp)
    (temp_root / "sources" / "state").mkdir(parents=True)
    snapshot_dir = temp_root / "sources" / "snapshots" / "drupal-core-releases"
    snapshot_dir.mkdir(parents=True)
    state = dk_core.read_json(ROOT / "sources" / "state" / "drupal-core-releases.json")
    old_snapshot = ROOT / context["source"]["snapshot_path"]
    shutil.copy2(old_snapshot, snapshot_dir / old_snapshot.name)
    changed = old_snapshot.read_bytes() + b"\n<!-- simulated source movement -->\n"
    changed_sha = dk_release_lifecycle.sha256_bytes(changed)
    (snapshot_dir / f"{changed_sha.removeprefix('sha256:')}.txt").write_bytes(changed)
    changed_state = copy.deepcopy(state)
    changed_state["content_sha256"] = changed_sha
    changed_state["content_length"] = len(changed)
    (temp_root / "sources" / "state" / "drupal-core-releases.json").write_text(
        dk_core.stable_json(changed_state),
        encoding="utf-8",
    )
    stale = dk_release_lifecycle_evaluator.evaluate_analysis_data_with_test_context(
        with_core_version(recommended, "11.4.5"),
        context=context,
        root=temp_root,
    )
    assert stale["evaluation_state"] == "evaluated"
    assert stale["context_freshness"]["relation"] == "stale"
    assert stale["lifecycle_context"]["context_relation"] == "stale"
    assert "LIFECYCLE_CONTEXT_STALE" in {item["code"] for item in stale["limitations"]}
    assert CONTEXT_PATH.read_bytes() == context_before

with tempfile.TemporaryDirectory() as temp:
    analysis_path = Path(temp) / "analysis.json"
    analysis_path.write_text(dk_project_analyzer.stable_json(recommended), encoding="utf-8")
    before_analysis = analysis_path.read_bytes()
    first = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "lifecycle-evaluate", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "lifecycle-evaluate", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    external_context = Path(temp) / "external-reviewed-context.json"
    external_context.write_text(dk_core.stable_json(context), encoding="utf-8")
    external = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "dk.py"),
            "lifecycle-evaluate",
            str(analysis_path),
            "--context",
            str(external_context),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.stdout == second.stdout
    assert json.loads(first.stdout) == recommended_assessment
    assert external.returncode == 2
    assert "unrecognized arguments: --context" in external.stderr
    assert analysis_path.read_bytes() == before_analysis

with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
    left_project = Path(left) / "copy-a"
    right_project = Path(right) / "nested" / "copy-b"
    shutil.copytree(FIXTURES / "recommended", left_project)
    shutil.copytree(FIXTURES / "recommended", right_project)
    left_analysis = dk_project_analyzer.analyze_project(left_project).data
    right_analysis = dk_project_analyzer.analyze_project(right_project).data
    left_output = dk_release_lifecycle_evaluator.evaluate_analysis_data(left_analysis)
    right_output = dk_release_lifecycle_evaluator.evaluate_analysis_data(right_analysis)
    assert dk_release_lifecycle_evaluator.stable_json(left_output) == dk_release_lifecycle_evaluator.stable_json(right_output)
    output_text = dk_release_lifecycle_evaluator.stable_json(left_output)
    assert str(left) not in output_text
    assert str(right) not in output_text
    assert str(left_project) not in output_text
    assert str(right_project) not in output_text

after_applicability = dk_applicability.resolve_analysis_data(recommended)
assert dk_applicability.stable_json(before_applicability) == dk_applicability.stable_json(after_applicability)
after_protected = protected_digest()
assert before_protected == after_protected
assert CONTEXT_PATH.read_bytes() == context_before
assert len(dk_core.load_knowledge_records()) == 11
assert dk_core.validate_generated_current() == ["GENERATED_KNOWLEDGE_CURRENT=PASS"]

source = (ROOT / "scripts" / "dk_release_lifecycle_evaluator.py").read_text(encoding="utf-8")
cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
assert "analyze_project" not in source
assert "context_path:" not in source
assert "--context" not in cli_source
assert "xml.etree" not in source
assert "parse_snapshot_xml" not in source
assert "requests" not in source
assert "urllib" not in source
assert "socket" not in source
assert "subprocess" not in source

print("LIFECYCLE_ASSESSMENT_IS_NOT_FINDING=PASS")
print("LIFECYCLE_ASSESSMENT_DISTINCT_AUTHORITY_LAYER=PASS")
print("LIFECYCLE_EVALUATOR_CONSUMES_ANALYZER_CONTRACT=PASS")
print("LIFECYCLE_EVALUATOR_DOES_NOT_RESCAN_PROJECT=PASS")
print("LIFECYCLE_EVALUATOR_USES_REVIEWED_CONTEXT=PASS")
print("UNREVIEWED_LIFECYCLE_CONTEXT_CANNOT_AUTHOR_ASSESSMENT=PASS")
print("STALE_LIFECYCLE_CONTEXT_EXPLICIT=PASS")
print("LIFECYCLE_EVALUATION_OFFLINE=PASS")
print("PROJECT_CORE_VERSION_FROM_ANALYZER_ONLY=PASS")
print("UNKNOWN_CORE_VERSION_DOES_NOT_GUESS_RELEASE=PASS")
print("EXACT_RELEASE_MATCH_IS_SOURCE_GROUNDED=PASS")
print("MISSING_RELEASE_ROW_IS_NOT_UNSUPPORTED=PASS")
print("SOURCE_BRANCH_MATCHING_DETERMINISTIC=PASS")
print("SUPPORTED_BRANCH_MEMBERSHIP_NOT_SUPPORT_VERDICT=PASS")
print("UNKNOWN_BRANCH_MAPPING_NOT_ABSENT=PASS")
print("RELEASE_TERMS_PRESERVED_WITHOUT_VERDICT=PASS")
print("INSECURE_TERM_REMAINS_SOURCE_ATTRIBUTE=PASS")
print("SECURITY_COVERAGE_REMAINS_SOURCE_ATTRIBUTE=PASS")
print("CONTEXT_FRESHNESS_SEPARATE_FROM_RELEASE_MATCH=PASS")
print("LIFECYCLE_ASSESSMENT_PROVENANCE_COMPLETE=PASS")
print("LIFECYCLE_ASSESSMENT_PORTABLE=PASS")
print("LIFECYCLE_EVALUATION_DETERMINISTIC=PASS")
print("LIFECYCLE_ASSESSMENT_IDENTITY_DETERMINISTIC=PASS")
print("LIFECYCLE_ASSESSMENT_SCHEMA_VALID=PASS")
print("LIFECYCLE_PROJECT_VERDICT_FIELDS=0")
print("CURRENT_APPLICABILITY_RESULTS_UNCHANGED=PASS")
print("LIFECYCLE_EVALUATOR_EMITS_NO_FINDINGS=PASS")
print("LIFECYCLE_EVALUATOR_EMITS_NO_REMEDIATION=PASS")
print("LIFECYCLE_INVALID_ANALYZER_INPUT_REJECTED=PASS")
print("LIFECYCLE_ANALYZER_SCHEMA_VERSION_ENFORCED=PASS")
print("INVALID_LIFECYCLE_CONTEXT_REJECTED=PASS")
print("RUNTIME_EVALUATOR_DOES_NOT_PARSE_RAW_SOURCE=PASS")
print("LIFECYCLE_EVALUATOR_SIDE_EFFECT_FREE=PASS")
print("REVIEWED_LIFECYCLE_CONTEXT_UNCHANGED=PASS")
print("CANONICAL_KNOWLEDGE_RECORD_SET_UNCHANGED=PASS")
print("LIFECYCLE_EVALUATOR_CI_OFFLINE=PASS")
print("ARBITRARY_REVIEWED_CONTEXT_OVERRIDE_AUDITED=PASS")
print("SELF_DECLARED_REVIEW_STATUS_NOT_TRUST_ANCHOR=PASS")
print("AUTHORITATIVE_EVALUATION_REQUIRES_CANONICAL_REVIEWED_CONTEXT=PASS")
print("TEST_CONTEXT_INJECTION_NOT_PRODUCTION_AUTHORITY=PASS")
print("CONTEXT_PROVENANCE_NOT_EQUIVALENT_TO_REVIEW_AUTHORITY=PASS")
print("STALE_REVIEWED_CONTEXT_REMAINS_IDENTIFIABLE_AUTHORITY=PASS")
print("BRANCH_MEMBERSHIP_FALSE_NOT_UNSUPPORTED=PASS")
print("SUPPORTED_BRANCH_MEMBERSHIP_HAS_NO_VERDICT_ALIAS=PASS")
print("LIFECYCLE_CONTEXT_AUTHORITY_MATRIX=PASS")
