#!/usr/bin/env python3
"""Applicability resolver foundation invariants."""

from __future__ import annotations

import copy
import json
import shutil
import socket
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

import dk_applicability
import dk_core
import dk_project_analyzer


ROOT = dk_core.ROOT
FIXTURES = ROOT / "tests" / "fixtures" / "project-analyzer"


def analyze_fixture(name: str) -> dict[str, Any]:
    result = dk_project_analyzer.analyze_project(FIXTURES / name)
    assert result.exit_code == 0, (name, result.exit_code, result.data["diagnostics"])
    return result.data


def result_for(output: dict[str, Any], knowledge_id: str) -> dict[str, Any]:
    matches = [item for item in output["results"] if item["knowledge_id"] == knowledge_id]
    assert len(matches) == 1, knowledge_id
    return matches[0]


def synthetic_record(
    record_id: str,
    condition: dict[str, Any] | None,
    review_status: str = "reviewed",
    enforcement_intent: str = "non_blocking",
) -> dict[str, Any]:
    record = {
        "id": record_id,
        "title": f"Synthetic {record_id}",
        "review_status": review_status,
        "enforcement": {
            "intent": enforcement_intent,
            "rationale": "Synthetic resolver authority test.",
        },
    }
    if condition is not None:
        record["machine_applicability"] = {
            "schema_version": "0.1",
            "condition": condition,
            "notes": "Synthetic declarative applicability test.",
        }
    return record


def resolve_one(record: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    output = dk_applicability.resolve_analysis_data(
        analysis,
        records=[record],
        validate_canonical_knowledge=False,
    )
    return output["results"][0]


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
        "sources/state",
        "sources/snapshots",
        "generated",
        "public",
    ):
        base = ROOT / relative
        if base.is_file():
            paths.append(base)
        elif base.is_dir():
            paths.extend(path for path in base.rglob("*") if path.is_file())
    return digest_paths(paths)


def recursive_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        strings = []
        for key, item in value.items():
            strings.append(str(key))
            strings.extend(recursive_strings(item))
        return strings
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(recursive_strings(item))
        return strings
    if isinstance(value, str):
        return [value]
    return []


def assert_status(record: dict[str, Any], analysis: dict[str, Any], status: str) -> dict[str, Any]:
    result = resolve_one(record, analysis)
    assert result["applicability"] == status, result
    return result


recommended = analyze_fixture("recommended")
composer_only = analyze_fixture("composer-only")
non_drupal = analyze_fixture("non-drupal")
disabled = analyze_fixture("installed-but-disabled")
ambiguous = analyze_fixture("ambiguous-config")
prerelease = analyze_fixture("prerelease-core")

audit = dk_applicability.audit_current_knowledge()
assert len(audit) == len(dk_core.load_knowledge_records()) == 11
audit_by_id = {row["knowledge_id"]: row for row in audit}
assert audit_by_id["drupal.api.reference-drupal-11"]["machine_state"] == "MACHINE_RESOLVABLE"
assert audit_by_id["drupal.api.version-aware-documentation"]["machine_state"] == "PARTIALLY_MACHINE_RESOLVABLE"
assert audit_by_id["drupal.change-records.introduced-version"]["machine_state"] == "HUMAN_SEMANTIC_REVIEW_REQUIRED"
assert audit_by_id["drupal.coding-standards.phpcs-coder-tooling"]["machine_state"] == "INSUFFICIENT_PROJECT_EVIDENCE"

canonical = dk_applicability.resolve_analysis_data(recommended)
assert dk_applicability.validate_resolution_output(canonical) == [
    "RESOLUTION_OUTPUT_SCHEMA_VALID=PASS"
]
expected_version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert canonical["analysis"]["analysis_sha256"].startswith("sha256:")
assert canonical["knowledge_set"]["version"] == expected_version
assert canonical["knowledge_set"]["record_count"] == 11
api_reference = result_for(canonical, "drupal.api.reference-drupal-11")
assert api_reference["applicability"] == "applicable"
assert "drupal_core_version" in api_reference["fact_refs"]
assert "evidence.drupal.composer-lock.composer-lock" in api_reference["evidence_ids"]
assert api_reference["predicate_evaluations"]
assert result_for(canonical, "drupal.security.twig-output-escaping")["applicability"] != "applicable"
assert all(item["effective_enforcement"] == "guidance" for item in canonical["results"])
assert canonical["summary"]["applicable_effective_enforcement_counts"]["blocking"] == 0

changed_free_text = copy.deepcopy(dk_core.load_knowledge_records())
for record in changed_free_text:
    if record["id"] == "drupal.api.reference-drupal-11":
        record["automation_hints"] = ["This prose must not authorize applicability."]
free_text_output = dk_applicability.resolve_analysis_data(
    recommended,
    records=changed_free_text,
    validate_canonical_knowledge=False,
)
assert result_for(free_text_output, "drupal.api.reference-drupal-11")["applicability"] == result_for(
    canonical,
    "drupal.api.reference-drupal-11",
)["applicability"]

assert dk_applicability.tvl_and([dk_applicability.TRUE, dk_applicability.TRUE]) == dk_applicability.TRUE
assert dk_applicability.tvl_and([dk_applicability.TRUE, dk_applicability.FALSE]) == dk_applicability.FALSE
assert dk_applicability.tvl_and([dk_applicability.TRUE, dk_applicability.UNKNOWN]) == dk_applicability.UNKNOWN
assert dk_applicability.tvl_and([dk_applicability.FALSE, dk_applicability.UNKNOWN]) == dk_applicability.FALSE
assert dk_applicability.tvl_and([dk_applicability.UNKNOWN, dk_applicability.UNKNOWN]) == dk_applicability.UNKNOWN
assert dk_applicability.tvl_or([dk_applicability.TRUE, dk_applicability.UNKNOWN]) == dk_applicability.TRUE
assert dk_applicability.tvl_or([dk_applicability.FALSE, dk_applicability.UNKNOWN]) == dk_applicability.UNKNOWN
assert dk_applicability.tvl_or([dk_applicability.FALSE, dk_applicability.FALSE]) == dk_applicability.FALSE
assert dk_applicability.tvl_not(dk_applicability.TRUE) == dk_applicability.FALSE
assert dk_applicability.tvl_not(dk_applicability.FALSE) == dk_applicability.TRUE
assert dk_applicability.tvl_not(dk_applicability.UNKNOWN) == dk_applicability.UNKNOWN

drupal_project = synthetic_record(
    "drupal.synthetic.project-type",
    {
        "operator": "equals",
        "fact": "project_type",
        "path": "value.type",
        "value": "drupal",
    },
)
assert_status(drupal_project, recommended, "applicable")
assert_status(drupal_project, non_drupal, "unknown")

module_present = synthetic_record(
    "drupal.synthetic.commerce-module",
    {
        "operator": "list_contains",
        "fact": "modules",
        "value": "commerce",
    },
)
present_result = assert_status(module_present, recommended, "applicable")
assert "evidence.drupal.core-extension-config.config-sync-core-extension-yml" in present_result["evidence_ids"]
assert_status(module_present, composer_only, "unknown")
assert_status(module_present, ambiguous, "unknown")
absent_result = assert_status(module_present, disabled, "not_applicable")
assert "FACT_CONTRADICTS_REQUIREMENT" in absent_result["reason_codes"]

known_empty = copy.deepcopy(recommended)
known_empty["profile"]["facts"]["modules"]["value"] = []
known_empty["completeness"]["drupal_config"] = "available"
empty_result = assert_status(module_present, known_empty, "not_applicable")
assert "FACT_CONTRADICTS_REQUIREMENT" in empty_result["reason_codes"]

incomplete_domain = copy.deepcopy(recommended)
incomplete_domain["profile"]["facts"]["modules"]["value"] = []
incomplete_domain["completeness"]["drupal_config"] = "ambiguous"
unknown_result = assert_status(module_present, incomplete_domain, "unknown")
assert "EVIDENCE_DOMAIN_INCOMPLETE" in unknown_result["reason_codes"]

not_enabled_by_package = synthetic_record(
    "drupal.synthetic.webform-module",
    {
        "operator": "list_contains",
        "fact": "modules",
        "value": "webform",
    },
)
assert_status(not_enabled_by_package, disabled, "not_applicable")

unreviewed_blocking = synthetic_record(
    "drupal.synthetic.unreviewed",
    {
        "operator": "equals",
        "fact": "project_type",
        "path": "value.type",
        "value": "drupal",
    },
    review_status="seed_needs_human_review",
    enforcement_intent="blocking",
)
unreviewed_result = assert_status(unreviewed_blocking, recommended, "applicable")
assert unreviewed_result["effective_enforcement"] == "advisory"

human_only = synthetic_record("drupal.synthetic.semantic", None)
human_result = assert_status(human_only, recommended, "requires_human_review")
assert "NO_MACHINE_APPLICABILITY_CONTRACT" in human_result["reason_codes"]

stable_version = synthetic_record(
    "drupal.synthetic.version",
    {
        "operator": "version_matches",
        "fact": "drupal_core_version",
        "path": "value.version",
        "constraint": "11.x",
    },
)
assert_status(stable_version, recommended, "applicable")
version_result = assert_status(stable_version, prerelease, "unknown")
assert "UNSUPPORTED_VERSION_SEMANTICS" in version_result["reason_codes"]
unsupported_constraint = synthetic_record(
    "drupal.synthetic.unsupported-version",
    {
        "operator": "version_matches",
        "fact": "drupal_core_version",
        "path": "value.version",
        "constraint": "^11",
    },
)
constraint_result = assert_status(unsupported_constraint, recommended, "unknown")
assert "UNSUPPORTED_VERSION_CONSTRAINT" in constraint_result["reason_codes"]

bad_path = synthetic_record(
    "drupal.synthetic.bad-path",
    {
        "operator": "equals",
        "fact": "project_type",
        "path": "value.__class__",
        "value": "dict",
    },
)
try:
    resolve_one(bad_path, recommended)
except dk_core.ValidationError:
    pass
else:
    raise AssertionError("unsafe fact path must be rejected")

type_mismatch = synthetic_record(
    "drupal.synthetic.type-mismatch",
    {
        "operator": "list_contains",
        "fact": "project_type",
        "path": "value.type",
        "value": "drupal",
    },
)
type_result = assert_status(type_mismatch, recommended, "unknown")
assert "PREDICATE_TYPE_MISMATCH" in type_result["reason_codes"]

invalid_analysis = {"schema_version": "0.1"}
try:
    dk_applicability.resolve_analysis_data(invalid_analysis, validate_canonical_knowledge=False)
except dk_applicability.ResolverValidationError:
    pass
else:
    raise AssertionError("invalid analyzer input must fail")

future_analysis = copy.deepcopy(recommended)
future_analysis["schema_version"] = "9.9"
try:
    dk_applicability.resolve_analysis_data(future_analysis, validate_canonical_knowledge=False)
except dk_applicability.ResolverValidationError:
    pass
else:
    raise AssertionError("unsupported analyzer schema version must fail")

with tempfile.TemporaryDirectory() as workspace:
    repo = Path(workspace) / "repo"
    shutil.copytree(
        ROOT,
        repo,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"),
    )
    record_path = next((repo / "knowledge" / "records").rglob("*.json"))
    record_data = json.loads(record_path.read_text(encoding="utf-8"))
    record_data["review_status"] = "invalid"
    record_path.write_text(dk_core.stable_json(record_data), encoding="utf-8")
    try:
        dk_applicability.resolve_analysis_data(recommended, root=repo)
    except dk_core.ValidationError:
        pass
    else:
        raise AssertionError("resolver must require valid canonical knowledge")

with tempfile.TemporaryDirectory() as workspace:
    analysis_path = Path(workspace) / "analysis.json"
    analysis_path.write_text(dk_project_analyzer.stable_json(recommended), encoding="utf-8")
    before_tree = protected_digest()
    before_input = sha256(analysis_path.read_bytes()).hexdigest()
    first = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "resolve", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "resolve", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert first.stdout == second.stdout
    assert before_input == sha256(analysis_path.read_bytes()).hexdigest()
    assert before_tree == protected_digest()
    assert json.loads(first.stdout) == canonical

original_socket = socket.socket


def deny_socket(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("resolver must not use network sockets")


socket.socket = deny_socket
try:
    offline_result = dk_applicability.resolve_analysis_data(recommended)
finally:
    socket.socket = original_socket
assert offline_result == canonical

resolver_source = (ROOT / "scripts" / "dk_applicability.py").read_text(encoding="utf-8")
assert "requests" not in resolver_source
assert "urllib" not in resolver_source
assert "socket" not in resolver_source
assert "subprocess" not in resolver_source
assert "os.walk" not in resolver_source
assert "rglob(" not in resolver_source
assert "analyze_project(" not in resolver_source
assert "composer.json" not in resolver_source
assert "composer.lock" not in resolver_source
assert "core.extension.yml" not in resolver_source

resolution_text = dk_applicability.stable_json(canonical)
assert "content_sha256" not in resolution_text
assert '"evidence":' not in resolution_text
for text in recursive_strings(canonical):
    assert text.lower() not in {"vulnerable", "secure", "compliant", "non-compliant"}

ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert "test_applicability_resolver_foundation.py" in ci
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
assert "continue-on-error" not in ci, "validation must be required"

print("CURRENT_KNOWLEDGE_APPLICABILITY_AUDITED=PASS")
print("FREE_TEXT_CANNOT_AUTHOR_APPLICABILITY=PASS")
print("APPLICABILITY_CONTRACT_DECLARATIVE=PASS")
print("APPLICABILITY_USES_THREE_VALUED_LOGIC=PASS")
print("THREE_VALUED_LOGIC_TRUTH_TABLE=PASS")
print("UNKNOWN_DISTINCT_FROM_HUMAN_REVIEW=PASS")
print("ABSENCE_ONLY_AUTHORITATIVE_WHEN_DOMAIN_COMPLETE=PASS")
print("KNOWN_EMPTY_DISTINCT_FROM_UNKNOWN=PASS")
print("RESOLUTION_RESPECTS_ANALYZER_COMPLETENESS=PASS")
print("APPLICABILITY_HAS_EVIDENCE_PROVENANCE=PASS")
print("APPLICABILITY_REASON_CODES_STABLE=PASS")
print("UNREVIEWED_APPLICABLE_RECORD_CANNOT_BLOCK=PASS")
print("APPLICABILITY_DOES_NOT_ESCALATE_ENFORCEMENT=PASS")
print("CURRENT_KNOWLEDGE_REMAINS_GUIDANCE_ONLY=PASS")
print("RESOLVER_EMITS_NO_COMPLIANCE_FINDINGS=PASS")
print("VERSION_APPLICABILITY_FAILS_CLOSED=PASS")
print("UNSUPPORTED_VERSION_SEMANTICS_NOT_GUESSED=PASS")
print("AUTOMATION_LIMITATION_DOES_NOT_DOWNGRADE_TRUSTED_KNOWLEDGE=PASS")
print("CODE_SEMANTICS_NOT_INFERRED_FROM_PROJECT_SHAPE=PASS")
print("INVALID_ANALYZER_INPUT_REJECTED=PASS")
print("ANALYZER_SCHEMA_VERSION_ENFORCED=PASS")
print("RESOLVER_REQUIRES_VALID_KNOWLEDGE=PASS")
print("APPLICABILITY_RESOLUTION_DETERMINISTIC=PASS")
print("RESOLUTION_IDENTIFIES_KNOWLEDGE_SET=PASS")
print("RESOLUTION_IDENTIFIES_ANALYSIS_INPUT=PASS")
print("RESOLVER_KNOWLEDGE_IDENTITY_USES_CURRENT_VERSION=PASS")
print("RESOLUTION_OUTPUT_SCHEMA_VALID=PASS")
print("RESOLVER_OUTPUT_MINIMIZES_SOURCE_DATA=PASS")
print("RESOLVER_SIDE_EFFECT_FREE=PASS")
print("APPLICABILITY_RESOLUTION_OFFLINE=PASS")
print("RESOLVER_DOES_NOT_RESCAN_PROJECT=PASS")
print("RESOLVER_CONSUMES_ANALYZER_CONTRACT_ONLY=PASS")
print("ANALYZER_RESOLVER_CONTRACT_INTEGRATION=PASS")
print("APPLICABILITY_IS_NOT_COMPLIANCE=PASS")
print("MISSING_CONFIG_PROPAGATES_UNKNOWN=PASS")
print("KNOWN_EXTENSION_ABSENCE_CAN_EXCLUDE=PASS")
print("AMBIGUOUS_CONFIG_PROPAGATES_UNKNOWN=PASS")
print("FACT_PATH_LOOKUP_FAILS_SAFE=PASS")
print("APPLICABILITY_PREDICATES_TYPE_SAFE=PASS")
print("APPLICABILITY_RESOLVER_REAL_CI=PASS")
