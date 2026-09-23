#!/usr/bin/env python3
"""Finding runtime behavior invariants.

Proves that the reviewed machine_finding contract is executed into real
finding evaluations, that every negative, unknown, stale, and unreviewed path
fails closed, that identity is deterministic, and that the runtime stays
inside its authority boundary: no project rescan, no network, no source
collection, no invented severity, no escalated enforcement, no remediation.
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import dk_core
import dk_finding_runtime
import dk_project_analyzer


ROOT = dk_core.ROOT
FIXTURES = ROOT / "tests" / "fixtures" / "project-analyzer"
RECORD_ID = "drupal.update.core-release-insecure-term-condition"
RECORD_PATH = ROOT / "knowledge" / "records" / f"{RECORD_ID}.json"

record = dk_core.read_json(RECORD_PATH)
contract = record["machine_finding"]


def analyze_fixture(name: str) -> dict[str, Any]:
    result = dk_project_analyzer.analyze_project(FIXTURES / name)
    return result.data


def analyze_path(path: Path) -> dict[str, Any]:
    return dk_project_analyzer.analyze_project(path).data


def with_core_version(analysis: dict[str, Any], version: str) -> dict[str, Any]:
    mutated = copy.deepcopy(analysis)
    fact = mutated["profile"]["facts"]["drupal_core_version"]
    fact["state"] = "known"
    fact["value"] = {"package": "drupal/core", "version": version}
    fact["source_evidence_ids"] = ["evidence.drupal.composer-lock.composer-lock"]
    fact["confidence"] = "high"
    fact["notes"] = "Synthetic analyzer-contract fixture for finding runtime tests."
    return mutated


def single_finding(evaluation: dict[str, Any]) -> dict[str, Any]:
    assert evaluation["contracts"]["executed"] == 1
    assert len(evaluation["findings"]) == 1
    return evaluation["findings"][0]


def data_root_copy(destination: Path) -> Path:
    """Copy the canonical data tree so tests can mutate authority safely."""
    root = destination / "root"
    root.mkdir()
    for directory in ("knowledge", "sources", "schema", "taxonomy"):
        shutil.copytree(
            ROOT / directory,
            root / directory,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    (root / "VERSION").write_text(
        (ROOT / "VERSION").read_text(encoding="utf-8"), encoding="utf-8"
    )
    return root


recommended = analyze_fixture("recommended")
term_absent = analyze_fixture("insecure-term-absent")
row_missing = analyze_fixture("release-row-missing")
composer_only = analyze_fixture("composer-only")


# --- reviewed authorized exact condition -> exactly one confirmed finding ----
evaluation = dk_finding_runtime.evaluate_analysis_data(recommended)
assert dk_finding_runtime.validate_finding_evaluation(evaluation) == [
    "FINDING_EVALUATION_SCHEMA_VALID=PASS"
]
confirmed = single_finding(evaluation)
assert confirmed["state"] == "confirmed"
assert confirmed["observation_key"] == "term_present_and_context_current"
assert confirmed["knowledge_id"] == RECORD_ID
assert confirmed["condition_id"] == contract["condition_id"]
assert confirmed["assertion"] == contract["assertion"]
assert confirmed["human_title"] == contract["human_title"]
assert confirmed["finding_type"] == "release_lifecycle"
assert evaluation["summary"]["states"]["confirmed"] == 1
assert evaluation["summary"]["states"]["unknown"] == 0
assert evaluation["contracts"]["not_executed"] == []
assert evaluation["evidence"]["domain"] == "release_lifecycle_assessment"
assert evaluation["evidence"]["assessment_error"] is None


# --- the runtime executes the contract, not a bespoke version check ----------
runtime_source = (ROOT / "scripts" / "dk_finding_runtime.py").read_text(encoding="utf-8")
assert "11.2.3" not in runtime_source
assert "Insecure" not in runtime_source
assert RECORD_ID not in runtime_source
assert "machine_finding" in runtime_source
assert confirmed["provenance"]["literal_source_term"]["value"] == "Insecure"
assert confirmed["provenance"]["literal_source_term"]["match_mode"] == "literal_exact_string"


# --- provenance is complete per the reviewed contract ------------------------
provenance = confirmed["provenance"]
assert set(contract["provenance_requirements"]) <= set(provenance)
assert not [key for key, value in provenance.items() if value is None]
assert provenance["exact_matched_release"] == "11.2.3"
assert provenance["core_version_fact_ref"] == "drupal_core_version"
assert provenance["core_version_evidence_ids"] == [
    "evidence.drupal.composer-lock.composer-lock"
]
assert provenance["lifecycle_context_id"] == "drupal-core-release-lifecycle"
assert dk_core.SHA256_RE.fullmatch(provenance["lifecycle_context_source_snapshot_sha256"])
assert dk_core.SHA256_RE.fullmatch(provenance["lifecycle_assessment_id"])
assert provenance["context_relation"] == "current"
assert provenance["effective_enforcement"] == "guidance"
assert provenance["finding_severity_state"] == "not_established"
assert provenance["analysis_identity"]["project_id"] == "example/recommended-fixture"
# Confirmation consumed the canonical Applicability Resolver, definitively.
applicability_ref = provenance["applicability_result_identity"]
assert applicability_ref["applicability"] == "applicable"
assert applicability_ref["automation_status"] == "machine_resolved"
assert applicability_ref["resolver"]["name"] == "drupal-knowledge-applicability-resolver"
assert "drupal_core_version" in applicability_ref["fact_refs"]
# Confirmation is version-scoped to the reviewed semantic authority majors.
scope_ref = provenance["semantic_authority_version_scope"]
assert scope_ref == {
    "drupal_core_majors": ["11"],
    "installed_core_major": "11",
    "in_scope": True,
}


# --- the explanation reuses provenance and reviewed meaning only -------------
explanation = confirmed["explanation"]
assert "11.2.3" in explanation["observed"]
assert "example/recommended-fixture" in explanation["observed"]
assert provenance["lifecycle_context_source_snapshot_sha256"] in (
    explanation["authoritative_drupal_knowledge"]
)
assert explanation["drupal_definition"] == contract["term_semantics"]["authorized_meaning"]
assert "missing security update(s)" in explanation["drupal_definition"]
assert contract["human_title"] in explanation["conclusion"]
assert confirmed["claim"]["meaning_authorized"] is True
assert confirmed["claim"]["authorized_meaning"] == (
    contract["term_semantics"]["authorized_meaning"]
)
assert confirmed["claim"]["temporality"] == "current"
assert sorted(contract["term_semantics"]["forbidden_claims"]) == confirmed["not_claimed"]


# --- exact release without the term -> not_observed, never a security pass ---
absent_evaluation = dk_finding_runtime.evaluate_analysis_data(term_absent)
absent = single_finding(absent_evaluation)
assert absent["state"] == "not_observed"
assert absent["observation_key"] == "term_absent_in_matched_row"
# The "term absent" fixture tracks the reviewed semantic authority release, so
# it cannot silently become a release that upstream has marked Insecure.
assert absent["provenance"]["exact_matched_release"] == dk_core.semantic_authority_tag()
assert absent["provenance"]["literal_source_term"]["present_on_matched_release"] is False
assert absent["claim"]["meaning_authorized"] is False
assert absent["claim"]["authorized_meaning"] is None
serialized_absent = dk_finding_runtime.stable_json(absent_evaluation).lower()
for forbidden in ('"passed"', '"secure"', '"safe"'):
    assert forbidden not in serialized_absent, forbidden
assert "not a security pass" in absent["explanation"]["conclusion"].lower()

# A release carrying only the "Security update" term is still not_observed:
# the non-authoritative signal is ignored.
# A currently published security release on another supported branch: it
# carries "Security update" and not the audited term. Taken from the reviewed
# observation so it cannot silently become a superseded release.
SECURITY_UPDATE_ONLY_RELEASE = dk_core.read_json(
    ROOT / "docs" / "lifecycle-finding-eligibility-review-2026-09-23.json"
)["current_reviewed_observation"]["rows_with_security_update_term_and_without_insecure_term"][1]
security_update_only = dk_finding_runtime.evaluate_analysis_data(
    with_core_version(recommended, SECURITY_UPDATE_ONLY_RELEASE)
)
security_update_finding = single_finding(security_update_only)
assert security_update_finding["state"] == "not_observed"
assert security_update_finding["provenance"]["exact_matched_release"] == SECURITY_UPDATE_ONLY_RELEASE


# --- cross-major semantic authority leakage is blocked ------------------------
# Drupal 9 and Drupal 10 releases carry the literal term in the reviewed
# context, but the reviewed semantics are pinned Drupal 11 update-module
# sources. Outside that scope the observation caps at candidate: never
# confirmed, never given the reviewed meaning, never called secure or absent.
for out_of_scope_version, out_of_scope_major in (("9.5.9", "9"), ("10.3.0", "10")):
    out_of_scope = dk_finding_runtime.evaluate_analysis_data(
        with_core_version(recommended, out_of_scope_version)
    )
    entry = single_finding(out_of_scope)
    assert entry["state"] == "candidate", out_of_scope_version
    assert entry["observation_key"] == "term_present_and_semantic_authority_version_out_of_scope"
    assert entry["reason_code"] == "SEMANTIC_AUTHORITY_VERSION_OUT_OF_SCOPE"
    assert out_of_scope["summary"]["states"]["confirmed"] == 0
    assert entry["claim"]["meaning_authorized"] is False
    assert entry["claim"]["authorized_meaning"] is None
    assert entry["provenance"]["semantic_authority_version_scope"] == {
        "drupal_core_majors": ["11"],
        "installed_core_major": out_of_scope_major,
        "in_scope": False,
    }
    assert entry["provenance"]["literal_source_term"]["present_on_matched_release"] is None
    serialized_scope = dk_finding_runtime.stable_json(out_of_scope).lower()
    for forbidden in ('"passed"', '"secure"', '"safe"'):
        assert forbidden not in serialized_scope, (out_of_scope_version, forbidden)
    assert "not a security pass" in entry["explanation"]["conclusion"].lower()
    assert "drupal core major" in entry["explanation"]["drupal_definition"].lower()

# A major outside the reviewed feed entirely fails closed as unknown.
future_major = single_finding(
    dk_finding_runtime.evaluate_analysis_data(with_core_version(recommended, "12.0.0"))
)
assert future_major["state"] == "unknown"
assert future_major["observation_key"] == "release_not_found"


# --- confirmed findings require definitive canonical applicability ------------
# A contract-bearing record whose applicability cannot resolve definitively
# (here: the explicit machine contract is removed, reverting the record to the
# legacy requires_human_review resolution) must fail closed as unknown even
# though the term is present on an in-scope release.
with tempfile.TemporaryDirectory() as temp:
    root = data_root_copy(Path(temp))
    record_path = root / "knowledge" / "records" / f"{RECORD_ID}.json"
    bypassed = dk_core.read_json(record_path)
    del bypassed["machine_applicability"]
    record_path.write_text(dk_core.stable_json(bypassed), encoding="utf-8")
    no_applicability = dk_finding_runtime.evaluate_analysis_data(recommended, root=root)
    gated = single_finding(no_applicability)
    assert gated["state"] == "unknown"
    assert gated["observation_key"] == "applicability_not_definitive"
    assert gated["reason_code"] == "APPLICABILITY_REQUIRES_HUMAN_REVIEW"
    assert no_applicability["summary"]["states"]["confirmed"] == 0
    ref = gated["provenance"]["applicability_result_identity"]
    assert ref["applicability"] == "requires_human_review"

# The runtime consumes resolver authority; it does not reimplement predicates.
for resolver_token in ("fact_known", "version_matches", "list_contains", "evaluate_condition"):
    assert resolver_token not in runtime_source, resolver_token
assert "dk_applicability" in runtime_source
assert "resolve_analysis_data" in runtime_source


# --- unknown core version -> unknown -----------------------------------------
unknown_core = single_finding(dk_finding_runtime.evaluate_analysis_data(composer_only))
assert unknown_core["state"] == "unknown"
assert unknown_core["observation_key"] == "core_version_unknown"
assert unknown_core["reason_code"] == "CORE_VERSION_UNKNOWN"
assert unknown_core["provenance"]["exact_matched_release"] is None
assert unknown_core["claim"]["meaning_authorized"] is False


# --- release row missing from context -> unknown -----------------------------
missing = single_finding(dk_finding_runtime.evaluate_analysis_data(row_missing))
assert missing["state"] == "unknown"
assert missing["observation_key"] == "release_not_found"
assert missing["reason_code"] == "EXACT_RELEASE_ROW_NOT_FOUND"


# --- stale context -> historical_candidate, never a current confirmation -----
with tempfile.TemporaryDirectory() as temp:
    root = data_root_copy(Path(temp))
    state_path = root / "sources" / "state" / "drupal-core-releases.json"
    state = dk_core.read_json(state_path)
    snapshot_text = dk_core.require_snapshot(
        ROOT, "drupal-core-releases", state["content_sha256"]
    ).read_text(encoding="utf-8")
    changed_text = snapshot_text + "\n<!-- simulated source movement -->\n"
    changed_sha = dk_core.content_digest(changed_text)
    dk_core.write_snapshot(root, "drupal-core-releases", changed_sha, changed_text)
    state["content_sha256"] = changed_sha
    state["content_length"] = len(changed_text.encode("utf-8"))
    state_path.write_text(dk_core.stable_json(state), encoding="utf-8")
    stale_evaluation = dk_finding_runtime.evaluate_analysis_data(recommended, root=root)
    stale = single_finding(stale_evaluation)
    assert stale["state"] == "historical_candidate"
    assert stale["observation_key"] == "term_present_and_context_stale"
    assert stale_evaluation["summary"]["states"]["confirmed"] == 0
    assert stale["provenance"]["context_relation"] == "stale"
    assert "LIFECYCLE_CONTEXT_STALE" in stale["limitations"]
    assert stale["claim"]["temporality"] == "historical_at_pinned_snapshot"
    assert "no current" in stale["explanation"]["conclusion"].lower()


# --- noncanonical context id -> unknown, fails closed ------------------------
with tempfile.TemporaryDirectory() as temp:
    root = data_root_copy(Path(temp))
    context_path = root / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
    context = dk_core.read_json(context_path)
    context["id"] = "not-the-canonical-context"
    context_path.write_text(dk_core.stable_json(context), encoding="utf-8")
    noncanonical = single_finding(dk_finding_runtime.evaluate_analysis_data(recommended, root=root))
    assert noncanonical["state"] == "unknown"
    assert noncanonical["observation_key"] == "context_not_canonical"
    assert noncanonical["reason_code"] == "CONTEXT_NOT_CANONICAL"


# --- unreviewed context -> assessment invalid -> unknown ---------------------
with tempfile.TemporaryDirectory() as temp:
    root = data_root_copy(Path(temp))
    context_path = root / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
    context = dk_core.read_json(context_path)
    context["review"]["status"] = "candidate"
    context_path.write_text(dk_core.stable_json(context), encoding="utf-8")
    invalid_evaluation = dk_finding_runtime.evaluate_analysis_data(recommended, root=root)
    invalid = single_finding(invalid_evaluation)
    assert invalid["state"] == "unknown"
    assert invalid["observation_key"] == "assessment_invalid"
    assert invalid["reason_code"] == "ASSESSMENT_INVALID"
    assert invalid_evaluation["evidence"]["lifecycle_assessment"] is None
    assert invalid_evaluation["evidence"]["assessment_error"]["reason_code"] == (
        "ASSESSMENT_INVALID"
    )


# --- unreviewed knowledge cannot author findings -----------------------------
with tempfile.TemporaryDirectory() as temp:
    root = data_root_copy(Path(temp))
    record_path = root / "knowledge" / "records" / f"{RECORD_ID}.json"
    unreviewed = dk_core.read_json(record_path)
    unreviewed["review_status"] = "seed_needs_human_review"
    record_path.write_text(dk_core.stable_json(unreviewed), encoding="utf-8")
    refused_evaluation = dk_finding_runtime.evaluate_analysis_data(recommended, root=root)
    assert refused_evaluation["contracts"]["executed"] == 0
    assert refused_evaluation["findings"] == []
    assert refused_evaluation["summary"]["states"]["confirmed"] == 0
    refusals = refused_evaluation["contracts"]["not_executed"]
    assert [item["reason_code"] for item in refusals] == [
        "UNREVIEWED_KNOWLEDGE_CANNOT_AUTHOR_FINDINGS"
    ]


# --- unresolved term semantics cap at candidate, never confirmed -------------
with tempfile.TemporaryDirectory() as temp:
    root = data_root_copy(Path(temp))
    record_path = root / "knowledge" / "records" / f"{RECORD_ID}.json"
    demoted = dk_core.read_json(record_path)
    demoted_contract = demoted["machine_finding"]
    demoted_contract["confirmation_authority"]["status"] = "not_established"
    demoted_contract["confirmation_authority"]["semantic_authority_refs"] = []
    demoted_contract["states"] = dict(dk_core.MACHINE_FINDING_CANDIDATE_STATES)
    demoted_contract["term_semantics"] = {
        "state": "TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY",
        "meaning_bearing_claims_authorized": False,
    }
    del demoted_contract["confirmation_authority"]["semantic_authority_version_scope"]
    record_path.write_text(dk_core.stable_json(demoted), encoding="utf-8")
    candidate_evaluation = dk_finding_runtime.evaluate_analysis_data(recommended, root=root)
    candidate = single_finding(candidate_evaluation)
    assert candidate["state"] == "candidate"
    assert candidate["observation_key"] == "term_present_and_context_current"
    assert candidate_evaluation["summary"]["states"]["confirmed"] == 0
    assert candidate["claim"]["meaning_authorized"] is False
    assert candidate["claim"]["authorized_meaning"] is None


# --- severity is not invented ------------------------------------------------
for entry in (confirmed, absent, unknown_core, missing):
    assert entry["severity"] == {"state": "not_established", "source": None}
    assert entry["severity"]["state"] not in dk_core.SEVERITIES
    assert entry["provenance"]["finding_severity_state"] == "not_established"
assert record["severity"] == "info"
assert confirmed["severity"]["state"] != record["severity"]


# --- enforcement is not escalated --------------------------------------------
for entry in (confirmed, absent, unknown_core, missing):
    assert entry["effective_enforcement"] == "guidance"
assert "blocking" not in json.dumps(evaluation["summary"])
assert evaluation["summary"]["effective_enforcement"] == {"guidance": 1, "advisory": 0}


# --- deterministic identity ---------------------------------------------------
again = dk_finding_runtime.evaluate_analysis_data(recommended)
assert dk_finding_runtime.stable_json(again) == dk_finding_runtime.stable_json(evaluation)
assert again["findings"][0]["finding_id"] == confirmed["finding_id"]
assert again["evaluation_id"] == evaluation["evaluation_id"]
serialized = dk_finding_runtime.stable_json(evaluation)
for volatile in ("evaluated_at", "hostname", "run_id", "wall_clock_time", "timestamp"):
    assert volatile not in serialized

# The same project content at a different absolute path yields the same
# logical finding: no absolute path participates in identity.
with tempfile.TemporaryDirectory() as temp:
    moved_project = Path(temp) / "relocated-project"
    shutil.copytree(FIXTURES / "recommended", moved_project)
    moved_analysis = analyze_path(moved_project)
    moved_evaluation = dk_finding_runtime.evaluate_analysis_data(moved_analysis)
    assert moved_evaluation["findings"][0]["finding_id"] == confirmed["finding_id"]
    assert moved_evaluation["evaluation_id"] == evaluation["evaluation_id"]


# --- duplicate evidence read paths collapse into one logical finding ---------
assert len(evaluation["findings"]) == 1
assert confirmed["deduplication"]["max_instances"] == 1
assert confirmed["deduplication"]["key"] == {
    "knowledge_id": RECORD_ID,
    "condition_id": contract["condition_id"],
    "installed_core_package": "drupal/core",
    "matched_release_source_version": "11.2.3",
}
assert len(confirmed["deduplication"]["collapsed_read_paths"]) >= 3


# --- no project rescan: the project may vanish after analysis ----------------
with tempfile.TemporaryDirectory() as temp:
    ephemeral = Path(temp) / "ephemeral-project"
    shutil.copytree(FIXTURES / "recommended", ephemeral)
    ephemeral_analysis = analyze_path(ephemeral)
    shutil.rmtree(ephemeral)
    assert not ephemeral.exists()
    ephemeral_evaluation = dk_finding_runtime.evaluate_analysis_data(ephemeral_analysis)
    assert ephemeral_evaluation["findings"][0]["state"] == "confirmed"


# --- no network, no source collection, no knowledge mutation -----------------
for token in ("urllib", "requests", "socket", "http.client", "urlopen", "collectors"):
    assert token not in runtime_source, token
assert "fetch" not in runtime_source
assert "write_text" not in runtime_source
assert "write_bytes" not in runtime_source
knowledge_digest_before = dk_core.knowledge_tree_digest()
dk_finding_runtime.evaluate_analysis_data(recommended)
assert dk_core.knowledge_tree_digest() == knowledge_digest_before


# --- no remediation -----------------------------------------------------------
lowered = serialized.lower()
for forbidden in ("composer require", "composer update", "drush ", "upgrade to "):
    assert forbidden not in lowered, forbidden
assert "remediation" not in dk_finding_runtime.recursive_keys(evaluation)


# --- upstream authority unchanged --------------------------------------------
for module in (
    "dk_project_analyzer.py",
    "dk_applicability.py",
    "dk_release_lifecycle.py",
    "dk_release_lifecycle_evaluator.py",
):
    text = (ROOT / "scripts" / module).read_text(encoding="utf-8")
    assert "machine_finding" not in text, module
    assert "dk_finding_runtime" not in text, module


# --- evaluation validator fails closed ---------------------------------------
def rejects(mutate) -> None:
    candidate = copy.deepcopy(evaluation)
    mutate(candidate)
    try:
        dk_finding_runtime.validate_finding_evaluation(candidate)
    except dk_finding_runtime.FindingRuntimeValidationError:
        return
    raise AssertionError(f"finding evaluation validator accepted unsafe mutation: {mutate}")


rejects(lambda out: out.update({"remediation": "composer update drupal/core"}))
rejects(lambda out: out["findings"][0].update({"state": "passed"}))
rejects(lambda out: out["findings"][0].update({"state": "secure"}))
rejects(lambda out: out["findings"][0]["severity"].update({"state": "high"}))
rejects(lambda out: out["findings"][0].update({"effective_enforcement": "blocking"}))
rejects(lambda out: out["findings"][0].update({"evaluated_at": "2026-09-07T00:00:00Z"}))
rejects(lambda out: out["findings"][0]["provenance"].pop("literal_source_term"))
rejects(lambda out: out["summary"]["states"].update({"confirmed": 5}))
rejects(lambda out: out["findings"].append(copy.deepcopy(out["findings"][0])))
rejects(lambda out: out.update({"schema_version": "9.9"}))
rejects(
    lambda out: out["findings"][0]["provenance"]["semantic_authority_version_scope"].update(
        {"in_scope": False}
    )
)
rejects(
    lambda out: out["findings"][0]["provenance"]["applicability_result_identity"].update(
        {"applicability": "unknown"}
    )
)
rejects(
    lambda out: out["findings"][0]["provenance"].update({"applicability_result_identity": None})
)


# --- CLI: deterministic JSON, explanation surface, safe exit codes -----------
with tempfile.TemporaryDirectory() as temp:
    analysis_path = Path(temp) / "analysis.json"
    analysis_path.write_text(dk_project_analyzer.stable_json(recommended), encoding="utf-8")
    first = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "findings", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "findings", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert first.stdout == second.stdout
    parsed = json.loads(first.stdout)
    assert parsed == evaluation
    explain = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "dk.py"),
            "findings",
            str(analysis_path),
            "--explain",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "CONFIRMED" in explain.stdout
    assert "Observed:" in explain.stdout
    assert "Authoritative Drupal knowledge:" in explain.stdout
    assert "Drupal definition:" in explain.stdout
    assert "Conclusion:" in explain.stdout
    assert "missing security update(s)" in explain.stdout
    assert "severity: not established" in explain.stdout
    assert "enforcement: guidance (non-blocking)" in explain.stdout
    missing_run = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "dk.py"),
            "findings",
            str(Path(temp) / "does-not-exist.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert missing_run.returncode == 2
    invalid_path = Path(temp) / "invalid.json"
    invalid_path.write_text("{not json", encoding="utf-8")
    invalid_run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "findings", str(invalid_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert invalid_run.returncode == 1
    version_run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "version"],
        check=True,
        capture_output=True,
        text=True,
    )
    version_payload = json.loads(version_run.stdout)
    assert version_payload["product"] == "Drupal Knowledge"
    assert version_payload["version"] == (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert version_payload["interfaces"]["finding_evaluation_schema"] == "0.1"


# --- runtime contract validation is wired into dk.py validate ----------------
assert dk_core.validate_finding_runtime_contract() == ["FINDING_RUNTIME_CONTRACT_VALID=PASS"]
schema = dk_core.read_json(ROOT / "schema" / "finding-evaluation.schema.json")
states_enum = schema["$defs"]["finding"]["properties"]["state"]["enum"]
assert states_enum == [
    "confirmed",
    "candidate",
    "historical_candidate",
    "not_observed",
    "unknown",
    "requires_human_review",
]
assert contract["runtime_status"] == "executed_by_reviewed_finding_runtime"


print("FINDING_RUNTIME_EXECUTES_REVIEWED_CONTRACT=PASS")
print("FIRST_CONFIRMED_LIFECYCLE_FINDING_DETERMINISTIC_FIXTURE=PASS")
print("FINDING_RUNTIME_NOT_BESPOKE_VERSION_CHECK=PASS")
print("CONFIRMED_FINDING_PROVENANCE_COMPLETE=PASS")
print("FINDING_EXPLANATION_REUSES_PROVENANCE=PASS")
print("TERM_ABSENCE_IS_NOT_SECURITY_PASS=PASS")
print("NON_AUTHORITATIVE_SECURITY_UPDATE_TERM_IGNORED=PASS")
print("UNKNOWN_CORE_VERSION_FAILS_CLOSED=PASS")
print("MISSING_RELEASE_ROW_FAILS_CLOSED=PASS")
print("STALE_CONTEXT_NEVER_CURRENT_CONFIRMATION=PASS")
print("NONCANONICAL_CONTEXT_CANNOT_CONFIRM=PASS")
print("UNREVIEWED_CONTEXT_FAILS_CLOSED=PASS")
print("UNREVIEWED_KNOWLEDGE_CANNOT_AUTHOR_RUNTIME_FINDINGS=PASS")
print("UNRESOLVED_SEMANTICS_CAP_AT_CANDIDATE_IN_RUNTIME=PASS")
print("FINDING_SEVERITY_NOT_INVENTED_BY_RUNTIME=PASS")
print("FINDING_ENFORCEMENT_NOT_ESCALATED_BY_RUNTIME=PASS")
print("FINDING_IDENTITY_DETERMINISTIC=PASS")
print("FINDING_IDENTITY_PATH_INDEPENDENT=PASS")
print("DUPLICATE_EVIDENCE_PATHS_ONE_LOGICAL_FINDING=PASS")
print("FINDING_RUNTIME_NO_PROJECT_RESCAN=PASS")
print("FINDING_RUNTIME_NO_NETWORK_NO_COLLECTION=PASS")
print("FINDING_RUNTIME_NO_KNOWLEDGE_MUTATION=PASS")
print("FINDING_RUNTIME_NO_REMEDIATION=PASS")
print("UPSTREAM_AUTHORITY_MODULES_UNCHANGED=PASS")
print("FINDING_EVALUATION_VALIDATOR_FAILS_CLOSED=PASS")
print("FINDING_CLI_DETERMINISTIC_AND_EXPLAINABLE=PASS")
print("SEMANTIC_AUTHORITY_VERSION_SCOPE_EXPLICIT=PASS")
print("CROSS_MAJOR_SEMANTIC_AUTHORITY_LEAKAGE_BLOCKED=PASS")
print("DRUPAL9_NOT_CONFIRMED_BY_DRUPAL11_SEMANTICS=PASS")
print("OUT_OF_SCOPE_SEMANTIC_VERSION_CANNOT_CONFIRM=PASS")
print("UNKNOWN_SEMANTIC_VERSION_IS_NOT_SECURITY_PASS=PASS")
print("CONFIRMED_FINDING_REQUIRES_DEFINITIVE_APPLICABILITY=PASS")
print("FINDING_RUNTIME_DOES_NOT_BYPASS_APPLICABILITY_AUTHORITY=PASS")
print("APPLICABILITY_LOGIC_NOT_DUPLICATED=PASS")
print("DK_VERSION_HANDSHAKE_SURFACE_PRESENT=PASS")
print("REAL_PROJECT_FINDING_PIPELINE_COMPONENTS_WIRED=PASS")
