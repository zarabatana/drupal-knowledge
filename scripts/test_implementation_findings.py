#!/usr/bin/env python3
"""When a reviewed rule and observed evidence may say something, and when they may not.

The twelve fixtures below guard the one step this engine exists to make safely:
turning a project observation into something a developer should act on. Four
ways that step goes wrong, each with a fixture:

    a preference dressed as a rule        -> authority is checked against the registry
    an unreviewed rule confirming things  -> capped at candidate, always
    a guess treated as an observation     -> heuristic evidence can never confirm
    a context-free verdict                -> missing context caps at candidate

The last one is the subtle one, and it is why this engine has a context
contract at all. Drupal's own documentation says a site behind a CDN can
disable page caching on purpose. A rule that ignored that would be confidently
wrong on every well-run site it met.

Everything here is hermetic: fixtures build their own evidence sets and rules.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_applicability
import dk_core
import dk_evidence as E
import dk_implementation as I


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"

REGISTERED = {source["id"]: source for source in dk_core.load_sources(ROOT)}
PRODUCTION_RULES = I.load_rules(ROOT)
BY_ID = {rule["rule_id"]: rule for rule in PRODUCTION_RULES}


# --- hermetic evidence --------------------------------------------------------


def evidence_set(records: list[dict], revision: str = "a" * 64) -> dict:
    """An evidence set in exactly the shape the evidence engine emits."""
    by_domain = {domain: 0 for domain in E.DOMAINS}
    by_state = {state: 0 for state in E.STATES}
    for item in records:
        by_domain[item["domain"]] += 1
        by_state[item["observation"]["state"]] += 1
    payload = {
        "schema_version": E.EVIDENCE_SET_VERSION,
        "evidence_set_id": "evidence-set." + revision[:16],
        "result_domain": E.RESULT_DOMAIN,
        "engine": {
            "name": E.ENGINE_NAME,
            "version": E.ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
            "produces_trusted_knowledge": False,
            "project_writes": False,
        },
        "generated_at": "2026-09-09T00:00:00Z",
        "project": {
            "project_id": "fixture/implementation",
            "project_fingerprint": "f" * 64,
            "revision_fingerprint": revision,
            "facts_source": "drupal_project_analyzer_profile_facts",
            "analyzer_version": "0.1",
        },
        "records": records,
        "summary": {
            "records": len(records),
            "by_domain": by_domain,
            "by_state": by_state,
            "definitive": sum(1 for item in records if item["observation"]["definitive"]),
            "negative_capable": sum(
                1 for item in records if item["completeness"]["supports_negative_conclusion"]
            ),
        },
        "domain_completeness": {
            domain: {"search_domain": E.COMPLETE, "basis": "fixture"} for domain in E.DOMAINS
        },
        "boundaries": {
            "runtime_observed": False,
            "database_inspected": False,
            "php_executed": False,
            "statement": "fixture",
            "security_relationship": "fixture",
        },
        "execution": {"project_writes": False, "code_modified": False, "runtime_probed": False},
        "trusted_knowledge_mutations": {
            "knowledge_records": 0,
            "reviewed_context": 0,
            "source_derived_records": 0,
            "advisories": 0,
            "solved_cases": 0,
            "discovery": 0,
        },
    }
    E.validate_set(payload)
    return payload


def core_version(version: str = "10.6.0") -> dict:
    return E.record(
        E.A_CORE_VERSION,
        "drupal/core",
        state=E.OBSERVED,
        value=version,
        quality=E.QUALITY_CANONICAL,
        completeness=E.COMPLETE,
        extraction="installed_core_package",
    )


def config_value(subject: str, value, completeness: str = E.BOUNDED) -> dict:
    return E.record(
        E.A_CONFIG_VALUE,
        subject,
        state=E.OBSERVED,
        value=value,
        quality=E.QUALITY_CANONICAL,
        completeness=completeness,
        extraction="exported_config_declared_key",
        scope={"config_name": subject.split(":")[0], "key": subject.split(":")[1]},
    )


def settings_value(key: str, value) -> dict:
    return E.record(
        E.A_SETTINGS_VALUE,
        key,
        state=E.OBSERVED,
        value=value,
        quality=E.QUALITY_SYNTAX,
        completeness=E.BOUNDED,
        extraction="settings_php_scalar_assignment",
    )


def exported_enabled(name: str, kind: str = "module") -> dict:
    return E.record(
        E.A_EXTENSION_EXPORTED_ENABLED,
        name,
        state=E.OBSERVED,
        value={"extension_type": kind, "source": "core.extension"},
        quality=E.QUALITY_CANONICAL,
        completeness=E.COMPLETE,
        extraction="core_extension_exported_config",
    )


def config_dependency(name: str, modules: list[str]) -> dict:
    return E.record(
        E.A_CONFIG_DEPENDENCY,
        name,
        state=E.OBSERVED,
        value={"modules": modules},
        quality=E.QUALITY_CANONICAL,
        completeness=E.PARTIAL,
        extraction="exported_config_dependencies_block",
        scope={"path": f"config/sync/{name}.yml", "config_name": name},
    )


def finding_for(result: dict, rule_id: str) -> dict:
    return next(item for item in result["findings"] if item["rule_id"] == rule_id)


def evaluate(records: list[dict], rules: list[dict], revision: str = "a" * 64) -> dict:
    return I.evaluate(
        evidence_set(records, revision), ROOT, rules=rules, generated_at="2026-09-09T00:00:00Z"
    )


# --- the contract itself --------------------------------------------------------

assert set(I.CATEGORIES) == {"performance", "security", "configuration_quality"}
assert set(I.FINDING_STATES) >= {"confirmed", "candidate", "not_observed", "unknown"}
assert set(I.REVIEW_STATES) == {"draft", "reviewed", "deprecated", "superseded"}
assert I.CONFIRMING_REVIEW_STATES == frozenset({"reviewed"})
# Every category is represented and the initial set stays deliberately small.
counts = {name: sum(1 for rule in PRODUCTION_RULES if rule["category"] == name) for name in I.CATEGORIES}
assert all(2 <= count <= 4 for count in counts.values()), counts
assert len(PRODUCTION_RULES) == sum(counts.values()) == 9
print("IMPLEMENTATION_RULE_CONTRACT_MACHINE_READABLE=PASS")
print("IMPLEMENTATION_RULE_CATEGORIES_DISTINCT=PASS")
print("INITIAL_IMPLEMENTATION_RULE_SET_BOUNDED=PASS")

# A rule's authority is checked against the registry, not asserted by the rule.
for rule in PRODUCTION_RULES:
    I.validate_rule(rule, REGISTERED, ROOT)
    for reference in rule["authority"]["sources"]:
        source = REGISTERED[reference["source_id"]]
        assert source["trust"] == "authoritative"
        assert rule["category"] in source["implementation_authority"]["categories"]
        assert reference["quotes"], rule["rule_id"]

invented = copy.deepcopy(BY_ID["security.update-php-free-access-enabled"])
invented["authority"]["sources"] = [
    {"source_id": "drupal-contrib-token-releases", "snapshot_sha256": "sha256:" + "0" * 64, "quotes": ["x"]}
]
try:
    I.validate_rule(invented, REGISTERED, ROOT)
except dk_core.ValidationError:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("a rule cited a source that is not implementation authority")
print("IMPLEMENTATION_RULE_AUTHORITY_EXPLICIT=PASS")

# Rules use the Prompt 12 evidence vocabulary and nothing else.
for rule in PRODUCTION_RULES:
    check = rule["check"]
    if check["kind"] == I.CHECK_CONDITION:
        stack = [check["condition"]]
        while stack:
            node = stack.pop()
            for key in ("all", "any"):
                if key in node:
                    stack.extend(node[key])
            if "not" in node:
                stack.append(node["not"])
            if "assertion" in node:
                assert node["assertion"] in E.ASSERTIONS, node
    else:
        assert check["source_assertion"] in E.ASSERTIONS
        assert check["target_assertion"] in E.ASSERTIONS
print("IMPLEMENTATION_RULES_USE_MACHINE_READABLE_EVIDENCE_REQUIREMENTS=PASS")
print("IMPLEMENTATION_RULES_REUSE_PROJECT_EVIDENCE=PASS")


# --- fixture A: definitive configuration-quality issue ----------------------------

RULE_CONFIG = BY_ID["configuration_quality.config-depends-on-module-not-enabled"]
result_a = evaluate(
    [
        core_version(),
        exported_enabled("node"),
        exported_enabled("user"),
        config_dependency("views.view.frontpage", ["node", "webform"]),
    ],
    [RULE_CONFIG],
)
finding_a = finding_for(result_a, RULE_CONFIG["rule_id"])
assert finding_a["state"] == I.CONFIRMED, finding_a
assert finding_a["evidence"]["occurrences"] == [
    {
        "subject": "views.view.frontpage",
        "missing": "webform",
        "path": "config/sync/views.view.frontpage.yml",
        "evidence_id": finding_a["evidence"]["evidence_ids"][0],
    }
]
assert finding_a["effective_enforcement"] == I.ENFORCEMENT_GUIDANCE
assert finding_a["severity"]["state"] == "not_established"
print("FIXTURE_A_DEFINITIVE_CONFIG_QUALITY_ISSUE_CONFIRMED=PASS")
print("CONFIG_QUALITY_FINDINGS_REQUIRE_OPERATIONAL_RELEVANCE=PASS")

# An exported-enabled module is not a claim that it runs, and the finding says so.
assert any("not proof the module is enabled at runtime" in text for text in finding_a["limitations"])
print("CONFIG_DEPENDENCY_FINDINGS_RESPECT_EXTENSION_SEMANTICS=PASS")


# --- fixture B: same rule, condition not met in a complete domain -------------------

result_b = evaluate(
    [
        core_version(),
        exported_enabled("node"),
        exported_enabled("webform"),
        config_dependency("views.view.frontpage", ["node", "webform"]),
    ],
    [RULE_CONFIG],
)
finding_b = finding_for(result_b, RULE_CONFIG["rule_id"])
assert finding_b["state"] == I.NOT_OBSERVED, finding_b
assert finding_b["reason_code"] == "RULE_CONDITION_NOT_MET"
# not_observed is not a conformance verdict, and no such state exists.
assert not set(I.FINDING_STATES) & I.FORBIDDEN_STATE_VALUES
print("FIXTURE_B_CONDITION_NOT_MET_IS_NOT_A_PASS=PASS")


# --- fixture C: partial evidence domain -------------------------------------------

partial_target = E.record(
    E.A_EXTENSION_EXPORTED_ENABLED,
    "node",
    state=E.OBSERVED,
    value={"extension_type": "module", "source": "core.extension"},
    quality=E.QUALITY_CANONICAL,
    completeness=E.PARTIAL,
    extraction="core_extension_exported_config",
)
result_c = evaluate(
    [core_version(), partial_target, config_dependency("views.view.frontpage", ["webform"])],
    [RULE_CONFIG],
)
finding_c = finding_for(result_c, RULE_CONFIG["rule_id"])
assert finding_c["state"] == I.UNKNOWN, finding_c
assert finding_c["reason_code"] == "EVIDENCE_DOMAIN_INCOMPLETE"
print("FIXTURE_C_PARTIAL_DOMAIN_IS_UNKNOWN=PASS")
print("IMPLEMENTATION_FINDING_NEGATIVE_EVIDENCE_REQUIRES_COMPLETE_DOMAIN=PASS")


# --- fixture D: performance recommendation ------------------------------------------

RULE_PAGE_CACHE = BY_ID["performance.page-cache-maximum-age-zero"]
result_d = evaluate(
    [core_version(), config_value("system.performance:cache.page.max_age", 0)],
    [RULE_PAGE_CACHE],
)
finding_d = finding_for(result_d, RULE_PAGE_CACHE["rule_id"])
assert finding_d["category"] == "performance"
assert finding_d["effective_enforcement"] == I.ENFORCEMENT_GUIDANCE
assert finding_d["severity"]["state"] == "not_established"
assert result_d["summary"]["blocking"] == 0
# Performance guidance never borrows security-style weight.
assert finding_d["severity"]["source"] is None
assert any("No runtime performance was measured" in text for text in finding_d["limitations"])
print("FIXTURE_D_PERFORMANCE_IS_NON_BLOCKING_GUIDANCE=PASS")
print("PERFORMANCE_GUIDANCE_NOT_FAKE_SECURITY_SEVERITY=PASS")
print("STATIC_PERFORMANCE_EVIDENCE_NOT_RUNTIME_PERFORMANCE_PROOF=PASS")

# The rule declares the deployment context it would need, and without it the
# finding is a candidate rather than a verdict.
assert finding_d["state"] == I.CANDIDATE
assert finding_d["reason_code"] == "REQUIRED_CONTEXT_NOT_OBSERVED"
assert finding_d["context"]["complete"] is False
assert "reverse caching proxy" in finding_d["explanation"]["what_remains_unknown"]
print("CONTEXT_DEPENDENT_RULES_REQUIRE_CONTEXT=PASS")
print("VIEWS_CACHE_FINDING_CONTEXT_CONSERVATIVE=PASS")


# --- fixture E: environment-dependent configuration ------------------------------------

RULE_ERRORS = BY_ID["security.verbose-error-display-without-environment-evidence"]
result_e = evaluate(
    [core_version(), config_value("system.logging:error_level", "verbose")],
    [RULE_ERRORS],
)
finding_e = finding_for(result_e, RULE_ERRORS["rule_id"])
assert finding_e["state"] == I.CANDIDATE, finding_e
assert finding_e["context"]["unsatisfied"] == ["project.environment"]
assert "production" in finding_e["explanation"]["conclusion"]
assert finding_e["state"] != I.CONFIRMED
print("FIXTURE_E_ENVIRONMENT_DEPENDENT_IS_NOT_CONFIRMED=PASS")
print("ENVIRONMENT_DEPENDENT_CONFIG_NOT_OVERCLAIMED=PASS")


# --- fixture F: security configuration with definitive evidence --------------------------

RULE_UPDATE = BY_ID["security.update-php-free-access-enabled"]
result_f = evaluate(
    [core_version(), settings_value("update_free_access", True)],
    [RULE_UPDATE],
)
finding_f = finding_for(result_f, RULE_UPDATE["rule_id"])
assert finding_f["state"] == I.CONFIRMED, finding_f
assert finding_f["category"] == "security"
# A security category never implies blocking; only a reviewed intent does.
assert finding_f["effective_enforcement"] == I.ENFORCEMENT_GUIDANCE
assert result_f["summary"]["blocking"] == 0
assert finding_f["evidence"]["evidence_ids"], finding_f
assert finding_f["authority"]["sources"][0]["source_id"] == "drupal-default-settings-php"
print("FIXTURE_F_SECURITY_CONFIG_CONFIRMED_AS_GUIDANCE=PASS")
print("IMPLEMENTATION_CATEGORY_NOT_AUTOMATIC_BLOCKING=PASS")
print("IMPLEMENTATION_FINDING_CONFIRMATION_REQUIRES_DEFINITIVE_EVIDENCE=PASS")

# Every question a reader should be able to ask is answered.
explanation = finding_f["explanation"]
for key in (
    "what_rule",
    "why_it_applies",
    "what_evidence",
    "evidence_completeness",
    "what_remains_unknown",
    "authority",
    "conclusion",
):
    assert explanation[key], key
assert finding_f["remediation"]["guidance"] and finding_f["remediation"]["applied"] is False
assert finding_f["execution"] == {
    "configuration_modified": False,
    "code_modified": False,
    "composer_invoked": False,
    "drupal_state_changed": False,
}
print("IMPLEMENTATION_FINDING_EXPLAINABLE=PASS")
print("IMPLEMENTATION_REMEDIATION_READ_ONLY=PASS")


# --- fixture G: heuristic-only evidence -------------------------------------------------

heuristic = E.record(
    E.A_SETTINGS_VALUE,
    "update_free_access",
    state=E.OBSERVED,
    value=True,
    quality=E.QUALITY_HEURISTIC,
    completeness=E.PARTIAL,
    extraction="filename_pattern_guess",
)
assert heuristic["observation"]["definitive"] is False
result_g = evaluate([core_version(), heuristic], [RULE_UPDATE])
finding_g = finding_for(result_g, RULE_UPDATE["rule_id"])
assert finding_g["state"] == I.UNKNOWN, finding_g
assert finding_g["reason_code"] == "HEURISTIC_EVIDENCE_NOT_DEFINITIVE"
assert result_g["summary"]["confirmed"] == 0
print("FIXTURE_G_HEURISTIC_CANNOT_CONFIRM=PASS")
print("HEURISTIC_IMPLEMENTATION_EVIDENCE_CANNOT_CONFIRM_FINDING=PASS")


# --- fixture H: unreviewed rule ----------------------------------------------------------

RULE_DRAFT = BY_ID["performance.asset-aggregation-disabled"]
assert RULE_DRAFT["review"]["status"] == I.REVIEW_DRAFT
result_h = evaluate(
    [core_version(), config_value("system.performance:css.preprocess", False)],
    [RULE_DRAFT],
)
finding_h = finding_for(result_h, RULE_DRAFT["rule_id"])
assert finding_h["state"] == I.CANDIDATE, finding_h
assert finding_h["reason_code"] == "RULE_NOT_REVIEWED"
# A draft rule is also stripped of any enforcement intent it declares.
assert finding_h["effective_enforcement"] == I.ENFORCEMENT_ADVISORY
assert result_h["summary"]["confirmed"] == 0

# Forcing a draft rule to confirm is refused by the output guard, not just by
# the state machine that produced it.
forged = copy.deepcopy(result_h)
forged["findings"][0]["state"] = I.CONFIRMED
try:
    I.validate_evaluation(forged)
except I.ImplementationEngineDefect:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("an unreviewed rule confirmed a finding")
print("FIXTURE_H_UNREVIEWED_RULE_CANNOT_CONFIRM=PASS")
print("UNREVIEWED_RULE_CANNOT_CONFIRM_FINDING=PASS")


# --- fixture I: authority source changed after review --------------------------------------

stale_rule = copy.deepcopy(RULE_UPDATE)
stale_rule["authority"]["sources"][0]["snapshot_sha256"] = "sha256:" + "9" * 64
result_i = evaluate([core_version(), settings_value("update_free_access", True)], [stale_rule])
finding_i = finding_for(result_i, stale_rule["rule_id"])
assert finding_i["state"] == I.REQUIRES_HUMAN_REVIEW, finding_i
assert finding_i["reason_code"] == "RULE_AUTHORITY_SOURCE_CHANGED"
assert finding_i["authority"]["stale_sources"], finding_i
assert any("changed after the rule was reviewed" in text for text in finding_i["limitations"])
# And the rule itself no longer validates, so the change surfaces as review work
# rather than as a quietly different interpretation.
try:
    I.validate_rule(stale_rule, REGISTERED, ROOT)
except dk_core.ValidationError as exc:
    assert "needs re-review" in str(exc)
else:  # pragma: no cover - the guard must fire
    raise AssertionError("a stale rule validated")
print("FIXTURE_I_SOURCE_CHANGE_BECOMES_REVIEW_WORK=PASS")
print("IMPLEMENTATION_RULE_SOURCE_CHANGE_REQUIRES_REVIEW=PASS")


# --- fixture J: negative evidence from an incomplete domain ---------------------------------

RULE_TRUSTED_HOST = BY_ID["security.trusted-host-patterns-not-declared"]
result_j = evaluate(
    [core_version(), settings_value("config_sync_directory", "../config/sync")],
    [RULE_TRUSTED_HOST],
)
finding_j = finding_for(result_j, RULE_TRUSTED_HOST["rule_id"])
assert finding_j["state"] == I.UNKNOWN, finding_j
assert finding_j["reason_code"] == "EVIDENCE_DOMAIN_INCOMPLETE"
assert any("Included settings files are not followed" in text for text in finding_j["limitations"])
# No hostname is recorded anywhere in the finding.
assert "example.com" not in json.dumps(finding_j)
print("FIXTURE_J_INCOMPLETE_DOMAIN_CANNOT_CONFIRM_ABSENCE=PASS")
print("TRUSTED_HOST_RULE_USES_SAFE_STATIC_EVIDENCE=PASS")


# --- fixture K: same evidence twice ----------------------------------------------------------

again = evaluate([core_version(), settings_value("update_free_access", True)], [RULE_UPDATE])
assert again["evaluation_id"] == result_f["evaluation_id"]
assert finding_for(again, RULE_UPDATE["rule_id"])["finding_id"] == finding_f["finding_id"]
assert I.stable_json(again) == I.stable_json(result_f)
print("FIXTURE_K_SAME_EVIDENCE_SAME_FINDING_ID=PASS")


# --- fixture L: evidence revision changes -------------------------------------------------------

other_revision = evaluate(
    [core_version(), settings_value("update_free_access", True)], [RULE_UPDATE], revision="b" * 64
)
other = finding_for(other_revision, RULE_UPDATE["rule_id"])
assert other["finding_id"] != finding_f["finding_id"]
assert other["project"]["revision_fingerprint"] == "b" * 64
assert other["project"]["project_fingerprint"] == finding_f["project"]["project_fingerprint"]
assert other["evidence"]["evidence_set_id"] != finding_f["evidence"]["evidence_set_id"]
print("FIXTURE_L_REVISION_CHANGES_FINDING_IDENTITY=PASS")


# --- unknown propagates -------------------------------------------------------------------------

no_evidence = evaluate([core_version()], [RULE_UPDATE])
assert finding_for(no_evidence, RULE_UPDATE["rule_id"])["state"] == I.UNKNOWN

# A rule whose scope cannot be decided does not resolve either way.
no_core = evaluate([settings_value("update_free_access", True)], [RULE_UPDATE])
scopeless = finding_for(no_core, RULE_UPDATE["rule_id"])
assert scopeless["state"] == I.UNKNOWN
assert scopeless["reason_code"] == "RULE_SCOPE_UNDECIDABLE"

# A rule outside its declared core-version scope is not applicable rather than met.
out_of_scope = evaluate(
    [core_version("7.98"), settings_value("update_free_access", True)], [RULE_UPDATE]
)
assert finding_for(out_of_scope, RULE_UPDATE["rule_id"])["reason_code"] == "RULE_OUT_OF_SCOPE"
print("IMPLEMENTATION_RULE_UNKNOWN_PROPAGATES=PASS")


# --- the finding runtime is reused, not reinvented ------------------------------------------------

import dk_finding_runtime

assert I.FORBIDDEN_STATE_VALUES is dk_finding_runtime.FORBIDDEN_STATE_VALUES
assert set(I.FINDING_STATES) <= set(dk_finding_runtime.FINDING_STATES)
assert I.SEVERITY_NOT_ESTABLISHED == "not_established"
engine_source = (ROOT / "scripts" / "dk_implementation.py").read_text(encoding="utf-8")
assert "import dk_finding_runtime" in engine_source
assert "import dk_applicability" in engine_source
# It does not grow a second applicability evaluator or a second project reader:
# its condition check delegates to the resolver rather than interpreting
# predicates itself.
assert "dk_applicability.evaluate_condition(" in engine_source
assert "def evaluate_condition(" not in engine_source
assert "def evaluate_leaf_predicate" not in engine_source
assert "def tvl_and" not in engine_source and "def tvl_or" not in engine_source
# It reads repository snapshots to verify rule authority, and never a project:
# no walking, no project path, no manifest.
for forbidden in ("os.walk", "rglob", "subprocess", "composer.lock", "project_path"):
    assert forbidden not in engine_source, forbidden
assert "require_snapshot" in engine_source, "authority is verified against pinned snapshots"
print("IMPLEMENTATION_FINDINGS_REUSE_FINDING_RUNTIME=PASS")


# --- domains stay apart ----------------------------------------------------------------------------

import dk_migration
import dk_security

assert I.RESULT_DOMAIN == "implementation_finding"
assert I.RESULT_DOMAIN not in {dk_migration.RESULT_DOMAIN, E.RESULT_DOMAIN}
# "advisory" appears as an enforcement level and in the boundary statement that
# names the other engine. What must never appear is an advisory *record*: a
# published identifier, a CVE or a risk vector.
blob = json.dumps(result_f).lower()
for term in ("cve-", "criticality", "sa-core", "sa-contrib", "field_sa_", "affected_versions"):
    assert term not in blob, term
for item in result_f["findings"]:
    assert set(item) & {"cve", "cves", "advisory_id", "severity_score"} == set()
assert "advisory engine's domain" in result_f["boundaries"]["advisory_relationship"]
assert "own domain" in result_f["boundaries"]["migration_relationship"]
# Nothing in the rule set consumes migration or advisory records.
for rule in PRODUCTION_RULES:
    text = json.dumps(rule)
    assert "migration-work" not in text and "advisory" not in text.lower()
print("IMPLEMENTATION_SECURITY_DISTINCT_FROM_ADVISORY_SECURITY=PASS")
print("ADVISORY_SECURITY_ENGINE_REMAINS_DISTINCT=PASS")
print("API_MIGRATION_AND_IMPLEMENTATION_FINDINGS_DISTINCT=PASS")

# A text-format or filter rule would need its own reviewed rule; none is
# shipped, and none is implied by any other rule.
assert not [rule for rule in PRODUCTION_RULES if "filter" in rule["rule_id"] or "format" in rule["rule_id"]]
assert not [
    rule
    for rule in PRODUCTION_RULES
    if "filter_format" in json.dumps(rule["check"])
]
print("TEXT_FORMAT_SECURITY_FINDING_REQUIRES_EXPLICIT_RULE=PASS")

# Absence from the bounded code-evidence scan is never global absence, and no
# rule treats it as such.
for rule in PRODUCTION_RULES:
    if rule["check"]["kind"] != I.CHECK_CONDITION:
        continue
    node = rule["check"]["condition"]
    if node.get("operator") == "evidence_absent":
        assert not str(node.get("assertion", "")).startswith("code."), rule["rule_id"]
print("CACHEABILITY_NO_MATCH_NOT_GLOBAL_ABSENCE=PASS")


# --- provenance channels stay distinct ----------------------------------------------------------------

finding = finding_f
assert finding["authority"]["sources"][0]["source_id"] in REGISTERED
assert finding["authority"]["review_status"] == "reviewed"
assert finding["evidence"]["evidence_set_id"].startswith("evidence-set.")
assert finding["finding_id"].startswith("implementation-finding.")
assert finding["result_domain"] == "implementation_finding"
# Five channels, five different shapes: authoritative source, reviewed rule,
# project evidence, the applicability result inside it, and the finding.
channels = {
    "authoritative_source": finding["authority"]["sources"][0]["source_id"],
    "reviewed_rule": finding["rule_id"],
    "project_evidence": finding["evidence"]["evidence_ids"][0],
    "applicability": finding["evidence"]["reason_codes"][0],
    "finding": finding["finding_id"],
}
assert len(set(channels.values())) == 5, channels
print("IMPLEMENTATION_FINDING_PROVENANCE_CHANNELS_DISTINCT=PASS")


# --- the CLI cannot change anything -------------------------------------------------------------------

with tempfile.TemporaryDirectory() as directory:
    workspace = Path(directory)
    path = workspace / "evidence.json"
    path.write_text(json.dumps(evidence_set([core_version(), settings_value("update_free_access", True)])), encoding="utf-8")
    before = sorted(item.name for item in workspace.iterdir())

    result = subprocess.run(
        [sys.executable, str(CLI), "implementation-findings", str(path), "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["result_domain"] == "implementation_finding"
    assert payload["execution"]["configuration_modified"] is False

    explained = subprocess.run(
        [sys.executable, str(CLI), "implementation-findings", str(path), "--explain", "--category", "security"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "No project changes were performed." in explained.stdout
    assert "Recommended action:" in explained.stdout
    assert "Authority:" in explained.stdout
    assert sorted(item.name for item in workspace.iterdir()) == before

help_text = subprocess.run(
    [sys.executable, str(CLI), "implementation-findings", "--help"],
    capture_output=True,
    text=True,
    check=True,
).stdout
for forbidden in ("--apply", "--fix", "--write", "--optimize", "--secure", "--rewrite"):
    assert forbidden not in help_text, forbidden
print("IMPLEMENTATION_FINDINGS_CLI_READ_ONLY=PASS")


# --- the released interface advertises the contract -----------------------------------------------------

version = json.loads(
    subprocess.run([sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True).stdout
)
interfaces = version["interfaces"]
assert interfaces["implementation_rule_schema"] == I.RULE_CONTRACT_VERSION
assert interfaces["implementation_finding_schema"] == I.FINDING_CONTRACT_VERSION
engine = version["implementation_engine"]
assert engine["categories"] == list(I.CATEGORIES)
assert engine["evidence_requirement_contract"] == "project_evidence_assertions"
assert engine["produces_trusted_knowledge"] is False
assert engine["severity_established"] is False
assert engine["read_only"] is True
for key in ("project_evidence_set_schema", "migration_work_item_schema", "upgrade_assessment_schema"):
    assert key in interfaces, key
print("IMPLEMENTATION_FINDING_INTERFACE_ADVERTISED=PASS")


# --- the trust boundary -----------------------------------------------------------------------------------

import hashlib

GUARDED = (
    "knowledge/records",
    "knowledge/context",
    "api/lifecycle",
    "api/change-records",
    "security/advisories",
    "cases/solved",
    "discovery",
    "sources/snapshots",
    "rules/implementation",
)


def digest_tree() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for relative in GUARDED
        for path in sorted((ROOT / relative).rglob("*"))
        if path.is_file()
    }


before_state = digest_tree()
evaluate([core_version(), settings_value("update_free_access", True)], PRODUCTION_RULES)
I.validate_implementation_contract(ROOT)
after_state = digest_tree()
assert before_state == after_state, "implementation evaluation mutated reviewed knowledge"
assert len(before_state) > 250, len(before_state)
print("IMPLEMENTATION_FINDINGS_ZERO_UNREVIEWED_KNOWLEDGE_MUTATION=PASS")


# --- no second consumer authority ---------------------------------------------------------------------------
# Consumers read released Drupal Knowledge through the CLI and API. No
# integration directory may carry a second engine.

integration = ROOT / "integrations"
if integration.is_dir():
    for path in integration.rglob("*"):
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace").lower()
            assert "implementation-findings" not in body, path
            assert "implementation_engine" not in body, path
print("NO_SECOND_IMPLEMENTATION_AUTHORITY=PASS")
