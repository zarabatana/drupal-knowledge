#!/usr/bin/env python3
"""What the evidence layer will and will not claim was observed.

The twelve fixtures below are the ones that decide whether this layer is a
foundation or a liability. Three pairs matter most, and each pair is two
observations that look alike and mean different things:

    declared in composer.json   vs  present in composer.lock
    exported in configuration   vs  effective at runtime
    absent from a complete list vs  not found by a bounded scan

Get any of those wrong and a later rule confidently reports something the
project never said. So each is a fixture here, and each stays fixed.

Everything is hermetic: the fixtures build their own analyzer profiles and
their own project trees in a temporary directory.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_applicability as R
import dk_core
import dk_evidence as E
import dk_project_analyzer as P


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"
WORKSPACE = Path(tempfile.mkdtemp(prefix="dk-evidence-fixture-"))


# --- fixture construction -----------------------------------------------------


def analysis(
    *,
    declared: dict | None = None,
    locked: list[dict] | None = None,
    lock_available: bool = True,
    core_version: str | None = "10.6.0",
    config_objects: list[dict] | None = None,
    config_values: list[dict] | None = None,
    config_root: str | None = "config/sync",
    root_selection: str = "available",
    modules: list[str] | None = None,
    themes: list[str] | None = None,
    settings_entries: list[dict] | None = None,
    settings_redacted: list[dict] | None = None,
    custom_modules: list[dict] | None = None,
    code_files: list[dict] | None = None,
) -> dict:
    """An analyzer profile in exactly the shape the real analyzer emits."""
    packages = list(locked or [])
    drupal_packages = [item for item in packages if item["name"].startswith("drupal/")]

    def fact_known(value, confidence: str = "high") -> dict:
        return {"state": "known", "confidence": confidence, "value": value}

    def fact_unknown(note: str) -> dict:
        return {"state": "unknown", "notes": note}

    # Every analyzer fact exists, so the fixture satisfies the real project
    # analysis contract; the ones this fixture does not care about are unknown
    # rather than absent, which is what a real profile looks like too.
    facts: dict = {
        name: fact_unknown("not set by this fixture") for name in P.ANALYZER_FACTS
    }
    facts.update(
        {
            "drupal_core_version": (
                    fact_known({"package": "drupal/core", "version": core_version})
                    if core_version
                    else fact_unknown("no installed core package evidence")
                ),
                "php_version": fact_known(
                    {"composer_platform": "8.3.0", "composer_requirement": ">=8.1", "runtime": "unknown"}
                ),
                "project_type": fact_known({"type": "drupal", "reasons": []}),
                "drupal_web_root": fact_known("web"),
                "composer_packages": fact_known(
                    {
                        "declared": {"require": dict(declared or {}), "require_dev": {}},
                        "installed": {
                            "available": lock_available,
                            "packages": packages,
                            "drupal_packages": drupal_packages,
                            "counts": {"packages": len(packages), "drupal_packages": len(drupal_packages)},
                        },
                    }
                ),
                "modules": fact_known(list(modules)) if modules is not None else fact_unknown("no config root"),
                "themes": fact_known(list(themes)) if themes is not None else fact_unknown("no config root"),
                "custom_modules": (
                    fact_known(list(custom_modules), "medium")
                    if custom_modules is not None
                    else fact_unknown("no custom roots")
                ),
                "custom_themes": fact_unknown("no custom theme roots"),
                "configuration_objects": fact_known(
                    {
                        "scan": {
                            "config_id": "drupal-project-evidence",
                            "config_digest": "sha256:" + "c" * 64,
                            "config_root": config_root,
                            "root_selection": root_selection,
                            "object_enumeration": (
                                "complete_for_selected_config_root" if config_root else "unavailable"
                            ),
                            "value_observation": "declared_keys_only",
                            "declared_objects": ["system.logging", "system.performance"],
                            "excluded_keys": ["_core.default_config_hash"],
                        },
                        "objects": list(config_objects or []),
                        "values": list(config_values or []),
                        "redacted": [],
                        "unreadable": [],
                        "counts": {
                            "objects": len(config_objects or []),
                            "values": len(config_values or []),
                            "redacted": 0,
                            "unreadable": 0,
                        },
                    }
                ),
                "settings_declarations": fact_known(
                    {
                        "scan": {
                            "config_id": "drupal-project-evidence",
                            "config_digest": "sha256:" + "d" * 64,
                            "method": "php_lexer_scalar_assignment",
                            "php_executed": False,
                            "value_observation": "declared_keys_only",
                            "declared_keys": ["update_free_access"],
                            "files_considered": ["web/sites/default/settings.php"],
                        },
                        "files_read": ["web/sites/default/settings.php"] if settings_entries else [],
                        "entries": list(settings_entries or []),
                        "redacted": list(settings_redacted or []),
                        "counts": {
                            "files_read": 1 if settings_entries else 0,
                            "entries": len(settings_entries or []),
                            "redacted": len(settings_redacted or []),
                        },
                    }
                ),
                "custom_code_files": fact_known(
                    {
                        "scan": {
                            "config_id": "drupal-custom-code-scan",
                            "config_digest": "sha256:" + "e" * 64,
                            "roots": ["web/modules/custom"],
                            "excluded_directories": ["vendor"],
                            "included_extensions": {"php": [".php", ".module"], "yaml": [".yml"]},
                            "limits": {"max_file_bytes": 1048576, "max_files": 5000, "max_depth": 12},
                            "truncated": False,
                            "scope": "project_owned_custom_code_only",
                        },
                        "files": list(code_files or []),
                        "skipped": [],
                        "counts": {
                            "files": len(code_files or []),
                            "skipped": 0,
                            "by_language": {"php": len(code_files or [])},
                            "components": 1 if code_files else 0,
                        },
                    }
                ),
        }
    )
    return {
        "schema_version": "0.1",
        "project_id": "fixture/evidence",
        "analyzer": {
            "name": "drupal-project-analyzer",
            "version": "0.1",
            "mode": "static-file-inspection",
        },
        "profile": {
            "schema_version": "0.1",
            "project_id": "fixture/evidence",
            "facts": facts,
        },
        "evidence": [],
        "completeness": {
            "composer_declaration": "available",
            "installed_package_evidence": "available" if lock_available else "unavailable",
            "drupal_config": "available" if config_root else "ambiguous",
        },
        "unknowns": [],
        "diagnostics": [],
    }


def package(name: str, version: str, kind: str = "drupal-module", dev: bool = False) -> dict:
    return {"name": name, "version": version, "type": kind, "dev": dev}


def config_value(name: str, key: str, value, state: str = "present") -> dict:
    return {
        "config_name": name,
        "key": key,
        "path": f"config/sync/{name}.yml",
        "state": state,
        "value": value,
    }


def config_object(name: str) -> dict:
    return {
        "config_name": name,
        "path": f"config/sync/{name}.yml",
        "bytes": 64,
        "sha256": "sha256:" + hashlib.sha256(name.encode()).hexdigest(),
    }


def write_code(directory: Path, files: list[dict]) -> list[dict]:
    inventory = []
    for entry in files:
        path = directory / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry["source"], encoding="utf-8")
        inventory.append(
            {
                "path": entry["path"],
                "language": "php",
                "component": entry.get("component", "fixture_module"),
                "component_type": "module",
                "bytes": len(entry["source"].encode("utf-8")),
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return inventory


def find(evidence_set: dict, assertion: str, subject: str) -> dict | None:
    return next(
        (
            item
            for item in evidence_set["records"]
            if item["assertion"] == assertion and item["subject"] == subject
        ),
        None,
    )


def probe(predicate: dict, evidence_set: dict | None) -> tuple[str, list[str]]:
    index = E.index(evidence_set) if evidence_set is not None else None
    outcome = R.evaluate_evidence_predicate(predicate, index)
    return outcome.value, sorted(outcome.reason_codes)


# --- the contract itself --------------------------------------------------------

assert set(E.STATES) >= {
    "observed",
    "not_observed",
    "unknown",
    "insufficient_evidence",
    "ambiguous",
    "unsupported_evidence_type",
}
assert set(E.DOMAINS) == {"code", "configuration", "dependency", "extension", "project_metadata"}
assert set(E.COMPLETENESS) == {"complete", "bounded", "partial", "unknown"}
assert "heuristic_candidate" not in E.DEFINITIVE_QUALITIES
print("PROJECT_EVIDENCE_CONTRACT_MACHINE_READABLE=PASS")


# --- fixture A: Composer installed package ---------------------------------------

FIXTURE_A = analysis(
    declared={"drupal/webform": "^6.2"},
    locked=[package("drupal/webform", "6.2.0"), package("drupal/core", "10.6.0", "drupal-core")],
)
evidence_a = E.build(FIXTURE_A, ROOT)
installed = find(evidence_a, E.A_PACKAGE_INSTALLED, "drupal/webform")
assert installed["observation"]["state"] == E.OBSERVED
assert installed["observation"]["quality"] == E.QUALITY_CANONICAL
assert installed["completeness"]["search_domain"] == E.COMPLETE
version = find(evidence_a, E.A_PACKAGE_VERSION, "drupal/webform")
assert version["observation"]["value"] == "6.2.0"
kind = find(evidence_a, E.A_PACKAGE_TYPE, "drupal/webform")
assert kind["observation"]["value"] == "drupal-module"
print("FIXTURE_A_INSTALLED_PACKAGE_IS_EXACT=PASS")

# The three dependency dimensions stay apart rather than collapsing into one.
requirement = find(evidence_a, E.A_ROOT_REQUIREMENT, "drupal/webform")
assert requirement["observation"]["value"]["constraint"] == "^6.2"
assert requirement["observation"]["value"]["dev"] is False
relation = find(evidence_a, E.A_DEPENDENCY_RELATION, "drupal/webform")
assert relation["observation"]["value"]["direct"] is True
assert relation["observation"]["value"]["required_by"] == "root_manifest"
assert requirement["assertion"] != installed["assertion"] != version["assertion"]
print("DEPENDENCY_EVIDENCE_DIMENSIONS_DISTINCT=PASS")

# A transitive package keeps an honest answer about why it is present.
FIXTURE_TRANSITIVE = analysis(
    declared={"drupal/webform": "^6.2"},
    locked=[package("drupal/webform", "6.2.0"), package("drupal/token", "1.15.0")],
)
transitive = find(E.build(FIXTURE_TRANSITIVE, ROOT), E.A_DEPENDENCY_RELATION, "drupal/token")
assert transitive["observation"]["value"]["direct"] is False
assert transitive["observation"]["value"]["required_by"] == "unknown"
assert transitive["completeness"]["search_domain"] == E.BOUNDED
print("TRANSITIVE_DEPENDENCY_PROVENANCE_PRESERVED=PASS")


# --- fixture B: declared but not installed ------------------------------------------

FIXTURE_B = analysis(
    declared={"drupal/webform": "^6.2", "drupal/paragraphs": "^1.16"},
    locked=[package("drupal/webform", "6.2.0")],
)
evidence_b = E.build(FIXTURE_B, ROOT)
declared_only = find(evidence_b, E.A_ROOT_REQUIREMENT, "drupal/paragraphs")
assert declared_only["observation"]["state"] == E.OBSERVED, "the requirement itself is observed"
missing = find(evidence_b, E.A_PACKAGE_INSTALLED, "drupal/paragraphs")
assert missing["observation"]["state"] == E.NOT_OBSERVED, missing
assert missing["observation"]["value"] is False
# A requirement is not an installation, and the two records say so separately.
assert declared_only["assertion"] == E.A_ROOT_REQUIREMENT
assert missing["assertion"] == E.A_PACKAGE_INSTALLED
print("FIXTURE_B_DECLARED_IS_NOT_INSTALLED=PASS")
print("DECLARED_DEPENDENCY_NOT_ASSUMED_INSTALLED=PASS")


# --- fixture C: exported config value -----------------------------------------------

FIXTURE_C = analysis(
    locked=[package("drupal/core", "10.6.0", "drupal-core")],
    config_objects=[config_object("system.logging"), config_object("system.performance")],
    config_values=[
        config_value("system.logging", "error_level", "verbose"),
        config_value("system.performance", "css.preprocess", False),
    ],
)
evidence_c = E.build(FIXTURE_C, ROOT)
exported = find(evidence_c, E.A_CONFIG_VALUE, "system.logging:error_level")
assert exported["observation"]["state"] == E.OBSERVED
assert exported["observation"]["value"] == "verbose"
assert exported["scope"]["config_name"] == "system.logging"
assert exported["scope"]["key"] == "error_level"
assert exported["scope"]["path"] == "config/sync/system.logging.yml"
# The object itself is identified separately from the value read out of it.
identity = find(evidence_c, E.A_CONFIG_OBJECT, "system.logging")
assert identity["observation"]["state"] == E.OBSERVED
assert identity["completeness"]["search_domain"] == E.COMPLETE
print("FIXTURE_C_EXPORTED_CONFIG_VALUE_OBSERVED=PASS")
print("DRUPAL_CONFIG_IDENTITY_EXPLICIT=PASS")


# --- fixture D: runtime config unknown -----------------------------------------------

assert "runtime effective value is unknown" in exported["notes"]
assert exported["assertion"] == "config.exported_value", "the assertion names exported, not effective"
assert evidence_c["boundaries"]["runtime_observed"] is False
assert evidence_c["boundaries"]["php_executed"] is False
# There is no assertion in the whole vocabulary that claims effective runtime
# configuration, so no rule can accidentally ask for one.
assert not any("runtime_value" in assertion for assertion in E.ASSERTIONS)
print("FIXTURE_D_RUNTIME_CONFIG_STAYS_UNKNOWN=PASS")
print("EXPORTED_CONFIG_NOT_ASSUMED_RUNTIME_EFFECTIVE=PASS")


# --- fixture E: package present, no exported enablement ---------------------------------

FIXTURE_E = analysis(
    declared={"drupal/webform": "^6.2"},
    locked=[package("drupal/webform", "6.2.0")],
    modules=["node", "user"],
    themes=["olivero"],
)
evidence_e = E.build(FIXTURE_E, ROOT)
present = find(evidence_e, E.A_EXTENSION_PACKAGE, "webform")
assert present["observation"]["state"] == E.OBSERVED
assert find(evidence_e, E.A_EXTENSION_EXPORTED_ENABLED, "webform") is None
assert find(evidence_e, E.A_EXTENSION_EXPORTED_ENABLED, "node")["observation"]["state"] == E.OBSERVED
# Installed and enabled are different records, and only one of them exists here.
assert "not evidence that the extension is enabled" in present["notes"]
runtime = find(evidence_e, E.A_EXTENSION_RUNTIME_ENABLED, "*")
assert runtime["observation"]["state"] == E.UNKNOWN
print("FIXTURE_E_PACKAGE_PRESENT_IS_NOT_ENABLED=PASS")
print("EXTENSION_PRESENT_NOT_EQUAL_RUNTIME_ENABLED=PASS")


# --- fixture F: core.extension exported enablement ------------------------------------

enabled = find(evidence_e, E.A_EXTENSION_EXPORTED_ENABLED, "node")
assert enabled["observation"]["value"]["source"] == "core.extension"
assert enabled["completeness"]["search_domain"] == E.COMPLETE
assert "Whether the running site has" in enabled["notes"]
assert enabled["assertion"] == "extension.exported_enabled"
print("FIXTURE_F_CORE_EXTENSION_IS_EXPORTED_STATE_ONLY=PASS")
print("CORE_EXTENSION_EVIDENCE_SCOPED_TO_EXPORTED_CONFIG=PASS")

# Without an exported config root, no extension can be called enabled or absent.
FIXTURE_NO_CONFIG = analysis(
    locked=[package("drupal/webform", "6.2.0")],
    config_root=None,
    root_selection="ambiguous",
)
evidence_no_config = E.build(FIXTURE_NO_CONFIG, ROOT)
blocked = find(evidence_no_config, E.A_EXTENSION_EXPORTED_ENABLED, "*:module")
assert blocked["observation"]["state"] == E.INSUFFICIENT
ambiguous = find(evidence_no_config, E.A_CONFIG_OBJECT, "*")
assert ambiguous["observation"]["state"] == E.AMBIGUOUS
print("AMBIGUOUS_CONFIG_ROOT_YIELDS_NO_ENUMERATION=PASS")


# --- fixture G: code API usage ---------------------------------------------------------

project_g = WORKSPACE / "g"
project_g.mkdir(parents=True, exist_ok=True)
code_files = write_code(
    project_g,
    [
        {
            "path": "web/modules/custom/fixture_module/src/Uses.php",
            "source": """<?php
namespace Drupal\\fixture_module;

use Drupal\\Core\\Controller\\ControllerBase;

class Uses extends ControllerBase {
  public function go() {
    // A commented reference to file_create_url() proves nothing.
    $service = \\Drupal::service('renderer');
    return drupal_get_path('module', 'fixture_module') . $service;
  }
}
""",
        },
        {
            "path": "web/modules/custom/fixture_module/fixture_module.module",
            "source": """<?php

/**
 * Implements hook_help().
 */
function fixture_module_help($route, $match) {
  return '';
}
""",
        },
    ],
)
FIXTURE_G = analysis(locked=[package("drupal/core", "10.6.0", "drupal-core")], code_files=code_files)
evidence_g = E.build(FIXTURE_G, ROOT, project_path=project_g)

api = find(evidence_g, E.A_CODE_API_USAGE, "drupal_get_path")
assert api is not None and api["observation"]["state"] == E.OBSERVED
assert api["observation"]["quality"] == E.QUALITY_SYNTAX
assert api["completeness"]["search_domain"] == E.BOUNDED
assert api["scope"]["occurrences"][0]["line"] == 10

service = find(evidence_g, E.A_CODE_SERVICE, "renderer")
assert service is not None and service["observation"]["state"] == E.OBSERVED
hook = find(evidence_g, E.A_CODE_HOOK, "hook_help")
assert hook is not None
klass = find(evidence_g, E.A_CODE_CLASS, "Drupal\\Core\\Controller\\ControllerBase")
assert klass is not None

# The commented name never becomes code evidence, because this reuses the
# syntax-aware observation rather than searching text.
assert find(evidence_g, E.A_CODE_API_USAGE, "file_create_url") is None
assert api["provenance"]["observation_engine"] == "drupal-knowledge-migration-engine"
print("FIXTURE_G_CODE_EVIDENCE_IS_SYNTAX_OBSERVED=PASS")
print("CODE_EVIDENCE_REUSES_API_USAGE_OBSERVATIONS=PASS")


# --- fixture H: heuristic-only candidate ------------------------------------------------
# The engine produces no heuristic records today. The guard proves that if one
# ever appears it cannot be definitive and cannot decide a rule.

heuristic = E.record(
    E.A_EXTENSION_CODE,
    "guessed_module",
    state=E.OBSERVED,
    value={"basis": "directory name resembles a module"},
    quality=E.QUALITY_HEURISTIC,
    completeness=E.PARTIAL,
    extraction="filename_pattern",
    scope={"path": "web/modules/custom/guessed_module"},
)
assert heuristic["observation"]["definitive"] is False
E.validate_record(heuristic)

with_heuristic = copy.deepcopy(evidence_g)
with_heuristic["records"].append(heuristic)
value, codes = probe(
    {"operator": "evidence_matches", "assertion": E.A_EXTENSION_CODE, "subject": "guessed_module"},
    with_heuristic,
)
assert value == R.UNKNOWN, value
assert codes == ["HEURISTIC_EVIDENCE_NOT_DEFINITIVE"], codes

# And a heuristic record that claims to be definitive is refused outright.
forged = copy.deepcopy(heuristic)
forged["observation"]["definitive"] = True
try:
    E.validate_record(forged)
except E.EvidenceEngineDefect:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("a definitive heuristic record was accepted")
print("FIXTURE_H_HEURISTIC_IS_NEVER_DEFINITIVE=PASS")
print("STATIC_HEURISTIC_NOT_DEFINITIVE_PROJECT_FACT=PASS")
print("EVIDENCE_QUALITY_DETERMINISTIC=PASS")


# --- fixture I: complete-domain negative evidence ------------------------------------------

value, codes = probe(
    {"operator": "evidence_absent", "assertion": E.A_PACKAGE_INSTALLED, "subject": "drupal/never_installed"},
    evidence_a,
)
assert value == R.TRUE, value
assert codes == ["AUTHORITATIVE_ABSENCE"], codes
assert evidence_a["domain_completeness"]["dependency"]["search_domain"] == E.COMPLETE
print("FIXTURE_I_COMPLETE_DOMAIN_SUPPORTS_ABSENCE=PASS")


# --- fixture J: partial-domain no match ------------------------------------------------------

value, codes = probe(
    {"operator": "evidence_absent", "assertion": E.A_CODE_API_USAGE, "subject": "file_create_url"},
    evidence_g,
)
assert value == R.UNKNOWN, value
assert codes == ["EVIDENCE_DOMAIN_INCOMPLETE"], codes
assert evidence_g["domain_completeness"]["code"]["search_domain"] == E.BOUNDED
# The same question against the complete dependency domain answers definitively,
# which is the whole point of tracking completeness per domain.
assert probe(
    {"operator": "evidence_absent", "assertion": E.A_PACKAGE_INSTALLED, "subject": "drupal/whatever"},
    evidence_g,
)[0] == R.TRUE
print("FIXTURE_J_BOUNDED_SCAN_IS_NOT_ABSENCE=PASS")
print("NEGATIVE_EVIDENCE_REQUIRES_COMPLETE_DOMAIN=PASS")
print("NOT_OBSERVED_NOT_FALSE=PASS")

# A record may not claim not_observed from an incomplete domain at all.
try:
    E.record(
        E.A_CODE_API_USAGE,
        "some_function",
        state=E.NOT_OBSERVED,
        quality=E.QUALITY_SYNTAX,
        completeness=E.BOUNDED,
        extraction="bounded_scan",
    )
    E.validate_record(
        E.record(
            E.A_CODE_API_USAGE,
            "some_function",
            state=E.NOT_OBSERVED,
            quality=E.QUALITY_SYNTAX,
            completeness=E.BOUNDED,
            extraction="bounded_scan",
        )
    )
except E.EvidenceEngineDefect:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("not_observed was accepted from a bounded domain")
print("PROJECT_EVIDENCE_COMPLETENESS_EXPLICIT=PASS")


# --- fixture K: secret-bearing settings value -------------------------------------------------

project_k = WORKSPACE / "k"
(project_k / "web" / "sites" / "default").mkdir(parents=True, exist_ok=True)
(project_k / "web" / "sites" / "default" / "settings.php").write_text(
    """<?php
$settings['hash_salt'] = 'sup3r-s3cret-value';
$databases['default']['default']['password'] = 'hunter2';
$settings['update_free_access'] = FALSE;
$settings['config_sync_directory'] = '../config/sync';
$settings['trusted_host_patterns'] = ['^example\\.com$'];
""",
    encoding="utf-8",
)
scanned = P.scan_settings_declarations(project_k, P.load_evidence_config(ROOT))
keys = {entry["key"] for entry in scanned["entries"]}
assert "hash_salt" not in keys, "a secret key must never reach an entry"
assert {item["key"] for item in scanned["redacted"]} == {"hash_salt"}
assert scanned["redacted"][0]["reason"] == "declared_secret_key"
assert "update_free_access" in keys
# The secret value appears nowhere in the output, not even in a diagnostic.
assert "sup3r-s3cret-value" not in json.dumps(scanned)
assert "hunter2" not in json.dumps(scanned)
# A non-scalar value is unsupported rather than half-read.
array_entry = next(entry for entry in scanned["entries"] if entry["key"] == "trusted_host_patterns")
assert array_entry["state"] == "unsupported_value_type"
assert array_entry["value"] is None
assert scanned["scan"]["php_executed"] is False
print("FIXTURE_K_SECRETS_ARE_REDACTED=PASS")
print("PROJECT_EVIDENCE_EXCLUDES_SECRETS=PASS")

# And a value that is an absolute local path is refused as well.
config = P.load_evidence_config(ROOT)
key_patterns, value_patterns = P.redaction_rules(config)
assert P.value_is_forbidden("/Users/someone/site", value_patterns)
assert P.value_is_forbidden("/home/deploy/site", value_patterns)
assert not P.value_is_forbidden("../config/sync", value_patterns)
for evidence_set in (evidence_a, evidence_c, evidence_e, evidence_g):
    E.assert_no_local_paths(evidence_set["records"], "fixture")
    blob = json.dumps(evidence_set)
    assert "/Users/" not in blob and "/home/" not in blob
print("PROJECT_EVIDENCE_PATHS_RELATIVE=PASS")


# --- fixture L: revision change ------------------------------------------------------------------

FIXTURE_L_BEFORE = analysis(
    declared={"drupal/webform": "^6.2"},
    locked=[package("drupal/webform", "6.2.0")],
    config_objects=[config_object("system.logging")],
    config_values=[config_value("system.logging", "error_level", "hide")],
)
FIXTURE_L_AFTER = analysis(
    declared={"drupal/webform": "^6.2", "drupal/paragraphs": "^1.16"},
    locked=[package("drupal/webform", "6.3.0"), package("drupal/paragraphs", "1.16.0")],
    config_objects=[config_object("system.logging")],
    config_values=[config_value("system.logging", "error_level", "verbose")],
)
before = E.build(FIXTURE_L_BEFORE, ROOT, generated_at="2026-09-09T00:00:00Z")
after = E.build(FIXTURE_L_AFTER, ROOT, generated_at="2026-09-09T00:00:00Z")

assert before["project"]["project_fingerprint"] == after["project"]["project_fingerprint"]
assert before["project"]["revision_fingerprint"] != after["project"]["revision_fingerprint"]
assert before["evidence_set_id"] != after["evidence_set_id"]
print("PROJECT_EVIDENCE_REVISION_SCOPED=PASS")

# Identical content produces identical identity, every time.
again = E.build(FIXTURE_L_BEFORE, ROOT, generated_at="2026-09-09T00:00:00Z")
assert again["evidence_set_id"] == before["evidence_set_id"]
assert again["project"]["revision_fingerprint"] == before["project"]["revision_fingerprint"]
assert [item["evidence_id"] for item in again["records"]] == [
    item["evidence_id"] for item in before["records"]
]
assert E.stable_json(again) == E.stable_json(before)
print("PROJECT_EVIDENCE_IDEMPOTENT=PASS")

change = E.diff(before, after)
assert change["same_project"] is True
assert change["same_revision"] is False
added = {(item["assertion"], item["subject"]) for item in change["added"]}
assert (E.A_PACKAGE_INSTALLED, "drupal/paragraphs") in added
assert (E.A_ROOT_REQUIREMENT, "drupal/paragraphs") in added
changed = {(item["assertion"], item["subject"]): item for item in change["changed"]}
version_change = changed[(E.A_PACKAGE_VERSION, "drupal/webform")]
assert version_change["before"]["value"] == "6.2.0"
assert version_change["after"]["value"] == "6.3.0"
config_change = changed[(E.A_CONFIG_VALUE, "system.logging:error_level")]
assert config_change["before"]["value"] == "hide"
assert config_change["after"]["value"] == "verbose"
assert change["summary"]["added"] and change["summary"]["changed"]
assert change["unchanged_count"] > 0
# A diff against itself moves nothing.
identity_diff = E.diff(before, before)
assert identity_diff["summary"]["added"] == identity_diff["summary"]["removed"] == 0
assert identity_diff["summary"]["changed"] == 0
assert identity_diff["same_revision"] is True
print("FIXTURE_L_REVISION_DIFF_IS_DETERMINISTIC=PASS")
print("PROJECT_EVIDENCE_DIFF_DETERMINISTIC=PASS")


# --- the analyzer is reused, not replaced -------------------------------------------------------

engine_source = (ROOT / "scripts" / "dk_evidence.py").read_text(encoding="utf-8")
assert "import dk_project_analyzer" not in engine_source
# It discovers nothing and opens nothing: every fact comes from an analyzer
# profile, and source observation is delegated to the one engine that reads PHP.
for forbidden in ("os.walk", "rglob", "glob(", "subprocess", "read_text", "read_bytes", "open("):
    assert forbidden not in engine_source, f"the evidence engine must not read projects ({forbidden})"
assert "dk_migration.observe_project" in engine_source
try:
    E.build({"profile": {}, "analyzer": {"name": "something-else"}}, ROOT)
except E.EvidenceInputError:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("input from another producer was accepted as analyzer facts")
print("PROJECT_EVIDENCE_REUSES_EXISTING_ANALYZER=PASS")


# --- provenance channels stay distinct ------------------------------------------------------------

for item in evidence_a["records"]:
    assert item["provenance"]["channel"] == "project_derived_evidence"
assert evidence_a["engine"]["produces_trusted_knowledge"] is False
# The other channels in the product are different strings, so a consumer can
# always tell a project observation from an authoritative Drupal claim.
import dk_api_lifecycle
import dk_acquisition

assert E.EVIDENCE_CHANNEL != dk_acquisition.ACQUISITION_CHANNEL
assert E.EVIDENCE_CHANNEL != dk_api_lifecycle.RECORD_CLASS
assert E.RESULT_DOMAIN not in {"api_migration", "upgrade_compatibility"}
print("PROJECT_DERIVED_EVIDENCE_PROVENANCE_DISTINCT=PASS")


# --- config evidence is not security authority -------------------------------------------------------

assert "not security truth" in evidence_c["boundaries"]["security_relationship"]
blob = json.dumps(evidence_c).lower()
for term in ("advisory", "cve-", "criticality", "vulnerab", "severity"):
    assert term not in blob, term
print("CONFIG_EVIDENCE_NOT_SECURITY_AUTHORITY=PASS")


# --- persistence carries no project name ---------------------------------------------------------

persist_root = WORKSPACE / "persisted"
persist_root.mkdir(parents=True, exist_ok=True)
stored = E.persist(before, persist_root)
payload = json.loads(stored.read_text(encoding="utf-8"))
assert "project_id" not in payload["project"], payload["project"]
assert payload["project"]["identity_basis"] == "fingerprints_only"
assert "fixture/evidence" not in stored.read_text(encoding="utf-8")
assert stored.parent.name == before["project"]["project_fingerprint"]
assert stored.stem == before["project"]["revision_fingerprint"]
# A different revision is a different file; history is never overwritten.
second = E.persist(after, persist_root)
assert second != stored and stored.is_file()
print("PROJECT_EVIDENCE_STORAGE_PRIVACY_PRESERVED=PASS")


# --- evidence feeds the existing applicability resolver -------------------------------------------
# There is one applicability engine. Evidence predicates are new operators
# inside it, not a second evaluator, so three-valued logic, grouping, reason
# codes and provenance all keep working unchanged.

assert "evidence_matches" in R.SUPPORTED_OPERATORS
assert "evidence_absent" in R.SUPPORTED_OPERATORS
assert "evidence_matches" in dk_core.MACHINE_APPLICABILITY_OPERATORS
resolver_source = (ROOT / "scripts" / "dk_applicability.py").read_text(encoding="utf-8")
assert resolver_source.count("def evaluate_condition") == 1, "one condition evaluator only"

FIXTURE_RULE = {
    "id": "fixture.evidence.implementation-rule",
    "title": "Fixture rule requiring observed project implementation evidence",
    "review_status": "reviewed",
    "enforcement": {"intent": "non_blocking"},
    "machine_applicability": {
        "schema_version": "0.1",
        "condition": {
            "all": [
                {
                    "id": "webform-installed",
                    "operator": "evidence_matches",
                    "assertion": "composer.package.installed",
                    "subject": "drupal/webform",
                },
                {
                    "id": "verbose-error-output",
                    "operator": "evidence_matches",
                    "assertion": "config.exported_value",
                    "subject": "system.logging:error_level",
                    "value": "verbose",
                },
            ]
        },
    },
}
R.validate_machine_applicability(FIXTURE_RULE, "fixture rule")
dk_core.validate_machine_applicability_contract(FIXTURE_RULE, "fixture rule")
print("EVIDENCE_REQUIREMENTS_MACHINE_READABLE=PASS")

# Both conditions definitively met: the rule applies.
CONFIRMING = analysis(
    declared={"drupal/webform": "^6.2"},
    locked=[package("drupal/webform", "6.2.0")],
    config_objects=[config_object("system.logging")],
    config_values=[config_value("system.logging", "error_level", "verbose")],
)
confirming_evidence = E.build(CONFIRMING, ROOT)
resolved = R.resolve_analysis_data(
    CONFIRMING,
    records=[FIXTURE_RULE],
    validate_canonical_knowledge=False,
    evidence=confirming_evidence,
)
result = resolved["results"][0]
assert result["applicability"] == "applicable", result
assert result["automation"]["status"] == "machine_resolved"
assert resolved["project_evidence"]["supplied"] is True
assert resolved["project_evidence"]["records"] == len(confirming_evidence["records"])
# The finding traces back to the exact evidence records that produced it.
evidence_ids = set(result["evidence_ids"])
assert evidence_ids, result
for item in confirming_evidence["records"]:
    if item["evidence_id"] in evidence_ids:
        assert item["observation"]["definitive"] is True
print("IMPLEMENTATION_EVIDENCE_FINDING_PATH_PROVEN=PASS")
print("PROJECT_EVIDENCE_FEEDS_EXISTING_APPLICABILITY_RESOLVER=PASS")
print("PROJECT_EVIDENCE_FINDING_CONFIRMATION_REQUIRES_SUFFICIENT_EVIDENCE=PASS")

# One condition definitively contradicted: not applicable, deterministically.
CONTRADICTING = analysis(
    declared={"drupal/webform": "^6.2"},
    locked=[package("drupal/webform", "6.2.0")],
    config_objects=[config_object("system.logging")],
    config_values=[config_value("system.logging", "error_level", "hide")],
)
contradicted = R.resolve_analysis_data(
    CONTRADICTING,
    records=[FIXTURE_RULE],
    validate_canonical_knowledge=False,
    evidence=E.build(CONTRADICTING, ROOT),
)["results"][0]
assert contradicted["applicability"] == "not_applicable", contradicted
print("MULTI_EVIDENCE_APPLICABILITY_DETERMINISTIC=PASS")

# The config side is unobservable: the whole rule stays unknown rather than
# resolving on the half it could see.
PARTIAL = analysis(
    declared={"drupal/webform": "^6.2"},
    locked=[package("drupal/webform", "6.2.0")],
    config_root=None,
    root_selection="ambiguous",
)
partial = R.resolve_analysis_data(
    PARTIAL,
    records=[FIXTURE_RULE],
    validate_canonical_knowledge=False,
    evidence=E.build(PARTIAL, ROOT),
)["results"][0]
assert partial["applicability"] == "unknown", partial
assert "EVIDENCE_NOT_OBSERVED" in partial["reason_codes"], partial["reason_codes"]

# And with no evidence set at all, an evidence rule cannot resolve either way.
without = R.resolve_analysis_data(
    CONFIRMING, records=[FIXTURE_RULE], validate_canonical_knowledge=False
)
assert without["results"][0]["applicability"] == "unknown"
assert without["project_evidence"]["supplied"] is False
assert "PROJECT_EVIDENCE_UNAVAILABLE" in without["results"][0]["reason_codes"]
print("PROJECT_EVIDENCE_UNKNOWN_PROPAGATES=PASS")

# A heuristic-only observation can never carry a rule to applicable.
HEURISTIC_RULE = {
    **FIXTURE_RULE,
    "id": "fixture.evidence.heuristic-rule",
    "enforcement": {"intent": "blocking"},
    "machine_applicability": {
        "schema_version": "0.1",
        "condition": {
            "id": "guessed-module",
            "operator": "evidence_matches",
            "assertion": "extension.code_present",
            "subject": "guessed_module",
        },
    },
}
heuristic_evidence = copy.deepcopy(confirming_evidence)
heuristic_evidence["records"].append(heuristic)
heuristic_result = R.resolve_analysis_data(
    CONFIRMING,
    records=[HEURISTIC_RULE],
    validate_canonical_knowledge=False,
    evidence=heuristic_evidence,
)["results"][0]
assert heuristic_result["applicability"] == "unknown", heuristic_result
assert "HEURISTIC_EVIDENCE_NOT_DEFINITIVE" in heuristic_result["reason_codes"]
# Even a blocking-intent rule cannot become applicable on heuristic evidence,
# so no blocking finding can be built from one.
assert heuristic_result["effective_enforcement"] == "blocking"
assert heuristic_result["applicability"] != "applicable"
print("HEURISTIC_EVIDENCE_CANNOT_CREATE_BLOCKING_FINDING=PASS")

# An unknown assertion fails conservatively rather than being guessed at.
UNKNOWN_RULE = {
    **FIXTURE_RULE,
    "id": "fixture.evidence.unknown-assertion",
    "machine_applicability": {
        "schema_version": "0.1",
        "condition": {
            "id": "made-up",
            "operator": "evidence_matches",
            "assertion": "invented.assertion",
            "subject": "whatever",
        },
    },
}
unknown_result = R.resolve_analysis_data(
    CONFIRMING,
    records=[UNKNOWN_RULE],
    validate_canonical_knowledge=False,
    evidence=confirming_evidence,
)["results"][0]
assert unknown_result["applicability"] == "unknown"
assert "UNSUPPORTED_EVIDENCE_ASSERTION" in unknown_result["reason_codes"]
print("UNKNOWN_EVIDENCE_ASSERTION_FAILS_CONSERVATIVELY=PASS")


# --- the CLI writes nothing to a project ------------------------------------------------------------

with tempfile.TemporaryDirectory() as directory:
    workspace = Path(directory)
    analysis_path = workspace / "analysis.json"
    analysis_path.write_text(json.dumps(CONFIRMING), encoding="utf-8")
    before_tree = sorted(path.name for path in workspace.iterdir())

    result = subprocess.run(
        [sys.executable, str(CLI), "evidence", str(analysis_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["result_domain"] == "project_evidence"
    assert payload["execution"]["project_writes"] is False

    explained = subprocess.run(
        [sys.executable, str(CLI), "evidence", str(analysis_path), "--domain", "dependency"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "PROJECT EVIDENCE" in explained.stdout
    assert "runtime_observed=False" in explained.stdout

    later = workspace / "after.json"
    later.write_text(json.dumps(payload), encoding="utf-8")
    diffed = subprocess.run(
        [sys.executable, str(CLI), "evidence-diff", str(later), str(later), "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(diffed.stdout)["summary"]["changed"] == 0

    assert sorted(path.name for path in workspace.iterdir()) == sorted(before_tree + ["after.json"])

for command in ("evidence", "evidence-diff"):
    help_text = subprocess.run(
        [sys.executable, str(CLI), command, "--help"], capture_output=True, text=True, check=True
    ).stdout
    for forbidden in ("--apply", "--rewrite", "--fix", "--write", "--execute"):
        assert forbidden not in help_text, f"{command} must not offer {forbidden}"
print("PROJECT_EVIDENCE_CLI_READ_ONLY=PASS")


# --- the released interface advertises the contract ---------------------------------------------------

version = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True
    ).stdout
)
interfaces = version["interfaces"]
assert interfaces["project_evidence_record_schema"] == E.EVIDENCE_RECORD_VERSION
assert interfaces["project_evidence_set_schema"] == E.EVIDENCE_SET_VERSION
engine = version["project_evidence_engine"]
assert engine["name"] == E.ENGINE_NAME
assert engine["result_domain"] == E.RESULT_DOMAIN
assert engine["channel"] == E.EVIDENCE_CHANNEL
assert engine["domains"] == list(E.DOMAINS)
assert engine["produces_trusted_knowledge"] is False
assert engine["project_writes"] is False
assert engine["runtime_observed"] is False
# Earlier releases still advertise what they advertised.
for key in ("migration_work_item_schema", "upgrade_assessment_schema", "security_advisory_schema"):
    assert key in interfaces, key
print("PROJECT_EVIDENCE_INTERFACE_ADVERTISED=PASS")


# --- the trust boundary --------------------------------------------------------------------------------

GUARDED = (
    "knowledge/records",
    "knowledge/context",
    "api/lifecycle",
    "api/change-records",
    "security/advisories",
    "cases/solved",
    "discovery",
    "sources/snapshots",
)
before_state = {
    str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in GUARDED
    for path in sorted((ROOT / relative).rglob("*"))
    if path.is_file()
}
E.build(CONFIRMING, ROOT)
E.diff(before, after)
R.resolve_analysis_data(
    CONFIRMING, records=[FIXTURE_RULE], validate_canonical_knowledge=False, evidence=confirming_evidence
)
after_state = {
    str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in GUARDED
    for path in sorted((ROOT / relative).rglob("*"))
    if path.is_file()
}
assert before_state == after_state, "evidence generation mutated trusted knowledge"
assert len(before_state) > 250, len(before_state)
print("PROJECT_EVIDENCE_ZERO_TRUSTED_KNOWLEDGE_MUTATION=PASS")


# --- no second consumer authority ---------------------------------------------------------------------------
# Consumers read released Drupal Knowledge through the CLI and API. No
# integration directory may carry a second engine.

integration = ROOT / "integrations"
if integration.is_dir():
    for path in integration.rglob("*"):
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace").lower()
            assert "evidence-diff" not in body, path
            assert "project_evidence_engine" not in body, path
print("NO_SECOND_EVIDENCE_AUTHORITY=PASS")
