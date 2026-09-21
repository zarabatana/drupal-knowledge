#!/usr/bin/env python3
"""Canonical project evidence: what was concretely observed, and how completely.

Every engine before this one grew its own way of asking the analyzer a
question. The security engine reads installed packages, the upgrade engine
reads constraints and extension metadata, the migration engine reads code. Each
was right, and each was private. This module turns those readings into one
reusable contract so a rule can say *composer package X is installed* or
*config key Y is Z* without a fourth engine learning to read composer.lock.

An evidence record says::

    this was concretely observed here

It never says::

    this is universally true

Three distinctions hold the layer up:

    static heuristic  != project fact       != trusted Drupal knowledge
    not_observed      != false              (unless the domain is complete)
    exported config   != runtime effective configuration

Completeness is why the second one works. Every producer declares whether its
search domain is complete, bounded, partial or unknown, and a negative
conclusion is only ever offered from a complete one. composer.lock enumerates
every locked package, so "package absent" is real. A bounded custom-code scan
finding no call to an API is not the same claim at all.

The engine is read-only. It writes nothing into the analysed project and
mutates no trusted knowledge.
"""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_core


ENGINE_NAME = "drupal-knowledge-evidence-engine"
ENGINE_VERSION = "0.1"
EVIDENCE_RECORD_VERSION = "0.1"
EVIDENCE_SET_VERSION = "0.1"

# Project-derived evidence is its own provenance channel, alongside external
# authoritative source-derived records, internal solved cases, discovery
# signals and trusted knowledge. Collapsing them is how a project observation
# turns into a Drupal-wide claim.
EVIDENCE_CHANNEL = "project_derived_evidence"
RESULT_DOMAIN = "project_evidence"

PERSIST_RELATIVE_PATH = Path("evidence") / "projects"

# --- domains -----------------------------------------------------------------

DOMAIN_CODE = "code"
DOMAIN_CONFIGURATION = "configuration"
DOMAIN_DEPENDENCY = "dependency"
DOMAIN_EXTENSION = "extension"
DOMAIN_PROJECT_METADATA = "project_metadata"

DOMAINS = (
    DOMAIN_CODE,
    DOMAIN_CONFIGURATION,
    DOMAIN_DEPENDENCY,
    DOMAIN_EXTENSION,
    DOMAIN_PROJECT_METADATA,
)

# --- states ------------------------------------------------------------------

OBSERVED = "observed"
NOT_OBSERVED = "not_observed"
UNKNOWN = "unknown"
INSUFFICIENT = "insufficient_evidence"
AMBIGUOUS = "ambiguous"
UNSUPPORTED = "unsupported_evidence_type"

STATES = (OBSERVED, NOT_OBSERVED, UNKNOWN, INSUFFICIENT, AMBIGUOUS, UNSUPPORTED)

# --- completeness ------------------------------------------------------------

COMPLETE = "complete"
BOUNDED = "bounded"
PARTIAL = "partial"
COMPLETENESS_UNKNOWN = "unknown"

COMPLETENESS = (COMPLETE, BOUNDED, PARTIAL, COMPLETENESS_UNKNOWN)

# --- quality -----------------------------------------------------------------
#
# Deterministic classes describing how the observation was made. There is no
# probability here and no model scoring: the class follows from the extraction
# method alone.

QUALITY_CANONICAL = "canonical_structured"
QUALITY_SYNTAX = "syntax_observed"
QUALITY_EXACT_FILE = "exact_file_fact"
QUALITY_BOUNDED_STATIC = "bounded_static_observation"
QUALITY_HEURISTIC = "heuristic_candidate"

QUALITIES = (
    QUALITY_CANONICAL,
    QUALITY_SYNTAX,
    QUALITY_EXACT_FILE,
    QUALITY_BOUNDED_STATIC,
    QUALITY_HEURISTIC,
)

# A heuristic may point somewhere worth looking. It may never author a fact, so
# no consumer is allowed to treat one as settled.
DEFINITIVE_QUALITIES = frozenset(
    {QUALITY_CANONICAL, QUALITY_SYNTAX, QUALITY_EXACT_FILE, QUALITY_BOUNDED_STATIC}
)

# --- assertions --------------------------------------------------------------
#
# The vocabulary a knowledge rule may require. Anything outside it fails
# conservatively rather than being guessed at.

A_PACKAGE_INSTALLED = "composer.package.installed"
A_PACKAGE_VERSION = "composer.package.locked_version"
A_PACKAGE_TYPE = "composer.package.type"
A_ROOT_REQUIREMENT = "composer.root_requirement"
A_DEPENDENCY_RELATION = "composer.dependency_relation"

A_CONFIG_OBJECT = "config.object.exported"
A_CONFIG_VALUE = "config.exported_value"
A_SETTINGS_VALUE = "config.settings_declaration"
A_CONFIG_DEPENDENCY = "config.dependency_module"
A_CONFIG_ROOT_SELECTION = "config.root_selection"

A_EXTENSION_PACKAGE = "extension.package_present"
A_EXTENSION_CODE = "extension.code_present"
A_EXTENSION_EXPORTED_ENABLED = "extension.exported_enabled"
A_EXTENSION_RUNTIME_ENABLED = "extension.runtime_enabled"
A_EXTENSION_CORE_REQUIREMENT = "extension.core_version_requirement"

A_CODE_API_USAGE = "code.api_usage"
A_CODE_SERVICE = "code.service_reference"
A_CODE_HOOK = "code.hook_implementation"
A_CODE_CLASS = "code.class_reference"

A_CORE_VERSION = "project.core_version"
A_PHP_PLATFORM = "project.php_platform"
A_WEB_ROOT = "project.web_root"
A_PROJECT_TYPE = "project.type"

ASSERTIONS = (
    A_PACKAGE_INSTALLED,
    A_PACKAGE_VERSION,
    A_PACKAGE_TYPE,
    A_ROOT_REQUIREMENT,
    A_DEPENDENCY_RELATION,
    A_CONFIG_OBJECT,
    A_CONFIG_VALUE,
    A_SETTINGS_VALUE,
    A_CONFIG_DEPENDENCY,
    A_CONFIG_ROOT_SELECTION,
    A_EXTENSION_PACKAGE,
    A_EXTENSION_CODE,
    A_EXTENSION_EXPORTED_ENABLED,
    A_EXTENSION_RUNTIME_ENABLED,
    A_EXTENSION_CORE_REQUIREMENT,
    A_CODE_API_USAGE,
    A_CODE_SERVICE,
    A_CODE_HOOK,
    A_CODE_CLASS,
    A_CORE_VERSION,
    A_PHP_PLATFORM,
    A_WEB_ROOT,
    A_PROJECT_TYPE,
)

ASSERTION_DOMAIN = {
    A_PACKAGE_INSTALLED: DOMAIN_DEPENDENCY,
    A_PACKAGE_VERSION: DOMAIN_DEPENDENCY,
    A_PACKAGE_TYPE: DOMAIN_DEPENDENCY,
    A_ROOT_REQUIREMENT: DOMAIN_DEPENDENCY,
    A_DEPENDENCY_RELATION: DOMAIN_DEPENDENCY,
    A_CONFIG_OBJECT: DOMAIN_CONFIGURATION,
    A_CONFIG_VALUE: DOMAIN_CONFIGURATION,
    A_SETTINGS_VALUE: DOMAIN_CONFIGURATION,
    A_CONFIG_DEPENDENCY: DOMAIN_CONFIGURATION,
    A_CONFIG_ROOT_SELECTION: DOMAIN_CONFIGURATION,
    A_EXTENSION_PACKAGE: DOMAIN_EXTENSION,
    A_EXTENSION_CODE: DOMAIN_EXTENSION,
    A_EXTENSION_EXPORTED_ENABLED: DOMAIN_EXTENSION,
    A_EXTENSION_RUNTIME_ENABLED: DOMAIN_EXTENSION,
    A_EXTENSION_CORE_REQUIREMENT: DOMAIN_EXTENSION,
    A_CODE_API_USAGE: DOMAIN_CODE,
    A_CODE_SERVICE: DOMAIN_CODE,
    A_CODE_HOOK: DOMAIN_CODE,
    A_CODE_CLASS: DOMAIN_CODE,
    A_CORE_VERSION: DOMAIN_PROJECT_METADATA,
    A_PHP_PLATFORM: DOMAIN_PROJECT_METADATA,
    A_WEB_ROOT: DOMAIN_PROJECT_METADATA,
    A_PROJECT_TYPE: DOMAIN_PROJECT_METADATA,
}

LOCAL_PATH_RE = re.compile(r"(^|[\"'\s=:])(/Users/|/home/|/root/|[A-Za-z]:\\\\)")

# Composer platform requirements are constraints on the environment, not
# packages. Reporting "php is not installed" because it is absent from the lock
# file's package list would be true and useless.
PLATFORM_REQUIREMENT_RE = re.compile(r"^(php(-64bit|-ipv6)?|hhvm|ext-[\w.-]+|lib-[\w.-]+|composer(-.+)?)$")


class EvidenceInputError(RuntimeError):
    """Caller asked for something the analyzer facts do not describe."""


class EvidenceEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as an evidence problem."""


def now_iso(moment: datetime | None = None) -> str:
    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def digest_hex(*parts: Any) -> str:
    accumulator = hashlib.sha256()
    for part in parts:
        accumulator.update(str(part).encode("utf-8"))
        accumulator.update(b"\0")
    return accumulator.hexdigest()


# ---------------------------------------------------------------------------
# Analyzer facts, read rather than re-derived
# ---------------------------------------------------------------------------


def require_analysis(analysis: Any) -> dict:
    if not isinstance(analysis, dict) or "profile" not in analysis:
        raise EvidenceInputError("input is not a project analyzer result")
    if analysis.get("analyzer", {}).get("name") != "drupal-project-analyzer":
        raise EvidenceInputError(
            "input was not produced by the Drupal Knowledge project analyzer"
        )
    return analysis


def fact(analysis: dict, name: str) -> dict:
    return (analysis.get("profile", {}).get("facts", {}) or {}).get(name) or {"state": UNKNOWN}


def known_value(analysis: dict, name: str) -> Any:
    item = fact(analysis, name)
    return item.get("value") if item.get("state") == "known" else None


def fact_evidence_ids(analysis: dict, name: str) -> list[str]:
    item = fact(analysis, name)
    ids = item.get("source_evidence_ids")
    return sorted(ids) if isinstance(ids, list) else []


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def evidence_id(assertion: str, subject: str, scope: dict) -> str:
    return "evidence." + digest_hex(
        EVIDENCE_RECORD_VERSION, assertion, subject, stable_json(scope)
    )[:16]


def record(
    assertion: str,
    subject: str,
    *,
    state: str,
    value: Any = None,
    quality: str,
    completeness: str,
    extraction: str,
    scope: dict | None = None,
    provenance: dict | None = None,
    notes: str | None = None,
) -> dict:
    if assertion not in ASSERTIONS:
        raise EvidenceEngineDefect(f"unknown assertion type {assertion!r}")
    if state not in STATES:
        raise EvidenceEngineDefect(f"unknown evidence state {state!r}")
    if quality not in QUALITIES:
        raise EvidenceEngineDefect(f"unknown evidence quality {quality!r}")
    if completeness not in COMPLETENESS:
        raise EvidenceEngineDefect(f"unknown completeness {completeness!r}")
    scope = scope or {}
    return {
        "record_contract_version": EVIDENCE_RECORD_VERSION,
        "evidence_id": evidence_id(assertion, subject, scope),
        "domain": ASSERTION_DOMAIN[assertion],
        "assertion": assertion,
        "subject": subject,
        "observation": {
            "state": state,
            "value": value,
            "quality": quality,
            "extraction": extraction,
            # A heuristic can point at something. It cannot settle it, and this
            # flag is what stops a consumer treating one as though it had.
            "definitive": quality in DEFINITIVE_QUALITIES and state in (OBSERVED, NOT_OBSERVED),
        },
        "scope": scope,
        "completeness": {
            "search_domain": completeness,
            # Only a complete domain can support "this is absent". Everything
            # else can only report that it did not observe the thing.
            "supports_negative_conclusion": completeness == COMPLETE,
        },
        "provenance": {
            "channel": EVIDENCE_CHANNEL,
            "produced_by": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
            **(provenance or {}),
        },
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Dependency evidence
#
# Declared, locked and installed are three different observations of one
# package. Collapsing them is how "it is in composer.json" becomes "it is
# installed", which is exactly the mistake the upgrade engine must not make.
# ---------------------------------------------------------------------------


def dependency_records(analysis: dict) -> list[dict]:
    packages = known_value(analysis, "composer_packages") or {}
    declared = packages.get("declared") or {}
    installed = packages.get("installed") or {}
    evidence_ids = fact_evidence_ids(analysis, "composer_packages")
    lock_available = bool(installed.get("available"))

    base_provenance = {
        "analyzer_fact": "composer_packages",
        "analyzer_evidence_ids": evidence_ids,
    }
    found: list[dict] = []

    # Root requirements: what the manifest asks for, which is not what is here.
    for section, is_dev in (("require", False), ("require_dev", True)):
        block = declared.get(section)
        if not isinstance(block, dict):
            continue
        for package, constraint in sorted(block.items()):
            found.append(
                record(
                    A_ROOT_REQUIREMENT,
                    package,
                    state=OBSERVED,
                    value={"constraint": constraint, "dev": is_dev, "manifest_section": section},
                    quality=QUALITY_CANONICAL,
                    completeness=COMPLETE,
                    extraction="composer_json_root_manifest",
                    scope={"manifest": "composer.json", "section": section},
                    provenance=base_provenance,
                    notes=(
                        "A root requirement states what the project asks for. It is not "
                        "evidence that the package is present."
                    ),
                )
            )

    if not lock_available:
        found.append(
            record(
                A_PACKAGE_INSTALLED,
                "*",
                state=INSUFFICIENT,
                quality=QUALITY_CANONICAL,
                completeness=COMPLETENESS_UNKNOWN,
                extraction="composer_lock_absent",
                scope={"manifest": "composer.lock"},
                provenance=base_provenance,
                notes=(
                    "No installed package evidence was observed, so no package can be "
                    "reported installed and none can be reported absent."
                ),
            )
        )
        return sorted(found, key=lambda item: (item["assertion"], item["subject"]))

    # composer.lock enumerates every locked package, so this domain is complete
    # and a negative conclusion drawn from it is real.
    for package in sorted(installed.get("packages") or [], key=lambda item: item["name"]):
        name = package["name"]
        relation = "dev_requirement" if package.get("dev") else "runtime_requirement"
        direct = name in (declared.get("require") or {}) or name in (
            declared.get("require_dev") or {}
        )
        found.append(
            record(
                A_PACKAGE_INSTALLED,
                name,
                state=OBSERVED,
                value=True,
                quality=QUALITY_CANONICAL,
                completeness=COMPLETE,
                extraction="composer_lock_package_list",
                scope={"manifest": "composer.lock"},
                provenance=base_provenance,
            )
        )
        found.append(
            record(
                A_PACKAGE_VERSION,
                name,
                state=OBSERVED,
                value=package.get("version"),
                quality=QUALITY_CANONICAL,
                completeness=COMPLETE,
                extraction="composer_lock_package_version",
                scope={"manifest": "composer.lock"},
                provenance=base_provenance,
            )
        )
        if package.get("type"):
            found.append(
                record(
                    A_PACKAGE_TYPE,
                    name,
                    state=OBSERVED,
                    value=package["type"],
                    quality=QUALITY_CANONICAL,
                    completeness=COMPLETE,
                    extraction="composer_lock_package_type",
                    scope={"manifest": "composer.lock"},
                    provenance=base_provenance,
                )
            )
        found.append(
            record(
                A_DEPENDENCY_RELATION,
                name,
                state=OBSERVED,
                value={
                    "relation": relation,
                    "direct": direct,
                    # composer.lock as the analyzer reads it does not carry the
                    # requiring package, so a transitive package's parent is not
                    # claimed rather than guessed.
                    "required_by": "unknown" if not direct else "root_manifest",
                },
                quality=QUALITY_CANONICAL,
                completeness=BOUNDED,
                extraction="composer_lock_relation",
                scope={"manifest": "composer.lock"},
                provenance=base_provenance,
                notes=(
                    "Direct or transitive follows from the root manifest. The requiring "
                    "package of a transitive dependency is not observed here."
                ),
            )
        )

    # A root requirement whose package is not in the lock file. The lock is a
    # complete enumeration, so this absence is a real observation.
    locked = {package["name"] for package in installed.get("packages") or []}
    for section in ("require", "require_dev"):
        for package in sorted((declared.get(section) or {})):
            if package in locked or PLATFORM_REQUIREMENT_RE.match(package):
                continue
            found.append(
                record(
                    A_PACKAGE_INSTALLED,
                    package,
                    state=NOT_OBSERVED,
                    value=False,
                    quality=QUALITY_CANONICAL,
                    completeness=COMPLETE,
                    extraction="composer_lock_package_list",
                    scope={"manifest": "composer.lock"},
                    provenance=base_provenance,
                    notes=(
                        "Declared in the root manifest and absent from the complete lock "
                        "enumeration, so it is genuinely not installed."
                    ),
                )
            )

    return sorted(found, key=lambda item: (item["assertion"], item["subject"]))


# ---------------------------------------------------------------------------
# Configuration evidence
# ---------------------------------------------------------------------------


def configuration_records(analysis: dict) -> list[dict]:
    configuration = known_value(analysis, "configuration_objects") or {}
    settings = known_value(analysis, "settings_declarations") or {}
    scan = configuration.get("scan") or {}
    evidence_ids = fact_evidence_ids(analysis, "configuration_objects")
    found: list[dict] = []

    config_root = scan.get("config_root")
    objects_complete = scan.get("object_enumeration") == "complete_for_selected_config_root"

    # How root selection went is itself a definitive observation: the candidate
    # roots were enumerated, and finding two of them is a fact about the
    # repository rather than an absence of information about it.
    selection = scan.get("root_selection")
    if selection:
        found.append(
            record(
                A_CONFIG_ROOT_SELECTION,
                "exported_configuration",
                state=OBSERVED,
                value=selection,
                quality=QUALITY_EXACT_FILE,
                completeness=COMPLETE,
                extraction="config_root_candidate_enumeration",
                scope={"config_root": config_root},
                provenance={
                    "analyzer_fact": "configuration_objects",
                    "analyzer_evidence_ids": evidence_ids,
                },
                notes=(
                    "Which exported configuration root was selected, or that none could "
                    "be. An ambiguous result means no configuration was enumerated."
                ),
            )
        )

    if not config_root:
        found.append(
            record(
                A_CONFIG_OBJECT,
                "*",
                state=AMBIGUOUS if scan.get("root_selection") == "ambiguous" else INSUFFICIENT,
                quality=QUALITY_EXACT_FILE,
                completeness=COMPLETENESS_UNKNOWN,
                extraction="config_root_selection",
                scope={"config_root": None},
                provenance={
                    "analyzer_fact": "configuration_objects",
                    "analyzer_evidence_ids": evidence_ids,
                    "root_selection": scan.get("root_selection"),
                },
                notes=(
                    "No single exported config root was selected, so no exported "
                    "configuration was enumerated and none can be reported absent."
                ),
            )
        )
    else:
        for item in configuration.get("objects") or []:
            found.append(
                record(
                    A_CONFIG_OBJECT,
                    item["config_name"],
                    state=OBSERVED,
                    value={"sha256": item["sha256"], "bytes": item["bytes"]},
                    quality=QUALITY_EXACT_FILE,
                    completeness=COMPLETE if objects_complete else PARTIAL,
                    extraction="exported_config_root_enumeration",
                    scope={"config_root": config_root, "path": item["path"]},
                    provenance={
                        "analyzer_fact": "configuration_objects",
                        "analyzer_evidence_ids": evidence_ids,
                        "config_scan_digest": scan.get("config_digest"),
                    },
                )
            )

    for item in configuration.get("values") or []:
        subject = f"{item['config_name']}:{item['key']}"
        if item["state"] == "present":
            state, value = OBSERVED, item["value"]
        elif item["state"] == "absent_from_object":
            state, value = NOT_OBSERVED, None
        else:
            state, value = UNSUPPORTED, None
        found.append(
            record(
                A_CONFIG_VALUE,
                subject,
                state=state,
                value=value,
                quality=QUALITY_CANONICAL,
                # The key list is declared, so this domain is bounded: a key
                # nobody declared is unobserved, not absent.
                completeness=BOUNDED,
                extraction="exported_config_declared_key",
                scope={
                    "config_root": config_root,
                    "path": item["path"],
                    "config_name": item["config_name"],
                    "key": item["key"],
                },
                provenance={
                    "analyzer_fact": "configuration_objects",
                    "analyzer_evidence_ids": evidence_ids,
                    "config_scan_digest": scan.get("config_digest"),
                },
                notes=(
                    "This is the exported value held in the repository. settings.php and "
                    "environment overrides can change it, and neither is observed here, so "
                    "the runtime effective value is unknown."
                ),
            )
        )

    for item in configuration.get("dependencies") or []:
        found.append(
            record(
                A_CONFIG_DEPENDENCY,
                item["config_name"],
                state=OBSERVED,
                value={"modules": list(item["modules"])},
                quality=QUALITY_CANONICAL,
                # Objects the safe parser refuses are not read at all, so the
                # set of dependency declarations is partial by construction and
                # cannot support a claim that some module is depended on by
                # nothing.
                completeness=PARTIAL,
                extraction="exported_config_dependencies_block",
                scope={
                    "config_root": config_root,
                    "path": item["path"],
                    "config_name": item["config_name"],
                },
                provenance={
                    "analyzer_fact": "configuration_objects",
                    "analyzer_evidence_ids": evidence_ids,
                    "config_scan_digest": scan.get("config_digest"),
                },
                notes=(
                    "The modules this config object declares a dependency on, read from "
                    "its own dependencies block."
                ),
            )
        )

    for item in configuration.get("unreadable") or []:
        found.append(
            record(
                A_CONFIG_OBJECT,
                item["config_name"],
                state=UNSUPPORTED,
                quality=QUALITY_EXACT_FILE,
                completeness=COMPLETENESS_UNKNOWN,
                extraction="exported_config_parse_failure",
                scope={"config_root": config_root, "path": item["path"]},
                provenance={
                    "analyzer_fact": "configuration_objects",
                    "parse_error": item["reason"],
                },
                notes="The object exists but could not be parsed, so its keys are unknown.",
            )
        )

    settings_scan = settings.get("scan") or {}
    for item in settings.get("entries") or []:
        found.append(
            record(
                A_SETTINGS_VALUE,
                item["key"],
                state=OBSERVED if item["state"] == "present" else UNSUPPORTED,
                value=item["value"] if item["state"] == "present" else None,
                quality=QUALITY_SYNTAX,
                completeness=BOUNDED,
                extraction="settings_php_scalar_assignment",
                scope={"path": item["path"], "line": item["line"]},
                provenance={
                    "analyzer_fact": "settings_declarations",
                    "php_executed": False,
                    "config_scan_digest": settings_scan.get("config_digest"),
                },
                notes=(
                    "A declared assignment read without executing PHP. A later assignment "
                    "in an included file could still override it."
                ),
            )
        )

    return sorted(found, key=lambda item: (item["assertion"], item["subject"]))


# ---------------------------------------------------------------------------
# Extension evidence
#
# Four different things a repository can show about one extension, and only the
# fourth is what an operator usually means by "is it on".
# ---------------------------------------------------------------------------


DRUPAL_PACKAGE_RE = re.compile(r"^drupal/(?P<name>[a-z0-9_]+)$")


def extension_records(analysis: dict) -> list[dict]:
    packages = known_value(analysis, "composer_packages") or {}
    installed = packages.get("installed") or {}
    modules_fact = fact(analysis, "modules")
    themes_fact = fact(analysis, "themes")
    configuration = known_value(analysis, "configuration_objects") or {}
    config_root = (configuration.get("scan") or {}).get("config_root")
    found: list[dict] = []

    # 1. The package is in the lock file.
    for package in sorted(installed.get("drupal_packages") or [], key=lambda item: item["name"]):
        match = DRUPAL_PACKAGE_RE.match(package["name"])
        if not match:
            continue
        found.append(
            record(
                A_EXTENSION_PACKAGE,
                match.group("name"),
                state=OBSERVED,
                value={"package": package["name"], "version": package.get("version")},
                quality=QUALITY_CANONICAL,
                completeness=COMPLETE,
                extraction="composer_lock_drupal_package",
                scope={"manifest": "composer.lock"},
                provenance={"analyzer_fact": "composer_packages"},
                notes=(
                    "The package is installed. That is not evidence that the extension is "
                    "enabled, in exported configuration or at runtime."
                ),
            )
        )

    # 2. Custom extension code exists in the tree, with what it declares.
    for name in ("custom_modules", "custom_themes"):
        entry = fact(analysis, name)
        if entry.get("state") != "known":
            continue
        for extension in entry.get("value") or []:
            found.append(
                record(
                    A_EXTENSION_CODE,
                    extension["machine_name"],
                    state=OBSERVED,
                    value={"type": extension["type"], "path": extension["path"]},
                    quality=QUALITY_EXACT_FILE,
                    completeness=BOUNDED,
                    extraction="custom_extension_info_yml",
                    scope={"path": extension["path"], "extension_type": extension["type"]},
                    provenance={"analyzer_fact": name},
                    notes="Code present in a conventional custom root. Not an enablement claim.",
                )
            )
            if extension.get("core_version_requirement"):
                found.append(
                    record(
                        A_EXTENSION_CORE_REQUIREMENT,
                        extension["machine_name"],
                        state=OBSERVED,
                        value=extension["core_version_requirement"],
                        quality=QUALITY_EXACT_FILE,
                        completeness=BOUNDED,
                        extraction="custom_extension_info_yml",
                        scope={"path": extension["path"]},
                        provenance={"analyzer_fact": name},
                    )
                )

    # 3. The exported configuration lists it as enabled. Exported, not running.
    for entry, extension_type in ((modules_fact, "module"), (themes_fact, "theme")):
        if entry.get("state") != "known":
            found.append(
                record(
                    A_EXTENSION_EXPORTED_ENABLED,
                    f"*:{extension_type}",
                    state=INSUFFICIENT,
                    quality=QUALITY_CANONICAL,
                    completeness=COMPLETENESS_UNKNOWN,
                    extraction="core_extension_exported_config",
                    scope={"config_root": config_root, "extension_type": extension_type},
                    provenance={"analyzer_fact": "modules" if extension_type == "module" else "themes"},
                    notes=(
                        "No exported core.extension state was observed, so no extension can "
                        "be reported exported-enabled and none can be reported absent."
                    ),
                )
            )
            continue
        for name in entry.get("value") or []:
            found.append(
                record(
                    A_EXTENSION_EXPORTED_ENABLED,
                    name,
                    state=OBSERVED,
                    value={"extension_type": extension_type, "source": "core.extension"},
                    quality=QUALITY_CANONICAL,
                    # core.extension enumerates every extension the exported
                    # configuration enables, so absence from it is meaningful
                    # for the exported state and only for that.
                    completeness=COMPLETE,
                    extraction="core_extension_exported_config",
                    scope={"config_root": config_root, "extension_type": extension_type},
                    provenance={"analyzer_fact": "modules" if extension_type == "module" else "themes"},
                    notes=(
                        "Enabled in exported configuration. Whether the running site has "
                        "this extension enabled is a different question this cannot answer."
                    ),
                )
            )

    # 4. Runtime enablement. The repository never proves it.
    found.append(
        record(
            A_EXTENSION_RUNTIME_ENABLED,
            "*",
            state=UNKNOWN,
            quality=QUALITY_CANONICAL,
            completeness=COMPLETENESS_UNKNOWN,
            extraction="no_runtime_observation",
            scope={},
            provenance={"analyzer_mode": "static-file-inspection"},
            notes=(
                "Runtime state is not observed by static repository analysis. An installed "
                "package and an exported-enabled extension are both compatible with the "
                "module being disabled on the running site."
            ),
        )
    )

    return sorted(found, key=lambda item: (item["assertion"], item["subject"]))


# ---------------------------------------------------------------------------
# Code evidence
#
# Reuses the migration engine's syntax-aware observation rather than looking at
# any file itself, so there is one reading of PHP in the product and not two.
# ---------------------------------------------------------------------------


CODE_ASSERTION_FOR_USAGE = {
    "function_call": A_CODE_API_USAGE,
    "static_call": A_CODE_API_USAGE,
    "constant_reference": A_CODE_API_USAGE,
    "class_reference": A_CODE_CLASS,
    "service_reference": A_CODE_SERVICE,
    "hook_implementation": A_CODE_HOOK,
}


def code_records(analysis: dict, observations: list[dict], scan: dict | None) -> list[dict]:
    """Canonical code evidence from already-observed API usage."""
    grouped: dict[tuple[str, str], list[dict]] = {}
    for observation in observations:
        assertion = CODE_ASSERTION_FOR_USAGE.get(observation["usage_kind"])
        if assertion is None:
            continue
        grouped.setdefault((assertion, observation["symbol"]), []).append(observation)

    found: list[dict] = []
    for (assertion, symbol), items in sorted(grouped.items()):
        occurrences = sorted(
            ({"path": item["path"], "line": item["line"], "component": item["component"]}
             for item in items),
            key=lambda item: (item["path"], item["line"]),
        )
        found.append(
            record(
                assertion,
                symbol,
                state=OBSERVED,
                value={
                    "occurrence_count": len(occurrences),
                    "usage_kinds": sorted({item["usage_kind"] for item in items}),
                },
                quality=QUALITY_SYNTAX,
                # The scan is bounded by the declared custom-code configuration,
                # so not finding a symbol is not the same as it being unused.
                completeness=BOUNDED,
                extraction="syntax_aware_php_token_stream",
                scope={
                    "occurrences": occurrences,
                    "components": sorted({item["component"] for item in items if item["component"]}),
                },
                provenance={
                    "analyzer_fact": "custom_code_files",
                    "observation_engine": "drupal-knowledge-migration-engine",
                    "custom_code_scan_digest": (scan or {}).get("config_digest"),
                },
                notes=(
                    "Observed in code, not in a comment or a string. Absence from this "
                    "bounded scan is not evidence the symbol is unused."
                ),
            )
        )
    return found


# ---------------------------------------------------------------------------
# Project metadata evidence
# ---------------------------------------------------------------------------


def metadata_records(analysis: dict) -> list[dict]:
    found: list[dict] = []
    core = fact(analysis, "drupal_core_version")
    found.append(
        record(
            A_CORE_VERSION,
            "drupal/core",
            state=OBSERVED if core.get("state") == "known" else INSUFFICIENT,
            value=(core.get("value") or {}).get("version") if core.get("state") == "known" else None,
            quality=QUALITY_CANONICAL,
            completeness=COMPLETE if core.get("state") == "known" else COMPLETENESS_UNKNOWN,
            extraction="installed_core_package",
            scope={"manifest": "composer.lock"},
            provenance={"analyzer_fact": "drupal_core_version"},
        )
    )

    php = fact(analysis, "php_version")
    if php.get("state") == "known":
        value = php.get("value") or {}
        found.append(
            record(
                A_PHP_PLATFORM,
                "php",
                state=OBSERVED,
                value={
                    "composer_platform": value.get("composer_platform"),
                    "composer_requirement": value.get("composer_requirement"),
                    # The analyzer refuses to report the host PHP as the
                    # project's, and so does this.
                    "runtime": UNKNOWN,
                },
                quality=QUALITY_CANONICAL,
                completeness=BOUNDED,
                extraction="composer_json_platform",
                scope={"manifest": "composer.json"},
                provenance={"analyzer_fact": "php_version"},
                notes="Declared platform only. The runtime PHP version is not observed.",
            )
        )
    else:
        found.append(
            record(
                A_PHP_PLATFORM,
                "php",
                state=INSUFFICIENT,
                quality=QUALITY_CANONICAL,
                completeness=COMPLETENESS_UNKNOWN,
                extraction="composer_json_platform",
                scope={"manifest": "composer.json"},
                provenance={"analyzer_fact": "php_version"},
            )
        )

    web_root = fact(analysis, "drupal_web_root")
    found.append(
        record(
            A_WEB_ROOT,
            "web_root",
            state=OBSERVED if web_root.get("state") == "known" else INSUFFICIENT,
            value=web_root.get("value") if web_root.get("state") == "known" else None,
            quality=QUALITY_EXACT_FILE,
            completeness=BOUNDED,
            extraction="filesystem_marker",
            scope={},
            provenance={"analyzer_fact": "drupal_web_root"},
        )
    )

    project_type = fact(analysis, "project_type")
    if project_type.get("state") == "known":
        found.append(
            record(
                A_PROJECT_TYPE,
                "project",
                state=OBSERVED,
                value=(project_type.get("value") or {}).get("type"),
                quality=QUALITY_CANONICAL,
                completeness=BOUNDED,
                extraction="composer_and_filesystem_markers",
                scope={},
                provenance={"analyzer_fact": "project_type"},
            )
        )
    return sorted(found, key=lambda item: (item["assertion"], item["subject"]))


# ---------------------------------------------------------------------------
# Evidence set
# ---------------------------------------------------------------------------


def revision_fingerprint(analysis: dict) -> str:
    """Identity of exactly this repository content.

    Built from the file digests the analyzer already recorded, so the same
    revision always produces the same evidence identities and a changed file
    always produces a different set.
    """
    inventory = known_value(analysis, "custom_code_files") or {}
    configuration = known_value(analysis, "configuration_objects") or {}
    settings = known_value(analysis, "settings_declarations") or {}
    packages = known_value(analysis, "composer_packages") or {}
    return digest_hex(
        stable_json([[item["path"], item["sha256"]] for item in inventory.get("files", [])]),
        stable_json([[item["path"], item["sha256"]] for item in configuration.get("objects", [])]),
        stable_json([[item["path"], item["key"], item["value"]] for item in settings.get("entries", [])]),
        stable_json((packages.get("installed") or {}).get("packages") or []),
        stable_json((packages.get("declared") or {}).get("require") or {}),
    )


def project_fingerprint(analysis: dict) -> str:
    """Stable identity of the project, carrying no owner-identifying name."""
    return digest_hex("drupal-knowledge-project", analysis.get("project_id") or "")


def assert_no_local_paths(payload: Any, where: str) -> None:
    text = stable_json(payload)
    match = LOCAL_PATH_RE.search(text)
    if match:
        raise EvidenceEngineDefect(
            f"{where}: refused to record an absolute local path: {match.group(0)!r}"
        )


def build(
    analysis: Any,
    root: Path = dk_core.ROOT,
    project_path: str | Path | None = None,
    generated_at: str | None = None,
) -> dict:
    """Canonical evidence for one analysed project revision. Read-only."""
    analysis = require_analysis(analysis)

    code_scan = known_value(analysis, "custom_code_files") or {}
    code_available = bool(code_scan.get("files"))
    observations: list[dict] = []
    if project_path and code_available:
        # Source is read in exactly one place in the product. This layer asks
        # for the observations rather than opening a file itself, so there is
        # never a second reading of PHP to keep in agreement with the first.
        import dk_migration

        observations = dk_migration.observe_project(analysis, project_path)["observations"]

    records = (
        dependency_records(analysis)
        + configuration_records(analysis)
        + extension_records(analysis)
        + code_records(analysis, observations, code_scan.get("scan"))
        + metadata_records(analysis)
    )
    records.sort(key=lambda item: (item["domain"], item["assertion"], item["subject"]))

    revision = revision_fingerprint(analysis)
    fingerprint = project_fingerprint(analysis)
    by_domain = {domain: 0 for domain in DOMAINS}
    by_state = {state: 0 for state in STATES}
    for item in records:
        by_domain[item["domain"]] += 1
        by_state[item["observation"]["state"]] += 1

    payload = {
        "schema_version": EVIDENCE_SET_VERSION,
        "evidence_set_id": "evidence-set." + digest_hex(EVIDENCE_SET_VERSION, fingerprint, revision)[:16],
        "result_domain": RESULT_DOMAIN,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
            "produces_trusted_knowledge": False,
            "project_writes": False,
        },
        "generated_at": generated_at or now_iso(),
        "project": {
            "project_id": analysis.get("project_id"),
            "project_fingerprint": fingerprint,
            "revision_fingerprint": revision,
            "facts_source": "drupal_project_analyzer_profile_facts",
            "analyzer_version": analysis.get("analyzer", {}).get("version"),
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
            DOMAIN_DEPENDENCY: {
                "search_domain": COMPLETE if (known_value(analysis, "composer_packages") or {}).get("installed", {}).get("available") else COMPLETENESS_UNKNOWN,
                "basis": "composer.lock enumerates every locked package",
            },
            DOMAIN_CONFIGURATION: {
                "search_domain": COMPLETE
                if (known_value(analysis, "configuration_objects") or {}).get("objects")
                else COMPLETENESS_UNKNOWN,
                "basis": "config objects are complete for the selected root; values are bounded by declared keys",
            },
            DOMAIN_EXTENSION: {
                "search_domain": COMPLETE
                if fact(analysis, "modules").get("state") == "known"
                else COMPLETENESS_UNKNOWN,
                "basis": "core.extension enumerates exported-enabled extensions; runtime state is never observed",
            },
            DOMAIN_CODE: {
                "search_domain": BOUNDED if code_available and project_path else COMPLETENESS_UNKNOWN,
                "basis": "custom-code scan bounded by its declared configuration; contrib and vendor are out of scope",
            },
            DOMAIN_PROJECT_METADATA: {
                "search_domain": BOUNDED,
                "basis": "declared manifest and filesystem markers only",
            },
        },
        "boundaries": {
            "runtime_observed": False,
            "database_inspected": False,
            "php_executed": False,
            "statement": (
                "Every record here is a repository observation. Absence of evidence is "
                "only absence of the thing where the search domain is complete."
            ),
            "security_relationship": (
                "A configuration or code observation is evidence, not security truth. It "
                "may later contribute to a security finding; it is not one."
            ),
        },
        "execution": {
            "project_writes": False,
            "code_modified": False,
            "runtime_probed": False,
        },
        "trusted_knowledge_mutations": {
            "knowledge_records": 0,
            "reviewed_context": 0,
            "source_derived_records": 0,
            "advisories": 0,
            "solved_cases": 0,
            "discovery": 0,
        },
    }

    assert_no_local_paths(payload["records"], "evidence records")
    validate_set(payload)
    return payload


# ---------------------------------------------------------------------------
# Lookup used by the applicability resolver
# ---------------------------------------------------------------------------


def index(evidence_set: dict) -> dict:
    """Records keyed by (assertion, subject), plus per-assertion completeness."""
    by_key: dict[tuple[str, str], dict] = {}
    domain_complete: dict[str, bool] = {}
    for item in evidence_set.get("records", []):
        by_key[(item["assertion"], item["subject"])] = item
        complete = item["completeness"]["supports_negative_conclusion"]
        domain_complete[item["assertion"]] = domain_complete.get(item["assertion"], False) or complete
    return {"by_key": by_key, "assertion_complete": domain_complete}


def read_path(value: Any, path: str | None) -> tuple[bool, Any]:
    if not path:
        return True, value
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def diff(before: dict, after: dict) -> dict:
    """Deterministic comparison of two evidence sets."""
    for payload, label in ((before, "before"), (after, "after")):
        if not isinstance(payload, dict) or payload.get("result_domain") != RESULT_DOMAIN:
            raise EvidenceInputError(f"{label} is not a project evidence set")

    def keyed(payload: dict) -> dict[tuple[str, str], dict]:
        return {(item["assertion"], item["subject"]): item for item in payload["records"]}

    old, new = keyed(before), keyed(after)
    added, removed, changed, unchanged = [], [], [], []

    for key in sorted(set(old) | set(new)):
        assertion, subject = key
        entry = {"assertion": assertion, "subject": subject, "domain": ASSERTION_DOMAIN[assertion]}
        if key not in old:
            added.append({**entry, "state": new[key]["observation"]["state"], "value": new[key]["observation"]["value"]})
        elif key not in new:
            removed.append({**entry, "state": old[key]["observation"]["state"], "value": old[key]["observation"]["value"]})
        else:
            before_observation = old[key]["observation"]
            after_observation = new[key]["observation"]
            if (
                before_observation["state"] != after_observation["state"]
                or before_observation["value"] != after_observation["value"]
            ):
                changed.append(
                    {
                        **entry,
                        "before": {"state": before_observation["state"], "value": before_observation["value"]},
                        "after": {"state": after_observation["state"], "value": after_observation["value"]},
                    }
                )
            else:
                unchanged.append(entry)

    return {
        "schema_version": EVIDENCE_SET_VERSION,
        "result_domain": RESULT_DOMAIN,
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION, "deterministic": True},
        "before": {
            "evidence_set_id": before["evidence_set_id"],
            "project_fingerprint": before["project"]["project_fingerprint"],
            "revision_fingerprint": before["project"]["revision_fingerprint"],
        },
        "after": {
            "evidence_set_id": after["evidence_set_id"],
            "project_fingerprint": after["project"]["project_fingerprint"],
            "revision_fingerprint": after["project"]["revision_fingerprint"],
        },
        "same_project": before["project"]["project_fingerprint"] == after["project"]["project_fingerprint"],
        "same_revision": before["project"]["revision_fingerprint"] == after["project"]["revision_fingerprint"],
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": len(unchanged),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
    }


# ---------------------------------------------------------------------------
# Optional persistence
# ---------------------------------------------------------------------------


def persist(evidence_set: dict, root: Path = dk_core.ROOT) -> Path:
    """Store an evidence set under fingerprints, never under a project name.

    Persistence is optional; the CLI is ephemeral by default. When a set is
    stored it is stored by identity alone, so the tree carries no project name,
    and a revision's file is never rewritten by a later revision.
    """
    scrubbed = copy.deepcopy(evidence_set)
    # The project id is the owner's own name for the project. Fingerprints
    # identify the same thing without carrying it into a shared tree.
    scrubbed["project"].pop("project_id", None)
    scrubbed["project"]["identity_basis"] = "fingerprints_only"
    assert_no_local_paths(scrubbed, "persisted evidence set")

    fingerprint = scrubbed["project"]["project_fingerprint"]
    revision = scrubbed["project"]["revision_fingerprint"]
    directory = root / PERSIST_RELATIVE_PATH / fingerprint
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{revision}.json"
    path.write_text(stable_json(scrubbed), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Guards and rendering
# ---------------------------------------------------------------------------


def validate_record(item: dict) -> None:
    required = {
        "record_contract_version",
        "evidence_id",
        "domain",
        "assertion",
        "subject",
        "observation",
        "scope",
        "completeness",
        "provenance",
    }
    missing = sorted(required - set(item))
    if missing:
        raise EvidenceEngineDefect(f"evidence record missing keys: {', '.join(missing)}")
    if item["domain"] not in DOMAINS:
        raise EvidenceEngineDefect(f"unknown evidence domain {item['domain']!r}")
    if item["observation"]["state"] == NOT_OBSERVED and not item["completeness"][
        "supports_negative_conclusion"
    ]:
        raise EvidenceEngineDefect(
            f"{item['evidence_id']}: not_observed requires a complete search domain"
        )
    if item["observation"]["quality"] == QUALITY_HEURISTIC and item["observation"]["definitive"]:
        raise EvidenceEngineDefect(
            f"{item['evidence_id']}: a heuristic observation is never definitive"
        )
    if item["provenance"]["channel"] != EVIDENCE_CHANNEL:
        raise EvidenceEngineDefect(f"{item['evidence_id']}: wrong provenance channel")


def validate_set(payload: dict) -> None:
    required = {
        "schema_version",
        "evidence_set_id",
        "result_domain",
        "engine",
        "generated_at",
        "project",
        "records",
        "summary",
        "domain_completeness",
        "boundaries",
        "execution",
        "trusted_knowledge_mutations",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise EvidenceEngineDefect(f"evidence set missing keys: {', '.join(missing)}")
    if payload["result_domain"] != RESULT_DOMAIN:
        raise EvidenceEngineDefect("evidence output must declare the project_evidence domain")
    if payload["engine"]["produces_trusted_knowledge"] is not False:
        raise EvidenceEngineDefect("project evidence is never trusted knowledge")
    for value in payload["execution"].values():
        if value is not False:
            raise EvidenceEngineDefect("the evidence engine never writes to a project")
    for count in payload["trusted_knowledge_mutations"].values():
        if count != 0:
            raise EvidenceEngineDefect("the evidence engine never mutates trusted knowledge")
    for item in payload["records"]:
        validate_record(item)


def render(payload: dict) -> str:
    lines: list[str] = []
    summary = payload["summary"]
    project = payload["project"]
    lines.append(f"PROJECT EVIDENCE {payload['evidence_set_id']}")
    lines.append(f"  result domain      {payload['result_domain']}")
    lines.append(f"  project            {project.get('project_id', '(fingerprint only)')}")
    lines.append(f"  project print      {project['project_fingerprint'][:16]}")
    lines.append(f"  revision print     {project['revision_fingerprint'][:16]}")
    lines.append("")
    lines.append("RECORDS BY DOMAIN")
    for domain in DOMAINS:
        completeness = payload["domain_completeness"][domain]
        lines.append(
            f"  {domain:<18} {summary['by_domain'][domain]:>5}  "
            f"search domain: {completeness['search_domain']}"
        )
        lines.append(f"      {completeness['basis']}")
    lines.append("")
    lines.append("RECORDS BY STATE")
    for state in STATES:
        if summary["by_state"][state]:
            lines.append(f"  {state:<26} {summary['by_state'][state]}")
    lines.append(f"  definitive observations    {summary['definitive']}")
    lines.append(f"  negative-capable records   {summary['negative_capable']}")
    lines.append("")
    lines.append("BOUNDARIES")
    lines.append(f"  {payload['boundaries']['statement']}")
    lines.append(f"  {payload['boundaries']['security_relationship']}")
    lines.append(
        f"  runtime_observed={payload['boundaries']['runtime_observed']} "
        f"php_executed={payload['boundaries']['php_executed']} "
        f"database_inspected={payload['boundaries']['database_inspected']}"
    )
    return "\n".join(lines) + "\n"


def render_records(payload: dict, domain: str | None, limit: int) -> str:
    lines: list[str] = []
    records = [
        item for item in payload["records"] if domain is None or item["domain"] == domain
    ]
    lines.append(f"RECORDS ({len(records)}{' in ' + domain if domain else ''})")
    for item in records[:limit]:
        observation = item["observation"]
        value = observation["value"]
        rendered = "" if value is None else f" = {value!r}"
        lines.append(
            f"  [{observation['state']}] {item['assertion']} {item['subject']}{rendered}"
        )
        lines.append(
            f"      quality={observation['quality']} "
            f"domain={item['completeness']['search_domain']} "
            f"definitive={observation['definitive']}"
        )
    if len(records) > limit:
        lines.append(f"  ... and {len(records) - limit} more; --format json lists every one.")
    return "\n".join(lines) + "\n"


def render_diff(payload: dict) -> str:
    lines: list[str] = []
    lines.append("PROJECT EVIDENCE DIFF")
    lines.append(f"  same project       {payload['same_project']}")
    lines.append(f"  same revision      {payload['same_revision']}")
    lines.append(
        f"  before revision    {payload['before']['revision_fingerprint'][:16]}"
    )
    lines.append(
        f"  after revision     {payload['after']['revision_fingerprint'][:16]}"
    )
    lines.append("")
    for label in ("added", "removed", "changed"):
        entries = payload[label]
        lines.append(f"{label.upper()} ({len(entries)})")
        for entry in entries[:12]:
            if label == "changed":
                lines.append(
                    f"  {entry['assertion']} {entry['subject']}: "
                    f"{entry['before']['value']!r} -> {entry['after']['value']!r}"
                )
            else:
                lines.append(f"  {entry['assertion']} {entry['subject']} [{entry['state']}]")
        if len(entries) > 12:
            lines.append(f"  ... and {len(entries) - 12} more")
    lines.append(f"UNCHANGED ({payload['unchanged_count']})")
    return "\n".join(lines) + "\n"


def validate_evidence_contract(root: Path = dk_core.ROOT) -> list[str]:
    dk_core.read_json(root / "schema" / "evidence-record.schema.json")
    dk_core.read_json(root / "schema" / "evidence-set.schema.json")
    config = dk_core.read_json(root / "config" / "project-evidence.json")
    for key in ("configuration", "settings_php", "redaction"):
        if key not in config:
            raise dk_core.ValidationError(f"project-evidence config is missing {key}")
    if not config["redaction"]["key_patterns"]:
        raise dk_core.ValidationError("project-evidence config declares no secret key patterns")
    for pattern in ("password", "secret", "token", "hash_salt"):
        if pattern not in config["redaction"]["key_patterns"]:
            raise dk_core.ValidationError(f"redaction must cover {pattern}")
    if config["settings_php"].get("semantics", "").find("never executed") == -1:
        raise dk_core.ValidationError("settings_php semantics must state PHP is not executed")
    return [
        "PROJECT_EVIDENCE_CONTRACT_VALID=PASS",
        f"PROJECT_EVIDENCE_ENGINE_VERSION={ENGINE_VERSION}",
        f"PROJECT_EVIDENCE_DOMAINS={len(DOMAINS)}",
        f"PROJECT_EVIDENCE_ASSERTIONS={len(ASSERTIONS)}",
        "PROJECT_EVIDENCE_EXCLUDES_SECRETS=PASS",
        "PROJECT_EVIDENCE_ZERO_TRUSTED_KNOWLEDGE_MUTATION=PASS",
    ]
