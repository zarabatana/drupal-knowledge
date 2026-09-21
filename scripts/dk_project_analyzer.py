#!/usr/bin/env python3
"""Read-only Drupal project profile and evidence analyzer."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

import dk_core


ANALYZER_NAME = "drupal-project-analyzer"
ANALYZER_VERSION = "0.1"
OBSERVED_AT = "deterministic-static-analysis"

HEAVY_DIRS = {".git", "vendor", "node_modules"}
CONFIG_EXCLUDED_PARTS = HEAVY_DIRS | {"core", "tests"}
CONFIG_MAX_DEPTH = 8
CUSTOM_MAX_DEPTH = 6
CUSTOM_ROOTS = (
    ("modules/custom", "module"),
    ("web/modules/custom", "module"),
    ("docroot/modules/custom", "module"),
    ("themes/custom", "theme"),
    ("web/themes/custom", "theme"),
    ("docroot/themes/custom", "theme"),
    ("profiles/custom", "profile"),
    ("web/profiles/custom", "profile"),
    ("docroot/profiles/custom", "profile"),
)
WEB_ROOT_CANDIDATES = (".", "web", "docroot", "htdocs", "public")

BASE_FACTS = (
    "drupal_core_version",
    "php_version",
    "installation_profile",
    "modules",
    "themes",
    "custom_modules",
    "custom_themes",
    "base_themes",
    "composer_packages",
    "database",
    "config_status",
    "multilingual",
    "commerce",
    "views",
    "search_api",
    "authentication",
    "file_schemes",
    "caching_layers",
    "deployment_model",
    "environment_type",
    "custom_code_files",
    "configuration_objects",
    "settings_declarations",
)
ANALYZER_FACTS = BASE_FACTS + ("project_type", "drupal_web_root")

# The custom-code scan is bounded by a declared configuration rather than by
# constants in here, so what was and was not read is auditable from the
# repository instead of from this file.
CUSTOM_CODE_SCAN_CONFIG = Path("config") / "custom-code-scan.json"

# What the evidence layer may observe, redact and refuse to read. Declared in
# the repository so an evidence set can be audited against the rules that made
# it, rather than against constants buried here.
PROJECT_EVIDENCE_CONFIG = Path("config") / "project-evidence.json"


class AnalyzerInputError(RuntimeError):
    """Raised when the caller gives an unusable analyzer input path."""


class SafeYamlError(RuntimeError):
    """Raised when the local safe YAML subset cannot parse a file."""


@dataclass(frozen=True)
class AnalysisResult:
    """Analyzer output plus CLI exit semantics."""

    data: dict[str, Any]
    exit_code: int


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def file_sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def slug(value: str) -> str:
    chars = [char if char.isalnum() else "-" for char in value.lower()]
    collapsed = "-".join(part for part in "".join(chars).split("-") if part)
    return collapsed or "root"


def portable_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    text = relative.as_posix()
    return text or "."


def fact(
    state: str,
    value: Any | None = None,
    evidence_ids: list[str] | None = None,
    confidence: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"state": state}
    if state == "known" and value is not None:
        result["value"] = value
    if evidence_ids:
        result["source_evidence_ids"] = sorted(set(evidence_ids))
    if confidence:
        result["confidence"] = confidence
    if notes:
        result["notes"] = notes
    return result


def known(
    value: Any,
    evidence_ids: list[str] | None = None,
    confidence: str = "high",
    notes: str | None = None,
) -> dict[str, Any]:
    return fact("known", value, evidence_ids, confidence, notes)


def unknown(notes: str, evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return fact("unknown", evidence_ids=evidence_ids, notes=notes)


def diagnostic(
    code: str,
    severity: str,
    message: str,
    path: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "code": code,
        "severity": severity,
        "message": message,
    }
    if path is not None:
        item["path"] = path
    if details:
        item["details"] = details
    return item


def sort_diagnostics(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            item.get("severity", ""),
            item.get("code", ""),
            item.get("path", ""),
            item.get("message", ""),
            json.dumps(item.get("details", {}), sort_keys=True),
        ),
    )


def make_file_evidence(
    root: Path,
    path: Path,
    project_id: str,
    kind: str,
    role: str,
    facts_supported: list[str],
    summary: str,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    raw = path.read_bytes()
    relative = portable_path(root, path)
    return {
        "schema_version": "0.1",
        "id": f"evidence.drupal.{slug(role)}.{slug(relative)}",
        "project_id": project_id,
        "kind": kind,
        "observed_at": OBSERVED_AT,
        "collector": ANALYZER_NAME,
        "path": relative,
        "content_sha256": file_sha256(raw),
        "bytes": len(raw),
        "role": role,
        "facts_supported": sorted(facts_supported),
        "summary": summary,
        "limitations": sorted(limitations or []),
    }


def quote_can_start(text: str, index: int) -> bool:
    if index == 0:
        return True
    previous = text[index - 1]
    return previous.isspace() or previous in ":,[{"


def skip_yaml_quoted(text: str, index: int, path: str, line_number: int) -> int:
    quote = text[index]
    index += 1
    while index < len(text):
        char = text[index]
        if quote == "'" and char == "'":
            if index + 1 < len(text) and text[index + 1] == "'":
                index += 2
                continue
            return index + 1
        if quote == '"' and char == "\\":
            index += 2
            continue
        if quote == '"' and char == '"':
            return index + 1
        index += 1
    raise SafeYamlError(f"{path}:{line_number}: unterminated quoted scalar")


def strip_yaml_comment(line: str, path: str, line_number: int) -> str:
    index = 0
    while index < len(line):
        char = line[index]
        if char in {"'", '"'} and quote_can_start(line, index):
            index = skip_yaml_quoted(line, index, path, line_number)
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
        index += 1
    return line


def yaml_tokens(text: str, path: str) -> list[tuple[int, str, int]]:
    tokens: list[tuple[int, str, int]] = []
    for line_number, original in enumerate(text.splitlines(), start=1):
        if "\t" in original:
            raise SafeYamlError(f"{path}:{line_number}: tabs are not supported")
        stripped_comment = strip_yaml_comment(original, path, line_number).rstrip()
        if not stripped_comment.strip():
            continue
        indent = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        text = stripped_comment.strip()
        if text in {"---", "..."}:
            raise SafeYamlError(f"{path}:{line_number}: document markers are not supported")
        tokens.append((indent, text, line_number))
    return tokens


def decode_single_quoted_scalar(value: str, path: str, line_number: int) -> str:
    if not (value.startswith("'") and value.endswith("'")):
        raise SafeYamlError(f"{path}:{line_number}: invalid single-quoted scalar")
    result = []
    index = 1
    while index < len(value) - 1:
        char = value[index]
        if char == "'":
            if index + 1 < len(value) - 1 and value[index + 1] == "'":
                result.append("'")
                index += 2
                continue
            raise SafeYamlError(f"{path}:{line_number}: invalid single quote in scalar")
        result.append(char)
        index += 1
    return "".join(result)


def decode_double_quoted_scalar(value: str, path: str, line_number: int) -> str:
    if not (value.startswith('"') and value.endswith('"')):
        raise SafeYamlError(f"{path}:{line_number}: invalid double-quoted scalar")
    escapes = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }
    result = []
    index = 1
    while index < len(value) - 1:
        char = value[index]
        if char == "\\":
            index += 1
            if index >= len(value) - 1 or value[index] not in escapes:
                raise SafeYamlError(f"{path}:{line_number}: unsupported double-quoted escape")
            result.append(escapes[value[index]])
        else:
            result.append(char)
        index += 1
    return "".join(result)


def parse_yaml_scalar(value: str, path: str, line_number: int) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value.startswith("'"):
        return decode_single_quoted_scalar(value, path, line_number)
    if value.startswith('"'):
        return decode_double_quoted_scalar(value, path, line_number)
    if value.startswith(("&", "*", "!")):
        raise SafeYamlError(f"{path}:{line_number}: anchors, aliases, and tags are not supported")
    if value.startswith(("|", ">")):
        raise SafeYamlError(f"{path}:{line_number}: multiline scalars are not supported")
    if value in {"{}", "[]"}:
        return {} if value == "{}" else []
    if value.startswith(("{", "[")) or value.endswith(("}", "]")):
        raise SafeYamlError(f"{path}:{line_number}: non-empty flow collections are not supported")
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "~"}:
        return None
    try:
        return int(value)
    except ValueError:
        return value


def find_yaml_mapping_separator(text: str, path: str, line_number: int) -> int:
    index = 0
    while index < len(text):
        char = text[index]
        if char in {"'", '"'} and quote_can_start(text, index):
            index = skip_yaml_quoted(text, index, path, line_number)
            continue
        if char == ":" and (index + 1 == len(text) or text[index + 1].isspace()):
            return index
        index += 1
    return -1


def parse_yaml_key(value: str, path: str, line_number: int) -> str:
    key = value.strip()
    if not key:
        raise SafeYamlError(f"{path}:{line_number}: empty mapping key")
    parsed = parse_yaml_scalar(key, path, line_number)
    if not isinstance(parsed, str) or parsed == "":
        raise SafeYamlError(f"{path}:{line_number}: mapping key must be a string")
    if parsed.startswith(("?", "-", "&", "*", "!")):
        raise SafeYamlError(f"{path}:{line_number}: complex mapping keys are not supported")
    return parsed


def split_yaml_key_value(text: str, path: str, line_number: int) -> tuple[str, str]:
    separator = find_yaml_mapping_separator(text, path, line_number)
    if separator == -1:
        raise SafeYamlError(f"{path}:{line_number}: expected key/value mapping")
    key = parse_yaml_key(text[:separator], path, line_number)
    return key, text[separator + 1 :].strip()


def parse_yaml_block(
    tokens: list[tuple[int, str, int]],
    index: int,
    indent: int,
    path: str,
) -> tuple[Any, int]:
    if index >= len(tokens):
        return {}, index
    current_indent, text, line_number = tokens[index]
    if current_indent != indent:
        raise SafeYamlError(
            f"{path}:{line_number}: unexpected indentation {current_indent}, expected {indent}"
        )
    if text.startswith("- "):
        return parse_yaml_list(tokens, index, indent, path)
    return parse_yaml_mapping(tokens, index, indent, path)


def parse_yaml_mapping(
    tokens: list[tuple[int, str, int]],
    index: int,
    indent: int,
    path: str,
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(tokens):
        current_indent, text, line_number = tokens[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise SafeYamlError(f"{path}:{line_number}: unexpected nested indentation")
        if text.startswith("- "):
            raise SafeYamlError(f"{path}:{line_number}: sequence item in mapping")
        key, value = split_yaml_key_value(text, path, line_number)
        if key in result:
            raise SafeYamlError(f"{path}:{line_number}: duplicate mapping key {key!r}")
        if value:
            result[key] = parse_yaml_scalar(value, path, line_number)
            index += 1
            if index < len(tokens) and tokens[index][0] > current_indent:
                raise SafeYamlError(
                    f"{path}:{tokens[index][2]}: nested block after scalar value"
                )
            continue
        index += 1
        if index < len(tokens) and tokens[index][0] > current_indent:
            result[key], index = parse_yaml_block(tokens, index, tokens[index][0], path)
        else:
            result[key] = None
    return result, index


def parse_yaml_list(
    tokens: list[tuple[int, str, int]],
    index: int,
    indent: int,
    path: str,
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(tokens):
        current_indent, text, line_number = tokens[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise SafeYamlError(f"{path}:{line_number}: unexpected nested indentation")
        if not text.startswith("- "):
            break
        item = text[2:].strip()
        index += 1
        if not item:
            if index >= len(tokens) or tokens[index][0] <= current_indent:
                result.append(None)
                continue
            child, index = parse_yaml_block(tokens, index, tokens[index][0], path)
            result.append(child)
            continue
        if find_yaml_mapping_separator(item, path, line_number) != -1:
            raise SafeYamlError(f"{path}:{line_number}: inline sequence mappings are not supported")
        result.append(parse_yaml_scalar(item, path, line_number))
        if index < len(tokens) and tokens[index][0] > current_indent:
            raise SafeYamlError(
                f"{path}:{tokens[index][2]}: nested block after scalar sequence item"
            )
    return result, index


def safe_yaml_load(text: str, path: str) -> Any:
    tokens = yaml_tokens(text, path)
    if not tokens:
        return {}
    data, index = parse_yaml_block(tokens, 0, tokens[0][0], path)
    if index != len(tokens):
        _, _, line_number = tokens[index]
        raise SafeYamlError(f"{path}:{line_number}: trailing unparsable YAML")
    return data


def load_json_file(
    root: Path,
    path: Path,
    diagnostics: list[dict[str, Any]],
    invalid_code: str,
    missing_code: str,
) -> tuple[dict[str, Any] | None, str]:
    relative = portable_path(root, path)
    if not path.is_file():
        diagnostics.append(
            diagnostic(missing_code, "info", f"{relative} is not present.", relative)
        )
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "available"
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        diagnostics.append(
            diagnostic(
                invalid_code,
                "error",
                f"{relative} is malformed and cannot be trusted.",
                relative,
                {"error": exc.__class__.__name__},
            )
        )
        return None, "invalid"


def declared_drupal_dependencies(require: dict[str, Any], require_dev: dict[str, Any]) -> list[str]:
    names = []
    for dependency_name in list(require) + list(require_dev):
        if dependency_name == "drupal/core" or dependency_name.startswith("drupal/"):
            names.append(dependency_name)
    return sorted(set(names))


def composer_scaffold_web_root(composer_json: dict[str, Any] | None) -> str | None:
    if not isinstance(composer_json, dict):
        return None
    extra = composer_json.get("extra")
    if not isinstance(extra, dict):
        return None
    scaffold = extra.get("drupal-scaffold")
    if not isinstance(scaffold, dict):
        return None
    locations = scaffold.get("locations")
    if not isinstance(locations, dict):
        return None
    web_root = locations.get("web-root")
    if not isinstance(web_root, str) or not web_root.strip():
        return None
    normalized = web_root.strip().rstrip("/")
    return normalized or "."


def safe_declared_relative_path(value: str) -> str | None:
    path = Path(value)
    if path.is_absolute():
        return None
    if ".." in path.parts:
        return None
    return path.as_posix() or "."


def extract_composer_declaration(composer_json: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(composer_json, dict):
        return None
    require = composer_json.get("require", {})
    require_dev = composer_json.get("require-dev", {})
    if not isinstance(require, dict):
        require = {}
    if not isinstance(require_dev, dict):
        require_dev = {}
    declaration = {
        "name": composer_json.get("name") if isinstance(composer_json.get("name"), str) else None,
        "type": composer_json.get("type") if isinstance(composer_json.get("type"), str) else None,
        "require": {key: require[key] for key in sorted(require)},
        "require_dev": {key: require_dev[key] for key in sorted(require_dev)},
        "php_requirement": require.get("php") if isinstance(require.get("php"), str) else None,
        "drupal_declared_dependencies": declared_drupal_dependencies(require, require_dev),
        "drupal_scaffold_web_root": composer_scaffold_web_root(composer_json),
    }
    config = composer_json.get("config")
    platform_php = None
    if isinstance(config, dict):
        platform = config.get("platform")
        if isinstance(platform, dict) and isinstance(platform.get("php"), str):
            platform_php = platform["php"]
    declaration["composer_platform_php"] = platform_php
    return declaration


def extract_installed_packages(lock_data: dict[str, Any] | None) -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(lock_data, dict):
        return [], False
    packages: list[dict[str, Any]] = []
    for key, is_dev in (("packages", False), ("packages-dev", True)):
        items = lock_data.get(key, [])
        if not isinstance(items, list):
            return [], False
        for item in items:
            if not isinstance(item, dict):
                return [], False
            name = item.get("name")
            version = item.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                return [], False
            package_type = item.get("type") if isinstance(item.get("type"), str) else "unknown"
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "type": package_type,
                    "dev": is_dev,
                }
            )
    return sorted(packages, key=lambda item: (item["name"], item["version"], item["dev"])), True


def drupal_ecosystem_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        package
        for package in packages
        if package["name"].startswith("drupal/") or package["type"].startswith("drupal-")
    ]


def package_by_name(packages: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    matches = [package for package in packages if package["name"] == name]
    if len(matches) == 1:
        return matches[0]
    return None


def resolve_core_version(
    packages: list[dict[str, Any]],
    lock_status: str,
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    if lock_status != "available":
        return unknown("Installed Drupal core version is unknown because composer.lock is unavailable.")
    core = package_by_name(packages, "drupal/core")
    recommended = package_by_name(packages, "drupal/core-recommended")
    evidence = ["evidence.drupal.composer-lock.composer-lock"]
    if core and recommended and core["version"] != recommended["version"]:
        diagnostics.append(
            diagnostic(
                "DRUPAL_CORE_VERSION_CONFLICT",
                "error",
                "Installed drupal/core and drupal/core-recommended versions conflict.",
                "composer.lock",
                {
                    "drupal/core": core["version"],
                    "drupal/core-recommended": recommended["version"],
                },
            )
        )
        return unknown("Conflicting installed Drupal core package evidence.", evidence)
    if core:
        value = {"package": "drupal/core", "version": core["version"]}
        if recommended:
            value["corroborated_by"] = {
                "package": "drupal/core-recommended",
                "version": recommended["version"],
            }
        return known(
            value,
            evidence,
            notes="Derived from installed Composer package evidence only.",
        )
    if recommended:
        diagnostics.append(
            diagnostic(
                "DRUPAL_CORE_PACKAGE_NOT_INSTALLED",
                "warning",
                "drupal/core-recommended is installed but drupal/core is absent; core version is not inferred.",
                "composer.lock",
            )
        )
    return unknown("No installed drupal/core package evidence was found.", evidence)


def should_exclude_config_candidate(relative: Path) -> bool:
    parts = relative.parts
    if any(part in CONFIG_EXCLUDED_PARTS for part in parts):
        return True
    paired_exclusions = {("modules", "contrib"), ("themes", "contrib"), ("profiles", "contrib")}
    return any(pair[0] in parts and pair[1] in parts for pair in paired_exclusions)


def find_core_extension_candidates(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        relative = current_path.relative_to(root)
        if len(relative.parts) > CONFIG_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory not in HEAVY_DIRS and directory != "core"
        )
        if "core.extension.yml" not in files:
            continue
        config_path = current_path / "core.extension.yml"
        if should_exclude_config_candidate(config_path.relative_to(root)):
            continue
        candidates.append(config_path.parent)
    return sorted(candidates, key=lambda path: portable_path(root, path))


def resolve_config_dir(root: Path, config_dir: str | None) -> Path | None:
    if config_dir is None:
        return None
    candidate = Path(config_dir)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise AnalyzerInputError("--config-dir must be inside the analyzed project") from exc
    if not resolved_candidate.is_dir():
        raise AnalyzerInputError("--config-dir must point to an existing directory")
    return candidate


def count_config_yaml_files(config_root: Path) -> tuple[int, list[str]]:
    paths = sorted(path for path in config_root.rglob("*.yml") if path.is_file())
    families = set()
    prefixes = {
        "language.": "language",
        "commerce_": "commerce",
        "views.view.": "views",
        "search_api.": "search_api",
        "user.role.": "user_roles",
        "system.site": "system_site",
    }
    for path in paths:
        name = path.name
        for prefix, family in prefixes.items():
            if name.startswith(prefix):
                families.add(family)
    return len(paths), sorted(families)


def parse_core_extension(
    root: Path,
    config_root: Path,
    project_id: str,
    evidence: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, str, str | None]:
    core_extension = config_root / "core.extension.yml"
    relative = portable_path(root, core_extension)
    if not core_extension.is_file():
        diagnostics.append(
            diagnostic(
                "CORE_EXTENSION_MISSING",
                "warning",
                "Selected config root does not contain core.extension.yml.",
                portable_path(root, config_root),
            )
        )
        return None, "unavailable", None
    item = make_file_evidence(
        root,
        core_extension,
        project_id,
        "core_extension_config",
        "core-extension-config",
        ["modules", "themes", "installation_profile", "config_status"],
        "Parsed exported Drupal core.extension.yml for enabled extension evidence.",
        ["Exported configuration does not prove current runtime state."],
    )
    evidence.append(item)
    try:
        parsed = safe_yaml_load(core_extension.read_text(encoding="utf-8"), relative)
    except (UnicodeDecodeError, SafeYamlError) as exc:
        diagnostics.append(
            diagnostic(
                "CORE_EXTENSION_YAML_INVALID",
                "error",
                "core.extension.yml is malformed and enabled extension evidence cannot be trusted.",
                relative,
                {"error": exc.__class__.__name__},
            )
        )
        return None, "invalid", item["id"]
    if not isinstance(parsed, dict):
        diagnostics.append(
            diagnostic(
                "CORE_EXTENSION_YAML_INVALID",
                "error",
                "core.extension.yml did not parse to a mapping.",
                relative,
            )
        )
        return None, "invalid", item["id"]
    return parsed, "available", item["id"]


def discover_config(
    root: Path,
    config_dir: str | None,
    project_id: str,
    evidence: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    explicit = resolve_config_dir(root, config_dir)
    if explicit is not None:
        selected = explicit
        candidates = [selected]
        method = "explicit"
    else:
        candidates = find_core_extension_candidates(root)
        method = "auto"
        if len(candidates) > 1:
            diagnostics.append(
                diagnostic(
                    "CONFIG_ROOT_AMBIGUOUS",
                    "warning",
                    "Multiple plausible exported Drupal config roots were found; none was selected.",
                    details={"candidates": [portable_path(root, candidate) for candidate in candidates]},
                )
            )
            return {
                "status": "ambiguous",
                "method": method,
                "candidates": [portable_path(root, candidate) for candidate in candidates],
                "root": None,
                "data": None,
                "evidence_id": None,
                "yaml_file_count": 0,
                "families": [],
            }
        if not candidates:
            diagnostics.append(
                diagnostic(
                    "CONFIG_ROOT_NOT_FOUND",
                    "info",
                    "No exported Drupal config root with core.extension.yml was found.",
                )
            )
            return {
                "status": "unavailable",
                "method": method,
                "candidates": [],
                "root": None,
                "data": None,
                "evidence_id": None,
                "yaml_file_count": 0,
                "families": [],
            }
        selected = candidates[0]
    data, status, evidence_id = parse_core_extension(
        root,
        selected,
        project_id,
        evidence,
        diagnostics,
    )
    yaml_count, families = count_config_yaml_files(selected) if selected.is_dir() else (0, [])
    return {
        "status": status,
        "method": method,
        "candidates": [portable_path(root, candidate) for candidate in candidates],
        "root": portable_path(root, selected),
        "data": data,
        "evidence_id": evidence_id,
        "yaml_file_count": yaml_count,
        "families": families,
    }


def enabled_extensions_from_config(config: dict[str, Any] | None) -> tuple[list[str], list[str], str | None]:
    if not isinstance(config, dict):
        return [], [], None
    modules_data = config.get("module", {})
    themes_data = config.get("theme", {})
    modules = sorted(modules_data) if isinstance(modules_data, dict) else []
    themes = sorted(themes_data) if isinstance(themes_data, dict) else []
    profile = config.get("profile") if isinstance(config.get("profile"), str) else None
    return modules, themes, profile


def walk_info_files(root: Path, base: Path) -> list[Path]:
    found: list[Path] = []
    for current, dirs, files in os.walk(base):
        current_path = Path(current)
        relative_to_base = current_path.relative_to(base)
        if len(relative_to_base.parts) > CUSTOM_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = sorted(directory for directory in dirs if directory not in HEAVY_DIRS)
        for filename in sorted(files):
            if filename.endswith(".info.yml"):
                found.append(current_path / filename)
    return found


def machine_name_from_info_path(path: Path) -> str:
    name = path.name
    return name[: -len(".info.yml")]


def scan_custom_extensions(
    root: Path,
    project_id: str,
    evidence: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    inventory = {"module": [], "theme": [], "profile": []}
    for root_text, expected_type in CUSTOM_ROOTS:
        base = root / root_text
        if not base.is_dir():
            continue
        for info_path in walk_info_files(root, base):
            relative = portable_path(root, info_path)
            item = make_file_evidence(
                root,
                info_path,
                project_id,
                "custom_extension_info",
                "custom-extension-definition",
                ["custom_modules", "custom_themes", "base_themes"],
                "Parsed Drupal custom extension .info.yml metadata.",
                ["Presence in the source tree does not prove the extension is enabled."],
            )
            evidence.append(item)
            try:
                data = safe_yaml_load(info_path.read_text(encoding="utf-8"), relative)
            except (UnicodeDecodeError, SafeYamlError) as exc:
                diagnostics.append(
                    diagnostic(
                        "CUSTOM_EXTENSION_INFO_YAML_INVALID",
                        "warning",
                        "Custom extension .info.yml could not be parsed.",
                        relative,
                        {"error": exc.__class__.__name__},
                    )
                )
                continue
            if not isinstance(data, dict):
                diagnostics.append(
                    diagnostic(
                        "CUSTOM_EXTENSION_INFO_YAML_INVALID",
                        "warning",
                        "Custom extension .info.yml did not parse to a mapping.",
                        relative,
                    )
                )
                continue
            extension_type = data.get("type") if isinstance(data.get("type"), str) else expected_type
            if extension_type not in inventory:
                extension_type = expected_type
            record = {
                "machine_name": machine_name_from_info_path(info_path),
                "name": data.get("name") if isinstance(data.get("name"), str) else None,
                "type": extension_type,
                "path": relative,
                "core_version_requirement": (
                    data.get("core_version_requirement")
                    if isinstance(data.get("core_version_requirement"), str)
                    else None
                ),
                "enabled": "unknown",
                "evidence_id": item["id"],
            }
            if extension_type == "theme" and isinstance(data.get("base theme"), str):
                record["base_theme"] = data["base theme"]
            inventory[extension_type].append(record)
    for key in inventory:
        inventory[key] = sorted(inventory[key], key=lambda item: (item["machine_name"], item["path"]))
    return inventory


def load_scan_config(config_root: Path) -> dict[str, Any]:
    """The declared bounds of the custom-code scan, with its own digest."""
    path = config_root / CUSTOM_CODE_SCAN_CONFIG
    raw = path.read_bytes()
    config = json.loads(raw.decode("utf-8"))
    config["config_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return config


def scan_custom_code_files(
    root: Path,
    config: dict[str, Any],
    custom_extensions: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """A deterministic inventory of project-owned custom source files.

    This is an inventory, not an interpretation: it records which files exist,
    how big they are and what they hash to. It reads no PHP semantics and makes
    no compatibility claim. Files it declines to read are listed with the reason,
    because a file that was never opened cannot support any conclusion about it.
    """
    excluded_dirs = set(config["excluded_directories"])
    excluded_names = set(config["excluded_file_names"])
    languages = {
        suffix: language
        for language, suffixes in config["included_extensions"].items()
        for suffix in suffixes
    }
    limits = config["limits"]

    # Every custom extension root, so a file can be attributed to the component
    # that owns it rather than to a bare path.
    components: list[tuple[str, str, str]] = []
    for extension_type in ("module", "theme", "profile"):
        for extension in custom_extensions[extension_type]:
            directory = str(Path(extension["path"]).parent.as_posix())
            components.append((directory, extension["machine_name"], extension_type))
    components.sort(key=lambda item: (-len(item[0]), item[0]))

    def owner(relative: str) -> tuple[str | None, str | None]:
        for directory, machine_name, extension_type in components:
            if relative == directory or relative.startswith(directory + "/"):
                return machine_name, extension_type
        return None, None

    files: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    truncated = False

    for root_text in config["scope"]["roots"]:
        base = root / root_text
        if not base.is_dir():
            continue
        for current, dirs, names in os.walk(base):
            current_path = Path(current)
            depth = len(current_path.relative_to(base).parts)
            if depth > limits["max_depth"]:
                dirs[:] = []
                skipped.append(
                    {"path": portable_path(root, current_path), "reason": "exceeds_max_depth"}
                )
                continue
            dirs[:] = sorted(name for name in dirs if name not in excluded_dirs)
            for name in sorted(names):
                if name in excluded_names:
                    continue
                suffix = Path(name).suffix
                language = languages.get(suffix)
                if language is None:
                    continue
                path = current_path / name
                relative = portable_path(root, path)
                if len(files) >= limits["max_files"]:
                    truncated = True
                    skipped.append({"path": relative, "reason": "exceeds_max_files"})
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    skipped.append({"path": relative, "reason": "unreadable"})
                    continue
                if size > limits["max_file_bytes"]:
                    skipped.append({"path": relative, "reason": "exceeds_max_file_bytes"})
                    continue
                try:
                    data = path.read_bytes()
                except OSError:
                    skipped.append({"path": relative, "reason": "unreadable"})
                    continue
                machine_name, extension_type = owner(relative)
                files.append(
                    {
                        "path": relative,
                        "language": language,
                        "component": machine_name,
                        "component_type": extension_type,
                        "bytes": size,
                        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                    }
                )

    files.sort(key=lambda item: item["path"])
    skipped.sort(key=lambda item: (item["path"], item["reason"]))
    counts: dict[str, int] = {}
    for item in files:
        counts[item["language"]] = counts.get(item["language"], 0) + 1

    return {
        "scan": {
            "config_id": config["config_id"],
            "config_digest": config["config_digest"],
            "roots": list(config["scope"]["roots"]),
            "excluded_directories": sorted(excluded_dirs),
            "included_extensions": {
                language: sorted(suffixes)
                for language, suffixes in config["included_extensions"].items()
            },
            "limits": dict(limits),
            "truncated": truncated,
            # Contributed and vendored source is deliberately not walked.
            "scope": "project_owned_custom_code_only",
        },
        "files": files,
        "skipped": skipped,
        "counts": {
            "files": len(files),
            "skipped": len(skipped),
            "by_language": dict(sorted(counts.items())),
            "components": len({item["component"] for item in files if item["component"]}),
        },
    }


def load_evidence_config(config_root: Path) -> dict[str, Any]:
    """Declared bounds of project-evidence observation, with its own digest."""
    path = config_root / PROJECT_EVIDENCE_CONFIG
    raw = path.read_bytes()
    config = json.loads(raw.decode("utf-8"))
    config["config_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return config


def redaction_rules(config: dict[str, Any]) -> tuple[tuple[str, ...], tuple[Any, ...]]:
    redaction = config["redaction"]
    return (
        tuple(str(item).lower() for item in redaction["key_patterns"]),
        tuple(re.compile(pattern) for pattern in redaction["forbidden_value_patterns"]),
    )


def is_secret_key(key: str, key_patterns: tuple[str, ...]) -> bool:
    lowered = key.lower()
    return any(pattern in lowered for pattern in key_patterns)


def value_is_forbidden(value: Any, value_patterns: tuple[Any, ...]) -> bool:
    if not isinstance(value, str):
        return False
    return any(pattern.search(value) for pattern in value_patterns)


def flatten_config(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Every scalar leaf of a parsed config object, as dotted key paths."""
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            found.extend(flatten_config(item, child))
    elif isinstance(value, list):
        found.append((prefix, value))
    else:
        found.append((prefix, value))
    return found


def read_config_key(data: Any, key_path: str) -> tuple[bool, Any]:
    current = data
    for part in key_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def scan_configuration_objects(
    root: Path,
    config: dict[str, Any],
    config_state: dict[str, Any],
) -> dict[str, Any]:
    """Exported Drupal configuration observed from the repository.

    Two different things are recorded, and the difference matters. The set of
    config objects in the selected root is a *complete* enumeration of that
    root. The values read out of them are *bounded* by the declared key list,
    so a key nobody declared is simply not observed and its absence says
    nothing about the project.

    Nothing here is a claim about runtime. Exported configuration is what the
    repository holds; settings.php overrides and environment configuration can
    change it, and this analyzer cannot see either.
    """
    declared = config["configuration"]
    key_patterns, value_patterns = redaction_rules(config)
    excluded_keys = set(declared["excluded_keys"]["entries"])
    observed_keys = {
        entry["object"]: list(entry["keys"]) for entry in declared["observed_keys"]["entries"]
    }

    if config_state.get("status") not in {"available", "invalid"} or not config_state.get("root"):
        return {
            "scan": {
                "config_id": config["config_id"],
                "config_digest": config["config_digest"],
                "config_root": config_state.get("root"),
                "root_selection": config_state.get("status"),
                "object_enumeration": "unavailable",
                "value_observation": "declared_keys_only",
                "declared_objects": sorted(observed_keys),
                "excluded_keys": sorted(excluded_keys),
            },
            "objects": [],
            "values": [],
            "redacted": [],
            "unreadable": [],
            "dependencies": [],
            "counts": {
                "objects": 0,
                "values": 0,
                "redacted": 0,
                "unreadable": 0,
                "dependencies": 0,
            },
        }

    config_root = root / config_state["root"]
    objects: list[dict[str, Any]] = []
    values: list[dict[str, Any]] = []
    redacted: list[dict[str, str]] = []
    unreadable: list[dict[str, str]] = []
    dependencies: list[dict[str, Any]] = []

    for path in sorted(config_root.glob("*.yml")):
        if not path.is_file():
            continue
        relative = portable_path(root, path)
        name = path.name[: -len(".yml")]
        data = path.read_bytes()
        objects.append(
            {
                "config_name": name,
                "path": relative,
                "bytes": len(data),
                "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            }
        )
        wanted = observed_keys.get(name)
        try:
            parsed = safe_yaml_load(data.decode("utf-8"), relative)
        except (UnicodeDecodeError, SafeYamlError) as exc:
            unreadable.append(
                {
                    "config_name": name,
                    "path": relative,
                    "reason": exc.__class__.__name__,
                }
            )
            continue

        # A config object names the modules it depends on. Reading this for
        # every parseable object is what lets a later rule notice that exported
        # configuration depends on something the same export does not enable.
        declared_modules = ((parsed.get("dependencies") or {}) if isinstance(parsed, dict) else {})
        modules = declared_modules.get("module") if isinstance(declared_modules, dict) else None
        if isinstance(modules, list):
            named = sorted({item for item in modules if isinstance(item, str) and item})
            if named:
                dependencies.append(
                    {"config_name": name, "path": relative, "modules": named}
                )

        if not wanted:
            continue
        for key in wanted:
            if key in excluded_keys or is_secret_key(key, key_patterns):
                redacted.append({"config_name": name, "key": key, "reason": "declared_secret_key"})
                continue
            present, value = read_config_key(parsed, key)
            if not present:
                values.append(
                    {
                        "config_name": name,
                        "key": key,
                        "path": relative,
                        "state": "absent_from_object",
                        "value": None,
                    }
                )
                continue
            if value_is_forbidden(value, value_patterns):
                redacted.append({"config_name": name, "key": key, "reason": "forbidden_value"})
                continue
            if isinstance(value, (dict, list)):
                values.append(
                    {
                        "config_name": name,
                        "key": key,
                        "path": relative,
                        "state": "unsupported_value_type",
                        "value": None,
                    }
                )
                continue
            values.append(
                {
                    "config_name": name,
                    "key": key,
                    "path": relative,
                    "state": "present",
                    "value": value,
                }
            )

    objects.sort(key=lambda item: item["config_name"])
    values.sort(key=lambda item: (item["config_name"], item["key"]))
    redacted.sort(key=lambda item: (item["config_name"], item["key"]))
    unreadable.sort(key=lambda item: item["config_name"])
    dependencies.sort(key=lambda item: item["config_name"])
    return {
        "scan": {
            "config_id": config["config_id"],
            "config_digest": config["config_digest"],
            "config_root": config_state["root"],
            "root_selection": config_state["status"],
            # The object list is every .yml directly in the selected root.
            "object_enumeration": "complete_for_selected_config_root",
            "value_observation": "declared_keys_only",
            "declared_objects": sorted(observed_keys),
            "excluded_keys": sorted(excluded_keys),
        },
        "objects": objects,
        "values": values,
        "redacted": redacted,
        "unreadable": unreadable,
        "dependencies": dependencies,
        "counts": {
            "objects": len(objects),
            "values": len(values),
            "redacted": len(redacted),
            "unreadable": len(unreadable),
            "dependencies": len(dependencies),
        },
    }


SETTINGS_ASSIGNMENT_STATES = ("present", "unsupported_value_type", "redacted")


def scan_settings_declarations(
    root: Path,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Declared ``$settings[...]`` values, read without executing any PHP.

    settings.php is lexed, not run. Only an assignment whose value is a single
    scalar literal is recorded; anything needing evaluation is marked
    unsupported rather than guessed. Any key or value the redaction rules match
    is dropped before a record exists, so a database password or a hash salt
    cannot reach an evidence set even as a diagnostic.
    """
    import dk_php_lexer as lexer

    declared = config["settings_php"]
    key_patterns, value_patterns = redaction_rules(config)
    wanted = set(declared["observed_keys"])

    files: list[str] = []
    entries: list[dict[str, Any]] = []
    redacted: list[dict[str, str]] = []

    for candidate in declared["files"]:
        path = root / candidate
        if not path.is_file():
            continue
        relative = portable_path(root, path)
        files.append(relative)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        tokens = lexer.code_tokens(lexer.tokenize(source))
        for index, token in enumerate(tokens):
            if token.type != lexer.T_VARIABLE or token.value != "$settings":
                continue
            window = tokens[index : index + 6]
            if len(window) < 6:
                continue
            if not (
                window[1].type == lexer.T_OPERATOR
                and window[1].value == "["
                and window[2].type == lexer.T_STRING_LITERAL
                and window[3].type == lexer.T_OPERATOR
                and window[3].value == "]"
                and window[4].type == lexer.T_OPERATOR
                and window[4].value == "="
            ):
                continue
            key = window[2].value[1:-1]
            if is_secret_key(key, key_patterns):
                # Checked before the declared-key filter: a secret must be seen
                # and refused, not merely left unobserved by accident.
                redacted.append({"key": key, "path": relative, "reason": "declared_secret_key"})
                continue
            if key not in wanted:
                continue
            literal = window[5]
            terminator = tokens[index + 6] if index + 6 < len(tokens) else None
            scalar_ends_statement = (
                terminator is not None
                and terminator.type == lexer.T_OPERATOR
                and terminator.value == ";"
            )
            if not scalar_ends_statement:
                entries.append(
                    {
                        "key": key,
                        "path": relative,
                        "line": literal.line,
                        "state": "unsupported_value_type",
                        "value": None,
                    }
                )
                continue
            if literal.type == lexer.T_STRING_LITERAL:
                value: Any = literal.value[1:-1]
            elif literal.type == lexer.T_NUMBER:
                value = int(literal.value) if literal.value.isdigit() else literal.value
            elif literal.type == lexer.T_IDENT and literal.value.upper() in ("TRUE", "FALSE", "NULL"):
                value = {"TRUE": True, "FALSE": False, "NULL": None}[literal.value.upper()]
            else:
                entries.append(
                    {
                        "key": key,
                        "path": relative,
                        "line": literal.line,
                        "state": "unsupported_value_type",
                        "value": None,
                    }
                )
                continue
            if value_is_forbidden(value, value_patterns):
                redacted.append({"key": key, "path": relative, "reason": "forbidden_value"})
                continue
            entries.append(
                {
                    "key": key,
                    "path": relative,
                    "line": literal.line,
                    "state": "present",
                    "value": value,
                }
            )

    entries.sort(key=lambda item: (item["path"], item["key"], item["line"]))
    redacted.sort(key=lambda item: (item["path"], item["key"]))
    return {
        "scan": {
            "config_id": config["config_id"],
            "config_digest": config["config_digest"],
            "method": "php_lexer_scalar_assignment",
            "php_executed": False,
            # Only declared keys are looked for, so a key absent from this list
            # is unobserved rather than unset.
            "value_observation": "declared_keys_only",
            "declared_keys": sorted(wanted),
            "files_considered": list(declared["files"]),
        },
        "files_read": sorted(files),
        "entries": entries,
        "redacted": redacted,
        "counts": {
            "files_read": len(files),
            "entries": len(entries),
            "redacted": len(redacted),
        },
    }


def find_web_root_layouts(
    root: Path,
    project_id: str,
    evidence: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen_evidence_paths: set[str] = set()
    for candidate in WEB_ROOT_CANDIDATES:
        base = root if candidate == "." else root / candidate
        marker = base / "core" / "lib" / "Drupal.php"
        if not marker.is_file():
            continue
        relative_marker = portable_path(root, marker)
        if relative_marker not in seen_evidence_paths:
            item = make_file_evidence(
                root,
                marker,
                project_id,
                "web_root",
                "drupal-web-root-filesystem-evidence",
                ["drupal_web_root", "project_type"],
                "Observed Drupal core filesystem marker for web-root detection.",
                ["File was read as bytes only; PHP was not imported or executed."],
            )
            evidence.append(item)
            seen_evidence_paths.add(relative_marker)
        found.append((candidate, f"evidence.drupal.{slug('drupal-web-root-filesystem-evidence')}.{slug(relative_marker)}"))
    return sorted(found, key=lambda item: item[0])


def determine_web_root(
    root: Path,
    project_id: str,
    composer_declaration: dict[str, Any] | None,
    composer_evidence_id: str | None,
    evidence: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    declared = None
    if composer_declaration:
        declared_raw = composer_declaration.get("drupal_scaffold_web_root")
        if isinstance(declared_raw, str):
            declared = safe_declared_relative_path(declared_raw)
            if declared is None:
                diagnostics.append(
                    diagnostic(
                        "WEB_ROOT_DECLARATION_NOT_PORTABLE",
                        "warning",
                        "Composer scaffold web-root declaration is absolute or escapes the project root; it was ignored.",
                        "composer.json",
                    )
                )
    layout_roots = find_web_root_layouts(root, project_id, evidence)
    layout_values = {item[0] for item in layout_roots}
    layout_evidence_ids = [item[1] for item in layout_roots]
    if declared and layout_values and declared not in layout_values:
        diagnostics.append(
            diagnostic(
                "WEB_ROOT_CONFLICT",
                "warning",
                "Composer scaffold web-root and Drupal core filesystem markers disagree.",
                details={"declared": declared, "filesystem": sorted(layout_values)},
            )
        )
        return {
            "state": "unknown",
            "notes": "Conflicting web-root evidence.",
            "evidence_ids": sorted(set(([composer_evidence_id] if composer_evidence_id else []) + layout_evidence_ids)),
        }
    if declared:
        evidence_ids = ([composer_evidence_id] if composer_evidence_id else []) + [
            evidence_id
            for value, evidence_id in layout_roots
            if value == declared
        ]
        notes = "Derived from Composer Drupal scaffold metadata."
        if any(value == declared for value, _ in layout_roots):
            notes = "Derived from Composer Drupal scaffold metadata and corroborated by a Drupal core filesystem marker."
        return {
            "state": "known",
            "value": declared,
            "evidence_ids": sorted(set(evidence_ids)),
            "notes": notes,
        }
    if len(layout_values) == 1:
        return {
            "state": "known",
            "value": next(iter(layout_values)),
            "evidence_ids": layout_evidence_ids,
            "notes": "Derived from Drupal core filesystem marker.",
        }
    if len(layout_values) > 1:
        diagnostics.append(
            diagnostic(
                "WEB_ROOT_AMBIGUOUS",
                "warning",
                "Multiple Drupal core filesystem markers were found; web root was not selected.",
                details={"candidates": sorted(layout_values)},
            )
        )
    return {"state": "unknown", "notes": "No unambiguous Drupal web-root evidence was found.", "evidence_ids": layout_evidence_ids}


def determine_project_type(
    composer_declaration: dict[str, Any] | None,
    installed_packages: list[dict[str, Any]],
    config_status: str,
    web_root_state: dict[str, Any],
    evidence_ids: list[str],
) -> dict[str, Any]:
    reasons = []
    if package_by_name(installed_packages, "drupal/core"):
        reasons.append("installed drupal/core package")
    if composer_declaration and "drupal/core" in composer_declaration.get("drupal_declared_dependencies", []):
        reasons.append("declared drupal/core dependency")
    if config_status == "available":
        reasons.append("exported core.extension.yml")
    if web_root_state.get("state") == "known":
        reasons.append("Drupal core filesystem or scaffold web-root evidence")
    if reasons:
        confidence = "high" if any(reason.startswith("installed") or reason.startswith("exported") for reason in reasons) else "medium"
        return known(
            {"type": "drupal", "reasons": sorted(reasons)},
            evidence_ids,
            confidence=confidence,
        )
    return unknown("No Drupal project evidence strong enough for classification was found.")


def build_profile(
    project_id: str,
    composer_status: str,
    composer_evidence_id: str | None,
    composer_declaration: dict[str, Any] | None,
    lock_status: str,
    lock_evidence_id: str | None,
    installed_packages: list[dict[str, Any]],
    config: dict[str, Any],
    custom_extensions: dict[str, list[dict[str, Any]]],
    custom_code: dict[str, Any],
    configuration_objects: dict[str, Any],
    settings_declarations: dict[str, Any],
    web_root: dict[str, Any],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    facts: dict[str, dict[str, Any]] = {}
    composer_eids = [eid for eid in (composer_evidence_id, lock_evidence_id) if eid]
    config_eid = config.get("evidence_id")
    config_eids = [config_eid] if config_eid else []

    if composer_declaration or lock_status == "available":
        installed_available = lock_status == "available"
        drupal_packages = drupal_ecosystem_packages(installed_packages)
        facts["composer_packages"] = known(
            {
                "declared": composer_declaration,
                "installed": {
                    "available": installed_available,
                    "packages": installed_packages if installed_available else [],
                    "drupal_packages": drupal_packages if installed_available else [],
                    "counts": {
                        "packages": sum(1 for package in installed_packages if not package["dev"]),
                        "packages_dev": sum(1 for package in installed_packages if package["dev"]),
                        "drupal_packages": len(drupal_packages),
                    },
                },
            },
            composer_eids,
            notes="Declared dependencies and installed packages are separate evidence classes.",
        )
    else:
        facts["composer_packages"] = unknown("No valid Composer declaration or lock evidence was available.")

    facts["drupal_core_version"] = resolve_core_version(installed_packages, lock_status, diagnostics)

    if composer_declaration and (
        composer_declaration.get("php_requirement") or composer_declaration.get("composer_platform_php")
    ):
        facts["php_version"] = known(
            {
                "composer_requirement": composer_declaration.get("php_requirement"),
                "composer_platform": composer_declaration.get("composer_platform_php"),
                "runtime": "unknown",
            },
            [composer_evidence_id] if composer_evidence_id else [],
            notes="The analyzer does not report the host PHP version as project runtime PHP.",
        )
    else:
        facts["php_version"] = unknown(
            "No Composer PHP requirement or platform PHP evidence was found; runtime PHP is unobserved."
        )

    modules, themes, profile = enabled_extensions_from_config(config.get("data"))
    if config.get("status") == "available":
        facts["modules"] = known(
            modules,
            config_eids,
            notes="Enabled modules are derived from exported core.extension.yml, not Composer packages.",
        )
        facts["themes"] = known(
            themes,
            config_eids,
            notes="Enabled themes are derived from exported core.extension.yml, not Composer packages.",
        )
        facts["installation_profile"] = (
            known(profile, config_eids, notes="Derived from exported core.extension.yml.")
            if profile
            else unknown("core.extension.yml did not declare an installation profile.", config_eids)
        )
        facts["config_status"] = known(
            {
                "export_available": True,
                "runtime_synchronized": "unknown",
                "root": config.get("root"),
                "discovery_method": config.get("method"),
                "yaml_file_count": config.get("yaml_file_count", 0),
                "selected_config_families": config.get("families", []),
            },
            config_eids,
            notes="Exported config availability does not prove runtime config synchronization.",
        )
    else:
        reason = {
            "ambiguous": "Multiple config roots were found; no root was selected.",
            "invalid": "core.extension.yml could not be parsed.",
            "unavailable": "No exported core.extension.yml evidence was available.",
        }.get(config.get("status"), "Config evidence is unavailable.")
        facts["modules"] = unknown(reason, config_eids)
        facts["themes"] = unknown(reason, config_eids)
        facts["installation_profile"] = unknown(reason, config_eids)
        facts["config_status"] = unknown(reason, config_eids)

    custom_eids = [
        extension["evidence_id"]
        for extension_type in ("module", "theme", "profile")
        for extension in custom_extensions[extension_type]
    ]
    facts["custom_modules"] = known(
        custom_extensions["module"],
        custom_eids,
        "medium",
        "Only conventional custom extension roots were inspected; presence does not imply enabled state.",
    )
    facts["custom_themes"] = known(
        custom_extensions["theme"],
        custom_eids,
        "medium",
        "Only conventional custom theme roots were inspected; presence does not imply enabled state.",
    )
    facts["custom_code_files"] = known(
        custom_code,
        custom_eids,
        "high",
        (
            "A file inventory bounded by the declared scan configuration. It records "
            "which project-owned source files exist, not what they do."
        ),
    )
    facts["configuration_objects"] = known(
        configuration_objects,
        config_eids,
        "high",
        (
            "Exported Drupal configuration read from the repository. The object list is "
            "complete for the selected config root; observed values are bounded by the "
            "declared key list. Neither is a claim about runtime effective configuration."
        ),
    )
    facts["settings_declarations"] = known(
        settings_declarations,
        [],
        "high",
        (
            "Scalar $settings assignments read from a lexed token stream. PHP was not "
            "executed, and secret-bearing keys and values were dropped before recording."
        ),
    )
    facts["base_themes"] = known(
        sorted(
            {
                extension["base_theme"]
                for extension in custom_extensions["theme"]
                if isinstance(extension.get("base_theme"), str)
            }
        ),
        custom_eids,
        "medium",
        "Base-theme evidence is read only from parsed custom theme .info.yml files.",
    )

    def module_feature(module: str, label: str) -> dict[str, Any]:
        if config.get("status") != "available":
            return unknown(f"{label} cannot be derived because enabled extension config is unavailable.", config_eids)
        return known(
            module in modules,
            config_eids,
            notes=f"Derived from exported core.extension.yml only; this is not a runtime {label} verdict.",
        )

    facts["multilingual"] = module_feature("language", "multilingual")
    facts["commerce"] = module_feature("commerce", "Commerce")
    facts["views"] = module_feature("views", "Views")
    facts["search_api"] = module_feature("search_api", "Search API")
    facts["authentication"] = module_feature("user", "authentication")

    facts["database"] = unknown("Runtime database engine/version is not observable from static repository metadata.")
    facts["file_schemes"] = unknown("Runtime file schemes are not inferred from repository metadata in this analyzer.")
    facts["caching_layers"] = unknown("Runtime cache backend state is not inferred from repository metadata in this analyzer.")
    facts["deployment_model"] = unknown("Deployment model is not inferred from repository metadata in this analyzer.")
    facts["environment_type"] = unknown("Runtime environment type is not inferred from repository metadata in this analyzer.")

    facts["drupal_web_root"] = (
        known(
            web_root["value"],
            web_root.get("evidence_ids", []),
            notes=web_root.get("notes"),
        )
        if web_root.get("state") == "known"
        else unknown(web_root.get("notes", "Drupal web root is unknown."), web_root.get("evidence_ids", []))
    )
    facts["project_type"] = determine_project_type(
        composer_declaration,
        installed_packages,
        config.get("status", "unavailable"),
        web_root,
        sorted(set(composer_eids + config_eids + web_root.get("evidence_ids", []))),
    )

    return {
        "schema_version": "0.1",
        "project_id": project_id,
        "facts": {key: facts[key] for key in sorted(facts)},
    }


def project_id_from_composer(composer_declaration: dict[str, Any] | None) -> str:
    if composer_declaration and isinstance(composer_declaration.get("name"), str):
        return composer_declaration["name"]
    return "unknown-project"


def build_completeness(
    composer_status: str,
    lock_status: str,
    config_status: str,
    custom_extensions: dict[str, list[dict[str, Any]]],
    custom_code: dict[str, Any],
    configuration_objects: dict[str, Any],
    settings_declarations: dict[str, Any],
) -> dict[str, Any]:
    return {
        "composer_declaration": composer_status,
        "installed_package_evidence": "available" if lock_status == "available" else lock_status,
        "drupal_config": config_status,
        "custom_extension_inventory": {
            "state": "available",
            "custom_modules": len(custom_extensions["module"]),
            "custom_themes": len(custom_extensions["theme"]),
            "custom_profiles": len(custom_extensions["profile"]),
            "scope": "conventional-custom-roots",
        },
        "custom_code_inventory": {
            "state": "available",
            "files": custom_code["counts"]["files"],
            "skipped": custom_code["counts"]["skipped"],
            "by_language": dict(custom_code["counts"]["by_language"]),
            "truncated": custom_code["scan"]["truncated"],
            "scope": custom_code["scan"]["scope"],
            "config_digest": custom_code["scan"]["config_digest"],
        },
        "exported_configuration": {
            # Complete for the selected root, and only for it. A project with an
            # ambiguous or missing config root has no enumeration at all.
            "state": "available" if configuration_objects["objects"] else "unavailable",
            "object_enumeration": configuration_objects["scan"]["object_enumeration"],
            "value_observation": configuration_objects["scan"]["value_observation"],
            "objects": configuration_objects["counts"]["objects"],
            "values": configuration_objects["counts"]["values"],
            "redacted": configuration_objects["counts"]["redacted"],
            "unreadable": configuration_objects["counts"]["unreadable"],
            "dependencies": configuration_objects["counts"]["dependencies"],
            "config_root": configuration_objects["scan"]["config_root"],
        },
        "settings_declarations": {
            "state": "available" if settings_declarations["files_read"] else "unavailable",
            "value_observation": settings_declarations["scan"]["value_observation"],
            "files_read": settings_declarations["counts"]["files_read"],
            "entries": settings_declarations["counts"]["entries"],
            "redacted": settings_declarations["counts"]["redacted"],
            "php_executed": False,
        },
        # Nothing here observes a running site. Runtime state stays unavailable
        # however much configuration the repository exports.
        "runtime_evidence": "unavailable",
    }


def build_unknowns(profile: dict[str, Any]) -> list[dict[str, str]]:
    unknowns = []
    for name, item in profile["facts"].items():
        if item.get("state") == "unknown":
            unknowns.append(
                {
                    "fact": name,
                    "reason": item.get("notes", "Unknown from available repository evidence."),
                }
            )
    return sorted(unknowns, key=lambda item: (item["fact"], item["reason"]))


def analyze_project(project_path: str | Path, config_dir: str | None = None) -> AnalysisResult:
    root = Path(project_path)
    if not root.exists():
        raise AnalyzerInputError("project path does not exist")
    if not root.is_dir():
        raise AnalyzerInputError("project path must be a directory")
    root = root.resolve()

    diagnostics: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    exit_code = 0

    composer_json_path = root / "composer.json"
    composer_json, composer_status = load_json_file(
        root,
        composer_json_path,
        diagnostics,
        "COMPOSER_JSON_INVALID",
        "COMPOSER_JSON_MISSING",
    )
    if composer_status == "invalid":
        exit_code = 1
    composer_declaration = extract_composer_declaration(composer_json)
    project_id = project_id_from_composer(composer_declaration)

    composer_evidence_id = None
    if composer_json_path.is_file():
        item = make_file_evidence(
            root,
            composer_json_path,
            project_id,
            "composer_json",
            "composer-json",
            ["composer_packages", "php_version", "project_type", "drupal_web_root"],
            "Parsed root composer.json for declared project metadata and dependencies.",
        )
        evidence.append(item)
        composer_evidence_id = item["id"]

    composer_lock_path = root / "composer.lock"
    composer_lock, lock_status = load_json_file(
        root,
        composer_lock_path,
        diagnostics,
        "COMPOSER_LOCK_INVALID",
        "COMPOSER_LOCK_MISSING",
    )
    if lock_status == "invalid":
        exit_code = 1
    installed_packages, lock_shape_valid = extract_installed_packages(composer_lock)
    if lock_status == "available" and not lock_shape_valid:
        diagnostics.append(
            diagnostic(
                "COMPOSER_LOCK_INVALID",
                "error",
                "composer.lock package lists are malformed and installed package evidence cannot be trusted.",
                "composer.lock",
            )
        )
        lock_status = "invalid"
        exit_code = 1
        installed_packages = []

    lock_evidence_id = None
    if composer_lock_path.is_file():
        item = make_file_evidence(
            root,
            composer_lock_path,
            project_id,
            "composer_lock",
            "composer-lock",
            ["composer_packages", "drupal_core_version", "project_type"],
            "Parsed composer.lock for installed package evidence.",
            ["Installed packages do not prove enabled Drupal extensions."],
        )
        evidence.append(item)
        lock_evidence_id = item["id"]

    config = discover_config(root, config_dir, project_id, evidence, diagnostics)
    if config["status"] == "invalid":
        exit_code = 1
    custom_extensions = scan_custom_extensions(root, project_id, evidence, diagnostics)
    custom_code = scan_custom_code_files(root, load_scan_config(dk_core.ROOT), custom_extensions)
    evidence_config = load_evidence_config(dk_core.ROOT)
    configuration_objects = scan_configuration_objects(root, evidence_config, config)
    settings_declarations = scan_settings_declarations(root, evidence_config)
    web_root = determine_web_root(
        root,
        project_id,
        composer_declaration,
        composer_evidence_id,
        evidence,
        diagnostics,
    )
    profile = build_profile(
        project_id,
        composer_status,
        composer_evidence_id,
        composer_declaration,
        lock_status,
        lock_evidence_id,
        installed_packages,
        config,
        custom_extensions,
        custom_code,
        configuration_objects,
        settings_declarations,
        web_root,
        diagnostics,
    )
    output = {
        "schema_version": "0.1",
        "project_id": project_id,
        "analyzer": {
            "name": ANALYZER_NAME,
            "version": ANALYZER_VERSION,
            "mode": "static-file-inspection",
        },
        "profile": profile,
        "evidence": sorted(evidence, key=lambda item: item["id"]),
        "completeness": build_completeness(
            composer_status,
            lock_status,
            config["status"],
            custom_extensions,
            custom_code,
            configuration_objects,
            settings_declarations,
        ),
        "unknowns": [],
        "diagnostics": sort_diagnostics(diagnostics),
    }
    output["unknowns"] = build_unknowns(profile)
    validate_project_analysis(output)
    return AnalysisResult(output, exit_code)


def validate_fact_object(value: dict[str, Any], context: str) -> None:
    if not isinstance(value, dict):
        raise dk_core.ValidationError(f"{context}: fact must be an object")
    if value.get("state") not in {"known", "unknown", "not_applicable"}:
        raise dk_core.ValidationError(f"{context}: invalid fact state")
    if value.get("state") == "unknown" and value.get("value") is False:
        raise dk_core.ValidationError(f"{context}: unknown must not be false")
    if "source_evidence_ids" in value:
        if not isinstance(value["source_evidence_ids"], list):
            raise dk_core.ValidationError(f"{context}: source_evidence_ids must be a list")
        for evidence_id in value["source_evidence_ids"]:
            if not isinstance(evidence_id, str):
                raise dk_core.ValidationError(f"{context}: source_evidence_ids must be strings")
    if "confidence" in value and value["confidence"] not in {"low", "medium", "high"}:
        raise dk_core.ValidationError(f"{context}: invalid confidence")


def validate_project_profile(profile: dict[str, Any]) -> None:
    schema = dk_core.read_json(dk_core.ROOT / "schema" / "project-profile.schema.json")
    required = set(schema["properties"]["facts"]["required"])
    allowed = set(schema["properties"]["facts"]["properties"])
    if profile.get("schema_version") != "0.1":
        raise dk_core.ValidationError("project profile: invalid schema_version")
    if not isinstance(profile.get("project_id"), str) or not profile["project_id"]:
        raise dk_core.ValidationError("project profile: missing project_id")
    facts = profile.get("facts")
    if not isinstance(facts, dict):
        raise dk_core.ValidationError("project profile: facts must be object")
    missing = sorted(required - set(facts))
    if missing:
        raise dk_core.ValidationError("project profile: missing facts: " + ", ".join(missing))
    extra = sorted(set(facts) - allowed)
    if extra:
        raise dk_core.ValidationError("project profile: unknown facts: " + ", ".join(extra))
    for name, item in facts.items():
        validate_fact_object(item, f"project profile fact {name}")


def validate_project_evidence(item: dict[str, Any]) -> None:
    schema = dk_core.read_json(dk_core.ROOT / "schema" / "project-evidence.schema.json")
    required = set(schema["required"])
    missing = sorted(required - set(item))
    if missing:
        raise dk_core.ValidationError("project evidence: missing keys: " + ", ".join(missing))
    allowed = set(schema["properties"])
    extra = sorted(set(item) - allowed)
    if extra:
        raise dk_core.ValidationError("project evidence: unknown keys: " + ", ".join(extra))
    kinds = set(schema["properties"]["kind"]["enum"])
    if item["kind"] not in kinds:
        raise dk_core.ValidationError(f"project evidence {item['id']}: invalid kind")
    if not isinstance(item.get("path"), str) or Path(item["path"]).is_absolute():
        raise dk_core.ValidationError(f"project evidence {item['id']}: path must be relative")
    if item["path"].startswith("../") or "/../" in item["path"]:
        raise dk_core.ValidationError(f"project evidence {item['id']}: path escapes project root")
    if not dk_core.SHA256_RE.fullmatch(item.get("content_sha256", "")):
        raise dk_core.ValidationError(f"project evidence {item['id']}: invalid content_sha256")
    if "bytes" in item and (not isinstance(item["bytes"], int) or item["bytes"] < 0):
        raise dk_core.ValidationError(f"project evidence {item['id']}: invalid bytes")
    if "role" in item and not isinstance(item["role"], str):
        raise dk_core.ValidationError(f"project evidence {item['id']}: invalid role")


def validate_project_analysis(data: dict[str, Any]) -> list[str]:
    if data.get("schema_version") != "0.1":
        raise dk_core.ValidationError("project analysis: invalid schema_version")
    if not isinstance(data.get("project_id"), str) or not data["project_id"]:
        raise dk_core.ValidationError("project analysis: missing project_id")
    analyzer = data.get("analyzer")
    if not isinstance(analyzer, dict) or analyzer.get("name") != ANALYZER_NAME:
        raise dk_core.ValidationError("project analysis: invalid analyzer")
    validate_project_profile(data.get("profile", {}))
    if data["profile"]["project_id"] != data["project_id"]:
        raise dk_core.ValidationError("project analysis: profile project_id mismatch")
    evidence = data.get("evidence")
    if not isinstance(evidence, list):
        raise dk_core.ValidationError("project analysis: evidence must be list")
    evidence_ids = set()
    for item in evidence:
        validate_project_evidence(item)
        if item["id"] in evidence_ids:
            raise dk_core.ValidationError(f"project analysis: duplicate evidence id {item['id']}")
        evidence_ids.add(item["id"])
    for fact_name, item in data["profile"]["facts"].items():
        for evidence_id in item.get("source_evidence_ids", []):
            if evidence_id not in evidence_ids:
                raise dk_core.ValidationError(
                    f"project analysis: fact {fact_name} references missing evidence {evidence_id}"
                )
    for key in ("completeness", "unknowns", "diagnostics"):
        if key not in data:
            raise dk_core.ValidationError(f"project analysis: missing {key}")
    return ["PROJECT_ANALYSIS_SCHEMA_VALID=PASS"]


def assert_project_profile_schema_backward_compatible() -> None:
    schema = dk_core.read_json(dk_core.ROOT / "schema" / "project-profile.schema.json")
    required = set(schema["properties"]["facts"]["required"])
    if set(BASE_FACTS) - required:
        raise AssertionError("base v0.1 project profile facts must remain required")
    if "project_type" in required or "drupal_web_root" in required:
        raise AssertionError("new analyzer profile facts must remain optional")


def assert_project_evidence_schema_backward_compatible() -> None:
    schema = dk_core.read_json(dk_core.ROOT / "schema" / "project-evidence.schema.json")
    required = set(schema["required"])
    if "bytes" in required or "role" in required:
        raise AssertionError("new project evidence provenance fields must remain optional")
