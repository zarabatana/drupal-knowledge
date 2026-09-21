#!/usr/bin/env python3
"""Read-only Drupal Project Analyzer foundation invariants."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

import dk_core
import dk_project_analyzer


ROOT = dk_core.ROOT
FIXTURES = ROOT / "tests" / "fixtures" / "project-analyzer"


def fixture(name: str) -> Path:
    return FIXTURES / name


def analyze(name: str, config_dir: str | None = None, exit_code: int = 0) -> dict[str, Any]:
    result = dk_project_analyzer.analyze_project(fixture(name), config_dir)
    assert result.exit_code == exit_code, (name, result.exit_code, result.data["diagnostics"])
    dk_project_analyzer.validate_project_analysis(result.data)
    return result.data


def profile_fact(data: dict[str, Any], name: str) -> dict[str, Any]:
    return data["profile"]["facts"][name]


def evidence_paths(data: dict[str, Any]) -> list[str]:
    return sorted(item["path"] for item in data["evidence"])


def diagnostic_codes(data: dict[str, Any]) -> set[str]:
    return {item["code"] for item in data["diagnostics"]}


def tree_fingerprint(root: Path) -> str:
    digest = sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


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


recommended = analyze("recommended")
assert profile_fact(recommended, "project_type")["value"]["type"] == "drupal"
assert profile_fact(recommended, "drupal_core_version")["value"]["version"] == "11.2.3"
assert profile_fact(recommended, "php_version")["value"] == {
    "composer_platform": "8.3.0",
    "composer_requirement": "^8.3",
    "runtime": "unknown",
}
assert profile_fact(recommended, "drupal_web_root")["value"] == "web"
assert profile_fact(recommended, "installation_profile")["value"] == "standard"
assert profile_fact(recommended, "modules")["value"] == [
    "commerce",
    "language",
    "node",
    "user",
    "views",
]
assert profile_fact(recommended, "themes")["value"] == ["claro", "olivero"]
assert profile_fact(recommended, "commerce")["value"] is True
assert profile_fact(recommended, "views")["value"] is True
assert profile_fact(recommended, "search_api")["value"] is False
assert profile_fact(recommended, "config_status")["value"]["runtime_synchronized"] == "unknown"
assert profile_fact(recommended, "config_status")["value"]["yaml_file_count"] == 3
assert profile_fact(recommended, "custom_modules")["value"][0]["enabled"] == "unknown"
assert profile_fact(recommended, "custom_themes")["value"][0]["base_theme"] == "olivero"

evidence_by_id = {item["id"]: item for item in recommended["evidence"]}
for item in recommended["evidence"]:
    path = Path(item["path"])
    assert not path.is_absolute()
    assert ".." not in path.parts
    raw = (fixture("recommended") / path).read_bytes()
    assert item["bytes"] == len(raw)
    assert item["content_sha256"] == "sha256:" + sha256(raw).hexdigest()
    assert item["role"]
for fact_name, item in recommended["profile"]["facts"].items():
    for evidence_id in item.get("source_evidence_ids", []):
        assert evidence_id in evidence_by_id, fact_name

composer_value = profile_fact(recommended, "composer_packages")["value"]
assert composer_value["declared"]["require"]["drupal/commerce"] == "^3.1"
assert any(package["name"] == "drupal/commerce" for package in composer_value["installed"]["packages"])
assert profile_fact(recommended, "composer_packages")["notes"].startswith(
    "Declared dependencies and installed packages are separate"
)

first = subprocess.run(
    [sys.executable, str(ROOT / "scripts" / "dk.py"), "analyze", str(fixture("recommended"))],
    check=True,
    capture_output=True,
    text=True,
)
second = subprocess.run(
    [sys.executable, str(ROOT / "scripts" / "dk.py"), "analyze", str(fixture("recommended"))],
    check=True,
    capture_output=True,
    text=True,
)
assert first.stdout == second.stdout
assert json.loads(first.stdout) == recommended

composer_only = analyze("composer-only")
assert profile_fact(composer_only, "composer_packages")["state"] == "known"
assert profile_fact(composer_only, "drupal_core_version")["state"] == "unknown"
assert profile_fact(composer_only, "modules")["state"] == "unknown"
assert "CONFIG_ROOT_NOT_FOUND" in diagnostic_codes(composer_only)

no_lock = analyze("no-lock")
assert profile_fact(no_lock, "composer_packages")["state"] == "known"
assert profile_fact(no_lock, "drupal_core_version")["state"] == "unknown"
assert profile_fact(no_lock, "modules")["value"] == ["node", "user"]

disabled = analyze("installed-but-disabled")
disabled_packages = profile_fact(disabled, "composer_packages")["value"]["installed"]["packages"]
assert any(package["name"] == "drupal/webform" for package in disabled_packages)
assert "webform" not in profile_fact(disabled, "modules")["value"]

core_module = analyze("enabled-core-module")
assert "views" in profile_fact(core_module, "modules")["value"]
assert not any(
    package["name"] == "drupal/views"
    for package in profile_fact(core_module, "composer_packages")["value"]["installed"]["packages"]
)
assert "PACKAGE_FOR_EXTENSION_MISSING" not in diagnostic_codes(core_module)

ambiguous = analyze("ambiguous-config")
assert ambiguous["completeness"]["drupal_config"] == "ambiguous"
assert profile_fact(ambiguous, "modules")["state"] == "unknown"
assert "CONFIG_ROOT_AMBIGUOUS" in diagnostic_codes(ambiguous)
override = dk_project_analyzer.analyze_project(fixture("ambiguous-config"), "config/a")
assert override.exit_code == 0
assert profile_fact(override.data, "modules")["value"] == ["node", "user"]

heavy = analyze("heavy-trees")
assert heavy["completeness"]["drupal_config"] == "unavailable"
assert profile_fact(heavy, "modules")["state"] == "unknown"
joined_heavy = dk_project_analyzer.stable_json(heavy)
assert "should_not_be_seen" not in joined_heavy
assert not any(path.startswith("vendor/") or path.startswith("node_modules/") for path in evidence_paths(heavy))
assert profile_fact(heavy, "drupal_web_root")["state"] == "unknown"

malformed_composer = analyze("malformed-composer-json", exit_code=1)
assert "COMPOSER_JSON_INVALID" in diagnostic_codes(malformed_composer)
assert profile_fact(malformed_composer, "composer_packages")["state"] == "unknown"

malformed_lock = analyze("malformed-composer-lock", exit_code=1)
assert "COMPOSER_LOCK_INVALID" in diagnostic_codes(malformed_lock)
assert profile_fact(malformed_lock, "drupal_core_version")["state"] == "unknown"

malformed_config = analyze("malformed-core-extension", exit_code=1)
assert "CORE_EXTENSION_YAML_INVALID" in diagnostic_codes(malformed_config)
assert profile_fact(malformed_config, "composer_packages")["state"] == "known"
assert profile_fact(malformed_config, "modules")["state"] == "unknown"

with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
    left_project = Path(left) / "copy-a"
    right_project = Path(right) / "nested" / "copy-b"
    shutil.copytree(fixture("recommended"), left_project)
    shutil.copytree(fixture("recommended"), right_project)
    left_output = dk_project_analyzer.analyze_project(left_project).data
    right_output = dk_project_analyzer.analyze_project(right_project).data
    assert dk_project_analyzer.stable_json(left_output) == dk_project_analyzer.stable_json(right_output)
    absolute_tokens = {left, right, str(left_project), str(right_project)}
    output_text = dk_project_analyzer.stable_json(left_output)
    assert not any(token in output_text for token in absolute_tokens)

with tempfile.TemporaryDirectory() as workspace:
    immutable_project = Path(workspace) / "immutable"
    shutil.copytree(fixture("recommended"), immutable_project)
    before = tree_fingerprint(immutable_project)
    dk_project_analyzer.analyze_project(immutable_project)
    after = tree_fingerprint(immutable_project)
    assert before == after

with tempfile.TemporaryDirectory() as workspace:
    code_project = Path(workspace) / "code-execution"
    shutil.copytree(fixture("code-execution"), code_project)
    secret = "SHOULD_NOT_APPEAR_IN_ANALYSIS"
    (code_project / ".env").write_text(f"SECRET_TOKEN={secret}\n", encoding="utf-8")
    before = tree_fingerprint(code_project)
    code_result = dk_project_analyzer.analyze_project(code_project)
    after = tree_fingerprint(code_project)
    assert code_result.exit_code == 0
    assert before == after
    assert not (code_project / "target-code-executed.txt").exists()
    assert secret not in dk_project_analyzer.stable_json(code_result.data)

for text in recursive_strings(recommended):
    lowered = text.lower()
    assert lowered not in {"vulnerable", "secure", "compliant", "non-compliant", "blocking"}
assert "applicable_context" not in recommended
assert "consumer" not in dk_project_analyzer.stable_json(recommended).lower()

source = (ROOT / "scripts" / "dk_project_analyzer.py").read_text(encoding="utf-8")
assert "requests" not in source
assert "urllib" not in source
assert "socket" not in source
assert "subprocess" not in source

before_knowledge = dk_core.knowledge_tree_digest()
dk_project_analyzer.analyze_project(fixture("recommended"))
after_knowledge = dk_core.knowledge_tree_digest()
assert before_knowledge == after_knowledge

try:
    dk_project_analyzer.analyze_project(fixture("recommended"), "../composer-only")
except dk_project_analyzer.AnalyzerInputError:
    pass
else:
    raise AssertionError("escaped --config-dir should fail")

print("TARGET_PROJECT_IMMUTABLE=PASS")
print("TARGET_CODE_NOT_EXECUTED=PASS")
print("PROJECT_ANALYSIS_OFFLINE=PASS")
print("PROJECT_ANALYSIS_DETERMINISTIC=PASS")
print("PROJECT_EVIDENCE_PATHS_PORTABLE=PASS")
print("PROJECT_FACTS_HAVE_EVIDENCE_PROVENANCE=PASS")
print("DRUPAL_CORE_VERSION_EVIDENCE_BASED=PASS")
print("HOST_PHP_NOT_PROJECT_PHP=PASS")
print("DECLARED_INSTALLED_ENABLED_RUNTIME_SEPARATED=PASS")
print("COMPOSER_PACKAGE_DOES_NOT_IMPLY_EXTENSION_ENABLED=PASS")
print("PACKAGE_EXTENSION_NAME_MATCH_NOT_AUTHORITY=PASS")
print("DRUPAL_WEB_ROOT_NOT_BLINDLY_ASSUMED=PASS")
print("AMBIGUOUS_CONFIG_ROOT_NOT_GUESSED=PASS")
print("CONFIG_EXPORT_NOT_RUNTIME_SYNC_PROOF=PASS")
print("UNOBSERVED_RUNTIME_FACTS_UNKNOWN=PASS")
print("MISSING_CONFIG_DOES_NOT_DISABLE_ALL_EXTENSIONS=PASS")
print("ANALYZER_EMITS_NO_KNOWLEDGE_VERDICTS=PASS")
print("ANALYZER_DOES_NOT_MUTATE_KNOWLEDGE=PASS")
print("PROJECT_ANALYZER_CONSUMER_INDEPENDENT=PASS")
print("ANALYZER_DOES_NOT_EXTRACT_SECRETS=PASS")
print("HEAVY_TREES_EXCLUDED=PASS")
