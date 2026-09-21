#!/usr/bin/env python3
"""Drupal config YAML parsing must stay narrow and fail closed."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import dk_project_analyzer


def parse(text: str, path: str = "fixture.yml") -> Any:
    return dk_project_analyzer.safe_yaml_load(text, path)


def assert_rejected(text: str) -> None:
    try:
        parse(text)
    except dk_project_analyzer.SafeYamlError:
        return
    raise AssertionError(f"unsupported YAML parsed successfully: {text!r}")


valid_core_extension = """
# Exported extension state with comments and whitespace variation.
module:
  node: 0
  user: 10
  "views": -1 # quoted key with a negative weight
theme:
  olivero: 0
  "claro": 5
profile: "standard"
"""
valid = parse(valid_core_extension)
assert valid == {
    "module": {"node": 0, "user": 10, "views": -1},
    "theme": {"claro": 5, "olivero": 0},
    "profile": "standard",
}

empty_extension = parse(
    """
module: {}
theme: {}
"""
)
assert empty_extension == {"module": {}, "theme": {}}

metadata = parse(
    """
name: "Admin: Tools # Internal"
description: 'URL: https://example.com/docs#section'
core_version_requirement: "^10 || ^11"
package: Custom
dependencies:
  - drupal:node
  - "drupal:user"
  - 'drupal:views'
empty_dependencies: []
"""
)
assert metadata["name"] == "Admin: Tools # Internal"
assert metadata["description"] == "URL: https://example.com/docs#section"
assert metadata["core_version_requirement"] == "^10 || ^11"
assert metadata["dependencies"] == ["drupal:node", "drupal:user", "drupal:views"]
assert metadata["empty_dependencies"] == []

single_quote = parse("name: 'Editor''s tools'\n")
assert single_quote["name"] == "Editor's tools"

for unsupported in (
    "module:\n  node: &node_weight 0\n",
    "module:\n  node: *node_weight\n",
    "profile: !str standard\n",
    "description: |\n  multiline\n",
    "description: >\n  folded\n",
    "dependencies: [drupal:node, drupal:user]\n",
    "module: {node: 0}\n",
    "? [node, user]: 0\n",
    "dependencies:\n  - name: node\n",
    "module:\n  node: 0\n  node: 1\n",
    "module:\n  node: 0\nmodule:\n  user: 0\n",
):
    assert_rejected(unsupported)

with tempfile.TemporaryDirectory() as workspace:
    project = Path(workspace) / "project"
    config = project / "config" / "sync"
    config.mkdir(parents=True)
    (project / "composer.json").write_text(
        json.dumps({"name": "example/project", "require": {"drupal/core": "^11"}}),
        encoding="utf-8",
    )
    (config / "core.extension.yml").write_text(
        "module:\n  node: &node_weight 0\n",
        encoding="utf-8",
    )
    result = dk_project_analyzer.analyze_project(project)
    facts = result.data["profile"]["facts"]
    assert result.exit_code == 1
    assert facts["composer_packages"]["state"] == "known"
    assert facts["modules"]["state"] == "unknown"
    assert facts["themes"]["state"] == "unknown"
    assert facts["installation_profile"]["state"] == "unknown"
    assert "node" not in dk_project_analyzer.stable_json(facts["modules"])
    assert {item["code"] for item in result.data["diagnostics"]} >= {"CORE_EXTENSION_YAML_INVALID"}

with tempfile.TemporaryDirectory() as workspace:
    project = Path(workspace) / "project"
    custom = project / "web" / "modules" / "custom" / "unsafe"
    custom.mkdir(parents=True)
    (project / "composer.json").write_text(
        json.dumps({"name": "example/project", "require": {"drupal/core": "^11"}}),
        encoding="utf-8",
    )
    (custom / "unsafe.info.yml").write_text(
        "name: &unsafe Unsafe module\ncore_version_requirement: *unsafe\n",
        encoding="utf-8",
    )
    result = dk_project_analyzer.analyze_project(project)
    facts = result.data["profile"]["facts"]
    assert result.exit_code == 0
    assert facts["custom_modules"]["value"] == []
    assert any(item["path"].endswith("unsafe.info.yml") for item in result.data["evidence"])
    assert "Unsafe module" not in dk_project_analyzer.stable_json(facts)
    assert {item["code"] for item in result.data["diagnostics"]} >= {"CUSTOM_EXTENSION_INFO_YAML_INVALID"}

print("CORE_EXTENSION_VALID_YAML_PARSED_CORRECTLY=PASS")
print("YAML_SCALAR_BOUNDARIES_SAFE=PASS")
print("YAML_SEQUENCE_HANDLING_EXPLICIT=PASS")
print("UNSUPPORTED_YAML_FAILS_CLOSED=PASS")
print("UNSUPPORTED_YAML_CANNOT_AUTHOR_PROJECT_FACTS=PASS")
print("YAML_DUPLICATE_KEYS_NOT_SILENTLY_OVERRIDDEN=PASS")
print("CONFIG_PARSE_FAILURE_PRESERVES_UNKNOWN=PASS")
print("DRUPAL_CONFIG_YAML_PARSED_SAFELY=PASS")
