#!/usr/bin/env python3
"""What the migration engine will and will not call a piece of work.

The nine fixtures below are the matrix that decides whether this engine helps a
migration or wastes a week of someone's time. A current API, a deprecation that
is only debt, a removal that genuinely blocks, a replacement that is sourced and
one that is not, a hook, a service, a name that only ever appears in a comment,
and a project whose code was never read at all.

The last two are the ones a careless engine gets wrong in opposite directions:
it invents work that is not there, or it reports silence as a clean bill of
health. Both are represented here, and both must stay fixed.

Everything is hermetic. The fixtures build their own lifecycle corpus and their
own project tree in a temporary directory, so nothing here reaches Drupal.org.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_api_lifecycle as A
import dk_core
import dk_migration as M
import dk_php_lexer as L


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"


# --- a hermetic lifecycle corpus ---------------------------------------------


def record(
    index_name: str,
    core_file: str,
    annotation: str,
    index_kind: str,
    source_id: str = "drupal-api-deprecated-9-p0",
) -> dict:
    """One lifecycle record built exactly as ingest would build it."""
    return A.build_lifecycle_record(
        {
            "name": index_name,
            "core_file": core_file,
            "annotation": annotation,
            "index_kind": index_kind,
        },
        {
            "id": source_id,
            "url": "https://api.drupal.org/api/drupal/deprecated/9",
            "api_lifecycle": {
                "role": A.AUTHORITY_ROLE,
                "authority_kind": A.KIND_DEPRECATION_INDEX,
                "source_branch": "9",
            },
        },
        "sha256:" + "a" * 64,
        "2026-09-09T00:00:00Z",
        "api.fixture",
    )


CORPUS = [
    # Deprecated in 10.2.0, removed in 11.0.0, replacement stated.
    record(
        "fixture_deprecated_function",
        "core/includes/fixture.inc",
        "in drupal:10.2.0 and is removed from drupal:11.0.0. Use \\Drupal\\Core\\Fixture\\Replacement::run() instead.",
        "function",
    ),
    # Deprecated in 9.3.0, removed in 10.0.0, replacement stated.
    record(
        "fixture_removed_function",
        "core/includes/fixture.inc",
        "in drupal:9.3.0 and is removed from drupal:10.0.0. Use \\Drupal\\Core\\File\\FileUrlGeneratorInterface::generate() instead.",
        "function",
    ),
    # Removed with the annotation explicitly stating no replacement exists.
    record(
        "fixture_no_replacement",
        "core/includes/fixture.inc",
        "in drupal:9.4.0 and is removed from drupal:10.0.0. There is no replacement.",
        "function",
    ),
    # An annotation that does not follow the mandated form at all.
    record(
        "fixture_unreadable",
        "core/includes/fixture.inc",
        "This will go away at some point in the future.",
        "function",
    ),
    # A class, matchable only through its core file path.
    record(
        "FixtureLegacy",
        "core/lib/Drupal/Core/Fixture/FixtureLegacy.php",
        "in drupal:9.2.0 and is removed from drupal:10.0.0. Use \\Drupal\\Core\\Fixture\\FixtureModern instead.",
        "class",
    ),
    # A method with a changed signature, deprecated ahead of removal.
    record(
        "FixtureHooks::alter",
        "core/lib/Drupal/Core/Fixture/FixtureHooks.php",
        "in drupal:9.5.0 and is removed from drupal:10.0.0. Use \\Drupal\\Core\\Fixture\\FixtureHooks::alterAll() instead.",
        "function",
    ),
]


def build_corpus(workspace: Path) -> Path:
    """A repository-shaped root holding only the fixture corpus."""
    directory = workspace / "api" / "lifecycle"
    directory.mkdir(parents=True, exist_ok=True)
    for item in CORPUS:
        (directory / f"{item['id']}.json").write_text(A.stable_json(item), encoding="utf-8")
    (workspace / "sources").mkdir(exist_ok=True)
    (workspace / "sources" / "registry.json").write_text(
        json.dumps(
            [
                {
                    "id": "drupal-api-deprecated-9-p0",
                    "title": "fixture",
                    "url": "https://api.drupal.org/api/drupal/deprecated/9",
                    "trust": "authoritative",
                    "enabled": True,
                    "category": "api-lifecycle",
                    "role": "fixture",
                    "collection_strategy": "change-detection",
                    "checked_on": "2026-09-09",
                    "provenance": "fixture",
                    "version_semantics": {},
                    "api_lifecycle": {
                        "role": A.AUTHORITY_ROLE,
                        "authority_kind": A.KIND_DEPRECATION_INDEX,
                        "source_branch": "9",
                        "index_complete_for_branch": True,
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    return workspace


INDEX_ROOT: Path | None = None


def analysis_for(project: Path, files: list[dict]) -> dict:
    """An analyzer profile in exactly the shape the real analyzer emits."""
    import hashlib

    inventory = []
    for entry in files:
        path = project / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry["source"], encoding="utf-8")
        inventory.append(
            {
                "path": entry["path"],
                "language": entry.get("language", "php"),
                "component": entry.get("component", "fixture_module"),
                "component_type": "module",
                "bytes": len(entry["source"].encode("utf-8")),
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return {
        "schema_version": "0.1",
        "project_id": "fixture/migration",
        "analyzer": {
            "name": "drupal-project-analyzer",
            "version": "0.1",
            "mode": "static-file-inspection",
        },
        "profile": {
            "schema_version": "0.1",
            "project_id": "fixture/migration",
            "facts": {
                "drupal_core_version": {
                    "state": "known",
                    "value": {"package": "drupal/core", "version": "9.5.9"},
                },
                "custom_code_files": {
                    "state": "known",
                    "confidence": "high",
                    "value": {
                        "scan": {
                            "config_id": "drupal-custom-code-scan",
                            "config_digest": "sha256:" + "b" * 64,
                            "roots": ["web/modules/custom"],
                            "excluded_directories": ["vendor", "node_modules"],
                            "included_extensions": {"php": [".php", ".module"], "yaml": [".yml"]},
                            "limits": {"max_file_bytes": 1048576, "max_files": 5000, "max_depth": 12},
                            "truncated": False,
                            "scope": "project_owned_custom_code_only",
                        },
                        "files": inventory,
                        "skipped": [],
                        "counts": {
                            "files": len(inventory),
                            "skipped": 0,
                            "by_language": {"php": len(inventory)},
                            "components": 1,
                        },
                    },
                },
            },
        },
        "evidence": [],
        "completeness": {},
        "unknowns": [],
        "diagnostics": [],
    }


def run(files: list[dict], target: str, workspace: Path, name: str) -> dict:
    project = workspace / name
    project.mkdir(parents=True, exist_ok=True)
    analysis = analysis_for(project, files)
    return M.analyze(analysis, target, INDEX_ROOT, project_path=project)


def item_for(result: dict, symbol: str) -> dict | None:
    return next(
        (item for item in result["work_items"] if item["usage"]["symbol"] == symbol), None
    )


WORKSPACE = Path(tempfile.mkdtemp(prefix="dk-migration-fixture-"))
INDEX_ROOT = build_corpus(WORKSPACE / "corpus")


# --- the deprecation grammar is parsed, never guessed -------------------------

parsed = A.read_annotation(
    "in drupal:9.3.0 and is removed from drupal:10.0.0. Use \\Drupal\\Core\\X::y() instead."
)
assert parsed["deprecated_version"] == "9.3.0"
assert parsed["removed_version"] == "10.0.0"
assert parsed["replacement_state"] == "stated"
assert parsed["replacement"] == "\\Drupal\\Core\\X::y()"

none_stated = A.read_annotation("in drupal:9.4.0 and is removed from drupal:10.0.0. There is no replacement.")
assert none_stated["replacement_state"] == "stated_none"
assert none_stated["replacement"] is None

unreadable = A.read_annotation("This will go away at some point.")
assert unreadable["state"] == A.UNKNOWN
assert unreadable["deprecated_version"] is None and unreadable["removed_version"] is None
print("API_LIFECYCLE_GRAMMAR_PARSED_NOT_GUESSED=PASS")

# Lifecycle states are distinct constants, and deprecated is not removed.
assert A.DEPRECATED != A.REMOVED
assert set(A.LIFECYCLE_STATES) >= {
    "current", "deprecated", "removed", "changed_signature",
    "replacement_available", "behavior_changed", "unknown",
}
print("API_LIFECYCLE_STATES_DISTINCT=PASS")

# Change-record categories stay apart rather than collapsing into "deprecated".
assert len(set(A.CHANGE_CATEGORIES)) == len(A.CHANGE_CATEGORIES) >= 11
assert A.categorize("Book module is removed from Drupal 11", "")["category"] == A.CATEGORY_REMOVAL
assert A.categorize("hook_foo_alter() gains a parameter", "")["category"] in (
    A.CATEGORY_SIGNATURE,
    A.CATEGORY_HOOK,
)
assert A.categorize("Something entirely unrelated", "")["category"] == A.CATEGORY_OTHER
print("CHANGE_RECORD_CATEGORIES_DISTINCT=PASS")


# --- fixture A: current API ---------------------------------------------------
# The symbol is deprecated in 10.2.0. For a 10.1.0 target it is not deprecated
# yet, and rounding 10.2.0 up to "Drupal 10" would wrongly report work.

FIXTURE_A = [
    {
        "path": "web/modules/custom/fixture_module/src/Uses.php",
        "source": """<?php
namespace Drupal\\fixture_module;
class Uses {
  public function go() {
    return fixture_deprecated_function('x');
  }
}
""",
    }
]
result_a = run(FIXTURE_A, "10.1.0", WORKSPACE, "a")
item_a = item_for(result_a, "fixture_deprecated_function")
assert item_a is not None, "the usage must still be observed"
assert item_a["target_effect"]["effect"] == M.EFFECT_COMPATIBLE, item_a["target_effect"]
assert result_a["summary"]["blocking_items"] == 0
print("FIXTURE_A_CURRENT_API_IS_COMPATIBLE=PASS")
print("API_LIFECYCLE_VERSION_BOUNDARIES_PRESERVED=PASS")


# --- fixture B: deprecated but still available --------------------------------
# Same symbol, target 10.6.0: deprecated before the target and removed after it.
# That is debt, not a blocker, and the difference is the whole point.

result_b = run(FIXTURE_A, "10.6.0", WORKSPACE, "b")
item_b = item_for(result_b, "fixture_deprecated_function")
assert item_b["target_effect"]["effect"] == M.EFFECT_RECOMMENDED, item_b["target_effect"]
assert item_b["target_effect"]["blocking"] is False
assert result_b["summary"]["blocking_items"] == 0
assert "10.2.0" in item_b["target_effect"]["reason"]
print("FIXTURE_B_DEPRECATED_IS_NOT_A_BLOCKER=PASS")
print("DEPRECATION_NOT_AUTOMATIC_BLOCKER=PASS")


# --- fixture C: removed -------------------------------------------------------
# Removed in 10.0.0 and observed in code. Both halves are present, so it blocks.

FIXTURE_C = [
    {
        "path": "web/modules/custom/fixture_module/src/Removed.php",
        "source": """<?php
namespace Drupal\\fixture_module;
class Removed {
  public function one() {
    return fixture_removed_function('a');
  }
  public function two() {
    return fixture_removed_function('b');
  }
}
""",
    }
]
result_c = run(FIXTURE_C, "10.6.13", WORKSPACE, "c")
item_c = item_for(result_c, "fixture_removed_function")
assert item_c["target_effect"]["effect"] == M.EFFECT_BLOCKING, item_c["target_effect"]
assert item_c["target_effect"]["blocking"] is True
assert result_c["summary"]["blocking_items"] == 1
print("FIXTURE_C_REMOVED_API_BLOCKS=PASS")
print("REMOVED_API_BLOCKER_REQUIRES_OBSERVED_USE=PASS")

# Two call sites, two occurrences. A migration plan needs both.
assert item_c["usage"]["occurrence_count"] == 2
assert [occurrence["line"] for occurrence in item_c["occurrences"]] == [5, 8]
assert len({occurrence["path"] for occurrence in item_c["occurrences"]}) == 1
print("MIGRATION_OCCURRENCES_PRESERVED=PASS")

# One symbol, one work item, however many occurrences or records describe it.
assert len(result_c["work_items"]) == 1
duplicate = A.build_lifecycle_record(
    {
        "name": "fixture_removed_function",
        "core_file": "core/includes/fixture.inc",
        "annotation": "in drupal:9.3.0 and is removed from drupal:10.0.0. Use \\Drupal\\Core\\File\\FileUrlGeneratorInterface::generate() instead.",
        "index_kind": "function",
    },
    {
        "id": "drupal-api-deprecated-9-p1",
        "url": "https://api.drupal.org/api/drupal/deprecated/9",
        "api_lifecycle": {
            "role": A.AUTHORITY_ROLE,
            "authority_kind": A.KIND_DEPRECATION_INDEX,
            "source_branch": "9",
        },
    },
    "sha256:" + "c" * 64,
    "2026-09-09T00:00:00Z",
    "api.fixture",
)
merged = json.loads(json.dumps(item_c))
M.merge_provenance(merged, duplicate)
assert len(merged["provenance"]) == 2, "a second record adds provenance"
M.merge_provenance(merged, duplicate)
assert len(merged["provenance"]) == 2, "the same record twice adds nothing"
print("MIGRATION_WORK_ITEMS_DEDUPLICATED=PASS")

# Same code, same target, same evidence: the same identity every time.
again = run(FIXTURE_C, "10.6.13", WORKSPACE, "c")
assert again["analysis_id"] == result_c["analysis_id"]
assert [item["work_item_id"] for item in again["work_items"]] == [
    item["work_item_id"] for item in result_c["work_items"]
]
# A different target is different work, and says so in its identity.
other_target = run(FIXTURE_C, "9.5.9", WORKSPACE, "c")
assert other_target["work_items"][0]["work_item_id"] != item_c["work_item_id"]
print("MIGRATION_WORK_ITEM_IDEMPOTENT=PASS")


# --- fixture D: sourced replacement --------------------------------------------

assert item_c["suggested_migration"]["replacement_state"] == "stated"
assert (
    item_c["suggested_migration"]["replacement"]
    == "\\Drupal\\Core\\File\\FileUrlGeneratorInterface::generate()"
)
assert item_c["suggested_migration"]["action_category"] == M.ACTION_REPLACE_SYMBOL
assert item_c["provenance"][0]["source_snapshot_sha256"].startswith("sha256:")
print("FIXTURE_D_REPLACEMENT_IS_SOURCED=PASS")


# --- fixture E: no replacement to invent ---------------------------------------

FIXTURE_E = [
    {
        "path": "web/modules/custom/fixture_module/src/NoReplacement.php",
        "source": """<?php
namespace Drupal\\fixture_module;
class NoReplacement {
  public function go() {
    return fixture_no_replacement();
  }
}
""",
    }
]
result_e = run(FIXTURE_E, "10.6.13", WORKSPACE, "e")
item_e = item_for(result_e, "fixture_no_replacement")
assert item_e["target_effect"]["effect"] == M.EFFECT_BLOCKING
assert item_e["suggested_migration"]["replacement_state"] == "stated_none"
assert item_e["suggested_migration"]["replacement"] is None
assert item_e["suggested_migration"]["action_category"] == M.ACTION_REVIEW_UNSOURCED
print("FIXTURE_E_NO_REPLACEMENT_IS_NOT_INVENTED=PASS")
print("API_REPLACEMENT_ONLY_WHEN_SOURCED=PASS")

# An unreadable annotation gives no version boundary and therefore no verdict.
FIXTURE_UNREADABLE = [
    {
        "path": "web/modules/custom/fixture_module/src/Unreadable.php",
        "source": """<?php
namespace Drupal\\fixture_module;
class Unreadable {
  public function go() {
    return fixture_unreadable();
  }
}
""",
    }
]
result_unreadable = run(FIXTURE_UNREADABLE, "10.6.13", WORKSPACE, "u")
item_unreadable = item_for(result_unreadable, "fixture_unreadable")
assert item_unreadable["target_effect"]["effect"] == M.EFFECT_UNKNOWN
assert result_unreadable["summary"]["blocking_items"] == 0
print("UNREADABLE_ANNOTATION_IS_UNKNOWN=PASS")


# --- fixture F: hook and class migration ---------------------------------------
# A custom hook implementation is observed by name, and a deprecated class is
# resolved through its use statement rather than by matching a short name.

FIXTURE_F = [
    {
        "path": "web/modules/custom/fixture_module/fixture_module.module",
        "source": """<?php

use Drupal\\Core\\Fixture\\FixtureLegacy;
use Drupal\\Core\\Fixture\\FixtureHooks;

/**
 * Implements hook_entity_presave().
 */
function fixture_module_entity_presave($entity) {
  $legacy = new FixtureLegacy();
  return FixtureHooks::alter($entity);
}
""",
    }
]
result_f = run(FIXTURE_F, "10.6.13", WORKSPACE, "f")
hooks = [item for item in result_f["work_items"] if item["usage"]["usage_kind"] == M.USAGE_HOOK]
observed_hooks = [
    entry
    for entry in result_f["observed_without_lifecycle_record"]
    if entry["usage_kind"] == M.USAGE_HOOK
]
assert observed_hooks and observed_hooks[0]["symbol"] == "hook_entity_presave"
assert observed_hooks[0]["relevance"] == "hook"

legacy = item_for(result_f, "Drupal\\Core\\Fixture\\FixtureLegacy")
assert legacy is not None, "a class must resolve through its use statement"
assert legacy["usage"]["usage_kind"] == M.USAGE_CLASS_REFERENCE
assert legacy["target_effect"]["effect"] == M.EFFECT_BLOCKING

method = item_for(result_f, "Drupal\\Core\\Fixture\\FixtureHooks::alter")
assert method is not None, "a static call must resolve to Class::method"
assert method["usage"]["usage_kind"] == M.USAGE_STATIC_CALL
assert method["target_effect"]["effect"] == M.EFFECT_BLOCKING
assert method["suggested_migration"]["replacement"].endswith("alterAll()")
print("FIXTURE_F_HOOK_AND_SIGNATURE_MIGRATION=PASS")
print("HOOK_LIFECYCLE_SEMANTICS_DISTINCT=PASS")


# --- fixture G: removed service -------------------------------------------------
# A service is a work item only when the project actually references its id.
# Depending on a module is not a reference.

SERVICE_CORPUS = build_corpus(WORKSPACE / "services")
service_record = record(
    "fixture.legacy_service",
    "core/lib/Drupal/Core/Fixture/LegacyService.php",
    "in drupal:9.1.0 and is removed from drupal:10.0.0. Use fixture.modern_service instead.",
    "service",
)
service_record["symbol"]["kind"] = A.SYMBOL_SERVICE
service_record["symbol"]["qualified_name"] = "fixture.legacy_service"
service_record["symbol"]["matchable"] = True
(SERVICE_CORPUS / "api" / "lifecycle" / f"{service_record['id']}.json").write_text(
    A.stable_json(service_record), encoding="utf-8"
)

FIXTURE_G = [
    {
        "path": "web/modules/custom/fixture_module/src/Service.php",
        "source": """<?php
namespace Drupal\\fixture_module;
class Service {
  public function go() {
    return \\Drupal::service('fixture.legacy_service')->run();
  }
}
""",
    },
    {
        "path": "web/modules/custom/fixture_module/fixture_module.services.yml",
        "language": "yaml",
        "source": """services:
  fixture_module.thing:
    class: Drupal\\fixture_module\\Thing
    arguments: ['@fixture.legacy_service']
""",
    },
]
project_g = WORKSPACE / "g"
project_g.mkdir(parents=True, exist_ok=True)
result_g = M.analyze(
    analysis_for(project_g, FIXTURE_G), "10.6.13", SERVICE_CORPUS, project_path=project_g
)
item_g = item_for(result_g, "fixture.legacy_service")
assert item_g is not None, "an observed service id must produce a work item"
assert item_g["target_effect"]["effect"] == M.EFFECT_BLOCKING
assert item_g["usage"]["occurrence_count"] == 2, "PHP and YAML references are both occurrences"
assert {occurrence["evidence_quality"] for occurrence in item_g["occurrences"]} == {
    M.EVIDENCE_SYNTAX,
    M.EVIDENCE_STRUCTURED_YAML,
}
print("FIXTURE_G_REMOVED_SERVICE_BLOCKS=PASS")

# A module that merely declares a dependency references no service.
FIXTURE_G_NEGATIVE = [
    {
        "path": "web/modules/custom/fixture_module/fixture_module.info.yml",
        "language": "yaml",
        "source": "name: Fixture\ntype: module\ndependencies:\n  - drupal:fixture\n",
    },
    {
        "path": "web/modules/custom/fixture_module/src/Unrelated.php",
        "source": """<?php
namespace Drupal\\fixture_module;
class Unrelated {
  public function go() {
    // Uses fixture.legacy_service one day, perhaps.
    return 'fixture.legacy_service';
  }
}
""",
    },
]
project_gn = WORKSPACE / "gn"
project_gn.mkdir(parents=True, exist_ok=True)
result_gn = M.analyze(
    analysis_for(project_gn, FIXTURE_G_NEGATIVE), "10.6.13", SERVICE_CORPUS, project_path=project_gn
)
assert item_for(result_gn, "fixture.legacy_service") is None
assert result_gn["summary"]["blocking_items"] == 0
print("SERVICE_MIGRATION_REQUIRES_OBSERVED_REFERENCE=PASS")


# --- fixture H: comment-only reference -------------------------------------------
# Every way a name can appear without being code. None of them is a usage.

FIXTURE_H = [
    {
        "path": "web/modules/custom/fixture_module/src/FalsePositives.php",
        "source": """<?php
namespace Drupal\\fixture_module;

/**
 * Once called fixture_removed_function() before the rewrite.
 *
 * @see fixture_removed_function()
 */
class FalsePositives {

  // TODO: fixture_removed_function() used to live here.
  # And here: fixture_removed_function().

  /* A block comment mentioning fixture_removed_function() too. */

  public function go() {
    $sql = 'select fixture_removed_function() from nowhere';
    $doc = "documented as fixture_removed_function()";
    $text = <<<'TXT'
      fixture_removed_function() inside a nowdoc
TXT;
    return [$sql, $doc, $text];
  }

  public function similar() {
    // A project function whose name merely contains the deprecated one.
    return my_fixture_removed_function_wrapper();
  }

  public function unrelatedNamespace() {
    // A different FixtureLegacy entirely.
    return new \\Vendor\\Other\\FixtureLegacy();
  }

  public function methodNotFunction($object) {
    // A method call that happens to share the name.
    return $object->fixture_removed_function();
  }
}
""",
    }
]
result_h = run(FIXTURE_H, "10.6.13", WORKSPACE, "h")
assert item_for(result_h, "fixture_removed_function") is None, result_h["work_items"]
assert result_h["summary"]["blocking_items"] == 0
assert result_h["summary"]["work_items"] == 0

# The name was seen. Declining to call it a usage is recorded, not silent.
rejected = {entry["symbol"] for entry in result_h["rejected_non_code_matches"]}
assert "fixture_removed_function" in rejected
found_in = {entry["found_in"] for entry in result_h["rejected_non_code_matches"]}
assert {"comment", "doc_comment", "string", "heredoc"} <= found_in, found_in

# The similarly named wrapper is a different symbol, not a partial match.
observed = {entry["symbol"] for entry in result_h["observed_without_lifecycle_record"]}
assert "my_fixture_removed_function_wrapper" in observed
# A different vendor's class of the same short name resolves elsewhere.
assert "Vendor\\Other\\FixtureLegacy" in observed
assert item_for(result_h, "Drupal\\Core\\Fixture\\FixtureLegacy") is None
print("FIXTURE_H_COMMENT_ONLY_IS_NOT_USAGE=PASS")
print("RAW_TEXT_MATCH_NOT_AUTOMATIC_API_USAGE=PASS")
print("API_FALSE_POSITIVE_GUARDS=PASS")

# The lexer, directly: the same name in code and in a comment is not the same.
tokens = L.tokenize("<?php\n// fixture_removed_function();\nfixture_removed_function();\n")
assert len(L.non_code_occurrences(tokens, "fixture_removed_function")) == 1
assert sum(
    1
    for token in L.code_tokens(tokens)
    if token.type == L.T_IDENT and token.value == "fixture_removed_function"
) == 1
print("PHP_API_USAGE_SYNTAX_AWARE_WHERE_REQUIRED=PASS")


# --- fixture I: unknown code coverage ---------------------------------------------
# No inventory, and therefore no reading. The result cannot be compatible.

blind = M.analyze(
    {
        "schema_version": "0.1",
        "project_id": "fixture/blind",
        "analyzer": {"name": "drupal-project-analyzer", "version": "0.1"},
        "profile": {"facts": {"custom_code_files": {"state": "unknown"}}},
    },
    "10.6.13",
    INDEX_ROOT,
)
assert blind["summary"]["work_items"] == 0
assert blind["summary"]["files_read"] == 0
assert any("inventory" in unknown["subject"] for unknown in blind["unknowns"])
assert blind["coverage"]["custom_code"]["scope"] == "unavailable"
print("FIXTURE_I_UNKNOWN_CODE_COVERAGE_STAYS_UNKNOWN=PASS")

# And an empty result is never a compatibility proof, even when files were read.
empty = run(
    [
        {
            "path": "web/modules/custom/fixture_module/src/Clean.php",
            "source": "<?php\nnamespace Drupal\\fixture_module;\nclass Clean {}\n",
        }
    ],
    "10.6.13",
    WORKSPACE,
    "clean",
)
assert empty["summary"]["work_items"] == 0
assert "not a compatibility proof" in empty["coverage"]["statement"]
assert any("coverage" in unknown["subject"] for unknown in empty["unknowns"])
print("NO_MATCHES_NOT_GLOBAL_COMPATIBILITY_PROOF=PASS")


# --- coverage is machine-readable ----------------------------------------------

coverage = result_c["coverage"]
assert coverage["custom_code"]["php_analysis"] == "syntax_aware_lexer_not_full_parser"
assert coverage["custom_code"]["contrib_source_scanned"] is False
assert coverage["custom_code"]["vendor_scanned"] is False
assert coverage["custom_code"]["files_inventoried"] >= coverage["custom_code"]["files_read"]
assert coverage["custom_code"]["config_id"] == "drupal-custom-code-scan"
assert coverage["lifecycle_authority"]["deprecation_index"]["covered_source_branches"] == ["9"]
assert coverage["unsupported_constructs"], "unsupported constructs are declared"
print("API_ANALYSIS_COVERAGE_MACHINE_READABLE=PASS")

# The scan is bounded by declared configuration, not by constants in code.
scan_config = dk_core.read_json(ROOT / "config" / "custom-code-scan.json")
assert "vendor" in scan_config["excluded_directories"]
assert "node_modules" in scan_config["excluded_directories"]
assert scan_config["scope"]["roots"], "the scan declares its roots"
assert all("custom" in root for root in scan_config["scope"]["roots"])
print("DEFAULT_API_SCAN_BOUNDED_TO_PROJECT_CUSTOM_CODE=PASS")
print("API_SCAN_EXCLUSIONS_CONFIGURATION_DRIVEN=PASS")


# --- work items are machine-readable and never applied ---------------------------

for item in result_c["work_items"] + result_f["work_items"] + result_g["work_items"]:
    assert item["result_domain"] == "api_migration"
    assert item["execution_performed"] is False
    assert item["provenance"] and all(
        entry["source_snapshot_sha256"] for entry in item["provenance"]
    )
    assert item["usage"]["occurrence_count"] == len(item["occurrences"])
    for occurrence in item["occurrences"]:
        assert not occurrence["path"].startswith("/"), occurrence
        assert occurrence["line"] >= 1
    assert item["limitations"], "an item states what it could not see"
print("MIGRATION_WORK_ITEM_MACHINE_READABLE=PASS")
print("CUSTOM_CODE_PROVENANCE_EXCLUDES_LOCAL_PATHS=PASS")

# Nothing in the output is a security finding.
for result in (result_c, result_f, result_g):
    assert result["result_domain"] == "api_migration"
    assert "not a security finding" in result["relationship_to_security"]
    blob = json.dumps(result).lower()
    for term in ("advisory", "cve-", "criticality", "sa-core"):
        assert term not in blob, term
print("API_MIGRATION_NOT_SECURITY_FINDING=PASS")

# Every entry point leaves the analysed project untouched.
import hashlib

before = {
    str(path.relative_to(WORKSPACE)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(WORKSPACE.rglob("*"))
    if path.is_file()
}
for target in ("9.5.9", "10.6.13", "11.4.6"):
    run(FIXTURE_C, target, WORKSPACE, "c")
after = {
    str(path.relative_to(WORKSPACE)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(WORKSPACE.rglob("*"))
    if path.is_file()
}
assert before == after, "analysis modified the project tree"
print("MIGRATION_ENGINE_READ_ONLY=PASS")


# --- the CLI cannot change code ---------------------------------------------------

for command in ("migration-analyze", "migration-work"):
    help_text = subprocess.run(
        [sys.executable, str(CLI), command, "--help"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for forbidden in ("--apply", "--rewrite", "--fix", "--patch", "--write", "--execute"):
        assert forbidden not in help_text, f"{command} must not offer {forbidden}"
print("MIGRATION_CLI_HAS_NO_CODE_MODIFICATION_MODE=PASS")

# Third-party analysers are not semantic authority. Rector and Upgrade Status
# may be named — the engine states that it does not run them — but nothing here
# may import one, shell out to one, or take a lifecycle claim from one.
engine_source = (ROOT / "scripts" / "dk_migration.py").read_text(encoding="utf-8")
lifecycle_source = (ROOT / "scripts" / "dk_api_lifecycle.py").read_text(encoding="utf-8")
lexer_source = (ROOT / "scripts" / "dk_php_lexer.py").read_text(encoding="utf-8")
for source in (engine_source, lifecycle_source, lexer_source):
    assert "import subprocess" not in source, "the engines never shell out"
    assert "os.system" not in source and "Popen" not in source
    for community in ("stackoverflow", "drupal answers", "reddit", "medium.com"):
        assert community not in source.lower(), community

# Every lifecycle claim traces to a registered authoritative source, and the
# only registered authority is Drupal.org and api.drupal.org.
for source_entry in A.authority_sources(ROOT):
    assert source_entry["trust"] == "authoritative", source_entry["id"]
    host = source_entry.get("fetch_url", source_entry["url"])
    assert host.startswith(("https://www.drupal.org/", "https://api.drupal.org/")), host
for stored in A.iter_lifecycle_records(ROOT)[:50]:
    assert stored["provenance"]["source_id"].startswith("drupal-")
    assert stored["is_trusted_knowledge"] is False
print("API_LIFECYCLE_AUTHORITY_OFFICIAL_ONLY=PASS")
print("THIRD_PARTY_ANALYZER_NOT_SEMANTIC_AUTHORITY=PASS")


# --- lifecycle evidence comes through acquisition, never a live fetch -------------
# The engines read pinned snapshots. Nothing in them opens a socket, so a
# changed source cannot reach the lifecycle corpus without the acquisition
# engine writing a snapshot and its review machinery running first.

for module in ("dk_api_lifecycle.py", "dk_migration.py", "dk_php_lexer.py"):
    source = (ROOT / "scripts" / module).read_text(encoding="utf-8")
    for forbidden in ("urlopen", "urllib.request", "requests.", "http.client", "socket."):
        assert forbidden not in source, f"{module} must not fetch: {forbidden}"
assert "snapshot_for" in (ROOT / "scripts" / "dk_api_lifecycle.py").read_text(encoding="utf-8")

# Every stored record points at a snapshot that is still on disk and still
# hashes to the name it is filed under.
for stored in A.iter_lifecycle_records(ROOT)[:25] + A.iter_change_records(ROOT)[:5]:
    sha = stored["provenance"]["source_snapshot_sha256"]
    snapshot = dk_core.require_snapshot(ROOT, stored["provenance"]["source_id"], sha)
    assert snapshot.is_file(), stored["id"]
    assert snapshot.stem == sha.split(":", 1)[1]
print("API_INTELLIGENCE_REUSES_ACQUISITION_ENGINE=PASS")

# A source that changes produces an acquisition review candidate. It cannot
# rewrite lifecycle semantics on its own, because ingest only ever reads the
# snapshot the source state currently points at.
registry_ids = {entry["id"] for entry in dk_core.load_sources(ROOT)}
for authority in A.authority_sources(ROOT):
    assert authority["collection_strategy"] == "change-detection", authority["id"]
    assert authority["id"] in registry_ids
    state = dk_core.read_json(ROOT / "sources" / "state" / f"{authority['id']}.json")
    assert state["content_sha256"].startswith("sha256:")
print("API_SOURCE_CHANGE_CANNOT_BYPASS_REVIEW=PASS")


# --- migration findings feed the existing compatibility model ---------------------
# There is one upgrade compatibility authority. Migration evidence enters it
# through the project_code dimension rather than becoming a second one.

import dk_upgrade as U

upgrade_analysis = {
    "schema_version": "0.1",
    "project_id": "fixture/migration",
    "analyzer": {"name": "drupal-project-analyzer", "version": "0.1"},
    "profile": {
        "facts": {
            "drupal_core_version": {
                "state": "known",
                "value": {"package": "drupal/core", "version": "10.6.0"},
            },
            "php_version": {
                "state": "known",
                "value": {"composer_platform": "8.3.0", "runtime": "unknown"},
            },
            "composer_packages": {
                "state": "known",
                "value": {
                    "declared": {"require": {"drupal/core-recommended": "^11"}},
                    "installed": {"available": True, "drupal_packages": [], "packages": []},
                },
            },
            "custom_modules": {"state": "unknown"},
            "custom_themes": {"state": "unknown"},
            "modules": {"state": "unknown"},
            "themes": {"state": "unknown"},
        }
    },
}

without = U.evaluate(upgrade_analysis, "11.4.6", ROOT)
code_without = next(
    dimension
    for dimension in without["dimensions"]
    if dimension["dimension"] == U.DIMENSION_PROJECT_CODE
)
assert code_without["api_migration"] is None
assert code_without["status"] == U.UNKNOWN

with_migration = U.evaluate(upgrade_analysis, "11.4.6", ROOT, migration=result_c)
code_with = next(
    dimension
    for dimension in with_migration["dimensions"]
    if dimension["dimension"] == U.DIMENSION_PROJECT_CODE
)
assert code_with["api_migration"]["analysis_id"] == result_c["analysis_id"]
assert code_with["status"] == U.BLOCKED, code_with["status"]
blockers = [
    item
    for item in with_migration["blockers"]
    if item["kind"] == U.BLOCKER_REMOVED_API_IN_USE
]
assert blockers, "a removed API in use must block the upgrade assessment"
assert blockers[0]["provenance"]["evidence"] == "api_migration_analysis"
assert blockers[0]["required_change"]["occurrences"], "the locations travel with the blocker"
assert with_migration["assessment"] in (
    U.ASSESSMENT_BLOCKED,
    U.ASSESSMENT_REQUIRES_CHANGES,
)
# A deprecation that is not removed at the target is reported as work, not as a
# blocker, when it reaches the same model.
deprecated_only = U.evaluate(upgrade_analysis, "10.6.0", ROOT, migration=result_b)
code_deprecated = next(
    dimension
    for dimension in deprecated_only["dimensions"]
    if dimension["dimension"] == U.DIMENSION_PROJECT_CODE
)
assert not [
    item for item in code_deprecated["blockers"] if item["kind"] == U.BLOCKER_REMOVED_API_IN_USE
]
assert code_deprecated["required_changes"], "deprecated usage is reported as work"
print("API_FINDINGS_FEED_EXISTING_UPGRADE_COMPATIBILITY=PASS")


# --- the trust boundary ------------------------------------------------------------

GUARDED = (
    "knowledge/records",
    "knowledge/context",
    "security/advisories",
    "cases/solved",
    "discovery",
    "sources/snapshots",
)
before_tree = {
    str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in GUARDED
    for path in sorted((ROOT / relative).rglob("*"))
    if path.is_file()
}
run(FIXTURE_C, "10.6.13", WORKSPACE, "trust")
U.evaluate(upgrade_analysis, "11.4.6", ROOT, migration=result_c)
after_tree = {
    str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in GUARDED
    for path in sorted((ROOT / relative).rglob("*"))
    if path.is_file()
}
assert before_tree == after_tree, "migration analysis mutated trusted knowledge"
assert len(before_tree) > 40, len(before_tree)

# Migration output lives in its own store, separate from trusted knowledge.
assert (ROOT / "api" / "lifecycle").is_dir()
assert not list((ROOT / "knowledge" / "records").glob("*api-lifecycle*"))
assert not list((ROOT / "knowledge" / "records").glob("*migration*"))
print("MIGRATION_ANALYSIS_ZERO_TRUSTED_KNOWLEDGE_MUTATION=PASS")
print("API_RECORD_NOT_GENERAL_TRUSTED_KNOWLEDGE=PASS")


# --- the released interface advertises the contract ---------------------------------

version = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True
    ).stdout
)
interfaces = version["interfaces"]
for key in (
    "api_lifecycle_record_schema",
    "change_record_schema",
    "migration_work_item_schema",
    "migration_analysis_schema",
):
    assert key in interfaces, key
engine = version["migration_engine"]
assert engine["name"] == M.ENGINE_NAME
assert engine["result_domain"] == M.RESULT_DOMAIN
assert engine["produces_trusted_knowledge"] is False
assert engine["produces_security_findings"] is False
for key in ("execution_performed", "code_modified", "rector_invoked"):
    assert engine[key] is False, key
assert engine["read_only"] is True
assert version["api_lifecycle_engine"]["produces_trusted_knowledge"] is False
# Earlier releases still advertise what they advertised.
for key in ("upgrade_assessment_schema", "security_remediation_plan_schema", "security_advisory_schema"):
    assert key in interfaces, key
print("MIGRATION_INTERFACE_ADVERTISED=PASS")


# --- no second consumer authority ---------------------------------------------------------------------------
# Consumers read released Drupal Knowledge through the CLI and API. No
# integration directory may carry a second engine.

integration = ROOT / "integrations"
if integration.is_dir():
    for path in integration.rglob("*"):
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace").lower()
            assert "migration-analyze" not in body, path
            assert "migration_engine" not in body, path
print("NO_SECOND_MIGRATION_AUTHORITY=PASS")
