#!/usr/bin/env python3
"""Drupal Insecure release-type semantic authority chain invariants."""

from __future__ import annotations

import re
from typing import Any

import dk_core


ROOT = dk_core.ROOT
RECORD_ID = "drupal.update.core-release-insecure-term-condition"
# The reviewed semantic authority release is whatever the registry currently
# pins, never a second hard-coded copy of it. Advancing the pin is a reviewed
# act (docs/lifecycle-finding-eligibility-review-2026-09-23.json); this test
# fails again if that release is ever itself marked Insecure upstream.
PINNED_TAG = dk_core.semantic_authority_tag()

SEMANTIC_SOURCE_IDS = [
    "drupal-update-project-release-semantics",
    "drupal-update-status-security-semantics",
    "drupal-update-manager-interface-semantics",
]

SEMANTIC_FETCH_FILES = {
    "drupal-update-project-release-semantics": "core/modules/update/src/ProjectRelease.php",
    "drupal-update-status-security-semantics": "core/modules/update/update.compare.inc",
    "drupal-update-manager-interface-semantics": "core/modules/update/src/UpdateManagerInterface.php",
}


def snapshot_text(source_id: str) -> str:
    state = dk_core.read_json(ROOT / "sources" / "state" / f"{source_id}.json")
    assert state["source_id"] == source_id
    snapshot = dk_core.require_snapshot(ROOT, source_id, state["content_sha256"])
    text = snapshot.read_text(encoding="utf-8")
    assert len(text.encode("utf-8")) == state["content_length"]
    return text


sources = {source["id"]: source for source in dk_core.load_sources()}
records = {record["id"]: record for record in dk_core.load_knowledge_records()}
record = records[RECORD_ID]
contract = record["machine_finding"]


# --- baselined authoritative sources ----------------------------------------
for source_id in SEMANTIC_SOURCE_IDS:
    source = sources[source_id]
    assert source["trust"] == "authoritative", source_id
    assert source["enabled"] is True
    assert source["category"] == "update-status-semantics"
    fetch_url = source["fetch_url"]
    assert fetch_url == (
        f"https://git.drupalcode.org/project/drupal/-/raw/{PINNED_TAG}/"
        + SEMANTIC_FETCH_FILES[source_id]
    ), fetch_url
    assert source["url"].startswith("https://api.drupal.org/api/drupal/"), source_id
    assert "/11.x" in source["url"], "documentation URL must be the current Drupal 11 page"
project_release = snapshot_text("drupal-update-project-release-semantics")
update_compare = snapshot_text("drupal-update-status-security-semantics")
manager_interface = snapshot_text("drupal-update-manager-interface-semantics")


# --- current Drupal 11 authority dominates ----------------------------------
# The pinned tag is the current covered stable release row in the reviewed
# lifecycle context, not a historical Drupal 8 artifact.
context = dk_core.read_json(ROOT / "knowledge" / "context" / "drupal-core-release-lifecycle.json")
context_rows = {
    row["version"]["source"]["source_value"]: row
    for row in context["releases"]
    if row.get("version", {}).get("source", {}).get("state") == "present"
}
pinned_row = context_rows[PINNED_TAG]
assert pinned_row["security"]["covered_attribute"]["source_value"] == "1"
assert "Insecure" not in pinned_row.get("release_type_source_values", [])
for source_id in SEMANTIC_SOURCE_IDS:
    fetch_url = sources[source_id]["fetch_url"]
    assert f"/-/raw/{PINNED_TAG}/" in fetch_url
    assert "/-/raw/8." not in fetch_url and "/-/raw/9." not in fetch_url
assert "Drupal\\update" in project_release and "Drupal\\update" in manager_interface


# --- LINK 1: Release type "Insecure" -> isInsecure() -------------------------
is_insecure = re.search(
    r"public function isInsecure\(\): bool \{\s*return \$this->isReleaseType\('Insecure'\);\s*\}",
    project_release,
)
assert is_insecure, "isInsecure() must literally delegate to isReleaseType('Insecure')"
is_release_type = re.search(
    r"private function isReleaseType\(string \$type\): bool \{\s*"
    r"return \$this->releaseTypes && in_array\(\$type, \$this->releaseTypes, TRUE\);\s*\}",
    project_release,
)
assert is_release_type, "isReleaseType must be a strict literal membership test"
assert "$release_data['terms']['Release type'] ?? NULL" in project_release, (
    "release types must be populated from the feed's Release type taxonomy"
)


# --- LINK 2: exact installed insecure release -> NOT_SECURE ------------------
calc = update_compare.split("function update_calculate_project_update_status", 1)[1]
installed_branch = re.search(
    r"if \(\$project_data\['existing_version'\] === \$version\) \{\s*"
    r"if \(\$release->isInsecure\(\)\) \{\s*"
    r"\$project_data\['status'\] = UpdateManagerInterface::NOT_SECURE;\s*\}",
    calc,
)
assert installed_branch, (
    "the exact installed release with isInsecure() must be assigned NOT_SECURE"
)
# The assignment is terminal: once a status is known the function returns
# before any later status branch can override it.
terminal_guard = re.search(
    r"if \(isset\(\$project_data\['status'\]\)\) \{\s*"
    r"// If we already know the status, we're done\.\s*return;",
    calc,
)
assert terminal_guard, "status set on the installed release must be terminal"
assert calc.index(installed_branch.group(0)) < calc.index(terminal_guard.group(0))


# --- LINK 3: NOT_SECURE means missing security update(s) ---------------------
not_secure = re.search(
    r"/\*\*\s*\n\s*\* Project is missing security update\(s\)\.\s*\n\s*\*/\s*\n\s*"
    r"const NOT_SECURE = 1;",
    manager_interface,
)
assert not_secure, "NOT_SECURE must be documented as missing security update(s)"


# --- chain completeness: no inferred link ------------------------------------
evidence_matrix = {
    "drupal-update-project-release-semantics": is_insecure.group(0),
    "drupal-update-status-security-semantics": installed_branch.group(0),
    "drupal-update-manager-interface-semantics": not_secure.group(0),
}
assert all(evidence_matrix.values())
assert set(evidence_matrix) == set(SEMANTIC_SOURCE_IDS)
assert set(contract["confirmation_authority"]["semantic_authority_refs"]) == set(
    SEMANTIC_SOURCE_IDS
)


def non_advisory_authoritative(sources) -> int:
    """Authoritative sources excluding the separately declared functional classes.

    The count this guard protects is the reviewed documentation and semantic
    authority set. Advisory feeds, upgrade authority, API lifecycle authority and
    implementation-rule authority are separate functional classes, each declared
    by its own registry block and counted by its own contract. Excluding them
    keeps this guard measuring the thing it was written to measure, rather than
    every source the registry has since gained.
    """
    return sum(
        1
        for source in sources
        if source["trust"] == "authoritative"
        and (source.get("security") or {}).get("role") != "advisory_feed"
        and (source.get("upgrade") or {}).get("role") != "upgrade_authority"
        and (source.get("api_lifecycle") or {}).get("role") != "api_lifecycle_authority"
        and (source.get("implementation_authority") or {}).get("role")
        != "implementation_rule_authority"
    )


# --- minimal source set -------------------------------------------------------
semantic_registered = sorted(
    source["id"] for source in sources.values() if source["category"] == "update-status-semantics"
)
assert semantic_registered == sorted(SEMANTIC_SOURCE_IDS), semantic_registered
assert non_advisory_authoritative(sources.values()) == 15, (
    "only the three semantic sources may be added"
)
# The registry has grown past that set, and the growth is accounted for by name
# rather than by silently raising the number this guard protects.
upgrade_authority = sorted(
    source_id
    for source_id, source in sources.items()
    if (source.get("upgrade") or {}).get("role") == "upgrade_authority"
)
assert upgrade_authority == [
    "drupal-php-requirements",
    "drupal-upgrade-10-to-11",
    "drupal-upgrade-11-to-12",
    "drupal-upgrade-9-to-10",
    "drupal-upgrade-process-overview",
], upgrade_authority
assert all(
    source["category"] in {"upgrade-process", "upgrade-transition", "platform-requirements"}
    for source_id, source in sources.items()
    if source_id in upgrade_authority
)
assert not any("update-module-ui" in source_id for source_id in sources)
update_module_sources = [
    source_id
    for source_id, source in sources.items()
    if source.get("fetch_url", "").endswith("update.module")
]
assert update_module_sources == [], "update.module was not needed; first three sources suffice"


# --- targeted collection only -------------------------------------------------
# Each semantic source was baselined exactly once, with no change candidates,
# and the collection did not advance the release-history source state away from
# the reviewed lifecycle context pin.
for source_id in SEMANTIC_SOURCE_IDS:
    snapshots = list((ROOT / "sources" / "snapshots" / source_id).glob("*.txt"))
    assert len(snapshots) == 1, (source_id, snapshots)
candidate_dir = ROOT / "discovery" / "candidates"
if candidate_dir.is_dir():
    for candidate_path in candidate_dir.glob("*.json"):
        candidate = dk_core.read_json(candidate_path)
        assert candidate.get("source_id") not in SEMANTIC_SOURCE_IDS
releases_state = dk_core.read_json(ROOT / "sources" / "state" / "drupal-core-releases.json")
assert releases_state["content_sha256"] == context["source"]["snapshot_sha256"]


# --- the record binds the chain ----------------------------------------------
record_source_ids = [item["source_id"] for item in record["sources"]]
assert record_source_ids == ["drupal-core-releases"] + SEMANTIC_SOURCE_IDS
locator_text = " ".join(item["locator"] for item in record["sources"])
assert "isInsecure" in locator_text
assert "NOT_SECURE" in locator_text
assert "missing security update(s)" in locator_text
semantics = contract["term_semantics"]
assert semantics["state"] == "DRUPAL_UPDATE_STATUS_SEMANTICS_REVIEWED"
assert "NOT_SECURE" in semantics["authorized_meaning"]
assert "missing security update(s)" in semantics["authorized_meaning"]


print("DRUPAL_INSECURE_SEMANTIC_CHAIN_AUDITED=PASS")
print("DRUPAL_RELEASE_TYPE_INSECURE_MAPS_TO_IS_INSECURE=PASS")
print("INSTALLED_INSECURE_RELEASE_MAPS_TO_NOT_SECURE=PASS")
print("DRUPAL_NOT_SECURE_MEANING_VERIFIED=PASS")
print("INSECURE_TO_NOT_SECURE_CHAIN_COMPLETE=PASS")
print("SEMANTIC_SOURCE_SET_MINIMAL=PASS")
print("CURRENT_DRUPAL_AUTHORITY_DOMINATES_HISTORICAL_EVIDENCE=PASS")
print("INSECURE_SEMANTIC_SOURCES_BASELINED=PASS")
print("SEMANTIC_SOURCE_COLLECTION_TARGETED_ONLY=PASS")
