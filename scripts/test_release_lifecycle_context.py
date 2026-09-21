#!/usr/bin/env python3
"""Release lifecycle context authority and normalization invariants."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import dk_applicability
import dk_core
import dk_project_analyzer
import dk_release_lifecycle


ROOT = dk_core.ROOT
CONTEXT_PATH = ROOT / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
# Pinned to the currently reviewed snapshot. Advancing this constant is only
# correct alongside an explicit re-review of the context it describes.
EXPECTED_SOURCE_SHA = "sha256:2c6302dcfe0d2dd98afb22db753b6ee0761b9440555b71b1af2272b9ba84c2fb"
FORBIDDEN_PROJECT_VERDICT_KEYS = {
    "project_is_outdated",
    "project_is_supported",
    "project_is_vulnerable",
    "project_requires_upgrade",
    "project_security_verdict",
    "project_compliance_verdict",
}
FORBIDDEN_ANALYZER_RELEASE_FACTS = {
    "supported",
    "unsupported",
    "eol",
    "current",
    "obsolete",
    "security_supported",
    "release_lifecycle",
    "release_support",
}


def recursive_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for child in value.values():
            keys.update(recursive_keys(child))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for child in value:
            keys.update(recursive_keys(child))
        return keys
    return set()


def recursive_values(value: Any) -> list[Any]:
    if isinstance(value, dict):
        items: list[Any] = []
        for child in value.values():
            items.extend(recursive_values(child))
        return items
    if isinstance(value, list):
        items = []
        for child in value:
            items.extend(recursive_values(child))
        return items
    return [value]


def strip(tag: str) -> str:
    return tag.split("}", 1)[-1]


def child_text(parent: ET.Element, name: str) -> str | None:
    for child in list(parent):
        if strip(child.tag) == name:
            return (child.text or "").strip()
    return None


def terms(release: ET.Element) -> list[str]:
    values: list[str] = []
    terms_parent = next((child for child in list(release) if strip(child.tag) == "terms"), None)
    if terms_parent is None:
        return values
    for term in (child for child in list(terms_parent) if strip(child.tag) == "term"):
        if child_text(term, "name") == "Release type":
            value = child_text(term, "value")
            if value is not None:
                values.append(value)
    return values


def security(release: ET.Element) -> tuple[str | None, str | None]:
    element = next((child for child in list(release) if strip(child.tag) == "security"), None)
    if element is None:
        return None, None
    return (element.text or "").strip(), element.attrib.get("covered")


def archive_types(release: ET.Element) -> list[str]:
    files = next((child for child in list(release) if strip(child.tag) == "files"), None)
    if files is None:
        return []
    values = []
    for file_item in (child for child in list(files) if strip(child.tag) == "file"):
        value = child_text(file_item, "archive_type")
        if value is not None:
            values.append(value)
    return values


def source_release_rows(xml_root: ET.Element) -> list[ET.Element]:
    releases = next((child for child in list(xml_root) if strip(child.tag) == "releases"), None)
    assert releases is not None
    return [child for child in list(releases) if strip(child.tag) == "release"]


def source_row_by_version(xml_root: ET.Element) -> dict[str, ET.Element]:
    return {child_text(row, "version"): row for row in source_release_rows(xml_root)}


def context_row_by_version(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        row["version"]["source"]["source_value"]: row
        for row in context["releases"]
        if row["version"]["source"]["state"] == "present"
    }


def first_matching(rows: list[ET.Element], predicate) -> str:
    for row in rows:
        if predicate(row):
            version = child_text(row, "version")
            assert version is not None
            return version
    raise AssertionError("representative release row not found")


def assert_release_parity(
    source_row: ET.Element,
    context_row: dict[str, Any],
) -> None:
    for field in ("name", "tag", "status", "release_link", "download_link", "date"):
        assert context_row[field]["state"] == "present"
        assert context_row[field]["source_value"] == child_text(source_row, field)
    assert context_row["version"]["source"]["source_value"] == child_text(source_row, "version")
    assert context_row["release_type_source_values"] == terms(source_row)
    source_security_text, source_covered = security(source_row)
    assert context_row["security"]["text"].get("source_value") == source_security_text
    assert context_row["security"]["covered_attribute"].get("source_value") == source_covered
    assert context_row["files"]["archive_type_source_values"] == archive_types(source_row)


context = dk_release_lifecycle.load_context()
validation_messages = dk_release_lifecycle.validate_context_file()
assert "RELEASE_LIFECYCLE_CONTEXT_VALID=PASS" in validation_messages
assert context["authority_layer"] == "TRUSTED_KNOWLEDGE_CONTEXT"
assert context["review"]["status"] == "reviewed"
assert context["source"]["source_id"] == "drupal-core-releases"
assert context["source"]["snapshot_sha256"] == EXPECTED_SOURCE_SHA
assert context["source"]["snapshot_bytes"] == 543079
assert context["source"]["state_snapshot_relation"] == "current"

source_ref = dk_release_lifecycle.resolve_current_snapshot("drupal-core-releases")
assert source_ref.snapshot_sha256 == EXPECTED_SOURCE_SHA
xml_root = dk_release_lifecycle.parse_snapshot_xml(source_ref)
source_rows = source_release_rows(xml_root)
assert len(source_rows) == context["release_count"] == 556
assert context["supported_branches"]["source_value"] == child_text(xml_root, "supported_branches")
# The reviewed baseline now includes the 12.0. branch. Branch membership is a
# non-authoritative signal, so this records the source value only.
assert context["supported_branches"]["source_value"] == "10.6.,11.3.,11.4.,12.0."
assert [item["source_value"] for item in context["supported_branches"]["entries"]] == [
    "10.6.",
    "11.3.",
    "11.4.",
    "12.0.",
]
assert context["supported_branches"]["semantics"] == (
    "branches listed by the Drupal release-history feed; source values only"
)

matrix = {row["xml_field"]: row for row in context["feed_structure_audit"]}
assert matrix["/project/releases/release"]["occurrence_count"] == 556
assert matrix["/project/releases/release/security"]["attributes"] == ["covered"]
assert matrix["/project/releases/release/security"]["normalize_decision"] == "normalized"
assert matrix["/project/releases/release/files/file/url"]["normalize_decision"] == "audited_not_normalized"
assert matrix["/project/supported_branches"]["normalize_decision"] == "normalized"

source_by_version = source_row_by_version(xml_root)
context_by_version = context_row_by_version(context)
assert set(source_by_version) == set(context_by_version)
def is_prerelease(row) -> bool:
    return any(
        token in (child_text(row, "version") or "") for token in ("-alpha", "-beta", "-rc")
    )


representatives = {
    # An ordinary bugfix exemplar must be a stable release: the prerelease
    # exemplar below exists to cover the other case, and the two must not
    # collapse onto the same row when a prerelease heads the feed.
    "ordinary_bugfix": first_matching(
        source_rows,
        lambda row: "Bug fixes" in terms(row)
        and "Security update" not in terms(row)
        and "Insecure" not in terms(row)
        and not is_prerelease(row),
    ),
    "security_update": first_matching(source_rows, lambda row: "Security update" in terms(row)),
    "insecure_term": first_matching(source_rows, lambda row: "Insecure" in terms(row)),
    "security_coverage_metadata": first_matching(
        source_rows,
        lambda row: security(row)[1] == "1",
    ),
    "prerelease": first_matching(source_rows, is_prerelease),
}
assert representatives["ordinary_bugfix"] == "11.4.6"
assert representatives["security_update"] == "11.4.4"
assert representatives["insecure_term"] == "11.4.3"
assert representatives["prerelease"] == "12.0.0-alpha1"
assert representatives["ordinary_bugfix"] != representatives["prerelease"]
for version in representatives.values():
    assert_release_parity(source_by_version[version], context_by_version[version])

insecure_row = context_by_version[representatives["insecure_term"]]
assert "Insecure" in insecure_row["release_type_source_values"]
assert "project_is_vulnerable" not in json.dumps(insecure_row, sort_keys=True)
prerelease_row = context_by_version[representatives["prerelease"]]
assert prerelease_row["version"]["source"]["source_value"] == representatives["prerelease"]
assert prerelease_row["version"]["stable_semver"]["state"] == "not_applicable"
assert prerelease_row["security"]["covered_attribute"]["state"] == "not_present"
assert "not covered by Drupal security advisories" in prerelease_row["security"]["text"]["source_value"]

keys = recursive_keys(context)
assert keys.isdisjoint(FORBIDDEN_PROJECT_VERDICT_KEYS)
assert not any(value is False for value in recursive_values(context["supported_branches"]))
assert "CURRENT_FINDING_ENGINE_JUSTIFIED=NO" in (ROOT / "docs" / "FINDING_MODEL.md").read_text(encoding="utf-8")
assert not (ROOT / "scripts" / "dk_findings.py").exists()

regenerated = dk_release_lifecycle.build_context(
    source_ref,
    review_status="reviewed",
    reviewed_on=dk_release_lifecycle.REVIEWED_ON,
)
assert dk_release_lifecycle.stable_json(regenerated) == CONTEXT_PATH.read_text(encoding="utf-8")
assert dk_release_lifecycle.stable_json(regenerated) == dk_release_lifecycle.stable_json(
    dk_release_lifecycle.build_context(
        source_ref,
        review_status="reviewed",
        reviewed_on=dk_release_lifecycle.REVIEWED_ON,
    )
)

before_context = CONTEXT_PATH.read_bytes()
candidate_a = subprocess.run(
    [sys.executable, str(ROOT / "scripts" / "dk.py"), "release-lifecycle", "normalize"],
    check=True,
    capture_output=True,
    text=True,
)
candidate_b = subprocess.run(
    [sys.executable, str(ROOT / "scripts" / "dk.py"), "release-lifecycle", "normalize"],
    check=True,
    capture_output=True,
    text=True,
)
assert candidate_a.stdout == candidate_b.stdout
candidate = json.loads(candidate_a.stdout)
assert candidate["review"]["status"] == "candidate"
assert candidate["review"]["reviewed_on"] is None
assert CONTEXT_PATH.read_bytes() == before_context

with tempfile.TemporaryDirectory() as temp:
    output = Path(temp) / "candidate.json"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "dk.py"),
            "release-lifecycle",
            "normalize",
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8"))["review"]["status"] == "candidate"
    assert CONTEXT_PATH.read_bytes() == before_context

with tempfile.TemporaryDirectory() as temp:
    temp_root = Path(temp)
    state_dir = temp_root / "sources" / "state"
    snapshot_dir = temp_root / "sources" / "snapshots" / "drupal-core-releases"
    context_dir = temp_root / "knowledge" / "context"
    state_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)
    context_dir.mkdir(parents=True)
    state_path = state_dir / "drupal-core-releases.json"
    state = dk_core.read_json(ROOT / "sources" / "state" / "drupal-core-releases.json")
    state_path.write_text(dk_core.stable_json(state), encoding="utf-8")
    original_snapshot = source_ref.snapshot_path.read_bytes()
    (snapshot_dir / f"{EXPECTED_SOURCE_SHA.removeprefix('sha256:')}.txt").write_bytes(original_snapshot)
    temp_context_path = context_dir / "drupal-core-release-lifecycle.json"
    temp_context_path.write_bytes(before_context)
    changed_snapshot = original_snapshot + b"\n<!-- simulated source movement -->\n"
    changed_sha = dk_release_lifecycle.sha256_bytes(changed_snapshot)
    (snapshot_dir / f"{changed_sha.removeprefix('sha256:')}.txt").write_bytes(changed_snapshot)
    changed_state = copy.deepcopy(state)
    changed_state["content_sha256"] = changed_sha
    changed_state["content_length"] = len(changed_snapshot)
    state_path.write_text(dk_core.stable_json(changed_state), encoding="utf-8")
    temp_context = json.loads(temp_context_path.read_text(encoding="utf-8"))
    status = dk_release_lifecycle.context_staleness(temp_context, root=temp_root)
    assert status["status"] == "stale"
    assert status["reviewed_snapshot_sha256"] == EXPECTED_SOURCE_SHA
    assert temp_context_path.read_bytes() == before_context

with tempfile.TemporaryDirectory() as temp:
    temp_snapshot = Path(temp) / "missing-supported-branches.xml"
    modified_root = copy.deepcopy(xml_root)
    supported = next(
        (child for child in list(modified_root) if strip(child.tag) == "supported_branches"),
        None,
    )
    assert supported is not None
    modified_root.remove(supported)
    temp_snapshot.write_text(
        ET.tostring(modified_root, encoding="unicode"),
        encoding="utf-8",
    )
    candidate_ref = dk_release_lifecycle.snapshot_reference_from_path(temp_snapshot)
    missing_context = dk_release_lifecycle.build_context(candidate_ref)
    assert missing_context["supported_branches"]["state"] == "not_present"
    assert missing_context["supported_branches"]["source_value"] is None
    assert not any(value is False for value in recursive_values(missing_context["supported_branches"]))

knowledge_records = dk_core.load_knowledge_records()
knowledge_count = len(knowledge_records)
assert knowledge_count == 11
# A reviewed contract may reference the canonical lifecycle context by id, but
# normalized release rows must never be materialized into knowledge records.
context_referencing_records = [
    record
    for record in knowledge_records
    if "drupal-core-release-lifecycle" in dk_core.stable_json(record)
]
assert len(context_referencing_records) == 1
MATERIALIZED_RELEASE_KEYS = {
    "releases",
    "release_count",
    "release_type_source_values",
    "source_order_index",
    "stable_semver",
    "supported_branches",
}


def record_keys(value) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for child in value.values():
            keys |= record_keys(child)
        return keys
    if isinstance(value, list):
        keys = set()
        for child in value:
            keys |= record_keys(child)
        return keys
    return set()


release_record_spam = sorted(
    record["id"]
    for record in knowledge_records
    if record_keys(record) & MATERIALIZED_RELEASE_KEYS
)
assert not release_record_spam, release_record_spam
assert dk_core.validate_generated_current() == ["GENERATED_KNOWLEDGE_CURRENT=PASS"]

profile_schema = dk_core.read_json(ROOT / "schema" / "project-profile.schema.json")
fact_names = set(profile_schema["properties"]["facts"]["properties"])
assert fact_names.isdisjoint(FORBIDDEN_ANALYZER_RELEASE_FACTS)
analysis = dk_project_analyzer.analyze_project(ROOT / "tests" / "fixtures" / "project-analyzer" / "recommended")
assert analysis.exit_code == 0
assert set(analysis.data["profile"]["facts"]).isdisjoint(FORBIDDEN_ANALYZER_RELEASE_FACTS)
resolution_a = dk_applicability.resolve_analysis_data(analysis.data)
resolution_b = dk_applicability.resolve_analysis_data(analysis.data)
assert dk_applicability.stable_json(resolution_a) == dk_applicability.stable_json(resolution_b)
assert "release_lifecycle" not in dk_applicability.stable_json(resolution_a)

print("RELEASE_LIFECYCLE_CONTEXT_IS_KNOWLEDGE=PASS")
print("PROJECT_EVIDENCE_AND_RELEASE_KNOWLEDGE_SEPARATED=PASS")
print("RELEASE_CONTEXT_SOURCE_SNAPSHOT_VERIFIED=PASS")
print("RELEASE_FEED_STRUCTURE_AUDITED=PASS")
print("RELEASE_CONTEXT_EXPLICIT_FIELDS_ONLY=PASS")
print("RELEASE_NORMALIZATION_LOSSLESS=PASS")
print("SUPPORTED_BRANCHES_NOT_OVERGENERALIZED=PASS")
print("OLDER_RELEASE_NOT_AUTOMATICALLY_UNSUPPORTED=PASS")
print("INSECURE_SOURCE_TERM_NOT_OVERINTERPRETED=PASS")
print("SECURITY_COVERAGE_NOT_PROJECT_SECURITY_VERDICT=PASS")
print("RELEASE_ROWS_NOT_KNOWLEDGE_RECORD_SPAM=PASS")
print("RELEASE_CONTEXT_PROVENANCE_COMPLETE=PASS")
print("RELEASE_CONTEXT_REVIEW_AUTHORITY_EXPLICIT=PASS")
print("SOURCE_CHANGE_DOES_NOT_AUTO_PROMOTE_RELEASE_CONTEXT=PASS")
print("RELEASE_CONTEXT_STALENESS_DETECTABLE=PASS")
print("NORMALIZATION_DOES_NOT_AUTO_PUBLISH_AUTHORITY=PASS")
print("RELEASE_CONTEXT_DETERMINISTIC=PASS")
print("MISSING_RELEASE_FIELD_NOT_FALSE=PASS")
print("RELEASE_VERSION_SOURCE_VALUE_PRESERVED=PASS")
print("NORMALIZED_RELEASE_COUNT_MATCHES_SOURCE=PASS")
print("NORMALIZED_SUPPORTED_BRANCHES_MATCH_SOURCE=PASS")
print("NORMALIZED_RELEASE_FIELDS_TRACE_TO_SOURCE=PASS")
print("RELEASE_CONTEXT_PROJECT_VERDICTS=0")
print("RELEASE_LIFECYCLE_CONTEXT_VALID=PASS")
print("CURRENT_APPLICABILITY_RESULTS_UNCHANGED=PASS")
print("ANALYZER_EXTERNAL_RELEASE_FACTS=0")
print("ANALYZER_REMAINS_PROJECT_OBSERVATION_ONLY=PASS")
print("CURRENT_FINDING_ENGINE_JUSTIFIED=NO")
print("RELEASE_LIFECYCLE_VALIDATION_OFFLINE=PASS")
