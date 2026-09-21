#!/usr/bin/env python3
"""Normalize authoritative Drupal core release lifecycle context."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

import dk_core


CONTEXT_SCHEMA_VERSION = "0.1"
NORMALIZER_NAME = "drupal-core-release-lifecycle-normalizer"
NORMALIZER_VERSION = "0.1"
DEFAULT_SOURCE_ID = "drupal-core-releases"
CONTEXT_PATH = dk_core.ROOT / "knowledge" / "context" / "drupal-core-release-lifecycle.json"
SCHEMA_PATH = dk_core.ROOT / "schema" / "release-lifecycle-context.schema.json"
# Date the normalized release-lifecycle context was last reviewed against its
# pinned source snapshot. It moves only with an explicit human re-review.
REVIEWED_ON = "2026-09-08"

STABLE_VERSION_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)$"
)

FORBIDDEN_PROJECT_VERDICT_KEYS = {
    "project_is_outdated",
    "project_is_supported",
    "project_is_vulnerable",
    "project_requires_upgrade",
    "project_security_verdict",
    "project_compliance_verdict",
}


class ReleaseLifecycleError(RuntimeError):
    """Raised when release lifecycle context cannot be trusted."""


@dataclass(frozen=True)
class SnapshotReference:
    """Resolved source state and immutable snapshot metadata."""

    source_id: str
    state_path: Path
    snapshot_path: Path
    snapshot_sha256: str
    snapshot_bytes: int
    state: dict[str, Any]


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def strip_namespace(tag: str) -> str:
    return tag.split("}", 1)[-1]


def direct_child(parent: ET.Element, name: str) -> ET.Element | None:
    for child in list(parent):
        if strip_namespace(child.tag) == name:
            return child
    return None


def child_text(parent: ET.Element, name: str) -> dict[str, Any]:
    child = direct_child(parent, name)
    if child is None:
        return {"state": "not_present"}
    return {"state": "present", "source_value": (child.text or "").strip()}


def source_value(value: str | None) -> dict[str, Any]:
    if value is None:
        return {"state": "not_present"}
    return {"state": "present", "source_value": value}


def provenance_path(path: Path, external_label: str) -> str:
    if path.is_relative_to(dk_core.ROOT):
        return path.relative_to(dk_core.ROOT).as_posix()
    return external_label


def resolve_current_snapshot(
    source_id: str = DEFAULT_SOURCE_ID,
    root: Path = dk_core.ROOT,
) -> SnapshotReference:
    state_path = root / "sources" / "state" / f"{source_id}.json"
    if not state_path.is_file():
        raise ReleaseLifecycleError(f"missing source state: {state_path}")
    state = dk_core.read_json(state_path)
    if state.get("source_id") != source_id:
        raise ReleaseLifecycleError(f"source state does not belong to {source_id}")
    digest = state.get("content_sha256")
    if not isinstance(digest, str):
        raise ReleaseLifecycleError(f"source state missing content_sha256: {state_path}")
    snapshot_path = dk_core.require_snapshot(root, source_id, digest)
    data = snapshot_path.read_bytes()
    actual = sha256_bytes(data)
    if actual != digest:
        raise ReleaseLifecycleError(
            f"snapshot hash mismatch: expected {digest}, got {actual}"
        )
    expected_length = state.get("content_length")
    if expected_length != len(data):
        raise ReleaseLifecycleError(
            f"snapshot byte length mismatch: expected {expected_length}, got {len(data)}"
        )
    return SnapshotReference(
        source_id=source_id,
        state_path=state_path,
        snapshot_path=snapshot_path,
        snapshot_sha256=digest,
        snapshot_bytes=len(data),
        state=state,
    )


def snapshot_reference_from_path(
    snapshot_path: Path,
    source_id: str = DEFAULT_SOURCE_ID,
    root: Path = dk_core.ROOT,
) -> SnapshotReference:
    current = resolve_current_snapshot(source_id, root)
    path = snapshot_path if snapshot_path.is_absolute() else root / snapshot_path
    if not path.is_file():
        raise ReleaseLifecycleError(f"snapshot path does not exist: {path}")
    data = path.read_bytes()
    digest = sha256_bytes(data)
    return SnapshotReference(
        source_id=source_id,
        state_path=current.state_path,
        snapshot_path=path,
        snapshot_sha256=digest,
        snapshot_bytes=len(data),
        state=current.state,
    )


def parse_snapshot_xml(snapshot: SnapshotReference) -> ET.Element:
    try:
        root = ET.fromstring(snapshot.snapshot_path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        raise ReleaseLifecycleError(f"release source XML parse failed: {exc}") from exc
    if strip_namespace(root.tag) != "project":
        raise ReleaseLifecycleError("release source XML root must be project")
    return root


def terms_from(parent: ET.Element) -> list[dict[str, Any]]:
    terms_parent = direct_child(parent, "terms")
    if terms_parent is None:
        return []
    terms: list[dict[str, Any]] = []
    for index, term in enumerate(
        child for child in list(terms_parent) if strip_namespace(child.tag) == "term"
    ):
        terms.append(
            {
                "source_order_index": index,
                "name": child_text(term, "name"),
                "value": child_text(term, "value"),
            }
        )
    return terms


def present_term_values(terms: list[dict[str, Any]], name: str) -> list[str]:
    values: list[str] = []
    for term in terms:
        term_name = term.get("name", {})
        term_value = term.get("value", {})
        if (
            term_name.get("state") == "present"
            and term_name.get("source_value") == name
            and term_value.get("state") == "present"
        ):
            values.append(term_value["source_value"])
    return values


def supported_branches(root: ET.Element) -> dict[str, Any]:
    field = child_text(root, "supported_branches")
    if field["state"] != "present":
        return {
            "state": "not_present",
            "source_value": None,
            "entries": [],
            "semantics": "not_present_in_source_snapshot",
        }
    source = field["source_value"]
    entries = []
    for index, value in enumerate(part.strip() for part in source.split(",")):
        if not value:
            continue
        normalized = value[:-1] if value.endswith(".") else value
        entries.append(
            {
                "source_order_index": index,
                "source_value": value,
                "normalized_lookup_value": normalized,
                "normalization": "trim_trailing_dot_for_lookup_only"
                if normalized != value
                else "source_value_already_lookup_safe",
            }
        )
    return {
        "state": "present",
        "source_value": source,
        "entries": entries,
        "semantics": "branches listed by the Drupal release-history feed; source values only",
    }


def version_info(version: dict[str, Any]) -> dict[str, Any]:
    if version.get("state") != "present":
        return {"source": version, "stable_semver": {"state": "unknown"}}
    source = version["source_value"]
    match = STABLE_VERSION_RE.fullmatch(source)
    if not match:
        return {
            "source": version,
            "stable_semver": {
                "state": "not_applicable",
                "reason": "source version is not an x.y.z stable release",
            },
        }
    return {
        "source": version,
        "stable_semver": {
            "state": "present",
            "major": int(match.group("major")),
            "minor": int(match.group("minor")),
            "patch": int(match.group("patch")),
            "source_value": source,
        },
    }


def file_summary(release: ET.Element) -> dict[str, Any]:
    files = direct_child(release, "files")
    if files is None:
        return {
            "state": "not_present",
            "count": 0,
            "archive_type_source_values": [],
        }
    archive_types = []
    for item in (child for child in list(files) if strip_namespace(child.tag) == "file"):
        archive_type = child_text(item, "archive_type")
        if archive_type["state"] == "present":
            archive_types.append(archive_type["source_value"])
    return {
        "state": "present",
        "count": len(
            [
                child
                for child in list(files)
                if strip_namespace(child.tag) == "file"
            ]
        ),
        "archive_type_source_values": archive_types,
        "semantics": "release artifact summary only; full file authority remains in the immutable source snapshot",
    }


def security_field(release: ET.Element) -> dict[str, Any]:
    security = direct_child(release, "security")
    if security is None:
        return {
            "state": "not_present",
            "text": {"state": "not_present"},
            "attributes": {},
            "covered_attribute": {"state": "not_present"},
            "semantics": "no security coverage field present in source release row",
        }
    attributes = {key: security.attrib[key] for key in sorted(security.attrib)}
    return {
        "state": "present",
        "text": source_value((security.text or "").strip()),
        "attributes": attributes,
        "covered_attribute": source_value(security.attrib.get("covered")),
        "semantics": "source security coverage text/attributes only",
    }


def normalize_release(release: ET.Element, index: int) -> dict[str, Any]:
    terms = terms_from(release)
    version = child_text(release, "version")
    return {
        "source_order_index": index,
        "name": child_text(release, "name"),
        "version": version_info(version),
        "tag": child_text(release, "tag"),
        "status": child_text(release, "status"),
        "release_link": child_text(release, "release_link"),
        "download_link": child_text(release, "download_link"),
        "date": child_text(release, "date"),
        "files": file_summary(release),
        "terms": terms,
        "release_type_source_values": present_term_values(terms, "Release type"),
        "security": security_field(release),
    }


def field_matrix(root: ET.Element) -> list[dict[str, Any]]:
    paths: Counter[str] = Counter()
    attrs: defaultdict[str, Counter[str]] = defaultdict(Counter)

    def walk(element: ET.Element, path: str) -> None:
        name = strip_namespace(element.tag)
        current = f"{path}/{name}"
        paths[current] += 1
        for key in element.attrib:
            attrs[current][key] += 1
        for child in list(element):
            walk(child, current)

    walk(root, "")
    normalized_paths = {
        "/project/title",
        "/project/short_name",
        "/project/creator",
        "/project/type",
        "/project/supported_branches",
        "/project/composer_namespace",
        "/project/project_status",
        "/project/link",
        "/project/terms/term",
        "/project/terms/term/name",
        "/project/terms/term/value",
        "/project/releases/release",
        "/project/releases/release/name",
        "/project/releases/release/version",
        "/project/releases/release/tag",
        "/project/releases/release/status",
        "/project/releases/release/release_link",
        "/project/releases/release/download_link",
        "/project/releases/release/date",
        "/project/releases/release/files/file/archive_type",
        "/project/releases/release/terms/term",
        "/project/releases/release/terms/term/name",
        "/project/releases/release/terms/term/value",
        "/project/releases/release/security",
    }
    matrix = []
    for path in sorted(paths):
        if path == "/project" or path.endswith("/releases") or path.endswith("/terms") or path.endswith("/files"):
            decision = "container_only"
        elif path in normalized_paths:
            decision = "normalized"
        else:
            decision = "audited_not_normalized"
        matrix.append(
            {
                "xml_field": path,
                "occurrence_count": paths[path],
                "attributes": sorted(attrs[path]),
                "meaning_directly_explicit": True,
                "normalize_decision": decision,
                "notes": field_matrix_note(path, decision),
            }
        )
    return matrix


def field_matrix_note(path: str, decision: str) -> str:
    if path == "/project/supported_branches":
        return "Preserved as source feed value; not generalized into all support or security semantics."
    if path == "/project/releases/release/security":
        return "Preserved as source text/attributes without broader lifecycle conclusions."
    if path.endswith("/terms/term/value"):
        return "Preserved as source taxonomy term value, including Release type terms."
    if decision == "container_only":
        return "XML container used to locate explicit child fields."
    if decision == "audited_not_normalized":
        return "Audited field is not needed for lifecycle context convenience."
    return "Preserved from the source snapshot."


def source_project(root: ET.Element) -> dict[str, Any]:
    return {
        "title": child_text(root, "title"),
        "short_name": child_text(root, "short_name"),
        "creator": child_text(root, "creator"),
        "type": child_text(root, "type"),
        "composer_namespace": child_text(root, "composer_namespace"),
        "project_status": child_text(root, "project_status"),
        "link": child_text(root, "link"),
        "terms": terms_from(root),
    }


def build_context(
    snapshot: SnapshotReference,
    review_status: str = "candidate",
    reviewed_on: str | None = None,
) -> dict[str, Any]:
    if review_status not in {"candidate", "reviewed"}:
        raise ReleaseLifecycleError("review_status must be candidate or reviewed")
    xml_root = parse_snapshot_xml(snapshot)
    releases_parent = direct_child(xml_root, "releases")
    releases = []
    if releases_parent is not None:
        releases = [
            normalize_release(release, index)
            for index, release in enumerate(
                child
                for child in list(releases_parent)
                if strip_namespace(child.tag) == "release"
            )
        ]

    current_digest = snapshot.state.get("content_sha256")
    state_relation = "current" if current_digest == snapshot.snapshot_sha256 else "stale"
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "artifact_type": "release-lifecycle-context",
        "id": "drupal-core-release-lifecycle",
        "authority_layer": "TRUSTED_KNOWLEDGE_CONTEXT",
        "context_subject": "Drupal core release lifecycle source facts",
        "review": {
            "status": review_status,
            "reviewed_on": reviewed_on if review_status == "reviewed" else None,
            "authority": "reviewed normalized context is authoritative only for the pinned source snapshot",
            "source_state_at_review": state_relation,
        },
        "source": {
            "source_id": snapshot.source_id,
            "url": snapshot.state.get("url"),
            "fetch_url": snapshot.state.get("fetch_url"),
            "state_path": provenance_path(snapshot.state_path, "<external-source-state>"),
            "snapshot_path": provenance_path(snapshot.snapshot_path, "<explicit-snapshot>"),
            "snapshot_sha256": snapshot.snapshot_sha256,
            "snapshot_bytes": snapshot.snapshot_bytes,
            "current_state_sha256": current_digest,
            "current_state_content_length": snapshot.state.get("content_length"),
            "state_snapshot_relation": state_relation,
        },
        "normalizer": {
            "name": NORMALIZER_NAME,
            "version": NORMALIZER_VERSION,
            "method": "parse-drupal-release-history-xml-explicit-fields-only",
            "release_ordering": {
                "method": "source_order",
                "meaning": "preserves feed order from the source snapshot; not support priority",
            },
        },
        "feed_structure_audit": field_matrix(xml_root),
        "source_project": source_project(xml_root),
        "supported_branches": supported_branches(xml_root),
        "release_count": len(releases),
        "releases": releases,
        "non_inference": {
            "not_inferred_conclusions": [
                "no conclusions are inferred from omitted fields or release ordering",
                "release terms and security coverage are preserved as source fields only",
                "no project or upgrade recommendation is inferred from this context",
            ],
        },
    }


def load_context(path: Path = CONTEXT_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def collect_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for child in value.values():
            keys.update(collect_keys(child))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for child in value:
            keys.update(collect_keys(child))
        return keys
    return set()


def context_staleness(
    context: dict[str, Any],
    root: Path = dk_core.ROOT,
) -> dict[str, Any]:
    source = context.get("source", {})
    source_id = source.get("source_id")
    if not isinstance(source_id, str):
        raise ReleaseLifecycleError("context source.source_id is required")
    state = dk_core.read_json(root / "sources" / "state" / f"{source_id}.json")
    current = state.get("content_sha256")
    reviewed = source.get("snapshot_sha256")
    return {
        "status": "current" if current == reviewed else "stale",
        "source_id": source_id,
        "reviewed_snapshot_sha256": reviewed,
        "current_state_sha256": current,
    }


def validate_context_data(
    context: dict[str, Any],
    root: Path = dk_core.ROOT,
    require_current: bool = True,
) -> list[str]:
    if not SCHEMA_PATH.is_file():
        raise ReleaseLifecycleError(f"missing schema: {SCHEMA_PATH}")
    if context.get("schema_version") != CONTEXT_SCHEMA_VERSION:
        raise ReleaseLifecycleError("unsupported release lifecycle context schema_version")
    if context.get("artifact_type") != "release-lifecycle-context":
        raise ReleaseLifecycleError("invalid lifecycle context artifact_type")
    if context.get("authority_layer") != "TRUSTED_KNOWLEDGE_CONTEXT":
        raise ReleaseLifecycleError("release lifecycle context must be knowledge context")
    review = context.get("review", {})
    if review.get("status") not in {"candidate", "reviewed"}:
        raise ReleaseLifecycleError("review.status must be candidate or reviewed")
    if review.get("status") == "reviewed" and not review.get("reviewed_on"):
        raise ReleaseLifecycleError("reviewed context must include reviewed_on")

    source = context.get("source", {})
    source_id = source.get("source_id")
    digest = source.get("snapshot_sha256")
    if not isinstance(source_id, str) or not isinstance(digest, str):
        raise ReleaseLifecycleError("context source provenance is incomplete")
    snapshot_path = dk_core.require_snapshot(root, source_id, digest)
    data = snapshot_path.read_bytes()
    if source.get("snapshot_bytes") != len(data):
        raise ReleaseLifecycleError("context source snapshot byte length mismatch")
    state = dk_core.read_json(root / "sources" / "state" / f"{source_id}.json")
    if source.get("current_state_sha256") != state.get("content_sha256"):
        raise ReleaseLifecycleError("context current_state_sha256 does not match source state")
    staleness = context_staleness(context, root)
    if require_current and staleness["status"] != "current":
        raise ReleaseLifecycleError("release lifecycle context is stale against current source state")

    snapshot = SnapshotReference(
        source_id=source_id,
        state_path=root / source.get("state_path", ""),
        snapshot_path=snapshot_path,
        snapshot_sha256=digest,
        snapshot_bytes=len(data),
        state=state,
    )
    expected = build_context(
        snapshot,
        review_status=review["status"],
        reviewed_on=review.get("reviewed_on"),
    )
    if stable_json(context) != stable_json(expected):
        raise ReleaseLifecycleError("context does not match deterministic normalization")

    xml_root = parse_snapshot_xml(snapshot)
    releases_parent = direct_child(xml_root, "releases")
    source_release_count = 0 if releases_parent is None else len(
        [
            child
            for child in list(releases_parent)
            if strip_namespace(child.tag) == "release"
        ]
    )
    if context.get("release_count") != source_release_count:
        raise ReleaseLifecycleError("normalized release count does not match source")
    if context.get("release_count") != len(context.get("releases", [])):
        raise ReleaseLifecycleError("release_count does not match normalized release rows")
    source_branches = child_text(xml_root, "supported_branches").get("source_value")
    if context.get("supported_branches", {}).get("source_value") != source_branches:
        raise ReleaseLifecycleError("supported branches do not match source")
    if collect_keys(context).intersection(FORBIDDEN_PROJECT_VERDICT_KEYS):
        raise ReleaseLifecycleError("context contains forbidden project verdict keys")

    return [
        "RELEASE_LIFECYCLE_CONTEXT_VALID=PASS",
        "RELEASE_CONTEXT_SOURCE_SNAPSHOT_VERIFIED=PASS",
        "RELEASE_CONTEXT_PROVENANCE_COMPLETE=PASS",
        "RELEASE_CONTEXT_REVIEW_AUTHORITY_EXPLICIT=PASS",
        f"RELEASE_CONTEXT_STALENESS={staleness['status']}",
        f"NORMALIZED_RELEASE_COUNT={context['release_count']}",
    ]


def validate_context_file(
    path: Path = CONTEXT_PATH,
    root: Path = dk_core.ROOT,
    require_current: bool = True,
) -> list[str]:
    return validate_context_data(load_context(path), root, require_current)


def write_context(
    output: Path,
    context: dict[str, Any],
    force: bool = False,
) -> None:
    if output.exists() and not force:
        raise ReleaseLifecycleError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(stable_json(context), encoding="utf-8")


def copy_repo_for_staleness_test(source_root: Path, target_root: Path) -> None:
    ignore = shutil.ignore_patterns(".git", "__pycache__")
    shutil.copytree(source_root, target_root, ignore=ignore)
