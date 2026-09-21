#!/usr/bin/env python3
"""Coverage status must come from actual canonical knowledge records."""

from __future__ import annotations

import tempfile
from pathlib import Path

import dk_core


def status(domain: dict, records: list[dict]) -> str:
    return dk_core.coverage_status_for_domain(domain, records)


records = [
    {"id": "drupal.test.foundation", "domains": ["has-foundation"]},
    {"id": "drupal.test.partial", "domains": ["has-partial"]},
    {"id": "drupal.test.previously-empty", "domains": ["previously-empty"]},
    {"id": "drupal.test.removed", "domains": ["removed-domain"]},
]

assert status({"id": "zero-foundation", "initial_coverage": "FOUNDATION"}, records) == "EMPTY"
assert status({"id": "zero-partial", "initial_coverage": "PARTIAL"}, records) == "EMPTY"
assert status({"id": "has-foundation"}, records) == "FOUNDATION"
assert status({"id": "has-partial", "initial_coverage": "PARTIAL"}, records) == "PARTIAL"
assert status({"id": "previously-empty", "initial_coverage": "EMPTY"}, records) == "FOUNDATION"
assert status({"id": "removed-domain"}, records[:-1]) == "EMPTY"

statuses = {
    status({"id": "many-records"}, [{"domains": ["many-records"]} for _ in range(20)])
}
assert statuses == {"FOUNDATION"}


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    write_json(root / "sources" / "registry.json", [])
    write_json(root / "taxonomy" / "domains.json", {"domains": [
        {"id": "has-foundation", "label": "Has Foundation"},
        {"id": "has-partial", "label": "Has Partial", "initial_coverage": "PARTIAL"},
        {"id": "zero-foundation", "label": "Zero Foundation", "initial_coverage": "FOUNDATION"},
    ]})
    write_json(root / "knowledge" / "records" / "a.json", {
        "id": "drupal.test.foundation",
        "review_status": "reviewed",
        "enforcement": {"intent": "non_blocking"},
        "domains": ["has-foundation"],
    })
    write_json(root / "knowledge" / "records" / "b.json", {
        "id": "drupal.test.partial",
        "review_status": "reviewed",
        "enforcement": {"intent": "non_blocking"},
        "domains": ["has-partial"],
    })

    first = dk_core.stable_json(dk_core.build_generated(root))
    second = dk_core.stable_json(dk_core.build_generated(root))
    assert first == second
    generated = dk_core.build_generated(root)
    actual_statuses = {domain["status"] for domain in generated["coverage"]["domains"]}
    assert actual_statuses <= {"EMPTY", "FOUNDATION", "PARTIAL"}
    assert "COMPLETE" not in actual_statuses


print("COVERAGE_REFLECTS_ACTUAL_KNOWLEDGE=PASS")
print("RECORD_COUNT_CANNOT_IMPLY_COMPLETE_COVERAGE=PASS")
