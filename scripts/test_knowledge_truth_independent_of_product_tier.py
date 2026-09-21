#!/usr/bin/env python3
"""Canonical knowledge truth must not depend on commercial packaging."""

from __future__ import annotations

import dk_core


FORBIDDEN_KEYS = {
    "commercial_product",
    "commercial_tier",
    "license_tier",
    "minimum_plan",
    "paywall",
    "plan",
    "product_tier",
    "tier",
}


def forbidden_paths(value, path: str = "") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            if key in FORBIDDEN_KEYS:
                found.append(child_path)
            found.extend(forbidden_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(forbidden_paths(child, f"{path}[{index}]"))
    return found


violations = []
for record in dk_core.load_knowledge_records():
    for forbidden in forbidden_paths(record):
        violations.append(f"{record['id']}:{forbidden}")

if violations:
    raise AssertionError(
        "canonical knowledge contains product-tier or paywall fields: "
        + ", ".join(violations)
    )

print("KNOWLEDGE_TRUTH_INDEPENDENT_OF_PRODUCT_TIER=PASS")
