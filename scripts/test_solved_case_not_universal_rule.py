#!/usr/bin/env python3
"""Solved cases prove recurrence, not universal Drupal requirements."""

from __future__ import annotations

import dk_core


schema = dk_core.read_json(dk_core.ROOT / "schema" / "solved-case.schema.json")
statuses = set(schema["properties"]["status"]["enum"])
required_lifecycle = {
    "captured",
    "verified",
    "recurring",
    "generalization_proposed",
    "promoted_to_knowledge_proposal",
}
assert required_lifecycle <= statuses
assert "universal_rule" not in schema["properties"]

for case in dk_core.load_solved_cases():
    assert case.get("universal_rule") is not True

dk_core.validate_solved_cases()

print("SOLVED_CASE_NOT_UNIVERSAL_RULE=PASS")
