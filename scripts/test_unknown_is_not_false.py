#!/usr/bin/env python3
"""Unknown project facts must not be collapsed to false."""

from __future__ import annotations

import dk_core


schema = dk_core.read_json(dk_core.ROOT / "schema" / "project-profile.schema.json")
states = set(schema["$defs"]["fact"]["properties"]["state"]["enum"])
assert {"known", "unknown", "not_applicable"} <= states
dk_core.assert_unknown_is_not_false()
assert "UNKNOWN_IS_NOT_FALSE=PASS" in dk_core.validate_consumer_contract()

profile_fact = {"state": "unknown"}
assert "value" not in profile_fact
assert profile_fact["state"] != "known"

print("UNKNOWN_IS_NOT_FALSE=PASS")
