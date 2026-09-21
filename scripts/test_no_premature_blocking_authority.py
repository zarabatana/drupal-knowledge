#!/usr/bin/env python3
"""Foundation knowledge must not become blocking before project evidence exists."""

from __future__ import annotations

import dk_core


blocking = [
    record["id"]
    for record in dk_core.load_knowledge_records()
    if dk_core.effective_enforcement(record) == "blocking"
]

if blocking:
    raise AssertionError(
        "blocking authority requires implemented project evidence evaluation: "
        + ", ".join(blocking)
    )

print("NO_PREMATURE_BLOCKING_AUTHORITY=PASS")
