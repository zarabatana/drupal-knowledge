#!/usr/bin/env python3
"""Unreviewed knowledge must never become blocking context for any consumer."""

from __future__ import annotations

import dk_core


unreviewed = {
    "review_status": "seed_needs_human_review",
    "enforcement": {"intent": "blocking"},
}
reviewed_blocking = {
    "review_status": "reviewed",
    "enforcement": {"intent": "blocking"},
}
reviewed_guidance = {
    "review_status": "reviewed",
    "enforcement": {"intent": "non_blocking"},
}

assert dk_core.effective_enforcement(unreviewed) == "advisory"
assert dk_core.effective_enforcement(reviewed_blocking) == "blocking"
assert dk_core.effective_enforcement(reviewed_guidance) == "guidance"
dk_core.validate_knowledge()

print("UNREVIEWED_KNOWLEDGE_CANNOT_BLOCK=PASS")
