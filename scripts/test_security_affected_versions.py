#!/usr/bin/env python3
"""Affected-version semantics follow the advisory, not an approximation.

Every expression here is a real form published by the Drupal Security Team.
The cases that matter most are the ones where a shortcut would produce a false
negative: a range spanning majors, a legacy contrib version, and an expression
the engine cannot read.
"""

from __future__ import annotations

import dk_security as S


def state(expression, installed):
    parsed = S.parse_affected_versions(expression)
    version = S.parse_version(installed)
    if version is None:
        return "unreadable_version"
    covers = S.expression_covers_major(parsed, version.major)
    if covers is False:
        return S.VERSION_OUT_OF_SCOPE
    return S.evaluate_affected(version, parsed)["state"]


# ---------------------------------------------------------------------------
# Core expressions, as published
# ---------------------------------------------------------------------------

CORE_MIXED = "<10.6.13 || >=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.0.* || 11.1.* || 11.2.*"

# Boundaries are exclusive where the advisory says "<". The fixed release is
# the first version that is not affected.
assert state(CORE_MIXED, "11.4.3") == S.APPLICABLE
assert state(CORE_MIXED, "11.4.4") == S.NOT_APPLICABLE
assert state(CORE_MIXED, "11.3.13") == S.APPLICABLE
assert state(CORE_MIXED, "11.3.14") == S.NOT_APPLICABLE
assert state(CORE_MIXED, "10.6.12") == S.APPLICABLE
assert state(CORE_MIXED, "10.6.13") == S.NOT_APPLICABLE
# Branch wildcards constrain the branch, not the patch level.
assert state(CORE_MIXED, "11.2.0") == S.APPLICABLE
assert state(CORE_MIXED, "11.2.99") == S.APPLICABLE
assert state(CORE_MIXED, "11.5.0") == S.NOT_APPLICABLE
print("CORE_EXPRESSION_BOUNDARIES=PASS")

# The detached operator form is the same grammar.
SPACED = ">= 8.9.0 < 10.4.10 || >= 10.5.0 < 10.5.10 || >= 11.0.0 < 11.1.10"
assert state(SPACED, "10.4.9") == S.APPLICABLE
assert state(SPACED, "10.4.10") == S.NOT_APPLICABLE
assert state(SPACED, "8.8.0") == S.NOT_APPLICABLE
assert state(SPACED, "8.9.0") == S.APPLICABLE
print("DETACHED_OPERATOR_FORM=PASS")


# ---------------------------------------------------------------------------
# A range that spans majors covers every major inside it
#
# This is the case where reading the written majors as a set produces a false
# negative: ">= 8.0.0 < 10.3.13" names 8 and 10 but affects 9 as well.
# ---------------------------------------------------------------------------

SPANNING = ">= 8.0.0 < 10.3.13 || >= 10.4.0 < 10.4.3 || >= 11.0.0 < 11.0.12"
assert state(SPANNING, "9.5.9") == S.APPLICABLE, "a Drupal 9 site is inside this range"
assert state(SPANNING, "9.0.0") == S.APPLICABLE
assert state(SPANNING, "10.3.12") == S.APPLICABLE
assert state(SPANNING, "10.3.13") == S.NOT_APPLICABLE
# Nothing above the highest bound is spoken about at all.
assert state(SPANNING, "12.0.0") == S.VERSION_OUT_OF_SCOPE
print("MAJOR_SPANNING_RANGE_COVERS_INNER_MAJORS=PASS")

# An open upper bound also covers everything below it.
assert state("<10.6.13", "9.5.9") == S.APPLICABLE
assert state("<10.6.13", "8.1.0") == S.APPLICABLE

# An expression that only pins branches does not speak about other majors.
assert state("11.0.* || 11.1.*", "9.5.9") == S.VERSION_OUT_OF_SCOPE
assert state("11.0.* || 11.1.*", "11.1.4") == S.APPLICABLE
print("BRANCH_ONLY_EXPRESSION_SCOPE=PASS")


# ---------------------------------------------------------------------------
# Contrib expressions and Drupal's legacy version format
# ---------------------------------------------------------------------------

assert state("<1.2.0", "1.1.9") == S.APPLICABLE
assert state("<1.2.0", "1.2.0") == S.NOT_APPLICABLE
# Drupal.org publishes 8.x-1.2 as the semantic equivalent of 1.2.0.
assert state("<1.2.0", "8.x-1.1") == S.APPLICABLE
assert state("<1.2.0", "8.x-1.2") == S.NOT_APPLICABLE

legacy = S.parse_version("8.x-1.1")
assert legacy.key == (1, 1, 0)
# The normalization is recorded so a reviewer can see it happened.
assert legacy.notes and "legacy contrib format" in legacy.notes[0]
print("LEGACY_CONTRIB_VERSION_NORMALIZED_AND_RECORDED=PASS")

prerelease = S.parse_version("12.0.0-alpha1")
assert prerelease.key == (12, 0, 0)
assert prerelease.suffix == "alpha1"
assert any("pre-release" in note for note in prerelease.notes)
print("PRERELEASE_SUFFIX_RECORDED_NOT_RANKED=PASS")


# ---------------------------------------------------------------------------
# What cannot be read stays unknown, never "safe"
# ---------------------------------------------------------------------------

for expression in ("", "   ", None):
    parsed = S.parse_affected_versions(expression)
    assert parsed["state"] == "absent", expression
    outcome = S.evaluate_affected(S.parse_version("11.4.4"), parsed)
    assert outcome["state"] == S.UNKNOWN, expression
    assert outcome["matched"] is None

for expression in ("all versions before the fix", "~1.2 || bogus", "see advisory"):
    parsed = S.parse_affected_versions(expression)
    assert parsed["state"] == "unparseable", expression
    outcome = S.evaluate_affected(S.parse_version("11.4.4"), parsed)
    assert outcome["state"] == S.UNKNOWN, expression

# An unreadable installed version is unknown too, not unaffected.
for installed in ("", "dev-main", "unknown", None):
    assert S.parse_version(installed) is None, installed
print("UNREADABLE_VERSION_OR_EXPRESSION_STAYS_UNKNOWN=PASS")


# ---------------------------------------------------------------------------
# The parse is the advisory's own expression, preserved
# ---------------------------------------------------------------------------

parsed = S.parse_affected_versions(CORE_MIXED)
assert parsed["source_value"] == CORE_MIXED, "the advisory expression is kept verbatim"
assert parsed["parse_method"] == S.PARSE_METHOD
assert len(parsed["clauses"]) == 6
assert parsed["clauses"][1]["source_value"] == ">=11.3.0 <11.3.14"
assert [item["operator"] for item in parsed["clauses"][1]["constraints"]] == ["gte", "lt"]
assert parsed["clauses"][3]["constraints"][0]["operator"] == "branch_wildcard"

# Same expression, same parse. No randomness, no ordering surprise.
assert S.parse_affected_versions(CORE_MIXED) == parsed
print("AFFECTED_VERSION_PARSE_DETERMINISTIC=PASS")

print("SECURITY_AFFECTED_VERSION_TESTS=PASS")
