#!/usr/bin/env python3
"""Where upgrade authority comes from, and where it stops.

Three boundaries this file exists to hold.

The first is provenance. Every requirement the reviewed upgrade context states
must still be quotable, verbatim, from the immutable snapshot it came from. A
requirement that cannot be quoted is an invented one, and the contract refuses
it rather than reporting it.

The second is the relationship to security. The remediation engine answers what
stops an advisory applying. This one answers whether the project can get there.
A target that clears every advisory is not thereby a compatible target, and the
two engines are held apart on the same real project.

The third is the trust boundary. Upgrade analysis reads reviewed knowledge and
writes none of it, no matter which entry point runs.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_core
import dk_remediation as R
import dk_security as S
import dk_upgrade as U

from test_upgrade_compatibility import analysis, dimension, package


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"
CONTEXT = U.load_context(ROOT)
SOURCES = {source["id"]: source for source in dk_core.load_sources(ROOT)}


# --- authority is official, registered and quotable ---------------------------

authority = [
    source
    for source in SOURCES.values()
    if (source.get("upgrade") or {}).get("role") == U.UPGRADE_AUTHORITY_ROLE
]
assert authority, "upgrade authority must be declared in the registry, not in code"
for source in authority:
    assert source["trust"] == "authoritative", source["id"]
    assert source["url"].startswith("https://www.drupal.org/"), source["id"]
    assert source["enabled"] is True, source["id"]
    assert source["lifecycle"] == "active", source["id"]

# Transition policy, per-transition requirements and the platform matrix each
# come from an official Drupal.org page, never from a blog or a community post.
kinds = {(source.get("upgrade") or {})["authority_kind"] for source in authority}
assert kinds == {"transition_policy", "transition_requirements", "platform_requirements"}, kinds
print("UPGRADE_AUTHORITY_USES_OFFICIAL_SOURCES=PASS")


# Every quoted requirement is still present, byte for byte, in its snapshot.
# This is what stops the reviewed context drifting into invention.
quoted = 0
for where, provenance in [
    ("major_transition_policy", CONTEXT["major_transition_policy"]["provenance"]),
    ("php_support_matrix", CONTEXT["php_support_matrix"]["provenance"]),
    *[(f"transition {entry['id']}", entry["provenance"]) for entry in CONTEXT["transitions"]],
]:
    assert provenance["source_id"] in SOURCES, where
    U.verify_provenance(ROOT, provenance, where)
    quoted += len(provenance["source_text"])
assert quoted >= 20, quoted

# And the verification is real: a quote the snapshot does not contain is refused.
forged = copy.deepcopy(CONTEXT["transitions"][0]["provenance"])
forged["source_text"] = ["Drupal 9 sites may upgrade directly to Drupal 11."]
try:
    U.verify_provenance(ROOT, forged, "forged")
except dk_core.ValidationError:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("an unquotable requirement was accepted")
print("UPGRADE_CONTEXT_QUOTES_ARE_VERIFIED=PASS")


# --- transitions are read, never derived --------------------------------------

by_id = {entry["id"]: entry for entry in CONTEXT["transitions"]}
assert set(by_id) == {"9-to-10", "10-to-11", "11-to-12"}, sorted(by_id)
for entry in CONTEXT["transitions"]:
    assert entry["to_major"] - entry["from_major"] == 1, entry["id"]

# The 11-to-12 page publishes its minimum source version as TBA. It stays
# unknown: not filled in from the release feed, not borrowed from 10-to-11, and
# not inferred from the removed-updates sentence on the same page.
twelve = by_id["11-to-12"]
assert twelve["minimum_source_version"]["state"] == "unknown"
assert twelve["minimum_source_version"]["value"] is None
assert "TBA" in twelve["minimum_source_version"]["source_text"]
assert twelve["state"] == "documented_incomplete"

# A transition that states a requirement states it exactly.
assert by_id["10-to-11"]["minimum_source_version"]["value"] == "10.3.0"
assert by_id["10-to-11"]["php_minimum"]["value"] == "8.3.0"
assert by_id["9-to-10"]["minimum_source_version"]["value"] == "9.4.0"
# The 9-to-10 page defers to the platform requirements rather than naming a PHP
# version, so no PHP floor is invented for it.
assert by_id["9-to-10"]["php_minimum"]["state"] == "not_stated_on_transition_page"
assert by_id["9-to-10"]["php_minimum"]["value"] is None
print("TRANSITION_REQUIREMENTS_ARE_SOURCED_OR_UNKNOWN=PASS")


# An unclosed removal list is never treated as closed. The 9-to-10 page says
# "This includes ..." — so matching none of the named extensions proves nothing.
assert by_id["9-to-10"]["removed_core_extensions"]["list_exhaustive"] is False
assert by_id["10-to-11"]["removed_core_extensions"]["list_exhaustive"] is True
observed = U.evaluate(
    analysis(
        "9.5.9",
        modules={"state": "known", "value": ["node", "user"]},
        themes={"state": "known", "value": ["olivero"]},
    ),
    "10.6.16",
)
api = dimension(observed, U.DIMENSION_API)
assert api["status"] == U.UNKNOWN, "an open removal list cannot produce a settled answer"
assert any("removed extensions" in item["subject"] for item in api["unknowns"])
print("OPEN_REMOVAL_LIST_STAYS_OPEN=PASS")


# The PHP matrix is per Drupal minor and covers no Drupal 9 column, so PHP
# support for a Drupal 9 minor is unknown rather than inherited from Drupal 10.
matrix = CONTEXT["php_support_matrix"]
assert matrix["granularity"] == "drupal_core_minor"
assert "9" in matrix["uncovered_majors"]
assert U.php_supported_for_minor(CONTEXT, "9.5")["state"] == U.UNKNOWN
assert U.php_supported_for_minor(CONTEXT, "10.6")["supported_php"] == ["8.1", "8.2", "8.3", "8.4"]
print("PLATFORM_MATRIX_IS_PER_MINOR=PASS")


# --- the analyzer is reused, not replaced -------------------------------------

engine_source = (ROOT / "scripts" / "dk_upgrade.py").read_text(encoding="utf-8")
assert "import dk_project_analyzer" not in engine_source
for forbidden in ("os.walk", "rglob", "glob(", "subprocess", "composer.json", "composer.lock"):
    assert forbidden not in engine_source, f"the upgrade engine must not scan projects ({forbidden})"
# Every project fact it uses is read from an analyzer profile.
assert all(path.startswith("profile.facts.") for path in U.ANALYZER_FACT_PATHS)
try:
    U.evaluate({"profile": {}, "analyzer": {"name": "something-else"}}, "11.4.6")
except U.UpgradeInputError:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("input from another producer was accepted as analyzer facts")
print("UPGRADE_INTELLIGENCE_REUSES_PROJECT_ANALYZER=PASS")


# The engine reuses the one Composer constraint implementation rather than
# growing a second dialect.
assert U.constraint_admits("11.4.6", "^11") == R.constraint_satisfied("11.4.6", "^11")
assert U.parse_version("8.x-1.17").key == S.parse_version("8.x-1.17").key
print("UPGRADE_ENGINE_REUSES_SHARED_VERSION_SEMANTICS=PASS")


# --- security remediation is not a compatibility proof ------------------------
# Both engines run on the same real end-of-life project. Remediation names a
# target that resolves advisories; the upgrade engine independently reports that
# the project cannot reach it without changes. Neither answer stands in for the
# other.

REAL_PROJECT = os.environ.get("DK_TEST_PROJECT")
if REAL_PROJECT and Path(REAL_PROJECT).is_dir():
    import dk_project_analyzer

    real = dk_project_analyzer.analyze_project(REAL_PROJECT, None).data
else:  # pragma: no cover - CI has no working copy of a real project
    real = analysis(
        "9.5.9",
        installed=[package("drupal/token", "1.11.0")],
        require={"drupal/core": "^9.3.11"},
        platform_php="7.4.0",
        custom=[
            {
                "machine_name": "legacy_module",
                "type": "module",
                "path": "web/modules/custom/legacy_module/legacy_module.info.yml",
                "core_version_requirement": "^8 || ^9",
            }
        ],
    )

remediation_target = "10.6.13"
compat = U.evaluate(real, remediation_target, ROOT)
assert compat["assessment"] != U.COMPATIBLE, (
    "a target chosen for security must not arrive pre-approved for compatibility"
)
assert compat["result_domain"] == "upgrade_compatibility"
# The upgrade assessment reaches its verdict from compatibility evidence alone:
# no advisory, severity or CVE appears anywhere in it.
payload = json.dumps(compat).lower()
for term in ("advisory", "cve-", "criticality", "sa-core", "vulnerab"):
    assert term not in payload, term
assert "not a general upgrade compatibility proof" in compat["bounds"]["security_relationship"]
print("SECURITY_REMEDIATION_NOT_GENERAL_COMPATIBILITY_PROOF=PASS")


# --- the trust boundary --------------------------------------------------------
# Every entry point runs against the real tree, and the reviewed knowledge it
# reads is byte-identical afterwards.

GUARDED = (
    "knowledge/records",
    "knowledge/context",
    "security/advisories",
    "cases/solved",
    "sources/state",
    "sources/snapshots",
    "discovery",
)


def digest(root: Path) -> dict[str, str]:
    state = {}
    for relative in GUARDED:
        base = root / relative
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file():
                state[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return state


before = digest(ROOT)
with tempfile.TemporaryDirectory() as directory:
    analysis_path = Path(directory) / "analysis.json"
    analysis_path.write_text(json.dumps(real), encoding="utf-8")
    for argv in (
        ["upgrade-evaluate", str(analysis_path), "--target", "10.6.16", "--format", "json"],
        ["upgrade-evaluate", str(analysis_path), "--target", "11.4.6"],
        ["upgrade-path", str(analysis_path), "--format", "json"],
        ["upgrade-path", str(analysis_path)],
        ["validate"],
        ["version"],
    ):
        result = subprocess.run(
            [sys.executable, str(CLI), *argv], capture_output=True, text=True, check=True
        )
        assert result.stdout
after = digest(ROOT)
assert before == after, "upgrade analysis mutated reviewed knowledge"
assert len(before) > 40, len(before)
print("UPGRADE_ANALYSIS_ZERO_KNOWLEDGE_MUTATION=PASS")


# --- the released interface advertises the contract ---------------------------

version = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True
    ).stdout
)
assert version["interfaces"]["upgrade_assessment_schema"] == U.ASSESSMENT_SCHEMA_VERSION
assert version["interfaces"]["upgrade_path_schema"] == U.PATH_SCHEMA_VERSION
engine = version["upgrade_engine"]
assert engine["name"] == U.ENGINE_NAME
assert engine["result_domain"] == U.RESULT_DOMAIN
assert engine["produces_security_findings"] is False
for key in ("execution_performed", "project_files_written", "composer_invoked"):
    assert engine[key] is False, key
assert engine["read_only"] is True
# Adding upgrade compatibility did not disturb what earlier releases advertise.
for key in ("security_advisory_schema", "security_remediation_plan_schema", "acquisition_run_schema"):
    assert key in version["interfaces"], key
print("UPGRADE_INTERFACE_ADVERTISED=PASS")


# --- no second consumer authority ----------------------------------------------
# Consumers read released Drupal Knowledge through the CLI and API. No
# integration directory may carry a second upgrade engine.

integration = ROOT / "integrations"
if integration.is_dir():
    for path in integration.rglob("*"):
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace").lower()
            assert "upgrade-evaluate" not in body, path
            assert "upgrade_engine" not in body, path
print("NO_SECOND_UPGRADE_AUTHORITY=PASS")


# --- the documentation authority set is accounted for --------------------------
# Upgrade authority is a separate functional class, declared per source exactly
# as advisory feeds are. The reviewed documentation and semantic authority set
# that earlier prompts froze at fifteen has not grown; it has been joined.


def authoritative_excluding_declared_roles(sources) -> int:
    return sum(
        1
        for source in sources
        if source["trust"] == "authoritative"
        and (source.get("security") or {}).get("role") != "advisory_feed"
        and (source.get("upgrade") or {}).get("role") != U.UPGRADE_AUTHORITY_ROLE
        and (source.get("api_lifecycle") or {}).get("role") != "api_lifecycle_authority"
        and (source.get("implementation_authority") or {}).get("role")
        != "implementation_rule_authority"
    )


assert authoritative_excluding_declared_roles(SOURCES.values()) == 15
assert len(authority) == 5
assert sorted(source["id"] for source in authority) == [
    "drupal-php-requirements",
    "drupal-upgrade-10-to-11",
    "drupal-upgrade-11-to-12",
    "drupal-upgrade-9-to-10",
    "drupal-upgrade-process-overview",
]
# Every registered source still keeps inspectable, baselined state.
state_files = {path.stem for path in dk_core.iter_json_files(ROOT / "sources" / "state")}
assert state_files == set(SOURCES), sorted(state_files ^ set(SOURCES))
for source in authority:
    sha = U.source_snapshot_sha(ROOT, source["id"])
    assert sha, source["id"]
    assert dk_core.require_snapshot(ROOT, source["id"], sha).is_file(), source["id"]
print("UPGRADE_AUTHORITY_IS_A_DECLARED_SOURCE_CLASS=PASS")
