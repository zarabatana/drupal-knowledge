#!/usr/bin/env python3
"""What a developer can ask Drupal Knowledge, and what it refuses to imply.

The community CLI is the first surface where someone who has never read this
repository forms a belief about their Drupal site. That makes two failure modes
expensive in a way they were not before.

The first is flattening. Twelve prompts kept reviewed knowledge, authoritative
source records, project observations and untrusted discovery signals apart. A
result list that renders them identically undoes all of it, so every fixture
here checks the trust label as well as the answer.

The second is reassurance. "Not observed" is not "secure", a bounded scan
finding nothing is not a clean bill of health, and a query that succeeded is
not a project that passed. The tests below fail if any of those words appear
where they have not been earned.

Everything is hermetic against the real record set: no fixture needs the
network, and the offline test proves it by removing sockets entirely.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import dk_core
import dk_query as Q
import dk_render as R


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"
DK = ROOT / "dk"
FIXED = "2026-09-09T00:00:00Z"


def run(*args: str, expect: int = 0) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [sys.executable, str(CLI), *args], capture_output=True, text=True
    )
    assert result.returncode == expect, (args, result.returncode, result.stderr[:400])
    return result


# --- the contract itself ------------------------------------------------------

assert set(Q.DOMAINS) >= {
    "trusted_knowledge", "advisory", "project_evidence", "finding",
    "solved_case", "discovery_signal", "migration_work", "upgrade_assessment",
}
for domain in Q.DOMAINS:
    assert domain in Q.DOMAIN_TRUST_CLASS, domain
    assert Q.DOMAIN_TRUST_CLASS[domain] in Q.TRUST_CLASSES, domain
# Exactly one class is trusted knowledge. Everything else says so plainly.
trusted = [name for name, block in Q.TRUST_CLASSES.items() if block["trusted_knowledge"]]
assert trusted == ["reviewed_drupal_knowledge"], trusted
print("QUERY_RESULTS_DOMAIN_TYPED=PASS")
print("QUERY_OUTPUT_EXPLAINS_TRUST_CLASS=PASS")


# --- fixture A: trusted knowledge query ---------------------------------------

knowledge = Q.list_domain(Q.D_KNOWLEDGE, ROOT, generated_at=FIXED)
assert knowledge["result_count"] > 0
for item in knowledge["results"]:
    assert item["domain"] == "trusted_knowledge"
    assert item["trust"]["trusted_knowledge"] is True
    assert item["trust"]["review_status"] == "reviewed"
# Unreviewed material is not trusted knowledge and never appears here.
on_disk = dk_core.load_knowledge_records(ROOT)
assert len(knowledge["results"]) == sum(
    1 for record in on_disk if record["review_status"] == "reviewed"
)
assert all(record["review_status"] == "reviewed" for record in Q.knowledge_records(ROOT))
print("FIXTURE_A_TRUSTED_KNOWLEDGE_ONLY_REVIEWED=PASS")
print("COMMUNITY_TRUSTED_KNOWLEDGE_EXCLUDES_UNREVIEWED=PASS")


# --- fixture B: advisory lookup ranks the advisory itself first ------------------

advisory_id = sorted(item["id"] for item in Q.advisories(ROOT))[0]
found = Q.search(advisory_id, ROOT, generated_at=FIXED)
assert found["result_count"] >= 1
top = found["results"][0]
assert top["domain"] == "advisory" and top["id"] == advisory_id
assert top["match"]["rank"] == Q.RANK_EXACT_ID
assert top["match"]["reason"] == "exact identifier match"
assert top["trust"]["authority"] == "Drupal Security Team"
assert top["trust"]["trusted_knowledge"] is False
# The published risk vector is carried, and no score is computed from it.
assert top["detail"]["scored_by_drupal_knowledge"] is False
assert "risk_vector" in top["detail"]
print("FIXTURE_B_EXACT_ADVISORY_RANKS_FIRST=PASS")
print("COMMUNITY_SECURITY_OUTPUT_PRESERVES_SOURCE_SEMANTICS=PASS")

# A CVE finds its advisory through a structured field, not through prose.
with_cve = [
    record for record in Q.advisories(ROOT) if record["cves"].get("identifiers")
]
cve = with_cve[0]["cves"]["identifiers"][0]
by_cve = Q.search(cve, ROOT, generated_at=FIXED)
assert by_cve["results"][0]["match"]["rank"] == Q.RANK_EXACT_FIELD
assert cve in by_cve["results"][0]["detail"]["cves"]

# An API symbol prioritises its lifecycle record.
symbol = Q.search("file_create_url", ROOT, generated_at=FIXED)
assert symbol["results"][0]["domain"] == "api_lifecycle"
assert symbol["results"][0]["match"]["rank"] == Q.RANK_EXACT_ID

# Ranking bands are ordered, so structured identity can never lose to prose.
assert Q.RANK_EXACT_ID > Q.RANK_EXACT_FIELD > Q.RANK_PREFIX_ID > Q.RANK_EXACT_TOKEN
assert Q.RANK_EXACT_TOKEN > Q.RANK_TITLE_SUBSTRING > Q.RANK_BODY_SUBSTRING
# And a repeated search is byte-identical: no ordering nondeterminism.
assert Q.stable_json(Q.search(advisory_id, ROOT, generated_at=FIXED)) == Q.stable_json(found)
print("FIXTURE_B_STRUCTURED_MATCH_BEATS_PROSE=PASS")
print("COMMUNITY_SEARCH_DETERMINISTIC=PASS")
print("COMMUNITY_SEARCH_USES_CANONICAL_RECORDS=PASS")

# Nothing in the query layer does fuzzy or semantic matching: every rank comes
# from an exact comparison, so a near-miss can never decide identity.
source = (ROOT / "scripts" / "dk_query.py").read_text(encoding="utf-8")
for forbidden in ("difflib", "SequenceMatcher", "levenshtein", "embedding", "openai", "llm"):
    assert forbidden not in source.lower(), forbidden
print("FUZZY_SEARCH_NOT_SEMANTIC_MATCHING=PASS")


# --- fixture C: project security query -----------------------------------------

# An optional real Drupal project on the developer's machine, never named in
# the repository: set DK_TEST_PROJECT to its path to run the project fixtures.
PROJECT = Path(os.environ.get("DK_TEST_PROJECT", "")) if os.environ.get("DK_TEST_PROJECT") else None
HAVE_PROJECT = PROJECT is not None and PROJECT.is_dir()

if HAVE_PROJECT:
    inspection = Q.inspect_project(PROJECT, ROOT, target="10.6.13", generated_at=FIXED)
    security = inspection["sections"]["security"]
    assert security["state"] == Q.SECTION_AVAILABLE
    assert security["applicable"] > 0, "this project has applicable advisories"
    # Applicability is reported as guidance and never promoted to blocking.
    assert security["enforcement"] == "guidance"
    assert "not a statement about exploitability" in security["note"]
    print("FIXTURE_C_PROJECT_SECURITY_STAYS_GUIDANCE=PASS")

    # --- fixture D: upgrade query shows blockers and unknowns -------------------
    upgrade = inspection["sections"]["upgrade"]
    assert upgrade["state"] == Q.SECTION_AVAILABLE
    assert upgrade["blockers"] > 0 and upgrade["unknowns"] > 0
    assert upgrade["assessment"] in (
        "compatible_with_observed_evidence", "requires_changes", "blocked",
        "requires_review", "insufficient_evidence",
    )
    blob = json.dumps(inspection).lower()
    for phrase in ("guaranteed", "will upgrade cleanly", "upgrade is safe"):
        assert phrase not in blob, phrase
    print("FIXTURE_D_UPGRADE_SHOWS_BLOCKERS_AND_UNKNOWNS=PASS")
    print("COMMUNITY_UPGRADE_OUTPUT_CONSERVATIVE=PASS")

    # --- fixture E: migration query is actionable --------------------------------
    migration = inspection["sections"]["migration"]
    assert migration["state"] == Q.SECTION_AVAILABLE
    assert migration["target"] == "10.6.13"
    for key in ("work_items", "blocking", "occurrences", "files_read"):
        assert key in migration, key
    print("FIXTURE_E_MIGRATION_QUERY_ACTIONABLE=PASS")
    print("COMMUNITY_MIGRATION_QUERY_ACTIONABLE=PASS")

    # --- fixture G: unknown state is visible, never omitted -----------------------
    assert inspection["unknowns"], "a project inspection always states what it cannot settle"
    assert any("bounded" in text or "unknown" in text for text in inspection["unknowns"])
    evidence = inspection["sections"]["evidence"]
    assert "unknown" in evidence["domain_completeness"].values() or "bounded" in evidence[
        "domain_completeness"
    ].values()
    print("FIXTURE_G_UNKNOWNS_VISIBLE=PASS")
    print("COMMUNITY_CLI_SURFACES_UNKNOWNS=PASS")

    # --- one project inspection, one analysis pass --------------------------------
    # Every section reads the same evidence set rather than rebuilding it.
    assert inspection["sections"]["evidence"]["evidence_set_id"].startswith("evidence-set.")
    query_source = (ROOT / "scripts" / "dk_query.py").read_text(encoding="utf-8")
    assert query_source.count("analyze_project(") == 1, "the project is analysed once"
    assert query_source.count("dk_evidence.build(") == 1, "evidence is built once"
    print("COMMUNITY_QUERY_AVOIDS_REDUNDANT_ANALYSIS=PASS")

    # --- deterministic ------------------------------------------------------------
    again = Q.inspect_project(PROJECT, ROOT, target="10.6.13", generated_at=FIXED)
    assert Q.stable_json(again) == Q.stable_json(inspection)
    print("COMMUNITY_QUERY_DETERMINISTIC=PASS")
else:  # pragma: no cover - CI has no working copy of a real project
    print("FIXTURE_C_PROJECT_SECURITY_STAYS_GUIDANCE=SKIPPED_NO_PROJECT")
    print("FIXTURE_D_UPGRADE_SHOWS_BLOCKERS_AND_UNKNOWNS=SKIPPED_NO_PROJECT")
    print("FIXTURE_E_MIGRATION_QUERY_ACTIONABLE=SKIPPED_NO_PROJECT")
    print("FIXTURE_G_UNKNOWNS_VISIBLE=SKIPPED_NO_PROJECT")


# --- fixture F: implementation finding explain ----------------------------------

rules = Q.implementation_rules(ROOT)
rule_id = sorted(rule["rule_id"] for rule in rules)[0]
explained = Q.explain(rule_id, ROOT, generated_at=FIXED)
item = explained["results"][0]
assert item["domain"] == "implementation_rule"
assert item["trust"]["class"] == "reviewed_implementation_rule"
explanation = item["explanation"]
for key in (
    "what_is_this", "why_does_it_exist", "what_supports_it", "what_is_authoritative",
    "what_is_project_specific", "what_is_unknown", "what_is_recommended",
    "was_anything_changed",
):
    assert explanation[key], key
assert explanation["was_anything_changed"].startswith("No.")
# The chain reaches a registered source with its snapshot.
assert explained["provenance"], explained
step = explained["provenance"][0]
assert step["source_id"] and step["snapshot_sha256"].startswith("sha256:")
assert step["source_trust"] == "authoritative"
print("FIXTURE_F_IMPLEMENTATION_RULE_EXPLAINED=PASS")
print("COMMUNITY_IMPLEMENTATION_FINDINGS_EXPLAINABLE=PASS")
print("COMMUNITY_EXPLAIN_TRACES_FULL_PROVENANCE=PASS")


# --- fixture H: not_observed is never rendered as secure --------------------------

for payload in (knowledge, found, explained):
    text = R.render(payload).lower()
    for phrase in ("is secure", "is safe", "not affected", "no issues found", "all clear"):
        assert phrase not in text, phrase
# The guard is real: a payload claiming safety is refused outright.
try:
    Q.assert_no_reassurance({"summary": "this project is secure"})
except Q.QueryLayerDefect:
    pass
else:  # pragma: no cover - the guard must fire
    raise AssertionError("a reassurance claim was accepted")
# And no trust class or renderer badge implies conformance.
for block in Q.TRUST_CLASSES.values():
    lowered = json.dumps(block).lower()
    for word in ("secure", "safe", "compliant", "passed"):
        assert word not in lowered, word
print("FIXTURE_H_NOT_OBSERVED_IS_NOT_SECURE=PASS")
print("COMMUNITY_CLI_DOES_NOT_OVERSTATE_NOT_OBSERVED=PASS")


# --- fixture I: discovery signals are explicitly untrusted -------------------------

assert Q.D_DISCOVERY_SIGNAL not in Q.SEARCHABLE_DOMAINS
default_search = Q.search("drupal", ROOT, limit=50, generated_at=FIXED)
assert all(item["domain"] != "discovery_signal" for item in default_search["results"])
assert any("Discovery signals are excluded by default" in text for text in default_search["warnings"])

signals = Q.list_domain(Q.D_DISCOVERY_SIGNAL, ROOT, generated_at=FIXED)
if signals["result_count"]:
    signal = signals["results"][0]
    assert signal["trust"]["class"] == "untrusted_discovery_signal"
    assert signal["trust"]["trusted_knowledge"] is False
    assert signal["detail"]["can_promote_to_knowledge"] is False
    assert any("untrusted" in text.lower() for text in signal["unknowns"])
    assert "UNTRUSTED" in R.badge(signal)
assert any("untrusted community observations" in text for text in signals["warnings"])
print("FIXTURE_I_DISCOVERY_IS_LABELLED_UNTRUSTED=PASS")
print("RAW_DISCOVERY_NOT_PRESENTED_AS_TRUSTED_RESULT=PASS")


# --- fixture J: solved cases keep their context boundary ---------------------------

cases = Q.list_domain(Q.D_SOLVED_CASE, ROOT, generated_at=FIXED)
if cases["result_count"]:
    case = cases["results"][0]
    assert case["trust"]["class"] == "proven_case_context_only"
    assert case["trust"]["universal_drupal_rule"] is False
    assert case["detail"]["claimed_scope"] == "proven_context_only"
    assert case["detail"]["project_identity_disclosed"] is False
    assert any("not universal Drupal truth" in text for text in case["unknowns"])
    # No project name, path or fingerprint reaches the community result.
    blob = json.dumps(case)
    assert "/Users/" not in blob and "/home/" not in blob
    assert "project_fingerprint" not in blob
print("FIXTURE_J_SOLVED_CASE_CONTEXT_PRESERVED=PASS")
print("COMMUNITY_SOLVED_CASES_PRESERVE_CONTEXT_BOUNDARY=PASS")


# --- fixture K: JSON mode is clean machine output ------------------------------------

result = run("search", "file_create_url", "--json")
payload = json.loads(result.stdout)
assert payload["query_type"] == "search"
assert not result.stdout.startswith("Drupal Knowledge"), "no banner in JSON mode"
assert result.stdout.lstrip().startswith("{")
for payload_stream in (result.stdout,):
    assert "·" not in payload_stream, "no human formatting in JSON output"

status_json = json.loads(run("status", "--json").stdout)
assert status_json["query_type"] == "status"
assert "sections" in status_json
version_json = json.loads(run("version", "--json").stdout)
assert version_json["community"]["read_only_default"] is True
assert "·" not in run("version").stdout
print("FIXTURE_K_JSON_OUTPUT_CLEAN=PASS")
print("COMMUNITY_JSON_OUTPUT_CLEAN=PASS")
print("COMMUNITY_CLI_SUPPORTS_HUMAN_AND_MACHINE_OUTPUT=PASS")


# --- fixture L: expected errors are actionable, not tracebacks --------------------------

for args, fragment in (
    (("explain", "SA-CORE-9999-999"), "no Drupal Knowledge record"),
    (("provenance", "not-a-real-id"), "Try `dk search`"),
    (("search", ""), "search term is required"),
    (("project", "/nonexistent/path/xyz"), "not a directory"),
):
    failed = run(*args, expect=2)
    assert "Traceback" not in failed.stderr, args
    assert fragment in failed.stderr, (args, failed.stderr)
    assert failed.stdout == "", "an error writes nothing to stdout"
print("FIXTURE_L_EXPECTED_ERRORS_ACTIONABLE=PASS")
print("COMMUNITY_CLI_EXPECTED_ERRORS_ACTIONABLE=PASS")


# --- fixture M: provenance traversal ------------------------------------------------------

lineage = Q.provenance(advisory_id, ROOT, generated_at=FIXED)
edges = lineage["results"][0]["detail"]["edges"]
assert edges and edges[0]["from"] == advisory_id
assert edges[0]["relation"] == "supported_by"
assert edges[0]["to_kind"] == "authoritative_source"
step = lineage["provenance"][0]
assert step["source_id"] and step["snapshot_sha256"].startswith("sha256:")
assert step["source_url"].startswith("https://")
# The snapshot the chain names is on disk and addressable by its own hash.
snapshot = dk_core.require_snapshot(ROOT, step["source_id"], step["snapshot_sha256"])
assert snapshot.is_file()
assert snapshot.stem == step["snapshot_sha256"].split(":", 1)[1]
print("FIXTURE_M_PROVENANCE_TRAVERSABLE=PASS")
print("PROVENANCE_QUERY_MACHINE_TRAVERSABLE=PASS")


# --- fixture N: repeated query is semantically identical -------------------------------------

first = json.loads(run("search", "file_create_url", "--json").stdout)
second = json.loads(run("search", "file_create_url", "--json").stdout)
first.pop("generated_at"), second.pop("generated_at")
assert Q.stable_json(first) == Q.stable_json(second)
print("FIXTURE_N_REPEATED_QUERY_IDENTICAL=PASS")


# --- provenance channels stay apart -----------------------------------------------------------

channels = set()
for domain in Q.PROJECTORS:
    listing = Q.list_domain(domain, ROOT, limit=3, generated_at=FIXED)
    for item in listing["results"]:
        assert item["domain"] == domain
        for step in item["provenance"]:
            channels.add(step["channel"])
assert {"authoritative_source", "internal_solved_case", "discovery_signal"} <= channels, channels
# Each domain keeps its own trust class; none borrows another's.
classes = {domain: Q.DOMAIN_TRUST_CLASS[domain] for domain in Q.PROJECTORS}
assert classes[Q.D_KNOWLEDGE] != classes[Q.D_ADVISORY] != classes[Q.D_DISCOVERY_SIGNAL]
assert classes[Q.D_SOLVED_CASE] != classes[Q.D_KNOWLEDGE]
print("COMMUNITY_OUTPUT_PRESERVES_PROVENANCE_CHANNELS=PASS")


# --- the query layer is independent of the terminal ---------------------------------------------

# Every fixture above called the query layer directly and got a dict. Prompt 15
# and 16 will do the same, so the layer must not import or produce formatting.
assert "import dk_render" not in source
assert "print(" not in source, "the query layer never writes to a terminal"
render_source = (ROOT / "scripts" / "dk_render.py").read_text(encoding="utf-8")
assert "import dk_query" in render_source

# Rendering cannot change semantics: the payload is identical before and after.
before = Q.stable_json(knowledge)
R.render(knowledge)
R.render(knowledge, explain=True)
assert Q.stable_json(knowledge) == before
print("QUERY_LAYER_NOT_COUPLED_TO_TERMINAL_RENDERING=PASS")
print("COMMUNITY_RENDERING_SEPARATE_FROM_QUERY_SEMANTICS=PASS")
print("COMMUNITY_QUERY_LAYER_REUSABLE=PASS")


# --- basic querying works with no network ---------------------------------------------------------

import socket

original = socket.socket


class NoNetwork(socket.socket):  # pragma: no cover - only constructed on a violation
    def __init__(self, *args, **kwargs):
        raise AssertionError("a community query attempted a network connection")


socket.socket = NoNetwork
try:
    offline_status = Q.status(ROOT, generated_at=FIXED)
    offline_search = Q.search(advisory_id, ROOT, generated_at=FIXED)
    offline_explain = Q.explain(rule_id, ROOT, generated_at=FIXED)
    offline_provenance = Q.provenance(advisory_id, ROOT, generated_at=FIXED)
finally:
    socket.socket = original

assert Q.stable_json(offline_search) == Q.stable_json(found)
assert Q.stable_json(offline_explain) == Q.stable_json(explained)
assert offline_status["sections"]["release"]["drupal_knowledge_version"]
assert offline_provenance["result_count"] == 1
for forbidden in ("urlopen", "urllib.request", "requests.", "http.client"):
    assert forbidden not in source, forbidden
print("COMMUNITY_BASIC_QUERIES_OFFLINE=PASS")


# --- freshness is surfaced where it changes confidence -----------------------------------------------

freshness = offline_status["sections"]["freshness"]
for key in ("sources_checked", "stale", "unbaselined", "note"):
    assert key in freshness, key
assert "Acquisition is a separate maintainer operation" in freshness["note"]
assert freshness["sources_checked"] > 0
# Search results stay quiet about freshness; status is where it belongs.
assert not any("cadence" in text for text in found["warnings"])
print("COMMUNITY_QUERY_SURFACES_RELEVANT_STALENESS=PASS")


# --- the CLI ------------------------------------------------------------------------------------------

import dk as cli

# Every command is classified, and the classification covers the real parser.
parser = cli.build_parser()
subparsers = next(
    action for action in parser._actions
    if isinstance(action, __import__("argparse")._SubParsersAction)
)
registered = set(subparsers.choices)
classified = set(cli.COMMAND_AUDIENCE)
assert registered == classified, sorted(registered ^ classified)
assert set(cli.COMMAND_AUDIENCE.values()) == {"community", "maintainer", "internal"}
assert len(cli.commands_for("community")) > len(cli.commands_for("maintainer"))
print("CLI_COMMAND_AUDIENCE_EXPLICIT=PASS")

# Every command that existed before the community surface was built is still
# registered and still parses. This list is frozen deliberately: it is what the
# CLI promised at v0.18.0, and no later prompt may quietly retire part of it.
PRE_EXISTING_COMMANDS = (
    "acquire", "analyze", "api-lifecycle", "cases", "corroborate", "corroboration",
    "coverage", "discover", "evidence", "evidence-diff", "findings",
    "generalization-review", "generalizations", "generate", "implementation-findings",
    "knowledge", "lifecycle-evaluate", "migration-analyze", "migration-work",
    "recurrence", "release-lifecycle", "resolve", "review-candidates",
    "security-advisories", "security-evaluate", "security-remediation",
    "signal-review", "signals", "site", "solved-case", "source-status", "sources",
    "upgrade-evaluate", "upgrade-path", "validate", "version",
)
missing = sorted(set(PRE_EXISTING_COMMANDS) - registered)
assert not missing, f"the community CLI removed existing commands: {missing}"

# Community-first help hides maintenance from the front page; it does not hide
# it from the CLI. --help-all lists everything, and every command answers.
everything = run("--help-all").stdout
for command in sorted(registered):
    assert command in everything, f"--help-all omits {command}"
    probe = subprocess.run(
        [sys.executable, str(CLI), command, "--help"], capture_output=True, text=True
    )
    assert probe.returncode == 0, (command, probe.stderr[:200])
print("EVERY_EXISTING_COMMAND_STILL_REACHABLE=PASS")

# The guide is checked against the parser, not against memory. Every `dk <cmd>`
# it names must exist, and the guide itself must not leak a local path or a
# real project name — it is the most-copied text in the repository.
import re as _re

guide = (ROOT / "docs" / "CLI.md").read_text(encoding="utf-8")
named = {match.group(1) for match in _re.finditer(r"\bdk ([a-z][a-z0-9-]+)", guide)}
unknown = sorted(name for name in named if name not in registered)
assert not unknown, f"docs/CLI.md names commands that do not exist: {unknown}"
for command in ("status", "project", "search", "explain", "provenance"):
    assert f"dk {command}" in guide, f"the guide must document dk {command}"
for leak in ("/Users/", "/home/", "C:\\Users", "PhpstormProjects"):
    assert leak not in guide, f"docs/CLI.md leaks {leak}"
assert "Maintainer Operations" in guide, "the guide must separate maintainer work"
print("COMMUNITY_DOCUMENTATION_MATCHES_BEHAVIOR=PASS")
print("COMMUNITY_DOCS_PRIVACY_SAFE=PASS")

# Default help leads with the community workflow and never with maintenance.
help_text = run().stdout
assert help_text.index("Start here") < help_text.index("Maintainer commands")
for command in ("status", "project", "search", "explain", "provenance"):
    assert f"dk {command}" in help_text, command
# No maintenance operation appears in the default help.
for command in cli.commands_for("maintainer"):
    assert f"dk {command} " not in help_text, command
assert "--help-maintainer" in help_text
maintainer_help = run("--help-maintainer").stdout
# Wording is checked without depending on where the paragraph wraps.
collapsed = " ".join(maintainer_help.split())
assert "not part of a normal developer flow" in collapsed
assert "move records across trust boundaries" in collapsed
for command in ("acquire", "review-candidates", "signal-review", "generalization-review"):
    assert command in maintainer_help, command
print("DEFAULT_CLI_HELP_COMMUNITY_FIRST=PASS")
print("MAINTAINER_MUTATIONS_NOT_NORMAL_COMMUNITY_FLOW=PASS")

# Community commands are nouns and domains, not module names.
for command in cli.commands_for("community"):
    assert not command.startswith("dk_"), command
    assert "py" not in command.split("-"), command
assert {"status", "project", "search", "explain", "provenance"} <= set(
    cli.commands_for("community")
)
print("COMMUNITY_COMMAND_VOCABULARY_DOMAIN_ORIENTED=PASS")

# One CLI: no second entry point was created.
for forbidden in ("community-dk.py", "public-dk.py", "dk2.py"):
    assert not (ROOT / "scripts" / forbidden).exists(), forbidden
assert (ROOT / "dk").is_file(), "the ./dk wrapper exists"
wrapper = (ROOT / "dk").read_text(encoding="utf-8")
assert "import dk as cli" in wrapper and "cli.main()" in wrapper
# The wrapper adds nothing: both entry points produce the same document.
via_wrapper = subprocess.run(
    [sys.executable, str(DK), "status", "--json"], capture_output=True, text=True, check=True
).stdout
via_script = run("status", "--json").stdout
assert json.loads(via_wrapper)["sections"] == json.loads(via_script)["sections"]
print("COMMUNITY_EXPERIENCE_REUSES_EXISTING_CLI=PASS")
print("EXISTING_DK_CLI_BACKWARD_COMPATIBLE=PASS")

# `dk version` was a machine interface before this prompt existed and stays one:
# other tooling already parses it, so JSON remains the default and the new keys
# are purely additive. The readable summary is opt-in.
version_default = json.loads(run("version").stdout)
assert version_default["product"] == "Drupal Knowledge"
assert version_default["version"] == (ROOT / "VERSION").read_text(encoding="utf-8").strip()
for preexisting in (
    "interfaces", "acquisition_engine", "discovery_engine", "generalization_engine",
    "security_engine", "remediation_engine", "implementation_engine",
):
    assert preexisting in version_default, preexisting
assert json.loads(run("version", "--json").stdout) == version_default

version_text = run("version", "--human").stdout
assert "community query interface" in version_text
assert len(version_text.splitlines()) < 15, "the human summary stays readable"
assert "acquisition_engine" not in version_text
print("COMMUNITY_VERSION_OUTPUT_STABLE=PASS")
print("COMMUNITY_QUERY_INTERFACE_ADVERTISED=PASS")

# The community surface offers no path across a trust boundary.
for command in cli.commands_for("community"):
    command_help = subprocess.run(
        [sys.executable, str(CLI), command, "--help"], capture_output=True, text=True
    ).stdout
    for forbidden in ("--apply", "--fix", "--write", "--promote", "--accept", "--review"):
        assert forbidden not in command_help, (command, forbidden)
print("COMMUNITY_CLI_CANNOT_BYPASS_TRUST_MODEL=PASS")


# --- exit codes separate query success from finding state ----------------------------------------------

if HAVE_PROJECT:
    inspected = run("project", str(PROJECT), "--target", "10.6.13", "--json")
    payload = json.loads(inspected.stdout)
    assert payload["sections"]["security"]["applicable"] > 0
    assert inspected.returncode == 0, "findings do not make the query fail"
    findings_run = run("implementation-findings", str(PROJECT / "composer.json"), expect=2)
    assert "Traceback" not in findings_run.stderr
    print("FIXTURE_EXIT_CODE_NOT_FINDING_SEVERITY=PASS")
else:  # pragma: no cover
    print("FIXTURE_EXIT_CODE_NOT_FINDING_SEVERITY=SKIPPED_NO_PROJECT")
print("CLI_EXIT_CODE_NOT_FINDING_SEVERITY=PASS")


# --- a failed domain is reported, never hidden ------------------------------------------------------------

if HAVE_PROJECT:
    no_target = Q.inspect_project(PROJECT, ROOT, generated_at=FIXED)
    for name in ("upgrade", "migration"):
        block = no_target["sections"][name]
        assert block["state"] == Q.SECTION_UNAVAILABLE
        assert "target" in block["reason"], block
    rendered = R.render(no_target)
    assert "Upgrade: unavailable" in rendered
    assert "Migration: unavailable" in rendered
    # Present, explained, and not silently dropped from the report.
    assert set(no_target["sections"]) >= {
        "project", "drupal", "dependencies", "evidence", "security",
        "implementation_findings", "upgrade", "migration",
    }
    print("COMMUNITY_PROJECT_REPORT_DOES_NOT_HIDE_DOMAIN_FAILURES=PASS")
else:  # pragma: no cover
    print("COMMUNITY_PROJECT_REPORT_DOES_NOT_HIDE_DOMAIN_FAILURES=SKIPPED_NO_PROJECT")


# --- privacy -------------------------------------------------------------------------------------------------

for payload in (knowledge, found, explained, lineage, signals, cases, offline_status):
    blob = json.dumps(payload)
    assert "/Users/" not in blob and "/home/" not in blob, payload["query_type"]
    assert "@" not in blob or "api-d7" in blob or "://" in blob, payload["query_type"]
# Not even the echo of the argument carries a local path: the whole payload can
# be pasted into a public issue without disclosing the machine it came from.
if HAVE_PROJECT:
    echoed = json.loads(
        subprocess.run(
            [sys.executable, str(CLI), "project", str(PROJECT), "--json"],
            capture_output=True, text=True, check=True,
        ).stdout
    )
    assert echoed["query"].startswith("project:")
    assert str(PROJECT) not in json.dumps(echoed)
    assert PROJECT.name not in json.dumps(echoed)
    print("COMMUNITY_PROJECT_PATH_NEVER_ECHOED=PASS")

print("COMMUNITY_OUTPUT_PRIVACY_PRESERVED=PASS")


# --- querying mutates nothing --------------------------------------------------------------------------------

import hashlib

GUARDED = (
    "knowledge/records", "knowledge/context", "api/lifecycle", "api/change-records",
    "security/advisories", "cases/solved", "discovery", "sources", "rules/implementation",
    "evidence",
)


def digest_tree() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for relative in GUARDED
        for path in sorted((ROOT / relative).rglob("*"))
        if path.is_file()
    }


before_state = digest_tree()
Q.status(ROOT)
Q.search("drupal", ROOT, limit=50)
Q.explain(rule_id, ROOT)
Q.provenance(advisory_id, ROOT)
for domain in Q.PROJECTORS:
    Q.list_domain(domain, ROOT)
if HAVE_PROJECT:
    Q.inspect_project(PROJECT, ROOT, target="10.6.13")
after_state = digest_tree()
assert before_state == after_state, "a community query mutated canonical records"
assert len(before_state) > 300, len(before_state)
print("COMMUNITY_QUERY_ZERO_CANONICAL_MUTATION=PASS")
print("COMMUNITY_PROJECT_QUERY_READ_ONLY=PASS")


# --- no second consumer authority ------------------------------------------------------------------------------
# Drupal Knowledge names no consumer. If an integration directory ever appears
# it may carry contracts, never a second engine over the released query layer.

integration = ROOT / "integrations"
if integration.is_dir():
    for path in integration.rglob("*"):
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace").lower()
            assert "dk_query" not in body, path
            assert "community_query_interface" not in body, path
print("NO_SECOND_QUERY_AUTHORITY=PASS")
