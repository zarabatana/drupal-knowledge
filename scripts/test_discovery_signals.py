#!/usr/bin/env python3
"""Discovery signals are observations, never Drupal truth.

Every assertion here is behavioural: what the engine derives from a snapshot,
what it refuses to write, and which failures it refuses to blur together.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_acquisition
import dk_core
import dk_discovery


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"


def release_xml(short_name: str, releases: list[dict], project_type: str = "project_module") -> str:
    """Build a minimal but structurally faithful release-history document."""
    body = []
    for release in releases:
        body.append(
            "<release>"
            f"<name>{short_name} {release['version']}</name>"
            f"<version>{release['version']}</version>"
            f"<status>published</status>"
            f"<release_link>https://example.invalid/{short_name}/{release['version']}</release_link>"
            f"<date>1767941390</date>"
            "<terms><term><name>Release type</name>"
            f"<value>{release['type']}</value></term></terms>"
            f"<security>Covered by Drupal's security advisory policy</security>"
            f"<core_compatibility>{release['core']}</core_compatibility>"
            "</release>"
        )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<project xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<title>{short_name}</title>"
        f"<short_name>{short_name}</short_name>"
        f"<type>{project_type}</type>"
        f"<composer_namespace>drupal/{short_name}</composer_namespace>"
        "<project_status>published</project_status>"
        f"<releases>{''.join(body)}</releases>"
        "</project>"
    )


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dk_core.stable_json(data), encoding="utf-8")


def source_record(source_id: str, url: str, **overrides) -> dict:
    record = {
        "id": source_id,
        "title": f"Fixture {source_id}",
        "url": url,
        "fetch_url": url,
        "trust": "ecosystem",
        "enabled": True,
        "category": "fixture",
        "role": "Fixture discovery source used by discovery engine tests.",
        "collection_strategy": "change-detection",
        "expected_content_type": "xml",
        "normalization": "raw_text",
        "check_cadence_days": 7,
        "lifecycle": "active",
        "checked_on": "2026-09-08",
        "provenance": "Local test fixture.",
        "version_semantics": {},
        "discovery": {
            "role": "signal_source",
            "extraction": "project_release_xml",
            "signal_kind": "project-release",
            "independence_group": f"origin-{source_id}",
            "derived_from": None,
            "max_items": 5,
            "expected_refresh_days": 30,
            "component": {"type": "module", "name": "token", "package": "drupal/token"},
        },
    }
    for key, value in overrides.items():
        if key == "discovery":
            record["discovery"].update(value)
        else:
            record[key] = value
    return record


def build_workspace(root: Path, sources: list[dict]) -> None:
    write_json(root / "sources" / "registry.json", sources)
    write_json(
        root / "knowledge" / "records" / "sample.json",
        {"id": "drupal.fixture.sample", "value": "trusted knowledge must not change"},
    )


def fixture_document(root: Path, name: str, content: str) -> str:
    path = root / f"{name}.xml"
    path.write_text(content, encoding="utf-8")
    return path.as_uri()


BASE_RELEASES = [
    {"version": "8.x-1.17", "type": "Bug fixes", "core": "^10.3 || ^11"},
    {"version": "8.x-1.16", "type": "New features", "core": "^10.3 || ^11"},
]


# ---------------------------------------------------------------------------
# Identity, idempotence and immutability
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url = fixture_document(root, "token", release_xml("token", BASE_RELEASES))
    build_workspace(root, [source_record("fixture-ecosystem", url)])

    first = dk_discovery.discover(root, source_ids=["fixture-ecosystem"])
    assert first["results"][0]["status"] == "observed", first["results"]
    assert len(first["signals_created"]) == 2, first["signals_created"]
    assert first["trusted_knowledge_mutations"] == []

    # Discovery derives signals from the snapshot acquisition stored: the
    # discovery engine owns no downloader and no second source of truth.
    snapshot_digest = first["results"][0]["snapshot_sha256"]
    snapshot = dk_core.require_snapshot(root, "fixture-ecosystem", snapshot_digest)
    assert snapshot.is_file(), "discovery must reuse the acquisition snapshot tree"
    state = dk_acquisition.load_state(root, "fixture-ecosystem")
    assert state["content_sha256"] == snapshot_digest
    assert state["acquisition"]["engine_name"] == dk_acquisition.ENGINE_NAME
    print("DISCOVERY_REUSES_ACQUISITION_INFRASTRUCTURE=PASS")

    signal_id = sorted(first["signals_created"])[0]
    signal = dk_discovery.load_signal(root, signal_id)

    # A signal is structurally incapable of claiming to be knowledge.
    assert signal["is_trusted_knowledge"] is False
    assert signal["is_knowledge_proposal"] is False
    assert signal["can_promote_to_knowledge"] is False
    assert signal["review_required"] is True
    assert signal["source"]["discovery_channel"] == dk_discovery.DISCOVERY_CHANNEL
    assert signal["engine"]["language_model_used"] is False
    assert signal["claim"]["extraction"]["deterministic"] is True
    print("DISCOVERY_SIGNAL_NOT_TRUSTED_KNOWLEDGE=PASS")
    print("DISCOVERY_CORE_DOES_NOT_REQUIRE_LLM=PASS")

    # Re-observing the same item asserts the same thing: one signal, no churn.
    before = sorted(path.name for path in (root / "discovery" / "signals").glob("*.json"))
    stamp = (root / "discovery" / "signals" / f"{signal_id}.json").read_bytes()
    second = dk_discovery.discover(root, source_ids=["fixture-ecosystem"])
    after = sorted(path.name for path in (root / "discovery" / "signals").glob("*.json"))
    assert second["signals_created"] == [], second["signals_created"]
    assert len(second["signals_reused"]) == 2, second["signals_reused"]
    assert before == after
    assert (root / "discovery" / "signals" / f"{signal_id}.json").read_bytes() == stamp
    print("DISCOVERY_SIGNAL_CAPTURE_IDEMPOTENT=PASS")

    # Identity is a pure function of (source, item, assertion).
    assert dk_discovery.signal_identity("fixture-ecosystem", "release:8.x-1.17", "k") == \
        dk_discovery.signal_identity("fixture-ecosystem", "release:8.x-1.17", "k")
    assert dk_discovery.signal_identity("fixture-ecosystem", "release:8.x-1.17", "k") != \
        dk_discovery.signal_identity("other-source", "release:8.x-1.17", "k")


# ---------------------------------------------------------------------------
# Popularity is metadata, never authority
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    payload = {
        "list": [
            {
                "nid": "3300001",
                "title": "Cache tags are not invalidated on entity save",
                "field_issue_status": "Active",
                "field_issue_version": "8.x-1.17",
                "changed": "1767941390",
                # A wildly popular issue with no independent corroboration.
                "comment_count": 9999,
            }
        ]
    }
    path = root / "issues.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    source = source_record(
        "fixture-issues",
        path.as_uri(),
        expected_content_type="json",
        discovery={"extraction": "project_issue_json", "signal_kind": "issue"},
    )
    build_workspace(root, [source])

    run = dk_discovery.discover(root, source_ids=["fixture-issues"])
    signal = dk_discovery.load_signal(root, run["signals_created"][0])
    assert signal["popularity"]["metrics"]["comment_count"] == 9999
    assert signal["popularity"]["counts_toward_corroboration"] is False
    assert signal["popularity"]["authority_weight"] == 0

    dossier = dk_discovery.load_dossier(root, run["corroboration_results"][0]["dossier_id"])
    # 9999 comments and no independent evidence is still no evidence.
    assert dossier["corroboration_state"] == dk_discovery.INSUFFICIENT_EVIDENCE
    assert dossier["popularity_assessment"]["influenced_corroboration"] is False
    assert dossier["independence_assessment"]["independent_origin_count"] == 0
    print("POPULARITY_NOT_AUTHORITY=PASS")


# ---------------------------------------------------------------------------
# Dry run changes nothing canonical
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url = fixture_document(root, "token", release_xml("token", BASE_RELEASES))
    build_workspace(root, [source_record("fixture-ecosystem", url)])

    with tempfile.TemporaryDirectory() as scratch:
        run = dk_discovery.discover(
            root,
            source_ids=["fixture-ecosystem"],
            dry_run=True,
            normalized_dir=Path(scratch),
        )
    assert run["dry_run"] is True
    assert len(run["signals_created"]) == 2, "a dry run still reports what it would record"
    assert not (root / "discovery" / "signals").exists() or not list(
        (root / "discovery" / "signals").glob("*.json")
    )
    assert not (root / "discovery" / "review").exists() or not list(
        (root / "discovery" / "review").glob("*.json")
    )
    assert dk_acquisition.load_state(root, "fixture-ecosystem") is None
    assert not (root / "sources" / "snapshots").exists()
    assert run["trusted_knowledge_mutations"] == []
    print("DISCOVERY_DRY_RUN_HAS_NO_CANONICAL_MUTATION=PASS")


# ---------------------------------------------------------------------------
# Failure states stay distinct
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    missing = (root / "absent.xml").as_uri()
    build_workspace(root, [source_record("fixture-missing", missing)])

    run = dk_discovery.discover(root, source_ids=["fixture-missing"])
    result = run["results"][0]
    # An unreachable source is not evidence that nothing exists.
    assert result["status"] == "source_unavailable", result
    assert result["error"]["classification"] == dk_discovery.ERROR_SOURCE_UNAVAILABLE
    assert result["error"]["engine_defect"] is False
    assert result["signals_created"] == []
    assert run["failures"], "an unavailable source must be reported, not silently empty"
    assert dk_discovery.run_exit_code(run) == 1

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    # Well-formed transport, broken extraction contract.
    url = fixture_document(root, "broken", "<project><title>no releases here</title></project>")
    build_workspace(root, [source_record("fixture-broken", url)])

    run = dk_discovery.discover(root, source_ids=["fixture-broken"])
    result = run["results"][0]
    assert result["status"] == "extraction_failure", result
    assert result["error"]["classification"] == dk_discovery.ERROR_EXTRACTION
    assert result["error"]["engine_defect"] is False
    assert result["acquisition_status"] == dk_acquisition.STATUS_FIRST_OBSERVATION
    # The snapshot was still acquired: extraction failing is not fetch failing.
    assert result["snapshot_sha256"] is not None
print("DISCOVERY_FAILURE_STATES_DISTINCT=PASS")


# ---------------------------------------------------------------------------
# An engine defect is never filed as a source failure
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url = fixture_document(root, "token", release_xml("token", BASE_RELEASES))
    build_workspace(root, [source_record("fixture-ecosystem", url)])

    original = dk_discovery.extract_observations
    def exploding(text, source):  # noqa: ANN001 - deliberate fault injection
        raise ZeroDivisionError("simulated engine defect")

    dk_discovery.extract_observations = exploding
    try:
        dk_discovery.discover(root, source_ids=["fixture-ecosystem"])
    except dk_discovery.DiscoveryEngineDefect as exc:
        assert "simulated engine defect" in str(exc)
    else:
        raise AssertionError("engine defect was swallowed as a source failure")
    finally:
        dk_discovery.extract_observations = original

    # Nothing was filed as a discovery observation on the way out.
    assert not list((root / "discovery" / "signals").glob("*.json"))
print("DISCOVERY_ENGINE_DEFECT_NOT_SWALLOWED=PASS")


# ---------------------------------------------------------------------------
# Staleness is explicit, and stale is not false
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    from datetime import datetime, timedelta, timezone

    root = Path(workspace)
    url = fixture_document(root, "token", release_xml("token", BASE_RELEASES))
    build_workspace(root, [source_record("fixture-ecosystem", url)])

    observed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    dk_discovery.discover(root, source_ids=["fixture-ecosystem"], moment=observed)

    later = observed + timedelta(days=400)
    report = dk_discovery.refresh_signal_staleness(root, moment=later)
    assert report, "staleness must be inspectable"
    assert all(row["stale"] is True for row in report), report
    assert all(row["age_days"] == 400 for row in report), report
    # Stale is a freshness statement, never a truth statement: the signal keeps
    # its evidence-derived status rather than being recast as false.
    assert all(row["status"] != "dismissed" for row in report)
    for signal in dk_discovery.iter_signals(root):
        assert signal["claim"]["assertion_value"], "stale signals keep their evidence"
print("DISCOVERY_SIGNAL_STALENESS_EXPLICIT=PASS")


# ---------------------------------------------------------------------------
# Scope is bounded: authoritative tiers may not manufacture community signals
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as workspace:
    root = Path(workspace)
    url = fixture_document(root, "token", release_xml("token", BASE_RELEASES))
    build_workspace(root, [source_record("fixture-authoritative", url, trust="authoritative")])

    try:
        dk_discovery.discover(root, source_ids=["fixture-authoritative"])
    except dk_discovery.DiscoveryInputError as exc:
        assert "must not manufacture discovery signals" in str(exc)
    else:
        raise AssertionError("an authoritative source manufactured a discovery signal")

    # Unbounded discovery is not an available mode at all.
    try:
        dk_discovery.discover(root)
    except dk_discovery.DiscoveryInputError as exc:
        assert "broad unbounded discovery is not supported" in str(exc)
    else:
        raise AssertionError("discovery ran without a bounded selection")
print("DISCOVERY_SCOPE_BOUNDED=PASS")


# ---------------------------------------------------------------------------
# The CLI offers no route from a signal to trusted knowledge
# ---------------------------------------------------------------------------

# Default help is community-first, so maintainer commands are listed by
# `--help-all`. They stay reachable either way; what is checked here is that
# none of them offers a route across a trust boundary.
help_text = subprocess.run(
    [sys.executable, str(CLI), "--help-all"], capture_output=True, text=True, check=True
).stdout
for command in ("discover", "signals", "corroborate", "corroboration", "signal-review"):
    assert command in help_text, f"missing CLI command: {command}"

for command in ("discover", "signals", "corroborate", "corroboration", "signal-review"):
    text = subprocess.run(
        [sys.executable, str(CLI), command, "--help"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for forbidden in ("--promote-to-knowledge", "--trust-this", "--accept-and-update-knowledge"):
        assert forbidden not in text, f"{command} exposes {forbidden}"

engine_source = (ROOT / "scripts" / "dk_discovery.py").read_text(encoding="utf-8")
for forbidden in ("promote_to_knowledge", "trust_this", "promote-to-knowledge"):
    assert f"--{forbidden}" not in engine_source
print("DISCOVERY_NO_DIRECT_TRUST_PROMOTION_CLI=PASS")
print("TARGETED_DISCOVERY_PRESERVED=PASS")

# The released interface advertises discovery, and advertises that discovery
# output is not trusted knowledge, so a consumer can tell without reading docs.
released = json.loads(
    subprocess.run(
        [sys.executable, str(CLI), "version"], capture_output=True, text=True, check=True
    ).stdout
)
assert released["interfaces"]["discovery_signal_schema"] == dk_discovery.SIGNAL_CONTRACT_VERSION
assert (
    released["interfaces"]["corroboration_dossier_schema"]
    == dk_discovery.DOSSIER_CONTRACT_VERSION
)
assert released["interfaces"]["discovery_run_schema"] == dk_discovery.DISCOVERY_RUN_SCHEMA_VERSION
assert released["discovery_engine"]["name"] == dk_discovery.DISCOVERY_ENGINE_NAME
assert released["discovery_engine"]["channel"] == dk_discovery.DISCOVERY_CHANNEL
assert released["discovery_engine"]["produces_trusted_knowledge"] is False
# The acquisition interface is untouched by this addition.
assert released["interfaces"]["source_change_candidate_schema"] == "0.1"
assert released["acquisition_engine"]["channel"] == dk_acquisition.ACQUISITION_CHANNEL
print("DISCOVERY_RELEASED_INTERFACE_ADVERTISED=PASS")


# ---------------------------------------------------------------------------
# Behaviour comes from the registry, not from conditionals on source ids
# ---------------------------------------------------------------------------

registered = [source["id"] for source in dk_core.load_sources()]
assert registered, "the registry must not be empty"
engine = (ROOT / "scripts" / "dk_discovery.py").read_text(encoding="utf-8")
for source_id in registered:
    assert source_id not in engine, (
        f"dk_discovery.py mentions {source_id!r}: discovery behaviour must be "
        "declared in the registry, never branched on a source id"
    )

# Every registered discovery source declares the behaviour the engine reads.
discovery_sources = [
    source for source in dk_core.load_sources() if source.get("discovery") is not None
]
assert discovery_sources, "at least one discovery source must be registered"
for source in discovery_sources:
    config = source["discovery"]
    assert config["role"] in dk_discovery.DISCOVERY_ROLES
    assert config["extraction"] in dk_discovery.EXTRACTION_STRATEGIES
    assert dk_discovery.independence_group(source)
    assert dk_discovery.max_items(source) >= 1
    if config["role"] == dk_discovery.ROLE_SIGNAL_SOURCE:
        # Only tiers allowed to observe may be registered to produce signals.
        assert source["trust"] in dk_discovery.SIGNAL_SOURCE_TIERS, source["id"]

# Extraction is chosen by the registry, and an unknown strategy is refused
# rather than silently defaulted.
try:
    dk_discovery.extraction_strategy({"id": "x", "discovery": {"extraction": "guess"}})
except dk_discovery.DiscoveryInputError:
    pass
else:
    raise AssertionError("an unregistered extraction strategy was accepted")

print("DISCOVERY_SOURCE_BEHAVIOR_REGISTRY_DRIVEN=PASS")

print("DISCOVERY_SIGNAL_TESTS=PASS")
