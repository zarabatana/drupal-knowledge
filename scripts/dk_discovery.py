#!/usr/bin/env python3
"""Ecosystem discovery and deterministic corroboration for Drupal Knowledge.

This module adds one evidence channel on top of the released v0.9 acquisition
engine. It owns no downloader of its own: every byte a signal is derived from
was fetched, normalized, hashed and stored by :mod:`dk_acquisition`, and is
read back out of the immutable snapshot tree.

The boundaries this module exists to defend:

    discovery signal != source snapshot != trusted knowledge
                     != solved case    != finding

A signal means "something potentially useful was observed". A corroborated
dossier means "independent evidence agrees, and a human should look". Neither
is Drupal truth, and nothing here may write into ``knowledge/``.

Popularity is recorded because it is observable and ignored because it is not
authority. No language model participates in observing, extracting, matching or
classifying evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import dk_acquisition
import dk_core


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------

DISCOVERY_ENGINE_NAME = "drupal-knowledge-discovery-engine"
CORROBORATION_ENGINE_NAME = "drupal-knowledge-corroboration-engine"
DISCOVERY_ENGINE_VERSION = "0.1"
SIGNAL_CONTRACT_VERSION = "0.2"
DOSSIER_CONTRACT_VERSION = "0.1"
DISCOVERY_RUN_SCHEMA_VERSION = "0.1"

# Discovery evidence is a different provenance channel from authoritative
# source acquisition and from internal-proven solved cases. The three never
# share a channel label.
DISCOVERY_CHANNEL = "external_discovery_source"
ACQUISITION_CHANNEL = dk_acquisition.ACQUISITION_CHANNEL
SOLVED_CASE_CHANNEL = "internal_proven_solved_case"

SIGNALS_RELATIVE_PATH = Path("discovery") / "signals"
DOSSIERS_RELATIVE_PATH = Path("discovery") / "review"


# ---------------------------------------------------------------------------
# Signal lifecycle
# ---------------------------------------------------------------------------

SIGNAL_OBSERVED = "observed"
SIGNAL_CORROBORATION_PENDING = "corroboration_pending"
SIGNAL_CORROBORATED = "corroborated"
SIGNAL_CONTRADICTED = "contradicted"
SIGNAL_INSUFFICIENT = "insufficient_evidence"
SIGNAL_DISMISSED = "dismissed"
SIGNAL_STALE = "stale"

SIGNAL_STATUSES = (
    SIGNAL_OBSERVED,
    SIGNAL_CORROBORATION_PENDING,
    SIGNAL_CORROBORATED,
    SIGNAL_CONTRADICTED,
    SIGNAL_INSUFFICIENT,
    SIGNAL_DISMISSED,
    SIGNAL_STALE,
)

SIGNAL_KINDS = (
    "issue",
    "discussion",
    "blog",
    "forum",
    "reddit",
    "source-change",
    "project-release",
    "project-metadata",
)


# ---------------------------------------------------------------------------
# Corroboration lifecycle
# ---------------------------------------------------------------------------

CORROBORATED = "corroborated"
PARTIALLY_CORROBORATED = "partially_corroborated"
CONTRADICTED = "contradicted"
INSUFFICIENT_EVIDENCE = "insufficient_evidence"
NOT_APPLICABLE = "not_applicable"

CORROBORATION_STATES = (
    CORROBORATED,
    PARTIALLY_CORROBORATED,
    CONTRADICTED,
    INSUFFICIENT_EVIDENCE,
    NOT_APPLICABLE,
)

REVIEW_PENDING = "pending_review"
REVIEW_NO_ACTION = "no_action"
REVIEW_WATCH = "watch"
REVIEW_NEEDS_MORE_EVIDENCE = "needs_more_evidence"
REVIEW_PROPOSAL_CANDIDATE = "candidate_for_future_knowledge_proposal"
REVIEW_DISMISSED = "dismissed"

REVIEW_STATES = (
    REVIEW_PENDING,
    REVIEW_NO_ACTION,
    REVIEW_WATCH,
    REVIEW_NEEDS_MORE_EVIDENCE,
    REVIEW_PROPOSAL_CANDIDATE,
    REVIEW_DISMISSED,
)

REVIEW_OUTCOMES = (
    REVIEW_NO_ACTION,
    REVIEW_WATCH,
    REVIEW_NEEDS_MORE_EVIDENCE,
    REVIEW_PROPOSAL_CANDIDATE,
    REVIEW_DISMISSED,
)

# Only this outcome authorises later, explicit knowledge-proposal work. It is
# an authorisation to do reviewed work, never a knowledge mutation.
REVIEW_AUTHORIZING_OUTCOMES = frozenset({REVIEW_PROPOSAL_CANDIDATE})

REVIEW_METHODS = frozenset(
    {"human_signal_review", "human_security_review", "human_editorial_review"}
)

# Signal status implied by a terminal review outcome.
REVIEW_OUTCOME_TO_SIGNAL_STATUS = {
    REVIEW_DISMISSED: SIGNAL_DISMISSED,
}


# ---------------------------------------------------------------------------
# Evidence channels
# ---------------------------------------------------------------------------

CHANNEL_AUTHORITATIVE = "authoritative_source"
CHANNEL_INDUSTRY = "industry_standard_source"
CHANNEL_ECOSYSTEM = "ecosystem_source"
CHANNEL_DISCOVERY = "discovery_source"
CHANNEL_SOLVED_CASE = "internal_proven_solved_case"
CHANNEL_TRUSTED_KNOWLEDGE = "trusted_knowledge"

TRUST_TO_CHANNEL = {
    "authoritative": CHANNEL_AUTHORITATIVE,
    "industry-standard": CHANNEL_INDUSTRY,
    "ecosystem": CHANNEL_ECOSYSTEM,
    "discovery": CHANNEL_DISCOVERY,
    "internal-proven": CHANNEL_SOLVED_CASE,
}

RELATION_SUPPORTS = "supports"
RELATION_CONTRADICTS = "contradicts"
RELATION_DUPLICATE = "duplicate"
RELATION_SCOPE_MISMATCH = "scope_mismatch"

ALIGNED = "aligned"
PARTIALLY_ALIGNED = "partially_aligned"
MISMATCHED = "mismatched"
UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Registry-driven discovery behaviour
# ---------------------------------------------------------------------------

ROLE_SIGNAL_SOURCE = "signal_source"
ROLE_EVIDENCE_SOURCE = "evidence_source"
DISCOVERY_ROLES = (ROLE_SIGNAL_SOURCE, ROLE_EVIDENCE_SOURCE)

EXTRACTION_PROJECT_RELEASE_XML = "project_release_xml"
EXTRACTION_PROJECT_ISSUE_JSON = "project_issue_json"
EXTRACTION_STRATEGIES = (
    EXTRACTION_PROJECT_RELEASE_XML,
    EXTRACTION_PROJECT_ISSUE_JSON,
)

DEFAULT_MAX_ITEMS = 10
MAX_ITEMS_CEILING = 200

# Tiers a signal may originate from. Authoritative and industry-standard
# sources contribute evidence, but discovery does not manufacture community
# signals out of them.
SIGNAL_SOURCE_TIERS = frozenset({"ecosystem", "discovery"})

SIGNAL_ID_RE = re.compile(r"^signal\.drupal\.[a-z0-9.-]+$")
DOSSIER_ID_RE = re.compile(r"^corroboration\.drupal\.[a-z0-9.-]+$")

# Popularity metrics are stored verbatim under this key and are structurally
# excluded from corroboration strength.
POPULARITY_RATIONALE = (
    "Popularity metrics are recorded as observable metadata and are excluded "
    "from corroboration strength. Corroboration counts independent evidence "
    "origins only."
)


class DiscoveryInputError(RuntimeError):
    """Caller asked for something the registry does not describe."""


class DiscoveryError(RuntimeError):
    """Base class for failures attributable to an external discovery source."""


class SignalExtractionError(DiscoveryError):
    """The source was acquired but its signal-extraction contract failed."""


class DiscoveryEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as a source failure."""


ERROR_SOURCE_UNAVAILABLE = "external_source_unavailable"
ERROR_SOURCE_CONTRACT = "external_source_contract_failure"
ERROR_EXTRACTION = "signal_extraction_failure"
ERROR_ENGINE_DEFECT = "discovery_engine_defect"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def now_iso(moment: datetime | None = None) -> str:
    return dk_acquisition.now_iso(moment)


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def fingerprint(*parts: Any) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(str(part).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def discovery_config(source: dict) -> dict | None:
    """Return the registry-declared discovery behaviour for a source."""
    config = source.get("discovery")
    if config is None:
        return None
    if not isinstance(config, dict):
        raise DiscoveryInputError(f"source {source.get('id')!r}: discovery must be an object")
    return config


def discovery_role(source: dict) -> str | None:
    config = discovery_config(source)
    if config is None:
        return None
    role = config.get("role", ROLE_SIGNAL_SOURCE)
    if role not in DISCOVERY_ROLES:
        raise DiscoveryInputError(f"source {source['id']}: invalid discovery role {role!r}")
    return role


def extraction_strategy(source: dict) -> str:
    config = discovery_config(source) or {}
    strategy = config.get("extraction")
    if strategy not in EXTRACTION_STRATEGIES:
        raise DiscoveryInputError(
            f"source {source.get('id')!r}: unsupported discovery extraction {strategy!r}"
        )
    return strategy


def independence_group(source: dict) -> str:
    """Evidence lineage bucket.

    Sources sharing a group are not independent of one another: two drupal.org
    endpoints agreeing is one origin, not two.
    """
    config = discovery_config(source) or {}
    group = config.get("independence_group")
    if not group:
        raise DiscoveryInputError(
            f"source {source.get('id')!r}: discovery sources must declare independence_group"
        )
    if not isinstance(group, str):
        raise DiscoveryInputError(f"source {source.get('id')!r}: independence_group must be a string")
    return group


def derived_from(source: dict) -> str | None:
    config = discovery_config(source) or {}
    value = config.get("derived_from")
    if value is not None and not isinstance(value, str):
        raise DiscoveryInputError(f"source {source.get('id')!r}: derived_from must be a string or null")
    return value


def max_items(source: dict) -> int:
    config = discovery_config(source) or {}
    value = config.get("max_items", DEFAULT_MAX_ITEMS)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > MAX_ITEMS_CEILING:
        raise DiscoveryInputError(
            f"source {source.get('id')!r}: max_items must be an integer in 1..{MAX_ITEMS_CEILING}"
        )
    return value


def expected_refresh_days(source: dict) -> int | None:
    config = discovery_config(source) or {}
    value = config.get("expected_refresh_days")
    if value is None:
        return dk_acquisition.check_cadence_days(source)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise DiscoveryInputError(
            f"source {source.get('id')!r}: expected_refresh_days must be a positive integer"
        )
    return value


def declared_component(source: dict) -> dict:
    config = discovery_config(source) or {}
    component = config.get("component") or {}
    if not isinstance(component, dict):
        raise DiscoveryInputError(f"source {source.get('id')!r}: component must be an object")
    kind = component.get("type", "unknown")
    if kind not in {"core", "module", "theme", "package", "unknown"}:
        raise DiscoveryInputError(f"source {source.get('id')!r}: invalid component type {kind!r}")
    return {
        "type": kind,
        "name": component.get("name"),
        "package": component.get("package"),
    }


def signal_kind(source: dict) -> str:
    config = discovery_config(source) or {}
    kind = config.get("signal_kind")
    if kind is None:
        strategy = extraction_strategy(source)
        kind = "project-release" if strategy == EXTRACTION_PROJECT_RELEASE_XML else "issue"
    if kind not in SIGNAL_KINDS:
        raise DiscoveryInputError(f"source {source.get('id')!r}: invalid signal_kind {kind!r}")
    return kind


def select_discovery_sources(
    root: Path,
    *,
    source_ids: Iterable[str] | None = None,
    trust: str | None = None,
    role: str = ROLE_SIGNAL_SOURCE,
    include_disabled: bool = False,
) -> list[dict]:
    """Pick registered discovery sources without ever branching on a source id."""
    registry = {source["id"]: source for source in dk_acquisition.load_registry(root)}

    if source_ids is not None:
        requested = list(source_ids)
        unknown = [value for value in requested if value not in registry]
        if unknown:
            raise DiscoveryInputError(f"unknown source id(s): {', '.join(sorted(unknown))}")
        selected = [registry[value] for value in requested]
    else:
        selected = list(registry.values())

    picked = []
    for source in selected:
        if discovery_config(source) is None:
            if source_ids is not None:
                raise DiscoveryInputError(
                    f"source {source['id']!r} declares no discovery behaviour in the registry"
                )
            continue
        if discovery_role(source) != role:
            if source_ids is not None:
                raise DiscoveryInputError(
                    f"source {source['id']!r} is registered as discovery role "
                    f"{discovery_role(source)!r}, not {role!r}"
                )
            continue
        if trust is not None and source["trust"] != trust:
            continue
        if not include_disabled and not source.get("enabled", False):
            if source_ids is not None:
                raise DiscoveryInputError(f"source {source['id']!r} is disabled in the registry")
            continue
        if role == ROLE_SIGNAL_SOURCE and source["trust"] not in SIGNAL_SOURCE_TIERS:
            raise DiscoveryInputError(
                f"source {source['id']!r}: trust tier {source['trust']!r} may contribute "
                "evidence but must not manufacture discovery signals"
            )
        picked.append(source)

    return sorted(picked, key=lambda item: item["id"])


def due_sources(
    root: Path, sources: list[dict], moment: datetime
) -> tuple[list[dict], list[str]]:
    """Split sources into those past their configured cadence and those not."""
    due: list[dict] = []
    skipped: list[str] = []
    for source in sources:
        state = dk_acquisition.load_state(root, source["id"])
        fresh = dk_acquisition.staleness(source, state, moment)
        if fresh["stale"] or fresh["age_days"] is None:
            due.append(source)
        else:
            skipped.append(source["id"])
    return due, skipped


# ---------------------------------------------------------------------------
# Version and scope reasoning
#
# Scope is only ever narrowed by evidence, never widened. Absent scope stays
# unknown: "we do not know" must not decay into "applies everywhere".
# ---------------------------------------------------------------------------

CORE_CONSTRAINT_RE = re.compile(r"(\d+)(?:\.\d+)*")
PROJECT_BRANCH_LEGACY_RE = re.compile(r"^(\d+\.x-\d+)\.\d+.*$")
PROJECT_BRANCH_SEMVER_RE = re.compile(r"^(\d+)\.\d+.*$")


def core_majors(constraints: Iterable[str]) -> set[str]:
    """Reduce core compatibility constraints to the set of major versions.

    ``^10.3 || ^11`` becomes ``{"10", "11"}``. This is deliberately coarse:
    corroborating across major Drupal versions is the mistake worth blocking,
    and finer resolution would invite false precision.
    """
    majors: set[str] = set()
    for constraint in constraints:
        if not isinstance(constraint, str):
            continue
        for match in CORE_CONSTRAINT_RE.finditer(constraint):
            majors.add(match.group(1))
    return majors


def project_branch(version: str | None) -> str | None:
    """Reduce a project version to its branch identity.

    ``8.x-1.17`` -> ``8.x-1``; ``3.0.5`` -> ``3``. A module's 1.x line is not
    its 3.x line, and matching on project name alone is not scope alignment.
    """
    if not isinstance(version, str) or not version.strip():
        return None
    value = version.strip()
    legacy = PROJECT_BRANCH_LEGACY_RE.match(value)
    if legacy:
        return legacy.group(1)
    semver = PROJECT_BRANCH_SEMVER_RE.match(value)
    if semver:
        return semver.group(1)
    return value


def version_scope(project_version: str | None, core_constraints: Iterable[str]) -> dict:
    constraints = [value for value in core_constraints if isinstance(value, str) and value.strip()]
    return {
        "project_version": project_version,
        "drupal_core": sorted(set(constraints)),
        "explicitly_evidenced": bool(project_version) or bool(constraints),
    }


def compare_scope(signal_scope: dict, evidence_scope: dict) -> str:
    """Classify how two explicitly evidenced scopes relate."""
    signal_versions = signal_scope.get("version_scope") or {}
    evidence_versions = evidence_scope.get("version_scope") or {}

    if not signal_versions.get("explicitly_evidenced") or not evidence_versions.get(
        "explicitly_evidenced"
    ):
        return UNKNOWN

    signal_component = (signal_scope.get("component") or {}).get("name")
    evidence_component = (evidence_scope.get("component") or {}).get("name")
    if signal_component and evidence_component and signal_component != evidence_component:
        return MISMATCHED

    signal_branch = project_branch(signal_versions.get("project_version"))
    evidence_branch = project_branch(evidence_versions.get("project_version"))
    signal_core = core_majors(signal_versions.get("drupal_core") or [])
    evidence_core = core_majors(evidence_versions.get("drupal_core") or [])

    branch_state: str | None = None
    if signal_branch and evidence_branch:
        branch_state = ALIGNED if signal_branch == evidence_branch else MISMATCHED

    core_state: str | None = None
    if signal_core and evidence_core:
        core_state = ALIGNED if signal_core & evidence_core else MISMATCHED

    if branch_state == MISMATCHED or core_state == MISMATCHED:
        return MISMATCHED
    if branch_state == ALIGNED and core_state == ALIGNED:
        return ALIGNED
    if branch_state == ALIGNED or core_state == ALIGNED:
        return PARTIALLY_ALIGNED
    return UNKNOWN


# ---------------------------------------------------------------------------
# Deterministic extraction
#
# Each strategy turns one immutable snapshot into an ordered list of
# observations. No language model participates. Structured sources are read
# through their structured fields, never by guessing at prose.
# ---------------------------------------------------------------------------


def _release_terms(release: ET.Element) -> list[str]:
    terms: list[str] = []
    container = release.find("terms")
    if container is None:
        return terms
    for term in container:
        name = (term.findtext("name") or "").strip()
        value = (term.findtext("value") or "").strip()
        if name.lower() == "release type" and value:
            terms.append(value)
    return sorted(set(terms))


def extract_project_release_xml(text: str, source: dict) -> list[dict]:
    """Extract release observations from an update-status release-history document."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SignalExtractionError(f"release history is not parseable XML: {exc}") from exc

    short_name = (root.findtext("short_name") or "").strip()
    if not short_name:
        raise SignalExtractionError("release history is missing short_name")
    package = (root.findtext("composer_namespace") or "").strip() or None
    project_type = (root.findtext("type") or "").strip()
    releases = root.find("releases")
    if releases is None:
        raise SignalExtractionError("release history is missing a releases element")

    component_type = "module"
    if project_type == "project_theme":
        component_type = "theme"
    elif project_type == "project_core":
        component_type = "core"

    observations: list[dict] = []
    for release in releases.findall("release"):
        version = (release.findtext("version") or "").strip()
        if not version:
            continue
        status = (release.findtext("status") or "").strip() or None
        security = (release.findtext("security") or "").strip() or None
        core_compatibility = (release.findtext("core_compatibility") or "").strip()
        constraints = [
            part.strip()
            for part in re.split(r"\|\||,", core_compatibility)
            if part.strip()
        ]
        terms = _release_terms(release)
        release_type = terms[0] if terms else "Unspecified"
        release_link = (release.findtext("release_link") or "").strip() or None
        date_raw = (release.findtext("date") or "").strip()
        published_at = None
        if date_raw.isdigit():
            published_at = now_iso(datetime.fromtimestamp(int(date_raw), tz=timezone.utc))

        observations.append(
            {
                "item_ref": f"release:{version}",
                "topic": "project_release_type",
                "assertion_key": f"project.{short_name}.release.{version}.release_type",
                "assertion_value": release_type,
                "summary": (
                    f"{short_name} release {version} is published as release type "
                    f"{release_type!r}."
                ),
                "evidence": [
                    f"version={version}",
                    f"release_type={release_type}",
                    f"status={status}",
                    f"security={security}",
                    f"core_compatibility={core_compatibility or 'unstated'}",
                ],
                "field_path": "project/releases/release",
                "component": {
                    "type": component_type,
                    "name": short_name,
                    "package": package,
                },
                "version_scope": version_scope(version, constraints),
                "environment": None,
                "published_at": published_at,
                "item_updated_at": published_at,
                "canonical_ref": release_link,
                # Release metadata carries no popularity dimension at all.
                "popularity": {},
            }
        )

    if not observations:
        raise SignalExtractionError("release history contained no usable releases")
    return observations


def extract_project_issue_json(text: str, source: dict) -> list[dict]:
    """Extract issue observations from a drupal.org api-d7 node listing."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SignalExtractionError(f"issue listing is not parseable JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("list"), list):
        raise SignalExtractionError("issue listing is missing a 'list' array")

    component = declared_component(source)
    observations: list[dict] = []
    for node in payload["list"]:
        if not isinstance(node, dict):
            continue
        nid = str(node.get("nid") or "").strip()
        title = str(node.get("title") or "").strip()
        if not nid or not title:
            continue
        status = str(node.get("field_issue_status") or "").strip() or "unstated"
        version = str(node.get("field_issue_version") or "").strip() or None
        changed = str(node.get("changed") or "").strip()
        item_updated_at = None
        if changed.isdigit():
            item_updated_at = now_iso(datetime.fromtimestamp(int(changed), tz=timezone.utc))

        # Comment counts are observable. They are recorded and then ignored:
        # an issue is not more true because more people replied to it.
        comment_count = node.get("comment_count")
        popularity: dict[str, Any] = {}
        if comment_count is not None:
            popularity["comment_count"] = comment_count

        observations.append(
            {
                "item_ref": f"issue:{nid}",
                "topic": "project_issue_status",
                "assertion_key": f"issue.{nid}.status",
                "assertion_value": status,
                "summary": f"Issue {nid} ({title[:120]}) is reported with status {status!r}.",
                "evidence": [
                    f"nid={nid}",
                    f"status={status}",
                    f"issue_version={version or 'unstated'}",
                ],
                "field_path": "list[].field_issue_status",
                "component": component,
                "version_scope": version_scope(version, []),
                "environment": None,
                "published_at": None,
                "item_updated_at": item_updated_at,
                "canonical_ref": f"https://www.drupal.org/node/{nid}",
                "popularity": popularity,
            }
        )

    if not observations:
        raise SignalExtractionError("issue listing contained no usable issues")
    return observations


EXTRACTORS: dict[str, Callable[[str, dict], list[dict]]] = {
    EXTRACTION_PROJECT_RELEASE_XML: extract_project_release_xml,
    EXTRACTION_PROJECT_ISSUE_JSON: extract_project_issue_json,
}


def extract_observations(text: str, source: dict) -> list[dict]:
    """Run the registry-declared extraction strategy for a source."""
    strategy = extraction_strategy(source)
    extractor = EXTRACTORS.get(strategy)
    if extractor is None:  # pragma: no cover - guarded by extraction_strategy
        raise DiscoveryEngineDefect(f"no extractor registered for {strategy!r}")
    observations = extractor(text, source)
    limit = max_items(source)
    return observations[:limit]


# ---------------------------------------------------------------------------
# Signal identity and storage
# ---------------------------------------------------------------------------


def signal_identity(source_id: str, item_ref: str | None, assertion_key: str) -> str:
    """Deterministic signal id.

    Identity is (source, item, assertion). The same item asserting the same
    thing is the same signal however many times it is observed. A genuinely
    different report from a different source is a different signal, and stays
    countable as separate evidence.
    """
    digest = fingerprint(source_id, item_ref or "", assertion_key)[:16]
    return f"signal.drupal.{source_id}.{digest}"


def signal_path(root: Path, identity: str) -> Path:
    if not SIGNAL_ID_RE.fullmatch(identity):
        raise DiscoveryInputError(f"invalid signal id: {identity!r}")
    return root / SIGNALS_RELATIVE_PATH / f"{identity}.json"


def load_signal(root: Path, identity: str) -> dict:
    path = signal_path(root, identity)
    if not path.is_file():
        raise DiscoveryInputError(f"unknown signal: {identity}")
    return dk_core.read_json(path)


def iter_signals(root: Path) -> list[dict]:
    directory = root / SIGNALS_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def signal_staleness(source: dict, observed_at: str, moment: datetime) -> dict:
    expected = expected_refresh_days(source)
    try:
        observed = dk_acquisition.parse_iso(observed_at)
    except Exception:  # noqa: BLE001 - malformed timestamps must not crash listing
        return {"stale": False, "age_days": None, "expected_refresh_days": expected}
    age_days = max(0, int((moment - observed).total_seconds() // 86400))
    stale = expected is not None and age_days > expected
    return {"stale": stale, "age_days": age_days, "expected_refresh_days": expected}


def build_signal(
    source: dict,
    observation: dict,
    *,
    snapshot_sha256: str,
    stamp: str,
    run_id: str,
    acquisition_run_id: str | None,
) -> dict:
    """Assemble one discovery signal.

    Every const-false flag here is load-bearing: a signal is structurally
    incapable of describing itself as trusted knowledge or as a proposal.
    """
    item_ref = observation.get("item_ref")
    assertion_key = observation["assertion_key"]
    identity = signal_identity(source["id"], item_ref, assertion_key)

    return {
        "id": identity,
        "signal_contract_version": SIGNAL_CONTRACT_VERSION,
        "kind": signal_kind(source),
        "status": SIGNAL_OBSERVED,
        "review_status": "unreviewed",
        "review_required": True,
        "can_promote_to_knowledge": False,
        "is_trusted_knowledge": False,
        "is_knowledge_proposal": False,
        "engine": {
            "name": DISCOVERY_ENGINE_NAME,
            "version": DISCOVERY_ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "source": {
            "source_id": source["id"],
            "trust": source["trust"],
            "category": source["category"],
            "snapshot_sha256": snapshot_sha256,
            "canonical_url": observation.get("canonical_ref") or source["url"],
            "fetch_url": source.get("fetch_url", source["url"]),
            "item_ref": item_ref,
            "independence_group": independence_group(source),
            "derived_from": derived_from(source),
            "discovery_channel": DISCOVERY_CHANNEL,
        },
        "observed_at": stamp,
        "acquired_at": stamp,
        "published_at": observation.get("published_at"),
        "item_updated_at": observation.get("item_updated_at"),
        "summary": observation["summary"],
        "claim": {
            "topic": observation["topic"],
            "assertion_key": assertion_key,
            "assertion_value": observation.get("assertion_value"),
            "evidence": list(observation.get("evidence") or []),
            "extraction": {
                "strategy": extraction_strategy(source),
                "deterministic": True,
                "field_path": observation.get("field_path"),
            },
        },
        "scope": {
            "component": observation.get("component") or declared_component(source),
            "version_scope": observation.get("version_scope") or version_scope(None, []),
            "environment": observation.get("environment"),
        },
        "popularity": {
            "metrics": dict(observation.get("popularity") or {}),
            "counts_toward_corroboration": False,
            "authority_weight": 0,
        },
        "staleness": {
            "stale": False,
            "age_days": 0,
            "expected_refresh_days": expected_refresh_days(source),
        },
        "provenance": {
            "discovery_channel": DISCOVERY_CHANNEL,
            "acquisition_run_id": acquisition_run_id,
            "discovery_run_id": run_id,
            "acquired_by": {
                "name": DISCOVERY_ENGINE_NAME,
                "version": DISCOVERY_ENGINE_VERSION,
            },
        },
        "review": None,
    }


MATERIAL_SIGNAL_KEYS = ("kind", "summary", "claim", "scope")


def validate_signal(signal: dict) -> None:
    """Enforce the signal contract, including the boundaries it must not cross."""
    required = {
        "id",
        "signal_contract_version",
        "kind",
        "status",
        "review_status",
        "review_required",
        "can_promote_to_knowledge",
        "is_trusted_knowledge",
        "is_knowledge_proposal",
        "engine",
        "source",
        "observed_at",
        "acquired_at",
        "summary",
        "claim",
        "scope",
        "popularity",
        "provenance",
        "review",
    }
    context = f"signal {signal.get('id', '<unknown>')}"
    dk_core.assert_keys(signal, required, context)

    identity = signal["id"]
    if not SIGNAL_ID_RE.fullmatch(identity):
        raise dk_core.ValidationError(f"{context}: invalid signal id")
    if signal["status"] not in SIGNAL_STATUSES:
        raise dk_core.ValidationError(f"{context}: invalid status {signal['status']!r}")
    if signal["kind"] not in SIGNAL_KINDS:
        raise dk_core.ValidationError(f"{context}: invalid kind {signal['kind']!r}")
    if signal["review_status"] not in {"unreviewed", "reviewed"}:
        raise dk_core.ValidationError(f"{context}: invalid review_status")

    # A signal may never claim it is, or may become, trusted knowledge.
    if signal["review_required"] is not True:
        raise dk_core.ValidationError(f"{context}: review_required must be true")
    for flag in ("can_promote_to_knowledge", "is_trusted_knowledge", "is_knowledge_proposal"):
        if signal[flag] is not False:
            raise dk_core.ValidationError(f"{context}: {flag} must be false")

    engine = signal["engine"]
    if engine.get("name") != DISCOVERY_ENGINE_NAME:
        raise dk_core.ValidationError(f"{context}: unexpected engine name")
    if engine.get("deterministic") is not True:
        raise dk_core.ValidationError(f"{context}: engine must be deterministic")
    if engine.get("language_model_used") is not False:
        raise dk_core.ValidationError(f"{context}: no language model may produce a signal")

    source = signal["source"]
    if source.get("discovery_channel") != DISCOVERY_CHANNEL:
        raise dk_core.ValidationError(f"{context}: discovery signals must use the discovery channel")
    if source.get("trust") not in dk_core.TRUST_TIERS:
        raise dk_core.ValidationError(f"{context}: invalid source trust tier")
    if not isinstance(source.get("independence_group"), str) or not source["independence_group"]:
        raise dk_core.ValidationError(f"{context}: missing independence_group")
    digest = source.get("snapshot_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise dk_core.ValidationError(f"{context}: invalid snapshot_sha256")

    claim = signal["claim"]
    if not claim.get("assertion_key"):
        raise dk_core.ValidationError(f"{context}: claim requires an assertion_key")
    if claim.get("extraction", {}).get("deterministic") is not True:
        raise dk_core.ValidationError(f"{context}: extraction must be deterministic")

    # Popularity is metadata, structurally barred from becoming authority.
    popularity = signal["popularity"]
    if popularity.get("counts_toward_corroboration") is not False:
        raise dk_core.ValidationError(f"{context}: popularity must not count toward corroboration")
    if popularity.get("authority_weight") != 0:
        raise dk_core.ValidationError(f"{context}: popularity must carry zero authority weight")

    provenance = signal["provenance"]
    if provenance.get("discovery_channel") != DISCOVERY_CHANNEL:
        raise dk_core.ValidationError(f"{context}: provenance channel must stay distinct")
    dk_acquisition.assert_provenance_safe(
        {
            "canonical_url": source.get("canonical_url", ""),
            "fetch_url": source.get("fetch_url", ""),
        }
    )

    review = signal["review"]
    if review is not None:
        if review.get("outcome") not in REVIEW_OUTCOMES:
            raise dk_core.ValidationError(f"{context}: invalid review outcome")
        if review.get("method") not in REVIEW_METHODS:
            raise dk_core.ValidationError(f"{context}: invalid review method")
        if review.get("trusted_knowledge_changed") is not False:
            raise dk_core.ValidationError(f"{context}: review must not change trusted knowledge")
        if not review.get("actor"):
            raise dk_core.ValidationError(f"{context}: review requires an actor")


def write_signal(root: Path, signal: dict) -> tuple[Path, str]:
    """Persist a signal idempotently.

    Re-observing an unchanged signal rewrites nothing at all, so repeat
    discovery runs produce no churn and no duplicate evidence.
    """
    validate_signal(signal)
    path = signal_path(root, signal["id"])
    if path.is_file():
        existing = dk_core.read_json(path)
        same = all(existing.get(key) == signal.get(key) for key in MATERIAL_SIGNAL_KEYS)
        if same:
            return path, "reused"
        merged = dict(existing)
        for key in MATERIAL_SIGNAL_KEYS:
            merged[key] = signal[key]
        merged["observed_at"] = signal["observed_at"]
        merged["item_updated_at"] = signal.get("item_updated_at")
        merged["published_at"] = signal.get("published_at")
        merged["provenance"] = signal["provenance"]
        validate_signal(merged)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stable_json(merged), encoding="utf-8")
        return path, "updated"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(signal), encoding="utf-8")
    return path, "created"


# ---------------------------------------------------------------------------
# Discovery run
#
# Retrieval is delegated wholesale to the released acquisition engine: this
# module never opens a socket. Signals are derived from the immutable snapshot
# acquisition produced, which is what keeps discovery evidence addressable.
# ---------------------------------------------------------------------------


def build_run_id(stamp: str, source_ids: list[str]) -> str:
    compact = stamp.replace("-", "").replace(":", "").replace("Z", "")
    digest = fingerprint(stamp, DISCOVERY_ENGINE_VERSION, ",".join(sorted(source_ids)))[:8]
    return f"discovery.{compact}.{digest}"


def classify_discovery_failure(kind: str, detail: str) -> dict:
    return {
        "classification": kind,
        "engine_defect": False,
        "detail": dk_acquisition.sanitize_detail(detail),
    }


def _snapshot_text(
    root: Path, source: dict, outcome: dict, normalized_dir: Path | None
) -> str:
    """Read the acquired normalized text back out of immutable storage."""
    if normalized_dir is not None:
        path = normalized_dir / f"{source['id']}.txt"
        if not path.is_file():
            raise DiscoveryEngineDefect(
                f"dry-run normalized output missing for {source['id']}"
            )
        return path.read_text(encoding="utf-8")
    digest = outcome["current_snapshot_sha256"]
    return dk_core.require_snapshot(root, source["id"], digest).read_text(encoding="utf-8")


def discover_source(
    root: Path,
    source: dict,
    *,
    run_id: str,
    timeout: int = dk_acquisition.DEFAULT_TIMEOUT,
    dry_run: bool = False,
    fetcher: Callable[[dict, int], dict] | None = None,
    moment: datetime | None = None,
    normalized_dir: Path | None = None,
) -> dict:
    """Acquire one discovery source and derive signals from its snapshot.

    Failure kinds stay separate on purpose. An unreachable source is not
    evidence that nothing exists, a broken extraction contract is not an
    unreachable source, and neither is ever allowed to look like a defect in
    this engine.
    """
    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)
    source_id = source["id"]

    outcome: dict[str, Any] = {
        "source_id": source_id,
        "trust": source["trust"],
        "category": source["category"],
        "independence_group": independence_group(source),
        "extraction": extraction_strategy(source),
        "status": None,
        "dry_run": dry_run,
        "snapshot_sha256": None,
        "acquisition_status": None,
        "observations": 0,
        "signals_created": [],
        "signals_reused": [],
        "signals_updated": [],
        "error": None,
    }

    # Retrieval, normalization, hashing and snapshot storage: all reused.
    acquisition = dk_acquisition.acquire_source(
        root,
        source,
        run_id=run_id,
        timeout=timeout,
        dry_run=dry_run,
        fetcher=fetcher,
        normalized_output=normalized_dir,
        moment=moment,
    )
    outcome["acquisition_status"] = acquisition["status"]
    outcome["snapshot_sha256"] = acquisition["current_snapshot_sha256"]

    if acquisition["status"] in dk_acquisition.FAILURE_STATUSES:
        # Acquisition already told us which kind of failure this was. Keep that
        # distinction: an unreachable source and a source that broke its own
        # contract are different problems with different responses.
        malformed = acquisition["status"] == dk_acquisition.STATUS_INVALID_OR_MALFORMED
        error = acquisition.get("error") or {}
        outcome["status"] = "source_contract_failure" if malformed else "source_unavailable"
        outcome["error"] = {
            "classification": ERROR_SOURCE_CONTRACT if malformed else ERROR_SOURCE_UNAVAILABLE,
            "engine_defect": False,
            "detail": error.get("detail", "source acquisition failed"),
            "acquisition_classification": error.get("classification"),
        }
        return outcome

    try:
        text = _snapshot_text(root, source, acquisition, normalized_dir)
        observations = extract_observations(text, source)
    except SignalExtractionError as exc:
        outcome["status"] = "extraction_failure"
        outcome["error"] = classify_discovery_failure(ERROR_EXTRACTION, str(exc))
        return outcome
    except DiscoveryEngineDefect:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise DiscoveryEngineDefect(
            f"discovery engine defect while extracting {source_id}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    outcome["observations"] = len(observations)
    snapshot_sha = acquisition["current_snapshot_sha256"]

    try:
        for observation in observations:
            signal = build_signal(
                source,
                observation,
                snapshot_sha256=snapshot_sha,
                stamp=stamp,
                run_id=run_id,
                acquisition_run_id=run_id,
            )
            if dry_run:
                # Nothing canonical may move in a dry run: validate and drop.
                validate_signal(signal)
                outcome["signals_created"].append(signal["id"])
                continue
            _, result = write_signal(root, signal)
            if result == "created":
                outcome["signals_created"].append(signal["id"])
            elif result == "updated":
                outcome["signals_updated"].append(signal["id"])
            else:
                outcome["signals_reused"].append(signal["id"])
    except DiscoveryEngineDefect:
        raise
    except dk_core.ValidationError as exc:
        outcome["status"] = "extraction_failure"
        outcome["error"] = classify_discovery_failure(ERROR_EXTRACTION, str(exc))
        return outcome
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise DiscoveryEngineDefect(
            f"discovery engine defect while recording signals for {source_id}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    outcome["status"] = "observed"
    return outcome


# ---------------------------------------------------------------------------
# Corroboration
#
# Deterministic evidence matching on the assertion key, then three independent
# filters: lineage (is this really a second origin?), scope (is it even about
# the same thing?), and contradiction (does anything disagree?).
# ---------------------------------------------------------------------------

# Trusted-knowledge records carry no machine-readable assertion keys, so the
# trusted_knowledge channel contributes no automatic evidence yet. Recorded on
# every dossier rather than silently implied.
LIMITATION_NO_KNOWLEDGE_ASSERTIONS = (
    "Trusted knowledge records are not machine-keyed for assertion matching, so "
    "the trusted_knowledge evidence channel contributes no automatic evidence."
)
LIMITATION_DISCOVERY_ONLY = (
    "Corroborated discovery evidence is not trusted knowledge and authorises no "
    "knowledge change without explicit human review."
)


def lineage_key(independence: str, derived: str | None) -> str:
    """Collapse republication onto its origin.

    A source that declares it is derived from another shares that origin's
    lineage, so a repost can never count as a second independent voice.
    """
    return derived or independence


def evidence_item(
    *,
    channel: str,
    reference: str,
    trust: str,
    independence: str,
    derived: str | None,
    relation: str,
    scope_state: str,
    generalizes: bool,
    detail: str,
    content_fingerprint: str,
) -> dict:
    return {
        "channel": channel,
        "reference": reference,
        "trust": trust,
        "independence_group": lineage_key(independence, derived),
        "content_fingerprint": content_fingerprint,
        "relation": relation,
        "scope_state": scope_state,
        "generalizes": generalizes,
        "detail": detail,
    }


def claim_fingerprint(assertion_key: str, assertion_value: Any, summary: str) -> str:
    """Identity of the claim's content, used to spot verbatim reposts."""
    return "sha256:" + fingerprint(assertion_key, assertion_value, summary)


def _relation_for(signal_value: Any, evidence_value: Any) -> str:
    return RELATION_SUPPORTS if signal_value == evidence_value else RELATION_CONTRADICTS


def evidence_source_assertions(root: Path) -> list[dict]:
    """Derive assertions from registered evidence sources' existing snapshots.

    Read-only: this walks the immutable snapshot tree that acquisition already
    wrote. It never fetches and never advances source state.
    """
    assertions: list[dict] = []
    for source in select_discovery_sources(
        root, role=ROLE_EVIDENCE_SOURCE, include_disabled=True
    ):
        state = dk_acquisition.load_state(root, source["id"])
        digest = (state or {}).get("content_sha256")
        if not digest:
            continue
        try:
            path = dk_core.require_snapshot(root, source["id"], digest)
            observations = extract_observations(path.read_text(encoding="utf-8"), source)
        except (dk_core.ValidationError, SignalExtractionError):
            # An evidence source we cannot read yields no evidence. It must not
            # invent support and must not look like a contradiction.
            continue
        for observation in observations:
            assertions.append(
                {
                    "source": source,
                    "observation": observation,
                }
            )
    return assertions


def solved_case_evidence(root: Path, signal: dict) -> list[dict]:
    """Recurrence evidence from internal-proven solved cases.

    A solved case proves something happened in a named context. It never
    generalises on its own, so every item is flagged ``generalizes: False`` and
    can never by itself raise a dossier to fully corroborated.
    """
    component_block = signal["scope"].get("component") or {}
    component = component_block.get("name")
    package = component_block.get("package")
    identifiers = {value for value in (component, package) if value}
    if not identifiers:
        return []
    signal_core = core_majors(signal["scope"]["version_scope"].get("drupal_core") or [])

    items: list[dict] = []
    for case in dk_core.load_solved_cases(root):
        # Solved cases name components as {"name": "drupal/token", ...} objects.
        named = set()
        for entry in list(case.get("modules") or []) + list(case.get("themes") or []):
            if isinstance(entry, dict):
                value = entry.get("name")
                if isinstance(value, str) and value:
                    named.add(value)
                    named.add(value.rsplit("/", 1)[-1])
            elif isinstance(entry, str) and entry:
                named.add(entry)
        if not identifiers & named:
            continue
        case_core = core_majors(case.get("drupal_versions") or [])
        if signal_core and case_core:
            scope_state = ALIGNED if signal_core & case_core else MISMATCHED
        else:
            scope_state = UNKNOWN
        relation = RELATION_SCOPE_MISMATCH if scope_state == MISMATCHED else RELATION_SUPPORTS
        items.append(
            evidence_item(
                channel=CHANNEL_SOLVED_CASE,
                reference=case["id"],
                trust="internal-proven",
                # Solved cases are their own provenance channel and their own
                # lineage: internal proof is not an external ecosystem voice.
                independence=SOLVED_CASE_CHANNEL,
                derived=None,
                relation=relation,
                scope_state=scope_state,
                generalizes=False,
                detail=(
                    f"Solved case proven on Drupal {sorted(case_core) or 'unstated'} "
                    f"naming component {component!r}; proven context only."
                ),
                content_fingerprint=claim_fingerprint(
                    "solved-case", case["id"], case.get("title", "")
                ),
            )
        )
    return items


def gather_evidence(root: Path, signal: dict, *, signals: list[dict] | None = None) -> list[dict]:
    """Collect every evidence item bearing on one signal."""
    assertion_key = signal["claim"]["assertion_key"]
    assertion_value = signal["claim"].get("assertion_value")
    signal_lineage = lineage_key(
        signal["source"]["independence_group"], signal["source"].get("derived_from")
    )

    collected: list[dict] = []

    # (1) Other registered discovery/ecosystem signals.
    pool = signals if signals is not None else iter_signals(root)
    for other in sorted(pool, key=lambda item: item["id"]):
        if other["id"] == signal["id"]:
            continue
        if other["claim"]["assertion_key"] != assertion_key:
            continue
        other_lineage = lineage_key(
            other["source"]["independence_group"], other["source"].get("derived_from")
        )
        other_value = other["claim"].get("assertion_value")
        other_fingerprint = claim_fingerprint(
            other["claim"]["assertion_key"], other_value, other["summary"]
        )
        scope_state = compare_scope(signal["scope"], other["scope"])

        if other_lineage == signal_lineage:
            # Same editorial origin, including anything declaring itself derived
            # from that origin. A repost is not a second independent voice.
            relation = RELATION_DUPLICATE
            detail = (
                f"Shares evidence lineage {other_lineage!r} with the signal, so it is a "
                "repost of the same origin rather than independent support."
            )
        elif scope_state == MISMATCHED:
            relation = RELATION_SCOPE_MISMATCH
            detail = "Reports an incompatible component or version scope."
        else:
            relation = _relation_for(assertion_value, other_value)
            detail = f"Reports {other_value!r} for the same assertion key."

        collected.append(
            evidence_item(
                channel=TRUST_TO_CHANNEL[other["source"]["trust"]],
                reference=other["id"],
                trust=other["source"]["trust"],
                independence=other["source"]["independence_group"],
                derived=other["source"].get("derived_from"),
                relation=relation,
                scope_state=scope_state,
                generalizes=True,
                detail=detail,
                content_fingerprint=other_fingerprint,
            )
        )

    # (2) Registered evidence sources, including authoritative ones.
    for entry in evidence_source_assertions(root):
        source = entry["source"]
        observation = entry["observation"]
        if observation["assertion_key"] != assertion_key:
            continue
        evidence_scope = {
            "component": observation.get("component") or declared_component(source),
            "version_scope": observation.get("version_scope") or version_scope(None, []),
        }
        scope_state = compare_scope(signal["scope"], evidence_scope)
        value = observation.get("assertion_value")
        evidence_lineage = lineage_key(independence_group(source), derived_from(source))
        reference_tier = source["trust"] in ("authoritative", "industry-standard")
        if scope_state == MISMATCHED:
            relation = RELATION_SCOPE_MISMATCH
            detail = (
                f"{source['trust']} evidence exists but for an incompatible version "
                "scope, so it cannot support this signal directly."
            )
        elif evidence_lineage == signal_lineage and not reference_tier:
            # Same editorial origin as the signal: not a second voice.
            relation = RELATION_DUPLICATE
            detail = (
                f"Shares evidence lineage {evidence_lineage!r} with the signal, so it is "
                "the same origin rather than independent support."
            )
        else:
            relation = _relation_for(assertion_value, value)
            detail = f"{source['trust']} source reports {value!r} for the same assertion key."
        collected.append(
            evidence_item(
                channel=TRUST_TO_CHANNEL[source["trust"]],
                reference=f"{source['id']}#{observation.get('item_ref')}",
                trust=source["trust"],
                independence=independence_group(source),
                derived=derived_from(source),
                relation=relation,
                scope_state=scope_state,
                generalizes=True,
                detail=detail,
                content_fingerprint=claim_fingerprint(
                    observation["assertion_key"], value, observation["summary"]
                ),
            )
        )

    # (3) Internal-proven recurrence.
    collected.extend(solved_case_evidence(root, signal))
    return collected


def _alignment_state(states: list[str]) -> str:
    if not states:
        return UNKNOWN
    unique = set(states)
    if unique == {ALIGNED}:
        return ALIGNED
    if MISMATCHED in unique and unique <= {MISMATCHED, UNKNOWN}:
        return MISMATCHED
    if ALIGNED in unique or PARTIALLY_ALIGNED in unique:
        return PARTIALLY_ALIGNED
    return UNKNOWN


def classify_corroboration(signal: dict, evidence: list[dict]) -> dict:
    """Decide a corroboration state from evidence alone.

    The ordering matters. Contradiction from an authoritative source outranks
    any amount of agreement; independent origins outrank volume; and internal
    proof never generalises by itself.
    """
    supporting = [item for item in evidence if item["relation"] == RELATION_SUPPORTS]
    contradicting = [item for item in evidence if item["relation"] == RELATION_CONTRADICTS]
    disqualified = [
        item
        for item in evidence
        if item["relation"] in (RELATION_DUPLICATE, RELATION_SCOPE_MISMATCH)
    ]

    authoritative_support = [
        item for item in supporting if item["channel"] == CHANNEL_AUTHORITATIVE
    ]
    authoritative_contradiction = [
        item for item in contradicting if item["channel"] == CHANNEL_AUTHORITATIVE
    ]
    solved_support = [item for item in supporting if item["channel"] == CHANNEL_SOLVED_CASE]
    external_support = [item for item in supporting if item["channel"] != CHANNEL_SOLVED_CASE]

    signal_lineage = lineage_key(
        signal["source"]["independence_group"], signal["source"].get("derived_from")
    )
    independent_origins = sorted(
        {item["independence_group"] for item in supporting} - {signal_lineage}
    )
    external_origins = sorted(
        {item["independence_group"] for item in external_support} - {signal_lineage}
    )
    duplicate_origins = sorted(
        {item["independence_group"] for item in disqualified if item["relation"] == RELATION_DUPLICATE}
    )

    limitations = [LIMITATION_NO_KNOWLEDGE_ASSERTIONS, LIMITATION_DISCOVERY_ONLY]

    if not signal["claim"].get("assertion_key"):
        state = NOT_APPLICABLE
    elif authoritative_contradiction:
        state = CONTRADICTED
        limitations.append(
            "An authoritative source disagrees with this signal; the contradiction is "
            "retained as evidence and outranks any supporting agreement."
        )
    elif contradicting and not supporting:
        state = CONTRADICTED
    elif authoritative_support:
        state = CORROBORATED
    elif len(external_origins) >= 2:
        state = CORROBORATED
    elif independent_origins:
        state = PARTIALLY_CORROBORATED
    else:
        state = INSUFFICIENT_EVIDENCE

    # Internal proof is recurrence evidence, not generalisation. One solved
    # case plus one community report is not a universal Drupal fact.
    if state == CORROBORATED and not external_support and solved_support:
        state = PARTIALLY_CORROBORATED
        limitations.append(
            "Only internal-proven solved cases support this signal; solved cases prove "
            "a named context and do not generalise automatically."
        )
    if solved_support:
        limitations.append(
            "Solved-case support is proven-context evidence and requires review before "
            "any generalisation."
        )
    if duplicate_origins:
        limitations.append(
            "Evidence sharing a lineage with the signal or reproducing it verbatim was "
            "disqualified and did not increase corroboration strength."
        )
    if contradicting:
        limitations.append("Contradictory evidence is retained in full and never discarded.")

    scope_states = [item["scope_state"] for item in supporting]
    scope_state = _alignment_state(scope_states)
    mismatched = [item for item in disqualified if item["relation"] == RELATION_SCOPE_MISMATCH]
    scope_notes = []
    version_notes = []
    if mismatched:
        note = (
            f"{len(mismatched)} evidence item(s) matched the assertion key but were "
            "rejected for incompatible component or version scope."
        )
        scope_notes.append(note)
        version_notes.append(note)
    if not signal["scope"]["version_scope"].get("explicitly_evidenced"):
        version_notes.append(
            "The signal states no explicit version scope, so its scope stays unknown "
            "rather than being widened."
        )

    return {
        "corroboration_state": state,
        "supporting_evidence": supporting,
        "contradictory_evidence": contradicting,
        "disqualified_evidence": disqualified,
        "independence_assessment": {
            "independent_origin_count": len(independent_origins),
            "independent_origins": independent_origins,
            "duplicate_origin_count": len(duplicate_origins),
            "authoritative_origin_count": len(
                {item["independence_group"] for item in authoritative_support}
            ),
            "solved_case_origin_count": len(
                {item["independence_group"] for item in solved_support}
            ),
            "method": "independence_group_and_content_lineage",
        },
        "scope_alignment": {
            "state": scope_state,
            "component": (signal["scope"].get("component") or {}).get("name"),
            "notes": scope_notes,
        },
        "version_alignment": {
            "state": _alignment_state(scope_states),
            "signal_version_scope": signal["scope"]["version_scope"],
            "notes": version_notes,
        },
        "popularity_assessment": {
            "considered": bool(signal["popularity"].get("metrics")),
            "influenced_corroboration": False,
            "rationale": POPULARITY_RATIONALE,
        },
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Dossier identity and storage
# ---------------------------------------------------------------------------


def dossier_identity(signal_id: str) -> str:
    """One dossier per signal, so re-corroborating updates rather than piles up."""
    digest = fingerprint(signal_id)[:16]
    return f"corroboration.drupal.{digest}"


def dossier_path(root: Path, identity: str) -> Path:
    if not DOSSIER_ID_RE.fullmatch(identity):
        raise DiscoveryInputError(f"invalid dossier id: {identity!r}")
    return root / DOSSIERS_RELATIVE_PATH / f"{identity}.json"


def load_dossier(root: Path, identity: str) -> dict:
    path = dossier_path(root, identity)
    if not path.is_file():
        raise DiscoveryInputError(f"unknown corroboration dossier: {identity}")
    return dk_core.read_json(path)


def iter_dossiers(root: Path) -> list[dict]:
    directory = root / DOSSIERS_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def evidence_fingerprint(signal: dict, assessment: dict) -> str:
    parts = [signal["id"], assessment["corroboration_state"]]
    for bucket in ("supporting_evidence", "contradictory_evidence", "disqualified_evidence"):
        for item in assessment[bucket]:
            parts.append(
                "|".join(
                    [
                        item["channel"],
                        item["reference"],
                        item["relation"],
                        item["scope_state"],
                        item["content_fingerprint"],
                    ]
                )
            )
    return "sha256:" + fingerprint(*parts)


def build_dossier(signal: dict, assessment: dict, *, stamp: str, run_id: str) -> dict:
    return {
        "id": dossier_identity(signal["id"]),
        "dossier_contract_version": DOSSIER_CONTRACT_VERSION,
        "signal_id": signal["id"],
        # The originating tier is copied verbatim. Authoritative support never
        # retro-promotes a community observation into an authoritative one.
        "signal_trust": signal["source"]["trust"],
        "corroboration_state": assessment["corroboration_state"],
        "review_required": True,
        "review_state": REVIEW_PENDING,
        "can_promote_to_knowledge": False,
        "is_trusted_knowledge": False,
        "is_knowledge_proposal": False,
        "generalizes_automatically": False,
        "engine": {
            "name": CORROBORATION_ENGINE_NAME,
            "version": DISCOVERY_ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "evidence_fingerprint": evidence_fingerprint(signal, assessment),
        "built_at": stamp,
        "run_id": run_id,
        "supporting_evidence": assessment["supporting_evidence"],
        "contradictory_evidence": assessment["contradictory_evidence"],
        "disqualified_evidence": assessment["disqualified_evidence"],
        "independence_assessment": assessment["independence_assessment"],
        "scope_alignment": assessment["scope_alignment"],
        "version_alignment": assessment["version_alignment"],
        "popularity_assessment": assessment["popularity_assessment"],
        "limitations": assessment["limitations"],
        "review": None,
    }


def validate_dossier(dossier: dict) -> None:
    context = f"dossier {dossier.get('id', '<unknown>')}"
    required = {
        "id",
        "dossier_contract_version",
        "signal_id",
        "signal_trust",
        "corroboration_state",
        "review_required",
        "review_state",
        "can_promote_to_knowledge",
        "is_trusted_knowledge",
        "is_knowledge_proposal",
        "engine",
        "evidence_fingerprint",
        "built_at",
        "run_id",
        "supporting_evidence",
        "contradictory_evidence",
        "disqualified_evidence",
        "independence_assessment",
        "scope_alignment",
        "version_alignment",
        "popularity_assessment",
        "limitations",
        "review",
    }
    dk_core.assert_keys(dossier, required, context)
    if not DOSSIER_ID_RE.fullmatch(dossier["id"]):
        raise dk_core.ValidationError(f"{context}: invalid dossier id")
    if not SIGNAL_ID_RE.fullmatch(dossier["signal_id"]):
        raise dk_core.ValidationError(f"{context}: invalid signal id reference")
    if dossier["corroboration_state"] not in CORROBORATION_STATES:
        raise dk_core.ValidationError(f"{context}: invalid corroboration state")
    if dossier["review_state"] not in REVIEW_STATES:
        raise dk_core.ValidationError(f"{context}: invalid review state")
    if dossier["signal_trust"] not in dk_core.TRUST_TIERS:
        raise dk_core.ValidationError(f"{context}: invalid signal trust tier")

    # Even a fully corroborated dossier stays incapable of describing itself as
    # knowledge or as a proposal.
    if dossier["review_required"] is not True:
        raise dk_core.ValidationError(f"{context}: review_required must be true")
    for flag in (
        "can_promote_to_knowledge",
        "is_trusted_knowledge",
        "is_knowledge_proposal",
        "generalizes_automatically",
    ):
        if dossier.get(flag) is not False:
            raise dk_core.ValidationError(f"{context}: {flag} must be false")

    engine = dossier["engine"]
    if engine.get("name") != CORROBORATION_ENGINE_NAME:
        raise dk_core.ValidationError(f"{context}: unexpected engine name")
    if engine.get("deterministic") is not True:
        raise dk_core.ValidationError(f"{context}: corroboration must be deterministic")
    if engine.get("language_model_used") is not False:
        raise dk_core.ValidationError(f"{context}: no language model may corroborate")

    if dossier["popularity_assessment"].get("influenced_corroboration") is not False:
        raise dk_core.ValidationError(f"{context}: popularity must not influence corroboration")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", dossier["evidence_fingerprint"]):
        raise dk_core.ValidationError(f"{context}: invalid evidence fingerprint")

    for bucket in ("supporting_evidence", "contradictory_evidence", "disqualified_evidence"):
        for item in dossier[bucket]:
            if item.get("relation") not in (
                RELATION_SUPPORTS,
                RELATION_CONTRADICTS,
                RELATION_DUPLICATE,
                RELATION_SCOPE_MISMATCH,
            ):
                raise dk_core.ValidationError(f"{context}: invalid evidence relation")
            if item.get("trust") not in dk_core.TRUST_TIERS:
                raise dk_core.ValidationError(f"{context}: invalid evidence trust tier")

    review = dossier["review"]
    if review is not None:
        if review.get("outcome") not in REVIEW_OUTCOMES:
            raise dk_core.ValidationError(f"{context}: invalid review outcome")
        if review.get("method") not in REVIEW_METHODS:
            raise dk_core.ValidationError(f"{context}: invalid review method")
        if review.get("trusted_knowledge_changed") is not False:
            raise dk_core.ValidationError(f"{context}: review must not change trusted knowledge")
        if not review.get("actor"):
            raise dk_core.ValidationError(f"{context}: review requires an actor")


EVIDENCE_CHANGED_AFTER_REVIEW = (
    "Evidence changed after this dossier was reviewed, so it returned to pending review."
)


def write_dossier(root: Path, dossier: dict) -> tuple[Path, str]:
    """Persist a dossier idempotently.

    Identical evidence rewrites nothing. Changed evidence updates the existing
    dossier in place and, if it had already been reviewed, sends it back to
    pending review rather than carrying a stale human decision forward.
    """
    validate_dossier(dossier)
    path = dossier_path(root, dossier["id"])
    if path.is_file():
        existing = dk_core.read_json(path)
        if existing.get("evidence_fingerprint") == dossier["evidence_fingerprint"]:
            return path, "reused"
        merged = dict(dossier)
        merged["review"] = existing.get("review")
        merged["review_state"] = REVIEW_PENDING
        if existing.get("review") is not None:
            merged["limitations"] = list(merged["limitations"]) + [
                EVIDENCE_CHANGED_AFTER_REVIEW
            ]
        validate_dossier(merged)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stable_json(merged), encoding="utf-8")
        return path, "updated"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(dossier), encoding="utf-8")
    return path, "created"


CORROBORATION_TO_SIGNAL_STATUS = {
    CORROBORATED: SIGNAL_CORROBORATED,
    PARTIALLY_CORROBORATED: SIGNAL_CORROBORATION_PENDING,
    CONTRADICTED: SIGNAL_CONTRADICTED,
    INSUFFICIENT_EVIDENCE: SIGNAL_INSUFFICIENT,
    NOT_APPLICABLE: SIGNAL_OBSERVED,
}


def corroborate_signal(
    root: Path,
    signal_id: str,
    *,
    run_id: str | None = None,
    moment: datetime | None = None,
    dry_run: bool = False,
    signals: list[dict] | None = None,
) -> dict:
    """Build (or rebuild) the corroboration dossier for one signal."""
    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)
    run_id = run_id or build_run_id(stamp, [signal_id])

    signal = load_signal(root, signal_id)
    try:
        evidence = gather_evidence(root, signal, signals=signals)
        assessment = classify_corroboration(signal, evidence)
        dossier = build_dossier(signal, assessment, stamp=stamp, run_id=run_id)
    except (DiscoveryInputError, DiscoveryEngineDefect):
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise DiscoveryEngineDefect(
            f"corroboration engine defect for {signal_id}: {type(exc).__name__}: {exc}"
        ) from exc

    if dry_run:
        validate_dossier(dossier)
        return {
            "signal_id": signal_id,
            "dossier_id": dossier["id"],
            "corroboration_state": dossier["corroboration_state"],
            "result": "dry_run",
            "dossier": dossier,
        }

    _, result = write_dossier(root, dossier)
    stored = load_dossier(root, dossier["id"])

    # The signal's own lifecycle follows the evidence. Its trust tier does not.
    status = CORROBORATION_TO_SIGNAL_STATUS[stored["corroboration_state"]]
    if signal["status"] not in (SIGNAL_DISMISSED,) and signal["status"] != status:
        signal["status"] = status
        validate_signal(signal)
        signal_path(root, signal_id).write_text(stable_json(signal), encoding="utf-8")

    return {
        "signal_id": signal_id,
        "dossier_id": stored["id"],
        "corroboration_state": stored["corroboration_state"],
        "result": result,
        "dossier": stored,
    }


# ---------------------------------------------------------------------------
# Orchestrated discovery run
# ---------------------------------------------------------------------------


def discover(
    root: Path = dk_core.ROOT,
    *,
    source_ids: Iterable[str] | None = None,
    trust: str | None = None,
    due_only: bool = False,
    dry_run: bool = False,
    corroborate: bool = True,
    timeout: int = dk_acquisition.DEFAULT_TIMEOUT,
    fetcher: Callable[[dict, int], dict] | None = None,
    moment: datetime | None = None,
    normalized_dir: Path | None = None,
) -> dict:
    """Run discovery over selected sources and report deterministically.

    This is the single engine. The scheduled CI entry point and the manual CLI
    both land here, so a scheduled run can never take a different code path
    with different guarantees.
    """
    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)

    if source_ids is None and trust is None:
        raise DiscoveryInputError(
            "discovery requires --source or --trust: broad unbounded discovery is not supported"
        )

    sources = select_discovery_sources(
        root, source_ids=source_ids, trust=trust, role=ROLE_SIGNAL_SOURCE
    )
    skipped: list[str] = []
    if due_only:
        sources, skipped = due_sources(root, sources, moment)

    requested = [source["id"] for source in sources]
    run_id = build_run_id(stamp, requested)

    if dry_run and normalized_dir is None:
        raise DiscoveryEngineDefect(
            "dry-run discovery requires a normalized output directory to read from"
        )

    digest_before = dk_core.knowledge_tree_digest(root)

    results: list[dict] = []
    failures: list[dict] = []
    signals_created: list[str] = []
    signals_reused: list[str] = []
    signals_updated: list[str] = []
    snapshots_used: list[str] = []

    for source in sources:
        outcome = discover_source(
            root,
            source,
            run_id=run_id,
            timeout=timeout,
            dry_run=dry_run,
            fetcher=fetcher,
            moment=moment,
            normalized_dir=normalized_dir,
        )
        results.append(outcome)
        if outcome["snapshot_sha256"]:
            snapshots_used.append(outcome["snapshot_sha256"])
        signals_created.extend(outcome["signals_created"])
        signals_reused.extend(outcome["signals_reused"])
        signals_updated.extend(outcome["signals_updated"])
        if outcome["error"] is not None:
            failures.append({"source_id": outcome["source_id"], **outcome["error"]})

    corroboration: list[dict] = []
    if corroborate and not dry_run:
        touched = sorted(set(signals_created) | set(signals_reused) | set(signals_updated))
        pool = iter_signals(root)
        for identity in touched:
            outcome = corroborate_signal(
                root, identity, run_id=run_id, moment=moment, signals=pool
            )
            corroboration.append(
                {
                    "signal_id": outcome["signal_id"],
                    "dossier_id": outcome["dossier_id"],
                    "corroboration_state": outcome["corroboration_state"],
                    "result": outcome["result"],
                }
            )

    digest_after = dk_core.knowledge_tree_digest(root)
    if digest_before != digest_after:
        raise DiscoveryEngineDefect(
            "discovery mutated trusted knowledge; this is an engine defect"
        )

    review_work = sorted(
        {
            entry["dossier_id"]
            for entry in corroboration
            if entry["result"] in ("created", "updated")
        }
    )

    return {
        "schema_version": DISCOVERY_RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "engine": {
            "discovery": {"name": DISCOVERY_ENGINE_NAME, "version": DISCOVERY_ENGINE_VERSION},
            "corroboration": {
                "name": CORROBORATION_ENGINE_NAME,
                "version": DISCOVERY_ENGINE_VERSION,
            },
            "deterministic": True,
            "language_model_used": False,
        },
        "discovery_channel": DISCOVERY_CHANNEL,
        "started_at": stamp,
        "completed_at": now_iso(datetime.now(timezone.utc)),
        "dry_run": dry_run,
        "selection": {
            "requested": requested,
            "trust": trust,
            "skipped_not_due": skipped,
        },
        "snapshots_used": sorted(set(snapshots_used)),
        "signals_created": sorted(set(signals_created)),
        "signals_reused": sorted(set(signals_reused)),
        "signals_updated": sorted(set(signals_updated)),
        "corroboration_results": corroboration,
        "review_work_created": review_work,
        "failures": failures,
        "engine_defects": [],
        "results": results,
        # Prompt-06 invariant, asserted above and reported here.
        "trusted_knowledge_mutations": [],
        "trusted_knowledge_digest": {"before": digest_before, "after": digest_after},
    }


def run_exit_code(run: dict) -> int:
    return 1 if run["failures"] else 0


# ---------------------------------------------------------------------------
# Human review
# ---------------------------------------------------------------------------


def review_dossier(
    root: Path,
    dossier_id: str,
    *,
    outcome: str,
    actor: str,
    method: str = "human_signal_review",
    note: str | None = None,
    moment: datetime | None = None,
) -> dict:
    """Record an explicit human decision on a corroboration dossier.

    No outcome available here mutates trusted knowledge.
    ``candidate_for_future_knowledge_proposal`` authorises later, separate
    proposal work and nothing more.
    """
    if outcome not in REVIEW_OUTCOMES:
        raise DiscoveryInputError(
            f"invalid review outcome {outcome!r}; expected one of {', '.join(REVIEW_OUTCOMES)}"
        )
    if method not in REVIEW_METHODS:
        raise DiscoveryInputError(f"invalid review method {method!r}")
    if not actor or not actor.strip():
        raise DiscoveryInputError("review requires an actor")

    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)
    digest_before = dk_core.knowledge_tree_digest(root)

    dossier = load_dossier(root, dossier_id)
    review = {
        "reviewed_at": stamp,
        "actor": actor.strip(),
        "method": method,
        "note": note,
        "outcome": outcome,
        "authorizes_knowledge_proposal_work": outcome in REVIEW_AUTHORIZING_OUTCOMES,
        "trusted_knowledge_changed": False,
    }
    dossier["review"] = review
    dossier["review_state"] = outcome
    validate_dossier(dossier)
    dossier_path(root, dossier_id).write_text(stable_json(dossier), encoding="utf-8")

    signal = load_signal(root, dossier["signal_id"])
    signal["review_status"] = "reviewed"
    signal["review"] = review
    if outcome == REVIEW_DISMISSED:
        signal["status"] = SIGNAL_DISMISSED
    validate_signal(signal)
    signal_path(root, signal["id"]).write_text(stable_json(signal), encoding="utf-8")

    digest_after = dk_core.knowledge_tree_digest(root)
    if digest_before != digest_after:
        raise DiscoveryEngineDefect(
            "review mutated trusted knowledge; this is an engine defect"
        )

    return {
        "dossier_id": dossier_id,
        "signal_id": signal["id"],
        "review_state": dossier["review_state"],
        "authorizes_knowledge_proposal_work": review["authorizes_knowledge_proposal_work"],
        "trusted_knowledge_changed": False,
        "trusted_knowledge_digest": {"before": digest_before, "after": digest_after},
    }


def refresh_signal_staleness(root: Path, moment: datetime | None = None) -> list[dict]:
    """Recompute signal staleness without ever reinterpreting it as falsehood."""
    moment = moment or datetime.now(timezone.utc)
    registry = {source["id"]: source for source in dk_acquisition.load_registry(root)}
    report: list[dict] = []
    for signal in iter_signals(root):
        source = registry.get(signal["source"]["source_id"])
        if source is None:
            continue
        fresh = signal_staleness(source, signal["observed_at"], moment)
        report.append(
            {
                "signal_id": signal["id"],
                "stale": fresh["stale"],
                "age_days": fresh["age_days"],
                "expected_refresh_days": fresh["expected_refresh_days"],
                "status": signal["status"],
            }
        )
    return sorted(report, key=lambda item: item["signal_id"])


def signal_report(root: Path, moment: datetime | None = None) -> list[dict]:
    """Inspectable view of every signal and its corroboration work."""
    moment = moment or datetime.now(timezone.utc)
    registry = {source["id"]: source for source in dk_acquisition.load_registry(root)}
    dossiers = {dossier["signal_id"]: dossier for dossier in iter_dossiers(root)}
    rows: list[dict] = []
    for signal in iter_signals(root):
        source = registry.get(signal["source"]["source_id"])
        fresh = (
            signal_staleness(source, signal["observed_at"], moment)
            if source is not None
            else {"stale": False, "age_days": None, "expected_refresh_days": None}
        )
        dossier = dossiers.get(signal["id"])
        rows.append(
            {
                "signal_id": signal["id"],
                "source_id": signal["source"]["source_id"],
                "trust": signal["source"]["trust"],
                "kind": signal["kind"],
                "status": signal["status"],
                "review_status": signal["review_status"],
                "assertion_key": signal["claim"]["assertion_key"],
                "assertion_value": signal["claim"].get("assertion_value"),
                "stale": fresh["stale"],
                "age_days": fresh["age_days"],
                "dossier_id": dossier["id"] if dossier else None,
                "corroboration_state": dossier["corroboration_state"] if dossier else None,
                "review_state": dossier["review_state"] if dossier else None,
            }
        )
    return sorted(rows, key=lambda item: item["signal_id"])


# ---------------------------------------------------------------------------
# Repository contract
# ---------------------------------------------------------------------------


def validate_discovery_contract(root: Path = dk_core.ROOT) -> list[str]:
    """Validate discovery configuration, signals and dossiers on disk."""
    for relative in (
        "schema/discovery-signal.schema.json",
        "schema/corroboration-dossier.schema.json",
    ):
        dk_core.read_json(root / relative)

    registry = dk_acquisition.load_registry(root)
    signal_sources = 0
    evidence_sources = 0
    for source in registry:
        config = discovery_config(source)
        if config is None:
            continue
        context = f"source {source['id']}"
        role = discovery_role(source)
        extraction_strategy(source)
        independence_group(source)
        derived_from(source)
        max_items(source)
        expected_refresh_days(source)
        declared_component(source)
        if role == ROLE_SIGNAL_SOURCE:
            signal_kind(source)
            if source["trust"] not in SIGNAL_SOURCE_TIERS:
                raise dk_core.ValidationError(
                    f"{context}: only ecosystem and discovery tiers may produce signals"
                )
            signal_sources += 1
        else:
            evidence_sources += 1
        successor = config.get("derived_from")
        if successor is not None and successor == independence_group(source):
            raise dk_core.ValidationError(
                f"{context}: derived_from must name a different origin lineage"
            )

    signals = iter_signals(root)
    for signal in signals:
        validate_signal(signal)
        if signal["source"]["source_id"] not in {source["id"] for source in registry}:
            raise dk_core.ValidationError(
                f"signal {signal['id']}: references an unregistered source"
            )

    dossiers = iter_dossiers(root)
    known = {signal["id"] for signal in signals}
    for dossier in dossiers:
        validate_dossier(dossier)
        if dossier["signal_id"] not in known:
            raise dk_core.ValidationError(
                f"dossier {dossier['id']}: references an unknown signal"
            )

    return [
        "DISCOVERY_ENGINE_CONTRACT_VALID=PASS",
        f"DISCOVERY_ENGINE_VERSION={DISCOVERY_ENGINE_VERSION}",
        f"DISCOVERY_SIGNAL_SOURCES={signal_sources}",
        f"DISCOVERY_EVIDENCE_SOURCES={evidence_sources}",
        f"DISCOVERY_SIGNALS={len(signals)}",
        f"CORROBORATION_DOSSIERS={len(dossiers)}",
        "DISCOVERY_CANNOT_PROMOTE_TRUSTED_KNOWLEDGE=PASS",
    ]
