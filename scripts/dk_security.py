#!/usr/bin/env python3
"""Drupal Security Team advisory intelligence.

This module turns authoritative Drupal Security Team advisories into canonical
records, and evaluates them against a project's analyzer facts.

What it will not do is the point of it. It preserves exactly what the Security
Team published and adds nothing: no CVSS score computed from a risk vector, no
severity read out of prose, no CVE invented where none was assigned, no
remediation of its own, and no exploitability or compromise claim of any kind.
Where the source is silent, the record says ``not_established`` and stops.

Three boundaries it defends:

    advisory record != general trusted knowledge
    severity        != enforcement
    unknown         != not applicable

An advisory record is source-derived authoritative evidence pinned to the
immutable snapshot it was read from. It is not a reusable behavioural rule
about Drupal, and it does not make Drupal Knowledge block anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_acquisition
import dk_core


# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------

ENGINE_NAME = "drupal-knowledge-security-engine"
ENGINE_VERSION = "0.1"
ADVISORY_CONTRACT_VERSION = "0.1"
APPLICABILITY_SCHEMA_VERSION = "0.1"

# The category that lets authoritative advisory data be materialized from a
# reviewed source snapshot without ever becoming trusted knowledge.
RECORD_CLASS = "source_derived_authoritative_record"
ACQUISITION_CHANNEL = dk_acquisition.ACQUISITION_CHANNEL

ADVISORIES_RELATIVE_PATH = Path("security") / "advisories"

ADVISORY_ID_RE = re.compile(r"^(SA-CORE|SA-CONTRIB|PSA)-[0-9]{4}-[0-9]{3,4}$")
FINDING_ID_RE = re.compile(r"^security-finding\.[a-z0-9-]+\.[a-f0-9]{16}$")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

# Drupal core's own project node. Core advisory identity is therefore never
# guessed from advisory title text.
DRUPAL_CORE_PROJECT_NID = "3060"
DRUPAL_CORE_MACHINE_NAME = "drupal"
DRUPAL_CORE_PACKAGE = "drupal/core"

KIND_CORE = "core"
KIND_CONTRIB = "contrib"
KIND_PSA = "psa"

SCOPE_CORE = "drupal_core"
SCOPE_CONTRIB = "contrib_package"
SCOPE_NOT_MATCHABLE = "not_matchable"

APPLICABLE = "applicable"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"
INSUFFICIENT_EVIDENCE = "insufficient_project_evidence"
VERSION_OUT_OF_SCOPE = "version_out_of_scope"

APPLICABILITY_STATES = (
    APPLICABLE,
    NOT_APPLICABLE,
    UNKNOWN,
    INSUFFICIENT_EVIDENCE,
    VERSION_OUT_OF_SCOPE,
)

FINDING_CONFIRMED = "confirmed"
FINDING_CANDIDATE = "candidate"
FINDING_UNKNOWN = "unknown"

SEVERITY_SOURCED = "sourced"
SEVERITY_NOT_ESTABLISHED = "not_established"

# Enforcement is policy, not truth. Until a reviewed blocking policy exists,
# every security finding is guidance.
ENFORCEMENT_INTENT = "guidance"


class SecurityInputError(RuntimeError):
    """Caller asked for something the sources or facts do not describe."""


class SecurityEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as a source or evidence problem."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def now_iso(moment: datetime | None = None) -> str:
    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def digest_hex(*parts: Any) -> str:
    accumulator = hashlib.sha256()
    for part in parts:
        accumulator.update(str(part).encode("utf-8"))
        accumulator.update(b"\0")
    return accumulator.hexdigest()


# ---------------------------------------------------------------------------
# Version semantics
#
# Drupal Security Team advisories publish affected versions as a Composer-style
# expression. The grammar observed in the authoritative feed is:
#
#     expression := clause ( "||" clause )*
#     clause     := constraint ( " " constraint )*        -- space means AND
#     constraint := ( ">=" | "<=" | ">" | "<" )? version
#                 | branch ".*"
#                 | "*"
#
# Operators appear both attached ("<11.3.14") and detached ("< 11.3.14"). This
# parses that grammar rather than approximating it.
# ---------------------------------------------------------------------------

CONSTRAINT_RE = re.compile(r"(>=|<=|>|<)?\s*([0-9][0-9A-Za-z.*\-]*|\*)")

# Drupal's legacy contrib version format, e.g. 8.x-1.2 for the 1.2 release on
# the 8.x-1 branch. Drupal.org publishes the semantic equivalent as 1.2.0.
LEGACY_VERSION_RE = re.compile(r"^(\d+)\.x-(\d+)\.(\d+)(?:-(.+))?$")
SEMVER_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+](.+))?$")

OP_LT = "lt"
OP_LTE = "lte"
OP_GT = "gt"
OP_GTE = "gte"
OP_EQ = "eq"
OP_BRANCH = "branch_wildcard"
OP_ANY = "any"

OPERATOR_TOKENS = {"<": OP_LT, "<=": OP_LTE, ">": OP_GT, ">=": OP_GTE}

PARSE_METHOD = "drupal_security_advisory_constraint_grammar"

LEGACY_NORMALIZATION_NOTE = (
    "Installed version {installed!r} uses Drupal's legacy contrib format; compared as "
    "{normalized!r} following Drupal.org's published semantic equivalent."
)
PRERELEASE_NOTE = (
    "Version {version!r} carries a pre-release suffix {suffix!r}; comparison used the "
    "release numbers only and the suffix is recorded rather than ranked."
)


class Version:
    """A comparable Drupal version, with how it was read recorded."""

    __slots__ = ("major", "minor", "patch", "suffix", "source_value", "notes")

    def __init__(
        self,
        major: int,
        minor: int,
        patch: int,
        suffix: str | None,
        source_value: str,
        notes: list[str],
    ) -> None:
        self.major = major
        self.minor = minor
        self.patch = patch
        self.suffix = suffix
        self.source_value = source_value
        self.notes = notes

    @property
    def key(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"Version({self.source_value!r})"


def parse_version(value: Any) -> Version | None:
    """Parse a Drupal version, or return None when it cannot be read.

    Returning None is deliberate: an unreadable version must become unknown
    downstream, never an assumption that the project is unaffected.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None

    notes: list[str] = []

    legacy = LEGACY_VERSION_RE.match(text)
    if legacy:
        major, minor, suffix = int(legacy.group(2)), int(legacy.group(3)), legacy.group(4)
        normalized = f"{major}.{minor}.0"
        notes.append(
            LEGACY_NORMALIZATION_NOTE.format(installed=text, normalized=normalized)
        )
        if suffix:
            notes.append(PRERELEASE_NOTE.format(version=text, suffix=suffix))
        return Version(major, minor, 0, suffix, text, notes)

    semver = SEMVER_RE.match(text)
    if not semver:
        return None
    major = int(semver.group(1))
    minor = int(semver.group(2)) if semver.group(2) is not None else 0
    patch = int(semver.group(3)) if semver.group(3) is not None else 0
    suffix = semver.group(4)
    if suffix:
        notes.append(PRERELEASE_NOTE.format(version=text, suffix=suffix))
    return Version(major, minor, patch, suffix, text, notes)


def parse_constraint(token_operator: str | None, operand: str) -> dict | None:
    """Turn one operator/operand pair into a constraint, or None if unreadable."""
    source_value = f"{token_operator or ''}{operand}".strip()

    if operand == "*":
        return {"operator": OP_ANY, "version": None, "source_value": source_value}

    if operand.endswith(".*"):
        branch = operand[:-2]
        if not parse_version(branch):
            return None
        return {"operator": OP_BRANCH, "version": branch, "source_value": source_value}

    if not parse_version(operand):
        return None

    operator = OPERATOR_TOKENS.get(token_operator or "", OP_EQ)
    return {"operator": operator, "version": operand, "source_value": source_value}


def parse_affected_versions(source_value: Any) -> dict:
    """Parse an advisory's affected-version expression.

    An absent expression is ``absent`` and an unreadable one is ``unparseable``.
    Neither is ever treated as "no versions affected".
    """
    if not isinstance(source_value, str) or not source_value.strip():
        return {
            "state": "absent",
            "source_value": source_value if isinstance(source_value, str) else None,
            "clauses": [],
            "parse_method": PARSE_METHOD,
        }

    text = source_value.strip()
    clauses: list[dict] = []
    for raw_clause in text.split("||"):
        clause_text = raw_clause.strip()
        if not clause_text:
            continue
        constraints: list[dict] = []
        consumed = 0
        for match in CONSTRAINT_RE.finditer(clause_text):
            constraint = parse_constraint(match.group(1), match.group(2))
            if constraint is None:
                return {
                    "state": "unparseable",
                    "source_value": text,
                    "clauses": [],
                    "parse_method": PARSE_METHOD,
                }
            constraints.append(constraint)
            consumed += len(match.group(0))
        # Anything the grammar did not consume means the expression is not one
        # we understand, so we refuse to guess at it.
        if not constraints or consumed < len(clause_text.replace(" ", "")):
            residue = re.sub(r"\s+", "", clause_text)
            rebuilt = "".join(
                re.sub(r"\s+", "", item["source_value"]) for item in constraints
            )
            if rebuilt != residue:
                return {
                    "state": "unparseable",
                    "source_value": text,
                    "clauses": [],
                    "parse_method": PARSE_METHOD,
                }
        clauses.append({"source_value": clause_text, "constraints": constraints})

    if not clauses:
        return {
            "state": "unparseable",
            "source_value": text,
            "clauses": [],
            "parse_method": PARSE_METHOD,
        }

    return {
        "state": "parsed",
        "source_value": text,
        "clauses": clauses,
        "parse_method": PARSE_METHOD,
    }


def constraint_satisfied(installed: Version, constraint: dict) -> bool | None:
    """Does the installed version satisfy one constraint? None means unreadable."""
    operator = constraint["operator"]
    if operator == OP_ANY:
        return True

    bound = parse_version(constraint["version"])
    if bound is None:
        return None

    if operator == OP_BRANCH:
        # 11.0.* constrains the branch, not the patch level. A two-segment
        # branch matches on major and minor; a one-segment branch on major.
        segments = str(constraint["version"]).count(".") + 1
        if segments >= 2:
            return (installed.major, installed.minor) == (bound.major, bound.minor)
        return installed.major == bound.major

    if operator == OP_LT:
        return installed.key < bound.key
    if operator == OP_LTE:
        return installed.key <= bound.key
    if operator == OP_GT:
        return installed.key > bound.key
    if operator == OP_GTE:
        return installed.key >= bound.key
    if operator == OP_EQ:
        return installed.key == bound.key
    return None


def evaluate_affected(installed: Version, affected: dict) -> dict:
    """Evaluate an installed version against a parsed affected expression.

    ``matched`` is only ever True or False when the expression was fully
    readable. Otherwise the result is unknown and says why.
    """
    if affected["state"] != "parsed":
        return {
            "state": UNKNOWN,
            "matched": None,
            "matched_clause": None,
            "detail": (
                "The advisory's affected-version expression is "
                f"{affected['state']}, so applicability cannot be determined."
            ),
        }

    for clause in affected["clauses"]:
        outcomes = [constraint_satisfied(installed, item) for item in clause["constraints"]]
        if any(outcome is None for outcome in outcomes):
            return {
                "state": UNKNOWN,
                "matched": None,
                "matched_clause": None,
                "detail": (
                    f"Clause {clause['source_value']!r} contains a constraint this engine "
                    "does not understand, so applicability cannot be determined."
                ),
            }
        if all(outcomes):
            return {
                "state": APPLICABLE,
                "matched": True,
                "matched_clause": clause["source_value"],
                "detail": (
                    f"Installed version {installed.source_value} satisfies affected clause "
                    f"{clause['source_value']!r}."
                ),
            }

    return {
        "state": NOT_APPLICABLE,
        "matched": False,
        "matched_clause": None,
        "detail": (
            f"Installed version {installed.source_value} satisfies no affected clause in "
            f"{affected['source_value']!r}."
        ),
    }


# ---------------------------------------------------------------------------
# Advisory ingestion
#
# Every advisory is read out of an immutable snapshot the acquisition engine
# already fetched, normalized and hashed. This module opens no socket of its
# own except to resolve the authoritative project and release nodes an advisory
# references, and it does that through the acquisition transport so transport
# failures stay classified the same way everywhere.
# ---------------------------------------------------------------------------

ADVISORY_URL_RE = re.compile(r"/(sa-core|sa-contrib|psa)-(\d{4})-(\d{3,4})/?$")

NODE_ENDPOINT = "https://www.drupal.org/api-d7/node/{nid}.json"

PROJECT_TYPES = {
    "project_core",
    "project_module",
    "project_theme",
    "project_distribution",
}


def parse_advisory_feed(text: str) -> list[dict]:
    """Read advisory nodes out of an acquired api-d7 listing snapshot."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SecurityInputError(f"advisory feed is not parseable JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("list"), list):
        raise SecurityInputError("advisory feed is missing a 'list' array")
    nodes = [item for item in payload["list"] if isinstance(item, dict)]
    if not nodes:
        raise SecurityInputError("advisory feed contained no advisory nodes")
    return nodes


def advisory_identity(node: dict) -> tuple[str, str, str, str]:
    """Derive advisory id, kind, year and number from its canonical URL.

    The canonical URL carries the published identifier as a structured path
    segment, so identity never depends on parsing advisory title prose.
    """
    url = node.get("url")
    if not isinstance(url, str):
        raise SecurityInputError("advisory node has no canonical url")
    match = ADVISORY_URL_RE.search(url.strip())
    if not match:
        raise SecurityInputError(f"advisory url is not a published advisory path: {url!r}")
    slug, year, number = match.group(1), match.group(2), match.group(3)
    identifier = f"{slug.upper()}-{year}-{number}"
    kind = KIND_PSA if slug == "psa" else (KIND_CORE if slug == "sa-core" else KIND_CONTRIB)
    return identifier, kind, year, number


def project_nid(node: dict) -> str | None:
    project = node.get("field_project")
    if isinstance(project, dict):
        value = project.get("id")
        return str(value) if value is not None else None
    return None


def default_node_fetcher(nid: str, timeout: int = dk_acquisition.DEFAULT_TIMEOUT) -> dict:
    """Fetch one authoritative drupal.org node through the acquisition transport."""
    url = NODE_ENDPOINT.format(nid=nid)
    source = {
        "id": "drupal-org-node-resolution",
        "url": url,
        "fetch_url": url,
        "expected_content_type": "json",
        "normalization": "raw_text",
    }
    result = dk_acquisition.fetch_source(source, timeout)
    try:
        return json.loads(result["normalized_text"])
    except json.JSONDecodeError as exc:
        raise dk_acquisition.SourceContractError(
            f"node {nid} did not return parseable JSON"
        ) from exc


def resolve_project(node: dict, fetcher=None, cache: dict | None = None) -> dict:
    """Resolve an advisory's project to an explicit Drupal.org identity.

    Core is identified by its own project node id. Everything else is resolved
    by fetching the referenced authoritative project node. Nothing is matched
    on name similarity, and an unresolvable reference stays ``unresolved``
    rather than being guessed at.
    """
    nid = project_nid(node)
    cache = cache if cache is not None else {}

    if nid is None:
        return {
            "identity_state": "unresolved",
            "machine_name": None,
            "project_type": None,
            "composer_package": None,
            "drupal_project_nid": None,
            "resolution": "unresolved",
            "resolved_from": None,
        }

    if nid == DRUPAL_CORE_PROJECT_NID:
        return {
            "identity_state": "resolved",
            "machine_name": DRUPAL_CORE_MACHINE_NAME,
            "project_type": "project_core",
            "composer_package": DRUPAL_CORE_PACKAGE,
            "drupal_project_nid": nid,
            "resolution": "authoritative_core_project",
            "resolved_from": NODE_ENDPOINT.format(nid=nid),
        }

    if nid in cache:
        return dict(cache[nid])

    fetcher = fetcher or default_node_fetcher
    try:
        project_node = fetcher(nid)
    except (dk_acquisition.AcquisitionError, SecurityInputError):
        resolved = {
            "identity_state": "unresolved",
            "machine_name": None,
            "project_type": None,
            "composer_package": None,
            "drupal_project_nid": nid,
            "resolution": "unresolved",
            "resolved_from": NODE_ENDPOINT.format(nid=nid),
        }
        cache[nid] = resolved
        return dict(resolved)

    machine_name = project_node.get("field_project_machine_name")
    project_type = project_node.get("type")
    if not isinstance(machine_name, str) or not machine_name:
        resolved = {
            "identity_state": "unresolved",
            "machine_name": None,
            "project_type": project_type if project_type in PROJECT_TYPES else "unknown",
            "composer_package": None,
            "drupal_project_nid": nid,
            "resolution": "unresolved",
            "resolved_from": NODE_ENDPOINT.format(nid=nid),
        }
    else:
        resolved = {
            "identity_state": "resolved",
            "machine_name": machine_name,
            "project_type": project_type if project_type in PROJECT_TYPES else "unknown",
            # Drupal.org publishes every project to Packagist as
            # drupal/<machine_name>. That is a documented convention, not a
            # similarity guess.
            "composer_package": f"drupal/{machine_name}",
            "drupal_project_nid": nid,
            "resolution": "authoritative_project_node",
            "resolved_from": NODE_ENDPOINT.format(nid=nid),
        }
    cache[nid] = resolved
    return dict(resolved)


def resolve_fixed_in(node: dict, fetcher=None, cache: dict | None = None) -> dict:
    """Resolve the releases an advisory names as fixed."""
    refs = node.get("field_fixed_in")
    nids: list[str] = []
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict) and ref.get("id") is not None:
                nids.append(str(ref["id"]))

    if not nids:
        # Absent is a real state: unsupported projects and PSAs may name no fix.
        return {"state": "absent", "versions": [], "release_nids": []}

    cache = cache if cache is not None else {}
    fetcher = fetcher or default_node_fetcher
    versions: list[str] = []
    for nid in nids:
        if nid in cache:
            version = cache[nid]
        else:
            try:
                release = fetcher(nid)
                version = release.get("field_release_version")
            except (dk_acquisition.AcquisitionError, SecurityInputError):
                version = None
            cache[nid] = version
        if isinstance(version, str) and version:
            versions.append(version)

    return {
        "state": "stated" if versions else "absent",
        "versions": sorted(set(versions)),
        "release_nids": sorted(set(nids)),
    }


def sourced_cves(node: dict) -> dict:
    """Preserve published CVEs. Never mint one."""
    raw = node.get("field_sa_cve")
    identifiers: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            value = item.get("value") if isinstance(item, dict) else item
            if isinstance(value, str) and CVE_RE.fullmatch(value.strip()):
                identifiers.append(value.strip())
    identifiers = sorted(set(identifiers))
    return {
        "state": SEVERITY_SOURCED if identifiers else "none_published",
        "identifiers": identifiers,
        "inferred": False,
    }


def sourced_severity(node: dict) -> dict:
    """Preserve the published risk vector exactly, or say nothing.

    Drupal publishes a risk vector such as ``AC:Basic/A:None/CI:None/II:Some``.
    Drupal Knowledge does not turn that into a score, and does not read a
    severity label out of the advisory title.
    """
    raw = node.get("field_sa_criticality")
    value = raw.get("value") if isinstance(raw, dict) else raw
    if isinstance(value, str) and value.strip():
        return {
            "state": SEVERITY_SOURCED,
            "risk_vector": value.strip(),
            "source_field": "field_sa_criticality",
            "scored_by_drupal_knowledge": False,
            "inferred": False,
        }
    return {
        "state": SEVERITY_NOT_ESTABLISHED,
        "risk_vector": None,
        "source_field": None,
        "scored_by_drupal_knowledge": False,
        "inferred": False,
    }


def field_text(node: dict, field: str) -> str | None:
    raw = node.get(field)
    if isinstance(raw, dict):
        value = raw.get("value")
        return value if isinstance(value, str) and value.strip() else None
    if isinstance(raw, list):
        for item in raw:
            value = item.get("value") if isinstance(item, dict) else item
            if isinstance(value, str) and value.strip():
                return value
        return None
    if isinstance(raw, str) and raw.strip():
        return raw
    return None


def timestamp_field(node: dict, field: str) -> str | None:
    raw = node.get(field)
    if isinstance(raw, str) and raw.isdigit():
        return now_iso(datetime.fromtimestamp(int(raw), tz=timezone.utc))
    return None


def advisory_path(root: Path, identifier: str) -> Path:
    if not ADVISORY_ID_RE.fullmatch(identifier):
        raise SecurityInputError(f"invalid advisory id: {identifier!r}")
    return root / ADVISORIES_RELATIVE_PATH / f"{identifier}.json"


def load_advisory(root: Path, identifier: str) -> dict:
    path = advisory_path(root, identifier)
    if not path.is_file():
        raise SecurityInputError(f"unknown security advisory: {identifier}")
    return dk_core.read_json(path)


def iter_advisories(root: Path) -> list[dict]:
    directory = root / ADVISORIES_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def build_advisory(
    node: dict,
    *,
    source_id: str,
    snapshot_sha256: str,
    stamp: str,
    run_id: str,
    project: dict,
    fixed_in: dict,
) -> dict:
    """Materialize one canonical advisory record from an authoritative node."""
    identifier, kind, year, number = advisory_identity(node)
    solution = field_text(node, "field_sa_solution")
    affected = parse_affected_versions(node.get("field_affected_versions"))

    return {
        "id": identifier,
        "advisory_contract_version": ADVISORY_CONTRACT_VERSION,
        "record_class": RECORD_CLASS,
        "is_trusted_knowledge": False,
        "is_general_knowledge_record": False,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "advisory": {
            "title": str(node.get("title") or identifier),
            "kind": kind,
            "advisory_number": number,
            "year": year,
            "vulnerability_type": field_text(node, "field_sa_type"),
            "is_psa": str(node.get("field_is_psa") or "0") == "1",
            "canonical_url": str(node.get("url")),
            "published_at": timestamp_field(node, "created"),
            "updated_at": timestamp_field(node, "changed"),
            # The description is authoritative prose. It is recorded as
            # present or absent rather than copied and re-interpreted here.
            "description_present": field_text(node, "field_sa_description") is not None,
        },
        "project": project,
        "affected_versions": affected,
        "fixed_in": fixed_in,
        "severity": sourced_severity(node),
        "cves": sourced_cves(node),
        "remediation": {
            "state": "sourced" if (solution or fixed_in["versions"]) else "not_provided",
            "source_solution_present": solution is not None,
            "fixed_versions": list(fixed_in["versions"]),
            "authored_by_drupal_knowledge": False,
            "executable": False,
        },
        "provenance": {
            "source_id": source_id,
            "source_snapshot_sha256": snapshot_sha256,
            "source_url": str(node.get("url")),
            "source_node_id": str(node.get("nid")) if node.get("nid") is not None else None,
            "acquisition_channel": ACQUISITION_CHANNEL,
            "ingested_at": stamp,
            "ingest_run_id": run_id,
            "ingested_by": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        },
        "enforcement": {
            "intent": ENFORCEMENT_INTENT,
            "policy_controlled": True,
            "automatically_blocking": False,
        },
    }


def validate_advisory(advisory: dict) -> None:
    """Enforce the advisory contract, including what it must never claim."""
    context = f"advisory {advisory.get('id', '<unknown>')}"
    required = {
        "id",
        "advisory_contract_version",
        "record_class",
        "is_trusted_knowledge",
        "is_general_knowledge_record",
        "engine",
        "advisory",
        "project",
        "affected_versions",
        "fixed_in",
        "severity",
        "cves",
        "remediation",
        "provenance",
        "enforcement",
    }
    dk_core.assert_keys(advisory, required, context)

    if not ADVISORY_ID_RE.fullmatch(advisory["id"]):
        raise dk_core.ValidationError(f"{context}: invalid advisory id")
    if advisory["record_class"] != RECORD_CLASS:
        raise dk_core.ValidationError(f"{context}: advisory must be a source-derived record")

    # An advisory is authoritative security evidence, never a general rule.
    if advisory["is_trusted_knowledge"] is not False:
        raise dk_core.ValidationError(f"{context}: is_trusted_knowledge must be false")
    if advisory["is_general_knowledge_record"] is not False:
        raise dk_core.ValidationError(
            f"{context}: an advisory is not a general knowledge record"
        )

    engine = advisory["engine"]
    if engine.get("name") != ENGINE_NAME:
        raise dk_core.ValidationError(f"{context}: unexpected engine name")
    if engine.get("deterministic") is not True:
        raise dk_core.ValidationError(f"{context}: advisory ingestion must be deterministic")
    if engine.get("language_model_used") is not False:
        raise dk_core.ValidationError(f"{context}: no language model may author an advisory")

    if advisory["advisory"]["kind"] not in (KIND_CORE, KIND_CONTRIB, KIND_PSA):
        raise dk_core.ValidationError(f"{context}: invalid advisory kind")

    project = advisory["project"]
    if project["identity_state"] not in ("resolved", "unresolved"):
        raise dk_core.ValidationError(f"{context}: invalid project identity state")
    if project["resolution"] not in (
        "authoritative_project_node",
        "authoritative_core_project",
        "unresolved",
    ):
        raise dk_core.ValidationError(
            f"{context}: project identity must be authoritatively resolved or unresolved"
        )
    if project["identity_state"] == "resolved" and not project["machine_name"]:
        raise dk_core.ValidationError(f"{context}: resolved identity requires a machine name")

    affected = advisory["affected_versions"]
    if affected["state"] not in ("parsed", "absent", "unparseable"):
        raise dk_core.ValidationError(f"{context}: invalid affected-version state")
    if affected["parse_method"] != PARSE_METHOD:
        raise dk_core.ValidationError(f"{context}: affected versions must use the source grammar")

    # Severity and CVEs are preserved or absent. Never derived.
    severity = advisory["severity"]
    if severity["state"] == SEVERITY_SOURCED and not severity["risk_vector"]:
        raise dk_core.ValidationError(f"{context}: sourced severity requires a risk vector")
    if severity["state"] == SEVERITY_NOT_ESTABLISHED and severity["risk_vector"]:
        raise dk_core.ValidationError(
            f"{context}: severity cannot be not_established and carry a value"
        )
    if severity["scored_by_drupal_knowledge"] is not False or severity["inferred"] is not False:
        raise dk_core.ValidationError(f"{context}: severity must never be scored or inferred")

    cves = advisory["cves"]
    if cves["inferred"] is not False:
        raise dk_core.ValidationError(f"{context}: CVEs must never be inferred")
    if cves["state"] == "none_published" and cves["identifiers"]:
        raise dk_core.ValidationError(f"{context}: none_published cannot carry identifiers")
    for identifier in cves["identifiers"]:
        if not CVE_RE.fullmatch(identifier):
            raise dk_core.ValidationError(f"{context}: malformed CVE {identifier!r}")

    remediation = advisory["remediation"]
    if remediation["authored_by_drupal_knowledge"] is not False:
        raise dk_core.ValidationError(f"{context}: remediation must be authoritative only")
    if remediation["executable"] is not False:
        raise dk_core.ValidationError(f"{context}: remediation must never be executable")

    enforcement = advisory["enforcement"]
    if enforcement["intent"] != ENFORCEMENT_INTENT:
        raise dk_core.ValidationError(f"{context}: enforcement intent must stay guidance")
    if enforcement["automatically_blocking"] is not False:
        raise dk_core.ValidationError(f"{context}: an advisory may not block automatically")
    if enforcement["policy_controlled"] is not True:
        raise dk_core.ValidationError(f"{context}: enforcement must remain policy controlled")

    provenance = advisory["provenance"]
    if provenance["acquisition_channel"] != ACQUISITION_CHANNEL:
        raise dk_core.ValidationError(f"{context}: advisories come from authoritative sources")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", provenance["source_snapshot_sha256"]):
        raise dk_core.ValidationError(f"{context}: advisory must pin a source snapshot")
    dk_acquisition.assert_provenance_safe(
        {
            "canonical_url": advisory["advisory"]["canonical_url"],
            "fetch_url": provenance["source_url"],
        }
    )


MATERIAL_ADVISORY_KEYS = (
    "advisory",
    "project",
    "affected_versions",
    "fixed_in",
    "severity",
    "cves",
    "remediation",
)


def write_advisory(root: Path, advisory: dict) -> tuple[Path, str]:
    """Persist an advisory idempotently.

    An unchanged advisory rewrites nothing. A changed one is written with its
    new source snapshot pinned; the previous snapshot stays immutable in the
    snapshot tree, so advisory history is never rewritten in place.
    """
    validate_advisory(advisory)
    path = advisory_path(root, advisory["id"])
    if path.is_file():
        existing = dk_core.read_json(path)
        if all(existing.get(key) == advisory.get(key) for key in MATERIAL_ADVISORY_KEYS):
            return path, "reused"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stable_json(advisory), encoding="utf-8")
        return path, "updated"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(advisory), encoding="utf-8")
    return path, "created"


def build_run_id(stamp: str, source_ids: Iterable[str]) -> str:
    compact = stamp.replace("-", "").replace(":", "").replace("Z", "")
    return f"security.{compact}.{digest_hex(stamp, ENGINE_VERSION, ','.join(sorted(source_ids)))[:8]}"


def ingest(
    root: Path = dk_core.ROOT,
    *,
    source_ids: Iterable[str],
    node_fetcher=None,
    dry_run: bool = False,
    moment: datetime | None = None,
) -> dict:
    """Materialize advisory records from already-acquired source snapshots.

    Ingestion reads the snapshot the acquisition engine accepted. It never
    fetches the advisory feed itself, so a feed that has moved produces an
    acquisition review candidate first and is ingested only from a snapshot
    that acquisition has recorded.
    """
    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)
    requested = list(source_ids)
    if not requested:
        raise SecurityInputError("advisory ingestion requires at least one --source")
    run_id = build_run_id(stamp, requested)

    registry = {source["id"]: source for source in dk_acquisition.load_registry(root)}
    digest_before = dk_core.knowledge_tree_digest(root)

    project_cache: dict[str, dict] = {}
    release_cache: dict[str, Any] = {}
    created: list[str] = []
    updated: list[str] = []
    reused: list[str] = []
    failures: list[dict] = []
    per_source: list[dict] = []

    for source_id in requested:
        source = registry.get(source_id)
        if source is None:
            raise SecurityInputError(f"unknown source id: {source_id}")
        state = dk_acquisition.load_state(root, source_id)
        snapshot_sha = (state or {}).get("content_sha256")
        if not snapshot_sha:
            failures.append(
                {
                    "source_id": source_id,
                    "classification": "source_not_acquired",
                    "detail": (
                        "The source has no accepted snapshot. Acquire it first so ingestion "
                        "reads reviewed source evidence rather than a live feed."
                    ),
                }
            )
            continue

        text = dk_core.require_snapshot(root, source_id, snapshot_sha).read_text(encoding="utf-8")
        try:
            nodes = parse_advisory_feed(text)
        except SecurityInputError as exc:
            failures.append(
                {
                    "source_id": source_id,
                    "classification": "advisory_feed_contract_failure",
                    "detail": str(exc),
                }
            )
            continue

        source_created = source_updated = source_reused = 0
        skipped: list[str] = []
        for node in nodes:
            try:
                identifier, _kind, _year, _number = advisory_identity(node)
            except SecurityInputError as exc:
                skipped.append(str(exc))
                continue
            try:
                project = resolve_project(node, node_fetcher, project_cache)
                fixed_in = resolve_fixed_in(node, node_fetcher, release_cache)
                advisory = build_advisory(
                    node,
                    source_id=source_id,
                    snapshot_sha256=snapshot_sha,
                    stamp=stamp,
                    run_id=run_id,
                    project=project,
                    fixed_in=fixed_in,
                )
            except (SecurityInputError, dk_core.ValidationError):
                raise
            except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
                raise SecurityEngineDefect(
                    f"security engine defect building {identifier}: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc

            if dry_run:
                validate_advisory(advisory)
                created.append(advisory["id"])
                source_created += 1
                continue

            _, result = write_advisory(root, advisory)
            if result == "created":
                created.append(advisory["id"])
                source_created += 1
            elif result == "updated":
                updated.append(advisory["id"])
                source_updated += 1
            else:
                reused.append(advisory["id"])
                source_reused += 1

        per_source.append(
            {
                "source_id": source_id,
                "snapshot_sha256": snapshot_sha,
                "advisory_nodes": len(nodes),
                "created": source_created,
                "updated": source_updated,
                "reused": source_reused,
                "skipped": skipped,
            }
        )

    digest_after = dk_core.knowledge_tree_digest(root)
    if digest_before != digest_after:
        raise SecurityEngineDefect(
            "advisory ingestion mutated trusted knowledge; this is an engine defect"
        )

    return {
        "schema_version": APPLICABILITY_SCHEMA_VERSION,
        "run_id": run_id,
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "started_at": stamp,
        "completed_at": now_iso(),
        "dry_run": dry_run,
        "sources": per_source,
        "advisories_created": sorted(set(created)),
        "advisories_updated": sorted(set(updated)),
        "advisories_reused": sorted(set(reused)),
        "failures": failures,
        "record_class": RECORD_CLASS,
        "trusted_knowledge_mutations": [],
        "trusted_knowledge_digest": {"before": digest_before, "after": digest_after},
    }


# ---------------------------------------------------------------------------
# Project facts
#
# Facts come from the Project Analyzer profile. This module runs no scanner of
# its own and re-derives nothing from the project tree.
# ---------------------------------------------------------------------------

FACTS_SOURCE = "drupal_project_analyzer_profile_facts"
CORE_VERSION_FACT = "drupal_core_version"
PACKAGES_FACT = "composer_packages"


def project_facts(analysis: dict) -> dict:
    """Read the analyzer facts security applicability depends on."""
    if not isinstance(analysis, dict):
        raise SecurityInputError("project analysis must be an object")
    profile = analysis.get("profile")
    if not isinstance(profile, dict) or not isinstance(profile.get("facts"), dict):
        raise SecurityInputError("project analysis is missing profile facts")
    facts = profile["facts"]

    core_fact = facts.get(CORE_VERSION_FACT) or {}
    core_value = core_fact.get("value") or {}
    core_known = core_fact.get("state") == "known" and isinstance(core_value, dict)
    core_version = core_value.get("version") if core_known else None
    core = {
        "state": "known" if core_known and isinstance(core_version, str) else "unknown",
        "value": core_version if isinstance(core_version, str) else None,
        "package": core_value.get("package") if core_known else None,
    }

    packages_fact = facts.get(PACKAGES_FACT) or {}
    packages_value = packages_fact.get("value") or {}
    installed = packages_value.get("installed") if isinstance(packages_value, dict) else None
    entries: list[dict] = []
    packages_known = (
        packages_fact.get("state") == "known"
        and isinstance(installed, dict)
        and installed.get("available") is True
    )
    if packages_known:
        for item in installed.get("drupal_packages") or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            version = item.get("version")
            if not isinstance(name, str) or not name:
                continue
            entries.append(
                {
                    "name": name,
                    "version": version if isinstance(version, str) and version else None,
                    "version_state": "known"
                    if isinstance(version, str) and version
                    else "unknown",
                }
            )

    return {
        "project_id": str(analysis.get("project_id") or "unknown"),
        "facts_source": FACTS_SOURCE,
        "core_version": core,
        "installed_packages": {
            "state": "known" if packages_known else "unknown",
            "count": len(entries),
            "packages": sorted(entries, key=lambda item: item["name"]),
        },
        "evidence_completeness": analysis.get("completeness") or {},
    }


def clause_covers_major(clause: dict, major: int) -> bool | None:
    """Could this clause speak about the given major version at all?

    A clause is a conjunction, so its major coverage is an interval, not a set
    of the majors that happen to be written in it. ``>= 8.0.0 < 10.3.13`` covers
    majors 8, 9 and 10 — reading it as {8, 10} would silently declare a Drupal 9
    site out of scope for an advisory that affects it.
    """
    lower: int | None = None
    upper: int | None = None
    pinned: set[int] = set()

    for constraint in clause["constraints"]:
        operator = constraint["operator"]
        if operator == OP_ANY:
            return True
        parsed = parse_version(constraint["version"])
        if parsed is None:
            return None
        if operator in (OP_GTE, OP_GT):
            lower = parsed.major if lower is None else max(lower, parsed.major)
        elif operator in (OP_LT, OP_LTE):
            upper = parsed.major if upper is None else min(upper, parsed.major)
        elif operator in (OP_BRANCH, OP_EQ):
            pinned.add(parsed.major)

    if pinned and major not in pinned:
        return False
    if lower is not None and major < lower:
        return False
    if upper is not None and major > upper:
        return False
    return True


def expression_covers_major(affected: dict, major: int) -> bool | None:
    """Does any clause of the expression speak about this major version?"""
    clauses = affected.get("clauses") or []
    if not clauses:
        return None
    outcomes = [clause_covers_major(clause, major) for clause in clauses]
    if any(outcome is None for outcome in outcomes):
        return None
    return any(outcomes)


def finding_identity(
    advisory_id: str, scope: str, package: str | None, installed: str | None, project_id: str
) -> str:
    slug = advisory_id.lower()
    fingerprint = digest_hex(advisory_id, scope, package or "", installed or "", project_id)[:16]
    return f"security-finding.{slug}.{fingerprint}"


def evaluate_advisory(advisory: dict, facts: dict) -> dict:
    """Evaluate one advisory against one project's facts, deterministically."""
    kind = advisory["advisory"]["kind"]
    project = advisory["project"]
    affected = advisory["affected_versions"]
    severity = advisory["severity"]

    result = {
        "advisory_id": advisory["id"],
        "advisory_kind": kind,
        "scope": SCOPE_NOT_MATCHABLE,
        "applicability": UNKNOWN,
        "reason": "",
        "matched_clause": None,
        "installed_version": None,
        "installed_version_state": "unknown",
        "project_identity_state": project["identity_state"],
        "severity_state": severity["state"],
        "severity_risk_vector": severity["risk_vector"],
        "cves": list(advisory["cves"]["identifiers"]),
        "fixed_versions": list(advisory["fixed_in"]["versions"]),
        "version_normalization": [],
        "limitations": [],
    }

    # A PSA is a policy or operational announcement. It carries no installed
    # version to match, so it is never resolved into an applicability verdict.
    if kind == KIND_PSA:
        result["applicability"] = UNKNOWN
        result["reason"] = (
            "Public service announcements carry no affected-version scope, so project "
            "applicability is not determinable from them."
        )
        result["limitations"].append("PSA advisories require human reading, not version matching.")
        return result

    if project["identity_state"] != "resolved":
        result["applicability"] = UNKNOWN
        result["reason"] = (
            "The advisory's project could not be resolved to an authoritative Drupal.org "
            "identity, and package identity is never matched by name similarity."
        )
        return result

    if kind == KIND_CORE:
        result["scope"] = SCOPE_CORE
        core = facts["core_version"]
        if core["state"] != "known":
            result["applicability"] = INSUFFICIENT_EVIDENCE
            result["reason"] = (
                "The analyzer observed no definitive installed Drupal core version, so a core "
                "advisory cannot be evaluated."
            )
            return result
        installed_raw = core["value"]
    else:
        result["scope"] = SCOPE_CONTRIB
        packages = facts["installed_packages"]
        if packages["state"] != "known":
            result["applicability"] = INSUFFICIENT_EVIDENCE
            result["reason"] = (
                "The analyzer observed no definitive installed package set, so a contrib "
                "advisory cannot be evaluated."
            )
            return result
        # Exact package identity only. drupal/<machine_name> comes from the
        # authoritative project node, never from advisory title text.
        wanted = project["composer_package"]
        matches = [item for item in packages["packages"] if item["name"] == wanted]
        if not matches:
            result["applicability"] = NOT_APPLICABLE
            result["reason"] = (
                f"The advisory concerns {wanted}, which the analyzer did not observe among the "
                f"{packages['count']} installed Drupal packages."
            )
            return result
        entry = matches[0]
        if entry["version_state"] != "known":
            result["installed_version_state"] = "unknown"
            result["applicability"] = UNKNOWN
            result["reason"] = (
                f"{wanted} is installed but its version is not definitively observed, so "
                "affected-version matching cannot conclude."
            )
            return result
        installed_raw = entry["version"]

    installed = parse_version(installed_raw)
    result["installed_version"] = installed_raw
    if installed is None:
        result["applicability"] = UNKNOWN
        result["reason"] = (
            f"Installed version {installed_raw!r} is not in a version format this engine reads, "
            "so applicability stays unknown rather than assuming safety."
        )
        return result

    result["installed_version_state"] = "known"
    result["version_normalization"] = list(installed.notes)

    if affected["state"] != "parsed":
        result["applicability"] = UNKNOWN
        result["reason"] = (
            f"The advisory's affected-version expression is {affected['state']}, so "
            "applicability cannot be determined."
        )
        return result

    # The advisory's own version scope decides what it speaks about. Evidence
    # from one Drupal major never carries to another, but a range that spans
    # majors does speak about every major inside it.
    covers = expression_covers_major(affected, installed.major)
    if covers is False:
        result["applicability"] = VERSION_OUT_OF_SCOPE
        result["reason"] = (
            f"No clause of {affected['source_value']!r} covers major version "
            f"{installed.major}, so the advisory does not speak about installed version "
            f"{installed_raw}."
        )
        return result

    outcome = evaluate_affected(installed, affected)
    result["applicability"] = outcome["state"]
    result["reason"] = outcome["detail"]
    result["matched_clause"] = outcome["matched_clause"]
    return result


def build_finding(advisory: dict, result: dict, facts: dict) -> dict | None:
    """Build a finding where one is warranted, at the state the evidence supports."""
    if result["applicability"] in (NOT_APPLICABLE, VERSION_OUT_OF_SCOPE):
        return None
    if result["scope"] == SCOPE_NOT_MATCHABLE:
        return None
    # A contrib advisory for a package the project does not carry produced
    # not_applicable above, so anything reaching here is potentially relevant.

    definitive = (
        result["applicability"] == APPLICABLE
        and result["project_identity_state"] == "resolved"
        and result["installed_version_state"] == "known"
    )
    if definitive:
        state = FINDING_CONFIRMED
    elif result["applicability"] == INSUFFICIENT_EVIDENCE:
        state = FINDING_UNKNOWN
    else:
        state = FINDING_CANDIDATE

    package = (
        DRUPAL_CORE_PACKAGE if result["scope"] == SCOPE_CORE else advisory["project"]["composer_package"]
    )
    return {
        "id": finding_identity(
            advisory["id"],
            result["scope"],
            package,
            result["installed_version"] if result["installed_version_state"] == "known" else None,
            facts["project_id"],
        ),
        "advisory_id": advisory["id"],
        "state": state,
        "scope": result["scope"],
        "installed_version": result["installed_version"],
        "affected_expression": advisory["affected_versions"]["source_value"],
        "severity_state": result["severity_state"],
        "severity_risk_vector": result["severity_risk_vector"],
        "cves": list(result["cves"]),
        "remediation": {
            "state": advisory["remediation"]["state"],
            "fixed_versions": list(advisory["remediation"]["fixed_versions"]),
            "authored_by_drupal_knowledge": False,
            "executed": False,
        },
        "enforcement": {
            "intent": ENFORCEMENT_INTENT,
            "policy_controlled": True,
            "automatically_blocking": False,
        },
        "evidence": {
            "advisory_source_id": advisory["provenance"]["source_id"],
            "advisory_snapshot_sha256": advisory["provenance"]["source_snapshot_sha256"],
            "project_identity_resolution": advisory["project"]["resolution"],
            "analyzer_fact_paths": [CORE_VERSION_FACT]
            if result["scope"] == SCOPE_CORE
            else [PACKAGES_FACT],
        },
        "is_trusted_knowledge": False,
    }


def evaluate(
    analysis: dict,
    root: Path = dk_core.ROOT,
    *,
    advisory_ids: Iterable[str] | None = None,
    moment: datetime | None = None,
) -> dict:
    """Evaluate the advisory set against one project's analyzer facts."""
    moment = moment or datetime.now(timezone.utc)
    facts = project_facts(analysis)
    advisories = iter_advisories(root)
    if advisory_ids is not None:
        wanted = set(advisory_ids)
        advisories = [item for item in advisories if item["id"] in wanted]
    advisories = sorted(advisories, key=lambda item: item["id"])

    digest_before = dk_core.knowledge_tree_digest(root)

    results: list[dict] = []
    findings: list[dict] = []
    try:
        for advisory in advisories:
            validate_advisory(advisory)
            result = evaluate_advisory(advisory, facts)
            results.append(result)
            finding = build_finding(advisory, result, facts)
            if finding is not None:
                findings.append(finding)
    except (SecurityInputError, dk_core.ValidationError):
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise SecurityEngineDefect(
            f"security engine defect during evaluation: {type(exc).__name__}: {exc}"
        ) from exc

    digest_after = dk_core.knowledge_tree_digest(root)
    if digest_before != digest_after:
        raise SecurityEngineDefect(
            "security evaluation mutated trusted knowledge; this is an engine defect"
        )

    summary = {
        state: sum(1 for item in results if item["applicability"] == state)
        for state in APPLICABILITY_STATES
    }
    summary["confirmed_findings"] = sum(
        1 for item in findings if item["state"] == FINDING_CONFIRMED
    )
    summary["candidate_findings"] = sum(
        1 for item in findings if item["state"] == FINDING_CANDIDATE
    )

    return {
        "schema_version": APPLICABILITY_SCHEMA_VERSION,
        "evaluation_id": "security-eval."
        + digest_hex(facts["project_id"], ",".join(item["id"] for item in advisories))[:16],
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
        },
        "evaluated_at": now_iso(moment),
        "project": facts,
        "advisories_considered": [item["id"] for item in advisories],
        "results": results,
        "findings": sorted(findings, key=lambda item: item["id"]),
        "summary": summary,
        "enforcement": {
            "intent": ENFORCEMENT_INTENT,
            "policy_controlled": True,
            "automatically_blocking": False,
            "blocking_requires_reviewed_policy": True,
        },
        "trusted_knowledge_mutations": [],
    }


# ---------------------------------------------------------------------------
# Repository contract
# ---------------------------------------------------------------------------


def validate_security_contract(root: Path = dk_core.ROOT) -> list[str]:
    """Validate security schemas, registered sources and stored advisories."""
    for relative in (
        "schema/security-advisory.schema.json",
        "schema/security-applicability.schema.json",
    ):
        dk_core.read_json(root / relative)

    registry = dk_acquisition.load_registry(root)
    feeds = [
        source
        for source in registry
        if (source.get("security") or {}).get("role") == "advisory_feed"
    ]
    for source in feeds:
        if source["trust"] != "authoritative":
            raise dk_core.ValidationError(
                f"source {source['id']}: advisory feeds must be authoritative"
            )

    advisories = iter_advisories(root)
    kinds = {KIND_CORE: 0, KIND_CONTRIB: 0, KIND_PSA: 0}
    sourced_severity_count = 0
    sourced_cve_count = 0
    for advisory in advisories:
        validate_advisory(advisory)
        kinds[advisory["advisory"]["kind"]] += 1
        if advisory["severity"]["state"] == SEVERITY_SOURCED:
            sourced_severity_count += 1
        if advisory["cves"]["state"] == SEVERITY_SOURCED:
            sourced_cve_count += 1
        source_id = advisory["provenance"]["source_id"]
        if source_id not in {source["id"] for source in registry}:
            raise dk_core.ValidationError(
                f"advisory {advisory['id']}: references unregistered source {source_id}"
            )

    return [
        "SECURITY_ADVISORY_CONTRACT_VALID=PASS",
        f"SECURITY_ENGINE_VERSION={ENGINE_VERSION}",
        f"SECURITY_ADVISORY_FEEDS={len(feeds)}",
        f"SECURITY_ADVISORIES={len(advisories)}",
        f"SECURITY_ADVISORIES_CORE={kinds[KIND_CORE]}",
        f"SECURITY_ADVISORIES_CONTRIB={kinds[KIND_CONTRIB]}",
        f"SECURITY_ADVISORIES_WITH_SOURCED_SEVERITY={sourced_severity_count}",
        f"SECURITY_ADVISORIES_WITH_SOURCED_CVE={sourced_cve_count}",
        "SECURITY_ADVISORY_NOT_TRUSTED_KNOWLEDGE=PASS",
        "SECURITY_ENFORCEMENT_REMAINS_GUIDANCE=PASS",
    ]
