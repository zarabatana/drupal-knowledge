#!/usr/bin/env python3
"""The query layer a Drupal developer actually talks to, without knowing any of this.

Twelve prompts built engines that each know how to read one thing. A developer
should not have to learn which of them owns advisories, which owns upgrade
compatibility, or where a snapshot lives on disk. This module is the single
read surface over all of them.

It answers questions, and it renders nothing. Every function returns a typed
result envelope; turning that into a terminal is somebody else's job, because
Prompt 15's website and Prompt 16's API will need the same answers with
different presentation and must not have to re-derive them from a formatted
string.

The one thing it must never do is flatten what Drupal Knowledge worked so hard
to keep apart::

    reviewed Drupal knowledge   != authoritative source-derived record
    authoritative record        != this project's observed evidence
    observed evidence           != a universal Drupal rule
    discovery signal            != anything trusted at all

So every result carries a trust class in plain language rather than an internal
enum, and a consumer that only reads the headline still cannot mistake a
community discovery signal for a reviewed rule.

Reading is all it does. No query fetches a URL, promotes a candidate, writes a
snapshot or touches a project.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import dk_core


QUERY_INTERFACE_VERSION = "0.1"
RESULT_CONTRACT_VERSION = "0.1"
QUERY_LAYER_NAME = "drupal-knowledge-query-layer"

# --- domains a community query may return ------------------------------------

D_KNOWLEDGE = "trusted_knowledge"
D_ADVISORY = "advisory"
D_API_LIFECYCLE = "api_lifecycle"
D_CHANGE_RECORD = "change_record"
D_IMPLEMENTATION_RULE = "implementation_rule"
D_PROJECT_EVIDENCE = "project_evidence"
D_FINDING = "finding"
D_IMPLEMENTATION_FINDING = "implementation_finding"
D_MIGRATION_WORK = "migration_work"
D_UPGRADE_ASSESSMENT = "upgrade_assessment"
D_REMEDIATION_PLAN = "remediation_plan"
D_SOLVED_CASE = "solved_case"
D_DISCOVERY_SIGNAL = "discovery_signal"

DOMAINS = (
    D_KNOWLEDGE,
    D_ADVISORY,
    D_API_LIFECYCLE,
    D_CHANGE_RECORD,
    D_IMPLEMENTATION_RULE,
    D_PROJECT_EVIDENCE,
    D_FINDING,
    D_IMPLEMENTATION_FINDING,
    D_MIGRATION_WORK,
    D_UPGRADE_ASSESSMENT,
    D_REMEDIATION_PLAN,
    D_SOLVED_CASE,
    D_DISCOVERY_SIGNAL,
)

# Domains a bare search walks. Discovery signals are deliberately absent: they
# are community observations awaiting corroboration, and a developer who did
# not ask for them should never meet one in a result list.
SEARCHABLE_DOMAINS = (
    D_KNOWLEDGE,
    D_ADVISORY,
    D_API_LIFECYCLE,
    D_CHANGE_RECORD,
    D_IMPLEMENTATION_RULE,
    D_SOLVED_CASE,
)
OPT_IN_DOMAINS = (D_DISCOVERY_SIGNAL,)

# --- trust classes, in words rather than enums --------------------------------
#
# The label a consumer reads is the point. An internal string like
# "source_derived_authoritative_record" tells a Drupal developer nothing about
# whether they may act on it.

TRUST_CLASSES = {
    "reviewed_drupal_knowledge": {
        "authority": "reviewed Drupal Knowledge record",
        "record_type": "trusted knowledge, reviewed by a human against authoritative sources",
        "trusted_knowledge": True,
        "universal_drupal_rule": True,
        "explanation": (
            "A human reviewed this against registered authoritative sources. It states "
            "something about Drupal, not about any one project."
        ),
    },
    "source_derived_authoritative": {
        "authority": "authoritative Drupal source",
        "record_type": "source-derived authoritative record",
        "trusted_knowledge": False,
        "universal_drupal_rule": True,
        "explanation": (
            "Projected verbatim from an official Drupal source snapshot. It is "
            "authoritative evidence about Drupal, but it is not a Drupal Knowledge rule."
        ),
    },
    "reviewed_implementation_rule": {
        "authority": "reviewed Drupal Knowledge implementation rule",
        "record_type": "reviewed rule evaluated against project evidence",
        "trusted_knowledge": False,
        "universal_drupal_rule": False,
        "explanation": (
            "A reviewed rule whose authority is a pinned authoritative source. It says "
            "what to look for; it says nothing until evidence settles it."
        ),
    },
    "project_observation": {
        "authority": "observed in this project",
        "record_type": "project-derived evidence",
        "trusted_knowledge": False,
        "universal_drupal_rule": False,
        "explanation": (
            "Observed in this repository at this revision. It is a fact about this "
            "project and never a rule about Drupal."
        ),
    },
    "derived_finding": {
        "authority": "derived from a rule and this project's evidence",
        "record_type": "finding",
        "trusted_knowledge": False,
        "universal_drupal_rule": False,
        "explanation": (
            "Produced by applying a reviewed rule or authoritative record to this "
            "project's evidence. Its strength is whatever its state and evidence say."
        ),
    },
    "proven_case_context_only": {
        "authority": "verified in one observed project context",
        "record_type": "solved case",
        "trusted_knowledge": False,
        "universal_drupal_rule": False,
        "explanation": (
            "Proven in the project context it was captured from. It is not universal "
            "Drupal truth and widening it requires review."
        ),
    },
    "untrusted_discovery_signal": {
        "authority": "community observation, not authority",
        "record_type": "discovery signal",
        "trusted_knowledge": False,
        "universal_drupal_rule": False,
        "explanation": (
            "An untrusted ecosystem observation awaiting corroboration and review. It "
            "may not be acted on as Drupal Knowledge."
        ),
    },
}

DOMAIN_TRUST_CLASS = {
    D_KNOWLEDGE: "reviewed_drupal_knowledge",
    D_ADVISORY: "source_derived_authoritative",
    D_API_LIFECYCLE: "source_derived_authoritative",
    D_CHANGE_RECORD: "source_derived_authoritative",
    D_IMPLEMENTATION_RULE: "reviewed_implementation_rule",
    D_PROJECT_EVIDENCE: "project_observation",
    D_FINDING: "derived_finding",
    D_IMPLEMENTATION_FINDING: "derived_finding",
    D_MIGRATION_WORK: "derived_finding",
    D_UPGRADE_ASSESSMENT: "derived_finding",
    D_REMEDIATION_PLAN: "derived_finding",
    D_SOLVED_CASE: "proven_case_context_only",
    D_DISCOVERY_SIGNAL: "untrusted_discovery_signal",
}

# Words a query result may never use about an absence. "Not observed" is not
# "safe", and the difference is the whole product.
FORBIDDEN_REASSURANCE = ("secure", "safe", "not affected", "compliant", "no issues", "all clear")

LOCAL_PATH_RE = re.compile(r"(^|[\"'\s=:(])(/Users/|/home/|/root/|[A-Za-z]:\\\\)")

# Deterministic ranking bands. Exact structured identity always outranks text.
RANK_EXACT_ID = 1000
RANK_EXACT_FIELD = 900
RANK_PREFIX_ID = 600
RANK_EXACT_TOKEN = 400
RANK_TITLE_SUBSTRING = 200
RANK_BODY_SUBSTRING = 50


class QueryInputError(RuntimeError):
    """The caller asked for something that does not exist or cannot be read.

    Always a user-facing message, never a stack trace.
    """


class QueryLayerDefect(RuntimeError):
    """A defect in this layer. Never reported as a user error."""


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
# Result contract
# ---------------------------------------------------------------------------


def trust_block(domain: str, extra: dict | None = None) -> dict:
    if domain not in DOMAIN_TRUST_CLASS:
        raise QueryLayerDefect(f"no trust class declared for domain {domain!r}")
    name = DOMAIN_TRUST_CLASS[domain]
    block = {"class": name, **TRUST_CLASSES[name]}
    if extra:
        block.update(extra)
    return block


def result(
    domain: str,
    identifier: str,
    title: str,
    summary: str,
    *,
    trust_extra: dict | None = None,
    detail: dict | None = None,
    provenance: list[dict] | None = None,
    unknowns: list[str] | None = None,
) -> dict:
    if domain not in DOMAINS:
        raise QueryLayerDefect(f"unknown query domain {domain!r}")
    return {
        "domain": domain,
        "id": identifier,
        "title": title,
        "summary": summary,
        "trust": trust_block(domain, trust_extra),
        "detail": detail or {},
        "provenance": provenance or [],
        "unknowns": unknowns or [],
    }


def envelope(
    query: str,
    query_type: str,
    results: list[dict],
    *,
    root: Path,
    warnings: list[str] | None = None,
    unknowns: list[str] | None = None,
    provenance: list[dict] | None = None,
    sections: dict | None = None,
    generated_at: str | None = None,
) -> dict:
    payload = {
        "query_contract_version": RESULT_CONTRACT_VERSION,
        "query_interface_version": QUERY_INTERFACE_VERSION,
        "query": query,
        "query_type": query_type,
        "dataset": dataset_identity(root),
        "result_count": len(results),
        "results": results,
        "warnings": sorted(set(warnings or [])),
        "unknowns": sorted(set(unknowns or [])),
        "provenance": provenance or [],
        "generated_at": generated_at or now_iso(),
    }
    if sections is not None:
        payload["sections"] = sections
    assert_no_reassurance(payload)
    return payload


def assert_no_reassurance(payload: Any) -> None:
    """Refuse to describe an absence of evidence as a clean bill of health."""
    for text in recursive_strings(payload):
        lowered = text.lower()
        for phrase in ("is secure", "is safe", "site is secure", "no issues found", "all clear"):
            if phrase in lowered:
                raise QueryLayerDefect(f"refused a reassurance claim: {phrase!r}")


def recursive_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from recursive_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from recursive_strings(item)


# ---------------------------------------------------------------------------
# Dataset identity and freshness
# ---------------------------------------------------------------------------
#
# Two identities, and they answer different questions.
#
#     VERSION      which release of the product you are running
#     dataset_id   which trusted semantic knowledge that release holds
#
# They are related by a release and by nothing else. A release may ship a CLI
# fix over unchanged knowledge, and a source re-fetch may prove the knowledge
# still current without a release. Neither is required to move the other, so
# neither is allowed to be an input to the other.
#
# What follows is therefore computed from the trusted records alone. Freshness,
# snapshot digests, review dates, ingestion dates, the build clock and the
# release version are all real and all preserved elsewhere; none of them is
# knowledge, so none of them appears here.


# The record stores whose contents are trusted public Drupal knowledge. This is
# the published set of `dk_public.PUBLIC_DOMAINS`, named here because identity
# is a property of the knowledge and must not wait for a website to exist.
# `D_DISCOVERY_SIGNAL` is deliberately absent: an untrusted community
# observation is not knowledge, and counting one would let unreviewed material
# move the identity of reviewed material.
SEMANTIC_DOMAINS = (
    D_KNOWLEDGE,
    D_ADVISORY,
    D_API_LIFECYCLE,
    D_CHANGE_RECORD,
    D_IMPLEMENTATION_RULE,
    D_SOLVED_CASE,
)

# Domain separation, so that two public fields derived from one payload cannot
# be prefixes of one another and nobody can "verify" one by slicing the other.
_RECORDS_DIGEST_LABEL = "drupal-knowledge/semantic-records"
_DATASET_ID_LABEL = "drupal-knowledge/semantic-dataset"

# Deliberately not cached. Identity is cheap to compute (one projection pass)
# and a memo keyed by directory path is how a process ends up reporting the
# identity a tree had before it was edited. A wrong identity is worth far more
# than the milliseconds a cache would save.


def semantic_trust(trust: dict) -> dict:
    """A record's own trust facts, without the shared trust-class prose.

    The class name is knowledge: it says how far the record may be trusted.
    The paragraph explaining what that class means is product wording, shared
    by every record of the class, and rewording it changes no Drupal fact — so
    only what this record says beyond its class is kept.
    """
    name = trust.get("class")
    shared = TRUST_CLASSES.get(name, {})
    kept = {"class": name}
    for key, value in trust.items():
        if key != "class" and (key not in shared or shared[key] != value):
            kept[key] = value
    return kept


def semantic_records(root: Path = dk_core.ROOT) -> list[dict]:
    """Every trusted record this release publishes, canonically projected.

    The projection is the one the CLI and the website already answer with, so
    identity is computed over exactly the knowledge a reader is given, not over
    a private shadow of it. It is a pure function of the canonical record
    stores: no clock, no filesystem layout, no registry state.

    Route, label and explanation are excluded on purpose. They are how the
    knowledge is presented, they move when the product moves, and a reworded
    explanation is a release, not a new dataset.
    """
    payload = []
    for domain in SEMANTIC_DOMAINS:
        loader, projector = PROJECTORS[domain]
        for record in loader(root):
            item = projector(record)
            payload.append(
                {
                    "domain": domain,
                    "id": item["id"],
                    "title": item["title"],
                    "summary": item["summary"],
                    "trust": semantic_trust(item["trust"]),
                    "detail": item["detail"],
                    "provenance": item["provenance"],
                    "unknowns": item["unknowns"],
                }
            )
    # Ordering is not knowledge. Two trees holding the same records are the
    # same dataset however their files happen to be laid out or listed.
    payload.sort(key=lambda entry: (entry["domain"], entry["id"], stable_json(entry)))
    return payload


def semantic_identity(root: Path = dk_core.ROOT) -> dict:
    """The identity of the trusted semantic knowledge, and nothing else.

    Recomputed on every call, so a caller that edits a tree and asks again is
    told what the tree now holds rather than what it held a moment ago.
    """
    payload = stable_json(semantic_records(root))
    return {
        "records_digest": digest_hex(_RECORDS_DIGEST_LABEL, payload)[:16],
        "dataset_id": "dataset:" + digest_hex(_DATASET_ID_LABEL, payload)[:32],
    }


def dataset_identity(root: Path = dk_core.ROOT) -> dict:
    """What release and record set this answer came from.

    `record_counts` still reports the discovery signals held, because a reader
    of `dk status` should see them. Reporting them is not trusting them: they
    are not in `records_digest` and never reach dataset identity.
    """
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    counts = {
        D_KNOWLEDGE: len(dk_core.iter_json_files(root / "knowledge" / "records")),
        D_ADVISORY: len(dk_core.iter_json_files(root / "security" / "advisories")),
        D_API_LIFECYCLE: len(dk_core.iter_json_files(root / "api" / "lifecycle")),
        D_CHANGE_RECORD: len(dk_core.iter_json_files(root / "api" / "change-records")),
        D_IMPLEMENTATION_RULE: len(dk_core.iter_json_files(root / "rules" / "implementation")),
        D_SOLVED_CASE: len(dk_core.iter_json_files(root / "cases" / "solved")),
        D_DISCOVERY_SIGNAL: len(dk_core.iter_json_files(root / "discovery" / "signals")),
    }
    identity = {
        "drupal_knowledge_version": version,
        "record_counts": counts,
        "records_digest": semantic_identity(root)["records_digest"],
    }
    return identity


def source_freshness(root: Path = dk_core.ROOT) -> dict:
    """How current the registered sources behind an answer are.

    Surfaced where it changes confidence rather than on every query, because a
    staleness banner on every line teaches people to ignore it.
    """
    stale: list[dict] = []
    unbaselined: list[str] = []
    checked = 0
    for source in dk_core.load_sources(root):
        state_path = root / "sources" / "state" / f"{source['id']}.json"
        if not state_path.is_file():
            unbaselined.append(source["id"])
            continue
        state = dk_core.read_json(state_path)
        if not state.get("content_sha256"):
            unbaselined.append(source["id"])
            continue
        checked += 1
        cadence = source.get("check_cadence_days")
        last = (state.get("acquisition") or {}).get("last_success_at")
        if not cadence or not last:
            continue
        try:
            when = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        age = (datetime.now(timezone.utc) - when).days
        if age > cadence:
            stale.append({"source_id": source["id"], "age_days": age, "cadence_days": cadence})
    return {
        "sources_checked": checked,
        "unbaselined": sorted(unbaselined),
        "stale": sorted(stale, key=lambda item: item["source_id"]),
        "note": (
            "Freshness describes when a source was last acquired. Acquisition is a "
            "separate maintainer operation; querying never fetches anything."
        ),
    }


# ---------------------------------------------------------------------------
# Record loading
# ---------------------------------------------------------------------------


def _load(root: Path, relative: str) -> list[dict]:
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(root / relative)]


def knowledge_records(root: Path = dk_core.ROOT) -> list[dict]:
    """Reviewed knowledge only. Anything unreviewed is not trusted knowledge."""
    return [
        record
        for record in dk_core.load_knowledge_records(root)
        if record.get("review_status") == "reviewed"
    ]


def advisories(root: Path = dk_core.ROOT) -> list[dict]:
    return _load(root, "security/advisories")


def api_lifecycle_records(root: Path = dk_core.ROOT) -> list[dict]:
    return _load(root, "api/lifecycle")


def change_records(root: Path = dk_core.ROOT) -> list[dict]:
    return _load(root, "api/change-records")


def implementation_rules(root: Path = dk_core.ROOT) -> list[dict]:
    return _load(root, "rules/implementation")


def solved_cases(root: Path = dk_core.ROOT) -> list[dict]:
    return dk_core.load_solved_cases(root)


def discovery_signals(root: Path = dk_core.ROOT) -> list[dict]:
    return _load(root, "discovery/signals")


# ---------------------------------------------------------------------------
# Projections: one record -> one typed result
# ---------------------------------------------------------------------------


def project_knowledge(record: dict) -> dict:
    return result(
        D_KNOWLEDGE,
        record["id"],
        record["title"],
        record["summary"],
        trust_extra={
            "review_status": record["review_status"],
            "enforcement": dk_core.effective_enforcement(record),
        },
        detail={
            "domains": record.get("domains", []),
            "kind": record.get("kind"),
            "version_applicability": record.get("version_applicability", {}),
        },
        provenance=[
            {
                "channel": "authoritative_source",
                "source_id": item["source_id"],
                "locator": item.get("locator"),
            }
            for item in record.get("sources", [])
        ],
    )


def project_advisory(record: dict) -> dict:
    advisory = record["advisory"]
    severity = record["severity"]
    return result(
        D_ADVISORY,
        record["id"],
        advisory["title"],
        (
            f"{advisory['kind']} advisory for "
            f"{record['project'].get('machine_name') or 'an unresolved project'}"
        ),
        trust_extra={"authority": "Drupal Security Team"},
        detail={
            "kind": advisory["kind"],
            "vulnerability_type": advisory.get("vulnerability_type"),
            "published_at": advisory.get("published_at"),
            "project": record["project"].get("machine_name"),
            "composer_package": record["project"].get("composer_package"),
            # The advisory's own affected-version expression, verbatim. The key
            # is source_value; reading a key the record does not have silently
            # dropped the most important field an advisory publishes.
            "affected_versions": record["affected_versions"].get("source_value"),
            "affected_versions_state": record["affected_versions"].get("state"),
            # A vector, never a number. Drupal publishes the vector and Drupal
            # Knowledge does not compute a score from it.
            "risk_vector": severity.get("risk_vector"),
            "risk_vector_state": severity.get("state"),
            "scored_by_drupal_knowledge": severity.get("scored_by_drupal_knowledge", False),
            "cves": record["cves"].get("identifiers", []),
            "cve_state": record["cves"].get("state"),
            "fixed_in": list(record.get("fixed_in", {}).get("versions", [])),
            "fixed_in_state": record.get("fixed_in", {}).get("state"),
            # Whether the source published a solution at all, kept apart from
            # whether Drupal Knowledge wrote one. It never does.
            "remediation_state": record.get("remediation", {}).get("state"),
            "remediation_authored_by_drupal_knowledge": record.get("remediation", {}).get(
                "authored_by_drupal_knowledge", False
            ),
        },
        provenance=[
            {
                "channel": "authoritative_source",
                "source_id": record["provenance"]["source_id"],
                "source_url": record["provenance"].get("source_url"),
                "snapshot_sha256": record["provenance"].get("source_snapshot_sha256"),
            }
        ],
        unknowns=(
            []
            if severity.get("state") == "sourced"
            else ["The advisory publishes no risk vector, so none is reported."]
        ),
    )


def project_api_lifecycle(record: dict) -> dict:
    symbol = record["symbol"]
    lifecycle = record["lifecycle"]
    return result(
        D_API_LIFECYCLE,
        record["id"],
        symbol["qualified_name"] or symbol["index_name"],
        (
            f"{symbol['kind']} deprecated in {lifecycle['deprecated_version'] or 'an unstated version'}"
            f", removed from {lifecycle['removed_version'] or 'an unstated version'}"
        ),
        detail={
            "symbol": symbol["index_name"],
            "qualified_name": symbol["qualified_name"],
            "kind": symbol["kind"],
            "deprecated_version": lifecycle["deprecated_version"],
            "removed_version": lifecycle["removed_version"],
            "replacement": record["replacement"]["value"],
            "replacement_state": record["replacement"]["state"],
            "core_file": symbol["core_file"],
        },
        provenance=[
            {
                "channel": "authoritative_source",
                "source_id": record["provenance"]["source_id"],
                "source_url": record["provenance"].get("source_url"),
                "snapshot_sha256": record["provenance"].get("source_snapshot_sha256"),
            }
        ],
        unknowns=(
            []
            if record["replacement"]["state"] != "unknown"
            else ["The annotation states no replacement, and none is invented."]
        ),
    )


def project_change_record(record: dict) -> dict:
    change = record["change_record"]
    return result(
        D_CHANGE_RECORD,
        record["id"],
        change["title"],
        f"{record['category']['value']} introduced in {change['introduced_version'] or 'an unstated version'}",
        detail={
            "node_id": change["node_id"],
            "url": change["canonical_url"],
            "introduced_branch": change["introduced_branch"],
            "introduced_version": change["introduced_version"],
            "category": record["category"]["value"],
            "symbols": record["symbols"]["named_with_call_syntax"],
        },
        provenance=[
            {
                "channel": "authoritative_source",
                "source_id": record["provenance"]["source_id"],
                "snapshot_sha256": record["provenance"].get("source_snapshot_sha256"),
            }
        ],
        unknowns=["A change record names symbols but asserts no lifecycle for them."],
    )


def project_implementation_rule(record: dict) -> dict:
    return result(
        D_IMPLEMENTATION_RULE,
        record["rule_id"],
        record["title"],
        record["summary"],
        trust_extra={"review_status": record["review"]["status"]},
        detail={
            "category": record["category"],
            "review_status": record["review"]["status"],
            "enforcement_intent": record["finding"]["enforcement_intent"],
            "severity_state": record["finding"]["severity_state"],
            "scope": record["scope"],
            "context_requirements": [
                item["assertion"] for item in record.get("context_requirements", [])
            ],
        },
        provenance=[
            {
                "channel": "authoritative_source",
                "source_id": item["source_id"],
                "snapshot_sha256": item["snapshot_sha256"],
                "quotes": item["quotes"],
            }
            for item in record["authority"]["sources"]
        ],
        unknowns=(
            []
            if record["review"]["status"] == "reviewed"
            else [f"The rule is {record['review']['status']} and may not confirm a finding."]
        ),
    )


def project_solved_case(record: dict) -> dict:
    """A solved case, with its context boundary in the headline, not a footnote."""
    return result(
        D_SOLVED_CASE,
        record["id"],
        record["title"],
        record.get("problem") or "",
        detail={
            "status": record["status"],
            # What was wrong, what caused it, what fixed it and how that was
            # checked. A case with the problem hidden is not a worked example,
            # and none of these fields names a project.
            "problem": record.get("problem") or "",
            "symptoms": record.get("symptoms", []),
            "root_cause": record.get("root_cause") or "",
            "root_cause_state": (record.get("capture") or {}).get("root_cause_state"),
            "solution": record.get("solution", []),
            "verification": record.get("verification", []),
            "limitations": record.get("limitations", []),
            "claimed_scope": record["applicability"]["claimed_scope"],
            "conditions": record["applicability"].get("conditions", []),
            "drupal_versions": record.get("drupal_versions", []),
            "php_versions": record.get("php_versions", []),
            "occurrence_count": record.get("occurrence_count"),
            "expansion_requires_review": record["applicability"].get(
                "expansion_requires_review", True
            ),
            # Deliberately no project name or path: a case is identified by its
            # own id and the context it was proven in, never by the project owner.
            "project_identity_disclosed": False,
        },
        provenance=[{"channel": "internal_solved_case", "case_id": record["id"]}],
        unknowns=[
            "Proven in one observed project context. It is not universal Drupal truth.",
        ],
    )


def project_discovery_signal(record: dict) -> dict:
    return result(
        D_DISCOVERY_SIGNAL,
        record["id"],
        record.get("summary") or record["id"],
        "Untrusted ecosystem observation awaiting corroboration and review.",
        trust_extra={"review_status": record.get("review_status")},
        detail={
            "kind": record.get("kind"),
            "review_status": record.get("review_status"),
            "review_required": record.get("review_required"),
            "can_promote_to_knowledge": record.get("can_promote_to_knowledge", False),
            "is_trusted_knowledge": record.get("is_trusted_knowledge", False),
        },
        provenance=[
            {
                "channel": "discovery_signal",
                "source_id": (record.get("source") or {}).get("source_id"),
                "source_url": (record.get("source") or {}).get("canonical_url"),
                "snapshot_sha256": (record.get("source") or {}).get("snapshot_sha256"),
            }
        ],
        unknowns=[
            "This is an untrusted discovery signal, not Drupal Knowledge, and may not "
            "be acted on as one until it is corroborated and reviewed.",
        ],
    )


PROJECTORS: dict[str, tuple[Callable[[Path], list[dict]], Callable[[dict], dict]]] = {
    D_KNOWLEDGE: (knowledge_records, project_knowledge),
    D_ADVISORY: (advisories, project_advisory),
    D_API_LIFECYCLE: (api_lifecycle_records, project_api_lifecycle),
    D_CHANGE_RECORD: (change_records, project_change_record),
    D_IMPLEMENTATION_RULE: (implementation_rules, project_implementation_rule),
    D_SOLVED_CASE: (solved_cases, project_solved_case),
    D_DISCOVERY_SIGNAL: (discovery_signals, project_discovery_signal),
}


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def searchable_fields(domain: str, record: dict) -> dict[str, list[str]]:
    """Structured identity fields, kept apart from free text.

    An advisory id matching an advisory's own id is a different kind of match
    from that id appearing in some other record's prose, and the ranking has to
    be able to tell them apart.
    """
    if domain == D_KNOWLEDGE:
        return {
            "identity": [record["id"]],
            "structured": list(record.get("domains", [])),
            "title": [record["title"]],
            "body": [record["summary"]],
        }
    if domain == D_ADVISORY:
        return {
            "identity": [record["id"]],
            "structured": [
                record["project"].get("machine_name") or "",
                record["project"].get("composer_package") or "",
                *record["cves"].get("identifiers", []),
            ],
            "title": [record["advisory"]["title"]],
            "body": [record["advisory"].get("vulnerability_type") or ""],
        }
    if domain == D_API_LIFECYCLE:
        symbol = record["symbol"]
        return {
            "identity": [record["id"], symbol["index_name"]],
            "structured": [symbol["qualified_name"] or "", symbol["member"] or ""],
            "title": [symbol["qualified_name"] or symbol["index_name"]],
            "body": [record["lifecycle"]["source_annotation"]],
        }
    if domain == D_CHANGE_RECORD:
        return {
            "identity": [record["id"], record["change_record"]["node_id"]],
            "structured": list(record["symbols"]["named_with_call_syntax"]),
            "title": [record["change_record"]["title"]],
            "body": [record["description"]["excerpt"]],
        }
    if domain == D_IMPLEMENTATION_RULE:
        return {
            "identity": [record["rule_id"]],
            "structured": [record["category"]],
            "title": [record["title"]],
            "body": [record["summary"], record["finding"]["assertion"]],
        }
    if domain == D_SOLVED_CASE:
        return {
            "identity": [record["id"]],
            "structured": list(record.get("drupal_versions", [])),
            "title": [record["title"]],
            "body": [record["problem"]["statement"] if isinstance(record.get("problem"), dict) else ""],
        }
    if domain == D_DISCOVERY_SIGNAL:
        claim = record.get("claim") or {}
        component = ((record.get("scope") or {}).get("component") or {})
        return {
            "identity": [record["id"]],
            # A signal is about something — a project, a release, a component.
            # Without these it is only findable by an opaque hash, which is not
            # a search anyone can perform.
            "structured": [
                component.get("machine_name") or "",
                component.get("composer_package") or "",
                (record.get("source") or {}).get("source_id") or "",
            ],
            "title": [record.get("summary") or "", claim.get("assertion_key") or ""],
            "body": [claim.get("assertion_value") or ""],
        }
    return {"identity": [], "structured": [], "title": [], "body": []}


TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


def score_record(term: str, fields: dict[str, list[str]]) -> tuple[int, str]:
    """Deterministic relevance. Structured identity always beats prose.

    No fuzzy layer participates in this score: a near-miss can help someone find
    a name they half-remember, but it must never decide which record *is* the
    one they asked for.
    """
    needle = term.strip()
    lowered = needle.lower()

    for value in fields["identity"]:
        if value and value.lower() == lowered:
            return RANK_EXACT_ID, "exact identifier match"
    for value in fields["structured"]:
        if value and value.lower() == lowered:
            return RANK_EXACT_FIELD, "exact structured field match"
    for value in fields["identity"]:
        if value and value.lower().startswith(lowered) and len(lowered) >= 3:
            return RANK_PREFIX_ID, "identifier prefix match"
    for group in ("title", "structured"):
        for value in fields[group]:
            if value and lowered in {token.lower() for token in TOKEN_RE.findall(value)}:
                return RANK_EXACT_TOKEN, f"exact word in {group}"
    for value in fields["title"]:
        if value and lowered in value.lower():
            return RANK_TITLE_SUBSTRING, "title contains the term"
    for value in fields["body"]:
        if value and lowered in value.lower():
            return RANK_BODY_SUBSTRING, "text contains the term"
    return 0, ""


def search(
    term: str,
    root: Path = dk_core.ROOT,
    domains: Iterable[str] | None = None,
    limit: int = 20,
    generated_at: str | None = None,
) -> dict:
    """Search canonical records. Never a repository grep."""
    if not isinstance(term, str) or not term.strip():
        raise QueryInputError("a search term is required")
    selected = list(domains) if domains else list(SEARCHABLE_DOMAINS)
    for domain in selected:
        if domain not in PROJECTORS:
            raise QueryInputError(
                f"unknown search domain {domain!r}; known domains are "
                + ", ".join(sorted(PROJECTORS))
            )

    warnings: list[str] = []
    if domains is None:
        warnings.append(
            "Discovery signals are excluded by default. Add --domain discovery_signal "
            "to include untrusted community observations."
        )
    elif D_DISCOVERY_SIGNAL in selected:
        warnings.append(
            "Discovery signals are untrusted community observations, not Drupal Knowledge."
        )

    scored: list[tuple[int, int, str, dict]] = []
    for domain in selected:
        loader, projector = PROJECTORS[domain]
        for record in loader(root):
            rank, why = score_record(term, searchable_fields(domain, record))
            if rank == 0:
                continue
            item = projector(record)
            item["match"] = {"rank": rank, "reason": why}
            scored.append((-rank, DOMAINS.index(domain), item["id"], item))

    scored.sort(key=lambda entry: (entry[0], entry[1], entry[2]))
    results = [item for _, _, _, item in scored[:limit]]
    truncated = len(scored) - len(results)
    if truncated > 0:
        warnings.append(f"{truncated} further match(es) not shown; raise --limit to see them.")

    return envelope(
        term,
        "search",
        results,
        root=root,
        warnings=warnings,
        unknowns=(
            []
            if results
            else [
                "Nothing matched. Drupal Knowledge holds a bounded record set, so no "
                "match is not evidence that the subject is unproblematic."
            ]
        ),
        generated_at=generated_at,
    )


# ---------------------------------------------------------------------------
# Direct lookup, explain and provenance
# ---------------------------------------------------------------------------


def find_record(identifier: str, root: Path = dk_core.ROOT) -> tuple[str, dict] | None:
    """Locate one record by id across every domain, including opt-in ones."""
    for domain in DOMAINS:
        if domain not in PROJECTORS:
            continue
        loader, _ = PROJECTORS[domain]
        for record in loader(root):
            for candidate in searchable_fields(domain, record)["identity"]:
                if candidate and candidate == identifier:
                    return domain, record
    return None


def show(identifier: str, root: Path = dk_core.ROOT, generated_at: str | None = None) -> dict:
    found = find_record(identifier, root)
    if found is None:
        raise QueryInputError(
            f"no Drupal Knowledge record has the identifier {identifier!r}. "
            "Try `dk search` to find it."
        )
    domain, record = found
    _, projector = PROJECTORS[domain]
    return envelope(identifier, "show", [projector(record)], root=root, generated_at=generated_at)


def explain(identifier: str, root: Path = dk_core.ROOT, generated_at: str | None = None) -> dict:
    """Everything a reader should be able to ask about one record.

    What it is, why it exists, what supports it, what is authoritative, what is
    project-specific, what is unknown, and whether anything was changed. The
    last one is always no.
    """
    found = find_record(identifier, root)
    if found is None:
        raise QueryInputError(
            f"no Drupal Knowledge record has the identifier {identifier!r}. "
            "Try `dk search` to find it."
        )
    domain, record = found
    _, projector = PROJECTORS[domain]
    item = projector(record)
    chain = provenance_chain(domain, record, root)
    item["explanation"] = explanation_for(domain, record, root, item=item, chain=chain)
    return envelope(
        identifier, "explain", [item], root=root, provenance=chain, generated_at=generated_at
    )


def explanation_for(
    domain: str,
    record: dict,
    root: Path = dk_core.ROOT,
    *,
    item: dict | None = None,
    chain: list[dict] | None = None,
) -> dict:
    """The seven questions, answered once for every consumer.

    Separate from ``explain`` so a bulk consumer — the public site export walks
    every record in the repository — can compose an explanation without paying
    for an identifier search it has already done. Both callers get the same
    words because there is only one place they are written.
    """
    if item is None:
        item = PROJECTORS[domain][1](record)
    if chain is None:
        chain = provenance_chain(domain, record, root)
    return {
        "what_is_this": f"{item['trust']['record_type']}: {item['title']}",
        "why_does_it_exist": explain_reason(domain, record),
        "what_supports_it": [
            entry.get("source_id") or entry.get("case_id") or entry["channel"] for entry in chain
        ],
        "what_is_authoritative": item["trust"]["explanation"],
        "what_is_project_specific": (
            "Nothing: this record is about Drupal, not about any one project."
            if item["trust"]["universal_drupal_rule"]
            else "This record is scoped to the context it names and is not a Drupal-wide rule."
        ),
        "what_is_unknown": item["unknowns"] or ["Nothing was left unstated by this record."],
        "what_is_recommended": explain_recommendation(domain, record),
        "was_anything_changed": "No. Querying Drupal Knowledge changes nothing.",
    }


def explain_reason(domain: str, record: dict) -> str:
    if domain == D_KNOWLEDGE:
        return "A human reviewed authoritative Drupal sources and recorded this as trusted knowledge."
    if domain == D_ADVISORY:
        return "The Drupal Security Team published this advisory and Drupal Knowledge projected it verbatim."
    if domain == D_API_LIFECYCLE:
        return "Drupal core annotates this symbol with a deprecation, and api.drupal.org publishes the annotation."
    if domain == D_CHANGE_RECORD:
        return "Drupal core published this change record for a change that landed in a branch."
    if domain == D_IMPLEMENTATION_RULE:
        return "A reviewer tied an authoritative Drupal statement to a condition that project evidence can settle."
    if domain == D_SOLVED_CASE:
        return "A real problem was solved and verified in one observed project context."
    if domain == D_DISCOVERY_SIGNAL:
        return "An ecosystem source published something that may matter. Nothing has been reviewed yet."
    return "It exists because a Drupal Knowledge engine produced it from evidence."


def explain_recommendation(domain: str, record: dict) -> str:
    if domain == D_ADVISORY:
        return (
            "Evaluate it against a project with `dk security-evaluate`; an advisory alone "
            "says nothing about whether your project is affected."
        )
    if domain == D_API_LIFECYCLE:
        return (
            "Check whether your custom code uses the symbol with `dk migration-analyze`; "
            "a deprecation matters only where the code actually calls it."
        )
    if domain == D_IMPLEMENTATION_RULE:
        return "Evaluate it against a project with `dk implementation-findings`."
    if domain == D_SOLVED_CASE:
        return "Treat it as a worked example for the context it names, not as a rule."
    if domain == D_DISCOVERY_SIGNAL:
        return "Nothing. It awaits corroboration and review before it can be acted on."
    return "Read the record's own actions and checks."


def provenance_chain(domain: str, record: dict, root: Path) -> list[dict]:
    """Lineage from a record back to the source snapshot behind it."""
    chain: list[dict] = []
    projector = PROJECTORS[domain][1]
    for entry in projector(record)["provenance"]:
        step = dict(entry)
        source_id = step.get("source_id")
        if source_id:
            registered = {item["id"]: item for item in dk_core.load_sources(root)}
            source = registered.get(source_id)
            if source:
                step["source_title"] = source["title"]
                step["source_url"] = step.get("source_url") or source["url"]
                step["source_trust"] = source["trust"]
            else:
                step["source_title"] = None
                step["unresolved"] = True
        chain.append(step)
    return chain


def provenance(identifier: str, root: Path = dk_core.ROOT, generated_at: str | None = None) -> dict:
    """Machine-traversable lineage for one record."""
    found = find_record(identifier, root)
    if found is None:
        raise QueryInputError(
            f"no Drupal Knowledge record has the identifier {identifier!r}. "
            "Try `dk search` to find it."
        )
    domain, record = found
    chain = provenance_chain(domain, record, root)
    edges = [
        {"from": identifier, "from_domain": domain, "to": step.get("source_id") or step["channel"],
         "to_kind": step["channel"], "relation": "supported_by"}
        for step in chain
    ]
    return envelope(
        identifier,
        "provenance",
        [
            result(
                domain,
                identifier,
                PROJECTORS[domain][1](record)["title"],
                "Lineage from this record to the authority behind it.",
                detail={"edges": edges, "steps": chain},
                # The chain is carried on the result as well as the envelope so
                # a renderer showing one record shows its lineage with it.
                provenance=chain,
            )
        ],
        root=root,
        provenance=chain,
        unknowns=(
            [] if chain else ["This record declares no upstream authority to traverse."]
        ),
        generated_at=generated_at,
    )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def status(root: Path = dk_core.ROOT, generated_at: str | None = None) -> dict:
    identity = dataset_identity(root)
    freshness = source_freshness(root)
    warnings: list[str] = []
    if freshness["stale"]:
        warnings.append(
            f"{len(freshness['stale'])} registered source(s) are older than their declared "
            "check cadence. Records derived from them may not reflect the current source."
        )
    if freshness["unbaselined"]:
        warnings.append(
            f"{len(freshness['unbaselined'])} registered source(s) have no baselined snapshot."
        )
    return envelope(
        "status",
        "status",
        [],
        root=root,
        warnings=warnings,
        unknowns=[
            "Record counts describe what Drupal Knowledge holds, not what exists in Drupal.",
        ],
        sections={
            "release": identity,
            "freshness": freshness,
            "domains": {
                "searchable": list(SEARCHABLE_DOMAINS),
                "opt_in": list(OPT_IN_DOMAINS),
                "all": list(DOMAINS),
            },
        },
        generated_at=generated_at,
    )


# ---------------------------------------------------------------------------
# Project inspection
#
# One consolidated read over every engine, each loaded once. The engines do the
# analysis; this only asks them and reports which of them could answer.
# ---------------------------------------------------------------------------


SECTION_AVAILABLE = "available"
SECTION_UNAVAILABLE = "unavailable"


def section(name: str, state: str, detail: dict, reason: str | None = None) -> dict:
    return {"section": name, "state": state, "reason": reason, **detail}


def project_reference(path: Path) -> str:
    """A stable, non-identifying handle for one project on one machine.

    Derived from the resolved path so repeated runs agree, and hashed so the
    path itself — and the organisation name usually in it — never reaches output.
    """
    return "project:" + digest_hex(str(path.resolve()))[:16]


def inspect_project(
    project_path: str | Path,
    root: Path = dk_core.ROOT,
    target: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """A consolidated read-only view of one project.

    Every section names an existing engine. Nothing here analyses anything
    itself, and a section that cannot answer says why rather than disappearing.
    """
    import dk_project_analyzer

    path = Path(project_path)
    if not path.is_dir():
        raise QueryInputError(f"{project_path} is not a directory that can be analysed")

    try:
        analysis = dk_project_analyzer.analyze_project(str(path)).data
    except dk_project_analyzer.AnalyzerInputError as exc:
        raise QueryInputError(f"project analysis unavailable: {exc}") from exc

    sections: dict[str, dict] = {}
    warnings: list[str] = []
    unknowns: list[str] = []

    facts = analysis["profile"]["facts"]
    core = facts.get("drupal_core_version", {})
    core_version = (core.get("value") or {}).get("version") if core.get("state") == "known" else None

    sections["project"] = section(
        "project",
        SECTION_AVAILABLE,
        {
            "project_id": analysis.get("project_id"),
            "analyzer_version": analysis["analyzer"]["version"],
            "diagnostics": len(analysis.get("diagnostics", [])),
            "unknown_facts": len(analysis.get("unknowns", [])),
        },
    )
    sections["drupal"] = section(
        "drupal",
        SECTION_AVAILABLE if core_version else SECTION_UNAVAILABLE,
        {"core_version": core_version, "php_platform": (facts.get("php_version", {}).get("value") or {}).get("composer_platform")},
        None if core_version else "no installed drupal/core package was observed",
    )
    if not core_version:
        unknowns.append("The installed Drupal core version was not observed.")

    # Evidence is built once and handed to every consumer that needs it.
    evidence = None
    try:
        import dk_evidence

        evidence = dk_evidence.build(analysis, root, project_path=path)
        sections["evidence"] = section(
            "evidence",
            SECTION_AVAILABLE,
            {
                "evidence_set_id": evidence["evidence_set_id"],
                "records": evidence["summary"]["records"],
                "by_domain": evidence["summary"]["by_domain"],
                "domain_completeness": {
                    name: block["search_domain"]
                    for name, block in evidence["domain_completeness"].items()
                },
            },
        )
        for name, block in evidence["domain_completeness"].items():
            if block["search_domain"] != "complete":
                unknowns.append(
                    f"Evidence for {name} is {block['search_domain']}, so absence there proves nothing."
                )
    except Exception as exc:  # noqa: BLE001 - a failed section is reported, never hidden
        sections["evidence"] = section("evidence", SECTION_UNAVAILABLE, {}, str(exc))
        warnings.append("Project evidence could not be built; dependent sections are unavailable.")

    sections["dependencies"] = dependency_section(facts)

    try:
        import dk_security

        security = dk_security.evaluate(analysis, root)
        applicable = [
            item for item in security["results"] if item["applicability"] == "applicable"
        ]
        sections["security"] = section(
            "security",
            SECTION_AVAILABLE,
            {
                "evaluation_id": security.get("evaluation_id"),
                "advisories_evaluated": len(security["results"]),
                "applicable": len(applicable),
                "unknown": sum(
                    1 for item in security["results"] if item["applicability"] == "unknown"
                ),
                "applicable_ids": sorted(item["advisory_id"] for item in applicable),
                "enforcement": "guidance",
                "note": (
                    "Applicable means the advisory's own affected-version expression covers "
                    "the installed version. It is not a statement about exploitability."
                ),
            },
        )
    except Exception as exc:  # noqa: BLE001
        sections["security"] = section("security", SECTION_UNAVAILABLE, {}, str(exc))
        warnings.append("The security evaluation could not run.")

    migration = None
    if target:
        try:
            import dk_migration

            migration = dk_migration.analyze(analysis, target, root, project_path=path)
            sections["migration"] = section(
                "migration",
                SECTION_AVAILABLE,
                {
                    "analysis_id": migration["analysis_id"],
                    "target": target,
                    "work_items": migration["summary"]["work_items"],
                    "blocking": migration["summary"]["blocking_items"],
                    "occurrences": migration["summary"]["occurrences"],
                    "files_read": migration["summary"]["files_read"],
                    "text_only_rejected": migration["summary"]["non_code_matches_rejected"],
                },
            )
            unknowns.append(migration["coverage"]["statement"])
        except Exception as exc:  # noqa: BLE001
            sections["migration"] = section("migration", SECTION_UNAVAILABLE, {}, str(exc))
            warnings.append("The migration analysis could not run.")
    else:
        sections["migration"] = section(
            "migration",
            SECTION_UNAVAILABLE,
            {},
            "no target Drupal version was given; pass --target to analyse migration work",
        )

    if target:
        try:
            import dk_upgrade

            upgrade = dk_upgrade.evaluate(analysis, target, root, migration=migration)
            sections["upgrade"] = section(
                "upgrade",
                SECTION_AVAILABLE,
                {
                    "assessment_id": upgrade["assessment_id"],
                    "target": target,
                    "assessment": upgrade["assessment"],
                    "basis": upgrade["assessment_basis"],
                    "blockers": len(upgrade["blockers"]),
                    "blocker_kinds": sorted({item["kind"] for item in upgrade["blockers"]}),
                    "required_changes": len(upgrade["required_changes"]),
                    "unknowns": len(upgrade["unknowns"]),
                },
            )
            unknowns.append(upgrade["bounds"]["statement"])
        except Exception as exc:  # noqa: BLE001
            sections["upgrade"] = section("upgrade", SECTION_UNAVAILABLE, {}, str(exc))
            warnings.append("The upgrade assessment could not run.")
    else:
        sections["upgrade"] = section(
            "upgrade",
            SECTION_UNAVAILABLE,
            {},
            "no target Drupal version was given; pass --target to assess an upgrade",
        )

    if evidence is not None:
        try:
            import dk_implementation

            findings = dk_implementation.evaluate(evidence, root)
            sections["implementation_findings"] = section(
                "implementation_findings",
                SECTION_AVAILABLE,
                {
                    "evaluation_id": findings["evaluation_id"],
                    "rules_evaluated": len(findings["rules"]["evaluated"]),
                    "by_state": findings["summary"]["by_state"],
                    "by_category": findings["summary"]["by_category"],
                    "confirmed": findings["summary"]["confirmed"],
                    "blocking": findings["summary"]["blocking"],
                },
            )
            unknowns.append(findings["boundaries"]["statement"])
        except Exception as exc:  # noqa: BLE001
            sections["implementation_findings"] = section(
                "implementation_findings", SECTION_UNAVAILABLE, {}, str(exc)
            )
            warnings.append("Implementation findings could not be evaluated.")
    else:
        sections["implementation_findings"] = section(
            "implementation_findings",
            SECTION_UNAVAILABLE,
            {},
            "project evidence is unavailable, and implementation rules read evidence",
        )

    results = [
        result(
            D_PROJECT_EVIDENCE,
            evidence["evidence_set_id"] if evidence else "unavailable",
            f"Consolidated inspection of {analysis.get('project_id') or 'this project'}",
            "One read-only pass over every Drupal Knowledge engine that could answer.",
            detail={"sections": list(sections)},
            provenance=[{"channel": "project_derived_evidence", "analyzer": "drupal-project-analyzer"}],
        )
    ]

    # The query echo is a fingerprint, never the path that was typed. A local
    # filesystem path says nothing about the answer and everything about the
    # machine, and this payload is meant to be safe to paste into an issue.
    return envelope(
        project_reference(path),
        "project_inspect",
        results,
        root=root,
        warnings=warnings,
        unknowns=unknowns,
        sections=sections,
        generated_at=generated_at,
    )


def dependency_section(facts: dict) -> dict:
    packages = facts.get("composer_packages", {})
    if packages.get("state") != "known":
        return section(
            "dependencies", SECTION_UNAVAILABLE, {}, "no Composer evidence was observed"
        )
    value = packages.get("value") or {}
    installed = value.get("installed") or {}
    declared = value.get("declared") or {}
    return section(
        "dependencies",
        SECTION_AVAILABLE if installed.get("available") else SECTION_UNAVAILABLE,
        {
            "declared_requirements": len(declared.get("require") or {}),
            "installed_packages": len(installed.get("packages") or []),
            "drupal_packages": len(installed.get("drupal_packages") or []),
            "lock_available": bool(installed.get("available")),
        },
        None if installed.get("available") else "composer.lock was not readable",
    )


# ---------------------------------------------------------------------------
# Domain listings
# ---------------------------------------------------------------------------


def list_domain(
    domain: str,
    root: Path = dk_core.ROOT,
    limit: int | None = None,
    generated_at: str | None = None,
) -> dict:
    if domain not in PROJECTORS:
        raise QueryInputError(
            f"unknown domain {domain!r}; known domains are " + ", ".join(sorted(PROJECTORS))
        )
    loader, projector = PROJECTORS[domain]
    records = sorted(loader(root), key=lambda item: stable_json(item))
    results = [projector(record) for record in records]
    results.sort(key=lambda item: item["id"])
    warnings = []
    if domain == D_DISCOVERY_SIGNAL:
        warnings.append(
            "Discovery signals are untrusted community observations, not Drupal Knowledge."
        )
    if domain == D_KNOWLEDGE:
        warnings.append("Only reviewed records are listed; unreviewed material is not trusted knowledge.")
    truncated = 0
    if limit is not None and len(results) > limit:
        truncated = len(results) - limit
        results = results[:limit]
        warnings.append(f"{truncated} further record(s) not shown; raise --limit to see them.")
    return envelope(domain, "list", results, root=root, warnings=warnings, generated_at=generated_at)


def validate_query_contract(root: Path = dk_core.ROOT) -> list[str]:
    dk_core.read_json(root / "schema" / "query-result.schema.json")
    for domain in DOMAINS:
        if domain not in DOMAIN_TRUST_CLASS:
            raise dk_core.ValidationError(f"domain {domain} declares no trust class")
        if DOMAIN_TRUST_CLASS[domain] not in TRUST_CLASSES:
            raise dk_core.ValidationError(f"domain {domain} names an unknown trust class")
    if D_DISCOVERY_SIGNAL in SEARCHABLE_DOMAINS:
        raise dk_core.ValidationError("discovery signals must not be searched by default")
    if not TRUST_CLASSES["reviewed_drupal_knowledge"]["trusted_knowledge"]:
        raise dk_core.ValidationError("reviewed knowledge must be marked trusted")
    for name, block in TRUST_CLASSES.items():
        if name != "reviewed_drupal_knowledge" and block["trusted_knowledge"]:
            raise dk_core.ValidationError(f"trust class {name} must not claim trusted knowledge")
    return [
        "COMMUNITY_QUERY_CONTRACT_VALID=PASS",
        f"COMMUNITY_QUERY_INTERFACE_VERSION={QUERY_INTERFACE_VERSION}",
        f"COMMUNITY_QUERY_DOMAINS={len(DOMAINS)}",
        f"COMMUNITY_QUERY_TRUST_CLASSES={len(TRUST_CLASSES)}",
        "COMMUNITY_CLI_CANNOT_BYPASS_TRUST_MODEL=PASS",
        "RAW_DISCOVERY_NOT_PRESENTED_AS_TRUSTED_RESULT=PASS",
    ]
