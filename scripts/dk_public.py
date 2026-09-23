#!/usr/bin/env python3
"""What Drupal Knowledge is willing to say in public, and in what shape.

This is the export layer between the released query layer and the public
website. It runs public-safe queries through ``dk_query``, projects the results
into a stable dataset, and stops. It decides nothing about Drupal.

That restraint is the whole point. The website must not be a second opinion:
if the CLI says an advisory's risk vector was sourced rather than scored, the
site has to say the same thing, from the same function, or Drupal Knowledge has
two truths and no way to tell which one a developer read.

Three rules hold this together.

**Public means published, not merely readable.** A project evidence set, a
finding, an upgrade assessment — these are about one repository at one revision.
They are legitimate answers to a local question and they are never global
content, so the domains that produce them are excluded here by name, each with
a stated reason rather than a silent omission.

**Identity is knowledge, not clock and not release.** The dataset carries a
``dataset_id`` derived from the trusted records alone, so any release over the
same knowledge identifies itself the same way. Which release built it, how
fresh each source is and when the build ran are all published here as fact and
none of them is an input: a re-fetch that proves the knowledge unchanged leaves
the identity unchanged, and so does a version bump. Anything that changes
because time passed — how many days old a snapshot is, when a build ran — is
volatile build metadata and lives outside the committed dataset entirely.

**Absence is deliberate.** Ten discovery signals exist in this repository and
none of them is published. That is recorded in the manifest as an exclusion with
a reason, because a public dataset that is quietly missing a domain is
indistinguishable from one that never had it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import dk_core
import dk_query as query
from dk_query import stable_json


PUBLIC_DATASET_SCHEMA_VERSION = "0.1"
PUBLIC_EXPORT_NAME = "drupal-knowledge-public-export"

DATASET_DIR = Path("public-site") / "dataset"

# --- what the public site publishes -------------------------------------------
#
# Ordered as the navigation orders them, because the manifest is also the
# routing table and two orderings would drift apart.

PUBLIC_DOMAINS = (
    query.D_KNOWLEDGE,
    query.D_ADVISORY,
    query.D_API_LIFECYCLE,
    query.D_CHANGE_RECORD,
    query.D_IMPLEMENTATION_RULE,
    query.D_SOLVED_CASE,
)

# Every domain the query layer knows and the site does not publish, with the
# reason. A reader can tell a deliberate exclusion from an oversight.
EXCLUDED_DOMAINS = {
    query.D_PROJECT_EVIDENCE: (
        "Evidence describes one repository at one revision. It answers a local "
        "question and is never global Drupal content."
    ),
    query.D_FINDING: (
        "A finding is a rule applied to one project's evidence. Publishing it "
        "would turn one project's state into a claim about Drupal."
    ),
    query.D_IMPLEMENTATION_FINDING: (
        "A finding is a rule applied to one project's evidence. The reviewed "
        "rule behind it is published instead."
    ),
    query.D_MIGRATION_WORK: (
        "Migration work items name files and lines in one project. The "
        "authoritative deprecation records behind them are published instead."
    ),
    query.D_UPGRADE_ASSESSMENT: (
        "An upgrade assessment is bounded by one project's evidence and is not "
        "a statement about Drupal."
    ),
    query.D_REMEDIATION_PLAN: (
        "A remediation plan is computed for one project's installed versions. "
        "The advisories behind it are published instead."
    ),
    query.D_DISCOVERY_SIGNAL: (
        "Discovery signals are untrusted community observations awaiting "
        "corroboration and review. Publishing them beside reviewed knowledge "
        "would make untrusted material look like an answer, so this release "
        "publishes none of them."
    ),
}

# Route prefixes are part of the public contract: a link that works today must
# work after the next release, so these are keyed by domain and never derived
# from a filesystem layout.
ROUTE_PREFIX = {
    query.D_KNOWLEDGE: "/knowledge",
    query.D_ADVISORY: "/security",
    query.D_API_LIFECYCLE: "/api",
    query.D_CHANGE_RECORD: "/change-records",
    query.D_IMPLEMENTATION_RULE: "/rules",
    query.D_SOLVED_CASE: "/solved-cases",
}

DOMAIN_LABEL = {
    query.D_KNOWLEDGE: "Knowledge",
    query.D_ADVISORY: "Security",
    query.D_API_LIFECYCLE: "API Changes",
    query.D_CHANGE_RECORD: "Change Records",
    query.D_IMPLEMENTATION_RULE: "Implementation Rules",
    query.D_SOLVED_CASE: "Solved Cases",
}

# The file each domain's records are written to, relative to the dataset root.
DOMAIN_FILE = {
    query.D_KNOWLEDGE: "domains/trusted-knowledge.json",
    query.D_ADVISORY: "domains/security.json",
    query.D_API_LIFECYCLE: "domains/api.json",
    query.D_CHANGE_RECORD: "domains/change-records.json",
    query.D_IMPLEMENTATION_RULE: "domains/rules.json",
    query.D_SOLVED_CASE: "domains/solved-cases.json",
}

SOURCES_FILE = "sources.json"
SEARCH_INDEX_FILE = "search-index.json"
MANIFEST_FILE = "manifest.json"


class PublicExportDefect(RuntimeError):
    """The export produced something it must never produce.

    Raised rather than returned: a dataset that leaked a local path or invented
    a trust label is not a degraded build, it is one that must not be written.
    """


# --- privacy ------------------------------------------------------------------
#
# Applied at the boundary, on the serialized bytes, because a scrubber that only
# knows the fields it was told about misses the field added next week.

PRIVATE_PATTERNS = (
    (re.compile(r"/Users/"), "a macOS home directory"),
    (re.compile(r"/home/[a-z]"), "a Linux home directory"),
    (re.compile(r"[A-Za-z]:\\\\?Users"), "a Windows home directory"),
    (re.compile(r"/private/(?:tmp|var)/"), "a local temporary directory"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "an email address"),
    # A credential is a name bound to a value. Matching the bare word flagged a
    # regular expression called TOKEN, which is the kind of false positive that
    # gets a scanner switched off.
    (
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token"
            r"|password|hash_salt|private[_-]?key)\b\s*[:=]\s*['\"]?[^\s'\",}]"
        ),
        "a credential",
    ),
)


def assert_public_safe(label: str, payload: object) -> None:
    """Refuse to publish anything carrying private or local detail."""
    text = payload if isinstance(payload, str) else stable_json(payload)
    for pattern, description in PRIVATE_PATTERNS:
        found = pattern.search(text)
        if found:
            raise PublicExportDefect(
                f"{label} would publish {description}: {found.group(0)!r}"
            )


def slug(identifier: str) -> str:
    """A URL segment derived from a canonical identifier, never from a path.

    Canonical ids already carry the identity; this only makes them safe in a
    URL. It is injective over the identifiers this repository produces, and the
    export refuses to write a dataset where two records collide.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", identifier).strip("-")
    if not cleaned:
        raise PublicExportDefect(f"identifier {identifier!r} has no usable route segment")
    return cleaned


def route_for(domain: str, identifier: str) -> str:
    prefix = ROUTE_PREFIX.get(domain)
    if prefix is None:
        raise PublicExportDefect(f"domain {domain!r} is not published and has no route")
    return f"{prefix}/{slug(identifier)}/"


def index_route(domain: str) -> str:
    return f"{ROUTE_PREFIX[domain]}/"


# --- projection ---------------------------------------------------------------


def public_record(item: dict) -> dict:
    """One query result, projected into the public shape.

    Nothing is recomputed. The trust block, provenance and unknowns arrive
    already settled from the query layer and are carried across unchanged, so
    the website cannot describe a record differently from the CLI.
    """
    domain = item["domain"]
    if domain not in PUBLIC_DOMAINS:
        raise PublicExportDefect(f"{domain!r} is not a published domain")
    return {
        "id": item["id"],
        "domain": domain,
        "route": route_for(domain, item["id"]),
        "title": item["title"],
        "summary": item["summary"],
        "trust": dict(item["trust"]),
        "detail": dict(item["detail"]),
        "provenance": [public_provenance_step(step) for step in item["provenance"]],
        "unknowns": list(item["unknowns"]),
    }


def public_provenance_step(step: dict) -> dict:
    """A provenance step reduced to what a stranger can act on.

    The snapshot digest stays because it is how a claim is checked. Where the
    snapshot lives on the machine that acquired it is local trivia and never
    crosses this line.
    """
    published = {
        "channel": step.get("channel"),
        "source_id": step.get("source_id"),
        "source_url": step.get("source_url"),
        "snapshot_sha256": step.get("snapshot_sha256"),
        "locator": step.get("locator"),
        "case_id": step.get("case_id"),
        "rule_id": step.get("rule_id"),
    }
    return {key: value for key, value in published.items() if value}


# --- domain export ------------------------------------------------------------


def export_domain(domain: str, root: Path = dk_core.ROOT) -> list[dict]:
    """Every published record of one domain, ordered by canonical identifier."""
    listing = query.list_domain(domain, root, limit=1_000_000)
    # One pass over the domain's own records, keyed by the identifiers the
    # scorer would match, so a record is never looked up by scanning every
    # domain again.
    loader, _ = query.PROJECTORS[domain]
    by_id: dict[str, dict] = {}
    for raw in loader(root):
        for candidate in query.searchable_fields(domain, raw)["identity"]:
            if candidate:
                by_id[candidate] = raw
    records = []
    seen: dict[str, str] = {}
    for item in listing["results"]:
        record = public_record(item)
        raw = by_id.get(record["id"])
        if raw is not None:
            # Explanations come from the query layer rather than from prose
            # written here, so the site and the CLI say the same words.
            record["explanation"] = dict(query.explanation_for(domain, raw, root))
            record["provenance"] = [
                public_provenance_step(step)
                for step in query.provenance_chain(domain, raw, root)
            ] or record["provenance"]
        route = record["route"]
        if route in seen and seen[route] != record["id"]:
            raise PublicExportDefect(
                f"route {route} is claimed by both {seen[route]!r} and {record['id']!r}"
            )
        seen[route] = record["id"]
        records.append(record)
    records.sort(key=lambda entry: entry["id"])
    assert_public_safe(f"domain {domain}", records)
    return records


def link_related(records_by_domain: dict[str, list[dict]], sources: list[dict]) -> None:
    """Cross-link records that canonical fields already relate.

    Only exact, declared relationships. An advisory and a knowledge record that
    happen to mention the same word are not related, and guessing that they are
    is how a documentation site starts asserting things nobody reviewed.
    """
    source_routes = {entry["id"]: entry["route"] for entry in sources}

    # A change record names the symbols it changed; a lifecycle record is one
    # symbol. Both are projected verbatim from authoritative sources, so an
    # exact name match is a fact about the sources, not a guess about meaning.
    by_symbol: dict[str, list[dict]] = {}
    for record in records_by_domain.get(query.D_API_LIFECYCLE, []):
        symbol = record["detail"].get("symbol")
        if symbol:
            by_symbol.setdefault(symbol, []).append(record)

    # Advisories for the same Drupal.org project, by the project machine name
    # the advisory itself declares.
    by_project: dict[str, list[dict]] = {}
    for record in records_by_domain.get(query.D_ADVISORY, []):
        project = record["detail"].get("project")
        if project:
            by_project.setdefault(project, []).append(record)

    for domain, records in records_by_domain.items():
        for record in records:
            related: list[dict] = []
            for step in record["provenance"]:
                route = source_routes.get(step.get("source_id") or "")
                if route:
                    related.append(
                        {
                            "relation": "derived_from_source",
                            "label": step.get("source_id"),
                            "route": route,
                        }
                    )
            if domain == query.D_ADVISORY:
                project = record["detail"].get("project")
                for sibling in by_project.get(project or "", []):
                    if sibling["id"] != record["id"]:
                        related.append(
                            {
                                "relation": "same_drupal_project",
                                "label": sibling["id"],
                                "route": sibling["route"],
                            }
                        )
            if domain == query.D_CHANGE_RECORD:
                for symbol in record["detail"].get("symbols", []):
                    for sibling in by_symbol.get(symbol, []):
                        related.append(
                            {
                                "relation": "names_this_symbol",
                                "label": sibling["title"],
                                "route": sibling["route"],
                            }
                        )
            if domain == query.D_API_LIFECYCLE:
                symbol = record["detail"].get("symbol")
                for sibling in records_by_domain.get(query.D_CHANGE_RECORD, []):
                    if symbol and symbol in sibling["detail"].get("symbols", []):
                        related.append(
                            {
                                "relation": "described_by_change_record",
                                "label": sibling["title"],
                                "route": sibling["route"],
                            }
                        )
            seen: set[tuple] = set()
            unique = []
            for entry in sorted(related, key=lambda item: (item["relation"], item["route"])):
                key = (entry["relation"], entry["route"])
                if key not in seen:
                    seen.add(key)
                    unique.append(entry)
            record["related"] = unique


def export_sources(root: Path = dk_core.ROOT) -> list[dict]:
    """The registered source directory, without the machine that reads it.

    Deliberately time-independent: the date a source was last observed is a
    fact, and how many days ago that was is a function of when someone looks.
    Only the fact is published, so the dataset does not change overnight.
    """
    published = []
    for source in sorted(dk_core.load_sources(root), key=lambda entry: entry["id"]):
        state_path = root / "sources" / "state" / f"{source['id']}.json"
        last_observed = None
        digest = None
        if state_path.is_file():
            state = dk_core.read_json(state_path)
            digest = state.get("content_sha256")
            last_observed = (state.get("acquisition") or {}).get("last_success_at")
        published.append(
            {
                "id": source["id"],
                "route": f"/sources/{slug(source['id'])}/",
                "title": source["title"],
                "url": source["url"],
                "trust": source["trust"],
                "category": source.get("category"),
                "role": source.get("role"),
                "lifecycle": source.get("lifecycle"),
                "check_cadence_days": source.get("check_cadence_days"),
                "baselined": bool(digest),
                "last_observed_at": last_observed,
                "snapshot_sha256": digest,
            }
        )
    assert_public_safe("source directory", published)
    return published


# --- search -------------------------------------------------------------------


def index_row(record: dict, root: Path) -> dict:
    """One search row: identity, the fields that decide a match, and nothing else.

    The field groups are the same four the released scorer reads, so the site
    ranks by exactly the comparison the CLI ranks by. Everything a result list
    does not display stays out of the browser.
    """
    found = query.find_record(record["id"], root)
    if found is None:
        raise PublicExportDefect(f"{record['id']!r} vanished between listing and indexing")
    fields = query.searchable_fields(found[0], found[1])
    return {
        "id": record["id"],
        "domain": record["domain"],
        "route": record["route"],
        "title": record["title"],
        "summary": record["summary"],
        "trust_class": record["trust"]["class"],
        "identity": [value for value in fields["identity"] if value],
        "structured": [value for value in fields["structured"] if value],
        # Title and body text are already present above; repeating them in the
        # index would double the payload every browser downloads.
        "body": [value for value in fields["body"] if value and value != record["summary"]],
    }


def search_fields(row: dict) -> dict[str, list[str]]:
    """Reconstruct the scorer's field groups from an index row."""
    return {
        "identity": list(row["identity"]),
        "structured": list(row["structured"]),
        "title": [row["title"]],
        "body": [row["summary"], *row["body"]],
    }


def search_index(
    root: Path = dk_core.ROOT, records_by_domain: dict[str, list[dict]] | None = None
) -> list[dict]:
    """Index rows for the already-exported records, never a second export."""
    if records_by_domain is None:
        records_by_domain = {domain: export_domain(domain, root) for domain in PUBLIC_DOMAINS}
    rows = []
    for domain in PUBLIC_DOMAINS:
        for record in records_by_domain[domain]:
            rows.append(index_row(record, root))
    rows.sort(key=lambda row: (row["domain"], row["id"]))
    assert_public_safe("search index", rows)
    return rows


def search(term: str, rows: Iterable[dict], limit: int = 20) -> list[dict]:
    """Rank index rows with the released scorer. There is no second algorithm.

    ``query.score_record`` is imported, not reimplemented: if Prompt 14's
    ranking changes, this changes with it or the parity test fails.
    """
    scored = []
    for row in rows:
        rank, reason = query.score_record(term, search_fields(row))
        if rank:
            scored.append((rank, row["id"], reason, row))
    scored.sort(key=lambda entry: (-entry[0], entry[1]))
    return [
        {**row, "rank": rank, "reason": reason}
        for rank, _identifier, reason, row in scored[:limit]
    ]


# --- dataset ------------------------------------------------------------------


def routes(records_by_domain: dict[str, list[dict]]) -> list[dict]:
    """Every page the site will have, named by the dataset rather than the build.

    The renderer walks this. A page that is not here does not get written, which
    is what keeps the manifest an honest description of the site.
    """
    listed: list[dict] = [
        {"route": "/", "kind": "home"},
        {"route": "/search/", "kind": "search"},
        # The error page is a page. Counting it keeps page_count equal to what
        # the build actually writes.
        {"route": "/404/", "kind": "error"},
        {"route": "/trust-model/", "kind": "editorial"},
        {"route": "/cli/", "kind": "editorial"},
        {"route": "/api-docs/", "kind": "editorial"},
        {"route": "/about/", "kind": "editorial"},
        {"route": "/sources/", "kind": "index", "domain": "sources"},
    ]
    for domain in PUBLIC_DOMAINS:
        listed.append({"route": index_route(domain), "kind": "index", "domain": domain})
        for record in records_by_domain[domain]:
            listed.append({"route": record["route"], "kind": "detail", "domain": domain})
    return listed


def build_dataset(root: Path = dk_core.ROOT) -> dict[str, object]:
    """The complete public dataset, as a mapping of relative path to content.

    Deterministic by construction: every list is sorted by canonical identity
    and nothing consults the clock.
    """
    records_by_domain = {domain: export_domain(domain, root) for domain in PUBLIC_DOMAINS}
    sources = export_sources(root)
    link_related(records_by_domain, sources)
    rows = search_index(root, records_by_domain)
    identity = query.dataset_identity(root)

    source_routes = [{"route": entry["route"], "kind": "detail", "domain": "sources"} for entry in sources]
    all_routes = sorted(routes(records_by_domain) + source_routes, key=lambda entry: entry["route"])

    files: dict[str, object] = {}
    for domain in PUBLIC_DOMAINS:
        files[DOMAIN_FILE[domain]] = {
            "domain": domain,
            "label": DOMAIN_LABEL[domain],
            "route": index_route(domain),
            "trust_class": query.DOMAIN_TRUST_CLASS[domain],
            "record_count": len(records_by_domain[domain]),
            "records": records_by_domain[domain],
        }
    files[SOURCES_FILE] = {"source_count": len(sources), "sources": sources}
    files[SEARCH_INDEX_FILE] = {
        "row_count": len(rows),
        # Bands travel with the index so the browser cannot invent its own
        # ordering, and a reader can check it against the released constants.
        "ranking": {
            "exact_id": query.RANK_EXACT_ID,
            "exact_field": query.RANK_EXACT_FIELD,
            "prefix_id": query.RANK_PREFIX_ID,
            "exact_token": query.RANK_EXACT_TOKEN,
            "title_substring": query.RANK_TITLE_SUBSTRING,
            "body_substring": query.RANK_BODY_SUBSTRING,
        },
        "rows": rows,
    }

    manifest = {
        "dataset_schema_version": PUBLIC_DATASET_SCHEMA_VERSION,
        "dk_version": identity["drupal_knowledge_version"],
        "query_interface_version": query.QUERY_INTERFACE_VERSION,
        "result_contract_version": query.RESULT_CONTRACT_VERSION,
        "generated_from_release": identity["drupal_knowledge_version"],
        "generated_by": PUBLIC_EXPORT_NAME,
        "records_digest": identity["records_digest"],
        "domains": [
            {
                "domain": domain,
                "label": DOMAIN_LABEL[domain],
                "route": index_route(domain),
                "file": DOMAIN_FILE[domain],
                "trust_class": query.DOMAIN_TRUST_CLASS[domain],
                "record_count": len(records_by_domain[domain]),
            }
            for domain in PUBLIC_DOMAINS
        ],
        "excluded_domains": [
            {"domain": domain, "reason": reason}
            for domain, reason in sorted(EXCLUDED_DOMAINS.items())
        ],
        "record_counts": {
            domain: len(records_by_domain[domain]) for domain in PUBLIC_DOMAINS
        },
        "source_freshness_summary": {
            "registered": len(sources),
            "baselined": sum(1 for entry in sources if entry["baselined"]),
            "never_acquired": sum(1 for entry in sources if not entry["baselined"]),
            "note": (
                "Freshness is measured against each source's declared check cadence "
                "when the site is built. A stale source is one nobody has looked at "
                "recently; it is not a source known to be wrong."
            ),
        },
        "trust_classes": {
            name: dict(block) for name, block in sorted(query.TRUST_CLASSES.items())
        },
        "search_index": {"file": SEARCH_INDEX_FILE, "row_count": len(rows)},
        # Said plainly, because a well-formed JSON file at a stable path invites
        # exactly the assumption this release has not earned yet.
        "api_status": (
            "This dataset is the build input for the Drupal Knowledge website. It is "
            "not a supported API contract and its shape may change between releases."
        ),
        "routes": all_routes,
        "page_count": len(all_routes),
    }
    # Identity is the trusted knowledge and nothing else, so it is computed at
    # the query layer over the canonical records rather than over these files.
    # Everything above that is not knowledge — which release built it, how
    # fresh each source is, how many rows the search index holds — is published
    # here as fact and is deliberately not an input: a re-fetch that confirms
    # the knowledge unchanged must leave the dataset identity unchanged.
    manifest["dataset_id"] = query.semantic_identity(root)["dataset_id"]
    files[MANIFEST_FILE] = manifest
    assert_public_safe("public manifest", manifest)
    return files


def dataset_bytes(root: Path = dk_core.ROOT) -> dict[Path, bytes]:
    """The dataset as the exact bytes that belong on disk."""
    target = root / DATASET_DIR
    return {
        target / relative: (stable_json(content) + "\n").encode("utf-8")
        for relative, content in build_dataset(root).items()
    }


def write_dataset(root: Path = dk_core.ROOT) -> list[Path]:
    written = []
    for path, payload in sorted(dataset_bytes(root).items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        written.append(path)
    return written


def load_dataset(root: Path = dk_core.ROOT) -> dict[str, object]:
    """Read the committed dataset. The renderer never gets canonical records."""
    target = root / DATASET_DIR
    manifest_path = target / MANIFEST_FILE
    if not manifest_path.is_file():
        raise PublicExportDefect(
            "the public dataset has not been generated; run `dk public-site build`"
        )
    loaded: dict[str, object] = {MANIFEST_FILE: dk_core.read_json(manifest_path)}
    for relative in [*DOMAIN_FILE.values(), SOURCES_FILE, SEARCH_INDEX_FILE]:
        loaded[relative] = dk_core.read_json(target / relative)
    return loaded


def validate_public_dataset(root: Path = dk_core.ROOT) -> list[str]:
    """Fail if canonical records moved and the published dataset did not.

    The same byte comparison the repository already uses for its other
    generated output. A dataset that describes a previous release is worse than
    no dataset, because it looks current.
    """
    stale = []
    for path, expected in sorted(dataset_bytes(root).items()):
        if not path.is_file() or path.read_bytes() != expected:
            stale.append(str(path.relative_to(root)))
    if stale:
        raise dk_core.ValidationError(
            "the public dataset is stale: "
            + ", ".join(stale)
            + ". Run python3 scripts/dk.py public-site build"
        )
    return ["PUBLIC_DATASET_CURRENT=PASS"]
