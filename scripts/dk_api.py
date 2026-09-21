#!/usr/bin/env python3
"""The Public Knowledge API, as a contract rather than as a server.

Three surfaces now answer the same questions: the command line, the website and
this. They must agree, and the cheapest way to guarantee that is to stop giving
each one its own way to reach the records.

So this module reads exactly one thing — the public dataset that Prompt 15
already exports through the released query layer. Not the canonical stores, not
the generated HTML, not a second projection written for HTTP. If the website
says an advisory's risk vector was sourced rather than scored, the API says it
too, because both are reading the same bytes, and those bytes carry a
content-addressed identity that goes out with every response.

Search is the one place a request does real work, and it reuses
``dk_public.search``, which reuses ``dk_query.score_record``. There is no
third ranking implementation and there is nowhere to put one.

Nothing here knows what HTTP is. ``handle()`` takes a method, a path and a
parsed query string and returns a status code and a payload; the transport in
``dk_api_http`` turns that into bytes and headers. Prompt 17's consumers can
call this directly, and the tests mostly do.

There is also nothing here that writes. The dataset is opened read-only, no
canonical store is touched at request time, and no verb but GET, HEAD and
OPTIONS is routable at all.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

import dk_core
import dk_public as public
import dk_query as query
from dk_query import stable_json


# The API contract moves on its own schedule. A DK release that adds records
# does not break a consumer, and pinning them together would force a major
# version every time a security advisory is ingested.
API_VERSION = "1"
API_CONTRACT_VERSION = "1.0"
API_ROOT = "/api/v1"

# Bounds. A public endpoint with no ceiling is a denial-of-service primitive
# that happens to return JSON.
DEFAULT_LIMIT = 25
MAX_LIMIT = 200
MAX_OFFSET = 100_000
MAX_QUERY_LENGTH = 200

# The transport is allowed its own spelling of a domain: `/api/v1/api` would be
# an unreadable path for the API lifecycle records. Meaning is unchanged.
DOMAIN_SEGMENT = {
    query.D_KNOWLEDGE: "knowledge",
    query.D_ADVISORY: "security",
    query.D_API_LIFECYCLE: "api-lifecycle",
    query.D_CHANGE_RECORD: "change-records",
    query.D_IMPLEMENTATION_RULE: "rules",
    query.D_SOLVED_CASE: "solved-cases",
}
SEGMENT_DOMAIN = {segment: domain for domain, segment in DOMAIN_SEGMENT.items()}

# What one record of each domain is called in a sentence. The website's labels
# are plural section headings and read badly in an endpoint summary.
DOMAIN_NOUN = {
    query.D_KNOWLEDGE: ("reviewed Drupal Knowledge record", "reviewed Drupal Knowledge records"),
    query.D_ADVISORY: ("Drupal security advisory", "Drupal security advisories"),
    query.D_API_LIFECYCLE: ("Drupal API lifecycle record", "Drupal API lifecycle records"),
    query.D_CHANGE_RECORD: ("Drupal core change record", "Drupal core change records"),
    query.D_IMPLEMENTATION_RULE: ("reviewed implementation rule", "reviewed implementation rules"),
    query.D_SOLVED_CASE: ("solved case", "solved cases"),
}

# Stable error codes. A consumer branches on these; the message is for a human
# reading a log and may be reworded.
ERROR_STATUS = {
    "INVALID_QUERY": 400,
    "INVALID_PAGINATION": 400,
    "INVALID_FILTER": 400,
    "UNKNOWN_DOMAIN": 400,
    "QUERY_TOO_LONG": 400,
    "NOT_FOUND": 404,
    "METHOD_NOT_ALLOWED": 405,
    "DATASET_UNAVAILABLE": 503,
    "INTERNAL_ERROR": 500,
}


class ApiError(Exception):
    """A refusal a consumer can act on, rather than a traceback."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        if code not in ERROR_STATUS:
            raise ValueError(f"unknown API error code {code!r}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    @property
    def status(self) -> int:
        return ERROR_STATUS[self.code]


# ---------------------------------------------------------------------------
# The dataset this API serves
# ---------------------------------------------------------------------------

_CACHE: dict[str, dict] = {}


def dataset(root: Path = dk_core.ROOT, refresh: bool = False) -> dict:
    """The published dataset, read once and held.

    Read-only by construction: the API never reaches a canonical store, so a
    request cannot observe — let alone cause — a change to one.
    """
    key = str(root)
    if refresh:
        _CACHE.pop(key, None)
    if key not in _CACHE:
        try:
            _CACHE[key] = public.load_dataset(root)
        except public.PublicExportDefect as exc:
            raise ApiError(
                "DATASET_UNAVAILABLE",
                "The public dataset has not been generated for this checkout.",
                remedy="Run `dk public-site build`.",
            ) from exc
    return _CACHE[key]


def manifest(root: Path = dk_core.ROOT) -> dict:
    return dataset(root)[public.MANIFEST_FILE]


def records_of(domain: str, root: Path = dk_core.ROOT) -> list[dict]:
    return dataset(root)[public.DOMAIN_FILE[domain]]["records"]


def all_records(root: Path = dk_core.ROOT) -> dict[str, dict]:
    """Every published record by canonical id, for detail and provenance lookup."""
    return {
        record["id"]: record
        for domain in public.PUBLIC_DOMAINS
        for record in records_of(domain, root)
    }


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------


def api_href(domain: str, identifier: str) -> str:
    return f"{API_ROOT}/{DOMAIN_SEGMENT[domain]}/{public.slug(identifier)}"


def api_record(record: dict) -> dict:
    """One dataset record as the API publishes it.

    The trust block arrives already decided and is promoted to the top level so
    a consumer reading only the headline still cannot mistake an advisory for a
    reviewed Drupal Knowledge rule.
    """
    trust = record["trust"]
    published = {
        "id": record["id"],
        "domain": record["domain"],
        "record_type": trust["record_type"],
        "trust_class": trust["class"],
        "trusted_knowledge": trust["trusted_knowledge"],
        "universal_drupal_rule": trust["universal_drupal_rule"],
        "authority": trust["authority"],
        "trust_explanation": trust["explanation"],
        "title": record["title"],
        "summary": record["summary"],
        "detail": record["detail"],
        "unknowns": record["unknowns"],
        "provenance": record["provenance"],
        "href": api_href(record["domain"], record["id"]),
        "provenance_href": f"{API_ROOT}/provenance/{public.slug(record['id'])}",
        "site_url": record["route"],
    }
    if "review_status" in trust:
        published["review_status"] = trust["review_status"]
    if record.get("explanation"):
        published["explanation"] = record["explanation"]
    if record.get("related"):
        published["related"] = [
            {"relation": entry["relation"], "label": entry["label"], "site_url": entry["route"]}
            for entry in record["related"]
        ]
    return published


def envelope(
    request: dict,
    root: Path = dk_core.ROOT,
    *,
    results: list[dict] | None = None,
    result: dict | None = None,
    sections: dict | None = None,
    pagination: dict | None = None,
    warnings: list[str] | None = None,
    unknowns: list[str] | None = None,
    provenance: list[dict] | None = None,
) -> dict:
    """One shape for every successful response.

    ``unknowns`` is always present and is never emptied to look tidy: a bounded
    record set that found nothing has said something, and it is not "no".
    """
    identity = manifest(root)
    payload: dict[str, Any] = {
        "api_version": API_VERSION,
        "api_contract_version": API_CONTRACT_VERSION,
        "dk_version": identity["dk_version"],
        "dataset_id": identity["dataset_id"],
        "dataset_schema_version": identity["dataset_schema_version"],
        "query_interface_version": identity["query_interface_version"],
        "request": request,
        "warnings": list(warnings or []),
        "unknowns": list(unknowns or []),
    }
    if result is not None:
        payload["result"] = result
        payload["count"] = 1
    if results is not None:
        payload["results"] = results
        payload["count"] = len(results)
    if sections is not None:
        payload["sections"] = sections
    if pagination is not None:
        payload["pagination"] = pagination
    if provenance is not None:
        payload["provenance"] = provenance
    return payload


def error_payload(err: ApiError, root: Path = dk_core.ROOT) -> dict:
    """An error a machine can branch on. No Python is described here."""
    payload: dict[str, Any] = {
        "api_version": API_VERSION,
        "api_contract_version": API_CONTRACT_VERSION,
        "error": {"code": err.code, "message": err.message, "details": err.details},
    }
    # Release identity is best-effort: the dataset is exactly what is missing
    # when DATASET_UNAVAILABLE is raised.
    try:
        identity = manifest(root)
        payload["dk_version"] = identity["dk_version"]
        payload["dataset_id"] = identity["dataset_id"]
    except ApiError:
        pass
    return payload


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------


def one(params: dict[str, list[str]], name: str) -> str | None:
    values = params.get(name)
    if not values:
        return None
    if len(values) > 1:
        raise ApiError("INVALID_QUERY", f"`{name}` was given more than once.", parameter=name)
    return values[0]


def bounded_int(params: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    raw = one(params, name)
    if raw is None:
        return default
    if not re.fullmatch(r"\d{1,9}", raw):
        raise ApiError(
            "INVALID_PAGINATION", f"`{name}` must be a whole number.", parameter=name, given=raw
        )
    value = int(raw)
    if value < minimum or value > maximum:
        raise ApiError(
            "INVALID_PAGINATION",
            f"`{name}` must be between {minimum} and {maximum}.",
            parameter=name,
            given=value,
            maximum=maximum,
        )
    return value


def paginate(items: list, params: dict, request: dict) -> tuple[list, dict]:
    """Deterministic slicing of an already-ordered list.

    Offset paging is honest here because the dataset is immutable for a given
    ``dataset_id``: the page a consumer asked for cannot shift underneath them
    without the identity in the envelope changing too.
    """
    limit = bounded_int(params, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)
    offset = bounded_int(params, "offset", 0, 0, MAX_OFFSET)
    request["limit"] = limit
    request["offset"] = offset
    page = items[offset : offset + limit]
    pagination = {
        "limit": limit,
        "offset": offset,
        "total": len(items),
        "returned": len(page),
        "next_offset": offset + limit if offset + limit < len(items) else None,
        "ordering": "canonical identifier, ascending",
    }
    return page, pagination


def reject_unknown(params: dict, allowed: set[str]) -> None:
    unknown = sorted(set(params) - allowed)
    if unknown:
        raise ApiError(
            "INVALID_FILTER",
            "Unsupported query parameter(s).",
            unsupported=unknown,
            supported=sorted(allowed),
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def endpoint_index(request: dict, params: dict, root: Path) -> dict:
    reject_unknown(params, set())
    return envelope(
        request,
        root,
        sections={
            "routes": [
                {"path": route["path"], "summary": route["summary"]}
                for route in ROUTES
                if not route["path"].endswith("}")
            ],
            "openapi": f"{API_ROOT}/openapi.json",
            "documentation": "docs/PUBLIC_API.md",
        },
        unknowns=[
            "This index lists routes, not the knowledge behind them. "
            "Use /status to see what this release holds."
        ],
    )


def endpoint_status(request: dict, params: dict, root: Path) -> dict:
    reject_unknown(params, set())
    identity = manifest(root)
    sources = dataset(root)[public.SOURCES_FILE]["sources"]
    freshness = identity["source_freshness_summary"]
    warnings = []
    never = [entry["id"] for entry in sources if not entry["baselined"]]
    if never:
        warnings.append(
            f"{len(never)} registered source(s) have never been acquired; records "
            "derived from them do not exist yet."
        )
    return envelope(
        request,
        root,
        sections={
            "release": {
                "dk_version": identity["dk_version"],
                "dataset_id": identity["dataset_id"],
                "records_digest": identity["records_digest"],
                "dataset_schema_version": identity["dataset_schema_version"],
                "query_interface_version": identity["query_interface_version"],
            },
            "domains": [
                {
                    "domain": block["domain"],
                    "label": block["label"],
                    "trust_class": block["trust_class"],
                    "record_count": block["record_count"],
                    "href": f"{API_ROOT}/{DOMAIN_SEGMENT[block['domain']]}",
                }
                for block in identity["domains"]
            ],
            "excluded_domains": identity["excluded_domains"],
            "record_counts": identity["record_counts"],
            "source_freshness_summary": {
                "registered": freshness["registered"],
                "baselined": freshness["baselined"],
                "never_acquired": freshness["never_acquired"],
                "note": freshness["note"],
            },
            "trust_classes": identity["trust_classes"],
        },
        warnings=warnings,
        unknowns=[
            "Record counts describe what Drupal Knowledge holds, not what exists in Drupal.",
            "Freshness describes when a source was last acquired. This API never acquires anything.",
        ],
    )


def endpoint_search(request: dict, params: dict, root: Path) -> dict:
    reject_unknown(params, {"q", "domain", "trust_class", "limit", "offset"})
    term = one(params, "q")
    if term is None or not term.strip():
        raise ApiError("INVALID_QUERY", "`q` is required and must not be empty.", parameter="q")
    if len(term) > MAX_QUERY_LENGTH:
        raise ApiError(
            "QUERY_TOO_LONG",
            f"`q` must be at most {MAX_QUERY_LENGTH} characters.",
            given_length=len(term),
            maximum=MAX_QUERY_LENGTH,
        )
    request["q"] = term

    domains = params.get("domain") or []
    for domain in domains:
        if domain not in public.PUBLIC_DOMAINS:
            raise ApiError(
                "UNKNOWN_DOMAIN",
                f"`{domain}` is not a published domain.",
                given=domain,
                published=list(public.PUBLIC_DOMAINS),
            )
    trust_classes = params.get("trust_class") or []
    published_classes = {query.DOMAIN_TRUST_CLASS[d] for d in public.PUBLIC_DOMAINS}
    for trust_class in trust_classes:
        if trust_class not in published_classes:
            raise ApiError(
                "INVALID_FILTER",
                f"`{trust_class}` is not a trust class this API publishes.",
                given=trust_class,
                published=sorted(published_classes),
            )
    if domains:
        request["domain"] = sorted(domains)
    if trust_classes:
        request["trust_class"] = sorted(trust_classes)

    rows = dataset(root)[public.SEARCH_INDEX_FILE]["rows"]
    if domains:
        rows = [row for row in rows if row["domain"] in set(domains)]
    if trust_classes:
        rows = [row for row in rows if row["trust_class"] in set(trust_classes)]

    # The released scorer, reached through the same projection the website uses.
    # There is no second ranking implementation in this repository.
    hits = public.search(term, rows, limit=MAX_LIMIT + MAX_OFFSET)
    by_id = all_records(root)
    matched = [
        {
            **api_record(by_id[hit["id"]]),
            "match": {"rank": hit["rank"], "reason": hit["reason"]},
        }
        for hit in hits
    ]
    page, pagination = paginate(matched, params, request)

    unknowns = [
        "Drupal Knowledge holds a bounded record set. No match is not evidence "
        "that the subject is unproblematic."
    ]
    warnings = []
    if query.D_DISCOVERY_SIGNAL not in public.PUBLIC_DOMAINS:
        warnings.append(
            "Discovery signals are untrusted community observations and are not "
            "published by this API. Search covers published domains only."
        )
    return envelope(
        request,
        root,
        results=page,
        pagination=pagination,
        warnings=warnings,
        unknowns=unknowns,
    )


def endpoint_domain_list(domain: str) -> Callable:
    def handler(request: dict, params: dict, root: Path) -> dict:
        reject_unknown(params, {"limit", "offset"})
        block = dataset(root)[public.DOMAIN_FILE[domain]]
        request["domain"] = domain
        page, pagination = paginate(block["records"], params, request)
        unknowns = [
            f"This lists what Drupal Knowledge holds in {domain}, not everything "
            "that exists in Drupal."
        ]
        warnings = []
        if domain == query.D_KNOWLEDGE:
            warnings.append(
                "Only reviewed records are published. Unreviewed material is not "
                "trusted knowledge and is not served here."
            )
        if domain == query.D_SOLVED_CASE:
            warnings.append(
                "A solved case is proven in the context it names. It is not "
                "universal Drupal truth."
            )
        return envelope(
            request,
            root,
            results=[api_record(record) for record in page],
            pagination=pagination,
            warnings=warnings,
            unknowns=unknowns,
        )

    return handler


def endpoint_domain_detail(domain: str) -> Callable:
    def handler(request: dict, params: dict, root: Path, identifier: str = "") -> dict:
        reject_unknown(params, set())
        request["domain"] = domain
        request["id"] = identifier
        for record in records_of(domain, root):
            if record["id"] == identifier or public.slug(record["id"]) == identifier:
                return envelope(
                    request,
                    root,
                    result=api_record(record),
                    provenance=record["provenance"],
                    unknowns=record["unknowns"],
                )
        raise ApiError(
            "NOT_FOUND",
            f"No {domain} record has the identifier {identifier!r}.",
            domain=domain,
            identifier=identifier,
            search=f"{API_ROOT}/search?q={identifier}",
        )

    return handler


def endpoint_sources(request: dict, params: dict, root: Path) -> dict:
    reject_unknown(params, {"limit", "offset"})
    sources = dataset(root)[public.SOURCES_FILE]["sources"]
    page, pagination = paginate(sources, params, request)
    return envelope(
        request,
        root,
        results=[public_source(entry) for entry in page],
        pagination=pagination,
        unknowns=[
            "Freshness records when a source was last observed. A source past its "
            "cadence is one nobody has looked at recently; it is not known to be wrong."
        ],
    )


def endpoint_source_detail(request: dict, params: dict, root: Path, identifier: str = "") -> dict:
    reject_unknown(params, set())
    request["id"] = identifier
    for entry in dataset(root)[public.SOURCES_FILE]["sources"]:
        if entry["id"] == identifier:
            return envelope(request, root, result=public_source(entry))
    raise ApiError(
        "NOT_FOUND", f"No registered source has the identifier {identifier!r}.", identifier=identifier
    )


def public_source(entry: dict) -> dict:
    """A registered source, with freshness stated and nothing operational."""
    if not entry["baselined"]:
        state = "never_attempted"
    elif entry["last_observed_at"]:
        state = "observed"
    else:
        state = "review_required"
    return {
        "source_id": entry["id"],
        "title": entry["title"],
        "trust": entry["trust"],
        "category": entry["category"],
        "role": entry["role"],
        "lifecycle": entry["lifecycle"],
        "canonical_url": entry["url"],
        "check_cadence_days": entry["check_cadence_days"],
        "last_observed_at": entry["last_observed_at"],
        "snapshot_sha256": entry["snapshot_sha256"],
        "freshness_state": state,
        "freshness_note": (
            "Stale means nobody has re-read the source recently. It does not mean "
            "the source or the records derived from it are wrong."
        ),
        "href": f"{API_ROOT}/sources/{public.slug(entry['id'])}",
        "site_url": entry["route"],
    }


def endpoint_provenance(request: dict, params: dict, root: Path, identifier: str = "") -> dict:
    """Lineage from a published record to the bytes behind it."""
    reject_unknown(params, set())
    request["id"] = identifier
    records = all_records(root)
    record = records.get(identifier)
    if record is None:
        record = next(
            (entry for entry in records.values() if public.slug(entry["id"]) == identifier), None
        )
    if record is None:
        raise ApiError(
            "NOT_FOUND",
            f"No published record has the identifier {identifier!r}.",
            identifier=identifier,
            search=f"{API_ROOT}/search?q={identifier}",
        )

    by_source = {entry["id"]: entry for entry in dataset(root)[public.SOURCES_FILE]["sources"]}
    steps = []
    edges = []
    for step in record["provenance"]:
        resolved = dict(step)
        source_id = step.get("source_id")
        if source_id and source_id in by_source:
            source = by_source[source_id]
            resolved["source_title"] = source["title"]
            resolved["source_trust"] = source["trust"]
            resolved["source_href"] = f"{API_ROOT}/sources/{public.slug(source_id)}"
            resolved["canonical_url"] = step.get("source_url") or source["url"]
        steps.append(resolved)
        edges.append(
            {
                "from": record["id"],
                "from_domain": record["domain"],
                "to": source_id or step.get("case_id") or step["channel"],
                "to_kind": step["channel"],
                "relation": "supported_by",
            }
        )
    return envelope(
        request,
        root,
        result={
            "id": record["id"],
            "domain": record["domain"],
            "trust_class": record["trust"]["class"],
            "trusted_knowledge": record["trust"]["trusted_knowledge"],
            "record_href": api_href(record["domain"], record["id"]),
            "edges": edges,
            "steps": steps,
        },
        provenance=steps,
        unknowns=(
            []
            if steps
            else ["This record declares no upstream authority to traverse."]
        ),
    )


def endpoint_openapi(request: dict, params: dict, root: Path) -> dict:
    """The API's own description, built from the same route table it dispatches."""
    reject_unknown(params, set())
    return openapi_document(root)


# ---------------------------------------------------------------------------
# Route table — one definition, used to dispatch and to describe
# ---------------------------------------------------------------------------


def build_routes() -> list[dict]:
    routes: list[dict] = [
        {
            "path": f"{API_ROOT}",
            "operation_id": "getIndex",
            "summary": "List the available endpoints.",
            "handler": endpoint_index,
            "kind": "index",
        },
        {
            "path": f"{API_ROOT}/status",
            "operation_id": "getStatus",
            "summary": "What this release holds and how current its sources are.",
            "handler": endpoint_status,
            "kind": "status",
        },
        {
            "path": f"{API_ROOT}/search",
            "operation_id": "search",
            "summary": "Search published records. Exact identity outranks prose.",
            "handler": endpoint_search,
            "kind": "search",
            "parameters": ["q", "domain", "trust_class", "limit", "offset"],
        },
    ]
    for domain in public.PUBLIC_DOMAINS:
        segment = DOMAIN_SEGMENT[domain]
        singular, plural = DOMAIN_NOUN[domain]
        routes.append(
            {
                "path": f"{API_ROOT}/{segment}",
                "operation_id": f"list{segment.title().replace('-', '')}",
                "summary": f"List {plural}.",
                "handler": endpoint_domain_list(domain),
                "kind": "list",
                "domain": domain,
                "parameters": ["limit", "offset"],
            }
        )
        routes.append(
            {
                "path": f"{API_ROOT}/{segment}/{{id}}",
                "operation_id": f"get{segment.title().replace('-', '')}",
                "summary": f"One {singular} by its canonical identifier.",
                "handler": endpoint_domain_detail(domain),
                "kind": "detail",
                "domain": domain,
            }
        )
    routes.extend(
        [
            {
                "path": f"{API_ROOT}/sources",
                "operation_id": "listSources",
                "summary": "The registered source directory.",
                "handler": endpoint_sources,
                "kind": "list",
                "parameters": ["limit", "offset"],
            },
            {
                "path": f"{API_ROOT}/sources/{{id}}",
                "operation_id": "getSource",
                "summary": "One registered source.",
                "handler": endpoint_source_detail,
                "kind": "detail",
            },
            {
                "path": f"{API_ROOT}/provenance/{{id}}",
                "operation_id": "getProvenance",
                "summary": "Lineage from a record to the snapshot and source behind it.",
                "handler": endpoint_provenance,
                "kind": "detail",
            },
            {
                "path": f"{API_ROOT}/openapi.json",
                "operation_id": "getOpenapi",
                "summary": "This API's OpenAPI 3.1 description.",
                "handler": endpoint_openapi,
                "kind": "openapi",
            },
        ]
    )
    return routes


ROUTES = build_routes()

# Methods that can reach a handler at all. Everything else is refused by the
# dispatcher before any lookup happens, so there is no code path from a POST to
# a record, let alone to a canonical store.
READ_METHODS = ("GET", "HEAD")
ALLOWED_METHODS = ("GET", "HEAD", "OPTIONS")


def match_route(path: str) -> tuple[dict, str | None] | None:
    normalized = path.rstrip("/") or path
    for route in ROUTES:
        if "{id}" not in route["path"]:
            if normalized == route["path"].rstrip("/"):
                return route, None
            continue
        prefix = route["path"][: route["path"].index("{id}")]
        if normalized.startswith(prefix):
            remainder = normalized[len(prefix) :]
            if remainder and "/" not in remainder:
                return route, remainder
    return None


def handle(
    method: str,
    path: str,
    params: dict[str, list[str]] | None = None,
    root: Path = dk_core.ROOT,
) -> tuple[int, dict]:
    """Answer one request. No sockets, no headers, no framework.

    Returns the HTTP status and the payload. Everything a transport needs to
    know beyond that — content type, caching, CORS — is the transport's business
    and is decided from the status and the payload alone.
    """
    params = params or {}
    method = method.upper()
    if method not in ALLOWED_METHODS:
        raise ApiError(
            "METHOD_NOT_ALLOWED",
            f"{method} is not supported. This API is read-only.",
            method=method,
            allowed=list(ALLOWED_METHODS),
        )
    matched = match_route(path)
    if matched is None:
        raise ApiError(
            "NOT_FOUND",
            f"No endpoint at {path!r}.",
            path=path,
            index=API_ROOT,
        )
    route, identifier = matched
    request = {"path": path, "operation_id": route["operation_id"]}
    if identifier is not None:
        payload = route["handler"](request, params, root, identifier)
    else:
        payload = route["handler"](request, params, root)
    return 200, payload


# ---------------------------------------------------------------------------
# Cache validators
# ---------------------------------------------------------------------------


def etag_for(payload: dict) -> str:
    """A strong validator derived from the response content.

    Deterministic on purpose: the same dataset and the same request produce the
    same bytes, so a consumer's conditional request is answerable without
    re-reading anything, and a restarted process does not invalidate every
    cache it ever populated.
    """
    return '"' + query.digest_hex(stable_json(payload))[:32] + '"'


# ---------------------------------------------------------------------------
# OpenAPI, generated from the route table above
# ---------------------------------------------------------------------------

PARAMETER_SPECS = {
    "q": {
        "name": "q",
        "in": "query",
        "required": True,
        "description": "Search term. Matching is exact, never fuzzy or semantic.",
        "schema": {"type": "string", "minLength": 1, "maxLength": MAX_QUERY_LENGTH},
    },
    "domain": {
        "name": "domain",
        "in": "query",
        "required": False,
        "description": "Restrict to one or more published domains. Repeatable.",
        "schema": {"type": "array", "items": {"type": "string", "enum": list(public.PUBLIC_DOMAINS)}},
    },
    "trust_class": {
        "name": "trust_class",
        "in": "query",
        "required": False,
        "description": "Restrict to one or more published trust classes. Repeatable.",
        "schema": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": sorted({query.DOMAIN_TRUST_CLASS[d] for d in public.PUBLIC_DOMAINS}),
            },
        },
    },
    "limit": {
        "name": "limit",
        "in": "query",
        "required": False,
        "description": f"Maximum records to return. Default {DEFAULT_LIMIT}, maximum {MAX_LIMIT}.",
        "schema": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": DEFAULT_LIMIT},
    },
    "offset": {
        "name": "offset",
        "in": "query",
        "required": False,
        "description": "Records to skip. Ordering is by canonical identifier and is stable.",
        "schema": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET, "default": 0},
    },
}


def openapi_document(root: Path = dk_core.ROOT) -> dict:
    """Describe the API from the same table that serves it.

    Generated rather than maintained, because a hand-written description is a
    second truth source that drifts the first time a route changes.
    """
    identity = manifest(root)
    paths: dict[str, Any] = {}
    for route in ROUTES:
        parameters = [PARAMETER_SPECS[name] for name in route.get("parameters", [])]
        if "{id}" in route["path"]:
            parameters = [
                {
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "description": "The record's canonical Drupal Knowledge identifier.",
                    "schema": {"type": "string"},
                }
            ] + parameters
        responses = {
            "200": {
                "description": "Success.",
                "headers": {
                    "ETag": {
                        "description": "Strong validator derived from the response content.",
                        "schema": {"type": "string"},
                    }
                },
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Envelope"}
                        if route["kind"] != "openapi"
                        else {"type": "object"}
                    }
                },
            },
            "304": {"description": "Not modified; the supplied ETag still matches."},
            "400": {"description": "Malformed request.", "content": _error_content()},
            "404": {"description": "No such record or route.", "content": _error_content()},
            "405": {
                "description": "This API is read-only; the method is not supported.",
                "content": _error_content(),
            },
            "503": {
                "description": "The published dataset is unavailable.",
                "content": _error_content(),
            },
        }
        if "{id}" not in route["path"]:
            responses.pop("404")
        entry = {
            "operationId": route["operation_id"],
            "summary": route["summary"],
            "responses": responses,
        }
        if parameters:
            entry["parameters"] = parameters
        paths[route["path"]] = {"get": entry}
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Drupal Knowledge Public Knowledge API",
            "version": API_CONTRACT_VERSION,
            "summary": "Read-only access to reviewed Drupal knowledge and source-derived records.",
            "description": (
                "Every response states how far its content can be trusted and where it "
                "came from. The API has no mutation authority: GET, HEAD and OPTIONS are "
                "the only methods it routes, and it reads a published dataset rather than "
                "any canonical store. Records are served from a content-addressed dataset "
                "whose identity appears in every response."
            ),
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"},
        },
        "servers": [{"url": "/", "description": "The host serving this API."}],
        "x-drupal-knowledge": {
            "dk_version": identity["dk_version"],
            "dataset_schema_version": identity["dataset_schema_version"],
            "query_interface_version": identity["query_interface_version"],
            "published_domains": list(public.PUBLIC_DOMAINS),
            "excluded_domains": identity["excluded_domains"],
            "trust_classes": sorted(
                {query.DOMAIN_TRUST_CLASS[d] for d in public.PUBLIC_DOMAINS}
            ),
            "cors": "Access-Control-Allow-Origin: * on every endpoint; no credentials accepted.",
            "authentication": "None. Everything served is public-safe and read-only.",
        },
        "paths": paths,
        "components": {
            "schemas": {
                "Envelope": ENVELOPE_SCHEMA,
                "Record": RECORD_SCHEMA,
                "Error": ERROR_SCHEMA,
            }
        },
    }


def _error_content() -> dict:
    return {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}


# Transport-level shapes only. Domain content keeps the contracts the records
# already carry, which is why nothing here re-describes an advisory.
ENVELOPE_SCHEMA = {
    "type": "object",
    "required": [
        "api_version",
        "api_contract_version",
        "dk_version",
        "dataset_id",
        "request",
        "warnings",
        "unknowns",
    ],
    "properties": {
        "api_version": {"type": "string"},
        "api_contract_version": {"type": "string"},
        "dk_version": {"type": "string"},
        "dataset_id": {"type": "string"},
        "dataset_schema_version": {"type": "string"},
        "query_interface_version": {"type": "string"},
        "request": {"type": "object"},
        "count": {"type": "integer", "minimum": 0},
        # Left unresolved on purpose: OpenAPI resolves it under components and
        # the standalone schema under $defs, and both spellings describe the
        # same wrapper.
        "result": {"type": "object"},
        "results": {"type": "array", "items": {"type": "object"}},
        "sections": {"type": "object"},
        "pagination": {
            "type": "object",
            "required": ["limit", "offset", "total", "returned", "ordering"],
            "properties": {
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
                "total": {"type": "integer"},
                "returned": {"type": "integer"},
                "next_offset": {"type": ["integer", "null"]},
                "ordering": {"type": "string"},
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
        "unknowns": {
            "type": "array",
            "items": {"type": "string"},
            "description": "What this answer does not settle. Never emptied for tidiness.",
        },
        "provenance": {"type": "array", "items": {"type": "object"}},
    },
}

ERROR_SCHEMA = {
    "type": "object",
    "required": ["api_version", "error"],
    "properties": {
        "api_version": {"type": "string"},
        "api_contract_version": {"type": "string"},
        "dk_version": {"type": "string"},
        "dataset_id": {"type": "string"},
        "error": {
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": {"type": "string", "enum": sorted(ERROR_STATUS)},
                "message": {"type": "string"},
                "details": {"type": "object"},
            },
        },
    },
}

# Referenced by the envelope; kept beside it so a consumer reading the document
# can see what a record looks like without opening a second file.
RECORD_SCHEMA = {
    "type": "object",
    "required": [
        "id",
        "domain",
        "record_type",
        "trust_class",
        "trusted_knowledge",
        "title",
        "detail",
        "unknowns",
        "provenance",
    ],
    "properties": {
        "id": {"type": "string"},
        "domain": {"type": "string", "enum": list(public.PUBLIC_DOMAINS)},
        "record_type": {"type": "string"},
        "trust_class": {
            "type": "string",
            "enum": sorted({query.DOMAIN_TRUST_CLASS[d] for d in public.PUBLIC_DOMAINS}),
        },
        "trusted_knowledge": {
            "type": "boolean",
            "description": "True for reviewed Drupal Knowledge only.",
        },
        "universal_drupal_rule": {"type": "boolean"},
        "authority": {"type": "string"},
        "trust_explanation": {"type": "string"},
        "review_status": {"type": "string"},
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "detail": {"type": "object"},
        "explanation": {"type": "object"},
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "provenance": {"type": "array", "items": {"type": "object"}},
        "related": {"type": "array", "items": {"type": "object"}},
        "href": {"type": "string"},
        "provenance_href": {"type": "string"},
        "site_url": {"type": "string"},
        "match": {"type": "object"},
    },
}


# ---------------------------------------------------------------------------
# Generated artifacts
# ---------------------------------------------------------------------------

ARTIFACT_DIR = Path("public-api")
OPENAPI_FILE = "openapi.json"
SCHEMA_FILE = "api-response.schema.json"


def response_schema() -> dict:
    """The transport contract, and only the transport contract.

    Domain content keeps the schemas the records already have. Re-describing an
    advisory here would create a second definition of what an advisory is, and
    the first one to drift would be this copy.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://drupal-knowledge.zarabatana.info/schema/api-response.schema.json",
        "title": "Drupal Knowledge Public Knowledge API response",
        "description": (
            "Envelope and record wrapper only. A record's `detail` is the domain "
            "contract it already carries in schema/: security-advisory.schema.json, "
            "api-lifecycle-record.schema.json, change-record.schema.json, "
            "knowledge-record.schema.json, implementation-rule.schema.json and "
            "solved-case.schema.json. Those are not restated here."
        ),
        "api_contract_version": API_CONTRACT_VERSION,
        "oneOf": [
            {"$ref": "#/$defs/Envelope"},
            {"$ref": "#/$defs/Error"},
        ],
        "$defs": {
            "Envelope": ENVELOPE_SCHEMA,
            "Record": RECORD_SCHEMA,
            "Error": ERROR_SCHEMA,
        },
    }

# A small, fixed set of real responses. They are regenerated with the contract
# and byte-compared, so a documented example cannot describe an API that no
# longer behaves that way.
EXAMPLE_REQUESTS = (
    ("status", "GET", f"{API_ROOT}/status", {}),
    ("search-cve", "GET", f"{API_ROOT}/search", {"q": ["CVE-2025-3057"]}),
    ("search-symbol", "GET", f"{API_ROOT}/search", {"q": ["file_create_url"]}),
    ("advisory-detail", "GET", f"{API_ROOT}/security/SA-CORE-2025-001", {}),
    ("provenance", "GET", f"{API_ROOT}/provenance/SA-CORE-2025-001", {}),
    ("source-detail", "GET", f"{API_ROOT}/sources/drupal-security-advisories-core", {}),
    ("error-not-found", "GET", f"{API_ROOT}/security/SA-CORE-9999-999", {}),
)


def artifact_bytes(root: Path = dk_core.ROOT) -> dict[Path, bytes]:
    """Every generated API artifact, as the exact bytes that belong on disk."""
    target = root / ARTIFACT_DIR
    files: dict[Path, bytes] = {
        target / OPENAPI_FILE: (stable_json(openapi_document(root)) + "\n").encode("utf-8"),
        target / SCHEMA_FILE: (stable_json(response_schema()) + "\n").encode("utf-8"),
    }
    for name, method, path, params in EXAMPLE_REQUESTS:
        try:
            _status, payload = handle(method, path, params, root)
        except ApiError as err:
            payload = error_payload(err, root)
        public.assert_public_safe(f"API example {name}", payload)
        files[target / "examples" / f"{name}.json"] = (
            stable_json(payload) + "\n"
        ).encode("utf-8")
    return files


def write_artifacts(root: Path = dk_core.ROOT) -> list[Path]:
    written = []
    for path, payload in sorted(artifact_bytes(root).items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        written.append(path)
    return written


def validate_api_artifacts(root: Path = dk_core.ROOT) -> list[str]:
    """Fail if the contract moved and the published description did not."""
    stale = []
    for path, expected in sorted(artifact_bytes(root).items()):
        if not path.is_file() or path.read_bytes() != expected:
            stale.append(str(path.relative_to(root)))
    if stale:
        raise dk_core.ValidationError(
            "the public API contract artifacts are stale: "
            + ", ".join(stale)
            + ". Run python3 scripts/dk.py api build"
        )
    return ["PUBLIC_API_ARTIFACTS_CURRENT=PASS"]
