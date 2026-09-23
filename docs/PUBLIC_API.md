# The Public Knowledge API

Read-only JSON over the same records the command line and the website answer
from. No accounts, no keys, no mutation.

## Overview

```text
canonical records → dk_query.py → dk_public.py → public-site/dataset/ → dk_api.py → dk_api_http.py
```

`scripts/dk_api.py` builds responses and knows nothing about HTTP.
`scripts/dk_api_http.py` moves bytes and knows nothing about Drupal. The
contract layer is importable and callable without starting a server:

```python
import dk_api
status, payload = dk_api.handle("GET", "/api/v1/search", {"q": ["CVE-2025-3057"]})
```

The dependency list is the Python standard library.

### Why it cannot disagree with the CLI

It reads the published dataset — the same bytes the website is built from — and
ranks search results with `dk_query.score_record` itself, reached through
`dk_public.search`. There is no second ranking implementation, no second trust
model, and no path from a request to a canonical store.

## Versioning

Two version numbers, on purpose:

| | |
| --- | --- |
| `api_contract_version` | `1.0` — the shape of requests and responses |
| `dk_version` | the Drupal Knowledge release that produced the records |
| `dataset_id` | content-addressed identity of the trusted knowledge behind them |

A release that ingests new advisories changes `dk_version` and `dataset_id` and
leaves the contract alone. A release that fixes the CLI changes `dk_version`
alone: `dataset_id` covers the trusted records and nothing else, so it does not
move for a version bump, a source re-fetch or a snapshot digest. Record both if
you need to reproduce an answer. Routes are versioned in the path (`/api/v1/…`),
so a future `v2` can exist beside `v1` rather than replacing it.

## Status

```text
GET /api/v1/status
```

Returns the release identity, the published domains with their record counts and
trust classes, the domains that are deliberately **not** published with the
reason for each, and a source-freshness summary. No local paths, no secrets.

## Search

```text
GET /api/v1/search?q=CVE-2025-3057
GET /api/v1/search?q=views&domain=api_lifecycle&limit=5
GET /api/v1/search?q=access%20bypass&trust_class=source_derived_authoritative
```

Matching is exact — never fuzzy, never semantic. Ranking is banded so structured
identity always beats prose:

```text
exact identifier (1000) > exact structured field (900) > identifier prefix (600)
> exact token (400) > title substring (200) > body substring (50)
```

Every result carries `match.rank` and `match.reason`. The same query against the
same `dataset_id` always returns the same order.

Filters are bounded to what canonical semantics already support: `domain`,
`trust_class`, `limit`, `offset`. Anything else is a `400 INVALID_FILTER` rather
than a silently ignored parameter.

## Knowledge, security, API lifecycle, change records, rules, solved cases

```text
GET /api/v1/knowledge          GET /api/v1/knowledge/{id}
GET /api/v1/security           GET /api/v1/security/SA-CORE-2025-001
GET /api/v1/api-lifecycle      GET /api/v1/api-lifecycle/{id}
GET /api/v1/change-records     GET /api/v1/change-records/{id}
GET /api/v1/rules              GET /api/v1/rules/{id}
GET /api/v1/solved-cases       GET /api/v1/solved-cases/{id}
```

`{id}` is the record's canonical Drupal Knowledge identifier — the same one the
CLI prints and the website routes on.

**Knowledge** serves reviewed records only. Unreviewed material is not trusted
knowledge and is not served as it.

**Security** preserves what the Drupal Security Team published: the advisory's
own affected-version expression, the releases it names as fixed, the risk vector
as a vector, assigned CVEs, whether a solution was published. `scored_by_drupal_knowledge`
and `remediation_authored_by_drupal_knowledge` are both `false` — no CVSS is
computed and no severity is invented.

**API lifecycle** keeps `deprecated_version` and `removed_version` distinct and
records `replacement_state: unknown` where the annotation stated none.

**Rules** carry their `review_status`, `enforcement_intent`, `severity_state`
and `context_requirements`, so a draft rule cannot be read as production
guidance.

**Solved cases** carry problem, root cause, solution, verification, conditions
and limitations, and say in `unknowns` that they are proven in one observed
context and are not universal Drupal truth.

## Sources

```text
GET /api/v1/sources
GET /api/v1/sources/drupal-security-advisories-core
```

Source id, title, trust tier, category, canonical URL, declared check cadence,
when it was last successfully observed, the snapshot digest, and a
`freshness_state` of `observed`, `never_attempted` or `review_required`.

Stale means nobody has re-read the source recently. It does not mean the source
or the records derived from it are wrong, and the response says so.

No credentials, no local snapshot paths, no collection environment detail, no
reviewer identities.

## Provenance

```text
GET /api/v1/provenance/SA-CORE-2025-001
```

```text
record → channel → registered source → snapshot digest → canonical URL
```

`edges` is the graph; `steps` is the detail, each step carrying
`source_href` back into the API. The snapshot digest is the point: it identifies
the exact bytes a claim was derived from, so the claim can be checked rather
than believed. Where a snapshot lives on disk is never published.

## Pagination

```text
?limit=25&offset=0
```

Default `limit` 25, maximum 200. Maximum `offset` 100000. Ordering is by
canonical identifier, ascending, and the dataset is immutable for a given
`dataset_id` — so a page cannot shift underneath a consumer without the identity
in the envelope changing too.

Every paginated response carries `pagination.total`, `pagination.returned` and
`pagination.next_offset` (`null` on the last page).

## Trust labels

Every result states its own standing:

| `trust_class` | `trusted_knowledge` | Means |
| --- | --- | --- |
| `reviewed_drupal_knowledge` | `true` | reviewed against authoritative sources |
| `source_derived_authoritative` | `false` | projected verbatim from an official Drupal source |
| `reviewed_implementation_rule` | `false` | a reviewed rule; says nothing until evidence settles it |
| `proven_case_context_only` | `false` | proven in one observed context |

Exactly one class is trusted knowledge. An advisory is authoritative *about*
Drupal without being a Drupal Knowledge rule, and the boolean makes that
impossible to miss.

Discovery signals are not served by this API at all. They are untrusted
community observations awaiting corroboration, and `/status` lists them among
the excluded domains with the reason.

## Unknown states

`unknowns` is present on every response and is never emptied to look tidy.

The API never converts `not_observed`, bounded evidence, partial evidence or a
stale source into `false`, `safe`, `secure` or `compatible`. A search that
matched nothing says the record set is bounded; it does not say the subject is
unproblematic.

## Caching

`ETag` is a strong validator derived from the response content, so the same
dataset and the same request produce the same validator across restarts and
across machines.

```console
$ curl -sI /api/v1/status | grep ETag
ETag: "3e06737ea9c0fad72c36311ef3c42233"

$ curl -s -o /dev/null -w '%{http_code}\n' -H 'If-None-Match: "3e06737…"' /api/v1/status
304
```

`Cache-Control: public, max-age=300, must-revalidate`. Error responses are
`no-store`.

## CORS

```text
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, HEAD, OPTIONS
Access-Control-Expose-Headers: ETag
```

Open deliberately: everything served is public-safe and read-only, browser
tooling is an intended consumer, and no endpoint accepts credentials — there is
no `Access-Control-Allow-Credentials` and nothing for one to protect.

## Errors

```json
{
  "api_version": "1",
  "dk_version": "0.20.0",
  "error": {
    "code": "NOT_FOUND",
    "message": "No advisory record has the identifier 'SA-CORE-9999-999'.",
    "details": {"domain": "advisory", "search": "/api/v1/search?q=SA-CORE-9999-999"}
  }
}
```

| Code | Status |
| --- | --- |
| `INVALID_QUERY`, `INVALID_PAGINATION`, `INVALID_FILTER`, `UNKNOWN_DOMAIN`, `QUERY_TOO_LONG` | 400 |
| `NOT_FOUND` | 404 |
| `METHOD_NOT_ALLOWED` | 405 |
| `INTERNAL_ERROR` | 500 |
| `DATASET_UNAVAILABLE` | 503 |

Client errors are refusals a consumer can branch on. No Python traceback ever
reaches a response body.

`POST`, `PUT`, `PATCH` and `DELETE` return `405` with `Allow: GET, HEAD, OPTIONS`.
This API has no mutation authority, and there is no query parameter that grants
it one.

## OpenAPI

```text
GET /api/v1/openapi.json          # served live
public-api/openapi.json           # committed, stale-guarded
```

OpenAPI 3.1, generated from the same route table the server dispatches, so it
cannot describe an API that no longer exists. `dk.py validate` fails if the
committed document no longer matches the contract:

```console
$ python3 scripts/dk.py validate
ERROR: the public API contract artifacts are stale: public-api/openapi.json.
Run python3 scripts/dk.py api build
```

The same guard covers `public-api/examples/*.json`, which are real responses
regenerated with the contract.

## Running it

```bash
python3 scripts/dk.py api serve                 # http://127.0.0.1:8088/api/v1
python3 scripts/dk.py api serve --port 9000
python3 scripts/dk.py api routes                # the route table
python3 scripts/dk.py api build                 # regenerate openapi + examples
```

The default bind is loopback. Binding a public interface is an explicit
`--host` decision for an explicit deployment.

Deployment is one long-running Python process with no dependencies, no database
and no writable state; `/api/v1/status` doubles as a health check and returns
`503 DATASET_UNAVAILABLE` if the published dataset is missing from the checkout.

## Examples

Real committed responses live in `public-api/examples/`:

```text
status.json            advisory-detail.json    provenance.json
search-cve.json        search-symbol.json      source-detail.json
error-not-found.json
```

They are regenerated by `dk api build` and byte-compared by validation, so a
documented example cannot describe behaviour the API no longer has.

## What this API is not

- Not an analysis service. There is no upload, no repository URL, no job
  queue, and nothing is stored about a caller.
- Not authenticated. Everything served is public-safe and read-only.
- Not a source of project-specific answers. Evidence, findings, upgrade
  assessments, migration work and remediation plans describe one repository at
  one revision; ask about your own project locally with `dk project`.
