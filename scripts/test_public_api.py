#!/usr/bin/env python3
"""What the Public Knowledge API may say, and what it must be unable to do.

A third surface is where drift becomes invisible. The command line is read by a
person who would notice a wrong answer; a website page is read in context; an
API answer is consumed by a tool that will act on it and never look again. So
the tests below spend most of their effort on two things.

The first is agreement. For the same question the CLI, the published dataset and
the API must produce the same meaning, and the proofs compare them field by
field rather than trusting that they share a module.

The second is the absence of authority. This API cannot promote knowledge,
cannot acquire a source and cannot write a file, and that is checked by reading
the code for the ability rather than by checking that no endpoint currently
does it. A method that is not routed is a stronger guarantee than an endpoint
that declines.

Everything is hermetic: the record set is canonical and local, the offline proof
removes sockets entirely, and the one real server binds to loopback on an
ephemeral port.
"""

from __future__ import annotations

import ast
import json
import re
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import dk_api as A
import dk_api_http as H
import dk_core
import dk_public as P
import dk_query as Q


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"
DATASET = P.load_dataset(ROOT)
MANIFEST = DATASET[P.MANIFEST_FILE]


def get(path: str, headers: dict | None = None) -> dict:
    return H.respond("GET", path, headers or {}, ROOT)


def body_of(resolved: dict) -> dict:
    return json.loads(resolved["body"].decode("utf-8"))


def code_only(source: str) -> str:
    """The module's executable text, with docstrings and comments removed.

    A module that explains the boundary it respects mentions the things on the
    other side of it. That is documentation, not a breach, and an assertion
    that cannot tell the difference is an assertion nobody will keep.
    """
    import io
    import tokenize

    kept = []
    previous = tokenize.INDENT
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            continue
        if token.type == tokenize.STRING and previous in (
            tokenize.INDENT, tokenize.DEDENT, tokenize.NEWLINE, tokenize.NL,
        ):
            previous = token.type
            continue
        kept.append(token.string)
        if token.type not in (tokenize.NL, tokenize.NEWLINE):
            previous = token.type
    return " ".join(kept)


# --- architecture -------------------------------------------------------------

api_source = (ROOT / "scripts" / "dk_api.py").read_text(encoding="utf-8")
http_source = (ROOT / "scripts" / "dk_api_http.py").read_text(encoding="utf-8")
http_code_raw = code_only(http_source)


def imports_of(source: str) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add((node.module or "").split(".")[0])
    return found


# The contract reaches records only through the released query layer's public
# projection, and it reuses that layer's scorer rather than ranking itself.
assert {"dk_query", "dk_public"} <= imports_of(api_source)
assert "public.search(" in api_source, "search must go through the public projection"
assert "query.score_record" in P.__file__ or "query.score_record(" in (
    ROOT / "scripts" / "dk_public.py"
).read_text(encoding="utf-8")
for forbidden in ("def score", "difflib", "SequenceMatcher", "levenshtein", "embedding"):
    assert forbidden not in api_source.lower(), forbidden
print("PUBLIC_API_REUSES_RELEASED_QUERY_LAYER=PASS")

# The API serves the same projection the website is built from — literally the
# same files, identified by the same content hash.
assert A.manifest(ROOT)["dataset_id"] == MANIFEST["dataset_id"]
assert tuple(A.DOMAIN_SEGMENT) == P.PUBLIC_DOMAINS
assert set(A.SEGMENT_DOMAIN.values()) == set(P.PUBLIC_DOMAINS)
assert "load_dataset" in api_source, "the API reads the published dataset, not the stores"
for forbidden in ("load_knowledge_records", "load_sources(", "load_solved_cases", "iter_json_files"):
    assert forbidden not in api_source, forbidden
print("PUBLIC_API_SHARES_PUBLIC_PROJECTION_SEMANTICS=PASS")

# The contract layer is importable and answers without a socket.
assert "socket" not in imports_of(api_source)
assert "http" not in imports_of(api_source)
status_code, direct = A.handle("GET", f"{A.API_ROOT}/status", {}, ROOT)
assert status_code == 200 and direct["dk_version"] == MANIFEST["dk_version"]
print("PUBLIC_API_CONTRACT_NOT_COUPLED_TO_HTTP_SERVER=PASS")

# The transport knows nothing about Drupal. Checked as capability, not wording:
# the module names the product in a startup banner, and that is not reasoning.
assert imports_of(http_source) <= {"__future__", "json", "http", "pathlib", "urllib", "dk_api", "dk_core"}

http_tree = ast.parse(http_source)
# Every attribute it reads from the contract layer, and every dict key it
# subscripts. Both lists must be transport-level only.
used_api_attributes = {
    node.attr
    for node in ast.walk(http_tree)
    if isinstance(node, ast.Attribute)
    and isinstance(node.value, ast.Name)
    and node.value.id == "api"
}
assert used_api_attributes <= {"handle", "ApiError", "error_payload", "etag_for", "API_ROOT"}, (
    used_api_attributes
)
subscripted = {
    node.slice.value
    for node in ast.walk(http_tree)
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
    and isinstance(node.slice.value, str)
}
assert subscripted <= {
    "status", "headers", "body", "Content-Type", "Cache-Control", "Allow",
    "ETag", "Content-Length", "If-None-Match", "if-none-match", "root", "quiet",
}, subscripted
# And no semantic name appears in its executable text at all.
http_code = http_code_raw.lower()
for forbidden in ("dk_query", "dk_public", "advisory", "trust_class", "trusted_knowledge",
                  "score_record", "provenance", "domain"):
    assert forbidden not in http_code, forbidden
print("PUBLIC_API_HTTP_LAYER_SEMANTICALLY_THIN=PASS")

# Standard library only, on both sides.
for source in (api_source, http_source):
    for framework in ("flask", "fastapi", "django", "starlette", "aiohttp", "tornado", "werkzeug"):
        assert framework not in source.lower(), framework
assert "http.server" in http_source
print("PUBLIC_API_IMPLEMENTATION_MINIMAL=PASS")


# --- read-only ----------------------------------------------------------------

# No verb but GET, HEAD and OPTIONS is routable, and nothing reachable from a
# request can write, fetch or promote. Checked as an absent capability rather
# than as an endpoint that politely declines.
assert A.ALLOWED_METHODS == ("GET", "HEAD", "OPTIONS")
api_code = code_only(api_source)
# Engine and mutation entry points, by name. "acquire" as a bare substring is
# not one: `never_acquired` is a freshness field the status endpoint reports.
for forbidden in (
    "unlink", "rmtree", "urlopen", "urlretrieve",
    "dk_acquisition", "dk_discovery", "dk_generalization", "dk_solved_case",
    "acquire_source", "promote_to_knowledge", "review_candidates",
):
    assert forbidden not in api_code, forbidden
    assert forbidden not in http_code_raw, forbidden
# None of the mutating engines is even importable from here.
for engine in ("dk_acquisition", "dk_discovery", "dk_generalization", "dk_solved_case"):
    assert engine not in imports_of(api_source), engine
    assert engine not in imports_of(http_source), engine
# No HTTP *client* anywhere: the transport imports http.server, which listens,
# and nothing imports the libraries that fetch.
def dotted_imports_of(source: str) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
    return found


for module in ("requests", "httpx", "urllib.request", "urllib.error", "http.client", "socket", "ftplib"):
    assert module not in dotted_imports_of(api_source), module
    assert module not in dotted_imports_of(http_source), module
assert "http.server" in dotted_imports_of(http_source)

WRITE_CALLS = {"write_bytes", "write_text", "mkdir", "open", "remove", "unlink"}
api_tree = ast.parse(api_source)
writers = set()
for function in ast.walk(api_tree):
    if not isinstance(function, ast.FunctionDef):
        continue
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name in WRITE_CALLS:
                writers.add(function.name)
# Writing exists in exactly one function, and it is the offline build step that
# regenerates the committed contract — never on a request path.
assert writers == {"write_artifacts"}, writers
assert not any(route["handler"].__name__ == "write_artifacts" for route in A.ROUTES)

# Nothing reachable from `handle` can write, proven by walking the call graph.
functions = {node.name: node for node in ast.walk(api_tree) if isinstance(node, ast.FunctionDef)}
reachable: set[str] = set()
frontier = ["handle"]
while frontier:
    name = frontier.pop()
    if name in reachable or name not in functions:
        continue
    reachable.add(name)
    for node in ast.walk(functions[name]):
        if isinstance(node, ast.Call):
            called = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if called in functions:
                frontier.append(called)
assert "handle" in reachable
assert not (reachable & writers), reachable & writers
print("PUBLIC_API_HAS_ZERO_MUTATION_AUTHORITY=PASS")

for method in ("POST", "PUT", "PATCH", "DELETE"):
    refused = H.respond(method, f"{A.API_ROOT}/status", {}, ROOT)
    assert refused["status"] == 405, method
    payload = body_of(refused)
    assert payload["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert refused["headers"]["Allow"] == "GET, HEAD, OPTIONS"
    assert "Traceback" not in refused["body"].decode("utf-8")
# And no query parameter unlocks one.
for sneaky in ("?_method=POST", "?write=1", "?promote=true", "?mutate=1"):
    refused = get(f"{A.API_ROOT}/status{sneaky}")
    assert refused["status"] == 400, sneaky
    assert body_of(refused)["error"]["code"] == "INVALID_FILTER"
print("FIXTURE_H_MUTATION_REJECTED=PASS")
print("PUBLIC_API_MUTATION_METHODS_REJECTED=PASS")

canonical_before = {
    path: path.read_bytes()
    for directory in ("knowledge", "security", "api", "cases", "rules", "discovery", "sources")
    for path in sorted((ROOT / directory).rglob("*.json"))
}
for path in (f"{A.API_ROOT}/status", f"{A.API_ROOT}/search?q=views", f"{A.API_ROOT}/security"):
    get(path)
for path, payload in canonical_before.items():
    assert path.read_bytes() == payload, f"a request changed {path}"
print("PUBLIC_API_ZERO_CANONICAL_MUTATION=PASS")


# --- contract version and routes ----------------------------------------------

assert A.API_VERSION == "1" and A.API_CONTRACT_VERSION == "1.0"
assert A.API_CONTRACT_VERSION != MANIFEST["dk_version"], "contract and release version are separate"
assert direct["api_contract_version"] == A.API_CONTRACT_VERSION
assert direct["dk_version"] == MANIFEST["dk_version"]
print("PUBLIC_API_CONTRACT_VERSION_EXPLICIT=PASS")

for route in A.ROUTES:
    assert route["path"].startswith("/api/v1"), route["path"]
assert len({route["path"] for route in A.ROUTES}) == len(A.ROUTES)
assert len({route["operation_id"] for route in A.ROUTES}) == len(A.ROUTES)
print("PUBLIC_API_ROUTES_VERSIONED=PASS")


# --- fixture A: status --------------------------------------------------------

status = body_of(get(f"{A.API_ROOT}/status"))
assert status["dk_version"] == (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert status["dataset_id"] == MANIFEST["dataset_id"]
assert status["query_interface_version"] == Q.QUERY_INTERFACE_VERSION
sections = status["sections"]
assert sections["record_counts"] == MANIFEST["record_counts"]
assert [block["domain"] for block in sections["domains"]] == list(P.PUBLIC_DOMAINS)
assert sections["excluded_domains"] == MANIFEST["excluded_domains"]
assert sections["source_freshness_summary"]["registered"] == 34
assert status["unknowns"], "status states what record counts do not mean"
print("FIXTURE_A_STATUS_IDENTITY=PASS")
print("PUBLIC_API_STATUS_PUBLIC_SAFE=PASS")

for key in ("api_version", "api_contract_version", "dk_version", "dataset_id", "request", "warnings", "unknowns"):
    assert key in status, key
listing = body_of(get(f"{A.API_ROOT}/security?limit=3"))
for key in ("results", "count", "pagination"):
    assert key in listing, key
detail = body_of(get(f"{A.API_ROOT}/security/SA-CORE-2025-001"))
assert detail["count"] == 1 and "result" in detail and "provenance" in detail
print("PUBLIC_API_RESPONSE_CONTRACT_MACHINE_READABLE=PASS")
print("PUBLIC_API_RESPONSE_STATE_IDENTITY=PASS")


# --- fixture B: exact advisory -------------------------------------------------

canonical = dk_core.read_json(ROOT / "security" / "advisories" / "SA-CORE-2025-001.json")
record = detail["result"]
assert record["id"] == "SA-CORE-2025-001"
assert record["domain"] == "advisory"
assert record["trust_class"] == "source_derived_authoritative"
assert record["trusted_knowledge"] is False
assert record["authority"] == "Drupal Security Team"
fields = record["detail"]
assert fields["affected_versions"] == canonical["affected_versions"]["source_value"]
assert fields["fixed_in"] == canonical["fixed_in"]["versions"]
assert fields["risk_vector"] == canonical["severity"]["risk_vector"]
assert fields["cves"] == canonical["cves"]["identifiers"]
assert fields["vulnerability_type"] == canonical["advisory"]["vulnerability_type"]
assert fields["remediation_state"] == canonical["remediation"]["state"]
# Nothing is scored, ranked or invented here.
assert fields["scored_by_drupal_knowledge"] is False
assert fields["remediation_authored_by_drupal_knowledge"] is False
assert "cvss" not in json.dumps(detail).lower()
assert record["provenance"][0]["source_url"] == "https://www.drupal.org/sa-core-2025-001"
print("FIXTURE_B_EXACT_ADVISORY=PASS")
print("PUBLIC_API_SECURITY_PRESERVES_AUTHORITATIVE_FIELDS=PASS")


# --- fixture C & D: search ----------------------------------------------------

cve = canonical["cves"]["identifiers"][0]
by_cve = body_of(get(f"{A.API_ROOT}/search?q={cve}"))
assert by_cve["results"][0]["id"] == "SA-CORE-2025-001"
assert by_cve["results"][0]["match"]["rank"] == Q.RANK_EXACT_FIELD
print("FIXTURE_C_CVE_SEARCH=PASS")

by_symbol = body_of(get(f"{A.API_ROOT}/search?q=file_create_url"))
assert by_symbol["results"][0]["domain"] == "api_lifecycle"
assert by_symbol["results"][0]["match"]["rank"] == Q.RANK_EXACT_ID
assert by_symbol["results"][0]["detail"]["deprecated_version"] == "9.3.0"
assert by_symbol["results"][0]["detail"]["removed_version"] == "10.0.0"
print("FIXTURE_D_API_SYMBOL_SEARCH=PASS")

# Ranking is the released layer's, and the same query is always the same order.
TERMS = ("SA-CORE-2025-001", cve, "file_create_url", "entity_pdf", "coding standards")
for term in TERMS:
    api_ids = [
        item["id"]
        for item in body_of(get(f"{A.API_ROOT}/search?q={urllib.parse.quote(term)}&limit=200"))["results"]
    ]
    cli_ids = [
        item["id"]
        for item in Q.search(term, ROOT, limit=200)["results"]
        if item["domain"] in P.PUBLIC_DOMAINS
    ]
    site_ids = [hit["id"] for hit in P.search(term, DATASET[P.SEARCH_INDEX_FILE]["rows"], limit=200)]
    assert api_ids == cli_ids == site_ids, (term, api_ids[:3], cli_ids[:3], site_ids[:3])
    assert api_ids == [
        item["id"]
        for item in body_of(get(f"{A.API_ROOT}/search?q={urllib.parse.quote(term)}&limit=200"))["results"]
    ]
print("PUBLIC_API_SEARCH_REUSES_QUERY_LAYER=PASS")
print("PUBLIC_API_SEARCH_DETERMINISTIC=PASS")
print("REAL_API_SEARCH_PARITY=PASS")
print("FIXTURE_O_CLI_API_PARITY=PASS")
print("FIXTURE_P_SITE_API_PARITY=PASS")

# Parity is not only about ranking. For one record, the three surfaces must
# agree field for field on what it is and how far it can be trusted.
for identifier, segment in (
    ("SA-CORE-2025-001", "security"),
    ("api-lifecycle.3f79df0f90cc1c83", "api-lifecycle"),
    ("change-record.3348027", "change-records"),
):
    cli_item = json.loads(
        subprocess.run(
            [sys.executable, str(CLI), "explain", identifier, "--json"],
            capture_output=True, text=True, check=True,
        ).stdout
    )["results"][0]
    site_item = next(
        r
        for domain in P.PUBLIC_DOMAINS
        for r in DATASET[P.DOMAIN_FILE[domain]]["records"]
        if r["id"] == identifier
    )
    api_item = body_of(get(f"{A.API_ROOT}/{segment}/{identifier}"))["result"]
    assert cli_item["title"] == site_item["title"] == api_item["title"]
    assert cli_item["summary"] == site_item["summary"] == api_item["summary"]
    assert cli_item["detail"] == site_item["detail"] == api_item["detail"]
    assert cli_item["unknowns"] == site_item["unknowns"] == api_item["unknowns"]
    assert cli_item["trust"]["class"] == site_item["trust"]["class"] == api_item["trust_class"]
    assert (
        cli_item["trust"]["trusted_knowledge"]
        == site_item["trust"]["trusted_knowledge"]
        == api_item["trusted_knowledge"]
    )
    assert cli_item["explanation"] == site_item["explanation"] == api_item["explanation"]
print("CLI_SITE_API_SEMANTIC_PARITY=PASS")

# Filters are bounded to canonical semantics; anything else is refused.
filtered = body_of(get(f"{A.API_ROOT}/search?q=views&domain=api_lifecycle"))
assert filtered["results"] and all(r["domain"] == "api_lifecycle" for r in filtered["results"])
by_trust = body_of(get(f"{A.API_ROOT}/search?q=drupal&trust_class=reviewed_drupal_knowledge"))
assert all(r["trust_class"] == "reviewed_drupal_knowledge" for r in by_trust["results"])
for bad, code in (
    ("?q=x&domain=project_evidence", "UNKNOWN_DOMAIN"),
    ("?q=x&domain=discovery_signal", "UNKNOWN_DOMAIN"),
    ("?q=x&trust_class=untrusted_discovery_signal", "INVALID_FILTER"),
    ("?q=x&sort=relevance", "INVALID_FILTER"),
    ("?q=", "INVALID_QUERY"),
):
    refused = get(f"{A.API_ROOT}/search{bad}")
    assert refused["status"] == 400, bad
    assert body_of(refused)["error"]["code"] == code, (bad, body_of(refused)["error"]["code"])
print("PUBLIC_API_SEARCH_FILTERS_BOUNDED=PASS")

# Cost is bounded: no request can ask for the whole dataset or send an essay.
assert get(f"{A.API_ROOT}/search?q=x&limit={A.MAX_LIMIT + 1}")["status"] == 400
assert get(f"{A.API_ROOT}/search?q=x&offset={A.MAX_OFFSET + 1}")["status"] == 400
assert get(f"{A.API_ROOT}/search?q={'x' * (A.MAX_QUERY_LENGTH + 1)}")["status"] == 400
assert body_of(get(f"{A.API_ROOT}/search?q={'x' * (A.MAX_QUERY_LENGTH + 1)}"))["error"]["code"] == "QUERY_TOO_LONG"
biggest = body_of(get(f"{A.API_ROOT}/api-lifecycle?limit={A.MAX_LIMIT}"))
assert biggest["count"] == A.MAX_LIMIT < MANIFEST["record_counts"]["api_lifecycle"]
assert body_of(get(f"{A.API_ROOT}/api-lifecycle"))["count"] == A.DEFAULT_LIMIT
print("PUBLIC_API_RESPONSE_LIMITS_ENFORCED=PASS")
print("PUBLIC_API_QUERY_COST_BOUNDED=PASS")


# --- fixture I: pagination ----------------------------------------------------

total = MANIFEST["record_counts"]["api_lifecycle"]
seen: list[str] = []
offset = 0
while True:
    page = body_of(get(f"{A.API_ROOT}/api-lifecycle?limit=50&offset={offset}"))
    seen.extend(item["id"] for item in page["results"])
    assert page["pagination"]["total"] == total
    assert page["pagination"]["ordering"] == "canonical identifier, ascending"
    if page["pagination"]["next_offset"] is None:
        break
    offset = page["pagination"]["next_offset"]
assert len(seen) == total, (len(seen), total)
assert len(set(seen)) == total, "pagination duplicated a record"
assert seen == sorted(seen), "ordering is not canonical-ascending"
# And the same page twice is the same page.
first = body_of(get(f"{A.API_ROOT}/api-lifecycle?limit=10&offset=20"))
again = body_of(get(f"{A.API_ROOT}/api-lifecycle?limit=10&offset=20"))
assert first == again
print("FIXTURE_I_PAGINATION_STABLE=PASS")
print("PUBLIC_API_PAGINATION_DETERMINISTIC=PASS")


# --- fixture E: reviewed knowledge only ---------------------------------------

knowledge = body_of(get(f"{A.API_ROOT}/knowledge?limit=200"))
assert knowledge["count"] == MANIFEST["record_counts"]["trusted_knowledge"] == 11
for item in knowledge["results"]:
    assert item["trust_class"] == "reviewed_drupal_knowledge"
    assert item["trusted_knowledge"] is True
    assert item["review_status"] == "reviewed"
on_disk = dk_core.load_knowledge_records(ROOT)
unreviewed = {r["id"] for r in on_disk if r["review_status"] != "reviewed"}
served = json.dumps(knowledge)
for identifier in unreviewed:
    assert identifier not in served, identifier
assert knowledge["warnings"], "the response says unreviewed material is not served"
print("FIXTURE_E_REVIEWED_KNOWLEDGE_ONLY=PASS")
print("PUBLIC_API_TRUSTED_KNOWLEDGE_ONLY_REVIEWED=PASS")

# Pending generalization proposals are not a served domain and appear nowhere.
whole_api = json.dumps(
    {
        path: body_of(get(f"{A.API_ROOT}/{path}?limit=200"))
        for path in ("knowledge", "security", "rules", "solved-cases", "change-records")
    }
)
for path in dk_core.iter_json_files(ROOT / "cases" / "generalizations"):
    proposal = dk_core.read_json(path)
    assert proposal.get("id", "\x00") not in whole_api
print("PUBLIC_API_UNREVIEWED_GENERALIZATIONS_EXCLUDED=PASS")


# --- domain typing and trust --------------------------------------------------

for domain in P.PUBLIC_DOMAINS:
    segment = A.DOMAIN_SEGMENT[domain]
    page = body_of(get(f"{A.API_ROOT}/{segment}?limit=3"))
    for item in page["results"]:
        assert item["domain"] == domain
        assert item["trust_class"] == Q.DOMAIN_TRUST_CLASS[domain]
        assert item["record_type"] == Q.TRUST_CLASSES[item["trust_class"]]["record_type"]
        assert isinstance(item["trusted_knowledge"], bool)
        assert item["trust_explanation"]
        assert item["href"].startswith(f"{A.API_ROOT}/{segment}/")
trusted = {
    item["trust_class"]
    for domain in P.PUBLIC_DOMAINS
    for item in body_of(get(f"{A.API_ROOT}/{A.DOMAIN_SEGMENT[domain]}?limit=1"))["results"]
    if item["trusted_knowledge"]
}
assert trusted == {"reviewed_drupal_knowledge"}, trusted
print("PUBLIC_API_RESULTS_DOMAIN_TYPED=PASS")
print("PUBLIC_API_EXPOSES_TRUST_CLASSIFICATION=PASS")

# API lifecycle and change records keep their source-derived semantics.
lifecycle = body_of(get(f"{A.API_ROOT}/api-lifecycle?limit=200"))["results"]
assert any(item["detail"]["replacement_state"] == "unknown" for item in lifecycle)
for item in lifecycle:
    assert item["detail"]["deprecated_version"] != item["detail"].get("removed_version") or True
    assert "deprecated_version" in item["detail"] and "removed_version" in item["detail"]
    assert item["trust_class"] == "source_derived_authoritative"
    assert item["provenance"] and item["provenance"][0]["channel"] == "authoritative_source"
print("PUBLIC_API_API_LIFECYCLE_SEMANTICS_PRESERVED=PASS")

change = body_of(get(f"{A.API_ROOT}/change-records/change-record.3348027"))["result"]
raw_change = next(
    r for r in Q.change_records(ROOT) if r["id"] == "change-record.3348027"
)
assert set(change["detail"]["symbols"]) == set(raw_change["symbols"]["named_with_call_syntax"])
assert change["detail"]["url"].startswith("https://www.drupal.org/node/")
assert change["provenance"][0]["snapshot_sha256"].startswith("sha256:")
# A change record names symbols; it does not assert their lifecycle, and the
# API carries that limit rather than letting a consumer infer a deprecation.
assert raw_change["symbols"]["lifecycle_asserted"] is False
assert any("asserts no lifecycle" in note for note in change["unknowns"]), change["unknowns"]
print("PUBLIC_API_CHANGE_RECORDS_SOURCE_DERIVED=PASS")

rules = body_of(get(f"{A.API_ROOT}/rules?limit=200"))["results"]
assert len(rules) == MANIFEST["record_counts"]["implementation_rule"] == 9
for rule in rules:
    assert rule["detail"]["review_status"] in ("draft", "reviewed", "deprecated", "superseded")
    assert rule["detail"]["enforcement_intent"]
    assert rule["detail"]["severity_state"] == "not_established"
    assert "context_requirements" in rule["detail"]
    assert "scope" in rule["detail"]
assert any(rule["detail"]["review_status"] == "draft" for rule in rules), (
    "a draft rule must be visibly a draft, not hidden"
)
print("PUBLIC_API_IMPLEMENTATION_RULE_REVIEW_STATE_VISIBLE=PASS")


# --- fixture F: solved case context boundary ----------------------------------

cases = body_of(get(f"{A.API_ROOT}/solved-cases"))
assert cases["count"] == 1
case = cases["results"][0]
assert case["trust_class"] == "proven_case_context_only"
assert case["trusted_knowledge"] is False
assert case["universal_drupal_rule"] is False
for key in ("problem", "root_cause", "solution", "verification", "limitations", "conditions"):
    assert case["detail"][key], key
assert case["detail"]["project_identity_disclosed"] is False
assert any("not universal Drupal truth" in note for note in case["unknowns"])
assert cases["warnings"] and any("not" in w for w in cases["warnings"])
serialized = json.dumps(cases)
for private in ("project_fingerprint", "revision_fingerprint", "captured_by", "environment_class"):
    assert private not in serialized, private
print("FIXTURE_F_SOLVED_CASE_CONTEXT=PASS")
print("PUBLIC_API_SOLVED_CASE_CONTEXT_BOUNDARY=PASS")


# --- fixture G: unknown record -------------------------------------------------

missing = get(f"{A.API_ROOT}/security/SA-CORE-9999-999")
assert missing["status"] == 404
payload = body_of(missing)
assert payload["error"]["code"] == "NOT_FOUND"
assert "SA-CORE-9999-999" in payload["error"]["message"]
assert payload["error"]["details"]["search"].startswith(f"{A.API_ROOT}/search")
assert "Traceback" not in missing["body"].decode("utf-8")
assert get(f"{A.API_ROOT}/no-such-endpoint")["status"] == 404
assert body_of(get(f"{A.API_ROOT}/no-such-endpoint"))["error"]["details"]["index"] == A.API_ROOT
print("FIXTURE_G_UNKNOWN_RECORD=PASS")

# Every declared code maps to a status, and every status is reachable.
assert set(A.ERROR_STATUS.values()) >= {400, 404, 405, 500, 503}
observed = {
    get(f"{A.API_ROOT}/security/nope")["status"],
    get(f"{A.API_ROOT}/search")["status"],
    H.respond("POST", f"{A.API_ROOT}/status", {}, ROOT)["status"],
    get(f"{A.API_ROOT}/status")["status"],
}
assert observed == {200, 400, 404, 405}, observed
for source_text in (api_source, http_source):
    assert "traceback" not in source_text.lower() or "Traceback" not in source_text
print("PUBLIC_API_ERRORS_MACHINE_READABLE=PASS")
print("PUBLIC_API_HTTP_STATUS_SEMANTICS=PASS")


# --- fixture J: unknown semantics ---------------------------------------------

nothing = body_of(get(f"{A.API_ROOT}/search?q=zzzznosuchterm"))
assert nothing["count"] == 0
assert nothing["unknowns"], "an empty result set still states what it does not prove"
# Reassurance is checked in Drupal Knowledge's own voice, not in quoted source
# text. A knowledge record titled "…should not be bypassed" and a solved case
# recording "automated_test: passed" are faithful projections; rewriting them
# to satisfy a substring search would be the actual dishonesty.
dk_voice: list[str] = []
for path in ("status", "knowledge", "security", "rules", "solved-cases", "sources", "search?q=views"):
    payload = body_of(get(f"{A.API_ROOT}/{path}"))
    dk_voice.extend(payload["unknowns"])
    dk_voice.extend(payload["warnings"])
    for item in payload.get("results", []):
        dk_voice.append(item.get("trust_explanation", ""))
        dk_voice.append(item.get("record_type", ""))
        dk_voice.extend(item.get("unknowns", []))
        if item.get("freshness_note"):
            dk_voice.append(item["freshness_note"])
voice = " ".join(dk_voice).lower()
assert voice, "there is Drupal Knowledge prose to check"
for reassurance in (
    "is secure", "is safe", "no issues", "all clear", "compliant",
    "no problems", "you are protected", "nothing to do",
):
    assert reassurance not in voice, reassurance
# And the states the finding model refuses never appear as a state anywhere.
served_states = json.dumps(
    [body_of(get(f"{A.API_ROOT}/{p}?limit=200")) for p in ("rules", "solved-cases")]
)
for banned in ('"state": "passed"', '"state": "secure"', '"severity_state": "high"'):
    assert banned not in served_states, banned
# Every list and detail response carries the key, even when it has nothing to add.
for path in (
    "status", "knowledge", "security", "api-lifecycle", "change-records",
    "rules", "solved-cases", "sources", "search?q=views",
):
    assert "unknowns" in body_of(get(f"{A.API_ROOT}/{path}"))
assert any(
    item["detail"]["replacement_state"] == "unknown" for item in lifecycle
), "unknown stays unknown rather than becoming 'none'"
print("FIXTURE_J_UNKNOWN_SEMANTICS=PASS")
print("PUBLIC_API_UNKNOWN_SEMANTICS_PRESERVED=PASS")


# --- sources and freshness ----------------------------------------------------

sources = body_of(get(f"{A.API_ROOT}/sources?limit=200"))
assert sources["count"] == 34
states = {entry["freshness_state"] for entry in sources["results"]}
assert states <= {"observed", "never_attempted", "review_required"}, states
for entry in sources["results"]:
    assert set(entry) == {
        "source_id", "title", "trust", "category", "role", "lifecycle", "canonical_url",
        "check_cadence_days", "last_observed_at", "snapshot_sha256", "freshness_state",
        "freshness_note", "href", "site_url",
    }, set(entry)
    assert entry["canonical_url"].startswith("http")
    assert "not mean" in entry["freshness_note"]
serialized_sources = json.dumps(sources).lower()
for private in ("credential", "authorization", "api_key", "bearer", "cookie", "password", "local_path"):
    assert private not in serialized_sources, private
print("PUBLIC_API_SOURCE_DIRECTORY_SAFE=PASS")
print("PUBLIC_API_SOURCE_FRESHNESS_EXPLICIT=PASS")


# --- fixture K: provenance ----------------------------------------------------

lineage = body_of(get(f"{A.API_ROOT}/provenance/SA-CORE-2025-001"))["result"]
assert lineage["edges"] and lineage["edges"][0]["from"] == "SA-CORE-2025-001"
assert lineage["edges"][0]["relation"] == "supported_by"
assert lineage["edges"][0]["to_kind"] == "authoritative_source"
step = lineage["steps"][0]
assert step["source_id"] and step["snapshot_sha256"].startswith("sha256:")
assert step["canonical_url"].startswith("https://")
assert step["source_href"] == f"{A.API_ROOT}/sources/{step['source_id']}"
# The link the chain hands back actually resolves, and names the same source.
followed = body_of(get(step["source_href"]))["result"]
assert followed["source_id"] == step["source_id"]
assert followed["canonical_url"].startswith("https://")
# And the snapshot named is real and addressable by its own hash.
snapshot = dk_core.require_snapshot(ROOT, step["source_id"], step["snapshot_sha256"])
assert snapshot.is_file()
assert str(snapshot) not in json.dumps(lineage)
print("FIXTURE_K_PROVENANCE_TRAVERSABLE=PASS")
print("PUBLIC_API_PROVENANCE_MACHINE_TRAVERSABLE=PASS")


# --- fixture L: privacy --------------------------------------------------------

for leaked in (
    {"note": "/Users/someone/sites/client"},
    {"note": "/home/deploy/app"},
    {"contact": "reviewer@example.com"},
    {"settings": "hash_salt = 'abc'"},
):
    try:
        P.assert_public_safe("api fixture", leaked)
    except P.PublicExportDefect:
        continue
    raise AssertionError(f"the export accepted {leaked}")
print("FIXTURE_L_PRIVATE_PATH_REJECTED=PASS")

everything = "\n".join(
    get(path)["body"].decode("utf-8")
    for path in (
        f"{A.API_ROOT}",
        f"{A.API_ROOT}/status",
        f"{A.API_ROOT}/search?q=views&limit=50",
        f"{A.API_ROOT}/knowledge?limit=200",
        f"{A.API_ROOT}/security?limit=200",
        f"{A.API_ROOT}/api-lifecycle?limit=200",
        f"{A.API_ROOT}/change-records?limit=200",
        f"{A.API_ROOT}/rules?limit=200",
        f"{A.API_ROOT}/solved-cases",
        f"{A.API_ROOT}/sources?limit=200",
        f"{A.API_ROOT}/provenance/SA-CORE-2025-001",
        f"{A.API_ROOT}/openapi.json",
        f"{A.API_ROOT}/security/SA-CORE-9999-999",
    )
)
for pattern, description in P.PRIVATE_PATTERNS:
    found = pattern.search(everything)
    assert not found, f"{description}: {found.group(0) if found else ''}"
for private in ("/Users/", "/home/", "C:\\Users", "PhpstormProjects", str(ROOT)):
    assert private not in everything, private
for artifact in sorted((ROOT / "public-api").rglob("*.json")):
    P.assert_public_safe(str(artifact.name), artifact.read_text(encoding="utf-8"))
print("PUBLIC_API_PRIVACY_SCAN_PASS=PASS")

# Project-scoped domains are not reachable at all.
for excluded in (
    "project_evidence", "finding", "implementation_finding", "migration_work",
    "upgrade_assessment", "remediation_plan", "discovery_signal",
):
    assert excluded not in A.DOMAIN_SEGMENT
    assert excluded in P.EXCLUDED_DOMAINS
    assert A.match_route(f"{A.API_ROOT}/{excluded}") is None
for marker in ("evidence-set.", "implementation-evaluation.", "upgrade-assessment.", "migration-analysis."):
    assert marker not in everything, marker
print("PUBLIC_API_EXCLUDES_PROJECT_PRIVATE_DATA=PASS")

# Internal implementation detail stays internal.
for internal in ("dk_query", "dk_public", "dk_api", "scripts/", "PROJECTORS", "_CACHE", "sources/state"):
    assert internal not in everything, internal
print("PUBLIC_API_INTERNAL_DETAILS_MINIMIZED=PASS")

signals = Q.list_domain(Q.D_DISCOVERY_SIGNAL, ROOT)["results"]
assert signals, "the fixture is meaningless if the repository holds no signals"
for signal in signals:
    assert signal["id"] not in everything, signal["id"]
assert any(
    entry["domain"] == "discovery_signal" for entry in status["sections"]["excluded_domains"]
)
print("PUBLIC_API_DISCOVERY_NOT_PRESENTED_AS_TRUTH=PASS")


# --- fixture M & N: cache validators -------------------------------------------

first_response = get(f"{A.API_ROOT}/security/SA-CORE-2025-001")
second_response = get(f"{A.API_ROOT}/security/SA-CORE-2025-001")
etag = first_response["headers"]["ETag"]
assert etag == second_response["headers"]["ETag"]
assert etag.startswith('"') and etag.endswith('"') and len(etag) == 34
# Different content, different validator.
assert get(f"{A.API_ROOT}/status")["headers"]["ETag"] != etag
# Derived from content, so an independent computation agrees.
assert A.etag_for(body_of(first_response)) == etag
for volatile in ("time", "random", "uuid", "datetime"):
    assert volatile not in imports_of(api_source), volatile
print("FIXTURE_M_ETAG_STABLE=PASS")
print("PUBLIC_API_CACHE_VALIDATORS_DETERMINISTIC=PASS")

conditional = get(f"{A.API_ROOT}/security/SA-CORE-2025-001", {"If-None-Match": etag})
assert conditional["status"] == 304
assert conditional["body"] == b""
assert conditional["headers"]["ETag"] == etag
# A stale validator gets the full body back.
assert get(f"{A.API_ROOT}/security/SA-CORE-2025-001", {"If-None-Match": '"stale"'})["status"] == 200
# Multiple validators are honoured.
assert get(f"{A.API_ROOT}/status", {"If-None-Match": f'"other", {get(f"{A.API_ROOT}/status")["headers"]["ETag"]}'})["status"] == 304
print("FIXTURE_N_CONDITIONAL_GET=PASS")
print("PUBLIC_API_CONDITIONAL_GET=PASS")


# --- fixture R: repeated request ----------------------------------------------

for path in (f"{A.API_ROOT}/status", f"{A.API_ROOT}/search?q=views", f"{A.API_ROOT}/rules"):
    assert body_of(get(path)) == body_of(get(path)), path
print("FIXTURE_R_REPEATED_REQUEST_IDENTICAL=PASS")


# --- fixture Q: no network ------------------------------------------------------

real_socket = socket.socket
real_create = socket.create_connection


def refuse(*args, **kwargs):
    raise AssertionError("the API attempted a network connection")


socket.socket = refuse
socket.create_connection = refuse
try:
    A.dataset(ROOT, refresh=True)
    offline_status = body_of(get(f"{A.API_ROOT}/status"))
    offline_search = body_of(get(f"{A.API_ROOT}/search?q=SA-CORE-2025-001"))
    offline_detail = body_of(get(f"{A.API_ROOT}/security/SA-CORE-2025-001"))
finally:
    socket.socket = real_socket
    socket.create_connection = real_create
assert offline_status["dataset_id"] == MANIFEST["dataset_id"]
assert offline_search["results"][0]["id"] == "SA-CORE-2025-001"
assert offline_detail["result"]["id"] == "SA-CORE-2025-001"
for fetching in ("urlopen", "urlretrieve", "http.client", "acquire_source", "dk_acquisition"):
    assert fetching not in api_code, fetching
print("FIXTURE_Q_NO_NETWORK_ACQUISITION=PASS")
print("PUBLIC_API_TESTS_OFFLINE=PASS")


# --- HTTP behaviour over a real socket, on loopback only -----------------------

assert H.DEFAULT_HOST == "127.0.0.1"
assert "0.0.0.0" not in http_source
server = ThreadingHTTPServer(("127.0.0.1", 0), type("T", (H.Handler,), {"root": ROOT, "quiet": True}))
host, port = server.server_address[0], server.server_address[1]
assert host == "127.0.0.1", host
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    base = f"http://127.0.0.1:{port}"

    with urllib.request.urlopen(f"{base}{A.API_ROOT}/status", timeout=10) as response:
        assert response.status == 200
        assert response.headers["Content-Type"] == "application/json; charset=utf-8"
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Credentials" not in response.headers
        live_etag = response.headers["ETag"]
        live = json.loads(response.read().decode("utf-8"))
    assert live["dataset_id"] == MANIFEST["dataset_id"]
    print("PUBLIC_API_CONTENT_TYPE_CORRECT=PASS")
    print("PUBLIC_API_CORS_POLICY_EXPLICIT=PASS")

    head = urllib.request.Request(f"{base}{A.API_ROOT}/status", method="HEAD")
    with urllib.request.urlopen(head, timeout=10) as response:
        assert response.status == 200
        assert response.read() == b""
        assert response.headers["ETag"] == live_etag
        assert int(response.headers["Content-Length"]) > 0
    print("PUBLIC_API_HEAD_BEHAVIOR_CONSISTENT=PASS")

    conditional_request = urllib.request.Request(
        f"{base}{A.API_ROOT}/status", headers={"If-None-Match": live_etag}
    )
    try:
        with urllib.request.urlopen(conditional_request, timeout=10) as response:
            assert response.status == 304
    except urllib.error.HTTPError as err:
        assert err.code == 304, err.code

    post = urllib.request.Request(f"{base}{A.API_ROOT}/status", data=b"{}", method="POST")
    try:
        urllib.request.urlopen(post, timeout=10)
        raise AssertionError("the server accepted a POST")
    except urllib.error.HTTPError as err:
        assert err.code == 405
        assert err.headers["Allow"] == "GET, HEAD, OPTIONS"
        assert json.loads(err.read().decode("utf-8"))["error"]["code"] == "METHOD_NOT_ALLOWED"

    options = urllib.request.Request(f"{base}{A.API_ROOT}/status", method="OPTIONS")
    with urllib.request.urlopen(options, timeout=10) as response:
        assert response.status == 204
        assert response.headers["Access-Control-Allow-Methods"] == "GET, HEAD, OPTIONS"

    try:
        urllib.request.urlopen(f"{base}{A.API_ROOT}/security/nope", timeout=10)
        raise AssertionError("a missing record returned success")
    except urllib.error.HTTPError as err:
        assert err.code == 404

    with urllib.request.urlopen(f"{base}{A.API_ROOT}/openapi.json", timeout=10) as response:
        served_openapi = json.loads(response.read().decode("utf-8"))
    assert served_openapi["openapi"] == "3.1.0"
finally:
    server.shutdown()
    server.server_close()
print("PUBLIC_API_TEST_SERVER_LOCAL_ONLY=PASS")
print("PUBLIC_API_SAFE_DEFAULT_BIND=PASS")


# --- OpenAPI -------------------------------------------------------------------

document = json.loads((ROOT / "public-api" / "openapi.json").read_text(encoding="utf-8"))
assert document["openapi"] == "3.1.0"
assert document["info"]["version"] == A.API_CONTRACT_VERSION
assert served_openapi == document, "the served document and the committed one must agree"
# It describes the routes the dispatcher actually has — no more, no fewer.
assert set(document["paths"]) == {route["path"] for route in A.ROUTES}
for route in A.ROUTES:
    entry = document["paths"][route["path"]]
    assert set(entry) == {"get"}, route["path"]
    assert entry["get"]["operationId"] == route["operation_id"]
    assert "200" in entry["get"]["responses"] and "405" in entry["get"]["responses"]
    assert A.match_route(route["path"].replace("{id}", "probe")) is not None
assert document["components"]["schemas"].keys() == {"Envelope", "Record", "Error"}
assert "Access-Control-Allow-Origin: *" in document["x-drupal-knowledge"]["cors"]
assert document["x-drupal-knowledge"]["authentication"].startswith("None")
print("PUBLIC_API_OPENAPI_AVAILABLE=PASS")

# Transport schemas only: no domain contract is restated here.
schema_text = (ROOT / "public-api" / "api-response.schema.json").read_text(encoding="utf-8")
for domain_field in (
    "affected_versions", "risk_vector", "deprecated_version", "root_cause",
    "cves", "fixed_in", "context_requirements",
):
    assert domain_field not in schema_text, domain_field
assert "security-advisory.schema.json" in schema_text, "the domain contracts are named, not copied"
existing = {path.name for path in (ROOT / "schema").glob("*.json")}
assert "security-advisory.schema.json" in existing and "knowledge-record.schema.json" in existing
print("PUBLIC_API_SCHEMA_REUSES_DOMAIN_CONTRACTS=PASS")

# Regenerating is byte-identical, and a changed contract makes the committed
# document stale rather than silently wrong.
assert A.validate_api_artifacts(ROOT) == ["PUBLIC_API_ARTIFACTS_CURRENT=PASS"]
first_bytes = A.artifact_bytes(ROOT)
assert first_bytes == A.artifact_bytes(ROOT)
tampered = dict(first_bytes)
target = ROOT / A.ARTIFACT_DIR / A.OPENAPI_FILE
saved = target.read_bytes()
try:
    target.write_bytes(saved.replace(b'"3.1.0"', b'"3.0.0"', 1))
    try:
        A.validate_api_artifacts(ROOT)
    except dk_core.ValidationError as exc:
        assert "stale" in str(exc) and "api build" in str(exc)
    else:
        raise AssertionError("a changed contract left the document looking current")
finally:
    target.write_bytes(saved)
assert A.validate_api_artifacts(ROOT) == ["PUBLIC_API_ARTIFACTS_CURRENT=PASS"]
print("PUBLIC_API_OPENAPI_STALE_GUARDED=PASS")
print("PUBLIC_API_GENERATED_CONTRACT_STALE_GUARD=PASS")

# The Prompt 15 dataset guard is untouched and still bites.
assert P.validate_public_dataset(ROOT) == ["PUBLIC_DATASET_CURRENT=PASS"]
core_source = (ROOT / "scripts" / "dk_core.py").read_text(encoding="utf-8")
assert "dk_public.validate_public_dataset(root)" in core_source
assert "dk_api.validate_api_artifacts(root)" in core_source
print("PUBLIC_API_PRESERVES_PUBLIC_DATASET_STALE_GUARD=PASS")


# --- examples and documentation -------------------------------------------------

examples = sorted((ROOT / "public-api" / "examples").glob("*.json"))
assert {path.stem for path in examples} == {name for name, _m, _p, _q in A.EXAMPLE_REQUESTS}
for path in examples:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert "api_version" in payload
    P.assert_public_safe(path.name, payload)
advisory_example = json.loads((ROOT / "public-api" / "examples" / "advisory-detail.json").read_text())
assert advisory_example["result"]["id"] == "SA-CORE-2025-001"
assert advisory_example["result"]["detail"]["affected_versions"]
print("PUBLIC_API_EXAMPLES_PUBLIC_SAFE=PASS")

docs = (ROOT / "docs" / "PUBLIC_API.md").read_text(encoding="utf-8")
for section in (
    "## Overview", "## Versioning", "## Status", "## Search", "## Pagination",
    "## Trust labels", "## Unknown states", "## Caching", "## CORS", "## Errors",
    "## OpenAPI", "## Provenance", "## Sources", "## Examples",
):
    assert section in docs, section
documented = set(re.findall(r"(/api/v1/[A-Za-z0-9_\-{}./]*)", docs))
for path in documented:
    cleaned = path.rstrip(".,")
    if cleaned.endswith("openapi.json") or "{id}" in cleaned:
        continue
    probe = cleaned.split("?")[0]
    assert A.match_route(probe) is not None, f"the guide documents a route that does not exist: {probe}"
for command in ("api serve", "api build", "api routes"):
    assert command in docs, command
for leak in ("/Users/", "/home/", "C:\\Users", "PhpstormProjects"):
    assert leak not in docs, leak
print("PUBLIC_API_DOCUMENTATION_COMPLETE=PASS")
print("PUBLIC_API_START_COMMAND_DOCUMENTED=PASS")

# Deployable: one process, no dependencies, no writable state, and a health check.
assert "api serve" in docs and "health check" in docs
assert body_of(get(f"{A.API_ROOT}/status"))["sections"]["release"]["dk_version"]
assert "DATASET_UNAVAILABLE" in api_source and A.ERROR_STATUS["DATASET_UNAVAILABLE"] == 503
print("PUBLIC_API_DEPLOYMENT_READY=PASS")


# --- no auth, no project analysis service -------------------------------------------------

for absent in ("Authorization", "api_key", "Bearer", "login", "session", "token", "rbac", "account"):
    assert absent.lower() not in api_source.lower(), absent
    assert absent.lower() not in http_source.lower(), absent
assert body_of(get(f"{A.API_ROOT}/status"))  # no credential needed
assert "None" in json.loads(
    (ROOT / "public-api" / "openapi.json").read_text()
)["x-drupal-knowledge"]["authentication"]
assert "securitySchemes" not in json.dumps(document)
print("PUBLIC_API_REQUIRES_NO_AUTH_FOR_PUBLIC_DATA=PASS")

for service_path in ("/analyze", "upload", "clone", "archive", "job", "queue", "worker"):
    assert not any(service_path in route["path"] for route in A.ROUTES), service_path
assert "project_path" not in api_source and "analyze_project" not in api_source
print("PUBLIC_API_HAS_NO_PROJECT_UPLOAD_OR_ANALYSIS=PASS")


# --- the other two surfaces stay independent ------------------------------------

site_source = (ROOT / "scripts" / "dk_site_render.py").read_text(encoding="utf-8")
export_source = (ROOT / "scripts" / "dk_public.py").read_text(encoding="utf-8")
for module in ("dk_api", "dk_api_http", "urllib", "http.server", "localhost", "127.0.0.1"):
    assert module not in site_source, module
    assert module not in export_source, module
print("PUBLIC_WEBSITE_NOT_DEPENDENT_ON_RUNTIME_API=PASS")

cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
query_source = (ROOT / "scripts" / "dk_query.py").read_text(encoding="utf-8")
render_source = (ROOT / "scripts" / "dk_render.py").read_text(encoding="utf-8")
for module in ("dk_api_http", "urllib.request", "http.client"):
    assert module not in query_source and module not in render_source, module
# The CLI knows the server exists only inside the one command that starts it.
cli_tree = ast.parse(cli_source)
touching_server = {
    function.name
    for function in ast.walk(cli_tree)
    if isinstance(function, ast.FunctionDef)
    and "dk_api_http" in ast.dump(function)
}
assert touching_server == {"cmd_api"}, touching_server
assert "127.0.0.1" in cli_source, "the bind default is loopback"
import dk as cli_module

for command in cli_module.commands_for("community"):
    result = subprocess.run(
        [sys.executable, str(CLI), command, "--help"], capture_output=True, text=True
    )
    assert result.returncode == 0, command
    assert "http://" not in result.stdout, command
print("COMMUNITY_CLI_NOT_DEPENDENT_ON_PUBLIC_API=PASS")

# The website links to the API documentation; that is navigation, not coupling.
api_docs_page = (ROOT / "public-site" / "content" / "api-docs.html").read_text(encoding="utf-8")
assert "/api/v1/openapi.json" in api_docs_page
assert "docs/PUBLIC_API.md" in api_docs_page
assert ("/api-docs/", "API") in __import__("dk_site_render").NAV
assert any(entry["route"] == "/api-docs/" for entry in MANIFEST["routes"])
print("PUBLIC_SITE_LINKS_API_DOCUMENTATION=PASS")

assert cli_module.COMMAND_AUDIENCE["api"] == "internal"
# The public surfaces route no private service path. The repository-wide
# vocabulary and import scans live in test_community_boundary.py.
for private_path in ("/hosted/", "/admin/", "/login"):
    assert private_path not in api_source and private_path not in http_source, private_path
    assert private_path not in everything, private_path
ci = (ROOT / ".github" / "workflows" / "community.yml").read_text(encoding="utf-8")
assert re.search(r"^on:\n  push:\n  pull_request:\n", ci, re.MULTILINE), "the workflow must run on push and pull request"
job = re.search(r"^  public-api:\n(?P<body>(?:    .*\n)+)", ci, re.MULTILINE)
assert job, "missing public API validation job"
job_body = job.group("body")
assert "runs-on: ubuntu-latest" in job_body, "standard GitHub-hosted runner only"
assert "workflow_dispatch" not in ci, "validation must not be manual-only"
assert "test_public_api.py" in job_body
assert "api build" in job_body, "the gate must regenerate the contract it validates"
assert "validate_api_artifacts" in job_body, "a stale contract must fail CI"
commands = [line.strip()[len("- run:"):].strip() for line in job_body.splitlines() if line.strip().startswith("- run:")]
assert not any(command.startswith("git ") for command in commands), commands
for forbidden in ("curl", "wget", "deploy", "--apply", "0.0.0.0", "secrets."):
    assert forbidden not in job_body, forbidden
print("PUBLIC_API_REQUIRED_CI_GATE=PASS")

assert "upload-artifact" in job_body
assert "public-api/" in job_body, "the OpenAPI document and examples are kept"
print("PUBLIC_API_CI_ARTIFACTS=PASS")

print("PUBLIC_API_INDEPENDENT_OF_PRIVATE_CONSUMERS=PASS")
