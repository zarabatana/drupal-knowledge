#!/usr/bin/env python3
"""HTTP for the Public Knowledge API, and nothing else.

This module moves bytes. It parses a path and a query string, asks
``dk_api.handle`` what the answer is, and turns the result into a status line,
some headers and a body. It contains no knowledge of Drupal, no trust
reasoning, no record lookup and no ranking — if a question about Drupal can be
answered here, the layering has already failed.

The standard library is the whole dependency. A public read-only JSON API over
an immutable dataset does not need a framework, and every dependency added to
this repository is one more thing a reader has to trust before they can trust a
security advisory.

Three transport decisions worth stating out loud:

**CORS is open, deliberately.** Everything served is public-safe and read-only,
the intended consumers include browser tooling, and no endpoint accepts
credentials. ``Access-Control-Allow-Origin: *`` with no
``Allow-Credentials`` is the honest expression of that.

**Validators are content-derived.** The ETag is a hash of the response body, so
the same dataset and the same request produce the same validator across
restarts and across machines. A random or time-based ETag would make every
cache miss on every deploy.

**The default bind is loopback.** A development server that listens on every
interface by default is a mistake waiting for a laptop on a conference network.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import dk_api as api
import dk_core


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8088

JSON_CONTENT_TYPE = "application/json; charset=utf-8"

# Read-only, public, no credentials. Stated here rather than configured, so a
# reader of this file knows exactly what the policy is.
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "If-None-Match",
    "Access-Control-Expose-Headers": "ETag",
    "Access-Control-Max-Age": "86400",
}

MUTATION_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def encode(payload: dict) -> bytes:
    """Deterministic bytes, so the validator over them is deterministic too."""
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def respond(method: str, path: str, headers: dict, root: Path = dk_core.ROOT) -> dict:
    """One request, resolved to everything a transport needs.

    Returned rather than written, so the whole HTTP contract — statuses,
    validators, CORS, conditional requests — is testable without a socket.
    """
    method = method.upper()
    split = urlsplit(path)
    params = parse_qs(split.query, keep_blank_values=True)

    if method == "OPTIONS":
        return {
            "status": 204,
            "headers": {**CORS_HEADERS, "Allow": "GET, HEAD, OPTIONS"},
            "body": b"",
        }

    try:
        status, payload = api.handle(method, split.path, params, root)
    except api.ApiError as err:
        payload = api.error_payload(err, root)
        response = {
            "status": err.status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": JSON_CONTENT_TYPE,
                # Refusals are about this request, not about the dataset, so
                # they are not cached.
                "Cache-Control": "no-store",
            },
            "body": encode(payload),
        }
        if err.code == "METHOD_NOT_ALLOWED":
            response["headers"]["Allow"] = "GET, HEAD, OPTIONS"
        return response
    except Exception as exc:  # pragma: no cover - defect path
        # A defect is reported as a defect. What went wrong internally is not a
        # consumer's business and is never described in the body.
        defect = api.ApiError("INTERNAL_ERROR", "The API failed to produce a response.")
        _ = exc
        return {
            "status": defect.status,
            "headers": {**CORS_HEADERS, "Content-Type": JSON_CONTENT_TYPE, "Cache-Control": "no-store"},
            "body": encode(api.error_payload(defect, root)),
        }

    body = encode(payload)
    etag = api.etag_for(payload)
    response_headers = {
        **CORS_HEADERS,
        "Content-Type": JSON_CONTENT_TYPE,
        "ETag": etag,
        # A dataset is immutable for a given identity, but a deployment can be
        # replaced, so this is a revalidation hint rather than a promise.
        "Cache-Control": "public, max-age=300, must-revalidate",
        "X-Content-Type-Options": "nosniff",
    }

    if_none_match = headers.get("If-None-Match") or headers.get("if-none-match")
    if if_none_match and etag in [tag.strip() for tag in if_none_match.split(",")]:
        return {"status": 304, "headers": response_headers, "body": b""}

    # HEAD carries the same headers as GET, including the length the body would
    # have had, and no body.
    response_headers["Content-Length"] = str(len(body))
    return {
        "status": status,
        "headers": response_headers,
        "body": b"" if method == "HEAD" else body,
    }


class Handler(BaseHTTPRequestHandler):
    """Thin glue. Every branch here is about HTTP, never about Drupal."""

    server_version = "DrupalKnowledgePublicAPI/1"
    sys_version = ""
    root = dk_core.ROOT
    quiet = False

    def _drain_request_body(self) -> None:
        """Read and discard whatever body the client sent, bounded.

        The API ignores request bodies, but the socket does not: answering —
        especially refusing — while unread bytes sit in the client's send
        buffer makes the kernel reset the connection under the response,
        and the client sees ECONNRESET instead of the 405 it was owed.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        remaining = min(length, 1024 * 1024)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

    def _send(self, resolved: dict) -> None:
        self._drain_request_body()
        self.send_response(resolved["status"])
        for name, value in sorted(resolved["headers"].items()):
            self.send_header(name, value)
        self.end_headers()
        if resolved["body"]:
            self.wfile.write(resolved["body"])

    def do_GET(self) -> None:
        self._send(respond("GET", self.path, dict(self.headers), self.root))

    def do_HEAD(self) -> None:
        self._send(respond("HEAD", self.path, dict(self.headers), self.root))

    def do_OPTIONS(self) -> None:
        self._send(respond("OPTIONS", self.path, dict(self.headers), self.root))

    def _refuse_mutation(self) -> None:
        self._send(respond(self.command, self.path, dict(self.headers), self.root))

    do_POST = _refuse_mutation
    do_PUT = _refuse_mutation
    do_PATCH = _refuse_mutation
    do_DELETE = _refuse_mutation

    def log_message(self, fmt: str, *args) -> None:  # pragma: no cover - I/O
        if not self.quiet:
            super().log_message(fmt, *args)


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    root: Path = dk_core.ROOT,
    quiet: bool = False,
) -> None:  # pragma: no cover - long-running
    handler = type("BoundHandler", (Handler,), {"root": root, "quiet": quiet})
    with ThreadingHTTPServer((host, port), handler) as server:
        print(f"Drupal Knowledge Public Knowledge API on http://{host}:{port}{api.API_ROOT}")
        print(f"  status   http://{host}:{port}{api.API_ROOT}/status")
        print(f"  openapi  http://{host}:{port}{api.API_ROOT}/openapi.json")
        print("  read-only: GET, HEAD and OPTIONS only. Ctrl-C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print()
