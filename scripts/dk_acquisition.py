#!/usr/bin/env python3
"""Knowledge acquisition engine for registered authoritative sources.

The engine is one orchestration layer over the source architecture that
Drupal Knowledge already had: the registry in ``sources/registry.json``, the
content-addressed snapshot tree under ``sources/snapshots/``, the per-source
state under ``sources/state/``, and the review candidates under
``discovery/candidates/``. It creates no second registry, no second snapshot
tree and no second trust taxonomy.

The invariant it exists to protect:

    SOURCE CHANGE != TRUSTED KNOWLEDGE CHANGE

A newly acquired snapshot is an ``observed_source_snapshot``. It is never
``reviewed_trusted_knowledge``, no matter how authoritative the source is. The
engine writes source state, immutable snapshots and review candidates. It never
writes ``knowledge/``, and every canonical mutation path asserts the trusted
knowledge digest is unchanged before and after.

Failure classes stay separate on purpose:

- ``external_source_unavailable``  the source could not be reached;
- ``source_contract_failure``      the source answered but broke its contract;
- ``acquisition_engine_defect``    our own bug, never blamed on the source.

None of them may ever be reported as ``unchanged``.
"""

from __future__ import annotations

import difflib
import hashlib
import http.client
import re
import socket
import urllib.error
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import dk_core


ENGINE_NAME = "drupal-knowledge-acquisition-engine"
ENGINE_VERSION = "0.1"
ACQUISITION_RUN_SCHEMA_VERSION = "0.1"

# The provenance channel of everything this engine produces. Internal proven
# solved cases arrive through a different channel with different provenance and
# the two must never be conflated.
ACQUISITION_CHANNEL = "external_authoritative_source"

USER_AGENT = (
    "Drupal-Knowledge/1.0 "
    "(+https://github.com/zarabatana/drupal-knowledge)"
)
ACCEPT_HEADER = (
    "text/html,application/xhtml+xml,application/xml,text/plain;q=0.9,*/*;q=0.8"
)

MAX_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 20

# Change detection outcomes. These are the only values a source may end an
# acquisition attempt with.
STATUS_FIRST_OBSERVATION = "first_observation"
STATUS_UNCHANGED = "unchanged"
STATUS_CHANGED = "changed"
STATUS_UNAVAILABLE = "unavailable"
STATUS_INVALID_OR_MALFORMED = "invalid_or_malformed"

ACQUISITION_STATUSES = (
    STATUS_FIRST_OBSERVATION,
    STATUS_UNCHANGED,
    STATUS_CHANGED,
    STATUS_UNAVAILABLE,
    STATUS_INVALID_OR_MALFORMED,
)

SUCCESS_STATUSES = frozenset(
    {STATUS_FIRST_OBSERVATION, STATUS_UNCHANGED, STATUS_CHANGED}
)
FAILURE_STATUSES = frozenset({STATUS_UNAVAILABLE, STATUS_INVALID_OR_MALFORMED})

# The legacy collector vocabulary, preserved so existing output and tooling
# keep working while the engine speaks a more precise language internally.
LEGACY_STATUS_WORDS = {
    STATUS_FIRST_OBSERVATION: "BASELINE",
    STATUS_UNCHANGED: "UNCHANGED",
    STATUS_CHANGED: "CHANGED",
}

ERROR_EXTERNAL = "external_source_unavailable"
ERROR_CONTRACT = "source_contract_failure"
ERROR_ENGINE_DEFECT = "acquisition_engine_defect"

# Review lifecycle. A candidate says "something changed and a human must look",
# never "Drupal Knowledge should change in this way".
REVIEW_PENDING = "pending_review"
REVIEW_NO_KNOWLEDGE_CHANGE = "reviewed_no_knowledge_change"
REVIEW_REQUIRES_PROPOSAL = "reviewed_requires_knowledge_proposal"
REVIEW_DISMISSED_NON_SEMANTIC = "dismissed_as_non_semantic"

REVIEW_STATES = (
    REVIEW_PENDING,
    REVIEW_NO_KNOWLEDGE_CHANGE,
    REVIEW_REQUIRES_PROPOSAL,
    REVIEW_DISMISSED_NON_SEMANTIC,
)
REVIEW_TERMINAL_STATES = frozenset(
    {REVIEW_NO_KNOWLEDGE_CHANGE, REVIEW_REQUIRES_PROPOSAL, REVIEW_DISMISSED_NON_SEMANTIC}
)

# Legacy coarse status kept in the candidate for the published schema.
REVIEW_STATE_TO_LEGACY_STATUS = {
    REVIEW_PENDING: "review_required",
    REVIEW_NO_KNOWLEDGE_CHANGE: "reviewed",
    REVIEW_REQUIRES_PROPOSAL: "reviewed",
    REVIEW_DISMISSED_NON_SEMANTIC: "rejected",
}

REVIEW_METHODS = {
    "human_source_diff_review",
    "human_editorial_review",
    "human_security_review",
}

NORMALIZATION_AUTO = "auto"
NORMALIZATION_HTML_TEXT = "html_text"
NORMALIZATION_RAW_TEXT = "raw_text"
NORMALIZATION_STRATEGIES = (
    NORMALIZATION_AUTO,
    NORMALIZATION_HTML_TEXT,
    NORMALIZATION_RAW_TEXT,
)

CONTENT_TYPE_FAMILIES = ("html", "xml", "json", "text", "auto")

SOURCE_LIFECYCLE_ACTIVE = "active"
SOURCE_LIFECYCLE_RETIRED = "retired"
SOURCE_LIFECYCLE_SUPERSEDED = "superseded"
SOURCE_LIFECYCLES = (
    SOURCE_LIFECYCLE_ACTIVE,
    SOURCE_LIFECYCLE_RETIRED,
    SOURCE_LIFECYCLE_SUPERSEDED,
)

# Provenance is an allow-list, not a dump of whatever the transport saw. No
# request headers, no cookies, no tokens, no local machine paths.
PROVENANCE_FIELDS = (
    "acquisition_channel",
    "canonical_url",
    "fetch_url",
    "trust",
    "category",
    "http_status",
    "content_type",
    "etag",
    "last_modified",
    "normalization",
    "content_window",
    "content_length",
    "acquired_at",
    "acquired_by",
)

PROVENANCE_FORBIDDEN_SUBSTRINGS = (
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "secret",
    "password",
    "credential",
    "api_key",
    "apikey",
    "bearer",
    "session",
    "env",
    "local_path",
    "home",
)

# Local machine paths must never reach a shared artifact. Transport errors
# routinely quote them, so they are redacted before anything is persisted.
MACHINE_PATH_RE = re.compile(
    r"(?<![\w/])/(?:Users|home|root|builds|tmp|var/tmp|var/folders|private/var)/\S*"
)
REDACTED_LOCAL_PATH = "<redacted-local-path>"
CREDENTIAL_IN_URL_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")

CANDIDATE_ID_RE = re.compile(r"^source-change\.[a-z0-9]+(?:-[a-z0-9]+)*\.[a-f0-9]{16}$")

CANDIDATES_RELATIVE_PATH = Path("discovery") / "candidates"
STATE_RELATIVE_PATH = Path("sources") / "state"

CHANGE_SUMMARY_SAMPLE_LIMIT = 5
CHANGE_SUMMARY_SAMPLE_WIDTH = 160


class AcquisitionInputError(RuntimeError):
    """Raised when acquisition input cannot be resolved."""


class AcquisitionError(RuntimeError):
    """Base class for acquisition attempt failures attributable to a source."""

    error_class = ERROR_CONTRACT
    code = "acquisition_failed"


class SourceUnavailableError(AcquisitionError):
    """The registered source could not be reached or answered with an error.

    This is an expected external failure. It preserves the last known snapshot
    and never becomes ``unchanged``.
    """

    error_class = ERROR_EXTERNAL
    code = "source_unavailable"


class SourceContractError(AcquisitionError):
    """The source answered but broke the contract the registry declares."""

    error_class = ERROR_CONTRACT
    code = "source_contract_failure"


class ContentWindowError(SourceContractError):
    """A configured stable content window was not found in the response."""

    code = "content_window_missing"


class AcquisitionEngineDefect(RuntimeError):
    """Our own defect.

    Never converted into a source availability or source contract failure. A
    programming error in the engine is an engine problem, not evidence about
    Drupal.
    """


def now_iso(moment: datetime | None = None) -> str:
    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_iso(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


# ---------------------------------------------------------------------------
# Deterministic normalization
# ---------------------------------------------------------------------------


class VisibleText(HTMLParser):
    """Extract visible text, dropping script/style/noscript/svg content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self._skip += 1

    def handle_endtag(self, tag) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self._skip:
            self._skip -= 1

    def handle_data(self, data) -> None:
        if self._skip:
            return
        text = re.sub(r"\s+", " ", data).strip()
        if text:
            self._parts.append(text)

    @property
    def text(self) -> str:
        return "\n".join(self._parts)


def normalization_strategy(source: dict) -> str:
    strategy = source.get("normalization", NORMALIZATION_AUTO)
    if strategy not in NORMALIZATION_STRATEGIES:
        raise AcquisitionInputError(
            f"source {source.get('id')!r}: unsupported normalization {strategy!r}"
        )
    return strategy


def content_type_family(header: str | None) -> str | None:
    """Map a Content-Type header onto a coarse family, or None if unknown."""
    if not header:
        return None
    value = header.split(";")[0].strip().lower()
    if not value:
        return None
    if value in {"text/html", "application/xhtml+xml"}:
        return "html"
    if value in {"text/xml", "application/xml"} or value.endswith("+xml"):
        return "xml"
    if value in {"application/json", "text/json"} or value.endswith("+json"):
        return "json"
    if value.startswith("text/"):
        return "text"
    return None


def looks_like_html(text: str, content_type: str | None) -> bool:
    return "html" in (content_type or "").lower() or "<html" in text[:1000].lower()


def apply_content_window(text: str, source: dict) -> str:
    """Restrict normalized text to the configured stable window.

    Windows are declared per source in the registry. They exist so page chrome,
    generated navigation and footer timestamps cannot look like a semantic
    change. A configured marker that is missing is a source contract failure,
    never silently ignored and never hashed as empty content.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    start = source.get("content_start")
    end = source.get("content_end")
    if start:
        try:
            start_index = lines.index(start)
        except ValueError as exc:
            raise ContentWindowError(f"content_start marker not found: {start!r}") from exc
        lines = lines[start_index:]
    if end:
        try:
            end_index = lines.index(end)
        except ValueError as exc:
            raise ContentWindowError(f"content_end marker not found: {end!r}") from exc
        lines = lines[:end_index]
    if not lines:
        raise ContentWindowError("content window produced empty normalized text")
    return "\n".join(lines)


def normalized_text(raw: bytes, content_type: str | None, source: dict) -> str:
    """Normalize raw source bytes deterministically.

    The same bytes and the same registry configuration always produce the same
    normalized text, and therefore the same snapshot identity. Normalization
    removes transport noise and configured page chrome. It does not remove
    meaningful semantic differences.
    """
    text = raw.decode("utf-8", errors="replace")
    strategy = normalization_strategy(source)
    if strategy == NORMALIZATION_HTML_TEXT or (
        strategy == NORMALIZATION_AUTO and looks_like_html(text, content_type)
    ):
        parser = VisibleText()
        parser.feed(text)
        text = parser.text
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    if source.get("content_start") or source.get("content_end"):
        text = apply_content_window(text, source)
    if not text:
        raise SourceContractError("normalized source content is empty")
    return text


# ---------------------------------------------------------------------------
# Fetch with explicit failure classification
# ---------------------------------------------------------------------------


def assert_safe_fetch_url(url: str) -> None:
    """Reject fetch URLs that would drag credentials into provenance."""
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise SourceContractError("fetch url must not carry credentials")


def fetch_source(source: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fetch and normalize one registered source.

    Transport failures raise :class:`SourceUnavailableError`. Contract failures
    raise :class:`SourceContractError`. Anything else propagates untouched so an
    engine defect can never be filed as a source failure.
    """
    fetch_url = source.get("fetch_url") or source["url"]
    assert_safe_fetch_url(fetch_url)
    request = Request(
        fetch_url,
        headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_BYTES + 1)
            headers = response.headers
            http_status = getattr(response, "status", None)
    except urllib.error.HTTPError as exc:
        raise SourceUnavailableError(f"HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise SourceUnavailableError(f"transport failure: {exc.reason}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise SourceUnavailableError("request timed out") from exc
    except (http.client.HTTPException, ConnectionError, OSError) as exc:
        raise SourceUnavailableError(f"transport failure: {exc}") from exc

    if len(raw) > MAX_BYTES:
        raise SourceContractError("response exceeds 8 MiB safety limit")

    content_type = headers.get("Content-Type")
    expected = source.get("expected_content_type")
    if expected and expected != "auto":
        observed = content_type_family(content_type)
        if observed is not None and observed != expected:
            raise SourceContractError(
                f"expected {expected} content, source returned {observed}"
            )

    text = normalized_text(raw, content_type, source)
    return {
        "content_sha256": dk_core.content_digest(text),
        "content_length": len(text.encode("utf-8")),
        "normalized_text": text,
        "etag": headers.get("ETag"),
        "last_modified": headers.get("Last-Modified"),
        "content_type": content_type,
        "http_status": http_status,
        "fetch_url": fetch_url,
    }


# ---------------------------------------------------------------------------
# Registry-driven selection
# ---------------------------------------------------------------------------


PROTECTED_RELATIVE_PATHS = (
    Path("sources") / "state",
    Path("sources") / "snapshots",
    Path("discovery") / "candidates",
    Path("knowledge"),
    Path("cases"),
)


def resolve_writable_output(root: Path, value: str, label: str) -> Path:
    """Resolve an operator-supplied output path outside canonical directories.

    Inspection output and run reports are debugging aids. They must never be
    able to land inside the trees that hold canonical evidence.
    """
    output = Path(value)
    if not output.is_absolute():
        output = root / output
    output = output.resolve()
    for relative in PROTECTED_RELATIVE_PATHS:
        protected = (root / relative).resolve()
        if output == protected or output.is_relative_to(protected):
            raise dk_core.ValidationError(
                f"{label} cannot write under {relative.as_posix()}"
            )
    return output


def source_lifecycle(source: dict) -> str:
    return source.get("lifecycle", SOURCE_LIFECYCLE_ACTIVE)


def check_cadence_days(source: dict) -> int | None:
    value = source.get("check_cadence_days")
    return value if isinstance(value, int) else None


def load_registry(root: Path) -> list[dict]:
    return dk_core.load_sources(root)


def state_path(root: Path, source_id: str) -> Path:
    if not dk_core.SOURCE_ID_RE.fullmatch(source_id):
        raise AcquisitionInputError(f"invalid source id: {source_id!r}")
    return root / STATE_RELATIVE_PATH / f"{source_id}.json"


def load_state(root: Path, source_id: str) -> dict | None:
    path = state_path(root, source_id)
    if not path.is_file():
        return None
    return dk_core.read_json(path)


def last_success_at(state: dict | None) -> str | None:
    """Best available evidence of the last successful acquisition.

    State written before this engine existed has no acquisition block. For those
    sources the last recorded content change is used as a conservative lower
    bound: it is a moment at which acquisition definitely succeeded, so it can
    only make a source look staler than it is, never fresher.
    """
    if not state:
        return None
    acquisition = state.get("acquisition")
    if isinstance(acquisition, dict) and acquisition.get("last_success_at"):
        return acquisition["last_success_at"]
    changed_at = state.get("last_changed_at")
    return changed_at if isinstance(changed_at, str) and changed_at else None


def staleness(source: dict, state: dict | None, moment: datetime) -> dict:
    """Explicit staleness. Stale is not incorrect, and stale is not changed."""
    cadence = check_cadence_days(source)
    success = last_success_at(state)
    result = {
        "check_cadence_days": cadence,
        "last_success_at": success,
        "stale": False,
        "due": True,
        "age_days": None,
    }
    if success is None:
        result["stale"] = cadence is not None
        return result
    age = moment - parse_iso(success)
    result["age_days"] = max(int(age.total_seconds() // 86400), 0)
    if cadence is None:
        result["due"] = True
        return result
    deadline = parse_iso(success) + timedelta(days=cadence)
    result["due"] = moment >= deadline
    result["stale"] = moment >= deadline
    return result


def select_sources(
    root: Path,
    *,
    source_ids: Iterable[str] | None = None,
    trust: str | None = None,
    all_sources: bool = False,
    due_only: bool = False,
    include_disabled: bool = False,
    moment: datetime | None = None,
) -> tuple[list[dict], list[dict]]:
    """Resolve which registered sources this run should check.

    Returns the selected sources and a list of explicit skip reasons. Targeted
    selection by id stays first class: it is the only mode that does not need
    an opt-in to reach the network broadly.
    """
    moment = moment or datetime.now(timezone.utc)
    registry = load_registry(root)
    by_id = {source["id"]: source for source in registry}
    skipped: list[dict] = []

    requested_ids = list(source_ids or [])
    if requested_ids:
        candidates = []
        for source_id in requested_ids:
            source = by_id.get(source_id)
            if source is None:
                raise AcquisitionInputError(f"source not registered: {source_id}")
            candidates.append(source)
    elif trust or all_sources:
        candidates = sorted(registry, key=lambda item: item["id"])
    else:
        raise AcquisitionInputError(
            "select sources with --source <id>, --trust <tier> or --all"
        )

    selected: list[dict] = []
    for source in candidates:
        source_id = source["id"]
        if trust and source["trust"] != trust:
            skipped.append({"source_id": source_id, "reason": "trust_tier_not_selected"})
            continue
        if not source["enabled"] and not include_disabled:
            skipped.append({"source_id": source_id, "reason": "source_disabled"})
            continue
        lifecycle = source_lifecycle(source)
        if lifecycle != SOURCE_LIFECYCLE_ACTIVE:
            skipped.append({"source_id": source_id, "reason": f"source_{lifecycle}"})
            continue
        if due_only:
            state = load_state(root, source_id)
            if not staleness(source, state, moment)["due"]:
                skipped.append({"source_id": source_id, "reason": "not_due"})
                continue
        selected.append(source)

    if requested_ids and not selected:
        reasons = ", ".join(sorted({item["reason"] for item in skipped})) or "unknown"
        raise AcquisitionInputError(
            f"no acquirable source selected from {', '.join(requested_ids)}: {reasons}"
        )
    return selected, skipped


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def build_provenance(source: dict, result: dict, stamp: str) -> dict:
    window = None
    if source.get("content_start") or source.get("content_end"):
        window = {
            "start": source.get("content_start"),
            "end": source.get("content_end"),
        }
    provenance = {
        "acquisition_channel": ACQUISITION_CHANNEL,
        "canonical_url": source["url"],
        "fetch_url": result["fetch_url"],
        "trust": source["trust"],
        "category": source["category"],
        "http_status": result.get("http_status"),
        "content_type": result.get("content_type"),
        "etag": result.get("etag"),
        "last_modified": result.get("last_modified"),
        "normalization": normalization_strategy(source),
        "content_window": window,
        "content_length": result["content_length"],
        "acquired_at": stamp,
        "acquired_by": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
    }
    assert_provenance_safe(provenance)
    return provenance


def assert_provenance_safe(provenance: dict) -> None:
    """Provenance carries source identity and safe response metadata only."""
    unexpected = sorted(set(provenance) - set(PROVENANCE_FIELDS))
    if unexpected:
        raise AcquisitionEngineDefect(
            "provenance carries unexpected fields: " + ", ".join(unexpected)
        )
    for key in provenance:
        lowered = key.lower()
        for forbidden in PROVENANCE_FORBIDDEN_SUBSTRINGS:
            if forbidden in lowered:
                raise AcquisitionEngineDefect(
                    f"provenance field {key!r} looks like transport secret material"
                )
    for value in iter_strings(provenance):
        if "://" in value:
            # URL-shaped values come from the registry, which is reviewed
            # repository data. They must still never carry credentials.
            try:
                parts = urlsplit(value)
            except ValueError:
                raise AcquisitionEngineDefect("provenance carries an unparsable url") from None
            if parts.username or parts.password:
                raise AcquisitionEngineDefect("provenance must not carry embedded credentials")
            continue
        if MACHINE_PATH_RE.search(value):
            raise AcquisitionEngineDefect("provenance must not carry local machine paths")


def iter_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        found: list[str] = []
        for item in value.values():
            found.extend(iter_strings(item))
        return found
    if isinstance(value, list):
        found = []
        for item in value:
            found.extend(iter_strings(item))
        return found
    return [value] if isinstance(value, str) else []


# ---------------------------------------------------------------------------
# Deterministic change summary
# ---------------------------------------------------------------------------


def truncate(text: str) -> str:
    if len(text) <= CHANGE_SUMMARY_SAMPLE_WIDTH:
        return text
    return text[:CHANGE_SUMMARY_SAMPLE_WIDTH] + "…"


def build_change_summary(previous_text: str, current_text: str) -> dict:
    """Summarize what changed, deterministically and without any model.

    Change detection is a hash comparison and this summary is a line diff. No
    language model is involved in deciding that a source changed or in
    describing the change; an assisted semantic explanation could only ever be
    an addition on top of this.
    """
    previous_lines = previous_text.splitlines()
    current_lines = current_text.splitlines()
    matcher = difflib.SequenceMatcher(None, previous_lines, current_lines, autojunk=False)

    added: list[str] = []
    removed: list[str] = []
    regions = 0
    first_changed_line: int | None = None
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        regions += 1
        if first_changed_line is None:
            first_changed_line = j1 + 1
        removed.extend(previous_lines[i1:i2])
        added.extend(current_lines[j1:j2])

    return {
        "method": "normalized_line_diff",
        "deterministic": True,
        "previous_line_count": len(previous_lines),
        "current_line_count": len(current_lines),
        "previous_bytes": len(previous_text.encode("utf-8")),
        "current_bytes": len(current_text.encode("utf-8")),
        "added_line_count": len(added),
        "removed_line_count": len(removed),
        "changed_region_count": regions,
        "first_changed_line": first_changed_line,
        "added_sample": [truncate(line) for line in added[:CHANGE_SUMMARY_SAMPLE_LIMIT]],
        "removed_sample": [truncate(line) for line in removed[:CHANGE_SUMMARY_SAMPLE_LIMIT]],
    }


# ---------------------------------------------------------------------------
# Review candidates
# ---------------------------------------------------------------------------


def candidate_kind(source: dict) -> str:
    """Classify a change by registry category and role, never by source id."""
    category = source.get("category", "")
    role = source.get("role", "")
    if "security" in category or "security" in role:
        return "security-source-change"
    if "release" in category or "version" in role:
        return "release-source-change"
    if "change" in role:
        return "version-change-source-change"
    return "source-change"


def candidate_id(source_id: str, previous_hash: str, current_hash: str) -> str:
    """Deterministic candidate identity.

    The same source moving between the same two snapshots is always the same
    candidate, so re-acquiring identical content can never create a duplicate.
    """
    fingerprint = hashlib.sha256(
        f"{source_id}:{previous_hash}:{current_hash}".encode("utf-8")
    ).hexdigest()[:16]
    return f"source-change.{source_id}.{fingerprint}"


def candidate_path(root: Path, identity: str) -> Path:
    if not CANDIDATE_ID_RE.fullmatch(identity):
        raise AcquisitionInputError(f"invalid review candidate id: {identity!r}")
    return root / CANDIDATES_RELATIVE_PATH / f"{identity}.json"


def build_candidate(
    source: dict,
    *,
    previous_hash: str,
    current_hash: str,
    stamp: str,
    run_id: str,
    change_summary: dict,
    provenance: dict,
) -> dict:
    identity = candidate_id(source["id"], previous_hash, current_hash)
    return {
        "id": identity,
        "kind": candidate_kind(source),
        "status": REVIEW_STATE_TO_LEGACY_STATUS[REVIEW_PENDING],
        "review_state": REVIEW_PENDING,
        "review_required": True,
        "can_promote_to_knowledge": False,
        # A review candidate is an observation that something changed. It is
        # never a proposal about what Drupal Knowledge should say.
        "is_knowledge_proposal": False,
        "discovered_at": stamp,
        "run_id": run_id,
        "engine_version": ENGINE_VERSION,
        "source_id": source["id"],
        "source_url": source["url"],
        "trust": source["trust"],
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "summary": (
            "Registered source content changed. A human review must decide "
            "whether trusted Drupal knowledge is affected."
        ),
        "change_summary": change_summary,
        "provenance": provenance,
        "affected_knowledge_ids": [],
        "review": None,
    }


def load_candidate(root: Path, identity: str) -> dict:
    path = candidate_path(root, identity)
    if not path.is_file():
        raise AcquisitionInputError(f"review candidate not found: {identity}")
    return dk_core.read_json(path)


def iter_candidates(root: Path) -> list[dict]:
    directory = root / CANDIDATES_RELATIVE_PATH
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def validate_candidate(candidate: dict) -> None:
    required = {
        "id",
        "kind",
        "status",
        "review_state",
        "review_required",
        "can_promote_to_knowledge",
        "is_knowledge_proposal",
        "discovered_at",
        "run_id",
        "engine_version",
        "source_id",
        "source_url",
        "trust",
        "previous_hash",
        "current_hash",
        "summary",
        "change_summary",
        "provenance",
        "affected_knowledge_ids",
        "review",
    }
    context = f"review candidate {candidate.get('id', '<unknown>')}"
    dk_core.assert_keys(candidate, required, context)
    dk_core.assert_only_keys(candidate, required, context)
    if candidate["review_state"] not in REVIEW_STATES:
        raise dk_core.ValidationError(f"{context}: invalid review_state")
    if candidate["status"] != REVIEW_STATE_TO_LEGACY_STATUS[candidate["review_state"]]:
        raise dk_core.ValidationError(f"{context}: status does not match review_state")
    if candidate["review_required"] is not True:
        raise dk_core.ValidationError(f"{context}: review_required must be true")
    if candidate["can_promote_to_knowledge"] is not False:
        raise dk_core.ValidationError(f"{context}: candidates cannot self-promote")
    if candidate["is_knowledge_proposal"] is not False:
        raise dk_core.ValidationError(f"{context}: a candidate is not a knowledge proposal")
    expected_id = candidate_id(
        candidate["source_id"], candidate["previous_hash"], candidate["current_hash"]
    )
    if candidate["id"] != expected_id:
        raise dk_core.ValidationError(f"{context}: identity is not deterministic")
    assert_provenance_safe(candidate["provenance"])


def write_candidate(root: Path, candidate: dict) -> tuple[Path, str]:
    """Persist a candidate idempotently.

    An existing candidate keeps its original detection evidence; a repeated
    observation of the same change never rewrites or duplicates it.
    """
    validate_candidate(candidate)
    path = candidate_path(root, candidate["id"])
    if path.is_file():
        return path, "reused"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(candidate), encoding="utf-8")
    return path, "created"


def review_candidate(
    root: Path,
    identity: str,
    *,
    review_state: str,
    actor: str,
    method: str,
    note: str | None = None,
    moment: datetime | None = None,
    force: bool = False,
) -> dict:
    """Record an explicit human review decision.

    Every supported outcome leaves trusted knowledge exactly as it was.
    ``reviewed_requires_knowledge_proposal`` authorizes later proposal work; it
    does not create, edit or schedule any knowledge change here.
    """
    if review_state not in REVIEW_TERMINAL_STATES:
        raise AcquisitionInputError(
            "review state must be one of: " + ", ".join(sorted(REVIEW_TERMINAL_STATES))
        )
    if method not in REVIEW_METHODS:
        raise AcquisitionInputError(
            "review method must be one of: " + ", ".join(sorted(REVIEW_METHODS))
        )
    if not actor.strip():
        raise AcquisitionInputError("review actor is required")

    candidate = load_candidate(root, identity)
    validate_candidate(candidate)
    if candidate["review_state"] != REVIEW_PENDING and not force:
        raise AcquisitionInputError(
            f"candidate {identity} is already {candidate['review_state']}; use --force to re-review"
        )

    before = dk_core.knowledge_tree_digest(root)
    updated = dict(candidate)
    updated["review_state"] = review_state
    updated["status"] = REVIEW_STATE_TO_LEGACY_STATUS[review_state]
    updated["review"] = {
        "reviewed_at": now_iso(moment),
        "actor": actor.strip(),
        "method": method,
        "note": note,
        "outcome": review_state,
        # Even the strongest outcome only authorizes future proposal work.
        "authorizes_knowledge_proposal_work": review_state == REVIEW_REQUIRES_PROPOSAL,
        "trusted_knowledge_changed": False,
    }
    validate_candidate(updated)
    path = candidate_path(root, identity)
    path.write_text(stable_json(updated), encoding="utf-8")

    after = dk_core.knowledge_tree_digest(root)
    if before != after:
        raise AcquisitionEngineDefect("review mutated trusted knowledge")
    return {
        "candidate_id": identity,
        "review_state": review_state,
        "trusted_knowledge_digest_before": before,
        "trusted_knowledge_digest_after": after,
        "trusted_knowledge_mutations": [],
        "path": str(path.relative_to(root)),
    }


# ---------------------------------------------------------------------------
# Source state
# ---------------------------------------------------------------------------


def build_state(
    source: dict,
    *,
    previous_state: dict | None,
    result: dict | None,
    status: str,
    stamp: str,
    run_id: str,
    error: dict | None,
    candidate_reference: str | None,
) -> dict:
    """Advance source state without ever rewriting history.

    Snapshots are immutable and are not touched here. A failed attempt records
    the failure and keeps the last known snapshot pointer intact.
    """
    previous_state = previous_state or {}
    previous_acquisition = previous_state.get("acquisition") or {}
    succeeded = status in SUCCESS_STATUSES

    state: dict[str, Any] = {
        "source_id": source["id"],
        "url": source["url"],
    }

    if succeeded and result is not None:
        state["fetch_url"] = result["fetch_url"]
        state["content_sha256"] = result["content_sha256"]
        state["content_length"] = result["content_length"]
        state["etag"] = result.get("etag")
        state["last_modified"] = result.get("last_modified")
        state["last_changed_at"] = (
            previous_state.get("last_changed_at", stamp)
            if status == STATUS_UNCHANGED
            else stamp
        )
    else:
        for key in (
            "fetch_url",
            "content_sha256",
            "content_length",
            "etag",
            "last_modified",
            "last_changed_at",
        ):
            if key in previous_state:
                state[key] = previous_state[key]

    previous_hash = previous_state.get("content_sha256")
    if status == STATUS_CHANGED:
        superseded = previous_hash
    else:
        superseded = previous_acquisition.get("previous_snapshot_sha256")

    consecutive = 0 if succeeded else int(previous_acquisition.get("consecutive_failures", 0)) + 1
    state["acquisition"] = {
        "engine_name": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
        "acquisition_channel": ACQUISITION_CHANNEL,
        "last_attempt_at": stamp,
        "last_attempt_run_id": run_id,
        "last_attempt_status": status,
        "last_success_at": stamp if succeeded else previous_acquisition.get("last_success_at"),
        "last_success_run_id": (
            run_id if succeeded else previous_acquisition.get("last_success_run_id")
        ),
        "previous_snapshot_sha256": superseded,
        "consecutive_failures": consecutive,
        "last_error": None if succeeded else error,
        "review_candidate_id": (
            candidate_reference
            if candidate_reference
            else previous_acquisition.get("review_candidate_id")
        ),
        "check_cadence_days": check_cadence_days(source),
    }
    return state


def write_state(root: Path, state: dict) -> Path:
    path = state_path(root, state["source_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(state), encoding="utf-8")
    return path


def source_status(root: Path, source: dict, moment: datetime | None = None) -> dict:
    """Inspectable state for one registered source."""
    moment = moment or datetime.now(timezone.utc)
    state = load_state(root, source["id"])
    acquisition = (state or {}).get("acquisition") or {}
    fresh = staleness(source, state, moment)
    candidate_reference = acquisition.get("review_candidate_id")
    open_candidate = None
    if candidate_reference:
        path = candidate_path(root, candidate_reference)
        if path.is_file():
            candidate = dk_core.read_json(path)
            if candidate.get("review_state") == REVIEW_PENDING:
                open_candidate = candidate_reference
    return {
        "source_id": source["id"],
        "title": source["title"],
        "trust": source["trust"],
        "category": source["category"],
        "enabled": source["enabled"],
        "lifecycle": source_lifecycle(source),
        "superseded_by": source.get("superseded_by"),
        "baselined": bool(state and state.get("content_sha256")),
        "current_snapshot_sha256": (state or {}).get("content_sha256"),
        "previous_snapshot_sha256": acquisition.get("previous_snapshot_sha256"),
        "last_attempt_at": acquisition.get("last_attempt_at"),
        "last_attempt_status": acquisition.get("last_attempt_status"),
        "last_success_at": fresh["last_success_at"],
        "consecutive_failures": acquisition.get("consecutive_failures", 0),
        "last_error": acquisition.get("last_error"),
        "check_cadence_days": fresh["check_cadence_days"],
        "age_days": fresh["age_days"],
        "stale": fresh["stale"],
        "due": fresh["due"],
        "open_review_candidate_id": open_candidate,
        "engine_observed": bool(acquisition),
    }


# ---------------------------------------------------------------------------
# Acquisition
# ---------------------------------------------------------------------------


def sanitize_detail(detail: str) -> str:
    """Strip local machine paths and embedded credentials from a stored detail.

    Transport errors quote whatever path or URL they failed on. That text ends
    up in committed source state, so it is redacted before it is persisted.
    """
    redacted = MACHINE_PATH_RE.sub(REDACTED_LOCAL_PATH, detail)
    return CREDENTIAL_IN_URL_RE.sub(r"\1<redacted-credentials>@", redacted)


def classify_failure(exc: AcquisitionError) -> dict:
    return {
        "class": exc.error_class,
        "code": exc.code,
        "detail": sanitize_detail(str(exc)),
        "engine_defect": False,
    }


def acquire_source(
    root: Path,
    source: dict,
    *,
    run_id: str,
    timeout: int = DEFAULT_TIMEOUT,
    dry_run: bool = False,
    fetcher: Callable[[dict, int], dict] | None = None,
    normalized_output: Path | None = None,
    moment: datetime | None = None,
) -> dict:
    """Acquire one registered source and report a deterministic result.

    Only :class:`AcquisitionError` subclasses are turned into a source status.
    Every other exception is an engine defect and is re-raised as one.
    """
    moment = moment or datetime.now(timezone.utc)
    stamp = now_iso(moment)
    fetcher = fetcher or fetch_source
    source_id = source["id"]
    previous_state = load_state(root, source_id)
    previous_hash = previous_state.get("content_sha256") if previous_state else None
    fresh = staleness(source, previous_state, moment)

    outcome: dict[str, Any] = {
        "source_id": source_id,
        "trust": source["trust"],
        "category": source["category"],
        "status": None,
        "dry_run": dry_run,
        "previous_snapshot_sha256": previous_hash,
        "current_snapshot_sha256": None,
        "snapshot": {"created": False, "reused": False},
        "review_candidate": {"id": None, "result": "none"},
        "change_summary": None,
        "provenance": None,
        "stale": fresh["stale"],
        "age_days": fresh["age_days"],
        "error": None,
    }

    try:
        result = fetcher(source, timeout)
    except AcquisitionError as exc:
        outcome["status"] = (
            STATUS_UNAVAILABLE
            if isinstance(exc, SourceUnavailableError)
            else STATUS_INVALID_OR_MALFORMED
        )
        outcome["error"] = classify_failure(exc)
        # A failed attempt never invents content: the previously accepted
        # snapshot pointer is preserved untouched.
        outcome["current_snapshot_sha256"] = previous_hash
        if not dry_run:
            state = build_state(
                source,
                previous_state=previous_state,
                result=None,
                status=outcome["status"],
                stamp=stamp,
                run_id=run_id,
                error=outcome["error"],
                candidate_reference=None,
            )
            write_state(root, state)
        return outcome
    except AcquisitionEngineDefect:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise AcquisitionEngineDefect(
            f"acquisition engine defect while acquiring {source_id}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    try:
        return _record_acquisition(
            root,
            source,
            outcome=outcome,
            result=result,
            previous_state=previous_state,
            previous_hash=previous_hash,
            stamp=stamp,
            run_id=run_id,
            dry_run=dry_run,
            normalized_output=normalized_output,
        )
    except AcquisitionEngineDefect:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: classify, never swallow
        raise AcquisitionEngineDefect(
            f"acquisition engine defect while recording {source_id}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _record_acquisition(
    root: Path,
    source: dict,
    *,
    outcome: dict,
    result: dict,
    previous_state: dict | None,
    previous_hash: str | None,
    stamp: str,
    run_id: str,
    dry_run: bool,
    normalized_output: Path | None,
) -> dict:
    """Classify a successful fetch and persist the resulting evidence."""
    source_id = source["id"]
    if previous_hash:
        # The previously accepted snapshot must still be addressable and intact.
        dk_core.require_snapshot(root, source_id, previous_hash)

    current_hash = result["content_sha256"]
    provenance = build_provenance(source, result, stamp)
    outcome["provenance"] = provenance
    outcome["current_snapshot_sha256"] = current_hash

    if previous_hash is None:
        outcome["status"] = STATUS_FIRST_OBSERVATION
    elif previous_hash == current_hash:
        outcome["status"] = STATUS_UNCHANGED
    else:
        outcome["status"] = STATUS_CHANGED

    if normalized_output is not None:
        target = normalized_output / f"{source_id}.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(result["normalized_text"], encoding="utf-8")

    if outcome["status"] == STATUS_CHANGED:
        previous_text = dk_core.require_snapshot(root, source_id, previous_hash).read_text(
            encoding="utf-8"
        )
        outcome["change_summary"] = build_change_summary(
            previous_text, result["normalized_text"]
        )

    if dry_run:
        return outcome

    _, created = dk_core.write_snapshot(
        root, source_id, current_hash, result["normalized_text"]
    )
    outcome["snapshot"] = {"created": created, "reused": not created}

    candidate_reference = None
    if outcome["status"] == STATUS_CHANGED:
        candidate = build_candidate(
            source,
            previous_hash=previous_hash,
            current_hash=current_hash,
            stamp=stamp,
            run_id=run_id,
            change_summary=outcome["change_summary"],
            provenance=provenance,
        )
        _, candidate_result = write_candidate(root, candidate)
        candidate_reference = candidate["id"]
        outcome["review_candidate"] = {"id": candidate["id"], "result": candidate_result}

    state = build_state(
        source,
        previous_state=previous_state,
        result=result,
        status=outcome["status"],
        stamp=stamp,
        run_id=run_id,
        error=None,
        candidate_reference=candidate_reference,
    )
    write_state(root, state)
    return outcome


def build_run_id(stamp: str, source_ids: list[str]) -> str:
    compact = stamp.replace("-", "").replace(":", "").replace("Z", "")
    fingerprint = hashlib.sha256(
        (stamp + "|" + ENGINE_VERSION + "|" + ",".join(sorted(source_ids))).encode("utf-8")
    ).hexdigest()[:8]
    return f"run.{compact}.{fingerprint}"


def acquire(
    root: Path = dk_core.ROOT,
    *,
    source_ids: Iterable[str] | None = None,
    trust: str | None = None,
    all_sources: bool = False,
    due_only: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    dry_run: bool = False,
    fetcher: Callable[[dict, int], dict] | None = None,
    normalized_output: Path | None = None,
    moment: datetime | None = None,
    run_id: str | None = None,
) -> dict:
    """Run one acquisition pass and return a machine-readable run result.

    This is the single entry point. Manual CLI runs and scheduled CI runs both
    call it, so there is exactly one acquisition behaviour to reason about.
    """
    moment = moment or datetime.now(timezone.utc)
    started_at = now_iso(moment)
    requested = list(source_ids or [])
    selected, skipped = select_sources(
        root,
        source_ids=requested or None,
        trust=trust,
        all_sources=all_sources,
        due_only=due_only,
        moment=moment,
    )
    selected_ids = [source["id"] for source in selected]
    run_id = run_id or build_run_id(started_at, selected_ids)

    knowledge_before = dk_core.knowledge_tree_digest(root)
    results: list[dict] = []
    engine_defects: list[dict] = []
    for source in selected:
        try:
            results.append(
                acquire_source(
                    root,
                    source,
                    run_id=run_id,
                    timeout=timeout,
                    dry_run=dry_run,
                    fetcher=fetcher,
                    normalized_output=normalized_output,
                    moment=moment,
                )
            )
        except AcquisitionEngineDefect as exc:
            # Recorded as an engine defect and never as evidence about the
            # source. The run fails; the source keeps its previous state.
            engine_defects.append(
                {
                    "source_id": source["id"],
                    "class": ERROR_ENGINE_DEFECT,
                    "detail": sanitize_detail(str(exc)),
                    "engine_defect": True,
                }
            )
    knowledge_after = dk_core.knowledge_tree_digest(root)

    run = {
        "schema_version": ACQUISITION_RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "acquisition_channel": ACQUISITION_CHANNEL,
        "started_at": started_at,
        "completed_at": now_iso(),
        "dry_run": dry_run,
        "selection": {
            "requested": requested,
            "trust": trust,
            "due_only": due_only,
            "all_sources": all_sources,
            "selected": selected_ids,
            "skipped": skipped,
        },
        "results": results,
        "snapshots_created": [
            item["current_snapshot_sha256"]
            for item in results
            if item["snapshot"]["created"]
        ],
        "snapshots_reused": [
            item["current_snapshot_sha256"]
            for item in results
            if item["snapshot"]["reused"]
        ],
        "review_candidates_created": [
            item["review_candidate"]["id"]
            for item in results
            if item["review_candidate"]["result"] == "created"
        ],
        "review_candidates_reused": [
            item["review_candidate"]["id"]
            for item in results
            if item["review_candidate"]["result"] == "reused"
        ],
        "failures": [
            {"source_id": item["source_id"], "status": item["status"], **item["error"]}
            for item in results
            if item["error"]
        ],
        "engine_defects": engine_defects,
        "stale_sources": [item["source_id"] for item in results if item["stale"]],
        # The engine has no path that edits knowledge/. This is asserted, not
        # asserted-by-convention: the digest is taken before and after the run.
        "trusted_knowledge_mutations": [],
        "trusted_knowledge_digest": {
            "before": knowledge_before,
            "after": knowledge_after,
        },
    }

    if knowledge_before != knowledge_after:
        raise AcquisitionEngineDefect(
            "acquisition mutated trusted knowledge: "
            f"{knowledge_before} -> {knowledge_after}"
        )
    return run


def run_exit_code(run: dict) -> int:
    """0 clean, 1 source failure, 3 engine defect. Never silently zero."""
    if run["engine_defects"]:
        return 3
    if run["failures"]:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Repository contract validation
# ---------------------------------------------------------------------------


def validate_acquisition_contract(root: Path = dk_core.ROOT) -> list[str]:
    schema = dk_core.read_json(root / "schema" / "source-change-candidate.schema.json")
    states = schema.get("properties", {}).get("review_state", {}).get("enum")
    if sorted(states or []) != sorted(REVIEW_STATES):
        raise dk_core.ValidationError(
            "source-change candidate schema must declare the engine review states"
        )
    if schema.get("properties", {}).get("is_knowledge_proposal", {}).get("const") is not False:
        raise dk_core.ValidationError(
            "source-change candidate schema must pin is_knowledge_proposal to false"
        )
    state_schema = dk_core.read_json(root / "schema" / "source-state.schema.json")
    if "acquisition" not in state_schema.get("properties", {}):
        raise dk_core.ValidationError("source state schema must describe acquisition state")

    for candidate in iter_candidates(root):
        validate_candidate(candidate)

    for source in load_registry(root):
        context = f"source {source['id']}"
        normalization_strategy(source)
        if source.get("expected_content_type") not in (None, *CONTENT_TYPE_FAMILIES):
            raise dk_core.ValidationError(f"{context}: invalid expected_content_type")
        if source_lifecycle(source) not in SOURCE_LIFECYCLES:
            raise dk_core.ValidationError(f"{context}: invalid lifecycle")
        cadence = source.get("check_cadence_days")
        if cadence is not None and (not isinstance(cadence, int) or cadence < 1):
            raise dk_core.ValidationError(f"{context}: check_cadence_days must be a positive integer")

    return [
        "ACQUISITION_ENGINE_CONTRACT_VALID=PASS",
        f"ACQUISITION_ENGINE_VERSION={ENGINE_VERSION}",
    ]
