#!/usr/bin/env python3
"""Drupal API lifecycle: what an official annotation says about one symbol.

Prompt 10 could say a project's code compatibility was unknown. This module is
half of the answer to *why*: it turns two authoritative Drupal sources into
symbol-level lifecycle records that a matcher can join against observed code.

    api.drupal.org deprecated index  ->  api/lifecycle/*.json
    Drupal.org change-record feed    ->  api/change-records/*.json

Both are source-derived authoritative records, not Drupal Knowledge rules. They
follow the security advisory precedent exactly: they live in their own store,
they carry provenance back to an immutable snapshot, and they never appear in
``knowledge/records/``.

The deprecated index is parsed, never read as prose. Drupal core's coding
standards mandate one sentence shape for every deprecation::

    in drupal:9.3.0 and is removed from drupal:10.0.0. Use X instead.

That grammar is matched exactly. A row that does not match it becomes a record
whose lifecycle is ``unknown`` rather than a record with a guessed version, and
a replacement is recorded only when the annotation states one.

Four distinctions this module exists to keep:

    deprecated                 != removed
    deprecated in 9.3.0        != deprecated in all of 9
    "There is no replacement." != no replacement stated
    change record mentions X   != X has that lifecycle
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_acquisition
import dk_core


ENGINE_NAME = "drupal-knowledge-api-lifecycle-engine"
ENGINE_VERSION = "0.1"
LIFECYCLE_RECORD_VERSION = "0.1"
CHANGE_RECORD_VERSION = "0.1"

LIFECYCLE_RELATIVE_PATH = Path("api") / "lifecycle"
CHANGE_RECORDS_RELATIVE_PATH = Path("api") / "change-records"

AUTHORITY_ROLE = "api_lifecycle_authority"
KIND_DEPRECATION_INDEX = "core_deprecation_index"
KIND_CHANGE_RECORD_FEED = "change_record_feed"

RECORD_CLASS = "source_derived_authoritative_api_lifecycle_record"

# --- lifecycle states --------------------------------------------------------
#
# Prompt 10 kept deprecated and removed apart. These are the same distinction
# carried down to one symbol, plus the states an annotation can express that
# neither of those two words covers.

CURRENT = "current"
DEPRECATED = "deprecated"
REMOVED = "removed"
CHANGED_SIGNATURE = "changed_signature"
REPLACEMENT_AVAILABLE = "replacement_available"
BEHAVIOR_CHANGED = "behavior_changed"
UNKNOWN = "unknown"

LIFECYCLE_STATES = (
    CURRENT,
    DEPRECATED,
    REMOVED,
    CHANGED_SIGNATURE,
    REPLACEMENT_AVAILABLE,
    BEHAVIOR_CHANGED,
    UNKNOWN,
)

# --- change-record categories ------------------------------------------------

CATEGORY_DEPRECATION = "deprecation"
CATEGORY_REMOVAL = "removal"
CATEGORY_SIGNATURE = "signature_change"
CATEGORY_SERVICE = "service_change"
CATEGORY_HOOK = "hook_change"
CATEGORY_EVENT = "event_change"
CATEGORY_CONFIGURATION = "configuration_change"
CATEGORY_BEHAVIOR = "behavior_change"
CATEGORY_DEPENDENCY = "dependency_change"
CATEGORY_ADDITION = "API_addition"
CATEGORY_OTHER = "other"

CHANGE_CATEGORIES = (
    CATEGORY_DEPRECATION,
    CATEGORY_REMOVAL,
    CATEGORY_SIGNATURE,
    CATEGORY_SERVICE,
    CATEGORY_HOOK,
    CATEGORY_EVENT,
    CATEGORY_CONFIGURATION,
    CATEGORY_BEHAVIOR,
    CATEGORY_DEPENDENCY,
    CATEGORY_ADDITION,
    CATEGORY_OTHER,
)

# --- symbol kinds ------------------------------------------------------------

SYMBOL_FUNCTION = "function"
SYMBOL_METHOD = "method"
SYMBOL_CLASS = "class"
SYMBOL_INTERFACE = "interface"
SYMBOL_TRAIT = "trait"
SYMBOL_CONSTANT = "constant"
SYMBOL_PROPERTY = "property"
SYMBOL_SERVICE = "service"
SYMBOL_HOOK = "hook"
SYMBOL_UNKNOWN = "unknown"

SYMBOL_KINDS = (
    SYMBOL_FUNCTION,
    SYMBOL_METHOD,
    SYMBOL_CLASS,
    SYMBOL_INTERFACE,
    SYMBOL_TRAIT,
    SYMBOL_CONSTANT,
    SYMBOL_PROPERTY,
    SYMBOL_SERVICE,
    SYMBOL_HOOK,
    SYMBOL_UNKNOWN,
)

# api.drupal.org labels a deprecated method "function" because that is what it
# is in PHP. Whether it is global or bound is decided by the name, not by us.
INDEX_KIND_MAP = {
    "function": SYMBOL_FUNCTION,
    "class": SYMBOL_CLASS,
    "interface": SYMBOL_INTERFACE,
    "trait": SYMBOL_TRAIT,
    "constant": SYMBOL_CONSTANT,
    "property": SYMBOL_PROPERTY,
    "service": SYMBOL_SERVICE,
}

# --- the mandated deprecation grammar ---------------------------------------
#
# Drupal core requires every @deprecated annotation to read exactly this way.
# Matching the grammar is parsing; reading around it would be inference.

DEPRECATION_GRAMMAR = re.compile(
    r"^in\s+drupal:(?P<deprecated>\d+\.\d+\.\d+)"
    r"\s+and\s+is\s+removed\s+from\s+drupal:(?P<removed>\d+\.\d+\.\d+)\.\s*(?P<rest>.*)$",
    re.DOTALL,
)

# The annotation states a replacement one of exactly two ways.
NO_REPLACEMENT = re.compile(r"^there\s+is\s+no\s+replacement\.?\s*$", re.IGNORECASE)
REPLACEMENT_SENTENCE = re.compile(r"^use\s+(?P<replacement>.+?)\s*(?:instead)?\.?\s*$", re.IGNORECASE | re.DOTALL)

# A symbol name as api.drupal.org prints it: Foo, Foo::bar, some_function.
SYMBOL_NAME_RE = re.compile(r"^[A-Za-z_\\][A-Za-z0-9_\\]*(?:::[A-Za-z_][A-Za-z0-9_]*)?$")

# Identifiers followed by parentheses inside a change-record title. Extracting
# these is pattern matching on code punctuation, not reading the sentence.
TITLE_SYMBOL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)?)\(\)")

TABLE_RE = re.compile(r"<table[^>]*>(?P<body>.*?)</table>", re.DOTALL | re.IGNORECASE)
ROW_RE = re.compile(r"<tr[^>]*>(?P<row>.*?)</tr>", re.DOTALL | re.IGNORECASE)
CELL_RE = re.compile(r"<t[dh][^>]*>(?P<cell>.*?)</t[dh]>", re.DOTALL | re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")


class ApiLifecycleInputError(RuntimeError):
    """Caller asked for something the evidence does not describe."""


class ApiLifecycleEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as an evidence problem."""


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


def collapse(text: str) -> str:
    return " ".join(text.split())


def cell_text(markup: str) -> str:
    """Text of one index table cell.

    Tags are removed without substituting a space. api.drupal.org splits long
    file paths with ``<wbr />`` word-break hints, and a space there would turn
    ``core/modules/action`` into three unusable fragments.
    """
    return collapse(html.unescape(TAG_RE.sub("", markup)))


def block_text(markup: str) -> str:
    """Text of an HTML block, where tags do separate words."""
    return collapse(html.unescape(TAG_RE.sub(" ", markup)))


# ---------------------------------------------------------------------------
# Registered authority
# ---------------------------------------------------------------------------


def authority_sources(root: Path = dk_core.ROOT, authority_kind: str | None = None) -> list[dict]:
    """Registered sources that declare themselves API lifecycle authority."""
    found = []
    for source in dk_core.load_sources(root):
        block = source.get("api_lifecycle") or {}
        if block.get("role") != AUTHORITY_ROLE:
            continue
        if authority_kind and block.get("authority_kind") != authority_kind:
            continue
        found.append(source)
    return sorted(found, key=lambda item: item["id"])


def snapshot_for(root: Path, source_id: str) -> tuple[str, str]:
    """The pinned snapshot for one source, as (sha, text)."""
    state_path = root / "sources" / "state" / f"{source_id}.json"
    if not state_path.is_file():
        raise ApiLifecycleInputError(f"source {source_id} has no acquisition state")
    state = dk_core.read_json(state_path)
    sha = state.get("content_sha256")
    if not isinstance(sha, str):
        raise ApiLifecycleInputError(f"source {source_id} has no baselined snapshot")
    path = dk_core.require_snapshot(root, source_id, sha)
    if not path.is_file():
        raise ApiLifecycleInputError(f"snapshot {sha} for source {source_id} is missing")
    return sha, path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Fully qualified identity
#
# api.drupal.org prints a class as its short name. Matching a short name against
# project code would find every "Action", "Image" and "Term" in it. The core
# file path is what makes the symbol identifiable, through Drupal's own PSR-4
# layout, so identity is derived from the source row rather than from the name.
# ---------------------------------------------------------------------------


def namespace_from_core_path(file_path: str) -> str | None:
    parts = file_path.split("/")
    if len(parts) < 3 or parts[0] != "core":
        return None
    if not parts[-1].endswith(".php"):
        # core/includes/*.inc holds procedural code in the global namespace.
        return None
    tail = parts[-1][: -len(".php")]

    if parts[1] == "lib" and parts[2] == "Drupal":
        return "\\".join(["Drupal", *parts[3:-1], tail])
    if parts[1] == "tests" and parts[2] == "Drupal":
        return "\\".join(["Drupal", *parts[3:-1], tail])
    if parts[1] == "modules" and len(parts) > 3:
        module = parts[2]
        rest = parts[3:-1]
        if rest[:1] == ["src"]:
            return "\\".join(["Drupal", module, *rest[1:], tail])
        if rest[:2] == ["tests", "src"]:
            return "\\".join(["Drupal", "Tests", module, *rest[2:], tail])
    if parts[1] == "profiles" and len(parts) > 3 and parts[3:4] == ["src"]:
        return "\\".join(["Drupal", parts[2], *parts[4:-1], tail])
    if parts[1] == "themes" and len(parts) > 3 and parts[3:4] == ["src"]:
        return "\\".join(["Drupal", parts[2], *parts[4:-1], tail])
    return None


def qualify(name: str, core_file: str, index_kind: str) -> dict:
    """Resolve one index row to a matchable symbol identity."""
    if "::" in name:
        short_class, member = name.split("::", 1)
        namespace = namespace_from_core_path(core_file)
        if namespace and namespace.rsplit("\\", 1)[-1] == short_class:
            return {
                "kind": SYMBOL_METHOD,
                "qualified_name": f"{namespace}::{member}",
                "class": namespace,
                "member": member,
                "identity_basis": "core_file_path_psr4",
            }
        # The row names a member of a class this path does not resolve. It is
        # still a real deprecation, but not one that can be matched safely.
        return {
            "kind": SYMBOL_METHOD,
            "qualified_name": None,
            "class": None,
            "member": member,
            "identity_basis": "unresolved_class_for_member",
        }

    kind = INDEX_KIND_MAP.get(index_kind, SYMBOL_UNKNOWN)
    if kind in (SYMBOL_CLASS, SYMBOL_INTERFACE, SYMBOL_TRAIT):
        namespace = namespace_from_core_path(core_file)
        if namespace and namespace.rsplit("\\", 1)[-1] == name:
            return {
                "kind": kind,
                "qualified_name": namespace,
                "class": namespace,
                "member": None,
                "identity_basis": "core_file_path_psr4",
            }
        return {
            "kind": kind,
            "qualified_name": None,
            "class": None,
            "member": None,
            "identity_basis": "unresolved_class_path",
        }

    if kind == SYMBOL_FUNCTION:
        if namespace_from_core_path(core_file) is not None:
            # A bare function name inside a namespaced class file is a method
            # whose row did not spell out its class. It is not a global
            # function and must not be matched as one.
            return {
                "kind": SYMBOL_METHOD,
                "qualified_name": None,
                "class": None,
                "member": name,
                "identity_basis": "unqualified_member_in_class_file",
            }
        return {
            "kind": SYMBOL_FUNCTION,
            "qualified_name": name,
            "class": None,
            "member": None,
            "identity_basis": "global_procedural_function",
        }

    if kind == SYMBOL_CONSTANT and namespace_from_core_path(core_file) is None:
        return {
            "kind": SYMBOL_CONSTANT,
            "qualified_name": name,
            "class": None,
            "member": None,
            "identity_basis": "global_constant",
        }

    return {
        "kind": kind,
        "qualified_name": None,
        "class": None,
        "member": None,
        "identity_basis": "not_resolvable_from_index_row",
    }


# ---------------------------------------------------------------------------
# Deprecation index parsing
# ---------------------------------------------------------------------------


def parse_deprecation_index(text: str) -> list[dict]:
    """Rows of one api.drupal.org deprecated-symbol index page."""
    table = TABLE_RE.search(text)
    if not table:
        raise ApiLifecycleInputError("deprecated index page contains no table")

    rows = []
    for match in ROW_RE.finditer(table.group("body")):
        cells = [cell_text(cell.group("cell")) for cell in CELL_RE.finditer(match.group("row"))]
        if len(cells) < 4:
            continue
        name, core_file, annotation, index_kind = cells[0], cells[1], cells[2], cells[3]
        if not name or not SYMBOL_NAME_RE.match(name):
            continue
        if not core_file.startswith("core/"):
            continue
        rows.append(
            {
                "name": name,
                "core_file": core_file,
                "annotation": annotation,
                "index_kind": index_kind,
            }
        )
    return rows


def read_annotation(annotation: str) -> dict:
    """The lifecycle an annotation states, or unknown if it states none."""
    grammar = DEPRECATION_GRAMMAR.match(annotation.strip())
    if not grammar:
        return {
            "state": UNKNOWN,
            "deprecated_version": None,
            "removed_version": None,
            "replacement": None,
            "replacement_state": UNKNOWN,
            "annotation_parsed": False,
            "reason": (
                "The annotation does not follow the mandated "
                "'in drupal:X and is removed from drupal:Y.' form, so no version "
                "boundary is read from it."
            ),
        }

    rest = collapse(grammar.group("rest"))
    if not rest:
        replacement, replacement_state = None, UNKNOWN
    elif NO_REPLACEMENT.match(rest):
        replacement, replacement_state = None, "stated_none"
    else:
        sentence = REPLACEMENT_SENTENCE.match(rest)
        if sentence:
            replacement, replacement_state = collapse(sentence.group("replacement")), "stated"
        else:
            # The annotation says something this engine cannot read as a
            # replacement. Inventing one from it is exactly what is forbidden.
            replacement, replacement_state = None, UNKNOWN

    return {
        "state": DEPRECATED,
        "deprecated_version": grammar.group("deprecated"),
        "removed_version": grammar.group("removed"),
        "replacement": replacement,
        "replacement_state": replacement_state,
        "annotation_parsed": True,
        "reason": "Read from the mandated Drupal core @deprecated annotation form.",
    }


def record_id_for(qualified: dict, name: str, core_file: str) -> str:
    basis = qualified["qualified_name"] or f"{core_file}::{name}"
    return "api-lifecycle." + digest_hex(LIFECYCLE_RECORD_VERSION, qualified["kind"], basis)[:16]


def build_lifecycle_record(
    row: dict,
    source: dict,
    snapshot_sha256: str,
    ingested_at: str,
    run_id: str,
) -> dict:
    qualified = qualify(row["name"], row["core_file"], row["index_kind"])
    lifecycle = read_annotation(row["annotation"])
    block = source["api_lifecycle"]

    return {
        "record_contract_version": LIFECYCLE_RECORD_VERSION,
        "id": record_id_for(qualified, row["name"], row["core_file"]),
        "record_class": RECORD_CLASS,
        # Source-derived authority, never a Drupal Knowledge rule. Consumers can
        # see that without reading any documentation.
        "is_trusted_knowledge": False,
        "is_general_knowledge_record": False,
        "symbol": {
            "index_name": row["name"],
            "kind": qualified["kind"],
            "qualified_name": qualified["qualified_name"],
            "class": qualified["class"],
            "member": qualified["member"],
            "identity_basis": qualified["identity_basis"],
            "matchable": qualified["qualified_name"] is not None,
            "core_file": row["core_file"],
        },
        "lifecycle": {
            "state": lifecycle["state"],
            "deprecated_version": lifecycle["deprecated_version"],
            "removed_version": lifecycle["removed_version"],
            "changed_version": None,
            "annotation_parsed": lifecycle["annotation_parsed"],
            "reason": lifecycle["reason"],
            "source_annotation": row["annotation"],
        },
        "replacement": {
            "state": lifecycle["replacement_state"],
            "value": lifecycle["replacement"],
            "semantics": (
                "A replacement is recorded only when the annotation states one. "
                "An equivalent API is never inferred."
            ),
        },
        "observed_branch": block["source_branch"],
        "provenance": {
            "source_id": source["id"],
            "source_url": source["url"],
            "source_snapshot_sha256": snapshot_sha256,
            "authority_kind": block["authority_kind"],
            "acquisition_channel": dk_acquisition.ACQUISITION_CHANNEL,
            "ingested_at": ingested_at,
            "ingest_run_id": run_id,
            "ingested_by": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        },
    }


# ---------------------------------------------------------------------------
# Change records
# ---------------------------------------------------------------------------


def categorize(title: str, description: str) -> dict:
    """Categorize a change record from words its own source wrote.

    This reads the record's title and description for the vocabulary Drupal
    itself uses. It is a classification of the source text, and the text it
    matched is recorded so a reviewer can disagree with it.
    """
    haystack = f"{title}\n{description}".lower()
    signals: list[tuple[str, str]] = []
    for category, phrases in (
        (CATEGORY_REMOVAL, ("is removed", "are removed", "has been removed", "have been removed", "no longer available")),
        (CATEGORY_DEPRECATION, ("deprecated", "deprecation")),
        (CATEGORY_SIGNATURE, ("signature", "new argument", "additional argument", "parameter is added", "changed argument")),
        (CATEGORY_SERVICE, ("service is", "services are", "service id", "new service", "service has been")),
        (CATEGORY_HOOK, ("hook_",)),
        (CATEGORY_EVENT, ("event subscriber", "new event", "event is")),
        (CATEGORY_CONFIGURATION, ("config schema", "configuration schema", "settings.php", "config key")),
        (CATEGORY_DEPENDENCY, ("symfony", "composer requirement", "dependency is", "requires php")),
        (CATEGORY_ADDITION, ("new method", "added to", "now supports", "new class")),
        (CATEGORY_BEHAVIOR, ("behavior", "behaviour", "now uses", "no longer needs")),
    ):
        for phrase in phrases:
            if phrase in haystack:
                signals.append((category, phrase))
                break

    if not signals:
        return {"category": CATEGORY_OTHER, "matched_phrase": None, "additional_categories": []}
    primary = signals[0]
    return {
        "category": primary[0],
        "matched_phrase": primary[1],
        "additional_categories": sorted({item[0] for item in signals[1:]}),
    }


def extract_title_symbols(title: str) -> list[str]:
    """Identifiers the title writes with call parentheses.

    ``file_create_url()`` in a title is the source writing code, not this engine
    reading prose. Anything without the parentheses is left alone.
    """
    return sorted({match.group(1) for match in TITLE_SYMBOL_RE.finditer(title)})


def build_change_record(
    node: dict,
    source: dict,
    snapshot_sha256: str,
    ingested_at: str,
    run_id: str,
) -> dict:
    block = source["api_lifecycle"]
    nid = str(node.get("nid") or "").strip()
    if not nid:
        raise ApiLifecycleInputError("change record node has no nid")

    title = collapse(str(node.get("title") or ""))
    description_field = node.get(block["description_field"])
    description_html = ""
    if isinstance(description_field, dict):
        description_html = str(description_field.get("value") or "")
    description_text = block_text(description_html)

    branch = node.get(block["introduced_branch_field"])
    version = node.get(block["introduced_version_field"])
    category = categorize(title, description_text)
    status = node.get(block["status_field"])

    return {
        "record_contract_version": CHANGE_RECORD_VERSION,
        "id": f"change-record.{nid}",
        "record_class": RECORD_CLASS,
        "is_trusted_knowledge": False,
        "is_general_knowledge_record": False,
        "change_record": {
            "node_id": nid,
            "title": title,
            "canonical_url": str(node.get("url") or ""),
            "published": bool(status),
            "introduced_branch": branch if isinstance(branch, str) and branch else None,
            "introduced_version": version if isinstance(version, str) and version else None,
            "created_at": now_iso(datetime.fromtimestamp(int(node["created"]), tz=timezone.utc))
            if str(node.get("created") or "").isdigit()
            else None,
        },
        "category": {
            "value": category["category"],
            "additional": category["additional_categories"],
            "basis": "source_text_vocabulary_match",
            "matched_phrase": category["matched_phrase"],
        },
        "symbols": {
            # Only identifiers the source itself wrote as code. A symbol named
            # in prose without parentheses is not extracted, and no symbol is
            # given a lifecycle by this record on its own.
            "named_with_call_syntax": extract_title_symbols(title),
            "extraction": "title_call_syntax_only",
            "lifecycle_asserted": False,
            "semantics": (
                "A change record names symbols. It does not, in this contract, "
                "assert their lifecycle; that comes from the deprecation index."
            ),
        },
        "description": {
            "present": bool(description_text),
            "text_length": len(description_text),
            "excerpt": description_text[:600],
        },
        "provenance": {
            "source_id": source["id"],
            "source_url": source["url"],
            "source_node_id": nid,
            "source_snapshot_sha256": snapshot_sha256,
            "authority_kind": block["authority_kind"],
            "acquisition_channel": dk_acquisition.ACQUISITION_CHANNEL,
            "ingested_at": ingested_at,
            "ingest_run_id": run_id,
            "ingested_by": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        },
    }


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


def lifecycle_path(root: Path, identifier: str) -> Path:
    return root / LIFECYCLE_RELATIVE_PATH / f"{identifier}.json"


def change_record_path(root: Path, identifier: str) -> Path:
    return root / CHANGE_RECORDS_RELATIVE_PATH / f"{identifier}.json"


def iter_lifecycle_records(root: Path = dk_core.ROOT) -> list[dict]:
    directory = root / LIFECYCLE_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def iter_change_records(root: Path = dk_core.ROOT) -> list[dict]:
    directory = root / CHANGE_RECORDS_RELATIVE_PATH
    if not directory.is_dir():
        return []
    return [dk_core.read_json(path) for path in dk_core.iter_json_files(directory)]


def clear_records(root: Path, relative: Path, source_ids: set[str]) -> int:
    """Drop stored records that came from the sources about to be re-ingested."""
    directory = root / relative
    if not directory.is_dir():
        return 0
    removed = 0
    for path in dk_core.iter_json_files(directory):
        record = dk_core.read_json(path)
        if record.get("provenance", {}).get("source_id") in source_ids:
            path.unlink()
            removed += 1
    return removed


def ingest(root: Path = dk_core.ROOT, moment: datetime | None = None) -> dict:
    """Project the pinned snapshots into source-derived records.

    Reads only snapshots the acquisition engine already wrote. Nothing here
    fetches, and nothing here touches trusted knowledge.
    """
    ingested_at = now_iso(moment)
    run_id = "api.{}.{}".format(
        ingested_at.replace("-", "").replace(":", "").replace("Z", ""),
        digest_hex(ingested_at)[:8],
    )

    # Ingest replaces the records it produces rather than merging into them.
    # A record's identity comes from the symbol it resolved to, so a parsing
    # improvement changes identities, and merging would leave the superseded
    # record behind to be matched against forever.
    index_sources = authority_sources(root, KIND_DEPRECATION_INDEX)
    feed_sources = authority_sources(root, KIND_CHANGE_RECORD_FEED)
    replaced = clear_records(
        root,
        LIFECYCLE_RELATIVE_PATH,
        {source["id"] for source in index_sources},
    ) + clear_records(
        root,
        CHANGE_RECORDS_RELATIVE_PATH,
        {source["id"] for source in feed_sources},
    )

    lifecycle_written = 0
    lifecycle_rows = 0
    unparsed = 0
    unmatchable = 0
    for source in index_sources:
        sha, text = snapshot_for(root, source["id"])
        for row in parse_deprecation_index(text):
            lifecycle_rows += 1
            record = build_lifecycle_record(row, source, sha, ingested_at, run_id)
            if not record["lifecycle"]["annotation_parsed"]:
                unparsed += 1
            if not record["symbol"]["matchable"]:
                unmatchable += 1
            path = lifecycle_path(root, record["id"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(stable_json(record), encoding="utf-8")
            lifecycle_written += 1

    change_written = 0
    for source in feed_sources:
        sha, text = snapshot_for(root, source["id"])
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ApiLifecycleInputError(f"change-record feed is not JSON: {exc}") from exc
        for node in payload.get("list", []):
            record = build_change_record(node, source, sha, ingested_at, run_id)
            path = change_record_path(root, record["id"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(stable_json(record), encoding="utf-8")
            change_written += 1

    return {
        "run_id": run_id,
        "ingested_at": ingested_at,
        "records_replaced": replaced,
        "lifecycle_rows_read": lifecycle_rows,
        "lifecycle_records_written": lifecycle_written,
        "lifecycle_annotations_unparsed": unparsed,
        "lifecycle_symbols_unmatchable": unmatchable,
        "change_records_written": change_written,
    }


# ---------------------------------------------------------------------------
# Lookup index used by the migration matcher
# ---------------------------------------------------------------------------


def build_index(root: Path = dk_core.ROOT) -> dict:
    """Matchable lifecycle records keyed by their qualified identity."""
    functions: dict[str, dict] = {}
    classes: dict[str, dict] = {}
    methods: dict[str, dict] = {}
    constants: dict[str, dict] = {}
    services: dict[str, dict] = {}
    unmatchable = 0

    for record in iter_lifecycle_records(root):
        symbol = record["symbol"]
        name = symbol["qualified_name"]
        if not name:
            unmatchable += 1
            continue
        kind = symbol["kind"]
        if kind == SYMBOL_FUNCTION:
            functions[name] = record
        elif kind in (SYMBOL_CLASS, SYMBOL_INTERFACE, SYMBOL_TRAIT):
            classes[name] = record
        elif kind == SYMBOL_METHOD:
            methods[name] = record
        elif kind == SYMBOL_CONSTANT:
            constants[name] = record
        elif kind == SYMBOL_SERVICE:
            services[name] = record

    branches = sorted(
        {
            (source.get("api_lifecycle") or {}).get("source_branch")
            for source in authority_sources(root, KIND_DEPRECATION_INDEX)
        }
        - {None}
    )
    return {
        "functions": functions,
        "classes": classes,
        "methods": methods,
        "constants": constants,
        "services": services,
        "unmatchable_records": unmatchable,
        "covered_source_branches": branches,
        "record_count": len(functions) + len(classes) + len(methods) + len(constants) + len(services),
    }


def coverage(root: Path = dk_core.ROOT) -> dict:
    """What the lifecycle corpus does and does not cover.

    Coverage is first-class because the alternative is letting "no record
    matched" read as "nothing is wrong", which is the single most dangerous
    thing a migration analyser can say.
    """
    index_sources = authority_sources(root, KIND_DEPRECATION_INDEX)
    feed_sources = authority_sources(root, KIND_CHANGE_RECORD_FEED)
    records = iter_lifecycle_records(root)
    branches = sorted({(source["api_lifecycle"])["source_branch"] for source in index_sources})

    removed_versions = sorted(
        {
            record["lifecycle"]["removed_version"]
            for record in records
            if record["lifecycle"]["removed_version"]
        }
    )
    return {
        "deprecation_index": {
            "source_ids": [source["id"] for source in index_sources],
            "covered_source_branches": branches,
            "complete_for_branch": all(
                (source["api_lifecycle"]).get("index_complete_for_branch") is True
                for source in index_sources
            )
            and bool(index_sources),
            "records": len(records),
            "matchable_records": sum(1 for record in records if record["symbol"]["matchable"]),
            "annotations_unparsed": sum(
                1 for record in records if not record["lifecycle"]["annotation_parsed"]
            ),
            "removal_versions_present": removed_versions,
        },
        "change_records": {
            "source_ids": [source["id"] for source in feed_sources],
            "records": len(iter_change_records(root)),
            "complete_for_branch": False,
            "window": "most recent records published by the feed, bounded by its limit",
        },
        "gaps": [
            (
                "Only Drupal source branches "
                f"{', '.join(branches) or 'none'} have a deprecation index registered. "
                "A symbol deprecated on another branch has no record here, and its "
                "absence is not evidence that it is current."
            ),
            (
                "The change-record feed is a recent window, not the full history. "
                "Absence from it means nothing."
            ),
            (
                "A record whose class could not be resolved from its core file path is "
                "kept but not matchable, so it can never produce a finding."
            ),
        ],
    }


# ---------------------------------------------------------------------------
# Repository contract
# ---------------------------------------------------------------------------


def validate_lifecycle_record(record: dict) -> None:
    required = {
        "record_contract_version",
        "id",
        "record_class",
        "is_trusted_knowledge",
        "is_general_knowledge_record",
        "symbol",
        "lifecycle",
        "replacement",
        "observed_branch",
        "provenance",
    }
    missing = sorted(required - set(record))
    if missing:
        raise dk_core.ValidationError(
            f"api lifecycle record {record.get('id')}: missing keys: {', '.join(missing)}"
        )
    if record["is_trusted_knowledge"] is not False:
        raise dk_core.ValidationError(
            f"{record['id']}: a source-derived record is never trusted knowledge"
        )
    if record["symbol"]["kind"] not in SYMBOL_KINDS:
        raise dk_core.ValidationError(f"{record['id']}: unknown symbol kind")
    if record["lifecycle"]["state"] not in LIFECYCLE_STATES:
        raise dk_core.ValidationError(f"{record['id']}: unknown lifecycle state")
    if record["replacement"]["state"] not in ("stated", "stated_none", UNKNOWN):
        raise dk_core.ValidationError(f"{record['id']}: unknown replacement state")
    if record["replacement"]["state"] != "stated" and record["replacement"]["value"] is not None:
        raise dk_core.ValidationError(
            f"{record['id']}: a replacement value without a sourced replacement"
        )
    for version in ("deprecated_version", "removed_version"):
        value = record["lifecycle"][version]
        if value is not None and not re.fullmatch(r"\d+\.\d+\.\d+", value):
            raise dk_core.ValidationError(f"{record['id']}: {version} is not an exact version")
    if not record["provenance"].get("source_snapshot_sha256"):
        raise dk_core.ValidationError(f"{record['id']}: no snapshot provenance")


def validate_change_record(record: dict) -> None:
    required = {
        "record_contract_version",
        "id",
        "record_class",
        "is_trusted_knowledge",
        "change_record",
        "category",
        "symbols",
        "description",
        "provenance",
    }
    missing = sorted(required - set(record))
    if missing:
        raise dk_core.ValidationError(
            f"change record {record.get('id')}: missing keys: {', '.join(missing)}"
        )
    if record["is_trusted_knowledge"] is not False:
        raise dk_core.ValidationError(f"{record['id']}: a change record is never trusted knowledge")
    if record["category"]["value"] not in CHANGE_CATEGORIES:
        raise dk_core.ValidationError(f"{record['id']}: unknown change category")
    if record["symbols"]["lifecycle_asserted"] is not False:
        raise dk_core.ValidationError(
            f"{record['id']}: a change record must not assert symbol lifecycle by itself"
        )
    if not record["provenance"].get("source_snapshot_sha256"):
        raise dk_core.ValidationError(f"{record['id']}: no snapshot provenance")


def validate_api_lifecycle_contract(root: Path = dk_core.ROOT) -> list[str]:
    dk_core.read_json(root / "schema" / "api-lifecycle-record.schema.json")
    dk_core.read_json(root / "schema" / "change-record.schema.json")

    registered = {source["id"] for source in dk_core.load_sources(root)}
    authority = authority_sources(root)
    for source in authority:
        if source["trust"] != "authoritative":
            raise dk_core.ValidationError(
                f"source {source['id']}: API lifecycle authority must be authoritative"
            )
        if (source["api_lifecycle"]).get("authority_kind") not in (
            KIND_DEPRECATION_INDEX,
            KIND_CHANGE_RECORD_FEED,
        ):
            raise dk_core.ValidationError(f"source {source['id']}: unknown authority kind")

    records = iter_lifecycle_records(root)
    for record in records:
        validate_lifecycle_record(record)
        if record["provenance"]["source_id"] not in registered:
            raise dk_core.ValidationError(
                f"{record['id']}: references unregistered source {record['provenance']['source_id']}"
            )

    change_records = iter_change_records(root)
    for record in change_records:
        validate_change_record(record)
        if record["provenance"]["source_id"] not in registered:
            raise dk_core.ValidationError(
                f"{record['id']}: references unregistered source {record['provenance']['source_id']}"
            )

    index = build_index(root)
    return [
        "API_LIFECYCLE_CONTRACT_VALID=PASS",
        f"API_LIFECYCLE_ENGINE_VERSION={ENGINE_VERSION}",
        f"API_LIFECYCLE_AUTHORITY_SOURCES={len(authority)}",
        f"API_LIFECYCLE_RECORDS={len(records)}",
        f"API_LIFECYCLE_MATCHABLE_SYMBOLS={index['record_count']}",
        f"API_CHANGE_RECORDS={len(change_records)}",
        "API_LIFECYCLE_AUTHORITY_OFFICIAL_ONLY=PASS",
        "API_RECORD_NOT_GENERAL_TRUSTED_KNOWLEDGE=PASS",
    ]
