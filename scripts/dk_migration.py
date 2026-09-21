#!/usr/bin/env python3
"""Concrete custom-code migration work, or an honest admission there is none.

Prompt 10 could report that a project's code compatibility was unknown. This
engine narrows that to the only answer worth acting on::

    this file uses this symbol here
    this symbol is deprecated in X and removed from Y, per this source
    for this target that means blocking / recommended / compatible
    this is the replacement the annotation states, or none was stated

Three rules decide whether it is useful or dangerous:

    a name in a comment      != a call
    deprecated               != removed
    no match found           != nothing to migrate

The first is why every observation comes from a lexed token stream rather than
a text search. The second is carried down from the API lifecycle records. The
third is why coverage is a first-class part of every result: this engine knows
one branch's deprecation index and nothing else, and it says so instead of
letting silence read as a clean bill of health.

The engine is read-only. It rewrites no PHP, edits no YAML, runs no Rector and
performs no upgrade. ``execution_performed`` is structurally false.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import dk_api_lifecycle as lifecycle_api
import dk_core
import dk_php_lexer as lexer
import dk_security


ENGINE_NAME = "drupal-knowledge-migration-engine"
ENGINE_VERSION = "0.1"
WORK_ITEM_SCHEMA_VERSION = "0.1"
ANALYSIS_SCHEMA_VERSION = "0.1"

# Migration output is its own result domain, kept apart from security for the
# same reason upgrade compatibility is: a deprecated call is not a vulnerability.
RESULT_DOMAIN = "api_migration"

# --- usage kinds -------------------------------------------------------------

USAGE_FUNCTION_CALL = "function_call"
USAGE_CLASS_REFERENCE = "class_reference"
USAGE_STATIC_CALL = "static_call"
USAGE_CONSTANT = "constant_reference"
USAGE_SERVICE = "service_reference"
USAGE_HOOK = "hook_implementation"

USAGE_KINDS = (
    USAGE_FUNCTION_CALL,
    USAGE_CLASS_REFERENCE,
    USAGE_STATIC_CALL,
    USAGE_CONSTANT,
    USAGE_SERVICE,
    USAGE_HOOK,
)

# --- evidence quality --------------------------------------------------------

EVIDENCE_SYNTAX = "syntax_aware_token_stream"
EVIDENCE_STRUCTURED_YAML = "structured_yaml_value"
EVIDENCE_NON_CODE = "non_code_text_only"

# --- target effects ----------------------------------------------------------

EFFECT_COMPATIBLE = "compatible"
EFFECT_RECOMMENDED = "migration_recommended"
EFFECT_REQUIRED = "migration_required"
EFFECT_BLOCKING = "blocking"
EFFECT_UNKNOWN = "unknown"

EFFECTS = (EFFECT_COMPATIBLE, EFFECT_RECOMMENDED, EFFECT_REQUIRED, EFFECT_BLOCKING, EFFECT_UNKNOWN)

# Only these two mean the project cannot simply leave the code alone.
ACTIONABLE_EFFECTS = (EFFECT_BLOCKING, EFFECT_REQUIRED)

ACTION_REPLACE_SYMBOL = "replace_symbol"
ACTION_REVIEW_SIGNATURE = "review_signature"
ACTION_REVIEW_UNSOURCED = "review_without_stated_replacement"

# Names that are PHP language constructs, never a Drupal API call, and would
# otherwise look like global function calls to the token rules.
PHP_CONSTRUCTS = frozenset(
    {
        "array", "echo", "print", "isset", "unset", "empty", "list", "eval", "exit",
        "die", "include", "include_once", "require", "require_once", "return",
        "if", "elseif", "else", "while", "for", "foreach", "switch", "case",
        "match", "fn", "function", "static", "new", "clone", "throw", "catch",
        "try", "finally", "and", "or", "xor", "instanceof", "yield", "declare",
    }
)

# Where a class name can appear such that it is a reference to that class.
CLASS_CONTEXT_KEYWORDS = frozenset({"new", "extends", "implements", "instanceof", "use", "catch"})

# Relative class references that name no class at all. Resolving these against
# the current namespace invents a class such as ``Drupal\Tests\pa_core\parent``.
RELATIVE_CLASS_KEYWORDS = frozenset({"parent", "self", "static", "class"})

# Words that end a name rather than continue one. Without these, ``return
# \Drupal::service(...)`` reads as the qualified name ``return\Drupal`` and the
# whole statement becomes invisible.
NAME_BREAKING_KEYWORDS = (
    PHP_CONSTRUCTS
    | CLASS_CONTEXT_KEYWORDS
    | frozenset(
        {
            "abstract", "as", "break", "callable", "const", "continue", "default",
            "do", "endif", "enum", "final", "global", "goto", "implements",
            "insteadof", "interface", "namespace", "private", "protected",
            "public", "readonly", "trait", "var",
        }
    )
)

# How many entries of a long list the explain rendering prints before it
# summarizes. Truncation is a display choice; JSON output is never trimmed.
EXPLAIN_SAMPLE = 8

SERVICE_ID_RE = re.compile(r"^[a-z0-9_.]+(?:\.[a-z0-9_.]+)*$")
HOOK_FILE_SUFFIXES = (".module", ".install", ".theme", ".profile", ".engine")


class MigrationInputError(RuntimeError):
    """Caller asked for something the evidence does not describe."""


class MigrationEngineDefect(RuntimeError):
    """A defect in this engine. Never reported as an evidence problem."""


def now_iso(moment: datetime | None = None) -> str:
    return lifecycle_api.now_iso(moment)


def stable_json(data: Any) -> str:
    return dk_core.stable_json(data)


def digest_hex(*parts: Any) -> str:
    accumulator = hashlib.sha256()
    for part in parts:
        accumulator.update(str(part).encode("utf-8"))
        accumulator.update(b"\0")
    return accumulator.hexdigest()


def parse_version(value: Any):
    return dk_security.parse_version(value)


# ---------------------------------------------------------------------------
# Observing usage in one PHP file
#
# Everything here reads the token stream. A name that only ever appears in a
# comment, a docblock or a string literal produces no observation at all.
# ---------------------------------------------------------------------------


def strip_quotes(literal: str) -> str | None:
    if len(literal) < 2 or literal[0] != literal[-1] or literal[0] not in "'\"":
        return None
    body = literal[1:-1]
    if literal[0] == "'":
        return body.replace("\\'", "'").replace("\\\\", "\\")
    if "$" in body or "{" in body:
        # An interpolated string is not a literal value this engine can read.
        return None
    return body


def read_use_map(tokens: list[lexer.Token]) -> tuple[str | None, dict[str, str]]:
    """The file's namespace and its ``use`` aliases.

    Without this a short class name means nothing: matching a bare ``Action``
    or ``Image`` against project code finds words, not classes.
    """
    namespace: str | None = None
    aliases: dict[str, str] = {}
    index = 0
    depth = 0

    while index < len(tokens):
        token = tokens[index]
        if token.type == lexer.T_OPERATOR and token.value == "{":
            depth += 1
        elif token.type == lexer.T_OPERATOR and token.value == "}":
            depth = max(0, depth - 1)

        if token.type == lexer.T_IDENT and token.value in ("namespace", "use") and depth == 0:
            keyword = token.value
            index += 1
            parts: list[str] = []
            alias: str | None = None
            seen_as = False
            group_base: str | None = None
            while index < len(tokens):
                item = tokens[index]
                if item.type == lexer.T_OPERATOR and item.value in (";", "{"):
                    if item.value == "{" and keyword == "use":
                        # A grouped use statement: use A\B\{C, D as E};
                        group_base = "\\".join(parts)
                        index += 1
                        member: list[str] = []
                        member_alias: str | None = None
                        member_seen_as = False
                        while index < len(tokens):
                            entry = tokens[index]
                            if entry.type == lexer.T_OPERATOR and entry.value in (",", "}"):
                                if member:
                                    full = f"{group_base}\\" + "\\".join(member)
                                    aliases[member_alias or member[-1]] = full
                                member, member_alias, member_seen_as = [], None, False
                                if entry.value == "}":
                                    break
                            elif entry.type == lexer.T_IDENT:
                                if entry.value == "as":
                                    member_seen_as = True
                                elif member_seen_as:
                                    member_alias = entry.value
                                else:
                                    member.append(entry.value)
                            index += 1
                    break
                if item.type == lexer.T_IDENT:
                    if item.value == "as":
                        seen_as = True
                    elif seen_as:
                        alias = item.value
                    elif item.value in ("function", "const"):
                        pass
                    else:
                        parts.append(item.value)
                index += 1
            if group_base is None and parts:
                full = "\\".join(parts)
                if keyword == "namespace":
                    namespace = full
                else:
                    aliases[alias or parts[-1]] = full
        index += 1

    return namespace, aliases


def starts_name(tokens: list[lexer.Token], index: int) -> bool:
    """Whether the identifier at ``index`` begins a name rather than continues one.

    ``A\\B`` is one name, so ``B`` does not start one. ``\\Drupal`` is a
    root-qualified name, so ``Drupal`` does. Getting this wrong is how
    ``\\Drupal::messenger()`` becomes ``Drupal\\pa_actions\\...\\Drupal::messenger``.
    """
    return not continues_name(tokens, index)


def continues_name(tokens: list[lexer.Token], index: int) -> bool:
    r"""Whether the identifier at ``index`` continues a qualified name.

    Only a backslash that follows part of a name is a namespace separator. A
    backslash following a keyword is the root-namespace marker, which is how
    ``return \Drupal::service()`` differs from ``Foo\Bar``.
    """
    if index < 2:
        return False
    previous = tokens[index - 1]
    if previous.type != lexer.T_OPERATOR or previous.value != "\\":
        return False
    before = tokens[index - 2]
    return before.type == lexer.T_IDENT and before.value.lower() not in NAME_BREAKING_KEYWORDS


def root_qualified(tokens: list[lexer.Token], index: int) -> bool:
    """Whether the name at ``index`` is written with a leading backslash."""
    if index == 0:
        return False
    previous = tokens[index - 1]
    if previous.type != lexer.T_OPERATOR or previous.value != "\\":
        return False
    return not continues_name(tokens, index)


def governing_keyword(tokens: list[lexer.Token], index: int) -> lexer.Token | None:
    r"""The keyword that introduces the name starting at ``index``, if any.

    ``new Foo`` and ``new \Vendor\Foo`` are both a class reference, so the
    root-namespace backslash must not hide the ``new`` behind it.
    """
    if index == 0:
        return None
    previous = tokens[index - 1]
    if previous.type == lexer.T_IDENT:
        return previous
    if previous.type == lexer.T_OPERATOR and previous.value == "\\" and root_qualified(tokens, index):
        candidate = tokens[index - 2] if index >= 2 else None
        if candidate is not None and candidate.type == lexer.T_IDENT:
            return candidate
    return None


def read_qualified_name(tokens: list[lexer.Token], start: int) -> tuple[str, int]:
    """A possibly namespace-qualified name beginning at ``start``."""
    parts: list[str] = []
    index = start
    while index < len(tokens):
        token = tokens[index]
        if token.type != lexer.T_IDENT:
            break
        parts.append(token.value)
        index += 1
        if (
            index < len(tokens)
            and tokens[index].type == lexer.T_OPERATOR
            and tokens[index].value == "\\"
            and index + 1 < len(tokens)
            and tokens[index + 1].type == lexer.T_IDENT
        ):
            index += 1
            continue
        break
    name = "\\".join(parts)
    if name and root_qualified(tokens, start):
        name = "\\" + name
    return name, index


def resolve_class(name: str, namespace: str | None, aliases: dict[str, str]) -> str | None:
    """Turn a written class reference into a fully qualified name."""
    if not name:
        return None
    if name.lower() in RELATIVE_CLASS_KEYWORDS:
        # parent, self and static name a class only at runtime.
        return None
    if name.startswith("\\"):
        return name.lstrip("\\")
    head, _, rest = name.partition("\\")
    if head in aliases:
        return aliases[head] + ("\\" + rest if rest else "")
    if namespace:
        return f"{namespace}\\{name}"
    return name


def observe_php(relative_path: str, source: str, component: str | None) -> dict:
    """Every API usage this engine is prepared to stand behind, in one file."""
    tokens = lexer.tokenize(source)
    namespace, aliases = read_use_map(tokens)
    code = lexer.code_tokens(tokens)

    observations: list[dict] = []
    unsupported: list[dict] = []

    def add(kind: str, symbol: str, line: int, detail: dict | None = None) -> None:
        observations.append(
            {
                "usage_kind": kind,
                "symbol": symbol,
                "path": relative_path,
                "line": line,
                "component": component,
                "evidence_quality": EVIDENCE_SYNTAX,
                "detail": detail or {},
            }
        )

    index = 0
    while index < len(code):
        token = code[index]
        previous = code[index - 1] if index else None
        following = code[index + 1] if index + 1 < len(code) else None

        if token.type == lexer.T_IDENT:
            value = token.value
            lowered = value.lower()

            # A class name in a position that can only mean "this class".
            keyword = governing_keyword(code, index)
            if (
                keyword is not None
                and keyword.value.lower() in CLASS_CONTEXT_KEYWORDS
                and lowered not in PHP_CONSTRUCTS
                and starts_name(code, index)
            ):
                name, _ = read_qualified_name(code, index)
                resolved = resolve_class(name, namespace, aliases)
                if resolved and keyword.value.lower() != "use":
                    add(USAGE_CLASS_REFERENCE, resolved, token.line, {"context": keyword.value})

            # X::something — a static reference through a resolvable class.
            if (
                following is not None
                and following.type == lexer.T_OPERATOR
                and following.value == "::"
                and starts_name(code, index)
            ):
                name, after = read_qualified_name(code, index)
                if after < len(code) and code[after].type == lexer.T_OPERATOR and code[after].value == "::":
                    member = code[after + 1] if after + 1 < len(code) else None
                    resolved = resolve_class(name, namespace, aliases)
                    if resolved and member is not None and member.type == lexer.T_IDENT:
                        call = (
                            after + 2 < len(code)
                            and code[after + 2].type == lexer.T_OPERATOR
                            and code[after + 2].value == "("
                        )
                        add(
                            USAGE_STATIC_CALL if call else USAGE_CONSTANT,
                            f"{resolved}::{member.value}",
                            token.line,
                            {"class": resolved, "member": member.value},
                        )
                        # A service fetched by id through the container.
                        if resolved == "Drupal" and member.value == "service" and call:
                            literal = code[after + 3] if after + 3 < len(code) else None
                            service = (
                                strip_quotes(literal.value)
                                if literal is not None and literal.type == lexer.T_STRING_LITERAL
                                else None
                            )
                            if service and SERVICE_ID_RE.match(service):
                                add(USAGE_SERVICE, service, token.line, {"via": "Drupal::service"})
                            elif literal is not None:
                                unsupported.append(
                                    {
                                        "path": relative_path,
                                        "line": token.line,
                                        "construct": "dynamic_service_id",
                                        "reason": (
                                            "The service id is not a plain string literal, so "
                                            "the referenced service cannot be observed."
                                        ),
                                    }
                                )
                        index = after + 2
                        continue

            # A global function call: name immediately followed by "(", not a
            # method, not a static call, not a declaration.
            if (
                following is not None
                and following.type == lexer.T_OPERATOR
                and following.value == "("
                and lowered not in PHP_CONSTRUCTS
            ):
                preceded_by_arrow = previous is not None and previous.type == lexer.T_OPERATOR and previous.value in ("->", "?->", "::")
                declared = previous is not None and previous.type == lexer.T_IDENT and previous.value.lower() in ("function", "new")
                if not preceded_by_arrow and not declared:
                    qualified = previous is not None and previous.type == lexer.T_OPERATOR and previous.value == "\\"
                    namespaced = (
                        previous is not None
                        and previous.type == lexer.T_OPERATOR
                        and previous.value == "\\"
                        and index >= 2
                        and code[index - 2].type == lexer.T_IDENT
                    )
                    if not namespaced:
                        add(
                            USAGE_FUNCTION_CALL,
                            value,
                            token.line,
                            {"root_namespaced": bool(qualified)},
                        )

            # A container service fetched from a variable literally named
            # $container. Anything looser would guess.
            if (
                value == "get"
                and previous is not None
                and previous.type == lexer.T_OPERATOR
                and previous.value in ("->", "?->")
                and index >= 2
                and code[index - 2].type == lexer.T_VARIABLE
                and code[index - 2].value == "$container"
                and following is not None
                and following.value == "("
            ):
                literal = code[index + 2] if index + 2 < len(code) else None
                service = (
                    strip_quotes(literal.value)
                    if literal is not None and literal.type == lexer.T_STRING_LITERAL
                    else None
                )
                if service and SERVICE_ID_RE.match(service):
                    add(USAGE_SERVICE, service, token.line, {"via": "container->get"})

        index += 1

    # Hook implementations, which only exist in procedural extension files.
    name = Path(relative_path).name
    for suffix in HOOK_FILE_SUFFIXES:
        if not name.endswith(suffix):
            continue
        module = name[: -len(suffix)]
        for position, token in enumerate(code):
            if (
                token.type == lexer.T_IDENT
                and token.value.lower() == "function"
                and position + 2 < len(code)
                and code[position + 1].type == lexer.T_IDENT
                and code[position + 2].type == lexer.T_OPERATOR
                and code[position + 2].value == "("
            ):
                declared = code[position + 1].value
                if declared.startswith(f"{module}_") and len(declared) > len(module) + 1:
                    add(
                        USAGE_HOOK,
                        f"hook_{declared[len(module) + 1:]}",
                        code[position + 1].line,
                        {"implementation": declared, "module": module},
                    )
        break

    return {
        "observations": observations,
        "unsupported": unsupported,
        "namespace": namespace,
        "use_aliases": dict(sorted(aliases.items())),
        "tokens": tokens,
    }


def observe_yaml_services(relative_path: str, source: str, component: str | None) -> dict:
    """Service ids a ``*.services.yml`` file references as arguments.

    Read from the structured ``'@service.id'`` form only. A service named in a
    comment or in free text is not a reference.
    """
    observations: list[dict] = []
    for number, raw in enumerate(source.splitlines(), start=1):
        line = raw.split("#", 1)[0]
        for match in re.finditer(r"['\"]?@([a-z0-9_][a-z0-9_.]*)['\"]?", line):
            service = match.group(1)
            if not SERVICE_ID_RE.match(service):
                continue
            observations.append(
                {
                    "usage_kind": USAGE_SERVICE,
                    "symbol": service,
                    "path": relative_path,
                    "line": number,
                    "component": component,
                    "evidence_quality": EVIDENCE_STRUCTURED_YAML,
                    "detail": {"via": "services_yml_argument"},
                }
            )
    return {"observations": observations, "unsupported": []}


# ---------------------------------------------------------------------------
# Target-aware lifecycle matching
# ---------------------------------------------------------------------------


def effect_for(record: dict, target: str) -> dict:
    """What one lifecycle record means for one target version.

    Version boundaries are exact. A symbol deprecated in 10.3.0 is current for
    a 10.2.0 target, and a symbol removed in 11.0.0 is merely deprecated for a
    10.6.0 one. Neither is rounded to its major.
    """
    target_version = parse_version(target)
    if target_version is None:
        return {"effect": EFFECT_UNKNOWN, "reason": f"Target {target!r} could not be read."}

    state = record["lifecycle"]
    deprecated = parse_version(state["deprecated_version"])
    removed = parse_version(state["removed_version"])

    if not state["annotation_parsed"] or (deprecated is None and removed is None):
        return {
            "effect": EFFECT_UNKNOWN,
            "reason": (
                "The authoritative annotation does not state version boundaries, so its "
                "effect on this target is unknown."
            ),
        }

    if removed is not None and target_version.key >= removed.key:
        return {
            "effect": EFFECT_BLOCKING,
            "reason": (
                f"Removed from Drupal {state['removed_version']}, which is at or below "
                f"the target {target}."
            ),
        }
    if deprecated is not None and target_version.key >= deprecated.key:
        return {
            "effect": EFFECT_RECOMMENDED,
            "reason": (
                f"Deprecated in Drupal {state['deprecated_version']} and still available at "
                f"the target {target}"
                + (f"; removed from {state['removed_version']}." if removed else ".")
            ),
        }
    return {
        "effect": EFFECT_COMPATIBLE,
        "reason": (
            f"Not deprecated until Drupal {state['deprecated_version']}, which is above the "
            f"target {target}."
        ),
    }


def relevance_of(usage_kind: str, symbol: str) -> str:
    """A display aid, and only that.

    It says whether a symbol is visibly Drupal's, so an operator reading the
    unmatched list sees ``node_load`` before ``json_encode``. It is not a
    lifecycle judgement: a global function cannot be told apart from a PHP
    builtin without a list of builtins this engine does not have, so those stay
    unclassified rather than being called irrelevant.
    """
    if usage_kind == USAGE_HOOK:
        return "hook"
    if symbol.startswith("Drupal\\") or symbol == "Drupal" or symbol.startswith("Drupal::"):
        return "drupal_namespaced"
    if usage_kind == USAGE_SERVICE:
        return "service_id"
    if usage_kind in (USAGE_CLASS_REFERENCE, USAGE_STATIC_CALL, USAGE_CONSTANT):
        return "third_party_namespaced"
    return "unclassified_global"


def lookup(observation: dict, index: dict) -> dict | None:
    """The lifecycle record for one observation, matched on exact identity."""
    kind = observation["usage_kind"]
    symbol = observation["symbol"]
    if kind == USAGE_FUNCTION_CALL:
        return index["functions"].get(symbol)
    if kind == USAGE_CLASS_REFERENCE:
        return index["classes"].get(symbol)
    if kind == USAGE_STATIC_CALL:
        return index["methods"].get(symbol) or index["classes"].get(symbol.split("::")[0])
    if kind == USAGE_CONSTANT:
        return index["constants"].get(symbol) or index["classes"].get(symbol.split("::")[0])
    if kind == USAGE_SERVICE:
        return index["services"].get(symbol)
    return None


def suggested_action(record: dict, effect: str) -> dict:
    replacement = record["replacement"]
    if effect in (EFFECT_COMPATIBLE, EFFECT_UNKNOWN):
        return {"category": None, "detail": None}
    if replacement["state"] == "stated":
        return {
            "category": ACTION_REPLACE_SYMBOL,
            "detail": f"The annotation states the replacement: {replacement['value']}",
        }
    if replacement["state"] == "stated_none":
        return {
            "category": ACTION_REVIEW_UNSOURCED,
            "detail": (
                "The annotation states there is no replacement, so the code must be "
                "reworked rather than substituted."
            ),
        }
    return {
        "category": ACTION_REVIEW_UNSOURCED,
        "detail": (
            "No replacement is stated by the authoritative annotation. Drupal Knowledge "
            "does not invent an equivalent API."
        ),
    }


# ---------------------------------------------------------------------------
# Work items
# ---------------------------------------------------------------------------


def work_item_id(project_fingerprint: str, target: str, symbol: str, usage_kind: str) -> str:
    return "migration-work." + digest_hex(
        WORK_ITEM_SCHEMA_VERSION, project_fingerprint, target, usage_kind, symbol
    )[:16]


def build_work_item(
    project_fingerprint: str,
    target: str,
    usage_kind: str,
    symbol: str,
    occurrences: list[dict],
    record: dict,
    effect: dict,
) -> dict:
    """One actionable item, however many records or occurrences produced it.

    Occurrences are preserved in full: a removed API used in twelve places is
    twelve pieces of work, and a migration plan that hides eleven of them is
    worse than useless. Provenance is likewise a list, because more than one
    authoritative record can describe the same lifecycle event without that
    being two separate tasks.
    """
    action = suggested_action(record, effect["effect"])
    return {
        "schema_version": WORK_ITEM_SCHEMA_VERSION,
        "work_item_id": work_item_id(project_fingerprint, target, symbol, usage_kind),
        "result_domain": RESULT_DOMAIN,
        "target_drupal_version": target,
        "project_fingerprint": project_fingerprint,
        "usage": {
            "usage_kind": usage_kind,
            "symbol": symbol,
            "occurrence_count": len(occurrences),
            "components": sorted({item["component"] for item in occurrences if item["component"]}),
            "evidence_quality": sorted({item["evidence_quality"] for item in occurrences}),
        },
        "occurrences": [
            {
                "path": item["path"],
                "line": item["line"],
                "component": item["component"],
                "usage_kind": item["usage_kind"],
                "evidence_quality": item["evidence_quality"],
            }
            for item in sorted(occurrences, key=lambda entry: (entry["path"], entry["line"]))
        ],
        "lifecycle": {
            "state": record["lifecycle"]["state"],
            "deprecated_version": record["lifecycle"]["deprecated_version"],
            "removed_version": record["lifecycle"]["removed_version"],
            "changed_version": record["lifecycle"]["changed_version"],
            "source_annotation": record["lifecycle"]["source_annotation"],
            "symbol_kind": record["symbol"]["kind"],
            "core_file": record["symbol"]["core_file"],
        },
        "target_effect": {
            "effect": effect["effect"],
            "reason": effect["reason"],
            "blocking": effect["effect"] == EFFECT_BLOCKING,
        },
        "suggested_migration": {
            "replacement_state": record["replacement"]["state"],
            "replacement": record["replacement"]["value"],
            "action_category": action["category"],
            "action_detail": action["detail"],
            "semantics": (
                "A replacement is reported only when the authoritative annotation states "
                "one. Nothing here has been applied to the project."
            ),
        },
        "provenance": [
            {
                "record_id": record["id"],
                "source_id": record["provenance"]["source_id"],
                "source_url": record["provenance"]["source_url"],
                "source_snapshot_sha256": record["provenance"]["source_snapshot_sha256"],
                "authority_kind": record["provenance"]["authority_kind"],
            }
        ],
        "limitations": [
            (
                "Usage was observed from a lexed token stream, not a full PHP parse. A "
                "call built at runtime is not visible to it."
            ),
            (
                "Only symbols present in the registered deprecation index can be matched. "
                "A symbol outside it produces no item, which is not evidence that it is fine."
            ),
        ],
        "execution_performed": False,
    }


def merge_provenance(item: dict, record: dict) -> None:
    """Add a second authoritative record to one item rather than duplicating it."""
    entry = {
        "record_id": record["id"],
        "source_id": record["provenance"]["source_id"],
        "source_url": record["provenance"]["source_url"],
        "source_snapshot_sha256": record["provenance"]["source_snapshot_sha256"],
        "authority_kind": record["provenance"]["authority_kind"],
    }
    if entry not in item["provenance"]:
        item["provenance"].append(entry)
        item["provenance"].sort(key=lambda value: value["record_id"])


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def require_analysis(analysis: Any) -> dict:
    if not isinstance(analysis, dict) or "profile" not in analysis:
        raise MigrationInputError("input is not a project analyzer result")
    if analysis.get("analyzer", {}).get("name") != "drupal-project-analyzer":
        raise MigrationInputError(
            "input was not produced by the Drupal Knowledge project analyzer"
        )
    return analysis


def custom_code_fact(analysis: dict) -> dict | None:
    fact = (analysis.get("profile", {}).get("facts", {}) or {}).get("custom_code_files") or {}
    if fact.get("state") != "known":
        return None
    return fact.get("value")


def project_fingerprint(analysis: dict, inventory: dict) -> str:
    """Identity of exactly this code, so the same revision gives the same items."""
    return digest_hex(
        analysis.get("project_id", ""),
        stable_json([[item["path"], item["sha256"]] for item in inventory["files"]]),
    )


def observe_project(analysis: dict, project_path: str | Path | None) -> dict:
    """Observe API usage across every inventoried custom PHP file.

    The single place in the product that re-reads project source. Both this
    engine and the project-evidence layer call it, so PHP is read once, one
    way, and a file whose content no longer matches the inventory is skipped
    rather than attributed to code that was never analysed.
    """
    inventory = custom_code_fact(analysis)
    observations: list[dict] = []
    unsupported: list[dict] = []
    unreadable: list[dict] = []
    files_read = 0

    if inventory is None:
        return {
            "observations": observations,
            "unsupported": unsupported,
            "unreadable": unreadable,
            "files_read": 0,
            "inventory": None,
        }

    base = Path(project_path).resolve() if project_path else None
    for entry in inventory["files"]:
        if base is None:
            unreadable.append({"path": entry["path"], "reason": "no_project_path_supplied"})
            continue
        path = base / entry["path"]
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            raw = path.read_bytes()
        except OSError:
            unreadable.append({"path": entry["path"], "reason": "unreadable"})
            continue
        if "sha256:" + hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            # The inventory describes a different revision of this file. Reading
            # it anyway would attribute findings to code that was not analysed.
            unreadable.append({"path": entry["path"], "reason": "content_changed_since_inventory"})
            continue
        files_read += 1
        if entry["language"] == "php":
            result = observe_php(entry["path"], source, entry["component"])
            observations.extend(result["observations"])
            unsupported.extend(result["unsupported"])
        elif entry["path"].endswith(".services.yml"):
            result = observe_yaml_services(entry["path"], source, entry["component"])
            observations.extend(result["observations"])

    return {
        "observations": observations,
        "unsupported": unsupported,
        "unreadable": unreadable,
        "files_read": files_read,
        "inventory": inventory,
    }


def analyze(
    analysis: Any,
    target: str,
    root: Path = dk_core.ROOT,
    project_path: str | Path | None = None,
    generated_at: str | None = None,
) -> dict:
    """Analyse one project against one target. Nothing is modified anywhere."""
    analysis = require_analysis(analysis)
    if not isinstance(target, str) or not target.strip():
        raise MigrationInputError("a target version is required")
    target = target.strip()
    if parse_version(target) is None:
        raise MigrationInputError(f"target {target!r} is not a readable Drupal version")

    index = lifecycle_api.build_index(root)
    coverage_block = lifecycle_api.coverage(root)
    inventory = custom_code_fact(analysis)

    if inventory is None:
        return finalize(
            analysis,
            target,
            fingerprint="unknown",
            items=[],
            unmatched=[],
            observations=0,
            files_read=0,
            unsupported=[],
            unreadable=[],
            non_code=[],
            inventory=None,
            index=index,
            coverage_block=coverage_block,
            generated_at=generated_at,
        )

    base = Path(project_path).resolve() if project_path else None
    fingerprint = project_fingerprint(analysis, inventory)

    observed = observe_project(analysis, project_path)
    observations = observed["observations"]
    unsupported = observed["unsupported"]
    unreadable = observed["unreadable"]
    files_read = observed["files_read"]

    # Group into work items: one per (usage kind, symbol), occurrences kept.
    grouped: dict[tuple[str, str], list[dict]] = {}
    for observation in observations:
        grouped.setdefault((observation["usage_kind"], observation["symbol"]), []).append(observation)

    items: dict[str, dict] = {}
    unmatched: list[dict] = []
    for (usage_kind, symbol), occurrences in sorted(grouped.items()):
        record = lookup({"usage_kind": usage_kind, "symbol": symbol}, index)
        if record is None:
            # Observed in code and not listed as deprecated on any indexed
            # branch. That is weak evidence, not good news: the index lists
            # deprecated symbols, so absence covers both "still current" and
            # "removed before the indexed branch, and therefore already gone".
            # node_load() is the second, which is why these are reported.
            unmatched.append(
                {
                    "usage_kind": usage_kind,
                    "symbol": symbol,
                    "occurrence_count": len(occurrences),
                    "occurrences": [
                        {"path": item["path"], "line": item["line"]}
                        for item in sorted(occurrences, key=lambda entry: (entry["path"], entry["line"]))
                    ],
                    "lifecycle": EFFECT_UNKNOWN,
                    "relevance": relevance_of(usage_kind, symbol),
                    "reason": (
                        "The registered deprecation index lists deprecated symbols and "
                        "does not list this one. That is not proof it is current: a "
                        "symbol removed before the indexed branch is also absent."
                    ),
                }
            )
            continue
        effect = effect_for(record, target)
        item = build_work_item(fingerprint, target, usage_kind, symbol, occurrences, record, effect)
        if item["work_item_id"] in items:
            merge_provenance(items[item["work_item_id"]], record)
            continue
        items[item["work_item_id"]] = item

    # Names the engine found only in text a human wrote, reported so that the
    # decision not to treat them as usage is visible rather than silent.
    non_code: list[dict] = []
    if base is not None:
        watched = set(index["functions"]) | {name.split("\\")[-1] for name in index["classes"]}
        for entry in inventory["files"]:
            if entry["language"] != "php":
                continue
            path = base / entry["path"]
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            tokens = lexer.tokenize(source)
            for name in sorted(watched):
                if name not in source:
                    continue
                if any(
                    observation["symbol"].endswith(name) and observation["path"] == entry["path"]
                    for observation in observations
                ):
                    continue
                for occurrence in lexer.non_code_occurrences(tokens, name):
                    non_code.append(
                        {
                            "path": entry["path"],
                            "line": occurrence["line"],
                            "symbol": name,
                            "found_in": occurrence["kind"],
                            "evidence_quality": EVIDENCE_NON_CODE,
                            "treated_as_usage": False,
                        }
                    )

    return finalize(
        analysis,
        target,
        fingerprint=fingerprint,
        items=sorted(items.values(), key=lambda item: item["work_item_id"]),
        unmatched=sorted(unmatched, key=lambda item: (item["usage_kind"], item["symbol"])),
        observations=len(observations),
        files_read=files_read,
        unsupported=unsupported,
        unreadable=unreadable,
        non_code=sorted(non_code, key=lambda item: (item["path"], item["line"], item["symbol"])),
        inventory=inventory,
        index=index,
        coverage_block=coverage_block,
        generated_at=generated_at,
    )


def finalize(
    analysis: dict,
    target: str,
    *,
    fingerprint: str,
    items: list[dict],
    unmatched: list[dict],
    observations: int,
    files_read: int,
    unsupported: list[dict],
    unreadable: list[dict],
    non_code: list[dict],
    inventory: dict | None,
    index: dict,
    coverage_block: dict,
    generated_at: str | None,
) -> dict:
    by_effect = {effect: 0 for effect in EFFECTS}
    for item in items:
        by_effect[item["target_effect"]["effect"]] += 1

    blocking = [item for item in items if item["target_effect"]["effect"] == EFFECT_BLOCKING]
    required = [item for item in items if item["target_effect"]["effect"] == EFFECT_REQUIRED]

    unknowns: list[dict] = []
    if inventory is None:
        unknowns.append(
            {
                "subject": "custom code inventory",
                "detail": (
                    "The analyzer profile carries no custom-code inventory, so no usage "
                    "could be observed and code compatibility remains unknown."
                ),
            }
        )
    if inventory is not None and files_read == 0:
        unknowns.append(
            {
                "subject": "source access",
                "detail": (
                    "No inventoried file was read, so no usage could be observed. This is "
                    "not evidence that the project uses nothing."
                ),
            }
        )
    if unreadable:
        unknowns.append(
            {
                "subject": "unread files",
                "detail": (
                    f"{len(unreadable)} inventoried file(s) could not be read as analysed, so "
                    "their usage is unknown."
                ),
            }
        )
    if unsupported:
        unknowns.append(
            {
                "subject": "unsupported constructs",
                "detail": (
                    f"{len(unsupported)} construct(s) need semantics this engine does not "
                    "have, so any API they reach is unobserved."
                ),
            }
        )
    if unmatched:
        unknowns.append(
            {
                "subject": "observed symbols not listed as deprecated",
                "detail": (
                    f"{len(unmatched)} observed symbol(s) have no entry in the registered "
                    "deprecation index. Most will simply be current APIs, but a symbol "
                    "removed before the indexed branch is absent for the opposite reason, "
                    "so absence settles nothing on its own."
                ),
            }
        )
    unknowns.append(
        {
            "subject": "lifecycle corpus coverage",
            "detail": (
                "Only Drupal source branch(es) "
                f"{', '.join(index['covered_source_branches']) or 'none'} have a registered "
                "deprecation index. A symbol outside it produces no work item, and that "
                "absence is not evidence that the code is compatible."
            ),
        }
    )
    unknowns.append(
        {
            "subject": "call sites needing semantics",
            "detail": (
                "Usage is observed from a token stream. Dynamic calls, interpolated "
                "strings and reflection are outside what it can see."
            ),
        }
    )

    analysis_id = "migration-analysis." + digest_hex(
        ANALYSIS_SCHEMA_VERSION,
        ENGINE_VERSION,
        fingerprint,
        target,
        stable_json([item["work_item_id"] for item in items]),
    )[:16]

    payload = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "analysis_id": analysis_id,
        "result_domain": RESULT_DOMAIN,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "deterministic": True,
            "language_model_used": False,
            "produces_trusted_knowledge": False,
        },
        "generated_at": generated_at or now_iso(),
        "project": {
            "project_id": analysis.get("project_id"),
            "facts_source": "drupal_project_analyzer_profile_facts",
            "project_fingerprint": fingerprint,
            "current_core_version": (
                (analysis.get("profile", {}).get("facts", {}).get("drupal_core_version", {}) or {})
                .get("value", {})
                or {}
            ).get("version"),
        },
        "target": {"drupal_version": target},
        "summary": {
            "custom_components_scanned": (
                inventory["counts"]["components"] if inventory else 0
            ),
            "files_inventoried": inventory["counts"]["files"] if inventory else 0,
            "files_read": files_read,
            "observations": observations,
            "work_items": len(items),
            "by_effect": by_effect,
            "blocking_items": len(blocking),
            "non_blocking_items": len(items) - len(blocking) - len(required),
            "migration_required_items": len(required),
            "occurrences": sum(item["usage"]["occurrence_count"] for item in items),
            "non_code_matches_rejected": len(non_code),
            "observed_symbols_without_lifecycle_record": len(unmatched),
        },
        "work_items": items,
        "observed_without_lifecycle_record": unmatched,
        "rejected_non_code_matches": non_code,
        "unsupported_constructs": sorted(
            unsupported, key=lambda item: (item["path"], item["line"], item["construct"])
        ),
        "unread_files": sorted(unreadable, key=lambda item: item["path"]),
        "unknowns": unknowns,
        "coverage": {
            "custom_code": {
                "scope": inventory["scan"]["scope"] if inventory else "unavailable",
                "config_id": inventory["scan"]["config_id"] if inventory else None,
                "config_digest": inventory["scan"]["config_digest"] if inventory else None,
                "languages_supported": ["php", "yaml"],
                "php_analysis": "syntax_aware_lexer_not_full_parser",
                "yaml_analysis": "service_argument_references_only",
                "files_inventoried": inventory["counts"]["files"] if inventory else 0,
                "files_read": files_read,
                "files_skipped_by_scan": inventory["counts"]["skipped"] if inventory else 0,
                "truncated": inventory["scan"]["truncated"] if inventory else False,
                # Contributed and vendored source is out of scope by default;
                # its compatibility is package metadata, not source inspection.
                "contrib_source_scanned": False,
                "vendor_scanned": False,
            },
            "lifecycle_authority": coverage_block,
            "unsupported_constructs": [
                "dynamic and variable function calls",
                "symbols reached through reflection or call_user_func",
                "string interpolation",
                "runtime service ids that are not plain literals",
                "Twig templates",
                "JavaScript",
            ],
            "statement": (
                "Finding no match is not a compatibility proof. It means nothing matched "
                "within the scope and corpus described here."
            ),
        },
        "relationship_to_security": (
            "An API migration item is not a security finding. It becomes one only if "
            "independent security evidence says so."
        ),
        "execution": {
            "execution_performed": False,
            "code_modified": False,
            "files_written": False,
            "rector_invoked": False,
            "composer_invoked": False,
        },
        "trusted_knowledge_mutations": {
            "knowledge_records": 0,
            "reviewed_context": 0,
            "advisories": 0,
            "solved_cases": 0,
            "source_snapshots": 0,
        },
    }
    validate_analysis(payload)
    return payload


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def validate_analysis(payload: dict) -> None:
    required = {
        "schema_version",
        "analysis_id",
        "result_domain",
        "engine",
        "generated_at",
        "project",
        "target",
        "summary",
        "work_items",
        "coverage",
        "unknowns",
        "execution",
        "trusted_knowledge_mutations",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise MigrationEngineDefect(f"migration analysis missing keys: {', '.join(missing)}")
    if payload["result_domain"] != RESULT_DOMAIN:
        raise MigrationEngineDefect("migration output must declare the api_migration domain")
    for value in payload["execution"].values():
        if value is not False:
            raise MigrationEngineDefect("the migration engine never modifies a project")
    for count in payload["trusted_knowledge_mutations"].values():
        if count != 0:
            raise MigrationEngineDefect("the migration engine never mutates trusted knowledge")
    for item in payload["work_items"]:
        if item["target_effect"]["effect"] not in EFFECTS:
            raise MigrationEngineDefect(f"unknown target effect in {item['work_item_id']}")
        if item["execution_performed"] is not False:
            raise MigrationEngineDefect("a work item must never report itself as performed")
        if not item["provenance"]:
            raise MigrationEngineDefect(f"work item {item['work_item_id']} carries no provenance")
        if item["usage"]["occurrence_count"] != len(item["occurrences"]):
            raise MigrationEngineDefect(
                f"work item {item['work_item_id']} lost occurrences"
            )
        migration = item["suggested_migration"]
        if migration["replacement_state"] != "stated" and migration["replacement"] is not None:
            raise MigrationEngineDefect(
                f"work item {item['work_item_id']} carries an unsourced replacement"
            )


def render(payload: dict) -> str:
    lines: list[str] = []
    summary = payload["summary"]
    lines.append(f"API MIGRATION ANALYSIS {payload['analysis_id']}")
    lines.append(f"  result domain      {payload['result_domain']}")
    lines.append(f"  project            {payload['project']['project_id']}")
    lines.append(f"  current core       {payload['project']['current_core_version'] or 'unknown'}")
    lines.append(f"  target             {payload['target']['drupal_version']}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"  custom components  {summary['custom_components_scanned']}")
    lines.append(f"  files inventoried  {summary['files_inventoried']} (read {summary['files_read']})")
    lines.append(f"  observed usages    {summary['observations']}")
    lines.append(f"  work items         {summary['work_items']} across {summary['occurrences']} occurrence(s)")
    lines.append(f"  blocking           {summary['blocking_items']}")
    lines.append(f"  migration required {summary['migration_required_items']}")
    lines.append(f"  non-blocking       {summary['non_blocking_items']}")
    lines.append(f"  text-only rejected {summary['non_code_matches_rejected']}")

    if payload["work_items"]:
        lines.append("")
        lines.append("WORK ITEMS")
        for item in sorted(
            payload["work_items"],
            key=lambda entry: (
                EFFECTS.index(entry["target_effect"]["effect"]),
                entry["usage"]["symbol"],
            ),
            reverse=True,
        ):
            usage = item["usage"]
            state = item["lifecycle"]
            lines.append(
                f"  [{item['target_effect']['effect']}] {usage['symbol']} "
                f"({usage['usage_kind']}, {usage['occurrence_count']} occurrence(s))"
            )
            lines.append(
                f"      deprecated {state['deprecated_version'] or 'unknown'} -> "
                f"removed {state['removed_version'] or 'unknown'}"
            )
            lines.append(f"      {item['target_effect']['reason']}")
            replacement = item["suggested_migration"]
            lines.append(
                f"      replacement: {replacement['replacement'] or replacement['replacement_state']}"
            )
            for occurrence in item["occurrences"]:
                lines.append(f"        {occurrence['path']}:{occurrence['line']}")
            lines.append(f"      evidence: {item['provenance'][0]['source_id']}")

    unmatched = payload["observed_without_lifecycle_record"]
    if unmatched:
        lines.append("")
        lines.append(f"NOT LISTED AS DEPRECATED ({len(unmatched)} observed symbol(s))")
        lines.append(
            "  The index lists deprecated symbols. Absence usually means current, but a "
            "symbol removed before the indexed branch is absent too, so this is not a"
        )
        lines.append("  pass. Sampled below; --format json lists every one.")
        for entry in unmatched[:EXPLAIN_SAMPLE]:
            where = ", ".join(
                f"{item['path']}:{item['line']}" for item in entry["occurrences"][:2]
            )
            lines.append(
                f"    {entry['symbol']} ({entry['usage_kind']}, "
                f"{entry['occurrence_count']} occurrence(s)) {where}"
            )
        if len(unmatched) > EXPLAIN_SAMPLE:
            lines.append(f"    ... and {len(unmatched) - EXPLAIN_SAMPLE} more")

    if payload["rejected_non_code_matches"]:
        lines.append("")
        lines.append("NAMES FOUND ONLY IN NON-CODE TEXT (not treated as usage)")
        for entry in payload["rejected_non_code_matches"][:EXPLAIN_SAMPLE]:
            lines.append(
                f"  {entry['symbol']} in {entry['found_in']} at {entry['path']}:{entry['line']}"
            )

    lines.append("")
    lines.append("COVERAGE")
    coverage_block = payload["coverage"]
    lines.append(f"  php analysis       {coverage_block['custom_code']['php_analysis']}")
    lines.append(
        f"  lifecycle branches "
        f"{', '.join(coverage_block['lifecycle_authority']['deprecation_index']['covered_source_branches'])}"
    )
    lines.append(f"  {coverage_block['statement']}")
    lines.append("")
    lines.append("UNKNOWNS")
    for unknown in payload["unknowns"]:
        lines.append(f"  {unknown['subject']}: {unknown['detail']}")
    lines.append("")
    lines.append("EXECUTION")
    for key, value in sorted(payload["execution"].items()):
        lines.append(f"  {key}={value}")
    return "\n".join(lines) + "\n"


def validate_migration_contract(root: Path = dk_core.ROOT) -> list[str]:
    dk_core.read_json(root / "schema" / "migration-work-item.schema.json")
    dk_core.read_json(root / "schema" / "migration-analysis.schema.json")
    config = dk_core.read_json(root / "config" / "custom-code-scan.json")
    for key in ("config_id", "scope", "excluded_directories", "included_extensions", "limits"):
        if key not in config:
            raise dk_core.ValidationError(f"custom-code scan config is missing {key}")
    if "vendor" not in config["excluded_directories"]:
        raise dk_core.ValidationError("the custom-code scan must exclude vendor by default")
    return [
        "MIGRATION_CONTRACT_VALID=PASS",
        f"MIGRATION_ENGINE_VERSION={ENGINE_VERSION}",
        f"MIGRATION_WORK_ITEM_SCHEMA={WORK_ITEM_SCHEMA_VERSION}",
        "MIGRATION_ENGINE_READ_ONLY=PASS",
        "DEFAULT_API_SCAN_BOUNDED_TO_PROJECT_CUSTOM_CODE=PASS",
        "API_SCAN_EXCLUSIONS_CONFIGURATION_DRIVEN=PASS",
    ]
