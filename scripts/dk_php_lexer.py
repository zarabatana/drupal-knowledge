#!/usr/bin/env python3
"""A bounded PHP lexer, written for one job: not lying about where a name is.

Prompt 11 forbids a raw substring match from becoming a confirmed API usage,
and the reason is concrete. ``file_create_url`` appears in a real project file
three times, all of them inside ``//`` comments left behind by a developer. A
grep says the project calls a function removed in Drupal 10. It does not.

So this module tokenizes PHP far enough to know what a stretch of text *is*:
inline HTML, a comment, a string, or code. Nothing downstream ever looks at raw
file text again. It is deliberately a lexer and not a parser — it has no idea
what an expression means, and callers must treat anything needing semantics as
unsupported rather than guessing.

What it handles: open and close tags, ``//`` ``#`` and ``/* */`` comments,
single- and double-quoted strings with escapes, heredoc and nowdoc bodies,
identifiers including namespace separators, and the operators that decide
whether a name is a call, a static reference or a member access.

What it does not handle, and says so: string interpolation is one token, so a
symbol named inside ``"{$a->b()}"`` is invisible; and there is no expression
evaluation, so ``call_user_func('file_create_url')`` is a string, not a call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator


T_INLINE_HTML = "inline_html"
T_OPEN_TAG = "open_tag"
T_CLOSE_TAG = "close_tag"
T_COMMENT = "comment"
T_DOC_COMMENT = "doc_comment"
T_STRING_LITERAL = "string"
T_HEREDOC = "heredoc"
T_IDENT = "ident"
T_VARIABLE = "variable"
T_NUMBER = "number"
T_OPERATOR = "operator"
T_WHITESPACE = "whitespace"

# Token types that carry text a human wrote *about* code rather than code. A
# symbol found in one of these is never a usage.
NON_CODE_TYPES = frozenset(
    {T_COMMENT, T_DOC_COMMENT, T_STRING_LITERAL, T_HEREDOC, T_INLINE_HTML}
)

# Operators the usage rules need to distinguish, longest first so that ``::``
# is never read as two ``:``.
OPERATORS = (
    "<<<",
    "===",
    "!==",
    "<=>",
    "??=",
    "?->",
    "->",
    "::",
    "=>",
    "==",
    "!=",
    "<=",
    ">=",
    "&&",
    "||",
    "??",
    "++",
    "--",
    "+=",
    "-=",
    "*=",
    "/=",
    ".=",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    ";",
    ",",
    ".",
    "=",
    "<",
    ">",
    "+",
    "-",
    "*",
    "/",
    "%",
    "!",
    "?",
    ":",
    "&",
    "|",
    "^",
    "~",
    "@",
    "$",
    "\\",
)

IDENT_RE = re.compile(r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*")
VARIABLE_RE = re.compile(r"\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*")
NUMBER_RE = re.compile(r"\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?\d+)?|0[xX][0-9a-fA-F_]+")
HEREDOC_START_RE = re.compile(r"<<<[ \t]*(?P<quote>['\"]?)(?P<label>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)\r?\n")
OPEN_TAG_RE = re.compile(r"<\?php\b|<\?=|<\?")


@dataclass(frozen=True)
class Token:
    type: str
    value: str
    line: int
    offset: int

    @property
    def is_code(self) -> bool:
        return self.type not in NON_CODE_TYPES


def tokenize(source: str) -> list[Token]:
    """Tokens for one PHP file. Never raises on malformed input.

    A file that cannot be lexed cleanly still produces tokens; the caller
    decides what to do with a partial reading. Refusing to crash matters
    because the alternative is skipping a file silently.
    """
    tokens: list[Token] = []
    length = len(source)
    index = 0
    line = 1
    in_php = False

    def push(kind: str, text: str, start: int, start_line: int) -> None:
        tokens.append(Token(kind, text, start_line, start))

    while index < length:
        if not in_php:
            match = OPEN_TAG_RE.search(source, index)
            if match is None:
                if index < length:
                    push(T_INLINE_HTML, source[index:], index, line)
                    line += source.count("\n", index)
                break
            if match.start() > index:
                text = source[index : match.start()]
                push(T_INLINE_HTML, text, index, line)
                line += text.count("\n")
            push(T_OPEN_TAG, match.group(0), match.start(), line)
            index = match.end()
            in_php = True
            continue

        char = source[index]

        # whitespace
        if char in " \t\r\n":
            start = index
            start_line = line
            while index < length and source[index] in " \t\r\n":
                if source[index] == "\n":
                    line += 1
                index += 1
            push(T_WHITESPACE, source[start:index], start, start_line)
            continue

        # close tag
        if source.startswith("?>", index):
            push(T_CLOSE_TAG, "?>", index, line)
            index += 2
            in_php = False
            # PHP swallows exactly one newline after a close tag.
            if index < length and source[index] == "\n":
                line += 1
                index += 1
            continue

        # comments
        if source.startswith("//", index) or char == "#":
            if source.startswith("#[", index):
                # An attribute, not a comment. Emit the punctuation and let the
                # caller read the attribute name as code.
                push(T_OPERATOR, "#[", index, line)
                index += 2
                continue
            start = index
            end = source.find("\n", index)
            stop = length if end == -1 else end
            close = source.find("?>", index, stop)
            if close != -1:
                stop = close
            push(T_COMMENT, source[start:stop], start, line)
            index = stop
            continue

        if source.startswith("/*", index):
            start = index
            start_line = line
            end = source.find("*/", index + 2)
            stop = length if end == -1 else end + 2
            text = source[start:stop]
            push(T_DOC_COMMENT if text.startswith("/**") else T_COMMENT, text, start, start_line)
            line += text.count("\n")
            index = stop
            continue

        # heredoc / nowdoc
        if source.startswith("<<<", index):
            match = HEREDOC_START_RE.match(source, index)
            if match:
                start = index
                start_line = line
                label = match.group("label")
                body_start = match.end()
                terminator = re.compile(rf"^[ \t]*{re.escape(label)}\b", re.MULTILINE)
                found = terminator.search(source, body_start)
                stop = found.end() if found else length
                text = source[start:stop]
                push(T_HEREDOC, text, start, start_line)
                line += text.count("\n")
                index = stop
                continue

        # strings
        if char in "'\"":
            start = index
            start_line = line
            quote = char
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                if source[index] == "\n":
                    line += 1
                index += 1
            push(T_STRING_LITERAL, source[start:index], start, start_line)
            continue

        # variables
        match = VARIABLE_RE.match(source, index)
        if match:
            push(T_VARIABLE, match.group(0), index, line)
            index = match.end()
            continue

        # identifiers
        match = IDENT_RE.match(source, index)
        if match:
            push(T_IDENT, match.group(0), index, line)
            index = match.end()
            continue

        # numbers
        match = NUMBER_RE.match(source, index)
        if match:
            push(T_NUMBER, match.group(0), index, line)
            index = match.end()
            continue

        for operator in OPERATORS:
            if source.startswith(operator, index):
                push(T_OPERATOR, operator, index, line)
                index += len(operator)
                break
        else:
            # An unrecognised byte. Emit it so offsets stay honest.
            push(T_OPERATOR, char, index, line)
            index += 1

    return tokens


# Dropped from the code stream entirely: they are not syntax a caller can
# position against. String literals are kept, because a literal is a syntactic
# element even though its *contents* are not code — that is what lets a service
# id be read out of ``\Drupal::service('some.service')`` while a symbol name
# spelled inside a string is still never an identifier.
DISCARDED_TYPES = frozenset(
    {T_WHITESPACE, T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML}
)


def code_tokens(tokens: list[Token]) -> list[Token]:
    """The syntactic token stream: no whitespace, no comments, no inline HTML."""
    return [token for token in tokens if token.type not in DISCARDED_TYPES]


def non_code_occurrences(tokens: list[Token], needle: str) -> list[dict]:
    """Where a name appears in text that is not code.

    Reported so an operator can see that Drupal Knowledge found the name and
    deliberately declined to treat it as a usage.
    """
    pattern = re.compile(r"\b" + re.escape(needle) + r"\b")
    found = []
    for token in tokens:
        if token.type not in NON_CODE_TYPES:
            continue
        for match in pattern.finditer(token.value):
            found.append(
                {
                    "kind": token.type,
                    "line": token.line + token.value.count("\n", 0, match.start()),
                }
            )
    return found
