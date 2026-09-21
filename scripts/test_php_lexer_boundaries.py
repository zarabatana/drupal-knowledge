#!/usr/bin/env python3
"""The lexer's job is to know what a stretch of PHP is, and to admit what it isn't.

Everything the migration engine refuses to call a usage rests on this file
getting comments, strings and heredocs right. So the cases below are the ones
where a naive reading goes wrong: a deprecated name inside every kind of
comment, inside every kind of string, spanning inline HTML, and the constructs
the lexer genuinely cannot see and must therefore not pretend to.
"""

from __future__ import annotations

import dk_core
import dk_php_lexer as L
import dk_migration as M


NEEDLE = "file_create_url"


def kinds_containing(source: str, needle: str = NEEDLE) -> set[str]:
    return {item["kind"] for item in L.non_code_occurrences(L.tokenize(source), needle)}


def code_idents(source: str) -> list[str]:
    return [token.value for token in L.code_tokens(L.tokenize(source)) if token.type == L.T_IDENT]


# --- a name is only a name where it is code ---------------------------------

LINE_COMMENT = "<?php\n// file_create_url($uri);\n$a = 1;\n"
assert kinds_containing(LINE_COMMENT) == {"comment"}
assert NEEDLE not in code_idents(LINE_COMMENT)

HASH_COMMENT = "<?php\n# file_create_url($uri);\n$a = 1;\n"
assert kinds_containing(HASH_COMMENT) == {"comment"}
assert NEEDLE not in code_idents(HASH_COMMENT)

BLOCK_COMMENT = "<?php\n/* file_create_url($uri); */\n$a = 1;\n"
assert kinds_containing(BLOCK_COMMENT) == {"comment"}
assert NEEDLE not in code_idents(BLOCK_COMMENT)

DOC_COMMENT = "<?php\n/**\n * @see file_create_url()\n */\nfunction go() {}\n"
assert kinds_containing(DOC_COMMENT) == {"doc_comment"}
assert NEEDLE not in code_idents(DOC_COMMENT)

SINGLE_QUOTED = "<?php\n$q = 'file_create_url';\n"
assert kinds_containing(SINGLE_QUOTED) == {"string"}
assert NEEDLE not in code_idents(SINGLE_QUOTED)

DOUBLE_QUOTED = '<?php\n$q = "call file_create_url here";\n'
assert kinds_containing(DOUBLE_QUOTED) == {"string"}
assert NEEDLE not in code_idents(DOUBLE_QUOTED)

HEREDOC = "<?php\n$q = <<<TXT\nfile_create_url() in a heredoc\nTXT;\n"
assert kinds_containing(HEREDOC) == {"heredoc"}
assert NEEDLE not in code_idents(HEREDOC)

NOWDOC = "<?php\n$q = <<<'TXT'\nfile_create_url() in a nowdoc\nTXT;\n"
assert kinds_containing(NOWDOC) == {"heredoc"}
assert NEEDLE not in code_idents(NOWDOC)

INLINE_HTML = "<p>file_create_url() in template text</p>\n<?php $a = 1;\n"
assert kinds_containing(INLINE_HTML) == {"inline_html"}
assert NEEDLE not in code_idents(INLINE_HTML)

ESCAPED_QUOTE = "<?php\n$q = 'it\\'s file_create_url';\n$b = 2;\n"
assert kinds_containing(ESCAPED_QUOTE) == {"string"}, kinds_containing(ESCAPED_QUOTE)
assert NEEDLE not in code_idents(ESCAPED_QUOTE)

# And the same name in real code is real code.
REAL = "<?php\n$url = file_create_url($uri);\n"
assert L.non_code_occurrences(L.tokenize(REAL), NEEDLE) == []
assert NEEDLE in code_idents(REAL)
print("LEXER_SEPARATES_CODE_FROM_TEXT=PASS")


# --- a mixed file gets every case right at once ------------------------------

MIXED = """<?php
// file_create_url one
/* file_create_url two */
/** file_create_url three */
$a = 'file_create_url four';
$b = "file_create_url five";
?>
<p>file_create_url six</p>
<?php
$real = file_create_url($uri);
"""
occurrences = L.non_code_occurrences(L.tokenize(MIXED), NEEDLE)
assert len(occurrences) == 6, occurrences
assert {item["kind"] for item in occurrences} == {
    "comment",
    "doc_comment",
    "string",
    "inline_html",
}
assert code_idents(MIXED).count(NEEDLE) == 1
print("LEXER_MIXED_FILE_IS_EXACT=PASS")


# --- line numbers are usable --------------------------------------------------
# A work item points a human at a line. If the count drifts the item is noise.

NUMBERED = "<?php\n\n\n// file_create_url here on line 4\n\n$x = file_create_url($u);\n"
assert L.non_code_occurrences(L.tokenize(NUMBERED), NEEDLE)[0]["line"] == 4
call = next(
    token
    for token in L.code_tokens(L.tokenize(NUMBERED))
    if token.type == L.T_IDENT and token.value == NEEDLE
)
assert call.line == 6, call
print("LEXER_LINE_NUMBERS_ARE_ACCURATE=PASS")


# --- malformed input never crashes ---------------------------------------------
# A file the lexer cannot finish reading must still produce tokens, because the
# alternative is an unread file that silently supports no conclusion.

for broken in (
    "<?php\n/* never closed",
    "<?php\n$a = 'never closed",
    "<?php\n$a = <<<TXT\nnever closed",
    "<?php\n\x00\x01\x02",
    "",
    "no php at all",
):
    tokens = L.tokenize(broken)
    assert isinstance(tokens, list)
print("LEXER_TOLERATES_MALFORMED_INPUT=PASS")


# --- what it cannot see, it does not claim -------------------------------------

DYNAMIC = """<?php
namespace Drupal\\fixture;
class Dynamic {
  public function go($uri) {
    $fn = 'file_create_url';
    $a = $fn($uri);
    $b = call_user_func('file_create_url', $uri);
    $c = "{$this->helper()}";
    return [$a, $b, $c];
  }
}
"""
observed = M.observe_php("x.php", DYNAMIC, "fixture")
symbols = {item["symbol"] for item in observed["observations"]}
assert NEEDLE not in symbols, "a name reached only through a variable is not observed"
assert "call_user_func" in symbols, "the call that is written is observed"
# The name is present, and is reported as text rather than as a usage.
assert L.non_code_occurrences(L.tokenize(DYNAMIC), NEEDLE)
print("LEXER_DYNAMIC_CALLS_ARE_NOT_INVENTED=PASS")

# A service id that is not a plain literal is recorded as unsupported rather
# than guessed at.
DYNAMIC_SERVICE = """<?php
namespace Drupal\\fixture;
class S {
  public function go($name) {
    return \\Drupal::service($name);
  }
}
"""
result = M.observe_php("s.php", DYNAMIC_SERVICE, "fixture")
assert not any(
    item["usage_kind"] == M.USAGE_SERVICE for item in result["observations"]
), "a variable service id is not a service reference"
assert result["unsupported"], "and the engine says it could not read it"
assert result["unsupported"][0]["construct"] == "dynamic_service_id"
print("UNSUPPORTED_CONSTRUCTS_ARE_DECLARED_NOT_GUESSED=PASS")


# --- namespace resolution --------------------------------------------------------

RESOLUTION = """<?php
namespace Drupal\\my_module\\Plugin;

use Drupal\\Core\\Action\\ActionBase;
use Drupal\\Core\\Session\\AccountInterface as Account;
use Drupal\\Core\\{Url, Cache\\Cache};

class Thing extends ActionBase {
  public function go(Account $account) {
    $a = new Url();
    $b = \\Drupal::service('renderer');
    $c = Cache::invalidateTags([]);
    $d = new Local();
    return [$a, $b, $c, $d];
  }
}
"""
namespace, aliases = M.read_use_map(L.tokenize(RESOLUTION))
assert namespace == "Drupal\\my_module\\Plugin", namespace
assert aliases["ActionBase"] == "Drupal\\Core\\Action\\ActionBase"
assert aliases["Account"] == "Drupal\\Core\\Session\\AccountInterface"
assert aliases["Url"] == "Drupal\\Core\\Url"
assert aliases["Cache"] == "Drupal\\Core\\Cache\\Cache"

symbols = {item["symbol"] for item in M.observe_php("r.php", RESOLUTION, "my_module")["observations"]}
assert "Drupal\\Core\\Action\\ActionBase" in symbols, "extends resolves through the use map"
assert "Drupal\\Core\\Url" in symbols, "a grouped use resolves"
assert "Drupal::service" in symbols, "a root-qualified static call keeps its root"
# An unimported class is relative to the file's own namespace, not to Drupal\Core.
assert "Drupal\\my_module\\Plugin\\Local" in symbols, symbols
print("NAMESPACE_RESOLUTION_IS_EXACT=PASS")

# parent, self and static name no class and must resolve to nothing.
RELATIVE = """<?php
namespace Drupal\\my_module;
class Child extends Base {
  public function go() {
    parent::setUp();
    self::helper();
    static::other();
  }
}
"""
symbols = {item["symbol"] for item in M.observe_php("rel.php", RELATIVE, "my_module")["observations"]}
for invented in ("Drupal\\my_module\\parent::setUp", "Drupal\\my_module\\self::helper"):
    assert invented not in symbols, invented
print("RELATIVE_CLASS_KEYWORDS_RESOLVE_TO_NOTHING=PASS")


# --- a method call is not a function call -------------------------------------

METHOD = """<?php
namespace Drupal\\fixture;
class M {
  public function go($object) {
    $a = $object->file_create_url();
    $b = $object?->file_create_url();
    return [$a, $b];
  }
}
"""
symbols = {item["symbol"] for item in M.observe_php("m.php", METHOD, "fixture")["observations"]}
assert NEEDLE not in symbols, "a member call is not the global function"
print("MEMBER_CALL_IS_NOT_A_GLOBAL_FUNCTION=PASS")

# Nor is a declaration a call.
DECLARATION = "<?php\nfunction file_create_url($uri) { return $uri; }\n"
symbols = {item["symbol"] for item in M.observe_php("d.php", DECLARATION, "fixture")["observations"]}
assert NEEDLE not in symbols, "declaring a function is not calling it"
print("DECLARATION_IS_NOT_A_CALL=PASS")


# --- the real-world file shape that motivated all of this ------------------------

REAL_WORLD = """<?php
namespace Drupal\\example_api\\Controller;

use Drupal\\Core\\Controller\\ControllerBase;

class ExampleApiController extends ControllerBase {
  public function getparameters($request) {
    $nids = \\Drupal::entityQuery('node')->condition('type', 'product')->execute();
    foreach ($nids as $nid) {
      // $response[]['uri'] = file_create_url($image);
      // $response[]['image_original'] = file_create_url($image);
      // $response[]['image_style_thumbnail'] = file_create_url($url);
      $response['title'] = $nid;
    }
    return $response;
  }
}
"""
observed = M.observe_php("ExampleApiController.php", REAL_WORLD, "example_api")
symbols = {item["symbol"] for item in observed["observations"]}
assert NEEDLE not in symbols, "three commented-out calls are not three usages"
assert "Drupal::entityQuery" in symbols, "the live call is observed"
assert len(L.non_code_occurrences(L.tokenize(REAL_WORLD), NEEDLE)) == 3
print("REAL_WORLD_COMMENTED_CALL_IS_NOT_USAGE=PASS")
