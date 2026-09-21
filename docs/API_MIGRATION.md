# API Migration Intelligence

Prompt 10 could tell a project its custom-code compatibility was unknown. This
is the answer to *why*, narrowed to something a developer can act on:

```text
this file uses this symbol here
this symbol is deprecated in X and removed from Y, per this source
for this target that means blocking / recommended / compatible
this is the replacement the annotation states, or none was stated
```

Three rules decide whether that is useful or dangerous.

## A Name In A Comment Is Not A Call

`file_create_url()` appears three times in one real project file, all of them
inside `//` comments a developer left behind. A grep says the project calls a
function removed in Drupal 10. It does not.

So `scripts/dk_php_lexer.py` tokenizes PHP far enough to know what a stretch of
text *is*: inline HTML, a comment, a docblock, a string, a heredoc, or code.
Nothing downstream ever reads raw file text. It is a lexer, not a parser, and
the difference is declared rather than glossed over — a call reached through a
variable, `call_user_func('...')`, or string interpolation is invisible to it,
and those are recorded as unsupported constructs instead of guessed at.

Names found only in non-code text are reported in
`rejected_non_code_matches`, so the decision *not* to treat them as usage is
visible rather than silent.

Short names are never matched either. api.drupal.org prints a deprecated class
as `Action`, `Image` or `Term`; matching those against project source finds
English words. Identity is fully qualified on both sides — the corpus resolves
each class through its core file path and Drupal's PSR-4 layout, and the project
side resolves through the file's own `namespace` and `use` statements.

## Deprecated Is Not Removed

```text
deprecated   still executes; upgrade debt
removed      blocks, but only where use is actually observed
```

Lifecycle comes from Drupal core's own mandated annotation form, which
api.drupal.org publishes as a per-branch index:

```text
in drupal:9.3.0 and is removed from drupal:10.0.0. Use X instead.
```

That grammar is matched exactly. A row that does not follow it becomes a record
whose lifecycle is `unknown` rather than one with a guessed version. A
replacement is recorded only when the annotation states one; `There is no
replacement.` is recorded as exactly that, and anything else is `unknown`. No
equivalent API is ever invented.

Version boundaries are exact and never rounded to a major. A symbol deprecated
in 10.2.0 is *current* for a 10.1.0 target, and one removed in 11.0.0 is merely
*deprecated* for a 10.6.0 one.

## No Match Found Is Not A Clean Bill Of Health

The corpus indexes deprecated symbols on registered branches and nothing else.
Absence from it covers two opposite situations: a symbol that is current, and a
symbol removed *before* the indexed branch and therefore already gone. `node_load()`
on a real Drupal 9.5.9 project is the second.

So every analysis carries first-class coverage — which files were read, which
languages are supported, which branches are indexed, which constructs are
unsupported — and states outright that finding no match is not a compatibility
proof. Observed symbols with no index entry are listed rather than dropped.

## Sources

| Source | Carries |
| --- | --- |
| `drupal-api-deprecated-9-p0` … `p4` | every Drupal 9 deprecation, with versions and stated replacements |
| `drupal-core-change-notices` | structured core change records, with introduced branch and version |

Each declares an `api_lifecycle` block in `sources/registry.json` giving its
role, authority kind and the fields that may be read from it — the same pattern
advisory feeds and upgrade authority already use, so no engine branches on a
source id.

Everything is read through the acquisition engine's pinned snapshots. No engine
in this feature opens a socket, so a changed source cannot reach the lifecycle
corpus without acquisition writing a snapshot and its review machinery running
first. Stack Overflow, Drupal Answers, blogs and Reddit are not registered and
cannot become semantic authority. Drupal Rector, Upgrade Status and PHPStan are
tools, not authority: nothing here imports, invokes or takes a claim from them.

## Records

Two source-derived record classes, stored apart from trusted knowledge exactly
as security advisories are:

```text
api/lifecycle/*.json        one symbol's lifecycle
api/change-records/*.json   one official change record
```

Both carry `is_trusted_knowledge: false`. Neither is written into
`knowledge/records/`.

A change record deliberately asserts no symbol lifecycle. It records the
symbols its own title wrote with call syntax, and `lifecycle_asserted` is
structurally `false` — a record that merely mentions an API can never give that
API a lifecycle. Categories stay distinct (`deprecation`, `removal`,
`signature_change`, `service_change`, `hook_change`, `event_change`,
`configuration_change`, `behavior_change`, `dependency_change`, `API_addition`,
`other`) rather than collapsing into "deprecated", and the phrase that produced
the category is recorded so a reviewer can disagree with it.

## What Is Observed

| Usage kind | Evidence |
| --- | --- |
| `function_call` | identifier followed by `(`, not a member, declaration or static call |
| `class_reference` | `new`, `extends`, `implements`, `instanceof`, resolved through the use map |
| `static_call` | `Class::method(`, with `Class` resolved to a fully qualified name |
| `constant_reference` | `Class::CONSTANT` |
| `service_reference` | `\Drupal::service('id')`, `$container->get('id')`, `'@id'` in `*.services.yml` |
| `hook_implementation` | `function <module>_<hook>(` in `.module`, `.install`, `.theme` |

Depending on a module is not a service reference. Only an observed reference to
the id counts.

## Work Items

One item per symbol and usage kind, with every occurrence preserved: a removed
API used in twelve places is twelve pieces of work, and a plan that hides eleven
of them is worse than useless. Several authoritative records describing one
lifecycle event add provenance to the same item rather than duplicating the task.

Target effects:

```text
compatible             migration_recommended    migration_required
blocking               unknown
```

Identity is deterministic: the same project revision, target and evidence
produce the same `work_item_id` every time, and a different target produces a
different one.

## Scan Boundaries

`config/custom-code-scan.json` declares the roots, the excluded directories
(`vendor`, `node_modules`, `.git`, build output), the file extensions, and the
size, count and depth limits. Nothing is hardcoded in the analyzer, and the
config's digest travels in every analysis so a result can be audited against the
rules that produced it. A file skipped for any reason is recorded with that
reason.

Contributed and vendored source is out of scope by default. Contrib
compatibility remains package and release metadata, as Prompt 10 established.
Only paths relative to the project root are ever recorded.

## Feeding Compatibility

Migration findings enter the existing upgrade model through its `project_code`
dimension rather than forming a second authority. A removed API in use becomes a
`removed_api_in_use_by_project_code` blocker carrying its occurrences; a
deprecation that survives to the target becomes a required change. Even a clean
analysis leaves an explicit unknown, so "no work item" never becomes "the code
is fine".

## Read-Only

No `--apply`, `--rewrite`, `--fix` or `--patch` on any subcommand.
`execution_performed` is structurally `false` and the contract refuses to
serialize anything else. No PHP is rewritten, no YAML edited, no Rector run, no
Composer invoked, and no trusted knowledge record, reviewed context, advisory,
solved case or source snapshot is touched.

```text
dk.py api-lifecycle ingest | coverage | list [--removed-in V] | show <symbol>
dk.py migration-analyze <analysis.json> --target V --project-path P [--format json]
dk.py migration-work    <analysis.json> --target V --project-path P [--effect E]
```

An API migration item is not a security finding. It becomes one only if
independent security evidence says so.
