# Upgrade Compatibility

Security remediation answers *what stops this advisory applying*. Upgrade
compatibility answers a broader question: *can this project get there at all*.

A version being the newest one is not a reason a project can move to it. A
package declaring Drupal 11 support is not the whole application being Drupal 11
compatible. The engine in `scripts/dk_upgrade.py` exists to keep those two
sentences from being written anywhere in Drupal Knowledge.

## Five Distinctions

```text
version exists              != version installable by Composer
version installable         != version supported by Drupal
version supported           != version reachable from this project
project reaches version     != project code works on it
security remediation target != general upgrade compatibility proof
```

The last one matters most in practice. Prompt 09 can pick a target that resolves
every applicable advisory on an end-of-life site and still be pointing at a
version that site cannot reach. Both engines run independently; neither answer
substitutes for the other.

## Authority

Transitions are never derived. Every statement about what an upgrade requires
comes from a registered authoritative Drupal.org page, quoted verbatim:

| Source | Declares |
| --- | --- |
| `drupal-upgrade-process-overview` | that a major version cannot be skipped |
| `drupal-upgrade-9-to-10` | minimum source version, Composer changes, removed extensions |
| `drupal-upgrade-10-to-11` | as above, plus a PHP floor |
| `drupal-upgrade-11-to-12` | as above, published while Drupal 12 is unreleased |
| `drupal-php-requirements` | supported PHP versions per Drupal minor |

Each carries an `upgrade` block in `sources/registry.json` declaring its role, so
the engine never branches on a source id — the same pattern advisory feeds use.
Blogs, forums and community posts are not upgrade authority and cannot become
it, because only registered authoritative sources are read at all.

`knowledge/context/drupal-upgrade-compatibility.json` is the reviewed
normalization of those snapshots. Every requirement in it carries the exact
lines it was read from, and `dk.py validate` re-reads the pinned snapshot and
fails if a quoted line is no longer there. A requirement that cannot be quoted
cannot be stated.

Consequences of reading rather than deriving:

- Drupal 11 to 12 publishes its minimum source version as `TBA`. It stays
  `unknown`. It is not filled in from the release feed, from the neighbouring
  transition, or from the removed-updates sentence on the same page.
- The 9-to-10 page names removed extensions with "This includes ...", so the
  list is not closed. Matching none of them proves nothing, and the API
  lifecycle dimension stays `unknown` for that transition.
- The PHP matrix is published per Drupal *minor* and has no Drupal 9 column, so
  PHP support for a Drupal 9 minor is unknown rather than inherited.

## Reuse

There is one project scanner in Drupal Knowledge and this is not it. Every
project fact comes from a Project Analyzer profile:

```text
profile.facts.drupal_core_version    profile.facts.composer_packages
profile.facts.php_version            profile.facts.custom_modules
profile.facts.custom_themes          profile.facts.modules / themes
```

Composer constraint semantics, version parsing and supported-branch lookup are
reused from `dk_remediation` and `dk_security` rather than reimplemented, so a
constraint means one thing across the whole product.

## Dimensions

Project-wide compatibility is an aggregate. Core supporting a target says
nothing on its own about a project reaching it.

| Dimension | Reads |
| --- | --- |
| `core_transition` | reviewed transitions, supported branches, minimum source version |
| `contrib_compatibility` | published `core_compatibility` per contributed release |
| `composer_constraints` | declared constraints against the target and the documented ones |
| `platform_requirements` | transition PHP floor and the per-minor PHP matrix |
| `api_lifecycle` | extensions deprecated on one major and removed on the next |
| `project_code` | `core_version_requirement` declared by custom extensions |

Each dimension reports its own blockers, unknowns and required changes.

## Verdicts

```text
compatible_with_observed_evidence   requires_changes   blocked
requires_review                     insufficient_evidence
```

Never a bare boolean. The ordering is: a blocker the project cannot clear
outranks one it can; a change the project must make outranks an open question;
an open question outranks silence. Only a run that reaches the end with nothing
outstanding is `compatible_with_observed_evidence`, and even that is bounded by
what was evaluated — an unevaluated dimension is not a passing one.

## Blockers

Every blocker is machine-readable, carries provenance, and says how it could
stop being one:

```text
resolvable_by_declared_change   the project changes its own manifest or metadata
requires_upstream_release       someone else must publish something first
requires_intermediate_upgrade   a major must be crossed on the way
not_resolvable_by_this_target   the target itself is wrong
```

That distinction is what separates `requires_changes` from `blocked`.

## Contributed Projects

Identity is explicit. A Composer package is matched to a Drupal.org project only
through a registry entry declaring that exact package name. There is no fuzzy
matching: `drupal/token_custom` gets no evidence from `drupal/token`.

Where an authoritative release feed is registered, the release's own
`core_compatibility` field is read and the answer is evidenced. Where none is
registered, the answer is `unknown` — not a blocker, and emphatically not a
pass. A release whose version cannot be parsed, such as a `8.x-1.x-dev` branch
entry, is never offered as a target however well its compatibility reads.

## Deprecated Is Not Removed

```text
deprecated API   still executes; upgrade risk and debt
removed API      may block a target, but only with observed use
```

Both are reported for the same extension, as separate records. A removal becomes
a blocker only when authoritative removal evidence and observed project use are
both present. When the analyzer could not observe the enabled extension set,
every removal is `code_compatibility_unknown` — the honest answer, and never a
silent pass.

Prompt 10 deliberately stops at extension-level lifecycle. The analyzer sees
extension metadata, not call sites, so the engine says so in every assessment
rather than letting an unexamined codebase read as a clean one.

## Read-Only

There is no execution mode. No `--apply`, no `--execute`, no `--write`, on any
subcommand. `execution_performed` is structurally `false` and the contract
refuses to serialize anything else. The engine runs no Composer command, writes
no project file, runs no database update, and mutates no trusted knowledge
record, advisory, solved case or source snapshot.

```text
dk.py upgrade-evaluate <analysis.json> --target 11.4.6 [--format json|explain]
dk.py upgrade-path     <analysis.json> [--target V]... [--format json|explain]
```

Required changes are reported with `applied: false` on every one.

## Multiple Targets

`upgrade-path` evaluates the newest supported stable release on each supported
branch. Newest is not treated as best: a nearer target may be reachable while a
later one is blocked, and the reverse also happens. The `tradeoffs` block reports
which candidates have the fewest blockers, the fewest major steps, and no
dependency on an upstream release. It reports measurements and does not rank
them, because the balance between disruption and compatibility is the operator's
call.

## Contracts

```text
schema/upgrade-assessment.schema.json
schema/upgrade-path.schema.json
```

Both versions are advertised by `dk.py version` under `interfaces`, alongside an
`upgrade_engine` block declaring `result_domain: upgrade_compatibility` and
`produces_security_findings: false`. Compatibility output has its own result
domain so an upgrade blocker is never presented as a vulnerability.
