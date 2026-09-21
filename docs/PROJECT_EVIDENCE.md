# Project Evidence

Every engine before this one grew its own way of asking the analyzer a
question. The security engine reads installed packages, the upgrade engine
reads constraints and extension metadata, the migration engine reads code. Each
was right, and each was private.

This is the reusable layer underneath them. An evidence record says:

```text
this was concretely observed here
```

It never says:

```text
this is universally true
```

## Three Distinctions

```text
static heuristic  != project fact          != trusted Drupal knowledge
not_observed      != false                 (unless the domain is complete)
exported config   != runtime effective configuration
```

The second is the one that does the work, and completeness is how it holds.

## Completeness Is First-Class

Every producer declares whether its search domain is `complete`, `bounded`,
`partial` or `unknown`, and a negative conclusion is only offered from a
complete one.

| Domain | Search domain | Why |
| --- | --- | --- |
| `dependency` | complete | composer.lock enumerates every locked package |
| `configuration` | complete objects, bounded values | the config root is fully enumerated; values are read for declared keys only |
| `extension` | complete for exported state | core.extension lists every exported-enabled extension |
| `code` | bounded | the custom-code scan is bounded by its declared configuration |
| `project_metadata` | bounded | declared manifest and filesystem markers only |

So `evidence_absent` on a Composer package answers `TRUE` from a complete lock
enumeration, and the same operator on a code symbol answers `UNKNOWN` with
`EVIDENCE_DOMAIN_INCOMPLETE`. A record may not even be constructed with state
`not_observed` from an incomplete domain — the contract refuses it.

## States, Quality, Domains

```text
states      observed  not_observed  unknown  insufficient_evidence
            ambiguous  unsupported_evidence_type

quality     canonical_structured  syntax_observed  exact_file_fact
            bounded_static_observation  heuristic_candidate

domains     code  configuration  dependency  extension  project_metadata
```

Quality is a deterministic class following from the extraction method. There is
no probability and no model scoring. A `heuristic_candidate` is structurally
never `definitive`, the schema forbids the combination, and an evidence
predicate reading one returns `UNKNOWN` with
`HEURISTIC_EVIDENCE_NOT_DEFINITIVE` — so no blocking finding can be built from
a heuristic however alarming it looks.

## Dependency Dimensions Stay Apart

```text
composer.root_requirement       what the manifest asks for
composer.package.installed      what the lock file holds
composer.package.locked_version which version that is
composer.dependency_relation    direct or transitive
```

A root requirement is not an installation. A package declared in
`composer.json` and absent from `composer.lock` produces an observed
requirement *and* a `not_observed` installation, as two records. A transitive
package records `required_by: unknown` rather than inventing a parent the lock
file as read does not name.

## Configuration Is Exported, Not Effective

`config.object.exported` identifies a config object; `config.exported_value`
carries a declared key's value. Both say what the repository holds. There is no
assertion anywhere in the vocabulary that claims a runtime effective value, so
no rule can ask for one by accident — settings.php and environment overrides
are not observed, and the record says so.

Config objects are files directly inside the selected exported config root. A
YAML file elsewhere is never treated as a Drupal config object. Where no single
root can be selected, the result is `ambiguous` and nothing is enumerated.

`settings.php` is lexed, never executed. Only `$settings['key'] = <scalar>;`
is read; anything needing evaluation is `unsupported_evidence_type`.

## Extensions: Four Different Things

```text
extension.package_present        the package is in the lock file
extension.code_present           the code is in the tree
extension.exported_enabled       core.extension exports it as enabled
extension.runtime_enabled        always unknown
```

A repository can show all three of the first and still be a site where the
module is switched off. The fourth exists precisely so that a rule asking about
runtime gets `unknown` instead of an installed package standing in for it.

## Secrets And Paths

`config/project-evidence.json` declares the secret key patterns and forbidden
value patterns. Redaction runs *before* a record is built, so a value can never
reach an evidence set even in a diagnostic, and a secret key is checked before
the declared-key filter so it is visibly refused rather than accidentally
unobserved. Only project-relative paths are ever recorded, and the engine
refuses to serialize an absolute local path.

## Feeding Applicability

There is one applicability engine. Two operators were added to it rather than a
second evaluator being written:

```json
{"operator": "evidence_matches", "assertion": "composer.package.installed", "subject": "drupal/webform"}
{"operator": "evidence_matches", "assertion": "config.exported_value",
 "subject": "system.logging:error_level", "value": "verbose"}
{"operator": "evidence_absent", "assertion": "composer.package.installed", "subject": "drupal/paragraphs"}
```

They compose with the existing `all` / `any` / `not` grouping and three-valued
logic, so a rule requiring a package *and* a config value resolves
deterministically, and an unobservable half leaves the whole rule `unknown`
rather than resolving on the half it could see. An assertion outside the
declared vocabulary fails conservatively with
`UNSUPPORTED_EVIDENCE_ASSERTION`; with no evidence set supplied at all, an
evidence predicate is `PROJECT_EVIDENCE_UNAVAILABLE` and stays unknown.

## Identity, Revisions And Diff

A set is identified by a project fingerprint and a revision fingerprint built
from the file digests the analyzer already recorded. The same content always
produces the same set, byte for byte; changed content produces a distinguishable
one. `evidence-diff` reports `added`, `removed`, `changed` and `unchanged`
deterministically.

Persistence is optional and ephemeral by default. A persisted set is stored at
`evidence/projects/<project_fingerprint>/<revision_fingerprint>.json` with
`project_id` stripped, so a shared tree carries no project name and a revision's
file is never rewritten by a later one.

## Read-Only

```text
dk.py evidence <analysis.json> [--project-path P] [--domain D] [--format json] [--persist]
dk.py evidence-diff <before.json> <after.json>
dk.py resolve <analysis.json> [--project-path P]
```

No project file is written, no PHP is executed, no database is inspected and no
runtime is probed. The evidence engine discovers nothing and opens nothing: every
fact comes from an analyzer profile, and source observation is delegated to
`dk_migration.observe_project`, the one place in the product that reads PHP.

A configuration or code observation is evidence, not security truth. It may
later contribute to a security finding; it is not one.
