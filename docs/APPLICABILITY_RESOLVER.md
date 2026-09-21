# Drupal Knowledge Applicability Resolver

The Applicability Resolver consumes deterministic Drupal Project Analyzer JSON and
canonical Drupal Knowledge records. It produces applicability results only.

It does not inspect the original Drupal project. It does not fetch network data.
It does not emit security, compliance, vulnerability, or remediation findings.

## Pipeline Boundary

The current architecture is:

```text
Drupal project files
-> Drupal Project Analyzer
-> analyzer JSON facts and evidence
-> Applicability Resolver
-> applicability results
```

The resolver stops before any finding engine:

```text
SOURCE
!= TRUSTED KNOWLEDGE
!= PROJECT FACT
!= OBSERVED PROJECT EVIDENCE
!= APPLICABILITY RESULT
!= FINDING
!= SOLVED CASE
```

Applicability asks whether a knowledge record concerns the observed project.
Compliance asks whether the project satisfies an applicable requirement. This
resolver does not answer compliance.

## CLI

Analyze first:

```sh
python3 scripts/dk.py analyze /path/to/project > /tmp/dk-analysis.json
```

Resolve applicability from the analyzer output:

```sh
python3 scripts/dk.py resolve /tmp/dk-analysis.json
```

The resolver writes deterministic JSON to stdout. Errors go to stderr. It does
not write output files by default.

## Inputs

The resolver accepts only the Drupal Project Analyzer contract:

- `schema_version: 0.1`
- analyzer name `drupal-project-analyzer`
- analyzer version `0.1`
- profile facts
- evidence IDs and portable evidence paths
- completeness states
- unknowns and diagnostics

Invalid analyzer JSON is rejected. Unsupported future analyzer schema versions
are rejected until explicit compatibility is implemented.

The resolver validates canonical Drupal Knowledge before resolving. Malformed
trusted knowledge is a resolution integrity failure.

## Applicability States

Resolver results use four public states:

- `applicable`: all machine-resolvable requirements are definitively true.
- `not_applicable`: sufficient authoritative evidence proves a required
  predicate false.
- `unknown`: the decision depends on missing, ambiguous, or unknown project
  facts.
- `requires_human_review`: the knowledge record needs semantic judgment or uses
  applicability semantics outside the safe machine contract.

`unknown` and `requires_human_review` are intentionally distinct. Missing
evidence is not semantic judgment, and semantic judgment is not missing data.

## Three-Valued Logic

Internal predicate evaluation uses:

- `TRUE`
- `FALSE`
- `UNKNOWN`

This prevents missing evidence from becoming false. For example, when enabled
module evidence is unavailable, a rule that requires module `foo` returns
`unknown`, not `not_applicable`.

Absence can author `not_applicable` only when the relevant observation domain is
complete. A known enabled-module list that lacks `foo` can exclude a
module-specific rule. An unknown module list cannot.

## Declarative Machine Contract

Knowledge records may optionally include `machine_applicability`. The contract
is additive and declarative. It is not a programming language.

Supported predicates:

- `fact_known`
- `equals`
- `list_contains`
- `list_not_contains`
- `list_non_empty`
- `version_matches`

Supported composition:

- `all`
- `any`
- `not`

Fact lookup uses explicit dot paths over analyzer JSON fact objects. Missing
paths evaluate safely to `UNKNOWN`. Paths are not Python expressions and cannot
traverse objects.

Free-form fields such as `summary`, `evidence_requirements`, `checks`, and
`automation_hints` do not author machine applicability. They remain human
guidance unless represented by the safe structured contract.

## Version Handling

The first resolver implements only stable semantic versions like `11.2.3` and
simple constraints:

- exact version, such as `11.2.3`
- major branch, such as `11.x`

Unsupported constraints and prerelease/dev versions fail closed to `unknown` or
human review. The resolver does not strip suffixes or guess release stability.

## Evidence Provenance

Each machine-resolved result includes deterministic provenance:

- knowledge ID
- predicate evaluations
- reason codes
- fact references
- evidence IDs
- missing facts

The resolver references evidence IDs from the analyzer output. It does not copy
source snapshots, target file contents, Drupal config contents, secrets, or
arbitrary project data.

## Enforcement Boundary

Applicability does not change enforcement. A reviewed guidance record that is
applicable remains applicable guidance. An unreviewed synthetic or future record
cannot become blocking merely because its applicability predicate evaluates
true.

Current Drupal Knowledge records remain guidance-only.

## Offline And Side-Effect Boundary

Resolution uses only:

- the analyzer JSON file;
- canonical local knowledge records;
- canonical local schemas.

It does not query Drupal.org, Packagist, GitLab, Composer, or the original
project. It does not mutate analyzer input, knowledge records, sources,
snapshots, generated outputs, or project files.

## Current Limitations

The resolver does not yet:

- evaluate Drupal security advisory applicability;
- evaluate release support state from release-history source data;
- inspect code paths, routes, Twig templates, or data flow;
- emit findings, issue severities, compliance states, or remediations;
- integrate with any specific consumer.

Those require future analyzer evidence and a separate finding engine.
