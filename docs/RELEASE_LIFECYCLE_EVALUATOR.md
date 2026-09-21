# Drupal Core Release Lifecycle Evaluator

The release lifecycle evaluator joins project evidence from the Drupal Project
Analyzer with reviewed Drupal release lifecycle context.

It emits a neutral lifecycle assessment. It does not emit findings,
remediation, compliance results, vulnerability labels, or upgrade
recommendations.

## Authority Boundary

The evaluator preserves these separate layers:

```text
project evidence
!= authoritative lifecycle knowledge
!= lifecycle assessment
!= finding
!= remediation
```

The Project Analyzer observes project facts such as the installed
`drupal/core` Composer version. It does not contain external Drupal release
truth.

The lifecycle context is reviewed ecosystem knowledge normalized from the
captured `drupal-core-releases` source snapshot. The evaluator reads that
reviewed context. It does not parse the raw source snapshot during normal
evaluation and does not fetch Drupal.org.

## CLI

Create analyzer JSON first:

```sh
python3 scripts/dk.py analyze /path/to/project > /tmp/dk-analysis.json
```

Evaluate the observed core version against the reviewed lifecycle context:

```sh
python3 scripts/dk.py lifecycle-evaluate /tmp/dk-analysis.json
```

The command writes deterministic JSON to stdout. Errors go to stderr. It does
not write files by default.

The public CLI always uses the checked-in canonical reviewed context at
`knowledge/context/drupal-core-release-lifecycle.json`. An arbitrary JSON file
does not become authoritative merely because it declares `review.status:
reviewed` or carries plausible source provenance. Test fixtures may inject
synthetic contexts through internal evaluator helpers to exercise stale,
candidate, malformed, and altered-provenance behavior, but that injection path
does not define production trust semantics.

## Inputs

The evaluator accepts only Drupal Project Analyzer JSON:

- `schema_version: 0.1`
- analyzer name `drupal-project-analyzer`
- analyzer version `0.1`
- project facts and evidence IDs from the analyzer contract

It uses the `drupal_core_version` fact only. If that fact is unknown, missing,
conflicting, or malformed, the evaluator returns `core_version_unknown` and
does not guess a release.

The lifecycle context must be the reviewed
`knowledge/context/drupal-core-release-lifecycle.json` shape:

- review status `reviewed`;
- pinned source snapshot SHA-256 and byte length;
- valid immutable source snapshot integrity;
- release rows normalized from explicit source fields;
- supported branch source values preserved from the feed.

The trust anchor is repository review and promotion of the canonical context
artifact, not self-declared JSON metadata. Context provenance identifies the
source snapshot used for review, but provenance alone is not review authority.

## Exact Release Matching

The evaluator performs exact source-version lookup against the reviewed context.
It preserves version strings exactly.

Examples:

- `11.4.5` matches only source row `11.4.5`;
- `11.4.0-rc2` matches only source row `11.4.0-rc2`;
- `11.x-dev` matches only source row `11.x-dev` if that exact source row exists.

If no exact row exists, the assessment reports `release_not_found`. That does
not mean the project is unsupported, invalid, insecure, obsolete, EOL, or
vulnerable.

## Branch Token Matching

The evaluator uses a small deterministic branch-token rule:

```text
major.minor.patch[-alphaN|-betaN|-rcN] -> major.minor.
```

For example, `11.4.3` maps to source branch token `11.4.`.

The assessment can report whether that token is listed in the reviewed
`supported_branches` source values as:

`branch_listed_in_source_supported_branches`

This is only membership in the feed's source field. It is not a project support
verdict and is not generalized into security support, EOL, recommendation, or
upgrade status.

If the installed version cannot safely map to a branch token, branch membership
is `unknown`, not false.

## Source Attributes

When an exact release row is matched, the evaluator preserves source attributes:

- source release status;
- source release type terms;
- source security coverage text and attributes;
- source publication timestamp.

The term `Insecure`, when present, remains a literal source release term. It is
not converted into `vulnerable=true`, a project security finding, or a
compliance result.

Security coverage text and attributes remain source fields. They do not mean the
project is secure, insecure, vulnerable, or compliant.

## Freshness

Context freshness is separate from release matching:

- `current`: reviewed context snapshot equals current source state;
- `stale`: current source state points to a different snapshot.

A stale reviewed context can still produce a reproducible historical assessment
against its pinned snapshot, but the output explicitly reports the stale
relation. The evaluator does not regenerate, publish, or promote lifecycle
context.

## Output

The output schema is:

`schema/release-lifecycle-assessment.schema.json`

Every assessment includes:

- deterministic assessment identity;
- analysis identity and analyzer schema/version;
- core-version fact reference and evidence IDs;
- lifecycle context identity, schema version, review status, and snapshot SHA;
- context freshness;
- exact release match state;
- branch-token match and source supported-branch membership;
- preserved source attributes;
- limitations.

The output contains no absolute project paths and no source file contents.

## Limitations

The evaluator does not:

- inspect the original Drupal project;
- parse Composer, Drupal config, or source files;
- parse raw Drupal release XML during normal evaluation;
- query Drupal.org, Packagist, GitLab, Composer, Drush, databases, Docker, or
  Drupal runtime;
- calculate newer release risk or age risk;
- produce findings, vulnerabilities, compliance states, or remediation.

Future layers may use this assessment as one input to a finding model, but only
after a separate machine finding contract defines the exact project condition
being asserted.
