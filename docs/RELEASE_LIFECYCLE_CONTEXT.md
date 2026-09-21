# Drupal Core Release Lifecycle Context

Drupal Knowledge keeps release lifecycle context separate from project evidence.

The Project Analyzer observes repository facts such as an installed Drupal core
version from `composer.lock`. It does not decide whether that version is current,
supported, unsupported, EOL, insecure, or recommended.

Release lifecycle context is Drupal ecosystem knowledge derived from an
authoritative Drupal source snapshot:

```text
authoritative source snapshot
-> reviewed normalized release lifecycle context
-> future resolver/finding evaluation with project core-version evidence
```

It is not:

```text
authoritative source
-> project evidence
```

## Source Authority

The current context is normalized from the baselined `drupal-core-releases`
source:

- human source URL: `https://www.drupal.org/project/drupal/releases`
- machine fetch URL:
  `https://updates.drupal.org/release-history/drupal/current`
- immutable snapshot:
  `sources/snapshots/drupal-core-releases/c7de75d2508c7d134765affdea101e9bc7a4d534d8eaaa97fda3308a14ea0063.txt`

The checked-in context records the source ID, state path, snapshot path,
snapshot SHA-256, snapshot byte length, current source-state digest, normalizer
name/version, and release count.

## Artifact

The reviewed context lives at:

`knowledge/context/drupal-core-release-lifecycle.json`

Its schema lives at:

`schema/release-lifecycle-context.schema.json`

This is a machine-readable knowledge context artifact. It is not a set of
knowledge records, and individual release rows are not materialized as prose
rules under `knowledge/records/`.

## Normalized Fields

The normalizer preserves only explicit fields from the captured release-history
XML:

- project metadata: title, short name, creator, type, Composer namespace,
  project status, link, and project terms;
- `supported_branches` as the literal source value plus lossless lookup entries;
- release rows with source order index, name, version, tag, status, links,
  timestamp, release type terms, security coverage text/attributes, and release
  file summary;
- an audit matrix of XML fields observed in the source snapshot.

Version strings are preserved exactly. Stable `x.y.z` values additionally get a
lossless numeric lookup object. Prerelease and dev values remain source strings
and are not treated as stable releases.

## Non-Inference Rules

The context does not infer lifecycle conclusions beyond the source fields.

`supported_branches` means the branch string appeared in the feed's
`supported_branches` element. It is not generalized into every possible support,
security-support, EOL, or recommendation concept.

Release ordering does not prove that an older release is unsupported, obsolete,
EOL, insecure, vulnerable, or less suitable for a project.

The release type term `Insecure`, when present, is preserved as a source term.
It is not a project vulnerability finding or a compliance verdict.

The `security` element's text and `covered` attribute are preserved as source
fields. They are not project security verdicts.

## Review And Staleness

Source collection can create a new immutable snapshot and update source state.
That must not automatically mutate or promote the reviewed lifecycle context.

The reviewed context is considered:

- `current` when its pinned snapshot digest equals the current source-state
  digest;
- `stale` when source state points to a different snapshot.

Staleness is review information, not automatic authority promotion. A stale
context needs a new normalization/review step before replacing the reviewed
artifact.

## CLI

Validate the checked-in reviewed context:

```bash
python3 scripts/dk.py release-lifecycle validate
```

Check staleness against current source state:

```bash
python3 scripts/dk.py release-lifecycle status
```

Generate candidate normalized context to stdout:

```bash
python3 scripts/dk.py release-lifecycle normalize
```

Write an explicit candidate file:

```bash
python3 scripts/dk.py release-lifecycle normalize --output /tmp/drupal-core-release-lifecycle.candidate.json
```

The command defaults to candidate output and does not overwrite the reviewed
context unless an explicit output path and `--force` are supplied.

## Future Use

A future resolver/finding layer may compare:

- project evidence: installed Drupal core version; with
- reviewed release lifecycle context: explicit release-history source facts.

That join still needs a separate machine finding contract. This context alone
does not authorize findings, remediation, vulnerability labels, compliance
verdicts, or any consumer's behaviour.
