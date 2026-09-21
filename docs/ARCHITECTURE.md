# Architecture

Drupal Knowledge is a Git-backed evidence system. Generated views and future
indexes must be rebuildable from canonical repository data.

## Flow

```text
Drupal sources
  -> normalized immutable snapshots
  -> source state
  -> source-change review candidates
  -> reviewed knowledge records
  -> generated trusted aggregate
  -> project profile + observed evidence matching
  -> resolved applicable context for external consumers
```

## Authority Layers

`SOURCE` is a monitored external or internal origin. Source snapshots preserve
what was seen, but source text is not trusted knowledge by itself.

`TRUSTED KNOWLEDGE` is a reviewed record in `knowledge/records/` with explicit
source citations, version applicability, and enforcement intent.

`PROJECT FACT` is a statement about a Drupal project profile, such as core
version or installed modules. Unknown remains unknown.

`OBSERVED PROJECT EVIDENCE` is collected proof, such as `composer.lock`,
`core.extension`, status reports, CI output, PHPCS, PHPStan, PHPUnit, Behat,
database metrics, cache diagnostics, or runtime status.

`SOLVED CASE` is a problem the maintainers solved and verified in one real
project. It can support recurrence and future proposals, but does not silently
become a universal Drupal rule.

`DISCOVERY SIGNAL` is an untrusted observation. It can become a candidate only
after review and corroboration.

## Source Change Boundary

Acquisition behavior:

```text
registered source
  -> fetch
  -> normalize
  -> optional stable content window
  -> SHA-256
  -> immutable snapshot
  -> source state
  -> source-change review candidate if previously baselined content changed
  -> human review
```

One engine, `scripts/dk_acquisition.py`, orchestrates this for targeted CLI runs,
`collectors/collect.py` and the scheduled CI job. It writes only source state,
snapshots, and discovery candidates. It does not write `knowledge/`, and it
verifies the trusted knowledge digest before and after every run.

A source change never reaches trusted knowledge on its own:

```text
source change -> review candidate -> explicit human review -> MAY authorize
future proposal work
```

`reviewed_requires_knowledge_proposal` authorizes later work. It does not create
it. See [ACQUISITION_ENGINE.md](ACQUISITION_ENGINE.md).

## Knowledge Enforcement

Records carry `severity`, `review_status`, and `enforcement.intent`.

Effective enforcement is computed:

- reviewed + blocking intent -> blocking
- reviewed + non-blocking intent -> guidance
- unreviewed or internal-only -> advisory

This keeps review/enforcement separate from severity.

## Version Model

`version_applicability` supports:

- Drupal core constraints;
- introduced, deprecated, and removed markers;
- PHP constraints;
- module/theme package constraints;
- advisory-specific affected/fixed ranges.

Drupal change records explicitly preserve introduced branch/version, so Drupal
Knowledge must preserve those values instead of flattening them.

## Project Profile And Evidence

External tools provide a project profile plus observed evidence. A project
declaration does not prove runtime compliance.

Example:

```text
project fact: module X enabled
observed evidence: version X.Y installed
knowledge: X.Y affected by advisory Z
derived conclusion: security finding applies
```

Facts and evidence remain separate namespaces.

## External Consumers

```text
Drupal Knowledge
    ↓
external consumers
```

A consumer receives only resolved applicable context through the released CLI
and the read-only public API. This repository names no consumer, carries no
consumer-specific adapter, contract or policy, and never encodes one
consumer's needs as universal Drupal guidance. Anything that operates Drupal
Knowledge privately and continuously over particular projects is a separate
product that depends on a tagged release of this repository; this repository
never depends on it. See [COMMUNITY_BOUNDARY.md](COMMUNITY_BOUNDARY.md).

`KNOWLEDGE_AUTHORITY_BOUNDARIES_DEFINED=PASS`
