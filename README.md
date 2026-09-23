# Drupal Knowledge

**Drupal Knowledge Community** — maintained by Zarabatana.

Evidence-backed Drupal knowledge you can trace: security advisories, API
lifecycle and change records, upgrade and migration intelligence, reviewed
implementation rules, and a read-only project analyzer — every statement
labelled with how far it can be trusted and where it came from.

It runs from a clone, with Python 3 and nothing else. There is no build step,
no service, no account, no network access at query time and no telemetry.

## What it is

Drupal Knowledge is a Git-backed evidence system. Registered authoritative
Drupal sources are acquired into immutable, content-addressed snapshots;
structured records are projected from those snapshots; a small set of
knowledge records and implementation rules is reviewed by humans against them;
and one query layer answers every question the same way for the command line,
the static website and the public API.

Three public surfaces, one query layer, one set of trust labels:

```text
PUBLIC    community CLI (./dk) · static website · read-only knowledge API
          one query layer, one set of trust labels, no accounts
```

It is not a crawler, not a vector store, not an always-running service, and
it does not claim comprehensive Drupal coverage in v1.0 or any release. What
it knows, it can show the evidence for; what it does not know, it says.

## What it knows

At v1.1.2 the repository holds:

- **Security advisories** — Drupal Security Team advisories projected from
  authoritative structured sources, preserving the risk vector as written,
  assigned CVEs, the advisory's own affected-version expression and the fixed
  releases it names.
- **API lifecycle and change records** — Drupal core deprecation and removal
  versions read from the mandated `@deprecated` annotation on api.drupal.org,
  and official core change records with their introduced branch and version.
- **Release lifecycle context** — a pinned, hand-reviewed record of Drupal
  release lines and support states, with an evaluator that joins it to a
  project's installed releases.
- **Upgrade transitions** — quoted verbatim from official Drupal.org upgrade
  documentation and re-verified against the pinned snapshot at validation
  time.
- **Implementation rules** — nine reviewed performance, security and
  configuration-quality rules, each pinned to the snapshot and the quoted
  lines it was reviewed against.
- **Reviewed knowledge records** — a small set of hand-reviewed records with
  explicit source citations, version applicability and enforcement intent.
- **Solved cases, discovery signals and review candidates** — evidence that
  is explicitly *not* trusted knowledge, kept in its own place with its own
  labels.

`./dk status` reports exactly what a checkout knows and how current it is;
`generated/coverage.json` records which taxonomy domains are `FOUNDATION`,
`PARTIAL` or `EMPTY`. Coverage is what the counters say, not more.

## Trust model

Every record carries a trust class, and exactly one of them is trusted
knowledge:

```text
SOURCE
!= TRUSTED KNOWLEDGE
!= PROJECT FACT
!= OBSERVED EVIDENCE
!= APPLICABILITY RESULT
!= FINDING
!= SOLVED CASE
!= DISCOVERY SIGNAL
!= RECURRENCE
!= GENERALIZATION PROPOSAL
```

```text
SOURCE CHANGE != TRUSTED KNOWLEDGE CHANGE
UNKNOWN       != FALSE
```

- A **source** is a monitored authoritative origin. Its snapshot preserves
  what was seen; source text is not trusted knowledge by itself.
- A **source change** creates a review candidate with `review_required=true`
  and `can_promote_to_knowledge=false`. It never mutates trusted knowledge.
- A **discovery signal** is an untrusted community observation. Corroboration
  counts independent evidence origins, never popularity, and even a fully
  corroborated dossier only authorises later human review.
- A **solved case** says a solution was proven in one specific context. It is
  never automatically a universal Drupal rule.
- A **project fact** that cannot be observed stays `unknown`. Unknown is never
  treated as `false`, and never becomes a pass.
- **Enforcement** is computed from review status plus explicit intent, never
  from severity. Unreviewed records are advisory and cannot block anything.

Trusted knowledge changes only by explicit, reviewed edits to this
repository. The CLI, the website and the API offer no flag, route or setting
that moves anything across a trust boundary. See `docs/ARCHITECTURE.md`.

Source trust classes, in descending authority: `authoritative` (Drupal.org,
api.drupal.org, Drupal Security Team, official coding standards),
`industry-standard` (WCAG, PHP, Symfony, Composer, OWASP — only when a record
depends on them), `ecosystem` (project pages, issue queues, upstream
repositories; never blocking on its own), `discovery` (community discussion;
advisory until reviewed) and `internal-proven` (cases solved and verified by
the maintainers; strong recurrence evidence, not universal guidance).

## Install and use

```bash
git clone https://github.com/zarabatana/drupal-knowledge.git
cd drupal-knowledge
./dk status
```

`./dk` and `python3 scripts/dk.py` are the same program. Python 3.12 or newer
is the only requirement; the dependency policy is the standard library only,
verified by the release SBOM.

```bash
./dk status                                 what this release knows, how current it is
./dk project /path/to/drupal-project        inspect a project, read-only
./dk search file_create_url                 advisories, APIs, rules and knowledge
./dk explain SA-CORE-2025-004               why a record exists and what supports it
./dk provenance <record-id>                 trace a record to its source snapshot
```

Every result states how far it can be trusted. Nothing writes to a project,
runs Composer, executes Drupal or reads a database, and querying never
mutates Drupal Knowledge. Output carries no absolute path, no project name
and no secret, so a `--json` result is safe to paste into an issue.

## CLI

Default help is the developer workflow; maintainer operations are one flag
away and never implied.

```bash
./dk status --json
./dk project /path/to/drupal-project --target 10.6.13
./dk search views --domain advisory --explain
./dk explain drupal.security.twig-output-escaping
./dk provenance api-lifecycle.3f79df0f90cc1c83
./dk security-advisories list --kind core
./dk security-evaluate analysis.json
./dk security-remediation analysis.json
./dk upgrade-evaluate analysis.json --target 11.4.6
./dk upgrade-path analysis.json --format json
./dk migration-analyze analysis.json --target 10.6.13 --project-path /path/to/project
./dk migration-work analysis.json --target 10.6.13 --project-path /path/to/project
./dk evidence analysis.json --project-path /path/to/project --domain configuration
./dk evidence-diff before.json after.json
./dk implementation-findings analysis.json --project-path /path/to/project --explain
./dk api-lifecycle coverage
./dk coverage
./dk --help-maintainer                      acquire, review, promote — never implied
./dk --help-internal                        validate, generate, publish
```

The community CLI and the query layer under it are documented in
`docs/CLI.md`. One query layer answers every surface, so the terminal, the
website and the API reach the same conclusions with the same trust labels and
the same stated unknowns; rendering never decides anything.

## Project analysis

`./dk project` runs the read-only Drupal Project Analyzer and the engines
over it:

- **Project analyzer** — extracts profile facts and observed evidence from
  `composer.json`, `composer.lock`, `core.extension` and custom code. It
  executes nothing and applies no rule. See `docs/PROJECT_ANALYZER.md`.
- **Project evidence** — one canonical evidence layer across code,
  configuration, dependency, extension and metadata domains, each declaring
  whether its search was complete, bounded, partial or unknown. Secrets and
  absolute local paths are refused before a record exists. See
  `docs/PROJECT_EVIDENCE.md`.
- **Security applicability and remediation** — a confirmed finding needs a
  resolved project identity, a definitively observed installed version and
  an affected-version match; anything less stays candidate or unknown. The
  remediation path never offers a downgrade and never runs a dependency
  command. See `docs/SECURITY_INTELLIGENCE.md`, `docs/SECURITY_REMEDIATION.md`.
- **Upgrade compatibility** — a target is judged across core transition,
  contributed projects, Composer constraints, PHP platform requirements,
  extension lifecycle and project code, with every transition rule a verified
  quote from official documentation. See `docs/UPGRADE_COMPATIBILITY.md`.
- **API migration** — usage is observed from a lexed PHP token stream, so a
  deprecated name inside a comment or string is never a usage; identity is
  fully qualified on both sides. See `docs/API_MIGRATION.md`.
- **Implementation findings** — a finding needs a reviewed rule whose
  authority is a registered authoritative source *and* evidence definitive
  enough to settle it; missing either produces a candidate or an unknown.
  See `docs/IMPLEMENTATION_FINDINGS.md`.

Project evidence, findings, upgrade assessments and migration work items
describe one repository at one revision. They are never published and never
become knowledge about Drupal.

## Public website

Everything in `knowledge/`, `security/`, `api/`, `rules/` and `cases/` is
browsable as a static website, generated from the released query layer
rather than from the files:

```text
canonical records -> dk_query.py -> dk_public.py -> public-site/dataset/ -> pages
```

The renderer imports `html`, `json`, `pathlib` and `typing` and nothing
else. It cannot reach a canonical record, so it cannot disagree with the CLI.
The site has no accounts, no analytics, no tracking and no server component.

```bash
python3 scripts/dk.py public-site build      # dataset + site -> public-site/dist
python3 scripts/dk.py public-site serve      # http://127.0.0.1:8000/
```

The dataset is committed, content-addressed and byte-compared, so changing a
canonical record without rebuilding fails `dk validate`. See
`docs/PUBLIC_SITE.md`. The public website will be published at
`drupal-knowledge.zarabatana.info`.

## Public API

The same records again, as read-only JSON for tools:

```bash
python3 scripts/dk.py api serve      # http://127.0.0.1:8088/api/v1
python3 scripts/dk.py api routes     # the route table
python3 scripts/dk.py api build      # regenerate openapi.json and examples
```

`GET`, `HEAD` and `OPTIONS` are the only methods it routes; it reads the
published dataset rather than any canonical store, and a test walks the call
graph from `handle()` to prove nothing reachable from a request can write.
Every response carries `api_contract_version`, `dk_version` and
`dataset_id`; every result carries `trust_class` and a `trusted_knowledge`
boolean. `public-api/openapi.json` is OpenAPI 3.1 generated from the same
route table the server dispatches. See `docs/PUBLIC_API.md`.

## Sources and provenance

`sources/registry.json` is the high-authority allow-list: Drupal.org,
api.drupal.org, updates.drupal.org and drupalcode.org pages, each with a
declared trust class, cadence and content window. Registered sources are
fetched, normalized, hashed and stored under `sources/snapshots/` as
immutable `SHA-256`-named files; `sources/state/` points to the exact
snapshot hash. Every derived record cites its source id and snapshot hash,
and `./dk provenance <id>` walks that chain.

Acquisition is a maintainer operation (`dk acquire`, `dk discover`) and is
never run by the validation workflow. A network or parse failure is reported
as unavailable or malformed, never as unchanged. See `docs/SOURCES.md` and
`docs/ACQUISITION_ENGINE.md`.

Snapshots are third-party material redistributed under their sources' own
terms with attribution; see `THIRD_PARTY_NOTICES.md`.

## Solved cases

Solved cases are first-class records for problems the maintainers solved and
verified in one real project, stored by fingerprint and never by project
name:

```text
captured -> verified -> recurring -> generalization proposal -> human review -> trusted knowledge
```

No automatic promotion exists at any point in that chain. Recurrence is
counted per distinct project fingerprint and grouped by exact structural
identity, never by description similarity. See `docs/SOLVED_CASES.md` and
`docs/RECURRENCE_GENERALIZATION.md`.

## Contributing

Contributions are welcome — code, documentation, source registrations,
evidence and review. An accepted contribution is not automatically trusted
knowledge: a knowledge change still needs source evidence, validation and
review before it earns a trust class. See `CONTRIBUTING.md` and
`CODE_OF_CONDUCT.md`.

The repository validates itself:

```bash
python3 scripts/dk.py validate
python3 scripts/test_community_boundary.py
```

`.github/workflows/community.yml` runs every gate on every push and pull
request, on standard GitHub-hosted runners, with no credential and no
network acquisition.

## Security

To report a vulnerability in Drupal Knowledge itself, use the private
disclosure path in `SECURITY.md` — not a public issue. Vulnerabilities in
Drupal belong to the Drupal Security Team; this project only records what
they publish.

## Versioning

`VERSION` is the product release (`1.1.2`). Contract versions — the public API
contract, the dataset schema and every engine's record schema — are declared
in code, advertised by `dk version --json` and versioned on their own
schedules. What each promises through 1.x, and what a consumer should pin, is
in `docs/VERSIONING_AND_COMPATIBILITY.md`; what changed in each release is in
`CHANGELOG.md`.

## Repository shape

```text
sources/registry.json       High-authority source allow-list
sources/state/              Last known source hashes and acquisition state
sources/snapshots/          Immutable normalized source snapshots
knowledge/records/          Canonical reviewed Drupal knowledge records
knowledge/context/          Reviewed release-lifecycle and upgrade context
security/advisories/        Authoritative security advisory records
api/lifecycle/              Source-derived Drupal symbol lifecycle records
api/change-records/         Source-derived Drupal core change records
rules/implementation/       Reviewed performance, security and config-quality rules
cases/solved/               Verified solved cases (fingerprints only)
cases/recurrence/           Recurrence analyses over verified cases
cases/generalizations/      Generalization proposals awaiting review
discovery/candidates/       Source-change review candidates
discovery/signals/          Untrusted ecosystem discovery signals
discovery/review/           Corroboration dossiers awaiting human review
evidence/projects/          Optional evidence sets, stored by fingerprint only
config/                     Declared bounds of custom-code scan and evidence observation
schema/                     JSON schemas and contracts
taxonomy/domains.json       Extensible Drupal domain model
generated/                  Deterministic generated aggregates
public/                     Deterministic static browse index
public-site/                Public website source, dataset and build output
public-api/                 Generated OpenAPI document, response schema and examples
release/                    Generated release SBOM and artifact checksums
tests/fixtures/             Synthetic project and case fixtures
collectors/collect.py       Targeted source collection CLI over the engine
dk                          Community entry point over the same CLI
scripts/dk.py               CLI, community-first by audience
scripts/dk_core.py          Loading, validation and shared contracts
scripts/dk_query.py         Reusable trust-preserving query layer
scripts/dk_render.py        Terminal rendering, no query semantics
scripts/dk_public.py        Deterministic public dataset export over the query layer
scripts/dk_site_render.py   Static site rendering, dataset-only by construction
scripts/dk_api.py           Public Knowledge API contract, callable without HTTP
scripts/dk_api_http.py      HTTP transport for the API, semantically thin
scripts/dk_acquisition.py   Knowledge acquisition engine
scripts/dk_discovery.py     Ecosystem discovery and corroboration engine
scripts/dk_solved_case.py   Solved-case capture
scripts/dk_generalization.py   Solved-case recurrence and generalization engine
scripts/dk_security.py      Security advisory intelligence engine
scripts/dk_remediation.py   Security remediation and update-path engine
scripts/dk_upgrade.py       Upgrade compatibility and upgrade-path engine
scripts/dk_api_lifecycle.py    Source-derived Drupal API lifecycle and change records
scripts/dk_php_lexer.py     Bounded PHP lexer separating code from comments and strings
scripts/dk_migration.py     Custom-code API migration work-item engine
scripts/dk_project_analyzer.py Read-only Drupal project analyzer
scripts/dk_applicability.py    The one applicability resolver
scripts/dk_evidence.py      Canonical project evidence layer
scripts/dk_implementation.py   Reviewed implementation rules and findings
scripts/dk_finding_runtime.py  Reviewed machine finding contract runtime
scripts/dk_release_lifecycle.py           Reviewed release lifecycle context
scripts/dk_release_lifecycle_evaluator.py Release lifecycle evaluation
scripts/dk_release_meta.py  Release SBOM and artifact checksum builders
scripts/test_*.py           The validation suites the workflow runs
```

## Licence

The original Drupal Knowledge source code, schemas, tests and documentation
in this repository are licensed under the Apache License, Version 2.0 — see
`LICENSE` and `NOTICE`.

The Apache-2.0 licence does **not** relicense third-party material.
Everything acquired from a registered source — the normalized snapshots under
`sources/snapshots/` and the titles, excerpts and structured facts derived
from them — remains under its source's own terms (CC BY-SA 2.0 for Drupal.org
content; GPL-2.0-or-later for Drupal core, api.drupal.org and drupalcode.org
repository content) and is redistributed with attribution.
`THIRD_PARTY_LICENSES.json` lists every redistributed file with its SHA-256,
origin and the documentary evidence for its licence; `THIRD_PARTY_NOTICES.md`
is the readable form. No copyright owner is asserted for the original
material at this release; it is published as Drupal Knowledge Community,
maintained by Zarabatana.

## Trademark notice

Drupal is a registered trademark of Dries Buytaert. Drupal Knowledge is an
independent project and is not affiliated with, endorsed by or sponsored by
the Drupal Association or Dries Buytaert. The name "Drupal" is used only to
refer to the Drupal software this project documents, and this repository
uses no Drupal logo or other protected branding. See `TRADEMARK.md`.

Drupal Knowledge Community is maintained by Zarabatana. A separately
governed product may operate this Core privately and continuously over
particular projects; that product depends on tagged releases of this
repository, and this repository never depends on it. See
`docs/COMMUNITY_BOUNDARY.md`.
