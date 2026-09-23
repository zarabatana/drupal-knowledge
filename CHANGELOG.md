# Changelog

This is a curated record of what each release added and, just as deliberately,
what it refused to change — not a generated git log. Release themes below the
1.0.0 entry are one line each; the full design rationale for every layer lives
in `docs/`.

Drupal Knowledge Community is the public Core extracted from the Drupal
Knowledge v1.0.0 release. Its history begins at `1.0.0`; the entries below
`1.0.0` describe the releases of the Core's engines and boundaries that led to
it, so that a record's contract version and a document's references can be
read in context.

## 1.1.3 — 2026-09-23

Publishes the reviewed evidence from the 2026-09-22 scheduled ecosystem
discovery run. The run found nothing: this release changes what the dataset
says about when its sources were last looked at, and nothing about Drupal.

### Changed

- Published source provenance now reflects the reviewed discovery run. Both
  registered ecosystem signal sources — the Pathauto and Token module release
  histories — were re-contacted and their content was byte-identical to the
  2026-09-08 observation, so only their `last_observed_at` advanced. Two rows
  of `sources.json` changed, one field each; no snapshot digest moved, and
  every source's title, trust tier, category, role, licence and lifecycle is
  unchanged.
- The canonical dataset identity is now
  `dataset:04a485c68fa2ed0e5d928872224f1bd3`. Two things move it: the reviewed
  freshness above, which is published provenance, and the release version
  itself, which participates in dataset identity through `records_digest`.
  Neither is new knowledge. Against the reviewed pre-release tree the only
  dataset file that changed at all is `manifest.json`, in four derived fields —
  `dataset_id`, `dk_version`, `generated_from_release` and `records_digest` —
  and the record counts behind that digest are identical.

### Unchanged by design

- The run produced no new discovery signal, no new candidate, no new
  corroboration dossier and no new snapshot. The discovery corpus is still ten
  signals and ten dossiers, every one already reviewed `no_action` /
  `insufficient_evidence`.
- Nothing was promoted across a trust boundary. No discovery signal became
  trusted knowledge, a rule, a finding, a solved case or a generalization: a
  source being re-observed is not a source changing, and a source changing
  would still not be a knowledge change.
- The six semantic domain files and the search index are byte-identical to
  1.1.2. No advisory, rule, API lifecycle, change record, solved case or
  knowledge record was added, changed or removed, and every contract version
  advertised by `dk version --json` is unchanged.

## 1.1.2 — 2026-09-23

Publishes the reviewed acquisition evidence from the 2026-09-22 scheduled
run. No reviewed conclusion about Drupal changed in this release; what
changed is the evidence those conclusions are pinned to, and the record of
the human review that accepted it.

### Changed

- Published source provenance now reflects the reviewed acquisition: eight
  authoritative sources carry new immutable snapshot digests and all twelve
  contacted sources carry new observation timestamps. Every source's title,
  trust tier, category, role, licence and lifecycle is unchanged, and no
  published record content changed — the six domain files and the search
  index are byte-identical to 1.1.1.
- The reviewed Drupal core release-lifecycle context was re-normalized onto
  the new snapshot, 556 to 559 releases. Drupal marked nine previously
  covered releases `Insecure` after its 2026-09-16 core security release:
  11.4.6, 11.4.5, 11.4.4, 11.3.16, 11.3.14, 10.6.16, 10.6.15, 10.6.14 and
  10.6.13, superseded by 11.4.7, 11.3.17 and 10.6.17.
- The update-module semantic authority advanced from Drupal 11.4.5, which is
  now one of those insecure releases, to 11.4.7. The three pinned files are
  byte-identical at both tags, verified by raw fetch and by re-acquisition
  reporting `unchanged`, so the reviewed meaning is untouched and only the
  representative release moved. `dk_core.semantic_authority_tag()` is now
  the single place that answers which release that is.

### Added

- `docs/lifecycle-finding-eligibility-review-2026-09-23.json`, a superseding
  review that records the current observation, the drift from the frozen
  2026-09-07 audit as a conservation identity, and why a statement that was
  true at the audit is no longer true. The 2026-09-07 audit itself is
  historical evidence and is unchanged.

### Unchanged by design

- No advisory, rule, API lifecycle or knowledge record was added, changed or
  removed. SA-CORE-2026-013, SA-CONTRIB-2026-148 to 2026-153, PSA-2026-09-21
  and the Drupal 12.0.x / 11.5.x change records remain review candidates:
  a source change is not a knowledge change.
- Every contract version advertised by `dk version --json` is unchanged.

## 1.1.1 — 2026-09-22

### Fixed

- Corrected Community public branding and repository references. The About
  page now states the edition's identity — Drupal Knowledge, maintained by
  Zarabatana; Drupal Knowledge Community as the public, open-source edition —
  and lists what the release actually holds. Its clone instruction is the
  canonical `git clone https://github.com/zarabatana/drupal-knowledge.git`.
- Updated About content to describe the existing read-only public API
  accurately. The page no longer says the site "is not an API" or that a
  supported API is separate future work; it distinguishes the supported,
  independently versioned public API from the internal JSON build artifacts
  behind the pages.
- Described the source-to-knowledge process accurately on the About page and
  in the site footer: published pages are generated artifacts; canonical
  knowledge and editorial content are maintained and reviewed in the
  repository; a source change is not a knowledge change and a discovery
  signal is not knowledge. The footer no longer claims that nothing on the
  site is edited by hand while maintained editorial pages exist.
- Strengthened generated-site regression checks for stale pre-split
  branding: the isolated site build is scanned for the previous maintainer's
  branding, the historical clone instruction and the stale API claims, the
  About page must carry the canonical identity, repository and API wording,
  and no page may name a maintainer other than Zarabatana.

### Unchanged by design

- Scheduled acquisition and discovery, their persistence boundary and the
  trust invariants are untouched. Every contract version is unchanged.

## 1.1.0 — 2026-09-22

### Added

- Scheduled registered-source acquisition:
  `.github/workflows/scheduled-acquisition.yml` runs
  `dk.py acquire --trust authoritative --due` every six hours and on demand.
  The engine's per-source cadence decides what is contacted; `--all` is never
  used. A run that changed nothing produces no commit and no pull request. A
  run that observed a change regenerates the derived public artifacts with the
  canonical commands and persists source state, immutable snapshots, review
  candidates and those artifacts on the deterministic branch
  `automation/source-acquisition` as a pull request that later runs update.
  Such a pull request stays red until a human re-reviews any pinned context
  and inventories each new snapshot in `THIRD_PARTY_LICENSES.json`; the
  manifest is never written by automation.
- Scheduled discovery and review-candidate processing:
  `.github/workflows/scheduled-discovery.yml` runs
  `dk.py discover --trust ecosystem --due` daily and on demand, over
  registered signal sources only, persisting signals, corroboration dossiers,
  snapshots, state and candidates on `automation/discovery` the same way.
- `scripts/dk_automation.py`: the one place that fixes what a scheduled run
  may persist. Trusted knowledge, rules, API lifecycle and security records,
  code, documentation, CI configuration and the source registry are rejected
  before anything is committed; a report recording a trusted-knowledge
  mutation is refused; run summaries, commit messages and pull request bodies
  are rendered from the engine's own report. `scripts/test_scheduled_automation.py`
  exercises the rejection, the failure semantics (a fetch failure is never
  "unchanged") and the least-privilege shape of both workflows.
- Generated-public-output repository identity validation: the public site is
  built into an isolated directory and every generated file is scanned for any
  non-canonical repository identity; every rendered page must carry exactly one
  Repository link, to `github.com/zarabatana/drupal-knowledge`. The public API
  artifacts and release metadata are scanned the same way.
- AI-development provenance hygiene guard: `scripts/test_community_boundary.py`
  rejects development-tool and AI-agent attribution — co-author trailers naming
  such tools, their no-reply addresses, "generated with" banners, agent
  instruction files, and any such trailer in the commit at `HEAD`. Product
  statements about language models and third-party material are not matched.

### Fixed

- Public Repository links are now explicitly validated against the canonical
  GitHub Community repository on every generated page, not only on the CLI
  page. The rendered link was already canonical at `1.0.0`; the gap was that
  nothing proved it for generated output.

### Unchanged by design

- Automation never pushes to `main`, never merges, never bypasses the branch
  ruleset, holds no credential beyond the workflow token, and has no path to
  `knowledge/`: SOURCE CHANGE != TRUSTED KNOWLEDGE CHANGE, DISCOVERY SIGNAL !=
  TRUSTED KNOWLEDGE, and unknown is never `false`.
- The validation workflow still never acquires or discovers.
- Every contract version advertised by `dk version --json` is unchanged.

## 1.0.0 — 2026-09-21

Drupal Knowledge Community v1.0.0: the public Core — evidence-backed Drupal
knowledge, authoritative source acquisition, security advisories, API
lifecycle and change records, upgrade and migration intelligence,
implementation rules, the read-only project analyzer, solved-case workflow,
discovery and corroboration, the community CLI, the static website and the
read-only public API. Every analysis engine, every contract and every
boundary law from 0.1.0–0.21.0 ships unchanged.

### Community extraction

- The repository is the public Core of a product that also has a separately
  governed, privately operated layer. That layer, its record contracts,
  documentation, container image, CI templates and tests are not part of this
  repository, and nothing here imports or depends on them.
  `scripts/test_community_boundary.py` enforces that direction.
- Knowledge records no longer carry a consumer-specific eligibility object
  (`eligible` / `stages` / `notes`). It was removed from every record and
  from `schema/knowledge-record.schema.json`, together with an unused
  consumer-specific projection property and the matching taxonomy domain.
  Nothing in the public dataset, the public API or the CLI query layer ever
  exposed these fields, so the published `dataset_id` is unchanged.
- `dk validate` no longer checks a consumer-specific integration contract;
  `validate_consumer_contract` checks the same product-neutral invariant
  (a project-profile fact state must be able to say `unknown`).
- `dk status` and `dk version` advertise the Core's interfaces only.
- Schema `$id` values, the acquisition User-Agent and the website's
  repository links point at `github.com/zarabatana/drupal-knowledge` and
  `drupal-knowledge.zarabatana.info`.
- The OpenAPI document's licence field names Apache-2.0, matching the
  repository licence added in this release.
- Validation runs in `.github/workflows/community.yml` on standard
  GitHub-hosted runners: the same test suites as before, the same
  regeneration gates, no acquisition, no credential.
- Added `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `TRADEMARK.md`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` and
  `docs/COMMUNITY_BOUNDARY.md`.

### Unchanged by design

- Canonical knowledge remains immutable at runtime; no CLI, website or API
  path can write it.
- Unknown never becomes pass, and unknown is never `false`.
- No source snapshot, discovery signal, solved case or project observation
  can become trusted knowledge without explicit human review expressed as a
  reviewed edit to this repository.
- The public API routes `GET`, `HEAD` and `OPTIONS` only and reads the
  published dataset, never a canonical store.
- The website renders the published dataset and cannot disagree with the CLI.
- The dependency policy is the Python standard library only, proven by the
  SBOM import scan.

## 0.26.0 — 2026-09-14, 0.25.0 — 2026-09-13, 0.24.0 — 2026-09-13, 0.23.0 — 2026-09-13, 0.22.0 — 2026-09-13

Releases of the privately operated layer. They added no engine, no contract
and no boundary to the Core, and none of their content is in this
repository.

## 0.21.0 — 2026-09-13

Public Knowledge API: a read-only, HTTP-free contract module plus a
stdlib-only transport, generated OpenAPI 3.1, and a third public surface that
cannot write or disagree with the CLI.

## 0.20.0 — 2026-09-13

Public knowledge website: static rendering of the same released dataset the
CLI reads, so the site can never disagree with it.

## 0.19.0 — 2026-09-09

Community CLI and the reusable query layer: `dk_query` decides, `dk_render`
formats, and ranking is banded and non-fuzzy across seven trust classes.

## 0.18.0 — 2026-09-09

Explainable implementation findings: nine reviewed rules over persisted
project evidence, each conclusion capped by what the rule can actually
confirm.

## 0.17.0 — 2026-09-09

Canonical project-evidence layer: new analyzer facts and the
`evidence_matches` / `evidence_absent` resolver operators, making absence a
first-class observation.

## 0.16.0 — 2026-09-09

API migration intelligence: lexed (not grepped) usage observation over the
`api/lifecycle/` and `api/change-records/` stores.

## 0.15.0 — 2026-09-08

Upgrade compatibility intelligence; every transition rule is a verified quote.

## 0.14.0 — 2026-09-08

Security remediation intelligence: fix paths derived from advisories that
never offer a downgrade.

*0.13.0 was never published: a parallel release branch had claimed the number
before 0.14.0 shipped, and publishing it afterwards would have moved the
version backwards. The number is permanently retired.*

## 0.12.0 — 2026-09-08

Security advisory intelligence: the structured advisory feed with criticality
as a vector, never a score.

## 0.11.0 — 2026-09-08

Solved-case recurrence generalization: repeated solved cases may propose, but
never silently become, general knowledge.

## 0.10.0 — 2026-09-08

Ecosystem discovery and corroboration: independence established by declared
lineage, never by comparing claim content.

## 0.9.0 — 2026-09-08

Authoritative knowledge acquisition engine: canonical knowledge grows only
from inspected, registered sources under source-count guards.

## 0.8.0 — 2026-09-08

Solved-case capture foundation: real solved problems recorded with identity,
evidence and provenance.

## 0.7.0 — 2026-09-08

Runtime-first confirmed lifecycle findings: the first finding contract, built
so a finding exists only when its evidence does.

## 0.6.0 — 2026-09-07

Insecure-release semantics in canonical knowledge: what "insecure" means,
stated precisely before anything acts on it.

## 0.5.0 — 2026-08-31

Release lifecycle evaluator: deterministic evaluation of a project's Drupal
releases against the recorded lifecycle context.

## 0.4.0 — 2026-08-31

Authoritative release lifecycle context: the pinned, hand-reviewed record of
Drupal release lines and their support states.

## 0.3.0 — 2026-08-31

Applicability resolver foundation: deciding whether a piece of knowledge
applies to a concrete project, as its own reviewed discipline.

## 0.2.0 — 2026-08-30

Drupal project analyzer foundation: static observation of a project's
composition without executing its code.

## 0.1.0 — 2026-08-30

Initial authoritative knowledge baseline: hand-reviewed Drupal knowledge
checked against canonical evidence, with source inspection and coverage
invariants from the first commit.
