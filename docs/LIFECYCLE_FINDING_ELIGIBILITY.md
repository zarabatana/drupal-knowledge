# First Lifecycle Finding Eligibility Audit

This document audits whether the released Drupal Knowledge stack can safely
authorize its first narrowly scoped Drupal project finding. It is an
authority/design artifact, not canonical Drupal truth, and no finding engine is
implemented by it.

The audited baseline is `main` `90d6238e04adb22e1db5eed77606608c1e27e4f0`,
`VERSION` `0.5.0`, tag `v0.5.0`. The machine-readable companion is
`docs/lifecycle-finding-eligibility.json`.

## Audited Authority Chain

The chain proposed for audit was:

```text
PROJECT ANALYZER exact installed Drupal core version X
+ REVIEWED LIFECYCLE CONTEXT exact release row X
+ NEUTRAL LIFECYCLE EVALUATOR exact_release_match = matched
+ literal authoritative source term "Insecure"
-> CONFIRMED NARROW FINDING
```

The audit result is that this chain is **not** sufficient as stated. It proves
an evidence proposition, but it never crosses into finding authority, because
no reviewed knowledge record declares what that evidence is allowed to assert.

The corrected chain is:

```text
AUTHORITATIVE SOURCE SNAPSHOT
-> REVIEWED LIFECYCLE CONTEXT (exact release row)
+ PROJECT EVIDENCE (exact installed core version)
-> NEUTRAL LIFECYCLE ASSESSMENT (exact_release_match, context_relation)
+ REVIEWED MACHINE FINDING CONTRACT        <-- missing today
-> CONFIRMED NARROW FINDING
```

The layers stay separate:

```text
SOURCE
!= REVIEWED LIFECYCLE CONTEXT
!= PROJECT EVIDENCE
!= LIFECYCLE ASSESSMENT
!= FINDING
!= VULNERABILITY
!= REMEDIATION
```

A source attribute preserved literally in reviewed context is not a finding. A
neutral assessment that reports that attribute is not a finding. A finding is a
separate assertion about a project, and it needs its own reviewed authority.

## Exact Finding Candidate

The audited statement is:

> The installed Drupal core release is explicitly marked "Insecure" in the
> reviewed Drupal release metadata.

Proposed machine assertion, not yet authorized:

`installed_core_release_explicitly_marked_insecure_by_source`

Proposed human title, not yet finalized:

`Installed Drupal core release is explicitly marked Insecure by Drupal release metadata`

Proposed finding type: `release_lifecycle` (alternate:
`authoritative_release_state`). The type `vulnerability` is forbidden.

The statement is deliberately narrower than "project is insecure", "site is
vulnerable", "an exploitable vulnerability exists", "project is compromised", or
"upgrade is mandatory". None of those are audited as defensible.

**Eligibility classification: `CANDIDATE_ONLY`.**

The classification is an authority gap, not an evidence gap. Static certainty is
sufficient and deterministic; what is missing is a reviewed contract that
authorizes the assertion. This is a narrower use of `candidate` than the
existing finding model's pattern-based candidates, and the audit records it
explicitly so the two are not confused.

## Source Term Structure

Audited directly against the pinned snapshot
`sources/snapshots/drupal-core-releases/c7de75d2508c7d134765affdea101e9bc7a4d534d8eaaa97fda3308a14ea0063.txt`
and the reviewed context, not against earlier summaries.

| Property | Audited value |
| --- | --- |
| XML field path | `/project/releases/release/terms/term/value` |
| Taxonomy term name | `Release type` |
| Term value | `Insecure` |
| Attached directly to a release | Yes, 514 of 553 release rows |
| Attached at project level | No; `/project/terms` carries only Projects, Maintenance status, Development status |
| Attributes on `<term>` | None |
| Attributes on `<value>` | None |
| Explicit source identifier beyond display text | No: no term id, vocabulary id, machine name, URI, or enum code |
| Literal occurrences in snapshot | 514 |
| Rows with no `<terms>` container at all | 9 |
| Duplicate occurrences within one row | 0 |
| Distinct from `Security update` | Yes, separate taxonomy values |
| Coexists with security coverage metadata | Yes |

Normalized representation in the reviewed context, both with `state: present`:

- `releases[].terms[].value.source_value`
- `releases[].release_type_source_values[]`

Representative versions carrying the term: `11.4.3`, `11.3.13`, `11.3.12`,
`10.6.12`, `8.0-alpha2`. Representative versions not carrying it: `11.4.5`,
`11.4.4`, `11.3.16`, `11.3.14`, `10.6.15`.

Matching must therefore be literal exact string comparison against the
normalized source value. There is nothing more stable to match on.

`INSECURE_SOURCE_TERM_STRUCTURE_AUDITED=PASS`

## Source Semantics

Two questions must stay separate.

**A. Can we prove that release X carries the source term?** Yes. The exact
release row is addressable, the term is normalized with `state: present`, and
the provenance is complete from analyzer evidence through pinned snapshot
digest.

**B. Can we prove what Drupal means by the term?** No. The pinned snapshot
contains the string 514 times and defines it zero times. There is no vocabulary
documentation, no schema or DTD, no explanatory element, and no identifier that
could be resolved against a definition.

What the current snapshot **does** establish:

- the literal string is attached to specific release rows as a `Release type`
  taxonomy value;
- which exact release versions carry it at the pinned snapshot state;
- that it is a different value from `Bug fixes`, `New features`, and
  `Security update`;
- that it can coexist with a `security` element carrying `covered="1"`.

What the current snapshot **does not** establish:

- what Drupal intends the term to assert about a release;
- whether it implies a known exploitable defect in that release;
- whether it implies the release was superseded by a later security release;
- whether it implies the release lacks security advisory coverage;
- whether it implies any obligation for projects running the release;
- any severity, urgency, or risk ranking.

Classification: `TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY`.

The English word must not be read lexically. `exploitable`, `vulnerable`,
`compromised`, `unsupported`, `unsafe`, and `critical` are all forbidden
readings. Machine authority must come from Drupal source semantics.

The observed distribution actively argues against casual interpretation. 514 of
553 rows carry the term, including Drupal 8 alpha releases. 376 of those rows
simultaneously carry `Covered by Drupal's security advisory policy` with
`covered="1"`, which rules out the reading "not covered by security policy"
without establishing any replacement reading. Ruling a reading out is not the
same as establishing one.

`SOURCE_TERM_PRESENCE_DISTINCT_FROM_TERM_SEMANTICS=PASS`
`INSECURE_TERM_SEMANTICS_NOT_INFERRED=PASS`
`INSECURE_LABEL_NOT_INTERPRETED_LEXICALLY=PASS`

## Existing Knowledge Authority

The candidate authorizing record is `drupal.update.core-release-state-update-feed`.
Its actual content was audited. It was not modified.

| Property | Audited value |
| --- | --- |
| `review_status` | `reviewed` |
| `severity` | `moderate` |
| `enforcement.intent` | `non_blocking` (effective: `guidance`) |
| Declares `machine_finding` | No |
| Declares `machine_applicability` | No |
| Mentions the term `Insecure` | No |
| Defines term semantics | No |
| Defines a finding assertion or title | No |
| Defines a finding type | No |
| Defines condition severity | No |

What it does authorize: treating the release-history feed as the watched source
for Drupal core release state, refusing to hard-code a latest Drupal version as
permanent knowledge, and requiring observed project core version before release
applicability is resolved.

What it does not authorize: asserting a project condition from a release row
source term, defining machine semantics for any release type term, attaching
severity to a lifecycle condition, or emitting a finding from a lifecycle
assessment.

Its condition-bearing text lives in `actions`, `checks`,
`evidence_requirements`, and `automation_hints`. The existing finding model
already declares those fields non-executable. The `checks` entry
("Compare observed project Drupal core versions against the current
release-history source state before making release or support findings") is
human-readable guidance and cannot author a machine condition.

Other reviewed records were checked and also do not authorize the condition:
`drupal.security.advisory-streams-separated` governs where Drupal security
communications live and carries no release row condition or affected-version
model; `drupal.api.version-aware-documentation` governs documentation and
version-aware knowledge selection.

Zero of the ten canonical records declare a `machine_finding` contract.

`EXISTING_KNOWLEDGE_FINDING_AUTHORITY_AUDITED=PASS`

## Finding Authority Conditions

Nine requirements are satisfied today, all on the evidence side:

1. exact installed core version project evidence with evidence IDs;
2. exact reviewed release row present in the lifecycle context;
3. evaluator `release_match.state == matched`;
4. literal source term present with `state: present` in the matched row;
5. canonical reviewed context with verified snapshot integrity;
6. `context_freshness.relation == current`;
7. complete provenance;
8. deterministic evaluation with no semantic judgment;
9. fully offline evaluation.

Five requirements are missing, all on the knowledge side:

1. a reviewed `machine_finding` contract for this evidence domain;
2. reviewed authority for the exact assertion wording and human title;
3. reviewed authority for the finding type;
4. reviewed severity authority, or an explicit declaration that severity is
   unestablished;
5. an owning reviewed record so enforcement resolves through
   `effective_enforcement`.

One requirement is conditional: authoritative source semantics for the term.
That is not required for the literal presence assertion, but it is required for
any meaning-bearing assertion, for severity derivation, and for a remediation
layer.

### Exact release match

A lifecycle finding must require analyzer exact installed core version equal to
the exact reviewed lifecycle release version. Approximate matching, nearest
release, branch-only inference, and "older than" comparison are all forbidden.

If the project core version is unknown, there is no lifecycle finding; the
assessment state is `core_version_unknown`.

If the exact release row is absent from the reviewed context, there is no
lifecycle finding; the assessment state is `release_not_found`. A missing row is
not an unsupported, outdated, invalid, insecure, or end-of-life conclusion.

`LIFECYCLE_FINDING_REQUIRES_EXACT_RELEASE_MATCH=PASS`
`UNKNOWN_CORE_VERSION_CANNOT_AUTHOR_LIFECYCLE_FINDING=PASS`
`MISSING_RELEASE_ROW_CANNOT_AUTHOR_LIFECYCLE_FINDING=PASS`

### Canonical context

Finding eligibility requires the canonical reviewed lifecycle context
`drupal-core-release-lifecycle` at
`knowledge/context/drupal-core-release-lifecycle.json`, loaded through the
evaluator's canonical path, with `artifact_type` `release-lifecycle-context`,
`authority_layer` `TRUSTED_KNOWLEDGE_CONTEXT`, `review.status` `reviewed`, and
verified snapshot digest and byte length.

A self-declared external context cannot author a finding. Review authority comes
from repository review and promotion, not from JSON that declares a review
status or carries plausible provenance.

`LIFECYCLE_FINDING_REQUIRES_CANONICAL_CONTEXT=PASS`

## Non-Authoritative Signals

### Branch membership

`branch_listed_in_source_supported_branches` must never independently authorize
this finding, in either direction. Using the evaluator's own branch-token rule
against the reviewed context, 40 rows on listed branches carry the term and 32
rows on unlisted branches do not. The two dimensions are independent.

`SUPPORTED_BRANCH_MEMBERSHIP_CANNOT_AUTHOR_INSECURE_FINDING=PASS`

### Security coverage

Security coverage metadata alone cannot author the finding. 376 rows carry both
the term and `covered="1"`; 9 rows carry `covered="1"` without the term.
`Covered by Drupal's security advisory policy` does not prove anything about an
installed release's state.

`SECURITY_COVERAGE_CANNOT_AUTHOR_INSECURE_FINDING=PASS`

### Security update term

A release carrying `Security update` must not automatically author an
insecure-installed-release finding. It is a distinct taxonomy value describing
the release itself. Five rows carry `Security update` without the audited term:
`8.9.20`, `9.5.11`, `10.6.13`, `11.3.14`, `11.4.4`.

No vulnerability may be inferred for projects running that release, prior
releases, or other releases without explicit semantics.

`SECURITY_UPDATE_TERM_NOT_INSECURE_FINDING=PASS`

### Other non-signals

Release ordering and the existence of a newer release prove nothing; source
order is feed order and is explicitly not support priority. Absence of the term
in a matched row is `not_observed`, never proof that the release is safe.

## Staleness

A current confirmed lifecycle finding requires `context_relation == current`.

A pinned reviewed context proves that, at the reviewed source snapshot state,
release X carried term Y. It does not prove a current lifecycle assertion if the
authoritative source state has moved. Because the finding layer asserts a
current project condition, a stale context produces `historical_candidate` or
`requires_refresh`, never a current confirmed finding.

The alternative formulation — allowing confirmed findings from a stale context
carrying a staleness qualifier — was considered and rejected. No reviewed
knowledge authorizes a staleness-qualified current assertion, and the existing
finding authority model offers no safer competing formulation.

`CURRENT_LIFECYCLE_FINDING_REQUIRES_CURRENT_CONTEXT=PASS`

## Severity And Enforcement

Severity cannot be derived from an existing reviewed knowledge record, and it
cannot be derived from an explicit lifecycle policy, because neither exists. The
answer is **neither**.

The `moderate` severity on `drupal.update.core-release-state-update-feed` rates
the source-selection rule, not an installed release condition. Transferring it
would be invention by proxy. The lifecycle context contains no severity field at
all. Severity must not be read out of the word `Insecure`.

A future finding must therefore carry `severity: {state: not_established,
source: null}`. It must not present as critical, high, moderate, low, or info.

A confirmed lifecycle finding does not automatically become blocking. All ten
canonical records are `non_blocking` and resolve to `guidance`; zero are
blocking. The future finding stays guidance-only, resolved through
`effective_enforcement` of its owning reviewed record, unless reviewed knowledge
explicitly authorizes stronger enforcement.

`INSECURE_FINDING_SEVERITY_NOT_INVENTED=PASS`
`LIFECYCLE_FINDING_DOES_NOT_ESCALATE_ENFORCEMENT=PASS`
`LIFECYCLE_FINDING_DOES_NOT_OVERSTATE_VULNERABILITY=PASS`

## Proposed Machine Finding Contract

Design only. Declarative only. No free-text execution. Separate from
`machine_applicability`.

```json
{
  "id": "drupal.lifecycle.core-release-marked-insecure-by-source",
  "condition_id": "installed_core_release_carries_source_release_type_term_insecure",
  "finding_type": "release_lifecycle",
  "evidence_domain": "release_lifecycle_assessment",
  "requires": {
    "assessment_evaluation_state": "evaluated",
    "exact_release_match": true,
    "context_relation": "current",
    "canonical_context_id": "drupal-core-release-lifecycle",
    "source_field_path": "/project/releases/release/terms/term/value",
    "source_term_name": "Release type",
    "source_term": "Insecure",
    "match_mode": "literal_exact_string"
  },
  "assertion": "installed_core_release_explicitly_marked_insecure_by_source",
  "assertion_scope": "reviewed_release_metadata_state_of_the_exact_installed_release",
  "severity": {"state": "not_established", "source": null},
  "effective_enforcement": "guidance",
  "states": {
    "term_present_and_context_current": "confirmed",
    "term_present_and_context_stale": "historical_candidate",
    "term_absent_in_matched_row": "not_observed",
    "release_not_found": "unknown",
    "core_version_unknown": "unknown",
    "context_not_canonical": "unknown"
  },
  "remediation_emitted": false
}
```

Reason codes: `LIFECYCLE_SOURCE_TERM_PRESENT_IN_EXACT_RELEASE_ROW`,
`LIFECYCLE_SOURCE_TERM_ABSENT_IN_EXACT_RELEASE_ROW`,
`LIFECYCLE_CONTEXT_STALE`, `EXACT_RELEASE_ROW_NOT_FOUND`,
`CORE_VERSION_UNKNOWN`, `LIFECYCLE_CONTEXT_NOT_CANONICAL`.

Forbidden output claims: project is insecure, site is vulnerable, an exploitable
vulnerability exists, project is compromised, upgrade is mandatory, release is
unsupported, release is end-of-life.

`LIFECYCLE_MACHINE_FINDING_CONTRACT_DESIGNED=PASS`

## Provenance

A future confirmed lifecycle finding must carry:

| Field | Source |
| --- | --- |
| `knowledge_id` | owning reviewed knowledge record |
| `finding_condition_id` | `condition_id` from the machine finding contract |
| `analysis_identity` | project ID, analyzer name/version/mode, `analysis_sha256` |
| `core_version_fact_ref` | `profile.facts.drupal_core_version` |
| `core_version_evidence_ids` | sorted analyzer evidence IDs supporting the fact |
| `lifecycle_assessment_identity` | `assessment_id` from the neutral evaluator |
| `lifecycle_context_id` | `drupal-core-release-lifecycle` |
| `lifecycle_context_source_snapshot_sha256` | pinned immutable snapshot digest |
| `exact_matched_release` | `release_match.source_version` and source order index |
| `exact_source_term_evidence` | XML field path, term name, literal value, normalized context paths |
| `context_freshness` | relation plus both compared digests |
| `effective_enforcement` | `guidance`, resolved from the owning record |
| `severity_source` | `not_established` until reviewed severity authority exists |

`LIFECYCLE_FINDING_PROVENANCE_DEFINED=PASS`

## Deterministic Identity

```text
finding_id = sha256(stable_json({
  knowledge_id,
  finding_condition_id,
  assertion,
  analysis_project_id,
  analysis_sha256,
  core_version_fact_ref,
  core_version_evidence_ids,
  matched_release_source_version,
  lifecycle_context_id,
  lifecycle_context_sha256
}))
```

No timestamp. No run ID, hostname, wall-clock value, or absolute path.
Identical inputs reproduce an identical finding ID offline.

`LIFECYCLE_FINDING_IDENTITY_DESIGNED=PASS`

## Deduplication

One installed Drupal core release produces at most one logical instance of the
same lifecycle condition. The dedup key is knowledge ID, finding condition ID,
project entity (`drupal/core`), and matched release source version. That key is
deliberately coarser than the full finding identity.

The same source term is reachable through four read paths: `releases[].terms[]`
occurrences, the `releases[].release_type_source_values[]` representation, the
assessment's `source_attributes.source_release_type_terms`, and the raw snapshot
XML. All collapse into one logical finding carrying multiple supporting evidence
refs. No release row in the reviewed context carries the term more than once, so
duplicate occurrences are a structural risk to guard rather than an observed
one.

`LIFECYCLE_FINDING_DEDUPLICATION_DESIGNED=PASS`

## Project Version Scope

A finding is scoped to the exact installed release. When a project moves from
release X to release Y, the analyzer observes a different
`drupal_core_version` fact, the evaluator matches a different row, and the
condition is re-evaluated against Y. The finding for X cannot remain current,
because the deterministic identity binds both the matched release version and
the analysis identity.

If Y's row does not carry the term, the result is `not_observed`. If it does, a
new confirmed finding with a new deterministic identity is produced. Historical
retention is external and out of scope for current evaluation.

`LIFECYCLE_FINDING_PROJECT_VERSION_SCOPED=PASS`

## Context Change Semantics

When a new authoritative snapshot is promoted into a newly reviewed lifecycle
context, finding evaluation must be recomputed. The context digest changes, so a
new deterministic finding identity is produced and historical evidence identity
is never mutated in place.

Source collection alone does not promote context. Until a new normalization and
review step lands, the previously reviewed context becomes stale, and a stale
context downgrades to `historical_candidate` or `requires_refresh`.

`LIFECYCLE_FINDING_REEVALUATES_ON_CONTEXT_CHANGE=PASS`

## No Remediation

This audit decides no upgrade target, recommends no version, and generates no
Composer command. Remediation is a separate future authority layer.

`LIFECYCLE_FINDING_AUDIT_HAS_NO_REMEDIATION=PASS`

## Decision

`FIRST_LIFECYCLE_FINDING_AUTHORIZED_NOW=NO_KNOWLEDGE_CONTRACT`

Project evidence and reviewed source evidence are sufficient to prove literal
term presence on an exactly matched release row. The pinned snapshot does not
define the term, so only presence assertions are available at all. No reviewed
canonical knowledge record declares a machine finding contract, assertion,
finding type, or severity authority for that presence. The audited statement is
therefore `CANDIDATE_ONLY` today, blocked by knowledge authority rather than by
evidence.

Outcome C was considered and rejected for this specific candidate. Missing
source semantics would block a meaning-bearing assertion, but the audited
statement asserts only that the reviewed metadata attaches the term. Its truth
conditions do not depend on what the term means. Outcome C remains the correct
answer for any assertion that does depend on the term's meaning.

The exact reviewed knowledge contract that must be added and reviewed next is a
canonical knowledge record carrying a `machine_finding` contract for the
`release_lifecycle_assessment` evidence domain, defining: condition ID and
evidence domain; required assessment inputs including `exact_release_match` and
`context_relation: current`; the literal source term and `literal_exact_string`
match mode; the exact machine assertion and human title; finding type
`release_lifecycle` with an explicit prohibition on vulnerability typing;
`severity.state: not_established` with no invented value; guidance-only
effective enforcement; and provenance, identity, and deduplication requirements.

## Next Required Authority Source

Not required for the candidate condition, and not collected during this task,
but required before any meaning-bearing lifecycle assertion, before reviewed
severity derivation, and before any defensible path toward vulnerability typing:

`official_drupal_release_status_and_update_status_vocabulary_documentation`

Acceptable categories: official Drupal release-status documentation; Drupal
security advisory policy documentation defining release security state; or
update-status / release-history vocabulary documentation defining `Release type`
term values.

`NEXT_REQUIRED_AUTHORITY_SOURCE_IDENTIFIED=PASS`

## Canonical Integrity

This audit changed zero knowledge records, zero lifecycle context bytes, zero
sources, zero snapshots, zero generated outputs, and no Analyzer, Resolver, or
Evaluator runtime. No authority defect was found in the neutral lifecycle
evaluator, so it was not altered. `VERSION` was not bumped.

No runtime finding engine was added: `scripts/dk_findings.py`,
`scripts/dk_lifecycle_findings.py`, `schema/finding.schema.json`, and
`schema/lifecycle-finding.schema.json` all remain absent.

`LIFECYCLE_FINDING_AUTHORITY_AUDITED=PASS`
`LIFECYCLE_FINDING_DISTINCT_FROM_SOURCE_ATTRIBUTE=PASS`
`INSECURE_SOURCE_TERM_FINDING_ELIGIBILITY_DECIDED=PASS`
`LIFECYCLE_FINDING_AUDIT_DOES_NOT_CHANGE_DRUPAL_TRUTH=PASS`

## Next Task

Create and review the minimum canonical knowledge contract required to authorize
the lifecycle finding; do not implement the finding engine yet.

## Runtime Resolution (2026-09-07, after v0.6.0)

Everything above is the settled audit and settlement history and is preserved
verbatim, including its statements that no runtime finding engine existed at
settlement time. Those live-runtime statements are superseded by the additive
`runtime_resolution` block of `docs/lifecycle-finding-eligibility.json`: the
reviewed finding runtime (`scripts/dk_finding_runtime.py`, `dk.py findings`)
now executes the single reviewed `machine_finding` contract against the
neutral release lifecycle assessment and emits schema-validated finding
evaluations. The historical forbidden artifact names remain absent, the
analyzer, resolver, and lifecycle evaluator remain free of `machine_finding`,
severity remains `not_established`, enforcement remains guidance-only, and no
remediation exists. See `docs/FINDING_RUNTIME.md`.
