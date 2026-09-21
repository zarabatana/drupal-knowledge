# Lifecycle Finding Contract

Drupal Knowledge now carries its first reviewed `machine_finding` contract. It
lives on the canonical knowledge record:

`drupal.update.core-release-insecure-term-condition`

The contract is declarative data. Since the 2026-09-07 runtime increment it is
executed by exactly one reviewed component, the finding runtime
(`scripts/dk_finding_runtime.py`, exposed as `dk.py findings`).

## What The Contract Authorizes

Exactly one future assertion:

`installed_core_release_is_not_secure_per_drupal_update_status`

Human title:

`Installed Drupal core release is classified as not secure by Drupal Update Manager`

The trigger is unchanged and literal: the reviewed Drupal release metadata
attaches the `Release type` term value `Insecure` to the exact release row
matching the Analyzer-observed installed Drupal core version. What is new is
that reviewed current Drupal 11 authority now defines what that trigger means,
so the contract's strongest state is `confirmed` when the term is present on the
exact installed release under a current canonical context.

The authorized meaning is exactly and only:

> For Drupal Update Manager release metadata, a release carrying Release type
> "Insecure" is treated as insecure; when that exact release is installed,
> Drupal assigns NOT_SECURE status, whose documented meaning is that the project
> is missing security update(s).

A finding may explain: Drupal Update Manager defines this status as the project
missing security update(s).

## Semantic Authority Chain

The meaning above is proven, link by link, from pinned current Drupal 11.4.5
update-module sources — never inferred from the English word and never from the
release-history feed, which carries the term without defining it
(`TERM_MEANING_REQUIRES_ADDITIONAL_AUTHORITY` remains the enforced state for any
contract without this reviewed authority):

| Authority | Explicit fact |
| --- | --- |
| `ProjectRelease.php` (`drupal-update-project-release-semantics`) | `isInsecure()` literally returns `isReleaseType('Insecure')`, a strict `in_array(..., TRUE)` membership test over `terms['Release type']` from the feed |
| `update.compare.inc` (`drupal-update-status-security-semantics`) | in `update_calculate_project_update_status()`, `existing_version === $version` with `$release->isInsecure()` assigns `UpdateManagerInterface::NOT_SECURE`, and a later guard returns as soon as a status is known, so the assignment is terminal |
| `UpdateManagerInterface.php` (`drupal-update-manager-interface-semantics`) | `NOT_SECURE` is documented as "Project is missing security update(s)." |

No link is inferred. Each source is registered as `authoritative`, pinned to the
immutable release tag `11.4.5` on git.drupalcode.org with an immutable
content-addressed snapshot, and referenced by the record. With the chain
reviewed, the record's `term_semantics.state` is
`DRUPAL_UPDATE_STATUS_SEMANTICS_REVIEWED`; historical Drupal 8 implementations,
issue comments, and third-party writing were not used as authority.

## What The Contract Does Not Authorize

Even with the reviewed meaning, the contract makes no claim of a known
exploitation path, no specific CVE identifier, no finding severity level, no
compromise of any site, and no support, obsolescence, end-of-life, or
upgrade-obligation status. `NOT_SECURE` is a Drupal Update Manager
classification — the project is missing security update(s) — and nothing more.

The `term_semantics` block pins those boundaries structurally: the validator
rejects any reviewed contract whose `forbidden_claims` stop forbidding
exploitability, specific-CVE, compromise, or severity derivation, and rejects
any `authorized_meaning` whose text smuggles such claims.

The `drupal-core-releases` snapshot itself still attaches the term to 514 of
553 release rows without defining it; term presence there proves only presence.
The meaning comes exclusively from the three reviewed update-module sources
above, which is why they — and not the feed — are the
`semantic_authority_refs`.

## Exact Source Field

| Property | Value |
| --- | --- |
| Source | `drupal-core-releases` |
| XML field path | `/project/releases/release/terms/term/value` |
| Taxonomy term name | `Release type` |
| Term value | `Insecure` |
| Attached to | individual release rows only |
| Explicit identifier | none; display text is the only stable handle |

## Literal Exact Matching

`match_mode` is `literal_exact_string`. The contract does not permit regular
expressions, JSONPath, XPath expressions, case-insensitive comparison, aliases,
synonyms, natural-language interpretation, or model classification. The schema
pins every `requires` value with `const` and rejects unknown keys, so no
expression can be smuggled into the contract.

## Exact Release Requirement

`exact_release_match` is `true` and `evaluation_state` must be `evaluated`. The
lifecycle assessment must have matched the exact Analyzer-observed installed
core version against an exact reviewed release row.

There is no branch-only matching, no nearest release, no newer/older comparison,
and no range. The `requires` block contains no branch, range, or ordering key,
and the schema rejects any attempt to add one.

## Canonical And Current Context

`canonical_context_id` is `drupal-core-release-lifecycle`, and
`context_relation` must be `current`.

A stale reviewed context can still prove what the metadata said at its pinned
snapshot, so it downgrades to `historical_candidate`. It never authorizes a
current confirmed finding. A context that is not the canonical reviewed artifact
yields `unknown`.

## Confirmation Authority Is Established Through References

A knowledge contract must not manufacture finding authority by declaring "if
observation X is present, X is a confirmed finding" while the authority that
makes X adverse or relevant is unknown. The validator enforces this
anti-bootstrap rule directly, in both directions: `confirmed` states require
`semantic_authority_reviewed` paired with reviewed term semantics and
resolvable references, and unresolved semantics cap every contract at
`candidate`.

Evidence completeness and semantic authority remain separate dimensions. The
evidence chain was already complete; the settlement kept the contract at
`candidate` because the semantic bridge was missing. That bridge is now supplied
by the reviewed chain above, so the same complete evidence may yield
`confirmed`:

```json
{
  "status": "semantic_authority_reviewed",
  "semantic_authority_refs": [
    "drupal-update-project-release-semantics",
    "drupal-update-status-security-semantics",
    "drupal-update-manager-interface-semantics"
  ],
  "required_semantic_authority_category": "official_drupal_release_status_and_update_status_vocabulary_documentation"
}
```

`status` stays a closed enum, and the reviewed value is reachable only through
explicit resolvable references — every reference must be a baselined registered
source with a verified immutable snapshot or a reviewed canonical knowledge
record, references must be non-empty and unique, fabricated references are
rejected, and a status flip with empty references is rejected. Demoting any
single field while the rest stay promoted is rejected; the full candidate
generation (unresolved semantics, empty references, candidate states) remains
representable and validates.

## Version-Scoped Semantic Authority

The reviewed meaning is proven from pinned Drupal 11.4.5 update-module sources
on the 11.x branch, so the contract's
`confirmation_authority.semantic_authority_version_scope` declares
`drupal_core_majors: ["11"]`. The validator derives the permissible majors
from the registered version pins of the semantic authority sources themselves
and rejects any scope claiming a major without pinned source evidence.

When the literal term is present on the exact installed release but the
installed Drupal core major is outside the reviewed scope, the state is
`term_present_and_semantic_authority_version_out_of_scope` -> `candidate`: the
observation stands, no meaning-bearing claim is attached, and no confirmed
finding exists. Drupal 9 or Drupal 10 term presence therefore never inherits
Drupal 11 semantics, and it is never called secure, absent, or a pass.

## Definitive Applicability

The record carries an explicit reviewed `machine_applicability` contract
(`fact_known drupal_core_version`), and the finding runtime consumes the
canonical Applicability Resolver result before any confirmation. Without a
definitive `applicable` / `machine_resolved` resolution the state is
`applicability_not_definitive` -> `unknown`. The runtime never reimplements
applicability predicates.

## Non-Authoritative Signals

The contract explicitly ignores every signal that could be mistaken for the
term:

- `branch_listed_in_source_supported_branches`
- `source_supported_branches_presence_or_absence`
- `source_security_coverage_text_or_covered_attribute`
- `release_type_term_security_update`
- `release_ordering_or_source_order_index`
- `newer_release_existence`

These are independent of the term in the reviewed context. Listed branches carry
the term, unlisted branches lack it, rows carry the term alongside
`covered="1"` security advisory coverage, and several releases carry
`Security update` without the term. None of them is a substitute.

## Severity Is Not Established

`severity` on the contract is:

```json
{"state": "not_established", "source": null}
```

Neither a reviewed knowledge record nor a reviewed lifecycle policy establishes
severity for this condition. Severity is not derived from the word `Insecure`.

The knowledge record carries its own required `severity` field, set to `info`.
That value rates the knowledge record itself. It is never reused as finding
severity: the validator rejects any contract whose finding severity equals a
knowledge severity level, and `enforcement` may not carry severity at all.

## Enforcement Is Guidance Only

`enforcement.intent` is `non_blocking`, so `effective_enforcement` is
`guidance`. Any state this contract yields — including today's strongest,
`candidate` — remains guidance, as would any future confirmed finding. The
validator rejects a `machine_finding` contract on any record that resolves to
blocking.

## Provenance

A future finding must carry all thirteen provenance fields:

`knowledge_id`, `condition_id`, `analysis_identity`, `core_version_fact_ref`,
`core_version_evidence_ids`, `lifecycle_assessment_id`, `lifecycle_context_id`,
`lifecycle_context_source_snapshot_sha256`, `exact_matched_release`,
`literal_source_term`, `context_relation`, `effective_enforcement`,
`finding_severity_state`.

## Deterministic Identity

`sha256_stable_json` over the declared key fields, with `timestamp_allowed`
fixed to `false`. Key fields bind the knowledge and condition, the analysis
identity, the core-version fact and its evidence IDs, the matched release
version, and the lifecycle context digest. `evaluated_at`, `wall_clock_time`,
`run_id`, `hostname`, and absolute paths are excluded, and the validator rejects
any key field that looks like a time value.

Because the matched release version and the analysis identity are part of the
identity, a finding cannot survive a move to a different installed release.
Because the lifecycle context digest is part of it, a newly reviewed context
produces a new identity rather than mutating history.

## Deduplication

One logical finding per knowledge ID, condition ID, installed Drupal core
package, and exact matched release. The dedup key is deliberately coarser than
the finding identity, and the validator enforces that.

The same source term is reachable through several read paths — the normalized
`terms[]` entries, the `release_type_source_values[]` list, the assessment's
preserved source attributes, and the immutable snapshot XML. All collapse into
one finding carrying multiple supporting evidence references.

## Absence Is Not A Pass

When the exact matched release row does not carry the term, the state is
`not_observed`. It is never `passed`, `secure`, or `safe`. The schema forbids
those values.

## Unknown Fails Closed

`unknown` is returned when the core version is unknown, the exact release row is
not found, the context is not canonical, or the assessment is invalid. None of
these is coerced to false, and none is a pass.

## Runtime

`runtime_status` is `executed_by_reviewed_finding_runtime`. The single runtime
consumer of `machine_finding` contracts is `scripts/dk_finding_runtime.py`,
exposed as `dk.py findings` and documented in `docs/FINDING_RUNTIME.md`. The
Project Analyzer, the Applicability Resolver, the release lifecycle
normalizer, and the neutral release lifecycle evaluator all remain free of any
reference to `machine_finding`, and a permanent test asserts that the runtime
is the only consumer.

The reviewed semantic authority completed the knowledge-side chain the
lifecycle finding eligibility audit began: contract, assertion, finding type,
severity boundary, enforcement boundary, and term meaning are all reviewed.
The runtime executes that reviewed authority and adds none of its own: finding
states come from the contract state map, severity stays `not_established`,
enforcement stays guidance, absence stays `not_observed`, unknown fails
closed, and no remediation is emitted.
