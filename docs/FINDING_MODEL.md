# Drupal Knowledge Finding Model

This document defines the authority boundary for future Drupal Knowledge
project findings. It is an audit/design artifact, not canonical Drupal truth.

The current released stack is:

```text
Authoritative sources
-> reviewed Drupal Knowledge
-> Drupal Project Analyzer observations
-> Applicability Resolver results
```

The stack intentionally stops before findings. Applicability says whether a
knowledge record concerns the observed project. A finding needs a separate,
machine-safe project condition check.

## Authority Layers

```text
SOURCE
!= TRUSTED KNOWLEDGE
!= PROJECT FACT
!= OBSERVED PROJECT EVIDENCE
!= APPLICABILITY RESULT
!= FINDING
!= REMEDIATION
!= SOLVED CASE
```

The layers are separate so that source truth, reviewed guidance, project facts,
applicability, findings, and fixes cannot silently authorize each other.

## Definitions

Observation
: A neutral project fact derived from static evidence. Example: Composer lock
  evidence reports `drupal/core` version `11.2.3`.

Applicability
: A resolver result that a knowledge record does or does not concern the
  observed project, or that the answer is unknown or needs human review.

Candidate
: A deterministic review signal from project evidence where static certainty is
  insufficient for a confirmed finding. Example: a future Twig scanner may see
  `|raw`, but that alone does not prove an XSS vulnerability. A signal is also
  only a candidate when its evidence is complete but the reviewed semantic
  authority that makes the observed condition reportable is not yet
  established.

Confirmed finding
: An evidence-backed project condition that satisfies or contradicts an explicit
  machine-defined condition associated with reviewed knowledge. A confirmed
  finding is not created by applicability alone.

Unknown
: The required evidence domain is unavailable, incomplete, ambiguous, or not
  observed. Missing evidence is not a finding and is not a pass.

Human review
: Evidence or knowledge requires semantic judgment outside the safe machine
  contract. Human review is not a confirmed finding.

Remediation
: A proposed or automated fix. Remediation is outside this model and must not be
  inferred from a finding without a separate authority layer.

## Finding Eligibility Criteria

A current or future record is finding-eligible only when all of these are true:

1. The knowledge record has `review_status == reviewed`.
2. The resolver can definitively establish applicability for the project.
3. The required project observation domain is available and sufficiently
   complete.
4. The expected or forbidden condition is machine-defined, not interpreted from
   prose.
5. Observed project evidence definitively establishes the condition.
6. Evidence provenance can be attached to the result.
7. No required semantic judgment remains.
8. The finding does not depend on network or runtime evidence unavailable to the
   analyzer.

If any criterion is missing, the result is not a confirmed finding. It may be an
observation, candidate, unknown, or human-review item depending on the evidence.

## Current Analyzer Evidence Inventory

Drupal Project Analyzer v0.3.0 can currently observe these domains:

| Domain | Current capability | Finding authority today |
| --- | --- | --- |
| Drupal project classification | Known, unknown, or insufficient from static project evidence | Applicability support only |
| Drupal core version | Installed `drupal/core` from `composer.lock` when present and not contradictory | Applicability and release-analysis input |
| Composer declarations | Root `composer.json` require, require-dev, package metadata, platform PHP, scaffold metadata | Observation only |
| Installed Composer packages | `composer.lock` packages and packages-dev with version/type/dev origin | Observation only |
| Enabled extensions | `core.extension.yml` when one config root is unambiguous and parseable | Applicability support only |
| Web root | Explicit scaffold metadata and/or core filesystem marker | Observation only |
| Custom extensions | Bounded `.info.yml` inventory in conventional custom roots | Observation only; presence is not enablement |
| Config inventory | Export root, YAML count, selected config families, config parse diagnostics | Observation only |
| Completeness | Composer/config/custom/runtime availability and ambiguity states | Controls unknown vs definitive absence |
| Evidence provenance | Relative path, SHA-256, byte length, role, facts supported | Required for future findings |

The analyzer does not inspect route semantics, controller mutations, PHP data
flow, SQL query construction, Twig trust context, PHPCS configuration, advisory
affected-version semantics, or normalized release-lifecycle knowledge.

## Project Evidence vs Release Knowledge

The analyzer already observes project-specific Drupal core version from
repository evidence. That fact can say a project has installed `drupal/core`
version `11.2.3` when Composer lock evidence supports it.

Statements such as "release X is current", "branch X is supported", "release X
is unsupported", "release X is EOL", or "release X is covered by security
advisories" are not project evidence. They are authoritative Drupal
release-lifecycle knowledge or context derived from captured Drupal source
snapshots and reviewed normalization.

The correct authority chain is:

```text
AUTHORITATIVE SOURCE SNAPSHOT
-> REVIEWED/NORMALIZED RELEASE-LIFECYCLE KNOWLEDGE
+ PROJECT FACT/EVIDENCE: installed Drupal core version
-> APPLICABILITY / FUTURE FINDING EVALUATION
```

The incorrect chain is:

```text
AUTHORITATIVE SOURCE
-> PROJECT EVIDENCE
```

The Project Analyzer must remain project-observation only. It may output
installed Drupal core version, evidence provenance, and completeness. It must
not output externally sourced Drupal lifecycle truth such as `supported`,
`unsupported`, `EOL`, `current`, `obsolete`, or `security-supported`.

## Current Knowledge Finding Eligibility Audit

| Knowledge ID | Applicability automation | Finding classification | Evidence available | Evidence missing | Why |
| --- | --- | --- | --- | --- | --- |
| `drupal.api.reference-drupal-11` | MACHINE_RESOLVABLE | APPLICABILITY_ONLY | Drupal project classification and core version can prove Drupal 11 API guidance applies | No defective or conforming project condition is defined | Selecting the Drupal 11 API reference is knowledge applicability, not a project finding. |
| `drupal.api.version-aware-documentation` | PARTIALLY_MACHINE_RESOLVABLE | KNOWLEDGE_PROCESS_RULE | Core version may be observed | No project condition beyond documentation/version selection | This governs knowledge selection and documentation use, not project compliance. |
| `drupal.change-records.introduced-version` | HUMAN_SEMANTIC_REVIEW_REQUIRED | KNOWLEDGE_PROCESS_RULE | Core version may be observed | Upgrade change impact evidence and explicit change-record applicability | This is upgrade-analysis infrastructure for interpreting change records. |
| `drupal.coding-standards.current-source` | HUMAN_SEMANTIC_REVIEW_REQUIRED | KNOWLEDGE_PROCESS_RULE | Custom code inventory may exist | Rule-specific code evidence and coding-standard check results | This record identifies the canonical standards source, not a code violation. |
| `drupal.coding-standards.phpcs-coder-tooling` | INSUFFICIENT_PROJECT_EVIDENCE | NOT_A_PROJECT_FINDING | Composer packages may show Coder installed or absent | PHPCS configuration, CI tooling, organization-level tooling, executed lint evidence | Tool absence in one repository does not prove coding standards are unenforced. |
| `drupal.security.advisory-streams-separated` | PARTIALLY_MACHINE_RESOLVABLE | KNOWLEDGE_PROCESS_RULE | Core version, installed packages, enabled extensions may be observed | Individual advisory affected-version knowledge and package applicability semantics | Advisory stream separation is authority governance, not a vulnerability finding. |
| `drupal.security.csrf-route-protection` | HUMAN_SEMANTIC_REVIEW_REQUIRED | NEEDS_MORE_PROJECT_EVIDENCE | Custom extensions may be observed | Route definitions, HTTP methods, mutation semantics, route requirements/options, CSRF/access mechanism evidence | The analyzer does not inspect routes or controller/form semantics. |
| `drupal.security.database-query-parameterization` | HUMAN_SEMANTIC_REVIEW_REQUIRED | NEEDS_MORE_PROJECT_EVIDENCE | Custom extensions may be observed | PHP query construction evidence, data-flow/trust evidence, operator/LIKE escaping semantics | The analyzer does not inspect PHP query code. |
| `drupal.security.twig-output-escaping` | HUMAN_SEMANTIC_REVIEW_REQUIRED | NEEDS_MORE_PROJECT_EVIDENCE | Custom themes may be observed | Twig template evidence, output context, `raw` usage, attribute quoting, data trust evidence | The analyzer does not inspect Twig templates or trust context. |
| `drupal.update.core-release-insecure-term-condition` | PARTIALLY_MACHINE_RESOLVABLE | MACHINE_FINDING_CONTRACT_ONLY | Core version, reviewed lifecycle context, neutral lifecycle assessment, and a reviewed `machine_finding` contract | Finding evaluator runtime and authoritative release-type term semantics | The record carries the first reviewed `machine_finding` contract, but the contract is declarative data and no component evaluates it into a finding. |
| `drupal.update.core-release-state-update-feed` | PARTIALLY_MACHINE_RESOLVABLE | KNOWLEDGE_PROCESS_RULE | Project core version and baselined release source exist | Reviewed release-lifecycle knowledge/context and explicit machine finding contract | The record identifies the release-state source; it does not itself assert supported, unsupported, outdated, or insecure. |

No current canonical knowledge record is `FINDING_ELIGIBLE_NOW`.

One record, `drupal.update.core-release-insecure-term-condition`, carries the first
reviewed `machine_finding` contract. A contract is knowledge authority, not an engine: it
declares exactly when a lifecycle assessment may become a finding. Since the 2026-09-07
runtime increment, the reviewed finding runtime (`scripts/dk_finding_runtime.py`,
`dk.py findings`) executes it; the audit table above keeps the audit-time
classification. Its term semantics are established by reviewed current Drupal 11 update-module
authority (Release type `Insecure` -> `isInsecure()` -> installed release `NOT_SECURE` ->
missing security update(s)), so its strongest declared state is `confirmed` — reachable
only through explicit reviewed `semantic_authority_refs`. The validator still rejects any
contract that maps an observation to `confirmed` without that reviewed semantic authority.
See `docs/LIFECYCLE_FINDING_CONTRACT.md`.

## Security-Rule Audit

CSRF route protection requires static route evidence plus semantic evidence that
a route mutates state and lacks an appropriate CSRF/access mechanism. A route
YAML entry alone is not enough if operation semantics are unknown.

Database query parameterization requires PHP query construction evidence and
data-flow/trust context. Finding unsafe interpolation is not the same as seeing
database code.

Twig output escaping requires template evidence and trust/output-context
analysis. A `|raw` occurrence may be a candidate for review, but it is not a
confirmed XSS finding without evidence about the value and context.

Advisory stream separation only establishes where different Drupal security
communications live. A vulnerability finding needs an individual advisory,
authoritative affected-version context from that advisory, installed
package/version project evidence, and applicability.

## Future Machine Finding Contract

A future finding-capable knowledge record needs a separate `machine_finding`
contract. `machine_applicability` must not be reused as violation semantics.

The safe future contract should be declarative and constrained. It should
describe:

- condition ID;
- finding type;
- evidence domain;
- authoritative completeness requirement;
- required applicability result;
- required or forbidden project condition;
- supported predicate type;
- unknown behavior;
- candidate behavior;
- reason codes;
- provenance requirements;
- severity source;
- effective enforcement handling.

It must not execute free-text `checks`, `actions`, `evidence_requirements`, or
`automation_hints`. Those fields remain human-readable knowledge text until a
reviewed structured condition exists.

## Finding States

The first finding engine should use states equivalent to:

- `confirmed`: a reviewed, applicable, machine-defined condition is proven by
  sufficiently complete project evidence.
- `not_observed`: the evidence domain is complete enough to say the forbidden
  condition was not observed. This is not automatically a pass.
- `unknown`: required evidence is missing, ambiguous, or incomplete.
- `requires_human_review`: semantic judgment is required.

Static review signals with incomplete certainty should use `candidate`, not
`confirmed`.

No state should be called `passed` unless a future contract defines the evidence
domain as complete enough to prove conformance.

## Enforcement And Severity

A confirmed finding does not escalate enforcement. Current records are
guidance-only; a future finding tied to them remains guidance unless reviewed
knowledge explicitly authorizes stronger enforcement.

Finding severity must be derived from reviewed knowledge. A finding engine must
not invent or increase severity.

Unreviewed or deferred knowledge cannot author confirmed findings. At most it
may produce advisory candidates under a future reviewed policy.

## Provenance, Identity, And Deduplication

A future confirmed finding should identify:

- finding ID;
- knowledge ID;
- applicability result identity;
- project fact references;
- evidence IDs;
- relevant relative file paths where safe;
- deterministic condition ID;
- stable reason code;
- effective enforcement;
- knowledge-set identity;
- analysis identity.

The finding ID should be deterministic from stable inputs such as knowledge ID,
condition ID, and project evidence location/identity. It must not include
timestamps.

Deduplication should group repeated observations into one logical finding when
they represent the same knowledge rule, same condition, and same project
entity. Multiple supporting evidence refs can attach to that one finding.

## Gap Taxonomy

Project evidence gaps are facts that would come from files inside the analyzed
project:

| Knowledge record | Project evidence gap | Analyzer has it today | Minimum safe extension |
| --- | --- | --- | --- |
| `drupal.security.csrf-route-protection` | `route_static_evidence`, `route_operation_semantics` | No | Static routing YAML inventory with requirements/options, followed by conservative mutation semantics. |
| `drupal.security.database-query-parameterization` | `php_query_static_evidence`, `php_dataflow_or_trust_semantics` | No | PHP static query-construction evidence with explicit limits and candidate separation. |
| `drupal.security.twig-output-escaping` | `twig_static_evidence`, `twig_trust_context_evidence` | No | Twig template inventory and context-aware candidate model before confirmed findings. |
| `drupal.coding-standards.phpcs-coder-tooling` | `phpcs_configuration_evidence`, external/CI tooling evidence | Partial Composer evidence only | Static PHPCS/Coder config and CI-tooling inventory as observations, not violations by absence. |

Authoritative ecosystem or knowledge-context gaps come from Drupal source
snapshots and reviewed normalization, not from the analyzed project:

| Knowledge record | Authoritative knowledge/context gap | Current captured source status | Minimum safe extension |
| --- | --- | --- | --- |
| `drupal.security.advisory-streams-separated` | `advisory_affected_version_context` | Advisory streams are baselined, but no individual advisory applicability model exists. | Dedicated advisory ingestion/applicability model using canonical advisory source facts. |
| `drupal.update.core-release-state-update-feed` | `authoritative_release_lifecycle_context` | The `drupal-core-releases` snapshot includes release entries, `supported_branches`, release type terms, and security coverage text/attributes. | Normalize explicit release lifecycle fields from the baselined source into reviewed knowledge/context. |

## Current Release Source Semantics

The current canonical `drupal-core-releases` snapshot is the Drupal update-status
release-history XML from `https://updates.drupal.org/release-history/drupal/current`.
It can prove that, at the captured source state, the feed contained:

- project metadata including Drupal core title, short name, Composer namespace,
  project status, maintenance status, and development status;
- explicit `supported_branches` value `10.6.,11.3.,11.4.`;
- release entries with version, tag, status, links, timestamps, files, and
  release type terms;
- release type terms such as `Bug fixes`, `Security update`, `New features`,
  and `Insecure`;
- per-release security coverage text/attributes, including `covered="1"` for
  covered stable releases and text saying alpha, beta, RC, and dev releases are
  not covered by Drupal security advisories.

It cannot by itself prove every support/EOL policy consequence. Interpreting
branch absence, long-term support lifecycle, EOL naming, or security-support
policy beyond explicit feed fields may require another reviewed authoritative
Drupal policy/support source.

No finding model may infer that an older release is unsupported, EOL, insecure,
or vulnerable merely because a newer release exists. Security support requires
explicit captured authority.

## Next Capability Ranking

1. `NORMALIZE_AUTHORITATIVE_RELEASE_LIFECYCLE_KNOWLEDGE`: best first choice
   after the authority correction. It is deterministic, offline after source
   baselining, easy to provenance, low false-positive risk, and directly
   complements the analyzer's existing project core-version fact without moving
   ecosystem truth into analyzer output. It can later support release/support
   findings only after a reviewed `machine_finding` contract exists.
2. `route_static_evidence`: structured and useful, but confirmed CSRF findings
   still need mutation semantics and contextual exclusions.
3. `phpcs_configuration_evidence`: easy to observe, useful for agencies, but
   absence of local tooling is not a policy violation.
4. `twig_static_evidence`: useful for candidates, but trust context makes
   confirmed findings high risk.
5. `php_query_static_evidence`: valuable but requires careful PHP parsing and
   data-flow limits to avoid false positives.
6. `advisory_affected_version_context`: high value, but needs a dedicated
   advisory model rather than broad ingestion.

## Engine Decision

`CURRENT_FINDING_ENGINE_JUSTIFIED=NO`

The current Analyzer and Resolver provide project profiling and applicability,
but no current reviewed canonical knowledge record has enough observed project
condition evidence and machine-defined finding semantics to author a confirmed
finding today.

The single next capability to implement is:

`NORMALIZE_AUTHORITATIVE_RELEASE_LIFECYCLE_KNOWLEDGE`

## Engine Decision Update (2026-09-07)

The decision above is the audit-time conclusion and is preserved verbatim. Its
blockers were then resolved by reviewed increments: the normalized reviewed
release lifecycle context (v0.4.0), the neutral release lifecycle evaluator
(v0.5.0), and the reviewed `machine_finding` contract with reviewed Drupal
update-status semantic authority (v0.6.0). With every finding eligibility
criterion satisfied for exactly one record, the current decision is:

`CURRENT_FINDING_ENGINE_JUSTIFIED=YES_SINGLE_REVIEWED_CONTRACT`

The reviewed finding runtime (`scripts/dk_finding_runtime.py`, exposed as
`dk.py findings`) executes reviewed `machine_finding` contracts against the
neutral release lifecycle assessment and emits schema-validated finding
evaluations (`schema/finding-evaluation.schema.json`). It adds no finding
semantics of its own: states come from the contract state map, severity stays
`not_established`, enforcement stays guidance, and no remediation is emitted.
`docs/finding-eligibility.json` records this in its additive
`engine_resolution` block, and `docs/FINDING_RUNTIME.md` documents the runtime.
