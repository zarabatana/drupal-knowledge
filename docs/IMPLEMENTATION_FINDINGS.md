# Implementation Findings

Prompt 12 could tell you a project's `system.performance:cache.page.max_age` is
`0`. That is a fact and nothing more. This is where a fact becomes something
worth acting on, and the whole design exists to keep that step honest:

```text
static observation  !=  bad practice
```

A finding needs two things neither the evidence layer nor a developer's taste
can supply alone:

```text
reviewed rule whose authority is a registered authoritative source
                            +
project evidence definitive enough to settle its conditions
```

Missing either one produces a candidate or an unknown, never a confirmation.

## Four Ways The Step Goes Wrong

| Failure | Guard |
| --- | --- |
| a preference dressed as a rule | authority is checked against the registry, not asserted by the rule |
| an unreviewed rule confirming | only `reviewed` may confirm; a draft is capped at candidate and stripped to advisory |
| a guess treated as an observation | heuristic evidence returns `UNKNOWN`, never a confirmation |
| a context-free verdict | a rule declares the context it needs; missing context caps it at candidate |

The last one is the subtle one. Drupal's own Internal Page Cache documentation
says a site behind a reverse caching proxy or CDN *can safely disable* page
caching. A rule that ignored that would be confidently wrong on every well-run
site it met. So `performance.page-cache-maximum-age-zero` declares the
deployment context it would need, does not get it from a repository, and stays
guidance with the gap written into the finding.

## Rule Contract

`rules/implementation/*.json`, one file per rule.

```text
identity     rule_id (namespaced by category), contract version, title
review       draft | reviewed | deprecated | superseded
authority    registered source + pinned snapshot + the exact quoted lines
scope        Drupal core minimum major, component
check        evidence_condition | evidence_cross_reference
context      what the rule would need to be certain, and why it matters
finding      assertion, severity state, enforcement intent, conclusions,
             remediation, limitations
```

A rule's authority must be a registered source whose `implementation_authority`
block declares the rule's category. The snapshot hash is pinned, and validation
re-reads the snapshot to confirm the quoted lines are still there. If the source
has moved, the rule fails validation with *needs re-review* and its findings
become `requires_human_review` — the change surfaces as review work rather than
as a quietly different interpretation.

## Checks Are Not A Rules Language

Exactly two kinds, with fixed semantics:

- `evidence_condition` — a condition evaluated by the **one** applicability
  resolver, using the Prompt 12 evidence predicates. No second evaluator exists.
- `evidence_cross_reference` — one declared join between two evidence
  assertions, reporting each unmatched subject. It only reports a miss when the
  *target* domain is complete, because otherwise "no record" means "we did not
  look there".

## Finding States

```text
confirmed   candidate   not_observed   unknown   requires_human_review
```

Borrowed from the finding runtime, including its refusal of `passed`, `secure`,
`safe`, `compliant` and `ok`. Absence of an adverse condition is not a
conformance verdict, so there is no passing state to reach for.

Severity is always `not_established`: this product does not manufacture it.
Category never sets enforcement — a security rule is guidance unless a human
reviewed it into something stronger, and a draft rule is advisory whatever it
declares.

## The Initial Rule Set

Deliberately small. Nine rules, three per category, each with authority strong
enough to survive being read back.

| Rule | Category | Authority | Notes |
| --- | --- | --- | --- |
| `performance.page-cache-maximum-age-zero` | performance | Internal Page Cache docs | context-dependent; caps at candidate |
| `performance.views-cache-strategy-unobservable` | performance | Cache API docs | views config is unparseable by the safe reader, so this is `unknown`, never a pass |
| `performance.asset-aggregation-disabled` | performance | Cache API docs | **draft**: no source yet states the expected production value |
| `security.trusted-host-patterns-not-declared` | security | trusted host docs, core default.settings.php | settings domain is bounded, so absence cannot confirm |
| `security.update-php-free-access-enabled` | security | core default.settings.php | confirms on definitive evidence |
| `security.verbose-error-display-without-environment-evidence` | security | core default.settings.php | environment-dependent; never a production claim |
| `configuration_quality.config-depends-on-module-not-enabled` | configuration_quality | core default.settings.php | cross-reference; occurrences preserved |
| `configuration_quality.default-theme-not-enabled` | configuration_quality | core default.settings.php | cross-reference scoped to `system.theme:` |
| `configuration_quality.exported-config-root-ambiguous` | configuration_quality | core default.settings.php | names *why* other config rules are unevaluable |

## What A Finding Answers

```text
What rule?             explanation.what_rule
Why does it apply?     explanation.why_it_applies
What evidence?         evidence.evidence_ids, evidence.occurrences
How complete is it?    explanation.evidence_completeness
What remains unknown?  explanation.what_remains_unknown, context.unsatisfied
What source?           authority.sources with snapshot and quoted lines
What remediation?      remediation.guidance, with basis and applied: false
Was anything changed?  execution, all false
```

## Boundaries

These are implementation and configuration findings. Known-vulnerability
applicability belongs to the security advisory engine; API migration work
belongs to the migration engine. Neither becomes a finding here without a
reviewed rule saying so, and no advisory identifier, CVE or risk vector appears
in this domain's output.

A bounded rule set finding nothing says nothing about the rest of a project.
Nine rules are not a health check.

## Read-Only

```text
dk.py implementation-findings <evidence-set.json|analysis.json> [--project-path P]
                              [--category performance|security|configuration_quality]
                              [--state confirmed|candidate|...] [--explain] [--format json]
```

No `--apply`, `--fix`, `--write`, `--optimize` or `--secure`. No configuration,
code, Composer state or Drupal state is modified, and no trusted knowledge or
reviewed rule is mutated by evaluation.
