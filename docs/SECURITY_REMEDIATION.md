# Security Remediation Intelligence

`scripts/dk_remediation.py` answers a different question from the security
engine. That one says *this project is affected by advisory X*. This one says
*here is the nearest target the authoritative evidence supports, here is what it
resolves, here is what it does not, and here is what nobody can tell you yet*.

It explains remediation. It never performs it.

## The invariants

```text
advisory fixed version   !=  project-safe upgrade target
minimum non-affected     !=  recommended supported version
remediation plan         !=  executed remediation
unknown                  !=  compatible
```

`execution_performed`, `project_files_written` and `composer_invoked` are pinned
false, and `knowledge/records/` is digested before and after every plan.

## Flow

```text
Project Analyzer facts  ──┐
                          ├─> security evaluation (v0.12)
advisory records ─────────┘        │
                                   ▼
                        confirmed applicable findings
                                   │
                     grouped by component, not by advisory
                                   ▼
              candidates from authoritative evidence only
                                   │
                   each re-evaluated by the security engine
                                   ▼
        minimum non-affected  +  recommended supported target
                                   │
                    transition, constraints, residual, steps
```

## What is reused, not rebuilt

| Concern | Owner |
| --- | --- |
| advisory records, affected-version parsing | `dk_security` (v0.12) |
| applicability and findings | `dk_security.evaluate` |
| project facts | Project Analyzer `profile.facts` |
| supported branches and releases | reviewed release-lifecycle context |
| target selection and constraints | `dk_remediation` |

There is no second security authority and no second analyzer. The engine parses
no project file: the only path it reads is Drupal Knowledge's own reviewed
context.

## Candidates come from evidence, never from imagination

A candidate target is only ever:

- a release an advisory names as fixed;
- the newest published, stable, non-`Insecure` release on a branch the reviewed
  release context lists as supported;
- a version an operator asked about explicitly with `--target`.

**Downgrades are excluded.** A lower release can look like it resolves an
advisory simply by falling outside the majors that advisory speaks about.
Recommending it would be a downgrade, not remediation, so candidates below the
installed version are dropped and reported in `limitations`.

## Every candidate is re-evaluated

A target is not compared against the finding that started the plan. The analyzer
facts are copied with that one component's version substituted, and
`dk_security.evaluate` runs again over the **whole** applicable advisory set.
Each candidate therefore reports `resolves_advisories`,
`residual_advisories` and `unknown_advisories` on its own evidence, and carries
`reevaluated_by_security_engine: true`.

This is what makes a multi-advisory target correct:

```text
18 applicable core advisories
10.3.13  resolves  3   residual 15
10.5.12  resolves 16   residual  2
10.6.13  resolves 18   residual  0   <- first target covering the whole set
```

## Minimum non-affected is not a recommendation

`minimum_non_affected_target` is the lowest candidate that resolves every
applicable advisory. That is a fact about advisories, nothing more.

`recommended_supported_target` additionally requires, for core:

- the branch is listed as supported by the reviewed release context;
- the release is stable and published;
- the release is not flagged `Insecure` by the release feed.

So a fixed release on a branch nobody supports any more is reported as the
minimum and refused as the recommendation, with the reason spelled out. Being
non-affected is not the same as being supported.

## End-of-life projects

Branch support comes from the reviewed release-lifecycle context, so today's
supported Drupal branches are never hardcoded. A project on a branch the context
does not list is `unsupported`, that appears in `limitations`, and remaining on
the branch cannot be recommended.

The plan does not stop at the first fixed version it sees. Every authoritative
fixed release is preserved verbatim in `authoritative_remediation`, and the
supported target is worked out separately in `project_remediation_plan`.

## Upgrade compatibility is never inferred

| Transition | `supported` | Review |
| --- | --- | --- |
| target is the installed version | `supported` | no |
| same branch, patch move | `supported` | no |
| minor within a major | `unknown` | **required** |
| major transition | `unknown` | **required** |

Drupal Knowledge holds no authoritative evidence that a given transition works
for a given project, so it says so rather than implying otherwise. Generic
upgrade compatibility is a later epic.

## Composer constraints are read, never written

`declared.require` from the analyzer gives the manifest constraint. The engine
parses `^`, `~`, wildcards, comparator ranges and `||` alternatives, and reports:

| `constraint_change_required` | Meaning |
| --- | --- |
| `not_required` | the target lies inside the declared constraint |
| `required` | it does not; a human must decide the new constraint |
| `constraint_not_observed` | no constraint was found for this package |
| `unknown` | the constraint could not be read |

An unreadable constraint is never treated as permissive. Nothing edits
`composer.json` or `composer.lock`.

The analyzer derives installed versions from lock evidence, so lock resolution
is **not** a separately observable dimension from the installed version.
`lock_resolution_state` records that rather than pretending otherwise.

## One action per component

Findings are grouped by component before planning, so eighteen core advisories
produce one core action with eighteen `applicable_advisories`, not eighteen
identical recommendations.

## Authoritative and project remediation stay apart

| Block | Whose |
| --- | --- |
| `authoritative_remediation` | the Security Team's; `authored_by_drupal_knowledge: false` |
| `project_remediation_plan` | Drupal Knowledge's; `authored_by_drupal_knowledge: true` |

Fixed versions are preserved exactly as published, including Drupal's legacy
contrib format: an advisory fixed in `8.x-1.2` is recommended by that
identifier, while comparing semantically as `1.2.0`.

## No claim of security

The engine reports what no longer applies. It never says a project is secure,
safe or fully patched — `validate_plan` refuses any output containing such a
claim. With no applicable advisories it says:

```text
No applicable advisories in the evaluated authoritative set of N. This is a
statement about the advisories evaluated, not a judgement about the project
overall.
```

Note that `insecure` is a Drupal source term and is deliberately not caught by
that check.

## Completeness, not confidence

There is no confidence score. Completeness is deterministic:

| State | Meaning |
| --- | --- |
| `no_applicable_advisories_in_evaluated_set` | nothing applied |
| `complete_for_evaluated_security_set` | supported target on the installed branch |
| `partial_due_to_dependency_unknowns` | a declared constraint could not be read |
| `blocked_by_unsupported_branch` | no supported target follows from the evidence |
| `requires_compatibility_review` | the target needs a transition DK cannot vouch for |
| `insufficient_project_evidence` | core version or package set not observed |

## Severity and enforcement are untouched

The engine derives no score from Drupal's risk vector, and a plan changes no
policy: `enforcement.changed_by_plan` is pinned false and findings stay
guidance.

## CLI

```text
dk.py security-remediation <analysis.json>
dk.py security-remediation <analysis.json> --json
dk.py security-remediation <analysis.json> --explain
dk.py security-remediation <analysis.json> --target 11.4.6
```

`--target` evaluates a version read-only and installs nothing. There is
deliberately no `--apply`, `--fix`, `--write` or `--composer-update`.

The remediation tests run in the `engines` job of `.github/workflows/community.yml`,
a required gate on every push and pull request.
