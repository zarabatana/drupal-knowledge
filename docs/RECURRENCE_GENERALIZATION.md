# Solved-Case Recurrence and Generalization

`scripts/dk_generalization.py` answers one narrow question: has Drupal Knowledge
now seen the same proven problem, cause and fix in more than one independent
place, and if so what would a reusable rule look like for a human to judge?

It owns no case store and no Drupal truth.

## The invariant

```text
RECURRENCE
!=
GENERALIZATION
!=
TRUSTED KNOWLEDGE
```

Recurrence is a count of proven occurrences in named contexts. A generalization
proposal is a question put to a reviewer. Neither is Drupal truth. Every
canonical path takes the digest of `knowledge/records/` before and after the
work and refuses to continue if it moved. A run always reports:

```json
"trusted_knowledge_mutations": []
```

## Flow

```text
verified solved case A
verified solved case B
verified solved case C
        ↓
structural grouping   (exact identity, never text similarity)
        ↓
recurrence analysis   (independent occurrences, conflicts, contradictions)
        ↓
generalization proposal   (pending_review, scope bounded by observation)
        ↓
human review
        ↓
may authorise later, separate knowledge-proposal work
```

## What is reused, not rebuilt

| Concern | Owner |
| --- | --- |
| case capture, verification, storage | `dk_solved_case` (v0.8) |
| case identity and fingerprints | `dk_solved_case.case_identity` |
| case lifecycle vocabulary | `schema/solved-case.schema.json` |
| secret and path screening | `dk_solved_case.screen_for_secrets` |
| recurrence grouping and counting | `dk_generalization` |
| proposal assembly and confidence | `dk_generalization` |

Reading is limited to `cases/solved`. The `status` enum already carried
`recurring` and `generalization_proposed`, so no new case vocabulary was
invented.

## Only verified cases count

Standing is earned by evidence, not by a label. A case participates only if:

- its status is not `captured`, `rejected` or `retired`;
- `verification.performed` is true;
- at least one verification result actually **passed**;
- it states what its evidence demonstrates about causality.

That is the same bar solved-case capture applies to reach `verified`, checked
structurally so a mislabelled case cannot slip through. Cases that fail it are
recorded in `excluded_cases` with reason `not_verified` — set aside visibly
rather than silently dropped.

## Grouping is structural, not textual

Two cases join a group only when all of these are identical:

- normalized root-cause statement;
- fix category;
- normalized set of fix summaries;
- affected component names.

Normalization collapses case, whitespace runs and a trailing full stop, and
nothing else. This is exact identity, not similarity scoring. A similar title,
overlapping symptom wording or a shared module name is not enough, and none of
them appear in the key at all.

```text
same symptoms + different root cause  ->  different group
```

## Independence is counted conservatively

```text
one independent occurrence = one distinct project fingerprint
```

Solved-case identity already collapses a re-capture of the same project at the
same core version. Two distinct cases can still share a project fingerprint —
the same project upgraded across versions, for instance — and recurrence counts
that as **one place**, reporting the rest as `duplicate_capture_count` and
`revision_count`. A project heard from twice is not two projects.

## Scope is bounded by observation

`observed_scope` records exactly what the participating cases were proven on:
core versions and majors, PHP versions, component versions and environment
classes. A proposal restates that scope and no more:

```text
case A: Drupal 11.2 + module X 3.x
case B: Drupal 11.4 + module X 3.x
->  proposal scoped to the observed Drupal 11 / module X 3.x evidence
->  never Drupal 10-12, never "module X all versions"
```

`expansion_requires_review` and `bounded_by_observed_cases` are pinned true, so
widening is always a reviewer's act.

## Conflicts constrain, they do not merge

Structurally aligned cases whose scopes do not reconcile produce
`applicability_conflicts` rather than a wider claim:

| Kind | Meaning |
| --- | --- |
| `incompatible_drupal_major` | proven on more than one Drupal core major |
| `incompatible_component_major` | a shared component name across major lines |
| `incompatible_php_major` | proven across PHP majors |
| `unreconciled_environment` | proven in different environment classes |

A conflict caps confidence and makes `narrow_scope_required` the recommended
review state.

## Contradiction is first-class

A verified case whose own verification records a **failed** result under
otherwise matching conditions is important evidence that the rule does not hold
universally. It stays in the group, appears in `contradictory_cases`, drags the
verification grade to `weak`, caps confidence, and makes
`needs_more_evidence` the recommendation. It is never hidden and never dropped.

## A count is never proof

Confidence is a conjunction, and every factor is reported:

```text
independent occurrences
+ verification quality
+ root-cause and fix agreement
+ absence of contradiction
+ absence of unreconciled scope conflict
```

Two independent occurrences is the floor for a proposal to exist at all, not a
truth threshold. Five independent occurrences that each record a failed
verification still grade `weak`. Every proposal carries:

```json
"count_alone_is_sufficient": false
```

There is deliberately no `if occurrences >= 3` anywhere in the engine.

## Verification quality

| Grade | Condition |
| --- | --- |
| `strong` | every case demonstrates causality with a confirmed root cause, across more than one verification method |
| `moderate` | every case is at least consistent with evidence and evidenced |
| `weak` | any failed result, or any case with unknown root cause or unestablished causality |

The weakest participating case sets the grade. A group is only as good as its
worst evidence.

## Generalization proposals

A proposal is assembled deterministically from the participating cases' own
fields. No language model writes it, and it is pinned:

```json
"review_required": true,
"review_state": "pending_review",
"is_trusted_knowledge": false,
"is_knowledge_record": false,
"generalizes_automatically": false,
"can_promote_to_knowledge": false,
"proposed_statement": {"asserts_universal_truth": false}
```

One proposal per recurrence analysis. Identical evidence rewrites nothing
(`reused`); changed evidence updates it in place and, if it had been reviewed,
returns it to `pending_review` rather than carrying a stale decision forward.

## Human review

| Outcome | Meaning |
| --- | --- |
| `needs_more_evidence` | insufficient to decide |
| `narrow_scope_required` | plausible, but not at this scope |
| `accepted_for_knowledge_proposal` | authorises later, separate proposal work |
| `rejected` | not a reusable rule |

None of these mutates trusted knowledge or creates a knowledge record.
`accepted_for_knowledge_proposal` authorises *work*, and the artifact records
`knowledge_record_created: false` to say so. Knowledge-proposal generation is
deliberately not implemented here.

## Evidence channels stay separate

```text
verified solved case   !=   discovery signal
```

Recurrence reads `cases/solved` and nothing else. A discovery signal about the
same component sitting on disk contributes nothing: every run reports
`discovery_signals_counted: 0`, and the engine imports no discovery module.

Authoritative evidence may be attached to a proposal as
`provenance.authoritative_support`, supporting or contradicting it. Each entry
is pinned `rewrites_case_provenance: false`: authoritative agreement never
converts internal-proven case history into authoritative history.

## Privacy

Recurrence and generalization artifacts carry the fingerprints the solved cases
already hold and nothing more. Fields whose names suggest project identity are
refused outright, and every string is screened for local machine paths and
secret material using the solved-case screener. A named review actor is
exempted from the contact-detail check, because review authority is recorded the
same way elsewhere in the repository.

## CLI

```text
dk.py recurrence analyze [--min-cases N] [--no-propose] [--dry-run] [--quiet]
dk.py recurrence list [--json]
dk.py recurrence show <recurrence-id>
dk.py generalizations list [--review-state S] [--confidence G]
dk.py generalizations show <proposal-id>
dk.py generalization-review <proposal-id> --outcome <outcome> --actor <who>
```

`--dry-run` analyses and validates without writing any artifact. There is
deliberately no promotion command.

The recurrence tests run in the `engines` job of `.github/workflows/community.yml`,
a required gate on every push and pull request.
