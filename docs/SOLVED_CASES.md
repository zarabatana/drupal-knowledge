# Solved Cases

Solved cases are first-class Drupal Knowledge records for problems the
maintainers solved and verified in a real project.

The single case shipped at v1.0.0 is test-derived — captured from the
repository fixture under `tests/fixtures/solved-case/` to prove the workflow
end to end — and carries fingerprints only (see `cases/solved/README.md`).

A solved case means:

```text
this solution was proven in this context
```

It does not mean:

```text
Drupal universally requires this
```

`SOLVED_CASE_NOT_UNIVERSAL_RULE=PASS`

## Schema

`schema/solved-case.schema.json` captures:

- id;
- title;
- problem;
- symptoms;
- root cause;
- solution;
- verification;
- environment;
- Drupal versions;
- PHP versions;
- modules;
- themes;
- project type;
- applicability;
- limitations;
- evidence;
- related knowledge IDs;
- occurrence count;
- first seen;
- last verified;
- status.

## Lifecycle

```text
captured
  -> verified
  -> recurring
  -> generalization_proposed
  -> promoted_to_knowledge_proposal
  -> human-reviewed trusted knowledge
```

Promotion is never automatic. A recurring solved case can support a knowledge
proposal, but source authority, applicability, and enforcement still require
review.

Recurrence and generalization are their own step, documented in
[RECURRENCE_GENERALIZATION.md](RECURRENCE_GENERALIZATION.md). Cases are grouped
by exact structural identity rather than description similarity, occurrences are
counted per distinct project fingerprint, and a proposal's scope never exceeds
what the participating cases were proven on.

## Capture

Solved cases are captured through the released interface. An external producer
submits a candidate; Drupal Knowledge validates it and owns storage. Producers
never write into `cases/solved/` or any trusted-knowledge directory themselves.

```bash
python3 scripts/dk.py solved-case validate candidate.json
python3 scripts/dk.py solved-case capture candidate.json
python3 scripts/dk.py solved-case show <case-id>
python3 scripts/dk.py solved-case verify <case-id> verification.json
python3 scripts/dk.py solved-case list
```

The candidate contract is `schema/solved-case-candidate.schema.json`. Capture
supports only `captured` and `verified`; the later lifecycle states remain in
the canonical schema but are never entered automatically, and no command
promotes a case to trusted knowledge.

### What capture enforces

- **Verification needs evidence.** `verified` requires verification to have
  been performed, at least one result that actually passed, and an explicit
  causality statement. "It is fixed" never verifies a case.
- **Applicability is bounded by evidence.** `proven_on` may list only the
  Drupal core version the case was observed on, and `claimed_scope` stays
  `proven_context_only`. Widening scope is a reviewable proposal.
- **Root cause may be unknown.** `confirmed`, `evidenced` and `unknown` are all
  valid; an unknown cause must say so rather than assert an explanation, and a
  confirmed one requires evidence references.
- **Causality is not overclaimed.** `demonstrated`,
  `consistent_with_evidence` and `not_established` record what the evidence
  proves versus what remains inference.
- **Limitations are mandatory.** A single-project case always has limits.
- **Identity is deterministic.** Recapturing the same evidence collapses into
  one record; the same problem on a different project stays a separate case and
  may later become recurrence evidence.
- **Project identity is minimized.** Contexts carry sha256 fingerprints, never
  organisation names, domains, or machine paths.
- **Obvious secret material is rejected**, not stored: credential tokens,
  private keys, inline credentials, credentials in URLs, absolute home paths
  and personal contact details.

Capturing or verifying a case never creates or edits a knowledge record, a
source, or an applicability rule.
