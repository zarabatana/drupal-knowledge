# Generalization Proposals

One file per proposal: `generalization.drupal.<digest>.json`.

A proposal means *evidence from recurring verified cases suggests a reusable
rule may exist*. Its scope is bounded by what the participating cases were
actually proven on, and widening it always requires review.

Confidence is a conjunction of independence, verification quality, agreement and
the absence of contradiction. An occurrence count alone never produces
confidence, and every factor is reported so a reviewer can disagree on evidence.

Review outcomes are `needs_more_evidence`, `accepted_for_knowledge_proposal`,
`rejected` and `narrow_scope_required`. None of them mutates trusted knowledge
or creates a knowledge record; `accepted_for_knowledge_proposal` authorises
later, separate proposal work.

Contract: `schema/generalization-proposal.schema.json`.
