# Discovery Review

One file per corroboration dossier: `corroboration.drupal.<digest>.json`.

A dossier records, deterministically and without any language model, what
evidence bears on one signal: independent supporting origins, contradictory
evidence (never discarded), and evidence disqualified for shared lineage or
incompatible version scope.

Every dossier starts at `pending_review`. Review outcomes are `no_action`,
`watch`, `needs_more_evidence`, `candidate_for_future_knowledge_proposal` and
`dismissed`. None of them mutates trusted knowledge;
`candidate_for_future_knowledge_proposal` only authorises later explicit
proposal work.

Contract: `schema/corroboration-dossier.schema.json`.
