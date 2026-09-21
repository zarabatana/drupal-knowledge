# Discovery Signals

One file per discovery signal: `signal.drupal.<source-id>.<digest>.json`.

A signal means *something potentially useful was observed*. It is not Drupal
truth, not a source snapshot, not a solved case and not a finding.

Identity is `(source, item, assertion)`, so re-observing the same item asserting
the same thing reuses the signal rather than duplicating evidence. Popularity is
recorded as metadata and carries zero authority weight.

Contract: `schema/discovery-signal.schema.json`.
