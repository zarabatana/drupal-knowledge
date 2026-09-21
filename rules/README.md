# Reviewed Implementation Rules

`implementation/` holds the rules that turn canonical project evidence into
explainable performance, security and configuration-quality findings.

A rule is not a preference. Each one names a registered authoritative source,
pins the snapshot it was reviewed against, and quotes the lines it rests on.
`dk.py validate` re-reads the snapshot: if the source has moved, the rule fails
validation with *needs re-review* rather than quietly meaning something else.

Only a `reviewed` rule may confirm a finding. A `draft` rule still evaluates so
its author can see what it would say, but its findings are capped at candidate
and stripped to advisory enforcement.

Severity is always `not_established`, and a rule's category never sets
enforcement. Nothing here is trusted Drupal knowledge; these are reviewed rules
about implementation, evaluated against one project at a time.
