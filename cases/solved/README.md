# Solved Case Records

Add verified solved cases here as JSON files conforming to
`schema/solved-case.schema.json`, through `dk solved-case capture`.

The one case shipped at v1.0.0,
`case.drupal.solved.code-change.5bffad1b0b45288d.json`, is **test-derived**:
it was captured from the repository fixture
`tests/fixtures/solved-case/toolchain-module-resolution.candidate.json`
(producer `drupal-knowledge-fixture`) to exercise the capture → recurrence →
generalization → publication path end to end. It describes a tooling defect
in generic terms, identifies its project by fingerprint only, and carries no
organisation, repository, domain, path, credential or e-mail. It is a
`proven_case_context_only` record like any other and is never a universal
rule.
