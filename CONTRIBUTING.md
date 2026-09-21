# Contributing to Drupal Knowledge

Thank you for considering a contribution. This document says what kinds of
contribution exist, how each one is reviewed, and — most importantly — what a
merged contribution does and does not mean.

## The one rule that governs everything else

```text
accepted contribution != automatically trusted knowledge
```

Drupal Knowledge separates *what was contributed* from *what the project
believes*. Merging a pull request means the change is correct as code, data
or documentation. It does not, by itself, make any statement trusted Drupal
knowledge. A knowledge change still travels the same path as every other
claim in the repository:

```text
source / evidence
  -> validation (dk validate, the test suites)
  -> appropriate review (a maintainer reads the source the claim rests on)
  -> trust classification (review_status, enforcement intent, trust class)
```

Nothing in a pull request can shortcut that. There is no label, flag or
field that promotes a source snapshot, a discovery signal, a solved case or
a project observation into a reviewed record; the review is a human editing
the record and taking responsibility for it.

## Kinds of contribution

**Code.** Engines, the CLI, the website, the API, validation. Keep to the
standard library — a third-party import fails the build by design. Every
engine is read-only over projects and never mutates canonical records;
preserve that. Add or extend a `scripts/test_*.py` for behaviour you change,
and run the whole suite (see below).

**Source registrations.** Adding a source to `sources/registry.json` is a
trust decision: the registry is a high-authority allow-list, not a link
collection. A new source needs a stable URL, a declared trust class with the
reason it earns it, a content window and a cadence. Community blogs, forums
and Q&A sites are `discovery` at most and are not registered for live
collection by default.

**Acquisition.** Running `dk acquire` or `dk discover` and committing the
resulting snapshots, state and review candidates is welcome. Snapshots are
immutable and content-addressed; never edit one. A candidate you create is
`pending_review` and stays that way until a maintainer reviews it.

**Knowledge.** New or changed records under `knowledge/`, `rules/`,
`knowledge/context/`. Each must cite a registered source and the snapshot
hash it was reviewed against, and each quoted line must be in that snapshot.
Set `review_status` honestly: a record you have not had reviewed is
`seed_needs_human_review`, and an unreviewed record cannot block anything.

**Solved cases.** Capture through `dk solved-case capture` from a candidate
document. Cases carry fingerprints, never project names, paths or
organisation identity, and `dk validate` refuses one that does. A solved
case is proven in one context and is never a universal rule.

**Documentation.** Corrections and clarity are always welcome. Documentation
never restates record content by hand — the website and the CLI render
records; prose that copies an advisory's affected versions or a rule's
conclusion is a data fork and the tests reject it.

## Before you open a pull request

```bash
python3 scripts/dk.py validate
python3 scripts/dk.py generate
python3 scripts/dk.py site public/index.html
python3 scripts/dk.py public-site build
python3 scripts/dk.py api build
python3 scripts/dk.py release-meta
python3 scripts/test_community_boundary.py
```

Then run the test scripts named in `.github/workflows/community.yml`; the
workflow runs exactly those on every push and pull request, on standard
GitHub-hosted runners, with no credential and no network acquisition. A
change that leaves a generated artifact stale fails `dk validate`; regenerate
and commit the artifact with the change that caused it.

Do not commit: absolute local paths, project or organisation names, e-mail
addresses, credentials, or anything observed inside a private project.
`scripts/test_community_boundary.py` scans for these and the pull request
will fail if it finds one.

## Review

Maintainers review for three things, in order: does it preserve the trust
model; is it correct; is it clear. A change that makes the product claim more
than its evidence supports is declined however well it is written.

Reviews of *knowledge* are reviews of the source, not of the prose: the
maintainer opens the snapshot and checks that the claim is what the source
says, for the versions the record says it applies to.

## Licensing of contributions

By contributing, you agree that your original contribution is licensed under
the Apache License, Version 2.0, the licence of this repository (see
`LICENSE`), and that you have the right to contribute it. There is no
separate contributor licence agreement.

Material you acquire from a third-party source through the acquisition
engine is not your contribution to license: it stays under the source's own
terms, recorded in `THIRD_PARTY_NOTICES.md`. Do not add third-party content
by hand; register the source and acquire it, so provenance is recorded.

## Conduct

Participation is governed by `CODE_OF_CONDUCT.md`.

## Security

Do not report a vulnerability in Drupal Knowledge through a public issue or
pull request. See `SECURITY.md`. Vulnerabilities in Drupal itself belong to
the Drupal Security Team.
