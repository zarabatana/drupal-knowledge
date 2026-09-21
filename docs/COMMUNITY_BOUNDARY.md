# The Community Boundary

Drupal Knowledge Community is the **Core**: the public, evidence-backed
Drupal knowledge and the engines that read it. It is complete and useful on
its own — a clone, Python 3 and nothing else — and it is also the foundation
that any privately operated product built on Drupal Knowledge depends on.

This document states the boundary between the two, the direction of the
dependency, and the tests that keep it that way.

## The architecture

```text
GitHub · zarabatana/drupal-knowledge
PUBLIC CORE — Drupal truth
        │
        │ tagged, versioned dependency
        ▼
separately governed product(s) that operate the Core privately
```

```text
Drupal truth / Community Core         →  this repository, in public
private application of that truth     →  elsewhere, never here
```

The Core owns: source acquisition and provenance, reviewed knowledge,
security advisories, API lifecycle and change records, upgrade and migration
intelligence, implementation rules, the read-only project analyzer and
evidence layer, the solved-case, recurrence and generalization workflows,
the discovery and corroboration engine, the community CLI, the static
website, the read-only public API, and every schema and contract those
surfaces need.

A product that *operates* the Core — running it continuously over particular
projects, storing results for particular organisations, gating pipelines
under an organisation's own policy, offering accounts, tenancy or
entitlements — is a different product with a different governance. It may
depend on this repository. This repository does not depend on it, does not
name it, and carries no adapter, contract, route or schema for it.

## The laws

1. **The dependency points one way.** Nothing under `scripts/` or
   `collectors/` imports a module that is not in this repository, and no
   route of the public API, page of the website or command of the CLI
   reaches a private service. `scripts/test_community_boundary.py` proves
   this on every push.

2. **A Core fix happens here first.** A defect in an engine, a record or a
   contract is fixed in this repository and released with a tag. A
   downstream product pins a tag and moves deliberately; it does not carry a
   patched private copy of Drupal truth.

3. **No private fork of Drupal truth.** A downstream product may hold its
   own organisational knowledge and policy — statements about *its*
   projects and *its* requirements — and may present them beside Core
   knowledge with a distinct trust class. It may never present them as
   Drupal knowledge, and it may never rewrite what a Core record says.

4. **Customer evidence never flows automatically into public knowledge.**
   What any product observes inside a private project is project-specific
   applicability. It becomes a candidate for public knowledge only through
   the same path as everything else: a solved case or a discovery signal,
   captured with fingerprints and no identity, corroborated, proposed, and
   reviewed by a human who edits this repository. There is no automatic
   path, however many projects show the same thing.

5. **The Core names no consumer.** Records carry no consumer-specific
   eligibility, the taxonomy has no consumer domain, and the documentation
   describes external consumers generically. A consumer's needs are never
   encoded as universal Drupal guidance.

## What stays out of this repository

- Any module, schema, route, document or test whose subject is a privately
  operated service: tenancy, accounts, entitlements, usage metering,
  persistent per-organisation projects, runs and artifacts, continuous
  monitoring, portfolios, organisational policy, waivers, pipeline decision
  delivery, production deployment and operations.
- Any consumer-specific adapter or contract.
- Any absolute local path, e-mail address, credential, private repository
  URL, project name or organisation name.

`scripts/test_community_boundary.py` scans the tree for all of these.

## What this does not mean

The Core is not a reduced edition. Every engine ships with its full
capability, every command answers completely, and nothing is withheld to
make a downstream product more valuable. A downstream product
differentiates by *operating and applying* the Core privately and
continuously — not by the Core being made artificially less useful.
