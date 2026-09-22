# Known Limitations — v1.0

What Drupal Knowledge Community v1.0 deliberately does not do, cannot yet do,
or does only within stated bounds. Every entry says why the limit exists,
what to do about it today, and whether it is a named candidate for work
after v1.0.

Two words are used precisely here. **Roadmap candidate** means a limit we
expect to revisit — it is not a commitment, a date, or a release promise.
**By design** means the limit is a property of the system's honesty model and
removing it would make the product lie; those entries have no roadmap.

## Analysis coverage: what is not observed stays unknown

Every conclusion is evidence-based: the engines state what they observed in
the project and what the released knowledge dataset says about it. What an
engine cannot observe is reported as **unknown — surfaced, never resolved**.
Unknown never becomes pass. Concretely: Drupal Knowledge does not find every
vulnerability, does not prove an upgrade is safe, and does not certify
compliance with anything. Coverage is bounded by the reviewed dataset and by
each engine's observation method (lexed API usage, declared manifests,
structured advisories — not execution, not exploit search).

**Why — by design.** Resolving unknowns optimistically is how analysis tools
lie. The entire authority model exists so that every statement can name its
evidence, and "we did not look at that" is a statement with evidence too.

**Workaround.** None, and none should be wanted. Review the unknowns a run
surfaces and decide them with your own judgment; nothing in this repository
will decide them for you.

## The public dataset is what was reviewed — not "everything about Drupal"

The public site and API ship reviewed records only. The dataset publishes
per-domain record counts and an explicit list of excluded domains with
reasons; unreviewed knowledge and pending generalization proposals are
deliberately absent. Coverage is exactly what the counters say.

**Why — by design.** Publishing unreviewed material beside reviewed
knowledge would make untrusted material look like an answer. A smaller
truthful dataset outranks a larger plausible one in every use this product
is for.

**Workaround.** None needed for the public surface. If you need a statement
the canonical dataset does not make, propose it through the contribution
workflow with its source evidence; it becomes trusted knowledge only after
review.

**Roadmap.** Coverage grows release by release through the acquisition and
review pipeline, never by loosening the review standard.

## Knowledge breadth at v1.0

The reviewed knowledge set is small and concentrated: security advisories,
Drupal core API lifecycle and change records, a reviewed release-lifecycle
context, upgrade transition rules quoted from official documentation, nine
implementation rules, and a handful of reviewed knowledge records. Many
taxonomy domains are marked `EMPTY` in `generated/coverage.json`, and the
coverage report is the honest statement of breadth.

**Why.** Every record required a registered authoritative source, an
immutable snapshot and human review. Breadth that skipped any of those steps
would not be trusted knowledge.

**Workaround.** `dk coverage` shows what exists; `dk search` says when it
found nothing rather than returning something adjacent.

**Roadmap candidate.** Yes — this is the primary axis of growth.

## Acquisition and discovery are scheduled, review is not

Registered sources are fetched by `dk acquire` and `dk discover`, either by a
maintainer or by the scheduled workflows (`scheduled-acquisition.yml` every
six hours, `scheduled-discovery.yml` daily). The validation workflow never
reaches the network. A source that changed is reflected as a pull request on a
deterministic automation branch, and only there, until a maintainer reviews
the resulting candidate, re-reviews any pinned context, and merges.

**Why — by design.** The trust model requires that a source change creates
review work and never mutates knowledge on its own. Scheduling the *fetch* is
an operational choice; the review step can never be scheduled away, and the
automation branch may carry evidence, state, candidates and derived artifacts
only (`scripts/dk_automation.py`).

**Workaround.** Run `dk source-status` to see how stale each source is,
`dk acquire --due` to refresh due sources locally, and `dk review-candidates`
to review. GitHub does not start `push`/`pull_request` workflows for changes
made with the workflow token, so the required checks on an automation pull
request are started by a maintainer (Update branch, or close and reopen).

**Roadmap candidate.** None for the fetch; the review step stays human.

## The project analyzer observes files, not a running site

`dk project` reads `composer.json`, `composer.lock`, `core.extension` and
custom code from a checkout. It does not execute Composer, Drush or PHP,
does not read a database, does not inspect a running site, and does not
resolve Composer package ownership of every extension. Facts it cannot read
from the tree are `unknown`.

**Why — by design.** Executing project code to learn about it would make the
analyzer a way to run untrusted code, and every conclusion would depend on an
environment the repository cannot see.

**Workaround.** Provide a full checkout including `composer.lock` and
`config/sync`; the analyzer reports which facts it derived from which file.

**Roadmap candidate.** Additional declared evidence kinds, always read-only.

## The public website is static and offline-first

The site is a directory of generated HTML with a client-side search over a
published index. It has no accounts, no comments, no analytics, no tracking
and no server component; serving it is a static file server's job. A build
is a snapshot of the released dataset and is only as current as the release
it was built from.

**Why — by design.** A site that cannot run code cannot disagree with the CLI
and cannot collect anything about its readers.

**Workaround.** Rebuild with `dk public-site build` after a release.

## No package distribution

There is no Composer package, PyPI package, Homebrew formula or binary
release. The repository is the distribution: clone it and run `./dk`.

**Why.** The dependency policy is the Python standard library only, and the
knowledge records ship with the code they were validated against; a package
that separated them would be a way to run one release's code over another
release's records.

**Roadmap candidate.** A tagged release archive with checksums
(`release/checksums.json` already covers the release-coupled artifacts).
