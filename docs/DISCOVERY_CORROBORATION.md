# Ecosystem Discovery and Corroboration

`scripts/dk_discovery.py` adds one evidence channel on top of the released
acquisition engine. It watches registered ecosystem sources, records what it
observed as untrusted **signals**, and assembles deterministic **corroboration
dossiers** so a human can decide what, if anything, it means.

It owns no downloader, and it does not own Drupal truth.

## The invariant

```text
DISCOVERY SIGNAL
!=
SOURCE SNAPSHOT
!=
TRUSTED KNOWLEDGE
!=
SOLVED CASE
!=
FINDING
```

There is no path from a blog post, an issue queue, a forum thread or a vote
count to trusted Drupal knowledge. Every canonical mutation path takes the
digest of `knowledge/records/` before and after the work and refuses to continue
if it moved. A discovery run always reports:

```json
"trusted_knowledge_mutations": []
```

## Flow

```text
registered ecosystem/discovery source
        ↓
acquisition engine: fetch → normalize → SHA-256 → immutable snapshot
        ↓
deterministic signal extraction
        ↓
discovery signal            (observed, untrusted)
        ↓
corroboration
        ├── authoritative source assertions
        ├── independent ecosystem origins
        ├── internal-proven solved cases
        ├── contradictory evidence
        └── insufficient evidence
        ↓
corroboration dossier       (pending_review)
        ↓
human review
        ↓
may authorise later, separate knowledge-proposal work
```

## What is reused, not rebuilt

Discovery never opens a socket. Retrieval, normalization, hashing, snapshot
storage, source state, cadence and failure classification are all the v0.9
acquisition engine:

| Concern | Owner |
| --- | --- |
| fetch, normalize, hash | `dk_acquisition.acquire_source` |
| immutable snapshots | `dk_core.write_snapshot` / `require_snapshot` |
| source state, staleness | `dk_acquisition.build_state` / `staleness` |
| source registry | `sources/registry.json` |
| signal extraction | `dk_discovery.EXTRACTORS` |
| corroboration | `dk_discovery.classify_corroboration` |

A signal always cites the snapshot digest it was derived from, so its evidence
stays addressable and immutable.

## Trust tiers

The existing taxonomy is unchanged. What differs is what each tier is *allowed
to do*:

| Tier | May produce signals | May corroborate |
| --- | --- | --- |
| `authoritative` | no | yes, strongly |
| `industry-standard` | no | yes |
| `ecosystem` | yes | yes |
| `discovery` | yes | yes |
| `internal-proven` | no (separate channel) | yes, without generalising |

Authoritative and industry-standard sources contribute *evidence*; discovery
does not manufacture community signals out of them. Attempting it is a
registry error, not a silent reinterpretation.

## Registry-driven behaviour

Discovery behaviour is declared per source under a `discovery` block, so no
code branches on a source id:

```json
"discovery": {
  "role": "signal_source",
  "extraction": "project_release_xml",
  "signal_kind": "project-release",
  "independence_group": "drupal-org-project-token",
  "derived_from": null,
  "max_items": 5,
  "expected_refresh_days": 30,
  "component": {"type": "module", "name": "token", "package": "drupal/token"}
}
```

- `role` — `signal_source` produces signals; `evidence_source` only contributes
  assertions to corroboration, read back out of its existing snapshot.
- `extraction` — which deterministic extractor to run.
- `independence_group` — the **editorial origin**. Sources sharing a group are
  not independent of one another.
- `derived_from` — declares this source republishes another origin. Its lineage
  collapses onto that origin.
- `max_items` — bounds how much of a source one run will observe.

Unregistered URLs are not ingestible. There is no crawler and no free-form URL
input.

## Signal extraction

Extraction is deterministic and structured. `project_release_xml` reads
`version`, release-type terms, `status`, `security` and `core_compatibility`
from update-status release history; `project_issue_json` reads `nid`,
`field_issue_status` and `field_issue_version` from a drupal.org api-d7 listing.

No language model participates in observing, extracting, matching or
classifying. Every signal records:

```json
"extraction": {"strategy": "...", "deterministic": true, "field_path": "..."}
```

An LLM-written summary could later be added as presentation. It would remain
optional, and the engine would keep working without it.

## Signals

A signal means *something potentially useful was observed*. Identity is
`(source, item, assertion)`:

```text
signal.drupal.<source-id>.<sha256[:16]>
```

Re-observing the same item asserting the same thing **reuses** the signal and
rewrites nothing, so repeat runs produce no churn and no duplicate evidence. A
genuinely different report from a different source is a different signal and
stays countable as separate evidence.

Signal statuses: `observed`, `corroboration_pending`, `corroborated`,
`contradicted`, `insufficient_evidence`, `dismissed`, `stale`.

Every signal is pinned:

```json
"review_required": true,
"can_promote_to_knowledge": false,
"is_trusted_knowledge": false,
"is_knowledge_proposal": false
```

## Popularity is not authority

Popularity is recorded because it is observable and ignored because it is not
evidence:

```json
"popularity": {"metrics": {"comment_count": 9999},
               "counts_toward_corroboration": false,
               "authority_weight": 0}
```

An issue with 9999 comments and no independent corroboration is
`insufficient_evidence`. Corroboration counts independent evidence origins,
never volume, votes or reposts.

## Corroboration

Evidence is matched on the claim's `assertion_key`. Matching evidence with an
equal `assertion_value` supports the signal; a differing value contradicts it.
Three independent filters then apply.

### Independence

Corroboration counts **origins**, not documents. Evidence is disqualified as
`duplicate` when it shares the signal's lineage, where lineage is
`derived_from or independence_group`. Three sources republishing one origin are
one origin.

Identical structured assertions from *separate* origins are what agreement
looks like, so claim equality alone is never read as duplication. Every
evidence item still records a `content_fingerprint` for lineage inspection.

Authoritative and industry-standard evidence are exempt from the lineage rule:
their weight comes from authority, not from being a second voice.

### Version and scope alignment

Scope is only ever narrowed by evidence, never widened. Absent scope stays
`unknown` rather than decaying into "applies everywhere".

Alignment compares the component and the version scope. Project versions reduce
to a branch (`8.x-1.17` → `8.x-1`; `3.0.5` → `3`) and core constraints reduce to
major versions (`^10.3 || ^11` → `{10, 11}`). Mismatched evidence is recorded as
`scope_mismatch` and cannot support the signal:

```text
signal:          module X 3.x on Drupal 11
matching case:   module X 1.x on Drupal 9
result:          scope_mismatch, not corroboration
```

### Contradiction

Contradictory evidence is first-class and never discarded. An authoritative
contradiction outranks any amount of agreement, and the supporting evidence is
retained alongside it.

### Resulting states

| State | Condition |
| --- | --- |
| `corroborated` | authoritative support, or ≥2 independent external origins |
| `partially_corroborated` | exactly one independent origin, or solved-case support only |
| `contradicted` | authoritative contradiction, or contradiction with no support |
| `insufficient_evidence` | no scope-aligned supporting evidence |
| `not_applicable` | the signal carries no checkable assertion |

A dossier is rebuilt in place, one per signal. Identical evidence rewrites
nothing (`reused`); changed evidence updates it (`updated`).

## Solved cases support without generalising

Solved cases are a separate provenance channel
(`internal_proven_solved_case`). They contribute recurrence evidence matched on
component and version, always flagged `generalizes: false`.

One solved case plus one community report is not a universal Drupal fact: when
solved cases are the only support, the dossier is capped at
`partially_corroborated` and says so in `limitations`.

## Corroborated is still not knowledge

```text
corroborated discovery evidence
!=
trusted knowledge
```

Every dossier is pinned `review_required: true`,
`can_promote_to_knowledge: false`, `is_trusted_knowledge: false`,
`is_knowledge_proposal: false` and `generalizes_automatically: false`.

## Human review

Dossiers start at `pending_review`. Outcomes:

| Outcome | Meaning |
| --- | --- |
| `no_action` | evidence noted, nothing to do |
| `watch` | keep observing |
| `needs_more_evidence` | insufficient to decide |
| `candidate_for_future_knowledge_proposal` | authorises later, separate proposal work |
| `dismissed` | noise |

None of these mutates trusted knowledge.
`candidate_for_future_knowledge_proposal` authorises *work*, not a change, and
creates no knowledge record. Knowledge-proposal generation is deliberately not
implemented here.

If evidence changes after a review, the dossier returns to `pending_review`,
keeps the earlier decision as history, and records that the evidence moved.
A new fact deserves a fresh judgement.

## Failure model

Four failure kinds stay separate, because they call for different responses:

| Kind | Discovery status | Meaning |
| --- | --- | --- |
| external unavailable | `source_unavailable` | unreachable; **not** evidence that nothing exists |
| source contract | `source_contract_failure` | fetched, but broke its own format contract |
| extraction | `extraction_failure` | acquired fine, signal contract failed |
| insufficient evidence | `insufficient_evidence` | a valid signal with nothing to corroborate it |

An engine defect is none of these. Unexpected exceptions are re-raised as
`DiscoveryEngineDefect`, exit code 3, and are never filed as a source failure.

## Staleness

Signals age. `stale` is a freshness statement, never a truth statement:

```text
stale signal != false signal
```

A stale signal keeps its evidence and its evidence-derived status. Nothing is
deleted because a refresh lapsed.

## Dry run

`--dry-run` fetches and normalizes into scratch space, reports what it would
record, and mutates no source state, no snapshot tree, no signal, no dossier and
no trusted knowledge.

## CLI

```text
dk.py discover --source <id> [--dry-run] [--due] [--report PATH]
dk.py discover --trust ecosystem --due
dk.py signals list [--status S] [--trust T] [--json]
dk.py signals show <signal-id>
dk.py corroborate <signal-id> [--dry-run]
dk.py corroboration list [--state S] [--review-state S]
dk.py corroboration show <dossier-id>
dk.py signal-review <dossier-id> --outcome <outcome> --actor <who>
```

`--source` or `--trust` is required: unbounded discovery is not an available
mode. There is deliberately no `--promote-to-knowledge` and no `--trust-this`.

## Scheduling

The Community validation workflow never discovers: a pull request cannot reach
the network on the repository's behalf. Scheduled discovery is a separate
workflow, `.github/workflows/scheduled-discovery.yml`, which runs daily
(`43 3 * * *` UTC) and on demand. It drives the same `dk.py discover` entry
point a human would, with `--trust ecosystem --due`, so only registered signal
sources past their cadence are contacted. Discovery is registry-bound: there is
no broad crawl and no unregistered URL is ever fetched.

Persistence follows the acquisition workflow's model. A run that changed
nothing produces no commit and no pull request. A run that recorded signals,
dossiers, snapshots, state or review candidates regenerates the derived public
artifacts, checks every changed path against the allow-list in
`scripts/dk_automation.py`, and persists the change set on the deterministic
branch `automation/discovery` as a pull request that later runs update rather
than duplicate. Nothing is pushed to `main`, nothing is merged automatically,
and the branch ruleset applies. A discovery signal is review work:
DISCOVERY SIGNAL != TRUSTED KNOWLEDGE, and the workflow has no path that could
make it otherwise. No daemon, no persistent service, no credential beyond the
workflow token.

The discovery tests run in the `engines` job of `.github/workflows/community.yml`,
a required gate on every push and pull request.

## Boundary with the other channels

Drupal Knowledge now has five distinct provenance channels, and they never blur:

```text
external_authoritative_source   authoritative acquisition (v0.9)
external_discovery_source       ecosystem discovery (this engine)
internal_proven_solved_case     solved cases (v0.8)
trusted_knowledge               knowledge/records/
project evidence / finding      analyzer and finding runtime
```

Corroboration reads solved cases and authoritative snapshots as *evidence*. It
never rewrites a signal's originating tier: authoritative support does not
retro-promote a community observation into an authoritative one, and the
dossier records the signal's original trust verbatim.

Trusted-knowledge records carry no machine-readable assertion keys, so the
`trusted_knowledge` evidence channel contributes no automatic evidence yet.
Every dossier states that limitation rather than implying it.
