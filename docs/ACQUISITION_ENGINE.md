# Knowledge Acquisition Engine

`scripts/dk_acquisition.py` is one orchestration layer over the source
architecture Drupal Knowledge already had. It systematically watches registered
authoritative sources and turns what it observes into deterministic review work.

It does not own Drupal truth.

## The invariant

```text
SOURCE CHANGE
!=
TRUSTED KNOWLEDGE CHANGE
```

A newly acquired snapshot is an `observed_source_snapshot`. It is never
`reviewed_trusted_knowledge`, no matter how authoritative the source is. Every
canonical mutation path takes the digest of `knowledge/records/` before and
after the work and refuses to continue if it moved. An acquisition run always
reports:

```json
"trusted_knowledge_mutations": []
```

## Flow

```text
registered authoritative source
        ↓
scheduled or targeted acquisition
        ↓
fetch → normalize → stable window → SHA-256
        ↓
immutable content-addressed snapshot
        ↓
change detection against the last accepted snapshot
        ↓
review candidate
        ↓
human review
        ↓
possible trusted-knowledge proposal, later and separately
```

## What is reused, not rebuilt

The engine deliberately owns no storage of its own:

| Concern | Lives in | Owner |
| --- | --- | --- |
| Registered sources | `sources/registry.json` | pre-existing registry |
| Immutable snapshots | `sources/snapshots/<source-id>/<sha256>.txt` | `dk_core.write_snapshot` |
| Per-source state | `sources/state/<source-id>.json` | extended in place |
| Review candidates | `discovery/candidates/<candidate-id>.json` | pre-existing candidate tree |
| Trust tiers | `dk_core.TRUST_TIERS` | pre-existing taxonomy |

`collectors/collect.py` is now a thin front end over the same engine, so manual
collection, `dk.py acquire` and the scheduled CI job cannot drift apart.

## Trust tiers

The existing taxonomy is unchanged: `authoritative`, `industry-standard`,
`ecosystem`, `discovery`, `internal-proven`. Every registered source today is
`authoritative`, and the engine is operated against authoritative sources.
`--trust` can select any tier the registry contains; broad ecosystem and
community discovery is not activated.

## Registry-driven behaviour

Acquisition behaviour is declared per source, never branched on a source id.
Beyond the fields the registry already carried, a source may declare:

| Field | Meaning |
| --- | --- |
| `expected_content_type` | `html`, `xml`, `json`, `text` or `auto`. A conflicting response is a contract failure, not a silent change. |
| `normalization` | `auto` (historical content-type sniffing), `html_text` or `raw_text`. |
| `check_cadence_days` | How fresh a successful acquisition must be before the source is stale and due. |
| `lifecycle` | `active`, `retired` or `superseded`. Only active sources are acquired. |
| `superseded_by` | The registered source that replaced this one. |

`content_start` / `content_end` remain the mechanism for stable content windows.
Noise filtering is configuration, not scraping logic inside the engine.

## Normalization

Normalization is a pure function of response bytes plus registry configuration:
line endings collapse, runs of whitespace collapse, HTML is reduced to visible
text when the strategy says so, and a configured window is applied last. The
same bytes always yield the same normalized text and therefore the same snapshot
identity.

It removes transport noise and page chrome. It does not remove meaningful
semantic differences to make a source look quieter than it is.

## Immutable snapshots

```text
normalized content → SHA-256 → sources/snapshots/<source-id>/<sha256>.txt
```

The filename is the digest of the file's own bytes. Acquiring identical content
twice reuses the same snapshot rather than creating a second logical truth.
When content changes, the previous snapshot stays byte-identical and addressable
and the new state records it as `previous_snapshot_sha256`.

## Change detection

Detection is a hash comparison. Every attempt ends in exactly one status:

| Status | Meaning |
| --- | --- |
| `first_observation` | The source had no accepted snapshot yet. |
| `unchanged` | Normalized content matches the last accepted snapshot. |
| `changed` | Normalized content differs. A review candidate is created. |
| `unavailable` | The source could not be reached. |
| `invalid_or_malformed` | The source answered but broke its declared contract. |

A network failure is never `unchanged`. A parse or window failure is never
`unchanged`.

The reviewer-facing change summary is a `difflib` line diff over normalized
snapshot text: line and byte counts, changed regions, the first changed line,
and bounded samples of added and removed lines. No language model participates
in deciding that a source changed or in describing the change. An assisted
semantic explanation could only ever be an addition on top of this.

## Review candidates

A meaningful change writes `discovery/candidates/<candidate-id>.json`, where the
id is deterministic:

```text
source-change.<source-id>.<sha256(source_id:previous:current)[:16]>
```

Because identity is derived from the two snapshots, re-observing the same change
reuses the existing candidate and preserves its original detection evidence. It
never duplicates.

A candidate carries the source id, trust tier, both snapshot digests, the
detecting run id, the engine version, the deterministic change summary, safe
provenance, and its review state. It also carries three assertions that the
schema pins:

```json
"review_required": true,
"can_promote_to_knowledge": false,
"is_knowledge_proposal": false
```

A candidate means *something changed and requires review*. It never means
*Drupal Knowledge should change in this way*.

## Review states

```text
pending_review
reviewed_no_knowledge_change
reviewed_requires_knowledge_proposal
dismissed_as_non_semantic
```

Review records the reviewer, the method, the timestamp and an optional note.

None of these states changes trusted knowledge.
`reviewed_requires_knowledge_proposal` only authorizes later, explicit
knowledge-proposal work; generating proposals is not part of this engine, and
there is no flag anywhere that accepts a source change into knowledge.

## Failure model

Three classes are kept apart because they mean different things:

| Class | Cause | Effect |
| --- | --- | --- |
| `external_source_unavailable` | timeout, DNS, connection, 404/5xx | explicit unavailable state, last known snapshot preserved, failure counter increments |
| `source_contract_failure` | missing window, wrong content family, empty or oversized response | explicit malformed state, nothing baselined |
| `acquisition_engine_defect` | our own bug or a broken internal invariant | reported as an engine defect, exit code 3, never filed as evidence about the source |

Exit codes: `0` clean, `1` at least one source failure, `2` bad input, `3`
engine defect.

## Source state

`sources/state/<source-id>.json` keeps its existing shape and gains an
`acquisition` block: last attempt time, run and status; last success time and
run; the superseded snapshot; consecutive failures; the last classified error;
the open review candidate; and the configured cadence.

A source whose only attempts failed has acquisition state and no snapshot
pointer, so it reads as *not baselined* instead of looking healthy. State
written before this engine existed has no `acquisition` block; its last recorded
content change is used as a conservative lower bound for the last success, which
can only make a source look staler than it is.

Advancing state never rewrites a historical snapshot.

## Staleness

A source that has not been successfully refreshed within `check_cadence_days` is
visibly stale and due for a check.

```text
stale != incorrect
stale != changed
```

A refresh that fails never deletes the last known evidence.

## Acquisition run

Every run emits a machine-readable result: run id, engine name and version,
start and completion, dry-run flag, the full selection with explicit skip
reasons, per-source results, snapshots created and reused, review candidates
created and reused, failures, engine defects, stale sources, the trusted
knowledge digest before and after, and `trusted_knowledge_mutations`.

## Dry run

`--dry-run` fetches, normalizes, hashes and compares for real, and reports the
true status. It writes no source state, no snapshot, no review candidate and no
knowledge. `--normalized-output` writes normalized text for inspection outside
canonical directories, and requires `--dry-run`.

## CLI

```bash
python3 scripts/dk.py acquire --source drupal-core-releases
python3 scripts/dk.py acquire --source drupal-api-11 --dry-run
python3 scripts/dk.py acquire --trust authoritative --due --report acquisition-report/run.json
python3 scripts/dk.py source-status [<source-id>] [--json]
python3 scripts/dk.py review-candidates list [--state pending_review]
python3 scripts/dk.py review-candidates show <candidate-id>
python3 scripts/dk.py review-candidates review <candidate-id> \
  --state reviewed_no_knowledge_change \
  --actor "<reviewer>" \
  --method human_source_diff_review
```

Targeted acquisition stays first class. Running with no selection is an error
rather than an implicit broad crawl. `collectors/collect.py --source <id>`
continues to work and runs the same engine.

## Scheduling

The Community validation workflow never acquires: a pull request cannot reach
the network on the repository's behalf. When a maintainer schedules acquisition
(a separate workflow, not part of this repository's validation gate), it must
call the same `dk.py acquire` entry point as a manual run, target due
authoritative sources with `--due`, publish the run report, source state,
snapshots and review candidates as artifacts, and commit nothing.

There is no daemon, no long-running service and no external infrastructure. The
scheduled job never commits or pushes: a changed source becomes a downloadable,
reviewable artifact, and accepting it into the repository stays a human act.

## Accepting an observed change is a separate act

Acquiring a change and accepting it are not the same operation, and the
repository enforces the gap.

Some reviewed knowledge context is pinned to the exact source snapshot it was
derived from. `dk.py validate` requires that pinned context to match the current
source state, so baselining a new snapshot for such a source deliberately fails
validation until a human re-normalizes and re-reviews the context against the
new evidence.

That is the boundary working, not an obstacle to route around. An acquisition
run reports the change truthfully, the previous snapshot stays the accepted one,
and the source reads as stale. Deciding what the change means to Drupal
Knowledge stays a reviewed act with its own commit.

## Boundary with solved cases

External source acquisition and internal proven solved cases are separate
ingestion channels with separate storage, producers and provenance:

```text
discovery/candidates/  external_authoritative_source  drupal-knowledge-acquisition-engine
cases/solved/          internal proven evidence       drupal-knowledge-solved-case-capture
```

Both may eventually inform knowledge proposals, but never through each other's
provenance.
