# Sources

`sources/registry.json` is the source allow-list. It is built around a small set
of high-authority Drupal sources, plus a small, explicitly registered set of
ecosystem sources used for discovery. It deliberately excludes broad contrib
ingestion, Stack Exchange, Reddit, arbitrary blogs, and all Symfony/PHP docs.
There is no crawler and no free-form URL ingestion: a source must be registered
and reviewed before anything reads it.

## Trust

- `authoritative`: Drupal.org, api.drupal.org, Drupal Security Team, current
  official Drupal Coding Standards, or delegated upstream authority.
- `industry-standard`: standards directly required by a record, such as WCAG,
  PHP, Symfony, Composer, or OWASP.
- `ecosystem`: useful Drupal ecosystem information that cannot automatically
  create blocking authority.
- `discovery`: community signals only. Supported by the discovery engine but not
  currently registered for live collection.

Security advisory feeds carry a `security` block declaring their advisory role
and the authoritative field names the security engine reads, so advisory parsing
never hardcodes them. See
[SECURITY_INTELLIGENCE.md](SECURITY_INTELLIGENCE.md).

API lifecycle sources carry an `api_lifecycle` block the same way, declaring
whether they are a per-branch core deprecation index or a change-record feed,
and which fields the migration engine may read. Community upgrade advice and
third-party analysers such as Drupal Rector are not registered and are never
semantic authority. See [API_MIGRATION.md](API_MIGRATION.md).

Official Drupal upgrade documentation carries an `upgrade` block the same way,
declaring which transition or platform requirement the page speaks for, so the
upgrade engine never branches on a source id. Community upgrade advice is not
registered and therefore is never upgrade authority. See
[UPGRADE_COMPATIBILITY.md](UPGRADE_COMPATIBILITY.md).
- `internal-proven`: cases solved and verified by the maintainers only.

## Immutable Snapshots

Collector snapshots are content-addressed normalized text:

```text
sources/snapshots/<source-id>/<sha256-hex>.txt
```

The filename must equal `SHA-256(snapshot bytes)`. State files point to the exact
`sha256:<hex>` value. Historical snapshots are never rewritten.

## Source Updates

A changed source creates a source-change review candidate:

```json
{
  "review_required": true,
  "can_promote_to_knowledge": false,
  "is_knowledge_proposal": false
}
```

Trusted knowledge does not change until a human reviews and edits records.

Acquisition is orchestrated by the knowledge acquisition engine. See
[ACQUISITION_ENGINE.md](ACQUISITION_ENGINE.md) for change detection, review
states, failure classes, staleness, dry-run and scheduling.

## fetch_url

Each source has a canonical human URL. Some sources also have `fetch_url` for a
machine-friendly representation. Drupal core releases use the Drupal.org release
page as the canonical URL and the update-status XML endpoint as `fetch_url`.

## Content Windows

`content_start` and `content_end` may be configured when a page contains noisy
navigation or footer content. If a marker is configured and missing, collection
fails rather than hashing unstable or empty content.

## Acquisition Configuration

Acquisition behaviour is declared per source instead of being branched on a
source id:

- `expected_content_type`: the response family the source is expected to return.
  A conflicting response is a contract failure, never a silent change.
- `normalization`: `auto` keeps the historical content-type sniffing; `html_text`
  and `raw_text` state the strategy explicitly.
- `check_cadence_days`: how fresh a successful acquisition must be. Past it the
  source is visibly stale and due for a check.
- `lifecycle`: `active`, `retired` or `superseded`. Only active sources are
  acquired; `superseded_by` names the replacement.

## Discovery Configuration

An optional `discovery` block declares how a source participates in ecosystem
discovery, so no code branches on a source id:

- `role`: `signal_source` produces untrusted discovery signals; `evidence_source`
  only contributes assertions to corroboration, read back out of the snapshot
  acquisition already stored.
- `extraction`: which deterministic extractor to run over the snapshot.
- `independence_group`: the editorial origin. Sources sharing a group are not
  independent of one another, so their agreement is one origin, not two.
- `derived_from`: declares that this source republishes another origin. Its
  lineage collapses onto that origin, so a repost cannot corroborate.
- `max_items`: bounds how much of a source one run observes.
- `expected_refresh_days`: how fresh a signal must be before it reads as stale.

Only `ecosystem` and `discovery` tiers may produce signals. Authoritative and
industry-standard sources contribute evidence. See
[DISCOVERY_CORROBORATION.md](DISCOVERY_CORROBORATION.md).

## Coding Standards Provenance

The Drupal.org Coding Standards project page links to the current GitLab Pages
standards site. The historical Drupal.org standards guide is marked obsolete and
deprecated, so it is not registered as primary authority. It can be used only as
redirect/provenance evidence when needed.
