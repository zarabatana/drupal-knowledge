# Source-Derived API Records

Two record classes, both projected from pinned authoritative snapshots and both
outside trusted knowledge. They follow the `security/advisories/` precedent:
authoritative evidence with full provenance, never a Drupal Knowledge rule.

```text
lifecycle/       one Drupal symbol's deprecation and removal versions
change-records/  one official Drupal core change record
```

Every record carries `is_trusted_knowledge: false`. Neither directory is written
into `knowledge/records/`, and nothing here is edited by hand: run
`dk.py api-lifecycle ingest` to reproject them from the current snapshots.

A change record names symbols but asserts no lifecycle for them. That comes from
the deprecation index alone, so a record that merely mentions an API can never
give it one.
