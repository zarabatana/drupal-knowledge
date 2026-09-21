# Security Advisory Records

One file per advisory: `SA-CORE-YYYY-NNN.json`, `SA-CONTRIB-YYYY-NNN.json`,
`PSA-YYYY-NNN.json`.

Each record is a faithful projection of one Drupal Security Team advisory as
published in an authoritative structured source, pinned to the immutable
snapshot it was read from.

```text
authoritative advisory record  !=  general trusted Drupal knowledge rule
severity                       !=  enforcement
unknown                        !=  not applicable
```

`record_class` is `source_derived_authoritative_record`. That is the category
that lets advisory data be materialized from a reviewed source snapshot without
becoming trusted knowledge: it is authoritative security *evidence*, not a
reusable behavioural rule about Drupal.

What these records never contain: a severity score computed from the published
risk vector, a severity label read out of the advisory title, a CVE where none
was assigned, remediation Drupal Knowledge wrote itself, or any exploitability
claim. Where the source is silent the record says `not_established` and stops.

Ingestion reads only a snapshot the acquisition engine has accepted, so a moved
feed produces a review candidate before anything is re-materialized. Superseded
snapshots stay addressable, so advisory history is never rewritten in place.

Contract: `schema/security-advisory.schema.json`.
Architecture: `docs/SECURITY_INTELLIGENCE.md`.
