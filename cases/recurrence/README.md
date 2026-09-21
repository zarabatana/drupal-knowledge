# Recurrence Analyses

One file per recurrence group: `recurrence.drupal.<digest>.json`.

A recurrence analysis records that the same proven root cause and fix were
observed in more than one verified solved case. Grouping is exact structural
identity over normalized root cause, fix category, fix summaries and affected
components — never description-text similarity.

Occurrences are counted per distinct project fingerprint. Recapturing one
project, and that project at another revision, are further evidence about one
place rather than a second place.

```text
RECURRENCE != GENERALIZATION != TRUSTED KNOWLEDGE
```

Contract: `schema/recurrence-analysis.schema.json`.
