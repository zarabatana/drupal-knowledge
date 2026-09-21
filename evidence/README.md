# Project Evidence Sets

Optional storage for canonical project evidence. The CLI is ephemeral by
default; `dk.py evidence --persist` writes here.

```text
projects/<project_fingerprint>/<revision_fingerprint>.json
```

Identity is fingerprints alone. `project_id` is stripped on the way in, so this
tree carries no project name, and a revision's file is never rewritten by a
later revision — evidence for one revision is history, not state.

Nothing here is trusted knowledge. Every record carries
`channel: project_derived_evidence` and describes one repository observation.
