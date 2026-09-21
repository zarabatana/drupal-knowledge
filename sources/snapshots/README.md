# Source Snapshots

Snapshots are immutable normalized source text.

Path convention:

`sources/snapshots/<source-id>/<sha256-hex>.txt`

The filename must equal `SHA-256(snapshot bytes)`. Existing snapshots must never
be rewritten.
