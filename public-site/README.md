# Public Website Source

```text
content/    authored editorial pages — home, trust model, CLI, about
assets/     site.css and search.js
dataset/    GENERATED. Committed and stale-guarded. Do not edit by hand.
dist/       GENERATED. Gitignored. Produced by `dk public-site build` and by CI.
```

Only the four files in `content/` and the two in `assets/` are written by hand.
Every domain page is generated from canonical records through the released query
layer, so an advisory page cannot say something the CLI would not.

Rebuild after changing anything canonical:

```bash
python3 scripts/dk.py public-site build
python3 scripts/dk.py public-site serve      # http://127.0.0.1:8000/
```

`python3 scripts/dk.py validate` fails if the committed dataset no longer matches
the canonical records. See `docs/PUBLIC_SITE.md`.
