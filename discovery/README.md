# Discovery

Discovery is the ecosystem evidence channel. It observes registered
ecosystem/discovery sources, records what it saw as untrusted **signals**, and
assembles deterministic **corroboration dossiers** for human review.

    registered discovery source
        -> acquisition (snapshot)
        -> discovery signal
        -> corroboration dossier
        -> human review

This directory holds:

- `candidates/` — source-change review candidates from authoritative acquisition;
- `signals/` — untrusted discovery observations;
- `review/` — corroboration dossiers carrying review state.

Nothing here is trusted knowledge, and nothing here can promote itself into
trusted knowledge or block any consumer. Even a fully corroborated dossier is
corroborated *discovery evidence*: only explicit human review may authorise
later, separate knowledge-proposal work.

See `docs/DISCOVERY_CORROBORATION.md` for the full architecture.
