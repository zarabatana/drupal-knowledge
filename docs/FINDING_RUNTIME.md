# Finding Runtime

The finding runtime is the single reviewed component that executes
`machine_finding` contracts. It turns one trusted project analysis into one
deterministic, schema-validated finding evaluation.

```text
REAL DRUPAL PROJECT
  -> Drupal Project Analyzer (dk.py analyze)
  -> neutral release lifecycle assessment (release lifecycle evaluator)
  -> reviewed machine_finding contracts (knowledge records)
  -> finding runtime (dk.py findings)
  -> finding evaluation with zero or more findings
```

## Command

```bash
python3 scripts/dk.py version
python3 scripts/dk.py analyze /path/to/drupal-project > analysis.json
python3 scripts/dk.py findings analysis.json
python3 scripts/dk.py findings analysis.json --explain
```

`version` prints the product version and the interface contract versions so a
consumer can perform a version handshake against a released checkout.

`findings` prints the machine-readable finding evaluation JSON. `--explain`
prints the deterministic human-readable explanation rendered from the same
provenance; nothing in the explanation is generated outside the evaluation
document.

## What The Runtime Consumes

- the analysis JSON produced by the Drupal Project Analyzer (trusted analyzer
  output; the analyzed project itself is never reopened);
- the neutral release lifecycle assessment, built in-process by the release
  lifecycle evaluator from that analysis and the canonical reviewed lifecycle
  context;
- the canonical Applicability Resolver result for the analysis: a confirmed
  finding requires a definitive `applicable` / `machine_resolved` resolution of
  the owning knowledge record, and the runtime never reimplements
  applicability predicates;
- reviewed knowledge records carrying declarative `machine_finding` contracts,
  including their explicit `semantic_authority_version_scope`.

The runtime is a consumer, not an authority. It executes the reviewed
declarative contract: the condition requirements, the state map, the identity
recipe, the deduplication key, and the provenance requirements all come from
contract data. There is no per-version or per-release logic in the runtime.

The only join between contract data and assessment fields is the evidence
binding table, which maps a contract's declared literal source term location
(`evidence_domain`, `source_field_path`, `source_term_name`) to the assessment
field that preserves it. A future reviewed contract using an already bound
location executes with no runtime change.

## Supported Contract

Exactly one reviewed contract exists and is executed:

| Property | Value |
| --- | --- |
| Knowledge record | `drupal.update.core-release-insecure-term-condition` |
| Condition | `installed_core_release_carries_source_release_type_term_insecure` |
| Assertion | `installed_core_release_is_not_secure_per_drupal_update_status` |
| Evidence domain | `release_lifecycle_assessment` |
| Literal trigger | `Release type` term value `Insecure` on the exact installed release row |
| Semantic authority | reviewed Drupal 11.4.5 update-module sources (`isInsecure()` -> `NOT_SECURE` -> "Project is missing security update(s).") |

## Finding States

States come from the contract state map plus the fail-closed runtime states of
the Finding Authority Model:

| State | Meaning |
| --- | --- |
| `confirmed` | The reviewed condition is proven on the exact installed release under a current canonical reviewed context, with definitive applicability and the installed Drupal core major inside the reviewed semantic authority version scope. |
| `candidate` | The literal term is present but confirmation authority is missing: either the contract's term semantics are not reviewed, or the installed Drupal core major is outside the reviewed semantic authority version scope. Never a security pass. |
| `historical_candidate` | The term was present at the pinned reviewed snapshot, but the context is stale; never a current confirmed finding. |
| `not_observed` | The exact matched release row does not carry the term. Not a security pass. |
| `unknown` | Core version unknown, release row missing, context not canonical, assessment invalid, or canonical applicability not definitively resolved. Unknown is not false. |
| `requires_human_review` | The lifecycle assessment itself requires human review. |

Unexecutable contracts (unreviewed record, unsupported evidence domain or
match mode, missing evidence binding) are refused: they appear under
`contracts.not_executed` with a reason code and can never confirm anything.

## Output Contract

The finding evaluation is validated against
`schema/finding-evaluation.schema.json` before it is returned. Every finding
carries:

- the fifteen provenance fields required by the contract, including analysis
  identity, core-version evidence IDs, the lifecycle assessment and context
  identities, the pinned source snapshot digest, the exact matched release,
  the literal source term, the canonical applicability result identity, and
  the semantic authority version scope decision;
- a deterministic `finding_id`: `sha256_stable_json` over the contract's
  declared identity key fields. No timestamps, hostnames, run IDs, or absolute
  paths participate, so repeated runs and relocated checkouts produce the same
  logical finding;
- the contract deduplication key with `max_instances` 1: the term is reachable
  through several source read paths, and all of them collapse into one logical
  finding;
- `severity` fixed to `not_established` with a null source;
- `effective_enforcement` `guidance` (blocking is structurally excluded);
- a `not_claimed` list carrying the contract's forbidden claims;
- a four-part explanation (`observed`, `authoritative_drupal_knowledge`,
  `drupal_definition`, `conclusion`) assembled only from provenance and the
  reviewed `authorized_meaning`.

## What A Confirmed Finding Does Not Mean

A confirmed finding asserts exactly the reviewed Drupal Update Manager
meaning: the exact installed release is classified not secure, documented as
the project missing security update(s). It does not assert a specific CVE, an
exploitation path, a compromise, a severity level, a support or end-of-life
status, or an upgrade obligation, and it proposes no remediation.

## Limitations

- Only the `release_lifecycle_assessment` evidence domain is bound.
- Only `literal_exact_string` matching and `sha256_stable_json` identity are
  executable.
- Evaluation is only as current as the reviewed lifecycle context; a stale
  context downgrades a present term to `historical_candidate`.
- The runtime performs no network access, no source collection, no project
  rescan, no knowledge mutation, and no remediation. No external adapter
  consumes finding evaluations yet.
