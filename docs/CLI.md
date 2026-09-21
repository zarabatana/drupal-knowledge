# The Drupal Knowledge CLI

Everything here reads. Nothing here writes to your project, runs Composer,
executes Drupal, touches a database or changes what Drupal Knowledge believes.

```text
dk <command> [options]        or        python3 scripts/dk.py <command>
```

The two entry points are the same program: `dk` is a thin wrapper, and their
output is byte-identical.

## Install

Drupal Knowledge is a repository, not a package. Clone it and run it — there is
no build step, no service to start and no dependency to install beyond Python 3.

```bash
git clone https://github.com/zarabatana/drupal-knowledge.git
cd drupal-knowledge
./dk status
```

Add it to your `PATH` if you want to run it from a project directory:

```bash
export PATH="$PATH:/path/to/drupal-knowledge"
```

Queries are offline. The record set ships in the repository, and no command
below contacts the network.

## Start With Status

`dk status` answers the only question that matters before you trust an answer:
what does this release actually hold, and how current is it?

```console
$ dk status
Drupal Knowledge 0.19.0
  record set digest   69f48dcb2d9aeb6c

Records held
  advisory               40
  api_lifecycle          225
  ...

What Drupal Knowledge does not know here
  ? Record counts describe what Drupal Knowledge holds, not what exists in Drupal.
```

Freshness is reported per source: when it was last acquired, and whether that is
past its declared cadence. Querying never fetches anything, so a stale source
stays stale until a maintainer acquires it.

## Inspect A Project

One command, every engine, read-only.

```bash
dk project /path/to/drupal-project
dk project /path/to/drupal-project --target 10.6.13
```

Without `--target` you get identity, Drupal version, dependencies, evidence,
applicable advisories and implementation findings. With `--target` you also get
the upgrade assessment and the custom-code migration work for that target.

Each section reports its own state. A section that could not answer says
`unavailable` and gives the reason, rather than being quietly dropped:

```text
Security: available
  advisories_evaluated: 40
  applicable: 18
  enforcement: guidance
  note: Applicable means the advisory's own affected-version expression covers
        the installed version. It is not a statement about exploitability.
```

The exit code is `0` whenever the query succeeded. It is not a severity signal:
a project with eighteen applicable advisories and a confirmed finding still
exits `0`, because the command answered the question it was asked. Read the
findings, not the exit code.

Every run ends with what it could not settle:

```text
What Drupal Knowledge does not know here
  ? Evidence for code is bounded, so absence there proves nothing.
  ? Finding no match is not a compatibility proof.
```

## Check Security

```bash
dk security-evaluate analysis.json
dk security-remediation analysis.json
dk security-advisories list --project drupal
```

Applicable means the advisory's own affected-version expression covers the
installed version. It is not an exploitability claim, and it is guidance:
nothing here blocks and nothing here runs Composer.

Remediation explains the update path — the fixed releases as published, the
lowest target that clears the whole advisory set, and separately the lowest
target that also sits on a supported branch. It never offers a downgrade and
never applies anything.

## Assess An Upgrade

```bash
dk upgrade-evaluate analysis.json --target 11.4.6
dk upgrade-path analysis.json
```

The verdict is one of `compatible_with_observed_evidence`, `requires_changes`,
`blocked`, `requires_review` or `insufficient_evidence`. There is no "safe" and
no "guaranteed", because the assessment is bounded by the evidence available for
each dimension and an unevaluated dimension is not a passing one.

Blockers are separated from unknowns on purpose. A blocker is something the
evidence establishes; an unknown is something nobody looked at or nobody could
see. Ten unknowns are not ten problems, and they are not ten clearances either.

## Inspect Migration Work

```bash
dk migration-analyze analysis.json --target 10.6.13 --project-path /path/to/project
dk migration-work    analysis.json --target 10.6.13 --project-path /path/to/project
```

Usage is read from a lexed PHP token stream, so a deprecated name inside a
comment, docblock, string or heredoc is not a usage. Those rejections are
reported rather than hidden — `text_only_rejected: 63` means sixty-three raw
text matches were examined and correctly refused.

Work items carry file, line and the authoritative deprecation record behind
them. Nothing is rewritten; there is no `--apply`.

## Explain A Finding

```bash
dk explain SA-CORE-2025-004
dk explain file_create_url
```

`explain` answers the questions you would otherwise have to trust someone about:

```text
What is this:   source-derived authoritative record: file_create_url
Why it exists:  Drupal core annotates this symbol with a deprecation, and
                api.drupal.org publishes the annotation.
Authority:      Projected verbatim from an official Drupal source snapshot. It
                is authoritative evidence about Drupal, but it is not a Drupal
                Knowledge rule.
Project scope:  Nothing: this record is about Drupal, not about any one project.
Recommended:    Check whether your custom code uses the symbol with
                `dk migration-analyze`; a deprecation matters only where the
                code actually calls it.
Changed:        No. Querying Drupal Knowledge changes nothing.
```

## Search Drupal Knowledge

```bash
dk search file_create_url
dk search CVE-2025-31673
dk search "access bypass" --domain advisory
dk search views --limit 5 --explain
```

Matching is exact, never fuzzy and never semantic. Ranking is banded so
structured identity always beats prose:

```text
exact identifier  >  exact structured field  >  identifier prefix
                  >  exact token  >  title substring  >  body substring
```

The same query returns byte-identical results every time.

Discovery signals are excluded by default and a warning says so. They are
untrusted community observations, and you opt in explicitly:

```bash
dk search pathauto --domain discovery_signal
```

```text
  signal.drupal.drupal-contrib-pathauto-releases.0f387b13d545009e
    pathauto release 8.x-1.15 is published as release type 'Bug fixes'.
    [UNTRUSTED signal]  discovery signal
```

## Inspect Provenance

```bash
dk provenance api-lifecycle.3f79df0f90cc1c83
```

Every record traces to where it came from — the channel, the registered source,
the pinned snapshot hash and the published URL:

```text
Provenance:
  - authoritative_source: Drupal 9 deprecated API index, page 2 (sha256:9b9b29988d9a578f)
    https://api.drupal.org/api/drupal/deprecated/9
```

The snapshot hash is the point. It identifies the exact bytes the record was
derived from, so a claim can be checked rather than believed.

## Understand Trust Labels

Every result carries one label, and they do not mean the same thing:

| Label | What it means | Can it be applied as a Drupal rule? |
| --- | --- | --- |
| `trusted knowledge` | reviewed Drupal Knowledge | yes |
| `authoritative source` | projected verbatim from an official Drupal source | it is evidence about Drupal, not a rule |
| `reviewed rule` | a reviewed implementation rule | yes, within its declared scope |
| `this project only` | observed in one project | no |
| `finding` | a rule plus this project's evidence | act on it for this project |
| `one project context` | a solved case, proven in its own context | no, not universally |
| `UNTRUSTED signal` | an uncorroborated community observation | no |

Exactly one of those is trusted knowledge. The distinction is the product: an
advisory is authoritative about Drupal without being a Drupal Knowledge rule,
and a case solved on one site is not a universal requirement.

Two phrases you will not find anywhere in the output are "secure" and "passed".
`not_observed` means the search did not find it within a bounded scope, and a
bounded scan finding nothing is not a clean bill of health.

## JSON Automation

The five query commands take `--json` and print one object, with no banner, no
progress text and no formatting characters:

```bash
dk status  --json
dk search  file_create_url --json
dk project /path/to/project --target 10.6.13 --json
dk explain SA-CORE-2025-004 --json
dk provenance api-lifecycle.3f79df0f90cc1c83 --json
```

The analysis engines predate this interface and keep their own: several of them
(`analyze`, `security-evaluate`, `resolve`, `lifecycle-evaluate`, `findings`)
emit JSON natively, and the rest take `--json` or `--format json`. Check
`dk <command> --help` — none of it changed for this release.

The envelope is the same shape for every query, and is validated against
`schema/query-result.schema.json`:

```json
{
  "query_interface_version": "0.1",
  "result_contract_version": "0.1",
  "query_type": "search",
  "dataset": { "drupal_knowledge_version": "...", "records_digest": "..." },
  "result_count": 1,
  "results": [ { "domain": "...", "id": "...", "trust": { "class": "...", "trusted_knowledge": false }, "provenance": [ ... ] } ],
  "warnings": [],
  "unknowns": []
}
```

`dk version` is the machine interface for the contracts themselves and prints
JSON by default; `dk version --human` prints the short summary.

Trust travels with the data. `results[].trust.trusted_knowledge` is a boolean,
so an integration cannot accidentally treat a discovery signal as knowledge, and
`unknowns` is never empty for the sake of looking tidy.

Errors are actionable rather than tracebacks, and they go to stderr:

```console
$ dk explain SA-CORE-9999-999
ERROR: no Drupal Knowledge record has the identifier 'SA-CORE-9999-999'.
Try `dk search` to find it.
$ echo $?
2
```

## What Leaves Your Machine

Nothing. Queries are offline, and output is scrubbed before it exists:

- absolute paths never appear — not in evidence, and not even in the echo of
  the path you typed, which is reduced to a fingerprint like
  `project:1fbfda6d9c605a66`
- secrets, hashes, tokens and credentials are refused before a record is built
- reviewer identities and local environment detail unrelated to the query are
  not included

One thing is deliberately not hidden: the project's own declared Composer
package name, because that is what the project calls itself and it is what makes
the report legible. Everything that would identify the *machine* is gone, which
is what makes `dk project ... --json` safe to paste into an issue.

## Maintainer Operations

The commands below are a different job. They acquire sources, review candidates
and move records across trust boundaries, and none of them runs unless you name
it explicitly:

```text
dk acquire        dk discover        dk signals          dk signal-review
dk corroborate    dk corroboration   dk recurrence       dk generalizations
dk generalization-review             dk review-candidates
dk release-lifecycle                 dk solved-case
dk source-status
```

```bash
dk --help-maintainer     # this list, with descriptions
dk --help-internal       # repository maintenance
dk --help-all            # every command
```

There is no flag anywhere in the community surface that promotes a source
snapshot, a discovery signal or a project observation into trusted knowledge.
That is a review decision made by editing this repository, and the CLI is not a
way around it.
