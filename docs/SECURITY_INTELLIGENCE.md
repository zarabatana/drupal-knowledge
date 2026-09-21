# Security Advisory Intelligence

`scripts/dk_security.py` turns authoritative Drupal Security Team advisories
into canonical records, and evaluates them against a project's analyzer facts.

What it refuses to do is the point of it.

## The invariants

```text
authoritative advisory record  !=  general trusted Drupal knowledge rule
severity                       !=  enforcement
unknown                        !=  not applicable
```

Every canonical path takes the digest of `knowledge/records/` before and after
the work and refuses to continue if it moved.

## Nothing is invented

| Dimension | Behaviour |
| --- | --- |
| severity | the published risk vector, verbatim, or `not_established` |
| severity score | never computed — Drupal publishes a vector, not a CVSS number |
| severity label | never read out of the advisory title |
| CVE | preserved when assigned, `none_published` when not |
| affected versions | the advisory's own expression, parsed; `absent`/`unparseable` otherwise |
| remediation | the advisory's own solution and fixed releases only |
| exploitability | not modelled at all |

The advisory title for SA-CORE-2026-012 contains the words "Moderately
critical". The record does not, because reading a severity label out of prose is
inference. `field_sa_criticality` is preserved exactly as
`AC:Basic/A:User/CI:Some/II:Some/E:Theoretical/TD:Default`, and
`scored_by_drupal_knowledge` is pinned false.

## Authoritative source contract

Advisories come from the Drupal.org structured node API, which is the machine
form of the same advisories the human SA listings present:

| Field | Meaning |
| --- | --- |
| `url` | canonical advisory path; the published identifier and core/contrib kind |
| `field_sa_advisory_id` | advisory number |
| `field_sa_type` | vulnerability type |
| `field_sa_criticality` | published risk vector |
| `field_affected_versions` | affected-version expression |
| `field_sa_cve` | assigned CVEs |
| `field_project` | reference to the authoritative project node |
| `field_fixed_in` | references to the authoritative release nodes |
| `field_sa_solution` | published remediation |
| `field_is_psa` | public service announcement flag |

Registered feeds: `drupal-security-advisories-core` (filtered to the Drupal core
project node) and `drupal-security-advisories-recent`. Both are acquired by the
v0.9 acquisition engine, so they are snapshotted, hashed and change-detected
like any other authoritative source.

Blogs, Reddit, Stack Exchange, GitHub comments and maintainer speculation are
not advisory authority and are not consulted here.

## Ingestion cannot outrun review

```text
registered feed
  -> acquisition: fetch, normalize, hash, immutable snapshot
  -> change detection -> review candidate
  -> ingest, from the accepted snapshot only
  -> advisory record, pinning that snapshot
```

`dk.py security-advisories ingest` reads the snapshot acquisition accepted. It
never fetches the feed itself, so a feed that has moved produces an acquisition
review candidate first. A source with no accepted snapshot yields
`source_not_acquired` rather than a live read.

When an advisory is corrected, the record is rewritten against the new snapshot
and the superseded snapshot stays addressable. Advisory history is never
rewritten in place.

### Source-derived records are a distinct category

`record_class: source_derived_authoritative_record` is what makes this safe. An
advisory record is authoritative security *evidence*, faithfully projected from
reviewed source data and pinned to it. It is not a claim Drupal Knowledge
authored, and it is not a reusable behavioural rule, so it lives in
`security/advisories/` and never in `knowledge/records/`.

## Affected-version semantics

The grammar is the advisory's own, not an approximation:

```text
expression := clause ( "||" clause )*
clause     := constraint ( " " constraint )*        -- space means AND
constraint := ( ">=" | "<=" | ">" | "<" )? version
            | branch ".*"
            | "*"
```

Operators appear attached (`<11.3.14`) and detached (`< 11.3.14`); both parse.

```text
<10.6.13 || >=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.0.* || 11.1.* || 11.2.*
```

Upper bounds are exclusive, so the fixed release is the first version that is
not affected. Branch wildcards constrain the branch, not the patch level.

### A range that spans majors covers the majors inside it

`>= 8.0.0 < 10.3.13` affects Drupal 8, **9** and 10. Reading the majors written
in the expression as a set would silently declare a Drupal 9 site out of scope
for an advisory that affects it, which is a false negative on security. Major
coverage is therefore computed per clause as an interval.

`version_out_of_scope` is reserved for the case where no clause could cover the
installed major at all — an expression of `11.0.* || 11.1.*` genuinely says
nothing about Drupal 9.

### Drupal's legacy contrib format

`8.x-1.2` is compared as `1.2.0`, following Drupal.org's published semantic
equivalent, and the normalization is recorded in `version_normalization` so a
reviewer can see it happened. Pre-release suffixes are recorded rather than
ranked.

### What cannot be read stays unknown

An absent, empty or unparseable expression yields `unknown`. An installed
version in a format the engine does not read yields `unknown`. Neither becomes
an assumption of safety.

## Project identity is explicit

Core is identified by its own project node id. Every other advisory is resolved
by fetching the authoritative project node it references, giving
`field_project_machine_name` and the project type. The Composer package is
`drupal/<machine_name>`, which is Drupal.org's documented Packagist convention.

Contrib matching is exact package-name equality against
`composer_packages.value.installed.drupal_packages`. Nothing is matched on name
similarity: an unresolvable project reference stays `unresolved` and its
applicability stays `unknown`, even when a package with a plausibly matching
name is installed.

## Core and contrib stay distinct

| Advisory kind | Matched against |
| --- | --- |
| `core` | the installed Drupal core version fact |
| `contrib` | the explicitly identified installed package and its version |
| `psa` | nothing — a PSA carries no affected-version scope |

## Facts come from the Project Analyzer

Security applicability consumes `profile.facts`:

- `drupal_core_version` — state, version, package
- `composer_packages` — installed Drupal packages and versions

There is no second scanner. The engine reads no `composer.lock`, no
`core.extension.yml` and no project tree, and it never re-runs the analyzer.

## Applicability states

| State | Meaning |
| --- | --- |
| `applicable` | the installed version satisfies an affected clause |
| `not_applicable` | it satisfies none, or the project does not carry the package |
| `unknown` | identity unresolved, version unobserved, or expression unreadable |
| `insufficient_project_evidence` | the analyzer observed no definitive core version or package set |
| `version_out_of_scope` | no clause covers the installed major at all |

## Findings

A **confirmed** finding requires all three:

```text
authoritative advisory
+ definitive project identity   (resolved)
+ definitive installed version  (known)
+ affected-version match
```

Anything less is `candidate` or `unknown`. Finding identity is deterministic
over advisory, scope, package, installed version and project, so re-evaluating
unchanged evidence produces the same ids.

## Severity is not enforcement

Every advisory record and every finding carries:

```json
"enforcement": {
  "intent": "guidance",
  "policy_controlled": true,
  "automatically_blocking": false
}
```

An advisory may carry an authoritative risk vector and a real CVE and still not
block anything. Blocking requires a reviewed policy that does not exist yet, and
the evaluation says so with
`blocking_requires_reviewed_policy: true`.

## Remediation is authoritative only

Findings carry the advisory's own fixed versions and solution presence.
`authored_by_drupal_knowledge` and `executed` are pinned false. Nothing here
runs Composer, and there is deliberately no remediation command.

## CLI

```text
dk.py security-advisories ingest --source <id> [--dry-run]
dk.py security-advisories list [--kind core|contrib|psa] [--project NAME] [--json]
dk.py security-advisories show <advisory-id>
dk.py security-evaluate <analysis.json> [--advisory ID] [--explain] [--only-relevant]
```

`security-evaluate` is read-only: it reads analyzer output and advisory records
and writes nothing to the project.

The security tests run in the `engines` job of `.github/workflows/community.yml`,
a required gate on every push and pull request.
