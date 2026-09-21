# Drupal Project Analyzer

The Drupal Project Analyzer is a read-only static file inspector. It turns
repository files into observed project evidence and project profile facts.

It stops before Drupal Knowledge resolution. It does not decide which knowledge
records apply, does not emit findings, and does not remediate projects.

## Flow

```text
Drupal project files
  -> observed evidence with provenance
  -> project profile facts
  -> future Drupal Knowledge resolver
```

This preserves the repository authority boundary:

```text
SOURCE
!= TRUSTED_KNOWLEDGE
!= PROJECT_FACT
!= OBSERVED_PROJECT_EVIDENCE
!= SOLVED_CASE
!= DISCOVERY_SIGNAL
```

## CLI

```bash
python3 scripts/dk.py analyze <project-path>
python3 scripts/dk.py analyze <project-path> --config-dir config/sync
```

The default output is deterministic JSON on stdout. Diagnostics are also present
in the JSON output. Invalid CLI inputs, such as a missing project path or a
`--config-dir` outside the project root, exit with code 2.

Normal unknowns are not fatal. Malformed trusted input files, such as invalid
`composer.json`, invalid `composer.lock`, or malformed `core.extension.yml`,
return partial JSON and exit with code 1.

## Read-Only Guarantee

The analyzer reads files only. It does not create cache files, write reports into
the analyzed project, change lock files, run Composer, bootstrap Drupal, invoke
Drush, start containers, execute PHP, or run project scripts.

Project analysis is offline. It does not call Packagist, Drupal.org, source
collectors, or any network service.

## Supported Evidence

`composer.json`
: Root package declaration, package type, `require`, `require-dev`, PHP
  requirement, Composer `config.platform.php`, Drupal-related declared
  dependencies, and Drupal scaffold web-root metadata when explicitly declared.

`composer.lock`
: Installed package evidence from `packages` and `packages-dev`: package name,
  version, Composer type, and dev/non-dev origin.

`core.extension.yml`
: Exported Drupal configuration evidence for enabled module names, enabled theme
  names, and installation profile. Weights are preserved only as parse input;
  they are not versions.

Custom `.info.yml`
: Bounded inventory of conventional custom module, theme, and profile
  definitions under custom roots. Existing custom code is not treated as enabled
  unless exported configuration also says it is enabled.

Drupal core filesystem marker
: A `core/lib/Drupal.php` marker can corroborate web-root detection. The PHP file
  is read as bytes only and is not executed.

## Facts And Evidence

Every file used for facts has portable evidence provenance:

```json
{
  "path": "composer.lock",
  "content_sha256": "sha256:...",
  "bytes": 123456,
  "role": "composer-lock"
}
```

Evidence paths are relative to the analyzed project root. The deterministic JSON
does not include machine-specific absolute project paths.

## Important Separations

A declared dependency is not an installed dependency.

An installed Composer package is not an enabled Drupal extension.

An enabled extension in exported configuration is not proof that runtime
configuration is imported or synchronized.

An enabled extension is not proof of correct configuration.

Repository metadata is not runtime state.

## Config Discovery

`--config-dir` wins when supplied and must point inside the project root.

Without `--config-dir`, the analyzer performs a bounded search for plausible
`core.extension.yml` roots. It excludes heavy or irrelevant trees such as
`vendor`, `node_modules`, `.git`, Drupal `core`, and test fixtures inside the
analyzed project.

If exactly one credible config root exists, it is selected. If none exists,
enabled extension facts remain unknown. If multiple roots exist, the analyzer
reports an ambiguous config root and does not guess.

## YAML Safety

The analyzer uses an in-repository safe YAML subset parser for Drupal exported
config and `.info.yml` metadata. It supports the scalar, mapping, and sequence
forms needed by the inspected files and rejects unsupported syntax with a
diagnostic. It does not load Python objects or execute YAML constructors.

PyYAML is not introduced in this first version so CI and analysis remain
dependency-light and offline.

The supported grammar is intentionally narrow: indentation-based mappings,
nested mappings, block sequences, quoted and plain scalar strings, booleans,
nulls, integers, comments outside quoted strings, empty `{}` mappings, and empty
`[]` sequences. Duplicate mapping keys, anchors, aliases, tags, complex keys,
block scalars, inline sequence mappings, and non-empty flow collections are
rejected. Rejected config does not author enabled-extension facts; those facts
remain unknown with an explicit diagnostic.

## Unknowns

Unknown means unobserved, not false.

Typical unknowns in this first analyzer include runtime PHP version, database
engine/version, current imported configuration, cache backend, live site URL,
runtime environment, and enabled extensions when no unambiguous exported config
is available.

## Privacy

The analyzer does not scan `.env` files, private keys, settings files, or
arbitrary project content for secrets. It extracts only bounded Composer,
Drupal config, custom extension metadata, and web-root marker evidence needed
for project facts.

## Current Limitations

- Analyzer output is consumed by the separate applicability resolver.
- No vulnerability, compliance, or remediation verdicts.
- No advisory matching.
- No Composer package-to-extension ownership mapping.
- No runtime inspection.
- No consumer-specific integration.
