# Security Policy

## Scope

This policy covers vulnerabilities in **Drupal Knowledge itself**: the CLI,
the engines, the website build, the public API server, the validation
tooling, and the way records are acquired, stored and rendered.

It does **not** cover vulnerabilities in Drupal core or contributed
projects. Those belong to the Drupal Security Team —
https://www.drupal.org/security-team — and must be reported to them, not
here. Drupal Knowledge only records what the Drupal Security Team publishes;
it cannot act on, and must not receive, a report about Drupal.

## How to report

Use **GitHub private vulnerability reporting** on this repository:

1. Open https://github.com/zarabatana/drupal-knowledge/security
2. Choose **Report a vulnerability**.
3. Describe what you observed, how to reproduce it, the commit or release
   you tested, and the impact you believe it has.

The report is visible only to you and the maintainers. Please **do not**
open a public issue, a pull request or a discussion for a security problem,
and do not describe one in a commit message.

No e-mail disclosure address is configured for this project. If the private
reporting form is ever unavailable, contact a maintainer privately through
their GitHub profile rather than posting publicly.

## What to expect

- An acknowledgement of your report.
- A decision — confirmed, declined, or more information needed — with the
  reasoning.
- For a confirmed report: a fix on the current `1.x` line, a `CHANGELOG.md`
  entry, and a GitHub security advisory published from the report, with
  credit to you unless you ask otherwise. Public discussion waits until the
  fix is released.

## What counts

Examples of in-scope reports:

- a way for a query, a website build or an API request to write to, or
  change the meaning of, a canonical record;
- a way for project analysis to execute project code, or to leak a secret or
  an absolute path into output;
- a way for acquisition to fetch an unregistered URL, or to present
  unavailable or malformed source content as unchanged;
- a way for the public API or the static site to serve content that is not
  in the published dataset;
- a third-party import or dangerous construct that passes the supply-chain
  scan.

## Supported versions

Security fixes are made on the current `1.x` release line.

## Security design

The trust model, the read-only guarantees and the reasons behind them are
documented in `docs/ARCHITECTURE.md`, `docs/PUBLIC_API.md`,
`docs/PUBLIC_SITE.md` and `docs/PROJECT_EVIDENCE.md`. The supply-chain
policy is standard library only, proven by
`scripts/test_supply_chain_security.py` and `release/sbom.json`.
