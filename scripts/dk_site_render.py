#!/usr/bin/env python3
"""Turning the public dataset into pages, and being unable to do anything else.

This module has one input: the dataset produced by ``dk_public``. It does not
import the query layer, does not read ``knowledge/``, ``security/`` or any other
canonical store, and does not know where the repository is. That is deliberate
and it is tested: a renderer that can reach canonical records is a renderer that
can quietly disagree with the CLI, and the whole point of Prompt 14's split was
to make that impossible rather than merely discouraged.

So everything here is layout. Which heading, which order, which words around a
value that was already decided. The one editorial judgement it makes is that the
trust label goes next to the title rather than in a footnote, and that what a
record does not know is a section rather than a caveat.

Pages are plain HTML. Search is the only interactive part, it uses the exported
index and the exported ranking bands, and every other page is readable with
JavaScript switched off.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Iterable


BUILD_SCHEMA_VERSION = "0.1"
SITE_NAME = "Drupal Knowledge"
REPOSITORY_URL = "https://github.com/zarabatana/drupal-knowledge"
# Who publishes this, and whose mark "Drupal" is. Both are rendered on every
# page; the independence statement in full lives on the About page.
COMMUNITY_LABEL = "Drupal Knowledge Community, maintained by Zarabatana"
TRADEMARK_NOTICE = (
    "Drupal is a registered trademark of Dries Buytaert; this independent "
    "project is not affiliated with or endorsed by the Drupal Association or Dries Buytaert."
)

# Navigation is community-oriented on purpose: nothing here is a maintenance
# operation, and acquisition and review have no entry.
NAV = (
    ("/knowledge/", "Knowledge"),
    ("/security/", "Security"),
    ("/api/", "API Changes"),
    ("/change-records/", "Change Records"),
    ("/rules/", "Rules"),
    ("/solved-cases/", "Solved Cases"),
    ("/sources/", "Sources"),
    ("/trust-model/", "Trust Model"),
    ("/cli/", "CLI"),
    ("/api-docs/", "API"),
    ("/search/", "Search"),
)

# The badge text a reader sees. Words, never colour alone: a trust distinction
# that only exists as a hue is not a distinction for everybody.
TRUST_BADGE = {
    "reviewed_drupal_knowledge": "Reviewed Drupal Knowledge",
    "source_derived_authoritative": "Authoritative Drupal Source Record",
    "reviewed_implementation_rule": "Reviewed Implementation Rule",
    "project_observation": "Project Observation",
    "derived_finding": "Finding",
    "proven_case_context_only": "Internal Proven Solved Case",
    "untrusted_discovery_signal": "Untrusted Discovery Signal",
}

RELATION_LABEL = {
    "derived_from_source": "Derived from source",
    "same_drupal_project": "Same Drupal project",
    "names_this_symbol": "Change record names this symbol",
    "described_by_change_record": "Described by change record",
}

# Detail keys rendered with a friendlier name. Anything not listed is shown
# under its own key rather than dropped, so a new field appears rather than
# disappearing until someone remembers to add it here.
FIELD_LABEL = {
    "affected_versions": "Affected versions",
    "affected_versions_state": "Affected-version expression state",
    "fixed_in_state": "Fixed-version state",
    "remediation_state": "Published remediation",
    "remediation_authored_by_drupal_knowledge": "Remediation authored by Drupal Knowledge",
    "composer_package": "Composer package",
    "core_file": "Drupal core file",
    "cve_state": "CVE state",
    "cves": "CVEs",
    "deprecated_version": "Deprecated in",
    "fixed_in": "Fixed in",
    "introduced_branch": "Introduced branch",
    "introduced_version": "Introduced in",
    "kind": "Kind",
    "published_at": "Published",
    "qualified_name": "Fully qualified name",
    "removed_version": "Removed from",
    "replacement": "Replacement",
    "replacement_state": "Replacement state",
    "risk_vector": "Risk vector",
    "risk_vector_state": "Risk vector state",
    "scored_by_drupal_knowledge": "Scored by Drupal Knowledge",
    "symbol": "Symbol",
    "symbols": "Symbols",
    "root_cause": "Root cause",
    "root_cause_state": "Root cause state",
    "claimed_scope": "Claimed scope",
    "occurrence_count": "Projects it has been proven on",
    "expansion_requires_review": "Widening it requires review",
    "project_identity_disclosed": "Project identity disclosed",
    "vulnerability_type": "Vulnerability type",
}


class SiteRenderDefect(RuntimeError):
    """The dataset asked for a page that cannot be rendered honestly."""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def label_for(key: str) -> str:
    return FIELD_LABEL.get(key, key.replace("_", " ").capitalize())


def badge(trust_class: str) -> str:
    text = TRUST_BADGE.get(trust_class)
    if text is None:
        raise SiteRenderDefect(f"no public badge for trust class {trust_class!r}")
    return (
        f'<span class="badge badge--{esc(trust_class)}">{esc(text)}</span>'
    )


# --- page shell ---------------------------------------------------------------


def page(
    *,
    route: str,
    title: str,
    description: str,
    body: str,
    manifest: dict,
    built_at: str,
    noindex: bool = False,
) -> str:
    """One complete document. Semantic landmarks, one h1, skip link, no frameworks."""
    robots = '\n  <meta name="robots" content="noindex">' if noindex else ""
    nav_items = "\n".join(
        '      <li><a href="{href}"{current}>{label}</a></li>'.format(
            href=esc(href),
            label=esc(label),
            current=' aria-current="page"' if route.startswith(href) and href != "/" else "",
        )
        for href, label in NAV
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">{robots}
  <title>{esc(title)} — {esc(SITE_NAME)}</title>
  <meta name="description" content="{esc(description)}">
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header class="site-header">
    <a class="brand" href="/">{esc(SITE_NAME)}</a>
    <nav aria-label="Primary">
      <ul>
{nav_items}
      </ul>
    </nav>
  </header>
  <main id="main">
{body}
  </main>
  <footer class="site-footer">
    <p>
      Generated from Drupal Knowledge {esc(manifest['dk_version'])},
      dataset <code>{esc(manifest['dataset_id'])}</code>,
      built {esc(built_at)}.
    </p>
    <p>
      Published pages are generated artifacts. Canonical knowledge and editorial
      content are maintained and reviewed in the repository; querying changes nothing.
      <a href="{esc(REPOSITORY_URL)}">Repository</a> ·
      <a href="/about/">About</a> ·
      <a href="/trust-model/">Trust model</a>
    </p>
    <p>
      {esc(COMMUNITY_LABEL)}. {esc(TRADEMARK_NOTICE)}
    </p>
  </footer>
</body>
</html>
"""


def breadcrumb(trail: Iterable[tuple[str, str]]) -> str:
    items = "\n".join(
        f'      <li><a href="{esc(href)}">{esc(label)}</a></li>' for href, label in trail
    )
    return f"""    <nav class="breadcrumb" aria-label="Breadcrumb">
      <ol>
{items}
      </ol>
    </nav>
"""


# --- record rendering ---------------------------------------------------------


def value_html(value: object) -> str:
    if isinstance(value, bool):
        return esc("yes" if value else "no")
    if isinstance(value, list):
        if not value:
            return '<span class="empty">none stated</span>'
        return ", ".join(f"<code>{esc(entry)}</code>" for entry in value)
    if isinstance(value, dict):
        return ", ".join(f"{esc(key)}: {esc(val)}" for key, val in sorted(value.items()))
    if value is None or value == "":
        return '<span class="empty">not stated by the source</span>'
    return f"<code>{esc(value)}</code>"


def detail_table(detail: dict, sourced: bool = True) -> str:
    """The record's own fields. What "blank" means depends on who wrote them."""
    if not detail:
        return ""
    caption = (
        "Values as published by the source. Blank means the source did not say."
        if sourced
        else "Values as recorded. Blank means the record did not state one."
    )
    rows = "\n".join(
        f"        <tr><th scope=\"row\">{esc(label_for(key))}</th>"
        f"<td>{value_html(value)}</td></tr>"
        for key, value in sorted(detail.items())
    )
    return f"""    <section aria-labelledby="detail-heading">
      <h2 id="detail-heading">What the record states</h2>
      <div class="table-scroll">
      <table>
        <caption>{caption}</caption>
        <tbody>
{rows}
        </tbody>
      </table>
      </div>
    </section>
"""


def explanation_block(explanation: dict | None) -> str:
    if not explanation:
        return ""
    unknowns = "\n".join(
        f"        <li>{esc(entry)}</li>" for entry in explanation["what_is_unknown"]
    )
    return f"""    <section aria-labelledby="explain-heading">
      <h2 id="explain-heading">What this is</h2>
      <dl class="explain">
        <dt>What is this</dt><dd>{esc(explanation['what_is_this'])}</dd>
        <dt>Why it exists</dt><dd>{esc(explanation['why_does_it_exist'])}</dd>
        <dt>What makes it authoritative</dt><dd>{esc(explanation['what_is_authoritative'])}</dd>
        <dt>Project scope</dt><dd>{esc(explanation['what_is_project_specific'])}</dd>
        <dt>Recommended next step</dt><dd>{esc(explanation['what_is_recommended'])}</dd>
        <dt>Was anything changed</dt><dd>{esc(explanation['was_anything_changed'])}</dd>
      </dl>
      <h3>What is not known</h3>
      <ul class="unknowns">
{unknowns}
      </ul>
    </section>
"""


def provenance_block(steps: list[dict], source_routes: dict[str, str]) -> str:
    if not steps:
        return """    <section aria-labelledby="prov-heading">
      <h2 id="prov-heading">Provenance</h2>
      <p>This record declares no upstream authority to traverse.</p>
    </section>
"""
    items = []
    for step in steps:
        parts = [f"<strong>{esc(step.get('channel', 'unknown channel'))}</strong>"]
        source_id = step.get("source_id")
        if source_id:
            route = source_routes.get(source_id)
            if route:
                parts.append(f'<a href="{esc(route)}">{esc(source_id)}</a>')
            else:
                parts.append(f"<code>{esc(source_id)}</code>")
        if step.get("case_id"):
            parts.append(f"<code>{esc(step['case_id'])}</code>")
        if step.get("locator"):
            parts.append(f"<span class=\"locator\">{esc(step['locator'])}</span>")
        line = " · ".join(parts)
        extra = ""
        if step.get("source_url"):
            url = step["source_url"]
            extra += f'<br><a class="canonical" href="{esc(url)}">{esc(url)}</a>'
        if step.get("snapshot_sha256"):
            extra += (
                '<br><span class="digest">snapshot '
                f"<code>{esc(step['snapshot_sha256'])}</code></span>"
            )
        items.append(f"        <li>{line}{extra}</li>")
    joined = "\n".join(items)
    intro = (
        "The snapshot digest identifies the exact bytes this record was derived "
        "from, so the claim can be checked rather than believed."
        if any(step.get("snapshot_sha256") for step in steps)
        else "This record's authority is internal to Drupal Knowledge; no external "
        "source snapshot stands behind it."
    )
    return f"""    <section aria-labelledby="prov-heading">
      <h2 id="prov-heading">Provenance</h2>
      <p>{esc(intro)}</p>
      <ul class="provenance">
{joined}
      </ul>
    </section>
"""


def related_block(related: list[dict]) -> str:
    if not related:
        return ""
    grouped: dict[str, list[dict]] = {}
    for entry in related:
        grouped.setdefault(entry["relation"], []).append(entry)
    blocks = []
    for relation, entries in sorted(grouped.items()):
        links = "\n".join(
            f'        <li><a href="{esc(entry["route"])}">{esc(entry["label"])}</a></li>'
            for entry in entries
        )
        blocks.append(
            f"      <h3>{esc(RELATION_LABEL.get(relation, relation))}</h3>\n"
            f"      <ul class=\"related\">\n{links}\n      </ul>"
        )
    joined = "\n".join(blocks)
    return f"""    <section aria-labelledby="related-heading">
      <h2 id="related-heading">Related records</h2>
      <p>Only relationships the canonical records already declare. Nothing here is inferred.</p>
{joined}
    </section>
"""


def record_page(
    record: dict, domain_block: dict, manifest: dict, source_routes: dict[str, str], built_at: str
) -> str:
    trust = record["trust"]
    summary = (
        f'    <p class="lede">{esc(record["summary"])}</p>\n' if record["summary"] else ""
    )
    body = (
        breadcrumb([("/", "Home"), (domain_block["route"], domain_block["label"])])
        + f"""    <article>
    <h1>{esc(record['title'])}</h1>
    <p class="trust">{badge(trust['class'])} <span class="trust-type">{esc(trust['record_type'])}</span></p>
    <p class="trust-note">{esc(trust['explanation'])}</p>
{summary}    <p class="record-id">Record <code>{esc(record['id'])}</code></p>
"""
        + explanation_block(record.get("explanation"))
        + detail_table(
            record["detail"],
            sourced=trust["class"] == "source_derived_authoritative",
        )
        + provenance_block(record["provenance"], source_routes)
        + related_block(record.get("related", []))
        + "    </article>\n"
    )
    return page(
        route=record["route"],
        title=record["title"],
        description=record["summary"] or trust["record_type"],
        body=body,
        manifest=manifest,
        built_at=built_at,
    )


def index_page(domain_block: dict, manifest: dict, built_at: str) -> str:
    rows = "\n".join(
        f'        <li><a href="{esc(record["route"])}">{esc(record["title"])}</a>'
        f'<span class="row-summary">{esc(record["summary"])}</span></li>'
        for record in domain_block["records"]
    )
    listing = (
        f'      <ul class="record-list">\n{rows}\n      </ul>'
        if domain_block["records"]
        else "      <p>No records in this domain in this release.</p>"
    )
    body = (
        breadcrumb([("/", "Home")])
        + f"""    <h1>{esc(domain_block['label'])}</h1>
    <p class="trust">{badge(domain_block['trust_class'])}</p>
    <p class="lede">
      {esc(domain_block['record_count'])} record(s) in Drupal Knowledge
      {esc(manifest['dk_version'])}. Every entry below carries the same trust class.
    </p>
{listing}
"""
    )
    return page(
        route=domain_block["route"],
        title=domain_block["label"],
        description=f"{domain_block['record_count']} {domain_block['label']} records in Drupal Knowledge.",
        body=body,
        manifest=manifest,
        built_at=built_at,
    )


# --- sources ------------------------------------------------------------------


def freshness_of(source: dict, today_ordinal: int, parse_day) -> dict:
    """Whether a source is past its own declared cadence, stated without alarm."""
    if not source["baselined"] or not source["last_observed_at"]:
        return {"state": "never acquired", "age_days": None, "stale": False}
    day = parse_day(source["last_observed_at"])
    if day is None:
        return {"state": "observed", "age_days": None, "stale": False}
    age = today_ordinal - day
    cadence = source.get("check_cadence_days")
    stale = bool(cadence and age > cadence)
    return {
        "state": "past its check cadence" if stale else "within its check cadence",
        "age_days": age,
        "stale": stale,
    }


def source_page(source: dict, manifest: dict, freshness: dict, built_at: str) -> str:
    age = (
        f"{freshness['age_days']} day(s) ago"
        if freshness["age_days"] is not None
        else "not recorded"
    )
    body = (
        breadcrumb([("/", "Home"), ("/sources/", "Sources")])
        + f"""    <article>
    <h1>{esc(source['title'])}</h1>
    <p class="trust"><span class="badge badge--source">Registered {esc(source['trust'])} source</span></p>
    <p class="lede">{esc(source.get('role') or 'A registered Drupal Knowledge source.')}</p>
    <div class="table-scroll">
    <table>
      <caption>Registered source metadata. No credentials, local paths or collection environment detail is published.</caption>
      <tbody>
        <tr><th scope="row">Source id</th><td><code>{esc(source['id'])}</code></td></tr>
        <tr><th scope="row">Canonical URL</th><td><a href="{esc(source['url'])}">{esc(source['url'])}</a></td></tr>
        <tr><th scope="row">Trust tier</th><td>{esc(source['trust'])}</td></tr>
        <tr><th scope="row">Category</th><td>{esc(source.get('category') or 'not stated')}</td></tr>
        <tr><th scope="row">Lifecycle</th><td>{esc(source.get('lifecycle') or 'not stated')}</td></tr>
        <tr><th scope="row">Check cadence</th><td>{esc(source.get('check_cadence_days') or 'not declared')} day(s)</td></tr>
        <tr><th scope="row">Last successfully observed</th><td>{esc(source['last_observed_at'] or 'never')} ({esc(age)})</td></tr>
        <tr><th scope="row">Current source state</th><td>{esc(freshness['state'])}</td></tr>
        <tr><th scope="row">Snapshot digest</th><td>{value_html(source['snapshot_sha256'])}</td></tr>
      </tbody>
    </table>
    </div>
    <section aria-labelledby="stale-heading">
      <h2 id="stale-heading">What the freshness state means</h2>
      <p>
        Freshness says when this source was last read, and nothing more. A source
        past its check cadence is one nobody has looked at recently. It is not a
        source known to be wrong, and the records derived from it are unchanged.
      </p>
    </section>
    </article>
"""
    )
    return page(
        route=source["route"],
        title=source["title"],
        description=f"Registered {source['trust']} Drupal Knowledge source.",
        body=body,
        manifest=manifest,
        built_at=built_at,
    )


def sources_index(sources: list[dict], manifest: dict, freshness_by_id: dict, built_at: str) -> str:
    rows = "\n".join(
        f"""        <tr>
          <td><a href="{esc(source['route'])}">{esc(source['title'])}</a></td>
          <td>{esc(source['trust'])}</td>
          <td>{esc(source.get('category') or '—')}</td>
          <td>{esc(source['last_observed_at'] or 'never')}</td>
          <td>{esc(freshness_by_id[source['id']]['state'])}</td>
        </tr>"""
        for source in sources
    )
    stale_count = sum(1 for entry in freshness_by_id.values() if entry["stale"])
    body = (
        breadcrumb([("/", "Home")])
        + f"""    <h1>Sources</h1>
    <p class="lede">
      Every record on this site is derived from one of these {esc(len(sources))} registered
      sources. {esc(stale_count)} of them are currently past their declared check cadence.
    </p>
    <div class="table-scroll">
    <table>
      <caption>Registered Drupal Knowledge sources and when each was last observed.</caption>
      <thead>
        <tr><th scope="col">Source</th><th scope="col">Trust</th><th scope="col">Category</th>
        <th scope="col">Last observed</th><th scope="col">State</th></tr>
      </thead>
      <tbody>
{rows}
      </tbody>
    </table>
    </div>
"""
    )
    return page(
        route="/sources/",
        title="Sources",
        description="The registered authoritative sources behind Drupal Knowledge.",
        body=body,
        manifest=manifest,
        built_at=built_at,
    )


# --- home and editorial -------------------------------------------------------


def home_page(manifest: dict, content: str, built_at: str) -> str:
    cards = "\n".join(
        f"""      <li>
        <a href="{esc(block['route'])}"><h3>{esc(block['label'])}</h3></a>
        <p class="count">{esc(block['record_count'])} record(s)</p>
        <p>{esc(TRUST_BADGE[block['trust_class']])}</p>
      </li>"""
        for block in manifest["domains"]
    )
    body = f"""    <h1>Drupal Knowledge</h1>
{content}
    <section aria-labelledby="holds-heading">
      <h2 id="holds-heading">What this release holds</h2>
      <ul class="cards">
{cards}
      </ul>
    </section>
"""
    return page(
        route="/",
        title="Authoritative Drupal knowledge you can trace",
        description=(
            "Browse reviewed Drupal knowledge, security advisories, API deprecations "
            "and change records, each labelled with how far it can be trusted."
        ),
        body=body,
        manifest=manifest,
        built_at=built_at,
    )


def editorial_page(route: str, title: str, description: str, content: str, manifest: dict, built_at: str) -> str:
    return page(
        route=route,
        title=title,
        description=description,
        body=f"    <article>\n{content}\n    </article>\n",
        manifest=manifest,
        built_at=built_at,
    )


def trust_model_page(manifest: dict, content: str, built_at: str) -> str:
    rows = "\n".join(
        f"""        <tr>
          <th scope="row">{esc(TRUST_BADGE.get(name, name))}</th>
          <td>{esc(block['record_type'])}</td>
          <td>{esc('yes' if block['trusted_knowledge'] else 'no')}</td>
          <td>{esc(block['explanation'])}</td>
        </tr>"""
        for name, block in sorted(manifest["trust_classes"].items())
    )
    excluded = "\n".join(
        f"        <li><strong>{esc(entry['domain'])}</strong> — {esc(entry['reason'])}</li>"
        for entry in manifest["excluded_domains"]
    )
    body = f"""    <article>
    <h1>Trust model</h1>
{content}
    <section aria-labelledby="classes-heading">
      <h2 id="classes-heading">The classes, and which one is trusted knowledge</h2>
      <div class="table-scroll">
      <table>
        <caption>Every record Drupal Knowledge can return carries exactly one of these.</caption>
        <thead>
          <tr><th scope="col">Label</th><th scope="col">Record type</th>
          <th scope="col">Trusted knowledge</th><th scope="col">What it means</th></tr>
        </thead>
        <tbody>
{rows}
        </tbody>
      </table>
      </div>
    </section>
    <section aria-labelledby="excluded-heading">
      <h2 id="excluded-heading">What this site deliberately does not publish</h2>
      <p>
        Drupal Knowledge holds more than it publishes. These domains are excluded
        by name so that a missing section reads as a decision rather than an oversight.
      </p>
      <ul class="excluded">
{excluded}
      </ul>
    </section>
    </article>
"""
    return page(
        route="/trust-model/",
        title="Trust model",
        description="How Drupal Knowledge separates reviewed knowledge from sources, evidence, findings and signals.",
        body=body,
        manifest=manifest,
        built_at=built_at,
    )


def cli_page(manifest: dict, content: str, commands: list[dict], built_at: str) -> str:
    rows = "\n".join(
        f'        <tr><th scope="row"><code>dk {esc(entry["command"])}</code></th>'
        f"<td>{esc(entry['help'])}</td></tr>"
        for entry in commands
    )
    body = f"""    <article>
    <h1>The command line</h1>
{content}
    <section aria-labelledby="commands-heading">
      <h2 id="commands-heading">Community commands in this release</h2>
      <p>
        Generated from the released command parser, so this list cannot drift from
        what the CLI actually accepts. Maintainer operations are not shown here.
      </p>
      <div class="table-scroll">
      <table>
        <caption>Community commands in Drupal Knowledge {esc(manifest['dk_version'])}.</caption>
        <tbody>
{rows}
        </tbody>
      </table>
      </div>
    </section>
    </article>
"""
    return page(
        route="/cli/",
        title="The command line",
        description="Install and use the read-only Drupal Knowledge CLI.",
        body=body,
        manifest=manifest,
        built_at=built_at,
    )


def search_page(manifest: dict, built_at: str) -> str:
    ranking = manifest["search_index"]
    body = f"""    <h1>Search</h1>
    <p class="lede">
      Matching is exact, never fuzzy and never semantic. An exact identifier always
      outranks a passing mention, and the same query always returns the same order.
    </p>
    <form class="search" role="search" action="/search/" method="get">
      <label for="q">Search Drupal Knowledge</label>
      <input type="search" id="q" name="q" autocomplete="off"
             placeholder="SA-CORE-2025-001, CVE-2025-3057, file_create_url, views">
      <button type="submit">Search</button>
    </form>
    <p id="search-status" role="status">
      Searching {esc(ranking['row_count'])} published records.
    </p>
    <ol id="search-results" class="record-list"></ol>
    <noscript>
      <p>
        Search needs JavaScript because the index is loaded in your browser and
        nothing is sent anywhere. Every other page on this site works without it —
        browse <a href="/knowledge/">Knowledge</a>, <a href="/security/">Security</a>
        or <a href="/api/">API Changes</a> directly.
      </p>
    </noscript>
    <script src="/assets/search.js" defer></script>
"""
    return page(
        route="/search/",
        title="Search",
        description="Search Drupal Knowledge advisories, APIs, rules and reviewed records.",
        body=body,
        manifest=manifest,
        built_at=built_at,
        noindex=True,
    )


def not_found_page(manifest: dict, built_at: str) -> str:
    body = """    <h1>No such page</h1>
    <p class="lede">
      That address does not correspond to a Drupal Knowledge record in this release.
    </p>
    <p>
      Records are addressed by their canonical identifier, so a link that worked
      before still works unless the record itself was withdrawn.
    </p>
    <ul>
      <li><a href="/search/">Search for it</a></li>
      <li><a href="/knowledge/">Browse reviewed knowledge</a></li>
      <li><a href="/security/">Browse security advisories</a></li>
      <li><a href="/">Start from the home page</a></li>
    </ul>
"""
    return page(
        route="/404/",
        title="No such page",
        description="The requested page does not exist in this release.",
        body=body,
        manifest=manifest,
        built_at=built_at,
        noindex=True,
    )


# --- the whole site -----------------------------------------------------------


def output_path(route: str) -> str:
    """A route becomes a directory index, so URLs need no file extension."""
    if route == "/":
        return "index.html"
    return route.strip("/") + "/index.html"


def render_site(
    dataset: dict,
    *,
    editorial: dict[str, str],
    assets: dict[str, str],
    commands: list[dict],
    built_at: str,
    today_ordinal: int,
    parse_day,
    commit: str | None = None,
) -> dict[str, str]:
    """Every file of the site, as a mapping of relative path to text.

    Nothing is written here. The caller decides where the site goes, which keeps
    this function testable without a filesystem and keeps the build honest about
    what it produced.
    """
    manifest = dataset["manifest.json"]
    sources = dataset["sources.json"]["sources"]
    source_routes = {entry["id"]: entry["route"] for entry in sources}
    freshness_by_id = {
        entry["id"]: freshness_of(entry, today_ordinal, parse_day) for entry in sources
    }

    files: dict[str, str] = {}
    files["index.html"] = home_page(manifest, editorial["home"], built_at)
    files[output_path("/trust-model/")] = trust_model_page(
        manifest, editorial["trust-model"], built_at
    )
    files[output_path("/cli/")] = cli_page(manifest, editorial["cli"], commands, built_at)
    files[output_path("/api-docs/")] = editorial_page(
        "/api-docs/",
        "The Public Knowledge API",
        "Read-only JSON access to Drupal Knowledge, with trust labels and provenance intact.",
        editorial["api-docs"],
        manifest,
        built_at,
    )
    files[output_path("/about/")] = editorial_page(
        "/about/",
        "About Drupal Knowledge",
        "What Drupal Knowledge is, what it refuses to claim, and how to get it.",
        editorial["about"],
        manifest,
        built_at,
    )
    files[output_path("/search/")] = search_page(manifest, built_at)
    files["404.html"] = not_found_page(manifest, built_at)

    for block_meta in manifest["domains"]:
        block = dataset[block_meta["file"]]
        files[output_path(block["route"])] = index_page(block, manifest, built_at)
        for record in block["records"]:
            files[output_path(record["route"])] = record_page(
                record, block, manifest, source_routes, built_at
            )

    files[output_path("/sources/")] = sources_index(sources, manifest, freshness_by_id, built_at)
    for source in sources:
        files[output_path(source["route"])] = source_page(
            source, manifest, freshness_by_id[source["id"]], built_at
        )

    for name, text in sorted(assets.items()):
        files[f"assets/{name}"] = text

    # The search index is the only dataset file the browser downloads, and it
    # holds only the fields a result list needs.
    files["search-index.json"] = json.dumps(
        dataset["search-index.json"], indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    files["robots.txt"] = (
        "# Reviewed and authoritative pages may be indexed. Search results and the\n"
        "# error page carry a noindex meta tag because they are not content.\n"
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /search/\n"
    )

    # Volatile build metadata, deliberately outside the dataset so the dataset's
    # identity does not change because a clock moved.
    files["build-info.json"] = json.dumps(
        {
            "build_schema_version": BUILD_SCHEMA_VERSION,
            "dk_version": manifest["dk_version"],
            "dataset_id": manifest["dataset_id"],
            "dataset_schema_version": manifest["dataset_schema_version"],
            "query_interface_version": manifest["query_interface_version"],
            "commit": commit,
            "built_at": built_at,
            "page_count": sum(1 for name in files if name.endswith(".html")),
            "record_counts": manifest["record_counts"],
            "public_domains": [block["domain"] for block in manifest["domains"]],
            "search_index_rows": manifest["search_index"]["row_count"],
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    return files
