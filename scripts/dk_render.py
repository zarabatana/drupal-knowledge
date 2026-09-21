#!/usr/bin/env python3
"""Turning a query result into something readable, and changing nothing about it.

This module formats. It does not decide. Every judgement — what matched, how
trustworthy it is, what remains unknown — was made in ``dk_query`` and arrives
here already settled, because Prompt 15's website and Prompt 16's API will
render the same results differently and must reach the same conclusions.

The one editorial choice it does make is what to put first. A developer reading
a terminal sees the trust label beside every item, and sees the unknowns before
they stop reading, because a result list that buries "we could not tell" under
forty lines of detail is how a careful engine ends up misleading someone.
"""

from __future__ import annotations

from typing import Any

import dk_query as query


# How many items of a long list the terminal shows before summarizing. JSON
# output is never trimmed; truncation is a reading aid, not a filter.
SAMPLE = 12

TRUST_BADGE = {
    "reviewed_drupal_knowledge": "trusted knowledge",
    "source_derived_authoritative": "authoritative source",
    "reviewed_implementation_rule": "reviewed rule",
    "project_observation": "this project only",
    "derived_finding": "finding",
    "proven_case_context_only": "one project context",
    "untrusted_discovery_signal": "UNTRUSTED signal",
}


def badge(item: dict) -> str:
    return TRUST_BADGE.get(item["trust"]["class"], item["trust"]["class"])


def header(payload: dict) -> list[str]:
    dataset = payload["dataset"]
    return [
        f"Drupal Knowledge {dataset['drupal_knowledge_version']}  ·  "
        f"{payload['query_type']}  ·  {payload['result_count']} result(s)",
    ]


def trailer(payload: dict) -> list[str]:
    """Warnings and unknowns, always shown, never at the bottom of a long dump."""
    lines: list[str] = []
    if payload["warnings"]:
        lines.append("")
        lines.append("Warnings")
        for warning in payload["warnings"]:
            lines.append(f"  ! {warning}")
    if payload["unknowns"]:
        lines.append("")
        lines.append("What Drupal Knowledge does not know here")
        for unknown in payload["unknowns"]:
            lines.append(f"  ? {unknown}")
    return lines


def render_results(payload: dict, explain: bool = False) -> str:
    lines = header(payload)
    if not payload["results"]:
        lines.append("")
        lines.append("  No matching record.")
    else:
        lines.append("")
    for item in payload["results"][:SAMPLE]:
        lines.append(f"  {item['id']}")
        lines.append(f"    {item['title']}")
        lines.append(f"    [{badge(item)}]  {item['trust']['record_type']}")
        if item.get("match"):
            lines.append(f"    match: {item['match']['reason']}")
        if item["summary"]:
            lines.append(f"    {item['summary']}")
        if explain:
            lines.extend(render_detail(item))
        lines.append("")
    remaining = len(payload["results"]) - SAMPLE
    if remaining > 0:
        lines.append(f"  ... and {remaining} more; use --json for the full list.")
    lines.extend(trailer(payload))
    return "\n".join(lines) + "\n"


def render_detail(item: dict) -> list[str]:
    lines: list[str] = []
    explanation = item.get("explanation")
    if explanation:
        lines.append(f"    What is this:   {explanation['what_is_this']}")
        lines.append(f"    Why it exists:  {explanation['why_does_it_exist']}")
        lines.append(f"    Authority:      {explanation['what_is_authoritative']}")
        lines.append(f"    Project scope:  {explanation['what_is_project_specific']}")
        lines.append("    Unknown:")
        for unknown in explanation["what_is_unknown"]:
            lines.append(f"      - {unknown}")
        lines.append(f"    Recommended:    {explanation['what_is_recommended']}")
        lines.append(f"    Changed:        {explanation['was_anything_changed']}")
    for key, value in sorted(item["detail"].items()):
        if value in (None, [], {}, ""):
            continue
        if isinstance(value, list) and isinstance(value[0], dict):
            # Structured lineage. Dumping Python dicts here would be unreadable
            # and would compete with the Provenance block below, so the count is
            # stated and the full structure is left to --json.
            noun = "entry" if len(value) == 1 else "entries"
            lines.append(f"    {key}: {len(value)} structured {noun}; see --json")
            continue
        rendered = ", ".join(str(entry) for entry in value) if isinstance(value, list) else value
        lines.append(f"    {key}: {rendered}")
    if item["provenance"]:
        lines.append("    Provenance:")
        for step in item["provenance"]:
            label = step.get("source_title") or step.get("source_id") or step["channel"]
            suffix = f" ({step['snapshot_sha256'][:23]})" if step.get("snapshot_sha256") else ""
            lines.append(f"      - {step['channel']}: {label}{suffix}")
            if step.get("source_url"):
                lines.append(f"        {step['source_url']}")
    if item["unknowns"] and not explanation:
        lines.append("    Unknown:")
        for unknown in item["unknowns"]:
            lines.append(f"      - {unknown}")
    return lines


def render_status(payload: dict) -> str:
    sections = payload["sections"]
    release = sections["release"]
    freshness = sections["freshness"]
    lines = [
        f"Drupal Knowledge {release['drupal_knowledge_version']}",
        f"  record set digest   {release['records_digest']}",
        "",
        "Records held",
    ]
    for domain, count in sorted(release["record_counts"].items()):
        lines.append(f"  {domain:<22} {count}")
    lines.append("")
    lines.append("Sources")
    lines.append(f"  baselined           {freshness['sources_checked']}")
    lines.append(f"  past check cadence  {len(freshness['stale'])}")
    lines.append(f"  never acquired      {len(freshness['unbaselined'])}")
    for entry in freshness["stale"][:SAMPLE]:
        lines.append(
            f"    - {entry['source_id']}: last acquired {entry['age_days']} days ago "
            f"(cadence {entry['cadence_days']})"
        )
    lines.append(f"  {freshness['note']}")
    lines.append("")
    lines.append("Query domains")
    lines.append(f"  searched by default  {', '.join(sections['domains']['searchable'])}")
    lines.append(f"  opt-in only          {', '.join(sections['domains']['opt_in'])}")
    lines.extend(trailer(payload))
    return "\n".join(lines) + "\n"


def render_project(payload: dict, explain: bool = False) -> str:
    """A consolidated project view. A section that could not answer says so."""
    sections = payload["sections"]
    lines = header(payload)
    lines.append("")

    order = (
        "project",
        "drupal",
        "dependencies",
        "evidence",
        "security",
        "implementation_findings",
        "upgrade",
        "migration",
    )
    for name in order:
        block = sections.get(name)
        if block is None:
            continue
        state = block["state"]
        lines.append(f"{name.replace('_', ' ').title()}: {state}")
        if state == query.SECTION_UNAVAILABLE:
            lines.append(f"  — {block['reason']}")
            lines.append("")
            continue
        for key, value in sorted(block.items()):
            if key in ("section", "state", "reason") or value in (None, [], {}, ""):
                continue
            if isinstance(value, dict):
                rendered = ", ".join(f"{k}={v}" for k, v in sorted(value.items()))
            elif isinstance(value, list):
                shown = value[:6]
                rendered = ", ".join(str(entry) for entry in shown)
                if len(value) > len(shown):
                    rendered += f", ... (+{len(value) - len(shown)})"
            else:
                rendered = value
            lines.append(f"  {key}: {rendered}")
        lines.append("")

    lines.extend(trailer(payload))
    lines.append("")
    lines.append("No project files were read for writing, and nothing was changed.")
    return "\n".join(lines) + "\n"


def render(payload: dict, explain: bool = False) -> str:
    """Route one query result to its renderer. Semantics are never touched."""
    query_type = payload["query_type"]
    if query_type == "status":
        return render_status(payload)
    if query_type == "project_inspect":
        return render_project(payload, explain)
    return render_results(payload, explain=explain or query_type in ("explain", "provenance"))
