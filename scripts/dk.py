#!/usr/bin/env python3
"""The Drupal Knowledge command line.

One CLI, two audiences. A Drupal developer arriving with a project and a
question should meet the queries first: what does DK know, what applies to this
project, why does this finding exist, what does DK not know. The maintenance
operations that acquire sources, review candidates and promote knowledge stay
available and stay clearly separated, because a developer who stumbles into one
by accident can move something across a trust boundary that was meant to need a
human.

That separation is presentational and structural, never a permission system.
Nothing in the community surface can promote a source snapshot into trusted
knowledge, turn a discovery signal into a rule, or make project evidence stand
for Drupal-wide truth — those paths simply do not exist in it.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import dk_acquisition
import dk_api
import dk_api_lifecycle
import dk_applicability
import dk_core
import dk_discovery
import dk_evidence
import dk_finding_runtime
import dk_implementation
import dk_migration
import dk_generalization
import dk_project_analyzer
import dk_public
import dk_query
import dk_render
import dk_release_lifecycle
import dk_release_lifecycle_evaluator
import dk_remediation
import dk_security
import dk_solved_case
import dk_upgrade


# Which audience each command serves. Community commands ask questions;
# maintainer commands move things across trust boundaries or publish; internal
# commands exist for repository development. The classification is data so the
# help text, the docs and the tests all read the same answer.
AUDIENCE_COMMUNITY = "community"
AUDIENCE_MAINTAINER = "maintainer"
AUDIENCE_INTERNAL = "internal"

COMMAND_AUDIENCE = {
    # Community: ask Drupal Knowledge something.
    "status": AUDIENCE_COMMUNITY,
    "search": AUDIENCE_COMMUNITY,
    "explain": AUDIENCE_COMMUNITY,
    "provenance": AUDIENCE_COMMUNITY,
    "project": AUDIENCE_COMMUNITY,
    "version": AUDIENCE_COMMUNITY,
    "knowledge": AUDIENCE_COMMUNITY,
    "cases": AUDIENCE_COMMUNITY,
    "coverage": AUDIENCE_COMMUNITY,
    "sources": AUDIENCE_COMMUNITY,
    "analyze": AUDIENCE_COMMUNITY,
    "resolve": AUDIENCE_COMMUNITY,
    "findings": AUDIENCE_COMMUNITY,
    "evidence": AUDIENCE_COMMUNITY,
    "evidence-diff": AUDIENCE_COMMUNITY,
    "security-advisories": AUDIENCE_COMMUNITY,
    "security-evaluate": AUDIENCE_COMMUNITY,
    "security-remediation": AUDIENCE_COMMUNITY,
    "upgrade-evaluate": AUDIENCE_COMMUNITY,
    "upgrade-path": AUDIENCE_COMMUNITY,
    "migration-analyze": AUDIENCE_COMMUNITY,
    "migration-work": AUDIENCE_COMMUNITY,
    "implementation-findings": AUDIENCE_COMMUNITY,
    "lifecycle-evaluate": AUDIENCE_COMMUNITY,
    "api-lifecycle": AUDIENCE_COMMUNITY,
    # Maintainer: acquire, review, promote, publish. These cross trust
    # boundaries and are never part of a normal developer flow.
    "acquire": AUDIENCE_MAINTAINER,
    "source-status": AUDIENCE_MAINTAINER,
    "review-candidates": AUDIENCE_MAINTAINER,
    "discover": AUDIENCE_MAINTAINER,
    "signals": AUDIENCE_MAINTAINER,
    "corroborate": AUDIENCE_MAINTAINER,
    "corroboration": AUDIENCE_MAINTAINER,
    "signal-review": AUDIENCE_MAINTAINER,
    "recurrence": AUDIENCE_MAINTAINER,
    "generalizations": AUDIENCE_MAINTAINER,
    "generalization-review": AUDIENCE_MAINTAINER,
    "release-lifecycle": AUDIENCE_MAINTAINER,
    "solved-case": AUDIENCE_MAINTAINER,
    # Internal: repository development and publication. None of these answers
    # a Drupal question.
    "validate": AUDIENCE_INTERNAL,
    "generate": AUDIENCE_INTERNAL,
    "release-meta": AUDIENCE_INTERNAL,
    "site": AUDIENCE_INTERNAL,
    "public-site": AUDIENCE_INTERNAL,
    "api": AUDIENCE_INTERNAL,
}

# The order a developer meets community commands in: orient, ask about a
# project, then look something up, then dig into why.
COMMUNITY_ORDER = (
    "status",
    "project",
    "search",
    "explain",
    "provenance",
    "knowledge",
    "security-advisories",
    "security-evaluate",
    "security-remediation",
    "upgrade-evaluate",
    "upgrade-path",
    "migration-analyze",
    "migration-work",
    "implementation-findings",
    "evidence",
    "evidence-diff",
    "analyze",
    "resolve",
    "findings",
    "lifecycle-evaluate",
    "api-lifecycle",
    "cases",
    "coverage",
    "sources",
    "version",
)


def commands_for(audience: str) -> list[str]:
    return sorted(name for name, value in COMMAND_AUDIENCE.items() if value == audience)


def print_lines(lines: list[str]) -> None:
    for line in lines:
        print(line)


def cmd_validate(_args) -> int:
    print_lines(dk_core.validate_all())
    return 0


def cmd_sources(args) -> int:
    print_lines(dk_core.validate_source_contracts())
    sources = dk_core.load_sources()
    if args.enabled:
        sources = [source for source in sources if source["enabled"]]
    for source in sorted(sources, key=lambda item: item["id"]):
        print(
            f"{source['id']}\t{source['trust']}\t"
            f"{'enabled' if source['enabled'] else 'disabled'}\t{source['title']}"
        )
    return 0


def cmd_knowledge(_args) -> int:
    print_lines(dk_core.validate_knowledge())
    for record in sorted(dk_core.load_knowledge_records(), key=lambda item: item["id"]):
        print(
            f"{record['id']}\t{record['review_status']}\t"
            f"{dk_core.effective_enforcement(record)}\t{record['title']}"
        )
    return 0


def cmd_cases(_args) -> int:
    print_lines(dk_core.validate_solved_cases())
    cases = dk_core.load_solved_cases()
    if not cases:
        print("NO_SOLVED_CASES_YET")
    for case in sorted(cases, key=lambda item: item["id"]):
        print(f"{case['id']}\t{case['status']}\t{case['title']}")
    return 0


def cmd_generate(_args) -> int:
    paths = dk_core.write_generated()
    for path in paths:
        print(f"WROTE {path.relative_to(dk_core.ROOT)}")
    return 0


def cmd_site(args) -> int:
    path = Path(args.output)
    if not path.is_absolute():
        path = dk_core.ROOT / path
    dk_core.write_site(path)
    print(f"WROTE {path.relative_to(dk_core.ROOT)}")
    return 0


def cmd_release_meta(_args) -> int:
    import dk_release_meta
    for path in dk_release_meta.write_release_meta():
        print(f"WROTE {path}")
    return 0


def cmd_public_site(args) -> int:
    """Regenerate the public dataset and render the website from it.

    Two steps, in this order and never the other: the dataset is exported from
    the released query layer, and the site is rendered from the dataset. The
    renderer never sees a canonical record, which is what makes the website
    incapable of disagreeing with the CLI.
    """
    import dk_site_render

    if args.action == "serve":
        return serve_public_site(args)

    dataset_files = dk_public.write_dataset(dk_core.ROOT)
    dataset = dk_public.load_dataset(dk_core.ROOT)

    root = dk_core.ROOT / "public-site"
    editorial = {
        path.stem: path.read_text(encoding="utf-8").rstrip("\n")
        for path in sorted((root / "content").glob("*.html"))
    }
    assets = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((root / "assets").iterdir())
        if path.is_file()
    }
    commands = [
        {"command": name, "help": command_help(name)}
        for name in commands_for(AUDIENCE_COMMUNITY)
    ]

    built_at = args.built_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files = dk_site_render.render_site(
        dataset,
        editorial=editorial,
        assets=assets,
        commands=commands,
        built_at=built_at,
        today_ordinal=date.today().toordinal(),
        parse_day=parse_day_ordinal,
        commit=args.commit,
    )

    out = Path(args.output) if args.output else root / "dist"
    if not out.is_absolute():
        out = dk_core.ROOT / out
    if out.exists():
        shutil.rmtree(out)
    for relative, text in sorted(files.items()):
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    manifest = dataset[dk_public.MANIFEST_FILE]
    print(f"dataset  {manifest['dataset_id']}  ({len(dataset_files)} file(s))")
    print(f"site     {len(files)} file(s) -> {out.relative_to(dk_core.ROOT)}")
    print(f"pages    {sum(1 for name in files if name.endswith('.html'))}")
    print(f"records  {sum(manifest['record_counts'].values())} in {len(manifest['domains'])} domain(s)")
    return 0


def cmd_api(args) -> int:
    """Serve or describe the Public Knowledge API.

    Both actions read the published dataset. Neither can reach a canonical
    store, which is why serving one is not a way to change anything.
    """
    import dk_api_http

    if args.action == "build":
        written = dk_api.write_artifacts(dk_core.ROOT)
        document = dk_api.openapi_document(dk_core.ROOT)
        print(f"openapi  {document['openapi']}  contract {document['info']['version']}")
        print(f"paths    {len(document['paths'])}")
        print(f"wrote    {len(written)} file(s) under {dk_api.ARTIFACT_DIR}")
        return 0

    if args.action == "routes":
        for route in dk_api.ROUTES:
            print(f"GET {route['path']:<44} {route['summary']}")
        return 0

    dk_api_http.serve(host=args.host, port=args.port, root=dk_core.ROOT)
    return 0


def parse_day_ordinal(stamp: str):
    """A UTC timestamp reduced to a day number, or None when it is unreadable."""
    try:
        return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").date().toordinal()
    except (TypeError, ValueError):
        return None


def command_help(name: str) -> str:
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    for action in subparsers._choices_actions:
        if action.dest == name:
            return action.help or ""
    return ""


def serve_public_site(args) -> int:
    """A local static server for checking the generated site. Never a product."""
    import functools
    import http.server

    out = Path(args.output) if args.output else dk_core.ROOT / "public-site" / "dist"
    if not out.is_absolute():
        out = dk_core.ROOT / out
    if not (out / "index.html").is_file():
        print(f"ERROR: {out} has no generated site; run `dk public-site build` first", file=sys.stderr)
        return 2

    class DirectoryIndex(http.server.SimpleHTTPRequestHandler):
        def translate_path(self, path):
            resolved = Path(super().translate_path(path))
            if resolved.is_dir():
                return str(resolved / "index.html")
            return str(resolved)

    handler = functools.partial(DirectoryIndex, directory=str(out))
    with http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
        print(f"Serving {out.relative_to(dk_core.ROOT)} at http://127.0.0.1:{args.port}/  (ctrl-c to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print()
    return 0


def cmd_coverage(_args) -> int:
    generated = dk_core.build_generated()
    for domain in generated["coverage"]["domains"]:
        print(f"{domain['id']}\t{domain['status']}\t{domain['record_count']}")
    return 0


def cmd_analyze(args) -> int:
    try:
        result = dk_project_analyzer.analyze_project(args.project_path, args.config_dir)
    except dk_project_analyzer.AnalyzerInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(dk_project_analyzer.stable_json(result.data), end="")
    return result.exit_code


def cmd_resolve(args) -> int:
    try:
        analysis = dk_core.read_json(Path(args.analysis_json))
        # With a project path the resolver can answer evidence predicates from
        # observed project state instead of leaving them unknown.
        evidence = (
            dk_evidence.build(analysis, dk_core.ROOT, project_path=args.project_path)
            if getattr(args, "project_path", None)
            else None
        )
        result = dk_applicability.resolve_analysis_data(
            analysis, root=dk_core.ROOT, evidence=evidence
        )
    except dk_applicability.ResolverInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_applicability.ResolverValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(dk_applicability.stable_json(result), end="")
    return 0


def cmd_release_lifecycle_normalize(args) -> int:
    try:
        if args.snapshot:
            snapshot = dk_release_lifecycle.snapshot_reference_from_path(
                Path(args.snapshot),
                source_id=args.source,
            )
        else:
            snapshot = dk_release_lifecycle.resolve_current_snapshot(args.source)
        context = dk_release_lifecycle.build_context(
            snapshot,
            review_status=args.review_status,
            reviewed_on=args.reviewed_on,
        )
        if args.output:
            output = Path(args.output)
            if not output.is_absolute():
                output = dk_core.ROOT / output
            dk_release_lifecycle.write_context(output, context, force=args.force)
            display = (
                output.relative_to(dk_core.ROOT).as_posix()
                if output.is_relative_to(dk_core.ROOT)
                else output.as_posix()
            )
            print(f"WROTE {display}")
        else:
            print(dk_release_lifecycle.stable_json(context), end="")
    except dk_release_lifecycle.ReleaseLifecycleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_release_lifecycle_validate(_args) -> int:
    try:
        print_lines(dk_release_lifecycle.validate_context_file())
    except dk_release_lifecycle.ReleaseLifecycleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_release_lifecycle_status(_args) -> int:
    try:
        context = dk_release_lifecycle.load_context()
        status = dk_release_lifecycle.context_staleness(context)
    except dk_release_lifecycle.ReleaseLifecycleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(dk_release_lifecycle.stable_json(status), end="")
    return 0


def cmd_lifecycle_evaluate(args) -> int:
    try:
        result = dk_release_lifecycle_evaluator.evaluate_analysis_file(args.analysis_json)
    except dk_release_lifecycle_evaluator.LifecycleEvaluatorInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_release_lifecycle_evaluator.LifecycleEvaluatorValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(dk_release_lifecycle_evaluator.stable_json(result), end="")
    return 0


def cmd_version(args) -> int:
    version_path = dk_core.ROOT / "VERSION"
    release = version_path.read_text(encoding="utf-8").strip()
    community = {
        "community_query_interface": dk_query.QUERY_INTERFACE_VERSION,
        "query_result_contract": dk_query.RESULT_CONTRACT_VERSION,
        "community_domains": list(dk_query.SEARCHABLE_DOMAINS),
        "opt_in_domains": list(dk_query.OPT_IN_DOMAINS),
        "read_only_default": True,
        "trust_model_preserved": True,
        "trust_classes": sorted(dk_query.TRUST_CLASSES),
        "command_audiences": {
            "community": len(commands_for(AUDIENCE_COMMUNITY)),
            "maintainer": len(commands_for(AUDIENCE_MAINTAINER)),
            "internal": len(commands_for(AUDIENCE_INTERNAL)),
        },
    }
    # JSON is the default and always has been: this command is the machine
    # interface other tooling reads, and quietly turning it into prose would
    # break every consumer that already parses it. --human is the short summary
    # a developer wants, and it is opt-in for exactly that reason.
    if getattr(args, "human", False):
        print(f"Drupal Knowledge {release}")
        print(f"  community query interface  {community['community_query_interface']}")
        print(f"  query result contract      {community['query_result_contract']}")
        print(f"  community domains          {', '.join(community['community_domains'])}")
        print(f"  opt-in domains             {', '.join(community['opt_in_domains'])}")
        print(f"  read-only by default       {community['read_only_default']}")
        print(f"  trust model preserved      {community['trust_model_preserved']}")
        print(
            "  commands                   "
            f"{community['command_audiences']['community']} community, "
            f"{community['command_audiences']['maintainer']} maintainer, "
            f"{community['command_audiences']['internal']} internal"
        )
        print("  full interface contracts   dk version")
        return 0
    payload = {
        "product": "Drupal Knowledge",
        "version": release,
        "community": community,
        "interfaces": {
            "project_analysis_schema": "0.1",
            "applicability_resolution_schema": "0.1",
            "release_lifecycle_assessment_schema": "0.1",
            "finding_evaluation_schema": "0.1",
            "solved_case_candidate_schema": "0.1",
            "source_change_candidate_schema": "0.1",
            "acquisition_run_schema": dk_acquisition.ACQUISITION_RUN_SCHEMA_VERSION,
            "discovery_signal_schema": dk_discovery.SIGNAL_CONTRACT_VERSION,
            "corroboration_dossier_schema": dk_discovery.DOSSIER_CONTRACT_VERSION,
            "discovery_run_schema": dk_discovery.DISCOVERY_RUN_SCHEMA_VERSION,
            "recurrence_analysis_schema": dk_generalization.ANALYSIS_CONTRACT_VERSION,
            "generalization_proposal_schema": dk_generalization.PROPOSAL_CONTRACT_VERSION,
            "security_advisory_schema": dk_security.ADVISORY_CONTRACT_VERSION,
            "security_applicability_schema": dk_security.APPLICABILITY_SCHEMA_VERSION,
            "security_remediation_plan_schema": dk_remediation.PLAN_SCHEMA_VERSION,
            "upgrade_assessment_schema": dk_upgrade.ASSESSMENT_SCHEMA_VERSION,
            "upgrade_path_schema": dk_upgrade.PATH_SCHEMA_VERSION,
            "api_lifecycle_record_schema": dk_api_lifecycle.LIFECYCLE_RECORD_VERSION,
            "change_record_schema": dk_api_lifecycle.CHANGE_RECORD_VERSION,
            "migration_work_item_schema": dk_migration.WORK_ITEM_SCHEMA_VERSION,
            "migration_analysis_schema": dk_migration.ANALYSIS_SCHEMA_VERSION,
            "project_evidence_record_schema": dk_evidence.EVIDENCE_RECORD_VERSION,
            "project_evidence_set_schema": dk_evidence.EVIDENCE_SET_VERSION,
            "implementation_rule_schema": dk_implementation.RULE_CONTRACT_VERSION,
            "implementation_finding_schema": dk_implementation.FINDING_CONTRACT_VERSION,
        },
        "acquisition_engine": {
            "name": dk_acquisition.ENGINE_NAME,
            "version": dk_acquisition.ENGINE_VERSION,
            "channel": dk_acquisition.ACQUISITION_CHANNEL,
        },
        "discovery_engine": {
            "name": dk_discovery.DISCOVERY_ENGINE_NAME,
            "version": dk_discovery.DISCOVERY_ENGINE_VERSION,
            "channel": dk_discovery.DISCOVERY_CHANNEL,
            "corroboration_engine": dk_discovery.CORROBORATION_ENGINE_NAME,
            # Consumers must be able to see that discovery output is untrusted
            # without reading any documentation.
            "produces_trusted_knowledge": False,
        },
        "generalization_engine": {
            "name": dk_generalization.GENERALIZATION_ENGINE_NAME,
            "version": dk_generalization.ENGINE_VERSION,
            "channel": dk_generalization.EVIDENCE_CHANNEL,
            "recurrence_engine": dk_generalization.RECURRENCE_ENGINE_NAME,
            # Recurrence is evidence, never truth, and consumers can see that
            # without reading any documentation.
            "produces_trusted_knowledge": False,
        },
        "security_engine": {
            "name": dk_security.ENGINE_NAME,
            "version": dk_security.ENGINE_VERSION,
            "record_class": dk_security.RECORD_CLASS,
            # Advisories are authoritative evidence, not Drupal Knowledge rules,
            # and security truth never sets enforcement policy on its own.
            "produces_trusted_knowledge": False,
            "enforcement_intent": dk_security.ENFORCEMENT_INTENT,
            "automatically_blocking": False,
        },
        "remediation_engine": {
            "name": dk_remediation.ENGINE_NAME,
            "version": dk_remediation.ENGINE_VERSION,
            # The engine explains remediation and never performs it.
            "execution_performed": False,
            "project_files_written": False,
            "composer_invoked": False,
            "read_only": True,
        },
        "implementation_engine": {
            "name": dk_implementation.ENGINE_NAME,
            "version": dk_implementation.ENGINE_VERSION,
            "result_domain": dk_implementation.RESULT_DOMAIN,
            "categories": list(dk_implementation.CATEGORIES),
            "finding_states": list(dk_implementation.FINDING_STATES),
            "review_states": list(dk_implementation.REVIEW_STATES),
            "evidence_requirement_contract": "project_evidence_assertions",
            # A rule plus evidence makes a finding. Neither a preference nor an
            # observation makes one alone, and nothing here is applied.
            "produces_trusted_knowledge": False,
            "severity_established": False,
            "read_only": True,
        },
        "project_evidence_engine": {
            "name": dk_evidence.ENGINE_NAME,
            "version": dk_evidence.ENGINE_VERSION,
            "result_domain": dk_evidence.RESULT_DOMAIN,
            "channel": dk_evidence.EVIDENCE_CHANNEL,
            "domains": list(dk_evidence.DOMAINS),
            "evidence_states": list(dk_evidence.STATES),
            "quality_classes": list(dk_evidence.QUALITIES),
            # Evidence is what a repository was observed to hold, never a
            # Drupal-wide claim, and the engine touches no project file.
            "produces_trusted_knowledge": False,
            "project_writes": False,
            "runtime_observed": False,
        },
        "api_lifecycle_engine": {
            "name": dk_api_lifecycle.ENGINE_NAME,
            "version": dk_api_lifecycle.ENGINE_VERSION,
            "record_class": dk_api_lifecycle.RECORD_CLASS,
            # Lifecycle records are authoritative evidence projected from
            # official sources, not Drupal Knowledge rules.
            "produces_trusted_knowledge": False,
        },
        "migration_engine": {
            "name": dk_migration.ENGINE_NAME,
            "version": dk_migration.ENGINE_VERSION,
            "result_domain": dk_migration.RESULT_DOMAIN,
            "produces_trusted_knowledge": False,
            "produces_security_findings": False,
            # The engine identifies migration work and never performs it.
            "execution_performed": False,
            "code_modified": False,
            "rector_invoked": False,
            "read_only": True,
        },
        "upgrade_engine": {
            "name": dk_upgrade.ENGINE_NAME,
            "version": dk_upgrade.ENGINE_VERSION,
            # Compatibility output is its own domain. An upgrade blocker is not
            # a vulnerability, and consumers can see that without reading docs.
            "result_domain": dk_upgrade.RESULT_DOMAIN,
            "produces_security_findings": False,
            # The engine explains the upgrade and never performs it.
            "execution_performed": False,
            "project_files_written": False,
            "composer_invoked": False,
            "read_only": True,
        },
    }
    print(dk_core.stable_json(payload), end="")
    return 0


def cmd_findings(args) -> int:
    try:
        result = dk_finding_runtime.evaluate_analysis_file(args.analysis_json)
    except dk_finding_runtime.FindingRuntimeInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_finding_runtime.FindingRuntimeValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.explain:
        print(dk_finding_runtime.render_explanation(result), end="")
    else:
        print(dk_finding_runtime.stable_json(result), end="")
    return 0


def cmd_solved_case(args) -> int:
    try:
        if args.solved_case_command == "validate":
            candidate = dk_solved_case.read_candidate_file(args.candidate_json)
            print_lines(dk_solved_case.validate_candidate(candidate))
            return 0
        if args.solved_case_command == "capture":
            candidate = dk_solved_case.read_candidate_file(args.candidate_json)
            result = dk_solved_case.capture(candidate, force=args.force)
            print(dk_solved_case.stable_json(result), end="")
            return 0 if result["stored"] else 1
        if args.solved_case_command == "show":
            record = dk_solved_case.load_case(dk_core.ROOT, args.case_id)
            print(dk_solved_case.stable_json(record), end="")
            return 0
        if args.solved_case_command == "verify":
            verification = dk_solved_case.read_candidate_file(args.verification_json)
            result = dk_solved_case.verify_case(args.case_id, verification)
            print(dk_solved_case.stable_json(result), end="")
            return 0
        if args.solved_case_command == "list":
            for case in sorted(dk_core.load_solved_cases(), key=lambda item: item["id"]):
                print(f"{case['id']}\t{case['status']}\t{case['title']}")
            return 0
    except dk_solved_case.SolvedCaseInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (dk_solved_case.SolvedCaseValidationError, dk_core.ValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 2


def cmd_acquire(args) -> int:
    """Run the knowledge acquisition engine over registered sources."""
    try:
        normalized_output = None
        if args.normalized_output:
            if not args.dry_run:
                raise dk_acquisition.AcquisitionInputError(
                    "--normalized-output requires --dry-run"
                )
            normalized_output = dk_acquisition.resolve_writable_output(
                dk_core.ROOT, args.normalized_output, "--normalized-output"
            )
        report = (
            dk_acquisition.resolve_writable_output(dk_core.ROOT, args.report, "--report")
            if args.report
            else None
        )
        run = dk_acquisition.acquire(
            dk_core.ROOT,
            source_ids=args.source or None,
            trust=args.trust,
            all_sources=args.all,
            due_only=args.due,
            timeout=args.timeout,
            dry_run=args.dry_run,
            normalized_output=normalized_output,
        )
    except (dk_acquisition.AcquisitionInputError, dk_core.ValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_acquisition.AcquisitionEngineDefect as exc:
        # An engine defect is our problem. It is never reported as a source
        # availability failure and never exits zero.
        print(f"ACQUISITION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(dk_acquisition.stable_json(run), encoding="utf-8")
    if args.quiet:
        for result in run["results"]:
            print(f"{result['source_id']}\t{result['status']}\t{result['current_snapshot_sha256']}")
    else:
        print(dk_acquisition.stable_json(run), end="")
    return dk_acquisition.run_exit_code(run)


def cmd_source_status(args) -> int:
    sources = {source["id"]: source for source in dk_core.load_sources()}
    if args.source_id:
        if args.source_id not in sources:
            print(f"ERROR: source not registered: {args.source_id}", file=sys.stderr)
            return 2
        selected = [sources[args.source_id]]
    else:
        selected = [sources[key] for key in sorted(sources)]
    statuses = [dk_acquisition.source_status(dk_core.ROOT, source) for source in selected]
    if args.json:
        print(dk_acquisition.stable_json(statuses), end="")
        return 0
    for status in statuses:
        print(
            f"{status['source_id']}\t{status['trust']}\t"
            f"{status['last_attempt_status'] or 'never_attempted'}\t"
            f"{'stale' if status['stale'] else 'fresh'}\t"
            f"{status['open_review_candidate_id'] or '-'}\t"
            f"{status['current_snapshot_sha256'] or 'not_baselined'}"
        )
    return 0


def cmd_review_candidates(args) -> int:
    try:
        if args.review_candidates_command == "list":
            candidates = dk_acquisition.iter_candidates(dk_core.ROOT)
            if args.state:
                candidates = [
                    item for item in candidates if item["review_state"] == args.state
                ]
            if not candidates:
                print("NO_REVIEW_CANDIDATES")
                return 0
            for candidate in sorted(candidates, key=lambda item: item["id"]):
                print(
                    f"{candidate['id']}\t{candidate['review_state']}\t"
                    f"{candidate['source_id']}\t{candidate['kind']}"
                )
            return 0
        if args.review_candidates_command == "show":
            candidate = dk_acquisition.load_candidate(dk_core.ROOT, args.candidate_id)
            print(dk_acquisition.stable_json(candidate), end="")
            return 0
        if args.review_candidates_command == "review":
            result = dk_acquisition.review_candidate(
                dk_core.ROOT,
                args.candidate_id,
                review_state=args.state,
                actor=args.actor,
                method=args.method,
                note=args.note,
                force=args.force,
            )
            print(dk_acquisition.stable_json(result), end="")
            return 0
    except dk_acquisition.AcquisitionInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_core.ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 2


def cmd_discover(args) -> int:
    """Run ecosystem discovery over registered discovery sources."""
    import tempfile

    try:
        report = (
            dk_acquisition.resolve_writable_output(dk_core.ROOT, args.report, "--report")
            if args.report
            else None
        )
        # A dry run still fetches and normalizes, but it reads the normalized
        # text out of a scratch directory so nothing canonical moves.
        with tempfile.TemporaryDirectory() as scratch:
            run = dk_discovery.discover(
                dk_core.ROOT,
                source_ids=args.source or None,
                trust=args.trust,
                due_only=args.due,
                dry_run=args.dry_run,
                corroborate=not args.no_corroborate,
                timeout=args.timeout,
                normalized_dir=Path(scratch) if args.dry_run else None,
            )
    except (dk_discovery.DiscoveryInputError, dk_acquisition.AcquisitionInputError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (dk_discovery.DiscoveryEngineDefect, dk_acquisition.AcquisitionEngineDefect) as exc:
        # An engine defect is our problem. It is never reported as a source
        # failure and never exits zero.
        print(f"DISCOVERY_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(dk_discovery.stable_json(run), encoding="utf-8")
    if args.quiet:
        for result in run["results"]:
            print(
                f"{result['source_id']}\t{result['status']}\t"
                f"{result['observations']}\t{len(result['signals_created'])}"
            )
    else:
        print(dk_discovery.stable_json(run), end="")
    return dk_discovery.run_exit_code(run)


def cmd_signals(args) -> int:
    try:
        if args.signals_command == "list":
            rows = dk_discovery.signal_report(dk_core.ROOT)
            if args.status:
                rows = [row for row in rows if row["status"] == args.status]
            if args.trust:
                rows = [row for row in rows if row["trust"] == args.trust]
            if not rows:
                print("NO_DISCOVERY_SIGNALS")
                return 0
            if args.json:
                print(dk_discovery.stable_json(rows), end="")
                return 0
            for row in rows:
                print(
                    f"{row['signal_id']}\t{row['trust']}\t{row['status']}\t"
                    f"{row['corroboration_state'] or '-'}\t"
                    f"{row['review_state'] or '-'}\t"
                    f"{'stale' if row['stale'] else 'fresh'}\t{row['assertion_key']}"
                )
            return 0
        if args.signals_command == "show":
            print(
                dk_discovery.stable_json(
                    dk_discovery.load_signal(dk_core.ROOT, args.signal_id)
                ),
                end="",
            )
            return 0
    except dk_discovery.DiscoveryInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


def cmd_corroborate(args) -> int:
    try:
        result = dk_discovery.corroborate_signal(
            dk_core.ROOT, args.signal_id, dry_run=args.dry_run
        )
    except dk_discovery.DiscoveryInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_discovery.DiscoveryEngineDefect as exc:
        print(f"CORROBORATION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3
    print(dk_discovery.stable_json(result), end="")
    return 0


def cmd_corroboration(args) -> int:
    try:
        if args.corroboration_command == "list":
            dossiers = dk_discovery.iter_dossiers(dk_core.ROOT)
            if args.state:
                dossiers = [
                    item for item in dossiers if item["corroboration_state"] == args.state
                ]
            if args.review_state:
                dossiers = [
                    item for item in dossiers if item["review_state"] == args.review_state
                ]
            if not dossiers:
                print("NO_CORROBORATION_DOSSIERS")
                return 0
            for dossier in sorted(dossiers, key=lambda item: item["id"]):
                independence = dossier["independence_assessment"]
                print(
                    f"{dossier['id']}\t{dossier['corroboration_state']}\t"
                    f"{dossier['review_state']}\t"
                    f"independent={independence['independent_origin_count']}\t"
                    f"{dossier['signal_id']}"
                )
            return 0
        if args.corroboration_command == "show":
            print(
                dk_discovery.stable_json(
                    dk_discovery.load_dossier(dk_core.ROOT, args.dossier_id)
                ),
                end="",
            )
            return 0
    except dk_discovery.DiscoveryInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


def cmd_signal_review(args) -> int:
    """Record a human decision. No outcome here can mutate trusted knowledge."""
    try:
        result = dk_discovery.review_dossier(
            dk_core.ROOT,
            args.dossier_id,
            outcome=args.outcome,
            actor=args.actor,
            method=args.method,
            note=args.note,
        )
    except dk_discovery.DiscoveryInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_discovery.DiscoveryEngineDefect as exc:
        print(f"CORROBORATION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3
    print(dk_discovery.stable_json(result), end="")
    return 0


def cmd_recurrence(args) -> int:
    """Analyze recurrence across verified solved cases."""
    try:
        if args.recurrence_command == "analyze":
            run = dk_generalization.analyze(
                dk_core.ROOT,
                min_cases=args.min_cases,
                propose=not args.no_propose,
                dry_run=args.dry_run,
            )
            if args.quiet:
                for entry in run["recurrence_analyses"]:
                    print(
                        f"{entry['id']}\t{entry['result']}\t"
                        f"independent={entry['independent_occurrences']}\t"
                        f"{entry['verification_grade']}"
                    )
            else:
                print(dk_generalization.stable_json(run), end="")
            return 0
        if args.recurrence_command == "list":
            rows = dk_generalization.recurrence_report(dk_core.ROOT)
            if not rows:
                print("NO_RECURRENCE_ANALYSES")
                return 0
            if args.json:
                print(dk_generalization.stable_json(rows), end="")
                return 0
            for row in rows:
                print(
                    f"{row['recurrence_id']}\tcases={row['case_count']}\t"
                    f"independent={row['independent_occurrences']}\t"
                    f"{row['verification_grade']}\t"
                    f"contradictory={row['contradictory_cases']}\t"
                    f"conflicts={row['scope_conflicts']}\t"
                    f"{row['proposal_id'] or '-'}"
                )
            return 0
        if args.recurrence_command == "show":
            print(
                dk_generalization.stable_json(
                    dk_generalization.load_analysis(dk_core.ROOT, args.recurrence_id)
                ),
                end="",
            )
            return 0
    except dk_generalization.GeneralizationInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_generalization.GeneralizationEngineDefect as exc:
        # An engine defect is our problem, never an evidence problem.
        print(f"RECURRENCE_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3
    return 2


def cmd_generalizations(args) -> int:
    try:
        if args.generalizations_command == "list":
            proposals = dk_generalization.iter_proposals(dk_core.ROOT)
            if args.review_state:
                proposals = [
                    item for item in proposals if item["review_state"] == args.review_state
                ]
            if args.confidence:
                proposals = [
                    item
                    for item in proposals
                    if item["evidence_confidence"]["grade"] == args.confidence
                ]
            if not proposals:
                print("NO_GENERALIZATION_PROPOSALS")
                return 0
            for proposal in sorted(proposals, key=lambda item: item["id"]):
                confidence = proposal["evidence_confidence"]
                print(
                    f"{proposal['id']}\t{proposal['review_state']}\t"
                    f"confidence={confidence['grade']}\t"
                    f"independent={confidence['independent_occurrence_count']}\t"
                    f"recommended={proposal['eligibility']['recommended_review_state']}\t"
                    f"{proposal['recurrence_analysis_id']}"
                )
            return 0
        if args.generalizations_command == "show":
            print(
                dk_generalization.stable_json(
                    dk_generalization.load_proposal(dk_core.ROOT, args.proposal_id)
                ),
                end="",
            )
            return 0
    except dk_generalization.GeneralizationInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


def cmd_generalization_review(args) -> int:
    """Record a human decision. No outcome creates trusted knowledge."""
    try:
        result = dk_generalization.review_proposal(
            dk_core.ROOT,
            args.proposal_id,
            outcome=args.outcome,
            actor=args.actor,
            method=args.method,
            note=args.note,
        )
    except dk_generalization.GeneralizationInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_generalization.GeneralizationEngineDefect as exc:
        print(f"GENERALIZATION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3
    print(dk_generalization.stable_json(result), end="")
    return 0


def cmd_security_advisories(args) -> int:
    """Inspect and ingest authoritative Drupal Security Team advisories."""
    try:
        if args.security_advisories_command == "ingest":
            run = dk_security.ingest(
                dk_core.ROOT, source_ids=args.source, dry_run=args.dry_run
            )
            print(dk_security.stable_json(run), end="")
            return 1 if run["failures"] else 0
        if args.security_advisories_command == "list":
            advisories = dk_security.iter_advisories(dk_core.ROOT)
            if args.kind:
                advisories = [a for a in advisories if a["advisory"]["kind"] == args.kind]
            if args.project:
                advisories = [
                    a for a in advisories if a["project"]["machine_name"] == args.project
                ]
            if not advisories:
                print("NO_SECURITY_ADVISORIES")
                return 0
            if args.json:
                print(dk_security.stable_json(advisories), end="")
                return 0
            for advisory in sorted(advisories, key=lambda item: item["id"]):
                severity = advisory["severity"]
                print(
                    f"{advisory['id']}\t{advisory['advisory']['kind']}\t"
                    f"{advisory['project']['machine_name'] or '-'}\t"
                    f"{advisory['affected_versions']['source_value'] or '-'}\t"
                    f"severity={severity['state']}\t"
                    f"cve={','.join(advisory['cves']['identifiers']) or '-'}"
                )
            return 0
        if args.security_advisories_command == "show":
            print(
                dk_security.stable_json(
                    dk_security.load_advisory(dk_core.ROOT, args.advisory_id)
                ),
                end="",
            )
            return 0
    except dk_security.SecurityInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_security.SecurityEngineDefect as exc:
        # An engine defect is our problem, never a source or evidence problem.
        print(f"SECURITY_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3
    return 2


def cmd_security_evaluate(args) -> int:
    """Evaluate advisories against Project Analyzer facts. Read-only."""
    try:
        analysis = dk_core.read_json(Path(args.analysis))
        evaluation = dk_security.evaluate(
            analysis, dk_core.ROOT, advisory_ids=args.advisory or None
        )
    except dk_security.SecurityInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_security.SecurityEngineDefect as exc:
        print(f"SECURITY_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if args.explain:
        for result in evaluation["results"]:
            if args.only_relevant and result["applicability"] in (
                dk_security.NOT_APPLICABLE,
                dk_security.VERSION_OUT_OF_SCOPE,
            ):
                continue
            print(
                f"{result['advisory_id']}\t{result['applicability']}\t"
                f"{result['scope']}\t{result['installed_version'] or '-'}"
            )
            print(f"    {result['reason']}")
        for finding in evaluation["findings"]:
            print(
                f"FINDING {finding['id']}\t{finding['state']}\t"
                f"enforcement={finding['enforcement']['intent']}"
            )
        return 0
    print(dk_security.stable_json(evaluation), end="")
    return 0


def cmd_security_remediation(args) -> int:
    """Explain how a project could remediate applicable advisories. Read-only."""
    try:
        analysis = dk_core.read_json(Path(args.analysis))
        built = dk_remediation.plan(
            analysis,
            dk_core.ROOT,
            target=args.target,
            advisory_ids=args.advisory or None,
        )
    except (dk_remediation.RemediationInputError, dk_security.SecurityInputError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (dk_remediation.RemediationEngineDefect, dk_security.SecurityEngineDefect) as exc:
        # An engine defect is our problem, never an evidence problem.
        print(f"REMEDIATION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(dk_remediation.stable_json(built), end="")
        return 0
    print(dk_remediation.render(built))
    if args.explain:
        print()
        print("Candidates considered (each re-evaluated against the applicable advisories):")
        for component in built["components"]:
            for candidate in component["project_remediation_plan"]["candidates"]:
                print(
                    f"  {component['component']}\t{candidate['version']}\t"
                    f"{candidate['origin']}\t{candidate['branch_support']}\t"
                    f"{candidate['stable_release']}\t"
                    f"resolves={len(candidate['resolves_advisories'])}\t"
                    f"residual={len(candidate['residual_advisories'])}\t"
                    f"constraint={candidate['satisfies_declared_constraint']}"
                )
    return 0


def cmd_upgrade_evaluate(args) -> int:
    """Evaluate one proposed upgrade target. Read-only: nothing is changed."""
    try:
        analysis = dk_core.read_json(Path(args.analysis))
        # With a project path the custom-code dimension is answered by the
        # migration engine instead of staying unknown. Without one it stays
        # unknown, which is the honest default.
        migration = (
            dk_migration.analyze(
                analysis, args.target, dk_core.ROOT, project_path=args.project_path
            )
            if args.project_path
            else None
        )
        assessment = dk_upgrade.evaluate(
            analysis, args.target, dk_core.ROOT, migration=migration
        )
    except dk_migration.MigrationInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_upgrade.UpgradeInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_upgrade.UpgradeEngineDefect as exc:
        # An engine defect is our problem, never an evidence problem.
        print(f"UPGRADE_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(dk_upgrade.stable_json(assessment), end="")
        return 0
    print(dk_upgrade.render_assessment(assessment), end="")
    return 0


def cmd_upgrade_path(args) -> int:
    """Describe the supported targets reachable from a project. Read-only."""
    try:
        analysis = dk_core.read_json(Path(args.analysis))
        path = dk_upgrade.build_path(
            analysis,
            dk_core.ROOT,
            targets=args.target or None,
        )
    except dk_upgrade.UpgradeInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_upgrade.UpgradeEngineDefect as exc:
        print(f"UPGRADE_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(dk_upgrade.stable_json(path), end="")
        return 0
    print(dk_upgrade.render_path(path), end="")
    return 0


def cmd_api_lifecycle(args) -> int:
    """Inspect and refresh the source-derived API lifecycle corpus."""
    try:
        if args.api_command == "ingest":
            run = dk_api_lifecycle.ingest(dk_core.ROOT)
            print(
                "API_LIFECYCLE_INGEST=PASS "
                f"LIFECYCLE={run['lifecycle_records_written']} "
                f"CHANGE_RECORDS={run['change_records_written']} "
                f"UNPARSED={run['lifecycle_annotations_unparsed']}"
            )
            return 0
        if args.api_command == "coverage":
            print(dk_api_lifecycle.stable_json(dk_api_lifecycle.coverage(dk_core.ROOT)), end="")
            return 0
        if args.api_command == "show":
            index = dk_api_lifecycle.build_index(dk_core.ROOT)
            for bucket in ("functions", "classes", "methods", "constants", "services"):
                record = index[bucket].get(args.symbol)
                if record:
                    print(dk_api_lifecycle.stable_json(record), end="")
                    return 0
            print(f"NO_LIFECYCLE_RECORD symbol={args.symbol}", file=sys.stderr)
            return 4
        # list
        records = dk_api_lifecycle.iter_lifecycle_records(dk_core.ROOT)
        if args.removed_in:
            records = [
                record
                for record in records
                if record["lifecycle"]["removed_version"] == args.removed_in
            ]
        for record in sorted(records, key=lambda item: item["symbol"]["index_name"]):
            state = record["lifecycle"]
            print(
                f"{record['symbol']['index_name']}\t{record['symbol']['kind']}\t"
                f"{state['deprecated_version']}\t{state['removed_version']}\t"
                f"{record['replacement']['state']}"
            )
        return 0
    except dk_api_lifecycle.ApiLifecycleInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_migration_analyze(args) -> int:
    """Identify custom-code migration work for a target. Read-only."""
    try:
        analysis = dk_core.read_json(Path(args.analysis))
        result = dk_migration.analyze(
            analysis,
            args.target,
            dk_core.ROOT,
            project_path=args.project_path,
        )
    except dk_migration.MigrationInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_migration.MigrationEngineDefect as exc:
        # An engine defect is our problem, never an evidence problem.
        print(f"MIGRATION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(dk_migration.stable_json(result), end="")
        return 0
    print(dk_migration.render(result), end="")
    return 0


def cmd_migration_work(args) -> int:
    """List the machine-readable migration work items only. Read-only."""
    try:
        analysis = dk_core.read_json(Path(args.analysis))
        result = dk_migration.analyze(
            analysis,
            args.target,
            dk_core.ROOT,
            project_path=args.project_path,
        )
    except dk_migration.MigrationInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_migration.MigrationEngineDefect as exc:
        print(f"MIGRATION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    items = result["work_items"]
    if args.effect:
        items = [item for item in items if item["target_effect"]["effect"] == args.effect]
    if args.format == "json":
        print(dk_migration.stable_json(items), end="")
        return 0
    if not items:
        print("NO_MIGRATION_WORK_ITEMS")
        print(f"  {result['coverage']['statement']}")
        return 0
    for item in items:
        print(
            f"{item['work_item_id']}\t{item['target_effect']['effect']}\t"
            f"{item['usage']['usage_kind']}\t{item['usage']['symbol']}\t"
            f"occurrences={item['usage']['occurrence_count']}\t"
            f"applied={item['execution_performed']}"
        )
        for occurrence in item["occurrences"]:
            print(f"    {occurrence['path']}:{occurrence['line']}")
    return 0


def build_evidence_set(args):
    """Canonical evidence for one analyzer result. Read-only."""
    analysis = dk_core.read_json(Path(args.analysis))
    return dk_evidence.build(analysis, dk_core.ROOT, project_path=args.project_path)


def cmd_evidence(args) -> int:
    """Print canonical project evidence. Nothing is written to the project."""
    try:
        evidence = build_evidence_set(args)
    except dk_evidence.EvidenceInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_evidence.EvidenceEngineDefect as exc:
        # An engine defect is our problem, never an evidence problem.
        print(f"EVIDENCE_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if args.domain:
        evidence = dict(evidence)
        evidence["records"] = [
            item for item in evidence["records"] if item["domain"] == args.domain
        ]

    if args.persist:
        path = dk_evidence.persist(evidence, dk_core.ROOT)
        print(f"WROTE {path.relative_to(dk_core.ROOT)}")
        return 0

    if args.format == "json":
        print(dk_evidence.stable_json(evidence), end="")
        return 0
    print(dk_evidence.render(evidence), end="")
    print()
    print(dk_evidence.render_records(evidence, args.domain, args.limit), end="")
    return 0


def cmd_evidence_diff(args) -> int:
    """Compare two evidence sets. Read-only."""
    try:
        before = dk_core.read_json(Path(args.before))
        after = dk_core.read_json(Path(args.after))
        result = dk_evidence.diff(before, after)
    except dk_evidence.EvidenceInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(dk_evidence.stable_json(result), end="")
        return 0
    print(dk_evidence.render_diff(result), end="")
    return 0


def cmd_implementation_findings(args) -> int:
    """Evaluate reviewed implementation rules. Read-only: nothing is changed."""
    try:
        payload = dk_core.read_json(Path(args.input))
        if payload.get("result_domain") == dk_evidence.RESULT_DOMAIN:
            evidence = payload
        else:
            # An analyzer result is accepted directly, so a caller does not have
            # to produce an evidence set by hand first.
            evidence = dk_evidence.build(
                payload, dk_core.ROOT, project_path=args.project_path
            )
        result = dk_implementation.evaluate(
            evidence, dk_core.ROOT, category=args.category
        )
    except (dk_implementation.ImplementationInputError, dk_evidence.EvidenceInputError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_implementation.ImplementationEngineDefect as exc:
        # An engine defect is our problem, never an evidence problem.
        print(f"IMPLEMENTATION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    if args.state:
        result = dict(result)
        result["findings"] = [
            item for item in result["findings"] if item["state"] == args.state
        ]
    if args.format == "json":
        print(dk_implementation.stable_json(result), end="")
        return 0
    print(dk_implementation.render(result, explain=args.explain), end="")
    return 0


def emit(payload: dict, args, renderer) -> int:
    """One output path for every community command.

    ``--json`` writes only the machine document to stdout: no banner, no prose,
    nothing a parser has to strip. Everything else is a rendering of the same
    result and never changes it.
    """
    if getattr(args, "json", False):
        print(dk_query.stable_json(payload), end="")
        return 0
    print(renderer(payload, explain=getattr(args, "explain", False)), end="")
    return 0


def community_query(args, run, renderer=dk_render.render) -> int:
    """Run one query, turning expected problems into actionable messages.

    A developer who mistypes an advisory id should read a sentence telling them
    what to do, not a traceback. An engine defect still fails loudly, because
    that is our bug and hiding it would be worse.
    """
    try:
        payload = run()
    except dk_query.QueryInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_query.QueryLayerDefect as exc:
        print(f"QUERY_LAYER_DEFECT: {exc}", file=sys.stderr)
        return 3
    return emit(payload, args, renderer)


def cmd_status(args) -> int:
    """What this Drupal Knowledge release holds, and how current it is."""
    return community_query(args, lambda: dk_query.status(dk_core.ROOT))


def cmd_search(args) -> int:
    """Search canonical Drupal Knowledge records."""
    return community_query(
        args,
        lambda: dk_query.search(
            args.term, dk_core.ROOT, domains=args.domain or None, limit=args.limit
        ),
    )


def cmd_explain(args) -> int:
    """Explain one record: what it is, what supports it, what is unknown."""
    return community_query(args, lambda: dk_query.explain(args.id, dk_core.ROOT))


def cmd_provenance(args) -> int:
    """Walk one record's lineage back to the source behind it."""
    return community_query(args, lambda: dk_query.provenance(args.id, dk_core.ROOT))


def cmd_project(args) -> int:
    """Consolidated read-only inspection of one Drupal project."""
    return community_query(
        args,
        lambda: dk_query.inspect_project(
            args.path, dk_core.ROOT, target=args.target
        ),
    )


class CommunityFirstHelp(argparse.HelpFormatter):
    """Help that answers "what can I ask?" before "what can I administer?"."""


def format_root_help(parser: argparse.ArgumentParser, subparsers) -> str:
    lines = [
        "Drupal Knowledge — authoritative Drupal intelligence you can trace.",
        "",
        "Usage: dk <command> [options]        (or: python3 scripts/dk.py <command>)",
        "",
        "Start here",
        "  dk status                       what this release knows, and how current it is",
        "  dk project <path>               inspect a Drupal project, read-only",
        "  dk search <term>                find advisories, APIs, rules and knowledge",
        "  dk explain <id>                 why a record exists and what supports it",
        "  dk provenance <id>              trace a record back to its source",
        "",
        "Ask about a project",
    ]
    described = {
        "security-evaluate": "which published advisories apply to a project",
        "security-remediation": "what update path the advisories support",
        "upgrade-evaluate": "whether a project can reach a target Drupal version",
        "upgrade-path": "which supported targets are reachable, and what blocks each",
        "migration-analyze": "custom-code migration work for a target version",
        "migration-work": "the migration work items alone, with file and line",
        "implementation-findings": "performance, security and configuration-quality findings",
        "evidence": "what was concretely observed in a project",
        "analyze": "the raw project analyzer profile",
    }
    for name, blurb in described.items():
        lines.append(f"  dk {name:<28} {blurb}")
    lines += [
        "",
        "Browse Drupal Knowledge",
        "  dk knowledge                    reviewed Drupal Knowledge records",
        "  dk security-advisories          published Drupal Security Team advisories",
        "  dk api-lifecycle                Drupal API deprecations and removals",
        "  dk cases                        solved cases, limited to their proven context",
        "  dk coverage                     which Drupal domains are covered",
        "  dk sources                      the registered authoritative source list",
        "",
        "Every result says how far it can be trusted: reviewed Drupal Knowledge,",
        "authoritative source record, an observation about one project, or an",
        "untrusted discovery signal. Querying never changes anything.",
        "",
        f"Maintainer commands ({len(commands_for(AUDIENCE_MAINTAINER))}) acquire sources, review candidates and",
        "promote knowledge across trust boundaries. See `dk --help-maintainer`.",
        "",
        "Full command list: dk --help-all        Guide: docs/CLI.md",
    ]
    return "\n".join(lines) + "\n"


def format_audience_help(audience: str) -> str:
    heading = {
        AUDIENCE_MAINTAINER: (
            "Maintainer commands. These acquire sources, review candidates and move\n"
            "records across trust boundaries. They are not part of a normal developer\n"
            "flow, and none of them runs unless you name it explicitly."
        ),
        AUDIENCE_INTERNAL: (
            "Repository development commands. They validate contracts and\n"
            "regenerate published artifacts. None of them answers a Drupal\n"
            "question on anyone's behalf."
        ),
        AUDIENCE_COMMUNITY: "Community commands. Every one of them is read-only.",
    }[audience]
    lines = [heading, ""]
    for name in commands_for(audience):
        lines.append(f"  dk {name}")
    lines.append("")
    lines.append("Run `dk <command> --help` for options.")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Drupal Knowledge foundation CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate all repository contracts")
    validate.set_defaults(func=cmd_validate)

    version = sub.add_parser("version", help="print the release and the community query interface")
    version.add_argument(
        "--human", action="store_true", help="print a short summary instead of the full JSON"
    )
    version.add_argument(
        "--json", action="store_true",
        help="print every interface contract as JSON (the default; accepted for clarity)",
    )
    version.set_defaults(func=cmd_version)

    sources = sub.add_parser("sources", help="validate and list sources")
    sources.add_argument("--enabled", action="store_true", help="show only enabled sources")
    sources.set_defaults(func=cmd_sources)

    knowledge = sub.add_parser("knowledge", help="validate and list knowledge records")
    knowledge.set_defaults(func=cmd_knowledge)

    cases = sub.add_parser("cases", help="validate and list solved cases")
    cases.set_defaults(func=cmd_cases)

    generate = sub.add_parser("generate", help="write deterministic generated JSON")
    release_meta = sub.add_parser(
        "release-meta", help="write the release SBOM and artifact checksums"
    )
    release_meta.set_defaults(func=cmd_release_meta)
    generate.set_defaults(func=cmd_generate)

    site = sub.add_parser("site", help="write deterministic static HTML index")
    site.add_argument("output", help="output path, usually public/index.html")
    site.set_defaults(func=cmd_site)

    public_site = sub.add_parser(
        "public-site", help="build the public Drupal Knowledge website from the query layer"
    )
    public_site.add_argument("action", choices=("build", "serve"))
    public_site.add_argument("--output", help="output directory, default public-site/dist")
    public_site.add_argument("--port", type=int, default=8000, help="port for `serve`")
    public_site.add_argument(
        "--built-at", help="fix the build timestamp, for reproducible comparisons"
    )
    public_site.add_argument("--commit", help="record the commit the build came from")
    public_site.set_defaults(func=cmd_public_site)

    api = sub.add_parser(
        "api", help="serve or describe the read-only Public Knowledge API"
    )
    api.add_argument("action", choices=("serve", "build", "routes"))
    api.add_argument(
        # Loopback. Binding a public interface is an explicit decision for an
        # explicit deployment, never a default a laptop inherits.
        "--host", default="127.0.0.1",
        help="interface to bind; defaults to loopback",
    )
    api.add_argument("--port", type=int, default=8088, help="port for `serve`")
    api.set_defaults(func=cmd_api)

    coverage = sub.add_parser("coverage", help="print coverage summary")
    coverage.set_defaults(func=cmd_coverage)

    analyze = sub.add_parser("analyze", help="statically analyze a Drupal project path")
    analyze.add_argument("project_path", help="project root to inspect")
    analyze.add_argument(
        "--config-dir",
        help="explicit Drupal exported config directory, relative to the project root unless absolute",
    )
    analyze.set_defaults(func=cmd_analyze)

    resolve = sub.add_parser("resolve", help="resolve knowledge applicability from analyzer JSON")
    resolve.add_argument(
        "--project-path",
        help="project root the analyzer read, so evidence predicates can be answered",
    )
    resolve.add_argument("analysis_json", help="analysis JSON produced by dk.py analyze")
    resolve.set_defaults(func=cmd_resolve)

    lifecycle_evaluate = sub.add_parser(
        "lifecycle-evaluate",
        help="evaluate analyzer core-version evidence against reviewed release lifecycle context",
    )
    lifecycle_evaluate.add_argument("analysis_json", help="analysis JSON produced by dk.py analyze")
    lifecycle_evaluate.set_defaults(func=cmd_lifecycle_evaluate)

    solved_case = sub.add_parser(
        "solved-case",
        help="validate, capture, inspect and verify solved-case candidates",
    )
    solved_case_sub = solved_case.add_subparsers(dest="solved_case_command", required=True)

    sc_validate = solved_case_sub.add_parser("validate", help="validate a candidate without storing it")
    sc_validate.add_argument("candidate_json", help="solved-case candidate JSON")
    sc_validate.set_defaults(func=cmd_solved_case)

    sc_capture = solved_case_sub.add_parser("capture", help="validate and store a candidate")
    sc_capture.add_argument("candidate_json", help="solved-case candidate JSON")
    sc_capture.add_argument("--force", action="store_true", help="replace an existing record for the same case identity")
    sc_capture.set_defaults(func=cmd_solved_case)

    sc_show = solved_case_sub.add_parser("show", help="print a stored solved case")
    sc_show.add_argument("case_id", help="solved case id")
    sc_show.set_defaults(func=cmd_solved_case)

    sc_verify = solved_case_sub.add_parser(
        "verify",
        help="transition a captured case to verified using explicit verification evidence",
    )
    sc_verify.add_argument("case_id", help="solved case id")
    sc_verify.add_argument("verification_json", help="verification evidence JSON")
    sc_verify.set_defaults(func=cmd_solved_case)

    sc_list = solved_case_sub.add_parser("list", help="list stored solved cases")
    sc_list.set_defaults(func=cmd_solved_case)

    findings = sub.add_parser(
        "findings",
        help="execute reviewed finding contracts against analyzer output",
    )
    findings.add_argument("analysis_json", help="analysis JSON produced by dk.py analyze")
    findings.add_argument(
        "--explain",
        action="store_true",
        help="print the human-readable explanation instead of JSON",
    )
    findings.set_defaults(func=cmd_findings)

    lifecycle = sub.add_parser(
        "release-lifecycle",
        help="normalize and validate authoritative Drupal release lifecycle context",
    )
    lifecycle_sub = lifecycle.add_subparsers(dest="release_lifecycle_command", required=True)

    lifecycle_normalize = lifecycle_sub.add_parser(
        "normalize",
        help="normalize release lifecycle context from a canonical source snapshot",
    )
    lifecycle_normalize.add_argument(
        "--source",
        default=dk_release_lifecycle.DEFAULT_SOURCE_ID,
        help="source ID to normalize",
    )
    lifecycle_normalize.add_argument(
        "--snapshot",
        help="explicit snapshot path; defaults to the current state snapshot",
    )
    lifecycle_normalize.add_argument(
        "--review-status",
        choices=["candidate", "reviewed"],
        default="candidate",
        help="mark normalized output as candidate or reviewed",
    )
    lifecycle_normalize.add_argument(
        "--reviewed-on",
        default=dk_release_lifecycle.REVIEWED_ON,
        help="review date used only with --review-status reviewed",
    )
    lifecycle_normalize.add_argument(
        "--output",
        help="optional output path; stdout is used by default",
    )
    lifecycle_normalize.add_argument(
        "--force",
        action="store_true",
        help="allow overwriting an explicit output path",
    )
    lifecycle_normalize.set_defaults(func=cmd_release_lifecycle_normalize)

    lifecycle_validate = lifecycle_sub.add_parser(
        "validate",
        help="validate the checked-in reviewed release lifecycle context",
    )
    lifecycle_validate.set_defaults(func=cmd_release_lifecycle_validate)

    lifecycle_status = lifecycle_sub.add_parser(
        "status",
        help="print whether reviewed lifecycle context matches current source state",
    )
    lifecycle_status.set_defaults(func=cmd_release_lifecycle_status)

    acquire = sub.add_parser(
        "acquire",
        help="acquire registered sources into immutable snapshots and review candidates",
    )
    acquire.add_argument(
        "--source",
        action="append",
        help="acquire a single registered source id; repeatable",
    )
    acquire.add_argument(
        "--trust",
        choices=sorted(dk_core.TRUST_TIERS),
        help="acquire every registered source in one trust tier",
    )
    acquire.add_argument(
        "--all",
        action="store_true",
        help="acquire every enabled registered source",
    )
    acquire.add_argument(
        "--due",
        action="store_true",
        help="skip sources still inside their configured check cadence",
    )
    acquire.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch and compare without mutating any canonical state",
    )
    acquire.add_argument(
        "--normalized-output",
        help="write normalized text for inspection; requires --dry-run",
    )
    acquire.add_argument("--report", help="write the acquisition run result to a path")
    acquire.add_argument("--quiet", action="store_true", help="print one line per source")
    acquire.add_argument("--timeout", type=int, default=dk_acquisition.DEFAULT_TIMEOUT)
    acquire.set_defaults(func=cmd_acquire)

    source_status = sub.add_parser(
        "source-status",
        help="inspect acquisition state, freshness and open review candidates",
    )
    source_status.add_argument("source_id", nargs="?", help="registered source id")
    source_status.add_argument("--json", action="store_true", help="print JSON")
    source_status.set_defaults(func=cmd_source_status)

    review_candidates = sub.add_parser(
        "review-candidates",
        help="list, inspect and review source-change candidates",
    )
    review_candidates_sub = review_candidates.add_subparsers(
        dest="review_candidates_command", required=True
    )

    rc_list = review_candidates_sub.add_parser("list", help="list review candidates")
    rc_list.add_argument(
        "--state",
        choices=list(dk_acquisition.REVIEW_STATES),
        help="filter by review state",
    )
    rc_list.set_defaults(func=cmd_review_candidates)

    rc_show = review_candidates_sub.add_parser("show", help="print one review candidate")
    rc_show.add_argument("candidate_id", help="review candidate id")
    rc_show.set_defaults(func=cmd_review_candidates)

    rc_review = review_candidates_sub.add_parser(
        "review",
        help="record an explicit human review decision; never mutates trusted knowledge",
    )
    rc_review.add_argument("candidate_id", help="review candidate id")
    rc_review.add_argument(
        "--state",
        required=True,
        choices=sorted(dk_acquisition.REVIEW_TERMINAL_STATES),
        help="review outcome",
    )
    rc_review.add_argument("--actor", required=True, help="who reviewed the change")
    rc_review.add_argument(
        "--method",
        required=True,
        choices=sorted(dk_acquisition.REVIEW_METHODS),
        help="how the change was reviewed",
    )
    rc_review.add_argument("--note", help="optional reviewer note")
    rc_review.add_argument(
        "--force",
        action="store_true",
        help="allow re-reviewing a candidate that already has an outcome",
    )
    rc_review.set_defaults(func=cmd_review_candidates)

    discover = sub.add_parser(
        "discover",
        help="observe registered ecosystem/discovery sources and record untrusted signals",
    )
    discover.add_argument(
        "--source",
        action="append",
        help="discover a single registered discovery source id; repeatable",
    )
    discover.add_argument(
        "--trust",
        choices=sorted(dk_discovery.SIGNAL_SOURCE_TIERS),
        help="discover every registered signal source in one trust tier",
    )
    discover.add_argument(
        "--due",
        action="store_true",
        help="skip sources still inside their configured check cadence",
    )
    discover.add_argument(
        "--dry-run",
        action="store_true",
        help="observe without mutating any canonical state",
    )
    discover.add_argument(
        "--no-corroborate",
        action="store_true",
        help="record signals without building corroboration dossiers",
    )
    discover.add_argument("--report", help="write the discovery run result to a path")
    discover.add_argument("--quiet", action="store_true", help="print one line per source")
    discover.add_argument("--timeout", type=int, default=dk_acquisition.DEFAULT_TIMEOUT)
    discover.set_defaults(func=cmd_discover)

    signals = sub.add_parser(
        "signals",
        help="inspect untrusted discovery signals and their corroboration state",
    )
    signals_sub = signals.add_subparsers(dest="signals_command", required=True)
    sig_list = signals_sub.add_parser("list", help="list discovery signals")
    sig_list.add_argument("--status", choices=sorted(dk_discovery.SIGNAL_STATUSES))
    sig_list.add_argument("--trust", choices=sorted(dk_core.TRUST_TIERS))
    sig_list.add_argument("--json", action="store_true", help="print machine-readable output")
    sig_list.set_defaults(func=cmd_signals)
    sig_show = signals_sub.add_parser("show", help="print one discovery signal")
    sig_show.add_argument("signal_id", help="discovery signal id")
    sig_show.set_defaults(func=cmd_signals)

    corroborate = sub.add_parser(
        "corroborate",
        help="build the deterministic corroboration dossier for one signal",
    )
    corroborate.add_argument("signal_id", help="discovery signal id")
    corroborate.add_argument(
        "--dry-run",
        action="store_true",
        help="assess evidence without writing the dossier",
    )
    corroborate.set_defaults(func=cmd_corroborate)

    corroboration = sub.add_parser(
        "corroboration",
        help="inspect corroboration dossiers awaiting human review",
    )
    corroboration_sub = corroboration.add_subparsers(
        dest="corroboration_command", required=True
    )
    cor_list = corroboration_sub.add_parser("list", help="list corroboration dossiers")
    cor_list.add_argument("--state", choices=sorted(dk_discovery.CORROBORATION_STATES))
    cor_list.add_argument("--review-state", choices=sorted(dk_discovery.REVIEW_STATES))
    cor_list.set_defaults(func=cmd_corroboration)
    cor_show = corroboration_sub.add_parser("show", help="print one corroboration dossier")
    cor_show.add_argument("dossier_id", help="corroboration dossier id")
    cor_show.set_defaults(func=cmd_corroboration)

    signal_review = sub.add_parser(
        "signal-review",
        help=(
            "record an explicit human decision on a corroboration dossier; "
            "never mutates trusted knowledge"
        ),
    )
    signal_review.add_argument("dossier_id", help="corroboration dossier id")
    signal_review.add_argument(
        "--outcome",
        required=True,
        choices=sorted(dk_discovery.REVIEW_OUTCOMES),
        help=(
            "review outcome; candidate_for_future_knowledge_proposal only authorises "
            "later explicit proposal work"
        ),
    )
    signal_review.add_argument("--actor", required=True, help="who reviewed the signal")
    signal_review.add_argument(
        "--method",
        default="human_signal_review",
        choices=sorted(dk_discovery.REVIEW_METHODS),
        help="how the signal was reviewed",
    )
    signal_review.add_argument("--note", help="optional reviewer note")
    signal_review.set_defaults(func=cmd_signal_review)

    recurrence = sub.add_parser(
        "recurrence",
        help="analyze and inspect recurrence across verified solved cases",
    )
    recurrence_sub = recurrence.add_subparsers(dest="recurrence_command", required=True)
    rec_analyze = recurrence_sub.add_parser(
        "analyze", help="group verified solved cases and propose where evidence warrants"
    )
    rec_analyze.add_argument(
        "--min-cases",
        type=int,
        default=2,
        help="minimum cases in a structural group before it is analyzed",
    )
    rec_analyze.add_argument(
        "--no-propose",
        action="store_true",
        help="analyze recurrence without building generalization proposals",
    )
    rec_analyze.add_argument(
        "--dry-run", action="store_true", help="analyze without writing any artifact"
    )
    rec_analyze.add_argument("--quiet", action="store_true", help="print one line per analysis")
    rec_analyze.set_defaults(func=cmd_recurrence)
    rec_list = recurrence_sub.add_parser("list", help="list recurrence analyses")
    rec_list.add_argument("--json", action="store_true", help="print machine-readable output")
    rec_list.set_defaults(func=cmd_recurrence)
    rec_show = recurrence_sub.add_parser("show", help="print one recurrence analysis")
    rec_show.add_argument("recurrence_id", help="recurrence analysis id")
    rec_show.set_defaults(func=cmd_recurrence)

    generalizations = sub.add_parser(
        "generalizations",
        help="inspect generalization proposals awaiting human review",
    )
    generalizations_sub = generalizations.add_subparsers(
        dest="generalizations_command", required=True
    )
    gen_list = generalizations_sub.add_parser("list", help="list generalization proposals")
    gen_list.add_argument("--review-state", choices=sorted(dk_generalization.REVIEW_STATES))
    gen_list.add_argument(
        "--confidence",
        choices=[
            dk_generalization.CONFIDENCE_INSUFFICIENT,
            dk_generalization.CONFIDENCE_WEAK,
            dk_generalization.CONFIDENCE_MODERATE,
            dk_generalization.CONFIDENCE_STRONG,
        ],
    )
    gen_list.set_defaults(func=cmd_generalizations)
    gen_show = generalizations_sub.add_parser("show", help="print one generalization proposal")
    gen_show.add_argument("proposal_id", help="generalization proposal id")
    gen_show.set_defaults(func=cmd_generalizations)

    generalization_review = sub.add_parser(
        "generalization-review",
        help=(
            "record an explicit human decision on a generalization proposal; "
            "never mutates trusted knowledge"
        ),
    )
    generalization_review.add_argument("proposal_id", help="generalization proposal id")
    generalization_review.add_argument(
        "--outcome",
        required=True,
        choices=sorted(dk_generalization.REVIEW_OUTCOMES),
        help=(
            "review outcome; accepted_for_knowledge_proposal only authorises later "
            "explicit proposal work and creates no knowledge record"
        ),
    )
    generalization_review.add_argument("--actor", required=True, help="who reviewed the proposal")
    generalization_review.add_argument(
        "--method",
        default="human_generalization_review",
        choices=sorted(dk_generalization.REVIEW_METHODS),
        help="how the proposal was reviewed",
    )
    generalization_review.add_argument("--note", help="optional reviewer note")
    generalization_review.set_defaults(func=cmd_generalization_review)

    security_advisories = sub.add_parser(
        "security-advisories",
        help="inspect and ingest authoritative Drupal Security Team advisories",
    )
    security_sub = security_advisories.add_subparsers(
        dest="security_advisories_command", required=True
    )
    sa_ingest = security_sub.add_parser(
        "ingest",
        help="materialize advisory records from an already-acquired source snapshot",
    )
    sa_ingest.add_argument(
        "--source",
        action="append",
        required=True,
        help="registered advisory feed source id; repeatable",
    )
    sa_ingest.add_argument(
        "--dry-run", action="store_true", help="parse and validate without writing records"
    )
    sa_ingest.set_defaults(func=cmd_security_advisories)
    sa_list = security_sub.add_parser("list", help="list stored advisory records")
    sa_list.add_argument("--kind", choices=["core", "contrib", "psa"])
    sa_list.add_argument("--project", help="filter by Drupal.org project machine name")
    sa_list.add_argument("--json", action="store_true", help="print machine-readable output")
    sa_list.set_defaults(func=cmd_security_advisories)
    sa_show = security_sub.add_parser("show", help="print one advisory record")
    sa_show.add_argument("advisory_id", help="advisory id, for example SA-CORE-2026-012")
    sa_show.set_defaults(func=cmd_security_advisories)

    security_evaluate = sub.add_parser(
        "security-evaluate",
        help=(
            "evaluate advisories against Project Analyzer output; read-only and "
            "never remediates"
        ),
    )
    security_evaluate.add_argument("analysis", help="path to project analyzer JSON")
    security_evaluate.add_argument(
        "--advisory", action="append", help="restrict to advisory id(s); repeatable"
    )
    security_evaluate.add_argument(
        "--explain", action="store_true", help="print one line per advisory with its reason"
    )
    security_evaluate.add_argument(
        "--only-relevant",
        action="store_true",
        help="with --explain, omit advisories that do not concern this project",
    )
    security_evaluate.set_defaults(func=cmd_security_evaluate)

    security_remediation = sub.add_parser(
        "security-remediation",
        help=(
            "explain how a project could remediate applicable advisories; read-only, "
            "changes no dependency and runs no Composer command"
        ),
    )
    security_remediation.add_argument("analysis", help="path to project analyzer JSON")
    security_remediation.add_argument(
        "--target",
        help="evaluate a specific version read-only, without installing it",
    )
    security_remediation.add_argument(
        "--advisory", action="append", help="restrict to advisory id(s); repeatable"
    )
    security_remediation.add_argument(
        "--json", action="store_true", help="print the machine-readable plan"
    )
    security_remediation.add_argument(
        "--explain",
        action="store_true",
        help="also print every candidate target and what it resolves",
    )
    security_remediation.set_defaults(func=cmd_security_remediation)

    # Both upgrade commands are read-only by construction. There is deliberately
    # no --apply, --execute or --write flag anywhere on this surface.
    upgrade_evaluate = sub.add_parser(
        "upgrade-evaluate",
        help=(
            "evaluate whether a project can reach a proposed Drupal target; read-only, "
            "changes no dependency and runs no Composer command"
        ),
    )
    upgrade_evaluate.add_argument("analysis", help="path to project analyzer JSON")
    upgrade_evaluate.add_argument(
        "--target", required=True, help="the Drupal core version to evaluate, e.g. 11.4.0"
    )
    upgrade_evaluate.add_argument(
        "--project-path",
        help=(
            "project root the analyzer read; supplying it answers the custom-code "
            "dimension from observed API usage instead of leaving it unknown"
        ),
    )
    upgrade_evaluate.add_argument(
        "--format",
        choices=("explain", "json"),
        default="explain",
        help="explain prints a readable assessment; json prints the machine-readable contract",
    )
    upgrade_evaluate.set_defaults(func=cmd_upgrade_evaluate)

    upgrade_path = sub.add_parser(
        "upgrade-path",
        help=(
            "describe the supported targets reachable from a project and what blocks "
            "each; read-only, performs no upgrade"
        ),
    )
    upgrade_path.add_argument("analysis", help="path to project analyzer JSON")
    upgrade_path.add_argument(
        "--target",
        action="append",
        help="evaluate specific target version(s) instead of the supported set; repeatable",
    )
    upgrade_path.add_argument(
        "--format",
        choices=("explain", "json"),
        default="explain",
        help="explain prints a readable path; json prints the machine-readable contract",
    )
    upgrade_path.set_defaults(func=cmd_upgrade_path)

    api_lifecycle = sub.add_parser(
        "api-lifecycle",
        help="inspect the source-derived Drupal API lifecycle corpus",
    )
    api_sub = api_lifecycle.add_subparsers(dest="api_command", required=True)
    api_ingest = api_sub.add_parser(
        "ingest",
        help="project pinned source snapshots into lifecycle and change records",
    )
    api_ingest.set_defaults(func=cmd_api_lifecycle, symbol=None, removed_in=None)
    api_coverage = api_sub.add_parser(
        "coverage", help="print what the lifecycle corpus does and does not cover"
    )
    api_coverage.set_defaults(func=cmd_api_lifecycle, symbol=None, removed_in=None)
    api_list = api_sub.add_parser("list", help="list lifecycle records")
    api_list.add_argument("--removed-in", help="only symbols removed in this exact version")
    api_list.set_defaults(func=cmd_api_lifecycle, symbol=None)
    api_show = api_sub.add_parser("show", help="print one lifecycle record by qualified symbol")
    api_show.add_argument("symbol", help="qualified symbol, e.g. file_create_url")
    api_show.set_defaults(func=cmd_api_lifecycle, removed_in=None)

    # Neither migration command can change a project. There is deliberately no
    # --apply, --rewrite, --fix or --patch anywhere on this surface.
    migration_analyze = sub.add_parser(
        "migration-analyze",
        help=(
            "identify custom-code migration work for a target Drupal version; read-only, "
            "rewrites no code and runs no Rector"
        ),
    )
    migration_analyze.add_argument("analysis", help="path to project analyzer JSON")
    migration_analyze.add_argument(
        "--target", required=True, help="the Drupal core version to analyse against"
    )
    migration_analyze.add_argument(
        "--project-path",
        help="project root the analyzer read, so inventoried files can be re-read",
    )
    migration_analyze.add_argument(
        "--format",
        choices=("explain", "json"),
        default="explain",
        help="explain prints a readable analysis; json prints the machine-readable contract",
    )
    migration_analyze.set_defaults(func=cmd_migration_analyze)

    migration_work = sub.add_parser(
        "migration-work",
        help="list machine-readable migration work items; read-only, changes no code",
    )
    migration_work.add_argument("analysis", help="path to project analyzer JSON")
    migration_work.add_argument("--target", required=True, help="the Drupal core version")
    migration_work.add_argument("--project-path", help="project root the analyzer read")
    migration_work.add_argument(
        "--effect",
        choices=dk_migration.EFFECTS,
        help="only items with this target effect",
    )
    migration_work.add_argument(
        "--format", choices=("explain", "json"), default="explain"
    )
    migration_work.set_defaults(func=cmd_migration_work)

    # Neither evidence command can change a project. There is deliberately no
    # --apply or --write flag on this surface; --persist stores Drupal
    # Knowledge's own artifact and never touches the analysed project.
    evidence = sub.add_parser(
        "evidence",
        help=(
            "print canonical project evidence from an analyzer result; read-only, "
            "writes nothing to the project"
        ),
    )
    evidence.add_argument("analysis", help="path to project analyzer JSON")
    evidence.add_argument(
        "--project-path",
        help="project root the analyzer read, so code evidence can be observed",
    )
    evidence.add_argument(
        "--domain", choices=dk_evidence.DOMAINS, help="restrict output to one evidence domain"
    )
    evidence.add_argument(
        "--limit", type=int, default=25, help="records to print in explain output"
    )
    evidence.add_argument(
        "--persist",
        action="store_true",
        help="store the set under evidence/projects by fingerprint, carrying no project name",
    )
    evidence.add_argument("--format", choices=("explain", "json"), default="explain")
    evidence.set_defaults(func=cmd_evidence)

    evidence_diff = sub.add_parser(
        "evidence-diff",
        help="compare two project evidence sets; read-only",
    )
    evidence_diff.add_argument("before", help="path to the earlier evidence set JSON")
    evidence_diff.add_argument("after", help="path to the later evidence set JSON")
    evidence_diff.add_argument("--format", choices=("explain", "json"), default="explain")
    evidence_diff.set_defaults(func=cmd_evidence_diff)

    # There is deliberately no --apply, --fix, --optimize or --secure on this
    # surface. The engine explains findings and never acts on them.
    implementation = sub.add_parser(
        "implementation-findings",
        help=(
            "evaluate reviewed implementation rules against project evidence; read-only, "
            "changes no configuration, code or Drupal state"
        ),
    )
    implementation.add_argument(
        "input", help="path to a project evidence set, or to project analyzer JSON"
    )
    implementation.add_argument(
        "--project-path",
        help="project root the analyzer read, used when building evidence from analyzer JSON",
    )
    implementation.add_argument(
        "--category",
        choices=dk_implementation.CATEGORIES,
        help="restrict evaluation to one rule category",
    )
    implementation.add_argument(
        "--state",
        choices=dk_implementation.FINDING_STATES,
        help="print only findings in this state",
    )
    implementation.add_argument(
        "--explain",
        action="store_true",
        help="print the rule, evidence, authority, limitations and recommended action",
    )
    implementation.add_argument("--format", choices=("explain", "json"), default="explain")
    implementation.set_defaults(func=cmd_implementation_findings)

    # --- community query surface -------------------------------------------
    # Read-only by construction: every one of these calls the query layer, and
    # the query layer opens no socket and writes no file.
    status_parser = sub.add_parser(
        "status", help="what this Drupal Knowledge release knows, and how current it is"
    )
    status_parser.add_argument("--json", action="store_true", help="print the machine-readable result")
    status_parser.set_defaults(func=cmd_status, explain=False)

    project_parser = sub.add_parser(
        "project",
        help="inspect a Drupal project across every engine; read-only, changes nothing",
    )
    project_parser.add_argument("path", help="path to the Drupal project to inspect")
    project_parser.add_argument(
        "--target",
        help="a target Drupal version, which enables the upgrade and migration sections",
    )
    project_parser.add_argument("--explain", action="store_true", help="show more detail")
    project_parser.add_argument("--json", action="store_true", help="print the machine-readable result")
    project_parser.set_defaults(func=cmd_project)

    search_parser = sub.add_parser(
        "search", help="search advisories, API lifecycle, rules, knowledge and solved cases"
    )
    search_parser.add_argument("term", help="an identifier, symbol, CVE, module name or phrase")
    search_parser.add_argument(
        "--domain",
        action="append",
        choices=sorted(dk_query.PROJECTORS),
        help=(
            "restrict to a domain; repeatable. Discovery signals are excluded unless "
            "asked for, because they are untrusted."
        ),
    )
    search_parser.add_argument("--limit", type=int, default=20, help="maximum results to return")
    search_parser.add_argument("--explain", action="store_true", help="show provenance for each result")
    search_parser.add_argument("--json", action="store_true", help="print the machine-readable result")
    search_parser.set_defaults(func=cmd_search)

    explain_parser = sub.add_parser(
        "explain", help="explain one record: what it is, what supports it, what is unknown"
    )
    explain_parser.add_argument("id", help="a record identifier from search or a report")
    explain_parser.add_argument("--json", action="store_true", help="print the machine-readable result")
    explain_parser.set_defaults(func=cmd_explain, explain=True)

    provenance_parser = sub.add_parser(
        "provenance", help="trace one record back to the authoritative source behind it"
    )
    provenance_parser.add_argument("id", help="a record identifier from search or a report")
    provenance_parser.add_argument("--json", action="store_true", help="print the machine-readable result")
    provenance_parser.set_defaults(func=cmd_provenance, explain=True)

    return parser






def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )

    # The bare invocation and --help lead with what a developer can ask, not
    # with the maintenance surface.
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(format_root_help(parser, subparsers), end="")
        return 0
    if argv[0] == "--help-maintainer":
        print(format_audience_help(AUDIENCE_MAINTAINER), end="")
        return 0
    if argv[0] == "--help-internal":
        print(format_audience_help(AUDIENCE_INTERNAL), end="")
        return 0
    if argv[0] == "--help-all":
        parser.print_help()
        return 0

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except dk_core.ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
