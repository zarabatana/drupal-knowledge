#!/usr/bin/env python3
"""Targeted source collection CLI.

This is a thin front end over the one knowledge acquisition engine in
``scripts/dk_acquisition.py``. It exists because targeted collection predates
the engine and stays a first-class entry point; it is deliberately not a second
collector. Manual collection, ``dk.py acquire`` and the scheduled CI job all run
the same acquisition code, so there is exactly one behaviour to reason about.

The collector never promotes web text into trusted knowledge. It fetches
registered enabled sources, normalizes content, writes immutable content-
addressed snapshots, advances source state, and emits review-required source
change candidates when a previously baselined source changes.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import dk_acquisition  # noqa: E402
import dk_core  # noqa: E402


# Preserved names for callers that imported the collector's primitives before
# they moved into the engine.
ContentWindowError = dk_acquisition.ContentWindowError
VisibleText = dk_acquisition.VisibleText
apply_content_window = dk_acquisition.apply_content_window
normalized_text = dk_acquisition.normalized_text
fetch_source = dk_acquisition.fetch_source
now_iso = dk_acquisition.now_iso
candidate_kind = dk_acquisition.candidate_kind
MAX_BYTES = dk_acquisition.MAX_BYTES


def resolve_normalized_output(root: Path, value: str | None, dry_run: bool) -> Path | None:
    if value is None:
        return None
    if not dry_run:
        raise dk_core.ValidationError("--normalized-output requires --dry-run")
    return dk_acquisition.resolve_writable_output(root, value, "--normalized-output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect registered Drupal Knowledge sources")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--source", help="collect a single enabled source id")
    group.add_argument("--all", action="store_true", help="collect all enabled sources")
    parser.add_argument("--dry-run", action="store_true", help="fetch and compare without writing")
    parser.add_argument(
        "--normalized-output",
        help="write normalized text for inspection; use with --dry-run for source review",
    )
    parser.add_argument("--timeout", type=int, default=dk_acquisition.DEFAULT_TIMEOUT)
    parser.add_argument("--root", default=str(dk_core.ROOT), help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    try:
        normalized_output = resolve_normalized_output(
            root,
            args.normalized_output,
            args.dry_run,
        )
        run = dk_acquisition.acquire(
            root,
            source_ids=[args.source] if args.source else None,
            all_sources=bool(args.all),
            timeout=args.timeout,
            dry_run=args.dry_run,
            normalized_output=normalized_output,
        )
    except (dk_core.ValidationError, dk_acquisition.AcquisitionInputError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except dk_acquisition.AcquisitionEngineDefect as exc:
        print(f"ACQUISITION_ENGINE_DEFECT: {exc}", file=sys.stderr)
        return 3

    for result in run["results"]:
        if result["error"]:
            print(
                f"{result['source_id']}: ERROR {result['error']['detail']}",
                file=sys.stderr,
            )
            continue
        legacy = dk_acquisition.LEGACY_STATUS_WORDS[result["status"]]
        print(f"{result['source_id']}: {legacy} {result['current_snapshot_sha256']}")

    for defect in run["engine_defects"]:
        print(
            f"{defect['source_id']}: ACQUISITION_ENGINE_DEFECT {defect['detail']}",
            file=sys.stderr,
        )
    return dk_acquisition.run_exit_code(run)


if __name__ == "__main__":
    raise SystemExit(main())
