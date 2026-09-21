#!/usr/bin/env python3
"""Applicability resolution schema and CLI smoke checks."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_applicability
import dk_core
import dk_project_analyzer


ROOT = dk_core.ROOT
FIXTURES = ROOT / "tests" / "fixtures" / "project-analyzer"


analysis = dk_project_analyzer.analyze_project(FIXTURES / "recommended").data
resolution = dk_applicability.resolve_analysis_data(analysis)
assert dk_applicability.validate_resolution_output(resolution) == [
    "RESOLUTION_OUTPUT_SCHEMA_VALID=PASS"
]

schema = dk_core.read_json(ROOT / "schema" / "applicability-resolution.schema.json")
assert schema["properties"]["schema_version"]["const"] == "0.1"
assert schema["properties"]["resolver"]["properties"]["name"]["const"] == dk_applicability.RESOLVER_NAME
assert schema["properties"]["results"]["type"] == "array"
assert "applicable" in schema["properties"]["results"]["items"]["properties"]["applicability"]["enum"]

with tempfile.TemporaryDirectory() as workspace:
    analysis_path = Path(workspace) / "analysis.json"
    analysis_path.write_text(dk_project_analyzer.stable_json(analysis), encoding="utf-8")
    first = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "resolve", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "resolve", str(analysis_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert first.stdout == second.stdout
    cli_resolution = json.loads(first.stdout)
    assert cli_resolution == resolution
    dk_applicability.validate_resolution_output(cli_resolution)

print("RESOLUTION_OUTPUT_SCHEMA_VALID=PASS")
