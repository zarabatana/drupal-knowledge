#!/usr/bin/env python3
"""Project analyzer output and schema compatibility checks."""

from __future__ import annotations

import dk_core
import dk_project_analyzer


fixture = dk_core.ROOT / "tests" / "fixtures" / "project-analyzer" / "recommended"
analysis = dk_project_analyzer.analyze_project(fixture)
assert analysis.exit_code == 0
messages = dk_project_analyzer.validate_project_analysis(analysis.data)
assert messages == ["PROJECT_ANALYSIS_SCHEMA_VALID=PASS"]

dk_project_analyzer.assert_project_profile_schema_backward_compatible()
dk_project_analyzer.assert_project_evidence_schema_backward_compatible()

legacy_profile = {
    "schema_version": "0.1",
    "project_id": "legacy-profile",
    "facts": {name: {"state": "unknown"} for name in dk_project_analyzer.BASE_FACTS},
}
dk_project_analyzer.validate_project_profile(legacy_profile)

legacy_evidence = {
    "schema_version": "0.1",
    "id": "evidence.drupal.legacy",
    "project_id": "legacy-profile",
    "kind": "composer_json",
    "observed_at": "2026-08-30",
    "collector": "legacy",
    "path": "composer.json",
    "content_sha256": "sha256:" + "0" * 64,
    "facts_supported": ["composer_packages"],
    "summary": "Legacy evidence shape without analyzer provenance additions.",
}
dk_project_analyzer.validate_project_evidence(legacy_evidence)

for relative in (
    "schema/project-analysis.schema.json",
    "schema/project-profile.schema.json",
    "schema/project-evidence.schema.json",
):
    dk_core.read_json(dk_core.ROOT / relative)

print("PROJECT_ANALYSIS_SCHEMA_VALID=PASS")
print("PROJECT_SCHEMA_BACKWARD_COMPATIBLE=PASS")
