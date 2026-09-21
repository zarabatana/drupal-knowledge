#!/usr/bin/env python3
"""Solved-case capture behaviour invariants.

Proves that a solved case stays what it is: proof that a solution worked in
one concrete context. It never becomes Drupal truth, never promotes itself,
never claims applicability beyond its evidence, and never accepts "it is
fixed" as verification.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import dk_core
import dk_solved_case


ROOT = dk_core.ROOT
FIXTURE = ROOT / "tests" / "fixtures" / "solved-case" / "toolchain-module-resolution.candidate.json"


def load_candidate() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def fingerprint(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def temp_root() -> tempfile.TemporaryDirectory:
    """A disposable Drupal Knowledge tree so capture never touches canonical data."""
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    for directory in ("knowledge", "schema", "sources", "taxonomy"):
        shutil.copytree(
            ROOT / directory,
            root / directory,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    (root / "cases" / "solved").mkdir(parents=True)
    shutil.copy2(ROOT / "cases" / "README.md", root / "cases" / "README.md")
    shutil.copy2(ROOT / "cases" / "solved" / "README.md", root / "cases" / "solved" / "README.md")
    return temp


def rejects(mutate, expected: str) -> None:
    candidate = load_candidate()
    mutate(candidate)
    try:
        dk_solved_case.validate_candidate(candidate)
    except (dk_solved_case.SolvedCaseValidationError, dk_core.ValidationError) as exc:
        assert expected.lower() in str(exc).lower(), f"expected {expected!r}, got {exc}"
        return
    raise AssertionError(f"validator accepted an unsafe candidate: {expected}")


candidate = load_candidate()


# --- a candidate is a candidate, never trusted knowledge ---------------------
assert dk_solved_case.validate_candidate(candidate) == [
    "SOLVED_CASE_CANDIDATE_VALID=PASS",
    "SOLVED_CASE_CANDIDATE_STATE=captured",
]
schema = dk_core.read_json(ROOT / "schema" / "solved-case-candidate.schema.json")
assert schema["properties"]["state"]["enum"] == ["captured", "verified"]
assert "promotion" not in schema["properties"], "a producer must not be able to request promotion"
assert "universal_rule" not in schema["properties"]
# A case record is not a knowledge record: the two contracts stay disjoint.
knowledge_schema = dk_core.read_json(ROOT / "schema" / "knowledge-record.schema.json")
assert "machine_finding" not in schema["properties"]
assert "capture" not in knowledge_schema["properties"]


# --- captured is not verified ------------------------------------------------
record = dk_solved_case.build_case_record(candidate)
assert record["status"] == "captured"
assert record["last_verified"] == "not_verified"
assert record["capture"]["promotion"] == {
    "automatic_promotion": False,
    "human_review_required": True,
    "trusted_knowledge_created": False,
}


# --- verification requires evidence, never an assertion ---------------------
claim_only = copy.deepcopy(candidate)
claim_only["state"] = "verified"
claim_only["verification"] = {
    "performed": True,
    "results": [],
    "causality": {"state": "demonstrated", "statement": "We fixed it and it works now."},
}
try:
    dk_solved_case.validate_candidate(claim_only)
except dk_solved_case.SolvedCaseValidationError as exc:
    assert "actually passed" in str(exc)
else:
    raise AssertionError("a bare claim must never verify a case")

not_performed = copy.deepcopy(candidate)
not_performed["state"] = "verified"
not_performed["verification"]["performed"] = False
try:
    dk_solved_case.validate_candidate(not_performed)
except dk_solved_case.SolvedCaseValidationError:
    pass
else:
    raise AssertionError("verified requires verification to have been performed")

failed_only = copy.deepcopy(candidate)
failed_only["state"] = "verified"
for result in failed_only["verification"]["results"]:
    result["outcome"] = "inconclusive"
try:
    dk_solved_case.validate_candidate(failed_only)
except dk_solved_case.SolvedCaseValidationError:
    pass
else:
    raise AssertionError("inconclusive results must not verify a case")


# --- applicability is bounded by evidence ------------------------------------
rejects(
    lambda c: c["applicability"]["proven_on"].__setitem__(
        "drupal_core_versions", ["10.3.0", "11.4.5", "12.0.0"]
    ),
    "only list Drupal core versions the case was actually proven on",
)
rejects(
    lambda c: c["applicability"].__setitem__("claimed_scope", "all_drupal_projects"),
    "proven_context_only",
)
rejects(
    lambda c: c["applicability"].__setitem__("expansion_requires_review", False),
    "expansion must always require review",
)
rejects(
    lambda c: c["applicability"]["proven_on"].__setitem__("drupal_core_versions", ["10.3.0"]),
    "must include the Drupal core version the case was actually observed on",
)


# --- limitations are mandatory and preserved ---------------------------------
rejects(lambda c: c.__setitem__("limitations", []), "non-empty list")
assert record["limitations"] == candidate["limitations"]


# --- root cause may honestly be unknown --------------------------------------
unknown_cause = copy.deepcopy(candidate)
unknown_cause["root_cause"] = {
    "state": "unknown",
    "statement": "The root cause is unknown; the trigger could not be isolated from the available evidence.",
}
assert dk_solved_case.validate_candidate(unknown_cause)[0] == "SOLVED_CASE_CANDIDATE_VALID=PASS"
# but an unknown cause may not be dressed up as an explanation
rejects_unknown = copy.deepcopy(candidate)
rejects_unknown["root_cause"] = {
    "state": "unknown",
    "statement": "A stale cache entry caused the failure in every case.",
}
try:
    dk_solved_case.validate_candidate(rejects_unknown)
except dk_solved_case.SolvedCaseValidationError as exc:
    assert "explicitly" in str(exc)
else:
    raise AssertionError("an unknown root cause must not assert an explanation")
# a confirmed cause needs supporting evidence
rejects(
    lambda c: c["root_cause"].pop("evidence_refs"),
    "requires evidence references",
)


# --- project identity is minimized -------------------------------------------
rejects(
    lambda c: c["project_context"].__setitem__("project_fingerprint", "acme-customer-production"),
    "sha256 fingerprint, never a name or path",
)
serialized = dk_solved_case.stable_json(record)
assert "/Users/" not in serialized
assert "@" not in record["problem"]


# --- obvious secret material is rejected -------------------------------------
secret_cases = [
    ("credential token", lambda c: c["problem"]["symptoms"].append("token glpat-AbCdEfGhIjKlMnOpQrSt")),
    ("private key", lambda c: c["fix"]["changes"][0].__setitem__("summary", "-----BEGIN PRIVATE KEY----- redacted")),
    ("inline credential", lambda c: c["problem"]["symptoms"].append("db password: hunter2secret")),
    ("credential in url", lambda c: c["problem"]["symptoms"].append("https://user:pass@example.invalid/repo.git")),
    ("machine path", lambda c: c["fix"]["changes"][0].__setitem__("summary", "Edited /Users/someone/site/web/index.php")),
    ("personal contact", lambda c: c["problem"]["symptoms"].append("reported by person@example.com")),
]
for label, mutate in secret_cases:
    dirty = load_candidate()
    mutate(dirty)
    try:
        dk_solved_case.validate_candidate(dirty)
    except dk_solved_case.SolvedCaseSecretError:
        pass
    else:
        raise AssertionError(f"{label} must be rejected, never stored")


# --- capture is idempotent, and distinct projects stay distinct ---------------
with temp_root() as temp:
    root = Path(temp)
    first = dk_solved_case.capture(load_candidate(), root=root)
    assert first["result"] == "created" and first["state"] == "captured"
    second = dk_solved_case.capture(load_candidate(), root=root)
    assert second["result"] == "unchanged", "recapturing identical evidence must not duplicate"
    assert second["case_id"] == first["case_id"]
    assert len(list((root / "cases" / "solved").glob("*.json"))) == 1

    # The same problem on another project is a separate case, not the same
    # occurrence: recurrence is later evidence, never a silent merge.
    other_project = load_candidate()
    other_project["project_context"]["project_fingerprint"] = fingerprint("a-different-project")
    third = dk_solved_case.capture(other_project, root=root)
    assert third["case_id"] != first["case_id"], "a different project must not collapse into the same case"
    assert len(list((root / "cases" / "solved").glob("*.json"))) == 2
    for stored in (root / "cases" / "solved").glob("*.json"):
        assert json.loads(stored.read_text(encoding="utf-8"))["occurrence_count"] == 1, (
            "one capture is one occurrence; recurrence is never inferred"
        )

    # Provenance survives the roundtrip in machine-readable form.
    read_back = dk_solved_case.load_case(root, first["case_id"])
    capture_block = read_back["capture"]
    assert capture_block["case_identity"] == first["case_identity"]
    assert capture_block["producer"] == candidate["producer"]
    assert capture_block["captured_by"]["name"] == dk_solved_case.CAPTURE_NAME
    assert capture_block["contract_version"] == dk_solved_case.CASE_CONTRACT_VERSION
    assert capture_block["root_cause_state"] == "confirmed"
    assert isinstance(capture_block["verification"], dict)
    assert read_back["limitations"] == candidate["limitations"]
    assert read_back["applicability"]["claimed_scope"] == "proven_context_only"

    # captured -> verified requires evidence, and stays short of promotion.
    try:
        dk_solved_case.verify_case(
            first["case_id"],
            {"performed": True, "results": [], "causality": {"state": "demonstrated", "statement": "It is fixed now."}},
            root=root,
        )
    except dk_solved_case.SolvedCaseValidationError:
        pass
    else:
        raise AssertionError("verification without evidence must fail")

    verified = dk_solved_case.verify_case(
        first["case_id"],
        {
            "performed": True,
            "results": [{"method": "automated_test", "outcome": "passed", "evidence_ref": "suite run"}],
            "causality": {
                "state": "demonstrated",
                "statement": "The suite failed before the change and passed after it.",
            },
        },
        root=root,
    )
    assert verified["state"] == "verified"
    assert verified["promoted_to_knowledge"] is False
    after = dk_solved_case.load_case(root, first["case_id"])
    assert after["status"] == "verified"
    assert after["capture"]["promotion"]["trusted_knowledge_created"] is False

    # Verifying created no knowledge record and no source. The tree digest is
    # path-sensitive, so compare canonical content rather than absolute paths.
    def knowledge_content(tree: Path) -> str:
        return dk_core.stable_json(
            sorted(dk_core.load_knowledge_records(tree), key=lambda item: item["id"])
        )

    assert knowledge_content(root) == knowledge_content(ROOT), (
        "capturing a solved case must not change any knowledge record"
    )
    assert dk_core.stable_json(dk_core.load_sources(root)) == dk_core.stable_json(dk_core.load_sources(ROOT))


# --- a case may exist without an originating finding -------------------------
no_finding = load_candidate()
assert "origin_finding_id" not in no_finding["problem"]
assert dk_solved_case.validate_candidate(no_finding)[0] == "SOLVED_CASE_CANDIDATE_VALID=PASS"

# --- and preserves the finding identity when it has one ----------------------
from_finding = load_candidate()
finding_id = "sha256:" + "a" * 64
from_finding["problem"]["origin_finding_id"] = finding_id
assert dk_solved_case.validate_candidate(from_finding)[0] == "SOLVED_CASE_CANDIDATE_VALID=PASS"
finding_record = dk_solved_case.build_case_record(from_finding)
assert finding_record["capture"]["origin_finding_id"] == finding_id
assert finding_record["id"] != record["id"], "finding origin participates in case identity"
rejects(
    lambda c: c["problem"].__setitem__("origin_finding_id", "F-123"),
    "deterministic finding identity",
)


# --- causality is not overclaimed --------------------------------------------
assert candidate["verification"]["causality"]["state"] in dk_solved_case.CAUSALITY_STATES
weak = copy.deepcopy(candidate)
weak["verification"]["causality"] = {
    "state": "consistent_with_evidence",
    "statement": "The symptom stopped after the change, but other changes could also explain it.",
}
assert dk_solved_case.validate_candidate(weak)[0] == "SOLVED_CASE_CANDIDATE_VALID=PASS"
rejects(
    lambda c: c["verification"]["causality"].__setitem__("state", "proven_universally"),
    "causality.state must be one of",
)


# --- capture never enters a later lifecycle state ----------------------------
for later in ("recurring", "generalization_proposed", "promoted_to_knowledge_proposal"):
    rejects(lambda c, s=later: c.__setitem__("state", s), "capture supports only")
stored_schema = dk_core.read_json(ROOT / "schema" / "solved-case.schema.json")
assert "recurring" in stored_schema["properties"]["status"]["enum"], (
    "the canonical lifecycle keeps later states; capture simply never reaches them"
)
promotion_schema = stored_schema["properties"]["capture"]["properties"]["promotion"]["properties"]
assert promotion_schema["automatic_promotion"]["const"] is False
assert promotion_schema["human_review_required"]["const"] is True
assert promotion_schema["trusted_knowledge_created"]["const"] is False


# --- an external producer cannot write trusted knowledge ---------------------
capture_source = (ROOT / "scripts" / "dk_solved_case.py").read_text(encoding="utf-8")
assert "knowledge/records" not in capture_source
assert "sources/registry" not in capture_source
assert str(dk_solved_case.CASES_RELATIVE_PATH) == "cases/solved"
for forbidden in ("write_snapshot", "write_generated"):
    assert forbidden not in capture_source, f"capture must not call {forbidden}"


# --- the released CLI exposes capture without an auto-promote path -----------
cli_source = (ROOT / "scripts" / "dk.py").read_text(encoding="utf-8")
assert "solved-case" in cli_source
for forbidden in ("auto-promote", "auto_promote", "--promote"):
    assert forbidden not in cli_source, f"the CLI must not expose {forbidden}"
version_payload = json.loads(
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "version"],
        check=True, capture_output=True, text=True,
    ).stdout
)
assert version_payload["interfaces"]["solved_case_candidate_schema"] == "0.1"

with tempfile.TemporaryDirectory() as temp:
    bad = Path(temp) / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "solved-case", "validate", str(bad)],
        check=False, capture_output=True, text=True,
    )
    assert run.returncode == 1
    missing = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dk.py"), "solved-case", "validate", str(Path(temp) / "nope.json")],
        check=False, capture_output=True, text=True,
    )
    assert missing.returncode == 2


print("SOLVED_CASE_IS_NOT_TRUSTED_KNOWLEDGE=PASS")
print("SOLVED_CASE_CAPTURE_MINIMIZES_PROJECT_IDENTITY=PASS")
print("SOLVED_CASE_VERIFICATION_REQUIRES_EVIDENCE=PASS")
print("SOLVED_CASE_APPLICABILITY_IS_EVIDENCE_BOUNDED=PASS")
print("SOLVED_CASE_LIMITATIONS_PRESERVED=PASS")
print("CAPTURED_CASE_NOT_AUTOMATICALLY_VERIFIED=PASS")
print("VERIFIED_CASE_NOT_AUTOMATICALLY_PROMOTED=PASS")
print("SOLVED_CASE_PROVENANCE_MACHINE_READABLE=PASS")
print("SOLVED_CASE_CAPTURE_IDEMPOTENT=PASS")
print("SOLVED_CASE_CAPTURE_AVAILABLE_VIA_RELEASED_DK_INTERFACE=PASS")
print("EXTERNAL_PRODUCER_CANNOT_WRITE_TRUSTED_KNOWLEDGE_DIRECTLY=PASS")
print("SOLVED_CASE_CAUSALITY_NOT_OVERCLAIMED=PASS")
print("SOLVED_CASE_CAPTURE_REJECTS_OBVIOUS_SECRET_MATERIAL=PASS")
print("SOLVED_CASE_UNKNOWN_ROOT_CAUSE_ALLOWED=PASS")
print("SOLVED_CASE_WITHOUT_ORIGIN_FINDING_ALLOWED=PASS")
print("SOLVED_CASE_ORIGIN_FINDING_PRESERVED=PASS")
print("SIMILAR_CASE_ON_ANOTHER_PROJECT_NOT_COLLAPSED=PASS")
print("SOLVED_CASE_CAPTURE_DOES_NOT_MUTATE_TRUSTED_KNOWLEDGE=PASS")
