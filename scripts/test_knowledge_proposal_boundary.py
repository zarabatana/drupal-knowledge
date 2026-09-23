#!/usr/bin/env python3
"""A reviewed proposal is the only way evidence becomes a record.

The acquisition engine observes sources. It never promotes. Between an
observation and a published record stands one human decision, recorded in a
review artifact, and these tests hold that gap open from both sides:

    candidate                -> can never promote itself
    decided PROMOTE          -> the record exists and cites its snapshot
    decided REJECT / RETAIN  -> no record exists
    review metadata alone    -> semantic identity unmoved
    promoted record          -> semantic identity moved

The last two are the pair that matters. Deciding is not publishing, and
publishing must not be silent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import dk_core
import dk_query
import dk_security


ROOT = dk_core.ROOT
REVIEW = ROOT / "docs" / "security-knowledge-review-2026-09-23.json"
CANDIDATES = ROOT / "discovery" / "candidates"
ADVISORIES = ROOT / "security" / "advisories"

DECISIONS = {
    "PROMOTE_TO_TRUSTED_KNOWLEDGE",
    "UPDATE_TRUSTED_KNOWLEDGE",
    "RETAIN_AS_PROPOSAL",
    "NEEDS_MORE_EVIDENCE",
    "DUPLICATE_NO_CHANGE",
    "REJECT_PROPOSAL",
}
PUBLISHING = {"PROMOTE_TO_TRUSTED_KNOWLEDGE", "UPDATE_TRUSTED_KNOWLEDGE"}


def advisory_ids() -> set[str]:
    return {path.stem for path in dk_core.iter_json_files(ADVISORIES)}


# --- A. a candidate cannot promote itself -------------------------------------

candidates = [dk_core.read_json(p) for p in dk_core.iter_json_files(CANDIDATES)]
assert candidates, "no source-change candidates found"
for candidate in candidates:
    where = candidate["id"]
    assert candidate["can_promote_to_knowledge"] is False, where
    assert candidate["is_knowledge_proposal"] is False, where
    assert candidate["review_required"] is True, where
    review = candidate.get("review")
    if review is not None:
        assert review["trusted_knowledge_changed"] is False, where

print("SOURCE_CANDIDATE_CANNOT_AUTO_PROMOTE=PASS")


# --- B. every proposal carries exactly one recorded human decision -------------

review = json.loads(REVIEW.read_text(encoding="utf-8"))
decided = [d["candidate_id"] for d in review["decisions"]]
assert len(decided) == len(set(decided)), "a proposal was decided twice"

queued = {
    c["id"]
    for c in candidates
    if c["review_state"] == "reviewed_requires_knowledge_proposal"
}
assert queued, "no proposals in the reviewed queue"
assert queued == set(decided), (
    "the review artifact does not decide exactly the reviewed proposal queue: "
    f"undecided={sorted(queued - set(decided))} extra={sorted(set(decided) - queued)}"
)
for decision in review["decisions"]:
    assert decision["decision"] in DECISIONS, decision["decision"]
    assert decision["rationale"].strip(), decision["candidate_id"]
    assert decision["evidence_references"], decision["candidate_id"]
    assert decision["next_action"].strip(), decision["candidate_id"]
assert review["reviewer"].strip()
assert review["reviewed_on"].strip()

print("PROPOSAL_REVIEW_CANNOT_BYPASS_HUMAN_DECISION=PASS")


# --- C. approved proposals entered the trusted domain -------------------------

stored = advisory_ids()
promoted: set[str] = set()
for decision in review["decisions"]:
    published = list(decision.get("records_created", [])) + list(
        decision.get("records_updated", [])
    )
    if decision["decision"] in PUBLISHING:
        assert published, f"{decision['candidate_id']} promotes nothing"
        for identifier in published:
            assert identifier in stored, f"{identifier} was approved but is not stored"
        promoted.update(published)
    else:
        assert not published, (
            f"{decision['candidate_id']} is {decision['decision']} but names records"
        )
assert promoted, "no records were promoted"

print("APPROVED_PROPOSAL_ENTERS_TRUSTED_DOMAIN=PASS")


# --- D. rejected and retained proposals entered nothing ------------------------

for decision in review["decisions"]:
    if decision["decision"] in PUBLISHING:
        continue
    for identifier in decision.get("observed_not_promoted", []):
        assert identifier not in stored, (
            f"{identifier} was {decision['decision']} but a record exists"
        )

# The rejected public service announcement is not carried as a vulnerability.
for path in dk_core.iter_json_files(ADVISORIES):
    record = dk_core.read_json(path)
    assert record["advisory"]["is_psa"] is False, f"{path.stem} is a PSA record"
    assert "psa-2026-09-21" not in record["advisory"]["canonical_url"].lower()

print("REJECTED_AND_RETAINED_PROPOSALS_ENTER_NOTHING=PASS")


# --- E. every promoted record cites reviewed immutable evidence ----------------

without_evidence = []
for identifier in sorted(promoted):
    record = dk_core.read_json(ADVISORIES / f"{identifier}.json")
    provenance = record["provenance"]
    snapshot = provenance["source_snapshot_sha256"]
    path = dk_core.require_snapshot(ROOT, provenance["source_id"], snapshot)
    if not path.is_file():
        without_evidence.append(identifier)
        continue
    # The record must be reproducible from that snapshot, not merely near it.
    nodes = dk_security.parse_advisory_feed(path.read_text(encoding="utf-8"))
    identities = {dk_security.advisory_identity(node)[0] for node in nodes}
    if identifier not in identities:
        without_evidence.append(identifier)
assert not without_evidence, f"records without source evidence: {without_evidence}"

print(f"TRUSTED_RECORD_WITHOUT_SOURCE_EVIDENCE={len(without_evidence)}")


# --- F. no record claims a site or an installed project is vulnerable ----------

FORBIDDEN = (
    "this site is vulnerable",
    "your site is vulnerable",
    "is affected",
    "installed project is affected",
)
for path in dk_core.iter_json_files(ADVISORIES):
    record = dk_core.read_json(path)
    blob = dk_core.stable_json(record).lower()
    for phrase in FORBIDDEN:
        assert phrase not in blob, f"{path.stem} claims applicability: {phrase!r}"
    assert record["is_trusted_knowledge"] is False, path.stem
    assert record["enforcement"]["automatically_blocking"] is False, path.stem
    assert record["severity"]["scored_by_drupal_knowledge"] is False, path.stem
    assert record["cves"]["inferred"] is False, path.stem
    assert record["remediation"]["authored_by_drupal_knowledge"] is False, path.stem

print("SECURITY_KNOWLEDGE_IS_NOT_AN_APPLICABILITY_RESULT=PASS")


# --- G. review metadata alone does not move semantic identity ------------------
#
# Proven by construction rather than by editing the tree: the review artifact
# lives outside every semantic record store, so no projection can read it.

semantic_stores = {
    "knowledge/records",
    "security/advisories",
    "api/lifecycle",
    "api/change-records",
    "rules/implementation",
    "cases/solved",
}
relative = REVIEW.relative_to(ROOT).as_posix()
assert not any(relative.startswith(store) for store in semantic_stores), relative
assert "docs/" not in dk_core.stable_json(
    [entry["provenance"] for entry in dk_query.semantic_records(ROOT)]
), "a semantic record cites the review artifact"

baseline = dk_query.semantic_identity(ROOT)
again = dk_query.semantic_identity(ROOT)
assert baseline == again, "semantic identity is not stable across calls"

print("REVIEW_METADATA_DOES_NOT_MOVE_SEMANTIC_IDENTITY=PASS")


# --- H. a promoted record does move semantic identity -------------------------
#
# Removing any one promoted record from the projected payload must change both
# published identity fields. Computed on the payload, so the tree is not edited.

records = dk_query.semantic_records(ROOT)
present = {(entry["domain"], entry["id"]) for entry in records}
sample = sorted(promoted)[0]
assert ("advisory", sample) in present, sample

reduced = [e for e in records if not (e["domain"] == "advisory" and e["id"] == sample)]
assert len(reduced) == len(records) - 1

full_payload = dk_core.stable_json(records)
cut_payload = dk_core.stable_json(reduced)


def digest(label: str, payload: str) -> str:
    return dk_query.digest_hex(label, payload)


assert digest(dk_query._RECORDS_DIGEST_LABEL, full_payload) != digest(
    dk_query._RECORDS_DIGEST_LABEL, cut_payload
), "dropping a promoted record left records_digest unchanged"
assert digest(dk_query._DATASET_ID_LABEL, full_payload) != digest(
    dk_query._DATASET_ID_LABEL, cut_payload
), "dropping a promoted record left dataset_id unchanged"

print("APPROVED_SEMANTIC_CHANGE_MOVES_DATASET_IDENTITY=PASS")

print(f"PROPOSALS_DECIDED={len(decided)} PROMOTED_RECORDS={len(promoted)}")
