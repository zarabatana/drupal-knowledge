#!/usr/bin/env python3
"""What `dataset_id` is allowed to mean, and what must never be able to move it.

Drupal Knowledge publishes two identities and they answer different questions::

    VERSION      which release of the product you are running
    dataset_id   which trusted semantic knowledge that release holds

Before this suite existed they were entangled. A source re-fetch that confirmed
every record still correct, a review timestamp, a snapshot digest or a version
bump each minted a new dataset identity, and a new dataset identity was read as
evidence that something had to be published. Routine provenance upkeep was
therefore pushed toward releases it did not need.

The tests below hold the boundary from both sides. Freshness, provenance,
review dates, build metadata and the release version must not move semantic
identity; trusted knowledge itself must. Both halves matter: an identity that
never moves is as useless as one that always does.

Every mutation happens in a throwaway copy of the tree. Nothing here rewrites
the repository, bumps VERSION or touches an immutable snapshot.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import dk_core
import dk_public as P
import dk_query as Q


ROOT = dk_core.ROOT
CLI = ROOT / "scripts" / "dk.py"

BASE = Q.semantic_identity(ROOT)
BASE_ID = BASE["dataset_id"]
BASE_DIGEST = BASE["records_digest"]

failures: list[str] = []


# --- helpers ------------------------------------------------------------------


class Tree:
    """A disposable copy of the repository, addressed by a fresh path.

    A fresh path matters: identity is cached per root, so two mutations of the
    same directory would answer from the first one's cache and every invariance
    test would pass for the wrong reason.
    """

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="dk-identity-"))
        self.root = self.dir / "tree"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(".git", "dist"))

    def __enter__(self) -> Path:
        return self.root

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def identity(root: Path) -> dict:
    return Q.semantic_identity(root)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"{label}=PASS")
    else:
        failures.append(f"{label}: {detail}")
        print(f"{label}=FAIL {detail}")


def invariant(label: str, mutate, *, expect_change: bool) -> None:
    """Mutate one input in a throwaway tree and report the identity effect."""
    with Tree() as root:
        detail = mutate(root)
        got = identity(root)
        moved_id = got["dataset_id"] != BASE_ID
        moved_digest = got["records_digest"] != BASE_DIGEST
        ok = (moved_id and moved_digest) if expect_change else not (moved_id or moved_digest)
        check(
            label,
            ok,
            f"{detail}: dataset_id {'moved' if moved_id else 'held'}, "
            f"records_digest {'moved' if moved_digest else 'held'}, "
            f"expected {'both to move' if expect_change else 'both to hold'}",
        )


def first(*parts: str) -> Path:
    directory = ROOT.joinpath(*parts)
    return sorted(directory.rglob("*.json"))[0].relative_to(ROOT)


# --- the formula itself -------------------------------------------------------
#
# Reproduced from the documented inputs rather than by calling the function
# under test, so a match is evidence the formula is what it claims to be.

import hashlib


def reproduce(root: Path) -> dict:
    payload = dk_core.stable_json(Q.semantic_records(root))
    def digest(label: str) -> str:
        acc = hashlib.sha256()
        for part in (label, payload):
            acc.update(str(part).encode("utf-8"))
            acc.update(b"\0")
        return acc.hexdigest()
    return {
        "records_digest": digest("drupal-knowledge/semantic-records")[:16],
        "dataset_id": "dataset:" + digest("drupal-knowledge/semantic-dataset")[:32],
    }


check("IDENTITY_FORMULA_REPRODUCED", reproduce(ROOT) == BASE, f"{reproduce(ROOT)} != {BASE}")
check(
    "IDENTITY_FIELDS_NOT_SUBSTRINGS",
    BASE_DIGEST not in BASE_ID and BASE_ID.removeprefix("dataset:") not in BASE_DIGEST,
    "one public identity field is a slice of the other",
)
check("DATASET_ID_FORMAT_STABLE", BASE_ID.startswith("dataset:") and len(BASE_ID) == len("dataset:") + 32, BASE_ID)
check("RECORDS_DIGEST_FORMAT_STABLE", len(BASE_DIGEST) == 16 and all(c in "0123456789abcdef" for c in BASE_DIGEST), BASE_DIGEST)
check("PUBLISHED_MANIFEST_CARRIES_SEMANTIC_IDENTITY",
      P.build_dataset(ROOT)[P.MANIFEST_FILE]["dataset_id"] == BASE_ID
      and P.build_dataset(ROOT)[P.MANIFEST_FILE]["records_digest"] == BASE_DIGEST,
      "the published manifest disagrees with the query layer")


# --- A. VERSION invariance ----------------------------------------------------
#
# The whole point. A release that ships a CLI fix over unchanged knowledge must
# publish the same dataset identity. The bump happens in a copy and never in the
# repository.

def bump_version(root: Path) -> str:
    current = (root / "VERSION").read_text(encoding="utf-8").strip()
    (root / "VERSION").write_text("1.1.4\n", encoding="utf-8")
    return f"VERSION {current} -> 1.1.4"


invariant("IDENTITY_INVARIANT_VERSION", bump_version, expect_change=False)
check("VERSION_UNCHANGED_IN_REPOSITORY",
      (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "1.1.3",
      "a test bumped the repository's VERSION")

# A major bump must be no different from a patch bump.
invariant(
    "IDENTITY_INVARIANT_VERSION_MAJOR",
    lambda root: ((root / "VERSION").write_text("9.0.0\n", encoding="utf-8"), "VERSION -> 9.0.0")[1],
    expect_change=False,
)


# --- B. source freshness invariance -------------------------------------------

STATE = sorted((ROOT / "sources" / "state").glob("*.json"))


def touch_last_observed(root: Path) -> str:
    changed = 0
    for path in sorted((root / "sources" / "state").glob("*.json")):
        state = read(path)
        if "acquisition" in state:
            state["acquisition"]["last_success_at"] = "2099-01-01T00:00:00Z"
            state["acquisition"]["last_attempt_at"] = "2099-01-01T00:00:00Z"
            write(path, state)
            changed += 1
    return f"last_success_at advanced on {changed} source state file(s)"


invariant("IDENTITY_INVARIANT_LAST_OBSERVED_AT", touch_last_observed, expect_change=False)


# --- C. source snapshot hash invariance ---------------------------------------
#
# Source state only. The immutable snapshots themselves are never touched: they
# are third-party evidence and rewriting one to make a test pass would be the
# exact failure this repository exists to prevent.

def rewrite_state_snapshot_hash(root: Path) -> str:
    changed = 0
    for path in sorted((root / "sources" / "state").glob("*.json")):
        state = read(path)
        if state.get("content_sha256"):
            state["content_sha256"] = "sha256:" + "0" * 64
            write(path, state)
            changed += 1
    return f"content_sha256 rewritten in {changed} source state file(s)"


invariant("IDENTITY_INVARIANT_SOURCE_SNAPSHOT_HASH", rewrite_state_snapshot_hash, expect_change=False)


def snapshots_untouched() -> bool:
    with Tree() as root:
        rewrite_state_snapshot_hash(root)
        for original in sorted((ROOT / "sources" / "snapshots").rglob("*.txt"))[:40]:
            copy = root / original.relative_to(ROOT)
            if not copy.is_file() or copy.read_bytes() != original.read_bytes():
                return False
    return True


check("IMMUTABLE_SNAPSHOTS_NOT_MUTATED_BY_TESTS", snapshots_untouched(),
      "an identity test altered an immutable upstream snapshot")


# --- D. review timestamp invariance -------------------------------------------

def move_review_dates(root: Path) -> str:
    changed = []
    for path in sorted((root / "rules" / "implementation").rglob("*.json")):
        record = read(path)
        if isinstance(record.get("review"), dict) and "reviewed_on" in record["review"]:
            record["review"]["reviewed_on"] = "2099-01-01"
            write(path, record)
            changed.append("rules/reviewed_on")
    for path in sorted((root / "security" / "advisories").rglob("*.json")):
        record = read(path)
        if isinstance(record.get("provenance"), dict) and "ingested_at" in record["provenance"]:
            record["provenance"]["ingested_at"] = "2099-01-01T00:00:00Z"
            write(path, record)
            changed.append("advisory/ingested_at")
    for path in sorted((root / "api" / "lifecycle").rglob("*.json")):
        record = read(path)
        if isinstance(record.get("provenance"), dict) and "ingested_at" in record["provenance"]:
            record["provenance"]["ingested_at"] = "2099-01-01T00:00:00Z"
            write(path, record)
            changed.append("lifecycle/ingested_at")
    return f"{len(changed)} review/ingestion timestamp(s) moved to 2099"


invariant("IDENTITY_INVARIANT_REVIEW_TIMESTAMP", move_review_dates, expect_change=False)


# --- E. build metadata invariance ---------------------------------------------
#
# The dataset is built from a root and nothing else: there is no clock and no
# commit to pass it. Proven structurally and then by building the real site
# twice with different build metadata.

check("DATASET_BUILD_TAKES_NO_CLOCK",
      "built_at" not in P.build_dataset.__code__.co_varnames
      and "commit" not in P.build_dataset.__code__.co_varnames,
      "the dataset build accepts build metadata")

check("BUILD_INFO_OUTSIDE_DATASET",
      not any("build-info" in str(path) for path in P.dataset_bytes(ROOT)),
      "build-info.json is inside the dataset")


def site_build_identity(commit: str, built_at: str) -> tuple[str, str]:
    with Tree() as root:
        subprocess.run(
            [sys.executable, str(root / "scripts" / "dk.py"), "public-site", "build",
             "--commit", commit, "--built-at", built_at],
            cwd=root, check=True, capture_output=True, text=True,
        )
        manifest = read(root / "public-site" / "dataset" / "manifest.json")
        info = read(root / "public-site" / "dist" / "build-info.json")
        return manifest["dataset_id"], info["commit"]


left = site_build_identity("1111111111111111111111111111111111111111", "2026-01-01T00:00:00Z")
right = site_build_identity("2222222222222222222222222222222222222222", "2099-12-31T23:59:59Z")
check("IDENTITY_INVARIANT_BUILD_METADATA",
      left[0] == right[0] == BASE_ID and left[1] != right[1],
      f"{left} vs {right}")


# --- F. semantic mutation sensitivity -----------------------------------------

def change_advisory(root: Path) -> str:
    path = root / first("security", "advisories")
    record = read(path)
    record["advisory"]["vulnerability_type"] = "Changed by the identity suite"
    write(path, record)
    return f"{path.name} advisory.vulnerability_type changed"


def change_knowledge(root: Path) -> str:
    path = root / first("knowledge", "records")
    record = read(path)
    record["summary"] = record["summary"] + " Changed by the identity suite."
    write(path, record)
    return f"{path.name} summary changed"


def change_rule(root: Path) -> str:
    path = root / first("rules", "implementation")
    record = read(path)
    record["review"]["status"] = "provisional"
    write(path, record)
    return f"{path.name} review.status changed"


invariant("IDENTITY_SENSITIVE_ADVISORY_CONTENT", change_advisory, expect_change=True)
invariant("IDENTITY_SENSITIVE_KNOWLEDGE_CONTENT", change_knowledge, expect_change=True)
invariant("IDENTITY_SENSITIVE_RULE_REVIEW_STATUS", change_rule, expect_change=True)


# --- G. add and remove a semantic record --------------------------------------

def remove_knowledge(root: Path) -> str:
    path = root / first("knowledge", "records")
    path.unlink()
    return f"removed {path.name}"


def add_knowledge(root: Path) -> str:
    path = root / first("knowledge", "records")
    record = read(path)
    record["id"] = record["id"] + ".identity-suite-clone"
    record["title"] = record["title"] + " (clone)"
    write(path.with_name(path.stem + "-identity-suite-clone.json"), record)
    return f"added a clone of {path.name}"


invariant("IDENTITY_SENSITIVE_RECORD_REMOVED", remove_knowledge, expect_change=True)
invariant("IDENTITY_SENSITIVE_RECORD_ADDED", add_knowledge, expect_change=True)


# --- non-trusted discovery material -------------------------------------------
#
# Discovery signals, candidates and corroboration dossiers are explicitly not
# trusted knowledge. Holding one must not change what the release knows.

def add_discovery_signal(root: Path) -> str:
    path = sorted((root / "discovery" / "signals").rglob("*.json"))[0]
    signal = read(path)
    for key in ("id", "signal_id"):
        if key in signal:
            signal[key] = str(signal[key]) + ".identity-suite-clone"
    write(path.with_name(path.stem + "-identity-suite-clone.json"), signal)
    return "one untrusted discovery signal added"


def add_acquisition_candidate(root: Path) -> str:
    candidates = sorted((root / "discovery" / "candidates").rglob("*.json"))
    if not candidates:
        return "no acquisition candidates present"
    candidate = read(candidates[0])
    if "id" in candidate:
        candidate["id"] = str(candidate["id"]) + ".identity-suite-clone"
    write(candidates[0].with_name(candidates[0].stem + "-identity-suite-clone.json"), candidate)
    return "one untrusted acquisition candidate added"


invariant("IDENTITY_EXCLUDES_DISCOVERY_SIGNAL", add_discovery_signal, expect_change=False)
invariant("IDENTITY_EXCLUDES_ACQUISITION_CANDIDATE", add_acquisition_candidate, expect_change=False)

check("DISCOVERY_NOT_A_SEMANTIC_DOMAIN",
      Q.D_DISCOVERY_SIGNAL not in Q.SEMANTIC_DOMAINS,
      "discovery signals are a semantic identity input")
check("SEMANTIC_DOMAINS_ARE_THE_PUBLISHED_DOMAINS",
      tuple(Q.SEMANTIC_DOMAINS) == tuple(P.PUBLIC_DOMAINS),
      f"{Q.SEMANTIC_DOMAINS} != {P.PUBLIC_DOMAINS}")


# --- H. deterministic ordering ------------------------------------------------
#
# Identity is a property of the records, not of how a filesystem happened to
# list them. Renaming the files that carry them changes nothing.

def rename_record_files(root: Path) -> str:
    renamed = 0
    for path in sorted((root / "knowledge" / "records").rglob("*.json")):
        path.rename(path.with_name("zzz-reordered-" + path.name))
        renamed += 1
    return f"{renamed} knowledge record file(s) renamed"


invariant("IDENTITY_INVARIANT_FILE_ORDER", rename_record_files, expect_change=False)

check("SEMANTIC_PAYLOAD_IS_SORTED",
      [(e["domain"], e["id"]) for e in Q.semantic_records(ROOT)]
      == sorted((e["domain"], e["id"]) for e in Q.semantic_records(ROOT)),
      "the semantic payload is not canonically ordered")

repeated = [Q.semantic_identity(Tree().root)["dataset_id"] for _ in range(2)]
check("IDENTITY_DETERMINISTIC_ACROSS_TREES", repeated[0] == repeated[1] == BASE_ID, str(repeated))


# --- the documented valid states ----------------------------------------------
#
# Section by section, the three states the release policy calls valid.

with Tree() as root:
    # Product-only patch: a release over unchanged knowledge.
    (root / "VERSION").write_text("1.2.1\n", encoding="utf-8")
    check("VALID_STATE_PRODUCT_ONLY_PATCH", identity(root)["dataset_id"] == BASE_ID,
          "a product-only release changed the dataset identity")

with Tree() as root:
    # Provenance refresh: same version, newer evidence of the same knowledge.
    touch_last_observed(root)
    rewrite_state_snapshot_hash(root)
    check("VALID_STATE_PROVENANCE_REFRESH", identity(root)["dataset_id"] == BASE_ID,
          "a provenance refresh changed the dataset identity")

with Tree() as root:
    # Trusted knowledge update: the one thing that must move it.
    change_knowledge(root)
    check("VALID_STATE_TRUSTED_KNOWLEDGE_UPDATE", identity(root)["dataset_id"] != BASE_ID,
          "changed trusted knowledge left the dataset identity alone")


# --- provenance is preserved, not discounted ----------------------------------
#
# The simplification is that provenance is not identity. It is emphatically not
# that provenance may be dropped.

published_sources = P.build_dataset(ROOT)[P.SOURCES_FILE]["sources"]
check("SOURCE_FRESHNESS_STILL_PUBLISHED",
      all("last_observed_at" in entry and "snapshot_sha256" in entry for entry in published_sources)
      and any(entry["last_observed_at"] for entry in published_sources),
      "the published source directory lost its freshness evidence")

manifest = P.build_dataset(ROOT)[P.MANIFEST_FILE]
for field in ("dk_version", "generated_from_release", "records_digest", "dataset_id",
              "source_freshness_summary"):
    check(f"MANIFEST_STILL_PUBLISHES_{field.upper()}", field in manifest, f"{field} disappeared")

check("RECORD_PROVENANCE_STILL_CARRIES_SNAPSHOT_DIGESTS",
      any(step.get("snapshot_sha256")
          for record in P.build_dataset(ROOT)["domains/security.json"]["records"]
          for step in record["provenance"]),
      "published advisories lost their snapshot digests")


# --- report -------------------------------------------------------------------

print()
print(f"SEMANTIC_RECORDS={len(Q.semantic_records(ROOT))}")
print(f"RECORDS_DIGEST={BASE_DIGEST}")
print(f"DATASET_ID={BASE_ID}")
if failures:
    print()
    for line in failures:
        print("FAILED:", line)
    raise SystemExit(f"SEMANTIC_DATASET_IDENTITY={len(failures)}_FAILURE(S)")
print("SEMANTIC_DATASET_IDENTITY=PASS")
