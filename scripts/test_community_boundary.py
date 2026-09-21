#!/usr/bin/env python3
"""The Community boundary: this repository depends on nothing private.

Drupal Knowledge Community is the Core. A separately governed hosted product
may depend on a tagged release of this repository; this repository may never
depend on it. The dependency points one way, and this test is the place that
direction is enforced rather than described.

Four scans, all static, all over the whole tracked tree:

1. Import scan. No module under scripts/ or collectors/ imports a hosted,
   VDA or other private module, by any name and by any import form.
2. Route scan. The public API route table routes GET, HEAD and OPTIONS only,
   and no route path is a hosted or authenticated surface.
3. Vocabulary scan. No tracked text names a private product, consumer,
   tenant, entitlement or commercial concept.
4. Identity scan. No absolute user path, no personal e-mail address, no
   private repository URL anywhere in the tree.
5. Third-party manifest scan. Every redistributed snapshot is listed in
   THIRD_PARTY_LICENSES.json with its exact SHA-256 and a licence, and the
   manifest lists nothing that is not in the tree.

Failing any of these is a boundary breach, not a style problem.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import dk_api  # noqa: E402
import dk_core  # noqa: E402

ROOT = dk_core.ROOT

# --- 1. import scan ------------------------------------------------------------

PRIVATE_MODULE_PREFIXES = ("dk_hosted", "hosted_", "dk_vda")


def imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


product_files = sorted((ROOT / "scripts").glob("*.py")) + sorted((ROOT / "collectors").glob("*.py"))
product_files.append(ROOT / "dk")
assert len(product_files) > 40, "the import scan found too few modules to be scanning the product"
SELF = Path(__file__).resolve()
for path in product_files:
    for name in imports_of(path):
        assert not name.startswith(PRIVATE_MODULE_PREFIXES), f"{path.name} imports private module {name}"
    if path.resolve() == SELF:
        continue  # this file names the prefixes it bans
    # `__import__("dk_hosted")` and importlib would slip an AST import scan.
    text = path.read_text(encoding="utf-8")
    for prefix in PRIVATE_MODULE_PREFIXES:
        assert prefix not in text, f"{path.name} names private module prefix {prefix!r}"
for prefix in PRIVATE_MODULE_PREFIXES:
    assert not list((ROOT / "scripts").glob(f"{prefix}*")), f"a {prefix}* module is present"
print("COMMUNITY_IMPORTS_NO_PRIVATE_MODULE=PASS")
print(f"COMMUNITY_MODULES_SCANNED={len(product_files)}")


# --- 2. route scan -------------------------------------------------------------

assert set(dk_api.ALLOWED_METHODS) == {"GET", "HEAD", "OPTIONS"}, dk_api.ALLOWED_METHODS
assert set(dk_api.READ_METHODS) <= set(dk_api.ALLOWED_METHODS)
for route in dk_api.ROUTES:
    path = route["path"]
    assert path.startswith(dk_api.API_ROOT), path
    for private in ("/hosted", "/private", "/tenant", "/admin", "/auth", "/login", "/token"):
        assert private not in path, path
assert not any("hosted" in route["path"] for route in dk_api.ROUTES)
print("PUBLIC_API_ROUTES_READ_ONLY=PASS")
print("PUBLIC_API_NO_HOSTED_ROUTE=PASS")


# --- 3. vocabulary scan --------------------------------------------------------

# Words that would mean a private product, consumer or commercial concept had
# leaked into the Community tree. Matched case-insensitively as whole words or
# obvious compounds.
PRIVATE_VOCABULARY = re.compile(
    r"launchpad|\bvda\b|hosted[ _-]?(project|workspace|api|service|instance)|"
    r"\btenant|entitlement|agency portfolio|continuous assurance|"
    r"organi[sz]ational (policy|knowledge)|itflowing|commercial (model|tier|plan|entitlement)",
    re.IGNORECASE,
)

# Two files legitimately name the excluded concepts: this test, which bans
# them, and the boundary document, which says what stays out and why.
VOCABULARY_EXEMPT = {"scripts/test_community_boundary.py", "docs/COMMUNITY_BOUNDARY.md"}

TEXT_SUFFIXES = {".py", ".md", ".json", ".html", ".css", ".js", ".yml", ".yaml", ".txt", ".lock", ""}
SKIP_DIRS = {".git", "__pycache__", "dist", "tmp", ".venv"}


def tracked_text_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        # Source snapshots are third-party text and may say anything; their
        # provenance, not their vocabulary, is what this repository controls.
        if path.relative_to(ROOT).parts[:2] == ("sources", "snapshots"):
            continue
        yield path


leaks = []
scanned = 0
for path in tracked_text_files():
    rel = path.relative_to(ROOT).as_posix()
    if rel in VOCABULARY_EXEMPT:
        continue
    scanned += 1
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for match in PRIVATE_VOCABULARY.finditer(text):
        leaks.append(f"{rel}: {match.group(0)!r}")
assert scanned > 300, scanned
assert not leaks, "private vocabulary in the Community tree:\n  " + "\n  ".join(leaks[:40])
print("COMMUNITY_TREE_NAMES_NO_PRIVATE_PRODUCT=PASS")
print(f"COMMUNITY_TEXT_FILES_SCANNED={scanned}")


# --- 4. identity scan ----------------------------------------------------------

USER_PATH = re.compile(r"(^|[\s\"'=(:])(/Users/[A-Za-z0-9_.-]+|/home/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\)")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PRIVATE_REPO = re.compile(r"gitlab\.com/[A-Za-z0-9_.-]+/|ssh://|git@gitlab")
# Redaction modules and their tests must be able to name the shapes they scrub.
IDENTITY_ALLOWLIST = {
    "scripts/dk_evidence.py", "scripts/dk_query.py", "scripts/dk_public.py",
    "scripts/dk_acquisition.py", "scripts/dk_generalization.py",
    "config/project-evidence.json",
    "scripts/test_community_boundary.py",
}
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.invalid", "example.org", "github.com")

PLACEHOLDER_PATHS = ("/Users/someone", "/home/someone", "/home/runner", "/home/deploy", "C:\\Users\\")

identity_leaks = []
for path in tracked_text_files():
    rel = path.relative_to(ROOT).as_posix()
    if rel == "scripts/test_community_boundary.py":
        continue  # names the shapes it scans for
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if rel not in IDENTITY_ALLOWLIST and not rel.startswith("scripts/test_"):
        for match in USER_PATH.finditer(text):
            identity_leaks.append(f"{rel}: path {match.group(2)!r}")
    elif rel.startswith("scripts/test_") and rel not in IDENTITY_ALLOWLIST:
        # Tests may use a placeholder like /Users/someone to prove redaction,
        # never a real account name.
        for match in USER_PATH.finditer(text):
            if match.group(2) not in PLACEHOLDER_PATHS:
                identity_leaks.append(f"{rel}: path {match.group(2)!r}")
    for match in EMAIL.finditer(text):
        if not match.group(0).endswith(ALLOWED_EMAIL_DOMAINS):
            identity_leaks.append(f"{rel}: e-mail {match.group(0)!r}")
    for match in PRIVATE_REPO.finditer(text):
        identity_leaks.append(f"{rel}: private repository reference {match.group(0)!r}")
assert not identity_leaks, "identity leaks in the Community tree:\n  " + "\n  ".join(identity_leaks[:40])
print("COMMUNITY_TREE_CARRIES_NO_PRIVATE_IDENTITY=PASS")



# --- 5. third-party manifest scan --------------------------------------------

import hashlib
import json

manifest = json.loads((ROOT / "THIRD_PARTY_LICENSES.json").read_text(encoding="utf-8"))
assert manifest["root_license"]["relicenses_third_party_material"] is False
assert manifest["root_license"]["copyright_owner_asserted"] is False
known_licences = set(manifest["licenses"])
listed = {}
for family in manifest["families"]:
    assert family["license"] in known_licences, family["source_id"]
    assert family["license_evidence"], family["source_id"]
    assert family["attribution"], family["source_id"]
    assert family["redistribution_status"] in ("permitted_with_attribution", "no_snapshot_redistributed"), family["source_id"]
    for item in family["files"]:
        assert item["path"] not in listed, f"listed twice: {item['path']}"
        listed[item["path"]] = item["sha256"]
on_disk = {
    path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in (ROOT / "sources" / "snapshots").rglob("*.txt")
}
missing = sorted(set(on_disk) - set(listed))
stale = sorted(set(listed) - set(on_disk))
assert not missing, "snapshots not covered by THIRD_PARTY_LICENSES.json: " + ", ".join(missing[:10])
assert not stale, "THIRD_PARTY_LICENSES.json lists files that do not exist: " + ", ".join(stale[:10])
mismatched = sorted(p for p in on_disk if on_disk[p] != listed[p])
assert not mismatched, "manifest sha256 differs from the file: " + ", ".join(mismatched[:10])
assert not manifest["unresolved"], manifest["unresolved"]
assert manifest["totals"]["files"] == len(on_disk) == len(listed)
print("THIRD_PARTY_MANIFEST_COMPLETE=PASS")
print(f"THIRD_PARTY_SNAPSHOTS_LISTED={len(listed)}")

print("COMMUNITY_DEPENDS_ON_PRIVATE_CODE=NO")
print("PRIVATE_DEPENDENCY_GATE=PASS")
