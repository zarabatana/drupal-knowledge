#!/usr/bin/env python3
"""Release metadata: the software bill of materials and artifact checksums.

Two committed, regenerated, byte-stale-guarded artifacts, in the same
discipline as the public dataset and the API artifacts:

``release/sbom.json``
    The dependency inventory. It is short because the dependency policy is
    short: the application is Python standard library only, verified here by
    an import scan rather than asserted by prose. The runtime requirement
    (Python) and the zero third-party Python dependencies are the whole
    supply chain.

``release/checksums.json``
    SHA-256 of every committed release-coupled artifact — the public dataset,
    the public API artifacts, the generated knowledge exports, the SBOM —
    so a consumer of a release can verify what they received against what
    was tagged.

Both are deterministic: no clock, no environment, nothing machine-specific.
`dk release-meta` regenerates them; `dk validate` fails if they are stale.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

import dk_core

RELEASE_DIR = "release"
SBOM_NAME = "sbom.json"
CHECKSUMS_NAME = "checksums.json"

SBOM_CONTRACT_VERSION = "1.0"
CHECKSUMS_CONTRACT_VERSION = "1.0"

# First-party top-level modules: the dk_*/test_* families plus the
# two bare names (the CLI wrapper module and the collector script). Matched
# exactly or on the underscore prefix — never on a bare prefix, which would
# both hide stdlib names like `collections` from the inventory and let a
# third-party package named `collectd` or `dk_anything` slip the gate.
FIRST_PARTY_PREFIXES = ("dk_", "test_")
FIRST_PARTY_MODULES = ("dk", "collect", "__future__")

# The committed artifacts a release is judged by. Directories are hashed
# file-by-file; the checksums file itself is excluded by construction.
CHECKSUM_TARGETS = (
    "VERSION",
    "generated/knowledge.json",
    "generated/coverage.json",
    "public/index.html",
    "public-site/dataset",
    "public-api",
    "release/sbom.json",
)


def stable_json(data) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _module_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def scan_third_party_imports(
    root: Path, *, product_only: bool = False
) -> tuple[list[str], list[str]]:
    """Every top-level import across the codebase, split stdlib / other.

    The dependency POLICY covers everything, tests included — a test that
    imports a third-party package would still be a dependency. The SBOM's
    stdlib inventory, though, describes the shipped product, so it scans
    product modules only; otherwise every new test would dirty the committed
    release metadata without changing what a deployment runs.
    """
    stdlib: set[str] = set()
    third_party: set[str] = set()
    for directory in ("scripts", "collectors"):
        for path in sorted((Path(root) / directory).glob("*.py")):
            if product_only and path.name.startswith("test_"):
                continue
            for name in _module_imports(path):
                if name.startswith(FIRST_PARTY_PREFIXES) or name in FIRST_PARTY_MODULES:
                    continue
                if name in sys.stdlib_module_names:
                    stdlib.add(name)
                else:
                    third_party.add(name)
    return sorted(stdlib), sorted(third_party)


def sbom_content(root: Path = dk_core.ROOT) -> dict:
    version = (Path(root) / "VERSION").read_text(encoding="utf-8").strip()
    _product_stdlib, _ = scan_third_party_imports(root, product_only=True)
    stdlib = _product_stdlib
    _, third_party = scan_third_party_imports(root)
    if third_party:
        raise dk_core.ValidationError(
            "the dependency policy is standard library only, but these are "
            f"imported: {', '.join(third_party)}"
        )
    return {
        "sbom_contract_version": SBOM_CONTRACT_VERSION,
        "dk_version": version,
        "component": {
            "name": "drupal-knowledge",
            "version": version,
            "language": "python",
        },
        "dependency_policy": (
            "Python standard library only. Verified by an import scan over "
            "scripts/ and collectors/ at generation time; a third-party "
            "import fails the build."
        ),
        "python_dependencies": [],
        "python_stdlib_modules_used": stdlib,
        "runtime_requirements": [
            {
                "name": "python",
                "constraint": ">=3.12",
                "purpose": "the entire application",
            },
        ],
    }


def _iter_files(root: Path, target: str):
    path = Path(root) / target
    if path.is_dir():
        for item in sorted(path.rglob("*")):
            if item.is_file() and not any(
                part.startswith(".") for part in item.relative_to(path).parts
            ):
                yield item
    elif path.is_file():
        yield path
    else:
        raise dk_core.ValidationError(f"release checksum target missing: {target}")


def checksums_content(root: Path = dk_core.ROOT) -> dict:
    version = (Path(root) / "VERSION").read_text(encoding="utf-8").strip()
    artifacts = {}
    for target in CHECKSUM_TARGETS:
        for item in _iter_files(Path(root), target):
            rel = item.relative_to(root).as_posix()
            artifacts[rel] = hashlib.sha256(item.read_bytes()).hexdigest()
    return {
        "checksums_contract_version": CHECKSUMS_CONTRACT_VERSION,
        "dk_version": version,
        "algorithm": "sha256",
        "artifacts": artifacts,
    }


def sbom_bytes(root: Path = dk_core.ROOT) -> bytes:
    return stable_json(sbom_content(root)).encode("utf-8")


def checksums_bytes(root: Path = dk_core.ROOT) -> bytes:
    return stable_json(checksums_content(root)).encode("utf-8")


def write_release_meta(root: Path = dk_core.ROOT) -> list[str]:
    release_dir = Path(root) / RELEASE_DIR
    release_dir.mkdir(parents=True, exist_ok=True)
    (release_dir / SBOM_NAME).write_bytes(sbom_bytes(root))
    # The checksums cover the SBOM, so the SBOM is written first.
    (release_dir / CHECKSUMS_NAME).write_bytes(checksums_bytes(root))
    return [f"{RELEASE_DIR}/{SBOM_NAME}", f"{RELEASE_DIR}/{CHECKSUMS_NAME}"]


def validate_release_meta(root: Path = dk_core.ROOT) -> list[str]:
    release_dir = Path(root) / RELEASE_DIR
    for name, expected in (
        (SBOM_NAME, sbom_bytes(root)),
        (CHECKSUMS_NAME, checksums_bytes(root)),
    ):
        path = release_dir / name
        if not path.exists() or path.read_bytes() != expected:
            raise dk_core.ValidationError(
                f"release metadata is stale: {RELEASE_DIR}/{name}. "
                "Run python3 scripts/dk.py release-meta"
            )
    sbom = json.loads((release_dir / SBOM_NAME).read_text(encoding="utf-8"))
    return [
        "RELEASE_SBOM_CURRENT=PASS",
        "RELEASE_CHECKSUMS_CURRENT=PASS",
        f"RELEASE_THIRD_PARTY_PYTHON_DEPENDENCIES={len(sbom['python_dependencies'])}",
    ]
