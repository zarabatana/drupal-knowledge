#!/usr/bin/env python3
"""Supply chain and source security scanning for the v1.0 release.

Three scans, none of which claims more than it covers:

1. Dependency scan. The dependency policy is Python standard library only,
   so the dependency attack surface is the Python runtime, named in the
   SBOM. The scan proves the policy rather than trusting
   it: any third-party top-level import anywhere in scripts/ or collectors/
   fails this build.
2. Dangerous-construct scan. No eval/exec, no os.system, no shell=True, no
   pickle/marshal deserialization anywhere in the product source. These are
   the constructs through which repository content or stored data could
   become code.
3. Release metadata freshness. The committed SBOM and artifact checksums
   are regenerated in memory and byte-compared.

This is a static scan of first-party source. It does not audit CPython, git
or the operating system, and passing it is not a claim that no vulnerability
exists anywhere.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import dk_core  # noqa: E402
import dk_release_meta  # noqa: E402


# --- 1. dependency scan ------------------------------------------------------

stdlib_used, third_party = dk_release_meta.scan_third_party_imports(dk_core.ROOT)
assert not third_party, f"third-party imports violate the dependency policy: {third_party}"
assert stdlib_used, "the import scan found nothing, which means it scanned nothing"
print("SUPPLY_CHAIN_STDLIB_ONLY=PASS")
print(f"SUPPLY_CHAIN_STDLIB_MODULES={len(stdlib_used)}")


# --- 2. dangerous-construct scan --------------------------------------------

# Product source only: tests may monkeypatch and simulate, the product may
# not evaluate. The `dk` wrapper and collectors are product source.
product_files = sorted(
    path
    for path in SCRIPTS.glob("*.py")
    if not path.name.startswith("test_")
)
product_files += sorted((dk_core.ROOT / "collectors").glob("*.py"))

FORBIDDEN_CALLS = {"eval", "exec", "compile"}
FORBIDDEN_ATTRS = {
    ("os", "system"),
    ("os", "popen"),
    ("pickle", "load"),
    ("pickle", "loads"),
    ("marshal", "load"),
    ("marshal", "loads"),
}

scanned = 0
for path in product_files:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    scanned += 1
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                raise AssertionError(f"{path.name} calls {node.func.id}()")
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                pair = (node.func.value.id, node.func.attr)
                if pair in FORBIDDEN_ATTRS:
                    raise AssertionError(f"{path.name} calls {pair[0]}.{pair[1]}()")
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    assert keyword.value.value is not True, f"{path.name} uses shell=True"
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                assert name.split(".")[0] not in ("pickle", "marshal"), (
                    f"{path.name} imports {name}"
                )

assert scanned > 20, f"only {scanned} product files scanned; the glob is broken"
print("SUPPLY_CHAIN_NO_DYNAMIC_CODE_EXECUTION=PASS")
print("SUPPLY_CHAIN_NO_UNSAFE_DESERIALIZATION=PASS")
print(f"SUPPLY_CHAIN_FILES_SCANNED={scanned}")


# --- 3. release metadata freshness -------------------------------------------

for line in dk_release_meta.validate_release_meta(dk_core.ROOT):
    print(line)

# Honesty line: what this scan is and is not.
print("SUPPLY_CHAIN_SCAN_SCOPE=first-party source and dependency policy only")
print("V100_SECURITY_SCAN_EXECUTED=PASS")
print("SUPPLY_CHAIN_SECURITY_CONTRACT=PASS")
