#!/usr/bin/env python3
"""Run repository checks used by local development and CI."""

from __future__ import annotations

import subprocess
import sys


CHECKS = (
    ("docs", ("python3", "scripts/validate_docs.py")),
    ("schemas", ("python3", "scripts/validate_schemas.py")),
    ("bindings", ("python3", "scripts/generate_bindings.py", "--check")),
    ("rust-bindings", ("cargo", "check", "--manifest-path", "bindings/rust/Cargo.toml")),
    ("unit-tests", ("python3", "-m", "unittest", "discover", "-s", "tests")),
    ("py-compile", ("python3", "-m", "py_compile", "scripts/check.py", "scripts/generate_bindings.py", "scripts/validate_docs.py", "scripts/validate_schemas.py")),
)


def main() -> int:
    for name, command in CHECKS:
        print(f"==> {name}", flush=True)
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
