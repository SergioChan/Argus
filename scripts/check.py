#!/usr/bin/env python3
"""Run repository checks used by local development and CI."""

from __future__ import annotations

import subprocess
import sys


CHECKS = (
    ("docs", ("python3", "scripts/validate_docs.py")),
    ("roadmap-audit", ("python3", "scripts/roadmap_audit.py")),
    ("schemas", ("python3", "scripts/validate_schemas.py")),
    ("schema-compat", ("python3", "scripts/schema_compatibility.py", "--check-manifest")),
    ("bindings", ("python3", "scripts/generate_bindings.py", "--check")),
    ("typescript-install", ("npm", "ci", "--prefix", "bindings/typescript")),
    ("typescript-bindings", ("npm", "test", "--prefix", "bindings/typescript")),
    ("rust-bindings", ("cargo", "check", "--manifest-path", "bindings/rust/Cargo.toml")),
    ("rust-tests", ("cargo", "test", "--manifest-path", "bindings/rust/Cargo.toml")),
    ("unit-tests", ("python3", "-m", "unittest", "discover", "-s", "tests")),
    (
        "py-compile",
        (
            "python3",
            "-m",
            "py_compile",
            "scripts/apply_s3_migrations.py",
            "scripts/apply_s8_migrations.py",
            "scripts/check.py",
            "scripts/generate_bindings.py",
            "scripts/run_s1_perf_scale_battery.py",
            "scripts/run_s2_perf_latency_battery.py",
            "scripts/run_s8_read_query_scale_battery.py",
            "scripts/run_s8_lineage_scale_battery.py",
            "scripts/run_m0_spine_battery.py",
            "scripts/roadmap_audit.py",
            "scripts/schema_compatibility.py",
            "scripts/validate_docs.py",
            "scripts/validate_schemas.py",
            "src/argus_core/s3.py",
            "src/argus_core/s10.py",
            "src/argus_runtime/s3_profile_registry.py",
            "src/argus_runtime/s3_report_signer_service.py",
            "src/argus_runtime/s3_verifier_service.py",
            "src/argus_runtime/s3_verify_orchestrator.py",
            "src/argusverify/__init__.py",
            "tests/test_s3_blind_data_manager.py",
            "tests/test_s3_check_plugin_host.py",
            "tests/test_s3_frozen_pipeline_runner.py",
            "tests/test_s3_independence_resolver.py",
            "tests/test_s3_report_canonicalizer.py",
            "tests/test_s3_profile_resolver.py",
            "tests/test_s3_report_signer.py",
            "tests/test_s3_profile_registry.py",
            "tests/test_s3_statistics_library.py",
            "tests/test_s3_trust_store_key_management.py",
        ),
    ),
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
