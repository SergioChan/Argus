#!/usr/bin/env python3
"""Run JSON Schema semantic compatibility gates."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
CONTRACTS = ROOT / "schemas" / "contracts"
COMPATIBILITY_MANIFEST = CONTRACTS / "compatibility.json"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from argus_core.schema_compat import (  # noqa: E402
    SchemaCompatibilityResult,
    assert_schema_version_declares_change,
    classify_json_schema_change,
    schema_version_declares_change,
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def result_payload(
    *,
    contract_id: str,
    old_version: str,
    new_version: str,
    result: SchemaCompatibilityResult,
) -> dict[str, Any]:
    return {
        "contract_id": contract_id,
        "old_version": old_version,
        "new_version": new_version,
        "classification": result.classification,
        "allowed": schema_version_declares_change(
            old_version=old_version,
            new_version=new_version,
            classification=result.classification,
        ),
        "breaking_changes": list(result.breaking_changes),
        "additive_changes": list(result.additive_changes),
        "patch_changes": list(result.patch_changes),
    }


def check_pair(
    *,
    contract_id: str,
    old_path: Path,
    new_path: Path,
    old_version: str,
    new_version: str,
) -> dict[str, Any]:
    result = classify_json_schema_change(load_json(old_path), load_json(new_path))
    payload = result_payload(
        contract_id=contract_id,
        old_version=old_version,
        new_version=new_version,
        result=result,
    )
    if payload["allowed"]:
        assert_schema_version_declares_change(
            old_version=old_version,
            new_version=new_version,
            classification=result.classification,
        )
    return payload


def check_manifest() -> list[dict[str, Any]]:
    manifest = load_json(CONTRACTS / "manifest.json")
    current_by_id = {entry["id"]: entry for entry in manifest["contracts"]}
    compatibility = load_json(COMPATIBILITY_MANIFEST)
    payloads: list[dict[str, Any]] = []
    for entry in compatibility.get("contracts", []):
        contract_id = entry["id"]
        current = current_by_id[contract_id]
        payloads.append(
            check_pair(
                contract_id=contract_id,
                old_path=CONTRACTS / entry["baseline_schema"],
                new_path=CONTRACTS / current["schema"],
                old_version=entry["baseline_version"],
                new_version=current["version"],
            )
        )
    return payloads


def print_payload(payload: Any, *, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif isinstance(payload, list):
        for entry in payload:
            print(
                f"{entry['contract_id']}: {entry['classification']} "
                f"{entry['old_version']}->{entry['new_version']} allowed={entry['allowed']}"
            )
    else:
        print(
            f"{payload['contract_id']}: {payload['classification']} "
            f"{payload['old_version']}->{payload['new_version']} allowed={payload['allowed']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("text", "json"), default="text")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-manifest", action="store_true")
    mode.add_argument("--old", type=Path)
    parser.add_argument("--new", type=Path)
    parser.add_argument("--old-version")
    parser.add_argument("--new-version")
    parser.add_argument("--contract-id", default="C1")
    args = parser.parse_args()

    if args.check_manifest:
        payload = check_manifest()
        print_payload(payload, output_format=args.format)
        return 0 if all(entry["allowed"] for entry in payload) else 1

    if args.old is None or args.new is None or args.old_version is None or args.new_version is None:
        parser.error("--old requires --new, --old-version, and --new-version")

    payload = check_pair(
        contract_id=args.contract_id,
        old_path=args.old,
        new_path=args.new,
        old_version=args.old_version,
        new_version=args.new_version,
    )
    print_payload(payload, output_format=args.format)
    return 0 if payload["allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
