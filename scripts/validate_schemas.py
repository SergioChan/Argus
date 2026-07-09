#!/usr/bin/env python3
"""Validate the local contract schema source tree."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "schemas" / "contracts"
EXAMPLES = CONTRACTS / "examples"

EXPECTED_CONTRACT_CONSUMERS = {
    "C1": {"S2", "S3", "S4", "S5", "S11", "S12"},
    "C2": {"S1", "S2", "S3", "S4", "S7", "S9", "S10", "S11", "S12"},
    "C3": {"S1", "S2", "S4", "S5", "S7", "S8", "S9", "S11", "S12"},
    "C4": {"S1", "S2", "S3", "S4", "S5", "S6", "S7", "S9", "S10", "S11", "S12"},
    "C5": {"S1", "S2", "S3", "S4", "S5", "S7", "S9", "S10", "S11"},
    "C6": {"S1", "S2", "S3", "S5", "S6", "S10", "S11", "S12"},
    "C10": {"S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S11", "S12"},
}

EXPECTED_CONTRACT_VERSIONS = {
    "C1": "1.0.0",
    "C2": "1.0.0",
    "C3": "2.0.0",
    "C4": "1.0.0",
    "C5": "1.0.0",
    "C6": "1.1.0",
    "C10": "4.0.0",
}

C3_V11_FIELDS = {
    "perturbation_pairs",
    "insensitivity_flags",
    "challenger_panel",
    "independence_attestation_debate",
    "referee",
    "debate_ref",
}

C3_V2_REQUIRED_FIELDS = {
    "perturbation_pairs",
    "insensitivity_flags",
    "referee",
}

C1_REQUIRED_DEFS = {
    "Acceptance",
    "BuildResult",
    "Heartbeat",
    "LifecycleEvent",
    "Plan",
    "SubagentEnvelope",
    "SubagentReport",
    "TypedError",
    "ValidationRequest",
}

C4_REQUIRED_DEFS = {
    "ArtifactRecord",
    "ArtifactRef",
    "ClaimTier",
    "HashRef",
    "Lineage",
    "Producer",
    "RetentionPolicy",
}

C6_REQUIRED_DEFS = {
    "AdapterDescriptor",
    "EvalRequest",
    "EvalResult",
    "OutputQuantity",
    "Quantity",
}

C10_REQUIRED_DEFS = {
    "AuditEvent",
    "BudgetCaps",
    "BudgetToken",
    "BudgetUsage",
    "EgressDecision",
    "EgressRule",
    "LaunchEnvelope",
    "LaunchRequest",
    "PolicyBundle",
    "PolicyVerdict",
    "QuotaState",
    "ResourceCeilings",
    "S8CheckpointSignature",
    "SandboxExecutionResult",
    "SandboxHandle",
    "SandboxPartialResult",
    "ScopeGrant",
    "ScopeToken",
    "StoreBrokerHandle",
    "TokenSignature",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def validate_manifest(manifest: dict) -> list[dict]:
    contracts = manifest.get("contracts")
    if not isinstance(contracts, list):
        fail("schemas/contracts/manifest.json must contain a contracts array")
    ids = [entry.get("id") for entry in contracts]
    expected_ids = sorted(EXPECTED_CONTRACT_CONSUMERS)
    if sorted(ids) != expected_ids:
        fail(f"manifest contract ids mismatch: actual={sorted(ids)} expected={expected_ids}")
    if len(ids) != len(set(ids)):
        fail("manifest contains duplicate contract ids")

    for entry in contracts:
        contract_id = entry["id"]
        consumers = set(entry.get("consumers", []))
        if consumers != EXPECTED_CONTRACT_CONSUMERS[contract_id]:
            fail(f"{contract_id} manifest consumers mismatch: actual={sorted(consumers)} expected={sorted(EXPECTED_CONTRACT_CONSUMERS[contract_id])}")
        version = entry.get("version")
        if version != EXPECTED_CONTRACT_VERSIONS[contract_id]:
            fail(f"{contract_id} manifest version mismatch: actual={version} expected={EXPECTED_CONTRACT_VERSIONS[contract_id]}")
        schema_path = CONTRACTS / entry.get("schema", "")
        if not schema_path.is_file():
            fail(f"{contract_id} schema file does not exist: {schema_path.relative_to(ROOT)}")
    return contracts


def validate_contract_schema(entry: dict) -> None:
    contract_id = entry["id"]
    path = CONTRACTS / entry["schema"]
    schema = load_json(path)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail(f"{path.relative_to(ROOT)} must use JSON Schema draft 2020-12")
    if "$id" not in schema:
        fail(f"{path.relative_to(ROOT)} must declare $id")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        fail(f"{path.relative_to(ROOT)} failed JSON Schema meta-validation: {exc}")

    metadata = schema.get("x-argus-contract")
    if not isinstance(metadata, dict):
        fail(f"{path.relative_to(ROOT)} must declare x-argus-contract metadata")
    if metadata.get("id") != contract_id:
        fail(f"{path.relative_to(ROOT)} metadata id mismatch")
    if metadata.get("owner") != entry["owner"]:
        fail(f"{path.relative_to(ROOT)} owner mismatch")
    if metadata.get("version") != entry["version"]:
        fail(f"{path.relative_to(ROOT)} version mismatch")

    if contract_id == "C3":
        report = schema.get("$defs", {}).get("ValidationReport", {})
        properties = set(report.get("properties", {}))
        missing = sorted(C3_V11_FIELDS - properties)
        if missing:
            fail(f"C3 ValidationReport missing v1.1 fields: {missing}")
        required = set(report.get("required", []))
        missing_required = sorted(C3_V2_REQUIRED_FIELDS - required)
        if missing_required:
            fail(f"C3 ValidationReport missing v2 required fields: {missing_required}")
        missing_defaults = sorted(
            field
            for field in C3_V11_FIELDS
            if "default" not in report.get("properties", {}).get(field, {})
        )
        if missing_defaults:
            fail(f"C3 ValidationReport v1.1 additive fields missing defaults: {missing_defaults}")

    if contract_id == "C1":
        definitions = schema.get("$defs", {})
        missing_defs = sorted(C1_REQUIRED_DEFS - set(definitions))
        if missing_defs:
            fail(f"C1 schema missing canonical public definitions: {missing_defs}")
        lifecycle_states = set(definitions.get("LifecycleState", {}).get("enum", []))
        if "REJECTED" not in lifecycle_states:
            fail("C1 LifecycleState must include REJECTED")
        if "REFUSED" in lifecycle_states:
            fail("C1 LifecycleState must not use REFUSED; refusal is represented by Acceptance.accepted=false and state REJECTED")
        method_values = set(definitions.get("LifecycleMethod", {}).get("enum", []))
        required_methods = {"register", "accept", "refuse", "plan", "build", "validate", "report", "heartbeat", "cancel"}
        missing_methods = sorted(required_methods - method_values)
        if missing_methods:
            fail(f"C1 LifecycleMethod missing public methods: {missing_methods}")

    if contract_id == "C4":
        definitions = schema.get("$defs", {})
        missing_defs = sorted(C4_REQUIRED_DEFS - set(definitions))
        if missing_defs:
            fail(f"C4 schema missing canonical public definitions: {missing_defs}")
        for definition_name in ("Producer", "Lineage", "RetentionPolicy", "ArtifactRecord"):
            definition = definitions.get(definition_name, {})
            if definition.get("additionalProperties") is not False:
                fail(f"C4 {definition_name} must set additionalProperties=false")
        lineage_required = set(definitions.get("Lineage", {}).get("required", []))
        for field in ("input_refs", "code_ref", "environment_digest", "seeds"):
            if field not in lineage_required:
                fail(f"C4 Lineage missing required field: {field}")
        artifact_record = definitions.get("ArtifactRecord", {})
        has_tier_coupling = any(
            "validation_report_ref" in rule.get("then", {}).get("required", [])
            for rule in artifact_record.get("allOf", [])
            if isinstance(rule, dict)
        )
        if not has_tier_coupling:
            fail("C4 ArtifactRecord must require validation_report_ref for promoted tiers")

    if contract_id == "C6":
        definitions = schema.get("$defs", {})
        missing_defs = sorted(C6_REQUIRED_DEFS - set(definitions))
        if missing_defs:
            fail(f"C6 schema missing canonical public definitions: {missing_defs}")
        output_quantity_required = set(definitions.get("OutputQuantity", {}).get("required", []))
        if "uncertainty" not in output_quantity_required:
            fail("C6 OutputQuantity must require uncertainty")
        eval_result_outputs = (
            definitions.get("EvalResult", {})
            .get("properties", {})
            .get("outputs", {})
            .get("additionalProperties", {})
        )
        if eval_result_outputs.get("$ref") != "#/$defs/OutputQuantity":
            fail("C6 EvalResult.outputs must reference OutputQuantity")
        eval_result = definitions.get("EvalResult", {})
        eval_required = set(eval_result.get("required", []))
        for field in ("unit_registry_version", "unit_registry_hash"):
            if field not in eval_required:
                fail(f"C6 EvalResult must require {field}")
            if "default" not in eval_result.get("properties", {}).get(field, {}):
                fail(f"C6 EvalResult {field} must declare an additive default")

    if contract_id == "C10":
        definitions = schema.get("$defs", {})
        missing_defs = sorted(C10_REQUIRED_DEFS - set(definitions))
        if missing_defs:
            fail(f"C10 schema missing canonical public definitions: {missing_defs}")
        launch_request = definitions.get("LaunchRequest", {})
        launch_required = set(launch_request.get("required", []))
        for field in ("budget_token", "scope_token", "image", "requested_envelope", "runtime_class_hint"):
            if field not in launch_required:
                fail(f"C10 LaunchRequest missing required field: {field}")
        image_schema = launch_request.get("properties", {}).get("image", {})
        if "sha256" not in image_schema.get("pattern", ""):
            fail("C10 LaunchRequest.image must require a digest-pinned image")
        scope_grant = definitions.get("ScopeGrant", {})
        if scope_grant.get("additionalProperties") is not False:
            fail("C10 ScopeGrant must set additionalProperties=false")
        policy_bundle = definitions.get("PolicyBundle", {})
        if policy_bundle.get("properties", {}).get("signature", {}).get("$ref") != "#/$defs/Signature":
            fail("C10 PolicyBundle.signature must reference Signature")
        for token_def in ("BudgetToken", "ScopeToken"):
            token_signature = definitions.get(token_def, {}).get("properties", {}).get("signature", {})
            if token_signature.get("$ref") != "#/$defs/TokenSignature":
                fail(f"C10 {token_def}.signature must reference TokenSignature")

    example_path = EXAMPLES / f"{contract_id.lower()}.example.json"
    if not example_path.is_file():
        fail(f"{contract_id} example file does not exist: {example_path.relative_to(ROOT)}")
    example = load_json(example_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(example), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        fail(f"{example_path.relative_to(ROOT)} does not validate against {contract_id} at {location}: {first.message}")
    if contract_id == "C10":
        for golden_path in sorted(EXAMPLES.glob("c10.*.example.json")):
            golden = load_json(golden_path)
            golden_errors = sorted(validator.iter_errors(golden), key=lambda error: list(error.path))
            if golden_errors:
                first = golden_errors[0]
                location = ".".join(str(part) for part in first.path) or "<root>"
                fail(
                    f"{golden_path.relative_to(ROOT)} does not validate against C10 at {location}: {first.message}"
                )


def main() -> int:
    manifest = load_json(CONTRACTS / "manifest.json")
    contracts = validate_manifest(manifest)
    for entry in contracts:
        validate_contract_schema(entry)
    print("schema validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
