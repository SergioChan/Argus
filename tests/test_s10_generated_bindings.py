from __future__ import annotations

import copy
from dataclasses import fields as dataclass_fields
import json
from pathlib import Path
import subprocess
import sys
import types
from typing import Annotated, Any, Literal, Union, get_args, get_origin, get_type_hints
import unittest

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
BINDINGS_PYTHON = ROOT / "bindings" / "python"
if str(BINDINGS_PYTHON) not in sys.path:
    sys.path.insert(0, str(BINDINGS_PYTHON))

from argus_contracts import (  # noqa: E402
    AuditEvent,
    BudgetCaps,
    BudgetToken,
    BudgetUsage,
    C10_SCHEMA_SHA256,
    CONTRACT_BY_ID,
    EgressDecision,
    EgressRule,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyVerdict,
    QuotaState,
    ResourceCeilings,
    S8CheckpointSignature,
    SandboxExecutionResult,
    SandboxHandle,
    ScopeGrant,
    ScopeToken,
    StoreBrokerHandle,
    validate_launch_request,
    validate_policy_bundle,
)
from argus_core import s10 as runtime_s10  # noqa: E402


C10_EXAMPLE = ROOT / "schemas" / "contracts" / "examples" / "c10.example.json"
C10_POLICY_EXAMPLE = ROOT / "schemas" / "contracts" / "examples" / "c10.policy-bundle.example.json"
C10_SCHEMA = ROOT / "schemas" / "contracts" / "c10.s10-runtime.schema.json"

C10_RUNTIME_FIELD_GUARDS = (
    ("AuditEvent", runtime_s10.AuditEvent, AuditEvent),
    ("BudgetCaps", runtime_s10.BudgetCaps, BudgetCaps),
    ("BudgetToken", runtime_s10.BudgetToken, BudgetToken),
    ("BudgetUsage", runtime_s10.BudgetUsage, BudgetUsage),
    ("EgressDecision", runtime_s10.EgressDecision, EgressDecision),
    ("EgressRule", runtime_s10.EgressRule, EgressRule),
    ("LaunchEnvelope", runtime_s10.LaunchEnvelope, LaunchEnvelope),
    ("LaunchRequest", runtime_s10.LaunchRequest, LaunchRequest),
    ("PolicyBundle", runtime_s10.PolicyBundle, PolicyBundle),
    ("PolicyVerdict", runtime_s10.PolicyVerdict, PolicyVerdict),
    ("QuotaState", runtime_s10.QuotaState, QuotaState),
    ("ResourceCeilings", runtime_s10.ResourceCeilings, ResourceCeilings),
    ("S8CheckpointSignature", runtime_s10.S8CheckpointSignature, S8CheckpointSignature),
    ("SandboxExecutionResult", runtime_s10.SandboxExecutionResult, SandboxExecutionResult),
    ("SandboxHandle", runtime_s10.SandboxHandle, SandboxHandle),
    ("ScopeGrant", runtime_s10.ScopeGrant, ScopeGrant),
    ("ScopeToken", runtime_s10.ScopeToken, ScopeToken),
    ("StoreBrokerHandle", runtime_s10.StoreBrokerHandle, StoreBrokerHandle),
)


class S10GeneratedBindingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.launch_request = json.loads(C10_EXAMPLE.read_text(encoding="utf-8"))
        self.policy_bundle = json.loads(C10_POLICY_EXAMPLE.read_text(encoding="utf-8"))

    def test_c10_python_binding_validates_launch_request_and_policy_samples(self) -> None:
        launch_request = validate_launch_request(self.launch_request)
        policy_bundle = validate_policy_bundle(self.policy_bundle)

        self.assertEqual(launch_request.image, self.launch_request["image"])
        self.assertEqual(launch_request.budget_token.job_id, "job-s10-golden")
        self.assertEqual(policy_bundle.risk_to_runtime["standard"], "gvisor")
        self.assertEqual(C10_SCHEMA_SHA256, CONTRACT_BY_ID["C10"].schema_sha256)

    def test_c10_python_binding_rejects_schema_violations(self) -> None:
        tag_only_image = {**copy.deepcopy(self.launch_request), "image": "busybox:latest"}
        duplicate_allowlist = copy.deepcopy(self.launch_request)
        duplicate_allowlist["env_allowlist"] = ["ARGUS_MODE", "ARGUS_MODE"]
        bad_policy_signature = {**copy.deepcopy(self.policy_bundle), "signature": "hmac-sha256:bad"}

        with self.assertRaises(ValidationError):
            validate_launch_request(tag_only_image)
        with self.assertRaises(ValidationError):
            validate_launch_request(duplicate_allowlist)
        with self.assertRaises(ValidationError):
            validate_policy_bundle(bad_policy_signature)

    def test_c10_registry_entry_is_present_in_typescript_and_rust_bindings(self) -> None:
        c10 = CONTRACT_BY_ID["C10"]
        typescript_contracts = (ROOT / "bindings" / "typescript" / "src" / "contracts.ts").read_text(
            encoding="utf-8"
        )
        typescript_s10 = (ROOT / "bindings" / "typescript" / "src" / "s10.ts").read_text(encoding="utf-8")
        rust_lib = (ROOT / "bindings" / "rust" / "src" / "lib.rs").read_text(encoding="utf-8")
        rust_s10 = (ROOT / "bindings" / "rust" / "src" / "s10.rs").read_text(encoding="utf-8")

        self.assertIn('"id": "C10"', typescript_contracts)
        self.assertIn(f'"schema_sha256": "{c10.schema_sha256}"', typescript_contracts)
        self.assertIn(f'export const C10_SCHEMA_SHA256 = "{c10.schema_sha256}"', typescript_s10)
        self.assertIn('id: "C10"', rust_lib)
        self.assertIn(f'pub const C10_SCHEMA_SHA256: &str = "{c10.schema_sha256}"', rust_s10)

    def test_c10_runtime_dataclasses_match_generated_wire_fields(self) -> None:
        schema = json.loads(C10_SCHEMA.read_text(encoding="utf-8"))
        definitions = schema["$defs"]

        for definition_name, runtime_cls, generated_cls in C10_RUNTIME_FIELD_GUARDS:
            with self.subTest(definition=definition_name):
                schema_properties = definitions[definition_name]["properties"]
                schema_fields = set(schema_properties)
                required_fields = set(definitions[definition_name]["required"])
                runtime_fields = {field.name for field in dataclass_fields(runtime_cls)}
                generated_fields = set(generated_cls.model_fields)
                schema_types = {
                    field_name: _schema_wire_type(schema_properties[field_name], definitions)
                    for field_name in schema_fields
                }
                runtime_types = {
                    field_name: _annotation_wire_type(annotation, definitions)
                    for field_name, annotation in get_type_hints(runtime_cls).items()
                }
                generated_types = {
                    field_name: _annotation_wire_type(field.annotation, definitions)
                    for field_name, field in generated_cls.model_fields.items()
                }

                self.assertEqual(schema_fields, required_fields)
                self.assertEqual(schema_fields, generated_fields)
                self.assertEqual(schema_fields, runtime_fields)
                self.assertEqual(schema_types, generated_types)
                self.assertEqual(schema_types, runtime_types)

    def test_c10_type_guard_distinguishes_integer_and_string_wire_shapes(self) -> None:
        schema = json.loads(C10_SCHEMA.read_text(encoding="utf-8"))
        definitions = schema["$defs"]

        self.assertEqual(_schema_wire_type(definitions["BudgetToken"]["properties"]["budget_epoch"], definitions), "integer")
        self.assertEqual(_annotation_wire_type(int, definitions), "integer")
        self.assertEqual(_annotation_wire_type(str, definitions), "string")

    def test_binding_generator_is_byte_stable_after_c10_generation(self) -> None:
        result = subprocess.run(
            ["python3", "scripts/generate_bindings.py", "--check"],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)

def _schema_wire_type(schema_fragment: dict[str, Any], definitions: dict[str, Any]) -> str:
    ref = schema_fragment.get("$ref")
    if isinstance(ref, str):
        definition_name = ref.rsplit("/", 1)[-1]
        definition = definitions[definition_name]
        if definition.get("type") == "object":
            return f"object:{definition_name}"
        return _schema_wire_type(definition, definitions)

    raw_type = schema_fragment.get("type")
    if isinstance(raw_type, list):
        return "|".join(sorted(_schema_wire_type({**schema_fragment, "type": item}, definitions) for item in raw_type))
    if raw_type == "array":
        return f"array[{_schema_wire_type(schema_fragment.get('items', {}), definitions)}]"
    if raw_type == "object":
        additional = schema_fragment.get("additionalProperties")
        if additional is True:
            return "map[any]"
        if isinstance(additional, dict):
            return f"map[{_schema_wire_type(additional, definitions)}]"
        return "object"
    if raw_type in {"string", "integer", "number", "boolean", "null"}:
        return raw_type
    raise AssertionError(f"unsupported C10 schema type fragment: {schema_fragment}")


def _annotation_wire_type(annotation: Any, definitions: dict[str, Any]) -> str:
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin is Annotated:
        return _annotation_wire_type(args[0], definitions)
    if origin is Literal:
        literal_types = {_literal_wire_type(value) for value in args}
        return "|".join(sorted(literal_types))
    if origin in {Union, types.UnionType}:
        return "|".join(sorted(_annotation_wire_type(arg, definitions) for arg in args))
    if origin in {list, tuple}:
        item_annotation = args[0] if args and args[0] is not Ellipsis else Any
        return f"array[{_annotation_wire_type(item_annotation, definitions)}]"
    if origin is dict:
        value_annotation = args[1] if len(args) == 2 else Any
        return f"map[{_annotation_wire_type(value_annotation, definitions)}]"
    if annotation is Any:
        return "any"
    if annotation is str:
        return "string"
    if annotation is int:
        return "integer"
    if annotation is float:
        return "number"
    if annotation is bool:
        return "boolean"
    if annotation is type(None):
        return "null"
    definition_name = getattr(annotation, "__name__", None)
    if isinstance(definition_name, str) and definitions.get(definition_name, {}).get("type") == "object":
        return f"object:{definition_name}"
    raise AssertionError(f"unsupported C10 annotation type: {annotation!r}")


def _literal_wire_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if value is None:
        return "null"
    raise AssertionError(f"unsupported C10 literal value: {value!r}")


if __name__ == "__main__":
    unittest.main()
