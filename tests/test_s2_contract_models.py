from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

from argus_core import (
    C2ContractError,
    S2ContractModelError,
    S2_REQUIRED_CONTRACT_IDS,
    compile_build_spec_from_c2_envelope,
    validate_s2_contract_model_set,
)


ROOT = Path(__file__).resolve().parents[1]
BINDINGS_PYTHON = ROOT / "bindings" / "python"
if str(BINDINGS_PYTHON) not in sys.path:
    sys.path.insert(0, str(BINDINGS_PYTHON))

from argus_contracts import CONTRACT_BY_ID  # noqa: E402


SCHEMA_ROOT = ROOT / "schemas" / "contracts"
EXAMPLE_PATH = SCHEMA_ROOT / "examples" / "c2.example.json"


class S2ContractModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))

    def test_s2_required_generated_bindings_match_canonical_schema_digests(self) -> None:
        model_set = validate_s2_contract_model_set(CONTRACT_BY_ID, schema_root=SCHEMA_ROOT)

        self.assertEqual(tuple(binding.contract_id for binding in model_set.bindings), S2_REQUIRED_CONTRACT_IDS)
        self.assertEqual(model_set.by_id("C1").version, "1.0.0")
        self.assertEqual(model_set.by_id("C2").schema, "c2.job-envelope.schema.json")
        self.assertEqual(model_set.by_id("C4").version, "1.0.0")
        self.assertEqual(model_set.by_id("C6").version, "2.0.0")

    def test_stale_generated_binding_digest_fails_closed(self) -> None:
        stale = dict(CONTRACT_BY_ID)
        stale["C2"] = replace(CONTRACT_BY_ID["C2"], schema_sha256="sha256:" + "0" * 64)

        with self.assertRaises(S2ContractModelError):
            validate_s2_contract_model_set(stale, schema_root=SCHEMA_ROOT)

    def test_c2_minor_version_with_unknown_field_compiles_build_spec(self) -> None:
        payload = {
            **self.example,
            "contract_version": "1.4.0",
            "future_scheduler_hint": {"ignored_by_s2": True},
            "problem_spec": {
                "task_type": "surrogate_emulation",
                "observable": "toy_order_parameter",
                "inputs_schema": [
                    {"name": "temperature", "units": "GeV"},
                    {"name": "alpha", "units": "dimensionless", "role": "control"},
                ],
            },
        }

        spec = compile_build_spec_from_c2_envelope(payload, runtime_version="1.0.0")

        self.assertEqual(spec.job_id, self.example["job_id"])
        self.assertEqual(spec.task_type, "surrogate_emulation")
        self.assertEqual(spec.target_observable, "toy_order_parameter")
        self.assertEqual(spec.allowed_adapters, ("adapter:toy-bounce",))
        self.assertEqual(spec.budget.max_wallclock_seconds, 600)
        self.assertEqual([field.units for field in spec.fields], ["GeV", "dimensionless"])
        self.assertFalse(hasattr(spec, "future_scheduler_hint"))

    def test_c2_unsupported_major_rejects_before_build_spec(self) -> None:
        payload = {**self.example, "contract_version": "2.0.0"}

        with self.assertRaises(C2ContractError) as raised:
            compile_build_spec_from_c2_envelope(payload, runtime_version="1.0.0")

        self.assertEqual(raised.exception.error.category, "PERMANENT")
        self.assertEqual(raised.exception.error.code, "VERSION_UNSUPPORTED")

    def test_build_spec_units_contract_requires_units_per_field(self) -> None:
        payload = {
            **self.example,
            "problem_spec": {
                "observable": "toy_order_parameter",
                "inputs_schema": [{"name": "temperature", "units": ""}],
            },
        }

        with self.assertRaises(S2ContractModelError):
            compile_build_spec_from_c2_envelope(payload)


if __name__ == "__main__":
    unittest.main()
