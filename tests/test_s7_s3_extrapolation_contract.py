from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    EvalRequest,
    InMemoryArtifactStore,
    Quantity,
    SimpleAdapter,
    c6_eval_result_payload,
)
from argus_core.s1 import _eval_result_payload
from argus_core.s3 import CheckResult


ROOT = Path(__file__).resolve().parents[1]
C6_SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c6.compute-adapter.schema.json"


class S3C6ExtrapolationContractError(ValueError):
    """Raised when an S3 contract fixture cannot safely consume C6 output."""


class S3ExtrapolationProfileConsumer:
    """Test-only C3 consumer for the S7-T32 C6 extrapolation contract."""

    def __init__(self, *, max_extrapolated_fraction: float = 0.0) -> None:
        if not 0.0 <= max_extrapolated_fraction <= 1.0:
            raise ValueError("max_extrapolated_fraction must be within [0, 1]")
        self._max_extrapolated_fraction = max_extrapolated_fraction

    def consume_cross_code_outputs(self, payloads: tuple[Mapping[str, Any], ...]) -> CheckResult:
        if not payloads:
            raise S3C6ExtrapolationContractError("C6 outputs cannot be empty")

        extrapolated_count = 0
        for index, payload in enumerate(payloads):
            in_validity_domain = payload.get("in_validity_domain")
            extrapolation_flag = payload.get("extrapolation_flag")
            if not isinstance(in_validity_domain, bool) or not isinstance(extrapolation_flag, bool):
                raise S3C6ExtrapolationContractError(
                    f"C6 output {index} must include boolean in_validity_domain and extrapolation_flag"
                )
            if extrapolation_flag == in_validity_domain:
                raise S3C6ExtrapolationContractError(
                    f"C6 output {index} has inconsistent validity-domain state"
                )
            extrapolated_count += int(extrapolation_flag)

        extrapolated_fraction = extrapolated_count / len(payloads)
        metrics = {
            "test_cases": ["S7-TC39"],
            "c6_output_count": len(payloads),
            "extrapolated_result_count": extrapolated_count,
            "extrapolated_fraction": extrapolated_fraction,
            "max_extrapolated_fraction": self._max_extrapolated_fraction,
            "numeric_coercion_performed": False,
        }
        if extrapolated_fraction > self._max_extrapolated_fraction:
            return CheckResult(
                check="CROSS_CODE",
                status="INCONCLUSIVE",
                metrics={
                    **metrics,
                    "failure_reason": "EXTRAPOLATION_NOT_PERMITTED",
                    "profile_allows_extrapolation": False,
                },
            )
        return CheckResult(
            check="CROSS_CODE",
            status="PASS",
            metrics={
                **metrics,
                "failure_reason": None,
                "profile_allows_extrapolation": True,
            },
        )


class S7S3ExtrapolationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads(C6_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        cls._validator = Draft202012Validator(schema)

    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.broker = AdapterBroker(artifact_store=self.store)
        self.broker.register(self._adapter())

    def test_tc39_default_profile_turns_schema_valid_extrapolated_c6_output_inconclusive(self) -> None:
        result = self._evaluate(v_w=1.2)
        payload = self._wire_payload(result)

        self._assert_c6_valid(payload)
        self.assertEqual(payload, _eval_result_payload(result))

        decision = S3ExtrapolationProfileConsumer().consume_cross_code_outputs((payload,))

        self.assertEqual(decision.check, "CROSS_CODE")
        self.assertEqual(decision.status, "INCONCLUSIVE")
        self.assertEqual(decision.metrics["test_cases"], ["S7-TC39"])
        self.assertEqual(decision.metrics["failure_reason"], "EXTRAPOLATION_NOT_PERMITTED")
        self.assertEqual(decision.metrics["extrapolated_result_count"], 1)
        self.assertEqual(decision.metrics["extrapolated_fraction"], 1.0)
        self.assertFalse(decision.metrics["numeric_coercion_performed"])

    def test_profile_explicitly_permitting_extrapolation_can_continue_with_valid_points(self) -> None:
        payloads = tuple(
            self._wire_payload(self._evaluate(v_w=value))
            for value in (0.60, 0.80, 1.20)
        )
        for payload in payloads:
            self._assert_c6_valid(payload)

        decision = S3ExtrapolationProfileConsumer(
            max_extrapolated_fraction=1.0 / 3.0
        ).consume_cross_code_outputs(payloads)

        self.assertEqual(decision.check, "CROSS_CODE")
        self.assertEqual(decision.status, "PASS")
        self.assertTrue(decision.metrics["profile_allows_extrapolation"])
        self.assertEqual(decision.metrics["extrapolated_result_count"], 1)
        self.assertAlmostEqual(decision.metrics["extrapolated_fraction"], 1.0 / 3.0)

    def test_missing_or_inconsistent_c6_domain_flags_fail_closed(self) -> None:
        payload = self._wire_payload(self._evaluate(v_w=1.2))
        missing_flag = dict(payload)
        missing_flag.pop("extrapolation_flag")

        self._assert_c6_invalid(missing_flag)
        with self.assertRaisesRegex(S3C6ExtrapolationContractError, "boolean"):
            S3ExtrapolationProfileConsumer().consume_cross_code_outputs((missing_flag,))

        inconsistent_flags = dict(payload)
        inconsistent_flags["in_validity_domain"] = True
        with self.assertRaisesRegex(S3C6ExtrapolationContractError, "inconsistent"):
            S3ExtrapolationProfileConsumer().consume_cross_code_outputs((inconsistent_flags,))

    def _evaluate(self, *, v_w: float):
        return self.broker.evaluate(
            EvalRequest(
                adapter_id="gw_spectrum_contract_fixture",
                inputs={
                    "T_n": Quantity(value=100.0, units="GeV"),
                    "alpha": Quantity(value=0.2, units="dimensionless"),
                    "v_w": Quantity(value=v_w, units="dimensionless"),
                },
                seed=17,
            )
        )

    @staticmethod
    def _adapter() -> SimpleAdapter:
        descriptor = AdapterDescriptor(
            adapter_id="gw_spectrum_contract_fixture",
            version="1.0.0",
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref="c4://adapter/gw-spectrum-contract-fixture/v1",
            domain_policy="flag",
        )
        return SimpleAdapter(descriptor, S7S3ExtrapolationContractTests._evaluate_adapter)

    @staticmethod
    def _evaluate_adapter(inputs: dict[str, Any], _seed: int | None) -> dict[str, Quantity]:
        return {
            "omega": Quantity(
                value=inputs["alpha"].value * inputs["T_n"].value / 1000.0,
                units="dimensionless",
                uncertainty={"kind": "interval", "radius": 0.01},
            )
        }

    @staticmethod
    def _wire_payload(result: Any) -> dict[str, Any]:
        return json.loads(json.dumps(c6_eval_result_payload(result), sort_keys=True))

    def _assert_c6_valid(self, payload: Mapping[str, Any]) -> None:
        errors = sorted(self._validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def _assert_c6_invalid(self, payload: Mapping[str, Any]) -> None:
        errors = sorted(self._validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertTrue(errors, msg=f"payload unexpectedly validated: {payload}")


if __name__ == "__main__":
    unittest.main()
