from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    AdapterBroker,
    c6_eval_result_payload,
    EvalRequest,
    GWSpectrumAdapter,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Quantity,
    S7RegistrationService,
    register_gw_spectrum_adapter,
)


C6_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/contracts/c6.compute-adapter.schema.json"


class GWSpectrumReferenceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact_store = InMemoryArtifactStore()
        self.adapter = GWSpectrumAdapter()
        self.broker = AdapterBroker(artifact_store=self.artifact_store)
        self.broker.register(self.adapter.as_simple_adapter())

    def test_peak_frequency_and_amplitude_follow_sound_wave_scaling(self) -> None:
        slow = self._evaluate(beta_over_h=100.0, frequency_hz=0.003)
        fast = self._evaluate(beta_over_h=200.0, frequency_hz=0.006)

        self.assertAlmostEqual(
            fast.outputs["peak_frequency"].value / slow.outputs["peak_frequency"].value,
            2.0,
            places=12,
        )
        self.assertAlmostEqual(
            fast.outputs["peak_omega"].value / slow.outputs["peak_omega"].value,
            0.5,
            places=12,
        )
        self.assertLess(fast.outputs["peak_omega"].value, slow.outputs["peak_omega"].value)

        slow_at_peak = self._evaluate(
            beta_over_h=100.0,
            frequency_hz=slow.outputs["peak_frequency"].value,
        )
        fast_at_peak = self._evaluate(
            beta_over_h=200.0,
            frequency_hz=fast.outputs["peak_frequency"].value,
        )
        self.assertAlmostEqual(
            slow_at_peak.outputs["omega"].value,
            slow.outputs["peak_omega"].value,
            places=18,
        )
        self.assertAlmostEqual(
            fast_at_peak.outputs["omega"].value,
            fast.outputs["peak_omega"].value,
            places=18,
        )

    def test_spectrum_is_non_negative_over_the_declared_domain(self) -> None:
        for frequency_hz in (1e-6, 1e-5, 1e-4, 1e-3, 3e-3, 1e-2, 1e-1):
            result = self._evaluate(beta_over_h=100.0, frequency_hz=frequency_hz)

            self.assertTrue(result.in_validity_domain)
            self.assertFalse(result.extrapolation_flag)
            self.assertGreaterEqual(result.outputs["omega"].value, 0.0)
            self.assertEqual(result.outputs["omega"].units, "dimensionless")
            self.assertGreater(result.outputs["omega"].uncertainty["radius"], 0.0)
            self.assertGreater(result.outputs["peak_frequency"].value, 0.0)
            self.assertEqual(result.outputs["peak_frequency"].units, "Hz")
            self.assertTrue(result.provenance_ref.startswith("c4://"))

    def test_real_broker_result_serializes_as_schema_valid_c6(self) -> None:
        result = self._evaluate(beta_over_h=100.0, frequency_hz=0.003)
        payload = c6_eval_result_payload(result)
        schema = json.loads(C6_SCHEMA_PATH.read_text(encoding="utf-8"))

        self.assertEqual(list(Draft202012Validator(schema).iter_errors(payload)), [])
        self.assertEqual(payload["adapter_id"], "gw_spectrum")
        self.assertEqual(set(payload["outputs"]), {"omega", "peak_omega", "peak_frequency"})

    def test_out_of_domain_wall_velocity_is_flagged_but_has_provenance(self) -> None:
        result = self._evaluate(beta_over_h=100.0, frequency_hz=0.003, wall_velocity=1.1)

        self.assertFalse(result.in_validity_domain)
        self.assertTrue(result.extrapolation_flag)
        self.assertIn("v_w", result.violated_fields)
        self.assertGreaterEqual(result.outputs["omega"].value, 0.0)
        record = self.artifact_store.get_record(result.provenance_ref)
        self.assertEqual(record.producer.subsystem, "S7")
        provenance = json.loads(self.artifact_store.get_artifact(result.provenance_ref).decode("utf-8"))
        self.assertEqual(provenance["underlying_code_version"], "argus-core:gw-sound-wave-template-v1")

    def test_registration_publishes_real_reference_adapter_to_c5(self) -> None:
        registry = InMemoryRegistry(artifact_store=self.artifact_store)
        service = S7RegistrationService(registry=registry, artifact_store=self.artifact_store)

        registration = register_gw_spectrum_adapter(service)
        resolution = registry.resolve(kind="adapter", subtopic="ewpt", required_scope="evaluate")

        self.assertTrue(registration.conformance.passed)
        self.assertTrue(registration.determinism.checked)
        self.assertTrue(registration.determinism.passed)
        self.assertEqual([descriptor.entity_id for descriptor in resolution.descriptors], ["gw_spectrum"])
        resolved = resolution.descriptors[0]
        self.assertEqual(resolved.revision, 1)
        self.assertEqual(resolved.cost_class, "standard")
        self.assertIn("gw-sound-wave-template-v1", resolved.independence_tags)
        self.assertTrue(registration.revision_ref.startswith("c4://"))

    def _evaluate(
        self,
        *,
        beta_over_h: float,
        frequency_hz: float,
        wall_velocity: float = 0.7,
    ):
        return self.broker.evaluate(
            EvalRequest(
                adapter_id="gw_spectrum",
                inputs={
                    "T_n": Quantity(value=100.0, units="GeV"),
                    "alpha": Quantity(value=0.2, units="dimensionless"),
                    "beta_over_H": Quantity(value=beta_over_h, units="dimensionless"),
                    "v_w": Quantity(value=wall_velocity, units="dimensionless"),
                    "frequency": Quantity(value=frequency_hz, units="Hz"),
                },
                seed=17,
            )
        )


if __name__ == "__main__":
    unittest.main()
