from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    Adapter,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Quantity,
    RegistryError,
    S7DeterminismResult,
    S7RegistrationError,
    S7RegistrationService,
    adapter_metadata,
    declare_domain_box,
    uncertainty,
    units_in,
    units_out,
    validity_domain,
)


ROOT = Path(__file__).resolve().parents[1]
C5_SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c5.capability-descriptor.schema.json"


@adapter_metadata(
    adapter_id="determinism-fixture",
    version="1.0.0",
    cost_class="standard",
    independence_tags=("determinism-fixture-impl",),
)
@uncertainty(kind="interval")
@validity_domain(declare_domain_box({"alpha": (0.0, 1.0)}))
@units_out({"omega": "dimensionless"})
@units_in({"alpha": "dimensionless"})
class DeterministicFixtureAdapter(Adapter):
    def evaluate(self, inputs, _ctx):
        return {
            "omega": Quantity(
                value=inputs["alpha"].value * 0.5,
                units="dimensionless",
                uncertainty={"kind": "interval", "radius": 0.01},
            )
        }


@adapter_metadata(
    adapter_id="determinism-violating-fixture",
    version="1.0.0",
    cost_class="standard",
    independence_tags=("determinism-violating-fixture-impl",),
)
@uncertainty(kind="interval")
@validity_domain(declare_domain_box({"alpha": (0.0, 1.0)}))
@units_out({"omega": "dimensionless"})
@units_in({"alpha": "dimensionless"})
class DeterminismViolatingFixtureAdapter(Adapter):
    def __init__(self) -> None:
        self._calls = 0

    def evaluate(self, inputs, _ctx):
        self._calls += 1
        return {
            "omega": Quantity(
                value=inputs["alpha"].value + self._calls,
                units="dimensionless",
                uncertainty={"kind": "interval", "radius": 0.01},
            )
        }


class S7DeterminismTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.service = S7RegistrationService(registry=self.registry, artifact_store=self.store)
        self.sample_inputs = {"alpha": Quantity(value=0.2, units="dimensionless")}

    def test_deterministic_registration_rechecks_byte_stable_output_and_provenance(self) -> None:
        registration = self.service.register(
            adapter=DeterministicFixtureAdapter(),
            subtopics=("ewpt",),
            sample_inputs=self.sample_inputs,
            seed=17,
        )

        determinism = registration.determinism
        self.assertIsInstance(determinism, S7DeterminismResult)
        self.assertTrue(determinism.checked)
        self.assertTrue(determinism.passed)
        self.assertEqual(determinism.baseline_output_hash, determinism.recheck_output_hash)
        self.assertEqual(determinism.baseline_provenance_hash, determinism.recheck_provenance_hash)
        self.assertIsNotNone(determinism.evidence_ref)
        evidence = json.loads(self.store.get_artifact(determinism.evidence_ref))
        self.assertTrue(evidence["passed"])
        self.assertEqual(evidence["baseline"]["output_hash"], evidence["recheck"]["output_hash"])
        self.assertEqual(evidence["baseline"]["provenance_hash"], evidence["recheck"]["provenance_hash"])

        resolution = self.registry.resolve(kind="adapter", subtopic="ewpt", required_scope="evaluate")
        self.assertEqual([descriptor.entity_id for descriptor in resolution.descriptors], ["determinism-fixture"])
        self.assertEqual(resolution.descriptors[0].revision, 1)
        self.assertEqual(registration.capability.contract_versions["C5"], "2.0.0")

    def test_determinism_violation_quarantines_c5_revision_and_excludes_resolution(self) -> None:
        with self.assertRaises(S7RegistrationError) as raised:
            self.service.register(
                adapter=DeterminismViolatingFixtureAdapter(),
                subtopics=("ewpt",),
                sample_inputs=self.sample_inputs,
                seed=17,
            )

        self.assertEqual(raised.exception.category, "DETERMINISM_VIOLATION")
        evidence_ref = raised.exception.diagnostics["evidence_ref"]
        quarantined = self.registry.get("determinism-violating-fixture")
        self.assertEqual(quarantined.revision, 2)
        self.assertEqual(quarantined.status, "quarantined")
        self.assertEqual(quarantined.provenance_ref, evidence_ref)
        self.assertEqual(self.registry.events[-1].event_type, "s6.registry.quarantined")
        self.assertEqual(self.registry.resolve(kind="adapter", subtopic="ewpt").descriptors, ())
        with self.assertRaises(RegistryError):
            self.registry.publish(replace(quarantined, revision=3, status="active"))

        evidence = json.loads(self.store.get_artifact(evidence_ref))
        self.assertFalse(evidence["passed"])
        self.assertNotEqual(evidence["baseline"]["output_hash"], evidence["recheck"]["output_hash"])
        self.assertNotEqual(evidence["baseline"]["provenance_hash"], evidence["recheck"]["provenance_hash"])
        self.assertEqual(
            list(
                Draft202012Validator(json.loads(C5_SCHEMA_PATH.read_text(encoding="utf-8"))).iter_errors(
                    quarantined.as_c5_payload()
                )
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
