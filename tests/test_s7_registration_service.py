from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    Adapter,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Quantity,
    S7CostCeiling,
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
    adapter_id="registration-fixture",
    version="1.0.0",
    cost_class="standard",
    independence_tags=("registration-fixture-impl",),
)
@uncertainty(kind="interval")
@validity_domain(declare_domain_box({"alpha": (0.0, 1.0)}))
@units_out({"omega": "dimensionless"})
@units_in({"alpha": "dimensionless"})
class RegistrationFixtureAdapter(Adapter):
    def evaluate(self, inputs, _ctx):
        return {
            "omega": Quantity(
                value=inputs["alpha"].value * 0.5,
                units="dimensionless",
                uncertainty={"kind": "interval", "radius": 0.01},
            )
        }


@adapter_metadata(
    adapter_id="registration-heavy-fixture",
    version="1.0.0",
    cost_class="heavy",
    independence_tags=("registration-heavy-impl",),
)
@uncertainty(kind="interval")
@validity_domain(declare_domain_box({"alpha": (0.0, 1.0)}))
@units_out({"omega": "dimensionless"})
@units_in({"alpha": "dimensionless"})
class HeavyRegistrationFixtureAdapter(RegistrationFixtureAdapter):
    pass


@adapter_metadata(
    adapter_id="registration-nonconformant-fixture",
    version="1.0.0",
    cost_class="standard",
    independence_tags=("registration-nonconformant-impl",),
)
@uncertainty(kind="interval")
@validity_domain(declare_domain_box({"alpha": (0.0, 1.0)}))
@units_out({"omega": "dimensionless"})
@units_in({"alpha": "dimensionless"})
class NonconformantRegistrationFixtureAdapter(Adapter):
    def evaluate(self, inputs, _ctx):
        return {"omega": Quantity(value=inputs["alpha"].value, units="dimensionless")}


class S7RegistrationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.service = S7RegistrationService(
            registry=self.registry,
            artifact_store=self.store,
            cost_ceiling=S7CostCeiling(allowed_cost_classes=("toy", "standard")),
        )
        self.sample_inputs = {"alpha": Quantity(value=0.2, units="dimensionless")}

    def test_cost_class_ceiling_rejects_heavy_before_registry_publication(self) -> None:
        with self.assertRaises(S7RegistrationError) as raised:
            self.service.register(
                adapter=HeavyRegistrationFixtureAdapter(),
                subtopics=("ewpt",),
                sample_inputs=self.sample_inputs,
            )

        self.assertEqual(raised.exception.category, "COST_CLASS_EXCEEDED")
        self.assertEqual(self.registry.events, ())
        self.assertEqual(self.registry.resolve(kind="adapter", subtopic="ewpt").descriptors, ())

    def test_conformance_failure_prevents_c5_publication(self) -> None:
        with self.assertRaises(S7RegistrationError) as raised:
            self.service.register(
                adapter=NonconformantRegistrationFixtureAdapter(),
                subtopics=("ewpt",),
                sample_inputs=self.sample_inputs,
            )

        self.assertEqual(raised.exception.category, "CONFORMANCE_FAILED")
        self.assertEqual(self.registry.events, ())

    def test_conformant_adapter_publishes_resolvable_c5_revision_with_cost_class(self) -> None:
        registration = self.service.register(
            adapter=RegistrationFixtureAdapter(),
            subtopics=("ewpt",),
            sample_inputs=self.sample_inputs,
        )
        resolution = self.registry.resolve(kind="adapter", subtopic="ewpt", required_scope="evaluate")

        self.assertTrue(registration.conformance.passed)
        self.assertEqual(registration.revision_ref, registration.capability.provenance_ref)
        self.assertEqual(registration.revision_ref, registration.conformance.eval_result.provenance_ref)
        self.assertEqual(self.store.get_record(registration.revision_ref).kind, "log")
        self.assertEqual([descriptor.entity_id for descriptor in resolution.descriptors], ["registration-fixture"])
        resolved = resolution.descriptors[0]
        self.assertEqual(resolved.revision, 1)
        self.assertEqual(resolved.cost_class, "standard")
        self.assertEqual(resolved.independence_tags, ("registration-fixture-impl",))
        self.assertEqual(resolution.pinned_revisions, {"registration-fixture": 1})
        self.assertEqual(
            list(
                Draft202012Validator(json.loads(C5_SCHEMA_PATH.read_text(encoding="utf-8"))).iter_errors(
                    resolved.as_c5_payload()
                )
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
