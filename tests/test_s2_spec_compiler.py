from __future__ import annotations

import json
from pathlib import Path
import unittest

from argus_core import (
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Lineage,
    Producer,
    S2SpecCompilerError,
    SpecCompiler,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = ROOT / "schemas" / "contracts" / "examples" / "c2.example.json"


class S2SpecCompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.profile_catalog = C3VerifierProfileCatalog()
        self.dataset = self.store.create_artifact(
            kind="dataset_descriptor",
            payload={"dataset_id": "dataset:ewpt-toy", "rows": 128, "schema": "toy-v1"},
            artifact_ref="c4://dataset/ewpt-toy/v1",
            producer=Producer(subsystem="S8", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:test-dataset", environment_digest="oci:test-dataset"),
        )
        self._publish_registry_descriptors()

    def test_compiles_c2_problem_constraints_and_resolves_profiles_adapters_datasets(self) -> None:
        self.profile_catalog.register(
            C3VerifierProfile(
                profile_ref="c4://profile/ewpt-toy/v1",
                profile_id="ewpt-toy",
                version="1.0.0",
                checks=("six-check",),
                provenance_ref="c4://profile/ewpt-toy/v1",
            )
        )
        compiler = SpecCompiler(
            verifier_profiles=self.profile_catalog,
            capability_registry=self.registry,
            artifact_store=self.store,
        )

        spec = compiler.compile(self._payload())

        self.assertEqual(spec.task_type, "regression")
        self.assertEqual(spec.constraints["max_features"], 8)
        self.assertEqual(spec.verifier_profile.profile_ref, "c4://profile/ewpt-toy/v1")
        self.assertEqual(spec.verifier_profile.checks, ("six-check",))
        self.assertEqual(spec.resolved_adapters[0].entity_id, "adapter:toy-bounce")
        self.assertEqual(spec.resolved_adapters[0].revision, 1)
        self.assertEqual(spec.resolved_datasets[0].entity_id, "dataset:ewpt-toy")
        self.assertEqual(spec.resolved_datasets[0].provenance_ref, self.dataset.artifact_ref)
        self.assertEqual(spec.resolved_input_artifacts[0].artifact_ref, self.dataset.artifact_ref)
        self.assertEqual(spec.resolved_input_artifacts[0].kind, "dataset_descriptor")
        self.assertEqual(
            [(field.name, field.units, field.role) for field in spec.fields],
            [
                ("temperature", "GeV", "feature"),
                ("alpha", "dimensionless", "control"),
                ("toy_order_parameter", "dimensionless", "target"),
            ],
        )

    def test_missing_verifier_profile_blocks_before_training_artifacts(self) -> None:
        compiler = SpecCompiler(
            verifier_profiles=self.profile_catalog,
            capability_registry=self.registry,
            artifact_store=self.store,
        )
        training_calls = []

        def _training_executor(_spec):
            training_calls.append(_spec)
            return self.store.create_artifact(
                kind="model",
                payload={"should_not_exist": True},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(
                    input_refs=(self.dataset.artifact_ref,),
                    code_ref="git:training",
                    environment_digest="oci:training",
                ),
            )

        with self.assertRaises(S2SpecCompilerError) as raised:
            compiler.compile_then_execute(self._payload(), _training_executor)

        self.assertEqual(raised.exception.category, "VERIFIER_UNAVAILABLE")
        self.assertEqual(raised.exception.code, "VERIFIER_PROFILE_UNAVAILABLE")
        self.assertTrue(raised.exception.before_execution)
        self.assertEqual(training_calls, [])
        self.assertNotIn("model", {record.kind for record in self.store.query_artifacts()})
        self.assertNotIn("container", {record.kind for record in self.store.query_artifacts()})

    def test_unresolvable_adapter_fails_policy_before_execution(self) -> None:
        self.profile_catalog.register(
            C3VerifierProfile(
                profile_ref="c4://profile/ewpt-toy/v1",
                profile_id="ewpt-toy",
                version="1.0.0",
                checks=("six-check",),
                provenance_ref="c4://profile/ewpt-toy/v1",
            )
        )
        compiler = SpecCompiler(
            verifier_profiles=self.profile_catalog,
            capability_registry=self.registry,
            artifact_store=self.store,
        )
        payload = self._payload()
        payload["capability_scopes"]["allowed_adapters"] = ["adapter:missing"]

        with self.assertRaises(S2SpecCompilerError) as raised:
            compiler.compile_then_execute(payload, lambda _spec: self.fail("training must not start"))

        self.assertEqual(raised.exception.category, "POLICY")
        self.assertEqual(raised.exception.code, "ADAPTER_UNAVAILABLE")
        self.assertTrue(raised.exception.before_execution)

    def _payload(self) -> dict[str, object]:
        return {
            **self.example,
            "problem_spec": {
                "task_type": "regression",
                "observable": "toy_order_parameter",
                "target_units": "dimensionless",
                "inputs_schema": [
                    {"name": "temperature", "units": "GeV"},
                    {"name": "alpha", "units": "dimensionless", "role": "control"},
                ],
            },
            "constraints": {"max_features": 8, "monotonic": ["temperature"]},
            "capability_scopes": {
                "allowed_adapters": ["adapter:toy-bounce"],
                "allowed_datasets": ["dataset:ewpt-toy"],
                "allowed_egress": [],
            },
            "input_artifact_refs": [self.dataset.artifact_ref],
        }

    def _publish_registry_descriptors(self) -> None:
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="adapter:toy-bounce",
                revision=1,
                kind="adapter",
                owner_subsystem="S7",
                contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
                trust_class="local",
                capability_scopes=("c6.evaluate",),
                provenance_ref="c4://descriptor/adapter-toy-bounce/v1",
                subtopics=("ewpt-toy",),
            )
        )
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="dataset:ewpt-toy",
                revision=1,
                kind="dataset",
                owner_subsystem="S8",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="local",
                capability_scopes=("c4.read",),
                provenance_ref=self.dataset.artifact_ref,
                subtopics=("ewpt-toy",),
            )
        )


if __name__ == "__main__":
    unittest.main()
