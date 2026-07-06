from __future__ import annotations

import json
import unittest

from argus_core import (
    BuildOrchestrationRequest,
    BuildOrchestrator,
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    InMemoryArtifactStore,
    InMemoryRegistry,
    InMemoryS2EventBus,
    InMemoryS2TelemetrySink,
    Lineage,
    Producer,
    ProvenanceEmitter,
    S2SandboxViolation,
    SpecCompiler,
)


class S2ObservabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.event_bus = InMemoryS2EventBus()
        self.telemetry_sink = InMemoryS2TelemetrySink()
        self.profile_catalog = C3VerifierProfileCatalog(
            (
                C3VerifierProfile(
                    profile_ref="c4://profile/s2-tc23-linear/v1",
                    profile_id="s2-tc23-linear",
                    version="1.0.0",
                    checks=("six-check", "calibration", "freeze-replay"),
                    provenance_ref="c4://profile/s2-tc23-linear/v1",
                ),
            )
        )
        self.dataset_ref = self._dataset()
        self.dataset_descriptor_ref = self._dataset_descriptor(self.dataset_ref)
        self._publish_registry_descriptors()

    def test_build_emits_trace_spans_and_s2_build_events(self) -> None:
        result = self._orchestrator().build(self._request())

        events = self.event_bus.events()
        subjects = [event.subject for event in events]
        phase_events = self.event_bus.subscribe("s2.build.phase")
        spans = self.telemetry_sink.spans("trace-s2-tc23-observability")
        span_names = {span.name for span in spans}

        self.assertEqual(subjects[0], "s2.build.started")
        self.assertIn("s2.build.phase", subjects)
        self.assertEqual(subjects[-1], "s2.build.completed")
        self.assertEqual(len(phase_events), 10)
        self.assertEqual(
            [event.payload["phase"] for event in phase_events],
            [
                "spec_compiler",
                "sandbox_guard",
                "data_manager",
                "feature_graph",
                "model_synthesizer",
                "hpo_engine",
                "training_runtime",
                "uq_calibrator",
                "advisory_self_check",
                "pipeline_freezer",
            ],
        )
        self.assertIn("S2.build", span_names)
        self.assertIn("S2.spec_compiler", span_names)
        self.assertIn("S2.sandbox_guard", span_names)
        self.assertIn("S2.pipeline_freezer", span_names)
        for event in events:
            self.assertEqual(event.trace_id, "trace-s2-tc23-observability")
            self.assertEqual(event.root_request_id, "66666666-6666-4666-8666-666666666667")
            self.assertEqual(event.payload["job_id"], result.job_id)
            self.assertEqual(event.payload["subtopic"], "s2-tc23-observability")
        completed = self.event_bus.subscribe("s2.build.completed")[0]
        self.assertEqual(completed.payload["status"], "SUCCEEDED")
        self.assertEqual(completed.payload["frozen_pipeline_ref"], result.frozen_pipeline_ref)
        self.assertEqual(completed.payload["artifact_count"], len(result.artifact_refs))
        self.assertEqual(result.diagnostics["s2_tc23"], "PASS")
        self.assertIn("observability", result.diagnostics)
        self.assertEqual(result.diagnostics["observability"]["event_subjects"], subjects)
        self.assertEqual(result.diagnostics["observability"]["span_names"], [span.name for span in spans])

    def test_sandbox_quarantine_emits_quarantined_event_and_span(self) -> None:
        with self.assertRaises(S2SandboxViolation) as raised:
            self._orchestrator().build(
                self._request(
                    allowed_egress=(),
                    sandbox_egress_probe={
                        "host": "blocked.example",
                        "port": 443,
                        "proto": "https",
                        "sni": "blocked.example",
                    },
                )
            )

        quarantined = self.event_bus.subscribe("s2.build.quarantined")
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].trace_id, "trace-s2-tc23-observability")
        self.assertEqual(quarantined[0].payload["status"], "QUARANTINED")
        self.assertEqual(quarantined[0].payload["code"], "EGRESS_DENIED")
        self.assertEqual(quarantined[0].payload["evidence_ref"], raised.exception.evidence_ref)
        span_names = {span.name for span in self.telemetry_sink.spans("trace-s2-tc23-observability")}
        self.assertIn("S2.build", span_names)
        self.assertIn("S2.sandbox_guard", span_names)
        failed_build_span = [span for span in self.telemetry_sink.spans() if span.name == "S2.build"][-1]
        self.assertEqual(failed_build_span.attributes["status"], "QUARANTINED")
        self.assertEqual(failed_build_span.attributes["code"], "EGRESS_DENIED")

    def _orchestrator(self) -> BuildOrchestrator:
        compiler = SpecCompiler(
            verifier_profiles=self.profile_catalog,
            capability_registry=self.registry,
            artifact_store=self.store,
        )
        return BuildOrchestrator(
            artifact_store=self.store,
            spec_compiler=compiler,
            provenance_emitter=self.emitter,
            hpo_scheduler_backend="threadpool",
            event_bus=self.event_bus,
            telemetry_sink=self.telemetry_sink,
        )

    def _request(
        self,
        *,
        allowed_egress: tuple[dict[str, object], ...] = ({"host": "store.local", "port": 443, "proto": "https"},),
        sandbox_egress_probe: dict[str, object] | None = None,
    ) -> BuildOrchestrationRequest:
        return BuildOrchestrationRequest(
            c2_envelope=self._c2_payload(allowed_egress=allowed_egress),
            code_ref="git:s2-observability-test",
            environment_digest="oci:s2-observability-test@sha256:fixture",
            seed="s2-tc23-seed",
            hpo_parameter_grid={"learning_rate": (0.02, 0.05)},
            hpo_max_epochs=2,
            final_max_epochs=5,
            train_ratio=0.6,
            validation_ratio=0.2,
            test_ratio=0.2,
            nominal_coverage=0.8,
            coverage_tolerance=0.25,
            max_self_replay_fraction=1.0,
            cost_usd_per_epoch=0.01,
            sandbox_egress_probe=sandbox_egress_probe,
        )

    def _c2_payload(self, *, allowed_egress: tuple[dict[str, object], ...]) -> dict[str, object]:
        return {
            "contract_version": "1.0.0",
            "job_id": "66666666-6666-4666-8666-666666666666",
            "root_request_id": "66666666-6666-4666-8666-666666666667",
            "trace_id": "trace-s2-tc23-observability",
            "subtopic": "s2-tc23-observability",
            "problem_spec": {
                "task_type": "regression",
                "observable": "y",
                "target_units": "GeV",
                "inputs_schema": [
                    {"name": "x", "units": "GeV"},
                ],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": "c4://profile/s2-tc23-linear/v1",
            "contamination_index_version": "contam-2026-07-01",
            "budget": {
                "max_usd": 10.0,
                "max_wallclock_seconds": 600,
                "max_gpu_seconds": 10.0,
                "max_model_tokens": 1000,
            },
            "constraints": {"max_features": 4},
            "capability_scopes": {
                "allowed_adapters": ["adapter:s2-local-featuregraph"],
                "allowed_datasets": ["dataset:s2-tc23-linear"],
                "allowed_egress": list(allowed_egress),
            },
            "input_artifact_refs": [self.dataset_descriptor_ref],
        }

    def _dataset(self) -> str:
        rows = []
        for index in range(60):
            x_value = (index - 30) / 10.0
            rows.append(
                {
                    "row_id": f"r{index:03d}",
                    "x": x_value,
                    "y": 1.0 + 2.0 * x_value,
                    "role": "train",
                }
            )
        return self.store.create_artifact(
            kind="dataset",
            payload={
                "schema": {"features": ["x"], "target": "y"},
                "rows": rows,
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc23-dataset"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-tc23-dataset",
                environment_digest="oci:s2-tc23-dataset",
                job_id="s2-tc23-dataset",
            ),
        ).artifact_ref

    def _dataset_descriptor(self, dataset_ref: str) -> str:
        return self.store.create_artifact(
            kind="dataset_descriptor",
            payload={
                "dataset_id": "dataset:s2-tc23-linear",
                "dataset_ref": dataset_ref,
                "rows": 60,
                "schema": {"features": ["x"], "target": "y"},
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc23-descriptor"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="git:s2-tc23-descriptor",
                environment_digest="oci:s2-tc23-descriptor",
                job_id="s2-tc23-descriptor",
            ),
        ).artifact_ref

    def _publish_registry_descriptors(self) -> None:
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="adapter:s2-local-featuregraph",
                revision=1,
                kind="adapter",
                owner_subsystem="S7",
                contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
                trust_class="local",
                capability_scopes=("c6.evaluate",),
                provenance_ref="c4://descriptor/adapter-s2-local-featuregraph/v1",
                subtopics=("s2-tc23-observability",),
            )
        )
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="dataset:s2-tc23-linear",
                revision=1,
                kind="dataset",
                owner_subsystem="S8",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="local",
                capability_scopes=("c4.read",),
                provenance_ref=self.dataset_descriptor_ref,
                subtopics=("s2-tc23-observability",),
            )
        )

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
