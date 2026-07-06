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
    Lineage,
    Producer,
    ProvenanceEmitter,
    S2SandboxViolation,
    SpecCompiler,
)


class S2SandboxIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.profile_catalog = C3VerifierProfileCatalog(
            (
                C3VerifierProfile(
                    profile_ref="c4://profile/s2-tc22-linear/v1",
                    profile_id="s2-tc22-linear",
                    version="1.0.0",
                    checks=("six-check", "calibration", "freeze-replay"),
                    provenance_ref="c4://profile/s2-tc22-linear/v1",
                ),
            )
        )
        self.dataset_ref = self._dataset()
        self.dataset_descriptor_ref = self._dataset_descriptor(self.dataset_ref)
        self._publish_registry_descriptors()

    def test_build_emits_s10_sandbox_evidence_and_broker_only_write_path(self) -> None:
        result = self._orchestrator().build(
            self._request(
                sandbox_env={
                    "ARGUS_SAFE_FLAG": "visible",
                    "UNLISTED_SECRET": "api_key=sk-abcdefghijklmnop",
                },
                sandbox_env_allowlist=("ARGUS_SAFE_FLAG",),
            )
        )

        self.assertEqual(result.diagnostics["s2_tc30"], "PASS")
        self.assertEqual(result.diagnostics["s2_tc31"], "PASS")
        self.assertEqual(result.diagnostics["s2_tc32"], "PASS")
        self.assertTrue(result.sandbox_evidence_ref)
        evidence_record = self.store.get_record(result.sandbox_evidence_ref or "")
        evidence_payload = json.loads(self.store.get_artifact(evidence_record.artifact_ref).decode("utf-8"))
        frozen_payload = self._payload(result.frozen_pipeline_ref)
        frozen_record = self.store.get_record(result.frozen_pipeline_ref)

        self.assertEqual(evidence_record.kind, "s2_sandbox_evidence")
        self.assertEqual(evidence_record.producer.job_id, result.job_id)
        self.assertEqual(evidence_record.lineage.job_id, result.job_id)
        self.assertEqual(evidence_payload["status"], "PASS")
        self.assertEqual(evidence_payload["checks"]["S2-TC30"]["status"], "PASS")
        self.assertEqual(evidence_payload["checks"]["S2-TC31"]["status"], "PASS")
        self.assertEqual(evidence_payload["checks"]["S2-TC32"]["status"], "PASS")
        self.assertEqual(evidence_payload["sandbox_visible_env"], {"ARGUS_SAFE_FLAG": "visible"})
        self.assertTrue(evidence_payload["secret_scan"]["zero_matches"])
        self.assertEqual(evidence_payload["secret_scan"]["scanned_keys"], ["ARGUS_SAFE_FLAG"])
        self.assertNotIn("UNLISTED_SECRET", json.dumps(evidence_payload, sort_keys=True))
        self.assertTrue(evidence_payload["direct_write_bypass"]["denied"])
        self.assertIn("store.direct_write_denied", evidence_payload["audit_events"])
        self.assertIn("store.put", evidence_payload["audit_events"])
        self.assertTrue(evidence_payload["brokered_store_client"]["opaque_handle"])
        self.assertEqual(frozen_payload["config"]["s2_tc30"], True)
        self.assertEqual(frozen_payload["config"]["s2_tc31"], True)
        self.assertEqual(frozen_payload["config"]["s2_tc32"], True)
        self.assertEqual(frozen_payload["config"]["sandbox_evidence_ref"], result.sandbox_evidence_ref)
        self.assertIn(result.sandbox_evidence_ref, frozen_record.lineage.input_refs)

    def test_non_allowlisted_egress_probe_quarantines_before_training_artifacts(self) -> None:
        before_refs = {record.artifact_ref for record in self.store.query_artifacts()}

        with self.assertRaises(S2SandboxViolation) as raised:
            self._orchestrator().build(
                self._request(
                    allowed_egress=(),
                    sandbox_egress_probe={
                        "host": "evil.local",
                        "port": 443,
                        "proto": "https",
                        "sni": "evil.local",
                    },
                )
            )

        self.assertEqual(raised.exception.status, "QUARANTINED")
        self.assertEqual(raised.exception.code, "EGRESS_DENIED")
        self.assertTrue(raised.exception.evidence_ref)
        evidence_payload = self._payload(raised.exception.evidence_ref or "")
        self.assertEqual(evidence_payload["status"], "QUARANTINED")
        self.assertEqual(evidence_payload["checks"]["S2-TC30"]["status"], "FAIL")
        self.assertEqual(evidence_payload["checks"]["S2-TC30"]["severity"], "SEV-1")
        self.assertEqual(evidence_payload["egress_probe"]["decision"], "DENY")
        self.assertEqual(evidence_payload["egress_probe"]["reason"], "egress_denied")
        new_records = [record for record in self.store.query_artifacts() if record.artifact_ref not in before_refs]
        self.assertEqual([record.kind for record in new_records], ["s2_sandbox_evidence"])

    def test_secret_shaped_allowlisted_env_quarantines_without_secret_value_leakage(self) -> None:
        with self.assertRaises(S2SandboxViolation) as raised:
            self._orchestrator().build(
                self._request(
                    sandbox_env={"ARGUS_SAFE_FLAG": "password=supersecretvalue"},
                    sandbox_env_allowlist=("ARGUS_SAFE_FLAG",),
                )
            )

        self.assertEqual(raised.exception.status, "QUARANTINED")
        self.assertEqual(raised.exception.code, "SECRET_EXPOSED")
        evidence_payload = self._payload(raised.exception.evidence_ref or "")
        payload_text = json.dumps(evidence_payload, sort_keys=True)
        self.assertEqual(evidence_payload["status"], "QUARANTINED")
        self.assertEqual(evidence_payload["checks"]["S2-TC31"]["status"], "FAIL")
        self.assertEqual(evidence_payload["secret_scan"]["zero_matches"], False)
        self.assertEqual(evidence_payload["secret_scan"]["scanned_keys"], ["ARGUS_SAFE_FLAG"])
        self.assertNotIn("supersecretvalue", payload_text)
        self.assertNotIn("password=", payload_text)

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
        )

    def _request(
        self,
        *,
        allowed_egress: tuple[dict[str, object], ...] = ({"host": "store.local", "port": 443, "proto": "https"},),
        sandbox_env: dict[str, str] | None = None,
        sandbox_env_allowlist: tuple[str, ...] = (),
        sandbox_egress_probe: dict[str, object] | None = None,
    ) -> BuildOrchestrationRequest:
        return BuildOrchestrationRequest(
            c2_envelope=self._c2_payload(allowed_egress=allowed_egress),
            code_ref="git:s2-sandbox-integration-test",
            environment_digest="oci:s2-sandbox-integration-test@sha256:fixture",
            seed="s2-tc22-seed",
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
            sandbox_env=sandbox_env or {},
            sandbox_env_allowlist=sandbox_env_allowlist,
            sandbox_egress_probe=sandbox_egress_probe,
        )

    def _c2_payload(self, *, allowed_egress: tuple[dict[str, object], ...]) -> dict[str, object]:
        return {
            "contract_version": "1.0.0",
            "job_id": "55555555-5555-4555-8555-555555555555",
            "root_request_id": "55555555-5555-4555-8555-555555555556",
            "trace_id": "trace-s2-tc22-sandbox",
            "subtopic": "s2-tc22-sandbox-integration",
            "problem_spec": {
                "task_type": "regression",
                "observable": "y",
                "target_units": "GeV",
                "inputs_schema": [{"name": "x", "units": "GeV"}],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": "c4://profile/s2-tc22-linear/v1",
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
                "allowed_datasets": ["dataset:s2-tc22-linear"],
                "allowed_egress": list(allowed_egress),
            },
            "input_artifact_refs": [self.dataset_descriptor_ref],
        }

    def _dataset(self) -> str:
        rows = []
        for index in range(60):
            x_value = (index - 30) / 10.0
            rows.append({"row_id": f"r{index:03d}", "x": x_value, "y": 1.0 + 2.0 * x_value, "role": "train"})
        return self.store.create_artifact(
            kind="dataset",
            payload={"schema": {"features": ["x"], "target": "y"}, "rows": rows},
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc22-dataset"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-tc22-dataset",
                environment_digest="oci:s2-tc22-dataset",
                job_id="s2-tc22-dataset",
            ),
        ).artifact_ref

    def _dataset_descriptor(self, dataset_ref: str) -> str:
        return self.store.create_artifact(
            kind="dataset_descriptor",
            payload={
                "dataset_id": "dataset:s2-tc22-linear",
                "dataset_ref": dataset_ref,
                "schema": {"features": ["x"], "target": "y"},
                "row_count": 60,
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc22-dataset-descriptor"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="git:s2-tc22-dataset-descriptor",
                environment_digest="oci:s2-tc22-dataset-descriptor",
                job_id="s2-tc22-dataset-descriptor",
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
                trust_class="internal",
                capability_scopes=("c6.evaluate",),
                provenance_ref="c4://adapter/s2-local-featuregraph/v1",
                subtopics=("s2-tc22-sandbox-integration",),
                independence_tags=("s2-featuregraph-independent",),
            )
        )
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="dataset:s2-tc22-linear",
                revision=1,
                kind="dataset",
                owner_subsystem="S8",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="internal",
                capability_scopes=("c4.read",),
                provenance_ref=self.dataset_descriptor_ref,
                subtopics=("s2-tc22-sandbox-integration",),
                independence_tags=("s2-dataset-independent",),
            )
        )

    def _payload(self, artifact_ref: str) -> dict[str, object]:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
