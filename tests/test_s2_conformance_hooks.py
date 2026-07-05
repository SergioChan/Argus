from __future__ import annotations

import json
import unittest

from argus_core import (
    BuildOrchestrationRequest,
    BuildOrchestrator,
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    ConformanceService,
    ConformanceSuiteVersion,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Lineage,
    MutationSpec,
    Producer,
    ProvenanceEmitter,
    S2ConformanceHarness,
    S2ConformanceRequest,
    SpecCompiler,
)


class S2ConformanceHarnessHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.profile_catalog = C3VerifierProfileCatalog(
            (
                C3VerifierProfile(
                    profile_ref="c4://profile/s2-tc25-linear/v1",
                    profile_id="s2-tc25-linear",
                    version="1.0.0",
                    checks=("six-check", "calibration", "freeze-replay"),
                    provenance_ref="c4://profile/s2-tc25-linear/v1",
                ),
            )
        )
        self.dataset_ref = self._dataset()
        self.dataset_descriptor_ref = self._dataset_descriptor(self.dataset_ref)
        self._publish_registry_descriptors()
        self.standard_release = self.store.create_artifact(
            kind="standard_release",
            payload={"version": "1.0.0", "contracts": ["C1", "C5"]},
            producer=Producer(subsystem="S12", version="0.0.0", job_id="s2-tc25-standard"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-tc25-standard",
                environment_digest="oci:s2-tc25-standard",
                job_id="s2-tc25-standard",
            ),
        )
        self.suite = ConformanceSuiteVersion(
            suite_version="s2-s12-conformance.v1",
            standard_release_ref=self.standard_release.artifact_ref,
        )
        self.service = ConformanceService(
            suite=self.suite,
            signer_key_id="s12-conformance",
            signer_secret=b"s12-s2-conformance-secret",
        )

    def test_s2_variant_fixture_passes_s12_silver_from_real_c4_artifacts(self) -> None:
        _base, variant = self._completed_variant_build()

        result = S2ConformanceHarness(artifact_store=self.store, conformance_service=self.service).run(
            S2ConformanceRequest(build_result=variant, level="silver", entity_id="s2-builder-fixture")
        )

        self.assertTrue(result.record.aggregate_passed)
        self.assertEqual(result.record.level_awarded, "silver")
        self.assertEqual(result.status, "PASSED")
        by_id = {check.check_id: check for check in result.record.checks}
        self.assertEqual(by_id["SLV-UNCERTAINTY-MANDATORY"].status, "PASS")
        self.assertEqual(by_id["SLV-REFUSE-NO-VERIFIER"].status, "PASS")
        self.assertEqual(by_id["SLV-ERROR-ENVELOPE"].status, "PASS")
        self.assertEqual(result.bundle.descriptor_draft.contract_versions["C1"], "1.0.0")
        self.assertEqual(result.bundle.descriptor_draft.contract_versions["C5"], "1.0.0")

        record_payload = json.loads(self.store.get_artifact(result.record_ref).decode("utf-8"))
        record = self.store.get_record(result.record_ref)
        self.assertEqual(record.kind, "conformance_record")
        self.assertEqual(record_payload["level_awarded"], "silver")
        self.assertIn(variant.frozen_pipeline_ref, record.lineage.input_refs)
        self.assertIn(variant.uq_calibration_ref, record.lineage.input_refs)
        self.assertIn(variant.advisory_self_check_ref, record.lineage.input_refs)

    def test_gold_recursion_safe_path_passes_with_no_reward_score_authority(self) -> None:
        base, variant = self._completed_variant_build()

        result = S2ConformanceHarness(artifact_store=self.store, conformance_service=self.service).run(
            S2ConformanceRequest(
                build_result=variant,
                level="gold",
                entity_id="s2-builder-fixture-gold",
                base_pipeline_ref=base.frozen_pipeline_ref,
                independence_tags=("s2-impl-A", "s2-impl-B"),
            )
        )

        self.assertTrue(result.record.aggregate_passed)
        self.assertEqual(result.record.level_awarded, "gold")
        by_id = {check.check_id: check for check in result.record.checks}
        self.assertEqual(by_id["GLD-RECURSION-NO-REWARD-WRITE"].status, "PASS")
        self.assertEqual(by_id["GLD-REPRO-MANIFEST"].status, "PASS")
        self.assertEqual(result.recursion_safety["reward_source"], "c3-only")
        self.assertFalse(result.recursion_safety["s2_score_returned"])
        self.assertEqual(result.recursion_safety["base_pipeline_ref"], base.frozen_pipeline_ref)

    def test_gold_recursion_reward_path_write_probe_quarantines_record(self) -> None:
        _base, variant = self._completed_variant_build()

        result = S2ConformanceHarness(artifact_store=self.store, conformance_service=self.service).run(
            S2ConformanceRequest(
                build_result=variant,
                level="gold",
                entity_id="s2-builder-fixture-unsafe",
                reward_path_write_attempt=True,
            )
        )

        by_id = {check.check_id: check for check in result.record.checks}
        self.assertFalse(result.record.aggregate_passed)
        self.assertEqual(result.status, "QUARANTINED")
        self.assertEqual(result.record.status, "QUARANTINED")
        self.assertEqual(result.record.level_awarded, "silver")
        self.assertEqual(by_id["GLD-RECURSION-NO-REWARD-WRITE"].status, "FAIL")

    def _completed_variant_build(self):
        orchestrator = self._orchestrator()
        base = orchestrator.build(self._request(job_id="33333333-3333-4333-8333-333333333333", seed="base-seed"))
        variant = orchestrator.build_variant(
            base_pipeline_ref=base.frozen_pipeline_ref,
            request=self._request(job_id="44444444-4444-4444-8444-444444444444", seed="variant-seed"),
            mutation=MutationSpec(
                variant_id="variant-conformance",
                model_family="tabular-baseline",
                parameters={"learning_rate": 0.02},
            ),
            warm_start_ref=base.hpo_selection_ref,
        )
        return base, variant

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

    def _request(self, *, job_id: str, seed: str) -> BuildOrchestrationRequest:
        return BuildOrchestrationRequest(
            c2_envelope=self._c2_payload(job_id=job_id),
            code_ref="git:s2-conformance-test",
            environment_digest="oci:s2-conformance-test@sha256:fixture",
            seed=seed,
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
        )

    def _c2_payload(self, *, job_id: str) -> dict[str, object]:
        return {
            "contract_version": "1.0.0",
            "job_id": job_id,
            "root_request_id": "33333333-3333-4333-8333-333333335555",
            "trace_id": f"trace-s2-tc25-{job_id[:8]}",
            "subtopic": "s2-tc25-conformance",
            "problem_spec": {
                "task_type": "regression",
                "observable": "y",
                "target_units": "GeV",
                "inputs_schema": [{"name": "x", "units": "GeV"}],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": "c4://profile/s2-tc25-linear/v1",
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
                "allowed_datasets": ["dataset:s2-tc25-linear"],
                "allowed_egress": [],
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
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc25-dataset"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-tc25-dataset",
                environment_digest="oci:s2-tc25-dataset",
                job_id="s2-tc25-dataset",
            ),
        ).artifact_ref

    def _dataset_descriptor(self, dataset_ref: str) -> str:
        return self.store.create_artifact(
            kind="dataset_descriptor",
            payload={
                "dataset_id": "dataset:s2-tc25-linear",
                "dataset_ref": dataset_ref,
                "schema": {"features": ["x"], "target": "y"},
                "row_count": 60,
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc25-dataset-descriptor"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="git:s2-tc25-dataset-descriptor",
                environment_digest="oci:s2-tc25-dataset-descriptor",
                job_id="s2-tc25-dataset-descriptor",
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
                subtopics=("s2-tc25-conformance",),
                independence_tags=("s2-featuregraph-independent",),
            )
        )
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="dataset:s2-tc25-linear",
                revision=1,
                kind="dataset",
                owner_subsystem="S8",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="internal",
                capability_scopes=("c4.read",),
                provenance_ref=self.dataset_descriptor_ref,
                subtopics=("s2-tc25-conformance",),
                independence_tags=("s2-dataset-independent",),
            )
        )


if __name__ == "__main__":
    unittest.main()
