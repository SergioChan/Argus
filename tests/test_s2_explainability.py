from __future__ import annotations

from dataclasses import asdict
from io import StringIO
import json
import tempfile
import unittest
from pathlib import Path

from argus_core import (
    BuildOrchestrationRequest,
    BuildOrchestrator,
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    ExplainabilityReportError,
    ExplainabilityReportRequest,
    ExplainabilityReporter,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Lineage,
    MutationSpec,
    Producer,
    ProvenanceEmitter,
    SpecCompiler,
)
from argus_runtime.s2_cli import main as s2_cli_main


class S2ExplainabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.profile_catalog = C3VerifierProfileCatalog(
            (
                C3VerifierProfile(
                    profile_ref="c4://profile/s2-tc39-linear/v1",
                    profile_id="s2-tc39-linear",
                    version="1.0.0",
                    checks=("six-check", "calibration", "freeze-replay"),
                    provenance_ref="c4://profile/s2-tc39-linear/v1",
                ),
            )
        )
        self.dataset_ref = self._dataset()
        self.dataset_descriptor_ref = self._dataset_descriptor(self.dataset_ref)
        self._publish_registry_descriptors()

    def test_explainability_report_artifact_contains_required_sections(self) -> None:
        base, variant = self._completed_variant_build()

        report = ExplainabilityReporter(artifact_store=self.store).explain(
            ExplainabilityReportRequest(build_ref=variant.frozen_pipeline_ref)
        )

        self.assertEqual(report.status, "GENERATED")
        self.assertEqual(report.build_ref, variant.frozen_pipeline_ref)
        record = self.store.get_record(report.report_ref)
        payload = self._payload(report.report_ref)
        self.assertEqual(record.kind, "s2_explainability_report")
        self.assertEqual(record.claim_tier, "ran-toy")
        self.assertIn(variant.frozen_pipeline_ref, record.lineage.input_refs)
        self.assertIn(variant.hpo_selection_ref, record.lineage.input_refs)
        self.assertIn(variant.uq_calibration_ref, record.lineage.input_refs)
        self.assertIn(variant.advisory_self_check_ref, record.lineage.input_refs)
        self.assertEqual(payload["s2_tc39"], True)
        self.assertEqual(payload["build_ref"], variant.frozen_pipeline_ref)
        self.assertEqual(payload["base_pipeline_ref"], base.frozen_pipeline_ref)
        self.assertEqual(payload["claim_tier"], "ran-toy")
        self.assertEqual(payload["sections"]["rationale"]["status"], "PRESENT")
        self.assertEqual(payload["sections"]["hpo_trace"]["selected_trial_id"], variant.diagnostics["hpo"]["selected_trial_id"])
        self.assertGreaterEqual(len(payload["sections"]["hpo_trace"]["trials"]), 1)
        self.assertEqual(payload["sections"]["priors"]["cache_reuse"]["feature_set_reused"], True)
        self.assertEqual(payload["sections"]["calibration_plot"]["plot_data"]["nominal_coverage"], 0.8)
        self.assertIn("repair_actions", payload["sections"]["repair_log"])
        self.assertEqual(payload["sections"]["repair_log"]["failure_doctor_status"], "ARMED")
        self.assertFalse(payload["score_authority"]["s2_score_returned"])
        self.assertEqual(payload["score_authority"]["authoritative_reward_source"], "C3_ONLY")

    def test_explainability_rejects_missing_build_ref_before_writes(self) -> None:
        before_count = self.store.record_count

        with self.assertRaises(ExplainabilityReportError):
            ExplainabilityReporter(artifact_store=self.store).explain(
                ExplainabilityReportRequest(build_ref="c4://artifact/missing")
            )

        self.assertEqual(self.store.record_count, before_count)

    def test_argus_s2_explain_cli_reads_c4_bundle_and_writes_report(self) -> None:
        _base, variant = self._completed_variant_build()

        with tempfile.TemporaryDirectory() as tempdir:
            bundle_path = Path(tempdir) / "bundle.json"
            output_path = Path(tempdir) / "explainability.json"
            bundle_path.write_text(json.dumps(self._artifact_bundle(), sort_keys=True), encoding="utf-8")
            stdout = StringIO()
            stderr = StringIO()

            exit_code = s2_cli_main(
                [
                    "explain",
                    "--store",
                    str(bundle_path),
                    "--build",
                    variant.frozen_pipeline_ref,
                    "--out",
                    str(output_path),
                    "--format",
                    "json",
                ],
                stdout=stdout,
                stderr=stderr,
            )

            self.assertEqual(exit_code, 0, stderr.getvalue())
            cli_summary = json.loads(stdout.getvalue())
            report_payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(cli_summary["status"], "GENERATED")
            self.assertEqual(cli_summary["build_ref"], variant.frozen_pipeline_ref)
            self.assertEqual(report_payload["sections"]["rationale"]["status"], "PRESENT")
            self.assertIn("hpo_trace", report_payload["sections"])
            self.assertIn("calibration_plot", report_payload["sections"])
            self.assertIn("repair_log", report_payload["sections"])

    def _completed_variant_build(self):
        orchestrator = self._orchestrator()
        base = orchestrator.build(self._request(job_id="33333333-3333-4333-8333-333333333333", seed="base-seed"))
        variant = orchestrator.build_variant(
            base_pipeline_ref=base.frozen_pipeline_ref,
            request=self._request(job_id="44444444-4444-4444-8444-444444444444", seed="variant-seed"),
            mutation=MutationSpec(
                variant_id="variant-explainability",
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
            code_ref="git:s2-explainability-test",
            environment_digest="oci:s2-explainability-test@sha256:fixture",
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
            "root_request_id": "33333333-3333-4333-8333-333333334444",
            "trace_id": f"trace-s2-tc39-{job_id[:8]}",
            "subtopic": "s2-tc39-explainability",
            "problem_spec": {
                "task_type": "regression",
                "observable": "y",
                "target_units": "GeV",
                "inputs_schema": [
                    {"name": "x", "units": "GeV"},
                ],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": "c4://profile/s2-tc39-linear/v1",
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
                "allowed_datasets": ["dataset:s2-tc39-linear"],
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
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc39-dataset"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-tc39-dataset",
                environment_digest="oci:s2-tc39-dataset",
                job_id="s2-tc39-dataset",
            ),
        ).artifact_ref

    def _dataset_descriptor(self, dataset_ref: str) -> str:
        return self.store.create_artifact(
            kind="dataset_descriptor",
            payload={
                "dataset_id": "dataset:s2-tc39-linear",
                "dataset_ref": dataset_ref,
                "rows": 60,
                "schema": {"features": ["x"], "target": "y"},
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc39-descriptor"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="git:s2-tc39-descriptor",
                environment_digest="oci:s2-tc39-descriptor",
                job_id="s2-tc39-descriptor",
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
                subtopics=("s2-tc39-explainability",),
            )
        )
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="dataset:s2-tc39-linear",
                revision=1,
                kind="dataset",
                owner_subsystem="S8",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="local",
                capability_scopes=("c4.read",),
                provenance_ref=self.dataset_descriptor_ref,
                subtopics=("s2-tc39-explainability",),
            )
        )

    def _artifact_bundle(self) -> dict[str, object]:
        artifacts = []
        for record in self.store.query_artifacts():
            artifacts.append(
                {
                    "record": {
                        "artifact_ref": record.artifact_ref,
                        "kind": record.kind,
                        "producer": asdict(record.producer),
                        "lineage": asdict(record.lineage),
                        "claim_tier": record.claim_tier,
                        "validation_report_ref": record.validation_report_ref,
                        "created_at": record.created_at,
                    },
                    "payload": self._payload(record.artifact_ref),
                }
            )
        return {"artifacts": artifacts}

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
