from __future__ import annotations

from unittest.mock import patch
import unittest

from argus_core import (
    C3ReportSigner,
    InMemoryArtifactStore,
    Lineage,
    Producer,
    S3Verifier,
    evaluate_sound_wave_spectrum,
)
import argus_core.s1_reference as s1_reference
from argus_core.s1_reference import ReferenceS3ValidationEngine
from argus_core.s2 import (
    S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
    S2_FROZEN_PIPELINE_SCHEMA_VERSION,
)
from argus_core.s3 import InMemoryBlindDataVault, S3BlindDataManager


class ReferenceS3SandboxExecutionTests(unittest.TestCase):
    def test_s2_reference_checks_consume_nested_sandbox_output_without_in_process_prediction(self) -> None:
        store, request, execution = self._reference_fixture()
        verifier = S3Verifier(
            verifier_id="s3-reference-verifier",
            signer_key_id="s3-reference-key",
            signer=C3ReportSigner(key_id="s3-reference-key", secret=b"s3-reference-secret"),
        )
        engine = ReferenceS3ValidationEngine(
            artifact_store=store,
            verifier=verifier,
            contamination_index=None,
            contamination_snapshot=None,
            mode="happy",
        )

        with patch.object(
            s1_reference.FrozenPipelineRunner,
            "predict",
            side_effect=AssertionError("reference verifier must not run the frozen pipeline in-process"),
        ):
            report = engine.validate(request, frozen_pipeline_execution=execution)

        self.assertTrue(report["aggregate"]["passed"])
        self.assertEqual(report["claim_tier"], "recapitulated-known")
        self.assertEqual(
            {item["check"]: item["status"] for item in report["checks"]},
            {
                "CALIBRATION": "PASS",
                "INJECTION": "PASS",
                "NULL_CONTROL": "PASS",
                "PHYSICAL_CONSISTENCY": "PASS",
                "RECAP_BENCHMARK": "PASS",
            },
        )

    def test_s2_reference_checks_consume_the_supplied_nested_blind_stage(self) -> None:
        store, request, execution = self._reference_fixture()
        verifier = S3Verifier(
            verifier_id="s3-reference-verifier",
            signer_key_id="s3-reference-key",
            signer=C3ReportSigner(key_id="s3-reference-key", secret=b"s3-reference-secret"),
        )
        engine = ReferenceS3ValidationEngine(
            artifact_store=store,
            verifier=verifier,
            contamination_index=None,
            contamination_snapshot=None,
            mode="happy",
        )
        vault = InMemoryBlindDataVault(artifact_store=store, actor_id="s3-reference-verifier")
        record = vault.register_dataset(
            dataset_id="nested-s10-recap",
            version="v1",
            split="recap",
            dataset_kind="recap_benchmark",
            opaque_input={
                "samples": [
                    {
                        "sample_id": "reference-row",
                        "inputs_units_tagged": {
                            "adapter_omega_scaled": {"value": 1.0, "units": "dimensionless"}
                        },
                    }
                ]
            },
            truth={"samples": [{"sample_id": "reference-row", "expected": 100.0}]},
        )
        stage = S3BlindDataManager(
            artifact_store=store,
            vault=vault,
            actor_id="s3-reference-verifier",
        ).stage_for_pipeline(
            blind_data_handle=record.handle,
            job_id="m1-reference-job",
            trace_id="trace:m1-reference-sandbox-output",
        )

        report = engine.validate(
            request,
            frozen_pipeline_execution=execution,
            recap_blind_data_vault=vault,
            recap_blind_data_stage=stage,
        )

        checks = {item["check"]: item["status"] for item in report["checks"]}
        self.assertEqual(checks["RECAP_BENCHMARK"], "FAIL")

    @staticmethod
    def _reference_fixture() -> tuple[InMemoryArtifactStore, dict[str, object], dict[str, object]]:
        store = InMemoryArtifactStore()
        omega = evaluate_sound_wave_spectrum(
            temperature_gev=100.0,
            alpha=0.2,
            beta_over_h=100.0,
            wall_velocity=0.7,
            frequency_hz=0.003,
        ).omega
        scale = 1e-11
        dataset = store.create_artifact(
            kind="dataset",
            payload={
                "rows": [
                    {
                        "row_id": "reference-row",
                        "T_n": 100.0,
                        "alpha": 0.2,
                        "beta_over_H": 100.0,
                        "v_w": 0.7,
                        "frequency": 0.003,
                        "adapter_omega_scaled": omega / scale,
                        "omega_scaled": omega / scale,
                        "omega": omega,
                        "known_omega": omega,
                    }
                ],
                "feature_scale": scale,
                "target_scale": scale,
                "reference_context": {},
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1-reference", job_id="m1-reference-job"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:m1-reference-dataset",
                environment_digest="oci:m1-reference-dataset",
                job_id="m1-reference-job",
            ),
        )
        frozen = store.create_artifact(
            kind="frozen_pipeline",
            payload={
                "schema_version": S2_FROZEN_PIPELINE_SCHEMA_VERSION,
                "entrypoint": "predict",
                "entrypoint_contract_version": S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
                "s3_executable": True,
                "container_digest": "sha256:" + "c" * 64,
                "self_replay_passed": True,
                "artifact_refs": [dataset.artifact_ref],
                "component_refs": {"input_refs": [dataset.artifact_ref]},
                "io_signature": {
                    "inputs": {"adapter_omega_scaled": {"units": "dimensionless", "value_type": "float"}},
                    "outputs": {"omega_scaled": {"units": "dimensionless", "value_type": "float"}},
                },
                "feature_graph": {
                    "nodes": [
                        {
                            "node_id": "adapter_omega_scaled",
                            "feature": {"terms": [{"field_name": "adapter_omega_scaled", "exponent": 1}]},
                        }
                    ]
                },
                "feature_set": {"selected_nodes": ["adapter_omega_scaled"]},
                "model_checkpoint": {
                    "backend": "deterministic-linear",
                    "model_state": {
                        "feature_names": ["adapter_omega_scaled"],
                        "weights": {"adapter_omega_scaled": 1.0},
                        "bias": 0.0,
                    },
                },
                "uq_calibration": {
                    "uncertainty_method": "split_conformal",
                    "interval": {"kind": "symmetric_conformal", "radius": max(omega / scale * 0.01, 1e-12)},
                },
                "code_ref": "git:m1-reference-pipeline",
                "environment_digest": "oci:m1-reference-pipeline",
            },
            producer=Producer(subsystem="S2", version="0.0.0", actor_id="s2-reference", job_id="m1-reference-job"),
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:m1-reference-pipeline",
                environment_digest="oci:m1-reference-pipeline",
                job_id="m1-reference-job",
            ),
        )
        request = {
            "job_id": "m1-reference-job",
            "profile_ref": "c4://profile/ewpt-reference/v1",
            "frozen_pipeline_ref": frozen.artifact_ref,
            "artifact_refs": [dataset.artifact_ref],
            "blind_dataset_handle": "blind://m1-reference/recap",
            "trace_id": "trace:m1-reference-sandbox-output",
        }
        execution = {
            "schema": "argus.s3.frozen_pipeline_execution_output.v1",
            "frozen_pipeline_ref": frozen.artifact_ref,
            "frozen_pipeline_content_hash": frozen.content_hash,
            "entrypoint": "predict",
            "outputs_units_tagged": {
                "omega_scaled": {"value": omega / scale, "units": "dimensionless"}
            },
            "uncertainty": {
                "kind": "interval",
                "source": "split_conformal",
                "radius": omega / scale * 0.01,
                "lower": omega / scale * 0.99,
                "upper": omega / scale * 1.01,
            },
            "io_signature": {
                "inputs": {"adapter_omega_scaled": {"units": "dimensionless", "value_type": "float"}},
                "outputs": {"omega_scaled": {"units": "dimensionless", "value_type": "float"}},
            },
            "diagnostics": {"loaded_from_c4": True},
        }
        return store, request, execution


if __name__ == "__main__":
    unittest.main()
