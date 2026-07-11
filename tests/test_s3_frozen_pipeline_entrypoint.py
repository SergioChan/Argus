from __future__ import annotations

import json
import subprocess
import sys
import unittest

from argus_core.s2 import (
    S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
    S2_FROZEN_PIPELINE_SCHEMA_VERSION,
)


class S3FrozenPipelineEntrypointTests(unittest.TestCase):
    def test_executes_the_frozen_pipeline_from_opaque_inputs(self) -> None:
        completed = self._run_entrypoint(
            inputs={"adapter_omega_scaled": {"value": 0.5, "units": "dimensionless"}},
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = json.loads(completed.stdout)
        self.assertEqual(output["schema"], "argus.s3.frozen_pipeline_execution_output.v1")
        self.assertEqual(output["frozen_pipeline_ref"], "c4://artifact/reference-pipeline")
        self.assertEqual(output["outputs_units_tagged"]["omega_scaled"]["units"], "dimensionless")
        self.assertAlmostEqual(output["outputs_units_tagged"]["omega_scaled"]["value"], 1.1)
        self.assertEqual(output["uncertainty"]["kind"], "interval")
        self.assertNotIn("reference-truth", completed.stdout)

    def test_rejects_truth_material_in_sandbox_inputs_without_echoing_it(self) -> None:
        completed = self._run_entrypoint(
            inputs={
                "adapter_omega_scaled": {"value": 0.5, "units": "dimensionless"},
                "truth": "reference-truth",
            },
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("S3_FROZEN_PIPELINE_EXECUTION_INPUT_LABEL_MATERIAL_FORBIDDEN", completed.stderr)
        self.assertNotIn("reference-truth", completed.stdout + completed.stderr)

    def _run_entrypoint(self, *, inputs: dict[str, object]) -> subprocess.CompletedProcess[str]:
        request = {
            "schema": "argus.s3.frozen_pipeline_entrypoint_request.v1",
            "verification_request": {
                "request_id": "s3-entrypoint-test",
                "job_id": "11111111-1111-4111-8111-000000000111",
                "profile_ref": "c4://profile/ewpt-reference/v1",
                "frozen_pipeline_ref": "c4://artifact/reference-pipeline",
                "blind_data_handle": "c4://artifact/opaque-input",
            },
            "entrypoint": {
                "method": "predict",
                "entrypoint_ref": "predict",
                "frozen_pipeline_ref": "c4://artifact/reference-pipeline",
                "record_kind": "frozen_pipeline",
                "content_hash": "blake3:" + "a" * 64,
                "code_ref": "git:project-argus@s3-entrypoint-test",
                "environment_digest": "oci:argus-s3-entrypoint-test",
            },
            "artifact_refs": ["c4://artifact/reference-pipeline", "c4://artifact/opaque-input"],
        }
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "argus_runtime.s3_frozen_pipeline_entrypoint",
                "--entrypoint-request-json",
                json.dumps(request, separators=(",", ":"), sort_keys=True),
                "--frozen-pipeline-json",
                json.dumps(self._frozen_pipeline_payload(), separators=(",", ":"), sort_keys=True),
                "--inputs-json",
                json.dumps(inputs, separators=(",", ":"), sort_keys=True),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _frozen_pipeline_payload() -> dict[str, object]:
        return {
            "schema_version": S2_FROZEN_PIPELINE_SCHEMA_VERSION,
            "entrypoint": "predict",
            "entrypoint_contract_version": S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
            "s3_executable": True,
            "container_digest": "sha256:" + "b" * 64,
            "self_replay_passed": True,
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
                    "weights": {"adapter_omega_scaled": 2.0},
                    "bias": 0.1,
                },
            },
            "uq_calibration": {
                "uncertainty_method": "split_conformal",
                "interval": {"kind": "symmetric_conformal", "radius": 0.05},
            },
        }


if __name__ == "__main__":
    unittest.main()
