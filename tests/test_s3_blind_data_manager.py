from __future__ import annotations

import json
import unittest

from argus_core import (
    BudgetCaps,
    BudgetUsage,
    EgressRule,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryBlindDataVault,
    InMemoryTokenService,
    LaunchEnvelope,
    Lineage,
    Producer,
    S3BlindDataManager,
    S3BlindDataVaultError,
    S3FrozenPipelineRunner,
    SandboxExecutionResult,
    SandboxHandle,
    ScopeGrant,
)


class S3BlindDataManagerTests(unittest.TestCase):
    def test_tc26_runner_stages_only_opaque_input_and_keeps_truth_server_side(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline()
        audit = InMemoryAuditLedger()
        vault = InMemoryBlindDataVault(artifact_store=store, audit_ledger=audit)
        dataset = vault.register_dataset(
            dataset_id="s3-t12-injection",
            version="1.0.0",
            split="blind",
            dataset_kind="injection",
            opaque_input={
                "schema": "argus.s3.opaque_input.v1",
                "sample_ids": ["blind-1"],
                "features": [{"x": 1.0, "units": "dimensionless"}],
            },
            truth={"target": "secret-label-42", "amplitude": 1.25},
        )
        runner_s10 = _RecordingNestedS10(audit=audit)
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
            blind_data_manager=S3BlindDataManager(artifact_store=store, vault=vault, audit_ledger=audit),
        )

        result = runner.run(self._validation_request(frozen_ref=frozen_ref, blind_handle=dataset.handle))

        self.assertEqual(result.status, "SUCCEEDED")
        self.assertEqual(len(runner_s10.requests), 1)
        launch_args = " ".join(runner_s10.requests[0].args)
        self.assertNotIn("secret-label-42", launch_args)
        self.assertNotIn(dataset.truth_hash, launch_args)
        self.assertNotIn(dataset.handle, launch_args)

        evidence = self._artifact_payload(store, result.evidence_ref)
        self.assertEqual(evidence["s3_test_cases"]["S3-TC26"]["status"], "PASS")
        stage = evidence["blind_data_stage"]
        self.assertTrue(stage["truth_retained_server_side"])
        self.assertFalse(stage["truth_bytes_delivered_to_sandbox"])
        self.assertFalse(stage["truth_hash_delivered_to_sandbox"])
        self.assertEqual(stage["vault_handle_hash"], dataset.handle_hash)
        self.assertTrue(stage["opaque_input_ref"].startswith("c4://artifact/"))
        self.assertEqual(
            evidence["entrypoint_request"]["verification_request"]["blind_data_handle"],
            stage["opaque_input_ref"],
        )

        opaque_payload = self._artifact_payload(store, stage["opaque_input_ref"])
        opaque_text = json.dumps(opaque_payload, sort_keys=True)
        self.assertIn("blind-1", opaque_text)
        self.assertNotIn("secret-label-42", opaque_text)
        self.assertNotIn(dataset.truth_hash, opaque_text)
        self.assertEqual(vault.truth_for_scoring(dataset.handle), {"target": "secret-label-42", "amplitude": 1.25})

    def test_blind_hash_mismatch_quarantines_before_s10_launch(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline()
        audit = InMemoryAuditLedger()
        vault = InMemoryBlindDataVault(artifact_store=store, audit_ledger=audit)
        dataset = vault.register_dataset(
            dataset_id="s3-t12-mismatch",
            version="1.0.0",
            split="blind",
            dataset_kind="held_out",
            opaque_input={"schema": "argus.s3.opaque_input.v1", "samples": [{"x": 2.0}]},
            truth={"target": "actual-server-side-truth"},
            expected_truth_hash="blake3:" + "0" * 64,
        )
        runner_s10 = _RecordingNestedS10(audit=audit)
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
            blind_data_manager=S3BlindDataManager(artifact_store=store, vault=vault, audit_ledger=audit),
        )

        with self.assertRaises(S3BlindDataVaultError) as raised:
            runner.run(self._validation_request(frozen_ref=frozen_ref, blind_handle=dataset.handle))

        self.assertEqual(raised.exception.code, "S3_BLIND_DATA_HASH_MISMATCH")
        self.assertTrue(raised.exception.quarantine_ref.startswith("c4://artifact/"))
        self.assertEqual(runner_s10.requests, [])
        quarantine = self._artifact_payload(store, raised.exception.quarantine_ref)
        self.assertEqual(quarantine["status"], "QUARANTINED")
        self.assertEqual(quarantine["quarantine"]["severity"], "Sev-1")
        self.assertEqual(quarantine["quarantine"]["reason"], "S3:BLIND_HASH_MISMATCH")
        self.assertEqual(quarantine["mismatch"]["field"], "truth_hash")
        self.assertNotIn("actual-server-side-truth", json.dumps(quarantine, sort_keys=True))
        self.assertIn("s3.quarantine", [event.event_type for event in audit.events()])

    def test_opaque_input_rejects_label_material_before_c4_write(self) -> None:
        store = InMemoryArtifactStore()
        vault = InMemoryBlindDataVault(artifact_store=store)

        with self.assertRaises(S3BlindDataVaultError) as raised:
            vault.register_dataset(
                dataset_id="s3-t12-bad-opaque",
                version="1.0.0",
                split="blind",
                dataset_kind="blind",
                opaque_input={"features": [{"x": 1.0}], "labels": [1]},
                truth={"labels": [1]},
            )

        self.assertEqual(raised.exception.code, "S3_BLIND_OPAQUE_INPUT_LABEL_MATERIAL_FORBIDDEN")
        self.assertEqual(store.query_artifacts(), ())

    def test_stage_evidence_has_c4_lineage_without_raw_truth(self) -> None:
        store = InMemoryArtifactStore()
        audit = InMemoryAuditLedger()
        vault = InMemoryBlindDataVault(artifact_store=store, audit_ledger=audit)
        dataset = vault.register_dataset(
            dataset_id="s3-t12-null",
            version="1.0.0",
            split="null",
            dataset_kind="null_control",
            opaque_input={"schema": "argus.s3.opaque_input.v1", "samples": [{"x": 0.0}]},
            truth={"target": "null-truth"},
        )
        manager = S3BlindDataManager(artifact_store=store, vault=vault, audit_ledger=audit)

        stage = manager.stage_for_pipeline(blind_data_handle=dataset.handle, job_id=self._job_id(), trace_id="trace-s3-t12")

        stage_payload = self._artifact_payload(store, stage.stage_evidence_ref)
        self.assertEqual(stage_payload["schema"], "argus.s3.blind_data_stage.v1")
        self.assertEqual(stage_payload["status"], "STAGED")
        self.assertEqual(stage_payload["opaque_input_ref"], stage.opaque_input_ref)
        self.assertEqual(stage_payload["truth_hash"], dataset.truth_hash)
        self.assertNotIn("null-truth", json.dumps(stage_payload, sort_keys=True))
        stage_record = store.get_record(stage.stage_evidence_ref)
        self.assertIn(stage.opaque_input_ref, stage_record.lineage.input_refs)
        self.assertIn(dataset.metadata_ref, stage_record.lineage.input_refs)

    def _store_with_frozen_pipeline(self) -> tuple[InMemoryArtifactStore, str]:
        store = InMemoryArtifactStore()
        payload = {
            "schema_version": "argus-s2-frozen-pipeline-v1",
            "entrypoint": "argus_core.s2.baseline.predict",
            "entrypoint_contract_version": "argus.s3.frozen_pipeline_entrypoint.v1",
            "s3_executable": True,
            "artifact_refs": ["c4://artifact/model"],
            "model_ref": "c4://artifact/model",
            "io_signature": {
                "inputs": {"x": {"units": "dimensionless", "value_type": "float"}},
                "outputs": {"prediction": {"units": "dimensionless", "value_type": "float"}},
            },
            "code_ref": "git:project-argus@s3-t12",
            "environment_digest": "oci:s3-frozen-pipeline@sha256-s3-t12",
            "container_digest": "sha256:" + "d" * 64,
            "seed": "seed-s3-t12",
            "self_replay_passed": True,
            "config": {},
        }
        record = store.create_artifact(
            kind="frozen_pipeline",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", actor_id="s2-freezer"),
            lineage=Lineage(
                input_refs=("c4://artifact/model",),
                code_ref="git:project-argus@s3-t12",
                environment_digest="oci:s3-frozen-pipeline@sha256-s3-t12",
                seeds=("seed-s3-t12",),
                job_id=self._job_id(),
            ),
        )
        return store, record.artifact_ref

    def _tokens(self, *, job_id: str):
        tokens = InMemoryTokenService(signing_key=b"s3-t12-token-key", now_fn=lambda: 1_000)
        budget = tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=100, max_wallclock_s=30, max_cost_usd=1),
            job_id=job_id,
            root_request_id="root-s3-t12",
        )
        scope = tokens.mint_scope(
            job_id=job_id,
            scopes=ScopeGrant(
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                broker_audiences=("store",),
                capabilities=("s8.read",),
                producer_subsystems=("S3",),
                disallowed_actions=("direct_ledger_write", "direct_egress"),
            ),
        )
        return budget, scope

    @staticmethod
    def _launch_envelope() -> LaunchEnvelope:
        return LaunchEnvelope(
            cpu_m=1_000,
            mem_bytes=512_000_000,
            gpu_count=0,
            wallclock_s=10,
            scratch_bytes=1_000_000,
            pids=32,
            estimated_cost_usd=0.01,
        )

    @staticmethod
    def _job_id() -> str:
        return "11111111-1111-4111-8111-000000000112"

    def _validation_request(self, *, frozen_ref: str, blind_handle: str) -> dict[str, object]:
        return {
            "job_id": self._job_id(),
            "frozen_pipeline_ref": frozen_ref,
            "artifact_refs": ["c4://artifact/model"],
            "profile_ref": "c4://profile/ewpt/v1",
            "blind_dataset_handle": blind_handle,
            "budget_token_ref": "budget://token/job-s3-t12",
            "trace_id": "trace-s3-t12",
        }

    @staticmethod
    def _artifact_payload(store: InMemoryArtifactStore, artifact_ref: str) -> dict[str, object]:
        return json.loads(store.get_artifact(artifact_ref).decode("utf-8"))


class _RecordingNestedS10:
    def __init__(self, *, audit: InMemoryAuditLedger) -> None:
        self.audit = audit
        self.requests = []

    def launch_and_wait(self, request):
        self.requests.append(request)
        sandbox_id = f"sandbox-s3-t12-{len(self.requests)}"
        handle = SandboxHandle(
            sandbox_id=sandbox_id,
            job_id=request.job_id,
            runtime_class="gvisor",
            budget_epoch=request.budget_token.budget_epoch,
            policy_bundle_version="s3-t12-test",
            state="SUCCEEDED",
            launch_provenance_ref="c4://artifact/s10-launch-s3-t12",
        )
        self.audit.append(
            "sandbox.launched",
            {
                "sandbox_id": sandbox_id,
                "job_id": request.job_id,
                "runtime_class": "gvisor",
                "pid_namespace": f"pidns:{sandbox_id}",
            },
        )
        self.audit.append("sandbox.exited", {"sandbox_id": sandbox_id, "job_id": request.job_id, "exit_code": 0})
        return SandboxExecutionResult(
            handle=handle,
            exit_code=0,
            stdout="{\"ok\": true}",
            stderr="",
            timed_out=False,
            duration_s=0.1,
            budget_usage=BudgetUsage(wallclock_s=0.1, cost_usd=0.01),
            partial_result=None,
        )


if __name__ == "__main__":
    unittest.main()
