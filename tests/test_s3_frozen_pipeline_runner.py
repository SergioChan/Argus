from __future__ import annotations

from dataclasses import replace
import json
import unittest

from argus_core import (
    BudgetCaps,
    BudgetUsage,
    EgressRule,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemorySandboxOrchestrator,
    InMemoryTokenService,
    LaunchEnvelope,
    Lineage,
    PolicyBundle,
    Producer,
    ResourceCeilings,
    S3FrozenPipelineRunnerError,
    S3FrozenPipelineRunner,
    SandboxExecutionResult,
    SandboxHandle,
    SandboxPartialResult,
    ScopeGrant,
)


class S3FrozenPipelineRunnerTests(unittest.TestCase):
    def test_default_nested_envelope_fits_the_deployed_m0_memory_ceiling(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline()
        audit = InMemoryAuditLedger()
        runner_s10 = _ScriptedNestedS10(audit=audit, mode="success")
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
        )

        result = runner.run(self._validation_request(frozen_ref))

        envelope = result.launch_request.requested_envelope
        self.assertEqual(envelope.mem_bytes, 128 * 1024 * 1024)
        self.assertLessEqual(envelope.mem_bytes, 128 * 1024 * 1024)
        self.assertEqual(envelope.wallclock_s, 10)
        self.assertLessEqual(envelope.cpu_m * envelope.wallclock_s / 1_000, 10)

    def test_tc25_launches_frozen_pipeline_only_through_nested_s10_sandbox(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline(entrypoint="evil_nonexistent_module.predict")
        audit = InMemoryAuditLedger()
        runner_s10 = _ScriptedNestedS10(audit=audit, mode="success")
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
        )

        result = runner.run(self._validation_request(frozen_ref))

        self.assertEqual(result.status, "SUCCEEDED")
        self.assertEqual(len(runner_s10.requests), 1)
        launch_request = runner_s10.requests[0]
        self.assertEqual(launch_request.image, "sha256:" + "c" * 64)
        self.assertEqual(launch_request.entrypoint, ("python", "-m", "argus_runtime.s3_frozen_pipeline_entrypoint"))
        self.assertIn("evil_nonexistent_module.predict", " ".join(launch_request.args))
        self.assertTrue(result.evidence_ref.startswith("c4://artifact/"))

        evidence = self._artifact_payload(store, result.evidence_ref)
        self.assertEqual(evidence["schema"], "argus.s3.frozen_pipeline_run_evidence.v1")
        self.assertEqual(evidence["execution_boundary"], "nested_s10_sandbox")
        self.assertFalse(evidence["verifier_imported_pipeline_code"])
        self.assertEqual(evidence["sandbox"]["state"], "SUCCEEDED")
        self.assertEqual(evidence["s3_test_cases"]["S3-TC25"]["status"], "PASS")
        self.assertIn("sandbox.launched", evidence["audit_event_types"])

    def test_nested_runner_passes_immutable_pipeline_and_opaque_inputs_and_returns_execution(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline()
        audit = InMemoryAuditLedger()
        runner_s10 = _ScriptedNestedS10(audit=audit, mode="success")
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
        )

        result = runner.run(
            self._validation_request(frozen_ref),
            execution_inputs={"x": {"value": 0.5, "units": "dimensionless"}},
        )

        launch = runner_s10.requests[0]
        self.assertEqual(launch.image, "sha256:" + "c" * 64)
        self.assertEqual(result.execution.stdout, "{\"ok\": true}")
        self.assertEqual(result.execution.handle.sandbox_id, result.sandbox_id)
        self.assertIn("--frozen-pipeline-json", launch.args)
        self.assertIn("--inputs-json", launch.args)
        pipeline_payload = json.loads(launch.args[launch.args.index("--frozen-pipeline-json") + 1])
        input_payload = json.loads(launch.args[launch.args.index("--inputs-json") + 1])
        self.assertEqual(pipeline_payload["container_digest"], "sha256:" + "c" * 64)
        self.assertEqual(input_payload, {"x": {"units": "dimensionless", "value": 0.5}})

    def test_tc27_trust_mount_write_is_quarantined_with_sev1_evidence(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline(
            config={"s3_t10_probe": {"trust_path_write": True}},
        )
        audit = InMemoryAuditLedger()
        runner_s10 = _ScriptedNestedS10(audit=audit, mode="trust_path_write")
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
        )

        result = runner.run(self._validation_request(frozen_ref))

        self.assertEqual(result.status, "QUARANTINED")
        evidence = self._artifact_payload(store, result.evidence_ref)
        self.assertEqual(evidence["s3_test_cases"]["S3-TC27"]["status"], "PASS")
        self.assertEqual(evidence["quarantine"]["severity"], "Sev-1")
        self.assertEqual(evidence["quarantine"]["reason"], "SANDBOX:TRUST_PATH_WRITE")
        self.assertIn("EROFS", evidence["quarantine"]["stderr"])
        self.assertIn("s3.quarantine", evidence["audit_event_types"])

    def test_tc44_non_allowlisted_egress_is_denied_with_zero_allowed_bytes(self) -> None:
        denied = {"host": "exfil.example", "port": 443, "proto": "https"}
        store, frozen_ref = self._store_with_frozen_pipeline(
            config={"s3_t10_probe": {"egress": denied}},
        )
        audit = InMemoryAuditLedger()
        runner_s10 = _ScriptedNestedS10(audit=audit, mode="egress_denied", denied_egress=denied)
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
        )

        result = runner.run(self._validation_request(frozen_ref))

        self.assertEqual(result.status, "QUARANTINED")
        evidence = self._artifact_payload(store, result.evidence_ref)
        self.assertEqual(evidence["s3_test_cases"]["S3-TC44"]["status"], "PASS")
        self.assertEqual(evidence["egress"]["denied_dest"], denied)
        self.assertEqual(evidence["egress"]["allowed_bytes"], 0)
        self.assertIn("egress.denied", evidence["audit_event_types"])

    def test_tc25_uses_real_s10_admission_and_c4_launch_provenance(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline()
        audit = InMemoryAuditLedger()
        tokens = InMemoryTokenService(signing_key=b"s3-t10-token-key", now_fn=lambda: 1_000)
        budget, scope = self._tokens(job_id=self._job_id(), tokens=tokens)
        orchestrator = InMemorySandboxOrchestrator(
            token_service=tokens,
            quota_ledger=InMemoryQuotaLedger(),
            audit_ledger=audit,
            policy_bundle=PolicyBundle(
                bundle_version="s3-t10-real-s10-test",
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                resource_ceilings=ResourceCeilings(
                    cpu_m=2_000,
                    mem_bytes=1_000_000_000,
                    gpu_count=0,
                    wallclock_s=30,
                    max_cost_usd=1,
                ),
                risk_to_runtime={"standard": "gvisor", "federated": "firecracker", "high": "firecracker"},
                seccomp_profile_hash="blake3:" + "a" * 64,
                signer_key_id="policy",
                signature="test-signature",
            ),
            artifact_store=store,
        )
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=orchestrator,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
        )

        result = runner.run(self._validation_request(frozen_ref))

        self.assertEqual(result.status, "ADMITTED")
        launch_record = store.get_record(result.evidence_ref)
        self.assertEqual(launch_record.kind, "s3_frozen_pipeline_run")
        evidence = self._artifact_payload(store, result.evidence_ref)
        launch_ref = evidence["sandbox"]["launch_provenance_ref"]
        self.assertTrue(str(launch_ref).startswith("c4://artifact/"))
        self.assertEqual(store.get_record(str(launch_ref)).kind, "container")
        self.assertEqual(evidence["s3_test_cases"]["S3-TC25"]["status"], "PASS")
        self.assertIn("sandbox.launched", evidence["audit_event_types"])

    def test_missing_digest_pinned_image_fails_closed_before_s10_launch(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline(container_digest=None)
        audit = InMemoryAuditLedger()
        runner_s10 = _ScriptedNestedS10(audit=audit, mode="success")
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
        )

        with self.assertRaises(S3FrozenPipelineRunnerError) as raised:
            runner.run(self._validation_request(frozen_ref))

        self.assertEqual(raised.exception.code, "S3_FROZEN_PIPELINE_IMAGE_REQUIRED")
        self.assertEqual(runner_s10.requests, [])

    def test_unpinned_image_fails_closed_before_s10_launch(self) -> None:
        store, frozen_ref = self._store_with_frozen_pipeline(container_digest="latest")
        audit = InMemoryAuditLedger()
        runner_s10 = _ScriptedNestedS10(audit=audit, mode="success")
        budget, scope = self._tokens(job_id=self._job_id())
        runner = S3FrozenPipelineRunner(
            artifact_store=store,
            sandbox_orchestrator=runner_s10,
            audit_ledger=audit,
            budget_token=budget,
            scope_token=scope,
            launch_envelope=self._launch_envelope(),
        )

        with self.assertRaises(S3FrozenPipelineRunnerError) as raised:
            runner.run(self._validation_request(frozen_ref))

        self.assertEqual(raised.exception.code, "S3_FROZEN_PIPELINE_IMAGE_UNPINNED")
        self.assertEqual(runner_s10.requests, [])

    def _store_with_frozen_pipeline(
        self,
        *,
        entrypoint: str = "argus_core.s2.baseline.predict",
        config: dict[str, object] | None = None,
        container_digest: str | None = "sha256:" + "c" * 64,
    ) -> tuple[InMemoryArtifactStore, str]:
        store = InMemoryArtifactStore()
        payload = {
            "schema_version": "argus-s2-frozen-pipeline-v1",
            "entrypoint": entrypoint,
            "entrypoint_contract_version": "argus.s3.frozen_pipeline_entrypoint.v1",
            "s3_executable": True,
            "artifact_refs": ["c4://artifact/model"],
            "model_ref": "c4://artifact/model",
            "io_signature": {
                "inputs": {"x": {"units": "dimensionless", "value_type": "float"}},
                "outputs": {"prediction": {"units": "dimensionless", "value_type": "float"}},
            },
            "code_ref": "git:project-argus@s3-t10",
            "environment_digest": "oci:s3-frozen-pipeline@sha256-s3-t10",
            "seed": "seed-s3-t10",
            "self_replay_passed": True,
            "config": config or {},
        }
        if container_digest is not None:
            payload["container_digest"] = container_digest
        record = store.create_artifact(
            kind="frozen_pipeline",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", actor_id="s2-freezer"),
            lineage=Lineage(
                input_refs=("c4://artifact/model",),
                code_ref="git:project-argus@s3-t10",
                environment_digest="oci:s3-frozen-pipeline@sha256-s3-t10",
                seeds=("seed-s3-t10",),
                job_id=self._job_id(),
            ),
        )
        return store, record.artifact_ref

    def _tokens(self, *, job_id: str, tokens: InMemoryTokenService | None = None):
        tokens = tokens or InMemoryTokenService(signing_key=b"s3-t10-token-key", now_fn=lambda: 1_000)
        budget = tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=100, max_wallclock_s=30, max_cost_usd=1),
            job_id=job_id,
            root_request_id="root-s3-t10",
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
        return "11111111-1111-4111-8111-000000000110"

    def _validation_request(self, frozen_pipeline_ref: str) -> dict[str, object]:
        return {
            "job_id": self._job_id(),
            "frozen_pipeline_ref": frozen_pipeline_ref,
            "artifact_refs": ["c4://artifact/model"],
            "profile_ref": "c4://profile/ewpt/v1",
            "blind_dataset_handle": "blind://vault/job-s3-t10/features",
            "budget_token_ref": "budget://token/job-s3-t10",
            "trace_id": "trace-s3-t10",
        }

    @staticmethod
    def _artifact_payload(store: InMemoryArtifactStore, artifact_ref: str) -> dict[str, object]:
        return json.loads(store.get_artifact(artifact_ref).decode("utf-8"))


class _ScriptedNestedS10:
    def __init__(
        self,
        *,
        audit: InMemoryAuditLedger,
        mode: str,
        denied_egress: dict[str, object] | None = None,
    ) -> None:
        self.audit = audit
        self.mode = mode
        self.denied_egress = denied_egress or {}
        self.requests = []

    def launch_and_wait(self, request):
        self.requests.append(request)
        sandbox_id = f"sandbox-s3-t10-{len(self.requests)}"
        handle = SandboxHandle(
            sandbox_id=sandbox_id,
            job_id=request.job_id,
            runtime_class="gvisor",
            budget_epoch=request.budget_token.budget_epoch,
            policy_bundle_version="s3-t10-test",
            state="SUCCEEDED",
            launch_provenance_ref="c4://artifact/s10-launch",
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
        if self.mode == "trust_path_write":
            partial = SandboxPartialResult(
                reason="SANDBOX:TRUST_PATH_WRITE",
                stdout="",
                stderr="EROFS verifier read-only mount",
                captured_after_freeze=True,
                freeze_succeeded=True,
                terminate_succeeded=True,
                stdout_bytes=0,
                stderr_bytes=len("EROFS verifier read-only mount"),
            )
            quarantined = replace(handle, state="QUARANTINED")
            self.audit.append(
                "s3.quarantine",
                {
                    "sandbox_id": sandbox_id,
                    "severity": "Sev-1",
                    "reason": partial.reason,
                },
            )
            return SandboxExecutionResult(
                handle=quarantined,
                exit_code=13,
                stdout="",
                stderr=partial.stderr,
                timed_out=False,
                duration_s=0.1,
                budget_usage=BudgetUsage(wallclock_s=0.1, cost_usd=0.01),
                partial_result=partial,
            )
        if self.mode == "egress_denied":
            partial = SandboxPartialResult(
                reason="SANDBOX:EGRESS_DENIED",
                stdout="",
                stderr="connection refused by S10 egress proxy",
                captured_after_freeze=True,
                freeze_succeeded=True,
                terminate_succeeded=True,
                stdout_bytes=0,
                stderr_bytes=len("connection refused by S10 egress proxy"),
            )
            quarantined = replace(handle, state="QUARANTINED")
            self.audit.append(
                "egress.denied",
                {
                    "sandbox_id": sandbox_id,
                    "dest": dict(self.denied_egress),
                    "allowed_bytes": 0,
                },
            )
            return SandboxExecutionResult(
                handle=quarantined,
                exit_code=111,
                stdout="",
                stderr=partial.stderr,
                timed_out=False,
                duration_s=0.1,
                budget_usage=BudgetUsage(wallclock_s=0.1, cost_usd=0.01),
                partial_result=partial,
            )
        self.audit.append(
            "sandbox.exited",
            {"sandbox_id": sandbox_id, "job_id": request.job_id, "exit_code": 0},
        )
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
