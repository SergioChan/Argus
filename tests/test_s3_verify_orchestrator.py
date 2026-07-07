from __future__ import annotations

import json
import unittest

from argus_core import (
    BudgetCaps,
    C3ReportSigner,
    C3ReportVerifier,
    CheckPluginContext,
    CheckPluginDescriptor,
    CheckResult,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    ScopeGrant,
    build_frozen_pipeline_entrypoint_request,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest
from argus_runtime.s3_verifier_service import (
    S3_CLIENT_CERT_SUBJECT_HEADER,
    S3_VERIFY_CAPABILITY,
    S3VerificationDispatch,
    S3VerifierApiApp,
)
from argus_runtime.s3_verify_orchestrator import (
    S3_VERIFY_WORKFLOW_TYPE,
    S3CheckPluginPipelineRunner,
    InMemoryS3WorkflowStore,
    S3PipelineRunResult,
    S3VerifyOrchestrator,
)


class CountingPipelineRunner:
    def __init__(self, result: S3PipelineRunResult) -> None:
        self.result = result
        self.calls = 0

    def run(self, *, dispatch: S3VerificationDispatch, entrypoint_request: dict[str, object]) -> S3PipelineRunResult:
        self.calls += 1
        return self.result


class FailingPipelineRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, *, dispatch: S3VerificationDispatch, entrypoint_request: dict[str, object]) -> S3PipelineRunResult:
        self.calls += 1
        raise AssertionError("restart replay must not re-run an already completed pipeline activity")


class _PassPlugin:
    def __init__(self, check: str) -> None:
        self.check = check

    def describe(self) -> CheckPluginDescriptor:
        return CheckPluginDescriptor(
            check=self.check,
            plugin_ref=f"argus.s3.plugins.{self.check.lower()}",
            plugin_version="1.0.0",
            determinism="deterministic",
        )

    def run(self, ctx: CheckPluginContext) -> CheckResult:
        return CheckResult(
            check=self.check,
            status="PASS",
            metrics={
                "profile_ref": ctx.compiled_profile.profile_ref,
                "job_id": ctx.job_id,
            },
        )


class S3VerifyOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.artifact_store = InMemoryArtifactStore(report_verifier=C3ReportVerifier(self.trust_store))
        self.frozen_record = self.artifact_store.create_artifact(
            kind="frozen_pipeline",
            payload={
                "schema": "argus.s3.frozen_pipeline_entrypoint.v1",
                "entrypoint": "argus_core.s2.baseline.predict",
                "artifact_refs": ["c4://artifact/model"],
                "model_ref": "c4://artifact/model",
                "io_signature": {
                    "inputs": [{"name": "x", "dtype": "float64"}],
                    "outputs": [{"name": "prediction", "dtype": "float64"}],
                    "uncertainty": {"representation": "interval"},
                },
                "code_ref": "git:project-argus@s3-t03",
                "environment_digest": "oci:s3-verify-workflow@sha256-s3-t03",
                "seeds": ["seed-s3-t03"],
                "self_replay_passed": True,
            },
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3-t03"),
            lineage=Lineage(
                input_refs=("c4://artifact/model",),
                code_ref="git:project-argus@s3-t03",
                environment_digest="oci:s3-verify-workflow@sha256-s3-t03",
                seeds=("seed-s3-t03",),
            ),
        )

    def test_api_starts_durable_verify_workflow(self) -> None:
        runner = CountingPipelineRunner(self._succeeded_pipeline_result())
        orchestrator = self._orchestrator(InMemoryS3WorkflowStore(), runner)
        app = S3VerifierApiApp(
            auth=self._auth(),
            artifact_store=self.artifact_store,
            health_token="health",
            orchestrator=orchestrator,
        )

        status, payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/verifications",
                query={},
                body=self._verification_request(),
                headers=self._headers(),
            )
        )

        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "DISPATCHED")
        self.assertEqual(payload["workflow_status"], "RUNNING")
        self.assertEqual(payload["workflow_type"], S3_VERIFY_WORKFLOW_TYPE)
        self.assertTrue(str(payload["workflow_id"]).startswith("s3-verify-"))
        self.assertEqual(len(orchestrator.store.events(payload["workflow_id"])), 1)

    def test_happy_path_survives_worker_restart_without_double_pipeline_run(self) -> None:
        durable_store = InMemoryS3WorkflowStore()
        runner = CountingPipelineRunner(self._succeeded_pipeline_result())
        orchestrator = self._orchestrator(durable_store, runner)
        started = orchestrator.start(self._dispatch())

        after_pipeline = orchestrator.run_next_step(started.workflow_id)
        self.assertEqual(after_pipeline.status, "RUNNING")
        self.assertEqual(runner.calls, 1)

        replay_runner = FailingPipelineRunner()
        restarted_worker = self._orchestrator(durable_store, replay_runner)
        final = restarted_worker.run_until_terminal(started.workflow_id)

        self.assertEqual(final.status, "REPORTED")
        self.assertEqual(replay_runner.calls, 0)
        self.assertIsNotNone(final.report)
        self.assertIsNotNone(final.validation_report_ref)
        assert final.report is not None
        verification = C3ReportVerifier(self.trust_store).verify(final.report)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.claim_tier, "recapitulated-known")
        stored_report = json.loads(self.artifact_store.get_artifact(str(final.validation_report_ref)).decode("utf-8"))
        self.assertEqual(stored_report, final.report)
        self.assertEqual(final.report["referee"]["distinct_from_proponent"], True)
        self.assertEqual(
            [event.event_type for event in durable_store.events(started.workflow_id)],
            [
                "WorkflowStarted",
                "PipelineRunStarted",
                "PipelineRunSucceeded",
                "ReportProduced",
                "WorkflowCompleted",
            ],
        )

    def test_check_plugin_pipeline_runner_wires_frozen_dispatch_to_report_evidence(self) -> None:
        durable_store = InMemoryS3WorkflowStore()
        runner = S3CheckPluginPipelineRunner(
            artifact_store=self.artifact_store,
            compiled_profile=_compiled_profile(),
            plugins=tuple(
                _PassPlugin(check)
                for check in (
                    "INJECTION",
                    "NULL_CONTROL",
                    "CROSS_CODE",
                    "PHYSICAL_CONSISTENCY",
                    "LEAKAGE",
                    "CALIBRATION",
                    "RECAP_BENCHMARK",
                )
            ),
        )
        orchestrator = self._orchestrator(durable_store, runner)
        started = orchestrator.start(self._dispatch())

        final = orchestrator.run_until_terminal(started.workflow_id)

        self.assertEqual(final.status, "REPORTED")
        assert final.report is not None
        checks = {check["check"]: check for check in final.report["checks"]}
        self.assertEqual(set(checks), set(check.check for check in _compiled_profile().checks))
        for check_name, check in checks.items():
            self.assertEqual(len(check["evidence_refs"]), 1)
            evidence = json.loads(self.artifact_store.get_artifact(check["evidence_refs"][0]).decode("utf-8"))
            self.assertEqual(evidence["schema"], "argus.s3.check_result_evidence.v1")
            self.assertEqual(evidence["check"], check_name)
            self.assertEqual(evidence["plugin_ref"], f"argus.s3.plugins.{check_name.lower()}")
        output = json.loads(self.artifact_store.get_artifact(str(final.output_artifact_ref)).decode("utf-8"))
        self.assertEqual(output["schema"], "argus.s3.pipeline_check_output.v1")
        self.assertEqual(len(output["evidence_refs"]), 7)

    def test_event_snapshot_rehydrates_after_process_restart(self) -> None:
        original_store = InMemoryS3WorkflowStore()
        runner = CountingPipelineRunner(self._succeeded_pipeline_result())
        orchestrator = self._orchestrator(original_store, runner)
        started = orchestrator.start(self._dispatch())
        orchestrator.run_next_step(started.workflow_id)

        rehydrated_store = InMemoryS3WorkflowStore(original_store.all_events())
        replay_runner = FailingPipelineRunner()
        restarted_process = self._orchestrator(rehydrated_store, replay_runner)
        final = restarted_process.run_until_terminal(started.workflow_id)

        self.assertEqual(final.status, "REPORTED")
        self.assertEqual(replay_runner.calls, 0)
        self.assertEqual(final.event_count, 5)

    def test_start_is_idempotent_for_same_dispatch(self) -> None:
        durable_store = InMemoryS3WorkflowStore()
        orchestrator = self._orchestrator(durable_store, CountingPipelineRunner(self._succeeded_pipeline_result()))
        dispatch = self._dispatch()

        first = orchestrator.start(dispatch)
        second = orchestrator.start(dispatch)

        self.assertEqual(first.workflow_id, second.workflow_id)
        self.assertEqual([event.event_type for event in durable_store.events(first.workflow_id)], ["WorkflowStarted"])

    def test_budget_breach_halts_and_records_partial_capture(self) -> None:
        durable_store = InMemoryS3WorkflowStore()
        runner = CountingPipelineRunner(
            S3PipelineRunResult.budget_halted(
                reason="budget_exceeded",
                partial_result_ref="c4://artifact/s3-t03-partial",
                captured_stdout_bytes=128,
            )
        )
        orchestrator = self._orchestrator(durable_store, runner)
        started = orchestrator.start(self._dispatch())

        final = orchestrator.run_until_terminal(started.workflow_id)

        self.assertEqual(final.status, "BUDGET_HALTED")
        self.assertIsNone(final.report)
        self.assertEqual(final.partial_result_ref, "c4://artifact/s3-t03-partial")
        self.assertEqual(runner.calls, 1)
        self.assertEqual(
            [event.event_type for event in durable_store.events(started.workflow_id)],
            ["WorkflowStarted", "PipelineRunStarted", "BudgetHaltCaptured", "WorkflowCompleted"],
        )

    def _orchestrator(self, store: InMemoryS3WorkflowStore, runner: object) -> S3VerifyOrchestrator:
        return S3VerifyOrchestrator(
            store=store,
            artifact_store=self.artifact_store,
            verifier_id="s3-referee",
            signer_key_id="s3-key",
            signer=self.signer,
            pipeline_runner=runner,
        )

    def _auth(self) -> RuntimeAuth:
        return RuntimeAuth(
            {
                "valid-token": RuntimeIdentity(
                    caller_id="builder",
                    job_id="job-s3-t03",
                    root_request_id="root-s3-t03",
                    scopes=ScopeGrant(capabilities=(S3_VERIFY_CAPABILITY,)),
                    budget_caps=BudgetCaps(),
                )
            }
        )

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": "Bearer valid-token",
            S3_CLIENT_CERT_SUBJECT_HEADER: "builder",
        }

    def _verification_request(self) -> dict[str, object]:
        return {
            "job_id": "job-s3-t03",
            "profile_ref": "c4://profile/ewpt/v1",
            "frozen_pipeline_ref": self.frozen_record.artifact_ref,
            "artifact_refs": ["c4://artifact/model"],
            "blind_dataset_handle": "blind://vault/job-s3-t03/features",
            "budget_token_ref": "budget://token/job-s3-t03",
            "scope_token_ref": "scope://token/job-s3-t03",
            "trace_id": "trace-s3-t03",
        }

    def _dispatch(self) -> S3VerificationDispatch:
        entrypoint_request = build_frozen_pipeline_entrypoint_request(
            self._verification_request(),
            artifact_store=self.artifact_store,
        )
        verification_request = entrypoint_request["verification_request"]
        return S3VerificationDispatch(
            request_id=str(verification_request["request_id"]),
            job_id=str(verification_request["job_id"]),
            profile_ref=str(verification_request["profile_ref"]),
            frozen_pipeline_ref=str(verification_request["frozen_pipeline_ref"]),
            trace_id="trace-s3-t03",
            caller_id="builder",
            client_cert_subject="builder",
            transport="test",
            entrypoint_request=entrypoint_request,
        )

    @staticmethod
    def _succeeded_pipeline_result() -> S3PipelineRunResult:
        return S3PipelineRunResult.succeeded(
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
                CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
            ),
            output_artifact_ref="c4://artifact/s3-t03-output",
            cost_actual_usd=0.0042,
        )


def _compiled_profile() -> CompiledProfile:
    checks = (
        "INJECTION",
        "NULL_CONTROL",
        "CROSS_CODE",
        "PHYSICAL_CONSISTENCY",
        "LEAKAGE",
        "CALIBRATION",
        "RECAP_BENCHMARK",
    )
    return CompiledProfile(
        profile_id="s3-orchestrator-plugin-runner",
        revision=1,
        profile_ref="c4://profile/s3-orchestrator-plugin-runner/v1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-orchestrator-plugin-runner",
        public_profile={"profile_id": "s3-orchestrator-plugin-runner", "revision": 1, "checks": list(checks)},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=tuple(
            CompiledCheckSpec(
                check=check,
                plugin_ref=f"argus.s3.plugins.{check.lower()}",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds={},
                determinism="deterministic",
                seed=31 + index,
                tolerance={},
                requires_independence=check == "CROSS_CODE",
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            )
            for index, check in enumerate(checks)
        ),
        independence_policy={"requires_cross_code": True, "min_independent": 2},
        determinism_profile={"deterministic_checks": list(checks)},
    )


if __name__ == "__main__":
    unittest.main()
