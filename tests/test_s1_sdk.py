from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import unittest
from weakref import ReferenceType

from jsonschema import Draft202012Validator

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    BudgetCaps,
    C3ReportSigner,
    C3ReportVerifier,
    CheckResult,
    EgressRule,
    ExecContext,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemoryS1TelemetrySink,
    InMemorySandboxOrchestrator,
    InMemoryTokenService,
    InMemoryVerifierTrustStore,
    JobEnvelope,
    LaunchEnvelope,
    LaunchRequest,
    LifecyclePolicyError,
    LifecycleState,
    LifecycleStore,
    Lineage,
    PolicyBundle,
    Producer,
    Quantity,
    ResourceCeilings,
    S1_SANDBOX_ATTACHMENT_KIND,
    S1AdapterBrokerProxy,
    ScopeGrant,
    S3Verifier,
    SimpleAdapter,
    Subagent,
    SubagentDescriptor,
    SubagentSDKRunner,
    SubagentRuntime,
    TraceAssembler,
    build_error_envelope,
    build_frozen_pipeline_entrypoint_request,
    hash_bytes,
    run_perturbation_pair,
    tag_uncertainty,
    uncertainty_tag_for_artifact,
)
from argus_core.s1 import S1_LIFECYCLE_LEDGER_KIND


class ExampleSubagent(Subagent):
    def __init__(self, descriptor: SubagentDescriptor) -> None:
        super().__init__(descriptor)
        self.plan_ctx_job_id: str | None = None
        self.build_ctx_job_id: str | None = None
        self.seen_plan_hash: str | None = None
        self.plan_ctx_payload: dict[str, object] | None = None
        self.build_ctx_payload: dict[str, object] | None = None
        self.build_log_handle: dict[str, object] | None = None
        self.build_span_handle: dict[str, object] | None = None
        self.plan_ctx_forbidden_handles: dict[str, bool] | None = None

    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
        self.plan_ctx_job_id = ctx.job_id
        self.plan_ctx_payload = ctx.as_c1_payload()
        self.plan_ctx_forbidden_handles = {
            name: hasattr(ctx, name)
            for name in (
                "set_claim_tier",
                "verifier",
                "report_verifier",
                "credentials",
                "raw_credentials",
                "allowed_adapters",
                "allowed_datasets",
                "adapter_broker",
                "adapter_client",
                "artifact_store",
                "broker_secret",
                "scope_token",
                "token_service",
            )
        }
        return {
            "steps": [
                {
                    "step_id": "inspect",
                    "kind": "feature",
                    "description": "Inspect the toy spectrum",
                    "est_cost": {"cost_usd": 0.25},
                }
            ],
            "datasets_required": ["c4://dataset/ewpt-toy"],
            "risk_notes": ["toy baseline only"],
        }

    def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
        self.build_ctx_job_id = ctx.job_id
        self.build_ctx_payload = ctx.as_c1_payload()
        self.build_log_handle = ctx.log("building toy model", fields={"phase": "build"})
        self.build_span_handle = ctx.span("build", attributes={"job_id": ctx.job_id})
        self.seen_plan_hash = str(plan["plan_hash"])
        return {
            "artifact_refs": ["c4://artifact/ewpt-toy/model"],
            "diagnostics": {"plan_hash": self.seen_plan_hash},
            "self_checks": [{"type": "smoke", "status": "PASS", "advisory": True}],
        }


class S1SDKBaseClassTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "contracts" / "c1.subagent.schema.json"
        cls.c1_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        cls.c1_validator = Draft202012Validator(cls.c1_schema)

    def setUp(self) -> None:
        self._adapter_broker_proxies: list[S1AdapterBrokerProxy] = []
        self.descriptor = SubagentDescriptor(
            subagent_id="sdk-subagent",
            contract_version="1.0.0",
            subtopics=("ewpt",),
            required_adapters=("adapter:bounce",),
        )
        self.envelope = JobEnvelope(
            job_id="55555555-5555-4555-8555-555555555555",
            envelope_version="1.0.0",
            subtopic="ewpt",
            required_adapters=("adapter:bounce",),
            allowed_adapters=("adapter:bounce",),
            verifier_profile_ref="c4://profile/ewpt/v1",
            estimated_cost=0.5,
            budget_cost=1.0,
        )

    def test_runner_wraps_author_plan_build_in_real_lifecycle(self) -> None:
        subagent = ExampleSubagent(self.descriptor)
        runner = SubagentSDKRunner(subagent)

        acceptance = runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        built = runner.build(self.envelope.job_id, planned.payload)

        self.assertTrue(acceptance.accepted)
        self.assertEqual(subagent.plan_ctx_job_id, self.envelope.job_id)
        self.assertEqual(subagent.build_ctx_job_id, self.envelope.job_id)
        self.assertEqual(subagent.plan_ctx_payload, subagent.build_ctx_payload)
        self._assert_c1_def_valid("ExecContext", subagent.plan_ctx_payload or {})
        self.assertEqual(
            subagent.plan_ctx_forbidden_handles,
            {
                "set_claim_tier": False,
                "verifier": False,
                "report_verifier": False,
                "credentials": False,
                "raw_credentials": False,
                "allowed_adapters": False,
                "allowed_datasets": False,
                "adapter_broker": False,
                "adapter_client": False,
                "artifact_store": False,
                "broker_secret": False,
                "scope_token": False,
                "token_service": False,
            },
        )
        self.assertEqual(subagent.build_log_handle["capability"], "log")
        self.assertEqual(subagent.build_span_handle["capability"], "span")
        self.assertEqual(subagent.seen_plan_hash, planned.payload["plan_hash"])
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.BUILDING)
        self.assertEqual([event.method for event in runner.runtime.store.events(self.envelope.job_id)], ["accept", "plan", "build"])
        self.assertEqual(planned.event.to_state, LifecycleState.PLANNING)
        self.assertEqual(planned.event.trigger, "internal")
        self.assertEqual(built.event.to_state, LifecycleState.BUILDING)
        self.assertEqual(built.event.trigger, "internal")
        self.assertIsNotNone(runner.runtime.store.events(self.envelope.job_id)[0].ledger_ref)
        self.assertIsNotNone(planned.event.ledger_ref)
        self.assertIsNotNone(built.event.ledger_ref)
        ledger_records = runner.runtime.store.ledger_records(self.envelope.job_id)
        self.assertEqual(len(ledger_records), 3)
        self.assertEqual([record.kind for record in ledger_records], [S1_LIFECYCLE_LEDGER_KIND] * 3)
        self.assertEqual(ledger_records[1].lineage.input_refs, (ledger_records[0].artifact_ref,))
        self.assertEqual(ledger_records[2].lineage.input_refs, (ledger_records[1].artifact_ref,))
        self.assertEqual(planned.payload["job_id"], self.envelope.job_id)
        self.assertEqual(planned.payload["adapters_required"], ["adapter:bounce"])
        self.assertEqual(planned.payload["verifier_profile_ref"], "c4://profile/ewpt/v1")
        self.assertTrue(str(planned.payload["plan_hash"]).startswith("blake3:"))
        self.assertEqual(built.payload["job_id"], self.envelope.job_id)
        self.assertEqual(built.payload["uncertainty_summary"], {"representation": "none", "value": {}})
        self._assert_c1_valid(planned.payload)
        self._assert_c1_valid(built.payload)

    def test_runner_records_method_and_author_spans_for_s11_trace_assembly(self) -> None:
        telemetry = InMemoryS1TelemetrySink()
        subagent = ExampleSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(descriptor=self.descriptor, telemetry_sink=telemetry),
        )

        runner.accept(self.envelope, root_request_id="root-s1-t24", trace_id="trace-s1-t24")
        planned = runner.plan(self.envelope, root_request_id="root-s1-t24", trace_id="trace-s1-t24")
        runner.build(
            self.envelope.job_id,
            planned.payload,
            root_request_id="root-s1-t24",
            trace_id="trace-s1-t24",
        )

        spans = telemetry.spans(trace_id="trace-s1-t24")
        span_names = [span.name for span in spans]
        self.assertEqual(span_names, ["S1.accept", "S1.plan", "S1.exec.build", "S1.build"])
        self.assertEqual(subagent.build_span_handle["span_name"], "S1.exec.build")
        self.assertEqual(subagent.build_span_handle["trace_id"], "trace-s1-t24")
        self.assertEqual(spans[2].attributes["author_span_name"], "build")
        self.assertEqual(spans[2].attributes["job_id"], self.envelope.job_id)
        summary = TraceAssembler(required_spans=("S1.accept", "S1.plan", "S1.exec.build", "S1.build")).assemble(
            trace_id="trace-s1-t24",
            spans=spans,
        )
        self.assertEqual(summary.status, "complete")

    def test_runner_auto_repairs_retryable_build_once_with_attempt_provenance(self) -> None:
        class RepairableBuildSubagent(ExampleSubagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.build_plans: list[dict[str, object]] = []

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                self.build_plans.append(dict(plan))
                if not plan.get("repair_applied"):
                    raise LifecyclePolicyError(
                        build_error_envelope(
                            category="RETRYABLE",
                            code="TRAINING_NAN",
                            message="loss became NaN during the first build attempt",
                            retry_after_seconds=0,
                        )
                    )
                payload = super().build(ctx, plan)
                payload["diagnostics"]["repair_applied"] = plan["repair_applied"]
                return payload

        repair_calls: list[dict[str, object]] = []

        def repair_hook(ctx: ExecContext, attempt: dict[str, object]) -> dict[str, object]:
            repair_calls.append(attempt)
            return {
                "plan_patch": {"repair_applied": True},
                "diagnostics": {"action": "lower_learning_rate", "sandbox_job": ctx.job_id},
            }

        subagent = RepairableBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(
                descriptor=self.descriptor,
                max_build_repair_attempts=2,
                build_repair_hook=repair_hook,
            ),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        built = runner.build(self.envelope.job_id, planned.payload)

        self.assertEqual(len(subagent.build_plans), 2)
        self.assertFalse(subagent.build_plans[0].get("repair_applied", False))
        self.assertTrue(subagent.build_plans[1]["repair_applied"])
        self.assertEqual(len(repair_calls), 1)
        self.assertEqual(repair_calls[0]["attempt"], 1)
        self.assertEqual(repair_calls[0]["max_attempts"], 2)
        self.assertEqual(repair_calls[0]["error"]["category"], "RETRYABLE")
        self.assertEqual(repair_calls[0]["error"]["code"], "TRAINING_NAN")
        self.assertEqual(built.payload["diagnostics"]["repair_applied"], True)
        repair = built.payload["diagnostics"]["repair"]
        self.assertEqual(repair["repair_attempts"], 1)
        self.assertEqual(len(repair["attempts"]), 1)
        self.assertEqual(repair["attempts"][0]["attempt"], 1)
        self.assertEqual(repair["attempts"][0]["error"]["code"], "TRAINING_NAN")
        self.assertTrue(str(repair["attempts"][0]["provenance_ref"]).startswith("c4://"))
        attempt_record = runner.runtime.artifact_store.get_record(str(repair["attempts"][0]["provenance_ref"]))
        self.assertEqual(attempt_record.kind, "s1_build_repair_attempt")
        self.assertEqual(attempt_record.lineage.job_id, self.envelope.job_id)
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.BUILDING)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "build"],
        )
        self._assert_c1_valid(built.payload)

    def test_runner_auto_repair_cap_exhaustion_fails_with_typed_error_and_attempts(self) -> None:
        class AlwaysFailingBuildSubagent(ExampleSubagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.build_calls = 0

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                self.build_calls += 1
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="RETRYABLE",
                        code="TRAINING_NAN",
                        message=f"attempt {self.build_calls} still produced NaN loss",
                        retry_after_seconds=0,
                    )
                )

        repair_calls: list[dict[str, object]] = []

        def repair_hook(ctx: ExecContext, attempt: dict[str, object]) -> dict[str, object]:
            repair_calls.append(attempt)
            return {
                "plan_patch": {"repair_iteration": attempt["attempt"]},
                "diagnostics": {"action": "retry_with_grad_clip", "sandbox_job": ctx.job_id},
            }

        subagent = AlwaysFailingBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(
                descriptor=self.descriptor,
                max_build_repair_attempts=2,
                build_repair_hook=repair_hook,
            ),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.build(self.envelope.job_id, planned.payload)

        self.assertEqual(raised.exception.envelope.category, "PERMANENT")
        self.assertEqual(raised.exception.envelope.code, "S1_BUILD_AUTO_REPAIR_EXHAUSTED")
        self.assertIn("2 repair attempts", raised.exception.envelope.message)
        self.assertEqual(subagent.build_calls, 3)
        self.assertEqual(len(repair_calls), 2)
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.FAILED)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "fail"],
        )
        attempt_records = runner.runtime.artifact_store.query_artifacts(
            {"kind": "s1_build_repair_attempt", "job_id": self.envelope.job_id}
        )
        self.assertEqual(len(attempt_records), 2)
        self.assertTrue(all(record.lineage.job_id == self.envelope.job_id for record in attempt_records))

    def test_runner_auto_repair_does_not_retry_policy_or_sandbox_errors(self) -> None:
        class PolicyFailingBuildSubagent(ExampleSubagent):
            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="POLICY",
                        code="MODEL_SELF_PROMOTION",
                        message="author attempted to bypass tier policy",
                    )
                )

        repair_calls: list[dict[str, object]] = []

        def repair_hook(ctx: ExecContext, attempt: dict[str, object]) -> dict[str, object]:
            repair_calls.append(attempt)
            return {"plan_patch": {"should_not_apply": True}}

        runner = SubagentSDKRunner(
            PolicyFailingBuildSubagent(self.descriptor),
            runtime=SubagentRuntime(
                descriptor=self.descriptor,
                max_build_repair_attempts=2,
                build_repair_hook=repair_hook,
            ),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.build(self.envelope.job_id, planned.payload)

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(raised.exception.envelope.code, "MODEL_SELF_PROMOTION")
        self.assertEqual(repair_calls, [])
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.QUARANTINED)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "quarantine"],
        )

    def test_runner_rejects_author_build_tier_self_promotion_fields(self) -> None:
        class SelfPromotingBuildSubagent(ExampleSubagent):
            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                payload = super().build(ctx, plan)
                payload["claim_tier"] = "novel-needs-human"
                payload["validation_report_ref"] = "c4://artifact/author-claimed-report"
                payload["self_checks"] = [
                    {"type": "PHYSICAL_CONSISTENCY", "status": "PASS", "advisory": True}
                ]
                return payload

        runner = SubagentSDKRunner(SelfPromotingBuildSubagent(self.descriptor))

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.build(self.envelope.job_id, planned.payload)

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(raised.exception.envelope.code, "S1_BUILD_TIER_SELF_PROMOTION_FORBIDDEN")
        self.assertIn("claim_tier", raised.exception.envelope.message)
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.QUARANTINED)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "quarantine"],
        )

    def test_exec_context_is_canonical_restricted_capability_handle(self) -> None:
        expected_capabilities = [
            "submit_sandbox_job",
            "emit_artifact",
            "call_adapter",
            "read_dataset",
            "log",
            "span",
        ]
        ctx = ExecContext(job_id=self.envelope.job_id)

        self.assertEqual(ctx.capabilities, tuple(expected_capabilities))
        self.assertEqual(ctx.capability_methods(), tuple(expected_capabilities))
        self.assertEqual(ctx.as_c1_payload(), {"job_id": self.envelope.job_id, "capabilities": expected_capabilities})
        self._assert_c1_def_valid("ExecContext", ctx.as_c1_payload())
        for capability in expected_capabilities:
            self.assertTrue(callable(getattr(ctx, capability)))
        for forbidden in (
            "set_claim_tier",
            "verifier",
            "report_verifier",
            "credentials",
            "raw_credentials",
            "allowed_adapters",
            "allowed_datasets",
            "artifact_store",
        ):
            self.assertFalse(hasattr(ctx, forbidden), forbidden)

    def test_exec_context_tags_canonical_uncertainty_without_expanding_capabilities(self) -> None:
        ctx = ExecContext(job_id=self.envelope.job_id)

        summary = ctx.tag_uncertainty(
            "interval",
            {"radius": 0.1, "confidence": 0.95, "source": "adapter:bounce"},
        )
        c4_tag = uncertainty_tag_for_artifact(summary)

        self.assertEqual(
            ctx.capability_methods(),
            ("submit_sandbox_job", "emit_artifact", "call_adapter", "read_dataset", "log", "span"),
        )
        self.assertEqual(
            summary,
            {
                "representation": "interval",
                "value": {"radius": 0.1, "confidence": 0.95, "source": "adapter:bounce"},
            },
        )
        self.assertEqual(
            c4_tag,
            {"kind": "interval", "radius": 0.1, "confidence": 0.95, "source": "adapter:bounce"},
        )
        self._assert_c1_def_valid("UncertaintySummary", summary)

    def test_runner_preserves_author_uncertainty_summary(self) -> None:
        class UncertaintySubagent(ExampleSubagent):
            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                payload = super().build(ctx, plan)
                payload["uncertainty_summary"] = ctx.tag_uncertainty(
                    "interval",
                    {"radius": 0.05, "confidence": 0.9, "source": "self-check"},
                )
                return payload

        subagent = UncertaintySubagent(self.descriptor)
        runner = SubagentSDKRunner(subagent)

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        built = runner.build(self.envelope.job_id, planned.payload)

        self.assertEqual(
            built.payload["uncertainty_summary"],
            {
                "representation": "interval",
                "value": {"radius": 0.05, "confidence": 0.9, "source": "self-check"},
            },
        )
        self._assert_c1_valid(built.payload)

    def test_exec_context_denies_missing_and_unknown_capabilities(self) -> None:
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            capabilities=("read_dataset",),
            allowed_datasets=("c4://dataset/ewpt-toy",),
        )

        self.assertEqual(ctx.as_c1_payload(), {"job_id": self.envelope.job_id, "capabilities": ["read_dataset"]})
        self.assertEqual(ctx.read_dataset("c4://dataset/ewpt-toy")["capability"], "read_dataset")
        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.call_adapter("adapter:bounce", {"input": 1})

        self.assertEqual(raised.exception.envelope.code, "EXEC_CONTEXT_CAPABILITY_DENIED")
        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertIn("call_adapter", raised.exception.envelope.message)
        with self.assertRaisesRegex(ValueError, "unknown ExecContext capability"):
            ExecContext(job_id=self.envelope.job_id, capabilities=("set_claim_tier",))

    def test_exec_context_empty_allowlists_default_deny_adapter_and_dataset_handles(self) -> None:
        ctx = ExecContext(job_id=self.envelope.job_id)

        with self.assertRaises(LifecyclePolicyError) as adapter_denied:
            ctx.call_adapter("adapter:undeclared", {"input": 1})
        with self.assertRaises(LifecyclePolicyError) as dataset_denied:
            ctx.read_dataset("c4://dataset/undeclared")

        self.assertEqual(adapter_denied.exception.envelope.code, "EXEC_CONTEXT_CAPABILITY_DENIED")
        self.assertEqual(dataset_denied.exception.envelope.code, "EXEC_CONTEXT_CAPABILITY_DENIED")
        self.assertIn("adapter is not allowlisted", adapter_denied.exception.envelope.message)
        self.assertIn("dataset is not allowlisted", dataset_denied.exception.envelope.message)

    def test_exec_context_call_adapter_requires_brokered_proxy_for_allowlisted_adapter(self) -> None:
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.call_adapter("adapter:bounce", self._adapter_call_payload(x=2.0))

        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertEqual(raised.exception.envelope.code, "S1_ADAPTER_BROKER_UNAVAILABLE")
        self.assertIn("brokered adapter proxy is unavailable", raised.exception.envelope.message)

    def test_exec_context_call_adapter_uses_brokered_c6_client_without_exposing_secrets(self) -> None:
        client, audit, artifacts = self._brokered_adapter_client(
            allowed_adapters=("adapter:bounce",),
            broker_audiences=("adapter:bounce",),
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            adapter_client=client,
        )

        result = ctx.call_adapter("adapter:bounce", self._adapter_call_payload(x=2.0, seed=7))

        self.assertEqual(result["capability"], "call_adapter")
        self.assertEqual(result["adapter_ref"], "adapter:bounce")
        self.assertTrue(str(result["request_hash"]).startswith("blake3:"))
        self.assertTrue(str(result["provenance_ref"]).startswith("c4://"))
        self.assertEqual(result["result"]["adapter_id"], "adapter:bounce")
        self.assertEqual(result["result"]["outputs"]["y"]["value"], 4.0)
        self.assertEqual(result["result"]["outputs"]["y"]["units"], "dimensionless")
        self.assertEqual(result["result"]["outputs"]["y"]["uncertainty"], {"kind": "interval", "radius": 0.1})
        self.assertEqual(artifacts.get_record(str(result["provenance_ref"])).kind, "log")
        self.assertEqual(audit.events()[-1].event_type, "adapter.evaluate")
        self.assertEqual(audit.events()[-1].payload["adapter_id"], "adapter:bounce")
        for forbidden in (
            "adapter_broker",
            "scope_token",
            "token_service",
            "raw_credentials",
            "credentials",
            "broker_secret",
        ):
            self.assertFalse(hasattr(ctx, forbidden), forbidden)
            self.assertFalse(hasattr(client, forbidden), forbidden)
        self.assertFalse(hasattr(client, "__dict__"))
        self.assertFalse(hasattr(client, "_scope_token"))
        self.assertFalse(hasattr(client, "_broker"))

    def test_brokered_adapter_client_object_graph_cannot_reach_proxy_or_signing_key(self) -> None:
        signing_key = b"TOP-SECRET-SIGNING-KEY-CAFEBABE"
        artifacts = InMemoryArtifactStore()
        audit = InMemoryAuditLedger()
        tokens = InMemoryTokenService(signing_key=signing_key, now_fn=lambda: 1_000)
        adapter_broker = AdapterBroker(artifact_store=artifacts)
        adapter_broker.register(self._bounce_adapter())
        scope = tokens.mint_scope(
            job_id=self.envelope.job_id,
            scopes=ScopeGrant(
                allowed_adapters=("adapter:bounce",),
                broker_audiences=("adapter:bounce",),
            ),
        )
        proxy = S1AdapterBrokerProxy(
            token_service=tokens,
            adapter_broker=adapter_broker,
            audit_ledger=audit,
        )
        self._adapter_broker_proxies.append(proxy)
        client = proxy.client_for(scope)

        reachable = self._walk_client_object_graph(client, max_depth=6)

        self.assertNotIn(id(proxy), {id(item) for item in reachable})
        self.assertFalse(any(item is tokens for item in reachable))
        self.assertFalse(any(getattr(item, "_signing_key", None) == signing_key for item in reachable))
        self.assertFalse(any(callable(getattr(item, "mint_scope", None)) for item in reachable))

    def test_exec_context_call_adapter_rejects_scope_without_adapter_broker_audience(self) -> None:
        client, audit, artifacts = self._brokered_adapter_client(
            allowed_adapters=("adapter:bounce",),
            broker_audiences=(),
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            adapter_client=client,
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.call_adapter("adapter:bounce", self._adapter_call_payload(x=2.0))

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(raised.exception.envelope.code, "S1_ADAPTER_SCOPE_DENIED")
        self.assertIn("adapter broker audience is not granted", raised.exception.envelope.message)
        self.assertEqual(len(artifacts), 0)
        self.assertEqual(audit.events()[-1].event_type, "adapter.denied")

    def test_exec_context_call_adapter_rejects_unregistered_broker_adapter_fail_closed(self) -> None:
        client, audit, artifacts = self._brokered_adapter_client(
            allowed_adapters=("adapter:bounce",),
            broker_audiences=("adapter:bounce",),
            register_adapter=False,
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            adapter_client=client,
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.call_adapter("adapter:bounce", self._adapter_call_payload(x=2.0))

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(raised.exception.envelope.code, "S1_ADAPTER_SCOPE_DENIED")
        self.assertIn("adapter is not registered with broker", raised.exception.envelope.message)
        self.assertEqual(len(artifacts), 0)
        self.assertEqual(audit.events()[-1].event_type, "adapter.denied")
        self.assertEqual(audit.events()[-1].payload["reason"], "adapter_not_registered")

    def test_exec_context_call_adapter_rejects_mismatched_request_adapter_id(self) -> None:
        client, _audit, artifacts = self._brokered_adapter_client(
            allowed_adapters=("adapter:bounce",),
            broker_audiences=("adapter:bounce",),
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            adapter_client=client,
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.call_adapter(
                "adapter:bounce",
                {"adapter_id": "adapter:other", **self._adapter_call_payload(x=2.0)},
            )

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(raised.exception.envelope.code, "S1_ADAPTER_REQUEST_MISMATCH")
        self.assertEqual(len(artifacts), 0)

    def test_exec_context_brokers_documented_capabilities_with_allowlists(self) -> None:
        client, _audit, _artifacts = self._brokered_adapter_client(
            allowed_adapters=("adapter:bounce",),
            broker_audiences=("adapter:bounce",),
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            allowed_datasets=("c4://dataset/ewpt-toy",),
            adapter_client=client,
        )

        artifact = ctx.emit_artifact(
            {"metric": 0.98},
            kind="diagnostic",
            lineage_inputs=("c4://artifact/source",),
        )
        self.assertEqual(artifact["capability"], "emit_artifact")
        self.assertEqual(artifact["kind"], "diagnostic")
        self.assertTrue(str(artifact["artifact_ref"]).startswith("c4://"))
        self.assertTrue(str(artifact["content_hash"]).startswith("blake3:"))
        adapter_result = ctx.call_adapter("adapter:bounce", self._adapter_call_payload(x=1.0))
        self.assertEqual(adapter_result["capability"], "call_adapter")
        self.assertEqual(adapter_result["result"]["outputs"]["y"]["value"], 2.0)
        self.assertEqual(ctx.read_dataset("c4://dataset/ewpt-toy")["dataset_ref"], "c4://dataset/ewpt-toy")
        with self.assertRaises(LifecyclePolicyError) as adapter_denied:
            ctx.call_adapter("adapter:unlisted", {"input": 1})
        with self.assertRaises(LifecyclePolicyError) as dataset_denied:
            ctx.read_dataset("c4://dataset/other")

        self.assertEqual(adapter_denied.exception.envelope.code, "EXEC_CONTEXT_CAPABILITY_DENIED")
        self.assertEqual(dataset_denied.exception.envelope.code, "EXEC_CONTEXT_CAPABILITY_DENIED")

    def test_exec_context_emit_artifact_fails_closed_on_incomplete_lineage_without_commit(self) -> None:
        artifacts = InMemoryArtifactStore()
        ctx = ExecContext(job_id=self.envelope.job_id, artifact_store=artifacts)

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.emit_artifact(
                {"weights": [1]},
                kind="model",
                lineage=Lineage(
                    input_refs=("c4://artifact/source",),
                    code_ref="git:project-argus@deadbeef",
                    environment_digest="",
                    seeds=("seed-1",),
                ),
            )

        self.assertEqual(raised.exception.envelope.code, "INCOMPLETE_LINEAGE")
        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertIn("lineage.environment_digest", raised.exception.envelope.message)
        self.assertEqual(len(artifacts), 0)

    def test_exec_context_emit_artifact_writes_complete_c4_lineage_to_store(self) -> None:
        artifacts = InMemoryArtifactStore()
        source = artifacts.create_artifact(
            kind="dataset",
            payload={"rows": [{"x": 1}]},
            producer=Producer(subsystem="S6", version="test"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:project-argus@source",
                environment_digest="oci:dataset@sha256-source",
                seeds=("seed-source",),
            ),
        )
        ctx = ExecContext(job_id=self.envelope.job_id, artifact_store=artifacts)

        result = ctx.emit_artifact(
            {"weights": [1], "bias": 0.5},
            kind="model",
            lineage=Lineage(
                input_refs=(source.artifact_ref,),
                code_ref="git:project-argus@model",
                environment_digest="oci:model@sha256-model",
                seeds=("seed-model",),
            ),
        )
        record = artifacts.get_record(str(result["artifact_ref"]))
        payload_bytes = artifacts.get_artifact(record.artifact_ref)
        lineage_graph = artifacts.get_lineage(record.artifact_ref, direction="ancestors")

        self.assertEqual(result["capability"], "emit_artifact")
        self.assertEqual(record.kind, "model")
        self.assertEqual(record.content_hash, result["content_hash"])
        self.assertEqual(hash_bytes(payload_bytes), record.content_hash)
        self.assertEqual(record.producer.subsystem, "s1")
        self.assertEqual(record.producer.job_id, self.envelope.job_id)
        self.assertEqual(record.lineage.input_refs, (source.artifact_ref,))
        self.assertEqual(record.lineage.job_id, self.envelope.job_id)
        self.assertEqual(
            {node.artifact_ref for node in lineage_graph.nodes},
            {source.artifact_ref, record.artifact_ref},
        )
        self.assertEqual(
            [(edge.source_ref, edge.target_ref) for edge in lineage_graph.edges],
            [(source.artifact_ref, record.artifact_ref)],
        )

    def test_exec_context_retains_empty_injected_artifact_store(self) -> None:
        artifacts = InMemoryArtifactStore()
        self.assertFalse(bool(artifacts))
        ctx = ExecContext(job_id=self.envelope.job_id, artifact_store=artifacts)

        result = ctx.emit_artifact(
            {"weights": [1]},
            kind="model",
            lineage=Lineage(
                input_refs=(),
                code_ref="git:project-argus@empty-store",
                environment_digest="oci:model@sha256-empty-store",
                seeds=("seed-empty-store",),
            ),
        )

        self.assertIs(ctx._artifact_store, artifacts)
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts.get_record(str(result["artifact_ref"])).kind, "model")

    def test_exec_context_emit_artifact_rejects_promoted_tier_before_c4_commit(self) -> None:
        artifacts = InMemoryArtifactStore()
        ctx = ExecContext(job_id=self.envelope.job_id, artifact_store=artifacts)

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.emit_artifact(
                {"weights": [1]},
                kind="model",
                lineage=Lineage(
                    input_refs=("c4://artifact/source",),
                    code_ref="git:project-argus@tier",
                    environment_digest="oci:model@sha256-tier",
                    seeds=("seed-tier",),
                ),
                claim_tier="recapitulated-known",
            )

        self.assertEqual(raised.exception.envelope.code, "S1_ARTIFACT_TIER_SELF_PROMOTION_FORBIDDEN")
        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertIn("claim_tier", raised.exception.envelope.message)
        self.assertEqual(len(artifacts), 0)

    def test_runner_author_build_emits_artifact_through_runtime_c4_store(self) -> None:
        artifacts = InMemoryArtifactStore()
        source = artifacts.create_artifact(
            kind="dataset",
            payload={"rows": [{"x": 2}]},
            producer=Producer(subsystem="S6", version="test"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:project-argus@source",
                environment_digest="oci:dataset@sha256-source",
                seeds=("seed-source",),
            ),
        )

        class ArtifactBuildSubagent(Subagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.emitted_ref: str | None = None

            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {"datasets_required": [source.artifact_ref], "steps": []}

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                result = ctx.emit_artifact(
                    {"weights": [2], "bias": 0.25},
                    kind="model",
                    lineage=Lineage(
                        input_refs=(source.artifact_ref,),
                        code_ref="git:project-argus@author-build",
                        environment_digest="oci:model@sha256-author-build",
                        seeds=("seed-author-build",),
                    ),
                )
                self.emitted_ref = str(result["artifact_ref"])
                return {
                    "artifact_refs": [self.emitted_ref],
                    "diagnostics": {"content_hash": result["content_hash"]},
                }

        subagent = ArtifactBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(descriptor=self.descriptor, artifact_store=artifacts),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        built = runner.build(self.envelope.job_id, planned.payload)
        record = artifacts.get_record(subagent.emitted_ref or "")
        lineage_graph = artifacts.get_lineage(record.artifact_ref, direction="ancestors")

        self.assertEqual(built.payload["artifact_refs"], [record.artifact_ref])
        self.assertEqual(record.kind, "model")
        self.assertEqual(record.producer.subsystem, "s1")
        self.assertEqual(record.lineage.input_refs, (source.artifact_ref,))
        self.assertEqual(
            {node.artifact_ref for node in lineage_graph.nodes},
            {source.artifact_ref, record.artifact_ref},
        )

    def test_subagent_runtime_retains_empty_injected_artifact_store(self) -> None:
        artifacts = InMemoryArtifactStore()
        self.assertFalse(bool(artifacts))
        runtime = SubagentRuntime(descriptor=self.descriptor, artifact_store=artifacts)

        acceptance = runtime.accept(self.envelope)
        event = runtime.store.events(self.envelope.job_id)[0]

        self.assertTrue(acceptance.accepted)
        self.assertIs(runtime.artifact_store, artifacts)
        self.assertIs(runtime.store.artifact_store, artifacts)
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts.get_record(str(event.ledger_ref)).kind, S1_LIFECYCLE_LEDGER_KIND)

    def test_runner_validate_packages_frozen_pipeline_for_s3_without_blind_labels(self) -> None:
        trust_store = InMemoryVerifierTrustStore()
        trust_store.register_key("s3-key", b"s3-secret")
        c3_verifier = C3ReportVerifier(trust_store)
        artifacts = InMemoryArtifactStore(report_verifier=c3_verifier)

        class ValidatingBuildSubagent(Subagent):
            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {
                    "steps": [{"step_id": "fit", "kind": "train", "description": "Fit toy model"}],
                    "adapters_required": list(envelope.required_adapters),
                    "datasets_required": ["c4://dataset/ewpt-toy"],
                    "verifier_profile_ref": envelope.verifier_profile_ref,
                    "budget_breakdown": {"total": {"cost_usd": envelope.estimated_cost}},
                    "risk_notes": [],
                }

            def build(self, ctx: ExecContext, _plan: dict[str, object]) -> dict[str, object]:
                artifact = ctx.emit_artifact(
                    {"weights": [1.0], "headline": 1.0},
                    kind="model",
                    lineage=Lineage(
                        input_refs=(),
                        code_ref="git:project-argus@s1-t17",
                        environment_digest="oci:s1-build@sha256-s1-t17",
                        seeds=("seed-s1-t17",),
                    ),
                )
                return {
                    "artifact_refs": [str(artifact["artifact_ref"])],
                    "diagnostics": {"blind_labels": ["secret-label-must-not-leak"]},
                    "self_checks": [{"type": "smoke", "status": "PASS", "advisory": True}],
                    "uncertainty_summary": tag_uncertainty(
                        "interval",
                        {"radius": 0.01, "source": "build-output"},
                    ),
                }

        class RecordingS3ValidationClient:
            def __init__(self) -> None:
                signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
                self.s3 = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-key", signer=signer)
                self.request: dict[str, object] | None = None

            def validate(self, request: dict[str, object]) -> dict[str, object]:
                self.request = request
                self_test.assertNotIn("blind_labels", request)
                outcome = run_perturbation_pair(
                    perturbation_id="pair-s1-t17",
                    must_react_expected=1.0,
                    must_react_observed=1.0,
                    must_not_react_observed=0.0,
                    unperturbed_headline=1.0,
                    perturbed_headline=0.2,
                )
                return self.s3.build_report(
                    profile_ref=str(request["profile_ref"]),
                    frozen_pipeline_ref=str(request["frozen_pipeline_ref"]),
                    proponent_id="sdk-subagent",
                    checks=(
                        CheckResult("INJECTION", "PASS"),
                        CheckResult("NULL_CONTROL", "PASS"),
                        CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                        CheckResult("CALIBRATION", "PASS"),
                        CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
                    ),
                    perturbation_outcome=outcome,
                    challenger_ids=("challenger-a", "challenger-b"),
                    debate_ref="c4://debate/s1-t17",
                )

        self_test = self
        subagent = ValidatingBuildSubagent(self.descriptor)
        runtime = SubagentRuntime(descriptor=self.descriptor, artifact_store=artifacts)
        runner = SubagentSDKRunner(subagent, runtime=runtime)
        s3_client = RecordingS3ValidationClient()

        runner.accept(self.envelope)
        plan = runner.plan(self.envelope)
        build = runner.build(self.envelope.job_id, plan.payload)
        validated = runner.validate(
            self.envelope.job_id,
            build.payload,
            profile_ref=str(self.envelope.verifier_profile_ref),
            blind_dataset_handle="blind://s3/labels/job-555",
            budget_token_ref="budget://token/job-555",
            validation_client=s3_client,
            report_verifier=c3_verifier,
            trace_id="trace-s1-t17",
        )

        assert s3_client.request is not None
        request = s3_client.request
        self._assert_c1_def_valid("ValidationRequest", request)
        self.assertEqual(request["blind_dataset_handle"], "blind://s3/labels/job-555")
        self.assertEqual(request["budget_token_ref"], "budget://token/job-555")
        self.assertEqual(validated.event.to_state, LifecycleState.VALIDATING)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "build", "validate"],
        )

        frozen_payload = json.loads(
            artifacts.get_artifact(str(validated.payload["frozen_pipeline_ref"])).decode("utf-8")
        )
        validation_request_payload = json.loads(
            artifacts.get_artifact(str(validated.payload["validation_request_ref"])).decode("utf-8")
        )
        report_payload = json.loads(
            artifacts.get_artifact(str(validated.payload["validation_report_ref"])).decode("utf-8")
        )
        serialized_handoff = json.dumps(
            {
                "frozen": frozen_payload,
                "request": validation_request_payload,
                "runner_payload": validated.payload,
            },
            sort_keys=True,
        )

        self.assertEqual(frozen_payload["artifact_refs"], build.payload["artifact_refs"])
        self.assertEqual(validation_request_payload, request)
        s3_entrypoint_request = build_frozen_pipeline_entrypoint_request(
            validation_request_payload,
            artifact_store=artifacts,
        )
        self.assertEqual(s3_entrypoint_request["entrypoint"]["method"], "predict")
        self.assertEqual(
            s3_entrypoint_request["verification_request"]["blind_data_handle"],
            "blind://s3/labels/job-555",
        )
        self.assertNotIn("blind_dataset_handle", s3_entrypoint_request["verification_request"])
        self.assertNotIn("secret-label-must-not-leak", serialized_handoff)
        self.assertNotIn("secret-label-must-not-leak", json.dumps(s3_entrypoint_request, sort_keys=True))
        self.assertEqual(report_payload["frozen_pipeline_ref"], request["frozen_pipeline_ref"])
        self.assertTrue(c3_verifier.verify(report_payload).valid)
        self._assert_c1_def_valid("SubagentReport", validated.payload["subagent_report"])
        self.assertEqual(validated.payload["subagent_report"]["claim_tier"], "recapitulated-known")
        self.assertEqual(validated.payload["subagent_report"]["validation_report_ref"], validated.payload["validation_report_ref"])

    def test_runner_validate_fails_closed_without_s3_validation_client(self) -> None:
        class ArtifactBuildSubagent(ExampleSubagent):
            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                payload = super().build(ctx, plan)
                payload["artifact_refs"] = [
                    str(
                        ctx.emit_artifact(
                            {"weights": [1]},
                            kind="model",
                            lineage=Lineage(
                                input_refs=(),
                                code_ref="git:project-argus@s1-t17-missing-client",
                                environment_digest="oci:s1-build@sha256-missing-client",
                                seeds=("seed-missing-client",),
                            ),
                        )["artifact_ref"]
                    )
                ]
                payload["uncertainty_summary"] = tag_uncertainty("interval", {"radius": 0.01})
                return payload

        runner = SubagentSDKRunner(ArtifactBuildSubagent(self.descriptor))

        runner.accept(self.envelope)
        plan = runner.plan(self.envelope)
        build = runner.build(self.envelope.job_id, plan.payload)

        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.validate(
                self.envelope.job_id,
                build.payload,
                profile_ref=str(self.envelope.verifier_profile_ref),
                blind_dataset_handle="blind://s3/labels/job-555",
                budget_token_ref="budget://token/job-555",
            )

        self.assertEqual(raised.exception.envelope.code, "S1_VALIDATION_CLIENT_REQUIRED")
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.BUILDING)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "build"],
        )

    def test_runner_plan_context_default_denies_empty_adapter_allowlist(self) -> None:
        class UndeclaredAdapterPlanSubagent(Subagent):
            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                ctx.call_adapter("adapter:undeclared", {"input": 1})
                return {}

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                return {}

        descriptor = SubagentDescriptor(
            subagent_id="sdk-empty-adapter-subagent",
            contract_version="1.0.0",
            subtopics=("ewpt",),
        )
        envelope = JobEnvelope(
            job_id="66666666-6666-4666-8666-666666666666",
            envelope_version="1.0.0",
            subtopic="ewpt",
            verifier_profile_ref="c4://profile/ewpt/v1",
        )
        runner = SubagentSDKRunner(UndeclaredAdapterPlanSubagent(descriptor))

        runner.accept(envelope)
        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.plan(envelope)

        self.assertEqual(raised.exception.envelope.code, "EXEC_CONTEXT_CAPABILITY_DENIED")
        self.assertIn("adapter is not allowlisted", raised.exception.envelope.message)
        self.assertEqual([event.method for event in runner.runtime.store.events(envelope.job_id)], ["accept"])

    def test_runner_build_context_default_denies_undeclared_dataset(self) -> None:
        class UndeclaredDatasetBuildSubagent(Subagent):
            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {"steps": []}

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                ctx.read_dataset("c4://dataset/undeclared")
                return {}

        descriptor = SubagentDescriptor(
            subagent_id="sdk-empty-dataset-subagent",
            contract_version="1.0.0",
            subtopics=("ewpt",),
        )
        envelope = JobEnvelope(
            job_id="77777777-7777-4777-8777-777777777777",
            envelope_version="1.0.0",
            subtopic="ewpt",
            verifier_profile_ref="c4://profile/ewpt/v1",
        )
        runner = SubagentSDKRunner(UndeclaredDatasetBuildSubagent(descriptor))

        runner.accept(envelope)
        planned = runner.plan(envelope)
        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.build(envelope.job_id, planned.payload)

        self.assertEqual(raised.exception.envelope.code, "EXEC_CONTEXT_CAPABILITY_DENIED")
        self.assertIn("dataset is not allowlisted", raised.exception.envelope.message)
        self.assertEqual(runner.runtime.store.current(envelope.job_id).state, LifecycleState.QUARANTINED)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(envelope.job_id)],
            ["accept", "plan", "quarantine"],
        )

    def test_exec_context_submit_sandbox_job_fails_closed_without_s10_marshaler(self) -> None:
        ctx = ExecContext(job_id=self.envelope.job_id)

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.submit_sandbox_job({"entrypoint": ["python", "build.py"]})

        self.assertEqual(raised.exception.envelope.code, "S10_MARSHALER_UNAVAILABLE")
        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertFalse(raised.exception.envelope.retryable)
        self.assertIn("direct in-process execution is forbidden", raised.exception.envelope.message)

    def test_exec_context_submit_sandbox_job_delegates_to_real_s10_orchestrator(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        orchestrator, request, audit, artifacts = self._s10_orchestrator_and_request()
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            sandbox_marshaler=S10SandboxMarshaler(orchestrator),
        )

        result = ctx.submit_sandbox_job({"launch_request": request})

        self.assertEqual(result["capability"], "submit_sandbox_job")
        self.assertEqual(result["job_id"], self.envelope.job_id)
        self.assertEqual(result["state"], "ADMITTED")
        self.assertEqual(result["runtime_class"], "gvisor")
        self.assertEqual(result["policy_bundle_version"], "s1-t11-test")
        self.assertEqual(result["budget_epoch"], request.budget_token.budget_epoch)
        self.assertTrue(str(result["sandbox_id"]))
        self.assertTrue(str(result["launch_provenance_ref"]).startswith("c4://artifact/"))
        self.assertEqual(audit.events()[-1].event_type, "sandbox.launched")
        self.assertEqual(artifacts.get_record(str(result["launch_provenance_ref"])).kind, "container")

    def test_derive_sandbox_egress_allowlist_uses_store_and_declared_adapter_endpoints(self) -> None:
        from argus_core.s1 import S1_CONTENT_STORE_EGRESS_RULE, derive_sandbox_egress_allowlist

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")

        self.assertEqual(
            derive_sandbox_egress_allowlist(
                ("adapter:bounce", "adapter:bounce"),
                {"adapter:bounce": adapter_rule},
            ),
            (S1_CONTENT_STORE_EGRESS_RULE, adapter_rule),
        )

    def test_exec_context_submit_sandbox_job_denies_non_derived_egress_before_s10_launch(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")
        evil_rule = EgressRule("evil.local", 443, "https")
        orchestrator, request, audit, _artifacts = self._s10_orchestrator_and_request(
            scope_allowed_adapters=("adapter:bounce",),
            egress_allowlist=(EgressRule("store.local", 443, "https"), adapter_rule, evil_rule),
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            adapter_egress_allowlist={"adapter:bounce": adapter_rule},
            sandbox_marshaler=S10SandboxMarshaler(orchestrator),
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.submit_sandbox_job({"launch_request": request})

        self.assertEqual(raised.exception.envelope.code, "S10_EGRESS_SCOPE_WIDENED")
        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertNotIn("sandbox.launched", [event.event_type for event in audit.events()])

    def test_exec_context_submit_sandbox_job_requires_declared_adapter_scope(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")
        orchestrator, request, audit, _artifacts = self._s10_orchestrator_and_request(
            scope_allowed_adapters=(),
            egress_allowlist=(EgressRule("store.local", 443, "https"), adapter_rule),
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            adapter_egress_allowlist={"adapter:bounce": adapter_rule},
            sandbox_marshaler=S10SandboxMarshaler(orchestrator),
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            ctx.submit_sandbox_job({"launch_request": request})

        self.assertEqual(raised.exception.envelope.code, "S10_ADAPTER_SCOPE_MISSING")
        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertNotIn("sandbox.launched", [event.event_type for event in audit.events()])

    def test_exec_context_submit_sandbox_job_allows_declared_adapter_egress(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")
        store_rule = EgressRule("store.local", 443, "https")
        orchestrator, request, audit, artifacts = self._s10_orchestrator_and_request(
            scope_allowed_adapters=("adapter:bounce",),
            egress_allowlist=(store_rule, adapter_rule),
        )
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            adapter_egress_allowlist={"adapter:bounce": adapter_rule},
            sandbox_marshaler=S10SandboxMarshaler(orchestrator),
        )

        result = ctx.submit_sandbox_job({"launch_request": request})
        record = artifacts.get_record(str(result["launch_provenance_ref"]))
        payload = json.loads(artifacts.get_artifact(record.artifact_ref).decode("utf-8"))

        self.assertEqual(result["state"], "ADMITTED")
        self.assertEqual(audit.events()[-1].event_type, "sandbox.launched")
        self.assertEqual(
            {tuple(sorted(rule.items())) for rule in payload["exec_environment"]["egress_acl"]},
            {tuple(sorted(asdict(store_rule).items())), tuple(sorted(asdict(adapter_rule).items()))},
        )

    def test_runner_passes_runtime_adapter_egress_registry_to_build_context(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")
        orchestrator, request, audit, _artifacts = self._s10_orchestrator_and_request(
            scope_allowed_adapters=("adapter:bounce",),
            egress_allowlist=(EgressRule("store.local", 443, "https"), adapter_rule),
        )

        class SandboxBuildSubagent(Subagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.sandbox_state: str | None = None

            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {
                    "steps": [
                        {
                            "step_id": "sandbox-build",
                            "kind": "feature",
                            "description": "Run sandboxed adapter build",
                        }
                    ],
                    "adapters_required": ["adapter:bounce"],
                }

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                result = ctx.submit_sandbox_job({"launch_request": request})
                self.sandbox_state = str(result["state"])
                return {
                    "artifact_refs": ["c4://artifact/sandbox-model"],
                    "diagnostics": {"sandbox_state": self.sandbox_state},
                }

        subagent = SandboxBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(
                descriptor=self.descriptor,
                sandbox_marshaler=S10SandboxMarshaler(orchestrator),
                adapter_egress_allowlist={"adapter:bounce": adapter_rule},
            ),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        built = runner.build(self.envelope.job_id, planned.payload)

        self.assertEqual(subagent.sandbox_state, "ADMITTED")
        self.assertEqual(audit.events()[-1].event_type, "sandbox.launched")
        self.assertEqual(built.payload["diagnostics"], {"sandbox_state": "ADMITTED"})
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.BUILDING)

    def test_runtime_cancel_uses_real_s10_marshaler_and_partial_provenance(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")
        orchestrator, request, audit, artifacts = self._s10_orchestrator_and_request(
            scope_allowed_adapters=("adapter:bounce",),
            egress_allowlist=(EgressRule("store.local", 443, "https"), adapter_rule),
        )

        class SandboxBuildSubagent(Subagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.sandbox_id: str | None = None
                self.launch_provenance_ref: str | None = None

            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {
                    "steps": [
                        {
                            "step_id": "sandbox-build",
                            "kind": "feature",
                            "description": "Run cancellable sandbox build",
                        }
                    ]
                }

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                result = ctx.submit_sandbox_job({"launch_request": request})
                self.sandbox_id = str(result["sandbox_id"])
                self.launch_provenance_ref = str(result["launch_provenance_ref"])
                return {
                    "artifact_refs": ["c4://artifact/cancellable-sandbox-model"],
                    "diagnostics": {"sandbox_id": self.sandbox_id},
                }

        subagent = SandboxBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(
                descriptor=self.descriptor,
                sandbox_marshaler=S10SandboxMarshaler(orchestrator),
                adapter_egress_allowlist={"adapter:bounce": adapter_rule},
            ),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        runner.build(self.envelope.job_id, planned.payload)
        event = runner.runtime.cancel(self.envelope.job_id, reason="operator", grace_seconds=0.25)

        assert subagent.sandbox_id is not None
        assert subagent.launch_provenance_ref is not None
        self.assertEqual(orchestrator.get(subagent.sandbox_id).state, "TERMINATED")
        self.assertEqual(event.to_state, LifecycleState.CANCELLED)
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.CANCELLED)
        event_types = [item.event_type for item in audit.events()]
        self.assertIn("sandbox.partial_result", event_types)
        self.assertIn("sandbox.cancelled", event_types)
        partial_records = artifacts.query_artifacts({"kind": "sandbox.partial_result"})
        self.assertEqual(len(partial_records), 1)
        partial_record = partial_records[0]
        partial_payload = json.loads(artifacts.get_artifact(partial_record.artifact_ref).decode("utf-8"))
        self.assertEqual(partial_payload["reason"], "operator")
        self.assertEqual(partial_payload["terminated_state"], "TERMINATED")
        self.assertEqual(partial_record.lineage.input_refs, (subagent.launch_provenance_ref,))

    def test_restart_recovery_reattaches_real_s10_handle_and_cancel_uses_recovered_sandbox(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")
        orchestrator, request, audit, s10_artifacts = self._s10_orchestrator_and_request(
            scope_allowed_adapters=("adapter:bounce",),
            egress_allowlist=(EgressRule("store.local", 443, "https"), adapter_rule),
        )

        class SandboxBuildSubagent(Subagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.sandbox_id: str | None = None

            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {
                    "steps": [
                        {
                            "step_id": "sandbox-build",
                            "kind": "feature",
                            "description": "Run restart-recoverable sandbox build",
                        }
                    ],
                    "adapters_required": ["adapter:bounce"],
                }

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                result = ctx.submit_sandbox_job({"launch_request": request})
                self.sandbox_id = str(result["sandbox_id"])
                return {
                    "artifact_refs": ["c4://artifact/restart-recovered-sandbox-model"],
                    "diagnostics": {"sandbox_id": self.sandbox_id},
                }

        subagent = SandboxBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(
                descriptor=self.descriptor,
                sandbox_marshaler=S10SandboxMarshaler(orchestrator),
                adapter_egress_allowlist={"adapter:bounce": adapter_rule},
            ),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        runner.build(self.envelope.job_id, planned.payload)

        assert subagent.sandbox_id is not None
        runtime_artifacts = runner.runtime.artifact_store
        attachment_refs = runner.runtime.sandbox_attachment_refs(self.envelope.job_id)
        self.assertEqual(len(attachment_refs), 1)
        self.assertEqual(runtime_artifacts.get_record(attachment_refs[0]).kind, S1_SANDBOX_ATTACHMENT_KIND)
        before_ledger_refs = runner.runtime.store.ledger_refs(self.envelope.job_id)
        rebuilt_store = LifecycleStore.from_event_log(
            {self.envelope.job_id: runner.runtime.store.events(self.envelope.job_id)},
            artifact_store=runtime_artifacts,
        )
        restarted_runtime = SubagentRuntime(
            descriptor=self.descriptor,
            store=rebuilt_store,
            sandbox_marshaler=S10SandboxMarshaler(orchestrator),
            adapter_egress_allowlist={"adapter:bounce": adapter_rule},
        )

        recovered = restarted_runtime.recover_active_sandboxes(self.envelope.job_id)
        cancel_event = restarted_runtime.cancel(self.envelope.job_id, reason="operator-restart", grace_seconds=0.25)

        self.assertEqual(restarted_runtime.store.current(self.envelope.job_id).state, LifecycleState.CANCELLED)
        self.assertEqual(recovered[0]["sandbox_id"], subagent.sandbox_id)
        self.assertEqual(recovered[0]["reattach_state"], "ADMITTED")
        self.assertEqual(restarted_runtime.sandbox_attachment_refs(self.envelope.job_id), attachment_refs)
        self.assertEqual(before_ledger_refs, restarted_runtime.store.ledger_refs(self.envelope.job_id)[:-1])
        self.assertEqual(cancel_event.to_state, LifecycleState.CANCELLED)
        self.assertEqual(orchestrator.get(subagent.sandbox_id).state, "TERMINATED")
        event_types = [item.event_type for item in audit.events()]
        self.assertIn("sandbox.cancelled", event_types)
        partial_records = s10_artifacts.query_artifacts({"kind": "sandbox.partial_result"})
        self.assertEqual(len(partial_records), 1)
        partial_payload = json.loads(s10_artifacts.get_artifact(partial_records[0].artifact_ref).decode("utf-8"))
        self.assertEqual(partial_payload["reason"], "operator-restart")
        self.assertEqual(partial_records[0].lineage.input_refs, (recovered[0]["launch_provenance_ref"],))

    def test_runner_quarantines_sandbox_error_with_real_s10_forensic_partial_result(self) -> None:
        from argus_core.s1 import S10SandboxMarshaler

        adapter_rule = EgressRule("bounce.adapter.local", 8443, "grpc")
        orchestrator, request, audit, artifacts = self._s10_orchestrator_and_request(
            scope_allowed_adapters=("adapter:bounce",),
            egress_allowlist=(EgressRule("store.local", 443, "https"), adapter_rule),
        )

        class QuarantinedSandboxBuildSubagent(Subagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.sandbox_id: str | None = None
                self.launch_provenance_ref: str | None = None

            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {
                    "steps": [
                        {
                            "step_id": "sandbox-build",
                            "kind": "feature",
                            "description": "Run sandboxed build that trips a trust mount policy",
                        }
                    ],
                    "adapters_required": ["adapter:bounce"],
                }

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                result = ctx.submit_sandbox_job({"launch_request": request})
                self.sandbox_id = str(result["sandbox_id"])
                self.launch_provenance_ref = str(result["launch_provenance_ref"])
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="SANDBOX",
                        code="TRUST_PATH_WRITE",
                        message="sandbox attempted to write verifier trust-path",
                    )
                )

        subagent = QuarantinedSandboxBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(
            subagent,
            runtime=SubagentRuntime(
                descriptor=self.descriptor,
                sandbox_marshaler=S10SandboxMarshaler(orchestrator),
                adapter_egress_allowlist={"adapter:bounce": adapter_rule},
            ),
        )

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.build(self.envelope.job_id, planned.payload)

        assert subagent.sandbox_id is not None
        assert subagent.launch_provenance_ref is not None
        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertEqual(raised.exception.envelope.code, "TRUST_PATH_WRITE")
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.QUARANTINED)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "quarantine"],
        )
        self.assertEqual(orchestrator.get(subagent.sandbox_id).state, "QUARANTINED")
        event_types = [item.event_type for item in audit.events()]
        self.assertIn("sandbox.partial_result", event_types)
        self.assertIn("sandbox.quarantined", event_types)
        partial_records = artifacts.query_artifacts({"kind": "sandbox.partial_result"})
        self.assertEqual(len(partial_records), 1)
        partial_record = partial_records[0]
        partial_payload = json.loads(artifacts.get_artifact(partial_record.artifact_ref).decode("utf-8"))
        self.assertEqual(partial_payload["reason"], "SANDBOX:TRUST_PATH_WRITE")
        self.assertEqual(partial_payload["error"]["code"], "TRUST_PATH_WRITE")
        self.assertEqual(partial_payload["frozen_state"], "FROZEN")
        self.assertEqual(partial_payload["terminated_state"], "TERMINATED")
        self.assertTrue(partial_payload["captured_after_freeze"])
        self.assertTrue(partial_payload["freeze_succeeded"])
        self.assertTrue(partial_payload["terminate_succeeded"])
        self.assertEqual(partial_record.lineage.input_refs, (subagent.launch_provenance_ref,))

    def test_build_context_records_runtime_heartbeat_spend(self) -> None:
        class HeartbeatBuildSubagent(ExampleSubagent):
            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                payload = super().build(ctx, plan)
                heartbeat = ctx.record_heartbeat(progress=0.40, spend_so_far={"cost_usd": 0.125})
                payload["diagnostics"]["heartbeat_progress"] = heartbeat["progress"]
                payload["diagnostics"]["heartbeat_spend"] = heartbeat["spend_so_far"]
                return payload

        runner = SubagentSDKRunner(HeartbeatBuildSubagent(self.descriptor))

        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        built = runner.build(self.envelope.job_id, planned.payload)
        health = runner.runtime.heartbeat(self.envelope.job_id)

        self.assertEqual(health.status, LifecycleState.BUILDING)
        self.assertEqual(health.progress, 0.40)
        self.assertEqual(health.spend_so_far, {"cost_usd": 0.125})
        self.assertEqual(built.payload["diagnostics"]["heartbeat_progress"], 0.40)
        self.assertEqual(built.payload["diagnostics"]["heartbeat_spend"], {"cost_usd": 0.125})
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "build"],
        )

    def test_subagent_linter_flags_direct_in_process_exec_patterns(self) -> None:
        from argus_core.s1 import lint_subagent_for_direct_exec

        class DirectExecSubagent(Subagent):
            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {"unsafe": eval("1")}

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                subprocess.run(["true"], check=False)
                return {"artifact_refs": []}

        violations = lint_subagent_for_direct_exec(DirectExecSubagent(self.descriptor))

        self.assertIn("plan: eval", violations)
        self.assertIn("build: subprocess.run", violations)

    def test_runner_quarantines_direct_in_process_exec_before_build_invocation(self) -> None:
        class DirectExecBuildSubagent(Subagent):
            def __init__(self, descriptor: SubagentDescriptor) -> None:
                super().__init__(descriptor)
                self.build_called = False

            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                return {}

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                self.build_called = True
                os.system("true")
                return {"artifact_refs": []}

        subagent = DirectExecBuildSubagent(self.descriptor)
        runner = SubagentSDKRunner(subagent)
        runner.accept(self.envelope)
        planned = runner.plan(self.envelope)

        with self.assertRaises(LifecyclePolicyError) as raised:
            runner.build(self.envelope.job_id, planned.payload)

        self.assertEqual(raised.exception.envelope.code, "DIRECT_IN_PROCESS_EXEC_FORBIDDEN")
        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertFalse(subagent.build_called)
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.QUARANTINED)
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(self.envelope.job_id)],
            ["accept", "plan", "quarantine"],
        )

    def test_framework_owned_methods_cannot_be_overridden_by_authors(self) -> None:
        with self.assertRaisesRegex(TypeError, "validate"):

            class BadValidateSubagent(Subagent):
                def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                    return {}

                def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                    return {}

                def validate(self) -> dict[str, object]:
                    return {}

        with self.assertRaisesRegex(TypeError, "accept"):

            class BadAcceptSubagent(Subagent):
                def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                    return {}

                def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                    return {}

                def accept(self) -> bool:
                    return True

    def test_framework_owned_methods_cannot_be_inherited_from_mixins(self) -> None:
        def plan(self: Subagent, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
            return {}

        def build(self: Subagent, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
            return {}

        for method in ("register", "accept", "validate", "report", "cancel", "heartbeat"):
            with self.subTest(method=method):
                mixin_method = lambda self, *args, **kwargs: {"bypassed": method}
                mixin = type(f"{method.title()}Mixin", (), {method: mixin_method})
                attrs = {"plan": plan, "build": build}

                with self.assertRaisesRegex(TypeError, method):
                    type(f"Sneaky{method.title()}Subagent", (mixin, Subagent), attrs)

    def test_base_validate_is_framework_owned_policy_error(self) -> None:
        subagent = ExampleSubagent(self.descriptor)

        with self.assertRaises(LifecyclePolicyError) as raised:
            subagent.validate()

        self.assertEqual(raised.exception.envelope.code, "SDK_VALIDATE_FRAMEWORK_OWNED")
        self.assertEqual(raised.exception.envelope.category, "POLICY")

    def test_invalid_author_plan_payload_does_not_advance_lifecycle(self) -> None:
        class BadPlanSubagent(Subagent):
            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> list[str]:
                return ["not", "a", "mapping"]

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                return {}

        runner = SubagentSDKRunner(BadPlanSubagent(self.descriptor))
        runner.accept(self.envelope)

        with self.assertRaises(TypeError):
            runner.plan(self.envelope)

        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.ACCEPTED)
        self.assertEqual([event.method for event in runner.runtime.store.events(self.envelope.job_id)], ["accept"])

    def _assert_c1_valid(self, payload: dict[str, object]) -> None:
        errors = sorted(self.c1_validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def _assert_c1_def_valid(self, def_name: str, payload: dict[str, object]) -> None:
        validator = self.c1_validator.evolve(schema=self.c1_schema["$defs"][def_name])
        errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def _walk_client_object_graph(self, root: object, *, max_depth: int) -> list[object]:
        simple = (str, bytes, int, float, bool, type(None))
        seen: set[int] = set()
        queue: list[tuple[object, int]] = [(root, 0)]
        reachable: list[object] = []
        while queue:
            item, depth = queue.pop(0)
            if id(item) in seen:
                continue
            seen.add(id(item))
            reachable.append(item)
            if depth >= max_depth or isinstance(item, simple):
                continue
            children: list[object] = []
            if isinstance(item, ReferenceType):
                target = item()
                if target is not None:
                    children.append(target)
            if isinstance(item, dict):
                children.extend(item.keys())
                children.extend(item.values())
            elif isinstance(item, (list, tuple, set, frozenset)):
                children.extend(item)
            item_dict = getattr(item, "__dict__", None)
            if isinstance(item_dict, dict):
                children.extend(item_dict.values())
            for cls in type(item).__mro__:
                slots = getattr(cls, "__slots__", ())
                if isinstance(slots, str):
                    slots = (slots,)
                for slot in slots:
                    if slot in {"__weakref__", "__dict__"}:
                        continue
                    if hasattr(item, slot):
                        children.append(getattr(item, slot))
            for child in children:
                if id(child) not in seen:
                    queue.append((child, depth + 1))
        return reachable

    def _brokered_adapter_client(
        self,
        *,
        allowed_adapters: tuple[str, ...],
        broker_audiences: tuple[str, ...],
        register_adapter: bool = True,
    ) -> tuple[object, InMemoryAuditLedger, InMemoryArtifactStore]:
        artifacts = InMemoryArtifactStore()
        audit = InMemoryAuditLedger()
        tokens = InMemoryTokenService(signing_key=b"s1-t13-token-key", now_fn=lambda: 1_000)
        adapter_broker = AdapterBroker(artifact_store=artifacts)
        if register_adapter:
            adapter_broker.register(self._bounce_adapter())
        scope = tokens.mint_scope(
            job_id=self.envelope.job_id,
            scopes=ScopeGrant(
                allowed_adapters=allowed_adapters,
                broker_audiences=broker_audiences,
            ),
        )
        proxy = S1AdapterBrokerProxy(
            token_service=tokens,
            adapter_broker=adapter_broker,
            audit_ledger=audit,
        )
        self._adapter_broker_proxies.append(proxy)
        return proxy.client_for(scope), audit, artifacts

    @staticmethod
    def _adapter_call_payload(*, x: float, seed: int | None = None) -> dict[str, object]:
        payload: dict[str, object] = {
            "inputs": {
                "x": {
                    "value": x,
                    "units": "dimensionless",
                    "uncertainty": {"kind": "interval", "radius": 0.01},
                }
            }
        }
        if seed is not None:
            payload["seed"] = seed
        return payload

    @staticmethod
    def _bounce_adapter() -> SimpleAdapter:
        descriptor = AdapterDescriptor(
            adapter_id="adapter:bounce",
            version="1.0.0",
            input_units={"x": "dimensionless"},
            output_units={"y": "dimensionless"},
            validity_domain={"x": (0.0, 10.0)},
            determinism="deterministic",
            provenance_ref="c4://adapter/bounce",
        )
        return SimpleAdapter(
            descriptor,
            lambda inputs, _seed: {
                "y": Quantity(
                    value=inputs["x"].value * 2.0,
                    units="dimensionless",
                    uncertainty={"kind": "interval", "radius": 0.1},
                )
            },
        )

    def _s10_orchestrator_and_request(
        self,
        *,
        scope_allowed_adapters: tuple[str, ...] = (),
        egress_allowlist: tuple[EgressRule, ...] = (EgressRule("store.local", 443, "https"),),
    ) -> tuple[InMemorySandboxOrchestrator, LaunchRequest, InMemoryAuditLedger, InMemoryArtifactStore]:
        audit = InMemoryAuditLedger()
        artifacts = InMemoryArtifactStore()
        tokens = InMemoryTokenService(signing_key=b"s1-t11-token-key", now_fn=lambda: 1_000)
        policy = PolicyBundle(
            bundle_version="s1-t11-test",
            egress_allowlist=egress_allowlist,
            resource_ceilings=ResourceCeilings(
                cpu_m=2_000,
                mem_bytes=4_000_000_000,
                gpu_count=0,
                wallclock_s=120,
                max_cost_usd=10,
            ),
            risk_to_runtime={"standard": "gvisor", "federated": "firecracker", "high": "firecracker"},
            seccomp_profile_hash="blake3:" + "a" * 64,
            signer_key_id="policy",
            signature="test-signature",
        )
        budget = tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=1_000, max_wallclock_s=120, max_cost_usd=10),
            job_id=self.envelope.job_id,
            root_request_id="root-s1-t11",
        )
        scope = tokens.mint_scope(
            job_id=self.envelope.job_id,
            scopes=ScopeGrant(
                allowed_adapters=scope_allowed_adapters,
                egress_allowlist=egress_allowlist,
                broker_audiences=("store",),
            ),
        )
        request = LaunchRequest(
            job_id=self.envelope.job_id,
            subagent_id=self.descriptor.subagent_id,
            trace_id="trace-s1-t11",
            budget_token=budget,
            scope_token=scope,
            image="registry.local/argus@sha256:" + "b" * 64,
            entrypoint=("python",),
            args=("build.py",),
            env={},
            env_allowlist=(),
            requested_envelope=LaunchEnvelope(
                cpu_m=1_000,
                mem_bytes=1_000_000,
                gpu_count=0,
                wallclock_s=10,
                scratch_bytes=1_000,
                pids=10,
                estimated_cost_usd=0.01,
            ),
        )
        orchestrator = InMemorySandboxOrchestrator(
            token_service=tokens,
            quota_ledger=InMemoryQuotaLedger(),
            audit_ledger=audit,
            policy_bundle=policy,
            artifact_store=artifacts,
        )
        return orchestrator, request, audit, artifacts


if __name__ == "__main__":
    unittest.main()
