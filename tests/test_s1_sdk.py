from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    BudgetCaps,
    EgressRule,
    ExecContext,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemorySandboxOrchestrator,
    InMemoryTokenService,
    JobEnvelope,
    LaunchEnvelope,
    LaunchRequest,
    LifecyclePolicyError,
    LifecycleState,
    Lineage,
    PolicyBundle,
    Producer,
    ResourceCeilings,
    ScopeGrant,
    Subagent,
    SubagentDescriptor,
    SubagentSDKRunner,
    SubagentRuntime,
    hash_bytes,
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
                "artifact_store",
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
                "artifact_store": False,
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

    def test_exec_context_brokers_documented_capabilities_with_allowlists(self) -> None:
        ctx = ExecContext(
            job_id=self.envelope.job_id,
            allowed_adapters=("adapter:bounce",),
            allowed_datasets=("c4://dataset/ewpt-toy",),
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
        self.assertEqual(ctx.call_adapter("adapter:bounce", {"input": 1})["capability"], "call_adapter")
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

    def test_exec_context_emit_artifact_rejects_illegal_tier_without_commit(self) -> None:
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

        self.assertEqual(raised.exception.envelope.code, "ILLEGAL_TIER")
        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertIn("validation_report_ref", raised.exception.envelope.message)
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
        self.assertEqual(
            [event.method for event in runner.runtime.store.events(envelope.job_id)],
            ["accept", "plan"],
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
