from __future__ import annotations

import unittest

from argus_core import (
    BudgetCaps,
    EgressRule,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemorySandboxOrchestrator,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    Lineage,
    PolicyBundle,
    Producer,
    ResourceCeilings,
    ScopeDeniedError,
    ScopeGrant,
    StoreWriterBroker,
)


class M0SpineIntegrationSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifacts = InMemoryArtifactStore()
        self.audit = InMemoryAuditLedger()
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)
        self.quota = InMemoryQuotaLedger()
        self.bundle = PolicyBundle(
            bundle_version="1.0.0",
            egress_allowlist=(EgressRule("store.local", 443, "https"),),
            resource_ceilings=ResourceCeilings(
                cpu_m=2_000,
                mem_bytes=4_000_000_000,
                gpu_count=1,
                wallclock_s=120,
                max_cost_usd=100,
            ),
            risk_to_runtime={"standard": "gvisor", "federated": "firecracker", "high": "firecracker"},
            seccomp_profile_hash="blake3:" + "a" * 64,
            signer_key_id="security",
            signature="test-signature",
        )

    def test_spine_slice_launches_and_writes_artifact_through_broker(self) -> None:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=1_000, max_wallclock_s=120, max_cost_usd=20),
            job_id="job-1",
            root_request_id="root-1",
        )
        scope = self.tokens.mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                broker_audiences=("store",),
                producer_subsystems=("S2",),
            ),
        )
        orchestrator = InMemorySandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            policy_bundle=self.bundle,
            artifact_store=self.artifacts,
        )

        handle = orchestrator.launch(
            LaunchRequest(
                job_id="job-1",
                subagent_id="subagent-1",
                trace_id="trace-1",
                budget_token=budget,
                scope_token=scope,
                image="registry.local/argus@sha256:" + "b" * 64,
                entrypoint=("python",),
                args=("train.py",),
                env={},
                env_allowlist=(),
                requested_envelope=LaunchEnvelope(
                    cpu_m=1_000,
                    mem_bytes=1_000_000,
                    gpu_count=0,
                    wallclock_s=10,
                    scratch_bytes=1_000,
                    pids=10,
                    estimated_cost_usd=2,
                ),
            )
        )
        self.assertIsNotNone(handle.launch_provenance_ref)
        launch_record = self.artifacts.get_record(handle.launch_provenance_ref or "")
        self.assertEqual(launch_record.kind, "container")

        broker = StoreWriterBroker(
            token_service=self.tokens,
            artifact_store=self.artifacts,
            audit_ledger=self.audit,
        )
        model = broker.client_for(scope).put_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(
                input_refs=(handle.launch_provenance_ref or "",),
                code_ref="git:model",
                environment_digest="oci:model",
                seeds=("seed-1",),
            ),
        )

        lineage = self.artifacts.get_lineage(model.artifact_ref, direction="ancestors")
        lineage_refs = {node.artifact_ref for node in lineage.nodes}

        self.assertIn(handle.launch_provenance_ref, lineage_refs)
        self.assertEqual(model.producer.job_id, "job-1")
        self.assertEqual(model.lineage.job_id, "job-1")
        self.assertEqual(self.artifacts.record_count, 2)
        self.assertTrue(self.artifacts.verify_audit_chain().valid)
        self.assertTrue(self.audit.verify_chain().valid)
        self.assertEqual(self.audit.events()[-1].event_type, "store.put")

    def test_store_broker_denies_scope_without_store_audience(self) -> None:
        scope = self.tokens.mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                broker_audiences=("adapter:a",),
            ),
        )
        broker = StoreWriterBroker(
            token_service=self.tokens,
            artifact_store=self.artifacts,
            audit_ledger=self.audit,
        )

        with self.assertRaises(ScopeDeniedError):
            broker.client_for(scope).put_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
            )

        self.assertEqual(self.artifacts.record_count, 0)
        self.assertEqual(self.audit.events()[-1].event_type, "store.denied")


if __name__ == "__main__":
    unittest.main()
