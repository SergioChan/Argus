from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
import shutil
import subprocess
import unittest

from argus_core import (
    BudgetCaps,
    BudgetExceededError,
    BudgetUsage,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    EgressProxy,
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
    PolicyDeniedError,
    Producer,
    ResourceCeilings,
    SandboxExecutionResult,
    SandboxHandle,
    SandboxRuntimeUnavailableError,
    ScopeDeniedError,
    ScopeGrant,
    ScopeWideningError,
    StoreWriterBroker,
    TokenInvalidError,
    canonical_json_bytes,
    decide_policy,
    hash_bytes,
    hash_json,
    materialize_sandbox_env,
)


class S10TokenServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_000
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: self.now)

    def test_budget_token_verification_rejects_tampered_expired_unknown_and_revoked(self) -> None:
        token = self.tokens.mint_budget(
            caps=BudgetCaps(max_gpu_seconds=10, max_cost_usd=5),
            job_id="job-1",
            root_request_id="root-1",
            ttl_s=30,
        )

        tampered = replace(token, caps=replace(token.caps, max_cost_usd=999))
        unknown = replace(token, signer_key_id="unknown")
        self.assertTrue(self.tokens.verify_budget(token).valid)
        self.assertEqual(self.tokens.verify_budget(tampered).reason, "signature_invalid")
        self.assertEqual(self.tokens.verify_budget(unknown).reason, "unknown_signer")

        self.tokens.revoke(token.budget_id)
        self.assertEqual(self.tokens.verify_budget(token).reason, "revoked")

        fresh = self.tokens.mint_budget(
            caps=BudgetCaps(max_gpu_seconds=10, max_cost_usd=5),
            job_id="job-1",
            root_request_id="root-1",
            ttl_s=30,
        )
        self.now = 1_031
        self.assertEqual(self.tokens.verify_budget(fresh).reason, "expired")

    def test_attenuation_cannot_widen_budget_or_scope(self) -> None:
        parent_budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_gpu_seconds=100, max_cost_usd=10),
            job_id="job-1",
            root_request_id="root-1",
        )
        child_budget = self.tokens.attenuate_budget(
            parent_budget,
            BudgetCaps(max_gpu_seconds=50, max_cost_usd=5),
        )
        self.assertTrue(self.tokens.verify_budget(child_budget).valid)

        with self.assertRaises(ScopeWideningError):
            self.tokens.attenuate_budget(parent_budget, BudgetCaps(max_gpu_seconds=101, max_cost_usd=5))

        parent_scope = self.tokens.mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(
                allowed_adapters=("adapter:a",),
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                broker_audiences=("store", "adapter:a"),
                disallowed_actions=("direct_ledger_write",),
            ),
        )
        child_scope = self.tokens.attenuate_scope(
            parent_scope,
            ScopeGrant(
                allowed_adapters=("adapter:a",),
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                broker_audiences=("store",),
                disallowed_actions=("direct_ledger_write", "direct_egress"),
            ),
        )
        self.assertTrue(self.tokens.verify_scope(child_scope).valid)

        with self.assertRaises(ScopeWideningError):
            self.tokens.attenuate_scope(
                parent_scope,
                ScopeGrant(
                    allowed_adapters=("adapter:a", "adapter:b"),
                    egress_allowlist=(EgressRule("store.local", 443, "https"),),
                    broker_audiences=("store",),
                    disallowed_actions=("direct_ledger_write",),
                ),
            )


class S10QuotaLedgerTests(unittest.TestCase):
    def test_reserve_consume_release_keeps_remaining_exact(self) -> None:
        tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)
        token = tokens.mint_budget(
            caps=BudgetCaps(max_gpu_seconds=100, max_cost_usd=100),
            job_id="job-1",
            root_request_id="root-1",
        )
        ledger = InMemoryQuotaLedger()
        ledger.register_budget(token)

        ledger.reserve(token.budget_id, BudgetUsage(gpu_seconds=60, cost_usd=30))
        ledger.consume(token.budget_id, BudgetUsage(gpu_seconds=40, cost_usd=18))
        ledger.release(token.budget_id)

        state = ledger.state(token.budget_id)
        remaining = ledger.remaining(token.budget_id)
        self.assertEqual(state.reserved, BudgetUsage())
        self.assertEqual(state.actual.gpu_seconds, 40)
        self.assertEqual(state.actual.cost_usd, 18)
        self.assertEqual(remaining.gpu_seconds, 60)
        self.assertEqual(remaining.cost_usd, 82)

        with self.assertRaises(BudgetExceededError):
            ledger.reserve(token.budget_id, BudgetUsage(gpu_seconds=61))


class S10PolicyAndEgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_000
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: self.now)
        self.bundle = PolicyBundle(
            bundle_version="1.0.0",
            egress_allowlist=(EgressRule("store.local", 443, "https"),),
            resource_ceilings=ResourceCeilings(
                cpu_m=2_000,
                mem_bytes=4_000_000_000,
                gpu_count=1,
                wallclock_s=120,
                max_cost_usd=20,
            ),
            risk_to_runtime={"standard": "gvisor", "federated": "firecracker", "high": "firecracker"},
            seccomp_profile_hash="blake3:" + "a" * 64,
            signer_key_id="security",
            signature="test-signature",
        )

    def test_policy_decision_is_pure_and_deterministic(self) -> None:
        request = self._launch_request()

        first = decide_policy(self.bundle, request)
        second = decide_policy(self.bundle, request)

        self.assertEqual(canonical_json_bytes(asdict(first)), canonical_json_bytes(asdict(second)))
        self.assertTrue(first.allowed)
        self.assertEqual(first.runtime_class, "gvisor")
        self.assertEqual(first.egress_acl, (EgressRule("store.local", 443, "https"),))

    def test_policy_denies_resource_ceiling(self) -> None:
        request = self._launch_request(
            envelope=LaunchEnvelope(
                cpu_m=2_001,
                mem_bytes=1_000,
                gpu_count=0,
                wallclock_s=10,
                scratch_bytes=1_000,
                pids=10,
            )
        )

        verdict = decide_policy(self.bundle, request)

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.deny_reason, "cpu_ceiling")

    def test_egress_proxy_is_default_deny_with_sni_check(self) -> None:
        scope = self.tokens.mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(egress_allowlist=(EgressRule("store.local", 443, "https"),)),
        )
        proxy = EgressProxy(self.bundle)

        self.assertTrue(proxy.decide(scope, host="store.local", port=443, proto="https", sni="store.local").allowed)
        self.assertFalse(proxy.decide(scope, host="evil.local", port=443, proto="https", sni="evil.local").allowed)
        self.assertEqual(
            proxy.decide(scope, host="store.local", port=443, proto="https", sni="other.local").reason,
            "sni_mismatch",
        )

    def test_env_materialization_strips_unlisted_and_rejects_secret_shaped_values(self) -> None:
        materialized = materialize_sandbox_env(
            {"SAFE": "visible", "UNLISTED": "ignored"},
            ("SAFE",),
        )
        self.assertEqual(materialized, {"SAFE": "visible"})

        with self.assertRaises(PolicyDeniedError):
            materialize_sandbox_env({"SAFE": "api_key=sk-abcdefghijklmnop"}, ("SAFE",))

    def _launch_request(self, envelope: LaunchEnvelope | None = None) -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(
                max_compute_units=1_000,
                max_gpu_seconds=120,
                max_wallclock_s=120,
                max_cost_usd=20,
            ),
            job_id="job-1",
            root_request_id="root-1",
        )
        scope = self.tokens.mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                broker_audiences=("store",),
            ),
        )
        return LaunchRequest(
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
            requested_envelope=envelope
            or LaunchEnvelope(
                cpu_m=1_000,
                mem_bytes=1_000_000,
                gpu_count=0,
                wallclock_s=10,
                scratch_bytes=1_000,
                pids=10,
                estimated_cost_usd=1,
            ),
        )


class S10StoreWriterBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifacts = InMemoryArtifactStore()
        self.audit = InMemoryAuditLedger()
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)
        self.broker = StoreWriterBroker(
            token_service=self.tokens,
            artifact_store=self.artifacts,
            audit_ledger=self.audit,
        )

    def test_sandbox_client_put_writes_artifact_and_matches_content_hash(self) -> None:
        scope = self.tokens.mint_scope(job_id="job-1", scopes=ScopeGrant(broker_audiences=("store",)))
        client = self.broker.client_for(scope)
        payload = {"weights": [1, 2, 3]}

        record = client.put_artifact(
            kind="model",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
        )

        payload_bytes = canonical_json_bytes(payload)
        self.assertEqual(record.content_hash, hash_bytes(payload_bytes))
        self.assertEqual(self.artifacts.get_artifact(record.artifact_ref), payload_bytes)
        self.assertEqual(self.artifacts.record_count, 1)
        self.assertEqual(self.audit.events()[-1].event_type, "store.put")

    def test_sandbox_client_denies_direct_store_write_method(self) -> None:
        scope = self.tokens.mint_scope(job_id="job-1", scopes=ScopeGrant(broker_audiences=("store",)))
        client = self.broker.client_for(scope)

        with self.assertRaises(ScopeDeniedError):
            client.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
            )

        self.assertEqual(self.artifacts.record_count, 0)
        self.assertEqual(self.audit.events()[-1].event_type, "store.direct_write_denied")

    def test_store_broker_denies_scope_without_store_audience(self) -> None:
        scope = self.tokens.mint_scope(job_id="job-1", scopes=ScopeGrant(broker_audiences=("adapter:a",)))

        with self.assertRaises(ScopeDeniedError):
            self.broker.client_for(scope).put_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
            )

        self.assertEqual(self.artifacts.record_count, 0)
        self.assertEqual(self.audit.events()[-1].event_type, "store.denied")


class S10OrchestratorAndAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)
        self.quota = InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
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
        self.orchestrator = InMemorySandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            policy_bundle=self.bundle,
        )

    def test_launch_admits_digest_pinned_image_and_records_audit(self) -> None:
        request = self._launch_request(max_cost_usd=10, estimated_cost_usd=2)

        handle = self.orchestrator.launch(request)

        self.assertEqual(handle.runtime_class, "gvisor")
        self.assertEqual(handle.policy_bundle_version, "1.0.0")
        self.assertEqual(self.orchestrator.get(handle.sandbox_id), handle)
        self.assertEqual(self.quota.remaining(request.budget_token.budget_id).cost_usd, 8)
        self.assertTrue(self.audit.verify_chain().valid)
        self.assertEqual(self.audit.events()[-1].event_type, "sandbox.launched")

    def test_launch_emits_reproducible_c4_exec_environment_digest(self) -> None:
        artifacts = InMemoryArtifactStore()
        orchestrator = InMemorySandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            policy_bundle=self.bundle,
            artifact_store=artifacts,
        )
        request = self._launch_request(max_cost_usd=10, estimated_cost_usd=2)

        handle = orchestrator.launch(request)
        record = artifacts.get_record(handle.launch_provenance_ref or "")
        payload = json.loads(artifacts.get_artifact(record.artifact_ref).decode("utf-8"))
        exec_environment = payload["exec_environment"]
        exec_environment_digest = hash_json(exec_environment)

        self.assertEqual(record.kind, "container")
        self.assertFalse(hasattr(handle, "seccomp_profile_hash"))
        self.assertEqual(record.lineage.code_ref, request.image)
        self.assertEqual(record.lineage.environment_digest, exec_environment_digest)
        self.assertEqual(record.lineage.seeds, (request.trace_id,))
        self.assertEqual(payload["exec_environment_digest"], exec_environment_digest)
        self.assertEqual(exec_environment["image_digest"], request.image)
        self.assertEqual(exec_environment["runtime_class"], "gvisor")
        self.assertEqual(exec_environment["runtime_user"], "65532:65532")
        self.assertEqual(exec_environment["cgroup_limits"], asdict(request.requested_envelope))
        self.assertEqual(exec_environment["egress_acl"], [asdict(EgressRule("store.local", 443, "https"))])
        self.assertNotIn("seccomp_profile_hash", exec_environment)
        self.assertEqual(payload["launch"]["budget_id"], request.budget_token.budget_id)

        replacement_budget = self.tokens.mint_budget(
            caps=request.budget_token.caps,
            job_id=request.job_id,
            root_request_id=request.budget_token.root_request_id,
        )
        replacement_scope = self.tokens.mint_scope(job_id=request.job_id, scopes=request.scope_token.scopes)
        second_handle = orchestrator.launch(
            replace(request, budget_token=replacement_budget, scope_token=replacement_scope)
        )
        second_payload = json.loads(artifacts.get_artifact(second_handle.launch_provenance_ref or "").decode("utf-8"))
        self.assertEqual(second_payload["exec_environment_digest"], exec_environment_digest)

    def test_launch_rejects_tag_only_image_before_reserving_budget(self) -> None:
        request = replace(self._launch_request(max_cost_usd=10, estimated_cost_usd=2), image="registry.local/argus:latest")

        with self.assertRaises(PolicyDeniedError):
            self.orchestrator.launch(request)

        with self.assertRaises(KeyError):
            self.quota.state(request.budget_token.budget_id)
        self.assertEqual(self.audit.events()[-1].event_type, "image.verify_fail")

    def test_launch_rejects_over_budget_without_handle(self) -> None:
        request = self._launch_request(max_cost_usd=1, estimated_cost_usd=2)

        with self.assertRaises(BudgetExceededError):
            self.orchestrator.launch(request)

        self.assertEqual(self.audit.events()[-1].event_type, "budget.reject")

    def test_launch_rejects_invalid_token_fail_closed(self) -> None:
        request = self._launch_request(max_cost_usd=10, estimated_cost_usd=2)
        tampered_request = replace(
            request,
            budget_token=replace(request.budget_token, caps=replace(request.budget_token.caps, max_cost_usd=999)),
        )

        with self.assertRaises(TokenInvalidError):
            self.orchestrator.launch(tampered_request)

        self.assertEqual(self.audit.events()[-1].event_type, "token.verify_fail")

    def test_launch_rejects_secret_shaped_env_before_reserving_budget(self) -> None:
        request = replace(
            self._launch_request(max_cost_usd=10, estimated_cost_usd=2),
            env={"SAFE": "password=supersecretvalue"},
            env_allowlist=("SAFE",),
        )

        with self.assertRaises(PolicyDeniedError):
            self.orchestrator.launch(request)

        with self.assertRaises(KeyError):
            self.quota.state(request.budget_token.budget_id)
        self.assertEqual(self.audit.events()[-1].event_type, "env.denied")

    def test_audit_chain_detects_payload_tampering(self) -> None:
        self.audit.append("token.mint", {"token_id": "t1"})
        self.audit.append("quota.reserve", {"budget_id": "b1"})

        self.assertTrue(self.audit.verify_chain().valid)

        self.audit._events[0] = replace(self.audit._events[0], payload={"token_id": "tampered"})

        verification = self.audit.verify_chain()
        self.assertFalse(verification.valid)
        self.assertEqual(verification.break_sequence, 1)

    def _launch_request(self, *, max_cost_usd: float, estimated_cost_usd: float) -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(
                max_compute_units=1_000,
                max_gpu_seconds=120,
                max_wallclock_s=120,
                max_cost_usd=max_cost_usd,
            ),
            job_id="job-1",
            root_request_id="root-1",
        )
        scope = self.tokens.mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(
                egress_allowlist=(EgressRule("store.local", 443, "https"),),
                broker_audiences=("store",),
            ),
        )
        return LaunchRequest(
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
                estimated_cost_usd=estimated_cost_usd,
            ),
        )


class S10DockerSupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docker_bin = shutil.which("docker")
        if cls.docker_bin is None:
            cls._skip_or_fail("docker CLI is unavailable")
        version = subprocess.run(
            [cls.docker_bin, "version", "--format", "{{.Server.Version}}"],
            check=False,
            capture_output=True,
            text=True,
        )
        if version.returncode != 0:
            cls._skip_or_fail(f"docker daemon is unavailable: {version.stderr.strip()}")
        cls.image = cls._resolve_digest_pinned_busybox()

    def setUp(self) -> None:
        self.supervisor = DockerSandboxSupervisor(docker_bin=self.docker_bin)

    def test_launches_digest_pinned_container_with_no_network_route(self) -> None:
        request = self._launch_request(
            entrypoint=("/bin/sh",),
            args=("-c", "cat /proc/net/route; printf '\\nARGUS_UID=%s\\nARGUS_SAFE=%s\\n' \"$(id -u)\" \"$ARGUS_SAFE\""),
            env={"ARGUS_SAFE": "visible", "ARGUS_SECRET": "hidden"},
            env_allowlist=("ARGUS_SAFE",),
            wallclock_s=5,
        )
        handle = self._handle()

        result = self.supervisor.run(
            handle=handle,
            request=request,
            materialized_env=materialize_sandbox_env(request.env, request.env_allowlist),
        )

        self.assertFalse(result.timed_out)
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertIn("ARGUS_UID=65532", result.stdout)
        self.assertIn("ARGUS_SAFE=visible", result.stdout)
        self.assertNotIn("hidden", result.stdout)
        self.assertFalse(_has_default_route(result.stdout), result.stdout)
        self.assertGreater(result.duration_s, 0)
        self.assertGreater(result.budget_usage.wallclock_s, 0)

    def test_timeout_kills_container(self) -> None:
        request = self._launch_request(
            entrypoint=("/bin/sh",),
            args=("-c", "sleep 5"),
            env={},
            env_allowlist=(),
            wallclock_s=1,
        )
        handle = self._handle()
        container_name = f"argus-{handle.sandbox_id.replace('-', '')[:24]}"
        self.addCleanup(
            lambda: subprocess.run(
                [self.docker_bin, "rm", "-f", container_name],
                check=False,
                capture_output=True,
                text=True,
            )
        )

        result = self.supervisor.run(handle=handle, request=request, materialized_env={})

        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)
        self.assertGreaterEqual(result.duration_s, 1)
        self.assertFalse(self._container_exists(container_name))

    def _container_exists(self, container_name: str) -> bool:
        inspect = subprocess.run(
            [self.docker_bin, "container", "inspect", container_name],
            check=False,
            capture_output=True,
            text=True,
        )
        return inspect.returncode == 0

    @classmethod
    def _resolve_digest_pinned_busybox(cls) -> str:
        image = os.environ.get("ARGUS_S10_TEST_IMAGE", "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")
        inspect = subprocess.run(
            [cls.docker_bin, "image", "inspect", image],
            check=False,
            capture_output=True,
            text=True,
        )
        if inspect.returncode != 0:
            pull = subprocess.run(
                [cls.docker_bin, "pull", image],
                check=False,
                capture_output=True,
                text=True,
            )
            if pull.returncode != 0:
                cls._skip_or_fail(f"cannot pull S10 test image {image}: {pull.stderr.strip()}")
        return image

    @classmethod
    def _skip_or_fail(cls, reason: str) -> None:
        if os.environ.get("ARGUS_REQUIRE_DOCKER_TESTS") == "1":
            raise AssertionError(reason)
        raise unittest.SkipTest(reason)

    def _launch_request(
        self,
        *,
        entrypoint: tuple[str, ...],
        args: tuple[str, ...],
        env: dict[str, str],
        env_allowlist: tuple[str, ...],
        wallclock_s: int,
    ) -> LaunchRequest:
        tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)
        budget = tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-1",
            root_request_id="root-1",
        )
        scope = tokens.mint_scope(job_id="job-1", scopes=ScopeGrant())
        return LaunchRequest(
            job_id="job-1",
            subagent_id="subagent-1",
            trace_id="trace-1",
            budget_token=budget,
            scope_token=scope,
            image=self.image,
            entrypoint=entrypoint,
            args=args,
            env=env,
            env_allowlist=env_allowlist,
            requested_envelope=LaunchEnvelope(
                cpu_m=500,
                mem_bytes=64 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=wallclock_s,
                scratch_bytes=1024 * 1024,
                pids=16,
                estimated_cost_usd=0.01,
            ),
        )

    @staticmethod
    def _handle() -> SandboxHandle:
        return SandboxHandle(
            sandbox_id="sandbox-test",
            job_id="job-1",
            runtime_class="docker",
            budget_epoch=1,
            policy_bundle_version="1.0.0",
            state="ADMITTED",
        )


class S10DockerOrchestratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docker_bin = shutil.which("docker")
        if cls.docker_bin is None:
            cls._skip_or_fail("docker CLI is unavailable")
        version = subprocess.run(
            [cls.docker_bin, "version", "--format", "{{.Server.Version}}"],
            check=False,
            capture_output=True,
            text=True,
        )
        if version.returncode != 0:
            cls._skip_or_fail(f"docker daemon is unavailable: {version.stderr.strip()}")
        cls.image = cls._resolve_digest_pinned_busybox()

    def setUp(self) -> None:
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)
        self.quota = InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        self.artifacts = InMemoryArtifactStore()
        self.bundle = PolicyBundle(
            bundle_version="1.0.0",
            egress_allowlist=(),
            resource_ceilings=ResourceCeilings(
                cpu_m=1_000,
                mem_bytes=128 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=10,
                max_cost_usd=1,
            ),
            risk_to_runtime={"standard": "docker"},
            seccomp_profile_hash="blake3:" + "a" * 64,
            signer_key_id="security",
            signature="test-signature",
        )
        self.orchestrator = DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            policy_bundle=self.bundle,
            artifact_store=self.artifacts,
            supervisor=DockerSandboxSupervisor(docker_bin=self.docker_bin),
        )

    def test_admission_launches_real_container_and_records_final_state(self) -> None:
        request = self._launch_request(
            args=("-c", "cat /proc/net/route; printf '\\nARGUS_UID=%s\\nARGUS_SAFE=%s\\n' \"$(id -u)\" \"$ARGUS_SAFE\""),
            env={"ARGUS_SAFE": "visible", "ARGUS_SECRET": "hidden"},
            env_allowlist=("ARGUS_SAFE",),
            wallclock_s=5,
        )

        result = self.orchestrator.launch_and_wait(request)

        self.assertEqual(result.handle.state, "SUCCEEDED", result.stderr)
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertEqual(self.orchestrator.get(result.handle.sandbox_id).state, "SUCCEEDED")
        self.assertIn("ARGUS_UID=65532", result.stdout)
        self.assertIn("ARGUS_SAFE=visible", result.stdout)
        self.assertNotIn("hidden", result.stdout)
        self.assertFalse(_has_default_route(result.stdout), result.stdout)
        provenance_ref = result.handle.launch_provenance_ref or ""
        provenance_record = self.artifacts.get_record(provenance_ref)
        provenance_payload = json.loads(self.artifacts.get_artifact(provenance_ref).decode("utf-8"))
        self.assertEqual(provenance_record.kind, "container")
        self.assertEqual(provenance_payload["exec_environment"]["runtime_class"], "docker")
        self.assertEqual(provenance_payload["exec_environment"]["runtime_user"], "65532:65532")
        self.assertNotIn("seccomp_profile_hash", provenance_payload["exec_environment"])
        self.assertFalse(hasattr(result.handle, "seccomp_profile_hash"))
        self.assertEqual(
            provenance_payload["exec_environment_digest"],
            provenance_record.lineage.environment_digest,
        )
        quota_state = self.quota.state(request.budget_token.budget_id)
        self.assertEqual(quota_state.reserved, BudgetUsage())
        self.assertGreater(quota_state.actual.wallclock_s, 0)
        self.assertEqual(
            [event.event_type for event in self.audit.events()[-5:]],
            ["sandbox.launched", "sandbox.started", "sandbox.exited", "budget.consume", "budget.release"],
        )

    def test_timeout_launch_records_timed_out_state(self) -> None:
        request = self._launch_request(args=("-c", "sleep 5"), env={}, env_allowlist=(), wallclock_s=1)

        result = self.orchestrator.launch_and_wait(request)

        self.assertEqual(result.handle.state, "TIMED_OUT")
        self.assertTrue(result.timed_out)
        self.assertEqual(self.orchestrator.get(result.handle.sandbox_id).state, "TIMED_OUT")
        quota_state = self.quota.state(request.budget_token.budget_id)
        self.assertEqual(quota_state.reserved, BudgetUsage())
        self.assertGreater(quota_state.actual.wallclock_s, 0)
        self.assertEqual(
            [event.event_type for event in self.audit.events()[-5:]],
            ["sandbox.launched", "sandbox.started", "sandbox.timeout", "budget.consume", "budget.release"],
        )

    def test_runtime_budget_exceed_halts_and_releases_reservation(self) -> None:
        over_budget_usage = BudgetUsage(compute_units=11, wallclock_s=11)
        self.orchestrator = DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            policy_bundle=self.bundle,
            supervisor=_FixedUsageSupervisor(over_budget_usage),
            artifact_store=InMemoryArtifactStore(),
        )
        request = self._launch_request(args=("-c", "true"), env={}, env_allowlist=(), wallclock_s=1)

        with self.assertRaises(BudgetExceededError):
            self.orchestrator.launch_and_wait(request)

        quota_state = self.quota.state(request.budget_token.budget_id)
        self.assertTrue(quota_state.halted)
        self.assertEqual(quota_state.reserved, BudgetUsage())
        self.assertEqual(quota_state.actual.wallclock_s, 11)
        self.assertIn("budget.halt", [event.event_type for event in self.audit.events()])
        self.assertEqual(next(iter(self.orchestrator._handles.values())).state, "BUDGET_HALTED")

    @classmethod
    def _resolve_digest_pinned_busybox(cls) -> str:
        image = os.environ.get("ARGUS_S10_TEST_IMAGE", "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")
        inspect = subprocess.run(
            [cls.docker_bin, "image", "inspect", image],
            check=False,
            capture_output=True,
            text=True,
        )
        if inspect.returncode != 0:
            pull = subprocess.run(
                [cls.docker_bin, "pull", image],
                check=False,
                capture_output=True,
                text=True,
            )
            if pull.returncode != 0:
                cls._skip_or_fail(f"cannot pull S10 test image {image}: {pull.stderr.strip()}")
        return image

    @classmethod
    def _skip_or_fail(cls, reason: str) -> None:
        if os.environ.get("ARGUS_REQUIRE_DOCKER_TESTS") == "1":
            raise AssertionError(reason)
        raise unittest.SkipTest(reason)

    def _launch_request(
        self,
        *,
        args: tuple[str, ...],
        env: dict[str, str],
        env_allowlist: tuple[str, ...],
        wallclock_s: int,
    ) -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-1",
            root_request_id="root-1",
        )
        scope = self.tokens.mint_scope(job_id="job-1", scopes=ScopeGrant())
        return LaunchRequest(
            job_id="job-1",
            subagent_id="subagent-1",
            trace_id="trace-1",
            budget_token=budget,
            scope_token=scope,
            image=self.image,
            entrypoint=("/bin/sh",),
            args=args,
            env=env,
            env_allowlist=env_allowlist,
            requested_envelope=LaunchEnvelope(
                cpu_m=500,
                mem_bytes=64 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=wallclock_s,
                scratch_bytes=1024 * 1024,
                pids=16,
                estimated_cost_usd=0.01,
            ),
        )


class S10DockerOrchestratorFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)
        self.quota = InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        self.bundle = PolicyBundle(
            bundle_version="1.0.0",
            egress_allowlist=(),
            resource_ceilings=ResourceCeilings(
                cpu_m=1_000,
                mem_bytes=128 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=10,
                max_cost_usd=1,
            ),
            risk_to_runtime={"standard": "docker"},
            seccomp_profile_hash="blake3:" + "a" * 64,
            signer_key_id="security",
            signature="test-signature",
        )

    def test_docker_orchestrator_requires_artifact_store_for_launch_provenance(self) -> None:
        with self.assertRaisesRegex(PolicyDeniedError, "artifact_store is required"):
            DockerSandboxOrchestrator(
                token_service=self.tokens,
                quota_ledger=self.quota,
                audit_ledger=self.audit,
                policy_bundle=self.bundle,
                supervisor=_RaisingSupervisor(PermissionError("not reached")),
            )

    def test_supervisor_exceptions_release_reserved_quota_and_fail_handle(self) -> None:
        for exc in (
            SandboxRuntimeUnavailableError("docker runtime is unavailable"),
            PermissionError("docker binary is not executable"),
        ):
            with self.subTest(error_type=type(exc).__name__):
                quota = InMemoryQuotaLedger()
                audit = InMemoryAuditLedger()
                orchestrator = DockerSandboxOrchestrator(
                    token_service=self.tokens,
                    quota_ledger=quota,
                    audit_ledger=audit,
                    policy_bundle=self.bundle,
                    artifact_store=InMemoryArtifactStore(),
                    supervisor=_RaisingSupervisor(exc),
                )
                request = self._launch_request()

                with self.assertRaises(type(exc)):
                    orchestrator.launch_and_wait(request)

                quota_state = quota.state(request.budget_token.budget_id)
                self.assertEqual(quota_state.reserved, BudgetUsage())
                self.assertEqual(quota_state.actual, BudgetUsage())
                self.assertEqual(next(iter(orchestrator._handles.values())).state, "FAILED")
                self.assertEqual(
                    [event.event_type for event in audit.events()[-4:]],
                    ["sandbox.launched", "sandbox.started", "budget.release", "sandbox.runtime_failed"],
                )
                self.assertEqual(audit.events()[-1].payload["error_type"], type(exc).__name__)

    def _launch_request(self) -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-1",
            root_request_id="root-1",
        )
        scope = self.tokens.mint_scope(job_id="job-1", scopes=ScopeGrant())
        return LaunchRequest(
            job_id="job-1",
            subagent_id="subagent-1",
            trace_id="trace-1",
            budget_token=budget,
            scope_token=scope,
            image="registry.local/argus@sha256:" + "b" * 64,
            entrypoint=("/bin/sh",),
            args=("-c", "true"),
            env={},
            env_allowlist=(),
            requested_envelope=LaunchEnvelope(
                cpu_m=500,
                mem_bytes=64 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=1,
                scratch_bytes=1024 * 1024,
                pids=16,
                estimated_cost_usd=0.01,
            ),
        )


def _has_default_route(route_table: str) -> bool:
    for line in route_table.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] != "Iface" and fields[1] == "00000000":
            return True
    return False


class _FixedUsageSupervisor:
    def __init__(self, budget_usage: BudgetUsage) -> None:
        self._budget_usage = budget_usage

    def run(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        materialized_env: dict[str, str],
    ) -> SandboxExecutionResult:
        return SandboxExecutionResult(
            handle=handle,
            exit_code=0,
            stdout="",
            stderr="",
            timed_out=False,
            duration_s=self._budget_usage.wallclock_s,
            budget_usage=self._budget_usage,
        )


class _RaisingSupervisor:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def run(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        materialized_env: dict[str, str],
    ) -> SandboxExecutionResult:
        raise self._exc


if __name__ == "__main__":
    unittest.main()
