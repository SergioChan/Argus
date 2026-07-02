from __future__ import annotations

from dataclasses import asdict, replace
import os
import shutil
import subprocess
import unittest

from argus_core import (
    BudgetCaps,
    BudgetExceededError,
    BudgetUsage,
    DockerSandboxSupervisor,
    EgressProxy,
    EgressRule,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemorySandboxOrchestrator,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyDeniedError,
    ResourceCeilings,
    SandboxHandle,
    ScopeGrant,
    ScopeWideningError,
    TokenInvalidError,
    canonical_json_bytes,
    decide_policy,
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
            args=("-c", "cat /proc/net/route; printf '\\nARGUS_SAFE=%s\\n' \"$ARGUS_SAFE\""),
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

        result = self.supervisor.run(handle=handle, request=request, materialized_env={})

        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)
        self.assertGreaterEqual(result.duration_s, 1)

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
            seccomp_profile_hash="blake3:" + "a" * 64,
            state="ADMITTED",
        )


def _has_default_route(route_table: str) -> bool:
    for line in route_table.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] != "Iface" and fields[1] == "00000000":
            return True
    return False


if __name__ == "__main__":
    unittest.main()
