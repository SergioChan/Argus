from __future__ import annotations

import base64
from dataclasses import asdict
import inspect
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts import run_m0_spine_battery as m0_battery
from argus_core import (
    BudgetCaps,
    BudgetUsage,
    DockerSandboxOrchestrator,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryImageVerifier,
    InMemoryPolicyBundleTrustStore,
    InMemoryPolicyService,
    InMemoryQuotaLedger,
    InMemorySandboxOrchestrator,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyBundleSigner,
    PolicyDeniedError,
    ResourceCeilings,
    SandboxExecutionResult,
    ScopeGrant,
    materialize_sandbox_env,
)


TEST_IMAGE = "registry.local/argus-env@sha256:" + "e" * 64


class _RecordingSupervisor:
    def __init__(self) -> None:
        self.materialized_env: dict[str, str] | None = None
        self.request: LaunchRequest | None = None

    def run(
        self,
        *,
        handle,
        request: LaunchRequest,
        materialized_env: dict[str, str],
        **kwargs,
    ) -> SandboxExecutionResult:
        del kwargs
        self.materialized_env = dict(materialized_env)
        self.request = request
        return SandboxExecutionResult(
            handle=handle,
            exit_code=0,
            stdout="",
            stderr="",
            timed_out=False,
            duration_s=0.01,
            budget_usage=BudgetUsage(wallclock_s=0.01),
        )


class _MutatingImageVerifier(InMemoryImageVerifier):
    def __init__(self, mutate) -> None:
        super().__init__(trusted_images=(TEST_IMAGE,))
        self._mutate = mutate

    def verify(self, image: str):
        self._mutate()
        return super().verify(image)


class S10EnvironmentSanitizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tokens = InMemoryTokenService(signing_key=b"s10-env-token-key")
        self.quota = InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        unsigned_policy = PolicyBundle(
            bundle_version="s10-env-v1",
            egress_allowlist=(),
            resource_ceilings=ResourceCeilings(
                cpu_m=1_000,
                mem_bytes=128 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=30,
                max_cost_usd=10,
            ),
            risk_to_runtime={"standard": "docker"},
            seccomp_profile_hash="blake3:" + "0" * 64,
            signer_key_id="",
            signature="",
        )
        signed_policy = PolicyBundleSigner(
            key_id="s10-env-policy",
            secret=b"s10-env-policy-key",
        ).sign(unsigned_policy)
        self.policy = InMemoryPolicyService(
            initial_bundle=signed_policy,
            trust_store=InMemoryPolicyBundleTrustStore(
                {"s10-env-policy": b"s10-env-policy-key"}
            ),
        )

    def test_materializer_rejects_plain_encoded_and_opaque_secret_shapes(self) -> None:
        openai_secret = "sk-proj-" + "A9" * 20
        encoded_secret = base64.b64encode(
            json.dumps({"api_key": openai_secret}, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        double_encoded_secret = base64.b64encode(encoded_secret.encode("ascii")).decode("ascii")
        hex_encoded_secret = ("api_key=" + openai_secret).encode("utf-8").hex()
        secret_values = (
            "ghp_" + "Ab9" * 14,
            "xoxb-" + "123456789012-" * 2 + "abcdefghijklmnopqrstuvwx",
            "Bearer AbCdEf0123456789+/AbCdEf0123456789+/",
            "https://runtime:correct-horse-battery-staple@vault.internal/v1/secret",
            '{"client_secret":"correct-horse-battery-staple"}',
            "api%5Fkey%3D" + openai_secret,
            encoded_secret,
            double_encoded_secret,
            hex_encoded_secret,
            "ａｐｉ＿ｋｅｙ＝" + openai_secret,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhcmd1cyIsImV4cCI6OTk5OTk5OTk5OX0."
            "fakesignaturebutstillcredentialshaped",
            "aB3dE5gH7jK9mN2pQ4sT6vX8zC1fJ3lR5uW7yZ9aD2eG4iL6",
        )

        for secret in secret_values:
            with self.subTest(secret=secret[:24]):
                with self.assertRaisesRegex(PolicyDeniedError, "secret-shaped") as raised:
                    materialize_sandbox_env({"ARGUS_CONFIG": secret}, ("ARGUS_CONFIG",))
                self.assertNotIn(secret, str(raised.exception))

    def test_materializer_rejects_sensitive_reserved_and_ambiguous_keys(self) -> None:
        rejected = (
            ("AWS_SECRET_ACCESS_KEY", "visible"),
            ("SERVICE_API_TOKEN", "visible"),
            ("LD_PRELOAD", "/tmp/visible.so"),
            ("PYTHONPATH", "/tmp/visible"),
            ("BAD-NAME", "visible"),
            ("1BAD", "visible"),
        )

        for key, value in rejected:
            with self.subTest(key=key):
                with self.assertRaises(PolicyDeniedError):
                    materialize_sandbox_env({key: value}, (key,))

        with self.assertRaises(PolicyDeniedError):
            materialize_sandbox_env({"ARGUS_SAFE": "visible"}, ("ARGUS_SAFE", "ARGUS_SAFE"))
        with self.assertRaises(PolicyDeniedError):
            materialize_sandbox_env({"ARGUS_SAFE": "line-one\nline-two"}, ("ARGUS_SAFE",))

    def test_materializer_enforces_entry_value_and_total_byte_bounds(self) -> None:
        too_many_entries = {f"ARGUS_UNUSED_{index}": "visible" for index in range(129)}
        with self.assertRaises(PolicyDeniedError):
            materialize_sandbox_env(too_many_entries, ())

        with self.assertRaises(PolicyDeniedError):
            materialize_sandbox_env(
                {"ARGUS_VALUE": "a" * (16 * 1024 + 1)},
                ("ARGUS_VALUE",),
            )

        oversized_total = {
            f"ARGUS_CHUNK_{index}": chr(ord("a") + index) * (16 * 1024)
            for index in range(4)
        }
        with self.assertRaises(PolicyDeniedError):
            materialize_sandbox_env(oversized_total, tuple(oversized_total))

    def test_materializer_keeps_bounded_non_secret_values_and_drops_unlisted_secrets(self) -> None:
        unlisted_secret = "ghp_" + "Z9y" * 14
        materialized = materialize_sandbox_env(
            {
                "ARGUS_MODE": "strict",
                "ARGUS_DIGEST": "sha256:" + "a" * 64,
                "ARGUS_CONFIG": '{"timeout_s":5,"mode":"strict"}',
                "UNLISTED_SECRET": unlisted_secret,
            },
            ("ARGUS_MODE", "ARGUS_DIGEST", "ARGUS_CONFIG"),
        )

        self.assertEqual(
            materialized,
            {
                "ARGUS_MODE": "strict",
                "ARGUS_DIGEST": "sha256:" + "a" * 64,
                "ARGUS_CONFIG": '{"timeout_s":5,"mode":"strict"}',
            },
        )
        self.assertNotIn(unlisted_secret, json.dumps(materialized, sort_keys=True))

    def test_rejection_is_pre_quota_pre_handle_and_audit_never_contains_value(self) -> None:
        secret = "ghp_" + "A7z" * 14
        request = self._request(env={"ARGUS_CONFIG": secret}, env_allowlist=("ARGUS_CONFIG",))
        orchestrator = InMemorySandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            image_verifier=InMemoryImageVerifier(trusted_images=(TEST_IMAGE,)),
            policy_service=self.policy,
        )

        with self.assertRaisesRegex(PolicyDeniedError, "environment rejected"):
            orchestrator.launch(request)

        events = self.audit.events()
        self.assertEqual([event.event_type for event in events], ["env.denied"])
        self.assertEqual(events[0].payload["reason_code"], "secret_value")
        self.assertEqual(events[0].payload["env_keys"], ["ARGUS_CONFIG"])
        self.assertNotIn(secret, json.dumps([asdict(event) for event in events], sort_keys=True))
        with self.assertRaises(KeyError):
            self.quota.state(request.budget_token.budget_id)

    def test_admission_freezes_sanitized_env_before_image_verifier_side_effects(self) -> None:
        request = self._request(env={"ARGUS_VISIBLE": "original"}, env_allowlist=("ARGUS_VISIBLE",))
        supervisor = _RecordingSupervisor()
        verifier = _MutatingImageVerifier(
            lambda: request.env.__setitem__("ARGUS_VISIBLE", "changed-after-sanitization")
        )
        orchestrator = DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            image_verifier=verifier,
            policy_service=self.policy,
            artifact_store=InMemoryArtifactStore(),
            supervisor=supervisor,  # type: ignore[arg-type]
        )

        result = orchestrator.launch_and_wait(request)

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(request.env["ARGUS_VISIBLE"], "changed-after-sanitization")
        self.assertEqual(supervisor.materialized_env, {"ARGUS_VISIBLE": "original"})
        self.assertIsNot(supervisor.request, request)
        self.assertEqual(supervisor.request.env, {"ARGUS_VISIBLE": "original"})

    def _request(
        self,
        *,
        env: dict[str, str],
        env_allowlist: tuple[str, ...],
    ) -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(
                max_compute_units=30,
                max_wallclock_s=30,
                max_cost_usd=10,
            ),
            job_id="s10-env-job",
            root_request_id="s10-env-root",
        )
        scope = self.tokens.mint_scope(
            job_id="s10-env-job",
            scopes=ScopeGrant(sandbox_risk_class="standard"),
        )
        return LaunchRequest(
            job_id="s10-env-job",
            subagent_id="s10-env-subagent",
            trace_id="trace-s10-env",
            budget_token=budget,
            scope_token=scope,
            image=TEST_IMAGE,
            entrypoint=("sh",),
            args=("-c", "true"),
            env=env,
            env_allowlist=env_allowlist,
            requested_envelope=LaunchEnvelope(
                cpu_m=100,
                mem_bytes=32 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=5,
                scratch_bytes=1024 * 1024,
                pids=16,
                estimated_cost_usd=0,
            ),
        )


class S10SecretFreeArchiveScannerTests(unittest.TestCase):
    def test_scanner_walks_nested_image_layers_and_reports_only_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "image.tar"
            layer = self._tar_bytes({"etc/config.txt": b"mode=strict\n"})
            self._write_tar(archive, {"manifest.json": b"[]", "layer.tar": layer})

            report = m0_battery._scan_secret_free_tar(
                archive,
                forbidden_values=("runtime-secret-sentinel",),
            )

        self.assertEqual(report["archive_count"], 2)
        self.assertEqual(report["file_count"], 2)
        self.assertGreater(report["scanned_bytes"], 0)
        self.assertEqual(report["secret_matches"], 0)
        self.assertNotIn("runtime-secret-sentinel", json.dumps(report, sort_keys=True))

    def test_scanner_rejects_exact_and_pattern_secrets_without_echoing_them(self) -> None:
        forbidden = "runtime-secret-sentinel"
        fixtures = (
            forbidden.encode("utf-8"),
            ("ghp_" + "A7z" * 14).encode("utf-8"),
            b"-----BEGIN PRIVATE KEY-----\nnot-real\n",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture[:20]):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive = Path(temp_dir) / "filesystem.tar"
                    self._write_tar(archive, {"opt/app/config.bin": fixture})
                    with self.assertRaisesRegex(AssertionError, "secret material detected") as raised:
                        m0_battery._scan_secret_free_tar(
                            archive,
                            forbidden_values=(forbidden,),
                        )
                self.assertNotIn(forbidden, str(raised.exception))
                self.assertNotIn(fixture.decode("utf-8", errors="ignore"), str(raised.exception))

    def test_scanner_rejects_secret_material_in_archive_metadata(self) -> None:
        forbidden = "runtime-secret-sentinel"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "filesystem.tar"
            self._write_tar(
                archive,
                {f"opt/{forbidden}/config.txt": b"mode=strict\n"},
            )

            with self.assertRaisesRegex(AssertionError, "secret material detected") as raised:
                m0_battery._scan_secret_free_tar(
                    archive,
                    forbidden_values=(forbidden,),
                )

        self.assertNotIn(forbidden, str(raised.exception))

    @staticmethod
    def _tar_bytes(files: dict[str, bytes]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, payload in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        return output.getvalue()

    @classmethod
    def _write_tar(cls, path: Path, files: dict[str, bytes]) -> None:
        path.write_bytes(cls._tar_bytes(files))


class S10EnvironmentBatteryWiringTests(unittest.TestCase):
    def test_m0_battery_mints_a_bounded_identity_and_calls_tc05_tc36(self) -> None:
        identity = m0_battery._m0_identity_requests()["env-sanitization"]

        self.assertEqual(identity["job_id"], "s10-t21-env-job")
        self.assertEqual(identity["scopes"], {"sandbox_risk_class": "standard"})
        self.assertEqual(identity["budget_caps"]["max_compute_units"], 20)
        self.assertIn(
            "_battery_s10_env_sanitization(",
            inspect.getsource(m0_battery.main),
        )


if __name__ == "__main__":
    unittest.main()
