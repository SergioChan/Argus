from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from argus_core.hashing import hash_bytes
from argus_core.s10 import (
    BudgetCaps,
    BudgetUsage,
    DockerRuntimeLaunchEvidence,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    GvisorRuntimeConfig,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryImageVerifier,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    ResourceCeilings,
    SandboxHandle,
    SandboxExecutionResult,
    SandboxRuntimeUnavailableError,
    ScopeGrant,
    TrustMount,
    materialize_gvisor_pod_spec,
)
from argus_runtime.s10_supervisor_service import (
    _default_policy_bundle,
    _gvisor_runtime_config_from_env,
)


PROFILE = {
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
        {
            "names": ["bpf", "keyctl", "kexec_load", "mount", "ptrace"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
        }
    ],
}
ROOT = Path(__file__).resolve().parents[1]


class S10GvisorRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.profile_path = root / "argus-gvisor-seccomp.json"
        self.profile_path.write_bytes((json.dumps(PROFILE, sort_keys=True, separators=(",", ":")) + "\n").encode())
        self.verifier_path = root / "verifier"
        self.ledger_path = root / "ledger"
        self.verifier_path.mkdir()
        self.ledger_path.mkdir()
        (self.verifier_path / "verify.py").write_text("VERIFIER = 'trusted'\n", encoding="utf-8")
        (self.ledger_path / "ledger.jsonl").write_text('{"sequence":1}\n', encoding="utf-8")
        self.config = GvisorRuntimeConfig(
            docker_runtime="runsc-argus",
            seccomp_profile_path=str(self.profile_path),
            kubernetes_runtime_class="gvisor",
            kubernetes_seccomp_profile="argus/argus-gvisor-seccomp.json",
            trust_mounts=(
                TrustMount(
                    name="verifier-code",
                    source=str(self.verifier_path),
                    target="/opt/argus/trust/verifier",
                ),
                TrustMount(
                    name="provenance-ledger",
                    source=str(self.ledger_path),
                    target="/opt/argus/trust/ledger",
                ),
            ),
        )
        self.tokens = InMemoryTokenService(signing_key=b"gvisor-test-token-key", now_fn=lambda: 1_000)
        self.bundle = PolicyBundle(
            bundle_version="2.0.0",
            egress_allowlist=(),
            resource_ceilings=ResourceCeilings(
                cpu_m=1_000,
                mem_bytes=128 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=10,
                max_cost_usd=1,
            ),
            risk_to_runtime={"standard": "gvisor"},
            seccomp_profile_hash=hash_bytes(self.profile_path.read_bytes()),
            signer_key_id="security",
            signature="test-signature",
        )
        self.request = self._launch_request()
        self.handle = SandboxHandle(
            sandbox_id="sandbox-gvisor-test",
            job_id=self.request.job_id,
            runtime_class="gvisor",
            budget_epoch=1,
            policy_bundle_version=self.bundle.bundle_version,
            state="ADMITTED",
        )

    def test_materializes_gvisor_pod_spec_with_signed_seccomp_and_read_only_trust_mounts(self) -> None:
        pod = materialize_gvisor_pod_spec(
            handle=self.handle,
            request=self.request,
            policy_bundle=self.bundle,
            config=self.config,
        )

        spec = pod["spec"]
        self.assertEqual(spec["runtimeClassName"], "gvisor")
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertFalse(spec["hostUsers"])
        container = spec["containers"][0]
        security = container["securityContext"]
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertEqual(security["capabilities"]["drop"], ["ALL"])
        self.assertEqual(
            security["seccompProfile"],
            {"type": "Localhost", "localhostProfile": "argus/argus-gvisor-seccomp.json"},
        )
        trust_mounts = [mount for mount in container["volumeMounts"] if mount["name"] != "scratch"]
        self.assertEqual({mount["name"] for mount in trust_mounts}, {"verifier-code", "provenance-ledger"})
        self.assertTrue(all(mount["readOnly"] for mount in trust_mounts))
        self.assertEqual(spec["volumes"][-1]["emptyDir"]["sizeLimit"], str(1024 * 1024))
        self.assertEqual(pod["metadata"]["annotations"]["argus.dev/seccomp-profile-hash"], self.bundle.seccomp_profile_hash)

    def test_cli_command_selects_runsc_and_applies_verified_profile_and_mounts(self) -> None:
        supervisor = DockerSandboxSupervisor(docker_bin="/usr/bin/docker", gvisor_config=self.config)
        security_spec = supervisor.materialize_security_spec(self.handle, self.bundle)

        command = supervisor._docker_command("argus-test", self.request, {}, security_spec)

        self.assertIn("--runtime", command)
        self.assertEqual(command[command.index("--runtime") + 1], "runsc-argus")
        seccomp_index = command.index("seccomp=" + str(self.profile_path))
        self.assertEqual(command[seccomp_index - 1], "--security-opt")
        mount_values = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
        self.assertEqual(len(mount_values), 2)
        self.assertTrue(all("readonly" in value for value in mount_values))
        self.assertTrue(all("bind-propagation=rprivate" in value for value in mount_values))

    def test_profile_hash_mismatch_fails_before_docker_is_called(self) -> None:
        supervisor = _CapturingDockerApiSupervisor(self.config)
        tampered_bundle = PolicyBundle(
            **{**self.bundle.__dict__, "seccomp_profile_hash": "blake3:" + "0" * 64}
        )

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "seccomp profile hash mismatch"):
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                policy_bundle=tampered_bundle,
            )

        self.assertEqual(supervisor.calls, [])

    def test_gvisor_config_rejects_runtime_downgrade_and_missing_trust_boundary(self) -> None:
        with self.assertRaisesRegex(ValueError, "identify runsc"):
            GvisorRuntimeConfig(
                docker_runtime="runc",
                seccomp_profile_path=str(self.profile_path),
                kubernetes_runtime_class="gvisor",
                kubernetes_seccomp_profile="argus/profile.json",
                trust_mounts=self.config.trust_mounts,
            )
        with self.assertRaisesRegex(ValueError, "requires verifier-code and provenance-ledger"):
            GvisorRuntimeConfig(
                docker_runtime="runsc-argus",
                seccomp_profile_path=str(self.profile_path),
                kubernetes_runtime_class="gvisor",
                kubernetes_seccomp_profile="argus/profile.json",
                trust_mounts=(self.config.trust_mounts[0],),
            )

    def test_repo_seccomp_profile_denies_complete_tc02_set_with_eperm(self) -> None:
        profile = json.loads(
            (ROOT / "deploy/argus-m0/security/argus-gvisor-seccomp.json").read_text(encoding="utf-8")
        )
        denied = {
            name
            for rule in profile["syscalls"]
            if rule["action"] == "SCMP_ACT_ERRNO" and rule["errnoRet"] == 1
            for name in rule["names"]
        }
        self.assertTrue({"ptrace", "mount", "kexec_load", "bpf", "keyctl"}.issubset(denied))
        self.assertIn("unshare", denied)

    def test_runtime_environment_activates_gvisor_with_profile_hash_from_disk(self) -> None:
        env = {
            "ARGUS_S10_GVISOR_RUNTIME_NAME": "runsc-argus",
            "ARGUS_S10_GVISOR_SECCOMP_PROFILE_PATH": str(self.profile_path),
            "ARGUS_S10_GVISOR_TRUST_MOUNTS_JSON": json.dumps(
                [
                    {"name": mount.name, "source": mount.source, "target": mount.target}
                    for mount in self.config.trust_mounts
                ]
            ),
            "ARGUS_S10_DEFAULT_RUNTIME_CLASS": "gvisor",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _gvisor_runtime_config_from_env()
            bundle = _default_policy_bundle()

        self.assertIsNotNone(config)
        assert config is not None
        self.assertEqual(config.docker_runtime, "runsc-argus")
        self.assertEqual(bundle.risk_to_runtime, {"standard": "gvisor"})
        self.assertEqual(bundle.seccomp_profile_hash, hash_bytes(self.profile_path.read_bytes()))

    def test_docker_api_attests_runsc_profile_and_read_only_mounts(self) -> None:
        supervisor = _CapturingDockerApiSupervisor(self.config)
        evidence: list[DockerRuntimeLaunchEvidence] = []

        result = supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            policy_bundle=self.bundle,
            runtime_evidence_sink=evidence.append,
        )

        self.assertEqual(result.exit_code, 0)
        create = next(call for call in supervisor.calls if call[0] == "POST" and call[1].startswith("/containers/create"))
        host_config = create[2]["HostConfig"]
        self.assertEqual(host_config["Runtime"], "runsc-argus")
        self.assertIn("no-new-privileges", host_config["SecurityOpt"])
        self.assertTrue(any(value.startswith("seccomp={") for value in host_config["SecurityOpt"]))
        self.assertEqual(len(host_config["Mounts"]), 2)
        self.assertTrue(all(mount["ReadOnly"] for mount in host_config["Mounts"]))
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].attestation_source, "docker-api-inspect")
        self.assertEqual(evidence[0].docker_runtime, "runsc-argus")
        self.assertEqual(evidence[0].seccomp_profile_hash, self.bundle.seccomp_profile_hash)
        self.assertEqual({mount.name for mount in evidence[0].trust_mounts}, {"verifier-code", "provenance-ledger"})

    def test_missing_runsc_runtime_fails_closed_before_container_create(self) -> None:
        supervisor = _CapturingDockerApiSupervisor(self.config, runtime_available=False)

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "runsc-argus.*unavailable"):
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                policy_bundle=self.bundle,
            )

        self.assertFalse(any(method == "POST" and path.startswith("/containers/create") for method, path, _ in supervisor.calls))

    def test_orchestrator_records_host_controlled_runtime_security_evidence(self) -> None:
        supervisor = _CapturingDockerApiSupervisor(self.config)
        audit = InMemoryAuditLedger()
        orchestrator = DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=InMemoryQuotaLedger(),
            audit_ledger=audit,
            image_verifier=InMemoryImageVerifier(trusted_images=(self.request.image,)),
            policy_bundle=self.bundle,
            artifact_store=InMemoryArtifactStore(),
            supervisor=supervisor,
        )

        result = orchestrator.launch_and_wait(self.request)

        self.assertEqual(result.handle.runtime_class, "gvisor")
        events = {event.event_type: event.payload for event in audit.events()}
        self.assertEqual(events["runtime.attested"]["docker_runtime"], "runsc-argus")
        self.assertEqual(events["seccomp.profile_applied"]["profile_hash"], self.bundle.seccomp_profile_hash)
        self.assertEqual(events["trust.mounts_applied"]["mount_count"], 2)
        self.assertTrue(events["trust.mounts_applied"]["all_read_only"])

    def test_gvisor_launch_without_host_attestation_fails_closed_and_releases_budget(self) -> None:
        audit = InMemoryAuditLedger()
        quota = InMemoryQuotaLedger()
        orchestrator = DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=quota,
            audit_ledger=audit,
            image_verifier=InMemoryImageVerifier(trusted_images=(self.request.image,)),
            policy_bundle=self.bundle,
            artifact_store=InMemoryArtifactStore(),
            supervisor=_NoAttestationSupervisor(),
        )

        with self.assertRaisesRegex(
            SandboxRuntimeUnavailableError,
            "exactly one host-controlled runtime attestation",
        ):
            orchestrator.launch_and_wait(self.request)

        self.assertEqual(quota.state(self.request.budget_token.budget_id).reserved, BudgetUsage())
        self.assertEqual(next(iter(orchestrator._handles.values())).state, "FAILED")
        self.assertEqual(audit.events()[-1].event_type, "sandbox.runtime_failed")

    def _launch_request(self) -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-gvisor-test",
            root_request_id="root-gvisor-test",
        )
        scope = self.tokens.mint_scope(job_id="job-gvisor-test", scopes=ScopeGrant())
        return LaunchRequest(
            job_id="job-gvisor-test",
            subagent_id="subagent-gvisor-test",
            trace_id="trace-gvisor-test",
            budget_token=budget,
            scope_token=scope,
            image="sha256:" + "b" * 64,
            entrypoint=("/bin/true",),
            args=(),
            env={},
            env_allowlist=(),
            requested_envelope=LaunchEnvelope(
                cpu_m=500,
                mem_bytes=64 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=2,
                scratch_bytes=1024 * 1024,
                pids=16,
                estimated_cost_usd=0.01,
            ),
        )


class _CapturingDockerApiSupervisor(DockerSandboxSupervisor):
    def __init__(self, config: GvisorRuntimeConfig, *, runtime_available: bool = True) -> None:
        super().__init__(docker_bin="/usr/bin/docker", gvisor_config=config)
        self._docker_socket_path = "/tmp/fake-docker.sock"
        self.runtime_available = runtime_available
        self.calls: list[tuple[str, str, dict]] = []
        self.create_payload: dict = {}

    def _docker_api_request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        *,
        expected: tuple[int, ...] = (200,),
        timeout: float = 5,
    ) -> dict:
        del expected, timeout
        body = payload or {}
        self.calls.append((method, path, body))
        if method == "GET" and path == "/info":
            runtimes = {"runc": {}}
            if self.runtime_available:
                runtimes["runsc-argus"] = {"path": "/usr/local/bin/runsc", "args": ["--oci-seccomp"]}
            return {"Runtimes": runtimes}
        if method == "POST" and path.startswith("/containers/create"):
            self.create_payload = body
            return {"Id": "container-gvisor-test"}
        if method == "GET" and path == "/containers/container-gvisor-test/json":
            return {
                "Id": "container-gvisor-test",
                "HostConfig": self.create_payload["HostConfig"],
                "State": {"Running": False, "ExitCode": 0},
            }
        return {}

    def _docker_api_logs(self, container_id: str):  # type: ignore[no-untyped-def]
        del container_id
        from argus_core import s10 as s10_module

        return s10_module._DockerLogCapture(
            stdout="ok\n",
            stderr="",
            stdout_bytes=3,
            stderr_bytes=0,
            log_capture_limit_bytes=s10_module.PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES,
            truncated=False,
        )

    def _docker_api_resource_sample(self, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        raise AssertionError("completed fake container must not be metered")


class _NoAttestationSupervisor(DockerSandboxSupervisor):
    def run(self, *, handle, request, materialized_env):  # type: ignore[no-untyped-def]
        del request, materialized_env
        return SandboxExecutionResult(
            handle=handle,
            exit_code=0,
            stdout="",
            stderr="",
            timed_out=False,
            duration_s=0.1,
            budget_usage=BudgetUsage(wallclock_s=0.1),
        )


if __name__ == "__main__":
    unittest.main()
