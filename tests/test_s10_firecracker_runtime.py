from __future__ import annotations

import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from argus_core.hashing import hash_bytes
from argus_core.s10 import (
    BudgetCaps,
    BudgetUsage,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    FirecrackerRuntimeConfig,
    FirecrackerRuntimeLaunchEvidence,
    FirecrackerSandboxSupervisor,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyDeniedError,
    ResourceCeilings,
    SandboxExecutionResult,
    SandboxHandle,
    SandboxRuntimeUnavailableError,
    ScopeGrant,
    materialize_firecracker_pod_spec,
    materialize_firecracker_vm_spec,
)
from argus_runtime.s10_supervisor_service import (
    _docker_supervisor_from_env,
    _firecracker_runtime_config_from_env,
)


class S10FirecrackerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.firecracker_bin = root / "firecracker"
        self.jailer_bin = root / "jailer"
        self.kernel_path = root / "vmlinux"
        self.rootfs_path = root / "argus-rootfs.ext4"
        self.chroot_base = root / "jailer-root"
        self.firecracker_bin.write_bytes(b"firecracker-v1.15.1")
        self.jailer_bin.write_bytes(b"jailer-v1.15.1")
        self.kernel_path.write_bytes(b"argus-firecracker-kernel")
        self.rootfs_path.write_bytes(b"argus-firecracker-rootfs")
        self.chroot_base.mkdir()
        self.image_ref = "registry.example/argus-firecracker@sha256:" + "a" * 64
        self.config = FirecrackerRuntimeConfig(
            expected_version="1.15.1",
            kubernetes_runtime_class="firecracker",
            firecracker_bin=str(self.firecracker_bin),
            jailer_bin=str(self.jailer_bin),
            kernel_image_path=str(self.kernel_path),
            kernel_image_hash=hash_bytes(self.kernel_path.read_bytes()),
            rootfs_image_path=str(self.rootfs_path),
            rootfs_image_hash=hash_bytes(self.rootfs_path.read_bytes()),
            rootfs_image_ref=self.image_ref,
            chroot_base_dir=str(self.chroot_base),
            jailer_uid=65532,
            jailer_gid=65532,
        )
        self.tokens = InMemoryTokenService(signing_key=b"firecracker-test-token-key", now_fn=lambda: 1_000)
        self.bundle = PolicyBundle(
            bundle_version="2.1.0",
            egress_allowlist=(),
            resource_ceilings=ResourceCeilings(
                cpu_m=2_000,
                mem_bytes=256 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=10,
                max_cost_usd=1,
            ),
            risk_to_runtime={"standard": "gvisor", "federated": "firecracker"},
            seccomp_profile_hash="blake3:" + "0" * 64,
            signer_key_id="security",
            signature="test-signature",
        )
        self.request = self._launch_request()
        self.handle = SandboxHandle(
            sandbox_id="sandbox-firecracker-test",
            job_id=self.request.job_id,
            runtime_class="firecracker",
            budget_epoch=1,
            policy_bundle_version=self.bundle.bundle_version,
            state="ADMITTED",
        )

    def test_materializes_jailer_microvm_spec_with_no_network_and_read_only_rootfs(self) -> None:
        spec = materialize_firecracker_vm_spec(
            handle=self.handle,
            request=self.request,
            policy_bundle=self.bundle,
            config=self.config,
        )

        self.assertEqual(spec["runtime_class"], "firecracker")
        self.assertEqual(spec["microvm_id"], self.handle.sandbox_id)
        self.assertEqual(spec["jailer"]["uid"], 65532)
        self.assertEqual(spec["jailer"]["gid"], 65532)
        self.assertEqual(spec["jailer"]["cgroup_version"], 2)
        self.assertTrue(spec["jailer"]["new_pid_namespace"])
        self.assertEqual(spec["jailer"]["resource_limits"]["memory.max"], 128 * 1024 * 1024)
        self.assertEqual(spec["machine_config"]["mem_size_mib"], 64)
        self.assertEqual(spec["network_interfaces"], [])
        self.assertTrue(spec["drives"][0]["is_root_device"])
        self.assertTrue(spec["drives"][0]["is_read_only"])
        self.assertTrue(spec["drives"][1]["is_read_only"])
        self.assertFalse(spec["drives"][2]["is_read_only"])
        self.assertEqual(spec["drives"][2]["size_limit_bytes"], 1024 * 1024)
        self.assertEqual(spec["kernel_image_hash"], self.config.kernel_image_hash)
        self.assertEqual(spec["rootfs_image_hash"], self.config.rootfs_image_hash)
        self.assertEqual(spec["risk_class"], "federated")
        self.assertEqual(spec["trust_class"], "federated")
        self.assertFalse(spec["federated_extra_access"])

    def test_rejects_memory_envelope_without_vmm_headroom(self) -> None:
        request = LaunchRequest(
            **{
                **self.request.__dict__,
                "requested_envelope": LaunchEnvelope(
                    **{
                        **self.request.requested_envelope.__dict__,
                        "mem_bytes": 127 * 1024 * 1024,
                    }
                ),
            }
        )

        with self.assertRaisesRegex(PolicyDeniedError, "at least 134217728 bytes"):
            materialize_firecracker_vm_spec(
                handle=self.handle,
                request=request,
                policy_bundle=self.bundle,
                config=self.config,
            )

    def test_rejects_scratch_smaller_than_a_mountable_ext4_drive(self) -> None:
        request = LaunchRequest(
            **{
                **self.request.__dict__,
                "requested_envelope": LaunchEnvelope(
                    **{
                        **self.request.requested_envelope.__dict__,
                        "scratch_bytes": (1024 * 1024) - 1,
                    }
                ),
            }
        )

        with self.assertRaisesRegex(PolicyDeniedError, "scratch_bytes must be at least 1048576"):
            materialize_firecracker_vm_spec(
                handle=self.handle,
                request=request,
                policy_bundle=self.bundle,
                config=self.config,
            )

    def test_materializes_firecracker_pod_spec_without_federated_privilege_elevation(self) -> None:
        pod = materialize_firecracker_pod_spec(
            handle=self.handle,
            request=self.request,
            policy_bundle=self.bundle,
            config=self.config,
        )

        self.assertEqual(pod["apiVersion"], "v1")
        self.assertEqual(pod["kind"], "Pod")
        self.assertEqual(pod["metadata"]["annotations"]["argus.dev/risk-class"], "federated")
        self.assertEqual(
            pod["metadata"]["annotations"]["argus.dev/firecracker-kernel-hash"],
            self.config.kernel_image_hash,
        )
        spec = pod["spec"]
        self.assertEqual(spec["runtimeClassName"], "firecracker")
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertFalse(spec["hostNetwork"])
        self.assertFalse(spec["hostPID"])
        self.assertFalse(spec["hostIPC"])
        self.assertFalse(spec["hostUsers"])
        self.assertNotIn("serviceAccountName", spec)
        self.assertEqual(spec["dnsPolicy"], "None")
        self.assertEqual(spec["dnsConfig"]["nameservers"], ["127.0.0.1"])
        container = spec["containers"][0]
        security = container["securityContext"]
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertTrue(security["runAsNonRoot"])
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertFalse(security["privileged"])
        self.assertEqual(security["capabilities"]["drop"], ["ALL"])
        self.assertEqual(security["seccompProfile"], {"type": "RuntimeDefault"})
        self.assertEqual(
            container["volumeMounts"],
            [{"name": "scratch", "mountPath": "/tmp", "readOnly": False}],
        )
        self.assertEqual(
            spec["volumes"],
            [{"name": "scratch", "emptyDir": {"sizeLimit": str(1024 * 1024)}}],
        )

    def test_config_hash_or_image_mismatch_fails_before_jailer_launch(self) -> None:
        supervisor = FirecrackerSandboxSupervisor(config=self.config)
        tampered_config = FirecrackerRuntimeConfig(
            **{**self.config.__dict__, "kernel_image_hash": "blake3:" + "f" * 64}
        )

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "kernel image hash mismatch"):
            materialize_firecracker_vm_spec(
                handle=self.handle,
                request=self.request,
                policy_bundle=self.bundle,
                config=tampered_config,
            )
        wrong_image_request = LaunchRequest(
            **{**self.request.__dict__, "image": "registry.example/wrong@sha256:" + "b" * 64}
        )
        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "rootfs image reference mismatch"):
            supervisor.materialize_vm_spec(
                handle=self.handle,
                request=wrong_image_request,
                policy_bundle=self.bundle,
            )

    def test_environment_configuration_is_all_or_nothing(self) -> None:
        env = {
            "ARGUS_S10_FIRECRACKER_VERSION": "1.15.1",
            "ARGUS_S10_FIRECRACKER_KUBERNETES_RUNTIME_CLASS": "firecracker",
            "ARGUS_S10_FIRECRACKER_BIN": str(self.firecracker_bin),
            "ARGUS_S10_FIRECRACKER_JAILER_BIN": str(self.jailer_bin),
            "ARGUS_S10_FIRECRACKER_KERNEL_PATH": str(self.kernel_path),
            "ARGUS_S10_FIRECRACKER_KERNEL_HASH": self.config.kernel_image_hash,
            "ARGUS_S10_FIRECRACKER_ROOTFS_PATH": str(self.rootfs_path),
            "ARGUS_S10_FIRECRACKER_ROOTFS_HASH": self.config.rootfs_image_hash,
            "ARGUS_S10_FIRECRACKER_ROOTFS_IMAGE_REF": self.image_ref,
            "ARGUS_S10_FIRECRACKER_CHROOT_BASE": str(self.chroot_base),
            "ARGUS_S10_FIRECRACKER_JAILER_UID": "65532",
            "ARGUS_S10_FIRECRACKER_JAILER_GID": "65532",
        }
        with patch.dict(os.environ, env, clear=True):
            config = _firecracker_runtime_config_from_env()

        self.assertIsNotNone(config)
        assert config is not None
        self.assertEqual(config.rootfs_image_ref, self.image_ref)
        self.assertEqual(config.expected_version, "1.15.1")
        self.assertEqual(config.kubernetes_runtime_class, "firecracker")
        self.assertEqual(config.kernel_image_hash, hash_bytes(self.kernel_path.read_bytes()))

        incomplete = dict(env)
        incomplete.pop("ARGUS_S10_FIRECRACKER_ROOTFS_HASH")
        with patch.dict(os.environ, incomplete, clear=True):
            with self.assertRaisesRegex(RuntimeError, "must be configured together"):
                _firecracker_runtime_config_from_env()

        with patch.dict(os.environ, env, clear=True):
            facade = _docker_supervisor_from_env()
        self.assertTrue(facade.firecracker_configured)
        self.assertEqual(facade.firecracker_version, "1.15.1")
        self.assertEqual(facade.firecracker_resource_meter_kind, "firecracker-host-cgroup-v2")

    def test_runtime_versions_must_match_the_exact_operator_pin(self) -> None:
        self.firecracker_bin.write_text("#!/bin/sh\necho 'Firecracker v1.15.1'\n", encoding="utf-8")
        self.jailer_bin.write_text("#!/bin/sh\necho 'Jailer v1.14.0'\n", encoding="utf-8")
        self.firecracker_bin.chmod(0o755)
        self.jailer_bin.chmod(0o755)
        supervisor = FirecrackerSandboxSupervisor(config=self.config)

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "jailer version mismatch"):
            supervisor.verify_runtime_versions()

    def test_jailer_command_enforces_cgroup_pid_namespace_and_default_seccomp(self) -> None:
        supervisor = FirecrackerSandboxSupervisor(config=self.config)
        spec = supervisor.materialize_vm_spec(
            handle=self.handle,
            request=self.request,
            policy_bundle=self.bundle,
        )

        command = supervisor.jailer_command(spec)

        self.assertIn("--new-pid-ns", command)
        self.assertIn("--daemonize", command)
        self.assertIn("--cgroup-version", command)
        self.assertIn("memory.max=134217728", command)
        self.assertIn("pids.max=16", command)
        self.assertIn("cpu.max=100000 100000", command)
        self.assertEqual(command[-3:], ["--", "--api-sock", "/run/firecracker.socket"])
        self.assertNotIn("--no-seccomp", command)
        self.assertNotIn("--seccomp-filter", command)
        self.assertNotIn("--seccomp-level", command)

    def test_firecracker_api_attestation_rejects_network_or_drive_drift(self) -> None:
        supervisor = FirecrackerSandboxSupervisor(config=self.config)
        spec = supervisor.materialize_vm_spec(
            handle=self.handle,
            request=self.request,
            policy_bundle=self.bundle,
        )
        expected = supervisor.expected_api_configuration(spec)
        observed = {
            **expected,
            "network-interfaces": [
                {"iface_id": "unexpected", "host_dev_name": "tap0"},
            ],
        }

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "network interface"):
            supervisor.verify_api_attestation(spec=spec, observed=observed)

        observed = {
            **expected,
            "drives": [
                {**drive, "is_read_only": False} if drive["drive_id"] == "argus-input" else drive
                for drive in expected["drives"]
            ],
        }
        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "drive configuration"):
            supervisor.verify_api_attestation(spec=spec, observed=observed)

    def test_jailer_readiness_timeout_terminates_the_verified_microvm_process(self) -> None:
        supervisor = FirecrackerSandboxSupervisor(config=self.config)
        microvm_id = "sandbox-readiness-timeout"
        jail_root = supervisor._jail_root(microvm_id)
        jail_root.mkdir(parents=True)
        (jail_root / "firecracker.pid").write_text("1234\n", encoding="utf-8")
        identity = object()

        with (
            patch.object(supervisor, "_verify_microvm_process", return_value=identity),
            patch.object(supervisor, "_process_identity_is_alive", return_value=True),
            patch.object(supervisor, "_signal_microvm") as signal_microvm,
            patch.object(supervisor, "_wait_for_process_exit", return_value=True) as wait_for_exit,
        ):
            with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "did not become ready"):
                supervisor._wait_for_jailer_ready(microvm_id, timeout_s=0.01)

        signal_microvm.assert_called_once_with(identity, signal.SIGKILL)
        wait_for_exit.assert_called_once_with(identity, timeout_s=2.0)

    def test_process_attestation_requires_jailer_identity_namespace_cgroup_and_seccomp(self) -> None:
        supervisor = FirecrackerSandboxSupervisor(config=self.config)
        microvm_id = "sandbox-proc-attestation"
        command = (
            f"/firecracker\0--id\0{microvm_id}\0--api-sock\0/run/firecracker.socket\0"
        ).encode("utf-8")
        with (
            patch.object(Path, "read_bytes", return_value=command),
            patch.object(supervisor, "_proc_start_time_ticks", return_value=99),
            patch.object(supervisor, "_proc_status", return_value={"NSpid": "4321 1"}),
            patch.object(
                supervisor,
                "_proc_cgroup_v2_path",
                return_value=f"/argus-firecracker/{microvm_id}",
            ),
        ):
            identity = supervisor._verify_microvm_process(4321, microvm_id)

        self.assertEqual(identity.pid_namespace_ids, (4321, 1))
        self.assertEqual(identity.cgroup_v2_path, f"/argus-firecracker/{microvm_id}")
        with (
            patch.object(supervisor, "_process_identity_is_alive", return_value=True),
            patch.object(
                supervisor,
                "_proc_status",
                return_value={"Seccomp": "2", "Seccomp_filters": "3"},
            ),
        ):
            self.assertEqual(supervisor._wait_for_process_seccomp(identity, timeout_s=0.1), 3)

        disabled_command = command.replace(
            b"--api-sock\0",
            b"--no-seccomp\0--api-sock\0",
        )
        with (
            patch.object(Path, "read_bytes", return_value=disabled_command),
            patch.object(supervisor, "_proc_start_time_ticks", return_value=99),
            patch.object(supervisor, "_proc_status", return_value={"NSpid": "4321 1"}),
            patch.object(
                supervisor,
                "_proc_cgroup_v2_path",
                return_value=f"/argus-firecracker/{microvm_id}",
            ),
        ):
            with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "disabled or replaced"):
                supervisor._verify_microvm_process(4321, microvm_id)

        wrong_binary = command.replace(b"/firecracker\0", b"/not-firecracker\0")
        with (
            patch.object(Path, "read_bytes", return_value=wrong_binary),
            patch.object(supervisor, "_proc_start_time_ticks", return_value=99),
            patch.object(supervisor, "_proc_status", return_value={"NSpid": "4321 1"}),
            patch.object(
                supervisor,
                "_proc_cgroup_v2_path",
                return_value=f"/argus-firecracker/{microvm_id}",
            ),
        ):
            with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "identity does not match"):
                supervisor._verify_microvm_process(4321, microvm_id)

    def test_docker_supervisor_delegates_firecracker_before_docker(self) -> None:
        firecracker = _DelegatedFirecrackerSupervisor()
        supervisor = DockerSandboxSupervisor(
            docker_bin="definitely-not-a-docker-binary",
            firecracker_supervisor=firecracker,
        )

        result = supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            policy_bundle=self.bundle,
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(firecracker.calls, 1)

    def test_firecracker_rejects_materialized_environment_drift_before_host_launch(self) -> None:
        supervisor = FirecrackerSandboxSupervisor(config=self.config)

        with self.assertRaisesRegex(PolicyDeniedError, "materialized environment differs"):
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={"UNAUTHORIZED": "value"},
                policy_bundle=self.bundle,
            )

    def test_guest_entrypoint_quotes_arguments_and_leaves_reboot_to_guest_init(self) -> None:
        request = LaunchRequest(
            **{
                **self.request.__dict__,
                "entrypoint": ("/bin/echo",),
                "args": ("$(touch /tmp/not-executed)",),
            }
        )

        script = FirecrackerSandboxSupervisor._guest_entrypoint_script(request, {"SAFE": "a b"})

        self.assertIn("export SAFE='a b'", script)
        self.assertIn("/bin/echo '$(touch /tmp/not-executed)'", script)
        self.assertNotIn("reboot", script)
        self.assertNotIn("ARGUS_FIRECRACKER_EXIT_CODE", script)

    def test_orchestrator_records_one_host_controlled_microvm_attestation(self) -> None:
        audit = InMemoryAuditLedger()
        orchestrator = DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=InMemoryQuotaLedger(),
            audit_ledger=audit,
            policy_bundle=self.bundle,
            artifact_store=InMemoryArtifactStore(),
            supervisor=_AttestedFirecrackerSupervisor(self.config),
        )

        result = orchestrator.launch_and_wait(self.request)

        self.assertEqual(result.handle.runtime_class, "firecracker")
        events = {event.event_type: event.payload for event in audit.events()}
        self.assertEqual(events["runtime.attested"]["runtime_class"], "firecracker")
        self.assertEqual(events["runtime.attested"]["microvm_id"], result.handle.sandbox_id)
        self.assertEqual(events["microvm.security_applied"]["network_interface_count"], 0)
        self.assertTrue(events["microvm.security_applied"]["read_only_rootfs"])
        self.assertTrue(events["microvm.security_applied"]["pid_namespace_init"])
        self.assertEqual(
            events["microvm.security_applied"]["cgroup_v2_path"],
            f"/argus-firecracker/{result.handle.sandbox_id}",
        )
        self.assertTrue(events["microvm.security_applied"]["seccomp_enabled"])
        self.assertEqual(events["microvm.security_applied"]["seccomp_filter_count"], 1)
        self.assertEqual(
            events["microvm.security_applied"]["seccomp_filter_mode"],
            "default-built-in",
        )
        self.assertFalse(events["trust.boundary_applied"]["federated_extra_access"])
        self.assertEqual(events["trust.boundary_applied"]["trust_mount_count"], 0)

    def test_firecracker_launch_without_attestation_fails_and_releases_budget(self) -> None:
        audit = InMemoryAuditLedger()
        quota = InMemoryQuotaLedger()
        orchestrator = DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=quota,
            audit_ledger=audit,
            policy_bundle=self.bundle,
            artifact_store=InMemoryArtifactStore(),
            supervisor=_NoAttestationFirecrackerSupervisor(),
        )

        with self.assertRaisesRegex(
            SandboxRuntimeUnavailableError,
            "Firecracker launch requires exactly one host-controlled runtime attestation",
        ):
            orchestrator.launch_and_wait(self.request)

        self.assertEqual(quota.state(self.request.budget_token.budget_id).reserved, BudgetUsage())
        self.assertEqual(next(iter(orchestrator._handles.values())).state, "FAILED")
        self.assertEqual(audit.events()[-1].event_type, "sandbox.runtime_failed")

    def _launch_request(self) -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=20, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-firecracker-test",
            root_request_id="root-firecracker-test",
            risk_class="federated",
        )
        scope = self.tokens.mint_scope(
            job_id="job-firecracker-test",
            scopes=ScopeGrant(sandbox_risk_class="federated"),
        )
        return LaunchRequest(
            job_id="job-firecracker-test",
            subagent_id="subagent-firecracker-test",
            trace_id="trace-firecracker-test",
            budget_token=budget,
            scope_token=scope,
            image=self.image_ref,
            entrypoint=("/usr/local/bin/argus-federated-probe",),
            args=(),
            env={},
            env_allowlist=(),
            requested_envelope=LaunchEnvelope(
                cpu_m=1_000,
                mem_bytes=128 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=2,
                scratch_bytes=1024 * 1024,
                pids=16,
                estimated_cost_usd=0.01,
            ),
        )


class _AttestedFirecrackerSupervisor:
    def __init__(self, config: FirecrackerRuntimeConfig) -> None:
        self.config = config

    def run(self, *, handle, request, materialized_env, policy_bundle, runtime_evidence_sink, **kwargs):  # type: ignore[no-untyped-def]
        del materialized_env, kwargs
        runtime_evidence_sink(
            FirecrackerRuntimeLaunchEvidence(
                sandbox_id=handle.sandbox_id,
                microvm_id=handle.sandbox_id,
                runtime_class="firecracker",
                firecracker_version="1.15.1",
                jailer_version="1.15.1",
                kernel_image_hash=self.config.kernel_image_hash,
                rootfs_image_hash=self.config.rootfs_image_hash,
                request_drive_hash="blake3:" + "c" * 64,
                scratch_bytes=request.requested_envelope.scratch_bytes,
                network_interface_count=0,
                jailer_uid=self.config.jailer_uid,
                jailer_gid=self.config.jailer_gid,
                pid_namespace_init=True,
                cgroup_v2_path=f"/argus-firecracker/{handle.sandbox_id}",
                seccomp_enabled=True,
                seccomp_filter_mode="default-built-in",
                seccomp_filter_count=1,
                read_only_rootfs=True,
                federated_extra_access=False,
                trust_mount_count=0,
                attestation_source="firecracker-api+jailer-pid",
            )
        )
        self.assert_policy_bundle = policy_bundle
        return SandboxExecutionResult(
            handle=handle,
            exit_code=0,
            stdout="ARGUS_FIRECRACKER_PROBE_PASS\n",
            stderr="",
            timed_out=False,
            duration_s=0.1,
            budget_usage=BudgetUsage(wallclock_s=0.1),
        )


class _NoAttestationFirecrackerSupervisor:
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


class _DelegatedFirecrackerSupervisor:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, *, handle, request, materialized_env, **kwargs):  # type: ignore[no-untyped-def]
        del request, materialized_env, kwargs
        self.calls += 1
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
