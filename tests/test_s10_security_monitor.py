from __future__ import annotations

import copy
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from argus_core import (
    BudgetCaps,
    BudgetUsage,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    FirecrackerRuntimeLaunchEvidence,
    FirecrackerSandboxSupervisor,
    HostSecurityEvent,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryPolicyBundleTrustStore,
    InMemoryPolicyService,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyBundleSigner,
    ResourceCeilings,
    SandboxExecutionResult,
    SandboxHandle,
    SandboxPartialResult,
    ScopeGrant,
    SecurityMonitorError,
    SecurityMonitorPoll,
    SecurityMonitorRegistration,
    hash_bytes,
    hash_json,
)
from argus_core.s10 import _FirecrackerJailResources, _FirecrackerProcessIdentity
from argus_runtime.s10_security_monitor_client import HttpSecurityMonitorClient


CONTAINER_ID = "a" * 64
TC21_CONTAINER_DIGEST = "sha256:" + "b" * 64
ROOT = Path(__file__).resolve().parents[1]


def _security_event(
    *,
    event_id: str | None = None,
    kind: str = "trustwrite",
    sandbox_id: str = "sandbox-security-1",
    job_id: str = "job-security-1",
    sequence: int = 1,
    isolation_class: str = "docker",
    engine: str = "falco-modern-ebpf",
) -> HostSecurityEvent:
    return HostSecurityEvent(
        event_id=event_id or "",
        sequence=sequence,
        kind=kind,
        severity="Sev-1",
        engine=engine,
        rule=(
            "Argus trust path write attempt"
            if kind == "trustwrite"
            else "Argus sandbox escape indicator"
        ),
        observed_at="2026-07-15T00:00:00Z",
        sandbox_id=sandbox_id,
        job_id=job_id,
        isolation_class=isolation_class,
        runtime_kind="container",
        container_id=CONTAINER_ID,
        process_id=4242,
        syscall="openat" if kind == "trustwrite" else "unshare",
        result=-30 if kind == "trustwrite" else -1,
        path="/opt/argus/trust/verifier/profile.json" if kind == "trustwrite" else None,
    )


def _host_security_event(
    *,
    sandbox_id: str = "sandbox-firecracker-security-1",
    job_id: str = "job-security-1",
) -> HostSecurityEvent:
    return HostSecurityEvent(
        event_id="",
        sequence=1,
        kind="escape",
        severity="Sev-1",
        engine="falco-modern-ebpf",
        rule="Argus sandbox escape indicator",
        observed_at="2026-07-15T00:00:00Z",
        sandbox_id=sandbox_id,
        job_id=job_id,
        isolation_class="firecracker",
        runtime_kind="host_process",
        container_id=None,
        process_id=9013,
        syscall="unshare",
        result=-1,
    )


class SecurityMonitorWireContractTests(unittest.TestCase):
    def test_container_registration_requires_full_id_and_absolute_unique_trust_paths(self) -> None:
        registration = SecurityMonitorRegistration(
            sandbox_id="sandbox-security-1",
            job_id="job-security-1",
            isolation_class="docker",
            runtime_kind="container",
            container_id=CONTAINER_ID,
            trust_paths=("/opt/argus/trust/ledger", "/opt/argus/trust/verifier"),
        )

        self.assertEqual(registration.container_id, CONTAINER_ID)
        self.assertEqual(
            registration.trust_paths,
            ("/opt/argus/trust/ledger", "/opt/argus/trust/verifier"),
        )
        with self.assertRaises(ValueError):
            SecurityMonitorRegistration(
                sandbox_id="sandbox-security-1",
                job_id="job-security-1",
                isolation_class="docker",
                runtime_kind="container",
                container_id="short-id",
                trust_paths=("relative/path",),
            )
        with self.assertRaises(ValueError):
            SecurityMonitorRegistration(
                sandbox_id="sandbox-security-1",
                job_id="job-security-1",
                isolation_class="docker",
                runtime_kind="container",
                container_id=CONTAINER_ID,
                trust_paths=("/opt/argus/trust", "/opt/argus/trust"),
            )

    def test_host_process_registration_binds_pid_and_cgroup_without_container_identity(self) -> None:
        registration = SecurityMonitorRegistration(
            sandbox_id="sandbox-firecracker-1",
            job_id="job-firecracker-1",
            isolation_class="firecracker",
            runtime_kind="host_process",
            process_id=9012,
            cgroup_v2_path="/argus-firecracker/sandbox-firecracker-1",
        )

        self.assertIsNone(registration.container_id)
        self.assertEqual(registration.process_id, 9012)
        with self.assertRaises(ValueError):
            SecurityMonitorRegistration(
                sandbox_id="sandbox-firecracker-1",
                job_id="job-firecracker-1",
                isolation_class="firecracker",
                runtime_kind="host_process",
                process_id=0,
                cgroup_v2_path="/",
            )
        with self.assertRaises(ValueError):
            SecurityMonitorRegistration(
                sandbox_id="sandbox-firecracker-1",
                job_id="job-firecracker-1",
                isolation_class="firecracker",
                runtime_kind="host_process",
                process_id=9012,
                cgroup_v2_path="/argus-firecracker/sandbox-other",
            )

    def test_isolation_class_selects_exact_sensor_and_rejects_cross_runtime_pairing(self) -> None:
        gvisor = SecurityMonitorRegistration(
            sandbox_id="sandbox-gvisor-1",
            job_id="job-gvisor-1",
            isolation_class="gvisor",
            runtime_kind="container",
            container_id=CONTAINER_ID,
            trust_paths=("/opt/argus/trust",),
        )
        firecracker = SecurityMonitorRegistration(
            sandbox_id="sandbox-firecracker-1",
            job_id="job-firecracker-1",
            isolation_class="firecracker",
            runtime_kind="host_process",
            process_id=9012,
            cgroup_v2_path="/argus-firecracker/sandbox-firecracker-1",
        )

        self.assertEqual(gvisor.engine, "gvisor-runtime-monitor")
        self.assertEqual(firecracker.engine, "falco-modern-ebpf")
        self.assertEqual(gvisor.as_wire_payload()["isolation_class"], "gvisor")
        for isolation_class, runtime_kind in (
            ("gvisor", "host_process"),
            ("firecracker", "container"),
            ("unknown", "container"),
        ):
            with self.subTest(isolation_class=isolation_class, runtime_kind=runtime_kind):
                with self.assertRaises(ValueError):
                    SecurityMonitorRegistration(
                        sandbox_id="sandbox-invalid",
                        job_id="job-invalid",
                        isolation_class=isolation_class,
                        runtime_kind=runtime_kind,
                        container_id=CONTAINER_ID if runtime_kind == "container" else None,
                        process_id=9012 if runtime_kind == "host_process" else None,
                        cgroup_v2_path=(
                            "/argus-firecracker/sandbox-invalid"
                            if runtime_kind == "host_process"
                            else None
                        ),
                    )

    def test_security_event_rejects_unknown_engine_identity_or_non_sev1_payload(self) -> None:
        event = _security_event()
        self.assertEqual(event.audit_event_type, "trustwrite.detected")
        self.assertEqual(event.halt_reason, "trust_path_write")

        payload = asdict(event)
        for field, bad_value in (
            ("engine", "userspace-mock"),
            ("severity", "Sev-2"),
            ("container_id", "b" * 64),
        ):
            mutated = dict(payload)
            mutated[field] = bad_value
            with self.subTest(field=field), self.assertRaises(ValueError):
                HostSecurityEvent(**mutated)

        gvisor_event = _security_event(isolation_class="gvisor", engine="gvisor-runtime-monitor")
        self.assertEqual(gvisor_event.engine, "gvisor-runtime-monitor")
        with self.assertRaises(ValueError):
            HostSecurityEvent(**{**asdict(gvisor_event), "engine": "falco-modern-ebpf"})

    def test_poll_requires_monotonic_cursor_healthy_sensor_and_unique_events(self) -> None:
        first = _security_event(sequence=1)
        duplicate = _security_event(sequence=1)

        with self.assertRaises(SecurityMonitorError):
            SecurityMonitorPoll(
                cursor=1,
                healthy=False,
                engine="falco-modern-ebpf",
                overflowed=False,
                events=(),
            ).require_healthy()
        with self.assertRaises(ValueError):
            SecurityMonitorPoll(
                cursor=1,
                healthy=True,
                engine="falco-modern-ebpf",
                overflowed=False,
                events=(first, duplicate),
            )
        with self.assertRaises(ValueError):
            SecurityMonitorPoll(
                cursor=1,
                healthy=True,
                engine="gvisor-runtime-monitor",
                overflowed=False,
                events=(first,),
            )


class GvisorMonitorConfigTests(unittest.TestCase):
    def test_generator_emits_arch_specific_fail_closed_remote_session(self) -> None:
        expected_raw = {
            "x86_64": {101, 165, 166, 246, 250, 272, 308, 321},
            "aarch64": {39, 40, 97, 104, 117, 219, 268, 280},
        }
        for architecture, syscalls in expected_raw.items():
            with self.subTest(architecture=architecture), TemporaryDirectory() as temp_dir:
                output = Path(temp_dir) / "pod-init.json"
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/generate_s10_gvisor_monitor_config.py"),
                        "--architecture",
                        architecture,
                        "--endpoint",
                        "/run/argus-gvisor/events.sock",
                        "--output",
                        str(output),
                    ],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                payload = json.loads(output.read_text(encoding="utf-8"))
                session = payload["trace_session"]
                self.assertEqual(session["name"], "Default")
                self.assertFalse(session["ignore_missing"])
                points = session["points"]
                names = [point["name"] for point in points]
                self.assertEqual(len(names), len(set(names)))
                self.assertIn("syscall/openat/exit", names)
                self.assertIn("syscall/write/exit", names)
                self.assertEqual(
                    {
                        int(name.split("/")[2])
                        for name in names
                        if name.startswith("syscall/sysno/")
                    },
                    syscalls,
                )
                for point in points:
                    self.assertEqual(
                        set(point["context_fields"]),
                        {"time", "container_id", "thread_id", "group_id", "cwd", "process_name"},
                    )
                self.assertEqual(
                    session["sinks"],
                    [
                        {
                            "name": "remote",
                            "config": {
                                "endpoint": "/run/argus-gvisor/events.sock",
                                "retries": 3,
                                "backoff": "25us",
                                "backoff_max": "10ms",
                            },
                            "ignore_setup_error": False,
                        }
                    ],
                )

    def test_generator_rejects_unsupported_architecture_and_relative_endpoint(self) -> None:
        for architecture, endpoint in (
            ("riscv64", "/run/argus-gvisor/events.sock"),
            ("x86_64", "relative.sock"),
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/generate_s10_gvisor_monitor_config.py"),
                    "--architecture",
                    architecture,
                    "--endpoint",
                    endpoint,
                    "--output",
                    "/tmp/argus-invalid-gvisor-config.json",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)


class IsolatedS2TrainingEntrypointTests(unittest.TestCase):
    def test_entrypoint_runs_real_tc21_build_and_reports_lineage(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "argus_runtime.s2_isolated_training_entrypoint",
                "--container-digest",
                TC21_CONTAINER_DIGEST,
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}"},
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertLess(len(completed.stdout.encode("utf-8")), 65_536)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["schema"], "argus.s2.isolated-training.v1")
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["diagnostics"]["s2_tc21"], "PASS")
        self.assertEqual(payload["claim_tier"], "ran-toy")
        self.assertEqual(payload["container_digest"], TC21_CONTAINER_DIGEST)
        self.assertEqual(payload["adapter_call_count"], 60)
        self.assertEqual(payload["adapter_provenance_count"], 60)
        self.assertEqual(payload["dataset_lineage_count"], 60)
        self.assertGreater(payload["artifact_count"], 8)
        self.assertTrue(
            {
                "dataset_split",
                "feature_set",
                "hpo_selection",
                "training_log",
                "model_checkpoint",
                "uq_calibration",
                "advisory_self_check",
                "frozen_pipeline",
            }.issubset(payload["artifact_kinds"])
        )
        self.assertIn(payload["model_ref"], payload["frozen_pipeline_lineage"])
        self.assertIn(payload["uq_calibration_ref"], payload["frozen_pipeline_lineage"])
        self.assertTrue(payload["model_content_hash"].startswith("blake3:"))
        self.assertTrue(payload["frozen_pipeline_content_hash"].startswith("blake3:"))
        self.assertEqual(payload["self_replay"], "PASS")
        self.assertGreater(payload["cost_actual"]["cost_usd"], 0)
        self.assertEqual(payload["prediction"]["units"], "GeV")
        self.assertLessEqual(
            payload["prediction"]["uncertainty"]["lower"],
            payload["prediction"]["value"],
        )
        self.assertGreaterEqual(
            payload["prediction"]["uncertainty"]["upper"],
            payload["prediction"]["value"],
        )

    def test_entrypoint_rejects_unpinned_container_digest(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "argus_runtime.s2_isolated_training_entrypoint",
                "--container-digest",
                "argus-s2:latest",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}"},
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("container digest must be sha256", completed.stderr)


class SecurityMonitorBatteryEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.battery = importlib.import_module("scripts.run_s10_security_monitor_battery")

    def test_quarantined_case_requires_one_bound_sev1_and_physical_halt(self) -> None:
        response = {
            "handle": {
                "sandbox_id": "sandbox-t17-tc01",
                "job_id": "s10-t17-tc01-job",
                "state": "QUARANTINED",
                "runtime_class": "gvisor",
                "launch_provenance_ref": "c4://artifact/launch-tc01",
            },
            "partial_result": {
                "reason": "trust_path_write",
                "freeze_succeeded": True,
                "terminate_succeeded": True,
                "captured_after_freeze": True,
            },
            "halt_telemetry": {
                "reason": "trust_path_write",
                "halt_detected_elapsed_s": 0.2,
                "freeze_completed_elapsed_s": 0.3,
                "terminate_completed_elapsed_s": 0.4,
            },
        }
        events = [
            {
                "event_type": "trustwrite.detected",
                "payload": {
                    "event_id": "security-tc01",
                    "sandbox_id": "sandbox-t17-tc01",
                    "job_id": "s10-t17-tc01-job",
                    "severity": "Sev-1",
                    "engine": "gvisor-runtime-monitor",
                    "isolation_class": "gvisor",
                    "syscall": "openat",
                    "result": -30,
                    "path": "/opt/argus/trust/verifier/verify.py",
                },
            },
            {
                "event_type": "sandbox.quarantined",
                "payload": {
                    "sandbox_id": "sandbox-t17-tc01",
                    "job_id": "s10-t17-tc01-job",
                    "reason": "trust_path_write",
                    "state": "QUARANTINED",
                    "security_event_ids": ["security-tc01"],
                    "snapshot_refs": [],
                    "forensic_snapshot_status": "pending_s10_t18",
                },
            },
        ]

        evidence = self.battery._assert_quarantined_security_case(
            response,
            events,
            event_type="trustwrite.detected",
            reason="trust_path_write",
            syscall="openat",
            expected_path="/opt/argus/trust/verifier/verify.py",
        )
        self.assertEqual(evidence["security_event_id"], "security-tc01")

        duplicate = copy.deepcopy(events)
        duplicate.append(copy.deepcopy(events[0]))
        with self.assertRaises(AssertionError):
            self.battery._assert_quarantined_security_case(
                response,
                duplicate,
                event_type="trustwrite.detected",
                reason="trust_path_write",
                syscall="openat",
                expected_path="/opt/argus/trust/verifier/verify.py",
            )

    def test_clean_tc21_summary_rejects_mock_or_incomplete_lineage(self) -> None:
        required_kinds = {
            "dataset_split",
            "feature_set",
            "hpo_selection",
            "training_log",
            "model_checkpoint",
            "uq_calibration",
            "advisory_self_check",
            "frozen_pipeline",
        }
        summary = {
            "schema": "argus.s2.isolated-training.v1",
            "status": "PASS",
            "diagnostics": {"status": "SUCCEEDED", "s2_tc21": "PASS"},
            "claim_tier": "ran-toy",
            "container_digest": TC21_CONTAINER_DIGEST,
            "artifact_count": 84,
            "build_artifact_kinds": sorted(required_kinds),
            "model_ref": "c4://artifact/model",
            "model_content_hash": "blake3:" + "1" * 64,
            "uq_calibration_ref": "c4://artifact/uq",
            "frozen_pipeline_ref": "c4://artifact/frozen",
            "frozen_pipeline_content_hash": "blake3:" + "2" * 64,
            "frozen_pipeline_lineage": ["c4://artifact/model", "c4://artifact/uq"],
            "adapter_call_count": 60,
            "adapter_provenance_count": 60,
            "adapter_provenance_refs": [f"c4://artifact/provenance-{index:02d}" for index in range(60)],
            "dataset_lineage_count": 60,
            "self_replay": "PASS",
            "cost_actual": {"cost_usd": 0.05},
            "prediction": {
                "value": 3.5,
                "units": "GeV",
                "uncertainty": {"kind": "interval", "lower": 3.4, "upper": 3.6},
            },
        }

        self.battery._assert_clean_tc21_summary(summary, expected_container_digest=TC21_CONTAINER_DIGEST)
        incomplete = copy.deepcopy(summary)
        incomplete["adapter_provenance_count"] = 0
        with self.assertRaises(AssertionError):
            self.battery._assert_clean_tc21_summary(
                incomplete,
                expected_container_digest=TC21_CONTAINER_DIGEST,
            )

    def test_attack_probe_programs_are_valid_python(self) -> None:
        compile(self.battery._trust_write_probe_program(), "<tc01>", "exec")
        compile(self.battery._escape_probe_program(165), "<tc20>", "exec")

    def test_runsc_runtime_config_requires_every_security_audit_flag(self) -> None:
        required_args = [
            "--oci-seccomp",
            "--pod-init-config=/etc/argus/s10/gvisor-monitor-pod-init.json",
            "--debug",
            "--debug-command=boot",
            "--debug-log=/var/log/argus-runsc/%ID%/gvisor.%COMMAND%.json",
            "--debug-log-format=json",
        ]

        self.battery._assert_runsc_runtime_config({"runtimeArgs": required_args})
        for missing in required_args:
            with self.subTest(missing=missing), self.assertRaisesRegex(
                RuntimeError,
                "lacks S10-T17 monitoring flags",
            ):
                self.battery._assert_runsc_runtime_config(
                    {"runtimeArgs": [argument for argument in required_args if argument != missing]}
                )

    def test_compose_startup_failure_includes_monitor_diagnostics(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if len(calls) == 1:
                raise RuntimeError("compose startup failed")
            output = (
                '{"Service":"s10-security-monitor","State":"exited"}'
                if "ps" in command
                else "monitor stderr: address already in use"
            )
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

        with mock.patch.object(self.battery.m0_battery, "_run", side_effect=fake_run):
            with self.assertRaisesRegex(
                RuntimeError,
                "monitor stderr: address already in use",
            ) as raised:
                self.battery._compose(
                    "docker",
                    "compose.yaml",
                    {"COMPOSE_PROJECT_NAME": "argus-s10-test"},
                    "up",
                    "-d",
                    "--wait",
                    "s10-security-monitor",
                    timeout=240,
                    diagnostic_services=("s10-security-monitor",),
                )

        self.assertIn('"State":"exited"', str(raised.exception))
        self.assertEqual(len(calls), 3)
        self.assertIn("ps", calls[1])
        self.assertIn("logs", calls[2])

    def test_battery_projects_dynamic_trust_root_at_identical_path(self) -> None:
        with TemporaryDirectory(prefix="argus-s10-trust-root-") as temp_dir:
            trust_root = Path(temp_dir)
            environment = self.battery._gvisor_trust_source_mount_environment(trust_root)

        expected_path = str(trust_root.resolve())
        self.assertEqual(
            environment,
            {
                "ARGUS_S10_GVISOR_TRUST_SOURCE_ROOT": expected_path,
                "ARGUS_S10_GVISOR_TRUST_SOURCE_ROOT_MOUNT_PATH": expected_path,
            },
        )

    def test_supervisor_compose_mounts_dynamic_trust_root_read_only(self) -> None:
        compose = (ROOT / "deploy/argus-m0/compose.yaml").read_text(encoding="utf-8")

        self.assertIn(
            "source: ${ARGUS_S10_GVISOR_TRUST_SOURCE_ROOT:-./security}",
            compose,
        )
        self.assertIn(
            "target: ${ARGUS_S10_GVISOR_TRUST_SOURCE_ROOT_MOUNT_PATH:-/var/lib/argus/s10/trust-sources}",
            compose,
        )
        self.assertIn("read_only: true", compose)


class HttpSecurityMonitorClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _SecurityMonitorServer(token="monitor-secret")
        self.server.start()
        self.client = HttpSecurityMonitorClient(
            endpoint_url=self.server.url,
            auth_token="monitor-secret",
            allow_insecure=True,
        )

    def tearDown(self) -> None:
        self.server.stop()

    def test_authenticated_health_register_poll_and_unregister_round_trip(self) -> None:
        registration = SecurityMonitorRegistration(
            sandbox_id="sandbox-security-1",
            job_id="job-security-1",
            isolation_class="docker",
            runtime_kind="container",
            container_id=CONTAINER_ID,
            trust_paths=("/opt/argus/trust",),
        )
        self.server.events = [_security_event()]

        self.client.register(registration)
        poll = self.client.poll(sandbox_id=registration.sandbox_id, after=0)
        self.client.unregister(sandbox_id=registration.sandbox_id)

        self.assertEqual(poll.cursor, 1)
        self.assertEqual(poll.events, (_security_event(),))
        self.assertEqual(
            self.server.actions,
            ["health", "register", "poll:0", "unregister"],
        )
        self.assertEqual(self.server.registrations, [registration.as_wire_payload()])

    def test_client_rejects_unauthorized_or_unhealthy_monitor(self) -> None:
        unauthorized = HttpSecurityMonitorClient(
            endpoint_url=self.server.url,
            auth_token="wrong-secret",
            allow_insecure=True,
        )
        with self.assertRaisesRegex(SecurityMonitorError, "HTTP 401"):
            unauthorized.health()

        self.server.sensor_running = False
        with self.assertRaisesRegex(SecurityMonitorError, "not healthy"):
            self.client.health()

    def test_gvisor_registration_requires_and_preserves_the_gvisor_source(self) -> None:
        registration = SecurityMonitorRegistration(
            sandbox_id="sandbox-gvisor-1",
            job_id="job-gvisor-1",
            isolation_class="gvisor",
            runtime_kind="container",
            container_id=CONTAINER_ID,
            trust_paths=("/opt/argus/trust",),
        )
        self.server.gvisor_running = False
        with self.assertRaisesRegex(SecurityMonitorError, "gvisor-runtime-monitor"):
            self.client.register(registration)

        self.server.gvisor_running = True
        self.server.events = [
            _security_event(
                sandbox_id=registration.sandbox_id,
                job_id=registration.job_id,
                isolation_class="gvisor",
                engine="gvisor-runtime-monitor",
            )
        ]
        self.client.register(registration)
        poll = self.client.poll(sandbox_id=registration.sandbox_id, after=0)

        self.assertEqual(poll.engine, "gvisor-runtime-monitor")
        self.assertEqual(poll.events[0].isolation_class, "gvisor")

    def test_client_rejects_cross_identity_and_non_monotonic_event_batches(self) -> None:
        registration = SecurityMonitorRegistration(
            sandbox_id="sandbox-security-1",
            job_id="job-security-1",
            isolation_class="docker",
            runtime_kind="container",
            container_id=CONTAINER_ID,
            trust_paths=("/opt/argus/trust",),
        )
        self.client.register(registration)
        self.server.events = [_security_event(sandbox_id="sandbox-other")]
        with self.assertRaisesRegex(SecurityMonitorError, "invalid event"):
            self.client.poll(sandbox_id="sandbox-security-1", after=0)

        self.server.events = [_security_event(sequence=1)]
        self.server.force_all_events = True
        with self.assertRaisesRegex(SecurityMonitorError, "advance monotonically"):
            self.client.poll(sandbox_id="sandbox-security-1", after=1)

    def test_client_rejects_unexpected_fields_and_insecure_remote_origin(self) -> None:
        self.server.extra_health_field = True
        with self.assertRaisesRegex(SecurityMonitorError, "fields are invalid"):
            self.client.health()

        with self.assertRaisesRegex(ValueError, "requires HTTPS"):
            HttpSecurityMonitorClient(
                endpoint_url="http://security-monitor.internal:8765",
                auth_token="monitor-secret",
            )
        for endpoint in (
            f"{self.server.url}?token=leak",
            f"{self.server.url}#fragment",
            self.server.url.replace("http://", "http://user@"),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, "origin"):
                HttpSecurityMonitorClient(
                    endpoint_url=endpoint,
                    auth_token="monitor-secret",
                    allow_insecure=True,
                )

    def test_client_rejects_redirects_without_forwarding_monitor_credentials(self) -> None:
        self.server.health_redirect = True

        with self.assertRaisesRegex(SecurityMonitorError, "HTTP 302"):
            self.client.health()

        self.assertEqual(self.server.actions, ["health"])


class DockerSecurityMonitorOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        tokens = InMemoryTokenService(signing_key=b"s10-security-monitor-ordering")
        budget = tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-security-1",
            root_request_id="root-security-1",
        )
        scope = tokens.mint_scope(
            job_id="job-security-1",
            scopes=ScopeGrant(sandbox_risk_class="standard"),
        )
        self.request = LaunchRequest(
            job_id="job-security-1",
            subagent_id="s2-builder",
            trace_id="trace-security-1",
            budget_token=budget,
            scope_token=scope,
            image="busybox@sha256:" + "b" * 64,
            entrypoint=("sh",),
            args=("-c", "true"),
            env={},
            env_allowlist=(),
            requested_envelope=LaunchEnvelope(
                cpu_m=100,
                mem_bytes=16 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=2,
                scratch_bytes=1024 * 1024,
                pids=8,
            ),
        )
        self.handle = SandboxHandle(
            sandbox_id="sandbox-security-1",
            job_id="job-security-1",
            runtime_class="docker",
            budget_epoch=1,
            policy_bundle_version="2.0.0",
            state="ADMITTED",
        )

    def test_registration_precedes_start_and_trustwrite_physically_halts(self) -> None:
        monitor = _FakeSecurityMonitor(polls=[SecurityMonitorPoll(
            cursor=1,
            healthy=True,
            engine="falco-modern-ebpf",
            overflowed=False,
            events=(_security_event(),),
        )])
        supervisor = _SecurityMonitorDockerApiSupervisor(monitor)
        events: list[HostSecurityEvent] = []

        result = supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            security_event_sink=events.append,
        )

        start_index = supervisor.actions.index("docker:start")
        register_index = supervisor.actions.index("monitor:register")
        self.assertLess(register_index, start_index)
        self.assertEqual(supervisor.actions[start_index + 1 : start_index + 5], [
            "monitor:poll",
            "docker:pause",
            "docker:unpause",
            "docker:kill",
        ])
        self.assertEqual(supervisor.actions[-2:], ["monitor:unregister", "docker:delete"])
        self.assertEqual(events, [_security_event()])
        self.assertIsNotNone(result.partial_result)
        self.assertEqual(result.partial_result.reason, "trust_path_write")
        self.assertTrue(result.partial_result.captured_after_freeze)

    def test_sensor_registration_failure_prevents_container_start(self) -> None:
        monitor = _FakeSecurityMonitor(register_error=SecurityMonitorError("sensor unavailable"))
        supervisor = _SecurityMonitorDockerApiSupervisor(monitor)

        with self.assertRaisesRegex(SecurityMonitorError, "sensor unavailable"):
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                security_event_sink=lambda event: None,
            )

        self.assertNotIn("docker:start", supervisor.actions)
        self.assertEqual(supervisor.actions[-1], "docker:delete")

    def test_clean_execution_unregisters_without_security_event(self) -> None:
        monitor = _FakeSecurityMonitor(polls=[SecurityMonitorPoll(
            cursor=0,
            healthy=True,
            engine="falco-modern-ebpf",
            overflowed=False,
            events=(),
        )])
        supervisor = _SecurityMonitorDockerApiSupervisor(monitor, clean_exit=True)
        events: list[HostSecurityEvent] = []

        result = supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            security_event_sink=events.append,
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.partial_result)
        self.assertEqual(events, [])
        self.assertEqual(monitor.unregister_count, 1)

    def test_terminal_state_drains_late_sensor_event_before_unregister(self) -> None:
        monitor = _FakeSecurityMonitor(
            polls=[
                SecurityMonitorPoll(
                    cursor=0,
                    healthy=True,
                    engine="falco-modern-ebpf",
                    overflowed=False,
                    events=(),
                ),
                SecurityMonitorPoll(
                    cursor=1,
                    healthy=True,
                    engine="falco-modern-ebpf",
                    overflowed=False,
                    events=(_security_event(),),
                ),
            ]
        )
        supervisor = _SecurityMonitorDockerApiSupervisor(monitor, clean_exit=True)
        events: list[HostSecurityEvent] = []

        supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            security_event_sink=events.append,
        )

        self.assertEqual(events, [_security_event()])
        self.assertEqual(supervisor.actions.count("monitor:poll"), 2)
        self.assertLess(
            max(index for index, action in enumerate(supervisor.actions) if action == "monitor:poll"),
            supervisor.actions.index("monitor:unregister"),
        )

    def test_sensor_loss_while_running_physically_halts_fail_closed(self) -> None:
        monitor = _FakeSecurityMonitor(polls=[SecurityMonitorPoll(
            cursor=0,
            healthy=False,
            engine="falco-modern-ebpf",
            overflowed=False,
            events=(),
        )])
        supervisor = _SecurityMonitorDockerApiSupervisor(monitor)

        result = supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            security_event_sink=lambda event: None,
        )

        self.assertIsNotNone(result.partial_result)
        assert result.partial_result is not None
        self.assertEqual(result.partial_result.reason, "security_monitor_unavailable")
        self.assertEqual(
            supervisor.actions[supervisor.actions.index("monitor:poll") + 1 :][:3],
            ["docker:pause", "docker:unpause", "docker:kill"],
        )


class FirecrackerSecurityMonitorOrderingTests(unittest.TestCase):
    def test_registers_authenticated_host_identity_before_instance_start_and_halts_on_event(self) -> None:
        actions: list[str] = []
        monitor = _FakeFirecrackerSecurityMonitor(actions=actions)
        with TemporaryDirectory() as temp_dir:
            supervisor = _SecurityMonitorFirecrackerSupervisor(
                actions=actions,
                root=Path(temp_dir),
            )
            request = _firecracker_security_request()
            handle = SandboxHandle(
                sandbox_id="sandbox-firecracker-security-1",
                job_id=request.job_id,
                runtime_class="firecracker",
                budget_epoch=1,
                policy_bundle_version="2.0.0",
                state="ADMITTED",
            )
            events: list[HostSecurityEvent] = []

            result = supervisor.run(
                handle=handle,
                request=request,
                materialized_env={},
                policy_bundle=object(),  # type: ignore[arg-type]
                security_monitor=monitor,
                security_event_sink=events.append,
            )

        self.assertIsNotNone(result.partial_result)
        assert result.partial_result is not None
        self.assertEqual(result.partial_result.reason, "escape_attempt")
        self.assertEqual(events, [_host_security_event()])
        self.assertLess(actions.index("monitor:register"), actions.index("firecracker:InstanceStart"))
        self.assertLess(actions.index("firecracker:InstanceStart"), actions.index("monitor:poll"))
        self.assertLess(actions.index("microvm:halt:escape_attempt"), actions.index("monitor:unregister"))

    def test_terminal_state_drains_late_sensor_event_before_unregister(self) -> None:
        actions: list[str] = []
        monitor = _FakeFirecrackerSecurityMonitor(
            actions=actions,
            polls=[
                SecurityMonitorPoll(
                    cursor=1,
                    healthy=True,
                    engine="falco-modern-ebpf",
                    overflowed=False,
                    events=(),
                ),
                SecurityMonitorPoll(
                    cursor=2,
                    healthy=True,
                    engine="falco-modern-ebpf",
                    overflowed=False,
                    events=(_host_security_event(),),
                ),
            ],
        )
        with TemporaryDirectory() as temp_dir:
            supervisor = _SecurityMonitorFirecrackerSupervisor(
                actions=actions,
                root=Path(temp_dir),
                clean_exit=True,
            )
            request = _firecracker_security_request()
            handle = SandboxHandle(
                sandbox_id="sandbox-firecracker-security-1",
                job_id=request.job_id,
                runtime_class="firecracker",
                budget_epoch=1,
                policy_bundle_version="2.0.0",
                state="ADMITTED",
            )
            events: list[HostSecurityEvent] = []

            result = supervisor.run(
                handle=handle,
                request=request,
                materialized_env={},
                policy_bundle=object(),  # type: ignore[arg-type]
                security_monitor=monitor,
                security_event_sink=events.append,
            )

        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.partial_result)
        self.assertEqual(events, [_host_security_event()])
        poll_positions = [index for index, action in enumerate(actions) if action == "monitor:poll"]
        self.assertEqual(len(poll_positions), 2)
        self.assertLess(poll_positions[-1], actions.index("monitor:unregister"))


class SecurityViolationOrchestratorTests(unittest.TestCase):
    def test_trustwrite_is_durable_sev1_quarantine_without_claiming_t18_snapshot(self) -> None:
        tokens = InMemoryTokenService(signing_key=b"s10-security-violation-orchestrator")
        budget = tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-security-1",
            root_request_id="root-security-1",
        )
        scope = tokens.mint_scope(
            job_id="job-security-1",
            scopes=ScopeGrant(sandbox_risk_class="standard"),
        )
        bundle = _policy_bundle()
        trust = InMemoryPolicyBundleTrustStore({bundle.signer_key_id: b"security-policy-key"})
        policy = InMemoryPolicyService(initial_bundle=bundle, trust_store=trust)
        audit = InMemoryAuditLedger()
        artifacts = InMemoryArtifactStore()
        orchestrator = DockerSandboxOrchestrator(
            token_service=tokens,
            quota_ledger=InMemoryQuotaLedger(),
            audit_ledger=audit,
            policy_service=policy,
            artifact_store=artifacts,
            supervisor=_SecurityEventResultSupervisor(_security_event()),
        )
        request = LaunchRequest(
            job_id="job-security-1",
            subagent_id="s2-builder",
            trace_id="trace-security-1",
            budget_token=budget,
            scope_token=scope,
            image="busybox@sha256:" + "b" * 64,
            entrypoint=("sh",),
            args=("-c", "true"),
            env={},
            env_allowlist=(),
            requested_envelope=LaunchEnvelope(
                cpu_m=100,
                mem_bytes=16 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=2,
                scratch_bytes=1024 * 1024,
                pids=8,
            ),
        )

        result = orchestrator.launch_and_wait(request)

        self.assertEqual(result.handle.state, "QUARANTINED")
        matching = audit.query(job_id=request.job_id, event_type="trustwrite.detected", severity="Sev-1")
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].payload["sandbox_id"], result.handle.sandbox_id)
        self.assertEqual(matching[0].payload["engine"], "falco-modern-ebpf")
        quarantined = audit.query(job_id=request.job_id, event_type="sandbox.quarantined")
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].payload["snapshot_refs"], [])
        self.assertEqual(quarantined[0].payload["forensic_snapshot_status"], "pending_s10_t18")
        self.assertTrue(audit.verify_chain().valid)


class _SecurityMonitorServer:
    def __init__(self, *, token: str) -> None:
        self.token = token
        self.sensor_running = True
        self.gvisor_configured = True
        self.gvisor_running = True
        self.overflowed = False
        self.extra_health_field = False
        self.force_all_events = False
        self.health_redirect = False
        self.actions: list[str] = []
        self.events: list[HostSecurityEvent] = []
        self.registrations: list[dict[str, object]] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if not self._authorized():
                    return
                if self.path == "/healthz":
                    with outer._lock:
                        outer.actions.append("health")
                    if outer.health_redirect:
                        self.send_response(302)
                        self.send_header("Location", "/redirected-health")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self._respond(200, self._health_payload())
                    return
                if self.path == "/redirected-health":
                    with outer._lock:
                        outer.actions.append("redirected-health")
                    self._respond(200, self._health_payload())
                    return
                prefix = "/v1/registrations/"
                suffix = "/events?after="
                if self.path.startswith(prefix) and suffix in self.path:
                    sandbox_id, raw_after = self.path.removeprefix(prefix).split(suffix, 1)
                    after = int(raw_after)
                    with outer._lock:
                        outer.actions.append(f"poll:{after}")
                        events = [
                            event
                            for event in outer.events
                            if outer.force_all_events or event.sequence > after
                        ]
                        registration = next(
                            (
                                item
                                for item in reversed(outer.registrations)
                                if item["sandbox_id"] == sandbox_id
                            ),
                            None,
                        )
                        engine = (
                            "gvisor-runtime-monitor"
                            if registration is not None and registration["isolation_class"] == "gvisor"
                            else "falco-modern-ebpf"
                        )
                    self._respond(
                        200,
                        {
                            "sandbox_id": sandbox_id,
                            "cursor": max([after, *(event.sequence for event in events)]),
                            "healthy": outer.sensor_running,
                            "engine": engine,
                            "overflowed": outer.overflowed,
                            "events": [asdict(event) for event in events],
                        },
                    )
                    return
                self._respond(404, {"error": "not found"})

            def _health_payload(self) -> dict[str, object]:
                response: dict[str, object] = {
                        "service": "argus-s10-security-monitor",
                        "status": (
                            "ok"
                            if outer.sensor_running
                            and (not outer.gvisor_configured or outer.gvisor_running)
                            and not outer.overflowed
                            else "degraded"
                        ),
                        "engine": "argus-host-security",
                        "overflowed": outer.overflowed,
                        "sources": {
                            "falco-modern-ebpf": {
                                "configured": True,
                                "running": outer.sensor_running,
                                "degraded": False,
                            },
                            "gvisor-runtime-monitor": {
                                "configured": outer.gvisor_configured,
                                "running": outer.gvisor_running,
                                "degraded": False,
                            },
                        },
                    }
                if outer.extra_health_field:
                    response["unexpected"] = True
                return response

            def do_POST(self) -> None:
                if not self._authorized():
                    return
                if self.path != "/v1/registrations":
                    self._respond(404, {"error": "not found"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                with outer._lock:
                    outer.actions.append("register")
                    outer.registrations.append(payload)
                self._respond(
                    201,
                    {
                        "registered": True,
                        "sandbox_id": payload["sandbox_id"],
                        "job_id": payload["job_id"],
                        "isolation_class": payload["isolation_class"],
                        "runtime_kind": payload["runtime_kind"],
                        "engine": (
                            "gvisor-runtime-monitor"
                            if payload["isolation_class"] == "gvisor"
                            else "falco-modern-ebpf"
                        ),
                        "cursor": 0,
                    },
                )

            def do_DELETE(self) -> None:
                if not self._authorized():
                    return
                prefix = "/v1/registrations/"
                if not self.path.startswith(prefix):
                    self._respond(404, {"error": "not found"})
                    return
                sandbox_id = self.path.removeprefix(prefix)
                with outer._lock:
                    outer.actions.append("unregister")
                self._respond(200, {"registered": False, "sandbox_id": sandbox_id})

            def _authorized(self) -> bool:
                if self.headers.get("Authorization") == f"Bearer {outer.token}":
                    return True
                self._respond(401, {"error": "unauthorized"})
                return False

            def _respond(self, status: int, payload: dict[str, object]) -> None:
                encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, format: str, *args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class _FakeSecurityMonitor:
    def __init__(
        self,
        *,
        polls: list[SecurityMonitorPoll] | None = None,
        register_error: Exception | None = None,
    ) -> None:
        self.polls = list(polls or [])
        self.register_error = register_error
        self.actions: list[str] | None = None
        self.unregister_count = 0

    def register(self, registration: SecurityMonitorRegistration) -> None:
        if self.actions is not None:
            self.actions.append("monitor:register")
        if self.register_error is not None:
            raise self.register_error
        if registration.container_id != CONTAINER_ID:
            raise AssertionError("monitor registration lost the full container identity")
        if registration.isolation_class != "docker" or registration.engine != "falco-modern-ebpf":
            raise AssertionError("Docker monitor registration selected the wrong sensor source")

    def poll(self, *, sandbox_id: str, after: int) -> SecurityMonitorPoll:
        if self.actions is not None:
            self.actions.append("monitor:poll")
        if sandbox_id != "sandbox-security-1" or after != 0:
            raise AssertionError("monitor poll identity/cursor mismatch")
        return self.polls.pop(0) if self.polls else SecurityMonitorPoll(
            cursor=after,
            healthy=True,
            engine="falco-modern-ebpf",
            overflowed=False,
            events=(),
        )

    def unregister(self, *, sandbox_id: str) -> None:
        if self.actions is not None:
            self.actions.append("monitor:unregister")
        if sandbox_id != "sandbox-security-1":
            raise AssertionError("monitor unregister identity mismatch")
        self.unregister_count += 1


class _FakeFirecrackerSecurityMonitor:
    def __init__(
        self,
        *,
        actions: list[str],
        polls: list[SecurityMonitorPoll] | None = None,
    ) -> None:
        self.actions = actions
        self.polls = list(polls) if polls is not None else [
            SecurityMonitorPoll(
                cursor=1,
                healthy=True,
                engine="falco-modern-ebpf",
                overflowed=False,
                events=(_host_security_event(),),
            )
        ]
        self.expected_after = 0

    def register(self, registration: SecurityMonitorRegistration) -> None:
        self.actions.append("monitor:register")
        if registration.as_wire_payload() != {
            "sandbox_id": "sandbox-firecracker-security-1",
            "job_id": "job-security-1",
            "isolation_class": "firecracker",
            "runtime_kind": "host_process",
            "process_id": 9012,
            "cgroup_v2_path": "/argus-firecracker/sandbox-firecracker-security-1",
            "trust_paths": [],
        }:
            raise AssertionError("Firecracker monitor registration identity drifted")

    def poll(self, *, sandbox_id: str, after: int) -> SecurityMonitorPoll:
        self.actions.append("monitor:poll")
        if sandbox_id != "sandbox-firecracker-security-1" or after != self.expected_after:
            raise AssertionError("Firecracker monitor poll identity drifted")
        poll = self.polls.pop(0) if self.polls else SecurityMonitorPoll(
            cursor=after,
            healthy=True,
            engine="falco-modern-ebpf",
            overflowed=False,
            events=(),
        )
        self.expected_after = poll.cursor
        return poll

    def unregister(self, *, sandbox_id: str) -> None:
        self.actions.append("monitor:unregister")
        if sandbox_id != "sandbox-firecracker-security-1":
            raise AssertionError("Firecracker monitor unregister identity drifted")


class _SecurityMonitorDockerApiSupervisor(DockerSandboxSupervisor):
    def __init__(self, monitor: _FakeSecurityMonitor, *, clean_exit: bool = False) -> None:
        super().__init__(meter_interval_s=0.1, security_monitor=monitor)
        self._docker_socket_path = "/tmp/fake-docker.sock"
        self.actions: list[str] = []
        self.clean_exit = clean_exit
        monitor.actions = self.actions

    def _docker_api_request(  # type: ignore[override]
        self,
        method: str,
        path: str,
        body=None,
        *,
        expected,
        timeout: float = 10,
    ):
        del body, expected, timeout
        if method == "POST" and path.startswith("/containers/create"):
            self.actions.append("docker:create")
            return {"Id": CONTAINER_ID}
        if method == "POST" and path.endswith("/start"):
            self.actions.append("docker:start")
            return {}
        if method == "GET" and path.endswith("/json"):
            self.actions.append("docker:inspect")
            return {"State": {"Running": not self.clean_exit, "ExitCode": 0}}
        if method == "POST" and path.endswith("/pause"):
            self.actions.append("docker:pause")
            return {}
        if method == "POST" and path.endswith("/kill"):
            self.actions.append("docker:kill")
            return {}
        if method == "POST" and path.endswith("/unpause"):
            self.actions.append("docker:unpause")
            return {}
        if method == "DELETE":
            self.actions.append("docker:delete")
            return {}
        raise AssertionError(f"unexpected Docker API call: {method} {path}")

    def _docker_api_logs(self, container_id: str):  # type: ignore[no-untyped-def]
        del container_id
        from argus_core import s10 as s10_module

        return s10_module._DockerLogCapture(
            stdout="partial-security-evidence\n",
            stderr="",
            stdout_bytes=26,
            stderr_bytes=0,
            log_capture_limit_bytes=s10_module.PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES,
            truncated=False,
        )

    def _docker_api_resource_sample(self, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        raise AssertionError("security poll must precede the next resource sample")


class _SecurityEventResultSupervisor:
    def __init__(self, event: HostSecurityEvent) -> None:
        self.event = event

    def run(  # type: ignore[no-untyped-def]
        self,
        *,
        handle,
        request,
        materialized_env,
        security_event_sink,
        **kwargs,
    ):
        del request, materialized_env, kwargs
        security_event_sink(replace(self.event, sandbox_id=handle.sandbox_id, event_id=""))
        return SandboxExecutionResult(
            handle=handle,
            exit_code=137,
            stdout="",
            stderr="",
            timed_out=False,
            duration_s=0.1,
            budget_usage=BudgetUsage(wallclock_s=0.1),
            partial_result=SandboxPartialResult(
                reason="trust_path_write",
                stdout="",
                stderr="",
                captured_after_freeze=True,
                freeze_succeeded=True,
                terminate_succeeded=True,
                stdout_bytes=0,
                stderr_bytes=0,
            ),
        )


class _SecurityMonitorFirecrackerSupervisor(FirecrackerSandboxSupervisor):
    def __init__(self, *, actions: list[str], root: Path, clean_exit: bool = False) -> None:
        self.actions = actions
        self.root = root
        self.clean_exit = clean_exit

    def materialize_vm_spec(self, **kwargs):  # type: ignore[no-untyped-def]
        handle = kwargs["handle"]
        return {"microvm_id": handle.sandbox_id}

    def _verify_host_runtime(self) -> None:
        return

    def verify_runtime_versions(self) -> tuple[str, str]:
        return "1.15.1", "1.15.1"

    def _jail_root(self, microvm_id: str) -> Path:
        return self.root / microvm_id / "root"

    def _validate_api_socket_path(self, microvm_id: str) -> None:
        del microvm_id

    def _create_drive_images(self, root, request, materialized_env):  # type: ignore[no-untyped-def]
        del request, materialized_env
        request_drive = root / "request.ext4"
        scratch_drive = root / "scratch.ext4"
        request_drive.write_bytes(b"request")
        scratch_drive.write_bytes(b"scratch")
        return request_drive, hash_bytes(b"request"), scratch_drive

    def _launch_jailer(self, spec):  # type: ignore[no-untyped-def]
        del spec
        self.actions.append("jailer:launch")

    def _wait_for_jailer_ready(self, microvm_id: str, *, timeout_s: float):  # type: ignore[no-untyped-def]
        del timeout_s
        self.actions.append("jailer:ready")
        return _FirecrackerProcessIdentity(
            pid=9012,
            start_time_ticks=100,
            pid_namespace_ids=(9012, 1),
            cgroup_v2_path=f"/argus-firecracker/{microvm_id}",
        )

    def _stage_jail_resources(self, **kwargs):  # type: ignore[no-untyped-def]
        microvm_id = kwargs["microvm_id"]
        jail_root = self._jail_root(microvm_id)
        jail_root.mkdir(parents=True)
        serial_path = jail_root / "serial.log"
        log_path = jail_root / "firecracker.log"
        serial_path.write_text("partial\n", encoding="utf-8")
        log_path.write_text("", encoding="utf-8")
        return _FirecrackerJailResources(
            jail_root=jail_root,
            api_socket=jail_root / "run/firecracker.socket",
            pid_file=jail_root / "firecracker.pid",
            kernel_path=jail_root / "vmlinux",
            rootfs_path=jail_root / "rootfs.ext4",
            request_drive_path=jail_root / "argus-input.ext4",
            request_drive_hash=kwargs["request_drive_hash"],
            scratch_path=jail_root / "scratch.ext4",
            scratch_bytes=kwargs["scratch_bytes"],
            serial_path=serial_path,
            log_path=log_path,
        )

    def _configure_and_attest(self, **kwargs):  # type: ignore[no-untyped-def]
        process_identity = kwargs["process_identity"]
        spec = kwargs["spec"]
        return FirecrackerRuntimeLaunchEvidence(
            sandbox_id=spec["microvm_id"],
            microvm_id=spec["microvm_id"],
            runtime_class="firecracker",
            firecracker_version="1.15.1",
            jailer_version="1.15.1",
            kernel_image_hash="blake3:" + "1" * 64,
            rootfs_image_hash="blake3:" + "2" * 64,
            request_drive_hash=kwargs["resources"].request_drive_hash,
            scratch_bytes=kwargs["resources"].scratch_bytes,
            network_interface_count=0,
            jailer_uid=65532,
            jailer_gid=65532,
            pid_namespace_init=True,
            cgroup_v2_path=process_identity.cgroup_v2_path,
            seccomp_enabled=True,
            seccomp_filter_mode="default-built-in",
            seccomp_filter_count=1,
            read_only_rootfs=True,
            federated_extra_access=False,
            trust_mount_count=0,
            attestation_source="test-host-control",
        )

    def _firecracker_api_request(self, socket_path, method, path, body, *, expected):  # type: ignore[no-untyped-def]
        del socket_path, method, path, expected
        self.actions.append(f"firecracker:{body['action_type']}")
        return {}

    def _wait_for_process_seccomp(self, process_identity, *, timeout_s):  # type: ignore[no-untyped-def]
        del process_identity, timeout_s
        return 1

    def _wait_for_microvm(self, **kwargs):  # type: ignore[no-untyped-def]
        halt = kwargs["runtime_halt_probe"]()
        if halt is None:
            if not self.clean_exit:
                raise AssertionError("security monitor event did not halt the microVM")
            return SandboxExecutionResult(
                handle=kwargs["handle"],
                exit_code=0,
                stdout="clean\n",
                stderr="",
                timed_out=False,
                duration_s=0.1,
                budget_usage=BudgetUsage(wallclock_s=0.1),
            )
        self.actions.append(f"microvm:halt:{halt.reason}")
        return SandboxExecutionResult(
            handle=kwargs["handle"],
            exit_code=None,
            stdout="partial\n",
            stderr="",
            timed_out=True,
            duration_s=0.1,
            budget_usage=BudgetUsage(wallclock_s=0.1),
            partial_result=SandboxPartialResult(
                reason=halt.reason,
                stdout="partial\n",
                stderr="",
                captured_after_freeze=True,
                freeze_succeeded=True,
                terminate_succeeded=True,
                stdout_bytes=8,
                stderr_bytes=0,
            ),
        )

    def _process_identity_is_alive(self, process_identity):  # type: ignore[no-untyped-def]
        del process_identity
        return False

    def _cleanup_microvm(self, microvm_id: str, microvm_dir: Path) -> None:
        del microvm_id, microvm_dir
        self.actions.append("microvm:cleanup")


def _firecracker_security_request() -> LaunchRequest:
    tokens = InMemoryTokenService(signing_key=b"s10-firecracker-security-monitor")
    budget = tokens.mint_budget(
        caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
        job_id="job-security-1",
        root_request_id="root-security-1",
        risk_class="federated",
    )
    scope = tokens.mint_scope(
        job_id="job-security-1",
        scopes=ScopeGrant(sandbox_risk_class="federated"),
    )
    return LaunchRequest(
        job_id="job-security-1",
        subagent_id="s2-builder",
        trace_id="trace-security-1",
        budget_token=budget,
        scope_token=scope,
        image="firecracker-rootfs@sha256:" + "b" * 64,
        entrypoint=("/bin/true",),
        args=(),
        env={},
        env_allowlist=(),
        requested_envelope=LaunchEnvelope(
            cpu_m=100,
            mem_bytes=128 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=2,
            scratch_bytes=1024 * 1024,
            pids=8,
        ),
    )


def _policy_bundle() -> PolicyBundle:
    signer = PolicyBundleSigner(key_id="security-policy", secret=b"security-policy-key")
    unsigned = PolicyBundle(
        bundle_version="2.0.0",
        egress_allowlist=(),
        resource_ceilings=ResourceCeilings(
            cpu_m=1000,
            mem_bytes=1024 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=60,
            max_cost_usd=10,
        ),
        risk_to_runtime={"standard": "docker"},
        seccomp_profile_hash=hash_bytes(b"security-seccomp"),
        signer_key_id=signer.key_id,
        signature="",
    )
    return signer.sign(unsigned)


if __name__ == "__main__":
    unittest.main()
