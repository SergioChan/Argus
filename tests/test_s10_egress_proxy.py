from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from argus_core import (
    BudgetCaps,
    DockerSandboxSupervisor,
    EgressProxyManifest,
    EgressProxyManifestError,
    EgressRule,
    EgressSidecarRuntimeConfig,
    ExfilThresholds,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyBundleSigner,
    ResourceCeilings,
    SandboxHandle,
    SandboxRuntimeUnavailableError,
    ScopeGrant,
)
from argus_egress import EgressProxyManifest as SidecarEgressProxyManifest
from argus_runtime.s10_egress_proxy_service import (
    EgressConnectProxy,
    LinuxEgressFirewall,
    _ExfiltrationByteMeter,
    _relay_bidirectional,
    _send_metered_payload,
)
from argus_runtime.s10_supervisor_service import _egress_sidecar_runtime_config_from_env
from scripts import run_s10_egress_battery as egress_battery


class EgressProxyManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allowed = EgressRule("allowed.test", 443, "https")
        self.scope_only = EgressRule("scope-only.test", 443, "https")
        self.policy_only = EgressRule("policy-only.test", 443, "https")
        self.bundle = PolicyBundleSigner(key_id="policy-key", secret=b"policy-secret").sign(
            PolicyBundle(
                bundle_version="2.0.0",
                egress_allowlist=(self.allowed, self.policy_only),
                resource_ceilings=ResourceCeilings(
                    cpu_m=1_000,
                    mem_bytes=128 * 1024 * 1024,
                    gpu_count=0,
                    wallclock_s=30,
                    max_cost_usd=1,
                ),
                risk_to_runtime={"standard": "docker"},
                seccomp_profile_hash="blake3:" + "0" * 64,
                signer_key_id="",
                signature="",
            )
        )
        self.scope = InMemoryTokenService(signing_key=b"scope-secret", now_fn=lambda: 1_000).mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(egress_allowlist=(self.allowed, self.scope_only)),
        )

    def test_materializes_only_signed_policy_and_scope_intersection(self) -> None:
        manifest = EgressProxyManifest.materialize(
            sandbox_id="sandbox-1",
            scope_token=self.scope,
            policy_bundle=self.bundle,
        )

        self.assertEqual(manifest.rules, (self.allowed,))
        self.assertEqual(manifest.scope_id, self.scope.scope_id)
        self.assertEqual(manifest.policy_bundle_version, "2.0.0")
        self.assertEqual(manifest.schema_version, 2)
        self.assertEqual(manifest.exfil_thresholds, self.bundle.exfil_thresholds)
        self.assertTrue(manifest.manifest_hash.startswith("blake3:"))

    def test_exfil_thresholds_are_content_bound_and_ordered(self) -> None:
        thresholds = ExfilThresholds(soft_bytes=1_024, hard_bytes=2_048)
        bundle = PolicyBundleSigner(key_id="policy-key", secret=b"policy-secret").sign(
            replace(self.bundle, exfil_thresholds=thresholds, signer_key_id="", signature="")
        )
        manifest = EgressProxyManifest.materialize(
            sandbox_id="sandbox-1",
            scope_token=self.scope,
            policy_bundle=bundle,
        )
        payload = json.loads(manifest.to_json())

        self.assertEqual(payload["exfil_thresholds"], {"soft_bytes": 1_024, "hard_bytes": 2_048})
        payload["exfil_thresholds"]["hard_bytes"] = 4_096
        with self.assertRaisesRegex(EgressProxyManifestError, "hash"):
            EgressProxyManifest.from_json(json.dumps(payload), expected_hash=manifest.manifest_hash)

        for soft_bytes, hard_bytes in ((0, 2), (2, 2), (3, 2)):
            with self.subTest(soft_bytes=soft_bytes, hard_bytes=hard_bytes):
                with self.assertRaises(ValueError):
                    ExfilThresholds(soft_bytes=soft_bytes, hard_bytes=hard_bytes)

    def test_expected_hash_rejects_manifest_drift(self) -> None:
        manifest = EgressProxyManifest.materialize(
            sandbox_id="sandbox-1",
            scope_token=self.scope,
            policy_bundle=self.bundle,
        )
        payload = json.loads(manifest.to_json())
        payload["rules"][0]["host"] = "evil.test"

        with self.assertRaisesRegex(EgressProxyManifestError, "hash"):
            EgressProxyManifest.from_json(json.dumps(payload), expected_hash=manifest.manifest_hash)

    def test_sidecar_wire_package_parses_core_manifest_without_project_dependencies(self) -> None:
        manifest = EgressProxyManifest.materialize(
            sandbox_id="sandbox-1",
            scope_token=self.scope,
            policy_bundle=self.bundle,
        )

        parsed = SidecarEgressProxyManifest.from_json(
            manifest.to_json(),
            expected_hash=manifest.manifest_hash,
        )

        self.assertEqual(parsed.manifest_hash, manifest.manifest_hash)
        self.assertEqual(parsed.sandbox_id, manifest.sandbox_id)
        self.assertEqual(parsed.job_id, manifest.job_id)
        self.assertEqual(parsed.scope_id, manifest.scope_id)
        self.assertEqual(parsed.exfil_thresholds.soft_bytes, manifest.exfil_thresholds.soft_bytes)
        self.assertEqual(parsed.exfil_thresholds.hard_bytes, manifest.exfil_thresholds.hard_bytes)
        self.assertEqual(
            tuple((rule.host, rule.port, rule.proto) for rule in parsed.rules),
            tuple((rule.host, rule.port, rule.proto) for rule in manifest.rules),
        )


class EgressConnectProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        rule = EgressRule("allowed.test", 443, "https")
        bundle = PolicyBundleSigner(key_id="policy-key", secret=b"policy-secret").sign(
            PolicyBundle(
                bundle_version="2.0.0",
                egress_allowlist=(rule,),
                resource_ceilings=ResourceCeilings(1_000, 128 * 1024 * 1024, 0, 30, 1),
                risk_to_runtime={"standard": "docker"},
                seccomp_profile_hash="blake3:" + "0" * 64,
                signer_key_id="",
                signature="",
            )
        )
        scope = InMemoryTokenService(signing_key=b"scope-secret", now_fn=lambda: 1_000).mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(egress_allowlist=(rule,)),
        )
        self.manifest = EgressProxyManifest.materialize(
            sandbox_id="sandbox-1",
            scope_token=scope,
            policy_bundle=bundle,
        )
        self.resolver = _SequenceResolver(("127.0.0.2", "127.0.0.3"))
        self.connector = _RecordingConnector()
        self.events: list[tuple[str, dict[str, object]]] = []
        self.proxy = EgressConnectProxy(
            manifest=self.manifest,
            resolver=self.resolver,
            connector=self.connector,
            audit_sink=lambda event_type, payload: self.events.append((event_type, payload)),
            handshake_timeout_s=0.5,
        )

    def tearDown(self) -> None:
        self.connector.close()

    def test_default_deny_does_not_resolve_or_open_upstream(self) -> None:
        client, worker = self._start_handler()
        client.sendall(b"CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n")

        response = _read_headers(client)
        client.close()
        worker.join(timeout=1)

        self.assertIn(b"403", response)
        self.assertEqual(self.resolver.calls, [])
        self.assertEqual(self.connector.calls, [])
        self.assertEqual(self.events[-1][0], "egress.denied")
        self.assertEqual(self.events[-1][1]["host"], "denied.test")
        self.assertEqual(self.events[-1][1]["bytes_to_upstream"], 0)

    def test_https_sni_is_checked_before_dns_or_upstream_connect(self) -> None:
        client, worker = self._start_handler()
        client.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
        self.assertIn(b"200", _read_headers(client))
        client.sendall(_client_hello("other.test"))
        client.shutdown(socket.SHUT_WR)

        worker.join(timeout=1)
        client.close()

        self.assertEqual(self.resolver.calls, [])
        self.assertEqual(self.connector.calls, [])
        self.assertEqual(self.events[-1][0], "egress.denied")
        self.assertEqual(self.events[-1][1]["reason"], "sni_mismatch")
        self.assertEqual(self.events[-1][1]["bytes_to_upstream"], 0)

    def test_connection_resolves_once_pins_ip_and_forwards_buffered_client_hello(self) -> None:
        client, worker = self._start_handler()
        hello = _client_hello("allowed.test")
        client.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
        self.assertIn(b"200", _read_headers(client))
        client.sendall(hello)

        upstream = self.connector.wait_for_peer()
        self.assertEqual(_recv_exact(upstream, len(hello)), hello)
        upstream.sendall(b"reply-one")
        self.assertEqual(_recv_exact(client, len(b"reply-one")), b"reply-one")
        client.sendall(b"still-first-tunnel")
        self.assertEqual(_recv_exact(upstream, len(b"still-first-tunnel")), b"still-first-tunnel")
        client.close()
        upstream.close()
        worker.join(timeout=1)

        self.assertEqual(self.resolver.calls, [("allowed.test", 443)])
        self.assertEqual(self.connector.calls, [("127.0.0.2", 443)])
        allowed = next(payload for event_type, payload in self.events if event_type == "egress.allowed")
        self.assertEqual(allowed["resolved_ip"], "127.0.0.2")
        self.assertEqual(allowed["sni"], "allowed.test")

    def test_malformed_connect_is_denied_without_network_activity(self) -> None:
        client, worker = self._start_handler()
        client.sendall(b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")

        response = _read_headers(client)
        client.close()
        worker.join(timeout=1)

        self.assertIn(b"400", response)
        self.assertEqual(self.resolver.calls, [])
        self.assertEqual(self.connector.calls, [])
        self.assertEqual(self.events[-1][0], "egress.denied")

    def test_bidirectional_relay_preserves_large_payload_under_backpressure(self) -> None:
        left_client, left_proxy = socket.socketpair()
        right_proxy, right_server = socket.socketpair()
        right_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024)
        payload = (b"argus-egress-relay-" * 110_000)[: 2 * 1024 * 1024]
        relay_errors: list[BaseException] = []
        sender_errors: list[BaseException] = []

        def relay() -> None:
            try:
                _relay_bidirectional(left_proxy, right_proxy)
            except BaseException as exc:
                relay_errors.append(exc)

        def send() -> None:
            try:
                left_client.sendall(payload)
                left_client.shutdown(socket.SHUT_WR)
            except BaseException as exc:
                sender_errors.append(exc)

        relay_thread = threading.Thread(target=relay, daemon=True)
        sender_thread = threading.Thread(target=send, daemon=True)
        relay_thread.start()
        sender_thread.start()
        time.sleep(0.1)

        received = bytearray()
        right_server.settimeout(2)
        try:
            while len(received) < len(payload):
                try:
                    chunk = right_server.recv(64 * 1024)
                except TimeoutError:
                    break
                if not chunk:
                    break
                received.extend(chunk)
            right_server.shutdown(socket.SHUT_WR)
            sender_thread.join(timeout=2)
            relay_thread.join(timeout=2)
        finally:
            for sock in (left_client, left_proxy, right_proxy, right_server):
                sock.close()

        self.assertFalse(sender_thread.is_alive())
        self.assertFalse(relay_thread.is_alive())
        self.assertEqual(sender_errors, [])
        self.assertEqual(relay_errors, [])
        self.assertEqual(bytes(received), payload)

    def test_signed_soft_and_hard_thresholds_alert_then_truncate_and_drop(self) -> None:
        hello = _client_hello("allowed.test")
        thresholds = ExfilThresholds(
            soft_bytes=len(hello) + 4,
            hard_bytes=len(hello) + 8,
        )
        unsigned_manifest = replace(
            self.manifest,
            exfil_thresholds=thresholds,
            manifest_hash="",
        )
        manifest = replace(unsigned_manifest, manifest_hash=unsigned_manifest.computed_hash())
        events: list[tuple[str, dict[str, object]]] = []
        proxy = EgressConnectProxy(
            manifest=SidecarEgressProxyManifest.from_json(
                manifest.to_json(),
                expected_hash=manifest.manifest_hash,
            ),
            resolver=self.resolver,
            connector=self.connector,
            audit_sink=lambda event_type, payload: events.append((event_type, payload)),
            handshake_timeout_s=0.5,
        )
        client, accepted = socket.socketpair()
        client.settimeout(1)
        worker = threading.Thread(
            target=proxy.handle_connection,
            args=(accepted, ("local", 0)),
            daemon=True,
        )
        worker.start()

        client.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
        self.assertIn(b"200", _read_headers(client))
        client.sendall(hello)
        upstream = self.connector.wait_for_peer()
        self.assertEqual(_recv_exact(upstream, len(hello)), hello)
        client.sendall(b"0123456789abcdef")

        self.assertEqual(_recv_exact(upstream, 8), b"01234567")
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(client.recv(1), b"")
        client.close()
        upstream.close()

        threshold_events = [item for item in events if item[0].startswith("egress.exfil_")]
        self.assertEqual(
            [event_type for event_type, _ in threshold_events],
            ["egress.exfil_soft_alert", "egress.exfil_hard_halt"],
        )
        soft_payload = threshold_events[0][1]
        hard_payload = threshold_events[1][1]
        self.assertEqual(soft_payload["threshold_bytes"], thresholds.soft_bytes)
        self.assertGreaterEqual(soft_payload["bytes_to_upstream"], thresholds.soft_bytes)
        self.assertEqual(soft_payload["action"], "alert")
        self.assertEqual(hard_payload["threshold_bytes"], thresholds.hard_bytes)
        self.assertEqual(hard_payload["bytes_to_upstream"], thresholds.hard_bytes)
        self.assertEqual(hard_payload["dropped_bytes"], 8)
        self.assertEqual(hard_payload["action"], "drop_and_halt")

    def test_exfil_meter_enforces_one_aggregate_hard_cap_under_concurrency(self) -> None:
        meter = _ExfiltrationByteMeter(soft_bytes=16, hard_bytes=32)
        barrier = threading.Barrier(8)
        reservations = []
        lock = threading.Lock()

        def reserve() -> None:
            barrier.wait()
            result = meter.reserve(8)
            with lock:
                reservations.append(result)

        workers = [threading.Thread(target=reserve, daemon=True) for _ in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=1)

        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(sum(item.permitted_bytes for item in reservations), 32)
        self.assertEqual(sum(item.dropped_bytes for item in reservations), 32)
        observations = [
            meter.commit(item.permitted_bytes)
            for item in reservations
            if item.permitted_bytes
        ]
        self.assertEqual(sum(item.soft_alert for item in observations), 1)
        self.assertEqual(sum(item.hard_halt for item in observations), 1)
        self.assertEqual(meter.bytes_to_upstream, 32)

    def test_concurrent_threshold_callbacks_publish_soft_before_hard(self) -> None:
        thresholds = ExfilThresholds(soft_bytes=16, hard_bytes=32)
        unsigned_manifest = replace(
            self.manifest,
            exfil_thresholds=thresholds,
            manifest_hash="",
        )
        manifest = replace(unsigned_manifest, manifest_hash=unsigned_manifest.computed_hash())
        events: list[tuple[str, dict[str, object]]] = []
        proxy = EgressConnectProxy(
            manifest=SidecarEgressProxyManifest.from_json(
                manifest.to_json(),
                expected_hash=manifest.manifest_hash,
            ),
            resolver=self.resolver,
            connector=self.connector,
            audit_sink=lambda event_type, payload: events.append((event_type, payload)),
        )
        meter = _ExfiltrationByteMeter(soft_bytes=16, hard_bytes=32)
        soft_committed = threading.Event()
        release_soft_callback = threading.Event()
        worker_errors: list[BaseException] = []

        def publish(observation: object) -> None:
            proxy._emit_exfil_events(  # type: ignore[arg-type]
                observation,
                host="allowed.test",
                port=443,
                proto="https",
                sni="allowed.test",
                resolved_ip="127.0.0.2",
            )

        def cross_soft_threshold() -> None:
            try:
                reservation = meter.reserve(16)
                observation = meter.commit(reservation.permitted_bytes)
                soft_committed.set()
                if not release_soft_callback.wait(timeout=1):
                    raise TimeoutError("hard threshold callback did not complete")
                publish(observation)
            except BaseException as exc:
                worker_errors.append(exc)

        def cross_hard_threshold() -> None:
            try:
                if not soft_committed.wait(timeout=1):
                    raise TimeoutError("soft threshold was not committed")
                reservation = meter.reserve(16)
                observation = meter.commit(reservation.permitted_bytes)
                publish(observation)
            except BaseException as exc:
                worker_errors.append(exc)
            finally:
                release_soft_callback.set()

        soft_worker = threading.Thread(target=cross_soft_threshold, daemon=True)
        hard_worker = threading.Thread(target=cross_hard_threshold, daemon=True)
        soft_worker.start()
        hard_worker.start()
        soft_worker.join(timeout=2)
        hard_worker.join(timeout=2)

        self.assertFalse(soft_worker.is_alive())
        self.assertFalse(hard_worker.is_alive())
        self.assertEqual(worker_errors, [])
        self.assertEqual(
            [event_type for event_type, _ in events],
            ["egress.exfil_soft_alert", "egress.exfil_hard_halt"],
        )

    def test_meter_releases_unsent_capacity_after_partial_upstream_failure(self) -> None:
        class PartialSendSocket:
            def __init__(self) -> None:
                self.calls = 0

            def send(self, payload: memoryview) -> int:
                self.calls += 1
                if self.calls == 1:
                    return min(len(payload), 8)
                raise BrokenPipeError("fixture upstream closed")

        meter = _ExfiltrationByteMeter(soft_bytes=16, hard_bytes=32)
        observations = []
        with self.assertRaises(BrokenPipeError):
            _send_metered_payload(
                PartialSendSocket(),  # type: ignore[arg-type]
                b"x" * 32,
                meter=meter,
                event_sink=observations.append,
            )

        self.assertEqual(meter.bytes_to_upstream, 8)
        self.assertFalse(any(item.soft_alert or item.hard_halt for item in observations))
        retry = meter.reserve(32)
        self.assertEqual(retry.permitted_bytes, 24)
        final = meter.commit(retry.permitted_bytes)
        self.assertTrue(final.soft_alert)
        self.assertTrue(final.hard_halt)
        self.assertEqual(final.bytes_to_upstream, 32)

    def _start_handler(self) -> tuple[socket.socket, threading.Thread]:
        client, accepted = socket.socketpair()
        client.settimeout(1)
        worker = threading.Thread(
            target=self.proxy.handle_connection,
            args=(accepted, ("local", 0)),
            daemon=True,
        )
        worker.start()
        return client, worker


class LinuxEgressFirewallTests(unittest.TestCase):
    def test_default_drop_allows_sandbox_only_to_loopback_proxy(self) -> None:
        commands = LinuxEgressFirewall(
            proxy_port=15001,
            proxy_uid=65531,
            sandbox_uid=65532,
        ).commands()

        self.assertIn(("iptables", "-P", "OUTPUT", "DROP"), commands)
        self.assertIn(
            (
                "iptables",
                "-A",
                "OUTPUT",
                "-o",
                "lo",
                "-p",
                "tcp",
                "--dport",
                "15001",
                "-m",
                "owner",
                "--uid-owner",
                "65532",
                "-j",
                "ACCEPT",
            ),
            commands,
        )
        sandbox_accepts = [command for command in commands if "65532" in command and "ACCEPT" in command]
        self.assertEqual({command[0] for command in sandbox_accepts}, {"iptables", "ip6tables"})
        self.assertTrue(all("53" not in command for command in sandbox_accepts))

    def test_proxy_rules_are_uid_bound_and_survive_worker_exit(self) -> None:
        firewall = LinuxEgressFirewall(proxy_port=15001, proxy_uid=65531, sandbox_uid=65532)
        commands = firewall.commands()

        proxy_accepts = [command for command in commands if "65531" in command and "ACCEPT" in command]
        self.assertTrue(any("tcp" in command for command in proxy_accepts))
        self.assertTrue(any("udp" in command and "53" in command for command in proxy_accepts))
        self.assertTrue(all("--pid-owner" not in command for command in commands))
        self.assertEqual(commands[-1], ("iptables", "-P", "OUTPUT", "DROP"))

    def test_custom_dns_port_is_the_only_udp_destination_granted_to_proxy_uid(self) -> None:
        commands = LinuxEgressFirewall(
            proxy_port=15001,
            proxy_uid=65531,
            sandbox_uid=65532,
            dns_port=5353,
        ).commands()

        proxy_udp_accepts = [
            command
            for command in commands
            if "65531" in command and "udp" in command and "ACCEPT" in command
        ]
        self.assertEqual(len(proxy_udp_accepts), 2)
        self.assertTrue(all(command[command.index("--dport") + 1] == "5353" for command in proxy_udp_accepts))

    def test_apply_preflights_coherent_dual_stack_backend_before_mutation(self) -> None:
        commands: list[tuple[str, ...]] = []

        def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
            normalized = tuple(command)
            commands.append(normalized)
            version = "iptables v1.8.11 (nf_tables)\n" if normalized[0] == "iptables" else "ip6tables v1.8.11 (nf_tables)\n"
            return SimpleNamespace(
                returncode=0,
                stdout=version if normalized[1:] == ("--version",) else "",
                stderr="",
            )

        with patch("argus_runtime.s10_egress_proxy_service.subprocess.run", side_effect=run):
            LinuxEgressFirewall(proxy_port=15001, proxy_uid=65531, sandbox_uid=65532).apply()

        self.assertEqual(
            commands[:4],
            [
                ("iptables", "--version"),
                ("ip6tables", "--version"),
                ("iptables", "-S", "OUTPUT"),
                ("ip6tables", "-S", "OUTPUT"),
            ],
        )
        self.assertEqual(commands[4], ("iptables", "-F", "OUTPUT"))

    def test_apply_rejects_mismatched_backends_before_mutation(self) -> None:
        commands: list[tuple[str, ...]] = []

        def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
            normalized = tuple(command)
            commands.append(normalized)
            backend = "nf_tables" if normalized[0] == "iptables" else "legacy"
            return SimpleNamespace(
                returncode=0,
                stdout=f"{normalized[0]} v1.8.11 ({backend})\n",
                stderr="",
            )

        with (
            patch("argus_runtime.s10_egress_proxy_service.subprocess.run", side_effect=run),
            self.assertRaisesRegex(RuntimeError, "coherent"),
        ):
            LinuxEgressFirewall(proxy_port=15001, proxy_uid=65531, sandbox_uid=65532).apply()

        self.assertEqual(commands, [("iptables", "--version"), ("ip6tables", "--version")])

    def test_apply_rejects_unavailable_ipv6_table_before_mutation(self) -> None:
        commands: list[tuple[str, ...]] = []

        def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
            normalized = tuple(command)
            commands.append(normalized)
            if normalized[1:] == ("--version",):
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"{normalized[0]} v1.8.11 (nf_tables)\n",
                    stderr="",
                )
            if normalized == ("ip6tables", "-S", "OUTPUT"):
                return SimpleNamespace(returncode=1, stdout="", stderr="table unavailable")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch("argus_runtime.s10_egress_proxy_service.subprocess.run", side_effect=run),
            patch(
                "argus_runtime.s10_egress_proxy_service._effective_capabilities",
                return_value="00000000000030c0",
            ),
            self.assertRaisesRegex(RuntimeError, "preflight"),
        ):
            LinuxEgressFirewall(proxy_port=15001, proxy_uid=65531, sandbox_uid=65532).apply()

        self.assertFalse(any(command[1] in {"-F", "-A", "-P"} for command in commands))


class EgressFirewallBackendContractTests(unittest.TestCase):
    def test_images_and_battery_use_the_system_coherent_backend(self) -> None:
        root = Path(__file__).resolve().parents[1]
        dockerfile = (root / "deploy/argus-m0/security/egress-sidecar.Dockerfile").read_text(
            encoding="utf-8"
        )
        battery = (root / "scripts/run_s10_egress_battery.py").read_text(encoding="utf-8")

        self.assertEqual(egress_battery.FIREWALL_BINARIES, ("iptables", "ip6tables"))
        self.assertNotIn("update-alternatives --set", dockerfile)
        self.assertNotIn("iptables-legacy", dockerfile)
        self.assertNotIn("ip6tables-legacy", dockerfile)
        self.assertNotIn("iptables-legacy", battery)
        self.assertNotIn("ip6tables-legacy", battery)


class EgressBatteryCaptureTests(unittest.TestCase):
    def test_packet_capture_observes_only_traffic_leaving_the_sandbox_namespace(self) -> None:
        captured_commands: list[list[str]] = []

        class CaptureProcess:
            returncode = 0

            def __init__(self) -> None:
                self.running = True

            def poll(self) -> int | None:
                return None if self.running else self.returncode

            def send_signal(self, _signum: int) -> None:
                self.running = False

            def wait(self, timeout: float) -> int:
                del timeout
                self.running = False
                return self.returncode

            def kill(self) -> None:
                self.running = False

        def popen(command: list[str], **_kwargs: object) -> CaptureProcess:
            captured_commands.append(command)
            return CaptureProcess()

        with tempfile.TemporaryDirectory(prefix="argus-egress-capture-test-") as temp_dir:
            with (
                patch.object(egress_battery, "_command", return_value=SimpleNamespace(stdout="123\n")),
                patch.object(egress_battery.subprocess, "Popen", side_effect=popen),
                patch.object(egress_battery.time, "sleep"),
            ):
                capture = egress_battery._start_capture(
                    "sandbox",
                    Path(temp_dir) / "capture.txt",
                    cwd=Path(temp_dir),
                )
                capture.stop()

        self.assertEqual(
            captured_commands,
            [[
                "nsenter",
                "-t",
                "123",
                "-n",
                "tcpdump",
                "-i",
                "eth0",
                "-Q",
                "out",
                "-nn",
                "-tt",
                "-l",
            ]],
        )


class EgressSidecarRuntimeConfigTests(unittest.TestCase):
    def test_environment_materializes_digest_pinned_sidecar_and_custom_dns(self) -> None:
        environment = {
            "ARGUS_S10_EGRESS_SIDECAR_IMAGE": "registry.test/argus-egress@sha256:" + "a" * 64,
            "ARGUS_S10_EGRESS_NETWORK_MODE": "argus-egress-net",
            "ARGUS_S10_EGRESS_DNS_SERVERS": "192.0.2.10,2001:db8::10",
            "ARGUS_S10_EGRESS_DNS_PORT": "5353",
            "ARGUS_S10_EGRESS_LISTEN_PORT": "16001",
        }
        with patch.dict(os.environ, environment, clear=True):
            config = _egress_sidecar_runtime_config_from_env()

        self.assertIsNotNone(config)
        assert config is not None
        self.assertEqual(config.network_mode, "argus-egress-net")
        self.assertEqual(config.dns_servers, ("192.0.2.10", "2001:db8::10"))
        self.assertEqual(config.dns_port, 5353)
        self.assertEqual(config.proxy_port, 16001)


class DockerEgressSidecarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = EgressRule("allowed.test", 443, "https")
        self.bundle = PolicyBundleSigner(key_id="policy-key", secret=b"policy-secret").sign(
            PolicyBundle(
                bundle_version="2.0.0",
                egress_allowlist=(self.rule,),
                resource_ceilings=ResourceCeilings(1_000, 128 * 1024 * 1024, 0, 30, 1),
                risk_to_runtime={"standard": "docker"},
                seccomp_profile_hash="blake3:" + "0" * 64,
                signer_key_id="",
                signature="",
            )
        )
        self.tokens = InMemoryTokenService(signing_key=b"scope-secret", now_fn=lambda: 1_000)
        scope = self.tokens.mint_scope(job_id="job-1", scopes=ScopeGrant(egress_allowlist=(self.rule,)))
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
            job_id="job-1",
            root_request_id="root-1",
        )
        self.request = LaunchRequest(
            job_id="job-1",
            subagent_id="subagent-1",
            trace_id="trace-1",
            budget_token=budget,
            scope_token=scope,
            image="sha256:" + "b" * 64,
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
            sandbox_id="sandbox-1",
            job_id="job-1",
            runtime_class="docker",
            budget_epoch=1,
            policy_bundle_version="2.0.0",
            state="ADMITTED",
        )
        self.config = EgressSidecarRuntimeConfig(image="sha256:" + "a" * 64, startup_timeout_s=0.1)

    def test_docker_api_launches_attested_sidecar_and_shares_only_its_network_namespace(self) -> None:
        supervisor = _CapturingEgressDockerSupervisor(self.config)
        events: list[tuple[str, dict[str, object]]] = []

        result = supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            policy_bundle=self.bundle,
            egress_audit_sink=lambda event_type, payload: events.append((event_type, payload)),
        )

        self.assertEqual(result.exit_code, 0)
        creates = [call for call in supervisor.calls if call[0] == "POST" and call[1].startswith("/containers/create")]
        self.assertEqual(len(creates), 2)
        sidecar = creates[0][2]
        sandbox = creates[1][2]
        self.assertEqual(sidecar["Image"], self.config.image)
        self.assertTrue(sidecar["HostConfig"]["ReadonlyRootfs"])
        self.assertEqual(
            sidecar["HostConfig"]["CapAdd"],
            ["NET_ADMIN", "NET_RAW", "SETGID", "SETUID"],
        )
        self.assertNotIn("Sysctls", sidecar["HostConfig"])
        self.assertEqual(sandbox["HostConfig"]["NetworkMode"], "container:egress-sidecar-id")
        self.assertFalse(sandbox["NetworkDisabled"])
        self.assertIn("HTTPS_PROXY=http://127.0.0.1:15001", sandbox["Env"])
        self.assertIn("ALL_PROXY=http://127.0.0.1:15001", sandbox["Env"])
        self.assertTrue(any(event_type == "egress.ready" for event_type, _ in events))
        deletes = [path for method, path, _ in supervisor.calls if method == "DELETE"]
        self.assertEqual(deletes[-2:], [
            "/containers/sandbox-container-id?force=true",
            "/containers/egress-sidecar-id?force=true",
        ])

    def test_sidecar_readiness_failure_prevents_sandbox_creation(self) -> None:
        supervisor = _CapturingEgressDockerSupervisor(self.config, sidecar_ready=False)

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "ready"):
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                policy_bundle=self.bundle,
            )

        creates = [call for call in supervisor.calls if call[0] == "POST" and call[1].startswith("/containers/create")]
        self.assertEqual(len(creates), 1)
        self.assertEqual(creates[0][2]["Image"], self.config.image)

    def test_sidecar_readiness_rejects_retained_effective_capabilities(self) -> None:
        supervisor = _CapturingEgressDockerSupervisor(
            self.config,
            ready_effective_capabilities="0000000000002000",
        )

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "effective capabilities"):
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                policy_bundle=self.bundle,
            )

        creates = [call for call in supervisor.calls if call[0] == "POST" and call[1].startswith("/containers/create")]
        self.assertEqual(len(creates), 1)

    def test_sidecar_startup_failure_reports_bounded_runtime_error(self) -> None:
        supervisor = _CapturingEgressDockerSupervisor(
            self.config,
            sidecar_ready=False,
            sidecar_running=False,
            sidecar_stderr="fatal\nfirewall setup failed " + "x" * 2_000,
        )

        with self.assertRaises(SandboxRuntimeUnavailableError) as raised:
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                policy_bundle=self.bundle,
            )
        message = str(raised.exception)
        prefix = "egress sidecar exited before it became ready: "
        self.assertIn("fatal firewall setup failed", message)
        self.assertLessEqual(len(message), len(prefix) + 1_024)

    def test_empty_policy_scope_intersection_still_runs_default_deny_sidecar(self) -> None:
        empty_scope = self.tokens.mint_scope(job_id="job-1", scopes=ScopeGrant())
        request = replace(self.request, scope_token=empty_scope)
        supervisor = _CapturingEgressDockerSupervisor(self.config)

        result = supervisor.run(
            handle=self.handle,
            request=request,
            materialized_env={},
            policy_bundle=self.bundle,
        )

        self.assertEqual(result.exit_code, 0)
        creates = [call for call in supervisor.calls if call[0] == "POST" and call[1].startswith("/containers/create")]
        self.assertEqual(len(creates), 2)
        manifest = json.loads(
            next(
                item.removeprefix("ARGUS_S10_EGRESS_MANIFEST_JSON=")
                for item in creates[0][2]["Env"]
                if item.startswith("ARGUS_S10_EGRESS_MANIFEST_JSON=")
            )
        )
        self.assertEqual(manifest["rules"], [])

    def test_sidecar_is_removed_even_when_sandbox_cleanup_fails(self) -> None:
        supervisor = _CapturingEgressDockerSupervisor(self.config, sandbox_delete_error=True)

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "sandbox cleanup failed"):
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                policy_bundle=self.bundle,
            )

        deletes = [path for method, path, _ in supervisor.calls if method == "DELETE"]
        self.assertIn("/containers/sandbox-container-id?force=true", deletes)
        self.assertIn("/containers/egress-sidecar-id?force=true", deletes)

    def test_cleanup_failure_does_not_mask_primary_runtime_failure(self) -> None:
        supervisor = _CapturingEgressDockerSupervisor(
            self.config,
            runtime_error=SandboxRuntimeUnavailableError("primary runtime failure"),
            sandbox_delete_error=True,
        )

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "primary runtime failure") as raised:
            supervisor.run(
                handle=self.handle,
                request=self.request,
                materialized_env={},
                policy_bundle=self.bundle,
            )

        self.assertTrue(
            any("sandbox cleanup failed" in note for note in getattr(raised.exception, "__notes__", ()))
        )

    def test_live_hard_limit_event_is_ingested_once_before_freeze_and_terminate(self) -> None:
        supervisor = _CapturingEgressDockerSupervisor(self.config, emit_exfil_halt=True)
        events: list[tuple[str, dict[str, object]]] = []
        samples = []
        halt_telemetry = []

        result = supervisor.run(
            handle=self.handle,
            request=self.request,
            materialized_env={},
            policy_bundle=self.bundle,
            egress_audit_sink=lambda event_type, payload: events.append((event_type, payload)),
            meter_sample_sink=samples.append,
            halt_telemetry_sink=halt_telemetry.append,
        )

        self.assertTrue(result.timed_out)
        self.assertIsNotNone(result.partial_result)
        assert result.partial_result is not None
        self.assertEqual(result.partial_result.reason, "exfil_hard_limit")
        self.assertTrue(result.partial_result.freeze_succeeded)
        self.assertTrue(result.partial_result.terminate_succeeded)
        self.assertEqual(
            [event_type for event_type, _ in events],
            ["egress.ready", "egress.exfil_soft_alert", "egress.exfil_hard_halt"],
        )
        self.assertEqual(sum(event_type == "egress.exfil_hard_halt" for event_type, _ in events), 1)
        hard_payload = events[-1][1]
        self.assertEqual(hard_payload["bytes_to_upstream"], self.bundle.exfil_thresholds.hard_bytes)
        self.assertTrue(any(sample.source == "egress-sidecar-byte-meter" for sample in samples))
        self.assertTrue(any("exfil_bytes" in sample.breached_dimensions for sample in samples))
        self.assertEqual(len(halt_telemetry), 1)
        self.assertEqual(halt_telemetry[0].reason, "exfil_hard_limit")

        paths = [(method, path) for method, path, _ in supervisor.calls]
        pause_index = paths.index(("POST", "/containers/sandbox-container-id/pause"))
        kill_index = paths.index(("POST", "/containers/sandbox-container-id/kill"))
        self.assertLess(pause_index, kill_index)

    def test_malformed_hard_limit_evidence_cannot_trigger_a_trusted_halt(self) -> None:
        malformed_cases = (
            {"hard_event_byte_delta": -1},
            {"hard_event_attempted_delta": 0},
        )
        for overrides in malformed_cases:
            with self.subTest(overrides=overrides):
                supervisor = _CapturingEgressDockerSupervisor(
                    self.config,
                    emit_exfil_halt=True,
                    **overrides,
                )

                with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "exfil threshold"):
                    supervisor.run(
                        handle=self.handle,
                        request=self.request,
                        materialized_env={},
                        policy_bundle=self.bundle,
                    )

                paths = [(method, path) for method, path, _ in supervisor.calls]
                self.assertNotIn(("POST", "/containers/sandbox-container-id/pause"), paths)


class _CapturingEgressDockerSupervisor(DockerSandboxSupervisor):
    def __init__(
        self,
        config: EgressSidecarRuntimeConfig,
        *,
        sidecar_ready: bool = True,
        sidecar_running: bool = True,
        sidecar_stderr: str = "",
        sandbox_delete_error: bool = False,
        ready_effective_capabilities: str = "0000000000000000",
        runtime_error: Exception | None = None,
        emit_exfil_halt: bool = False,
        hard_event_byte_delta: int = 0,
        hard_event_attempted_delta: int = 1,
    ) -> None:
        super().__init__(docker_bin="/usr/bin/docker", egress_sidecar_config=config)
        self._docker_socket_path = "/tmp/fake-docker.sock"
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.sidecar_ready = sidecar_ready
        self.sidecar_running = sidecar_running
        self.sidecar_stderr = sidecar_stderr
        self.sandbox_delete_error = sandbox_delete_error
        self.ready_effective_capabilities = ready_effective_capabilities
        self.runtime_error = runtime_error
        self.emit_exfil_halt = emit_exfil_halt
        self.hard_event_byte_delta = hard_event_byte_delta
        self.hard_event_attempted_delta = hard_event_attempted_delta
        self.sidecar_payload: dict[str, object] = {}
        self.sandbox_payload: dict[str, object] = {}
        self.sidecar_log_reads = 0

    def _docker_api_request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        expected: tuple[int, ...],
        timeout: float = 10,
    ) -> dict:
        del expected, timeout
        payload = body or {}
        self.calls.append((method, path, payload))
        if (
            method == "DELETE"
            and path == "/containers/sandbox-container-id?force=true"
            and self.sandbox_delete_error
        ):
            raise SandboxRuntimeUnavailableError("sandbox cleanup failed")
        if method == "POST" and path.startswith("/containers/create"):
            if not self.sidecar_payload:
                self.sidecar_payload = payload
                return {"Id": "egress-sidecar-id"}
            self.sandbox_payload = payload
            return {"Id": "sandbox-container-id"}
        if method == "GET" and path == "/containers/egress-sidecar-id/json":
            return {
                "Config": {
                    "Image": self.sidecar_payload["Image"],
                    "User": self.sidecar_payload["User"],
                    "Entrypoint": self.sidecar_payload["Entrypoint"],
                    "Cmd": self.sidecar_payload["Cmd"],
                    "Env": self.sidecar_payload["Env"],
                },
                "HostConfig": self.sidecar_payload["HostConfig"],
                "State": {"Running": self.sidecar_running},
            }
        if method == "GET" and path == "/containers/sandbox-container-id/json":
            return {
                "Config": {
                    "User": self.sandbox_payload["User"],
                    "Env": self.sandbox_payload["Env"],
                },
                "HostConfig": self.sandbox_payload["HostConfig"],
                "State": {"Running": self.emit_exfil_halt, "ExitCode": 0},
            }
        return {}

    def _docker_api_logs(self, container_id: str):  # type: ignore[no-untyped-def]
        from argus_core import s10 as s10_module

        if container_id == "egress-sidecar-id":
            self.sidecar_log_reads += 1
            manifest = json.loads(
                next(
                    item.removeprefix("ARGUS_S10_EGRESS_MANIFEST_JSON=")
                    for item in self.sidecar_payload["Env"]
                    if item.startswith("ARGUS_S10_EGRESS_MANIFEST_JSON=")
                )
            )
            stdout = ""
            if self.sidecar_ready:
                stdout = json.dumps(
                    {
                        "event_type": "egress.ready",
                        "payload": {
                            "sandbox_id": manifest["sandbox_id"],
                            "job_id": manifest["job_id"],
                            "scope_id": manifest["scope_id"],
                            "policy_bundle_version": manifest["policy_bundle_version"],
                            "manifest_hash": manifest["manifest_hash"],
                            "effective_capabilities": self.ready_effective_capabilities,
                            "listen_host": "127.0.0.1",
                            "listen_port": 15001,
                            "proxy_uid": 65531,
                            "rule_count": len(manifest["rules"]),
                        },
                    }
                ) + "\n"
                if self.emit_exfil_halt and self.sidecar_log_reads > 1:
                    common = {
                        "sandbox_id": manifest["sandbox_id"],
                        "job_id": manifest["job_id"],
                        "scope_id": manifest["scope_id"],
                        "policy_bundle_version": manifest["policy_bundle_version"],
                        "manifest_hash": manifest["manifest_hash"],
                        "host": "allowed.test",
                        "port": 443,
                        "proto": "https",
                        "sni": "allowed.test",
                        "resolved_ip": "192.0.2.10",
                    }
                    stdout += json.dumps(
                        {
                            "event_type": "egress.exfil_soft_alert",
                            "payload": {
                                **common,
                                "bytes_to_upstream": manifest["exfil_thresholds"]["soft_bytes"],
                                "attempted_bytes": manifest["exfil_thresholds"]["soft_bytes"],
                                "threshold_bytes": manifest["exfil_thresholds"]["soft_bytes"],
                                "dropped_bytes": 0,
                                "action": "alert",
                            },
                        }
                    ) + "\n"
                    stdout += json.dumps(
                        {
                            "event_type": "egress.exfil_hard_halt",
                            "payload": {
                                **common,
                                "bytes_to_upstream": (
                                    manifest["exfil_thresholds"]["hard_bytes"] + self.hard_event_byte_delta
                                ),
                                "attempted_bytes": (
                                    manifest["exfil_thresholds"]["hard_bytes"]
                                    + self.hard_event_attempted_delta
                                ),
                                "threshold_bytes": manifest["exfil_thresholds"]["hard_bytes"],
                                "dropped_bytes": 1,
                                "action": "drop_and_halt",
                            },
                        }
                    ) + "\n"
        else:
            stdout = "ok\n"
        return s10_module._DockerLogCapture(
            stdout=stdout,
            stderr=self.sidecar_stderr if container_id == "egress-sidecar-id" else "",
            stdout_bytes=len(stdout.encode()),
            stderr_bytes=len(self.sidecar_stderr.encode()) if container_id == "egress-sidecar-id" else 0,
            log_capture_limit_bytes=s10_module.PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES,
            truncated=False,
        )

    def _docker_api_resource_sample(self, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        raise AssertionError("completed fake container must not be metered")

    def _wait_for_container_with_meter(self, **kwargs):  # type: ignore[no-untyped-def]
        if self.runtime_error is not None:
            raise self.runtime_error
        return super()._wait_for_container_with_meter(**kwargs)


class _SequenceResolver:
    def __init__(self, answers: tuple[str, ...]) -> None:
        self._answers = iter(answers)
        self.calls: list[tuple[str, int]] = []

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        return (next(self._answers),)


class _RecordingConnector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []
        self._peers: list[socket.socket] = []
        self._ready = threading.Event()

    def __call__(self, ip: str, port: int, timeout_s: float) -> socket.socket:
        del timeout_s
        self.calls.append((ip, port))
        proxy, peer = socket.socketpair()
        self._peers.append(peer)
        self._ready.set()
        return proxy

    def wait_for_peer(self) -> socket.socket:
        if not self._ready.wait(timeout=1):
            raise AssertionError("proxy did not open the upstream connection")
        return self._peers[-1]

    def close(self) -> None:
        for peer in self._peers:
            try:
                peer.close()
            except OSError:
                pass


def _client_hello(server_name: str) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_name)
    with unittest.TestCase().assertRaises(ssl.SSLWantReadError):
        client.do_handshake()
    return outgoing.read()


def _read_headers(sock: socket.socket) -> bytes:
    payload = bytearray()
    while b"\r\n\r\n" not in payload:
        chunk = sock.recv(4096)
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    sock.settimeout(1)
    payload = bytearray()
    deadline = time.monotonic() + 1
    while len(payload) < size and time.monotonic() < deadline:
        chunk = sock.recv(size - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


if __name__ == "__main__":
    unittest.main()
