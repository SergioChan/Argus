#!/usr/bin/env python3
"""Run the real Linux S10 egress sidecar security battery or its container fixtures."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


FIXTURE_PORT = 8443
TC33_SOFT_BYTES = 16 * 1024
TC33_HARD_BYTES = 32 * 1024
FIREWALL_BINARIES = ("iptables", "ip6tables")
FIREWALL_IPV4_BIN, FIREWALL_IPV6_BIN = FIREWALL_BINARIES


def _json_line(event_type: str, payload: dict[str, Any]) -> None:
    print(json.dumps({"event_type": event_type, "payload": payload}, sort_keys=True), flush=True)


def _run_dns_fixture(answer_a: str, answer_b: str) -> None:
    answers = [str(ipaddress.IPv4Address(answer_a)), str(ipaddress.IPv4Address(answer_b))]
    state = {"index": 0, "running": True}

    def rebind(_signum: int, _frame: object) -> None:
        state["index"] = 1
        _json_line("dns.rebound", {"answer": answers[1]})

    def stop(_signum: int, _frame: object) -> None:
        state["running"] = False

    signal.signal(signal.SIGUSR1, rebind)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 53))
        server.settimeout(0.2)
        _json_line("fixture.ready", {"kind": "dns", "answers": answers})
        while state["running"]:
            try:
                query, peer = server.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                response, qname = _dns_a_response(query, answers[state["index"]])
            except ValueError as exc:
                _json_line("dns.invalid", {"reason": str(exc)})
                continue
            _json_line(
                "dns.query",
                {
                    "qname": qname,
                    "answer": answers[state["index"]],
                    "peer": peer[0],
                },
            )
            server.sendto(response, peer)


def _dns_a_response(query: bytes, answer: str) -> tuple[bytes, str]:
    if len(query) < 17:
        raise ValueError("query_too_short")
    transaction_id, _flags, qdcount = struct.unpack("!HHH", query[:6])
    if qdcount != 1:
        raise ValueError("one_question_required")
    labels: list[str] = []
    offset = 12
    while True:
        if offset >= len(query):
            raise ValueError("qname_incomplete")
        size = query[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(query):
            raise ValueError("qname_invalid")
        labels.append(query[offset : offset + size].decode("ascii"))
        offset += size
    if offset + 4 > len(query):
        raise ValueError("question_incomplete")
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    question_end = offset + 4
    qname = ".".join(labels).lower()
    if qtype != 1 or qclass != 1:
        header = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 0, 0, 0)
        return header + query[12:question_end], qname
    header = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
    answer_record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(answer)
    return header + query[12:question_end] + answer_record, qname


def _run_backend_fixture(label: str) -> None:
    stop_event = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", FIXTURE_PORT))
        server.listen(16)
        server.settimeout(0.2)
        _json_line("fixture.ready", {"kind": "backend", "label": label, "port": FIXTURE_PORT})
        workers: list[threading.Thread] = []
        while not stop_event.is_set():
            try:
                connection, peer = server.accept()
            except socket.timeout:
                continue
            worker = threading.Thread(
                target=_serve_backend_connection,
                args=(connection, peer, label),
                daemon=True,
            )
            workers.append(worker)
            worker.start()


def _serve_backend_connection(connection: socket.socket, peer: tuple[str, int], label: str) -> None:
    _json_line("backend.accepted", {"label": label, "peer": peer[0]})
    with connection:
        connection.settimeout(5)
        while True:
            try:
                chunk = connection.recv(64 * 1024)
            except socket.timeout:
                return
            if not chunk:
                return
            _json_line("backend.bytes", {"label": label, "count": len(chunk)})
            connection.sendall(label.encode("ascii") + b"\n")


def _run_sandbox_fixture() -> None:
    dns_ip = os.environ["ARGUS_EGRESS_TEST_DNS_IP"]
    backend_a_ip = os.environ["ARGUS_EGRESS_TEST_BACKEND_A_IP"]
    proxy_url = os.environ["ARGUS_EGRESS_PROXY"]
    proxy_host, proxy_port = _proxy_address(proxy_url)
    phase_release_event = threading.Event()
    action_release_event = threading.Event()
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: phase_release_event.set())
    signal.signal(signal.SIGUSR2, lambda _signum, _frame: action_release_event.set())

    def wait_for_release(event: threading.Event, phase: str) -> None:
        if not event.wait(timeout=10):
            raise RuntimeError(f"host did not release sandbox phase {phase}")
        event.clear()

    print("PHASE capture-ready", flush=True)
    wait_for_release(phase_release_event, "capture-ready")

    results: dict[str, Any] = {}
    results["direct_tcp_blocked"] = _tcp_blocked(backend_a_ip, FIXTURE_PORT)
    results["direct_dns_blocked"] = _dns_blocked(dns_ip)

    denied = _open_connect(proxy_host, proxy_port, "denied.test", FIXTURE_PORT)
    results["default_deny_status"] = denied[0]
    denied[1].close()
    print("PHASE default-deny-complete", flush=True)
    wait_for_release(phase_release_event, "default-deny-complete")

    mismatch_status, mismatch = _open_connect(proxy_host, proxy_port, "allowed.test", FIXTURE_PORT)
    if mismatch_status != 200:
        raise RuntimeError(f"SNI mismatch tunnel was not admitted for inspection: {mismatch_status}")
    mismatch.sendall(_client_hello("wrong.test"))
    mismatch.settimeout(1)
    try:
        mismatch_payload = mismatch.recv(1)
    except (ConnectionError, OSError):
        mismatch_payload = b""
    mismatch.close()
    results["sni_mismatch_closed"] = mismatch_payload == b""

    first, first_label = _open_tls_tunnel(proxy_host, proxy_port, "allowed.test", FIXTURE_PORT)
    results["first_resolved_backend"] = first_label
    print("PHASE dns-pin-ready", flush=True)
    wait_for_release(action_release_event, "dns-pin-ready")
    first.sendall(b"same-tunnel")
    results["pinned_backend_after_rebind"] = _readline(first)
    first.close()

    second, second_label = _open_tls_tunnel(proxy_host, proxy_port, "allowed.test", FIXTURE_PORT)
    results["second_resolved_backend"] = second_label
    second.close()

    print("PHASE crash-ready", flush=True)
    wait_for_release(action_release_event, "crash-ready")
    results["proxy_connect_blocked_after_crash"] = _tcp_blocked(proxy_host, proxy_port)
    results["direct_tcp_blocked_after_crash"] = _tcp_blocked(backend_a_ip, FIXTURE_PORT)
    results["direct_dns_blocked_after_crash"] = _dns_blocked(dns_ip)
    print(json.dumps({"sandbox_results": results}, sort_keys=True), flush=True)
    print("PHASE post-crash-complete", flush=True)
    wait_for_release(phase_release_event, "post-crash-complete")


def _run_exfil_sandbox_fixture() -> None:
    proxy_host, proxy_port = _proxy_address(os.environ["ARGUS_EGRESS_PROXY"])
    release_event = threading.Event()
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: release_event.set())
    print("PHASE exfil-ready", flush=True)
    if not release_event.wait(timeout=10):
        raise RuntimeError("host did not release the exfiltration stream")

    connection, backend_label = _open_tls_tunnel(
        proxy_host,
        proxy_port,
        "allowed.test",
        FIXTURE_PORT,
    )
    streamed_bytes = 0
    payload = b"argus-tc33-exfil" * 256
    try:
        while streamed_bytes < TC33_HARD_BYTES * 2:
            connection.sendall(payload)
            streamed_bytes += len(payload)
            _readline(connection)
    except (BrokenPipeError, ConnectionError, OSError, RuntimeError, TimeoutError):
        pass
    finally:
        connection.close()
    print(
        json.dumps(
            {
                "exfil_stream": {
                    "backend": backend_label,
                    "attempted_payload_bytes": streamed_bytes,
                }
            },
            sort_keys=True,
        ),
        flush=True,
    )
    time.sleep(10)


def _proxy_address(proxy_url: str) -> tuple[str, int]:
    prefix = "http://"
    if not proxy_url.startswith(prefix) or proxy_url.count(":") != 2:
        raise RuntimeError("sandbox received an invalid egress proxy URL")
    host, raw_port = proxy_url.removeprefix(prefix).rsplit(":", 1)
    return host, int(raw_port)


def _tcp_blocked(host: str, port: int) -> bool:
    try:
        connection = socket.create_connection((host, port), timeout=0.4)
    except (ConnectionError, OSError, TimeoutError):
        return True
    connection.close()
    return False


def _dns_blocked(nameserver: str) -> bool:
    query = _dns_query("direct-bypass.test")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.4)
        try:
            client.sendto(query, (nameserver, 53))
            client.recvfrom(4096)
        except (ConnectionError, OSError, TimeoutError, socket.timeout):
            return True
    return False


def _dns_query(host: str) -> bytes:
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in host.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0xA741, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def _open_connect(proxy_host: str, proxy_port: int, host: str, port: int) -> tuple[int, socket.socket]:
    connection = socket.create_connection((proxy_host, proxy_port), timeout=2)
    connection.sendall(
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("ascii")
    )
    response = _read_headers(connection)
    try:
        status = int(response.split(b" ", 2)[1])
    except (IndexError, ValueError) as exc:
        connection.close()
        raise RuntimeError("proxy returned an invalid CONNECT response") from exc
    return status, connection


def _open_tls_tunnel(proxy_host: str, proxy_port: int, host: str, port: int) -> tuple[socket.socket, str]:
    status, connection = _open_connect(proxy_host, proxy_port, host, port)
    if status != 200:
        connection.close()
        raise RuntimeError(f"allowed CONNECT failed with status {status}")
    connection.sendall(_client_hello(host))
    return connection, _readline(connection)


def _client_hello(server_name: str) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_name)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def _read_headers(connection: socket.socket) -> bytes:
    payload = bytearray()
    while b"\r\n\r\n" not in payload:
        chunk = connection.recv(4096)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > 16 * 1024:
            raise RuntimeError("CONNECT response exceeded its bound")
    return bytes(payload)


def _readline(connection: socket.socket) -> str:
    connection.settimeout(2)
    payload = bytearray()
    while not payload.endswith(b"\n"):
        chunk = connection.recv(1)
        if not chunk:
            raise RuntimeError("backend closed before returning its identity")
        payload.extend(chunk)
        if len(payload) > 64:
            raise RuntimeError("backend identity exceeded its bound")
    return payload.decode("ascii").strip()


def _run_host_battery(evidence_file: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    commit = _command(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip()
    dirty = bool(_command(["git", "status", "--porcelain"], cwd=repo).stdout.strip())
    evidence: dict[str, Any] = {
        "schema": "argus.s10.egress-security.v1",
        "commit": commit,
        "working_tree_dirty": dirty,
        "target": {
            "os": sys.platform,
            "docker_server": _command(["docker", "version", "--format", "{{.Server.Version}}"], cwd=repo).stdout.strip(),
        },
        "status": "FAIL",
        "cases": {},
    }
    try:
        evidence.update(_execute_host_battery(repo))
        evidence["status"] = "PASS"
    except Exception as exc:
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        _write_evidence(evidence_file, evidence)
        raise
    _write_evidence(evidence_file, evidence)


def _execute_host_battery(repo: Path) -> dict[str, Any]:
    if sys.platform != "linux":
        raise RuntimeError("the egress security battery requires a real Linux network namespace")
    if os.geteuid() != 0:
        raise RuntimeError("the egress security battery must run as root for namespace packet capture")
    for command in (
        "docker",
        "nsenter",
        "tcpdump",
        *FIREWALL_BINARIES,
    ):
        if shutil.which(command) is None:
            raise RuntimeError(f"required host command is unavailable: {command}")

    run_id = f"{os.getpid()}-{int(time.time())}"
    sidecar_tag = f"argus-s10-egress-sidecar:{run_id}"
    probe_tag = f"argus-s10-egress-probe:{run_id}"
    network_name = f"argus-s10-egress-{run_id}"
    fixture_names = {
        "dns": f"s10egress-{run_id}-dns",
        "backend_a": f"s10egress-{run_id}-backend-a",
        "backend_b": f"s10egress-{run_id}-backend-b",
    }
    job_id = f"s10-egress-{run_id}"
    runtime_thread: threading.Thread | None = None
    runtime_state: dict[str, Any] = {}
    captures: list[_Capture] = []
    try:
        server_platform = _docker_server_platform(repo)
        _command(
            [
                "docker",
                "build",
                "--platform",
                server_platform,
                "--file",
                "deploy/argus-m0/security/egress-sidecar.Dockerfile",
                "--tag",
                sidecar_tag,
                ".",
            ],
            cwd=repo,
            timeout=600,
        )
        _command(
            [
                "docker",
                "build",
                "--platform",
                server_platform,
                "--file",
                "deploy/argus-m0/security/egress-probe.Dockerfile",
                "--tag",
                probe_tag,
                ".",
            ],
            cwd=repo,
            timeout=300,
        )
        sidecar_image = _command(
            ["docker", "image", "inspect", sidecar_tag, "--format", "{{.Id}}"], cwd=repo
        ).stdout.strip()
        probe_image = _command(
            ["docker", "image", "inspect", probe_tag, "--format", "{{.Id}}"], cwd=repo
        ).stdout.strip()
        if not sidecar_image.startswith("sha256:") or not probe_image.startswith("sha256:"):
            raise RuntimeError("Docker did not return digest-pinned test images")
        expected_architecture = server_platform.split("/", 1)[1]
        for image in (sidecar_image, probe_image):
            architecture = _command(
                ["docker", "image", "inspect", image, "--format", "{{.Architecture}}"],
                cwd=repo,
            ).stdout.strip()
            if architecture != expected_architecture:
                raise RuntimeError(
                    f"Docker built {architecture or 'unknown'} image for {server_platform} server"
                )

        subnet = _create_task_network(network_name, cwd=repo)
        dns_ip = str(subnet.network_address + 10)
        backend_a_ip = str(subnet.network_address + 20)
        backend_b_ip = str(subnet.network_address + 21)

        _start_fixture(
            name=fixture_names["dns"],
            network=network_name,
            ip=dns_ip,
            image=probe_image,
            args=("--fixture", "dns", "--answer-a", backend_a_ip, "--answer-b", backend_b_ip),
            cwd=repo,
        )
        _start_fixture(
            name=fixture_names["backend_a"],
            network=network_name,
            ip=backend_a_ip,
            image=probe_image,
            args=("--fixture", "backend", "--backend-label", "A"),
            cwd=repo,
        )
        _start_fixture(
            name=fixture_names["backend_b"],
            network=network_name,
            ip=backend_b_ip,
            image=probe_image,
            args=("--fixture", "backend", "--backend-label", "B"),
            cwd=repo,
        )
        for name in fixture_names.values():
            _wait_for_log(name, "fixture.ready", cwd=repo, timeout=10)

        runtime_state.update(
            _build_runtime(
                job_id=job_id,
                sidecar_image=sidecar_image,
                probe_image=probe_image,
                network_name=network_name,
                dns_ip=dns_ip,
                backend_a_ip=backend_a_ip,
                backend_b_ip=backend_b_ip,
            )
        )

        def launch() -> None:
            try:
                runtime_state["result"] = runtime_state["orchestrator"].launch_and_wait(runtime_state["request"])
            except BaseException as exc:
                runtime_state["error"] = exc

        runtime_thread = threading.Thread(target=launch, name="s10-egress-runtime", daemon=True)
        runtime_thread.start()
        sandbox_name = _wait_for_role_container(
            job_id,
            "sandbox",
            cwd=repo,
            timeout=10,
            thread=runtime_thread,
            state=runtime_state,
        )
        sidecar_name = _wait_for_role_container(
            job_id,
            "egress-sidecar",
            cwd=repo,
            timeout=10,
            thread=runtime_thread,
            state=runtime_state,
        )
        _wait_for_log(sandbox_name, "PHASE capture-ready", cwd=repo, timeout=10, thread=runtime_thread, state=runtime_state)

        with tempfile.TemporaryDirectory(prefix="argus-s10-egress-") as temp_dir:
            tc03_capture_path = Path(temp_dir) / "tc03-default-deny.packets.txt"
            pre_capture_path = Path(temp_dir) / "pre-crash.packets.txt"
            post_capture_path = Path(temp_dir) / "post-crash.packets.txt"
            tc03_capture = _start_capture(sandbox_name, tc03_capture_path, cwd=repo)
            captures.append(tc03_capture)
            _command(["docker", "kill", "--signal", "USR1", sandbox_name], cwd=repo)
            _wait_for_log(
                sandbox_name,
                "PHASE default-deny-complete",
                cwd=repo,
                timeout=10,
                thread=runtime_thread,
                state=runtime_state,
            )
            tc03_capture.stop()
            pre_capture = _start_capture(sandbox_name, pre_capture_path, cwd=repo)
            captures.append(pre_capture)
            _command(["docker", "kill", "--signal", "USR1", sandbox_name], cwd=repo)
            _wait_for_log(
                sandbox_name,
                "PHASE dns-pin-ready",
                cwd=repo,
                timeout=10,
                thread=runtime_thread,
                state=runtime_state,
            )
            _command(["docker", "kill", "--signal", "USR1", fixture_names["dns"]], cwd=repo)
            _wait_for_log(fixture_names["dns"], "dns.rebound", cwd=repo, timeout=10)
            _command(["docker", "kill", "--signal", "USR2", sandbox_name], cwd=repo)
            _wait_for_log(
                sandbox_name,
                "PHASE crash-ready",
                cwd=repo,
                timeout=10,
                thread=runtime_thread,
                state=runtime_state,
            )
            pre_firewall_v4 = _namespace_command(
                sandbox_name,
                [FIREWALL_IPV4_BIN, "-S", "OUTPUT"],
                cwd=repo,
            ).stdout
            pre_firewall_v6 = _namespace_command(
                sandbox_name,
                [FIREWALL_IPV6_BIN, "-S", "OUTPUT"],
                cwd=repo,
            ).stdout
            firewall_version_v4 = _namespace_command(
                sandbox_name,
                [FIREWALL_IPV4_BIN, "--version"],
                cwd=repo,
            ).stdout.strip()
            firewall_version_v6 = _namespace_command(
                sandbox_name,
                [FIREWALL_IPV6_BIN, "--version"],
                cwd=repo,
            ).stdout.strip()
            firewall_backend_v4 = _iptables_backend(firewall_version_v4)
            firewall_backend_v6 = _iptables_backend(firewall_version_v6)
            if firewall_backend_v4 != firewall_backend_v6:
                raise RuntimeError(
                    "egress battery observed incoherent firewall backends: "
                    f"IPv4={firewall_backend_v4} IPv6={firewall_backend_v6}"
                )
            pre_capture.stop()
            post_capture = _start_capture(sandbox_name, post_capture_path, cwd=repo)
            captures.append(post_capture)
            _command(["docker", "kill", "--signal", "KILL", sidecar_name], cwd=repo)
            _command(["docker", "kill", "--signal", "USR2", sandbox_name], cwd=repo)
            _wait_for_log(
                sandbox_name,
                "PHASE post-crash-complete",
                cwd=repo,
                timeout=10,
                thread=runtime_thread,
                state=runtime_state,
            )
            post_firewall_v4 = _namespace_command(
                sandbox_name,
                [FIREWALL_IPV4_BIN, "-S", "OUTPUT"],
                cwd=repo,
            ).stdout
            post_firewall_v6 = _namespace_command(
                sandbox_name,
                [FIREWALL_IPV6_BIN, "-S", "OUTPUT"],
                cwd=repo,
            ).stdout
            post_capture.stop()
            _command(["docker", "kill", "--signal", "USR1", sandbox_name], cwd=repo)
            runtime_thread.join(timeout=30)
            if runtime_thread.is_alive():
                raise RuntimeError("sandbox runtime did not finish after the egress proxy crash")
            if "error" in runtime_state:
                raise runtime_state["error"]

            result = runtime_state["result"]
            sandbox_results = _sandbox_result(result.stdout)
            dns_events = _container_events(fixture_names["dns"], cwd=repo)
            backend_a_events = _container_events(fixture_names["backend_a"], cwd=repo)
            backend_b_events = _container_events(fixture_names["backend_b"], cwd=repo)
            audit_events = runtime_state["audit"].events()
            if not runtime_state["audit"].verify_chain().valid:
                raise RuntimeError("S10 audit chain failed after egress event ingestion")

            tc03_packets = _packet_lines(tc03_capture_path.read_text(encoding="utf-8"))
            pre_packets = pre_capture_path.read_text(encoding="utf-8")
            post_packets = post_capture_path.read_text(encoding="utf-8")
            post_egress_packets = _packet_lines(post_packets)
            dns_queries = [event for event in dns_events if event["event_type"] == "dns.query"]
            accepted_a = [event for event in backend_a_events if event["event_type"] == "backend.accepted"]
            accepted_b = [event for event in backend_b_events if event["event_type"] == "backend.accepted"]
            egress_events = [event for event in audit_events if event.event_type.startswith("egress.")]
            ready_events = [event for event in egress_events if event.event_type == "egress.ready"]
            denied_reasons = {
                str(event.payload.get("reason"))
                for event in egress_events
                if event.event_type == "egress.denied"
            }
            allowed_ips = [
                str(event.payload.get("resolved_ip"))
                for event in egress_events
                if event.event_type == "egress.allowed"
            ]

            tc03_pass = all(
                (
                    sandbox_results["direct_tcp_blocked"],
                    sandbox_results["default_deny_status"] == 403,
                    "egress_denied" in denied_reasons,
                    len(accepted_a) == 1,
                    len(accepted_b) == 1,
                    not tc03_packets,
                )
            )
            tc04_pass = all(
                (
                    sandbox_results["direct_dns_blocked"],
                    sandbox_results["sni_mismatch_closed"],
                    "sni_mismatch" in denied_reasons,
                    sandbox_results["first_resolved_backend"] == "A",
                    sandbox_results["pinned_backend_after_rebind"] == "A",
                    sandbox_results["second_resolved_backend"] == "B",
                    [event["payload"]["answer"] for event in dns_queries] == [backend_a_ip, backend_b_ip],
                    allowed_ips == [backend_a_ip, backend_b_ip],
                    dns_ip in pre_packets,
                )
            )
            tc27_pass = all(
                (
                    sandbox_results["proxy_connect_blocked_after_crash"],
                    sandbox_results["direct_tcp_blocked_after_crash"],
                    sandbox_results["direct_dns_blocked_after_crash"],
                    any(event.event_type == "egress.proxy_crashed" for event in egress_events),
                    len(ready_events) == 1,
                    ready_events[0].payload.get("effective_capabilities") == "0000000000000000",
                    not post_egress_packets,
                    "-P OUTPUT DROP" in post_firewall_v4,
                    "--uid-owner 65532" in post_firewall_v4,
                    "-P OUTPUT DROP" in post_firewall_v6,
                )
            )
            if not all((tc03_pass, tc04_pass, tc27_pass)):
                failure_detail = {
                    "TC03": {
                        "passed": tc03_pass,
                        "direct_tcp_blocked": sandbox_results["direct_tcp_blocked"],
                        "default_deny_status": sandbox_results["default_deny_status"],
                        "egress_denied": "egress_denied" in denied_reasons,
                        "backend_a_connections": len(accepted_a),
                        "backend_b_connections": len(accepted_b),
                        "outbound_ip_packet_count": len(tc03_packets),
                        "packet_sample": tc03_packets[:8],
                    },
                    "TC04": tc04_pass,
                    "TC27": tc27_pass,
                }
                raise RuntimeError(
                    "egress acceptance failed: "
                    + json.dumps(failure_detail, sort_keys=True, separators=(",", ":"))
                )

            tc33 = _run_tc33_case(
                repo=repo,
                job_id=f"{job_id}-tc33",
                sidecar_image=sidecar_image,
                probe_image=probe_image,
                network_name=network_name,
                dns_ip=dns_ip,
                backend_container=fixture_names["backend_b"],
            )

            cases = {
                "S10-TC03": {
                    "status": "PASS",
                    "direct_tcp_blocked": sandbox_results["direct_tcp_blocked"],
                    "denied_status": sandbox_results["default_deny_status"],
                    "denied_audit": "egress_denied" in denied_reasons,
                    "outbound_ip_packet_count": len(tc03_packets),
                    "unexpected_backend_connections": max(len(accepted_a) + len(accepted_b) - 2, 0),
                },
                "S10-TC04": {
                    "status": "PASS",
                    "direct_dns_blocked": sandbox_results["direct_dns_blocked"],
                    "sni_mismatch_blocked_before_dns": "sni_mismatch" in denied_reasons,
                    "dns_answers": [event["payload"]["answer"] for event in dns_queries],
                    "proxy_pinned_ips": allowed_ips,
                    "open_tunnel_backend_after_rebind": sandbox_results["pinned_backend_after_rebind"],
                    "new_tunnel_backend_after_rebind": sandbox_results["second_resolved_backend"],
                },
                "S10-TC27": {
                    "status": "PASS",
                    "proxy_connect_blocked": sandbox_results["proxy_connect_blocked_after_crash"],
                    "direct_tcp_blocked": sandbox_results["direct_tcp_blocked_after_crash"],
                    "direct_dns_blocked": sandbox_results["direct_dns_blocked_after_crash"],
                    "proxy_crash_audit": True,
                    "runtime_capabilities_dropped": True,
                    "post_crash_eth0_packet_count": len(post_egress_packets),
                    "default_drop_v4": "-P OUTPUT DROP" in post_firewall_v4,
                    "default_drop_v6": "-P OUTPUT DROP" in post_firewall_v6,
                    "network_interface_removed": post_capture.interface_disappeared,
                },
                "S10-TC33": tc33,
            }
            return {
                "images": {
                    "platform": server_platform,
                    "sidecar": sidecar_image,
                    "sandbox_probe": probe_image,
                },
                "network": {
                    "name": network_name,
                    "dns_ip": dns_ip,
                    "backend_ips": [backend_a_ip, backend_b_ip],
                },
                "cases": cases,
                "pass_count": 4,
                "total_count": 4,
                "audit": {
                    "chain_valid": True,
                    "egress_event_types": [event.event_type for event in egress_events],
                    "egress_event_count": len(egress_events),
                },
                "packet_capture": {
                    "default_deny_packet_count": len(tc03_packets),
                    "pre_crash_packet_count": len(_packet_lines(pre_packets)),
                    "post_crash_packet_count": len(post_egress_packets),
                },
                "firewall": {
                    "backend": firewall_backend_v4,
                    "ipv4_version": firewall_version_v4,
                    "ipv6_version": firewall_version_v6,
                    "pre_crash_ipv4": pre_firewall_v4.splitlines(),
                    "pre_crash_ipv6": pre_firewall_v6.splitlines(),
                    "post_crash_ipv4": post_firewall_v4.splitlines(),
                    "post_crash_ipv6": post_firewall_v6.splitlines(),
                },
            }
    finally:
        active_error = sys.exception()
        cleanup_errors: list[Exception] = []

        def cleanup(command: list[str]) -> None:
            try:
                _command(command, cwd=repo, check=False)
            except Exception as exc:
                cleanup_errors.append(exc)

        for capture in captures:
            try:
                capture.stop()
            except Exception as exc:
                cleanup_errors.append(exc)
        if runtime_thread is not None and runtime_thread.is_alive():
            for role in ("sandbox", "egress-sidecar"):
                try:
                    names = _role_containers(job_id, role, cwd=repo, all_states=True)
                except Exception as exc:
                    cleanup_errors.append(exc)
                    names = []
                for name in names:
                    cleanup(["docker", "rm", "--force", name])
            runtime_thread.join(timeout=5)
            if runtime_thread.is_alive():
                cleanup_errors.append(RuntimeError("egress runtime thread survived container cleanup"))
        for name in fixture_names.values():
            cleanup(["docker", "rm", "--force", name])
        for role in ("sandbox", "egress-sidecar"):
            try:
                names = _role_containers(job_id, role, cwd=repo, all_states=True)
            except Exception as exc:
                cleanup_errors.append(exc)
                names = []
            for name in names:
                cleanup(["docker", "rm", "--force", name])
        cleanup(["docker", "network", "rm", network_name])
        cleanup(["docker", "image", "rm", "--force", sidecar_tag])
        cleanup(["docker", "image", "rm", "--force", probe_tag])

        if cleanup_errors:
            if active_error is not None:
                for error in cleanup_errors:
                    active_error.add_note(f"cleanup failure: {type(error).__name__}: {error}")
            else:
                primary = cleanup_errors[0]
                for additional in cleanup_errors[1:]:
                    primary.add_note(f"additional cleanup failure: {type(additional).__name__}: {additional}")
                raise primary


def _build_runtime(
    *,
    job_id: str,
    sidecar_image: str,
    probe_image: str,
    network_name: str,
    dns_ip: str,
    backend_a_ip: str,
    backend_b_ip: str,
    fixture: str = "sandbox",
    exfil_soft_bytes: int = 64 * 1024 * 1024,
    exfil_hard_bytes: int = 128 * 1024 * 1024,
) -> dict[str, Any]:
    from argus_core import (
        BudgetCaps,
        DockerSandboxOrchestrator,
        DockerSandboxSupervisor,
        EgressRule,
        EgressSidecarRuntimeConfig,
        ExfilThresholds,
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
        ScopeGrant,
    )

    rule = EgressRule("allowed.test", FIXTURE_PORT, "https")
    policy_key = b"argus-s10-egress-policy-test-key"
    signer = PolicyBundleSigner(key_id="s10-egress-policy", secret=policy_key)
    bundle = signer.sign(
        PolicyBundle(
            bundle_version="2.0.0",
            egress_allowlist=(rule,),
            exfil_thresholds=ExfilThresholds(
                soft_bytes=exfil_soft_bytes,
                hard_bytes=exfil_hard_bytes,
            ),
            resource_ceilings=ResourceCeilings(
                cpu_m=500,
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
    policy_service = InMemoryPolicyService(
        initial_bundle=bundle,
        trust_store=InMemoryPolicyBundleTrustStore({"s10-egress-policy": policy_key}),
    )
    tokens = InMemoryTokenService(signing_key=b"argus-s10-egress-scope-test-key")
    budget = tokens.mint_budget(
        caps=BudgetCaps(max_compute_units=20, max_wallclock_s=30, max_cost_usd=1),
        job_id=job_id,
        root_request_id=f"root-{job_id}",
    )
    scope = tokens.mint_scope(job_id=job_id, scopes=ScopeGrant(egress_allowlist=(rule,)))
    request = LaunchRequest(
        job_id=job_id,
        subagent_id="s10-egress-probe",
        trace_id=f"trace-{job_id}",
        budget_token=budget,
        scope_token=scope,
        image=probe_image,
        entrypoint=("python",),
        args=("/opt/argus/run_s10_egress_battery.py", "--fixture", fixture),
        env={
            "ARGUS_EGRESS_TEST_DNS_IP": dns_ip,
            "ARGUS_EGRESS_TEST_BACKEND_A_IP": backend_a_ip,
            "ARGUS_EGRESS_TEST_BACKEND_B_IP": backend_b_ip,
        },
        env_allowlist=(
            "ARGUS_EGRESS_TEST_DNS_IP",
            "ARGUS_EGRESS_TEST_BACKEND_A_IP",
            "ARGUS_EGRESS_TEST_BACKEND_B_IP",
        ),
        requested_envelope=LaunchEnvelope(
            cpu_m=250,
            mem_bytes=64 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=20,
            scratch_bytes=1024 * 1024,
            pids=32,
            estimated_cost_usd=0.01,
        ),
    )
    audit = InMemoryAuditLedger()
    supervisor = DockerSandboxSupervisor(
        meter_interval_s=0.2,
        meter_gap_halt_s=2,
        egress_sidecar_config=EgressSidecarRuntimeConfig(
            image=sidecar_image,
            network_mode=network_name,
            dns_servers=(dns_ip,),
            startup_timeout_s=10,
        ),
    )
    orchestrator = DockerSandboxOrchestrator(
        token_service=tokens,
        quota_ledger=InMemoryQuotaLedger(),
        audit_ledger=audit,
        policy_service=policy_service,
        artifact_store=InMemoryArtifactStore(),
        supervisor=supervisor,
    )
    return {"audit": audit, "orchestrator": orchestrator, "request": request}


def _run_tc33_case(
    *,
    repo: Path,
    job_id: str,
    sidecar_image: str,
    probe_image: str,
    network_name: str,
    dns_ip: str,
    backend_container: str,
) -> dict[str, Any]:
    before_backend_events = _container_events(backend_container, cwd=repo)
    state = _build_runtime(
        job_id=job_id,
        sidecar_image=sidecar_image,
        probe_image=probe_image,
        network_name=network_name,
        dns_ip=dns_ip,
        backend_a_ip="unused",
        backend_b_ip="unused",
        fixture="exfil-sandbox",
        exfil_soft_bytes=TC33_SOFT_BYTES,
        exfil_hard_bytes=TC33_HARD_BYTES,
    )
    runtime_thread: threading.Thread | None = None

    def launch() -> None:
        try:
            state["result"] = state["orchestrator"].launch_and_wait(state["request"])
        except BaseException as exc:
            state["error"] = exc

    try:
        runtime_thread = threading.Thread(target=launch, name="s10-tc33-runtime", daemon=True)
        runtime_thread.start()
        sandbox_name = _wait_for_role_container(
            job_id,
            "sandbox",
            cwd=repo,
            timeout=10,
            thread=runtime_thread,
            state=state,
        )
        _wait_for_role_container(
            job_id,
            "egress-sidecar",
            cwd=repo,
            timeout=10,
            thread=runtime_thread,
            state=state,
        )
        _wait_for_log(
            sandbox_name,
            "PHASE exfil-ready",
            cwd=repo,
            timeout=10,
            thread=runtime_thread,
            state=state,
        )
        _command(["docker", "kill", "--signal", "USR1", sandbox_name], cwd=repo)
        runtime_thread.join(timeout=30)
        if runtime_thread.is_alive():
            raise RuntimeError("TC33 runtime did not halt after the hard exfil threshold")
        if "error" in state:
            raise state["error"]

        result = state["result"]
        partial = result.partial_result
        audit = state["audit"]
        if not audit.verify_chain().valid:
            raise RuntimeError("TC33 audit chain failed verification")
        audit_events = audit.events()
        event_types = [event.event_type for event in audit_events]
        soft_events = [event for event in audit_events if event.event_type == "egress.exfil_soft_alert"]
        hard_events = [event for event in audit_events if event.event_type == "egress.exfil_hard_halt"]
        new_backend_events = _container_events(backend_container, cwd=repo)[len(before_backend_events) :]
        backend_byte_events = [event for event in new_backend_events if event["event_type"] == "backend.bytes"]
        backend_bytes = sum(int(event["payload"]["count"]) for event in backend_byte_events)
        accepted_connections = sum(
            event["event_type"] == "backend.accepted" for event in new_backend_events
        )
        required_order = [
            "egress.exfil_soft_alert",
            "egress.exfil_hard_halt",
            "meter.halt",
            "sandbox.freeze",
            "sandbox.terminate",
        ]
        ordered = all(event_type in event_types for event_type in required_order) and all(
            event_types.index(left) < event_types.index(right)
            for left, right in zip(required_order, required_order[1:])
        )
        meter_halts = [event for event in audit_events if event.event_type == "meter.halt"]
        soft_payload = soft_events[0].payload if soft_events else {}
        hard_payload = hard_events[0].payload if hard_events else {}
        meter_payload = meter_halts[0].payload if meter_halts else {}
        passed = all(
            (
                result.timed_out,
                partial is not None,
                partial is not None and partial.reason == "exfil_hard_limit",
                partial is not None and partial.freeze_succeeded,
                partial is not None and partial.terminate_succeeded,
                len(soft_events) == 1,
                len(hard_events) == 1,
                soft_payload.get("threshold_bytes") == TC33_SOFT_BYTES,
                soft_payload.get("action") == "alert",
                TC33_SOFT_BYTES
                <= int(soft_payload.get("bytes_to_upstream", 0))
                <= TC33_HARD_BYTES,
                hard_payload.get("threshold_bytes") == TC33_HARD_BYTES,
                hard_payload.get("bytes_to_upstream") == TC33_HARD_BYTES,
                hard_payload.get("action") == "drop_and_halt",
                int(hard_payload.get("dropped_bytes", 0)) > 0,
                accepted_connections == 1,
                TC33_SOFT_BYTES <= backend_bytes <= TC33_HARD_BYTES,
                ordered,
                len(meter_halts) == 1,
                meter_payload.get("source") == "egress-sidecar-byte-meter",
            )
        )
        detail = {
            "status": "PASS" if passed else "FAIL",
            "soft_threshold_bytes": TC33_SOFT_BYTES,
            "hard_threshold_bytes": TC33_HARD_BYTES,
            "backend_bytes_received": backend_bytes,
            "backend_connection_count": accepted_connections,
            "soft_alert_count": len(soft_events),
            "hard_halt_count": len(hard_events),
            "soft_alert_bytes": soft_payload.get("bytes_to_upstream"),
            "soft_action": soft_payload.get("action"),
            "hard_halt_bytes": hard_payload.get("bytes_to_upstream"),
            "hard_drop_bytes": hard_payload.get("dropped_bytes"),
            "hard_action": hard_payload.get("action"),
            "meter_source": meter_payload.get("source"),
            "runtime_timed_out": result.timed_out,
            "partial_reason": partial.reason if partial is not None else None,
            "freeze_succeeded": partial.freeze_succeeded if partial is not None else False,
            "terminate_succeeded": partial.terminate_succeeded if partial is not None else False,
            "ordered_audit": ordered,
            "audit_event_types": event_types,
            "audit_chain_valid": True,
        }
        if not passed:
            raise RuntimeError(
                "TC33 exfiltration threshold acceptance failed: "
                + json.dumps(detail, sort_keys=True, separators=(",", ":"))
            )
        return detail
    finally:
        if runtime_thread is not None and runtime_thread.is_alive():
            for role in ("sandbox", "egress-sidecar"):
                for name in _role_containers(job_id, role, cwd=repo, all_states=True):
                    _command(["docker", "rm", "--force", name], cwd=repo, check=False)
            runtime_thread.join(timeout=5)


def _start_fixture(
    *,
    name: str,
    network: str,
    ip: str,
    image: str,
    args: tuple[str, ...],
    cwd: Path,
) -> None:
    _command(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            network,
            "--ip",
            ip,
            image,
            *args,
        ],
        cwd=cwd,
    )


def _docker_server_platform(cwd: Path) -> str:
    platform = _command(
        ["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"],
        cwd=cwd,
    ).stdout.strip()
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise RuntimeError(f"unsupported Docker server platform for egress battery: {platform or 'unknown'}")
    return platform


def _create_task_network(name: str, *, cwd: Path) -> ipaddress.IPv4Network:
    seed = (os.getpid() + int(time.time())) % 128
    failures: list[str] = []
    for offset in range(128):
        third_octet = 64 + ((seed + offset) % 128)
        candidate = ipaddress.IPv4Network(f"10.253.{third_octet}.0/24")
        completed = _command(
            [
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                str(candidate),
                name,
            ],
            cwd=cwd,
            check=False,
        )
        if completed.returncode != 0:
            failures.append(completed.stderr.strip() or completed.stdout.strip())
            continue
        try:
            inspected = json.loads(
                _command(["docker", "network", "inspect", name], cwd=cwd).stdout
            )
            configs = inspected[0]["IPAM"]["Config"] if len(inspected) == 1 else []
            if len(configs) != 1 or configs[0].get("Subnet") != str(candidate):
                raise RuntimeError("Docker network did not preserve the task-scoped subnet")
            return candidate
        except Exception:
            _command(["docker", "network", "rm", name], cwd=cwd, check=False)
            raise
    detail = failures[-1] if failures else "no Docker error was reported"
    raise RuntimeError(f"could not allocate a task-scoped Docker subnet: {detail}")


def _wait_for_role_container(
    job_id: str,
    role: str,
    *,
    cwd: Path,
    timeout: float,
    thread: threading.Thread | None = None,
    state: dict[str, Any] | None = None,
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        names = _role_containers(job_id, role, cwd=cwd)
        if len(names) == 1:
            return names[0]
        if len(names) > 1:
            raise RuntimeError(f"multiple {role} containers found for {job_id}")
        if thread is not None and not thread.is_alive():
            error = (state or {}).get("error")
            raise RuntimeError(f"runtime exited before {role} container creation: {error or 'no error reported'}")
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {role} container")


def _role_containers(job_id: str, role: str, *, cwd: Path, all_states: bool = False) -> list[str]:
    command = ["docker", "ps"]
    if all_states:
        command.append("--all")
    command.extend(
        (
            "--filter",
            f"label=argus.dev/job-id={job_id}",
            "--filter",
            f"label=argus.dev/role={role}",
            "--format",
            "{{.Names}}",
        )
    )
    output = _command(command, cwd=cwd, check=False).stdout
    return [line for line in output.splitlines() if line]


def _wait_for_log(
    container: str,
    marker: str,
    *,
    cwd: Path,
    timeout: float,
    thread: threading.Thread | None = None,
    state: dict[str, Any] | None = None,
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output = _command(["docker", "logs", container], cwd=cwd, check=False).stdout
        if marker in output:
            return output
        if thread is not None and not thread.is_alive():
            error = (state or {}).get("error")
            raise RuntimeError(f"runtime exited before {marker}: {error or output}")
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {marker} in {container}")


class _Capture:
    def __init__(
        self,
        process: subprocess.Popen[str],
        output: Any,
        stderr: Any,
        stderr_path: Path,
    ) -> None:
        self.process = process
        self.output = output
        self.stderr = stderr
        self.stderr_path = stderr_path
        self.stopped = False
        self.interface_disappeared = False

    def stop(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.output.close()
        self.stderr.close()
        if self.process.returncode not in {0, 130, -signal.SIGINT}:
            detail = " ".join(self.stderr_path.read_text(encoding="utf-8").strip().split())[:512]
            if self.process.returncode == 1 and "pcap_loop: The interface disappeared" in detail:
                self.interface_disappeared = True
                return
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"tcpdump failed with exit code {self.process.returncode}{suffix}")


def _start_capture(container: str, output_path: Path, *, cwd: Path) -> _Capture:
    pid = _command(["docker", "inspect", container, "--format", "{{.State.Pid}}"], cwd=cwd).stdout.strip()
    output = output_path.open("w", encoding="utf-8")
    stderr_path = output_path.parent / f"{output_path.stem}.stderr.txt"
    stderr = stderr_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            "nsenter",
            "-t",
            pid,
            "-n",
            "tcpdump",
            "-i",
            "eth0",
            "-Q",
            "out",
            "-nn",
            "-tt",
            "-l",
        ],
        cwd=cwd,
        stdout=output,
        stderr=stderr,
        text=True,
    )
    time.sleep(0.1)
    if process.poll() is not None:
        output.close()
        stderr.close()
        raise RuntimeError("tcpdump could not enter the sandbox network namespace")
    return _Capture(process, output, stderr, stderr_path)


def _namespace_command(container: str, command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    pid = _command(["docker", "inspect", container, "--format", "{{.State.Pid}}"], cwd=cwd).stdout.strip()
    return _command(["nsenter", "-t", pid, "-n", *command], cwd=cwd)


def _iptables_backend(version: str) -> str:
    for backend in ("nf_tables", "legacy"):
        if f"({backend})" in version:
            return backend
    raise RuntimeError(f"could not identify iptables backend: {version.strip()[:160]}")


def _sandbox_result(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("sandbox_results"), dict):
            return parsed["sandbox_results"]
    raise RuntimeError("sandbox probe did not emit its result envelope")


def _container_events(container: str, *, cwd: Path) -> list[dict[str, Any]]:
    output = _command(["docker", "logs", container], cwd=cwd).stdout
    events: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and set(parsed) == {"event_type", "payload"}:
            events.append(parsed)
    return events


def _packet_lines(raw: str) -> list[str]:
    return [line for line in raw.splitlines() if " IP " in line or " IP6 " in line]


def _command(
    command: list[str],
    *,
    cwd: Path,
    check: bool = True,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}: {message}")
    return completed


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-file", type=Path)
    parser.add_argument("--fixture", choices=("dns", "backend", "sandbox", "exfil-sandbox"))
    parser.add_argument("--answer-a")
    parser.add_argument("--answer-b")
    parser.add_argument("--backend-label")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.fixture == "dns":
        if not args.answer_a or not args.answer_b:
            raise SystemExit("DNS fixture requires --answer-a and --answer-b")
        _run_dns_fixture(args.answer_a, args.answer_b)
        return
    if args.fixture == "backend":
        if args.backend_label not in {"A", "B"}:
            raise SystemExit("backend fixture requires --backend-label A or B")
        _run_backend_fixture(args.backend_label)
        return
    if args.fixture == "sandbox":
        _run_sandbox_fixture()
        return
    if args.fixture == "exfil-sandbox":
        _run_exfil_sandbox_fixture()
        return
    if args.evidence_file is None:
        raise SystemExit("host battery requires --evidence-file")
    _run_host_battery(args.evidence_file)


if __name__ == "__main__":
    main()
