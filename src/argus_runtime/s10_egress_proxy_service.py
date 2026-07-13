"""Fail-closed S10 CONNECT egress sidecar with DNS pinning and TLS SNI enforcement."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import threading
from typing import Protocol

import dns.exception
import dns.resolver

from argus_egress import EgressProxyManifest, EgressRule, canonical_json_bytes, normalize_egress_host


CONNECT_HEADER_LIMIT_BYTES = 8 * 1024
TLS_CLIENT_HELLO_LIMIT_BYTES = 64 * 1024
TLS_RECORD_LIMIT_BYTES = 18 * 1024
RELAY_CHUNK_BYTES = 64 * 1024
RELAY_BUFFER_LIMIT_BYTES = 256 * 1024
DEFAULT_PROXY_PORT = 15001
DEFAULT_PROXY_UID = 65531
DEFAULT_SANDBOX_UID = 65532


class EgressProxyProtocolError(ValueError):
    """Raised when a CONNECT request or TLS ClientHello is malformed."""


class AddressResolver(Protocol):
    def resolve(self, host: str, port: int) -> tuple[str, ...]: ...


class DnsAddressResolver:
    """Sidecar-owned DNS resolver that performs one uncached address lookup per tunnel."""

    def __init__(
        self,
        *,
        nameservers: tuple[str, ...] = (),
        nameserver_port: int = 53,
        lifetime_s: float = 2.0,
    ) -> None:
        if not 1 <= nameserver_port <= 65535:
            raise ValueError("DNS nameserver port is invalid")
        self._resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = [str(ipaddress.ip_address(value)) for value in nameservers]
        self._resolver.port = nameserver_port
        self._lifetime_s = max(float(lifetime_s), 0.1)

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del port
        failures: list[str] = []
        for record_type in ("A", "AAAA"):
            try:
                answer = self._resolver.resolve(
                    host,
                    record_type,
                    lifetime=self._lifetime_s,
                    raise_on_no_answer=False,
                    search=False,
                )
            except dns.exception.DNSException as exc:
                failures.append(type(exc).__name__)
                continue
            addresses = tuple(dict.fromkeys(str(item) for item in answer)) if answer.rrset is not None else ()
            if addresses:
                return addresses
        reason = ",".join(failures) or "no_address_records"
        raise OSError(f"DNS resolution failed: {reason}")


class EgressConnectProxy:
    def __init__(
        self,
        *,
        manifest: EgressProxyManifest,
        resolver: AddressResolver,
        connector: Callable[[str, int, float], socket.socket] | None = None,
        audit_sink: Callable[[str, dict[str, object]], None] | None = None,
        connect_timeout_s: float = 3.0,
        handshake_timeout_s: float = 3.0,
    ) -> None:
        self._manifest = manifest
        self._resolver = resolver
        self._connector = connector or _connect_numeric
        self._audit_sink = audit_sink or (lambda _event_type, _payload: None)
        self._connect_timeout_s = max(float(connect_timeout_s), 0.1)
        self._handshake_timeout_s = max(float(handshake_timeout_s), 0.1)
        self._rules_by_destination: dict[tuple[str, int], tuple[EgressRule, ...]] = {}
        for rule in manifest.rules:
            key = (rule.host, rule.port)
            self._rules_by_destination[key] = self._rules_by_destination.get(key, ()) + (rule,)

    def handle_connection(self, client: socket.socket, peer: tuple[object, ...]) -> None:
        upstream: socket.socket | None = None
        host = ""
        port = 0
        proto = "unknown"
        try:
            client.settimeout(self._handshake_timeout_s)
            try:
                host, port = _read_connect_request(client)
            except EgressProxyProtocolError as exc:
                _send_response(client, 400, "Bad Request")
                self._denied(host=host, port=port, proto=proto, reason=str(exc), peer=peer)
                return

            rules = self._rules_by_destination.get((host, port), ())
            protocols = {rule.proto for rule in rules}
            if not protocols:
                _send_response(client, 403, "Forbidden")
                self._denied(host=host, port=port, proto=proto, reason="egress_denied", peer=peer)
                return
            tls_protocols = protocols & {"https", "grpc"}
            if "tcp" in protocols and tls_protocols:
                _send_response(client, 403, "Forbidden")
                self._denied(host=host, port=port, proto=proto, reason="ambiguous_protocol", peer=peer)
                return
            proto = sorted(protocols)[0]

            buffered = b""
            sni = ""
            if tls_protocols:
                _send_response(client, 200, "Connection Established")
                try:
                    sni, buffered = _read_tls_client_hello(client, timeout_s=self._handshake_timeout_s)
                except (EgressProxyProtocolError, OSError, TimeoutError) as exc:
                    self._denied(
                        host=host,
                        port=port,
                        proto=proto,
                        reason=_safe_reason(exc, "invalid_tls_client_hello"),
                        peer=peer,
                    )
                    return
                if sni != host:
                    self._denied(
                        host=host,
                        port=port,
                        proto=proto,
                        reason="sni_mismatch",
                        peer=peer,
                        sni=sni,
                    )
                    return

            try:
                answers = self._resolver.resolve(host, port)
                if not answers:
                    raise OSError("DNS resolver returned no addresses")
                pinned_ip = str(ipaddress.ip_address(answers[0]))
                upstream = self._connector(pinned_ip, port, self._connect_timeout_s)
            except (OSError, TimeoutError, ValueError) as exc:
                if not tls_protocols:
                    _send_response(client, 502, "Bad Gateway")
                self._denied(
                    host=host,
                    port=port,
                    proto=proto,
                    reason=_safe_reason(exc, "upstream_unavailable"),
                    peer=peer,
                    sni=sni,
                )
                return

            if not tls_protocols:
                _send_response(client, 200, "Connection Established")
            if buffered:
                upstream.sendall(buffered)
            self._audit(
                "egress.allowed",
                {
                    "host": host,
                    "port": port,
                    "proto": proto,
                    "sni": sni,
                    "resolved_ip": pinned_ip,
                    "dns_answer_count": len(answers),
                    "bytes_to_upstream": len(buffered),
                    "peer": _peer_label(peer),
                },
            )
            client.settimeout(None)
            upstream.settimeout(None)
            _relay_bidirectional(client, upstream)
        except (BrokenPipeError, ConnectionError, OSError):
            return
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass

    def serve_forever(
        self,
        *,
        host: str,
        port: int,
        stop_event: threading.Event,
        ready: Callable[[socket.socket], None] | None = None,
    ) -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, port))
            listener.listen(128)
            listener.settimeout(0.2)
            if ready is not None:
                ready(listener)
            workers: set[threading.Thread] = set()
            while not stop_event.is_set():
                try:
                    accepted, peer = listener.accept()
                except socket.timeout:
                    workers = {worker for worker in workers if worker.is_alive()}
                    continue
                worker = threading.Thread(
                    target=self.handle_connection,
                    args=(accepted, peer),
                    name="argus-egress-tunnel",
                    daemon=True,
                )
                workers.add(worker)
                worker.start()

    def _denied(
        self,
        *,
        host: str,
        port: int,
        proto: str,
        reason: str,
        peer: tuple[object, ...],
        sni: str = "",
    ) -> None:
        self._audit(
            "egress.denied",
            {
                "host": host,
                "port": port,
                "proto": proto,
                "sni": sni,
                "reason": reason,
                "bytes_to_upstream": 0,
                "peer": _peer_label(peer),
            },
        )

    def _audit(self, event_type: str, payload: dict[str, object]) -> None:
        self._audit_sink(
            event_type,
            {
                "sandbox_id": self._manifest.sandbox_id,
                "job_id": self._manifest.job_id,
                "scope_id": self._manifest.scope_id,
                "policy_bundle_version": self._manifest.policy_bundle_version,
                "manifest_hash": self._manifest.manifest_hash,
                **payload,
            },
        )


class LinuxEgressFirewall:
    """UID-bound OUTPUT policy for an isolated sandbox/proxy network namespace."""

    def __init__(
        self,
        *,
        proxy_port: int = DEFAULT_PROXY_PORT,
        proxy_uid: int = DEFAULT_PROXY_UID,
        sandbox_uid: int = DEFAULT_SANDBOX_UID,
        dns_port: int = 53,
        iptables_bin: str = "iptables",
        ip6tables_bin: str = "ip6tables",
    ) -> None:
        if not 1 <= int(proxy_port) <= 65535:
            raise ValueError("proxy port is invalid")
        if not 1 <= int(dns_port) <= 65535:
            raise ValueError("DNS port is invalid")
        if min(int(proxy_uid), int(sandbox_uid)) < 1 or proxy_uid == sandbox_uid:
            raise ValueError("proxy and sandbox UIDs must be distinct non-root users")
        self.proxy_port = int(proxy_port)
        self.proxy_uid = int(proxy_uid)
        self.sandbox_uid = int(sandbox_uid)
        self.dns_port = int(dns_port)
        self.iptables_bin = iptables_bin
        self.ip6tables_bin = ip6tables_bin

    def commands(self) -> tuple[tuple[str, ...], ...]:
        commands: list[tuple[str, ...]] = []
        for binary in (self.iptables_bin, self.ip6tables_bin):
            commands.extend(self._family_rules(binary))
        commands.append((self.ip6tables_bin, "-P", "OUTPUT", "DROP"))
        commands.append((self.iptables_bin, "-P", "OUTPUT", "DROP"))
        return tuple(commands)

    def apply(self) -> None:
        self._preflight()
        for command in self.commands():
            self._run(command, phase="apply")

    def _preflight(self) -> None:
        backends: dict[str, str] = {}
        for binary in (self.iptables_bin, self.ip6tables_bin):
            completed = self._run((binary, "--version"), phase="preflight")
            version = f"{completed.stdout}\n{completed.stderr}"
            backends[binary] = _iptables_backend(version)
        if len(set(backends.values())) != 1:
            detail = ", ".join(f"{binary}={backend}" for binary, backend in backends.items())
            raise RuntimeError(f"egress firewall requires one coherent dual-stack backend: {detail}")
        for binary in (self.iptables_bin, self.ip6tables_bin):
            self._run((binary, "-S", "OUTPUT"), phase="preflight")

    @staticmethod
    def _run(command: tuple[str, ...], *, phase: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
            raise RuntimeError(
                f"failed to {phase} egress firewall command {command!r}: {message}; "
                f"euid={os.geteuid()} cap_eff={_effective_capabilities()}"
            )
        return completed

    def _family_rules(self, binary: str) -> tuple[tuple[str, ...], ...]:
        proxy_uid = str(self.proxy_uid)
        sandbox_uid = str(self.sandbox_uid)
        proxy_port = str(self.proxy_port)
        dns_port = str(self.dns_port)
        return (
            (binary, "-F", "OUTPUT"),
            (
                binary,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-m",
                "owner",
                "--uid-owner",
                proxy_uid,
                "-j",
                "ACCEPT",
            ),
            (
                binary,
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                dns_port,
                "-m",
                "owner",
                "--uid-owner",
                proxy_uid,
                "-j",
                "ACCEPT",
            ),
            (
                binary,
                "-A",
                "OUTPUT",
                "-o",
                "lo",
                "-p",
                "tcp",
                "--dport",
                proxy_port,
                "-m",
                "owner",
                "--uid-owner",
                sandbox_uid,
                "-j",
                "ACCEPT",
            ),
        )


def _iptables_backend(version: str) -> str:
    for backend in ("nf_tables", "legacy"):
        if f"({backend})" in version:
            return backend
    raise RuntimeError(f"egress firewall could not identify iptables backend: {version.strip()[:160]}")


def _read_connect_request(client: socket.socket) -> tuple[str, int]:
    payload = bytearray()
    while b"\r\n\r\n" not in payload:
        if len(payload) >= CONNECT_HEADER_LIMIT_BYTES:
            raise EgressProxyProtocolError("connect_headers_too_large")
        chunk = client.recv(min(4096, CONNECT_HEADER_LIMIT_BYTES + 1 - len(payload)))
        if not chunk:
            raise EgressProxyProtocolError("connect_headers_incomplete")
        payload.extend(chunk)
    end = payload.index(b"\r\n\r\n") + 4
    if end != len(payload):
        raise EgressProxyProtocolError("connect_request_has_early_tunnel_bytes")
    try:
        lines = bytes(payload[: end - 2]).decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise EgressProxyProtocolError("connect_headers_not_ascii") from exc
    request_parts = lines[0].split(" ")
    if len(request_parts) != 3 or request_parts[0] != "CONNECT" or request_parts[2] not in {"HTTP/1.0", "HTTP/1.1"}:
        raise EgressProxyProtocolError("connect_method_required")
    host, port = _parse_authority(request_parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in {" ", "\t"} or ":" not in line:
            raise EgressProxyProtocolError("connect_header_invalid")
        name, value = line.split(":", 1)
        normalized_name = name.lower()
        if normalized_name in headers:
            raise EgressProxyProtocolError("connect_duplicate_header")
        headers[normalized_name] = value.strip()
    if "host" in headers:
        header_host, header_port = _parse_authority(headers["host"])
        if (header_host, header_port) != (host, port):
            raise EgressProxyProtocolError("connect_host_header_mismatch")
    return host, port


def _parse_authority(authority: str) -> tuple[str, int]:
    if not authority or "@" in authority or "/" in authority or "#" in authority or "?" in authority:
        raise EgressProxyProtocolError("connect_authority_invalid")
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0 or authority[close + 1 : close + 2] != ":":
            raise EgressProxyProtocolError("connect_authority_invalid")
        raw_host = authority[1:close]
        raw_port = authority[close + 2 :]
    else:
        if authority.count(":") != 1:
            raise EgressProxyProtocolError("connect_authority_invalid")
        raw_host, raw_port = authority.rsplit(":", 1)
    try:
        host = normalize_egress_host(raw_host)
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise EgressProxyProtocolError("connect_authority_invalid") from exc
    if isinstance(port, bool) or not 1 <= port <= 65535:
        raise EgressProxyProtocolError("connect_authority_invalid")
    return host, port


def _read_tls_client_hello(client: socket.socket, *, timeout_s: float) -> tuple[str, bytes]:
    client.settimeout(timeout_s)
    payload = bytearray()
    while len(payload) <= TLS_CLIENT_HELLO_LIMIT_BYTES:
        try:
            sni = _parse_tls_client_hello_sni(bytes(payload))
        except _NeedMoreTlsData:
            chunk = client.recv(min(4096, TLS_CLIENT_HELLO_LIMIT_BYTES + 1 - len(payload)))
            if not chunk:
                raise EgressProxyProtocolError("tls_client_hello_incomplete")
            payload.extend(chunk)
            continue
        return sni, bytes(payload)
    raise EgressProxyProtocolError("tls_client_hello_too_large")


class _NeedMoreTlsData(Exception):
    pass


def _parse_tls_client_hello_sni(payload: bytes) -> str:
    record_offset = 0
    handshake = bytearray()
    handshake_size: int | None = None
    while True:
        if len(payload) - record_offset < 5:
            raise _NeedMoreTlsData
        content_type = payload[record_offset]
        major_version = payload[record_offset + 1]
        record_size = int.from_bytes(payload[record_offset + 3 : record_offset + 5], "big")
        if content_type != 22 or major_version != 3 or record_size < 1 or record_size > TLS_RECORD_LIMIT_BYTES:
            raise EgressProxyProtocolError("tls_client_hello_record_invalid")
        record_end = record_offset + 5 + record_size
        if len(payload) < record_end:
            raise _NeedMoreTlsData
        handshake.extend(payload[record_offset + 5 : record_end])
        record_offset = record_end
        if handshake_size is None and len(handshake) >= 4:
            if handshake[0] != 1:
                raise EgressProxyProtocolError("tls_client_hello_required")
            handshake_size = int.from_bytes(handshake[1:4], "big")
            if handshake_size < 34 or handshake_size > TLS_CLIENT_HELLO_LIMIT_BYTES - 4:
                raise EgressProxyProtocolError("tls_client_hello_length_invalid")
        if handshake_size is not None and len(handshake) >= handshake_size + 4:
            return _client_hello_sni(bytes(handshake[4 : handshake_size + 4]))


def _client_hello_sni(body: bytes) -> str:
    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        if size < 0 or offset + size > len(body):
            raise EgressProxyProtocolError("tls_client_hello_structure_invalid")
        value = body[offset : offset + size]
        offset += size
        return value

    take(2)
    take(32)
    session_id_size = take(1)[0]
    take(session_id_size)
    cipher_size = int.from_bytes(take(2), "big")
    if cipher_size < 2 or cipher_size % 2:
        raise EgressProxyProtocolError("tls_client_hello_cipher_list_invalid")
    take(cipher_size)
    compression_size = take(1)[0]
    if compression_size < 1:
        raise EgressProxyProtocolError("tls_client_hello_compression_invalid")
    take(compression_size)
    extensions_size = int.from_bytes(take(2), "big")
    extensions_end = offset + extensions_size
    if extensions_end != len(body):
        raise EgressProxyProtocolError("tls_client_hello_extensions_invalid")
    while offset < extensions_end:
        extension_type = int.from_bytes(take(2), "big")
        extension_size = int.from_bytes(take(2), "big")
        extension = take(extension_size)
        if extension_type != 0:
            continue
        if len(extension) < 5 or int.from_bytes(extension[:2], "big") != len(extension) - 2:
            raise EgressProxyProtocolError("tls_sni_extension_invalid")
        name_offset = 2
        names: list[str] = []
        while name_offset < len(extension):
            if name_offset + 3 > len(extension):
                raise EgressProxyProtocolError("tls_sni_extension_invalid")
            name_type = extension[name_offset]
            name_size = int.from_bytes(extension[name_offset + 1 : name_offset + 3], "big")
            name_offset += 3
            if name_offset + name_size > len(extension):
                raise EgressProxyProtocolError("tls_sni_extension_invalid")
            raw_name = extension[name_offset : name_offset + name_size]
            name_offset += name_size
            if name_type == 0:
                try:
                    names.append(normalize_egress_host(raw_name.decode("ascii")))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise EgressProxyProtocolError("tls_sni_name_invalid") from exc
        if len(names) != 1:
            raise EgressProxyProtocolError("tls_sni_name_required")
        return names[0]
    raise EgressProxyProtocolError("tls_sni_extension_required")


def _connect_numeric(ip: str, port: int, timeout_s: float) -> socket.socket:
    address = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    upstream = socket.socket(family, socket.SOCK_STREAM)
    upstream.settimeout(timeout_s)
    try:
        target: tuple[object, ...] = (str(address), port, 0, 0) if address.version == 6 else (str(address), port)
        upstream.connect(target)
    except Exception:
        upstream.close()
        raise
    return upstream


def _relay_bidirectional(left: socket.socket, right: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    peers = {left: right, right: left}
    buffers = {left: bytearray(), right: bytearray()}
    read_open = {left: True, right: True}
    write_shutdown = {left: False, right: False}
    for sock in peers:
        sock.setblocking(False)

    def shutdown_write(sock: socket.socket) -> None:
        if write_shutdown[sock]:
            return
        write_shutdown[sock] = True
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def refresh(sock: socket.socket) -> None:
        if not read_open[peers[sock]] and not buffers[sock]:
            shutdown_write(sock)
        events = 0
        if read_open[sock] and len(buffers[peers[sock]]) < RELAY_BUFFER_LIMIT_BYTES:
            events |= selectors.EVENT_READ
        if buffers[sock]:
            events |= selectors.EVENT_WRITE
        try:
            selector.get_key(sock)
        except KeyError:
            if events:
                selector.register(sock, events)
        else:
            if events:
                selector.modify(sock, events)
            else:
                selector.unregister(sock)

    for sock in peers:
        refresh(sock)
    try:
        while selector.get_map():
            events = selector.select(timeout=1.0)
            if not events:
                continue
            for key, mask in events:
                sock = key.fileobj
                assert isinstance(sock, socket.socket)
                if mask & selectors.EVENT_READ and read_open[sock]:
                    target = peers[sock]
                    available = RELAY_BUFFER_LIMIT_BYTES - len(buffers[target])
                    try:
                        chunk = sock.recv(min(RELAY_CHUNK_BYTES, available))
                    except BlockingIOError:
                        chunk = None
                    if chunk:
                        buffers[target].extend(chunk)
                    elif chunk == b"":
                        read_open[sock] = False
                if mask & selectors.EVENT_WRITE and buffers[sock]:
                    try:
                        sent = sock.send(buffers[sock])
                    except BlockingIOError:
                        sent = 0
                    if sent > 0:
                        del buffers[sock][:sent]
            for sock in peers:
                refresh(sock)
    finally:
        selector.close()


def _send_response(client: socket.socket, status: int, reason: str) -> None:
    try:
        client.sendall(
            f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nProxy-Agent: argus-s10\r\n\r\n".encode("ascii")
        )
    except OSError:
        pass


def _safe_reason(exc: BaseException, fallback: str) -> str:
    if isinstance(exc, EgressProxyProtocolError) and str(exc):
        return str(exc)
    return fallback


def _peer_label(peer: tuple[object, ...]) -> str:
    return str(peer[0]) if peer else "unknown"


class _JsonLineAuditSink:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def __call__(self, event_type: str, payload: dict[str, object]) -> None:
        line = canonical_json_bytes({"event_type": event_type, "payload": payload}).decode("utf-8")
        with self._lock:
            print(line, flush=True)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw is not None else default


def _load_manifest() -> EgressProxyManifest:
    manifest_path = os.environ.get("ARGUS_S10_EGRESS_MANIFEST_PATH")
    raw = Path(manifest_path).read_text(encoding="utf-8") if manifest_path else os.environ.get(
        "ARGUS_S10_EGRESS_MANIFEST_JSON", ""
    )
    expected_hash = os.environ.get("ARGUS_S10_EGRESS_MANIFEST_HASH", "")
    return EgressProxyManifest.from_json(raw, expected_hash=expected_hash)


def _prepare_runtime_file(path: str | None, *, uid: int, gid: int) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(mode=0o600, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(target, uid, gid)


def _drop_privileges(*, uid: int, gid: int) -> None:
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    if os.geteuid() != uid or os.getegid() != gid:
        raise RuntimeError("egress proxy could not assume its dedicated uid/gid")


def _effective_capabilities() -> str:
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith("CapEff:"):
            value = line.split(":", 1)[1].strip().lower()
            if value and all(character in "0123456789abcdef" for character in value):
                return value
            break
    raise RuntimeError("egress proxy could not attest its effective capabilities")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default=os.environ.get("ARGUS_S10_EGRESS_LISTEN_HOST", "127.0.0.1"))
    parser.add_argument("--listen-port", type=int, default=_env_int("ARGUS_S10_EGRESS_LISTEN_PORT", DEFAULT_PROXY_PORT))
    parser.add_argument("--proxy-uid", type=int, default=_env_int("ARGUS_S10_EGRESS_PROXY_UID", DEFAULT_PROXY_UID))
    parser.add_argument("--proxy-gid", type=int, default=_env_int("ARGUS_S10_EGRESS_PROXY_GID", DEFAULT_PROXY_UID))
    parser.add_argument("--sandbox-uid", type=int, default=_env_int("ARGUS_S10_SANDBOX_UID", DEFAULT_SANDBOX_UID))
    parser.add_argument("--dns-server", action="append", default=[])
    parser.add_argument("--dns-port", type=int, default=_env_int("ARGUS_S10_EGRESS_DNS_PORT", 53))
    parser.add_argument("--apply-firewall", action="store_true")
    parser.add_argument("--ready-file", default=os.environ.get("ARGUS_S10_EGRESS_READY_FILE"))
    parser.add_argument("--pid-file", default=os.environ.get("ARGUS_S10_EGRESS_PID_FILE"))
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    manifest = _load_manifest()
    if args.apply_firewall:
        if os.geteuid() != 0:
            raise RuntimeError("egress firewall setup requires root in the isolated network namespace")
        LinuxEgressFirewall(
            proxy_port=args.listen_port,
            proxy_uid=args.proxy_uid,
            sandbox_uid=args.sandbox_uid,
            dns_port=args.dns_port,
        ).apply()
    _prepare_runtime_file(args.ready_file, uid=args.proxy_uid, gid=args.proxy_gid)
    _prepare_runtime_file(args.pid_file, uid=args.proxy_uid, gid=args.proxy_gid)
    _drop_privileges(uid=args.proxy_uid, gid=args.proxy_gid)
    effective_capabilities = _effective_capabilities()
    if int(effective_capabilities, 16) != 0:
        raise RuntimeError("egress proxy retained effective capabilities after privilege drop")
    if args.pid_file:
        Path(args.pid_file).write_text(f"{os.getpid()}\n", encoding="ascii")

    env_dns_servers = tuple(filter(None, os.environ.get("ARGUS_S10_EGRESS_DNS_SERVERS", "").split(",")))
    resolver = DnsAddressResolver(
        nameservers=tuple(args.dns_server) or env_dns_servers,
        nameserver_port=args.dns_port,
    )
    audit_sink = _JsonLineAuditSink()
    proxy = EgressConnectProxy(manifest=manifest, resolver=resolver, audit_sink=audit_sink)
    stop_event = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda _signum, _frame: stop_event.set())

    def ready(listener: socket.socket) -> None:
        if args.ready_file:
            Path(args.ready_file).write_text("ready\n", encoding="ascii")
        audit_sink(
            "egress.ready",
            {
                "sandbox_id": manifest.sandbox_id,
                "job_id": manifest.job_id,
                "manifest_hash": manifest.manifest_hash,
                "listen_host": args.listen_host,
                "listen_port": listener.getsockname()[1],
                "proxy_uid": os.geteuid(),
                "effective_capabilities": effective_capabilities,
                "rule_count": len(manifest.rules),
            },
        )

    proxy.serve_forever(
        host=args.listen_host,
        port=args.listen_port,
        stop_event=stop_event,
        ready=ready,
    )


if __name__ == "__main__":
    main()
