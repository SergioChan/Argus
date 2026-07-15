"""Authenticated client for the isolation-aware host security-monitor bridge."""

from __future__ import annotations

from dataclasses import fields
import json
import threading
from typing import Any
from urllib import error, parse, request

from argus_core import (
    HostSecurityEvent,
    SecurityMonitorError,
    SecurityMonitorPoll,
    SecurityMonitorRegistration,
)


MAX_MONITOR_RESPONSE_BYTES = 1024 * 1024
BRIDGE_ENGINE = "argus-host-security"
SENSOR_ENGINES = ("falco-modern-ebpf", "gvisor-runtime-monitor")


class _RejectRedirects(request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class HttpSecurityMonitorClient:
    """Fail-closed HTTP client used only by the trusted S10 supervisor."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        auth_token: str,
        allow_insecure: bool = False,
        timeout_s: float = 1.0,
    ) -> None:
        endpoint = endpoint_url.rstrip("/")
        parsed = parse.urlsplit(endpoint)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("security monitor endpoint must be an HTTP(S) origin")
        if parsed.scheme != "https" and not allow_insecure:
            raise ValueError("security monitor endpoint requires HTTPS unless explicitly allowed")
        if not auth_token:
            raise ValueError("security monitor auth token is required")
        if timeout_s <= 0:
            raise ValueError("security monitor timeout must be positive")
        self._endpoint = endpoint
        self._auth_token = auth_token
        self._timeout_s = float(timeout_s)
        self._opener = request.build_opener(_RejectRedirects())
        self._registrations: dict[str, str] = {}
        self._registrations_lock = threading.Lock()

    def health(self, *, required_engine: str | None = None) -> dict[str, Any]:
        payload = self._request("GET", "/healthz", expected=(200,))
        expected_fields = {"service", "status", "engine", "overflowed", "sources"}
        if set(payload) != expected_fields:
            raise SecurityMonitorError("security monitor health response fields are invalid")
        sources = payload.get("sources")
        if not isinstance(sources, dict) or set(sources) != set(SENSOR_ENGINES):
            raise SecurityMonitorError("security monitor source health fields are invalid")
        for engine in SENSOR_ENGINES:
            source = sources.get(engine)
            if not isinstance(source, dict) or set(source) != {"configured", "running", "degraded"}:
                raise SecurityMonitorError("security monitor source health fields are invalid")
            if any(not isinstance(source[field], bool) for field in source):
                raise SecurityMonitorError("security monitor source health values are invalid")
        if (
            payload.get("service") != "argus-s10-security-monitor"
            or payload.get("status") not in {"ok", "degraded", "error"}
            or payload.get("engine") != BRIDGE_ENGINE
            or payload.get("overflowed") is not False
        ):
            raise SecurityMonitorError("security monitor is not healthy")
        if required_engine is None:
            if payload["status"] != "ok":
                raise SecurityMonitorError("security monitor is not healthy")
        else:
            if required_engine not in SENSOR_ENGINES:
                raise SecurityMonitorError("security monitor required source is invalid")
            required = sources[required_engine]
            if not required["configured"] or not required["running"] or required["degraded"]:
                raise SecurityMonitorError(f"security monitor source is not healthy: {required_engine}")
        return payload

    def register(self, registration: SecurityMonitorRegistration) -> None:
        self.health(required_engine=registration.engine)
        payload = self._request(
            "POST",
            "/v1/registrations",
            body=registration.as_wire_payload(),
            expected=(201,),
        )
        expected = {
            "registered": True,
            "sandbox_id": registration.sandbox_id,
            "job_id": registration.job_id,
            "isolation_class": registration.isolation_class,
            "runtime_kind": registration.runtime_kind,
            "engine": registration.engine,
            "cursor": 0,
        }
        if payload != expected:
            raise SecurityMonitorError("security monitor registration response differs from the request")
        with self._registrations_lock:
            if registration.sandbox_id in self._registrations:
                raise SecurityMonitorError("security monitor client already registered the sandbox")
            self._registrations[registration.sandbox_id] = registration.engine

    def poll(self, *, sandbox_id: str, after: int) -> SecurityMonitorPoll:
        if not sandbox_id:
            raise ValueError("security monitor poll requires sandbox_id")
        if isinstance(after, bool) or not isinstance(after, int) or after < 0:
            raise ValueError("security monitor poll cursor must be non-negative")
        with self._registrations_lock:
            expected_engine = self._registrations.get(sandbox_id)
        if expected_engine is None:
            raise SecurityMonitorError("security monitor sandbox is not registered by this client")
        encoded_id = parse.quote(sandbox_id, safe="._-:")
        payload = self._request(
            "GET",
            f"/v1/registrations/{encoded_id}/events?after={after}",
            expected=(200,),
        )
        expected_fields = {"sandbox_id", "cursor", "healthy", "engine", "overflowed", "events"}
        if set(payload) != expected_fields or payload.get("sandbox_id") != sandbox_id:
            raise SecurityMonitorError("security monitor poll response identity is invalid")
        raw_events = payload.get("events")
        if not isinstance(raw_events, list):
            raise SecurityMonitorError("security monitor events must be a list")
        event_fields = {field.name for field in fields(HostSecurityEvent)}
        events: list[HostSecurityEvent] = []
        for raw_event in raw_events:
            if not isinstance(raw_event, dict) or set(raw_event) != event_fields:
                raise SecurityMonitorError("security monitor event fields are invalid")
            try:
                event = HostSecurityEvent(**raw_event)
            except (TypeError, ValueError) as exc:
                raise SecurityMonitorError("security monitor emitted an invalid event") from exc
            if event.sandbox_id != sandbox_id:
                raise SecurityMonitorError("security monitor emitted an invalid event identity")
            events.append(event)
        try:
            poll = SecurityMonitorPoll(
                cursor=payload["cursor"],
                healthy=payload["healthy"],
                engine=payload["engine"],
                overflowed=payload["overflowed"],
                events=tuple(events),
            )
        except (TypeError, ValueError) as exc:
            raise SecurityMonitorError("security monitor emitted an invalid poll response") from exc
        if poll.engine != expected_engine:
            raise SecurityMonitorError("security monitor poll source differs from the registered isolation class")
        if poll.cursor < after or any(event.sequence <= after for event in poll.events):
            raise SecurityMonitorError("security monitor poll did not advance monotonically")
        return poll

    def unregister(self, *, sandbox_id: str) -> None:
        if not sandbox_id:
            raise ValueError("security monitor unregister requires sandbox_id")
        encoded_id = parse.quote(sandbox_id, safe="._-:")
        payload = self._request(
            "DELETE",
            f"/v1/registrations/{encoded_id}",
            expected=(200,),
        )
        if payload != {"registered": False, "sandbox_id": sandbox_id}:
            raise SecurityMonitorError("security monitor unregister response is invalid")
        with self._registrations_lock:
            if self._registrations.pop(sandbox_id, None) is None:
                raise SecurityMonitorError("security monitor sandbox was not registered by this client")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        expected: tuple[int, ...],
    ) -> dict[str, Any]:
        encoded = None if body is None else json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._auth_token}",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        outbound = request.Request(
            f"{self._endpoint}{path}",
            data=encoded,
            headers=headers,
            method=method,
        )
        status: int
        raw: bytes
        try:
            with self._opener.open(outbound, timeout=self._timeout_s) as response:
                status = response.status
                raw = response.read(MAX_MONITOR_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            status = exc.code
            raw = exc.read(MAX_MONITOR_RESPONSE_BYTES + 1)
        except (OSError, TimeoutError) as exc:
            raise SecurityMonitorError("host security monitor is unavailable") from exc
        if len(raw) > MAX_MONITOR_RESPONSE_BYTES:
            raise SecurityMonitorError("security monitor response exceeded the control-plane limit")
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecurityMonitorError("security monitor returned invalid JSON") from exc
        if status not in expected:
            detail = payload.get("error") if isinstance(payload, dict) else None
            suffix = f": {detail}" if isinstance(detail, str) and detail else ""
            raise SecurityMonitorError(f"security monitor returned HTTP {status}{suffix}")
        if not isinstance(payload, dict):
            raise SecurityMonitorError("security monitor returned a non-object response")
        return payload
