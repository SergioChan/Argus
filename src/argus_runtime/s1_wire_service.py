"""C1 wire API service for the S1 subagent runtime."""

from __future__ import annotations

from concurrent import futures
from dataclasses import asdict, is_dataclass
import json
from typing import Any, Callable

import grpc

from argus_core import (
    ErrorEnvelope,
    JobEnvelope,
    LifecycleEvent,
    LifecyclePolicyError,
    LifecycleState,
    SubagentDescriptor,
    SubagentRuntime,
    build_error_envelope,
    parse_job_envelope,
)
from .http_json import JsonHttpApp, JsonRequest, serve_json_app


C1_GRPC_SERVICE = "argus.c1.SubagentRuntime"
C1_GRPC_METHODS = {
    "Register": "register",
    "Accept": "accept",
    "Plan": "plan",
    "Build": "build",
    "Validate": "validate",
    "Report": "report",
    "Cancel": "cancel",
    "Heartbeat": "heartbeat",
}


class C1WireService:
    """Transport-neutral C1 method dispatcher backed by the real S1 runtime."""

    def __init__(self, runtime: SubagentRuntime) -> None:
        self.runtime = runtime

    @property
    def descriptor(self) -> SubagentDescriptor:
        return self.runtime.descriptor

    def handle(self, method: str, request: dict[str, Any] | None) -> tuple[int, dict[str, Any]]:
        body = request or {}
        try:
            if method == "register":
                return 200, self._register(body)
            if method == "accept":
                return 200, self._accept(body)
            if method in {"plan", "build", "validate", "report"}:
                return 200, self._transition(method, body)
            if method == "cancel":
                return 200, self._cancel(body)
            if method == "heartbeat":
                return self._heartbeat(body)
        except LifecyclePolicyError as exc:
            return 409, {"error": exc.envelope.as_c1_payload()}
        except ValueError as exc:
            return 400, {"error": _error_payload("INVALID_REQUEST", "PERMANENT", str(exc))}
        except KeyError as exc:
            return 404, {"error": _error_payload("JOB_NOT_FOUND", "NOT_FOUND", f"unknown job {exc.args[0]}")}
        return 404, {"error": _error_payload("METHOD_NOT_FOUND", "PERMANENT", f"unknown C1 method {method}")}

    def _register(self, body: dict[str, Any]) -> dict[str, Any]:
        requested_subagent_id = body.get("subagent_id")
        return self.runtime.register(
            subagent_id=requested_subagent_id,
            root_request_id=_root_request_id(body, self.descriptor.subagent_id),
            trace_id=_trace_id(body, self.descriptor.subagent_id),
        )

    def _accept(self, body: dict[str, Any]) -> dict[str, Any]:
        envelope_payload = _job_envelope_payload(body)
        envelope = parse_job_envelope(envelope_payload)
        acceptance = self.runtime.accept(
            envelope,
            idempotency_key=_idempotency_key(body),
            root_request_id=_root_request_id(body, envelope.job_id),
            trace_id=_trace_id(body, envelope.job_id),
        )
        return acceptance.as_c1_payload()

    def _transition(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        job_id = _required_string(body, "job_id")
        event = self.runtime.store.apply_method(
            job_id,
            method,
            trigger=_trigger(body, method),
            payload=body.get("payload") or {},
            idempotency_key=_idempotency_key(body),
            root_request_id=_root_request_id(body, job_id),
            trace_id=_trace_id(body, job_id),
        )
        self.runtime._record_method_span(
            method,
            job_id=job_id,
            root_request_id=_root_request_id(body, job_id),
            trace_id=_trace_id(body, job_id),
            attributes={"state": event.to_state.value},
        )
        return lifecycle_event_wire_payload(event)

    def _cancel(self, body: dict[str, Any]) -> dict[str, Any]:
        job_id = _required_string(body, "job_id")
        payload = body.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValueError("cancel payload must be an object")
        reason = payload.get("reason", body.get("reason", "operator"))
        grace_seconds = payload.get("grace_seconds", body.get("grace_seconds", 30.0))
        event = self.runtime.cancel(
            job_id,
            reason=str(reason),
            grace_seconds=grace_seconds,
            idempotency_key=_idempotency_key(body),
            root_request_id=_root_request_id(body, job_id),
            trace_id=_trace_id(body, job_id),
        )
        return lifecycle_event_wire_payload(event)

    def _heartbeat(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        job_id = _required_string(body, "job_id")
        try:
            heartbeat = self.runtime.heartbeat(
                job_id,
                root_request_id=_root_request_id(body, job_id),
                trace_id=_trace_id(body, job_id),
            )
        except KeyError:
            return 404, {"error": _error_payload("JOB_NOT_FOUND", "NOT_FOUND", f"unknown job {job_id}")}
        return 200, heartbeat.as_c1_payload()


def build_s1_http_app(service: C1WireService) -> JsonHttpApp:
    app = JsonHttpApp()

    @app.route("GET", "/healthz")
    def health(_request: JsonRequest) -> tuple[int, dict[str, Any]]:
        return 200, {"ok": True, "contract": "C1", "transport": "http-json"}

    @app.prefix("POST", "/v1/subagents/")
    def register(request: JsonRequest) -> tuple[int, dict[str, Any]]:
        try:
            subagent_id = _subagent_id_from_path(request.path)
            body = _body_dict(request)
        except ValueError as exc:
            return 400, {"error": _error_payload("INVALID_REQUEST", "PERMANENT", str(exc))}
        body.setdefault("subagent_id", subagent_id)
        return service.handle("register", body)

    @app.prefix("POST", "/v1/jobs/")
    def post_job_method(request: JsonRequest) -> tuple[int, dict[str, Any]]:
        try:
            job_id, method = _job_method_from_path(request.path)
            body = _body_dict(request)
        except ValueError as exc:
            return 400, {"error": _error_payload("INVALID_REQUEST", "PERMANENT", str(exc))}
        if method not in {"accept", "plan", "build", "validate", "cancel"}:
            return 404, {"error": _error_payload("METHOD_NOT_FOUND", "PERMANENT", f"unknown C1 HTTP method {method}")}
        body.setdefault("job_id", job_id)
        return service.handle(method, body)

    @app.prefix("GET", "/v1/jobs/")
    def get_job_method(request: JsonRequest) -> tuple[int, dict[str, Any]]:
        try:
            job_id, method = _job_method_from_path(request.path)
            body = _query_body(request)
        except ValueError as exc:
            return 400, {"error": _error_payload("INVALID_REQUEST", "PERMANENT", str(exc))}
        if method not in {"report", "heartbeat"}:
            return 404, {"error": _error_payload("METHOD_NOT_FOUND", "PERMANENT", f"unknown C1 HTTP method {method}")}
        body.setdefault("job_id", job_id)
        return service.handle(method, body)

    return app


def build_s1_grpc_server(
    service: C1WireService,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    max_workers: int = 4,
) -> tuple[grpc.Server, int]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    handlers = {
        grpc_name: grpc.unary_unary_rpc_method_handler(
            _grpc_behavior(service, method),
            request_deserializer=_grpc_decode,
            response_serializer=_grpc_encode,
        )
        for grpc_name, method in C1_GRPC_METHODS.items()
    }
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(C1_GRPC_SERVICE, handlers),))
    bound_port = server.add_insecure_port(f"{host}:{port}")
    return server, bound_port


def serve_http(service: C1WireService, *, host: str, port: int) -> None:
    serve_json_app(build_s1_http_app(service), host=host, port=port)


def lifecycle_event_wire_payload(event: LifecycleEvent) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": event.event_id,
        "job_id": event.job_id,
        "root_request_id": event.root_request_id,
        "seq": event.sequence,
        "from_state": event.from_state.value,
        "to_state": event.to_state.value,
        "method": event.method,
        "trigger": event.trigger,
        "payload_hash": event.payload_hash,
        "trace_id": event.trace_id,
        "idempotency_key": event.idempotency_key,
    }
    if event.ledger_ref is not None:
        payload["ledger_ref"] = event.ledger_ref
    return payload


def _grpc_behavior(service: C1WireService, method: str) -> Callable[[dict[str, Any], grpc.ServicerContext], dict[str, Any]]:
    def call(request: dict[str, Any], context: grpc.ServicerContext) -> dict[str, Any]:
        status, payload = service.handle(method, request)
        if status >= 400:
            context.set_code(_grpc_status(status))
            context.set_details(json.dumps(payload.get("error", payload), sort_keys=True))
        return payload

    return call


def _grpc_status(status: int) -> grpc.StatusCode:
    if status == 400:
        return grpc.StatusCode.INVALID_ARGUMENT
    if status == 404:
        return grpc.StatusCode.NOT_FOUND
    if status == 409:
        return grpc.StatusCode.FAILED_PRECONDITION
    return grpc.StatusCode.UNKNOWN


def _grpc_decode(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("C1 gRPC JSON payload must be an object")
    return value


def _grpc_encode(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True).encode("utf-8")


def _body_dict(request: JsonRequest) -> dict[str, Any]:
    if request.body is None:
        return {}
    if not isinstance(request.body, dict):
        raise ValueError("C1 HTTP body must be a JSON object")
    return dict(request.body)


def _query_body(request: JsonRequest) -> dict[str, Any]:
    body = {key: values[-1] for key, values in request.query.items() if values}
    if isinstance(request.body, dict):
        body.update(request.body)
    return body


def _subagent_id_from_path(path: str) -> str:
    parts = path.strip("/").split("/")
    if len(parts) != 4 or parts[:2] != ["v1", "subagents"] or parts[3] != "register":
        raise ValueError(f"invalid C1 register path: {path}")
    return parts[2]


def _job_method_from_path(path: str) -> tuple[str, str]:
    parts = path.strip("/").split("/")
    if len(parts) != 4 or parts[:2] != ["v1", "jobs"]:
        raise ValueError(f"invalid C1 job method path: {path}")
    return parts[2], parts[3]


def _job_envelope_payload(body: dict[str, Any]) -> dict[str, Any]:
    payload = body.get("job_envelope", body.get("payload", body))
    if not isinstance(payload, dict):
        raise ValueError("accept requires a JobEnvelope JSON object")
    if "job_id" not in payload and "job_id" in body:
        payload = {**payload, "job_id": body["job_id"]}
    return payload


def _required_string(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} is required")
    return value


def _idempotency_key(body: dict[str, Any]) -> str | None:
    value = body.get("idempotency_key")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("idempotency_key must be a non-empty string")
    return value


def _root_request_id(body: dict[str, Any], job_id: str) -> str:
    value = body.get("root_request_id")
    if value is None:
        return job_id
    if not isinstance(value, str) or not value:
        raise ValueError("root_request_id must be a non-empty string")
    return value


def _trace_id(body: dict[str, Any], job_id: str) -> str:
    value = body.get("trace_id")
    if value is None:
        return f"trace:{job_id}"
    if not isinstance(value, str) or not value:
        raise ValueError("trace_id must be a non-empty string")
    return value


def _trigger(body: dict[str, Any], method: str) -> str:
    value = body.get("trigger")
    if value is None:
        return "cancel" if method == "cancel" else "S5"
    if value not in {"S5", "S4", "internal", "cancel"}:
        raise ValueError("trigger must be one of S5, S4, internal, cancel")
    return value


def _error_payload(code: str, category: str, message: str) -> dict[str, Any]:
    return build_error_envelope(code=code, category=category, message=message).as_c1_payload()


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, LifecycleState):
        return value.value
    return value
