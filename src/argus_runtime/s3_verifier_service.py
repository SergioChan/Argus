"""S3 verifier API transport skeleton."""

from __future__ import annotations

from concurrent import futures
from dataclasses import asdict, dataclass
import json
from typing import Any, Callable, Mapping
from uuid import NAMESPACE_URL, uuid5

import grpc

from argus_core import (
    FrozenPipelineEntrypointContractError,
    build_frozen_pipeline_entrypoint_request,
    hash_json,
)

from .auth import RuntimeAuth, RuntimeIdentity, UnauthorizedError, require_static_bearer_token
from .http_json import JsonHttpApp, JsonRequest, serve_json_app


S3_VERIFY_CAPABILITY = "s3.verify"
S3_CLIENT_CERT_SUBJECT_HEADER = "x-argus-client-cert-subject"
S3_GRPC_SERVICE = "argus.s3.VerifierApi"
S3_GRPC_METHODS = {"SubmitVerification": "submit_verification"}


class S3ApiValidationError(Exception):
    """Raised when an API request is syntactically valid JSON but not a valid S3 request."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class S3ScopeDeniedError(Exception):
    """Raised when a caller lacks the S3 verifier capability."""


class S3MutualTlsError(Exception):
    """Raised when the mTLS-authenticated caller subject is absent or mismatched."""

    def __init__(self, *, code: str, message: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class S3ApiTraceSpan:
    trace_id: str
    span_id: str
    name: str
    status: str
    attributes: dict[str, Any]


class InMemoryS3TelemetrySink:
    """Deterministic trace sink for local S3 API tests and CI evidence."""

    def __init__(self) -> None:
        self._spans: list[S3ApiTraceSpan] = []

    def record(self, *, trace_id: str, name: str, status: str, attributes: Mapping[str, Any]) -> S3ApiTraceSpan:
        span = S3ApiTraceSpan(
            trace_id=trace_id,
            span_id=str(uuid5(NAMESPACE_URL, f"argus:s3:span:{trace_id}:{name}:{len(self._spans)}")),
            name=name,
            status=status,
            attributes={str(key): _jsonable(value) for key, value in attributes.items()},
        )
        self._spans.append(span)
        return span

    def spans(self, *, trace_id: str | None = None) -> tuple[S3ApiTraceSpan, ...]:
        if trace_id is None:
            return tuple(self._spans)
        return tuple(span for span in self._spans if span.trace_id == trace_id)


@dataclass(frozen=True)
class S3VerificationDispatch:
    request_id: str
    job_id: str
    profile_ref: str
    frozen_pipeline_ref: str
    trace_id: str
    caller_id: str
    client_cert_subject: str
    transport: str
    entrypoint_request: dict[str, Any]


@dataclass(frozen=True)
class S3GrpcTlsConfig:
    private_key: bytes
    certificate_chain: bytes
    client_root_certificates: bytes


class S3VerifierApiApp:
    """HTTP/gRPC-neutral S3 verifier API skeleton.

    The app dispatches validated verification requests to an in-memory queue for
    S3-T02. S3-T03 owns durable orchestration and report production.
    """

    def __init__(
        self,
        *,
        auth: RuntimeAuth,
        artifact_store: Any,
        health_token: str | None = None,
        telemetry: InMemoryS3TelemetrySink | None = None,
        orchestrator: Any | None = None,
    ) -> None:
        self.auth = auth
        self.artifact_store = artifact_store
        self._health_token = health_token
        self.telemetry = telemetry or InMemoryS3TelemetrySink()
        self._orchestrator = orchestrator
        self._dispatches: list[S3VerificationDispatch] = []
        self.http = JsonHttpApp()
        self._register_routes()

    @property
    def dispatches(self) -> tuple[S3VerificationDispatch, ...]:
        return tuple(self._dispatches)

    def handle_submit(
        self,
        body: Any,
        *,
        headers: Mapping[str, str],
        transport: str,
        grpc_context: grpc.ServicerContext | None = None,
    ) -> tuple[int, dict[str, Any]]:
        trace_id = _trace_id_from_body(body)
        try:
            request_body = _body_dict(body)
            identity = self._authenticate(headers=headers)
            client_cert_subject = self._require_mtls_subject(
                identity=identity,
                headers=headers,
                grpc_context=grpc_context,
            )
            self._require_scope(identity)
            entrypoint_request = build_frozen_pipeline_entrypoint_request(
                request_body,
                artifact_store=self.artifact_store,
            )
            verification_request = entrypoint_request["verification_request"]
            dispatch = S3VerificationDispatch(
                request_id=verification_request["request_id"],
                job_id=verification_request["job_id"],
                profile_ref=verification_request["profile_ref"],
                frozen_pipeline_ref=verification_request["frozen_pipeline_ref"],
                trace_id=trace_id,
                caller_id=identity.caller_id,
                client_cert_subject=client_cert_subject,
                transport=transport,
                entrypoint_request=entrypoint_request,
            )
            self._dispatches.append(dispatch)
            workflow_state = self._orchestrator.start(dispatch) if self._orchestrator is not None else None
            self._record_trace(
                trace_id=trace_id,
                status="OK",
                transport=transport,
                attributes={
                    "caller_id": identity.caller_id,
                    "client_cert_subject": client_cert_subject,
                    "request_id": dispatch.request_id,
                    "job_id": dispatch.job_id,
                    "profile_ref": dispatch.profile_ref,
                    "frozen_pipeline_ref": dispatch.frozen_pipeline_ref,
                    **(
                        {
                            "workflow_id": workflow_state.workflow_id,
                            "workflow_type": workflow_state.workflow_type,
                        }
                        if workflow_state is not None
                        else {}
                    ),
                },
            )
            response = {
                "status": "DISPATCHED",
                "transport": transport,
                "trace_id": trace_id,
                "request_id": dispatch.request_id,
                "entrypoint_request": entrypoint_request,
            }
            if workflow_state is not None:
                response.update(
                    {
                        "workflow_id": workflow_state.workflow_id,
                        "workflow_type": workflow_state.workflow_type,
                        "workflow_status": workflow_state.status,
                    }
                )
            return 202, response
        except UnauthorizedError as exc:
            self._record_trace(trace_id=trace_id, status="UNAUTHORIZED", transport=transport, attributes={})
            return 401, {"error": "Unauthorized", "message": str(exc)}
        except S3MutualTlsError as exc:
            self._record_trace(trace_id=trace_id, status="UNAUTHORIZED" if exc.status == 401 else "DENIED", transport=transport, attributes={})
            return exc.status, {"error": exc.code, "message": exc.message}
        except S3ScopeDeniedError as exc:
            self._record_trace(trace_id=trace_id, status="DENIED", transport=transport, attributes={})
            return 403, {"error": "ScopeDenied", "message": str(exc)}
        except FrozenPipelineEntrypointContractError as exc:
            self._record_trace(
                trace_id=trace_id,
                status="INVALID",
                transport=transport,
                attributes={"error_code": exc.code},
            )
            return 422, {"error": exc.code, "message": exc.message}
        except S3ApiValidationError as exc:
            self._record_trace(
                trace_id=trace_id,
                status="INVALID",
                transport=transport,
                attributes={"error_code": exc.code},
            )
            return 422, {"error": exc.code, "message": exc.message}

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(request: JsonRequest) -> tuple[int, Any]:
            try:
                require_static_bearer_token(request, expected_token=self._health_token, purpose="health")
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            return 200, {
                "service": "s3-verifier-api",
                "status": "ok",
                "dispatch_count": len(self._dispatches),
                "required_capability": S3_VERIFY_CAPABILITY,
            }

        @self.http.route("POST", "/v1/verifications")
        def submit(request: JsonRequest) -> tuple[int, Any]:
            return self.handle_submit(request.body, headers=request.headers, transport="http-json")

    def _authenticate(self, *, headers: Mapping[str, str]) -> RuntimeIdentity:
        return self.auth.authenticate(
            JsonRequest(method="POST", path="/v1/verifications", query={}, body=None, headers=dict(headers))
        )

    def _require_mtls_subject(
        self,
        *,
        identity: RuntimeIdentity,
        headers: Mapping[str, str],
        grpc_context: grpc.ServicerContext | None,
    ) -> str:
        subject = str(headers.get(S3_CLIENT_CERT_SUBJECT_HEADER, "")).strip()
        if not subject and grpc_context is not None:
            subject = _grpc_client_cert_subject(grpc_context)
        if not subject:
            raise S3MutualTlsError(
                code="MutualTlsRequired",
                message="client certificate subject is required",
                status=401,
            )
        if subject != identity.caller_id:
            raise S3MutualTlsError(
                code="MutualTlsSubjectMismatch",
                message="client certificate subject does not match authenticated caller",
                status=403,
            )
        return subject

    def _require_scope(self, identity: RuntimeIdentity) -> None:
        if S3_VERIFY_CAPABILITY not in identity.scopes.capabilities:
            raise S3ScopeDeniedError(f"missing capability: {S3_VERIFY_CAPABILITY}")

    def _record_trace(
        self,
        *,
        trace_id: str,
        status: str,
        transport: str,
        attributes: Mapping[str, Any],
    ) -> None:
        self.telemetry.record(
            trace_id=trace_id,
            name="S3.verification.dispatch",
            status=status,
            attributes={"transport": transport, **dict(attributes)},
        )


def build_s3_grpc_server(
    app: S3VerifierApiApp,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    max_workers: int = 4,
    tls: S3GrpcTlsConfig | None = None,
) -> tuple[grpc.Server, int]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    handlers = {
        grpc_name: grpc.unary_unary_rpc_method_handler(
            _grpc_behavior(app, method),
            request_deserializer=_grpc_decode,
            response_serializer=_grpc_encode,
        )
        for grpc_name, method in S3_GRPC_METHODS.items()
    }
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(S3_GRPC_SERVICE, handlers),))
    address = f"{host}:{port}"
    if tls is None:
        bound_port = server.add_insecure_port(address)
    else:
        credentials = grpc.ssl_server_credentials(
            [(tls.private_key, tls.certificate_chain)],
            root_certificates=tls.client_root_certificates,
            require_client_auth=True,
        )
        bound_port = server.add_secure_port(address, credentials)
    return server, bound_port


def serve_http(app: S3VerifierApiApp, *, host: str, port: int) -> None:
    serve_json_app(app.http, host=host, port=port)


def _grpc_behavior(
    app: S3VerifierApiApp,
    method: str,
) -> Callable[[dict[str, Any], grpc.ServicerContext], dict[str, Any]]:
    def call(request: dict[str, Any], context: grpc.ServicerContext) -> dict[str, Any]:
        if method != "submit_verification":
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"unknown S3 method {method}")
            return {"error": "method_not_found"}
        headers = {key.lower(): value for key, value in context.invocation_metadata()}
        status, payload = app.handle_submit(
            request,
            headers=headers,
            transport="grpc-json",
            grpc_context=context,
        )
        if status >= 400:
            context.set_code(_grpc_status(status))
            context.set_details(json.dumps(payload, sort_keys=True))
        return payload

    return call


def _grpc_status(status: int) -> grpc.StatusCode:
    if status == 401:
        return grpc.StatusCode.UNAUTHENTICATED
    if status == 403:
        return grpc.StatusCode.PERMISSION_DENIED
    if status == 422:
        return grpc.StatusCode.INVALID_ARGUMENT
    if status == 404:
        return grpc.StatusCode.NOT_FOUND
    return grpc.StatusCode.UNKNOWN


def _grpc_decode(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("S3 gRPC JSON payload must be an object")
    return value


def _grpc_encode(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True).encode("utf-8")


def _body_dict(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise S3ApiValidationError(code="S3_VERIFICATION_REQUEST_INVALID", message="request body must be a JSON object")
    return {str(key): _jsonable(value) for key, value in body.items()}


def _trace_id_from_body(body: Any) -> str:
    if isinstance(body, Mapping):
        value = body.get("trace_id")
        if isinstance(value, str) and value:
            return value
        job_id = body.get("job_id")
        if isinstance(job_id, str) and job_id:
            return f"trace:{job_id}"
    return "trace:s3"


def _grpc_client_cert_subject(context: grpc.ServicerContext) -> str:
    auth_context = context.auth_context()
    for key in ("x509_subject", "x509_common_name"):
        values = auth_context.get(key, ())
        if values:
            value = values[0]
            if isinstance(value, bytes):
                return value.decode("utf-8")
            return str(value)
    return ""


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def dispatch_digest(dispatch: S3VerificationDispatch) -> str:
    return hash_json(asdict(dispatch))
