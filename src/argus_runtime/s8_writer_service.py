"""S8 writer service for the argus-m0 stack."""

from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import hmac
import os
from pathlib import Path
from typing import Any

from argus_core import FileSystemArtifactStore, Lineage, Producer, canonical_json_bytes

from .auth import RuntimeAuth, UnauthorizedError, runtime_auth_from_env
from .http_json import JsonHttpApp, JsonRequest, serve_json_app


class S8WriterApp:
    def __init__(
        self,
        store: FileSystemArtifactStore,
        *,
        data_dir: str | os.PathLike[str] | None = None,
        auth: RuntimeAuth | None = None,
        broker_write_key: bytes | None = None,
    ) -> None:
        self.store = store
        self._data_dir = Path(data_dir) if data_dir is not None else None
        self.auth = auth
        self._broker_write_key = broker_write_key
        self.http = JsonHttpApp()
        self._register_routes()

    def create_artifact(self, body: dict[str, Any]) -> dict[str, Any]:
        self._refresh_store()
        record = self.store.create_artifact(
            kind=_required_str(body, "kind"),
            payload=body.get("payload"),
            producer=Producer(**_required_dict(body, "producer")),
            lineage=Lineage(**_normalize_lineage(_required_dict(body, "lineage"))),
            artifact_ref=body.get("artifact_ref") if isinstance(body.get("artifact_ref"), str) else None,
            claim_tier=body.get("claim_tier") if isinstance(body.get("claim_tier"), str) else "ran-toy",
            validation_report_ref=body.get("validation_report_ref")
            if isinstance(body.get("validation_report_ref"), str)
            else None,
        )
        return asdict(record)

    def create_brokered_artifact(self, body: dict[str, Any]) -> dict[str, Any]:
        authorization = _required_dict(body, "authorization")
        if authorization.get("audience") != "store":
            raise PermissionError("broker authorization audience must be store")
        scope_job_id = _required_str(authorization, "scope_job_id")
        producer_subsystems = tuple(authorization.get("producer_subsystems") or ())
        producer_body = _required_dict(body, "producer")
        lineage_body = _normalize_lineage(_required_dict(body, "lineage"))
        producer = Producer(**producer_body)
        lineage = Lineage(**lineage_body)
        if producer.job_id != scope_job_id or lineage.job_id != scope_job_id:
            raise PermissionError("broker authorization job_id does not match producer/lineage")
        if producer.subsystem not in producer_subsystems:
            raise PermissionError("broker authorization does not allow producer subsystem")
        return self.create_artifact(
            {
                "kind": _required_str(body, "kind"),
                "payload": body.get("payload"),
                "producer": asdict(producer),
                "lineage": asdict(lineage),
                "artifact_ref": body.get("artifact_ref") if isinstance(body.get("artifact_ref"), str) else None,
                "claim_tier": body.get("claim_tier") if isinstance(body.get("claim_tier"), str) else "ran-toy",
                "validation_report_ref": body.get("validation_report_ref")
                if isinstance(body.get("validation_report_ref"), str)
                else None,
            }
        )

    def get_artifact_record(self, ref: str) -> dict[str, Any]:
        self._refresh_store()
        return asdict(self.store.get_artifact_record(ref))

    def get_lineage(self, ref: str, *, direction: str) -> dict[str, Any]:
        self._refresh_store()
        graph = self.store.get_lineage(ref, direction=direction)
        return {
            "nodes": [asdict(node) for node in graph.nodes],
            "edges": [asdict(edge) for edge in graph.edges],
        }

    def _refresh_store(self) -> None:
        if self._data_dir is not None:
            self.store = FileSystemArtifactStore(self._data_dir)

    def _authenticate(self, request: JsonRequest) -> tuple[bool, dict[str, Any] | None]:
        try:
            if self.auth is None:
                raise UnauthorizedError("runtime auth is not configured")
            self.auth.authenticate(request)
            return True, None
        except UnauthorizedError as exc:
            return False, {"error": "Unauthorized", "message": str(exc)}

    def _authenticate_broker_write(self, request: JsonRequest) -> tuple[bool, dict[str, Any] | None]:
        if self._broker_write_key is None:
            return False, {"error": "Unauthorized", "message": "broker write key is not configured"}
        signature = request.headers.get("x-argus-store-write-signature", "")
        expected = "hmac-sha256:" + hmac.new(
            self._broker_write_key,
            canonical_json_bytes(request.body),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False, {"error": "Unauthorized", "message": "broker write signature invalid"}
        return True, None

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(request: JsonRequest) -> tuple[int, Any]:
            authenticated, error_response = self._authenticate(request)
            if not authenticated:
                return 401, error_response
            self._refresh_store()
            return 200, {"service": "s8-writer", "status": "ok", "record_count": self.store.record_count}

        @self.http.route("POST", "/v1/artifacts")
        def create(request: JsonRequest) -> tuple[int, Any]:
            authenticated, error_response = self._authenticate(request)
            if not authenticated:
                return 401, error_response
            return 403, {
                "error": "DirectWriteDenied",
                "message": "artifact writes must use the S10 store broker",
            }

        @self.http.route("POST", "/v1/internal/brokered-artifacts")
        def create_brokered(request: JsonRequest) -> tuple[int, Any]:
            authenticated, error_response = self._authenticate_broker_write(request)
            if not authenticated:
                return 401, error_response
            try:
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.create_brokered_artifact(request.body)
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.prefix("GET", "/v1/artifacts/")
        def get_record(request: JsonRequest) -> tuple[int, Any]:
            authenticated, error_response = self._authenticate(request)
            if not authenticated:
                return 401, error_response
            suffix = request.path.removeprefix("/v1/artifacts/")
            if not suffix.endswith("/record"):
                return 404, {"error": "not_found"}
            artifact_ref = suffix.removesuffix("/record")
            try:
                return 200, self.get_artifact_record(artifact_ref)
            except Exception as exc:
                return 404, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.prefix("GET", "/v1/lineage/")
        def lineage(request: JsonRequest) -> tuple[int, Any]:
            authenticated, error_response = self._authenticate(request)
            if not authenticated:
                return 401, error_response
            artifact_ref = request.path.removeprefix("/v1/lineage/")
            direction = request.query.get("direction", ["both"])[0]
            try:
                return 200, self.get_lineage(artifact_ref, direction=direction)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}


def build_app_from_env() -> S8WriterApp:
    data_dir = os.environ.get("ARGUS_S8_DATA_DIR", "/var/lib/argus/s8")
    broker_write_key = os.environ.get("ARGUS_S8_BROKER_WRITE_KEY")
    return S8WriterApp(
        FileSystemArtifactStore(data_dir),
        data_dir=data_dir,
        auth=runtime_auth_from_env(),
        broker_write_key=broker_write_key.encode("utf-8") if broker_write_key else None,
    )


def main() -> None:
    host = os.environ.get("ARGUS_S8_HOST", "127.0.0.1")
    port = int(os.environ.get("ARGUS_S8_PORT", "8080"))
    serve_json_app(build_app_from_env().http, host=host, port=port)


def _required_str(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    return value


def _required_dict(body: dict[str, Any], field: str) -> dict[str, Any]:
    value = body.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"{field} is required")
    return dict(value)


def _normalize_lineage(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    normalized["input_refs"] = tuple(normalized.get("input_refs") or ())
    normalized["seeds"] = tuple(normalized.get("seeds") or ())
    return normalized


if __name__ == "__main__":
    main()
