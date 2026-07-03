"""S8 writer service for the argus-m0 stack."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
from typing import Any

from argus_core import (
    ArtifactQueryFilter,
    DatasetRegistry,
    DatasetSplit,
    FileSystemArtifactStore,
    Lineage,
    Producer,
    S8ScopeDeniedError,
    canonical_json_bytes,
)

from .auth import (
    RuntimeAuth,
    RuntimeIdentity,
    UnauthorizedError,
    health_token_from_env,
    require_static_bearer_token,
    runtime_auth_from_env,
)
from .http_json import JsonHttpApp, JsonRequest, serve_json_app


S8_READ_CAPABILITY = "s8.read"
S8_REPRODUCIBILITY_WRITE_CAPABILITY = "s8.reproducibility.write"
S8_DATASET_WRITE_CAPABILITY = "s8.dataset.write"


class S8WriterApp:
    def __init__(
        self,
        store: Any,
        *,
        data_dir: str | os.PathLike[str] | None = None,
        auth: RuntimeAuth | None = None,
        broker_write_key: bytes | None = None,
        health_token: str | None = None,
    ) -> None:
        self.store = store
        self._data_dir = Path(data_dir) if data_dir is not None else None
        self.auth = auth
        self._broker_write_key = broker_write_key
        self._health_token = health_token
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

    def get_artifact_payload(self, ref: str) -> Any:
        self._refresh_store()
        return json.loads(self.store.get_artifact(ref).decode("utf-8"))

    def query_artifacts(
        self,
        query: ArtifactQueryFilter,
        *,
        page_size: int | None = None,
        page_token: int | None = None,
    ) -> dict[str, Any]:
        self._refresh_store()
        page = self.store.query_artifacts_page(query, page_size=page_size, page_token=page_token)
        return {
            "records": [asdict(record) for record in page.records],
            "next_page_token": page.next_page_token,
        }

    def get_lineage(self, ref: str, *, direction: str) -> dict[str, Any]:
        self._refresh_store()
        graph = self.store.get_lineage(ref, direction=direction)
        return {
            "nodes": [asdict(node) for node in graph.nodes],
            "edges": [asdict(edge) for edge in graph.edges],
        }

    def query_impact_set(self, seed_refs: tuple[str, ...], *, edge_types: set[str] | None = None) -> dict[str, Any]:
        self._refresh_store()
        records = self.store.query_impact_set(seed_refs, edge_types=edge_types)
        return {"records": [asdict(record) for record in records]}

    def get_reproducibility_manifest(self, ref: str) -> dict[str, Any]:
        self._refresh_store()
        return asdict(self.store.get_reproducibility_manifest(ref))

    def record_reproducibility_check(self, body: dict[str, Any]) -> dict[str, Any]:
        self._refresh_store()
        return asdict(
            self.store.record_reproducibility_check(
                _required_str(body, "artifact_ref"),
                rerun_payload=body.get("rerun_payload"),
                rerun_content_hash=body.get("rerun_content_hash")
                if isinstance(body.get("rerun_content_hash"), str)
                else None,
                comparator_id=body.get("comparator_id") if isinstance(body.get("comparator_id"), str) else None,
                tolerance_id=body.get("tolerance_id") if isinstance(body.get("tolerance_id"), str) else None,
            )
        )

    def register_dataset(self, body: dict[str, Any]) -> dict[str, Any]:
        self._refresh_store()
        dataset_id = _required_str(body, "dataset_id")
        version = _required_str(body, "version")
        splits = _dataset_splits_from_body(_required_list(body, "splits"))
        contamination_index_version = _required_str(body, "contamination_index_version")
        dataset_artifact_ref = _optional_str(body, "dataset_artifact_ref") or _optional_str(
            body,
            "dataset_artifact_id",
        )
        if hasattr(self.store, "register_dataset"):
            if dataset_artifact_ref is None:
                raise ValueError("dataset_artifact_ref is required")
            return _dataset_wire_payload(
                self.store.register_dataset(
                    dataset_id=dataset_id,
                    version=version,
                    dataset_artifact_ref=dataset_artifact_ref,
                    splits=splits,
                    contamination_index_version=contamination_index_version,
                )
            )
        registry = DatasetRegistry(artifact_store=self.store)
        return _dataset_wire_payload(
            registry.register(
                dataset_id=dataset_id,
                version=version,
                splits=splits,
                contamination_index_version=contamination_index_version,
            )
        )

    def get_dataset(self, dataset_id: str, version: str | None = None) -> dict[str, Any]:
        self._refresh_store()
        if hasattr(self.store, "get_dataset"):
            return _dataset_wire_payload(self.store.get_dataset(dataset_id, version))
        return _dataset_wire_payload(DatasetRegistry(artifact_store=self.store).get(dataset_id, version))

    def list_dataset_versions(self, dataset_id: str) -> dict[str, Any]:
        self._refresh_store()
        if hasattr(self.store, "list_dataset_versions"):
            versions = self.store.list_dataset_versions(dataset_id)
        else:
            versions = DatasetRegistry(artifact_store=self.store).list_versions(dataset_id)
        return {"dataset_id": dataset_id, "versions": list(versions)}

    def resolve_dataset_split(
        self,
        dataset_id: str,
        split_id: str,
        *,
        version: str | None,
        identity: RuntimeIdentity,
    ) -> dict[str, Any]:
        self._refresh_store()
        if hasattr(self.store, "resolve_split"):
            return _dataset_split_resolution_wire_payload(
                self.store.resolve_split(
                    dataset_id=dataset_id,
                    split_id=split_id,
                    version=version,
                    requester_capabilities=identity.scopes.capabilities,
                )
            )
        return _dataset_split_resolution_wire_payload(
            DatasetRegistry(artifact_store=self.store).resolve_split(
                dataset_id=dataset_id,
                version=version,
                split_id=split_id,
                scope_token=identity,
            )
        )

    def export_audit_slice(self, artifact_refs: tuple[str, ...]) -> dict[str, Any]:
        self._refresh_store()
        audit_slice = self.store.export_audit_slice(artifact_refs)
        verification = self.store.verify_audit_slice(audit_slice)
        return {
            "audit_slice": _audit_slice_wire_payload(audit_slice),
            "verification": _structured_payload(verification),
        }

    def _refresh_store(self) -> None:
        if self._data_dir is not None:
            self.store = FileSystemArtifactStore(self._data_dir)
        elif hasattr(self.store, "refresh") and getattr(self.store, "requires_service_refresh", True):
            self.store.refresh()

    def _authenticate(self, request: JsonRequest) -> tuple[bool, dict[str, Any] | None]:
        authorized, _, error_response = self._authorize(request)
        return authorized, error_response

    def _authorize(self, request: JsonRequest, *, capability: str | None = None) -> tuple[bool, int, dict[str, Any] | None]:
        identity, status, error_response = self._authorize_identity(request, capability=capability)
        return identity is not None, status, error_response

    def _authorize_identity(
        self,
        request: JsonRequest,
        *,
        capability: str | None = None,
    ) -> tuple[RuntimeIdentity | None, int, dict[str, Any] | None]:
        try:
            if self.auth is None:
                raise UnauthorizedError("runtime auth is not configured")
            identity = self.auth.authenticate(request)
        except UnauthorizedError as exc:
            return None, 401, {"error": "Unauthorized", "message": str(exc)}
        if capability is not None and capability not in identity.scopes.capabilities:
            return None, 403, {"error": "CapabilityDenied", "message": f"missing capability: {capability}"}
        return identity, 200, None

    def _authenticate_health(self, request: JsonRequest) -> tuple[bool, dict[str, Any] | None]:
        try:
            require_static_bearer_token(request, expected_token=self._health_token, purpose="health")
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
            authenticated, error_response = self._authenticate_health(request)
            if not authenticated:
                return 401, error_response
            self._refresh_store()
            return 200, {
                "service": "s8-writer",
                "status": "ok",
                "record_count": self.store.record_count,
                "ledger_writer": getattr(self.store, "ledger_writer_kind", "filesystem"),
                "checkpoint_signer": getattr(self.store, "checkpoint_signer_kind", "unconfigured"),
                "report_verifier": getattr(self.store, "report_verifier_kind", "unconfigured"),
                "report_verifier_trust_store": getattr(
                    self.store,
                    "report_verifier_trust_store_kind",
                    "unconfigured",
                ),
            }

        @self.http.route("POST", "/v1/artifacts")
        def create(request: JsonRequest) -> tuple[int, Any]:
            authenticated, error_response = self._authenticate(request)
            if not authenticated:
                return 401, error_response
            return 403, {
                "error": "DirectWriteDenied",
                "message": "artifact writes must use the S10 store broker",
            }

        @self.http.route("GET", "/v1/artifacts")
        def query_artifacts(request: JsonRequest) -> tuple[int, Any]:
            authorized, status, error_response = self._authorize(request, capability=S8_READ_CAPABILITY)
            if not authorized:
                return status, error_response
            try:
                return 200, self.query_artifacts(
                    _artifact_query_filter_from_query(request.query),
                    page_size=_query_int(request.query, "page_size"),
                    page_token=_query_int(request.query, "page_token"),
                )
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

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
            authorized, status, error_response = self._authorize(request, capability=S8_READ_CAPABILITY)
            if not authorized:
                return status, error_response
            suffix = request.path.removeprefix("/v1/artifacts/")
            if suffix.endswith("/record"):
                artifact_ref = suffix.removesuffix("/record")
                try:
                    return 200, self.get_artifact_record(artifact_ref)
                except Exception as exc:
                    return 404, {"error": type(exc).__name__, "message": str(exc)}
            if suffix.endswith("/payload"):
                artifact_ref = suffix.removesuffix("/payload")
                try:
                    return 200, self.get_artifact_payload(artifact_ref)
                except Exception as exc:
                    return 404, {"error": type(exc).__name__, "message": str(exc)}
            return 404, {"error": "not_found"}

        @self.http.prefix("GET", "/v1/lineage/")
        def lineage(request: JsonRequest) -> tuple[int, Any]:
            authorized, status, error_response = self._authorize(request, capability=S8_READ_CAPABILITY)
            if not authorized:
                return status, error_response
            artifact_ref = request.path.removeprefix("/v1/lineage/")
            direction = request.query.get("direction", ["both"])[0]
            try:
                return 200, self.get_lineage(artifact_ref, direction=direction)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("GET", "/v1/impact-set")
        def impact_set(request: JsonRequest) -> tuple[int, Any]:
            authorized, status, error_response = self._authorize(request, capability=S8_READ_CAPABILITY)
            if not authorized:
                return status, error_response
            seed_refs = tuple(request.query.get("seed_ref") or ())
            edge_types = set(request.query.get("edge_type") or ()) or None
            if not seed_refs:
                return 400, {"error": "seed_ref_required"}
            try:
                return 200, self.query_impact_set(seed_refs, edge_types=edge_types)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("GET", "/v1/audit-slice")
        def audit_slice(request: JsonRequest) -> tuple[int, Any]:
            authorized, status, error_response = self._authorize(request, capability=S8_READ_CAPABILITY)
            if not authorized:
                return status, error_response
            artifact_refs = tuple(request.query.get("artifact_ref") or ())
            if not artifact_refs:
                return 400, {"error": "artifact_ref_required"}
            try:
                return 200, self.export_audit_slice(artifact_refs)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.prefix("GET", "/v1/reproducibility-manifest/")
        def reproducibility_manifest(request: JsonRequest) -> tuple[int, Any]:
            authorized, status, error_response = self._authorize(request, capability=S8_READ_CAPABILITY)
            if not authorized:
                return status, error_response
            artifact_ref = request.path.removeprefix("/v1/reproducibility-manifest/")
            try:
                return 200, self.get_reproducibility_manifest(artifact_ref)
            except Exception as exc:
                return 404, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/reproducibility-checks")
        def reproducibility_check(request: JsonRequest) -> tuple[int, Any]:
            authorized, status, error_response = self._authorize(
                request,
                capability=S8_REPRODUCIBILITY_WRITE_CAPABILITY,
            )
            if not authorized:
                return status, error_response
            try:
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.record_reproducibility_check(request.body)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/datasets")
        def register_dataset(request: JsonRequest) -> tuple[int, Any]:
            authorized, status, error_response = self._authorize(
                request,
                capability=S8_DATASET_WRITE_CAPABILITY,
            )
            if not authorized:
                return status, error_response
            try:
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.register_dataset(request.body)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.prefix("GET", "/v1/datasets/")
        def get_dataset(request: JsonRequest) -> tuple[int, Any]:
            identity, status, error_response = self._authorize_identity(request, capability=S8_READ_CAPABILITY)
            if identity is None:
                return status, error_response
            suffix = request.path.removeprefix("/v1/datasets/")
            try:
                if suffix.endswith("/versions"):
                    dataset_id = suffix.removesuffix("/versions").rstrip("/")
                    if not dataset_id:
                        return 400, {"error": "dataset_id_required"}
                    return 200, self.list_dataset_versions(dataset_id)
                split_route = _dataset_split_resolve_route(suffix)
                if split_route is not None:
                    dataset_id, split_id = split_route
                    return 200, self.resolve_dataset_split(
                        dataset_id,
                        split_id,
                        version=_query_str(request.query, "version"),
                        identity=identity,
                    )
                if not suffix:
                    return 400, {"error": "dataset_id_required"}
                return 200, self.get_dataset(suffix, version=_query_str(request.query, "version"))
            except S8ScopeDeniedError as exc:
                return 403, _scope_denied_payload(exc)
            except Exception as exc:
                if _is_scope_denied_exception(exc):
                    return 403, _scope_denied_payload(exc)
                return 404, {"error": type(exc).__name__, "message": str(exc)}


def build_app_from_env() -> S8WriterApp:
    broker_write_key = os.environ.get("ARGUS_S8_BROKER_WRITE_KEY")
    if os.environ.get("ARGUS_S8_POSTGRES_DSN"):
        from .s8_persistence import build_postgres_minio_store_from_env

        return S8WriterApp(
            build_postgres_minio_store_from_env(dict(os.environ)),
            auth=runtime_auth_from_env(),
            broker_write_key=broker_write_key.encode("utf-8") if broker_write_key else None,
            health_token=health_token_from_env(),
        )
    data_dir = os.environ.get("ARGUS_S8_DATA_DIR", "/var/lib/argus/s8")
    return S8WriterApp(
        FileSystemArtifactStore(data_dir),
        data_dir=data_dir,
        auth=runtime_auth_from_env(),
        broker_write_key=broker_write_key.encode("utf-8") if broker_write_key else None,
        health_token=health_token_from_env(),
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


def _required_list(body: dict[str, Any], field: str) -> list[Any]:
    value = body.get(field)
    if not isinstance(value, list):
        raise ValueError(f"{field} is required")
    return list(value)


def _optional_str(body: dict[str, Any], field: str) -> str | None:
    value = body.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _normalize_lineage(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    normalized["input_refs"] = tuple(normalized.get("input_refs") or ())
    normalized["seeds"] = tuple(normalized.get("seeds") or ())
    return normalized


def _artifact_query_filter_from_query(query: dict[str, list[str]]) -> ArtifactQueryFilter:
    return ArtifactQueryFilter(
        artifact_ref=_query_str(query, "artifact_ref"),
        content_hash=_query_str(query, "content_hash"),
        kind=_query_str(query, "kind"),
        actor_id=_query_str(query, "actor_id"),
        job_id=_query_str(query, "job_id"),
        producer_subsystem=_query_str(query, "producer_subsystem"),
        producer_version=_query_str(query, "producer_version"),
        claim_tier=_query_str(query, "claim_tier"),
        validation_report_ref=_query_str(query, "validation_report_ref"),
        contamination_index_version=_query_str(query, "contamination_index_version"),
        created_after=_query_str(query, "created_after"),
        created_before=_query_str(query, "created_before"),
    )


def _query_str(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name) or ()
    if not values:
        return None
    value = values[0]
    return value if value else None


def _query_int(query: dict[str, list[str]], name: str) -> int | None:
    value = _query_str(query, name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _dataset_splits_from_body(values: list[Any]) -> tuple[DatasetSplit, ...]:
    splits: list[DatasetSplit] = []
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("dataset splits must be objects")
        row_count = value.get("row_count")
        if isinstance(row_count, bool) or not isinstance(row_count, int):
            raise ValueError("dataset split row_count must be an integer")
        content_hash = _optional_str(value, "content_hash")
        splits.append(
            DatasetSplit(
                split_id=_required_str(value, "split_id"),
                role=_required_str(value, "role"),
                content_hash=content_hash,
                row_count=row_count,
                schema_ref=_required_str(value, "schema_ref"),
                access_scope=_required_str(value, "access_scope"),
                label_seal_ref=_optional_str(value, "label_seal_ref"),
            )
        )
    return tuple(splits)


def _dataset_wire_payload(value: Any) -> dict[str, Any]:
    payload = _structured_payload(value)
    if not isinstance(payload, dict):
        raise TypeError(f"expected dataset payload object, got {type(payload).__name__}")
    provenance = payload.get("provenance_ref")
    if isinstance(provenance, dict):
        normalized_provenance = dict(provenance)
        artifact_id = normalized_provenance.pop("artifact_id", None)
        if artifact_id is not None and "artifact_ref" not in normalized_provenance:
            normalized_provenance["artifact_ref"] = artifact_id
        payload["provenance_ref"] = normalized_provenance
    return payload


def _dataset_split_resolution_wire_payload(value: Any) -> dict[str, Any]:
    payload = _structured_payload(value)
    if not isinstance(payload, dict):
        raise TypeError(f"expected dataset split resolution object, got {type(payload).__name__}")
    return payload


def _dataset_split_resolve_route(suffix: str) -> tuple[str, str] | None:
    parts = [part for part in suffix.split("/") if part]
    if len(parts) == 4 and parts[1] == "splits" and parts[3] == "resolve":
        return parts[0], parts[2]
    return None


def _is_scope_denied_exception(exc: Exception) -> bool:
    return getattr(exc, "category", None) == "SCOPE_DENIED" or "SCOPE_DENIED" in str(exc)


def _scope_denied_payload(exc: Exception) -> dict[str, str]:
    message = str(exc).splitlines()[0]
    return {"error": "ScopeDenied", "category": "SCOPE_DENIED", "message": message}


def _structured_payload(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    return value


def _audit_slice_wire_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    payload = asdict(value)
    return {
        "leaves": [
            {
                "sequence": leaf["sequence"],
                "artifact_id": leaf["artifact_ref"],
                "record_hash": leaf["record_hash"],
                "previous_root": leaf["previous_root"],
                "root": leaf["root"],
            }
            for leaf in payload["leaves"]
        ],
        "merkle_checkpoints": [
            {
                "sequence": payload["checkpoint"]["sequence"],
                "root": payload["checkpoint"]["root"],
                "signature": payload["checkpoint"]["signature"],
                "signer_key_id": payload["checkpoint"]["signer_key_id"],
            }
        ],
        "inclusion_proofs": [
            {
                "artifact_id": proof["artifact_ref"],
                "sequence": proof["sequence"],
                "record_hash": proof["record_hash"],
                "anchor_previous_root": proof["anchor_previous_root"],
                "steps": [
                    {
                        "sequence": step["sequence"],
                        "artifact_id": step["artifact_ref"],
                        "record_hash": step["record_hash"],
                        "previous_root": step["previous_root"],
                        "root": step["root"],
                    }
                    for step in proof["steps"]
                ],
            }
            for proof in payload["inclusion_proofs"]
        ],
    }


if __name__ == "__main__":
    main()
