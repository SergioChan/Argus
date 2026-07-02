"""S8 writer service for the argus-m0 stack."""

from __future__ import annotations

from dataclasses import asdict
import os
from pathlib import Path
from typing import Any

from argus_core import FileSystemArtifactStore, Lineage, Producer

from .http_json import JsonHttpApp, JsonRequest, serve_json_app


class S8WriterApp:
    def __init__(self, store: FileSystemArtifactStore, *, data_dir: str | os.PathLike[str] | None = None) -> None:
        self.store = store
        self._data_dir = Path(data_dir) if data_dir is not None else None
        self.http = JsonHttpApp()
        self._register_routes()

    def create_artifact(self, body: dict[str, Any]) -> dict[str, Any]:
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

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(_: JsonRequest) -> tuple[int, Any]:
            self._refresh_store()
            return 200, {"service": "s8-writer", "status": "ok", "record_count": self.store.record_count}

        @self.http.route("POST", "/v1/artifacts")
        def create(request: JsonRequest) -> tuple[int, Any]:
            return 403, {
                "error": "DirectWriteDenied",
                "message": "artifact writes must use the S10 store broker",
            }

        @self.http.prefix("GET", "/v1/artifacts/")
        def get_record(request: JsonRequest) -> tuple[int, Any]:
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
            artifact_ref = request.path.removeprefix("/v1/lineage/")
            direction = request.query.get("direction", ["both"])[0]
            try:
                return 200, self.get_lineage(artifact_ref, direction=direction)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}


def build_app_from_env() -> S8WriterApp:
    data_dir = os.environ.get("ARGUS_S8_DATA_DIR", "/var/lib/argus/s8")
    return S8WriterApp(FileSystemArtifactStore(data_dir), data_dir=data_dir)


def main() -> None:
    host = os.environ.get("ARGUS_S8_HOST", "0.0.0.0")
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
