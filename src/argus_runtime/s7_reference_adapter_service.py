"""Deployed S7 broker for the fixed M1 GW-spectrum reference adapter."""

from __future__ import annotations

from dataclasses import asdict
import os
from typing import Any, Mapping

from argus_core import (
    AdapterBroker,
    EvalRequest,
    GWSpectrumAdapter,
    Lineage,
    Producer,
    Quantity,
    S7Error,
    c6_eval_result_payload,
    hash_json,
)

from .http_json import JsonHttpApp, JsonRequest, serve_json_app
from .m1_reference_service_auth import M1RequesterUnauthorized, require_m1_s1_requester
from .m1_runtime_artifacts import RuntimeIdentitySession, S10S8ArtifactStore, runtime_identity_session


S7_REFERENCE_ADAPTER_NAME = "s7-reference-adapter"
S7_REFERENCE_ADAPTER_ROUTE = "/v1/reference-adapter/evaluate"
S7_REFERENCE_ADAPTER_DEFAULT_CALLER_ID = "m1-reference-s7"
S7_REFERENCE_ADAPTER_DEFAULT_JOB_ID = "m1-reference-job"
S7_REFERENCE_ADAPTER_ID = "gw_spectrum"
S7_REFERENCE_ADAPTER_DESCRIPTOR_SCHEMA = "argus.s7.adapter-descriptor.v1"


class S7ReferenceAdapterApp:
    """Owns S7 evaluation provenance for the one deployed M1 adapter."""

    def __init__(
        self,
        *,
        s10_url: str,
        s8_url: str,
        bootstrap_token: str | None = None,
        access_token: str | None = None,
        caller_id: str = S7_REFERENCE_ADAPTER_DEFAULT_CALLER_ID,
        expected_job_id: str = S7_REFERENCE_ADAPTER_DEFAULT_JOB_ID,
    ) -> None:
        if bool(bootstrap_token) == bool(access_token):
            raise ValueError("S7 reference adapter requires exactly one runtime credential")
        self._s10_url = s10_url
        self._s8_url = s8_url
        self._bootstrap_token = bootstrap_token
        self._access_token = access_token
        self._caller_id = caller_id
        self._expected_job_id = expected_job_id
        self._session: RuntimeIdentitySession | None = None
        self._store: S10S8ArtifactStore | None = None
        self._broker: AdapterBroker | None = None
        self.http = JsonHttpApp()
        self._register_routes()

    def evaluate(self, body: Mapping[str, Any]) -> dict[str, Any]:
        payload = _mapping(body, "reference adapter request")
        if payload.get("job_id") != self._expected_job_id:
            raise PermissionError("job_id_mismatch")
        request = _eval_request_from_body(payload)
        if request.adapter_id != S7_REFERENCE_ADAPTER_ID:
            raise ValueError("adapter_id_mismatch")
        return c6_eval_result_payload(self._adapter_broker().evaluate(request))

    def _artifact_store(self) -> S10S8ArtifactStore:
        if self._store is None:
            self._session = runtime_identity_session(
                s10_url=self._s10_url,
                caller_id=self._caller_id,
                expected_job_id=self._expected_job_id,
                bootstrap_token=self._bootstrap_token,
                access_token=self._access_token,
            )
            self._store = S10S8ArtifactStore(session=self._session, s8_url=self._s8_url)
        return self._store

    def _adapter_broker(self) -> AdapterBroker:
        if self._broker is None:
            adapter = GWSpectrumAdapter().as_simple_adapter()
            self._ensure_adapter_descriptor(adapter.descriptor)
            broker = AdapterBroker(artifact_store=self._artifact_store())
            broker.register(adapter)
            self._broker = broker
        return self._broker

    def _ensure_adapter_descriptor(self, descriptor: Any) -> None:
        descriptor_payload = asdict(descriptor)
        payload = {
            "schema": S7_REFERENCE_ADAPTER_DESCRIPTOR_SCHEMA,
            "service": S7_REFERENCE_ADAPTER_NAME,
            "descriptor": descriptor_payload,
        }
        record = self._artifact_store().create_artifact(
            kind="adapter_descriptor",
            artifact_ref=descriptor.provenance_ref,
            payload=payload,
            producer=Producer(
                subsystem="S7",
                version=descriptor.version,
                actor_id=self._caller_id,
            ),
            lineage=Lineage(
                input_refs=(),
                code_ref=f"adapter:{descriptor.adapter_id}@{descriptor.version}",
                environment_digest=hash_json(
                    {
                        "service": S7_REFERENCE_ADAPTER_NAME,
                        "descriptor": descriptor_payload,
                    }
                ),
            ),
        )
        if record.artifact_ref != descriptor.provenance_ref:
            raise RuntimeError("S7 reference adapter descriptor record ref mismatch")

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(_request: JsonRequest) -> tuple[int, Any]:
            return 200, {
                "service": S7_REFERENCE_ADAPTER_NAME,
                "status": "ok",
                "expected_job_id": self._expected_job_id,
                "adapter_id": S7_REFERENCE_ADAPTER_ID,
            }

        @self.http.route("POST", S7_REFERENCE_ADAPTER_ROUTE)
        def evaluate(request: JsonRequest) -> tuple[int, Any]:
            if not isinstance(request.body, Mapping):
                return 400, {"error": "invalid_json_body"}
            try:
                require_m1_s1_requester(
                    request,
                    s10_url=self._s10_url,
                    expected_job_id=self._expected_job_id,
                    required_adapters=(S7_REFERENCE_ADAPTER_ID,),
                    required_broker_audiences=(S7_REFERENCE_ADAPTER_ID,),
                )
                return 200, self.evaluate(request.body)
            except M1RequesterUnauthorized as exc:
                return 403, {"error": "requester_unauthorized", "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": str(exc)}
            except S7Error as exc:
                return 422, {"error": exc.category, "message": exc.message, "diagnostics": exc.diagnostics}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}


def build_app_from_env() -> S7ReferenceAdapterApp:
    return S7ReferenceAdapterApp(
        s10_url=_required_env("ARGUS_S7_REFERENCE_ADAPTER_S10_URL"),
        s8_url=_required_env("ARGUS_S7_REFERENCE_ADAPTER_S8_URL"),
        access_token=_required_env("ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN"),
        caller_id=os.environ.get("ARGUS_S7_REFERENCE_ADAPTER_CALLER_ID", S7_REFERENCE_ADAPTER_DEFAULT_CALLER_ID),
        expected_job_id=os.environ.get("ARGUS_S7_REFERENCE_ADAPTER_JOB_ID", S7_REFERENCE_ADAPTER_DEFAULT_JOB_ID),
    )


def main(argv: list[str] | None = None) -> int:
    del argv
    host = os.environ.get("ARGUS_S7_REFERENCE_ADAPTER_HOST", "127.0.0.1")
    port = int(os.environ.get("ARGUS_S7_REFERENCE_ADAPTER_PORT", "8080"))
    serve_json_app(build_app_from_env().http, host=host, port=port)
    return 0


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _eval_request_from_body(body: Mapping[str, Any]) -> EvalRequest:
    raw = _mapping(body.get("eval_request"), "reference adapter eval_request")
    adapter_id = _required_str(raw, "adapter_id", "reference adapter eval_request")
    inputs_raw = _mapping(raw.get("inputs"), "reference adapter inputs")
    inputs = {str(name): _quantity(value, field=str(name)) for name, value in inputs_raw.items()}
    if not inputs:
        raise ValueError("reference adapter inputs must not be empty")
    return EvalRequest(
        adapter_id=adapter_id,
        inputs=inputs,
        c6_version=_optional_str(raw.get("c6_version"), "c6_version") or "2.3.0",
        seed=_optional_int(raw.get("seed"), "seed"),
        job_seed=_optional_int(raw.get("job_seed"), "job_seed"),
        dag_node_id=_optional_str(raw.get("dag_node_id"), "dag_node_id"),
        call_index=_optional_int(raw.get("call_index"), "call_index"),
        budget_token_ref=_optional_str(raw.get("budget_token_ref"), "budget_token_ref"),
    )


def _quantity(value: Any, *, field: str) -> Quantity:
    payload = _mapping(value, f"reference adapter input {field}")
    try:
        numeric = float(payload["value"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"reference adapter input {field} requires numeric value") from exc
    units = _required_str(payload, "units", f"reference adapter input {field}")
    uncertainty = payload.get("uncertainty")
    if uncertainty is not None and not isinstance(uncertainty, Mapping):
        raise ValueError(f"reference adapter input {field} uncertainty must be an object")
    return Quantity(value=numeric, units=units, uncertainty=dict(uncertainty) if isinstance(uncertainty, Mapping) else None)


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return dict(value)


def _required_str(value: Mapping[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{context} requires non-empty {field}")
    return item


def _optional_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"reference adapter {field} must be a non-empty string")
    return value


def _optional_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"reference adapter {field} must be an integer")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
