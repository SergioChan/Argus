"""Deployed S2 builder for the M1 reference tabular pipeline."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from math import isfinite
import os
from typing import Any, Mapping

from argus_core import (
    BuildOrchestrationRequest,
    BuildOrchestrator,
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    GWSpectrumAdapter,
    InMemoryRegistry,
    Lineage,
    Producer,
    ProvenanceEmitter,
    SpecCompiler,
)
from argus_core.s1_reference import S1_REFERENCE_PHYSICS_PROFILE_REF

from .http_json import JsonHttpApp, JsonRequest, serve_json_app
from .m1_reference_service_auth import M1RequesterUnauthorized, require_m1_s1_requester
from .m1_runtime_artifacts import RuntimeIdentitySession, S10S8ArtifactStore, runtime_identity_session


S2_REFERENCE_BUILDER_NAME = "s2-reference-builder"
S2_REFERENCE_BUILDER_ROUTE = "/v1/reference-builder/build"
S2_REFERENCE_BUILDER_DEFAULT_CALLER_ID = "m1-reference-s2"
S2_REFERENCE_BUILDER_DEFAULT_JOB_ID = "m1-reference-job"
S2_REFERENCE_DATASET_ID = "dataset:m1-reference-ewpt"
S2_REFERENCE_ADAPTER_ID = "gw_spectrum"
S2_REFERENCE_MIN_ROWS = 12
S2_REFERENCE_OMEGA_SCALE = 1e-11


class _RootBoundS2ArtifactStore:
    """Seals S2 trial artifacts to the one S10-authorized parent job."""

    def __init__(self, store: S10S8ArtifactStore, *, job_id: str) -> None:
        self._store = store
        self._job_id = job_id

    def create_artifact(
        self,
        *,
        producer: Producer,
        lineage: Lineage,
        **kwargs: Any,
    ) -> Any:
        self._assert_job(producer.job_id, "producer")
        self._assert_job(lineage.job_id, "lineage")
        return self._store.create_artifact(
            producer=replace(producer, job_id=self._job_id),
            lineage=replace(lineage, job_id=self._job_id),
            **kwargs,
        )

    def get_record(self, artifact_ref: str) -> Any:
        return self._store.get_record(artifact_ref)

    def get_artifact(self, artifact_ref: str) -> bytes:
        return self._store.get_artifact(artifact_ref)

    def _assert_job(self, value: str | None, field: str) -> None:
        if value is None or value == self._job_id or value.startswith(f"{self._job_id}:"):
            return
        raise PermissionError(f"S2 {field} job_id is outside the authorized M1 root job")


class S2ReferenceBuilderApp:
    """Builds a deterministic, S2-owned frozen pipeline from S1-provided reference data."""

    def __init__(
        self,
        *,
        s10_url: str,
        s8_url: str,
        bootstrap_token: str | None = None,
        access_token: str | None = None,
        caller_id: str = S2_REFERENCE_BUILDER_DEFAULT_CALLER_ID,
        expected_job_id: str = S2_REFERENCE_BUILDER_DEFAULT_JOB_ID,
        require_s1_requester: bool = False,
    ) -> None:
        if not caller_id:
            raise ValueError("S2 reference builder caller_id is required")
        if not expected_job_id:
            raise ValueError("S2 reference builder expected_job_id is required")
        if bool(bootstrap_token) == bool(access_token):
            raise ValueError("S2 reference builder requires exactly one runtime credential")
        self._s10_url = s10_url.rstrip("/")
        self._s8_url = s8_url.rstrip("/")
        self._bootstrap_token = bootstrap_token
        self._access_token = access_token
        self._caller_id = caller_id
        self._expected_job_id = expected_job_id
        self._require_s1_requester = require_s1_requester
        self._session: RuntimeIdentitySession | None = None
        self._store: S10S8ArtifactStore | None = None
        self.http = JsonHttpApp()
        self._register_routes()

    def build(self, request: Mapping[str, Any]) -> dict[str, Any]:
        payload = _mapping(request, "S2 reference builder request")
        if payload.get("job_id") != self._expected_job_id:
            raise PermissionError("job_id_mismatch")
        dataset_ref = _required_str(payload, "dataset_ref", "S2 reference builder request")
        profile_ref = _optional_str(payload.get("profile_ref"), "profile_ref") or S1_REFERENCE_PHYSICS_PROFILE_REF
        store = self._artifact_store()
        self._validate_dataset(store, dataset_ref)
        result = self._orchestrator(store=store, dataset_ref=dataset_ref, profile_ref=profile_ref).build(
            _reference_build_request(
                job_id=self._expected_job_id,
                dataset_ref=dataset_ref,
                profile_ref=profile_ref,
            )
        )
        return {
            "job_id": result.job_id,
            "dataset_ref": dataset_ref,
            "model_ref": result.model_ref,
            "frozen_pipeline_ref": result.frozen_pipeline_ref,
            "artifact_refs": list(result.artifact_refs),
            "adapter_provenance_refs": list(result.adapter_provenance_refs),
            "claim_tier": result.claim_tier,
            "diagnostics": result.diagnostics,
            "cost_actual": result.cost_actual,
            "dataset_split_ref": result.dataset_split_ref,
            "feature_set_ref": result.feature_set_ref,
            "hpo_selection_ref": result.hpo_selection_ref,
            "training_log_ref": result.training_log_ref,
            "uq_calibration_ref": result.uq_calibration_ref,
            "advisory_self_check_ref": result.advisory_self_check_ref,
            "sandbox_evidence_ref": result.sandbox_evidence_ref,
        }

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

    def _orchestrator(
        self,
        *,
        store: S10S8ArtifactStore,
        dataset_ref: str,
        profile_ref: str,
    ) -> BuildOrchestrator:
        bound_store = _RootBoundS2ArtifactStore(store, job_id=self._expected_job_id)
        registry = InMemoryRegistry()
        registry.publish(
            CapabilityDescriptor(
                entity_id=S2_REFERENCE_ADAPTER_ID,
                revision=1,
                kind="adapter",
                owner_subsystem="S7",
                contract_versions={"C5": "1.0.0", "C6": "2.3.0"},
                trust_class="local",
                capability_scopes=("c6.evaluate",),
                provenance_ref=GWSpectrumAdapter().as_simple_adapter().descriptor.provenance_ref,
                subtopics=("ewpt",),
            )
        )
        registry.publish(
            CapabilityDescriptor(
                entity_id=S2_REFERENCE_DATASET_ID,
                revision=1,
                kind="dataset",
                owner_subsystem="S1",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="local",
                capability_scopes=("c4.read",),
                provenance_ref=dataset_ref,
                subtopics=("ewpt",),
            )
        )
        profiles = C3VerifierProfileCatalog(
            (
                C3VerifierProfile(
                    profile_ref=profile_ref,
                    profile_id="ewpt-reference",
                    version="1.0.0",
                    checks=("injection", "null", "physical-consistency", "calibration"),
                    provenance_ref=profile_ref,
                ),
            )
        )
        emitter = ProvenanceEmitter(
            artifact_store=bound_store,
            producer=Producer(
                subsystem="S2",
                version="0.0.0",
                actor_id=self._caller_id,
                job_id=self._expected_job_id,
            ),
        )
        return BuildOrchestrator(
            artifact_store=bound_store,
            spec_compiler=SpecCompiler(
                verifier_profiles=profiles,
                capability_registry=registry,
                artifact_store=bound_store,
            ),
            provenance_emitter=emitter,
            hpo_scheduler_backend="threadpool",
        )

    def _validate_dataset(self, store: S10S8ArtifactStore, dataset_ref: str) -> None:
        record = store.get_record(dataset_ref)
        if record.kind != "dataset":
            raise ValueError("S2 reference builder requires a C4 dataset artifact")
        if record.producer.subsystem != "S1":
            raise PermissionError("dataset_producer_must_be_s1")
        if record.producer.job_id != self._expected_job_id:
            raise PermissionError("dataset_job_id_mismatch")
        payload = _artifact_payload(store, dataset_ref)
        feature_scale = _positive_finite(payload.get("feature_scale"), "reference dataset feature_scale")
        target_scale = _positive_finite(payload.get("target_scale"), "reference dataset target_scale")
        if feature_scale != S2_REFERENCE_OMEGA_SCALE or target_scale != S2_REFERENCE_OMEGA_SCALE:
            raise ValueError("reference dataset must use the fixed M1 omega scale")
        rows = payload.get("rows")
        if not isinstance(rows, list) or len(rows) < S2_REFERENCE_MIN_ROWS:
            raise ValueError(f"reference dataset requires at least {S2_REFERENCE_MIN_ROWS} rows")
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise ValueError(f"reference dataset row {index} must be an object")
            if not isinstance(row.get("row_id"), str) or not row["row_id"]:
                raise ValueError(f"reference dataset row {index} requires row_id")
            for field in ("adapter_omega", "omega", "adapter_omega_scaled", "omega_scaled"):
                value = row.get(field)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(float(value)):
                    raise ValueError(f"reference dataset row {index} requires finite {field}")
                if float(value) <= 0.0:
                    raise ValueError(f"reference dataset row {index} requires positive {field}")
            _assert_scaled_value(
                value=float(row["adapter_omega_scaled"]),
                raw=float(row["adapter_omega"]),
                scale=feature_scale,
                field=f"reference dataset row {index} adapter_omega_scaled",
            )
            _assert_scaled_value(
                value=float(row["omega_scaled"]),
                raw=float(row["omega"]),
                scale=target_scale,
                field=f"reference dataset row {index} omega_scaled",
            )

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(_request: JsonRequest) -> tuple[int, Any]:
            return 200, {
                "service": S2_REFERENCE_BUILDER_NAME,
                "status": "ok",
                "expected_job_id": self._expected_job_id,
            }

        @self.http.route("POST", S2_REFERENCE_BUILDER_ROUTE)
        def build(request: JsonRequest) -> tuple[int, Any]:
            if not isinstance(request.body, Mapping):
                return 400, {"error": "invalid_json_body"}
            try:
                self._authorize_s1_requester(request)
                return 200, self.build(request.body)
            except M1RequesterUnauthorized as exc:
                return 403, {"error": "requester_unauthorized", "message": str(exc)}
            except PermissionError as exc:
                if str(exc) in {"job_id_mismatch", "dataset_producer_must_be_s1", "dataset_job_id_mismatch"}:
                    return 403, {"error": str(exc)}
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

    def _authorize_s1_requester(self, request: JsonRequest) -> None:
        if not self._require_s1_requester:
            return
        require_m1_s1_requester(
            request,
            s10_url=self._s10_url,
            expected_job_id=self._expected_job_id,
            required_adapters=(S2_REFERENCE_ADAPTER_ID,),
            required_broker_audiences=("store",),
        )


def build_app_from_env() -> S2ReferenceBuilderApp:
    return S2ReferenceBuilderApp(
        s10_url=_required_env("ARGUS_S2_REFERENCE_BUILDER_S10_URL"),
        s8_url=_required_env("ARGUS_S2_REFERENCE_BUILDER_S8_URL"),
        access_token=_required_env("ARGUS_S2_REFERENCE_BUILDER_ACCESS_TOKEN"),
        caller_id=os.environ.get("ARGUS_S2_REFERENCE_BUILDER_CALLER_ID", S2_REFERENCE_BUILDER_DEFAULT_CALLER_ID),
        expected_job_id=os.environ.get("ARGUS_S2_REFERENCE_BUILDER_JOB_ID", S2_REFERENCE_BUILDER_DEFAULT_JOB_ID),
        require_s1_requester=_env_flag(os.environ.get("ARGUS_S2_REFERENCE_BUILDER_REQUIRE_S1_REQUESTER")),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("ARGUS_S2_REFERENCE_BUILDER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ARGUS_S2_REFERENCE_BUILDER_PORT", "8080")))
    args = parser.parse_args(argv)
    serve_json_app(build_app_from_env().http, host=args.host, port=args.port)
    return 0


def _reference_build_request(
    *,
    job_id: str,
    dataset_ref: str,
    profile_ref: str,
) -> BuildOrchestrationRequest:
    return BuildOrchestrationRequest(
        c2_envelope={
            "contract_version": "1.0.0",
            "job_id": job_id,
            "root_request_id": "m1-reference-root",
            "trace_id": f"trace:{job_id}:s2-reference-builder",
            "subtopic": "ewpt",
            "problem_spec": {
                "task_type": "regression",
                "observable": "omega_scaled",
                "target_units": "dimensionless",
                "inputs_schema": [{"name": "adapter_omega_scaled", "units": "dimensionless"}],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": profile_ref,
            "contamination_index_version": "m1-reference",
            "budget": {
                "max_usd": 1.0,
                "max_wallclock_seconds": 30,
                "max_gpu_seconds": 0.0,
                "max_model_tokens": 0,
            },
            "constraints": {"max_features": 1},
            "capability_scopes": {
                "allowed_adapters": [S2_REFERENCE_ADAPTER_ID],
                "allowed_datasets": [S2_REFERENCE_DATASET_ID],
                "allowed_egress": [],
            },
            "input_artifact_refs": [dataset_ref],
        },
        code_ref="argus-runtime:s2-reference-builder",
        environment_digest="oci:argus-s2-reference-builder:v1",
        seed="m1-reference-s2-builder",
        hpo_parameter_grid={"learning_rate": (0.05, 0.1)},
        hpo_max_epochs=20,
        final_max_epochs=80,
        train_ratio=0.6,
        validation_ratio=0.2,
        test_ratio=0.2,
        nominal_coverage=0.8,
        coverage_tolerance=0.5,
        max_self_replay_fraction=1.0,
        wallclock_seconds_per_epoch=0.1,
        cost_usd_per_epoch=0.005,
    )


def _artifact_payload(store: S10S8ArtifactStore, artifact_ref: str) -> dict[str, Any]:
    payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("reference dataset payload must be an object")
    return payload


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
        raise ValueError(f"S2 reference builder {field} must be a non-empty string")
    return value


def _positive_finite(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(float(value)):
        raise ValueError(f"{context} must be finite")
    normalized = float(value)
    if normalized <= 0.0:
        raise ValueError(f"{context} must be positive")
    return normalized


def _assert_scaled_value(*, value: float, raw: float, scale: float, field: str) -> None:
    expected = raw / scale
    tolerance = max(abs(expected) * 1e-12, 1e-15)
    if abs(value - expected) > tolerance:
        raise ValueError(f"{field} does not match its declared scale")


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _env_flag(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    raise SystemExit(main())
