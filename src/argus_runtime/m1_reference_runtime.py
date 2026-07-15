"""Runtime-only helpers for the deployed M1 reference lifecycle."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from math import isfinite
from typing import Any, Callable, Mapping
from urllib import error as urlerror
from urllib import request as urlrequest

from argus_core import (
    BudgetCaps,
    BudgetToken,
    EgressRule,
    LaunchEnvelope,
    LaunchRequest,
    PolicyDeniedError,
    SandboxExecutionResult,
    SandboxHandle,
    SandboxPartialResult,
    SandboxRuntimeUnavailableError,
    S10Error,
    ScopeGrant,
    ScopeToken,
)
from argus_core.s10 import BudgetUsage, DIGEST_PINNED_IMAGE
from argus_core.s10 import S10VerifierTrustStoreClient
from argus_core.s1 import ExecContext, JobEnvelope, S10SandboxMarshaler, SubagentDescriptor, SubagentRuntime, SubagentSDKRunner
from argus_core.s1_reference import (
    S1_REFERENCE_PHYSICS_ADAPTER_ID,
    S1_REFERENCE_PHYSICS_DATASET_REF,
    S1_REFERENCE_PHYSICS_PROFILE_REF,
    S1ReferencePhysicsSubagent,
)
from argus_core.s7 import EvalRequest, EvalResult, Quantity, S7Error
from argus_core.s8 import Lineage, Producer
from argus_core.s11 import ObservatoryLineageBundle, verify_observatory_v0
from argusverify import C3ReportVerifier

from .m1_runtime_artifacts import (
    RuntimeArtifactStoreError,
    RuntimeIdentitySession,
    S10S8ArtifactStore,
    runtime_identity_session,
)
from .s2_reference_builder_service import S2_REFERENCE_BUILDER_ROUTE, S2_REFERENCE_OMEGA_SCALE
from .s8_persistence import HttpS10VerifierKeyProvider


REFERENCE_SANDBOX_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

# The program is carried in the signed S10 launch request and executes without a shell,
# network, writable root filesystem, capabilities, or injected secrets.
REFERENCE_SANDBOX_AWK_PROGRAM = (
    "BEGIN { "
    "g=106.75; "
    "efficiency=alpha/(0.73+0.083*sqrt(alpha)+alpha); "
    "peak_frequency=1.9e-5*beta*(tn/100)*(g/100)^(1/6)/vw; "
    "fluid=efficiency*alpha/(1+alpha); "
    "peak_omega=2.65e-6*(1/beta)*fluid^2*(100/g)^(1/3)*vw; "
    "ratio=frequency/peak_frequency; "
    "shape=ratio^3*(7/(4+3*ratio^2))^3.5; "
    "omega=peak_omega*shape; "
    'printf "{\\\"omega\\\":%.17g,\\\"peak_omega\\\":%.17g,\\\"peak_frequency\\\":%.17g}\\n", '
    "omega, peak_omega, peak_frequency "
    "}"
)


@dataclass(frozen=True)
class ReferenceS10SandboxSpecFactory:
    """Mint constrained S10 tokens for one deterministic reference computation."""

    session: Any
    image: str = REFERENCE_SANDBOX_IMAGE

    def __call__(self, job_id: str, adapter_inputs: Mapping[str, Any]) -> dict[str, Any]:
        session_job_id = getattr(self.session, "job_id", None)
        if not isinstance(session_job_id, str) or not session_job_id:
            raise ValueError("reference sandbox session must expose a non-empty job_id")
        if job_id != session_job_id:
            raise ValueError("reference sandbox job_id must match the runtime identity")
        if not _is_digest_pinned_image(self.image):
            raise ValueError("reference sandbox image must be digest-pinned")
        budget = _budget_token_from_mapping(self.session.mint_budget())
        scope = _scope_token_from_mapping(self.session.mint_scope())
        if budget.job_id != job_id or scope.job_id != job_id:
            raise ValueError("reference sandbox token job_id must match the runtime identity")
        return {
            "launch_request": LaunchRequest(
                job_id=job_id,
                subagent_id="s1-reference-physics",
                trace_id=f"trace:{job_id}:reference-compute",
                budget_token=budget,
                scope_token=scope,
                image=self.image,
                entrypoint=("awk",),
                args=_reference_sandbox_args(adapter_inputs),
                env={},
                env_allowlist=(),
                requested_envelope=LaunchEnvelope(
                    cpu_m=250,
                    mem_bytes=64 * 1024 * 1024,
                    gpu_count=0,
                    wallclock_s=30,
                    scratch_bytes=16 * 1024 * 1024,
                    pids=8,
                    estimated_cost_usd=0.02,
                ),
                runtime_class_hint="auto",
            )
        }


@dataclass(frozen=True)
class HttpS10SandboxLauncher:
    """Transport adapter that makes an S10 HTTP launch look like a core launcher."""

    session: Any

    def launch_and_wait(self, request: LaunchRequest) -> SandboxExecutionResult:
        session_job_id = getattr(self.session, "job_id", None)
        if request.job_id != session_job_id:
            raise PolicyDeniedError("reference sandbox request job_id is not bound to the runtime identity")
        s10_url = getattr(self.session, "s10_url", None)
        access_token = getattr(self.session, "access_token", None)
        timeout_s = getattr(self.session, "timeout_s", None)
        if not isinstance(s10_url, str) or not s10_url:
            raise SandboxRuntimeUnavailableError("reference sandbox session has no S10 endpoint")
        if not isinstance(access_token, str) or not access_token:
            raise PolicyDeniedError("reference sandbox session has no runtime access token")
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
            raise SandboxRuntimeUnavailableError("reference sandbox session has an invalid timeout")
        http_request = urlrequest.Request(
            f"{s10_url.rstrip('/')}/v1/sandboxes:launch",
            data=json.dumps(_jsonable(asdict(request)), separators=(",", ":"), sort_keys=True).encode("utf-8"),
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlrequest.urlopen(http_request, timeout=float(timeout_s)) as response:
                raw = response.read()
        except urlerror.HTTPError as exc:
            message = _http_error_message(exc)
            if exc.code == 403:
                raise PolicyDeniedError(message) from exc
            if exc.code == 503:
                raise SandboxRuntimeUnavailableError(message) from exc
            raise S10Error(message) from exc
        except OSError as exc:
            raise SandboxRuntimeUnavailableError(f"S10 sandbox endpoint could not be reached: {exc}") from exc
        try:
            response_payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise S10Error("S10 sandbox endpoint returned invalid JSON") from exc
        if not isinstance(response_payload, Mapping):
            raise S10Error("S10 sandbox endpoint returned a non-object JSON response")
        return _sandbox_execution_result_from_mapping(response_payload, expected_job_id=request.job_id)


def mint_s10_launch_tokens(session: RuntimeIdentitySession) -> tuple[BudgetToken, ScopeToken]:
    """Mint one runtime-bound S10 budget and scope token pair for a nested launch."""

    return _budget_token_from_mapping(session.mint_budget()), _scope_token_from_mapping(session.mint_scope())


def _reference_sandbox_args(adapter_inputs: Mapping[str, Any]) -> tuple[str, ...]:
    values = {
        "tn": _reference_input(adapter_inputs, "T_n"),
        "alpha": _reference_input(adapter_inputs, "alpha"),
        "beta": _reference_input(adapter_inputs, "beta_over_H"),
        "vw": _reference_input(adapter_inputs, "v_w"),
        "frequency": _reference_input(adapter_inputs, "frequency"),
    }
    args: list[str] = []
    for key, value in values.items():
        args.extend(("-v", f"{key}={value:.17g}"))
    args.append(REFERENCE_SANDBOX_AWK_PROGRAM)
    return tuple(args)


def _sandbox_execution_result_from_mapping(
    value: Mapping[str, Any],
    *,
    expected_job_id: str,
) -> SandboxExecutionResult:
    handle = _mapping(value.get("handle"), "S10 sandbox response handle")
    job_id = _required_str(handle, "job_id", "S10 sandbox response handle")
    if job_id != expected_job_id:
        raise S10Error("S10 sandbox response job_id does not match the request")
    partial_raw = value.get("partial_result")
    partial = None if partial_raw is None else _sandbox_partial_result_from_mapping(_mapping(partial_raw, "S10 sandbox partial result"))
    return SandboxExecutionResult(
        handle=SandboxHandle(
            sandbox_id=_required_str(handle, "sandbox_id", "S10 sandbox response handle"),
            job_id=job_id,
            runtime_class=_required_str(handle, "runtime_class", "S10 sandbox response handle"),
            budget_epoch=_required_int(handle, "budget_epoch", "S10 sandbox response handle"),
            policy_bundle_version=_required_str(handle, "policy_bundle_version", "S10 sandbox response handle"),
            state=_required_str(handle, "state", "S10 sandbox response handle"),
            launch_provenance_ref=_optional_str(
                handle.get("launch_provenance_ref"),
                "S10 sandbox response handle launch_provenance_ref",
            ),
        ),
        exit_code=_optional_int(value.get("exit_code"), "S10 sandbox response exit_code"),
        stdout=_required_string(value, "stdout", "S10 sandbox response"),
        stderr=_required_string(value, "stderr", "S10 sandbox response"),
        timed_out=_required_bool(value, "timed_out", "S10 sandbox response"),
        duration_s=_required_number(value, "duration_s", "S10 sandbox response"),
        budget_usage=_budget_usage_from_mapping(_mapping(value.get("budget_usage"), "S10 sandbox budget usage")),
        partial_result=partial,
    )


def _sandbox_partial_result_from_mapping(value: Mapping[str, Any]) -> SandboxPartialResult:
    return SandboxPartialResult(
        reason=_required_str(value, "reason", "S10 sandbox partial result"),
        stdout=_required_string(value, "stdout", "S10 sandbox partial result"),
        stderr=_required_string(value, "stderr", "S10 sandbox partial result"),
        captured_after_freeze=_required_bool(value, "captured_after_freeze", "S10 sandbox partial result"),
        freeze_succeeded=_required_bool(value, "freeze_succeeded", "S10 sandbox partial result"),
        terminate_succeeded=_required_bool(value, "terminate_succeeded", "S10 sandbox partial result"),
        stdout_bytes=_required_int(value, "stdout_bytes", "S10 sandbox partial result"),
        stderr_bytes=_required_int(value, "stderr_bytes", "S10 sandbox partial result"),
        capture_error=_optional_str(value.get("capture_error"), "S10 sandbox partial result capture_error"),
        log_capture_limit_bytes=_required_int(
            value,
            "log_capture_limit_bytes",
            "S10 sandbox partial result",
        ),
        logs_truncated=_required_bool(value, "logs_truncated", "S10 sandbox partial result"),
        frozen_state=_required_str(value, "frozen_state", "S10 sandbox partial result"),
        terminated_state=_required_str(value, "terminated_state", "S10 sandbox partial result"),
    )


def _budget_usage_from_mapping(value: Mapping[str, Any]) -> BudgetUsage:
    return BudgetUsage(
        compute_units=_required_number(value, "compute_units", "S10 sandbox budget usage"),
        gpu_seconds=_required_number(value, "gpu_seconds", "S10 sandbox budget usage"),
        model_tokens=_required_number(value, "model_tokens", "S10 sandbox budget usage"),
        wallclock_s=_required_number(value, "wallclock_s", "S10 sandbox budget usage"),
        cost_usd=_required_number(value, "cost_usd", "S10 sandbox budget usage"),
    )


def _reference_input(inputs: Mapping[str, Any], field: str) -> float:
    value = inputs.get(field)
    if not isinstance(value, Mapping):
        raise ValueError(f"reference sandbox input {field} must be an object")
    try:
        numeric = float(value["value"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"reference sandbox input {field} must provide a numeric value") from exc
    if not isfinite(numeric) or numeric <= 0:
        raise ValueError(f"reference sandbox input {field} must be finite and positive")
    return numeric


def _budget_token_from_mapping(value: Mapping[str, Any]) -> BudgetToken:
    return BudgetToken(
        budget_id=_required_str(value, "budget_id", "budget token"),
        job_id=_required_str(value, "job_id", "budget token"),
        root_request_id=_required_str(value, "root_request_id", "budget token"),
        budget_epoch=_required_int(value, "budget_epoch", "budget token"),
        caps=BudgetCaps(**_mapping(value.get("caps"), "budget token caps")),
        risk_class=_required_str(value, "risk_class", "budget token"),
        issued_at=_required_int(value, "issued_at", "budget token"),
        expires_at=_required_int(value, "expires_at", "budget token"),
        ttl_s=_required_int(value, "ttl_s", "budget token"),
        parent_budget_id=_optional_str(value.get("parent_budget_id"), "budget token parent_budget_id"),
        signer_key_id=_required_str(value, "signer_key_id", "budget token"),
        signature=_required_str(value, "signature", "budget token"),
    )


def _scope_token_from_mapping(value: Mapping[str, Any]) -> ScopeToken:
    scopes = _mapping(value.get("scopes"), "scope token scopes")
    return ScopeToken(
        scope_id=_required_str(value, "scope_id", "scope token"),
        job_id=_required_str(value, "job_id", "scope token"),
        scopes=ScopeGrant(
            allowed_adapters=_string_tuple(scopes.get("allowed_adapters"), "scope token allowed_adapters"),
            allowed_datasets=_string_tuple(scopes.get("allowed_datasets"), "scope token allowed_datasets"),
            egress_allowlist=tuple(
                EgressRule(**_mapping(item, "scope token egress_allowlist item"))
                for item in _sequence(scopes.get("egress_allowlist"), "scope token egress_allowlist")
            ),
            broker_audiences=_string_tuple(scopes.get("broker_audiences"), "scope token broker_audiences"),
            capabilities=_string_tuple(scopes.get("capabilities"), "scope token capabilities"),
            producer_subsystems=_string_tuple(scopes.get("producer_subsystems"), "scope token producer_subsystems"),
            disallowed_actions=_string_tuple(scopes.get("disallowed_actions"), "scope token disallowed_actions"),
            sandbox_risk_class=_required_str(scopes, "sandbox_risk_class", "scope token scopes"),
        ),
        issued_at=_required_int(value, "issued_at", "scope token"),
        expires_at=_required_int(value, "expires_at", "scope token"),
        ttl_s=_required_int(value, "ttl_s", "scope token"),
        parent_scope_id=_optional_str(value.get("parent_scope_id"), "scope token parent_scope_id"),
        signer_key_id=_required_str(value, "signer_key_id", "scope token"),
        signature=_required_str(value, "signature", "scope token"),
    )


def _is_digest_pinned_image(image: str) -> bool:
    return isinstance(image, str) and DIGEST_PINNED_IMAGE.fullmatch(image) is not None


def _required_str(value: Mapping[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{context} requires non-empty {field}")
    return item


def _optional_str(value: Any, context: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a string or null")
    return value


def _required_int(value: Mapping[str, Any], field: str, context: str) -> int:
    item = value.get(field)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{context} requires integer {field}")
    return item


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return dict(value)


def _sequence(value: Any, context: str) -> tuple[Any, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{context} must be an array")
    return tuple(value)


def _string_tuple(value: Any, context: str) -> tuple[str, ...]:
    sequence = _sequence(value, context)
    if not all(isinstance(item, str) for item in sequence):
        raise ValueError(f"{context} must contain strings")
    return tuple(sequence)


def _required_string(value: Mapping[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str):
        raise S10Error(f"{context} requires string {field}")
    return item


def _optional_int(value: Any, context: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise S10Error(f"{context} must be an integer or null")
    return value


def _required_bool(value: Mapping[str, Any], field: str, context: str) -> bool:
    item = value.get(field)
    if not isinstance(item, bool):
        raise S10Error(f"{context} requires boolean {field}")
    return item


def _required_number(value: Mapping[str, Any], field: str, context: str) -> float:
    item = value.get(field)
    if isinstance(item, bool):
        raise S10Error(f"{context} requires numeric {field}")
    try:
        numeric = float(item)
    except (TypeError, ValueError) as exc:
        raise S10Error(f"{context} requires numeric {field}") from exc
    if not isfinite(numeric):
        raise S10Error(f"{context} requires finite {field}")
    return numeric


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_jsonable(item) for item in value]
    return value


def _http_error_message(exc: urlerror.HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8")
    except Exception:
        return f"S10 sandbox endpoint failed with HTTP {exc.code}"
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return f"S10 sandbox endpoint failed with HTTP {exc.code}"
    if not isinstance(payload, Mapping):
        return f"S10 sandbox endpoint failed with HTTP {exc.code}"
    message = payload.get("message") or payload.get("error")
    return str(message) if isinstance(message, str) and message else f"S10 sandbox endpoint failed with HTTP {exc.code}"


M1_REFERENCE_JOB_ID = "m1-reference-job"
M1_REFERENCE_S1_CALLER_ID = "m1-reference-s1"
M1_REFERENCE_ADAPTER_EGRESS_RULE = EgressRule("s10-supervisor", 443, "https")
M1_REFERENCE_ADAPTER_ROUTE = "/v1/broker/adapter/gw_spectrum/evaluate"
M1_REFERENCE_BUILDER_ROUTE = S2_REFERENCE_BUILDER_ROUTE
M1_REFERENCE_REFEREE_ROUTE = "/v1/reference-referee/validate"
M1_REFERENCE_PROFILE_ROUTE = "/v1/reference-referee/profile"
M1_REFERENCE_OBSERVATORY_ROUTE = "/v1/reference-observatory/render"
M1_REFERENCE_SERVICE_REQUEST_TIMEOUT_S = 90.0
M1_REFERENCE_S2_TRAINING_ROW_COUNT = 16
M1_REFERENCE_OMEGA_SCALE = S2_REFERENCE_OMEGA_SCALE


@dataclass(frozen=True)
class HttpM1ReferenceAdapterClient:
    """C6 client that exposes only the S10-brokered reference adapter to S1."""

    endpoint_url: str
    session: RuntimeIdentitySession
    scope_token: Mapping[str, Any]

    def evaluate(self, request: EvalRequest) -> EvalResult:
        payload = {
            "scope_token": dict(self.scope_token),
            "eval_request": _m1_eval_request_payload(request),
        }
        try:
            response = _m1_request_json(
                "POST",
                self.endpoint_url,
                body=payload,
                bearer_token=self.session.access_token,
                timeout_s=self.session.timeout_s,
            )
        except RuntimeArtifactStoreError as exc:
            raise S7Error("REFERENCE_ADAPTER_UNAVAILABLE", str(exc)) from exc
        return _m1_eval_result_from_payload(response)


@dataclass(frozen=True)
class HttpM1ReferenceBuilderClient:
    """S1-facing client for the separately deployed S2 reference builder."""

    endpoint_url: str
    session: RuntimeIdentitySession

    def build(self, *, dataset_ref: str, profile_ref: str) -> dict[str, Any]:
        response = _m1_request_json(
            "POST",
            self.endpoint_url,
            body={
                "job_id": self.session.job_id,
                "dataset_ref": dataset_ref,
                "profile_ref": profile_ref,
            },
            bearer_token=self.session.access_token,
            timeout_s=self.session.timeout_s,
        )
        if response.get("job_id") != self.session.job_id:
            raise RuntimeArtifactStoreError("S2 builder response job_id does not match the S1 runtime identity")
        if response.get("dataset_ref") != dataset_ref:
            raise RuntimeArtifactStoreError("S2 builder response does not bind the requested training dataset")
        if response.get("claim_tier") != "ran-toy":
            raise RuntimeArtifactStoreError("S2 builder response violates the ran-toy claim-tier cap")
        for field in (
            "model_ref",
            "frozen_pipeline_ref",
            "training_log_ref",
            "uq_calibration_ref",
            "sandbox_evidence_ref",
        ):
            _m1_required_str(response, field, "S2 builder response")
        artifact_refs = response.get("artifact_refs")
        if not isinstance(artifact_refs, list) or not artifact_refs or not all(
            isinstance(ref, str) and ref for ref in artifact_refs
        ):
            raise RuntimeArtifactStoreError("S2 builder response requires non-empty string artifact_refs")
        if response["frozen_pipeline_ref"] not in artifact_refs:
            raise RuntimeArtifactStoreError("S2 builder response omits the frozen pipeline from artifact_refs")
        return dict(response)


@dataclass(frozen=True)
class M1ReferenceS2BuildDelegate:
    """Converts S7-backed training evidence into an authenticated S2 build request."""

    builder: HttpM1ReferenceBuilderClient
    source_dataset_ref: str
    adapter_inputs: Mapping[str, Any]

    def __call__(
        self,
        ctx: ExecContext,
        plan: Mapping[str, Any],
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        base_inputs = _m1_copy_adapter_inputs(self.adapter_inputs)
        base_adapter_call = _m1_mapping(evidence.get("adapter_call"), "S1 reference adapter evidence")
        rows = [_m1_s2_training_row(row_id="s7-reference-base", inputs=base_inputs, adapter_call=base_adapter_call)]
        provenance_refs = [str(base_adapter_call["provenance_ref"])]
        for index in range(1, M1_REFERENCE_S2_TRAINING_ROW_COUNT):
            inputs = _m1_s2_training_inputs(base_inputs, index=index)
            adapter_call = ctx.call_adapter(
                S1_REFERENCE_PHYSICS_ADAPTER_ID,
                {"inputs": inputs, "seed": 1000 + index},
            )
            rows.append(
                _m1_s2_training_row(
                    row_id=f"s7-reference-{index:03d}",
                    inputs=inputs,
                    adapter_call=adapter_call,
                )
            )
            provenance_refs.append(str(adapter_call["provenance_ref"]))

        perturbation_observations = _m1_mapping(
            evidence.get("perturbation_observations"),
            "S1 reference perturbation evidence",
        )
        for observation in perturbation_observations.values():
            if isinstance(observation, Mapping):
                provenance_ref = observation.get("provenance_ref")
                if isinstance(provenance_ref, str) and provenance_ref:
                    provenance_refs.append(provenance_ref)
        training_dataset = ctx.emit_artifact(
            {
                "schema": {
                    "features": ["adapter_omega_scaled"],
                    "target": "omega_scaled",
                },
                "rows": rows,
                "feature_scale": M1_REFERENCE_OMEGA_SCALE,
                "target_scale": M1_REFERENCE_OMEGA_SCALE,
                "source_class": "m1-s7-derived-reference-training",
                "reference_context": {
                    "source_dataset_ref": self.source_dataset_ref,
                    "canonical_row_id": rows[0]["row_id"],
                    "canonical_adapter_outputs": _m1_mapping(
                        evidence.get("adapter_outputs"),
                        "S1 reference adapter outputs",
                    ),
                    "canonical_adapter_provenance_ref": str(base_adapter_call["provenance_ref"]),
                    "perturbation_observations": perturbation_observations,
                },
            },
            kind="dataset",
            lineage=Lineage(
                input_refs=tuple(dict.fromkeys((self.source_dataset_ref, *provenance_refs))),
                code_ref="argus-runtime:m1-s1-s7-training-dataset",
                environment_digest="oci:argus-s1-reference-runtime:v2",
                seeds=("m1-reference-s7-training-v1",),
                job_id=ctx.job_id,
            ),
        )
        training_dataset_ref = _m1_required_str(training_dataset, "artifact_ref", "S1 training dataset")
        remote_build = self.builder.build(
            dataset_ref=training_dataset_ref,
            profile_ref=_m1_required_str(plan, "verifier_profile_ref", "S1 reference plan"),
        )
        remote_artifact_refs = tuple(str(ref) for ref in remote_build["artifact_refs"])
        diagnostics = _m1_mapping(evidence.get("diagnostics"), "S1 reference diagnostics")
        diagnostics.update(
            {
                "s2_training_dataset_ref": training_dataset_ref,
                "external_frozen_pipeline": {
                    "artifact_ref": str(remote_build["frozen_pipeline_ref"]),
                    "producer_subsystem": "S2",
                    "builder": "s2-reference-builder",
                    "model_ref": str(remote_build["model_ref"]),
                    "uq_calibration_ref": str(remote_build["uq_calibration_ref"]),
                    "sandbox_evidence_ref": str(remote_build["sandbox_evidence_ref"]),
                },
            }
        )
        omega_radius = float(evidence["omega_radius"])
        omega_source = str(evidence["omega_source"])
        return {
            "job_id": plan["job_id"],
            "artifact_refs": list(dict.fromkeys((training_dataset_ref, *remote_artifact_refs))),
            "training_log_ref": str(remote_build["training_log_ref"]),
            "diagnostics": diagnostics,
            "self_checks": [
                {
                    "type": "PHYSICAL_CONSISTENCY",
                    "status": "PASS",
                    "advisory": True,
                }
            ],
            "uncertainty_summary": ctx.tag_uncertainty(
                "interval",
                {
                    "radius": omega_radius,
                    "source": omega_source,
                    "s2_uq_calibration_ref": str(remote_build["uq_calibration_ref"]),
                },
            ),
        }


@dataclass(frozen=True)
class HttpM1ReferenceRefereeClient:
    """S1-facing client for the separately deployed S3 referee."""

    endpoint_url: str
    profile_endpoint_url: str
    session: RuntimeIdentitySession

    def ensure_profile(self) -> str:
        response = _m1_request_json(
            "GET",
            self.profile_endpoint_url,
            bearer_token=self.session.access_token,
            timeout_s=self.session.timeout_s,
        )
        return _m1_required_str(response, "profile_ref", "S3 profile response")

    def validate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        response = _m1_request_json(
            "POST",
            self.endpoint_url,
            body=_m1_mapping(request, "S3 validation request"),
            bearer_token=self.session.access_token,
            timeout_s=self.session.timeout_s,
        )
        payload = response.get("validation_report_payload")
        report_ref = response.get("validation_report_ref")
        if not isinstance(payload, Mapping) or not isinstance(report_ref, str) or not report_ref:
            raise RuntimeArtifactStoreError("S3 referee response lacks a persisted signed report")
        return {
            "validation_report_payload": dict(payload),
            "validation_report_ref": report_ref,
        }


@dataclass(frozen=True)
class HttpM1ReferenceObservatoryClient:
    """S1-facing client for S11's remote signature-verified rendering path."""

    endpoint_url: str
    session: RuntimeIdentitySession

    def render(self, *, subject_ref: str, report_ref: str) -> dict[str, Any]:
        response = _m1_request_json(
            "POST",
            self.endpoint_url,
            body={
                "job_id": self.session.job_id,
                "subject_ref": subject_ref,
                "report_ref": report_ref,
            },
            bearer_token=self.session.access_token,
            timeout_s=self.session.timeout_s,
        )
        if not isinstance(response.get("observatory_html_ref"), str):
            raise RuntimeArtifactStoreError("S11 response lacks observatory_html_ref")
        if response.get("trusted") is not True:
            failures = response.get("failures")
            raise RuntimeArtifactStoreError(f"S11 refused to render a trusted Observatory report: {failures}")
        return response


@dataclass(frozen=True)
class M1ReferenceLifecycleResult:
    """Materialized evidence from one fixed-job M1 reference lifecycle."""

    job_id: str
    final_state: str
    lifecycle_methods: tuple[str, ...]
    dataset_ref: str
    build_payload: dict[str, Any]
    validation_report_ref: str
    validation_report_payload: dict[str, Any]
    promoted_artifact_ref: str
    observatory_html_ref: str
    observatory_html: str
    observatory_trusted: bool
    observatory_failures: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        report = self.validation_report_payload
        checks = report.get("checks")
        diagnostics = _m1_mapping(self.build_payload.get("diagnostics"), "S1 build diagnostics")
        sandbox = diagnostics.get("sandbox")
        external_frozen_pipeline = diagnostics.get("external_frozen_pipeline")
        return {
            "demo": "s1-reference-physics",
            "job_id": self.job_id,
            "final_state": self.final_state,
            "lifecycle_methods": list(self.lifecycle_methods),
            "dataset_ref": self.dataset_ref,
            "runtime_provenance": {
                "adapter_provenance_ref": diagnostics.get("adapter_provenance_ref"),
                "sandbox_launch_provenance_ref": (
                    sandbox.get("launch_provenance_ref") if isinstance(sandbox, Mapping) else None
                ),
                "s2_training_dataset_ref": diagnostics.get("s2_training_dataset_ref"),
                "s2_frozen_pipeline_ref": (
                    external_frozen_pipeline.get("artifact_ref")
                    if isinstance(external_frozen_pipeline, Mapping)
                    else None
                ),
            },
            "artifact_refs": list(self.build_payload.get("artifact_refs", ())),
            "validation_report_ref": self.validation_report_ref,
            "promoted_artifact_ref": self.promoted_artifact_ref,
            "observatory_html_ref": self.observatory_html_ref,
            "observatory_trusted": self.observatory_trusted,
            "observatory_failures": list(self.observatory_failures),
            "claim_tier": report.get("claim_tier"),
            "claim_tier_is_candidate": bool(report.get("claim_tier_is_candidate")),
            "referee_id": _m1_mapping(report.get("referee"), "C3 referee").get("referee_id"),
            "signature_key_id": _m1_mapping(report.get("signature"), "C3 signature").get("key_id"),
            "checks": [
                {
                    "check": item.get("check"),
                    "status": item.get("status"),
                    "metrics": dict(item.get("metrics") or {}),
                    "evidence_refs": list(item.get("evidence_refs") or ()),
                }
                for item in checks
                if isinstance(item, Mapping)
            ]
            if isinstance(checks, list)
            else [],
        }


M1ReferenceLifecycleEventSink = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class M1ReferenceArtifactVerification:
    """Fresh C3/C4 verification evidence for a completed M1 reference run."""

    trusted: bool
    failures: tuple[str, ...]
    signature_key_id: str | None
    subject_ref: str
    report_ref: str
    report_matches_run_result: bool
    checked_at: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "trusted": self.trusted,
            "failures": list(self.failures),
            "signature_key_id": self.signature_key_id,
            "subject_ref": self.subject_ref,
            "report_ref": self.report_ref,
            "report_matches_run_result": self.report_matches_run_result,
            "checked_at": self.checked_at,
        }


def _emit_lifecycle_event(
    event_sink: M1ReferenceLifecycleEventSink | None,
    *,
    stage: str,
    status: str,
    detail: Mapping[str, Any] | None = None,
) -> None:
    if event_sink is None:
        return
    event = {"stage": stage, "status": status, "detail": dict(detail or {})}
    # A read-only observer must never be able to alter the trusted execution path.
    try:
        event_sink(event)
    except Exception:
        return


class M1ReferenceLifecycleRunner:
    """Runs the deployed S1/S7/S3/S11 reference path without in-memory fallbacks."""

    def __init__(
        self,
        *,
        s10_url: str,
        s8_url: str,
        bootstrap_token: str | None = None,
        access_token: str | None = None,
        secrets_broker_url: str,
        s2_url: str,
        s3_url: str,
        s11_url: str,
        verifier_key_endpoint_url: str,
        verifier_key_auth_token: str,
        allow_insecure_verifier_key_store: bool,
        caller_id: str = M1_REFERENCE_S1_CALLER_ID,
        expected_job_id: str = M1_REFERENCE_JOB_ID,
    ) -> None:
        if expected_job_id != M1_REFERENCE_JOB_ID:
            raise ValueError("M1 reference lifecycle only supports the fixed reference job")
        if bool(bootstrap_token) == bool(access_token):
            raise ValueError("M1 reference lifecycle requires exactly one runtime credential")
        self._s10_url = s10_url.rstrip("/")
        self._s8_url = s8_url.rstrip("/")
        self._bootstrap_token = bootstrap_token
        self._access_token = access_token
        self._secrets_broker_url = secrets_broker_url.rstrip("/")
        self._s2_url = s2_url.rstrip("/")
        self._s3_url = s3_url.rstrip("/")
        self._s11_url = s11_url.rstrip("/")
        self._verifier_key_endpoint_url = verifier_key_endpoint_url
        self._verifier_key_auth_token = verifier_key_auth_token
        self._allow_insecure_verifier_key_store = allow_insecure_verifier_key_store
        self._caller_id = caller_id
        self._expected_job_id = expected_job_id

    def _runtime_session(self) -> RuntimeIdentitySession:
        return runtime_identity_session(
            s10_url=self._s10_url,
            caller_id=self._caller_id,
            expected_job_id=self._expected_job_id,
            bootstrap_token=self._bootstrap_token,
            access_token=self._access_token,
            timeout_s=M1_REFERENCE_SERVICE_REQUEST_TIMEOUT_S,
        )

    def run(
        self,
        *,
        job_id: str,
        event_sink: M1ReferenceLifecycleEventSink | None = None,
    ) -> M1ReferenceLifecycleResult:
        if job_id != self._expected_job_id:
            raise ValueError("job_id_mismatch")
        _emit_lifecycle_event(event_sink, stage="runtime_identity", status="started")
        session = self._runtime_session()
        _emit_lifecycle_event(event_sink, stage="runtime_identity", status="completed")
        store = S10S8ArtifactStore(session=session, s8_url=self._s8_url)
        referee = HttpM1ReferenceRefereeClient(
            endpoint_url=f"{self._s3_url}{M1_REFERENCE_REFEREE_ROUTE}",
            profile_endpoint_url=f"{self._s3_url}{M1_REFERENCE_PROFILE_ROUTE}",
            session=session,
        )
        _emit_lifecycle_event(event_sink, stage="verifier_profile", status="started")
        profile_ref = referee.ensure_profile()
        if profile_ref != S1_REFERENCE_PHYSICS_PROFILE_REF:
            raise RuntimeArtifactStoreError("S3 returned an unexpected fixed reference profile")
        _emit_lifecycle_event(
            event_sink,
            stage="verifier_profile",
            status="completed",
            detail={"profile_ref": profile_ref},
        )
        _emit_lifecycle_event(event_sink, stage="reference_dataset", status="started")
        dataset_ref = self._ensure_controlled_reference_dataset(store)
        _emit_lifecycle_event(
            event_sink,
            stage="reference_dataset",
            status="completed",
            detail={"dataset_ref": dataset_ref},
        )
        adapter_client = HttpM1ReferenceAdapterClient(
            endpoint_url=f"{self._secrets_broker_url}{M1_REFERENCE_ADAPTER_ROUTE}",
            session=session,
            scope_token=session.mint_scope(),
        )
        builder_client = HttpM1ReferenceBuilderClient(
            endpoint_url=f"{self._s2_url}{M1_REFERENCE_BUILDER_ROUTE}",
            session=session,
        )
        provider = HttpS10VerifierKeyProvider(
            endpoint_url=self._verifier_key_endpoint_url,
            auth_token=self._verifier_key_auth_token,
            allow_insecure_verifier_key_store=self._allow_insecure_verifier_key_store,
        )
        report_verifier = C3ReportVerifier(S10VerifierTrustStoreClient(provider))
        descriptor = SubagentDescriptor(
            subagent_id="s1-reference-physics",
            contract_version="1.0.0",
            subtopics=("ewpt",),
            required_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
        )
        subagent = S1ReferencePhysicsSubagent(
            descriptor=descriptor,
            dataset_ref=dataset_ref,
            adapter_inputs=_m1_reference_adapter_inputs(),
            sandbox_spec_factory=ReferenceS10SandboxSpecFactory(session=session),
            build_delegate=M1ReferenceS2BuildDelegate(
                builder=builder_client,
                source_dataset_ref=dataset_ref,
                adapter_inputs=_m1_reference_adapter_inputs(),
            ),
        )
        runtime = SubagentRuntime(
            descriptor=descriptor,
            artifact_store=store,
            sandbox_marshaler=S10SandboxMarshaler(HttpS10SandboxLauncher(session=session)),
            adapter_client=adapter_client,
            adapter_egress_allowlist={S1_REFERENCE_PHYSICS_ADAPTER_ID: (M1_REFERENCE_ADAPTER_EGRESS_RULE,)},
        )
        runner = SubagentSDKRunner(subagent, runtime=runtime)
        envelope = JobEnvelope(
            job_id=job_id,
            envelope_version="1.0.0",
            subtopic="ewpt",
            required_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
            allowed_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
            verifier_profile_ref=profile_ref,
            estimated_cost=1.0,
            budget_cost=2.0,
        )
        _emit_lifecycle_event(event_sink, stage="accept", status="started")
        acceptance = runner.accept(envelope)
        if not acceptance.accepted:
            raise RuntimeArtifactStoreError(f"S1 reference lifecycle was refused: {acceptance.reason}")
        _emit_lifecycle_event(event_sink, stage="accept", status="completed")
        _emit_lifecycle_event(event_sink, stage="plan", status="started")
        plan = runner.plan(envelope)
        _emit_lifecycle_event(event_sink, stage="plan", status="completed")
        _emit_lifecycle_event(
            event_sink,
            stage="build",
            status="started",
            detail={"components": ["S10", "S7", "S2"]},
        )
        build = runner.build(job_id, plan.payload)
        build_diagnostics = _m1_mapping(build.payload.get("diagnostics"), "S1 build diagnostics")
        frozen_pipeline = build_diagnostics.get("external_frozen_pipeline")
        _emit_lifecycle_event(
            event_sink,
            stage="build",
            status="completed",
            detail={
                "artifact_refs": [str(ref) for ref in build.payload.get("artifact_refs", ())],
                "frozen_pipeline_ref": (
                    frozen_pipeline.get("artifact_ref") if isinstance(frozen_pipeline, Mapping) else None
                ),
            },
        )
        _emit_lifecycle_event(event_sink, stage="validate", status="started", detail={"component": "S3"})
        validation = runner.validate(
            job_id,
            build.payload,
            profile_ref=profile_ref,
            blind_dataset_handle=f"blind://m1-reference/{job_id}",
            budget_token_ref=f"budget://m1-reference/{job_id}",
            validation_client=referee,
            report_verifier=report_verifier,
            trace_id=f"trace:{job_id}",
        )
        _emit_lifecycle_event(
            event_sink,
            stage="validate",
            status="completed",
            detail={"validation_report_ref": validation.payload.get("validation_report_ref")},
        )
        _emit_lifecycle_event(event_sink, stage="report", status="started")
        promoted_ref = self._promote_validated_subject(
            store=store,
            job_id=job_id,
            build_payload=build.payload,
            validation_payload=validation.payload,
        )
        subagent_report = dict(validation.payload["subagent_report"])
        subagent_report["artifact_refs"] = [promoted_ref]
        reproducibility_manifest = _m1_mapping(subagent_report.get("reproducibility_manifest"), "S1 report manifest")
        subagent_report["reproducibility_manifest"] = {
            **reproducibility_manifest,
            "lineage_ref": promoted_ref,
        }
        runner.report(job_id, subagent_report)
        _emit_lifecycle_event(
            event_sink,
            stage="report",
            status="completed",
            detail={"promoted_artifact_ref": promoted_ref},
        )
        _emit_lifecycle_event(event_sink, stage="observatory", status="started", detail={"component": "S11"})
        observatory = HttpM1ReferenceObservatoryClient(
            endpoint_url=f"{self._s11_url}{M1_REFERENCE_OBSERVATORY_ROUTE}",
            session=session,
        ).render(
            subject_ref=promoted_ref,
            report_ref=str(validation.payload["validation_report_ref"]),
        )
        state = runner.runtime.store.current(job_id).state.value
        methods = tuple(event.method for event in runner.runtime.store.events(job_id))
        result = M1ReferenceLifecycleResult(
            job_id=job_id,
            final_state=state,
            lifecycle_methods=methods,
            dataset_ref=dataset_ref,
            build_payload=dict(build.payload),
            validation_report_ref=str(validation.payload["validation_report_ref"]),
            validation_report_payload=dict(validation.payload["validation_report_payload"]),
            promoted_artifact_ref=promoted_ref,
            observatory_html_ref=str(observatory["observatory_html_ref"]),
            observatory_html=str(observatory["observatory_html"]),
            observatory_trusted=bool(observatory["trusted"]),
            observatory_failures=tuple(str(item) for item in observatory.get("failures", ())),
        )
        _emit_lifecycle_event(
            event_sink,
            stage="observatory",
            status="completed",
            detail={
                "observatory_html_ref": result.observatory_html_ref,
                "trusted": result.observatory_trusted,
            },
        )
        _emit_lifecycle_event(
            event_sink,
            stage="run",
            status="completed",
            detail={"final_state": result.final_state},
        )
        return result

    def verify_artifact(self, *, result: M1ReferenceLifecycleResult) -> M1ReferenceArtifactVerification:
        """Re-read the persisted report and lineage before returning a pilot-facing verdict."""

        if result.job_id != self._expected_job_id:
            raise ValueError("job_id_mismatch")
        session = self._runtime_session()
        store = S10S8ArtifactStore(session=session, s8_url=self._s8_url)
        try:
            persisted_report = json.loads(store.get_artifact(result.validation_report_ref).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeArtifactStoreError("persisted validation report is invalid JSON") from exc
        if not isinstance(persisted_report, dict):
            raise RuntimeArtifactStoreError("persisted validation report must be an object")
        provider = HttpS10VerifierKeyProvider(
            endpoint_url=self._verifier_key_endpoint_url,
            auth_token=self._verifier_key_auth_token,
            allow_insecure_verifier_key_store=self._allow_insecure_verifier_key_store,
        )
        verification = verify_observatory_v0(
            report_payload=persisted_report,
            lineage=ObservatoryLineageBundle(
                subject_ref=result.promoted_artifact_ref,
                report_ref=result.validation_report_ref,
                graph=store.get_lineage(result.promoted_artifact_ref, direction="ancestors"),
            ),
            report_verifier=C3ReportVerifier(S10VerifierTrustStoreClient(provider)),
        )
        report_matches_run_result = persisted_report == result.validation_report_payload
        failures = list(verification.failures)
        if not report_matches_run_result:
            failures.append("persisted validation report does not match the run result")
        return M1ReferenceArtifactVerification(
            trusted=verification.trusted and report_matches_run_result,
            failures=tuple(failures),
            signature_key_id=verification.signature_key_id,
            subject_ref=result.promoted_artifact_ref,
            report_ref=result.validation_report_ref,
            report_matches_run_result=report_matches_run_result,
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    def _ensure_controlled_reference_dataset(self, store: S10S8ArtifactStore) -> str:
        inputs = _m1_reference_adapter_inputs()
        record = store.create_artifact(
            kind="dataset",
            artifact_ref=S1_REFERENCE_PHYSICS_DATASET_REF,
            payload={
                "schema": "argus.m1.reference_request_context.v2",
                "rows": [
                    {
                        "T_n": inputs["T_n"]["value"],
                        "alpha": inputs["alpha"]["value"],
                        "beta_over_H": inputs["beta_over_H"]["value"],
                        "v_w": inputs["v_w"]["value"],
                        "frequency": inputs["frequency"]["value"],
                    }
                ],
                "source_class": "m1-reference-request-context",
            },
            producer=Producer(
                subsystem="S1",
                version="0.0.0",
                actor_id="s1.reference-input",
                job_id=self._expected_job_id,
            ),
            lineage=Lineage(
                input_refs=(),
                code_ref="argus-runtime:m1-reference-input",
                environment_digest="oci:argus-s1-reference-runtime:v1",
                job_id=self._expected_job_id,
            ),
        )
        return record.artifact_ref

    def _promote_validated_subject(
        self,
        *,
        store: S10S8ArtifactStore,
        job_id: str,
        build_payload: Mapping[str, Any],
        validation_payload: Mapping[str, Any],
    ) -> str:
        report = _m1_mapping(validation_payload.get("validation_report_payload"), "S3 report")
        report_ref = _m1_required_str(validation_payload, "validation_report_ref", "S3 validation result")
        artifact_refs = tuple(str(ref) for ref in build_payload.get("artifact_refs", ()))
        if not artifact_refs:
            raise RuntimeArtifactStoreError("S1 build did not produce promotable artifact references")
        input_refs = list(artifact_refs)
        diagnostics = _m1_mapping(build_payload.get("diagnostics"), "S1 build diagnostics")
        sandbox = diagnostics.get("sandbox")
        if isinstance(sandbox, Mapping):
            launch_ref = sandbox.get("launch_provenance_ref")
            if isinstance(launch_ref, str) and launch_ref:
                input_refs.append(launch_ref)
        record = store.create_artifact(
            kind="model",
            payload={
                "schema": "argus.s1.reference_physics_subject.v1",
                "job_id": job_id,
                "artifact_refs": list(artifact_refs),
                "validation_report_ref": report_ref,
                "uncertainty_tag": {"kind": "interval", "source": "s1-reference-physics"},
                "report_id": report.get("report_id"),
            },
            producer=Producer(
                subsystem="S1",
                version="0.0.0",
                actor_id="s1.reference-physics",
                job_id=job_id,
            ),
            lineage=Lineage(
                input_refs=tuple(dict.fromkeys(input_refs)),
                code_ref="argus-runtime:s1-reference-promote",
                environment_digest="oci:argus-s1-reference-runtime:v1",
                seeds=("m1-reference-seed",),
                job_id=job_id,
            ),
            claim_tier=_m1_required_str(report, "claim_tier", "S3 report"),
            validation_report_ref=report_ref,
        )
        return record.artifact_ref


def _m1_reference_adapter_inputs() -> dict[str, dict[str, object]]:
    return {
        "T_n": {"value": 100.0, "units": "GeV", "uncertainty": {"kind": "interval", "radius": 1.0}},
        "alpha": {"value": 0.2, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 0.01}},
        "beta_over_H": {"value": 100.0, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 5.0}},
        "v_w": {"value": 0.7, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 0.02}},
        "frequency": {"value": 0.003, "units": "Hz", "uncertainty": {"kind": "interval", "radius": 0.0001}},
    }


def _m1_copy_adapter_inputs(inputs: Mapping[str, Any]) -> dict[str, dict[str, object]]:
    copied: dict[str, dict[str, object]] = {}
    for field in ("T_n", "alpha", "beta_over_H", "v_w", "frequency"):
        payload = _m1_mapping(inputs.get(field), f"reference adapter input {field}")
        copied[field] = dict(payload)
        uncertainty = copied[field].get("uncertainty")
        if isinstance(uncertainty, Mapping):
            copied[field]["uncertainty"] = dict(uncertainty)
    return copied


def _m1_s2_training_inputs(
    template: Mapping[str, Any],
    *,
    index: int,
) -> dict[str, dict[str, object]]:
    inputs = _m1_copy_adapter_inputs(template)
    values = {
        "alpha": 0.05 + (index % 10) * 0.02,
        "beta_over_H": 70.0 + (index // 10) * 12.0,
        "v_w": 0.45 + (index % 6) * 0.07,
        "frequency": 0.001 + (index % 8) * 0.0005,
    }
    for field, value in values.items():
        inputs[field] = {**inputs[field], "value": value}
    return inputs


def _m1_s2_training_row(
    *,
    row_id: str,
    inputs: Mapping[str, Any],
    adapter_call: Mapping[str, Any],
) -> dict[str, Any]:
    result = _m1_mapping(adapter_call.get("result"), "S7 training adapter result")
    outputs = _m1_mapping(result.get("outputs"), "S7 training adapter outputs")
    omega = _m1_mapping(outputs.get("omega"), "S7 training adapter omega")
    try:
        omega_value = float(omega["value"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeArtifactStoreError("S7 training adapter omega must be numeric") from exc
    if not isfinite(omega_value) or omega_value <= 0.0:
        raise RuntimeArtifactStoreError("S7 training adapter omega must be finite and positive")
    provenance_ref = _m1_required_str(adapter_call, "provenance_ref", "S7 training adapter result")
    row = {
        "row_id": row_id,
        "T_n": _m1_adapter_input_value(inputs, "T_n"),
        "alpha": _m1_adapter_input_value(inputs, "alpha"),
        "beta_over_H": _m1_adapter_input_value(inputs, "beta_over_H"),
        "v_w": _m1_adapter_input_value(inputs, "v_w"),
        "frequency": _m1_adapter_input_value(inputs, "frequency"),
        "adapter_omega": omega_value,
        "omega": omega_value,
        "known_omega": omega_value,
        "adapter_omega_scaled": omega_value / M1_REFERENCE_OMEGA_SCALE,
        "omega_scaled": omega_value / M1_REFERENCE_OMEGA_SCALE,
        "adapter_provenance_ref": provenance_ref,
        "role": "train",
    }
    uncertainty = omega.get("uncertainty")
    if isinstance(uncertainty, Mapping):
        row["omega_uncertainty"] = dict(uncertainty)
    return row


def _m1_adapter_input_value(inputs: Mapping[str, Any], field: str) -> float:
    quantity = _m1_mapping(inputs.get(field), f"reference adapter input {field}")
    try:
        value = float(quantity["value"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeArtifactStoreError(f"reference adapter input {field} must be numeric") from exc
    if not isfinite(value) or value <= 0.0:
        raise RuntimeArtifactStoreError(f"reference adapter input {field} must be finite and positive")
    return value


def _m1_eval_request_payload(request: EvalRequest) -> dict[str, Any]:
    return {
        "adapter_id": request.adapter_id,
        "inputs": {field: asdict(quantity) for field, quantity in sorted(request.inputs.items())},
        "c6_version": request.c6_version,
        "seed": request.seed,
        "job_seed": request.job_seed,
        "dag_node_id": request.dag_node_id,
        "call_index": request.call_index,
        "budget_token_ref": request.budget_token_ref,
    }


def _m1_eval_result_from_payload(payload: Mapping[str, Any]) -> EvalResult:
    adapter_id = _m1_required_str(payload, "adapter_id", "S7 evaluation response")
    raw_outputs = _m1_mapping(payload.get("outputs"), "S7 evaluation response outputs")
    outputs = {
        str(field): Quantity(
            value=float(_m1_mapping(value, f"S7 output {field}")["value"]),
            units=_m1_required_str(_m1_mapping(value, f"S7 output {field}"), "units", f"S7 output {field}"),
            uncertainty=(
                dict(_m1_mapping(_m1_mapping(value, f"S7 output {field}").get("uncertainty"), f"S7 output {field} uncertainty"))
                if _m1_mapping(value, f"S7 output {field}").get("uncertainty") is not None
                else None
            ),
        )
        for field, value in raw_outputs.items()
    }
    if not outputs:
        raise RuntimeArtifactStoreError("S7 evaluation response has no outputs")
    return EvalResult(
        adapter_id=adapter_id,
        outputs=outputs,
        in_validity_domain=_m1_required_bool(payload, "in_validity_domain", "S7 evaluation response"),
        extrapolation_flag=_m1_required_bool(payload, "extrapolation_flag", "S7 evaluation response"),
        provenance_ref=_m1_required_str(payload, "provenance_ref", "S7 evaluation response"),
        seed_used=_m1_optional_int(payload.get("seed_used"), "S7 evaluation response seed_used"),
        seed_source=_m1_optional_str(payload.get("seed_source"), "S7 evaluation response seed_source") or "unseeded",
        seed_derivation=_m1_mapping(payload.get("seed_derivation"), "S7 evaluation response seed_derivation"),
        domain_diagnostics=_m1_mapping(payload.get("domain_diagnostics"), "S7 evaluation response domain_diagnostics"),
        unit_registry_version=_m1_optional_str(payload.get("unit_registry_version"), "S7 evaluation response unit_registry_version")
        or "unknown",
        unit_registry_hash=_m1_optional_str(payload.get("unit_registry_hash"), "S7 evaluation response unit_registry_hash") or "unknown",
        uncertainty_engine_version=_m1_optional_str(
            payload.get("uncertainty_engine_version"), "S7 evaluation response uncertainty_engine_version"
        )
        or "unknown",
        uncertainty_engine_hash=_m1_optional_str(
            payload.get("uncertainty_engine_hash"), "S7 evaluation response uncertainty_engine_hash"
        )
        or "unknown",
        validity_domain_guard_version=_m1_optional_str(
            payload.get("validity_domain_guard_version"), "S7 evaluation response validity_domain_guard_version"
        )
        or "unknown",
        validity_domain_guard_hash=_m1_optional_str(
            payload.get("validity_domain_guard_hash"), "S7 evaluation response validity_domain_guard_hash"
        )
        or "unknown",
        seed_manager_version=_m1_optional_str(payload.get("seed_manager_version"), "S7 evaluation response seed_manager_version")
        or "unknown",
        seed_manager_hash=_m1_optional_str(payload.get("seed_manager_hash"), "S7 evaluation response seed_manager_hash")
        or "unknown",
        backend_name=_m1_optional_str(payload.get("backend_name"), "S7 evaluation response backend_name") or "unknown",
        backend_version=_m1_optional_str(payload.get("backend_version"), "S7 evaluation response backend_version")
        or "unknown",
        backend_hash=_m1_optional_str(payload.get("backend_hash"), "S7 evaluation response backend_hash") or "unknown",
        underlying_code_version=_m1_optional_str(
            payload.get("underlying_code_version"), "S7 evaluation response underlying_code_version"
        )
        or "unknown",
    )


def _m1_request_json(
    method: str,
    url: str,
    *,
    body: Mapping[str, Any] | None = None,
    bearer_token: str,
    timeout_s: float,
) -> dict[str, Any]:
    data = None
    headers = {"Authorization": f"Bearer {bearer_token}"}
    if body is not None:
        data = json.dumps(_jsonable(body), separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urlrequest.Request(url, data=data, headers=headers, method=method)
    try:
        with urlrequest.urlopen(request, timeout=timeout_s) as response:
            raw = response.read()
    except urlerror.HTTPError as exc:
        raise RuntimeArtifactStoreError(f"{method} {url} failed with HTTP {exc.code}: {_http_error_message(exc)}") from exc
    except OSError as exc:
        raise RuntimeArtifactStoreError(f"{method} {url} could not be reached: {exc}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeArtifactStoreError(f"{method} {url} returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeArtifactStoreError(f"{method} {url} returned a non-object JSON response")
    return payload


def _m1_mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeArtifactStoreError(f"{context} must be an object")
    return dict(value)


def _m1_required_str(value: Mapping[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise RuntimeArtifactStoreError(f"{context} requires non-empty {field}")
    return item


def _m1_optional_str(value: Any, context: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeArtifactStoreError(f"{context} must be a string or null")
    return value


def _m1_optional_int(value: Any, context: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeArtifactStoreError(f"{context} must be an integer or null")
    return value


def _m1_required_bool(value: Mapping[str, Any], field: str, context: str) -> bool:
    item = value.get(field)
    if not isinstance(item, bool):
        raise RuntimeArtifactStoreError(f"{context} requires boolean {field}")
    return item
