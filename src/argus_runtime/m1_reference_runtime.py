"""Runtime-only helpers for the deployed M1 reference lifecycle."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from math import isfinite
from typing import Any, Mapping
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
