"""S10 supervisor service for the argus-m0 stack."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import hmac
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Mapping
from urllib import error, parse, request

from argus_core import (
    ArtifactRecord,
    BudgetCaps,
    BudgetExceededError,
    BudgetToken,
    BudgetUsage,
    EgressRule,
    EgressSidecarRuntimeConfig,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    Ed25519KmsTokenSigner,
    ExfilThresholds,
    FileTokenRevocationStore,
    FirecrackerRuntimeConfig,
    FirecrackerSandboxSupervisor,
    FileSystemArtifactStore,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryPolicyBundleTrustStore,
    InMemoryPolicyService,
    InMemoryS10KmsCheckpointSigner,
    InMemoryS10KmsVerifierKeyProvider,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    Lineage,
    PolicyBundle,
    PolicyBundleSigner,
    PolicyDeniedError,
    Producer,
    PriceTable,
    PriceTableSignatureError,
    PriceTableSigner,
    PriceTableTrustStore,
    ResourceCeilings,
    GvisorRuntimeConfig,
    SandboxRuntimeUnavailableError,
    ScopeDeniedError,
    ScopeGrant,
    ScopeToken,
    StoreWriterBroker,
    TrustMount,
    TokenInvalidError,
    TokenSignatureTrustStore,
    WriteOnceViolationError,
    IncompleteLineageError,
    canonical_json_bytes,
    hash_bytes,
    hash_json,
    roll_up_price_table_usage,
)

from .auth import (
    IdentityOverrideError,
    RuntimeAuth,
    RuntimeIdentity,
    UnauthorizedError,
    health_token_from_env,
    reject_identity_overrides,
    require_static_bearer_token,
    runtime_identity_from_dict,
    runtime_auth_from_env,
)
from .http_json import JsonHttpApp, JsonRequest, serve_json_app


class AdapterBrokerUpstreamError(RuntimeError):
    """Raised when a configured credentialed adapter cannot return a trusted C6 response."""


class ModelBrokerUpstreamError(RuntimeError):
    """Raised when a configured model provider violates the broker contract."""


@dataclass(frozen=True)
class CredentialedAdapterTarget:
    adapter_id: str
    endpoint_url: str
    credential_header: str
    credential: str = field(repr=False)
    timeout_s: float = 10.0

    def __post_init__(self) -> None:
        if not self.adapter_id or "/" in self.adapter_id:
            raise ValueError("adapter target id must be a non-empty path segment")
        endpoint = parse.urlparse(self.endpoint_url)
        if endpoint.scheme not in {"http", "https"} or not endpoint.netloc:
            raise ValueError("adapter target endpoint must be an absolute HTTP(S) URL")
        if endpoint.username is not None or endpoint.password is not None:
            raise ValueError("adapter target endpoint must not contain credentials")
        if not self.credential_header.lower().startswith("x-argus-") or any(
            char in self.credential_header for char in "\r\n:"
        ):
            raise ValueError("adapter credential header must be a valid X-Argus header name")
        if not self.credential or any(char in self.credential for char in "\r\n"):
            raise ValueError("adapter credential must be a non-empty single-line value")
        if not math.isfinite(self.timeout_s) or self.timeout_s <= 0:
            raise ValueError("adapter target timeout must be a positive finite number")


@dataclass(frozen=True)
class CredentialedModelTarget:
    model_id: str
    completion_url: str
    token_count_url: str
    credential_header: str
    credential: str = field(repr=False)
    static_headers: Mapping[str, str] = field(default_factory=dict)
    audience: str = "model"
    timeout_s: float = 30.0

    def __post_init__(self) -> None:
        if not self.model_id or any(char.isspace() for char in self.model_id):
            raise ValueError("model target id must be a non-empty token")
        for field_name, endpoint_url in (
            ("completion_url", self.completion_url),
            ("token_count_url", self.token_count_url),
        ):
            endpoint = parse.urlparse(endpoint_url)
            if endpoint.scheme not in {"http", "https"} or not endpoint.netloc:
                raise ValueError(f"model target {field_name} must be an absolute HTTP(S) URL")
            if endpoint.username is not None or endpoint.password is not None:
                raise ValueError(f"model target {field_name} must not contain credentials")
        _validate_outbound_header_name(self.credential_header, field="model credential_header")
        if self.credential_header.lower() in {"content-type", "content-length", "host"}:
            raise ValueError("model credential header cannot override an HTTP framing header")
        if not self.credential or any(char in self.credential for char in "\r\n"):
            raise ValueError("model credential must be a non-empty single-line value")
        if (
            not isinstance(self.audience, str)
            or not self.audience
            or any(char.isspace() for char in self.audience)
        ):
            raise ValueError("model broker audience must be a non-empty token")
        normalized_static_headers: dict[str, str] = {}
        for name, value in self.static_headers.items():
            _validate_outbound_header_name(name, field="model static header")
            if name.lower() in {
                "content-type",
                "content-length",
                "host",
                self.credential_header.lower(),
            }:
                raise ValueError("model static headers cannot override broker-owned headers")
            if not isinstance(value, str) or not value or any(char in value for char in "\r\n"):
                raise ValueError("model static header values must be non-empty single-line strings")
            normalized_static_headers[name] = value
        object.__setattr__(self, "static_headers", normalized_static_headers)
        if not math.isfinite(self.timeout_s) or self.timeout_s <= 0:
            raise ValueError("model target timeout must be a positive finite number")


@dataclass(frozen=True)
class RuntimeIdentityMintPolicy:
    identities_by_caller: dict[str, RuntimeIdentity]

    @classmethod
    def from_json(cls, raw: str) -> "RuntimeIdentityMintPolicy":
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("runtime identity mint policy must be a JSON object")
        identities: dict[str, RuntimeIdentity] = {}
        for caller_id, identity_body in parsed.items():
            if not isinstance(caller_id, str) or not caller_id:
                raise ValueError("runtime identity mint policy caller ids must be non-empty strings")
            if not isinstance(identity_body, dict):
                raise ValueError("runtime identity mint policy entries must be objects")
            identity = runtime_identity_from_dict({**identity_body, "caller_id": caller_id})
            identities[caller_id] = RuntimeIdentity(
                caller_id=identity.caller_id,
                job_id=identity.job_id,
                root_request_id=identity.root_request_id,
                scopes=identity.scopes,
                budget_caps=identity.budget_caps,
                max_ttl_s=identity.max_ttl_s,
            )
        return cls(identities)

    def identity_for_request(self, body: dict[str, Any]) -> RuntimeIdentity:
        override_fields = sorted(set(body) - {"caller_id", "ttl_s"})
        if override_fields:
            raise IdentityOverrideError(
                "runtime identity fields are bound to the server mint policy: " + ", ".join(override_fields)
            )
        caller_id = _required_str(body, "caller_id")
        identity = self.identities_by_caller.get(caller_id)
        if identity is None:
            raise PermissionError("runtime identity caller is not allowed by mint policy")
        return identity


class S10SupervisorApp:
    def __init__(
        self,
        *,
        signing_key: bytes | None = None,
        token_service: InMemoryTokenService | None = None,
        artifact_store: InMemoryArtifactStore | None = None,
        artifact_store_path: str | os.PathLike[str] | None = None,
        auth: RuntimeAuth | None = None,
        runtime_identity_mint_policy: RuntimeIdentityMintPolicy | None = None,
        health_token: str | None = None,
        policy_service: InMemoryPolicyService | None = None,
        quota_ledger: Any | None = None,
        checkpoint_signer: InMemoryS10KmsCheckpointSigner | None = None,
        checkpoint_signer_auth_token: str | None = None,
        verifier_key_provider: InMemoryS10KmsVerifierKeyProvider | None = None,
        verifier_key_auth_token: str | None = None,
        docker_supervisor: DockerSandboxSupervisor | None = None,
        price_table: PriceTable | None = None,
        price_table_trust_store: PriceTableTrustStore | None = None,
        adapter_targets: Mapping[str, CredentialedAdapterTarget] | None = None,
        model_targets: Mapping[str, CredentialedModelTarget] | None = None,
    ) -> None:
        self.tokens = token_service or InMemoryTokenService(signing_key=signing_key)
        self.quota = quota_ledger or InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        self.artifacts = artifact_store if artifact_store is not None else InMemoryArtifactStore()
        self._artifact_store_path = Path(artifact_store_path) if artifact_store_path is not None else None
        self.auth = auth
        self.runtime_identity_mint_policy = runtime_identity_mint_policy
        self._health_token = health_token
        self.policy_service = policy_service or _default_policy_service()
        self.policy = self.policy_service.active_bundle
        self.checkpoint_signer = checkpoint_signer
        self._checkpoint_signer_auth_token = checkpoint_signer_auth_token
        self.verifier_key_provider = verifier_key_provider
        self._verifier_key_auth_token = verifier_key_auth_token
        self._docker_supervisor = docker_supervisor or DockerSandboxSupervisor()
        self.price_table = price_table
        self.price_table_trust_store = price_table_trust_store
        self._adapter_targets = dict(adapter_targets or {})
        for adapter_id, target in self._adapter_targets.items():
            if adapter_id != target.adapter_id:
                raise ValueError("adapter target map key must match target.adapter_id")
        self._model_targets = dict(model_targets or {})
        for model_id, target in self._model_targets.items():
            if model_id != target.model_id:
                raise ValueError("model target map key must match target.model_id")
        if self._model_targets and (self.price_table is None or self.price_table_trust_store is None):
            raise ValueError("model targets require a signed price table and trust store")
        if self.price_table is not None and self.price_table_trust_store is not None:
            self.price_table_trust_store.verify(self.price_table)
        self.broker = StoreWriterBroker(
            token_service=self.tokens,
            artifact_store=self.artifacts,
            audit_ledger=self.audit,
        )
        self._docker_orchestrator = self._build_docker_orchestrator()
        self.http = JsonHttpApp()
        self._register_routes()

    def mint_budget(self, body: dict[str, Any]) -> dict[str, Any]:
        caps = BudgetCaps(**dict(body.get("caps") or {}))
        token = self.tokens.mint_budget(
            caps=caps,
            job_id=_required_str(body, "job_id"),
            root_request_id=_required_str(body, "root_request_id"),
            ttl_s=int(body.get("ttl_s", 3600)),
        )
        return asdict(token)

    def mint_budget_for_identity(self, identity: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        _require_runtime_identity(identity)
        reject_identity_overrides(body, ("job_id", "root_request_id", "caps", "risk_class"))
        ttl_s = _bounded_ttl(body, identity.max_ttl_s)
        token = self.tokens.mint_budget(
            caps=identity.budget_caps,
            job_id=identity.job_id,
            root_request_id=identity.root_request_id,
            risk_class=identity.scopes.sandbox_risk_class,
            ttl_s=ttl_s,
        )
        return asdict(token)

    def mint_scope(self, body: dict[str, Any]) -> dict[str, Any]:
        scopes_body = dict(body.get("scopes") or {})
        scopes = _scope_grant_from_dict(scopes_body)
        token = self.tokens.mint_scope(
            job_id=_required_str(body, "job_id"),
            scopes=scopes,
            ttl_s=int(body.get("ttl_s", 3600)),
        )
        return asdict(token)

    def mint_scope_for_identity(self, identity: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        _require_runtime_identity(identity)
        reject_identity_overrides(body, ("job_id", "scopes"))
        ttl_s = _bounded_ttl(body, identity.max_ttl_s)
        token = self.tokens.mint_scope(
            job_id=identity.job_id,
            scopes=identity.scopes,
            ttl_s=ttl_s,
        )
        return asdict(token)

    def broker_put_artifact(self, body: dict[str, Any]) -> dict[str, Any]:
        self._refresh_artifacts()
        record = self.broker.client_for(_scope_token_from_dict(_required_dict(body, "scope_token"))).put_artifact(
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

    def broker_put_artifact_for_identity(self, identity: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        scope_token = self._verified_scope_for_identity(identity, body)
        self._refresh_artifacts()
        record = self.broker.client_for(scope_token).put_artifact(
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

    def broker_get_artifact_for_identity(self, identity: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        scope_token = self._verified_scope_for_identity(identity, body)
        self._refresh_artifacts()
        return self.broker.client_for(scope_token).get_artifact(
            artifact_ref=_required_str(body, "artifact_ref"),
            representation=_required_str(body, "representation"),
        )

    def broker_evaluate_adapter_for_identity(
        self,
        identity: RuntimeIdentity,
        *,
        adapter_id: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        scope_token = self._verified_scope_for_identity(identity, body)
        eval_request = _required_dict(body, "eval_request")
        requested_adapter_id = _required_str(eval_request, "adapter_id")
        if requested_adapter_id != adapter_id:
            self._deny_adapter(scope_token, adapter_id=adapter_id, reason="adapter_id_mismatch")
        if adapter_id not in scope_token.scopes.allowed_adapters:
            self._deny_adapter(scope_token, adapter_id=adapter_id, reason="adapter_not_allowlisted")
        if adapter_id not in scope_token.scopes.broker_audiences:
            self._deny_adapter(scope_token, adapter_id=adapter_id, reason="broker_audience_missing")
        target = self._adapter_targets.get(adapter_id)
        if target is None:
            self._deny_adapter(scope_token, adapter_id=adapter_id, reason="adapter_not_configured")

        result = self._call_credentialed_adapter(
            target,
            {"job_id": identity.job_id, "eval_request": eval_request},
        )
        if result.get("adapter_id") != adapter_id:
            raise AdapterBrokerUpstreamError("adapter upstream response id does not match the broker target")
        if not isinstance(result.get("outputs"), dict):
            raise AdapterBrokerUpstreamError("adapter upstream response omits C6 outputs")
        if not isinstance(result.get("provenance_ref"), str) or not result["provenance_ref"]:
            raise AdapterBrokerUpstreamError("adapter upstream response omits C6 provenance")
        if not isinstance(result.get("uncertainty_engine_version"), str) or not result[
            "uncertainty_engine_version"
        ]:
            raise AdapterBrokerUpstreamError("adapter upstream response omits C6 uncertainty metadata")
        self.audit.append(
            "adapter.evaluate",
            {
                "audience": adapter_id,
                "adapter_id": adapter_id,
                "scope_id": scope_token.scope_id,
                "job_id": scope_token.job_id,
                "provenance_ref": result["provenance_ref"],
                "request_hash": hash_bytes(canonical_json_bytes(eval_request)),
            },
        )
        return result

    def broker_complete_model_for_identity(
        self,
        identity: RuntimeIdentity,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        scope_token = self._verified_scope_for_identity(identity, body)
        budget_token = self._verified_budget_for_identity(identity, body)
        model_request = _validated_model_broker_request(_required_dict(body, "request"))
        model_id = _required_str(model_request, "model")
        target = self._model_targets.get(model_id)
        if target is None:
            self._deny_model(scope_token, model_id=model_id, reason="model_not_configured")
        if target.audience not in scope_token.scopes.broker_audiences:
            self._deny_model(scope_token, model_id=model_id, reason="broker_audience_missing")

        self.quota.register_budget(budget_token)
        state = self.quota.state(budget_token.budget_id)
        if state.halted:
            self._audit_model_budget_halt(
                scope_token=scope_token,
                budget_token=budget_token,
                model_id=model_id,
                reason="budget_already_halted",
                requested_tokens=0,
            )
            raise BudgetExceededError(f"budget is halted: {budget_token.budget_id}")

        count_request = _model_token_count_request(model_request)
        try:
            count_result = self._call_credentialed_model(
                target,
                endpoint_url=target.token_count_url,
                payload=count_request,
                operation="token count",
            )
            input_tokens = _model_input_token_count(count_result)
        except ModelBrokerUpstreamError:
            self.audit.append(
                "model.upstream_error",
                {
                    "audience": target.audience,
                    "model_id": model_id,
                    "operation": "token_count",
                    "scope_id": scope_token.scope_id,
                    "budget_id": budget_token.budget_id,
                    "job_id": identity.job_id,
                },
            )
            raise

        max_output_tokens = _positive_int(model_request.get("max_tokens"), "request.max_tokens")
        reserved_tokens = input_tokens + max_output_tokens
        reserved_rollup = self._model_price_rollup(model_id=model_id, token_count=reserved_tokens)
        reserved_usage = reserved_rollup.usage
        try:
            self.quota.reserve(budget_token.budget_id, reserved_usage)
        except BudgetExceededError as exc:
            self.quota.halt(budget_token.budget_id, reason="model_reservation_exceeded")
            self._audit_model_budget_halt(
                scope_token=scope_token,
                budget_token=budget_token,
                model_id=model_id,
                reason="model_reservation_exceeded",
                requested_tokens=reserved_tokens,
            )
            raise BudgetExceededError("model call exceeds the remaining token or cost budget") from exc

        try:
            provider_response = self._call_credentialed_model(
                target,
                endpoint_url=target.completion_url,
                payload=model_request,
                operation="completion",
            )
            usage = _validated_model_usage(
                provider_response,
                expected_model_id=model_id,
                expected_input_tokens=input_tokens,
                max_output_tokens=max_output_tokens,
            )
        except ModelBrokerUpstreamError:
            self.quota.release(budget_token.budget_id, reserved_usage)
            self.quota.halt(budget_token.budget_id, reason="model_usage_untrusted")
            self._audit_model_budget_halt(
                scope_token=scope_token,
                budget_token=budget_token,
                model_id=model_id,
                reason="model_usage_untrusted",
                requested_tokens=reserved_tokens,
            )
            raise

        actual_rollup = self._model_price_rollup(model_id=model_id, token_count=usage["total_tokens"])
        try:
            self.quota.consume(budget_token.budget_id, actual_rollup.usage)
        except BudgetExceededError:
            self.quota.release(budget_token.budget_id, reserved_usage)
            self._audit_model_budget_halt(
                scope_token=scope_token,
                budget_token=budget_token,
                model_id=model_id,
                reason="provider_usage_exceeded_budget",
                requested_tokens=usage["total_tokens"],
            )
            raise
        self.quota.release(budget_token.budget_id, reserved_usage)

        try:
            provenance = self._persist_model_provenance(
                identity=identity,
                scope_token=scope_token,
                budget_token=budget_token,
                target=target,
                model_request=model_request,
                provider_response=provider_response,
                usage=usage,
                cost_usd_exact=actual_rollup.cost_usd_exact,
                price_table_hash=actual_rollup.price_table_hash,
            )
        except Exception as exc:
            self.quota.halt(budget_token.budget_id, reason="model_provenance_unavailable")
            self.audit.append(
                "model.provenance_error",
                {
                    "audience": target.audience,
                    "model_id": model_id,
                    "scope_id": scope_token.scope_id,
                    "budget_id": budget_token.budget_id,
                    "job_id": identity.job_id,
                    "usage": usage,
                    "budget_halted": True,
                },
            )
            raise ModelBrokerUpstreamError("model usage was debited but provenance persistence failed") from exc

        remaining = self.quota.remaining(budget_token.budget_id)
        self.audit.append(
            "model.complete",
            {
                "audience": target.audience,
                "model_id": model_id,
                "scope_id": scope_token.scope_id,
                "budget_id": budget_token.budget_id,
                "job_id": identity.job_id,
                "tokens_used": usage["total_tokens"],
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "cost_usd_exact": actual_rollup.cost_usd_exact,
                "provenance_ref": provenance.artifact_ref,
                "request_hash": hash_json(model_request),
                "response_hash": hash_json(provider_response),
            },
        )
        return {
            "response": provider_response,
            "usage": usage,
            "tokens_used": usage["total_tokens"],
            "cost_usd_exact": actual_rollup.cost_usd_exact,
            "price_table_version": actual_rollup.price_table_version,
            "price_table_hash": actual_rollup.price_table_hash,
            "provenance_ref": provenance.artifact_ref,
            "remaining": asdict(remaining),
            "budget_halted": False,
        }

    def _verified_budget_for_identity(
        self,
        identity: RuntimeIdentity,
        body: Mapping[str, Any],
    ) -> BudgetToken:
        _require_runtime_identity(identity)
        budget_token = _budget_token_from_dict(_required_dict(dict(body), "budget_token"))
        verification = self.tokens.verify_budget(budget_token)
        if not verification.valid:
            self.audit.append(
                "token.verify_fail",
                {
                    "token": "budget",
                    "reason": verification.reason,
                    "job_id": identity.job_id,
                },
            )
            raise TokenInvalidError(verification.reason or "invalid budget token")
        if budget_token.job_id != identity.job_id:
            raise PermissionError("budget token is not bound to the authenticated runtime identity")
        if budget_token.root_request_id != identity.root_request_id:
            raise PermissionError("budget token root request is not bound to the authenticated runtime identity")
        if budget_token.risk_class != identity.scopes.sandbox_risk_class:
            raise PermissionError("budget token risk class is not bound to the authenticated runtime identity")
        _require_budget_caps_subset(budget_token.caps, identity.budget_caps)
        return budget_token

    def _model_price_rollup(self, *, model_id: str, token_count: int) -> Any:
        if self.price_table is None or self.price_table_trust_store is None:
            raise PriceTableSignatureError("model broker price table is unavailable")
        self.price_table_trust_store.verify(self.price_table)
        return roll_up_price_table_usage(
            BudgetUsage(model_tokens=float(token_count)),
            self.price_table,
            model_id=model_id,
        )

    def _persist_model_provenance(
        self,
        *,
        identity: RuntimeIdentity,
        scope_token: ScopeToken,
        budget_token: BudgetToken,
        target: CredentialedModelTarget,
        model_request: dict[str, Any],
        provider_response: dict[str, Any],
        usage: dict[str, int],
        cost_usd_exact: str,
        price_table_hash: str,
    ) -> ArtifactRecord:
        self._refresh_artifacts()
        environment_digest = hash_json(
            {
                "schema": "argus.s10.llm-call-environment.v1",
                "model_id": target.model_id,
                "audience": target.audience,
                "price_table_version": self.price_table.price_table_version if self.price_table else None,
                "price_table_hash": price_table_hash,
            }
        )
        return self.artifacts.create_artifact(
            kind="llm_call",
            payload={
                "schema": "argus.s10.llm-call.v1",
                "job_id": identity.job_id,
                "scope_id": scope_token.scope_id,
                "budget_id": budget_token.budget_id,
                "budget_epoch": budget_token.budget_epoch,
                "model_id": target.model_id,
                "request": model_request,
                "response": provider_response,
                "usage": usage,
                "tokens_used": usage["total_tokens"],
                "cost_usd_exact": cost_usd_exact,
                "price_table_version": self.price_table.price_table_version if self.price_table else None,
                "price_table_hash": price_table_hash,
                "request_hash": hash_json(model_request),
                "response_hash": hash_json(provider_response),
            },
            producer=Producer(
                subsystem="S10",
                version="0.0.0",
                actor_id="s10-model-broker",
                job_id=identity.job_id,
            ),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:project-argus/s10-model-broker",
                environment_digest=environment_digest,
                actor_id=identity.caller_id,
                job_id=identity.job_id,
            ),
        )

    def _deny_model(self, scope_token: ScopeToken, *, model_id: str, reason: str) -> None:
        self.audit.append(
            "model.denied",
            {
                "audience": "model",
                "model_id": model_id,
                "reason": reason,
                "scope_id": scope_token.scope_id,
                "job_id": scope_token.job_id,
            },
        )
        raise ScopeDeniedError(reason)

    def _audit_model_budget_halt(
        self,
        *,
        scope_token: ScopeToken,
        budget_token: BudgetToken,
        model_id: str,
        reason: str,
        requested_tokens: int,
    ) -> None:
        state = self.quota.state(budget_token.budget_id)
        self.audit.append(
            "model.budget_halt",
            {
                "audience": "model",
                "model_id": model_id,
                "reason": reason,
                "scope_id": scope_token.scope_id,
                "budget_id": budget_token.budget_id,
                "job_id": budget_token.job_id,
                "requested_tokens": requested_tokens,
                "actual_model_tokens": state.actual.model_tokens,
                "actual_cost_usd": state.actual.cost_usd,
                "budget_halted": state.halted,
            },
        )

    @staticmethod
    def _call_credentialed_model(
        target: CredentialedModelTarget,
        *,
        endpoint_url: str,
        payload: Mapping[str, Any],
        operation: str,
    ) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            target.credential_header: target.credential,
            **dict(target.static_headers),
        }
        outbound = request.Request(
            endpoint_url,
            data=canonical_json_bytes(payload),
            method="POST",
            headers=headers,
        )
        try:
            with request.urlopen(outbound, timeout=target.timeout_s) as response:
                raw = response.read()
        except error.HTTPError as exc:
            raise ModelBrokerUpstreamError(
                f"model provider {operation} request failed with HTTP {exc.code}"
            ) from exc
        except OSError as exc:
            raise ModelBrokerUpstreamError(f"model provider {operation} endpoint is unavailable") from exc
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ModelBrokerUpstreamError(f"model provider {operation} returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise ModelBrokerUpstreamError(f"model provider {operation} returned a non-object response")
        if target.credential in json.dumps(result, sort_keys=True, ensure_ascii=False):
            raise ModelBrokerUpstreamError(f"model provider {operation} response contained credential material")
        return result

    def _verified_scope_for_identity(
        self,
        identity: RuntimeIdentity,
        body: Mapping[str, Any],
    ) -> ScopeToken:
        _require_runtime_identity(identity)
        scope_token = _scope_token_from_dict(_required_dict(body, "scope_token"))
        verification = self.tokens.verify_scope(scope_token)
        if not verification.valid:
            self.audit.append(
                "token.verify_fail",
                {
                    "token": "scope",
                    "reason": verification.reason,
                    "job_id": identity.job_id,
                },
            )
            raise TokenInvalidError(verification.reason or "invalid scope token")
        if scope_token.job_id != identity.job_id:
            raise PermissionError("scope token is not bound to the authenticated runtime identity")
        _require_scope_subset(scope_token.scopes, identity.scopes)
        return scope_token

    def _deny_adapter(self, scope_token: ScopeToken, *, adapter_id: str, reason: str) -> None:
        self.audit.append(
            "adapter.denied",
            {
                "audience": adapter_id,
                "adapter_id": adapter_id,
                "reason": reason,
                "scope_id": scope_token.scope_id,
                "job_id": scope_token.job_id,
            },
        )
        raise ScopeDeniedError(reason)

    @staticmethod
    def _call_credentialed_adapter(
        target: CredentialedAdapterTarget,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        outbound = request.Request(
            target.endpoint_url,
            data=canonical_json_bytes(payload),
            method="POST",
            headers={
                "Content-Type": "application/json",
                target.credential_header: target.credential,
            },
        )
        try:
            with request.urlopen(outbound, timeout=target.timeout_s) as response:
                raw = response.read()
        except error.HTTPError as exc:
            raise AdapterBrokerUpstreamError(
                f"adapter upstream rejected the broker request with HTTP {exc.code}"
            ) from exc
        except OSError as exc:
            raise AdapterBrokerUpstreamError("adapter upstream is unavailable") from exc
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterBrokerUpstreamError("adapter upstream returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise AdapterBrokerUpstreamError("adapter upstream returned a non-object response")
        if target.credential in json.dumps(result, sort_keys=True, ensure_ascii=False):
            raise AdapterBrokerUpstreamError("adapter upstream response contained broker credential material")
        return result

    def mint_runtime_identity_for_launcher(self, launcher: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        if not launcher.can_mint_runtime_identity:
            raise PermissionError("runtime identity minting requires bootstrap authentication")
        if self.auth is None:
            raise RuntimeError("runtime auth is not configured")
        if self.runtime_identity_mint_policy is None:
            raise PermissionError("runtime identity mint policy is not configured")
        identity = self.runtime_identity_mint_policy.identity_for_request(body)
        ttl_s = _identity_mint_ttl(body, identity.max_ttl_s)
        return self.auth.mint_identity_token(identity, ttl_s=ttl_s)

    def launch_sandbox_for_identity(self, identity: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        _require_runtime_identity(identity)
        launch = _launch_request_from_dict(body)
        _require_launch_identity_binding(identity, launch)
        self._refresh_artifacts()
        result = self._docker_orchestrator.launch_and_wait(launch)
        payload = asdict(result)
        halt_telemetry = self._docker_orchestrator.halt_telemetry_for(result.handle.sandbox_id)
        if halt_telemetry is not None:
            payload["halt_telemetry"] = halt_telemetry
        payload["audit_events"] = self._recent_audit_event_types()
        return payload

    def revoke_token_for_identity(self, identity: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        _require_runtime_identity(identity)
        token_type = _required_str(body, "token_type")
        token_body = _required_dict(body, "token")
        if token_type == "budget":
            token = _budget_token_from_dict(token_body)
            verification = self.tokens.verify_budget(token)
            if not verification.valid and verification.reason != "revoked":
                raise TokenInvalidError(verification.reason or "invalid budget token")
            if token.job_id != identity.job_id or token.root_request_id != identity.root_request_id:
                raise PermissionError("budget token is not bound to the authenticated runtime identity")
            token_id = token.budget_id
        elif token_type == "scope":
            token = _scope_token_from_dict(token_body)
            verification = self.tokens.verify_scope(token)
            if not verification.valid and verification.reason != "revoked":
                raise TokenInvalidError(verification.reason or "invalid scope token")
            if token.job_id != identity.job_id:
                raise PermissionError("scope token is not bound to the authenticated runtime identity")
            _require_scope_subset(token.scopes, identity.scopes)
            token_id = token.scope_id
        else:
            raise ValueError("token_type must be budget or scope")
        self.tokens.revoke(token_id)
        return {
            "revoked_token_id": token_id,
            "token_type": token_type,
            "revocation_store": self.tokens.revocation_store_kind,
        }

    def _build_docker_orchestrator(self) -> DockerSandboxOrchestrator:
        return DockerSandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            policy_service=self.policy_service,
            artifact_store=self.artifacts,
            supervisor=self._docker_supervisor,
            price_table=self.price_table,
            price_table_trust_store=self.price_table_trust_store,
        )

    def _refresh_artifacts(self) -> None:
        if self._artifact_store_path is not None:
            self.artifacts = FileSystemArtifactStore(self._artifact_store_path)
            self.broker = StoreWriterBroker(
                token_service=self.tokens,
                artifact_store=self.artifacts,
                audit_ledger=self.audit,
            )
            self._docker_orchestrator = self._build_docker_orchestrator()

    def _authenticate(self, request: JsonRequest) -> RuntimeIdentity:
        if self.auth is None:
            raise UnauthorizedError("runtime auth is not configured")
        return self.auth.authenticate(request)

    def _authenticate_health(self, request: JsonRequest) -> None:
        require_static_bearer_token(request, expected_token=self._health_token, purpose="health")

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(request: JsonRequest) -> tuple[int, Any]:
            try:
                self._authenticate_health(request)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            return 200, {
                "service": "s10-supervisor",
                "status": "ok",
                "policy_bundle_version": self.policy.bundle_version,
                "policy_signer_key_id": self.policy.signer_key_id,
                "exfil_soft_bytes": self.policy.exfil_thresholds.soft_bytes,
                "exfil_hard_bytes": self.policy.exfil_thresholds.hard_bytes,
                "checkpoint_signer": self.checkpoint_signer.kind if self.checkpoint_signer is not None else "unconfigured",
                "verifier_key_provider": "s10-kms" if self.verifier_key_provider is not None else "unconfigured",
                "verifier_key_epoch": self.verifier_key_provider.epoch if self.verifier_key_provider is not None else None,
                "token_signer": self.tokens.signer_kind,
                "token_signature_algorithm": self.tokens.signature_algorithm,
                "token_verifier": self.tokens.verifier_kind,
                "token_revocation_store": self.tokens.revocation_store_kind,
                "quota_ledger": getattr(self.quota, "kind", type(self.quota).__name__),
                "price_table": self._docker_orchestrator.price_table_version or "unconfigured",
                "price_table_signer_key_id": self._docker_orchestrator.price_table_signer_key_id or "unconfigured",
                "resource_meter": self._docker_supervisor.resource_meter_kind,
                "meter_interval_s": self._docker_supervisor.meter_interval_s,
                "meter_gap_halt_s": self._docker_supervisor.meter_gap_halt_s,
                "dcgm_available": self._docker_supervisor.dcgm_available,
                "nvidia_smi_available": self._docker_supervisor.nvidia_smi_available,
                "gpu_count": self._docker_supervisor.gpu_count,
                "gpu_models": list(self._docker_supervisor.gpu_models),
                "mig_enabled": self._docker_supervisor.mig_enabled,
                "mig_instance_count": self._docker_supervisor.mig_instance_count,
                "gpu_telemetry_source": self._docker_supervisor.gpu_telemetry_source,
                "dcgm_metric_sampler_enabled": self._docker_supervisor.dcgm_metric_sampler_enabled,
                "dcgm_metric_fields": list(self._docker_supervisor.dcgm_metric_fields),
                "gvisor_configured": self._docker_supervisor.gvisor_configured,
                "gvisor_docker_runtime": self._docker_supervisor.gvisor_docker_runtime or "unconfigured",
                "firecracker_configured": self._docker_supervisor.firecracker_configured,
                "firecracker_version": self._docker_supervisor.firecracker_version or "unconfigured",
                "firecracker_resource_meter": (
                    self._docker_supervisor.firecracker_resource_meter_kind or "unconfigured"
                ),
                "egress_sidecar_configured": self._docker_supervisor.egress_sidecar_configured,
                "secrets_broker_configured": bool(self._adapter_targets),
                "adapter_broker_targets": sorted(self._adapter_targets),
                "model_broker_configured": bool(self._model_targets),
                "model_broker_targets": sorted(self._model_targets),
                "audit_events": len(self.audit.events()),
            }

        @self.http.route("POST", "/v1/runtime-identities")
        def runtime_identity(request: JsonRequest) -> tuple[int, Any]:
            try:
                launcher = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.mint_runtime_identity_for_launcher(launcher, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except IdentityOverrideError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/budget-tokens")
        def budget(request: JsonRequest) -> tuple[int, Any]:
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.mint_budget_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except IdentityOverrideError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/scope-tokens")
        def scope(request: JsonRequest) -> tuple[int, Any]:
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.mint_scope_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except IdentityOverrideError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/internal/s8-checkpoint-signatures")
        def checkpoint_signature(request: JsonRequest) -> tuple[int, Any]:
            try:
                self._authenticate_checkpoint_signer(request)
                if self.checkpoint_signer is None:
                    raise PermissionError("checkpoint signer is not configured")
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                signature = self.checkpoint_signer.sign_checkpoint(
                    sequence=int(request.body.get("sequence")),
                    root=_required_str(request.body, "root"),
                )
                return 201, asdict(signature)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("GET", "/v1/internal/verifier-keys")
        def verifier_key_snapshot(request: JsonRequest) -> tuple[int, Any]:
            try:
                self._authenticate_verifier_key_store(request)
                if self.verifier_key_provider is None:
                    raise PermissionError("verifier key provider is not configured")
                epoch, keys = self.verifier_key_provider.snapshot()
                return 200, {
                    "provider": "s10-kms",
                    "epoch": epoch,
                    "keys": [asdict(key) for key in keys],
                }
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/internal/verifier-keys:verify")
        def verifier_key_verify(request: JsonRequest) -> tuple[int, Any]:
            try:
                self._authenticate_verifier_key_store(request)
                if self.verifier_key_provider is None:
                    raise PermissionError("verifier key provider is not configured")
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                result = self.verifier_key_provider.verify_signature_value(
                    key_id=_required_str(request.body, "key_id"),
                    report_with_empty_signature=_required_dict(request.body, "report_with_empty_signature"),
                    signature_value=_required_str(request.body, "signature_value"),
                )
                return 200, {"result": result or "signature_abstain"}
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/store/artifacts")
        def store_artifact(request: JsonRequest) -> tuple[int, Any]:
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.broker_put_artifact_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except TokenInvalidError as exc:
                return 401, {"error": type(exc).__name__, "message": str(exc)}
            except ScopeDeniedError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/broker/store/put")
        def broker_store_put(request: JsonRequest) -> tuple[int, Any]:
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.broker_put_artifact_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except TokenInvalidError as exc:
                return 401, {"error": type(exc).__name__, "message": str(exc)}
            except (PermissionError, ScopeDeniedError) as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/broker/store/get")
        def broker_store_get(request: JsonRequest) -> tuple[int, Any]:
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 200, self.broker_get_artifact_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except TokenInvalidError as exc:
                return 401, {"error": type(exc).__name__, "message": str(exc)}
            except (PermissionError, ScopeDeniedError) as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except KeyError as exc:
                return 404, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.prefix("POST", "/v1/broker/adapter/")
        def broker_adapter_evaluate(request: JsonRequest) -> tuple[int, Any]:
            suffix = request.path.removeprefix("/v1/broker/adapter/")
            if not suffix.endswith("/evaluate"):
                return 404, {"error": "not_found"}
            adapter_id = suffix.removesuffix("/evaluate")
            if not adapter_id or "/" in adapter_id:
                return 404, {"error": "not_found"}
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 200, self.broker_evaluate_adapter_for_identity(
                    identity,
                    adapter_id=adapter_id,
                    body=request.body,
                )
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except TokenInvalidError as exc:
                return 401, {"error": type(exc).__name__, "message": str(exc)}
            except (PermissionError, ScopeDeniedError) as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except AdapterBrokerUpstreamError as exc:
                return 502, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/broker/model/complete")
        def broker_model_complete(request: JsonRequest) -> tuple[int, Any]:
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 200, self.broker_complete_model_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except TokenInvalidError as exc:
                return 401, {"error": type(exc).__name__, "message": str(exc)}
            except BudgetExceededError as exc:
                return 403, {
                    "error": type(exc).__name__,
                    "message": str(exc),
                    "budget_halted": True,
                }
            except (PermissionError, PriceTableSignatureError, ScopeDeniedError) as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except ModelBrokerUpstreamError as exc:
                return 502, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/tokens:revoke")
        def revoke_token(request: JsonRequest) -> tuple[int, Any]:
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 200, self.revoke_token_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except TokenInvalidError as exc:
                return 401, {"error": type(exc).__name__, "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/sandboxes:launch")
        def launch_sandbox(request: JsonRequest) -> tuple[int, Any]:
            launch: LaunchRequest | None = None
            try:
                identity = self._authenticate(request)
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                launch = _launch_request_from_dict(request.body)
                return 201, self.launch_sandbox_for_identity(identity, request.body)
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            except TokenInvalidError as exc:
                return 401, {"error": type(exc).__name__, "message": str(exc)}
            except (
                BudgetExceededError,
                PermissionError,
                PolicyDeniedError,
                PriceTableSignatureError,
                ScopeDeniedError,
            ) as exc:
                return 403, self._launch_error_payload(exc, launch)
            except SandboxRuntimeUnavailableError as exc:
                return 503, self._launch_error_payload(exc, launch)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

    def _authenticate_checkpoint_signer(self, request: JsonRequest) -> None:
        require_static_bearer_token(
            request,
            expected_token=self._checkpoint_signer_auth_token,
            purpose="checkpoint signer",
        )

    def _authenticate_verifier_key_store(self, request: JsonRequest) -> None:
        require_static_bearer_token(
            request,
            expected_token=self._verifier_key_auth_token,
            purpose="verifier key store",
        )

    def _launch_error_payload(self, exc: Exception, launch: LaunchRequest | None) -> dict[str, Any]:
        handle = None
        ceiling_reject = None
        if launch is not None:
            handles = [
                asdict(candidate)
                for candidate in self._docker_orchestrator._handles.values()
                if candidate.job_id == launch.job_id
            ]
            if handles:
                handle = handles[-1]
            ceiling_reject = next(
                (
                    dict(event.payload)
                    for event in reversed(self.audit.events())
                    if event.event_type == "ceiling.reject" and event.payload.get("job_id") == launch.job_id
                ),
                None,
            )
        payload = {
            "error": type(exc).__name__,
            "message": str(exc),
            "handle": handle,
            "audit_events": self._audit_event_types_for_job(launch.job_id)
            if launch is not None
            else self._recent_audit_event_types(),
        }
        if ceiling_reject is not None:
            payload["ceiling_reject"] = ceiling_reject
        return payload

    def _recent_audit_event_types(self, *, limit: int = 12) -> list[str]:
        return [event.event_type for event in self.audit.events()[-limit:]]

    def _audit_event_types_for_job(self, job_id: str, *, limit: int = 12) -> list[str]:
        return [
            event.event_type
            for event in self.audit.events()
            if event.payload.get("job_id") == job_id
        ][-limit:]


def build_app_from_env() -> S10SupervisorApp:
    token_service = _token_service_from_env()
    quota_ledger = _quota_ledger_from_env()
    price_table, price_table_trust_store = _price_table_from_env()
    docker_supervisor = _docker_supervisor_from_env()
    s8_broker_url = os.environ.get("ARGUS_S8_BROKER_URL")
    s8_broker_key = os.environ.get("ARGUS_S8_BROKER_WRITE_KEY")
    mint_policy = _runtime_identity_mint_policy_from_env()
    health_token = health_token_from_env()
    policy_service = _policy_service_from_env()
    checkpoint_signer = _checkpoint_signer_from_env()
    checkpoint_signer_auth_token = _required_env("ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN")
    verifier_key_provider = _verifier_key_provider_from_env()
    verifier_key_auth_token = os.environ.get("ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN")
    adapter_targets = _adapter_targets_from_env()
    model_targets = _model_targets_from_env()
    if verifier_key_provider is not None and not verifier_key_auth_token:
        raise RuntimeError("ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN is required when verifier keys are configured")
    if s8_broker_url:
        if not s8_broker_key:
            raise RuntimeError("ARGUS_S8_BROKER_WRITE_KEY is required when ARGUS_S8_BROKER_URL is configured")
        return S10SupervisorApp(
            token_service=token_service,
            quota_ledger=quota_ledger,
            artifact_store=S8BrokeredArtifactStoreClient(
                endpoint_url=s8_broker_url,
                broker_write_key=s8_broker_key.encode("utf-8"),
            ),
            auth=runtime_auth_from_env(),
            runtime_identity_mint_policy=mint_policy,
            health_token=health_token,
            policy_service=policy_service,
            checkpoint_signer=checkpoint_signer,
            checkpoint_signer_auth_token=checkpoint_signer_auth_token,
            verifier_key_provider=verifier_key_provider,
            verifier_key_auth_token=verifier_key_auth_token,
            docker_supervisor=docker_supervisor,
            price_table=price_table,
            price_table_trust_store=price_table_trust_store,
            adapter_targets=adapter_targets,
            model_targets=model_targets,
        )
    data_dir = os.environ.get("ARGUS_S8_DATA_DIR")
    if data_dir:
        return S10SupervisorApp(
            token_service=token_service,
            quota_ledger=quota_ledger,
            artifact_store=FileSystemArtifactStore(data_dir),
            artifact_store_path=data_dir,
            auth=runtime_auth_from_env(),
            runtime_identity_mint_policy=mint_policy,
            health_token=health_token,
            policy_service=policy_service,
            checkpoint_signer=checkpoint_signer,
            checkpoint_signer_auth_token=checkpoint_signer_auth_token,
            verifier_key_provider=verifier_key_provider,
            verifier_key_auth_token=verifier_key_auth_token,
            docker_supervisor=docker_supervisor,
            price_table=price_table,
            price_table_trust_store=price_table_trust_store,
            adapter_targets=adapter_targets,
            model_targets=model_targets,
        )
    return S10SupervisorApp(
        token_service=token_service,
        quota_ledger=quota_ledger,
        auth=runtime_auth_from_env(),
        runtime_identity_mint_policy=mint_policy,
        health_token=health_token,
        policy_service=policy_service,
        checkpoint_signer=checkpoint_signer,
        checkpoint_signer_auth_token=checkpoint_signer_auth_token,
        verifier_key_provider=verifier_key_provider,
        verifier_key_auth_token=verifier_key_auth_token,
        docker_supervisor=docker_supervisor,
        price_table=price_table,
        price_table_trust_store=price_table_trust_store,
        adapter_targets=adapter_targets,
        model_targets=model_targets,
    )


def main() -> None:
    host = os.environ.get("ARGUS_S10_HOST", "127.0.0.1")
    port = int(os.environ.get("ARGUS_S10_PORT", "8080"))
    serve_json_app(build_app_from_env().http, host=host, port=port)


def _token_service_from_env() -> InMemoryTokenService:
    revocation_store = _token_revocation_store_from_env()
    mode = os.environ.get("ARGUS_S10_TOKEN_SIGNING_MODE", "hmac-sha256").strip().lower()
    signer_key_id = os.environ.get("ARGUS_S10_TOKEN_SIGNER_KEY_ID", "s10-test-key")
    if mode in {"hmac", "hmac-sha256"}:
        key_file = os.environ.get("ARGUS_S10_SIGNING_KEY_FILE")
        if key_file:
            signing_key = Path(key_file).read_bytes()
        else:
            signing_key_value = os.environ.get("ARGUS_S10_SIGNING_KEY")
            if not signing_key_value:
                raise RuntimeError("ARGUS_S10_SIGNING_KEY or ARGUS_S10_SIGNING_KEY_FILE is required")
            signing_key = signing_key_value.encode("utf-8")
        return InMemoryTokenService(
            signing_key=signing_key,
            signer_key_id=signer_key_id,
            revocation_store=revocation_store,
        )
    if mode == "ed25519":
        private_key = _read_hex_secret(
            value_name="ARGUS_S10_TOKEN_ED25519_PRIVATE_KEY_HEX",
            file_name="ARGUS_S10_TOKEN_ED25519_PRIVATE_KEY_HEX_FILE",
            expected_bytes=32,
        )
        public_key = _read_hex_secret(
            value_name="ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX",
            file_name="ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX_FILE",
            expected_bytes=32,
        )
        signer = Ed25519KmsTokenSigner(signer_key_id=signer_key_id, private_key_bytes=private_key)
        if signer.public_key_bytes != public_key:
            raise RuntimeError("ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX does not match private key")
        return InMemoryTokenService(
            signer=signer,
            verifier=TokenSignatureTrustStore(ed25519_public_keys={signer_key_id: public_key}),
            revocation_store=revocation_store,
        )
    raise RuntimeError("ARGUS_S10_TOKEN_SIGNING_MODE must be hmac-sha256 or ed25519")


def _adapter_targets_from_env() -> dict[str, CredentialedAdapterTarget]:
    raw = os.environ.get("ARGUS_S10_ADAPTER_TARGETS_JSON")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ARGUS_S10_ADAPTER_TARGETS_JSON must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("ARGUS_S10_ADAPTER_TARGETS_JSON must be an object map")
    targets: dict[str, CredentialedAdapterTarget] = {}
    for adapter_id, value in parsed.items():
        if not isinstance(adapter_id, str) or not adapter_id or not isinstance(value, dict):
            raise RuntimeError("adapter target entries must map non-empty ids to objects")
        endpoint_url = value.get("endpoint_url")
        credential_env = value.get("credential_env")
        credential_header = value.get("credential_header", "X-Argus-Adapter-Credential")
        if not isinstance(endpoint_url, str) or not endpoint_url:
            raise RuntimeError(f"adapter target {adapter_id} requires endpoint_url")
        if not isinstance(credential_env, str) or not credential_env:
            raise RuntimeError(f"adapter target {adapter_id} requires credential_env")
        credential = os.environ.get(credential_env)
        if not credential:
            raise RuntimeError(f"adapter target {adapter_id} credential env is unavailable: {credential_env}")
        if not isinstance(credential_header, str):
            raise RuntimeError(f"adapter target {adapter_id} credential_header must be a string")
        try:
            targets[adapter_id] = CredentialedAdapterTarget(
                adapter_id=adapter_id,
                endpoint_url=endpoint_url,
                credential_header=credential_header,
                credential=credential,
                timeout_s=float(value.get("timeout_s", 10.0)),
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid adapter target {adapter_id}: {exc}") from exc
    return targets


def _model_targets_from_env() -> dict[str, CredentialedModelTarget]:
    raw = os.environ.get("ARGUS_S10_MODEL_TARGETS_JSON")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ARGUS_S10_MODEL_TARGETS_JSON must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("ARGUS_S10_MODEL_TARGETS_JSON must be an object map")
    targets: dict[str, CredentialedModelTarget] = {}
    for model_id, value in parsed.items():
        if not isinstance(model_id, str) or not model_id or not isinstance(value, dict):
            raise RuntimeError("model target entries must map non-empty ids to objects")
        completion_url = value.get("completion_url")
        token_count_url = value.get("token_count_url")
        credential_env = value.get("credential_env")
        credential_header = value.get("credential_header", "X-Api-Key")
        static_headers = value.get("static_headers", {})
        if not isinstance(completion_url, str) or not completion_url:
            raise RuntimeError(f"model target {model_id} requires completion_url")
        if not isinstance(token_count_url, str) or not token_count_url:
            raise RuntimeError(f"model target {model_id} requires token_count_url")
        if not isinstance(credential_env, str) or not credential_env:
            raise RuntimeError(f"model target {model_id} requires credential_env")
        credential = os.environ.get(credential_env)
        if not credential:
            raise RuntimeError(f"model target {model_id} credential env is unavailable: {credential_env}")
        if not isinstance(credential_header, str):
            raise RuntimeError(f"model target {model_id} credential_header must be a string")
        if not isinstance(static_headers, dict) or any(
            not isinstance(name, str) or not isinstance(header_value, str)
            for name, header_value in static_headers.items()
        ):
            raise RuntimeError(f"model target {model_id} static_headers must map strings to strings")
        audience = value.get("audience", "model")
        if not isinstance(audience, str):
            raise RuntimeError(f"model target {model_id} audience must be a string")
        try:
            targets[model_id] = CredentialedModelTarget(
                model_id=model_id,
                completion_url=completion_url,
                token_count_url=token_count_url,
                credential_header=credential_header,
                credential=credential,
                static_headers=static_headers,
                audience=audience,
                timeout_s=float(value.get("timeout_s", 30.0)),
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid model target {model_id}: {exc}") from exc
    return targets


def _token_revocation_store_from_env() -> FileTokenRevocationStore | None:
    path = os.environ.get("ARGUS_S10_TOKEN_REVOCATION_STORE_PATH")
    if not path:
        return None
    return FileTokenRevocationStore(path)


def _docker_supervisor_from_env() -> DockerSandboxSupervisor:
    meter_interval_s = _positive_float_env("ARGUS_S10_METER_INTERVAL_S", 1.0)
    firecracker_config = _firecracker_runtime_config_from_env()
    return DockerSandboxSupervisor(
        meter_interval_s=meter_interval_s,
        meter_gap_halt_s=_positive_float_env("ARGUS_S10_METER_GAP_HALT_S", 5.0),
        gvisor_config=_gvisor_runtime_config_from_env(),
        firecracker_supervisor=(
            FirecrackerSandboxSupervisor(config=firecracker_config, meter_interval_s=meter_interval_s)
            if firecracker_config is not None
            else None
        ),
        egress_sidecar_config=_egress_sidecar_runtime_config_from_env(),
    )


def _egress_sidecar_runtime_config_from_env() -> EgressSidecarRuntimeConfig | None:
    image = os.environ.get("ARGUS_S10_EGRESS_SIDECAR_IMAGE")
    if not image:
        return None
    dns_servers = tuple(
        value.strip()
        for value in os.environ.get("ARGUS_S10_EGRESS_DNS_SERVERS", "").split(",")
        if value.strip()
    )
    return EgressSidecarRuntimeConfig(
        image=image,
        network_mode=os.environ.get("ARGUS_S10_EGRESS_NETWORK_MODE", "bridge"),
        proxy_port=int(os.environ.get("ARGUS_S10_EGRESS_LISTEN_PORT", "15001")),
        proxy_uid=int(os.environ.get("ARGUS_S10_EGRESS_PROXY_UID", "65531")),
        proxy_gid=int(os.environ.get("ARGUS_S10_EGRESS_PROXY_GID", "65531")),
        sandbox_uid=int(os.environ.get("ARGUS_S10_SANDBOX_UID", "65532")),
        dns_servers=dns_servers,
        dns_port=int(os.environ.get("ARGUS_S10_EGRESS_DNS_PORT", "53")),
        startup_timeout_s=_positive_float_env("ARGUS_S10_EGRESS_STARTUP_TIMEOUT_S", 5.0),
        memory_bytes=int(os.environ.get("ARGUS_S10_EGRESS_MEMORY_BYTES", str(64 * 1024 * 1024))),
        pids=int(os.environ.get("ARGUS_S10_EGRESS_PIDS", "64")),
    )


def _gvisor_runtime_config_from_env() -> GvisorRuntimeConfig | None:
    runtime_name = os.environ.get("ARGUS_S10_GVISOR_RUNTIME_NAME")
    profile_path = os.environ.get("ARGUS_S10_GVISOR_SECCOMP_PROFILE_PATH")
    trust_mounts_raw = os.environ.get("ARGUS_S10_GVISOR_TRUST_MOUNTS_JSON")
    configured_values = (runtime_name, profile_path, trust_mounts_raw)
    if all(value is None or value.strip() == "" for value in configured_values):
        return None
    if any(value is None or value.strip() == "" for value in configured_values):
        raise RuntimeError(
            "ARGUS_S10_GVISOR_RUNTIME_NAME, ARGUS_S10_GVISOR_SECCOMP_PROFILE_PATH, and "
            "ARGUS_S10_GVISOR_TRUST_MOUNTS_JSON must be configured together"
        )
    assert runtime_name is not None and profile_path is not None and trust_mounts_raw is not None
    try:
        parsed = json.loads(trust_mounts_raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ARGUS_S10_GVISOR_TRUST_MOUNTS_JSON must be valid JSON") from exc
    if not isinstance(parsed, list) or not parsed:
        raise RuntimeError("ARGUS_S10_GVISOR_TRUST_MOUNTS_JSON must be a non-empty array")
    mounts: list[TrustMount] = []
    for item in parsed:
        if not isinstance(item, dict):
            raise RuntimeError("ARGUS_S10_GVISOR_TRUST_MOUNTS_JSON entries must be objects")
        try:
            mounts.append(
                TrustMount(
                    name=str(item["name"]),
                    source=str(item["source"]),
                    target=str(item["target"]),
                )
            )
        except (KeyError, ValueError) as exc:
            raise RuntimeError(f"invalid gVisor trust mount: {exc}") from exc
    try:
        return GvisorRuntimeConfig(
            docker_runtime=runtime_name,
            seccomp_profile_path=profile_path,
            kubernetes_runtime_class=os.environ.get("ARGUS_S10_GVISOR_KUBERNETES_RUNTIME_CLASS", "gvisor"),
            kubernetes_seccomp_profile=os.environ.get(
                "ARGUS_S10_GVISOR_KUBERNETES_SECCOMP_PROFILE",
                "argus/argus-gvisor-seccomp.json",
            ),
            trust_mounts=tuple(mounts),
        )
    except ValueError as exc:
        raise RuntimeError(f"invalid gVisor runtime configuration: {exc}") from exc


def _firecracker_runtime_config_from_env() -> FirecrackerRuntimeConfig | None:
    names = (
        "ARGUS_S10_FIRECRACKER_VERSION",
        "ARGUS_S10_FIRECRACKER_KUBERNETES_RUNTIME_CLASS",
        "ARGUS_S10_FIRECRACKER_BIN",
        "ARGUS_S10_FIRECRACKER_JAILER_BIN",
        "ARGUS_S10_FIRECRACKER_KERNEL_PATH",
        "ARGUS_S10_FIRECRACKER_KERNEL_HASH",
        "ARGUS_S10_FIRECRACKER_ROOTFS_PATH",
        "ARGUS_S10_FIRECRACKER_ROOTFS_HASH",
        "ARGUS_S10_FIRECRACKER_ROOTFS_IMAGE_REF",
        "ARGUS_S10_FIRECRACKER_CHROOT_BASE",
        "ARGUS_S10_FIRECRACKER_JAILER_UID",
        "ARGUS_S10_FIRECRACKER_JAILER_GID",
    )
    values = {name: os.environ.get(name) for name in names}
    configured = {name: value for name, value in values.items() if value is not None and value.strip()}
    if not configured:
        return None
    if len(configured) != len(names):
        missing = ", ".join(name for name in names if name not in configured)
        raise RuntimeError(f"Firecracker runtime variables must be configured together; missing: {missing}")
    try:
        return FirecrackerRuntimeConfig(
            expected_version=str(values["ARGUS_S10_FIRECRACKER_VERSION"]),
            kubernetes_runtime_class=str(
                values["ARGUS_S10_FIRECRACKER_KUBERNETES_RUNTIME_CLASS"]
            ),
            firecracker_bin=str(values["ARGUS_S10_FIRECRACKER_BIN"]),
            jailer_bin=str(values["ARGUS_S10_FIRECRACKER_JAILER_BIN"]),
            kernel_image_path=str(values["ARGUS_S10_FIRECRACKER_KERNEL_PATH"]),
            kernel_image_hash=str(values["ARGUS_S10_FIRECRACKER_KERNEL_HASH"]),
            rootfs_image_path=str(values["ARGUS_S10_FIRECRACKER_ROOTFS_PATH"]),
            rootfs_image_hash=str(values["ARGUS_S10_FIRECRACKER_ROOTFS_HASH"]),
            rootfs_image_ref=str(values["ARGUS_S10_FIRECRACKER_ROOTFS_IMAGE_REF"]),
            chroot_base_dir=str(values["ARGUS_S10_FIRECRACKER_CHROOT_BASE"]),
            jailer_uid=int(str(values["ARGUS_S10_FIRECRACKER_JAILER_UID"])),
            jailer_gid=int(str(values["ARGUS_S10_FIRECRACKER_JAILER_GID"])),
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"invalid Firecracker runtime configuration: {exc}") from exc


def _positive_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive finite float") from exc
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError(f"{name} must be a positive finite float")
    return value


def _quota_ledger_from_env() -> Any:
    if not os.environ.get("ARGUS_S10_QUOTA_POSTGRES_DSN"):
        return InMemoryQuotaLedger()
    from .s10_quota_persistence import build_postgres_quota_ledger_from_env

    return build_postgres_quota_ledger_from_env(dict(os.environ))


def _price_table_from_env() -> tuple[PriceTable | None, PriceTableTrustStore | None]:
    key_file = os.environ.get("ARGUS_S10_PRICE_TABLE_SIGNING_KEY_FILE")
    signing_key_value = os.environ.get("ARGUS_S10_PRICE_TABLE_SIGNING_KEY")
    if not key_file and not signing_key_value:
        return None, None
    if key_file:
        signing_key = Path(key_file).read_bytes()
    else:
        assert signing_key_value is not None
        signing_key = signing_key_value.encode("utf-8")
    expires_at = os.environ.get("ARGUS_S10_PRICE_TABLE_EXPIRES_AT")
    if not expires_at:
        raise RuntimeError("ARGUS_S10_PRICE_TABLE_EXPIRES_AT is required when price table signing is configured")
    signer = PriceTableSigner(
        signer_key_id=os.environ.get("ARGUS_S10_PRICE_TABLE_SIGNER_KEY_ID", "argus-m0-price-table"),
        signing_key=signing_key,
    )
    table = PriceTable(
        price_table_version=os.environ.get("ARGUS_S10_PRICE_TABLE_VERSION", "0.1.0"),
        usd_per_cpu_second=os.environ.get("ARGUS_S10_PRICE_TABLE_USD_PER_CPU_SECOND", "0"),
        usd_per_gpu_second={"default": os.environ.get("ARGUS_S10_PRICE_TABLE_USD_PER_GPU_SECOND", "0")},
        usd_per_1k_model_tokens={
            "default": os.environ.get("ARGUS_S10_PRICE_TABLE_USD_PER_1K_MODEL_TOKENS", "0")
        },
        issued_at=int(os.environ.get("ARGUS_S10_PRICE_TABLE_ISSUED_AT", "0")),
        expires_at=int(expires_at),
    )
    signed = signer.sign(table)
    trust_store = signer.trust_store()
    trust_store.verify(signed)
    return signed, trust_store


def _read_hex_secret(*, value_name: str, file_name: str, expected_bytes: int) -> bytes:
    file_path = os.environ.get(file_name)
    if file_path:
        raw = Path(file_path).read_text(encoding="utf-8").strip()
    else:
        raw = os.environ.get(value_name, "").strip()
    if not raw:
        raise RuntimeError(f"{value_name} or {file_name} is required")
    try:
        value = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError(f"{value_name} must be lowercase hex") from exc
    if raw != value.hex() or len(value) != expected_bytes:
        raise RuntimeError(f"{value_name} must be {expected_bytes} raw bytes encoded as lowercase hex")
    return value


def _default_policy_bundle() -> PolicyBundle:
    runtime_class = os.environ.get("ARGUS_S10_DEFAULT_RUNTIME_CLASS", "docker")
    if runtime_class not in {"docker", "gvisor"}:
        raise RuntimeError("ARGUS_S10_DEFAULT_RUNTIME_CLASS must be docker or gvisor")
    seccomp_profile_hash = "blake3:" + "0" * 64
    if runtime_class == "gvisor":
        profile_path = os.environ.get("ARGUS_S10_GVISOR_SECCOMP_PROFILE_PATH")
        if not profile_path:
            raise RuntimeError("gVisor default runtime requires ARGUS_S10_GVISOR_SECCOMP_PROFILE_PATH")
        try:
            seccomp_profile_hash = hash_bytes(Path(profile_path).read_bytes())
        except OSError as exc:
            raise RuntimeError("gVisor seccomp profile is unavailable") from exc
    return PolicyBundle(
        bundle_version="argus-m0-dev",
        egress_allowlist=(),
        exfil_thresholds=ExfilThresholds(
            soft_bytes=int(os.environ.get("ARGUS_S10_EXFIL_SOFT_BYTES", str(64 * 1024 * 1024))),
            hard_bytes=int(os.environ.get("ARGUS_S10_EXFIL_HARD_BYTES", str(128 * 1024 * 1024))),
        ),
        resource_ceilings=ResourceCeilings(
            cpu_m=1_000,
            mem_bytes=128 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=30,
            max_cost_usd=1,
        ),
        risk_to_runtime={"standard": runtime_class},
        seccomp_profile_hash=seccomp_profile_hash,
        signer_key_id="",
        signature="",
    )


def _default_policy_service() -> InMemoryPolicyService:
    return _policy_service_from_signing_key(
        b"argus-m0-dev-policy-signing-key",
        signer_key_id="argus-m0-dev-policy",
    )


def _policy_service_from_env() -> InMemoryPolicyService:
    key_file = os.environ.get("ARGUS_S10_POLICY_SIGNING_KEY_FILE")
    if key_file:
        signing_key = Path(key_file).read_bytes()
    else:
        signing_key_value = os.environ.get("ARGUS_S10_POLICY_SIGNING_KEY")
        if not signing_key_value:
            raise RuntimeError("ARGUS_S10_POLICY_SIGNING_KEY or ARGUS_S10_POLICY_SIGNING_KEY_FILE is required")
        signing_key = signing_key_value.encode("utf-8")
    return _policy_service_from_signing_key(
        signing_key,
        signer_key_id=os.environ.get("ARGUS_S10_POLICY_SIGNER_KEY_ID", "argus-m0-policy"),
    )


def _policy_service_from_signing_key(signing_key: bytes, *, signer_key_id: str) -> InMemoryPolicyService:
    signed_bundle = PolicyBundleSigner(key_id=signer_key_id, secret=signing_key).sign(_default_policy_bundle())
    return InMemoryPolicyService(
        initial_bundle=signed_bundle,
        trust_store=InMemoryPolicyBundleTrustStore({signer_key_id: signing_key}),
    )


def _checkpoint_signer_from_env() -> InMemoryS10KmsCheckpointSigner:
    key_file = os.environ.get("ARGUS_S10_CHECKPOINT_SIGNING_KEY_FILE")
    if key_file:
        signing_key = Path(key_file).read_bytes()
    else:
        signing_key_value = os.environ.get("ARGUS_S10_CHECKPOINT_SIGNING_KEY")
        if not signing_key_value:
            raise RuntimeError("ARGUS_S10_CHECKPOINT_SIGNING_KEY or ARGUS_S10_CHECKPOINT_SIGNING_KEY_FILE is required")
        signing_key = signing_key_value.encode("utf-8")
    return InMemoryS10KmsCheckpointSigner(
        signer_key_id=os.environ.get("ARGUS_S10_CHECKPOINT_SIGNER_KEY_ID", "argus-m0-s8-checkpoint"),
        signing_key=signing_key,
    )


def _verifier_key_provider_from_env() -> InMemoryS10KmsVerifierKeyProvider | None:
    raw_keys = os.environ.get("ARGUS_S10_C3_VERIFIER_KEYS_JSON")
    if not raw_keys:
        return None
    try:
        parsed = json.loads(raw_keys)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ARGUS_S10_C3_VERIFIER_KEYS_JSON must be valid JSON") from exc
    provider = InMemoryS10KmsVerifierKeyProvider()
    for key in _verifier_key_items(parsed, env_name="ARGUS_S10_C3_VERIFIER_KEYS_JSON"):
        provider.register_verifier_key(key["key_id"], key["secret"].encode("utf-8"))
        if key.get("revoked"):
            provider.revoke_verifier_key(key["key_id"])
    return provider


def _verifier_key_items(value: Any, *, env_name: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        if all(isinstance(secret, str) for secret in value.values()):
            return [{"key_id": str(key_id), "secret": secret} for key_id, secret in value.items()]
        keys = value.get("keys")
        if isinstance(keys, list):
            value = keys
    if not isinstance(value, list):
        raise RuntimeError(f"{env_name} must be an object map or a list of key objects")
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise RuntimeError("verifier key entries must be objects")
        key_id = item.get("key_id")
        secret = item.get("secret")
        if not isinstance(key_id, str) or not key_id:
            raise RuntimeError("verifier key entry key_id is required")
        if not isinstance(secret, str) or not secret:
            raise RuntimeError("verifier key entry secret is required")
        items.append({"key_id": key_id, "secret": secret, "revoked": bool(item.get("revoked", False))})
    return items


class S8BrokeredArtifactStoreClient:
    def __init__(self, *, endpoint_url: str, broker_write_key: bytes) -> None:
        self._endpoint_url = endpoint_url
        self._read_endpoint_url = endpoint_url + ":get"
        self._broker_write_key = broker_write_key

    def create_brokered_artifact(
        self,
        *,
        scope_token: ScopeToken,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        artifact_ref: str | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> ArtifactRecord:
        body = {
            "authorization": {
                "audience": "store",
                "scope_id": scope_token.scope_id,
                "scope_job_id": scope_token.job_id,
                "producer_subsystems": list(scope_token.scopes.producer_subsystems),
            },
            "kind": kind,
            "payload": payload,
            "producer": asdict(producer),
            "lineage": asdict(lineage),
            "artifact_ref": artifact_ref,
            "claim_tier": claim_tier,
            "validation_report_ref": validation_report_ref,
        }
        encoded = canonical_json_bytes(body)
        signature = "hmac-sha256:" + hmac.new(self._broker_write_key, canonical_json_bytes(body), sha256).hexdigest()
        http_request = request.Request(
            self._endpoint_url,
            data=encoded,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Argus-Store-Write-Signature": signature,
            },
        )
        try:
            with request.urlopen(http_request, timeout=10) as response:
                response_body = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            response_body = json.loads(exc.read().decode("utf-8"))
            _raise_s8_http_error(response_body)
        return _artifact_record_from_dict(response_body)

    def get_brokered_artifact(
        self,
        *,
        scope_token: ScopeToken,
        artifact_ref: str,
        representation: str,
    ) -> dict[str, Any]:
        body = {
            "authorization": {
                "audience": "store",
                "scope_id": scope_token.scope_id,
                "scope_job_id": scope_token.job_id,
                "capabilities": list(scope_token.scopes.capabilities),
            },
            "artifact_ref": artifact_ref,
            "representation": representation,
        }
        encoded = canonical_json_bytes(body)
        signature = "hmac-sha256:" + hmac.new(self._broker_write_key, encoded, sha256).hexdigest()
        http_request = request.Request(
            self._read_endpoint_url,
            data=encoded,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Argus-Store-Write-Signature": signature,
            },
        )
        try:
            with request.urlopen(http_request, timeout=10) as response:
                response_body = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            response_body = json.loads(exc.read().decode("utf-8"))
            _raise_s8_http_error(response_body)
        if not isinstance(response_body, dict):
            raise RuntimeError("s8 brokered read returned a non-object response")
        return response_body

    def create_artifact(
        self,
        *,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        artifact_ref: str | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> ArtifactRecord:
        scope_job_id = _artifact_scope_job_id(payload=payload, producer=producer, lineage=lineage)
        sealed_producer = Producer(
            subsystem=producer.subsystem,
            version=producer.version,
            actor_id=producer.actor_id,
            job_id=producer.job_id or scope_job_id,
        )
        sealed_lineage = Lineage(
            input_refs=lineage.input_refs,
            code_ref=lineage.code_ref,
            environment_digest=lineage.environment_digest,
            seeds=lineage.seeds,
            actor_id=lineage.actor_id,
            job_id=lineage.job_id or scope_job_id,
            contamination_index_version=lineage.contamination_index_version,
        )
        body = {
            "authorization": {
                "audience": "store",
                "scope_job_id": scope_job_id,
                "producer_subsystems": [producer.subsystem],
            },
            "kind": kind,
            "payload": payload,
            "producer": asdict(sealed_producer),
            "lineage": asdict(sealed_lineage),
            "artifact_ref": artifact_ref,
            "claim_tier": claim_tier,
            "validation_report_ref": validation_report_ref,
        }
        encoded = canonical_json_bytes(body)
        signature = "hmac-sha256:" + hmac.new(self._broker_write_key, encoded, sha256).hexdigest()
        http_request = request.Request(
            self._endpoint_url,
            data=encoded,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Argus-Store-Write-Signature": signature,
            },
        )
        try:
            with request.urlopen(http_request, timeout=10) as response:
                response_body = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            response_body = json.loads(exc.read().decode("utf-8"))
            _raise_s8_http_error(response_body)
        return _artifact_record_from_dict(response_body)


def _required_str(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    return value


def _validate_outbound_header_name(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", value) is None:
        raise ValueError(f"{field} is not a valid HTTP header name")
    return value


def _validated_model_broker_request(value: dict[str, Any]) -> dict[str, Any]:
    disallowed_fields = {
        "api_key",
        "authorization",
        "credential",
        "credential_header",
        "headers",
    }
    present_disallowed = sorted(disallowed_fields.intersection(key.lower() for key in value))
    if present_disallowed:
        raise ValueError("model request contains broker-owned credential fields")
    _required_str(value, "model")
    _positive_int(value.get("max_tokens"), "request.max_tokens")
    messages = value.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("request.messages must be a non-empty array")
    if value.get("stream") is not None and value.get("stream") is not False:
        raise ValueError("streaming model calls are not supported by the metering hook")
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("model request must be canonical JSON") from exc
    return dict(value)


def _model_token_count_request(model_request: Mapping[str, Any]) -> dict[str, Any]:
    count_fields = ("model", "messages", "system", "tools", "tool_choice", "thinking")
    return {field: model_request[field] for field in count_fields if field in model_request}


def _model_input_token_count(value: Mapping[str, Any]) -> int:
    try:
        return _positive_int(value.get("input_tokens"), "provider input_tokens")
    except ValueError as exc:
        raise ModelBrokerUpstreamError("model provider token count is invalid") from exc


def _validated_model_usage(
    response: dict[str, Any],
    *,
    expected_model_id: str,
    expected_input_tokens: int,
    max_output_tokens: int,
) -> dict[str, int]:
    if response.get("model") != expected_model_id:
        raise ModelBrokerUpstreamError("model provider response id does not match the broker target")
    if not isinstance(response.get("id"), str) or not response["id"]:
        raise ModelBrokerUpstreamError("model provider response omits a request id")
    if not isinstance(response.get("content"), list):
        raise ModelBrokerUpstreamError("model provider response omits content")
    usage = response.get("usage")
    if not isinstance(usage, Mapping):
        raise ModelBrokerUpstreamError("model provider response omits usage")
    input_tokens = _nonnegative_provider_int(usage.get("input_tokens"), "input_tokens")
    output_tokens = _nonnegative_provider_int(usage.get("output_tokens"), "output_tokens")
    if input_tokens != expected_input_tokens:
        raise ModelBrokerUpstreamError("model provider completion usage disagrees with token preflight")
    if output_tokens > max_output_tokens:
        raise ModelBrokerUpstreamError("model provider exceeded request.max_tokens")
    total_tokens = input_tokens + output_tokens
    if total_tokens > expected_input_tokens + max_output_tokens:
        raise ModelBrokerUpstreamError("model provider usage exceeded the reserved token amount")
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _nonnegative_provider_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelBrokerUpstreamError(f"model provider {field} must be a non-negative integer")
    return value


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _required_dict(body: dict[str, Any], field: str) -> dict[str, Any]:
    value = body.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"{field} is required")
    return dict(value)


def _artifact_scope_job_id(*, payload: Any, producer: Producer, lineage: Lineage) -> str:
    if producer.job_id:
        return producer.job_id
    if lineage.job_id:
        return lineage.job_id
    if isinstance(payload, dict):
        launch = payload.get("launch")
        if isinstance(launch, dict) and isinstance(launch.get("job_id"), str) and launch["job_id"]:
            return launch["job_id"]
    raise ValueError("artifact job_id is required for brokered S10 provenance writes")


def _raise_s8_http_error(payload: dict[str, Any]) -> None:
    error_name = payload.get("error")
    message = str(payload.get("message", error_name or "s8 broker operation failed"))
    if error_name == "IncompleteLineageError":
        prefix = "incomplete lineage: "
        missing = tuple(part.strip() for part in message.removeprefix(prefix).split(",") if part.strip())
        raise IncompleteLineageError(missing)
    if error_name == "WriteOnceViolationError":
        raise WriteOnceViolationError(message)
    if error_name == "PermissionError":
        raise ScopeDeniedError(message)
    if error_name == "KeyError":
        raise KeyError(message)
    raise RuntimeError(message)


def _bounded_ttl(body: dict[str, Any], max_ttl_s: int) -> int:
    requested = int(body.get("ttl_s", max_ttl_s))
    if requested <= 0:
        raise ValueError("ttl_s must be positive")
    return min(requested, max_ttl_s)


def _identity_mint_ttl(body: dict[str, Any], max_ttl_s: int) -> int:
    requested = int(body.get("ttl_s", max_ttl_s))
    if requested <= 0:
        raise ValueError("ttl_s must be positive")
    if requested > max_ttl_s:
        raise PermissionError("ttl_s exceeds runtime identity mint policy")
    return requested


def _require_runtime_identity(identity: RuntimeIdentity) -> None:
    if identity.can_mint_runtime_identity:
        raise PermissionError("runtime identity token required")


def _runtime_identity_mint_policy_from_env() -> RuntimeIdentityMintPolicy | None:
    raw = os.environ.get("ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON")
    if not raw:
        return None
    return RuntimeIdentityMintPolicy.from_json(raw)


def _scope_grant_from_dict(value: dict[str, Any]) -> ScopeGrant:
    return ScopeGrant(
        allowed_adapters=tuple(value.get("allowed_adapters") or ()),
        allowed_datasets=tuple(value.get("allowed_datasets") or ()),
        egress_allowlist=tuple(EgressRule(**rule) for rule in value.get("egress_allowlist") or ()),
        broker_audiences=tuple(value.get("broker_audiences") or ()),
        capabilities=tuple(value.get("capabilities") or ()),
        producer_subsystems=tuple(value.get("producer_subsystems") or ()),
        disallowed_actions=tuple(value.get("disallowed_actions") or ()),
        sandbox_risk_class=str(value.get("sandbox_risk_class", "standard")),
    )


def _budget_caps_from_dict(value: dict[str, Any]) -> BudgetCaps:
    return BudgetCaps(
        max_compute_units=value.get("max_compute_units", 0),
        max_gpu_seconds=value.get("max_gpu_seconds", 0),
        max_model_tokens=value.get("max_model_tokens", 0),
        max_wallclock_s=value.get("max_wallclock_s", 0),
        max_cost_usd=value.get("max_cost_usd", 0),
    )


def _budget_token_from_dict(value: dict[str, Any]) -> BudgetToken:
    return BudgetToken(
        budget_id=_required_str(value, "budget_id"),
        job_id=_required_str(value, "job_id"),
        root_request_id=_required_str(value, "root_request_id"),
        budget_epoch=int(value["budget_epoch"]),
        caps=_budget_caps_from_dict(_required_dict(value, "caps")),
        risk_class=str(value.get("risk_class", "standard")),
        issued_at=int(value["issued_at"]),
        expires_at=int(value["expires_at"]),
        ttl_s=int(value["ttl_s"]),
        parent_budget_id=value.get("parent_budget_id") if isinstance(value.get("parent_budget_id"), str) else None,
        signer_key_id=_required_str(value, "signer_key_id"),
        signature=_required_str(value, "signature"),
    )


def _launch_envelope_from_dict(value: dict[str, Any]) -> LaunchEnvelope:
    return LaunchEnvelope(
        cpu_m=int(value["cpu_m"]),
        mem_bytes=int(value["mem_bytes"]),
        gpu_count=int(value["gpu_count"]),
        wallclock_s=int(value["wallclock_s"]),
        scratch_bytes=int(value["scratch_bytes"]),
        pids=int(value["pids"]),
        estimated_cost_usd=float(value.get("estimated_cost_usd", 0)),
    )


def _launch_request_from_dict(value: dict[str, Any]) -> LaunchRequest:
    return LaunchRequest(
        job_id=_required_str(value, "job_id"),
        subagent_id=_required_str(value, "subagent_id"),
        trace_id=_required_str(value, "trace_id"),
        budget_token=_budget_token_from_dict(_required_dict(value, "budget_token")),
        scope_token=_scope_token_from_dict(_required_dict(value, "scope_token")),
        image=_required_str(value, "image"),
        entrypoint=_string_tuple(value.get("entrypoint"), "entrypoint"),
        args=_string_tuple(value.get("args"), "args"),
        env=_string_dict(value.get("env"), "env"),
        env_allowlist=_string_tuple(value.get("env_allowlist"), "env_allowlist"),
        requested_envelope=_launch_envelope_from_dict(_required_dict(value, "requested_envelope")),
        runtime_class_hint=str(value.get("runtime_class_hint", "auto")),
        policy_pin=value.get("policy_pin") if isinstance(value.get("policy_pin"), str) else None,
    )


def _artifact_record_from_dict(value: dict[str, Any]) -> ArtifactRecord:
    return ArtifactRecord(
        artifact_ref=_required_str(value, "artifact_ref"),
        kind=_required_str(value, "kind"),
        content_hash=_required_str(value, "content_hash"),
        size_bytes=int(value["size_bytes"]),
        created_at=_required_str(value, "created_at"),
        producer=Producer(**_required_dict(value, "producer")),
        lineage=Lineage(**_normalize_lineage(_required_dict(value, "lineage"))),
        claim_tier=_required_str(value, "claim_tier"),
        validation_report_ref=value.get("validation_report_ref")
        if isinstance(value.get("validation_report_ref"), str)
        else None,
    )


def _require_scope_subset(child: ScopeGrant, parent: ScopeGrant) -> None:
    if not set(child.allowed_adapters).issubset(parent.allowed_adapters):
        raise PermissionError("scope token allowed_adapters exceeds authenticated identity")
    if not set(child.allowed_datasets).issubset(parent.allowed_datasets):
        raise PermissionError("scope token allowed_datasets exceeds authenticated identity")
    if not set(child.egress_allowlist).issubset(parent.egress_allowlist):
        raise PermissionError("scope token egress_allowlist exceeds authenticated identity")
    if not set(child.broker_audiences).issubset(parent.broker_audiences):
        raise PermissionError("scope token broker_audiences exceeds authenticated identity")
    if not set(child.capabilities).issubset(parent.capabilities):
        raise PermissionError("scope token capabilities exceeds authenticated identity")
    if not set(child.producer_subsystems).issubset(parent.producer_subsystems):
        raise PermissionError("scope token producer_subsystems exceeds authenticated identity")
    if not set(parent.disallowed_actions).issubset(child.disallowed_actions):
        raise PermissionError("scope token disallowed_actions exceeds authenticated identity")
    if child.sandbox_risk_class != parent.sandbox_risk_class:
        raise PermissionError("scope token sandbox_risk_class exceeds authenticated identity")


def _scope_token_from_dict(value: dict[str, Any]) -> ScopeToken:
    return ScopeToken(
        scope_id=_required_str(value, "scope_id"),
        job_id=_required_str(value, "job_id"),
        scopes=_scope_grant_from_dict(_required_dict(value, "scopes")),
        issued_at=int(value["issued_at"]),
        expires_at=int(value["expires_at"]),
        ttl_s=int(value["ttl_s"]),
        parent_scope_id=value.get("parent_scope_id") if isinstance(value.get("parent_scope_id"), str) else None,
        signer_key_id=_required_str(value, "signer_key_id"),
        signature=_required_str(value, "signature"),
    )


def _string_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{field} must be an array")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} entries must be strings")
    return tuple(value)


def _string_dict(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()):
        raise ValueError(f"{field} must map strings to strings")
    return dict(value)


def _require_launch_identity_binding(identity: RuntimeIdentity, launch: LaunchRequest) -> None:
    if launch.job_id != identity.job_id:
        raise PermissionError("launch job_id is not bound to the authenticated runtime identity")
    if launch.budget_token.job_id != identity.job_id:
        raise PermissionError("budget token job_id is not bound to the authenticated runtime identity")
    if launch.budget_token.root_request_id != identity.root_request_id:
        raise PermissionError("budget token root_request_id is not bound to the authenticated runtime identity")
    if launch.budget_token.risk_class != identity.scopes.sandbox_risk_class:
        raise PermissionError("budget token risk_class is not bound to the authenticated runtime identity")
    if launch.scope_token.job_id != identity.job_id:
        raise PermissionError("scope token job_id is not bound to the authenticated runtime identity")
    _require_budget_caps_subset(launch.budget_token.caps, identity.budget_caps)
    _require_scope_subset(launch.scope_token.scopes, identity.scopes)


def _require_budget_caps_subset(child: BudgetCaps, parent: BudgetCaps) -> None:
    for field, child_value in asdict(child).items():
        if child_value > getattr(parent, field):
            raise PermissionError(f"budget token {field} exceeds authenticated identity")


def _normalize_lineage(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    normalized["input_refs"] = tuple(normalized.get("input_refs") or ())
    normalized["seeds"] = tuple(normalized.get("seeds") or ())
    return normalized


if __name__ == "__main__":
    main()
