"""S10 supervisor service for the argus-m0 stack."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
from typing import Any
from urllib import error, request

from argus_core import (
    ArtifactRecord,
    BudgetCaps,
    EgressRule,
    FileSystemArtifactStore,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    Lineage,
    PolicyBundle,
    Producer,
    ResourceCeilings,
    ScopeDeniedError,
    ScopeGrant,
    ScopeToken,
    StoreWriterBroker,
    TokenInvalidError,
    WriteOnceViolationError,
    IncompleteLineageError,
    canonical_json_bytes,
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
        signing_key: bytes,
        artifact_store: InMemoryArtifactStore | None = None,
        artifact_store_path: str | os.PathLike[str] | None = None,
        auth: RuntimeAuth | None = None,
        runtime_identity_mint_policy: RuntimeIdentityMintPolicy | None = None,
        health_token: str | None = None,
    ) -> None:
        self.tokens = InMemoryTokenService(signing_key=signing_key)
        self.quota = InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        self.artifacts = artifact_store or InMemoryArtifactStore()
        self._artifact_store_path = Path(artifact_store_path) if artifact_store_path is not None else None
        self.auth = auth
        self.runtime_identity_mint_policy = runtime_identity_mint_policy
        self._health_token = health_token
        self.policy = _default_policy_bundle()
        self.broker = StoreWriterBroker(
            token_service=self.tokens,
            artifact_store=self.artifacts,
            audit_ledger=self.audit,
        )
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
        _require_runtime_identity(identity)
        scope_token = _scope_token_from_dict(_required_dict(body, "scope_token"))
        if scope_token.job_id != identity.job_id:
            raise PermissionError("scope token is not bound to the authenticated runtime identity")
        _require_scope_subset(scope_token.scopes, identity.scopes)
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

    def _refresh_artifacts(self) -> None:
        if self._artifact_store_path is not None:
            self.artifacts = FileSystemArtifactStore(self._artifact_store_path)
            self.broker = StoreWriterBroker(
                token_service=self.tokens,
                artifact_store=self.artifacts,
                audit_ledger=self.audit,
            )

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


def build_app_from_env() -> S10SupervisorApp:
    key_file = os.environ.get("ARGUS_S10_SIGNING_KEY_FILE")
    if key_file:
        signing_key = Path(key_file).read_bytes()
    else:
        signing_key_value = os.environ.get("ARGUS_S10_SIGNING_KEY")
        if not signing_key_value:
            raise RuntimeError("ARGUS_S10_SIGNING_KEY or ARGUS_S10_SIGNING_KEY_FILE is required")
        signing_key = signing_key_value.encode("utf-8")
    s8_broker_url = os.environ.get("ARGUS_S8_BROKER_URL")
    s8_broker_key = os.environ.get("ARGUS_S8_BROKER_WRITE_KEY")
    mint_policy = _runtime_identity_mint_policy_from_env()
    health_token = health_token_from_env()
    if s8_broker_url:
        if not s8_broker_key:
            raise RuntimeError("ARGUS_S8_BROKER_WRITE_KEY is required when ARGUS_S8_BROKER_URL is configured")
        return S10SupervisorApp(
            signing_key=signing_key,
            artifact_store=S8BrokeredArtifactStoreClient(
                endpoint_url=s8_broker_url,
                broker_write_key=s8_broker_key.encode("utf-8"),
            ),
            auth=runtime_auth_from_env(),
            runtime_identity_mint_policy=mint_policy,
            health_token=health_token,
        )
    data_dir = os.environ.get("ARGUS_S8_DATA_DIR")
    if data_dir:
        return S10SupervisorApp(
            signing_key=signing_key,
            artifact_store=FileSystemArtifactStore(data_dir),
            artifact_store_path=data_dir,
            auth=runtime_auth_from_env(),
            runtime_identity_mint_policy=mint_policy,
            health_token=health_token,
        )
    return S10SupervisorApp(
        signing_key=signing_key,
        auth=runtime_auth_from_env(),
        runtime_identity_mint_policy=mint_policy,
        health_token=health_token,
    )


def main() -> None:
    host = os.environ.get("ARGUS_S10_HOST", "127.0.0.1")
    port = int(os.environ.get("ARGUS_S10_PORT", "8080"))
    serve_json_app(build_app_from_env().http, host=host, port=port)


def _default_policy_bundle() -> PolicyBundle:
    return PolicyBundle(
        bundle_version="argus-m0-dev",
        egress_allowlist=(),
        resource_ceilings=ResourceCeilings(
            cpu_m=1_000,
            mem_bytes=128 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=30,
            max_cost_usd=1,
        ),
        risk_to_runtime={"standard": "docker"},
        seccomp_profile_hash="blake3:" + "0" * 64,
        signer_key_id="argus-m0-dev",
        signature="dev-policy-signature",
    )


class S8BrokeredArtifactStoreClient:
    def __init__(self, *, endpoint_url: str, broker_write_key: bytes) -> None:
        self._endpoint_url = endpoint_url
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


def _raise_s8_http_error(payload: dict[str, Any]) -> None:
    error_name = payload.get("error")
    message = str(payload.get("message", error_name or "s8 brokered write failed"))
    if error_name == "IncompleteLineageError":
        prefix = "incomplete lineage: "
        missing = tuple(part.strip() for part in message.removeprefix(prefix).split(",") if part.strip())
        raise IncompleteLineageError(missing)
    if error_name == "WriteOnceViolationError":
        raise WriteOnceViolationError(message)
    if error_name == "PermissionError":
        raise ScopeDeniedError(message)
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
        producer_subsystems=tuple(value.get("producer_subsystems") or ()),
        disallowed_actions=tuple(value.get("disallowed_actions") or ()),
        sandbox_risk_class=str(value.get("sandbox_risk_class", "standard")),
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


def _normalize_lineage(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    normalized["input_refs"] = tuple(normalized.get("input_refs") or ())
    normalized["seeds"] = tuple(normalized.get("seeds") or ())
    return normalized


if __name__ == "__main__":
    main()
