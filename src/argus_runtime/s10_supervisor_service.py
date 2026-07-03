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
    BudgetExceededError,
    BudgetToken,
    EgressRule,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    Ed25519KmsTokenSigner,
    FileTokenRevocationStore,
    FileSystemArtifactStore,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryPolicyBundleTrustStore,
    InMemoryPolicyService,
    InMemoryS10KmsCheckpointSigner,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    Lineage,
    PolicyBundle,
    PolicyBundleSigner,
    PolicyDeniedError,
    Producer,
    ResourceCeilings,
    SandboxRuntimeUnavailableError,
    ScopeDeniedError,
    ScopeGrant,
    ScopeToken,
    StoreWriterBroker,
    TokenInvalidError,
    TokenSignatureTrustStore,
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
        docker_supervisor: DockerSandboxSupervisor | None = None,
    ) -> None:
        self.tokens = token_service or InMemoryTokenService(signing_key=signing_key)
        self.quota = quota_ledger or InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        self.artifacts = artifact_store or InMemoryArtifactStore()
        self._artifact_store_path = Path(artifact_store_path) if artifact_store_path is not None else None
        self.auth = auth
        self.runtime_identity_mint_policy = runtime_identity_mint_policy
        self._health_token = health_token
        self.policy_service = policy_service or _default_policy_service()
        self.policy = self.policy_service.active_bundle
        self.checkpoint_signer = checkpoint_signer
        self._checkpoint_signer_auth_token = checkpoint_signer_auth_token
        self._docker_supervisor = docker_supervisor
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

    def launch_sandbox_for_identity(self, identity: RuntimeIdentity, body: dict[str, Any]) -> dict[str, Any]:
        _require_runtime_identity(identity)
        launch = _launch_request_from_dict(body)
        _require_launch_identity_binding(identity, launch)
        self._refresh_artifacts()
        result = self._docker_orchestrator.launch_and_wait(launch)
        return asdict(result)

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
                "checkpoint_signer": self.checkpoint_signer.kind if self.checkpoint_signer is not None else "unconfigured",
                "token_signer": self.tokens.signer_kind,
                "token_signature_algorithm": self.tokens.signature_algorithm,
                "token_verifier": self.tokens.verifier_kind,
                "token_revocation_store": self.tokens.revocation_store_kind,
                "quota_ledger": getattr(self.quota, "kind", type(self.quota).__name__),
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
            except (BudgetExceededError, PermissionError, PolicyDeniedError, ScopeDeniedError) as exc:
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

    def _launch_error_payload(self, exc: Exception, launch: LaunchRequest | None) -> dict[str, Any]:
        handle = None
        if launch is not None:
            handles = [
                asdict(candidate)
                for candidate in self._docker_orchestrator._handles.values()
                if candidate.job_id == launch.job_id
            ]
            if handles:
                handle = handles[-1]
        return {
            "error": type(exc).__name__,
            "message": str(exc),
            "handle": handle,
            "audit_events": [event.event_type for event in self.audit.events()[-10:]],
        }


def build_app_from_env() -> S10SupervisorApp:
    token_service = _token_service_from_env()
    quota_ledger = _quota_ledger_from_env()
    s8_broker_url = os.environ.get("ARGUS_S8_BROKER_URL")
    s8_broker_key = os.environ.get("ARGUS_S8_BROKER_WRITE_KEY")
    mint_policy = _runtime_identity_mint_policy_from_env()
    health_token = health_token_from_env()
    policy_service = _policy_service_from_env()
    checkpoint_signer = _checkpoint_signer_from_env()
    checkpoint_signer_auth_token = _required_env("ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN")
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


def _token_revocation_store_from_env() -> FileTokenRevocationStore | None:
    path = os.environ.get("ARGUS_S10_TOKEN_REVOCATION_STORE_PATH")
    if not path:
        return None
    return FileTokenRevocationStore(path)


def _quota_ledger_from_env() -> Any:
    if not os.environ.get("ARGUS_S10_QUOTA_POSTGRES_DSN"):
        return InMemoryQuotaLedger()
    from .s10_quota_persistence import build_postgres_quota_ledger_from_env

    return build_postgres_quota_ledger_from_env(dict(os.environ))


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
