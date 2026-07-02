"""S10 supervisor service for the argus-m0 stack."""

from __future__ import annotations

from dataclasses import asdict
import os
from pathlib import Path
from typing import Any

from argus_core import (
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
    ScopeGrant,
    ScopeToken,
    StoreWriterBroker,
)

from .http_json import JsonHttpApp, JsonRequest, serve_json_app


class S10SupervisorApp:
    def __init__(
        self,
        *,
        signing_key: bytes,
        artifact_store: InMemoryArtifactStore | None = None,
        artifact_store_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.tokens = InMemoryTokenService(signing_key=signing_key)
        self.quota = InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        self.artifacts = artifact_store or InMemoryArtifactStore()
        self._artifact_store_path = Path(artifact_store_path) if artifact_store_path is not None else None
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

    def mint_scope(self, body: dict[str, Any]) -> dict[str, Any]:
        scopes_body = dict(body.get("scopes") or {})
        scopes = _scope_grant_from_dict(scopes_body)
        token = self.tokens.mint_scope(
            job_id=_required_str(body, "job_id"),
            scopes=scopes,
            ttl_s=int(body.get("ttl_s", 3600)),
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

    def _refresh_artifacts(self) -> None:
        if self._artifact_store_path is not None:
            self.artifacts = FileSystemArtifactStore(self._artifact_store_path)
            self.broker = StoreWriterBroker(
                token_service=self.tokens,
                artifact_store=self.artifacts,
                audit_ledger=self.audit,
            )

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(_: JsonRequest) -> tuple[int, Any]:
            return 200, {
                "service": "s10-supervisor",
                "status": "ok",
                "policy_bundle_version": self.policy.bundle_version,
                "audit_events": len(self.audit.events()),
            }

        @self.http.route("POST", "/v1/budget-tokens")
        def budget(request: JsonRequest) -> tuple[int, Any]:
            try:
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.mint_budget(request.body)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/scope-tokens")
        def scope(request: JsonRequest) -> tuple[int, Any]:
            try:
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.mint_scope(request.body)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}

        @self.http.route("POST", "/v1/store/artifacts")
        def store_artifact(request: JsonRequest) -> tuple[int, Any]:
            try:
                if not isinstance(request.body, dict):
                    return 400, {"error": "json_object_required"}
                return 201, self.broker_put_artifact(request.body)
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}


def build_app_from_env() -> S10SupervisorApp:
    key_file = os.environ.get("ARGUS_S10_SIGNING_KEY_FILE")
    if key_file:
        signing_key = Path(key_file).read_bytes()
    else:
        signing_key = os.environ.get("ARGUS_S10_SIGNING_KEY", "argus-m0-dev-signing-key").encode("utf-8")
    data_dir = os.environ.get("ARGUS_S8_DATA_DIR")
    if data_dir:
        return S10SupervisorApp(
            signing_key=signing_key,
            artifact_store=FileSystemArtifactStore(data_dir),
            artifact_store_path=data_dir,
        )
    return S10SupervisorApp(signing_key=signing_key)


def main() -> None:
    host = os.environ.get("ARGUS_S10_HOST", "0.0.0.0")
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
