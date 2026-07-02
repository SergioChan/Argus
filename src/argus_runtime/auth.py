"""Runtime HTTP authentication for the M0 service boundary."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import time
from typing import Any

from argus_core import BudgetCaps, EgressRule, ScopeGrant, canonical_json_bytes

from .http_json import JsonRequest


class UnauthorizedError(Exception):
    """Raised when a request lacks a trusted runtime identity."""


class IdentityOverrideError(Exception):
    """Raised when a request attempts to self-select an identity-bound field."""


RUNTIME_IDENTITY_TOKEN_PREFIX = "argus-runtime-v1"


@dataclass(frozen=True)
class RuntimeIdentity:
    caller_id: str
    job_id: str
    root_request_id: str
    scopes: ScopeGrant
    budget_caps: BudgetCaps
    max_ttl_s: int = 3600
    issued_at: int | None = None
    expires_at: int | None = None
    can_mint_runtime_identity: bool = False


class RuntimeAuth:
    def __init__(
        self,
        identities_by_token: dict[str, RuntimeIdentity] | None = None,
        *,
        bootstrap_token: str | None = None,
        identity_signing_key: bytes | None = None,
        now_fn: Any | None = None,
    ) -> None:
        if not identities_by_token and not (bootstrap_token and identity_signing_key):
            raise ValueError("runtime auth requires static identities or a bootstrap token plus signing key")
        self._identities_by_token = dict(identities_by_token or {})
        self._bootstrap_token = bootstrap_token
        self._identity_signing_key = identity_signing_key
        self._now_fn = now_fn or (lambda: int(time.time()))

    @classmethod
    def from_json(cls, raw: str) -> "RuntimeAuth":
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("runtime auth config must be a JSON object")
        identities: dict[str, RuntimeIdentity] = {}
        for token, identity_body in parsed.items():
            if not isinstance(token, str) or not token:
                raise ValueError("runtime auth token keys must be non-empty strings")
            if not isinstance(identity_body, dict):
                raise ValueError("runtime auth identity values must be objects")
            identities[token] = _identity_from_dict(identity_body)
        return cls(identities)

    @classmethod
    def with_signed_identities(cls, *, bootstrap_token: str, identity_signing_key: bytes) -> "RuntimeAuth":
        if not bootstrap_token:
            raise ValueError("bootstrap token is required")
        if not identity_signing_key:
            raise ValueError("runtime identity signing key is required")
        return cls(bootstrap_token=bootstrap_token, identity_signing_key=identity_signing_key)

    def authenticate(self, request: JsonRequest) -> RuntimeIdentity:
        value = request.headers.get("authorization", "")
        scheme, separator, token = value.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token:
            raise UnauthorizedError("bearer token required")
        if self._bootstrap_token and hmac.compare_digest(self._bootstrap_token, token):
            return RuntimeIdentity(
                caller_id="runtime-bootstrap",
                job_id="runtime-bootstrap",
                root_request_id="runtime-bootstrap",
                scopes=ScopeGrant(),
                budget_caps=BudgetCaps(),
                can_mint_runtime_identity=True,
            )
        for configured_token, identity in self._identities_by_token.items():
            if hmac.compare_digest(configured_token, token):
                return identity
        if token.startswith(f"{RUNTIME_IDENTITY_TOKEN_PREFIX}."):
            return self._verify_identity_token(token)
        raise UnauthorizedError("invalid bearer token")

    def mint_identity_token(self, identity: RuntimeIdentity, *, ttl_s: int | None = None) -> dict[str, Any]:
        if self._identity_signing_key is None:
            raise RuntimeError("runtime identity minting is unavailable")
        now = int(self._now_fn())
        effective_ttl = min(int(ttl_s or identity.max_ttl_s), identity.max_ttl_s)
        if effective_ttl <= 0:
            raise ValueError("ttl_s must be positive")
        payload = _identity_to_dict(
            RuntimeIdentity(
                caller_id=identity.caller_id,
                job_id=identity.job_id,
                root_request_id=identity.root_request_id,
                scopes=identity.scopes,
                budget_caps=identity.budget_caps,
                max_ttl_s=identity.max_ttl_s,
                issued_at=now,
                expires_at=now + effective_ttl,
                can_mint_runtime_identity=False,
            )
        )
        payload_bytes = canonical_json_bytes(payload)
        signature = hmac.new(self._identity_signing_key, payload_bytes, sha256).hexdigest()
        return {
            "token_type": "Bearer",
            "access_token": ".".join((RUNTIME_IDENTITY_TOKEN_PREFIX, _b64encode(payload_bytes), signature)),
            "expires_at": payload["expires_at"],
            "identity": _public_identity(payload),
        }

    def _verify_identity_token(self, token: str) -> RuntimeIdentity:
        if self._identity_signing_key is None:
            raise UnauthorizedError("signed runtime identities are not configured")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != RUNTIME_IDENTITY_TOKEN_PREFIX:
            raise UnauthorizedError("invalid runtime identity token")
        try:
            payload_bytes = _b64decode(parts[1])
        except Exception as exc:
            raise UnauthorizedError("invalid runtime identity token") from exc
        expected = hmac.new(self._identity_signing_key, payload_bytes, sha256).hexdigest()
        if not hmac.compare_digest(parts[2], expected):
            raise UnauthorizedError("runtime identity signature invalid")
        payload = json.loads(payload_bytes.decode("utf-8"))
        identity = runtime_identity_from_dict(payload)
        if identity.expires_at is None or identity.expires_at <= int(self._now_fn()):
            raise UnauthorizedError("runtime identity expired")
        return identity


def runtime_auth_from_env() -> RuntimeAuth:
    bootstrap_token = os.environ.get("ARGUS_RUNTIME_BOOTSTRAP_TOKEN")
    identity_key = _secret_from_env(
        value_name="ARGUS_RUNTIME_IDENTITY_SIGNING_KEY",
        file_name="ARGUS_RUNTIME_IDENTITY_SIGNING_KEY_FILE",
    )
    if bootstrap_token and identity_key:
        return RuntimeAuth.with_signed_identities(
            bootstrap_token=bootstrap_token,
            identity_signing_key=identity_key,
        )
    raise RuntimeError("ARGUS_RUNTIME_BOOTSTRAP_TOKEN plus ARGUS_RUNTIME_IDENTITY_SIGNING_KEY is required")


def health_token_from_env() -> str:
    token = os.environ.get("ARGUS_M0_HEALTH_TOKEN")
    if not token:
        raise RuntimeError("ARGUS_M0_HEALTH_TOKEN is required")
    return token


def require_static_bearer_token(request: JsonRequest, *, expected_token: str | None, purpose: str) -> None:
    if not expected_token:
        raise UnauthorizedError(f"{purpose} token is not configured")
    value = request.headers.get("authorization", "")
    scheme, separator, token = value.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        raise UnauthorizedError(f"{purpose} bearer token required")
    if not hmac.compare_digest(expected_token, token):
        raise UnauthorizedError(f"{purpose} token invalid")


def reject_identity_overrides(body: dict[str, Any], fields: tuple[str, ...]) -> None:
    for field in fields:
        if field in body:
            raise IdentityOverrideError(f"{field} is bound to the authenticated runtime identity")


def runtime_identity_from_dict(value: dict[str, Any]) -> RuntimeIdentity:
    return _identity_from_dict(value)


def _identity_from_dict(value: dict[str, Any]) -> RuntimeIdentity:
    max_ttl_s = int(value.get("max_ttl_s", 3600))
    if max_ttl_s <= 0:
        raise ValueError("max_ttl_s must be positive")
    return RuntimeIdentity(
        caller_id=_required_str(value, "caller_id"),
        job_id=_required_str(value, "job_id"),
        root_request_id=_required_str(value, "root_request_id"),
        scopes=_scope_grant_from_dict(dict(value.get("scopes") or {})),
        budget_caps=BudgetCaps(**dict(value.get("budget_caps") or {})),
        max_ttl_s=max_ttl_s,
        issued_at=int(value["issued_at"]) if value.get("issued_at") is not None else None,
        expires_at=int(value["expires_at"]) if value.get("expires_at") is not None else None,
        can_mint_runtime_identity=bool(value.get("can_mint_runtime_identity", False)),
    )


def _identity_to_dict(identity: RuntimeIdentity) -> dict[str, Any]:
    return {
        "caller_id": identity.caller_id,
        "job_id": identity.job_id,
        "root_request_id": identity.root_request_id,
        "scopes": asdict(identity.scopes),
        "budget_caps": asdict(identity.budget_caps),
        "max_ttl_s": identity.max_ttl_s,
        "issued_at": identity.issued_at,
        "expires_at": identity.expires_at,
        "can_mint_runtime_identity": identity.can_mint_runtime_identity,
    }


def _public_identity(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "caller_id": payload["caller_id"],
        "job_id": payload["job_id"],
        "root_request_id": payload["root_request_id"],
        "scopes": payload["scopes"],
        "budget_caps": payload["budget_caps"],
        "expires_at": payload["expires_at"],
    }


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


def _required_str(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    return value


def _secret_from_env(*, value_name: str, file_name: str) -> bytes | None:
    file_path = os.environ.get(file_name)
    if file_path:
        return Path(file_path).read_bytes()
    value = os.environ.get(value_name)
    return value.encode("utf-8") if value else None


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))
