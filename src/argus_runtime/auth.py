"""Runtime HTTP authentication for the M0 service boundary."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
import os
from pathlib import Path
from typing import Any

from argus_core import BudgetCaps, EgressRule, ScopeGrant

from .http_json import JsonRequest


class UnauthorizedError(Exception):
    """Raised when a request lacks a trusted runtime identity."""


class IdentityOverrideError(Exception):
    """Raised when a request attempts to self-select an identity-bound field."""


@dataclass(frozen=True)
class RuntimeIdentity:
    caller_id: str
    job_id: str
    root_request_id: str
    scopes: ScopeGrant
    budget_caps: BudgetCaps
    max_ttl_s: int = 3600


class RuntimeAuth:
    def __init__(self, identities_by_token: dict[str, RuntimeIdentity]) -> None:
        if not identities_by_token:
            raise ValueError("at least one runtime auth token is required")
        self._identities_by_token = dict(identities_by_token)

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

    def authenticate(self, request: JsonRequest) -> RuntimeIdentity:
        value = request.headers.get("authorization", "")
        scheme, separator, token = value.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token:
            raise UnauthorizedError("bearer token required")
        for configured_token, identity in self._identities_by_token.items():
            if hmac.compare_digest(configured_token, token):
                return identity
        raise UnauthorizedError("invalid bearer token")


def runtime_auth_from_env() -> RuntimeAuth:
    file_path = os.environ.get("ARGUS_RUNTIME_AUTH_TOKENS_FILE")
    if file_path:
        raw = Path(file_path).read_text()
    else:
        raw = os.environ.get("ARGUS_RUNTIME_AUTH_TOKENS_JSON")
    if not raw:
        raise RuntimeError("ARGUS_RUNTIME_AUTH_TOKENS_JSON or ARGUS_RUNTIME_AUTH_TOKENS_FILE is required")
    return RuntimeAuth.from_json(raw)


def reject_identity_overrides(body: dict[str, Any], fields: tuple[str, ...]) -> None:
    for field in fields:
        if field in body:
            raise IdentityOverrideError(f"{field} is bound to the authenticated runtime identity")


def _identity_from_dict(value: dict[str, Any]) -> RuntimeIdentity:
    return RuntimeIdentity(
        caller_id=_required_str(value, "caller_id"),
        job_id=_required_str(value, "job_id"),
        root_request_id=_required_str(value, "root_request_id"),
        scopes=_scope_grant_from_dict(dict(value.get("scopes") or {})),
        budget_caps=BudgetCaps(**dict(value.get("budget_caps") or {})),
        max_ttl_s=int(value.get("max_ttl_s", 3600)),
    )


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


def _required_str(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    return value
