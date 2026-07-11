"""S10-backed requester checks for M1 reference runtime services."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .http_json import JsonRequest
from .m1_runtime_artifacts import RuntimeArtifactStoreError, RuntimeIdentitySession


class M1RequesterUnauthorized(PermissionError):
    """Raised when an internal M1 service cannot prove an S1 caller identity."""


def require_m1_s1_requester(
    request: JsonRequest,
    *,
    s10_url: str,
    expected_job_id: str,
    required_adapters: Iterable[str] = (),
    required_broker_audiences: Iterable[str] = (),
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    """Validate the bearer through S10 and require the S1 producer scope.

    The requester bearer is never treated as a bootstrap credential. The callee
    asks S10 to mint a short-lived derived scope from that bearer and checks the
    returned server-bound grant.
    """

    bearer = _bearer_token(request)
    session = RuntimeIdentitySession(
        s10_url=s10_url.rstrip("/"),
        access_token=bearer,
        caller_id="m1-reference-peer",
        job_id=expected_job_id,
        timeout_s=timeout_s,
    )
    try:
        scope = session.mint_scope(ttl_s=60)
    except RuntimeArtifactStoreError as exc:
        raise M1RequesterUnauthorized(f"S10 rejected requester identity: {exc}") from exc
    scopes = scope.get("scopes")
    if not isinstance(scopes, Mapping):
        raise M1RequesterUnauthorized("S10 requester scope is malformed")
    producers = _string_set(scopes.get("producer_subsystems"), "producer_subsystems")
    if "S1" not in producers:
        raise M1RequesterUnauthorized("requester does not hold the S1 producer scope")
    adapters = _string_set(scopes.get("allowed_adapters"), "allowed_adapters")
    missing_adapters = set(required_adapters) - adapters
    if missing_adapters:
        raise M1RequesterUnauthorized(
            "requester is missing adapter scope: " + ", ".join(sorted(missing_adapters))
        )
    audiences = _string_set(scopes.get("broker_audiences"), "broker_audiences")
    missing_audiences = set(required_broker_audiences) - audiences
    if missing_audiences:
        raise M1RequesterUnauthorized(
            "requester is missing broker audience: " + ", ".join(sorted(missing_audiences))
        )
    return dict(scope)


def _bearer_token(request: JsonRequest) -> str:
    header = request.headers.get("authorization")
    if not isinstance(header, str) or not header.startswith("Bearer "):
        raise M1RequesterUnauthorized("bearer authorization is required")
    token = header.removeprefix("Bearer ").strip()
    if not token:
        raise M1RequesterUnauthorized("bearer authorization is required")
    return token


def _string_set(value: Any, field: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) and item for item in value):
        raise M1RequesterUnauthorized(f"S10 requester scope {field} is malformed")
    return set(value)
