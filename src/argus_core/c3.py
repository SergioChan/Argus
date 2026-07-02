"""C3 validation-report signing and verification helpers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol
import hmac

from .canonical import canonical_json_bytes


C3_SIGNATURE_ALGORITHM = "hmac-sha256"
C3_SIGNATURE_PREFIX = "hmac-sha256:"


@dataclass(frozen=True)
class VerifierKey:
    key_id: str
    secret: bytes
    revoked: bool = False


@dataclass(frozen=True)
class C3SignatureVerification:
    valid: bool
    reason: str | None = None
    key_id: str | None = None
    claim_tier: str | None = None
    aggregate_passed: bool | None = None


class VerifierTrustStore(Protocol):
    def get_key(self, key_id: str) -> VerifierKey | None:
        ...


class InMemoryVerifierTrustStore:
    """Read-only verifier-key trust store used by early S8/S3 tests."""

    def __init__(self) -> None:
        self._keys: dict[str, VerifierKey] = {}

    def register_key(self, key_id: str, secret: bytes) -> None:
        self._keys[key_id] = VerifierKey(key_id=key_id, secret=secret)

    def revoke_key(self, key_id: str) -> None:
        key = self._keys[key_id]
        self._keys[key_id] = VerifierKey(key_id=key.key_id, secret=key.secret, revoked=True)

    def get_key(self, key_id: str) -> VerifierKey | None:
        return self._keys.get(key_id)


class C3ReportSigner:
    """Signs C3 ValidationReport payloads for deterministic tests."""

    def __init__(self, *, key_id: str, secret: bytes) -> None:
        self._key_id = key_id
        self._secret = secret

    def sign(self, report: dict[str, Any]) -> dict[str, Any]:
        signed = deepcopy(report)
        signed["signature"] = {
            "algorithm": C3_SIGNATURE_ALGORITHM,
            "key_id": self._key_id,
            "value": "",
        }
        signed["signature"]["value"] = self._signature_value(signed, self._secret)
        return signed

    @staticmethod
    def _signature_value(report_with_empty_signature: dict[str, Any], secret: bytes) -> str:
        digest = hmac.new(secret, canonical_json_bytes(report_with_empty_signature), sha256).hexdigest()
        return f"{C3_SIGNATURE_PREFIX}{digest}"


class C3ReportVerifier:
    """Verifies C3 ValidationReport signatures against a trust store."""

    def __init__(self, trust_store: VerifierTrustStore) -> None:
        self._trust_store = trust_store

    def verify(self, report: dict[str, Any]) -> C3SignatureVerification:
        signature = report.get("signature")
        if not isinstance(signature, dict):
            return C3SignatureVerification(valid=False, reason="signature_missing")
        algorithm = signature.get("algorithm")
        key_id = signature.get("key_id")
        value = signature.get("value")
        if algorithm != C3_SIGNATURE_ALGORITHM:
            return C3SignatureVerification(valid=False, reason="algorithm_unsupported", key_id=key_id)
        if not isinstance(key_id, str):
            return C3SignatureVerification(valid=False, reason="key_missing")
        key = self._trust_store.get_key(key_id)
        if key is None:
            return C3SignatureVerification(valid=False, reason="unknown_key", key_id=key_id)
        if key.revoked:
            return C3SignatureVerification(valid=False, reason="revoked_key", key_id=key_id)
        if not isinstance(value, str):
            return C3SignatureVerification(valid=False, reason="signature_value_missing", key_id=key_id)

        unsigned = deepcopy(report)
        unsigned["signature"] = {
            "algorithm": algorithm,
            "key_id": key_id,
            "value": "",
        }
        verify_signature_value = getattr(self._trust_store, "verify_signature_value", None)
        if callable(verify_signature_value):
            reason = verify_signature_value(
                key_id=key_id,
                report_with_empty_signature=unsigned,
                signature_value=value,
            )
            if reason is not None:
                return C3SignatureVerification(valid=False, reason=reason, key_id=key_id)
        else:
            expected = C3ReportSigner._signature_value(unsigned, key.secret)
            if not hmac.compare_digest(value, expected):
                return C3SignatureVerification(valid=False, reason="signature_invalid", key_id=key_id)

        return C3SignatureVerification(
            valid=True,
            key_id=key_id,
            claim_tier=report.get("claim_tier") if isinstance(report.get("claim_tier"), str) else None,
            aggregate_passed=self._aggregate_passed(report),
        )

    @staticmethod
    def _aggregate_passed(report: dict[str, Any]) -> bool | None:
        aggregate = report.get("aggregate")
        if not isinstance(aggregate, dict):
            return None
        passed = aggregate.get("passed")
        return passed if isinstance(passed, bool) else None
