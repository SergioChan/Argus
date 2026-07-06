"""Client boundary for the S3 Rust ValidationReport signer service."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from copy import deepcopy
import json
import os
import subprocess
from typing import Any, Mapping, Sequence
from uuid import uuid4

from argusverify import C3_SIGNATURE_ALGORITHM

from argus_core.s3 import ReportCanonicalizationError, canonicalize_validation_report


class S3ReportSigningError(Exception):
    """Raised when the isolated S3 report signer cannot return a trusted signature."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        signed_report: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.signed_report = signed_report


@dataclass(frozen=True)
class S3ReportSigningResult:
    request_id: str
    provider: str
    key_id: str
    algorithm: str
    signature_value: str
    signed_report: dict[str, Any]
    secret_exposed: bool

    def asdict(self) -> dict[str, Any]:
        return asdict(self)


class RustS3ReportSigner:
    """Subprocess client for a Rust signer that owns verifier signing key access."""

    def __init__(
        self,
        *,
        command: Sequence[str],
        key_id: str,
        environment: Mapping[str, str] | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        if not command:
            raise ValueError("Rust signer command is required")
        if not key_id:
            raise ValueError("S3 signer key_id is required")
        self.command = tuple(str(item) for item in command)
        self.key_id = key_id
        self.environment = {str(key): str(value) for key, value in (environment or {}).items()}
        self.timeout_s = timeout_s

    def sign(self, report: Mapping[str, Any]) -> S3ReportSigningResult:
        request_id = f"s3-sign-{uuid4()}"
        signing_payload = self._signing_payload(report)
        request = {
            "request_id": request_id,
            "key_id": self.key_id,
            "report": signing_payload,
        }
        completed = subprocess.run(
            self.command,
            input=json.dumps(request, separators=(",", ":"), sort_keys=True),
            text=True,
            capture_output=True,
            env={**os.environ, **self.environment},
            timeout=self.timeout_s,
            check=False,
        )
        if completed.returncode != 0:
            raise S3ReportSigningError(
                code=_stderr_error_code(completed.stderr),
                message=completed.stderr.strip() or "S3 Rust signer failed",
            )
        response = _json_object(completed.stdout, code="S3_SIGNER_RESPONSE_INVALID")
        result = self._parse_response(response, request_id=request_id)
        canonicalize_validation_report(result.signed_report)
        return result

    def _signing_payload(self, report: Mapping[str, Any]) -> dict[str, Any]:
        payload = _mapping_payload(report)
        payload["signature"] = {
            "algorithm": C3_SIGNATURE_ALGORITHM,
            "key_id": self.key_id,
            "value": "",
        }
        try:
            canonicalize_validation_report(payload)
        except ReportCanonicalizationError as exc:
            raise S3ReportSigningError(code=exc.code, message=exc.message) from exc
        return payload

    def _parse_response(self, response: dict[str, Any], *, request_id: str) -> S3ReportSigningResult:
        signed_report = response.get("signed_report")
        if not isinstance(signed_report, dict):
            raise S3ReportSigningError(code="S3_SIGNER_RESPONSE_INVALID", message="signed_report must be an object")
        key_id = _required_str(response, "key_id")
        if key_id != self.key_id:
            raise S3ReportSigningError(
                code="S3_SIGNER_KEY_MISMATCH",
                message=f"signer returned key_id {key_id!r}, expected {self.key_id!r}",
                signed_report=signed_report,
            )
        algorithm = _required_str(response, "algorithm")
        if algorithm != C3_SIGNATURE_ALGORITHM:
            raise S3ReportSigningError(
                code="S3_SIGNER_ALGORITHM_UNSUPPORTED",
                message=f"signer returned unsupported algorithm {algorithm!r}",
                signed_report=signed_report,
            )
        signature_value = _required_str(response, "signature_value")
        signature = signed_report.get("signature")
        if not isinstance(signature, dict):
            raise S3ReportSigningError(
                code="S3_SIGNER_RESPONSE_INVALID",
                message="signed report signature must be an object",
                signed_report=signed_report,
            )
        if signature.get("key_id") != key_id or signature.get("algorithm") != algorithm:
            raise S3ReportSigningError(
                code="S3_SIGNER_SIGNATURE_METADATA_MISMATCH",
                message="signed report signature metadata does not match signer response",
                signed_report=signed_report,
            )
        if signature.get("value") != signature_value:
            raise S3ReportSigningError(
                code="S3_SIGNER_SIGNATURE_VALUE_MISMATCH",
                message="signed report signature value does not match signer response",
                signed_report=signed_report,
            )
        secret_exposed = bool(response.get("secret_exposed"))
        if secret_exposed:
            raise S3ReportSigningError(
                code="S3_SIGNER_SECRET_EXPOSED",
                message="signer response reported exposed secret material",
                signed_report=signed_report,
            )
        return S3ReportSigningResult(
            request_id=_optional_str(response.get("request_id")) or request_id,
            provider=_optional_str(response.get("provider")) or "rust-s3-report-signer",
            key_id=key_id,
            algorithm=algorithm,
            signature_value=signature_value,
            signed_report=signed_report,
            secret_exposed=secret_exposed,
        )


def _mapping_payload(report: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        raise S3ReportSigningError(code="S3_SIGNER_REPORT_INVALID", message="report must be a mapping")
    return deepcopy(dict(report))


def _json_object(raw: str, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise S3ReportSigningError(code=code, message="signer returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise S3ReportSigningError(code=code, message="signer response must be a JSON object")
    return value


def _required_str(value: Mapping[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise S3ReportSigningError(
            code="S3_SIGNER_RESPONSE_INVALID",
            message=f"signer response {field} must be a non-empty string",
        )
    return item


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _stderr_error_code(stderr: str) -> str:
    text = stderr.lower()
    if "s3_signer_key_revoked" in text or "revoked" in text:
        return "S3_SIGNER_KEY_REVOKED"
    if "s3_signer_key_unknown" in text or "unknown key" in text or "key not found" in text:
        return "S3_SIGNER_KEY_UNKNOWN"
    if "vault key material" in text:
        return "S3_SIGNER_KEY_MATERIAL_UNAVAILABLE"
    if "request must not include secret" in text:
        return "S3_SIGNER_SECRET_IN_REQUEST"
    return "S3_SIGNER_FAILED"
