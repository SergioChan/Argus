"""Lightweight wire protocol shared by the S10 supervisor and egress sidecar."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hmac
import ipaddress
import json
import re
from typing import Any

from blake3 import blake3


BLAKE3_PREFIX = "blake3:"


class EgressProxyManifestError(ValueError):
    """Raised when a sidecar manifest is malformed or differs from its bound hash."""


@dataclass(frozen=True)
class EgressRule:
    host: str
    port: int
    proto: str


@dataclass(frozen=True)
class ExfilThresholds:
    soft_bytes: int
    hard_bytes: int

    def validate(self) -> None:
        if (
            isinstance(self.soft_bytes, bool)
            or not isinstance(self.soft_bytes, int)
            or self.soft_bytes < 1
        ):
            raise EgressProxyManifestError("egress soft byte threshold is invalid")
        if (
            isinstance(self.hard_bytes, bool)
            or not isinstance(self.hard_bytes, int)
            or self.hard_bytes <= self.soft_bytes
        ):
            raise EgressProxyManifestError("egress hard byte threshold is invalid")


@dataclass(frozen=True)
class EgressProxyManifest:
    schema_version: int
    sandbox_id: str
    job_id: str
    scope_id: str
    policy_bundle_version: str
    policy_bundle_hash: str
    scope_token_hash: str
    exfil_thresholds: ExfilThresholds
    rules: tuple[EgressRule, ...]
    manifest_hash: str

    @classmethod
    def from_json(cls, raw: str, *, expected_hash: str) -> "EgressProxyManifest":
        if not isinstance(expected_hash, str) or not expected_hash.startswith(BLAKE3_PREFIX):
            raise EgressProxyManifestError("expected manifest hash is missing or unsupported")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EgressProxyManifestError("egress proxy manifest is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise EgressProxyManifestError("egress proxy manifest must be an object")
        expected_fields = {
            "schema_version",
            "sandbox_id",
            "job_id",
            "scope_id",
            "policy_bundle_version",
            "policy_bundle_hash",
            "scope_token_hash",
            "exfil_thresholds",
            "rules",
            "manifest_hash",
        }
        if set(parsed) != expected_fields:
            raise EgressProxyManifestError("egress proxy manifest fields are invalid")
        raw_rules = parsed.get("rules")
        if not isinstance(raw_rules, list):
            raise EgressProxyManifestError("egress proxy manifest rules must be an array")
        rules: list[EgressRule] = []
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict) or set(raw_rule) != {"host", "port", "proto"}:
                raise EgressProxyManifestError("egress proxy manifest rule is invalid")
            if (
                not isinstance(raw_rule["host"], str)
                or isinstance(raw_rule["port"], bool)
                or not isinstance(raw_rule["port"], int)
                or not isinstance(raw_rule["proto"], str)
            ):
                raise EgressProxyManifestError("egress proxy manifest rule is invalid")
            rule = EgressRule(
                host=raw_rule["host"],
                port=raw_rule["port"],
                proto=raw_rule["proto"],
            )
            validate_egress_rule(rule)
            rules.append(rule)
        raw_thresholds = parsed.get("exfil_thresholds")
        if not isinstance(raw_thresholds, dict) or set(raw_thresholds) != {"soft_bytes", "hard_bytes"}:
            raise EgressProxyManifestError("egress proxy manifest exfil thresholds are invalid")
        thresholds = ExfilThresholds(
            soft_bytes=raw_thresholds["soft_bytes"],
            hard_bytes=raw_thresholds["hard_bytes"],
        )
        thresholds.validate()
        scalar_fields = (
            "sandbox_id",
            "job_id",
            "scope_id",
            "policy_bundle_version",
            "policy_bundle_hash",
            "scope_token_hash",
            "manifest_hash",
        )
        if isinstance(parsed["schema_version"], bool) or not isinstance(parsed["schema_version"], int):
            raise EgressProxyManifestError("egress proxy manifest values are invalid")
        if any(not isinstance(parsed[field_name], str) for field_name in scalar_fields):
            raise EgressProxyManifestError("egress proxy manifest values are invalid")
        manifest = cls(
            schema_version=parsed["schema_version"],
            sandbox_id=parsed["sandbox_id"],
            job_id=parsed["job_id"],
            scope_id=parsed["scope_id"],
            policy_bundle_version=parsed["policy_bundle_version"],
            policy_bundle_hash=parsed["policy_bundle_hash"],
            scope_token_hash=parsed["scope_token_hash"],
            exfil_thresholds=thresholds,
            rules=tuple(rules),
            manifest_hash=parsed["manifest_hash"],
        )
        manifest.validate()
        if not hmac.compare_digest(manifest.manifest_hash, expected_hash):
            raise EgressProxyManifestError("egress proxy manifest expected hash mismatch")
        if not hmac.compare_digest(manifest.computed_hash(), manifest.manifest_hash):
            raise EgressProxyManifestError("egress proxy manifest content hash mismatch")
        return manifest

    def computed_hash(self) -> str:
        return hash_json(
            {
                "schema_version": self.schema_version,
                "sandbox_id": self.sandbox_id,
                "job_id": self.job_id,
                "scope_id": self.scope_id,
                "policy_bundle_version": self.policy_bundle_version,
                "policy_bundle_hash": self.policy_bundle_hash,
                "scope_token_hash": self.scope_token_hash,
                "exfil_thresholds": asdict(self.exfil_thresholds),
                "rules": [asdict(rule) for rule in self.rules],
            }
        )

    def validate(self) -> None:
        if self.schema_version != 2:
            raise EgressProxyManifestError("unsupported egress proxy manifest schema version")
        if not all((self.sandbox_id, self.job_id, self.scope_id, self.policy_bundle_version)):
            raise EgressProxyManifestError("egress proxy manifest identity fields are required")
        if not self.policy_bundle_hash.startswith(BLAKE3_PREFIX):
            raise EgressProxyManifestError("egress proxy manifest policy hash is invalid")
        if not self.scope_token_hash.startswith(BLAKE3_PREFIX):
            raise EgressProxyManifestError("egress proxy manifest scope hash is invalid")
        self.exfil_thresholds.validate()
        if tuple(sorted(self.rules, key=lambda rule: (rule.host, rule.port, rule.proto))) != self.rules:
            raise EgressProxyManifestError("egress proxy manifest rules must be sorted")
        if len(set(self.rules)) != len(self.rules):
            raise EgressProxyManifestError("egress proxy manifest rules must be unique")
        for rule in self.rules:
            validate_egress_rule(rule)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def hash_json(value: Any) -> str:
    return f"{BLAKE3_PREFIX}{blake3(canonical_json_bytes(value)).hexdigest()}"


def normalize_egress_host(host: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise EgressProxyManifestError("egress host is invalid")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host.endswith(".") or "*" in host or len(host) > 253:
        raise EgressProxyManifestError("egress host is invalid")
    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise EgressProxyManifestError("egress host is invalid") from exc
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise EgressProxyManifestError("egress host is invalid")
    return normalized


def validate_egress_rule(rule: EgressRule) -> None:
    if normalize_egress_host(rule.host) != rule.host:
        raise EgressProxyManifestError("egress rule host must be canonical")
    if isinstance(rule.port, bool) or not isinstance(rule.port, int) or not 1 <= rule.port <= 65535:
        raise EgressProxyManifestError("egress rule port is invalid")
    if rule.proto not in {"https", "grpc", "tcp"}:
        raise EgressProxyManifestError("egress rule protocol is invalid")
