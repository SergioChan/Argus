"""S6 knowledge registry, C5 resolution, and contamination-index core semantics."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
import json
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json_bytes
from .hashing import hash_json
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


S1_TRUSTED_CONFORMANCE_EVIDENCE_KIND = "s1_reference_conformance_evidence"
S1_TRUSTED_CONFORMANCE_PRODUCER_SUBSYSTEM = "S1"
S1_TRUSTED_CONFORMANCE_PRODUCER_ACTOR_ID = "s1.reference_conformance"
S1_TRUSTED_CONFORMANCE_CODE_REF = "argus-core:s1.reference-conformance"
S1_TRUSTED_CONFORMANCE_ENVIRONMENT_DIGEST = "python:s1-reference-conformance:v1"
S1_CONFORMANCE_ATTESTATION_ALGORITHM = "ed25519"
S1_CONFORMANCE_ATTESTATION_PREFIX = "ed25519:"
S1_CONFORMANCE_ATTESTATION_KEY_ID = "s1-reference-conformance-key-v1"


class S6Error(Exception):
    """Base class for S6 registry and contamination failures."""


class RegistryError(S6Error):
    """Raised when C5 registry operations are invalid."""


class DescriptorRevokedError(RegistryError):
    """Raised when an operation attempts to use a revoked descriptor."""


@dataclass(frozen=True)
class CapabilityDescriptor:
    entity_id: str
    revision: int
    kind: str
    owner_subsystem: str
    contract_versions: dict[str, str]
    trust_class: str
    capability_scopes: tuple[str, ...]
    provenance_ref: str
    subtopics: tuple[str, ...] = ()
    independence_tags: tuple[str, ...] = ()
    conformance: dict[str, str] | None = None
    conformance_level: str | None = None
    status: str = "active"

    def as_c5_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "entity_id": self.entity_id,
            "revision": self.revision,
            "kind": self.kind,
            "owner_subsystem": self.owner_subsystem,
            "contract_versions": dict(self.contract_versions),
            "trust_class": self.trust_class,
            "capability_scopes": list(self.capability_scopes),
            "provenance_ref": self.provenance_ref,
        }
        if self.subtopics:
            payload["subtopics"] = list(self.subtopics)
        if self.independence_tags:
            payload["independence_tags"] = list(self.independence_tags)
        conformance = dict(self.conformance or {})
        if self.conformance_level is not None and "level" not in conformance:
            conformance["level"] = self.conformance_level
        if conformance:
            payload["conformance"] = conformance
        if self.status != "active":
            payload["status"] = self.status
        return payload


@dataclass(frozen=True)
class RegistryEvent:
    event_type: str
    entity_id: str
    revision: int
    descriptor_ref: str


@dataclass(frozen=True)
class RegistryResolution:
    descriptors: tuple[CapabilityDescriptor, ...]
    pinned_revisions: dict[str, int]


@dataclass(frozen=True)
class IndependenceAttestation:
    candidate_ids: tuple[str, ...]
    selected_entity_ids: tuple[str, ...]
    min_independent: int
    lineage_disjoint: bool
    correlation_warning: bool
    excluded_tags: tuple[str, ...]


@dataclass(frozen=True)
class SourceDocument:
    doc_id: str
    text: str
    source_ref: str


class S1ConformanceAttestationSigner:
    """Private S1 conformance signer; only verifiers should be given to registries."""

    algorithm = S1_CONFORMANCE_ATTESTATION_ALGORITHM

    def __init__(self, *, key_id: str, private_key_bytes: bytes) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        if len(private_key_bytes) != 32:
            raise ValueError("Ed25519 private key must be 32 raw bytes")
        self.key_id = key_id
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign_evidence(self, evidence: Mapping[str, Any]) -> dict[str, Any]:
        signed = deepcopy(dict(evidence))
        signed["attestation"] = {
            "algorithm": S1_CONFORMANCE_ATTESTATION_ALGORITHM,
            "key_id": self.key_id,
            "value": "",
        }
        signature = self._private_key.sign(canonical_json_bytes(signed))
        signed["attestation"]["value"] = f"{S1_CONFORMANCE_ATTESTATION_PREFIX}{signature.hex()}"
        return signed

    def verifier(self) -> "S1ConformanceAttestationVerifier":
        return S1ConformanceAttestationVerifier(public_keys={self.key_id: self.public_key_bytes})


class S1ConformanceAttestationVerifier:
    """Offline verifier for S1 conformance evidence signatures."""

    algorithm = S1_CONFORMANCE_ATTESTATION_ALGORITHM

    def __init__(self, *, public_keys: Mapping[str, bytes]) -> None:
        self._public_keys: dict[str, Ed25519PublicKey] = {}
        for key_id, public_key_bytes in public_keys.items():
            if not key_id:
                raise ValueError("key_id is required")
            if len(public_key_bytes) != 32:
                raise ValueError("Ed25519 public key must be 32 raw bytes")
            self._public_keys[key_id] = Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._public_keys))

    def verify_evidence(self, evidence: Mapping[str, Any]) -> None:
        attestation = evidence.get("attestation")
        if not isinstance(attestation, Mapping):
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation")
        if attestation.get("algorithm") != S1_CONFORMANCE_ATTESTATION_ALGORITHM:
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation_algorithm")
        key_id = attestation.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation_key")
        public_key = self._public_keys.get(key_id)
        if public_key is None:
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation_key")
        value = attestation.get("value")
        if not isinstance(value, str) or not value.startswith(S1_CONFORMANCE_ATTESTATION_PREFIX):
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation_value")
        signature = _s1_conformance_attestation_signature(value)
        if signature is None:
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation_value")
        signed = deepcopy(dict(evidence))
        signed["attestation"] = dict(attestation)
        signed["attestation"]["value"] = ""
        try:
            public_key.verify(signature, canonical_json_bytes(signed))
        except InvalidSignature as exc:
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation_signature") from exc


@dataclass(frozen=True)
class S1ConformanceAttestationAuthority:
    signer: S1ConformanceAttestationSigner
    verifier: S1ConformanceAttestationVerifier

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        key_id: str,
        private_key_bytes: bytes,
    ) -> "S1ConformanceAttestationAuthority":
        signer = S1ConformanceAttestationSigner(
            key_id=key_id,
            private_key_bytes=private_key_bytes,
        )
        return cls(signer=signer, verifier=signer.verifier())


@dataclass(frozen=True)
class FrozenContaminationSnapshot:
    snapshot_ref: str
    version: str
    content_hash: str
    document_ids: tuple[str, ...]


@dataclass(frozen=True)
class NoveltyResult:
    query_hash: str
    snapshot_ref: str
    max_overlap: float
    matched_doc_id: str | None
    leakage: bool


class InMemoryRegistry:
    """Immutable C5 registry with active resolution and revocation events."""

    _ACTIVE_STATUSES = frozenset({"active"})

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore | None = None,
        conformance_attestation_verifier: S1ConformanceAttestationVerifier | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._conformance_attestation_verifier = conformance_attestation_verifier
        self._descriptors: dict[tuple[str, int], CapabilityDescriptor] = {}
        self._latest_revision: dict[str, int] = {}
        self._events: list[RegistryEvent] = []

    @property
    def events(self) -> tuple[RegistryEvent, ...]:
        return tuple(self._events)

    def publish(self, descriptor: CapabilityDescriptor) -> CapabilityDescriptor:
        self._validate_descriptor(descriptor)
        key = (descriptor.entity_id, descriptor.revision)
        if key in self._descriptors:
            existing = self._descriptors[key]
            if existing != descriptor:
                raise RegistryError("descriptor revision is immutable")
            return existing
        latest = self._latest_revision.get(descriptor.entity_id)
        if latest is not None and descriptor.revision != latest + 1:
            raise RegistryError("descriptor revision must advance by one")
        if latest is None and descriptor.revision != 1:
            raise RegistryError("first descriptor revision must be 1")
        if latest is not None and self.get(descriptor.entity_id).status == "revoked":
            raise DescriptorRevokedError("revoked descriptor cannot be republished")

        published = descriptor
        if self._artifact_store is not None and descriptor.provenance_ref == "c4://pending":
            record = self._write_descriptor_artifact(descriptor)
            published = replace(descriptor, provenance_ref=record.artifact_ref)
        self._descriptors[key] = published
        self._latest_revision[published.entity_id] = published.revision
        self._events.append(
            RegistryEvent(
                event_type="s6.registry.published",
                entity_id=published.entity_id,
                revision=published.revision,
                descriptor_ref=published.provenance_ref,
            )
        )
        return published

    def get(self, entity_id: str, revision: int | None = None) -> CapabilityDescriptor:
        revision = revision if revision is not None else self._latest_revision[entity_id]
        return self._descriptors[(entity_id, revision)]

    def resolve(
        self,
        *,
        kind: str | None = None,
        subtopic: str | None = None,
        required_scope: str | None = None,
        excluded_independence_tags: tuple[str, ...] = (),
    ) -> RegistryResolution:
        excluded = set(excluded_independence_tags)
        descriptors = []
        for entity_id in sorted(self._latest_revision):
            descriptor = self.get(entity_id)
            if descriptor.status not in self._ACTIVE_STATUSES:
                continue
            if kind is not None and descriptor.kind != kind:
                continue
            if subtopic is not None and subtopic not in descriptor.subtopics:
                continue
            if required_scope is not None and required_scope not in descriptor.capability_scopes:
                continue
            if excluded and set(descriptor.independence_tags) & excluded:
                continue
            descriptors.append(descriptor)
        return RegistryResolution(
            descriptors=tuple(descriptors),
            pinned_revisions={descriptor.entity_id: descriptor.revision for descriptor in descriptors},
        )

    def revoke(self, entity_id: str) -> CapabilityDescriptor:
        current = self.get(entity_id)
        if current.status == "revoked":
            return current
        revoked = replace(current, revision=current.revision + 1, status="revoked")
        self._descriptors[(revoked.entity_id, revoked.revision)] = revoked
        self._latest_revision[entity_id] = revoked.revision
        self._events.append(
            RegistryEvent(
                event_type="s6.registry.revoked",
                entity_id=revoked.entity_id,
                revision=revoked.revision,
                descriptor_ref=revoked.provenance_ref,
            )
        )
        return revoked

    def attest_independence(
        self,
        *,
        kind: str,
        subtopic: str,
        excluded_independence_tags: tuple[str, ...],
        min_independent: int,
    ) -> IndependenceAttestation:
        resolution = self.resolve(
            kind=kind,
            subtopic=subtopic,
            excluded_independence_tags=excluded_independence_tags,
        )
        selected: list[CapabilityDescriptor] = []
        used_tags: set[str] = set()
        for descriptor in resolution.descriptors:
            tags = set(descriptor.independence_tags)
            if tags and tags.isdisjoint(used_tags):
                selected.append(descriptor)
                used_tags.update(tags)
        selected_ids = tuple(descriptor.entity_id for descriptor in selected)
        return IndependenceAttestation(
            candidate_ids=tuple(descriptor.entity_id for descriptor in resolution.descriptors),
            selected_entity_ids=selected_ids,
            min_independent=min_independent,
            lineage_disjoint=len(selected_ids) >= min_independent,
            correlation_warning=len(selected_ids) < min_independent,
            excluded_tags=tuple(sorted(excluded_independence_tags)),
        )

    def _write_descriptor_artifact(self, descriptor: CapabilityDescriptor) -> ArtifactRecord:
        return self._artifact_store.create_artifact(
            kind="capability_descriptor",
            payload=descriptor.as_c5_payload(),
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:s6-registry", environment_digest="oci:s6-registry"),
        )

    def _validate_descriptor(self, descriptor: CapabilityDescriptor) -> None:
        payload = descriptor.as_c5_payload()
        if descriptor.revision < 1:
            raise RegistryError("descriptor revision must be positive")
        if not descriptor.entity_id:
            raise RegistryError("descriptor entity_id is required")
        if payload["owner_subsystem"] != descriptor.owner_subsystem:
            raise RegistryError("descriptor owner_subsystem payload mismatch")
        if not descriptor.capability_scopes:
            raise RegistryError("descriptor capability_scopes is required")
        if "C5" not in descriptor.contract_versions:
            raise RegistryError("descriptor contract_versions must include C5")
        if descriptor.status not in {"active", "deprecated", "revoked", "suspended"}:
            raise RegistryError("descriptor status is invalid")
        if descriptor.conformance is not None:
            self._validate_conformance_block(descriptor)

    def _validate_conformance_block(self, descriptor: CapabilityDescriptor) -> None:
        conformance = descriptor.conformance or {}
        required = {
            "level",
            "suite_version",
            "standard_release_ref",
            "evidence_ref",
            "determinism_hash",
            "expires_at",
        }
        missing = sorted(required - set(conformance))
        if missing:
            raise RegistryError("CONFORMANCE_MISSING: " + ", ".join(missing))
        extra = sorted(set(conformance) - required)
        if extra:
            raise RegistryError("CONFORMANCE_UNRECOGNIZED: " + ", ".join(extra))
        level = conformance["level"]
        if level not in {"bronze", "silver", "gold"}:
            raise RegistryError("CONFORMANCE_LEVEL_INVALID")
        expires_at = _parse_conformance_expiry(conformance["expires_at"])
        if expires_at <= datetime.now(UTC):
            raise RegistryError("CONFORMANCE_EXPIRED")
        if self._artifact_store is None:
            raise RegistryError("CONFORMANCE_EVIDENCE_STORE_REQUIRED")
        if self._conformance_attestation_verifier is None:
            raise RegistryError("CONFORMANCE_UNTRUSTED: attestation_verifier")
        evidence_ref = conformance["evidence_ref"]
        evidence_record = self._load_conformance_evidence_record(evidence_ref)
        evidence = self._load_conformance_evidence(evidence_ref)
        _assert_conformance_evidence_matches_descriptor(
            descriptor=descriptor,
            conformance=conformance,
            evidence=evidence,
            evidence_record=evidence_record,
            attestation_verifier=self._conformance_attestation_verifier,
        )

    def _load_conformance_evidence_record(self, evidence_ref: str) -> ArtifactRecord:
        try:
            return self._artifact_store.get_record(evidence_ref)
        except KeyError as exc:
            raise RegistryError("CONFORMANCE_EVIDENCE_NOT_FOUND") from exc

    def _load_conformance_evidence(self, evidence_ref: str) -> Mapping[str, Any]:
        try:
            payload = json.loads(self._artifact_store.get_artifact(evidence_ref).decode("utf-8"))
        except KeyError as exc:
            raise RegistryError("CONFORMANCE_EVIDENCE_NOT_FOUND") from exc
        except json.JSONDecodeError as exc:
            raise RegistryError("CONFORMANCE_EVIDENCE_INVALID") from exc
        if not isinstance(payload, Mapping):
            raise RegistryError("CONFORMANCE_EVIDENCE_INVALID")
        return payload


class ContaminationIndex:
    """Frozen contamination snapshots and lexical overlap queries."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore) -> None:
        self._artifact_store = artifact_store
        self._documents_by_snapshot: dict[str, tuple[SourceDocument, ...]] = {}

    def freeze(self, *, version: str, documents: tuple[SourceDocument, ...]) -> FrozenContaminationSnapshot:
        ordered = tuple(sorted(documents, key=lambda document: document.doc_id))
        payload = {
            "version": version,
            "documents": tuple(asdict(document) for document in ordered),
        }
        record = self._artifact_store.create_artifact(
            kind="contamination_index",
            payload=payload,
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=tuple(document.source_ref for document in ordered), code_ref="git:s6-freeze", environment_digest="oci:s6-freeze"),
        )
        self._documents_by_snapshot[record.artifact_ref] = ordered
        return FrozenContaminationSnapshot(
            snapshot_ref=record.artifact_ref,
            version=version,
            content_hash=record.content_hash,
            document_ids=tuple(document.doc_id for document in ordered),
        )

    def verify_snapshot(self, snapshot: FrozenContaminationSnapshot) -> bool:
        record = self._artifact_store.get_record(snapshot.snapshot_ref)
        return record.content_hash == snapshot.content_hash

    def query(self, *, snapshot: FrozenContaminationSnapshot, text: str, threshold: float) -> NoveltyResult:
        self.verify_snapshot(snapshot)
        query_tokens = _tokenize(text)
        best_doc_id: str | None = None
        best_overlap = 0.0
        for document in self._documents_by_snapshot[snapshot.snapshot_ref]:
            overlap = _jaccard(query_tokens, _tokenize(document.text))
            if overlap > best_overlap:
                best_overlap = overlap
                best_doc_id = document.doc_id
        return NoveltyResult(
            query_hash=hash_json({"text": text}),
            snapshot_ref=snapshot.snapshot_ref,
            max_overlap=best_overlap,
            matched_doc_id=best_doc_id,
            leakage=best_overlap >= threshold,
        )


def _tokenize(text: str) -> frozenset[str]:
    return frozenset(part.strip(".,;:()[]{}").lower() for part in text.split() if part.strip(".,;:()[]{}"))


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    left_set = set(left)
    right_set = set(right)
    if not left_set and not right_set:
        return 1.0
    if not left_set or not right_set:
        return 0.0
    return len(left_set & right_set) / len(left_set | right_set)


def _parse_conformance_expiry(value: str) -> datetime:
    if not isinstance(value, str):
        raise RegistryError("CONFORMANCE_EXPIRES_AT_INVALID")
    try:
        normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RegistryError("CONFORMANCE_EXPIRES_AT_INVALID") from exc
    if parsed.tzinfo is None:
        raise RegistryError("CONFORMANCE_EXPIRES_AT_INVALID")
    return parsed.astimezone(UTC)


def _assert_conformance_evidence_matches_descriptor(
    *,
    descriptor: CapabilityDescriptor,
    conformance: Mapping[str, str],
    evidence: Mapping[str, Any],
    evidence_record: ArtifactRecord,
    attestation_verifier: S1ConformanceAttestationVerifier,
) -> None:
    _assert_trusted_s1_conformance_record(evidence_record, conformance=conformance)
    attestation_verifier.verify_evidence(evidence)
    expected = {
        "subagent_id": descriptor.entity_id,
        "level_awarded": conformance["level"],
        "suite_version": conformance["suite_version"],
        "standard_release_ref": conformance["standard_release_ref"],
        "aggregate_passed": True,
    }
    for key, expected_value in expected.items():
        if evidence.get(key) != expected_value:
            raise RegistryError(f"CONFORMANCE_TAMPERED: {key}")
    if evidence.get("determinism_hash") != conformance["determinism_hash"]:
        raise RegistryError("CONFORMANCE_TAMPERED: determinism_hash")
    unsigned_evidence = dict(evidence)
    unsigned_evidence.pop("determinism_hash", None)
    unsigned_evidence.pop("attestation", None)
    if hash_json(unsigned_evidence) != conformance["determinism_hash"]:
        raise RegistryError("CONFORMANCE_TAMPERED: evidence_hash")


def _assert_trusted_s1_conformance_record(
    evidence_record: ArtifactRecord,
    *,
    conformance: Mapping[str, str],
) -> None:
    if evidence_record.kind != S1_TRUSTED_CONFORMANCE_EVIDENCE_KIND:
        raise RegistryError("CONFORMANCE_UNTRUSTED: evidence_kind")
    if evidence_record.producer.subsystem != S1_TRUSTED_CONFORMANCE_PRODUCER_SUBSYSTEM:
        raise RegistryError("CONFORMANCE_UNTRUSTED: producer_subsystem")
    if evidence_record.producer.version != conformance["suite_version"]:
        raise RegistryError("CONFORMANCE_UNTRUSTED: producer_version")
    if evidence_record.producer.actor_id != S1_TRUSTED_CONFORMANCE_PRODUCER_ACTOR_ID:
        raise RegistryError("CONFORMANCE_UNTRUSTED: producer_actor")
    if not evidence_record.producer.job_id:
        raise RegistryError("CONFORMANCE_UNTRUSTED: producer_job")
    if evidence_record.lineage.code_ref != S1_TRUSTED_CONFORMANCE_CODE_REF:
        raise RegistryError("CONFORMANCE_UNTRUSTED: code_ref")
    if evidence_record.lineage.environment_digest != S1_TRUSTED_CONFORMANCE_ENVIRONMENT_DIGEST:
        raise RegistryError("CONFORMANCE_UNTRUSTED: environment_digest")
    if evidence_record.lineage.job_id != evidence_record.producer.job_id:
        raise RegistryError("CONFORMANCE_UNTRUSTED: lineage_job")


def _s1_conformance_attestation_signature(value: str) -> bytes | None:
    signature_hex = value.removeprefix(S1_CONFORMANCE_ATTESTATION_PREFIX)
    if len(signature_hex) != 128:
        return None
    try:
        return bytes.fromhex(signature_hex)
    except ValueError:
        return None
