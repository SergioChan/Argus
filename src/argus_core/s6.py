"""S6 knowledge registry, C5 resolution, and contamination-index core semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Iterable

from .hashing import hash_json
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


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
    conformance_level: str | None = None
    status: str = "active"


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

    def __init__(self, *, artifact_store: InMemoryArtifactStore | None = None) -> None:
        self._artifact_store = artifact_store
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
            payload=asdict(descriptor),
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:s6-registry", environment_digest="oci:s6-registry"),
        )

    @staticmethod
    def _validate_descriptor(descriptor: CapabilityDescriptor) -> None:
        if descriptor.revision < 1:
            raise RegistryError("descriptor revision must be positive")
        if not descriptor.entity_id:
            raise RegistryError("descriptor entity_id is required")
        if descriptor.status not in {"active", "deprecated", "revoked", "suspended"}:
            raise RegistryError("descriptor status is invalid")


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
