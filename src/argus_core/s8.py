"""In-memory S8 artifact ledger semantics used by early M0 tests."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .canonical import canonical_json_bytes
from argusverify import C3ReportVerifier
from .hashing import BLAKE3_PREFIX, hash_bytes, hash_json


class S8Error(Exception):
    """Base class for S8 semantic failures."""


class IncompleteLineageError(S8Error):
    """Raised when an artifact lacks required provenance lineage."""

    def __init__(self, missing_fields: tuple[str, ...]) -> None:
        super().__init__("incomplete lineage: " + ", ".join(missing_fields))
        self.category = "INCOMPLETE_LINEAGE"
        self.missing_fields = missing_fields
        self.non_promotable = True


class IllegalTierError(S8Error):
    """Raised when a promoted tier is not coupled to a validation report."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "ILLEGAL_TIER"
        self.reason = reason


class HashMismatchError(S8Error):
    """Raised when verify-on-read detects payload tampering."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "HASH_MISMATCH"
        self.reason = reason


class WriteOnceViolationError(S8Error):
    """Raised when an existing artifact ref would be overwritten."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "IMMUTABLE_VIOLATION"
        self.reason = reason


class SignatureInvalidError(S8Error):
    """Raised when a C3 report signature is missing, unknown, revoked, or invalid."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "SIGNATURE_INVALID"
        self.reason = reason


class CycleDetectedError(S8Error):
    """Raised when a lineage edge would create a cycle."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "CYCLE_DETECTED"
        self.reason = reason


class LedgerReplayError(S8Error):
    """Raised when a durable ledger cannot be replayed without tamper evidence."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "LEDGER_REPLAY_FAILED"
        self.reason = reason


class DatasetRegistryError(S8Error):
    """Raised when a dataset registry record violates S8 dataset invariants."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "DATASET_REGISTRY_INVALID"
        self.reason = reason


class S8ScopeDeniedError(S8Error):
    """Raised when an S8 read or materialization request is outside its scope."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.category = "SCOPE_DENIED"
        self.reason = reason


@dataclass(frozen=True)
class Producer:
    subsystem: str
    version: str
    actor_id: str | None = None
    job_id: str | None = None


@dataclass(frozen=True)
class Lineage:
    input_refs: tuple[str, ...]
    code_ref: str
    environment_digest: str
    seeds: tuple[str, ...] = ()
    actor_id: str | None = None
    job_id: str | None = None
    contamination_index_version: str | None = None


@dataclass(frozen=True)
class LineageCompleteness:
    complete: bool
    missing_fields: tuple[str, ...] = ()
    non_promotable: bool = False

    @property
    def category(self) -> str | None:
        return None if self.complete else "INCOMPLETE_LINEAGE"


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_ref: str
    kind: str
    content_hash: str
    size_bytes: int
    producer: Producer
    lineage: Lineage
    claim_tier: str = "ran-toy"
    validation_report_ref: str | None = None
    created_at: str = ""


@dataclass(frozen=True)
class ArtifactQueryFilter:
    artifact_ref: str | None = None
    content_hash: str | None = None
    kind: str | None = None
    actor_id: str | None = None
    job_id: str | None = None
    producer_subsystem: str | None = None
    producer_version: str | None = None
    claim_tier: str | None = None
    validation_report_ref: str | None = None
    contamination_index_version: str | None = None
    created_after: str | None = None
    created_before: str | None = None


@dataclass(frozen=True)
class ArtifactQueryPage:
    records: tuple[ArtifactRecord, ...]
    next_page_token: int | None = None


@dataclass(frozen=True)
class LineageEdge:
    source_ref: str
    target_ref: str
    edge_type: str


@dataclass(frozen=True)
class LineageGraph:
    nodes: tuple[ArtifactRecord, ...]
    edges: tuple[LineageEdge, ...]


@dataclass(frozen=True)
class AuditLeaf:
    sequence: int
    artifact_ref: str
    record_hash: str
    previous_root: str
    root: str


@dataclass(frozen=True)
class AuditCheckpoint:
    sequence: int
    root: str
    signature: str | None = None
    signer_key_id: str | None = None


@dataclass(frozen=True)
class AuditProofStep:
    sequence: int
    artifact_ref: str
    record_hash: str
    previous_root: str
    root: str


@dataclass(frozen=True)
class AuditInclusionProof:
    artifact_ref: str
    sequence: int
    record_hash: str
    anchor_previous_root: str
    steps: tuple[AuditProofStep, ...]


@dataclass(frozen=True)
class AuditSlice:
    leaves: tuple[AuditLeaf, ...]
    checkpoint: AuditCheckpoint
    inclusion_proofs: tuple[AuditInclusionProof, ...] = ()


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    break_sequence: int | None = None


@dataclass(frozen=True)
class ReproducibilityManifest:
    artifact_ref: str
    content_hash: str
    kind: str
    producer: Producer
    lineage: Lineage
    claim_tier: str
    validation_report_ref: str | None
    nondeterminism_tolerance: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ReproducibilityCheck:
    check_id: str
    artifact_ref: str
    rerun_content_hash: str
    verdict: str
    comparator_id: str
    tolerance_id: str | None = None
    divergence: float | None = None
    reason: str | None = None


ReproducibilityComparator = Callable[..., tuple[bool, float | None, str | None]]


class ReproducibilityComparatorRegistry:
    def __init__(self) -> None:
        self._comparators: dict[str, ReproducibilityComparator] = {}
        self.register("hash_equal", self._hash_equal)
        self.register("numeric_abs_tolerance", self._numeric_abs_tolerance)

    def register(self, comparator_id: str, comparator: ReproducibilityComparator) -> None:
        self._comparators[comparator_id] = comparator

    def compare(
        self,
        comparator_id: str,
        *,
        original_payload: Any,
        rerun_payload: Any | None,
        original_hash: str,
        rerun_hash: str,
        params: Mapping[str, Any],
    ) -> tuple[bool, float | None, str | None]:
        comparator = self._comparators.get(comparator_id)
        if comparator is None:
            return False, None, "comparator_unknown"
        return comparator(
            original_payload=original_payload,
            rerun_payload=rerun_payload,
            original_hash=original_hash,
            rerun_hash=rerun_hash,
            params=params,
        )

    @staticmethod
    def _hash_equal(
        *,
        original_payload: Any,
        rerun_payload: Any | None,
        original_hash: str,
        rerun_hash: str,
        params: Mapping[str, Any],
    ) -> tuple[bool, float | None, str | None]:
        return original_hash == rerun_hash, None, None

    @staticmethod
    def _numeric_abs_tolerance(
        *,
        original_payload: Any,
        rerun_payload: Any | None,
        original_hash: str,
        rerun_hash: str,
        params: Mapping[str, Any],
    ) -> tuple[bool, float | None, str | None]:
        if rerun_payload is None:
            return False, None, "rerun_payload_required"
        field = params.get("field")
        tolerance = params.get("abs_tolerance", params.get("tolerance"))
        if not isinstance(field, str) or not isinstance(tolerance, int | float):
            return False, None, "tolerance_params_invalid"
        original_value = _numeric_field(original_payload, field)
        rerun_value = _numeric_field(rerun_payload, field)
        if original_value is None or rerun_value is None:
            return False, None, "numeric_field_missing"
        divergence = abs(original_value - rerun_value)
        return divergence <= float(tolerance), divergence, None


@dataclass(frozen=True)
class ExternalSourceRef:
    source: str
    external_id: str
    url: str
    snapshot_hash: str
    ingested_at: str
    license: str

    @property
    def source_id(self) -> str:
        return f"{self.source}:{self.external_id}"


@dataclass(frozen=True)
class DatasetSplit:
    split_id: str
    role: str
    content_hash: str | None
    row_count: int
    schema_ref: str
    access_scope: str
    label_seal_ref: str | None = None


@dataclass(frozen=True)
class DatasetProvenanceRef:
    artifact_ref: str
    content_hash: str


@dataclass(frozen=True)
class DatasetRecord:
    dataset_id: str
    version: str
    splits: tuple[DatasetSplit, ...]
    contamination_index_version: str
    provenance_ref: DatasetProvenanceRef


@dataclass(frozen=True)
class DatasetResolveAuditEvent:
    sequence: int
    event_type: str
    dataset_id: str
    version: str
    split_id: str
    requester_audiences: tuple[str, ...]
    verdict: str
    label_seal_ref: str | None = None


@dataclass(frozen=True)
class DatasetSplitResolution:
    dataset_id: str
    version: str
    split_id: str
    role: str
    feature_blob_ref: str
    label_blob_ref: str | None
    audit_event: DatasetResolveAuditEvent


WRITE_ONCE_BUCKET = "write_once"
SCRATCH_BUCKET = "scratch"
DATASET_SPLIT_ROLES = ("train", "val", "test", "blind", "null_control", "injection")
DATASET_VERIFIER_ONLY_ROLES = ("blind", "null_control", "injection")
DATASET_ACCESS_SCOPES = ("agent-readable", "verifier-only")


class ObjectStoreFacade(Protocol):
    def put(self, content_hash: str, payload: bytes, *, bucket_class: str) -> None:
        ...

    def get(self, content_hash: str) -> bytes:
        ...

    def promote_to_write_once(self, content_hash: str) -> None:
        ...

    def bucket_class(self, content_hash: str) -> str:
        ...

    @property
    def object_count(self) -> int:
        ...


class InMemoryObjectStore(ObjectStoreFacade):
    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._bucket_classes: dict[str, str] = {}

    def put(self, content_hash: str, payload: bytes, *, bucket_class: str) -> None:
        _assert_known_bucket_class(bucket_class)
        _assert_payload_matches_hash(content_hash, payload)
        existing = self._objects.get(content_hash)
        if existing is None:
            self._objects[content_hash] = payload
        elif existing != payload:
            raise HashMismatchError(f"existing object bytes do not match {content_hash}")
        self._bucket_classes[content_hash] = _merged_bucket_class(
            self._bucket_classes.get(content_hash),
            bucket_class,
        )

    def get(self, content_hash: str) -> bytes:
        payload = self._objects[content_hash]
        _assert_payload_matches_hash(content_hash, payload)
        return payload

    def promote_to_write_once(self, content_hash: str) -> None:
        if content_hash not in self._objects:
            raise KeyError(content_hash)
        self._bucket_classes[content_hash] = WRITE_ONCE_BUCKET

    def bucket_class(self, content_hash: str) -> str:
        return self._bucket_classes[content_hash]

    @property
    def object_count(self) -> int:
        return len(self._objects)


class FileSystemObjectStore(ObjectStoreFacade):
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        (self.root / WRITE_ONCE_BUCKET).mkdir(parents=True, exist_ok=True)
        (self.root / SCRATCH_BUCKET).mkdir(parents=True, exist_ok=True)

    def put(self, content_hash: str, payload: bytes, *, bucket_class: str) -> None:
        _assert_known_bucket_class(bucket_class)
        _assert_payload_matches_hash(content_hash, payload)
        existing_path = self.object_path(content_hash)
        if existing_path is not None:
            existing = existing_path.read_bytes()
            _assert_payload_matches_hash(content_hash, existing)
            if existing != payload:
                raise HashMismatchError(f"existing object bytes do not match {content_hash}")
            if bucket_class == WRITE_ONCE_BUCKET and existing_path.parent.name == SCRATCH_BUCKET:
                self.promote_to_write_once(content_hash)
            return

        destination = self._path_for(content_hash, bucket_class)
        try:
            with destination.open("xb") as handle:
                handle.write(payload)
        except FileExistsError:
            existing = destination.read_bytes()
            if existing != payload:
                raise HashMismatchError(f"existing object bytes do not match {content_hash}")

    def get(self, content_hash: str) -> bytes:
        existing_path = self.object_path(content_hash)
        if existing_path is None:
            raise KeyError(content_hash)
        payload = existing_path.read_bytes()
        _assert_payload_matches_hash(content_hash, payload)
        return payload

    def promote_to_write_once(self, content_hash: str) -> None:
        write_once_path = self._path_for(content_hash, WRITE_ONCE_BUCKET)
        scratch_path = self._path_for(content_hash, SCRATCH_BUCKET)
        if write_once_path.exists():
            _assert_payload_matches_hash(content_hash, write_once_path.read_bytes())
            if scratch_path.exists():
                scratch_payload = scratch_path.read_bytes()
                _assert_payload_matches_hash(content_hash, scratch_payload)
                if scratch_payload != write_once_path.read_bytes():
                    raise HashMismatchError(f"scratch object bytes do not match {content_hash}")
                scratch_path.unlink()
            return
        if not scratch_path.exists():
            raise KeyError(content_hash)
        scratch_payload = scratch_path.read_bytes()
        _assert_payload_matches_hash(content_hash, scratch_payload)
        scratch_path.replace(write_once_path)

    def bucket_class(self, content_hash: str) -> str:
        existing_path = self.object_path(content_hash)
        if existing_path is None:
            raise KeyError(content_hash)
        return existing_path.parent.name

    @property
    def object_count(self) -> int:
        names = {
            path.name
            for bucket in (WRITE_ONCE_BUCKET, SCRATCH_BUCKET)
            for path in (self.root / bucket).iterdir()
            if path.is_file()
        }
        return len(names)

    def object_path(self, content_hash: str) -> Path | None:
        write_once_path = self._path_for(content_hash, WRITE_ONCE_BUCKET)
        if write_once_path.exists():
            return write_once_path
        scratch_path = self._path_for(content_hash, SCRATCH_BUCKET)
        if scratch_path.exists():
            return scratch_path
        return None

    def _path_for(self, content_hash: str, bucket_class: str) -> Path:
        return self.root / bucket_class / _object_name(content_hash)


def assert_lineage_complete(
    lineage: Lineage | Mapping[str, Any],
    *,
    kind: str | None = None,
    payload: Mapping[str, Any] | None = None,
    claim_tier: str = "ran-toy",
    validation_report_ref: str | None = None,
) -> LineageCompleteness:
    missing_fields = _missing_lineage_fields(lineage)
    if (
        claim_tier != "ran-toy"
        and validation_report_ref is not None
        and kind in {"model", "container", "pipeline"}
        and (payload is None or not payload.get("uncertainty_tag"))
    ):
        missing_fields.append("payload.uncertainty_tag")

    result = LineageCompleteness(
        complete=not missing_fields,
        missing_fields=tuple(missing_fields),
        non_promotable=bool(missing_fields),
    )
    if not result.complete:
        raise IncompleteLineageError(result.missing_fields)
    return result


def _missing_lineage_fields(lineage: Lineage | Mapping[str, Any]) -> list[str]:
    values = asdict(lineage) if isinstance(lineage, Lineage) else dict(lineage)
    missing: list[str] = []
    if "input_refs" not in values or values.get("input_refs") is None:
        missing.append("lineage.input_refs")
    if not values.get("code_ref"):
        missing.append("lineage.code_ref")
    if not values.get("environment_digest"):
        missing.append("lineage.environment_digest")
    if "seeds" not in values or values.get("seeds") is None:
        missing.append("lineage.seeds")
    return missing


def _artifact_query_filter(query: ArtifactQueryFilter | Mapping[str, Any] | None) -> ArtifactQueryFilter:
    if query is None:
        return ArtifactQueryFilter()
    if isinstance(query, ArtifactQueryFilter):
        return query
    allowed_fields = ArtifactQueryFilter.__dataclass_fields__
    unknown_fields = sorted(set(query) - set(allowed_fields))
    if unknown_fields:
        raise ValueError("unsupported artifact query filters: " + ", ".join(unknown_fields))
    return ArtifactQueryFilter(**dict(query))


def _artifact_record_matches_filter(record: ArtifactRecord, query: ArtifactQueryFilter) -> bool:
    expected_values = {
        "artifact_ref": query.artifact_ref,
        "content_hash": query.content_hash,
        "kind": query.kind,
        "actor_id": query.actor_id,
        "job_id": query.job_id,
        "producer_subsystem": query.producer_subsystem,
        "producer_version": query.producer_version,
        "claim_tier": query.claim_tier,
        "validation_report_ref": query.validation_report_ref,
        "contamination_index_version": query.contamination_index_version,
    }
    for field_name, expected in expected_values.items():
        if expected is not None and _artifact_filter_value(record, field_name) != expected:
            return False
    if query.created_after is not None or query.created_before is not None:
        created_at_value = _artifact_filter_value(record, "created_at")
        if created_at_value is None:
            return False
        created_at = _parse_iso_instant(created_at_value)
        if query.created_after is not None and created_at < _parse_iso_instant(query.created_after):
            return False
        if query.created_before is not None and created_at > _parse_iso_instant(query.created_before):
            return False
    return True


def _parse_iso_instant(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _artifact_filter_value(record: ArtifactRecord, field_name: str) -> str | None:
    if field_name in {
        "artifact_ref",
        "content_hash",
        "kind",
        "claim_tier",
        "validation_report_ref",
        "created_at",
    }:
        value = getattr(record, field_name, None)
    elif field_name == "producer_subsystem":
        value = _object_field(record.producer, "subsystem")
    elif field_name == "producer_version":
        value = _object_field(record.producer, "version")
    elif field_name in {"actor_id", "job_id"}:
        value = _object_field(record.producer, field_name) or _object_field(record.lineage, field_name)
    elif field_name == "contamination_index_version":
        value = _object_field(record.lineage, field_name)
    else:
        value = None
    return str(value) if value is not None else None


def _object_field(value: object, field_name: str) -> Any | None:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class InMemoryArtifactStore:
    """A small write-once C4 store for exercising S8 invariants."""

    def __init__(
        self,
        *,
        report_verifier: C3ReportVerifier | None = None,
        object_store: ObjectStoreFacade | None = None,
    ) -> None:
        self._object_store = object_store or InMemoryObjectStore()
        self._records: dict[str, ArtifactRecord] = {}
        self._content_hash_index: dict[str, set[str]] = {}
        self._record_hashes: dict[str, str] = {}
        self._parents: dict[str, set[str]] = {}
        self._children: dict[str, set[str]] = {}
        self._edge_types: dict[tuple[str, str], set[str]] = {}
        self._audit_leaves: list[AuditLeaf] = []
        self._report_verifier = report_verifier
        self._reproducibility_comparators = ReproducibilityComparatorRegistry()
        self._reproducibility_checks: list[ReproducibilityCheck] = []
        self._non_reproducible_artifacts: set[str] = set()

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
        created_at: str | None = None,
    ) -> ArtifactRecord:
        self._assert_lineage_complete(
            lineage,
            kind=kind,
            payload=payload if isinstance(payload, Mapping) else None,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )

        payload_bytes = canonical_json_bytes(payload)
        self._assert_report_payload_if_present(kind, payload)
        self._assert_tier_coupled(claim_tier, validation_report_ref)
        content_hash = hash_bytes(payload_bytes)
        record_hash = self._compute_record_hash(
            kind=kind,
            content_hash=content_hash,
            producer=producer,
            lineage=lineage,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )
        artifact_ref = artifact_ref or self._artifact_ref_for_record_hash(record_hash)
        self._assert_acyclic(artifact_ref, lineage, validation_report_ref)

        if artifact_ref in self._records:
            existing = self._records[artifact_ref]
            if (
                self._object_store.get(existing.content_hash) != payload_bytes
                or self._record_hashes[artifact_ref] != record_hash
            ):
                raise WriteOnceViolationError(f"artifact_ref already exists: {artifact_ref}")
            return existing

        record = ArtifactRecord(
            artifact_ref=artifact_ref,
            kind=kind,
            content_hash=content_hash,
            size_bytes=len(payload_bytes),
            producer=producer,
            lineage=lineage,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
            created_at=created_at or _utc_now_iso(),
        )
        self._object_store.put(
            content_hash,
            payload_bytes,
            bucket_class=self._bucket_class_for_record(kind=kind, claim_tier=claim_tier),
        )
        self._records[artifact_ref] = record
        self._content_hash_index.setdefault(content_hash, set()).add(artifact_ref)
        self._record_hashes[artifact_ref] = record_hash
        self._insert_lineage(record)
        self._promote_referenced_inputs(record)
        self._append_audit_leaf(record)
        return record

    def get_artifact(self, ref: str) -> bytes:
        record = self._record_by_ref(ref, require_unique_record=False)
        return self._object_store.get(record.content_hash)

    def get_record(self, artifact_ref: str) -> ArtifactRecord:
        record = self._record_by_ref(artifact_ref, require_unique_record=True)
        self._object_store.get(record.content_hash)
        return record

    def get_artifact_record(self, ref: str) -> ArtifactRecord:
        return self._record_by_ref(ref, require_unique_record=True)

    def query_artifacts(
        self,
        query: ArtifactQueryFilter | Mapping[str, Any] | None = None,
        *,
        page_size: int | None = None,
        page_token: int | None = None,
    ) -> tuple[ArtifactRecord, ...]:
        return self.query_artifacts_page(query, page_size=page_size, page_token=page_token).records

    def query_artifacts_page(
        self,
        query: ArtifactQueryFilter | Mapping[str, Any] | None = None,
        *,
        page_size: int | None = None,
        page_token: int | None = None,
    ) -> ArtifactQueryPage:
        parsed_query = _artifact_query_filter(query)
        matched_records = tuple(
            record for record in sorted(self._records.values(), key=lambda item: item.artifact_ref)
            if _artifact_record_matches_filter(record, parsed_query)
        )
        offset = page_token or 0
        if offset < 0:
            raise ValueError("page_token must be non-negative")
        if page_size is None:
            return ArtifactQueryPage(records=matched_records[offset:], next_page_token=None)
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        page = matched_records[offset : offset + page_size]
        next_offset = offset + page_size
        next_page_token = next_offset if next_offset < len(matched_records) else None
        return ArtifactQueryPage(records=page, next_page_token=next_page_token)

    def get_lineage(
        self,
        artifact_ref: str,
        *,
        direction: str = "both",
        edge_types: set[str] | None = None,
        max_depth: int | None = None,
    ) -> LineageGraph:
        if direction not in {"ancestors", "descendants", "both"}:
            raise ValueError("direction must be ancestors, descendants, or both")

        visited_refs = {artifact_ref}
        traversed_edges: set[LineageEdge] = set()
        if direction in {"ancestors", "both"}:
            traversed_edges.update(
                self._walk_graph(
                    artifact_ref,
                    adjacency=self._parents,
                    reverse=True,
                    edge_types=edge_types,
                    max_depth=max_depth,
                    visited_refs=visited_refs,
                )
            )
        if direction in {"descendants", "both"}:
            traversed_edges.update(
                self._walk_graph(
                    artifact_ref,
                    adjacency=self._children,
                    reverse=False,
                    edge_types=edge_types,
                    max_depth=max_depth,
                    visited_refs=visited_refs,
                )
            )

        nodes = tuple(self._records[ref] for ref in sorted(visited_refs) if ref in self._records)
        edges = tuple(sorted(traversed_edges, key=lambda edge: (edge.source_ref, edge.target_ref, edge.edge_type)))
        return LineageGraph(nodes=nodes, edges=edges)

    def query_impact_set(
        self,
        seed_refs: tuple[str, ...],
        *,
        edge_types: set[str] | None = None,
    ) -> tuple[ArtifactRecord, ...]:
        impacted_refs: set[str] = set()
        for seed_ref in seed_refs:
            visited_refs = {seed_ref}
            self._walk_graph(
                seed_ref,
                adjacency=self._children,
                reverse=False,
                edge_types=edge_types,
                max_depth=None,
                visited_refs=visited_refs,
            )
            impacted_refs.update(visited_refs - {seed_ref})
        return tuple(self._records[ref] for ref in sorted(impacted_refs) if ref in self._records)

    def register_reproducibility_comparator(
        self,
        comparator_id: str,
        comparator: ReproducibilityComparator,
    ) -> None:
        self._reproducibility_comparators.register(comparator_id, comparator)

    def get_reproducibility_manifest(self, artifact_ref: str) -> ReproducibilityManifest:
        record = self.get_record(artifact_ref)
        payload = self._payload_for_record(record)
        return ReproducibilityManifest(
            artifact_ref=record.artifact_ref,
            content_hash=record.content_hash,
            kind=record.kind,
            producer=record.producer,
            lineage=record.lineage,
            claim_tier=record.claim_tier,
            validation_report_ref=record.validation_report_ref,
            nondeterminism_tolerance=self._nondeterminism_tolerance(payload),
        )

    def record_reproducibility_check(
        self,
        artifact_ref: str,
        *,
        rerun_payload: Any | None = None,
        rerun_content_hash: str | None = None,
        comparator_id: str | None = None,
        tolerance_id: str | None = None,
    ) -> ReproducibilityCheck:
        record = self.get_record(artifact_ref)
        original_payload = self._payload_for_record(record)
        tolerance = self._nondeterminism_tolerance(original_payload) or {}
        tolerance_params = tolerance.get("params") if isinstance(tolerance.get("params"), Mapping) else {}
        selected_comparator = comparator_id or (
            tolerance.get("comparator_id") if isinstance(tolerance.get("comparator_id"), str) else "hash_equal"
        )
        if rerun_content_hash is None:
            if rerun_payload is None:
                raise ValueError("rerun_payload or rerun_content_hash is required")
            rerun_content_hash = hash_bytes(canonical_json_bytes(rerun_payload))
        passed, divergence, reason = self._reproducibility_comparators.compare(
            selected_comparator,
            original_payload=original_payload,
            rerun_payload=rerun_payload,
            original_hash=record.content_hash,
            rerun_hash=rerun_content_hash,
            params=tolerance_params,
        )
        verdict = "PASS" if passed else "FAIL"
        check_id = "s8-repro-" + hash_json(
            {
                "artifact_ref": artifact_ref,
                "rerun_content_hash": rerun_content_hash,
                "comparator_id": selected_comparator,
                "tolerance_id": tolerance_id,
                "sequence": len(self._reproducibility_checks) + 1,
            }
        )[:16]
        check = ReproducibilityCheck(
            check_id=check_id,
            artifact_ref=artifact_ref,
            rerun_content_hash=rerun_content_hash,
            verdict=verdict,
            comparator_id=selected_comparator,
            tolerance_id=tolerance_id,
            divergence=divergence,
            reason=reason,
        )
        self._reproducibility_checks.append(check)
        if verdict == "FAIL":
            self._non_reproducible_artifacts.add(artifact_ref)
        return check

    def reproducibility_checks(self, artifact_ref: str) -> tuple[ReproducibilityCheck, ...]:
        return tuple(check for check in self._reproducibility_checks if check.artifact_ref == artifact_ref)

    def is_non_reproducible(self, artifact_ref: str) -> bool:
        return artifact_ref in self._non_reproducible_artifacts

    def export_audit_slice(self, artifact_refs: tuple[str, ...]) -> AuditSlice:
        wanted = set(artifact_refs)
        leaves = tuple(leaf for leaf in self._audit_leaves if leaf.artifact_ref in wanted)
        return AuditSlice(
            leaves=leaves,
            checkpoint=self._latest_checkpoint(),
            inclusion_proofs=tuple(self._audit_inclusion_proof(leaf) for leaf in leaves),
        )

    def verify_audit_slice(self, audit_slice: AuditSlice) -> AuditVerification:
        leaves_by_sequence = {leaf.sequence: leaf for leaf in self._audit_leaves}
        proofs_by_sequence = {proof.sequence: proof for proof in audit_slice.inclusion_proofs}
        for leaf in audit_slice.leaves:
            ledger_leaf = leaves_by_sequence.get(leaf.sequence)
            if ledger_leaf != leaf:
                return AuditVerification(valid=False, break_sequence=leaf.sequence)
            record = self._records.get(leaf.artifact_ref)
            if record is None or self._record_hash(record) != leaf.record_hash:
                return AuditVerification(valid=False, break_sequence=leaf.sequence)
            proof = proofs_by_sequence.get(leaf.sequence)
            if proof is None:
                return AuditVerification(valid=False, break_sequence=leaf.sequence)
            proof_verification = self._verify_audit_inclusion_proof(leaf, proof, audit_slice.checkpoint)
            if not proof_verification.valid:
                return proof_verification
        if self._latest_checkpoint() != audit_slice.checkpoint:
            return AuditVerification(valid=False, break_sequence=audit_slice.checkpoint.sequence)
        return AuditVerification(valid=True)

    def verify_audit_chain(self) -> AuditVerification:
        previous_root = self._zero_root()
        for leaf in self._audit_leaves:
            record = self._records.get(leaf.artifact_ref)
            if record is None or self._record_hash(record) != leaf.record_hash:
                return AuditVerification(valid=False, break_sequence=leaf.sequence)
            expected_root = self._next_audit_root(previous_root, leaf.record_hash, leaf.sequence)
            if leaf.previous_root != previous_root or leaf.root != expected_root:
                return AuditVerification(valid=False, break_sequence=leaf.sequence)
            previous_root = leaf.root
        return AuditVerification(valid=True)

    @property
    def object_count(self) -> int:
        return self._object_store.object_count

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def edge_count(self) -> int:
        return sum(len(edge_types) for edge_types in self._edge_types.values())

    def bucket_class_for_artifact(self, artifact_ref: str) -> str:
        record = self._records[artifact_ref]
        return self._object_store.bucket_class(record.content_hash)

    def __len__(self) -> int:
        return len(self._records)

    def _record_by_ref(self, ref: str, *, require_unique_record: bool) -> ArtifactRecord:
        record = self._records.get(ref)
        if record is not None:
            return record

        artifact_refs = sorted(self._content_hash_index.get(ref, set()))
        if not artifact_refs:
            raise KeyError(ref)
        if require_unique_record and len(artifact_refs) > 1:
            raise KeyError(f"ambiguous content_hash: {ref}")
        return self._records[artifact_refs[0]]

    @staticmethod
    def _assert_lineage_complete(
        lineage: Lineage,
        *,
        kind: str,
        payload: Mapping[str, Any] | None,
        claim_tier: str,
        validation_report_ref: str | None,
    ) -> None:
        assert_lineage_complete(
            lineage,
            kind=kind,
            payload=payload,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )

    def _assert_report_payload_if_present(self, kind: str, payload: Any) -> None:
        if kind == "report" and isinstance(payload, dict) and "signature" in payload:
            self._verify_report_payload(payload)

    def _assert_tier_coupled(self, claim_tier: str, validation_report_ref: str | None) -> None:
        if claim_tier != "ran-toy" and not validation_report_ref:
            raise IllegalTierError("tier above ran-toy requires validation_report_ref")
        if claim_tier == "ran-toy":
            return
        report_payload = self._report_payload(validation_report_ref or "")
        verification = self._verify_report_payload(report_payload)
        if verification.claim_tier != claim_tier:
            raise IllegalTierError("tier must match validation report claim_tier")
        if verification.aggregate_passed is not True:
            raise IllegalTierError("tier-bearing validation report must pass")
        if claim_tier == "novel-needs-human":
            self._assert_novel_report_requirements(report_payload)

    def _report_payload(self, validation_report_ref: str) -> dict[str, Any]:
        if validation_report_ref not in self._records:
            raise IllegalTierError("validation_report_ref does not exist")
        payload = json.loads(self.get_artifact(validation_report_ref).decode("utf-8"))
        if not isinstance(payload, dict):
            raise IllegalTierError("validation_report_ref does not point to a report object")
        return payload

    def _payload_for_record(self, record: ArtifactRecord) -> Any:
        return json.loads(self.get_artifact(record.artifact_ref).decode("utf-8"))

    @staticmethod
    def _nondeterminism_tolerance(payload: Any) -> Mapping[str, Any] | None:
        if isinstance(payload, Mapping) and isinstance(payload.get("nondeterminism_tolerance"), Mapping):
            return dict(payload["nondeterminism_tolerance"])
        return None

    def _verify_report_payload(self, report_payload: dict[str, Any]):
        if self._report_verifier is None:
            raise SignatureInvalidError("C3 report verifier unavailable")
        verification = self._report_verifier.verify(report_payload)
        if not verification.valid:
            raise SignatureInvalidError(verification.reason or "signature_invalid")
        return verification

    @staticmethod
    def _assert_novel_report_requirements(report_payload: dict[str, Any]) -> None:
        checks = report_payload.get("checks")
        if not isinstance(checks, list):
            raise IllegalTierError("novel report requires checks")
        statuses = {
            check.get("check"): check.get("status")
            for check in checks
            if isinstance(check, dict) and isinstance(check.get("check"), str)
        }
        if statuses.get("LEAKAGE") != "PASS":
            raise IllegalTierError("novel tier requires LEAKAGE PASS")
        if statuses.get("CROSS_CODE") != "PASS":
            raise IllegalTierError("novel tier requires CROSS_CODE PASS")

    @staticmethod
    def _compute_record_hash(
        *,
        kind: str,
        content_hash: str,
        producer: Producer,
        lineage: Lineage,
        claim_tier: str,
        validation_report_ref: str | None,
    ) -> str:
        return hash_json(
            {
                "kind": kind,
                "content_hash": content_hash,
                "producer": asdict(producer),
                "lineage": asdict(lineage),
                "claim_tier": claim_tier,
                "validation_report_ref": validation_report_ref,
            }
        )

    @staticmethod
    def _artifact_ref_for_record_hash(record_hash: str) -> str:
        return f"c4://artifact/{record_hash.removeprefix(BLAKE3_PREFIX)}"

    def _assert_acyclic(
        self,
        artifact_ref: str,
        lineage: Lineage,
        validation_report_ref: str | None,
    ) -> None:
        parent_refs = set(lineage.input_refs)
        if validation_report_ref:
            parent_refs.add(validation_report_ref)
        if artifact_ref in parent_refs:
            raise CycleDetectedError(f"artifact cannot depend on itself: {artifact_ref}")
        descendants = {record.artifact_ref for record in self.query_impact_set((artifact_ref,))}
        cyclic_parent_refs = parent_refs & descendants
        if cyclic_parent_refs:
            raise CycleDetectedError(f"lineage cycle detected through: {sorted(cyclic_parent_refs)}")

    def _insert_lineage(self, record: ArtifactRecord) -> None:
        for input_ref in record.lineage.input_refs:
            self._insert_edge(input_ref, record.artifact_ref, "input")
        if record.validation_report_ref:
            self._insert_edge(record.validation_report_ref, record.artifact_ref, "validation_report")

    def _promote_referenced_inputs(self, record: ArtifactRecord) -> None:
        for parent_ref in tuple(record.lineage.input_refs) + (
            (record.validation_report_ref,) if record.validation_report_ref else ()
        ):
            if parent_ref in self._records:
                parent_hash = self._records[parent_ref].content_hash
                self._object_store.promote_to_write_once(parent_hash)

    def _insert_edge(self, source_ref: str, target_ref: str, edge_type: str) -> None:
        self._children.setdefault(source_ref, set()).add(target_ref)
        self._parents.setdefault(target_ref, set()).add(source_ref)
        self._edge_types.setdefault((source_ref, target_ref), set()).add(edge_type)

    def _walk_graph(
        self,
        origin_ref: str,
        *,
        adjacency: dict[str, set[str]],
        reverse: bool,
        edge_types: set[str] | None,
        max_depth: int | None,
        visited_refs: set[str],
    ) -> set[LineageEdge]:
        traversed_edges: set[LineageEdge] = set()
        frontier: list[tuple[str, int]] = [(origin_ref, 0)]
        while frontier:
            current_ref, depth = frontier.pop(0)
            if max_depth is not None and depth >= max_depth:
                continue
            for next_ref in sorted(adjacency.get(current_ref, set())):
                source_ref, target_ref = (next_ref, current_ref) if reverse else (current_ref, next_ref)
                matching_types = self._matching_edge_types(source_ref, target_ref, edge_types)
                if not matching_types:
                    continue
                for edge_type in matching_types:
                    traversed_edges.add(LineageEdge(source_ref, target_ref, edge_type))
                if next_ref not in visited_refs:
                    visited_refs.add(next_ref)
                    frontier.append((next_ref, depth + 1))
        return traversed_edges

    def _matching_edge_types(
        self,
        source_ref: str,
        target_ref: str,
        edge_types: set[str] | None,
    ) -> tuple[str, ...]:
        stored_types = self._edge_types.get((source_ref, target_ref), set())
        if edge_types is not None:
            stored_types = stored_types & edge_types
        return tuple(sorted(stored_types))

    def _append_audit_leaf(self, record: ArtifactRecord) -> None:
        previous_root = self._audit_leaves[-1].root if self._audit_leaves else self._zero_root()
        sequence = len(self._audit_leaves) + 1
        record_hash = self._record_hash(record)
        root = self._next_audit_root(previous_root, record_hash, sequence)
        self._audit_leaves.append(
            AuditLeaf(
                sequence=sequence,
                artifact_ref=record.artifact_ref,
                record_hash=record_hash,
                previous_root=previous_root,
                root=root,
            )
        )

    def _audit_inclusion_proof(self, leaf: AuditLeaf) -> AuditInclusionProof:
        steps = tuple(
            AuditProofStep(
                sequence=suffix.sequence,
                artifact_ref=suffix.artifact_ref,
                record_hash=suffix.record_hash,
                previous_root=suffix.previous_root,
                root=suffix.root,
            )
            for suffix in self._audit_leaves
            if suffix.sequence > leaf.sequence
        )
        return AuditInclusionProof(
            artifact_ref=leaf.artifact_ref,
            sequence=leaf.sequence,
            record_hash=leaf.record_hash,
            anchor_previous_root=leaf.previous_root,
            steps=steps,
        )

    def _verify_audit_inclusion_proof(
        self,
        leaf: AuditLeaf,
        proof: AuditInclusionProof,
        checkpoint: AuditCheckpoint,
    ) -> AuditVerification:
        if proof.artifact_ref != leaf.artifact_ref or proof.sequence != leaf.sequence:
            return AuditVerification(valid=False, break_sequence=leaf.sequence)
        if proof.record_hash != leaf.record_hash or proof.anchor_previous_root != leaf.previous_root:
            return AuditVerification(valid=False, break_sequence=leaf.sequence)
        expected_root = self._next_audit_root(proof.anchor_previous_root, proof.record_hash, proof.sequence)
        if leaf.root != expected_root:
            return AuditVerification(valid=False, break_sequence=leaf.sequence)

        current_sequence = leaf.sequence
        current_root = leaf.root
        for step in proof.steps:
            if step.sequence != current_sequence + 1 or step.previous_root != current_root:
                return AuditVerification(valid=False, break_sequence=step.sequence)
            expected_step_root = self._next_audit_root(step.previous_root, step.record_hash, step.sequence)
            if step.root != expected_step_root:
                return AuditVerification(valid=False, break_sequence=step.sequence)
            current_sequence = step.sequence
            current_root = step.root

        if current_sequence != checkpoint.sequence or current_root != checkpoint.root:
            return AuditVerification(valid=False, break_sequence=checkpoint.sequence)
        return AuditVerification(valid=True)

    @staticmethod
    def _record_hash(record: ArtifactRecord) -> str:
        return hash_json(asdict(record))

    @staticmethod
    def _next_audit_root(previous_root: str, record_hash: str, sequence: int) -> str:
        return hash_bytes(f"{previous_root}|{record_hash}|{sequence}".encode("utf-8"))

    @staticmethod
    def _zero_root() -> str:
        return f"{BLAKE3_PREFIX}{'0' * 64}"

    @staticmethod
    def _bucket_class_for_record(*, kind: str, claim_tier: str) -> str:
        if kind == "report" or claim_tier != "ran-toy":
            return WRITE_ONCE_BUCKET
        return SCRATCH_BUCKET

    def _latest_checkpoint(self) -> AuditCheckpoint:
        if not self._audit_leaves:
            return AuditCheckpoint(sequence=0, root=self._zero_root())
        latest_leaf = self._audit_leaves[-1]
        return AuditCheckpoint(sequence=latest_leaf.sequence, root=latest_leaf.root)


class FileSystemArtifactStore(InMemoryArtifactStore):
    """Durable local C4 store backed by filesystem objects and an append-only ledger."""

    def __init__(self, root: str | Path, *, report_verifier: C3ReportVerifier | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._ledger_path = self.root / "artifact_ledger.jsonl"
        self._replaying_ledger = True
        super().__init__(
            report_verifier=report_verifier,
            object_store=FileSystemObjectStore(self.root / "objects"),
        )
        self._replay_ledger()
        self._replaying_ledger = False

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
        created_at: str | None = None,
    ) -> ArtifactRecord:
        previous_sequence = self._latest_checkpoint().sequence
        record = super().create_artifact(
            kind=kind,
            payload=payload,
            producer=producer,
            lineage=lineage,
            artifact_ref=artifact_ref,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
            created_at=created_at,
        )
        if not self._replaying_ledger and self._latest_checkpoint().sequence > previous_sequence:
            self._append_ledger_event(record)
        return record

    def _replay_ledger(self) -> None:
        if not self._ledger_path.exists():
            return
        with self._ledger_path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if not raw_line.strip():
                    continue
                try:
                    event = json.loads(raw_line)
                    record = _record_from_ledger_event(event)
                    payload = json.loads(self._object_store.get(record.content_hash).decode("utf-8"))
                    replayed = super().create_artifact(
                        artifact_ref=record.artifact_ref,
                        kind=record.kind,
                        payload=payload,
                        producer=record.producer,
                        lineage=record.lineage,
                        claim_tier=record.claim_tier,
                        validation_report_ref=record.validation_report_ref,
                        created_at=record.created_at,
                    )
                    self._assert_replayed_event(event, replayed)
                except Exception as exc:
                    if isinstance(exc, LedgerReplayError):
                        raise
                    raise LedgerReplayError(f"ledger replay failed at line {line_number}: {exc}") from exc

    def _append_ledger_event(self, record: ArtifactRecord) -> None:
        event = {
            "record": asdict(record),
            "record_hash": self._record_hash(record),
            "audit_leaf": asdict(self._audit_leaves[-1]),
        }
        with self._ledger_path.open("ab") as handle:
            handle.write(canonical_json_bytes(event))
            handle.write(b"\n")

    def _assert_replayed_event(self, event: Mapping[str, Any], record: ArtifactRecord) -> None:
        expected_record = event.get("record")
        if canonical_json_bytes(asdict(record)) != canonical_json_bytes(expected_record):
            raise LedgerReplayError(f"record payload mismatch for {record.artifact_ref}")
        expected_record_hash = event.get("record_hash")
        if expected_record_hash != self._record_hash(record):
            raise LedgerReplayError(f"record hash mismatch for {record.artifact_ref}")
        expected_leaf = event.get("audit_leaf")
        if not self._audit_leaves:
            raise LedgerReplayError(f"missing audit leaf for {record.artifact_ref}")
        if canonical_json_bytes(asdict(self._audit_leaves[-1])) != canonical_json_bytes(expected_leaf):
            raise LedgerReplayError(f"audit leaf mismatch for {record.artifact_ref}")


class ExternalSourceRegistry:
    """Immutable C4-backed registry for external-source ingestion records."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore) -> None:
        self._artifact_store = artifact_store

    def register(self, source_ref: ExternalSourceRef) -> ArtifactRecord:
        return self._artifact_store.create_artifact(
            artifact_ref=self._artifact_ref(source_ref.source_id),
            kind="external_source",
            payload=asdict(source_ref),
            producer=Producer(subsystem="S8", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:s8-external-source", environment_digest="oci:s8"),
        )

    def get(self, source_id: str) -> ExternalSourceRef:
        payload = json.loads(self._artifact_store.get_artifact(self._artifact_ref(source_id)).decode("utf-8"))
        return ExternalSourceRef(**payload)

    @staticmethod
    def _artifact_ref(source_id: str) -> str:
        return f"c4://external_source/{source_id}"


class DatasetRegistry:
    """C4-backed dataset registry projection with versioned, typed splits."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore) -> None:
        self._artifact_store = artifact_store
        self._records: dict[tuple[str, str], DatasetRecord] = {}
        self._resolve_events: list[DatasetResolveAuditEvent] = []
        self._rebuild_index()

    def register(
        self,
        *,
        dataset_id: str,
        version: str,
        splits: tuple[DatasetSplit, ...],
        contamination_index_version: str,
        producer: Producer | None = None,
        lineage: Lineage | None = None,
    ) -> DatasetRecord:
        normalized = self._normalize_dataset_input(
            dataset_id=dataset_id,
            version=version,
            splits=splits,
            contamination_index_version=contamination_index_version,
        )
        payload = _dataset_payload(
            dataset_id=dataset_id,
            version=version,
            splits=normalized,
            contamination_index_version=contamination_index_version,
        )
        artifact = self._artifact_store.create_artifact(
            artifact_ref=self._artifact_ref(dataset_id, version),
            kind="dataset",
            payload=payload,
            producer=producer or Producer(subsystem="S8", version="0.0.0"),
            lineage=lineage
            or Lineage(
                input_refs=tuple(split.content_hash for split in normalized),
                code_ref="s8:dataset-registry",
                environment_digest="s8:dataset-registry-v1",
            ),
        )
        dataset_record = DatasetRecord(
            dataset_id=dataset_id,
            version=version,
            splits=normalized,
            contamination_index_version=contamination_index_version,
            provenance_ref=DatasetProvenanceRef(
                artifact_ref=artifact.artifact_ref,
                content_hash=artifact.content_hash,
            ),
        )
        self._records[(dataset_id, version)] = dataset_record
        return dataset_record

    def get(
        self,
        dataset_id: str,
        version: str | None = None,
        *,
        include_verifier_only_seals: bool = False,
    ) -> DatasetRecord:
        selected_version = version or self._latest_version(dataset_id)
        try:
            record = self._records[(dataset_id, selected_version)]
        except KeyError as exc:
            raise DatasetRegistryError(f"dataset not found: {dataset_id}@{selected_version}") from exc
        if include_verifier_only_seals:
            return record
        return _mask_verifier_only_splits(record)

    def list_versions(self, dataset_id: str) -> tuple[str, ...]:
        return tuple(
            version
            for stored_dataset_id, version in sorted(self._records, key=lambda item: _dataset_version_key(item[1]))
            if stored_dataset_id == dataset_id
        )

    @property
    def resolve_events(self) -> tuple[DatasetResolveAuditEvent, ...]:
        return tuple(self._resolve_events)

    def resolve_split(
        self,
        *,
        dataset_id: str,
        version: str | None,
        split_id: str,
        scope_token: Any,
    ) -> DatasetSplitResolution:
        record = self.get(dataset_id, version, include_verifier_only_seals=True)
        split = self._split(record, split_id)
        requester_audiences = _scope_broker_audiences(scope_token)
        _assert_dataset_scope_allows(record, scope_token)

        if split.access_scope == "verifier-only":
            if not _scope_has_verifier_audience(scope_token):
                event = self._append_resolve_event(
                    dataset_id=record.dataset_id,
                    version=record.version,
                    split_id=split.split_id,
                    requester_audiences=requester_audiences,
                    verdict="DENIED",
                    label_seal_ref=None,
                )
                raise S8ScopeDeniedError(
                    f"scope denied for verifier-only split {record.dataset_id}@{record.version}/{split.split_id}; "
                    f"audit_event={event.sequence}"
                )
            if not split.label_seal_ref:
                raise DatasetRegistryError(f"{split.role} split requires label_seal_ref")

        label_blob_ref = split.label_seal_ref if split.access_scope == "verifier-only" else None
        event = self._append_resolve_event(
            dataset_id=record.dataset_id,
            version=record.version,
            split_id=split.split_id,
            requester_audiences=requester_audiences,
            verdict="ALLOWED",
            label_seal_ref=label_blob_ref,
        )
        return DatasetSplitResolution(
            dataset_id=record.dataset_id,
            version=record.version,
            split_id=split.split_id,
            role=split.role,
            feature_blob_ref=split.content_hash,
            label_blob_ref=label_blob_ref,
            audit_event=event,
        )

    def _latest_version(self, dataset_id: str) -> str:
        versions = self.list_versions(dataset_id)
        if not versions:
            raise DatasetRegistryError(f"dataset not found: {dataset_id}")
        return versions[-1]

    def _rebuild_index(self) -> None:
        for artifact in getattr(self._artifact_store, "_records", {}).values():
            if artifact.kind != "dataset":
                continue
            payload = self._artifact_store._payload_for_record(artifact)
            if not isinstance(payload, Mapping):
                continue
            required = {"dataset_id", "version", "splits", "contamination_index_version"}
            if not required <= set(payload):
                continue
            dataset_id = payload.get("dataset_id")
            version = payload.get("version")
            contamination_index_version = payload.get("contamination_index_version")
            raw_splits = payload.get("splits")
            if not isinstance(dataset_id, str) or not isinstance(version, str):
                continue
            if not isinstance(contamination_index_version, str) or not isinstance(raw_splits, list):
                continue
            splits = tuple(_dataset_split_from_mapping(split) for split in raw_splits if isinstance(split, Mapping))
            normalized = self._normalize_dataset_input(
                dataset_id=dataset_id,
                version=version,
                splits=splits,
                contamination_index_version=contamination_index_version,
            )
            self._records[(dataset_id, version)] = DatasetRecord(
                dataset_id=dataset_id,
                version=version,
                splits=normalized,
                contamination_index_version=contamination_index_version,
                provenance_ref=DatasetProvenanceRef(
                    artifact_ref=artifact.artifact_ref,
                    content_hash=artifact.content_hash,
                ),
            )

    @staticmethod
    def _normalize_dataset_input(
        *,
        dataset_id: str,
        version: str,
        splits: tuple[DatasetSplit, ...],
        contamination_index_version: str,
    ) -> tuple[DatasetSplit, ...]:
        if not dataset_id:
            raise DatasetRegistryError("dataset_id is required")
        if not version:
            raise DatasetRegistryError("dataset version is required")
        if not contamination_index_version:
            raise DatasetRegistryError("contamination_index_version is required")
        if not splits:
            raise DatasetRegistryError("at least one dataset split is required")
        seen_split_ids: set[str] = set()
        normalized: list[DatasetSplit] = []
        for split in splits:
            if not split.split_id:
                raise DatasetRegistryError("split_id is required")
            if split.split_id in seen_split_ids:
                raise DatasetRegistryError(f"duplicate split_id: {split.split_id}")
            seen_split_ids.add(split.split_id)
            if split.role not in DATASET_SPLIT_ROLES:
                raise DatasetRegistryError(f"unsupported split role: {split.role}")
            if split.access_scope not in DATASET_ACCESS_SCOPES:
                raise DatasetRegistryError(f"unsupported access_scope: {split.access_scope}")
            if split.role in DATASET_VERIFIER_ONLY_ROLES and split.access_scope != "verifier-only":
                raise DatasetRegistryError(f"{split.role} split must use verifier-only access_scope")
            if split.access_scope == "verifier-only" and not split.label_seal_ref:
                raise DatasetRegistryError(f"{split.role} split requires label_seal_ref")
            if split.row_count < 0:
                raise DatasetRegistryError("split row_count must be non-negative")
            if not split.content_hash:
                raise DatasetRegistryError("split content_hash is required")
            if not split.schema_ref:
                raise DatasetRegistryError("split schema_ref is required")
            normalized.append(split)
        return tuple(sorted(normalized, key=lambda split: split.split_id))

    @staticmethod
    def _artifact_ref(dataset_id: str, version: str) -> str:
        return "c4://dataset/" + dataset_id.replace("/", "_") + "/" + version.replace("/", "_")

    @staticmethod
    def _split(record: DatasetRecord, split_id: str) -> DatasetSplit:
        for split in record.splits:
            if split.split_id == split_id:
                return split
        raise DatasetRegistryError(f"dataset split not found: {record.dataset_id}@{record.version}/{split_id}")

    def _append_resolve_event(
        self,
        *,
        dataset_id: str,
        version: str,
        split_id: str,
        requester_audiences: tuple[str, ...],
        verdict: str,
        label_seal_ref: str | None,
    ) -> DatasetResolveAuditEvent:
        event = DatasetResolveAuditEvent(
            sequence=len(self._resolve_events) + 1,
            event_type="dataset.split_resolved",
            dataset_id=dataset_id,
            version=version,
            split_id=split_id,
            requester_audiences=requester_audiences,
            verdict=verdict,
            label_seal_ref=label_seal_ref,
        )
        self._resolve_events.append(event)
        return event


def _assert_known_bucket_class(bucket_class: str) -> None:
    if bucket_class not in {WRITE_ONCE_BUCKET, SCRATCH_BUCKET}:
        raise ValueError(f"unknown bucket_class: {bucket_class}")


def _assert_payload_matches_hash(content_hash: str, payload: bytes) -> None:
    if hash_bytes(payload) != content_hash:
        raise HashMismatchError(f"hash mismatch for {content_hash}")


def _dataset_payload(
    *,
    dataset_id: str,
    version: str,
    splits: tuple[DatasetSplit, ...],
    contamination_index_version: str,
) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "version": version,
        "splits": [
            {
                "split_id": split.split_id,
                "role": split.role,
                "content_hash": split.content_hash,
                "row_count": split.row_count,
                "schema_ref": split.schema_ref,
                "access_scope": split.access_scope,
                **({"label_seal_ref": split.label_seal_ref} if split.label_seal_ref is not None else {}),
            }
            for split in splits
        ],
        "contamination_index_version": contamination_index_version,
    }


def _dataset_split_from_mapping(value: Mapping[str, Any]) -> DatasetSplit:
    return DatasetSplit(
        split_id=str(value.get("split_id", "")),
        role=str(value.get("role", "")),
        content_hash=str(value.get("content_hash", "")),
        row_count=int(value.get("row_count", -1)),
        schema_ref=str(value.get("schema_ref", "")),
        access_scope=str(value.get("access_scope", "")),
        label_seal_ref=str(value["label_seal_ref"]) if value.get("label_seal_ref") is not None else None,
    )


def _mask_verifier_only_splits(record: DatasetRecord) -> DatasetRecord:
    return replace(
        record,
        splits=tuple(
            replace(split, content_hash=None, label_seal_ref=None)
            if split.access_scope == "verifier-only"
            else split
            for split in record.splits
        ),
    )


def _dataset_version_key(version: str) -> tuple[Any, ...]:
    parts = version.split(".")
    if all(part.isdigit() for part in parts):
        return (0, *(int(part) for part in parts))
    return (1, version)


def _scope_broker_audiences(scope_token: Any) -> tuple[str, ...]:
    scopes = _scope_grant(scope_token)
    return _tuple_field(scopes, "broker_audiences")


def _scope_allowed_datasets(scope_token: Any) -> tuple[str, ...]:
    scopes = _scope_grant(scope_token)
    return _tuple_field(scopes, "allowed_datasets")


def _scope_has_verifier_audience(scope_token: Any) -> bool:
    audiences = set(_scope_broker_audiences(scope_token))
    return "verifier" in audiences or "s8:verifier" in audiences


def _assert_dataset_scope_allows(record: DatasetRecord, scope_token: Any) -> None:
    allowed = set(_scope_allowed_datasets(scope_token))
    if not allowed:
        return
    accepted_refs = {
        record.dataset_id,
        f"{record.dataset_id}@{record.version}",
        f"{record.dataset_id}:{record.version}",
        record.provenance_ref.artifact_ref,
    }
    if allowed.isdisjoint(accepted_refs):
        raise S8ScopeDeniedError(f"scope does not allow dataset {record.dataset_id}@{record.version}")


def _scope_grant(scope_token: Any) -> Any:
    if isinstance(scope_token, Mapping):
        return scope_token.get("scopes", scope_token)
    return getattr(scope_token, "scopes", scope_token)


def _tuple_field(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, Mapping):
        raw = value.get(field_name, ())
    else:
        raw = getattr(value, field_name, ())
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    return tuple(str(item) for item in raw)


def _record_from_ledger_event(event: Mapping[str, Any]) -> ArtifactRecord:
    record = event.get("record")
    if not isinstance(record, Mapping):
        raise LedgerReplayError("ledger event missing record")
    producer = record.get("producer")
    lineage = record.get("lineage")
    if not isinstance(producer, Mapping) or not isinstance(lineage, Mapping):
        raise LedgerReplayError("ledger event has invalid producer or lineage")
    return ArtifactRecord(
        artifact_ref=str(record["artifact_ref"]),
        kind=str(record["kind"]),
        content_hash=str(record["content_hash"]),
        size_bytes=int(record["size_bytes"]),
        producer=Producer(
            subsystem=str(producer["subsystem"]),
            version=str(producer["version"]),
            actor_id=str(producer["actor_id"]) if producer.get("actor_id") is not None else None,
            job_id=str(producer["job_id"]) if producer.get("job_id") is not None else None,
        ),
        lineage=Lineage(
            input_refs=tuple(lineage.get("input_refs", ())),
            code_ref=str(lineage["code_ref"]),
            environment_digest=str(lineage["environment_digest"]),
            seeds=tuple(lineage.get("seeds", ())),
            actor_id=str(lineage["actor_id"]) if lineage.get("actor_id") is not None else None,
            job_id=str(lineage["job_id"]) if lineage.get("job_id") is not None else None,
            contamination_index_version=(
                str(lineage["contamination_index_version"])
                if lineage.get("contamination_index_version") is not None
                else None
            ),
        ),
        claim_tier=str(record.get("claim_tier", "ran-toy")),
        validation_report_ref=(
            str(record["validation_report_ref"]) if record.get("validation_report_ref") is not None else None
        ),
        created_at=str(record.get("created_at", "")),
    )


def _merged_bucket_class(existing: str | None, incoming: str) -> str:
    if existing == WRITE_ONCE_BUCKET or incoming == WRITE_ONCE_BUCKET:
        return WRITE_ONCE_BUCKET
    return incoming


def _numeric_field(payload: Any, field: str) -> float | None:
    if not isinstance(payload, Mapping):
        return None
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _object_name(content_hash: str) -> str:
    if content_hash.startswith(BLAKE3_PREFIX):
        return content_hash.removeprefix(BLAKE3_PREFIX)
    return content_hash.replace(":", "_")
