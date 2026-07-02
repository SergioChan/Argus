"""In-memory S8 artifact ledger semantics used by early M0 tests."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Mapping, Protocol

from .canonical import canonical_json_bytes
from .c3 import C3ReportVerifier
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


@dataclass(frozen=True)
class Producer:
    subsystem: str
    version: str


@dataclass(frozen=True)
class Lineage:
    input_refs: tuple[str, ...]
    code_ref: str
    environment_digest: str
    seeds: tuple[str, ...] = ()


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


@dataclass(frozen=True)
class AuditSlice:
    leaves: tuple[AuditLeaf, ...]
    checkpoint: AuditCheckpoint


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    break_sequence: int | None = None


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


WRITE_ONCE_BUCKET = "write_once"
SCRATCH_BUCKET = "scratch"


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
        self._record_hashes: dict[str, str] = {}
        self._parents: dict[str, set[str]] = {}
        self._children: dict[str, set[str]] = {}
        self._edge_types: dict[tuple[str, str], set[str]] = {}
        self._audit_leaves: list[AuditLeaf] = []
        self._report_verifier = report_verifier

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
        )
        self._object_store.put(
            content_hash,
            payload_bytes,
            bucket_class=self._bucket_class_for_record(kind=kind, claim_tier=claim_tier),
        )
        self._records[artifact_ref] = record
        self._record_hashes[artifact_ref] = record_hash
        self._insert_lineage(record)
        self._promote_referenced_inputs(record)
        self._append_audit_leaf(record)
        return record

    def get_artifact(self, artifact_ref: str) -> bytes:
        record = self._records[artifact_ref]
        return self._object_store.get(record.content_hash)

    def get_record(self, artifact_ref: str) -> ArtifactRecord:
        self.get_artifact(artifact_ref)
        return self._records[artifact_ref]

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

    def export_audit_slice(self, artifact_refs: tuple[str, ...]) -> AuditSlice:
        wanted = set(artifact_refs)
        leaves = tuple(leaf for leaf in self._audit_leaves if leaf.artifact_ref in wanted)
        return AuditSlice(leaves=leaves, checkpoint=self._latest_checkpoint())

    def verify_audit_slice(self, audit_slice: AuditSlice) -> AuditVerification:
        leaves_by_sequence = {leaf.sequence: leaf for leaf in self._audit_leaves}
        for leaf in audit_slice.leaves:
            ledger_leaf = leaves_by_sequence.get(leaf.sequence)
            if ledger_leaf != leaf:
                return AuditVerification(valid=False, break_sequence=leaf.sequence)
            record = self._records.get(leaf.artifact_ref)
            if record is None or self._record_hash(record) != leaf.record_hash:
                return AuditVerification(valid=False, break_sequence=leaf.sequence)
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


def _assert_known_bucket_class(bucket_class: str) -> None:
    if bucket_class not in {WRITE_ONCE_BUCKET, SCRATCH_BUCKET}:
        raise ValueError(f"unknown bucket_class: {bucket_class}")


def _assert_payload_matches_hash(content_hash: str, payload: bytes) -> None:
    if hash_bytes(payload) != content_hash:
        raise HashMismatchError(f"hash mismatch for {content_hash}")


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
        producer=Producer(subsystem=str(producer["subsystem"]), version=str(producer["version"])),
        lineage=Lineage(
            input_refs=tuple(lineage.get("input_refs", ())),
            code_ref=str(lineage["code_ref"]),
            environment_digest=str(lineage["environment_digest"]),
            seeds=tuple(lineage.get("seeds", ())),
        ),
        claim_tier=str(record.get("claim_tier", "ran-toy")),
        validation_report_ref=(
            str(record["validation_report_ref"]) if record.get("validation_report_ref") is not None else None
        ),
    )


def _merged_bucket_class(existing: str | None, incoming: str) -> str:
    if existing == WRITE_ONCE_BUCKET or incoming == WRITE_ONCE_BUCKET:
        return WRITE_ONCE_BUCKET
    return incoming


def _object_name(content_hash: str) -> str:
    if content_hash.startswith(BLAKE3_PREFIX):
        return content_hash.removeprefix(BLAKE3_PREFIX)
    return content_hash.replace(":", "_")
