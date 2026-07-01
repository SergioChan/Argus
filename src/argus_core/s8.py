"""In-memory S8 artifact ledger semantics used by early M0 tests."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .canonical import canonical_json_bytes
from .hashing import BLAKE3_PREFIX, hash_bytes, hash_json


class S8Error(Exception):
    """Base class for S8 semantic failures."""


class IncompleteLineageError(S8Error):
    """Raised when an artifact lacks required provenance lineage."""


class IllegalTierError(S8Error):
    """Raised when a promoted tier is not coupled to a validation report."""


class HashMismatchError(S8Error):
    """Raised when verify-on-read detects payload tampering."""


class WriteOnceViolationError(S8Error):
    """Raised when an existing artifact ref would be overwritten."""


class CycleDetectedError(S8Error):
    """Raised when a lineage edge would create a cycle."""


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


class InMemoryArtifactStore:
    """A small write-once C4 store for exercising S8 invariants."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._records: dict[str, ArtifactRecord] = {}
        self._record_hashes: dict[str, str] = {}
        self._parents: dict[str, set[str]] = {}
        self._children: dict[str, set[str]] = {}
        self._edge_types: dict[tuple[str, str], set[str]] = {}
        self._audit_leaves: list[AuditLeaf] = []

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
        self._assert_lineage_complete(lineage)
        self._assert_tier_coupled(claim_tier, validation_report_ref)

        payload_bytes = canonical_json_bytes(payload)
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
                self._objects[existing.content_hash] != payload_bytes
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
        self._objects.setdefault(content_hash, payload_bytes)
        self._records[artifact_ref] = record
        self._record_hashes[artifact_ref] = record_hash
        self._insert_lineage(record)
        self._append_audit_leaf(record)
        return record

    def get_artifact(self, artifact_ref: str) -> bytes:
        record = self._records[artifact_ref]
        payload = self._objects[record.content_hash]
        if hash_bytes(payload) != record.content_hash:
            raise HashMismatchError(f"hash mismatch for {artifact_ref}")
        return payload

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
        return len(self._objects)

    @property
    def record_count(self) -> int:
        return len(self._records)

    def __len__(self) -> int:
        return len(self._records)

    @staticmethod
    def _assert_lineage_complete(lineage: Lineage) -> None:
        if not lineage.code_ref:
            raise IncompleteLineageError("lineage.code_ref is required")
        if not lineage.environment_digest:
            raise IncompleteLineageError("lineage.environment_digest is required")

    @staticmethod
    def _assert_tier_coupled(claim_tier: str, validation_report_ref: str | None) -> None:
        if claim_tier != "ran-toy" and not validation_report_ref:
            raise IllegalTierError("tier above ran-toy requires validation_report_ref")

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

    def _latest_checkpoint(self) -> AuditCheckpoint:
        if not self._audit_leaves:
            return AuditCheckpoint(sequence=0, root=self._zero_root())
        latest_leaf = self._audit_leaves[-1]
        return AuditCheckpoint(sequence=latest_leaf.sequence, root=latest_leaf.root)
