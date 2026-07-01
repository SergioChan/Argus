"""S5 Control Tower DAG execution and provenance-gating semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable

from .hashing import hash_json
from .s8 import InMemoryArtifactStore


class S5Error(Exception):
    """Base class for S5 orchestration failures."""


class DAGCycleError(S5Error):
    """Raised when a DAG definition contains a cycle."""


class ProvenanceGateError(S5Error):
    """Raised when a downstream node tries to consume uncommitted or illegal artifacts."""


@dataclass(frozen=True)
class DAGNode:
    node_id: str
    handler: str
    depends_on: tuple[str, ...] = ()
    budget_cost: float = 0.0


@dataclass(frozen=True)
class DAG:
    dag_id: str
    nodes: tuple[DAGNode, ...]


@dataclass(frozen=True)
class NodeResult:
    node_id: str
    status: str
    artifact_refs: tuple[str, ...] = ()
    validation_report_ref: str | None = None
    claim_tier: str = "ran-toy"
    cost_actual: float = 0.0


@dataclass(frozen=True)
class DAGExecutionResult:
    dag_id: str
    status: str
    node_results: tuple[NodeResult, ...]
    preview_hash: str


Handler = Callable[[DAGNode, tuple[NodeResult, ...]], NodeResult]


class ControlTower:
    """In-memory S5 DAG executor with fail-closed provenance gates."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore) -> None:
        self._artifact_store = artifact_store

    def preview_hash(self, dag: DAG) -> str:
        return hash_json(asdict(dag))

    def execute(self, dag: DAG, handlers: dict[str, Handler]) -> DAGExecutionResult:
        order = topological_order(dag)
        results: dict[str, NodeResult] = {}
        for node in order:
            dependencies = tuple(results[dep] for dep in node.depends_on)
            self._assert_dependencies_committed(dependencies)
            result = handlers[node.handler](node, dependencies)
            self._assert_result_legal(result)
            results[node.node_id] = result
            if result.status != "SUCCEEDED":
                return DAGExecutionResult(
                    dag_id=dag.dag_id,
                    status="FAILED",
                    node_results=tuple(results[node.node_id] for node in order if node.node_id in results),
                    preview_hash=self.preview_hash(dag),
                )
        return DAGExecutionResult(
            dag_id=dag.dag_id,
            status="COMPLETED",
            node_results=tuple(results[node.node_id] for node in order),
            preview_hash=self.preview_hash(dag),
        )

    def _assert_dependencies_committed(self, dependencies: tuple[NodeResult, ...]) -> None:
        for dependency in dependencies:
            if dependency.status != "SUCCEEDED":
                raise ProvenanceGateError(f"dependency not successful: {dependency.node_id}")
            for artifact_ref in dependency.artifact_refs:
                self._artifact_store.get_record(artifact_ref)

    @staticmethod
    def _assert_result_legal(result: NodeResult) -> None:
        if result.claim_tier != "ran-toy" and not result.validation_report_ref:
            raise ProvenanceGateError("tier-bearing result requires validation_report_ref")


def topological_order(dag: DAG) -> tuple[DAGNode, ...]:
    nodes = {node.node_id: node for node in dag.nodes}
    ordered: list[DAGNode] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in permanent:
            return
        if node_id in temporary:
            raise DAGCycleError(f"cycle detected at {node_id}")
        temporary.add(node_id)
        for dependency_id in nodes[node_id].depends_on:
            if dependency_id not in nodes:
                raise KeyError(f"unknown dependency: {dependency_id}")
            visit(dependency_id)
        temporary.remove(node_id)
        permanent.add(node_id)
        ordered.append(nodes[node_id])

    for node in dag.nodes:
        visit(node.node_id)
    return tuple(ordered)
