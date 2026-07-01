"""S5 Control Tower DAG execution and provenance-gating semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import Callable

from .hashing import hash_json
from .s8 import InMemoryArtifactStore


class S5Error(Exception):
    """Base class for S5 orchestration failures."""


class DAGCycleError(S5Error):
    """Raised when a DAG definition contains a cycle."""


class ProvenanceGateError(S5Error):
    """Raised when a downstream node tries to consume uncommitted or illegal artifacts."""


class S5BudgetError(S5Error):
    """Raised when S5 budget reservations or reconciliation fail."""


class S5BudgetExceededError(S5BudgetError):
    """Raised when an admission or heartbeat exceeds the S5 budget cap."""


class S5SchedulingError(S5Error):
    """Raised when scheduler policy is invalid."""


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


@dataclass(frozen=True)
class BudgetLedgerEntry:
    node_id: str
    action: str
    amount_usd: Decimal


@dataclass(frozen=True)
class BudgetState:
    cap_usd: Decimal
    reserved_usd: Decimal
    spent_usd: Decimal
    entries: tuple[BudgetLedgerEntry, ...]


@dataclass(frozen=True)
class BudgetHeartbeat:
    node_id: str
    cost_actual_usd: Decimal
    partial_artifact_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class BudgetBreachDecision:
    node_id: str
    should_halt: bool
    reason: str
    partial_artifact_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class TypedNodeError:
    category: str
    code: str
    message: str = ""


@dataclass(frozen=True)
class RetryDecision:
    should_retry: bool
    terminal_status: str
    reason: str
    quarantine: bool = False


@dataclass(frozen=True)
class WorkItem:
    node_id: str
    pool: str
    priority: int = 0
    submitted_at: int = 0
    deadline_at: int | None = None


Handler = Callable[[DAGNode, tuple[NodeResult, ...]], NodeResult]


def money(value: Decimal | int | float | str) -> Decimal:
    return value if isinstance(value, Decimal) else Decimal(str(value))


class BudgetLedger:
    """Exact S5 reserve, reconcile, and release ledger."""

    def __init__(self, *, cap_usd: Decimal | int | float | str) -> None:
        self._cap_usd = money(cap_usd)
        self._spent_usd = Decimal("0")
        self._reservations: dict[str, Decimal] = {}
        self._entries: list[BudgetLedgerEntry] = []

    @property
    def spent_usd(self) -> Decimal:
        return self._spent_usd

    @property
    def reserved_usd(self) -> Decimal:
        return sum(self._reservations.values(), Decimal("0"))

    def reserve(self, node_id: str, amount_usd: Decimal | int | float | str) -> BudgetState:
        amount = money(amount_usd)
        if amount < 0:
            raise S5BudgetError("cannot reserve a negative amount")
        if node_id in self._reservations:
            raise S5BudgetError(f"budget already reserved for node: {node_id}")
        if self._spent_usd + self.reserved_usd + amount > self._cap_usd:
            raise S5BudgetExceededError("budget reservation exceeds cap")
        self._reservations[node_id] = amount
        self._entries.append(BudgetLedgerEntry(node_id=node_id, action="reserve", amount_usd=amount))
        return self.state()

    def reconcile(self, node_id: str, actual_usd: Decimal | int | float | str) -> BudgetState:
        actual = money(actual_usd)
        if actual < 0:
            raise S5BudgetError("cannot reconcile a negative amount")
        if node_id not in self._reservations:
            raise S5BudgetError(f"no active reservation for node: {node_id}")
        reserved = self._reservations.pop(node_id)
        if self._spent_usd + actual > self._cap_usd:
            self._reservations[node_id] = reserved
            raise S5BudgetExceededError("reconciled spend exceeds cap")
        self._spent_usd += actual
        self._entries.append(BudgetLedgerEntry(node_id=node_id, action="reconcile", amount_usd=actual))
        if reserved > actual:
            self._entries.append(
                BudgetLedgerEntry(node_id=node_id, action="release", amount_usd=reserved - actual)
            )
        return self.state()

    def release(self, node_id: str) -> BudgetState:
        if node_id not in self._reservations:
            raise S5BudgetError(f"no active reservation for node: {node_id}")
        reserved = self._reservations.pop(node_id)
        self._entries.append(BudgetLedgerEntry(node_id=node_id, action="release", amount_usd=reserved))
        return self.state()

    def state(self) -> BudgetState:
        return BudgetState(
            cap_usd=self._cap_usd,
            reserved_usd=self.reserved_usd,
            spent_usd=self._spent_usd,
            entries=tuple(self._entries),
        )


class BudgetGovernor:
    """S5 hard-breach detector for metered node heartbeats."""

    def __init__(self, *, max_cost_usd: Decimal | int | float | str, metering_interval_seconds: int) -> None:
        if metering_interval_seconds <= 0:
            raise S5BudgetError("metering interval must be positive")
        self._max_cost_usd = money(max_cost_usd)
        self.metering_interval_seconds = metering_interval_seconds

    def evaluate_heartbeat(self, heartbeat: BudgetHeartbeat) -> BudgetBreachDecision:
        if heartbeat.cost_actual_usd > self._max_cost_usd:
            return BudgetBreachDecision(
                node_id=heartbeat.node_id,
                should_halt=True,
                reason="BUDGET_BREACH",
                partial_artifact_refs=heartbeat.partial_artifact_refs,
            )
        return BudgetBreachDecision(node_id=heartbeat.node_id, should_halt=False, reason="WITHIN_BUDGET")


class RetryPolicy:
    """Retry policy for S5 typed C1/C2/C6 errors."""

    def __init__(self, *, max_attempts: int) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._max_attempts = max_attempts

    def decide(self, error: TypedNodeError, *, attempt_count: int) -> RetryDecision:
        if error.category == "RETRYABLE" and attempt_count < self._max_attempts:
            return RetryDecision(
                should_retry=True,
                terminal_status="RETRYING",
                reason="RETRYABLE",
            )
        if error.category in {"POLICY", "SANDBOX", "BUDGET"}:
            return RetryDecision(
                should_retry=False,
                terminal_status="QUARANTINED",
                reason=error.category,
                quarantine=True,
            )
        return RetryDecision(
            should_retry=False,
            terminal_status="FAILED",
            reason=error.category,
        )


class ConcurrencyGovernor:
    """Deterministic scheduler that respects pool caps and deadline escalation."""

    def __init__(self, *, pool_caps: dict[str, int], deadline_slack_seconds: int = 60) -> None:
        if not pool_caps:
            raise S5SchedulingError("at least one pool cap is required")
        if any(cap < 0 for cap in pool_caps.values()):
            raise S5SchedulingError("pool caps cannot be negative")
        self._pool_caps = dict(pool_caps)
        self._deadline_slack_seconds = deadline_slack_seconds

    def admit(
        self,
        queued: tuple[WorkItem, ...],
        *,
        active_by_pool: dict[str, int],
        now: int,
    ) -> tuple[WorkItem, ...]:
        admitted: list[WorkItem] = []
        active = dict(active_by_pool)
        for item in sorted(queued, key=lambda candidate: self._rank(candidate, now)):
            cap = self._pool_caps.get(item.pool, 0)
            if active.get(item.pool, 0) >= cap:
                continue
            admitted.append(item)
            active[item.pool] = active.get(item.pool, 0) + 1
        return tuple(admitted)

    def _rank(self, item: WorkItem, now: int) -> tuple[int, int, int, int, str]:
        deadline = item.deadline_at if item.deadline_at is not None else 10**18
        urgent = item.deadline_at is not None and item.deadline_at - now <= self._deadline_slack_seconds
        return (0 if urgent else 1, deadline, -item.priority, item.submitted_at, item.node_id)


class ControlTower:
    """In-memory S5 DAG executor with fail-closed provenance gates."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore, budget_ledger: BudgetLedger | None = None) -> None:
        self._artifact_store = artifact_store
        self._budget_ledger = budget_ledger

    def preview_hash(self, dag: DAG) -> str:
        return hash_json(asdict(dag))

    def execute(self, dag: DAG, handlers: dict[str, Handler]) -> DAGExecutionResult:
        order = topological_order(dag)
        results: dict[str, NodeResult] = {}
        for node in order:
            dependencies = tuple(results[dep] for dep in node.depends_on)
            self._assert_dependencies_committed(dependencies)
            self._reserve_budget(node)
            try:
                result = handlers[node.handler](node, dependencies)
                self._assert_result_legal(result)
                self._reconcile_budget(node, result)
            except Exception:
                self._release_budget(node)
                raise
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

    def _reserve_budget(self, node: DAGNode) -> None:
        if self._budget_ledger is not None and node.budget_cost > 0:
            self._budget_ledger.reserve(node.node_id, node.budget_cost)

    def _reconcile_budget(self, node: DAGNode, result: NodeResult) -> None:
        if self._budget_ledger is not None and node.budget_cost > 0:
            self._budget_ledger.reconcile(node.node_id, result.cost_actual)

    def _release_budget(self, node: DAGNode) -> None:
        if self._budget_ledger is not None and node.budget_cost > 0:
            self._budget_ledger.release(node.node_id)


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
