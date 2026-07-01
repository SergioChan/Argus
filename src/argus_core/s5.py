"""S5 Control Tower DAG execution and provenance-gating semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import Any, Callable, Mapping

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


class S5ReviewError(S5Error):
    """Raised when S5 review wait-state transitions are invalid."""


class C2ContractError(S5Error):
    """Raised when a C2 envelope cannot be accepted by this runtime."""

    def __init__(self, error: "TypedNodeError") -> None:
        super().__init__(error.message or error.code)
        self.error = error


@dataclass(frozen=True)
class C2JobEnvelope:
    contract_version: str
    job_id: str
    root_request_id: str
    trace_id: str
    subtopic: str
    required_claim_tier_max: str
    verifier_profile_ref: str
    budget: dict[str, Any]
    capability_scopes: dict[str, Any]
    parent_job_id: str | None = None
    problem_spec: dict[str, Any] | None = None
    contamination_index_version: str | None = None
    input_artifact_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class C2MigrationWindow:
    """Temporary dual-serve policy for one legacy C2 major during a runtime upgrade."""

    legacy_major: int
    runtime_major: int
    opens_at: int = 0
    hard_cutoff_at: int | None = None

    def __post_init__(self) -> None:
        if self.legacy_major < 0 or self.runtime_major < 0:
            raise ValueError("C2 major versions must be non-negative")
        if self.legacy_major == self.runtime_major:
            raise ValueError("C2 migration windows must bridge different major versions")
        if self.hard_cutoff_at is not None and self.hard_cutoff_at <= self.opens_at:
            raise ValueError("C2 hard cutoff must be later than the window opening")

    def supports(self, *, contract_major: int, runtime_major: int, now: int) -> bool:
        return (
            contract_major == self.legacy_major
            and runtime_major == self.runtime_major
            and self.opens_at <= now
            and (self.hard_cutoff_at is None or now < self.hard_cutoff_at)
        )


@dataclass(frozen=True)
class C2VersionPolicy:
    """Runtime C2 version compatibility rules.

    Same-major C2 envelopes are always accepted. Cross-major envelopes require an
    explicit migration window and are rejected once the window reaches hard cutoff.
    """

    migration_windows: tuple[C2MigrationWindow, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "migration_windows", tuple(self.migration_windows))

    def supports(self, contract_version: str, *, runtime_version: str, now: int = 0) -> bool:
        contract_major = _semver_major(contract_version)
        runtime_major = _semver_major(runtime_version)
        if contract_major == runtime_major:
            return True
        return any(
            window.supports(contract_major=contract_major, runtime_major=runtime_major, now=now)
            for window in self.migration_windows
        )

    def require_supported(self, contract_version: str, *, runtime_version: str, now: int = 0) -> None:
        if not self.supports(contract_version, runtime_version=runtime_version, now=now):
            raise _unsupported_c2_version_error(
                contract_version,
                runtime_version,
                detail="outside active C2 migration window",
            )


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


@dataclass(frozen=True)
class GuardrailEvent:
    rule_id: str
    action: str
    reason: str
    objective_nl: str


@dataclass(frozen=True)
class GuardrailDecision:
    passed: bool
    rule_id: str | None = None
    reason: str | None = None
    event: GuardrailEvent | None = None


@dataclass(frozen=True)
class ReviewWaitState:
    wait_id: str
    node_id: str
    reason: str
    status: str
    artifact_refs: tuple[str, ...] = ()
    resume_signal_sent: bool = False


@dataclass(frozen=True)
class BackPressureSignal:
    active: bool
    reason: str = "OK"
    retry_after_seconds: int = 0


Handler = Callable[[DAGNode, tuple[NodeResult, ...]], NodeResult]


def parse_c2_job_envelope(
    payload: Mapping[str, Any],
    *,
    runtime_version: str = "1.0.0",
    version_policy: C2VersionPolicy | None = None,
    now: int = 0,
) -> C2JobEnvelope:
    contract_version = str(payload.get("contract_version", ""))
    policy = version_policy or C2VersionPolicy()
    policy.require_supported(contract_version, runtime_version=runtime_version, now=now)

    values = {name: payload[name] for name in C2_JOB_ENVELOPE_FIELDS if name in payload}
    if "input_artifact_refs" in values:
        values["input_artifact_refs"] = tuple(values["input_artifact_refs"])
    try:
        return C2JobEnvelope(**values)
    except TypeError as exc:
        raise C2ContractError(
            TypedNodeError(
                category="PERMANENT",
                code="SCHEMA_INVALID",
                message=f"invalid C2 JobEnvelope payload: {exc}",
            )
        ) from exc


C2_JOB_ENVELOPE_FIELDS = frozenset(C2JobEnvelope.__dataclass_fields__)


def money(value: Decimal | int | float | str) -> Decimal:
    return value if isinstance(value, Decimal) else Decimal(str(value))


def _semver_major(version: str) -> int:
    try:
        return int(version.split(".", 1)[0])
    except (ValueError, IndexError) as exc:
        raise C2ContractError(
            TypedNodeError(
                category="PERMANENT",
                code="VERSION_UNSUPPORTED",
                message=f"invalid C2 semver: {version}",
            )
        ) from exc


def _unsupported_c2_version_error(contract_version: str, runtime_version: str, *, detail: str = "") -> C2ContractError:
    suffix = f": {detail}" if detail else ""
    return C2ContractError(
        TypedNodeError(
            category="PERMANENT",
            code="VERSION_UNSUPPORTED",
            message=f"C2 major version {contract_version!r} is not supported by runtime {runtime_version}{suffix}",
        )
    )


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


class GuardrailScreen:
    """Deterministic S5 non-goal guardrail screen for intake and execution."""

    _RULES: tuple[tuple[str, tuple[str, ...], str], ...] = (
        (
            "NO_EMPIRICAL_CLAIM",
            ("empirically confirm", "empirical validation", "confirm a new theory"),
            "autonomous empirical validation is out of scope",
        ),
        (
            "NO_AUTO_PAPER_SUBMIT",
            ("submit paper", "paper submission", "submit to arxiv", "arxiv submission"),
            "autonomous paper submission is out of scope",
        ),
        (
            "NO_FLAGSHIP_HPC",
            ("flagship hpc", "frontier supercomputer", "exascale run"),
            "flagship HPC execution is out of scope",
        ),
    )

    def screen(self, *, objective_nl: str, attempted_action: str | None = None) -> GuardrailDecision:
        text = f"{objective_nl} {attempted_action or ''}".lower()
        for rule_id, needles, reason in self._RULES:
            if any(needle in text for needle in needles):
                return GuardrailDecision(
                    passed=False,
                    rule_id=rule_id,
                    reason=reason,
                    event=GuardrailEvent(
                        rule_id=rule_id,
                        action="BLOCK",
                        reason=reason,
                        objective_nl=objective_nl,
                    ),
                )
        return GuardrailDecision(passed=True)


class ReviewCoordinator:
    """S9-compatible in-memory wait-state coordinator used by M2 S5 stubs."""

    def __init__(self) -> None:
        self._waits: dict[str, ReviewWaitState] = {}
        self._wait_ids_by_key: dict[tuple[str, str, tuple[str, ...]], str] = {}

    def open_wait(self, *, node_id: str, reason: str, artifact_refs: tuple[str, ...] = ()) -> ReviewWaitState:
        key = (node_id, reason, tuple(sorted(artifact_refs)))
        if key in self._wait_ids_by_key:
            return self._waits[self._wait_ids_by_key[key]]
        wait_id = "s5-review-" + hash_json({"node_id": node_id, "reason": reason, "artifact_refs": key[2]})[:16]
        wait = ReviewWaitState(
            wait_id=wait_id,
            node_id=node_id,
            reason=reason,
            status="PENDING",
            artifact_refs=key[2],
        )
        self._wait_ids_by_key[key] = wait_id
        self._waits[wait_id] = wait
        return wait

    def resolve(self, wait_id: str, *, approved: bool) -> ReviewWaitState:
        if wait_id not in self._waits:
            raise S5ReviewError(f"unknown review wait state: {wait_id}")
        wait = self._waits[wait_id]
        if wait.status != "PENDING":
            raise S5ReviewError(f"review wait state already resolved: {wait_id}")
        resolved = ReviewWaitState(
            wait_id=wait.wait_id,
            node_id=wait.node_id,
            reason=wait.reason,
            status="APPROVED" if approved else "REJECTED",
            artifact_refs=wait.artifact_refs,
            resume_signal_sent=approved,
        )
        self._waits[wait_id] = resolved
        return resolved


class BackPressureGovernor:
    """Review-capacity gate that throttles review-bound work while allowing ordinary nodes."""

    def __init__(self, *, review_queue_threshold: int, retry_after_seconds: int) -> None:
        if review_queue_threshold < 0:
            raise S5SchedulingError("review queue threshold cannot be negative")
        if retry_after_seconds < 0:
            raise S5SchedulingError("retry_after_seconds cannot be negative")
        self._review_queue_threshold = review_queue_threshold
        self._retry_after_seconds = retry_after_seconds

    def decide(self, *, review_queue_depth: int, requires_review: bool) -> BackPressureSignal:
        if requires_review and review_queue_depth >= self._review_queue_threshold:
            return BackPressureSignal(
                active=True,
                reason="THROTTLED",
                retry_after_seconds=self._retry_after_seconds,
            )
        return BackPressureSignal(active=False)


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
