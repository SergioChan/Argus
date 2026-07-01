from __future__ import annotations

import unittest
from decimal import Decimal

from argus_core import (
    BackPressureGovernor,
    BackPressureSignal,
    BudgetBreachDecision,
    BudgetGovernor,
    BudgetHeartbeat,
    BudgetLedger,
    ControlTower,
    ConcurrencyGovernor,
    DAG,
    DAGCycleError,
    DAGNode,
    GuardrailScreen,
    InMemoryArtifactStore,
    Lineage,
    NodeResult,
    Producer,
    ProvenanceGateError,
    ReviewCoordinator,
    RetryPolicy,
    S5BudgetExceededError,
    S5ReviewError,
    TypedNodeError,
    WorkItem,
    topological_order,
)


class S5ControlTowerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.control = ControlTower(artifact_store=self.store)

    def test_topological_order_and_preview_are_deterministic(self) -> None:
        dag = DAG(
            dag_id="dag-1",
            nodes=(
                DAGNode(node_id="verify", handler="verify", depends_on=("build",)),
                DAGNode(node_id="build", handler="build"),
            ),
        )

        order = topological_order(dag)

        self.assertEqual([node.node_id for node in order], ["build", "verify"])
        self.assertEqual(self.control.preview_hash(dag), self.control.preview_hash(dag))

    def test_cycle_is_rejected(self) -> None:
        dag = DAG(
            dag_id="dag-1",
            nodes=(
                DAGNode(node_id="a", handler="a", depends_on=("b",)),
                DAGNode(node_id="b", handler="b", depends_on=("a",)),
            ),
        )

        with self.assertRaises(DAGCycleError):
            topological_order(dag)

    def test_execute_gates_downstream_on_committed_artifact(self) -> None:
        dag = DAG(
            dag_id="dag-1",
            nodes=(
                DAGNode(node_id="build", handler="build"),
                DAGNode(node_id="verify", handler="verify", depends_on=("build",)),
            ),
        )

        def build(_node, _deps):
            artifact = self.store.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:build", environment_digest="oci:build"),
            )
            return NodeResult(node_id="build", status="SUCCEEDED", artifact_refs=(artifact.artifact_ref,))

        def verify(_node, deps):
            self.assertEqual(deps[0].node_id, "build")
            return NodeResult(node_id="verify", status="SUCCEEDED", artifact_refs=())

        result = self.control.execute(dag, {"build": build, "verify": verify})

        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual([node.node_id for node in result.node_results], ["build", "verify"])

    def test_tier_bearing_result_requires_validation_report_ref(self) -> None:
        dag = DAG(dag_id="dag-1", nodes=(DAGNode(node_id="verify", handler="verify"),))

        with self.assertRaises(ProvenanceGateError):
            self.control.execute(
                dag,
                {
                    "verify": lambda _node, _deps: NodeResult(
                        node_id="verify",
                        status="SUCCEEDED",
                        claim_tier="recapitulated-known",
                    )
                },
            )

    def test_missing_dependency_artifact_is_rejected(self) -> None:
        dag = DAG(
            dag_id="dag-1",
            nodes=(
                DAGNode(node_id="build", handler="build"),
                DAGNode(node_id="verify", handler="verify", depends_on=("build",)),
            ),
        )

        with self.assertRaises(KeyError):
            self.control.execute(
                dag,
                {
                    "build": lambda _node, _deps: NodeResult(
                        node_id="build",
                        status="SUCCEEDED",
                        artifact_refs=("c4://artifact/missing",),
                    ),
                    "verify": lambda _node, _deps: NodeResult(node_id="verify", status="SUCCEEDED"),
                },
            )

    def test_budget_ledger_reserve_reconcile_and_release_are_exact(self) -> None:
        ledger = BudgetLedger(cap_usd="100.00")

        state = ledger.reserve("build", "30.00")
        self.assertEqual(state.reserved_usd, Decimal("30.00"))
        self.assertEqual(state.spent_usd, Decimal("0"))

        state = ledger.reconcile("build", "18.25")
        self.assertEqual(state.reserved_usd, Decimal("0"))
        self.assertEqual(state.spent_usd, Decimal("18.25"))
        self.assertEqual(
            [(entry.action, entry.amount_usd) for entry in state.entries],
            [
                ("reserve", Decimal("30.00")),
                ("reconcile", Decimal("18.25")),
                ("release", Decimal("11.75")),
            ],
        )

        state = ledger.reserve("verify", "4.00")
        self.assertEqual(state.reserved_usd, Decimal("4.00"))
        state = ledger.release("verify")
        self.assertEqual(state.reserved_usd, Decimal("0"))
        self.assertEqual(state.spent_usd, Decimal("18.25"))

    def test_budget_reservation_cannot_exceed_cap(self) -> None:
        ledger = BudgetLedger(cap_usd="10")
        ledger.reserve("build", "8")

        with self.assertRaises(S5BudgetExceededError):
            ledger.reserve("verify", "3")

        state = ledger.state()
        self.assertEqual(state.reserved_usd, Decimal("8"))
        self.assertEqual(state.spent_usd, Decimal("0"))

    def test_budget_governor_hard_breach_halts_with_partial_capture(self) -> None:
        governor = BudgetGovernor(max_cost_usd="5.00", metering_interval_seconds=1)

        decision = governor.evaluate_heartbeat(
            BudgetHeartbeat(
                node_id="build",
                cost_actual_usd=Decimal("5.01"),
                partial_artifact_refs=("c4://artifact/partial",),
            )
        )

        self.assertEqual(
            decision,
            BudgetBreachDecision(
                node_id="build",
                should_halt=True,
                reason="BUDGET_BREACH",
                partial_artifact_refs=("c4://artifact/partial",),
            ),
        )
        self.assertEqual(governor.metering_interval_seconds, 1)

    def test_retry_policy_retries_only_retryable_errors(self) -> None:
        policy = RetryPolicy(max_attempts=3)

        retry = policy.decide(
            TypedNodeError(category="RETRYABLE", code="TRANSIENT_ADAPTER"),
            attempt_count=1,
        )
        quarantine = policy.decide(
            TypedNodeError(category="POLICY", code="UNITS_MISMATCH"),
            attempt_count=1,
        )
        exhausted = policy.decide(
            TypedNodeError(category="RETRYABLE", code="TRANSIENT_ADAPTER"),
            attempt_count=3,
        )

        self.assertTrue(retry.should_retry)
        self.assertFalse(quarantine.should_retry)
        self.assertTrue(quarantine.quarantine)
        self.assertEqual(quarantine.terminal_status, "QUARANTINED")
        self.assertFalse(exhausted.should_retry)
        self.assertEqual(exhausted.terminal_status, "FAILED")

    def test_concurrency_governor_respects_caps_and_deadline_escalation(self) -> None:
        governor = ConcurrencyGovernor(pool_caps={"cpu": 2, "gpu": 1}, deadline_slack_seconds=30)
        queued = (
            WorkItem(node_id="normal", pool="cpu", priority=10, submitted_at=1),
            WorkItem(node_id="urgent", pool="cpu", priority=0, submitted_at=2, deadline_at=120),
            WorkItem(node_id="overflow", pool="cpu", priority=100, submitted_at=3),
            WorkItem(node_id="gpu-blocked", pool="gpu", priority=100, submitted_at=1),
        )

        admitted = governor.admit(queued, active_by_pool={"gpu": 1}, now=100)

        self.assertEqual([item.node_id for item in admitted], ["urgent", "overflow"])

    def test_control_tower_reconciles_node_budget(self) -> None:
        ledger = BudgetLedger(cap_usd="10")
        control = ControlTower(artifact_store=self.store, budget_ledger=ledger)
        dag = DAG(dag_id="dag-1", nodes=(DAGNode(node_id="build", handler="build", budget_cost=3.0),))

        result = control.execute(
            dag,
            {"build": lambda _node, _deps: NodeResult(node_id="build", status="SUCCEEDED", cost_actual=2.25)},
        )

        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(ledger.state().reserved_usd, Decimal("0"))
        self.assertEqual(ledger.state().spent_usd, Decimal("2.25"))

    def test_control_tower_releases_budget_when_illegal_result_is_rejected(self) -> None:
        ledger = BudgetLedger(cap_usd="10")
        control = ControlTower(artifact_store=self.store, budget_ledger=ledger)
        dag = DAG(dag_id="dag-1", nodes=(DAGNode(node_id="verify", handler="verify", budget_cost=3.0),))

        with self.assertRaises(ProvenanceGateError):
            control.execute(
                dag,
                {
                    "verify": lambda _node, _deps: NodeResult(
                        node_id="verify",
                        status="SUCCEEDED",
                        claim_tier="recapitulated-known",
                        cost_actual=1.0,
                    )
                },
            )

        self.assertEqual(ledger.state().reserved_usd, Decimal("0"))
        self.assertEqual(ledger.state().spent_usd, Decimal("0"))

    def test_guardrail_blocks_empirical_claim_before_running(self) -> None:
        decision = GuardrailScreen().screen(
            objective_nl="Empirically confirm a new theory from this autonomous run."
        )

        self.assertFalse(decision.passed)
        self.assertEqual(decision.rule_id, "NO_EMPIRICAL_CLAIM")
        self.assertIsNotNone(decision.event)
        self.assertEqual(decision.event.action, "BLOCK")

    def test_guardrail_blocks_autonomous_paper_submission_action(self) -> None:
        decision = GuardrailScreen().screen(
            objective_nl="Build a recapitulation model.",
            attempted_action="submit paper to arxiv",
        )

        self.assertFalse(decision.passed)
        self.assertEqual(decision.rule_id, "NO_AUTO_PAPER_SUBMIT")

    def test_review_wait_state_pauses_and_resumes_on_approval(self) -> None:
        coordinator = ReviewCoordinator()
        wait = coordinator.open_wait(
            node_id="novel-node",
            reason="NOVEL_CANDIDATE",
            artifact_refs=("c4://artifact/a", "c4://artifact/b"),
        )
        duplicate = coordinator.open_wait(
            node_id="novel-node",
            reason="NOVEL_CANDIDATE",
            artifact_refs=("c4://artifact/b", "c4://artifact/a"),
        )

        self.assertEqual(wait, duplicate)
        self.assertEqual(wait.status, "PENDING")

        resolved = coordinator.resolve(wait.wait_id, approved=True)

        self.assertEqual(resolved.status, "APPROVED")
        self.assertTrue(resolved.resume_signal_sent)
        with self.assertRaises(S5ReviewError):
            coordinator.resolve(wait.wait_id, approved=True)

    def test_review_rejection_prunes_branch_without_resume_signal(self) -> None:
        coordinator = ReviewCoordinator()
        wait = coordinator.open_wait(node_id="novel-node", reason="NOVEL_CANDIDATE")

        resolved = coordinator.resolve(wait.wait_id, approved=False)

        self.assertEqual(resolved.status, "REJECTED")
        self.assertFalse(resolved.resume_signal_sent)

    def test_backpressure_throttles_review_bound_work_only(self) -> None:
        governor = BackPressureGovernor(review_queue_threshold=10, retry_after_seconds=60)

        review_signal = governor.decide(review_queue_depth=10, requires_review=True)
        ordinary_signal = governor.decide(review_queue_depth=10, requires_review=False)

        self.assertEqual(review_signal, BackPressureSignal(active=True, reason="THROTTLED", retry_after_seconds=60))
        self.assertEqual(ordinary_signal, BackPressureSignal(active=False))


if __name__ == "__main__":
    unittest.main()
