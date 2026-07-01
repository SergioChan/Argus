from __future__ import annotations

import unittest

from argus_core import (
    ControlTower,
    DAG,
    DAGCycleError,
    DAGNode,
    InMemoryArtifactStore,
    Lineage,
    NodeResult,
    Producer,
    ProvenanceGateError,
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


if __name__ == "__main__":
    unittest.main()
