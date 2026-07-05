from __future__ import annotations

import json
import unittest

from argus_core import (
    DimensionalError,
    FeatureGraphEngine,
    FeatureGraphNode,
    FeatureNode,
    FeatureTerm,
    InMemoryArtifactStore,
    Lineage,
    Producer,
    ProvenanceEmitter,
    S2ContractModelError,
)


class S2FeatureGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.engine = FeatureGraphEngine()

    def test_feature_graph_is_content_addressed_and_replays_deterministically(self) -> None:
        temperature = self._source("temperature", "GeV")
        mass_scale = self._source("mass_scale", "GeV")
        ratio = FeatureGraphNode(
            node_id="temperature_ratio",
            op="pi_group",
            inputs=("temperature", "mass_scale"),
            params={"basis": "T_over_M"},
            feature_node=FeatureNode(
                node_id="temperature_ratio",
                terms=(
                    FeatureTerm(field_name="temperature", units="GeV"),
                    FeatureTerm(field_name="mass_scale", units="GeV", exponent=-1),
                ),
                declared_units="dimensionless",
            ),
        )

        graph = self.engine.build_graph(
            graph_id="featuregraph:gwp",
            nodes=(ratio, temperature, mass_scale),
        )
        same_graph = self.engine.build_graph(
            graph_id="featuregraph:gwp",
            nodes=(mass_scale, ratio, temperature),
        )

        self.assertEqual(graph.content_hash, same_graph.content_hash)
        self.assertEqual(tuple(node.node_id for node in graph.nodes), ("mass_scale", "temperature", "temperature_ratio"))
        self.assertTrue(all(node.out_dim is not None for node in graph.nodes))

        first = self.engine.replay(
            graph,
            inputs={"temperature": 120.0, "mass_scale": 60.0},
            selected_nodes=("temperature_ratio",),
        )
        second = self.engine.replay(
            same_graph,
            inputs={"mass_scale": 60.0, "temperature": 120.0},
            selected_nodes=("temperature_ratio",),
        )

        self.assertEqual(first.values, {"temperature_ratio": 2.0})
        self.assertEqual(first.content_hash, second.content_hash)

    def test_dimensionally_invalid_node_fails_closed_before_c4_write(self) -> None:
        invalid = FeatureGraphNode(
            node_id="bad_energy_length",
            op="arithmetic",
            feature_node=FeatureNode(
                node_id="bad_energy_length",
                terms=(
                    FeatureTerm(field_name="temperature", units="GeV"),
                    FeatureTerm(field_name="baseline", units="m"),
                ),
                declared_units="dimensionless",
            ),
        )

        with self.assertRaises(DimensionalError) as raised:
            self.engine.build_graph(graph_id="featuregraph:bad", nodes=(invalid,))

        self.assertEqual(raised.exception.node_id, "bad_energy_length")
        self.assertEqual(len(self.store), 0)

    def test_feature_graph_rejects_non_replayable_topologies(self) -> None:
        with self.subTest("missing dependency"):
            with self.assertRaises(S2ContractModelError):
                self.engine.build_graph(
                    graph_id="featuregraph:missing",
                    nodes=(
                        FeatureGraphNode(
                            node_id="temperature_square",
                            op="arithmetic",
                            inputs=("temperature",),
                            feature_node=FeatureNode(
                                node_id="temperature_square",
                                terms=(FeatureTerm(field_name="temperature", units="GeV", exponent=2),),
                                declared_units="GeV^2",
                            ),
                        ),
                    ),
                )

        with self.subTest("cycle"):
            with self.assertRaises(S2ContractModelError):
                self.engine.build_graph(
                    graph_id="featuregraph:cycle",
                    nodes=(
                        FeatureGraphNode(
                            node_id="a",
                            op="arithmetic",
                            inputs=("b",),
                            feature_node=FeatureNode(
                                node_id="a",
                                terms=(FeatureTerm(field_name="b", units="dimensionless"),),
                                declared_units="dimensionless",
                            ),
                        ),
                        FeatureGraphNode(
                            node_id="b",
                            op="arithmetic",
                            inputs=("a",),
                            feature_node=FeatureNode(
                                node_id="b",
                                terms=(FeatureTerm(field_name="a", units="dimensionless"),),
                                declared_units="dimensionless",
                            ),
                        ),
                    ),
                )

        with self.subTest("nondeterministic node"):
            with self.assertRaises(S2ContractModelError):
                self.engine.build_graph(
                    graph_id="featuregraph:nondeterministic",
                    nodes=(
                        FeatureGraphNode(
                            node_id="temperature",
                            op="source",
                            deterministic=False,
                            params={"field": "temperature"},
                            feature_node=FeatureNode(
                                node_id="temperature",
                                terms=(FeatureTerm(field_name="temperature", units="GeV"),),
                                declared_units="GeV",
                            ),
                        ),
                    ),
                )

    def test_feature_set_emits_c4_artifact_with_complete_lineage_and_checked_dimensions(self) -> None:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [{"temperature": 120.0, "mass_scale": 60.0}]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:fixture", environment_digest="oci:fixture"),
        )
        emitter = ProvenanceEmitter(artifact_store=self.store)
        graph = self.engine.build_graph(
            graph_id="featuregraph:gwp",
            nodes=(
                self._source("temperature", "GeV"),
                self._source("mass_scale", "GeV"),
                FeatureGraphNode(
                    node_id="temperature_ratio",
                    op="pi_group",
                    inputs=("temperature", "mass_scale"),
                    params={"basis": "T_over_M"},
                    feature_node=FeatureNode(
                        node_id="temperature_ratio",
                        terms=(
                            FeatureTerm(field_name="temperature", units="GeV"),
                            FeatureTerm(field_name="mass_scale", units="GeV", exponent=-1),
                        ),
                        declared_units="dimensionless",
                    ),
                ),
            ),
        )

        result = self.engine.emit_feature_set(
            graph,
            selected_nodes=("temperature_ratio",),
            emitter=emitter,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:featuregraph",
                environment_digest="oci:featuregraph",
                seeds=("seed:7",),
                job_id="job-featuregraph",
            ),
            feature_set_id="featureset:gwp",
            replay_probe_input={"temperature": 120.0, "mass_scale": 60.0},
        )
        record = self.store.get_record(result.artifact_record.artifact_ref)
        payload = json.loads(self.store.get_artifact(record.artifact_ref).decode("utf-8"))

        self.assertEqual(record.kind, "feature_set")
        self.assertEqual(record.claim_tier, "ran-toy")
        self.assertEqual(record.lineage.input_refs, (dataset.artifact_ref,))
        self.assertEqual(record.lineage.code_ref, "git:featuregraph")
        self.assertEqual(record.lineage.environment_digest, "oci:featuregraph")
        self.assertEqual(payload["graph"]["content_hash"], graph.content_hash)
        self.assertEqual(payload["feature_set"]["content_hash"], result.feature_set.content_hash)
        self.assertEqual(payload["feature_set"]["selected_nodes"], ["temperature_ratio"])
        self.assertEqual(payload["replay_probe"]["values"], {"temperature_ratio": 2.0})
        checked_ratio = payload["graph"]["nodes"][2]["out_dim"]
        self.assertEqual(checked_ratio["units"], "dimensionless")
        self.assertEqual(checked_ratio["exponents"], [0, 0, 0, 0, 0, 0])

    @staticmethod
    def _source(field_name: str, units: str) -> FeatureGraphNode:
        return FeatureGraphNode(
            node_id=field_name,
            op="source",
            params={"field": field_name},
            feature_node=FeatureNode(
                node_id=field_name,
                terms=(FeatureTerm(field_name=field_name, units=units),),
                declared_units=units,
            ),
        )


if __name__ == "__main__":
    unittest.main()
