from __future__ import annotations

import json
import unittest

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    EvalRequest,
    GradRequest,
    InMemoryArtifactStore,
    ProvenanceUnavailableError,
    Quantity,
    S7NativePythonBackend,
    S7ProvenanceEmitter,
    SimpleAdapter,
    assert_lineage_complete,
)


class S7ProvenanceEmitterTests(unittest.TestCase):
    def test_evaluate_and_grad_emit_complete_c4_records(self) -> None:
        store = InMemoryArtifactStore()
        emitter = S7ProvenanceEmitter(artifact_store=store)
        backend = S7NativePythonBackend(
            evaluate=lambda inputs, _ctx: {
                "omega": Quantity(
                    value=inputs["alpha"].value * inputs["T_n"].value / 100.0,
                    units="dimensionless",
                    uncertainty={"kind": "interval", "radius": 0.01},
                )
            },
            grad=lambda _inputs, _ctx: {"omega": {"T_n": 0.002, "alpha": 1.0}},
            underlying_code_version="provenance-fixture@1",
        )
        broker = AdapterBroker(artifact_store=store, provenance_emitter=emitter)
        broker.register(
            SimpleAdapter(
                AdapterDescriptor(
                    adapter_id="provenance_fixture",
                    version="1.0.0",
                    input_units={"T_n": "GeV", "alpha": "dimensionless"},
                    output_units={"omega": "dimensionless"},
                    validity_domain={"alpha": (0.0, 1.0)},
                    determinism="deterministic",
                    provenance_ref="c4://adapter/provenance-fixture/v1",
                    differentiable=True,
                ),
                backend=backend,
            )
        )
        inputs = {
            "T_n": Quantity(value=100.0, units="GeV"),
            "alpha": Quantity(value=0.2, units="dimensionless"),
        }

        eval_result = broker.evaluate(
            EvalRequest(
                adapter_id="provenance_fixture",
                inputs=inputs,
                job_seed=7,
                dag_node_id="provenance-node",
                call_index=3,
            )
        )
        grad_result = broker.grad(
            GradRequest(
                adapter_id="provenance_fixture",
                inputs=inputs,
                job_seed=7,
                dag_node_id="provenance-node",
                call_index=4,
            )
        )

        for result, method in ((eval_result, "evaluate"), (grad_result, "grad")):
            record = store.get_record(result.provenance_ref)
            payload = json.loads(store.get_artifact(result.provenance_ref))
            self.assertEqual(record.kind, "log")
            self.assertEqual(record.producer.subsystem, "S7")
            self.assertTrue(assert_lineage_complete(record.lineage).complete)
            self.assertEqual(payload["schema"], "argus.s7.provenance.v1")
            self.assertEqual(payload["method"], method)
            self.assertEqual(payload["adapter_version"], "1.0.0")
            self.assertEqual(payload["underlying_code_version"], "provenance-fixture@1")
            self.assertEqual(payload["seed"], result.seed_used)
            self.assertTrue(payload["config_hash"].startswith("blake3:"))
            self.assertEqual(set(payload["input_hashes"]), {"T_n", "alpha"})
            self.assertTrue(payload["container_digest"].startswith("blake3:"))
            self.assertTrue(payload["environment_digest"].startswith("blake3:"))
            self.assertTrue(payload["unit_registry_version"])
            self.assertTrue(payload["unit_registry_hash"].startswith("blake3:"))
            lineage = store.get_lineage(result.provenance_ref, direction="both")
            self.assertIn(result.provenance_ref, {node.artifact_ref for node in lineage.nodes})

        self.assertEqual(
            json.loads(store.get_artifact(eval_result.provenance_ref))["input_hashes"],
            json.loads(store.get_artifact(grad_result.provenance_ref))["input_hashes"],
        )

    def test_writer_failure_after_compute_is_converted_to_provenance_unavailable(self) -> None:
        class FailingArtifactStore:
            def __init__(self) -> None:
                self.calls = 0

            def create_artifact(self, **_kwargs: object) -> object:
                self.calls += 1
                raise RuntimeError("S8 ledger writer unavailable")

        store = FailingArtifactStore()
        backend_calls = 0

        def evaluate(_inputs: object, _ctx: object) -> dict[str, Quantity]:
            nonlocal backend_calls
            backend_calls += 1
            return {
                "omega": Quantity(
                    value=0.1,
                    units="dimensionless",
                    uncertainty={"kind": "interval", "radius": 0.01},
                )
            }

        broker = AdapterBroker(
            artifact_store=store,  # type: ignore[arg-type]
            provenance_emitter=S7ProvenanceEmitter(artifact_store=store),  # type: ignore[arg-type]
        )
        broker.register(
            SimpleAdapter(
                AdapterDescriptor(
                    adapter_id="writer_failure_fixture",
                    version="1.0.0",
                    input_units={"alpha": "dimensionless"},
                    output_units={"omega": "dimensionless"},
                    validity_domain={"alpha": (0.0, 1.0)},
                    determinism="deterministic",
                    provenance_ref="c4://adapter/writer-failure/v1",
                ),
                backend=S7NativePythonBackend(evaluate=evaluate),
            )
        )

        with self.assertRaises(ProvenanceUnavailableError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="writer_failure_fixture",
                    inputs={"alpha": Quantity(value=0.2, units="dimensionless")},
                )
            )

        self.assertEqual(raised.exception.category, "PROVENANCE_UNAVAILABLE")
        self.assertEqual(backend_calls, 1)
        self.assertEqual(store.calls, 1)


if __name__ == "__main__":
    unittest.main()
