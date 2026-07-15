"""Run the real S7-to-S2 TC21 training slice inside an S10 sandbox."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from typing import Any, Mapping

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    BuildOrchestrationRequest,
    BuildOrchestrator,
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    EvalRequest,
    FrozenPipelineRunner,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Lineage,
    Producer,
    ProvenanceEmitter,
    Quantity,
    SimpleAdapter,
    SpecCompiler,
)
from argus_core.canonical import canonical_json_bytes


OUTPUT_SCHEMA = "argus.s2.isolated-training.v1"
ADAPTER_ID = "adapter:s2-local-featuregraph"
DATASET_ID = "dataset:s2-tc21-linear"
PROFILE_REF = "c4://profile/s2-tc21-linear/v1"
JOB_ID = "33333333-3333-4333-8333-333333333333"
ROOT_REQUEST_ID = "33333333-3333-4333-8333-333333333334"
CODE_REF = "git:project-argus/s2-isolated-training-entrypoint"
ROW_COUNT = 60
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REQUIRED_BUILD_ARTIFACT_KINDS = frozenset(
    {
        "dataset_split",
        "feature_set",
        "hpo_selection",
        "training_log",
        "model_checkpoint",
        "uq_calibration",
        "advisory_self_check",
        "frozen_pipeline",
    }
)


class IsolatedTrainingError(RuntimeError):
    """Raised when the executable TC21 slice cannot produce valid evidence."""


def run_isolated_training(*, container_digest: str) -> dict[str, Any]:
    """Execute S7 data generation, S2 training, freeze, and replay."""

    import optuna

    optuna.logging.set_verbosity(optuna.logging.WARNING)
    normalized_digest = _container_digest(container_digest)
    environment_digest = f"oci://argus/s2-isolated-training@{normalized_digest}"
    store = InMemoryArtifactStore()
    emitter = ProvenanceEmitter(artifact_store=store)
    registry = InMemoryRegistry(artifact_store=store)

    adapter_descriptor_ref = _create_adapter_descriptor(
        store=store,
        environment_digest=environment_digest,
        container_digest=normalized_digest,
    )
    rows, adapter_provenance_refs = _generate_dataset_rows(
        store=store,
        adapter_descriptor_ref=adapter_descriptor_ref,
    )
    dataset_ref = _create_dataset(
        store=store,
        rows=rows,
        adapter_provenance_refs=adapter_provenance_refs,
        environment_digest=environment_digest,
    )
    dataset_descriptor_ref = _create_dataset_descriptor(
        store=store,
        dataset_ref=dataset_ref,
        environment_digest=environment_digest,
    )
    _publish_capabilities(
        registry=registry,
        adapter_descriptor_ref=adapter_descriptor_ref,
        dataset_descriptor_ref=dataset_descriptor_ref,
    )

    profile_catalog = C3VerifierProfileCatalog(
        (
            C3VerifierProfile(
                profile_ref=PROFILE_REF,
                profile_id="s2-tc21-linear",
                version="1.0.0",
                checks=("six-check", "calibration", "freeze-replay"),
                provenance_ref=PROFILE_REF,
            ),
        )
    )
    compiler = SpecCompiler(
        verifier_profiles=profile_catalog,
        capability_registry=registry,
        artifact_store=store,
    )
    orchestrator = BuildOrchestrator(
        artifact_store=store,
        spec_compiler=compiler,
        provenance_emitter=emitter,
        hpo_scheduler_backend="threadpool",
    )
    result = orchestrator.build(
        _build_request(
            dataset_descriptor_ref=dataset_descriptor_ref,
            container_digest=normalized_digest,
            environment_digest=environment_digest,
        )
    )

    frozen_record = store.get_record(result.frozen_pipeline_ref)
    frozen_payload = _json_artifact(store, result.frozen_pipeline_ref)
    prediction = FrozenPipelineRunner(artifact_store=store).predict(
        result.frozen_pipeline_ref,
        {"x": {"value": 1.25, "units": "GeV"}},
    )
    all_records = store.query_artifacts()
    prediction_output = prediction.outputs_units_tagged["y"]
    summary = {
        "schema": OUTPUT_SCHEMA,
        "status": "PASS",
        "diagnostics": {
            "status": result.diagnostics.get("status"),
            "s2_tc21": result.diagnostics.get("s2_tc21"),
            "claim_tier_cap": result.diagnostics.get("claim_tier_cap"),
            "pipeline_freeze": result.diagnostics.get("pipeline_freeze"),
            "sandbox": result.diagnostics.get("sandbox"),
        },
        "claim_tier": result.claim_tier,
        "container_digest": normalized_digest,
        "artifact_count": len(all_records),
        "build_artifact_count": len(result.artifact_refs),
        "artifact_kinds": sorted({record.kind for record in all_records}),
        "build_artifact_kinds": sorted(
            {store.get_record(artifact_ref).kind for artifact_ref in result.artifact_refs}
        ),
        "model_ref": result.model_ref,
        "model_content_hash": store.get_record(result.model_ref).content_hash,
        "frozen_pipeline_ref": result.frozen_pipeline_ref,
        "frozen_pipeline_content_hash": frozen_record.content_hash,
        "frozen_pipeline_lineage": list(frozen_record.lineage.input_refs),
        "uq_calibration_ref": result.uq_calibration_ref,
        "dataset_ref": dataset_ref,
        "dataset_descriptor_ref": dataset_descriptor_ref,
        "dataset_lineage_count": len(store.get_record(dataset_ref).lineage.input_refs),
        "adapter_call_count": len(rows),
        "adapter_provenance_count": len(adapter_provenance_refs),
        "adapter_provenance_refs": list(adapter_provenance_refs),
        "self_replay": frozen_payload.get("self_replay", {}).get("status"),
        "cost_actual": dict(result.cost_actual),
        "prediction": {
            "value": prediction_output["value"],
            "units": prediction_output["units"],
            "uncertainty": dict(prediction.uncertainty),
        },
    }
    _assert_summary(
        summary,
        frozen_payload=frozen_payload,
        expected_adapter_provenance_refs=adapter_provenance_refs,
        dataset_lineage=store.get_record(dataset_ref).lineage.input_refs,
    )
    return summary


def _create_adapter_descriptor(
    *,
    store: InMemoryArtifactStore,
    environment_digest: str,
    container_digest: str,
) -> str:
    return store.create_artifact(
        kind="adapter_descriptor",
        payload={
            "schema": "argus.s7.adapter-descriptor.v1",
            "adapter_id": ADAPTER_ID,
            "version": "1.0.0",
            "input_units": {"x": "GeV"},
            "output_units": {"y": "GeV"},
            "validity_domain": {"x": [-3.0, 2.9]},
            "determinism": "deterministic",
            "container_digest": container_digest,
        },
        producer=Producer(subsystem="S7", version="1.0.0", job_id=JOB_ID),
        lineage=Lineage(
            input_refs=(),
            code_ref=CODE_REF,
            environment_digest=environment_digest,
            seeds=(),
            job_id=JOB_ID,
        ),
    ).artifact_ref


def _generate_dataset_rows(
    *,
    store: InMemoryArtifactStore,
    adapter_descriptor_ref: str,
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    descriptor = AdapterDescriptor(
        adapter_id=ADAPTER_ID,
        version="1.0.0",
        input_units={"x": "GeV"},
        output_units={"y": "GeV"},
        validity_domain={"x": (-3.0, 2.9)},
        determinism="deterministic",
        provenance_ref=adapter_descriptor_ref,
        domain_policy="refuse",
        cost_class="toy",
    )

    def evaluate(inputs: dict[str, Any], _seed: int | None) -> dict[str, Quantity]:
        value = 1.0 + 2.0 * float(inputs["x"].value)
        return {
            "y": Quantity(
                value=value,
                units="GeV",
                uncertainty={
                    "kind": "interval",
                    "radius": 0.01,
                    "source": "s2-tc21-linear-adapter",
                },
            )
        }

    broker = AdapterBroker(artifact_store=store)
    broker.register(SimpleAdapter(descriptor, evaluate))
    rows: list[dict[str, Any]] = []
    provenance_refs: list[str] = []
    for index in range(ROW_COUNT):
        x_value = (index - 30) / 10.0
        evaluation = broker.evaluate(
            EvalRequest(
                adapter_id=ADAPTER_ID,
                inputs={"x": Quantity(value=x_value, units="GeV")},
                job_seed=21021,
                dag_node_id="s2.tc21.dataset",
                call_index=index,
            )
        )
        rows.append(
            {
                "row_id": f"r{index:03d}",
                "x": x_value,
                "y": evaluation.outputs["y"].value,
                "role": "train",
            }
        )
        provenance_refs.append(evaluation.provenance_ref)
    return rows, tuple(provenance_refs)


def _create_dataset(
    *,
    store: InMemoryArtifactStore,
    rows: list[dict[str, Any]],
    adapter_provenance_refs: tuple[str, ...],
    environment_digest: str,
) -> str:
    return store.create_artifact(
        kind="dataset",
        payload={
            "schema": {"features": ["x"], "target": "y"},
            "rows": rows,
        },
        producer=Producer(subsystem="S8", version="1.0.0", job_id=JOB_ID),
        lineage=Lineage(
            input_refs=adapter_provenance_refs,
            code_ref=CODE_REF,
            environment_digest=environment_digest,
            seeds=("21021",),
            job_id=JOB_ID,
        ),
    ).artifact_ref


def _create_dataset_descriptor(
    *,
    store: InMemoryArtifactStore,
    dataset_ref: str,
    environment_digest: str,
) -> str:
    return store.create_artifact(
        kind="dataset_descriptor",
        payload={
            "dataset_id": DATASET_ID,
            "dataset_ref": dataset_ref,
            "rows": ROW_COUNT,
            "schema": {"features": ["x"], "target": "y"},
        },
        producer=Producer(subsystem="S8", version="1.0.0", job_id=JOB_ID),
        lineage=Lineage(
            input_refs=(dataset_ref,),
            code_ref=CODE_REF,
            environment_digest=environment_digest,
            seeds=("21021",),
            job_id=JOB_ID,
        ),
    ).artifact_ref


def _publish_capabilities(
    *,
    registry: InMemoryRegistry,
    adapter_descriptor_ref: str,
    dataset_descriptor_ref: str,
) -> None:
    registry.publish(
        CapabilityDescriptor(
            entity_id=ADAPTER_ID,
            revision=1,
            kind="adapter",
            owner_subsystem="S7",
            contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
            trust_class="local",
            capability_scopes=("c6.evaluate",),
            provenance_ref=adapter_descriptor_ref,
            subtopics=("s2-tc21-classical-baseline",),
        )
    )
    registry.publish(
        CapabilityDescriptor(
            entity_id=DATASET_ID,
            revision=1,
            kind="dataset",
            owner_subsystem="S8",
            contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
            trust_class="local",
            capability_scopes=("c4.read",),
            provenance_ref=dataset_descriptor_ref,
            subtopics=("s2-tc21-classical-baseline",),
        )
    )


def _build_request(
    *,
    dataset_descriptor_ref: str,
    container_digest: str,
    environment_digest: str,
) -> BuildOrchestrationRequest:
    return BuildOrchestrationRequest(
        c2_envelope={
            "contract_version": "1.0.0",
            "job_id": JOB_ID,
            "root_request_id": ROOT_REQUEST_ID,
            "trace_id": "trace-s2-tc21-isolated",
            "subtopic": "s2-tc21-classical-baseline",
            "problem_spec": {
                "task_type": "regression",
                "observable": "y",
                "target_units": "GeV",
                "inputs_schema": [{"name": "x", "units": "GeV"}],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": PROFILE_REF,
            "contamination_index_version": "contam-2026-07-01",
            "budget": {
                "max_usd": 10.0,
                "max_wallclock_seconds": 600,
                "max_gpu_seconds": 10.0,
                "max_model_tokens": 1000,
            },
            "constraints": {"max_features": 4},
            "capability_scopes": {
                "allowed_adapters": [ADAPTER_ID],
                "allowed_datasets": [DATASET_ID],
                "allowed_egress": [],
            },
            "input_artifact_refs": [dataset_descriptor_ref],
        },
        code_ref=CODE_REF,
        environment_digest=environment_digest,
        seed="s2-tc21-isolated-seed",
        hpo_parameter_grid={"learning_rate": (0.02, 0.05)},
        hpo_max_epochs=2,
        final_max_epochs=5,
        train_ratio=0.6,
        validation_ratio=0.2,
        test_ratio=0.2,
        nominal_coverage=0.8,
        coverage_tolerance=0.25,
        max_self_replay_fraction=1.0,
        cost_usd_per_epoch=0.01,
        container_digest=container_digest,
    )


def _assert_summary(
    summary: Mapping[str, Any],
    *,
    frozen_payload: Mapping[str, Any],
    expected_adapter_provenance_refs: tuple[str, ...],
    dataset_lineage: tuple[str, ...],
) -> None:
    if summary.get("diagnostics", {}).get("status") != "SUCCEEDED":
        raise IsolatedTrainingError("S2 build did not succeed")
    if summary.get("diagnostics", {}).get("s2_tc21") != "PASS":
        raise IsolatedTrainingError("S2 TC21 diagnostics did not pass")
    if summary.get("claim_tier") != "ran-toy":
        raise IsolatedTrainingError("S2 claim tier exceeded the isolated toy boundary")
    if len(expected_adapter_provenance_refs) != ROW_COUNT or len(set(expected_adapter_provenance_refs)) != ROW_COUNT:
        raise IsolatedTrainingError("S7 did not emit one unique provenance record per dataset row")
    if dataset_lineage != expected_adapter_provenance_refs:
        raise IsolatedTrainingError("dataset lineage is not bound to every S7 adapter call")
    if not _REQUIRED_BUILD_ARTIFACT_KINDS.issubset(set(summary.get("build_artifact_kinds", ()))):
        raise IsolatedTrainingError("S2 build omitted required artifacts")
    frozen_lineage = set(summary.get("frozen_pipeline_lineage", ()))
    if summary.get("model_ref") not in frozen_lineage or summary.get("uq_calibration_ref") not in frozen_lineage:
        raise IsolatedTrainingError("frozen pipeline lineage omitted model or UQ evidence")
    if frozen_payload.get("container_digest") != summary.get("container_digest"):
        raise IsolatedTrainingError("frozen pipeline is not bound to the executing container digest")
    if summary.get("self_replay") != "PASS":
        raise IsolatedTrainingError("frozen pipeline self-replay failed")
    if float(summary.get("cost_actual", {}).get("cost_usd", 0.0)) <= 0.0:
        raise IsolatedTrainingError("S2 did not meter a positive build cost")
    prediction = summary.get("prediction", {})
    value = float(prediction.get("value", math.nan))
    uncertainty = prediction.get("uncertainty", {})
    lower = float(uncertainty.get("lower", math.nan))
    upper = float(uncertainty.get("upper", math.nan))
    if prediction.get("units") != "GeV" or not all(math.isfinite(item) for item in (lower, value, upper)):
        raise IsolatedTrainingError("frozen pipeline prediction is not finite GeV output")
    if lower > value or upper < value:
        raise IsolatedTrainingError("frozen pipeline uncertainty does not enclose its prediction")


def _json_artifact(store: InMemoryArtifactStore, artifact_ref: str) -> dict[str, Any]:
    payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
    if not isinstance(payload, dict):
        raise IsolatedTrainingError(f"artifact is not a JSON object: {artifact_ref}")
    return payload


def _container_digest(value: str) -> str:
    normalized = value.strip().lower()
    if _DIGEST_PATTERN.fullmatch(normalized) is None:
        raise IsolatedTrainingError("container digest must be sha256:<64 lowercase hex characters>")
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-digest", required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_isolated_training(container_digest=args.container_digest)
    except Exception as exc:
        sys.stderr.write(f"S2_ISOLATED_TRAINING_FAILED: {exc}\n")
        return 2
    sys.stdout.write(canonical_json_bytes(summary).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
