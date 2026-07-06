#!/usr/bin/env python3
"""Run the S2-T26 perf and latency benchmark battery."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import (  # noqa: E402
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    DataManager,
    DataSplitRequest,
    DeterministicLinearTrainingBackend,
    FeatureGraphEngine,
    FeatureGraphNode,
    FeatureNode,
    FeatureTerm,
    HPOEngine,
    HPORequest,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Lineage,
    PipelineFreezeError,
    PipelineFreezeRequest,
    PipelineFreezer,
    Producer,
    ProvenanceEmitter,
    SpecCompiler,
    TrainingRequest,
    TrainingRuntime,
    UQCalibrationRequest,
    UQCalibrationSample,
    UQCalibrator,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hpo-trials", type=int, default=8)
    parser.add_argument("--hpo-workers", type=int, default=4)
    parser.add_argument("--hpo-trial-delay-seconds", type=float, default=2.0)
    parser.add_argument("--hpo-parallel-efficiency", type=float, default=0.7)
    parser.add_argument("--hpo-scheduler-backend", choices=("optuna_ray", "threadpool"), default="optuna_ray")
    parser.add_argument("--setup-latency-slo-seconds", type=float, default=10.0)
    parser.add_argument("--freeze-replay-fraction-slo", type=float, default=0.05)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()

    evidence = _run_battery(
        hpo_trials=args.hpo_trials,
        hpo_workers=args.hpo_workers,
        hpo_trial_delay_seconds=args.hpo_trial_delay_seconds,
        hpo_parallel_efficiency=args.hpo_parallel_efficiency,
        hpo_scheduler_backend=args.hpo_scheduler_backend,
        setup_latency_slo_seconds=args.setup_latency_slo_seconds,
        freeze_replay_fraction_slo=args.freeze_replay_fraction_slo,
    )
    output = json.dumps(evidence, indent=2, sort_keys=True)
    print(output)
    if args.evidence_file is not None:
        args.evidence_file.write_text(output + "\n", encoding="utf-8")
    return 0 if evidence["ok"] else 1


def _run_battery(
    *,
    hpo_trials: int,
    hpo_workers: int,
    hpo_trial_delay_seconds: float,
    hpo_parallel_efficiency: float,
    setup_latency_slo_seconds: float,
    freeze_replay_fraction_slo: float,
    hpo_scheduler_backend: str = "optuna_ray",
) -> dict[str, Any]:
    _assert_positive_int("hpo_trials", hpo_trials)
    _assert_positive_int("hpo_workers", hpo_workers)
    _assert_non_negative_float("hpo_trial_delay_seconds", hpo_trial_delay_seconds)
    _assert_positive_float("hpo_parallel_efficiency", hpo_parallel_efficiency)
    _assert_non_negative_float("setup_latency_slo_seconds", setup_latency_slo_seconds)
    _assert_positive_float("freeze_replay_fraction_slo", freeze_replay_fraction_slo)
    if hpo_scheduler_backend not in {"optuna_ray", "threadpool"}:
        raise ValueError("hpo_scheduler_backend must be optuna_ray or threadpool")

    checks = [
        _check_or_fail(
            "S2-TC34",
            lambda: _run_hpo_worker_scaling(
                hpo_trials=hpo_trials,
                hpo_workers=hpo_workers,
                hpo_trial_delay_seconds=hpo_trial_delay_seconds,
                hpo_parallel_efficiency=hpo_parallel_efficiency,
                hpo_scheduler_backend=hpo_scheduler_backend,
            ),
        ),
        _check_or_fail(
            "S2-TC35",
            lambda: _run_setup_latency(setup_latency_slo_seconds=setup_latency_slo_seconds),
        ),
        _check_or_fail(
            "S2-TC36",
            lambda: _run_freeze_replay_overhead(freeze_replay_fraction_slo=freeze_replay_fraction_slo),
        ),
    ]
    failed = [str(check["test_case"]) for check in checks if not check["ok"]]
    return {
        "ok": not failed,
        "battery": "s2-perf-latency",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "reference_hardware": _reference_hardware(),
        "checks": checks,
        "failed_test_cases": failed,
    }


def _run_hpo_worker_scaling(
    *,
    hpo_trials: int,
    hpo_workers: int,
    hpo_trial_delay_seconds: float,
    hpo_parallel_efficiency: float,
    hpo_scheduler_backend: str,
) -> dict[str, Any]:
    parameter_grid = {"learning_rate": tuple(round(0.01 + 0.01 * index, 5) for index in range(hpo_trials))}
    backend = DeterministicLinearTrainingBackend(delay_seconds=hpo_trial_delay_seconds)

    single = HPOEngine(
        artifact_store=InMemoryArtifactStore(),
        backends={"tabular-baseline": backend},
        worker_count=1,
        scheduler_backend=hpo_scheduler_backend,
    ).run(_hpo_request(parameter_grid=parameter_grid))
    parallel = HPOEngine(
        artifact_store=InMemoryArtifactStore(),
        backends={"tabular-baseline": backend},
        worker_count=hpo_workers,
        scheduler_backend=hpo_scheduler_backend,
    ).run(_hpo_request(parameter_grid=parameter_grid))

    single_succeeded = sum(1 for trial in single.trials if trial.status == "SUCCEEDED")
    parallel_succeeded = sum(1 for trial in parallel.trials if trial.status == "SUCCEEDED")
    threshold = single.wallclock_seconds / (hpo_parallel_efficiency * float(hpo_workers))
    ok = (
        single_succeeded == hpo_trials
        and parallel_succeeded == hpo_trials
        and parallel.wallclock_seconds <= threshold
    )
    return {
        "ok": ok,
        "test_case": "S2-TC34",
        "description": "HPO scales across workers",
        "runtime_path": "HPOEngine.run with real TrainingRuntime trial execution and C4 HPO artifacts",
        "scheduler_backend": parallel.diagnostics["scheduler_backend"],
        "ray_scheduler": parallel.diagnostics.get("ray_scheduler"),
        "scheduled_trials": hpo_trials,
        "worker_count": hpo_workers,
        "hpo_trial_delay_seconds": hpo_trial_delay_seconds,
        "parallel_efficiency": hpo_parallel_efficiency,
        "single_worker_succeeded_trials": single_succeeded,
        "parallel_succeeded_trials": parallel_succeeded,
        "single_worker_wallclock_seconds": single.wallclock_seconds,
        "parallel_wallclock_seconds": parallel.wallclock_seconds,
        "threshold_wallclock_seconds": threshold,
        "single_selection_ref": single.selection_artifact_ref,
        "parallel_selection_ref": parallel.selection_artifact_ref,
    }


def _run_setup_latency(*, setup_latency_slo_seconds: float) -> dict[str, Any]:
    fixture = _ReferenceFixture(job_id="s2-tc35-reference-setup")
    started = time.perf_counter()
    setup = _run_pretraining_setup(fixture)
    elapsed = time.perf_counter() - started
    return {
        "ok": elapsed <= setup_latency_slo_seconds,
        "test_case": "S2-TC35",
        "description": "Build setup latency within seconds",
        "runtime_path": "SpecCompiler.compile + DataManager.create_splits + FeatureGraphEngine.emit_feature_set",
        "setup_wallclock_seconds": elapsed,
        "slo_seconds": setup_latency_slo_seconds,
        "spec_compiler_status": "SUCCEEDED",
        "data_manager_status": "SUCCEEDED",
        "feature_graph_status": "SUCCEEDED",
        "dataset_rows": len(fixture.rows),
        "training_rows": len(setup["training_rows"]),
        "split_manifest_ref": setup["split_manifest_ref"],
        "feature_set_ref": setup["feature_set_ref"],
        "verifier_profile_ref": setup["spec"].verifier_profile_ref,
    }


def _run_freeze_replay_overhead(*, freeze_replay_fraction_slo: float) -> dict[str, Any]:
    fixture = _ReferenceFixture(job_id="s2-tc36-reference-freeze")
    started = time.perf_counter()
    setup = _run_pretraining_setup(fixture)
    training = TrainingRuntime(
        artifact_store=fixture.store,
        provenance_emitter=fixture.emitter,
        backends={"tabular-baseline": DeterministicLinearTrainingBackend(delay_seconds=0.02)},
    ).train(
        TrainingRequest(
            job_id=fixture.job_id,
            family_id="tabular-baseline",
            input_refs=(setup["feature_set_ref"], setup["split_manifest_ref"]),
            training_rows=setup["training_rows"],
            feature_names=("x",),
            target_name="y",
            max_epochs=6,
            learning_rate=0.05,
            code_ref="git:s2-tc36-training",
            environment_digest="oci:s2-tc36-training",
            seed="s2-tc36-training-seed",
        )
    )
    if not training.final_checkpoint_ref:
        raise RuntimeError("S2-TC36 reference training did not emit a model checkpoint")

    calibration = UQCalibrator(artifact_store=fixture.store, provenance_emitter=fixture.emitter).calibrate(
        UQCalibrationRequest(
            job_id=fixture.job_id,
            model_artifact_ref=training.final_checkpoint_ref,
            split_manifest_ref=setup["split_manifest_ref"],
            calibration_input_refs=(setup["split_manifest_ref"],),
            validation_input_refs=(setup["split_manifest_ref"],),
            calibration_samples=_conformal_samples(40, covered_error=0.08),
            validation_samples=_mixed_coverage_samples(
                covered=90,
                uncovered=10,
                covered_error=0.04,
                uncovered_error=0.18,
            ),
            uncertainty_method="split_conformal",
            native_uq="conformal",
            nominal_coverage=0.9,
            coverage_tolerance=0.03,
            nondeterminism_tolerance=0.0,
            replay_output_pairs=((1.0, 1.0),),
            code_ref="git:s2-tc36-uq",
            environment_digest="oci:s2-tc36-uq",
            seed="s2-tc36-uq-seed",
        )
    )
    build_wallclock_seconds = max(time.perf_counter() - started, 1e-9)
    try:
        freeze = PipelineFreezer(artifact_store=fixture.store, provenance_emitter=fixture.emitter).freeze(
            PipelineFreezeRequest(
                job_id=fixture.job_id,
                feature_set_ref=setup["feature_set_ref"],
                model_checkpoint_ref=training.final_checkpoint_ref,
                calibration_artifact_ref=calibration.calibration_artifact_ref,
                input_refs=(fixture.dataset_ref, setup["split_manifest_ref"], training.training_log_ref),
                code_ref="git:s2-tc36-freeze",
                environment_digest="oci:s2-tc36-freeze",
                seed="s2-tc36-freeze-seed",
                container_digest="oci://argus-s2/frozen-pipeline@sha256:s2tc36",
                probe_inputs_units_tagged={"x": {"value": 1.5, "units": "GeV"}},
                output_name="y",
                output_units="GeV",
                build_wallclock_seconds=build_wallclock_seconds,
                max_self_replay_fraction=freeze_replay_fraction_slo,
                config={"runtime": "python-independent-runner", "s2_tc36": True},
            )
        )
    except PipelineFreezeError as exc:
        return {
            "ok": False,
            "test_case": "S2-TC36",
            "description": "Freeze self-replay overhead bounded",
            "runtime_path": "PipelineFreezer.freeze double self-replay before C4 emit",
            "self_replay_passed": False,
            "build_wallclock_seconds": build_wallclock_seconds,
            "slo_fraction": freeze_replay_fraction_slo,
            "error_code": exc.code,
            "error_message": exc.message,
        }

    return {
        "ok": freeze.self_replay_passed and freeze.self_replay_fraction <= freeze_replay_fraction_slo,
        "test_case": "S2-TC36",
        "description": "Freeze self-replay overhead bounded",
        "runtime_path": "PipelineFreezer.freeze double self-replay before C4 emit",
        "self_replay_passed": freeze.self_replay_passed,
        "self_replay_time_seconds": freeze.self_replay_time_seconds,
        "self_replay_fraction": freeze.self_replay_fraction,
        "slo_fraction": freeze_replay_fraction_slo,
        "build_wallclock_seconds": build_wallclock_seconds,
        "frozen_pipeline_ref": freeze.artifact_ref,
        "training_log_ref": training.training_log_ref,
        "uq_calibration_ref": calibration.calibration_artifact_ref,
    }


def _run_pretraining_setup(fixture: "_ReferenceFixture") -> dict[str, Any]:
    spec = fixture.compiler.compile(fixture.c2_payload())
    feature_fields = tuple(field for field in spec.fields if field.role == "feature")
    target_field = next(field for field in spec.fields if field.role == "target")
    split = DataManager(artifact_store=fixture.store, provenance_emitter=fixture.emitter).create_splits(
        DataSplitRequest(
            job_id=fixture.job_id,
            dataset_ref=fixture.dataset_ref,
            split_seed=f"{fixture.job_id}:split",
            train_ratio=0.6,
            validation_ratio=0.2,
            test_ratio=0.2,
            row_id_key="row_id",
            label_key=target_field.name,
            blind_role_key="role",
            blind_roles=("blind",),
            fold_count=3,
            code_ref="git:s2-t26-data-manager",
            environment_digest="oci:s2-t26-data-manager",
        )
    )
    graph = FeatureGraphEngine().build_graph(
        graph_id=f"featuregraph:{fixture.job_id}",
        nodes=tuple(
            FeatureGraphNode(
                node_id=field.name,
                op="source",
                params={"field": field.name},
                feature_node=FeatureNode(
                    node_id=field.name,
                    terms=(FeatureTerm(field_name=field.name, units=field.units),),
                    declared_units=field.units,
                ),
            )
            for field in feature_fields
        ),
    )
    feature_set = FeatureGraphEngine().emit_feature_set(
        graph,
        selected_nodes=tuple(field.name for field in feature_fields),
        emitter=fixture.emitter,
        lineage=Lineage(
            input_refs=(fixture.dataset_ref, split.split_manifest_ref),
            code_ref="git:s2-t26-feature-graph",
            environment_digest="oci:s2-t26-feature-graph",
            seeds=(f"{fixture.job_id}:feature-graph",),
            job_id=fixture.job_id,
        ),
        feature_set_id=f"featureset:{fixture.job_id}",
        replay_probe_input={field.name: fixture.rows[0][field.name] for field in feature_fields},
    )
    return {
        "spec": spec,
        "split_manifest_ref": split.split_manifest_ref,
        "feature_set_ref": feature_set.artifact_record.artifact_ref,
        "training_rows": _training_rows(
            fixture.rows,
            split.split_indices["train"],
            feature_names=tuple(field.name for field in feature_fields),
            target_name=target_field.name,
        ),
    }


class _ReferenceFixture:
    def __init__(self, *, job_id: str) -> None:
        self.job_id = job_id
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.profile_catalog = C3VerifierProfileCatalog(
            (
                C3VerifierProfile(
                    profile_ref="c4://profile/s2-t26-linear/v1",
                    profile_id="s2-t26-linear",
                    version="1.0.0",
                    checks=("setup-latency", "hpo-scale", "freeze-replay"),
                    provenance_ref="c4://profile/s2-t26-linear/v1",
                ),
            )
        )
        self.rows = _dataset_rows()
        self.dataset_ref = self._dataset()
        self.dataset_descriptor_ref = self._dataset_descriptor()
        self._publish_registry_descriptors()
        self.compiler = SpecCompiler(
            verifier_profiles=self.profile_catalog,
            capability_registry=self.registry,
            artifact_store=self.store,
        )

    def c2_payload(self) -> dict[str, Any]:
        return {
            "contract_version": "1.0.0",
            "job_id": self.job_id,
            "root_request_id": f"{self.job_id}:root",
            "trace_id": f"trace:{self.job_id}",
            "subtopic": "s2-t26-reference-linear",
            "problem_spec": {
                "task_type": "regression",
                "observable": "y",
                "target_units": "GeV",
                "inputs_schema": [
                    {"name": "x", "units": "GeV"},
                ],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": "c4://profile/s2-t26-linear/v1",
            "contamination_index_version": "contam-2026-07-01",
            "budget": {
                "max_usd": 10.0,
                "max_wallclock_seconds": 600,
                "max_gpu_seconds": 10.0,
                "max_model_tokens": 1000,
            },
            "constraints": {"max_features": 4},
            "capability_scopes": {
                "allowed_adapters": ["adapter:s2-t26-local-featuregraph"],
                "allowed_datasets": ["dataset:s2-t26-linear"],
                "allowed_egress": [],
            },
            "input_artifact_refs": [self.dataset_descriptor_ref],
        }

    def _dataset(self) -> str:
        return self.store.create_artifact(
            kind="dataset",
            payload={
                "schema": {"features": ["x"], "target": "y"},
                "rows": self.rows,
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id=f"{self.job_id}:dataset"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-t26-dataset",
                environment_digest="oci:s2-t26-dataset",
                job_id=f"{self.job_id}:dataset",
            ),
        ).artifact_ref

    def _dataset_descriptor(self) -> str:
        return self.store.create_artifact(
            kind="dataset_descriptor",
            payload={
                "dataset_id": "dataset:s2-t26-linear",
                "dataset_ref": self.dataset_ref,
                "rows": len(self.rows),
                "schema": {"features": ["x"], "target": "y"},
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id=f"{self.job_id}:descriptor"),
            lineage=Lineage(
                input_refs=(self.dataset_ref,),
                code_ref="git:s2-t26-descriptor",
                environment_digest="oci:s2-t26-descriptor",
                job_id=f"{self.job_id}:descriptor",
            ),
        ).artifact_ref

    def _publish_registry_descriptors(self) -> None:
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="adapter:s2-t26-local-featuregraph",
                revision=1,
                kind="adapter",
                owner_subsystem="S7",
                contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
                trust_class="local",
                capability_scopes=("c6.evaluate",),
                provenance_ref="c4://descriptor/adapter-s2-t26-local-featuregraph/v1",
                subtopics=("s2-t26-reference-linear",),
            )
        )
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="dataset:s2-t26-linear",
                revision=1,
                kind="dataset",
                owner_subsystem="S8",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="local",
                capability_scopes=("c4.read",),
                provenance_ref=self.dataset_descriptor_ref,
                subtopics=("s2-t26-reference-linear",),
            )
        )


def _hpo_request(*, parameter_grid: Mapping[str, tuple[float, ...]]) -> HPORequest:
    return HPORequest(
        job_id="s2-tc34-hpo-scale",
        family_ids=("tabular-baseline",),
        parameter_grid=parameter_grid,
        input_refs=("c4://dataset/s2-tc34-reference/v1",),
        training_rows=tuple({"x": float(index), "y": 1.0 + 2.0 * float(index)} for index in range(8)),
        feature_names=("x",),
        target_name="y",
        max_epochs=1,
        code_ref="git:s2-tc34-hpo-scale",
        environment_digest="oci:s2-tc34-hpo-scale",
        seed="s2-tc34-hpo-scale-seed",
        objective_metric="loss",
        objective="minimize",
    )


def _dataset_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(60):
        x_value = (index - 30) / 10.0
        rows.append(
            {
                "row_id": f"r{index:03d}",
                "x": x_value,
                "y": 1.0 + 2.0 * x_value,
                "role": "train",
            }
        )
    return rows


def _training_rows(
    rows: list[Mapping[str, Any]],
    indices: tuple[int, ...],
    *,
    feature_names: tuple[str, ...],
    target_name: str,
) -> tuple[dict[str, float], ...]:
    training_rows: list[dict[str, float]] = []
    for index in indices:
        row = rows[index]
        training_row = {name: float(row[name]) for name in feature_names}
        training_row[target_name] = float(row[target_name])
        training_rows.append(training_row)
    return tuple(training_rows)


def _conformal_samples(count: int, *, covered_error: float) -> tuple[UQCalibrationSample, ...]:
    return tuple(
        UQCalibrationSample(sample_id=f"c{index}", prediction=float(index), target=float(index) + covered_error)
        for index in range(count)
    )


def _mixed_coverage_samples(
    *,
    covered: int,
    uncovered: int,
    covered_error: float,
    uncovered_error: float,
) -> tuple[UQCalibrationSample, ...]:
    samples = [
        UQCalibrationSample(sample_id=f"v-covered-{index}", prediction=float(index), target=float(index) + covered_error)
        for index in range(covered)
    ]
    samples.extend(
        UQCalibrationSample(
            sample_id=f"v-uncovered-{index}",
            prediction=float(covered + index),
            target=float(covered + index) + uncovered_error,
        )
        for index in range(uncovered)
    )
    return tuple(samples)


def _check_or_fail(test_case: str, run_check: Any) -> dict[str, Any]:
    try:
        return run_check()
    except Exception as exc:  # pragma: no cover - evidence failure path
        return {
            "ok": False,
            "test_case": test_case,
            "description": "benchmark check raised before producing normal evidence",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }


def _assert_positive_int(name: str, value: int) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def _assert_positive_float(name: str, value: float) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def _assert_non_negative_float(name: str, value: float) -> None:
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _git_dirty() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    return bool(result.stdout.strip()) if result.returncode == 0 else True


def _reference_hardware() -> dict[str, Any]:
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }


if __name__ == "__main__":
    sys.exit(main())
