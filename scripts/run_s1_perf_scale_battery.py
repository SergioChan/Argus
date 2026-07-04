#!/usr/bin/env python3
"""Run the S1-T29 perf and scale battery."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import (
    ExecContext,
    InMemoryArtifactStore,
    JobEnvelope,
    LifecycleState,
    LifecycleStore,
    Subagent,
    SubagentDescriptor,
    SubagentRuntime,
    SubagentSDKRunner,
)
from argus_core.s1 import S1_LIFECYCLE_LEDGER_KIND


METHOD_SEQUENCE = ("accept", "plan", "build", "validate", "report")


class PerfSubagent(Subagent):
    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, Any]:
        return {
            "steps": [
                {
                    "step_id": "noop",
                    "kind": "analysis",
                    "description": "No-op perf plan",
                    "est_cost": {"cost_usd": envelope.estimated_cost},
                }
            ],
            "risk_notes": [],
        }

    def build(self, ctx: ExecContext, plan: dict[str, Any]) -> dict[str, Any]:
        return {
            "artifact_refs": [f"c4://artifact/{ctx.job_id}/model"],
            "diagnostics": {"plan_hash": plan.get("plan_hash")},
            "self_checks": [{"type": "perf-smoke", "status": "PASS", "advisory": True}],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequential-jobs", type=int, default=1000)
    parser.add_argument("--concurrent-jobs", type=int, default=200)
    parser.add_argument("--scale-events", type=int, default=100_000)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--accept-plan-slo-seconds", type=float, default=3.0)
    parser.add_argument("--state-query-slo-seconds", type=float, default=0.5)
    parser.add_argument("--max-workers", type=int, default=32)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()

    evidence = _run_battery(
        sequential_jobs=args.sequential_jobs,
        concurrent_jobs=args.concurrent_jobs,
        scale_events=args.scale_events,
        samples=args.samples,
        accept_plan_slo_seconds=args.accept_plan_slo_seconds,
        state_query_slo_seconds=args.state_query_slo_seconds,
        max_workers=args.max_workers,
    )
    output = json.dumps(evidence, indent=2, sort_keys=True)
    print(output)
    if args.evidence_file is not None:
        args.evidence_file.write_text(output + "\n", encoding="utf-8")
    return 0 if evidence["ok"] else 1


def _run_battery(
    *,
    sequential_jobs: int,
    concurrent_jobs: int,
    scale_events: int,
    samples: int,
    accept_plan_slo_seconds: float,
    state_query_slo_seconds: float,
    max_workers: int,
) -> dict[str, Any]:
    _assert_positive("sequential_jobs", sequential_jobs)
    _assert_positive("concurrent_jobs", concurrent_jobs)
    _assert_positive("scale_events", scale_events)
    _assert_positive("samples", samples)
    _assert_positive("max_workers", max_workers)
    if scale_events % len(METHOD_SEQUENCE) != 0:
        raise ValueError(f"scale_events must be divisible by {len(METHOD_SEQUENCE)}")

    checks = [
        _run_accept_plan_latency(
            sequential_jobs=sequential_jobs,
            slo_seconds=accept_plan_slo_seconds,
        ),
        _run_concurrency_scaling(
            concurrent_jobs=concurrent_jobs,
            max_workers=max_workers,
        ),
        _run_lifecycle_store_scale(
            scale_events=scale_events,
            samples=samples,
            slo_seconds=state_query_slo_seconds,
        ),
    ]
    failed = [str(check["test_case"]) for check in checks if not check["ok"]]
    return {
        "ok": not failed,
        "battery": "s1-perf-scale",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "checks": checks,
        "failed_test_cases": failed,
    }


def _run_accept_plan_latency(*, sequential_jobs: int, slo_seconds: float) -> dict[str, Any]:
    descriptor = _perf_descriptor()
    runner = SubagentSDKRunner(PerfSubagent(descriptor), runtime=SubagentRuntime(descriptor=descriptor))
    accept_samples: list[float] = []
    plan_samples: list[float] = []
    combined_samples: list[float] = []
    accepted_jobs = 0
    planned_jobs = 0

    for index in range(sequential_jobs):
        envelope = _perf_envelope("s1-tc33", index)
        started = time.perf_counter()
        accept_started = time.perf_counter()
        acceptance = runner.accept(envelope)
        accept_samples.append(time.perf_counter() - accept_started)
        if acceptance.accepted:
            accepted_jobs += 1
        plan_started = time.perf_counter()
        planned = runner.plan(envelope)
        plan_samples.append(time.perf_counter() - plan_started)
        combined_samples.append(time.perf_counter() - started)
        if planned.event.to_state == LifecycleState.PLANNING:
            planned_jobs += 1

    event_log_consistent = True
    for index in range(sequential_jobs):
        job_id = _job_id("s1-tc33", index)
        if [event.method for event in runner.runtime.store.events(job_id)] != ["accept", "plan"]:
            event_log_consistent = False
            break

    accept_plan_p95 = _percentile(combined_samples, 0.95)
    ok = (
        accepted_jobs == sequential_jobs
        and planned_jobs == sequential_jobs
        and event_log_consistent
        and accept_plan_p95 <= slo_seconds
    )
    return {
        "ok": ok,
        "test_case": "S1-TC-33",
        "description": "perf accept()/plan() latency",
        "runtime_path": "SubagentSDKRunner.accept/plan with real LifecycleStore and C4 mirror",
        "adapters_registry": "deterministic in-memory descriptor/envelope; no external adapter or registry I/O",
        "sequential_jobs": sequential_jobs,
        "accepted_jobs": accepted_jobs,
        "planned_jobs": planned_jobs,
        "event_log_consistent": event_log_consistent,
        "slo_seconds": slo_seconds,
        "accept_plan_p95_seconds": accept_plan_p95,
        "accept_p95_seconds": _percentile(accept_samples, 0.95),
        "plan_p95_seconds": _percentile(plan_samples, 0.95),
        "accept_plan_max_seconds": max(combined_samples),
    }


def _run_concurrency_scaling(*, concurrent_jobs: int, max_workers: int) -> dict[str, Any]:
    artifact_store = InMemoryArtifactStore()
    store = LifecycleStore(artifact_store=artifact_store)
    failures: list[str] = []
    completed_jobs: list[str] = []
    started = time.perf_counter()

    def run_job(index: int) -> str:
        job_id = _job_id("s1-tc34", index)
        store.create_job(job_id)
        for method in METHOD_SEQUENCE:
            store.apply_method(
                job_id,
                method,
                trigger="s1-t29-concurrency",
                payload={"job_id": job_id, "method": method},
            )
        return job_id

    with ThreadPoolExecutor(max_workers=min(max_workers, concurrent_jobs)) as executor:
        futures = [executor.submit(run_job, index) for index in range(concurrent_jobs)]
        for future in as_completed(futures):
            try:
                completed_jobs.append(future.result())
            except Exception as exc:  # pragma: no cover - failure evidence path
                failures.append(f"{type(exc).__name__}: {exc}")

    elapsed = time.perf_counter() - started
    terminal_jobs = 0
    event_log_consistent = True
    lifecycle_artifacts = 0
    for job_id in completed_jobs:
        current = store.current(job_id)
        events = store.events(job_id)
        refs = store.ledger_refs(job_id)
        lifecycle_artifacts += len(refs)
        terminal_jobs += int(current.state == LifecycleState.REPORTED)
        if [event.method for event in events] != list(METHOD_SEQUENCE):
            event_log_consistent = False
        if [event.sequence for event in events] != list(range(1, len(METHOD_SEQUENCE) + 1)):
            event_log_consistent = False
        if len(refs) != len(METHOD_SEQUENCE):
            event_log_consistent = False

    ok = (
        terminal_jobs == concurrent_jobs
        and not failures
        and event_log_consistent
        and lifecycle_artifacts == concurrent_jobs * len(METHOD_SEQUENCE)
    )
    return {
        "ok": ok,
        "test_case": "S1-TC-34",
        "description": "perf concurrency scaling",
        "runtime_path": "Concurrent LifecycleStore.apply_method over real C4 mirrored lifecycle events",
        "concurrent_jobs": concurrent_jobs,
        "max_workers": min(max_workers, concurrent_jobs),
        "terminal_jobs": terminal_jobs,
        "failures": failures,
        "event_log_consistent": event_log_consistent,
        "total_events": sum(len(store.events(job_id)) for job_id in completed_jobs),
        "lifecycle_artifacts": lifecycle_artifacts,
        "elapsed_seconds": elapsed,
    }


def _run_lifecycle_store_scale(*, scale_events: int, samples: int, slo_seconds: float) -> dict[str, Any]:
    scale_jobs = scale_events // len(METHOD_SEQUENCE)
    sample_count = min(samples, scale_jobs)
    artifact_store = InMemoryArtifactStore()
    store = LifecycleStore(artifact_store=artifact_store)

    load_started = time.perf_counter()
    for index in range(scale_jobs):
        job_id = _job_id("s1-tc35", index)
        store.create_job(job_id)
        for method in METHOD_SEQUENCE:
            store.apply_method(
                job_id,
                method,
                trigger="s1-t29-scale",
                payload={"job_id": job_id, "method": method, "index": index},
            )
    load_elapsed = time.perf_counter() - load_started

    drift_count = 0
    lifecycle_artifacts = 0
    for index in range(scale_jobs):
        job_id = _job_id("s1-tc35", index)
        lifecycle_artifacts += len(store.ledger_refs(job_id))
        if store.replay(job_id) != store.current(job_id):
            drift_count += 1

    sample_indexes = _sample_indexes(scale_jobs, sample_count)
    query_samples: list[float] = []
    sampled_terminal_jobs = 0
    sampled_ledger_refs = 0
    sampled_bad_artifact_kinds = 0
    for index in sample_indexes:
        job_id = _job_id("s1-tc35", index)
        started = time.perf_counter()
        current = store.current(job_id)
        ledger_refs = store.ledger_refs(job_id)
        last_record = artifact_store.get_record(ledger_refs[-1])
        query_samples.append(time.perf_counter() - started)
        sampled_terminal_jobs += int(current.state == LifecycleState.REPORTED)
        sampled_ledger_refs += len(ledger_refs)
        if last_record.kind != S1_LIFECYCLE_LEDGER_KIND:
            sampled_bad_artifact_kinds += 1

    p95 = _percentile(query_samples, 0.95)
    ok = (
        lifecycle_artifacts == scale_events
        and sampled_terminal_jobs == sample_count
        and sampled_ledger_refs == sample_count * len(METHOD_SEQUENCE)
        and sampled_bad_artifact_kinds == 0
        and drift_count == 0
        and p95 <= slo_seconds
    )
    return {
        "ok": ok,
        "test_case": "S1-TC-35",
        "description": "lifecycle store scale",
        "runtime_path": "LifecycleStore state, ledger refs, and C4 ArtifactRecord lookup",
        "scale_events": scale_events,
        "scale_jobs": scale_jobs,
        "lifecycle_artifacts": lifecycle_artifacts,
        "query_samples": sample_count,
        "sampled_terminal_jobs": sampled_terminal_jobs,
        "sampled_ledger_refs": sampled_ledger_refs,
        "drift_count": drift_count,
        "slo_seconds": slo_seconds,
        "state_lineage_p95_seconds": p95,
        "state_lineage_max_seconds": max(query_samples),
        "load_elapsed_seconds": load_elapsed,
    }


def _perf_descriptor() -> SubagentDescriptor:
    return SubagentDescriptor(
        subagent_id="s1-t29-perf-subagent",
        contract_version="1.0.0",
        subtopics=("perf",),
        required_adapters=("adapter:perf",),
    )


def _perf_envelope(prefix: str, index: int) -> JobEnvelope:
    return JobEnvelope(
        job_id=_job_id(prefix, index),
        envelope_version="1.0.0",
        subtopic="perf",
        required_adapters=("adapter:perf",),
        allowed_adapters=("adapter:perf",),
        verifier_profile_ref="c4://profile/s1-t29/perf",
        estimated_cost=0.001,
        budget_cost=1.0,
    )


def _job_id(prefix: str, index: int) -> str:
    return f"{prefix}-job-{index:06d}"


def _sample_indexes(population: int, samples: int) -> list[int]:
    if samples >= population:
        return list(range(population))
    if samples == 1:
        return [population - 1]
    step = (population - 1) / (samples - 1)
    return [min(population - 1, round(index * step)) for index in range(samples)]


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("cannot compute percentile over an empty sample")
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction) - 1))
    return ordered[index]


def _assert_positive(name: str, value: int) -> None:
    if value < 1:
        raise ValueError(f"{name} must be positive")


def _git_head() -> str:
    return _git(["rev-parse", "HEAD"])


def _git_dirty() -> bool:
    return bool(_git(["status", "--porcelain"]))


def _git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


if __name__ == "__main__":
    sys.exit(main())
