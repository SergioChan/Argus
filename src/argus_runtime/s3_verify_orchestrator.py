"""Durable S3 VerifyWorkflow orchestration core.

This module owns the restart/replay semantics for S3-T03. It is intentionally
engine-neutral at the boundary: a Temporal worker can drive the same
``run_next_step`` activity loop, while local tests can prove replay behavior
without requiring a Temporal cluster in the unit-test process.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol

from argus_core import (
    C3ReportSigner,
    CheckPluginHost,
    CheckResult,
    CompiledProfile,
    Lineage,
    Producer,
    S3ReportBuilder,
    S3Verifier,
    hash_json,
)

from .s3_verifier_service import S3VerificationDispatch, dispatch_digest


S3_VERIFY_WORKFLOW_TYPE = "argus.s3.VerifyWorkflow"
S3_VERIFY_TASK_QUEUE = "argus-s3-verifier"
S3_WORKFLOW_TERMINAL_STATUSES = frozenset({"REPORTED", "BUDGET_HALTED", "FAILED"})


class S3WorkflowError(Exception):
    """Raised when a durable S3 workflow cannot be replayed safely."""


class S3WorkflowNotFound(S3WorkflowError):
    """Raised when a worker is asked to resume an unknown workflow id."""


class S3WorkflowStatus:
    RUNNING = "RUNNING"
    REPORTED = "REPORTED"
    BUDGET_HALTED = "BUDGET_HALTED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class S3WorkflowEvent:
    workflow_id: str
    sequence: int
    event_type: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class S3PipelineRunResult:
    status: str
    checks: tuple[CheckResult, ...] = ()
    output_artifact_ref: str | None = None
    partial_result_ref: str | None = None
    reason: str | None = None
    captured_stdout_bytes: int = 0
    cost_actual_usd: float = 0.0
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def succeeded(
        cls,
        *,
        checks: tuple[CheckResult, ...],
        output_artifact_ref: str,
        cost_actual_usd: float = 0.0,
        evidence_refs: tuple[str, ...] = (),
    ) -> "S3PipelineRunResult":
        if not checks:
            raise ValueError("successful S3 pipeline runs must include at least one check")
        if not output_artifact_ref:
            raise ValueError("successful S3 pipeline runs must include an output artifact ref")
        return cls(
            status="SUCCEEDED",
            checks=tuple(checks),
            output_artifact_ref=output_artifact_ref,
            cost_actual_usd=float(cost_actual_usd),
            evidence_refs=tuple(evidence_refs),
        )

    @classmethod
    def budget_halted(
        cls,
        *,
        reason: str,
        partial_result_ref: str,
        captured_stdout_bytes: int = 0,
    ) -> "S3PipelineRunResult":
        if not reason:
            raise ValueError("budget halt reason is required")
        if not partial_result_ref:
            raise ValueError("budget halt partial_result_ref is required")
        return cls(
            status="BUDGET_HALTED",
            partial_result_ref=partial_result_ref,
            reason=reason,
            captured_stdout_bytes=int(captured_stdout_bytes),
        )


class S3PipelineRunner(Protocol):
    def run(
        self,
        *,
        dispatch: S3VerificationDispatch,
        entrypoint_request: dict[str, Any],
    ) -> S3PipelineRunResult:
        """Run the frozen-pipeline activity and return a replayable outcome."""


class S3CheckPluginPipelineRunner:
    """Runs a frozen-pipeline verification dispatch through S3 check plugins."""

    def __init__(
        self,
        *,
        artifact_store: Any,
        compiled_profile: CompiledProfile,
        plugins: tuple[Any, ...],
        actor_id: str = "s3.check-plugin-pipeline-runner",
        cost_actual_usd: float = 0.0,
    ) -> None:
        if not hasattr(artifact_store, "create_artifact"):
            raise TypeError("artifact_store must provide create_artifact")
        if not isinstance(compiled_profile, CompiledProfile):
            raise TypeError("compiled_profile must be a CompiledProfile")
        if not plugins:
            raise ValueError("plugins must contain at least one S3 check plugin")
        self.artifact_store = artifact_store
        self.compiled_profile = compiled_profile
        self.plugins = tuple(plugins)
        self.actor_id = actor_id
        self.cost_actual_usd = float(cost_actual_usd)

    def run(
        self,
        *,
        dispatch: S3VerificationDispatch,
        entrypoint_request: dict[str, Any],
    ) -> S3PipelineRunResult:
        checks = CheckPluginHost(
            plugins=self.plugins,
            artifact_store=self.artifact_store,
            actor_id=self.actor_id,
            job_id=dispatch.job_id,
            trace_id=dispatch.trace_id,
        ).run(self.compiled_profile)
        evidence_refs = tuple(check.evidence_ref for check in checks if check.evidence_ref is not None)
        output_record = self.artifact_store.create_artifact(
            kind="s3_pipeline_check_output",
            payload={
                "schema": "argus.s3.pipeline_check_output.v1",
                "workflow_type": S3_VERIFY_WORKFLOW_TYPE,
                "request_id": dispatch.request_id,
                "job_id": dispatch.job_id,
                "profile_ref": dispatch.profile_ref,
                "frozen_pipeline_ref": dispatch.frozen_pipeline_ref,
                "compiled_profile_ref": self.compiled_profile.profile_ref,
                "checks": [_check_payload(check) for check in checks],
                "evidence_refs": list(evidence_refs),
                "entrypoint_request_hash": hash_json(entrypoint_request),
            },
            producer=Producer(
                subsystem="S3",
                version="0.0.0",
                actor_id=self.actor_id,
                job_id=dispatch.job_id,
            ),
            lineage=Lineage(
                input_refs=tuple(
                    dict.fromkeys(
                        (
                            dispatch.frozen_pipeline_ref,
                            *(
                                str(ref)
                                for ref in entrypoint_request.get("artifact_refs", ())
                                if isinstance(ref, str)
                            ),
                            *evidence_refs,
                        )
                    )
                ),
                code_ref="argus-runtime:s3.check-plugin-pipeline-runner",
                environment_digest=hash_json(
                    {
                        "runner": "s3-check-plugin-pipeline-runner:v1",
                        "profile_ref": self.compiled_profile.profile_ref,
                        "plugin_count": len(self.plugins),
                    }
                ),
                job_id=dispatch.job_id,
            ),
        )
        return S3PipelineRunResult.succeeded(
            checks=checks,
            output_artifact_ref=output_record.artifact_ref,
            cost_actual_usd=self.cost_actual_usd,
            evidence_refs=evidence_refs,
        )


@dataclass(frozen=True)
class S3WorkflowState:
    workflow_id: str
    workflow_type: str
    task_queue: str
    status: str
    request_id: str
    job_id: str
    trace_id: str
    dispatch_digest: str
    event_count: int
    report: dict[str, Any] | None = None
    validation_report_ref: str | None = None
    output_artifact_ref: str | None = None
    partial_result_ref: str | None = None
    halt_reason: str | None = None


class InMemoryS3WorkflowStore:
    """Append-only workflow event store used by local workers and tests.

    The store keeps enough durable history to reconstruct a workflow after a
    worker restart. It intentionally exposes only append and read operations so
    workflow effects are replayed from events rather than mutable worker state.
    """

    def __init__(self, events: tuple[S3WorkflowEvent, ...] = ()) -> None:
        self._events: dict[str, list[S3WorkflowEvent]] = {}
        for event in events:
            workflow_events = self._events.setdefault(event.workflow_id, [])
            expected = len(workflow_events) + 1
            if event.sequence != expected:
                raise S3WorkflowError(f"non-contiguous event sequence for {event.workflow_id}")
            workflow_events.append(event)

    def append(self, workflow_id: str, event_type: str, payload: Mapping[str, Any]) -> S3WorkflowEvent:
        sequence = len(self._events.get(workflow_id, ())) + 1
        event = S3WorkflowEvent(
            workflow_id=workflow_id,
            sequence=sequence,
            event_type=event_type,
            payload=_jsonable(payload),
        )
        self._events.setdefault(workflow_id, []).append(event)
        return event

    def events(self, workflow_id: str) -> tuple[S3WorkflowEvent, ...]:
        return tuple(self._events.get(workflow_id, ()))

    def all_events(self) -> tuple[S3WorkflowEvent, ...]:
        return tuple(event for workflow_events in self._events.values() for event in workflow_events)


class S3VerifyOrchestrator:
    """Restart-surviving S3 VerifyWorkflow coordinator."""

    def __init__(
        self,
        *,
        store: InMemoryS3WorkflowStore,
        artifact_store: Any,
        verifier_id: str,
        signer_key_id: str,
        signer: C3ReportSigner,
        pipeline_runner: S3PipelineRunner,
        task_queue: str = S3_VERIFY_TASK_QUEUE,
    ) -> None:
        self.store = store
        self.artifact_store = artifact_store
        self.task_queue = task_queue
        self.verifier = S3Verifier(verifier_id=verifier_id, signer_key_id=signer_key_id, signer=signer)
        self.report_builder = S3ReportBuilder(
            verifier=self.verifier,
            artifact_store=artifact_store,
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.verify-workflow"),
            code_ref="argus-runtime:s3.verify-orchestrator",
            environment_digest="python:s3-verify-orchestrator:v1",
        )
        self.pipeline_runner = pipeline_runner

    def start(self, dispatch: S3VerificationDispatch) -> S3WorkflowState:
        digest = dispatch_digest(dispatch)
        workflow_id = _workflow_id(digest)
        if not self.store.events(workflow_id):
            self.store.append(
                workflow_id,
                "WorkflowStarted",
                {
                    "workflow_type": S3_VERIFY_WORKFLOW_TYPE,
                    "task_queue": self.task_queue,
                    "dispatch_digest": digest,
                    "dispatch": _dispatch_payload(dispatch),
                },
            )
        return self.state(workflow_id)

    def run_until_terminal(self, workflow_id: str, *, max_steps: int = 16) -> S3WorkflowState:
        state = self.state(workflow_id)
        steps = 0
        while state.status not in S3_WORKFLOW_TERMINAL_STATUSES:
            if steps >= max_steps:
                raise S3WorkflowError(f"workflow {workflow_id} did not reach a terminal state")
            state = self.run_next_step(workflow_id)
            steps += 1
        return state

    def run_next_step(self, workflow_id: str) -> S3WorkflowState:
        state = self.state(workflow_id)
        if state.status in S3_WORKFLOW_TERMINAL_STATUSES:
            return state

        events = self.store.events(workflow_id)
        event_types = tuple(event.event_type for event in events)
        dispatch = _dispatch_from_events(events)

        if "PipelineRunSucceeded" not in event_types and "BudgetHaltCaptured" not in event_types:
            self.store.append(
                workflow_id,
                "PipelineRunStarted",
                {
                    "request_id": dispatch.request_id,
                    "job_id": dispatch.job_id,
                    "frozen_pipeline_ref": dispatch.frozen_pipeline_ref,
                },
            )
            result = self.pipeline_runner.run(
                dispatch=dispatch,
                entrypoint_request=dict(dispatch.entrypoint_request),
            )
            if result.status == "BUDGET_HALTED":
                self.store.append(workflow_id, "BudgetHaltCaptured", _pipeline_result_payload(result))
            elif result.status == "SUCCEEDED":
                self.store.append(workflow_id, "PipelineRunSucceeded", _pipeline_result_payload(result))
            else:
                self.store.append(workflow_id, "WorkflowFailed", {"reason": f"unknown pipeline status {result.status}"})
                self.store.append(workflow_id, "WorkflowCompleted", {"status": S3WorkflowStatus.FAILED})
            return self.state(workflow_id)

        if "BudgetHaltCaptured" in event_types and "WorkflowCompleted" not in event_types:
            halt_event = _last_event(events, "BudgetHaltCaptured")
            self.store.append(
                workflow_id,
                "WorkflowCompleted",
                {
                    "status": S3WorkflowStatus.BUDGET_HALTED,
                    "partial_result_ref": halt_event.payload.get("partial_result_ref"),
                    "reason": halt_event.payload.get("reason"),
                },
            )
            return self.state(workflow_id)

        if "PipelineRunSucceeded" in event_types and "ReportProduced" not in event_types:
            result = _pipeline_result_from_payload(_last_event(events, "PipelineRunSucceeded").payload)
            committed_report = self.report_builder.build_and_commit_report(
                profile_ref=dispatch.profile_ref,
                frozen_pipeline_ref=dispatch.frozen_pipeline_ref,
                checks=result.checks,
                proponent_id=dispatch.caller_id,
                input_refs=tuple(
                    ref
                    for ref in (
                        dispatch.frozen_pipeline_ref,
                        result.output_artifact_ref,
                        *result.evidence_refs,
                    )
                    if ref
                ),
                job_id=dispatch.job_id,
            )
            self.store.append(
                workflow_id,
                "ReportProduced",
                {
                    "report": committed_report.report,
                    "report_digest": hash_json(committed_report.report),
                    "validation_report_ref": committed_report.validation_report_ref,
                    "validation_report_digest": committed_report.canonical.digest,
                    "output_artifact_ref": result.output_artifact_ref,
                    "cost_actual_usd": result.cost_actual_usd,
                    "evidence_refs": list(result.evidence_refs),
                },
            )
            return self.state(workflow_id)

        if "ReportProduced" in event_types and "WorkflowCompleted" not in event_types:
            report_event = _last_event(events, "ReportProduced")
            self.store.append(
                workflow_id,
                "WorkflowCompleted",
                {
                    "status": S3WorkflowStatus.REPORTED,
                    "report_digest": report_event.payload["report_digest"],
                    "output_artifact_ref": report_event.payload.get("output_artifact_ref"),
                },
            )
            return self.state(workflow_id)

        return self.state(workflow_id)

    def state(self, workflow_id: str) -> S3WorkflowState:
        events = self.store.events(workflow_id)
        if not events:
            raise S3WorkflowNotFound(workflow_id)
        dispatch = _dispatch_from_events(events)
        started = events[0].payload
        status = S3WorkflowStatus.RUNNING
        report: dict[str, Any] | None = None
        validation_report_ref: str | None = None
        output_artifact_ref: str | None = None
        partial_result_ref: str | None = None
        halt_reason: str | None = None
        for event in events:
            if event.event_type == "BudgetHaltCaptured":
                partial_result_ref = _optional_str(event.payload.get("partial_result_ref"))
                halt_reason = _optional_str(event.payload.get("reason"))
            elif event.event_type == "ReportProduced":
                report_payload = event.payload.get("report")
                if isinstance(report_payload, Mapping):
                    report = {str(key): _jsonable(value) for key, value in report_payload.items()}
                validation_report_ref = _optional_str(event.payload.get("validation_report_ref"))
                output_artifact_ref = _optional_str(event.payload.get("output_artifact_ref"))
            elif event.event_type == "WorkflowCompleted":
                status = str(event.payload.get("status") or status)
        return S3WorkflowState(
            workflow_id=workflow_id,
            workflow_type=str(started.get("workflow_type", S3_VERIFY_WORKFLOW_TYPE)),
            task_queue=str(started.get("task_queue", self.task_queue)),
            status=status,
            request_id=dispatch.request_id,
            job_id=dispatch.job_id,
            trace_id=dispatch.trace_id,
            dispatch_digest=str(started["dispatch_digest"]),
            event_count=len(events),
            report=report,
            validation_report_ref=validation_report_ref,
            output_artifact_ref=output_artifact_ref,
            partial_result_ref=partial_result_ref,
            halt_reason=halt_reason,
        )


def _workflow_id(dispatch_digest_value: str) -> str:
    return "s3-verify-" + dispatch_digest_value[:24]


def _dispatch_payload(dispatch: S3VerificationDispatch) -> dict[str, Any]:
    return _jsonable(asdict(dispatch))


def _dispatch_from_events(events: tuple[S3WorkflowEvent, ...]) -> S3VerificationDispatch:
    dispatch_payload = events[0].payload.get("dispatch")
    if not isinstance(dispatch_payload, Mapping):
        raise S3WorkflowError("WorkflowStarted event is missing dispatch payload")
    return S3VerificationDispatch(
        request_id=_required_str(dispatch_payload, "request_id"),
        job_id=_required_str(dispatch_payload, "job_id"),
        profile_ref=_required_str(dispatch_payload, "profile_ref"),
        frozen_pipeline_ref=_required_str(dispatch_payload, "frozen_pipeline_ref"),
        trace_id=_required_str(dispatch_payload, "trace_id"),
        caller_id=_required_str(dispatch_payload, "caller_id"),
        client_cert_subject=_required_str(dispatch_payload, "client_cert_subject"),
        transport=_required_str(dispatch_payload, "transport"),
        entrypoint_request=_required_mapping(dispatch_payload, "entrypoint_request"),
    )


def _pipeline_result_payload(result: S3PipelineRunResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "checks": [_check_payload(check) for check in result.checks],
        "output_artifact_ref": result.output_artifact_ref,
        "partial_result_ref": result.partial_result_ref,
        "reason": result.reason,
        "captured_stdout_bytes": result.captured_stdout_bytes,
        "cost_actual_usd": result.cost_actual_usd,
        "evidence_refs": list(result.evidence_refs),
    }


def _pipeline_result_from_payload(payload: Mapping[str, Any]) -> S3PipelineRunResult:
    return S3PipelineRunResult(
        status=str(payload["status"]),
        checks=tuple(_check_from_payload(item) for item in payload.get("checks") or ()),
        output_artifact_ref=_optional_str(payload.get("output_artifact_ref")),
        partial_result_ref=_optional_str(payload.get("partial_result_ref")),
        reason=_optional_str(payload.get("reason")),
        captured_stdout_bytes=int(payload.get("captured_stdout_bytes") or 0),
        cost_actual_usd=float(payload.get("cost_actual_usd") or 0.0),
        evidence_refs=tuple(str(item) for item in payload.get("evidence_refs") or ()),
    )


def _check_payload(check: CheckResult) -> dict[str, Any]:
    payload = {"check": check.check, "status": check.status, "metrics": _jsonable(check.metrics)}
    if check.evidence_ref is not None:
        payload["evidence_ref"] = check.evidence_ref
    if check.plugin_ref is not None:
        payload["plugin_ref"] = check.plugin_ref
    if check.plugin_version is not None:
        payload["plugin_version"] = check.plugin_version
    if check.dependencies:
        payload["dependencies"] = list(check.dependencies)
    return payload


def _check_from_payload(value: Any) -> CheckResult:
    if not isinstance(value, Mapping):
        raise S3WorkflowError("check payload must be a mapping")
    metrics = value.get("metrics")
    return CheckResult(
        check=_required_str(value, "check"),
        status=_required_str(value, "status"),
        metrics=dict(metrics) if isinstance(metrics, Mapping) else None,
        evidence_ref=_optional_str(value.get("evidence_ref")),
        plugin_ref=_optional_str(value.get("plugin_ref")),
        plugin_version=_optional_str(value.get("plugin_version")),
        dependencies=tuple(str(item) for item in value.get("dependencies") or ()),
    )


def _last_event(events: tuple[S3WorkflowEvent, ...], event_type: str) -> S3WorkflowEvent:
    for event in reversed(events):
        if event.event_type == event_type:
            return event
    raise S3WorkflowError(f"workflow is missing required event {event_type}")


def _required_mapping(payload: Mapping[str, Any], field_name: str) -> dict[str, Any]:
    value = payload.get(field_name)
    if not isinstance(value, Mapping):
        raise S3WorkflowError(f"{field_name} must be a mapping")
    return {str(key): _jsonable(item) for key, item in value.items()}


def _required_str(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise S3WorkflowError(f"{field_name} must be a non-empty string")
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value
