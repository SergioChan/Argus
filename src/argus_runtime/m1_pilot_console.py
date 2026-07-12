"""Pilot-facing state management and single-page UI for the bounded M1 reference run."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
from threading import RLock, Thread
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from .m1_reference_runtime import M1_REFERENCE_JOB_ID, M1ReferenceLifecycleResult


M1_PILOT_CONSOLE_CONFIG_ROUTE = "/v1/pilot-console/config"
M1_PILOT_RUNS_ROUTE = "/v1/pilot-runs"
M1_PILOT_REFERENCE_SCOPE = "ewpt_gw_spectrum_reference"
M1_PILOT_REFERENCE_SCOPE_LABEL = "EWPT sound-wave gravitational-wave spectrum"
M1_PILOT_MAX_TEXT_LENGTH = 2_000
M1_PILOT_MAX_BASELINE_MINUTES = 1_440


class PilotLifecycleRunner(Protocol):
    def run(
        self,
        *,
        job_id: str,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> M1ReferenceLifecycleResult: ...

    def verify_artifact(self, *, result: M1ReferenceLifecycleResult) -> Any: ...


class PilotConsoleError(RuntimeError):
    """Base error for expected pilot-console API failures."""


class PilotIntakeError(PilotConsoleError):
    """Raised when a submitted study cannot run on the bounded M1 profile."""


class PilotRunConflict(PilotConsoleError):
    """Raised when a fixed M1 runtime already has an active pilot operation."""


class PilotRunNotFound(PilotConsoleError):
    """Raised when an opaque browser-facing run identifier is unknown."""


class PilotArtifactNotReady(PilotConsoleError):
    """Raised before a completed run has a verified artifact for review."""


@dataclass(frozen=True)
class PilotIntake:
    reference_scope: str
    research_question: str | None
    known_result: str | None
    baseline_minutes: int
    scope_acknowledged: bool
    share_with_operator: bool

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PilotIntake":
        reference_scope = _required_text(payload, "reference_scope", limit=120)
        if reference_scope != M1_PILOT_REFERENCE_SCOPE:
            raise PilotIntakeError("unsupported_reference_scope")
        research_question = _required_text(payload, "research_question", limit=M1_PILOT_MAX_TEXT_LENGTH)
        known_result = _required_text(payload, "known_result", limit=M1_PILOT_MAX_TEXT_LENGTH)
        baseline_minutes = _required_positive_int(payload, "baseline_minutes", maximum=M1_PILOT_MAX_BASELINE_MINUTES)
        scope_acknowledged = payload.get("scope_acknowledged") is True
        if not scope_acknowledged:
            raise PilotIntakeError("reference_scope_acknowledgement_required")
        share_with_operator = payload.get("share_with_operator") is True
        return cls(
            reference_scope=reference_scope,
            research_question=research_question if share_with_operator else None,
            known_result=known_result if share_with_operator else None,
            baseline_minutes=baseline_minutes,
            scope_acknowledged=scope_acknowledged,
            share_with_operator=share_with_operator,
        )

    def as_payload(self) -> dict[str, Any]:
        payload = {
            "reference_scope": self.reference_scope,
            "reference_scope_label": M1_PILOT_REFERENCE_SCOPE_LABEL,
            "baseline_minutes": self.baseline_minutes,
            "scope_acknowledged": self.scope_acknowledged,
            "study_context_shared": self.share_with_operator,
        }
        if self.share_with_operator and self.research_question is not None and self.known_result is not None:
            payload["research_question"] = self.research_question
            payload["known_result"] = self.known_result
        return payload


@dataclass(frozen=True)
class PilotRunEvent:
    sequence: int
    stage: str
    status: str
    occurred_at: str
    detail: dict[str, Any]

    def as_payload(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "stage": self.stage,
            "status": self.status,
            "occurred_at": self.occurred_at,
            "detail": dict(self.detail),
        }


@dataclass
class _PilotRun:
    run_id: str
    intake: PilotIntake
    status: str = "queued"
    started_at: str = field(default_factory=lambda: _utc_now())
    finished_at: str | None = None
    events: list[PilotRunEvent] = field(default_factory=list)
    result: M1ReferenceLifecycleResult | None = None
    verification: dict[str, Any] | None = None
    error_code: str | None = None


class M1PilotRunManager:
    """Runs one fixed-profile M1 lifecycle at a time and exposes read-only snapshots."""

    def __init__(self, *, lifecycle_runner: PilotLifecycleRunner) -> None:
        self._lifecycle_runner = lifecycle_runner
        self._lock = RLock()
        self._runs: dict[str, _PilotRun] = {}
        self._active_run_id: str | None = None

    def start(self, intake: PilotIntake) -> dict[str, Any]:
        with self._lock:
            if self._active_run_id is not None:
                raise PilotRunConflict("reference_run_in_progress")
            run_id = uuid4().hex
            run = _PilotRun(run_id=run_id, intake=intake)
            self._runs[run_id] = run
            self._active_run_id = run_id
            self._append_event_locked(
                run,
                stage="intake",
                status="completed",
                detail={"reference_scope": intake.reference_scope},
            )
            self._append_event_locked(run, stage="run", status="started", detail={})
            Thread(target=self._execute, args=(run_id,), daemon=True, name=f"argus-pilot-{run_id[:8]}").start()
            return self._snapshot_locked(run)

    def get_snapshot(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            return self._snapshot_locked(self._run_locked(run_id))

    def get_observatory_html(self, run_id: str) -> str:
        with self._lock:
            run = self._run_locked(run_id)
            if run.result is None or run.status not in {"ready_for_review", "verification_failed"}:
                raise PilotArtifactNotReady("verified_artifact_not_ready")
            return run.result.observatory_html

    def reverify(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            run = self._run_locked(run_id)
            if run.result is None:
                raise PilotArtifactNotReady("verified_artifact_not_ready")
            if self._active_run_id is not None:
                raise PilotRunConflict("reference_run_in_progress")
            self._active_run_id = run_id
            run.status = "verifying"
            self._append_event_locked(run, stage="reverify", status="started", detail={})
            result = run.result
        try:
            verification = self._lifecycle_runner.verify_artifact(result=result)
            payload = _verification_payload(verification)
        except Exception as exc:
            with self._lock:
                run = self._run_locked(run_id)
                run.status = "verification_failed"
                run.error_code = type(exc).__name__
                self._append_event_locked(run, stage="reverify", status="failed", detail={"error_code": run.error_code})
                self._active_run_id = None
                return self._snapshot_locked(run)
        with self._lock:
            run = self._run_locked(run_id)
            run.verification = payload
            run.status = "ready_for_review" if payload.get("trusted") is True else "verification_failed"
            self._append_event_locked(
                run,
                stage="reverify",
                status="completed" if run.status == "ready_for_review" else "failed",
                detail={"trusted": payload.get("trusted") is True},
            )
            self._active_run_id = None
            return self._snapshot_locked(run)

    def _execute(self, run_id: str) -> None:
        with self._lock:
            run = self._run_locked(run_id)
            run.status = "running"
        try:
            result = self._lifecycle_runner.run(
                job_id=M1_REFERENCE_JOB_ID,
                event_sink=lambda event: self._record_runner_event(run_id, event),
            )
        except Exception as exc:
            with self._lock:
                run = self._run_locked(run_id)
                run.status = "failed"
                run.error_code = type(exc).__name__
                run.finished_at = _utc_now()
                self._append_event_locked(run, stage="run", status="failed", detail={"error_code": run.error_code})
                self._active_run_id = None
            return
        with self._lock:
            run = self._run_locked(run_id)
            run.result = result
            run.finished_at = _utc_now()
            if result.observatory_trusted:
                run.status = "ready_for_review"
            else:
                run.status = "failed"
                run.error_code = "untrusted_observatory"
            self._active_run_id = None

    def _record_runner_event(self, run_id: str, event: Mapping[str, Any]) -> None:
        stage = event.get("stage")
        status = event.get("status")
        detail = event.get("detail")
        if not isinstance(stage, str) or not stage:
            return
        if not isinstance(status, str) or not status:
            return
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return
            self._append_event_locked(
                run,
                stage=stage,
                status=status,
                detail=dict(detail) if isinstance(detail, Mapping) else {},
            )

    def _run_locked(self, run_id: str) -> _PilotRun:
        run = self._runs.get(run_id)
        if run is None:
            raise PilotRunNotFound("pilot_run_not_found")
        return run

    def _append_event_locked(self, run: _PilotRun, *, stage: str, status: str, detail: dict[str, Any]) -> None:
        run.events.append(
            PilotRunEvent(
                sequence=len(run.events) + 1,
                stage=stage,
                status=status,
                occurred_at=_utc_now(),
                detail=detail,
            )
        )

    def _snapshot_locked(self, run: _PilotRun) -> dict[str, Any]:
        artifact = run.result.as_payload() if run.result is not None else None
        return {
            "run_id": run.run_id,
            "status": run.status,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "intake": run.intake.as_payload(),
            "events": [event.as_payload() for event in run.events],
            "artifact": artifact,
            "has_observatory": run.result is not None,
            "verification": dict(run.verification) if run.verification is not None else None,
            "error_code": run.error_code,
        }


def pilot_console_config(*, available: bool, access_required: bool) -> dict[str, Any]:
    return {
        "available": available,
        "access_required": access_required,
        "reference_scope": {
            "id": M1_PILOT_REFERENCE_SCOPE,
            "label": M1_PILOT_REFERENCE_SCOPE_LABEL,
            "execution_input_policy": "fixed_reference_profile",
            "reference_inputs": {
                "T_n": {"value": 100.0, "units": "GeV"},
                "alpha": {"value": 0.2, "units": "dimensionless"},
                "beta_over_H": {"value": 100.0, "units": "dimensionless"},
                "v_w": {"value": 0.7, "units": "dimensionless"},
                "frequency": {"value": 0.003, "units": "Hz"},
            },
        },
    }


def pilot_access_authorized(*, authorization_header: str | None, access_token: str | None) -> bool:
    if not access_token:
        return False
    if not isinstance(authorization_header, str) or not authorization_header.startswith("Bearer "):
        return False
    return hmac.compare_digest(authorization_header.removeprefix("Bearer "), access_token)


def render_m1_pilot_console_html() -> str:
    """Return the self-contained browser UI served beside the actual M1 lifecycle."""

    return _PILOT_CONSOLE_HTML


def _required_text(payload: Mapping[str, Any], field: str, *, limit: int) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise PilotIntakeError(f"{field}_required")
    normalized = value.strip()
    if not normalized:
        raise PilotIntakeError(f"{field}_required")
    if len(normalized) > limit:
        raise PilotIntakeError(f"{field}_too_long")
    return normalized


def _required_positive_int(payload: Mapping[str, Any], field: str, *, maximum: int) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise PilotIntakeError(f"{field}_must_be_an_integer")
    if value < 1 or value > maximum:
        raise PilotIntakeError(f"{field}_out_of_range")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verification_payload(verification: Any) -> dict[str, Any]:
    as_payload = getattr(verification, "as_payload", None)
    if callable(as_payload):
        payload = as_payload()
        if isinstance(payload, Mapping):
            return dict(payload)
    if isinstance(verification, Mapping):
        return dict(verification)
    raise PilotConsoleError("verification_result_invalid")


_PILOT_CONSOLE_HTML = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Argus M1 Pilot Console</title>
  <style>
    :root {
      --paper: #f5f7f8;
      --surface: #ffffff;
      --ink: #152126;
      --muted: #5c6b70;
      --line: #d4dde0;
      --teal: #076b61;
      --teal-pale: #e3f2ef;
      --green: #13795b;
      --green-pale: #e7f5ee;
      --amber: #9a5b08;
      --amber-pale: #fbf0df;
      --red: #b42318;
      --red-pale: #fce9e7;
      --mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      --sans: "Avenir Next", Avenir, "Segoe UI", Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    html { background: var(--paper); }
    body { margin: 0; color: var(--ink); background: var(--paper); font-family: var(--sans); line-height: 1.45; }
    button, input, select, textarea { font: inherit; }
    button { cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .55; }
    [hidden] { display: none !important; }
    .topbar { position: sticky; top: 0; z-index: 5; border-bottom: 1px solid var(--line); background: rgba(245,247,248,.97); backdrop-filter: blur(10px); }
    .topbar-inner { max-width: 1440px; min-height: 68px; margin: 0 auto; padding: 12px 28px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
    .brand-mark { width: 30px; height: 30px; display: grid; place-items: center; border: 2px solid var(--teal); color: var(--teal); font-family: var(--mono); font-weight: 700; }
    .brand strong { font-size: 15px; letter-spacing: 0; }
    .brand span { color: var(--muted); font-size: 14px; white-space: nowrap; }
    .access { display: flex; align-items: end; gap: 8px; }
    .access label { display: grid; gap: 3px; color: var(--muted); font-size: 12px; }
    .access input { width: 176px; height: 34px; padding: 6px 9px; border: 1px solid var(--line); border-radius: 4px; background: var(--surface); color: var(--ink); }
    .access button, .secondary-button, .primary-button { min-height: 36px; border-radius: 4px; border: 1px solid; padding: 8px 13px; font-weight: 650; }
    .access button, .secondary-button { border-color: var(--line); background: var(--surface); color: var(--ink); }
    .primary-button { border-color: var(--teal); background: var(--teal); color: #fff; }
    .shell { max-width: 1440px; margin: 0 auto; padding: 28px; display: grid; gap: 20px; }
    .section { border: 1px solid var(--line); border-radius: 6px; background: var(--surface); }
    .context { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(340px, .9fr); }
    .context-copy, .spectrum { padding: 28px; }
    .context-copy { border-right: 1px solid var(--line); }
    .eyebrow { margin: 0 0 8px; color: var(--teal); font-family: var(--mono); font-size: 12px; font-weight: 700; letter-spacing: 0; text-transform: uppercase; }
    h1, h2, h3, p { margin-top: 0; }
    h1 { max-width: 620px; margin-bottom: 12px; font-size: 32px; line-height: 1.1; letter-spacing: 0; }
    h2 { margin-bottom: 4px; font-size: 21px; letter-spacing: 0; }
    h3 { margin-bottom: 8px; font-size: 15px; }
    .lede { max-width: 650px; margin-bottom: 22px; color: var(--muted); font-size: 16px; }
    .scope-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border-top: 1px solid var(--line); border-left: 1px solid var(--line); }
    .scope-grid div { min-height: 72px; padding: 11px; border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); }
    .scope-grid dt { color: var(--muted); font-size: 12px; }
    .scope-grid dd { margin: 5px 0 0; font-family: var(--mono); font-size: 13px; }
    .spectrum { display: grid; align-content: start; gap: 10px; }
    .spectrum-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
    .spectrum-head span { color: var(--muted); font-family: var(--mono); font-size: 12px; }
    canvas { width: 100%; height: 220px; border: 1px solid var(--line); background: #fbfcfc; }
    .spectrum-note { margin: 0; color: var(--muted); font-size: 13px; }
    .section-head { padding: 22px 24px 16px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; gap: 20px; align-items: start; }
    .section-head p { margin: 0; color: var(--muted); max-width: 700px; }
    .status-chip { display: inline-flex; align-items: center; min-width: 120px; justify-content: center; padding: 5px 8px; border-radius: 4px; background: #eef2f3; color: var(--muted); font-family: var(--mono); font-size: 12px; font-weight: 700; white-space: nowrap; }
    .status-chip.running, .status-chip.verifying { background: var(--amber-pale); color: var(--amber); }
    .status-chip.ready_for_review { background: var(--green-pale); color: var(--green); }
    .status-chip.failed, .status-chip.verification_failed { background: var(--red-pale); color: var(--red); }
    .onboarding-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(270px, .46fr); }
    .pilot-form { padding: 24px; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
    .field { display: grid; gap: 6px; }
    .field.full { grid-column: 1 / -1; }
    .field label, .field legend { color: var(--ink); font-size: 13px; font-weight: 700; }
    .field input, .field select, .field textarea { width: 100%; border: 1px solid var(--line); border-radius: 4px; background: var(--surface); color: var(--ink); padding: 9px 10px; }
    .field textarea { min-height: 96px; resize: vertical; }
    .field select:disabled { background: #eef2f3; color: var(--muted); }
    .field-note { margin: 0; color: var(--muted); font-size: 12px; }
    .checkbox-field { grid-column: 1 / -1; display: grid; grid-template-columns: 18px 1fr; align-items: start; gap: 8px; color: var(--ink); font-size: 13px; }
    .checkbox-field input { width: 16px; height: 16px; margin: 2px 0 0; }
    .form-actions { grid-column: 1 / -1; display: flex; justify-content: space-between; gap: 14px; align-items: center; padding-top: 2px; }
    .form-actions span { color: var(--muted); font-size: 12px; }
    .onboarding-aside { padding: 24px; border-left: 1px solid var(--line); background: #f8faf9; }
    .onboarding-aside dl { margin: 0; display: grid; gap: 14px; }
    .onboarding-aside div { padding-bottom: 14px; border-bottom: 1px solid var(--line); }
    .onboarding-aside dt { color: var(--muted); font-size: 12px; }
    .onboarding-aside dd { margin: 4px 0 0; font-size: 14px; }
    .run-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, .42fr); }
    .timeline { list-style: none; margin: 0; padding: 0 24px 24px; }
    .timeline-item { display: grid; grid-template-columns: 26px 1fr auto; gap: 12px; align-items: start; padding: 13px 0; border-bottom: 1px solid var(--line); }
    .timeline-item:last-child { border-bottom: 0; }
    .event-index { width: 22px; height: 22px; display: grid; place-items: center; border: 1px solid var(--line); border-radius: 50%; color: var(--teal); font-family: var(--mono); font-size: 11px; }
    .event-main { min-width: 0; }
    .event-stage { margin: 0; font-size: 14px; font-weight: 700; }
    .event-detail { margin: 3px 0 0; color: var(--muted); font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
    .event-time { color: var(--muted); font-family: var(--mono); font-size: 11px; white-space: nowrap; }
    .empty-state { padding: 26px 0; color: var(--muted); }
    .run-aside { padding: 24px; border-left: 1px solid var(--line); background: #f8faf9; }
    .run-aside dl { margin: 0; display: grid; gap: 12px; }
    .run-aside dt { color: var(--muted); font-size: 12px; }
    .run-aside dd { margin: 3px 0 0; font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
    .artifact-body { padding: 24px; display: grid; gap: 18px; }
    .artifact-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-top: 1px solid var(--line); border-left: 1px solid var(--line); }
    .artifact-summary div { min-height: 72px; padding: 11px; border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); }
    .artifact-summary span { display: block; color: var(--muted); font-size: 12px; }
    .artifact-summary strong { display: block; margin-top: 5px; font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
    .artifact-actions { display: flex; align-items: center; justify-content: space-between; gap: 14px; }
    .verification-state { color: var(--muted); font-family: var(--mono); font-size: 12px; }
    .verification-state.good { color: var(--green); }
    .verification-state.bad { color: var(--red); }
    .artifact-frame { width: 100%; min-height: 720px; border: 1px solid var(--line); background: #fff; }
    .review-grid { display: grid; grid-template-columns: minmax(0, .58fr) minmax(0, .42fr); }
    .review-form { padding: 24px; display: grid; gap: 15px; }
    .review-record { padding: 24px; border-left: 1px solid var(--line); background: #f8faf9; }
    .review-record p { color: var(--muted); font-size: 14px; }
    .notice { min-height: 26px; padding: 0 28px 2px; color: var(--muted); font-size: 13px; }
    .notice[data-kind="error"] { color: var(--red); }
    .notice[data-kind="success"] { color: var(--green); }
    @media (max-width: 960px) {
      .topbar-inner { align-items: start; flex-direction: column; }
      .access { width: 100%; }
      .access label { flex: 1; }
      .access input { width: 100%; }
      .context, .onboarding-grid, .run-grid, .review-grid { grid-template-columns: 1fr; }
      .context-copy, .onboarding-aside, .run-aside, .review-record { border-right: 0; border-left: 0; border-bottom: 1px solid var(--line); }
      .scope-grid { grid-template-columns: 1fr; }
      .artifact-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 620px) {
      .shell { padding: 14px; gap: 14px; }
      .topbar-inner { padding: 12px 14px; }
      .brand span { white-space: normal; }
      h1 { font-size: 27px; }
      .context-copy, .spectrum, .section-head, .pilot-form, .onboarding-aside, .run-aside, .artifact-body, .review-form, .review-record { padding: 18px; }
      .pilot-form { grid-template-columns: 1fr; }
      .form-actions, .artifact-actions { align-items: stretch; flex-direction: column; }
      .primary-button, .secondary-button { width: 100%; }
      .artifact-summary { grid-template-columns: 1fr; }
      .timeline { padding: 0 18px 18px; }
      .timeline-item { grid-template-columns: 24px 1fr; }
      .event-time { grid-column: 2; }
      .artifact-frame { min-height: 560px; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand" aria-label="Argus M1 Pilot Console">
        <span class="brand-mark" aria-hidden="true">A</span>
        <strong>ARGUS</strong>
        <span>M1 Pilot Console</span>
      </div>
      <div class="access">
        <label for="access-token">Pilot access code<input id="access-token" type="password" autocomplete="off"></label>
        <button id="unlock-session" type="button">Unlock session</button>
      </div>
    </div>
  </header>

  <main class="shell">
    <div id="notice" class="notice" aria-live="polite"></div>

    <section class="section context" aria-labelledby="reference-title">
      <div class="context-copy">
        <p class="eyebrow">Bounded reference study</p>
        <h1 id="reference-title">EWPT gravitational-wave reference</h1>
        <p class="lede">One controlled run, a signed verification report, and a provenance trail for review.</p>
        <dl class="scope-grid">
          <div><dt>Execution profile</dt><dd>fixed M1 reference</dd></div>
          <div><dt>Adapter</dt><dd>gw_spectrum</dd></div>
          <div><dt>Verdict path</dt><dd>S3 then S11</dd></div>
        </dl>
      </div>
      <figure class="spectrum" aria-labelledby="spectrum-title">
        <div class="spectrum-head"><h2 id="spectrum-title">Reference spectrum</h2><span>fixed inputs</span></div>
        <canvas id="spectrum-plot" width="620" height="260" aria-label="Reference gravitational-wave spectrum plot"></canvas>
        <p class="spectrum-note">T_n 100 GeV, alpha 0.2, beta/H 100, v_w 0.7, f 0.003 Hz</p>
      </figure>
    </section>

    <section class="section" aria-labelledby="setup-title">
      <div class="section-head">
        <div><p class="eyebrow">01 / Pilot setup</p><h2 id="setup-title">Frame the study</h2><p>Only the displayed EWPT reference profile can start a run. The study note is context for the pilot, not executable physics input.</p></div>
        <span id="setup-status" class="status-chip">locked</span>
      </div>
      <div class="onboarding-grid">
        <form id="pilot-form" class="pilot-form">
          <div class="field full"><label for="reference-scope">Reference scope</label><select id="reference-scope" disabled><option value="ewpt_gw_spectrum_reference">EWPT sound-wave gravitational-wave spectrum</option></select></div>
          <div class="field full"><label for="research-question">Research question</label><textarea id="research-question" maxlength="2000" required placeholder="State an in-scope question about the reference spectrum."></textarea><p class="field-note">The fixed M1 profile cannot execute arbitrary topics or uploaded data.</p></div>
          <div class="field full"><label for="known-result">Known result to recapitulate</label><textarea id="known-result" maxlength="2000" required placeholder="Describe the established result you expect to inspect."></textarea></div>
          <div class="field"><label for="baseline-minutes">Status-quo estimate (minutes)</label><input id="baseline-minutes" type="number" min="1" max="1440" step="1" value="60" required></div>
          <div class="field"><label for="pilot-alias">Pilot alias</label><input id="pilot-alias" type="text" maxlength="120" autocomplete="off" placeholder="Stored only in this browser"></div>
          <label class="checkbox-field"><input id="share-context" type="checkbox"><span>Share this study context with the run operator for this in-memory session.</span></label>
          <label class="checkbox-field"><input id="scope-acknowledged" type="checkbox" required><span>I confirm that this pilot is within the displayed reference scope.</span></label>
          <div class="form-actions"><span>One fixed M1 lifecycle may run at a time.</span><button id="start-run" class="primary-button" type="submit">Start verified run</button></div>
        </form>
        <aside class="onboarding-aside" aria-label="Pilot acceptance criteria">
          <p class="eyebrow">Review target</p>
          <h3>What the pilot will review</h3>
          <dl>
            <div><dt>Process</dt><dd>Actual M1 lifecycle events from the deployed runner.</dd></div>
            <div><dt>Artifact</dt><dd>Signed C3 report and C4 provenance rendered by Observatory.</dd></div>
            <div><dt>Decision</dt><dd>Time against baseline and a recorded pilot signal.</dd></div>
          </dl>
        </aside>
      </div>
    </section>

    <section class="section" aria-labelledby="run-title">
      <div class="section-head">
        <div><p class="eyebrow">02 / Observed execution</p><h2 id="run-title">Lifecycle record</h2><p>Events appear when their corresponding runtime boundary is entered or completed.</p></div>
        <span id="run-status" class="status-chip">waiting</span>
      </div>
      <div class="run-grid">
        <ol id="timeline" class="timeline"><li class="empty-state">No pilot run has started.</li></ol>
        <aside class="run-aside" aria-label="Current pilot run metadata">
          <p class="eyebrow">Run facts</p>
          <dl id="run-facts"><div><dt>Run</dt><dd>Waiting for intake</dd></div></dl>
        </aside>
      </div>
    </section>

    <section id="artifact-section" class="section" aria-labelledby="artifact-title" hidden>
      <div class="section-head">
        <div><p class="eyebrow">03 / Artifact review</p><h2 id="artifact-title">Verified-run artifact</h2><p>The report below is generated by S11 from the completed M1 run.</p></div>
        <span id="artifact-status" class="status-chip">pending</span>
      </div>
      <div class="artifact-body">
        <div id="artifact-summary" class="artifact-summary"></div>
        <div class="artifact-actions"><span id="verification-state" class="verification-state">No fresh verification requested.</span><button id="reverify-artifact" class="secondary-button" type="button">Re-verify artifact</button></div>
        <iframe id="artifact-frame" class="artifact-frame" title="Argus Observatory verified-run artifact" sandbox></iframe>
      </div>
    </section>

    <section id="review-section" class="section" aria-labelledby="review-title" hidden>
      <div class="section-head">
        <div><p class="eyebrow">04 / Pilot review</p><h2 id="review-title">Record the test result</h2><p>The export stays in the pilot's browser until they choose to share it.</p></div>
      </div>
      <div class="review-grid">
        <form id="review-form" class="review-form">
          <div class="field"><label for="pilot-signal">Pilot signal</label><select id="pilot-signal"><option value="">Select a signal</option><option value="positive">Positive</option><option value="neutral">Neutral</option><option value="negative">Negative</option></select></div>
          <div class="field"><label for="pilot-notes">Pilot notes</label><textarea id="pilot-notes" maxlength="2000" placeholder="What was useful, unclear, or missing?"></textarea></div>
          <button id="export-record" class="primary-button" type="button">Export pilot record</button>
        </form>
        <aside class="review-record">
          <p class="eyebrow">Gate evidence</p>
          <h3>Session export</h3>
          <p>Includes the study note, baseline estimate, observed run duration, artifact references, fresh verification result, and pilot feedback.</p>
        </aside>
      </div>
    </section>
  </main>

  <script>
    (() => {
      "use strict";
      const apiRoot = "/v1";
      const pollableStatuses = new Set(["queued", "running", "verifying"]);
      const stageNames = {
        intake: "Pilot intake",
        runtime_identity: "Runtime identity",
        verifier_profile: "S3 verifier profile",
        reference_dataset: "Reference dataset",
        accept: "C1 acceptance",
        plan: "C1 plan",
        build: "S10, S7, S2 build",
        validate: "S3 blind verification",
        report: "C1 report",
        observatory: "S11 Observatory",
        reverify: "C3 and C4 re-verification",
        run: "Verified run"
      };
      const state = {
        accessToken: sessionStorage.getItem("argus.m1.pilot.access") || "",
        config: null,
        runId: null,
        snapshot: null,
        study: null,
        artifactLoadedFor: null,
        pollTimer: null
      };
      const $ = (id) => document.getElementById(id);
      const notice = $("notice");
      const accessInput = $("access-token");
      accessInput.value = state.accessToken;

      function setNotice(message, kind) {
        notice.textContent = message || "";
        notice.dataset.kind = kind || "";
      }

      function setStatus(id, value) {
        const node = $(id);
        node.textContent = String(value || "waiting").replaceAll("_", " ");
        node.className = "status-chip " + String(value || "");
      }

      function authHeaders() {
        return state.accessToken ? {"Authorization": "Bearer " + state.accessToken} : {};
      }

      async function requestJson(path, options = {}) {
        const headers = Object.assign({"Content-Type": "application/json"}, authHeaders(), options.headers || {});
        const response = await fetch(path, Object.assign({}, options, {headers}));
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          const error = new Error(payload.error || "request_failed");
          error.code = payload.error || "request_failed";
          throw error;
        }
        return payload;
      }

      async function requestHtml(path) {
        const response = await fetch(path, {headers: authHeaders()});
        const text = await response.text();
        if (!response.ok) {
          const error = new Error("artifact_request_failed");
          error.code = "artifact_request_failed";
          throw error;
        }
        return text;
      }

      function localTime(value) {
        if (!value) return "-";
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString();
      }

      function durationMinutes(snapshot) {
        if (!snapshot || !snapshot.started_at || !snapshot.finished_at) return null;
        const start = new Date(snapshot.started_at).getTime();
        const end = new Date(snapshot.finished_at).getTime();
        if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
        return Math.max(0, (end - start) / 60000);
      }

      function detailText(detail) {
        const entries = Object.entries(detail || {}).filter(([, value]) => value !== null && value !== undefined && value !== "");
        return entries.map(([key, value]) => key + "=" + conciseDetailValue(value)).join(" | ");
      }

      function conciseDetailValue(value) {
        if (Array.isArray(value)) return String(value.length) + " item(s)";
        const text = String(value);
        return text.length > 112 ? text.slice(0, 109) + "..." : text;
      }

      function renderTimeline(events) {
        const timeline = $("timeline");
        timeline.replaceChildren();
        if (!events || !events.length) {
          const empty = document.createElement("li");
          empty.className = "empty-state";
          empty.textContent = "No pilot run has started.";
          timeline.append(empty);
          return;
        }
        for (const event of events) {
          const item = document.createElement("li");
          item.className = "timeline-item";
          const index = document.createElement("span");
          index.className = "event-index";
          index.textContent = String(event.sequence);
          const main = document.createElement("div");
          main.className = "event-main";
          const stage = document.createElement("p");
          stage.className = "event-stage";
          stage.textContent = (stageNames[event.stage] || event.stage) + " / " + event.status;
          main.append(stage);
          const detail = detailText(event.detail);
          if (detail) {
            const detailNode = document.createElement("p");
            detailNode.className = "event-detail";
            detailNode.textContent = detail;
            main.append(detailNode);
          }
          const time = document.createElement("time");
          time.className = "event-time";
          time.textContent = localTime(event.occurred_at);
          item.append(index, main, time);
          timeline.append(item);
        }
      }

      function appendFact(container, label, value) {
        const row = document.createElement("div");
        const term = document.createElement("dt");
        term.textContent = label;
        const definition = document.createElement("dd");
        definition.textContent = value || "-";
        row.append(term, definition);
        container.append(row);
      }

      function renderFacts(snapshot) {
        const facts = $("run-facts");
        facts.replaceChildren();
        if (!snapshot) {
          appendFact(facts, "Run", "Waiting for intake");
          return;
        }
        appendFact(facts, "Run", snapshot.run_id);
        appendFact(facts, "Status", snapshot.status);
        appendFact(facts, "Started", localTime(snapshot.started_at));
        appendFact(facts, "Finished", localTime(snapshot.finished_at));
        appendFact(facts, "Baseline", String(snapshot.intake.baseline_minutes) + " minutes");
        if (snapshot.error_code) appendFact(facts, "Run code", snapshot.error_code);
      }

      function renderArtifact(snapshot) {
        const artifact = snapshot.artifact;
        if (!artifact) return;
        $("artifact-section").hidden = false;
        $("review-section").hidden = false;
        setStatus("artifact-status", artifact.observatory_trusted ? "ready_for_review" : "failed");
        const summary = $("artifact-summary");
        summary.replaceChildren();
        const items = [
          ["Claim tier", artifact.claim_tier],
          ["Referee", artifact.referee_id],
          ["Signature key", artifact.signature_key_id],
          ["Report ref", artifact.validation_report_ref],
          ["Subject ref", artifact.promoted_artifact_ref],
          ["Observatory ref", artifact.observatory_html_ref],
          ["Final state", artifact.final_state],
          ["Checks", String((artifact.checks || []).length)]
        ];
        for (const [label, value] of items) {
          const cell = document.createElement("div");
          const caption = document.createElement("span");
          caption.textContent = label;
          const content = document.createElement("strong");
          content.textContent = value || "-";
          cell.append(caption, content);
          summary.append(cell);
        }
        renderVerification(snapshot.verification);
        if (state.artifactLoadedFor !== snapshot.run_id) loadArtifact(snapshot.run_id);
      }

      function renderVerification(verification) {
        const node = $("verification-state");
        node.className = "verification-state";
        if (!verification) {
          node.textContent = "No fresh verification requested.";
          return;
        }
        if (verification.trusted) {
          node.classList.add("good");
          node.textContent = "Fresh verification passed at " + localTime(verification.checked_at) + ".";
          return;
        }
        node.classList.add("bad");
        node.textContent = "Fresh verification failed: " + (verification.failures || []).join("; ");
      }

      async function loadArtifact(runId) {
        try {
          const html = await requestHtml(apiRoot + "/pilot-runs/" + encodeURIComponent(runId) + "/observatory");
          $("artifact-frame").srcdoc = html;
          state.artifactLoadedFor = runId;
        } catch (error) {
          setNotice("The artifact could not be loaded for this session.", "error");
        }
      }

      function renderSnapshot(snapshot) {
        state.snapshot = snapshot;
        state.runId = snapshot.run_id;
        renderTimeline(snapshot.events);
        renderFacts(snapshot);
        setStatus("run-status", snapshot.status);
        if (snapshot.artifact) renderArtifact(snapshot);
        if (pollableStatuses.has(snapshot.status)) schedulePoll();
      }

      function schedulePoll() {
        window.clearTimeout(state.pollTimer);
        state.pollTimer = window.setTimeout(refreshRun, 900);
      }

      async function refreshRun() {
        if (!state.runId) return;
        try {
          const snapshot = await requestJson(apiRoot + "/pilot-runs/" + encodeURIComponent(state.runId), {method: "GET"});
          renderSnapshot(snapshot);
        } catch (error) {
          setNotice("The pilot run status is not available. Check the session access code.", "error");
        }
      }

      function formStudy() {
        return {
          pilot_alias: $("pilot-alias").value.trim(),
          research_question: $("research-question").value.trim(),
          known_result: $("known-result").value.trim(),
          baseline_minutes: Number($("baseline-minutes").value),
          reference_scope: $("reference-scope").value,
          scope_acknowledged: $("scope-acknowledged").checked,
          share_with_operator: $("share-context").checked
        };
      }

      async function startRun(event) {
        event.preventDefault();
        if (!state.config || !state.config.available) {
          setNotice("The deployed M1 pilot runtime is not available.", "error");
          return;
        }
        if (!state.accessToken) {
          setNotice("Enter the pilot access code before starting a run.", "error");
          return;
        }
        const study = formStudy();
        if (!study.research_question || !study.known_result || !Number.isInteger(study.baseline_minutes) || !study.scope_acknowledged) {
          setNotice("Complete the study fields and confirm the reference scope.", "error");
          return;
        }
        $("start-run").disabled = true;
        setNotice("Submitting the bounded reference study.", "");
        try {
          state.study = study;
          sessionStorage.setItem("argus.m1.pilot.study", JSON.stringify(study));
          const {pilot_alias: _pilotAlias, ...runRequest} = study;
          const snapshot = await requestJson(apiRoot + "/pilot-runs", {method: "POST", body: JSON.stringify(runRequest)});
          state.artifactLoadedFor = null;
          renderSnapshot(snapshot);
          setNotice("The deployed M1 lifecycle is running.", "success");
        } catch (error) {
          setNotice("The study could not start: " + (error.code || "request_failed") + ".", "error");
        } finally {
          $("start-run").disabled = false;
        }
      }

      async function reverifyArtifact() {
        if (!state.runId) return;
        $("reverify-artifact").disabled = true;
        setNotice("Re-reading the report and lineage for verification.", "");
        try {
          const snapshot = await requestJson(apiRoot + "/pilot-runs/" + encodeURIComponent(state.runId) + "/verify", {method: "POST"});
          renderSnapshot(snapshot);
          setNotice(snapshot.verification && snapshot.verification.trusted ? "Fresh verification passed." : "Fresh verification did not pass.", snapshot.verification && snapshot.verification.trusted ? "success" : "error");
        } catch (error) {
          setNotice("Verification could not run: " + (error.code || "request_failed") + ".", "error");
        } finally {
          $("reverify-artifact").disabled = false;
        }
      }

      function exportRecord() {
        if (!state.snapshot || !state.study) {
          setNotice("Complete a pilot run before exporting a record.", "error");
          return;
        }
        const record = {
          schema: "argus.m1.pilot-session.v1",
          exported_at: new Date().toISOString(),
          study: state.study,
          observed_duration_minutes: durationMinutes(state.snapshot),
          run: state.snapshot,
          pilot_feedback: {
            signal: $("pilot-signal").value,
            notes: $("pilot-notes").value.trim()
          }
        };
        const blob = new Blob([JSON.stringify(record, null, 2) + "\n"], {type: "application/json"});
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "argus-m1-pilot-session.json";
        link.click();
        URL.revokeObjectURL(link.href);
        setNotice("Pilot record exported from this browser.", "success");
      }

      async function unlockSession() {
        state.accessToken = accessInput.value.trim();
        if (!state.accessToken) {
          sessionStorage.removeItem("argus.m1.pilot.access");
          setStatus("setup-status", "locked");
          setNotice("Enter a pilot access code.", "error");
          return;
        }
        sessionStorage.setItem("argus.m1.pilot.access", state.accessToken);
        setStatus("setup-status", "ready");
        setNotice("Pilot access code stored for this browser session.", "success");
      }

      async function loadConfig() {
        try {
          state.config = await requestJson(apiRoot + "/pilot-console/config", {method: "GET", headers: {}});
          setStatus("setup-status", state.config.available && state.accessToken ? "ready" : "locked");
          if (!state.config.available) setNotice("This page needs the deployed M1 reference runtime before it can start a pilot run.", "error");
        } catch (error) {
          setNotice("Pilot console configuration is unavailable.", "error");
        }
      }

      function restoreStudy() {
        try {
          const study = JSON.parse(sessionStorage.getItem("argus.m1.pilot.study") || "null");
          if (!study) return;
          $("pilot-alias").value = study.pilot_alias || "";
          $("research-question").value = study.research_question || "";
          $("known-result").value = study.known_result || "";
          $("baseline-minutes").value = study.baseline_minutes || 60;
          $("share-context").checked = study.share_with_operator === true;
          $("scope-acknowledged").checked = study.scope_acknowledged === true;
        } catch (_) {
          sessionStorage.removeItem("argus.m1.pilot.study");
        }
      }

      function drawSpectrum() {
        const canvas = $("spectrum-plot");
        const context = canvas.getContext("2d");
        const width = canvas.width;
        const height = canvas.height;
        context.clearRect(0, 0, width, height);
        context.strokeStyle = "#d4dde0";
        context.lineWidth = 1;
        for (let index = 1; index < 5; index += 1) {
          const y = 18 + index * (height - 42) / 5;
          context.beginPath(); context.moveTo(42, y); context.lineTo(width - 18, y); context.stroke();
        }
        context.strokeStyle = "#076b61";
        context.lineWidth = 3;
        context.beginPath();
        for (let index = 0; index <= 120; index += 1) {
          const ratio = Math.pow(10, -1.7 + 3.4 * index / 120);
          const shape = Math.pow(ratio, 3) * Math.pow(7 / (4 + 3 * ratio * ratio), 3.5);
          const x = 42 + index * (width - 60) / 120;
          const y = height - 25 - Math.min(1, shape) * (height - 58);
          if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
        }
        context.stroke();
        context.fillStyle = "#5c6b70";
        context.font = "12px SFMono-Regular, Consolas, monospace";
        context.fillText("f / f_peak", width - 95, height - 7);
        context.fillText("Omega", 6, 18);
      }

      $("unlock-session").addEventListener("click", unlockSession);
      $("pilot-form").addEventListener("submit", startRun);
      $("reverify-artifact").addEventListener("click", reverifyArtifact);
      $("export-record").addEventListener("click", exportRecord);
      restoreStudy();
      drawSpectrum();
      renderFacts(null);
      loadConfig();
    })();
  </script>
</body>
</html>
'''
