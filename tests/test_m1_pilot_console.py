from __future__ import annotations

from dataclasses import dataclass
import socket
from threading import Thread
import time
from typing import Any
from urllib import request as urlrequest
import unittest

from argus_runtime.http_json import HttpResponse, JsonRequest, serve_json_app
from argus_runtime.m1_pilot_console import (
    M1_PILOT_REFERENCE_SCOPE,
    M1PilotRunManager,
    PilotIntake,
    PilotIntakeError,
    PilotRunConflict,
)
from argus_runtime.m1_reference_runtime import M1_REFERENCE_JOB_ID, M1ReferenceLifecycleResult
from argus_runtime.s1_reference_demo_service import S1ReferenceDemoApp


class M1PilotConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = _FakeLifecycleRunner()
        self.intake = PilotIntake.from_payload(_intake_payload())

    def test_intake_rejects_unsupported_scope_and_missing_acknowledgement(self) -> None:
        unsupported = _intake_payload(reference_scope="unbounded-topic")
        no_ack = _intake_payload(scope_acknowledged=False)

        with self.assertRaisesRegex(PilotIntakeError, "unsupported_reference_scope"):
            PilotIntake.from_payload(unsupported)
        with self.assertRaisesRegex(PilotIntakeError, "reference_scope_acknowledgement_required"):
            PilotIntake.from_payload(no_ack)

    def test_unshared_study_context_is_not_returned_in_run_snapshot(self) -> None:
        intake = PilotIntake.from_payload(_intake_payload(share_with_operator=False))
        manager = M1PilotRunManager(lifecycle_runner=self.runner)

        self.assertIsNone(intake.research_question)
        self.assertIsNone(intake.known_result)
        snapshot = manager.start(intake)
        completed = _wait_for_terminal(manager, snapshot["run_id"])

        self.assertTrue(completed["has_observatory"])
        self.assertNotIn("research_question", completed["intake"])
        self.assertNotIn("known_result", completed["intake"])
        self.assertEqual(completed["status"], "ready_for_review")

    def test_manager_streams_runner_events_and_reverifies_persisted_artifact(self) -> None:
        manager = M1PilotRunManager(lifecycle_runner=self.runner)

        started = manager.start(self.intake)
        completed = _wait_for_terminal(manager, started["run_id"])
        stages = [(item["stage"], item["status"]) for item in completed["events"]]

        self.assertIn(("runtime_identity", "completed"), stages)
        self.assertIn(("validate", "completed"), stages)
        self.assertEqual(manager.get_observatory_html(started["run_id"]), "<html>trusted artifact</html>")

        reverified = manager.reverify(started["run_id"])

        self.assertEqual(reverified["status"], "ready_for_review")
        self.assertTrue(reverified["verification"]["trusted"])
        self.assertTrue(reverified["verification"]["report_matches_run_result"])
        self.assertEqual(self.runner.verify_calls, 1)

    def test_manager_refuses_a_second_run_while_fixed_profile_is_active(self) -> None:
        blocking = _BlockingLifecycleRunner()
        manager = M1PilotRunManager(lifecycle_runner=blocking)
        started = manager.start(self.intake)

        with self.assertRaisesRegex(PilotRunConflict, "reference_run_in_progress"):
            manager.start(self.intake)

        blocking.release()
        completed = _wait_for_terminal(manager, started["run_id"])
        self.assertEqual(completed["status"], "ready_for_review")

    def test_demo_app_serves_authenticated_pilot_flow_and_html(self) -> None:
        app = S1ReferenceDemoApp(
            lifecycle_runner=self.runner,
            default_job_id=M1_REFERENCE_JOB_ID,
            pilot_access_token="pilot-access-token",
        )
        root_status, root = app.http.handle(JsonRequest(method="GET", path="/", query={}, body=None))
        self.assertEqual(root_status, 200)
        self.assertIsInstance(root, HttpResponse)
        self.assertIn("Start verified run", root.body)
        self.assertIn("Re-verify artifact", root.body)
        self.assertIn("Export pilot record", root.body)

        status, denied = app.http.handle(
            JsonRequest(method="POST", path="/v1/pilot-runs", query={}, body=_intake_payload())
        )
        self.assertEqual(status, 401)
        self.assertEqual(denied["error"], "pilot_access_unauthorized")

        headers = {"authorization": "Bearer pilot-access-token"}
        status, started = app.http.handle(
            JsonRequest(method="POST", path="/v1/pilot-runs", query={}, body=_intake_payload(), headers=headers)
        )
        self.assertEqual(status, 202)
        run_id = started["run_id"]
        completed = _wait_for_http_terminal(app, run_id, headers=headers)
        self.assertEqual(completed["status"], "ready_for_review")

        status, artifact = app.http.handle(
            JsonRequest(
                method="GET",
                path=f"/v1/pilot-runs/{run_id}/observatory",
                query={},
                body=None,
                headers=headers,
            )
        )
        self.assertEqual(status, 200)
        self.assertIsInstance(artifact, HttpResponse)
        self.assertEqual(artifact.content_type, "text/html; charset=utf-8")

        status, reverified = app.http.handle(
            JsonRequest(
                method="POST",
                path=f"/v1/pilot-runs/{run_id}/verify",
                query={},
                body=None,
                headers=headers,
            )
        )
        self.assertEqual(status, 200)
        self.assertTrue(reverified["verification"]["trusted"])

    def test_html_response_preserves_content_type_and_security_headers_over_http(self) -> None:
        app = S1ReferenceDemoApp(
            lifecycle_runner=self.runner,
            default_job_id=M1_REFERENCE_JOB_ID,
            pilot_access_token="pilot-access-token",
        )
        port = _free_port()
        Thread(target=serve_json_app, kwargs={"app": app.http, "host": "127.0.0.1", "port": port}, daemon=True).start()
        _wait_for_port(port)

        with urlrequest.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
            body = response.read().decode("utf-8")
            self.assertEqual(response.headers.get_content_type(), "text/html")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertIn("connect-src 'self'", response.headers["Content-Security-Policy"])
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertIn("Argus M1 Pilot Console", body)
            self.assertIn("const {pilot_alias: _pilotAlias, ...runRequest} = study;", body)


@dataclass(frozen=True)
class _FakeVerification:
    trusted: bool = True

    def as_payload(self) -> dict[str, Any]:
        return {
            "trusted": self.trusted,
            "failures": [],
            "signature_key_id": "s3-reference-referee-key",
            "subject_ref": "c4://subject/reference",
            "report_ref": "c4://report/reference",
            "report_matches_run_result": True,
            "checked_at": "2026-07-11T00:00:00+00:00",
        }


class _FakeLifecycleRunner:
    def __init__(self) -> None:
        self.verify_calls = 0

    def run(self, *, job_id: str, event_sink: Any = None) -> M1ReferenceLifecycleResult:
        if event_sink is not None:
            event_sink({"stage": "runtime_identity", "status": "completed", "detail": {}})
            event_sink({"stage": "validate", "status": "completed", "detail": {"validation_report_ref": "c4://report/reference"}})
            event_sink({"stage": "observatory", "status": "completed", "detail": {"trusted": True}})
        return _fake_result(job_id)

    def verify_artifact(self, *, result: M1ReferenceLifecycleResult) -> _FakeVerification:
        self.verify_calls += 1
        self.assert_result(result)
        return _FakeVerification()

    def assert_result(self, result: M1ReferenceLifecycleResult) -> None:
        if result.job_id != M1_REFERENCE_JOB_ID:
            raise AssertionError("unexpected job id")


class _BlockingLifecycleRunner(_FakeLifecycleRunner):
    def __init__(self) -> None:
        super().__init__()
        self._released = False

    def release(self) -> None:
        self._released = True

    def run(self, *, job_id: str, event_sink: Any = None) -> M1ReferenceLifecycleResult:
        deadline = time.monotonic() + 5
        while not self._released:
            if time.monotonic() >= deadline:
                raise AssertionError("test runner was never released")
            time.sleep(0.005)
        return super().run(job_id=job_id, event_sink=event_sink)


def _intake_payload(**overrides: Any) -> dict[str, Any]:
    payload = {
        "reference_scope": M1_PILOT_REFERENCE_SCOPE,
        "research_question": "How does the fixed EWPT reference spectrum behave near its peak?",
        "known_result": "The sound-wave spectrum has a bounded peak and decays away from it.",
        "baseline_minutes": 60,
        "scope_acknowledged": True,
        "share_with_operator": True,
    }
    payload.update(overrides)
    return payload


def _fake_result(job_id: str) -> M1ReferenceLifecycleResult:
    return M1ReferenceLifecycleResult(
        job_id=job_id,
        final_state="REPORTED",
        lifecycle_methods=("accept", "plan", "build", "validate", "report"),
        dataset_ref="c4://dataset/reference",
        build_payload={"diagnostics": {}, "artifact_refs": ("c4://pipeline/reference",)},
        validation_report_ref="c4://report/reference",
        validation_report_payload={
            "claim_tier": "recapitulated-known",
            "checks": [],
            "referee": {"referee_id": "s3-reference-referee"},
            "signature": {"key_id": "s3-reference-referee-key"},
        },
        promoted_artifact_ref="c4://subject/reference",
        observatory_html_ref="c4://observatory/reference",
        observatory_html="<html>trusted artifact</html>",
        observatory_trusted=True,
        observatory_failures=(),
    )


def _wait_for_terminal(manager: M1PilotRunManager, run_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 5
    while True:
        snapshot = manager.get_snapshot(run_id)
        if snapshot["status"] not in {"queued", "running", "verifying"}:
            return snapshot
        if time.monotonic() >= deadline:
            raise AssertionError("pilot run did not finish")
        time.sleep(0.01)


def _wait_for_http_terminal(app: S1ReferenceDemoApp, run_id: str, *, headers: dict[str, str]) -> dict[str, Any]:
    deadline = time.monotonic() + 5
    while True:
        status, snapshot = app.http.handle(
            JsonRequest(method="GET", path=f"/v1/pilot-runs/{run_id}", query={}, body=None, headers=headers)
        )
        if status != 200:
            raise AssertionError(snapshot)
        if snapshot["status"] not in {"queued", "running", "verifying"}:
            return snapshot
        if time.monotonic() >= deadline:
            raise AssertionError("pilot HTTP run did not finish")
        time.sleep(0.01)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int) -> None:
    deadline = time.monotonic() + 5
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise AssertionError("HTTP test server did not start")
            time.sleep(0.01)


if __name__ == "__main__":
    unittest.main()
