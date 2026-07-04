from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import unittest
from uuid import UUID

import grpc
from jsonschema import Draft202012Validator

from argus_core import (
    InMemoryS1EventBus,
    InMemoryS1TelemetrySink,
    LifecycleState,
    SubagentDescriptor,
    SubagentRuntime,
)
from argus_core.s1 import S1_LIFECYCLE_LEDGER_KIND
from argus_runtime.http_json import JsonRequest
from argus_runtime.s1_wire_service import C1_GRPC_SERVICE, C1WireService, build_s1_grpc_server, build_s1_http_app


class S1WireServiceHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "contracts" / "c1.subagent.schema.json"
        cls.c1_validator = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))

    def setUp(self) -> None:
        self.runtime = SubagentRuntime(
            descriptor=SubagentDescriptor(
                subagent_id="subagent-wire",
                contract_version="1.0.0",
                subtopics=("ewpt",),
                required_adapters=("adapter:bounce",),
            ),
        )
        self.service = C1WireService(self.runtime)
        self.app = build_s1_http_app(self.service)
        self.job_id = "11111111-1111-4111-8111-111111111111"
        self.root_request_id = "22222222-2222-4222-8222-222222222222"
        self.trace_id = "trace-wire-http"

    def test_http_accept_and_plan_use_real_runtime_and_emit_c1_wire_lifecycle_event(self) -> None:
        accept_status, accept_payload = self.app.handle(
            JsonRequest(
                method="POST",
                path=f"/v1/jobs/{self.job_id}/accept",
                query={},
                body={
                    "root_request_id": self.root_request_id,
                    "trace_id": self.trace_id,
                    "job_envelope": self._job_envelope_payload(),
                },
            )
        )

        self.assertEqual(accept_status, 200)
        self.assertEqual(accept_payload["job_id"], self.job_id)
        self.assertTrue(accept_payload["accepted"])
        self.assertEqual(self.runtime.store.current(self.job_id).state, LifecycleState.ACCEPTED)
        self.assertEqual(self.runtime.store.events(self.job_id)[0].root_request_id, self.root_request_id)
        self.assertEqual(self.runtime.store.events(self.job_id)[0].trace_id, self.trace_id)
        self.assertIsNotNone(self.runtime.store.events(self.job_id)[0].ledger_ref)

        plan_status, plan_payload = self.app.handle(
            JsonRequest(
                method="POST",
                path=f"/v1/jobs/{self.job_id}/plan",
                query={},
                body={
                    "root_request_id": self.root_request_id,
                    "trace_id": self.trace_id,
                    "payload": {"step": "inspect"},
                },
            )
        )

        self.assertEqual(plan_status, 200)
        self.assertEqual(plan_payload["job_id"], self.job_id)
        self.assertEqual(plan_payload["root_request_id"], self.root_request_id)
        self.assertEqual(plan_payload["trace_id"], self.trace_id)
        self.assertEqual(plan_payload["seq"], 2)
        self.assertNotIn("sequence", plan_payload)
        self.assertEqual(plan_payload["from_state"], "ACCEPTED")
        self.assertEqual(plan_payload["to_state"], "PLANNING")
        self.assertEqual(plan_payload["method"], "plan")
        self.assertIn("ledger_ref", plan_payload)
        ledger_records = self.runtime.store.ledger_records(self.job_id)
        self.assertEqual(len(ledger_records), 2)
        self.assertEqual([record.kind for record in ledger_records], [S1_LIFECYCLE_LEDGER_KIND] * 2)
        self.assertEqual(ledger_records[1].lineage.input_refs, (ledger_records[0].artifact_ref,))
        UUID(plan_payload["event_id"])
        errors = sorted(self.c1_validator.iter_errors(plan_payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def test_http_lifecycle_policy_errors_return_typed_error_envelopes(self) -> None:
        self._accept_job()

        status, payload = self.app.handle(
            JsonRequest(
                method="GET",
                path=f"/v1/jobs/{self.job_id}/report",
                query={},
                body={
                    "root_request_id": self.root_request_id,
                    "trace_id": self.trace_id,
                    "payload": {},
                },
            )
        )

        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "ILLEGAL_TRANSITION")
        self.assertEqual(payload["error"]["category"], "POLICY")
        self.assertFalse(payload["error"]["retryable"])
        self.assertEqual(len(self.runtime.store.events(self.job_id)), 1)

    def test_http_accept_refusal_is_non_error_c1_payload(self) -> None:
        status, payload = self.app.handle(
            JsonRequest(
                method="POST",
                path=f"/v1/jobs/{self.job_id}/accept",
                query={},
                body={
                    "root_request_id": self.root_request_id,
                    "trace_id": self.trace_id,
                    "job_envelope": self._job_envelope_payload(verifier_profile_ref=None),
                },
            )
        )

        self.assertEqual(status, 200)
        self.assertNotIn("error", payload)
        self.assertFalse(payload["accepted"])
        self.assertEqual(payload["reason"], "NO_VERIFIER")
        self.assertEqual(payload["state"], "REJECTED")
        self.assertEqual(self.runtime.store.current(self.job_id).state, LifecycleState.REJECTED)
        self.assertEqual([(event.method, event.to_state) for event in self.runtime.store.events(self.job_id)], [("refuse", LifecycleState.REJECTED)])
        errors = sorted(self.c1_validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def test_http_heartbeat_reports_current_state_without_transition(self) -> None:
        self._accept_job()

        status, payload = self.app.handle(
            JsonRequest(
                method="GET",
                path=f"/v1/jobs/{self.job_id}/heartbeat",
                query={"trace_id": [self.trace_id]},
                body=None,
            )
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["job_id"], self.job_id)
        self.assertEqual(payload["status"], "ACCEPTED")
        self.assertEqual(payload["progress"], 0.0)
        self.assertEqual(payload["spend_so_far"], {"cost_usd": 0.0})
        self.assertIn("last_heartbeat_at", payload)
        datetime.fromisoformat(str(payload["last_heartbeat_at"]).replace("Z", "+00:00"))
        self.assertNotIn("last_sequence", payload)
        self.assertNotIn("trace_id", payload)
        errors = sorted(self.c1_validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])
        self.assertEqual(len(self.runtime.store.events(self.job_id)), 1)

    def test_http_heartbeat_reports_runtime_progress_and_spend(self) -> None:
        self._accept_job()
        self.runtime.store.apply_method(self.job_id, "plan", payload={"step": "inspect"})
        self.runtime.store.apply_method(self.job_id, "build", payload={"artifact_refs": []})
        self.runtime.record_heartbeat(
            self.job_id,
            progress=0.60,
            spend_so_far={"cost_usd": 1.25, "gpu_seconds": 10.0},
        )

        status, payload = self.app.handle(
            JsonRequest(
                method="GET",
                path=f"/v1/jobs/{self.job_id}/heartbeat",
                query={"trace_id": [self.trace_id]},
                body=None,
            )
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["job_id"], self.job_id)
        self.assertEqual(payload["status"], "BUILDING")
        self.assertEqual(payload["progress"], 0.60)
        self.assertEqual(payload["spend_so_far"], {"cost_usd": 1.25, "gpu_seconds": 10.0})
        datetime.fromisoformat(str(payload["last_heartbeat_at"]).replace("Z", "+00:00"))
        errors = sorted(self.c1_validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])
        self.assertEqual([event.method for event in self.runtime.store.events(self.job_id)], ["accept", "plan", "build"])

    def test_http_methods_emit_s1_spans_and_nats_style_events(self) -> None:
        event_bus = InMemoryS1EventBus()
        telemetry = InMemoryS1TelemetrySink()
        runtime = SubagentRuntime(
            descriptor=SubagentDescriptor(
                subagent_id="subagent-wire-observed",
                contract_version="1.0.0",
                subtopics=("ewpt",),
                required_adapters=("adapter:bounce",),
            ),
            event_bus=event_bus,
            telemetry_sink=telemetry,
        )
        app = build_s1_http_app(C1WireService(runtime))

        register_status, register_payload = app.handle(
            JsonRequest(
                method="POST",
                path="/v1/subagents/subagent-wire-observed/register",
                query={},
                body={"root_request_id": self.root_request_id, "trace_id": self.trace_id},
            )
        )
        accept_status, _accept_payload = app.handle(
            JsonRequest(
                method="POST",
                path=f"/v1/jobs/{self.job_id}/accept",
                query={},
                body={
                    "root_request_id": self.root_request_id,
                    "trace_id": self.trace_id,
                    "job_envelope": self._job_envelope_payload(),
                },
            )
        )
        heartbeat_status, _heartbeat_payload = app.handle(
            JsonRequest(
                method="GET",
                path=f"/v1/jobs/{self.job_id}/heartbeat",
                query={"trace_id": [self.trace_id], "root_request_id": [self.root_request_id]},
                body=None,
            )
        )

        self.assertEqual(register_status, 200)
        self.assertEqual(accept_status, 200)
        self.assertEqual(heartbeat_status, 200)
        self.assertEqual(register_payload["subagent_id"], "subagent-wire-observed")
        self.assertEqual([span.name for span in telemetry.spans(trace_id=self.trace_id)], ["S1.register", "S1.accept", "S1.heartbeat"])
        self.assertEqual(event_bus.subscribe("s1.subagent.registered")[0].payload["subagent_id"], "subagent-wire-observed")
        transition = event_bus.subscribe("s1.lifecycle.transition")[0]
        self.assertEqual(transition.payload["method"], "accept")
        self.assertEqual(transition.payload["trace_id"], self.trace_id)
        self.assertEqual(transition.payload["root_request_id"], self.root_request_id)

    def _accept_job(self) -> None:
        status, payload = self.app.handle(
            JsonRequest(
                method="POST",
                path=f"/v1/jobs/{self.job_id}/accept",
                query={},
                body={
                    "root_request_id": self.root_request_id,
                    "trace_id": self.trace_id,
                    "job_envelope": self._job_envelope_payload(),
                },
            )
        )
        self.assertEqual(status, 200, payload)

    def _job_envelope_payload(self, **overrides: object) -> dict[str, object]:
        payload = {
            "job_id": self.job_id,
            "envelope_version": "1.0.0",
            "subtopic": "ewpt",
            "required_adapters": ["adapter:bounce"],
            "allowed_adapters": ["adapter:bounce"],
            "verifier_profile_ref": "c4://profile/ewpt/v1",
            "estimated_cost": 1,
            "budget_cost": 2,
        }
        payload.update(overrides)
        return payload


class S1WireServiceGrpcTests(unittest.TestCase):
    def test_grpc_register_accept_and_plan_use_real_server(self) -> None:
        runtime = SubagentRuntime(
            descriptor=SubagentDescriptor(
                subagent_id="subagent-grpc",
                contract_version="1.0.0",
                subtopics=("ewpt",),
                required_adapters=("adapter:bounce",),
            )
        )
        server, port = build_s1_grpc_server(C1WireService(runtime))
        server.start()
        try:
            channel = grpc.insecure_channel(f"127.0.0.1:{port}")
            register = _grpc_method(channel, "Register")
            accept = _grpc_method(channel, "Accept")
            plan = _grpc_method(channel, "Plan")
            heartbeat = _grpc_method(channel, "Heartbeat")
            job_id = "33333333-3333-4333-8333-333333333333"
            root_request_id = "44444444-4444-4444-8444-444444444444"
            trace_id = "trace-wire-grpc"

            register_payload = register({"subagent_id": "subagent-grpc"}, timeout=5)
            self.assertEqual(register_payload["subagent_id"], "subagent-grpc")
            self.assertEqual(register_payload["subtopics"], ["ewpt"])

            acceptance = accept(
                {
                    "root_request_id": root_request_id,
                    "trace_id": trace_id,
                    "job_envelope": {
                        "job_id": job_id,
                        "envelope_version": "1.0.0",
                        "subtopic": "ewpt",
                        "required_adapters": ["adapter:bounce"],
                        "allowed_adapters": ["adapter:bounce"],
                        "verifier_profile_ref": "c4://profile/ewpt/v1",
                        "estimated_cost": 1,
                        "budget_cost": 2,
                    },
                },
                timeout=5,
            )
            self.assertTrue(acceptance["accepted"])

            planned = plan(
                {
                    "job_id": job_id,
                    "root_request_id": root_request_id,
                    "trace_id": trace_id,
                    "payload": {"step": "inspect"},
                },
                timeout=5,
            )
            self.assertEqual(planned["seq"], 2)
            self.assertEqual(planned["root_request_id"], root_request_id)
            self.assertEqual(planned["trace_id"], trace_id)
            self.assertEqual(runtime.store.current(job_id).state, LifecycleState.PLANNING)

            heartbeat_payload = heartbeat({"job_id": job_id, "trace_id": trace_id}, timeout=5)
            self.assertEqual(heartbeat_payload["status"], "PLANNING")
            self.assertIn("last_heartbeat_at", heartbeat_payload)
            self.assertNotIn("last_sequence", heartbeat_payload)
            self.assertNotIn("trace_id", heartbeat_payload)
            schema_path = Path(__file__).resolve().parents[1] / "schemas" / "contracts" / "c1.subagent.schema.json"
            c1_validator = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
            errors = sorted(c1_validator.iter_errors(heartbeat_payload), key=lambda error: list(error.path))
            self.assertEqual(errors, [], msg=[error.message for error in errors])
        finally:
            server.stop(0)


def _grpc_method(channel: grpc.Channel, method: str):
    return channel.unary_unary(
        f"/{C1_GRPC_SERVICE}/{method}",
        request_serializer=lambda value: json.dumps(value, sort_keys=True).encode("utf-8"),
        response_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
    )
