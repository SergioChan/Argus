from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from argus_core import (
    Acceptance,
    C3ReportSigner,
    C3ReportVerifier,
    ExecContext,
    IdempotencyRecord,
    InMemoryIdempotencyStore,
    InMemoryArtifactStore,
    InMemoryS1EventBus,
    InMemoryS1TelemetrySink,
    InMemoryVerifierTrustStore,
    JobEnvelope,
    LEGAL_TRANSITIONS,
    Lineage,
    LifecyclePolicyError,
    LifecycleState,
    LifecycleStore,
    Producer,
    SubagentDescriptor,
    SubagentRuntime,
    TERMINAL_STATES,
    build_error_envelope,
    build_subagent_report,
    canonical_json_bytes,
    default_accept,
    hash_json,
    reduce_lifecycle,
    tag_uncertainty,
)
from argus_core.s1 import METHOD_TARGETS, NON_TRANSITION_METHODS, S1_LIFECYCLE_LEDGER_KIND, S1_SANDBOX_ATTACHMENT_KIND


def _test_descriptor() -> SubagentDescriptor:
    return SubagentDescriptor(
        subagent_id="s1-t19-subagent",
        contract_version="1.0.0",
        subtopics=("ewpt",),
        required_adapters=("adapter:bounce",),
    )


class _CancelableSandboxMarshaler:
    def __init__(self) -> None:
        self.cancellations: list[dict[str, object]] = []

    def cancel_sandbox_job(
        self,
        *,
        job_id: str,
        sandbox_id: str,
        reason: str,
        grace_seconds: float,
    ) -> dict[str, object]:
        self.cancellations.append(
            {
                "job_id": job_id,
                "sandbox_id": sandbox_id,
                "reason": reason,
                "grace_seconds": grace_seconds,
            }
        )
        return {
            "job_id": job_id,
            "sandbox_id": sandbox_id,
            "state": "TERMINATED",
            "terminate_succeeded": True,
            "partial_result_ref": "c4://artifact/partial-cancel-1",
        }


class _QuarantineSandboxMarshaler:
    def __init__(self) -> None:
        self.quarantines: list[dict[str, object]] = []

    def quarantine_sandbox_job(
        self,
        *,
        job_id: str,
        sandbox_id: str,
        reason: str,
        grace_seconds: float,
        error: dict[str, object],
    ) -> dict[str, object]:
        self.quarantines.append(
            {
                "job_id": job_id,
                "sandbox_id": sandbox_id,
                "reason": reason,
                "grace_seconds": grace_seconds,
                "error": error,
            }
        )
        return {
            "job_id": job_id,
            "sandbox_id": sandbox_id,
            "state": "QUARANTINED",
            "terminate_succeeded": True,
            "partial_result_ref": "c4://artifact/partial-quarantine-1",
        }


class _ReattachSandboxMarshaler:
    def __init__(self, handles: dict[str, dict[str, object]]) -> None:
        self.handles = handles
        self.resolved: list[dict[str, object]] = []

    def get(self, sandbox_id: str) -> dict[str, object]:
        payload = dict(self.handles[sandbox_id])
        self.resolved.append(payload)
        return payload


class S1LifecycleStoreTests(unittest.TestCase):
    def test_lifecycle_state_table_matches_c1_schema(self) -> None:
        schema_states = self._c1_def_enum("LifecycleState")
        runtime_states = {state.value for state in LifecycleState}

        self.assertEqual(runtime_states, schema_states)
        self.assertEqual(set(LEGAL_TRANSITIONS), set(LifecycleState))
        for from_state, to_states in LEGAL_TRANSITIONS.items():
            self.assertIsInstance(from_state, LifecycleState)
            self.assertTrue(to_states <= set(LifecycleState))
        for terminal_state in TERMINAL_STATES:
            self.assertEqual(LEGAL_TRANSITIONS[terminal_state], frozenset())

    def test_lifecycle_method_table_matches_c1_schema(self) -> None:
        schema_methods = self._c1_def_enum("LifecycleMethod")

        self.assertEqual(set(METHOD_TARGETS) | set(NON_TRANSITION_METHODS), schema_methods)
        self.assertEqual(NON_TRANSITION_METHODS, {"register", "heartbeat"})
        for target_state in METHOD_TARGETS.values():
            self.assertIsInstance(target_state, LifecycleState)

    def test_legal_transition_appends_event(self) -> None:
        store = LifecycleStore()
        store.create_job("job-1")
        store.apply_method("job-1", "accept")

        event = store.apply_method("job-1", "plan")

        self.assertEqual(store.current("job-1").state, LifecycleState.PLANNING)
        self.assertEqual(event.from_state, LifecycleState.ACCEPTED)
        self.assertEqual(event.to_state, LifecycleState.PLANNING)
        self.assertEqual(len(store.events("job-1")), 2)

    def test_illegal_transition_rejected_without_event(self) -> None:
        store = LifecycleStore()
        store.create_job("job-1")

        with self.assertRaises(LifecyclePolicyError) as raised:
            store.apply_method("job-1", "build")

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(store.current("job-1").state, LifecycleState.REGISTERED)
        self.assertEqual(len(store.events("job-1")), 0)

    def test_cancel_transition_reaches_cancelled_without_claiming_cooperative_cancel(self) -> None:
        store = LifecycleStore()
        store.create_job("job-1")
        store.apply_method("job-1", "accept")
        store.apply_method("job-1", "plan")

        event = store.apply_method("job-1", "cancel", trigger="cancel", payload={"reason": "operator"})

        self.assertEqual(event.from_state, LifecycleState.PLANNING)
        self.assertEqual(event.to_state, LifecycleState.CANCELLED)
        self.assertEqual(store.current("job-1").state, LifecycleState.CANCELLED)
        with self.assertRaises(LifecyclePolicyError) as raised:
            store.apply_method("job-1", "build")
        self.assertEqual(raised.exception.envelope.category, "POLICY")

    def test_terminal_states_reject_all_transition_methods_without_new_events(self) -> None:
        paths = {
            LifecycleState.REPORTED: ("accept", "plan", "build", "validate", "report"),
            LifecycleState.FAILED: ("accept", "fail"),
            LifecycleState.REJECTED: ("refuse",),
            LifecycleState.CANCELLED: ("accept", "cancel"),
            LifecycleState.QUARANTINED: ("accept", "quarantine"),
        }
        for terminal_state, setup_methods in paths.items():
            with self.subTest(terminal_state=terminal_state.value):
                store = LifecycleStore()
                store.create_job("job-1")
                for method in setup_methods:
                    store.apply_method("job-1", method)
                event_count = len(store.events("job-1"))
                self.assertEqual(store.current("job-1").state, terminal_state)

                for method in METHOD_TARGETS:
                    with self.subTest(method=method):
                        with self.assertRaises(LifecyclePolicyError):
                            store.apply_method(
                                "job-1",
                                method,
                                trigger="terminal-probe",
                                payload={"method": method},
                            )
                        self.assertEqual(len(store.events("job-1")), event_count)
                        self.assertEqual(store.current("job-1").state, terminal_state)

    def test_replay_is_deterministic(self) -> None:
        store = LifecycleStore()
        store.create_job("job-1")
        for method in ("accept", "plan", "build", "validate", "report"):
            store.apply_method("job-1", method, payload={"method": method})

        events = store.events("job-1")
        first = reduce_lifecycle(events, job_id="job-1")
        second = reduce_lifecycle(events, job_id="job-1")

        self.assertEqual(canonical_json_bytes(first.__dict__), canonical_json_bytes(second.__dict__))
        self.assertEqual(first, store.current("job-1"))

    def test_lifecycle_events_are_mirrored_to_c4_ledger(self) -> None:
        artifacts = InMemoryArtifactStore()
        store = LifecycleStore(artifact_store=artifacts)
        store.create_job("job-1")

        accepted = store.apply_method("job-1", "accept", trigger="operator", payload={"ok": True})
        planned = store.apply_method("job-1", "plan", trigger="runtime", payload={"step": "plan"})

        self.assertEqual(store.ledger_refs("job-1"), (accepted.ledger_ref, planned.ledger_ref))
        self.assertIsNotNone(accepted.ledger_ref)
        self.assertIsNotNone(planned.ledger_ref)

        accepted_record = artifacts.get_record(accepted.ledger_ref or "")
        planned_record = artifacts.get_record(planned.ledger_ref or "")
        accepted_payload = json.loads(artifacts.get_artifact(accepted.ledger_ref or "").decode("utf-8"))
        planned_payload = json.loads(artifacts.get_artifact(planned.ledger_ref or "").decode("utf-8"))

        self.assertEqual(accepted_record.kind, S1_LIFECYCLE_LEDGER_KIND)
        self.assertEqual(planned_record.kind, S1_LIFECYCLE_LEDGER_KIND)
        self.assertEqual(accepted_record.producer.subsystem, "S1")
        self.assertEqual(accepted_record.producer.job_id, "job-1")
        self.assertEqual(accepted_record.lineage.input_refs, ())
        self.assertEqual(planned_record.lineage.input_refs, (accepted.ledger_ref,))
        self.assertEqual(accepted_payload["schema"], "argus.s1.lifecycle_event.v1")
        self.assertEqual(accepted_payload["from_state"], "REGISTERED")
        self.assertEqual(accepted_payload["to_state"], "ACCEPTED")
        self.assertEqual(accepted_payload["method"], "accept")
        self.assertEqual(accepted_payload["idempotency_key"], accepted.idempotency_key)
        self.assertEqual(planned_payload["sequence"], 2)
        self.assertEqual(planned_payload["idempotency_key"], planned.idempotency_key)
        self.assertEqual(planned_payload["payload_hash"], planned.payload_hash)
        self.assertTrue(artifacts.verify_audit_chain().valid)

    def test_lifecycle_store_publishes_nats_style_transition_events(self) -> None:
        artifacts = InMemoryArtifactStore()
        event_bus = InMemoryS1EventBus()
        store = LifecycleStore(artifact_store=artifacts, event_bus=event_bus)
        store.create_job("job-1")

        accepted = store.apply_method(
            "job-1",
            "accept",
            trigger="S5",
            payload={"accepted": True},
            root_request_id="root-1",
            trace_id="trace-s1-t24",
        )
        planned = store.apply_method(
            "job-1",
            "plan",
            trigger="internal",
            payload={"step": "inspect"},
            root_request_id="root-1",
            trace_id="trace-s1-t24",
        )

        transition_events = event_bus.subscribe("s1.lifecycle.transition")
        self.assertEqual([event.payload["method"] for event in transition_events], ["accept", "plan"])
        self.assertEqual([event.payload["event_id"] for event in transition_events], [accepted.event_id, planned.event_id])
        self.assertEqual(transition_events[0].payload["from_state"], "REGISTERED")
        self.assertEqual(transition_events[0].payload["to_state"], "ACCEPTED")
        self.assertEqual(transition_events[1].payload["seq"], 2)
        self.assertEqual(transition_events[1].payload["ledger_ref"], planned.ledger_ref)
        self.assertEqual(transition_events[1].payload["root_request_id"], "root-1")
        self.assertEqual(transition_events[1].payload["trace_id"], "trace-s1-t24")

    def test_runtime_publishes_register_refusal_and_quarantine_domain_events(self) -> None:
        event_bus = InMemoryS1EventBus()
        runtime = SubagentRuntime(descriptor=_test_descriptor(), event_bus=event_bus)

        registration = runtime.register(root_request_id="root-register", trace_id="trace-register")
        refused = runtime.accept(
            JobEnvelope(
                job_id="11111111-1111-4111-8111-111111111111",
                envelope_version="1.0.0",
                subtopic="ewpt",
                required_adapters=("adapter:bounce",),
                allowed_adapters=("adapter:bounce",),
                verifier_profile_ref=None,
                estimated_cost=0.5,
                budget_cost=1.0,
            ),
            root_request_id="root-refuse",
            trace_id="trace-refuse",
        )
        runtime.store.create_job("22222222-2222-4222-8222-222222222222")
        runtime.store.apply_method("22222222-2222-4222-8222-222222222222", "accept")
        runtime.store.apply_method("22222222-2222-4222-8222-222222222222", "plan")
        quarantine_error = build_error_envelope(
            category="SANDBOX",
            code="DIRECT_IN_PROCESS_EXEC_FORBIDDEN",
            message="direct exec attempted",
        )
        quarantined = runtime.quarantine(
            "22222222-2222-4222-8222-222222222222",
            error=quarantine_error,
            root_request_id="root-quarantine",
            trace_id="trace-quarantine",
        )

        registered_events = event_bus.subscribe("s1.subagent.registered")
        refused_events = event_bus.subscribe("s1.job.refused")
        quarantine_events = event_bus.subscribe("s1.job.quarantined")
        self.assertEqual(registration["subagent_id"], _test_descriptor().subagent_id)
        self.assertEqual(registered_events[0].payload["subagent_id"], _test_descriptor().subagent_id)
        self.assertFalse(refused.accepted)
        self.assertEqual(refused_events[0].payload["reason"], "NO_VERIFIER")
        self.assertEqual(refused_events[0].payload["job_id"], refused.job_id)
        self.assertEqual(quarantine_events[0].payload["job_id"], quarantined.job_id)
        self.assertEqual(quarantine_events[0].payload["error"]["code"], "DIRECT_IN_PROCESS_EXEC_FORBIDDEN")

    def test_runtime_records_s11_compatible_method_spans(self) -> None:
        telemetry = InMemoryS1TelemetrySink()
        runtime = SubagentRuntime(descriptor=_test_descriptor(), telemetry_sink=telemetry)
        job_id = "33333333-3333-4333-8333-333333333333"
        runtime.store.create_job(job_id)

        runtime.accept(
            JobEnvelope(
                job_id=job_id,
                envelope_version="1.0.0",
                subtopic="ewpt",
                required_adapters=("adapter:bounce",),
                allowed_adapters=("adapter:bounce",),
                verifier_profile_ref="c4://profile/ewpt/v1",
                estimated_cost=0.5,
                budget_cost=1.0,
            ),
            root_request_id="root-span",
            trace_id="trace-span",
        )
        runtime.heartbeat(job_id, root_request_id="root-span", trace_id="trace-span")

        spans = telemetry.spans(trace_id="trace-span")
        self.assertEqual([span.name for span in spans], ["S1.accept", "S1.heartbeat"])
        self.assertEqual([span.subsystem for span in spans], ["S1", "S1"])
        self.assertEqual(spans[0].attributes["job_id"], job_id)
        self.assertEqual(spans[0].attributes["root_request_id"], "root-span")
        self.assertEqual(spans[0].attributes["method"], "accept")
        self.assertEqual(spans[1].attributes["state"], "ACCEPTED")

    def test_lifecycle_method_idempotency_returns_stored_event_without_new_side_effects(self) -> None:
        artifacts = InMemoryArtifactStore()
        store = LifecycleStore(artifact_store=artifacts)
        store.create_job("job-1")

        first = store.apply_method(
            "job-1",
            "accept",
            trigger="S5",
            payload={"accepted": True},
            idempotency_key="accept-job-1",
        )
        second = store.apply_method(
            "job-1",
            "accept",
            trigger="S5",
            payload={"accepted": True},
            idempotency_key="accept-job-1",
        )

        self.assertEqual(second, first)
        self.assertEqual(store.current("job-1").state, LifecycleState.ACCEPTED)
        self.assertEqual(store.events("job-1"), (first,))
        self.assertEqual(store.ledger_refs("job-1"), (first.ledger_ref,))
        self.assertEqual(len(store.ledger_records("job-1")), 1)
        idempotency = store.idempotency_records("job-1")
        self.assertEqual(len(idempotency), 1)
        self.assertEqual(idempotency[0].method, "lifecycle.accept")
        self.assertEqual(idempotency[0].idempotency_key, "accept-job-1")
        self.assertIsInstance(idempotency[0], IdempotencyRecord)

    def test_default_cancel_idempotency_returns_stored_event_for_bare_retry(self) -> None:
        artifacts = InMemoryArtifactStore()
        store = LifecycleStore(artifact_store=artifacts)
        store.create_job("job-1")
        store.apply_method("job-1", "accept")
        store.apply_method("job-1", "plan")

        first = store.apply_method("job-1", "cancel", trigger="operator", payload={"reason": "blip"})
        second = store.apply_method("job-1", "cancel", trigger="operator", payload={"reason": "blip"})

        self.assertEqual(second, first)
        self.assertEqual(store.current("job-1").state, LifecycleState.CANCELLED)
        self.assertEqual(store.events("job-1")[-1], first)
        self.assertEqual(len(store.events("job-1")), 3)
        self.assertEqual(len(store.ledger_records("job-1")), 3)
        self.assertEqual(len(store.idempotency_records("job-1")), 3)
        self.assertTrue(first.idempotency_key.startswith("cancel:job-1:"))

    def test_runtime_heartbeat_records_progress_and_monotonic_spend(self) -> None:
        runtime = SubagentRuntime(descriptor=_test_descriptor())
        job_id = "11111111-1111-4111-8111-111111111111"
        runtime.store.create_job(job_id)
        runtime.store.apply_method(job_id, "accept")
        runtime.store.apply_method(job_id, "plan")
        runtime.store.apply_method(job_id, "build")

        first = runtime.record_heartbeat(job_id, progress=0.25, spend_so_far={"cost_usd": 0.5})
        second = runtime.record_heartbeat(
            job_id,
            progress=0.75,
            spend_so_far={"cost_usd": 0.5, "gpu_seconds": 2.0},
        )
        health = runtime.heartbeat(job_id)

        self.assertEqual(first.status, LifecycleState.BUILDING)
        self.assertEqual(second.status, LifecycleState.BUILDING)
        self.assertEqual(health.job_id, job_id)
        self.assertEqual(health.progress, 0.75)
        self.assertEqual(health.spend_so_far, {"cost_usd": 0.5, "gpu_seconds": 2.0})
        self.assertEqual(health.as_c1_payload()["spend_so_far"], {"cost_usd": 0.5, "gpu_seconds": 2.0})
        self.assertEqual(len(runtime.store.events(job_id)), 3)

        with self.assertRaises(LifecyclePolicyError) as raised:
            runtime.record_heartbeat(job_id, progress=0.80, spend_so_far={"cost_usd": 0.4})

        self.assertEqual(raised.exception.envelope.code, "S1_HEARTBEAT_SPEND_REGRESSION")
        self.assertEqual(runtime.heartbeat(job_id).spend_so_far["cost_usd"], 0.5)

    def test_runtime_cancel_terminates_active_sandbox_with_partial_provenance(self) -> None:
        artifacts = InMemoryArtifactStore()
        marshaler = _CancelableSandboxMarshaler()
        runtime = SubagentRuntime(
            descriptor=_test_descriptor(),
            artifact_store=artifacts,
            sandbox_marshaler=marshaler,
        )
        job_id = "22222222-2222-4222-8222-222222222222"
        runtime.store.create_job(job_id)
        runtime.store.apply_method(job_id, "accept")
        runtime.store.apply_method(job_id, "plan")
        runtime.store.apply_method(job_id, "build")
        runtime.register_sandbox_result(
            job_id,
            {
                "sandbox_id": "sandbox-cancel-1",
                "state": "ADMITTED",
                "launch_provenance_ref": "c4://artifact/launch-1",
            },
        )

        event = runtime.cancel(job_id, reason="operator", grace_seconds=1.5)

        self.assertTrue(runtime.cancel_requested(job_id))
        self.assertEqual(runtime.store.current(job_id).state, LifecycleState.CANCELLED)
        self.assertEqual(event.to_state, LifecycleState.CANCELLED)
        self.assertEqual(
            marshaler.cancellations,
            [
                {
                    "job_id": job_id,
                    "sandbox_id": "sandbox-cancel-1",
                    "reason": "operator",
                    "grace_seconds": 1.5,
                }
            ],
        )
        expected_payload = {
            "category": "CANCELLED",
            "cooperative": True,
            "grace_seconds": 1.5,
            "reason": "operator",
            "sandbox_cancellations": [
                {
                    "job_id": job_id,
                    "launch_provenance_ref": "c4://artifact/launch-1",
                    "partial_result_ref": "c4://artifact/partial-cancel-1",
                    "sandbox_id": "sandbox-cancel-1",
                    "state": "TERMINATED",
                    "terminate_succeeded": True,
                }
            ],
        }
        self.assertEqual(event.payload_hash, hash_json(expected_payload))
        self.assertIsNotNone(event.ledger_ref)
        cancel_record = artifacts.get_record(event.ledger_ref or "")
        self.assertEqual(cancel_record.lineage.input_refs, (runtime.store.events(job_id)[-2].ledger_ref,))

    def test_runtime_quarantine_freezes_active_sandbox_with_forensic_provenance(self) -> None:
        artifacts = InMemoryArtifactStore()
        marshaler = _QuarantineSandboxMarshaler()
        runtime = SubagentRuntime(
            descriptor=_test_descriptor(),
            artifact_store=artifacts,
            sandbox_marshaler=marshaler,
        )
        job_id = "23232323-2323-4323-8323-232323232323"
        runtime.store.create_job(job_id)
        runtime.store.apply_method(job_id, "accept")
        runtime.store.apply_method(job_id, "plan")
        runtime.store.apply_method(job_id, "build")
        runtime.register_sandbox_result(
            job_id,
            {
                "sandbox_id": "sandbox-quarantine-1",
                "state": "ADMITTED",
                "launch_provenance_ref": "c4://artifact/launch-quarantine-1",
            },
        )
        error = build_error_envelope(
            category="SANDBOX",
            code="TRUST_PATH_WRITE",
            message="sandbox attempted to write a verifier mount",
        )

        event = runtime.quarantine(job_id, error=error, reason="trust-path-write", grace_seconds=2.0)

        self.assertEqual(runtime.store.current(job_id).state, LifecycleState.QUARANTINED)
        self.assertEqual(event.to_state, LifecycleState.QUARANTINED)
        self.assertEqual(
            marshaler.quarantines,
            [
                {
                    "job_id": job_id,
                    "sandbox_id": "sandbox-quarantine-1",
                    "reason": "trust-path-write",
                    "grace_seconds": 2.0,
                    "error": error.as_c1_payload(),
                }
            ],
        )
        expected_payload = {
            "category": "SANDBOX",
            "code": "TRUST_PATH_WRITE",
            "error": error.as_c1_payload(),
            "grace_seconds": 2.0,
            "reason": "trust-path-write",
            "sandbox_quarantines": [
                {
                    "job_id": job_id,
                    "launch_provenance_ref": "c4://artifact/launch-quarantine-1",
                    "partial_result_ref": "c4://artifact/partial-quarantine-1",
                    "sandbox_id": "sandbox-quarantine-1",
                    "state": "QUARANTINED",
                    "terminate_succeeded": True,
                }
            ],
        }
        self.assertEqual(event.payload_hash, hash_json(expected_payload))
        quarantine_record = artifacts.get_record(event.ledger_ref or "")
        self.assertEqual(quarantine_record.lineage.input_refs, (runtime.store.events(job_id)[-2].ledger_ref,))

    def test_default_report_idempotency_returns_stored_event_for_bare_retry(self) -> None:
        artifacts = InMemoryArtifactStore()
        store = LifecycleStore(artifact_store=artifacts)
        store.create_job("job-1")
        for method in ("accept", "plan", "build", "validate"):
            store.apply_method("job-1", method, payload={"method": method})

        first = store.apply_method("job-1", "report", trigger="runtime", payload={"artifact_refs": ["c4://a"]})
        second = store.apply_method("job-1", "report", trigger="runtime", payload={"artifact_refs": ["c4://a"]})

        self.assertEqual(second, first)
        self.assertEqual(store.current("job-1").state, LifecycleState.REPORTED)
        self.assertEqual(store.events("job-1")[-1], first)
        self.assertEqual(len(store.events("job-1")), 5)
        self.assertEqual(len(store.ledger_records("job-1")), 5)
        self.assertEqual(len(store.idempotency_records("job-1")), 5)
        self.assertTrue(first.idempotency_key.startswith("report:job-1:"))

    def test_lifecycle_idempotency_conflict_rejects_before_ledger_side_effect(self) -> None:
        artifacts = InMemoryArtifactStore()
        store = LifecycleStore(artifact_store=artifacts)
        store.create_job("job-1")
        store.apply_method(
            "job-1",
            "accept",
            trigger="S5",
            payload={"accepted": True},
            idempotency_key="accept-job-1",
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            store.apply_method(
                "job-1",
                "accept",
                trigger="S5",
                payload={"accepted": False},
                idempotency_key="accept-job-1",
            )

        self.assertEqual(raised.exception.envelope.code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(store.current("job-1").state, LifecycleState.ACCEPTED)
        self.assertEqual(len(store.events("job-1")), 1)
        self.assertEqual(len(store.ledger_records("job-1")), 1)

    def test_job_current_is_rebuildable_from_event_log(self) -> None:
        artifacts = InMemoryArtifactStore()
        store = LifecycleStore(artifact_store=artifacts)
        store.create_job("job-1")
        for method in ("accept", "plan", "build"):
            store.apply_method("job-1", method, payload={"method": method})

        rebuilt = LifecycleStore.from_event_log(
            {"job-1": store.events("job-1")},
            artifact_store=artifacts,
        )

        self.assertEqual(rebuilt.current("job-1"), store.current("job-1"))
        self.assertEqual(rebuilt.replay("job-1"), store.current("job-1"))
        self.assertEqual(rebuilt.ledger_refs("job-1"), store.ledger_refs("job-1"))

    def test_runtime_restart_recovers_building_state_and_active_sandbox_from_c4_attachment(self) -> None:
        artifacts = InMemoryArtifactStore()
        descriptor = _test_descriptor()
        runtime = SubagentRuntime(descriptor=descriptor, artifact_store=artifacts)
        job_id = "24242424-2424-4424-8424-242424242424"
        runtime.store.create_job(job_id)
        runtime.store.apply_method(job_id, "accept")
        runtime.store.apply_method(job_id, "plan")
        runtime.store.apply_method(job_id, "build")
        runtime.register_sandbox_result(
            job_id,
            {
                "sandbox_id": "sandbox-restart-1",
                "runtime_class": "gvisor",
                "budget_epoch": 7,
                "policy_bundle_version": "s1-t27-test",
                "state": "ADMITTED",
                "launch_provenance_ref": "c4://artifact/launch-restart-1",
            },
        )
        attachment_refs = runtime.sandbox_attachment_refs(job_id)
        before_refs = tuple(record.artifact_ref for record in artifacts.query_artifacts())

        rebuilt_store = LifecycleStore.from_event_log(
            {job_id: runtime.store.events(job_id)},
            artifact_store=artifacts,
        )
        reattach = _ReattachSandboxMarshaler(
            {
                "sandbox-restart-1": {
                    "sandbox_id": "sandbox-restart-1",
                    "job_id": job_id,
                    "runtime_class": "gvisor",
                    "budget_epoch": 7,
                    "policy_bundle_version": "s1-t27-test",
                    "state": "ADMITTED",
                    "launch_provenance_ref": "c4://artifact/launch-restart-1",
                }
            }
        )
        restarted = SubagentRuntime(
            descriptor=descriptor,
            store=rebuilt_store,
            sandbox_marshaler=reattach,
        )

        recovered = restarted.recover_active_sandboxes(job_id)

        self.assertEqual(restarted.store.current(job_id).state, LifecycleState.BUILDING)
        self.assertEqual(recovered, restarted.active_sandboxes(job_id))
        self.assertEqual(recovered[0]["sandbox_id"], "sandbox-restart-1")
        self.assertEqual(recovered[0]["reattach_state"], "ADMITTED")
        self.assertEqual(reattach.resolved[0]["sandbox_id"], "sandbox-restart-1")
        self.assertEqual(restarted.sandbox_attachment_refs(job_id), attachment_refs)
        self.assertEqual(artifacts.get_record(attachment_refs[0]).kind, S1_SANDBOX_ATTACHMENT_KIND)
        self.assertEqual(tuple(record.artifact_ref for record in artifacts.query_artifacts()), before_refs)
        self.assertEqual(restarted.store.ledger_refs(job_id), runtime.store.ledger_refs(job_id))

    def test_runtime_restart_recovery_fails_closed_when_durable_sandbox_handle_is_missing(self) -> None:
        artifacts = InMemoryArtifactStore()
        descriptor = _test_descriptor()
        runtime = SubagentRuntime(descriptor=descriptor, artifact_store=artifacts)
        job_id = "25252525-2525-4525-8525-252525252525"
        runtime.store.create_job(job_id)
        runtime.store.apply_method(job_id, "accept")
        runtime.store.apply_method(job_id, "plan")
        runtime.store.apply_method(job_id, "build")
        runtime.register_sandbox_result(
            job_id,
            {
                "sandbox_id": "sandbox-missing-after-restart",
                "state": "ADMITTED",
                "launch_provenance_ref": "c4://artifact/launch-missing-after-restart",
            },
        )
        restarted = SubagentRuntime(
            descriptor=descriptor,
            store=LifecycleStore.from_event_log({job_id: runtime.store.events(job_id)}, artifact_store=artifacts),
            sandbox_marshaler=_ReattachSandboxMarshaler({}),
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            restarted.recover_active_sandboxes(job_id)

        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertEqual(raised.exception.envelope.code, "S10_SANDBOX_REATTACH_FAILED")
        self.assertEqual(restarted.active_sandboxes(job_id), ())

    def test_runtime_restart_recovery_fails_closed_on_mismatched_attachment_job(self) -> None:
        artifacts = InMemoryArtifactStore()
        descriptor = _test_descriptor()
        runtime = SubagentRuntime(descriptor=descriptor, artifact_store=artifacts)
        job_id = "26262626-2626-4626-8626-262626262626"
        runtime.store.create_job(job_id)
        runtime.store.apply_method(job_id, "accept")
        runtime.store.apply_method(job_id, "plan")
        runtime.store.apply_method(job_id, "build")
        artifacts.create_artifact(
            kind=S1_SANDBOX_ATTACHMENT_KIND,
            payload={
                "schema": "argus.s1.sandbox_attachment.v1",
                "job_id": "other-job",
                "sandbox_id": "sandbox-corrupt-attachment",
                "sandbox_result": {"sandbox_id": "sandbox-corrupt-attachment", "state": "ADMITTED"},
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.sandbox-attachment", job_id=job_id),
            lineage=Lineage(
                input_refs=runtime.store.ledger_refs(job_id)[-1:],
                code_ref="test:s1-corrupt-attachment",
                environment_digest="test:s1-corrupt-attachment",
                job_id=job_id,
            ),
        )
        restarted = SubagentRuntime(
            descriptor=descriptor,
            store=LifecycleStore.from_event_log({job_id: runtime.store.events(job_id)}, artifact_store=artifacts),
            sandbox_marshaler=_ReattachSandboxMarshaler(
                {"sandbox-corrupt-attachment": {"sandbox_id": "sandbox-corrupt-attachment", "state": "ADMITTED"}}
            ),
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            restarted.recover_active_sandboxes(job_id)

        self.assertEqual(raised.exception.envelope.category, "SANDBOX")
        self.assertEqual(raised.exception.envelope.code, "S10_SANDBOX_ATTACHMENT_INVALID")
        self.assertEqual(restarted.active_sandboxes(job_id), ())

    def test_event_log_rebuild_restores_lifecycle_idempotency_records(self) -> None:
        artifacts = InMemoryArtifactStore()
        store = LifecycleStore(artifact_store=artifacts)
        store.create_job("job-1")
        accepted = store.apply_method("job-1", "accept", trigger="S5", idempotency_key="accept-job-1")
        planned = store.apply_method(
            "job-1",
            "plan",
            trigger="internal",
            payload={"step": "plan"},
            idempotency_key="plan-job-1",
        )

        rebuilt = LifecycleStore.from_event_log(
            {"job-1": store.events("job-1")},
            artifact_store=artifacts,
        )
        duplicate_plan = rebuilt.apply_method(
            "job-1",
            "plan",
            trigger="internal",
            payload={"step": "plan"},
            idempotency_key="plan-job-1",
        )

        self.assertEqual(duplicate_plan, planned)
        self.assertEqual(rebuilt.events("job-1"), (accepted, planned))
        self.assertEqual(rebuilt.ledger_refs("job-1"), store.ledger_refs("job-1"))
        self.assertEqual(
            [record.idempotency_key for record in rebuilt.idempotency_records("job-1")],
            ["accept-job-1", "plan-job-1"],
        )

    def test_replay_rejects_tampered_event_log(self) -> None:
        store = LifecycleStore()
        store.create_job("job-1")
        store.apply_method("job-1", "accept")
        planned = store.apply_method("job-1", "plan")
        events = store.events("job-1")

        with self.assertRaises(LifecyclePolicyError) as sequence_error:
            reduce_lifecycle((events[0], replace(planned, sequence=99)), job_id="job-1")
        self.assertEqual(sequence_error.exception.envelope.code, "LIFECYCLE_REPLAY_SEQUENCE_GAP")

        with self.assertRaises(LifecyclePolicyError) as state_error:
            reduce_lifecycle((replace(events[0], from_state=LifecycleState.PLANNING),), job_id="job-1")
        self.assertEqual(state_error.exception.envelope.code, "LIFECYCLE_REPLAY_STATE_DIVERGED")

        with self.assertRaises(LifecyclePolicyError) as job_error:
            reduce_lifecycle((replace(events[0], job_id="job-2"),), job_id="job-1")
        self.assertEqual(job_error.exception.envelope.code, "LIFECYCLE_REPLAY_JOB_MISMATCH")

    def test_ledger_mirror_failure_does_not_mutate_event_log_or_current(self) -> None:
        class BrokenArtifactStore:
            def create_artifact(self, **_kwargs: object) -> object:
                raise RuntimeError("ledger mirror unavailable")

        store = LifecycleStore(artifact_store=BrokenArtifactStore())  # type: ignore[arg-type]
        store.create_job("job-1")

        with self.assertRaises(RuntimeError):
            store.apply_method("job-1", "accept")

        self.assertEqual(store.current("job-1").state, LifecycleState.REGISTERED)
        self.assertEqual(store.events("job-1"), ())
        self.assertEqual(store.idempotency_records("job-1"), ())

    @staticmethod
    def _c1_def_enum(def_name: str) -> set[str]:
        schema_path = Path(__file__).resolve().parents[1] / "schemas/contracts/c1.subagent.schema.json"
        schema = json.loads(schema_path.read_text())
        return set(schema["$defs"][def_name]["enum"])


class S1TierRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        trust_store = InMemoryVerifierTrustStore()
        trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.verifier = C3ReportVerifier(trust_store)

    def test_self_tier_is_dropped_without_signed_report(self) -> None:
        report = build_subagent_report(
            artifact_refs=("c4://artifact/model",),
            attempted_claim_tier="novel-needs-human",
        )

        self.assertEqual(report.claim_tier, "ran-toy")
        self.assertIsNone(report.validation_report_ref)
        self.assertIn("self_tier_dropped", report.warnings)

    def test_signed_report_tier_is_relayed_verbatim(self) -> None:
        signed = self.signer.sign(self._report("recapitulated-known"))
        uncertainty_summary = tag_uncertainty(
            "interval",
            {"radius": 0.1, "confidence": 0.95, "source": "signed-c3-report"},
        )

        report = build_subagent_report(
            artifact_refs=("c4://artifact/model",),
            attempted_claim_tier="novel-needs-human",
            validation_report_ref="c4://report/signed",
            validation_report_payload=signed,
            report_verifier=self.verifier,
            uncertainty_summary=uncertainty_summary,
        )

        self.assertEqual(report.claim_tier, "recapitulated-known")
        self.assertEqual(report.validation_report_ref, "c4://report/signed")
        self.assertEqual(report.uncertainty_summary, uncertainty_summary)
        self.assertEqual(report.warnings, ())

    def test_signed_report_tier_requires_uncertainty_summary_at_silver(self) -> None:
        signed = self.signer.sign(self._report("recapitulated-known"))

        with self.assertRaises(LifecyclePolicyError) as raised:
            build_subagent_report(
                artifact_refs=("c4://artifact/model",),
                attempted_claim_tier="recapitulated-known",
                validation_report_ref="c4://report/signed",
                validation_report_payload=signed,
                report_verifier=self.verifier,
            )

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(raised.exception.envelope.code, "S1_UNCERTAINTY_REQUIRED_FOR_TIER")
        self.assertIn("recapitulated-known", raised.exception.envelope.message)

    def test_signed_report_tier_requires_validation_report_ref(self) -> None:
        signed = self.signer.sign(self._report("recapitulated-known"))
        uncertainty_summary = tag_uncertainty(
            "interval",
            {"radius": 0.1, "confidence": 0.95, "source": "signed-c3-report"},
        )

        with self.assertRaises(LifecyclePolicyError) as raised:
            build_subagent_report(
                artifact_refs=("c4://artifact/model",),
                validation_report_payload=signed,
                report_verifier=self.verifier,
                uncertainty_summary=uncertainty_summary,
            )

        self.assertEqual(raised.exception.envelope.category, "POLICY")
        self.assertEqual(raised.exception.envelope.code, "S1_VALIDATION_REPORT_REF_REQUIRED")
        self.assertIn("validation_report_ref", raised.exception.envelope.message)

    def test_unsigned_report_is_rejected_and_tier_stays_ran_toy(self) -> None:
        signed = self.signer.sign(self._report("recapitulated-known"))
        signed["aggregate"]["score"] = 0.1

        report = build_subagent_report(
            artifact_refs=("c4://artifact/model",),
            validation_report_ref="c4://report/tampered",
            validation_report_payload=signed,
            report_verifier=self.verifier,
        )

        self.assertEqual(report.claim_tier, "ran-toy")
        self.assertIsNone(report.validation_report_ref)
        self.assertIn("validation_report_rejected", report.warnings)

    def test_exec_context_has_no_tier_setter(self) -> None:
        ctx = ExecContext(job_id="job-1")

        self.assertFalse(hasattr(ctx, "set_claim_tier"))

    @staticmethod
    def _report(claim_tier: str) -> dict[str, object]:
        report = {
            "report_id": "33333333-3333-4333-8333-333333333333",
            "profile_ref": "c4://profile/ewpt-toy/v1",
            "frozen_pipeline_ref": "c4://pipeline/ewpt-toy/baseline",
            "checks": [{"check": "INJECTION", "status": "PASS"}],
            "aggregate": {"passed": True, "score": 0.98},
            "claim_tier": claim_tier,
            "claim_tier_is_candidate": False,
            "signature": {"algorithm": "placeholder", "key_id": "placeholder", "value": "placeholder"},
            "perturbation_pairs": [],
            "insensitivity_flags": [],
            "challenger_panel": {"challenger_ids": ["challenger-a"], "min_required": 1},
            "independence_attestation_debate": {
                "min_independent_challengers": 1,
                "lineage_disjoint": True,
                "correlation_warning": False,
            },
            "referee": {
                "referee_id": "s3-referee",
                "non_gameable": True,
                "signed_by": "s3-key",
                "distinct_from_proponent": True,
            },
            "debate_ref": "c4://debate/ewpt-toy/example",
        }
        return deepcopy(report)


class S1AcceptGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.descriptor = SubagentDescriptor(
            subagent_id="subagent-1",
            contract_version="1.0.0",
            subtopics=("ewpt",),
            required_adapters=("adapter:bounce",),
        )

    def test_default_accept_happy_path(self) -> None:
        envelope = self._envelope()
        acceptance = default_accept(self.descriptor, envelope)

        self.assertTrue(acceptance.accepted)
        self.assertEqual(acceptance.job_id, envelope.job_id)
        self.assertIsNone(acceptance.reason)
        self.assertEqual(acceptance.state, LifecycleState.ACCEPTED)
        self.assertEqual(acceptance.idempotency_key, "accept:job-1")
        self.assertEqual(
            acceptance.as_c1_payload(),
            {
                "job_id": "job-1",
                "accepted": True,
                "reason": None,
                "state": "ACCEPTED",
                "idempotency_key": "accept:job-1",
                "estimated_cost": {"cost_usd": 1},
            },
        )

    def test_default_accept_refuses_missing_adapter_no_verifier_and_major_version(self) -> None:
        cases = {
            "missing-adapter": (self._envelope(required_adapters=("adapter:missing",)), "MISSING_ADAPTER"),
            "no-verifier": (self._envelope(verifier_profile_ref=None), "NO_VERIFIER"),
            "major-mismatch": (self._envelope(envelope_version="2.0.0"), "VERSION_UNSUPPORTED"),
            "out-of-scope": (self._envelope(subtopic="other"), "OUT_OF_SCOPE"),
            "budget-too-small": (self._envelope(estimated_cost=3, budget_cost=2), "BUDGET_TOO_SMALL"),
        }
        for name, (envelope, reason) in cases.items():
            with self.subTest(name=name):
                acceptance = default_accept(self.descriptor, envelope)

                self.assertFalse(acceptance.accepted)
                self.assertEqual(acceptance.reason, reason)
                self.assertEqual(acceptance.state, LifecycleState.REJECTED)
                self.assertEqual(acceptance.as_c1_payload()["accepted"], False)
                self.assertNotIn("error", acceptance.as_c1_payload())

    def test_acceptance_rejects_inconsistent_refusal_payloads(self) -> None:
        with self.assertRaises(ValueError):
            Acceptance("job-1", True, "NO_VERIFIER", LifecycleState.ACCEPTED, "accept:job-1")
        with self.assertRaises(ValueError):
            Acceptance("job-1", True, None, LifecycleState.REJECTED, "accept:job-1")
        with self.assertRaises(ValueError):
            Acceptance("job-1", False, None, LifecycleState.REJECTED, "accept:job-1")
        with self.assertRaises(ValueError):
            Acceptance("job-1", False, "NO_VERIFIER", LifecycleState.ACCEPTED, "accept:job-1")

    def test_runtime_accept_is_idempotent_for_same_envelope(self) -> None:
        idempotency = InMemoryIdempotencyStore()
        runtime = SubagentRuntime(descriptor=self.descriptor, idempotency_store=idempotency)
        envelope = self._envelope()

        first = runtime.accept(envelope)
        second = runtime.accept(envelope)

        self.assertEqual(first, second)
        self.assertEqual(runtime.gate_invocations, 1)
        self.assertEqual(len(runtime.store.events(envelope.job_id)), 1)
        self.assertEqual(runtime.store.current(envelope.job_id).state, LifecycleState.ACCEPTED)
        self.assertEqual(first.idempotency_key, "accept:job-1")
        self.assertEqual(
            [(record.method, record.idempotency_key) for record in idempotency.records("job-1")],
            [("accept", "accept:job-1"), ("lifecycle.accept", "accept:job-1")],
        )

    def test_runtime_default_accept_mirrors_to_c4_ledger(self) -> None:
        runtime = SubagentRuntime(descriptor=self.descriptor)
        envelope = self._envelope()

        acceptance = runtime.accept(envelope)

        self.assertTrue(acceptance.accepted)
        events = runtime.store.events(envelope.job_id)
        self.assertEqual(len(events), 1)
        self.assertIsNotNone(events[0].ledger_ref)
        records = runtime.store.ledger_records(envelope.job_id)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].kind, S1_LIFECYCLE_LEDGER_KIND)
        self.assertEqual(records[0].producer.subsystem, "S1")
        self.assertEqual(records[0].lineage.job_id, envelope.job_id)

    def test_runtime_accept_refusal_is_non_error_and_idempotent(self) -> None:
        idempotency = InMemoryIdempotencyStore()
        runtime = SubagentRuntime(descriptor=self.descriptor, idempotency_store=idempotency)
        envelope = self._envelope(verifier_profile_ref=None)

        first = runtime.accept(envelope)
        second = runtime.accept(envelope)

        self.assertEqual(first, second)
        self.assertFalse(first.accepted)
        self.assertEqual(first.reason, "NO_VERIFIER")
        self.assertEqual(first.state, LifecycleState.REJECTED)
        self.assertEqual(runtime.gate_invocations, 1)
        self.assertEqual(runtime.store.current(envelope.job_id).state, LifecycleState.REJECTED)
        self.assertEqual([(event.method, event.to_state) for event in runtime.store.events(envelope.job_id)], [("refuse", LifecycleState.REJECTED)])
        self.assertEqual(
            [(record.method, record.idempotency_key) for record in idempotency.records("job-1")],
            [("accept", "accept:job-1"), ("lifecycle.refuse", "accept:job-1")],
        )

    def test_runtime_accept_rejects_same_job_different_envelope(self) -> None:
        idempotency = InMemoryIdempotencyStore()
        runtime = SubagentRuntime(descriptor=self.descriptor, idempotency_store=idempotency)
        runtime.accept(self._envelope(job_id="job-1"))

        with self.assertRaises(LifecyclePolicyError) as raised:
            runtime.accept(self._envelope(job_id="job-1", subtopic="other"))

        self.assertEqual(raised.exception.envelope.code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(runtime.gate_invocations, 1)
        self.assertEqual(len(runtime.store.events("job-1")), 1)
        self.assertEqual(
            [(record.method, record.idempotency_key) for record in idempotency.records("job-1")],
            [("accept", "accept:job-1"), ("lifecycle.accept", "accept:job-1")],
        )

    def _envelope(
        self,
        *,
        job_id: str = "job-1",
        envelope_version: str = "1.0.0",
        subtopic: str = "ewpt",
        required_adapters: tuple[str, ...] = ("adapter:bounce",),
        allowed_adapters: tuple[str, ...] = ("adapter:bounce",),
        verifier_profile_ref: str | None = "c4://profile/ewpt/v1",
        estimated_cost: float = 1,
        budget_cost: float = 2,
    ) -> JobEnvelope:
        return JobEnvelope(
            job_id=job_id,
            envelope_version=envelope_version,
            subtopic=subtopic,
            required_adapters=required_adapters,
            allowed_adapters=allowed_adapters,
            verifier_profile_ref=verifier_profile_ref,
            estimated_cost=estimated_cost,
            budget_cost=budget_cost,
        )


if __name__ == "__main__":
    unittest.main()
