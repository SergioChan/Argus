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
    InMemoryVerifierTrustStore,
    JobEnvelope,
    LEGAL_TRANSITIONS,
    LifecyclePolicyError,
    LifecycleState,
    LifecycleStore,
    SubagentDescriptor,
    SubagentRuntime,
    TERMINAL_STATES,
    build_subagent_report,
    canonical_json_bytes,
    default_accept,
    reduce_lifecycle,
    tag_uncertainty,
)
from argus_core.s1 import METHOD_TARGETS, NON_TRANSITION_METHODS, S1_LIFECYCLE_LEDGER_KIND


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
