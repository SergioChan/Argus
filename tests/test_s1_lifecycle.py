from __future__ import annotations

from copy import deepcopy
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    ExecContext,
    InMemoryVerifierTrustStore,
    JobEnvelope,
    LifecyclePolicyError,
    LifecycleState,
    LifecycleStore,
    SubagentDescriptor,
    SubagentRuntime,
    build_subagent_report,
    canonical_json_bytes,
    default_accept,
    reduce_lifecycle,
)


class S1LifecycleStoreTests(unittest.TestCase):
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

        report = build_subagent_report(
            artifact_refs=("c4://artifact/model",),
            attempted_claim_tier="novel-needs-human",
            validation_report_ref="c4://report/signed",
            validation_report_payload=signed,
            report_verifier=self.verifier,
        )

        self.assertEqual(report.claim_tier, "recapitulated-known")
        self.assertEqual(report.validation_report_ref, "c4://report/signed")
        self.assertEqual(report.warnings, ())

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
        acceptance = default_accept(self.descriptor, self._envelope())

        self.assertTrue(acceptance.accepted)
        self.assertIsNone(acceptance.reason)
        self.assertEqual(acceptance.state, LifecycleState.ACCEPTED)

    def test_default_accept_refuses_missing_adapter_no_verifier_and_major_version(self) -> None:
        missing_adapter = default_accept(
            self.descriptor,
            self._envelope(required_adapters=("adapter:missing",)),
        )
        no_verifier = default_accept(self.descriptor, self._envelope(verifier_profile_ref=None))
        major_mismatch = default_accept(self.descriptor, self._envelope(envelope_version="2.0.0"))

        self.assertEqual(missing_adapter.reason, "MISSING_ADAPTER")
        self.assertEqual(no_verifier.reason, "NO_VERIFIER")
        self.assertEqual(major_mismatch.reason, "VERSION_UNSUPPORTED")
        self.assertFalse(missing_adapter.accepted)
        self.assertFalse(no_verifier.accepted)
        self.assertFalse(major_mismatch.accepted)

    def test_runtime_accept_is_idempotent_for_same_envelope(self) -> None:
        runtime = SubagentRuntime(descriptor=self.descriptor)
        envelope = self._envelope()

        first = runtime.accept(envelope)
        second = runtime.accept(envelope)

        self.assertEqual(first, second)
        self.assertEqual(runtime.gate_invocations, 1)
        self.assertEqual(len(runtime.store.events(envelope.job_id)), 1)
        self.assertEqual(runtime.store.current(envelope.job_id).state, LifecycleState.ACCEPTED)

    def test_runtime_accept_rejects_same_job_different_envelope(self) -> None:
        runtime = SubagentRuntime(descriptor=self.descriptor)
        runtime.accept(self._envelope(job_id="job-1"))

        with self.assertRaises(LifecyclePolicyError) as raised:
            runtime.accept(self._envelope(job_id="job-1", subtopic="other"))

        self.assertEqual(raised.exception.envelope.code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(runtime.gate_invocations, 1)

    def _envelope(
        self,
        *,
        job_id: str = "job-1",
        envelope_version: str = "1.0.0",
        subtopic: str = "ewpt",
        required_adapters: tuple[str, ...] = ("adapter:bounce",),
        allowed_adapters: tuple[str, ...] = ("adapter:bounce",),
        verifier_profile_ref: str | None = "c4://profile/ewpt/v1",
    ) -> JobEnvelope:
        return JobEnvelope(
            job_id=job_id,
            envelope_version=envelope_version,
            subtopic=subtopic,
            required_adapters=required_adapters,
            allowed_adapters=allowed_adapters,
            verifier_profile_ref=verifier_profile_ref,
            estimated_cost=1,
            budget_cost=2,
        )


if __name__ == "__main__":
    unittest.main()
