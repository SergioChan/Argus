from __future__ import annotations

import json
import math
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CheckPluginHost,
    CheckPluginHostError,
    CheckResult,
    CompiledCheckSpec,
    CompiledProfile,
    ContaminationIndex,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    S3LeakageCheckPlugin,
    S3LeakageRewardLoopEvidence,
    S3LeakageTargetRow,
    S3LeakageTextItem,
    S3Verifier,
    SourceDocument,
    admit_signed_reward,
    run_perturbation_pair,
    tier_from_checks,
)


class S3LeakageCheckPluginTests(unittest.TestCase):
    def test_tc17_train_test_overlap_detects_near_duplicate_with_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        plugin = S3LeakageCheckPlugin(
            training_inputs=(
                S3LeakageTextItem(
                    item_id="train-ewpt-1",
                    text="electroweak phase transition gravitational wave spectrum at the peak frequency",
                    source_ref="c4://lineage/train-ewpt-1",
                ),
            ),
            blind_test_items=(
                S3LeakageTextItem(
                    item_id="blind-ewpt-1",
                    text="electroweak phase transition gravitational wave spectrum at peak frequency",
                    source_ref="blind://test/ewpt-1",
                ),
            ),
        )

        (result,) = CheckPluginHost(
            plugins=(plugin,),
            artifact_store=store,
            actor_id="s3-leakage-test",
            job_id="job-s3-t20-overlap",
        ).run(_compiled_profile(mandatory_gates=("train_test_overlap",)))

        self.assertEqual(result.check, "LEAKAGE")
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.plugin_ref, "argus.s3.plugins.leakage")
        self.assertEqual(result.plugin_version, "1.0.0")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC17"])
        self.assertFalse(result.metrics["leakage_pass"])
        overlap = result.metrics["sub_gates"]["train_test_overlap"]
        self.assertEqual(overlap["status"], "FAIL")
        self.assertEqual(overlap["overlap_count"], 1)
        self.assertEqual(overlap["overlap_set"][0]["training_id"], "train-ewpt-1")
        self.assertEqual(overlap["overlap_set"][0]["blind_id"], "blind-ewpt-1")
        self.assertGreaterEqual(overlap["overlap_set"][0]["similarity"], result.metrics["overlap_threshold"])
        self.assertNotIn("text", json.dumps(result.metrics).lower())
        self.assertNotIn("gravitational wave spectrum", json.dumps(result.metrics).lower())

        self.assertIsNotNone(result.evidence_ref)
        evidence_payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence_payload["check"], "LEAKAGE")
        self.assertEqual(evidence_payload["status"], "FAIL")
        self.assertEqual(store.get_record(result.evidence_ref).kind, "s3_check_result")
        self.assertEqual(
            evidence_payload["metrics"]["sub_gates"]["train_test_overlap"]["overlap_set"][0]["blind_id"],
            "blind-ewpt-1",
        )
        self.assertNotIn("gravitational wave spectrum", json.dumps(evidence_payload).lower())

    def test_tc18_frozen_index_overlap_blocks_novelty(self) -> None:
        store = InMemoryArtifactStore()
        index = ContaminationIndex(artifact_store=store)
        snapshot = index.freeze(
            version="2026-07-01",
            documents=(
                SourceDocument(
                    doc_id="known-paper-1",
                    text="electroweak phase transition gravitational wave spectrum benchmark",
                    source_ref="c4://source/known-paper-1",
                ),
            ),
        )
        plugin = S3LeakageCheckPlugin(
            candidate_text="electroweak phase transition gravitational wave spectrum benchmark",
            contamination_index=index,
            contamination_snapshot=snapshot,
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(
            _compiled_profile(mandatory_gates=("frozen_index_overlap",))
        )

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC18"])
        frozen = result.metrics["sub_gates"]["frozen_index_overlap"]
        self.assertEqual(frozen["status"], "FAIL")
        self.assertEqual(frozen["matched_doc_id"], "known-paper-1")
        self.assertEqual(frozen["snapshot_ref"], snapshot.snapshot_ref)
        self.assertEqual(frozen["snapshot_version"], "2026-07-01")
        self.assertTrue(result.metrics["novelty_blocked"])
        self.assertEqual(result.metrics["max_claim_tier"], "recapitulated-known")
        self.assertNotEqual(
            tier_from_checks(
                (
                    CheckResult("INJECTION", "PASS"),
                    CheckResult("NULL_CONTROL", "PASS"),
                    CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                    CheckResult("CALIBRATION", "PASS"),
                    CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
                    CheckResult("CROSS_CODE", "PASS"),
                    result,
                )
            ),
            "novel-needs-human",
        )

    def test_tc48_reward_loop_rejects_leaked_label_variant(self) -> None:
        plugin = S3LeakageCheckPlugin(
            target_leakage_rows=(
                S3LeakageTargetRow(
                    row_id="row-1",
                    features={"mass_bin": "low", "leaked_target_hash": "label:A"},
                    label_hash="label:A",
                ),
                S3LeakageTargetRow(
                    row_id="row-2",
                    features={"mass_bin": "high", "leaked_target_hash": "label:B"},
                    label_hash="label:B",
                ),
                S3LeakageTargetRow(
                    row_id="row-3",
                    features={"mass_bin": "low", "leaked_target_hash": "label:B"},
                    label_hash="label:B",
                ),
                S3LeakageTargetRow(
                    row_id="row-4",
                    features={"mass_bin": "high", "leaked_target_hash": "label:A"},
                    label_hash="label:A",
                ),
            ),
            reward_loop_evidence=S3LeakageRewardLoopEvidence(
                variant_id="leaked-label-variant",
                leaked_label_variant_score=0.99,
                baseline_score=0.52,
                shuffled_null_collapsed=True,
                aggregate_passed=False,
                s4_rejected_variant=True,
                s4_improvement_accepted=False,
            ),
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(
            _compiled_profile(mandatory_gates=("target_leakage", "reward_loop_rejection"))
        )

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC48"])
        self.assertEqual(result.metrics["sub_gates"]["target_leakage"]["status"], "FAIL")
        self.assertEqual(result.metrics["sub_gates"]["target_leakage"]["leaked_feature_count"], 1)
        reward = result.metrics["sub_gates"]["reward_loop_rejection"]
        self.assertEqual(reward["status"], "FAIL")
        self.assertTrue(reward["s4_rejected_variant"])
        self.assertTrue(reward["s4_non_improvement"])
        self.assertFalse(reward["aggregate_passed"])
        self.assertNotIn("label:A", json.dumps(result.metrics))
        self.assertNotIn("label:B", json.dumps(result.metrics))

        report, verification, report_ref, candidate_ref = self._signed_report_for_reward(result)
        admission = admit_signed_reward(
            candidate_ref=candidate_ref,
            report=report,
            verification=verification,
            validation_report_ref=report_ref,
            expected_pipeline_ref=candidate_ref,
        )
        self.assertFalse(report["aggregate"]["passed"])
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(admission.admitted)
        self.assertEqual(admission.reason, "LEAKAGE")
        self.assertTrue(admission.quarantine_required)

    def test_missing_thresholds_duplicate_ids_and_invalid_reward_evidence_fail_closed(self) -> None:
        missing_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError) as missing:
            CheckPluginHost(
                plugins=(
                    S3LeakageCheckPlugin(
                        training_inputs=(S3LeakageTextItem(item_id="train-1", text="alpha beta gamma"),),
                        blind_test_items=(S3LeakageTextItem(item_id="blind-1", text="alpha beta gamma"),),
                    ),
                ),
                artifact_store=missing_store,
            ).run(_compiled_profile(mandatory_gates=None))

        self.assertEqual(missing.exception.category, "CHECK_FAILED")
        self.assertEqual(missing.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(missing_store.record_count, 0)

        duplicate_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError):
            CheckPluginHost(
                plugins=(
                    S3LeakageCheckPlugin(
                        training_inputs=(
                            S3LeakageTextItem(item_id="dup", text="alpha beta gamma"),
                            S3LeakageTextItem(item_id="dup", text="delta epsilon zeta"),
                        ),
                        blind_test_items=(S3LeakageTextItem(item_id="blind-1", text="alpha beta gamma"),),
                    ),
                ),
                artifact_store=duplicate_store,
            ).run(_compiled_profile(mandatory_gates=("train_test_overlap",)))
        self.assertEqual(duplicate_store.record_count, 0)

        invalid_reward_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError):
            CheckPluginHost(
                plugins=(
                    S3LeakageCheckPlugin(
                        reward_loop_evidence=S3LeakageRewardLoopEvidence(
                            variant_id="bad-reward",
                            leaked_label_variant_score=math.inf,
                            baseline_score=0.2,
                            shuffled_null_collapsed=True,
                            aggregate_passed=False,
                            s4_rejected_variant=True,
                            s4_improvement_accepted=False,
                        )
                    ),
                ),
                artifact_store=invalid_reward_store,
            ).run(_compiled_profile(mandatory_gates=("reward_loop_rejection",)))
        self.assertEqual(invalid_reward_store.record_count, 0)

    def _signed_report_for_reward(self, leakage_result: CheckResult) -> tuple[dict, object, str, str]:
        trust_store = InMemoryVerifierTrustStore()
        trust_store.register_key("s3-key", b"s3-secret")
        signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        verifier = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-key", signer=signer)
        store = InMemoryArtifactStore(report_verifier=C3ReportVerifier(trust_store))
        candidate = store.create_artifact(
            kind="container",
            payload={"entrypoint": "candidate.predict"},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:candidate", environment_digest="oci:candidate"),
        )
        report = verifier.build_report(
            profile_ref="c4://profile/ewpt/v1",
            frozen_pipeline_ref=candidate.artifact_ref,
            proponent_id="builder",
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
                CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
                CheckResult("CROSS_CODE", "PASS"),
                leakage_result,
            ),
            perturbation_outcome=run_perturbation_pair(
                perturbation_id="pair-1",
                must_react_expected=1.0,
                must_react_observed=1.0,
                must_not_react_observed=0.0,
                unperturbed_headline=1.0,
                perturbed_headline=0.2,
            ),
            challenger_ids=("challenger-a", "challenger-b"),
        )
        report_record = store.create_artifact(
            kind="report",
            payload=report,
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(
                input_refs=(candidate.artifact_ref,),
                code_ref="git:s3-referee",
                environment_digest="oci:s3-referee",
            ),
        )
        return report, C3ReportVerifier(trust_store).verify(report), report_record.artifact_ref, candidate.artifact_ref


def _compiled_profile(
    *,
    mandatory_gates: tuple[str, ...] | None,
    thresholds: dict[str, object] | None = None,
) -> CompiledProfile:
    merged_thresholds: dict[str, object] = {
        "overlap_threshold": 0.8,
        "frozen_index_threshold": 0.8,
        "target_leakage_purity_threshold": 0.99,
        "target_leakage_min_support": 4,
        "shingle_size": 3,
        "mandatory_gates": list(mandatory_gates) if mandatory_gates is not None else None,
    }
    if mandatory_gates is None:
        merged_thresholds.pop("mandatory_gates")
    if thresholds is not None:
        merged_thresholds.update(thresholds)
    return CompiledProfile(
        profile_id="s3-t20-test",
        revision=1,
        profile_ref="c4://profile/s3-t20-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t20",
        public_profile={"profile_id": "s3-t20-test", "revision": 1, "checks": ["LEAKAGE"]},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=(
            CompiledCheckSpec(
                check="LEAKAGE",
                plugin_ref="argus.s3.plugins.leakage",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds=merged_thresholds,
                determinism="deterministic",
                seed=20,
                tolerance={},
                requires_independence=False,
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            ),
        ),
        independence_policy={"requires_cross_code": False},
        determinism_profile={"deterministic_checks": ["LEAKAGE"]},
    )


if __name__ == "__main__":
    unittest.main()
