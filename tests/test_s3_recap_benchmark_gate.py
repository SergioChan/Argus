from __future__ import annotations

import json
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CheckPluginHost,
    CheckPluginHostError,
    CheckResult,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
    InMemoryBlindDataVault,
    InMemoryVerifierProfileRegistry,
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    S3ClaimTieringRuleEngine,
    S3ProfileCompiler,
    S3RecapBenchmarkCheckPlugin,
    S3RecapBenchmarkPrediction,
    S3ReportBuilder,
    S3Verifier,
)


class S3RecapBenchmarkGateTests(unittest.TestCase):
    def test_recap_benchmark_plugin_scores_held_out_truth_without_exposing_it(self) -> None:
        store = InMemoryArtifactStore()
        vault = InMemoryBlindDataVault(artifact_store=store)
        dataset = vault.register_dataset(
            dataset_id="ewpt-held-out-recap",
            version="1.0.0",
            split="recap",
            dataset_kind="recap_benchmark",
            opaque_input={
                "schema": "argus.s3.opaque_input.v1",
                "samples": [{"sample_id": "ewpt-1", "temperature": 100.0}],
            },
            truth={
                "samples": [{"sample_id": "ewpt-1", "expected": 1.25}],
                "answer_secret": "recap-secret-never-to-pipeline",
            },
        )
        stage = self._stage(store=store, vault=vault, handle=dataset.handle)
        plugin = S3RecapBenchmarkCheckPlugin(
            blind_data_vault=vault,
            blind_data_stage=stage,
            predictions=(S3RecapBenchmarkPrediction(sample_id="ewpt-1", prediction=1.251),),
        )

        (result,) = CheckPluginHost(
            plugins=(plugin,),
            artifact_store=store,
            actor_id="s3-recap-test",
            job_id="job-s3-t24-pass",
        ).run(_compiled_profile())

        self.assertEqual(result.check, "RECAP_BENCHMARK")
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.plugin_ref, "argus.s3.plugins.recap_benchmark")
        self.assertTrue(result.metrics["recap_benchmark_pass"])
        self.assertEqual(result.metrics["sample_count"], 1)
        self.assertEqual(result.metrics["recovered_count"], 1)
        self.assertEqual(result.metrics["recap_benchmark_ref"], dataset.metadata_ref)
        self.assertTrue(result.metrics["truth_retained_server_side"])
        self.assertFalse(result.metrics["truth_bytes_delivered_to_sandbox"])
        self.assertFalse(result.metrics["truth_hash_delivered_to_sandbox"])
        self.assertFalse(result.metrics["raw_truth_exposed"])
        self.assertIn("S3-TC32", result.metrics["test_cases"])

        evidence_payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        evidence_text = json.dumps(evidence_payload, sort_keys=True)
        self.assertNotIn("recap-secret-never-to-pipeline", evidence_text)
        self.assertNotIn(dataset.handle, evidence_text)
        self.assertEqual(evidence_payload["metrics"]["recap_benchmark_ref"], dataset.metadata_ref)

    def test_failed_or_missing_recap_benchmark_blocks_recaps(self) -> None:
        engine = S3ClaimTieringRuleEngine()

        without_benchmark = engine.evaluate(
            checks=self._base_recap_checks(),
            independence_attestation=self._trusted_independence(),
            requested_tier="recapitulated-known",
        )
        self.assertEqual(without_benchmark.claim_tier, "ran-toy")
        self.assertIn("tier.recap_benchmark_required", without_benchmark.rule_ids)
        self.assertIn("S3-T24", without_benchmark.test_cases)

        failed_benchmark = engine.evaluate(
            checks=self._base_recap_checks()
            + (
                CheckResult(
                    "RECAP_BENCHMARK",
                    "FAIL",
                    metrics={"test_case": "S3-TC32", "degradation": "RECAP_BENCHMARK_FAILED"},
                ),
            ),
            independence_attestation=self._trusted_independence(),
            requested_tier="recapitulated-known",
        )
        self.assertEqual(failed_benchmark.claim_tier, "ran-toy")
        self.assertIn("RECAP_BENCHMARK_FAILED", failed_benchmark.degradations)
        self.assertIn("RECAP_BENCHMARK", failed_benchmark.failing_checks)

        passing_benchmark = engine.evaluate(
            checks=self._recap_checks(),
            independence_attestation=self._trusted_independence(),
            requested_tier="recapitulated-known",
        )
        self.assertEqual(passing_benchmark.claim_tier, "recapitulated-known")
        self.assertIn("tier.recap_benchmark_pass", passing_benchmark.rule_ids)

    def test_signed_committed_report_uses_recap_benchmark_gate(self) -> None:
        trust_store = InMemoryVerifierTrustStore()
        trust_store.register_key("s3-key", b"s3-secret")
        verifier = S3Verifier(
            verifier_id="s3-referee",
            signer_key_id="s3-key",
            signer=C3ReportSigner(key_id="s3-key", secret=b"s3-secret"),
        )
        store = InMemoryArtifactStore(report_verifier=C3ReportVerifier(trust_store))
        refs = self._seed_c4_inputs(store)
        builder = S3ReportBuilder(
            verifier=verifier,
            artifact_store=store,
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.report-builder"),
        )

        committed = builder.build_and_commit_report(
            profile_ref=refs["profile"],
            frozen_pipeline_ref=refs["frozen_pipeline"],
            checks=self._recap_checks(),
            proponent_id="builder",
            input_refs=(refs["profile"], refs["frozen_pipeline"], refs["validation_request"]),
            job_id="job-s3-t24-report",
        )

        verification = C3ReportVerifier(trust_store).verify(committed.report)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.claim_tier, "recapitulated-known")
        self.assertEqual(committed.report["claim_tier"], "recapitulated-known")
        self.assertIn("RECAP_BENCHMARK", [check["check"] for check in committed.report["checks"]])
        self.assertIn(committed.validation_report_ref, store.get_lineage(committed.validation_report_ref).nodes[0].artifact_ref)

    def test_profile_compiler_accepts_recap_benchmark_check(self) -> None:
        registry = InMemoryVerifierProfileRegistry()
        revision = registry.publish(
            {
                "profile_id": "ewpt-recap-gate",
                "subtopic": "electroweak.phase_transition",
                "checks": ["INJECTION", "NULL_CONTROL", "PHYSICAL_CONSISTENCY", "CALIBRATION", "RECAP_BENCHMARK"],
                "check_specs": [
                    {
                        "check": "RECAP_BENCHMARK",
                        "plugin_ref": "argus.s3.plugins.recap_benchmark",
                        "plugin_version": "1.0.0",
                        "thresholds": {"absolute_tolerance": 0.05, "min_recovered_fraction": 1.0},
                        "determinism": "deterministic",
                        "mandatory": True,
                    }
                ],
                "determinism_policy": {"class": "deterministic"},
                "independence_policy": {"requires_cross_code": False},
                "cost_estimate": {"max_wallclock_s": 3.0, "max_cost_usd": 0.02},
                "recap_benchmark_ref": "c4://artifact/recap-benchmark-metadata",
                "review_signatures": [
                    {
                        "reviewer_id": "s3-profile-registrar",
                        "signed_at": "2026-07-07T00:00:00Z",
                        "signature": "hmac-sha256:" + "c" * 64,
                    }
                ],
            }
        )

        compiled = S3ProfileCompiler(profile_registry=registry).compile(
            profile_ref=revision.profile_ref,
            subtopic="electroweak.phase_transition",
        )

        self.assertIn("RECAP_BENCHMARK", [check.check for check in compiled.checks])
        recap_spec = next(check for check in compiled.checks if check.check == "RECAP_BENCHMARK")
        self.assertEqual(recap_spec.plugin_ref, "argus.s3.plugins.recap_benchmark")
        self.assertEqual(recap_spec.thresholds["min_recovered_fraction"], 1.0)

    def test_invalid_recap_benchmark_inputs_fail_closed_before_c4_write(self) -> None:
        store = InMemoryArtifactStore()
        vault = InMemoryBlindDataVault(artifact_store=store)
        dataset = vault.register_dataset(
            dataset_id="ewpt-held-out-recap",
            version="1.0.0",
            split="recap",
            dataset_kind="held_out",
            opaque_input={"schema": "argus.s3.opaque_input.v1", "samples": [{"sample_id": "ewpt-1"}]},
            truth={"samples": [{"sample_id": "ewpt-1", "expected": 1.25}]},
        )
        stage = self._stage(store=store, vault=vault, handle=dataset.handle)
        plugin = S3RecapBenchmarkCheckPlugin(
            blind_data_vault=vault,
            blind_data_stage=stage,
            predictions=(S3RecapBenchmarkPrediction(sample_id="ewpt-1", prediction=1.25),),
        )

        with self.assertRaises(CheckPluginHostError) as raised:
            CheckPluginHost(plugins=(plugin,), artifact_store=store).run(_compiled_profile())

        self.assertEqual(raised.exception.category, "CHECK_FAILED")
        self.assertEqual(raised.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(
            tuple(record for record in store.query_artifacts({"kind": "s3_check_result"})),
            (),
        )

    @staticmethod
    def _base_recap_checks() -> tuple[CheckResult, ...]:
        return (
            CheckResult("INJECTION", "PASS"),
            CheckResult("NULL_CONTROL", "PASS"),
            CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
            CheckResult("CALIBRATION", "PASS"),
        )

    def _recap_checks(self) -> tuple[CheckResult, ...]:
        return self._base_recap_checks() + (
            CheckResult(
                "RECAP_BENCHMARK",
                "PASS",
                metrics={
                    "test_cases": ["S3-T24", "S3-TC32"],
                    "recap_benchmark_pass": True,
                    "truth_retained_server_side": True,
                    "truth_bytes_delivered_to_sandbox": False,
                    "truth_hash_delivered_to_sandbox": False,
                },
            ),
        )

    @staticmethod
    def _trusted_independence():
        from argus_core import IndependenceAttestation

        return IndependenceAttestation(
            candidate_ids=("challenger-a", "challenger-b"),
            selected_entity_ids=("challenger-a", "challenger-b"),
            min_independent=2,
            lineage_disjoint=True,
            correlation_warning=False,
            excluded_tags=(),
        )

    @staticmethod
    def _stage(*, store: InMemoryArtifactStore, vault: InMemoryBlindDataVault, handle: str):
        from argus_core import S3BlindDataManager

        return S3BlindDataManager(artifact_store=store, vault=vault).stage_for_pipeline(
            blind_data_handle=handle,
            job_id="job-s3-t24-stage",
            trace_id="trace-s3-t24",
        )

    @staticmethod
    def _seed_c4_inputs(store: InMemoryArtifactStore) -> dict[str, str]:
        profile = store.create_artifact(
            kind="profile",
            artifact_ref="c4://profile/s3-t24/ewpt-r1",
            payload={"schema": "argus.s3.profile.v1", "checks": ["RECAP_BENCHMARK"]},
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.profile-registry"),
            lineage=Lineage(input_refs=(), code_ref="git:s3-profile", environment_digest="oci:s3-profile"),
        )
        frozen = store.create_artifact(
            kind="frozen_pipeline",
            artifact_ref="c4://artifact/s3-t24-frozen",
            payload={"schema": "argus.s3.frozen_pipeline.v1", "entrypoint": "predict"},
            producer=Producer(subsystem="S2", version="0.0.0", actor_id="s2.freezer"),
            lineage=Lineage(input_refs=(), code_ref="git:s2", environment_digest="oci:s2"),
        )
        validation_request = store.create_artifact(
            kind="validation_request",
            artifact_ref="c4://artifact/s3-t24-validation-request",
            payload={"schema": "argus.c3.validation_request.v1", "profile_ref": profile.artifact_ref},
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference"),
            lineage=Lineage(input_refs=(profile.artifact_ref, frozen.artifact_ref), code_ref="git:s1", environment_digest="oci:s1"),
        )
        return {
            "profile": profile.artifact_ref,
            "frozen_pipeline": frozen.artifact_ref,
            "validation_request": validation_request.artifact_ref,
        }


def _compiled_profile() -> CompiledProfile:
    return CompiledProfile(
        profile_id="s3-t24-test",
        revision=1,
        profile_ref="c4://profile/s3-t24-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t24",
        public_profile={"profile_id": "s3-t24-test", "revision": 1, "checks": ["RECAP_BENCHMARK"]},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=(
            CompiledCheckSpec(
                check="RECAP_BENCHMARK",
                plugin_ref="argus.s3.plugins.recap_benchmark",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds={"absolute_tolerance": 0.05, "relative_tolerance": 0.0, "min_recovered_fraction": 1.0},
                determinism="deterministic",
                seed=24,
                tolerance={},
                requires_independence=False,
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            ),
        ),
        independence_policy={},
        determinism_profile={"deterministic_checks": ["RECAP_BENCHMARK"]},
    )


if __name__ == "__main__":
    unittest.main()
