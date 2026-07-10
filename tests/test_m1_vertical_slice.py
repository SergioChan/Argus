from __future__ import annotations

import json
import unittest

from argus_core import (
    AdapterBroker,
    BaselineBuilder,
    BuildPlan,
    C3ReportSigner,
    C3ReportVerifier,
    CheckResult,
    EvalRequest,
    GW_SPECTRUM_ADAPTER_ID,
    GWSpectrumAdapter,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    JobEnvelope,
    LifecycleState,
    Lineage,
    Producer,
    Quantity,
    S3Verifier,
    SubagentDescriptor,
    SubagentRuntime,
    build_subagent_report,
    run_perturbation_pair,
    tag_uncertainty,
)


class M1OracleGatedVerticalSliceTests(unittest.TestCase):
    def test_one_subtopic_build_verify_promote_and_report(self) -> None:
        trust_store = InMemoryVerifierTrustStore()
        trust_store.register_key("s3-key", b"s3-secret")
        c3_verifier = C3ReportVerifier(trust_store)
        artifacts = InMemoryArtifactStore(report_verifier=c3_verifier)

        s1 = SubagentRuntime(
            descriptor=SubagentDescriptor(
                subagent_id="subagent-ewpt",
                contract_version="1.0.0",
                subtopics=("ewpt",),
                required_adapters=(GW_SPECTRUM_ADAPTER_ID,),
            )
        )
        acceptance = s1.accept(
            JobEnvelope(
                job_id="job-1",
                envelope_version="1.0.0",
                subtopic="ewpt",
                required_adapters=(GW_SPECTRUM_ADAPTER_ID,),
                allowed_adapters=(GW_SPECTRUM_ADAPTER_ID,),
                verifier_profile_ref="c4://profile/ewpt/v1",
                estimated_cost=1,
                budget_cost=2,
            )
        )
        self.assertTrue(acceptance.accepted)
        self.assertEqual(s1.store.current("job-1").state, LifecycleState.ACCEPTED)

        dataset = artifacts.create_artifact(
            kind="dataset",
            payload={"rows": [1, 2, 3]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        broker = AdapterBroker(artifact_store=artifacts)
        broker.register(self._adapter())
        builder = BaselineBuilder(artifact_store=artifacts, adapter_broker=broker)
        build = builder.build(
            BuildPlan(
                job_id="job-1",
                input_refs=(dataset.artifact_ref,),
                adapter_request=EvalRequest(
                    adapter_id=GW_SPECTRUM_ADAPTER_ID,
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "beta_over_H": Quantity(value=100, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                        "frequency": Quantity(value=0.003, units="Hz"),
                    },
                    seed=7,
                ),
            )
        )
        self.assertEqual(build.claim_tier, "ran-toy")

        signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        s3 = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-key", signer=signer)
        perturbation = run_perturbation_pair(
            perturbation_id="pair-1",
            must_react_expected=1.0,
            must_react_observed=1.0,
            must_not_react_observed=0.0,
            unperturbed_headline=1.0,
            perturbed_headline=0.2,
        )
        signed_report = s3.build_report(
            profile_ref="c4://profile/ewpt/v1",
            frozen_pipeline_ref=build.frozen_pipeline_ref,
            proponent_id="subagent-ewpt",
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
                CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
            ),
            perturbation_outcome=perturbation,
            challenger_ids=("challenger-a", "challenger-b"),
            debate_ref="c4://debate/job-1",
        )
        report_record = artifacts.create_artifact(
            kind="report",
            payload=signed_report,
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(
                input_refs=(build.frozen_pipeline_ref,),
                code_ref="git:s3-verify",
                environment_digest="oci:s3-verify",
            ),
        )
        uncertainty_summary = tag_uncertainty(
            "interval",
            {"radius": 0.01, "source": "signed-c3-report"},
        )

        promoted = artifacts.create_artifact(
            kind="model",
            payload={
                "promoted_model_ref": build.model_ref,
                "report_id": signed_report["report_id"],
                "uncertainty_tag": {"kind": "interval", "source": "signed-c3-report"},
            },
            producer=Producer(subsystem="S1", version="0.0.0"),
            lineage=Lineage(
                input_refs=(build.model_ref, report_record.artifact_ref),
                code_ref="git:s1-report",
                environment_digest="oci:s1-report",
            ),
            claim_tier="recapitulated-known",
            validation_report_ref=report_record.artifact_ref,
        )
        subagent_report = build_subagent_report(
            artifact_refs=(promoted.artifact_ref,),
            attempted_claim_tier="novel-needs-human",
            validation_report_ref=report_record.artifact_ref,
            validation_report_payload=signed_report,
            report_verifier=c3_verifier,
            uncertainty_summary=uncertainty_summary,
        )

        promoted_lineage = artifacts.get_lineage(promoted.artifact_ref, direction="ancestors")
        promoted_lineage_refs = {node.artifact_ref for node in promoted_lineage.nodes}
        stored_report = json.loads(artifacts.get_artifact(report_record.artifact_ref).decode("utf-8"))

        self.assertEqual(promoted.claim_tier, "recapitulated-known")
        self.assertEqual(promoted.validation_report_ref, report_record.artifact_ref)
        self.assertEqual(subagent_report.claim_tier, "recapitulated-known")
        self.assertEqual(subagent_report.validation_report_ref, report_record.artifact_ref)
        self.assertEqual(subagent_report.uncertainty_summary, uncertainty_summary)
        self.assertTrue(c3_verifier.verify(stored_report).valid)
        self.assertIn(dataset.artifact_ref, promoted_lineage_refs)
        self.assertIn(report_record.artifact_ref, promoted_lineage_refs)
        self.assertTrue(artifacts.verify_audit_chain().valid)

    @staticmethod
    def _adapter():
        return GWSpectrumAdapter().as_simple_adapter()


if __name__ == "__main__":
    unittest.main()
