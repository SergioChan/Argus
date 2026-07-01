from __future__ import annotations

from dataclasses import replace
import unittest

from argus_core import (
    FEDERATION_DEFAULT_SCOPES,
    BundleTrustStore,
    CapabilityDescriptor,
    ConformanceService,
    ConformanceSuiteVersion,
    FederationGovernanceLedger,
    FederationIdentity,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Lineage,
    Producer,
    RegistryGateway,
    SemverCompatibilityError,
    StandardRelease,
    StandardService,
    SubmissionBundle,
    Taxonomy,
    assert_declared_semver_bump,
    challenge_conformance_record,
    classify_schema_change,
    deterministic_codegen,
    sign_submission_bundle,
    verify_conformance_record,
)


class S12StandardReleaseTests(unittest.TestCase):
    def test_semver_classifier_and_declared_bump_gate(self) -> None:
        old = {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}
        additive = {
            "type": "object",
            "properties": {"job_id": {"type": "string"}, "trace_id": {"type": "string", "default": ""}},
            "required": ["job_id"],
        }
        breaking = {"type": "object", "properties": {}, "required": []}

        self.assertEqual(classify_schema_change(old, additive), "additive-minor")
        self.assertEqual(classify_schema_change(old, breaking), "breaking-major")
        assert_declared_semver_bump(old_version="1.0.0", new_version="1.1.0", classification="additive-minor")
        with self.assertRaises(SemverCompatibilityError):
            assert_declared_semver_bump(old_version="1.0.0", new_version="1.1.0", classification="breaking-major")

    def test_standard_release_is_content_addressed_and_current_is_latest(self) -> None:
        store = InMemoryArtifactStore()
        service = StandardService(artifact_store=store)

        first = service.publish(self._release("1.0.0"))
        duplicate = service.publish(self._release("1.0.0"))
        second = service.publish(self._release("2.0.0"))

        self.assertEqual(first, duplicate)
        self.assertEqual(service.current(), second)
        self.assertTrue(service.supports("1.0.5"))
        self.assertEqual(store.get_record(first.artifact_ref), first)

    def test_deterministic_codegen_is_byte_identical(self) -> None:
        schema = {"type": "object", "properties": {"x": {"type": "number"}}}

        first = deterministic_codegen(schema, language="python")
        second = deterministic_codegen({"properties": {"x": {"type": "number"}}, "type": "object"}, language="python")

        self.assertEqual(first, second)

    @staticmethod
    def _release(version: str) -> StandardRelease:
        return StandardRelease(
            version=version,
            schemas={"C1": {"type": "object", "properties": {"version": {"const": version}}}},
            docs_ref=f"c4://docs/{version}",
            bindings_ref=f"c4://bindings/{version}",
            deprecation_calendar={},
            signer_key_id="s12-standard",
        )


class S12ConformanceAndAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.release = self.store.create_artifact(
            kind="standard_release",
            payload={"version": "1.0.0"},
            producer=Producer(subsystem="S12", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:standard", environment_digest="oci:standard"),
        )
        self.suite = ConformanceSuiteVersion(
            suite_version="2026.07",
            standard_release_ref=self.release.artifact_ref,
        )
        self.signer_secret = b"s12-conformance-secret"
        self.service = ConformanceService(
            suite=self.suite,
            signer_key_id="s12-conformance",
            signer_secret=self.signer_secret,
        )
        self.trust_store = BundleTrustStore()
        self.trust_store.register_identity(FederationIdentity("maintainer-1", "maintainer-key"), b"maintainer-secret")
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.ledger = FederationGovernanceLedger()
        self.gateway = RegistryGateway(
            registry=self.registry,
            trust_store=self.trust_store,
            governance_ledger=self.ledger,
            signer_secret=self.signer_secret,
        )

    def test_conformance_record_signature_covers_canonical_body(self) -> None:
        record = self.service.run(self._signed_bundle(), level="silver")
        tampered = replace(record, level_awarded="gold")

        self.assertTrue(verify_conformance_record(record, secret=self.signer_secret))
        self.assertFalse(verify_conformance_record(tampered, secret=self.signer_secret))

    def test_bronze_silver_and_gold_checks_fail_on_contract_violations(self) -> None:
        bronze = self.service.run(
            self._signed_bundle(attempted_claim_tier="novel-needs-human"),
            level="bronze",
        )
        silver = self.service.run(
            self._signed_bundle(uncertainty_tagged=False),
            level="silver",
        )
        gold = self.service.run(
            self._signed_bundle(reward_path_write_attempt=True, egress_attempt=True),
            level="gold",
        )

        bronze_checks = {check.check_id: check.status for check in bronze.checks}
        silver_checks = {check.check_id: check.status for check in silver.checks}
        gold_checks = {check.check_id: check.status for check in gold.checks}

        self.assertEqual(bronze_checks["BRZ-NO-SELF-NOVEL"], "FAIL")
        self.assertEqual(silver_checks["SLV-UNCERTAINTY-MANDATORY"], "FAIL")
        self.assertEqual(gold_checks["GLD-RECURSION-NO-REWARD-WRITE"], "FAIL")
        self.assertEqual(gold_checks["GLD-SANDBOX-EGRESS"], "FAIL")

    def test_submission_admission_forces_federated_trust_and_default_scopes(self) -> None:
        bundle = self._signed_bundle(claimed_level="silver")
        record = self.service.run(bundle, level="silver")

        submission = self.gateway.submit(bundle)
        in_review = self.gateway.admit(bundle=bundle, conformance_record=record, suite=self.suite)
        self.gateway.approve(submission_id=bundle.submission_id, entity_id=bundle.entity_id, reviewer_id="registrar-1")
        admitted = self.gateway.admit(bundle=bundle, conformance_record=record, suite=self.suite)

        self.assertTrue(submission.accepted)
        self.assertEqual(in_review.status, "IN_REVIEW")
        self.assertTrue(admitted.admit)
        self.assertEqual(admitted.descriptor.trust_class, "federated")
        self.assertEqual(admitted.descriptor.capability_scopes, FEDERATION_DEFAULT_SCOPES)
        self.assertEqual(admitted.descriptor.conformance_level, "silver")
        self.assertEqual(self.gateway.directory_get(bundle.entity_id), admitted.descriptor)
        self.assertEqual(self.registry.get(bundle.entity_id).trust_class, "federated")

    def test_admission_fails_closed_for_missing_or_mismatched_conformance(self) -> None:
        silver_bundle = self._signed_bundle(claimed_level="silver")
        gold_bundle = self._signed_bundle(submission_id="sub-gold", claimed_level="gold")
        silver_record = self.service.run(gold_bundle, level="silver")

        missing = self.gateway.admit(bundle=silver_bundle, conformance_record=None, suite=self.suite)
        mismatch = self.gateway.admit(bundle=gold_bundle, conformance_record=silver_record, suite=self.suite)

        self.assertFalse(missing.admit)
        self.assertEqual(missing.category, "CONFORMANCE_MISSING")
        self.assertFalse(mismatch.admit)
        self.assertEqual(mismatch.category, "CONFORMANCE_LEVEL_MISMATCH")

    def test_tampered_bundle_and_suspended_identity_are_rejected_pre_execution(self) -> None:
        bundle = self._signed_bundle()
        tampered = replace(bundle, code_ref="git:tampered")
        suspended = self._signed_bundle(submission_id="sub-suspended")
        self.trust_store.suspend("maintainer-key")

        tampered_decision = self.gateway.submit(tampered)
        suspended_decision = self.gateway.submit(suspended)

        self.assertFalse(tampered_decision.accepted)
        self.assertEqual(tampered_decision.category, "SIGNATURE_INVALID")
        self.assertFalse(suspended_decision.accepted)
        self.assertEqual(suspended_decision.category, "REVOKED")

    def test_suite_yank_invalidates_auto_pass(self) -> None:
        bundle = self._signed_bundle()
        record = self.service.run(bundle, level="silver")
        yanked = replace(self.suite, yanked=True, reason="flaky oracle")

        decision = self.gateway.admit(bundle=bundle, conformance_record=record, suite=yanked)

        self.assertFalse(decision.admit)
        self.assertEqual(decision.category, "CONFORMANCE_EXPIRED")

    def test_governance_ledger_detects_tampering(self) -> None:
        first = self.ledger.append(action="SUBMIT", entity_id="entity-1", actor_id="maintainer-1", payload={})
        second = self.ledger.append(action="APPROVE", entity_id="entity-1", actor_id="registrar-1", payload={})
        tampered = (replace(first, payload={"mutated": True}), second)

        self.assertTrue(self.ledger.verify().valid)
        self.assertFalse(self.ledger.verify(tampered).valid)
        self.assertEqual(self.ledger.verify(tampered).break_sequence, 1)

    def test_revocation_propagates_to_registry_and_in_flight_jobs(self) -> None:
        bundle = self._signed_bundle()
        record = self.service.run(bundle, level="silver")
        self.gateway.submit(bundle)
        self.gateway.approve(submission_id=bundle.submission_id, entity_id=bundle.entity_id, reviewer_id="registrar-1")
        self.gateway.admit(bundle=bundle, conformance_record=record, suite=self.suite)

        result = self.gateway.revoke(entity_id=bundle.entity_id, actor_id="registrar-1", in_flight_job_ids=("job-b", "job-a"))

        self.assertTrue(result.registry_revoked)
        self.assertEqual(result.halted_job_ids, ("job-a", "job-b"))
        self.assertEqual(self.registry.get(bundle.entity_id).status, "revoked")
        self.assertEqual(self.gateway.events[-1]["kind"], "entity.revoked")

    def test_conformance_record_challenge_matches_deterministic_rerun(self) -> None:
        bundle = self._signed_bundle()
        original = self.service.run(bundle, level="silver")
        rerun = self.service.run(bundle, level="silver")
        divergent = replace(rerun, determinism_hash="c4://hash/diverged")

        clean = challenge_conformance_record(original=original, rerun=rerun)
        dirty = challenge_conformance_record(original=original, rerun=divergent)

        self.assertTrue(clean.matches)
        self.assertFalse(clean.quarantined)
        self.assertFalse(dirty.matches)
        self.assertTrue(dirty.quarantined)

    def test_taxonomy_rejects_cycle(self) -> None:
        taxonomy = Taxonomy({"root": None, "ewpt": "root"})

        with self.assertRaisesRegex(Exception, "cycle"):
            taxonomy.merge({"root": "ewpt"})

    def _signed_bundle(self, **overrides) -> SubmissionBundle:
        fields = {
            "submission_id": "sub-1",
            "entity_id": "entity-1",
            "maintainer_id": "maintainer-1",
            "key_id": "maintainer-key",
            "descriptor_draft": self._descriptor(),
            "claimed_level": "silver",
            "code_ref": "git:contrib",
            "container_digest": "sha256:abcdef",
            "sbom_hash": "c4://sbom/hash",
        }
        fields.update(overrides)
        return sign_submission_bundle(SubmissionBundle(**fields), secret=b"maintainer-secret")

    @staticmethod
    def _descriptor() -> CapabilityDescriptor:
        return CapabilityDescriptor(
            entity_id="entity-1",
            revision=1,
            kind="subagent",
            owner_subsystem="S12",
            contract_versions={"C1": "1.0.0", "C5": "1.0.0"},
            trust_class="internal",
            capability_scopes=("admin", "ledger.write"),
            provenance_ref="c4://pending",
            subtopics=("ewpt",),
            independence_tags=("impl-fed",),
            conformance_level=None,
        )


if __name__ == "__main__":
    unittest.main()
