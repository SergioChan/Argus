from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import unittest

from argus_core import (
    BLAKE3_PREFIX,
    C3ReportSigner,
    C3ReportVerifier,
    CycleDetectedError,
    HashMismatchError,
    IllegalTierError,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    IncompleteLineageError,
    Lineage,
    Producer,
    SignatureInvalidError,
    WriteOnceViolationError,
    canonical_json_bytes,
    hash_bytes,
    hash_json,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_is_key_order_stable(self) -> None:
        left = canonical_json_bytes({"b": 2, "a": {"d": 4, "c": 3}})
        right = canonical_json_bytes({"a": {"c": 3, "d": 4}, "b": 2})

        self.assertEqual(left, right)
        self.assertEqual(left, b'{"a":{"c":3,"d":4},"b":2}')


class Blake3HashTests(unittest.TestCase):
    def test_hash_bytes_uses_c4_prefix_and_known_blake3_vector(self) -> None:
        self.assertEqual(
            hash_bytes(b""),
            f"{BLAKE3_PREFIX}af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )

    def test_hash_json_is_key_order_stable(self) -> None:
        left = hash_json({"b": 2, "a": 1})
        right = hash_json({"a": 1, "b": 2})

        self.assertEqual(left, right)
        self.assertTrue(left.startswith(BLAKE3_PREFIX))


class InMemoryArtifactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.producer = Producer(subsystem="S2", version="0.0.0")
        self.lineage = Lineage(
            input_refs=("c4://dataset/example",),
            code_ref="git:example",
            environment_digest="oci:sha256-example",
            seeds=("seed-1",),
        )

    def test_create_artifact_commits_complete_lineage(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=self.producer,
            lineage=self.lineage,
        )

        self.assertEqual(record.claim_tier, "ran-toy")
        self.assertEqual(len(self.store), 1)
        self.assertEqual(self.store.object_count, 1)
        self.assertEqual(self.store.record_count, 1)
        self.assertEqual(self.store.get_record(record.artifact_ref), record)

    def test_identical_record_commit_is_idempotent(self) -> None:
        first = self.store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=self.producer,
            lineage=self.lineage,
        )
        second = self.store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=self.producer,
            lineage=self.lineage,
        )

        self.assertEqual(first, second)
        self.assertEqual(self.store.object_count, 1)
        self.assertEqual(self.store.record_count, 1)
        self.assertTrue(self.store.verify_audit_chain().valid)

    def test_content_addressed_dedup_allows_distinct_records(self) -> None:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"same": True},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        model = self.store.create_artifact(
            kind="model",
            payload={"same": True},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:model",
                environment_digest="oci:model",
            ),
        )

        self.assertNotEqual(dataset.artifact_ref, model.artifact_ref)
        self.assertEqual(dataset.content_hash, model.content_hash)
        self.assertEqual(self.store.object_count, 1)
        self.assertEqual(self.store.record_count, 2)

    def test_explicit_ref_is_write_once(self) -> None:
        artifact_ref = "c4://artifact/fixed-ref"
        self.store.create_artifact(
            artifact_ref=artifact_ref,
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=self.lineage,
        )

        with self.assertRaises(WriteOnceViolationError):
            self.store.create_artifact(
                artifact_ref=artifact_ref,
                kind="model",
                payload={"weights": [2]},
                producer=self.producer,
                lineage=self.lineage,
            )

    def test_incomplete_lineage_fails_closed(self) -> None:
        with self.assertRaises(IncompleteLineageError):
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=Lineage(input_refs=(), code_ref="", environment_digest="oci:sha256-example"),
            )

        self.assertEqual(len(self.store), 0)

    def test_promoted_tier_requires_validation_report(self) -> None:
        with self.assertRaises(IllegalTierError):
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=self.lineage,
                claim_tier="recapitulated-known",
            )

    def test_verify_on_read_detects_tampering(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=self.lineage,
        )
        self.store._objects[record.content_hash] = b'{"weights":[2]}'

        with self.assertRaises(HashMismatchError):
            self.store.get_artifact(record.artifact_ref)

    def test_self_cycle_is_rejected(self) -> None:
        artifact_ref = "c4://artifact/self-cycle"

        with self.assertRaises(CycleDetectedError):
            self.store.create_artifact(
                artifact_ref=artifact_ref,
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=Lineage(
                    input_refs=(artifact_ref,),
                    code_ref="git:cycle",
                    environment_digest="oci:cycle",
                ),
            )

    def test_lineage_query_and_impact_set_follow_transitive_edges(self) -> None:
        source = self.store.create_artifact(
            kind="external_source",
            payload={"source": "paper"},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:ingest", environment_digest="oci:ingest"),
        )
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(
                input_refs=(source.artifact_ref,),
                code_ref="git:normalize",
                environment_digest="oci:normalize",
            ),
        )
        model = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:train",
                environment_digest="oci:train",
            ),
        )

        lineage_graph = self.store.get_lineage(model.artifact_ref, direction="ancestors")
        lineage_refs = {node.artifact_ref for node in lineage_graph.nodes}
        impact_refs = {record.artifact_ref for record in self.store.query_impact_set((source.artifact_ref,))}

        self.assertEqual(lineage_refs, {source.artifact_ref, dataset.artifact_ref, model.artifact_ref})
        self.assertEqual(impact_refs, {dataset.artifact_ref, model.artifact_ref})
        self.assertEqual(len(lineage_graph.edges), 2)

    def test_audit_slice_and_chain_detect_record_tampering(self) -> None:
        source = self.store.create_artifact(
            kind="external_source",
            payload={"source": "paper"},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:ingest", environment_digest="oci:ingest"),
        )
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(
                input_refs=(source.artifact_ref,),
                code_ref="git:normalize",
                environment_digest="oci:normalize",
            ),
        )

        audit_slice = self.store.export_audit_slice((dataset.artifact_ref,))

        self.assertTrue(self.store.verify_audit_slice(audit_slice).valid)
        self.assertTrue(self.store.verify_audit_chain().valid)

        self.store._records[dataset.artifact_ref] = replace(dataset, kind="tampered")

        slice_verification = self.store.verify_audit_slice(audit_slice)
        chain_verification = self.store.verify_audit_chain()
        self.assertFalse(slice_verification.valid)
        self.assertFalse(chain_verification.valid)
        self.assertEqual(chain_verification.break_sequence, 2)


class S8TierCouplingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.store = InMemoryArtifactStore(report_verifier=C3ReportVerifier(self.trust_store))
        self.producer = Producer(subsystem="S2", version="0.0.0")
        self.lineage = Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model")

    def test_promoted_tier_requires_signature_valid_matching_report(self) -> None:
        report = self.store.create_artifact(
            kind="report",
            payload=self.signer.sign(self._report(claim_tier="recapitulated-known")),
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
        )

        model = self.store.create_artifact(
            kind="model",
            payload={"weights": [1], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
            producer=self.producer,
            lineage=self.lineage,
            claim_tier="recapitulated-known",
            validation_report_ref=report.artifact_ref,
        )

        self.assertEqual(model.validation_report_ref, report.artifact_ref)
        self.assertEqual(model.claim_tier, "recapitulated-known")

    def test_tier_mismatch_vs_report_is_rejected(self) -> None:
        report = self.store.create_artifact(
            kind="report",
            payload=self.signer.sign(self._report(claim_tier="recapitulated-known")),
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
        )

        with self.assertRaises(IllegalTierError):
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                producer=self.producer,
                lineage=self.lineage,
                claim_tier="novel-needs-human",
                validation_report_ref=report.artifact_ref,
            )

    def test_unknown_or_tampered_report_signature_is_rejected(self) -> None:
        unknown_signer = C3ReportSigner(key_id="unknown-key", secret=b"unknown-secret")
        with self.assertRaises(SignatureInvalidError):
            self.store.create_artifact(
                kind="report",
                payload=unknown_signer.sign(self._report(claim_tier="recapitulated-known")),
                producer=Producer(subsystem="S3", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
            )

        tampered = self.signer.sign(self._report(claim_tier="recapitulated-known"))
        tampered["aggregate"]["score"] = 0.1
        with self.assertRaises(SignatureInvalidError):
            self.store.create_artifact(
                kind="report",
                payload=tampered,
                producer=Producer(subsystem="S3", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
            )

    def test_novel_tier_requires_leakage_and_cross_code_pass(self) -> None:
        report_payload = self.signer.sign(
            self._report(
                claim_tier="novel-needs-human",
                checks=[
                    {"check": "LEAKAGE", "status": "FAIL"},
                    {"check": "CROSS_CODE", "status": "PASS"},
                ],
            )
        )
        report = self.store.create_artifact(
            kind="report",
            payload=report_payload,
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
        )

        with self.assertRaises(IllegalTierError):
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                producer=self.producer,
                lineage=self.lineage,
                claim_tier="novel-needs-human",
                validation_report_ref=report.artifact_ref,
            )

    @staticmethod
    def _report(
        *,
        claim_tier: str,
        checks: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        report = {
            "report_id": "33333333-3333-4333-8333-333333333333",
            "profile_ref": "c4://profile/ewpt-toy/v1",
            "frozen_pipeline_ref": "c4://pipeline/ewpt-toy/baseline",
            "checks": checks
            or [
                {"check": "INJECTION", "status": "PASS"},
                {"check": "LEAKAGE", "status": "PASS"},
                {"check": "CROSS_CODE", "status": "PASS"},
            ],
            "aggregate": {
                "passed": True,
                "score": 0.98,
            },
            "claim_tier": claim_tier,
            "claim_tier_is_candidate": claim_tier == "novel-needs-human",
            "signature": {
                "algorithm": "placeholder",
                "key_id": "placeholder",
                "value": "placeholder",
            },
            "perturbation_pairs": [
                {
                    "perturbation_id": "must-react-1",
                    "kind": "must_react",
                    "verdict": "pass",
                },
                {
                    "perturbation_id": "must-not-react-1",
                    "kind": "must_not_react",
                    "verdict": "pass",
                },
            ],
            "insensitivity_flags": [],
            "challenger_panel": {
                "challenger_ids": ["challenger-a", "challenger-b"],
                "min_required": 2,
            },
            "independence_attestation_debate": {
                "min_independent_challengers": 2,
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


if __name__ == "__main__":
    unittest.main()
