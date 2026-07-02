from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest

from argus_core import (
    ArtifactQueryFilter,
    BLAKE3_PREFIX,
    C3ReportSigner,
    C3ReportVerifier,
    CycleDetectedError,
    FileSystemArtifactStore,
    FileSystemObjectStore,
    HashMismatchError,
    IllegalTierError,
    InMemoryArtifactStore,
    InMemoryObjectStore,
    InMemoryVerifierTrustStore,
    IncompleteLineageError,
    LedgerReplayError,
    Lineage,
    Producer,
    SCRATCH_BUCKET,
    SignatureInvalidError,
    WRITE_ONCE_BUCKET,
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
        self.object_store = InMemoryObjectStore()
        self.store = InMemoryArtifactStore(object_store=self.object_store)
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
        self.assertEqual(self.store.get_artifact(dataset.content_hash), b'{"same":true}')
        with self.assertRaises(KeyError) as raised:
            self.store.get_artifact_record(dataset.content_hash)
        self.assertIn("ambiguous content_hash", str(raised.exception))

    def test_explicit_ref_is_write_once(self) -> None:
        artifact_ref = "c4://artifact/fixed-ref"
        original = self.store.create_artifact(
            artifact_ref=artifact_ref,
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=self.lineage,
        )

        with self.assertRaises(WriteOnceViolationError) as raised:
            self.store.create_artifact(
                artifact_ref=artifact_ref,
                kind="model",
                payload={"weights": [2]},
                producer=self.producer,
                lineage=self.lineage,
            )

        self.assertEqual(raised.exception.category, "IMMUTABLE_VIOLATION")
        self.assertEqual(self.store.get_record(artifact_ref), original)
        self.assertEqual(self.store.get_artifact(artifact_ref), b'{"weights":[1]}')

    def test_scratch_object_promotes_to_write_once_when_referenced(self) -> None:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )

        self.assertEqual(self.store.bucket_class_for_artifact(dataset.artifact_ref), SCRATCH_BUCKET)

        model = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:model",
                environment_digest="oci:model",
            ),
        )

        self.assertEqual(self.store.bucket_class_for_artifact(dataset.artifact_ref), WRITE_ONCE_BUCKET)
        self.assertEqual(self.store.bucket_class_for_artifact(model.artifact_ref), SCRATCH_BUCKET)

    def test_report_artifact_is_written_to_write_once_bucket(self) -> None:
        report = self.store.create_artifact(
            kind="report",
            payload={"report": "unsigned-test-report"},
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
        )

        self.assertEqual(self.store.bucket_class_for_artifact(report.artifact_ref), WRITE_ONCE_BUCKET)

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
        self.object_store._objects[record.content_hash] = b'{"weights":[2]}'

        with self.assertRaises(HashMismatchError) as raised:
            self.store.get_artifact(record.artifact_ref)

        self.assertEqual(raised.exception.category, "HASH_MISMATCH")

    def test_get_artifact_by_content_hash_detects_tamper_but_record_read_is_metadata_only(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=self.lineage,
        )

        self.assertEqual(self.store.get_artifact(record.content_hash), b'{"weights":[1]}')
        self.object_store._objects[record.content_hash] = b'{"weights":[2]}'

        self.assertEqual(self.store.get_artifact_record(record.artifact_ref), record)
        with self.assertRaises(HashMismatchError) as raised:
            self.store.get_artifact(record.content_hash)
        self.assertEqual(raised.exception.category, "HASH_MISMATCH")
        with self.assertRaises(HashMismatchError):
            self.store.get_record(record.artifact_ref)

    def test_query_artifacts_filters_and_paginates_metadata(self) -> None:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        report = self.store.create_artifact(
            kind="report",
            payload={"report": "unsigned-test-report"},
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
        )
        model = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:model",
                environment_digest="oci:model",
            ),
            validation_report_ref=report.artifact_ref,
        )

        self.assertEqual(self.store.query_artifacts({"kind": "model"}), (model,))
        self.assertEqual(self.store.query_artifacts({"content_hash": dataset.content_hash}), (dataset,))
        self.assertEqual(self.store.query_artifacts(ArtifactQueryFilter(producer_subsystem="S6")), (dataset,))
        self.assertEqual(self.store.query_artifacts({"validation_report_ref": report.artifact_ref}), (model,))
        with self.assertRaises(ValueError):
            self.store.query_artifacts({"unsupported": "filter"})

        all_ran_toy = self.store.query_artifacts_page({"claim_tier": "ran-toy"}, page_size=2)
        second_page = self.store.query_artifacts_page(
            {"claim_tier": "ran-toy"},
            page_size=2,
            page_token=all_ran_toy.next_page_token,
        )
        expected_refs = tuple(sorted(record.artifact_ref for record in (dataset, model, report)))

        self.assertEqual(tuple(record.artifact_ref for record in all_ran_toy.records), expected_refs[:2])
        self.assertEqual(all_ran_toy.next_page_token, 2)
        self.assertEqual(tuple(record.artifact_ref for record in second_page.records), expected_refs[2:])
        self.assertIsNone(second_page.next_page_token)

    def test_get_artifact_record_metadata_lookup_unit_p95_stays_under_slo(self) -> None:
        records = [
            self.store.create_artifact(
                artifact_ref=f"c4://artifact/unit-scale-{index}",
                kind="dataset",
                payload={"row": index},
                producer=self.producer,
                lineage=Lineage(input_refs=(), code_ref=f"git:data:{index}", environment_digest=f"oci:data:{index}"),
            )
            for index in range(2500)
        ]
        samples: list[float] = []

        for record in records[-1000:]:
            started = time.perf_counter()
            self.store.get_artifact_record(record.content_hash)
            samples.append(time.perf_counter() - started)

        p95 = sorted(samples)[int(len(samples) * 0.95) - 1]
        self.assertLess(p95, 0.050)

    def test_self_cycle_is_rejected(self) -> None:
        artifact_ref = "c4://artifact/self-cycle"

        with self.assertRaises(CycleDetectedError) as raised:
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

        self.assertEqual(raised.exception.category, "CYCLE_DETECTED")

    def test_two_node_cycle_is_rejected_without_edge_mutation(self) -> None:
        a_ref = "c4://artifact/a"
        b_ref = "c4://artifact/b"
        self.store.create_artifact(
            artifact_ref=a_ref,
            kind="dataset",
            payload={"rows": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:a", environment_digest="oci:a"),
        )
        self.store.create_artifact(
            artifact_ref=b_ref,
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(a_ref,), code_ref="git:b", environment_digest="oci:b"),
        )
        edge_count = self.store.edge_count
        record_count = self.store.record_count

        with self.assertRaises(CycleDetectedError) as raised:
            self.store.create_artifact(
                artifact_ref=a_ref,
                kind="dataset",
                payload={"rows": [2]},
                producer=self.producer,
                lineage=Lineage(input_refs=(b_ref,), code_ref="git:a2", environment_digest="oci:a2"),
            )

        self.assertEqual(raised.exception.category, "CYCLE_DETECTED")
        self.assertEqual(self.store.edge_count, edge_count)
        self.assertEqual(self.store.record_count, record_count)

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

    def test_audit_slice_proofs_and_chain_detect_tampering(self) -> None:
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

        audit_slice = self.store.export_audit_slice((dataset.artifact_ref,))

        self.assertEqual(audit_slice.checkpoint.sequence, 3)
        self.assertEqual(tuple(leaf.artifact_ref for leaf in audit_slice.leaves), (dataset.artifact_ref,))
        self.assertEqual(len(audit_slice.inclusion_proofs), 1)
        self.assertEqual(audit_slice.inclusion_proofs[0].sequence, 2)
        self.assertEqual(tuple(step.artifact_ref for step in audit_slice.inclusion_proofs[0].steps), (model.artifact_ref,))
        self.assertTrue(self.store.verify_audit_slice(audit_slice).valid)
        self.assertTrue(self.store.verify_audit_chain().valid)

        tampered_step = replace(audit_slice.inclusion_proofs[0].steps[0], record_hash="blake3:" + ("f" * 64))
        tampered_proof = replace(audit_slice.inclusion_proofs[0], steps=(tampered_step,))
        tampered_slice = replace(audit_slice, inclusion_proofs=(tampered_proof,))

        proof_verification = self.store.verify_audit_slice(tampered_slice)
        self.assertFalse(proof_verification.valid)
        self.assertEqual(proof_verification.break_sequence, 3)

        self.store._records[dataset.artifact_ref] = replace(dataset, kind="tampered")

        slice_verification = self.store.verify_audit_slice(audit_slice)
        chain_verification = self.store.verify_audit_chain()
        self.assertFalse(slice_verification.valid)
        self.assertFalse(chain_verification.valid)
        self.assertEqual(chain_verification.break_sequence, 2)


class FileSystemObjectStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.object_store = FileSystemObjectStore(self.tempdir.name)
        self.store = InMemoryArtifactStore(object_store=self.object_store)
        self.producer = Producer(subsystem="S2", version="0.0.0")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_filesystem_store_persists_and_reads_canonical_bytes(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
        )
        stored_path = self.object_store.object_path(record.content_hash)

        self.assertIsNotNone(stored_path)
        self.assertEqual(self.object_store.bucket_class(record.content_hash), SCRATCH_BUCKET)
        self.assertEqual(self.store.get_artifact(record.artifact_ref), b'{"weights":[1]}')

    def test_filesystem_store_promotes_referenced_scratch_input_to_write_once(self) -> None:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        scratch_path = self.object_store.object_path(dataset.content_hash)

        self.assertIsNotNone(scratch_path)
        assert scratch_path is not None
        self.assertEqual(scratch_path.parent.name, SCRATCH_BUCKET)

        self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:model",
                environment_digest="oci:model",
            ),
        )
        promoted_path = self.object_store.object_path(dataset.content_hash)

        self.assertIsNotNone(promoted_path)
        assert promoted_path is not None
        self.assertEqual(promoted_path.parent.name, WRITE_ONCE_BUCKET)
        self.assertFalse(scratch_path.exists())

    def test_filesystem_store_verify_on_read_detects_tampering(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
        )
        stored_path = self.object_store.object_path(record.content_hash)
        assert stored_path is not None
        stored_path.write_bytes(b'{"weights":[2]}')

        with self.assertRaises(HashMismatchError) as raised:
            self.store.get_artifact(record.artifact_ref)

        self.assertEqual(raised.exception.category, "HASH_MISMATCH")

    def test_filesystem_store_rejects_write_to_mismatched_hash(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
        )

        with self.assertRaises(HashMismatchError):
            self.object_store.put(record.content_hash, b'{"weights":[2]}', bucket_class=SCRATCH_BUCKET)


class FileSystemArtifactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.producer = Producer(subsystem="S2", version="0.0.0")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_reopen_replays_records_lineage_and_audit_chain(self) -> None:
        store = FileSystemArtifactStore(self.root)
        dataset = store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        model = store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:model",
                environment_digest="oci:model",
            ),
        )

        reopened = FileSystemArtifactStore(self.root)
        lineage_graph = reopened.get_lineage(model.artifact_ref, direction="ancestors")

        self.assertEqual(reopened.record_count, 2)
        self.assertEqual(reopened.object_count, 2)
        self.assertEqual(reopened.get_artifact(model.artifact_ref), b'{"weights":[1]}')
        self.assertTrue(reopened.verify_audit_chain().valid)
        self.assertEqual({node.artifact_ref for node in lineage_graph.nodes}, {dataset.artifact_ref, model.artifact_ref})
        self.assertEqual(len(lineage_graph.edges), 1)

    def test_reopen_rejects_tampered_append_only_ledger(self) -> None:
        store = FileSystemArtifactStore(self.root)
        store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
        )
        ledger_path = self.root / "artifact_ledger.jsonl"
        ledger_bytes = ledger_path.read_bytes()
        ledger_path.write_bytes(ledger_bytes.replace(b'"kind":"model"', b'"kind":"tampered"', 1))

        with self.assertRaises(LedgerReplayError) as raised:
            FileSystemArtifactStore(self.root)

        self.assertEqual(raised.exception.category, "LEDGER_REPLAY_FAILED")


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

        with self.assertRaises(IllegalTierError) as raised:
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                producer=self.producer,
                lineage=self.lineage,
                claim_tier="novel-needs-human",
                validation_report_ref=report.artifact_ref,
            )

        self.assertEqual(raised.exception.category, "ILLEGAL_TIER")
        self.assertEqual(raised.exception.reason, "tier must match validation report claim_tier")

    def test_unknown_or_tampered_report_signature_is_rejected(self) -> None:
        unknown_signer = C3ReportSigner(key_id="unknown-key", secret=b"unknown-secret")
        with self.assertRaises(SignatureInvalidError) as unknown:
            self.store.create_artifact(
                kind="report",
                payload=unknown_signer.sign(self._report(claim_tier="recapitulated-known")),
                producer=Producer(subsystem="S3", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
            )
        self.assertEqual(unknown.exception.category, "SIGNATURE_INVALID")
        self.assertEqual(unknown.exception.reason, "unknown_key")

        tampered = self.signer.sign(self._report(claim_tier="recapitulated-known"))
        tampered["aggregate"]["score"] = 0.1
        with self.assertRaises(SignatureInvalidError) as tamper:
            self.store.create_artifact(
                kind="report",
                payload=tampered,
                producer=Producer(subsystem="S3", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
            )
        self.assertEqual(tamper.exception.category, "SIGNATURE_INVALID")
        self.assertEqual(tamper.exception.reason, "signature_invalid")

    def test_revoked_report_signing_key_is_rejected(self) -> None:
        self.trust_store.revoke_key("s3-key")

        with self.assertRaises(SignatureInvalidError) as raised:
            self.store.create_artifact(
                kind="report",
                payload=self.signer.sign(self._report(claim_tier="recapitulated-known")),
                producer=Producer(subsystem="S3", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
            )

        self.assertEqual(raised.exception.category, "SIGNATURE_INVALID")
        self.assertEqual(raised.exception.reason, "revoked_key")
        self.assertEqual(len(self.store), 0)

    def test_placeholder_report_signature_is_rejected_fail_closed(self) -> None:
        with self.assertRaises(SignatureInvalidError) as raised:
            self.store.create_artifact(
                kind="report",
                payload=self._report(claim_tier="recapitulated-known"),
                producer=Producer(subsystem="S3", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
            )

        self.assertEqual(raised.exception.category, "SIGNATURE_INVALID")
        self.assertEqual(raised.exception.reason, "algorithm_unsupported")
        self.assertEqual(len(self.store), 0)

    def test_unsigned_report_cannot_promote_tier(self) -> None:
        unsigned = self._report(claim_tier="recapitulated-known")
        unsigned.pop("signature")
        report = self.store.create_artifact(
            kind="report",
            payload=unsigned,
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify"),
        )

        with self.assertRaises(SignatureInvalidError) as raised:
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                producer=self.producer,
                lineage=self.lineage,
                claim_tier="recapitulated-known",
                validation_report_ref=report.artifact_ref,
            )

        self.assertEqual(raised.exception.category, "SIGNATURE_INVALID")
        self.assertEqual(raised.exception.reason, "signature_missing")

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

        with self.assertRaises(IllegalTierError) as raised:
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                producer=self.producer,
                lineage=self.lineage,
                claim_tier="novel-needs-human",
                validation_report_ref=report.artifact_ref,
            )

        self.assertEqual(raised.exception.category, "ILLEGAL_TIER")
        self.assertEqual(raised.exception.reason, "novel tier requires LEAKAGE PASS")

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
