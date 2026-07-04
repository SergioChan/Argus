from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    ExecContext,
    InMemoryArtifactStore,
    InMemoryRegistry,
    JobEnvelope,
    Lineage,
    Producer,
    S1_REFERENCE_CONFORMANCE_EVIDENCE_KIND,
    S1ReferenceConformanceHarness,
    Subagent,
    SubagentDescriptor,
    build_s1_capability_descriptor,
    hash_json,
    publish_s1_capability_descriptor,
)


ROOT = Path(__file__).resolve().parents[1]
C5_SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c5.capability-descriptor.schema.json"
FUTURE_EXPIRES_AT = "2099-01-01T00:00:00Z"
PAST_EXPIRES_AT = "1970-01-02T00:00:00Z"


class DescriptorConformanceSubagent(Subagent):
    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
        return {
            "steps": [{"step_id": "fit", "kind": "train", "description": "Fit descriptor conformance model"}],
            "adapters_required": list(envelope.required_adapters),
            "datasets_required": [],
            "risk_notes": [],
        }

    def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
        artifact = ctx.emit_artifact(
            {"weights": [1.0], "plan_hash": plan["plan_hash"]},
            kind="model",
            lineage=Lineage(
                input_refs=(),
                code_ref="git:project-argus@s1-t23-descriptor-conformance",
                environment_digest="oci:s1-t23-descriptor-conformance@sha256-reference",
                seeds=("s1-t23-conformance-seed",),
            ),
        )
        return {
            "artifact_refs": [str(artifact["artifact_ref"])],
            "diagnostics": {"model_ref": str(artifact["artifact_ref"])},
            "self_checks": [{"type": "smoke", "status": "PASS", "advisory": True}],
        }


class S1CapabilityDescriptorRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(C5_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def setUp(self) -> None:
        self.subagent_descriptor = SubagentDescriptor(
            subagent_id="s1-ewpt-reference",
            contract_version="1.0.0",
            subtopics=("ewpt", "gw-spectrum"),
            required_adapters=("adapter:bounce", "adapter:gw"),
        )
        self.envelope = JobEnvelope(
            job_id="23232323-2323-4232-8232-232323232323",
            envelope_version="1.0.0",
            subtopic="ewpt",
            required_adapters=("adapter:bounce",),
            allowed_adapters=("adapter:bounce",),
            verifier_profile_ref="c4://profile/ewpt/s1-t23",
            estimated_cost=0.25,
            budget_cost=1.0,
        )

    def test_builder_emits_schema_valid_c5_descriptor_for_s1_subagent(self) -> None:
        descriptor = build_s1_capability_descriptor(
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
        )

        payload = descriptor.as_c5_payload()
        self._assert_valid(payload)
        self.assertEqual(payload["entity_id"], "s1-ewpt-reference")
        self.assertEqual(payload["kind"], "subagent")
        self.assertEqual(payload["owner_subsystem"], "S1")
        self.assertEqual(payload["contract_versions"], {"C1": "1.0.0", "C5": "1.0.0"})
        self.assertEqual(payload["subtopics"], ["ewpt", "gw-spectrum"])
        self.assertEqual(payload["capability_scopes"], ["c1.accept", "c1.plan", "c1.build", "c1.validate", "c1.report"])
        self.assertEqual(payload["independence_tags"], ["impl-reference"])
        self.assertNotIn("conformance_level", payload)

    def test_publish_writes_schema_valid_descriptor_artifact_and_registry_resolution(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)

        published = publish_s1_capability_descriptor(
            registry,
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
        )

        self.assertNotEqual(published.provenance_ref, "c4://pending")
        self.assertEqual(published.conformance_level, None)
        record = store.get_record(published.provenance_ref)
        payload = json.loads(store.get_artifact(published.provenance_ref).decode("utf-8"))

        self.assertEqual(record.kind, "capability_descriptor")
        self._assert_valid(payload)
        self.assertEqual(payload["entity_id"], self.subagent_descriptor.subagent_id)
        self.assertEqual(registry.get(self.subagent_descriptor.subagent_id), published)
        resolution = registry.resolve(kind="subagent", subtopic="ewpt", required_scope="c1.build")
        self.assertEqual(resolution.descriptors, (published,))
        self.assertEqual(registry.events[-1].event_type, "s6.registry.published")

    def test_publish_rejects_descriptor_that_cannot_satisfy_s1_accept_scope(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)

        with self.assertRaisesRegex(ValueError, "c1.accept"):
            publish_s1_capability_descriptor(
                registry,
                self.subagent_descriptor,
                revision=1,
                capability_scopes=("c1.plan", "c1.build"),
                independence_tags=("impl-reference",),
            )

        self.assertEqual(registry.events, ())
        self.assertEqual(store.record_count, 0)

    def test_publish_populates_unexpired_conformance_block_from_passing_run(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)
        result = self._run_conformance(store, level="bronze")

        published = publish_s1_capability_descriptor(
            registry,
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
            conformance_result=result,
            conformance_expires_at=FUTURE_EXPIRES_AT,
        )

        payload = published.as_c5_payload()
        record_payload = json.loads(store.get_artifact(published.provenance_ref).decode("utf-8"))
        expected = {
            "level": "bronze",
            "suite_version": result.suite_version,
            "standard_release_ref": result.standard_release_ref,
            "evidence_ref": result.evidence_ref,
            "determinism_hash": result.determinism_hash,
            "expires_at": FUTURE_EXPIRES_AT,
        }

        self._assert_valid(payload)
        self.assertEqual(payload["conformance"], expected)
        self.assertEqual(record_payload["conformance"], expected)
        self.assertEqual(registry.get(self.subagent_descriptor.subagent_id).conformance, expected)
        evidence = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence["attestation"]["algorithm"], "hmac-sha256")
        self.assertEqual(evidence["attestation"]["key_id"], "s1-reference-conformance-key-v1")
        self.assertTrue(evidence["attestation"]["value"].startswith("hmac-sha256:"))

    def test_publish_rejects_failed_conformance_result_before_registry_mutation(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)
        failed = self._run_conformance(store, level="silver")
        evidence_records = store.record_count

        with self.assertRaisesRegex(ValueError, "passing conformance"):
            publish_s1_capability_descriptor(
                registry,
                self.subagent_descriptor,
                revision=1,
                independence_tags=("impl-reference",),
                conformance_result=failed,
                conformance_expires_at=FUTURE_EXPIRES_AT,
            )

        self.assertFalse(failed.aggregate_passed)
        self.assertEqual(registry.events, ())
        self.assertEqual(store.record_count, evidence_records)

    def test_builder_rejects_incomplete_raw_conformance_block(self) -> None:
        with self.assertRaisesRegex(ValueError, "conformance missing required field"):
            build_s1_capability_descriptor(
                self.subagent_descriptor,
                revision=1,
                independence_tags=("impl-reference",),
                conformance={"level": "gold"},
            )

    def test_builder_rejects_raw_conformance_block_with_unrecognized_fields(self) -> None:
        store = InMemoryArtifactStore()
        result = self._run_conformance(store, level="bronze")
        with self.assertRaisesRegex(ValueError, "conformance has unrecognized field"):
            build_s1_capability_descriptor(
                self.subagent_descriptor,
                revision=1,
                independence_tags=("impl-reference",),
                conformance=result.descriptor_conformance_block(expires_at=FUTURE_EXPIRES_AT)
                | {"self_attested": "true"},
            )

    def test_storeless_registry_rejects_raw_conformance_evidence_pass_through(self) -> None:
        store = InMemoryArtifactStore()
        result = self._run_conformance(store, level="bronze")
        registry = InMemoryRegistry()

        with self.assertRaisesRegex(Exception, "CONFORMANCE_EVIDENCE_STORE_REQUIRED"):
            publish_s1_capability_descriptor(
                registry,
                self.subagent_descriptor,
                revision=1,
                independence_tags=("impl-reference",),
                conformance=result.descriptor_conformance_block(expires_at=FUTURE_EXPIRES_AT),
            )

        self.assertEqual(registry.events, ())

    def test_store_backed_registry_accepts_verified_raw_conformance_pass_through(self) -> None:
        store = InMemoryArtifactStore()
        result = self._run_conformance(store, level="bronze")
        registry = InMemoryRegistry(artifact_store=store)

        published = publish_s1_capability_descriptor(
            registry,
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
            conformance=result.descriptor_conformance_block(expires_at=FUTURE_EXPIRES_AT),
        )

        self.assertEqual(published.conformance["evidence_ref"], result.evidence_ref)
        self.assertEqual(registry.get(self.subagent_descriptor.subagent_id), published)

    def test_registry_rejects_expired_or_tampered_conformance_block(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)
        result = self._run_conformance(store, level="bronze")
        valid_conformance = result.descriptor_conformance_block(expires_at=FUTURE_EXPIRES_AT)

        expired = build_s1_capability_descriptor(
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
            conformance=valid_conformance | {"expires_at": PAST_EXPIRES_AT},
        )
        tampered = build_s1_capability_descriptor(
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
            conformance=valid_conformance | {"determinism_hash": "blake3:" + ("0" * 64)},
        )

        with self.assertRaisesRegex(Exception, "CONFORMANCE_EXPIRED"):
            registry.publish(expired)
        with self.assertRaisesRegex(Exception, "CONFORMANCE_TAMPERED"):
            registry.publish(tampered)

        self.assertEqual(registry.events, ())

    def test_registry_rejects_self_consistent_forged_conformance_evidence(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)
        forged = {
            "schema": "argus.s1.reference_conformance_evidence.v1",
            "subagent_id": self.subagent_descriptor.subagent_id,
            "level_requested": "gold",
            "level_awarded": "gold",
            "suite_version": "s1-reference-conformance.v1",
            "standard_release_ref": "c4://standard/c1/1.0.0",
            "aggregate_passed": True,
            "checks": [],
        }
        forged["determinism_hash"] = hash_json(forged)
        forged_record = store.create_artifact(
            kind=S1_REFERENCE_CONFORMANCE_EVIDENCE_KIND,
            payload=forged,
            producer=Producer(subsystem="ATTACKER", version="0.0.0", actor_id="forged-conformance"),
            lineage=Lineage(
                input_refs=(),
                code_ref="argus-core:attacker.forged-conformance",
                environment_digest="python:attacker:v1",
            ),
        )
        descriptor = build_s1_capability_descriptor(
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
            conformance={
                "level": "gold",
                "suite_version": "s1-reference-conformance.v1",
                "standard_release_ref": "c4://standard/c1/1.0.0",
                "evidence_ref": forged_record.artifact_ref,
                "determinism_hash": forged["determinism_hash"],
                "expires_at": FUTURE_EXPIRES_AT,
            },
        )

        with self.assertRaisesRegex(Exception, "CONFORMANCE_UNTRUSTED"):
            registry.publish(descriptor)

        self.assertEqual(registry.events, ())

    def test_registry_rejects_forged_conformance_with_impersonated_record_metadata(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)
        forged = {
            "schema": "argus.s1.reference_conformance_evidence.v1",
            "subagent_id": self.subagent_descriptor.subagent_id,
            "level_requested": "gold",
            "level_awarded": "gold",
            "suite_version": "s1-reference-conformance.v1",
            "standard_release_ref": "c4://standard/c1/1.0.0",
            "aggregate_passed": True,
            "checks": [],
        }
        forged["determinism_hash"] = hash_json(forged)
        forged["attestation"] = {
            "algorithm": "hmac-sha256",
            "key_id": "s1-reference-conformance-key-v1",
            "value": "hmac-sha256:forged",
        }
        forged_record = store.create_artifact(
            kind=S1_REFERENCE_CONFORMANCE_EVIDENCE_KIND,
            payload=forged,
            producer=Producer(
                subsystem="S1",
                version="s1-reference-conformance.v1",
                actor_id="s1.reference_conformance",
                job_id=self.envelope.job_id,
            ),
            lineage=Lineage(
                input_refs=(),
                code_ref="argus-core:s1.reference-conformance",
                environment_digest="python:s1-reference-conformance:v1",
                job_id=self.envelope.job_id,
            ),
        )
        descriptor = build_s1_capability_descriptor(
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
            conformance={
                "level": "gold",
                "suite_version": "s1-reference-conformance.v1",
                "standard_release_ref": "c4://standard/c1/1.0.0",
                "evidence_ref": forged_record.artifact_ref,
                "determinism_hash": forged["determinism_hash"],
                "expires_at": FUTURE_EXPIRES_AT,
            },
        )

        with self.assertRaisesRegex(Exception, "CONFORMANCE_UNTRUSTED: attestation_signature"):
            registry.publish(descriptor)

        self.assertEqual(registry.events, ())

    def _run_conformance(self, store: InMemoryArtifactStore, *, level: str):
        harness = S1ReferenceConformanceHarness(
            suite_version="s1-reference-conformance.v1",
            standard_release_ref="c4://standard/c1/1.0.0",
        )
        return harness.run(
            DescriptorConformanceSubagent(self.subagent_descriptor),
            envelope=self.envelope,
            level=level,
            artifact_store=store,
        )

    def _assert_valid(self, payload: dict[str, object]) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])


if __name__ == "__main__":
    unittest.main()
