from __future__ import annotations

from copy import deepcopy
import json
import unittest

from argus_core import (
    CheckResult,
    S3KeyManagementError,
    S3TrustStoreKeyManager,
    S3Verifier,
)


class S3TrustStoreKeyManagementTests(unittest.TestCase):
    def test_tc49_rotation_keeps_archived_reports_valid_and_new_reports_use_active_key(self) -> None:
        manager = S3TrustStoreKeyManager(actor_id="s3-t15-test")
        manager.register_signing_key("s3-k1", b"s3-secret-k1")
        archived = self._build_report(manager, proponent_id="builder-k1")

        manager.rotate_signing_key("s3-k2", b"s3-secret-k2")
        fresh = self._build_report(manager, proponent_id="builder-k2")
        archived_verification = manager.verify_report(archived)
        fresh_verification = manager.verify_report(fresh)

        self.assertEqual(archived["signature"]["key_id"], "s3-k1")
        self.assertEqual(fresh["signature"]["key_id"], "s3-k2")
        self.assertTrue(archived_verification.valid)
        self.assertTrue(fresh_verification.valid)
        self.assertEqual(manager.get_key("s3-k1").secret, b"")
        self.assertEqual(manager.get_key("s3-k2").secret, b"")
        self.assertIn(
            ("s3.key.sign", "s3-k1", "accepted"),
            self._audit_triplets(manager),
        )
        self.assertIn(
            ("s3.key.rotate", "s3-k2", "accepted"),
            self._audit_triplets(manager),
        )
        self.assertIn(
            ("s3.key.verify", "s3-k1", "accepted"),
            self._audit_triplets(manager),
        )
        self.assertIn(
            ("s3.key.verify", "s3-k2", "accepted"),
            self._audit_triplets(manager),
        )

    def test_agent_zone_surfaces_never_expose_key_material(self) -> None:
        manager = S3TrustStoreKeyManager(actor_id="s3-t15-test")
        manager.register_signing_key("s3-k1", b"s3-secret-k1")
        report = self._build_report(manager, proponent_id="builder")
        manager.rotate_signing_key("s3-k2", b"s3-secret-k2")
        manager.verify_report(report)

        agent_visible_surface = {
            "audit": [event.as_payload() for event in manager.audit_events()],
            "metadata": [metadata.as_payload() for metadata in manager.key_metadata()],
            "report": report,
        }
        serialized = json.dumps(agent_visible_surface, sort_keys=True, default=_json_default)

        self.assertNotIn("s3-secret-k1", serialized)
        self.assertNotIn("s3-secret-k2", serialized)
        self.assertEqual(manager.get_key("s3-k1").secret, b"")
        self.assertTrue(all(not event.key_material_exposed for event in manager.audit_events()))

    def test_revoked_and_unknown_keys_fail_closed_with_audit(self) -> None:
        manager = S3TrustStoreKeyManager(actor_id="s3-t15-test")
        manager.register_signing_key("s3-k1", b"s3-secret-k1")
        report = self._build_report(manager, proponent_id="builder")

        tampered_unknown = deepcopy(report)
        tampered_unknown["signature"]["key_id"] = "missing-key"
        unknown = manager.verify_report(tampered_unknown)

        manager.revoke_signing_key("s3-k1", reason="compromised")
        revoked = manager.verify_report(report)

        self.assertFalse(unknown.valid)
        self.assertEqual(unknown.reason, "unknown_key")
        self.assertFalse(revoked.valid)
        self.assertEqual(revoked.reason, "revoked_key")
        with self.assertRaises(S3KeyManagementError) as raised:
            self._build_report(manager, proponent_id="builder-after-revoke")
        self.assertEqual(raised.exception.code, "S3_SIGNING_KEY_REVOKED")
        self.assertIn(("s3.key.verify", "missing-key", "unknown_key"), self._audit_triplets(manager))
        self.assertIn(("s3.key.revoke", "s3-k1", "accepted"), self._audit_triplets(manager))
        self.assertIn(("s3.key.verify", "s3-k1", "revoked_key"), self._audit_triplets(manager))

    def test_key_ids_are_immutable_and_cannot_overwrite_history(self) -> None:
        manager = S3TrustStoreKeyManager(actor_id="s3-t15-test")
        manager.register_signing_key("s3-k1", b"s3-secret-k1")
        archived = self._build_report(manager, proponent_id="builder-k1")

        with self.assertRaises(S3KeyManagementError) as register_error:
            manager.register_signing_key("s3-k1", b"replacement-secret")
        self.assertEqual(register_error.exception.code, "S3_SIGNING_KEY_ALREADY_EXISTS")
        with self.assertRaises(S3KeyManagementError) as rotate_error:
            manager.rotate_signing_key("s3-k1", b"replacement-secret")
        self.assertEqual(rotate_error.exception.code, "S3_SIGNING_KEY_ALREADY_EXISTS")

        verification = manager.verify_report(archived)

        self.assertTrue(verification.valid)
        self.assertEqual(archived["signature"]["key_id"], "s3-k1")
        self.assertEqual(manager.get_key("s3-k1").secret, b"")

    @staticmethod
    def _build_report(manager: S3TrustStoreKeyManager, *, proponent_id: str) -> dict[str, object]:
        verifier = S3Verifier(
            verifier_id="s3-referee",
            signer_key_id=manager.key_id,
            signer=manager,
        )
        return verifier.build_report(
            profile_ref="c4://profile/ewpt/v1",
            frozen_pipeline_ref="c4://pipeline/ewpt/baseline",
            proponent_id=proponent_id,
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
                CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
            ),
        )

    @staticmethod
    def _audit_triplets(manager: S3TrustStoreKeyManager) -> set[tuple[str, str, str]]:
        return {(event.event_type, event.key_id, event.outcome) for event in manager.audit_events()}


def _json_default(value: object) -> object:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


if __name__ == "__main__":
    unittest.main()
