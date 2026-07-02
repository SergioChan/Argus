from __future__ import annotations

from copy import deepcopy
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    InMemoryArtifactStore,
    InMemoryS10KmsVerifierKeyProvider,
    Lineage,
    Producer,
    S10VerifierTrustStoreClient,
    SignatureInvalidError,
)


class S8S10TrustStoreIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = InMemoryS10KmsVerifierKeyProvider()
        self.provider.register_verifier_key("s3-key", b"s3-secret")
        self.client = S10VerifierTrustStoreClient(self.provider)
        self.store = InMemoryArtifactStore(report_verifier=C3ReportVerifier(self.client))
        self.report_producer = Producer(subsystem="S3", version="0.0.0")
        self.report_lineage = Lineage(input_refs=(), code_ref="git:verify", environment_digest="oci:verify")

    def test_s8_verifier_accepts_s10_kms_backed_key_without_exposing_secret(self) -> None:
        report = self.store.create_artifact(
            kind="report",
            payload=C3ReportSigner(key_id="s3-key", secret=b"s3-secret").sign(self._report()),
            producer=self.report_producer,
            lineage=self.report_lineage,
        )
        key = self.client.get_key("s3-key")

        self.assertTrue(report.artifact_ref.startswith("c4://artifact/"))
        self.assertIsNotNone(key)
        self.assertEqual(key.secret, b"")
        self.assertFalse(hasattr(self.client, "register_verifier_key"))
        self.assertFalse(hasattr(self.client, "revoke_verifier_key"))
        self.assertFalse(hasattr(self.client, "register_key"))

    def test_s8_verifier_refreshes_unknown_new_and_revoked_keys_fail_closed(self) -> None:
        with self.assertRaises(SignatureInvalidError) as unknown:
            self.store.create_artifact(
                kind="report",
                payload=C3ReportSigner(key_id="s3-key-v2", secret=b"s3-secret-v2").sign(self._report()),
                producer=self.report_producer,
                lineage=self.report_lineage,
            )
        self.assertEqual(unknown.exception.reason, "unknown_key")

        self.provider.register_verifier_key("s3-key-v2", b"s3-secret-v2")
        accepted = self.store.create_artifact(
            kind="report",
            payload=C3ReportSigner(key_id="s3-key-v2", secret=b"s3-secret-v2").sign(self._report()),
            producer=self.report_producer,
            lineage=self.report_lineage,
        )
        self.assertTrue(accepted.artifact_ref.startswith("c4://artifact/"))
        self.assertEqual(self.client.epoch, self.provider.epoch)

        self.provider.revoke_verifier_key("s3-key-v2")
        before_count = len(self.store)
        with self.assertRaises(SignatureInvalidError) as revoked:
            self.store.create_artifact(
                kind="report",
                payload=C3ReportSigner(key_id="s3-key-v2", secret=b"s3-secret-v2").sign(self._report()),
                producer=self.report_producer,
                lineage=self.report_lineage,
            )
        self.assertEqual(revoked.exception.reason, "revoked_key")
        self.assertEqual(len(self.store), before_count)

    def test_s8_verifier_delegates_signature_validation_to_s10_provider_after_rotation(self) -> None:
        signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.store.create_artifact(
            kind="report",
            payload=signer.sign(self._report()),
            producer=self.report_producer,
            lineage=self.report_lineage,
        )

        self.provider.rotate_verifier_key("s3-key", b"s3-rotated-secret")
        with self.assertRaises(SignatureInvalidError) as stale:
            self.store.create_artifact(
                kind="report",
                payload=signer.sign(self._report()),
                producer=self.report_producer,
                lineage=self.report_lineage,
            )
        self.assertEqual(stale.exception.reason, "signature_invalid")

        rotated = self.store.create_artifact(
            kind="report",
            payload=C3ReportSigner(key_id="s3-key", secret=b"s3-rotated-secret").sign(self._report()),
            producer=self.report_producer,
            lineage=self.report_lineage,
        )
        self.assertTrue(rotated.artifact_ref.startswith("c4://artifact/"))

    @staticmethod
    def _report() -> dict[str, object]:
        return deepcopy(
            {
                "report_id": "33333333-3333-4333-8333-333333333333",
                "profile_ref": "c4://profile/ewpt-toy/v1",
                "frozen_pipeline_ref": "c4://pipeline/ewpt-toy/baseline",
                "checks": [
                    {"check": "INJECTION", "status": "PASS"},
                    {"check": "LEAKAGE", "status": "PASS"},
                    {"check": "CROSS_CODE", "status": "PASS"},
                ],
                "aggregate": {
                    "passed": True,
                    "score": 0.98,
                },
                "claim_tier": "recapitulated-known",
                "claim_tier_is_candidate": False,
                "signature": {
                    "algorithm": "placeholder",
                    "key_id": "placeholder",
                    "value": "placeholder",
                },
            }
        )


if __name__ == "__main__":
    unittest.main()
