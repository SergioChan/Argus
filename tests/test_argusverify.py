from __future__ import annotations

from copy import deepcopy
import unittest

import argusverify
from argus_core import C3ReportVerifier
from argusverify import (
    C3ReportSigner,
    InMemoryVerifierTrustStore,
    SIGNATURE_VERIFICATION_ABSTAIN,
    SIGNATURE_VERIFICATION_ACCEPTED,
    VerifierKey,
    sign_report,
    verify_report,
)


VECTOR_REPORT = {
    "report_id": "33333333-3333-4333-8333-333333333333",
    "profile_ref": "c4://profile/ewpt-toy/v1",
    "frozen_pipeline_ref": "c4://pipeline/ewpt-toy/baseline",
    "checks": [
        {
            "check": "INJECTION",
            "status": "PASS",
            "metrics": {
                "recovery_rate": 0.98,
                "integer_float": 1.0,
                "zero_float": 0.0,
                "z_max": 3.0,
                "tiny_signal": 0.0000001,
                "micro_signal": 0.000001,
                "large_fixed": 1e20,
                "large_exponent": 1e21,
            },
            "evidence_refs": ["c4://evidence/injection/example"],
        }
    ],
    "aggregate": {"passed": True, "score": 1.0},
    "claim_tier": "recapitulated-known",
    "claim_tier_is_candidate": False,
    "perturbation_pairs": [],
    "insensitivity_flags": [],
    "challenger_panel": {"challenger_ids": ["challenger-a", "challenger-b"], "min_required": 2},
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

EXPECTED_SIGNATURE = "hmac-sha256:49bb4f2abf5cf349d510031b6838e527f663c7b7c844cccf2487609c1da9cc54"


class ArgusVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")

    def test_valid_vector_matches_shared_signature_and_compat_layer(self) -> None:
        signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        signed = signer.sign(VECTOR_REPORT)

        verification = verify_report(signed, self.trust_store)
        compat_verification = C3ReportVerifier(self.trust_store).verify(signed)

        self.assertEqual(signer.key_id, "s3-key")
        self.assertEqual(signed["signature"]["value"], EXPECTED_SIGNATURE)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.key_id, "s3-key")
        self.assertEqual(verification.claim_tier, "recapitulated-known")
        self.assertTrue(verification.aggregate_passed)
        self.assertEqual(compat_verification, verification)

    def test_archived_report_survives_key_rotation_and_new_report_uses_new_key(self) -> None:
        archived = sign_report(VECTOR_REPORT, key_id="s3-key", secret=b"s3-secret")
        self.trust_store.register_key("s3-key-v2", b"s3-secret-v2")
        current = sign_report(VECTOR_REPORT, key_id="s3-key-v2", secret=b"s3-secret-v2")

        archived_verification = verify_report(archived, self.trust_store)
        current_verification = verify_report(current, self.trust_store)

        self.assertTrue(archived_verification.valid)
        self.assertEqual(archived_verification.key_id, "s3-key")
        self.assertTrue(current_verification.valid)
        self.assertEqual(current_verification.key_id, "s3-key-v2")

    def test_tamper_unsigned_and_revoked_key_reject_with_stable_error_codes(self) -> None:
        signed = sign_report(VECTOR_REPORT, key_id="s3-key", secret=b"s3-secret")
        tampered = deepcopy(signed)
        tampered["checks"][0]["metrics"]["recovery_rate"] = 0.9800000000000001
        unsigned = deepcopy(signed)
        unsigned.pop("signature")

        tampered_verification = verify_report(tampered, self.trust_store)
        unsigned_verification = verify_report(unsigned, self.trust_store)
        self.trust_store.revoke_key("s3-key")
        revoked_verification = verify_report(signed, self.trust_store)

        self.assertFalse(tampered_verification.valid)
        self.assertEqual(tampered_verification.reason, "signature_invalid")
        self.assertEqual(tampered_verification.error_code, "SIGNATURE_INVALID")
        self.assertFalse(unsigned_verification.valid)
        self.assertEqual(unsigned_verification.reason, "signature_missing")
        self.assertEqual(unsigned_verification.error_code, "UNSIGNED")
        self.assertFalse(revoked_verification.valid)
        self.assertEqual(revoked_verification.reason, "revoked_key")
        self.assertEqual(revoked_verification.error_code, "REVOKED_KEY")

    def test_secretless_delegating_trust_store_requires_explicit_accept(self) -> None:
        signed = sign_report(VECTOR_REPORT, key_id="s3-key", secret=b"s3-secret")
        case = self

        class SecretlessDelegatingTrustStore:
            def get_key(self, key_id: str) -> VerifierKey | None:
                if key_id != "s3-key":
                    return None
                return VerifierKey(key_id=key_id, secret=b"")

            def verify_signature_value(
                self,
                *,
                key_id: str,
                report_with_empty_signature: dict[str, object],
                signature_value: str,
            ) -> str | None:
                case.assertEqual(key_id, "s3-key")
                case.assertEqual(report_with_empty_signature["signature"]["value"], "")
                if signature_value == signed["signature"]["value"]:
                    return SIGNATURE_VERIFICATION_ACCEPTED
                return "signature_invalid"

        valid = verify_report(signed, SecretlessDelegatingTrustStore())
        self.assertTrue(valid.valid)

        forged = deepcopy(signed)
        forged["signature"]["value"] = "hmac-sha256:bad"
        invalid = verify_report(forged, SecretlessDelegatingTrustStore())
        self.assertFalse(invalid.valid)
        self.assertEqual(invalid.error_code, "SIGNATURE_INVALID")

    def test_delegating_trust_store_abstain_falls_back_and_fails_closed(self) -> None:
        signed = sign_report(VECTOR_REPORT, key_id="s3-key", secret=b"s3-secret")
        case = self

        class AbstainingTrustStore:
            def __init__(self, delegation: str | None) -> None:
                self._delegation = delegation

            def get_key(self, key_id: str) -> VerifierKey | None:
                if key_id != "s3-key":
                    return None
                return VerifierKey(key_id=key_id, secret=b"")

            def verify_signature_value(
                self,
                *,
                key_id: str,
                report_with_empty_signature: dict[str, object],
                signature_value: str,
            ) -> str | None:
                case.assertEqual(key_id, "s3-key")
                case.assertEqual(report_with_empty_signature["signature"]["value"], "")
                case.assertEqual(signature_value, signed["signature"]["value"])
                return self._delegation

        for delegation in (None, SIGNATURE_VERIFICATION_ABSTAIN):
            with self.subTest(delegation=delegation):
                verification = verify_report(signed, AbstainingTrustStore(delegation))
                self.assertFalse(verification.valid)
                self.assertEqual(verification.reason, "signature_invalid")
                self.assertEqual(verification.error_code, "SIGNATURE_INVALID")

    def test_canonical_number_policy_matches_cross_language_boundaries(self) -> None:
        rendered = argusverify._canonical_json_text(
            {
                "integer_float": 1.0,
                "large_exponent": 1e21,
                "large_fixed": 1e20,
                "micro_signal": 0.000001,
                "negative_zero": -0.0,
                "tiny_signal": 0.0000001,
                "z_max": 3.0,
                "zero_float": 0.0,
            }
        )

        self.assertEqual(
            rendered,
            '{"integer_float":1,"large_exponent":1e21,"large_fixed":100000000000000000000,'
            '"micro_signal":0.000001,"negative_zero":0,"tiny_signal":1e-7,"z_max":3,"zero_float":0}',
        )
        with self.assertRaises(ValueError):
            argusverify._canonical_json_text({"bad": float("nan")})


if __name__ == "__main__":
    unittest.main()
