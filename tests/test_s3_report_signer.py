from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    InMemoryS10KmsVerifierKeyProvider,
    S10VerifierTrustStoreClient,
    canonicalize_validation_report,
)
from argus_runtime.s3_report_signer_service import (
    RustS3ReportSigner,
    S3ReportSigningError,
)


ROOT = Path(__file__).resolve().parents[1]
RUST_SIGNER_COMMAND = (
    "cargo",
    "run",
    "--quiet",
    "--manifest-path",
    str(ROOT / "bindings/rust/Cargo.toml"),
    "--bin",
    "argus-s3-report-signer",
)


UNSIGNED_REPORT = {
    "report_id": "55555555-5555-4555-8555-555555555555",
    "profile_ref": "c4://profile/s3-t05/v1",
    "frozen_pipeline_ref": "c4://pipeline/s3-t05/baseline",
    "checks": [
        {"check": "INJECTION", "status": "PASS", "metrics": {"recovery_rate": 0.98}},
        {"check": "NULL_CONTROL", "status": "PASS"},
        {"check": "PHYSICAL_CONSISTENCY", "status": "PASS"},
        {"check": "CALIBRATION", "status": "PASS"},
    ],
    "aggregate": {"passed": True, "score": 1.0},
    "claim_tier": "recapitulated-known",
    "claim_tier_is_candidate": False,
    "perturbation_pairs": [
        {
            "perturbation_id": "pair-1",
            "kind": "must_react",
            "verdict": "pass",
            "amplitude_linearity": {"expected": 1.0, "observed": 0.99},
        },
        {
            "perturbation_id": "pair-1",
            "kind": "must_not_react",
            "verdict": "pass",
            "observed_degradation": {"observed_signal": 0.0, "absolute_tolerance": 0.05},
        },
    ],
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
    "debate_ref": "c4://debate/s3-t05/example",
}


class S3ReportSignerTests(unittest.TestCase):
    def test_rust_signer_service_signs_canonical_report_without_exposing_secret(self) -> None:
        signer = RustS3ReportSigner(
            command=RUST_SIGNER_COMMAND,
            key_id="s3-key",
            environment=_signer_environment(secret="s3-secret"),
        )

        result = signer.sign(UNSIGNED_REPORT)

        expected = C3ReportSigner(key_id="s3-key", secret=b"s3-secret").sign(UNSIGNED_REPORT)
        self.assertEqual(result.signed_report["signature"]["value"], expected["signature"]["value"])
        self.assertEqual(result.signature_value, expected["signature"]["value"])
        self.assertEqual(result.key_id, "s3-key")
        self.assertEqual(result.algorithm, "hmac-sha256")
        self.assertEqual(result.provider, "rust-local-vault")
        self.assertFalse(result.secret_exposed)
        self.assertNotIn("s3-secret", json.dumps(result.asdict(), sort_keys=True))

        provider = InMemoryS10KmsVerifierKeyProvider()
        provider.register_verifier_key("s3-key", b"s3-secret")
        verification = C3ReportVerifier(S10VerifierTrustStoreClient(provider)).verify(result.signed_report)
        self.assertTrue(verification.valid)
        self.assertEqual(canonicalize_validation_report(result.signed_report).signing_payload["signature"]["value"], "")

    def test_rust_signer_fails_closed_for_revoked_key(self) -> None:
        signer = RustS3ReportSigner(
            command=RUST_SIGNER_COMMAND,
            key_id="s3-key",
            environment=_signer_environment(secret="s3-secret", revoked=True),
        )

        with self.assertRaises(S3ReportSigningError) as raised:
            signer.sign(UNSIGNED_REPORT)

        self.assertEqual(raised.exception.code, "S3_SIGNER_KEY_REVOKED")
        self.assertIsNone(raised.exception.signed_report)

    def test_signer_client_rejects_mismatched_key_response(self) -> None:
        fake_signed = C3ReportSigner(key_id="wrong-key", secret=b"s3-secret").sign(UNSIGNED_REPORT)
        fake_response = {
            "request_id": "req-1",
            "provider": "fake",
            "key_id": "wrong-key",
            "algorithm": "hmac-sha256",
            "signature_value": fake_signed["signature"]["value"],
            "signed_report": fake_signed,
            "secret_exposed": False,
        }
        command = (
            sys.executable,
            "-c",
            "import json; print(json.dumps(%r))" % fake_response,
        )
        signer = RustS3ReportSigner(command=command, key_id="s3-key", environment={})

        with self.assertRaises(S3ReportSigningError) as raised:
            signer.sign(UNSIGNED_REPORT)

        self.assertEqual(raised.exception.code, "S3_SIGNER_KEY_MISMATCH")

    def test_rust_signer_does_not_accept_secret_material_in_request(self) -> None:
        request = {
            "request_id": "req-secret-in-request",
            "key_id": "s3-key",
            "report": deepcopy(UNSIGNED_REPORT),
            "secret": "s3-secret",
        }
        env = os.environ.copy()
        env.pop("ARGUS_S3_SIGNER_KEYS_JSON", None)
        env.pop("ARGUS_S3_SIGNER_KEY_FILE", None)

        completed = subprocess.run(
            RUST_SIGNER_COMMAND,
            input=json.dumps(request),
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("vault key material", completed.stderr)

        nested_request = {
            "request_id": "req-nested-secret-in-request",
            "key_id": "s3-key",
            "report": {
                **deepcopy(UNSIGNED_REPORT),
                "referee": {
                    **deepcopy(UNSIGNED_REPORT["referee"]),
                    "private_key": "s3-secret",
                },
            },
        }
        nested_completed = subprocess.run(
            RUST_SIGNER_COMMAND,
            input=json.dumps(nested_request),
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

        self.assertNotEqual(nested_completed.returncode, 0)
        self.assertIn("vault key material", nested_completed.stderr)


def _signer_environment(*, secret: str, revoked: bool = False) -> dict[str, str]:
    return {
        "ARGUS_S3_SIGNER_KEYS_JSON": json.dumps(
            {
                "provider": "rust-local-vault",
                "keys": [
                    {
                        "key_id": "s3-key",
                        "secret": secret,
                        "revoked": revoked,
                    }
                ],
            }
        )
    }


if __name__ == "__main__":
    unittest.main()
