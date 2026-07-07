from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

import argus_core.s3 as s3_module
from argus_core import (
    C3ReportSigner,
    ReportCanonicalizationError,
    S3_REPORT_CANONICALIZATION_SPEC_VERSION,
    canonical_validation_report_bytes,
    canonicalize_validation_report,
    validation_report_digest,
)


VECTOR_REPORT = {
    "report_id": "44444444-4444-4444-8444-444444444444",
    "profile_ref": "c4://profile/s3-t04/v1",
    "frozen_pipeline_ref": "c4://pipeline/s3-t04/baseline",
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
            "evidence_refs": ["c4://evidence/s3-t04/injection"],
        },
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
    "debate_ref": "c4://debate/s3-t04/example",
}

EXPECTED_REPORT_DIGEST = "blake3:8fd3f9d35518bc050b2397b9465a36b9782623f3219725d5549e48dbdb19e870"
EXPECTED_SIGNING_PAYLOAD_DIGEST = "blake3:2509b35cad7d6ad4795bf4ddc5d6fac8ebbf3bc464d8c738a2d0a86c3e5212cb"


class S3ReportCanonicalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.report = self.signer.sign(VECTOR_REPORT)

    def test_report_canonical_bytes_and_digest_are_stable_golden_vectors(self) -> None:
        shuffled = _reverse_nested_mappings(self.report)

        canonical = canonicalize_validation_report(self.report)
        repeated = canonicalize_validation_report(shuffled)

        self.assertEqual(canonical.spec_version, S3_REPORT_CANONICALIZATION_SPEC_VERSION)
        self.assertEqual(canonical.hash_algorithm, "BLAKE3")
        self.assertEqual(canonical.canonical_bytes, repeated.canonical_bytes)
        self.assertEqual(canonical.digest, repeated.digest)
        self.assertEqual(canonical.digest, EXPECTED_REPORT_DIGEST)
        self.assertEqual(canonical.signing_payload_digest, EXPECTED_SIGNING_PAYLOAD_DIGEST)
        self.assertEqual(canonical_validation_report_bytes(self.report), canonical.canonical_bytes)
        self.assertEqual(validation_report_digest(self.report), canonical.digest)
        self.assertNotIn(b" ", canonical.canonical_bytes)
        self.assertIn(b'"integer_float":1', canonical.canonical_bytes)
        self.assertIn(b'"large_fixed":100000000000000000000', canonical.canonical_bytes)
        self.assertIn(b'"tiny_signal":1e-7', canonical.canonical_bytes)

    def test_signing_payload_digest_excludes_signature_value_but_report_digest_includes_it(self) -> None:
        canonical = canonicalize_validation_report(self.report)
        tampered_signature = deepcopy(self.report)
        tampered_signature["signature"]["value"] = "hmac-sha256:" + "0" * 64

        tampered = canonicalize_validation_report(tampered_signature)

        self.assertEqual(canonical.signing_payload["signature"]["value"], "")
        self.assertEqual(tampered.signing_payload["signature"]["value"], "")
        self.assertEqual(canonical.signing_payload_digest, tampered.signing_payload_digest)
        self.assertNotEqual(canonical.digest, tampered.digest)

    def test_schema_invalid_report_fails_before_hashing(self) -> None:
        invalid = deepcopy(self.report)
        invalid["unexpected"] = "not allowed by C3 ValidationReport"

        with self.assertRaises(ReportCanonicalizationError) as raised:
            canonicalize_validation_report(invalid)

        self.assertEqual(raised.exception.code, "S3_REPORT_SCHEMA_INVALID")
        self.assertIsNone(raised.exception.digest)

    def test_non_finite_numbers_fail_closed_before_hashing(self) -> None:
        invalid = deepcopy(self.report)
        invalid["checks"][0]["metrics"]["bad"] = float("nan")

        with self.assertRaises(ReportCanonicalizationError) as raised:
            canonicalize_validation_report(invalid)

        self.assertEqual(raised.exception.code, "S3_REPORT_JSON_INVALID")
        self.assertIsNone(raised.exception.digest)

    def test_schema_root_env_is_honored_in_packaged_runtime_layout(self) -> None:
        schema_source = Path(__file__).resolve().parents[1] / "schemas" / "contracts" / "c3.validation-report.schema.json"
        old_root = os.environ.get("ARGUS_SCHEMA_ROOT")
        old_cwd = Path.cwd()
        with TemporaryDirectory() as tmp, TemporaryDirectory() as cwd:
            schema_root = Path(tmp) / "schemas"
            (schema_root / "contracts").mkdir(parents=True)
            shutil.copy2(schema_source, schema_root / "contracts" / "c3.validation-report.schema.json")
            os.environ["ARGUS_SCHEMA_ROOT"] = str(schema_root)
            os.chdir(cwd)
            s3_module._c3_validation_report_validator.cache_clear()
            s3_module._c3_verifier_profile_validator.cache_clear()
            try:
                self.assertEqual(canonicalize_validation_report(self.report).digest, EXPECTED_REPORT_DIGEST)
            finally:
                os.chdir(old_cwd)
                if old_root is None:
                    os.environ.pop("ARGUS_SCHEMA_ROOT", None)
                else:
                    os.environ["ARGUS_SCHEMA_ROOT"] = old_root
                s3_module._c3_validation_report_validator.cache_clear()
                s3_module._c3_verifier_profile_validator.cache_clear()


def _reverse_nested_mappings(value):
    if isinstance(value, dict):
        return {key: _reverse_nested_mappings(value[key]) for key in reversed(value)}
    if isinstance(value, list):
        return [_reverse_nested_mappings(item) for item in value]
    return value


if __name__ == "__main__":
    unittest.main()
