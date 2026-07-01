from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import ErrorEnvelope, LifecyclePolicyError, LifecycleStore, build_error_envelope, error_behavior


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c1.subagent.schema.json"


class S1TypedErrorEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(schema)

    def test_retryable_error_requires_retry_after_and_validates_against_c1(self) -> None:
        envelope = build_error_envelope(
            category="RETRYABLE",
            code="TRANSIENT_ADAPTER",
            message="adapter unavailable",
            retry_after_seconds=30,
        )

        self.assertTrue(envelope.retryable)
        self.assertEqual(envelope.behavior.terminal_status, "RETRYING")
        self._assert_c1_payload_valid(envelope)

        with self.assertRaises(ValueError):
            build_error_envelope(
                category="RETRYABLE",
                code="TRANSIENT_ADAPTER",
                message="adapter unavailable",
            )

    def test_policy_and_sandbox_errors_are_non_retryable_quarantine_behavior(self) -> None:
        for category in ("POLICY", "SANDBOX"):
            with self.subTest(category=category):
                envelope = build_error_envelope(
                    category=category,
                    code=f"{category}_DENIED",
                    message="operation denied",
                )

                self.assertFalse(envelope.retryable)
                self.assertTrue(error_behavior(category).quarantine)
                self.assertEqual(envelope.behavior.terminal_status, "QUARANTINED")
                self._assert_c1_payload_valid(envelope)

                with self.assertRaises(ValueError):
                    ErrorEnvelope(
                        category=category,
                        code=f"{category}_DENIED",
                        message="operation denied",
                        retryable=True,
                        retry_after_seconds=1,
                    )

    def test_version_unsupported_maps_to_rejected_non_retryable_behavior(self) -> None:
        envelope = build_error_envelope(
            category="VERSION_UNSUPPORTED",
            code="VERSION_UNSUPPORTED",
            message="major version mismatch",
        )

        self.assertFalse(envelope.retryable)
        self.assertEqual(envelope.behavior.terminal_status, "REJECTED")
        self.assertFalse(envelope.behavior.quarantine)
        self._assert_c1_payload_valid(envelope)

    def test_lifecycle_policy_error_carries_typed_policy_envelope(self) -> None:
        store = LifecycleStore()
        store.create_job("job-1")

        with self.assertRaises(LifecyclePolicyError) as raised:
            store.apply_method("job-1", "build")

        envelope = raised.exception.envelope
        self.assertEqual(envelope.category, "POLICY")
        self.assertFalse(envelope.retryable)
        self.assertEqual(envelope.behavior.terminal_status, "QUARANTINED")
        self._assert_c1_payload_valid(envelope)

    def test_non_retryable_error_rejects_retry_after(self) -> None:
        with self.assertRaises(ValueError):
            build_error_envelope(
                category="PERMANENT",
                code="BAD_INPUT",
                message="input cannot be repaired",
                retry_after_seconds=5,
            )

    def _assert_c1_payload_valid(self, envelope: ErrorEnvelope) -> None:
        errors = sorted(self.validator.iter_errors(envelope.as_c1_payload()), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])


if __name__ == "__main__":
    unittest.main()
