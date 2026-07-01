from __future__ import annotations

import json
from pathlib import Path
import unittest

from argus_core import (
    BREAKING_MAJOR,
    C2ContractError,
    C2MigrationWindow,
    C2VersionPolicy,
    classify_json_schema_change,
    parse_c2_job_envelope,
    schema_version_declares_change,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c2.job-envelope.schema.json"
EXAMPLE_PATH = ROOT / "schemas" / "contracts" / "examples" / "c2.example.json"


class C2VersionMigrationPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))

    def test_default_policy_rejects_cross_major_contract_version(self) -> None:
        with self.assertRaises(C2ContractError) as raised:
            parse_c2_job_envelope(self._payload("1.8.0"), runtime_version="2.0.0")

        self.assertEqual(raised.exception.error.category, "PERMANENT")
        self.assertEqual(raised.exception.error.code, "VERSION_UNSUPPORTED")

    def test_two_c2_majors_are_served_during_migration_window(self) -> None:
        policy = C2VersionPolicy(
            migration_windows=[
                C2MigrationWindow(legacy_major=1, runtime_major=2, opens_at=100, hard_cutoff_at=200)
            ]
        )

        legacy = parse_c2_job_envelope(
            self._payload("1.8.0"),
            runtime_version="2.0.0",
            version_policy=policy,
            now=150,
        )
        current = parse_c2_job_envelope(
            {**self._payload("2.1.0"), "future_scheduler_hint": {"ignored": True}},
            runtime_version="2.0.0",
            version_policy=policy,
            now=150,
        )

        self.assertEqual(legacy.contract_version, "1.8.0")
        self.assertEqual(current.contract_version, "2.1.0")
        self.assertEqual(legacy.job_id, self.example["job_id"])
        self.assertFalse(hasattr(current, "future_scheduler_hint"))

    def test_legacy_major_is_rejected_before_migration_window_opens(self) -> None:
        policy = C2VersionPolicy(
            migration_windows=(
                C2MigrationWindow(legacy_major=1, runtime_major=2, opens_at=100, hard_cutoff_at=200),
            )
        )

        with self.assertRaises(C2ContractError) as raised:
            parse_c2_job_envelope(
                self._payload("1.8.0"),
                runtime_version="2.0.0",
                version_policy=policy,
                now=99,
            )

        self.assertEqual(raised.exception.error.category, "PERMANENT")
        self.assertEqual(raised.exception.error.code, "VERSION_UNSUPPORTED")

    def test_legacy_major_is_rejected_at_hard_cutoff(self) -> None:
        policy = C2VersionPolicy(
            migration_windows=(
                C2MigrationWindow(legacy_major=1, runtime_major=2, opens_at=100, hard_cutoff_at=200),
            )
        )

        with self.assertRaises(C2ContractError) as raised:
            parse_c2_job_envelope(
                self._payload("1.8.0"),
                runtime_version="2.0.0",
                version_policy=policy,
                now=200,
            )

        self.assertEqual(raised.exception.error.category, "PERMANENT")
        self.assertEqual(raised.exception.error.code, "VERSION_UNSUPPORTED")

    def test_invalid_migration_window_shape_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            C2MigrationWindow(legacy_major=2, runtime_major=2)
        with self.assertRaises(ValueError):
            C2MigrationWindow(legacy_major=1, runtime_major=2, opens_at=100, hard_cutoff_at=100)

    def test_breaking_c2_schema_change_requires_major_bump(self) -> None:
        old_schema = self.schema["$defs"]["JobEnvelope"]
        new_schema = json.loads(json.dumps(old_schema))
        new_schema["properties"].pop("budget")
        new_schema["required"] = [field for field in new_schema["required"] if field != "budget"]

        result = classify_json_schema_change(old_schema, new_schema)

        self.assertEqual(result.classification, BREAKING_MAJOR)
        self.assertFalse(
            schema_version_declares_change(
                old_version="1.0.0",
                new_version="1.1.0",
                classification=result.classification,
            )
        )

    def _payload(self, contract_version: str) -> dict:
        return {**self.example, "contract_version": contract_version}


if __name__ == "__main__":
    unittest.main()
