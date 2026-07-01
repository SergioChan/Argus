from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from argus_core import (
    ADDITIVE_MINOR,
    BREAKING_MAJOR,
    SubagentDescriptor,
    assert_schema_version_declares_change,
    classify_json_schema_change,
    default_accept,
    parse_job_envelope,
)


ROOT = Path(__file__).resolve().parents[1]


class S1SchemaCompatibilityGateTests(unittest.TestCase):
    def test_s1_tc_09_minor_additive_field_is_ignored(self) -> None:
        descriptor = SubagentDescriptor(
            subagent_id="subagent-1",
            contract_version="1.2.0",
            subtopics=("ewpt",),
            required_adapters=("adapter:bounce",),
        )
        envelope = parse_job_envelope(
            {
                "job_id": "job-minor",
                "envelope_version": "1.4.0",
                "subtopic": "ewpt",
                "required_adapters": ["adapter:bounce"],
                "allowed_adapters": ["adapter:bounce"],
                "verifier_profile_ref": "c4://profile/ewpt/v1",
                "estimated_cost": 1,
                "budget_cost": 2,
                "future_optional_field": {"ignored": True},
            }
        )

        acceptance = default_accept(descriptor, envelope)

        self.assertTrue(acceptance.accepted)
        self.assertFalse(hasattr(envelope, "future_optional_field"))

    def test_s1_tc_10_major_version_is_refused(self) -> None:
        descriptor = SubagentDescriptor(
            subagent_id="subagent-1",
            contract_version="1.2.0",
            subtopics=("ewpt",),
        )
        envelope = parse_job_envelope(
            {
                "job_id": "job-major",
                "envelope_version": "2.0.0",
                "subtopic": "ewpt",
                "verifier_profile_ref": "c4://profile/ewpt/v1",
            }
        )

        acceptance = default_accept(descriptor, envelope)

        self.assertFalse(acceptance.accepted)
        self.assertEqual(acceptance.reason, "VERSION_UNSUPPORTED")

    def test_additive_schema_change_requires_minor_or_higher_bump(self) -> None:
        old_schema = self._schema(
            properties={
                "job_id": {"type": "string"},
            },
            required=["job_id"],
        )
        new_schema = self._schema(
            properties={
                "job_id": {"type": "string"},
                "trace_id": {"type": "string", "default": ""},
            },
            required=["job_id"],
        )

        result = classify_json_schema_change(old_schema, new_schema)

        self.assertEqual(result.classification, ADDITIVE_MINOR)
        assert_schema_version_declares_change(
            old_version="1.0.0",
            new_version="1.1.0",
            classification=result.classification,
        )

    def test_s1_tc_11_removed_required_field_fails_minor_only_publish(self) -> None:
        old_schema = self._schema(
            properties={
                "job_id": {"type": "string"},
                "subtopic": {"type": "string"},
            },
            required=["job_id", "subtopic"],
        )
        new_schema = self._schema(
            properties={
                "subtopic": {"type": "string"},
            },
            required=["subtopic"],
        )
        result = classify_json_schema_change(old_schema, new_schema)
        self.assertEqual(result.classification, BREAKING_MAJOR)

        with tempfile.TemporaryDirectory() as tmp:
            old_path = Path(tmp) / "old.schema.json"
            new_path = Path(tmp) / "new.schema.json"
            old_path.write_text(json.dumps(old_schema), encoding="utf-8")
            new_path.write_text(json.dumps(new_schema), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/schema_compatibility.py",
                    "--old",
                    str(old_path),
                    "--new",
                    str(new_path),
                    "--old-version",
                    "1.0.0",
                    "--new-version",
                    "1.1.0",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        payload = json.loads(completed.stdout)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(payload["allowed"])
        self.assertEqual(payload["classification"], BREAKING_MAJOR)

    @staticmethod
    def _schema(*, properties: dict[str, object], required: list[str]) -> dict[str, object]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": required,
        }


if __name__ == "__main__":
    unittest.main()
