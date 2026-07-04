from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c1.subagent.schema.json"


class C1ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_exposes_canonical_public_payloads(self) -> None:
        definitions = self.schema["$defs"]

        for name in (
            "Acceptance",
            "Plan",
            "BuildResult",
            "ValidationRequest",
            "SubagentReport",
            "LifecycleEvent",
            "Heartbeat",
            "TypedError",
        ):
            self.assertIn(name, definitions)

        self.assertEqual(self.schema["x-argus-contract"], {"id": "C1", "owner": "S1", "version": "1.0.0"})
        self.assertIn("REJECTED", definitions["LifecycleState"]["enum"])
        self.assertNotIn("REFUSED", definitions["LifecycleState"]["enum"])

    def test_acceptance_accept_and_refuse_payloads_validate(self) -> None:
        accepted = {
            "job_id": self._uuid("1"),
            "accepted": True,
            "reason": None,
            "state": "ACCEPTED",
            "estimated_cost": {"cost_usd": 1.25, "gpu_seconds": 0},
            "plan_eta_seconds": 12,
            "idempotency_key": "accept-job-1",
        }
        refused = {
            "job_id": self._uuid("2"),
            "accepted": False,
            "reason": "NO_VERIFIER",
            "state": "REJECTED",
            "idempotency_key": "accept-job-2",
        }

        self._assert_valid(accepted)
        self._assert_valid(refused)

    def test_acceptance_rejects_inconsistent_refusal_state(self) -> None:
        payload = {
            "job_id": self._uuid("1"),
            "accepted": False,
            "reason": "NO_VERIFIER",
            "state": "ACCEPTED",
            "idempotency_key": "accept-job-1",
        }

        self._assert_invalid(payload)

    def test_lifecycle_event_validates_cancel_method_and_rejects_refused_state(self) -> None:
        event = {
            "event_id": self._uuid("3"),
            "job_id": self._uuid("4"),
            "root_request_id": self._uuid("5"),
            "seq": 4,
            "from_state": "BUILDING",
            "to_state": "CANCELLED",
            "method": "cancel",
            "trigger": "cancel",
            "payload_hash": "blake3:abc123",
            "trace_id": "trace-1",
            "idempotency_key": "cancel-job-4",
            "ledger_ref": "c4://artifact/s1-lifecycle-event",
        }
        bad_event = {**event, "to_state": "REFUSED"}

        self._assert_valid(event)
        self._assert_invalid(bad_event)

    def test_plan_build_validation_and_heartbeat_payloads_validate(self) -> None:
        plan = {
            "job_id": self._uuid("6"),
            "steps": [
                {
                    "step_id": "train",
                    "kind": "train",
                    "description": "Train baseline model",
                    "est_cost": {"cost_usd": 2.0},
                }
            ],
            "adapters_required": ["adapter:bounce-solver@1"],
            "datasets_required": ["c4://dataset/ewpt"],
            "verifier_profile_ref": "c4://profile/ewpt",
            "budget_breakdown": {"per_step": [{"cost_usd": 2.0}], "total": {"cost_usd": 2.0}},
            "risk_notes": ["extrapolation possible"],
            "plan_hash": "blake3:plan",
        }
        build = {
            "job_id": self._uuid("6"),
            "artifact_refs": ["c4://artifact/model"],
            "training_log_ref": "c4://artifact/log",
            "diagnostics": {"converged": True},
            "self_checks": [{"type": "PHYSICAL_CONSISTENCY", "status": "PASS", "advisory": True}],
            "uncertainty_summary": {"representation": "interval", "value": {"radius": 0.1}},
        }
        validation = {
            "job_id": self._uuid("6"),
            "frozen_pipeline_ref": "c4://artifact/pipeline",
            "artifact_refs": ["c4://artifact/model"],
            "profile_ref": "c4://profile/ewpt",
            "blind_dataset_handle": "blind:ewpt:heldout",
            "budget_token_ref": "budget-token-ref",
            "trace_id": "trace-1",
        }
        heartbeat = {
            "job_id": self._uuid("6"),
            "status": "BUILDING",
            "progress": 0.5,
            "spend_so_far": {"cost_usd": 1.0},
            "last_heartbeat_at": "2026-07-01T00:00:00Z",
        }

        for payload in (plan, build, validation, heartbeat):
            self._assert_valid(payload)

    def test_promoted_report_requires_validation_report_ref(self) -> None:
        report = {
            "job_id": self._uuid("7"),
            "subagent_id": "subagent-1",
            "status": "REPORTED",
            "claim_tier": "recapitulated-known",
            "artifact_refs": ["c4://artifact/model"],
            "cost_actual": {"cost_usd": 3.0},
            "reproducibility_manifest": {
                "lineage_ref": "c4://artifact/lineage",
                "environment_digest": "oci:sha256-example",
                "code_ref": "git:abc",
                "seeds": ["seed-1"],
            },
        }
        valid_report = {**report, "validation_report_ref": "c4://artifact/report"}

        self._assert_invalid(report)
        self._assert_valid(valid_report)

    def test_retryable_typed_error_requires_retry_after(self) -> None:
        retryable = {
            "category": "RETRYABLE",
            "code": "TRANSIENT_ADAPTER",
            "message": "adapter unavailable",
            "retryable": True,
            "retry_after_seconds": 30,
        }
        missing_retry_after = {key: value for key, value in retryable.items() if key != "retry_after_seconds"}

        self._assert_valid(retryable)
        self._assert_invalid(missing_retry_after)

    def _assert_valid(self, payload: dict) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def _assert_invalid(self, payload: dict) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertTrue(errors, msg=f"payload unexpectedly validated: {payload}")

    @staticmethod
    def _uuid(suffix: str) -> str:
        return f"11111111-1111-4111-8111-{int(suffix):012d}"


if __name__ == "__main__":
    unittest.main()
