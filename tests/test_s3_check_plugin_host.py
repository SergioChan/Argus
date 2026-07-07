from __future__ import annotations

import json
import threading
import time
import unittest

from argus_core import (
    CheckPluginContext,
    CheckPluginDescriptor,
    CheckPluginHost,
    CheckPluginHostError,
    CheckResult,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
)


class _FakePlugin:
    def __init__(
        self,
        *,
        check: str,
        dependencies: tuple[str, ...] = (),
        calls: list[str] | None = None,
        result_status: str = "PASS",
        barrier: threading.Barrier | None = None,
        sleep_s: float = 0.0,
    ) -> None:
        self._check = check
        self._dependencies = dependencies
        self._calls = calls
        self._result_status = result_status
        self._barrier = barrier
        self._sleep_s = sleep_s

    def describe(self) -> CheckPluginDescriptor:
        return CheckPluginDescriptor(
            check=self._check,
            plugin_ref=f"argus.s3.plugins.{self._check.lower()}",
            plugin_version="1.0.0",
            dependencies=self._dependencies,
            determinism="deterministic",
        )

    def run(self, ctx: CheckPluginContext) -> CheckResult:
        if self._calls is not None:
            self._calls.append(f"{self._check}:start")
        if self._barrier is not None:
            self._barrier.wait(timeout=2.0)
        if self._sleep_s:
            time.sleep(self._sleep_s)
        metrics = {
            "dependency_checks": sorted(ctx.completed_results),
            "profile_ref": ctx.compiled_profile.profile_ref,
        }
        result = CheckResult(check=self._check, status=self._result_status, metrics=metrics)
        if self._calls is not None:
            self._calls.append(f"{self._check}:finish")
        return result


class S3CheckPluginHostTests(unittest.TestCase):
    def test_runs_independent_plugins_concurrently_then_dependent_and_writes_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        calls: list[str] = []
        barrier = threading.Barrier(2)
        profile = _compiled_profile(("INJECTION", "NULL_CONTROL", "CALIBRATION"))
        host = CheckPluginHost(
            plugins=(
                _FakePlugin(check="INJECTION", calls=calls, barrier=barrier, sleep_s=0.02),
                _FakePlugin(check="NULL_CONTROL", calls=calls, barrier=barrier, sleep_s=0.02),
                _FakePlugin(check="CALIBRATION", dependencies=("INJECTION", "NULL_CONTROL"), calls=calls),
            ),
            artifact_store=store,
            actor_id="s3-check-plugin-host-test",
            job_id="job-s3-t09",
        )

        results = host.run(profile)

        self.assertEqual([result.check for result in results], ["INJECTION", "NULL_CONTROL", "CALIBRATION"])
        self.assertEqual([result.status for result in results], ["PASS", "PASS", "PASS"])
        self.assertLess(calls.index("INJECTION:start"), calls.index("CALIBRATION:start"))
        self.assertLess(calls.index("NULL_CONTROL:start"), calls.index("CALIBRATION:start"))
        self.assertEqual(set(results[2].metrics["dependency_checks"]), {"INJECTION", "NULL_CONTROL"})
        for result in results:
            self.assertIsNotNone(result.evidence_ref)
            self.assertEqual(result.plugin_version, "1.0.0")
            record = store.get_record(result.evidence_ref)
            self.assertEqual(record.kind, "s3_check_result")
            payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
            self.assertEqual(payload["schema"], "argus.s3.check_result_evidence.v1")
            self.assertEqual(payload["check"], result.check)
            self.assertEqual(payload["status"], result.status)
            self.assertEqual(payload["plugin_ref"], f"argus.s3.plugins.{result.check.lower()}")
            self.assertEqual(payload["profile_ref"], profile.profile_ref)

    def test_missing_plugin_is_rejected_before_any_execution(self) -> None:
        calls: list[str] = []
        host = CheckPluginHost(
            plugins=(_FakePlugin(check="INJECTION", calls=calls),),
            artifact_store=InMemoryArtifactStore(),
        )

        with self.assertRaises(CheckPluginHostError) as raised:
            host.run(_compiled_profile(("INJECTION", "NULL_CONTROL")))

        self.assertEqual(raised.exception.category, "VERIFIER_UNAVAILABLE")
        self.assertEqual(raised.exception.code, "CHECK_PLUGIN_UNAVAILABLE")
        self.assertTrue(raised.exception.before_execution)
        self.assertEqual(calls, [])

    def test_duplicate_compiled_checks_are_rejected_before_execution(self) -> None:
        calls: list[str] = []
        host = CheckPluginHost(
            plugins=(_FakePlugin(check="INJECTION", calls=calls),),
            artifact_store=InMemoryArtifactStore(),
        )

        with self.assertRaises(CheckPluginHostError) as raised:
            host.run(_compiled_profile(("INJECTION", "INJECTION")))

        self.assertEqual(raised.exception.code, "CHECK_PLUGIN_DUPLICATE_CHECK")
        self.assertTrue(raised.exception.before_execution)
        self.assertEqual(calls, [])

    def test_dependency_cycle_is_rejected_before_execution(self) -> None:
        calls: list[str] = []
        host = CheckPluginHost(
            plugins=(
                _FakePlugin(check="INJECTION", dependencies=("NULL_CONTROL",), calls=calls),
                _FakePlugin(check="NULL_CONTROL", dependencies=("INJECTION",), calls=calls),
            ),
            artifact_store=InMemoryArtifactStore(),
        )

        with self.assertRaises(CheckPluginHostError) as raised:
            host.run(_compiled_profile(("INJECTION", "NULL_CONTROL")))

        self.assertEqual(raised.exception.code, "CHECK_PLUGIN_DEPENDENCY_CYCLE")
        self.assertTrue(raised.exception.before_execution)
        self.assertEqual(calls, [])

    def test_dependency_failure_prevents_downstream_plugin_and_preserves_partial_evidence(self) -> None:
        calls: list[str] = []
        store = InMemoryArtifactStore()
        host = CheckPluginHost(
            plugins=(
                _FakePlugin(check="INJECTION", calls=calls, result_status="FAIL"),
                _FakePlugin(check="NULL_CONTROL", dependencies=("INJECTION",), calls=calls),
            ),
            artifact_store=store,
        )

        with self.assertRaises(CheckPluginHostError) as raised:
            host.run(_compiled_profile(("INJECTION", "NULL_CONTROL")))

        self.assertEqual(raised.exception.code, "CHECK_PLUGIN_DEPENDENCY_FAILED")
        self.assertFalse(raised.exception.before_execution)
        self.assertEqual(calls, ["INJECTION:start", "INJECTION:finish"])
        self.assertEqual(len(raised.exception.partial_results), 1)
        partial = raised.exception.partial_results[0]
        self.assertEqual(partial.check, "INJECTION")
        self.assertEqual(partial.status, "FAIL")
        self.assertIsNotNone(partial.evidence_ref)
        self.assertEqual(store.get_record(partial.evidence_ref).kind, "s3_check_result")


def _compiled_profile(checks: tuple[str, ...]) -> CompiledProfile:
    return CompiledProfile(
        profile_id="s3-t09-test",
        revision=1,
        profile_ref="c4://profile/s3-t09-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t09",
        public_profile={"profile_id": "s3-t09-test", "revision": 1, "checks": list(checks)},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=tuple(_check_spec(check) for check in checks),
        independence_policy={},
        determinism_profile={},
    )


def _check_spec(check: str) -> CompiledCheckSpec:
    return CompiledCheckSpec(
        check=check,
        plugin_ref=f"argus.s3.plugins.{check.lower()}",
        plugin_version="1.0.0",
        mandatory=True,
        thresholds={},
        determinism="deterministic",
        seed=None,
        tolerance={},
        requires_independence=False,
        budget={},
        adapter=None,
    )


if __name__ == "__main__":
    unittest.main()
