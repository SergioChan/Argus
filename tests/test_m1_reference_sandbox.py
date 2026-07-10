from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from unittest.mock import patch

from argus_core import evaluate_sound_wave_spectrum
from argus_runtime.m1_reference_runtime import (
    REFERENCE_SANDBOX_AWK_PROGRAM,
    REFERENCE_SANDBOX_IMAGE,
    HttpS10SandboxLauncher,
    ReferenceS10SandboxSpecFactory,
)


class ReferenceS10SandboxSpecFactoryTests(unittest.TestCase):
    def test_digest_pinned_sandbox_runs_the_reference_spectrum_with_real_docker_isolation(self) -> None:
        docker = shutil.which("docker")
        if docker is None:
            if os.environ.get("ARGUS_REQUIRE_DOCKER_TESTS") == "1":
                self.fail("docker CLI is required when ARGUS_REQUIRE_DOCKER_TESTS=1")
            self.skipTest("docker CLI is unavailable")

        completed = subprocess.run(
            [
                docker,
                "run",
                "--rm",
                "--pull=never",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--user",
                "65532:65532",
                "--pids-limit",
                "8",
                "--memory",
                str(64 * 1024 * 1024),
                "--cpus",
                "0.250",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16777216",
                "--entrypoint",
                "awk",
                REFERENCE_SANDBOX_IMAGE,
                "-v",
                "tn=100",
                "-v",
                "alpha=0.2",
                "-v",
                "beta=100",
                "-v",
                "vw=0.7",
                "-v",
                "frequency=0.003",
                REFERENCE_SANDBOX_AWK_PROGRAM,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        actual = json.loads(completed.stdout)
        expected = evaluate_sound_wave_spectrum(
            temperature_gev=100.0,
            alpha=0.2,
            beta_over_h=100.0,
            wall_velocity=0.7,
            frequency_hz=0.003,
        )
        self.assertEqual(actual["omega"], expected.omega)
        self.assertEqual(actual["peak_omega"], expected.peak_omega)
        self.assertEqual(actual["peak_frequency"], expected.peak_frequency_hz)

    def test_mints_bound_tokens_and_emits_a_digest_pinned_no_network_compute_request(self) -> None:
        class Session:
            job_id = "m1-reference-job"

            def mint_budget(self) -> dict[str, object]:
                return {
                    "budget_id": "budget-m1",
                    "job_id": self.job_id,
                    "root_request_id": "m1-reference-root",
                    "budget_epoch": 1,
                    "caps": {
                        "max_compute_units": 10,
                        "max_gpu_seconds": 0,
                        "max_model_tokens": 0,
                        "max_wallclock_s": 30,
                        "max_cost_usd": 1,
                    },
                    "risk_class": "standard",
                    "issued_at": 1,
                    "expires_at": 601,
                    "ttl_s": 600,
                    "signer_key_id": "m1-root",
                    "signature": "ed25519:test",
                }

            def mint_scope(self) -> dict[str, object]:
                return {
                    "scope_id": "scope-m1",
                    "job_id": self.job_id,
                    "scopes": {
                        "allowed_adapters": ["gw_spectrum"],
                        "egress_allowlist": [{"host": "store.local", "port": 443, "proto": "https"}],
                        "broker_audiences": ["store"],
                        "capabilities": ["s8.read"],
                        "producer_subsystems": ["S1"],
                        "sandbox_risk_class": "standard",
                    },
                    "issued_at": 1,
                    "expires_at": 601,
                    "ttl_s": 600,
                    "signer_key_id": "m1-root",
                    "signature": "ed25519:test",
                }

        factory = ReferenceS10SandboxSpecFactory(session=Session())

        spec = factory(
            "m1-reference-job",
            {
                "T_n": {"value": 100.0},
                "alpha": {"value": 0.2},
                "beta_over_H": {"value": 100.0},
                "v_w": {"value": 0.7},
                "frequency": {"value": 0.003},
            },
        )

        request = spec["launch_request"]
        self.assertEqual(request.image, REFERENCE_SANDBOX_IMAGE)
        self.assertEqual(request.entrypoint, ("awk",))
        self.assertEqual(request.env, {})
        self.assertEqual(request.env_allowlist, ())
        self.assertEqual(request.requested_envelope.gpu_count, 0)
        self.assertEqual(request.requested_envelope.wallclock_s, 30)
        self.assertEqual(request.budget_token.job_id, "m1-reference-job")
        self.assertEqual(request.scope_token.job_id, "m1-reference-job")
        self.assertIn("omega", request.args[-1])

    def test_http_launcher_authenticates_and_rehydrates_a_real_s10_execution_result(self) -> None:
        class Session:
            job_id = "m1-reference-job"
            s10_url = "http://s10.example"
            access_token = "m1-access-token"
            timeout_s = 3.0

            def mint_budget(self) -> dict[str, object]:
                return {
                    "budget_id": "budget-m1",
                    "job_id": self.job_id,
                    "root_request_id": "m1-reference-root",
                    "budget_epoch": 4,
                    "caps": {
                        "max_compute_units": 10,
                        "max_gpu_seconds": 0,
                        "max_model_tokens": 0,
                        "max_wallclock_s": 30,
                        "max_cost_usd": 1,
                    },
                    "risk_class": "standard",
                    "issued_at": 1,
                    "expires_at": 601,
                    "ttl_s": 600,
                    "signer_key_id": "m1-root",
                    "signature": "ed25519:test",
                }

            def mint_scope(self) -> dict[str, object]:
                return {
                    "scope_id": "scope-m1",
                    "job_id": self.job_id,
                    "scopes": {
                        "allowed_adapters": ["gw_spectrum"],
                        "egress_allowlist": [{"host": "store.local", "port": 443, "proto": "https"}],
                        "broker_audiences": ["store"],
                        "capabilities": ["s8.read"],
                        "producer_subsystems": ["S1"],
                        "sandbox_risk_class": "standard",
                    },
                    "issued_at": 1,
                    "expires_at": 601,
                    "ttl_s": 600,
                    "signer_key_id": "m1-root",
                    "signature": "ed25519:test",
                }

        class Response:
            def __init__(self, body: dict[str, object]) -> None:
                self._body = json.dumps(body).encode("utf-8")

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
                return None

            def read(self) -> bytes:
                return self._body

        session = Session()
        request = ReferenceS10SandboxSpecFactory(session=session)(
            session.job_id,
            {
                "T_n": {"value": 100.0},
                "alpha": {"value": 0.2},
                "beta_over_H": {"value": 100.0},
                "v_w": {"value": 0.7},
                "frequency": {"value": 0.003},
            },
        )["launch_request"]
        captured: dict[str, object] = {}

        def urlopen(http_request: object, timeout: float) -> Response:
            captured["url"] = getattr(http_request, "full_url")
            captured["authorization"] = getattr(http_request, "get_header")("Authorization")
            captured["body"] = json.loads(getattr(http_request, "data").decode("utf-8"))
            captured["timeout"] = timeout
            return Response(
                {
                    "handle": {
                        "sandbox_id": "sandbox-m1",
                        "job_id": session.job_id,
                        "runtime_class": "docker",
                        "budget_epoch": 4,
                        "policy_bundle_version": "m1-policy",
                        "state": "SUCCEEDED",
                        "launch_provenance_ref": "c4://container/sandbox-m1",
                    },
                    "exit_code": 0,
                    "stdout": "{\\\"omega\\\":2.1267660025483526e-11}",
                    "stderr": "",
                    "timed_out": False,
                    "duration_s": 0.05,
                    "budget_usage": {
                        "compute_units": 0.0125,
                        "gpu_seconds": 0,
                        "model_tokens": 0,
                        "wallclock_s": 0.05,
                        "cost_usd": 0.0001,
                    },
                }
            )

        with patch("argus_runtime.m1_reference_runtime.urlrequest.urlopen", side_effect=urlopen):
            result = HttpS10SandboxLauncher(session=session).launch_and_wait(request)

        self.assertEqual(captured["url"], "http://s10.example/v1/sandboxes:launch")
        self.assertEqual(captured["authorization"], "Bearer m1-access-token")
        self.assertEqual(captured["timeout"], 3.0)
        self.assertEqual(captured["body"]["job_id"], session.job_id)
        self.assertEqual(result.handle.sandbox_id, "sandbox-m1")
        self.assertEqual(result.handle.launch_provenance_ref, "c4://container/sandbox-m1")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.budget_usage.wallclock_s, 0.05)


if __name__ == "__main__":
    unittest.main()
