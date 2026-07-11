from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts import run_m0_spine_battery as m0_battery
from scripts import run_m1_external_referee_battery as referee_battery


class M1ExternalRefereeBatteryTests(unittest.TestCase):
    def test_compose_environment_uses_preprovisioned_reference_service_tokens(self) -> None:
        service_tokens = {
            "m1-reference-s1": "s1-access-token",
            "m1-reference-s3": "s3-access-token",
            "m1-reference-s7": "s7-access-token",
            "m1-reference-s11": "s11-access-token",
        }

        with patch.object(referee_battery, "_m1_reference_service_access_tokens", return_value=service_tokens):
            environment = referee_battery._compose_environment(
                runtime_secrets=m0_battery._m0_runtime_secrets(),
                ports={"ARGUS_M0_S10_PORT": "18080"},
                now=1_700_000_000,
            )

        self.assertEqual(environment["ARGUS_S1_REFERENCE_DEMO_ACCESS_TOKEN"], service_tokens["m1-reference-s1"])
        self.assertEqual(environment["ARGUS_S3_REFERENCE_REFEREE_ACCESS_TOKEN"], service_tokens["m1-reference-s3"])
        self.assertEqual(environment["ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN"], service_tokens["m1-reference-s7"])
        self.assertEqual(
            environment["ARGUS_S11_REFERENCE_OBSERVATORY_ACCESS_TOKEN"],
            service_tokens["m1-reference-s11"],
        )
        self.assertNotEqual(
            environment["ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN"],
            environment["ARGUS_RUNTIME_BOOTSTRAP_TOKEN"],
        )

    def test_referee_post_uses_s1_runtime_bearer(self) -> None:
        requests = []

        class Response:
            status = 200

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
                return False

            def read(self) -> bytes:
                return b"{}"

        def open_request(request: object, *, timeout: float) -> Response:
            del timeout
            requests.append(request)
            return Response()

        with patch.object(referee_battery.urlrequest, "urlopen", side_effect=open_request):
            referee_battery._post_json(
                "http://referee.example/v1/reference-referee/validate",
                {"job_id": "m1-reference-job"},
                expected_status=200,
                token="s1-runtime-access-token",
            )

        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer s1-runtime-access-token")


if __name__ == "__main__":
    unittest.main()
