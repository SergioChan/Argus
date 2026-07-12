from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts import run_m0_spine_battery as m0_battery
from scripts import run_m1_external_referee_battery as referee_battery


class M1ExternalRefereeBatteryTests(unittest.TestCase):
    def test_build_verify_cost_ratio_uses_positive_metered_costs(self) -> None:
        ratio = referee_battery._build_verify_cost_ratio(
            {"cost_usd": 0.05},
            {"cost_usd": 0.01},
        )

        self.assertEqual(
            ratio,
            {
                "build_cost_usd": 0.05,
                "verify_cost_usd": 0.01,
                "build_to_verify_cost_ratio": 5.0,
                "formula": "build_cost_usd / verify_cost_usd",
            },
        )
        with self.assertRaisesRegex(AssertionError, "positive"):
            referee_battery._build_verify_cost_ratio({"cost_usd": 0.05}, {"cost_usd": 0.0})

    def test_external_referee_uses_an_isolated_compose_project_name(self) -> None:
        project_name = referee_battery._isolated_compose_project_name()

        self.assertRegex(project_name, r"^argus-m1-external-referee-[0-9a-f]{12}$")

    def test_external_referee_rows_satisfy_the_s2_raw_and_scaled_input_contract(self) -> None:
        rows = referee_battery._reference_rows()

        self.assertEqual(len(rows), 16)
        canonical = rows[0]
        self.assertEqual(canonical["row_id"], "s7-reference-base")
        self.assertEqual(canonical["T_n"], 100.0)
        self.assertEqual(canonical["alpha"], 0.2)
        self.assertEqual(canonical["beta_over_H"], 100.0)
        self.assertEqual(canonical["v_w"], 0.7)
        self.assertEqual(canonical["frequency"], 0.003)
        self.assertEqual(
            [str(row["row_id"]) for row in rows[1:]],
            [f"s7-reference-{index:03d}" for index in range(1, 16)],
        )
        for row in rows:
            self.assertTrue(
                {
                    "T_n",
                    "alpha",
                    "beta_over_H",
                    "v_w",
                    "frequency",
                    "adapter_omega",
                    "omega",
                    "known_omega",
                    "adapter_omega_scaled",
                    "omega_scaled",
                }.issubset(row)
            )
            self.assertGreater(float(row["adapter_omega"]), 0.0)
            self.assertGreater(float(row["omega"]), 0.0)
            self.assertAlmostEqual(float(row["known_omega"]), float(row["omega"]))
            self.assertAlmostEqual(
                float(row["adapter_omega_scaled"]),
                float(row["adapter_omega"]) / referee_battery.S2_REFERENCE_OMEGA_SCALE,
            )
            self.assertAlmostEqual(
                float(row["omega_scaled"]),
                float(row["omega"]) / referee_battery.S2_REFERENCE_OMEGA_SCALE,
            )

    def test_compose_environment_uses_preprovisioned_reference_service_tokens(self) -> None:
        service_tokens = {
            "m1-reference-s1": "s1-access-token",
            "m1-reference-s2": "s2-access-token",
            "m1-reference-s3": "s3-access-token",
            "m1-reference-s7": "s7-access-token",
            "m1-reference-s11": "s11-access-token",
        }

        with patch.object(m0_battery, "_m1_reference_service_access_tokens", return_value=service_tokens):
            environment = referee_battery._compose_environment(
                runtime_secrets=m0_battery._m0_runtime_secrets(),
                ports={"ARGUS_M0_S10_PORT": "18080"},
                now=1_700_000_000,
            )

        self.assertEqual(environment["ARGUS_S1_REFERENCE_DEMO_ACCESS_TOKEN"], service_tokens["m1-reference-s1"])
        self.assertTrue(environment["ARGUS_S1_REFERENCE_DEMO_PILOT_ACCESS_TOKEN"])
        self.assertEqual(
            environment["ARGUS_S2_REFERENCE_BUILDER_ACCESS_TOKEN"],
            service_tokens["m1-reference-s2"],
        )
        self.assertEqual(environment["ARGUS_S3_REFERENCE_REFEREE_ACCESS_TOKEN"], service_tokens["m1-reference-s3"])
        self.assertEqual(environment["ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN"], service_tokens["m1-reference-s7"])
        self.assertEqual(
            environment["ARGUS_S11_REFERENCE_OBSERVATORY_ACCESS_TOKEN"],
            service_tokens["m1-reference-s11"],
        )
        self.assertEqual(environment["ARGUS_S2_REFERENCE_PIPELINE_IMAGE"], "sha256:" + "0" * 64)
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
