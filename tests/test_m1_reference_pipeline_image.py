from __future__ import annotations

from subprocess import CompletedProcess
import unittest
from unittest.mock import patch

from scripts import run_m0_spine_battery as m0_battery


class M1ReferencePipelineImageTests(unittest.TestCase):
    def test_reference_s3_identity_has_budget_for_its_nested_s10_execution(self) -> None:
        identity = m0_battery._m0_identity_requests()["m1-reference-s3"]

        self.assertEqual(
            identity["budget_caps"],
            {
                "max_compute_units": 10,
                "max_wallclock_s": 30,
                "max_cost_usd": 1,
            },
        )

    def test_prepare_reference_pipeline_image_binds_the_built_compose_service_id(self) -> None:
        environment = {"ARGUS_S2_REFERENCE_PIPELINE_IMAGE": "sha256:" + "0" * 64}
        expected_image_id = "sha256:" + "a" * 64
        commands: list[list[str]] = []

        def run(command, *, env=None, timeout=60, check=True):
            del env, timeout, check
            commands.append(command)
            if command[-2:] == ["config", "--images"]:
                return CompletedProcess(
                    command,
                    0,
                    "\n".join(
                        (
                            "postgres@sha256:" + "1" * 64,
                            "argus-m0-s8-writer",
                            "argus-m0-s10-supervisor",
                            "argus-m0-s1-reference-demo",
                            "argus-m0-s2-reference-builder",
                            "argus-m0-s3-reference-referee",
                            "argus-m0-s7-reference-adapter",
                            "argus-m0-s11-reference-observatory",
                        )
                    )
                    + "\n",
                    "",
                )
            if command[:3] == ["docker", "image", "inspect"]:
                return CompletedProcess(command, 0, f"{expected_image_id}\n", "")
            return CompletedProcess(command, 0, "", "")

        with patch.object(m0_battery, "_run", side_effect=run):
            image_id = m0_battery._prepare_reference_pipeline_image(
                docker="docker",
                compose_file="deploy/argus-m0/compose.yaml",
                env=environment,
            )

        self.assertEqual(image_id, expected_image_id)
        self.assertEqual(environment["ARGUS_S2_REFERENCE_PIPELINE_IMAGE"], expected_image_id)
        self.assertEqual(
            commands,
            [
                [
                    "docker",
                    "compose",
                    "-f",
                    "deploy/argus-m0/compose.yaml",
                    "build",
                    "s3-reference-referee",
                ],
                [
                    "docker",
                    "compose",
                    "-f",
                    "deploy/argus-m0/compose.yaml",
                    "config",
                    "--images",
                ],
                ["docker", "image", "inspect", "--format", "{{.Id}}", "argus-m0-s3-reference-referee"],
                ["docker", "image", "tag", expected_image_id, "argus-m0-s8-writer"],
                ["docker", "image", "tag", expected_image_id, "argus-m0-s10-supervisor"],
                ["docker", "image", "tag", expected_image_id, "argus-m0-s1-reference-demo"],
                ["docker", "image", "tag", expected_image_id, "argus-m0-s2-reference-builder"],
                ["docker", "image", "tag", expected_image_id, "argus-m0-s7-reference-adapter"],
                ["docker", "image", "tag", expected_image_id, "argus-m0-s11-reference-observatory"],
            ],
        )


if __name__ == "__main__":
    unittest.main()
