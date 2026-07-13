from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class CIWorkflowEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_m0_and_m1_evidence_stay_outside_the_checkout(self) -> None:
        m0_run = self._step("Run M0 spine battery")
        m0_upload = self._step("Upload M0 spine evidence")
        clean_checkout = self._step("Assert clean checkout before M1 referee battery")
        m1_run = self._step("Run M1 external S3 referee battery")
        m1_upload = self._step("Upload M1 external S3 referee evidence")

        self.assertIn('--evidence-file "$RUNNER_TEMP/m0-spine-evidence.json"', m0_run)
        self.assertIn("path: ${{ runner.temp }}/m0-spine-evidence.json", m0_upload)
        self.assertIn('run: test -z "$(git status --porcelain)"', clean_checkout)
        self.assertIn('--evidence-file "$RUNNER_TEMP/m1-external-referee-evidence.json"', m1_run)
        self.assertIn("path: ${{ runner.temp }}/m1-external-referee-evidence.json", m1_upload)

    def test_real_gvisor_job_is_pinned_unskippable_and_uploads_evidence(self) -> None:
        self.assertIn("  gvisor-security:\n", self.workflow)
        self.assertIn('GVISOR_RELEASE: "20260706"', self.workflow)
        self.assertIn("runsc.sha512", self.workflow)
        self.assertIn("runsc install --runtime runsc-argus -- --oci-seccomp", self.workflow)
        self.assertIn(
            'python3 scripts/run_s10_gvisor_battery.py --evidence-file "$RUNNER_TEMP/s10-gvisor-evidence.json"',
            self.workflow,
        )
        self.assertIn("name: s10-gvisor-evidence", self.workflow)
        self.assertNotIn("ARGUS_REQUIRE_GVISOR_TESTS", self.workflow)

    def _step(self, name: str) -> str:
        marker = f"      - name: {name}\n"
        start = self.workflow.index(marker)
        end = self.workflow.find("\n      - name:", start + len(marker))
        return self.workflow[start:] if end == -1 else self.workflow[start:end]


if __name__ == "__main__":
    unittest.main()
