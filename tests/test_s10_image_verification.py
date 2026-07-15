from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from argus_core import (
    BudgetCaps,
    CosignImageVerifier,
    ImageVerificationError,
    ImageVerifierUnavailableError,
    InMemoryAuditLedger,
    InMemoryImageVerifier,
    InMemoryQuotaLedger,
    InMemorySandboxOrchestrator,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyDeniedError,
    ResourceCeilings,
    SandboxRuntimeUnavailableError,
    ScopeGrant,
    cosign_signature_store_path,
)
from argus_runtime.s10_supervisor_service import _image_verifier_from_env


SIGNED_IMAGE = "registry.local/argus/runtime@sha256:" + "a" * 64
UNSIGNED_IMAGE = "registry.local/argus/unsigned@sha256:" + "b" * 64
TAG_ONLY_IMAGE = "registry.local/argus/runtime:latest"
COSIGN_VERSION = "v2.6.3"


class S10ImageAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tokens = InMemoryTokenService(signing_key=b"image-admission-test", now_fn=lambda: 1_000)
        self.quota = InMemoryQuotaLedger()
        self.audit = InMemoryAuditLedger()
        self.policy = PolicyBundle(
            bundle_version="1.0.0",
            egress_allowlist=(),
            resource_ceilings=ResourceCeilings(
                cpu_m=1_000,
                mem_bytes=512 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=30,
                max_cost_usd=1,
            ),
            risk_to_runtime={"standard": "docker"},
            seccomp_profile_hash="blake3:" + "c" * 64,
            signer_key_id="test-policy",
            signature="test-signature",
        )

    def test_missing_verifier_fails_closed_before_quota_or_launch(self) -> None:
        orchestrator = self._orchestrator()
        request = self._request(SIGNED_IMAGE)

        with self.assertRaisesRegex(SandboxRuntimeUnavailableError, "image verifier is not configured"):
            orchestrator.launch(request)

        self._assert_no_quota_or_launch(request)
        failure = self.audit.events()[-1]
        self.assertEqual(failure.event_type, "image.verify_fail")
        self.assertEqual(failure.payload["reason_code"], "verifier_unconfigured")

    def test_tag_only_and_unsigned_images_are_policy_denied_before_quota(self) -> None:
        orchestrator = self._orchestrator(
            image_verifier=InMemoryImageVerifier(trusted_images=(SIGNED_IMAGE,)),
        )

        tag_request = self._request(TAG_ONLY_IMAGE, job_id="job-tag-only")
        with self.assertRaisesRegex(PolicyDeniedError, "digest_required"):
            orchestrator.launch(tag_request)
        self._assert_no_quota_or_launch(tag_request)
        self.assertEqual(self.audit.events()[-1].payload["reason_code"], "digest_required")

        unsigned_request = self._request(UNSIGNED_IMAGE, job_id="job-unsigned")
        with self.assertRaisesRegex(PolicyDeniedError, "signature_not_found"):
            orchestrator.launch(unsigned_request)
        self._assert_no_quota_or_launch(unsigned_request)
        self.assertEqual(self.audit.events()[-1].payload["reason_code"], "signature_not_found")

    def test_verified_image_evidence_is_audited_before_quota_and_launch(self) -> None:
        orchestrator = self._orchestrator(
            image_verifier=InMemoryImageVerifier(trusted_images=(SIGNED_IMAGE,)),
        )
        request = self._request(SIGNED_IMAGE)

        handle = orchestrator.launch(request)

        event_types = [event.event_type for event in self.audit.events()]
        self.assertLess(event_types.index("image.verified"), event_types.index("sandbox.launched"))
        verification = next(event for event in self.audit.events() if event.event_type == "image.verified")
        self.assertEqual(verification.payload["manifest_digest"], "sha256:" + "a" * 64)
        self.assertEqual(verification.payload["image_identity"], "registry.local/argus/runtime")
        self.assertEqual(verification.payload["verifier_kind"], "in-memory-test")
        self.assertEqual(handle.state, "ADMITTED")
        self.assertGreater(self.quota.state(request.budget_token.budget_id).reserved.wallclock_s, 0)

    def _orchestrator(self, *, image_verifier=None) -> InMemorySandboxOrchestrator:
        kwargs = {}
        if image_verifier is not None:
            kwargs["image_verifier"] = image_verifier
        return InMemorySandboxOrchestrator(
            token_service=self.tokens,
            quota_ledger=self.quota,
            audit_ledger=self.audit,
            policy_bundle=self.policy,
            **kwargs,
        )

    def _request(self, image: str, *, job_id: str = "job-signed") -> LaunchRequest:
        budget = self.tokens.mint_budget(
            caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=1),
            job_id=job_id,
            root_request_id=f"root-{job_id}",
        )
        scope = self.tokens.mint_scope(job_id=job_id, scopes=ScopeGrant(sandbox_risk_class="standard"))
        return LaunchRequest(
            job_id=job_id,
            subagent_id="image-admission-test",
            trace_id=f"trace-{job_id}",
            budget_token=budget,
            scope_token=scope,
            image=image,
            entrypoint=("sh",),
            args=("-c", "true"),
            env={},
            env_allowlist=(),
            requested_envelope=LaunchEnvelope(
                cpu_m=100,
                mem_bytes=32 * 1024 * 1024,
                gpu_count=0,
                wallclock_s=2,
                scratch_bytes=1024 * 1024,
                pids=8,
                estimated_cost_usd=0.01,
            ),
        )

    def _assert_no_quota_or_launch(self, request: LaunchRequest) -> None:
        with self.assertRaises(KeyError):
            self.quota.state(request.budget_token.budget_id)
        self.assertNotIn("sandbox.launched", [event.event_type for event in self.audit.events()])


class CosignImageVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="argus-cosign-unit-")
        self.root = Path(self.temp.name)
        self.public_key = self.root / "cosign.pub"
        self.public_key.write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        self.signature_store = self.root / "signatures"
        self.signature_store.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_valid_cosign_payload_is_bound_to_identity_and_digest(self) -> None:
        cosign = self._fake_cosign(verify_output="Verified OK")
        self._write_signature_entry(SIGNED_IMAGE)
        verifier = self._verifier(cosign)

        evidence = verifier.verify(SIGNED_IMAGE)

        self.assertEqual(evidence.image_identity, "registry.local/argus/runtime")
        self.assertEqual(evidence.manifest_digest, "sha256:" + "a" * 64)
        self.assertEqual(evidence.verifier_kind, "cosign-private-infrastructure")
        self.assertEqual(evidence.verifier_version, COSIGN_VERSION)
        self.assertTrue(evidence.signer_key_id.startswith("sha256:"))
        self.assertTrue(evidence.payload_sha256.startswith("sha256:"))
        self.assertTrue(evidence.signature_sha256.startswith("sha256:"))
        self.assertTrue(evidence.verifier_binary_sha256.startswith("sha256:"))

    def test_missing_signature_and_claim_tampering_are_rejected(self) -> None:
        cosign = self._fake_cosign(verify_output="Verified OK")
        verifier = self._verifier(cosign)

        with self.assertRaises(ImageVerificationError) as missing:
            verifier.verify(UNSIGNED_IMAGE)
        self.assertEqual(missing.exception.reason_code, "signature_not_found")

        self._write_signature_entry(
            SIGNED_IMAGE,
            manifest_digest="sha256:" + "d" * 64,
        )
        with self.assertRaises(ImageVerificationError) as digest_mismatch:
            verifier.verify(SIGNED_IMAGE)
        self.assertEqual(digest_mismatch.exception.reason_code, "digest_mismatch")

        self._write_signature_entry(
            SIGNED_IMAGE,
            image_identity="registry.local/argus/attacker",
        )
        with self.assertRaises(ImageVerificationError) as identity_mismatch:
            verifier.verify(SIGNED_IMAGE)
        self.assertEqual(identity_mismatch.exception.reason_code, "identity_mismatch")

    def test_crypto_failure_is_policy_rejection(self) -> None:
        cosign = self._fake_cosign(verify_exit=1, verify_output="signature invalid")
        self._write_signature_entry(SIGNED_IMAGE)
        verifier = self._verifier(cosign)

        with self.assertRaises(ImageVerificationError) as failure:
            verifier.verify(SIGNED_IMAGE)

        self.assertEqual(failure.exception.reason_code, "signature_invalid")

    def test_timeout_and_false_success_output_fail_closed_as_unavailable(self) -> None:
        self._write_signature_entry(SIGNED_IMAGE)
        timeout_verifier = self._verifier(self._fake_cosign(verify_sleep_s=5), timeout_s=0.5)
        with self.assertRaises(ImageVerifierUnavailableError) as timeout:
            timeout_verifier.verify(SIGNED_IMAGE)
        self.assertEqual(timeout.exception.reason_code, "verifier_timeout")

        malformed_verifier = self._verifier(self._fake_cosign(verify_output="looks fine"))
        with self.assertRaises(ImageVerifierUnavailableError) as malformed:
            malformed_verifier.verify(SIGNED_IMAGE)
        self.assertEqual(malformed.exception.reason_code, "verifier_output_invalid")

    def test_version_mismatch_fails_during_configuration(self) -> None:
        cosign = self._fake_cosign(version="v0.0.0", verify_output="Verified OK")

        with self.assertRaises(ImageVerifierUnavailableError) as mismatch:
            self._verifier(cosign)

        self.assertEqual(mismatch.exception.reason_code, "version_mismatch")

    def test_public_key_snapshot_matches_the_reported_signer_fingerprint(self) -> None:
        cosign = self._fake_cosign(verify_output="Verified OK", require_initial_public_key=True)
        self._write_signature_entry(SIGNED_IMAGE)
        verifier = self._verifier(cosign)
        signer_key_id = verifier.signer_key_id

        self.public_key.write_text(
            "-----BEGIN PUBLIC KEY-----\nrotated\n-----END PUBLIC KEY-----\n",
            encoding="utf-8",
        )

        evidence = verifier.verify(SIGNED_IMAGE)

        self.assertEqual(evidence.signer_key_id, signer_key_id)

    def test_store_path_separates_identities_that_share_a_digest(self) -> None:
        alias = "registry.local/argus/alias@sha256:" + "a" * 64

        self.assertNotEqual(
            cosign_signature_store_path(self.signature_store, SIGNED_IMAGE),
            cosign_signature_store_path(self.signature_store, alias),
        )

    def test_env_loader_requires_trust_material_and_pins_cosign_version(self) -> None:
        cosign = self._fake_cosign(verify_output="Verified OK")
        self._write_signature_entry(SIGNED_IMAGE)
        env = {
            "ARGUS_S10_COSIGN_BIN": str(cosign),
            "ARGUS_S10_COSIGN_PUBLIC_KEY_PATH": str(self.public_key),
            "ARGUS_S10_COSIGN_SIGNATURE_STORE_DIR": str(self.signature_store),
            "ARGUS_S10_COSIGN_EXPECTED_VERSION": COSIGN_VERSION,
            "ARGUS_S10_COSIGN_VERIFY_TIMEOUT_S": "1",
        }

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ARGUS_S10_COSIGN_PUBLIC_KEY_PATH"):
                _image_verifier_from_env()
        with patch.dict(os.environ, env, clear=True):
            verifier = _image_verifier_from_env()

        self.assertEqual(verifier.version, COSIGN_VERSION)
        self.assertEqual(verifier.verify(SIGNED_IMAGE).manifest_digest, "sha256:" + "a" * 64)

    def _verifier(self, cosign_bin: Path, *, timeout_s: float = 1.0) -> CosignImageVerifier:
        return CosignImageVerifier(
            cosign_bin=str(cosign_bin),
            public_key_path=self.public_key,
            signature_store_dir=self.signature_store,
            expected_version=COSIGN_VERSION,
            timeout_s=timeout_s,
        )

    def _write_signature_entry(
        self,
        image: str,
        *,
        image_identity: str | None = None,
        manifest_digest: str | None = None,
    ) -> None:
        identity, digest = image.rsplit("@", 1)
        entry = cosign_signature_store_path(self.signature_store, image)
        entry.mkdir(parents=True, exist_ok=True)
        payload = {
            "critical": {
                "identity": {"docker-reference": image_identity or identity},
                "image": {"Docker-manifest-digest": manifest_digest or digest},
                "type": "cosign container image signature",
            },
            "optional": {"creator": "project-argus-unit-test"},
        }
        (entry / "payload.json").write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        (entry / "signature.sig").write_text("MEQCIFakeCosignSignature==\n", encoding="ascii")

    def _fake_cosign(
        self,
        *,
        version: str = COSIGN_VERSION,
        verify_output: str = "Verified OK",
        verify_exit: int = 0,
        verify_sleep_s: float = 0,
        require_initial_public_key: bool = False,
    ) -> Path:
        path = self.root / f"cosign-{len(list(self.root.glob('cosign-*')))}"
        version_json = json.dumps(
            {
                "gitVersion": version,
                "gitCommit": "unit-test",
                "gitTreeState": "clean",
                "buildDate": "2026-04-06T21:25:20Z",
                "goVersion": "go1.25.7",
                "compiler": "gc",
                "platform": "test",
            },
            separators=(",", ":"),
        )
        sleep_line = f"sleep {verify_sleep_s}" if verify_sleep_s else ":"
        public_key_guard = "grep -q 'test' \"$4\" || exit 9" if require_initial_public_key else ":"
        path.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"version\" ]; then\n"
            f"  printf '%s\\n' '{version_json}'\n"
            "  exit 0\n"
            "fi\n"
            f"{sleep_line}\n"
            f"{public_key_guard}\n"
            f"printf '%s\\n' '{verify_output}'\n"
            f"exit {verify_exit}\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path


if __name__ == "__main__":
    unittest.main()
