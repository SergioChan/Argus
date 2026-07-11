from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

import argus_core.s10 as s10_module
from scripts import run_m0_spine_battery as m0_battery
from argus_core import (
    ArtifactRecord,
    BudgetCaps,
    BudgetUsage,
    C3ReportSigner,
    DockerSandboxSupervisor,
    BudgetToken,
    FileSystemArtifactStore,
    InMemoryS10KmsCheckpointSigner,
    InMemoryS10KmsVerifierKeyProvider,
    Lineage,
    PriceTableSignatureError,
    Producer,
    SandboxExecutionResult,
    ScopeGrant,
    ScopeToken,
    SIGNATURE_VERIFICATION_ACCEPTED,
)
from argus_core import canonical_json_bytes
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest
from argus_runtime.s10_supervisor_service import (
    RuntimeIdentityMintPolicy,
    S10SupervisorApp,
    build_app_from_env as build_s10_app_from_env,
)
from argus_runtime.s8_persistence import SubprocessRustLedgerWriter, _rust_ledger_writer_from_env
from argus_runtime.s8_writer_service import S8WriterApp


AUTH_TOKEN = "test-runtime-token"
S8_READ_TOKEN = "test-s8-read-token"
S8_REPRO_WRITE_TOKEN = "test-s8-repro-write-token"
S8_DATASET_WRITE_TOKEN = "test-s8-dataset-write-token"
S8_VERIFIER_LABEL_READ_TOKEN = "test-s8-verifier-label-read-token"
S8_BROKER_AUDIENCE_ONLY_READ_TOKEN = "test-s8-broker-audience-only-read-token"
BOOTSTRAP_TOKEN = "test-bootstrap-token"
IDENTITY_SIGNING_KEY = b"test-identity-signing-key"
HEALTH_TOKEN = "test-health-token"
BROKER_WRITE_KEY = b"test-s8-broker-write-key"
POLICY_SIGNING_KEY = "test-s10-policy-signing-key"
CHECKPOINT_SIGNING_KEY = "test-s10-checkpoint-signing-key"
CHECKPOINT_SIGNER_AUTH_TOKEN = "test-checkpoint-signer-token"
S10_VERIFIER_KEY_AUTH_TOKEN = "test-verifier-key-token"
PRICE_TABLE_SIGNING_KEY = "test-s10-price-table-signing-key"
S3_REFERENCE_REFEREE_SIGNING_KEY = "test-s3-reference-referee-signing-key"
TOKEN_ED25519_PRIVATE_KEY_HEX = "1111111111111111111111111111111111111111111111111111111111111111"
TOKEN_ED25519_PUBLIC_KEY_HEX = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
S10_C3_VERIFIER_KEYS_JSON = json.dumps(
    {
        "argus-m0-c3-verifier": "test-c3-verifier-key",
        "s3-reference-referee-key": S3_REFERENCE_REFEREE_SIGNING_KEY,
    },
    separators=(",", ":"),
    sort_keys=True,
)


class ArgusM0RuntimeServiceTests(unittest.TestCase):
    def _spend_final_payload(
        self,
        *,
        halt_latency_s: float = 0.003031,
        freeze_capture_latency_s: float = 2.558381,
    ) -> dict[str, object]:
        return {
            "schema": "argus.s10.spend.final.v1",
            "final_state": "BUDGET_HALTED",
            "price_table": {
                "price_table_version": "0.1.0",
                "signer_key_id": "argus-m0-price-table",
                "signature": "hmac-sha256:test",
                "usd_per_cpu_second": "0",
                "usd_per_gpu_second": {"default": "0"},
                "usd_per_1k_model_tokens": {"default": "0"},
            },
            "usage": {
                "compute_units": 0,
                "gpu_seconds": 0,
                "model_tokens": 0,
                "cost_usd": 0,
            },
            "usd_rollup": {
                "source": "signed_price_table",
                "cost_usd": 0,
                "cost_usd_exact": "0",
            },
            "metering": {
                "sample_count": 3,
                "max_cadence_s": freeze_capture_latency_s,
                "halted_by_meter": True,
                "halt_latency_s": halt_latency_s,
                "halt_detection_elapsed_s": 1.003031,
                "halt_completion_elapsed_s": 3.561411,
                "halt_completion_latency_s": halt_latency_s + freeze_capture_latency_s,
                "freeze_capture_latency_s": freeze_capture_latency_s,
                "dcgm_available": False,
                "nvidia_smi_available": False,
                "gpu_count": 0,
                "gpu_models": [],
                "mig_enabled": False,
                "mig_instance_count": 0,
                "gpu_telemetry_source": "unavailable",
                "dcgm_metrics_available": False,
                "dcgm_metric_row_count": 0,
            },
        }

    def test_halt_latency_summary_uses_conservative_nearest_rank_p99(self) -> None:
        latencies = [0.01] * 49 + [1.75]

        summary = m0_battery._halt_latency_summary(latencies)

        self.assertEqual(summary["trial_count"], 50)
        self.assertEqual(summary["p50_nearest_rank_s"], 0.01)
        self.assertEqual(summary["p95_nearest_rank_s"], 0.01)
        self.assertEqual(summary["p99_nearest_rank_s"], 1.75)
        self.assertEqual(summary["max_s"], 1.75)

    def test_halt_latency_summary_rejects_missing_trials_and_p99_breach(self) -> None:
        with self.assertRaisesRegex(AssertionError, "expected 50 halt latency trials"):
            m0_battery._halt_latency_summary([0.01] * 49)
        with self.assertRaisesRegex(AssertionError, "p99 exceeded"):
            m0_battery._halt_latency_summary([0.01] * 49 + [2.01])
        with self.assertRaisesRegex(AssertionError, "cannot be negative"):
            m0_battery._halt_latency_summary([0.01] * 49 + [-0.1])

    def test_spend_final_allows_slow_freeze_capture_when_halt_latency_is_within_slo(self) -> None:
        query = {
            "records": [
                {
                    "artifact_ref": "spend-ref",
                    "lineage": {"input_refs": ["launch-ref"]},
                }
            ]
        }
        payload = self._spend_final_payload(
            halt_latency_s=0.003031,
            freeze_capture_latency_s=2.558381,
        )

        with patch.object(m0_battery, "_get_json", side_effect=[query, payload]):
            spend_final = m0_battery._battery_spend_final(
                s8_url="http://s8",
                read_token="read-token",
                job_id="m0-halt-latency-job",
                launch_provenance_ref="launch-ref",
                expected_state="BUDGET_HALTED",
            )

        self.assertEqual(spend_final["meter_halt_latency_s"], 0.003031)
        self.assertEqual(spend_final["meter_freeze_capture_latency_s"], 2.558381)

    def test_spend_final_rejects_budget_halt_latency_breach(self) -> None:
        query = {
            "records": [
                {
                    "artifact_ref": "spend-ref",
                    "lineage": {"input_refs": ["launch-ref"]},
                }
            ]
        }
        payload = self._spend_final_payload(
            halt_latency_s=2.01,
            freeze_capture_latency_s=0.05,
        )

        with (
            patch.object(m0_battery, "_get_json", side_effect=[query, payload]),
            self.assertRaisesRegex(AssertionError, "budget halt latency exceeded"),
        ):
            m0_battery._battery_spend_final(
                s8_url="http://s8",
                read_token="read-token",
                job_id="m0-halt-latency-job",
                launch_provenance_ref="launch-ref",
                expected_state="BUDGET_HALTED",
            )

    def test_meter_gap_probe_restores_default_supervisor_config(self) -> None:
        evidence: dict[str, object] = {"results": []}
        run_envs: list[dict[str, str]] = []

        def fake_run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 60, check: bool = True):
            run_envs.append(dict(env or {}))
            return subprocess.CompletedProcess(command, 0, "", "")

        get_payloads = iter(
            [
                {
                    "status": "ok",
                    "resource_meter": "docker-api-cgroup",
                    "meter_interval_s": 0.1,
                    "meter_gap_halt_s": 0.1,
                },
                {"artifact_ref": "launch-ref"},
                {"status": "ok", "meter_interval_s": 1.0, "meter_gap_halt_s": 5.0},
            ]
        )
        post_payloads = iter(
            [
                {"budget_id": "budget-1"},
                {"scope_id": "scope-1"},
                {
                    "timed_out": True,
                    "stderr": "argus meter halted container: meter_gap",
                    "handle": {"state": "TIMED_OUT", "launch_provenance_ref": "launch-ref"},
                },
            ]
        )
        spend_final = {
            "artifact_ref": "spend-ref",
            "final_state": "TIMED_OUT",
            "meter_sample_count": 2,
            "meter_gap_sample_count": 1,
            "meter_gap_sources": ["docker-api-cgroup-gap"],
            "meter_gap_max_conservative_gap_s": 0.1,
            "meter_halted_by_meter": True,
            "meter_max_cadence_s": 0.1,
            "meter_dcgm_available": False,
            "meter_nvidia_smi_available": False,
            "meter_gpu_count": 0,
            "meter_gpu_models": [],
            "meter_mig_enabled": False,
            "meter_mig_instance_count": 0,
            "meter_gpu_telemetry_source": "unavailable",
        }

        with (
            patch.object(m0_battery, "_run", side_effect=fake_run),
            patch.object(m0_battery, "_wait_health"),
            patch.object(m0_battery, "_get_json", side_effect=lambda *args, **kwargs: next(get_payloads)),
            patch.object(m0_battery, "_post_json", side_effect=lambda *args, **kwargs: next(post_payloads)),
            patch.object(m0_battery, "_battery_spend_final", return_value=spend_final),
        ):
            m0_battery._battery_non_injected_meter_gap(
                evidence,
                docker="docker",
                compose_file="compose.yaml",
                compose_env={"BASE": "1"},
                s10_url="http://s10",
                s8_url="http://s8",
                image="busybox@sha256:" + "1" * 64,
                token="runtime-token",
                read_token="read-token",
                health_token="health-token",
            )

        self.assertEqual(len(run_envs), 2)
        self.assertEqual(run_envs[0]["ARGUS_S10_METER_INTERVAL_S"], "0.1")
        self.assertEqual(run_envs[0]["ARGUS_S10_METER_GAP_HALT_S"], "0.1")
        self.assertNotIn("ARGUS_S10_METER_INTERVAL_S", run_envs[1])
        self.assertNotIn("ARGUS_S10_METER_GAP_HALT_S", run_envs[1])
        result = evidence["results"][-1]  # type: ignore[index]
        detail = result["detail"]  # type: ignore[index]
        self.assertEqual(detail["s10_meter_restored_interval_s"], 1.0)
        self.assertEqual(detail["s10_meter_restored_gap_halt_s"], 5.0)

    def test_meter_gap_probe_restores_default_supervisor_config_on_failure(self) -> None:
        evidence: dict[str, object] = {"results": []}
        run_envs: list[dict[str, str]] = []

        def fake_run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 60, check: bool = True):
            run_envs.append(dict(env or {}))
            return subprocess.CompletedProcess(command, 0, "", "")

        get_payloads = iter(
            [
                {
                    "status": "ok",
                    "resource_meter": "docker-api-cgroup",
                    "meter_interval_s": 0.1,
                    "meter_gap_halt_s": 0.1,
                },
                {"status": "ok", "meter_interval_s": 1.0, "meter_gap_halt_s": 5.0},
            ]
        )

        def raise_probe_failure(*args, **kwargs):
            raise AssertionError("probe boom")

        with (
            patch.object(m0_battery, "_run", side_effect=fake_run),
            patch.object(m0_battery, "_wait_health"),
            patch.object(m0_battery, "_get_json", side_effect=lambda *args, **kwargs: next(get_payloads)),
            patch.object(m0_battery, "_post_json", side_effect=raise_probe_failure),
        ):
            with self.assertRaisesRegex(AssertionError, "probe boom"):
                m0_battery._battery_non_injected_meter_gap(
                    evidence,
                    docker="docker",
                    compose_file="compose.yaml",
                    compose_env={"BASE": "1"},
                    s10_url="http://s10",
                    s8_url="http://s8",
                    image="busybox@sha256:" + "1" * 64,
                    token="runtime-token",
                    read_token="read-token",
                    health_token="health-token",
                )

        self.assertEqual(len(run_envs), 2)
        self.assertEqual(run_envs[0]["ARGUS_S10_METER_INTERVAL_S"], "0.1")
        self.assertNotIn("ARGUS_S10_METER_INTERVAL_S", run_envs[1])

    def test_m0_identity_policy_declares_halt_latency_caller(self) -> None:
        requests = m0_battery._m0_identity_requests()
        policy = json.loads(m0_battery._m0_identity_mint_policy_json())

        self.assertIn("halt-latency", requests)
        self.assertEqual(requests["halt-latency"]["caller_id"], "m0-halt-latency")
        self.assertEqual(requests["halt-latency"]["job_id"], "m0-halt-latency-job")
        self.assertEqual(policy["m0-halt-latency"]["job_id"], "m0-halt-latency-job")
        self.assertEqual(policy["m0-halt-latency"]["budget_caps"]["max_wallclock_s"], 1)
        self.assertIn("partial-capture", requests)
        self.assertEqual(requests["partial-capture"]["caller_id"], "m0-partial-capture")
        self.assertEqual(requests["partial-capture"]["job_id"], "m0-partial-capture-job")
        self.assertEqual(policy["m0-partial-capture"]["job_id"], "m0-partial-capture-job")
        self.assertEqual(policy["m0-partial-capture"]["budget_caps"]["max_wallclock_s"], 10)

    def test_m1_reference_service_tokens_are_preprovisioned_and_non_minting(self) -> None:
        secrets = m0_battery._m0_runtime_secrets()
        tokens = m0_battery._m1_reference_service_access_tokens(secrets)
        auth = RuntimeAuth.with_signed_identities(
            bootstrap_token=secrets["bootstrap_token"],
            identity_signing_key=secrets["identity_signing_key"].encode("utf-8"),
        )
        expected_producers = {
            "m1-reference-s1": "S1",
            "m1-reference-s2": "S2",
            "m1-reference-s3": "S3",
            "m1-reference-s7": "S7",
            "m1-reference-s11": "S11",
        }

        self.assertEqual(set(tokens), set(expected_producers))
        for caller_id, producer in expected_producers.items():
            identity = auth.authenticate(
                JsonRequest(
                    method="GET",
                    path="/test",
                    query={},
                    body=None,
                    headers={"authorization": f"Bearer {tokens[caller_id]}"},
                )
            )
            self.assertEqual(identity.caller_id, caller_id)
            self.assertEqual(identity.job_id, "m1-reference-job")
            self.assertEqual(identity.scopes.producer_subsystems, (producer,))
            self.assertFalse(identity.can_mint_runtime_identity)

    def test_s1_reference_physics_demo_battery_requires_verified_http_face(self) -> None:
        evidence: dict[str, object] = {"results": []}
        posted: list[tuple[str, dict[str, object], float]] = []

        def fake_post_json(
            url: str,
            body: dict[str, object],
            *,
            expected_status: int = 200,
            token: str | None = None,
            timeout: float = 10,
        ) -> dict[str, object]:
            del token
            posted.append((url, body, timeout))
            self.assertEqual(expected_status, 200)
            self.assertEqual(url, "http://s1-demo/v1/s1-reference-physics-demo")
            self.assertEqual(body["job_id"], "m1-reference-job")
            return {
                "demo": "s1-reference-physics",
                "job_id": "m1-reference-job",
                "final_state": "REPORTED",
                "claim_tier": "recapitulated-known",
                "claim_tier_is_candidate": False,
                "dataset_ref": "c4://dataset/ewpt-reference/v1",
                "runtime_provenance": {
                    "adapter_provenance_ref": "c4://adapter/demo",
                    "sandbox_launch_provenance_ref": "c4://container/demo",
                    "s2_training_dataset_ref": "c4://dataset/s2-training-demo",
                    "s2_frozen_pipeline_ref": "c4://pipeline/s2-demo",
                },
                "validation_report_ref": "c4://report/demo",
                "promoted_artifact_ref": "c4://artifact/demo",
                "observatory_html_ref": "c4://observatory/demo",
                "observatory_trusted": True,
                "observatory_html": '<html data-verdict="VERIFIED"></html>',
                "referee_id": "s3-reference-verifier",
                "signature_key_id": "s3-reference-referee-key",
                "checks": [
                    {"check": "INJECTION", "status": "PASS"},
                    {"check": "NULL_CONTROL", "status": "PASS"},
                    {"check": "PHYSICAL_CONSISTENCY", "status": "PASS"},
                    {"check": "CALIBRATION", "status": "PASS"},
                    {"check": "RECAP_BENCHMARK", "status": "PASS"},
                ],
            }

        def fake_get_json(
            url: str,
            *,
            expected_status: int = 200,
            token: str | None = None,
        ) -> dict[str, object]:
            self.assertEqual(expected_status, 200)
            self.assertEqual(token, "read-token")
            if url.endswith("/payload"):
                return {
                    "component_refs": {
                        "input_refs": ["c4://dataset/s2-training-demo"],
                    }
                }
            producer_by_ref = {
                "c4://dataset/ewpt-reference/v1": "S1",
                "c4://adapter/demo": "S7",
                "c4://container/demo": "S10",
                "c4://dataset/s2-training-demo": "S1",
                "c4://pipeline/s2-demo": "S2",
                "c4://report/demo": "S3",
                "c4://artifact/demo": "S1",
                "c4://observatory/demo": "S11",
            }
            decoded_url = unquote(url)
            producer = next(value for ref, value in producer_by_ref.items() if ref in decoded_url)
            return {"producer": {"subsystem": producer}}

        with (
            patch.object(m0_battery, "_post_json", side_effect=fake_post_json),
            patch.object(m0_battery, "_get_json", side_effect=fake_get_json),
        ):
            m0_battery._battery_s1_reference_physics_demo(
                evidence,
                "http://s1-demo",
                s8_url="http://s8-demo",
                read_token="read-token",
            )

        self.assertEqual(
            posted,
            [
                (
                    "http://s1-demo/v1/s1-reference-physics-demo",
                    {"job_id": "m1-reference-job"},
                    m0_battery.M1_REFERENCE_DEMO_E2E_TIMEOUT_S,
                )
            ],
        )
        result = evidence["results"][-1]  # type: ignore[index]
        self.assertEqual(result["item"], "s1-reference-demo")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["detail"]["claim_tier"], "recapitulated-known")
        self.assertTrue(result["detail"]["observatory_trusted"])
        self.assertEqual(result["detail"]["producers"]["adapter"], "S7")
        self.assertTrue(result["detail"]["s2_pipeline_lineage_includes_s1_training_dataset"])

    def test_inflight_revocation_slo_starts_after_revoke_acknowledgement(self) -> None:
        evidence: dict[str, object] = {"results": []}

        class ImmediateThread:
            def __init__(self, *, target: object, daemon: bool) -> None:
                self._target = target
                self._alive = False
                self.daemon = daemon

            def start(self) -> None:
                self._target()  # type: ignore[operator]

            def join(self, timeout: float | None = None) -> None:
                del timeout

            def is_alive(self) -> bool:
                return self._alive

        def fake_post_json(url: str, *_args: object, **_kwargs: object) -> dict[str, object]:
            if url.endswith("/v1/budget-tokens"):
                return {"budget_id": "budget-token"}
            if url.endswith("/v1/scope-tokens"):
                return {"scope_id": "scope-token"}
            if url.endswith("/v1/sandboxes:launch"):
                return {
                    "handle": {
                        "state": "TIMED_OUT",
                        "launch_provenance_ref": "c4://artifact/revocation-launch",
                    },
                    "timed_out": True,
                    "stderr": "argus meter halted container: token_revoked",
                    "audit_events": ["meter.halt", "token.revocation_halt"],
                }
            if url.endswith("/v1/tokens:revoke"):
                return {
                    "revocation_store": "file",
                    "revoked_token_id": "budget-token",
                }
            raise AssertionError(f"unexpected POST {url}")

        with (
            patch.object(m0_battery, "_launch_request_json", return_value={"launch": "request"}),
            patch.object(m0_battery, "_post_json", side_effect=fake_post_json),
            patch.object(
                m0_battery,
                "_battery_spend_final",
                return_value={
                    "meter_breached_dimensions": ["token_revoked"],
                    "meter_halted_by_meter": True,
                    "artifact_ref": "c4://artifact/revocation-spend-final",
                    "final_state": "TIMED_OUT",
                    "partial_result_captured": True,
                },
            ),
            patch.object(m0_battery.threading, "Thread", ImmediateThread),
            patch.object(m0_battery.time, "sleep"),
            patch.object(m0_battery.time, "monotonic", side_effect=[10.0, 12.75, 12.75, 12.9]),
        ):
            m0_battery._battery_revoked_inflight_sandbox_halted(
                evidence,
                "http://s10-demo",
                s8_url="http://s8-demo",
                image="busybox@sha256:test",
                token="runtime-token",
                read_token="read-token",
            )

        result = evidence["results"][-1]  # type: ignore[index]
        detail = result["detail"]
        self.assertEqual(detail["revocation_ack_elapsed_s"], 2.75)
        self.assertEqual(detail["halted_after_revocation_ack_s"], 0.15)
        self.assertEqual(detail["propagation_slo_s"], 2.0)

    def test_s8_writer_service_commits_and_replays_c4_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp))
            record = app.create_artifact(
                {
                    "kind": "model",
                    "payload": {"weights": [1, 2, 3]},
                    "producer": {"subsystem": "S2", "version": "0.0.0"},
                    "lineage": {
                        "input_refs": [],
                        "code_ref": "git:model",
                        "environment_digest": "oci:model",
                        "seeds": ["seed-1"],
                    },
                }
            )

            reloaded = S8WriterApp(FileSystemArtifactStore(tmp))
            fetched = reloaded.get_artifact_record(record["artifact_ref"])

            self.assertEqual(fetched["artifact_ref"], record["artifact_ref"])
            self.assertEqual(fetched["content_hash"], record["content_hash"])
            self.assertEqual(reloaded.store.record_count, 1)
            self.assertEqual(reloaded.store.get_artifact(record["artifact_ref"]), b'{"weights":[1,2,3]}')

    def test_s8_writer_http_reads_payload_through_verify_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp, auth=_s8_runtime_auth())
            record = app.create_artifact(
                {
                    "kind": "model",
                    "payload": {"weights": [1, 2, 3]},
                    "producer": {"subsystem": "S2", "version": "0.0.0"},
                    "lineage": {
                        "input_refs": [],
                        "code_ref": "git:model",
                        "environment_digest": "oci:model",
                        "seeds": ["seed-1"],
                    },
                }
            )

            status, payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/artifacts/{record['artifact_ref']}/payload",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(status, 200)
            self.assertEqual(payload, {"weights": [1, 2, 3]})

    def test_s8_writer_service_refreshes_file_ledger_before_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp)
            external = FileSystemArtifactStore(tmp).create_artifact(
                kind="model",
                payload={"weights": [3, 2, 1]},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
            )

            fetched = app.get_artifact_record(external.artifact_ref)

            self.assertEqual(fetched["artifact_ref"], external.artifact_ref)
            self.assertEqual(app.store.record_count, 1)

    def test_s8_writer_skips_service_refresh_for_live_store(self) -> None:
        class LiveStore:
            requires_service_refresh = False

            def refresh(self) -> None:
                raise AssertionError("live store should not be service-refreshed")

            def get_artifact_record(self, ref: str) -> ArtifactRecord:
                return ArtifactRecord(
                    artifact_ref=ref,
                    kind="model",
                    content_hash="blake3:" + "0" * 64,
                    size_bytes=2,
                    producer=Producer(subsystem="S2", version="0.0.0"),
                    lineage=Lineage(input_refs=(), code_ref="git:live", environment_digest="oci:live"),
                    created_at="2026-07-02T00:00:00Z",
                )

        app = S8WriterApp(LiveStore())

        self.assertEqual(app.get_artifact_record("c4://live")["artifact_ref"], "c4://live")

    def test_subprocess_rust_ledger_writer_uses_s10_checkpoint_signer_env(self) -> None:
        script = (
            "import json, os, sys;"
            "json.load(sys.stdin);"
            "assert os.environ['ARGUS_S8_CHECKPOINT_SIGNER_URL'] == 'http://s10/sign';"
            "assert os.environ['ARGUS_S8_CHECKPOINT_SIGNER_AUTH_TOKEN'] == 'signer-token';"
            "assert os.environ['ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER'] == '1';"
            "assert 'ARGUS_S8_CHECKPOINT_SIGNING_KEY' not in os.environ;"
            "assert 'ARGUS_S8_CHECKPOINT_SIGNER_KEY_ID' not in os.environ;"
            "print('{\"status\":\"ok\",\"checkpoint\":null}')"
        )
        writer = SubprocessRustLedgerWriter(
            command=["python3", "-c", script],
            dsn="postgresql://argus@example/argus",
            db_role="argus_s8_ledger_writer",
            checkpoint_signer_url="http://s10/sign",
            checkpoint_signer_auth_token="signer-token",
            allow_insecure_checkpoint_signer=True,
        )
        record = ArtifactRecord(
            artifact_ref="c4://s8/signer-env",
            kind="model",
            content_hash="blake3:" + "0" * 64,
            size_bytes=2,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:signer-env", environment_digest="oci:signer-env"),
            created_at="2026-07-02T00:00:00Z",
        )

        result = writer.commit_record(record)

        self.assertEqual(writer.checkpoint_signer_kind, "s10-http-insecure-local")
        self.assertEqual(result, {"status": "ok", "checkpoint": None})

    def test_subprocess_rust_ledger_writer_rejects_plain_http_without_local_override(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER=1"):
            SubprocessRustLedgerWriter(
                command=["python3", "-c", "raise SystemExit('must not run')"],
                dsn="postgresql://argus@example/argus",
                db_role="argus_s8_ledger_writer",
                checkpoint_signer_url="http://s10/sign",
                checkpoint_signer_auth_token="signer-token",
            )

    def test_s8_postgres_env_requires_rust_ledger_writer(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "ARGUS_S8_RUST_LEDGER_WRITER_CMD"):
            _rust_ledger_writer_from_env(
                {},
                dsn="postgresql://argus@example/argus",
                db_role=None,
            )
        with self.assertRaisesRegex(RuntimeError, "ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER=1"):
            _rust_ledger_writer_from_env(
                {
                    "ARGUS_S8_RUST_LEDGER_WRITER_CMD": "argus-s8-ledger-writer",
                    "ARGUS_S8_CHECKPOINT_SIGNER_URL": "http://s10/sign",
                    "ARGUS_S8_CHECKPOINT_SIGNER_AUTH_TOKEN": "signer-token",
                },
                dsn="postgresql://argus@example/argus",
                db_role=None,
            )
        writer = _rust_ledger_writer_from_env(
            {
                "ARGUS_S8_RUST_LEDGER_WRITER_CMD": "argus-s8-ledger-writer",
                "ARGUS_S8_CHECKPOINT_SIGNER_URL": "http://s10/sign",
                "ARGUS_S8_CHECKPOINT_SIGNER_AUTH_TOKEN": "signer-token",
                "ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER": "1",
            },
            dsn="postgresql://argus@example/argus",
            db_role=None,
        )
        self.assertEqual(writer.checkpoint_signer_kind, "s10-http-insecure-local")
        with self.assertRaisesRegex(RuntimeError, "ARGUS_S8_CHECKPOINT_SIGNER_URL"):
            _rust_ledger_writer_from_env(
                {
                    "ARGUS_S8_RUST_LEDGER_WRITER_CMD": "argus-s8-ledger-writer",
                },
                dsn="postgresql://argus@example/argus",
                db_role=None,
            )

    def test_s8_writer_http_denies_direct_artifact_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp, auth=_runtime_auth())

            status, payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/artifacts",
                    query={},
                    body={
                        "kind": "model",
                        "payload": {"weights": [1]},
                        "producer": {"subsystem": "S2", "version": "0.0.0"},
                        "lineage": {
                            "input_refs": [],
                            "code_ref": "git:model",
                            "environment_digest": "oci:model",
                        },
                    },
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(status, 403)
            self.assertEqual(payload["error"], "DirectWriteDenied")
            self.assertEqual(app.store.record_count, 0)

    def test_s8_internal_broker_write_requires_signature_and_revalidates_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(
                FileSystemArtifactStore(tmp),
                data_dir=tmp,
                auth=_s8_runtime_auth(),
                broker_write_key=BROKER_WRITE_KEY,
            )
            body = {
                "authorization": {
                    "audience": "store",
                    "scope_job_id": "job-1",
                    "producer_subsystems": ["S2"],
                },
                "kind": "model",
                "payload": {"weights": [1]},
                "producer": asdict(Producer(subsystem="S2", version="0.0.0", job_id="job-1")),
                "lineage": asdict(Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model", job_id="job-1")),
            }
            bad_body = {
                **body,
                "producer": asdict(Producer(subsystem="S9", version="0.0.0", job_id="job-1")),
            }

            unauthorized_status, unauthorized_payload = app.http.handle(
                JsonRequest(method="POST", path="/v1/internal/brokered-artifacts", query={}, body=body)
            )
            accepted_status, accepted_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/internal/brokered-artifacts",
                    query={},
                    body=body,
                    headers=_broker_write_headers(body),
                )
            )
            rejected_status, rejected_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/internal/brokered-artifacts",
                    query={},
                    body=bad_body,
                    headers=_broker_write_headers(bad_body),
                )
            )

            self.assertEqual(unauthorized_status, 401)
            self.assertEqual(unauthorized_payload["error"], "Unauthorized")
            self.assertEqual(accepted_status, 201)
            self.assertEqual(accepted_payload["producer"]["job_id"], "job-1")
            self.assertEqual(rejected_status, 403)
            self.assertEqual(rejected_payload["error"], "PermissionError")
            self.assertEqual(app.store.record_count, 1)

            external = FileSystemArtifactStore(tmp).create_artifact(
                kind="container",
                payload={"exec_environment_digest": "oci:runtime", "exec_environment": {}, "launch": {}},
                producer=Producer(subsystem="S10", version="0.0.0"),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="busybox@sha256:test",
                    environment_digest="oci:runtime",
                    seeds=("trace-1",),
                ),
            )
            chained_body = {
                **body,
                "payload": {"weights": [2]},
                "lineage": asdict(
                    Lineage(
                        input_refs=(external.artifact_ref,),
                        code_ref="git:model",
                        environment_digest="oci:runtime",
                        seeds=("seed-1",),
                        job_id="job-1",
                    )
                ),
            }
            chained_status, chained_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/internal/brokered-artifacts",
                    query={},
                    body=chained_body,
                    headers=_broker_write_headers(chained_body),
                )
            )
            reloaded = FileSystemArtifactStore(tmp)

            self.assertEqual(chained_status, 201)
            self.assertEqual(reloaded.get_artifact_record(chained_payload["artifact_ref"]).artifact_ref, chained_payload["artifact_ref"])
            self.assertEqual(reloaded.record_count, 3)

            impact_status, impact_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/impact-set",
                    query={"seed_ref": [external.artifact_ref]},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            unauth_impact_status, unauth_impact_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/impact-set",
                    query={"seed_ref": [external.artifact_ref]},
                    body=None,
                )
            )
            missing_seed_status, missing_seed_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/impact-set",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            query_status, query_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/artifacts",
                    query={"kind": ["model"], "producer_subsystem": ["S2"], "page_size": ["10"]},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            unauth_query_status, unauth_query_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/artifacts",
                    query={"kind": ["model"]},
                    body=None,
                )
            )
            write_only_query_status, write_only_query_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/artifacts",
                    query={"kind": ["model"]},
                    body=None,
                    headers=_auth_headers(S8_REPRO_WRITE_TOKEN),
                )
            )
            broker_audience_only_query_status, broker_audience_only_query_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/artifacts",
                    query={"kind": ["model"]},
                    body=None,
                    headers=_auth_headers(S8_BROKER_AUDIENCE_ONLY_READ_TOKEN),
                )
            )
            record_status, record_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/artifacts/{chained_payload['artifact_ref']}/record",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            payload_status, payload_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/artifacts/{chained_payload['artifact_ref']}/payload",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            unauth_record_status, unauth_record_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/artifacts/{chained_payload['artifact_ref']}/record",
                    query={},
                    body=None,
                )
            )
            write_only_record_status, write_only_record_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/artifacts/{chained_payload['artifact_ref']}/record",
                    query={},
                    body=None,
                    headers=_auth_headers(S8_REPRO_WRITE_TOKEN),
                )
            )
            write_only_payload_status, write_only_payload_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/artifacts/{chained_payload['artifact_ref']}/payload",
                    query={},
                    body=None,
                    headers=_auth_headers(S8_REPRO_WRITE_TOKEN),
                )
            )
            bad_page_status, bad_page_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/artifacts",
                    query={"kind": ["model"], "page_size": ["not-an-int"]},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            manifest_status, manifest_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/reproducibility-manifest/{chained_payload['artifact_ref']}",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            unauth_manifest_status, unauth_manifest_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/reproducibility-manifest/{chained_payload['artifact_ref']}",
                    query={},
                    body=None,
                )
            )
            missing_manifest_status, missing_manifest_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/reproducibility-manifest/c4://artifact/missing",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            status_zero_status, status_zero_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/reproducibility-status/{chained_payload['artifact_ref']}",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            unauth_status_status, unauth_status_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/reproducibility-status/{chained_payload['artifact_ref']}",
                    query={},
                    body=None,
                )
            )
            write_only_status_status, write_only_status_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/reproducibility-status/{chained_payload['artifact_ref']}",
                    query={},
                    body=None,
                    headers=_auth_headers(S8_REPRO_WRITE_TOKEN),
                )
            )
            missing_status_status, missing_status_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/reproducibility-status/c4://artifact/missing",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            check_body = {
                "artifact_ref": chained_payload["artifact_ref"],
                "rerun_payload": {"weights": [2]},
                "tolerance_id": "m0-hash-equal",
            }
            fail_check_body = {
                "artifact_ref": chained_payload["artifact_ref"],
                "rerun_payload": {"weights": [3]},
                "tolerance_id": "m0-hash-equal-fail",
            }
            check_status, check_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/reproducibility-checks",
                    query={},
                    body=check_body,
                    headers=_auth_headers(),
                )
            )
            fail_check_status, fail_check_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/reproducibility-checks",
                    query={},
                    body=fail_check_body,
                    headers=_auth_headers(),
                )
            )
            unauth_check_status, unauth_check_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/reproducibility-checks",
                    query={},
                    body=check_body,
                )
            )
            read_only_check_status, read_only_check_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/reproducibility-checks",
                    query={},
                    body=check_body,
                    headers=_auth_headers(S8_READ_TOKEN),
                )
            )
            audit_status, audit_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/audit-slice",
                    query={"artifact_ref": [chained_payload["artifact_ref"]]},
                    body=None,
                    headers=_auth_headers(),
                )
            )
            multi_audit_page1_status, multi_audit_page1_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/audit-slice",
                    query={
                        "artifact_ref": [external.artifact_ref, chained_payload["artifact_ref"]],
                        "page_size": ["1"],
                    },
                    body=None,
                    headers=_auth_headers(),
                )
            )
            multi_audit_page2_status, multi_audit_page2_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/audit-slice",
                    query={
                        "artifact_ref": [external.artifact_ref, chained_payload["artifact_ref"]],
                        "page_size": ["1"],
                        "page_token": [str(multi_audit_page1_payload["next_page_token"])],
                    },
                    body=None,
                    headers=_auth_headers(),
                )
            )
            write_only_audit_status, write_only_audit_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/audit-slice",
                    query={"artifact_ref": [chained_payload["artifact_ref"]]},
                    body=None,
                    headers=_auth_headers(S8_REPRO_WRITE_TOKEN),
                )
            )
            bad_audit_page_status, bad_audit_page_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/audit-slice",
                    query={
                        "artifact_ref": [chained_payload["artifact_ref"]],
                        "page_size": ["0"],
                    },
                    body=None,
                    headers=_auth_headers(),
                )
            )
            unauth_audit_status, unauth_audit_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/audit-slice",
                    query={"artifact_ref": [chained_payload["artifact_ref"]]},
                    body=None,
                )
            )
            missing_audit_ref_status, missing_audit_ref_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/audit-slice",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(impact_status, 200)
            self.assertEqual(
                [record["artifact_ref"] for record in impact_payload["records"]],
                [chained_payload["artifact_ref"]],
            )
            self.assertEqual(unauth_impact_status, 401)
            self.assertEqual(unauth_impact_payload["error"], "Unauthorized")
            self.assertEqual(missing_seed_status, 400)
            self.assertEqual(missing_seed_payload["error"], "seed_ref_required")
            self.assertEqual(query_status, 200)
            self.assertIn(
                chained_payload["artifact_ref"],
                [record["artifact_ref"] for record in query_payload["records"]],
            )
            self.assertIsNone(query_payload["next_page_token"])
            self.assertEqual(unauth_query_status, 401)
            self.assertEqual(unauth_query_payload["error"], "Unauthorized")
            self.assertEqual(write_only_query_status, 403)
            self.assertEqual(write_only_query_payload["error"], "CapabilityDenied")
            self.assertEqual(broker_audience_only_query_status, 403)
            self.assertEqual(broker_audience_only_query_payload["error"], "CapabilityDenied")
            self.assertEqual(record_status, 200)
            self.assertEqual(record_payload["artifact_ref"], chained_payload["artifact_ref"])
            self.assertEqual(payload_status, 200)
            self.assertEqual(payload_payload, {"weights": [2]})
            self.assertEqual(unauth_record_status, 401)
            self.assertEqual(unauth_record_payload["error"], "Unauthorized")
            self.assertEqual(write_only_record_status, 403)
            self.assertEqual(write_only_record_payload["error"], "CapabilityDenied")
            self.assertEqual(write_only_payload_status, 403)
            self.assertEqual(write_only_payload_payload["error"], "CapabilityDenied")
            self.assertEqual(bad_page_status, 400)
            self.assertEqual(bad_page_payload["error"], "ValueError")
            self.assertEqual(manifest_status, 200)
            self.assertEqual(manifest_payload["artifact_ref"], chained_payload["artifact_ref"])
            self.assertEqual(manifest_payload["lineage"]["input_refs"], (external.artifact_ref,))
            self.assertEqual(manifest_payload["lineage"]["code_ref"], "git:model")
            self.assertEqual(unauth_manifest_status, 401)
            self.assertEqual(unauth_manifest_payload["error"], "Unauthorized")
            self.assertEqual(missing_manifest_status, 404)
            self.assertEqual(missing_manifest_payload["error"], "KeyError")
            self.assertEqual(status_zero_status, 200)
            self.assertFalse(status_zero_payload["non_promotable"])
            self.assertEqual(status_zero_payload["check_count"], 0)
            self.assertEqual(status_zero_payload["failed_check_count"], 0)
            self.assertEqual(unauth_status_status, 401)
            self.assertEqual(unauth_status_payload["error"], "Unauthorized")
            self.assertEqual(write_only_status_status, 403)
            self.assertEqual(write_only_status_payload["error"], "CapabilityDenied")
            self.assertEqual(missing_status_status, 404)
            self.assertEqual(missing_status_payload["error"], "KeyError")
            self.assertEqual(check_status, 201)
            self.assertEqual(check_payload["artifact_ref"], chained_payload["artifact_ref"])
            self.assertEqual(check_payload["verdict"], "PASS")
            self.assertEqual(check_payload["comparator_id"], "hash_equal")
            self.assertFalse(check_payload["non_promotable"])
            self.assertEqual(check_payload["status"]["check_count"], 1)
            self.assertEqual(check_payload["status"]["failed_check_count"], 0)
            self.assertEqual(fail_check_status, 201)
            self.assertEqual(fail_check_payload["verdict"], "FAIL")
            self.assertTrue(fail_check_payload["non_reproducible"])
            self.assertTrue(fail_check_payload["non_promotable"])
            self.assertEqual(fail_check_payload["status"]["failed_check_count"], 1)
            self.assertEqual(unauth_check_status, 401)
            self.assertEqual(unauth_check_payload["error"], "Unauthorized")
            self.assertEqual(read_only_check_status, 403)
            self.assertEqual(read_only_check_payload["error"], "CapabilityDenied")
            self.assertEqual(audit_status, 200)
            self.assertTrue(audit_payload["verification"]["valid"])
            self.assertEqual(audit_payload["audit_slice"]["leaves"][0]["artifact_id"], chained_payload["artifact_ref"])
            self.assertEqual(
                audit_payload["audit_slice"]["inclusion_proofs"][0]["artifact_id"],
                chained_payload["artifact_ref"],
            )
            self.assertEqual(multi_audit_page1_status, 200)
            self.assertTrue(multi_audit_page1_payload["verification"]["valid"])
            self.assertEqual(multi_audit_page1_payload["next_page_token"], 1)
            self.assertEqual(
                [leaf["artifact_id"] for leaf in multi_audit_page1_payload["audit_slice"]["leaves"]],
                [external.artifact_ref],
            )
            self.assertEqual(multi_audit_page2_status, 200)
            self.assertTrue(multi_audit_page2_payload["verification"]["valid"])
            self.assertIsNone(multi_audit_page2_payload["next_page_token"])
            self.assertEqual(
                [leaf["artifact_id"] for leaf in multi_audit_page2_payload["audit_slice"]["leaves"]],
                [chained_payload["artifact_ref"]],
            )
            self.assertEqual(write_only_audit_status, 403)
            self.assertEqual(write_only_audit_payload["error"], "CapabilityDenied")
            self.assertEqual(bad_audit_page_status, 400)
            self.assertEqual(bad_audit_page_payload["error"], "ValueError")
            self.assertEqual(unauth_audit_status, 401)
            self.assertEqual(unauth_audit_payload["error"], "Unauthorized")
            self.assertEqual(missing_audit_ref_status, 400)
            self.assertEqual(missing_audit_ref_payload["error"], "artifact_ref_required")

    def test_s8_writer_http_dataset_registry_routes_require_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp, auth=_s8_runtime_auth())
            dataset_body = {
                "dataset_id": "ewpt-corpus",
                "version": "1.0.0",
                "contamination_index_version": "contamination-2026-07-03",
                "splits": [
                    {
                        "split_id": "train",
                        "role": "train",
                        "content_hash": "blake3:" + "1" * 64,
                        "row_count": 10,
                        "schema_ref": "c4://schemas/ewpt/train",
                        "access_scope": "agent-readable",
                    },
                    {
                        "split_id": "blind",
                        "role": "blind",
                        "content_hash": "blake3:" + "2" * 64,
                        "row_count": 5,
                        "schema_ref": "c4://schemas/ewpt/blind",
                        "access_scope": "verifier-only",
                        "label_seal_ref": "c4://labels/ewpt/blind",
                    },
                ],
            }

            unauth_register_status, unauth_register_payload = app.http.handle(
                JsonRequest(method="POST", path="/v1/datasets", query={}, body=dataset_body)
            )
            read_only_register_status, read_only_register_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/datasets",
                    query={},
                    body=dataset_body,
                    headers=_auth_headers(S8_READ_TOKEN),
                )
            )
            register_status, register_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/datasets",
                    query={},
                    body=dataset_body,
                    headers=_auth_headers(S8_DATASET_WRITE_TOKEN),
                )
            )
            get_status, get_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus",
                    query={},
                    body=None,
                    headers=_auth_headers(S8_READ_TOKEN),
                )
            )
            exact_get_status, exact_get_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus",
                    query={"version": ["1.0.0"]},
                    body=None,
                    headers=_auth_headers(S8_READ_TOKEN),
                )
            )
            versions_status, versions_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus/versions",
                    query={},
                    body=None,
                    headers=_auth_headers(S8_READ_TOKEN),
                )
            )
            write_only_get_status, write_only_get_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus",
                    query={},
                    body=None,
                    headers=_auth_headers(S8_REPRO_WRITE_TOKEN),
                )
            )
            unauth_get_status, unauth_get_payload = app.http.handle(
                JsonRequest(method="GET", path="/v1/datasets/ewpt-corpus", query={}, body=None)
            )
            train_resolve_status, train_resolve_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus/splits/train/resolve",
                    query={"version": ["1.0.0"]},
                    body=None,
                    headers=_auth_headers(S8_READ_TOKEN),
                )
            )
            blind_read_resolve_status, blind_read_resolve_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus/splits/blind/resolve",
                    query={"version": ["1.0.0"]},
                    body=None,
                    headers=_auth_headers(S8_READ_TOKEN),
                )
            )
            blind_verifier_resolve_status, blind_verifier_resolve_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus/splits/blind/resolve",
                    query={"version": ["1.0.0"]},
                    body=None,
                    headers=_auth_headers(S8_VERIFIER_LABEL_READ_TOKEN),
                )
            )
            write_only_resolve_status, write_only_resolve_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus/splits/blind/resolve",
                    query={"version": ["1.0.0"]},
                    body=None,
                    headers=_auth_headers(S8_REPRO_WRITE_TOKEN),
                )
            )
            unauth_resolve_status, unauth_resolve_payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path="/v1/datasets/ewpt-corpus/splits/blind/resolve",
                    query={"version": ["1.0.0"]},
                    body=None,
                )
            )
            conflict_body = {
                **dataset_body,
                "splits": [
                    {
                        **dataset_body["splits"][0],
                        "row_count": 11,
                    }
                ],
            }
            conflict_status, conflict_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/datasets",
                    query={},
                    body=conflict_body,
                    headers=_auth_headers(S8_DATASET_WRITE_TOKEN),
                )
            )

            self.assertEqual(unauth_register_status, 401)
            self.assertEqual(unauth_register_payload["error"], "Unauthorized")
            self.assertEqual(read_only_register_status, 403)
            self.assertEqual(read_only_register_payload["error"], "CapabilityDenied")
            self.assertEqual(register_status, 201)
            self.assertEqual(register_payload["dataset_id"], "ewpt-corpus")
            self.assertEqual(register_payload["version"], "1.0.0")
            self.assertEqual(register_payload["provenance_ref"]["artifact_ref"], "c4://dataset/ewpt-corpus/1.0.0")
            self.assertEqual(get_status, 200)
            self.assertEqual(exact_get_status, 200)
            self.assertEqual(exact_get_payload["provenance_ref"]["artifact_ref"], get_payload["provenance_ref"]["artifact_ref"])
            blind_split = next(split for split in get_payload["splits"] if split["split_id"] == "blind")
            self.assertIsNone(blind_split["content_hash"])
            self.assertIsNone(blind_split["label_seal_ref"])
            self.assertEqual(versions_status, 200)
            self.assertEqual(versions_payload, {"dataset_id": "ewpt-corpus", "versions": ["1.0.0"]})
            self.assertEqual(write_only_get_status, 403)
            self.assertEqual(write_only_get_payload["error"], "CapabilityDenied")
            self.assertEqual(unauth_get_status, 401)
            self.assertEqual(unauth_get_payload["error"], "Unauthorized")
            self.assertEqual(train_resolve_status, 200)
            self.assertEqual(train_resolve_payload["feature_blob_ref"], "blake3:" + "1" * 64)
            self.assertIsNone(train_resolve_payload["label_blob_ref"])
            self.assertEqual(blind_read_resolve_status, 403)
            self.assertEqual(blind_read_resolve_payload["category"], "SCOPE_DENIED")
            self.assertNotIn("c4://labels/ewpt/blind", blind_read_resolve_payload["message"])
            self.assertEqual(blind_verifier_resolve_status, 200)
            self.assertEqual(blind_verifier_resolve_payload["feature_blob_ref"], "blake3:" + "2" * 64)
            self.assertEqual(blind_verifier_resolve_payload["label_blob_ref"], "c4://labels/ewpt/blind")
            self.assertEqual(
                blind_verifier_resolve_payload["audit_event"]["requester_capabilities"],
                ("s8.read", "s8.verifier-labels.read"),
            )
            self.assertEqual(write_only_resolve_status, 403)
            self.assertEqual(write_only_resolve_payload["error"], "CapabilityDenied")
            self.assertEqual(unauth_resolve_status, 401)
            self.assertEqual(unauth_resolve_payload["error"], "Unauthorized")
            self.assertEqual(conflict_status, 400)
            self.assertIn(conflict_payload["error"], {"WriteOnceViolationError", "DatasetRegistryError"})

    def test_runtime_http_routes_require_bearer_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            s8 = S8WriterApp(
                FileSystemArtifactStore(tmp),
                data_dir=tmp,
                auth=_signed_runtime_auth(),
                health_token=HEALTH_TOKEN,
            )
            s10 = S10SupervisorApp(
                signing_key=b"test-key",
                auth=_signed_runtime_auth(),
                runtime_identity_mint_policy=_runtime_identity_mint_policy(),
                health_token=HEALTH_TOKEN,
            )

            s8_no_auth_status, s8_no_auth_payload = s8.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None)
            )
            s8_bootstrap_status, s8_bootstrap_payload = s8.http.handle(
                JsonRequest(
                    method="GET",
                    path="/healthz",
                    query={},
                    body=None,
                    headers=_auth_headers(BOOTSTRAP_TOKEN),
                )
            )
            s8_health_status, s8_health_payload = s8.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )
            s10_no_auth_status, s10_no_auth_payload = s10.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None)
            )
            s10_bootstrap_status, s10_bootstrap_payload = s10.http.handle(
                JsonRequest(
                    method="GET",
                    path="/healthz",
                    query={},
                    body=None,
                    headers=_auth_headers(BOOTSTRAP_TOKEN),
                )
            )
            s10_health_status, s10_health_payload = s10.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )
            s10_scope_status, s10_scope_payload = s10.http.handle(
                JsonRequest(method="POST", path="/v1/scope-tokens", query={}, body={})
            )
            s10_mint_with_health_status, s10_mint_with_health_payload = s10.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/runtime-identities",
                    query={},
                    body={"caller_id": "sandbox-1"},
                    headers=_auth_headers(HEALTH_TOKEN),
                )
            )
            s8_write_with_health_status, s8_write_with_health_payload = s8.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/artifacts",
                    query={},
                    body={},
                    headers=_auth_headers(HEALTH_TOKEN),
                )
            )

            self.assertEqual(s8_no_auth_status, 401)
            self.assertEqual(s8_no_auth_payload["error"], "Unauthorized")
            self.assertEqual(s8_bootstrap_status, 401)
            self.assertEqual(s8_bootstrap_payload["error"], "Unauthorized")
            self.assertEqual(s8_health_status, 200)
            self.assertEqual(s8_health_payload["status"], "ok")
            self.assertEqual(s8_health_payload["ledger_writer"], "filesystem")
            self.assertEqual(s8_health_payload["report_verifier"], "unconfigured")
            self.assertEqual(s8_health_payload["report_verifier_trust_store"], "unconfigured")
            self.assertEqual(s10_no_auth_status, 401)
            self.assertEqual(s10_no_auth_payload["error"], "Unauthorized")
            self.assertEqual(s10_bootstrap_status, 401)
            self.assertEqual(s10_bootstrap_payload["error"], "Unauthorized")
            self.assertEqual(s10_health_status, 200)
            self.assertEqual(s10_health_payload["status"], "ok")
            self.assertEqual(s10_health_payload["quota_ledger"], "memory")
            self.assertEqual(s10_health_payload["resource_meter"], "docker-api-cgroup")
            self.assertLessEqual(s10_health_payload["meter_interval_s"], 5)
            self.assertGreaterEqual(s10_health_payload["meter_gap_halt_s"], s10_health_payload["meter_interval_s"])
            self.assertFalse(s10_health_payload["dcgm_available"])
            self.assertFalse(s10_health_payload["nvidia_smi_available"])
            self.assertEqual(s10_health_payload["gpu_count"], 0)
            self.assertFalse(s10_health_payload["mig_enabled"])
            self.assertEqual(s10_health_payload["mig_instance_count"], 0)
            self.assertFalse(s10_health_payload["dcgm_metric_sampler_enabled"])
            self.assertEqual(s10_health_payload["dcgm_metric_fields"], ["1001", "1004", "1005"])
            self.assertEqual(s10_scope_status, 401)
            self.assertEqual(s10_scope_payload["error"], "Unauthorized")
            self.assertEqual(s10_mint_with_health_status, 401)
            self.assertEqual(s10_mint_with_health_payload["error"], "Unauthorized")
            self.assertEqual(s8_write_with_health_status, 401)
            self.assertEqual(s8_write_with_health_payload["error"], "Unauthorized")

    def test_s10_verifier_key_routes_require_internal_token_and_hide_secrets(self) -> None:
        provider = InMemoryS10KmsVerifierKeyProvider()
        provider.register_verifier_key("s3-key", b"s3-secret")
        app = S10SupervisorApp(
            signing_key=b"test-key",
            verifier_key_provider=provider,
            verifier_key_auth_token=S10_VERIFIER_KEY_AUTH_TOKEN,
            health_token=HEALTH_TOKEN,
        )
        signed_report = C3ReportSigner(key_id="s3-key", secret=b"s3-secret").sign(_signed_report_payload())
        unsigned = json.loads(json.dumps(signed_report))
        unsigned["signature"]["value"] = ""

        no_auth_status, no_auth_payload = app.http.handle(
            JsonRequest(method="GET", path="/v1/internal/verifier-keys", query={}, body=None)
        )
        health_token_status, health_token_payload = app.http.handle(
            JsonRequest(
                method="GET",
                path="/v1/internal/verifier-keys",
                query={},
                body=None,
                headers=_auth_headers(HEALTH_TOKEN),
            )
        )
        snapshot_status, snapshot = app.http.handle(
            JsonRequest(
                method="GET",
                path="/v1/internal/verifier-keys",
                query={},
                body=None,
                headers=_auth_headers(S10_VERIFIER_KEY_AUTH_TOKEN),
            )
        )
        accepted_status, accepted = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/internal/verifier-keys:verify",
                query={},
                body={
                    "key_id": "s3-key",
                    "report_with_empty_signature": unsigned,
                    "signature_value": signed_report["signature"]["value"],
                },
                headers=_auth_headers(S10_VERIFIER_KEY_AUTH_TOKEN),
            )
        )
        invalid_status, invalid = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/internal/verifier-keys:verify",
                query={},
                body={
                    "key_id": "s3-key",
                    "report_with_empty_signature": unsigned,
                    "signature_value": "hmac-sha256:" + "0" * 64,
                },
                headers=_auth_headers(S10_VERIFIER_KEY_AUTH_TOKEN),
            )
        )

        self.assertEqual(no_auth_status, 401)
        self.assertEqual(no_auth_payload["error"], "Unauthorized")
        self.assertEqual(health_token_status, 401)
        self.assertEqual(health_token_payload["error"], "Unauthorized")
        self.assertEqual(snapshot_status, 200)
        self.assertEqual(snapshot["provider"], "s10-kms")
        self.assertEqual(snapshot["epoch"], provider.epoch)
        self.assertEqual(snapshot["keys"], [{"epoch": provider.epoch, "key_id": "s3-key", "revoked": False}])
        self.assertNotIn("secret", snapshot["keys"][0])
        self.assertEqual(accepted_status, 200)
        self.assertEqual(accepted["result"], SIGNATURE_VERIFICATION_ACCEPTED)
        self.assertEqual(invalid_status, 200)
        self.assertEqual(invalid["result"], "signature_invalid")

    def test_s10_http_mint_binds_tokens_to_authenticated_identity(self) -> None:
        app = S10SupervisorApp(signing_key=b"test-key", auth=_runtime_auth())

        budget_status, budget = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/budget-tokens",
                query={},
                body={"ttl_s": 120},
                headers=_auth_headers(),
            )
        )
        scope_status, scope = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/scope-tokens",
                query={},
                body={"ttl_s": 120},
                headers=_auth_headers(),
            )
        )
        override_status, override_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/scope-tokens",
                query={},
                body={
                    "job_id": "attacker-selected-job",
                    "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S9"]},
                },
                headers=_auth_headers(),
            )
        )

        self.assertEqual(budget_status, 201)
        self.assertEqual(budget["job_id"], "job-auth")
        self.assertEqual(budget["root_request_id"], "root-auth")
        self.assertEqual(budget["caps"]["max_wallclock_s"], 30)
        self.assertEqual(scope_status, 201)
        self.assertEqual(scope["job_id"], "job-auth")
        self.assertEqual(scope["scopes"]["broker_audiences"], ("store",))
        self.assertEqual(scope["scopes"]["producer_subsystems"], ("S2",))
        self.assertEqual(override_status, 403)
        self.assertEqual(override_payload["error"], "IdentityOverrideError")

    def test_s10_http_mints_runtime_identity_before_budget_scope_tokens(self) -> None:
        app = S10SupervisorApp(
            signing_key=b"test-key",
            auth=_signed_runtime_auth(),
            runtime_identity_mint_policy=_runtime_identity_mint_policy(),
        )

        identity_status, identity_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={
                    "caller_id": "sandbox-1",
                    "ttl_s": 120,
                },
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        bootstrap_budget_status, bootstrap_budget_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/budget-tokens",
                query={},
                body={},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        runtime_headers = _auth_headers(identity_payload["access_token"])
        budget_status, budget = app.http.handle(
            JsonRequest(method="POST", path="/v1/budget-tokens", query={}, body={}, headers=runtime_headers)
        )
        scope_status, scope = app.http.handle(
            JsonRequest(method="POST", path="/v1/scope-tokens", query={}, body={}, headers=runtime_headers)
        )

        self.assertEqual(identity_status, 201)
        self.assertEqual(identity_payload["identity"]["job_id"], "job-launch")
        self.assertTrue(identity_payload["access_token"].startswith("argus-runtime-v1."))
        self.assertEqual(bootstrap_budget_status, 403)
        self.assertEqual(bootstrap_budget_payload["error"], "PermissionError")
        self.assertEqual(budget_status, 201)
        self.assertEqual(budget["job_id"], "job-launch")
        self.assertEqual(budget["root_request_id"], "root-launch")
        self.assertEqual(scope_status, 201)
        self.assertEqual(scope["job_id"], "job-launch")
        self.assertEqual(scope["scopes"]["producer_subsystems"], ("S2",))

    def test_s10_http_launches_sandbox_through_authenticated_daemon_route(self) -> None:
        supervisor = _SuccessfulSupervisor()
        app = S10SupervisorApp(signing_key=b"test-key", auth=_runtime_auth(), docker_supervisor=supervisor)
        launch = _launch_body(app)

        status, payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/sandboxes:launch",
                query={},
                body=launch,
                headers=_auth_headers(),
            )
        )

        self.assertEqual(status, 201)
        self.assertEqual(payload["handle"]["state"], "SUCCEEDED")
        self.assertEqual(payload["handle"]["job_id"], "job-auth")
        self.assertIsNotNone(payload["handle"]["launch_provenance_ref"])
        self.assertIn("no-default-route", payload["stdout"])
        self.assertIn("sandbox.exited", payload["audit_events"])
        self.assertIn("spend.final", payload["audit_events"])
        self.assertEqual(supervisor.calls[0]["materialized_env"], {"VISIBLE": "ok"})
        provenance = app.artifacts.get_record(payload["handle"]["launch_provenance_ref"])
        self.assertEqual(provenance.producer.subsystem, "S10")
        self.assertEqual(provenance.producer.job_id, "job-auth")
        spend_records = app.artifacts.query_artifacts({"kind": "spend.final", "job_id": "job-auth"})
        self.assertEqual(len(spend_records), 1)
        spend_payload = json.loads(app.artifacts.get_artifact(spend_records[0].artifact_ref).decode("utf-8"))
        self.assertEqual(spend_payload["final_state"], "SUCCEEDED")
        self.assertEqual(spend_payload["metering"]["sample_count"], 1)
        self.assertEqual(spend_payload["metering"]["source"], "test-successful-supervisor")
        event_types = [event.event_type for event in app.audit.events()]
        self.assertIn("sandbox.started", event_types)
        self.assertIn("meter.sample", event_types)

    def test_s10_http_launch_rejects_identity_bound_job_override(self) -> None:
        supervisor = _SuccessfulSupervisor()
        app = S10SupervisorApp(signing_key=b"test-key", auth=_runtime_auth(), docker_supervisor=supervisor)
        launch = {**_launch_body(app), "job_id": "attacker-job"}

        status, payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/sandboxes:launch",
                query={},
                body=launch,
                headers=_auth_headers(),
            )
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "PermissionError")
        self.assertIn("launch job_id", payload["message"])
        self.assertEqual(supervisor.calls, [])

    def test_s10_http_launch_rejects_preflight_over_budget_without_handle(self) -> None:
        supervisor = _SuccessfulSupervisor()
        auth = RuntimeAuth(
            {
                AUTH_TOKEN: RuntimeIdentity(
                    caller_id="test-caller",
                    job_id="job-auth",
                    root_request_id="root-auth",
                    scopes=ScopeGrant(broker_audiences=("store",), producer_subsystems=("S2",)),
                    budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=0.01),
                    max_ttl_s=300,
                )
            }
        )
        app = S10SupervisorApp(signing_key=b"test-key", auth=auth, docker_supervisor=supervisor)
        launch = _launch_body(app)
        requested_envelope = dict(launch["requested_envelope"])
        requested_envelope["estimated_cost_usd"] = 0.02
        launch["requested_envelope"] = requested_envelope

        status, payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/sandboxes:launch",
                query={},
                body=launch,
                headers=_auth_headers(),
            )
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "BudgetExceededError")
        self.assertIsNone(payload["handle"])
        self.assertIn("budget.reject", payload["audit_events"])
        self.assertNotIn("sandbox.launched", payload["audit_events"])
        self.assertNotIn("sandbox.started", payload["audit_events"])
        self.assertNotIn("spend.final", payload["audit_events"])
        self.assertEqual(supervisor.calls, [])
        self.assertEqual(app.artifacts.record_count, 0)

    def test_s10_http_launch_budget_halt_returns_audit_and_provenance(self) -> None:
        supervisor = _SuccessfulSupervisor(usage=BudgetUsage(compute_units=11, wallclock_s=1))
        app = S10SupervisorApp(signing_key=b"test-key", auth=_runtime_auth(), docker_supervisor=supervisor)
        launch = _launch_body(app)

        status, payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/sandboxes:launch",
                query={},
                body=launch,
                headers=_auth_headers(),
            )
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "BudgetExceededError")
        self.assertEqual(payload["handle"]["state"], "BUDGET_HALTED")
        self.assertIsNotNone(payload["handle"]["launch_provenance_ref"])
        self.assertIn("budget.halt", payload["audit_events"])
        self.assertIn("spend.final", payload["audit_events"])
        spend_records = app.artifacts.query_artifacts({"kind": "spend.final", "job_id": "job-auth"})
        self.assertEqual(len(spend_records), 1)
        spend_payload = json.loads(app.artifacts.get_artifact(spend_records[0].artifact_ref).decode("utf-8"))
        self.assertEqual(spend_payload["final_state"], "BUDGET_HALTED")
        self.assertEqual(spend_payload["metering"]["sample_count"], 1)
        self.assertEqual(spend_payload["metering"]["source"], "test-successful-supervisor")

    def test_s10_runtime_identity_mint_policy_rejects_overrides_unknown_callers_and_ttl_widening(self) -> None:
        app = S10SupervisorApp(
            signing_key=b"test-key",
            auth=_signed_runtime_auth(),
            runtime_identity_mint_policy=_runtime_identity_mint_policy(),
        )

        override_status, override_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "sandbox-1", "job_id": "attacker-selected-job"},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        unknown_status, unknown_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "unknown"},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        ttl_status, ttl_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "sandbox-1", "ttl_s": 301},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        no_policy = S10SupervisorApp(signing_key=b"test-key", auth=_signed_runtime_auth())
        no_policy_status, no_policy_payload = no_policy.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "sandbox-1"},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )

        self.assertEqual(override_status, 403)
        self.assertEqual(override_payload["error"], "IdentityOverrideError")
        self.assertEqual(unknown_status, 403)
        self.assertEqual(unknown_payload["error"], "PermissionError")
        self.assertEqual(ttl_status, 403)
        self.assertEqual(ttl_payload["error"], "PermissionError")
        self.assertEqual(no_policy_status, 403)
        self.assertEqual(no_policy_payload["error"], "PermissionError")
        caller_key_policy = RuntimeIdentityMintPolicy.from_json(
            json.dumps(
                {
                    "sandbox-1": {
                        "caller_id": "attacker-caller",
                        "job_id": "job-launch",
                        "root_request_id": "root-launch",
                        "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 30, "max_cost_usd": 5},
                        "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S2"]},
                        "max_ttl_s": 300,
                    }
                }
            )
        )
        self.assertEqual(caller_key_policy.identity_for_request({"caller_id": "sandbox-1"}).caller_id, "sandbox-1")

    def test_s10_env_build_fails_closed_without_signing_key(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
                "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
            },
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                build_s10_app_from_env()

    def test_s10_env_build_requires_signed_policy_service(self) -> None:
        base_env = {
            "ARGUS_S10_SIGNING_KEY": "test-s10-signing-key",
            "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
            "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
            "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _runtime_identity_mint_policy_json(),
            "ARGUS_M0_HEALTH_TOKEN": HEALTH_TOKEN,
            "ARGUS_S10_CHECKPOINT_SIGNING_KEY": CHECKPOINT_SIGNING_KEY,
            "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN": CHECKPOINT_SIGNER_AUTH_TOKEN,
        }
        with patch.dict(os.environ, base_env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ARGUS_S10_POLICY_SIGNING_KEY"):
                build_s10_app_from_env()
        with patch.dict(os.environ, {**base_env, "ARGUS_S10_POLICY_SIGNING_KEY": POLICY_SIGNING_KEY}, clear=True):
            app = build_s10_app_from_env()
            status, payload = app.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )

        self.assertTrue(app.policy.signature.startswith("hmac-sha256:"))
        self.assertEqual(app.policy.signer_key_id, "argus-m0-policy")
        self.assertEqual(status, 200)
        self.assertEqual(payload["policy_bundle_version"], "argus-m0-dev")
        self.assertEqual(payload["policy_signer_key_id"], "argus-m0-policy")
        self.assertEqual(payload["checkpoint_signer"], "s10-kms")
        self.assertEqual(payload["token_signer"], "local-hmac")
        self.assertEqual(payload["token_signature_algorithm"], "hmac-sha256")
        self.assertEqual(payload["quota_ledger"], "memory")
        self.assertEqual(payload["price_table"], "unconfigured")
        self.assertEqual(payload["price_table_signer_key_id"], "unconfigured")
        self.assertEqual(payload["resource_meter"], "docker-api-cgroup")
        self.assertLessEqual(payload["meter_interval_s"], 5)
        self.assertGreaterEqual(payload["meter_gap_halt_s"], payload["meter_interval_s"])
        self.assertFalse(payload["dcgm_available"])
        self.assertFalse(payload["nvidia_smi_available"])
        self.assertEqual(payload["gpu_count"], 0)
        self.assertFalse(payload["mig_enabled"])
        self.assertEqual(payload["mig_instance_count"], 0)
        self.assertFalse(payload["dcgm_metric_sampler_enabled"])
        self.assertEqual(payload["dcgm_metric_fields"], ["1001", "1004", "1005"])

    def test_s10_env_build_uses_meter_gap_config_and_rejects_invalid_values(self) -> None:
        base_env = {
            "ARGUS_S10_SIGNING_KEY": "test-s10-signing-key",
            "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
            "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
            "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _runtime_identity_mint_policy_json(),
            "ARGUS_M0_HEALTH_TOKEN": HEALTH_TOKEN,
            "ARGUS_S10_POLICY_SIGNING_KEY": POLICY_SIGNING_KEY,
            "ARGUS_S10_CHECKPOINT_SIGNING_KEY": CHECKPOINT_SIGNING_KEY,
            "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN": CHECKPOINT_SIGNER_AUTH_TOKEN,
        }
        with patch.dict(
            os.environ,
            {
                **base_env,
                "ARGUS_S10_METER_INTERVAL_S": "0.25",
                "ARGUS_S10_METER_GAP_HALT_S": "0.75",
            },
            clear=True,
        ):
            app = build_s10_app_from_env()
            status, payload = app.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload["meter_interval_s"], 0.25)
        self.assertEqual(payload["meter_gap_halt_s"], 0.75)

        with patch.dict(os.environ, {**base_env, "ARGUS_S10_METER_INTERVAL_S": "0"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ARGUS_S10_METER_INTERVAL_S"):
                build_s10_app_from_env()
        with patch.dict(os.environ, {**base_env, "ARGUS_S10_METER_GAP_HALT_S": "not-a-number"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ARGUS_S10_METER_GAP_HALT_S"):
                build_s10_app_from_env()

    def test_s10_env_build_can_use_ed25519_token_signer_and_public_verifier(self) -> None:
        base_env = {
            "ARGUS_S10_TOKEN_SIGNING_MODE": "ed25519",
            "ARGUS_S10_TOKEN_SIGNER_KEY_ID": "argus-m0-token-root",
            "ARGUS_S10_TOKEN_ED25519_PRIVATE_KEY_HEX": TOKEN_ED25519_PRIVATE_KEY_HEX,
            "ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX": TOKEN_ED25519_PUBLIC_KEY_HEX,
            "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
            "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
            "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _runtime_identity_mint_policy_json(),
            "ARGUS_M0_HEALTH_TOKEN": HEALTH_TOKEN,
            "ARGUS_S10_POLICY_SIGNING_KEY": POLICY_SIGNING_KEY,
            "ARGUS_S10_CHECKPOINT_SIGNING_KEY": CHECKPOINT_SIGNING_KEY,
            "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN": CHECKPOINT_SIGNER_AUTH_TOKEN,
        }
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {**base_env, "ARGUS_S10_TOKEN_REVOCATION_STORE_PATH": os.path.join(tmp, "revocations.jsonl")},
            clear=True,
        ):
            app = build_s10_app_from_env()
            health_status, health = app.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )
            runtime_status, runtime_token = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/runtime-identities",
                    query={},
                    body={"caller_id": "sandbox-1"},
                    headers=_auth_headers(BOOTSTRAP_TOKEN),
                )
            )
            budget_status, budget = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/budget-tokens",
                    query={},
                    body={},
                    headers=_auth_headers(runtime_token["access_token"]),
                )
            )

        self.assertEqual(health_status, 200)
        self.assertEqual(health["token_signer"], "s10-kms-ed25519")
        self.assertEqual(health["token_signature_algorithm"], "ed25519")
        self.assertEqual(health["token_verifier"], "offline-ed25519-public")
        self.assertEqual(health["token_revocation_store"], "file")
        self.assertEqual(health["quota_ledger"], "memory")
        self.assertEqual(health["price_table"], "unconfigured")
        self.assertEqual(health["resource_meter"], "docker-api-cgroup")
        self.assertLessEqual(health["meter_interval_s"], 5)
        self.assertGreaterEqual(health["meter_gap_halt_s"], health["meter_interval_s"])
        self.assertFalse(health["dcgm_available"])
        self.assertFalse(health["nvidia_smi_available"])
        self.assertEqual(health["gpu_count"], 0)
        self.assertFalse(health["mig_enabled"])
        self.assertEqual(health["mig_instance_count"], 0)
        self.assertFalse(health["dcgm_metric_sampler_enabled"])
        self.assertEqual(health["dcgm_metric_fields"], ["1001", "1004", "1005"])
        self.assertEqual(runtime_status, 201)
        self.assertEqual(budget_status, 201)
        self.assertEqual(budget["signer_key_id"], "argus-m0-token-root")
        self.assertTrue(budget["signature"].startswith("ed25519:"))

        with patch.dict(
            os.environ,
            {**base_env, "ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX": "00" * 32},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "does not match private key"):
                build_s10_app_from_env()

    def test_s10_env_build_activates_signed_price_table_and_rejects_stale_table(self) -> None:
        base_env = {
            "ARGUS_S10_SIGNING_KEY": "test-s10-signing-key",
            "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
            "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
            "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _runtime_identity_mint_policy_json(),
            "ARGUS_M0_HEALTH_TOKEN": HEALTH_TOKEN,
            "ARGUS_S10_POLICY_SIGNING_KEY": POLICY_SIGNING_KEY,
            "ARGUS_S10_CHECKPOINT_SIGNING_KEY": CHECKPOINT_SIGNING_KEY,
            "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN": CHECKPOINT_SIGNER_AUTH_TOKEN,
            "ARGUS_S10_PRICE_TABLE_SIGNER_KEY_ID": "argus-m0-price-table",
            "ARGUS_S10_PRICE_TABLE_SIGNING_KEY": PRICE_TABLE_SIGNING_KEY,
            "ARGUS_S10_PRICE_TABLE_VERSION": "0.1.0",
            "ARGUS_S10_PRICE_TABLE_ISSUED_AT": "1",
            "ARGUS_S10_PRICE_TABLE_USD_PER_CPU_SECOND": "0.002",
            "ARGUS_S10_PRICE_TABLE_USD_PER_GPU_SECOND": "0",
            "ARGUS_S10_PRICE_TABLE_USD_PER_1K_MODEL_TOKENS": "0.004",
        }
        with patch.dict(os.environ, {**base_env, "ARGUS_S10_PRICE_TABLE_EXPIRES_AT": "4102444800"}, clear=True):
            app = build_s10_app_from_env()
            status, health = app.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )

        self.assertEqual(status, 200)
        self.assertEqual(health["price_table"], "0.1.0")
        self.assertEqual(health["price_table_signer_key_id"], "argus-m0-price-table")
        self.assertEqual(health["resource_meter"], "docker-api-cgroup")
        self.assertLessEqual(health["meter_interval_s"], 5)
        self.assertGreaterEqual(health["meter_gap_halt_s"], health["meter_interval_s"])
        self.assertFalse(health["dcgm_available"])
        self.assertFalse(health["nvidia_smi_available"])
        self.assertEqual(health["gpu_count"], 0)
        self.assertFalse(health["mig_enabled"])
        self.assertEqual(health["mig_instance_count"], 0)
        self.assertFalse(health["dcgm_metric_sampler_enabled"])
        self.assertEqual(health["dcgm_metric_fields"], ["1001", "1004", "1005"])
        self.assertIsNotNone(app.price_table)
        self.assertTrue(app.price_table.signature.startswith("hmac-sha256:"))

        with patch.dict(os.environ, {**base_env, "ARGUS_S10_PRICE_TABLE_EXPIRES_AT": "2"}, clear=True):
            with self.assertRaisesRegex(PriceTableSignatureError, "price table is stale"):
                build_s10_app_from_env()

    def test_s10_env_build_requires_checkpoint_signer_material_and_auth_token(self) -> None:
        base_env = {
            "ARGUS_S10_SIGNING_KEY": "test-s10-signing-key",
            "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
            "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
            "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _runtime_identity_mint_policy_json(),
            "ARGUS_M0_HEALTH_TOKEN": HEALTH_TOKEN,
            "ARGUS_S10_POLICY_SIGNING_KEY": POLICY_SIGNING_KEY,
        }
        with patch.dict(os.environ, base_env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "ARGUS_S10_CHECKPOINT_SIGNING_KEY"):
                build_s10_app_from_env()
        with patch.dict(
            os.environ,
            {**base_env, "ARGUS_S10_CHECKPOINT_SIGNING_KEY": CHECKPOINT_SIGNING_KEY},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN"):
                build_s10_app_from_env()

    def test_s10_checkpoint_signer_route_is_internal_and_s10_owned(self) -> None:
        app = S10SupervisorApp(
            signing_key=b"test-key",
            auth=_runtime_auth(),
            checkpoint_signer=InMemoryS10KmsCheckpointSigner(
                signer_key_id="argus-m0-s8-checkpoint",
                signing_key=CHECKPOINT_SIGNING_KEY.encode("utf-8"),
            ),
            checkpoint_signer_auth_token=CHECKPOINT_SIGNER_AUTH_TOKEN,
        )
        body = {"sequence": 7, "root": "blake3:" + "a" * 64}

        no_auth_status, no_auth_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/internal/s8-checkpoint-signatures",
                query={},
                body=body,
                headers={},
            )
        )
        health_token_status, health_token_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/internal/s8-checkpoint-signatures",
                query={},
                body=body,
                headers=_auth_headers(HEALTH_TOKEN),
            )
        )
        signed_status, signed_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/internal/s8-checkpoint-signatures",
                query={},
                body=body,
                headers=_auth_headers(CHECKPOINT_SIGNER_AUTH_TOKEN),
            )
        )
        unconfigured_app = S10SupervisorApp(
            signing_key=b"test-key",
            auth=_runtime_auth(),
            checkpoint_signer=None,
            checkpoint_signer_auth_token=CHECKPOINT_SIGNER_AUTH_TOKEN,
        )
        missing_signer_status, missing_signer_payload = unconfigured_app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/internal/s8-checkpoint-signatures",
                query={},
                body=body,
                headers=_auth_headers(CHECKPOINT_SIGNER_AUTH_TOKEN),
            )
        )
        tampered_status, tampered_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/internal/s8-checkpoint-signatures",
                query={},
                body={"sequence": 7, "root": "sha256:" + "a" * 64},
                headers=_auth_headers(CHECKPOINT_SIGNER_AUTH_TOKEN),
            )
        )

        self.assertEqual(no_auth_status, 401)
        self.assertEqual(no_auth_payload["error"], "Unauthorized")
        self.assertEqual(health_token_status, 401)
        self.assertEqual(health_token_payload["error"], "Unauthorized")
        self.assertEqual(signed_status, 201)
        self.assertEqual(signed_payload["sequence"], 7)
        self.assertEqual(signed_payload["root"], body["root"])
        self.assertEqual(signed_payload["signer_key_id"], "argus-m0-s8-checkpoint")
        self.assertTrue(signed_payload["signature"].startswith("hmac-sha256:"))
        self.assertEqual(missing_signer_status, 403)
        self.assertEqual(missing_signer_payload["error"], "PermissionError")
        self.assertEqual(missing_signer_payload["message"], "checkpoint signer is not configured")
        self.assertEqual(tampered_status, 400)
        self.assertEqual(tampered_payload["error"], "ValueError")

    def test_s10_store_artifact_rejects_scope_token_from_other_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S10SupervisorApp(
                signing_key=b"test-key",
                artifact_store=FileSystemArtifactStore(tmp),
                artifact_store_path=tmp,
                auth=_runtime_auth(),
            )
            other_scope = app.mint_scope(
                {
                    "job_id": "other-job",
                    "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S2"]},
                }
            )

            status, payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/store/artifacts",
                    query={},
                    body={
                        "scope_token": other_scope,
                        "kind": "model",
                        "payload": {"weights": [1]},
                        "producer": {"subsystem": "S2", "version": "0.0.0"},
                        "lineage": {
                            "input_refs": [],
                            "code_ref": "git:model",
                            "environment_digest": "oci:model",
                        },
                    },
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(status, 403)
            self.assertEqual(payload["error"], "PermissionError")
            self.assertEqual(app.artifacts.record_count, 0)

    def test_s10_revoke_scope_token_denies_brokered_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S10SupervisorApp(
                signing_key=b"test-key",
                artifact_store=FileSystemArtifactStore(tmp),
                artifact_store_path=tmp,
                auth=_runtime_auth(),
            )
            scope_status, scope = app.http.handle(
                JsonRequest(method="POST", path="/v1/scope-tokens", query={}, body={}, headers=_auth_headers())
            )
            revoke_status, revoke = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/tokens:revoke",
                    query={},
                    body={"token_type": "scope", "token": scope},
                    headers=_auth_headers(),
                )
            )
            write_status, write_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/store/artifacts",
                    query={},
                    body={
                        "scope_token": scope,
                        "kind": "model",
                        "payload": {"weights": [1]},
                        "producer": {"subsystem": "S2", "version": "0.0.0"},
                        "lineage": {
                            "input_refs": [],
                            "code_ref": "git:model",
                            "environment_digest": "oci:model",
                        },
                    },
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(scope_status, 201)
            self.assertEqual(revoke_status, 200)
            self.assertEqual(revoke["revoked_token_id"], scope["scope_id"])
            self.assertEqual(write_status, 401)
            self.assertEqual(write_payload["error"], "TokenInvalidError")
            self.assertIn("revoked", write_payload["message"])
            self.assertEqual(app.artifacts.record_count, 0)

    def test_s10_revoke_budget_token_denies_sandbox_launch(self) -> None:
        supervisor = _SuccessfulSupervisor()
        app = S10SupervisorApp(
            signing_key=b"test-key",
            auth=_runtime_auth(),
            docker_supervisor=supervisor,
        )
        launch = _launch_body(app)
        revoke_status, revoke = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/tokens:revoke",
                query={},
                body={"token_type": "budget", "token": launch["budget_token"]},
                headers=_auth_headers(),
            )
        )
        launch_status, launch_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/sandboxes:launch",
                query={},
                body=launch,
                headers=_auth_headers(),
            )
        )

        self.assertEqual(revoke_status, 200)
        self.assertEqual(revoke["revoked_token_id"], launch["budget_token"]["budget_id"])  # type: ignore[index]
        self.assertEqual(launch_status, 401)
        self.assertEqual(launch_payload["error"], "TokenInvalidError")
        self.assertIn("revoked", launch_payload["message"])
        self.assertEqual(supervisor.calls, [])

    def test_s10_supervisor_service_mints_verifiable_tokens(self) -> None:
        app = S10SupervisorApp(signing_key=b"test-key")

        budget = app.mint_budget(
            {
                "job_id": "job-1",
                "root_request_id": "root-1",
                "caps": {"max_wallclock_s": 30, "max_cost_usd": 1},
            }
        )
        scope = app.mint_scope(
            {
                "job_id": "job-1",
                "scopes": {
                    "broker_audiences": ["store"],
                    "producer_subsystems": ["S2"],
                    "sandbox_risk_class": "standard",
                },
            }
        )

        budget_token = BudgetToken(
            **{
                **budget,
                "caps": BudgetCaps(**budget["caps"]),
            }
        )
        scope_token = ScopeToken(
            **{
                **scope,
                "scopes": ScopeGrant(
                    allowed_adapters=tuple(scope["scopes"]["allowed_adapters"]),
                    allowed_datasets=tuple(scope["scopes"]["allowed_datasets"]),
                    egress_allowlist=(),
                    broker_audiences=tuple(scope["scopes"]["broker_audiences"]),
                    capabilities=tuple(scope["scopes"]["capabilities"]),
                    producer_subsystems=tuple(scope["scopes"]["producer_subsystems"]),
                    disallowed_actions=tuple(scope["scopes"]["disallowed_actions"]),
                    sandbox_risk_class=scope["scopes"]["sandbox_risk_class"],
                ),
            }
        )

        self.assertTrue(app.tokens.verify_budget(budget_token).valid)
        self.assertTrue(app.tokens.verify_scope(scope_token).valid)

    def test_s10_supervisor_broker_writes_shared_s8_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S10SupervisorApp(
                signing_key=b"test-key",
                artifact_store=FileSystemArtifactStore(tmp),
                artifact_store_path=tmp,
            )
            scope = app.mint_scope(
                {
                    "job_id": "job-1",
                    "scopes": {
                        "broker_audiences": ["store"],
                        "producer_subsystems": ["S2"],
                    },
                }
            )

            record = app.broker_put_artifact(
                {
                    "scope_token": scope,
                    "kind": "model",
                    "payload": {"weights": [1, 2, 3]},
                    "producer": {"subsystem": "S2", "version": "0.0.0"},
                    "lineage": {
                        "input_refs": [],
                        "code_ref": "git:model",
                        "environment_digest": "oci:model",
                    },
                }
            )
            s8 = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp)
            fetched = s8.get_artifact_record(record["artifact_ref"])

            self.assertEqual(fetched["artifact_ref"], record["artifact_ref"])
            self.assertEqual(fetched["producer"]["job_id"], "job-1")
            self.assertEqual(fetched["lineage"]["job_id"], "job-1")


class ArgusM0ComposeTests(unittest.TestCase):
    def test_compose_config_declares_argus_m0_services(self) -> None:
        compose = Path("deploy/argus-m0/compose.yaml")
        docker = shutil.which("docker")
        if docker is None:
            self._skip_or_fail("docker CLI is unavailable")
        config = subprocess.run(
            [docker, "compose", "-f", str(compose), "config", "--format", "json"],
            check=False,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
                "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
                "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _runtime_identity_mint_policy_json(),
                "ARGUS_M0_HEALTH_TOKEN": HEALTH_TOKEN,
                "ARGUS_S10_TOKEN_ED25519_PRIVATE_KEY_HEX": TOKEN_ED25519_PRIVATE_KEY_HEX,
                "ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX": TOKEN_ED25519_PUBLIC_KEY_HEX,
                "ARGUS_S10_POLICY_SIGNING_KEY": POLICY_SIGNING_KEY,
                "ARGUS_S8_BROKER_WRITE_KEY": BROKER_WRITE_KEY.decode("utf-8"),
                "ARGUS_S10_CHECKPOINT_SIGNING_KEY": CHECKPOINT_SIGNING_KEY,
                "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN": CHECKPOINT_SIGNER_AUTH_TOKEN,
                "ARGUS_S10_PRICE_TABLE_SIGNING_KEY": PRICE_TABLE_SIGNING_KEY,
                "ARGUS_S10_PRICE_TABLE_ISSUED_AT": "1",
                "ARGUS_S10_PRICE_TABLE_EXPIRES_AT": "4102444800",
                "ARGUS_S10_C3_VERIFIER_KEYS_JSON": S10_C3_VERIFIER_KEYS_JSON,
                "ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN": S10_VERIFIER_KEY_AUTH_TOKEN,
                "ARGUS_S3_REFERENCE_REFEREE_SIGNER_SECRET": S3_REFERENCE_REFEREE_SIGNING_KEY,
                "ARGUS_S1_REFERENCE_DEMO_ACCESS_TOKEN": "s1-reference-token",
                "ARGUS_S2_REFERENCE_BUILDER_ACCESS_TOKEN": "s2-reference-token",
                "ARGUS_S3_REFERENCE_REFEREE_ACCESS_TOKEN": "s3-reference-token",
                "ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN": "s7-reference-token",
                "ARGUS_S11_REFERENCE_OBSERVATORY_ACCESS_TOKEN": "s11-reference-token",
            },
        )
        if config.returncode != 0:
            self._skip_or_fail(config.stderr.strip() or "docker compose config failed")

        rendered = json.loads(config.stdout)
        services = rendered["services"]
        self.assertEqual(
            {
                "postgres",
                "minio",
                "s8-writer",
                "s10-supervisor",
                "s1-reference-demo",
                "s2-reference-builder",
                "s3-reference-referee",
                "s7-reference-adapter",
                "s11-reference-observatory",
            },
            set(services),
        )
        self.assertTrue(services["postgres"]["image"].startswith("postgres@sha256:"))
        self.assertTrue(services["minio"]["image"].startswith("minio/minio@sha256:"))
        self.assertEqual(services["s8-writer"]["command"], ["python", "-m", "argus_runtime.s8_writer_service"])
        self.assertEqual(services["s10-supervisor"]["command"], ["python", "-m", "argus_runtime.s10_supervisor_service"])
        self.assertEqual(
            services["s1-reference-demo"]["command"],
            ["python", "-m", "argus_runtime.s1_reference_demo_service", "--serve"],
        )
        self.assertEqual(
            services["s2-reference-builder"]["command"],
            ["python", "-m", "argus_runtime.s2_reference_builder_service"],
        )
        self.assertEqual(
            services["s3-reference-referee"]["command"],
            ["python", "-m", "argus_runtime.s3_reference_referee_service"],
        )
        self.assertEqual(
            services["s7-reference-adapter"]["command"],
            ["python", "-m", "argus_runtime.s7_reference_adapter_service"],
        )
        self.assertEqual(
            services["s11-reference-observatory"]["command"],
            ["python", "-m", "argus_runtime.s11_reference_observatory_service"],
        )
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_HOST"], "0.0.0.0")
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_POSTGRES_DSN"],
            "postgresql://argus:argus-dev-password@postgres:5432/argus",
        )
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_POSTGRES_ROLE"], "argus_s8_ledger_writer")
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_RUST_LEDGER_WRITER_CMD"],
            "/usr/local/bin/argus-s8-ledger-writer",
        )
        self.assertNotIn("ARGUS_S8_REQUIRE_RUST_LEDGER_WRITER", services["s8-writer"]["environment"])
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_CHECKPOINT_SIGNER_URL"],
            "http://s10-supervisor:8080/v1/internal/s8-checkpoint-signatures",
        )
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_CHECKPOINT_SIGNER_AUTH_TOKEN"],
            CHECKPOINT_SIGNER_AUTH_TOKEN,
        )
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_ALLOW_INSECURE_CHECKPOINT_SIGNER"],
            "1",
        )
        self.assertNotIn("ARGUS_S8_CHECKPOINT_SIGNING_KEY", services["s8-writer"]["environment"])
        self.assertNotIn("ARGUS_S8_CHECKPOINT_SIGNER_KEY_ID", services["s8-writer"]["environment"])
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_REQUIRE_REPORT_VERIFIER"], "1")
        self.assertNotIn("ARGUS_S8_C3_VERIFIER_KEYS_JSON", services["s8-writer"]["environment"])
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_S10_VERIFIER_KEYS_URL"],
            "http://s10-supervisor:8080/v1/internal/verifier-keys",
        )
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_S10_VERIFIER_KEY_AUTH_TOKEN"],
            S10_VERIFIER_KEY_AUTH_TOKEN,
        )
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_ALLOW_INSECURE_VERIFIER_KEY_STORE"],
            "1",
        )
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_MINIO_ENDPOINT"], "minio:9000")
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_MINIO_BUCKET"], "argus-s8-objects")
        self.assertNotIn("ARGUS_S8_DATA_DIR", services["s8-writer"]["environment"])
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_HOST"], "0.0.0.0")
        self.assertEqual(services["s1-reference-demo"]["environment"]["ARGUS_S1_REFERENCE_DEMO_HOST"], "0.0.0.0")
        self.assertEqual(services["s1-reference-demo"]["environment"]["ARGUS_S1_REFERENCE_DEMO_PORT"], "8080")
        self.assertEqual(
            services["s1-reference-demo"]["environment"]["ARGUS_S1_REFERENCE_DEMO_S7_URL"],
            "http://s7-reference-adapter:8080",
        )
        self.assertEqual(
            services["s1-reference-demo"]["environment"]["ARGUS_S1_REFERENCE_DEMO_S2_URL"],
            "http://s2-reference-builder:8080",
        )
        self.assertEqual(
            services["s1-reference-demo"]["environment"]["ARGUS_S1_REFERENCE_DEMO_S3_URL"],
            "http://s3-reference-referee:8080",
        )
        self.assertEqual(
            services["s1-reference-demo"]["environment"]["ARGUS_S1_REFERENCE_DEMO_S11_URL"],
            "http://s11-reference-observatory:8080",
        )
        self.assertEqual(services["s1-reference-demo"]["environment"]["ARGUS_SCHEMA_ROOT"], "/app/schemas")
        self.assertEqual(
            services["s2-reference-builder"]["environment"]["ARGUS_S2_REFERENCE_BUILDER_S10_URL"],
            "http://s10-supervisor:8080",
        )
        self.assertEqual(
            services["s2-reference-builder"]["environment"]["ARGUS_S2_REFERENCE_BUILDER_S8_URL"],
            "http://s8-writer:8080",
        )
        self.assertEqual(
            services["s2-reference-builder"]["environment"]["ARGUS_S2_REFERENCE_BUILDER_REQUIRE_S1_REQUESTER"],
            "1",
        )
        self.assertEqual(services["s3-reference-referee"]["environment"]["ARGUS_S3_REFERENCE_REFEREE_HOST"], "0.0.0.0")
        self.assertEqual(services["s3-reference-referee"]["environment"]["ARGUS_S3_REFERENCE_REFEREE_PORT"], "8080")
        self.assertEqual(
            services["s3-reference-referee"]["environment"]["ARGUS_S3_REFERENCE_REFEREE_S10_URL"],
            "http://s10-supervisor:8080",
        )
        self.assertEqual(
            services["s3-reference-referee"]["environment"]["ARGUS_S3_REFERENCE_REFEREE_S8_URL"],
            "http://s8-writer:8080",
        )
        self.assertEqual(
            services["s3-reference-referee"]["environment"]["ARGUS_S3_REFERENCE_REFEREE_SIGNER_KEY_ID"],
            "s3-reference-referee-key",
        )
        self.assertEqual(
            services["s3-reference-referee"]["environment"]["ARGUS_S3_REFERENCE_REFEREE_SIGNER_SECRET"],
            S3_REFERENCE_REFEREE_SIGNING_KEY,
        )
        self.assertEqual(
            services["s3-reference-referee"]["environment"]["ARGUS_S3_REFERENCE_REFEREE_REQUIRE_S1_REQUESTER"],
            "1",
        )
        self.assertEqual(
            services["s7-reference-adapter"]["environment"]["ARGUS_S7_REFERENCE_ADAPTER_S10_URL"],
            "http://s10-supervisor:8080",
        )
        self.assertEqual(
            services["s11-reference-observatory"]["environment"]["ARGUS_S11_REFERENCE_OBSERVATORY_S8_URL"],
            "http://s8-writer:8080",
        )
        self.assertEqual(services["s8-writer"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(services["s10-supervisor"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(services["s1-reference-demo"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(services["s2-reference-builder"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(services["s3-reference-referee"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertNotIn("ports", services["s7-reference-adapter"])
        self.assertNotIn("ports", services["s11-reference-observatory"])
        self.assertNotIn("volumes", services["s8-writer"])
        self.assertIn("ARGUS_RUNTIME_BOOTSTRAP_TOKEN", services["s8-writer"]["environment"])
        self.assertIn("ARGUS_RUNTIME_IDENTITY_SIGNING_KEY", services["s8-writer"]["environment"])
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], HEALTH_TOKEN)
        self.assertNotEqual(services["s8-writer"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], BOOTSTRAP_TOKEN)
        self.assertIn("ARGUS_RUNTIME_BOOTSTRAP_TOKEN", services["s10-supervisor"]["environment"])
        self.assertIn("ARGUS_RUNTIME_IDENTITY_SIGNING_KEY", services["s10-supervisor"]["environment"])
        self.assertIn("ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON", services["s10-supervisor"]["environment"])
        reference_service_credentials = {
            "s1-reference-demo": ("ARGUS_S1_REFERENCE_DEMO_ACCESS_TOKEN", "s1-reference-token"),
            "s2-reference-builder": ("ARGUS_S2_REFERENCE_BUILDER_ACCESS_TOKEN", "s2-reference-token"),
            "s3-reference-referee": ("ARGUS_S3_REFERENCE_REFEREE_ACCESS_TOKEN", "s3-reference-token"),
            "s7-reference-adapter": ("ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN", "s7-reference-token"),
            "s11-reference-observatory": ("ARGUS_S11_REFERENCE_OBSERVATORY_ACCESS_TOKEN", "s11-reference-token"),
        }
        for service_name, (credential_name, credential_value) in reference_service_credentials.items():
            environment = services[service_name]["environment"]
            self.assertNotIn("ARGUS_RUNTIME_BOOTSTRAP_TOKEN", environment)
            self.assertEqual(environment[credential_name], credential_value)
        self.assertEqual(
            services["s3-reference-referee"]["environment"]["ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN"],
            S10_VERIFIER_KEY_AUTH_TOKEN,
        )
        self.assertNotIn("ARGUS_S3_REFERENCE_REFEREE_SIGNER_SECRET", services["s8-writer"]["environment"])
        self.assertNotIn("ARGUS_S3_REFERENCE_REFEREE_SIGNER_SECRET", services["s10-supervisor"]["environment"])
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], HEALTH_TOKEN)
        self.assertNotEqual(services["s10-supervisor"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], BOOTSTRAP_TOKEN)
        self.assertIn("ARGUS_S8_BROKER_WRITE_KEY", services["s8-writer"]["environment"])
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S8_BROKER_URL"],
            "http://s8-writer:8080/v1/internal/brokered-artifacts",
        )
        self.assertIn("ARGUS_S8_BROKER_WRITE_KEY", services["s10-supervisor"]["environment"])
        self.assertNotIn("ARGUS_S10_SIGNING_KEY", services["s10-supervisor"]["environment"])
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_TOKEN_SIGNING_MODE"], "ed25519")
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_TOKEN_SIGNER_KEY_ID"],
            "argus-m0-token-root",
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_TOKEN_ED25519_PRIVATE_KEY_HEX"],
            TOKEN_ED25519_PRIVATE_KEY_HEX,
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX"],
            TOKEN_ED25519_PUBLIC_KEY_HEX,
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_TOKEN_REVOCATION_STORE_PATH"],
            "/var/lib/argus/s10/token-revocations.jsonl",
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_QUOTA_POSTGRES_DSN"],
            "postgresql://argus:argus-dev-password@postgres:5432/argus",
        )
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_APPLY_MIGRATIONS"], "1")
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_MIGRATIONS_DIR"], "/app/db/s10")
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_PRICE_TABLE_SIGNER_KEY_ID"],
            "argus-m0-price-table",
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_PRICE_TABLE_SIGNING_KEY"],
            PRICE_TABLE_SIGNING_KEY,
        )
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_PRICE_TABLE_VERSION"], "0.1.0")
        self.assertIn("ARGUS_S10_PRICE_TABLE_ISSUED_AT", services["s10-supervisor"]["environment"])
        self.assertIn("ARGUS_S10_PRICE_TABLE_EXPIRES_AT", services["s10-supervisor"]["environment"])
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_PRICE_TABLE_USD_PER_CPU_SECOND"],
            "0.002",
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_PRICE_TABLE_USD_PER_GPU_SECOND"],
            "0",
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_PRICE_TABLE_USD_PER_1K_MODEL_TOKENS"],
            "0.004",
        )
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_METER_INTERVAL_S"], "1.0")
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_METER_GAP_HALT_S"], "5.0")
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_POLICY_SIGNING_KEY"], POLICY_SIGNING_KEY)
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_CHECKPOINT_SIGNER_KEY_ID"],
            "argus-m0-s8-checkpoint",
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_CHECKPOINT_SIGNING_KEY"],
            CHECKPOINT_SIGNING_KEY,
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN"],
            CHECKPOINT_SIGNER_AUTH_TOKEN,
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_C3_VERIFIER_KEYS_JSON"],
            S10_C3_VERIFIER_KEYS_JSON,
        )
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN"],
            S10_VERIFIER_KEY_AUTH_TOKEN,
        )
        s10_volumes = services["s10-supervisor"].get("volumes", [])
        self.assertEqual(
            sorted(volume["target"] for volume in s10_volumes),
            ["/var/lib/argus/s10", "/var/run/docker.sock"],
        )
        self.assertEqual(s10_volumes[0]["source"], "/var/run/docker.sock")
        self.assertIn("postgres", services["s10-supervisor"]["depends_on"])
        self.assertIn("s8-writer", services["s1-reference-demo"]["depends_on"])
        self.assertIn("s10-supervisor", services["s1-reference-demo"]["depends_on"])
        self.assertIn("s8-writer", services["s3-reference-referee"]["depends_on"])
        self.assertIn("s10-supervisor", services["s3-reference-referee"]["depends_on"])
        self.assertIn("s7-reference-adapter", services["s1-reference-demo"]["depends_on"])
        self.assertIn("s11-reference-observatory", services["s1-reference-demo"]["depends_on"])
        self.assertIn("s3-reference-referee", services["s1-reference-demo"]["depends_on"])
        self.assertNotIn("s8-data", rendered["volumes"])
        self.assertIn("postgres-data", rendered["volumes"])
        self.assertIn("minio-data", rendered["volumes"])
        dockerfile = Path("deploy/argus-m0/python-service.Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY schemas ./schemas", dockerfile)
        self.assertIn("--bin argus-s3-report-signer", dockerfile)
        self.assertIn("/usr/local/bin/argus-s3-report-signer", dockerfile)

    def _skip_or_fail(self, reason: str) -> None:
        if os.environ.get("ARGUS_REQUIRE_DOCKER_TESTS") == "1":
            raise AssertionError(reason)
        raise unittest.SkipTest(reason)


def _runtime_auth() -> RuntimeAuth:
    return RuntimeAuth(
        {
            AUTH_TOKEN: RuntimeIdentity(
                caller_id="test-caller",
                job_id="job-auth",
                root_request_id="root-auth",
                scopes=ScopeGrant(broker_audiences=("store",), producer_subsystems=("S2",)),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            )
        }
    )


def _s8_runtime_auth() -> RuntimeAuth:
    return RuntimeAuth(
        {
            AUTH_TOKEN: RuntimeIdentity(
                caller_id="test-caller",
                job_id="job-auth",
                root_request_id="root-auth",
                scopes=ScopeGrant(
                    broker_audiences=("store",),
                    capabilities=("s8.read", "s8.reproducibility.write"),
                    producer_subsystems=("S2",),
                ),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            ),
            S8_READ_TOKEN: RuntimeIdentity(
                caller_id="test-s8-read",
                job_id="job-read",
                root_request_id="root-read",
                scopes=ScopeGrant(capabilities=("s8.read",)),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            ),
            S8_REPRO_WRITE_TOKEN: RuntimeIdentity(
                caller_id="test-s8-repro-write",
                job_id="job-repro-write",
                root_request_id="root-repro-write",
                scopes=ScopeGrant(capabilities=("s8.reproducibility.write",)),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            ),
            S8_DATASET_WRITE_TOKEN: RuntimeIdentity(
                caller_id="test-s8-dataset-write",
                job_id="job-dataset-write",
                root_request_id="root-dataset-write",
                scopes=ScopeGrant(capabilities=("s8.dataset.write", "s8.read")),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            ),
            S8_VERIFIER_LABEL_READ_TOKEN: RuntimeIdentity(
                caller_id="test-s8-verifier-label-read",
                job_id="job-verifier-label-read",
                root_request_id="root-verifier-label-read",
                scopes=ScopeGrant(capabilities=("s8.read", "s8.verifier-labels.read")),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            ),
            S8_BROKER_AUDIENCE_ONLY_READ_TOKEN: RuntimeIdentity(
                caller_id="test-s8-broker-audience-only-read",
                job_id="job-broker-only-read",
                root_request_id="root-broker-only-read",
                scopes=ScopeGrant(broker_audiences=("s8.read",)),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            ),
        }
    )


def _signed_runtime_auth() -> RuntimeAuth:
    return RuntimeAuth.with_signed_identities(
        bootstrap_token=BOOTSTRAP_TOKEN,
        identity_signing_key=IDENTITY_SIGNING_KEY,
    )


def _runtime_identity_mint_policy() -> RuntimeIdentityMintPolicy:
    return RuntimeIdentityMintPolicy.from_json(_runtime_identity_mint_policy_json())


def _runtime_identity_mint_policy_json() -> str:
    return json.dumps(
        {
            "sandbox-1": {
                "job_id": "job-launch",
                "root_request_id": "root-launch",
                "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 30, "max_cost_usd": 5},
                "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S2"]},
                "max_ttl_s": 300,
            }
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _signed_report_payload() -> dict[str, object]:
    return {
        "report_id": "vr-runtime-test",
        "profile_ref": "c4://profile/runtime-test/v1",
        "frozen_pipeline_ref": "c4://pipeline/runtime-test/baseline",
        "checks": [{"check": "INJECTION", "status": "PASS"}],
        "aggregate": {"passed": True, "score": 0.99},
        "claim_tier": "recapitulated-known",
        "claim_tier_is_candidate": False,
        "signature": {
            "algorithm": "placeholder",
            "key_id": "placeholder",
            "value": "placeholder",
        },
    }


class _SuccessfulSupervisor(DockerSandboxSupervisor):
    def __init__(
        self,
        *,
        usage: BudgetUsage | None = None,
        stdout: str = "Iface Destination Gateway\\nno-default-route\\nARGUS_UID=65532\\nVISIBLE=ok\\n",
    ) -> None:
        super().__init__(meter_interval_s=0.2)
        self.calls: list[dict[str, object]] = []
        self._usage = usage or BudgetUsage(wallclock_s=0.1)
        self._stdout = stdout

    def run(self, *, handle, request, materialized_env, meter_sample_sink=None):  # type: ignore[no-untyped-def]
        self.calls.append({"handle": handle, "request": request, "materialized_env": dict(materialized_env)})
        if meter_sample_sink is not None:
            meter_sample_sink(
                s10_module.ResourceMeterSample(
                    sample_seq=1,
                    elapsed_s=max(self._usage.wallclock_s, 0.1),
                    cadence_s=0.0,
                    usage=self._usage,
                    source="test-successful-supervisor",
                )
            )
        return SandboxExecutionResult(
            handle=handle,
            exit_code=0,
            stdout=self._stdout,
            stderr="",
            timed_out=False,
            duration_s=max(self._usage.wallclock_s, 0.1),
            budget_usage=self._usage,
        )


def _launch_body(app: S10SupervisorApp) -> dict[str, object]:
    budget_status, budget = app.http.handle(
        JsonRequest(method="POST", path="/v1/budget-tokens", query={}, body={}, headers=_auth_headers())
    )
    scope_status, scope = app.http.handle(
        JsonRequest(method="POST", path="/v1/scope-tokens", query={}, body={}, headers=_auth_headers())
    )
    if budget_status != 201 or scope_status != 201:
        raise AssertionError(f"failed to mint launch tokens: {budget_status=} {scope_status=}")
    return {
        "job_id": "job-auth",
        "subagent_id": "subagent-http",
        "trace_id": "trace-http",
        "budget_token": budget,
        "scope_token": scope,
        "image": "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662",
        "entrypoint": ["/bin/sh"],
        "args": ["-c", "echo no-default-route"],
        "env": {"VISIBLE": "ok", "SECRET_TOKEN": "hidden"},
        "env_allowlist": ["VISIBLE"],
        "requested_envelope": {
            "cpu_m": 500,
            "mem_bytes": 64 * 1024 * 1024,
            "gpu_count": 0,
            "wallclock_s": 1,
            "scratch_bytes": 1024 * 1024,
            "pids": 16,
            "estimated_cost_usd": 0,
        },
        "runtime_class_hint": "auto",
        "policy_pin": None,
    }


def _auth_headers(token: str = AUTH_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _broker_write_headers(body: dict[str, object]) -> dict[str, str]:
    signature = hmac.new(BROKER_WRITE_KEY, canonical_json_bytes(body), sha256).hexdigest()
    return {"X-Argus-Store-Write-Signature": f"hmac-sha256:{signature}"}


if __name__ == "__main__":
    unittest.main()
