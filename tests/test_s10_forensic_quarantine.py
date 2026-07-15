from __future__ import annotations

import base64
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from argus_core import (
    BudgetCaps,
    ForensicHostCapture,
    FileForensicCaptureSpool,
    ForensicSnapshotCaptureError,
    ForensicSnapshotPersistenceError,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    Lineage,
    Producer,
    QuarantineSnapshotPendingError,
    QuarantineWorkflow,
    ScopeGrant,
    DockerSandboxSupervisor,
    hash_bytes,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest
from argus_runtime.s10_supervisor_service import (
    HttpSecurityPager,
    S8BrokeredArtifactStoreClient,
    S10SupervisorApp,
    SecurityPagerDeliveryError,
)


IMAGE_DIGEST = "sha256:" + "a" * 64


def _request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: object | None = None,
) -> JsonRequest:
    return JsonRequest(
        method=method,
        path=path,
        query={},
        body=body,
        headers={"authorization": f"Bearer {token}"} if token is not None else {},
    )


def _launch_request() -> LaunchRequest:
    tokens = InMemoryTokenService(signing_key=b"s10-forensic-test")
    budget = tokens.mint_budget(
        caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
        job_id="job-forensic-1",
        root_request_id="root-forensic-1",
    )
    scope = tokens.mint_scope(
        job_id="job-forensic-1",
        scopes=ScopeGrant(sandbox_risk_class="standard"),
    )
    return LaunchRequest(
        job_id="job-forensic-1",
        subagent_id="s2-builder",
        trace_id="trace-forensic-1",
        budget_token=budget,
        scope_token=scope,
        image=IMAGE_DIGEST,
        entrypoint=("python",),
        args=("-c", "print('forensic')"),
        env={},
        env_allowlist=(),
        requested_envelope=LaunchEnvelope(
            cpu_m=100,
            mem_bytes=16 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=2,
            scratch_bytes=1024 * 1024,
            pids=8,
        ),
    )


def _capture() -> ForensicHostCapture:
    scratch = b"real-tar-archive-bytes"
    return ForensicHostCapture(
        captured_at="2026-07-15T00:00:00Z",
        container_id="c" * 64,
        image_digest=IMAGE_DIGEST,
        rootfs_evidence={
            "image_digest": IMAGE_DIGEST,
            "read_only": True,
            "runtime": "runsc-argus",
            "container_image_id": "sha256:" + "b" * 64,
        },
        scratch_archive=scratch,
        scratch_archive_hash=hash_bytes(scratch),
        network_mode="none",
        network_events=(),
    )


def _seed_inputs(store: InMemoryArtifactStore, audit: InMemoryAuditLedger) -> tuple[str, str]:
    launch = store.create_artifact(
        kind="container",
        payload={"schema": "argus.s10.launch.v1", "job_id": "job-forensic-1"},
        producer=Producer(subsystem="S10", version="1", job_id="job-forensic-1"),
        lineage=Lineage(
            input_refs=(),
            code_ref=IMAGE_DIGEST,
            environment_digest="blake3:" + "1" * 64,
            job_id="job-forensic-1",
        ),
    )
    partial = store.create_artifact(
        kind="sandbox.partial_result",
        payload={"schema": "argus.s10.partial_result.v1", "job_id": "job-forensic-1"},
        producer=Producer(subsystem="S10", version="1", job_id="job-forensic-1"),
        lineage=Lineage(
            input_refs=(launch.artifact_ref,),
            code_ref=IMAGE_DIGEST,
            environment_digest="blake3:" + "2" * 64,
            job_id="job-forensic-1",
        ),
    )
    audit.bind_trace(job_id="job-forensic-1", trace_id="trace-forensic-1")
    audit.append(
        "trustwrite.detected",
        {
            "job_id": "job-forensic-1",
            "sandbox_id": "sandbox-forensic-1",
            "severity": "Sev-1",
            "event_id": "security-event-1",
        },
    )
    return launch.artifact_ref, partial.artifact_ref


class _BlockingArtifactStore(InMemoryArtifactStore):
    def __init__(self) -> None:
        super().__init__()
        self.snapshot_write_started = threading.Event()
        self.allow_snapshot_write = threading.Event()

    def create_artifact(self, **kwargs: object):  # type: ignore[no-untyped-def]
        if kwargs.get("kind") == "sandbox.forensic.rootfs":
            self.snapshot_write_started.set()
            if not self.allow_snapshot_write.wait(timeout=5):
                raise TimeoutError("test did not release the snapshot writer")
        return super().create_artifact(**kwargs)


class QuarantineWorkflowTests(unittest.TestCase):
    def test_file_spool_round_trips_frozen_bytes_across_process_instances(self) -> None:
        with TemporaryDirectory() as temp_dir:
            first = FileForensicCaptureSpool(temp_dir)
            spool_ref = first.put("quarantine-1", _capture())
            second = FileForensicCaptureSpool(temp_dir)

            self.assertEqual(spool_ref, second.spool_ref("quarantine-1"))
            self.assertEqual(second.pending_quarantine_ids(), ("quarantine-1",))
            self.assertEqual(second.get("quarantine-1"), _capture())
            second.acknowledge_durable("quarantine-1")
            self.assertEqual(second.pending_quarantine_ids(), ())

    def test_file_spool_health_scan_rejects_tampered_frozen_bytes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            spool = FileForensicCaptureSpool(temp_dir)
            spool.put("quarantine-1", _capture())
            capture_dir = next(Path(temp_dir).iterdir())
            (capture_dir / "scratch.bin").write_bytes(b"tampered")

            with self.assertRaisesRegex(
                ForensicSnapshotPersistenceError,
                "scratch (size|bytes)",
            ):
                spool.pending_quarantine_ids()

    def test_pending_record_cannot_close_then_durable_components_resolve_and_close(self) -> None:
        store = InMemoryArtifactStore()
        audit = InMemoryAuditLedger()
        pages: list[dict[str, object]] = []
        launch_ref, partial_ref = _seed_inputs(store, audit)
        workflow = QuarantineWorkflow(
            artifact_store=store,
            audit_ledger=audit,
            page_sink=lambda payload: pages.append(dict(payload)),
        )

        pending = workflow.open(
            job_id="job-forensic-1",
            sandbox_id="sandbox-forensic-1",
            reason="trust_path_write",
            severity="Sev-1",
            launch_provenance_ref=launch_ref,
            partial_result_ref=partial_ref,
            security_event_ids=("security-event-1",),
        )

        self.assertEqual(pending.snapshot_status, "pending")
        self.assertEqual(pending.snapshot_refs, ())
        self.assertEqual(len(pages), 1)
        with self.assertRaises(QuarantineSnapshotPendingError):
            workflow.close(
                pending.quarantine_id,
                reviewer="security-engineer@example.com",
                disposition="confirmed-and-contained",
            )

        durable = workflow.persist_snapshot(pending.quarantine_id, _capture())

        self.assertEqual(durable.snapshot_status, "durable")
        self.assertEqual(len(durable.snapshot_refs), 3)
        self.assertIsNotNone(durable.audit_slice_ref)
        component_payloads = [
            json.loads(store.get_artifact(ref).decode("utf-8")) for ref in durable.snapshot_refs
        ]
        self.assertEqual(
            [payload["component"] for payload in component_payloads],
            ["rootfs", "scratch", "netlog"],
        )
        scratch_payload = component_payloads[1]
        self.assertEqual(base64.b64decode(scratch_payload["archive_b64"]), _capture().scratch_archive)
        audit_slice = json.loads(store.get_artifact(durable.audit_slice_ref or "").decode("utf-8"))
        self.assertTrue(audit_slice["chain_verification"]["intact"])
        self.assertIn(
            "trustwrite.detected",
            [event["event_type"] for event in audit_slice["events"]],
        )

        closed = workflow.close(
            pending.quarantine_id,
            reviewer="security-engineer@example.com",
            disposition="confirmed-and-contained",
        )

        self.assertEqual(closed.status, "closed")
        self.assertEqual(closed.snapshot_refs, durable.snapshot_refs)
        self.assertEqual(
            workflow.close(
                pending.quarantine_id,
                reviewer="security-engineer@example.com",
                disposition="confirmed-and-contained",
            ),
            closed,
        )
        self.assertTrue(audit.verify_chain().valid)

    def test_audit_slice_preserves_interleaved_shared_ledger_events(self) -> None:
        store = InMemoryArtifactStore()
        audit = InMemoryAuditLedger()
        launch_ref, partial_ref = _seed_inputs(store, audit)
        workflow = QuarantineWorkflow(
            artifact_store=store,
            audit_ledger=audit,
            page_sink=lambda _payload: None,
        )
        pending = workflow.open(
            job_id="job-forensic-1",
            sandbox_id="sandbox-forensic-1",
            reason="trust_path_write",
            severity="Sev-1",
            launch_provenance_ref=launch_ref,
            partial_result_ref=partial_ref,
            security_event_ids=("security-event-1",),
        )
        foreign = audit.append("other.job.event", {"job_id": "job-other"})
        relevant = audit.append(
            "sandbox.freeze",
            {"job_id": "job-forensic-1", "sandbox_id": "sandbox-forensic-1"},
        )

        durable = workflow.persist_snapshot(pending.quarantine_id, _capture())
        payload = json.loads(store.get_artifact(durable.audit_slice_ref or "").decode("utf-8"))
        sequences = [event["sequence"] for event in payload["events"]]

        self.assertEqual(
            sequences,
            list(range(payload["from_sequence"], payload["to_sequence"] + 1)),
        )
        self.assertIn(foreign.sequence, sequences)
        self.assertNotIn(foreign.sequence, payload["relevant_event_sequences"])
        self.assertIn(relevant.sequence, payload["relevant_event_sequences"])

    def test_close_rejects_tampered_c4_record_metadata(self) -> None:
        store = InMemoryArtifactStore()
        audit = InMemoryAuditLedger()
        launch_ref, partial_ref = _seed_inputs(store, audit)
        workflow = QuarantineWorkflow(
            artifact_store=store,
            audit_ledger=audit,
            page_sink=lambda _payload: None,
        )
        pending = workflow.open(
            job_id="job-forensic-1",
            sandbox_id="sandbox-forensic-1",
            reason="trust_path_write",
            severity="Sev-1",
            launch_provenance_ref=launch_ref,
            partial_result_ref=partial_ref,
            security_event_ids=("security-event-1",),
        )
        durable = workflow.persist_snapshot(pending.quarantine_id, _capture())
        rootfs_ref = durable.snapshot_refs[0]
        store._records[rootfs_ref] = replace(  # noqa: SLF001
            store._records[rootfs_ref],  # noqa: SLF001
            kind="model",
        )

        with self.assertRaises(QuarantineSnapshotPendingError):
            workflow.close(
                pending.quarantine_id,
                reviewer="security-engineer@example.com",
                disposition="contained",
            )

    def test_close_during_real_write_once_persistence_is_refused_until_commit_finishes(self) -> None:
        store = _BlockingArtifactStore()
        audit = InMemoryAuditLedger()
        launch_ref, partial_ref = _seed_inputs(store, audit)
        workflow = QuarantineWorkflow(
            artifact_store=store,
            audit_ledger=audit,
            page_sink=lambda _payload: None,
        )
        pending = workflow.open(
            job_id="job-forensic-1",
            sandbox_id="sandbox-forensic-1",
            reason="escape_attempt",
            severity="Sev-1",
            launch_provenance_ref=launch_ref,
            partial_result_ref=partial_ref,
            security_event_ids=("security-event-1",),
        )
        result: list[object] = []

        thread = threading.Thread(
            target=lambda: result.append(workflow.persist_snapshot(pending.quarantine_id, _capture())),
            daemon=True,
        )
        thread.start()
        self.assertTrue(store.snapshot_write_started.wait(timeout=2))
        with self.assertRaises(QuarantineSnapshotPendingError):
            workflow.close(
                pending.quarantine_id,
                reviewer="security-engineer@example.com",
                disposition="contained",
            )
        store.allow_snapshot_write.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        self.assertEqual(workflow.get(pending.quarantine_id).snapshot_status, "durable")
        self.assertEqual(
            workflow.close(
                pending.quarantine_id,
                reviewer="security-engineer@example.com",
                disposition="contained",
            ).status,
            "closed",
        )


class DockerForensicCaptureTests(unittest.TestCase):
    def test_frozen_capture_attests_read_only_rootfs_and_archives_real_scratch_bytes(self) -> None:
        supervisor = DockerSandboxSupervisor()
        request = _launch_request()
        scratch_archive = b"ustar-real-scratch"
        inspected = {
            "Id": "c" * 64,
            "Image": "sha256:" + "b" * 64,
            "Config": {
                "Image": request.image,
                "Labels": {
                    "argus.dev/job-id": request.job_id,
                    "argus.dev/sandbox-id": "sandbox-forensic-1",
                },
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Runtime": "runsc-argus",
                "NetworkMode": "none",
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=1048576"},
            },
        }
        with (
            mock.patch.object(supervisor, "_docker_api_request", return_value=inspected),
            mock.patch.object(
                supervisor,
                "_docker_api_request_bytes_limited",
                return_value=(scratch_archive, False),
            ),
        ):
            capture = supervisor._capture_forensic_host_state(  # noqa: SLF001
                container_id="c" * 64,
                request=request,
            )

        self.assertTrue(capture.rootfs_evidence["read_only"])
        self.assertEqual(capture.rootfs_evidence["image_digest"], request.image)
        self.assertEqual(capture.scratch_archive, scratch_archive)
        self.assertEqual(capture.scratch_archive_hash, hash_bytes(scratch_archive))

    def test_truncated_scratch_archive_fails_without_claiming_a_snapshot(self) -> None:
        supervisor = DockerSandboxSupervisor()
        request = _launch_request()
        inspected = {
            "Id": "c" * 64,
            "Image": "sha256:" + "b" * 64,
            "Config": {"Image": request.image, "Labels": {"argus.dev/job-id": request.job_id}},
            "HostConfig": {"ReadonlyRootfs": True, "Runtime": "runsc-argus", "NetworkMode": "none"},
        }
        with (
            mock.patch.object(supervisor, "_docker_api_request", return_value=inspected),
            mock.patch.object(
                supervisor,
                "_docker_api_request_bytes_limited",
                return_value=(b"partial", True),
            ),
            self.assertRaises(ForensicSnapshotCaptureError),
        ):
            supervisor._capture_forensic_host_state(  # noqa: SLF001
                container_id="c" * 64,
                request=request,
            )

    def test_capture_rejects_docker_inspect_for_a_different_container(self) -> None:
        supervisor = DockerSandboxSupervisor()
        request = _launch_request()
        inspected = {
            "Id": "d" * 64,
            "Image": "sha256:" + "b" * 64,
            "Config": {"Image": request.image, "Labels": {"argus.dev/job-id": request.job_id}},
            "HostConfig": {"ReadonlyRootfs": True, "Runtime": "runsc-argus", "NetworkMode": "none"},
        }
        with (
            mock.patch.object(supervisor, "_docker_api_request", return_value=inspected),
            mock.patch.object(supervisor, "_docker_api_request_bytes_limited") as archive,
            self.assertRaises(ForensicSnapshotCaptureError),
        ):
            supervisor._capture_forensic_host_state(  # noqa: SLF001
                container_id="c" * 64,
                request=request,
            )
        archive.assert_not_called()


class QuarantineApiTests(unittest.TestCase):
    def setUp(self) -> None:
        identity = RuntimeIdentity(
            caller_id="worker-1",
            job_id="job-forensic-1",
            root_request_id="root-forensic-1",
            scopes=ScopeGrant(),
            budget_caps=BudgetCaps(),
        )
        self.app = S10SupervisorApp(
            signing_key=b"s10-quarantine-api",
            artifact_store=InMemoryArtifactStore(),
            audit_ledger=InMemoryAuditLedger(),
            quota_ledger=InMemoryQuotaLedger(),
            auth=RuntimeAuth({"runtime-token": identity}),
            quarantine_review_token="review-token",
            quarantine_page_sink=lambda _payload: None,
        )
        launch_ref, partial_ref = _seed_inputs(self.app.artifacts, self.app.audit)
        self.pending = self.app.quarantine_workflow.open(
            job_id="job-forensic-1",
            sandbox_id="sandbox-forensic-1",
            reason="trust_path_write",
            severity="Sev-1",
            launch_provenance_ref=launch_ref,
            partial_result_ref=partial_ref,
            security_event_ids=("security-event-1",),
        )

    def test_review_api_is_separately_authenticated_and_returns_conflict_while_pending(self) -> None:
        path = f"/v1/quarantine/{self.pending.quarantine_id}"
        unauthenticated = self.app.http.handle(_request("GET", path))
        runtime_identity = self.app.http.handle(_request("GET", path, token="runtime-token"))
        pending = self.app.http.handle(_request("GET", path, token="review-token"))
        close_pending = self.app.http.handle(
            _request(
                "POST",
                path + "/close",
                token="review-token",
                body={"reviewer": "sec@example.com", "disposition": "contained"},
            )
        )

        self.assertEqual(unauthenticated[0], 401)
        self.assertEqual(runtime_identity[0], 401)
        self.assertEqual(pending[0], 200)
        self.assertEqual(pending[1]["snapshot_status"], "pending")
        self.assertEqual(close_pending[0], 409)
        self.assertEqual(close_pending[1]["error"], "QuarantineSnapshotPendingError")

        self.app.quarantine_workflow.persist_snapshot(self.pending.quarantine_id, _capture())
        closed = self.app.http.handle(
            _request(
                "POST",
                path + "/close",
                token="review-token",
                body={"reviewer": "sec@example.com", "disposition": "contained"},
            )
        )

        self.assertEqual(closed[0], 200)
        self.assertEqual(closed[1]["status"], "closed")
        self.assertEqual(len(closed[1]["snapshot_refs"]), 3)

    def test_review_api_refuses_close_when_a_durable_ref_becomes_unavailable(self) -> None:
        durable = self.app.quarantine_workflow.persist_snapshot(
            self.pending.quarantine_id,
            _capture(),
        )
        self.app.artifacts._records.pop(durable.snapshot_refs[0])  # noqa: SLF001

        status, payload = self.app.http.handle(
            _request(
                "POST",
                f"/v1/quarantine/{self.pending.quarantine_id}/close",
                token="review-token",
                body={"reviewer": "sec@example.com", "disposition": "contained"},
            )
        )

        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "QuarantineSnapshotPendingError")
        self.assertEqual(
            self.app.quarantine_workflow.get(self.pending.quarantine_id).status,
            "open",
        )

    def test_spooled_capture_can_be_retried_after_app_restart_then_closed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            spool = FileForensicCaptureSpool(temp_dir)
            spool.put(self.pending.quarantine_id, _capture())
            restarted = S10SupervisorApp(
                signing_key=b"s10-quarantine-api-restarted",
                artifact_store=self.app.artifacts,
                audit_ledger=self.app.audit,
                quota_ledger=InMemoryQuotaLedger(),
                quarantine_review_token="review-token",
                quarantine_page_sink=lambda _payload: None,
                forensic_spool=FileForensicCaptureSpool(temp_dir),
            )
            pending_status, pending_body = restarted.http.handle(
                _request(
                    "GET",
                    f"/v1/quarantine/{self.pending.quarantine_id}",
                    token="review-token",
                )
            )
            retry_status, retried = restarted.http.handle(
                _request(
                    "POST",
                    f"/v1/quarantine/{self.pending.quarantine_id}/snapshot:retry",
                    token="review-token",
                    body={},
                )
            )
            close_status, closed = restarted.http.handle(
                _request(
                    "POST",
                    f"/v1/quarantine/{self.pending.quarantine_id}/close",
                    token="review-token",
                    body={"reviewer": "sec@example.com", "disposition": "contained"},
                )
            )

            self.assertEqual(pending_status, 200)
            self.assertTrue(pending_body["forensic_spool_pending"])
            self.assertRegex(
                pending_body["forensic_spool_ref"],
                r"^forensic-spool:[0-9a-f]{64}$",
            )
            self.assertEqual(retry_status, 200)
            self.assertEqual(retried["snapshot_status"], "durable")
            self.assertFalse(retried["forensic_spool_pending"])
            self.assertIsNone(retried["forensic_spool_ref"])
            self.assertEqual(close_status, 200)
            self.assertEqual(closed["status"], "closed")
            self.assertEqual(restarted.forensic_spool.pending_quarantine_ids(), ())

    def test_failed_security_page_can_be_retried_through_the_review_api(self) -> None:
        attempts = 0

        def page_sink(_payload: object) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("pager unavailable")

        app = S10SupervisorApp(
            signing_key=b"s10-quarantine-page-retry",
            artifact_store=InMemoryArtifactStore(),
            audit_ledger=InMemoryAuditLedger(),
            quota_ledger=InMemoryQuotaLedger(),
            quarantine_review_token="review-token",
            quarantine_page_sink=page_sink,
        )
        launch_ref, partial_ref = _seed_inputs(app.artifacts, app.audit)
        pending = app.quarantine_workflow.open(
            job_id="job-forensic-1",
            sandbox_id="sandbox-forensic-1",
            reason="trust_path_write",
            severity="Sev-1",
            launch_provenance_ref=launch_ref,
            partial_result_ref=partial_ref,
        )

        status, payload = app.http.handle(
            _request(
                "POST",
                f"/v1/quarantine/{pending.quarantine_id}/page:retry",
                token="review-token",
                body={},
            )
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["page_status"], "delivered")
        self.assertEqual(attempts, 2)


class S8ForensicReadClientTests(unittest.TestCase):
    def test_internal_reads_are_signed_and_bound_to_job_ref_and_representation(self) -> None:
        client = S8BrokeredArtifactStoreClient(
            endpoint_url="https://s8.example/v1/internal/brokered-artifacts",
            broker_write_key=b"broker-key",
        )
        for representation in ("payload", "record"):
            with self.subTest(representation=representation):
                response_body = {
                    "artifact_ref": "artifact:forensic-1",
                    "representation": representation,
                    representation: {"schema": "test"},
                }
                response = mock.MagicMock()
                response.__enter__.return_value.read.return_value = json.dumps(response_body).encode(
                    "utf-8"
                )
                with mock.patch(
                    "argus_runtime.s10_supervisor_service.request.urlopen",
                    return_value=response,
                ) as urlopen:
                    fetched = client.get_internal_artifact(
                        artifact_ref="artifact:forensic-1",
                        job_id="job-forensic-1",
                        representation=representation,
                    )

                outbound = urlopen.call_args.args[0]
                outbound_body = json.loads(outbound.data.decode("utf-8"))
                headers = {name.lower(): value for name, value in outbound.header_items()}
                self.assertEqual(fetched, response_body)
                self.assertEqual(
                    outbound_body["authorization"],
                    {
                        "audience": "store",
                        "scope_id": "s10-forensic:job-forensic-1",
                        "scope_job_id": "job-forensic-1",
                        "capabilities": ["s8.read"],
                    },
                )
                self.assertEqual(outbound_body["artifact_ref"], "artifact:forensic-1")
                self.assertEqual(outbound_body["representation"], representation)
                self.assertRegex(
                    headers["x-argus-store-write-signature"],
                    r"^hmac-sha256:[0-9a-f]{64}$",
                )

    def test_internal_read_rejects_mismatched_s8_response_identity(self) -> None:
        client = S8BrokeredArtifactStoreClient(
            endpoint_url="https://s8.example/v1/internal/brokered-artifacts",
            broker_write_key=b"broker-key",
        )
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {
                "artifact_ref": "artifact:other",
                "representation": "payload",
                "payload": {},
            }
        ).encode("utf-8")
        with (
            mock.patch(
                "argus_runtime.s10_supervisor_service.request.urlopen",
                return_value=response,
            ),
            self.assertRaisesRegex(RuntimeError, "mismatched identity"),
        ):
            client.get_internal_artifact(
                artifact_ref="artifact:forensic-1",
                job_id="job-forensic-1",
                representation="payload",
            )


class HttpSecurityPagerTests(unittest.TestCase):
    def test_authenticated_page_is_delivered_with_no_secret_in_payload(self) -> None:
        received: list[dict[str, object]] = []
        expected_token = "pager-token"

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.headers.get("Authorization") != f"Bearer {expected_token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                received.append(json.loads(self.rfile.read(length)))
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"accepted"}')

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            pager = HttpSecurityPager(
                endpoint_url=f"http://127.0.0.1:{server.server_address[1]}/v1/pages",
                auth_token=expected_token,
                allow_insecure=True,
            )
            pager.page(
                {
                    "quarantine_id": "q-1",
                    "job_id": "job-forensic-1",
                    "sandbox_id": "sandbox-forensic-1",
                    "severity": "Sev-1",
                    "reason": "trust_path_write",
                }
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["quarantine_id"], "q-1")
        self.assertNotIn(expected_token, json.dumps(received[0], sort_keys=True))

    def test_redirect_is_rejected_without_forwarding_credentials(self) -> None:
        forwarded_authorization: list[str | None] = []

        class DestinationHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                forwarded_authorization.append(self.headers.get("Authorization"))
                self.send_response(202)
                self.end_headers()

            def log_message(self, _format: str, *_args: object) -> None:
                return

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_thread = threading.Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()
        location = f"http://127.0.0.1:{destination.server_address[1]}/stolen"

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(307)
                self.send_header("Location", location)
                self.end_headers()

            def log_message(self, _format: str, *_args: object) -> None:
                return

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        redirect_thread.start()
        try:
            pager = HttpSecurityPager(
                endpoint_url=f"http://127.0.0.1:{redirect.server_address[1]}/v1/pages",
                auth_token="pager-token",
                allow_insecure=True,
            )
            with self.assertRaisesRegex(SecurityPagerDeliveryError, "HTTP 307"):
                pager.page(
                    {
                        "quarantine_id": "q-1",
                        "job_id": "job-forensic-1",
                        "sandbox_id": "sandbox-forensic-1",
                        "severity": "Sev-1",
                        "reason": "trust_path_write",
                    }
                )
        finally:
            redirect.shutdown()
            redirect.server_close()
            redirect_thread.join(timeout=2)
            destination.shutdown()
            destination.server_close()
            destination_thread.join(timeout=2)

        self.assertEqual(forwarded_authorization, [])


if __name__ == "__main__":
    unittest.main()
