from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import threading
import unittest

from argus_core import (
    AuditEvent,
    BudgetCaps,
    InMemoryAuditLedger,
    ScopeGrant,
    hash_json,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest
from argus_runtime import s10_audit_persistence
from argus_runtime.s10_audit_persistence import (
    AuditAnchorUnavailableError,
    PostgresAuditLedger,
)
from argus_runtime.s10_quota_persistence import apply_s10_migrations
from argus_runtime.s10_supervisor_service import S10SupervisorApp


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "db" / "s10"
RUST_MANIFEST = ROOT / "bindings" / "rust" / "Cargo.toml"
ZERO_HASH = "blake3:" + "0" * 64


def _request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: object | None = None,
    query: dict[str, list[str]] | None = None,
) -> JsonRequest:
    headers = {"authorization": f"Bearer {token}"} if token is not None else {}
    return JsonRequest(
        method=method,
        path=path,
        query=query or {},
        body=body,
        headers=headers,
    )


class InMemoryAuditLedgerContractTests(unittest.TestCase):
    def test_trace_binding_is_copied_into_job_events_and_chain_verifies(self) -> None:
        ledger = InMemoryAuditLedger()
        ledger.bind_trace(job_id="job-1", trace_id="trace-1")

        first = ledger.append("token.mint", {"job_id": "job-1", "severity": "info"})
        second = ledger.append("sandbox.launched", {"job_id": "job-1"})

        self.assertEqual(first.payload["trace_id"], "trace-1")
        self.assertEqual(second.payload["trace_id"], "trace-1")
        self.assertEqual(first.previous_hash, ZERO_HASH)
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertTrue(ledger.verify_chain().valid)

    def test_trace_binding_advances_between_stages_without_overriding_explicit_trace(self) -> None:
        ledger = InMemoryAuditLedger()
        ledger.bind_trace(job_id="job-1", trace_id="trace-build")
        build = ledger.append("sandbox.launched", {"job_id": "job-1"})
        ledger.bind_trace(job_id="job-1", trace_id="trace-verify")
        verify = ledger.append("sandbox.launched", {"job_id": "job-1"})
        explicit = ledger.append(
            "sandbox.exited",
            {"job_id": "job-1", "trace_id": "trace-explicit"},
        )

        self.assertEqual(build.payload["trace_id"], "trace-build")
        self.assertEqual(verify.payload["trace_id"], "trace-verify")
        self.assertEqual(explicit.payload["trace_id"], "trace-explicit")
        self.assertTrue(ledger.verify_chain().valid)

    def test_concurrent_appends_have_one_strict_sequence(self) -> None:
        ledger = InMemoryAuditLedger()

        with ThreadPoolExecutor(max_workers=16) as pool:
            events = list(
                pool.map(
                    lambda index: ledger.append("meter.sample", {"job_id": "job-c", "index": index}),
                    range(100),
                )
            )

        self.assertEqual(sorted(event.sequence for event in events), list(range(1, 101)))
        self.assertEqual([event.sequence for event in ledger.events()], list(range(1, 101)))
        self.assertTrue(ledger.verify_chain().valid)

    def test_query_filters_job_type_and_severity_without_exposing_mutable_state(self) -> None:
        ledger = InMemoryAuditLedger()
        ledger.append("sandbox.launched", {"job_id": "job-1", "severity": "info"})
        ledger.append("meter.halt", {"job_id": "job-1", "severity": "critical"})
        ledger.append("meter.halt", {"job_id": "job-2", "severity": "critical"})

        result = ledger.query(job_id="job-1", event_type="meter.halt", severity="critical")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].payload["job_id"], "job-1")
        result[0].payload["severity"] = "tampered"
        self.assertEqual(ledger.events()[1].payload["severity"], "critical")

    def test_historical_payload_tamper_is_reported_at_edited_sequence(self) -> None:
        ledger = InMemoryAuditLedger()
        ledger.append("token.mint", {"job_id": "job-1"})
        ledger.append("sandbox.launched", {"job_id": "job-1"})
        original = ledger._events[0]
        ledger._events[0] = replace(original, payload={"job_id": "job-tampered"})

        verification = ledger.verify_chain()

        self.assertFalse(verification.valid)
        self.assertEqual(verification.break_sequence, 1)


class AuditMismatchDiagnosticsTests(unittest.TestCase):
    def test_summary_reports_only_path_types_and_payload_hashes(self) -> None:
        summary = s10_audit_persistence._json_mismatch_summary(
            {"usage": {"wallclock_s": 1.25}, "gpu_models": []},
            {"usage": {"wallclock_s": 1}, "gpu_models": ["A100"]},
        )

        self.assertRegex(summary, r"^expected=blake3:[0-9a-f]{64},actual=blake3:[0-9a-f]{64};")
        self.assertIn("$.gpu_models:length(0!=1)", summary)
        self.assertIn("$.usage.wallclock_s:type(float!=int)", summary)
        self.assertNotIn("A100", summary)
        self.assertNotIn("1.25", summary)


class AuditApiContractTests(unittest.TestCase):
    def setUp(self) -> None:
        identity = RuntimeIdentity(
            caller_id="worker-1",
            job_id="job-1",
            root_request_id="root-1",
            scopes=ScopeGrant(),
            budget_caps=BudgetCaps(),
        )
        self.app = S10SupervisorApp(
            signing_key=b"audit-api-signing-key",
            auth=RuntimeAuth({"runtime-token": identity}),
            health_token="health-token",
            audit_api_write_token="audit-write-token",
            audit_api_read_token="audit-read-token",
            audit_anchor_auth_token="audit-anchor-token",
        )

    def test_append_is_internal_only_and_caller_cannot_choose_chain_fields(self) -> None:
        body = {
            "event_type": "token.mint",
            "payload": {"job_id": "job-1", "trace_id": "trace-1"},
            "sequence": 99,
            "event_hash": "blake3:" + "f" * 64,
        }

        unauthenticated = self.app.http.handle(_request("POST", "/v1/audit/append", body=body))
        runtime_identity = self.app.http.handle(
            _request("POST", "/v1/audit/append", token="runtime-token", body=body)
        )
        bad_request = self.app.http.handle(
            _request("POST", "/v1/audit/append", token="audit-write-token", body=body)
        )
        created = self.app.http.handle(
            _request(
                "POST",
                "/v1/audit/append",
                token="audit-write-token",
                body={"event_type": "token.mint", "payload": body["payload"]},
            )
        )

        self.assertEqual(unauthenticated[0], 401)
        self.assertEqual(runtime_identity[0], 401)
        self.assertEqual(bad_request[0], 400)
        self.assertEqual(created[0], 201)
        self.assertEqual(created[1]["sequence"], 1)
        self.assertEqual(created[1]["this_hash"], self.app.audit.events()[0].event_hash)

    def test_verify_and_query_require_reader_auth_and_apply_filters(self) -> None:
        self.app.audit.append("sandbox.launched", {"job_id": "job-1", "severity": "info"})
        self.app.audit.append("meter.halt", {"job_id": "job-1", "severity": "critical"})
        self.app.audit.append("meter.halt", {"job_id": "job-2", "severity": "critical"})

        denied = self.app.http.handle(_request("GET", "/v1/audit/verify"))
        verified = self.app.http.handle(
            _request(
                "GET",
                "/v1/audit/verify",
                token="audit-read-token",
                query={"from_seq": ["1"], "to_seq": ["3"]},
            )
        )
        queried = self.app.http.handle(
            _request(
                "GET",
                "/v1/audit/query",
                token="audit-read-token",
                query={"job_id": ["job-1"], "type": ["meter.halt"], "sev": ["critical"]},
            )
        )

        self.assertEqual(denied[0], 401)
        self.assertEqual(verified, (200, {"intact": True, "break_at": None, "anchor_mismatch": False}))
        self.assertEqual(queried[0], 200)
        self.assertEqual(len(queried[1]), 1)
        self.assertEqual(queried[1][0]["event_type"], "meter.halt")

    def test_internal_anchor_callback_is_separately_authenticated_and_content_addressed(self) -> None:
        class AnchorStore:
            def __init__(self) -> None:
                self.payloads: list[dict[str, object]] = []

            def create_audit_anchor(self, payload: dict[str, object]) -> dict[str, str]:
                self.payloads.append(dict(payload))
                return {
                    "artifact_ref": "c4://audit/s10/1/root",
                    "content_hash": hash_json(payload),
                }

        store = AnchorStore()
        self.app._audit_anchor_store = store
        body = {
            "schema": "argus.s10.audit-anchor.v1",
            "sequence": 1,
            "previous_root": ZERO_HASH,
            "root": "blake3:" + "1" * 64,
            "event_hash": "blake3:" + "2" * 64,
        }

        denied = self.app.http.handle(_request("POST", "/v1/internal/audit-anchor", body=body))
        created = self.app.http.handle(
            _request("POST", "/v1/internal/audit-anchor", token="audit-anchor-token", body=body)
        )

        self.assertEqual(denied[0], 401)
        self.assertEqual(created[0], 201)
        self.assertEqual(created[1]["content_hash"], hash_json(body))
        self.assertEqual(store.payloads, [body])


class _AnchorServer:
    def __init__(self, token: str) -> None:
        self.token = token
        self.payloads: dict[str, dict[str, object]] = {}
        self.fail_next = False
        self.mismatch_next = False
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/v1/internal/audit-anchor":
                    self.send_error(404)
                    return
                if self.headers.get("Authorization") != f"Bearer {outer.token}":
                    self.send_error(401)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                with outer._lock:
                    if outer.fail_next:
                        outer.fail_next = False
                        self.send_error(503)
                        return
                    artifact_ref = f"artifact:s10-audit-anchor:{body['sequence']}:{str(body['root']).removeprefix('blake3:')}"
                    existing = outer.payloads.get(artifact_ref)
                    if existing is not None and existing != body:
                        self.send_error(409)
                        return
                    outer.payloads[artifact_ref] = body
                    response = {
                        "sequence": body["sequence"],
                        "root": body["root"],
                        "event_hash": body["event_hash"],
                        "artifact_ref": artifact_ref,
                        "content_hash": hash_json(body),
                    }
                    if outer.mismatch_next:
                        outer.mismatch_next = False
                        response["root"] = ZERO_HASH
                encoded = json.dumps(response, sort_keys=True).encode("utf-8")
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, format: str, *args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}/v1/internal/audit-anchor"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def load(self, artifact_ref: str) -> dict[str, object]:
        with self._lock:
            return json.loads(json.dumps(self.payloads[artifact_ref]))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@unittest.skipUnless(
    shutil.which("cargo") and shutil.which("initdb") and shutil.which("pg_ctl") and shutil.which("psql"),
    "Rust and PostgreSQL command-line tools are required for S10 audit ledger tests",
)
class PostgresAuditLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = TemporaryDirectory()
        cls.root = Path(cls.tempdir.name)
        cls.data_dir = cls.root / "pgdata"
        cls.socket_dir = cls.root / "socket"
        cls.socket_dir.mkdir()
        cls.port = _free_port()
        try:
            _run_checked(["initdb", "-A", "trust", "--nosync", "-D", str(cls.data_dir)])
        except RuntimeError as exc:
            cls.tempdir.cleanup()
            if "could not create shared memory segment" in str(exc):
                cls._start_existing_postgres_database()
            else:
                raise
        else:
            _run_checked(
                [
                    "pg_ctl",
                    "-D",
                    str(cls.data_dir),
                    "-l",
                    str(cls.root / "postgres.log"),
                    "-o",
                    f"-k {cls.socket_dir} -p {cls.port} -c listen_addresses=''",
                    "-w",
                    "start",
                ]
            )
            cls.pg_host = str(cls.socket_dir)
            cls.pg_port = cls.port
            cls.pg_database = "postgres"
            cls.uses_existing_postgres = False
        _run_checked(
            [
                "cargo",
                "build",
                "--quiet",
                "--manifest-path",
                str(RUST_MANIFEST),
                "--bin",
                "argus-s10-audit-ledger-writer",
            ]
        )
        cls.writer_binary = ROOT / "bindings" / "rust" / "target" / "debug" / "argus-s10-audit-ledger-writer"

    @classmethod
    def _start_existing_postgres_database(cls) -> None:
        cls.uses_existing_postgres = True
        cls.pg_host = "127.0.0.1"
        cls.pg_port = None
        cls.pg_database = f"argus_s10_audit_test_{os.getpid()}_{secrets.token_hex(4)}"
        _run_checked(
            [
                "psql",
                "-X",
                "-q",
                "-h",
                cls.pg_host,
                "-d",
                "postgres",
                "-c",
                f"CREATE DATABASE {cls.pg_database};",
            ]
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "uses_existing_postgres", False):
            _run_checked(
                [
                    "psql",
                    "-X",
                    "-q",
                    "-h",
                    cls.pg_host,
                    "-d",
                    "postgres",
                    "-c",
                    f"DROP DATABASE IF EXISTS {cls.pg_database};",
                ]
            )
        else:
            subprocess.run(
                ["pg_ctl", "-D", str(cls.data_dir), "-m", "fast", "-w", "stop"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            cls.tempdir.cleanup()

    def setUp(self) -> None:
        self._psql("DROP SCHEMA IF EXISTS s10 CASCADE;")
        apply_s10_migrations(dsn=self._postgres_dsn(), migrations_dir=MIGRATIONS_DIR)
        self.anchor = _AnchorServer("anchor-token")
        self.anchor.start()

    def tearDown(self) -> None:
        self.anchor.stop()

    def _ledger(self) -> PostgresAuditLedger:
        return PostgresAuditLedger(
            dsn=self._postgres_dsn(),
            writer_binary=self.writer_binary,
            writer_role="s10_audit_writer",
            anchor_url=self.anchor.url,
            anchor_auth_token="anchor-token",
            allow_insecure_anchor=True,
            anchor_loader=self.anchor.load,
        )

    def test_rust_writer_persists_chain_and_external_anchor_across_reload(self) -> None:
        ledger = self._ledger()
        first = ledger.append("token.mint", {"job_id": "job-1", "trace_id": "trace-1"})
        second = ledger.append("sandbox.launched", {"job_id": "job-1", "trace_id": "trace-1"})

        reloaded = self._ledger()
        verification = reloaded.verify_chain()

        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertTrue(verification.valid)
        self.assertFalse(verification.anchor_mismatch)
        self.assertEqual(reloaded.kind, "postgres-rust-subprocess")
        self.assertEqual(self._psql("SELECT count(*) FROM s10.audit_event;").stdout.strip(), "2")
        self.assertEqual(self._psql("SELECT count(*) FROM s10.audit_anchor;").stdout.strip(), "2")
        self.assertEqual(len(self.anchor.payloads), 2)

    def test_append_normalizes_nested_python_sequences_to_json_arrays(self) -> None:
        ledger = self._ledger()
        payload = {
            "job_id": "job-json-boundary",
            "gpu_models": ("A100", "H100"),
            "usage": {"breached_dimensions": ()},
        }

        event = ledger.append("meter.sample", payload)

        self.assertEqual(event.payload["gpu_models"], ["A100", "H100"])
        self.assertEqual(event.payload["usage"]["breached_dimensions"], [])
        self.assertEqual(payload["gpu_models"], ("A100", "H100"))
        self.assertTrue(ledger.verify_chain().valid)

    def test_append_preserves_python_float_bits_through_rust_and_postgres(self) -> None:
        ledger = self._ledger()
        cost_usd = 9.507422199628005e-05

        event = ledger.append(
            "meter.sample",
            {"job_id": "job-float-roundtrip", "usage": {"cost_usd": cost_usd}},
        )

        self.assertEqual(event.payload["usage"]["cost_usd"].hex(), cost_usd.hex())
        self.assertEqual(ledger.events()[0].payload, event.payload)
        verification = ledger.verify_chain()
        self.assertTrue(verification.valid, verification)

    def test_trace_binding_advances_across_persisted_job_stages(self) -> None:
        ledger = self._ledger()
        ledger.bind_trace(job_id="job-stage", trace_id="trace-build")
        build = ledger.append("sandbox.launched", {"job_id": "job-stage"})
        ledger.bind_trace(job_id="job-stage", trace_id="trace-verify")
        verify = ledger.append("sandbox.launched", {"job_id": "job-stage"})

        self.assertEqual(build.payload["trace_id"], "trace-build")
        self.assertEqual(verify.payload["trace_id"], "trace-verify")
        self.assertTrue(ledger.verify_chain().valid)

    def test_concurrent_rust_writers_serialize_without_forks_or_gaps(self) -> None:
        def append_one(index: int) -> AuditEvent:
            return self._ledger().append(
                "meter.sample",
                {"job_id": "job-concurrent", "trace_id": "trace-concurrent", "index": index},
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            events = list(pool.map(append_one, range(40)))

        self.assertEqual(sorted(event.sequence for event in events), list(range(1, 41)))
        self.assertTrue(self._ledger().verify_chain().valid)

    def test_anchor_failure_or_mismatched_response_rolls_back_database_append(self) -> None:
        ledger = self._ledger()
        ledger.append("token.mint", {"job_id": "job-1"})
        self.anchor.fail_next = True
        with self.assertRaises(AuditAnchorUnavailableError):
            ledger.append("sandbox.launched", {"job_id": "job-1"})
        self.anchor.mismatch_next = True
        with self.assertRaises(AuditAnchorUnavailableError):
            ledger.append("sandbox.launched", {"job_id": "job-1"})

        self.assertEqual(self._psql("SELECT count(*) FROM s10.audit_event;").stdout.strip(), "1")
        self.assertTrue(ledger.verify_chain().valid)

    def test_tc19_detects_historical_payload_tamper_and_merkle_anchor_mismatch(self) -> None:
        ledger = self._ledger()
        ledger.append("token.mint", {"job_id": "job-1", "trace_id": "trace-1"})
        ledger.append("sandbox.launched", {"job_id": "job-1", "trace_id": "trace-1"})
        self._psql("ALTER TABLE s10.audit_event DISABLE TRIGGER USER;")
        self._psql("UPDATE s10.audit_event SET payload = '{\"job_id\":\"tampered\"}'::jsonb WHERE sequence = 1;")
        self._psql("ALTER TABLE s10.audit_event ENABLE TRIGGER USER;")

        verification = ledger.verify_chain()

        self.assertFalse(verification.valid)
        self.assertEqual(verification.break_sequence, 1)
        self.assertTrue(verification.anchor_mismatch)

    def test_external_write_once_anchor_tamper_is_detected_even_when_database_chain_is_intact(self) -> None:
        ledger = self._ledger()
        ledger.append("token.mint", {"job_id": "job-1"})
        artifact_ref = next(iter(self.anchor.payloads))
        self.anchor.payloads[artifact_ref]["root"] = ZERO_HASH

        verification = ledger.verify_chain()

        self.assertFalse(verification.valid)
        self.assertEqual(verification.break_sequence, 1)
        self.assertTrue(verification.anchor_mismatch)

    def test_query_filters_job_type_severity_and_time_range(self) -> None:
        ledger = self._ledger()
        ledger.append("sandbox.launched", {"job_id": "job-1", "severity": "info"})
        ledger.append("meter.halt", {"job_id": "job-1", "severity": "critical"})
        ledger.append("meter.halt", {"job_id": "job-2", "severity": "critical"})

        matches = ledger.query(job_id="job-1", event_type="meter.halt", severity="critical")
        future = ledger.query(from_time=datetime(2100, 1, 1, tzinfo=UTC))

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].sequence, 2)
        self.assertEqual(future, ())

    def test_tables_are_append_only_and_writer_role_cannot_insert_directly(self) -> None:
        self._ledger().append("token.mint", {"job_id": "job-1"})
        update = self._psql("UPDATE s10.audit_event SET event_type = 'tampered' WHERE sequence = 1;", check=False)
        delete = self._psql("DELETE FROM s10.audit_event WHERE sequence = 1;", check=False)
        truncate = self._psql("TRUNCATE s10.audit_event CASCADE;", check=False)
        direct_insert = self._psql(
            "SET ROLE s10_audit_writer; "
            "INSERT INTO s10.audit_event (sequence,event_type,payload,previous_hash,event_hash) "
            f"VALUES (2,'direct','{{}}'::jsonb,'{ZERO_HASH}','{ZERO_HASH}');",
            check=False,
        )

        self.assertNotEqual(update.returncode, 0)
        self.assertIn("append-only table audit_event", update.stderr)
        self.assertNotEqual(delete.returncode, 0)
        self.assertIn("append-only table audit_event", delete.stderr)
        self.assertNotEqual(truncate.returncode, 0)
        self.assertIn("append-only table audit_event", truncate.stderr)
        self.assertNotEqual(direct_insert.returncode, 0)
        self.assertIn("permission denied", direct_insert.stderr)
        self.assertEqual(self._psql("SELECT count(*) FROM s10.audit_event;").stdout.strip(), "1")

    def _psql(self, sql: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._psql_base() + ["-c", sql],
            check=check,
            text=True,
            capture_output=True,
        )

    def _psql_base(self) -> list[str]:
        command = [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-X",
            "-q",
            "-t",
            "-A",
            "-h",
            str(self.pg_host),
        ]
        if self.pg_port is not None:
            command.extend(["-p", str(self.pg_port)])
        command.extend(["-d", self.pg_database])
        return command

    def _postgres_dsn(self) -> str:
        from psycopg.conninfo import make_conninfo

        kwargs = {"host": str(self.pg_host), "dbname": self.pg_database}
        if self.pg_port is not None:
            kwargs["port"] = str(self.pg_port)
        return make_conninfo("", **kwargs)


def _run_checked(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            "command failed: "
            + " ".join(command)
            + "\nstdout:\n"
            + result.stdout
            + "\nstderr:\n"
            + result.stderr
        )
    return result


if __name__ == "__main__":
    unittest.main()
