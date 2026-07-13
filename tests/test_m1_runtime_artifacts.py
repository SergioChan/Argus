from __future__ import annotations

import json
import socket
import tempfile
import time
from threading import Thread
import unittest
from unittest.mock import patch

from argus_core import BudgetCaps, FileSystemArtifactStore, Lineage, Producer, ScopeGrant
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import serve_json_app
from argus_runtime.m1_runtime_artifacts import (
    RuntimeArtifactStoreError,
    RuntimeIdentitySession,
    S10S8ArtifactStore,
)
from argus_runtime.s10_supervisor_service import (
    RuntimeIdentityMintPolicy,
    S10SupervisorApp,
    S8BrokeredArtifactStoreClient,
)
from argus_runtime.s8_writer_service import S8WriterApp


class _HttpResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def __enter__(self) -> "_HttpResponse":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


class M1RuntimeArtifactStoreTests(unittest.TestCase):
    def test_real_http_s10_broker_and_s8_readback_have_no_in_memory_fallback(self) -> None:
        bootstrap_token = "m1-runtime-bootstrap"
        broker_write_key = b"m1-runtime-broker-write-key"
        auth = RuntimeAuth.with_signed_identities(
            bootstrap_token=bootstrap_token,
            identity_signing_key=b"m1-runtime-identity-signing-key",
        )
        identity = RuntimeIdentity(
            caller_id="m1-reference-s1",
            job_id="m1-reference-job",
            root_request_id="m1-reference-root",
            scopes=ScopeGrant(
                broker_audiences=("store",),
                capabilities=("s8.read",),
                producer_subsystems=("S1",),
            ),
            budget_caps=BudgetCaps(max_compute_units=1, max_wallclock_s=60, max_cost_usd=1),
            max_ttl_s=600,
        )
        with tempfile.TemporaryDirectory() as tmp:
            durable_store = FileSystemArtifactStore(tmp)
            s8 = S8WriterApp(durable_store, auth=auth, broker_write_key=broker_write_key)
            s8_url = _start_json_server(s8)
            s10 = S10SupervisorApp(
                signing_key=b"m1-runtime-s10-signing-key",
                artifact_store=S8BrokeredArtifactStoreClient(
                    endpoint_url=f"{s8_url}/v1/internal/brokered-artifacts",
                    broker_write_key=broker_write_key,
                ),
                auth=auth,
                runtime_identity_mint_policy=RuntimeIdentityMintPolicy(
                    identities_by_caller={"m1-reference-s1": identity}
                ),
            )
            s10_url = _start_json_server(s10)
            session = RuntimeIdentitySession.from_bootstrap(
                s10_url=s10_url,
                bootstrap_token=bootstrap_token,
                caller_id="m1-reference-s1",
                expected_job_id="m1-reference-job",
            )
            budget = session.mint_budget()
            store = S10S8ArtifactStore(session=session, s8_url=s8_url)

            created = store.create_artifact(
                kind="model",
                payload={"weights": [1.0], "job_id": "m1-reference-job"},
                producer=Producer(
                    subsystem="S1",
                    version="0.0.0",
                    actor_id="s1.reference-physics",
                    job_id="m1-reference-job",
                ),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="git:m1-reference",
                    environment_digest="oci:m1-reference",
                    seeds=("seed-m1",),
                    actor_id="s1.reference-physics",
                    job_id="m1-reference-job",
                ),
            )
            fetched = store.get_record(created.artifact_ref)
            payload = json.loads(store.get_artifact(created.artifact_ref).decode("utf-8"))
            graph = store.get_lineage(created.artifact_ref, direction="ancestors")

            self.assertEqual(durable_store.record_count, 1)
            self.assertEqual(budget["job_id"], "m1-reference-job")
            self.assertEqual(fetched.artifact_ref, created.artifact_ref)
            self.assertEqual(payload["weights"], [1.0])
            self.assertEqual([node.artifact_ref for node in graph.nodes], [created.artifact_ref])

    def test_session_binds_policy_identity_and_uses_s10_broker_with_s8_readback(self) -> None:
        requests: list[dict[str, object]] = []
        record = {
            "artifact_ref": "c4://artifact/m1-runtime-model",
            "kind": "model",
            "content_hash": "blake3:" + "1" * 64,
            "size_bytes": 20,
            "producer": {
                "subsystem": "S1",
                "version": "0.0.0",
                "actor_id": "s1.reference-physics",
                "job_id": "m1-reference-job",
            },
            "lineage": {
                "input_refs": [],
                "code_ref": "git:m1-reference",
                "environment_digest": "oci:m1-reference",
                "seeds": ["seed-m1"],
                "actor_id": "s1.reference-physics",
                "job_id": "m1-reference-job",
                "contamination_index_version": None,
            },
            "claim_tier": "ran-toy",
            "validation_report_ref": None,
            "created_at": "2026-07-10T00:00:00Z",
        }

        def urlopen(request: object, timeout: float) -> _HttpResponse:
            url = str(getattr(request, "full_url"))
            data = getattr(request, "data", None)
            headers = dict(getattr(request, "headers", {}))
            body = json.loads(data.decode("utf-8")) if isinstance(data, bytes) else None
            requests.append({"url": url, "headers": headers, "body": body, "timeout": timeout})
            if url.endswith("/v1/runtime-identities"):
                return _HttpResponse(
                    {
                        "access_token": "m1-runtime-identity",
                        "identity": {"job_id": "m1-reference-job", "caller_id": "m1-reference-s1"},
                    }
                )
            if url.endswith("/v1/scope-tokens"):
                return _HttpResponse(
                    {
                        "scope_id": "scope-m1",
                        "job_id": "m1-reference-job",
                        "scopes": {
                            "broker_audiences": ["store"],
                            "capabilities": ["s8.read"],
                            "producer_subsystems": ["S1"],
                            "sandbox_risk_class": "standard",
                        },
                        "issued_at": 1,
                        "expires_at": 601,
                        "ttl_s": 600,
                        "signature": "ed25519:test",
                    }
                )
            if url.endswith("/v1/broker/store/put"):
                return _HttpResponse(record)
            if url.endswith("/v1/broker/store/get"):
                if body["representation"] == "record":
                    return _HttpResponse(
                        {
                            "artifact_ref": record["artifact_ref"],
                            "representation": "record",
                            "record": record,
                        }
                    )
                return _HttpResponse(
                    {
                        "artifact_ref": record["artifact_ref"],
                        "representation": "payload",
                        "payload": {"weights": [1.0], "job_id": "m1-reference-job"},
                    }
                )
            if url.endswith("/record"):
                return _HttpResponse(record)
            if url.endswith("/payload"):
                return _HttpResponse({"weights": [1.0], "job_id": "m1-reference-job"})
            if "/v1/lineage/" in url:
                return _HttpResponse({"nodes": [record], "edges": []})
            raise AssertionError(f"unexpected URL: {url}")

        with patch("argus_runtime.m1_runtime_artifacts.urlrequest.urlopen", side_effect=urlopen):
            session = RuntimeIdentitySession.from_bootstrap(
                s10_url="http://s10.example",
                bootstrap_token="bootstrap-only",
                caller_id="m1-reference-s1",
                expected_job_id="m1-reference-job",
            )
            store = S10S8ArtifactStore(session=session, s8_url="http://s8.example")
            created = store.create_artifact(
                kind="model",
                payload={"weights": [1.0], "job_id": "m1-reference-job"},
                producer=Producer(
                    subsystem="S1",
                    version="0.0.0",
                    actor_id="s1.reference-physics",
                    job_id="m1-reference-job",
                ),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="git:m1-reference",
                    environment_digest="oci:m1-reference",
                    seeds=("seed-m1",),
                    actor_id="s1.reference-physics",
                    job_id="m1-reference-job",
                ),
            )
            fetched = store.get_record(created.artifact_ref)
            payload = json.loads(store.get_artifact(created.artifact_ref).decode("utf-8"))
            graph = store.get_lineage(created.artifact_ref, direction="ancestors")

        self.assertEqual(created.artifact_ref, record["artifact_ref"])
        self.assertEqual(fetched.producer.subsystem, "S1")
        self.assertEqual(payload["job_id"], "m1-reference-job")
        self.assertEqual([node.artifact_ref for node in graph.nodes], [record["artifact_ref"]])
        self.assertEqual(requests[0]["url"], "http://s10.example/v1/runtime-identities")
        self.assertEqual(requests[0]["body"], {"caller_id": "m1-reference-s1", "ttl_s": 600})
        self.assertEqual(requests[1]["url"], "http://s10.example/v1/scope-tokens")
        self.assertEqual(requests[1]["body"], {"ttl_s": 600})
        self.assertEqual(requests[2]["url"], "http://s10.example/v1/broker/store/put")
        self.assertEqual(requests[2]["body"]["scope_token"]["scope_id"], "scope-m1")
        self.assertEqual(requests[3]["url"], "http://s10.example/v1/broker/store/get")
        self.assertEqual(requests[3]["headers"]["Authorization"], "Bearer m1-runtime-identity")
        self.assertEqual(requests[4]["url"], "http://s10.example/v1/broker/store/get")
        self.assertEqual(requests[5]["url"], "http://s8.example/v1/lineage/c4://artifact/m1-runtime-model?direction=ancestors")

    def test_session_rejects_policy_identity_for_the_wrong_job(self) -> None:
        def urlopen(_request: object, timeout: float) -> _HttpResponse:
            self.assertGreater(timeout, 0)
            return _HttpResponse(
                {
                    "access_token": "wrong-job-token",
                    "identity": {"job_id": "attacker-selected-job", "caller_id": "m1-reference-s1"},
                }
            )

        with patch("argus_runtime.m1_runtime_artifacts.urlrequest.urlopen", side_effect=urlopen):
            with self.assertRaisesRegex(RuntimeArtifactStoreError, "job_id mismatch"):
                RuntimeIdentitySession.from_bootstrap(
                    s10_url="http://s10.example",
                    bootstrap_token="bootstrap-only",
                    caller_id="m1-reference-s1",
                    expected_job_id="m1-reference-job",
                )

    def test_store_fails_closed_when_s10_broker_does_not_return_a_record(self) -> None:
        def urlopen(request: object, timeout: float) -> _HttpResponse:
            self.assertGreater(timeout, 0)
            url = str(getattr(request, "full_url"))
            if url.endswith("/v1/runtime-identities"):
                return _HttpResponse(
                    {
                        "access_token": "m1-runtime-identity",
                        "identity": {"job_id": "m1-reference-job", "caller_id": "m1-reference-s1"},
                    }
                )
            if url.endswith("/v1/scope-tokens"):
                return _HttpResponse(
                    {
                        "scope_id": "scope-m1",
                        "job_id": "m1-reference-job",
                        "scopes": {},
                        "issued_at": 1,
                        "expires_at": 601,
                        "ttl_s": 600,
                        "signature": "ed25519:test",
                    }
                )
            if url.endswith("/v1/broker/store/put"):
                return _HttpResponse({"error": "DirectWriteDenied"})
            raise AssertionError(f"unexpected URL: {url}")

        with patch("argus_runtime.m1_runtime_artifacts.urlrequest.urlopen", side_effect=urlopen):
            session = RuntimeIdentitySession.from_bootstrap(
                s10_url="http://s10.example",
                bootstrap_token="bootstrap-only",
                caller_id="m1-reference-s1",
                expected_job_id="m1-reference-job",
            )
            store = S10S8ArtifactStore(session=session, s8_url="http://s8.example")
            with self.assertRaisesRegex(RuntimeArtifactStoreError, "artifact_ref"):
                store.create_artifact(
                    kind="model",
                    payload={"weights": [1.0]},
                    producer=Producer(subsystem="S1", version="0.0.0", job_id="m1-reference-job"),
                    lineage=Lineage(
                        input_refs=(),
                        code_ref="git:m1-reference",
                        environment_digest="oci:m1-reference",
                        job_id="m1-reference-job",
                    ),
                )


def _start_json_server(app: object) -> str:
    port = _free_port()
    http = getattr(app, "http")
    thread = Thread(
        target=serve_json_app,
        kwargs={"app": http, "host": "127.0.0.1", "port": port},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return f"http://127.0.0.1:{port}"
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    unittest.main()
