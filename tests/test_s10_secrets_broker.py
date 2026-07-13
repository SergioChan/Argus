from __future__ import annotations

import json
import socket
from threading import Thread
import time
import unittest
from urllib import error as urlerror
from urllib import request as urlrequest

from argus_core import (
    BudgetCaps,
    InMemoryArtifactStore,
    InMemoryTokenService,
    ScopeGrant,
    canonical_json_bytes,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import serve_json_app
from argus_runtime.m1_runtime_artifacts import RuntimeIdentitySession
from argus_runtime.s10_supervisor_service import (
    CredentialedAdapterTarget,
    RuntimeIdentityMintPolicy,
    S10SupervisorApp,
    S8BrokeredArtifactStoreClient,
)
from argus_runtime.s7_reference_adapter_service import (
    S7_REFERENCE_ADAPTER_ROUTE,
    S7ReferenceAdapterApp,
)
from argus_runtime.s8_writer_service import S8WriterApp


JOB_ID = "m1-reference-job"
ADAPTER_ID = "gw_spectrum"
ADAPTER_CREDENTIAL_HEADER = "X-Argus-Adapter-Credential"


class S10SecretsBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter_credential = "broker-only-adapter-secret"
        self.broker_write_key = b"s10-t13-broker-write-key"
        self.auth = RuntimeAuth.with_signed_identities(
            bootstrap_token="s10-t13-bootstrap",
            identity_signing_key=b"s10-t13-runtime-identity-key",
        )
        self.identities = {
            "s1": _identity(
                caller_id="s1",
                allowed_adapters=(ADAPTER_ID,),
                broker_audiences=("store", ADAPTER_ID),
                capabilities=("s8.read",),
                producer_subsystems=("S1",),
            ),
            "s1-denied": _identity(
                caller_id="s1-denied",
                allowed_adapters=("other_adapter",),
                broker_audiences=("store", "other_adapter"),
                capabilities=("s8.read",),
                producer_subsystems=("S1",),
            ),
            "s7": _identity(
                caller_id="s7",
                broker_audiences=("store",),
                capabilities=("s8.read",),
                producer_subsystems=("S7",),
            ),
        }
        self.access_tokens = {
            caller_id: str(self.auth.mint_identity_token(identity, ttl_s=600)["access_token"])
            for caller_id, identity in self.identities.items()
        }

        self.s8_store = InMemoryArtifactStore()
        self.s8 = S8WriterApp(
            self.s8_store,
            auth=self.auth,
            broker_write_key=self.broker_write_key,
        )
        self.s8_url = _start_json_server(self.s8)

        adapter_port = _free_port()
        self.adapter_url = f"http://127.0.0.1:{adapter_port}"
        self.tokens = InMemoryTokenService(signing_key=b"s10-t13-scope-token-key")
        self.s10 = S10SupervisorApp(
            token_service=self.tokens,
            artifact_store=S8BrokeredArtifactStoreClient(
                endpoint_url=f"{self.s8_url}/v1/internal/brokered-artifacts",
                broker_write_key=self.broker_write_key,
            ),
            auth=self.auth,
            runtime_identity_mint_policy=RuntimeIdentityMintPolicy(self.identities),
            adapter_targets={
                ADAPTER_ID: CredentialedAdapterTarget(
                    adapter_id=ADAPTER_ID,
                    endpoint_url=f"{self.adapter_url}{S7_REFERENCE_ADAPTER_ROUTE}",
                    credential_header=ADAPTER_CREDENTIAL_HEADER,
                    credential=self.adapter_credential,
                )
            },
        )
        self.s10_url = _start_json_server(self.s10)
        self.s7 = S7ReferenceAdapterApp(
            s10_url=self.s10_url,
            s8_url=self.s8_url,
            access_token=self.access_tokens["s7"],
            caller_id="s7",
            expected_job_id=JOB_ID,
            broker_credential_header=ADAPTER_CREDENTIAL_HEADER,
            broker_credential=self.adapter_credential,
        )
        _start_json_server(self.s7, port=adapter_port)

    def test_broker_hides_adapter_credential_and_returns_real_c6_result(self) -> None:
        direct_status, direct_body = _request_json(
            "POST",
            f"{self.adapter_url}{S7_REFERENCE_ADAPTER_ROUTE}",
            body={"job_id": JOB_ID, "eval_request": _eval_request()},
        )
        self.assertEqual(direct_status, 403, direct_body)

        session = self._session("s1")
        status, result = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/adapter/{ADAPTER_ID}/evaluate",
            bearer_token=session.access_token,
            body={"scope_token": session.mint_scope(), "eval_request": _eval_request()},
        )

        self.assertEqual(status, 200, result)
        self.assertEqual(result["adapter_id"], ADAPTER_ID)
        self.assertIn("omega", result["outputs"])
        self.assertRegex(result["provenance_ref"], r"^c4://")
        self.assertTrue(result["uncertainty_engine_version"])
        self.assertNotIn(self.adapter_credential, json.dumps(result, sort_keys=True))
        self.assertNotIn(
            self.adapter_credential,
            json.dumps([event.payload for event in self.s10.audit.events()], sort_keys=True),
        )
        self.assertEqual(self.s10.audit.events()[-1].event_type, "adapter.evaluate")

    def test_broker_denies_ungranted_adapter_before_upstream_execution(self) -> None:
        session = self._session("s1-denied")
        scope_token = session.mint_scope()
        before_records = self.s8_store.record_count

        status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/adapter/{ADAPTER_ID}/evaluate",
            bearer_token=session.access_token,
            body={"scope_token": scope_token, "eval_request": _eval_request()},
        )

        self.assertEqual(status, 403, denied)
        self.assertEqual(denied["error"], "ScopeDeniedError")
        self.assertEqual(self.s8_store.record_count, before_records)
        self.assertEqual(self.s10.audit.events()[-1].event_type, "adapter.denied")
        self.assertEqual(self.s10.audit.events()[-1].payload["reason"], "adapter_not_allowlisted")

    def test_broker_denies_path_body_adapter_mismatch(self) -> None:
        session = self._session("s1")
        request_body = _eval_request()
        request_body["adapter_id"] = "other_adapter"

        status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/adapter/{ADAPTER_ID}/evaluate",
            bearer_token=session.access_token,
            body={"scope_token": session.mint_scope(), "eval_request": request_body},
        )

        self.assertEqual(status, 403, denied)
        self.assertEqual(denied["error"], "ScopeDeniedError")
        self.assertEqual(self.s10.audit.events()[-1].payload["reason"], "adapter_id_mismatch")

    def test_store_put_and_get_are_scope_checked_broker_operations(self) -> None:
        session = self._session("s1")
        scope_token = session.mint_scope()
        payload = {"weights": [1.0, 2.0, 3.0]}
        put_status, record = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/store/put",
            bearer_token=session.access_token,
            body={
                "scope_token": scope_token,
                "kind": "model",
                "payload": payload,
                "producer": {"subsystem": "S1", "version": "1.0.0"},
                "lineage": {
                    "input_refs": [],
                    "code_ref": "git:s10-t13",
                    "environment_digest": "oci:s10-t13",
                },
            },
        )
        self.assertEqual(put_status, 201, record)

        get_status, fetched = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/store/get",
            bearer_token=session.access_token,
            body={
                "scope_token": scope_token,
                "artifact_ref": record["artifact_ref"],
                "representation": "payload",
            },
        )
        self.assertEqual(get_status, 200, fetched)
        self.assertEqual(fetched["artifact_ref"], record["artifact_ref"])
        self.assertEqual(fetched["payload"], payload)
        self.assertEqual(self.s10.audit.events()[-1].event_type, "store.get")

        direct_status, direct = _request_json(
            "POST",
            f"{self.s8_url}/v1/artifacts",
            bearer_token=session.access_token,
            body={"payload": {"bypass": True}},
        )
        self.assertEqual(direct_status, 403, direct)
        self.assertEqual(direct["error"], "DirectWriteDenied")

    def test_store_get_requires_s8_read_capability(self) -> None:
        identity = _identity(
            caller_id="s1-no-read",
            broker_audiences=("store",),
            producer_subsystems=("S1",),
        )
        access_token = str(self.auth.mint_identity_token(identity, ttl_s=600)["access_token"])
        self.s10.runtime_identity_mint_policy.identities_by_caller[identity.caller_id] = identity
        session = RuntimeIdentitySession.from_access_token(
            s10_url=self.s10_url,
            access_token=access_token,
            caller_id=identity.caller_id,
            expected_job_id=JOB_ID,
        )

        status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/store/get",
            bearer_token=access_token,
            body={
                "scope_token": session.mint_scope(),
                "artifact_ref": "c4://artifact/does-not-matter",
                "representation": "payload",
            },
        )

        self.assertEqual(status, 403, denied)
        self.assertEqual(denied["error"], "ScopeDeniedError")
        self.assertEqual(self.s10.audit.events()[-1].payload["reason"], "read_scope_denied")

    def test_store_get_preserves_missing_artifact_status_across_brokers(self) -> None:
        session = self._session("s1")

        status, missing = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/store/get",
            bearer_token=session.access_token,
            body={
                "scope_token": session.mint_scope(),
                "artifact_ref": "c4://artifact/missing",
                "representation": "payload",
            },
        )

        self.assertEqual(status, 404, missing)
        self.assertEqual(missing["error"], "KeyError")

    def _session(self, caller_id: str) -> RuntimeIdentitySession:
        return RuntimeIdentitySession.from_access_token(
            s10_url=self.s10_url,
            access_token=self.access_tokens[caller_id],
            caller_id=caller_id,
            expected_job_id=JOB_ID,
        )


def _identity(
    *,
    caller_id: str,
    allowed_adapters: tuple[str, ...] = (),
    broker_audiences: tuple[str, ...] = (),
    capabilities: tuple[str, ...] = (),
    producer_subsystems: tuple[str, ...] = (),
) -> RuntimeIdentity:
    return RuntimeIdentity(
        caller_id=caller_id,
        job_id=JOB_ID,
        root_request_id="m1-reference-root",
        scopes=ScopeGrant(
            allowed_adapters=allowed_adapters,
            broker_audiences=broker_audiences,
            capabilities=capabilities,
            producer_subsystems=producer_subsystems,
        ),
        budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=1),
        max_ttl_s=600,
    )


def _eval_request() -> dict[str, object]:
    return {
        "adapter_id": ADAPTER_ID,
        "inputs": {
            "T_n": {"value": 100.0, "units": "GeV", "uncertainty": {"kind": "interval", "radius": 1.0}},
            "alpha": {
                "value": 0.2,
                "units": "dimensionless",
                "uncertainty": {"kind": "interval", "radius": 0.01},
            },
            "beta_over_H": {
                "value": 100.0,
                "units": "dimensionless",
                "uncertainty": {"kind": "interval", "radius": 5.0},
            },
            "v_w": {
                "value": 0.7,
                "units": "dimensionless",
                "uncertainty": {"kind": "interval", "radius": 0.02},
            },
            "frequency": {
                "value": 0.003,
                "units": "Hz",
                "uncertainty": {"kind": "interval", "radius": 0.0001},
            },
        },
        "c6_version": "2.3.0",
        "seed": 17,
    }


def _request_json(
    method: str,
    url: str,
    *,
    body: dict[str, object] | None = None,
    bearer_token: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers: dict[str, str] = {}
    encoded = None
    if body is not None:
        encoded = canonical_json_bytes(body)
        headers["Content-Type"] = "application/json"
    if bearer_token is not None:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = urlrequest.Request(url, data=encoded, headers=headers, method=method)
    try:
        with urlrequest.urlopen(request, timeout=10) as response:
            status = response.status
            raw = response.read()
    except urlerror.HTTPError as exc:
        status = exc.code
        raw = exc.read()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"expected JSON object from {url}")
    return status, payload


def _start_json_server(app: object, *, port: int | None = None) -> str:
    selected_port = port or _free_port()
    thread = Thread(
        target=serve_json_app,
        kwargs={"app": getattr(app, "http"), "host": "127.0.0.1", "port": selected_port},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while True:
        try:
            with socket.create_connection(("127.0.0.1", selected_port), timeout=0.2):
                return f"http://127.0.0.1:{selected_port}"
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
