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
    InMemoryQuotaLedger,
    InMemoryTokenService,
    PriceTable,
    PriceTableSigner,
    ScopeGrant,
    canonical_json_bytes,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonHttpApp, serve_json_app
from argus_runtime.m1_runtime_artifacts import RuntimeIdentitySession
from argus_runtime.s10_reference_model_provider_service import ReferenceModelProviderApp
from argus_runtime.s10_supervisor_service import (
    CredentialedModelTarget,
    RuntimeIdentityMintPolicy,
    S10SupervisorApp,
    S8BrokeredArtifactStoreClient,
)
from argus_runtime.s8_writer_service import S8WriterApp


JOB_ID = "s10-tc16-job"
MODEL_ID = "argus-reference-model-v1"
MODEL_AUDIENCE = "model"
MODEL_CREDENTIAL_HEADER = "X-Argus-Model-Credential"


class S10ModelBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model_credential = "broker-only-model-secret"
        self.broker_write_key = b"s10-t15-broker-write-key"
        self.auth = RuntimeAuth.with_signed_identities(
            bootstrap_token="s10-t15-bootstrap",
            identity_signing_key=b"s10-t15-runtime-identity-key",
        )
        self.identity = _identity(caller_id="s1-model")
        self.denied_identity = _identity(caller_id="s1-no-model", broker_audiences=("store",))
        self.other_identity = _identity(caller_id="s1-other-job", job_id="other-job")
        self.cost_limited_identity = _identity(caller_id="s1-cost-limited", max_cost_usd=0.001)
        self.identities = {
            identity.caller_id: identity
            for identity in (
                self.identity,
                self.denied_identity,
                self.other_identity,
                self.cost_limited_identity,
            )
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

        self.provider = ReferenceModelProviderApp(
            model_id=MODEL_ID,
            credential_header=MODEL_CREDENTIAL_HEADER,
            credential=self.model_credential,
        )
        self.provider_url = _start_json_server(self.provider)
        self.quota = InMemoryQuotaLedger()
        self.s10 = self._build_s10(self.provider_url, quota=self.quota)
        self.s10_url = _start_json_server(self.s10)

    def test_broker_debits_exact_usage_and_persists_prompt_response_provenance(self) -> None:
        session = self._session("s1-model")
        scope_token = session.mint_scope()
        budget_token = session.mint_budget()
        model_request = _model_request(max_tokens=32)

        status, result = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": scope_token,
                "budget_token": budget_token,
                "request": model_request,
            },
        )

        self.assertEqual(status, 200, result)
        usage = result["usage"]
        self.assertEqual(result["tokens_used"], usage["input_tokens"] + usage["output_tokens"])
        self.assertEqual(usage["total_tokens"], result["tokens_used"])
        self.assertGreater(usage["input_tokens"], 0)
        self.assertGreater(usage["output_tokens"], 0)
        self.assertRegex(result["provenance_ref"], r"^c4://")
        self.assertEqual(self.provider.count_request_count, 1)
        self.assertEqual(self.provider.completion_request_count, 1)

        state = self.quota.state(budget_token["budget_id"])
        self.assertEqual(state.reserved.model_tokens, 0)
        self.assertEqual(state.actual.model_tokens, result["tokens_used"])
        self.assertGreater(state.actual.cost_usd, 0)
        self.assertFalse(state.halted)

        record = self.s8_store.get_artifact_record(result["provenance_ref"])
        payload = json.loads(self.s8_store.get_artifact(result["provenance_ref"]).decode("utf-8"))
        self.assertEqual(record.kind, "llm_call")
        self.assertEqual(record.producer.subsystem, "S10")
        self.assertEqual(record.producer.job_id, JOB_ID)
        self.assertEqual(record.lineage.job_id, JOB_ID)
        self.assertEqual(payload["schema"], "argus.s10.llm-call.v1")
        self.assertEqual(payload["request"], model_request)
        self.assertEqual(payload["response"], result["response"])
        self.assertEqual(payload["usage"], usage)
        self.assertEqual(payload["budget_id"], budget_token["budget_id"])
        self.assertNotIn(self.model_credential, json.dumps(payload, sort_keys=True))
        self.assertNotIn(self.model_credential, json.dumps(result, sort_keys=True))
        self.assertNotIn(
            self.model_credential,
            json.dumps([event.payload for event in self.s10.audit.events()], sort_keys=True),
        )

    def test_over_limit_call_is_refused_before_completion_and_halts_budget(self) -> None:
        session = self._session("s1-model")
        scope_token = session.mint_scope()
        budget_token = session.mint_budget()

        first_status, first = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": scope_token,
                "budget_token": budget_token,
                "request": _model_request(max_tokens=32),
            },
        )
        self.assertEqual(first_status, 200, first)
        completion_count = self.provider.completion_request_count

        denied_status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": scope_token,
                "budget_token": budget_token,
                "request": _model_request(max_tokens=1000),
            },
        )

        self.assertEqual(denied_status, 403, denied)
        self.assertEqual(denied["error"], "BudgetExceededError")
        self.assertTrue(denied["budget_halted"])
        self.assertEqual(self.provider.completion_request_count, completion_count)
        state = self.quota.state(budget_token["budget_id"])
        self.assertEqual(state.actual.model_tokens, first["tokens_used"])
        self.assertLessEqual(state.actual.model_tokens, 1000)
        self.assertEqual(state.reserved.model_tokens, 0)
        self.assertTrue(state.halted)
        self.assertEqual(self.s10.audit.events()[-1].event_type, "model.budget_halt")

        count_after_halt = self.provider.count_request_count
        repeated_status, repeated = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": scope_token,
                "budget_token": budget_token,
                "request": _model_request(max_tokens=1),
            },
        )
        self.assertEqual(repeated_status, 403, repeated)
        self.assertEqual(self.provider.count_request_count, count_after_halt)
        self.assertEqual(self.provider.completion_request_count, completion_count)

    def test_scope_and_model_target_denials_happen_before_provider_execution(self) -> None:
        denied_session = self._session("s1-no-model")
        denied_status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=denied_session.access_token,
            body={
                "scope_token": denied_session.mint_scope(),
                "budget_token": denied_session.mint_budget(),
                "request": _model_request(max_tokens=8),
            },
        )
        self.assertEqual(denied_status, 403, denied)
        self.assertEqual(denied["error"], "ScopeDeniedError")

        session = self._session("s1-model")
        unknown_request = _model_request(max_tokens=8)
        unknown_request["model"] = "unconfigured-model"
        unknown_status, unknown = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": session.mint_scope(),
                "budget_token": session.mint_budget(),
                "request": unknown_request,
            },
        )
        self.assertEqual(unknown_status, 403, unknown)
        self.assertEqual(unknown["error"], "ScopeDeniedError")
        self.assertEqual(self.provider.count_request_count, 0)
        self.assertEqual(self.provider.completion_request_count, 0)

    def test_budget_token_must_match_authenticated_identity_and_scope_job(self) -> None:
        session = self._session("s1-model")
        other_session = self._session("s1-other-job")

        status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": session.mint_scope(),
                "budget_token": other_session.mint_budget(),
                "request": _model_request(max_tokens=8),
            },
        )

        self.assertEqual(status, 403, denied)
        self.assertEqual(denied["error"], "PermissionError")
        self.assertEqual(self.provider.count_request_count, 0)
        self.assertEqual(self.provider.completion_request_count, 0)

    def test_cost_limit_is_refused_before_completion_and_halts_budget(self) -> None:
        session = self._session("s1-cost-limited")
        budget_token = session.mint_budget()

        status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": session.mint_scope(),
                "budget_token": budget_token,
                "request": _model_request(max_tokens=8),
            },
        )

        self.assertEqual(status, 403, denied)
        self.assertEqual(denied["error"], "BudgetExceededError")
        self.assertTrue(denied["budget_halted"])
        self.assertEqual(self.provider.count_request_count, 1)
        self.assertEqual(self.provider.completion_request_count, 0)
        state = self.quota.state(budget_token["budget_id"])
        self.assertEqual(state.actual.model_tokens, 0)
        self.assertEqual(state.reserved.model_tokens, 0)
        self.assertTrue(state.halted)

    def test_request_cannot_override_broker_owned_credentials(self) -> None:
        session = self._session("s1-model")
        request_body = _model_request(max_tokens=8)
        request_body["headers"] = {"X-Api-Key": "caller-controlled"}

        status, denied = _request_json(
            "POST",
            f"{self.s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": session.mint_scope(),
                "budget_token": session.mint_budget(),
                "request": request_body,
            },
        )

        self.assertEqual(status, 400, denied)
        self.assertEqual(denied["error"], "ValueError")
        self.assertEqual(self.provider.count_request_count, 0)
        self.assertEqual(self.provider.completion_request_count, 0)

    def test_direct_provider_call_without_broker_credential_is_denied(self) -> None:
        status, denied = _request_json(
            "POST",
            f"{self.provider_url}/v1/messages",
            body=_model_request(max_tokens=8),
        )

        self.assertEqual(status, 403, denied)
        self.assertEqual(denied["error"], "broker_credential_required")
        self.assertEqual(self.provider.completion_request_count, 0)

    def test_malformed_provider_usage_halts_without_leaving_reservation(self) -> None:
        malformed_provider = _MalformedUsageProvider(
            model_id=MODEL_ID,
            credential_header=MODEL_CREDENTIAL_HEADER,
            credential=self.model_credential,
        )
        provider_url = _start_json_server(malformed_provider)
        quota = InMemoryQuotaLedger()
        s10 = self._build_s10(provider_url, quota=quota)
        s10_url = _start_json_server(s10)
        session = RuntimeIdentitySession.from_access_token(
            s10_url=s10_url,
            access_token=self.access_tokens["s1-model"],
            caller_id="s1-model",
            expected_job_id=JOB_ID,
        )
        budget_token = session.mint_budget()

        status, failed = _request_json(
            "POST",
            f"{s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": session.mint_scope(),
                "budget_token": budget_token,
                "request": _model_request(max_tokens=8),
            },
        )

        self.assertEqual(status, 502, failed)
        self.assertEqual(failed["error"], "ModelBrokerUpstreamError")
        state = quota.state(budget_token["budget_id"])
        self.assertEqual(state.reserved.model_tokens, 0)
        self.assertEqual(state.actual.model_tokens, 0)
        self.assertTrue(state.halted)
        self.assertEqual(self.s8_store.record_count, 0)

    def test_provenance_failure_keeps_exact_debit_and_halts_budget(self) -> None:
        quota = InMemoryQuotaLedger()
        s10 = self._build_s10(
            self.provider_url,
            quota=quota,
            artifact_store=_FailingArtifactStore(),
        )
        s10_url = _start_json_server(s10)
        session = RuntimeIdentitySession.from_access_token(
            s10_url=s10_url,
            access_token=self.access_tokens["s1-model"],
            caller_id="s1-model",
            expected_job_id=JOB_ID,
        )
        budget_token = session.mint_budget()

        status, failed = _request_json(
            "POST",
            f"{s10_url}/v1/broker/model/complete",
            bearer_token=session.access_token,
            body={
                "scope_token": session.mint_scope(),
                "budget_token": budget_token,
                "request": _model_request(max_tokens=8),
            },
        )

        self.assertEqual(status, 502, failed)
        self.assertEqual(failed["error"], "ModelBrokerUpstreamError")
        state = quota.state(budget_token["budget_id"])
        self.assertGreater(state.actual.model_tokens, 0)
        self.assertLessEqual(state.actual.model_tokens, 1000)
        self.assertEqual(state.reserved.model_tokens, 0)
        self.assertTrue(state.halted)
        self.assertEqual(s10.audit.events()[-1].event_type, "model.provenance_error")
        self.assertTrue(s10.audit.events()[-1].payload["budget_halted"])

    def test_model_target_rejects_embedded_or_overriding_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not contain credentials"):
            CredentialedModelTarget(
                model_id=MODEL_ID,
                completion_url="https://secret@example.test/v1/messages",
                token_count_url="https://example.test/v1/messages/count_tokens",
                credential_header="X-Api-Key",
                credential="secret",
            )
        with self.assertRaisesRegex(ValueError, "cannot override broker-owned headers"):
            CredentialedModelTarget(
                model_id=MODEL_ID,
                completion_url="https://example.test/v1/messages",
                token_count_url="https://example.test/v1/messages/count_tokens",
                credential_header="X-Api-Key",
                credential="secret",
                static_headers={"x-api-key": "caller-controlled"},
            )

    def _build_s10(
        self,
        provider_url: str,
        *,
        quota: InMemoryQuotaLedger,
        artifact_store: InMemoryArtifactStore | None = None,
    ) -> S10SupervisorApp:
        signer = PriceTableSigner(signer_key_id="s10-t15-price", signing_key=b"s10-t15-price-key")
        table = signer.sign(
            PriceTable(
                price_table_version="s10-t15-v1",
                usd_per_cpu_second="0",
                usd_per_gpu_second={"default": "0"},
                usd_per_1k_model_tokens={MODEL_ID: "0.25"},
                issued_at=int(time.time()) - 1,
                expires_at=int(time.time()) + 3600,
            )
        )
        return S10SupervisorApp(
            token_service=InMemoryTokenService(signing_key=b"s10-t15-token-key"),
            quota_ledger=quota,
            artifact_store=(
                artifact_store
                if artifact_store is not None
                else S8BrokeredArtifactStoreClient(
                    endpoint_url=f"{self.s8_url}/v1/internal/brokered-artifacts",
                    broker_write_key=self.broker_write_key,
                )
            ),
            auth=self.auth,
            runtime_identity_mint_policy=RuntimeIdentityMintPolicy(self.identities),
            price_table=table,
            price_table_trust_store=signer.trust_store(),
            model_targets={
                MODEL_ID: CredentialedModelTarget(
                    model_id=MODEL_ID,
                    completion_url=f"{provider_url}/v1/messages",
                    token_count_url=f"{provider_url}/v1/messages/count_tokens",
                    credential_header=MODEL_CREDENTIAL_HEADER,
                    credential=self.model_credential,
                    static_headers={"Anthropic-Version": "2023-06-01"},
                )
            },
        )

    def _session(self, caller_id: str) -> RuntimeIdentitySession:
        return RuntimeIdentitySession.from_access_token(
            s10_url=self.s10_url,
            access_token=self.access_tokens[caller_id],
            caller_id=caller_id,
            expected_job_id=self.identities[caller_id].job_id,
        )


class _MalformedUsageProvider:
    def __init__(self, *, model_id: str, credential_header: str, credential: str) -> None:
        self.http = JsonHttpApp()

        def authorize(headers: dict[str, str]) -> bool:
            return headers.get(credential_header.lower()) == credential

        @self.http.route("POST", "/v1/messages/count_tokens")
        def count_tokens(request: object) -> tuple[int, object]:
            if not authorize(getattr(request, "headers")):
                return 403, {"error": "broker_credential_required"}
            return 200, {"input_tokens": 4}

        @self.http.route("POST", "/v1/messages")
        def complete(request: object) -> tuple[int, object]:
            if not authorize(getattr(request, "headers")):
                return 403, {"error": "broker_credential_required"}
            return 200, {
                "id": "malformed-usage",
                "model": model_id,
                "content": [{"type": "text", "text": "invalid usage"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 4, "output_tokens": 9},
            }


class _FailingArtifactStore(InMemoryArtifactStore):
    def create_artifact(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise OSError("S8 unavailable")


def _identity(
    *,
    caller_id: str,
    job_id: str = JOB_ID,
    broker_audiences: tuple[str, ...] = (MODEL_AUDIENCE, "store"),
    max_cost_usd: float = 1,
) -> RuntimeIdentity:
    return RuntimeIdentity(
        caller_id=caller_id,
        job_id=job_id,
        root_request_id=f"{job_id}-root",
        scopes=ScopeGrant(
            broker_audiences=broker_audiences,
            capabilities=("s8.read",),
            producer_subsystems=("S1",),
        ),
        budget_caps=BudgetCaps(
            max_compute_units=10,
            max_model_tokens=1000,
            max_wallclock_s=30,
            max_cost_usd=max_cost_usd,
        ),
        max_ttl_s=600,
    )


def _model_request(*, max_tokens: int) -> dict[str, object]:
    return {
        "model": MODEL_ID,
        "max_tokens": max_tokens,
        "messages": [
            {
                "role": "user",
                "content": "Summarize why a broker must debit tokens before returning a model response.",
            }
        ],
        "temperature": 0,
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


def _start_json_server(app: object) -> str:
    port = _free_port()
    thread = Thread(
        target=serve_json_app,
        kwargs={"app": getattr(app, "http"), "host": "127.0.0.1", "port": port},
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
