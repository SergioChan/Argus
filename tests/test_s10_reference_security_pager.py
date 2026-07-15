from __future__ import annotations

import unittest
import threading

from argus_runtime.http_json import JsonRequest
from argus_runtime.s10_reference_security_pager_service import ReferenceSecurityPagerApp


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


def _page() -> dict[str, str]:
    return {
        "schema": "argus.s10.security-page.v1",
        "quarantine_id": "quarantine-1",
        "job_id": "job-1",
        "sandbox_id": "sandbox-1",
        "severity": "Sev-1",
        "reason": "trust_path_write",
        "record_ref": "artifact:quarantine-record-1",
        "opened_at": "2026-07-15T00:00:00Z",
    }


class ReferenceSecurityPagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = ReferenceSecurityPagerApp(
            delivery_token="delivery-token",
            read_token="read-token",
        )

    def test_delivery_and_read_tokens_are_separate(self) -> None:
        missing = self.app.http.handle(_request("POST", "/v1/pages", body=_page()))
        delivered = self.app.http.handle(
            _request("POST", "/v1/pages", token="delivery-token", body=_page())
        )
        delivery_token_cannot_read = self.app.http.handle(
            _request("GET", "/v1/pages/quarantine-1", token="delivery-token")
        )
        fetched = self.app.http.handle(
            _request("GET", "/v1/pages/quarantine-1", token="read-token")
        )

        self.assertEqual(missing[0], 401)
        self.assertEqual(delivered, (202, {"accepted": True, "quarantine_id": "quarantine-1"}))
        self.assertEqual(delivery_token_cannot_read[0], 401)
        self.assertEqual(fetched, (200, _page()))

    def test_repeated_identical_delivery_is_idempotent_and_conflict_is_rejected(self) -> None:
        first = self.app.http.handle(
            _request("POST", "/v1/pages", token="delivery-token", body=_page())
        )
        repeated = self.app.http.handle(
            _request("POST", "/v1/pages", token="delivery-token", body=_page())
        )
        conflict = self.app.http.handle(
            _request(
                "POST",
                "/v1/pages",
                token="delivery-token",
                body={**_page(), "reason": "escape_attempt"},
            )
        )
        health = self.app.http.handle(_request("GET", "/healthz"))

        self.assertEqual(first[0], 202)
        self.assertEqual(repeated[0], 200)
        self.assertEqual(conflict[0], 409)
        self.assertEqual(health[1]["accepted_pages"], 1)

    def test_payload_contract_and_unknown_page_fail_closed(self) -> None:
        malformed = self.app.http.handle(
            _request(
                "POST",
                "/v1/pages",
                token="delivery-token",
                body={**_page(), "severity": "Sev-2"},
            )
        )
        unknown = self.app.http.handle(
            _request("GET", "/v1/pages/unknown", token="read-token")
        )

        self.assertEqual(malformed[0], 400)
        self.assertEqual(unknown[0], 404)

    def test_explicit_test_control_holds_delivery_until_authenticated_release(self) -> None:
        app = ReferenceSecurityPagerApp(
            delivery_token="delivery-token",
            read_token="read-token",
            enable_test_control=True,
            hold_deliveries=True,
        )
        delivery_result: list[tuple[int, object]] = []
        thread = threading.Thread(
            target=lambda: delivery_result.append(
                app.http.handle(
                    _request("POST", "/v1/pages", token="delivery-token", body=_page())
                )
            ),
            daemon=True,
        )
        thread.start()
        self.assertTrue(app.delivery_received.wait(timeout=1))

        listed = app.http.handle(_request("GET", "/v1/pages", token="read-token"))
        denied_release = app.http.handle(
            _request("POST", "/v1/test-control/release", token="delivery-token", body={})
        )
        self.assertTrue(thread.is_alive())
        released = app.http.handle(
            _request("POST", "/v1/test-control/release", token="read-token", body={})
        )
        thread.join(timeout=1)

        self.assertEqual(listed, (200, [_page()]))
        self.assertEqual(denied_release[0], 401)
        self.assertEqual(released, (200, {"released": True}))
        self.assertFalse(thread.is_alive())
        self.assertEqual(delivery_result[0][0], 202)


if __name__ == "__main__":
    unittest.main()
